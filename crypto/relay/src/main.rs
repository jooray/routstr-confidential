//! `cu-sidecar` — the node (N) side of the confidential-upstream protocol.
//!
//! One WebSocket per session carries the control channel and the relayed TLS
//! records; a second WebSocket per proof carries the mpz VOLE protocol.
//!
//! Security-critical ordering (SPEC §5, PLAN §3):
//!   HANDSHAKE → KU0 → HS_VERIFIED → PI_C1_VERIFIED → C_COMMIT → PI_N_VERIFIED
//!   → [credential record ‖ KU1] (atomic) → BODY → CLOSE_NOTIFY → ATTESTED → SETTLED.
//!
//! The API key lives only in memory, is never logged (only its length), and
//! appears only inside the single credential record written to the upstream.

mod tls;
mod wsio;

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::Zeroizing;

use cu_crypto::aesgcm;
use zkbench::statements::{Params, SessionPublic, Witness};
use zkbench::Role;

use crate::tls::{
    parse_records, verify_handshake, HandshakeInfo, HsSecrets, Record, CT_APPLICATION_DATA,
};
use crate::wsio::ws_duplex;

// ---------------------------------------------------------------------------
// Offer / head template
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Offer {
    upstream_host: String,
    #[serde(default)]
    price_list: serde_json::Value,
    #[serde(default)]
    head_template: String,
    #[serde(default = "default_key_alphabet")]
    key_alphabet: String,
    #[serde(default)]
    key_length: usize,
    #[serde(default)]
    suffix_keys: Vec<String>,
    #[serde(default = "default_max_tokens_cap")]
    max_tokens_cap: u64,
    #[serde(default)]
    notary_pubkey: String,
    /// Per-model modality gate (GAP-3). Escrow prices the prompt as
    /// `prompt_tokens <= LEN` (SPEC §5.1), which an accepted `image_url` part
    /// breaks: the attacker picks the image, so its token cost is not bounded
    /// by body bytes (probe: one ~50-byte URL cost 554 → 2050 tokens on a
    /// vision model). A model is usable confidentially only if it *rejects*
    /// multimodal parts; `text_only_ok[model] == true` marks such a model.
    /// When the map is non-empty the sidecar refuses any setup for a model not
    /// explicitly marked true, so the confidential path cannot be priced this
    /// way even if the node's own model list is broader.
    #[serde(default)]
    text_only_ok: HashMap<String, bool>,
}

fn default_key_alphabet() -> String {
    "[A-Za-z0-9_-]".to_string()
}

fn default_max_tokens_cap() -> u64 {
    4096
}

fn default_head_template_for(host: &str) -> String {
    format!(
        "POST /api/v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {{KEY:42}}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {{LEN}}\r\n\r\n"
    )
}

/// Strip the port (if any) from an `host:port` upstream spec.
fn host_of(upstream: &str) -> String {
    upstream.split(':').next().unwrap_or(upstream).to_string()
}

/// `GET /offer` — the static offer the node fetches, augments with its own
/// price list/notary key and re-serves (signed) from `/v1/confidential/offer`.
async fn offer_http(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json((*app.offer).clone())
}

/// The advertised template with `{KEY:L}` replaced by zero placeholders and
/// `{LEN}` by the decimal body length. Returns the bytes and key positions.
fn placeholder_head(template: &str, key_len: usize, len: usize) -> Result<(Vec<u8>, Vec<usize>)> {
    let key_token = format!("{{KEY:{key_len}}}");
    if !template.contains(&key_token) {
        bail!("head template missing {key_token}");
    }
    let filled = template.replace(&key_token, &"\u{0}".repeat(key_len));
    let filled = filled.replace("{LEN}", &len.to_string());
    let bytes = filled.into_bytes();
    let offsets: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == 0)
        .map(|(i, _)| i)
        .collect();
    if offsets.len() != key_len {
        bail!(
            "key placeholder count {} != key length {key_len}",
            offsets.len()
        );
    }
    Ok((bytes, offsets))
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    key: Arc<Zeroizing<Vec<u8>>>,
    offer: Arc<Offer>,
    host: String,
    upstream: String,
    signer: Arc<SigningKey>,
    insecure: bool,
    /// Where per-session artifacts (attestation/receipt/sidecar log) are written.
    /// `--runs-dir` overrides the default `CARGO_MANIFEST_DIR/../runs`.
    runs_dir: std::path::PathBuf,
    /// When true the sidecar does *not* settle: it emits the π_C3-verified
    /// `usage` frame and lets the node (which holds the Cashu wallet and the
    /// Nostr key) price, refund and sign the receipt.
    node_settles: bool,
    sessions: StdMutex<HashMap<String, Arc<SessionShared>>>,
}

#[derive(Debug)]
enum Ev {
    ServerBytes(Vec<u8>),
    TcpClosed,
    ZkDone {
        proof: String,
        ok: bool,
        err: Option<String>,
        /// The exact parameters the proof ran against (snapshot taken when the
        /// proof started), so state changed meanwhile cannot ride on it.
        params: Option<Params>,
    },
}

struct SessionShared {
    params: StdMutex<HashMap<String, Params>>,
    key: Arc<Zeroizing<Vec<u8>>>,
    evt: mpsc::UnboundedSender<Ev>,
    insecure: bool,
    /// Serializes the ZK proofs of one session. The client may run π_C2
    /// concurrently with generation and start π_C3 before π_C2 has finished;
    /// running two mpz proofs at once on one node stalls (the VOLE/rayon paths
    /// contend). Proofs are per-session independent, so serializing inside a
    /// session costs nothing on the critical path and removes the contention.
    zk_lock: tokio::sync::Mutex<()>,
}

/// Recorded relay state needed for the proofs.
#[derive(Default)]
struct RelayLog {
    client_raw: Vec<u8>,
    server_raw: Vec<u8>,
    /// Client application-data records in wire order (KU0, KU1, body...).
    client_app: Vec<Record>,
    /// Server records (handshake + response) in wire order.
    server_all: Vec<Record>,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cu_sidecar=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let arg = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };

    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:7443".into());
    let upstream = arg("--upstream").unwrap_or_else(|| "api.venice.ai:443".into());
    let key_env = arg("--key-env").unwrap_or_else(|| "VENICE_API_KEY".into());
    let insecure = args.iter().any(|a| a == "--insecure-no-proofs");
    let node_settles = args.iter().any(|a| a == "--node-settles");
    let host = arg("--host").unwrap_or_else(|| host_of(&upstream));
    let runs_dir = arg("--runs-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../runs")
        });

    let raw_key = std::env::var(&key_env).with_context(|| format!("{key_env} is not set"))?;
    let key = Zeroizing::new(raw_key.into_bytes());
    if key.len() != 42 {
        bail!("unexpected key length {} (expected 42)", key.len());
    }
    info!(key_len = key.len(), "loaded upstream API key");

    if insecure && !(listen.starts_with("127.0.0.1") || listen.starts_with("localhost")) {
        bail!("--insecure-no-proofs may only be used when listening on 127.0.0.1");
    }

    let mut offer = if let Some(path) = arg("--offer") {
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        serde_json::from_str::<Offer>(&text).with_context(|| format!("parsing {path}"))?
    } else {
        Offer {
            upstream_host: host.clone(),
            price_list: serde_json::json!({
                "mistral-small-3-2-24b-instruct": {"in": 0.0, "cached_in": 0.0, "out": 0.0}
            }),
            head_template: default_head_template_for(&host),
            key_alphabet: default_key_alphabet(),
            key_length: 42,
            suffix_keys: vec![
                "model".into(),
                "max_tokens".into(),
                "max_completion_tokens".into(),
                "n".into(),
                "stream".into(),
                "stream_options".into(),
                "venice_parameters".into(),
            ],
            max_tokens_cap: default_max_tokens_cap(),
            notary_pubkey: String::new(),
            text_only_ok: HashMap::new(),
        }
    };
    if offer.upstream_host.is_empty() {
        offer.upstream_host = host.clone();
    }
    if offer.head_template.is_empty() {
        offer.head_template = default_head_template_for(&offer.upstream_host);
    }
    if offer.suffix_keys.is_empty() {
        offer.suffix_keys = vec![
            "model".into(),
            "max_tokens".into(),
            "max_completion_tokens".into(),
            "n".into(),
            "stream".into(),
            "stream_options".into(),
            "venice_parameters".into(),
        ];
    }
    offer.key_length = key.len();
    // The π_N membership circuit is a fixed-size check over one alphabet. An
    // offer demanding another alphabet must fail here rather than let the
    // sidecar prove membership in the wrong set.
    if offer.key_alphabet != zkbench::statements::SUPPORTED_KEY_ALPHABET {
        bail!(
            "unsupported key_alphabet {:?}: the π_N circuit is fixed to {:?}",
            offer.key_alphabet,
            zkbench::statements::SUPPORTED_KEY_ALPHABET
        );
    }
    // The key length is a proof parameter, not a compile-time constant, so any
    // key length the head template declares is provable; it is pinned to the
    // loaded key's real length here.

    let signer = SigningKey::from_bytes(&os_random_32());
    offer.notary_pubkey = hex::encode(signer.verifying_key().to_bytes());

    let state = Arc::new(AppState {
        key: Arc::new(key),
        offer: Arc::new(offer),
        host: host.clone(),
        upstream,
        signer: Arc::new(signer),
        insecure,
        runs_dir,
        node_settles,
        sessions: StdMutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/offer", get(offer_http))
        .route("/session", get(session_ws))
        .route("/zk", get(zk_ws))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(%listen, insecure, "cu-sidecar listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn os_random_32() -> [u8; 32] {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("os randomness");
    b
}

// ---------------------------------------------------------------------------
// /session
// ---------------------------------------------------------------------------

async fn session_ws(ws: WebSocketUpgrade, State(app): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| session_handler(socket, app))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Setup {
        nonce_c: String,
        model: String,
        max_tokens: u64,
        len: usize,
        #[serde(default)]
        escrow_e: u64,
        /// The client's Cashu escrow token (node-settles mode). The sidecar
        /// never redeems it; it only hashes it into `sid` per SPEC §5.1 so both
        /// sides agree on the session id.
        #[serde(default)]
        escrow: Option<String>,
        /// Pre-warm: the session was armed before a request existed. The
        /// escrow (or account reservation) is supplied by the later `claim`.
        #[serde(default)]
        armed: bool,
    },
    HsSecrets {
        /// The handshake secret itself. Only accepted in the loopback
        /// `--insecure-no-proofs` test mode: with HS the node could derive every
        /// application traffic secret, so a real client never sends it.
        #[serde(default)]
        hs: Option<String>,
        client_hs: String,
        server_hs: String,
    },
    C1Material {
        s: String,
        h1: String,
        t0: String,
    },
    BodySuffix {
        suffix: String,
    },
    Disclose {
        r: String,
        /// Ciphertext lengths of the trailing content records that cover R,
        /// ordered from the end (used to locate them unambiguously).
        tail_lens: Vec<usize>,
    },
    Ku1 {
        record: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SessionState {
    #[default]
    Handshake,
    AwaitKu0,
    AwaitC1,
    Body,
    Attested,
    Settled,
    Closed,
}

struct Assembled {
    record: Vec<u8>,
    c_commit: [u8; 32],
    header: [u8; 5],
}

async fn session_handler(socket: WebSocket, app: Arc<AppState>) {
    if let Err(e) = session_inner(socket, app).await {
        warn!(error = %e, "session ended with error");
    }
}

async fn session_inner(socket: WebSocket, app: Arc<AppState>) -> Result<()> {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (to_client, mut from_client) = mpsc::unbounded_channel::<Message>();

    let tcp = TcpStream::connect(&app.upstream)
        .await
        .with_context(|| format!("connecting to {}", app.upstream))?;
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<Ev>();
    let shared = Arc::new(SessionShared {
        params: StdMutex::new(HashMap::new()),
        key: app.key.clone(),
        evt: evt_tx.clone(),
        insecure: app.insecure,
        zk_lock: tokio::sync::Mutex::new(()),
    });

    let send_task = tokio::spawn(async move {
        while let Some(m) = from_client.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    {
        let evt = evt_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tcp_rx.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = evt.send(Ev::TcpClosed);
                        break;
                    }
                    Ok(n) => {
                        let _ = evt.send(Ev::ServerBytes(buf[..n].to_vec()));
                    }
                }
            }
        });
    }

    let mut st = Session::default();
    let mut log = RelayLog::default();
    let mut client_pending: Vec<u8> = Vec::new();
    let mut server_pending: Vec<u8> = Vec::new();

    let result: Result<()> = async {
        loop {
            tokio::select! {
                msg = ws_rx.next() => {
                    let Some(Ok(msg)) = msg else { break };
                    match msg {
                        Message::Text(t) => {
                            let parsed: ClientMsg = match serde_json::from_str(&t) {
                                Ok(p) => p, Err(e) => { return Err(anyhow!("bad control: {e}")); }
                            };
                            if let Err(e) = handle_control(parsed, &app, &shared, &to_client, &mut st, &mut log, &mut tcp_tx).await {
                                warn!("control error: {e}");
                                // Propagate: the outer handler sends an explicit
                                // {type:"error"} frame before closing, so the
                                // client fails fast instead of timing out.
                                return Err(e);
                            }
                        }
                    Message::Binary(data) => {
                        match st.state {
                            SessionState::Handshake => {
                                if st.sid.is_none() {
                                    bail!("TLS bytes before setup");
                                }
                                tcp_tx.write_all(&data).await?;
                                st.sent.extend_from_slice(&data);
                                log.client_raw.extend_from_slice(&data);
                            }
                            SessionState::AwaitKu0 => {
                                client_pending.extend_from_slice(&data);
                                log.client_raw.extend_from_slice(&data);
                                let (recs, used) = parse_records(&client_pending);
                                if recs.len() == 1 && used == client_pending.len() {
                                    let r = recs[0].clone();
                                    if !(r.ctype == CT_APPLICATION_DATA && r.payload.len() == 22) {
                                        bail!("epoch-0 client record is not a 22-byte KeyUpdate");
                                    }
                                    tcp_tx.write_all(&r.bytes()).await?;
                                    st.sent.extend_from_slice(&r.bytes());
                                    log.client_app.push(r);
                                    client_pending.clear();
                                    info!("KU0 forwarded");
                                    st.state = SessionState::AwaitC1;
                                } else if recs.len() > 1 {
                                    bail!("more than one client record in epoch 0");
                                }
                            }
                            SessionState::Body => {
                                let mut buf = std::mem::take(&mut client_pending);
                                buf.extend_from_slice(&data);
                                log.client_raw.extend_from_slice(&data);
                                let (recs, used) = parse_records(&buf);
                                for r in recs {
                                    // The epoch-2 plaintext must be exactly the
                                    // declared Content-Length: bytes past it would
                                    // be a smuggled second request, and records
                                    // after the π_C2-proven final record would let
                                    // the proven suffix not be the body's tail.
                                    if r.ctype != CT_APPLICATION_DATA || r.payload.len() < 18 {
                                        bail!("unexpected epoch-2 client record");
                                    }
                                    let content = r.payload.len() - 17;
                                    if st.body_bytes + content > st.body_len {
                                        bail!("client body exceeds declared length {}", st.body_len);
                                    }
                                    st.body_bytes += content;
                                    st.body_records += 1;
                                    if st.body_bytes == st.body_len {
                                        // The record that completes the body (and
                                        // carries the pinned suffix) is held until
                                        // π_C2 verifies: the upstream cannot start
                                        // inference without the full body, so a
                                        // client that swaps the model or caps is
                                        // stopped before it costs anything.
                                        st.held = Some(r.bytes());
                                        info!("final body record held until π_C2 verifies");
                                    } else {
                                        tcp_tx.write_all(&r.bytes()).await?;
                                        st.sent.extend_from_slice(&r.bytes());
                                    }
                                    log.client_app.push(r);
                                }
                                client_pending = buf[used..].to_vec();
                            }
                            _ => bail!("unexpected client record in state {:?}", st.state),
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            ev = evt_rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    Ev::ServerBytes(bytes) => {
                        server_pending.extend_from_slice(&bytes);
                        log.server_raw.extend_from_slice(&bytes);
                        let (recs, used) = parse_records(&server_pending);
                        for r in recs { log.server_all.push(r); }
                        server_pending.drain(..used);
                        if to_client.send(Message::Binary(bytes.into())).is_err() { break; }
                    }
                    Ev::TcpClosed => {
                        info!("upstream closed the connection");
                        let mut att_chain: Option<String> = None;
                        if let (Some(sid), Some(hs)) = (st.sid.as_ref(), st.handshake.as_ref()) {
                            let a = serde_json::json!({
                                "sid": sid,
                                "cert_chain_hash": hex::encode(hs.cert_chain_hash),
                                "th_sh": hex::encode(hs.th_sh),
                                "th_sf": hex::encode(hs.th_sf),
                                "sha256_sent": hex::encode(cu_crypto::transcript::hash(&st.sent)),
                                "sha256_recv": hex::encode(cu_crypto::transcript::hash(&log.server_raw)),
                                "client_records": log.client_app.len(),
                                "server_records": log.server_all.len(),
                                "c_commit": st.c_commit.map(hex::encode),
                                "time": now_unix(),
                            });
                            let sig = app.signer.sign(a.to_string().as_bytes());
                            let _ = to_client.send(Message::Text(
                                serde_json::json!({"type":"attestation","a":a,"sig":hex::encode(sig.to_bytes())}).to_string().into(),
                            ));
                            st.attestation = Some(a.clone());
                            att_chain = Some(hex::encode(hs.cert_chain_hash));
                            write_attestation(&st.run_dir, &a);
                            st.state = SessionState::Attested;
                        }
                        if let Some(c) = att_chain {
                            side(&mut st, format!("attestation cert_chain_hash={c}"));
                        }
                    }
                    Ev::ZkDone { proof, ok, err, params: proven } => {
                        info!(proof, ok, ?err, "zk result");
                        side(&mut st, format!("zk proof={} ok={} err={:?}", proof, ok, err));
                        if !ok { bail!("proof {proof} failed: {err:?}"); }
                        match proof.as_str() {
                            "pi_c1" => {
                                if st.assembled.is_some() {
                                    continue; // re-run of an already verified proof
                                }
                                // Assemble only from the material the proof was
                                // run on; reject if the session's copy differs.
                                let same = match (&proven, &st.c1_params) {
                                    (Some(a), Some(b)) => serde_json::to_value(a).ok() == serde_json::to_value(b).ok(),
                                    _ => false,
                                };
                                if !same {
                                    bail!("π_C1 material changed after the proof started");
                                }
                                let asm = assemble(&app, &st, &log)?;
                                st.c_commit = Some(asm.c_commit);
                                let (template, offsets) = placeholder_head(&app.offer.head_template, app.key.len(), st.body_len)?;
                                let params = Params::PiN(zkbench::statements::PiN {
                                    head_len: st.head_len,
                                    key_len: app.key.len(),
                                    key_alphabet: app.offer.key_alphabet.clone(),
                                    key_offsets: offsets,
                                    template,
                                    s: st.c1_s()?,
                                    c_commit: asm.c_commit,
                                    header: asm.header,
                                });
                                shared.params.lock().unwrap().insert("pi_n".into(), params.clone());
                                let _ = to_client.send(Message::Text(serde_json::json!({
                                    "type":"c_commit","params": params, "c_commit": hex::encode(asm.c_commit),
                                }).to_string().into()));
                                st.assembled = Some(asm);
                                info!("pi_c1 assembled; c_commit + pi_n params sent");
                            }
                            "pi_c2" => {
                                let same = match (&proven, shared.params.lock().unwrap().get("pi_c2")) {
                                    (Some(a), Some(b)) => serde_json::to_value(a).ok() == serde_json::to_value(b).ok(),
                                    _ => false,
                                };
                                if same && !st.c2_ok {
                                    st.c2_ok = true;
                                    // Suffix proven: release the final body record.
                                    let held = st.held.take().ok_or_else(|| anyhow!("π_C2 verified but no held body record"))?;
                                    // Tell the node *before* the write: once the
                                    // upstream may have the full request, the node
                                    // must treat the escrow as at stake (it drains
                                    // these frames even if the client leaves).
                                    let _ = to_client.send(Message::Text(
                                        serde_json::json!({"type":"body_released"}).to_string().into(),
                                    ));
                                    tcp_tx.write_all(&held).await?;
                                    st.sent.extend_from_slice(&held);
                                    info!("π_C2 verified; final body record released to the upstream");
                                    side(&mut st, "pi_c2 verified; final body record released".into());
                                }
                            }
                            "pi_c3" => {
                                if st.state == SessionState::Settled {
                                    continue;
                                }
                                if !st.c2_ok {
                                    bail!("π_C3 before π_C2 verified: the suffix (model, caps) is not proven");
                                }
                                let same = match (&proven, shared.params.lock().unwrap().get("pi_c3")) {
                                    (Some(a), Some(b)) => serde_json::to_value(a).ok() == serde_json::to_value(b).ok(),
                                    _ => false,
                                };
                                if !same {
                                    bail!("π_C3 parameters changed after the proof started");
                                }
                                if let Some(usage) = st.usage.clone() {
                                    let model = usage
                                        .get("model")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    if app.node_settles {
                                        // The node holds the wallet and the
                                        // Nostr key: it prices, refunds and
                                        // signs. Send it the verified usage.
                                        let _ = to_client.send(Message::Text(
                                            serde_json::json!({
                                                "type":"usage",
                                                "sid": st.sid,
                                                "model": model,
                                                "usage": usage,
                                            }).to_string().into(),
                                        ));
                                        side(&mut st, "pi_c3 verified; usage handed to the node to settle".into());
                                        st.state = SessionState::Settled;
                                    } else if let Some(receipt) = settle(&app, &st) {
                                        // Prototype/stub settlement (sidecar signs).
                                        // Sign the exact serialized bytes so the client
                                        // can verify without JSON re-serialization drift.
                                        let receipt_json = receipt.to_string();
                                        let sig = app.signer.sign(receipt_json.as_bytes());
                                        let _ = to_client.send(Message::Text(
                                            serde_json::json!({
                                                "type":"receipt","receipt":receipt,
                                                "receipt_json":receipt_json,
                                                "sig":hex::encode(sig.to_bytes()),
                                            }).to_string().into(),
                                        ));
                                        write_receipt(&st.run_dir, &receipt);
                                        st.state = SessionState::Settled;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    Ok(())
    }.await;

    if let Err(e) = &result {
        // Send an explicit error frame so the client fails fast instead of
        // waiting out its protocol timeout (the timeout remains the backstop).
        let _ = to_client.send(Message::Text(
            serde_json::json!({"type":"error","reason":e.to_string()}).to_string().into(),
        ));
    }
    if let Some(dir) = &st.run_dir {
        let _ = std::fs::write(dir.join("sidecar.jsonl"), st.side_log.join("\n") + "\n");
    }
    // Close the outbound queue so the sender task drains and flushes any last
    // frame (e.g. the explicit {type:"error"} abort) before the socket goes.
    drop(to_client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), send_task).await;
    result
}

/// Per-session mutable state kept inside the handler task.
#[derive(Default)]
struct Session {
    state: SessionState,
    sid: Option<String>,
    body_len: usize,
    head_len: usize,
    c1_params: Option<Params>,
    assembled: Option<Assembled>,
    c_commit: Option<[u8; 32]>,
    handshake: Option<HandshakeInfo>,
    hs_secrets: Option<HsSecrets>,
    /// Insecure test mode only.
    hs: Option<[u8; 32]>,
    /// The record completing the body, withheld from the upstream until π_C2.
    held: Option<Vec<u8>>,
    sent: Vec<u8>,
    /// Setup values the suffix must pin.
    model: String,
    max_tokens: u64,
    /// Epoch-2 (body) accounting: records and content bytes relayed.
    body_records: usize,
    body_bytes: usize,
    c2_requested: bool,
    c2_ok: bool,
    disclosed: bool,
    attestation: Option<serde_json::Value>,
    usage: Option<serde_json::Value>,
    run_dir: Option<std::path::PathBuf>,
    side_log: Vec<String>,
}

impl Session {
    fn c1_s(&self) -> Result<Vec<u8>> {
        match &self.c1_params {
            Some(Params::PiC1(p)) => Ok(p.s.clone()),
            _ => bail!("no c1 material"),
        }
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn side(st: &mut Session, ev: String) {
    st.side_log
        .push(serde_json::json!({"t": now_unix(), "ev": ev}).to_string());
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[allow(clippy::too_many_arguments)]
async fn handle_control(
    msg: ClientMsg,
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &mut RelayLog,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let send = |v: serde_json::Value| {
        let _ = to_client.send(Message::Text(v.to_string().into()));
    };

    match msg {
        ClientMsg::Setup { nonce_c, model, max_tokens, len, escrow_e, escrow, armed } => {
            if st.sid.is_some() || st.state != SessionState::Handshake {
                bail!("duplicate setup");
            }
            if max_tokens > app.offer.max_tokens_cap {
                bail!("max_tokens {max_tokens} exceeds cap {}", app.offer.max_tokens_cap);
            }
            // GAP-3: only models verified to reject multimodal parts may be
            // priced by the LEN bound. The gate is active only when the offer
            // carries a non-empty text_only_ok map (backwards compatible).
            if !app.offer.text_only_ok.is_empty()
                && app.offer.text_only_ok.get(&model) != Some(&true)
            {
                bail!(
                    "model {model:?} is not marked text_only_ok; refusing (an accepted image part can exceed the LEN-priced escrow)"
                );
            }
            let nonce_n = os_random_32();
            let mut h = Vec::new();
            h.extend_from_slice(&hex::decode(&nonce_c)?);
            h.extend_from_slice(&nonce_n);
            // SPEC §5.1: sid = SHA256(nonce_C ‖ nonce_N ‖ SHA256(cashu_token)).
            // Without a token (prototype / armed session before claim) the
            // placeholder preserves the same shape.
            match &escrow {
                Some(token) => h.extend_from_slice(&cu_crypto::transcript::hash(token.as_bytes())),
                None => {
                    let mut esc = b"stub-cashu".to_vec();
                    esc.extend_from_slice(&escrow_e.to_be_bytes());
                    h.extend_from_slice(&cu_crypto::transcript::hash(&esc));
                }
            }
            let sid = hex::encode(cu_crypto::transcript::hash(&h));
            st.sid = Some(sid.clone());
            st.body_len = len;
            st.model = model.clone();
            st.max_tokens = max_tokens;
            let (head, _) = placeholder_head(&app.offer.head_template, app.key.len(), len)?;
            st.head_len = head.len();
            st.run_dir = Some(init_run_dir(app, &sid)?);
            app.sessions.lock().unwrap().insert(sid.clone(), shared.clone());
            side(
                st,
                format!("setup sid={} model={} len={} max_tokens={} armed={} node_settles={}", sid, model, len, max_tokens, armed, app.node_settles),
            );
            send(serde_json::json!({
                "type":"ready","nonce_n":hex::encode(nonce_n),"sid":sid,
                "pubkey":app.offer.notary_pubkey,"head_len":head.len(),"offer":&*app.offer,
                "suffix": canonical_suffix(&model, max_tokens),
                "armed": armed,
            }));
        }
        ClientMsg::HsSecrets { hs, client_hs, server_hs } => {
            if st.sid.is_none() || st.handshake.is_some() {
                bail!("hs_secrets out of order");
            }
            let hs = match (app.insecure, hs) {
                (true, Some(h)) => Some(to32(&h)?),
                (true, None) => bail!("insecure mode needs hs"),
                // Refuse rather than silently accept: a client that sends HS
                // has given away its application keys.
                (false, Some(_)) => bail!("client disclosed HS; refusing (it would expose application keys)"),
                (false, None) => None,
            };
            let s = HsSecrets { client_hs: to32(&client_hs)?, server_hs: to32(&server_hs)? };
            let info = verify_handshake(&log.client_raw, &log.server_raw, &s, &app.host)?;
            // Nothing but ClientHello/CCS/Finished may have been relayed so far:
            // epoch-0 application data before the head would let the client
            // frame the credential record inside its own request.
            let (crecs, cused) = parse_records(&log.client_raw);
            let capp = crecs.iter().filter(|r| r.ctype == CT_APPLICATION_DATA).count();
            if cused != log.client_raw.len() || capp != info.client_handshake_records {
                bail!("client sent records beyond its Finished before the credential record");
            }
            st.hs = hs;
            let th_sh_hex = hex::encode(info.th_sh);
            info!(th_sh=%th_sh_hex, "handshake verified: chain + hostname + CertificateVerify + both Finished");
            st.handshake = Some(info);
            st.hs_secrets = Some(s);
            st.state = SessionState::AwaitKu0;
            side(st, format!("handshake_verified th_sh={th_sh_hex}"));
            send(serde_json::json!({"type":"hs_verified"}));
        }
        ClientMsg::C1Material { s, h1, t0 } => {
            if st.state != SessionState::AwaitC1 || st.c1_params.is_some() {
                bail!("c1_material out of order or repeated");
            }
            let s = hex::decode(&s)?;
            if s.len() != st.head_len + 1 {
                bail!("c1 keystream length {} != |head|+1 {}", s.len(), st.head_len + 1);
            }
            let hs = st.hs_secrets.clone().ok_or_else(|| anyhow!("no hs secrets"))?;
            let info = st.handshake.clone().ok_or_else(|| anyhow!("no handshake"))?;
            let params = Params::PiC1(zkbench::statements::PiC1 {
                session: SessionPublic { client_hs: hs.client_hs, server_hs: hs.server_hs, th_sh: info.th_sh, th_sf: info.th_sf },
                // |head| here is the record plaintext length: the HTTP head plus
                // the TLS 1.3 inner content-type byte.
                head_len: st.head_len + 1,
                s,
                h1: to16(&h1)?,
                t0: to16(&t0)?,
            });
            if app.insecure {
                let hs_raw = st.hs.ok_or_else(|| anyhow!("no hs"))?;
                verify_c1_native(&params, &hs_raw, &info)?;
            }
            shared.params.lock().unwrap().insert("pi_c1".into(), params.clone());
            st.c1_params = Some(params.clone());
            if app.insecure {
                // Test mode: the node checks the advice natively from the
                // disclosed HS and commits to the record it will write.
                let asm = assemble(&app, st, log)?;
                let c_commit = asm.c_commit;
                let header = asm.header;
                st.c_commit = Some(c_commit);
                // Send the template head with the key positions zeroed: the
                // filled head is the API key in the clear.
                let (mut head, _offsets) = placeholder_head(&app.offer.head_template, app.key.len(), st.body_len)?;
                head.push(0x17);
                st.assembled = Some(asm);
                send(serde_json::json!({
                    "type":"c_commit","c_commit":hex::encode(c_commit),
                    "template_head": hex::encode(head), "header": hex::encode(header),
                }));
            } else {
                send(serde_json::json!({"type":"zk_ack","proof":"pi_c1","params":params}));
            }
        }
        ClientMsg::Ku1 { record } => {
            let bytes = hex::decode(&record)?;
            // Full epoch-1 KeyUpdate record: 5-byte header + 22-byte ciphertext
            // (a KeyUpdate handshake message: 5-byte body + 1 inner type + 16 tag).
            if bytes.len() != 27 || bytes[0] != 0x17 || bytes[5] == 0 {
                bail!("KU1 record must be 27 bytes (header + 22-byte KeyUpdate), got {}", bytes.len());
            }
            if st.state != SessionState::AwaitC1 {
                bail!("ku1 out of order");
            }
            let a = st.assembled.as_ref().ok_or_else(|| anyhow!("credential record not assembled (π_C1 not verified)"))?;
            // Atomic write: credential record then KU1.
            tcp_tx.write_all(&a.record).await?;
            tcp_tx.write_all(&bytes).await?;
            st.sent.extend_from_slice(&a.record);
            st.sent.extend_from_slice(&bytes);
            st.state = SessionState::Body;
            info!(record_len = a.record.len(), "credential record + KU1 written to upstream");
            side(st, format!("credential_written len={} c_commit={}", a.record.len(), hex::encode(a.c_commit)));
            send(serde_json::json!({"type":"head_written"}));
        }
        ClientMsg::BodySuffix { suffix } => {
            if st.state != SessionState::Body && st.state != SessionState::Attested {
                bail!("body_suffix out of order");
            }
            if st.c2_requested {
                bail!("duplicate body_suffix");
            }
            if st.body_bytes != st.body_len || st.body_records == 0 {
                bail!("body incomplete ({} of {} bytes)", st.body_bytes, st.body_len);
            }
            let suffix = hex::decode(&suffix)?;
            // The suffix is not the client's choice: it must be exactly the one
            // that pins the setup's model and caps (and the escrow sizing).
            let expect = canonical_suffix(&st.model, st.max_tokens);
            if suffix != expect.as_bytes() {
                bail!("body suffix does not match the canonical suffix for model/max_tokens");
            }
            st.c2_requested = true;
            let last = log.client_app.last().ok_or_else(|| anyhow!("no body record"))?;
            let inner_len = last.payload.len().saturating_sub(16); // drop the GCM tag
            if inner_len == 0 || suffix.len() + 1 > inner_len {
                bail!("suffix does not fit in the last body record");
            }
            // Epoch-2 sequence of the final body record (KU1 is not in client_app).
            let seq = (st.body_records - 1) as u64;
            let (w, off, sel_start) = window(suffix.len(), inner_len);
            let params = Params::PiC2(zkbench::statements::PiC2 {
                session: session_of(st)?,
                seq,
                ct_window: last.payload[off..off + w].to_vec(),
                off,
                w,
                sel_start,
                sel_len: suffix.len(),
                expected: suffix,
            });
            shared.params.lock().unwrap().insert("pi_c2".into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":"pi_c2","params":params}));
        }
        ClientMsg::Disclose { r, tail_lens } => {
            // Only once, and only after the upstream closed: the anchor is the
            // end of the final transcript.
            if st.state != SessionState::Attested || st.disclosed {
                bail!("disclose out of order or repeated");
            }
            st.disclosed = true;
            let r = hex::decode(&r)?;
            // Either the terminal usage event of a successful stream, or (for
            // an upstream error the provider does not bill) the complete HTTP
            // error response. Both are anchored at the end of the transcript.
            let usage = if r.starts_with(b"HTTP/1.") {
                validate_error_response(&r)?
            } else {
                let usage = validate_r(&r)?;
                let umodel = usage.get("model").and_then(|m| m.as_str()).unwrap_or("");
                if umodel != st.model {
                    bail!("usage event model {umodel:?} != pinned model {:?}", st.model);
                }
                usage
            };
            st.usage = Some(usage);
            let info = st.handshake.as_ref().ok_or_else(|| anyhow!("no handshake"))?;
            let response: Vec<&Record> = log
                .server_all
                .iter()
                .filter(|x| x.ctype == CT_APPLICATION_DATA)
                .collect();
            let first_response = info.server_handshake_records;
            // The covered records are the final contiguous application records.
            // Only trailing records of alert size (2 + 1 + 16 = 19 bytes, i.e. a
            // close_notify) may be skipped; nothing in the middle.
            let mut chosen_rev: Vec<(usize, &Record)> = Vec::new();
            let mut j: isize = response.len() as isize - 1;
            if let Some(first_want) = tail_lens.first() {
                while j >= first_response as isize
                    && response[j as usize].payload.len() == 19
                    && response[j as usize].payload.len().saturating_sub(16) != *first_want
                {
                    j -= 1;
                }
            }
            for want in &tail_lens {
                if j >= first_response as isize
                    && response[j as usize].payload.len().saturating_sub(16) != *want
                {
                    bail!("tail record lengths do not match the end of the transcript");
                }
                if j < first_response as isize {
                    bail!("could not locate tail record of ciphertext length {want}");
                }
                chosen_rev.push((j as usize - first_response, response[j as usize]));
                j -= 1;
            }
            let mut chosen = chosen_rev;
            chosen.reverse();
            let total: usize = chosen
                .iter()
                .map(|(_, rec)| rec.payload.len().saturating_sub(16 + 1))
                .sum();
            if total < r.len() {
                bail!("disclosed range ({total}) does not cover R ({})", r.len());
            }
            let records: Vec<zkbench::statements::TailRecord> = chosen
                .iter()
                .map(|(idx, rec)| zkbench::statements::TailRecord {
                    seq: *idx as u64,
                    ct: rec.payload[..rec.payload.len() - 16].to_vec(),
                })
                .collect();
            info!(
                seqs = ?records.iter().map(|x| x.seq).collect::<Vec<_>>(),
                lens = ?records.iter().map(|x| x.ct.len()).collect::<Vec<_>>(),
                r_len = r.len(),
                "pi_c3 records"
            );
            let params = Params::PiC3(zkbench::statements::PiC3 {
                session: session_of(st)?,
                records,
                expected: r,
            });
            shared.params.lock().unwrap().insert("pi_c3".into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":"pi_c3","params":params}));
        }
    }
    Ok(())
}

/// The public JSON suffix that pins every cost-relevant parameter (paper
/// §4.4 / A.2). Last-wins semantics at the provider make these the effective
/// values whatever the private prefix carries.
fn canonical_suffix(model: &str, max_tokens: u64) -> String {
    let m = serde_json::to_string(model).unwrap_or_else(|_| "\"\"".into());
    format!(
        ",\"model\":{m},\"max_tokens\":{max_tokens},\"max_completion_tokens\":{max_tokens},\"n\":1,\"stream\":true,\"stream_options\":{{\"include_usage\":true}},\"venice_parameters\":{{\"include_venice_system_prompt\":false,\"enable_web_search\":\"off\"}}}}"
    )
}

/// Choose a block-aligned window ending at the record end that contains the
/// final `sel_len` content bytes (before the inner content-type byte).
fn window(sel_len: usize, ct_len: usize) -> (usize, usize, usize) {
    let w = (sel_len + 1 + 13).min(ct_len);
    let off = ct_len - w;
    let sel_start = w - 1 - sel_len;
    (w, off, sel_start)
}

fn session_of(st: &Session) -> Result<SessionPublic> {
    let hs = st.hs_secrets.as_ref().ok_or_else(|| anyhow!("no hs secrets"))?;
    let info = st.handshake.as_ref().ok_or_else(|| anyhow!("no handshake"))?;
    Ok(SessionPublic {
        client_hs: hs.client_hs,
        server_hs: hs.server_hs,
        th_sh: info.th_sh,
        th_sf: info.th_sf,
    })
}

fn fill_head_now(app: &Arc<AppState>, st: &Session, _log: &RelayLog) -> Result<(Vec<u8>, Vec<usize>)> {
    let (mut head, offsets) = placeholder_head(&app.offer.head_template, app.key.len(), st.body_len)?;
    for (i, off) in offsets.iter().enumerate() {
        head[*off] = app.key[i];
    }
    Ok((head, offsets))
}

/// Assemble the epoch-1 credential record from π_C1-verified material.
fn assemble(app: &Arc<AppState>, st: &Session, _log: &RelayLog) -> Result<Assembled> {
    let p = match st.c1_params.as_ref() {
        Some(Params::PiC1(p)) => p,
        _ => bail!("no π_C1 material"),
    };
    let (http_head, _) = fill_head_now(app, st, _log)?;
    // TLS 1.3 inner plaintext ends with the application_data content type.
    let mut plain = http_head.clone();
    plain.push(0x17);
    if plain.len() != p.head_len {
        bail!(
            "credential plaintext length {} != π_C1 head_len {}",
            plain.len(),
            p.head_len
        );
    }
    let c1 = xor(&plain, &p.s);
    let header = aesgcm::record_header(c1.len());
    let tag = aesgcm::ghash_tag_input(&p.h1, &header, &c1);
    let tag: Vec<u8> = tag.iter().zip(p.t0.iter()).map(|(a, b)| a ^ b).collect();
    let mut record = header.to_vec();
    record.extend_from_slice(&c1);
    record.extend_from_slice(&tag);
    let mut commit_input = header.to_vec();
    commit_input.extend_from_slice(&c1);
    let c_commit = cu_crypto::transcript::hash(&commit_input);
    Ok(Assembled { record, c_commit, header })
}

fn to32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}
fn to16(s: &str) -> Result<[u8; 16]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow!("expected 16 bytes"))
}

fn verify_c1_native(params: &Params, hs: &[u8; 32], info: &HandshakeInfo) -> Result<()> {
    let Params::PiC1(p) = params else { bail!("not pi_c1") };
    let (c_hs, s_hs) = cu_crypto::keyschedule::handshake_secrets(hs, &info.th_sh);
    let ms = cu_crypto::keyschedule::master_secret(hs);
    let (c_ap_0, _) = cu_crypto::keyschedule::application_secrets(&ms, &info.th_sf);
    let c_ap_1 = cu_crypto::keyschedule::traffic_update(&c_ap_0);
    if c_hs.as_bytes() != &p.session.client_hs || s_hs.as_bytes() != &p.session.server_hs {
        bail!("insecure π_C1: session secrets mismatch");
    }
    let k1 = c_ap_1.key();
    let iv1 = c_ap_1.iv();
    if aesgcm::ctr_keystream(&k1, &iv1, 0, p.head_len) != p.s {
        bail!("insecure π_C1: S mismatch");
    }
    if aesgcm::ghash_key(&k1) != p.h1 {
        bail!("insecure π_C1: H1 mismatch");
    }
    if aesgcm::aes128_encrypt_block(&k1, &aesgcm::j0(&iv1, 0)) != p.t0 {
        bail!("insecure π_C1: T0 mismatch");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// /zk
// ---------------------------------------------------------------------------

async fn zk_ws(
    ws: WebSocketUpgrade,
    Query(q): Query<HashMap<String, String>>,
    State(app): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| zk_handler(socket, q, app))
}

async fn zk_handler(socket: WebSocket, q: HashMap<String, String>, app: Arc<AppState>) {
    let proof = q.get("proof").cloned().unwrap_or_default();
    let sid = q.get("sid").cloned().unwrap_or_default();
    if let Err(e) = zk_inner(socket, &proof, &sid, &app).await {
        warn!(proof, error = %e, "zk session failed");
        if let Some(s) = app.sessions.lock().unwrap().get(&sid).cloned() {
            let _ = s.evt.send(Ev::ZkDone { proof, ok: false, err: Some(e.to_string()), params: None });
        }
    }
}

async fn zk_inner(socket: WebSocket, proof: &str, sid: &str, app: &Arc<AppState>) -> Result<()> {
    let started = std::time::Instant::now();
    info!(proof, sid, "zk start");
    let shared = app.sessions.lock().unwrap().get(sid).cloned().ok_or_else(|| anyhow!("unknown sid"))?;
    let params = shared.params.lock().unwrap().get(proof).cloned().ok_or_else(|| anyhow!("no params for {proof}"))?;
    let (role, witness) = match proof {
        "pi_n" => (Role::Prover, Some(Witness::Key(shared.key.to_vec()))),
        _ => (Role::Verifier, None),
    };
    let (io, bridge) = ws_duplex(socket);
    // One proof at a time per session (see SessionShared::zk_lock).
    let _guard = shared.zk_lock.lock().await;
    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        zkbench::proofs::run_io(io, role, &params, witness.as_ref()),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            warn!(proof, "zk proof timed out (30s)");
            Err(anyhow!("zk proof timed out after 30s"))
        }
    };
    // `run_io` dropped its endpoint; drain the outbound pump into the socket
    // before the handler returns and the WebSocket closes, or the verifier's
    // final message can be lost and the prover stalls until its timeout.
    bridge.finish().await;
    info!(proof, elapsed_ms = started.elapsed().as_millis() as u64, "zk end");
    let (ok, err) = match &result {
        Ok(checks) => (checks.iter().all(|c| c.ok), None),
        Err(e) => (false, Some(e.to_string())),
    };
    let _ = shared.evt.send(Ev::ZkDone { proof: proof.to_string(), ok, err, params: Some(params) });
    result.map(|_| ())
}

// ---------------------------------------------------------------------------
// R validation (§5) and settlement
// ---------------------------------------------------------------------------

/// A disclosed *complete* upstream HTTP error response (status >= 400).
///
/// Sound for the same reason as the usage disclosure: the raw status line and
/// CRLF-delimited header block cannot be produced by model output (JSON
/// strings carry no raw CR/LF), and the disclosure must end exactly at the end
/// of the relayed transcript with the body framing complete. Returns a usage
/// value with `error_status`, which the node settles at zero cost.
fn validate_error_response(r: &[u8]) -> Result<serde_json::Value> {
    let he = r
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("error R: no header terminator"))?;
    let head = std::str::from_utf8(&r[..he]).context("error R: head not utf8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let (ver, code) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !(ver == "HTTP/1.1" || ver == "HTTP/1.0") || code.len() != 3 {
        bail!("error R: malformed status line");
    }
    let status: u16 = code.parse().context("error R: status not numeric")?;
    if status < 400 {
        bail!("error R: status {status} is not an error");
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        let (k, v) = l.split_once(':').ok_or_else(|| anyhow!("error R: malformed header"))?;
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = Some(v.trim().parse().context("error R: bad content-length")?),
            "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let body = &r[he + 4..];
    if chunked {
        // Reuse the chunk walker: it requires the terminal chunk to end R.
        let mut off = 0usize;
        loop {
            let nl = body[off..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| anyhow!("error R: missing chunk-size CRLF"))?;
            let line = std::str::from_utf8(&body[off..off + nl]).context("error R: chunk size")?;
            let len = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .context("error R: bad chunk size")?;
            off += nl + 2;
            if len == 0 {
                if body.len() != off + 2 || &body[off..] != b"\r\n" {
                    bail!("error R: terminal chunk not at the end");
                }
                break;
            }
            if body.len() < off + len + 2 || &body[off + len..off + len + 2] != b"\r\n" {
                bail!("error R: chunk overruns the disclosure");
            }
            off += len + 2;
        }
    } else {
        let cl = content_length.ok_or_else(|| anyhow!("error R: no body framing"))?;
        if body.len() != cl {
            bail!("error R: body length {} != content-length {cl}", body.len());
        }
    }
    Ok(serde_json::json!({ "error_status": status, "choices": [] }))
}

fn validate_r(r: &[u8]) -> Result<serde_json::Value> {
    let mut off = 0usize;
    let mut data = Vec::new();
    loop {
        let nl = r[off..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("R: missing chunk-size CRLF"))?;
        let line = std::str::from_utf8(&r[off..off + nl]).context("R: chunk size not utf8")?;
        let len = usize::from_str_radix(line.trim(), 16)
            .with_context(|| format!("R: bad chunk size {line:?}"))?;
        off += nl + 2;
        if len == 0 {
            if r.len() < off + 2 || &r[off..off + 2] != b"\r\n" {
                bail!("R: terminal chunk not aligned with end of plaintext");
            }
            if off + 2 != r.len() {
                bail!("R: trailing bytes after terminal chunk");
            }
            break;
        }
        if r.len() < off + len + 2 {
            bail!("R: chunk extends past the disclosed range");
        }
        data.extend_from_slice(&r[off..off + len]);
        off += len;
        if &r[off..off + 2] != b"\r\n" {
            bail!("R: chunk data not terminated");
        }
        off += 2;
    }
    let text = String::from_utf8(data).context("R: dechunked data not utf8")?;
    if !text.ends_with("data: [DONE]\n\n") {
        bail!("R: dechunked tail does not end with data: [DONE]");
    }
    let before = &text[..text.len() - "data: [DONE]\n\n".len()];
    let start = before.rfind("data: ").map(|i| i + 6).unwrap_or(0);
    let ev = before[start..].trim();
    let v: serde_json::Value = serde_json::from_str(ev).context("R: usage event not JSON")?;
    let empty_choices = v
        .get("choices")
        .and_then(|c| c.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(false);
    if !empty_choices {
        bail!("R: usage event has non-empty choices");
    }
    if v.pointer("/usage/prompt_tokens").is_none() || v.pointer("/usage/completion_tokens").is_none() {
        bail!("R: usage event missing token counts");
    }
    Ok(v)
}

fn settle(app: &Arc<AppState>, st: &Session) -> Option<serde_json::Value> {
    let sid = st.sid.clone()?;
    let usage = st.usage.clone().unwrap_or(serde_json::json!({}));
    // Pricing stub: Venice's own `cost.usd` if present, else 0. Escrow E is a
    // plain integer (stub), so refund = E - cost is bounded by the stub escrow.
    let cost_usd = usage
        .pointer("/cost/usd")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0);
    let model = usage
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("mistral-small-3-2-24b-instruct")
        .to_string();
    let receipt = serde_json::json!({
        "sid": sid,
        "usage": usage,
        "model": model,
        "cost_usd": cost_usd,
        "cost_diem": usage.pointer("/cost/diem").cloned().unwrap_or(serde_json::json!(0)),
        "refund_diem": (1000.0 - cost_usd * 1e6).max(0.0),
        "attestation_hash": st.attestation.as_ref().map(|a| hex::encode(cu_crypto::transcript::hash(a.to_string().as_bytes()))),
        "notary_pubkey": app.offer.notary_pubkey,
        "time": now_unix(),
    });
    Some(receipt)
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

fn init_run_dir(app: &Arc<AppState>, sid: &str) -> Result<std::path::PathBuf> {
    let dir = app.runs_dir.join(sid);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_attestation(dir: &Option<std::path::PathBuf>, a: &serde_json::Value) {
    if let Some(dir) = dir {
        let _ = std::fs::write(dir.join("attestation.json"), serde_json::to_string_pretty(a).unwrap_or_default());
    }
}

fn write_receipt(dir: &Option<std::path::PathBuf>, r: &serde_json::Value) {
    if let Some(dir) = dir {
        let _ = std::fs::write(dir.join("receipt.json"), serde_json::to_string_pretty(r).unwrap_or_default());
    }
}
