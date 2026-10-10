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
mod tls_v2;
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
    /// Protocol version: 1 (paper §4) or 2 (two-party handshake, docs/TWOPC-DESIGN.md).
    #[serde(default = "default_protocol")]
    v: u8,
    upstream_host: String,
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
    /// Optional model allowlist; empty = every model the node serves through
    /// `upstream_host`. Models and prices come from the node, which signs
    /// the offer clients see (this file carries no prices). A list of ids;
    /// the earlier name `text_only_ok` (a map `{id: true}`) is accepted too.
    /// It was a modality gate while escrow priced the prompt by the body
    /// length; the node now reserves a full-context prompt, which bounds
    /// image parts as well, so the shipped offer leaves it empty.
    #[serde(default, alias = "text_only_ok", deserialize_with = "de_model_allowlist")]
    model_allowlist: Vec<String>,
}

/// `["id", …]`, or the legacy `{"id": true, …}` map (entries marked true).
fn de_model_allowlist<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Allow {
        List(Vec<String>),
        Map(HashMap<String, bool>),
    }
    let mut ids = match Allow::deserialize(d)? {
        Allow::List(v) => v,
        Allow::Map(m) => m.into_iter().filter(|(_, ok)| *ok).map(|(id, _)| id).collect(),
    };
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn default_protocol() -> u8 {
    1
}

fn default_key_alphabet() -> String {
    "[A-Za-z0-9_-]".to_string()
}

fn default_max_tokens_cap() -> u64 {
    4096
}

fn default_head_template_for(host: &str, key_len: usize) -> String {
    format!(
        "POST /api/v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {{KEY:{key_len}}}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {{LEN}}\r\n\r\n"
    )
}

/// Point the template's `{KEY:N}` token at the loaded key's real length.
fn with_key_length(template: &str, key_len: usize) -> String {
    match (template.find("{KEY:"), template.find("{KEY:").and_then(|i| template[i..].find('}').map(|j| i + j))) {
        (Some(start), Some(end)) => format!("{}{{KEY:{key_len}}}{}", &template[..start], &template[end + 1..]),
        _ => template.to_string(),
    }
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
    /// Concurrent sessions; a session holds a slot from setup to close.
    slots: Arc<tokio::sync::Semaphore>,
    /// Largest request body (`setup.len`) a session may declare.
    max_body: usize,
}

/// A session must send its `setup` this soon after connecting.
const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Hard limit on one session's lifetime (handshake to settlement).
const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// Largest TLS 1.3 record on the wire: header + 2^14 plaintext + 256 expansion.
const MAX_TLS_RECORD: usize = 5 + (1 << 14) + 256;

/// Most client bytes a v2 session buffers before relaying them (during the 2PC
/// preprocessing and until the credential record is written): the ClientHello,
/// CCS and Finished, then a body of `body_len` bytes in full-size records with
/// the suffix in its own record. Anything beyond is not an honest client.
fn client_buffer_cap(body_len: usize) -> usize {
    body_len + body_len / 256 + 4 * MAX_TLS_RECORD
}

/// Append client bytes to a pre-relay buffer, failing once it exceeds the cap.
fn buffer_client(buf: &mut Vec<u8>, data: &[u8], body_len: usize) -> Result<()> {
    if buf.len() + data.len() > client_buffer_cap(body_len) {
        bail!("client sent more than {} bytes before they could be relayed", client_buffer_cap(body_len));
    }
    buf.extend_from_slice(data);
    Ok(())
}

#[derive(Debug)]
enum Ev {
    ServerBytes(Vec<u8>),
    /// v2: the joint P-256 key share P = P_C + P_N.
    KeyShare([u8; 65]),
    /// v2: the handshake traffic secrets from 2PC phase A.
    Hs(HsSecrets),
    /// v2: N's outputs of 2PC phase B.
    Ap(Box<ApN>),
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

/// v2: N's outputs of the two-party key schedule (K_0/IV_0 never leave N).
#[derive(Debug)]
struct ApN {
    k0: Zeroizing<[u8; 16]>,
    iv0: Zeroizing<[u8; 12]>,
    h1: [u8; 32],
    h2: [u8; 32],
    hk: [u8; 32],
}

/// v2: what the session hands the 2PC task once U's messages arrive.
#[derive(Debug)]
enum TwoPcCmd {
    Handshake { server_share: [u8; 65], th_sh: [u8; 32] },
    App { th_sf: [u8; 32] },
}

struct SessionShared {
    params: StdMutex<HashMap<String, Params>>,
    /// v2: the command channel of this session's 2PC (taken by `/zk?proof=twopc`).
    twopc_rx: StdMutex<Option<mpsc::UnboundedReceiver<TwoPcCmd>>>,
    /// v2: N's epoch-0 key and IV, for the π_N witness.
    k0_iv0: StdMutex<Option<Zeroizing<Vec<u8>>>>,
    key: Arc<Zeroizing<Vec<u8>>>,
    evt: mpsc::UnboundedSender<Ev>,
    insecure: bool,
    /// Serializes the ZK proofs of one session. The client may run π_C2
    /// concurrently with generation and start π_C3 before π_C2 has finished;
    /// running two mpz proofs at once on one node stalls (the VOLE/rayon paths
    /// contend). Proofs are per-session independent, so serializing inside a
    /// session costs nothing on the critical path and removes the contention.
    zk_lock: tokio::sync::Mutex<()>,
    /// v2: the session's proof channel (`/zk?proof=zkchan`) was opened.
    zkchan_taken: std::sync::atomic::AtomicBool,
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
    let max_sessions: usize = arg("--max-sessions").map(|v| v.parse()).transpose()?.unwrap_or(32);
    let max_body: usize = arg("--max-body").map(|v| v.parse()).transpose()?.unwrap_or(8 << 20);
    let runs_dir = arg("--runs-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../runs")
        });

    let raw_key = std::env::var(&key_env).with_context(|| format!("{key_env} is not set"))?;
    let key = Zeroizing::new(raw_key.into_bytes());
    // The key length is a proof parameter (the head template's `{KEY:L}`), and
    // π_N/π_NK prove membership in one fixed alphabet; a key outside either
    // cannot be proven, so refuse to start (never printing the key).
    if !(16..=256).contains(&key.len()) {
        bail!("unexpected key length {} (expected 16..=256)", key.len());
    }
    if !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-') {
        bail!("the upstream key has characters outside [A-Za-z0-9_-]; π_N cannot prove it");
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
            v: 1,
            upstream_host: host.clone(),
            head_template: default_head_template_for(&host, key.len()),
            key_alphabet: default_key_alphabet(),
            key_length: key.len(),
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
            model_allowlist: Vec::new(),
        }
    };
    match arg("--protocol").as_deref() {
        None => {}
        Some("1") => offer.v = 1,
        Some("2") => offer.v = 2,
        Some(other) => bail!("unsupported --protocol {other}"),
    }
    if offer.v == 2 && insecure {
        bail!("--insecure-no-proofs is a v1 test mode");
    }
    if offer.upstream_host.is_empty() {
        offer.upstream_host = host.clone();
    }
    if offer.head_template.is_empty() {
        offer.head_template = default_head_template_for(&offer.upstream_host, key.len());
    }
    offer.head_template = with_key_length(&offer.head_template, key.len());
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
        slots: Arc::new(tokio::sync::Semaphore::new(max_sessions)),
        max_body,
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
        /// Ciphertext lengths of the trailing content records that cover R
        /// (and `skip`), ordered from the end (to locate them unambiguously).
        tail_lens: Vec<usize>,
        /// Content bytes between the end of R and the end of the response:
        /// 0 for a usage event; for an upstream error R is only the response
        /// head and `skip` is the undisclosed body length after it.
        #[serde(default)]
        skip: usize,
    },
    Ku1 {
        record: String,
    },
    /// v2: the client verified π_NK and claims the session; N writes the
    /// credential record and the KeyUpdate under K_0.
    ReleaseHead {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SessionState {
    #[default]
    Handshake,
    AwaitKu0,
    AwaitC1,
    /// v2: the client Finished is relayed; client records are held until N
    /// has written the credential record and the KeyUpdate.
    AwaitHead,
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
    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<Ev>();
    let (twopc_tx, twopc_rx) = mpsc::unbounded_channel::<TwoPcCmd>();
    let shared = Arc::new(SessionShared {
        params: StdMutex::new(HashMap::new()),
        twopc_rx: StdMutex::new((app.offer.v == 2).then_some(twopc_rx)),
        k0_iv0: StdMutex::new(None),
        key: app.key.clone(),
        evt: evt_tx.clone(),
        insecure: app.insecure,
        zk_lock: tokio::sync::Mutex::new(()),
        zkchan_taken: std::sync::atomic::AtomicBool::new(false),
    });

    let send_task = tokio::spawn(async move {
        while let Some(m) = from_client.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    let mut st = Session { v2: app.offer.v == 2, twopc_tx: Some(twopc_tx), ..Session::default() };
    let mut log = RelayLog::default();
    let mut client_pending: Vec<u8> = Vec::new();
    let mut server_pending: Vec<u8> = Vec::new();

    let result: Result<()> = async {
    // Nothing reaches the upstream before a valid setup: an idle or malformed
    // connection costs no provider socket.
    let first = match tokio::time::timeout(SETUP_TIMEOUT, ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t,
        Ok(_) => bail!("expected a setup frame"),
        Err(_) => bail!("no setup within {}s", SETUP_TIMEOUT.as_secs()),
    };
    let setup: ClientMsg = serde_json::from_str(&first).map_err(|e| anyhow!("bad setup: {e}"))?;
    let _slot = app
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("sidecar at capacity; retry later"))?;
    handle_setup(setup, &app, &shared, &to_client, &mut st)?;

    // v2: the 2PC preprocessing (tens of MB over the client's link) runs before
    // the ClientHello exists, and a pre-warmed session then waits for a request.
    // The provider closes an idle connection within seconds (Cloudflare: ~15 s
    // with no ClientHello), so dial it only when the client's ClientHello
    // arrives, after the joint key share is ready.
    if st.v2 {
        let prep = tokio::time::sleep(TWOPC_TIMEOUT);
        tokio::pin!(prep);
        let armed = tokio::time::sleep(SESSION_TIMEOUT);
        tokio::pin!(armed);
        while st.joint.is_none() || client_pending.is_empty() {
            tokio::select! {
                _ = &mut prep, if st.joint.is_none() => bail!("2PC preprocessing did not finish within {}s", TWOPC_TIMEOUT.as_secs()),
                _ = &mut armed => bail!("pre-warmed session unused for {}s", SESSION_TIMEOUT.as_secs()),
                ev = evt_rx.recv() => match ev {
                    Some(Ev::KeyShare(p)) if st.joint.is_none() => {
                        st.joint = Some(p);
                        side(&mut st, "2pc key share ready".into());
                    }
                    Some(Ev::ZkDone { proof, err, .. }) => bail!("{proof} failed before the handshake: {err:?}"),
                    Some(other) => bail!("unexpected event before the key share: {other:?}"),
                    None => bail!("session events closed"),
                },
                msg = ws_rx.next() => match msg {
                    Some(Ok(Message::Binary(data))) => {
                        buffer_client(&mut client_pending, &data, st.body_len)?;
                        log.client_raw.extend_from_slice(&data);
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => bail!("client left before the handshake"),
                    Some(Ok(Message::Text(_))) => bail!("unexpected control message during 2PC preprocessing"),
                    _ => {}
                },
            }
        }
    }

    let tcp = TcpStream::connect(&app.upstream)
        .await
        .with_context(|| format!("connecting to {}", app.upstream))?;
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
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

    if st.v2 {
        v2_pump_client(&mut st, &mut client_pending, &mut tcp_tx).await?;
    }

    let deadline = tokio::time::sleep(SESSION_TIMEOUT);
    tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => bail!("session time limit ({}s) reached", SESSION_TIMEOUT.as_secs()),
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
                    Message::Binary(data) if st.v2 => {
                        if st.sid.is_none() {
                            bail!("TLS bytes before setup");
                        }
                        log.client_raw.extend_from_slice(&data);
                        match st.state {
                            SessionState::Handshake => {
                                buffer_client(&mut client_pending, &data, st.body_len)?;
                                v2_pump_client(&mut st, &mut client_pending, &mut tcp_tx).await?;
                            }
                            SessionState::AwaitHead => buffer_client(&mut st.held_client, &data, st.body_len)?,
                            SessionState::Body => {
                                client_pending.extend_from_slice(&data);
                                relay_body(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;
                            }
                            _ => bail!("unexpected client record in state {:?}", st.state),
                        }
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
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
                                client_pending.extend_from_slice(&data);
                                log.client_raw.extend_from_slice(&data);
                                relay_body(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;
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
                        if st.v2 {
                            v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                        }
                    }
                    Ev::KeyShare(p) => {
                        if !st.v2 || st.joint.is_some() { bail!("unexpected key share"); }
                        st.joint = Some(p);
                        side(&mut st, "2pc key share ready".into());
                        v2_pump_client(&mut st, &mut client_pending, &mut tcp_tx).await?;
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::Hs(s) => {
                        if !st.v2 || st.hs_secrets.is_some() { bail!("unexpected handshake secrets"); }
                        st.hs_secrets = Some(s);
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::Ap(ap) => {
                        if !st.v2 || st.ap.is_some() { bail!("unexpected 2PC application output"); }
                        let mut kiv = Zeroizing::new(ap.k0.to_vec());
                        kiv.extend_from_slice(&ap.iv0[..]);
                        *shared.k0_iv0.lock().unwrap() = Some(kiv);
                        st.ap = Some(ap);
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
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
                            "pi_c2" | "pi_c2s" => {
                                let same = match (&proven, shared.params.lock().unwrap().get(proof.as_str())) {
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
                            "pi_c3" | "pi_c3s" => {
                                if st.state == SessionState::Settled {
                                    continue;
                                }
                                if !st.c2_ok {
                                    bail!("π_C3 before π_C2 verified: the suffix (model, caps) is not proven");
                                }
                                let same = match (&proven, shared.params.lock().unwrap().get(proof.as_str())) {
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
    // The session is over: its proofs can no longer run.
    if let Some(sid) = &st.sid {
        app.sessions.lock().unwrap().remove(sid);
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
    /// Protocol v2 (two-party handshake).
    v2: bool,
    twopc_tx: Option<mpsc::UnboundedSender<TwoPcCmd>>,
    joint: Option<[u8; 65]>,
    ch_checked: bool,
    hs_cmd_sent: bool,
    app_cmd_sent: bool,
    ap: Option<Box<ApN>>,
    /// v2: client bytes after its Finished, held until the head is written.
    held_client: Vec<u8>,
    /// v2: the KeyUpdate record N writes after the credential record.
    ku_record: Option<Vec<u8>>,
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

/// The session's first frame. Validated and bound to a sid before the
/// sidecar opens any connection to the upstream.
fn handle_setup(
    msg: ClientMsg,
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
) -> Result<()> {
    let send = |v: serde_json::Value| {
        let _ = to_client.send(Message::Text(v.to_string().into()));
    };
    let ClientMsg::Setup { nonce_c, model, max_tokens, len, escrow_e, escrow, armed } = msg else {
        bail!("expected a setup frame");
    };
    if st.sid.is_some() || st.state != SessionState::Handshake {
        bail!("duplicate setup");
    }
    if model.is_empty() || max_tokens == 0 {
        bail!("setup needs a model and max_tokens >= 1");
    }
    if len == 0 || len > app.max_body {
        bail!("declared body length {len} outside 1..={}", app.max_body);
    }
    if hex::decode(&nonce_c).map(|n| n.len()).unwrap_or(0) != 32 {
        bail!("nonce_c must be 32 bytes of hex");
    }
    if max_tokens > app.offer.max_tokens_cap {
        bail!("max_tokens {max_tokens} exceeds cap {}", app.offer.max_tokens_cap);
    }
    // The operator's optional allowlist (empty = all; the node applies the same list).
    if !app.offer.model_allowlist.is_empty() && !app.offer.model_allowlist.contains(&model) {
        bail!("model {model:?} is not in the offer's model_allowlist");
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
        "pubkey":app.offer.notary_pubkey,"head_len":head.len(),
        "suffix": canonical_suffix(&model, max_tokens),
        "armed": armed,
        "v": app.offer.v,
    }));
    Ok(())
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
        // Handled once, before the upstream connection exists (handle_setup).
        ClientMsg::Setup { .. } => bail!("duplicate setup"),
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
        ClientMsg::ReleaseHead {} => {
            if !st.v2 || st.state != SessionState::AwaitHead {
                bail!("release_head out of order");
            }
            let a = st.assembled.as_ref().ok_or_else(|| anyhow!("credential record not assembled"))?;
            let ku = st.ku_record.clone().ok_or_else(|| anyhow!("no KeyUpdate record"))?;
            // Atomic write: epoch-0 seq 0 (credential) then seq 1 (KeyUpdate).
            let mut out = a.record.clone();
            out.extend_from_slice(&ku);
            tcp_tx.write_all(&out).await?;
            st.sent.extend_from_slice(&out);
            let (len, commit) = (a.record.len(), hex::encode(a.c_commit));
            st.state = SessionState::Body;
            info!(record_len = len, "credential record + KeyUpdate written to upstream (epoch 0)");
            side(st, format!("credential_written len={len} c_commit={commit}"));
            send(serde_json::json!({"type":"head_written"}));
            let mut held = std::mem::take(&mut st.held_client);
            relay_body(st, log, &mut held, tcp_tx).await?;
            if !held.is_empty() {
                st.held_client = held;
                bail!("partial client record buffered across the head write");
            }
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
            let ct_window = last.payload[off..off + w].to_vec();
            let params = if st.v2 {
                let ap = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?;
                Params::PiC2S(zkbench::statements::PiC2S {
                    h1: ap.h1, seq, ct_window, off, w, sel_start, sel_len: suffix.len(), expected: suffix,
                })
            } else {
                Params::PiC2(zkbench::statements::PiC2 {
                    session: session_of(st)?, seq, ct_window, off, w, sel_start, sel_len: suffix.len(), expected: suffix,
                })
            };
            let name = if st.v2 { "pi_c2s" } else { "pi_c2" };
            shared.params.lock().unwrap().insert(name.into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":name,"params":params}));
        }
        ClientMsg::Disclose { r, tail_lens, skip } => {
            // Only once, and only after the upstream closed: the anchor is the
            // end of the final transcript.
            if st.state != SessionState::Attested || st.disclosed {
                bail!("disclose out of order or repeated");
            }
            st.disclosed = true;
            let r = hex::decode(&r)?;
            // Either the terminal usage event of a successful stream (anchored
            // at the end of the transcript), or, for an upstream error, only the
            // response head: its status decides the charge, the body stays
            // private (it sits in the `skip` bytes after the head).
            let usage = if r.starts_with(b"HTTP/1.") {
                validate_error_head(&r)?
            } else {
                if skip != 0 {
                    bail!("a usage disclosure must end the transcript (skip = {skip})");
                }
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
            // Only one trailing record of alert size (2 + 1 + 16 = 19 bytes, i.e.
            // a close_notify) may be skipped; nothing in the middle.
            let mut chosen_rev: Vec<(usize, &Record)> = Vec::new();
            let mut j: isize = response.len() as isize - 1;
            if let Some(first_want) = tail_lens.first() {
                if j >= first_response as isize
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
            let need = r.len().checked_add(skip).ok_or_else(|| anyhow!("skip overflow"))?;
            if total < need {
                bail!("disclosed records ({total}) do not cover R + skip ({need})");
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
            let params = if st.v2 {
                let ap = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?;
                Params::PiC3S(zkbench::statements::PiC3S { h2: ap.h2, records, expected: r, skip })
            } else {
                Params::PiC3(zkbench::statements::PiC3 { session: session_of(st)?, records, expected: r, skip })
            };
            let name = if st.v2 { "pi_c3s" } else { "pi_c3" };
            shared.params.lock().unwrap().insert(name.into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":name,"params":params}));
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

/// Relay complete body records from `buf` (leaving a partial one in it). The
/// body plaintext must be exactly the declared length, and the record that
/// completes it (the pinned suffix) is held until π_C2 verifies.
async fn relay_body(
    st: &mut Session,
    log: &mut RelayLog,
    buf: &mut Vec<u8>,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let (recs, used) = parse_records(buf);
    for r in recs {
        // Bytes past the declared Content-Length would be a smuggled second
        // request, and records after the proven final record would let the
        // proven suffix not be the body's tail.
        if r.ctype != CT_APPLICATION_DATA || r.payload.len() < 18 {
            bail!("unexpected body record");
        }
        let content = r.payload.len() - 17;
        if st.body_bytes + content > st.body_len {
            bail!("client body exceeds declared length {}", st.body_len);
        }
        st.body_bytes += content;
        st.body_records += 1;
        if st.body_bytes == st.body_len {
            // The upstream cannot start inference without the full body, so a
            // client that swaps the model or caps is stopped before it costs
            // anything.
            st.held = Some(r.bytes());
            info!("final body record held until π_C2 verifies");
        } else {
            tcp_tx.write_all(&r.bytes()).await?;
            st.sent.extend_from_slice(&r.bytes());
        }
        log.client_app.push(r);
    }
    buf.drain(..used);
    Ok(())
}

/// v2, before the client Finished: relay the ClientHello only once the joint
/// key share is known and the hello offers exactly that share (else C could
/// complete the handshake alone), then CCS and the client Finished. Anything
/// after the Finished waits for the credential record.
async fn v2_pump_client(
    st: &mut Session,
    pending: &mut Vec<u8>,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    if st.state != SessionState::Handshake {
        return Ok(());
    }
    loop {
        let (recs, _) = parse_records(pending);
        let Some(r) = recs.into_iter().next() else { return Ok(()) };
        let n = 5 + r.payload.len();
        if !st.ch_checked {
            let Some(joint) = st.joint else { return Ok(()) }; // wait for the 2PC
            if r.ctype != tls::CT_HANDSHAKE {
                bail!("first client record must be the ClientHello");
            }
            let msgs = tls::parse_handshake_messages(&r.payload);
            let [(ty, msg)] = msgs.as_slice() else { bail!("ClientHello must be one message in one record") };
            if *ty != tls::HS_CLIENT_HELLO || msg.len() != r.payload.len() {
                bail!("first client record must be exactly the ClientHello");
            }
            tls_v2::check_client_hello(msg, &joint)?;
            st.ch_checked = true;
            info!("v2 ClientHello checked: one P-256 share, the joint key");
        } else if r.ctype == tls::CT_CHANGE_CIPHER_SPEC {
            // relayed as is
        } else if r.ctype == CT_APPLICATION_DATA {
            // The client Finished (one encrypted record); then C waits for N.
            st.state = SessionState::AwaitHead;
        } else {
            bail!("unexpected client record type {} during the v2 handshake", r.ctype);
        }
        tcp_tx.write_all(&pending[..n]).await?;
        st.sent.extend_from_slice(&pending[..n]);
        pending.drain(..n);
        if st.state == SessionState::AwaitHead {
            st.held_client.append(pending);
            return Ok(());
        }
    }
}

/// v2: advance the joint handshake as U's messages and the 2PC outputs arrive.
async fn v2_progress(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &mut RelayLog,
) -> Result<()> {
    let Some((ch, sh)) = tls_v2::hellos(&log.client_raw, &log.server_raw) else { return Ok(()) };
    if !st.ch_checked {
        return Ok(());
    }
    let cmd = st.twopc_tx.clone().ok_or_else(|| anyhow!("no 2PC channel"))?;
    if !st.hs_cmd_sent {
        let server_share = tls_v2::server_hello_share(&sh)?;
        cmd.send(TwoPcCmd::Handshake { server_share, th_sh: tls_v2::th_sh(&ch, &sh) })
            .map_err(|_| anyhow!("2PC task gone"))?;
        st.hs_cmd_sent = true;
    }
    let Some(hs) = st.hs_secrets.clone() else { return Ok(()) };
    if !st.app_cmd_sent {
        let Some(th_sf) = tls_v2::th_sf(&ch, &sh, &log.server_raw, &hs.server_hs)? else { return Ok(()) };
        cmd.send(TwoPcCmd::App { th_sf }).map_err(|_| anyhow!("2PC task gone"))?;
        st.app_cmd_sent = true;
    }
    if st.handshake.is_none() && st.state == SessionState::AwaitHead {
        // The full fail-closed check (chain, hostname, CertificateVerify, both
        // Finished) before anything is written under K_0.
        let info = verify_handshake(&log.client_raw, &log.server_raw, &hs, &app.host)?;
        info!(th_sh = %hex::encode(info.th_sh), "v2 handshake verified: chain + hostname + CertificateVerify + both Finished");
        side(st, format!("handshake_verified th_sh={}", hex::encode(info.th_sh)));
        st.handshake = Some(info);
        let _ = to_client.send(Message::Text(serde_json::json!({"type":"hs_verified"}).to_string().into()));
    }
    if st.assembled.is_none() && st.handshake.is_some() {
        let Some(ap) = st.ap.as_ref() else { return Ok(()) };
        let (head, offsets) = fill_head_now(app, st)?;
        let rec = tls_v2::seal_record(&ap.k0, &ap.iv0, 0, &head, CT_APPLICATION_DATA);
        let header: [u8; 5] = rec[..5].try_into()?;
        let c_commit = cu_crypto::transcript::hash(&rec[..rec.len() - 16]);
        st.ku_record = Some(tls_v2::seal_record(&ap.k0, &ap.iv0, 1, &tls_v2::KEY_UPDATE_NOT_REQUESTED, tls::CT_HANDSHAKE));
        let (template, _) = placeholder_head(&app.offer.head_template, app.key.len(), st.body_len)?;
        let params = Params::PiNK(zkbench::statements::PiNK {
            hk: ap.hk,
            head_len: st.head_len,
            key_len: app.key.len(),
            key_alphabet: app.offer.key_alphabet.clone(),
            key_offsets: offsets,
            template,
            c_commit,
            header,
        });
        shared.params.lock().unwrap().insert("pi_nk".into(), params.clone());
        st.c_commit = Some(c_commit);
        st.assembled = Some(Assembled { record: rec, c_commit, header });
        let _ = to_client.send(Message::Text(serde_json::json!({
            "type":"c_commit","params": params, "c_commit": hex::encode(c_commit),
            "h1": hex::encode(ap.h1), "h2": hex::encode(ap.h2), "hk": hex::encode(ap.hk),
        }).to_string().into()));
        info!("v2 credential record assembled under K_0; π_NK params sent");
    }
    Ok(())
}

/// Limit on one session's 2PC preprocessing and key share (the session may
/// then stay armed, waiting for a request, up to `SESSION_TIMEOUT`).
const TWOPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// N's side of the two-party key schedule, driven by the session task.
async fn run_twopc_n<Io>(io: Io, mut rx: mpsc::UnboundedReceiver<TwoPcCmd>, evt: mpsc::UnboundedSender<Ev>) -> Result<()>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    let mut party = twopc::Party::new(twopc::Role::N, io).await?;
    let joint = tokio::time::timeout(TWOPC_TIMEOUT, async {
        party.preprocess().await?;
        party.key_share().await
    })
    .await
    .map_err(|_| anyhow!("2PC preprocessing timed out"))??;
    let _ = evt.send(Ev::KeyShare(joint));
    let Some(TwoPcCmd::Handshake { server_share, th_sh }) = rx.recv().await else {
        bail!("session ended before the ServerHello");
    };
    let hs = party.handshake(&server_share, th_sh).await?;
    let _ = evt.send(Ev::Hs(HsSecrets { client_hs: hs.c_hs, server_hs: hs.s_hs }));
    let Some(TwoPcCmd::App { th_sf }) = rx.recv().await else {
        bail!("session ended before the server Finished");
    };
    match party.application(th_sf).await? {
        twopc::ApOut::N { k0, iv0, h1, h2, hk } => {
            let _ = evt.send(Ev::Ap(Box::new(ApN { k0: Zeroizing::new(k0), iv0: Zeroizing::new(iv0), h1, h2, hk })));
        }
        _ => bail!("2PC returned the client's outputs to the node"),
    }
    let steps: Vec<String> = party.take_timings().iter().map(|t| format!("{}={}ms", t.step, t.ms)).collect();
    info!(steps = %steps.join(" "), "2pc done");
    party.close().await;
    Ok(())
}

fn fill_head_now(app: &Arc<AppState>, st: &Session) -> Result<(Vec<u8>, Vec<usize>)> {
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
    let (http_head, _) = fill_head_now(app, st)?;
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
        // A proof channel that fails outside a proof (setup, idle, transport)
        // reports nothing: the session goes on and the client falls back to
        // the per-proof path. A failed proof on it reported its own ZkDone.
        if proof == "zkchan" {
            return;
        }
        if let Some(s) = app.sessions.lock().unwrap().get(&sid).cloned() {
            let _ = s.evt.send(Ev::ZkDone { proof, ok: false, err: Some(e.to_string()), params: None });
        }
    }
}

async fn zk_inner(socket: WebSocket, proof: &str, sid: &str, app: &Arc<AppState>) -> Result<()> {
    let started = std::time::Instant::now();
    info!(proof, sid, "zk start");
    let shared = app.sessions.lock().unwrap().get(sid).cloned().ok_or_else(|| anyhow!("unknown sid"))?;
    if proof == "twopc" {
        let rx = shared.twopc_rx.lock().unwrap().take().ok_or_else(|| anyhow!("2PC not available for this session"))?;
        let (io, bridge) = ws_duplex(socket);
        let result = tokio::time::timeout(SESSION_TIMEOUT, run_twopc_n(io, rx, shared.evt.clone()))
            .await
            .unwrap_or_else(|_| Err(anyhow!("2PC timed out")));
        bridge.finish().await;
        info!(elapsed_ms = started.elapsed().as_millis() as u64, ok = result.is_ok(), "2pc end");
        if let Err(e) = &result {
            let _ = shared.evt.send(Ev::ZkDone { proof: "twopc".into(), ok: false, err: Some(e.to_string()), params: None });
        }
        return result;
    }
    if proof == "zkchan" {
        if app.offer.v != 2 {
            bail!("the proof channel is a protocol v2 feature");
        }
        if shared.zkchan_taken.swap(true, std::sync::atomic::Ordering::SeqCst) {
            bail!("proof channel already open for this session");
        }
        let (io, bridge) = ws_duplex(socket);
        let result = tokio::time::timeout(SESSION_TIMEOUT, run_zkchan(io, &shared))
            .await
            .unwrap_or_else(|_| Err(anyhow!("proof channel reached the session time limit")));
        bridge.finish().await;
        info!(elapsed_ms = started.elapsed().as_millis() as u64, ok = result.is_ok(), "zkchan end");
        return result;
    }
    let params = shared.params.lock().unwrap().get(proof).cloned().ok_or_else(|| anyhow!("no params for {proof}"))?;
    let (role, witness) = node_side(proof, &shared)?;
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

/// The node's role and witness for `proof`.
fn node_side(proof: &str, shared: &SessionShared) -> Result<(Role, Option<Witness>)> {
    Ok(match proof {
        "pi_n" => (Role::Prover, Some(Witness::Key(shared.key.to_vec()))),
        "pi_nk" => {
            let kiv = shared.k0_iv0.lock().unwrap().clone().ok_or_else(|| anyhow!("no K_0 yet"))?;
            let k0: [u8; 16] = kiv[..16].try_into()?;
            let iv0: [u8; 12] = kiv[16..28].try_into()?;
            (Role::Prover, Some(Witness::NodeKey { k0, iv0, key: shared.key.to_vec() }))
        }
        _ => (Role::Verifier, None),
    })
}

/// v2: the session's long-lived proof channel (`zkbench::channel`). The
/// correlations for π_NK (node proves) and π_C2S/π_C3S (client proves) are
/// generated while the session is armed; at claim time the client requests
/// each proof by name and the node runs it against *its own* parameters for
/// that name (exactly like the per-proof path), reporting `Ev::ZkDone`.
///
/// Failure semantics: setup or transport failure outside a proof reports
/// nothing (the client may fall back to `/zk?proof=pi_*`); a proof that fails
/// or times out on the channel reports `ZkDone { ok: false }` and the session
/// aborts, as with the per-proof path. The channel never runs a second proof
/// after a failure, and each proof at most once.
async fn run_zkchan<Io>(io: Io, shared: &Arc<SessionShared>) -> Result<()>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    use zkbench::channel::{Party, Prealloc, ZkChannel};
    let mut ch = tokio::time::timeout(TWOPC_TIMEOUT, ZkChannel::open(io, Party::Node, Prealloc::default()))
        .await
        .map_err(|_| anyhow!("proof channel preprocessing timed out"))??;
    let steps: Vec<String> = ch.take_timings().iter().map(|t| format!("{}={:.0}ms/{}B", t.step, t.ms, t.bytes_sent + t.bytes_recv)).collect();
    info!(steps = %steps.join(" "), "zkchan ready");
    loop {
        // The session may end while the channel idles (its task drops the
        // event receiver): stop serving then.
        let req = tokio::select! {
            r = ch.next_request() => r?,
            _ = shared.evt.closed() => None,
        };
        let Some(req) = req else { break };
        let proof = req.proof;
        let t = std::time::Instant::now();
        let run = async {
            if !matches!(proof.as_str(), "pi_nk" | "pi_c2s" | "pi_c3s") {
                bail!("{proof} is not served on the proof channel");
            }
            let params = shared.params.lock().unwrap().get(proof.as_str()).cloned().ok_or_else(|| anyhow!("no params for {proof}"))?;
            let (_, witness) = node_side(&proof, shared)?;
            let _guard = shared.zk_lock.lock().await;
            let r = match tokio::time::timeout(std::time::Duration::from_secs(30), ch.serve(&proof, &params, witness.as_ref())).await {
                Ok(r) => r,
                Err(_) => {
                    ch.poison();
                    Err(anyhow!("zk proof timed out after 30s"))
                }
            };
            Ok((params, r))
        }
        .await;
        let (params, result) = match run {
            Ok((p, r)) => (Some(p), r),
            Err(e) => (None, Err(e)),
        };
        let (ok, err) = match &result {
            Ok(checks) => (checks.iter().all(|c| c.ok), None),
            Err(e) => (false, Some(e.to_string())),
        };
        info!(proof, ok, elapsed_ms = t.elapsed().as_millis() as u64, "zkchan proof");
        let _ = shared.evt.send(Ev::ZkDone { proof: proof.clone(), ok, err, params });
        if !ok {
            break;
        }
    }
    ch.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// R validation (§5) and settlement
// ---------------------------------------------------------------------------

/// A disclosed upstream HTTP error response *head* (status >= 400).
///
/// R is exactly the status line and the header block, ending in the blank
/// line; π_C3 proves it sits `skip` bytes before the end of the response, so
/// the body stays private. Sound because a strict status line followed by
/// well-formed `Name: value` header lines cannot be produced by anything but
/// the provider's own response head: model output travels in JSON strings
/// (no raw CR/LF) and chunk framing lines are bare hex sizes, not headers. The
/// session carries a single response (`Connection: close`). Returns a usage
/// value with `error_status`, which the node settles from the status alone.
fn validate_error_head(r: &[u8]) -> Result<serde_json::Value> {
    if !r.ends_with(b"\r\n\r\n") {
        bail!("error R: must be exactly the response head");
    }
    let head = std::str::from_utf8(&r[..r.len() - 4]).context("error R: head not utf8")?;
    if head.contains("\r\n\r\n") {
        bail!("error R: more than one header block");
    }
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let (ver, code) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !(ver == "HTTP/1.1" || ver == "HTTP/1.0") || code.len() != 3 {
        bail!("error R: malformed status line");
    }
    let status: u16 = code.parse().context("error R: status not numeric")?;
    if !(400..600).contains(&status) {
        bail!("error R: status {status} is not an error");
    }
    let is_tchar = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    let mut headers = 0usize;
    for l in lines {
        let (k, v) = l.split_once(':').ok_or_else(|| anyhow!("error R: malformed header"))?;
        if k.is_empty() || !k.chars().all(is_tchar) || v.contains('\r') || v.contains('\n') {
            bail!("error R: malformed header");
        }
        headers += 1;
    }
    if headers == 0 {
        bail!("error R: no headers");
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
        .unwrap_or(&st.model)
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

#[cfg(test)]
mod offer_tests {
    use super::Offer;

    fn parse(extra: &str) -> Offer {
        let text = format!(r#"{{"upstream_host": "api.example.com"{extra}}}"#);
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn model_allowlist_list_map_and_legacy_fields() {
        assert!(parse("").model_allowlist.is_empty());
        assert_eq!(parse(r#", "model_allowlist": ["b", "a", "a"]"#).model_allowlist, vec!["a", "b"]);
        // legacy name and shape: only entries marked true
        assert_eq!(parse(r#", "text_only_ok": {"a": true, "b": false}"#).model_allowlist, vec!["a"]);
        // an old offer file with a price_list still parses (the field is ignored)
        let o = parse(r#", "price_list": {"m": {"in": 0.0}}, "text_only_ok": {}"#);
        assert!(o.model_allowlist.is_empty());
        assert!(!serde_json::to_string(&o).unwrap().contains("price_list"));
    }

    #[test]
    fn shipped_offer_parses() {
        let o: Offer = serde_json::from_str(include_str!("../offer.venice.json")).unwrap();
        assert!(o.model_allowlist.is_empty());
    }
}

#[cfg(test)]
mod buffer_tests {
    use super::{buffer_client, client_buffer_cap, MAX_TLS_RECORD};

    #[test]
    fn honest_body_fits_and_excess_is_refused() {
        let body_len = 8 << 20;
        // The body in full-size records (+22 bytes each), the suffix record,
        // ClientHello, CCS and Finished.
        let records = body_len / (1 << 14) + 1;
        let honest = body_len + records * 22 + 3 * MAX_TLS_RECORD;
        assert!(honest <= client_buffer_cap(body_len));

        let mut buf = Vec::new();
        let chunk = vec![0u8; 64 * 1024];
        while buf.len() + chunk.len() <= client_buffer_cap(body_len) {
            buffer_client(&mut buf, &chunk, body_len).unwrap();
        }
        let before = buf.len();
        assert!(buffer_client(&mut buf, &chunk, body_len).is_err());
        assert_eq!(buf.len(), before, "a refused chunk is not buffered");
        // A small body caps the buffer near its size, not at the global limit.
        assert!(client_buffer_cap(100) < 5 * MAX_TLS_RECORD);
    }
}

#[cfg(test)]
mod suffix_tests {
    #[test]
    fn proof_fixtures_use_the_production_suffix() {
        let s = super::canonical_suffix("mistral-small-3-2-24b-instruct", 12);
        assert_eq!(s.as_bytes(), zkbench::fixtures::SUFFIX);
    }
}
