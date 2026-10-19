//! `cu-sidecar` — the node (N) side of the confidential-upstream protocol.
//!
//! One WebSocket per session carries the control channel and the relayed TLS
//! records; a second WebSocket per proof carries the mpz VOLE protocol.
//!
//! Security-critical ordering (protocol v2, docs/TWOPC-DESIGN.md):
//!   SETUP → 2PC preprocessing → joint key share (armed; no provider
//!   connection, up to 600 s) → ClientHello (exactly the joint P-256 share;
//!   the upstream is dialed now; fresh 600 s deadline) → 2PC handshake and
//!   application phases → AWAIT_HEAD (client records held) → HS_VERIFIED →
//!   credential record assembled under K_0, π_NK params → π_NK run (the
//!   client verifies it; N, the prover, learns no verdict) → RELEASE_HEAD
//!   (the client's acceptance) → [credential record ‖ KeyUpdate] (atomic,
//!   epoch 0) → BODY (final suffix record held until π_C2S verifies)
//!   → CLOSE → ATTESTED → π_C3S → SETTLED.
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
use axum::extract::{Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use futures::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::Zeroizing;

use zkbench::statements::{Params, Witness};
use zkbench::Role;

use crate::tls::{parse_records, verify_handshake, HandshakeInfo, HsSecrets, Record, CT_APPLICATION_DATA};
use crate::wsio::ws_duplex;

// ---------------------------------------------------------------------------
// Offer / head template
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Offer {
    /// Protocol version: always 2 (two-party handshake, docs/TWOPC-DESIGN.md).
    /// Protocol v1 was retired; an offer that names it is refused at startup.
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
    /// Set from `--node-settles` when served: the sidecar hands the verified
    /// usage to the node instead of signing a stub receipt. A node in front of
    /// a sidecar without it would charge every session its full reservation.
    #[serde(default)]
    node_settles: bool,
    /// Further request kinds beside chat completions (absent: chat only).
    #[serde(default, skip_serializing_if = "Endpoints::is_empty")]
    endpoints: Endpoints,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Endpoints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    images: Option<ImagesEndpoint>,
}

impl Endpoints {
    fn is_empty(&self) -> bool {
        self.images.is_none()
    }
}

/// Image generation at a flat per-image price (docs/CONFIDENTIAL-IMAGES.md).
/// The node prices the variants and renders the suffix; the sidecar checks
/// that the suffix it is handed has exactly the shape this block allows.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImagesEndpoint {
    head_template: String,
    #[serde(default = "default_images_billing")]
    billing: String,
    response_shape: String,
    /// The request key that carries the image count (pinned after `model`).
    count_key: String,
    #[serde(default = "default_images_max_count")]
    max_count: u64,
    /// Pinned in this order after the count, for every request.
    #[serde(default)]
    fixed_pins: Vec<(String, serde_json::Value)>,
    /// The per-variant keys and the values they may take.
    #[serde(default)]
    param_space: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    #[serde(default = "default_images_max_response")]
    max_response_bytes: usize,
    #[serde(default = "default_images_idle")]
    response_idle_s: u64,
}

fn default_images_billing() -> String {
    "flat".into()
}

fn default_images_max_count() -> u64 {
    4
}

fn default_images_max_response() -> usize {
    MAX_SERVER_BYTES
}

fn default_images_idle() -> u64 {
    300
}

impl ImagesEndpoint {
    /// Startup checks: a template the relay and π_NK can use, and pins whose
    /// keys never collide (the suffix check relies on unique keys).
    fn validate(&self, host: &str, key_len: usize) -> Result<()> {
        let t = &self.head_template;
        for need in [" HTTP/1.1\r\n", "\r\nConnection: close\r\n", "\r\nAccept-Encoding: identity\r\n", "{LEN}"] {
            if !t.contains(need) {
                bail!("images head_template lacks {need:?}");
            }
        }
        if !t.starts_with("POST /") || !t.contains(&format!("\r\nHost: {host}\r\n")) || !t.ends_with("\r\n\r\n") {
            bail!("images head_template must be a POST to {host} ending the head");
        }
        placeholder_head(t, key_len, 1)?;
        if self.billing != "flat" {
            bail!("images billing {:?} is not supported (only flat)", self.billing);
        }
        if !matches!(self.response_shape.as_str(), "venice" | "openai") {
            bail!("images response_shape {:?} is not venice or openai", self.response_shape);
        }
        if !(1..=10).contains(&self.max_count) {
            bail!("images max_count {} outside 1..=10", self.max_count);
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_SERVER_BYTES {
            bail!("images max_response_bytes outside 1..={MAX_SERVER_BYTES}");
        }
        // Clients wait this long for the image; past the session limit the
        // relay ends the session anyway, and a value they refuse would make
        // them refuse the whole signed offer.
        if !(30..=SESSION_TIMEOUT.as_secs()).contains(&self.response_idle_s) {
            bail!("images response_idle_s {} outside 30..={}", self.response_idle_s, SESSION_TIMEOUT.as_secs());
        }
        let mut keys = std::collections::HashSet::new();
        for k in std::iter::once(&"model".to_string())
            .chain(std::iter::once(&self.count_key))
            .chain(self.fixed_pins.iter().map(|(k, _)| k))
            .chain(self.param_space.keys())
        {
            if k.is_empty() || !keys.insert(k.clone()) {
                bail!("images pin key {k:?} is empty or repeated");
            }
        }
        if self.param_space.values().any(|v| v.is_empty()) {
            bail!("images param_space has a key with no allowed values");
        }
        // A fixed pin only switches a provider extra off; clients refuse any
        // other value, so an offer carrying one would serve nobody.
        for (k, v) in &self.fixed_pins {
            let off = *v == serde_json::Value::Bool(false) || v.as_array().is_some_and(|a| a.is_empty());
            if !off {
                bail!("images fixed pin {k:?} must be false or [] (it may only switch an extra off)");
            }
        }
        Ok(())
    }

    /// The pinned suffix for `model`, `count` and the variant's `pins`, byte
    /// for byte as the node and the clients render it.
    fn render_suffix(&self, model: &str, count: u64, pins: &[(String, serde_json::Value)]) -> String {
        let j = |v: &serde_json::Value| serde_json::to_string(v).unwrap_or_default();
        let mut parts = vec![
            format!("\"model\":{}", j(&serde_json::Value::from(model))),
            format!("{}:{count}", j(&serde_json::Value::from(self.count_key.as_str()))),
        ];
        for (k, v) in self.fixed_pins.iter().chain(pins) {
            parts.push(format!("{}:{}", j(&serde_json::Value::from(k.as_str())), j(v)));
        }
        format!(",{}}}", parts.join(","))
    }

    /// The image count `suffix` pins, if it is exactly a suffix this endpoint
    /// allows for `model`: model, count in 1..=max_count, the fixed pins in
    /// order, then variant pins from `param_space` with allowed values, keys
    /// unique, compact.
    fn check_suffix(&self, model: &str, suffix: &str) -> Result<u64> {
        let body = suffix.strip_prefix(',').ok_or_else(|| anyhow!("images suffix must start with ','"))?;
        let pairs: Pairs = serde_json::from_str(&format!("{{{body}"))
            .map_err(|_| anyhow!("images suffix is not the tail of a JSON object"))?;
        let pairs = pairs.0;
        let nf = self.fixed_pins.len();
        if pairs.len() < 2 + nf {
            bail!("images suffix pins too few keys");
        }
        if pairs[0] != ("model".to_string(), serde_json::Value::from(model)) {
            bail!("images suffix does not pin the setup's model first");
        }
        if pairs[1].0 != self.count_key {
            bail!("images suffix does not pin {:?} second", self.count_key);
        }
        let count = pairs[1].1.as_u64().filter(|c| (1..=self.max_count).contains(c))
            .ok_or_else(|| anyhow!("images count outside 1..={}", self.max_count))?;
        if pairs[2..2 + nf] != self.fixed_pins[..] {
            bail!("images suffix does not carry the fixed pins in order");
        }
        let mut seen = std::collections::HashSet::new();
        for (k, _) in &pairs {
            if !seen.insert(k) {
                bail!("images suffix repeats {k:?}");
            }
        }
        let pins = &pairs[2 + nf..];
        for (k, v) in pins {
            let allowed = self.param_space.get(k).ok_or_else(|| anyhow!("images suffix pins {k:?}, not a variant key"))?;
            if !allowed.contains(v) {
                bail!("images suffix pins {k:?} to a value the offer does not allow");
            }
        }
        if self.render_suffix(model, count, pins) != suffix {
            bail!("images suffix is not in canonical form");
        }
        Ok(count)
    }
}

/// A JSON object's members in order, duplicates kept (so they can be refused).
struct Pairs(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Pairs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> std::result::Result<Pairs, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, serde_json::Value>()? {
                    out.push((k, v));
                }
                Ok(Pairs(out))
            }
        }
        d.deserialize_map(V)
    }
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
    2
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
    /// Where per-session artifacts (attestation/receipt/sidecar log) are written.
    /// `--runs-dir` overrides the default `CARGO_MANIFEST_DIR/../runs`.
    runs_dir: std::path::PathBuf,
    /// When true the sidecar does *not* settle: it emits the π_C3S-verified
    /// `usage` frame and lets the node (which holds the Cashu wallet and the
    /// Nostr key) price, refund and sign the receipt.
    node_settles: bool,
    sessions: StdMutex<HashMap<String, Arc<SessionShared>>>,
    /// Concurrent sessions; a session holds a slot from setup to close.
    slots: Arc<tokio::sync::Semaphore>,
    /// Largest request body (`setup.len`) a session may declare.
    max_body: usize,
    /// SHA-256 of the node's shared token (`--token-env`); `None` = no check.
    /// The sidecar does not check client credentials (the node does, before
    /// it dials), so anyone who reaches it spends the provider key.
    token_hash: Option<[u8; 32]>,
}

/// A session must send its `setup` this soon after connecting.
const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Hard limit on one session's lifetime, from its connection (armed time
/// included) to settlement. The node's limit is as long but counts from its
/// own, earlier accept, so it ends a session first.
const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// Largest TLS 1.3 record on the wire: header + 2^14 plaintext + 256 expansion.
const MAX_TLS_RECORD: usize = 5 + (1 << 14) + 256;
/// Limits on a π_C3S disclosure (the verifier decrypts every covered record in
/// the circuit): covered records, bytes of R, and R plus the undisclosed bytes
/// after it. They are the proof's own limits (`zkbench::statements`), so a
/// disclosure the sidecar accepts can be proven.
const MAX_DISCLOSE_RECORDS: usize = zkbench::statements::MAX_C3S_RECORDS;
const MAX_DISCLOSE_R: usize = 16 << 10;
const MAX_DISCLOSE_NEED: usize = zkbench::statements::MAX_C3S_NEED;
/// Server application-data records kept for a disclosure: the covered ones
/// and the KeyUpdates and close_notify that may follow them.
const SERVER_TAIL_RECORDS: usize = MAX_DISCLOSE_RECORDS + zkbench::statements::MAX_SERVER_KEY_UPDATES as usize + 1;
/// Largest server record that may follow the covered ones: a KeyUpdate
/// (4-byte header + request_update, inner type, 16-byte tag).
const MAX_TRAILING_RECORD: usize = 4 + 1 + 1 + 16;

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

/// Dialing the upstream, and each write to it, must finish within these.
const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const UPSTREAM_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Most bytes one session accepts from the upstream. A response is bounded by
/// `max_tokens_cap`; the records are kept for the usage proof.
const MAX_SERVER_BYTES: usize = 64 << 20;
/// Most upstream bytes queued for a client that reads slowly: the upstream
/// reader stops reading until the client catches up.
const TO_CLIENT_BUDGET: usize = 4 << 20;
/// Limits on the proof connections (`/zk`): a proof waits this long for the
/// session's proof lock, then has as long to run; and a session has at most
/// this many open (2PC, proof channel, and per-proof fallbacks).
const PROOF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_ZK_CONNS_PER_SESSION: usize = 6;

/// Write to the upstream within `UPSTREAM_WRITE_TIMEOUT`, and never past the
/// session `deadline`: an upstream that stops reading must not hold the
/// session past it (the session loop does not watch its deadline while a
/// write is in progress).
async fn write_upstream(
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
    deadline: Option<tokio::time::Instant>,
) -> Result<()> {
    let limit = tokio::time::Instant::now() + UPSTREAM_WRITE_TIMEOUT;
    let limit = deadline.map_or(limit, |d| d.min(limit));
    tokio::time::timeout_at(limit, tcp_tx.write_all(data))
        .await
        .map_err(|_| anyhow!("upstream did not accept {} bytes before the write or session time limit", data.len()))??;
    Ok(())
}

enum Ev {
    ServerBytes(Vec<u8>),
    /// The joint P-256 key share P = P_C + P_N.
    KeyShare([u8; 65]),
    /// The handshake traffic secrets from 2PC phase A.
    Hs(HsSecrets),
    /// N's outputs of 2PC phase B.
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

/// Names the event only: its payload (relayed bytes, traffic secrets, keys)
/// never reaches a log line or an error frame.
impl std::fmt::Debug for Ev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ev::ServerBytes(b) => write!(f, "ServerBytes({} bytes)", b.len()),
            Ev::KeyShare(_) => f.write_str("KeyShare"),
            Ev::Hs(_) => f.write_str("Hs"),
            Ev::Ap(_) => f.write_str("Ap"),
            Ev::TcpClosed => f.write_str("TcpClosed"),
            Ev::ZkDone { proof, ok, .. } => write!(f, "ZkDone({proof}, ok={ok})"),
        }
    }
}

/// N's outputs of the two-party key schedule (K_0/IV_0 never leave N).
struct ApN {
    k0: Zeroizing<[u8; 16]>,
    iv0: Zeroizing<[u8; 12]>,
    h1: [u8; 32],
    h2: [u8; 32],
    hk: [u8; 32],
}

/// What the session hands the 2PC task once U's messages arrive.
#[derive(Debug)]
enum TwoPcCmd {
    Handshake { server_share: [u8; 65], th_sh: [u8; 32] },
    App { th_sf: [u8; 32] },
}

struct SessionShared {
    params: StdMutex<HashMap<String, Params>>,
    /// The command channel of this session's 2PC (taken by `/zk?proof=twopc`).
    twopc_rx: StdMutex<Option<mpsc::UnboundedReceiver<TwoPcCmd>>>,
    /// N's epoch-0 key and IV, for the π_NK witness.
    k0_iv0: StdMutex<Option<Zeroizing<Vec<u8>>>>,
    key: Arc<Zeroizing<Vec<u8>>>,
    evt: mpsc::UnboundedSender<Ev>,
    /// Serializes the ZK proofs of one session. The client may run π_C2S
    /// concurrently with generation and start π_C3S before π_C2S has finished;
    /// running two mpz proofs at once on one node stalls (the VOLE/rayon paths
    /// contend). Proofs are per-session independent, so serializing inside a
    /// session costs nothing on the critical path and removes the contention.
    zk_lock: tokio::sync::Mutex<()>,
    /// The session's proof channel (`/zk?proof=zkchan`) was opened.
    zkchan_taken: std::sync::atomic::AtomicBool,
    /// Open `/zk` connections of this session (`MAX_ZK_CONNS_PER_SESSION`).
    zk_conns: Arc<std::sync::atomic::AtomicUsize>,
    /// Proofs that started running (on the channel or their own connection):
    /// each runs at most once per session.
    proofs_run: StdMutex<std::collections::HashSet<String>>,
}

impl SessionShared {
    /// Claim `proof`'s one run, refusing a second one.
    fn claim_proof(&self, proof: &str) -> Result<()> {
        if !self.proofs_run.lock().unwrap().insert(proof.to_string()) {
            bail!("{proof} already ran for this session");
        }
        Ok(())
    }
}

/// One open `/zk` connection, counted against its session's limit.
struct ZkConnSlot(Arc<std::sync::atomic::AtomicUsize>);

impl ZkConnSlot {
    fn take(count: &Arc<std::sync::atomic::AtomicUsize>) -> Result<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = count.load(Ordering::SeqCst);
        loop {
            if cur >= MAX_ZK_CONNS_PER_SESSION {
                bail!("too many proof connections for this session (limit {MAX_ZK_CONNS_PER_SESSION})");
            }
            match count.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Ok(Self(count.clone())),
                Err(now) => cur = now,
            }
        }
    }
}

impl Drop for ZkConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Recorded relay state needed for the proofs.
#[derive(Default)]
struct RelayLog {
    /// The endpoint's response cap (image sessions); `MAX_SERVER_BYTES` otherwise.
    max_server_bytes: Option<usize>,
    /// The client's handshake flight as relayed (ClientHello, CCS, Finished)
    /// and the raw upstream bytes up to the handshake verification (it and
    /// the 2PC need them); later upstream bytes are only hashed and counted.
    client_raw: Vec<u8>,
    server_raw: Vec<u8>,
    /// SHA-256 and length of every byte received from the upstream.
    recv: cu_crypto::transcript::Transcript,
    recv_len: usize,
    /// Client body records in wire order.
    client_app: Vec<Record>,
    /// Server records received (every content type), for the attestation.
    server_records: usize,
    /// Server application-data records received (the encrypted handshake
    /// flight included), and the last `SERVER_TAIL_RECORDS` of them: a
    /// disclosure covers only records at the end of the response.
    server_app_records: usize,
    server_tail: std::collections::VecDeque<Record>,
}

impl RelayLog {
    /// A client handshake record, as relayed upstream. Only the handshake
    /// flight is kept (at most three records, each at most `MAX_TLS_RECORD`):
    /// the body stays in the relay buffers alone.
    fn client_handshake_record(&mut self, record: &[u8]) -> Result<()> {
        if self.client_raw.len() + record.len() > 3 * MAX_TLS_RECORD {
            bail!("client handshake flight longer than three records");
        }
        self.client_raw.extend_from_slice(record);
        Ok(())
    }

    /// A complete server record: counted, and kept while it is among the last
    /// `SERVER_TAIL_RECORDS` application-data records.
    fn server_record(&mut self, r: Record) {
        self.server_records += 1;
        if r.ctype != CT_APPLICATION_DATA {
            return;
        }
        self.server_app_records += 1;
        if self.server_tail.len() == SERVER_TAIL_RECORDS {
            self.server_tail.pop_front();
        }
        self.server_tail.push_back(r);
    }

    /// The records covering a disclosure (`locate_tail`), each with its index
    /// among the response's application-data records, which start after the
    /// `first_response` records of the encrypted handshake flight.
    fn covered_records(&self, first_response: usize, tail_lens: &[usize], trailing: Option<usize>) -> Result<Vec<(usize, &Record)>> {
        // Only the last records are kept: `base` is the index of the first
        // kept one among all application-data records.
        let base = self.server_app_records - self.server_tail.len();
        let lens: Vec<usize> = self.server_tail.iter().map(|x| x.payload.len()).collect();
        Ok(locate_tail(&lens, first_response.saturating_sub(base), tail_lens, trailing)?
            .into_iter()
            .map(|j| (base + j - first_response, &self.server_tail[j]))
            .collect())
    }

    /// Upstream bytes: hashed and counted for the attestation, kept raw until
    /// the handshake is verified, and refused past `MAX_SERVER_BYTES`.
    fn server_bytes(&mut self, data: &[u8], handshake_verified: bool) -> Result<()> {
        let cap = self.max_server_bytes.unwrap_or(MAX_SERVER_BYTES);
        if self.recv_len + data.len() > cap {
            bail!("upstream sent more than {cap} bytes");
        }
        self.recv_len += data.len();
        self.recv.update(data);
        if !handshake_verified {
            self.server_raw.extend_from_slice(data);
        }
        Ok(())
    }
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
    let token_env = arg("--token-env").unwrap_or_else(|| "CU_SIDECAR_TOKEN".into());
    if args.iter().any(|a| a == "--insecure-no-proofs") {
        bail!("--insecure-no-proofs was a protocol v1 test mode; v1 is retired (branch v1-poc)");
    }
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
    // π_NK proves membership in one fixed alphabet; a key outside either
    // cannot be proven, so refuse to start (never printing the key).
    if !(16..=256).contains(&key.len()) {
        bail!("unexpected key length {} (expected 16..=256)", key.len());
    }
    if !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-') {
        bail!("the upstream key has characters outside [A-Za-z0-9_-]; π_NK cannot prove it");
    }
    info!(key_len = key.len(), "loaded upstream API key");

    // The node's credential. Required off loopback: any peer that reaches the
    // sidecar gets sessions on the provider key without the node's billing.
    let token_hash = match std::env::var(&token_env) {
        Ok(t) if !t.is_empty() => {
            if t.len() < 16 {
                bail!("{token_env} is too short (at least 16 characters)");
            }
            Some(cu_crypto::transcript::hash(t.as_bytes()))
        }
        _ if is_loopback(&listen) => None,
        _ => bail!(
            "{token_env} is not set; a sidecar listening on {listen} (not loopback) needs the \
             node's token (CONFIDENTIAL_SIDECAR_TOKEN on the node)"
        ),
    };

    let mut offer = if let Some(path) = arg("--offer") {
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        serde_json::from_str::<Offer>(&text).with_context(|| format!("parsing {path}"))?
    } else {
        Offer {
            v: 2,
            upstream_host: host.clone(),
            head_template: default_head_template_for(&host, key.len()),
            key_alphabet: default_key_alphabet(),
            key_length: key.len(),
            suffix_keys: SUFFIX_KEYS.iter().map(|k| k.to_string()).collect(),
            max_tokens_cap: default_max_tokens_cap(),
            notary_pubkey: String::new(),
            model_allowlist: Vec::new(),
            node_settles: false,
            endpoints: Endpoints::default(),
        }
    };
    offer.node_settles = node_settles;
    if !node_settles {
        warn!("running WITHOUT --node-settles: the stub settlement signs its own receipts; a node in front of this sidecar would charge every session its full reservation");
    }
    // Protocol v2 is the only one; `--protocol 2` is still accepted so existing
    // deploy scripts keep working.
    match arg("--protocol").as_deref() {
        None | Some("2") => {}
        Some("1") => bail!("protocol v1 is retired (branch v1-poc); run with --protocol 2 or without --protocol"),
        Some(other) => bail!("unsupported --protocol {other}"),
    }
    if offer.v != 2 {
        bail!("the offer names protocol v{}; only v2 is supported (v1 is retired)", offer.v);
    }
    if offer.upstream_host.is_empty() {
        offer.upstream_host = host.clone();
    }
    if offer.head_template.is_empty() {
        offer.head_template = default_head_template_for(&offer.upstream_host, key.len());
    }
    offer.head_template = with_key_length(&offer.head_template, key.len());
    // The offer advertises the keys the suffix pins; they are the ones
    // `canonical_suffix` writes, so an offer naming others is refused.
    if offer.suffix_keys.is_empty() {
        offer.suffix_keys = SUFFIX_KEYS.iter().map(|k| k.to_string()).collect();
    }
    if offer.suffix_keys != SUFFIX_KEYS {
        bail!("the offer's suffix_keys {:?} differ from the keys the sidecar pins {SUFFIX_KEYS:?}", offer.suffix_keys);
    }
    offer.key_length = key.len();
    if let Some(images) = offer.endpoints.images.as_mut() {
        images.head_template = with_key_length(&images.head_template, key.len());
        let host = offer.upstream_host.clone();
        images.validate(&host, key.len())?;
    }
    // The π_NK membership circuit is a fixed-size check over one alphabet. An
    // offer demanding another alphabet must fail here rather than let the
    // sidecar prove membership in the wrong set.
    if offer.key_alphabet != zkbench::statements::SUPPORTED_KEY_ALPHABET {
        bail!(
            "unsupported key_alphabet {:?}: the π_NK circuit is fixed to {:?}",
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
        runs_dir,
        node_settles,
        sessions: StdMutex::new(HashMap::new()),
        slots: Arc::new(tokio::sync::Semaphore::new(max_sessions)),
        max_body,
        token_hash,
    });

    let app = Router::new()
        .route("/offer", get(offer_http))
        .route("/session", get(session_ws))
        .route("/zk", get(zk_ws))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(%listen, token = state.token_hash.is_some(), "cu-sidecar listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// `--listen` names a loopback address (127.0.0.0/8, ::1 or localhost).
fn is_loopback(listen: &str) -> bool {
    if let Ok(addr) = listen.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    listen.rsplit_once(':').is_some_and(|(host, _)| host == "localhost")
}

/// Every route needs `Authorization: Bearer <token>` when a token is set.
/// Compared as SHA-256 digests, in constant time.
async fn require_token(State(app): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if let Some(want) = &app.token_hash {
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| cu_crypto::transcript::hash(t.as_bytes()));
        let ok = got.is_some_and(|g| g.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0);
        if !ok {
            warn!(path = %req.uri().path(), "rejected a request without the node's token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    next.run(req).await
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
    // No honest message is larger than a whole buffered body: refuse bigger
    // ones before they are read into memory.
    let max = client_buffer_cap(app.max_body);
    ws.max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| session_handler(socket, app))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Setup {
        nonce_c: String,
        model: String,
        #[serde(default)]
        max_tokens: u64,
        len: usize,
        /// `chat` (default) or `images`; any other kind is refused.
        #[serde(default)]
        kind: Option<String>,
        /// The node's rendered suffix for an image request (checked against
        /// the offer's images endpoint).
        #[serde(default)]
        suffix: Option<String>,
        #[serde(default)]
        count: Option<u64>,
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
        /// Server KeyUpdates before the covered records (they are under
        /// `s_ap_k`), and the index, among the response's application-data
        /// records, of the first record of that epoch (its sequence 0).
        #[serde(default)]
        key_updates: u32,
        #[serde(default)]
        epoch_start: usize,
        /// Server records after the covered ones that carry no response
        /// bytes: KeyUpdates and a close_notify. Each is at most a KeyUpdate's
        /// size. Absent: one trailing close_notify-sized record may be skipped.
        #[serde(default)]
        trailing: Option<usize>,
    },
    /// The client accepts π_NK (it verified it) and claims the session; N
    /// writes the credential record and the KeyUpdate under K_0.
    ReleaseHead {},
    /// Image sessions: the client accepts a successful response. The charge
    /// is the flat price fixed at setup, so nothing is disclosed.
    Accept {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SessionState {
    #[default]
    Handshake,
    /// The client Finished is relayed; client records are held until N
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
        twopc_rx: StdMutex::new(Some(twopc_rx)),
        k0_iv0: StdMutex::new(None),
        key: app.key.clone(),
        evt: evt_tx.clone(),
        zk_lock: tokio::sync::Mutex::new(()),
        zkchan_taken: std::sync::atomic::AtomicBool::new(false),
        zk_conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        proofs_run: StdMutex::new(Default::default()),
    });

    // Upstream bytes in flight to the client (queued or being sent) hold
    // permits of this budget; they are returned once the bytes are sent.
    let budget = Arc::new(tokio::sync::Semaphore::new(TO_CLIENT_BUDGET));
    let send_budget = budget.clone();
    let send_task = tokio::spawn(async move {
        while let Some(m) = from_client.recv().await {
            let n = if let Message::Binary(b) = &m { b.len() } else { 0 };
            if ws_tx.send(m).await.is_err() {
                break;
            }
            send_budget.add_permits(n);
        }
    });

    let mut st = Session { twopc_tx: Some(twopc_tx), ..Session::default() };
    let mut log = RelayLog::default();
    let mut client_pending: Vec<u8> = Vec::new();
    let mut server_pending: Vec<u8> = Vec::new();
    let mut cleanup = SessionCleanup { app: app.clone(), shared: shared.clone(), budget: budget.clone(), reader: None };

    let session_end = tokio::time::Instant::now() + SESSION_TIMEOUT;
    let result = std::panic::AssertUnwindSafe(async {
    // A connection holds a session slot from the start, so connections that
    // never send a setup are bounded too.
    let _slot = app
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("sidecar at capacity; retry later"))?;
    // Nothing reaches the upstream before a valid setup: an idle or malformed
    // connection costs no provider socket.
    let first = match tokio::time::timeout(SETUP_TIMEOUT, ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t,
        Ok(_) => bail!("expected a setup frame"),
        Err(_) => bail!("no setup within {}s", SETUP_TIMEOUT.as_secs()),
    };
    let setup: ClientMsg = serde_json::from_str(&first).map_err(|e| anyhow!("bad setup: {e}"))?;
    handle_setup(setup, &app, &shared, &to_client, &mut st)?;
    if st.images_count.is_some() {
        log.max_server_bytes = app.offer.endpoints.images.as_ref().map(|e| e.max_response_bytes);
    }

    // The 2PC preprocessing (tens of MB over the client's link) runs before
    // the ClientHello exists, and a pre-warmed session then waits for a request.
    // The provider closes an idle connection within seconds (Cloudflare: ~15 s
    // with no ClientHello), so dial it only when the client's ClientHello
    // arrives, after the joint key share is ready.
    {
        let prep = tokio::time::sleep(TWOPC_TIMEOUT);
        tokio::pin!(prep);
        let armed = tokio::time::sleep_until(session_end);
        tokio::pin!(armed);
        // Wait for a ClientHello that passes the v2 checks: a client that
        // sends anything else never makes the sidecar dial the provider.
        while !check_hello(&mut st, &client_pending)? {
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
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => bail!("client left before the handshake"),
                    Some(Ok(Message::Text(_))) => bail!("unexpected control message during 2PC preprocessing"),
                    _ => {}
                },
            }
        }
    }

    // The session deadline covers dialing the upstream too.
    let deadline_at = session_end;
    st.deadline = Some(deadline_at);
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);
    let tcp = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&app.upstream))
        .await
        .map_err(|_| anyhow!("connecting to {} timed out after {}s", app.upstream, UPSTREAM_CONNECT_TIMEOUT.as_secs()))?
        .with_context(|| format!("connecting to {}", app.upstream))?;
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
    {
        let evt = evt_tx.clone();
        let budget = budget.clone();
        cleanup.reader = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tcp_rx.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = evt.send(Ev::TcpClosed);
                        break;
                    }
                    Ok(n) => {
                        // Wait while the client is behind; the budget is
                        // closed when the session ends.
                        match budget.acquire_many(n as u32).await {
                            Ok(p) => p.forget(),
                            Err(_) => break,
                        }
                        if evt.send(Ev::ServerBytes(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                }
            }
        }));
    }

    v2_pump_client(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;

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
                    Message::Binary(data) => {
                        if st.sid.is_none() {
                            bail!("TLS bytes before setup");
                        }
                        match st.state {
                            SessionState::Handshake => {
                                buffer_client(&mut client_pending, &data, st.body_len)?;
                                v2_pump_client(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;
                            }
                            SessionState::AwaitHead => buffer_client(&mut st.held_client, &data, st.body_len)?,
                            SessionState::Body => {
                                buffer_client(&mut client_pending, &data, st.body_len)?;
                                relay_body(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;
                            }
                            _ => bail!("unexpected client record in state {:?}", st.state),
                        }
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            ev = evt_rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    Ev::ServerBytes(bytes) => {
                        log.server_bytes(&bytes, st.handshake.is_some())?;
                        server_pending.extend_from_slice(&bytes);
                        let (recs, used) = parse_records(&server_pending);
                        for r in recs { log.server_record(r); }
                        server_pending.drain(..used);
                        if to_client.send(Message::Binary(bytes.into())).is_err() { break; }
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::KeyShare(p) => {
                        if st.joint.is_some() { bail!("unexpected key share"); }
                        st.joint = Some(p);
                        side(&mut st, "2pc key share ready".into());
                        v2_pump_client(&mut st, &mut log, &mut client_pending, &mut tcp_tx).await?;
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::Hs(s) => {
                        if st.hs_secrets.is_some() { bail!("unexpected handshake secrets"); }
                        st.hs_secrets = Some(s);
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::Ap(ap) => {
                        if st.ap.is_some() { bail!("unexpected 2PC application output"); }
                        let mut kiv = Zeroizing::new(ap.k0.to_vec());
                        kiv.extend_from_slice(&ap.iv0[..]);
                        *shared.k0_iv0.lock().unwrap() = Some(kiv);
                        st.ap = Some(ap);
                        v2_progress(&app, &shared, &to_client, &mut st, &mut log).await?;
                    }
                    Ev::TcpClosed => {
                        info!("upstream closed the connection");
                        // Before the final body record was released the upstream
                        // never had a complete request: end the session here, so
                        // the node releases the reservation. Letting it go on
                        // would let a later π_C2S send `body_released` for a
                        // record that can no longer be written, and the node
                        // would charge the full reservation for nothing.
                        if !st.c2_ok {
                            bail!("upstream closed the connection before the request was complete (nothing billed)");
                        }
                        let mut att_chain: Option<String> = None;
                        if let (Some(sid), Some(hs)) = (st.sid.as_ref(), st.handshake.as_ref()) {
                            let a = serde_json::json!({
                                "sid": sid,
                                "cert_chain_hash": hex::encode(hs.cert_chain_hash),
                                "th_sh": hex::encode(hs.th_sh),
                                "th_sf": hex::encode(hs.th_sf),
                                "sha256_sent": hex::encode(st.sent.hash()),
                                "sha256_recv": hex::encode(log.recv.hash()),
                                "client_records": log.client_app.len(),
                                "server_records": log.server_records,
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
                        if !ok {
                            // Nothing can change a settled session: a late
                            // failure (a proof connection dropping) only ends
                            // that connection.
                            if st.state == SessionState::Settled {
                                continue;
                            }
                            bail!("proof {proof} failed: {err:?}");
                        }
                        match proof.as_str() {
                            "pi_nk" => {
                                // π_NK ran to completion on the session's own
                                // stored parameters. N is the prover and learns
                                // no verdict: the client's `release_head` is the
                                // acceptance, and both are needed for the write.
                                let same = same_params(proven.as_ref(), shared.params.lock().unwrap().get(proof.as_str()));
                                if same {
                                    st.head_proof_ok = true;
                                    write_head(&mut st, &mut log, &to_client, &mut tcp_tx).await?;
                                }
                            }
                            "pi_c2s" => {
                                let same = same_params(proven.as_ref(), shared.params.lock().unwrap().get(proof.as_str()));
                                if same && !st.c2_ok {
                                    st.c2_ok = true;
                                    // Suffix proven: release the final body record.
                                    let held = st.held.take().ok_or_else(|| anyhow!("π_C2S verified but no held body record"))?;
                                    // Tell the node *before* the write: once the
                                    // upstream may have the full request, the node
                                    // must treat the escrow as at stake (it drains
                                    // these frames even if the client leaves).
                                    let _ = to_client.send(Message::Text(
                                        serde_json::json!({"type":"body_released"}).to_string().into(),
                                    ));
                                    write_upstream(&mut tcp_tx, &held, st.deadline).await?;
                                    st.sent.update(&held);
                                    info!("π_C2S verified; final body record released to the upstream");
                                    side(&mut st, "pi_c2s verified; final body record released".into());
                                }
                            }
                            "pi_c3s" => {
                                if st.state == SessionState::Settled {
                                    continue;
                                }
                                if !st.c2_ok {
                                    bail!("π_C3S before π_C2S verified: the suffix (model, caps) is not proven");
                                }
                                let same = same_params(proven.as_ref(), shared.params.lock().unwrap().get(proof.as_str()));
                                if !same {
                                    bail!("π_C3S parameters changed after the proof started");
                                }
                                if st.usage.is_some() {
                                    emit_settlement(&app, &mut st, &to_client);
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
    })
    .catch_unwind()
    .await
    // A bug that panics ends the session like an error: the client still gets
    // its error frame, the log is written, and `cleanup` runs.
    .unwrap_or_else(|_| Err(anyhow!("internal error in the session")));

    if let Err(e) = &result {
        // Send an explicit error frame so the client fails fast instead of
        // waiting out its protocol timeout (the timeout remains the backstop).
        let _ = to_client.send(Message::Text(
            serde_json::json!({"type":"error","reason":e.to_string()}).to_string().into(),
        ));
    }
    if let Some(dir) = &st.run_dir {
        // Keep a record only of sessions that wrote a credential record: the rest
        // (abandoned armed sessions, failed setups) would pile up unbounded.
        if matches!(st.state, SessionState::Handshake | SessionState::AwaitHead) {
            let _ = std::fs::remove_dir_all(dir);
        } else {
            let _ = std::fs::write(dir.join("sidecar.jsonl"), st.side_log.join("\n") + "\n");
        }
    }
    drop(cleanup);
    // Close the outbound queue so the sender task drains and flushes any last
    // frame (e.g. the explicit {type:"error"} abort) before the socket goes.
    drop(to_client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), send_task).await;
    result
}

/// Releases what a session holds however its task ends (error, panic or
/// cancellation): the upstream reader (which may be parked on a read while
/// the upstream idles, or on the client budget) with its socket, and the
/// session's entry in the table, so `/zk` stops admitting it.
struct SessionCleanup {
    app: Arc<AppState>,
    shared: Arc<SessionShared>,
    budget: Arc<tokio::sync::Semaphore>,
    reader: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.budget.close();
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
        let mut sessions = self.app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, s| !Arc::ptr_eq(s, &self.shared));
    }
}

/// Per-session mutable state kept inside the handler task.
#[derive(Default)]
struct Session {
    state: SessionState,
    /// The session deadline (set when the upstream is dialed); upstream
    /// writes end by it too.
    deadline: Option<tokio::time::Instant>,
    twopc_tx: Option<mpsc::UnboundedSender<TwoPcCmd>>,
    joint: Option<[u8; 65]>,
    ch_checked: bool,
    /// The checked ClientHello was relayed to the upstream.
    ch_sent: bool,
    hs_cmd_sent: bool,
    app_cmd_sent: bool,
    ap: Option<Box<ApN>>,
    /// Client bytes after its Finished, held until the head is written.
    held_client: Vec<u8>,
    /// The KeyUpdate record N writes after the credential record.
    ku_record: Option<Vec<u8>>,
    /// π_NK ran to completion on the session's stored parameters. Not a
    /// verdict (N is the prover and never learns the client's); the client's
    /// `release_head` is its acceptance.
    head_proof_ok: bool,
    /// The client asked for the credential record (`release_head`):
    /// the KeyUpdate record to write right after it.
    head_release: Option<Vec<u8>>,
    sid: Option<String>,
    body_len: usize,
    head_len: usize,
    assembled: Option<Assembled>,
    c_commit: Option<[u8; 32]>,
    handshake: Option<HandshakeInfo>,
    hs_secrets: Option<HsSecrets>,
    /// The record completing the body, withheld from the upstream until π_C2S.
    held: Option<Vec<u8>>,
    /// SHA-256 of every byte written to the upstream (for the attestation).
    sent: cu_crypto::transcript::Transcript,
    /// Setup values the suffix must pin.
    model: String,
    max_tokens: u64,
    /// `Some(count)` for an image session, `None` for chat.
    images_count: Option<u64>,
    /// The suffix the final body record must end with (rendered at setup).
    suffix: String,
    /// The request head template for this session's kind.
    head_template: String,
    accepted: bool,
    /// Body (epoch 1) accounting: records and content bytes relayed.
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
    let ClientMsg::Setup { nonce_c, model, max_tokens, len, escrow_e, escrow, armed, kind, suffix, count } = msg else {
        bail!("expected a setup frame");
    };
    if st.sid.is_some() || st.state != SessionState::Handshake {
        bail!("duplicate setup");
    }
    let images = match kind.as_deref() {
        None | Some("chat") => false,
        Some("images") => true,
        Some(other) => bail!("unknown session kind {other:?}"),
    };
    let images_count = if images {
        let ep = app.offer.endpoints.images.as_ref().ok_or_else(|| anyhow!("this sidecar offers no images endpoint"))?;
        if model.is_empty() || max_tokens != 0 || armed {
            bail!("an image setup needs a model, no max_tokens, and is never armed");
        }
        let suffix = suffix.as_deref().ok_or_else(|| anyhow!("an image setup needs the node's suffix"))?;
        let n = ep.check_suffix(&model, suffix)?;
        if count.is_some_and(|c| c != n) {
            bail!("setup count {count:?} differs from the suffix's count {n}");
        }
        st.suffix = suffix.to_string();
        st.head_template = ep.head_template.clone();
        Some(n)
    } else {
        if model.is_empty() || max_tokens == 0 {
            bail!("setup needs a model and max_tokens >= 1");
        }
        let canonical = canonical_suffix(&model, max_tokens);
        if suffix.as_deref().is_some_and(|s| s != canonical) || count.is_some() {
            bail!("a chat setup's suffix is the canonical one and it has no count");
        }
        st.suffix = canonical;
        st.head_template = app.offer.head_template.clone();
        None
    };
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
    st.images_count = images_count;
    let (head, _) = placeholder_head(&st.head_template, app.key.len(), len)?;
    st.head_len = head.len();
    st.run_dir = Some(init_run_dir(app, &sid)?);
    app.sessions.lock().unwrap().insert(sid.clone(), shared.clone());
    side(
        st,
        format!("setup sid={} model={} len={} max_tokens={} armed={} node_settles={}", sid, model, len, max_tokens, armed, app.node_settles),
    );
    let mut ready = serde_json::json!({
        "type":"ready","nonce_n":hex::encode(nonce_n),"sid":sid,
        "pubkey":app.offer.notary_pubkey,"head_len":head.len(),
        "suffix": st.suffix,
        "armed": armed,
        "v": app.offer.v,
    });
    if let Some(n) = images_count {
        ready["kind"] = "images".into();
        ready["count"] = n.into();
    }
    send(ready);
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
        ClientMsg::ReleaseHead {} => {
            if st.state != SessionState::AwaitHead || st.head_release.is_some() {
                bail!("release_head out of order");
            }
            if st.assembled.is_none() {
                bail!("credential record not assembled");
            }
            st.head_release = Some(st.ku_record.clone().ok_or_else(|| anyhow!("no KeyUpdate record"))?);
            write_head(st, log, to_client, tcp_tx).await?;
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
            if suffix != st.suffix.as_bytes() {
                bail!("body suffix does not match the session's pinned suffix");
            }
            st.c2_requested = true;
            let last = log.client_app.last().ok_or_else(|| anyhow!("no body record"))?;
            let inner_len = last.payload.len().saturating_sub(16); // drop the GCM tag
            if inner_len == 0 || suffix.len() + 1 > inner_len {
                bail!("suffix does not fit in the last body record");
            }
            // Epoch-1 sequence of the final body record (the body starts at 0).
            let seq = (st.body_records - 1) as u64;
            let (w, off, sel_start) = window(suffix.len(), inner_len);
            let ct_window = last.payload[off..off + w].to_vec();
            let ap = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?;
            // The compared range runs through the inner content type byte, so
            // the statement alone shows the record is application data ending
            // in the suffix.
            let mut expected = suffix;
            expected.push(CT_APPLICATION_DATA);
            let params = Params::PiC2S(zkbench::statements::PiC2S {
                h1: ap.h1, seq, ct_window, off, w, sel_start, sel_len: expected.len(), expected,
            });
            shared.params.lock().unwrap().insert("pi_c2s".into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":"pi_c2s","params":params}));
        }
        ClientMsg::Accept {} => {
            let Some(count) = st.images_count else { bail!("accept is for image sessions only") };
            if st.state != SessionState::Attested || st.disclosed || st.accepted || !st.c2_ok {
                bail!("accept out of order or repeated");
            }
            st.accepted = true;
            st.usage = Some(serde_json::json!({"flat": true, "kind": "images", "count": count, "model": st.model}));
            side(st, format!("accepted: flat charge for {count} image(s)"));
            emit_settlement(app, st, to_client);
        }
        ClientMsg::Disclose { r, tail_lens, skip, key_updates, epoch_start, trailing } => {
            // Only once, and only after the upstream closed: the anchor is the
            // end of the final transcript.
            if st.state != SessionState::Attested || st.disclosed || st.accepted {
                bail!("disclose out of order or repeated");
            }
            st.disclosed = true;
            // Bound the verifier's work: π_C3S decrypts every covered record in
            // the circuit. An honest disclosure is the last one or two records
            // (usage event) or a short error head plus its body in `skip`.
            if tail_lens.len() > MAX_DISCLOSE_RECORDS {
                bail!("disclosure covers {} records (limit {MAX_DISCLOSE_RECORDS})", tail_lens.len());
            }
            if r.len() > 2 * MAX_DISCLOSE_R {
                bail!("disclosed R is too long");
            }
            if skip > MAX_DISCLOSE_NEED {
                bail!("skip {skip} exceeds {MAX_DISCLOSE_NEED}");
            }
            if key_updates > zkbench::statements::MAX_SERVER_KEY_UPDATES {
                bail!("{key_updates} server KeyUpdates (limit {})", zkbench::statements::MAX_SERVER_KEY_UPDATES);
            }
            if (key_updates == 0) != (epoch_start == 0) {
                bail!("epoch_start {epoch_start} does not fit {key_updates} server KeyUpdates");
            }
            let r = hex::decode(&r)?;
            check_disclosure_size(r.len(), skip)?;
            // Either the terminal usage event of a successful stream (anchored
            // at the end of the transcript), or, for an upstream error, only the
            // response head: its status decides the charge, the body stays
            // private (it sits in the `skip` bytes after the head).
            let error_head = r.starts_with(b"HTTP/1.");
            if st.images_count.is_some() && !error_head {
                bail!("an image session discloses only an error head (a success is accepted)");
            }
            let usage = if error_head {
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
            let chosen = log.covered_records(info.server_handshake_records, &tail_lens, trailing)?;
            // Covered records are in the last epoch: sequence numbers restart
            // at its first record. (A wrong claim only makes the proof fail:
            // the records then decrypt to noise under the derived key.)
            if chosen.first().is_some_and(|(idx, _)| *idx < epoch_start) {
                bail!("covered records start before the claimed key epoch");
            }
            let total: usize = chosen
                .iter()
                .map(|(_, rec)| rec.payload.len().saturating_sub(16 + 1))
                .sum();
            let need = r.len().checked_add(skip).ok_or_else(|| anyhow!("skip overflow"))?;
            if total < need {
                bail!("disclosed records ({total}) do not cover R + skip ({need})");
            }
            // An error head is the start of the response: it begins the first
            // covered record, and the records after it hold only its body.
            if error_head && total != need {
                bail!("an error head must start the first covered record ({total} content bytes, R + skip {need})");
            }
            // The proof decrypts the first covered record only from the
            // last block boundary that still covers R + skip, so its cost
            // follows the disclosure, not the size of the provider's records.
            // The proof decrypts at least one content byte of every covered
            // record: an empty one cannot be proven.
            if chosen.iter().any(|(_, rec)| rec.payload.len() < 16 + 2) {
                bail!("a covered record has no content");
            }
            let first_content = chosen.first().map(|(_, rec)| rec.payload.len().saturating_sub(16 + 1)).unwrap_or(0);
            let first_off = first_tail_offset(first_content, total - first_content, need);
            let records: Vec<zkbench::statements::TailRecord> = chosen
                .iter()
                .enumerate()
                .map(|(i, (idx, rec))| {
                    let off = if i == 0 { first_off } else { 0 };
                    zkbench::statements::TailRecord {
                        seq: (*idx - epoch_start) as u64,
                        ct: rec.payload[off..rec.payload.len() - 16].to_vec(),
                        off,
                    }
                })
                .collect();
            check_c3s_records(&records)?;
            info!(
                seqs = ?records.iter().map(|x| x.seq).collect::<Vec<_>>(),
                lens = ?records.iter().map(|x| x.ct.len()).collect::<Vec<_>>(),
                r_len = r.len(),
                "pi_c3s records"
            );
            let ap = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?;
            let params = Params::PiC3S(zkbench::statements::PiC3S { h2: ap.h2, records, expected: r, skip, key_updates });
            shared.params.lock().unwrap().insert("pi_c3s".into(), params.clone());
            send(serde_json::json!({"type":"zk_params","proof":"pi_c3s","params":params}));
        }
    }
    Ok(())
}

/// R and `skip` within what a usage proof can cover: R at most
/// `MAX_DISCLOSE_R`, and R + skip at most `MAX_DISCLOSE_NEED`, which always
/// fits the proof's ciphertext limit with the minimal tail.
fn check_disclosure_size(r_len: usize, skip: usize) -> Result<()> {
    if r_len > MAX_DISCLOSE_R {
        bail!("disclosed R is {r_len} bytes (limit {MAX_DISCLOSE_R})");
    }
    let need = r_len.checked_add(skip).ok_or_else(|| anyhow!("skip overflow"))?;
    if need > MAX_DISCLOSE_NEED {
        bail!("disclosed R + skip is {need} bytes (limit {MAX_DISCLOSE_NEED}): the usage proof cannot cover it");
    }
    Ok(())
}

/// The covered records within the usage proof's limits (count, and summed
/// ciphertext bytes), so the node never sends parameters that cannot be proven.
fn check_c3s_records(records: &[zkbench::statements::TailRecord]) -> Result<()> {
    use zkbench::statements::{MAX_C3S_BYTES, MAX_C3S_RECORDS};
    if records.len() > MAX_C3S_RECORDS {
        bail!("disclosure covers {} records (limit {MAX_C3S_RECORDS})", records.len());
    }
    let total = records.iter().try_fold(0usize, |acc, r| acc.checked_add(r.ct.len()));
    if total.is_none_or(|t| t > MAX_C3S_BYTES) {
        bail!("the covered records exceed {MAX_C3S_BYTES} ciphertext bytes: the usage proof cannot cover them");
    }
    Ok(())
}

/// The block-aligned offset into the first covered record (`first_content`
/// content bytes; the later ones hold `rest`) from which the usage proof
/// decrypts it: the last block boundary that still covers `need` bytes, and
/// never past its last content byte, which the proof always decrypts (also
/// when the later records alone cover `need`).
fn first_tail_offset(first_content: usize, rest: usize, need: usize) -> usize {
    let needed_first = need.saturating_sub(rest).clamp(1, first_content.max(1));
    (first_content - needed_first.min(first_content)) / 16 * 16
}

/// Indices (into the response's application-data records, ascending) of the
/// records that cover a disclosure: the final contiguous ones, matched from
/// the end by `tail_lens` (content length + 1, last record first). Only
/// records too short to carry response bytes may follow them: the server's
/// KeyUpdates (4 + 1 + 1 + 16 = 22 bytes) and a close_notify (2 + 1 + 16 =
/// 19). R ends in the terminal chunk, so nothing of the response can sit
/// after it anyway. Without `trailing`, one close_notify-sized record may be
/// skipped.
fn locate_tail(lens: &[usize], first_response: usize, tail_lens: &[usize], trailing: Option<usize>) -> Result<Vec<usize>> {
    let mut j: isize = lens.len() as isize - 1;
    match trailing {
        Some(n) => {
            if n > zkbench::statements::MAX_SERVER_KEY_UPDATES as usize + 1 {
                bail!("{n} trailing records (limit {})", zkbench::statements::MAX_SERVER_KEY_UPDATES + 1);
            }
            for _ in 0..n {
                if j < first_response as isize || lens[j as usize] > MAX_TRAILING_RECORD {
                    bail!("trailing records are not KeyUpdates or a close_notify");
                }
                j -= 1;
            }
        }
        None => {
            if let Some(first_want) = tail_lens.first() {
                if j >= first_response as isize && lens[j as usize] == 19 && lens[j as usize] - 16 != *first_want {
                    j -= 1;
                }
            }
        }
    }
    let mut chosen = Vec::with_capacity(tail_lens.len());
    for want in tail_lens {
        if j < first_response as isize {
            bail!("could not locate tail record of ciphertext length {want}");
        }
        if lens[j as usize].saturating_sub(16) != *want {
            bail!("tail record lengths do not match the end of the transcript");
        }
        chosen.push(j as usize);
        j -= 1;
    }
    chosen.reverse();
    Ok(chosen)
}

/// The keys `canonical_suffix` pins, in order (published in the offer).
const SUFFIX_KEYS: [&str; 7] = [
    "model",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "stream",
    "stream_options",
    "venice_parameters",
];

/// The public JSON suffix that pins every cost-relevant parameter (paper
/// §4.4 / A.2). Last-wins semantics at the provider make these the effective
/// values whatever the private prefix carries.
fn canonical_suffix(model: &str, max_tokens: u64) -> String {
    let m = serde_json::to_string(model).unwrap_or_else(|_| "\"\"".into());
    format!(
        ",\"model\":{m},\"max_tokens\":{max_tokens},\"max_completion_tokens\":{max_tokens},\"n\":1,\"stream\":true,\"stream_options\":{{\"include_usage\":true}},\"venice_parameters\":{{\"include_venice_system_prompt\":false,\"enable_web_search\":\"off\"}}}}"
    )
}

/// Whether the parameters a proof ran on are the session's stored ones. Both
/// must be present and serialize: a failure on either side is "changed".
fn same_params(proven: Option<&Params>, stored: Option<&Params>) -> bool {
    match (proven.map(serde_json::to_value), stored.map(serde_json::to_value)) {
        (Some(Ok(a)), Some(Ok(b))) => a == b,
        _ => false,
    }
}

/// Choose a block-aligned window ending at the record end that contains the
/// final `sel_len` content bytes (before the inner content-type byte).
fn window(sel_len: usize, ct_len: usize) -> (usize, usize, usize) {
    let w = (sel_len + 1 + 13).min(ct_len);
    let off = ct_len - w;
    let sel_start = w - 1 - sel_len;
    (w, off, sel_start)
}

/// Relay complete body records from `buf` (leaving a partial one in it). The
/// body plaintext must be exactly the declared length, and the record that
/// completes it (the pinned suffix) is held until π_C2S verifies.
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
        if r.ctype != CT_APPLICATION_DATA || r.payload.len() < 18 || 5 + r.payload.len() > MAX_TLS_RECORD {
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
            info!("final body record held until π_C2S verifies");
        } else {
            write_upstream(tcp_tx, &r.bytes(), st.deadline).await?;
            st.sent.update(&r.bytes());
        }
        log.client_app.push(r);
    }
    buf.drain(..used);
    Ok(())
}

/// Write the credential record and the KeyUpdate after it in one write, once
/// the client accepted (`release_head`) and π_NK (the record matches the
/// published template) ran to completion on the session's stored parameters;
/// whichever comes last triggers it. N, the prover, never learns the client's
/// verdict: `release_head` is the acceptance.
async fn write_head(
    st: &mut Session,
    log: &mut RelayLog,
    to_client: &mpsc::UnboundedSender<Message>,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    if !st.head_proof_ok || st.head_release.is_none() {
        return Ok(());
    }
    if st.state != SessionState::AwaitHead {
        bail!("credential record requested in state {:?}", st.state);
    }
    let ku = st.head_release.take().unwrap_or_default();
    let a = st.assembled.as_ref().ok_or_else(|| anyhow!("credential record not assembled"))?;
    // Atomic write: the credential record (seq 0) then the KeyUpdate (seq 1).
    let mut out = a.record.clone();
    out.extend_from_slice(&ku);
    write_upstream(tcp_tx, &out, st.deadline).await?;
    st.sent.update(&out);
    let (len, commit) = (a.record.len(), hex::encode(a.c_commit));
    st.state = SessionState::Body;
    info!(record_len = len, "credential record + KeyUpdate written to upstream");
    side(st, format!("credential_written len={len} c_commit={commit}"));
    let _ = to_client.send(Message::Text(serde_json::json!({"type":"head_written"}).to_string().into()));
    let mut held = std::mem::take(&mut st.held_client);
    relay_body(st, log, &mut held, tcp_tx).await?;
    if !held.is_empty() {
        st.held_client = held;
        bail!("partial client record buffered across the head write");
    }
    Ok(())
}

/// Whether `pending` starts with a ClientHello that offers exactly the joint
/// key share (checked once, as soon as both are there): false while either is
/// missing, an error for anything else.
fn check_hello(st: &mut Session, pending: &[u8]) -> Result<bool> {
    if st.ch_checked {
        return Ok(true);
    }
    if pending.first().is_some_and(|t| *t != tls::CT_HANDSHAKE) {
        bail!("first client record must be the ClientHello");
    }
    let Some(joint) = st.joint else { return Ok(false) };
    let (recs, _) = parse_records(pending);
    let Some(r) = recs.first() else { return Ok(false) };
    let msgs = tls::parse_handshake_messages(&r.payload);
    let [(ty, msg)] = msgs.as_slice() else { bail!("ClientHello must be one message in one record") };
    if *ty != tls::HS_CLIENT_HELLO || msg.len() != r.payload.len() {
        bail!("first client record must be exactly the ClientHello");
    }
    tls_v2::check_client_hello(msg, &joint)?;
    st.ch_checked = true;
    info!("v2 ClientHello checked: one P-256 share, the joint key");
    Ok(true)
}

/// Before the client Finished: relay the ClientHello only once the joint
/// key share is known and the hello offers exactly that share (else C could
/// complete the handshake alone), then CCS and the client Finished. Anything
/// after the Finished waits for the credential record.
async fn v2_pump_client(
    st: &mut Session,
    log: &mut RelayLog,
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
        if n > MAX_TLS_RECORD {
            bail!("client record of {n} bytes exceeds the TLS 1.3 limit");
        }
        if !st.ch_sent {
            if !check_hello(st, pending)? {
                return Ok(()); // wait for the 2PC
            }
            st.ch_sent = true;
        } else if r.ctype == tls::CT_CHANGE_CIPHER_SPEC {
            // relayed as is
        } else if r.ctype == CT_APPLICATION_DATA {
            // The client Finished (one encrypted record); then C waits for N.
            st.state = SessionState::AwaitHead;
        } else {
            bail!("unexpected client record type {} during the v2 handshake", r.ctype);
        }
        log.client_handshake_record(&pending[..n])?;
        write_upstream(tcp_tx, &pending[..n], st.deadline).await?;
        st.sent.update(&pending[..n]);
        pending.drain(..n);
        if st.state == SessionState::AwaitHead {
            st.held_client.append(pending);
            return Ok(());
        }
    }
}

/// Advance the joint handshake as U's messages and the 2PC outputs arrive.
async fn v2_progress(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &mut RelayLog,
) -> Result<()> {
    // Done once the credential record is assembled (and the raw logs stop
    // growing once the handshake is verified).
    if st.assembled.is_some() {
        return Ok(());
    }
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
        let (template, _) = placeholder_head(&st.head_template, app.key.len(), st.body_len)?;
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
        st.assembled = Some(Assembled { record: rec, c_commit });
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

/// The head with the API key spliced in; zeroized when dropped.
fn fill_head_now(app: &Arc<AppState>, st: &Session) -> Result<(Zeroizing<Vec<u8>>, Vec<usize>)> {
    let (head, offsets) = placeholder_head(&st.head_template, app.key.len(), st.body_len)?;
    let mut head = Zeroizing::new(head);
    for (i, off) in offsets.iter().enumerate() {
        head[*off] = app.key[i];
    }
    Ok((head, offsets))
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

/// The proof names a `/zk` connection may carry.
const ZK_PROOFS: [&str; 5] = ["twopc", "zkchan", "pi_nk", "pi_c2s", "pi_c3s"];

async fn zk_handler(socket: WebSocket, q: HashMap<String, String>, app: Arc<AppState>) {
    let proof = q.get("proof").cloned().unwrap_or_default();
    let sid = q.get("sid").cloned().unwrap_or_default();
    // Only a proof that actually ran reports its result to the session (and a
    // failed one ends it); zk_inner sends that report itself. A connection
    // refused before that (unknown proof name, no parameters yet, a second
    // 2PC or proof channel, a proof that already ran, too many connections,
    // the proof lock busy) only
    // closes, so whoever learns a live sid cannot end the session that way.
    // A proof channel that fails outside a proof also reports nothing: the
    // client falls back to the per-proof path.
    if let Err(e) = zk_inner(socket, &proof, &sid, &app).await {
        warn!(proof, error = %e, "zk session failed");
    }
}

/// Admit a `/zk` connection: a proof name the sidecar serves, a live sid,
/// and a free connection slot of that session. Reports nothing to the session.
fn zk_admit(app: &AppState, proof: &str, sid: &str) -> Result<(Arc<SessionShared>, ZkConnSlot)> {
    if !ZK_PROOFS.contains(&proof) {
        bail!("unknown proof name");
    }
    let shared = app.sessions.lock().unwrap().get(sid).cloned().ok_or_else(|| anyhow!("unknown sid"))?;
    let conn = ZkConnSlot::take(&shared.zk_conns)?;
    Ok((shared, conn))
}

async fn zk_inner(socket: WebSocket, proof: &str, sid: &str, app: &Arc<AppState>) -> Result<()> {
    let started = std::time::Instant::now();
    let (shared, _conn) = zk_admit(app, proof, sid)?;
    // The sid admits proof channels while the session is live: logged short.
    info!(proof, sid = sid.get(..12).unwrap_or(sid), "zk start");
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
    // One proof at a time per session (see SessionShared::zk_lock), waiting
    // for it at most PROOF_TIMEOUT. A proof that never got the lock did not
    // run, so it reports nothing.
    let Ok(_guard) = tokio::time::timeout(PROOF_TIMEOUT, shared.zk_lock.lock()).await else {
        bail!("zk proof waited {}s for the session's previous proof", PROOF_TIMEOUT.as_secs());
    };
    let (role, mut witness) = node_side(proof, &shared)?;
    shared.claim_proof(proof)?;
    let (io, bridge) = ws_duplex(socket);
    let result = match tokio::time::timeout(PROOF_TIMEOUT, zkbench::proofs::run_io(io, role, &params, witness.as_ref())).await {
        Ok(r) => r,
        Err(_) => {
            warn!(proof, "zk proof timed out ({}s)", PROOF_TIMEOUT.as_secs());
            Err(anyhow!("zk proof timed out after {}s", PROOF_TIMEOUT.as_secs()))
        }
    };
    wipe_witness(&mut witness);
    drop(_guard);
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
        "pi_nk" => {
            let kiv = shared.k0_iv0.lock().unwrap().clone().ok_or_else(|| anyhow!("no K_0 yet"))?;
            let witness = Witness::NodeKey {
                k0: <[u8; 16]>::try_from(&kiv[..16])?,
                iv0: <[u8; 12]>::try_from(&kiv[16..28])?,
                key: shared.key.to_vec(),
            };
            (Role::Prover, Some(witness))
        }
        _ => (Role::Verifier, None),
    })
}

/// Overwrite the node's copy of the API key and K_0/IV_0 in a π_NK witness
/// once the proof is done (the witness owns a plain copy of them).
fn wipe_witness(witness: &mut Option<Witness>) {
    use zeroize::Zeroize;
    if let Some(Witness::NodeKey { k0, iv0, key }) = witness {
        k0.zeroize();
        iv0.zeroize();
        key.zeroize();
    }
    *witness = None;
}

/// The session's long-lived proof channel (`zkbench::channel`). The
/// correlations for π_NK (node proves) and π_C2S/π_C3S (client proves) are
/// generated while the session is armed; at claim time the client requests
/// each proof by name and the node runs it against *its own* parameters for
/// that name (exactly like the per-proof path), reporting `Ev::ZkDone`.
///
/// Failure semantics: setup or transport failure outside a proof, and a
/// request the node cannot run (a name it does not serve, no parameters yet,
/// the proof lock busy), report nothing and close the channel (the client may
/// fall back to `/zk?proof=pi_*`); a proof that fails or times out on the
/// channel reports `ZkDone { ok: false }` and the session aborts, as with the
/// per-proof path. The channel never runs a second proof
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
        // A request the node cannot run (a name it does not serve, no
        // parameters yet, the proof lock busy, a proof that already ran) did
        // not run a proof: it closes
        // the channel without reporting to the session, which goes on (the
        // client may fall back to the per-proof path).
        let ready = async {
            if !matches!(proof.as_str(), "pi_nk" | "pi_c2s" | "pi_c3s") {
                bail!("{proof} is not served on the proof channel");
            }
            let params = shared.params.lock().unwrap().get(proof.as_str()).cloned().ok_or_else(|| anyhow!("no params for {proof}"))?;
            let Ok(guard) = tokio::time::timeout(PROOF_TIMEOUT, shared.zk_lock.lock()).await else {
                bail!("{proof} waited {}s for the session's previous proof", PROOF_TIMEOUT.as_secs());
            };
            let (_, witness) = node_side(&proof, shared)?;
            shared.claim_proof(&proof)?;
            Ok((params, guard, witness))
        }
        .await;
        let (params, guard, mut witness) = match ready {
            Ok(x) => x,
            Err(e) => {
                ch.poison();
                warn!(error = %e, "proof channel request refused");
                break;
            }
        };
        let result = match tokio::time::timeout(PROOF_TIMEOUT, ch.serve(&proof, &params, witness.as_ref())).await {
            Ok(r) => r,
            Err(_) => {
                ch.poison();
                Err(anyhow!("zk proof timed out after {}s", PROOF_TIMEOUT.as_secs()))
            }
        };
        wipe_witness(&mut witness);
        drop(guard);
        let params = Some(params);
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
/// line; π_C3S proves it sits `skip` bytes before the end of the response, so
/// the body stays private, and the disclosure check pins it to the start of a
/// record. Sound because a strict status line followed by
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
    // Field text: visible characters, spaces and tabs (obs-text allowed),
    // never a control character such as the LF that ends an event-stream line.
    let is_field_text = |v: &str| !v.chars().any(|c| c.is_ascii_control() && c != '\t');
    let mut parts = status_line.splitn(3, ' ');
    let (ver, code) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !(ver == "HTTP/1.1" || ver == "HTTP/1.0") || code.len() != 3 || !is_field_text(parts.next().unwrap_or("")) {
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
        if k.is_empty() || !k.chars().all(is_tchar) || !is_field_text(v) {
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
    // R starts either at a chunk-size line, or at an SSE line inside a chunk:
    // a raw "\n" then "data: ". Raw LF (and CR) never occur inside JSON
    // strings, so that LF ends a previous line of the event stream, and the
    // chunk's data runs to the first CRLF (SSE data carries no CR).
    if r.starts_with(b"\ndata: ") {
        let end = r
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("R: chunk data not terminated"))?;
        data.extend_from_slice(&r[1..end]);
        off = end + 2;
    }
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
        // `len` is up to 16 hex digits: the bounds use checked arithmetic.
        let end = off
            .checked_add(len)
            .filter(|e| e.checked_add(2).is_some_and(|t| t <= r.len()))
            .ok_or_else(|| anyhow!("R: chunk extends past the disclosed range"))?;
        data.extend_from_slice(&r[off..end]);
        off = end;
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
    // The last event starts at a line start: after the previous event's blank
    // line, or at the start of R (which begins at an event boundary).
    let start = match before.rfind("\ndata: ") {
        Some(i) => i + 7,
        None if before.starts_with("data: ") => 6,
        None => bail!("R: no data event before the terminator"),
    };
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
    if v.pointer("/usage/prompt_tokens").and_then(|t| t.as_u64()).is_none()
        || v.pointer("/usage/completion_tokens").and_then(|t| t.as_u64()).is_none()
    {
        bail!("R: usage event missing token counts");
    }
    Ok(v)
}

/// Hand the verified usage (π_C3S) or an image session's flat acceptance to
/// the node, or, without `--node-settles`, sign a stub receipt.
fn emit_settlement(app: &Arc<AppState>, st: &mut Session, to_client: &mpsc::UnboundedSender<Message>) {
    let Some(usage) = st.usage.clone() else { return };
    if app.node_settles {
        // The node holds the wallet and the Nostr key: it prices, refunds
        // and signs. An image usage carries the pinned model; a chat usage
        // event names its own (checked against the setup's).
        let model = if st.images_count.is_some() {
            st.model.clone()
        } else {
            usage.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string()
        };
        // An accepted image session is charged flat; its error head (like a
        // chat one) is handed over as verified by π_C3S.
        let usage = match (st.accepted, st.images_count) {
            (true, Some(count)) => serde_json::json!({"flat": true, "kind": "images", "count": count}),
            _ => usage,
        };
        let _ = to_client.send(Message::Text(
            serde_json::json!({
                "type":"usage",
                "sid": st.sid,
                "model": model,
                "usage": usage,
            }).to_string().into(),
        ));
        side(st, "usage handed to the node to settle".into());
        st.state = SessionState::Settled;
    } else if let Some(receipt) = settle(app, st) {
        // Prototype/stub settlement (sidecar signs). Sign the exact
        // serialized bytes so the client can verify without JSON
        // re-serialization drift.
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

#[cfg(test)]
mod disclosure_tests {
    use super::validate_r;

    fn chunked(body: &str) -> Vec<u8> {
        format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len()).into_bytes()
    }

    #[test]
    fn usage_event_must_start_a_line() {
        let usage = r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2},"model":"m"}"#;
        // At the start of R, or after the previous event's blank line.
        assert!(validate_r(&chunked(&format!("data: {usage}\n\ndata: [DONE]\n\n"))).is_ok());
        assert!(validate_r(&chunked(&format!("x\n\ndata: {usage}\n\ndata: [DONE]\n\n"))).is_ok());
        // "data: " inside a line is not an event start.
        assert!(validate_r(&chunked(&format!("xdata: {usage}\n\ndata: [DONE]\n\n"))).is_err());
    }
}

#[cfg(test)]
mod disclosure_line_start_tests {
    use super::validate_r;

    #[test]
    fn r_may_start_at_an_event_line_inside_a_chunk() {
        let usage = r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2},"model":"m"}"#;
        // The usage event and [DONE] in the middle of one big chunk.
        let r = format!("\ndata: {usage}\n\ndata: [DONE]\n\n\r\n0\r\n\r\n").into_bytes();
        assert!(validate_r(&r).is_ok());
        // Split across a chunk boundary after the event.
        let r = format!("\ndata: {usage}\n\n\r\ne\r\ndata: [DONE]\n\n\r\n0\r\n\r\n").into_bytes();
        assert!(validate_r(&r).is_ok());
        // Without the leading LF, a "data: " could be inside a JSON string.
        let r = format!("data: {usage}\n\ndata: [DONE]\n\n\r\n0\r\n\r\n").into_bytes();
        assert!(validate_r(&r).is_err());
    }
}

#[cfg(test)]
mod tail_offset_tests {
    use super::first_tail_offset;
    use cu_crypto::aesgcm;
    use zkbench::fixtures;
    use zkbench::proofs::run_pair_ideal;
    use zkbench::statements::{Params, PiC3S, TailRecord, Witness};

    #[test]
    fn the_first_record_keeps_a_content_byte() {
        // R + skip reaches into the first record: the last block boundary
        // that still covers it.
        assert_eq!(first_tail_offset(100, 10, 30), 80);
        assert_eq!(first_tail_offset(100, 10, 110), 0);
        assert_eq!(first_tail_offset(32, 10, 11), 16);
        // The later records alone cover R + skip: the proof still decrypts
        // the first record's last content byte (a tail of >= 2 bytes).
        for content in 1..100 {
            let off = first_tail_offset(content, 50, 40);
            assert_eq!(off % 16, 0);
            assert!(content + 1 - off >= 2, "content {content}: tail from {off}");
        }
        assert_eq!(first_tail_offset(32, 50, 40), 16);
    }

    fn sealed(secret: &cu_crypto::keyschedule::Secret, seq: u64, content: &[u8]) -> Vec<u8> {
        let mut inner = content.to_vec();
        inner.push(0x17);
        let ks = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), seq, inner.len());
        inner.iter().zip(ks).map(|(a, b)| a ^ b).collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disclosure_with_an_unneeded_first_record_proves() {
        // Two covered records; the second alone holds R, the first has 32
        // content bytes (a multiple of 16).
        let v = fixtures::v2_secrets();
        let secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
        let Params::PiC3S(base) = fixtures::pi_c3s().0 else { unreachable!() };
        let r = base.expected.clone();
        let first = sealed(&secret, 4, &[b'y'; 32]);
        let second = sealed(&secret, 5, &r);
        let params = |off: usize| {
            Params::PiC3S(PiC3S {
                h2: v.h2(),
                records: vec![
                    TailRecord { seq: 4, ct: first[off..].to_vec(), off },
                    TailRecord { seq: 5, ct: second.clone(), off: 0 },
                ],
                expected: r.clone(),
                skip: 0,
                key_updates: 0,
            })
        };
        let witness = Witness::Secret(v.s_ap_0);
        // Starting at the end of its content leaves a 1-byte tail: unprovable.
        assert!(run_pair_ideal(&params(32), &witness).await.is_err());
        let off = first_tail_offset(32, r.len(), r.len());
        let res = run_pair_ideal(&params(off), &witness).await.unwrap();
        assert!(res.iter().all(|c| c.ok), "tail from {off}");
    }
}

#[cfg(test)]
mod relay_log_tests {
    use super::{client_buffer_cap, RelayLog, ZkConnSlot, MAX_SERVER_BYTES, MAX_ZK_CONNS_PER_SESSION};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn raw_logs_stop_at_the_handshake_and_hashes_cover_everything() {
        let mut log = RelayLog::default();
        log.server_bytes(b"hello ", false).unwrap();
        log.server_bytes(b"world", true).unwrap();
        assert_eq!(log.server_raw, b"hello ");
        assert_eq!(log.recv_len, 11);
        assert_eq!(log.recv.hash(), cu_crypto::transcript::hash(b"hello world"));
    }

    #[test]
    fn unverified_client_bytes_and_server_bytes_are_capped() {
        let mut log = RelayLog::default();
        let big = vec![0u8; client_buffer_cap(100) + 1];
        assert!(super::buffer_client(&mut Vec::new(), &big, 100).is_err());

        let chunk = vec![0u8; 1 << 20];
        for _ in 0..MAX_SERVER_BYTES >> 20 {
            log.server_bytes(&chunk, true).unwrap();
        }
        assert!(log.server_bytes(b"x", true).is_err());
    }

    #[test]
    fn proof_connections_are_counted() {
        let count = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> = (0..MAX_ZK_CONNS_PER_SESSION).map(|_| ZkConnSlot::take(&count).unwrap()).collect();
        assert!(ZkConnSlot::take(&count).is_err());
        drop(slots);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(ZkConnSlot::take(&count).is_ok());
    }
}

#[cfg(test)]
mod head_release_tests {
    use super::{write_head, Assembled, RelayLog, Session, SessionState};
    use axum::extract::ws::Message;
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    async fn pair() -> (tokio::net::tcp::OwnedWriteHalf, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
        (c.unwrap().into_split().1, s.unwrap().0)
    }

    #[tokio::test]
    async fn the_head_waits_for_both_the_request_and_the_proof() {
        let (mut tx, mut peer) = pair().await;
        let (to_client, mut from) = mpsc::unbounded_channel::<Message>();
        let mut log = RelayLog::default();
        let mut st = Session {
            state: SessionState::AwaitHead,
            assembled: Some(Assembled { record: b"HEAD".to_vec(), c_commit: [0; 32] }),
            ..Session::default()
        };
        // Requested, proof not yet run: nothing is written.
        st.head_release = Some(b"KU".to_vec());
        write_head(&mut st, &mut log, &to_client, &mut tx).await.unwrap();
        assert!(st.head_release.is_some() && from.try_recv().is_err());
        // The proof completes: the record and the KeyUpdate go out at once.
        st.head_proof_ok = true;
        write_head(&mut st, &mut log, &to_client, &mut tx).await.unwrap();
        assert_eq!(st.state, SessionState::Body);
        assert!(matches!(from.try_recv(), Ok(Message::Text(t)) if t.contains("head_written")));
        drop(tx);
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"HEADKU");
        // Proof done but not requested: nothing happens.
        let (mut tx, _peer) = pair().await;
        let mut st2 = Session { head_proof_ok: true, state: SessionState::AwaitHead, ..Session::default() };
        write_head(&mut st2, &mut log, &to_client, &mut tx).await.unwrap();
        assert_eq!(st2.state, SessionState::AwaitHead);
    }
}

#[cfg(test)]
mod tail_locator_tests {
    use super::locate_tail;

    #[test]
    fn records_after_the_usage_event_are_skipped_only_when_tiny() {
        // Two handshake records, then the response: 80, 70, a KeyUpdate (22)
        // and a close_notify (19).
        let lens = [100, 100, 80, 70, 22, 19];
        assert_eq!(locate_tail(&lens, 2, &[54, 64], Some(2)).unwrap(), vec![2, 3]);
        // The legacy form skips only a close_notify.
        assert!(locate_tail(&lens, 2, &[54, 64], None).is_err());
        assert_eq!(locate_tail(&lens[..5], 2, &[6], None).unwrap(), vec![4]);
        assert_eq!(locate_tail(&lens[..4], 2, &[54], None).unwrap(), vec![3]);
        // Skipping a record that can carry response bytes is refused.
        assert!(locate_tail(&lens, 2, &[64], Some(3)).is_err());
        assert!(locate_tail(&[100, 80, 70, 23], 1, &[54], Some(1)).is_err());
        // Nor may the skip reach into the handshake flight.
        assert!(locate_tail(&[19, 19], 1, &[3], Some(2)).is_err());
        assert!(locate_tail(&lens, 2, &[54, 64], Some(99)).is_err());
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn rec(ctype: u8, len: usize) -> Record {
        let l = (len as u16).to_be_bytes();
        Record { ctype, header: [ctype, 3, 3, l[0], l[1]], payload: vec![0; len] }
    }

    fn app_state() -> Arc<AppState> {
        Arc::new(AppState {
            key: Arc::new(Zeroizing::new(b"k".repeat(32))),
            offer: Arc::new(serde_json::from_str(r#"{"upstream_host": "api.example.com"}"#).unwrap()),
            host: "api.example.com".into(),
            upstream: "127.0.0.1:9".into(),
            signer: Arc::new(SigningKey::from_bytes(&[7; 32])),
            runs_dir: std::env::temp_dir(),
            node_settles: true,
            sessions: StdMutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
            max_body: 1 << 20,
            token_hash: None,
        })
    }

    fn shared(app: &AppState) -> (Arc<SessionShared>, mpsc::UnboundedReceiver<Ev>) {
        let (evt, rx) = mpsc::unbounded_channel();
        let s = Arc::new(SessionShared {
            params: StdMutex::new(HashMap::new()),
            twopc_rx: StdMutex::new(None),
            k0_iv0: StdMutex::new(None),
            key: app.key.clone(),
            evt,
            zk_lock: tokio::sync::Mutex::new(()),
            zkchan_taken: std::sync::atomic::AtomicBool::new(false),
            zk_conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            proofs_run: StdMutex::new(Default::default()),
        });
        (s, rx)
    }

    fn venice_images() -> ImagesEndpoint {
        let offer: Offer = serde_json::from_str(include_str!("../offer.venice.json")).unwrap();
        let ep = offer.endpoints.images.unwrap();
        ep.validate("api.venice.ai", 42).unwrap();
        ep
    }

    fn images_app() -> Arc<AppState> {
        let mut offer: Offer = serde_json::from_str(include_str!("../offer.venice.json")).unwrap();
        let ep = offer.endpoints.images.as_mut().unwrap();
        ep.head_template = with_key_length(&ep.head_template, 32);
        offer.head_template = with_key_length(&offer.head_template, 32);
        let base = app_state();
        Arc::new(AppState {
            key: base.key.clone(),
            offer: Arc::new(offer),
            host: base.host.clone(),
            upstream: base.upstream.clone(),
            signer: base.signer.clone(),
            runs_dir: base.runs_dir.clone(),
            node_settles: true,
            sessions: StdMutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
            max_body: 1 << 20,
            token_hash: None,
        })
    }

    #[test]
    fn the_images_suffix_matches_the_shared_test_vector() {
        let ep = venice_images();
        let pins = vec![("format".to_string(), serde_json::json!("webp"))];
        let s = ep.render_suffix("z-image-turbo", 2, &pins);
        assert_eq!(
            s,
            r#","model":"z-image-turbo","variants":2,"return_binary":false,"enhance_prompt":false,"enable_web_search":false,"style_references":[],"format":"webp"}"#
        );
        assert_eq!(ep.check_suffix("z-image-turbo", &s).unwrap(), 2);
        let res = ep.render_suffix("m", 1, &[("resolution".into(), "2K".into()), ("format".into(), "webp".into())]);
        assert_eq!(ep.check_suffix("m", &res).unwrap(), 1);
    }

    #[test]
    fn an_images_suffix_outside_the_offer_is_refused() {
        let ep = venice_images();
        let ok = ep.render_suffix("m", 1, &[("format".into(), "webp".into())]);
        let fixed = r#""return_binary":false,"enhance_prompt":false,"enable_web_search":false,"style_references":[]"#;
        let bad = [
            ok.replace(r#""model":"m""#, r#""model":"other""#),
            ok.replace(r#""variants":1"#, r#""variants":0"#),
            ok.replace(r#""variants":1"#, r#""variants":5"#),
            ok.replace(r#""variants":1"#, r#""variants":"1""#),
            ok.replace(r#""enhance_prompt":false"#, r#""enhance_prompt":true"#),
            ok.replace(&format!(",{fixed}"), ""),
            ok.replace(r#""format":"webp""#, r#""format":"png""#),
            ok.replace(r#""format":"webp""#, r#""quality":"ultra""#),
            ok.replace(r#""format":"webp""#, r#""seed":1"#),
            ok.replace(r#""format":"webp""#, r#""format":"webp","format":"webp""#),
            ok.replace(r#""format":"webp""#, r#""variants":1"#),
            ok.replace(":", ": "),
            ok.trim_start_matches(',').to_string(),
            ok.trim_end_matches('}').to_string(),
            r#","model":"m","variants":1,"x":"}"#.to_string(),
        ];
        for b in bad {
            assert!(ep.check_suffix("m", &b).is_err(), "accepted {b}");
        }
    }

    #[test]
    fn an_offer_with_colliding_image_pins_is_refused() {
        let mut ep = venice_images();
        ep.param_space.insert("enhance_prompt".into(), vec![false.into()]);
        assert!(ep.validate("api.venice.ai", 42).is_err());
        let mut ep = venice_images();
        ep.count_key = "model".into();
        assert!(ep.validate("api.venice.ai", 42).is_err());
        let mut ep = venice_images();
        ep.head_template = ep.head_template.replace("Connection: close", "Connection: keep-alive");
        assert!(ep.validate("api.venice.ai", 42).is_err());
        assert!(venice_images().validate("api.other.ai", 42).is_err());
        for idle in [0, 29, 601] {
            let mut ep = venice_images();
            ep.response_idle_s = idle;
            assert!(ep.validate("api.venice.ai", 42).is_err(), "response_idle_s {idle}");
        }
        // A fixed pin may only switch an extra off.
        for on in [serde_json::json!(true), serde_json::json!(["x"]), serde_json::json!("on"), serde_json::json!(1)] {
            let mut ep = venice_images();
            ep.fixed_pins.push(("embed_exif_metadata".into(), on.clone()));
            assert!(ep.validate("api.venice.ai", 42).is_err(), "fixed pin {on}");
        }
        let mut ep = venice_images();
        ep.fixed_pins.push(("embed_exif_metadata".into(), serde_json::json!(false)));
        assert!(ep.validate("api.venice.ai", 42).is_ok());
    }

    fn setup(kind: Option<&str>, extra: serde_json::Value) -> serde_json::Value {
        let mut v = serde_json::json!({"type": "setup", "nonce_c": "11".repeat(32), "model": "m", "len": 100});
        if let Some(k) = kind {
            v["kind"] = k.into();
        }
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    }

    fn run_setup(app: &Arc<AppState>, v: serde_json::Value) -> Result<(Session, serde_json::Value)> {
        let (s, _rx) = shared(app);
        let (tx, mut out) = mpsc::unbounded_channel();
        let mut st = Session::default();
        handle_setup(serde_json::from_value(v)?, app, &s, &tx, &mut st)?;
        let Some(Message::Text(t)) = out.try_recv().ok() else { bail!("no ready") };
        Ok((st, serde_json::from_str(&t)?))
    }

    #[test]
    fn image_setups_take_the_node_suffix_and_chat_setups_stay_as_they_were() {
        let app = images_app();
        let suffix = venice_images().render_suffix("m", 3, &[("format".into(), "webp".into())]);
        let (st, ready) = run_setup(&app, setup(Some("images"), serde_json::json!({"suffix": suffix, "count": 3}))).unwrap();
        assert_eq!(st.images_count, Some(3));
        assert_eq!(ready["suffix"], suffix);
        assert_eq!(ready["kind"], "images");
        assert!(st.head_template.starts_with("POST /api/v1/image/generate "));
        let (st, ready) = run_setup(&app, setup(None, serde_json::json!({"max_tokens": 7}))).unwrap();
        assert_eq!(st.images_count, None);
        assert_eq!(ready["suffix"], canonical_suffix("m", 7));
        assert!(ready.get("kind").is_none());
        for bad in [
            setup(Some("video"), serde_json::json!({"max_tokens": 7})),
            setup(Some("images"), serde_json::json!({})),
            setup(Some("images"), serde_json::json!({"suffix": suffix, "count": 2})),
            setup(Some("images"), serde_json::json!({"suffix": suffix, "armed": true})),
            setup(Some("images"), serde_json::json!({"suffix": suffix, "max_tokens": 7})),
            setup(Some("chat"), serde_json::json!({"max_tokens": 7, "count": 1})),
            setup(Some("chat"), serde_json::json!({"max_tokens": 7, "suffix": suffix})),
        ] {
            assert!(run_setup(&app, bad.clone()).is_err(), "accepted {bad}");
        }
        // A sidecar without the images endpoint refuses image setups.
        assert!(run_setup(&app_state(), setup(Some("images"), serde_json::json!({"suffix": suffix}))).is_err());
    }

    #[test]
    fn accept_is_for_attested_image_sessions_once() {
        let app = images_app();
        let (s, _rx) = shared(&app);
        let (tx, mut out) = mpsc::unbounded_channel();
        let mut st = Session { images_count: Some(2), model: "m".into(), sid: Some("ab".into()), ..Session::default() };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let c = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
            let (_r, mut w) = c.into_split();
            let mut log = RelayLog::default();
            let mut go = |st: &mut Session| {
                let msg = ClientMsg::Accept {};
                let fut = handle_control(msg, &app, &s, &tx, st, &mut log, &mut w);
                futures_executor_block(fut)
            };
            st.state = SessionState::Body;
            assert!(go(&mut st).is_err(), "before the attestation");
            st.state = SessionState::Attested;
            assert!(go(&mut st).is_err(), "before π_C2S");
            st.c2_ok = true;
            go(&mut st).unwrap();
            let Some(Message::Text(t)) = out.try_recv().ok() else { panic!("no usage frame") };
            let v: serde_json::Value = serde_json::from_str(&t).unwrap();
            assert_eq!(v["usage"], serde_json::json!({"flat": true, "kind": "images", "count": 2}));
            assert_eq!(v["model"], "m");
            assert_eq!(st.state, SessionState::Settled);
            st.state = SessionState::Attested;
            assert!(go(&mut st).is_err(), "twice");
            let mut chat = Session { state: SessionState::Attested, c2_ok: true, ..Session::default() };
            assert!(go(&mut chat).is_err(), "on a chat session");
            let mut disclosed = Session { images_count: Some(1), state: SessionState::Attested, c2_ok: true, disclosed: true, ..Session::default() };
            assert!(go(&mut disclosed).is_err(), "after a disclosure");
            // An image session discloses only an error head, never a usage event.
            let mut img = Session { images_count: Some(1), state: SessionState::Attested, c2_ok: true, ..Session::default() };
            let usage = ClientMsg::Disclose {
                r: hex::encode(b"data: {\"usage\":{}}\n\n"),
                tail_lens: vec![40],
                skip: 0,
                key_updates: 0,
                epoch_start: 0,
                trailing: None,
            };
            let err = futures_executor_block(handle_control(usage, &app, &s, &tx, &mut img, &mut log, &mut w)).unwrap_err();
            assert!(err.to_string().contains("only an error head"), "{err}");
        });
    }

    /// Poll a future that never actually waits (the accept path does no I/O).
    fn futures_executor_block<F: std::future::Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("accept waited"),
        }
    }

    #[test]
    fn an_image_session_caps_the_response_at_its_endpoint_limit() {
        let mut log = RelayLog { max_server_bytes: Some(10), ..RelayLog::default() };
        assert!(log.server_bytes(&[0; 8], true).is_ok());
        assert!(log.server_bytes(&[0; 3], true).is_err());
    }

    #[test]
    fn the_offer_names_the_keys_the_suffix_pins() {
        let s = canonical_suffix("m", 5);
        let v: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&format!("{{{}", &s[1..])).unwrap();
        let mut keys: Vec<&str> = v.keys().map(|k| k.as_str()).collect();
        let mut want = SUFFIX_KEYS.to_vec();
        keys.sort();
        want.sort();
        assert_eq!(keys, want);
    }

    #[test]
    fn an_error_head_is_a_strict_status_line_and_headers() {
        let ok = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\r\n";
        assert_eq!(validate_error_head(ok).unwrap()["error_status"], 503);
        // A reason phrase or header value carrying an event-stream line end.
        assert!(validate_error_head(b"HTTP/1.1 503 x\"}]}\n\n\r\nA: b\r\n\r\n").is_err());
        assert!(validate_error_head(b"HTTP/1.1 503 x\r\nA: b\n\r\n\r\n").is_err());
        assert!(validate_error_head(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\n").is_err());
        assert!(validate_error_head(b"HTTP/1.1 503 x\r\n1a3\r\n\r\n").is_err());
    }

    #[test]
    fn anything_but_a_client_hello_is_refused_before_the_dial() {
        let mut st = Session::default();
        // Before the key share: a handshake record is awaited, anything else refused.
        assert!(!check_hello(&mut st, &[]).unwrap());
        assert!(!check_hello(&mut st, &[tls::CT_HANDSHAKE, 3, 1]).unwrap());
        assert!(check_hello(&mut st, &[CT_APPLICATION_DATA]).is_err());
        st.joint = Some([4; 65]);
        let mut garbage = rec(tls::CT_HANDSHAKE, 8).bytes();
        assert!(!check_hello(&mut st, &garbage[..7]).unwrap());
        garbage[5] = tls::HS_CLIENT_HELLO;
        assert!(check_hello(&mut st, &garbage).is_err());
        assert!(!st.ch_checked);
    }

    #[test]
    fn each_proof_runs_once_per_session() {
        let app = app_state();
        let (s, _rx) = shared(&app);
        assert!(s.claim_proof("pi_c3s").is_ok());
        assert!(s.claim_proof("pi_c2s").is_ok());
        assert!(s.claim_proof("pi_c3s").is_err());
    }

    #[test]
    fn a_huge_chunk_size_is_an_error_not_a_panic() {
        // 16 hex digits = usize::MAX: the bounds arithmetic must not wrap.
        assert!(validate_r(b"ffffffffffffffff\r\nAAAA\r\n0\r\n\r\n").is_err());
        assert!(validate_r(b"fffffffffffffffe\r\nAAAA\r\n0\r\n\r\n").is_err());
        assert!(validate_r(b"\ndata: x\r\nffffffffffffffff\r\nAAAA\r\n0\r\n\r\n").is_err());
        // A chunk ending exactly at the end of R, without its CRLF.
        assert!(validate_r(b"4\r\nAAAA").is_err());
    }

    #[test]
    fn the_first_tail_offset_keeps_what_the_proof_needs() {
        // For every shape: block-aligned, at least one content byte (plus the
        // inner type byte) decrypted, and enough of the record to cover the
        // part of R + skip the later records do not.
        for first in 1..80usize {
            for rest in [0usize, 1, 15, 16, 17, 50] {
                for need in 1..=first + rest {
                    let off = first_tail_offset(first, rest, need);
                    assert_eq!(off % 16, 0);
                    assert!(off < first, "{first} {rest} {need}: off {off}");
                    assert!(first - off >= need.saturating_sub(rest), "{first} {rest} {need}: off {off}");
                    // The last boundary that does: one block later fails.
                    let next = off + 16;
                    assert!(next >= first || first - next < need.saturating_sub(rest).max(1));
                }
            }
        }
    }

    #[test]
    fn only_the_response_tail_is_kept_and_indices_stay_absolute() {
        let mut log = RelayLog::default();
        // Unencrypted handshake records, 3 encrypted handshake records, then
        // a long response, a KeyUpdate and a close_notify.
        log.server_record(rec(tls::CT_HANDSHAKE, 90));
        log.server_record(rec(tls::CT_CHANGE_CIPHER_SPEC, 1));
        for _ in 0..3 {
            log.server_record(rec(CT_APPLICATION_DATA, 500));
        }
        let n = 1000;
        for i in 0..n {
            log.server_record(rec(CT_APPLICATION_DATA, 100 + i % 7));
        }
        log.server_record(rec(CT_APPLICATION_DATA, 22));
        log.server_record(rec(CT_APPLICATION_DATA, 19));
        assert_eq!(log.server_records, 2 + 3 + n + 2);
        assert_eq!(log.server_tail.len(), SERVER_TAIL_RECORDS);
        // The last two response records (lengths 100 + 998 % 7, 100 + 999 % 7).
        let want = [100 + 998 % 7 - 16, 100 + 999 % 7 - 16];
        let got = log.covered_records(3, &[want[1], want[0]], Some(2)).unwrap();
        let idx: Vec<usize> = got.iter().map(|(i, _)| *i).collect();
        assert_eq!(idx, vec![n - 2, n - 1]);
        // The largest disclosure still fits in what is kept.
        let lens: Vec<usize> = (n + 2 - MAX_DISCLOSE_RECORDS - 2..n).rev().map(|i| 100 + i % 7 - 16).collect();
        let got = log.covered_records(3, &lens, Some(2)).unwrap();
        assert_eq!(got.len(), MAX_DISCLOSE_RECORDS);
        assert_eq!(got[0].0, n - MAX_DISCLOSE_RECORDS);
        // A short response: the handshake flight is still excluded.
        let mut log = RelayLog::default();
        for len in [500, 500, 80, 70] {
            log.server_record(rec(CT_APPLICATION_DATA, len));
        }
        assert_eq!(log.covered_records(2, &[54, 64], Some(0)).unwrap().iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1]);
        assert!(log.covered_records(2, &[54, 64, 484], Some(0)).is_err());
    }

    #[tokio::test]
    async fn an_upstream_write_ends_at_the_session_deadline() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(TcpStream::connect(addr), l.accept());
        let _peer = s.unwrap().0; // never reads
        let (_, mut tx) = c.unwrap().into_split();
        let big = vec![0u8; 64 << 20];
        let t = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
        assert!(write_upstream(&mut tx, &big, Some(deadline)).await.is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "took {:?}", t.elapsed());
    }

    #[test]
    fn debug_output_names_events_without_their_bytes() {
        let hs = HsSecrets { client_hs: [0xab; 32], server_hs: [0xcd; 32] };
        assert!(!format!("{hs:?}").contains("171"));
        let ev = Ev::Hs(hs);
        assert_eq!(format!("{ev:?}"), "Hs");
        let ap = Ev::Ap(Box::new(ApN {
            k0: Zeroizing::new([0xab; 16]),
            iv0: Zeroizing::new([0xab; 12]),
            h1: [0xab; 32],
            h2: [0xab; 32],
            hk: [0xab; 32],
        }));
        assert_eq!(format!("{ap:?}"), "Ap");
        assert_eq!(format!("{:?}", Ev::ServerBytes(vec![0xab; 5])), "ServerBytes(5 bytes)");
    }

    #[test]
    fn the_node_witness_is_wiped_after_use() {
        let app = app_state();
        let (s, _rx) = shared(&app);
        let mut kiv = Zeroizing::new(vec![1u8; 16]);
        kiv.extend_from_slice(&[2u8; 12]);
        *s.k0_iv0.lock().unwrap() = Some(kiv);
        let (role, mut w) = node_side("pi_nk", &s).unwrap();
        assert!(matches!(role, Role::Prover));
        match &w {
            Some(Witness::NodeKey { k0, iv0, key }) => {
                assert_eq!(k0[..], [1u8; 16]);
                assert_eq!(iv0[..], [2u8; 12]);
                assert_eq!(key[..], app.key[..]);
            }
            _ => panic!("π_NK needs the node's key"),
        }
        wipe_witness(&mut w);
        assert!(w.is_none());
        assert!(matches!(node_side("pi_c2s", &s).unwrap(), (Role::Verifier, None)));
    }

    #[tokio::test]
    async fn zk_refusals_before_a_proof_report_nothing() {
        let app = app_state();
        let (s, mut rx) = shared(&app);
        app.sessions.lock().unwrap().insert("sid".into(), s.clone());
        assert!(zk_admit(&app, "pi_bogus", "sid").is_err());
        assert!(zk_admit(&app, "pi_nk", "other").is_err());
        let held: Vec<_> = (0..MAX_ZK_CONNS_PER_SESSION).map(|_| zk_admit(&app, "pi_c3s", "sid").unwrap()).collect();
        assert!(zk_admit(&app, "pi_c3s", "sid").is_err());
        drop(held);
        assert!(zk_admit(&app, "twopc", "sid").is_ok());
        // None of these reached the session's event loop.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn session_cleanup_runs_on_drop() {
        let app = app_state();
        let (s, _rx) = shared(&app);
        let (other, _rx2) = shared(&app);
        app.sessions.lock().unwrap().insert("a".into(), s.clone());
        app.sessions.lock().unwrap().insert("b".into(), other);
        let budget = Arc::new(tokio::sync::Semaphore::new(1));
        // A reader parked forever (as on an idle upstream socket).
        let reader = tokio::spawn(std::future::pending::<()>());
        let abort = reader.abort_handle();
        let cleanup = SessionCleanup { app: app.clone(), shared: s, budget: budget.clone(), reader: Some(reader) };
        drop(cleanup);
        tokio::task::yield_now().await;
        assert!(budget.is_closed());
        assert!(abort.is_finished());
        let sessions = app.sessions.lock().unwrap();
        assert!(!sessions.contains_key("a") && sessions.contains_key("b"));
    }

    #[tokio::test]
    async fn a_panicking_session_still_cleans_up() {
        let app = app_state();
        let (s, _rx) = shared(&app);
        app.sessions.lock().unwrap().insert("a".into(), s.clone());
        let budget = Arc::new(tokio::sync::Semaphore::new(1));
        let app2 = app.clone();
        let b2 = budget.clone();
        let task = tokio::spawn(async move {
            let _cleanup = SessionCleanup { app: app2, shared: s, budget: b2, reader: None };
            let r: Result<()> = std::panic::AssertUnwindSafe(async {
                let _ = validate_r(b"0\r\n\r\n");
                panic!("bug");
            })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(anyhow!("internal error in the session")));
            r
        });
        assert!(task.await.unwrap().is_err());
        assert!(budget.is_closed());
        assert!(app.sessions.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod disclosure_limit_tests {
    use super::{check_c3s_records, check_disclosure_size, MAX_DISCLOSE_NEED, MAX_DISCLOSE_R};
    use zkbench::statements::{TailRecord, MAX_C3S_BYTES, MAX_C3S_RECORDS};

    fn rec(len: usize) -> TailRecord {
        TailRecord { seq: 0, ct: vec![0; len], off: 0 }
    }

    #[test]
    fn disclosures_the_proof_cannot_cover_are_refused() {
        assert!(check_disclosure_size(200, 0).is_ok());
        assert!(check_disclosure_size(MAX_DISCLOSE_R, MAX_DISCLOSE_NEED - MAX_DISCLOSE_R).is_ok());
        assert!(check_disclosure_size(MAX_DISCLOSE_R + 1, 0).is_err());
        assert!(check_disclosure_size(100, MAX_DISCLOSE_NEED - 99).is_err());
        assert!(check_disclosure_size(100, 1 << 20).is_err());
        assert!(check_disclosure_size(100, usize::MAX).is_err());

        assert!(check_c3s_records(&[rec(MAX_C3S_BYTES - 100), rec(100)]).is_ok());
        assert!(check_c3s_records(&[rec(MAX_C3S_BYTES - 100), rec(101)]).is_err());
        let many: Vec<_> = (0..=MAX_C3S_RECORDS).map(|_| rec(2)).collect();
        assert!(check_c3s_records(&many).is_err());
        assert!(check_c3s_records(&many[1..]).is_ok());
    }
}

#[cfg(test)]
mod same_params_tests {
    use super::same_params;
    use zkbench::fixtures;

    #[test]
    fn only_equal_present_params_are_the_same() {
        let (a, _) = fixtures::pi_c2s();
        let (b, _) = fixtures::pi_c2s_after(1);
        assert!(same_params(Some(&a), Some(&a.clone())));
        assert!(!same_params(Some(&a), Some(&b)));
        assert!(!same_params(Some(&a), None));
        assert!(!same_params(None, Some(&a)));
        assert!(!same_params(None, None));
    }
}
