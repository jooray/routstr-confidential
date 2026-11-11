//! A framing-"2" connection (`PROTOCOL-V3.md` §5, §12.6, §12.8):
//! one two-party handshake, N writes the HTTP/2 connection head with the
//! credential once in epoch 0, and C then sends sequential requests that
//! refer to it by HPACK index.
//!
//! Security-critical rules, all enforced here:
//!   * Every client record is one HTTP/2 frame, queued in arrival order (the
//!     order of its TLS sequence number) and written to the upstream only
//!     after a π_WIN that covers it verified, and, for a request's records,
//!     only up to the client's `release`.
//!   * N builds every π_WIN and π_C3S parameter from its own buffers: the
//!     queued client records, the server records it received.
//!   * A request's disclosure covers only server records received after N
//!     wrote that request's first record (`S_k`), runs to the last server
//!     record N holds, and must show the request's stream ending.
//!   * After an error, an abort or a failed proof the connection is closed;
//!     only a settled 2xx request leaves it open for the next one.

use std::collections::VecDeque;

use super::*;
use crate::h2::{self, Ctl};

/// Upstream bytes after which a connection is closed at its next settlement:
/// its receive window (2^31-1, set by the connection head) is never
/// replenished, so it is retired long before the window can run out.
pub(crate) const H2_CONN_SOFT_BYTES: usize = 1 << 30;
/// The most a connection may receive at all: the soft limit, the request in
/// flight when it was reached (at most one response cap) and one more.
pub(crate) const H2_CONN_MAX_BYTES: usize = H2_CONN_SOFT_BYTES + 2 * MAX_SERVER_BYTES;
/// Most control records queued unproven.
const MAX_QUEUED_CTL: usize = 16;
/// Most records an error head may span (a response head is about 1 kB).
const MAX_HEAD_RECORDS: usize = 8;

#[derive(Debug, Clone, Copy)]
enum RecKind {
    Ctl(Ctl),
    Headers,
    Data { last: bool },
}

/// A client record held by N.
struct Rec {
    /// Its TLS sequence number under `c_ap_1` (the first record C writes
    /// after its Finished is 0).
    seq: u64,
    /// The record as received (header, ciphertext, tag).
    bytes: Vec<u8>,
    kind: RecKind,
    /// A verified π_WIN covers it.
    proven: bool,
    /// 1-based position among its request's records; 0 for a control record.
    req_idx: usize,
}

enum WinInflight {
    /// The first `n` unproven queued records.
    Records(usize),
    /// The current request's error head (server records under `s_ap_0`).
    ErrorHead,
}

/// One request on the connection.
struct Req {
    n: u32,
    stream: u32,
    model: String,
    /// `Some(count)` for an image request (settled flat on `accept`).
    images: Option<u64>,
    /// Most upstream bytes its interval may hold (the response cap).
    cap: usize,
    body_len: usize,
    suffix: String,
    /// The public header block of its HEADERS frame.
    block: Vec<u8>,
    /// Records received (HEADERS and DATA), DATA payload bytes among them,
    /// and whether the body is complete.
    records: usize,
    data_bytes: usize,
    complete: bool,
    /// The client's release limit and the records written to the upstream.
    upto: usize,
    written: usize,
    released: bool,
    /// `S_k`: the index (among the server's application-data records since
    /// the connection began) of the first server record of this request's
    /// interval; set when N writes the request's first record.
    s_k: Option<usize>,
    /// The interval: server records since `S_k`, until the disclosure.
    interval_open: bool,
    recv: cu_crypto::transcript::Transcript,
    recv_records: usize,
    recv_bytes: usize,
    /// The request's records as written to the upstream.
    sent: cu_crypto::transcript::Transcript,
    /// The disclosed usage (or error status), settled once its proof verifies.
    usage: Option<serde_json::Value>,
    /// The proof the settlement waits for.
    settle_on: Option<&'static str>,
    attestation: Option<serde_json::Value>,
}

/// Per-connection state of a framing-"2" connection.
pub(crate) struct H2 {
    cfg: h2::H2Block,
    /// The request path (the chat route of the offer's head template), and
    /// the images route when the connection serves image requests.
    path: String,
    images_path: Option<String>,
    /// Client bytes that do not yet form a record, the records held, and
    /// their size.
    pending: Vec<u8>,
    queue: VecDeque<Rec>,
    held: usize,
    next_seq: u64,
    /// The control frame the client declared for its next record.
    next_ctl: Option<Ctl>,
    win: Option<WinInflight>,
    /// Requests started on this connection.
    requests: u32,
    req: Option<Req>,
    tcp_closed: bool,
    /// Set to end the session in order (the loop sends `closed`).
    pub(crate) closing: Option<&'static str>,
    conn_end: Option<tokio::time::Instant>,
    /// When the connection head was written.
    head_at: Option<std::time::Instant>,
    /// The client reported the provider's SETTINGS (`settings_seen`).
    settings_seen: bool,
    /// The first request's response began (told to the offer guard once).
    responded: bool,
    responded_told: bool,
}

impl H2 {
    fn new(cfg: h2::H2Block, path: String, images_path: Option<String>) -> Self {
        H2 {
            cfg,
            path,
            images_path,
            pending: Vec::new(),
            queue: VecDeque::new(),
            held: 0,
            next_seq: 0,
            next_ctl: None,
            win: None,
            requests: 0,
            req: None,
            tcp_closed: false,
            closing: None,
            conn_end: None,
            head_at: None,
            settings_seen: false,
            responded: false,
            responded_told: false,
        }
    }

    /// True once, when the first response of the connection began.
    pub(crate) fn first_response(&mut self) -> bool {
        self.responded && !std::mem::replace(&mut self.responded_told, true)
    }

    /// The provider closed the connection on its head: soon after it was
    /// written, with no response to a request yet.
    pub(crate) fn open_failed(&self) -> bool {
        !self.responded && self.head_at.is_some_and(|t| t.elapsed() < H2_OPEN_WINDOW)
    }

    /// No request in flight: an expired deadline is the idle limit.
    pub(crate) fn idle(&self) -> bool {
        self.req.is_none()
    }

    /// Most client bytes held at once: the request being collected (its body,
    /// framing, and the HEADERS record) and a few control records.
    fn buffer_limit(&self) -> usize {
        let ctl = (MAX_QUEUED_CTL + 1) * 64;
        match &self.req {
            Some(q) => q.body_len + max_records(q.body_len) * 40 + 1024 + ctl,
            None => ctl,
        }
    }

    /// A complete server record, in arrival order: part of the current
    /// request's interval while it is open. A response past the request's
    /// cap ends the connection.
    pub(crate) fn server_record(&mut self, r: &Record) -> Result<()> {
        if r.ctype != CT_APPLICATION_DATA {
            return Ok(());
        }
        if let Some(q) = self.req.as_mut().filter(|q| q.interval_open) {
            q.recv.update(&r.header);
            q.recv.update(&r.payload);
            q.recv_records += 1;
            q.recv_bytes += 5 + r.payload.len();
            self.responded = true;
            if q.recv_bytes > q.cap {
                bail!("the response to request {} exceeds {} bytes", q.n, q.cap);
            }
        }
        Ok(())
    }

    fn idle_deadline(&self) -> tokio::time::Instant {
        let idle = tokio::time::Instant::now() + std::time::Duration::from_secs(self.cfg.idle_secs);
        self.conn_end.map_or(idle, |end| end.min(idle))
    }
}

/// Most records one request may arrive in: its HEADERS, and DATA frames that
/// average at least 4 KiB (a client sends full records and one for the suffix).
fn max_records(body_len: usize) -> usize {
    3 + body_len / 4096
}

/// The images route of an offer whose `h2` block serves image requests
/// (`None` when it does not): the path of the images endpoint's template.
pub(crate) fn images_path(offer: &Offer) -> Result<Option<String>> {
    if !offer.h2.as_ref().is_some_and(|b| b.serves("images")) {
        return Ok(None);
    }
    let ep = offer.endpoints.images.as_ref().ok_or_else(|| anyhow!("h2 kinds lists images, but the offer has no images endpoint"))?;
    Ok(Some(chat_path(&ep.head_template).context("the images endpoint's head template")?))
}

/// The path of a request route (`POST <path> HTTP/1.1` of a head template,
/// checked at startup): the offer's chat template, or its images endpoint's.
pub(crate) fn chat_path(head_template: &str) -> Result<String> {
    head_template
        .strip_prefix("POST ")
        .and_then(|t| t.split_once(" HTTP/1.1\r\n"))
        .map(|(p, _)| p.to_string())
        .filter(|p| h2::path_ok(p))
        .ok_or_else(|| anyhow!("the head template names no usable request path"))
}

/// The setup of a framing-"2" connection: no request terms, only the connection.
pub(crate) fn handle_setup(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    nonce_c: &str,
    escrow: Option<&str>,
    escrow_e: u64,
    armed: bool,
) -> Result<()> {
    let cfg = app.offer.h2.clone().ok_or_else(|| anyhow!("this sidecar offers no http: 2 sessions"))?;
    let (sid, nonce_n) = session_id(nonce_c, escrow, escrow_e)?;
    let (head, _) = h2::head(&app.offer.upstream_host, &cfg.probe_path, app.key.len())?;
    st.sid = Some(sid.clone());
    st.body_len = 0;
    st.head_len = head.len();
    st.h2 = Some(Box::new(H2::new(cfg.clone(), chat_path(&app.offer.head_template)?, images_path(&app.offer)?)));
    let _ = shared;
    st.run_dir = Some(init_run_dir(app, &sid)?);
    app.sessions.lock().unwrap().insert(sid.clone(), shared.clone());
    side(st, format!("setup sid={sid} http=2 armed={armed} node_settles={}", app.node_settles));
    let _ = to_client.send(Message::Text(
        serde_json::json!({
            "type":"ready","v":3,"http":"2","sid":sid,"nonce_n":hex::encode(nonce_n),
            "pubkey":app.offer.notary_pubkey,"armed":armed,"head_len":head.len(),"h2":cfg,
        })
        .to_string()
        .into(),
    ));
    Ok(())
}

/// The head template (zeros at the key's positions) and the key's positions.
pub(crate) fn head_template(app: &AppState, h: &H2) -> Result<(Vec<u8>, Vec<usize>)> {
    h2::head(&app.offer.upstream_host, &h.cfg.probe_path, app.key.len())
}

/// The connection head and the KeyUpdate are written: the connection is
/// open and idle.
pub(crate) fn head_written(st: &mut Session) {
    let Some(h) = st.h2.as_mut() else { return };
    h.conn_end = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(h.cfg.max_lifetime_s));
    h.head_at = Some(std::time::Instant::now());
    st.deadline = Some(h.idle_deadline());
}

/// `request`: the terms of the next request (what a v2 setup carries).
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_request(
    app: &Arc<AppState>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    n: u32,
    kind: Option<&str>,
    model: String,
    max_tokens: u64,
    body_len: usize,
    suffix: Option<&str>,
    count: Option<u64>,
) -> Result<()> {
    if st.state != SessionState::Body {
        bail!("request before the connection head was written");
    }
    let sid = st.sid.clone().unwrap_or_default();
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("request on a session that is not framing 2"))?;
    if h.req.is_some() {
        bail!("a request is already in flight (requests are sequential)");
    }
    if h.tcp_closed || h.closing.is_some() {
        bail!("the connection is closing");
    }
    if n != h.requests + 1 {
        bail!("request number {n}, expected {}", h.requests + 1);
    }
    if !h.settings_seen {
        bail!("request before settings_seen (the provider's HEADER_TABLE_SIZE)");
    }
    if n > h.cfg.max_requests {
        bail!("request {n} exceeds max_requests {}", h.cfg.max_requests);
    }
    let images = match kind {
        None | Some("chat") => false,
        Some("images") => true,
        Some(other) => refuse!("unknown request kind {other:?}"),
    };
    if !app.offer.model_allowlist.is_empty() && !app.offer.model_allowlist.contains(&model) {
        refuse!("model {model:?} is not in the offer's model_allowlist");
    }
    // The suffix the request's last record must end with, its path, the
    // image count (an image request) and the response cap.
    let (canonical, path, image_count, cap) = if images {
        // An image request (A.13): the node rendered the suffix from its
        // signed offer; it is checked here as for a v2 image setup.
        let (Some(path), Some(ep)) = (h.images_path.as_ref(), app.offer.endpoints.images.as_ref()) else {
            refuse!("this connection serves no image requests");
        };
        if model.is_empty() || max_tokens != 0 {
            refuse!("an image request needs a model and no max_tokens");
        }
        let Some(suffix) = suffix else { refuse!("an image request needs the node's suffix") };
        let c = ep.check_suffix(&model, suffix).map_err(|e| Refused(e.to_string()))?;
        if count.is_some_and(|x| x != c) {
            refuse!("request count {count:?} differs from the suffix's count {c}");
        }
        (suffix.to_string(), path.clone(), Some(c), ep.max_response_bytes)
    } else {
        if model.is_empty() || max_tokens == 0 {
            refuse!("a request needs a model and max_tokens >= 1");
        }
        if max_tokens > app.offer.max_tokens_cap {
            refuse!("max_tokens {max_tokens} exceeds cap {}", app.offer.max_tokens_cap);
        }
        let canonical = app.offer.chat.render(&model, max_tokens);
        if suffix.is_some_and(|s| s != canonical) || count.is_some() {
            refuse!("a chat request's suffix is the canonical one and it has no count");
        }
        (canonical, h.path.clone(), None, MAX_SERVER_BYTES)
    };
    if body_len <= canonical.len() || body_len > app.max_body {
        refuse!("declared body length {body_len} outside {}..={}", canonical.len() + 1, app.max_body);
    }
    let stream = h2::request_stream(n);
    let block = h2::request_block(&app.offer.upstream_host, &path);
    h.requests = n;
    h.req = Some(Req {
        n,
        stream,
        model: model.clone(),
        images: image_count,
        cap,
        body_len,
        suffix: canonical.clone(),
        block,
        records: 0,
        data_bytes: 0,
        complete: false,
        upto: 0,
        written: 0,
        released: false,
        s_k: None,
        interval_open: false,
        recv: Default::default(),
        recv_records: 0,
        recv_bytes: 0,
        sent: Default::default(),
        usage: None,
        settle_on: None,
        attestation: None,
    });
    // The per-request limit, as for a v2 session: up to the release, then
    // again from it.
    st.deadline = Some(tokio::time::Instant::now() + SESSION_TIMEOUT);
    side(st, format!("request n={n} stream={stream} model={model} body_len={body_len} max_tokens={max_tokens} images={image_count:?}"));
    let _ = to_client.send(Message::Text(
        serde_json::json!({"type":"request_ok","sid":sid,"n":n,"stream":stream,"suffix":canonical}).to_string().into(),
    ));
    Ok(())
}

/// `settings_seen`: the provider's `SETTINGS_HEADER_TABLE_SIZE` as the
/// client read it (`None`: not sent, the default 4096). Below the size of the
/// credential's entry the provider no longer holds it: the connection ends
/// (`PROTOCOL-V3.md` §5.6, H3 at run time). The value is the client's claim;
/// a lying client only harms its own next request.
pub(crate) fn on_settings_seen(app: &Arc<AppState>, st: &mut Session, header_table_size: Option<u64>) -> Result<()> {
    if st.state != SessionState::Body {
        bail!("settings_seen before the connection head was written");
    }
    let need = h2::credential_entry_size(app.key.len());
    if let Some(size) = header_table_size.filter(|s| *s < need) {
        warn!(size, need, "the provider's HEADER_TABLE_SIZE (as the client reports it) is below the credential entry: framing \"2\" does not work with it");
        st.code = Some("h2_table_size");
        bail!("the provider's HEADER_TABLE_SIZE {size} is below the credential entry's {need} bytes");
    }
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("settings_seen on a connection that is not framing 2"))?;
    h.settings_seen = true;
    Ok(())
}

/// `ctl`: the client's next record is this control frame.
pub(crate) fn on_ctl(st: &mut Session, frame: &str) -> Result<()> {
    if st.state != SessionState::Body {
        bail!("ctl before the connection head was written");
    }
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("ctl on a session that is not framing 2"))?;
    let c = Ctl::from_name(frame).ok_or_else(|| anyhow!("unknown control frame {frame:?}"))?;
    if h.next_ctl.is_some() || !h.pending.is_empty() {
        bail!("ctl must come right before its record");
    }
    h.next_ctl = Some(c);
    Ok(())
}

/// `release`: the first `upto` records of request `n` may go to the upstream
/// once proven. The limit only grows.
pub(crate) fn on_release(st: &mut Session, n: u32, upto: usize) -> Result<()> {
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("release on a session that is not framing 2"))?;
    let q = h.req.as_mut().filter(|q| q.n == n).ok_or_else(|| anyhow!("release names no request in flight"))?;
    if upto > max_records(q.body_len) {
        bail!("release upto {upto} exceeds what the request can hold");
    }
    q.upto = q.upto.max(upto);
    Ok(())
}

/// Client bytes after the head: complete records are classified and queued.
/// Nothing is written to the upstream here.
pub(crate) fn client_bytes(st: &mut Session, data: &[u8]) -> Result<()> {
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    if h.pending.len() + h.held + data.len() > h.buffer_limit() {
        bail!("client sent more than the {} bytes this connection may hold unreleased", h.buffer_limit());
    }
    h.pending.extend_from_slice(data);
    let (recs, used) = parse_records(&h.pending);
    for r in recs {
        if r.ctype != CT_APPLICATION_DATA || 5 + r.payload.len() > MAX_TLS_RECORD {
            bail!("unexpected client record");
        }
        // One frame per record: a 9-byte frame header, the payload, the
        // inner content type; at most 2^14 bytes of content.
        let inner = r
            .payload
            .len()
            .checked_sub(16)
            .filter(|n| (10..=(1 << 14) + 1).contains(n))
            .ok_or_else(|| anyhow!("a client record does not hold one HTTP/2 frame"))?;
        let (kind, req_idx) = if let Some(c) = h.next_ctl.take() {
            if inner != 10 + c.payload_len() {
                bail!("the record is not the declared control frame ({c:?})");
            }
            if c == Ctl::RstStream && !h.req.as_ref().is_some_and(|q| q.complete) {
                bail!("RST_STREAM without a complete request in flight");
            }
            if h.queue.iter().filter(|x| matches!(x.kind, RecKind::Ctl(_))).count() >= MAX_QUEUED_CTL {
                bail!("too many unproven control records");
            }
            (RecKind::Ctl(c), 0)
        } else {
            let q = h
                .req
                .as_mut()
                .filter(|q| !q.complete)
                .ok_or_else(|| anyhow!("a client record outside a request (control frames are declared with ctl)"))?;
            let kind = if q.records == 0 {
                if inner != 9 + q.block.len() + 1 {
                    bail!("the request's first record is not its HEADERS frame");
                }
                RecKind::Headers
            } else {
                let n = inner - 10;
                if q.data_bytes + n > q.body_len {
                    bail!("the request body exceeds its declared length {}", q.body_len);
                }
                q.data_bytes += n;
                let last = q.data_bytes == q.body_len;
                if n == 0 || (last && n < q.suffix.len()) {
                    bail!("an empty DATA frame, or a last one shorter than the pinned suffix");
                }
                if q.records + 1 > max_records(q.body_len) {
                    bail!("the request arrives in more than {} records", max_records(q.body_len));
                }
                q.complete = last;
                RecKind::Data { last }
            };
            q.records += 1;
            (kind, q.records)
        };
        let bytes = r.bytes();
        h.held += bytes.len();
        h.queue.push_back(Rec { seq: h.next_seq, bytes, kind, proven: false, req_idx });
        h.next_seq += 1;
    }
    h.pending.drain(..used);
    Ok(())
}

/// Write what may be written, then ask for the next proof if records wait.
pub(crate) async fn pump(
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &RelayLog,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    if st.h2.is_none() || st.state != SessionState::Body {
        return Ok(());
    }
    flush(to_client, st, log, tcp_tx).await?;
    next_batch(shared, to_client, st)
}

/// Write queued records to the upstream, in order: each must be proven, and
/// a request's record within the client's release limit.
async fn flush(
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &RelayLog,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    loop {
        let deadline = st.deadline;
        let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
        let Some(front) = h.queue.front() else { break };
        if !front.proven {
            break;
        }
        if front.req_idx > 0 {
            let q = h.req.as_mut().ok_or_else(|| anyhow!("a request record without its request"))?;
            if front.req_idx > q.upto {
                break;
            }
            if q.s_k.is_none() {
                // The interval starts before the first byte of the request
                // can reach the upstream.
                q.s_k = Some(log.server_app_records);
                q.interval_open = true;
            }
        }
        let rec = h.queue.pop_front().expect("front exists");
        h.held -= rec.bytes.len();
        write_upstream(tcp_tx, &rec.bytes, deadline).await?;
        st.sent.update(&rec.bytes);
        if rec.req_idx == 0 {
            continue;
        }
        let h = st.h2.as_mut().expect("checked above");
        let q = h.req.as_mut().expect("checked above");
        q.sent.update(&rec.bytes);
        q.written += 1;
        if q.written == 1 {
            let note = format!("request n={} first record written; S_k={}", q.n, q.s_k.unwrap_or(0));
            side(st, note);
            continue;
        }
        if q.complete && q.written == q.records {
            q.released = true;
            let n = q.n;
            // The upstream has the whole request: the reservation is at
            // stake from here, and the request gets a fresh time limit.
            let _ = to_client.send(Message::Text(serde_json::json!({"type":"body_released","n":n}).to_string().into()));
            st.deadline = Some(tokio::time::Instant::now() + SESSION_TIMEOUT);
            info!(n, "π_WIN verified; request released to the upstream");
            side(st, format!("request n={n} released"));
        }
    }
    Ok(())
}

/// If no π_WIN is in flight and unproven records wait (and no request is
/// half received), fix the parameters of the next one and send them.
fn next_batch(shared: &Arc<SessionShared>, to_client: &mpsc::UnboundedSender<Message>, st: &mut Session) -> Result<()> {
    let h1 = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?.h1;
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    if h.win.is_some() || h.req.as_ref().is_some_and(|q| !q.complete) {
        return Ok(());
    }
    let Some(first) = h.queue.iter().position(|r| !r.proven) else { return Ok(()) };
    let stream = h.req.as_ref().map_or(0, |q| q.stream);
    let mut windows = Vec::new();
    for rec in h.queue.iter().skip(first) {
        let payload = &rec.bytes[5..];
        let inner = payload.len() - 16;
        let (head, tail): (Vec<u8>, &[u8]) = match rec.kind {
            RecKind::Ctl(c) => (c.header(stream).to_vec(), &[]),
            RecKind::Headers => {
                let q = h.req.as_ref().ok_or_else(|| anyhow!("a HEADERS record without its request"))?;
                (h2::frame(h2::HEADERS, h2::END_HEADERS, q.stream, &q.block), &[])
            }
            RecKind::Data { last } => {
                let q = h.req.as_ref().ok_or_else(|| anyhow!("a DATA record without its request"))?;
                let flags = if last { h2::END_STREAM } else { 0 };
                let tail: &[u8] = if last { q.suffix.as_bytes() } else { &[] };
                (h2::frame_header(inner - 10, h2::DATA, flags, q.stream).to_vec(), tail)
            }
        };
        windows.extend(h2::windows_for(rec.seq, payload, &head, tail)?);
    }
    let count = h.queue.len() - first;
    let first_seq = h.queue[first].seq;
    let p = zkbench::statements::PiWin { anchor: h1, key_updates: 0, windows };
    zkbench::statements::check_pi_win(&p).context("the queued records exceed one π_WIN")?;
    let params = Params::PiWin(p);
    shared.set_params("pi_win", params.clone());
    h.win = Some(WinInflight::Records(count));
    let _ = to_client.send(Message::Text(
        serde_json::json!({"type":"zk_params","proof":"pi_win","purpose":"records","first_seq":first_seq,"count":count,"params":params})
            .to_string()
            .into(),
    ));
    Ok(())
}

/// A π_WIN or π_C3S of this session verified against `proven`.
pub(crate) async fn proof_done(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &RelayLog,
    tcp_tx: &mut tokio::net::tcp::OwnedWriteHalf,
    proof: &str,
    proven: Option<&Params>,
) -> Result<()> {
    if !same_params(proven, shared.params.lock().unwrap().get(proof)) {
        bail!("{proof} parameters changed after the proof started");
    }
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    match (proof, h.win.take()) {
        ("pi_win", Some(WinInflight::Records(count))) => {
            let mut left = count;
            for rec in h.queue.iter_mut().filter(|r| !r.proven) {
                if left == 0 {
                    break;
                }
                rec.proven = true;
                left -= 1;
            }
            if left != 0 {
                bail!("π_WIN covered records that are no longer queued");
            }
            side(st, format!("pi_win verified for {count} client record(s)"));
            pump(shared, to_client, st, log, tcp_tx).await
        }
        ("pi_win", Some(WinInflight::ErrorHead)) => settle(app, st, to_client, "pi_win", log.recv_len),
        ("pi_c3s", win) => {
            h.win = win;
            settle(app, st, to_client, "pi_c3s", log.recv_len)
        }
        _ => bail!("{proof} verified with nothing waiting for it"),
    }
}

/// `disclose`: the tail of a successful streamed completion (A.6).
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_disclose(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &RelayLog,
    n: Option<u32>,
    r: &str,
    tail_lens: &[usize],
    skip: usize,
    key_updates: u32,
    epoch_start: usize,
    trailing: Option<usize>,
    server_records: Option<usize>,
) -> Result<()> {
    let hs_records = st.handshake.as_ref().ok_or_else(|| anyhow!("no handshake"))?.server_handshake_records;
    let anchor = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?.h2;
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    let q = h.req.as_mut().filter(|q| Some(q.n) == n).ok_or_else(|| anyhow!("disclose names no request in flight"))?;
    if !q.released || q.usage.is_some() {
        bail!("disclose out of order or repeated");
    }
    if q.images.is_some() {
        bail!("an image request settles on accept or on an error head, never on a usage disclosure");
    }
    if skip != 0 || trailing.is_some() {
        bail!("a framing-2 usage disclosure ends at the last server record (no skip, no trailing records)");
    }
    // R must run to the last server record N holds. If more arrived since
    // the client built it, the client rebuilds.
    let upto = server_records.ok_or_else(|| anyhow!("a framing-2 disclosure names the server records it has seen (server_records)"))?;
    if upto > log.server_app_records {
        bail!("the disclosure counts {upto} server records, the node received {}", log.server_app_records);
    }
    if upto < log.server_app_records {
        let _ = to_client.send(Message::Text(
            serde_json::json!({"type":"disclose_retry","n":q.n,"server_records":log.server_app_records}).to_string().into(),
        ));
        return Ok(());
    }
    if r.len() > 2 * MAX_DISCLOSE_R {
        bail!("disclosed R is too long");
    }
    if key_updates > zkbench::statements::MAX_SERVER_KEY_UPDATES || (key_updates == 0) != (epoch_start == 0) {
        bail!("epoch_start {epoch_start} does not fit {key_updates} server KeyUpdates");
    }
    let r = hex::decode(r)?;
    check_disclosure_size(r.len(), 0)?;
    // The covered records: the last `tail_lens.len()` N holds, all inside
    // the request's interval.
    let k = tail_lens.len();
    if k == 0 || k > MAX_DISCLOSE_RECORDS || k > log.server_tail.len() {
        bail!("disclosure covers {k} records (limit {MAX_DISCLOSE_RECORDS}, and the node keeps the last {})", log.server_tail.len());
    }
    let first_abs = log.server_app_records - k;
    let s_k = q.s_k.ok_or_else(|| anyhow!("the request has no interval"))?;
    if first_abs < s_k || first_abs < hs_records + epoch_start {
        bail!("the disclosed records start before the request's interval (or its key epoch)");
    }
    let chosen: Vec<&Record> = log.server_tail.iter().skip(log.server_tail.len() - k).collect();
    for (rec, want) in chosen.iter().zip(tail_lens.iter().rev()) {
        if rec.payload.len() < 16 + 2 || rec.payload.len() - 16 != *want {
            bail!("tail record lengths do not match the end of the transcript");
        }
    }
    let total: usize = chosen.iter().map(|rec| rec.payload.len() - 17).sum();
    if total < r.len() {
        bail!("disclosed records ({total}) do not cover R ({})", r.len());
    }
    // R itself: one usage event and the end of the request's stream.
    let usage = h2::usage_event(&h2::parse_usage_tail(&r, q.stream)?)?;
    let umodel = usage.get("model").and_then(|m| m.as_str()).unwrap_or("");
    if umodel != q.model {
        warn!(reported = umodel, pinned = %q.model, "usage event model differs from the pinned model");
    }
    let first_content = chosen[0].payload.len() - 17;
    let first_off = first_tail_offset(first_content, total - first_content, r.len());
    let records: Vec<zkbench::statements::TailRecord> = chosen
        .iter()
        .enumerate()
        .map(|(i, rec)| {
            let off = if i == 0 { first_off } else { 0 };
            zkbench::statements::TailRecord {
                seq: (first_abs + i - hs_records - epoch_start) as u64,
                ct: rec.payload[off..rec.payload.len() - 16].to_vec(),
                off,
            }
        })
        .collect();
    check_c3s_records(&records)?;
    q.usage = Some(usage);
    q.settle_on = Some("pi_c3s");
    let params = Params::PiC3S(zkbench::statements::PiC3S { h2: anchor, records, expected: r, skip: 0, key_updates });
    let n = q.n;
    attest(app, st, to_client)?;
    shared.set_params("pi_c3s", params.clone());
    let _ = to_client.send(Message::Text(serde_json::json!({"type":"zk_params","proof":"pi_c3s","n":n,"params":params}).to_string().into()));
    Ok(())
}

/// `disclose_head`: the response head of a request the provider refused
/// (A.7): one complete HEADERS frame at the start of server record `record`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_disclose_head(
    app: &Arc<AppState>,
    shared: &Arc<SessionShared>,
    to_client: &mpsc::UnboundedSender<Message>,
    st: &mut Session,
    log: &RelayLog,
    n: u32,
    record: usize,
    r: &str,
    key_updates: u32,
    epoch_start: usize,
) -> Result<()> {
    let hs_records = st.handshake.as_ref().ok_or_else(|| anyhow!("no handshake"))?.server_handshake_records;
    let anchor = st.ap.as_ref().ok_or_else(|| anyhow!("no 2PC output"))?.h2;
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    // One π_WIN at a time: the client's records are proven first.
    if h.win.is_some() || h.queue.iter().any(|x| !x.proven) {
        bail!("disclose_head while client records are unproven");
    }
    let q = h.req.as_mut().filter(|q| q.n == n).ok_or_else(|| anyhow!("disclose_head names no request in flight"))?;
    let s_k = q.s_k.ok_or_else(|| anyhow!("disclose_head before any of the request reached the upstream"))?;
    if q.usage.is_some() {
        bail!("disclose_head out of order or repeated");
    }
    if r.len() > 2 * MAX_DISCLOSE_R {
        bail!("disclosed R is too long");
    }
    if key_updates > zkbench::statements::MAX_SERVER_KEY_UPDATES || (key_updates == 0) != (epoch_start == 0) {
        bail!("epoch_start {epoch_start} does not fit {key_updates} server KeyUpdates");
    }
    let r = hex::decode(r)?;
    let status = h2::parse_error_head(&r, q.stream)?;
    // Record `record` is in the request's interval and still held.
    let base = log.server_app_records - log.server_tail.len();
    if record < s_k || record < base || record >= log.server_app_records || record < hs_records + epoch_start {
        bail!("server record {record} is outside the request's interval or no longer held");
    }
    let mut windows = Vec::new();
    let mut rest: &[u8] = &r;
    for (i, rec) in log.server_tail.iter().skip(record - base).enumerate() {
        if rest.is_empty() {
            break;
        }
        if i >= MAX_HEAD_RECORDS {
            bail!("the error head spans more than {MAX_HEAD_RECORDS} records");
        }
        let content = rec.payload.len().checked_sub(17).filter(|c| *c > 0).ok_or_else(|| anyhow!("a covered record has no content"))?;
        let (chunk, tail) = rest.split_at(rest.len().min(content));
        let seq = (record + i - hs_records - epoch_start) as u64;
        // The frame's bytes from offset 0, and the record's last byte: it
        // is application data, not a handshake record that could carry them.
        windows.extend(h2::windows_for(seq, &rec.payload, chunk, &[])?);
        rest = tail;
    }
    if !rest.is_empty() {
        bail!("the error head extends past the server records received");
    }
    let p = zkbench::statements::PiWin { anchor, key_updates, windows };
    zkbench::statements::check_pi_win(&p)?;
    q.usage = Some(serde_json::json!({ "error_status": status, "choices": [] }));
    q.settle_on = Some("pi_win");
    h.win = Some(WinInflight::ErrorHead);
    let params = Params::PiWin(p);
    attest(app, st, to_client)?;
    shared.set_params("pi_win", params.clone());
    let _ = to_client.send(Message::Text(
        serde_json::json!({"type":"zk_params","proof":"pi_win","purpose":"error_head","n":n,"record":record,"params":params}).to_string().into(),
    ));
    Ok(())
}

/// `accept`: a successful image response (A.13). The price was fixed by the
/// request, so nothing is disclosed and nothing proven: the interval closes
/// at the records the client has seen, and the request is settled flat.
pub(crate) fn on_accept(
    app: &Arc<AppState>,
    st: &mut Session,
    to_client: &mpsc::UnboundedSender<Message>,
    log: &RelayLog,
    n: Option<u32>,
    server_records: Option<usize>,
) -> Result<()> {
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    if h.win.is_some() || h.queue.iter().any(|x| !x.proven) {
        bail!("accept while client records are unproven");
    }
    let q = h.req.as_mut().filter(|q| Some(q.n) == n).ok_or_else(|| anyhow!("accept names no request in flight"))?;
    let Some(count) = q.images else { bail!("accept is for image requests only") };
    if !q.released || q.usage.is_some() {
        bail!("accept out of order or repeated");
    }
    // The interval ends at the last server record the client has: if more
    // arrived since, the client catches up first (as for a disclosure).
    let upto = server_records.ok_or_else(|| anyhow!("a framing-2 accept names the server records it has seen (server_records)"))?;
    if upto > log.server_app_records {
        bail!("the accept counts {upto} server records, the node received {}", log.server_app_records);
    }
    if upto < log.server_app_records {
        let _ = to_client.send(Message::Text(
            serde_json::json!({"type":"accept_retry","n":q.n,"server_records":log.server_app_records}).to_string().into(),
        ));
        return Ok(());
    }
    q.usage = Some(serde_json::json!({"flat": true, "kind": "images", "count": count}));
    q.settle_on = Some("accept");
    let n = q.n;
    attest(app, st, to_client)?;
    side(st, format!("request n={n} accepted: flat charge for {count} image(s)"));
    settle(app, st, to_client, "accept", log.recv_len)
}

/// Close the current request's interval and sign its attestation.
fn attest(app: &Arc<AppState>, st: &mut Session, to_client: &mpsc::UnboundedSender<Message>) -> Result<()> {
    let hs = st.handshake.as_ref().ok_or_else(|| anyhow!("no handshake"))?;
    let (cert, th_sh, th_sf) = (hex::encode(hs.cert_chain_hash), hex::encode(hs.th_sh), hex::encode(hs.th_sf));
    let c_commit = st.c_commit.map(hex::encode);
    let sid = st.sid.clone();
    let run_dir = st.run_dir.clone();
    let q = st.h2.as_mut().and_then(|h| h.req.as_mut()).ok_or_else(|| anyhow!("no request in flight"))?;
    q.interval_open = false;
    let a = serde_json::json!({
        "sid": sid,
        "http": "2",
        "n": q.n,
        "stream": q.stream,
        "s_k": q.s_k,
        "server_records": q.recv_records,
        "sha256_recv": hex::encode(q.recv.hash()),
        "client_records": q.written,
        "sha256_sent": hex::encode(q.sent.hash()),
        "cert_chain_hash": cert,
        "th_sh": th_sh,
        "th_sf": th_sf,
        "c_commit": c_commit,
        "time": now_unix(),
    });
    let sig = app.signer.sign(a.to_string().as_bytes());
    let _ = to_client.send(Message::Text(
        serde_json::json!({"type":"attestation","n":q.n,"a":a,"sig":hex::encode(sig.to_bytes())}).to_string().into(),
    ));
    q.attestation = Some(a.clone());
    let n = q.n;
    write_attestation(&run_dir, &a);
    side(st, format!("attestation n={n} {a}"));
    Ok(())
}

/// The disclosure's proof verified: hand the usage to the node (or sign the
/// stub receipt), then either accept the next request or close.
fn settle(app: &Arc<AppState>, st: &mut Session, to_client: &mpsc::UnboundedSender<Message>, proof: &str, recv_len: usize) -> Result<()> {
    let sid = st.sid.clone();
    let run_dir = st.run_dir.clone();
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    let q = h.req.take().filter(|q| q.settle_on == Some(proof)).ok_or_else(|| anyhow!("{proof} verified with no disclosure waiting for it"))?;
    let usage = q.usage.clone().ok_or_else(|| anyhow!("no disclosed usage"))?;
    let error = usage.get("error_status").is_some();
    if app.node_settles {
        let mut msg = serde_json::json!({"type":"usage","sid":sid,"http":"2","n":q.n,"model":q.model,"usage":usage});
        if let Some(rm) = usage.get("model").and_then(|m| m.as_str()).filter(|m| *m != q.model) {
            msg["reported_model"] = rm.into();
        }
        let _ = to_client.send(Message::Text(msg.to_string().into()));
    } else {
        let cost_usd = usage.pointer("/cost/usd").and_then(|c| c.as_f64()).unwrap_or(0.0);
        let receipt = serde_json::json!({
            "sid": sid,
            "http": "2",
            "n": q.n,
            "usage": usage,
            "model": q.model,
            "cost_usd": cost_usd,
            "cost_diem": usage.pointer("/cost/diem").cloned().unwrap_or(serde_json::json!(0)),
            "refund_diem": (1000.0 - cost_usd * 1e6).max(0.0),
            "attestation_hash": q.attestation.as_ref().map(|a| hex::encode(cu_crypto::transcript::hash(a.to_string().as_bytes()))),
            "notary_pubkey": app.offer.notary_pubkey,
            "time": now_unix(),
        });
        let receipt_json = receipt.to_string();
        let sig = app.signer.sign(receipt_json.as_bytes());
        let _ = to_client.send(Message::Text(
            serde_json::json!({"type":"receipt","n":q.n,"receipt":receipt,"receipt_json":receipt_json,"sig":hex::encode(sig.to_bytes())})
                .to_string()
                .into(),
        ));
        write_receipt(&run_dir, &receipt);
    }
    // Only a settled 2xx leaves the connection open.
    if error {
        h.closing = Some("error_settled");
    } else if h.tcp_closed {
        h.closing = Some("upstream_closed");
    } else if h.requests >= h.cfg.max_requests {
        h.closing = Some("max_requests");
    } else if recv_len >= H2_CONN_SOFT_BYTES {
        h.closing = Some("max_bytes");
    } else if h.conn_end.is_some_and(|end| end <= tokio::time::Instant::now()) {
        h.closing = Some("max_lifetime");
    }
    let idle = h.idle_deadline();
    st.deadline = Some(idle);
    side(st, format!("request n={} settled ({proof}); error={error}", q.n));
    Ok(())
}

/// The upstream closed the connection. With no request in flight the session
/// ends in order; a request that never fully reached the upstream ends it
/// with nothing at stake; a released request may still be disclosed.
pub(crate) fn tcp_closed(st: &mut Session, to_client: &mpsc::UnboundedSender<Message>) -> Result<()> {
    let h = st.h2.as_mut().ok_or_else(|| anyhow!("not a framing-2 connection"))?;
    h.tcp_closed = true;
    match &h.req {
        None => h.closing = Some("upstream_closed"),
        Some(q) if !q.released => {
            let (n, response_bytes) = (q.n, q.recv_bytes);
            let _ = to_client.send(Message::Text(
                serde_json::json!({"type":"upstream_closed_early","n":n,"response_bytes":response_bytes}).to_string().into(),
            ));
            side(st, format!("upstream closed early; request n={n}, {response_bytes} response bytes"));
            bail!("upstream closed the connection before the request was complete (nothing billed)");
        }
        Some(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_path_of_the_template() {
        let t = "POST /api/v1/chat/completions HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(chat_path(t).unwrap(), "/api/v1/chat/completions");
        assert!(chat_path("GET / HTTP/1.1\r\n").is_err());
        assert!(chat_path("POST /a?b HTTP/1.1\r\n").is_err());
    }

    fn session_with_request(body_len: usize, suffix: &str) -> Session {
        let mut st = Session { state: SessionState::Body, ..Session::default() };
        let mut h = H2::new(h2::H2Block { probe_path: "/p".into(), idle_secs: 300, max_requests: 3, max_lifetime_s: 3600, kinds: vec!["chat".into()] }, "/api/v1/chat/completions".into(), None);
        h.settings_seen = true;
        h.requests = 1;
        h.req = Some(Req {
            n: 1,
            stream: 3,
            model: "m".into(),
            images: None,
            cap: MAX_SERVER_BYTES,
            body_len,
            suffix: suffix.into(),
            block: h2::request_block("h", "/api/v1/chat/completions"),
            records: 0,
            data_bytes: 0,
            complete: false,
            upto: 0,
            written: 0,
            released: false,
            s_k: None,
            interval_open: false,
            recv: Default::default(),
            recv_records: 0,
            recv_bytes: 0,
            sent: Default::default(),
            usage: None,
            settle_on: None,
            attestation: None,
        });
        st.h2 = Some(Box::new(h));
        st
    }

    /// A record of `inner` plaintext bytes (content and type byte), as N sees it.
    fn record(inner: usize) -> Vec<u8> {
        let n = inner + 16;
        let mut r = vec![0x17, 3, 3, (n >> 8) as u8, n as u8];
        r.resize(5 + n, 0xaa);
        r
    }

    fn kinds(st: &Session) -> Vec<String> {
        st.h2.as_ref().unwrap().queue.iter().map(|r| format!("{:?}/{}", r.kind, r.req_idx)).collect()
    }

    #[test]
    fn records_are_classified_by_position_and_length() {
        let block = h2::request_block("h", "/api/v1/chat/completions").len();
        let mut st = session_with_request(5000, ",\"model\":\"m\"}");
        // HEADERS, a DATA frame of 4000 bytes, the last one of 1000; fed in odd pieces.
        let mut bytes = record(9 + block + 1);
        bytes.extend(record(10 + 4000));
        bytes.extend(record(10 + 1000));
        for chunk in bytes.chunks(777) {
            client_bytes(&mut st, chunk).unwrap();
        }
        assert_eq!(kinds(&st), vec!["Headers/1", "Data { last: false }/2", "Data { last: true }/3"]);
        let h = st.h2.as_ref().unwrap();
        assert!(h.req.as_ref().unwrap().complete);
        assert_eq!(h.queue.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(h.queue.iter().all(|r| !r.proven));
        // Anything after the complete request, undeclared, is refused.
        assert!(client_bytes(&mut st, &record(10 + 5)).is_err());
    }

    #[test]
    fn malformed_request_records_are_refused() {
        let block = h2::request_block("h", "/api/v1/chat/completions").len();
        // A first record that is not the HEADERS frame's length.
        let mut st = session_with_request(5000, "sfx");
        assert!(client_bytes(&mut st, &record(9 + block + 2)).is_err());
        // More body than declared.
        let mut st = session_with_request(5000, "sfx");
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        assert!(client_bytes(&mut st, &record(10 + 5001)).is_err());
        // An empty DATA frame.
        let mut st = session_with_request(5000, "sfx");
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        assert!(client_bytes(&mut st, &record(10)).is_err());
        // A last frame shorter than the suffix.
        let mut st = session_with_request(5000, "a-suffix-of-18-bytes");
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        client_bytes(&mut st, &record(10 + 4990)).unwrap();
        assert!(client_bytes(&mut st, &record(10 + 10)).is_err());
        // Too many small frames.
        let mut st = session_with_request(5000, "sfx");
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        let mut refused = false;
        for _ in 0..10 {
            if client_bytes(&mut st, &record(10 + 1)).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused);
        // Not application data, shorter than a frame, longer than a record.
        let mut st = session_with_request(5000, "sfx");
        let mut hs = record(9 + block + 1);
        hs[0] = 0x16;
        assert!(client_bytes(&mut st, &hs).is_err());
        let mut st = session_with_request(5000, "sfx");
        assert!(client_bytes(&mut st, &record(9)).is_err());
        // No request at all.
        let mut st = session_with_request(5000, "sfx");
        st.h2.as_mut().unwrap().req = None;
        assert!(client_bytes(&mut st, &record(9 + block + 1)).is_err());
    }

    #[test]
    fn control_records_are_declared_and_sized() {
        let mut st = session_with_request(5000, "sfx");
        st.h2.as_mut().unwrap().req = None;
        on_ctl(&mut st, "settings_ack").unwrap();
        // A second declaration before the record is refused.
        assert!(on_ctl(&mut st, "ping_ack").is_err());
        client_bytes(&mut st, &record(10)).unwrap();
        on_ctl(&mut st, "ping_ack").unwrap();
        client_bytes(&mut st, &record(18)).unwrap();
        on_ctl(&mut st, "window_update").unwrap();
        client_bytes(&mut st, &record(14)).unwrap();
        assert_eq!(kinds(&st), vec!["Ctl(SettingsAck)/0", "Ctl(PingAck)/0", "Ctl(WindowUpdate)/0"]);
        // The wrong size for the declared frame, an unknown name, a reset with no request.
        on_ctl(&mut st, "settings_ack").unwrap();
        assert!(client_bytes(&mut st, &record(11)).is_err());
        let mut st = session_with_request(5000, "sfx");
        assert!(on_ctl(&mut st, "headers").is_err());
        on_ctl(&mut st, "rst_stream").unwrap();
        assert!(client_bytes(&mut st, &record(14)).is_err());
        // A declaration in the middle of a record is refused.
        let mut st = session_with_request(5000, "sfx");
        client_bytes(&mut st, &record(60)[..7]).unwrap();
        assert!(on_ctl(&mut st, "ping_ack").is_err());
    }

    #[test]
    fn the_buffer_is_bounded_by_the_request() {
        let mut st = session_with_request(5000, "sfx");
        let limit = st.h2.as_ref().unwrap().buffer_limit();
        assert!(limit < 5000 + 4096);
        assert!(client_bytes(&mut st, &vec![0x17; limit + 1]).is_err());
        // Idle: only a few control records.
        st.h2.as_mut().unwrap().req = None;
        assert!(st.h2.as_ref().unwrap().buffer_limit() < 2048);
    }

    #[test]
    fn release_only_grows() {
        let mut st = session_with_request(5000, "sfx");
        on_release(&mut st, 1, 2).unwrap();
        on_release(&mut st, 1, 1).unwrap();
        assert_eq!(st.h2.as_ref().unwrap().req.as_ref().unwrap().upto, 2);
        assert!(on_release(&mut st, 2, 1).is_err());
        assert!(on_release(&mut st, 1, 1 << 20).is_err());
    }

    // --- disclosures, proofs and the write gate, against a loopback "upstream" ---

    fn app_state(node_settles: bool) -> Arc<AppState> {
        let offer: Offer = serde_json::from_str(include_str!("../offer.venice.json")).unwrap();
        Arc::new(AppState {
            key: Arc::new(Zeroizing::new(b"k".repeat(42))),
            offer: Arc::new(offer),
            host: "api.venice.ai".into(),
            upstream: "127.0.0.1:9".into(),
            signer: Arc::new(SigningKey::from_bytes(&[7; 32])),
            runs_dir: std::env::temp_dir(),
            runs_keep: std::time::Duration::from_secs(3600),
            node_settles,
            sessions: StdMutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
            max_body: 1 << 20,
            token_hash: None,
            h2_guard: H2Guard::new(H2_WITHDRAW_FOR, None),
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
            fresh: StdMutex::new(Default::default()),
        });
        (s, rx)
    }

    const SFX: &str = ",\"model\":\"m\"}";
    const USAGE: &str = r#"{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3},"model":"m"}"#;

    /// A session after the head: handshake verified (2 handshake records),
    /// 2PC outputs present, one request open.
    fn open_session(body_len: usize) -> Session {
        let mut st = session_with_request(body_len, SFX);
        st.sid = Some("ab".repeat(32));
        st.handshake = Some(HandshakeInfo {
            client_hs: [0; 32],
            server_hs: [0; 32],
            th_sh: [1; 32],
            th_sf: [2; 32],
            cert_chain_hash: [3; 32],
            leaf_der: Vec::new(),
            server_handshake_records: 2,
            alpn: Some(b"h2".to_vec()),
        });
        st.ap = Some(Box::new(ApN { k0: Zeroizing::new([0; 16]), iv0: Zeroizing::new([0; 12]), h1: [0x11; 32], h2: [0x22; 32], hk: [0x33; 32] }));
        st.c_commit = Some([4; 32]);
        st
    }

    fn server_rec(content: &[u8]) -> Record {
        let n = content.len() + 17;
        let mut payload = content.to_vec();
        payload.push(0x17);
        payload.extend_from_slice(&[0xee; 16]);
        Record { ctype: CT_APPLICATION_DATA, header: [0x17, 3, 3, (n >> 8) as u8, n as u8], payload }
    }

    fn feed(st: &mut Session, log: &mut RelayLog, content: &[u8]) {
        let r = server_rec(content);
        st.h2.as_mut().unwrap().server_record(&r).unwrap();
        log.server_record(r);
    }

    fn texts(rx: &mut mpsc::UnboundedReceiver<Message>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let Message::Text(t) = m {
                out.push(serde_json::from_str(&t).unwrap());
            }
        }
        out
    }

    /// The request's two records (HEADERS, one DATA) arrive; returns them.
    fn send_request(st: &mut Session, body_len: usize) -> Vec<Vec<u8>> {
        let block = h2::request_block("h", "/api/v1/chat/completions").len();
        let recs = vec![record(9 + block + 1), record(10 + body_len)];
        for r in &recs {
            client_bytes(st, r).unwrap();
        }
        recs
    }

    async fn upstream() -> (tokio::net::tcp::OwnedWriteHalf, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        let (_r, w) = c.into_split();
        (w, s)
    }

    async fn read_some(s: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        // Everything that arrives until the socket stays quiet.
        while let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(150), s.read(&mut buf)).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// Mark the stored π_WIN batch proven, as the session loop does on `ZkDone`.
    async fn prove(
        app: &Arc<AppState>,
        sh: &Arc<SessionShared>,
        tx: &mpsc::UnboundedSender<Message>,
        st: &mut Session,
        log: &RelayLog,
        w: &mut tokio::net::tcp::OwnedWriteHalf,
        proof: &str,
    ) -> Result<()> {
        let params = sh.params.lock().unwrap().get(proof).cloned();
        sh.claim_proof(proof)?;
        proof_done(app, sh, tx, st, log, w, proof, params.as_ref()).await
    }

    #[tokio::test]
    async fn nothing_reaches_the_upstream_unproven_or_unreleased() {
        let app = app_state(false);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, mut up) = upstream().await;
        let mut log = RelayLog::default();
        log.server_app_records = 5;
        let mut st = open_session(300);
        // A SETTINGS ACK declared before the request's records: one batch.
        on_ctl(&mut st, "settings_ack").unwrap();
        client_bytes(&mut st, &record(10)).unwrap();
        // While the request is incomplete no proof is asked for.
        let block = h2::request_block("h", "/api/v1/chat/completions").len();
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        assert!(texts(&mut rx).is_empty());
        client_bytes(&mut st, &record(10 + 300)).unwrap();
        on_release(&mut st, 1, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        let msgs = texts(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert_eq!((msgs[0]["proof"].as_str(), msgs[0]["purpose"].as_str()), (Some("pi_win"), Some("records")));
        assert_eq!((msgs[0]["first_seq"].as_u64(), msgs[0]["count"].as_u64()), (Some(0), Some(3)));
        // The windows: the ACK and HEADERS records in full, the DATA record's
        // header and its suffix tail; all anchored on h1.
        let Params::PiWin(p) = serde_json::from_value(msgs[0]["params"].clone()).unwrap() else { panic!() };
        assert_eq!(p.anchor, [0x11; 32]);
        assert_eq!(p.windows.iter().map(|w| w.seq).collect::<Vec<_>>(), vec![0, 1, 2, 2]);
        assert_eq!(p.windows[0].expected, [0, 0, 0, 4, 1, 0, 0, 0, 0, 0x17]);
        assert_eq!(p.windows[1].expected.len(), 9 + block + 1);
        assert_eq!(&p.windows[1].expected[..9], &h2::frame_header(block, h2::HEADERS, h2::END_HEADERS, 3));
        assert_eq!(p.windows[2].expected, h2::frame_header(300, h2::DATA, h2::END_STREAM, 3));
        let mut tail = SFX.as_bytes().to_vec();
        tail.push(0x17);
        assert_eq!(p.windows[3].expected, tail);
        // Released but unproven: nothing was written, and a second pump asks
        // for no second proof.
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        assert!(texts(&mut rx).is_empty());
        assert!(read_some(&mut up).await.is_empty(), "unproven records reached the upstream");
        // Proven: everything goes, in order; S_k is the record count at the write.
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        let wrote = read_some(&mut up).await;
        let mut want = record(10);
        want.extend(record(9 + block + 1));
        want.extend(record(10 + 300));
        assert_eq!(wrote, want);
        let q = st.h2.as_ref().unwrap().req.as_ref().unwrap();
        assert!(q.released && q.interval_open);
        assert_eq!(q.s_k, Some(5));
        assert_eq!(texts(&mut rx).iter().filter(|m| m["type"] == "body_released").count(), 1);
        // The same proof cannot be claimed twice.
        assert!(sh.claim_proof("pi_win").is_err());
    }

    #[tokio::test]
    async fn proven_records_wait_for_the_release_limit() {
        let app = app_state(false);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, mut up) = upstream().await;
        let log = RelayLog::default();
        let mut st = open_session(9000);
        let block = h2::request_block("h", "/api/v1/chat/completions").len();
        for inner in [9 + block + 1, 10 + 4000, 10 + 4000, 10 + 1000] {
            client_bytes(&mut st, &record(inner)).unwrap();
        }
        // A control record behind the request keeps its place in the order.
        on_ctl(&mut st, "ping_ack").unwrap();
        client_bytes(&mut st, &record(18)).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        // Proven, no release yet: nothing.
        assert!(read_some(&mut up).await.is_empty());
        on_release(&mut st, 1, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        assert_eq!(read_some(&mut up).await.len(), record(9 + block + 1).len() + record(10 + 4000).len());
        assert!(!st.h2.as_ref().unwrap().req.as_ref().unwrap().released);
        assert!(texts(&mut rx).iter().all(|m| m["type"] != "body_released"));
        // The rest, then the control record behind it.
        on_release(&mut st, 1, 4).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        assert_eq!(read_some(&mut up).await.len(), record(10 + 4000).len() + record(10 + 1000).len() + record(18).len());
        assert!(st.h2.as_ref().unwrap().req.as_ref().unwrap().released);
        assert!(st.h2.as_ref().unwrap().queue.is_empty());
    }

    #[tokio::test]
    async fn a_proof_on_other_parameters_releases_nothing() {
        let app = app_state(false);
        let (sh, _ev) = shared(&app);
        let (tx, _rx) = mpsc::unbounded_channel();
        let (mut w, mut up) = upstream().await;
        let log = RelayLog::default();
        let mut st = open_session(300);
        send_request(&mut st, 300);
        on_release(&mut st, 1, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        let Some(Params::PiWin(mut other)) = sh.params.lock().unwrap().get("pi_win").cloned() else { panic!() };
        other.windows.pop();
        assert!(proof_done(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win", Some(&Params::PiWin(other))).await.is_err());
        assert!(proof_done(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win", None).await.is_err());
        // A π_C3S result with no disclosure waiting is an error too.
        let win = sh.params.lock().unwrap().get("pi_win").cloned().unwrap();
        sh.set_params("pi_c3s", win);
        let p = sh.params.lock().unwrap().get("pi_c3s").cloned();
        assert!(proof_done(&app, &sh, &tx, &mut st, &log, &mut w, "pi_c3s", p.as_ref()).await.is_err());
        assert!(read_some(&mut up).await.is_empty());
    }

    /// A released request with its response in the log; returns the tail R
    /// (the last three records) and their lengths, last first.
    async fn released(
        app: &Arc<AppState>,
        sh: &Arc<SessionShared>,
        tx: &mpsc::UnboundedSender<Message>,
        st: &mut Session,
        log: &mut RelayLog,
        w: &mut tokio::net::tcp::OwnedWriteHalf,
    ) -> (Vec<u8>, Vec<usize>) {
        // Before the request: the handshake flight and the provider's SETTINGS.
        for c in [&[1u8; 40][..], &[2; 900], &[3; 30]] {
            feed(st, log, c);
        }
        send_request(st, 300);
        on_release(st, 1, 2).unwrap();
        pump(sh, tx, st, log, w).await.unwrap();
        prove(app, sh, tx, st, log, w, "pi_win").await.unwrap();
        // The response: head, content, then the tail as Venice sends it.
        feed(st, log, &h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &[0x88]));
        feed(st, log, &h2::frame(h2::DATA, 0, 3, b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"));
        let tail = [
            h2::frame(h2::DATA, 0, 3, format!("data: {USAGE}\n\n").as_bytes()),
            h2::frame(h2::DATA, 0, 3, b"data: [DONE]\n\n"),
            h2::frame(h2::DATA, h2::END_STREAM, 3, b""),
        ];
        let mut r = Vec::new();
        let mut lens = Vec::new();
        for f in &tail {
            feed(st, log, f);
            r.extend_from_slice(f);
            lens.insert(0, f.len() + 1);
        }
        (r, lens)
    }

    #[tokio::test]
    async fn usage_disclosure_is_bound_to_the_interval_and_the_end() {
        let app = app_state(false);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = open_session(300);
        let (r, lens) = released(&app, &sh, &tx, &mut st, &mut log, &mut w).await;
        texts(&mut rx);
        let n = log.server_app_records;
        assert_eq!((n, st.h2.as_ref().unwrap().req.as_ref().unwrap().s_k), (8, Some(3)));
        let go = |st: &mut Session, log: &RelayLog, nn: Option<u32>, r: &[u8], lens: &[usize], skip, trailing, count: Option<usize>| {
            on_disclose(&app, &sh, &tx, st, log, nn, &hex::encode(r), lens, skip, 0, 0, trailing, count)
        };
        // Refused, leaving the request as it was: another request number, a
        // skip, trailing records, no count, a count ahead of the node.
        assert!(go(&mut st, &log, Some(2), &r, &lens, 0, None, Some(n)).is_err());
        assert!(go(&mut st, &log, None, &r, &lens, 0, None, Some(n)).is_err());
        assert!(go(&mut st, &log, Some(1), &r, &lens, 1, None, Some(n)).is_err());
        assert!(go(&mut st, &log, Some(1), &r, &lens, 0, Some(0), Some(n)).is_err());
        assert!(go(&mut st, &log, Some(1), &r, &lens, 0, None, None).is_err());
        assert!(go(&mut st, &log, Some(1), &r, &lens, 0, None, Some(n + 1)).is_err());
        // Lengths that are not the node's last records; records that do not cover R.
        assert!(go(&mut st, &log, Some(1), &r, &[lens[0], lens[1], lens[2] + 1], 0, None, Some(n)).is_err());
        assert!(go(&mut st, &log, Some(1), &r, &lens[..2], 0, None, Some(n)).is_err());
        // An R that is not a usage tail of this stream (the content event,
        // another stream's tail).
        let mut other = r.clone();
        other[8] = 5;
        assert!(go(&mut st, &log, Some(1), &other, &lens, 0, None, Some(n)).is_err());
        assert!(texts(&mut rx).is_empty());
        // Behind the node: a retry, nothing else changes.
        go(&mut st, &log, Some(1), &r, &lens, 0, None, Some(n - 1)).unwrap();
        let m = texts(&mut rx);
        assert_eq!((m.len(), m[0]["type"].as_str(), m[0]["server_records"].as_u64()), (1, Some("disclose_retry"), Some(n as u64)));
        assert!(st.h2.as_ref().unwrap().req.as_ref().unwrap().usage.is_none());
        // Honest: attestation, then the π_C3S parameters from N's own records.
        go(&mut st, &log, Some(1), &r, &lens, 0, None, Some(n)).unwrap();
        let m = texts(&mut rx);
        assert_eq!(m.iter().map(|x| x["type"].as_str().unwrap()).collect::<Vec<_>>(), vec!["attestation", "zk_params"]);
        let a = &m[0]["a"];
        assert_eq!((a["n"].as_u64(), a["stream"].as_u64(), a["s_k"].as_u64(), a["server_records"].as_u64(), a["client_records"].as_u64()), (Some(1), Some(3), Some(3), Some(5), Some(2)));
        assert_eq!(a["http"], "2");
        let Params::PiC3S(p) = serde_json::from_value(m[1]["params"].clone()).unwrap() else { panic!() };
        assert_eq!(p.h2, [0x22; 32]);
        assert_eq!(p.expected, r);
        // Sequence numbers count from the first record after the handshake flight (2 records).
        assert_eq!(p.records.iter().map(|x| x.seq).collect::<Vec<_>>(), vec![3, 4, 5]);
        assert_eq!(p.records[2].ct, log.server_tail[7].payload[..log.server_tail[7].payload.len() - 16]);
        // Once only.
        assert!(go(&mut st, &log, Some(1), &r, &lens, 0, None, Some(n)).is_err());
        // The proof verifies: settled, the connection is idle again.
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_c3s").await.unwrap();
        let m = texts(&mut rx);
        assert_eq!((m[0]["type"].as_str(), m[0]["n"].as_u64()), (Some("receipt"), Some(1)));
        assert_eq!(m[0]["receipt"]["usage"]["usage"]["prompt_tokens"], 7);
        let h = st.h2.as_ref().unwrap();
        assert!(h.req.is_none() && h.closing.is_none());
    }

    /// The image suffix the node would render for the shipped offer (model
    /// `img`, one image, WebP).
    fn image_suffix(app: &AppState, model: &str, count: u64) -> String {
        let ep = app.offer.endpoints.images.as_ref().unwrap();
        ep.render_suffix(model, count, &[("format".to_string(), serde_json::json!("webp"))])
    }

    /// An idle open connection (no request yet) on the shipped h2 offer.
    fn idle_session(app: &AppState) -> Session {
        let mut st = open_session(300);
        let h = st.h2.as_mut().unwrap();
        *h = Box::new(H2::new(app.offer.h2.clone().unwrap(), chat_path(&app.offer.head_template).unwrap(), images_path(&app.offer).unwrap()));
        h.settings_seen = true;
        st
    }

    #[test]
    fn the_images_route_comes_from_the_offers_endpoint() {
        let app = app_state(true);
        assert_eq!(images_path(&app.offer).unwrap().as_deref(), Some("/api/v1/image/generate"));
        // A chat-only h2 block: no image requests, whatever endpoints exist.
        let mut o = (*app.offer).clone();
        o.h2.as_mut().unwrap().kinds = vec!["chat".into()];
        assert_eq!(images_path(&o).unwrap(), None);
        // `images` without an images endpoint is refused at startup.
        let mut o = (*app.offer).clone();
        o.endpoints.images = None;
        assert!(images_path(&o).is_err());
    }

    #[test]
    fn an_image_request_takes_the_nodes_suffix_and_the_images_path() {
        let app = app_state(true);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sfx = image_suffix(&app, "img", 2);
        let req = |st: &mut Session, kind: Option<&str>, max_tokens: u64, suffix: Option<&str>, count: Option<u64>| {
            on_request(&app, &tx, st, 1, kind, "img".into(), max_tokens, sfx.len() + 40, suffix, count)
        };
        // Refused: no suffix, max_tokens, a count that is not the suffix's, a
        // suffix for another model, a tampered pin, an unknown kind; a chat
        // request with a count.
        for (kind, max_tokens, suffix, count) in [
            (Some("images"), 0, None, Some(2)),
            (Some("images"), 20, Some(sfx.as_str()), Some(2)),
            (Some("images"), 0, Some(sfx.as_str()), Some(1)),
            (Some("images"), 0, Some(image_suffix(&app, "other", 2).as_str()), Some(2)),
            (Some("images"), 0, Some(sfx.replace("\"return_binary\":false", "\"return_binary\":true").as_str()), Some(2)),
            (Some("video"), 0, Some(sfx.as_str()), Some(2)),
            (None, 20, None, Some(1)),
        ] {
            let mut st = idle_session(&app);
            assert!(req(&mut st, kind, max_tokens, suffix, count).is_err(), "{kind:?} {max_tokens} {suffix:?} {count:?}");
            assert!(st.h2.as_ref().unwrap().req.is_none());
        }
        assert!(texts(&mut rx).is_empty());
        // Honest: the suffix is echoed, the HEADERS block names the images path.
        let mut st = idle_session(&app);
        req(&mut st, Some("images"), 0, Some(&sfx), Some(2)).unwrap();
        let m = texts(&mut rx);
        assert_eq!((m[0]["type"].as_str(), m[0]["suffix"].as_str(), m[0]["stream"].as_u64()), (Some("request_ok"), Some(sfx.as_str()), Some(3)));
        let q = st.h2.as_ref().unwrap().req.as_ref().unwrap();
        assert_eq!(q.images, Some(2));
        assert_eq!(q.block, h2::request_block("api.venice.ai", "/api/v1/image/generate"));
        assert_ne!(q.block, h2::request_block("api.venice.ai", "/api/v1/chat/completions"));
        assert_eq!(q.cap, app.offer.endpoints.images.as_ref().unwrap().max_response_bytes);
        // A connection whose offer serves chat only refuses an image request.
        let mut st = open_session(300);
        st.h2.as_mut().unwrap().req = None;
        st.h2.as_mut().unwrap().requests = 0;
        assert!(req(&mut st, Some("images"), 0, Some(&sfx), Some(2)).is_err());
    }

    /// An image request written to the upstream in full, its response in the log.
    async fn image_released(
        app: &Arc<AppState>,
        sh: &Arc<SessionShared>,
        tx: &mpsc::UnboundedSender<Message>,
        st: &mut Session,
        log: &mut RelayLog,
        w: &mut tokio::net::tcp::OwnedWriteHalf,
        n: u32,
    ) {
        let sfx = image_suffix(app, "img", 1);
        let body_len = sfx.len() + 60;
        on_request(app, tx, st, n, Some("images"), "img".into(), 0, body_len, Some(&sfx), Some(1)).unwrap();
        let block = h2::request_block("api.venice.ai", "/api/v1/image/generate").len();
        for r in [record(9 + block + 1), record(10 + body_len)] {
            client_bytes(st, &r).unwrap();
        }
        on_release(st, n, 2).unwrap();
        pump(sh, tx, st, log, w).await.unwrap();
        prove(app, sh, tx, st, log, w, "pi_win").await.unwrap();
        let stream = h2::request_stream(n);
        feed(st, log, &h2::frame(h2::HEADERS, h2::END_HEADERS, stream, &[0x88]));
        feed(st, log, &h2::frame(h2::DATA, 0, stream, &[b'A'; 9000]));
        feed(st, log, &h2::frame(h2::DATA, h2::END_STREAM, stream, b"\"]}"));
    }

    #[tokio::test]
    async fn an_image_request_is_proven_like_chat_and_settles_flat_on_accept() {
        let app = app_state(true);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = idle_session(&app);
        for c in [&[1u8; 40][..], &[2; 900], &[3; 30]] {
            feed(&mut st, &mut log, c);
        }
        // Before the proof: nothing can be accepted.
        let sfx = image_suffix(&app, "img", 1);
        on_request(&app, &tx, &mut st, 1, Some("images"), "img".into(), 0, sfx.len() + 60, Some(&sfx), Some(1)).unwrap();
        assert!(on_accept(&app, &mut st, &tx, &log, Some(1), Some(log.server_app_records)).is_err());
        st.h2.as_mut().unwrap().req = None;
        st.h2.as_mut().unwrap().requests = 0;
        texts(&mut rx);

        image_released(&app, &sh, &tx, &mut st, &mut log, &mut w, 1).await;
        let m = texts(&mut rx);
        // π_WIN pins the whole HEADERS record and the last record's tail = suffix ‖ 0x17.
        let zk = m.iter().find(|x| x["type"] == "zk_params").unwrap();
        let Params::PiWin(p) = serde_json::from_value(zk["params"].clone()).unwrap() else { panic!() };
        let mut tail = sfx.clone().into_bytes();
        tail.push(0x17);
        assert!(p.windows.iter().any(|x| x.seq == 1 && x.expected.ends_with(&tail)));
        let headers = h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &h2::request_block("api.venice.ai", "/api/v1/image/generate"));
        assert!(p.windows.iter().any(|x| x.seq == 0 && x.expected.starts_with(&headers[..16])));
        assert!(m.iter().any(|x| x["type"] == "body_released"));

        let n = log.server_app_records;
        // A usage disclosure is refused for an image request.
        assert!(on_disclose(&app, &sh, &tx, &mut st, &log, Some(1), "00", &[5], 0, 0, 0, None, Some(n)).is_err());
        // Refused: another request, no record count, a count ahead of the node.
        assert!(on_accept(&app, &mut st, &tx, &log, Some(2), Some(n)).is_err());
        assert!(on_accept(&app, &mut st, &tx, &log, None, Some(n)).is_err());
        assert!(on_accept(&app, &mut st, &tx, &log, Some(1), None).is_err());
        assert!(on_accept(&app, &mut st, &tx, &log, Some(1), Some(n + 1)).is_err());
        assert!(texts(&mut rx).is_empty());
        // Behind the node: a retry, nothing else changes.
        on_accept(&app, &mut st, &tx, &log, Some(1), Some(n - 1)).unwrap();
        let m = texts(&mut rx);
        assert_eq!((m.len(), m[0]["type"].as_str(), m[0]["server_records"].as_u64()), (1, Some("accept_retry"), Some(n as u64)));
        // Honest: the attestation of the request's interval, then the flat usage for the node.
        on_accept(&app, &mut st, &tx, &log, Some(1), Some(n)).unwrap();
        let m = texts(&mut rx);
        assert_eq!(m.iter().map(|x| x["type"].as_str().unwrap()).collect::<Vec<_>>(), vec!["attestation", "usage"]);
        let a = &m[0]["a"];
        assert_eq!((a["n"].as_u64(), a["stream"].as_u64(), a["s_k"].as_u64(), a["server_records"].as_u64(), a["client_records"].as_u64()), (Some(1), Some(3), Some(3), Some(3), Some(2)));
        assert_eq!(m[1]["usage"], serde_json::json!({"flat": true, "kind": "images", "count": 1}));
        assert_eq!((m[1]["n"].as_u64(), m[1]["model"].as_str(), m[1]["http"].as_str()), (Some(1), Some("img"), Some("2")));
        // Settled: the connection is idle, and a second accept has no request.
        let h = st.h2.as_ref().unwrap();
        assert!(h.req.is_none() && h.closing.is_none());
        assert!(on_accept(&app, &mut st, &tx, &log, Some(1), Some(n)).is_err());

        // A chat request on the same connection is not settled by accept.
        on_request(&app, &tx, &mut st, 2, None, "m".into(), 20, 400, None, None).unwrap();
        assert!(on_accept(&app, &mut st, &tx, &log, Some(2), Some(log.server_app_records)).is_err());
    }

    #[tokio::test]
    async fn an_image_requests_error_head_is_disclosed_like_chats() {
        let app = app_state(true);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = idle_session(&app);
        // Before the request: the handshake flight and the provider's SETTINGS.
        for c in [&[1u8; 40][..], &[2; 900], &[3; 30]] {
            feed(&mut st, &mut log, c);
        }
        let sfx = image_suffix(&app, "img", 1);
        let body_len = sfx.len() + 60;
        on_request(&app, &tx, &mut st, 1, Some("images"), "img".into(), 0, body_len, Some(&sfx), Some(1)).unwrap();
        let block = h2::request_block("api.venice.ai", "/api/v1/image/generate").len();
        for r in [record(9 + block + 1), record(10 + body_len)] {
            client_bytes(&mut st, &r).unwrap();
        }
        on_release(&mut st, 1, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        // 400: `:status` literal, END_STREAM on the body.
        let head = h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &[0x8c]);
        feed(&mut st, &mut log, &head);
        feed(&mut st, &mut log, &h2::frame(h2::DATA, h2::END_STREAM, 3, b"{\"error\":\"bad\"}"));
        texts(&mut rx);
        on_disclose_head(&app, &sh, &tx, &mut st, &log, 1, 3, &hex::encode(&head), 0, 0).unwrap();
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        let m = texts(&mut rx);
        let usage = m.iter().find(|x| x["type"] == "usage").unwrap();
        assert_eq!(usage["usage"]["error_status"], 400);
        assert_eq!(st.h2.as_ref().unwrap().closing, Some("error_settled"));
    }

    #[test]
    fn a_response_past_its_requests_cap_ends_the_connection() {
        let mut st = session_with_request(300, SFX);
        let h = st.h2.as_mut().unwrap();
        let q = h.req.as_mut().unwrap();
        q.interval_open = true;
        q.cap = 100;
        assert!(h.server_record(&server_rec(&[0; 60])).is_ok());
        assert!(h.server_record(&server_rec(&[0; 60])).is_err());
        // Outside a request's interval nothing is counted against a request.
        let mut st = session_with_request(300, SFX);
        let h = st.h2.as_mut().unwrap();
        h.req.as_mut().unwrap().cap = 10;
        assert!(h.server_record(&server_rec(&[0; 60])).is_ok());
        // The connection's own cap is above the point where it is retired.
        assert!(H2_CONN_MAX_BYTES > H2_CONN_SOFT_BYTES && H2_CONN_MAX_BYTES < (1usize << 31) - 1);
    }

    #[tokio::test]
    async fn a_connection_is_retired_after_its_byte_limit() {
        let app = app_state(true);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = idle_session(&app);
        image_released(&app, &sh, &tx, &mut st, &mut log, &mut w, 1).await;
        texts(&mut rx);
        log.recv_len = H2_CONN_SOFT_BYTES;
        on_accept(&app, &mut st, &tx, &log, Some(1), Some(log.server_app_records)).unwrap();
        assert_eq!(st.h2.as_ref().unwrap().closing, Some("max_bytes"));
    }

    #[tokio::test]
    async fn an_earlier_requests_tail_is_outside_the_interval() {
        let app = app_state(true);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = open_session(300);
        let (r, lens) = released(&app, &sh, &tx, &mut st, &mut log, &mut w).await;
        let n = log.server_app_records;
        on_disclose(&app, &sh, &tx, &mut st, &log, Some(1), &hex::encode(&r), &lens, 0, 0, 0, None, Some(n)).unwrap();
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_c3s").await.unwrap();
        // With a node that settles: the usage frame, per request.
        let m = texts(&mut rx);
        let u = m.iter().find(|x| x["type"] == "usage").unwrap();
        assert_eq!((u["n"].as_u64(), u["http"].as_str(), u["model"].as_str()), (Some(1), Some("2"), Some("m")));
        // Request 2 on the same connection, released; no response yet.
        on_request(&app, &tx, &mut st, 2, None, "m".into(), 20, 400, None, None).unwrap();
        let block = st.h2.as_ref().unwrap().req.as_ref().unwrap().block.len();
        client_bytes(&mut st, &record(9 + block + 1)).unwrap();
        client_bytes(&mut st, &record(10 + 400)).unwrap();
        on_release(&mut st, 2, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        assert_eq!(st.h2.as_ref().unwrap().req.as_ref().unwrap().s_k, Some(n));
        // (d) Request 1's tail presented for request 2: its records lie
        // before S_2. The same bytes with stream 5 written into the frame
        // headers do not help.
        let err = on_disclose(&app, &sh, &tx, &mut st, &log, Some(2), &hex::encode(&r), &lens, 0, 0, 0, None, Some(n)).unwrap_err();
        assert!(err.to_string().contains("interval"), "{err}");
        let mut forged = r.clone();
        let mut at = 0;
        while at < forged.len() {
            forged[at + 8] = 5;
            at += 9 + forged[at + 2] as usize + ((forged[at + 1] as usize) << 8);
        }
        assert!(h2::parse_usage_tail(&forged, 5).is_ok());
        let err = on_disclose(&app, &sh, &tx, &mut st, &log, Some(2), &hex::encode(&forged), &lens, 0, 0, 0, None, Some(n)).unwrap_err();
        assert!(err.to_string().contains("interval"), "{err}");
    }

    #[tokio::test]
    async fn error_head_disclosure() {
        let app = app_state(false);
        let (sh, _ev) = shared(&app);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut w, _up) = upstream().await;
        let mut log = RelayLog::default();
        let mut st = open_session(300);
        for c in [&[1u8; 40][..], &[2; 900], &[3; 30]] {
            feed(&mut st, &mut log, c);
        }
        send_request(&mut st, 300);
        on_release(&mut st, 1, 2).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        // The head may not be disclosed while our records are unproven.
        let block = [0x20, 0x8d, 0x00, 0x04, b'd', b'a', b't', b'e', 0x03, b'x', b'y', b'z'];
        let head = h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &block);
        assert!(on_disclose_head(&app, &sh, &tx, &mut st, &log, 1, 3, &hex::encode(&head), 0, 0).is_err());
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        // The 404 head split over two records (index 3 and 4), the second
        // also holding the start of the error body.
        feed(&mut st, &mut log, &head[..12]);
        let mut second = head[12..].to_vec();
        second.extend_from_slice(&h2::frame(h2::DATA, h2::END_STREAM, 3, b"{\"error\":\"no\"}"));
        feed(&mut st, &mut log, &second);
        texts(&mut rx);
        let go = |st: &mut Session, n: u32, record: usize, r: &[u8]| on_disclose_head(&app, &sh, &tx, st, &log, n, record, &hex::encode(r), 0, 0);
        // A record before the interval, one not received, another request,
        // a success head, a frame on another stream, more than the frame.
        assert!(go(&mut st, 1, 2, &head).is_err());
        assert!(go(&mut st, 1, 5, &head).is_err());
        assert!(go(&mut st, 2, 3, &head).is_err());
        assert!(go(&mut st, 1, 3, &h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &[0x88])).is_err());
        assert!(go(&mut st, 1, 3, &h2::frame(h2::HEADERS, h2::END_HEADERS, 5, &block)).is_err());
        let mut long = head.clone();
        long.push(0);
        assert!(go(&mut st, 1, 3, &long).is_err());
        // A head that would run past the records received.
        let mut big = vec![0x8d, 0x00, 0x01, b'x', 80];
        big.extend_from_slice(&[b'v'; 80]);
        assert!(go(&mut st, 1, 4, &h2::frame(h2::HEADERS, h2::END_HEADERS, 3, &big)).is_err());
        assert!(texts(&mut rx).is_empty());
        go(&mut st, 1, 3, &head).unwrap();
        let m = texts(&mut rx);
        assert_eq!(m.iter().map(|x| x["type"].as_str().unwrap()).collect::<Vec<_>>(), vec!["attestation", "zk_params"]);
        assert_eq!((m[1]["proof"].as_str(), m[1]["purpose"].as_str()), (Some("pi_win"), Some("error_head")));
        let Params::PiWin(p) = serde_json::from_value(m[1]["params"].clone()).unwrap() else { panic!() };
        // Anchored on h2; record 3 in full (head bytes and its type byte),
        // record 4 from offset 0 for the rest, and its last byte.
        assert_eq!(p.anchor, [0x22; 32]);
        assert_eq!(p.windows.iter().map(|w| w.seq).collect::<Vec<_>>(), vec![1, 2, 2]);
        let mut first = head[..12].to_vec();
        first.push(0x17);
        assert_eq!(p.windows[0].expected, first);
        assert_eq!(p.windows[1].expected, head[12..]);
        assert_eq!(p.windows[2].expected, [0x17]);
        // While that proof is out, the client's own records get no batch.
        on_ctl(&mut st, "ping_ack").unwrap();
        client_bytes(&mut st, &record(18)).unwrap();
        pump(&sh, &tx, &mut st, &log, &mut w).await.unwrap();
        assert!(texts(&mut rx).is_empty());
        // Verified: an error receipt, and the connection closes.
        prove(&app, &sh, &tx, &mut st, &log, &mut w, "pi_win").await.unwrap();
        let m = texts(&mut rx);
        assert_eq!(m[0]["receipt"]["usage"]["error_status"], 404);
        assert_eq!(st.h2.as_ref().unwrap().closing, Some("error_settled"));
    }

    #[test]
    fn requests_are_sequential_and_limited() {
        let app = app_state(false);
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut st = open_session(300);
        // One in flight: no second.
        assert!(on_request(&app, &tx, &mut st, 2, None, "m".into(), 20, 400, None, None).is_err());
        st.h2.as_mut().unwrap().req = None;
        let ok = |st: &mut Session, n: u32, kind: Option<&str>, model: &str, max_tokens: u64, len: usize, suffix: Option<&str>| {
            let r = on_request(&app, &tx, st, n, kind, model.into(), max_tokens, len, suffix, None);
            if r.is_ok() {
                let h = st.h2.as_mut().unwrap();
                h.req = None;
                h.requests -= 1;
            }
            r
        };
        ok(&mut st, 2, Some("chat"), "m", 20, 400, None).unwrap();
        assert!(ok(&mut st, 3, None, "m", 20, 400, None).is_err(), "out of order");
        assert!(ok(&mut st, 2, Some("images"), "m", 20, 400, None).is_err());
        assert!(ok(&mut st, 2, None, "", 20, 400, None).is_err());
        assert!(ok(&mut st, 2, None, "m", 0, 400, None).is_err());
        assert!(ok(&mut st, 2, None, "m", 1 << 20, 400, None).is_err());
        assert!(ok(&mut st, 2, None, "m", 20, 10, None).is_err(), "shorter than the suffix");
        assert!(ok(&mut st, 2, None, "m", 20, (1 << 20) + 1, None).is_err());
        assert!(ok(&mut st, 2, None, "m", 20, 400, Some(",\"model\":\"other\"}")).is_err());
        let canonical = app.offer.chat.render("m", 20);
        ok(&mut st, 2, None, "m", 20, 400, Some(&canonical)).unwrap();
        // The connection's request limit, and a closing connection.
        st.h2.as_mut().unwrap().requests = 3;
        assert!(ok(&mut st, 4, None, "m", 20, 400, None).is_err());
        st.h2.as_mut().unwrap().requests = 1;
        st.h2.as_mut().unwrap().tcp_closed = true;
        assert!(ok(&mut st, 2, None, "m", 20, 400, None).is_err());
        // Before the head is written.
        let mut early = open_session(300);
        early.h2.as_mut().unwrap().req = None;
        early.state = SessionState::AwaitHead;
        assert!(on_request(&app, &tx, &mut early, 2, None, "m".into(), 20, 400, None, None).is_err());
    }

    #[test]
    fn upstream_close_by_request_state() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        // Idle: the session ends in order.
        let mut st = open_session(300);
        st.h2.as_mut().unwrap().req = None;
        tcp_closed(&mut st, &tx).unwrap();
        assert_eq!(st.h2.as_ref().unwrap().closing, Some("upstream_closed"));
        // A request not fully released: nothing is at stake.
        let mut st = open_session(300);
        assert!(tcp_closed(&mut st, &tx).is_err());
        assert_eq!(texts(&mut rx)[0]["type"], "upstream_closed_early");
        // A released one may still be disclosed.
        let mut st = open_session(300);
        st.h2.as_mut().unwrap().req.as_mut().unwrap().released = true;
        tcp_closed(&mut st, &tx).unwrap();
        assert!(st.h2.as_ref().unwrap().closing.is_none());
    }

    #[test]
    fn interval_counts_only_while_open() {
        let mut st = session_with_request(5000, "sfx");
        let rec = Record { ctype: CT_APPLICATION_DATA, header: [0x17, 3, 3, 0, 20], payload: vec![1; 20] };
        let h = st.h2.as_mut().unwrap();
        h.server_record(&rec);
        assert_eq!(h.req.as_ref().unwrap().recv_records, 0);
        h.req.as_mut().unwrap().interval_open = true;
        h.server_record(&rec);
        h.server_record(&Record { ctype: 21, header: [21, 3, 3, 0, 2], payload: vec![1, 0] });
        let q = h.req.as_ref().unwrap();
        assert_eq!((q.recv_records, q.recv_bytes), (1, 25));
        let mut want = cu_crypto::transcript::Transcript::new();
        want.update(&[0x17, 3, 3, 0, 20]);
        want.update(&[1; 20]);
        assert_eq!(q.recv.hash(), want.hash());
    }
}
