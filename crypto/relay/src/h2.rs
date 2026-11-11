//! HTTP/2 pieces of protocol v3, framing "2" (`PROTOCOL-V3.md` §5, §12): the
//! epoch-0 connection head N writes, the request header block, the frame
//! headers N expects of every client record, the windows π_WIN proves, and
//! the two disclosures N parses (the usage tail and the error head).
//!
//! Nothing here speaks HTTP/2 to the provider: N writes one fixed flight
//! under `K_0` and afterwards only relays records whose framing a proof
//! covered.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use zkbench::statements::WinWindow;

use crate::hpack;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;

pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;

/// The largest frame payload U may send: N's SETTINGS never raise
/// `MAX_FRAME_SIZE` above the default.
pub const MAX_FRAME: usize = 1 << 14;
/// The largest DATA payload in one client record: one frame per record, and
/// a record holds 2^14 plaintext bytes.
pub const MAX_DATA_IN_RECORD: usize = (1 << 14) - 9;

/// The offer's `h2` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2Block {
    /// The path of the throwaway GET that loads the credential into the
    /// provider's HPACK table (stream 1, reset in the same flight).
    pub probe_path: String,
    /// The sidecar closes a connection this long after its last settlement.
    #[serde(default = "default_idle")]
    pub idle_secs: u64,
    /// Requests per connection.
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    /// A connection is closed at the first settlement after this long since
    /// its head was written.
    #[serde(default = "default_max_lifetime")]
    pub max_lifetime_s: u64,
    /// The request kinds a connection serves: `chat`, and `images` when the
    /// offer has an images endpoint (A.13). Absent: chat only.
    #[serde(default = "default_kinds", skip_serializing_if = "chat_only")]
    pub kinds: Vec<String>,
}

fn default_kinds() -> Vec<String> {
    vec!["chat".into()]
}

fn chat_only(kinds: &Vec<String>) -> bool {
    kinds.len() == 1 && kinds[0] == "chat"
}

fn default_idle() -> u64 {
    300
}

fn default_max_requests() -> u32 {
    100
}

fn default_max_lifetime() -> u64 {
    3600
}

/// The longest `max_lifetime_s` an offer may name.
pub const MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(86400);

/// The size of the credential's entry in the provider's HPACK table
/// (RFC 7541 §4.1): name `authorization`, value `Bearer <key>`, 32 overhead.
pub fn credential_entry_size(key_len: usize) -> u64 {
    (32 + 13 + 7 + key_len) as u64
}

/// A path every party renders to the same header bytes and no provider
/// normalises onto another route: canonical segments, no query.
pub fn path_ok(path: &str) -> bool {
    path.len() < 127
        && path.starts_with('/')
        && path[1..].split('/').all(|seg| {
            !seg.is_empty() && seg != "." && seg != ".." && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
        })
}

impl H2Block {
    /// Startup checks (the clients apply the same to the signed offer).
    pub fn validate(&self, host: &str, key_len: usize) -> Result<()> {
        if !path_ok(&self.probe_path) {
            bail!("h2 probe_path {:?} is not a canonical path under 127 bytes", self.probe_path);
        }
        if host.is_empty() || host.len() >= 127 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)) {
            bail!("h2: the upstream host is not a plain host name under 127 bytes");
        }
        // "Bearer " + key as one HPACK string with a one-byte length.
        if key_len + 7 >= 127 {
            bail!("h2: a key of {key_len} bytes does not fit the head's one-byte string length");
        }
        if !(10..=3600).contains(&self.idle_secs) {
            bail!("h2 idle_secs {} outside 10..=3600", self.idle_secs);
        }
        if !(60..=MAX_LIFETIME.as_secs()).contains(&self.max_lifetime_s) {
            bail!("h2 max_lifetime_s {} outside 60..=86400", self.max_lifetime_s);
        }
        if !(1..=1000).contains(&self.max_requests) {
            bail!("h2 max_requests {} outside 1..=1000", self.max_requests);
        }
        if self.kinds != ["chat"] && self.kinds != ["chat", "images"] {
            bail!("h2 kinds {:?} must be [\"chat\"] or [\"chat\", \"images\"]", self.kinds);
        }
        Ok(())
    }

    /// Whether a connection serves requests of `kind`.
    pub fn serves(&self, kind: &str) -> bool {
        self.kinds.iter().any(|k| k == kind)
    }
}

pub fn frame_header(len: usize, ty: u8, flags: u8, stream: u32) -> [u8; 9] {
    let s = stream.to_be_bytes();
    [(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags, s[0] & 0x7f, s[1], s[2], s[3]]
}

pub fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = frame_header(payload.len(), ty, flags, stream).to_vec();
    f.extend_from_slice(payload);
    f
}

/// An HPACK string literal without Huffman coding (length under 127).
fn hstr(out: &mut Vec<u8>, s: &[u8]) {
    debug_assert!(s.len() < 127);
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

/// The connection head N writes as the one epoch-0 record (A.3): the client
/// preface, SETTINGS, a connection WINDOW_UPDATE, the probe HEADERS on stream
/// 1 carrying `authorization: Bearer <key>` as a literal with incremental
/// indexing, and RST_STREAM. Returns the bytes with zeros at the key's
/// positions, and those positions.
pub fn head(host: &str, probe_path: &str, key_len: usize) -> Result<(Vec<u8>, Vec<usize>)> {
    if host.len() >= 127 || probe_path.len() >= 127 || key_len + 7 >= 127 || key_len == 0 {
        bail!("h2 head: host, probe path or key too long for one-byte string lengths");
    }
    let mut out = PREFACE.to_vec();
    let mut settings = Vec::new();
    for (id, value) in [(1u16, 0u32), (2, 0), (4, 0x7fff_ffff)] {
        settings.extend_from_slice(&id.to_be_bytes());
        settings.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&frame(SETTINGS, 0, 0, &settings));
    out.extend_from_slice(&frame(WINDOW_UPDATE, 0, 0, &(0x7fff_ffffu32 - 65535).to_be_bytes()));
    let mut block = vec![0x82, 0x87, 0x01];
    hstr(&mut block, host.as_bytes());
    block.push(0x04);
    hstr(&mut block, probe_path.as_bytes());
    block.push(0x57);
    block.push((7 + key_len) as u8);
    block.extend_from_slice(b"Bearer ");
    let key_at = block.len();
    block.resize(block.len() + key_len, 0);
    out.extend_from_slice(&frame_header(block.len(), HEADERS, END_STREAM | END_HEADERS, 1));
    let base = out.len() + key_at;
    out.extend_from_slice(&block);
    out.extend_from_slice(&frame(RST_STREAM, 0, 1, &8u32.to_be_bytes()));
    Ok((out, (base..base + key_len).collect()))
}

/// The header block of every request (A.5): public, built from the offer.
/// `authorization` is the single byte 0xbe (dynamic index 62).
pub fn request_block(host: &str, path: &str) -> Vec<u8> {
    let mut b = vec![0x83, 0x87, 0x01];
    hstr(&mut b, host.as_bytes());
    b.push(0x04);
    hstr(&mut b, path.as_bytes());
    b.extend_from_slice(&[0x0f, 0x10]);
    hstr(&mut b, b"application/json");
    b.push(0xbe);
    b
}

/// The stream of request `n` (1, 2, …): stream 1 is the probe.
pub fn request_stream(n: u32) -> u32 {
    2 * n + 1
}

/// A control frame C may send (A.4 rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctl {
    SettingsAck,
    PingAck,
    WindowUpdate,
    RstStream,
}

impl Ctl {
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "settings_ack" => Ctl::SettingsAck,
            "ping_ack" => Ctl::PingAck,
            "window_update" => Ctl::WindowUpdate,
            "rst_stream" => Ctl::RstStream,
            _ => return None,
        })
    }

    pub fn payload_len(self) -> usize {
        match self {
            Ctl::SettingsAck => 0,
            Ctl::PingAck => 8,
            Ctl::WindowUpdate | Ctl::RstStream => 4,
        }
    }

    /// The frame header N expects; `stream` is the current request's (used
    /// by RST_STREAM only, everything else is on stream 0).
    pub fn header(self, stream: u32) -> [u8; 9] {
        match self {
            Ctl::SettingsAck => frame_header(0, SETTINGS, ACK, 0),
            Ctl::PingAck => frame_header(8, PING, ACK, 0),
            Ctl::WindowUpdate => frame_header(4, WINDOW_UPDATE, 0, 0),
            Ctl::RstStream => frame_header(4, RST_STREAM, 0, stream),
        }
    }
}

/// The π_WIN windows for one record: its plaintext starts with `head`, and
/// ends with `tail` followed by the inner content type 0x17 as the record's
/// **last** byte (so no TLS padding can shift the frame boundary). `payload`
/// is the record's ciphertext with the 16-byte tag, from N's relay buffer.
pub fn windows_for(seq: u64, payload: &[u8], head: &[u8], tail: &[u8]) -> Result<Vec<WinWindow>> {
    let inner = payload.len().checked_sub(16).filter(|n| *n >= 1).ok_or_else(|| anyhow!("record has no content"))?;
    let ct = &payload[..inner];
    if head.len() + tail.len() + 1 > inner {
        bail!("the expected bytes ({} + {} + 1) do not fit a record of {inner} plaintext bytes", head.len(), tail.len());
    }
    let mut last = tail.to_vec();
    last.push(0x17);
    if head.len() + last.len() == inner {
        let mut expected = head.to_vec();
        expected.extend_from_slice(&last);
        return Ok(vec![WinWindow { seq, off: 0, ct: ct.to_vec(), sel_start: 0, expected }]);
    }
    let mut out = Vec::with_capacity(2);
    if !head.is_empty() {
        let n = (head.len().div_ceil(16) * 16).min(inner);
        out.push(WinWindow { seq, off: 0, ct: ct[..n].to_vec(), sel_start: 0, expected: head.to_vec() });
    }
    let start = inner - last.len();
    let off = start / 16 * 16;
    out.push(WinWindow { seq, off, ct: ct[off..].to_vec(), sel_start: start - off, expected: last });
    Ok(out)
}

fn parse_header(b: &[u8]) -> Option<(usize, u8, u8, u32)> {
    if b.len() < 9 {
        return None;
    }
    let len = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize;
    // The reserved bit is kept: a set one never equals a stream id below.
    let stream = u32::from_be_bytes([b[5], b[6], b[7], b[8]]);
    Some((len, b[3], b[4], stream))
}

/// Parse the disclosed tail `R` of a streamed completion (A.6) and return the
/// SSE text it carries on `stream`.
///
/// `R` is a suffix of the server's plaintext (π_C3S proves that) and starts
/// either at a DATA frame header on `stream`, or at a raw LF inside a DATA
/// frame's payload followed by `data: `. From there SSE text and frames
/// alternate: text runs to the next 0x00 byte, which is the first byte of
/// every frame header (frames are at most 2^14 bytes) and never occurs in
/// SSE text (JSON escapes control bytes). Accepted frames: DATA on `stream`,
/// one HEADERS with END_STREAM on `stream` (trailers), and SETTINGS, PING,
/// WINDOW_UPDATE and GOAWAY on stream 0 (WINDOW_UPDATE also on `stream`).
/// The stream must end (END_STREAM) inside `R`, and nothing may follow on it.
pub fn parse_usage_tail(r: &[u8], stream: u32) -> Result<String> {
    let mut text: Vec<u8> = Vec::new();
    let mut p = 0usize;
    if r.starts_with(b"\ndata: ") {
        let end = r.iter().position(|b| *b == 0).unwrap_or(r.len());
        text.extend_from_slice(&r[1..end]);
        p = end;
    } else if !matches!(parse_header(r), Some((_, DATA, _, s)) if s == stream) {
        bail!("R: must start at a DATA frame of the request's stream or at a line start inside one");
    }
    let mut ended = false;
    while p < r.len() {
        let (len, ty, flags, s) = parse_header(&r[p..]).ok_or_else(|| anyhow!("R: truncated frame header"))?;
        if len > MAX_FRAME {
            bail!("R: frame of {len} bytes");
        }
        let body = r.get(p + 9..p + 9 + len).ok_or_else(|| anyhow!("R: a frame extends past the disclosed bytes"))?;
        match (ty, s) {
            (DATA, s) if s == stream => {
                if ended || flags & !END_STREAM != 0 {
                    bail!("R: DATA after the stream ended, or with unexpected flags");
                }
                text.extend_from_slice(body);
                ended = flags & END_STREAM != 0;
            }
            (HEADERS, s) if s == stream => {
                if ended || flags != END_STREAM | END_HEADERS {
                    bail!("R: a HEADERS frame that is not the stream's trailers");
                }
                ended = true;
            }
            (SETTINGS, 0) if len % 6 == 0 && flags & !ACK == 0 => {}
            (PING, 0) if len == 8 => {}
            (GOAWAY, 0) if len >= 8 => {}
            (WINDOW_UPDATE, s) if len == 4 && (s == 0 || s == stream) => {}
            _ => bail!("R: unexpected frame type {ty} on stream {s}"),
        }
        p += 9 + len;
    }
    if !ended {
        bail!("R: the request's stream does not end (no END_STREAM)");
    }
    if text.contains(&0) {
        bail!("R: a NUL byte in the event stream");
    }
    String::from_utf8(text).map_err(|_| anyhow!("R: event stream not utf8"))
}

/// The usage event of a disclosed tail: the text is exactly one event, the
/// usage event (empty `choices`, token counts), then `data: [DONE]`.
pub fn usage_event(text: &str) -> Result<serde_json::Value> {
    let ev = text
        .strip_prefix("data: ")
        .and_then(|t| t.strip_suffix("\n\ndata: [DONE]\n\n"))
        .ok_or_else(|| anyhow!("R: the event stream is not one usage event and data: [DONE]"))?;
    if ev.contains('\n') {
        bail!("R: more than one event before data: [DONE]");
    }
    let v: serde_json::Value = serde_json::from_str(ev).map_err(|_| anyhow!("R: usage event not JSON"))?;
    if !v.get("choices").and_then(|c| c.as_array()).is_some_and(|a| a.is_empty()) {
        bail!("R: usage event has non-empty choices");
    }
    if v.pointer("/usage/prompt_tokens").and_then(|t| t.as_u64()).is_none()
        || v.pointer("/usage/completion_tokens").and_then(|t| t.as_u64()).is_none()
    {
        bail!("R: usage event missing token counts");
    }
    Ok(v)
}

/// A disclosed error head (A.7): `R` is exactly one HEADERS frame on
/// `stream` with END_HEADERS, whose block decodes without a dynamic table to
/// a `:status` of 400..=599. Returns the status.
pub fn parse_error_head(r: &[u8], stream: u32) -> Result<u16> {
    let (len, ty, flags, s) = parse_header(r).ok_or_else(|| anyhow!("error R: shorter than a frame header"))?;
    if ty != HEADERS || s != stream {
        bail!("error R: not a HEADERS frame on the request's stream");
    }
    if flags & END_HEADERS == 0 || flags & !(END_HEADERS | END_STREAM) != 0 {
        bail!("error R: the HEADERS frame must carry END_HEADERS and no padding or priority");
    }
    if len > MAX_FRAME || r.len() != 9 + len {
        bail!("error R: must be exactly one HEADERS frame");
    }
    let status = hpack::response_status(&r[9..])?;
    if !(400..600).contains(&status) {
        bail!("error R: status {status} is not an error");
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USAGE: &str = r#"{"id":"x","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3},"model":"m"}"#;

    fn data(stream: u32, flags: u8, s: &str) -> Vec<u8> {
        frame(DATA, flags, stream, s.as_bytes())
    }

    fn venice_tail(stream: u32) -> Vec<u8> {
        // As observed: the usage event in its own DATA frame, a 14-byte
        // `data: [DONE]` frame, an empty DATA frame with END_STREAM.
        let mut r = data(stream, 0, &format!("data: {USAGE}\n\n"));
        r.extend(data(stream, 0, "data: [DONE]\n\n"));
        r.extend(data(stream, END_STREAM, ""));
        r
    }

    fn usage_of(r: &[u8], stream: u32) -> Result<serde_json::Value> {
        usage_event(&parse_usage_tail(r, stream)?)
    }

    #[test]
    fn head_layout() {
        let (h, offs) = head("api.venice.ai", "/api/v1/models", 42).unwrap();
        assert!(h.starts_with(PREFACE));
        // SETTINGS: three settings, HEADER_TABLE_SIZE 0, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 2^31-1.
        assert_eq!(&h[24..33], &[0, 0, 18, 4, 0, 0, 0, 0, 0]);
        assert_eq!(&h[33..51], &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(&h[51..64], &[0, 0, 4, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 0, 0]);
        // HEADERS on stream 1, END_STREAM | END_HEADERS.
        let block_len = h[66] as usize;
        assert_eq!(&h[64..73], &[0, 0, block_len as u8, 1, 5, 0, 0, 0, 1]);
        let block = &h[73..73 + block_len];
        assert_eq!(&block[..3], &[0x82, 0x87, 0x01]);
        assert_eq!(block[3] as usize, "api.venice.ai".len());
        assert_eq!(offs.len(), 42);
        assert!(offs.windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(&h[offs[0] - 9..offs[0]], &[0x57, 49, b'B', b'e', b'a', b'r', b'e', b'r', b' ']);
        assert!(offs.iter().all(|o| h[*o] == 0));
        // The key ends the block; RST_STREAM(CANCEL) on stream 1 ends the head.
        assert_eq!(offs[41] + 1, 73 + block_len);
        assert_eq!(&h[73 + block_len..], &[0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8]);
        // With a key filled in, the block decodes to the probe request.
        let mut filled = block.to_vec();
        let at = offs[0] - 73;
        filled[at..at + 42].copy_from_slice(&[b'k'; 42]);
        let f = hpack::decode_block(&filled).unwrap();
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
        let got: Vec<(String, String)> = f.iter().map(|(n, v)| (s(n), s(v))).collect();
        assert_eq!(
            got,
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":authority".into(), "api.venice.ai".into()),
                (":path".into(), "/api/v1/models".into()),
                ("authorization".into(), format!("Bearer {}", "k".repeat(42))),
            ]
        );
        assert!(head("h", "/p", 120).is_err());
    }

    /// The cross-language vectors (`client/src/h2-vectors.json`): what this
    /// module builds and decodes, for the reference client's self-check.
    fn vectors() -> serde_json::Value {
        let (template, offsets) = head("api.venice.ai", "/api/v1/models", 42).unwrap();
        let block = request_block("api.venice.ai", "/api/v1/chat/completions");
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
        let mut blocks = Vec::new();
        let huff = |text: &[u8]| {
            let h = hpack::huffman_encode(text);
            let mut v = vec![0x80 | h.len() as u8];
            v.extend(h);
            v
        };
        let mut b404 = vec![0x20, 0x8d, 0x0f, 0x10];
        b404.extend(huff(b"application/json"));
        b404.extend([0x00, 0x04, b'd', b'a', b't', b'e']);
        b404.extend(huff(b"Wed, 11 Nov 2026 12:00:00 GMT"));
        let mut b429 = vec![0x48];
        b429.extend(huff(b"429"));
        b429.extend([0x10]);
        b429.extend(huff(b"x-ratelimit"));
        b429.extend([0x02, b'n', b'o']);
        for b in [b404, b429, vec![0x88, 0x5f, 0x01, b'x']] {
            let fields: Vec<(String, String)> = hpack::decode_block(&b).unwrap().iter().map(|(n, v)| (s(n), s(v))).collect();
            blocks.push(serde_json::json!({"block": hex::encode(&b), "fields": fields}));
        }
        let refused: Vec<String> = [&[0xbe][..], &[0x3f, 0xe1, 0x1f], &[0x8d, 0x20], &[0x08, 0x05, b'4'], &[0x08, 0x81, 0x00]]
            .iter()
            .map(hex::encode)
            .collect();
        let all: Vec<u8> = (0..=255u8).collect();
        serde_json::json!({
            "head": {"host": "api.venice.ai", "probe_path": "/api/v1/models", "key_len": 42, "template": hex::encode(&template), "first_offset": offsets[0]},
            "request_block": {"host": "api.venice.ai", "path": "/api/v1/chat/completions", "block": hex::encode(&block)},
            "blocks": blocks,
            "refused_blocks": refused,
            "huffman_all_bytes": hex::encode(hpack::huffman_encode(&all)),
        })
    }

    #[test]
    fn client_vectors_are_current() {
        let on_disk: serde_json::Value = serde_json::from_str(include_str!("../../client/src/h2-vectors.json")).unwrap();
        assert_eq!(on_disk, vectors(), "regenerate with: cargo test -p cu-sidecar write_client_vectors -- --ignored");
        for b in on_disk["refused_blocks"].as_array().unwrap() {
            assert!(hpack::decode_block(&hex::decode(b.as_str().unwrap()).unwrap()).is_err(), "{b}");
        }
    }

    #[test]
    #[ignore]
    fn write_client_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../client/src/h2-vectors.json");
        std::fs::write(path, serde_json::to_string_pretty(&vectors()).unwrap() + "\n").unwrap();
    }

    #[test]
    fn request_block_layout() {
        let b = request_block("api.venice.ai", "/api/v1/chat/completions");
        assert_eq!(*b.last().unwrap(), 0xbe);
        // Everything but the credential reference decodes statelessly.
        let f = hpack::decode_block(&b[..b.len() - 1]).unwrap();
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
        let got: Vec<(String, String)> = f.iter().map(|(n, v)| (s(n), s(v))).collect();
        assert_eq!(
            got,
            vec![
                (":method".into(), "POST".into()),
                (":scheme".into(), "https".into()),
                (":authority".into(), "api.venice.ai".into()),
                (":path".into(), "/api/v1/chat/completions".into()),
                ("content-type".into(), "application/json".into()),
            ]
        );
        assert_eq!(request_stream(1), 3);
        assert_eq!(request_stream(2), 5);
    }

    #[test]
    fn block_validation() {
        let ok = H2Block { probe_path: "/api/v1/models".into(), idle_secs: 300, max_requests: 100, max_lifetime_s: 3600, kinds: vec!["chat".into()] };
        ok.validate("api.venice.ai", 42).unwrap();
        for path in ["", "models", "/a?b", "/a/../b", "/a//b", "/a b", &format!("/{}", "a".repeat(130))] {
            let b = H2Block { probe_path: path.into(), ..ok.clone() };
            assert!(b.validate("api.venice.ai", 42).is_err(), "{path}");
        }
        assert!(ok.validate("api.venice.ai", 120).is_err());
        assert!(ok.validate("bad host", 42).is_err());
        assert!(H2Block { idle_secs: 5, ..ok.clone() }.validate("h", 42).is_err());
        assert!(H2Block { max_requests: 0, ..ok.clone() }.validate("h", 42).is_err());
        // The kinds: chat, or chat and images, nothing else.
        let kinds = |k: &[&str]| H2Block { kinds: k.iter().map(|s| s.to_string()).collect(), ..ok.clone() };
        assert!(kinds(&["chat", "images"]).validate("h", 42).is_ok());
        for bad in [&[][..], &["images"], &["images", "chat"], &["chat", "chat"], &["chat", "video"], &["chat", "images", "images"]] {
            assert!(kinds(bad).validate("h", 42).is_err(), "{bad:?}");
        }
        assert!(kinds(&["chat", "images"]).serves("images") && !ok.serves("images"));
        // A chat-only block serializes as it did before the field existed.
        assert!(!serde_json::to_string(&ok).unwrap().contains("kinds"));
        assert!(serde_json::to_string(&kinds(&["chat", "images"])).unwrap().contains(r#""kinds":["chat","images"]"#));
    }

    #[test]
    fn windows_cover_head_tail_and_last_byte() {
        let payload = vec![0u8; 5000 + 16];
        // header + type byte
        let w = windows_for(3, &payload, &[1; 9], &[]).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!((w[0].off, w[0].ct.len(), w[0].sel_start, w[0].expected.len()), (0, 16, 0, 9));
        assert_eq!((w[1].off, w[1].ct.len(), w[1].sel_start), (4992, 8, 7));
        assert_eq!(w[1].expected, vec![0x17]);
        // suffix tail
        let w = windows_for(3, &payload, &[1; 9], &[2; 100]).unwrap();
        assert_eq!(w[1].off % 16, 0);
        assert_eq!(w[1].off + w[1].sel_start + 101, 5000);
        assert_eq!(*w[1].expected.last().unwrap(), 0x17);
        // whole record
        let w = windows_for(0, &vec![0u8; 10 + 16], &[1; 9], &[]).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].expected.len(), 10);
        // every window passes the statement's shape checks
        for (head, tail) in [(9usize, 0usize), (9, 100), (4999, 0), (0, 0), (17, 3)] {
            let w = windows_for(1, &payload, &vec![1; head], &vec![2; tail]).unwrap();
            let p = zkbench::statements::PiWin { anchor: [0; 32], key_updates: 0, windows: w };
            zkbench::statements::check_pi_win(&p).unwrap();
        }
        // does not fit / no content
        assert!(windows_for(0, &vec![0u8; 10 + 16], &[1; 9], &[2; 1]).is_err());
        assert!(windows_for(0, &[0u8; 16], &[], &[]).is_err());
    }

    #[test]
    fn usage_tail_as_observed() {
        let v = usage_of(&venice_tail(3), 3).unwrap();
        assert_eq!(v["usage"]["prompt_tokens"], 7);
        // Another stream's id anywhere is refused.
        assert!(usage_of(&venice_tail(3), 5).is_err());
        assert!(usage_of(&venice_tail(5), 3).is_err());
    }

    #[test]
    fn usage_tail_starting_inside_a_frame() {
        // The usage event follows an earlier event in the same DATA frame:
        // R starts at the LF that ends that event's blank line.
        let mut r = format!("\ndata: {USAGE}\n\n").into_bytes();
        r.extend(data(3, 0, "data: [DONE]\n\n"));
        r.extend(data(3, END_STREAM, ""));
        usage_of(&r, 3).unwrap();
        // Everything in one frame, END_STREAM on an empty frame.
        let mut r = format!("\ndata: {USAGE}\n\ndata: [DONE]\n\n").into_bytes();
        r.extend(data(3, END_STREAM, ""));
        usage_of(&r, 3).unwrap();
        // A frame boundary inside the event.
        let (a, b) = USAGE.split_at(20);
        let mut r = format!("\ndata: {a}").into_bytes();
        r.extend(data(3, 0, &format!("{b}\n\ndata: [DONE]\n\n")));
        r.extend(data(3, END_STREAM, ""));
        usage_of(&r, 3).unwrap();
        // Without the LF a "data: " could sit inside a JSON string.
        let mut r = format!("data: {USAGE}\n\ndata: [DONE]\n\n").into_bytes();
        r.extend(data(3, END_STREAM, ""));
        assert!(usage_of(&r, 3).is_err());
    }

    #[test]
    fn usage_tail_control_frames_and_trailers() {
        let mut r = data(3, 0, &format!("data: {USAGE}\n\n"));
        r.extend(frame(PING, 0, 0, &[9; 8]));
        r.extend(frame(WINDOW_UPDATE, 0, 3, &[0, 0, 1, 0]));
        r.extend(data(3, 0, "data: [DONE]\n\n"));
        r.extend(frame(SETTINGS, ACK, 0, &[]));
        r.extend(frame(HEADERS, END_STREAM | END_HEADERS, 3, &[0x00, 0x01, b't', 0x01, b'v']));
        r.extend(frame(GOAWAY, 0, 0, &[0; 8]));
        usage_of(&r, 3).unwrap();
        // Frames the grammar does not know, or on another stream.
        for bad in [
            frame(HEADERS, END_HEADERS, 5, &[0x88]),
            frame(DATA, 0, 5, b"x"),
            frame(RST_STREAM, 0, 3, &[0; 4]),
            frame(9, END_HEADERS, 3, &[]),
            frame(5, 0, 3, &[0; 4]),
            frame(WINDOW_UPDATE, 0, 7, &[0; 4]),
            frame(PING, 0, 3, &[0; 8]),
            frame(DATA, 8, 3, &[0]),
        ] {
            let mut r = data(3, 0, &format!("data: {USAGE}\n\n"));
            r.extend(&bad);
            r.extend(data(3, 0, "data: [DONE]\n\n"));
            r.extend(data(3, END_STREAM, ""));
            assert!(usage_of(&r, 3).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn usage_tail_must_end_the_stream_once() {
        // No END_STREAM.
        let mut r = data(3, 0, &format!("data: {USAGE}\n\n"));
        r.extend(data(3, 0, "data: [DONE]\n\n"));
        assert!(usage_of(&r, 3).is_err());
        // DATA after END_STREAM.
        let mut r = venice_tail(3);
        r.extend(data(3, 0, "x"));
        assert!(usage_of(&r, 3).is_err());
        // Truncated frame, and a frame longer than R.
        let r = venice_tail(3);
        assert!(usage_of(&r[..r.len() - 3], 3).is_err());
        let mut r = venice_tail(3);
        r[2] += 1;
        assert!(usage_of(&r, 3).is_err());
        // Bytes after the last frame that are not a frame.
        let mut r = venice_tail(3);
        r.extend(b"data");
        assert!(usage_of(&r, 3).is_err());
    }

    #[test]
    fn usage_text_is_exactly_one_usage_event() {
        let tail = |text: &str| {
            let mut r = data(3, 0, text);
            r.extend(data(3, END_STREAM, ""));
            r
        };
        usage_of(&tail(&format!("data: {USAGE}\n\ndata: [DONE]\n\n")), 3).unwrap();
        let content = r#"{"choices":[{"delta":{"content":"hi"}}]}"#;
        for text in [
            // an earlier event before the usage event
            format!("data: {content}\n\ndata: {USAGE}\n\ndata: [DONE]\n\n"),
            // no [DONE]
            format!("data: {USAGE}\n\n"),
            // something after [DONE]
            format!("data: {USAGE}\n\ndata: [DONE]\n\ndata: x\n\n"),
            // a content event presented as the usage event
            format!("data: {content}\n\ndata: [DONE]\n\n"),
            // no token counts
            "data: {\"choices\":[],\"usage\":{}}\n\ndata: [DONE]\n\n".to_string(),
            // CRLF line ends
            format!("data: {USAGE}\r\n\r\ndata: [DONE]\r\n\r\n"),
        ] {
            assert!(usage_of(&tail(&text), 3).is_err(), "{text}");
        }
    }

    #[test]
    fn model_output_cannot_fake_a_tail() {
        // Text a client can make the model emit arrives JSON-escaped inside a
        // content event: its quotes are backslash-escaped and it holds no raw
        // LF or NUL, so no position inside it starts a valid R.
        let fake = format!("data: {USAGE}\n\ndata: [DONE]\n\n");
        let escaped = serde_json::to_string(&fake).unwrap();
        let event = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":{escaped}}}}}]}}\n\n");
        assert!(!event[..event.len() - 2].contains('\n'));
        let mut stream = data(3, 0, &event);
        stream.extend(data(3, 0, "data: [DONE]\n\n"));
        stream.extend(data(3, END_STREAM, ""));
        for start in 0..stream.len() {
            assert!(usage_of(&stream[start..], 3).is_err(), "R from byte {start}");
        }
    }

    #[test]
    fn error_head_forms() {
        let head = |flags: u8, stream: u32, block: &[u8]| frame(HEADERS, flags, stream, block);
        let block = [0x20, 0x8d, 0x00, 0x04, b'd', b'a', b't', b'e', 0x01, b'x'];
        assert_eq!(parse_error_head(&head(END_HEADERS, 3, &block), 3).unwrap(), 404);
        assert_eq!(parse_error_head(&head(END_HEADERS | END_STREAM, 3, &block), 3).unwrap(), 404);
        // another stream, no END_HEADERS, padded, priority, a DATA frame
        assert!(parse_error_head(&head(END_HEADERS, 5, &block), 3).is_err());
        assert!(parse_error_head(&head(0, 3, &block), 3).is_err());
        assert!(parse_error_head(&head(END_HEADERS | 0x8, 3, &block), 3).is_err());
        assert!(parse_error_head(&head(END_HEADERS | 0x20, 3, &block), 3).is_err());
        assert!(parse_error_head(&frame(DATA, 0, 3, &block), 3).is_err());
        // a success status, bytes after the frame, a short frame
        assert!(parse_error_head(&head(END_HEADERS, 3, &[0x88]), 3).is_err());
        let mut r = head(END_HEADERS, 3, &block);
        r.push(0);
        assert!(parse_error_head(&r, 3).is_err());
        let r = head(END_HEADERS, 3, &block);
        assert!(parse_error_head(&r[..r.len() - 1], 3).is_err());
        assert!(parse_error_head(&r[..5], 3).is_err());
        // the reserved bit set in the stream id
        let mut r = head(END_HEADERS, 3, &block);
        r[5] |= 0x80;
        assert!(parse_error_head(&r, 3).is_err());
    }
}
