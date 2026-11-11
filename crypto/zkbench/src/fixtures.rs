//! Realistic proof fixtures (shared by tests and the benchmark harness).
//!
//! Session values are taken from RFC 8448 §3 ("Simple 1-RTT Handshake"), so the
//! proofs are exercised against the exact same numbers that `cu-crypto` tests
//! against the RFC.

use cu_crypto::aesgcm;
use cu_crypto::hex;
use cu_crypto::keyschedule::KeySchedule;

use crate::statements::{
    Params, PiC3S, PiNK, PiWin, SUPPORTED_KEY_ALPHABET, TailRecord, WinWindow, Witness,
};

/// The RFC 8448 handshake secret; the fixture's traffic secrets derive from it.
const HS: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
/// The RFC 8448 transcript hashes at ServerHello and server Finished.
const TH_SH: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
const TH_SF: &str = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn ks() -> KeySchedule {
    KeySchedule::from_handshake(arr32(HS), arr32(TH_SH), arr32(TH_SF))
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// The pinned suffix in production shape (the sidecar's `canonical_suffix`
/// for this model and max_tokens = 12): the statement size of the framing
/// `"1.1"` π_WIN ([`pi_win_suffix`]).
pub const SUFFIX: &[u8] = b",\"model\":\"mistral-small-3-2-24b-instruct\",\"max_tokens\":12,\"max_completion_tokens\":12,\"n\":1,\"stream\":true,\"stream_options\":{\"include_usage\":true},\"venice_parameters\":{\"enable_web_search\":\"off\",\"include_venice_system_prompt\":false}}";

/// The usage event plus the end of a chunked SSE stream: the disclosure `R`.
const USAGE_R: &[u8] = b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":12}}\n\ndata: [DONE]\n\n\r\n0\r\n\r\n";

// The secrets are the RFC 8448 session's c_ap_0 / s_ap_0, with
// c_ap_1 = traffic_update(c_ap_0) and (K_0, IV_0) derived from c_ap_0, i.e.
// exactly what the 2PC outputs to each party for that session.

/// The 2PC outputs for the fixture session.
pub struct V2Secrets {
    pub c_ap_1: [u8; 32],
    pub s_ap_0: [u8; 32],
    pub k0: [u8; 16],
    pub iv0: [u8; 12],
}

impl V2Secrets {
    pub fn h1(&self) -> [u8; 32] {
        cu_crypto::hkdf::sha256(&self.c_ap_1)
    }
    pub fn h2(&self) -> [u8; 32] {
        cu_crypto::hkdf::sha256(&self.s_ap_0)
    }
    pub fn hk(&self) -> [u8; 32] {
        let mut kiv = self.k0.to_vec();
        kiv.extend_from_slice(&self.iv0);
        cu_crypto::hkdf::sha256(&kiv)
    }
}

pub fn v2_secrets() -> V2Secrets {
    let ks = ks();
    V2Secrets {
        c_ap_1: *ks.c_ap_1.as_bytes(),
        s_ap_0: *ks.s_ap_0.as_bytes(),
        k0: ks.c_ap_0.key(),
        iv0: ks.c_ap_0.iv(),
    }
}

/// π_C3S: the usage disclosure on the tail server record under s_ap_0.
pub fn pi_c3s() -> (Params, Witness) {
    let v = v2_secrets();
    let secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
    let mut inner = vec![b'y'; 500];
    inner.extend_from_slice(USAGE_R);
    inner.push(0x17);
    let stream = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), 0, inner.len());
    let ct = xor(&inner, &stream);
    (
        Params::PiC3S(PiC3S {
            h2: v.h2(),
            records: vec![TailRecord { seq: 0, ct, off: 0 }],
            expected: USAGE_R.to_vec(),
            skip: 0,
            key_updates: 0,
        }),
        Witness::Secret(v.s_ap_0),
    )
}

/// π_C3S after `updates` server KeyUpdates: the usage disclosure on a record
/// under `s_ap_k` at sequence 2 of that epoch.
pub fn pi_c3s_after_updates(updates: u32) -> (Params, Witness) {
    let v = v2_secrets();
    let mut secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
    for _ in 0..updates {
        secret = cu_crypto::keyschedule::traffic_update(&secret);
    }
    let seq = 2u64;
    let mut inner = vec![b'y'; 300];
    inner.extend_from_slice(USAGE_R);
    inner.push(0x17);
    let stream = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), seq, inner.len());
    let ct = xor(&inner, &stream);
    (
        Params::PiC3S(PiC3S {
            h2: v.h2(),
            records: vec![TailRecord { seq, ct, off: 0 }],
            expected: USAGE_R.to_vec(),
            skip: 0,
            key_updates: updates,
        }),
        Witness::Secret(v.s_ap_0),
    )
}

/// π_C3S over several whole tail records (sequence numbers from 0) with the
/// given content lengths: the usage disclosure ends the last one, every
/// earlier byte is response filler. Each length must be at least 1, and the
/// last one at least `|R|`.
pub fn pi_c3s_records(contents: &[usize]) -> (Params, Witness) {
    let v = v2_secrets();
    let secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
    let last = contents.len().checked_sub(1).expect("at least one record");
    assert!(contents[last] >= USAGE_R.len(), "the last record holds R");
    let records = contents
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let mut inner = vec![b'y'; n];
            if i == last {
                inner[n - USAGE_R.len()..].copy_from_slice(USAGE_R);
            }
            inner.push(0x17);
            let stream = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), i as u64, inner.len());
            TailRecord { seq: i as u64, ct: xor(&inner, &stream), off: 0 }
        })
        .collect();
    (
        Params::PiC3S(PiC3S { h2: v.h2(), records, expected: USAGE_R.to_vec(), skip: 0, key_updates: 0 }),
        Witness::Secret(v.s_ap_0),
    )
}

/// π_C3S as the sidecar builds it for an honest disclosure: a response of
/// `total` content bytes in records of `record_len` (the last one shorter),
/// `R` the `r_len` bytes ending `skip` bytes before the end, the covered
/// records the fewest final ones that hold `R` and `skip`, and the first of
/// them decrypted only from the last block boundary that still covers them.
pub fn pi_c3s_disclosure(total: usize, record_len: usize, r_len: usize, skip: usize) -> (Params, Witness) {
    let v = v2_secrets();
    let secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
    let stream: Vec<u8> = (0..total).map(|i| b'a' + (i % 23) as u8).collect();
    let lens: Vec<usize> = stream.chunks(record_len).map(|c| c.len()).collect();
    let need = r_len + skip;
    let mut first = lens.len();
    let mut covered = 0;
    while covered < need {
        first -= 1;
        covered += lens[first];
    }
    // The sidecar's `first_tail_offset`.
    let first_content = lens[first];
    let rest = covered - first_content;
    let needed_first = need.saturating_sub(rest).clamp(1, first_content.max(1));
    let first_off = (first_content - needed_first.min(first_content)) / 16 * 16;
    let records = stream
        .chunks(record_len)
        .enumerate()
        .skip(first)
        .map(|(i, chunk)| {
            let mut inner = chunk.to_vec();
            inner.push(0x17);
            let ks = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), i as u64, inner.len());
            let off = if i == first { first_off } else { 0 };
            TailRecord { seq: i as u64, ct: xor(&inner, &ks)[off..].to_vec(), off }
        })
        .collect();
    (
        Params::PiC3S(PiC3S {
            h2: v.h2(),
            records,
            expected: stream[total - need..total - skip].to_vec(),
            skip,
            key_updates: 0,
        }),
        Witness::Secret(v.s_ap_0),
    )
}

/// π_NK pieces, so tests can build variants (another key, another template).
pub struct PiNKParts {
    pub template: Vec<u8>,
    pub key_offsets: Vec<usize>,
    pub key: Vec<u8>,
}

pub fn pi_nk_parts() -> PiNKParts {
    let prefix: &[u8] =
        b"POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer ";
    let key = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP".to_vec();
    let tail: &[u8] = b"\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: 400\r\n\r\n";
    let mut template = prefix.to_vec();
    let key_offsets: Vec<usize> = (0..key.len()).map(|i| prefix.len() + i).collect();
    template.extend(std::iter::repeat_n(0u8, key.len()));
    template.extend_from_slice(tail);
    PiNKParts { template, key_offsets, key }
}

/// The real credential record ciphertext `C_1` (tag excluded) that N writes
/// at epoch 0, seq 0 for `template` with `key` spliced in.
pub fn pi_nk_ciphertext(v: &V2Secrets, template: &[u8], key_offsets: &[usize], key: &[u8]) -> Vec<u8> {
    let mut p = template.to_vec();
    for (i, off) in key_offsets.iter().enumerate() {
        p[*off] = key[i];
    }
    p.push(0x17);
    let stream = aesgcm::ctr_keystream(&v.k0, &v.iv0, 0, p.len());
    xor(&p, &stream)
}

/// π_NK params for an explicit `C_1` (the record N actually writes).
pub fn pi_nk_params(v: &V2Secrets, parts: &PiNKParts, c1: &[u8]) -> PiNK {
    let head_len = parts.template.len();
    let header: [u8; 5] = aesgcm::record_header(head_len + 1);
    let mut record = header.to_vec();
    record.extend_from_slice(c1);
    PiNK {
        hk: v.hk(),
        head_len,
        key_len: parts.key.len(),
        key_alphabet: SUPPORTED_KEY_ALPHABET.to_string(),
        key_offsets: parts.key_offsets.clone(),
        template: parts.template.clone(),
        c_commit: cu_crypto::transcript::hash(&record),
        header,
    }
}

/// π_NK: a Venice-style POST head with a 42-byte `[A-Za-z0-9_-]` API key,
/// under K_0 / IV_0.
pub fn pi_nk() -> (Params, Witness) {
    let v = v2_secrets();
    let parts = pi_nk_parts();
    let c1 = pi_nk_ciphertext(&v, &parts.template, &parts.key_offsets, &parts.key);
    // The record really is what AES-128-GCM seals at seq 0 (tag excluded).
    let mut inner = parts.template.clone();
    for (i, off) in parts.key_offsets.iter().enumerate() {
        inner[*off] = parts.key[i];
    }
    inner.push(0x17);
    let header = aesgcm::record_header(inner.len());
    let sealed = aesgcm::gcm_seal(&v.k0, &v.iv0, 0, &header, &inner);
    assert_eq!(&sealed[..c1.len()], &c1[..]);
    (
        Params::PiNK(pi_nk_params(&v, &parts, &c1)),
        Witness::NodeKey { k0: v.k0, iv0: v.iv0, key: parts.key.clone() },
    )
}

/// The inner ciphertext (tag excluded) of a record holding `content` and the
/// inner content type `ctype`, then `pad` zero bytes, under `secret` at `seq`.
pub fn win_record(secret: &[u8; 32], seq: u64, content: &[u8], ctype: u8, pad: usize) -> Vec<u8> {
    let s = cu_crypto::keyschedule::Secret::new(*secret);
    let mut inner = content.to_vec();
    inner.push(ctype);
    inner.resize(inner.len() + pad, 0);
    let ks = aesgcm::ctr_keystream(&s.key(), &s.iv(), seq, inner.len());
    xor(&inner, &ks)
}

/// The windows the sidecar proves for one client record of a framing `"2"`
/// request (`PROTOCOL-V3.md` §12.6): the first `head` content bytes
/// (the frame header, or the whole frame), and the record's last bytes
/// (`tail` content bytes, then the inner content type 0x17). `content` is
/// the honest plaintext the windows expect; `ct` the record as relayed.
pub fn win_windows(seq: u64, ct: &[u8], content: &[u8], head: usize, tail: usize) -> Vec<WinWindow> {
    let inner = ct.len();
    let mut out = Vec::new();
    if head + 1 + tail >= inner {
        let mut expected = content.to_vec();
        expected.push(0x17);
        out.push(WinWindow { seq, off: 0, ct: ct.to_vec(), sel_start: 0, expected });
        return out;
    }
    let n = head.div_ceil(16) * 16;
    out.push(WinWindow { seq, off: 0, ct: ct[..n.min(inner)].to_vec(), sel_start: 0, expected: content[..head].to_vec() });
    let start = inner - 1 - tail;
    let off = start / 16 * 16;
    let mut expected = content[content.len() - tail..].to_vec();
    expected.push(0x17);
    out.push(WinWindow { seq, off, ct: ct[off..].to_vec(), sel_start: start - off, expected });
    out
}

/// An HTTP/2 frame: 9-byte header and payload.
pub fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// The plaintext frames of the π_WIN fixture request: HEADERS, a DATA frame
/// of `body` private bytes, and a final DATA frame ending in [`SUFFIX`].
pub fn pi_win_frames(body: usize) -> Vec<Vec<u8>> {
    let block = b"\x83\x87\x01\x0dapi.venice.ai\x04\x18/api/v1/chat/completions\x0f\x10\x10application/json\xbe";
    let private: Vec<u8> = (0..body).map(|i| b'a' + (i % 26) as u8).collect();
    let mut last = b"\"}]".to_vec();
    last.extend_from_slice(SUFFIX);
    vec![h2_frame(1, 4, 3, block), h2_frame(0, 0, 3, &private), h2_frame(0, 1, 3, &last)]
}

/// π_WIN: one framing `"2"` request under `c_ap_1` (epoch-1 records 0..2): the
/// HEADERS record in full, each DATA record's frame header and last byte,
/// and the pinned suffix at the end of the last one.
pub fn pi_win() -> (Params, Witness) {
    pi_win_body(4000)
}

pub fn pi_win_body(body: usize) -> (Params, Witness) {
    let v = v2_secrets();
    let frames = pi_win_frames(body);
    let mut windows = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let ct = win_record(&v.c_ap_1, i as u64, f, 0x17, 0);
        let (head, tail) = match i {
            0 => (f.len(), 0),
            2 => (9, SUFFIX.len()),
            _ => (9, 0),
        };
        windows.extend(win_windows(i as u64, &ct, f, head, tail));
    }
    (Params::PiWin(PiWin { anchor: v.h1(), key_updates: 0, windows }), Witness::Secret(v.c_ap_1))
}

/// The epoch-1 sequence number of the suffix record in [`pi_win_suffix`]
/// (the client sends the pinned suffix as the final body record, on its own).
pub const SUFFIX_SEQ: u64 = 3;

/// π_WIN as the sidecar builds it in framing `"1.1"` for a final body record
/// whose content is `content` when the pinned suffix is `suffix`: one window,
/// the record's whole ciphertext from offset 0, compared from its first byte
/// with `suffix ‖ 0x17`. For an honest record `content == suffix`, and the
/// window is [`WinWindow::whole_record`]; for any other length the sidecar
/// refuses before proving (the lengths are public), and this builds the
/// parameters it would otherwise have sent.
pub fn pi_win_suffix_record(seq: u64, content: &[u8], suffix: &[u8]) -> (Params, Witness) {
    let v = v2_secrets();
    let ct = win_record(&v.c_ap_1, seq, content, 0x17, 0);
    let mut expected = suffix.to_vec();
    expected.push(0x17);
    let window = WinWindow { seq, off: 0, ct, sel_start: 0, expected };
    (Params::PiWin(PiWin { anchor: v.h1(), key_updates: 0, windows: vec![window] }), Witness::Secret(v.c_ap_1))
}

/// π_WIN in the framing `"1.1"` shape: the pinned suffix ([`SUFFIX`], 230
/// bytes) as the final epoch-1 body record (seq [`SUFFIX_SEQ`]), the whole
/// record compared with `SUFFIX ‖ 0x17` under `h1`.
pub fn pi_win_suffix() -> (Params, Witness) {
    pi_win_suffix_record(SUFFIX_SEQ, SUFFIX, SUFFIX)
}

/// The three statements of a framing `"1.1"` request: π_NK, π_WIN over the
/// suffix record, π_C3S.
pub fn all() -> Vec<(&'static str, Params, Witness)> {
    vec![
        ("pi_nk", pi_nk().0, pi_nk().1),
        ("pi_win", pi_win_suffix().0, pi_win_suffix().1),
        ("pi_c3s", pi_c3s().0, pi_c3s().1),
    ]
}
