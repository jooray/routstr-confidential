//! Realistic proof fixtures (shared by tests and the benchmark harness).
//!
//! Session values are taken from RFC 8448 §3 ("Simple 1-RTT Handshake"), so the
//! proofs are exercised against the exact same numbers that `cu-crypto` tests
//! against the RFC.

use cu_crypto::aesgcm;
use cu_crypto::hex;
use cu_crypto::keyschedule::KeySchedule;

use crate::statements::{
    Params, PiC1, PiC2, PiC3 as PiC3Params, PiN, SUPPORTED_KEY_ALPHABET, SessionPublic, TailRecord,
    Witness,
};

pub const HS: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

/// RFC 8448 session secrets.
pub fn session() -> SessionPublic {
    SessionPublic {
        client_hs: arr32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
        server_hs: arr32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
        th_sh: arr32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        th_sf: arr32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"),
    }
}

fn ks() -> KeySchedule {
    let s = session();
    KeySchedule::from_handshake(arr32(HS), s.th_sh, s.th_sf)
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// π_C1 over a 251-byte head with the epoch-1 (c_ap_1) keys.
pub fn pi_c1() -> (Params, Witness) {
    let ks = ks();
    let k1 = ks.c_ap_1.key();
    let iv1 = ks.c_ap_1.iv();
    let head_len = 251;
    let s = aesgcm::ctr_keystream(&k1, &iv1, 0, head_len);
    let h1 = aesgcm::ghash_key(&k1);
    let j0 = aesgcm::j0(&iv1, 0);
    let t0 = aesgcm::aes128_encrypt_block(&k1, &j0);
    (
        Params::PiC1(PiC1 {
            session: session(),
            head_len,
            s,
            h1,
            t0,
        }),
        Witness::Hs(arr32(HS)),
    )
}

/// The pinned suffix in production shape (the sidecar's `canonical_suffix`
/// for this model and max_tokens = 12): the statement size of π_C2/π_C2S.
pub const SUFFIX: &[u8] = b",\"model\":\"mistral-small-3-2-24b-instruct\",\"max_tokens\":12,\"max_completion_tokens\":12,\"n\":1,\"stream\":true,\"stream_options\":{\"include_usage\":true},\"venice_parameters\":{\"include_venice_system_prompt\":false,\"enable_web_search\":\"off\"}}";

fn window_params(key: [u8; 16], iv: [u8; 12], seq: u64, inner: &[u8], target: &[u8]) -> PiC2 {
    let stream = aesgcm::ctr_keystream(&key, &iv, seq, inner.len());
    let ct = xor(inner, &stream);
    let tlen = target.len();
    let w = (tlen + 1 + 13).min(inner.len());
    let off = inner.len() - w;
    let sel_start = w - 1 - tlen;
    assert_eq!(&inner[off + sel_start..off + sel_start + tlen], target);
    PiC2 {
        session: session(),
        seq,
        ct_window: ct[off..off + w].to_vec(),
        off,
        w,
        sel_start,
        sel_len: tlen,
        expected: target.to_vec(),
    }
}

/// π_C2: the pinned suffix as the last epoch-2 record (the client sends it as
/// a record of its own).
pub fn pi_c2() -> (Params, Witness) {
    pi_c2_after(0)
}

/// π_C2 on a record that carries `prefix` private bytes ('x') before the suffix.
pub fn pi_c2_after(prefix: usize) -> (Params, Witness) {
    let ks = ks();
    let k2 = ks.c_ap_2.key();
    let iv2 = ks.c_ap_2.iv();
    let suffix = SUFFIX.to_vec();
    let mut inner = vec![b'x'; prefix];
    inner.extend_from_slice(&suffix);
    inner.push(0x17);
    let p = window_params(k2, iv2, 7, &inner, &suffix);
    (Params::PiC2(p), Witness::Hs(arr32(HS)))
}

/// π_C3: the usage disclosure on the tail server record.
pub fn pi_c3() -> (Params, Witness) {
    let ks = ks();
    let k = ks.s_ap_0.key();
    let iv = ks.s_ap_0.iv();
    let r = b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":12}}\n\ndata: [DONE]\n\n\r\n0\r\n\r\n".to_vec();
    let mut inner = vec![b'y'; 500];
    inner.extend_from_slice(&r);
    inner.push(0x17);
    let stream = aesgcm::ctr_keystream(&k, &iv, 0, inner.len());
    let ct = xor(&inner, &stream);
    (
        Params::PiC3(PiC3Params {
            session: session(),
            records: vec![TailRecord { seq: 0, ct }],
            expected: r,
            skip: 0,
        }),
        Witness::Hs(arr32(HS)),
    )
}

/// π_N: a Venice-style POST head with a 42-byte `[A-Za-z0-9_-]` API key.
pub fn pi_n() -> (Params, Witness) {
    let prefix: &[u8] =
        b"POST /api/v1/chat/completions HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer ";
    let key = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP".to_vec();
    assert_eq!(key.len(), 42);
    let tail: &[u8] = b"\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: 400\r\n\r\n";
    let mut template = prefix.to_vec();
    let key_offsets: Vec<usize> = (0..key.len()).map(|i| prefix.len() + i).collect();
    template.extend(std::iter::repeat(0u8).take(key.len()));
    template.extend_from_slice(tail);
    let head_len = template.len();

    let header: [u8; 5] = aesgcm::record_header(head_len + 1);
    let mut p = template.clone();
    for (i, off) in key_offsets.iter().enumerate() {
        p[*off] = key[i];
    }
    let s: Vec<u8> = (0..=head_len).map(|i| (i as u8).wrapping_mul(37)).collect();
    // TLS 1.3 inner plaintext = head || 0x17
    let mut p_full = p.clone();
    p_full.push(0x17);
    let c1 = xor(&p_full, &s);
    let mut record = header.to_vec();
    record.extend_from_slice(&c1);
    let c_commit = cu_crypto::transcript::hash(&record);

    (
        Params::PiN(PiN {
            head_len,
            key_len: key.len(),
            key_alphabet: SUPPORTED_KEY_ALPHABET.to_string(),
            key_offsets,
            template,
            s,
            c_commit,
            header,
        }),
        Witness::Key(key),
    )
}

/// All four statements in order.
pub fn all() -> Vec<(&'static str, Params, Witness)> {
    vec![
        ("pi_c1", pi_c1().0, pi_c1().1),
        ("pi_n", pi_n().0, pi_n().1),
        ("pi_c2", pi_c2().0, pi_c2().1),
        ("pi_c3", pi_c3().0, pi_c3().1),
    ]
}

// ---------------------------------------------------------------------------
// Protocol v2 (two-party handshake) fixtures
// ---------------------------------------------------------------------------
//
// The secrets are the RFC 8448 session's c_ap_0 / s_ap_0, with
// c_ap_1 = traffic_update(c_ap_0) and (K_0, IV_0) derived from c_ap_0, i.e.
// exactly what the v2 2PC outputs to each party for that session.

use crate::statements::{PiC2S, PiC3S, PiNK};

/// The v2 2PC outputs for the fixture session.
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

/// π_C2S: the pinned suffix as the final epoch-1 body record (seq 3; the
/// client sends it as a record of its own).
pub fn pi_c2s() -> (Params, Witness) {
    pi_c2s_after(0)
}

/// π_C2S on a record that carries `prefix` private bytes ('x') before the suffix.
pub fn pi_c2s_after(prefix: usize) -> (Params, Witness) {
    let v = v2_secrets();
    let secret = cu_crypto::keyschedule::Secret::new(v.c_ap_1);
    let suffix = SUFFIX.to_vec();
    let mut inner = vec![b'x'; prefix];
    inner.extend_from_slice(&suffix);
    inner.push(0x17);
    let w = window_params(secret.key(), secret.iv(), 3, &inner, &suffix);
    (
        Params::PiC2S(PiC2S {
            h1: v.h1(),
            seq: w.seq,
            ct_window: w.ct_window,
            off: w.off,
            w: w.w,
            sel_start: w.sel_start,
            sel_len: w.sel_len,
            expected: w.expected,
        }),
        Witness::Secret(v.c_ap_1),
    )
}

/// π_C3S: the usage disclosure on the tail server record under s_ap_0.
pub fn pi_c3s() -> (Params, Witness) {
    let (p, _) = pi_c3();
    let Params::PiC3(p) = p else { unreachable!() };
    let v = v2_secrets();
    (
        Params::PiC3S(PiC3S {
            h2: v.h2(),
            records: p.records,
            expected: p.expected,
            skip: p.skip,
            key_updates: 0,
        }),
        Witness::Secret(v.s_ap_0),
    )
}

/// π_C3S after `updates` server KeyUpdates: the usage disclosure on a record
/// under `s_ap_k` at sequence 2 of that epoch.
pub fn pi_c3s_after_updates(updates: u32) -> (Params, Witness) {
    let (p, _) = pi_c3();
    let Params::PiC3(p) = p else { unreachable!() };
    let v = v2_secrets();
    let mut secret = cu_crypto::keyschedule::Secret::new(v.s_ap_0);
    for _ in 0..updates {
        secret = cu_crypto::keyschedule::traffic_update(&secret);
    }
    let seq = 2u64;
    let mut inner = vec![b'y'; 300];
    inner.extend_from_slice(&p.expected);
    inner.push(0x17);
    let stream = aesgcm::ctr_keystream(&secret.key(), &secret.iv(), seq, inner.len());
    let ct = xor(&inner, &stream);
    (
        Params::PiC3S(PiC3S {
            h2: v.h2(),
            records: vec![TailRecord { seq, ct }],
            expected: p.expected,
            skip: 0,
            key_updates: updates,
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

/// π_NK: the Venice-style head of `pi_n` under K_0 / IV_0.
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

/// The three v2 statements.
pub fn all_v2() -> Vec<(&'static str, Params, Witness)> {
    vec![
        ("pi_nk", pi_nk().0, pi_nk().1),
        ("pi_c2s", pi_c2s().0, pi_c2s().1),
        ("pi_c3s", pi_c3s().0, pi_c3s().1),
    ]
}
