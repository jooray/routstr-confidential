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

/// π_C2: the pinned suffix on the last epoch-2 record.
pub fn pi_c2() -> (Params, Witness) {
    let ks = ks();
    let k2 = ks.c_ap_2.key();
    let iv2 = ks.c_ap_2.iv();
    let suffix = b",\"model\":\"mistral-small-3-2-24b-instruct\",\"max_tokens\":12,\"n\":1,\"stream\":true}".to_vec();
    let mut inner = vec![b'x'; 400];
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
