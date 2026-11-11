//! The key-schedule circuit of `split-public-1` (`Split`, one circuit in
//! five stages) and the public HMAC message blocks around it.
//!
//! Wire conventions: a byte string is a `Vec<W>` with 8 wires per byte, least
//! significant bit first (the convention of `mpz-circuits`). A SHA-256 state
//! is 8 `u32` words, 32 wires each, least significant bit first, as the
//! `SHA256_COMPRESS` circuit expects. Field elements (the ECDHE x-coordinate
//! shares) enter as 32 little-endian bytes, i.e. the integer's bits LSB first.
//!
//! The HMAC keys that are secret (HS, the derived secret, MS, c_ap_0) have
//! their inner/outer compression states computed once in the circuit and
//! reused for every HMAC under that key. The HS salt (`derived_es`) is a public
//! constant, so its states are plain constants and the compiler's constant
//! folding removes the gates that depend only on them.

use std::ops::Range;
use std::sync::{Arc, LazyLock};

use mpz_circuits::{Circuit, CircuitBuilder, Feed, Gate, Node, SHA256_COMPRESS};

type W = Node<Feed>;

pub(crate) const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct B {
    b: CircuitBuilder,
    compressions: usize,
    /// Gates and AND gates emitted so far (the builder folds constants, so
    /// a call does not always emit a gate), and the highest feed id seen.
    gates: usize,
    ands: usize,
    max_id: usize,
}

impl B {
    fn new() -> Self {
        Self {
            b: CircuitBuilder::new(),
            compressions: 0,
            gates: 0,
            ands: 0,
            max_id: 1,
        }
    }

    fn seen(&mut self, n: W, and: bool) -> W {
        if n.id() > self.max_id {
            self.max_id = n.id();
            self.gates += 1;
            if and {
                self.ands += 1;
            }
        }
        n
    }
    fn gx(&mut self, x: W, y: W) -> W {
        let n = self.b.add_xor_gate(x, y);
        self.seen(n, false)
    }
    fn ga(&mut self, x: W, y: W) -> W {
        let n = self.b.add_and_gate(x, y);
        self.seen(n, true)
    }
    fn gn(&mut self, x: W) -> W {
        let n = self.b.add_inv_gate(x);
        self.seen(n, false)
    }

    fn zero(&self) -> W {
        self.b.get_const_zero()
    }
    fn one(&self) -> W {
        self.b.get_const_one()
    }
    fn bit(&self, v: bool) -> W {
        if v { self.one() } else { self.zero() }
    }

    fn inputs(&mut self, n: usize) -> Vec<W> {
        (0..n)
            .map(|_| {
                let n = self.b.add_input();
                self.max_id = self.max_id.max(n.id());
                n
            })
            .collect()
    }

    fn const_bytes(&self, bytes: &[u8]) -> Vec<W> {
        bytes
            .iter()
            .flat_map(|byte| (0..8).map(move |k| (byte >> k) & 1 == 1))
            .map(|v| self.bit(v))
            .collect()
    }

    fn const_state(&self, words: &[u32; 8]) -> Vec<W> {
        words
            .iter()
            .flat_map(|w| (0..32).map(move |k| (w >> k) & 1 == 1))
            .map(|v| self.bit(v))
            .collect()
    }

    fn xor(&mut self, a: &[W], b: &[W]) -> Vec<W> {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b)
            .map(|(x, y)| self.gx(*x, *y))
            .collect()
    }

    fn xor_const(&mut self, a: &[W], c: &[u8]) -> Vec<W> {
        let cb = self.const_bytes(c);
        self.xor(a, &cb)
    }

    /// One SHA-256 compression: `state' = compress(state, block)`.
    fn compress(&mut self, state: &[W], block: &[W]) -> Vec<W> {
        assert_eq!(state.len(), 256);
        assert_eq!(block.len(), 512);
        self.compressions += 1;
        let circ: &Circuit = &SHA256_COMPRESS;
        let mut map: Vec<Option<W>> = vec![None; circ.feed_count()];
        for (i, w) in circ.inputs().zip(block.iter().chain(state.iter())) {
            map[i] = Some(*w);
        }
        let get = |map: &Vec<Option<W>>, id: usize| map[id].expect("wire defined");
        for gate in circ.gates() {
            let z = gate.z().id();
            let out = match gate {
                Gate::Xor { x, y, .. } => {
                    let (x, y) = (get(&map, x.id()), get(&map, y.id()));
                    self.gx(x, y)
                }
                Gate::And { x, y, .. } => {
                    let (x, y) = (get(&map, x.id()), get(&map, y.id()));
                    self.ga(x, y)
                }
                Gate::Inv { x, .. } => {
                    let x = get(&map, x.id());
                    self.gn(x)
                }
                Gate::Id { x, .. } => get(&map, x.id()),
            };
            map[z] = Some(out);
        }
        circ.outputs().map(|i| get(&map, i)).collect()
    }

    /// Big-endian digest bytes of a state.
    fn digest(&self, state: &[W]) -> Vec<W> {
        let mut out = Vec::with_capacity(256);
        for j in 0..8 {
            for t in 0..4 {
                for k in 0..8 {
                    out.push(state[32 * j + 8 * (3 - t) + k]);
                }
            }
        }
        out
    }

    /// Continues a SHA-256 computation from `state` (which has absorbed
    /// `prefix_len` bytes, a multiple of 64) over `msg`, with final padding.
    fn sha_from_state(&mut self, state: &[W], prefix_len: usize, msg: &[W]) -> Vec<W> {
        assert_eq!(prefix_len % 64, 0);
        assert_eq!(msg.len() % 8, 0);
        let mlen = msg.len() / 8;
        let total_bits = ((prefix_len + mlen) * 8) as u64;
        let mut padded: Vec<W> = msg.to_vec();
        padded.extend(self.const_bytes(&[0x80]));
        while (padded.len() / 8) % 64 != 56 {
            padded.extend(self.const_bytes(&[0]));
        }
        padded.extend(self.const_bytes(&total_bits.to_be_bytes()));
        let mut st = state.to_vec();
        for chunk in padded.chunks(512) {
            st = self.compress(&st, chunk);
        }
        st
    }

    fn sha256(&mut self, msg: &[W]) -> Vec<W> {
        let iv = self.const_state(&SHA256_IV);
        let st = self.sha_from_state(&iv, 0, msg);
        self.digest(&st)
    }

    /// Inner/outer HMAC-SHA256 states for a 32-byte secret key.
    fn hmac_key(&mut self, key: &[W]) -> HmacKey {
        assert_eq!(key.len(), 256);
        let iv = self.const_state(&SHA256_IV);
        let mut ib = self.xor_const(key, &[0x36; 32]);
        ib.extend(self.const_bytes(&[0x36; 32]));
        let mut ob = self.xor_const(key, &[0x5c; 32]);
        ob.extend(self.const_bytes(&[0x5c; 32]));
        let inner = self.compress(&iv, &ib);
        let outer = self.compress(&iv, &ob);
        HmacKey { inner, outer }
    }

    /// HMAC states for a public key (computed natively, no gates).
    fn hmac_key_const(&self, key: &[u8; 32]) -> HmacKey {
        let (i, o) = hmac_states_native(key);
        HmacKey {
            inner: self.const_state(&i),
            outer: self.const_state(&o),
        }
    }

    fn hmac(&mut self, k: &HmacKey, msg: &[W]) -> Vec<W> {
        let inner = self.sha_from_state(&k.inner, 64, msg);
        let inner = self.digest(&inner);
        let outer = self.sha_from_state(&k.outer, 64, &inner);
        self.digest(&outer)
    }

    /// The outer HMAC compression `f(OS, pad(inner digest))` as digest bytes.
    fn outer(&mut self, os: &[W], inner: &[W]) -> Vec<W> {
        let st = self.sha_from_state(os, 64, inner);
        self.digest(&st)
    }

    /// (a + b) mod p for a, b < p (bits LSB first, 256 each).
    fn add_mod_p(&mut self, a: &[W], b: &[W]) -> Vec<W> {
        // s = a + b (257 bits)
        let (mut s, carry) = self.add(a, b, None);
        s.push(carry);
        // d = s + (2^257 - p) mod 2^257; carry-out set iff s >= p.
        let p = p256_modulus_le();
        let mut negp = [0u8; 33];
        // 2^257 - p = (~p + 1) over 257 bits
        let mut c = 1u16;
        for i in 0..33 {
            let pi = if i < 32 { p[i] } else { 0 };
            let v = (!pi) as u16 + c;
            negp[i] = v as u8;
            c = v >> 8;
        }
        let negp_bits: Vec<W> = (0..257)
            .map(|i| self.bit((negp[i / 8] >> (i % 8)) & 1 == 1))
            .collect();
        let (d, ge) = self.add(&s, &negp_bits, None);
        // result = ge ? d : s  (low 256 bits)
        (0..256)
            .map(|i| {
                let diff = self.gx(d[i], s[i]);
                let sel = self.ga(ge, diff);
                self.gx(s[i], sel)
            })
            .collect()
    }

    /// Ripple-carry adder; returns (sum, carry_out).
    fn add(&mut self, a: &[W], b: &[W], cin: Option<W>) -> (Vec<W>, W) {
        assert_eq!(a.len(), b.len());
        let mut c = cin.unwrap_or(self.zero());
        let mut out = Vec::with_capacity(a.len());
        for (x, y) in a.iter().zip(b) {
            let xy = self.gx(*x, *y);
            out.push(self.gx(xy, c));
            let xc = self.gx(*x, c);
            let yc = self.gx(*y, c);
            let t = self.ga(xc, yc);
            c = self.gx(t, c);
        }
        (out, c)
    }

    fn output(&mut self, w: &[W]) {
        for x in w {
            self.b.add_output(*x);
        }
    }
}

struct HmacKey {
    inner: Vec<W>,
    outer: Vec<W>,
}

fn p256_modulus_le() -> [u8; 32] {
    let mut be = [0u8; 32];
    hex::decode_to_slice(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        &mut be,
    )
    .unwrap();
    be.reverse();
    be
}

pub(crate) fn compress_native(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut st = *state;
    sha2::compress256(&mut st, &[(*block).into()]);
    st
}

pub(crate) fn hmac_states_native(key: &[u8; 32]) -> ([u32; 8], [u32; 8]) {
    let mut ib = [0x36u8; 64];
    let mut ob = [0x5cu8; 64];
    for i in 0..32 {
        ib[i] ^= key[i];
        ob[i] ^= key[i];
    }
    (compress_native(&SHA256_IV, &ib), compress_native(&SHA256_IV, &ob))
}

fn sha256_native(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

fn hmac_native(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    k[..key.len()].copy_from_slice(key);
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let ih = sha256_native(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    sha256_native(&outer)
}

/// `derived_es = Derive-Secret(HKDF-Extract(0, 0), "derived", "")`, a
/// public constant of TLS 1.3 with SHA-256.
pub(crate) fn derived_es() -> [u8; 32] {
    let early = hmac_native(&[0u8; 32], &[0u8; 32]);
    let ctx = sha256_native(b"");
    let label = b"tls13 derived";
    let mut info = Vec::new();
    info.extend_from_slice(&32u16.to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label);
    info.push(32);
    info.extend_from_slice(&ctx);
    info.push(1);
    hmac_native(&early, &info)
}

// ---------------------------------------------------------------------------
// The split key schedule (`split-public-1`).
//
// One circuit, evaluated in five stages (A1, A2, A3, B1, B2). The garbled
// circuit computes only the HMAC key-pad states `IS_k = f(IV, k ⊕ ipad)`,
// `OS_k = f(IV, k ⊕ opad)`, the outer compressions `f(OS_k, pad(d))` and the
// three anchors. `IS_k` is a public output of its stage; the inner digests
// `d = f(IS_k, m)` (every `m` is public) are computed outside the circuit by
// both parties and enter the next stage as inputs. `OS_k` never leaves the
// circuit: it is an internal wire that simply continues into later stages.
// ---------------------------------------------------------------------------

/// Number of evaluation stages of the split circuit.
pub const N_STAGES: usize = 5;
/// Stages run by `Party::handshake` (A1, A2, A3); the rest by `application`.
pub const HS_STAGES: usize = 3;

/// Who learns an output group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutKind {
    /// Mask opened to C; never reported to N.
    ToC,
    /// Mask opened to C, pointer bits reported to N.
    Pub,
    /// Mask stays with N; C reports the pointer bits.
    ToN,
}

#[derive(Debug, Clone)]
pub struct OutGroup {
    pub name: &'static str,
    pub stage: usize,
    pub kind: OutKind,
    /// Offset and length in the circuit's outputs.
    pub off: usize,
    pub len: usize,
}

/// The split circuit and its layout.
#[derive(Debug)]
pub struct Split {
    pub circ: Arc<Circuit>,
    pub compressions: usize,
    /// End (exclusive) of each stage in `circ.gates()` and in AND-gate order.
    pub gate_end: [usize; N_STAGES],
    pub and_end: [usize; N_STAGES],
    pub xc: Range<usize>,
    pub xn: Range<usize>,
    /// Inner-digest inputs (256 wires each, digest byte order) and the stage
    /// that consumes them: d_c, d_s, d_der | d_0 | d_c0, d_s0 | d_key, d_iv,
    /// d_upd.
    pub dig: Vec<Range<usize>>,
    pub dig_stage: Vec<usize>,
    pub outs: Vec<OutGroup>,
}

impl Split {
    pub fn group(&self, name: &str) -> usize {
        self.outs.iter().position(|g| g.name == name).expect("output group")
    }
    /// Digest inputs consumed by `stage`.
    pub fn digs_of(&self, stage: usize) -> Vec<usize> {
        (0..self.dig.len()).filter(|&j| self.dig_stage[j] == stage).collect()
    }
}

pub(crate) const DIG_STAGE: [usize; 9] = [1, 1, 1, 2, 3, 3, 4, 4, 4];

fn add_out(outs: &mut Vec<OutGroup>, out_w: &mut Vec<W>, name: &'static str, stage: usize, kind: OutKind, w: &[W]) {
    outs.push(OutGroup {
        name,
        stage,
        kind,
        off: out_w.len(),
        len: w.len(),
    });
    out_w.extend_from_slice(w);
}

fn build_split() -> Split {
    let mut b = B::new();
    let xc = b.inputs(256);
    let xn = b.inputs(256);
    let dig: Vec<Vec<W>> = (0..9).map(|_| b.inputs(256)).collect();
    let mut gate_end = [0usize; N_STAGES];
    let mut and_end = [0usize; N_STAGES];
    let mut outs: Vec<OutGroup> = Vec::new();
    let mut out_w: Vec<W> = Vec::new();

    // A1: Z = x_C + x_N mod p, HS = HMAC(salt, Z), key-pad states of HS.
    let x = b.add_mod_p(&xc, &xn);
    let mut ikm = Vec::with_capacity(256);
    for j in 0..32 {
        for k in 0..8 {
            ikm.push(x[(31 - j) * 8 + k]);
        }
    }
    let salt = b.hmac_key_const(&derived_es());
    let hs = b.hmac(&salt, &ikm);
    let khs = b.hmac_key(&hs);
    add_out(&mut outs, &mut out_w, "IS_HS", 0, OutKind::Pub, &khs.inner);
    (gate_end[0], and_end[0]) = (b.gates, b.ands);

    // A2: c_hs, s_hs, dHS = f(OS_HS, ·); key-pad states of dHS.
    let c_hs = b.outer(&khs.outer, &dig[0]);
    let s_hs = b.outer(&khs.outer, &dig[1]);
    add_out(&mut outs, &mut out_w, "c_hs", 1, OutKind::Pub, &c_hs);
    add_out(&mut outs, &mut out_w, "s_hs", 1, OutKind::Pub, &s_hs);
    let dhs = b.outer(&khs.outer, &dig[2]);
    let kd = b.hmac_key(&dhs);
    add_out(&mut outs, &mut out_w, "IS_dHS", 1, OutKind::Pub, &kd.inner);
    (gate_end[1], and_end[1]) = (b.gates, b.ands);

    // A3: MS = f(OS_dHS, d_0); key-pad states of MS.
    let ms = b.outer(&kd.outer, &dig[3]);
    let kms = b.hmac_key(&ms);
    add_out(&mut outs, &mut out_w, "IS_MS", 2, OutKind::Pub, &kms.inner);
    (gate_end[2], and_end[2]) = (b.gates, b.ands);

    // B1: c_ap_0, s_ap_0 = f(OS_MS, ·); key-pad states of c_ap_0.
    let c_ap0 = b.outer(&kms.outer, &dig[4]);
    let s_ap0 = b.outer(&kms.outer, &dig[5]);
    let kc0 = b.hmac_key(&c_ap0);
    add_out(&mut outs, &mut out_w, "s_ap_0", 3, OutKind::ToC, &s_ap0);
    add_out(&mut outs, &mut out_w, "IS_c0", 3, OutKind::Pub, &kc0.inner);
    (gate_end[3], and_end[3]) = (b.gates, b.ands);

    // B2: K_0, IV_0, c_ap_1 = f(OS_c0, ·), and the anchors
    // h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0), hk = SHA256(K_0 ‖ IV_0).
    let c_ap1 = b.outer(&kc0.outer, &dig[8]);
    add_out(&mut outs, &mut out_w, "c_ap_1", 4, OutKind::ToC, &c_ap1);
    let t_key = b.outer(&kc0.outer, &dig[6]);
    let t_iv = b.outer(&kc0.outer, &dig[7]);
    let mut kiv = t_key[..128].to_vec();
    kiv.extend_from_slice(&t_iv[..96]);
    add_out(&mut outs, &mut out_w, "kiv", 4, OutKind::ToN, &kiv);
    let h1 = b.sha256(&c_ap1);
    let h2 = b.sha256(&s_ap0);
    let hk = b.sha256(&kiv);
    add_out(&mut outs, &mut out_w, "h1", 4, OutKind::Pub, &h1);
    add_out(&mut outs, &mut out_w, "h2", 4, OutKind::Pub, &h2);
    add_out(&mut outs, &mut out_w, "hk", 4, OutKind::Pub, &hk);
    (gate_end[4], and_end[4]) = (b.gates, b.ands);

    b.output(&out_w);
    let compressions = b.compressions;
    let circ = b.b.build().expect("split circuit");
    assert_eq!(circ.gates().len(), gate_end[4]);
    assert_eq!(circ.and_count(), and_end[4]);
    assert_eq!(circ.outputs().len(), out_w.len());
    Split {
        circ: Arc::new(circ),
        compressions,
        gate_end,
        and_end,
        xc: 0..256,
        xn: 256..512,
        dig: (0..9).map(|j| 512 + 256 * j..512 + 256 * (j + 1)).collect(),
        dig_stage: DIG_STAGE.to_vec(),
        outs,
    }
}

/// The circuit of `split-public-1`.
pub static SPLIT: LazyLock<Split> = LazyLock::new(build_split);

/// The single padded block of an HMAC inner hash over `msg` (the key block
/// was absorbed before): `msg ‖ 0x80 ‖ 0… ‖ bitlen(prefix + msg)`.
pub(crate) fn msg_block(prefix_len: usize, msg: &[u8]) -> [u8; 64] {
    assert!(msg.len() <= 55);
    let mut b = [0u8; 64];
    b[..msg.len()].copy_from_slice(msg);
    b[msg.len()] = 0x80;
    b[56..].copy_from_slice(&(((prefix_len + msg.len()) * 8) as u64).to_be_bytes());
    b
}

/// The inner block of `HKDF-Expand-Label(·, label, ctx, len)` (one HMAC
/// block; RFC 8446 §7.1).
pub(crate) fn hkdf_block(label: &str, ctx: &[u8], len: u16) -> [u8; 64] {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&len.to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    info.push(0x01);
    msg_block(64, &info)
}

/// The public message blocks of the inner digests of `stage`'s inputs.
pub(crate) fn digest_blocks(stage: usize, th: &[u8; 32]) -> Vec<[u8; 64]> {
    match stage {
        1 => vec![
            hkdf_block("c hs traffic", th, 32),
            hkdf_block("s hs traffic", th, 32),
            hkdf_block("derived", &sha256_native(b""), 32),
        ],
        2 => vec![msg_block(64, &[0u8; 32])],
        3 => vec![hkdf_block("c ap traffic", th, 32), hkdf_block("s ap traffic", th, 32)],
        4 => vec![hkdf_block("key", &[], 16), hkdf_block("iv", &[], 12), hkdf_block("traffic upd", &[], 32)],
        _ => Vec::new(),
    }
}

/// State wires (8 words, 32 bits each, LSB first) → words.
pub(crate) fn state_words(bits: &[bool]) -> [u32; 8] {
    core::array::from_fn(|j| (0..32).fold(0u32, |a, k| a | ((bits[32 * j + k] as u32) << k)))
}

/// Digest bits (byte order, LSB first per byte) of a state.
pub(crate) fn digest_bits(state: &[u32; 8]) -> Vec<bool> {
    let bytes: Vec<u8> = state.iter().flat_map(|w| w.to_be_bytes()).collect();
    to_bits(&bytes)
}

/// The inner digest `f(IS, block)` as digest bits.
pub(crate) fn inner_digest(is_bits: &[bool], block: &[u8; 64]) -> Vec<bool> {
    digest_bits(&compress_native(&state_words(is_bits), block))
}

/// Bytes → bits, LSB first per byte.
pub fn to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).map(move |k| (b >> k) & 1 == 1))
        .collect()
}

/// Bits (LSB first per byte) → bytes.
pub fn from_bits(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().enumerate().fold(0u8, |a, (k, &v)| a | ((v as u8) << k)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cu_crypto::hkdf::{hkdf_expand_label, hkdf_extract, sha256};
    use cu_crypto::keyschedule::KeySchedule;

    fn st_bits(w: &[u32; 8]) -> Vec<bool> {
        w.iter().flat_map(|w| (0..32).map(move |k| (w >> k) & 1 == 1)).collect()
    }

    /// The circuit's outputs for ECDHE x-coordinate shares `xc + xn mod p`
    /// (little-endian) and the inner digests an honest run feeds it.
    fn run(xc: &[u8; 32], xn: &[u8; 32], x_be: &[u8; 32], th_sh: [u8; 32], th_sf: [u8; 32]) -> (Vec<bool>, KeySchedule) {
        let hs = hkdf_extract(&derived_es(), x_be);
        let ks = KeySchedule::from_handshake(hs, th_sh, th_sf);
        let (is_hs, _) = hmac_states_native(&hs);
        let derived = cu_crypto::hkdf::derive_secret(&hs, "derived", b"");
        let (is_d, _) = hmac_states_native(&derived);
        let (is_ms, _) = hmac_states_native(ks.master_secret.as_bytes());
        let c_ap_0 = hkdf_expand_label(ks.master_secret.as_bytes(), "c ap traffic", &th_sf, 32);
        let (is_c0, _) = hmac_states_native(c_ap_0.as_slice().try_into().unwrap());
        let iss = [st_bits(&is_hs), st_bits(&is_d), st_bits(&is_ms), st_bits(&is_c0)];
        let mut input = to_bits(xc);
        input.extend(to_bits(xn));
        let mut n = 0;
        for (stage, th, is) in [(1, th_sh, &iss[0]), (2, th_sh, &iss[1]), (3, th_sf, &iss[2]), (4, th_sf, &iss[3])] {
            for blk in digest_blocks(stage, &th) {
                input.extend(inner_digest(is, &blk));
                n += 1;
            }
        }
        assert_eq!(n, 9);
        let out = SPLIT.circ.evaluate(input).unwrap();
        let get = |name: &str| -> Vec<bool> {
            let g = &SPLIT.outs[SPLIT.group(name)];
            out[g.off..g.off + g.len].to_vec()
        };
        assert_eq!(get("IS_HS"), iss[0]);
        assert_eq!(get("IS_dHS"), iss[1]);
        assert_eq!(get("IS_MS"), iss[2]);
        assert_eq!(get("IS_c0"), iss[3]);
        (out, ks)
    }

    #[test]
    fn split_circuit_matches_reference() {
        let x: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let th_sh = [0x42u8; 32];
        let th_sf = [0x17u8; 32];
        // Additive shares of x mod p: x_n = 5, x_c = x - 5 (x is < p, and
        // its low byte is >= 5, so there is no borrow).
        let mut xc = x;
        xc.reverse();
        assert!(xc[0] >= 5);
        xc[0] -= 5;
        let mut xn = [0u8; 32];
        xn[0] = 5;
        let (out, ks) = run(&xc, &xn, &x, th_sh, th_sf);
        let sp = &*SPLIT;
        let get = |name: &str| -> Vec<u8> {
            let g = &sp.outs[sp.group(name)];
            from_bits(&out[g.off..g.off + g.len])
        };
        let mut kiv = ks.c_ap_0.key().to_vec();
        kiv.extend_from_slice(&ks.c_ap_0.iv());
        assert_eq!(get("c_hs"), ks.client_hs.as_bytes());
        assert_eq!(get("s_hs"), ks.server_hs.as_bytes());
        assert_eq!(get("s_ap_0"), ks.s_ap_0.as_bytes());
        assert_eq!(get("c_ap_1"), ks.c_ap_1.as_bytes());
        assert_eq!(get("kiv"), kiv);
        assert_eq!(get("h1"), sha256(ks.c_ap_1.as_bytes()));
        assert_eq!(get("h2"), sha256(ks.s_ap_0.as_bytes()));
        assert_eq!(get("hk"), sha256(&kiv));

        // A stage reads only wires that exist by then, and its outputs
        // exist when it ends.
        let mut defined = vec![false; sp.circ.feed_count()];
        for w in sp.xc.clone().chain(sp.xn.clone()) {
            defined[w] = true;
        }
        let mut g0 = 0;
        for s in 0..N_STAGES {
            for j in sp.digs_of(s) {
                for w in sp.dig[j].clone() {
                    defined[w] = true;
                }
            }
            for g in &sp.circ.gates()[g0..sp.gate_end[s]] {
                match g {
                    Gate::Xor { x, y, z } | Gate::And { x, y, z } => {
                        assert!(defined[x.id()] && defined[y.id()]);
                        defined[z.id()] = true;
                    }
                    Gate::Inv { x, z } | Gate::Id { x, z } => {
                        assert!(defined[x.id()]);
                        defined[z.id()] = true;
                    }
                }
            }
            g0 = sp.gate_end[s];
            let o0 = sp.circ.outputs().start;
            for g in sp.outs.iter().filter(|g| g.stage == s) {
                assert!((g.off..g.off + g.len).all(|i| defined[o0 + i]), "{} ready after stage {s}", g.name);
            }
        }
        // The sizes the specification and BENCH.md quote.
        assert_eq!(sp.compressions, 22);
        assert_eq!(sp.circ.and_count(), 479_022);
        eprintln!("AND per stage end {:?}", sp.and_end);
    }

    #[test]
    fn add_mod_p_wraps() {
        // x_c + x_n >= p must wrap: x_c = p - 1, x_n = 2 → Z = 1.
        let mut pm1 = p256_modulus_le();
        pm1[0] -= 1;
        let mut two = [0u8; 32];
        two[0] = 2;
        let mut one_be = [0u8; 32];
        one_be[31] = 1;
        // `run` compares IS_HS (and everything after it) with the reference
        // for Z = 1.
        let (out, ks) = run(&pm1, &two, &one_be, [0u8; 32], [0u8; 32]);
        let g = &SPLIT.outs[SPLIT.group("c_hs")];
        assert_eq!(from_bits(&out[g.off..g.off + g.len]), ks.client_hs.as_bytes());
    }
}
