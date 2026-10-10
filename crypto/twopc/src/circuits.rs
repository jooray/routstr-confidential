//! The two key-schedule circuits (phase A and phase B).
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

use std::sync::{Arc, LazyLock};

use mpz_circuits::{Circuit, CircuitBuilder, Feed, Gate, Node, SHA256_COMPRESS};

type W = Node<Feed>;

pub(crate) const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Input layout of a circuit: C's inputs, N's inputs, then the garbler's
/// transcript hash (supplied by whichever party garbles that run).
#[derive(Debug)]
pub struct Spec {
    pub circ: Arc<Circuit>,
    pub c_bits: usize,
    pub n_bits: usize,
    pub th_bits: usize,
    pub out_bits: usize,
    /// SHA-256 compression functions instantiated.
    pub compressions: usize,
}

impl Spec {
    pub fn c_range(&self) -> std::ops::Range<usize> {
        0..self.c_bits
    }
    pub fn n_range(&self) -> std::ops::Range<usize> {
        self.c_bits..self.c_bits + self.n_bits
    }
    pub fn th_range(&self) -> std::ops::Range<usize> {
        let s = self.c_bits + self.n_bits;
        s..s + self.th_bits
    }
}

struct B {
    b: CircuitBuilder,
    compressions: usize,
}

impl B {
    fn new() -> Self {
        Self {
            b: CircuitBuilder::new(),
            compressions: 0,
        }
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
        (0..n).map(|_| self.b.add_input()).collect()
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
            .map(|(x, y)| self.b.add_xor_gate(*x, *y))
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
                    self.b.add_xor_gate(x, y)
                }
                Gate::And { x, y, .. } => {
                    let (x, y) = (get(&map, x.id()), get(&map, y.id()));
                    self.b.add_and_gate(x, y)
                }
                Gate::Inv { x, .. } => {
                    let x = get(&map, x.id());
                    self.b.add_inv_gate(x)
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

    /// HKDF-Expand-Label(secret, label, ctx, len) for len <= 32.
    fn expand_label(&mut self, k: &HmacKey, label: &str, ctx: &[W], len: usize) -> Vec<W> {
        assert!(len <= 32);
        let full = format!("tls13 {label}");
        let mut head = Vec::new();
        head.extend_from_slice(&(len as u16).to_be_bytes());
        head.push(full.len() as u8);
        head.extend_from_slice(full.as_bytes());
        head.push((ctx.len() / 8) as u8);
        let mut info = self.const_bytes(&head);
        info.extend_from_slice(ctx);
        info.extend(self.const_bytes(&[0x01]));
        let t = self.hmac(k, &info);
        t[..len * 8].to_vec()
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
                let diff = self.b.add_xor_gate(d[i], s[i]);
                let sel = self.b.add_and_gate(ge, diff);
                self.b.add_xor_gate(s[i], sel)
            })
            .collect()
    }

    /// Ripple-carry adder; returns (sum, carry_out).
    fn add(&mut self, a: &[W], b: &[W], cin: Option<W>) -> (Vec<W>, W) {
        assert_eq!(a.len(), b.len());
        let mut c = cin.unwrap_or(self.zero());
        let mut out = Vec::with_capacity(a.len());
        for (x, y) in a.iter().zip(b) {
            let xy = self.b.add_xor_gate(*x, *y);
            out.push(self.b.add_xor_gate(xy, c));
            let xc = self.b.add_xor_gate(*x, c);
            let yc = self.b.add_xor_gate(*y, c);
            let t = self.b.add_and_gate(xc, yc);
            c = self.b.add_xor_gate(t, c);
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

/// Phase A: x-coordinate shares, MS masks, th_SH →
/// `c_hs ‖ s_hs ‖ (MS ⊕ r_C ⊕ r_N)`.
///
/// Inputs: C = `x_C (32 B LE) ‖ r_C (32 B)`, N = `x_N ‖ r_N`, th = th_SH.
fn build_phase_a() -> Spec {
    let mut b = B::new();
    let xc = b.inputs(256);
    let rc = b.inputs(256);
    let xn = b.inputs(256);
    let rn = b.inputs(256);
    let th = b.inputs(256);

    let x = b.add_mod_p(&xc, &xn);
    // IKM = x as 32 big-endian bytes.
    let mut ikm = Vec::with_capacity(256);
    for j in 0..32 {
        for k in 0..8 {
            ikm.push(x[(31 - j) * 8 + k]);
        }
    }
    let salt = b.hmac_key_const(&derived_es());
    let hs = b.hmac(&salt, &ikm);
    let khs = b.hmac_key(&hs);
    let c_hs = b.expand_label(&khs, "c hs traffic", &th, 32);
    let s_hs = b.expand_label(&khs, "s hs traffic", &th, 32);
    let empty = b.const_bytes(&sha256_native(b""));
    let derived = b.expand_label(&khs, "derived", &empty, 32);
    let kd = b.hmac_key(&derived);
    let zeros = b.const_bytes(&[0u8; 32]);
    let ms = b.hmac(&kd, &zeros);
    let m1 = b.xor(&ms, &rc);
    let v = b.xor(&m1, &rn);

    b.output(&c_hs);
    b.output(&s_hs);
    b.output(&v);
    let compressions = b.compressions;
    Spec {
        circ: Arc::new(b.b.build().expect("phase A circuit")),
        c_bits: 512,
        n_bits: 512,
        th_bits: 256,
        out_bits: 768,
        compressions,
    }
}

/// Phase B: MS shares, output masks, th_SF →
/// `(s_ap_0 ‖ c_ap_1) ⊕ m_C ‖ (K_0 ‖ IV_0) ⊕ m_N ‖ h1 ‖ h2 ‖ hk`.
///
/// Inputs: C = `ms_C (32 B) ‖ m_C (64 B)`, N = `ms_N (32 B) ‖ m_N (28 B)`,
/// th = th_SF.
fn build_phase_b() -> Spec {
    let mut b = B::new();
    let msc = b.inputs(256);
    let mc = b.inputs(512);
    let msn = b.inputs(256);
    let mn = b.inputs(224);
    let th = b.inputs(256);

    let ms = b.xor(&msc, &msn);
    let kms = b.hmac_key(&ms);
    let c_ap0 = b.expand_label(&kms, "c ap traffic", &th, 32);
    let s_ap0 = b.expand_label(&kms, "s ap traffic", &th, 32);
    let kc0 = b.hmac_key(&c_ap0);
    let c_ap1 = b.expand_label(&kc0, "traffic upd", &[], 32);
    let k0 = b.expand_label(&kc0, "key", &[], 16);
    let iv0 = b.expand_label(&kc0, "iv", &[], 12);
    let h1 = b.sha256(&c_ap1);
    let h2 = b.sha256(&s_ap0);
    let mut kiv = k0.clone();
    kiv.extend_from_slice(&iv0);
    let hk = b.sha256(&kiv);

    let o_s = b.xor(&s_ap0, &mc[..256]);
    let o_c = b.xor(&c_ap1, &mc[256..]);
    let o_k = b.xor(&kiv, &mn);
    b.output(&o_s);
    b.output(&o_c);
    b.output(&o_k);
    b.output(&h1);
    b.output(&h2);
    b.output(&hk);
    let compressions = b.compressions;
    Spec {
        circ: Arc::new(b.b.build().expect("phase B circuit")),
        c_bits: 768,
        n_bits: 480,
        th_bits: 256,
        out_bits: 256 + 256 + 224 + 768,
        compressions,
    }
}

pub static PHASE_A: LazyLock<Spec> = LazyLock::new(build_phase_a);
pub static PHASE_B: LazyLock<Spec> = LazyLock::new(build_phase_b);

pub(crate) fn spec(phase: usize) -> &'static Spec {
    match phase {
        0 => &PHASE_A,
        _ => &PHASE_B,
    }
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

    fn eval(spec: &Spec, input: &[u8]) -> Vec<u8> {
        let out = spec.circ.evaluate(to_bits(input)).unwrap();
        from_bits(&out)
    }

    #[test]
    fn plaintext_circuits_match_reference() {
        // Random-ish fixed values.
        let x: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let th_sh = [0x42u8; 32];
        let th_sf = [0x17u8; 32];
        // Additive shares of x mod p: x_n = 5, x_c = x - 5 (x is < p).
        let mut x_le = x;
        x_le.reverse();
        let mut xc = x_le;
        // subtract 5 (no borrow issues for this x since low byte >= 5)
        assert!(xc[0] >= 5);
        xc[0] -= 5;
        let mut xn = [0u8; 32];
        xn[0] = 5;
        let rc = [0xaau8; 32];
        let rn = [0x0fu8; 32];

        let mut input = Vec::new();
        input.extend_from_slice(&xc);
        input.extend_from_slice(&rc);
        input.extend_from_slice(&xn);
        input.extend_from_slice(&rn);
        input.extend_from_slice(&th_sh);
        let out = eval(&PHASE_A, &input);

        let hs = hkdf_extract(&derived_es(), &x);
        let ks = KeySchedule::from_handshake(hs, th_sh, th_sf);
        assert_eq!(&out[0..32], ks.client_hs.as_bytes());
        assert_eq!(&out[32..64], ks.server_hs.as_bytes());
        let mut ms_masked = *ks.master_secret.as_bytes();
        for i in 0..32 {
            ms_masked[i] ^= rc[i] ^ rn[i];
        }
        assert_eq!(&out[64..96], &ms_masked);

        // Phase B with shares ms_C = rc, ms_N = ms ^ rc.
        let msc = rc;
        let mut msn = *ks.master_secret.as_bytes();
        for i in 0..32 {
            msn[i] ^= rc[i];
        }
        let mc = [0x33u8; 64];
        let mn = [0x99u8; 28];
        let mut input = Vec::new();
        input.extend_from_slice(&msc);
        input.extend_from_slice(&mc);
        input.extend_from_slice(&msn);
        input.extend_from_slice(&mn);
        input.extend_from_slice(&th_sf);
        let out = eval(&PHASE_B, &input);
        let unmask = |o: &[u8], m: &[u8]| o.iter().zip(m).map(|(a, b)| a ^ b).collect::<Vec<_>>();
        assert_eq!(unmask(&out[0..32], &mc[..32]), ks.s_ap_0.as_bytes());
        assert_eq!(unmask(&out[32..64], &mc[32..]), ks.c_ap_1.as_bytes());
        let mut kiv = ks.c_ap_0.key().to_vec();
        kiv.extend_from_slice(&ks.c_ap_0.iv());
        assert_eq!(unmask(&out[64..92], &mn), kiv);
        assert_eq!(&out[92..124], &sha256(ks.c_ap_1.as_bytes()));
        assert_eq!(&out[124..156], &sha256(ks.s_ap_0.as_bytes()));
        assert_eq!(&out[156..188], &sha256(&kiv));
        let _ = hkdf_expand_label;
    }

    #[test]
    fn add_mod_p_wraps() {
        // x_c + x_n >= p must wrap: take x_c = p - 1, x_n = 2 → 1.
        let mut pm1 = p256_modulus_le();
        pm1[0] -= 1;
        let mut two = [0u8; 32];
        two[0] = 2;
        let mut one_be = [0u8; 32];
        one_be[31] = 1;
        let th = [0u8; 32];
        let mut input = Vec::new();
        input.extend_from_slice(&pm1);
        input.extend_from_slice(&[0u8; 32]);
        input.extend_from_slice(&two);
        input.extend_from_slice(&[0u8; 32]);
        input.extend_from_slice(&th);
        let out = eval(&PHASE_A, &input);
        let hs = hkdf_extract(&derived_es(), &one_be);
        let ks = KeySchedule::from_handshake(hs, th, th);
        assert_eq!(&out[0..32], ks.client_hs.as_bytes());
    }
}
