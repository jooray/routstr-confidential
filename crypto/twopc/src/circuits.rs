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

use std::ops::Range;
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

// ---------------------------------------------------------------------------
// Split key schedule (protocol v3, option B).
//
// One circuit, evaluated in five stages (A1, A2, A3, B1, B2). The garbled
// circuit computes only the HMAC key-pad states `IS_k = f(IV, k ⊕ ipad)`,
// `OS_k = f(IV, k ⊕ opad)` and the outer compressions `f(OS_k, pad(d))`. The
// inner digests `d = f(IS_k, m)` (every `m` is public) are computed outside
// the circuit and enter the next stage as inputs. `OS_k` never leaves the
// circuit: it is an internal wire that simply continues into later stages.
// ---------------------------------------------------------------------------

/// Number of evaluation stages of the split circuit.
pub const N_STAGES: usize = 5;
/// Stages run by `Party::handshake` (A1, A2, A3); the rest by `application`.
pub const HS_STAGES: usize = 3;

/// How the inner digests and the anchors are bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Variant {
    /// Spec B.2: `IS_k` goes to C only; C proves each inner digest and the
    /// anchors h1, h2 in zero knowledge (under Δ_A); N proves hk (under Δ_B).
    /// 19 garbled compressions.
    #[default]
    Proven,
    /// `IS_k` is public: both parties compute the inner digests, which enter
    /// as public inputs pinned by pointer checks (as the transcript hash does
    /// in v2). No proofs; the anchors stay garbled. 22 garbled compressions.
    PublicIs,
}

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
    /// C turns this output into a commitment towards N (variant `Proven`).
    pub conv: bool,
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

fn add_out(outs: &mut Vec<OutGroup>, out_w: &mut Vec<W>, proven: bool, name: &'static str, stage: usize, kind: OutKind, w: &[W]) {
    outs.push(OutGroup {
        name,
        stage,
        kind,
        conv: proven && kind == OutKind::ToC,
        off: out_w.len(),
        len: w.len(),
    });
    out_w.extend_from_slice(w);
}

/// `aggressive` (spec B.3, statistics only): the outer compressions whose
/// output is public or N's (c_hs, s_hs, K_0, IV_0) leave the circuit, and
/// `OS_HS`, `OS_c0` become outputs to N.
fn build_split(variant: Variant, aggressive: bool) -> Split {
    let proven = variant == Variant::Proven;
    let mut b = B::new();
    let xc = b.inputs(256);
    let xn = b.inputs(256);
    let dig: Vec<Vec<W>> = (0..9).map(|_| b.inputs(256)).collect();
    let mut gate_end = [0usize; N_STAGES];
    let mut and_end = [0usize; N_STAGES];
    let mut outs: Vec<OutGroup> = Vec::new();
    let mut out_w: Vec<W> = Vec::new();
    let is_kind = if proven { OutKind::ToC } else { OutKind::Pub };

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
    add_out(&mut outs, &mut out_w, proven, "IS_HS", 0, is_kind, &khs.inner);
    (gate_end[0], and_end[0]) = (b.gates, b.ands);

    // A2: c_hs, s_hs, dHS = f(OS_HS, ·); key-pad states of dHS.
    if aggressive {
        add_out(&mut outs, &mut out_w, proven, "OS_HS", 1, OutKind::ToN, &khs.outer);
    } else {
        let c_hs = b.outer(&khs.outer, &dig[0]);
        let s_hs = b.outer(&khs.outer, &dig[1]);
        add_out(&mut outs, &mut out_w, proven, "c_hs", 1, OutKind::Pub, &c_hs);
        add_out(&mut outs, &mut out_w, proven, "s_hs", 1, OutKind::Pub, &s_hs);
    }
    let dhs = b.outer(&khs.outer, &dig[2]);
    let kd = b.hmac_key(&dhs);
    add_out(&mut outs, &mut out_w, proven, "IS_dHS", 1, is_kind, &kd.inner);
    (gate_end[1], and_end[1]) = (b.gates, b.ands);

    // A3: MS = f(OS_dHS, d_0); key-pad states of MS.
    let ms = b.outer(&kd.outer, &dig[3]);
    let kms = b.hmac_key(&ms);
    add_out(&mut outs, &mut out_w, proven, "IS_MS", 2, is_kind, &kms.inner);
    (gate_end[2], and_end[2]) = (b.gates, b.ands);

    // B1: c_ap_0, s_ap_0 = f(OS_MS, ·); key-pad states of c_ap_0.
    let c_ap0 = b.outer(&kms.outer, &dig[4]);
    let s_ap0 = b.outer(&kms.outer, &dig[5]);
    let kc0 = b.hmac_key(&c_ap0);
    add_out(&mut outs, &mut out_w, proven, "s_ap_0", 3, OutKind::ToC, &s_ap0);
    add_out(&mut outs, &mut out_w, proven, "IS_c0", 3, is_kind, &kc0.inner);
    if !proven {
        let h2 = b.sha256(&s_ap0);
        add_out(&mut outs, &mut out_w, proven, "h2", 3, OutKind::Pub, &h2);
    }
    (gate_end[3], and_end[3]) = (b.gates, b.ands);

    // B2: K_0, IV_0, c_ap_1 = f(OS_c0, ·).
    let c_ap1 = b.outer(&kc0.outer, &dig[8]);
    add_out(&mut outs, &mut out_w, proven, "c_ap_1", 4, OutKind::ToC, &c_ap1);
    if aggressive {
        add_out(&mut outs, &mut out_w, proven, "OS_c0", 4, OutKind::ToN, &kc0.outer);
    } else {
        let t_key = b.outer(&kc0.outer, &dig[6]);
        let t_iv = b.outer(&kc0.outer, &dig[7]);
        let mut kiv = t_key[..128].to_vec();
        kiv.extend_from_slice(&t_iv[..96]);
        add_out(&mut outs, &mut out_w, proven, "kiv", 4, OutKind::ToN, &kiv);
        if !proven {
            let h1 = b.sha256(&c_ap1);
            let hk = b.sha256(&kiv);
            add_out(&mut outs, &mut out_w, proven, "h1", 4, OutKind::Pub, &h1);
            add_out(&mut outs, &mut out_w, proven, "hk", 4, OutKind::Pub, &hk);
        }
    }
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

pub static SPLIT_PROVEN: LazyLock<Split> = LazyLock::new(|| build_split(Variant::Proven, false));
pub static SPLIT_PUBLIC: LazyLock<Split> = LazyLock::new(|| build_split(Variant::PublicIs, false));

pub fn split(v: Variant) -> &'static Split {
    match v {
        Variant::Proven => &SPLIT_PROVEN,
        Variant::PublicIs => &SPLIT_PUBLIC,
    }
}

/// (name, garbled AND gates, garbled SHA-256 compressions) of every design:
/// v2, the two built variants, and the aggressive variant B.3 (not built as a
/// protocol; its circuit is constructed only for this count).
pub fn design_stats() -> Vec<(&'static str, usize, usize)> {
    let b3 = build_split(Variant::Proven, true);
    vec![
        (
            "v2 (phase A + phase B)",
            PHASE_A.circ.and_count() + PHASE_B.circ.and_count(),
            PHASE_A.compressions + PHASE_B.compressions,
        ),
        ("B.2 proven (IS to C, inner digests and anchors in ZK)", SPLIT_PROVEN.circ.and_count(), SPLIT_PROVEN.compressions),
        ("public IS (no proofs, anchors garbled)", SPLIT_PUBLIC.circ.and_count(), SPLIT_PUBLIC.compressions),
        ("B.3 aggressive (count only, not built)", b3.circ.and_count(), b3.compressions),
    ]
}

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
/// block; RFC 8446 §7.1), as `expand_label` builds it in the circuit.
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

/// Reorders state wires (word order) into digest wires (byte order).
pub(crate) fn digest_perm<T: Copy>(state: &[T]) -> Vec<T> {
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
    fn split_circuits_match_reference() {
        let x: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let th_sh = [0x42u8; 32];
        let th_sf = [0x17u8; 32];
        let mut x_le = x;
        x_le.reverse();
        let mut xc = x_le;
        xc[0] -= 5;
        let mut xn = [0u8; 32];
        xn[0] = 5;
        let hs = hkdf_extract(&derived_es(), &x);
        let ks = KeySchedule::from_handshake(hs, th_sh, th_sf);
        // Native key-pad states and inner digests.
        let (is_hs, _) = hmac_states_native(&hs);
        let derived = cu_crypto::hkdf::derive_secret(&hs, "derived", b"");
        let (is_d, _) = hmac_states_native(&derived);
        let (is_ms, _) = hmac_states_native(ks.master_secret.as_bytes());
        let c_ap_0 = hkdf_expand_label(ks.master_secret.as_bytes(), "c ap traffic", &th_sf, 32);
        let (is_c0, _) = hmac_states_native(c_ap_0.as_slice().try_into().unwrap());
        let st_bits =
            |w: &[u32; 8]| -> Vec<bool> { w.iter().flat_map(|w| (0..32).map(move |k| (w >> k) & 1 == 1)).collect() };
        let iss = [st_bits(&is_hs), st_bits(&is_d), st_bits(&is_ms), st_bits(&is_c0)];
        let mut digs: Vec<Vec<bool>> = Vec::new();
        for (stage, th, is) in [(1, th_sh, &iss[0]), (2, th_sh, &iss[1]), (3, th_sf, &iss[2]), (4, th_sf, &iss[3])] {
            for blk in digest_blocks(stage, &th) {
                digs.push(inner_digest(is, &blk));
            }
        }
        assert_eq!(digs.len(), 9);
        let mut kiv = ks.c_ap_0.key().to_vec();
        kiv.extend_from_slice(&ks.c_ap_0.iv());
        for v in [Variant::Proven, Variant::PublicIs] {
            let sp = split(v);
            let mut input = to_bits(&xc);
            input.extend(to_bits(&xn));
            for d in &digs {
                input.extend(d.iter().copied());
            }
            let out = sp.circ.evaluate(input).unwrap();
            let get = |name: &str| -> Vec<bool> {
                let g = &sp.outs[sp.group(name)];
                out[g.off..g.off + g.len].to_vec()
            };
            assert_eq!(get("IS_HS"), iss[0]);
            assert_eq!(get("IS_dHS"), iss[1]);
            assert_eq!(get("IS_MS"), iss[2]);
            assert_eq!(get("IS_c0"), iss[3]);
            assert_eq!(from_bits(&get("c_hs")), ks.client_hs.as_bytes());
            assert_eq!(from_bits(&get("s_hs")), ks.server_hs.as_bytes());
            assert_eq!(from_bits(&get("s_ap_0")), ks.s_ap_0.as_bytes());
            assert_eq!(from_bits(&get("c_ap_1")), ks.c_ap_1.as_bytes());
            assert_eq!(from_bits(&get("kiv")), kiv);
            if v == Variant::PublicIs {
                assert_eq!(from_bits(&get("h1")), sha256(ks.c_ap_1.as_bytes()));
                assert_eq!(from_bits(&get("h2")), sha256(ks.s_ap_0.as_bytes()));
                assert_eq!(from_bits(&get("hk")), sha256(&kiv));
            }
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
            eprintln!("{v:?}: AND per stage end {:?}", sp.and_end);
        }
        for (name, and, comp) in design_stats() {
            eprintln!("{name}: {and} AND, {comp} compressions");
        }
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
