//! Garbler-only authenticated garbling: the primitives.
//!
//! * Three-halves garbling / evaluation (Rosulek–Roy 2021; 1.5κ+5 bits per
//!   AND, free XOR), keeping every wire's zero-label (garbler) and every
//!   active label (evaluator), which the consistency check needs. The hash is
//!   the paper's recommended RTCCR family [`HashG`], `AES_k(Y) ⊕ σ(Y)` with
//!   `Y = X ⊕ U(τ)`, its key and `U` drawn by N per session ([`gf64`]).
//! * IT-MAC bookkeeping over GF(2^128): the garbler N holds authenticated bits
//!   `[x] = (x, M[x])`, the evaluator C holds `(K[x], Δ_B)` with
//!   `M[x] = K[x] ⊕ x·Δ_B`. Wire masks `λ_w` (= the point-and-permute bit of
//!   N's zero-label) are authenticated for every circuit input and every AND
//!   output; every other wire follows by linearity (XOR: sum, INV: `λ ⊕ 1`,
//!   i.e. `K ⊕ Δ_B` on C's side).
//! * The per-AND products `t_k = λ_i·λ_j` (QuickSilver-style batched check).
//! * The consistency check of the evaluation (one 64-bit row per row wire,
//!   hashed by [`RowHash`] under a key from C's challenge seed).
//!
//! Notation: `P_{w,Λ}` is the label of wire w whose pointer bit is Λ:
//! `P_{w,Λ} = k_w ⊕ (Λ ⊕ λ_w)·Δ_A` (k_w = label of the value 0). The evaluator
//! holds `P_{w,Λ_w}` with `Λ_w = z_w ⊕ λ_w` (z_w = the true wire value).

use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;
use mpz_core::aes::AesEncryptor;
use rand::RngExt;
use zeroize::Zeroize;

/// GF(2^64) = GF(2)[x]/(x^64 + x^4 + x^3 + x + 1); a `u64` is the polynomial
/// whose coefficient of x^i is bit i.
pub mod gf64 {
    /// Multiplication by x. Branch-free: its input holds label bits.
    #[inline]
    pub fn xtime(a: u64) -> u64 {
        (a << 1) ^ (0x1b & (a >> 63).wrapping_neg())
    }

    /// The product, reduced. Branch-free (bit-serial with masks).
    pub fn mul(a: u64, b: u64) -> u64 {
        let (mut a, mut r) = (a, 0u64);
        for i in 0..64 {
            r ^= a & ((b >> i) & 1).wrapping_neg();
            a = xtime(a);
        }
        r
    }

    /// σ(Y_hi ‖ Y_lo) = x·Y_hi ‖ x·Y_lo (Rosulek–Roy's σ with α = x).
    #[inline]
    pub fn sigma(y: u128) -> u128 {
        ((xtime((y >> 64) as u64) as u128) << 64) | xtime(y as u64) as u128
    }

    /// `U_{a,b}(τ) = a·τ ‖ b·τ` for public multipliers and a public tweak:
    /// a table of `a·x^i`, `b·x^i`, XORed per set bit of τ.
    #[derive(Clone)]
    pub struct UMap {
        hi: [u64; 64],
        lo: [u64; 64],
    }

    impl UMap {
        pub fn new(a: u64, b: u64) -> UMap {
            let (mut hi, mut lo) = ([0u64; 64], [0u64; 64]);
            let (mut x, mut y) = (a, b);
            for i in 0..64 {
                hi[i] = x;
                lo[i] = y;
                x = xtime(x);
                y = xtime(y);
            }
            UMap { hi, lo }
        }

        /// `U(τ)`; branches on the bits of τ (a gate index or a row position).
        #[inline]
        pub fn at(&self, tau: u64) -> u128 {
            let (mut h, mut l, mut t) = (0u64, 0u64, tau);
            while t != 0 {
                let i = t.trailing_zeros() as usize;
                h ^= self.hi[i];
                l ^= self.lo[i];
                t &= t - 1;
            }
            ((h as u128) << 64) | l as u128
        }
    }
}

/// Parses the 32-byte layout shared by the hash parameters and the row
/// parameters: AES-128 key (bytes 0..16, as given to the cipher), the
/// multiplier of the high half (16..24) and of the low half (24..32), both
/// little-endian.
fn parse_params(p: &[u8; 32]) -> (AesEncryptor, gf64::UMap) {
    let key = Block::new(p[..16].try_into().expect("16 bytes"));
    let a = u64::from_le_bytes(p[16..24].try_into().expect("8 bytes"));
    let b = u64::from_le_bytes(p[24..32].try_into().expect("8 bytes"));
    (AesEncryptor::new(key), gf64::UMap::new(a, b))
}

/// The garbling hash `H_g(X, τ) = AES_k(Y) ⊕ σ(Y)`, `Y = X ⊕ U(τ)`, from N's
/// 32-byte parameters (fresh per session; sent to C right before the
/// tables). It protects only N: no check of C rests on it.
#[derive(Clone)]
pub struct HashG {
    aes: AesEncryptor,
    u: gf64::UMap,
}

impl HashG {
    pub fn new(params: &[u8; 32]) -> HashG {
        let (aes, u) = parse_params(params);
        HashG { aes, u }
    }

    #[inline]
    pub fn h(&self, x: u128, tau: u64) -> u128 {
        let y = x ^ self.u.at(tau);
        u(self.aes.encrypt_block(blk(y))) ^ gf64::sigma(y)
    }

    #[inline]
    pub fn h_many<const N: usize>(&self, x: [u128; N], tau: [u64; N]) -> [u128; N] {
        let y: [u128; N] = core::array::from_fn(|i| x[i] ^ self.u.at(tau[i]));
        let mut b = y.map(blk);
        self.aes.encrypt_many_blocks(&mut b);
        core::array::from_fn(|i| u(b[i]) ^ gf64::sigma(y[i]))
    }
}

/// Bit 63 of a tweak of [`HashG`] marks a check row; gate tweaks stay below.
pub const ROW_TWEAK: u64 = 1 << 63;

/// The check-row hash
/// `row(X; s, idx) = lo64(AES_{k_r}(H_g(X, 2^63 | τ) ⊕ U_r(τ)))`,
/// `τ = s·2^32 | idx`, keyed by the row parameters N derives from C's seed
/// after it committed to everything else. The inner call is a full-width
/// query of the garbling hash on a tweak no gate uses, the outer one a
/// bijection under a key N could not know when it committed.
pub struct RowHash<'a> {
    hg: &'a HashG,
    aes: AesEncryptor,
    u: gf64::UMap,
}

impl<'a> RowHash<'a> {
    pub fn new(hg: &'a HashG, rparams: &[u8; 32]) -> RowHash<'a> {
        let (aes, u) = parse_params(rparams);
        RowHash { hg, aes, u }
    }

    #[inline]
    fn tau(stage: usize, idx: usize) -> u64 {
        assert!(stage < 8 && (idx as u64) < (1 << 32), "row tweak out of range");
        ((stage as u64) << 32) | idx as u64
    }

    /// The row hash of one label.
    #[inline]
    pub fn row(&self, x: Block, stage: usize, idx: usize) -> u64 {
        let t = Self::tau(stage, idx);
        let w = self.hg.h(u(x), ROW_TWEAK | t) ^ self.u.at(t);
        u(self.aes.encrypt_block(blk(w))) as u64
    }

    /// The row hashes of both labels of a wire (N).
    #[inline]
    fn row2(&self, x: [Block; 2], stage: usize, idx: usize) -> [u64; 2] {
        let t = Self::tau(stage, idx);
        let h = self.hg.h_many([u(x[0]), u(x[1])], [ROW_TWEAK | t; 2]);
        let ut = self.u.at(t);
        let mut b = [blk(h[0] ^ ut), blk(h[1] ^ ut)];
        self.aes.encrypt_many_blocks(&mut b);
        [u(b[0]) as u64, u(b[1]) as u64]
    }

    /// Test vectors: the intermediate values of [`RowHash::row`].
    #[doc(hidden)]
    pub fn trace(&self, x: Block, stage: usize, idx: usize) -> (u128, u128, u128, u128) {
        let t = Self::tau(stage, idx);
        let inner = self.hg.h(u(x), ROW_TWEAK | t);
        let ut = self.u.at(t);
        let out = u(self.aes.encrypt_block(blk(inner ^ ut)));
        (inner, ut, inner ^ ut, out)
    }
}

#[inline]
fn sel(bit: bool, b: Block) -> Block {
    Block::SELECT_MASK[bit as usize] & b
}

#[inline]
fn m64(bit: bool) -> u64 {
    (bit as u64).wrapping_neg()
}

#[inline]
fn m128(bit: bool) -> u128 {
    (bit as u128).wrapping_neg()
}

#[inline]
fn u(b: Block) -> u128 {
    u128::from_le_bytes(b.to_bytes())
}

#[inline]
fn blk(x: u128) -> Block {
    Block::new(x.to_le_bytes())
}

/// Low 64 bits of a block (the projection used by the check rows).
#[inline]
pub fn lo64(b: Block) -> u64 {
    u(b) as u64
}

/// Overwrites secret blocks (Δ, zero-labels, COT keys and messages, MAC keys)
/// before their memory is released; `Block` has no `Zeroize` impl.
pub fn wipe_blocks(v: &mut [Block]) {
    for b in v {
        b.as_mut().zeroize();
    }
}

/// A `Vec<Block>` of secrets, overwritten when dropped (on every path,
/// errors included), like `Zeroizing` for types that implement `Zeroize`.
#[derive(Default)]
pub struct SecretBlocks(pub Vec<Block>);

impl std::ops::Deref for SecretBlocks {
    type Target = Vec<Block>;
    fn deref(&self) -> &Vec<Block> {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBlocks {
    fn deref_mut(&mut self) -> &mut Vec<Block> {
        &mut self.0
    }
}

impl Drop for SecretBlocks {
    fn drop(&mut self) {
        wipe_blocks(&mut self.0);
    }
}

// ---------------------------------------------------------------------------
// Three-halves garbling (Rosulek–Roy, CRYPTO 2021, eprint 2021/749).
//
// A label is split into halves `L ‖ R` (R = the low 64 bits, which hold the
// colour bit lsb). Free-XOR with global Δ (lsb Δ = 1). Per AND gate the
// garbler sends three half-labels G0, G1, G2 and five control bits z (1.5κ+5
// bits). The evaluator holds A, B with colours s, t and computes
//
//   (hA,bA) = H(A,τ0), (hB,bB) = H(B,τ1), (hX,bX) = H(A⊕B,τ2)   (64-bit half + 1 bit)
//   r0 = z0 ⊕ s·z2 ⊕ (s⊕t)·z4 ⊕ bA ⊕ bX
//   r1 = z1 ⊕ t·z3 ⊕ (s⊕t)·z4 ⊕ bB ⊕ bX
//   R  = r0·S1 ⊕ r1·S2 ⊕ Rp[s][t]                 (2×4 bit matrix on A_L,A_R,B_L,B_R)
//   C_L = s·G0 ⊕ (s⊕t)·G2 ⊕ hA ⊕ hX ⊕ R_0·(A_L,A_R,B_L,B_R)
//   C_R = t·G1 ⊕ (s⊕t)·G2 ⊕ hB ⊕ hX ⊕ R_1·(A_L,A_R,B_L,B_R)
//
// i.e. V_st = [[1,0,s,0,s⊕t],[0,1,0,t,s⊕t]] applied to (hash terms, G). The
// garbler picks two random bits (the "dicing" randomness r$) so that the
// evaluator's R_st is uniform in the coset Rp[s][t] + span(S1, S2), hence
// independent of the colour/permute bits; z2..z4 are padded with the hash bits
// of the inactive labels. The garbler computes, for all four colour pairs,
// T_st = R_st·(A_s, B_t) ⊕ v_st·Δ (v_st = the true AND value) and solves
// the linear system C_st = K0 ⊕ v_st·Δ for (K0, G); the system is consistent
// for this matrix family (checked for every gate in debug builds and over all
// permute/dicing bits in the tests).
// ---------------------------------------------------------------------------

/// One three-halves garbled AND gate: three 64-bit half-ciphertexts and five
/// control bits (bits 0..5 of `z`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate3 {
    pub g: [u64; 3],
    pub z: u8,
}

/// Bytes on the wire for `n` gates: 24 B each, plus the control bits packed
/// 5 per gate.
pub fn tables_len(n: usize) -> usize {
    24 * n + (5 * n).div_ceil(8)
}

pub fn tables_to_bytes(t: &[Gate3]) -> Vec<u8> {
    let n = t.len();
    let mut out = Vec::with_capacity(tables_len(n));
    for g in t {
        for h in g.g {
            out.extend_from_slice(&h.to_le_bytes());
        }
    }
    let mut bits = vec![0u8; (5 * n).div_ceil(8)];
    for (i, g) in t.iter().enumerate() {
        for k in 0..5 {
            if (g.z >> k) & 1 == 1 {
                let b = 5 * i + k;
                bits[b / 8] |= 1 << (b % 8);
            }
        }
    }
    out.extend_from_slice(&bits);
    out
}

pub fn tables_from_bytes(b: &[u8], n: usize) -> Option<Vec<Gate3>> {
    if b.len() != tables_len(n) {
        return None;
    }
    let (gs, bits) = b.split_at(24 * n);
    let mut out = Vec::with_capacity(n);
    for (i, c) in gs.chunks_exact(24).enumerate() {
        let mut z = 0u8;
        for k in 0..5 {
            let bb = 5 * i + k;
            z |= ((bits[bb / 8] >> (bb % 8)) & 1) << k;
        }
        out.push(Gate3 {
            g: [
                u64::from_le_bytes(c[0..8].try_into().unwrap()),
                u64::from_le_bytes(c[8..16].try_into().unwrap()),
                u64::from_le_bytes(c[16..24].try_into().unwrap()),
            ],
            z,
        });
    }
    Some(out)
}

// Rows of R as 4-bit masks over (A_L, A_R, B_L, B_R): bit 0 = A_L, 1 = A_R,
// 2 = B_L, 3 = B_R. Each matrix is (row0, row1).
const S1: (u8, u8) = (0b0111, 0b1001);
const S2: (u8, u8) = (0b1001, 0b1110);
// Rp[s][t] = ((¬s)·B_L, (¬t)·A_R): [[(0b0100, 0b0010), (0b0100, 0)], [(0, 0b0010), (0, 0)]].

/// R_st = r0·S1 ⊕ r1·S2 ⊕ Rp[s][t], by masks: s and t are colour bits, so no
/// table is indexed by them.
#[inline]
fn r_matrix(r0: bool, r1: bool, s: bool, t: bool) -> (u8, u8) {
    let m = |b: bool| (b as u8).wrapping_neg();
    (
        (m(r0) & S1.0) ^ (m(r1) & S2.0) ^ (m(!s) & 0b0100),
        (m(r0) & S1.1) ^ (m(r1) & S2.1) ^ (m(!t) & 0b0010),
    )
}

/// halves (L, R) of a label.
#[inline]
fn halves(x: u128) -> [u64; 2] {
    [(x >> 64) as u64, x as u64]
}

#[inline]
fn apply_row(row: u8, v: &[u64; 4]) -> u64 {
    m64(row & 1 != 0) & v[0] ^ m64(row & 2 != 0) & v[1] ^ m64(row & 4 != 0) & v[2] ^ m64(row & 8 != 0) & v[3]
}

/// Gate tweak `3·gid + slot` (gid = the global AND index; below 2^63, so
/// never a row tweak).
#[inline]
fn tw3(gid: u64, slot: u64) -> u64 {
    assert!(gid < 1 << 61, "gate index out of range");
    gid * 3 + slot
}

/// Hash for three-halves: 64-bit half (low bits) plus one extra bit (bit 127).
#[inline]
fn split_h(x: u128) -> (u64, bool) {
    (x as u64, (x >> 127) & 1 == 1)
}

/// Garbles one AND gate. `a0`, `b0`: zero-labels; returns the output
/// zero-label and the gate. `dice`: two fresh random bits.
#[inline]
pub fn and_garble3(hg: &HashG, a0: Block, b0: Block, delta: Block, gid: u64, dice: [bool; 2]) -> (Block, Gate3) {
    let d = u(delta);
    let (a0, b0) = (u(a0), u(b0));
    let pa = a0 & 1 == 1;
    let pb = b0 & 1 == 1;
    // Colour-0 labels.
    let a_s = a0 ^ (m128(pa) & d);
    let b_s = b0 ^ (m128(pb) & d);
    let x = a_s ^ b_s;
    let t0 = tw3(gid, 0);
    let t1 = tw3(gid, 1);
    let t2 = tw3(gid, 2);
    let h = hg.h_many([a_s, a_s ^ d, b_s, b_s ^ d, x, x ^ d], [t0, t0, t1, t1, t2, t2]);
    let [ha0, ha1, hb0, hb1, hx0, hx1] = h.map(split_h);

    let dh = halves(d);
    // T_st = R_st·(A_s, B_t) ⊕ v_st·Δ  for colours (s, t).
    let t_of = |s: bool, t: bool| -> [u64; 2] {
        let r0 = dice[0] ^ (s & !pa) ^ ((s ^ t) & (pa ^ pb));
        let r1 = dice[1] ^ (t & !pb) ^ ((s ^ t) & (pa ^ pb));
        let (row0, row1) = r_matrix(r0, r1, s, t);
        let ah = halves(a_s ^ (m128(s) & d));
        let bh = halves(b_s ^ (m128(t) & d));
        let v = [ah[0], ah[1], bh[0], bh[1]];
        let val = (s ^ pa) & (t ^ pb);
        [apply_row(row0, &v) ^ (m64(val) & dh[0]), apply_row(row1, &v) ^ (m64(val) & dh[1])]
    };
    let t00 = t_of(false, false);
    let t01 = t_of(false, true);
    let t10 = t_of(true, false);
    let t11 = t_of(true, true);
    let g0 = t00[0] ^ t11[0];
    let g1 = t00[1] ^ t11[1];
    let g2 = t00[0] ^ t01[0];
    // Three-halves identities. Every input is the garbler's own, so a failure
    // is a garbling bug; checked in release too (three compares per gate).
    assert_eq!(g2, t10[0] ^ t11[0]);
    assert_eq!(g2, t00[1] ^ t10[1]);
    assert_eq!(g2, t01[1] ^ t11[1]);
    let _ = t10;

    let k0l = ha0.0 ^ hx0.0 ^ t00[0];
    let k0r = hb0.0 ^ hx0.0 ^ t00[1];
    let k0 = ((k0l as u128) << 64) | k0r as u128;
    let g = [g0 ^ ha0.0 ^ ha1.0, g1 ^ hb0.0 ^ hb1.0, g2 ^ hx0.0 ^ hx1.0];
    let z = [
        dice[0] ^ ha0.1 ^ hx0.1,
        dice[1] ^ hb0.1 ^ hx0.1,
        !pa ^ ha0.1 ^ ha1.1,
        !pb ^ hb0.1 ^ hb1.1,
        (pa ^ pb) ^ hx0.1 ^ hx1.1,
    ];
    let zb = z.iter().enumerate().fold(0u8, |acc, (i, b)| acc | ((*b as u8) << i));
    (blk(k0), Gate3 { g, z: zb })
}

#[inline]
pub fn and_eval3(hg: &HashG, a: Block, b: Block, gate: &Gate3, gid: u64) -> Block {
    let (au, bu) = (u(a), u(b));
    let s = au & 1 == 1;
    let t = bu & 1 == 1;
    let h = hg.h_many([au, bu, au ^ bu], [tw3(gid, 0), tw3(gid, 1), tw3(gid, 2)]);
    let [ha, hb, hx] = h.map(split_h);
    let z = |k: u8| (gate.z >> k) & 1 == 1;
    let r0 = z(0) ^ (s & z(2)) ^ ((s ^ t) & z(4)) ^ ha.1 ^ hx.1;
    let r1 = z(1) ^ (t & z(3)) ^ ((s ^ t) & z(4)) ^ hb.1 ^ hx.1;
    let (row0, row1) = r_matrix(r0, r1, s, t);
    let ah = halves(au);
    let bh = halves(bu);
    let v = [ah[0], ah[1], bh[0], bh[1]];
    let cl = (m64(s) & gate.g[0]) ^ (m64(s ^ t) & gate.g[2]) ^ ha.0 ^ hx.0 ^ apply_row(row0, &v);
    let cr = (m64(t) & gate.g[1]) ^ (m64(s ^ t) & gate.g[2]) ^ hb.0 ^ hx.0 ^ apply_row(row1, &v);
    blk(((cl as u128) << 64) | cr as u128)
}

/// Base wires of a circuit: all circuit inputs, then every AND output in gate
/// order. Every wire's mask / label is an affine function of these.
pub fn base_wires(circ: &Circuit) -> Vec<usize> {
    let mut v: Vec<usize> = circ.inputs().collect();
    for g in circ.gates() {
        if let Gate::And { z, .. } = g {
            v.push(z.id());
        }
    }
    v
}

/// AND gates as (x, y, z) feed ids, in gate order.
pub fn and_gates(circ: &Circuit) -> Vec<(usize, usize, usize)> {
    circ.gates()
        .iter()
        .filter_map(|g| match g {
            Gate::And { x, y, z } => Some((x.id(), y.id(), z.id())),
            _ => None,
        })
        .collect()
}

/// Garbles `circ` (three-halves); returns the zero-label of every feed and the
/// tables. `rng` supplies the per-gate dicing bits. Gate tweaks use the
/// global AND index.
pub fn garble<R: rand::Rng + ?Sized>(
    circ: &Circuit,
    hg: &HashG,
    delta: Block,
    in_keys: &[Block],
    rng: &mut R,
) -> (Vec<Block>, Vec<Gate3>) {
    garble_impl(circ, hg, delta, in_keys, rng, |_| (false, false))
}

/// A garbler that deviates per AND gate (tests): `dev(and index)` returns
/// (shift A's zero-label by Δ: the gate becomes `(¬A)∧B`; complement the
/// output zero-label: the gate becomes a NAND). Every label stays valid.
#[cfg(test)]
pub(crate) fn garble_dev<R: rand::Rng + ?Sized>(
    circ: &Circuit,
    hg: &HashG,
    delta: Block,
    in_keys: &[Block],
    rng: &mut R,
    dev: impl Fn(usize) -> (bool, bool),
) -> (Vec<Block>, Vec<Gate3>) {
    garble_impl(circ, hg, delta, in_keys, rng, dev)
}

#[inline(always)]
fn garble_impl<R: rand::Rng + ?Sized>(
    circ: &Circuit,
    hg: &HashG,
    delta: Block,
    in_keys: &[Block],
    rng: &mut R,
    dev: impl Fn(usize) -> (bool, bool),
) -> (Vec<Block>, Vec<Gate3>) {
    let mut k = vec![Block::ZERO; circ.feed_count()];
    k[..in_keys.len()].copy_from_slice(in_keys);
    let mut tables = Vec::with_capacity(circ.and_count());
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => k[z.id()] = k[x.id()] ^ k[y.id()],
            Gate::And { x, y, z } => {
                let gid = tables.len();
                let (shift_a, flip_out) = dev(gid);
                let r: u8 = rng.random();
                let a0 = k[x.id()] ^ sel(shift_a, delta);
                let (z0, t) = and_garble3(hg, a0, k[y.id()], delta, gid as u64, [r & 1 == 1, r & 2 == 2]);
                k[z.id()] = z0 ^ sel(flip_out, delta);
                tables.push(t);
            }
            Gate::Inv { x, z } => k[z.id()] = k[x.id()] ^ delta,
            Gate::Id { x, z } => k[z.id()] = k[x.id()],
        }
    }
    (k, tables)
}

/// Evaluates; returns the active label of every feed.
pub fn evaluate(circ: &Circuit, hg: &HashG, in_labels: &[Block], tables: &[Gate3]) -> Vec<Block> {
    let mut l = vec![Block::ZERO; circ.feed_count()];
    l[..in_labels.len()].copy_from_slice(in_labels);
    evaluate_range(circ, hg, &mut l, tables, 0..circ.gates().len(), 0);
    l
}

/// Evaluates the gates `gates` (a stage) in place: `l` holds the active label
/// of every feed computed so far, `and_start` is the index of the stage's
/// first AND gate in `tables` (and its gate tweak).
pub fn evaluate_range(
    circ: &Circuit,
    hg: &HashG,
    l: &mut [Block],
    tables: &[Gate3],
    gates: std::ops::Range<usize>,
    and_start: usize,
) {
    let mut a = and_start;
    for g in &circ.gates()[gates] {
        match g {
            Gate::Xor { x, y, z } => l[z.id()] = l[x.id()] ^ l[y.id()],
            Gate::And { x, y, z } => {
                l[z.id()] = and_eval3(hg, l[x.id()], l[y.id()], &tables[a], a as u64);
                a += 1;
            }
            // The evaluator's label does not change under INV (the garbler
            // flips its zero-label instead), so the pointer bit is unchanged.
            Gate::Inv { x, z } | Gate::Id { x, z } => l[z.id()] = l[x.id()],
        }
    }
}

/// One evaluation stage of a circuit: its gates, its AND gates (indices in
/// AND-gate order) and the wires its consistency check has a row for.
#[derive(Debug, Clone)]
pub struct StageShape {
    pub gates: std::ops::Range<usize>,
    pub ands: std::ops::Range<usize>,
    /// The stage's *row wires* (feed ids): first the wires that enter the
    /// stage (circuit inputs and outputs of earlier stages' gates that an AND
    /// input of this stage depends on linearly), then every AND output of the
    /// stage in gate order.
    pub rows: Vec<usize>,
    /// How many of `rows` are entering wires.
    pub entering: usize,
}

/// Splits a circuit into stages ending at `gate_end` (exclusive gate indices,
/// increasing; the last one is the gate count).
///
/// The consistency check of a stage covers exactly the AND gates of that
/// stage. Its relation is linear in the pointer bits of the gates' inputs,
/// and within the stage those are linear in the pointer bits of the row
/// wires. A wire that crosses a stage boundary (`OS_k`) is a row wire of the
/// later stage in its own right, like a circuit input: its mask is committed
/// (a linear combination of base masks, so N holds its MAC and C its key),
/// C holds its active label, and its row is padded by hashes of its two
/// labels. Without this cut the stage would need a row for every base wire of
/// the earlier stages that the crossing wire depends on (most of them).
pub fn stage_shapes(circ: &Circuit, gate_end: &[usize]) -> Vec<StageShape> {
    let gates = circ.gates();
    let mut out = Vec::with_capacity(gate_end.len());
    let (mut g0, mut a0) = (0usize, 0usize);
    // Wires that exist before the current stage starts.
    let mut before = vec![false; circ.feed_count()];
    for w in circ.inputs() {
        before[w] = true;
    }
    for &g1 in gate_end {
        let mut mark = vec![false; circ.feed_count()];
        let mut and_out = Vec::new();
        for g in &gates[g0..g1] {
            if let Gate::And { x, y, z } = g {
                mark[x.id()] = true;
                mark[y.id()] = true;
                and_out.push(z.id());
            }
        }
        for g in gates[g0..g1].iter().rev() {
            match g {
                Gate::Xor { x, y, z } => {
                    if mark[z.id()] {
                        mark[x.id()] = true;
                        mark[y.id()] = true;
                    }
                }
                Gate::Inv { x, z } | Gate::Id { x, z } => {
                    if mark[z.id()] {
                        mark[x.id()] = true;
                    }
                }
                Gate::And { .. } => {}
            }
        }
        let mut rows: Vec<usize> = (0..circ.feed_count()).filter(|&w| mark[w] && before[w]).collect();
        let entering = rows.len();
        let na = and_out.len();
        rows.extend(and_out);
        out.push(StageShape {
            gates: g0..g1,
            ands: a0..a0 + na,
            rows,
            entering,
        });
        for g in &gates[g0..g1] {
            before[g.z().id()] = true;
        }
        g0 = g1;
        a0 += na;
    }
    out
}

/// N: propagates committed masks and their MACs from the base wires to every
/// feed. `base_lam`/`base_mac` are indexed like [`base_wires`].
pub fn propagate_n(circ: &Circuit, base_lam: &[bool], base_mac: &[Block]) -> (Vec<bool>, Vec<Block>) {
    let n_in = circ.inputs().len();
    let mut lam = vec![false; circ.feed_count()];
    let mut mac = vec![Block::ZERO; circ.feed_count()];
    lam[..n_in].copy_from_slice(&base_lam[..n_in]);
    mac[..n_in].copy_from_slice(&base_mac[..n_in]);
    let mut a = n_in;
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => {
                lam[z.id()] = lam[x.id()] ^ lam[y.id()];
                mac[z.id()] = mac[x.id()] ^ mac[y.id()];
            }
            Gate::And { z, .. } => {
                lam[z.id()] = base_lam[a];
                mac[z.id()] = base_mac[a];
                a += 1;
            }
            Gate::Inv { x, z } => {
                lam[z.id()] = !lam[x.id()];
                mac[z.id()] = mac[x.id()];
            }
            Gate::Id { x, z } => {
                lam[z.id()] = lam[x.id()];
                mac[z.id()] = mac[x.id()];
            }
        }
    }
    (lam, mac)
}

/// C: propagates the keys of the committed masks to every feed.
pub fn propagate_c(circ: &Circuit, base_key: &[Block], delta_b: Block) -> Vec<Block> {
    let n_in = circ.inputs().len();
    let mut key = vec![Block::ZERO; circ.feed_count()];
    key[..n_in].copy_from_slice(&base_key[..n_in]);
    let mut a = n_in;
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => key[z.id()] = key[x.id()] ^ key[y.id()],
            Gate::And { z, .. } => {
                key[z.id()] = base_key[a];
                a += 1;
            }
            Gate::Inv { x, z } => key[z.id()] = key[x.id()] ^ delta_b,
            Gate::Id { x, z } => key[z.id()] = key[x.id()],
        }
    }
    key
}

/// Powers χ, χ², … (one per AND gate).
pub fn powers(chi: Block, n: usize) -> Vec<Block> {
    let mut v = Vec::with_capacity(n);
    let mut p = chi;
    for _ in 0..n {
        v.push(p);
        p = p.gfmul(chi);
    }
    v
}

/// Product check, prover side (N): accumulates Σ χ^k A0_k and Σ χ^k A1_k for
/// the triples (λ_i, λ_j, t_k), `A0 = M_i·M_j`, `A1 = M_i·λ_j ⊕ M_j·λ_i ⊕ M_t`.
pub fn dvzk_prover_acc(
    ands: &[(usize, usize, usize)],
    lam: &[bool],
    mac: &[Block],
    t_mac: &[Block],
    pw: &[Block],
    acc: &mut (Block, Block),
) {
    for (k, &(i, j, _)) in ands.iter().enumerate() {
        let a0 = mac[i].gfmul(mac[j]);
        let a1 = sel(lam[j], mac[i]) ^ sel(lam[i], mac[j]) ^ t_mac[k];
        acc.0 ^= pw[k].gfmul(a0);
        acc.1 ^= pw[k].gfmul(a1);
    }
}

/// Product check, verifier side (C): Σ χ^k (K_i·K_j ⊕ K_t·Δ_B).
pub fn dvzk_verifier_acc(
    ands: &[(usize, usize, usize)],
    key: &[Block],
    t_key: &[Block],
    delta_b: Block,
    pw: &[Block],
    acc: &mut Block,
) {
    for (k, &(i, j, _)) in ands.iter().enumerate() {
        let b = key[i].gfmul(key[j]) ^ t_key[k].gfmul(delta_b);
        *acc ^= pw[k].gfmul(b);
    }
}

/// N's consistency-check material for one stage: `ands`, `t_mac` and `pw` are
/// the stage's AND gates, `base` its row wires ([`StageShape::rows`]), `gates`
/// the stage's gates, and `stage` the stage index (it separates the row-hash
/// tweaks of the stages).
///
/// For AND gate k = (i, j → o) the relation to check is
/// `e_k = λ_o ⊕ t_k ⊕ Λ_i·λ_j ⊕ Λ_j·λ_i ⊕ (Λ_o ⊕ Λ_i·Λ_j) = 0`. Under the MACs,
/// `Σ χ^k (M_o ⊕ M_t ⊕ Λ_i M_j ⊕ Λ_j M_i) = K_tot` iff every e_k = 0 (except
/// with probability ~2^-128), where C computes K_tot from its keys and the Λ
/// it observed. N does not know the Λ, so it splits the left side into
/// `A_N = Σ χ^k (M_o ⊕ M_t)` and `Σ_w Λ_w X_w`, pushes the X of every XOR /
/// INV / ID wire onto the base wires (Λ is linear in the base Λ), and for each
/// base wire b sends `T_b = H(P_{b,0}) ⊕ H(P_{b,1}) ⊕ X_b`; the evaluator gets
/// `H(P_{b,0}) ⊕ Λ_b X_b` from its active label. `Y_N = A_N ⊕ Σ_b H(P_{b,0})`.
///
/// Rows and `Y_N` are sent projected to their low 64 bits (`lo64`, a
/// GF(2)-linear map π: GF(2^128) → GF(2)^64); C compares
/// `π(Y_N ⊕ Y_C ⊕ K_tot) = 0`. The MACs, Δ_B, χ and the whole computation stay
/// in GF(2^128), only the comparison is projected: a wrong evaluation
/// (E ≠ 0) passes iff π(Δ_B·E) = π(R) for an R fixed before Δ_B is used, which
/// has probability ≤ 2^-63 over Δ_B (127 uniform bits: lsb Δ_B = 1, so the
/// image of the admissible Δ_B under Δ ↦ π(Δ·E) has dimension 64, giving
/// 2^-64, or 63 for the ~2^-64 fraction of E whose kernel lies in lsb = 0)
/// and cannot be ground offline because N never learns anything about Δ_B.
pub struct CheckMaterial {
    pub rows: Vec<u64>,
    pub y_n: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn check_material(
    circ: &Circuit,
    gates: std::ops::Range<usize>,
    rh: &RowHash,
    stage: usize,
    ands: &[(usize, usize, usize)],
    base: &[usize],
    k: &[Block],
    lam: &[bool],
    mac: &[Block],
    t_mac: &[Block],
    pw: &[Block],
    delta_a: Block,
) -> CheckMaterial {
    // X per wire. A stage touches the outputs of its own gates (a contiguous
    // range of feed ids, since ids follow gate order) and the few wires that
    // enter it, so X is kept for that range plus a small map, not for the
    // whole circuit (which would be 46 MB per stage).
    let stage_gates = &circ.gates()[gates];
    let lo = stage_gates.iter().map(|g| g.z().id()).min().unwrap_or(0);
    let hi = stage_gates.iter().map(|g| g.z().id() + 1).max().unwrap_or(0);
    let mut x = StageX {
        lo,
        own: vec![Block::ZERO; hi - lo],
        entering: Default::default(),
    };
    let mut a_n = Block::ZERO;
    for (kk, &(i, j, o)) in ands.iter().enumerate() {
        let c = pw[kk];
        a_n ^= c.gfmul(mac[o] ^ t_mac[kk]);
        *x.at(i) ^= c.gfmul(mac[j]);
        *x.at(j) ^= c.gfmul(mac[i]);
    }
    for g in stage_gates.iter().rev() {
        match g {
            Gate::Xor { x: a, y: b, z } => {
                let v = x.get(z.id());
                *x.at(a.id()) ^= v;
                *x.at(b.id()) ^= v;
            }
            Gate::Inv { x: a, z } | Gate::Id { x: a, z } => {
                let v = x.get(z.id());
                *x.at(a.id()) ^= v;
            }
            Gate::And { .. } => {}
        }
    }
    let mut rows = Vec::with_capacity(base.len());
    let mut y_n = lo64(a_n);
    for (idx, &b) in base.iter().enumerate() {
        let p0 = k[b] ^ sel(lam[b], delta_a);
        let [h0, h1] = rh.row2([p0, p0 ^ delta_a], stage, idx);
        rows.push(h0 ^ h1 ^ lo64(x.get(b)));
        y_n ^= h0;
    }
    CheckMaterial { rows, y_n }
}

/// The values X_w of one stage's check material, by feed id.
struct StageX {
    lo: usize,
    /// Feeds `lo..lo + own.len()`: the outputs of the stage's gates.
    own: Vec<Block>,
    /// Every other feed the stage reads (circuit inputs, crossing wires).
    entering: std::collections::HashMap<usize, Block, std::hash::BuildHasherDefault<IdHasher>>,
}

/// Hasher for feed ids (the map is hit once per gate that reads an entering
/// wire; ids are not attacker-chosen).
#[derive(Default)]
struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ *b as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    fn write_usize(&mut self, i: usize) {
        self.0 = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

impl StageX {
    #[inline]
    fn at(&mut self, id: usize) -> &mut Block {
        if id >= self.lo && id - self.lo < self.own.len() {
            &mut self.own[id - self.lo]
        } else {
            self.entering.entry(id).or_insert(Block::ZERO)
        }
    }
    #[inline]
    fn get(&self, id: usize) -> Block {
        if id >= self.lo && id - self.lo < self.own.len() {
            self.own[id - self.lo]
        } else {
            self.entering.get(&id).copied().unwrap_or(Block::ZERO)
        }
    }
}

impl Drop for StageX {
    fn drop(&mut self) {
        // Sums of χ^k·M: N's MACs.
        wipe_blocks(&mut self.own);
        for v in self.entering.values_mut() {
            v.as_mut().zeroize();
        }
    }
}

/// C's preprocessed key material for the check of one stage:
/// `static = Σ χ^k (K_o ⊕ K_t)`, and per gate `(χ^k, χ^k K_j, χ^k K_i)` so
/// that the online part is XORs plus one multiplication.
pub struct CheckKeys {
    pub stat: Block,
    pub per_gate: Vec<[Block; 3]>,
}

pub fn check_keys(ands: &[(usize, usize, usize)], key: &[Block], t_key: &[Block], pw: &[Block]) -> CheckKeys {
    let mut stat = Block::ZERO;
    let mut per_gate = Vec::with_capacity(ands.len());
    for (kk, &(i, j, o)) in ands.iter().enumerate() {
        let c = pw[kk];
        stat ^= c.gfmul(key[o] ^ t_key[kk]);
        per_gate.push([c, c.gfmul(key[j]), c.gfmul(key[i])]);
    }
    CheckKeys { stat, per_gate }
}

impl Drop for CheckKeys {
    fn drop(&mut self) {
        // χ^k·K: C's MAC keys (with N's MACs they would give Δ_B).
        self.stat.as_mut().zeroize();
        for g in self.per_gate.iter_mut() {
            wipe_blocks(g);
        }
    }
}

/// C, online: runs the consistency check over the active labels `l`.
/// Returns true iff `Y_N ⊕ Y_C = K_tot`.
pub fn run_check(
    rh: &RowHash,
    stage: usize,
    ands: &[(usize, usize, usize)],
    base: &[usize],
    l: &[Block],
    ck: &CheckKeys,
    rows: &[u64],
    y_n: u64,
    delta_b: Block,
) -> bool {
    let mut k_tot = ck.stat;
    let mut c_sum = Block::ZERO;
    for (kk, &(i, j, o)) in ands.iter().enumerate() {
        let (li, lj, lo) = (l[i].lsb(), l[j].lsb(), l[o].lsb());
        let [c, cj, ci] = ck.per_gate[kk];
        k_tot ^= sel(li, cj) ^ sel(lj, ci);
        c_sum ^= sel(lo ^ (li & lj), c);
    }
    k_tot ^= c_sum.gfmul(delta_b);
    let mut y_c = 0u64;
    for (idx, &b) in base.iter().enumerate() {
        let lb = l[b];
        y_c ^= rh.row(lb, stage, idx) ^ (m64(lb.lsb()) & rows[idx]);
    }
    (y_n ^ y_c) == lo64(k_tot)
}
