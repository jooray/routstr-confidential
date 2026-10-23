//! Garbler-only authenticated garbling: the primitives.
//!
//! * Three-halves garbling / evaluation (Rosulek–Roy 2021; 1.5κ+5 bits per
//!   AND, free XOR, fixed-key-AES TCCR hash as in mpz2), keeping every wire's
//!   zero-label (garbler) and every active label (evaluator), which the
//!   consistency check needs.
//! * IT-MAC bookkeeping over GF(2^128): the garbler N holds authenticated bits
//!   `[x] = (x, M[x])`, the evaluator C holds `(K[x], Δ_B)` with
//!   `M[x] = K[x] ⊕ x·Δ_B`. Wire masks `λ_w` (= the point-and-permute bit of
//!   N's zero-label) are authenticated for every circuit input and every AND
//!   output; every other wire follows by linearity (XOR: sum, INV: `λ ⊕ 1`,
//!   i.e. `K ⊕ Δ_B` on C's side).
//! * The per-AND products `t_k = λ_i·λ_j` (QuickSilver-style batched check).
//! * The consistency check of the evaluation (one 64-bit row per base wire,
//!   hashed under a per-session salt).
//!
//! Notation: `P_{w,Λ}` is the label of wire w whose pointer bit is Λ:
//! `P_{w,Λ} = k_w ⊕ (Λ ⊕ λ_w)·Δ_A` (k_w = label of the value 0). The evaluator
//! holds `P_{w,Λ_w}` with `Λ_w = z_w ⊕ λ_w` (z_w = the true wire value).

use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;
use mpz_core::aes::{FIXED_KEY_AES, FixedKeyAes};
use rand::RngExt;
use zeroize::Zeroize;

/// Tweak base of the garbling hash for a phase (garbling and check rows use
/// disjoint tweak spaces: bit 127 is set only for check rows).
fn gid_base(phase: usize) -> u128 {
    (phase as u128) << 64
}

/// Tweak of the check-row hash of base wire `idx`: a per-session salt (from
/// C's challenge seed, revealed only after N's tables and commitments) XOR the
/// wire position, with bit 127 forced to 1 so it never equals a garbling
/// tweak (those stay below 2^67). The salt is what makes 64-bit rows safe: any
/// label deviation N fixed before the seed (tables, Δ_A, its keys) changes the
/// projected check sum by a fresh-looking 64-bit value, so N cannot precompute
/// a garbage label whose truncated hash matches the honest one, even if it
/// reuses its labels across sessions.
fn check_tweak(salt: u128, phase: usize, idx: usize) -> Block {
    blk((salt | (1u128 << 127)) ^ (((phase as u128) << 64) | idx as u128))
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
const RP: [[(u8, u8); 2]; 2] = [[(0b0100, 0b0010), (0b0100, 0)], [(0, 0b0010), (0, 0)]];

#[inline]
fn r_matrix(r0: bool, r1: bool, s: bool, t: bool) -> (u8, u8) {
    let m = |b: bool| if b { 0xffu8 } else { 0 };
    let rp = RP[s as usize][t as usize];
    (
        (m(r0) & S1.0) ^ (m(r1) & S2.0) ^ rp.0,
        (m(r0) & S1.1) ^ (m(r1) & S2.1) ^ rp.1,
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

#[inline]
fn tw3(gid: u128, slot: u128) -> Block {
    blk(gid * 3 + slot)
}

/// Hash for three-halves: TCCR, 64-bit half (low bits) plus one extra bit (bit 127).
#[inline]
fn split_h(h: Block) -> (u64, bool) {
    let x = u(h);
    (x as u64, (x >> 127) & 1 == 1)
}

/// Garbles one AND gate. `a0`, `b0`: zero-labels; returns the output
/// zero-label and the gate. `dice`: two fresh random bits.
#[inline]
pub fn and_garble3(c: &FixedKeyAes, a0: Block, b0: Block, delta: Block, gid: u128, dice: [bool; 2]) -> (Block, Gate3) {
    let d = u(delta);
    let (a0, b0) = (u(a0), u(b0));
    let pa = a0 & 1 == 1;
    let pb = b0 & 1 == 1;
    // Colour-0 labels.
    let a_s = a0 ^ if pa { d } else { 0 };
    let b_s = b0 ^ if pb { d } else { 0 };
    let x = a_s ^ b_s;
    let t0 = tw3(gid, 0);
    let t1 = tw3(gid, 1);
    let t2 = tw3(gid, 2);
    let mut h = [blk(a_s), blk(a_s ^ d), blk(b_s), blk(b_s ^ d), blk(x), blk(x ^ d)];
    c.tccr_many(&[t0, t0, t1, t1, t2, t2], &mut h);
    let [ha0, ha1, hb0, hb1, hx0, hx1] = h.map(split_h);

    let dh = halves(d);
    // T_st = R_st·(A_s, B_t) ⊕ v_st·Δ  for colours (s, t).
    let t_of = |s: bool, t: bool| -> [u64; 2] {
        let r0 = dice[0] ^ (s & !pa) ^ ((s ^ t) & (pa ^ pb));
        let r1 = dice[1] ^ (t & !pb) ^ ((s ^ t) & (pa ^ pb));
        let (row0, row1) = r_matrix(r0, r1, s, t);
        let ah = halves(a_s ^ if s { d } else { 0 });
        let bh = halves(b_s ^ if t { d } else { 0 });
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
pub fn and_eval3(c: &FixedKeyAes, a: Block, b: Block, gate: &Gate3, gid: u128) -> Block {
    let (au, bu) = (u(a), u(b));
    let s = au & 1 == 1;
    let t = bu & 1 == 1;
    let mut h = [a, b, blk(au ^ bu)];
    c.tccr_many(&[tw3(gid, 0), tw3(gid, 1), tw3(gid, 2)], &mut h);
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
/// tables. `rng` supplies the per-gate dicing bits.
pub fn garble<R: rand::Rng + ?Sized>(
    circ: &Circuit,
    delta: Block,
    in_keys: &[Block],
    phase: usize,
    rng: &mut R,
) -> (Vec<Block>, Vec<Gate3>) {
    let cipher = &*FIXED_KEY_AES;
    let mut k = vec![Block::ZERO; circ.feed_count()];
    k[..in_keys.len()].copy_from_slice(in_keys);
    let mut tables = Vec::with_capacity(circ.and_count());
    let base = gid_base(phase);
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => k[z.id()] = k[x.id()] ^ k[y.id()],
            Gate::And { x, y, z } => {
                let gid = base + tables.len() as u128;
                let r: u8 = rng.random();
                let (z0, t) = and_garble3(cipher, k[x.id()], k[y.id()], delta, gid, [r & 1 == 1, r & 2 == 2]);
                k[z.id()] = z0;
                tables.push(t);
            }
            Gate::Inv { x, z } => k[z.id()] = k[x.id()] ^ delta,
            Gate::Id { x, z } => k[z.id()] = k[x.id()],
        }
    }
    (k, tables)
}

/// Evaluates; returns the active label of every feed.
pub fn evaluate(circ: &Circuit, in_labels: &[Block], tables: &[Gate3], phase: usize) -> Vec<Block> {
    let cipher = &*FIXED_KEY_AES;
    let mut l = vec![Block::ZERO; circ.feed_count()];
    l[..in_labels.len()].copy_from_slice(in_labels);
    let base = gid_base(phase);
    let mut a = 0usize;
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => l[z.id()] = l[x.id()] ^ l[y.id()],
            Gate::And { x, y, z } => {
                let gid = base + a as u128;
                l[z.id()] = and_eval3(cipher, l[x.id()], l[y.id()], &tables[a], gid);
                a += 1;
            }
            // The evaluator's label does not change under INV (the garbler
            // flips its zero-label instead), so the pointer bit is unchanged.
            Gate::Inv { x, z } | Gate::Id { x, z } => l[z.id()] = l[x.id()],
        }
    }
    l
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

/// N's consistency-check material for one phase.
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
    salt: u128,
    phase: usize,
    ands: &[(usize, usize, usize)],
    base: &[usize],
    k: &[Block],
    lam: &[bool],
    mac: &[Block],
    t_mac: &[Block],
    pw: &[Block],
    delta_a: Block,
) -> CheckMaterial {
    let mut x = vec![Block::ZERO; circ.feed_count()];
    let mut a_n = Block::ZERO;
    for (kk, &(i, j, o)) in ands.iter().enumerate() {
        let c = pw[kk];
        a_n ^= c.gfmul(mac[o] ^ t_mac[kk]);
        x[i] ^= c.gfmul(mac[j]);
        x[j] ^= c.gfmul(mac[i]);
    }
    for g in circ.gates().iter().rev() {
        match g {
            Gate::Xor { x: a, y: b, z } => {
                let v = x[z.id()];
                x[a.id()] ^= v;
                x[b.id()] ^= v;
            }
            Gate::Inv { x: a, z } | Gate::Id { x: a, z } => {
                let v = x[z.id()];
                x[a.id()] ^= v;
            }
            Gate::And { .. } => {}
        }
    }
    let cipher = &*FIXED_KEY_AES;
    let mut rows = Vec::with_capacity(base.len());
    let mut y_n = a_n;
    for (idx, &b) in base.iter().enumerate() {
        let p0 = k[b] ^ sel(lam[b], delta_a);
        let tw = check_tweak(salt, phase, idx);
        let h0 = cipher.tccr(tw, p0);
        let h1 = cipher.tccr(tw, p0 ^ delta_a);
        rows.push(lo64(h0 ^ h1 ^ x[b]));
        y_n ^= h0;
    }
    CheckMaterial { rows, y_n: lo64(y_n) }
}

/// C's preprocessed key material for the check of one phase:
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
    salt: u128,
    phase: usize,
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
    let cipher = &*FIXED_KEY_AES;
    let mut y_c = 0u64;
    for (idx, &b) in base.iter().enumerate() {
        let lb = l[b];
        y_c ^= lo64(cipher.tccr(check_tweak(salt, phase, idx), lb)) ^ (m64(lb.lsb()) & rows[idx]);
    }
    (y_n ^ y_c) == lo64(k_tot)
}
