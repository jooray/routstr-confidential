//! Garbler-only authenticated garbling: the primitives.
//!
//! * Half-gates garbling / evaluation (Zahur–Rosulek–Evans 2015, the same
//!   construction and fixed-key-AES TCCR hash as mpz2 `garble-core`), but
//!   keeping every wire's zero-label (garbler) and every active label
//!   (evaluator), which the consistency check needs.
//! * IT-MAC bookkeeping over GF(2^128): the garbler N holds authenticated bits
//!   `[x] = (x, M[x])`, the evaluator C holds `(K[x], Δ_B)` with
//!   `M[x] = K[x] ⊕ x·Δ_B`. Wire masks `λ_w` (= the point-and-permute bit of
//!   N's zero-label) are authenticated for every circuit input and every AND
//!   output; every other wire follows by linearity (XOR: sum, INV: `λ ⊕ 1`,
//!   i.e. `K ⊕ Δ_B` on C's side).
//! * The per-AND products `t_k = λ_i·λ_j` (QuickSilver-style batched check).
//! * The consistency check of the evaluation (one ciphertext per base wire).
//!
//! Notation: `P_{w,Λ}` is the label of wire w whose pointer bit is Λ:
//! `P_{w,Λ} = k_w ⊕ (Λ ⊕ λ_w)·Δ_A` (k_w = label of the value 0). The evaluator
//! holds `P_{w,Λ_w}` with `Λ_w = z_w ⊕ λ_w` (z_w = the true wire value).

use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;
use mpz_core::aes::{FIXED_KEY_AES, FixedKeyAes};

/// Tweak base of the garbling hash for a phase (garbling and check rows use
/// disjoint tweak spaces).
fn gid_base(phase: usize) -> u128 {
    (phase as u128) << 64
}

fn check_tweak(phase: usize, idx: usize) -> Block {
    Block::new(((1u128 << 127) | ((phase as u128) << 64) | idx as u128).to_be_bytes())
}

#[inline]
fn sel(bit: bool, b: Block) -> Block {
    Block::SELECT_MASK[bit as usize] & b
}

#[inline]
fn and_garble(c: &FixedKeyAes, x0: Block, y0: Block, delta: Block, gid: u128) -> (Block, [Block; 2]) {
    let x1 = x0 ^ delta;
    let y1 = y0 ^ delta;
    let pa = x0.lsb();
    let pb = y0.lsb();
    let j = Block::new(gid.to_be_bytes());
    let k = Block::new((gid + 1).to_be_bytes());
    let mut h = [x0, y0, x1, y1];
    c.tccr_many(&[j, k, j, k], &mut h);
    let [hx0, hy0, hx1, hy1] = h;
    let tg = hx0 ^ hx1 ^ sel(pb, delta);
    let wg = hx0 ^ sel(pa, tg);
    let te = hy0 ^ hy1 ^ x0;
    let we = hy0 ^ sel(pb, te ^ x0);
    (wg ^ we, [tg, te])
}

#[inline]
fn and_eval(c: &FixedKeyAes, x: Block, y: Block, t: &[Block; 2], gid: u128) -> Block {
    let j = Block::new(gid.to_be_bytes());
    let k = Block::new((gid + 1).to_be_bytes());
    let mut h = [x, y];
    c.tccr_many(&[j, k], &mut h);
    let [hx, hy] = h;
    let wg = hx ^ sel(x.lsb(), t[0]);
    let we = hy ^ sel(y.lsb(), t[1] ^ x);
    wg ^ we
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

/// Garbles `circ`; returns the zero-label of every feed and the tables.
pub fn garble(circ: &Circuit, delta: Block, in_keys: &[Block], phase: usize) -> (Vec<Block>, Vec<[Block; 2]>) {
    let cipher = &*FIXED_KEY_AES;
    let mut k = vec![Block::ZERO; circ.feed_count()];
    k[..in_keys.len()].copy_from_slice(in_keys);
    let mut tables = Vec::with_capacity(circ.and_count());
    let base = gid_base(phase);
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => k[z.id()] = k[x.id()] ^ k[y.id()],
            Gate::And { x, y, z } => {
                let gid = base + 2 * tables.len() as u128 + 1;
                let (z0, t) = and_garble(cipher, k[x.id()], k[y.id()], delta, gid);
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
pub fn evaluate(circ: &Circuit, in_labels: &[Block], tables: &[[Block; 2]], phase: usize) -> Vec<Block> {
    let cipher = &*FIXED_KEY_AES;
    let mut l = vec![Block::ZERO; circ.feed_count()];
    l[..in_labels.len()].copy_from_slice(in_labels);
    let base = gid_base(phase);
    let mut a = 0usize;
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => l[z.id()] = l[x.id()] ^ l[y.id()],
            Gate::And { x, y, z } => {
                let gid = base + 2 * a as u128 + 1;
                l[z.id()] = and_eval(cipher, l[x.id()], l[y.id()], &tables[a], gid);
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
pub struct CheckMaterial {
    pub rows: Vec<Block>,
    pub y_n: Block,
}

#[allow(clippy::too_many_arguments)]
pub fn check_material(
    circ: &Circuit,
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
        let tw = check_tweak(phase, idx);
        let h0 = cipher.tccr(tw, p0);
        let h1 = cipher.tccr(tw, p0 ^ delta_a);
        rows.push(h0 ^ h1 ^ x[b]);
        y_n ^= h0;
    }
    CheckMaterial { rows, y_n }
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

/// C, online: runs the consistency check over the active labels `l`.
/// Returns true iff `Y_N ⊕ Y_C = K_tot`.
pub fn run_check(
    phase: usize,
    ands: &[(usize, usize, usize)],
    base: &[usize],
    l: &[Block],
    ck: &CheckKeys,
    rows: &[Block],
    y_n: Block,
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
    let mut y_c = Block::ZERO;
    for (idx, &b) in base.iter().enumerate() {
        let lb = l[b];
        y_c ^= cipher.tccr(check_tweak(phase, idx), lb) ^ sel(lb.lsb(), rows[idx]);
    }
    (y_n ^ y_c) == k_tot
}
