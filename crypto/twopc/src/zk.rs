//! Zero-knowledge proofs of circuit evaluations over IT-MAC commitments
//! (QuickSilver-style, GF(2^128)), built on the product check of [`crate::gc`]
//! (`dvzk_prover_acc` / `dvzk_verifier_acc`).
//!
//! A committed bit `x` is `(x, M)` on the prover's side and `K` on the
//! verifier's, with `M = K ⊕ x·Δ` (Δ = the verifier's key, lsb 1). A public
//! bit is the commitment `M = 0`, `K = x·Δ`. XOR, INV and AND with a public
//! bit are local. An AND of two committed bits takes one random COT
//! `(r, M_r = K_r ⊕ r·Δ)`: the prover sends `d = z ⊕ r` and the output is
//! `(z, M_r)`, `K_r ⊕ d·Δ`. All ANDs of a statement are then checked at once:
//! with `A0 = M_i·M_j`, `A1 = z_j·M_i ⊕ z_i·M_j ⊕ M_o` and `B = K_i·K_j ⊕
//! K_o·Δ` we have `B = A0 ⊕ A1·Δ ⊕ (z_i·z_j ⊕ z_o)·Δ²`, so the prover sends
//! `U = Σχ^k·A0_k ⊕ M*`, `V = Σχ^k·A1_k ⊕ a*` (masked by a random committed
//! field element `a*`, 128 more COTs) and the verifier accepts iff
//! `Σχ^k·B_k ⊕ K* = U ⊕ V·Δ`.
//!
//! The challenge χ is derived by hashing (Fiat–Shamir) the statement and
//! every correction bit the prover sent. A prover that cheats on some gate
//! passes only if it hits a root of a non-zero polynomial of degree ≤ 2 in Δ
//! (2^-127 per attempt, the session dies on a failure) or if the hash gives a
//! χ with `Σχ^k·e_k = 0` (probability ≤ n/2^128 per hash evaluation, so about
//! 2^128/n work).
//!
//! Which wires are public is structural (it depends on which inputs are
//! public, not on their values), so both parties count the same gates.

use mpz_circuits::{Circuit, Gate, SHA256_COMPRESS};
use mpz_core::Block;

use crate::gc::{self, SecretBlocks};

#[inline]
fn sel(bit: bool, b: Block) -> Block {
    Block::SELECT_MASK[bit as usize] & b
}

/// The prover's view of a wire.
#[derive(Clone, Copy, Debug)]
pub struct PW {
    pub public: bool,
    pub v: bool,
    pub m: Block,
}

impl PW {
    pub fn public(v: bool) -> Self {
        PW {
            public: true,
            v,
            m: Block::ZERO,
        }
    }
    pub fn secret(v: bool, m: Block) -> Self {
        PW { public: false, v, m }
    }
}

/// The verifier's view of a wire (`v` is meaningful only for public wires).
#[derive(Clone, Copy, Debug)]
pub struct VW {
    pub public: bool,
    pub v: bool,
    pub k: Block,
}

impl VW {
    pub fn public(v: bool, delta: Block) -> Self {
        VW {
            public: true,
            v,
            k: sel(v, delta),
        }
    }
    pub fn secret(k: Block) -> Self {
        VW {
            public: false,
            v: false,
            k,
        }
    }
}

/// Number of COT-consuming AND gates when the inputs flagged in `public_in`
/// are public.
pub fn and_count(circ: &Circuit, public_in: &[bool]) -> usize {
    let mut p = vec![true; circ.feed_count()];
    p[..public_in.len()].copy_from_slice(public_in);
    let mut n = 0;
    for g in circ.gates() {
        match g {
            Gate::Xor { x, y, z } => p[z.id()] = p[x.id()] && p[y.id()],
            Gate::Inv { x, z } | Gate::Id { x, z } => p[z.id()] = p[x.id()],
            Gate::And { x, y, z } => {
                let (a, b) = (p[x.id()], p[y.id()]);
                if !a && !b {
                    n += 1;
                }
                p[z.id()] = a && b;
            }
        }
    }
    n
}

/// Inputs of `SHA256_COMPRESS`: the block (512 wires, byte order) then the
/// state (8 words).
pub fn compress_inputs<T: Copy>(state: &[T], block: &[T]) -> Vec<T> {
    assert_eq!((state.len(), block.len()), (256, 512));
    let mut v = Vec::with_capacity(768);
    v.extend_from_slice(block);
    v.extend_from_slice(state);
    v
}

/// AND gates of one compression with a committed state and a public block.
pub fn compress_ands_secret_state() -> usize {
    let mut p = vec![true; 512];
    p.extend(std::iter::repeat_n(false, 256));
    and_count(&SHA256_COMPRESS, &p)
}

/// AND gates of one compression from the public IV over a block whose first
/// `secret_bits` wires are committed.
pub fn compress_ands_secret_prefix(secret_bits: usize) -> usize {
    let mut p = vec![true; 768];
    p[..secret_bits].fill(false);
    and_count(&SHA256_COMPRESS, &p)
}

pub struct Prover<'a> {
    r: &'a [bool],
    mr: &'a [Block],
    n: usize,
    d: Vec<bool>,
    /// Per AND gate k: inputs at 2k, 2k+1 (the layout `gc::dvzk_*` expects).
    val: Vec<bool>,
    mac: SecretBlocks,
    t_mac: SecretBlocks,
}

impl<'a> Prover<'a> {
    /// `r`, `mr`: random COTs for the AND gates, then 128 for the mask.
    pub fn new(r: &'a [bool], mr: &'a [Block]) -> Self {
        assert_eq!(r.len(), mr.len());
        assert!(r.len() >= 128);
        Prover {
            r,
            mr,
            n: 0,
            d: Vec::new(),
            val: Vec::new(),
            mac: SecretBlocks::default(),
            t_mac: SecretBlocks::default(),
        }
    }

    pub fn eval(&mut self, circ: &Circuit, inputs: &[PW]) -> Vec<PW> {
        assert_eq!(inputs.len(), circ.inputs().len());
        let mut w = vec![PW::public(false); circ.feed_count()];
        w[..inputs.len()].copy_from_slice(inputs);
        for g in circ.gates() {
            match g {
                Gate::Xor { x, y, z } => {
                    let (a, b) = (w[x.id()], w[y.id()]);
                    w[z.id()] = PW {
                        public: a.public && b.public,
                        v: a.v ^ b.v,
                        m: a.m ^ b.m,
                    };
                }
                Gate::Inv { x, z } => {
                    let a = w[x.id()];
                    w[z.id()] = PW { v: !a.v, ..a };
                }
                Gate::Id { x, z } => w[z.id()] = w[x.id()],
                Gate::And { x, y, z } => {
                    let (a, b) = (w[x.id()], w[y.id()]);
                    w[z.id()] = match (a.public, b.public) {
                        (true, true) => PW::public(a.v & b.v),
                        (true, false) => PW::secret(a.v & b.v, sel(a.v, b.m)),
                        (false, true) => PW::secret(a.v & b.v, sel(b.v, a.m)),
                        (false, false) => {
                            let i = self.n;
                            assert!(i + 128 < self.r.len(), "COTs for the proof");
                            let v = a.v & b.v;
                            self.d.push(v ^ self.r[i]);
                            self.val.push(a.v);
                            self.val.push(b.v);
                            self.mac.push(a.m);
                            self.mac.push(b.m);
                            self.t_mac.push(self.mr[i]);
                            self.n += 1;
                            PW::secret(v, self.mr[i])
                        }
                    };
                }
            }
        }
        let out = circ.outputs().map(|i| w[i]).collect();
        for x in w.iter_mut() {
            x.m = Block::ZERO;
        }
        out
    }

    /// One SHA-256 compression; returns the new state (word order).
    pub fn compress(&mut self, state: &[PW], block: &[PW]) -> Vec<PW> {
        self.eval(&SHA256_COMPRESS, &compress_inputs(state, block))
    }

    /// Correction bits sent so far (they go into the challenge).
    pub fn d_bytes(&self) -> Vec<u8> {
        crate::circuits::from_bits(&self.d)
    }

    /// Finishes the statement: `chi` must be derived from [`Self::d_bytes`]
    /// and the statement. Returns `(U, V)`.
    pub fn finish(self, chi: Block) -> (Block, Block) {
        let n = self.n;
        assert_eq!(n + 128, self.r.len(), "the statement uses every COT");
        let pw = gc::powers(chi, n);
        let ands: Vec<(usize, usize, usize)> = (0..n).map(|k| (2 * k, 2 * k + 1, 0)).collect();
        let mut acc = (Block::ZERO, Block::ZERO);
        gc::dvzk_prover_acc(&ands, &self.val, &self.mac, &self.t_mac, &pw, &mut acc);
        let mut a_star = Block::ZERO;
        let mut m_star = Block::ZERO;
        for i in 0..128 {
            a_star ^= sel(self.r[n + i], Block::MONOMIAL[i]);
            m_star ^= Block::MONOMIAL[i].gfmul(self.mr[n + i]);
        }
        (acc.0 ^ m_star, acc.1 ^ a_star)
    }
}

pub struct Verifier<'a> {
    kr: &'a [Block],
    delta: Block,
    d: Vec<bool>,
    n: usize,
    key: SecretBlocks,
    t_key: SecretBlocks,
}

impl<'a> Verifier<'a> {
    /// `kr`: the COT keys (AND gates, then 128 for the mask); `d_bytes`: the
    /// prover's correction bits. `None` if the lengths do not fit.
    pub fn new(kr: &'a [Block], delta: Block, d_bytes: &[u8]) -> Option<Self> {
        let n = kr.len().checked_sub(128)?;
        if d_bytes.len() != n.div_ceil(8) {
            return None;
        }
        let mut d = crate::circuits::to_bits(d_bytes);
        // Padding bits of the last byte must be zero (one encoding per proof).
        if d[n..].iter().any(|b| *b) {
            return None;
        }
        d.truncate(n);
        Some(Verifier {
            kr,
            delta,
            d,
            n: 0,
            key: SecretBlocks::default(),
            t_key: SecretBlocks::default(),
        })
    }

    /// `None` if the statement needs more AND gates than there are COTs.
    pub fn eval(&mut self, circ: &Circuit, inputs: &[VW]) -> Option<Vec<VW>> {
        assert_eq!(inputs.len(), circ.inputs().len());
        let delta = self.delta;
        let mut w = vec![VW::public(false, delta); circ.feed_count()];
        w[..inputs.len()].copy_from_slice(inputs);
        for g in circ.gates() {
            match g {
                Gate::Xor { x, y, z } => {
                    let (a, b) = (w[x.id()], w[y.id()]);
                    w[z.id()] = VW {
                        public: a.public && b.public,
                        v: a.v ^ b.v,
                        k: a.k ^ b.k,
                    };
                }
                Gate::Inv { x, z } => {
                    let a = w[x.id()];
                    w[z.id()] = VW {
                        public: a.public,
                        v: !a.v,
                        k: a.k ^ delta,
                    };
                }
                Gate::Id { x, z } => w[z.id()] = w[x.id()],
                Gate::And { x, y, z } => {
                    let (a, b) = (w[x.id()], w[y.id()]);
                    w[z.id()] = match (a.public, b.public) {
                        (true, true) => VW::public(a.v & b.v, delta),
                        (true, false) => VW::secret(sel(a.v, b.k)),
                        (false, true) => VW::secret(sel(b.v, a.k)),
                        (false, false) => {
                            let i = self.n;
                            if i >= self.d.len() {
                                return None;
                            }
                            let k = self.kr[i] ^ sel(self.d[i], delta);
                            self.key.push(a.k);
                            self.key.push(b.k);
                            self.t_key.push(k);
                            self.n += 1;
                            VW::secret(k)
                        }
                    };
                }
            }
        }
        let out = circ.outputs().map(|i| w[i]).collect();
        for x in w.iter_mut() {
            x.k = Block::ZERO;
        }
        Some(out)
    }

    pub fn compress(&mut self, state: &[VW], block: &[VW]) -> Option<Vec<VW>> {
        self.eval(&SHA256_COMPRESS, &compress_inputs(state, block))
    }

    /// True iff the product check passes.
    pub fn finish(self, chi: Block, u: Block, v: Block) -> bool {
        let n = self.n;
        if n != self.d.len() {
            return false;
        }
        let pw = gc::powers(chi, n);
        let ands: Vec<(usize, usize, usize)> = (0..n).map(|k| (2 * k, 2 * k + 1, 0)).collect();
        let mut acc = Block::ZERO;
        gc::dvzk_verifier_acc(&ands, &self.key, &self.t_key, self.delta, &pw, &mut acc);
        let mut k_star = Block::ZERO;
        for i in 0..128 {
            k_star ^= Block::MONOMIAL[i].gfmul(self.kr[n + i]);
        }
        acc ^ k_star == u ^ v.gfmul(self.delta)
    }
}

/// Public block bytes as prover wires.
pub fn pub_block_p(block: &[u8; 64]) -> Vec<PW> {
    crate::circuits::to_bits(block).into_iter().map(PW::public).collect()
}

/// Public block bytes as verifier wires.
pub fn pub_block_v(block: &[u8; 64], delta: Block) -> Vec<VW> {
    crate::circuits::to_bits(block)
        .into_iter()
        .map(|b| VW::public(b, delta))
        .collect()
}
