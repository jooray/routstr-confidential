//! Two-party TLS 1.3 key schedule for protocol v2 (`docs/TWOPC-DESIGN.md`).
//!
//! C (the client) and N (the node) jointly run the client side of a TLS 1.3
//! ECDHE(P-256) + SHA-256 key schedule so that neither learns the ECDHE secret
//! or any secret that belongs to the other party:
//!
//! | output | C | N |
//! |---|---|---|
//! | c_hs, s_hs | yes | yes |
//! | s_ap_0, c_ap_1 | yes | never |
//! | K_0, IV_0 (of c_ap_0) | never | yes |
//! | h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0), hk = SHA256(K_0‖IV_0) | yes | yes |
//!
//! # API (as implemented)
//!
//! ```ignore
//! let mut p = Party::new(Role::C, io).await?;   // io: futures AsyncRead + AsyncWrite
//! p.preprocess().await?;                         // OT setup, all garbled tables, OLEs
//! let joint: [u8; 65] = p.key_share().await?;    // commit-then-open joint P-256 share
//! let hs: HsSecrets = p.handshake(&server_share, th_sh).await?;  // ECtF + phase A
//! let ap: ApOut = p.application(th_sf).await?;   // phase B
//! ```
//!
//! Differences from the requested shape: `Party::new` needs a running tokio
//! runtime (it spawns the channel multiplexer tasks); `Party::close` flushes
//! the last bytes to the transport and should be awaited before the transport
//! is dropped; `take_timings` returns per-step wall time and transport bytes.
//!
//! # Protocol
//!
//! One transport carries six multiplexed channels ([`mux`]): KOS random-COT
//! for each garbled-circuit run, share conversion, the two runs' garbled data,
//! and a control channel.
//!
//! * **Preprocess** (input independent). Each party garbles both phase
//!   circuits with its own global offset Δ (mpz2 `garble-core` half-gates) and
//!   sends the tables and output decoding bits to the peer. Run 1 = N garbles,
//!   C evaluates; run 2 = C garbles, N evaluates. Each garbler, as KOS sender
//!   with correlation Δ, generates random COTs for every evaluator input bit
//!   of both phases (Chou–Orlandi base OT). The random OLEs for ECtF are
//!   generated too.
//! * **Key share.** C commits to `SHA256(tag‖SEC1(P_C)‖nonce)`, N sends `P_N`,
//!   C opens; N checks the opening and both compute `P = P_C + P_N`.
//! * **Handshake.** ECtF ([`ectf`]) turns `a_C·S`, `a_N·S` into additive shares
//!   `x_C + x_N = x(ECDHE) mod p`. Phase A (both runs at once) computes
//!   `c_hs, s_hs` and `MS ⊕ r_C ⊕ r_N`; afterwards C's MS share is `r_C` and
//!   N's is `MS ⊕ r_C`.
//! * **Application.** Phase B takes the MS shares and computes
//!   `(s_ap_0‖c_ap_1) ⊕ m_C`, `(K_0‖IV_0) ⊕ m_N`, h1, h2, hk.
//!
//! Online, for each phase both runs execute concurrently: the evaluator sends
//! `d = x ⊕ b` (b = its random-COT choice bits) while the garbler sends the
//! active labels of its own inputs and of its transcript hash; the garbler
//! answers `K ⊕ R ⊕ d·Δ`, from which the evaluator gets `K ⊕ x·Δ` (Beaver
//! derandomisation of the random COT). Then both evaluate, decode, and run the
//! equality check. 2 round trips per phase (plus 1.5 for ECtF).
//!
//! # Security argument (sketch)
//!
//! * **Inputs are never revealed.** Every private input enters only as a
//!   garbled-circuit input (evaluator labels via OT, garbler labels that are
//!   uniformly random to the evaluator), or as an OLE input in ECtF. Nothing
//!   is opened afterwards (unlike DEAP / Garble-then-Prove).
//! * **Outputs.** Every output wire is decoded by both evaluators, so a
//!   private output is XOR-masked inside the circuit with a uniformly random
//!   mask that only its owner inputs; the other party sees a one-time-padded
//!   value. MS is masked by both parties' masks (`MS ⊕ r_C ⊕ r_N`) so each
//!   side's view of it is padded by the other's mask.
//! * **Dual execution (Mohassel–Franklin 2006, Huang–Katz–Evans 2012).**
//!   Against a malicious garbler, each party relies only on the circuit *it*
//!   garbled for correctness of what the peer sees, and on the circuit the
//!   *peer* garbled for what it decodes itself. The equality check compares
//!   the two decoded output vectors through labels: C hashes
//!   `(A_i^{v1_i}, B_i^{v1_i})` — A = labels of N's circuit it evaluated, B =
//!   its own run-2 labels for the bit it decoded — and N hashes
//!   `(A_i^{v2_i}, B_i^{v2_i})` symmetrically. A party can only produce the
//!   other's hash if both runs decoded the same vector: for a differing bit it
//!   would need the *inactive* label of the peer's circuit, which half-gates
//!   garbling hides. The hashes are exchanged commit-then-open (each commits
//!   before seeing the other's hash), and on mismatch the session aborts.
//!   **No output is returned before the check passes.**
//! * **Leakage: at most one bit per session.** A corrupt garbler (wrong
//!   circuit, wrong decode bits, inconsistent inputs between the runs, or a
//!   different transcript hash) and selective failure on the OT (KOS with a
//!   malicious sender) can only make the honest party's decoded vector a
//!   function of the honest input that differs from the correct one; the
//!   adversary learns whether the equality check passed — one predicate on
//!   the honest input — and the session aborts. KOS is secure against a
//!   malicious receiver (its consistency check can leak a few bits of Δ with
//!   exponentially small probability, the documented KOS15 leakage; it does
//!   not reveal inputs).
//! * **ECtF** uses mpz2's semi-honest A2M/M2A. A deviating party only shifts
//!   the result (the shares then sum to a wrong x), which yields wrong
//!   handshake secrets and the TLS server Finished check fails; a malicious
//!   OLE sender can at worst cause a selective failure that again surfaces as
//!   one success/failure bit. Every session uses fresh scalars and shares.
//! * **Phase consistency.** A party may feed different MS shares to phase B
//!   than phase A gave it, or different masks; within a phase the dual
//!   execution forces both runs to agree (else abort), and across phases the
//!   only effect is a key nobody knows (rejected by the server). It never
//!   yields a key the cheater can read: the MS shares are uniformly random
//!   to the other party.
//! * **Key share.** C commits before seeing `P_N`, so it cannot pick
//!   `P_C = T − P_N` for a target T whose discrete log it knows; N's share is
//!   uniformly random, so the joint P is uniformly random as long as one side
//!   is honest.
//! * Randomness: all scalars, masks, labels and Δ come from a ChaCha12 CSPRNG
//!   seeded from the OS (`getrandom`).

pub mod circuits;
mod ectf;
mod mux;
#[doc(hidden)]
pub mod testutil;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Instant;

use futures::{AsyncRead, AsyncWrite};
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::p256::P256 as Fp;
use mpz_garble_core::{
    Delta, EncryptedGate, EvaluatorOutput, GarbledCircuit, Garbler, GarblerOutput, Key, Mac,
    evaluate_garbled_circuits,
};
use mpz_ot::{chou_orlandi, kos};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput};
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use tokio_util::compat::TokioAsyncReadCompatExt;
use zeroize::Zeroize;

use circuits::{from_bits, spec, to_bits};
pub use mux::Counters;
use mux::{FrameChan, Mux};

/// Errors. `Abort` means a check failed (possible cheating); the session must
/// be discarded.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("abort: {0}")]
    Abort(String),
    #[error("invalid input: {0}")]
    Input(String),
    #[error("wrong call order: {0}")]
    State(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    C,
    N,
}

/// Handshake traffic secrets, given to both parties.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct HsSecrets {
    pub c_hs: [u8; 32],
    pub s_hs: [u8; 32],
}

impl std::fmt::Debug for HsSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HsSecrets(<redacted>)")
    }
}

/// Phase B outputs.
#[derive(Clone)]
pub enum ApOut {
    C {
        s_ap_0: [u8; 32],
        c_ap_1: [u8; 32],
        h1: [u8; 32],
        h2: [u8; 32],
        hk: [u8; 32],
    },
    N {
        k0: [u8; 16],
        iv0: [u8; 12],
        h1: [u8; 32],
        h2: [u8; 32],
        hk: [u8; 32],
    },
}

impl std::fmt::Debug for ApOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApOut(<redacted>)")
    }
}

impl Drop for ApOut {
    fn drop(&mut self) {
        match self {
            ApOut::C { s_ap_0, c_ap_1, .. } => {
                s_ap_0.zeroize();
                c_ap_1.zeroize();
            }
            ApOut::N { k0, iv0, .. } => {
                k0.zeroize();
                iv0.zeroize();
            }
        }
    }
}

/// Wall time and transport bytes of one step.
#[derive(Debug, Clone)]
pub struct StepTiming {
    pub step: &'static str,
    pub ms: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Circuit statistics (for reports).
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub name: &'static str,
    pub and_gates: usize,
    pub xor_gates: usize,
    pub compressions: usize,
    pub c_input_bits: usize,
    pub n_input_bits: usize,
    pub output_bits: usize,
}

pub fn circuit_stats() -> [CircuitStats; 2] {
    let f = |name, s: &circuits::Spec| CircuitStats {
        name,
        and_gates: s.circ.and_count(),
        xor_gates: s.circ.xor_count(),
        compressions: s.compressions,
        c_input_bits: s.c_bits,
        n_input_bits: s.n_bits,
        output_bits: s.out_bits,
    };
    [f("phase A", &circuits::PHASE_A), f("phase B", &circuits::PHASE_B)]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    New,
    Preprocessed,
    KeyShared,
    Handshaken,
    Done,
    Failed,
}

/// Test-only deviations used by the malicious tests.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Cheat {
    #[default]
    None,
    /// As garbler, corrupt encrypted gates of this phase.
    CorruptGate(usize),
    /// As garbler, flip the decoding bit of output 0 of this phase.
    FlipDecode(usize),
    /// Use a different value for own input bit `bit` of `phase` in the run
    /// this party garbles than in the run it evaluates.
    InconsistentInput { phase: usize, bit: usize },
    /// C opens its key-share commitment to a different point.
    BadOpen,
}

type KosS = kos::Sender<chou_orlandi::Receiver>;
type KosR = kos::Receiver<chou_orlandi::Sender>;

struct GarblerPhase {
    in_keys: Vec<Key>,
    out_keys: Vec<Key>,
}

struct EvalPhase {
    tables: Option<Vec<EncryptedGate>>,
    decode: Vec<bool>,
}

struct Pre {
    g: Vec<GarblerPhase>,
    e: Vec<EvalPhase>,
    /// Garbler side: random-COT keys for the peer's input bits (A then B).
    cot_keys: Vec<Block>,
    /// Evaluator side: random-COT choices and MACs for own input bits.
    cot_choices: Vec<bool>,
    cot_msgs: Vec<Block>,
}

/// Channel numbers on the mux.
const CH_COT1: usize = 0; // KOS for run 1 (N sender)
const CH_COT2: usize = 1; // KOS for run 2 (C sender)
const CH_SC: usize = 2; // share conversion
const CH_RUN1: usize = 3; // run 1 data (N garbles)
const CH_RUN2: usize = 4; // run 2 data (C garbles)
const CH_CTL: usize = 5; // key share, equality checks
const N_CH: usize = 6;

const TAG_KS: &[u8] = b"routstr-twopc-v2 key-share commit";
const TAG_EQ: &[u8] = b"routstr-twopc-v2 equality";
const TAG_EQC: &[u8] = b"routstr-twopc-v2 equality commit";

/// One side of the two-party key schedule.
pub struct Party {
    role: Role,
    mux: Option<Mux>,
    counters: Arc<Counters>,
    /// [run 1, run 2]
    ctx_cot: [Context; 2],
    ctx_sc: Context,
    ch_run: [FrameChan; 2],
    ch_ctl: FrameChan,
    rng: StdRng,
    delta: Delta,
    kos_s: Option<KosS>,
    kos_r: Option<KosR>,
    sc: ectf::Sc,
    stage: Stage,
    pre: Option<Pre>,
    scalar: Option<Scalar>,
    ms_share: [u8; 32],
    timings: Vec<StepTiming>,
    #[cfg(test)]
    pub(crate) cheat: Cheat,
}

impl Drop for Party {
    fn drop(&mut self) {
        self.ms_share.zeroize();
        self.scalar = None;
    }
}

fn os_rng() -> StdRng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness");
    let r = StdRng::from_seed(seed);
    seed.zeroize();
    r
}

fn pack(bits: &[bool]) -> Vec<u8> {
    from_bits(bits)
}

fn unpack(bytes: &[u8], n: usize) -> Vec<bool> {
    let mut b = to_bits(bytes);
    b.truncate(n);
    b
}

fn blocks_to_bytes<'a>(it: impl Iterator<Item = &'a Block>) -> Vec<u8> {
    let mut v = Vec::new();
    for b in it {
        v.extend_from_slice(b.as_bytes());
    }
    v
}

fn bytes_to_blocks(b: &[u8]) -> Vec<Block> {
    b.chunks_exact(16)
        .map(|c| Block::new(c.try_into().unwrap()))
        .collect()
}

fn parse_point(b: &[u8]) -> Result<ProjectivePoint> {
    if b.len() != 65 || b[0] != 0x04 {
        return Err(Error::Input("point must be 65-byte uncompressed SEC1".into()));
    }
    let ep = EncodedPoint::from_bytes(b).map_err(|_| Error::Input("bad SEC1 point".into()))?;
    let ap: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let ap = ap.ok_or_else(|| Error::Input("point not on P-256".into()))?;
    let p = ProjectivePoint::from(ap);
    if bool::from(p.is_identity()) {
        return Err(Error::Input("identity point".into()));
    }
    Ok(p)
}

fn encode_point(p: &ProjectivePoint) -> [u8; 65] {
    let ep = p.to_affine().to_encoded_point(false);
    ep.as_bytes().try_into().expect("65 bytes")
}

fn random_scalar(rng: &mut StdRng) -> Scalar {
    loop {
        let mut b: [u8; 32] = rng.random();
        let s: Option<Scalar> = Scalar::from_repr(b.into()).into();
        b.zeroize();
        if let Some(s) = s {
            if !bool::from(p256::elliptic_curve::Field::is_zero(&s)) {
                return s;
            }
        }
    }
}

/// Field element from 32 big-endian bytes.
fn fp_from_be(be: &[u8]) -> Result<Fp> {
    let mut le: [u8; 32] = be.try_into().map_err(|_| Error::Protocol("coord".into()))?;
    le.reverse();
    Fp::try_from(le).map_err(|_| Error::Protocol("non-canonical coordinate".into()))
}

impl Party {
    /// Creates a party over `io`, a duplex byte stream to the peer. Must be
    /// called inside a tokio runtime.
    pub async fn new<IO>(role: Role, io: IO) -> Result<Party>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mux, mut chans) = Mux::start(io, N_CH);
        let counters = mux.counters.clone();
        let mut take = |i: usize| std::mem::replace(&mut chans[i], tokio::io::duplex(1).0);
        let ctx_cot = [
            Context::new_single_threaded(take(CH_COT1).compat()),
            Context::new_single_threaded(take(CH_COT2).compat()),
        ];
        let ctx_sc = Context::new_single_threaded(take(CH_SC).compat());
        let ch_run = [FrameChan::new(take(CH_RUN1)), FrameChan::new(take(CH_RUN2))];
        let ch_ctl = FrameChan::new(take(CH_CTL));

        let mut rng = os_rng();
        let delta = Delta::random(&mut rng);
        let sc = match role {
            Role::C => ectf::Sc::new_sender(&mut rng),
            Role::N => ectf::Sc::new_receiver(&mut rng),
        };
        let (kos_s, kos_r) = (
            Some(kos::Sender::new(
                kos::SenderConfig::default(),
                *delta.as_block(),
                chou_orlandi::Receiver::new_with_seed(rng.random()),
            )),
            Some(kos::Receiver::new(
                kos::ReceiverConfig::default(),
                chou_orlandi::Sender::new_with_seed(rng.random()),
            )),
        );
        Ok(Party {
            role,
            mux: Some(mux),
            counters,
            ctx_cot,
            ctx_sc,
            ch_run,
            ch_ctl,
            rng,
            delta,
            kos_s,
            kos_r,
            sc,
            stage: Stage::New,
            pre: None,
            scalar: None,
            ms_share: [0u8; 32],
            timings: Vec::new(),
            #[cfg(test)]
            cheat: Cheat::None,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Transport byte counters (frame headers included).
    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }

    /// Returns and clears the per-step timings recorded so far.
    pub fn take_timings(&mut self) -> Vec<StepTiming> {
        std::mem::take(&mut self.timings)
    }

    /// Flushes everything to the transport and stops the mux. Await this
    /// before dropping the transport (e.g. before the process exits).
    pub async fn close(mut self) {
        let mux = self.mux.take();
        // Dropping the party drops the channel ends, so the pumps see EOF.
        drop(self);
        if let Some(m) = mux {
            m.close().await;
        }
    }

    fn mark(&self) -> (Instant, u64, u64) {
        (Instant::now(), self.counters.sent(), self.counters.recv())
    }

    fn record(&mut self, step: &'static str, m: (Instant, u64, u64)) {
        self.timings.push(StepTiming {
            step,
            ms: m.0.elapsed().as_secs_f64() * 1e3,
            bytes_sent: self.counters.sent() - m.1,
            bytes_recv: self.counters.recv() - m.2,
        });
    }

    fn g_run(&self) -> usize {
        match self.role {
            Role::N => 0,
            Role::C => 1,
        }
    }

    /// Own and peer input-bit counts of a phase.
    fn bits(&self, phase: usize) -> (usize, usize) {
        let s = spec(phase);
        match self.role {
            Role::C => (s.c_bits, s.n_bits),
            Role::N => (s.n_bits, s.c_bits),
        }
    }

    fn own_range(&self, phase: usize) -> std::ops::Range<usize> {
        let s = spec(phase);
        match self.role {
            Role::C => s.c_range(),
            Role::N => s.n_range(),
        }
    }

    fn peer_range(&self, phase: usize) -> std::ops::Range<usize> {
        let s = spec(phase);
        match self.role {
            Role::C => s.n_range(),
            Role::N => s.c_range(),
        }
    }

    fn check_stage(&self, want: Stage, what: &'static str) -> Result<()> {
        if self.stage != want {
            return Err(Error::State(what));
        }
        Ok(())
    }

    fn fail<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            self.stage = Stage::Failed;
        }
        r
    }

    /// Input-independent preprocessing: OT extension, garbled tables of both
    /// phases in both runs, random OLEs for ECtF.
    pub async fn preprocess(&mut self) -> Result<()> {
        self.check_stage(Stage::New, "preprocess must be first")?;
        let m = self.mark();
        let r = self.preprocess_inner().await;
        let r = self.fail(r);
        self.record("preprocess", m);
        r?;
        self.stage = Stage::Preprocessed;
        Ok(())
    }

    async fn preprocess_inner(&mut self) -> Result<()> {
        let role = self.role;
        let g_run = self.g_run();
        let e_run = 1 - g_run;
        let (own_a, peer_a) = self.bits(0);
        let (own_b, peer_b) = self.bits(1);
        let delta = self.delta;
        let mut grng = StdRng::from_seed(self.rng.random());
        #[cfg(test)]
        let cheat = self.cheat;

        // Garble both phases off the async thread.
        let garble = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for phase in 0..2 {
                let s = spec(phase);
                let in_keys: Vec<Key> = (0..s.circ.inputs().len())
                    .map(|_| Key::from(Block::random(&mut grng)))
                    .collect();
                let mut gb = Garbler::default();
                let mut it = gb.generate(&s.circ, delta, &in_keys).expect("garble");
                let gates: Vec<EncryptedGate> = it.by_ref().collect();
                let GarblerOutput { outputs } = it.finish().expect("garbler finish");
                let mut tables = bincode::serialize(&gates).expect("serialize");
                let mut decode: Vec<bool> = outputs.iter().map(|k| k.pointer()).collect();
                #[cfg(test)]
                {
                    if cheat == Cheat::CorruptGate(phase) {
                        // A corrupted row only matters if the evaluator uses it
                        // (selective failure), so corrupt both rows of 64 gates.
                        for g in 0..64 {
                            let k = 8 + 32 * (g * (gates.len() / 64));
                            tables[k + 3] ^= 0x10;
                            tables[k + 16 + 3] ^= 0x10;
                        }
                    }
                    if cheat == Cheat::FlipDecode(phase) {
                        decode[0] = !decode[0];
                    }
                }
                let _ = &mut tables;
                let _ = &mut decode;
                out.push((
                    GarblerPhase {
                        in_keys,
                        out_keys: outputs,
                    },
                    tables,
                    pack(&decode),
                ));
            }
            out
        });

        let Party {
            ctx_cot,
            ctx_sc,
            ch_run,
            kos_s,
            kos_r,
            sc,
            ..
        } = self;
        let [ctx1, ctx2] = ctx_cot;
        let (ctx_g, ctx_e) = if g_run == 0 { (ctx1, ctx2) } else { (ctx2, ctx1) };
        let [ch1, ch2] = ch_run;
        let (ch_g, ch_e) = if g_run == 0 { (ch1, ch2) } else { (ch2, ch1) };
        let _ = e_run;

        let send_fut = async {
            let garbled = garble
                .await
                .map_err(|e| Error::Protocol(format!("garbling task: {e}")))?;
            let mut keep = Vec::new();
            for (gp, tables, decode) in garbled {
                ch_g.send(&tables).await?;
                ch_g.send(&decode).await?;
                keep.push(gp);
            }
            Ok::<_, Error>(keep)
        };
        let recv_fut = async {
            let mut ev = Vec::new();
            for phase in 0..2 {
                let s = spec(phase);
                let tables = ch_e.recv().await?;
                let gates: Vec<EncryptedGate> = bincode::deserialize(&tables)
                    .map_err(|e| Error::Protocol(format!("tables: {e}")))?;
                if gates.len() != s.circ.and_count() {
                    return Err(Error::Protocol("garbled table size".into()));
                }
                let decode = ch_e.recv_exact(s.out_bits.div_ceil(8)).await?;
                ev.push(EvalPhase {
                    tables: Some(gates),
                    decode: unpack(&decode, s.out_bits),
                });
            }
            Ok::<_, Error>(ev)
        };
        let cot_s_fut = async {
            let s = kos_s.as_mut().unwrap();
            let n = peer_a + peer_b;
            s.alloc(n).map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            let f = s
                .queue_send_rcot(n)
                .map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            s.flush(ctx_g)
                .await
                .map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            let RCOTSenderOutput { keys, .. } =
                f.await.map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            Ok::<_, Error>(keys)
        };
        let cot_r_fut = async {
            let r = kos_r.as_mut().unwrap();
            let n = own_a + own_b;
            r.alloc(n).map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            let f = r
                .queue_recv_rcot(n)
                .map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            r.flush(ctx_e)
                .await
                .map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            let RCOTReceiverOutput { choices, msgs, .. } =
                f.await.map_err(|e| Error::Protocol(format!("kos: {e}")))?;
            Ok::<_, Error>((choices, msgs))
        };
        let sc_fut = sc.preprocess(ctx_sc);

        let (g, e, keys, cr, scr) = futures::join!(send_fut, recv_fut, cot_s_fut, cot_r_fut, sc_fut);
        let g = g?;
        let e = e?;
        let cot_keys = keys?;
        let (cot_choices, cot_msgs) = cr?;
        scr?;
        if cot_keys.len() != peer_a + peer_b || cot_choices.len() != own_a + own_b {
            return Err(Error::Protocol("cot count".into()));
        }
        let _ = role;
        self.pre = Some(Pre {
            g,
            e,
            cot_keys,
            cot_choices,
            cot_msgs,
        });
        Ok(())
    }

    /// Joint P-256 key share: C commits to `P_C`, N sends `P_N`, C opens.
    /// Returns `P_C + P_N` (65-byte uncompressed SEC1) to both.
    pub async fn key_share(&mut self) -> Result<[u8; 65]> {
        self.check_stage(Stage::Preprocessed, "key_share after preprocess")?;
        let m = self.mark();
        let r = self.key_share_inner().await;
        let r = self.fail(r);
        self.record("key_share", m);
        let p = r?;
        self.stage = Stage::KeyShared;
        Ok(p)
    }

    async fn key_share_inner(&mut self) -> Result<[u8; 65]> {
        let a = random_scalar(&mut self.rng);
        let p_own = ProjectivePoint::GENERATOR * a;
        let own = encode_point(&p_own);
        self.scalar = Some(a);
        let joint = match self.role {
            Role::C => {
                let nonce: [u8; 32] = self.rng.random();
                let com: [u8; 32] = Sha256::new()
                    .chain_update(TAG_KS)
                    .chain_update(own)
                    .chain_update(nonce)
                    .finalize()
                    .into();
                self.ch_ctl.send(&com).await?;
                let pn = self.ch_ctl.recv_exact(65).await?;
                let p_n = parse_point(&pn)?;
                #[allow(unused_mut)]
                let mut open = own.to_vec();
                #[cfg(test)]
                if self.cheat == Cheat::BadOpen {
                    // A rogue key T - P_N for a T we "know".
                    let t = ProjectivePoint::GENERATOR * Scalar::from(7u64);
                    open = encode_point(&(t - p_n)).to_vec();
                }
                open.extend_from_slice(&nonce);
                self.ch_ctl.send(&open).await?;
                p_own + p_n
            }
            Role::N => {
                let com = self.ch_ctl.recv_exact(32).await?;
                self.ch_ctl.send(&own).await?;
                let open = self.ch_ctl.recv_exact(97).await?;
                let check: [u8; 32] = Sha256::new()
                    .chain_update(TAG_KS)
                    .chain_update(&open[..65])
                    .chain_update(&open[65..])
                    .finalize()
                    .into();
                if check[..] != com[..] {
                    return Err(Error::Abort("key-share commitment does not open".into()));
                }
                let p_c = parse_point(&open[..65])?;
                p_c + p_own
            }
        };
        if bool::from(joint.is_identity()) {
            return Err(Error::Abort("joint key share is the identity".into()));
        }
        Ok(encode_point(&joint))
    }

    /// ECtF + phase A. `server_share` is the ServerHello key_share (65-byte
    /// uncompressed P-256), `th_sh = SHA256(ClientHello‖ServerHello)`.
    pub async fn handshake(&mut self, server_share: &[u8], th_sh: [u8; 32]) -> Result<HsSecrets> {
        self.check_stage(Stage::KeyShared, "handshake after key_share")?;
        let r = self.handshake_inner(server_share, th_sh).await;
        let r = self.fail(r);
        let hs = r?;
        self.stage = Stage::Handshaken;
        Ok(hs)
    }

    async fn handshake_inner(&mut self, server_share: &[u8], th_sh: [u8; 32]) -> Result<HsSecrets> {
        let s = parse_point(server_share)?;
        let a = self.scalar.take().ok_or(Error::State("no scalar"))?;
        let q = (s * a).to_affine();
        let ep = q.to_encoded_point(false);
        let x = fp_from_be(ep.x().ok_or_else(|| Error::Protocol("identity".into()))?)?;
        let y = fp_from_be(ep.y().ok_or_else(|| Error::Protocol("identity".into()))?)?;

        let m = self.mark();
        let share = self.sc.point_add_x(&mut self.ctx_sc, x, y).await?;
        self.record("ectf", m);
        let mut x_le: [u8; 32] = share.into();

        let mut r_mask: [u8; 32] = self.rng.random();
        let mut own = Vec::with_capacity(64);
        own.extend_from_slice(&x_le);
        own.extend_from_slice(&r_mask);
        x_le.zeroize();
        let out = self.run_phase(0, own, th_sh).await;
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                r_mask.zeroize();
                return Err(e);
            }
        };
        let mut hs = HsSecrets {
            c_hs: [0; 32],
            s_hs: [0; 32],
        };
        hs.c_hs.copy_from_slice(&out[0..32]);
        hs.s_hs.copy_from_slice(&out[32..64]);
        // MS shares: C keeps r_C; N keeps (MS ⊕ r_C ⊕ r_N) ⊕ r_N.
        match self.role {
            Role::C => self.ms_share = r_mask,
            Role::N => {
                for i in 0..32 {
                    self.ms_share[i] = out[64 + i] ^ r_mask[i];
                }
            }
        }
        r_mask.zeroize();
        Ok(hs)
    }

    /// Phase B. `th_sf = SHA256(ClientHello..server Finished)`.
    pub async fn application(&mut self, th_sf: [u8; 32]) -> Result<ApOut> {
        self.check_stage(Stage::Handshaken, "application after handshake")?;
        let r = self.application_inner(th_sf).await;
        let r = self.fail(r);
        let o = r?;
        self.stage = Stage::Done;
        Ok(o)
    }

    async fn application_inner(&mut self, th_sf: [u8; 32]) -> Result<ApOut> {
        let mask_len = match self.role {
            Role::C => 64,
            Role::N => 28,
        };
        let mut mask = vec![0u8; mask_len];
        self.rng.fill(&mut mask[..]);
        let mut own = Vec::with_capacity(32 + mask_len);
        own.extend_from_slice(&self.ms_share);
        own.extend_from_slice(&mask);
        self.ms_share.zeroize();
        let out = self.run_phase(1, own, th_sf).await;
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                mask.zeroize();
                return Err(e);
            }
        };
        let arr = |s: &[u8]| -> [u8; 32] { s.try_into().unwrap() };
        let h1 = arr(&out[92..124]);
        let h2 = arr(&out[124..156]);
        let hk = arr(&out[156..188]);
        let res = match self.role {
            Role::C => {
                let mut s_ap_0 = [0u8; 32];
                let mut c_ap_1 = [0u8; 32];
                for i in 0..32 {
                    s_ap_0[i] = out[i] ^ mask[i];
                    c_ap_1[i] = out[32 + i] ^ mask[32 + i];
                }
                if Sha256::digest(c_ap_1)[..] != h1 || Sha256::digest(s_ap_0)[..] != h2 {
                    return Err(Error::Abort("anchor mismatch".into()));
                }
                ApOut::C {
                    s_ap_0,
                    c_ap_1,
                    h1,
                    h2,
                    hk,
                }
            }
            Role::N => {
                let mut kiv = [0u8; 28];
                for i in 0..28 {
                    kiv[i] = out[64 + i] ^ mask[i];
                }
                if Sha256::digest(kiv)[..] != hk {
                    return Err(Error::Abort("anchor mismatch".into()));
                }
                let o = ApOut::N {
                    k0: kiv[..16].try_into().unwrap(),
                    iv0: kiv[16..].try_into().unwrap(),
                    h1,
                    h2,
                    hk,
                };
                kiv.zeroize();
                o
            }
        };
        mask.zeroize();
        Ok(res)
    }

    /// Runs one phase in both runs concurrently plus the equality check.
    /// `own` are this party's input bytes, `th` the garbler's transcript hash.
    /// Returns the decoded output bytes only if the check passes.
    async fn run_phase(&mut self, phase: usize, own: Vec<u8>, th: [u8; 32]) -> Result<Vec<u8>> {
        let names = [("phase_a", "check_a"), ("phase_b", "check_b")][phase];
        let m = self.mark();
        let s = spec(phase);
        let g_run = self.g_run();
        let (own_n, peer_n) = self.bits(phase);
        let own_range = self.own_range(phase);
        let peer_range = self.peer_range(phase);
        let th_range = s.th_range();
        let own_bits = to_bits(&own);
        if own_bits.len() != own_n {
            return Err(Error::Input("input length".into()));
        }
        let th_bits = to_bits(&th);
        #[allow(unused_mut)]
        let mut g_own_bits = own_bits.clone();
        #[cfg(test)]
        if let Cheat::InconsistentInput { phase: p, bit } = self.cheat {
            if p == phase {
                g_own_bits[bit] = !g_own_bits[bit];
            }
        }
        // Offsets into the random-COT vectors (phase A first).
        let (own_a, peer_a) = self.bits(0);
        let e_off = if phase == 0 { 0 } else { own_a };
        let g_off = if phase == 0 { 0 } else { peer_a };
        let delta = self.delta;

        let pre = self.pre.as_mut().ok_or(Error::State("not preprocessed"))?;
        let tables = pre.e[phase]
            .tables
            .take()
            .ok_or(Error::State("phase already used"))?;
        let decode = pre.e[phase].decode.clone();
        let in_keys = pre.g[phase].in_keys.clone();
        let out_keys = pre.g[phase].out_keys.clone();
        let cot_keys = pre.cot_keys[g_off..g_off + peer_n].to_vec();
        let choices = pre.cot_choices[e_off..e_off + own_n].to_vec();
        let cot_msgs = pre.cot_msgs[e_off..e_off + own_n].to_vec();

        let Party { ch_run, .. } = self;
        let [ch1, ch2] = ch_run;
        let (ch_g, ch_e) = if g_run == 0 { (ch1, ch2) } else { (ch2, ch1) };

        // Garbler side of the run this party garbled.
        let g_fut = async {
            let mut labels: Vec<Block> = Vec::with_capacity(g_own_bits.len() + 256);
            for (i, b) in own_range.clone().zip(&g_own_bits) {
                labels.push(*in_keys[i].auth(*b, &delta).as_block());
            }
            for (i, b) in th_range.clone().zip(&th_bits) {
                labels.push(*in_keys[i].auth(*b, &delta).as_block());
            }
            ch_g.send(&blocks_to_bytes(labels.iter())).await?;
            let d = ch_g.recv_exact(peer_n.div_ceil(8)).await?;
            let d = unpack(&d, peer_n);
            let adj: Vec<Block> = peer_range
                .clone()
                .enumerate()
                .map(|(j, i)| {
                    let base = *in_keys[i].as_block() ^ cot_keys[j];
                    if d[j] { base ^ *delta.as_block() } else { base }
                })
                .collect();
            ch_g.send(&blocks_to_bytes(adj.iter())).await?;
            Ok::<_, Error>(())
        };

        // Evaluator side of the run the peer garbled.
        let e_fut = async {
            let d: Vec<bool> = own_bits.iter().zip(&choices).map(|(x, b)| x ^ b).collect();
            ch_e.send(&pack(&d)).await?;
            let gl = ch_e.recv_exact(16 * (peer_n + 256)).await?;
            let gl = bytes_to_blocks(&gl);
            let el = ch_e.recv_exact(16 * own_n).await?;
            let el = bytes_to_blocks(&el);
            let mut macs = vec![Mac::from(Block::ZERO); s.circ.inputs().len()];
            for (j, i) in peer_range.clone().enumerate() {
                macs[i] = Mac::from(gl[j]);
            }
            for (j, i) in th_range.clone().enumerate() {
                macs[i] = Mac::from(gl[peer_n + j]);
            }
            for (j, i) in own_range.clone().enumerate() {
                macs[i] = Mac::from(el[j] ^ cot_msgs[j]);
            }
            let circ = s.circ.clone();
            let out = tokio::task::spawn_blocking(move || {
                evaluate_garbled_circuits(vec![(circ, macs, GarbledCircuit { gates: tables })])
            })
            .await
            .map_err(|e| Error::Protocol(format!("eval task: {e}")))?
            .map_err(|e| Error::Protocol(format!("eval: {e}")))?;
            let EvaluatorOutput { outputs } = out
                .into_iter()
                .next()
                .ok_or_else(|| Error::Protocol("eval output".into()))?;
            Ok::<_, Error>(outputs)
        };

        let (gr, er) = futures::join!(g_fut, e_fut);
        gr?;
        let out_macs = er?;
        if out_macs.len() != s.out_bits {
            return Err(Error::Protocol("output size".into()));
        }
        let v: Vec<bool> = out_macs
            .iter()
            .zip(&decode)
            .map(|(m, d)| m.pointer() ^ d)
            .collect();
        self.record(names.0, m);

        // Equality check (HKE12) over output labels, commit-then-open.
        let m = self.mark();
        let mut h = Sha256::new();
        h.update(TAG_EQ);
        h.update([phase as u8]);
        for i in 0..s.out_bits {
            let own_label = *out_keys[i].auth(v[i], &delta).as_block();
            let ev_label = *out_macs[i].as_block();
            // A = run-1 label (N's circuit), B = run-2 label (C's circuit).
            let (a, b) = match self.role {
                Role::C => (ev_label, own_label),
                Role::N => (own_label, ev_label),
            };
            h.update(a.as_bytes());
            h.update(b.as_bytes());
        }
        let digest: [u8; 32] = h.finalize().into();
        let nonce: [u8; 32] = self.rng.random();
        let com: [u8; 32] = Sha256::new()
            .chain_update(TAG_EQC)
            .chain_update(digest)
            .chain_update(nonce)
            .finalize()
            .into();
        self.ch_ctl.send(&com).await?;
        let peer_com = self.ch_ctl.recv_exact(32).await?;
        let mut open = digest.to_vec();
        open.extend_from_slice(&nonce);
        self.ch_ctl.send(&open).await?;
        let peer_open = self.ch_ctl.recv_exact(64).await?;
        let check: [u8; 32] = Sha256::new()
            .chain_update(TAG_EQC)
            .chain_update(&peer_open[..32])
            .chain_update(&peer_open[32..])
            .finalize()
            .into();
        let ok_open = check[..] == peer_com[..];
        let ok_eq = peer_open[..32] == digest[..];
        self.record(names.1, m);
        if !ok_open {
            return Err(Error::Abort("equality-check commitment does not open".into()));
        }
        if !ok_eq {
            return Err(Error::Abort("dual-execution equality check failed".into()));
        }
        Ok(from_bits(&v))
    }
}
