//! Two-party TLS 1.3 key schedule for protocol v2 (`docs/TWOPC-DESIGN.md`),
//! with **only N garbling**: authenticated garbling with garbler-held masks
//! and an IT-MAC consistency check (the node garbles, the client evaluates
//! and mostly downloads).
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
//! # API
//!
//! ```ignore
//! let mut p = Party::new(Role::C, io).await?;   // io: futures AsyncRead + AsyncWrite
//! p.preprocess().await?;                         // input independent (pre-warm)
//! let joint: [u8; 65] = p.key_share().await?;    // commit-then-open joint P-256 share
//! let hs: HsSecrets = p.handshake(&server_share, th_sh).await?;  // ECtF + phase A
//! let ap: ApOut = p.application(th_sf).await?;   // phase B
//! p.close().await;
//! ```
//!
//! `Party::new` needs a running tokio runtime (it spawns the channel
//! multiplexer); `close` flushes the transport; `take_timings` returns per-step
//! wall time and transport bytes.
//!
//! The library sets no deadlines: a receive waits until the peer's data or
//! EOF arrives, so a half-open transport stalls a step. Callers bound each
//! step themselves (the sidecar and the SDK do; `cu-2pc` has a per-step
//! watchdog).
//!
//! # Protocol
//!
//! N garbles both phase circuits once ([`gc`]: three-halves garbling,
//! Rosulek–Roy 2021, 1.5κ+5 bits per AND, global offset Δ_A). C is protected
//! by **IT-MACs on N's wire masks** under C's key Δ_B and a batched
//! consistency check of every AND gate:
//!
//! * **Preprocess.** Random COTs with C as sender (Δ_B; Ferret over KOS)
//!   authenticate, by `Fix` (N sends `d = λ ⊕ r`), N's mask λ_w of every
//!   circuit input and AND output, and `t_k = λ_i·λ_j` of every AND gate.
//!   N sends the garbled tables and the `d` bits, then C sends a random seed
//!   (χ). N proves `t_k = λ_i·λ_j` for all gates (QuickSilver-style, two field
//!   elements), opens the masks of C's input wires, the transcript-hash wires
//!   and all output wires (values + one hash of MACs), and sends one 64-bit
//!   check row per base wire and `Y_N` (`gc::check_material`). KOS random COT
//!   with N as sender (Δ_A) for C's input bits, and the ECtF OLEs.
//! * **Key share.** C commits to `SHA256(tag‖SEC1(P_C)‖nonce)`, N sends `P_N`,
//!   C opens; both compute `P = P_C + P_N`.
//! * **Handshake.** ECtF ([`ectf`]) turns `a_C·S`, `a_N·S` into additive shares
//!   `x_C + x_N = x(ECDHE) mod p`; phase A computes `c_hs, s_hs` and
//!   `MS ⊕ r_C ⊕ r_N` (C's MS share is `r_C`, N's is `MS ⊕ r_C`).
//! * **Application.** Phase B takes the MS shares and computes
//!   `(s_ap_0‖c_ap_1) ⊕ m_C`, `(K_0‖IV_0) ⊕ m_N`, h1, h2, hk.
//! * **Online, per phase.** C sends `d = x ⊕ b` (Beaver derandomisation of its
//!   COTs), N sends its own and the transcript-hash input labels, then the
//!   corrections for C's labels. C checks the pointer bits of its own and of
//!   the transcript-hash wires against the opened masks, evaluates, runs the
//!   consistency check, decodes its outputs with the opened (authenticated)
//!   masks and only then sends N the output pointer bits plus a hash of the
//!   output labels, which N checks against its labels. About 1.5 round trips.
//!
//! # Security (sketch; `docs/TWOPC-DESIGN.md` has the full argument)
//!
//! * **Malicious N.** Every base mask λ and product t is fixed under Δ_B
//!   before χ; the products are checked over GF(2^128) (error ≤ 2n/2^128). An
//!   AND gate evaluated inconsistently with the committed masks makes the
//!   (GF(2^128)) combination E = Σχ^k e_k non-zero except with probability
//!   n/2^128, and then C accepts only if the 64-bit projection of `Δ_B·E`
//!   hits a value fixed before Δ_B is used: ≤ 2^-63 per phase (Δ_B has 127
//!   uniform bits and N learns nothing about it). With all gates consistent,
//!   C's outputs are the correct function of the inputs (C's inputs and the
//!   transcript hash are pinned by the pointer checks against opened masks;
//!   outputs decode with authenticated masks). What N can still do is a
//!   *selective failure*: make C abort depending on C's private values. Per
//!   phase N observes one of {abort, labels rejected, success}, the session
//!   ends at the first failure, and a deviation in ECtF adds one outcome (the
//!   server Finished failing between the phases): six outcomes, ≤ log2 6 ≈ 2.6
//!   bits per session.
//! * **Malicious C.** C is the evaluator; it sees the tables, active labels
//!   and pointer bits, the opened masks (its inputs, the public transcript
//!   hash, the outputs), check rows padded by hashes of inactive labels, and
//!   `Y_N` (a value C can compute itself). It cannot report a wrong output to
//!   N without an inactive output label (needs Δ_A).
//! * **Fairness.** C decodes its outputs first and N gets its own only from
//!   C's final message of each phase, so a malicious C can keep N's outputs
//!   (`K_0, IV_0`) from it after learning its own. The protocol does not
//!   prevent this; in the routstr flow it gains C nothing, since without the
//!   credential record N writes under `K_0` there is no provider request.
//! * **Inputs are never revealed** by either party (nothing is opened after
//!   the evaluation). Private outputs are XOR-masked inside the circuit by
//!   their owner's random mask; MS by both parties' masks.
//! * **ECtF** uses mpz2's semi-honest A2M/M2A: a deviation only shifts the
//!   result (the TLS server Finished then fails) or causes a selective
//!   failure. All scalars, masks, labels and Δ are fresh per session
//!   (ChaCha12 seeded from the OS).

pub mod circuits;

mod ectf;
pub mod gc;
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
use mpz_ot::{chou_orlandi, ferret, kos};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use tokio_util::compat::TokioAsyncReadCompatExt;
use zeroize::{Zeroize, Zeroizing};

pub use mux::Counters;
use mux::{FrameChan, Mux};
use circuits::{Spec, from_bits, spec, to_bits};
use ectf::SecretFp;
use gc::SecretBlocks;

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

/// Test-only deviations.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Cheat {
    #[default]
    None,
    /// N: corrupt the half-ciphertexts of 64 AND gates of a phase.
    CorruptGate(usize),
    /// N: flip control (dicing) bits of 64 AND gates of a phase.
    CorruptControlBits(usize),
    /// N: commit the mask of one AND output of a phase flipped (turns that
    /// AND into a NAND as far as the decoded values go, "logic change").
    FlipLambda(usize),
    /// N: wrong t_k for one AND gate (product check must fail).
    BadT,
    /// N: lie about one opened output mask of a phase (flips C's output).
    LieOpen(usize),
    /// N: send a garbage label for its first own input of a phase.
    BadInputLabel(usize),
    /// N: run the KOS for C's input labels with a different Δ than garbling.
    KosDelta,
    /// N: add random offsets to every check row of a phase.
    BadRows(usize),
    /// N: computes the check rows of a phase under a different salt.
    WrongSalt(usize),
    /// N: flip Y_N of a phase.
    BadYn(usize),
    /// C: report one flipped output bit of a phase to N.
    FlipOutput(usize),
    /// C: opens its key-share commitment to a different point.
    BadOpen,
}

type KosS = kos::Sender<chou_orlandi::Receiver>;
type KosR = kos::Receiver<chou_orlandi::Sender>;
type FerS = ferret::Sender<KosS>;
type FerR = ferret::Receiver<KosR>;


/// N's per-phase state.
struct NPhase {
    /// Zero-label of every wire (with Δ_A, every label).
    k: SecretBlocks,
    /// Wire masks (each reveals a wire value to whoever sees the label).
    lam: Zeroizing<Vec<bool>>,
}

/// C's per-phase state.
struct CPhase {
    tables: Vec<gc::Gate3>,
    ck: Option<gc::CheckKeys>,
    rows: Vec<u64>,
    y_n: u64,
    /// Per-session salt of the check-row hash (from the challenge seed).
    salt: u128,
    /// Opened masks: C's input wires, th wires, outputs.
    lam_c: Vec<bool>,
    lam_th: Vec<bool>,
    lam_out: Vec<bool>,
}

enum Pre {
    N {
        ph: Vec<NPhase>,
        /// KOS keys for C's input bits (phase A then B).
        cot_keys: SecretBlocks,
    },
    C {
        ph: Vec<CPhase>,
        /// KOS choice bits and messages (C's inputs are `d ⊕ choice`).
        cot_choices: Zeroizing<Vec<bool>>,
        cot_msgs: SecretBlocks,
    },
}

const CH_COTA: usize = 0; // KOS for C's input labels (N sender, Δ_A)
const CH_COTB: usize = 1; // MAC COTs (C sender, Δ_B)
const CH_SC: usize = 2; // share conversion
const CH_N2C: usize = 3; // all N→C protocol messages
const CH_C2N: usize = 4; // all C→N protocol messages
const CH_TAB: usize = 5; // N→C garbled tables (bulk: lowest priority on the link)
const N_CH: usize = 6;

/// N streams phase A's tables once this many MAC-COT bytes from C arrived
/// (C has N's OT bootstrap messages and is uploading the first part of the
/// Ferret extension), and phase B's once C is past the first part (484 184
/// bytes with mpz2 rev 8f89783 and this circuit size; measured with
/// `TWOPC_TRACE=1`), i.e. past the last small N→C Ferret message. Either gate
/// also opens when N's MAC COTs are complete, or after `TABLES_MAX_WAIT`.
const TABLES_GATE: [u64; 2] = [64 * 1024, 500_000];
const TABLES_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

const TAG_KS: &[u8] = b"routstr-twopc-v2 key-share commit";
const TAG_OPEN: &[u8] = b"routstr-twopc-ag open";
const TAG_OUT: &[u8] = b"routstr-twopc-ag output labels";
const TAG_CHI: &[u8] = b"routstr-twopc-ag chi";


/// Number of MAC COTs per phase: inputs + AND outputs + AND products.
fn macs_per_phase(s: &Spec) -> usize {
    s.circ.inputs().len() + 2 * s.circ.and_count()
}

/// Circuit-derived index lists, computed once.
struct Shape {
    ands: Vec<(usize, usize, usize)>,
    base: Vec<usize>,
}

static SHAPES: std::sync::LazyLock<[Shape; 2]> = std::sync::LazyLock::new(|| {
    let f = |p| {
        let s = spec(p);
        Shape {
            ands: gc::and_gates(&s.circ),
            base: gc::base_wires(&s.circ),
        }
    };
    [f(0), f(1)]
});

pub struct Party {
    role: Role,
    mux: Option<Mux>,
    counters: Arc<Counters>,
    ctx_a: Context,
    ctx_b: Context,
    ctx_sc: Context,
    n2c: FrameChan,
    c2n: FrameChan,
    tab: FrameChan,
    rng: StdRng,
    /// N: garbling offset Δ_A. C: MAC key Δ_B.
    delta: Block,
    kos_a_s: Option<KosS>,
    kos_a_r: Option<KosR>,
    /// MAC COTs (C = Ferret sender with Δ_B, N = receiver).
    mac_s: Option<Box<FerS>>,
    mac_r: Option<Box<FerR>>,
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
        // Labels, masks, COT keys and MAC keys go with `pre` (their own
        // `Drop`s); copies inside mpz2's OT/OLE state are out of reach.
        self.ms_share.zeroize();
        if let Some(a) = self.scalar.as_mut() {
            a.zeroize();
        }
        self.scalar = None;
        self.delta.as_mut().zeroize();
    }
}

static TRACE: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| std::env::var_os("TWOPC_TRACE").is_some());
fn tr(t0: Instant, who: &str, what: &str) {
    if *TRACE {
        eprintln!("[{who} {:8.1} ms] {what}", t0.elapsed().as_secs_f64() * 1e3);
    }
}

fn os_rng() -> StdRng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness");
    let r = StdRng::from_seed(seed);
    seed.zeroize();
    r
}

fn blocks_to_bytes(v: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 * v.len());
    for b in v {
        out.extend_from_slice(b.as_bytes());
    }
    out
}

fn bytes_to_blocks(b: &[u8]) -> Vec<Block> {
    b.chunks_exact(16).map(|c| Block::new(c.try_into().unwrap())).collect()
}

fn unpack(bytes: &[u8], n: usize) -> Vec<bool> {
    let mut b = to_bits(bytes);
    b.truncate(n);
    b
}

fn sel(bit: bool, b: Block) -> Block {
    Block::SELECT_MASK[bit as usize] & b
}

/// A challenge derived from C's seed; both parties compute it the same way.
/// Never zero (χ = 0 would make the checks vacuous): a zero value, which an
/// honest seed gives with probability 2^-128, is re-drawn deterministically
/// by appending a counter, so every non-zero first draw is unchanged.
fn chi(seed: &[u8], what: &[u8]) -> Block {
    first_nonzero(|ctr| chi_draw(seed, what, ctr))
}

fn chi_draw(seed: &[u8], what: &[u8], ctr: u32) -> Block {
    let mut h = Sha256::new().chain_update(TAG_CHI).chain_update(seed).chain_update(what);
    if ctr > 0 {
        h.update(ctr.to_be_bytes());
    }
    let h: [u8; 32] = h.finalize().into();
    Block::new(h[..16].try_into().unwrap())
}

fn first_nonzero(mut draw: impl FnMut(u32) -> Block) -> Block {
    (0u32..)
        .map(&mut draw)
        .find(|c| *c != Block::ZERO)
        .expect("a non-zero draw")
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

fn fp_from_be(be: &[u8]) -> Result<Fp> {
    let mut le: [u8; 32] = be.try_into().map_err(|_| Error::Protocol("coord".into()))?;
    le.reverse();
    let r = Fp::try_from(le).map_err(|_| Error::Protocol("non-canonical coordinate".into()));
    le.zeroize();
    r
}

fn perr<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Protocol(format!("{what}: {e}"))
}

macro_rules! rcot_send {
    ($s:expr, $ctx:expr, $n:expr) => {{
        let s = $s;
        s.alloc($n).map_err(perr("cot alloc"))?;
        let f = s.queue_send_rcot($n).map_err(perr("cot queue"))?;
        s.flush($ctx).await.map_err(perr("cot flush"))?;
        let RCOTSenderOutput { keys, .. } = f.await.map_err(perr("cot"))?;
        keys
    }};
}

macro_rules! rcot_recv {
    ($r:expr, $ctx:expr, $n:expr) => {{
        let r = $r;
        r.alloc($n).map_err(perr("cot alloc"))?;
        let f = r.queue_recv_rcot($n).map_err(perr("cot queue"))?;
        r.flush($ctx).await.map_err(perr("cot flush"))?;
        let RCOTReceiverOutput { choices, msgs, .. } = f.await.map_err(perr("cot"))?;
        (choices, msgs)
    }};
}

impl Party {
    pub async fn new<IO>(role: Role, io: IO) -> Result<Party>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // What the peer may send per channel. N (the node) is the exposed
        // party: C's honest upload is ~1.2 MB in all (Ferret on CH_COTB), a
        // few KB of KOS/ECtF traffic and well under 4 KB of protocol messages;
        // N→C-only channels accept nothing from C. C bounds N too, so a
        // malicious node cannot grow the client's memory: an honest N sends
        // 4 KB on CH_COTA, 451 KB on CH_COTB, 21 KB on CH_SC, 5.5 MB on
        // CH_N2C and 16.2 MB of tables (the circuits are fixed).
        const MIB: u64 = 1 << 20;
        let caps: [u64; N_CH] = match role {
            Role::N => [8 * MIB, 16 * MIB, 4 * MIB, 0, MIB, 0],
            Role::C => [MIB, 4 * MIB, MIB, 16 * MIB, 0, 32 * MIB],
        };
        let (mux, mut chans) = Mux::start(io, N_CH, &[CH_TAB], &caps);
        let counters = mux.counters.clone();
        let mut take = |i: usize| std::mem::replace(&mut chans[i], tokio::io::duplex(1).0);
        let ctx_a = Context::new_single_threaded(take(CH_COTA).compat());
        let ctx_b = Context::new_single_threaded(take(CH_COTB).compat());
        let ctx_sc = Context::new_single_threaded(take(CH_SC).compat());
        let n2c = FrameChan::new(take(CH_N2C));
        let tab = FrameChan::new(take(CH_TAB));
        // N never receives a protocol message over a few hundred bytes on C→N.
        let c2n = match role {
            Role::N => FrameChan::with_max_msg(take(CH_C2N), 1 << 16),
            Role::C => FrameChan::new(take(CH_C2N)),
        };

        let mut rng = os_rng();
        let mut delta = Block::random(&mut rng);
        delta.set_lsb(true);
        let sc = match role {
            Role::C => ectf::Sc::new_sender(&mut rng),
            Role::N => ectf::Sc::new_receiver(&mut rng),
        };
        let fcfg = || {
            ferret::FerretConfig::builder()
                .lpn_type(ferret::LpnType::Regular)
                .build()
                .expect("ferret config")
        };
        let (mut kos_a_s, mut kos_a_r, mut mac_s, mut mac_r) = (None, None, None, None);
        match role {
            Role::N => {
                kos_a_s = Some(kos::Sender::new(
                    kos::SenderConfig::default(),
                    delta,
                    chou_orlandi::Receiver::new_with_seed(rng.random()),
                ));
                let kr = kos::Receiver::new(
                    kos::ReceiverConfig::default(),
                    chou_orlandi::Sender::new_with_seed(rng.random()),
                );
                mac_r = Some(Box::new(ferret::Receiver::new(fcfg(), rng.random(), kr)));
            }
            Role::C => {
                kos_a_r = Some(kos::Receiver::new(
                    kos::ReceiverConfig::default(),
                    chou_orlandi::Sender::new_with_seed(rng.random()),
                ));
                let ks = kos::Sender::new(
                    kos::SenderConfig::default(),
                    delta,
                    chou_orlandi::Receiver::new_with_seed(rng.random()),
                );
                mac_s = Some(Box::new(ferret::Sender::new(fcfg(), rng.random(), ks)));
            }
        }
        Ok(Party {
            role,
            mux: Some(mux),
            counters,
            ctx_a,
            ctx_b,
            ctx_sc,
            n2c,
            tab,
            c2n,
            rng,
            delta,
            kos_a_s,
            kos_a_r,
            mac_s,
            mac_r,
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

    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }

    pub fn take_timings(&mut self) -> Vec<StepTiming> {
        std::mem::take(&mut self.timings)
    }

    pub async fn close(mut self) {
        let mux = self.mux.take();
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

    #[cfg(test)]
    fn cheat(&self) -> Cheat {
        self.cheat
    }
    #[cfg(not(test))]
    #[inline(always)]
    fn cheat(&self) {}

    /// Input-independent preprocessing.
    pub async fn preprocess(&mut self) -> Result<()> {
        self.check_stage(Stage::New, "preprocess must be first")?;
        if *TRACE {
            let c = self.counters.clone();
            let who = if self.role == Role::C { "C" } else { "N" };
            tokio::spawn(async move {
                let t0 = Instant::now();
                let mut last = (0, 0);
                for _ in 0..200 {
                    let v = (c.ch_recv(CH_COTB), c.ch_recv(CH_TAB));
                    if v != last {
                        eprintln!("[{who} {:8.1} ms] recv cotb={} tab={}", t0.elapsed().as_secs_f64() * 1e3, v.0, v.1);
                        last = v;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            });
        }
        let m = self.mark();
        let r = match self.role {
            Role::N => self.preprocess_n().await,
            Role::C => self.preprocess_c().await,
        };
        let r = self.fail(r);
        self.record("preprocess", m);
        r?;
        self.stage = Stage::Preprocessed;
        Ok(())
    }

    async fn preprocess_n(&mut self) -> Result<()> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let delta = self.delta;
        let mut grng = StdRng::from_seed(self.rng.random());
        let c_bits = spec(0).c_bits + spec(1).c_bits;
        let n_mac = macs_per_phase(spec(0)) + macs_per_phase(spec(1)) + 128;

        let garble = tokio::task::spawn_blocking(move || {
            (0..2)
                .map(|p| {
                    let s = spec(p);
                    let in_keys = SecretBlocks((0..s.circ.inputs().len()).map(|_| Block::random(&mut grng)).collect());
                    let (k, tables) = gc::garble(&s.circ, delta, &in_keys, p, &mut grng);
                    (SecretBlocks(k), tables)
                })
                .collect::<Vec<_>>()
        });

        #[allow(unused_mut)]
        let mut kos_delta_cheat = false;
        #[cfg(test)]
        if cheat == Cheat::KosDelta {
            kos_delta_cheat = true;
        }
        if kos_delta_cheat {
            let mut d2 = Block::random(&mut self.rng);
            d2.set_lsb(true);
            self.kos_a_s = Some(kos::Sender::new(
                kos::SenderConfig::default(),
                d2,
                chou_orlandi::Receiver::new_with_seed(self.rng.random()),
            ));
        }

        let Party {
            ctx_a,
            ctx_b,
            ctx_sc,
            n2c,
            c2n,
            tab,
            kos_a_s,
            mac_r,
            sc,
            counters,
            ..
        } = self;

        // Garble and stream the tables while the OTs run, scheduled around C's
        // MAC-COT upload (Ferret, ~1.16 MB C→N, in two parts separated by a
        // small N→C message). Any small N→C message sent after the tables sits
        // behind them in the link buffers and stalls an OT round trip, so
        // phase A's tables wait until C is uploading the first part (N's OT
        // setup messages have arrived) and phase B's until the second part
        // (`TABLES_GATE`). The download then overlaps C's upload.
        let mac_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = |threshold: u64| {
            let counters = counters.clone();
            let mac_done = mac_done.clone();
            async move {
                let t0 = Instant::now();
                while counters.ch_recv(CH_COTB) < threshold
                    && !mac_done.load(std::sync::atomic::Ordering::Relaxed)
                    && t0.elapsed() < TABLES_MAX_WAIT
                {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            }
        };
        let mut gates = vec![gate(TABLES_GATE[0]), gate(TABLES_GATE[1])].into_iter();
        let send_fut = async {
            let g = garble.await.map_err(perr("garbling task"))?;
            #[allow(unused_mut)]
            let mut keep = Vec::new();
            #[allow(unused_mut)]
            for (p, (k, mut tables)) in g.into_iter().enumerate() {
                #[cfg(test)]
                if cheat == Cheat::CorruptGate(p) {
                    let n = tables.len();
                    for g in 0..64 {
                        let t = &mut tables[g * (n / 64)];
                        t.g[0] ^= 1;
                        t.g[2] ^= 1 << 40;
                    }
                }
                #[cfg(test)]
                if cheat == Cheat::CorruptControlBits(p) {
                    let n = tables.len();
                    for g in 0..64 {
                        tables[g * (n / 64)].z ^= 0b00011;
                    }
                }
                if let Some(g) = gates.next() {
                    g.await;
                }
                tab.send(&gc::tables_to_bytes(&tables)).await?;
                keep.push(k);
            }
            Ok::<_, Error>(keep)
        };
        let cot_a_fut = async {
            let keys = rcot_send!(kos_a_s.as_mut().unwrap(), ctx_a, c_bits);
            Ok::<_, Error>(SecretBlocks(keys))
        };
        let cot_b_fut = async {
            let (r, m) = rcot_recv!(mac_r.as_mut().unwrap().as_mut(), ctx_b, n_mac);
            mac_done.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok::<_, Error>((Zeroizing::new(r), SecretBlocks(m)))
        };
        let sc_fut = sc.preprocess(ctx_sc);
        let (keys, cot_keys, macs, scr) = futures::join!(send_fut, cot_a_fut, cot_b_fut, sc_fut);
        let keys = keys?;
        let cot_keys = cot_keys?;
        let (r_bits, r_macs) = macs?;
        scr?;
        if cot_keys.len() != c_bits || r_bits.len() != n_mac {
            return Err(Error::Protocol("cot count".into()));
        }

        // Commit (Fix) λ for the base wires and t for every AND gate.
        let mut d_bits = Vec::with_capacity(n_mac);
        let mut st = Vec::new(); // (lam, mac, t_mac) per phase
        let mut off = 0usize;
        for (p, k) in keys.iter().enumerate() {
            let shape = &SHAPES[p];
            let s = spec(p);
            let nb = shape.base.len();
            #[allow(unused_mut)]
            let mut base_lam: Vec<bool> = shape.base.iter().map(|&w| k[w].lsb()).collect();
            #[cfg(test)]
            if cheat == Cheat::FlipLambda(p) {
                // An internal AND gate (half-way through the circuit).
                let i = s.circ.inputs().len() + s.circ.and_count() / 2;
                base_lam[i] = !base_lam[i];
            }
            let base_mac = SecretBlocks(r_macs[off..off + nb].to_vec());
            for (i, l) in base_lam.iter().enumerate() {
                d_bits.push(l ^ r_bits[off + i]);
            }
            off += nb;
            let (lam, mac) = gc::propagate_n(&s.circ, &base_lam, &base_mac);
            let na = shape.ands.len();
            let mut t_mac = Vec::with_capacity(na);
            for (a, &(i, j, _)) in shape.ands.iter().enumerate() {
                #[allow(unused_mut)]
                let mut t = lam[i] & lam[j];
                #[cfg(test)]
                if cheat == Cheat::BadT && p == 1 && a == 1000 {
                    t = !t;
                }
                d_bits.push(t ^ r_bits[off + a]);
                t_mac.push(r_macs[off + a]);
            }
            off += na;
            st.push((Zeroizing::new(lam), SecretBlocks(mac), SecretBlocks(t_mac)));
        }
        let mask_bits = &r_bits[off..off + 128];
        let mask_macs = &r_macs[off..off + 128];
        n2c.send(&from_bits(&d_bits)).await?;

        // Challenge.
        let seed = c2n.recv_exact(32).await?;
        let t_seed = Instant::now();
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck = [chi(&seed, b"check0"), chi(&seed, b"check1")];
        let salt = u128::from_le_bytes(chi(&seed, b"check-salt").to_bytes());

        // Product check, openings, consistency-check material (CPU, blocking).
        let mask_bits = Zeroizing::new(mask_bits.to_vec());
        let mask_macs = SecretBlocks(mask_macs.to_vec());
        drop((r_bits, r_macs));
        let (st, keys, msgs) = tokio::task::spawn_blocking(move || {
            // Check rows and Y_N per phase.
            let rows_of = |p: usize| -> (Vec<u8>, Vec<u8>) {
                let (lam, mac, t_mac) = &st[p];
                let s = spec(p);
                let pw = gc::powers(chi_ck[p], t_mac.len());
                #[allow(unused_mut)]
                let mut salt_p = salt;
                #[cfg(test)]
                if cheat == Cheat::WrongSalt(p) {
                    salt_p ^= 1 << 7;
                }
                let cm = gc::check_material(
                    &s.circ,
                    salt_p,
                    p,
                    &SHAPES[p].ands,
                    &SHAPES[p].base,
                    &keys[p],
                    lam,
                    mac,
                    t_mac,
                    &pw,
                    delta,
                );
                #[allow(unused_mut)]
                let mut y_n = cm.y_n;
                #[cfg(test)]
                if cheat == Cheat::BadYn(p) {
                    y_n ^= 1;
                }
                #[allow(unused_mut)]
                let mut rows = cm.rows;
                #[cfg(test)]
                if cheat == Cheat::BadRows(p) {
                    let mut r = os_rng();
                    for x in rows.iter_mut() {
                        *x ^= r.random::<u64>();
                    }
                }
                (rows.iter().flat_map(|r| r.to_le_bytes()).collect(), y_n.to_le_bytes().to_vec())
            };
            let mut msgs: Vec<Vec<u8>> = Vec::new();
            let rows = std::thread::scope(|sc| {
                let r0 = sc.spawn(|| rows_of(0));
                let r1 = sc.spawn(|| rows_of(1));
                let mut acc = (Block::ZERO, Block::ZERO);
                for (p, (lam, mac, t_mac)) in st.iter().enumerate() {
                    let pw = gc::powers(chi_dv.gfmul(Block::new(((p as u128) + 1).to_le_bytes())), t_mac.len());
                    gc::dvzk_prover_acc(&SHAPES[p].ands, lam, mac, t_mac, &pw, &mut acc);
                }
                // Random mask a* = Σ r_i X^i.
                let mut a_star = Block::ZERO;
                let mut m_star = Block::ZERO;
                for i in 0..128 {
                    a_star ^= sel(mask_bits[i], Block::MONOMIAL[i]);
                    m_star ^= Block::MONOMIAL[i].gfmul(mask_macs[i]);
                }
                let u = acc.0 ^ m_star;
                let v = acc.1 ^ a_star;
                msgs.push(blocks_to_bytes(&[u, v]));

                // Openings: C's inputs, th, outputs (both phases), one MAC hash.
                let mut bits = Vec::new();
                let mut h = Sha256::new();
                h.update(TAG_OPEN);
                for (p, (lam, mac, _)) in st.iter().enumerate() {
                    let s = spec(p);
                    let n_feed = s.circ.feed_count();
                    let wires = s
                        .c_range()
                        .chain(s.th_range())
                        .chain(s.circ.outputs())
                        .collect::<Vec<_>>();
                    for (idx, &w) in wires.iter().enumerate() {
                        #[allow(unused_mut)]
                        let mut b = lam[w];
                        #[cfg(test)]
                        if cheat == Cheat::LieOpen(p) && w == n_feed - 1 && idx > 0 {
                            b = !b;
                        }
                        let _ = (idx, n_feed);
                        bits.push(b);
                        h.update(mac[w].as_bytes());
                    }
                }
                let hd: [u8; 32] = h.finalize().into();
                let mut open = from_bits(&bits);
                open.extend_from_slice(&hd);
                msgs.push(open);
                [r0.join().expect("rows thread"), r1.join().expect("rows thread")]
            });
            for (r, y) in rows {
                msgs.push(r);
                msgs.push(y);
            }

            (st, keys, msgs)
        })
        .await
        .map_err(perr("preprocess task"))?;
        tr(t_seed, "N", "post-seed compute done");
        for msg in msgs {
            n2c.send(&msg).await?;
        }

        let ph = st
            .into_iter()
            .zip(keys)
            .map(|((lam, _mac, _t_mac), k)| NPhase { k, lam })
            .collect();
        self.pre = Some(Pre::N { ph, cot_keys });
        Ok(())
    }

    async fn preprocess_c(&mut self) -> Result<()> {
        let delta_b = self.delta;
        let own_bits = spec(0).c_bits + spec(1).c_bits;
        let n_mac = macs_per_phase(spec(0)) + macs_per_phase(spec(1)) + 128;
        let seed: [u8; 32] = self.rng.random();
        let Party {
            ctx_a,
            ctx_b,
            ctx_sc,
            n2c,
            c2n,
            tab,
            kos_a_r,
            mac_s,
            sc,
            ..
        } = self;

        let t0 = Instant::now();
        let recv_fut = async {
            let mut t = Vec::new();
            for p in 0..2 {
                let s = spec(p);
                let n = s.circ.and_count();
                let b = tab.recv_exact(gc::tables_len(n)).await?;
                tr(t0, "C", "tables phase recv");
                t.push(gc::tables_from_bytes(&b, n).ok_or_else(|| Error::Protocol("tables".into()))?);
            }
            let d = n2c.recv_exact((n_mac - 128).div_ceil(8)).await?;
            tr(t0, "C", "d recv");
            Ok::<_, Error>((t, unpack(&d, n_mac - 128)))
        };
        let cot_a_fut = async {
            let (c, m) = rcot_recv!(kos_a_r.as_mut().unwrap(), ctx_a, own_bits);
            tr(t0, "C", "kos (input) done");
            Ok::<_, Error>((c, m))
        };
        let cot_b_fut = async {
            let keys = rcot_send!(mac_s.as_mut().unwrap().as_mut(), ctx_b, n_mac);
            tr(t0, "C", "mac cot done");
            Ok::<_, Error>(keys)
        };
        let sc_fut = async {
            let r = sc.preprocess(ctx_sc).await;
            tr(t0, "C", "ole done");
            r
        };
        let (rcv, cr, kb, scr) = futures::join!(recv_fut, cot_a_fut, cot_b_fut, sc_fut);
        let (tables, d) = rcv?;
        let (cot_choices, cot_msgs) = cr?;
        let kb = SecretBlocks(kb?);
        scr?;
        let (cot_choices, cot_msgs) = (Zeroizing::new(cot_choices), SecretBlocks(cot_msgs));
        if kb.len() != n_mac || cot_choices.len() != own_bits {
            return Err(Error::Protocol("cot count".into()));
        }
        // Keys of the committed values: K[x] = K[r] ⊕ d·Δ_B.
        // (The last 128 COTs stay random: they mask the product check.)
        let kfix = SecretBlocks(
            kb.iter()
                .enumerate()
                .map(|(i, k)| if i < d.len() { *k ^ sel(d[i], delta_b) } else { *k })
                .collect(),
        );
        drop(kb);
        // The χ challenge only after N's tables and commitments are in.
        c2n.send(&seed).await?;
        tr(t0, "C", "seed sent");

        // Receive the rest while computing the keys.
        let recv2 = async {
            let dv = n2c.recv_exact(32).await?;
            let n_open: usize = (0..2)
                .map(|p| {
                    let s = spec(p);
                    s.c_bits + s.th_bits + s.out_bits
                })
                .sum();
            let open = n2c.recv_exact(n_open.div_ceil(8) + 32).await?;
            let mut rows = Vec::new();
            for p in 0..2 {
                let r = n2c.recv_exact(8 * SHAPES[p].base.len()).await?;
                let y = n2c.recv_exact(8).await?;
                let r: Vec<u64> = r.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
                rows.push((r, u64::from_le_bytes(y[..].try_into().unwrap())));
            }
            Ok::<_, Error>((dv, open, rows))
        };
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck = [chi(&seed, b"check0"), chi(&seed, b"check1")];
        let salt = u128::from_le_bytes(chi(&seed, b"check-salt").to_bytes());
        let compute = tokio::task::spawn_blocking(move || {
            let mut off = 0;
            let mut per = Vec::new();
            let mut acc = Block::ZERO;
            for p in 0..2 {
                let s = spec(p);
                let shape = &SHAPES[p];
                let nb = shape.base.len();
                let key = SecretBlocks(gc::propagate_c(&s.circ, &kfix[off..off + nb], delta_b));
                off += nb;
                let na = shape.ands.len();
                let t_key = &kfix[off..off + na];
                off += na;
                let pw = gc::powers(chi_dv.gfmul(Block::new(((p as u128) + 1).to_le_bytes())), na);
                gc::dvzk_verifier_acc(&shape.ands, &key, t_key, delta_b, &pw, &mut acc);
                let pw = gc::powers(chi_ck[p], na);
                let ck = gc::check_keys(&shape.ands, &key, t_key, &pw);
                per.push((key, ck));
            }
            let mut k_star = Block::ZERO;
            for i in 0..128 {
                k_star ^= Block::MONOMIAL[i].gfmul(kfix[off + i]);
            }
            (per, acc ^ k_star)
        });
        let (r2, comp) = futures::join!(recv2, compute);
        tr(t0, "C", "rows recv + keys computed");
        let (dv, open, rows) = r2?;
        let (per, w) = comp.map_err(perr("preprocess task"))?;

        // Product check: Σχ B ⊕ K* = U ⊕ V·Δ_B.
        let uv = bytes_to_blocks(&dv);
        if w != uv[0] ^ uv[1].gfmul(delta_b) {
            return Err(Error::Abort("AND-product (t = λ_i·λ_j) check failed".into()));
        }

        // Openings.
        let n_open = open.len() - 32;
        let mut bits = to_bits(&open[..n_open]).into_iter();
        let mut h = Sha256::new();
        h.update(TAG_OPEN);
        let mut ph = Vec::new();
        for (p, ((key, ck), (rws, y_n))) in per.into_iter().zip(rows).enumerate() {
            let s = spec(p);
            let mut take = |r: std::ops::Range<usize>| -> Vec<bool> {
                r.map(|w| {
                    let b = bits.next().unwrap_or(false);
                    h.update((key[w] ^ sel(b, delta_b)).as_bytes());
                    b
                })
                .collect()
            };
            let lam_c = take(s.c_range());
            let lam_th = take(s.th_range());
            let lam_out = take(s.circ.outputs());
            ph.push(CPhase {
                tables: Vec::new(),
                ck: Some(ck),
                rows: rws,
                y_n,
                salt,
                lam_c,
                lam_th,
                lam_out,
            });
            let _ = p;
        }
        let hd: [u8; 32] = h.finalize().into();
        if hd[..] != open[n_open..] {
            return Err(Error::Abort("opened masks do not match their MACs".into()));
        }
        for (cp, t) in ph.iter_mut().zip(tables) {
            cp.tables = t;
        }
        self.pre = Some(Pre::C {
            ph,
            cot_choices,
            cot_msgs,
        });
        Ok(())
    }

    /// Joint P-256 key share: C commits to `P_C`, N sends `P_N`, C opens.
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
        let mut a = random_scalar(&mut self.rng);
        let p_own = ProjectivePoint::GENERATOR * a;
        let own = encode_point(&p_own);
        self.scalar = Some(a);
        a.zeroize();
        let joint = match self.role {
            Role::C => {
                let nonce: [u8; 32] = self.rng.random();
                let com: [u8; 32] = Sha256::new()
                    .chain_update(TAG_KS)
                    .chain_update(own)
                    .chain_update(nonce)
                    .finalize()
                    .into();
                self.c2n.send(&com).await?;
                let pn = self.n2c.recv_exact(65).await?;
                let p_n = parse_point(&pn)?;
                #[allow(unused_mut)]
                let mut open = own.to_vec();
                #[cfg(test)]
                if self.cheat == Cheat::BadOpen {
                    let t = ProjectivePoint::GENERATOR * Scalar::from(7u64);
                    open = encode_point(&(t - p_n)).to_vec();
                }
                open.extend_from_slice(&nonce);
                self.c2n.send(&open).await?;
                p_own + p_n
            }
            Role::N => {
                let com = self.c2n.recv_exact(32).await?;
                self.n2c.send(&own).await?;
                let open = self.c2n.recv_exact(97).await?;
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

    /// ECtF + phase A.
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
        // This party's ECDHE share a·S and everything derived from it are
        // overwritten when they go out of scope, error paths included.
        let a = Zeroizing::new(self.scalar.take().ok_or(Error::State("no scalar"))?);
        let q = Zeroizing::new((s * *a).to_affine());
        drop(a);
        let ep = Zeroizing::new(q.to_encoded_point(false));
        drop(q);
        let x = SecretFp(fp_from_be(ep.x().ok_or_else(|| Error::Protocol("identity".into()))?)?);
        let y = SecretFp(fp_from_be(ep.y().ok_or_else(|| Error::Protocol("identity".into()))?)?);
        drop(ep);

        let m = self.mark();
        let share = SecretFp(self.sc.point_add_x(&mut self.ctx_sc, x.0, y.0).await?);
        drop((x, y));
        self.record("ectf", m);
        let mut x_le: [u8; 32] = share.0.into();
        drop(share);

        let mut r_mask: [u8; 32] = self.rng.random();
        let mut own = Zeroizing::new(Vec::with_capacity(64));
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

    /// Phase B.
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
        let mut mask = Zeroizing::new(vec![0u8; mask_len]);
        self.rng.fill(&mut mask[..]);
        let mut own = Zeroizing::new(Vec::with_capacity(32 + mask_len));
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

    /// One phase. Returns the decoded output bytes (only after the checks).
    async fn run_phase(&mut self, phase: usize, own: Zeroizing<Vec<u8>>, th: [u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let name = ["phase_a", "phase_b"][phase];
        let m = self.mark();
        let r = match self.role {
            Role::N => self.phase_n(phase, own, th).await,
            Role::C => self.phase_c(phase, own, th).await,
        };
        self.record(name, m);
        r
    }

    async fn phase_n(&mut self, phase: usize, own: Zeroizing<Vec<u8>>, th: [u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let s = spec(phase);
        let own_bits = Zeroizing::new(to_bits(&own));
        if own_bits.len() != s.n_bits {
            return Err(Error::Input("input length".into()));
        }
        let th_bits = to_bits(&th);
        let delta = self.delta;
        let c_off = if phase == 0 { 0 } else { spec(0).c_bits };
        let Some(Pre::N { ph, cot_keys }) = self.pre.as_mut() else {
            return Err(Error::State("not preprocessed"));
        };
        let st = std::mem::replace(
            &mut ph[phase],
            NPhase {
                k: SecretBlocks::default(),
                lam: Zeroizing::new(Vec::new()),
            },
        );
        if st.k.is_empty() {
            return Err(Error::State("phase already used"));
        }
        let cot = SecretBlocks(cot_keys[c_off..c_off + s.c_bits].to_vec());

        // Own and transcript-hash labels, sent at once.
        let mut labels = Vec::with_capacity(s.n_bits + s.th_bits);
        for (w, b) in s.n_range().zip(own_bits.iter()) {
            labels.push(st.k[w] ^ sel(*b, delta));
        }
        for (w, b) in s.th_range().zip(&th_bits) {
            labels.push(st.k[w] ^ sel(*b, delta));
        }
        #[cfg(test)]
        if cheat == Cheat::BadInputLabel(phase) {
            labels[0] = labels[0] ^ Block::new([0x5a; 16]);
        }
        self.n2c.send(&blocks_to_bytes(&labels)).await?;
        let d = self.c2n.recv_exact(s.c_bits.div_ceil(8)).await?;
        let d = unpack(&d, s.c_bits);
        let adj: Vec<Block> = s
            .c_range()
            .enumerate()
            .map(|(j, w)| st.k[w] ^ cot[j] ^ sel(d[j], delta))
            .collect();
        self.n2c.send(&blocks_to_bytes(&adj)).await?;

        // C's verdict and output pointer bits.
        let msg = self.c2n.recv().await?;
        if msg.first() != Some(&1) {
            return Err(Error::Abort("peer aborted (consistency check failed on C)".into()));
        }
        if msg.len() != 1 + s.out_bits.div_ceil(8) + 32 {
            return Err(Error::Protocol("output message length".into()));
        }
        let pbits = unpack(&msg[1..1 + s.out_bits.div_ceil(8)], s.out_bits);
        let mut h = Sha256::new();
        h.update(TAG_OUT);
        h.update([phase as u8]);
        let mut v = Vec::with_capacity(s.out_bits);
        for (w, pb) in s.circ.outputs().zip(&pbits) {
            let lab = st.k[w] ^ sel(*pb ^ st.lam[w], delta);
            h.update(lab.as_bytes());
            v.push(*pb ^ st.lam[w]);
        }
        let hd: [u8; 32] = h.finalize().into();
        if hd[..] != msg[msg.len() - 32..] {
            return Err(Error::Abort("output labels do not authenticate".into()));
        }
        let out = Zeroizing::new(from_bits(&v));
        v.zeroize();
        Ok(out)
    }

    async fn phase_c(&mut self, phase: usize, own: Zeroizing<Vec<u8>>, th: [u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let s = spec(phase);
        let own_bits = Zeroizing::new(to_bits(&own));
        if own_bits.len() != s.c_bits {
            return Err(Error::Input("input length".into()));
        }
        let th_bits = to_bits(&th);
        let delta_b = self.delta;
        let c_off = if phase == 0 { 0 } else { spec(0).c_bits };
        let Some(Pre::C {
            ph,
            cot_choices,
            cot_msgs,
        }) = self.pre.as_mut()
        else {
            return Err(Error::State("not preprocessed"));
        };
        let st = ph[phase].ck.take().ok_or(Error::State("phase already used"))?;
        let tables = std::mem::take(&mut ph[phase].tables);
        let rows = std::mem::take(&mut ph[phase].rows);
        let y_n = ph[phase].y_n;
        let salt = ph[phase].salt;
        let lam_c = ph[phase].lam_c.clone();
        let lam_th = ph[phase].lam_th.clone();
        let lam_out = ph[phase].lam_out.clone();
        let b = Zeroizing::new(cot_choices[c_off..c_off + s.c_bits].to_vec());
        let msgs = SecretBlocks(cot_msgs[c_off..c_off + s.c_bits].to_vec());

        let d: Vec<bool> = own_bits.iter().zip(b.iter()).map(|(x, r)| x ^ r).collect();
        self.c2n.send(&from_bits(&d)).await?;
        let gl = bytes_to_blocks(&self.n2c.recv_exact(16 * (s.n_bits + s.th_bits)).await?);
        let el = bytes_to_blocks(&self.n2c.recv_exact(16 * s.c_bits).await?);
        // Active labels: with N's zero-labels and Δ_A they give C's inputs.
        let mut inl = SecretBlocks(vec![Block::ZERO; s.circ.inputs().len()]);
        for (j, w) in s.c_range().enumerate() {
            inl[w] = el[j] ^ msgs[j];
        }
        for (j, w) in s.n_range().chain(s.th_range()).enumerate() {
            inl[w] = gl[j];
        }

        let ok_in = s.c_range().enumerate().all(|(j, w)| inl[w].lsb() == own_bits[j] ^ lam_c[j])
            && s.th_range().enumerate().all(|(j, w)| inl[w].lsb() == th_bits[j] ^ lam_th[j]);

        let circ = s.circ.clone();
        let (ok_check, out_labels) = tokio::task::spawn_blocking(move || {
            let l = SecretBlocks(gc::evaluate(&circ, &inl, &tables, phase));
            drop(inl);
            let ok = gc::run_check(salt, phase, &SHAPES[phase].ands, &SHAPES[phase].base, &l, &st, &rows, y_n, delta_b);
            let out = SecretBlocks(circ.outputs().map(|w| l[w]).collect());
            (ok, out)
        })
        .await
        .map_err(perr("eval task"))?;

        if !ok_in || !ok_check {
            let _ = self.c2n.send(&[0u8]).await;
            return Err(Error::Abort(if !ok_in {
                "input label pointer bits do not match the opened masks".into()
            } else {
                "garbled-circuit consistency check failed".into()
            }));
        }
        // Decode with the authenticated masks; then report to N.
        let mut v: Vec<bool> = out_labels.iter().zip(&lam_out).map(|(l, m)| l.lsb() ^ m).collect();
        #[allow(unused_mut)]
        let mut pbits: Vec<bool> = out_labels.iter().map(|l| l.lsb()).collect();
        let mut h = Sha256::new();
        h.update(TAG_OUT);
        h.update([phase as u8]);
        for l in out_labels.iter() {
            h.update(l.as_bytes());
        }
        let hd: [u8; 32] = h.finalize().into();
        #[cfg(test)]
        if cheat == Cheat::FlipOutput(phase) {
            pbits[100] = !pbits[100];
        }
        let mut msg = vec![1u8];
        msg.extend_from_slice(&from_bits(&pbits));
        msg.extend_from_slice(&hd);
        self.c2n.send(&msg).await?;
        let out = Zeroizing::new(from_bits(&v));
        v.zeroize();
        Ok(out)
    }
}

/// Bytes of the protocol messages per session, by direction, as computed
/// from the circuit sizes (for reports). Excludes OT extension traffic.
pub fn message_sizes() -> (usize, usize) {
    let mut n2c = 0;
    let mut c2n = 0;
    for p in 0..2 {
        let s = spec(p);
        n2c += gc::tables_len(s.circ.and_count()); // three-halves tables
        n2c += macs_per_phase(s).div_ceil(8); // d bits (approx; one message)
        n2c += 8 * SHAPES[p].base.len() + 8; // check rows + Y_N (64-bit)
        n2c += (s.c_bits + s.th_bits + s.out_bits).div_ceil(8);
        n2c += 16 * (s.n_bits + s.th_bits + s.c_bits); // online labels
        c2n += s.c_bits.div_ceil(8) + 1 + s.out_bits.div_ceil(8) + 32;
    }
    n2c += 32 + 32;
    c2n += 32;
    (c2n, n2c)
}
