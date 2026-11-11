//! Two-party TLS 1.3 key schedule, version `split-public-1` (protocol v3,
//! `PROTOCOL-V3.md` §4; `docs/TWOPC-DESIGN.md`, `docs/TWOPC-NODE-GARBLING.md`).
//! Only N garbles (authenticated garbling with garbler-held masks and an
//! IT-MAC consistency check), and the garbled circuit holds only the part of
//! the key schedule that needs a secret: the HMAC key-pad states and the outer
//! compressions.
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
//! | IS_HS, IS_dHS, IS_MS, IS_c0 (inner key-pad states) | yes | yes |
//!
//! # API
//!
//! ```ignore
//! let mut p = Party::new(Role::C, io).await?;   // io: futures AsyncRead + AsyncWrite; exchanges VERSION_TAG
//! p.preprocess().await?;                         // input independent (pre-warm)
//! let joint: [u8; 65] = p.key_share().await?;    // commit-then-open joint P-256 share
//! let hs: HsSecrets = p.handshake(&server_share, th_sh).await?;  // ECtF + stages A1–A3
//! let ap: ApOut = p.application(th_sf).await?;   // stages B1, B2 (with the anchors)
//! p.close().await;
//! ```
//!
//! `Party::new` needs a running tokio runtime (it spawns the channel
//! multiplexer). It writes [`VERSION_TAG`] as the first bytes on the
//! transport and reads the peer's; anything else is
//! [`Error::VersionMismatch`] (`twopc_version_mismatch`). `close` flushes the
//! transport; `take_timings` returns per-step wall time and transport bytes.
//!
//! The library sets no deadlines: a receive waits until the peer's data or
//! EOF arrives, so a half-open transport stalls a step. Callers bound each
//! step themselves (the sidecar and the SDK do; `cu-2pc` has a per-step
//! watchdog).
//!
//! # Protocol
//!
//! `HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))` with `f` the SHA-256 compression
//! function. Every HKDF message of the key schedule is public, so the garbled
//! circuit ([`circuits::Split`], one circuit evaluated in five stages)
//! computes only `IS_k`, `OS_k`, the outer compressions and the anchors.
//! `IS_k` is a **public output** of its stage. Both parties compute the inner
//! digests `d = f(IS_k, m)` in the clear; N sends the labels of the digest's
//! input wires and C pins them with pointer checks against opened,
//! authenticated masks. `OS_k` never leaves the circuit.
//!
//! Garbling, the IT-MACs on N's masks, the product check and the AND-gate
//! consistency check are in [`gc`]; the check runs **per stage**, over exactly
//! that stage's AND gates, before any output of the stage is decoded, reported
//! or used.
//!
//! * **Preprocess.** N garbles the circuit and streams the tables. Random
//!   COTs with C as sender (Δ_B; Ferret over KOS) authenticate N's masks and
//!   the AND products (`Fix`). C sends its challenge seed only after the
//!   tables and commitments arrived. N then sends the product check, the
//!   opened masks (C's input wires, the digest input wires, every output that
//!   C may decode) with one hash of their MACs, per stage the check rows and
//!   `Y_N`, and the *label-check pairs*: for every output wire that C reports
//!   to N, two salted 128-bit hashes of its two labels. KOS COTs with N as
//!   sender (Δ_A) cover C's 256 input bits.
//! * **Online, per stage.** C gets its input labels (stage A1: `d = x ⊕ b`,
//!   then N's corrections; later stages: the digest labels), checks their
//!   pointer bits, evaluates, runs the stage's consistency check, checks the
//!   label-check pair of every output wire it is about to report, and only
//!   then sends one message: the pointer bits of the outputs N may know and
//!   one hash over their labels. N checks the hash (C cannot report a wrong
//!   bit without an inactive label), decodes `IS_k`, computes the next
//!   stage's inner digests and answers with their labels. One round trip per
//!   stage.
//!
//! # Security (sketch; `docs/TWOPC-DESIGN.md` has the argument and its limits)
//!
//! * **Malicious N** is held stage by stage: an AND gate evaluated
//!   inconsistently with the committed masks is caught by that stage's check
//!   (≤ 2^-63 per stage). N's remaining power is selective failure: one
//!   observable abort per stage. The label-check pairs make N commit to the
//!   labels it expects *before* it sees anything derived from them, so the
//!   report hash carries no information beyond that abort. A digest label for
//!   another bit fails the pointer check, whatever C's secrets are.
//! * **Malicious C** cannot report a wrong output bit (it needs an inactive
//!   label, i.e. Δ_A) and has exactly one label per digest input wire, the one
//!   N computed from the `IS_k` C reported under its labels.
//! * **Both parties see `IS_k`.** Beyond "HMAC-SHA256 is a PRF" this needs the
//!   two assumptions of Bellare's HMAC proof, used directly: `f` keyed by its
//!   chaining input is a PRF, and `OS_k` is pseudorandom given `IS_k`.
//! * **Inputs are never revealed.** ECtF is semi-honest A2M/M2A.

pub mod circuits;

mod ectf;
pub mod gc;
mod mux;
#[doc(hidden)]
pub mod testutil;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::LazyLock;
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

use circuits::{HS_STAGES, N_STAGES, OutKind, Split, from_bits, to_bits};
use ectf::SecretFp;
use gc::SecretBlocks;
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
    /// The peer's first bytes were not [`VERSION_TAG`]: it speaks another
    /// version of the two-party key schedule (or another protocol). The
    /// field is what was read up to the first differing byte, in hex. The
    /// message starts with the error code `twopc_version_mismatch`.
    #[error("twopc_version_mismatch: this side speaks routstr-2pc/split-public-1, the peer's first bytes were 0x{0}")]
    VersionMismatch(String),
}

/// The error code of [`Error::VersionMismatch`], as callers report it.
pub const VERSION_MISMATCH: &str = "twopc_version_mismatch";

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
    /// Public inner-digest input bits (labels chosen by N, pinned by C).
    pub digest_input_bits: usize,
    pub output_bits: usize,
}

/// The garbled circuit.
pub fn circuit_stats() -> CircuitStats {
    let sp = &*circuits::SPLIT;
    CircuitStats {
        name: "split-public-1",
        and_gates: sp.circ.and_count(),
        xor_gates: sp.circ.xor_count(),
        compressions: sp.compressions,
        c_input_bits: sp.xc.len(),
        n_input_bits: sp.xn.len(),
        digest_input_bits: sp.dig.iter().map(|d| d.len()).sum(),
        output_bits: sp.circ.outputs().len(),
    }
}

/// AND gates at the end of each stage of the circuit.
pub fn stage_and_ends() -> [usize; N_STAGES] {
    circuits::SPLIT.and_end
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

/// Test-only deviations. `usize` arguments are stage indices (0..5).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Cheat {
    #[default]
    None,
    /// N: corrupt the half-ciphertexts of 64 AND gates of a stage.
    CorruptGate(usize),
    /// N: flip control (dicing) bits of 64 AND gates of a stage.
    CorruptControlBits(usize),
    /// N: commit the mask of one AND output of a stage flipped (turns that
    /// AND into a NAND as far as the decoded values go, "logic change").
    FlipLambda(usize),
    /// N: wrong t_k for one AND gate (product check must fail).
    BadT,
    /// N: lie about one opened output mask of a stage (flips C's output).
    LieOpen(usize),
    /// N: lie about the opened mask of an input wire, by its position among
    /// the opened inputs (0..256: C's x share; then the digest inputs).
    LieOpenIn(usize),
    /// N: send a garbage label (right pointer bit) for its first own input
    /// (stage 0) or for the first digest input of a later stage.
    BadInputLabel(usize),
    /// N: the label of the flipped bit (shifted by Δ_A) for one digest input.
    FlipDigestLabel(usize),
    /// N: valid labels, but of another inner digest (the next block's of the
    /// stage, or the digest of a modified block if the stage has one).
    OtherDigest(usize),
    /// N: run the COTs under Δ_A with a different Δ than garbling.
    KosDelta,
    /// N: add random offsets to every check row of a stage.
    BadRows(usize),
    /// N: computes the check rows of a stage under a different salt.
    WrongSalt(usize),
    /// N: flip Y_N of a stage.
    BadYn(usize),
    /// N: the two halves of the label-check pair of one reported wire of a
    /// stage swapped.
    BadPair(usize),
    /// N: the label-check pairs of a stage's first reported group are right
    /// for the bit 0 and wrong for the bit 1 (an abort that depends on the
    /// group's value).
    BadPairHalf(usize),
    /// C: report one flipped bit of the named output group to N.
    FlipReported(&'static str),
    /// C: opens its key-share commitment to a different point.
    BadOpen,
    /// C: uses another label than the one it got for a digest input of a
    /// stage, ignores its own checks and reports what it computed.
    FeedOther(usize),
}

type KosS = kos::Sender<chou_orlandi::Receiver>;
type KosR = kos::Receiver<chou_orlandi::Sender>;
type FerS = ferret::Sender<KosS>;
type FerR = ferret::Receiver<KosR>;

/// N's state after preprocessing.
struct NState {
    /// Zero-labels of the circuit inputs and outputs (with Δ_A, both labels).
    k_in: SecretBlocks,
    k_out: SecretBlocks,
    /// Masks of the outputs.
    lam_out: Zeroizing<Vec<bool>>,
    /// COT keys under Δ_A for C's inputs.
    cota: SecretBlocks,
    /// Decoded values of the reported output groups.
    vals: Vec<Option<Zeroizing<Vec<bool>>>>,
    next: usize,
}

/// C's state after preprocessing.
struct CState {
    tables: Vec<gc::Gate3>,
    /// Active label of every feed evaluated so far.
    l: SecretBlocks,
    ck: Vec<Option<gc::CheckKeys>>,
    rows: Vec<Vec<u64>>,
    y_n: Vec<u64>,
    /// Per-session salt of the check-row hash (from the challenge seed).
    salt: u128,
    /// Opened masks, by input wire / output index (false where not opened).
    lam_in: Vec<bool>,
    lam_out: Vec<bool>,
    /// Label-check pairs, by `Lay::e_idx`.
    pairs: Vec<[[u8; 16]; 2]>,
    /// COTs under Δ_A for C's inputs (`msg = key ⊕ choice·Δ_A`).
    cot_choices: Zeroizing<Vec<bool>>,
    cot_msgs: SecretBlocks,
    /// Decoded values of the output groups (pointer bits for `ToN` groups).
    vals: Vec<Option<Zeroizing<Vec<bool>>>>,
    /// Inner digests C computed, waiting for N's labels.
    dig: Vec<Option<Zeroizing<Vec<bool>>>>,
    next: usize,
}

enum Pre {
    N(Box<NState>),
    C(Box<CState>),
}

const CH_COTA: usize = 0; // COTs under Δ_A (N sender): C's inputs
const CH_COTB: usize = 1; // MAC COTs (C sender, Δ_B)
const CH_SC: usize = 2; // share conversion
const CH_N2C: usize = 3; // all N→C protocol messages
const CH_C2N: usize = 4; // all C→N protocol messages
const CH_TAB: usize = 5; // N→C garbled tables (bulk: lowest priority on the link)
const N_CH: usize = 6;

/// The version tag: the first bytes each party writes on the transport,
/// before any multiplexer frame. A peer that reads anything else fails with
/// [`Error::VersionMismatch`].
pub const VERSION_TAG: &[u8] = b"routstr-2pc/split-public-1\n";

/// N streams the first part of the tables (stages A1–A3) once this many
/// MAC-COT bytes from C arrived (C has N's OT bootstrap messages and is
/// uploading the first part of the Ferret extension), and the rest once C is
/// past the first part (484 184 bytes with mpz2 rev 8f89783, for this
/// circuit's 960 988 COTs as for v2's 1.31 million; measured with
/// `TWOPC_TRACE=1`), i.e. past the small N→C Ferret message between the two
/// parts. Either gate also opens when N's MAC COTs are complete, or after
/// `TABLES_MAX_WAIT`. Re-measured for this circuit (`BENCH.md`, "Table
/// scheduling"): other thresholds were equal within noise or slower.
const TABLES_GATE: [u64; 2] = [64 * 1024, 500_000];
const TABLES_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

const TAG_KS: &[u8] = b"routstr-twopc-v2 key-share commit";
const TAG_OPEN: &[u8] = b"routstr-twopc-ag open";
const TAG_OUT: &[u8] = b"routstr-twopc-split output labels";
const TAG_CHI: &[u8] = b"routstr-twopc-ag chi";
const TAG_PAIR: &[u8] = b"routstr-twopc-split label check";

/// COTs under Δ_A: one per bit of C's x-coordinate share.
const N_COTA: usize = 256;

/// Everything derived from the circuit, computed once.
struct Lay {
    sp: &'static Split,
    shapes: Vec<gc::StageShape>,
    ands: Vec<(usize, usize, usize)>,
    base: Vec<usize>,
    n_in: usize,
    n_and: usize,
    n_out: usize,
    /// Feed id of output 0.
    out0: usize,
    /// Input wires whose mask is opened to C: its x share, the digest inputs.
    open_in: Vec<usize>,
    /// Per output: index of its label-check pair (the outputs C reports).
    e_idx: Vec<Option<usize>>,
    n_pairs: usize,
    /// Δ_B pool: base masks and products (fixed), then 128 product-check
    /// mask COTs.
    mac_fixed: usize,
    n_mac: usize,
}

impl Lay {
    fn new() -> Lay {
        let sp: &'static Split = &circuits::SPLIT;
        let circ = &sp.circ;
        let shapes = gc::stage_shapes(circ, &sp.gate_end);
        for (s, sh) in shapes.iter().enumerate() {
            assert_eq!(sh.ands.end, sp.and_end[s]);
        }
        let n_in = circ.inputs().len();
        let n_and = circ.and_count();
        let n_out = circ.outputs().len();
        assert_eq!(sp.xc.len(), N_COTA);
        let mut open_in: Vec<usize> = sp.xc.clone().collect();
        for d in &sp.dig {
            open_in.extend(d.clone());
        }
        let mut e_idx = vec![None; n_out];
        let mut n_pairs = 0;
        for g in &sp.outs {
            if g.kind != OutKind::ToC {
                for i in 0..g.len {
                    e_idx[g.off + i] = Some(n_pairs);
                    n_pairs += 1;
                }
            }
        }
        let mac_fixed = n_in + 2 * n_and;
        Lay {
            sp,
            ands: gc::and_gates(circ),
            base: gc::base_wires(circ),
            shapes,
            n_in,
            n_and,
            n_out,
            out0: circ.outputs().start,
            open_in,
            e_idx,
            n_pairs,
            mac_fixed,
            n_mac: mac_fixed + 128,
        }
    }

    /// Output groups C opens (decodes).
    fn opened(&self, gi: usize) -> bool {
        self.sp.outs[gi].kind != OutKind::ToN
    }

    /// Output groups of `stage` that C reports to N (pointer bits).
    fn reported(&self, stage: usize) -> Vec<usize> {
        (0..self.sp.outs.len())
            .filter(|&gi| {
                let g = &self.sp.outs[gi];
                g.stage == stage && g.kind != OutKind::ToC
            })
            .collect()
    }
}

static LAY: LazyLock<Lay> = LazyLock::new(Lay::new);

fn lay() -> &'static Lay {
    &LAY
}

/// The inner state whose digests feed `stage` (1..=4).
fn is_group(sp: &Split, stage: usize) -> usize {
    sp.group(["IS_HS", "IS_dHS", "IS_MS", "IS_c0"][stage - 1])
}

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
    timings: Vec<StepTiming>,
    #[cfg(test)]
    pub(crate) cheat: Cheat,
}

impl Drop for Party {
    fn drop(&mut self) {
        // Labels, masks, COT keys and MAC keys go with `pre` (their own
        // `Drop`s); copies inside mpz2's OT/OLE state are out of reach.
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

/// One half of a label-check pair: a salted hash of the value C holds for
/// output `o` when its reported bit is `p`.
fn pair_hash(salt: &[u8; 16], o: usize, p: bool, x: Block) -> [u8; 16] {
    let h: [u8; 32] = Sha256::new()
        .chain_update(TAG_PAIR)
        .chain_update(salt)
        .chain_update((o as u32).to_be_bytes())
        .chain_update([p as u8])
        .chain_update(x.as_bytes())
        .finalize()
        .into();
    h[..16].try_into().unwrap()
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

/// Writes [`VERSION_TAG`] and reads the peer's, byte by byte, so that a peer
/// speaking anything else (a v2 peer starts with a multiplexer frame header)
/// is refused at its first differing byte and nothing past the tag is read.
async fn exchange_version<IO>(io: IO) -> Result<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    use futures::{AsyncReadExt, AsyncWriteExt};
    let (mut rd, mut wr) = io.split();
    let send = async {
        wr.write_all(VERSION_TAG).await?;
        wr.flush().await?;
        Ok::<_, Error>(())
    };
    let recv = async {
        let mut got = Vec::with_capacity(VERSION_TAG.len());
        let mut b = [0u8; 1];
        while got.len() < VERSION_TAG.len() {
            rd.read_exact(&mut b).await?;
            got.push(b[0]);
            if b[0] != VERSION_TAG[got.len() - 1] {
                return Err(Error::VersionMismatch(hex::encode(&got)));
            }
        }
        Ok(())
    };
    futures::try_join!(send, recv)?;
    rd.reunite(wr).map_err(|_| Error::Protocol("transport halves".into()))
}

fn perr<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Protocol(format!("{what}: {e}"))
}

fn fcfg() -> ferret::FerretConfig {
    ferret::FerretConfig::builder()
        .lpn_type(ferret::LpnType::Regular)
        .build()
        .expect("ferret config")
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
        // The version tag, both ways, before anything else.
        let io = exchange_version(io).await?;
        // What the peer may send per channel. N (the node) is the exposed
        // party: C's honest upload is about 1.1 MB in all (Ferret on CH_COTB;
        // 12 KB of KOS on CH_COTA), a few KB of ECtF traffic and under 1 KB
        // of protocol messages; N→C-only channels accept nothing from C. C
        // bounds N too, so a malicious node cannot grow the client's memory:
        // an honest N sends about 0.5 MB on CH_COTB, a few KB on CH_COTA,
        // 21 KB on CH_SC, about 4.1 MB on CH_N2C and 11.8 MB of tables (the
        // circuit is fixed).
        const MIB: u64 = 1 << 20;
        let caps: [u64; N_CH] = match role {
            Role::N => [MIB, 16 * MIB, 4 * MIB, 0, MIB, 0],
            Role::C => [MIB, 4 * MIB, MIB, 16 * MIB, 0, 32 * MIB],
        };
        let (mux, mut chans) = Mux::start(io, N_CH, &[CH_TAB], &caps);
        let counters = mux.counters.clone();
        let tag = VERSION_TAG.len() as u64;
        counters.sent.fetch_add(tag, std::sync::atomic::Ordering::Relaxed);
        counters.recv.fetch_add(tag, std::sync::atomic::Ordering::Relaxed);
        let mut take = |i: usize| std::mem::replace(&mut chans[i], tokio::io::duplex(1).0);
        let ctx_a = Context::new_single_threaded(take(CH_COTA).compat());
        let ctx_b = Context::new_single_threaded(take(CH_COTB).compat());
        let ctx_sc = Context::new_single_threaded(take(CH_SC).compat());
        let n2c = FrameChan::new(take(CH_N2C));
        let tab = FrameChan::new(take(CH_TAB));
        // N never receives a protocol message over a few KB on C→N.
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

    fn nst(&mut self) -> Result<&mut NState> {
        match self.pre.as_mut() {
            Some(Pre::N(s)) => Ok(s),
            _ => Err(Error::State("not preprocessed")),
        }
    }

    fn cst(&mut self) -> Result<&mut CState> {
        match self.pre.as_mut() {
            Some(Pre::C(s)) => Ok(s),
            _ => Err(Error::State("not preprocessed")),
        }
    }

    /// Input-independent preprocessing.
    pub async fn preprocess(&mut self) -> Result<()> {
        self.check_stage(Stage::New, "preprocess must be first")?;
        if *TRACE {
            let c = self.counters.clone();
            let who = if self.role == Role::C { "C" } else { "N" };
            tokio::spawn(async move {
                let t0 = Instant::now();
                let mut last = (0, 0, 0);
                for _ in 0..200 {
                    let v = (c.ch_recv(CH_COTA), c.ch_recv(CH_COTB), c.ch_recv(CH_TAB));
                    if v != last {
                        eprintln!(
                            "[{who} {:8.1} ms] recv cota={} cotb={} tab={}",
                            t0.elapsed().as_secs_f64() * 1e3,
                            v.0,
                            v.1,
                            v.2
                        );
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
        let lay = lay();
        let sp = lay.sp;
        let delta = self.delta;
        let mut grng = StdRng::from_seed(self.rng.random());

        let garble = tokio::task::spawn_blocking(move || {
            let in_keys = SecretBlocks((0..lay.n_in).map(|_| Block::random(&mut grng)).collect());
            let (k, tables) = gc::garble(&sp.circ, delta, &in_keys, 0, &mut grng);
            (SecretBlocks(k), tables)
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
        let mut kos_a = self.kos_a_s.take().ok_or(Error::State("preprocess already ran"))?;

        let Party {
            ctx_a,
            ctx_b,
            ctx_sc,
            n2c,
            c2n,
            tab,
            mac_r,
            sc,
            counters,
            ..
        } = self;

        // Garble and stream the tables while the OTs run, scheduled around C's
        // MAC-COT upload (Ferret, about 1 MB C→N, in two parts separated by a
        // small N→C message). Any small N→C message sent after the tables sits
        // behind them in the link buffers and stalls an OT round trip, so the
        // first part of the tables waits until C is uploading (N's OT setup
        // messages have arrived) and the second until C is past the first
        // part (`TABLES_GATE`). The download then overlaps C's upload.
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
            #[allow(unused_mut)]
            let (k, mut tables) = garble.await.map_err(perr("garbling task"))?;
            #[cfg(test)]
            if let Cheat::CorruptGate(s) | Cheat::CorruptControlBits(s) = cheat {
                let r = lay.shapes[s].ands.clone();
                for g in 0..64 {
                    let t = &mut tables[r.start + g * (r.len() / 64)];
                    if matches!(cheat, Cheat::CorruptGate(_)) {
                        t.g[0] ^= 1;
                        t.g[2] ^= 1 << 40;
                    } else {
                        t.z ^= 0b00011;
                    }
                }
            }
            let cut = sp.and_end[HS_STAGES - 1];
            for part in [&tables[..cut], &tables[cut..]] {
                if let Some(g) = gates.next() {
                    g.await;
                }
                tab.send(&gc::tables_to_bytes(part)).await?;
            }
            Ok::<_, Error>(k)
        };
        let cot_a_fut = async {
            let keys = rcot_send!(&mut kos_a, ctx_a, N_COTA);
            Ok::<_, Error>(SecretBlocks(keys))
        };
        let cot_b_fut = async {
            let (r, m) = rcot_recv!(mac_r.as_mut().unwrap().as_mut(), ctx_b, lay.n_mac);
            mac_done.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok::<_, Error>((Zeroizing::new(r), SecretBlocks(m)))
        };
        let sc_fut = sc.preprocess(ctx_sc);
        let (k, cota, macs, scr) = futures::join!(send_fut, cot_a_fut, cot_b_fut, sc_fut);
        let k = k?;
        let cota = cota?;
        let (r_bits, r_macs) = macs?;
        scr?;
        if cota.len() != N_COTA || r_bits.len() != lay.n_mac {
            return Err(Error::Protocol("cot count".into()));
        }

        // Commit (Fix) λ for the base wires and t for every AND gate.
        let nb = lay.base.len();
        #[allow(unused_mut)]
        let mut base_lam: Vec<bool> = lay.base.iter().map(|&w| k[w].lsb()).collect();
        #[cfg(test)]
        if let Cheat::FlipLambda(s) = cheat {
            // An AND gate half-way through the stage.
            let r = &lay.shapes[s].ands;
            let i = lay.n_in + (r.start + r.end) / 2;
            base_lam[i] = !base_lam[i];
        }
        let mut d_bits = Vec::with_capacity(lay.mac_fixed);
        for (i, l) in base_lam.iter().enumerate() {
            d_bits.push(l ^ r_bits[i]);
        }
        let (lam, mac) = gc::propagate_n(&sp.circ, &base_lam, &r_macs[..nb]);
        let (lam, mac) = (Zeroizing::new(lam), SecretBlocks(mac));
        for (a, &(i, j, _)) in lay.ands.iter().enumerate() {
            #[allow(unused_mut)]
            let mut t = lam[i] & lam[j];
            #[cfg(test)]
            if cheat == Cheat::BadT && a == lay.n_and - 1000 {
                t = !t;
            }
            d_bits.push(t ^ r_bits[nb + a]);
        }
        let t_mac = SecretBlocks(r_macs[nb..nb + lay.n_and].to_vec());
        let off = lay.mac_fixed;
        let mask_bits = Zeroizing::new(r_bits[off..off + 128].to_vec());
        let mask_macs = SecretBlocks(r_macs[off..off + 128].to_vec());
        drop((r_bits, r_macs));
        n2c.send(&from_bits(&d_bits)).await?;

        // Challenge.
        let seed: [u8; 32] = c2n.recv_exact(32).await?.try_into().expect("32 bytes");
        let t_seed = Instant::now();
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck: Vec<Block> = (0..N_STAGES).map(|s| chi(&seed, format!("check{s}").as_bytes())).collect();
        let salt_b = chi(&seed, b"check-salt").to_bytes();
        let salt = u128::from_le_bytes(salt_b);

        // Product check, openings, consistency-check material, label-check
        // pairs (CPU, blocking).
        let (st, msgs) = tokio::task::spawn_blocking(move || {
            let rows_of = |s: usize| -> (Vec<u8>, Vec<u8>) {
                let sh = &lay.shapes[s];
                let pw = gc::powers(chi_ck[s], sh.ands.len());
                #[allow(unused_mut)]
                let mut salt_s = salt;
                #[cfg(test)]
                if cheat == Cheat::WrongSalt(s) {
                    salt_s ^= 1 << 7;
                }
                let cm = gc::check_material(
                    &sp.circ,
                    sh.gates.clone(),
                    salt_s,
                    s,
                    &lay.ands[sh.ands.clone()],
                    &sh.rows,
                    &k,
                    &lam,
                    &mac,
                    &t_mac[sh.ands.clone()],
                    &pw,
                    delta,
                );
                #[allow(unused_mut)]
                let mut y_n = cm.y_n;
                #[cfg(test)]
                if cheat == Cheat::BadYn(s) {
                    y_n ^= 1;
                }
                #[allow(unused_mut)]
                let mut rows = cm.rows;
                #[cfg(test)]
                if cheat == Cheat::BadRows(s) {
                    let mut r = os_rng();
                    for x in rows.iter_mut() {
                        *x ^= r.random::<u64>();
                    }
                }
                (rows.iter().flat_map(|r| r.to_le_bytes()).collect(), y_n.to_le_bytes().to_vec())
            };
            let mut msgs: Vec<Vec<u8>> = Vec::new();
            let rows = std::thread::scope(|sc| {
                let hs: Vec<_> = (0..N_STAGES).map(|s| sc.spawn(move || rows_of(s))).collect();
                let pw = gc::powers(chi_dv, lay.n_and);
                let mut acc = (Block::ZERO, Block::ZERO);
                gc::dvzk_prover_acc(&lay.ands, &lam, &mac, &t_mac, &pw, &mut acc);
                // Random mask a* = Σ r_i X^i.
                let mut a_star = Block::ZERO;
                let mut m_star = Block::ZERO;
                for i in 0..128 {
                    a_star ^= sel(mask_bits[i], Block::MONOMIAL[i]);
                    m_star ^= Block::MONOMIAL[i].gfmul(mask_macs[i]);
                }
                msgs.push(blocks_to_bytes(&[acc.0 ^ m_star, acc.1 ^ a_star]));

                // Openings: C's input wires, the digest input wires, every
                // output C decodes; one MAC hash.
                let mut bits = Vec::new();
                let mut h = Sha256::new();
                h.update(TAG_OPEN);
                #[allow(unused_variables)]
                for (j, &w) in lay.open_in.iter().enumerate() {
                    #[cfg(test)]
                    let lie = cheat == Cheat::LieOpenIn(j);
                    #[cfg(not(test))]
                    let lie = false;
                    bits.push(lam[w] ^ lie);
                    h.update(mac[w].as_bytes());
                }
                for (gi, g) in sp.outs.iter().enumerate() {
                    if !lay.opened(gi) {
                        continue;
                    }
                    #[cfg(test)]
                    let lie = cheat == Cheat::LieOpen(g.stage)
                        && sp.outs.iter().position(|x| x.stage == g.stage && x.kind != OutKind::ToN) == Some(gi);
                    #[cfg(not(test))]
                    let lie = false;
                    for i in 0..g.len {
                        let w = lay.out0 + g.off + i;
                        bits.push(lam[w] ^ (lie && i == 1));
                        h.update(mac[w].as_bytes());
                    }
                }
                let hd: [u8; 32] = h.finalize().into();
                let mut open = from_bits(&bits);
                open.extend_from_slice(&hd);
                msgs.push(open);
                hs.into_iter().map(|h| h.join().expect("rows thread")).collect::<Vec<_>>()
            });
            for (r, y) in rows {
                msgs.push(r);
                msgs.push(y);
            }

            // Label-check pairs: for each output wire C reports, the salted
            // hashes of its two labels, by pointer bit.
            let mut pairs = Vec::with_capacity(32 * lay.n_pairs);
            #[allow(unused_variables)]
            for (gi, g) in sp.outs.iter().enumerate() {
                for i in 0..g.len {
                    let o = g.off + i;
                    if lay.e_idx[o].is_none() {
                        continue;
                    }
                    // The label with pointer bit 0: k ⊕ λ·Δ_A.
                    let x0 = k[lay.out0 + o] ^ sel(lam[lay.out0 + o], delta);
                    #[allow(unused_mut)]
                    let mut pair = [pair_hash(&salt_b, o, false, x0), pair_hash(&salt_b, o, true, x0 ^ delta)];
                    #[cfg(test)]
                    if lay.reported(g.stage)[0] == gi {
                        if cheat == Cheat::BadPair(g.stage) && i == 3 {
                            pair.swap(0, 1);
                        }
                        if cheat == Cheat::BadPairHalf(g.stage) {
                            pair[1][0] ^= 1;
                        }
                    }
                    pairs.extend_from_slice(&pair[0]);
                    pairs.extend_from_slice(&pair[1]);
                }
            }
            msgs.push(pairs);

            let outs = sp.circ.outputs();
            let st = NState {
                k_in: SecretBlocks(k[..lay.n_in].to_vec()),
                k_out: SecretBlocks(k[outs.clone()].to_vec()),
                lam_out: Zeroizing::new(lam[outs].to_vec()),
                cota,
                vals: (0..sp.outs.len()).map(|_| None).collect(),
                next: 0,
            };
            (st, msgs)
        })
        .await
        .map_err(perr("preprocess task"))?;
        tr(t_seed, "N", "post-seed compute done");
        for msg in msgs {
            n2c.send(&msg).await?;
        }
        self.pre = Some(Pre::N(Box::new(st)));
        Ok(())
    }

    async fn preprocess_c(&mut self) -> Result<()> {
        let lay = lay();
        let sp = lay.sp;
        let delta_b = self.delta;
        let seed: [u8; 32] = self.rng.random();
        let mut kos_a = self.kos_a_r.take().ok_or(Error::State("preprocess already ran"))?;
        let Party {
            ctx_a,
            ctx_b,
            ctx_sc,
            n2c,
            c2n,
            tab,
            mac_s,
            sc,
            ..
        } = self;

        let t0 = Instant::now();
        let recv_fut = async {
            let mut t = Vec::with_capacity(lay.n_and);
            let cut = sp.and_end[HS_STAGES - 1];
            for n in [cut, lay.n_and - cut] {
                let b = tab.recv_exact(gc::tables_len(n)).await?;
                tr(t0, "C", "tables part recv");
                t.extend(gc::tables_from_bytes(&b, n).ok_or_else(|| Error::Protocol("tables".into()))?);
            }
            let d = n2c.recv_exact(lay.mac_fixed.div_ceil(8)).await?;
            tr(t0, "C", "d recv");
            Ok::<_, Error>((t, unpack(&d, lay.mac_fixed)))
        };
        let cot_a_fut = async {
            let (c, m) = rcot_recv!(&mut kos_a, ctx_a, N_COTA);
            tr(t0, "C", "cot (delta_A) done");
            Ok::<_, Error>((c, m))
        };
        let cot_b_fut = async {
            let keys = rcot_send!(mac_s.as_mut().unwrap().as_mut(), ctx_b, lay.n_mac);
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
        if kb.len() != lay.n_mac || cot_choices.len() != N_COTA {
            return Err(Error::Protocol("cot count".into()));
        }
        // Keys of the committed values: K[x] = K[r] ⊕ d·Δ_B. The 128 COTs
        // after them stay random: the product-check mask.
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
        let n_open: usize = lay.open_in.len()
            + sp.outs.iter().enumerate().filter(|(gi, _)| lay.opened(*gi)).map(|(_, g)| g.len).sum::<usize>();
        let recv2 = async {
            let dv = n2c.recv_exact(32).await?;
            let open = n2c.recv_exact(n_open.div_ceil(8) + 32).await?;
            let mut rows = Vec::new();
            for s in 0..N_STAGES {
                let r = n2c.recv_exact(8 * lay.shapes[s].rows.len()).await?;
                let y = n2c.recv_exact(8).await?;
                let r: Vec<u64> = r.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
                rows.push((r, u64::from_le_bytes(y[..].try_into().unwrap())));
            }
            let pairs = n2c.recv_exact(32 * lay.n_pairs).await?;
            Ok::<_, Error>((dv, open, rows, pairs))
        };
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck: Vec<Block> = (0..N_STAGES).map(|s| chi(&seed, format!("check{s}").as_bytes())).collect();
        let salt = u128::from_le_bytes(chi(&seed, b"check-salt").to_bytes());
        let compute = tokio::task::spawn_blocking(move || {
            let nb = lay.base.len();
            let key = SecretBlocks(gc::propagate_c(&sp.circ, &kfix[..nb], delta_b));
            let t_key = &kfix[nb..nb + lay.n_and];
            let mut acc = Block::ZERO;
            let pw = gc::powers(chi_dv, lay.n_and);
            gc::dvzk_verifier_acc(&lay.ands, &key, t_key, delta_b, &pw, &mut acc);
            let cks: Vec<gc::CheckKeys> = (0..N_STAGES)
                .map(|s| {
                    let sh = &lay.shapes[s];
                    let pw = gc::powers(chi_ck[s], sh.ands.len());
                    gc::check_keys(&lay.ands[sh.ands.clone()], &key, &t_key[sh.ands.clone()], &pw)
                })
                .collect();
            let off = lay.mac_fixed;
            let mut k_star = Block::ZERO;
            for i in 0..128 {
                k_star ^= Block::MONOMIAL[i].gfmul(kfix[off + i]);
            }
            (key, cks, acc ^ k_star)
        });
        let (r2, comp) = futures::join!(recv2, compute);
        tr(t0, "C", "rows recv + keys computed");
        let (dv, open, rows, pairs) = r2?;
        let (key, cks, w) = comp.map_err(perr("preprocess task"))?;

        // Product check: Σχ B ⊕ K* = U ⊕ V·Δ_B.
        let uv = bytes_to_blocks(&dv);
        if w != uv[0] ^ uv[1].gfmul(delta_b) {
            return Err(Error::Abort("AND-product (t = λ_i·λ_j) check failed".into()));
        }

        // Openings.
        let mut bits = unpack(&open[..open.len() - 32], n_open).into_iter();
        let mut h = Sha256::new();
        h.update(TAG_OPEN);
        let mut take = |w: usize| -> bool {
            let b = bits.next().unwrap_or(false);
            h.update((key[w] ^ sel(b, delta_b)).as_bytes());
            b
        };
        let mut lam_in = vec![false; lay.n_in];
        for &w in &lay.open_in {
            lam_in[w] = take(w);
        }
        let mut lam_out = vec![false; lay.n_out];
        for (gi, g) in sp.outs.iter().enumerate() {
            if lay.opened(gi) {
                for o in g.off..g.off + g.len {
                    lam_out[o] = take(lay.out0 + o);
                }
            }
        }
        let hd: [u8; 32] = h.finalize().into();
        if hd[..] != open[open.len() - 32..] {
            return Err(Error::Abort("opened masks do not match their MACs".into()));
        }
        let (rows, y_n): (Vec<Vec<u64>>, Vec<u64>) = rows.into_iter().unzip();
        let pairs = pairs
            .chunks_exact(32)
            .map(|c| [c[..16].try_into().unwrap(), c[16..].try_into().unwrap()])
            .collect();
        let st = CState {
            tables,
            l: SecretBlocks(vec![Block::ZERO; sp.circ.feed_count()]),
            ck: cks.into_iter().map(Some).collect(),
            rows,
            y_n,
            salt,
            lam_in,
            lam_out,
            pairs,
            cot_choices,
            cot_msgs,
            vals: (0..sp.outs.len()).map(|_| None).collect(),
            dig: (0..sp.dig.len()).map(|_| None).collect(),
            next: 0,
        };
        self.pre = Some(Pre::C(Box::new(st)));
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

    /// ECtF + stages A1–A3.
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
        let x_le: [u8; 32] = share.0.into();
        drop(share);
        let x_bits = Zeroizing::new(to_bits(&x_le));
        let mut x_le = x_le;
        x_le.zeroize();

        let m = self.mark();
        let r = match self.role {
            Role::N => self.handshake_n(&x_bits, th_sh).await,
            Role::C => self.handshake_c(&x_bits, th_sh).await,
        };
        self.record("phase_a", m);
        r
    }

    /// Stages B1, B2 and the anchors.
    pub async fn application(&mut self, th_sf: [u8; 32]) -> Result<ApOut> {
        self.check_stage(Stage::Handshaken, "application after handshake")?;
        let m = self.mark();
        let r = match self.role {
            Role::N => self.application_n(th_sf).await,
            Role::C => self.application_c(th_sf).await,
        };
        self.record("phase_b", m);
        let r = self.fail(r);
        let o = r?;
        self.stage = Stage::Done;
        Ok(o)
    }

    // ----------------------------------------------------------------- N --

    /// N found the peer cheating (or malformed): tell C, so that it does not
    /// wait for an answer, and pass the error on.
    async fn n_rej<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            let _ = self.n2c.send(&[0u8]).await;
        }
        r
    }

    async fn handshake_n(&mut self, x_bits: &[bool], th: [u8; 32]) -> Result<HsSecrets> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let lay = lay();
        let sp = lay.sp;
        let delta = self.delta;
        // Own input labels, sent at once.
        #[allow(unused_mut)]
        let mut labels: Vec<Block> = {
            let st = self.nst()?;
            if st.next != 0 {
                return Err(Error::State("handshake already ran"));
            }
            sp.xn.clone().zip(x_bits).map(|(w, b)| st.k_in[w] ^ sel(*b, delta)).collect()
        };
        #[cfg(test)]
        if cheat == Cheat::BadInputLabel(0) {
            labels[0] = labels[0] ^ Block::new([0x5a; 16]);
        }
        self.n2c.send(&blocks_to_bytes(&labels)).await?;
        gc::wipe_blocks(&mut labels);
        let d = unpack(&self.c2n.recv_exact(32).await?, 256);
        let mut adj: Vec<Block> = {
            let st = self.nst()?;
            sp.xc.clone().enumerate().map(|(j, w)| st.k_in[w] ^ st.cota[j] ^ sel(d[j], delta)).collect()
        };
        self.n2c.send(&blocks_to_bytes(&adj)).await?;
        gc::wipe_blocks(&mut adj);

        for s in 0..HS_STAGES {
            let r = self.n_report(s).await;
            self.n_rej(r).await?;
            if s + 1 < HS_STAGES {
                let lab = self.n_digest_labels(s + 1, &th)?;
                self.n2c.send(&lab).await?;
            }
        }
        let st = self.nst()?;
        let get = |name: &str| -> Result<[u8; 32]> {
            let v = st.vals[sp.group(name)].as_ref().ok_or(Error::State("output missing"))?;
            Ok(from_bits(v).try_into().expect("32 bytes"))
        };
        Ok(HsSecrets {
            c_hs: get("c_hs")?,
            s_hs: get("s_hs")?,
        })
    }

    async fn application_n(&mut self, th: [u8; 32]) -> Result<ApOut> {
        let lay = lay();
        let sp = lay.sp;
        // Stage B1's digests need th_SF; `IS_MS` came with the A3 report.
        let lab = self.n_digest_labels(HS_STAGES, &th)?;
        self.n2c.send(&lab).await?;
        for s in HS_STAGES..N_STAGES {
            let r = self.n_report(s).await;
            self.n_rej(r).await?;
            if s + 1 < N_STAGES {
                let lab = self.n_digest_labels(s + 1, &th)?;
                self.n2c.send(&lab).await?;
            }
        }
        let st = self.nst()?;
        let get = |name: &str| -> Result<[u8; 32]> {
            let v = st.vals[sp.group(name)].as_ref().ok_or(Error::State("output missing"))?;
            Ok(from_bits(v).try_into().expect("32 bytes"))
        };
        let (h1, h2, hk) = (get("h1")?, get("h2")?, get("hk")?);
        let mut kiv: [u8; 28] = from_bits(st.vals[sp.group("kiv")].as_ref().ok_or(Error::State("output missing"))?)
            .try_into()
            .expect("28 bytes");
        // The circuit computed hk over the same wires; a difference means C's
        // report went through although the labels were not N's (not reachable
        // without Δ_A), so this is a self-check.
        if Sha256::digest(kiv)[..] != hk {
            kiv.zeroize();
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
        Ok(o)
    }

    /// Receives C's report of stage `s` and checks it against N's labels: for
    /// every reported pointer bit N recomputes the label C must hold and
    /// compares one hash, so C cannot report a bit it has no label for.
    async fn n_report(&mut self, s: usize) -> Result<()> {
        let lay = lay();
        let sp = lay.sp;
        let delta = self.delta;
        let msg = self.c2n.recv().await?;
        if msg.first() != Some(&1) {
            return Err(Error::Abort("peer aborted (a check failed on C)".into()));
        }
        let groups = lay.reported(s);
        let body: usize = groups.iter().map(|&gi| sp.outs[gi].len / 8).sum();
        if msg.len() != 1 + body + 32 {
            return Err(Error::Protocol("report length".into()));
        }
        let st = self.nst()?;
        if st.next != s {
            return Err(Error::State("stage order"));
        }
        let mut h = Sha256::new();
        h.update(TAG_OUT);
        h.update([s as u8]);
        let mut off = 1;
        let mut parsed = Vec::new();
        for &gi in &groups {
            let g = &sp.outs[gi];
            let bits = unpack(&msg[off..off + g.len / 8], g.len);
            off += g.len / 8;
            for (i, p) in bits.iter().enumerate() {
                let o = g.off + i;
                // The label with pointer bit p: k ⊕ (p ⊕ λ)·Δ_A.
                let x = st.k_out[o] ^ sel(*p ^ st.lam_out[o], delta);
                h.update(x.as_bytes());
            }
            parsed.push((gi, bits));
        }
        let hd: [u8; 32] = h.finalize().into();
        if hd[..] != msg[off..] {
            return Err(Error::Abort("output labels do not authenticate".into()));
        }
        for (gi, bits) in parsed {
            let g = &sp.outs[gi];
            let v: Vec<bool> = bits.iter().enumerate().map(|(i, p)| p ^ st.lam_out[g.off + i]).collect();
            st.vals[gi] = Some(Zeroizing::new(v));
        }
        st.next = s + 1;
        Ok(())
    }

    /// The labels of stage `s`'s digest inputs: N computes the inner digests
    /// from the public `IS` (which C reported under its labels in the stage
    /// before) and its own transcript hash, and sends the label of every
    /// digest bit. C gets one label per wire and nothing to choose from.
    fn n_digest_labels(&mut self, s: usize, th: &[u8; 32]) -> Result<Vec<u8>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let lay = lay();
        let sp = lay.sp;
        let delta = self.delta;
        let st = self.nst()?;
        if st.next != s {
            return Err(Error::State("stage order"));
        }
        #[allow(unused_mut)]
        let mut blocks = circuits::digest_blocks(s, th);
        #[cfg(test)]
        if cheat == Cheat::OtherDigest(s) {
            if blocks.len() > 1 {
                blocks.rotate_left(1);
            } else {
                blocks[0][0] ^= 1;
            }
        }
        let digs = sp.digs_of(s);
        let is = st.vals[is_group(sp, s)].as_ref().ok_or(Error::State("no inner state"))?;
        let mut labels: Vec<Block> = Vec::with_capacity(256 * digs.len());
        for (n, blk) in blocks.iter().enumerate() {
            let d = Zeroizing::new(circuits::inner_digest(is, blk));
            for (i, w) in sp.dig[digs[n]].clone().enumerate() {
                labels.push(st.k_in[w] ^ sel(d[i], delta));
            }
        }
        #[cfg(test)]
        if cheat == Cheat::BadInputLabel(s) {
            labels[0] = labels[0] ^ Block::new([0x5a; 16]);
        }
        #[cfg(test)]
        if cheat == Cheat::FlipDigestLabel(s) {
            labels[0] = labels[0] ^ delta;
        }
        let out = blocks_to_bytes(&labels);
        gc::wipe_blocks(&mut labels);
        Ok(out)
    }

    // ----------------------------------------------------------------- C --

    /// A message from N of exactly `n` bytes; a single zero byte instead
    /// means N rejected C's last message.
    async fn c_recv(&mut self, n: usize) -> Result<Vec<u8>> {
        let m = self.n2c.recv().await?;
        if m.len() == 1 && m[0] == 0 && n != 1 {
            return Err(Error::Abort("peer aborted (N rejected a report)".into()));
        }
        if m.len() != n {
            return Err(Error::Protocol(format!("unexpected message length {} (expected {n})", m.len())));
        }
        Ok(m)
    }

    async fn handshake_c(&mut self, x_bits: &[bool], th: [u8; 32]) -> Result<HsSecrets> {
        let lay = lay();
        let sp = lay.sp;
        let d: Vec<bool> = {
            let st = self.cst()?;
            if st.next != 0 {
                return Err(Error::State("handshake already ran"));
            }
            x_bits.iter().zip(st.cot_choices.iter()).map(|(x, r)| x ^ r).collect()
        };
        self.c2n.send(&from_bits(&d)).await?;
        let gl = SecretBlocks(bytes_to_blocks(&self.c_recv(16 * 256).await?));
        let el = SecretBlocks(bytes_to_blocks(&self.c_recv(16 * 256).await?));
        // Active labels: with N's zero-labels and Δ_A they give C's inputs.
        let mut ok_in = true;
        {
            let st = self.cst()?;
            for (j, w) in sp.xc.clone().enumerate() {
                st.l[w] = el[j] ^ st.cot_msgs[j];
                ok_in &= st.l[w].lsb() == x_bits[j] ^ st.lam_in[w];
            }
            for (j, w) in sp.xn.clone().enumerate() {
                st.l[w] = gl[j];
            }
        }
        for s in 0..HS_STAGES {
            let msg = self.c_stage(s, ok_in).await?;
            self.c2n.send(&msg).await?;
            if s + 1 < HS_STAGES {
                ok_in = self.c_next_digests(s + 1, &th).await?;
            }
        }
        let st = self.cst()?;
        let get = |name: &str| -> Result<[u8; 32]> {
            let v = st.vals[sp.group(name)].as_ref().ok_or(Error::State("output missing"))?;
            Ok(from_bits(v).try_into().expect("32 bytes"))
        };
        Ok(HsSecrets {
            c_hs: get("c_hs")?,
            s_hs: get("s_hs")?,
        })
    }

    async fn application_c(&mut self, th: [u8; 32]) -> Result<ApOut> {
        let lay = lay();
        let sp = lay.sp;
        let mut ok_in = self.c_next_digests(HS_STAGES, &th).await?;
        for s in HS_STAGES..N_STAGES {
            let msg = self.c_stage(s, ok_in).await?;
            if s + 1 < N_STAGES {
                self.c2n.send(&msg).await?;
                ok_in = self.c_next_digests(s + 1, &th).await?;
                continue;
            }
            // Last stage: C compares the anchors with its own outputs before
            // it reports anything of the stage (N gets K_0 with that report).
            let st = self.cst()?;
            let get = |name: &str| -> Result<[u8; 32]> {
                let v = st.vals[sp.group(name)].as_ref().ok_or(Error::State("output missing"))?;
                Ok(from_bits(v).try_into().expect("32 bytes"))
            };
            let (h1, h2, hk) = (get("h1")?, get("h2")?, get("hk")?);
            let (mut s_ap_0, mut c_ap_1) = (get("s_ap_0")?, get("c_ap_1")?);
            if Sha256::digest(c_ap_1)[..] != h1 || Sha256::digest(s_ap_0)[..] != h2 {
                s_ap_0.zeroize();
                c_ap_1.zeroize();
                let _ = self.c2n.send(&[0u8]).await;
                return Err(Error::Abort("anchor mismatch".into()));
            }
            let o = ApOut::C {
                s_ap_0,
                c_ap_1,
                h1,
                h2,
                hk,
            };
            s_ap_0.zeroize();
            c_ap_1.zeroize();
            self.c2n.send(&msg).await?;
            return Ok(o);
        }
        unreachable!("the last stage returns")
    }

    /// Evaluates stage `s` and runs its checks; only if all pass does it
    /// decode the stage's outputs and return the report for N (`1 ‖ bits ‖
    /// hash`). On a failure it tells N (one zero byte) and aborts.
    ///
    /// The checks, in this order: the pointer bits of the stage's input
    /// labels (`ok_in`, done by the caller against opened masks), the
    /// consistency check of every AND gate of the stage, and the label check
    /// of every output wire that is reported: the label C holds must hash to
    /// the half of N's pair that belongs to the pointer bit C is about to
    /// send. N fixed the pairs in preprocessing, so the hash C then sends
    /// tells N nothing it did not commit to. Whatever fails, C evaluates the
    /// whole stage first and sends the same single byte.
    async fn c_stage(&mut self, s: usize, ok_in: bool) -> Result<Vec<u8>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let lay = lay();
        let sp = lay.sp;
        let delta_b = self.delta;
        let st = self.cst()?;
        if st.next != s {
            return Err(Error::State("stage order"));
        }
        let ck = st.ck[s].take().ok_or(Error::State("stage already used"))?;
        let rows = std::mem::take(&mut st.rows[s]);
        let (y_n, salt) = (st.y_n[s], st.salt);
        let tables = std::mem::take(&mut st.tables);
        let mut l = std::mem::take(&mut st.l);
        let (ok_check, tables, l) = tokio::task::spawn_blocking(move || {
            let sh = &lay.shapes[s];
            gc::evaluate_range(&sp.circ, &mut l, &tables, sh.gates.clone(), sh.ands.start, 0);
            let ok = gc::run_check(salt, s, &lay.ands[sh.ands.clone()], &sh.rows, &l, &ck, &rows, y_n, delta_b);
            (ok, tables, l)
        })
        .await
        .map_err(perr("eval task"))?;
        let st = self.cst()?;
        st.tables = tables;
        st.l = l;
        if s + 1 == N_STAGES {
            st.tables = Vec::new();
        }

        let salt_b = salt.to_le_bytes();
        let mut ok_pair = true;
        let mut body = vec![1u8];
        let mut h = Sha256::new();
        h.update(TAG_OUT);
        h.update([s as u8]);
        let mut decoded = Vec::new();
        #[allow(unused_mut, unused_variables)]
        let mut flip_at: Option<usize> = None;
        for (gi, g) in sp.outs.iter().enumerate().filter(|(_, g)| g.stage == s) {
            let mut vals = Vec::with_capacity(g.len);
            let mut bits = Vec::with_capacity(g.len);
            for i in 0..g.len {
                let o = g.off + i;
                let lab = st.l[lay.out0 + o];
                // N's own outputs: their masks are not opened (`lam_out` is
                // false there), so C keeps only the pointer bit.
                vals.push(lab.lsb() ^ st.lam_out[o]);
                if let Some(e) = lay.e_idx[o] {
                    let p = lab.lsb();
                    ok_pair &= pair_hash(&salt_b, o, p, lab) == st.pairs[e][p as usize];
                    h.update(lab.as_bytes());
                    bits.push(p);
                }
            }
            if !bits.is_empty() {
                #[cfg(test)]
                if cheat == Cheat::FlipReported(g.name) {
                    flip_at = Some(body.len() + 1);
                }
                body.extend_from_slice(&from_bits(&bits));
            }
            decoded.push((gi, Zeroizing::new(vals)));
        }
        let hd: [u8; 32] = h.finalize().into();
        body.extend_from_slice(&hd);

        #[allow(unused_mut)]
        let mut ignore = false;
        #[cfg(test)]
        if cheat == Cheat::FeedOther(s) {
            ignore = true;
        }
        if !(ok_in && ok_check && ok_pair) && !ignore {
            let _ = self.c2n.send(&[0u8]).await;
            return Err(Error::Abort(
                if !ok_in {
                    "input label pointer bits do not match the opened masks"
                } else if !ok_check {
                    "garbled-circuit consistency check failed"
                } else {
                    "output label check failed"
                }
                .into(),
            ));
        }
        #[cfg(test)]
        if let Some(at) = flip_at {
            body[at] ^= 0x10;
        }
        // Only now are the outputs used.
        for (gi, v) in decoded {
            st.vals[gi] = Some(v);
        }
        st.next = s + 1;
        Ok(body)
    }

    /// Computes the inner digests of stage `s`'s inputs from the public `IS`
    /// and C's own transcript hash, receives N's labels for them and checks
    /// every label's pointer bit against the opened, authenticated mask of
    /// its wire and C's own digest bit. Returns whether all matched (the
    /// caller aborts in `c_stage`, after evaluating, like for any other
    /// failed check of the stage).
    async fn c_next_digests(&mut self, s: usize, th: &[u8; 32]) -> Result<bool> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let lay = lay();
        let sp = lay.sp;
        let digs = sp.digs_of(s);
        {
            let st = self.cst()?;
            let is = st.vals[is_group(sp, s)].clone().ok_or(Error::State("no inner state"))?;
            for (n, blk) in circuits::digest_blocks(s, th).iter().enumerate() {
                st.dig[digs[n]] = Some(Zeroizing::new(circuits::inner_digest(&is, blk)));
            }
        }
        let msg = self.c_recv(16 * 256 * digs.len()).await?;
        let blocks = SecretBlocks(bytes_to_blocks(&msg));
        let st = self.cst()?;
        let mut ok = true;
        for (n, &j) in digs.iter().enumerate() {
            let bits = st.dig[j].take().ok_or(Error::State("digest missing"))?;
            for (i, w) in sp.dig[j].clone().enumerate() {
                let lab = blocks[256 * n + i];
                st.l[w] = lab;
                ok &= lab.lsb() == bits[i] ^ st.lam_in[w];
            }
        }
        #[cfg(test)]
        if cheat == Cheat::FeedOther(s) {
            // "Another digest": C has no other label, the best it can do is
            // to guess one (here: a random offset with the pointer flipped).
            let w = sp.dig[digs[0]].start + 5;
            let mut x = Block::random(&mut self.rng);
            x.set_lsb(true);
            let st = self.cst()?;
            st.l[w] = st.l[w] ^ x;
        }
        Ok(ok)
    }
}

/// Bytes of the protocol messages per session, by direction (C→N, N→C), as
/// computed from the circuit sizes (for reports). Excludes OT traffic and
/// the version tag.
pub fn message_sizes() -> (usize, usize) {
    let l = lay();
    let sp = l.sp;
    let mut n2c = gc::tables_len(l.n_and) + l.mac_fixed.div_ceil(8) + 32 + 32 * l.n_pairs;
    let n_open: usize = l.open_in.len()
        + sp.outs.iter().enumerate().filter(|(gi, _)| l.opened(*gi)).map(|(_, g)| g.len).sum::<usize>();
    n2c += n_open.div_ceil(8) + 32;
    n2c += l.shapes.iter().map(|s| 8 * s.rows.len() + 8).sum::<usize>();
    n2c += 16 * l.n_in + 65; // online labels and corrections, N's key share
    let mut c2n = 32 + 32 + 32 + 97; // seed, d, key-share commitment and opening
    for s in 0..N_STAGES {
        c2n += 1 + 32 + l.reported(s).iter().map(|&g| sp.outs[g].len / 8).sum::<usize>();
    }
    (c2n, n2c)
}

/// Bytes N→C by kind (tables, check rows and Y_N, mask commitment bits,
/// label-check pairs, online labels), for reports.
pub fn download_breakdown() -> [(&'static str, usize); 5] {
    let l = lay();
    [
        ("three-halves tables", gc::tables_len(l.n_and)),
        ("check rows and Y_N", l.shapes.iter().map(|s| 8 * s.rows.len() + 8).sum()),
        ("mask commitment bits", l.mac_fixed.div_ceil(8)),
        ("label-check pairs", 32 * l.n_pairs),
        ("online labels and corrections", 16 * l.n_in),
    ]
}
