//! PoC: the protocol-v2 two-party TLS 1.3 key schedule with **only N
//! garbling** (see `REPORT.md`).
//!
//! Same API, inputs and outputs as `crypto/twopc` (`docs/TWOPC-DESIGN.md`):
//!
//! ```ignore
//! let mut p = Party::new(Role::C, io).await?;
//! p.preprocess().await?;
//! let joint = p.key_share().await?;
//! let hs = p.handshake(&server_share, th_sh).await?;   // ECtF + phase A
//! let ap = p.application(th_sf).await?;                // phase B
//! ```
//!
//! # Protocol
//!
//! N (garbler) garbles both phase circuits once (half-gates, global offset
//! Δ_A). Instead of a second garbling by C (dual execution), C is protected
//! by **IT-MACs on N's wire masks** under C's key Δ_B and a batched
//! consistency check of every AND gate:
//!
//! * **Preprocess.** Random COT with C as sender (Δ_B; Ferret over KOS, or
//!   KOS alone) authenticates, by `Fix` (N sends `d = λ ⊕ r`), N's mask λ_w of
//!   every circuit input and AND output, and `t_k = λ_i·λ_j` of every AND gate.
//!   N sends the garbled tables and the `d` bits, C then sends a random seed
//!   (χ). N proves `t_k = λ_i·λ_j` for all gates (QuickSilver-style, two field
//!   elements), opens the masks of C's input wires, the transcript-hash wires
//!   and all output wires (values + one hash of MACs), and sends the check
//!   rows `T_b` and `Y_N` (`gc::check_material`). KOS random-COT with N as
//!   sender (Δ_A) for C's input bits, and the ECtF OLEs, as in `twopc`.
//! * **Phase.** C sends `d = x ⊕ b` (Beaver derandomisation of its COTs), N
//!   sends its own and the transcript-hash input labels, then the corrections
//!   for C's labels. C checks the pointer bits of its own and of the
//!   transcript-hash wires against the opened masks, evaluates, runs the
//!   consistency check, decodes its outputs with the opened (authenticated)
//!   masks and only then sends N the output pointer bits plus a hash of the
//!   corresponding output labels, which N checks against its labels.
//!
//! # Security (sketch; see REPORT.md)
//!
//! * Malicious N: the masks λ are fixed (committed under Δ_B) before χ; if
//!   any AND gate is evaluated inconsistently with them, the check fails except
//!   with probability ~2^-128 (Δ_B and χ unknown to N when it commits). With
//!   all gates consistent, C's decoded outputs are the correct function of the
//!   inputs (C's inputs are pinned by the pointer-bit check against the
//!   opened masks, the transcript hash likewise, outputs decode with
//!   authenticated masks). What N can still do is a *selective failure*: make
//!   C abort depending on C's private values (corrupted rows, bad check rows,
//!   wrong KOS correlation). That is one predicate per phase, observed as
//!   abort/continue, the same leakage class as the deployed dual execution.
//! * Malicious C: C is the evaluator; it learns only active labels, Λ values
//!   (pointer bits; masks unknown), the opened masks (its inputs, public th,
//!   outputs, all of which it may know), one-time-padded check rows, and
//!   `Y_N`, which equals a value C can compute itself. It cannot report a
//!   wrong output to N without the inactive output label (needs Δ_A).
//! * Inputs are never revealed by either party (no opening afterwards).

mod ectf;
pub mod gc;
mod mux;
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
use zeroize::Zeroize;

pub use mux::Counters;
use mux::{FrameChan, Mux};
use twopc::circuits::{PHASE_A, PHASE_B, Spec, from_bits, to_bits};

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

/// Source of the random COTs that authenticate N's masks (C = sender, Δ_B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacCot {
    /// Ferret (LPN, silent) bootstrapped from KOS: little traffic either way,
    /// the Ferret GGM-tree messages go C→N.
    Ferret,
    /// KOS only: C uploads almost nothing, N sends 16 B per COT to C.
    Kos,
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub mac_cot: MacCot,
}

impl Default for Config {
    fn default() -> Self {
        Config { mac_cot: MacCot::Ferret }
    }
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

#[derive(Debug, Clone)]
pub struct StepTiming {
    pub step: &'static str,
    pub ms: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
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
    /// N: corrupt both half-gate rows of 64 AND gates of a phase.
    CorruptGate(usize),
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

enum MacSender {
    Ferret(Box<FerS>),
    Kos(Box<KosS>),
}
enum MacReceiver {
    Ferret(Box<FerR>),
    Kos(Box<KosR>),
}

/// N's per-phase state.
struct NPhase {
    k: Vec<Block>,
    lam: Vec<bool>,
}

/// C's per-phase state.
struct CPhase {
    tables: Vec<[Block; 2]>,
    ck: Option<gc::CheckKeys>,
    rows: Vec<Block>,
    y_n: Block,
    /// Opened masks: C's input wires, th wires, outputs.
    lam_c: Vec<bool>,
    lam_th: Vec<bool>,
    lam_out: Vec<bool>,
}

enum Pre {
    N {
        ph: Vec<NPhase>,
        /// KOS keys for C's input bits (phase A then B).
        cot_keys: Vec<Block>,
    },
    C {
        ph: Vec<CPhase>,
        cot_choices: Vec<bool>,
        cot_msgs: Vec<Block>,
    },
}

const CH_COTA: usize = 0; // KOS for C's input labels (N sender, Δ_A)
const CH_COTB: usize = 1; // MAC COTs (C sender, Δ_B)
const CH_SC: usize = 2; // share conversion
const CH_N2C: usize = 3; // all N→C protocol messages
const CH_C2N: usize = 4; // all C→N protocol messages
const N_CH: usize = 5;

const TAG_KS: &[u8] = b"routstr-twopc-v2 key-share commit";
const TAG_OPEN: &[u8] = b"routstr-twopc-ag open";
const TAG_OUT: &[u8] = b"routstr-twopc-ag output labels";
const TAG_CHI: &[u8] = b"routstr-twopc-ag chi";

pub(crate) fn spec(phase: usize) -> &'static Spec {
    match phase {
        0 => &PHASE_A,
        _ => &PHASE_B,
    }
}

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
    rng: StdRng,
    /// N: garbling offset Δ_A. C: MAC key Δ_B.
    delta: Block,
    kos_a_s: Option<KosS>,
    kos_a_r: Option<KosR>,
    mac_s: Option<MacSender>,
    mac_r: Option<MacReceiver>,
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

fn chi(seed: &[u8], what: &[u8]) -> Block {
    let h: [u8; 32] = Sha256::new()
        .chain_update(TAG_CHI)
        .chain_update(seed)
        .chain_update(what)
        .finalize()
        .into();
    Block::new(h[..16].try_into().unwrap())
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
    Fp::try_from(le).map_err(|_| Error::Protocol("non-canonical coordinate".into()))
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
        Self::with_config(role, io, Config::default()).await
    }

    pub async fn with_config<IO>(role: Role, io: IO, cfg: Config) -> Result<Party>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mux, mut chans) = Mux::start(io, N_CH);
        let counters = mux.counters.clone();
        let mut take = |i: usize| std::mem::replace(&mut chans[i], tokio::io::duplex(1).0);
        let ctx_a = Context::new_single_threaded(take(CH_COTA).compat());
        let ctx_b = Context::new_single_threaded(take(CH_COTB).compat());
        let ctx_sc = Context::new_single_threaded(take(CH_SC).compat());
        let n2c = FrameChan::new(take(CH_N2C));
        let c2n = FrameChan::new(take(CH_C2N));

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
                mac_r = Some(match cfg.mac_cot {
                    MacCot::Ferret => MacReceiver::Ferret(Box::new(ferret::Receiver::new(fcfg(), rng.random(), kr))),
                    MacCot::Kos => MacReceiver::Kos(Box::new(kr)),
                });
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
                mac_s = Some(match cfg.mac_cot {
                    MacCot::Ferret => MacSender::Ferret(Box::new(ferret::Sender::new(fcfg(), rng.random(), ks))),
                    MacCot::Kos => MacSender::Kos(Box::new(ks)),
                });
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
                    let in_keys: Vec<Block> = (0..s.circ.inputs().len()).map(|_| Block::random(&mut grng)).collect();
                    gc::garble(&s.circ, delta, &in_keys, p)
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
            kos_a_s,
            mac_r,
            sc,
            ..
        } = self;

        // Garble and stream the tables while the OTs run.
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
                        t[0] = t[0] ^ Block::ONE;
                        t[1] = t[1] ^ Block::ONE;
                    }
                }
                let _ = p;
                let flat: Vec<Block> = tables.iter().flat_map(|t| [t[0], t[1]]).collect();
                n2c.send(&blocks_to_bytes(&flat)).await?;
                keep.push(k);
            }
            Ok::<_, Error>(keep)
        };
        let cot_a_fut = async {
            let keys = rcot_send!(kos_a_s.as_mut().unwrap(), ctx_a, c_bits);
            Ok::<_, Error>(keys)
        };
        let cot_b_fut = async {
            let (r, m) = match mac_r.as_mut().unwrap() {
                MacReceiver::Ferret(f) => rcot_recv!(f.as_mut(), ctx_b, n_mac),
                MacReceiver::Kos(k) => rcot_recv!(k.as_mut(), ctx_b, n_mac),
            };
            Ok::<_, Error>((r, m))
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
            let base_mac = r_macs[off..off + nb].to_vec();
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
            st.push((lam, mac, t_mac));
        }
        let mask_bits = &r_bits[off..off + 128];
        let mask_macs = &r_macs[off..off + 128];
        n2c.send(&from_bits(&d_bits)).await?;

        // Challenge.
        let seed = c2n.recv_exact(32).await?;
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck = [chi(&seed, b"check0"), chi(&seed, b"check1")];

        // Product check, openings, consistency-check material (CPU, blocking).
        let mask_bits = mask_bits.to_vec();
        let mask_macs = mask_macs.to_vec();
        let (st, keys, msgs) = tokio::task::spawn_blocking(move || {
            let mut acc = (Block::ZERO, Block::ZERO);
            let mut msgs: Vec<Vec<u8>> = Vec::new();
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

            // Check rows and Y_N per phase.
            for (p, (lam, mac, t_mac)) in st.iter().enumerate() {
                let s = spec(p);
                let pw = gc::powers(chi_ck[p], t_mac.len());
                let cm = gc::check_material(
                    &s.circ,
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
                    y_n = y_n ^ Block::ONE;
                }
                msgs.push(blocks_to_bytes(&cm.rows));
                msgs.push(y_n.as_bytes().to_vec());
            }
            (st, keys, msgs)
        })
        .await
        .map_err(perr("preprocess task"))?;
        for msg in msgs {
            n2c.send(&msg).await?;
        }

        let ph = st
            .into_iter()
            .zip(keys)
            .map(|((lam, _, _), k)| NPhase { k, lam })
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
            kos_a_r,
            mac_s,
            sc,
            ..
        } = self;

        let recv_fut = async {
            let mut t = Vec::new();
            for p in 0..2 {
                let s = spec(p);
                let b = n2c.recv_exact(32 * s.circ.and_count()).await?;
                let bl = bytes_to_blocks(&b);
                t.push(bl.chunks_exact(2).map(|c| [c[0], c[1]]).collect::<Vec<_>>());
            }
            let d = n2c.recv_exact((n_mac - 128).div_ceil(8)).await?;
            Ok::<_, Error>((t, unpack(&d, n_mac - 128)))
        };
        let cot_a_fut = async {
            let (c, m) = rcot_recv!(kos_a_r.as_mut().unwrap(), ctx_a, own_bits);
            Ok::<_, Error>((c, m))
        };
        let cot_b_fut = async {
            let keys = match mac_s.as_mut().unwrap() {
                MacSender::Ferret(f) => rcot_send!(f.as_mut(), ctx_b, n_mac),
                MacSender::Kos(k) => rcot_send!(k.as_mut(), ctx_b, n_mac),
            };
            Ok::<_, Error>(keys)
        };
        let sc_fut = sc.preprocess(ctx_sc);
        let (rcv, cr, kb, scr) = futures::join!(recv_fut, cot_a_fut, cot_b_fut, sc_fut);
        let (tables, d) = rcv?;
        let (cot_choices, cot_msgs) = cr?;
        let kb = kb?;
        scr?;
        if kb.len() != n_mac || cot_choices.len() != own_bits {
            return Err(Error::Protocol("cot count".into()));
        }
        // Keys of the committed values: K[x] = K[r] ⊕ d·Δ_B.
        // (The last 128 COTs stay random: they mask the product check.)
        let kfix: Vec<Block> = kb
            .iter()
            .enumerate()
            .map(|(i, k)| if i < d.len() { *k ^ sel(d[i], delta_b) } else { *k })
            .collect();
        // The χ challenge only after N's tables and commitments are in.
        c2n.send(&seed).await?;

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
                let r = n2c.recv_exact(16 * SHAPES[p].base.len()).await?;
                let y = n2c.recv_exact(16).await?;
                rows.push((bytes_to_blocks(&r), Block::new(y[..].try_into().unwrap())));
            }
            Ok::<_, Error>((dv, open, rows))
        };
        let chi_dv = chi(&seed, b"dvzk");
        let chi_ck = [chi(&seed, b"check0"), chi(&seed, b"check1")];
        let compute = tokio::task::spawn_blocking(move || {
            let mut off = 0;
            let mut per = Vec::new();
            let mut acc = Block::ZERO;
            for p in 0..2 {
                let s = spec(p);
                let shape = &SHAPES[p];
                let nb = shape.base.len();
                let key = gc::propagate_c(&s.circ, &kfix[off..off + nb], delta_b);
                off += nb;
                let na = shape.ands.len();
                let t_key = kfix[off..off + na].to_vec();
                off += na;
                let pw = gc::powers(chi_dv.gfmul(Block::new(((p as u128) + 1).to_le_bytes())), na);
                gc::dvzk_verifier_acc(&shape.ands, &key, &t_key, delta_b, &pw, &mut acc);
                let pw = gc::powers(chi_ck[p], na);
                let ck = gc::check_keys(&shape.ands, &key, &t_key, &pw);
                per.push((key, ck));
            }
            let mut k_star = Block::ZERO;
            for i in 0..128 {
                k_star ^= Block::MONOMIAL[i].gfmul(kfix[off + i]);
            }
            (per, acc ^ k_star)
        });
        let (r2, comp) = futures::join!(recv2, compute);
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

    /// One phase. Returns the decoded output bytes (only after the checks).
    async fn run_phase(&mut self, phase: usize, own: Vec<u8>, th: [u8; 32]) -> Result<Vec<u8>> {
        let name = ["phase_a", "phase_b"][phase];
        let m = self.mark();
        let r = match self.role {
            Role::N => self.phase_n(phase, own, th).await,
            Role::C => self.phase_c(phase, own, th).await,
        };
        self.record(name, m);
        r
    }

    async fn phase_n(&mut self, phase: usize, own: Vec<u8>, th: [u8; 32]) -> Result<Vec<u8>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let s = spec(phase);
        let own_bits = to_bits(&own);
        if own_bits.len() != s.n_bits {
            return Err(Error::Input("input length".into()));
        }
        let th_bits = to_bits(&th);
        let delta = self.delta;
        let c_off = if phase == 0 { 0 } else { spec(0).c_bits };
        let Some(Pre::N { ph, cot_keys }) = self.pre.as_mut() else {
            return Err(Error::State("not preprocessed"));
        };
        let st = std::mem::replace(&mut ph[phase], NPhase { k: Vec::new(), lam: Vec::new() });
        if st.k.is_empty() {
            return Err(Error::State("phase already used"));
        }
        let cot = cot_keys[c_off..c_off + s.c_bits].to_vec();

        // Own and transcript-hash labels, sent at once.
        let mut labels = Vec::with_capacity(s.n_bits + s.th_bits);
        for (w, b) in s.n_range().zip(&own_bits) {
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
        Ok(from_bits(&v))
    }

    async fn phase_c(&mut self, phase: usize, own: Vec<u8>, th: [u8; 32]) -> Result<Vec<u8>> {
        #[allow(unused_variables)]
        let cheat = self.cheat();
        let s = spec(phase);
        let own_bits = to_bits(&own);
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
        let lam_c = ph[phase].lam_c.clone();
        let lam_th = ph[phase].lam_th.clone();
        let lam_out = ph[phase].lam_out.clone();
        let b = cot_choices[c_off..c_off + s.c_bits].to_vec();
        let msgs = cot_msgs[c_off..c_off + s.c_bits].to_vec();

        let d: Vec<bool> = own_bits.iter().zip(&b).map(|(x, r)| x ^ r).collect();
        self.c2n.send(&from_bits(&d)).await?;
        let gl = bytes_to_blocks(&self.n2c.recv_exact(16 * (s.n_bits + s.th_bits)).await?);
        let el = bytes_to_blocks(&self.n2c.recv_exact(16 * s.c_bits).await?);
        let mut inl = vec![Block::ZERO; s.circ.inputs().len()];
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
            let l = gc::evaluate(&circ, &inl, &tables, phase);
            let ok = gc::run_check(phase, &SHAPES[phase].ands, &SHAPES[phase].base, &l, &st, &rows, y_n, delta_b);
            let out: Vec<Block> = circ.outputs().map(|w| l[w]).collect();
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
        let v: Vec<bool> = out_labels.iter().zip(&lam_out).map(|(l, m)| l.lsb() ^ m).collect();
        #[allow(unused_mut)]
        let mut pbits: Vec<bool> = out_labels.iter().map(|l| l.lsb()).collect();
        let mut h = Sha256::new();
        h.update(TAG_OUT);
        h.update([phase as u8]);
        for l in &out_labels {
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
        Ok(from_bits(&v))
    }
}

/// Bytes of the protocol messages per session, by direction, as computed
/// from the circuit sizes (for reports). Excludes OT extension traffic.
pub fn message_sizes() -> (usize, usize) {
    let mut n2c = 0;
    let mut c2n = 0;
    for p in 0..2 {
        let s = spec(p);
        n2c += 32 * s.circ.and_count(); // tables
        n2c += macs_per_phase(s).div_ceil(8); // d bits (approx; one message)
        n2c += 16 * SHAPES[p].base.len() + 16; // check rows + Y_N
        n2c += (s.c_bits + s.th_bits + s.out_bits).div_ceil(8);
        n2c += 16 * (s.n_bits + s.th_bits + s.c_bits); // online labels
        c2n += s.c_bits.div_ceil(8) + 1 + s.out_bits.div_ceil(8) + 32;
    }
    n2c += 32 + 32;
    c2n += 32;
    (c2n, n2c)
}
