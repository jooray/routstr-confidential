//! The v2 session's long-lived proof channel (pre-warmed VOLE correlations).
//!
//! A cold proof ([`crate::proofs::run_io`]) opens its own connection and runs
//! base OT (Chou-Orlandi) → KOS → one Ferret extension before QuickSilver even
//! starts: several round trips and ~1 MB, almost all of it independent of the
//! statement. A [`ZkChannel`] does that setup once per session, while the
//! session is armed, and keeps the correlations for the session's proofs:
//!
//! * chain **nk** (node proves, client verifies): π_NK. The client is the
//!   RCOT sender and holds this chain's Δ.
//! * chain **cp** (client proves, node verifies): π_C2S then π_C3S. The node
//!   is the RCOT sender and holds this chain's Δ.
//!
//! Both chains and a small control conversation share one connection
//! ([`crate::mux`], three channels). At claim time each proof is one control
//! message (`ProofReq`, client → node) followed by QuickSilver over the
//! chain's channel, consuming correlations that already exist. If a proof needs
//! more than were preprocessed, the VM's own flush extends the chain online
//! (one more Ferret iteration, from the COTs Ferret keeps in reserve; no new
//! base OT), so a short allocation costs time, never correctness.
//!
//! Security notes (see also `docs/`):
//! * Correlations and Δ are generated fresh per channel (= per session) and are
//!   never reused across sessions; each correlation is consumed exactly once
//!   (the Ferret buffer hands out disjoint ranges).
//! * One Δ for π_C2S and π_C3S is the same as one QuickSilver VM proving both
//!   statements: VOLE-ZK soundness rests on Δ being unknown to the prover and
//!   on fresh correlations per gate/check, both of which hold. Each proof
//!   keeps its own Fiat-Shamir transcript.
//! * The two chains are independent instances (different directions, different
//!   Δ, different seeds); sharing a transport only interleaves their messages,
//!   and the transport is untrusted in either case (the node relays it).
//! * A failed or aborted proof poisons the channel: no further proof runs on
//!   it, so a cheating prover can never probe a Δ more than once.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use futures::{AsyncRead, AsyncWrite};
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};
use mpz_vm_core::memory::correlated::Delta;
use mpz_zk::{Prover, ProverConfig};
use serio::{SinkExt, stream::IoStreamExt};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::Role;
use crate::mux::{Counters, Mux};
use crate::proofs::{CheckResult, ferret_config, prove_with, verify_with};
use crate::statements::{Params, Witness, build};

/// Wire version of the channel (bumped on any change to its message flow).
pub const CHANNEL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// A shared, re-usable RCOT handle
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PoolInner<T> {
    ot: T,
    /// Correlations the current VM has asked for (`alloc`) and not consumed
    /// yet. The inner Ferret instance only learns about them at flush time,
    /// as a target (`alloc` there means "extend until `available >= alloc`"),
    /// so pre-generated correlations count and none are generated twice.
    pending: usize,
}

/// An RCOT functionality shared by the successive VMs of one chain.
///
/// `mpz_zk::Prover`/`Verifier` take their OT by value and never hand it back;
/// this handle lets each proof of a session take a clone and leaves the
/// correlations (and Ferret's reserve) with the chain. Only one VM uses a chain
/// at a time.
#[derive(Debug)]
pub struct Pooled<T>(Arc<tokio::sync::Mutex<PoolInner<T>>>);

impl<T> Clone for Pooled<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Error of a [`Pooled`] handle.
#[derive(Debug)]
pub struct PoolError(String);

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pooled rcot: {}", self.0)
    }
}
impl std::error::Error for PoolError {}

fn busy() -> PoolError {
    PoolError("chain in use by another VM".into())
}

impl<T> Pooled<T> {
    pub fn new(ot: T) -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(PoolInner { ot, pending: 0 })))
    }

    /// Correlations the current VM has allocated but not consumed.
    pub fn pending(&self) -> usize {
        self.0.try_lock().map(|g| g.pending).unwrap_or(0)
    }
}

/// Generates at least `count` correlations now (both sides must call this
/// with the same `count`, as the flush decision is mirrored).
async fn preprocess<T>(pool: &Pooled<T>, count: usize, ctx: &mut Context, avail: impl Fn(&T) -> usize, alloc: impl Fn(&mut T, usize) -> Result<(), PoolError>) -> Result<usize>
where
    T: Flush + Send,
{
    let mut g = pool.0.lock().await;
    let have = avail(&g.ot);
    if count > have {
        alloc(&mut g.ot, count)?;
    }
    if g.ot.wants_flush() {
        g.ot.flush(ctx).await.map_err(|e| anyhow!("preprocess: {e}"))?;
    }
    Ok(avail(&g.ot))
}

impl<T> RCOTReceiver<bool, Block> for Pooled<T>
where
    T: RCOTReceiver<bool, Block>,
{
    type Error = PoolError;
    type Future = T::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        g.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.0.try_lock().map(|g| g.ot.available()).unwrap_or(0)
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        let out = g.ot.try_recv_rcot(count).map_err(|e| PoolError(e.to_string()))?;
        g.pending = g.pending.saturating_sub(count);
        Ok(out)
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        let out = g.ot.queue_recv_rcot(count).map_err(|e| PoolError(e.to_string()))?;
        g.pending = g.pending.saturating_sub(count);
        Ok(out)
    }
}

impl<T> RCOTSender<Block> for Pooled<T>
where
    T: RCOTSender<Block>,
{
    type Error = PoolError;
    type Future = T::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        g.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.0.try_lock().map(|g| g.ot.available()).unwrap_or(0)
    }

    fn delta(&self) -> Block {
        self.0.try_lock().expect("chain not in use").ot.delta()
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        let out = g.ot.try_send_rcot(count).map_err(|e| PoolError(e.to_string()))?;
        g.pending = g.pending.saturating_sub(count);
        Ok(out)
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let mut g = self.0.try_lock().map_err(|_| busy())?;
        let out = g.ot.queue_send_rcot(count).map_err(|e| PoolError(e.to_string()))?;
        g.pending = g.pending.saturating_sub(count);
        Ok(out)
    }
}

#[async_trait::async_trait]
impl<T> Flush for Pooled<T>
where
    T: RCOTReceiver<bool, Block> + Flush + Send,
{
    type Error = PoolError;

    /// Extend only when the VM's outstanding demand exceeds what the chain
    /// already holds.
    fn wants_flush(&self) -> bool {
        match self.0.try_lock() {
            Ok(g) => g.ot.wants_flush() || g.pending > g.ot.available(),
            Err(_) => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut g = self.0.lock().await;
        let target = g.pending;
        if target > g.ot.available() {
            g.ot.alloc(target).map_err(|e| PoolError(e.to_string()))?;
        }
        g.ot.flush(ctx).await.map_err(|e| PoolError(e.to_string()))
    }
}

// The sender direction gets its own wrapper type, because Rust cannot tell the
// two blanket `Flush` impls apart.

/// The sender-direction counterpart of [`Pooled`].
#[derive(Debug)]
pub struct PooledSend<T>(Pooled<T>);

impl<T> Clone for PooledSend<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: RCOTSender<Block>> RCOTSender<Block> for PooledSend<T> {
    type Error = PoolError;
    type Future = T::Future;
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTSender::alloc(&mut self.0, count)
    }
    fn available(&self) -> usize {
        RCOTSender::available(&self.0)
    }
    fn delta(&self) -> Block {
        self.0.delta()
    }
    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        self.0.try_send_rcot(count)
    }
    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.0.queue_send_rcot(count)
    }
}

#[async_trait::async_trait]
impl<T> Flush for PooledSend<T>
where
    T: RCOTSender<Block> + Flush + Send,
{
    type Error = PoolError;

    fn wants_flush(&self) -> bool {
        match self.0.0.try_lock() {
            Ok(g) => g.ot.wants_flush() || g.pending > g.ot.available(),
            Err(_) => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut g = self.0.0.lock().await;
        let target = g.pending;
        if target > g.ot.available() {
            g.ot.alloc(target).map_err(|e| PoolError(e.to_string()))?;
        }
        g.ot.flush(ctx).await.map_err(|e| PoolError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

type FerretRecv = ferret::Receiver<kos::Receiver<co::Sender>>;
type FerretSend = ferret::Sender<kos::Sender<co::Receiver>>;

enum Chain {
    /// This side proves on the chain (RCOT receiver).
    Prove(Pooled<FerretRecv>),
    /// This side verifies on the chain (RCOT sender, holds Δ).
    Verify(PooledSend<FerretSend>, Delta),
}

impl Chain {
    fn new(prove: bool) -> Self {
        let mut rng = rand::rng();
        if prove {
            let seed = Block::random(&mut rng);
            let kos_recv = kos::Receiver::new(kos::ReceiverConfig::default(), co::Sender::default());
            Chain::Prove(Pooled::new(ferret::Receiver::new(ferret_config(), seed, kos_recv)))
        } else {
            // Fresh Δ for every channel (i.e. every session).
            let delta = Delta::random(&mut rng);
            let seed = Block::random(&mut rng);
            let kos_send = kos::Sender::new(kos::SenderConfig::default(), delta.into_inner(), co::Receiver::default());
            Chain::Verify(PooledSend(Pooled::new(ferret::Sender::new(ferret_config(), seed, kos_send))), delta)
        }
    }

    async fn preprocess(&self, count: usize, ctx: &mut Context) -> Result<usize> {
        match self {
            Chain::Prove(p) => {
                preprocess(p, count, ctx, |t| RCOTReceiver::available(t), |t, n| {
                    RCOTReceiver::alloc(t, n).map_err(|e| PoolError(e.to_string()))
                })
                .await
            }
            Chain::Verify(p, _) => {
                preprocess(&p.0, count, ctx, |t| RCOTSender::available(t), |t, n| {
                    RCOTSender::alloc(t, n).map_err(|e| PoolError(e.to_string()))
                })
                .await
            }
        }
    }

    fn available(&self) -> usize {
        match self {
            Chain::Prove(p) => RCOTReceiver::available(p),
            Chain::Verify(p, _) => RCOTSender::available(p),
        }
    }

    async fn run(&self, ctx: &mut Context, params: &Params, witness: Option<&Witness>) -> Result<Vec<CheckResult>> {
        match self {
            Chain::Prove(p) => {
                prove_with(p.clone(), ctx, params, witness).await?;
                Ok(Vec::new())
            }
            Chain::Verify(p, delta) => verify_with(p.clone(), *delta, ctx, params).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Preallocation
// ---------------------------------------------------------------------------

/// How many correlations to generate up front on each chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Prealloc {
    /// Chain nk (π_NK).
    pub nk: usize,
    /// Chain cp (π_C2S + π_C3S).
    pub cp: usize,
}

impl Default for Prealloc {
    /// Sized from the circuits (`ot_demand_with` on the fixtures: π_NK ≈ 231k
    /// for a 190-byte head, π_C2S ≈ 197k, π_C3S ≈ 403k for a 600-byte tail)
    /// with margin. A Ferret iteration is coarse (n = 256k, 512k, 1024k, …),
    /// so these pick n = 512k for nk (≈ 473k usable: heads up to ~1 kB) and
    /// n = 1024k for cp (≈ 967k usable: π_C2S plus a tail of ~1.5 kB).
    /// Anything larger extends online.
    fn default() -> Self {
        Self { nk: 300_000, cp: 800_000 }
    }
}

/// The exact number of correlations one proof consumes, built on the prover
/// side with `witness`.
pub fn ot_demand_with(params: &Params, witness: &Witness) -> Result<usize> {
    let (_send, recv) = mpz_ot::ideal::rcot::ideal_rcot(Block::ZERO, Block::ONE);
    let pool = Pooled::new(recv);
    let mut prover = Prover::new(ProverConfig::default(), pool.clone());
    build(&mut prover, Role::Prover, params, Some(witness))?;
    drop(prover);
    Ok(pool.pending())
}

// ---------------------------------------------------------------------------
// The channel
// ---------------------------------------------------------------------------

/// Which party of the session this end is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    Client,
    Node,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Hello {
    version: u32,
    nk: u64,
    cp: u64,
}

/// One proof request (client → node, on the control channel).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofReq {
    pub proof: String,
}

/// Phase timing of a channel, for logs and benchmarks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Timing {
    pub step: String,
    pub ms: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// The proof names a channel serves and which chain each uses.
fn chain_of(proof: &str) -> Result<bool> {
    // true = chain nk (node proves), false = chain cp (client proves).
    match proof {
        "pi_nk" => Ok(true),
        "pi_c2s" | "pi_c3s" => Ok(false),
        other => bail!("proof {other} is not served on the proof channel"),
    }
}

fn params_name(params: &Params) -> &'static str {
    match params {
        Params::PiNK(_) => "pi_nk",
        Params::PiC2S(_) => "pi_c2s",
        Params::PiC3S(_) => "pi_c3s",
        Params::PiC1(_) => "pi_c1",
        Params::PiN(_) => "pi_n",
        Params::PiC2(_) => "pi_c2",
        Params::PiC3(_) => "pi_c3",
    }
}

/// A session's proof channel. See the module docs.
pub struct ZkChannel {
    party: Party,
    ctl: Context,
    nk_ctx: Context,
    cp_ctx: Context,
    nk: Chain,
    cp: Chain,
    mux: Option<Mux>,
    counters: Arc<Counters>,
    /// Proofs already run (each at most once per channel).
    done: Vec<String>,
    /// Set by any failure: the channel never runs another proof.
    poisoned: bool,
    timings: Vec<Timing>,
    last: (u64, u64),
}

impl ZkChannel {
    /// Opens the channel over `io` and preprocesses both chains concurrently.
    /// Both parties must call this; the larger of the two sides' preallocation
    /// wins on each chain.
    pub async fn open<IO>(io: IO, party: Party, prealloc: Prealloc) -> Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let t0 = Instant::now();
        let (mux, mut chans) = Mux::start(io, 3);
        let counters = mux.counters.clone();
        let cp_io = chans.pop().expect("3 channels");
        let nk_io = chans.pop().expect("3 channels");
        let ctl_io = chans.pop().expect("3 channels");
        let mut ctl = Context::new_single_threaded(ctl_io.compat());
        let mut nk_ctx = Context::new_single_threaded(nk_io.compat());
        let mut cp_ctx = Context::new_single_threaded(cp_io.compat());

        let mine = Hello { version: CHANNEL_VERSION, nk: prealloc.nk as u64, cp: prealloc.cp as u64 };
        ctl.io_mut().send(mine).await.context("proof channel hello")?;
        let peer: Hello = ctl.io_mut().expect_next().await.context("proof channel hello")?;
        if peer.version != CHANNEL_VERSION {
            bail!("proof channel version {} != {}", peer.version, CHANNEL_VERSION);
        }
        let cap = 1usize << 25;
        let nk_n = (prealloc.nk as u64).max(peer.nk).min(cap as u64) as usize;
        let cp_n = (prealloc.cp as u64).max(peer.cp).min(cap as u64) as usize;

        let nk = Chain::new(party == Party::Node);
        let cp = Chain::new(party == Party::Client);
        let hello_ms = t0.elapsed();
        let t1 = Instant::now();
        // Both chains concurrently (distinct mux channels and contexts).
        let (a, b) = futures::join!(nk.preprocess(nk_n, &mut nk_ctx), cp.preprocess(cp_n, &mut cp_ctx));
        a.context("preprocessing chain nk")?;
        b.context("preprocessing chain cp")?;
        let mut ch = Self {
            party,
            ctl,
            nk_ctx,
            cp_ctx,
            nk,
            cp,
            mux: Some(mux),
            counters,
            done: Vec::new(),
            poisoned: false,
            timings: vec![Timing { step: "hello".into(), ms: hello_ms.as_secs_f64() * 1e3, bytes_sent: 0, bytes_recv: 0 }],
            last: (0, 0),
        };
        ch.mark("preprocess", t1);
        Ok(ch)
    }

    fn mark(&mut self, step: &str, since: Instant) {
        let (s, r) = (self.counters.sent(), self.counters.recv());
        self.timings.push(Timing {
            step: step.to_string(),
            ms: since.elapsed().as_secs_f64() * 1e3,
            bytes_sent: s - self.last.0,
            bytes_recv: r - self.last.1,
        });
        self.last = (s, r);
    }

    /// Timings recorded since the last call.
    pub fn take_timings(&mut self) -> Vec<Timing> {
        std::mem::take(&mut self.timings)
    }

    /// Correlations currently held by (nk, cp), for diagnostics.
    pub fn available(&self) -> (usize, usize) {
        (self.nk.available(), self.cp.available())
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn admit(&mut self, proof: &str) -> Result<bool> {
        if self.poisoned {
            bail!("proof channel is closed after a failure");
        }
        let nk = chain_of(proof)?;
        if self.done.iter().any(|p| p == proof) {
            bail!("{proof} already ran on this channel");
        }
        self.done.push(proof.to_string());
        Ok(nk)
    }

    async fn run_inner(&mut self, nk: bool, params: &Params, witness: Option<&Witness>) -> Result<Vec<CheckResult>> {
        let (chain, ctx) = if nk { (&self.nk, &mut self.nk_ctx) } else { (&self.cp, &mut self.cp_ctx) };
        chain.run(ctx, params, witness).await
    }

    /// Client: run `params`' proof on the channel (π_NK: verify; π_C2S/π_C3S:
    /// prove with `witness`). The node serves it with [`ZkChannel::serve`].
    pub async fn request(&mut self, params: &Params, witness: Option<&Witness>) -> Result<Vec<CheckResult>> {
        if self.party != Party::Client {
            bail!("only the client requests proofs");
        }
        let proof = params_name(params);
        let t = Instant::now();
        let nk = self.admit(proof)?;
        let r = async {
            self.ctl.io_mut().send(ProofReq { proof: proof.to_string() }).await?;
            self.run_inner(nk, params, witness).await
        }
        .await;
        if r.is_err() {
            self.poisoned = true;
        }
        self.mark(proof, t);
        r
    }

    /// Node: wait for the client's next proof request. `Ok(None)` when the
    /// client closed the channel.
    pub async fn next_request(&mut self) -> Result<Option<ProofReq>> {
        if self.poisoned {
            bail!("proof channel is closed after a failure");
        }
        match self.ctl.io_mut().expect_next::<ProofReq>().await {
            Ok(r) => Ok(Some(r)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(anyhow!("proof channel: {e}")),
        }
    }

    /// Node: run its side of `proof` (π_NK: prove with `witness`; π_C2S/π_C3S:
    /// verify) against the node's own `params`.
    pub async fn serve(&mut self, proof: &str, params: &Params, witness: Option<&Witness>) -> Result<Vec<CheckResult>> {
        if self.party != Party::Node {
            bail!("only the node serves proofs");
        }
        if params_name(params) != proof {
            bail!("params are for {}, request is {proof}", params_name(params));
        }
        let t = Instant::now();
        let nk = self.admit(proof)?;
        let r = self.run_inner(nk, params, witness).await;
        if r.is_err() {
            self.poisoned = true;
        }
        self.mark(proof, t);
        r
    }

    /// Mark the channel unusable (e.g. a proof timed out on the caller's side).
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Flushes everything written so far and closes the transport.
    pub async fn close(mut self) {
        let mux = self.mux.take();
        drop(self);
        if let Some(m) = mux {
            m.close().await;
        }
    }

    /// Which side this end proves on for `proof`.
    pub fn role_for(&self, proof: &str) -> Result<Role> {
        let nk = chain_of(proof)?;
        Ok(match (self.party, nk) {
            (Party::Node, true) | (Party::Client, false) => Role::Prover,
            _ => Role::Verifier,
        })
    }
}
