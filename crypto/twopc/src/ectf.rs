//! ECtF: point-addition share conversion over the P-256 base field.
//!
//! C holds `Q_C = (x1, y1)`, N holds `Q_N = (x2, y2)`; they want additive
//! shares of `x(Q_C + Q_N) = λ² − x1 − x2` with `λ = (y2 − y1)/(x2 − x1)`.
//!
//! 1. A2M on `[y2 − y1, x2 − x1]` (C inputs `[−y1, −x1]`, N `[y2, x2]`) gives
//!    multiplicative shares `a_C·a_N = y2 − y1`, `b_C·b_N = x2 − x1`.
//! 2. Locally `c_P = (a_P / b_P)²`, so `c_C·c_N = λ²`.
//! 3. M2A on `c` gives `d_C + d_N = λ²`.
//! 4. `x_C = d_C − x1`, `x_N = d_N − x2`.
//!
//! The conversions are mpz2's OLE-based A2M/M2A (semi-honest), on random OLE
//! generated from KOS random-COT (Chou–Orlandi base OT). The random OLEs are
//! input independent and generated in `preprocess`.

use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::p256::P256;
use mpz_ot::{
    chou_orlandi, kos,
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{
    A2MOutput, AdditiveToMultiplicative, M2AOutput, MultiplicativeToAdditive,
    ShareConversionReceiver, ShareConversionSender,
};
use rand::{Rng, RngExt};

use crate::{Error, Result};

type RoleS = mpz_ole::Sender<AnySender<RandomizeRCOTSender<kos::Sender<chou_orlandi::Receiver>>>, P256>;
type RoleR = mpz_ole::Receiver<AnyReceiver<RandomizeRCOTReceiver<kos::Receiver<chou_orlandi::Sender>>>, P256>;

pub(crate) enum Sc {
    /// C side.
    S(ShareConversionSender<RoleS, P256>),
    /// N side.
    R(ShareConversionReceiver<RoleR, P256>),
}

fn err<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Protocol(format!("ectf {what}: {e}"))
}

impl Sc {
    pub fn new_sender<R: Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let base = chou_orlandi::Receiver::new_with_seed(rng.random());
        let kos = kos::Sender::new(kos::SenderConfig::default(), Block::random(rng), base);
        let rot = AnySender::new(RandomizeRCOTSender::new(kos));
        let role = mpz_ole::Sender::new(Block::random(rng), rot);
        Sc::S(ShareConversionSender::new(role))
    }

    pub fn new_receiver<R: Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let base = chou_orlandi::Sender::new_with_seed(rng.random());
        let kos = kos::Receiver::new(kos::ReceiverConfig::default(), base);
        let rot = AnyReceiver::new(RandomizeRCOTReceiver::new(kos));
        let role = mpz_ole::Receiver::new(rot);
        Sc::R(ShareConversionReceiver::new(role))
    }

    /// Generates the random OLEs for 2 A2M + 1 M2A.
    pub async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
        match self {
            Sc::S(s) => {
                AdditiveToMultiplicative::alloc(s, 2).map_err(err("alloc"))?;
                MultiplicativeToAdditive::alloc(s, 1).map_err(err("alloc"))?;
                s.flush(ctx).await.map_err(err("role"))?;
            }
            Sc::R(r) => {
                AdditiveToMultiplicative::alloc(r, 2).map_err(err("alloc"))?;
                MultiplicativeToAdditive::alloc(r, 1).map_err(err("alloc"))?;
                r.flush(ctx).await.map_err(err("role"))?;
            }
        }
        Ok(())
    }

    async fn a2m(&mut self, ctx: &mut Context, inputs: &[P256]) -> Result<Vec<P256>> {
        let out = match self {
            Sc::S(s) => {
                let f = s.queue_to_multiplicative(inputs).map_err(err("a2m"))?;
                s.flush(ctx).await.map_err(err("a2m"))?;
                f.await.map_err(err("a2m"))?
            }
            Sc::R(r) => {
                let f = r.queue_to_multiplicative(inputs).map_err(err("a2m"))?;
                r.flush(ctx).await.map_err(err("a2m"))?;
                f.await.map_err(err("a2m"))?
            }
        };
        let A2MOutput { shares } = out;
        Ok(shares)
    }

    async fn m2a(&mut self, ctx: &mut Context, inputs: &[P256]) -> Result<Vec<P256>> {
        let out = match self {
            Sc::S(s) => {
                let f = s.queue_to_additive(inputs).map_err(err("m2a"))?;
                s.flush(ctx).await.map_err(err("m2a"))?;
                f.await.map_err(err("m2a"))?
            }
            Sc::R(r) => {
                let f = r.queue_to_additive(inputs).map_err(err("m2a"))?;
                r.flush(ctx).await.map_err(err("m2a"))?;
                f.await.map_err(err("m2a"))?
            }
        };
        let M2AOutput { shares } = out;
        Ok(shares)
    }

    /// Runs the point-addition conversion for this party's point `(x, y)`
    /// and returns its additive share of the sum's x-coordinate. The local
    /// intermediates are overwritten before returning (copies inside mpz2's
    /// OLE state are out of reach).
    pub async fn point_add_x(&mut self, ctx: &mut Context, x: P256, y: P256) -> Result<P256> {
        let mut inputs = match self {
            Sc::S(_) => [-y, -x],
            Sc::R(_) => [y, x],
        };
        let r = self.point_add_x_inner(ctx, &inputs, x).await;
        wipe_fps(&mut inputs);
        r
    }

    async fn point_add_x_inner(&mut self, ctx: &mut Context, inputs: &[P256; 2], x: P256) -> Result<P256> {
        let mut m = self.a2m(ctx, inputs).await?;
        if m.len() != 2 {
            wipe_fps(&mut m);
            return Err(Error::Protocol("ectf: a2m output length".into()));
        }
        let Some(mut inv) = m[1].inverse() else {
            wipe_fps(&mut m);
            return Err(Error::Protocol("ectf: degenerate share".into()));
        };
        let mut lam = m[0] * inv;
        let mut c = [lam * lam];
        wipe_fps(&mut m);
        wipe_fp(&mut inv);
        wipe_fp(&mut lam);
        let d = self.m2a(ctx, &c).await;
        wipe_fps(&mut c);
        let mut d = d?;
        let r = if d.len() == 1 {
            Ok(d[0] - x)
        } else {
            Err(Error::Protocol("ectf: m2a output length".into()))
        };
        wipe_fps(&mut d);
        r
    }
}

/// Overwrites a secret field element. mpz2's `P256` is `Copy` without a
/// `Zeroize` impl, so this does what `zeroize` does for such types: a
/// volatile write the compiler cannot elide, then a fence.
pub(crate) fn wipe_fp(x: &mut P256) {
    // SAFETY: `x` is a valid, aligned, exclusive reference, and the value
    // written is a valid `P256` (which has no drop glue).
    unsafe { std::ptr::write_volatile(x, P256::zero()) };
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn wipe_fps(v: &mut [P256]) {
    for x in v {
        wipe_fp(x);
    }
}

/// A secret field element, overwritten when dropped.
pub(crate) struct SecretFp(pub P256);

impl Drop for SecretFp {
    fn drop(&mut self) {
        wipe_fp(&mut self.0);
    }
}

use mpz_fields::Field as _;
