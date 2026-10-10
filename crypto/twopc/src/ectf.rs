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
    /// and returns its additive share of the sum's x-coordinate.
    pub async fn point_add_x(&mut self, ctx: &mut Context, x: P256, y: P256) -> Result<P256> {
        let inputs = match self {
            Sc::S(_) => [-y, -x],
            Sc::R(_) => [y, x],
        };
        let m = self.a2m(ctx, &inputs).await?;
        if m.len() != 2 {
            return Err(Error::Protocol("ectf: a2m output length".into()));
        }
        let inv = m[1]
            .inverse()
            .ok_or_else(|| Error::Protocol("ectf: degenerate share".into()))?;
        let lam = m[0] * inv;
        let c = lam * lam;
        let d = self.m2a(ctx, &[c]).await?;
        if d.len() != 1 {
            return Err(Error::Protocol("ectf: m2a output length".into()));
        }
        Ok(d[0] - x)
    }
}

use mpz_fields::Field as _;
