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
type RoleRx = mpz_ole::Receiver<AnyReceiver<RandomizeRCOTReceiver<kos::Receiver<chou_orlandi::Sender>>>, P256>;
#[cfg(not(test))]
type RoleR = RoleRx;
#[cfg(test)]
type RoleR = lab::Tap<RoleRx>;

pub(crate) enum Sc {
    /// C side.
    S(ShareConversionSender<RoleS, P256>),
    /// N side (in tests with what its ROLE tap recorded).
    R(
        ShareConversionReceiver<RoleR, P256>,
        #[cfg(test)] lab::Recorded,
    ),
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
        #[cfg(test)]
        let (role, rec) = lab::Tap::new(role);
        Sc::R(
            ShareConversionReceiver::new(role),
            #[cfg(test)]
            rec,
        )
    }

    /// Generates the random OLEs for 2 A2M + 1 M2A.
    pub async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
        match self {
            Sc::S(s) => {
                AdditiveToMultiplicative::alloc(s, 2).map_err(err("alloc"))?;
                MultiplicativeToAdditive::alloc(s, 1).map_err(err("alloc"))?;
                s.flush(ctx).await.map_err(err("role"))?;
            }
            Sc::R(r, ..) => {
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
            Sc::R(r, ..) => {
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
            Sc::R(r, ..) => {
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
    ///
    /// `dev` holds test deviations and the trace; outside tests it is empty.
    pub(crate) async fn point_add_x(&mut self, ctx: &mut Context, x: P256, y: P256, dev: &mut Dev) -> Result<P256> {
        let mut inputs = match self {
            Sc::S(_) => [-y, -x],
            Sc::R(..) => [y, x],
        };
        let r = self.point_add_x_inner(ctx, &inputs, x, dev).await;
        wipe_fps(&mut inputs);
        r
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    async fn point_add_x_inner(&mut self, ctx: &mut Context, inputs: &[P256; 2], x: P256, dev: &mut Dev) -> Result<P256> {
        let mut m = self.a2m(ctx, inputs).await?;
        if m.len() != 2 {
            wipe_fps(&mut m);
            return Err(Error::Protocol("ectf: a2m output length".into()));
        }
        #[cfg(test)]
        self.c_masks_effect(&mut m, dev);
        let Some(mut inv) = m[1].inverse() else {
            wipe_fps(&mut m);
            return Err(Error::Protocol("ectf: degenerate share".into()));
        };
        let mut lam = m[0] * inv;
        let mut c = [lam * lam];
        #[cfg(test)]
        {
            if dev.zero_c {
                c[0] = P256::zero();
            }
            dev.trace = Some(Trace { m: [m[0], m[1]], c: c[0], d: P256::zero() });
        }
        wipe_fps(&mut m);
        wipe_fp(&mut inv);
        wipe_fp(&mut lam);
        let d = self.m2a(ctx, &c).await;
        wipe_fps(&mut c);
        let mut d = d?;
        #[cfg(test)]
        if let (Some(t), Some(d0)) = (dev.trace.as_mut(), d.first()) {
            t.d = *d0;
        }
        let r = if d.len() == 1 {
            Ok(d[0] - x)
        } else {
            Err(Error::Protocol("ectf: m2a output length".into()))
        };
        wipe_fps(&mut d);
        r
    }
}

/// Test deviations of one conversion and what it computed. The production
/// path uses the default (no deviation, no trace).
#[derive(Debug, Default)]
pub(crate) struct Dev {
    /// N: feeds 0 to the M2A instead of its `c`.
    #[cfg(test)]
    pub zero_c: bool,
    /// N: applies the effect a deviating C (the OLE sender) has on N's second
    /// A2M output (see [`lab::CMasks`]).
    #[cfg(test)]
    pub c_masks: Option<lab::CMasks>,
    /// This party's A2M outputs, its M2A input and output.
    #[cfg(test)]
    pub trace: Option<Trace>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Trace {
    pub m: [P256; 2],
    pub c: P256,
    pub d: P256,
}

#[cfg(test)]
impl Sc {
    /// The ROLE receiver's multiplicative shares (N's `b` of each OLE, in
    /// order of use), as recorded by the tap.
    pub(crate) fn role_b(&self) -> Vec<P256> {
        match self {
            Sc::R(_, rec) => rec.lock().unwrap().clone(),
            Sc::S(_) => Vec::new(),
        }
    }

    /// N's second A2M output after a deviation of C's correlation for bit j
    /// of that OLE (see [`lab::CMasks`]).
    fn c_masks_effect(&self, m: &mut [P256], dev: &Dev) {
        let Some(cm) = dev.c_masks else { return };
        let b = self.role_b();
        let Some(b1) = b.get(1) else { return };
        let le: [u8; 32] = (*b1).into();
        let delta_j = (le[cm.j / 8] >> (cm.j % 8)) & 1 == 1;
        let mut pow = [0u8; 32];
        pow[cm.j / 8] = 1 << (cm.j % 8);
        let term = if delta_j { P256::try_from(pow).expect("2^j < p") * cm.w } else { P256::zero() };
        m[1] = if cm.force { term } else { m[1] + term };
    }
}

/// Test instruments for the share conversion.
#[cfg(test)]
pub(crate) mod lab {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use mpz_common::{Context, Flush};
    use mpz_fields::p256::P256;
    use mpz_ole::{ROLEReceiver, ROLEReceiverOutput};

    /// A deviation of C, the OLE sender, in its masked correlations for one
    /// bit j of the second A2M's OLE (`u_j` sent with `a_j = a + w`), and,
    /// with `force`, also in the other bits (`a_i = 0`) and in its masked
    /// share (`masked = x`). On N, the receiver, the first gives the A2M output
    /// `m_N + 2^j·δ_j·w`, the second `2^j·δ_j·w`, with δ_j = bit j of N's ROLE
    /// share `b` (the ROT choice bit, except when the 256 bits are ≥ p).
    ///
    /// Reproducing mpz2's private message types to send those values on the
    /// wire would mean copying its serialisation; the tests instead apply the
    /// effect where N's code consumes the A2M output, with δ_j read from N's
    /// real ROLE share. What they test is N's handling of every value C can
    /// cause there, not mpz2's parsing.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct CMasks {
        pub j: usize,
        pub w: P256,
        pub force: bool,
    }

    /// A ROLE receiver that records its multiplicative shares (tests only;
    /// otherwise it passes everything through).
    pub(crate) struct Tap<T> {
        inner: T,
        b: Arc<Mutex<Vec<P256>>>,
    }

    /// What the tap recorded.
    pub(crate) type Recorded = Arc<Mutex<Vec<P256>>>;

    impl<T> Tap<T> {
        pub fn new(inner: T) -> (Self, Recorded) {
            let b = Recorded::default();
            (Tap { inner, b: b.clone() }, b)
        }
    }

    impl<T> ROLEReceiver<P256> for Tap<T>
    where
        T: ROLEReceiver<P256>,
    {
        type Error = T::Error;
        type Future = T::Future;

        fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
            self.inner.alloc(count)
        }

        fn available(&self) -> usize {
            self.inner.available()
        }

        fn try_recv_role(&mut self, count: usize) -> Result<ROLEReceiverOutput<P256>, Self::Error> {
            let out = self.inner.try_recv_role(count)?;
            self.b.lock().unwrap().extend(out.shares.iter().map(|s| s.mul));
            Ok(out)
        }

        fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
            self.inner.queue_recv_role(count)
        }
    }

    impl<T> Flush for Tap<T>
    where
        T: Flush + Send,
    {
        type Error = T::Error;

        fn wants_flush(&self) -> bool {
            self.inner.wants_flush()
        }

        fn flush<'a, 'b, 'c>(
            &'a mut self,
            ctx: &'b mut Context,
        ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + 'c>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            self.inner.flush(ctx)
        }
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
