//! Proof drivers: real OT (Chou-Orlandi → KOS → Ferret) over any duplex, and a
//! fast ideal-OT pair for tests over an in-memory duplex.

use anyhow::{anyhow, bail, Result};
use futures::{AsyncRead, AsyncWrite};
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::{RCOTReceiver, RCOTSender},
};
use mpz_vm_core::{Execute, memory::correlated::Delta, prelude::*};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use rand::RngExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Role;
use crate::statements::{Check, Params, Witness, build};
use crate::transport::Counters;

pub(crate) fn ferret_config() -> ferret::FerretConfig {
    ferret::FerretConfig::builder()
        .lpn_type(ferret::LpnType::Regular)
        .build()
        .expect("valid ferret config")
}

/// The result of checking one output on the verifier side.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub label: String,
    pub ok: bool,
    /// Hex of the decoded value (truncated) for diagnostics.
    pub got: String,
    /// The first mismatching byte index, if any.
    pub first_diff: Option<usize>,
}

/// Decide whether a decoded value satisfies a check.
///
/// A `full` check (`compare_len == None`) requires an **exact-length** match:
/// a value longer than `expected` must fail even when `expected` is a prefix of
/// it. A `prefix` check compares only the first `compare_len` bytes.
fn check_ok(expected: &[u8], compare_len: Option<usize>, got: &[u8]) -> bool {
    match compare_len {
        Some(len) => len <= expected.len() && got.len() >= len && got[..len] == expected[..len],
        None => got.len() == expected.len() && got == expected,
    }
}

fn check_results(checks: &[Check], got: &[Vec<u8>]) -> Vec<CheckResult> {
    checks
        .iter()
        .zip(got)
        .map(|(c, g)| {
            let len = c.compare_len.unwrap_or(c.expected.len());
            let ok = check_ok(&c.expected, c.compare_len, g);
            let first_diff = {
                let m = len.min(g.len()).min(c.expected.len());
                (0..m).find(|&i| g[i] != c.expected[i])
            };
            let show = g.len().min(48);
            CheckResult {
                label: c.label.clone(),
                ok,
                got: hex::encode(&g[..show]),
                first_diff,
            }
        })
        .collect()
}

fn all_ok(results: &[CheckResult]) -> bool {
    results.iter().all(|r| r.ok)
}

/// Run one side of a proof over an arbitrary duplex, using real OT.
///
/// The prover's witness is `Some(..)`; the verifier passes `None`.
pub async fn run_io<S>(
    io: S,
    role: Role,
    params: &Params,
    witness: Option<&Witness>,
) -> Result<Vec<CheckResult>>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (delta, base_seed, ferret_seed) = {
        let mut rng = rand::rng();
        (
            Delta::random(&mut rng),
            Block::random(&mut rng),
            Block::random(&mut rng),
        )
    };
    let mut ctx = Context::new_single_threaded(io);

    match role {
        Role::Prover => {
            let base_send = co::Sender::default();
            let kos_recv = kos::Receiver::new(kos::ReceiverConfig::default(), base_send);
            let ferret_recv = ferret::Receiver::new(ferret_config(), ferret_seed, kos_recv);
            prove_with(ferret_recv, &mut ctx, params, witness).await?;
            Ok(Vec::new())
        }
        Role::Verifier => {
            let base_recv = co::Receiver::default();
            let kos_send = kos::Sender::new(kos::SenderConfig::default(), delta.into_inner(), base_recv);
            let ferret_send = ferret::Sender::new(ferret_config(), base_seed, kos_send);
            verify_with(ferret_send, delta, &mut ctx, params).await
        }
    }
}

/// The prover side of one proof over `ctx`, with correlations from `ot`
/// (generated on demand by the VM's flush, or already preprocessed).
pub(crate) async fn prove_with<OT>(
    ot: OT,
    ctx: &mut Context,
    params: &Params,
    witness: Option<&Witness>,
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + mpz_common::Flush + Send + 'static,
{
    let mut prover = Prover::new(ProverConfig::default(), ot);
    let checks = build(&mut prover, Role::Prover, params, witness)?;
    // The prover must decode exactly the outputs the verifier decodes:
    // mpz stages a "prove" flush entry for these ranges on both sides.
    let mut futs = Vec::with_capacity(checks.len());
    for c in &checks {
        futs.push(prover.decode(c.value)?);
    }
    prover
        .execute_all(ctx)
        .await
        .map_err(|e| anyhow!("prover execute: {e}"))?;
    for f in futs {
        let _ = f.await.map_err(|e| anyhow!("prover decode: {e}"))?;
    }
    Ok(())
}

/// The verifier side of one proof over `ctx`; `delta` must be `ot`'s global
/// correlation. Fails unless every check holds.
pub(crate) async fn verify_with<OT>(
    ot: OT,
    delta: Delta,
    ctx: &mut Context,
    params: &Params,
) -> Result<Vec<CheckResult>>
where
    OT: RCOTSender<Block> + mpz_common::Flush + Send + 'static,
{
    let mut verifier = Verifier::new(VerifierConfig::default(), delta, ot);
    let checks = build(&mut verifier, Role::Verifier, params, None)?;
    let mut futs = Vec::with_capacity(checks.len());
    for c in &checks {
        futs.push(verifier.decode(c.value)?);
    }
    verifier
        .execute_all(ctx)
        .await
        .map_err(|e| anyhow!("verifier execute: {e}"))?;
    let mut got = Vec::with_capacity(futs.len());
    for f in futs {
        got.push(f.await.map_err(|e| anyhow!("verifier decode: {e}"))?);
    }
    let results = check_results(&checks, &got);
    if !all_ok(&results) {
        bail!("proof checks failed: {results:?}");
    }
    Ok(results)
}

/// Run prover and verifier against each other in one process with ideal OT,
/// each side on its own task (mirrors the two-process deployment). Returns the
/// verifier's check results.
pub async fn run_pair_ideal(params: &Params, witness: &Witness) -> Result<Vec<CheckResult>> {
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let (delta, seed_send, seed_recv) = {
        let mut rng = rand::rng();
        (
            Delta::random(&mut rng),
            Block::random(&mut rng),
            Block::random(&mut rng),
        )
    };
    let (ot_send, ot_recv) = mpz_ot::ideal::rcot::ideal_rcot(seed_send, delta.into_inner());

    let mut prover = Prover::new(ProverConfig::default(), ot_recv);
    let mut verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

    let (ep_p, ep_v) = tokio::io::duplex(1 << 22);
    let mut ctx_p = Context::new_single_threaded(ep_p.compat());
    let mut ctx_v = Context::new_single_threaded(ep_v.compat());

    let params_p = params.clone();
    let witness_p = witness.clone();
    let params_v = params.clone();

    let prover_task = tokio::spawn(async move {
        let checks = build(&mut prover, Role::Prover, &params_p, Some(&witness_p))?;
        let mut futs = Vec::with_capacity(checks.len());
        for c in &checks {
            futs.push(prover.decode(c.value)?);
        }
        prover
            .execute_all(&mut ctx_p)
            .await
            .map_err(|e| anyhow!("prover: {e}"))?;
        for f in futs {
            let _ = f.await.map_err(|e| anyhow!("prover decode: {e}"))?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let verifier_task = tokio::spawn(async move {
        let checks = build(&mut verifier, Role::Verifier, &params_v, None)?;
        let mut futs = Vec::with_capacity(checks.len());
        for c in &checks {
            futs.push(verifier.decode(c.value)?);
        }
        verifier
            .execute_all(&mut ctx_v)
            .await
            .map_err(|e| anyhow!("verifier: {e}"))?;
        let mut got = Vec::with_capacity(futs.len());
        for f in futs {
            got.push(f.await.map_err(|e| anyhow!("decode: {e}"))?);
        }
        let results = check_results(&checks, &got);
        Ok::<_, anyhow::Error>(results)
    });

    prover_task.await??;
    let results = verifier_task.await??;
    Ok(results)}

/// Analytic circuit statistics for the SPEC §11 table.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Stats {
    /// Number of SHA-256 compression calls (each 512-bit block).
    pub sha256_compressions: usize,
    /// Number of AES-128 block encryptions.
    pub aes_blocks: usize,
}

/// Count SHA-256 compressions and AES blocks a statement performs.
pub fn stats(params: &Params) -> Stats {
    // π_C2S/π_C3S: SHA256(secret) + keyed ipad/opad + key + iv = 1 + 2 + 2 + 2
    // = 7 compressions.
    let mut aes_blocks = 0usize;
    let sha256_compressions = match params {
        Params::PiC2S(p) => {
            aes_blocks += (p.off % 16 + p.w).div_ceil(16);
            7
        }
        Params::PiC3S(p) => {
            for r in &p.records {
                aes_blocks += r.ct.len().div_ceil(16);
            }
            7
        }
        Params::PiNK(p) => {
            // hk (28 bytes, one block) + SHA256(header || C_1).
            aes_blocks += (p.head_len + 1).div_ceil(16);
            1 + sha256_blocks(5 + p.head_len + 1)
        }
    };
    Stats {
        sha256_compressions,
        aes_blocks,
    }
}

/// SHA-256 compressions for a message of `len` bytes.
fn sha256_blocks(len: usize) -> usize {
    (len * 8 + 1 + 64).div_ceil(512)
}

/// Outcome of a prover‖verifier run over an emulated transport.
#[derive(Debug)]
pub struct PairOutcome {
    pub checks: Vec<CheckResult>,
    pub counters: Arc<Counters>,
    pub elapsed: Duration,
    pub ok: bool,
}

/// Run prover and verifier against each other over the emulated transport.
pub async fn run_pair_transport(
    delay: Duration,
    rate: f64,
    params: &Params,
    witness: &Witness,
) -> Result<PairOutcome> {
    let (ep_p, ep_v, counters) = crate::transport::emulated_pair(delay, rate);
    let params_p = params.clone();
    let witness_p = witness.clone();
    let params_v = params.clone();
    let start = Instant::now();
    let p = tokio::spawn(async move { run_io(ep_p, Role::Prover, &params_p, Some(&witness_p)).await });
    let v = tokio::spawn(async move { run_io(ep_v, Role::Verifier, &params_v, None).await });
    let pr = p.await?;
    let vr = v.await?;
    let elapsed = start.elapsed();
    pr?;
    let checks = vr?;
    let ok = checks.iter().all(|c| c.ok);
    Ok(PairOutcome {
        checks,
        counters,
        elapsed,
        ok,
    })
}


#[cfg(test)]
mod tests {
    use super::check_ok;

    #[test]
    fn full_check_is_exact_length() {
        // Exact-length: a value longer than expected must fail even when the
        // expected bytes are a prefix of the proven value (a prefix bug once found here).
        assert!(check_ok(b"ab", None, b"ab"));
        assert!(!check_ok(b"ab", None, b"abc"), "longer value must fail");
        assert!(!check_ok(b"ab", None, b"a"), "shorter value must fail");
        assert!(!check_ok(b"ab", None, b"ax"));
    }

    #[test]
    fn prefix_check_compares_only_the_prefix() {
        assert!(check_ok(b"abcd", Some(2), b"abXY"));
        assert!(!check_ok(b"abcd", Some(2), b"aX"));
        assert!(!check_ok(b"abcd", Some(2), b"a"));
        // A prefix longer than the expected value can never match.
        assert!(!check_ok(b"ab", Some(4), b"abcd"));
    }
}
