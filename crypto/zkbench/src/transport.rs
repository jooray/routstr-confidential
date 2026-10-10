//! Locally and WAN emulated transports for the benchmarks and tests.
//!
//! A tiny in-process proxy sits between the two endpoints, so the exact same
//! proxy is used for the `local` (no delay) and `wan` (one-way delay + token
//! bucket) cases, and it counts bytes in each direction.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Bytes transferred in each direction, shared with the proxy task.
#[derive(Debug, Default)]
pub struct Counters {
    pub prover_to_verifier: AtomicU64,
    pub verifier_to_prover: AtomicU64,
}

impl Counters {
    pub fn p2v(&self) -> u64 {
        self.prover_to_verifier.load(Ordering::Relaxed)
    }
    pub fn v2p(&self) -> u64 {
        self.verifier_to_prover.load(Ordering::Relaxed)
    }
    pub fn total(&self) -> u64 {
        self.p2v() + self.v2p()
    }
}

/// A futures `AsyncRead + AsyncWrite` endpoint suitable for `run_io`.
pub type Endpoint = Compat<tokio::io::DuplexStream>;

const CHUNK: usize = 64 * 1024;
const BUF: usize = 4 * 1024 * 1024;

/// Spawn a proxy emulating one-way `delay` and a token bucket of `rate`
/// bytes/second (use `f64::INFINITY` for unlimited). Returns the two endpoints.
pub fn emulated_pair(delay: Duration, rate: f64) -> (Endpoint, Endpoint, Arc<Counters>) {
    let (ep_p, p_proxy) = tokio::io::duplex(BUF);
    let (ep_v, v_proxy) = tokio::io::duplex(BUF);
    let (mut p_rx, p_tx) = tokio::io::split(p_proxy);
    let (mut v_rx, v_tx) = tokio::io::split(v_proxy);
    let counters = Arc::new(Counters::default());
    let c1 = counters.clone();
    let c2 = counters.clone();

    // p -> v
    tokio::spawn(async move {
        let mut dst = v_tx;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match p_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            throttle(delay, rate, n).await;
            if dst.write_all(&buf[..n]).await.is_err() {
                break;
            }
            c1.prover_to_verifier.fetch_add(n as u64, Ordering::Relaxed);
        }
    });

    // v -> p
    tokio::spawn(async move {
        let mut dst = p_tx;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match v_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            throttle(delay, rate, n).await;
            if dst.write_all(&buf[..n]).await.is_err() {
                break;
            }
            c2.verifier_to_prover.fetch_add(n as u64, Ordering::Relaxed);
        }
    });

    (ep_p.compat(), ep_v.compat(), counters)
}

async fn throttle(delay: Duration, rate: f64, n: usize) {
    let mut total = delay;
    if rate.is_finite() {
        total += Duration::from_secs_f64(n as f64 / rate);
    }
    if !total.is_zero() {
        tokio::time::sleep(total).await;
    }
}

/// A more faithful link model than [`emulated_pair`]: each direction is a
/// pipe with one-way latency `delay` and its own bandwidth (bytes/second;
/// `f64::INFINITY` for unlimited). Chunks are serialised at the link rate and
/// delivered `delay` later, so latency and bandwidth overlap like on a real
/// path (`emulated_pair` sleeps `delay` per chunk, which caps throughput at
/// one chunk per `delay`). `a_to_b` counts into `prover_to_verifier`.
pub fn emulated_link(delay: Duration, rate_a_to_b: f64, rate_b_to_a: f64) -> (Endpoint, Endpoint, Arc<Counters>) {
    let (ep_a, a_proxy) = tokio::io::duplex(BUF);
    let (ep_b, b_proxy) = tokio::io::duplex(BUF);
    let (a_rx, a_tx) = tokio::io::split(a_proxy);
    let (b_rx, b_tx) = tokio::io::split(b_proxy);
    let counters = Arc::new(Counters::default());
    spawn_pipe(a_rx, b_tx, delay, rate_a_to_b, counters.clone(), true);
    spawn_pipe(b_rx, a_tx, delay, rate_b_to_a, counters.clone(), false);
    (ep_a.compat(), ep_b.compat(), counters)
}

fn spawn_pipe(
    mut rx: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut tx: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    delay: Duration,
    rate: f64,
    counters: Arc<Counters>,
    a_to_b: bool,
) {
    let (q_tx, mut q_rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut busy_until = tokio::time::Instant::now();
        loop {
            let n = match rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let now = tokio::time::Instant::now();
            let start = busy_until.max(now);
            let ser = if rate.is_finite() { Duration::from_secs_f64(n as f64 / rate) } else { Duration::ZERO };
            busy_until = start + ser;
            if q_tx.send((busy_until + delay, buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, data)) = q_rx.recv().await {
            tokio::time::sleep_until(at).await;
            if tx.write_all(&data).await.is_err() {
                break;
            }
            let c = if a_to_b { &counters.prover_to_verifier } else { &counters.verifier_to_prover };
            c.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        let _ = tx.shutdown().await;
    });
}
