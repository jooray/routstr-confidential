//! In-process transports for tests and benchmarks: a proxy with one-way
//! delay and a token-bucket rate limit (same model as
//! `zkbench::transport::emulated_pair`, copied to keep this crate independent).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

pub type Endpoint = Compat<tokio::io::DuplexStream>;

const CHUNK: usize = 64 * 1024;
const BUF: usize = 4 * 1024 * 1024;

/// Two endpoints connected through a proxy that delays each chunk by `delay`
/// plus its serialisation time at `rate` bytes/s (`f64::INFINITY` = no limit).
pub fn emulated_pair(delay: Duration, rate: f64) -> (Endpoint, Endpoint) {
    let (ep_a, a_proxy) = tokio::io::duplex(BUF);
    let (ep_b, b_proxy) = tokio::io::duplex(BUF);
    let (a_rx, a_tx) = tokio::io::split(a_proxy);
    let (b_rx, b_tx) = tokio::io::split(b_proxy);
    tokio::spawn(pipe(a_rx, b_tx, delay, rate));
    tokio::spawn(pipe(b_rx, a_tx, delay, rate));
    (ep_a.compat(), ep_b.compat())
}

/// Delay is modelled as latency (pipelined), bandwidth as a serial link.
async fn pipe(
    mut rx: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut tx: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    delay: Duration,
    rate: f64,
) {
    let (qtx, mut qrx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        while let Some((due, data)) = qrx.recv().await {
            tokio::time::sleep_until(due).await;
            if tx.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = tx.shutdown().await;
    });
    let mut buf = vec![0u8; CHUNK];
    // Time at which the link becomes free (serialisation).
    let mut link_free = tokio::time::Instant::now();
    loop {
        let n = match rx.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let now = tokio::time::Instant::now();
        let start = if link_free > now { link_free } else { now };
        let ser = if rate.is_finite() {
            Duration::from_secs_f64(n as f64 / rate)
        } else {
            Duration::ZERO
        };
        link_free = start + ser;
        if !rate.is_finite() && delay.is_zero() {
            if qtx.send((now, buf[..n].to_vec())).is_err() {
                break;
            }
        } else if qtx.send((link_free + delay, buf[..n].to_vec())).is_err() {
            break;
        }
        if rate.is_finite() {
            // Backpressure: do not run ahead of the link by more than ~1 s.
            let ahead = link_free.saturating_duration_since(tokio::time::Instant::now());
            if ahead > Duration::from_secs(1) {
                tokio::time::sleep(ahead - Duration::from_secs(1)).await;
            }
        }
    }
    drop(qtx);
    let _ = writer.await;
}
