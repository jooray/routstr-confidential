//! A tiny channel multiplexer over one duplex byte stream.
//!
//! A copy of `twopc::mux`. The v2 proof channel ([`crate::channel`]) carries
//! three independent conversations (control, the π_NK correlation chain, the
//! client-prover correlation chain) over one connection (a WebSocket on the
//! node side, stdin/stdout on the client side). Frames are
//! `[1 byte channel][4 bytes BE length][payload]`. Each channel is exposed as
//! a local in-memory duplex stream.
//!
//! Byte counters cover everything written to / read from the real transport,
//! frame headers included.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Maximum payload of one mux frame.
const MAX_MUX_FRAME: usize = 1 << 20;
/// Per-channel in-memory buffer. Tokio grows it lazily, so a large cap costs
/// nothing unless it is used; it must be large enough that a garbled table
/// which the peer has not started reading yet never blocks other channels.
const CHAN_BUF: usize = 64 << 20;
const PUMP_CHUNK: usize = 64 * 1024;

/// Bytes on the real transport.
#[derive(Debug, Default)]
pub struct Counters {
    pub sent: AtomicU64,
    pub recv: AtomicU64,
}

impl Counters {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn recv(&self) -> u64 {
        self.recv.load(Ordering::Relaxed)
    }
}

pub struct Mux {
    pub counters: Arc<Counters>,
    writer: Option<JoinHandle<()>>,
    reader: JoinHandle<()>,
    pumps: Vec<JoinHandle<()>>,
}

impl Mux {
    /// Starts the mux tasks (requires a tokio runtime) and returns the local
    /// end of each of the `n` channels.
    ///
    /// `inbound_caps[ch]` bounds the payload bytes the peer may send on channel
    /// `ch` over the mux's lifetime; a frame past it is a protocol violation and
    /// tears the mux down (otherwise a peer could fill a channel nobody is
    /// reading, `CHAN_BUF` per channel, and hold that memory for the session).
    pub fn start<IO>(io: IO, n: usize, inbound_caps: &[u64]) -> (Mux, Vec<DuplexStream>)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        assert_eq!(inbound_caps.len(), n, "one inbound cap per channel");
        let inbound_caps = inbound_caps.to_vec();
        let mut ch_recv = vec![0u64; n];
        let counters = Arc::new(Counters::default());
        let (mut rd, mut wr) = io.split();
        let (tx, mut rx) = mpsc::channel::<(u8, Vec<u8>)>(256);

        let mut locals = Vec::with_capacity(n);
        let mut remotes_w = Vec::with_capacity(n);
        let mut pumps = Vec::with_capacity(n);
        for ch in 0..n {
            let (local, remote) = tokio::io::duplex(CHAN_BUF);
            let (mut rr, rw) = tokio::io::split(remote);
            remotes_w.push(rw);
            locals.push(local);
            let tx = tx.clone();
            pumps.push(tokio::spawn(async move {
                let mut buf = vec![0u8; PUMP_CHUNK];
                loop {
                    match rr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => {
                            if tx.send((ch as u8, buf[..k].to_vec())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }));
        }
        drop(tx);

        let c_w = counters.clone();
        let writer = tokio::spawn(async move {
            while let Some((ch, data)) = rx.recv().await {
                let mut hdr = [0u8; 5];
                hdr[0] = ch;
                hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
                if wr.write_all(&hdr).await.is_err() || wr.write_all(&data).await.is_err() {
                    break;
                }
                c_w.sent.fetch_add(5 + data.len() as u64, Ordering::Relaxed);
                // Coalesce: only flush when nothing else is queued.
                if rx.is_empty() && wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.flush().await;
            let _ = wr.close().await;
        });

        let c_r = counters.clone();
        let reader = tokio::spawn(async move {
            let mut remotes_w = remotes_w;
            loop {
                let mut hdr = [0u8; 5];
                if rd.read_exact(&mut hdr).await.is_err() {
                    break;
                }
                let ch = hdr[0] as usize;
                let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
                if ch >= remotes_w.len() || len > MAX_MUX_FRAME {
                    break; // protocol violation: tear everything down
                }
                if ch_recv[ch] + len as u64 > inbound_caps[ch] {
                    break; // more than an honest peer sends on this channel
                }
                ch_recv[ch] += len as u64;
                let mut data = vec![0u8; len];
                if rd.read_exact(&mut data).await.is_err() {
                    break;
                }
                c_r.recv.fetch_add(5 + len as u64, Ordering::Relaxed);
                if remotes_w[ch].write_all(&data).await.is_err() {
                    // Local side dropped; ignore data for it.
                    continue;
                }
            }
            // Dropping the write halves signals EOF to every channel.
            for w in remotes_w.iter_mut() {
                let _ = w.shutdown().await;
            }
        });

        (
            Mux {
                counters,
                writer: Some(writer),
                reader,
                pumps,
            },
            locals,
        )
    }

    /// Waits until everything written to the channels so far has been handed
    /// to the transport. The channel ends must have been dropped first.
    pub async fn close(mut self) {
        for p in self.pumps.drain(..) {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), p).await;
        }
        if let Some(w) = self.writer.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), w).await;
        }
        self.reader.abort();
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

