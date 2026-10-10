//! A tiny channel multiplexer over one duplex byte stream.
//!
//! The 2PC needs several independent, full-duplex conversations at once (OT
//! extension in each direction, share conversion, both garbled-circuit runs
//! and the control channel), but the transport is a single connection (a
//! WebSocket on the node side, stdin/stdout on the client side). Frames are
//! `[1 byte channel][4 bytes BE length][payload]`. Each channel is exposed as
//! a local in-memory duplex stream.
//!
//! Byte counters cover everything written to / read from the real transport,
//! frame headers included.
//!
//! Channels can be marked *bulk* (the garbled tables): their frames are sent
//! only when no frame of a normal channel is waiting, and at most a few
//! chunks of bulk data are queued inside the mux. Without this, the interactive
//! OT extension rounds that run during preprocessing would wait behind
//! megabytes of queued tables on every round trip.

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
/// Bulk chunks queued inside the mux (the rest waits in the channel buffer).
const BULK_QUEUE: usize = 2;

/// Bytes on the real transport.
#[derive(Debug, Default)]
pub struct Counters {
    pub sent: AtomicU64,
    pub recv: AtomicU64,
    /// Payload bytes received per channel.
    pub(crate) ch_recv: Vec<AtomicU64>,
}

impl Counters {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn recv(&self) -> u64 {
        self.recv.load(Ordering::Relaxed)
    }
    pub(crate) fn ch_recv(&self, ch: usize) -> u64 {
        self.ch_recv.get(ch).map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

pub(crate) struct Mux {
    pub counters: Arc<Counters>,
    writer: Option<JoinHandle<()>>,
    reader: JoinHandle<()>,
    pumps: Vec<JoinHandle<()>>,
}

impl Mux {
    /// Starts the mux tasks (requires a tokio runtime) and returns the local
    /// end of each of the `n` channels.
    pub fn start<IO>(io: IO, n: usize, bulk: &[usize]) -> (Mux, Vec<DuplexStream>)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let counters = Arc::new(Counters {
            ch_recv: (0..n).map(|_| AtomicU64::new(0)).collect(),
            ..Counters::default()
        });
        let (mut rd, mut wr) = io.split();
        let (tx, mut rx) = mpsc::channel::<(u8, Vec<u8>)>(256);
        let (tx_bulk, mut rx_bulk) = mpsc::channel::<(u8, Vec<u8>)>(BULK_QUEUE);

        let mut locals = Vec::with_capacity(n);
        let mut remotes_w = Vec::with_capacity(n);
        let mut pumps = Vec::with_capacity(n);
        for ch in 0..n {
            let (local, remote) = tokio::io::duplex(CHAN_BUF);
            let (mut rr, rw) = tokio::io::split(remote);
            remotes_w.push(rw);
            locals.push(local);
            let tx = if bulk.contains(&ch) { tx_bulk.clone() } else { tx.clone() };
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
        drop(tx_bulk);

        let c_w = counters.clone();
        let writer = tokio::spawn(async move {
            let (mut hi_open, mut lo_open) = (true, true);
            loop {
                // Normal frames first; bulk only when none is waiting.
                let next = tokio::select! {
                    biased;
                    m = rx.recv(), if hi_open => match m {
                        Some(m) => Some(m),
                        None => { hi_open = false; None }
                    },
                    m = rx_bulk.recv(), if lo_open => match m {
                        Some(m) => Some(m),
                        None => { lo_open = false; None }
                    },
                    else => break,
                };
                let Some((ch, data)) = next else { continue };
                let mut hdr = [0u8; 5];
                hdr[0] = ch;
                hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
                if wr.write_all(&hdr).await.is_err() || wr.write_all(&data).await.is_err() {
                    break;
                }
                c_w.sent.fetch_add(5 + data.len() as u64, Ordering::Relaxed);
                // Coalesce: only flush when nothing else is queued.
                if rx.is_empty() && rx_bulk.is_empty() && wr.flush().await.is_err() {
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
                let mut data = vec![0u8; len];
                if rd.read_exact(&mut data).await.is_err() {
                    break;
                }
                c_r.recv.fetch_add(5 + len as u64, Ordering::Relaxed);
                c_r.ch_recv[ch].fetch_add(len as u64, Ordering::Relaxed);
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

/// Length-prefixed message framing on top of a mux channel.
pub(crate) struct FrameChan {
    io: DuplexStream,
}

/// Largest single protocol message (a garbled table is ~11 MB).
pub(crate) const MAX_MSG: usize = 64 << 20;

impl FrameChan {
    pub fn new(io: DuplexStream) -> Self {
        Self { io }
    }

    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.io.write_all(&(data.len() as u32).to_be_bytes()).await?;
        self.io.write_all(data).await?;
        self.io.flush().await
    }

    pub async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.io.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_MSG {
            return Err(std::io::Error::other("message too large"));
        }
        let mut buf = vec![0u8; len];
        self.io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Receives a message of exactly `n` bytes.
    pub async fn recv_exact(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let m = self.recv().await?;
        if m.len() != n {
            return Err(std::io::Error::other(format!(
                "unexpected message length {} (expected {n})",
                m.len()
            )));
        }
        Ok(m)
    }
}
