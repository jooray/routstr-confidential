//! Bridge an axum WebSocket into a futures `AsyncRead + AsyncWrite` duplex, so
//! the mpz VOLE protocol can run over `/zk` unchanged.

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

pub const BRIDGE_BUF: usize = 4 * 1024 * 1024;

/// The outbound (duplex → WebSocket) pump. `finish` waits for it to drain the
/// final bytes into the socket; without that, returning from the proof handler
/// drops the socket and can lose the last protocol message, stalling the peer.
pub struct WsBridge {
    out: tokio::task::JoinHandle<()>,
}

impl WsBridge {
    pub async fn finish(self) {
        // The peer may be gone; never block a teardown forever.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.out).await;
    }
}

/// Returns a duplex endpoint carrying raw bytes to/from the WebSocket, plus a
/// bridge handle whose `finish` must be awaited after the endpoint is dropped.
pub fn ws_duplex(ws: WebSocket) -> (Compat<tokio::io::DuplexStream>, WsBridge) {
    let (a, b) = tokio::io::duplex(BRIDGE_BUF);
    let (mut br, mut bw) = tokio::io::split(b);
    let (mut ws_tx, mut ws_rx) = ws.split();

    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) => {
                    if bw.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        // Signal EOF to the protocol side: dropping this half alone does not
        // (the read half lives on in the outbound pump), and a long-lived
        // reader (the proof channel waiting for its next request) would
        // otherwise wait for the session time limit.
        let _ = bw.shutdown().await;
    });

    let out = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    (a.compat(), WsBridge { out })
}
