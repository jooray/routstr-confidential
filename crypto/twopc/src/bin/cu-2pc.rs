//! `cu-2pc`: the C side of the two-party TLS key schedule, spawned by the
//! TypeScript client.
//!
//! stdin/stdout carry frames `[1 byte channel][4 bytes BE length][payload]`.
//! Channel 0 = network bytes to/from the peer (the client relays them to the
//! node's WebSocket); channel 1 = control JSON, one object per frame.
//!
//! ```text
//! out {"ev":"timing","step":..,"ms":..,"bytes_sent":..,"bytes_recv":..}   (every step)
//! out {"ev":"key_share","p":"<hex65>"}                       after preprocess + key_share
//! in  {"cmd":"handshake","s":"<hex65>","th_sh":"<hex32>"}  → out {"ev":"hs","c_hs":..,"s_hs":..}
//! in  {"cmd":"app","th_sf":"<hex32>"}                      → out {"ev":"ap","s_ap_0":..,"c_ap_1":..,"h1":..,"h2":..,"hk":..}
//! out {"ev":"error","msg":..} and exit 1 on any failure
//! ```
//!
//! Secrets are only ever written to the control channel (stdout), never to
//! stderr.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::compat::TokioAsyncReadCompatExt;
use twopc::{ApOut, Party, Role};

const MAX_FRAME: usize = 16 << 20;

type Out = mpsc::UnboundedSender<(u8, Vec<u8>)>;

fn emit(out: &Out, v: Value) {
    let _ = out.send((1, serde_json::to_vec(&v).expect("json")));
}

fn emit_timings(out: &Out, p: &mut Party) {
    for t in p.take_timings() {
        emit(
            out,
            json!({"ev":"timing","step":t.step,"ms":(t.ms * 1000.0).round() / 1000.0,
                   "bytes_sent":t.bytes_sent,"bytes_recv":t.bytes_recv}),
        );
    }
}

fn hex_arr<const N: usize>(v: &Value, k: &str) -> Result<[u8; N], String> {
    let s = v
        .get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing field {k}"))?;
    let b = hex::decode(s).map_err(|_| format!("field {k}: bad hex"))?;
    b.try_into().map_err(|_| format!("field {k}: expected {N} bytes"))
}

async fn next_cmd(ctl: &mut mpsc::UnboundedReceiver<Value>, want: &str) -> Result<Value, String> {
    let v = ctl.recv().await.ok_or("control channel closed")?;
    match v.get("cmd").and_then(|c| c.as_str()) {
        Some(c) if c == want => Ok(v),
        Some(c) => Err(format!("unexpected command {c:?}, expected {want:?}")),
        None => Err("control message without cmd".into()),
    }
}

async fn run(out: Out, mut ctl: mpsc::UnboundedReceiver<Value>, io: tokio::io::DuplexStream) -> Result<(), String> {
    let mut p = Party::new(Role::C, io.compat()).await.map_err(|e| e.to_string())?;
    p.preprocess().await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    let joint = p.key_share().await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    emit(&out, json!({"ev":"key_share","p":hex::encode(joint)}));

    let cmd = next_cmd(&mut ctl, "handshake").await?;
    let s: [u8; 65] = hex_arr(&cmd, "s")?;
    let th_sh: [u8; 32] = hex_arr(&cmd, "th_sh")?;
    let hs = p.handshake(&s, th_sh).await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    emit(
        &out,
        json!({"ev":"hs","c_hs":hex::encode(hs.c_hs),"s_hs":hex::encode(hs.s_hs)}),
    );

    let cmd = next_cmd(&mut ctl, "app").await?;
    let th_sf: [u8; 32] = hex_arr(&cmd, "th_sf")?;
    let ap = p.application(th_sf).await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    match &ap {
        ApOut::C {
            s_ap_0,
            c_ap_1,
            h1,
            h2,
            hk,
        } => emit(
            &out,
            json!({"ev":"ap","s_ap_0":hex::encode(s_ap_0),"c_ap_1":hex::encode(c_ap_1),
                   "h1":hex::encode(h1),"h2":hex::encode(h2),"hk":hex::encode(hk)}),
        ),
        ApOut::N { .. } => return Err("unexpected output role".into()),
    }
    p.close().await;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u8, Vec<u8>)>();
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<Value>();
    let (party_io, bridge) = tokio::io::duplex(4 << 20);
    let (mut br, mut bw) = tokio::io::split(bridge);

    // stdout writer
    let writer = tokio::spawn(async move {
        let mut so = tokio::io::stdout();
        while let Some((ch, data)) = out_rx.recv().await {
            let mut hdr = [0u8; 5];
            hdr[0] = ch;
            hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
            if so.write_all(&hdr).await.is_err() || so.write_all(&data).await.is_err() {
                break;
            }
            if out_rx.is_empty() && so.flush().await.is_err() {
                break;
            }
        }
        let _ = so.flush().await;
    });

    // network: party → stdout channel 0
    let net_out = out_tx.clone();
    let pump = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if net_out.send((0, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // stdin reader: channel 0 → party, channel 1 → control
    // Weak, so that a still-open stdin does not keep the stdout writer alive.
    let err_out = out_tx.downgrade();
    tokio::spawn(async move {
        let mut si = tokio::io::stdin();
        loop {
            let mut hdr = [0u8; 5];
            if si.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
            if len > MAX_FRAME {
                if let Some(o) = err_out.upgrade() {
                    emit(&o, json!({"ev":"error","msg":"stdin frame too large"}));
                }
                break;
            }
            let mut data = vec![0u8; len];
            if si.read_exact(&mut data).await.is_err() {
                break;
            }
            match hdr[0] {
                0 => {
                    if bw.write_all(&data).await.is_err() {
                        break;
                    }
                }
                1 => match serde_json::from_slice::<Value>(&data) {
                    Ok(v) => {
                        let _ = ctl_tx.send(v);
                    }
                    Err(_) => {
                        if let Some(o) = err_out.upgrade() {
                            emit(&o, json!({"ev":"error","msg":"bad control JSON"}));
                        }
                    }
                },
                _ => {}
            }
        }
        // EOF on stdin: close the network input too.
        let _ = bw.shutdown().await;
    });

    let res = run(out_tx.clone(), ctl_rx, party_io).await;
    let code = match res {
        Ok(()) => 0,
        Err(msg) => {
            emit(&out_tx, json!({"ev":"error","msg":msg}));
            1
        }
    };
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
    std::process::exit(code);
}
