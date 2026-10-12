//! The v2 proof channel (`zkbench::channel`): correlations preprocessed while
//! armed, then π_NK, π_C2S and π_C3S on the same connection; online extension
//! when the preallocation is short; tampering still fails; channel loss.

use std::time::{Duration, Instant};

use zkbench::channel::{Party, Prealloc, ZkChannel, ot_demand_with};
use zkbench::fixtures;
use zkbench::proofs::run_pair_transport;
use zkbench::statements::{Params, Witness};
use zkbench::transport::{Endpoint, emulated_link};

struct Session {
    nk: (Params, Witness),
    c2s: (Params, Witness),
    c3s: (Params, Witness),
}

fn session() -> Session {
    Session { nk: fixtures::pi_nk(), c2s: fixtures::pi_c2s(), c3s: fixtures::pi_c3s() }
}

async fn open_pair(a: Endpoint, b: Endpoint, pre: Prealloc) -> (ZkChannel, ZkChannel) {
    let c = tokio::spawn(async move { ZkChannel::open(a, Party::Client, pre).await });
    let n = tokio::spawn(async move { ZkChannel::open(b, Party::Node, pre).await });
    (c.await.unwrap().expect("client open"), n.await.unwrap().expect("node open"))
}

/// Node: serve requests until the client closes, with the node's own params
/// (`tamper` replaces the expected suffix of π_C2S on the node side only).
fn spawn_node(node: ZkChannel, s: Session) -> tokio::task::JoinHandle<Vec<(String, bool)>> {
    spawn_node_notify(node, s, None)
}

/// As `spawn_node`, also sending the instant each proof finished on the node.
fn spawn_node_notify(
    mut node: ZkChannel,
    s: Session,
    notify: Option<tokio::sync::mpsc::UnboundedSender<Instant>>,
) -> tokio::task::JoinHandle<Vec<(String, bool)>> {
    tokio::spawn(async move {
        let mut out = Vec::new();
        loop {
            let req = match node.next_request().await {
                Ok(Some(r)) => r,
                Ok(None) | Err(_) => break,
            };
            let (params, witness) = match req.proof.as_str() {
                "pi_nk" => (s.nk.0.clone(), Some(s.nk.1.clone())),
                "pi_c2s" => (s.c2s.0.clone(), None),
                "pi_c3s" => (s.c3s.0.clone(), None),
                _ => break,
            };
            let r = node.serve(&req.proof, &params, witness.as_ref()).await;
            let ok = matches!(&r, Ok(c) if c.iter().all(|x| x.ok));
            if let Some(n) = &notify {
                let _ = n.send(Instant::now());
            }
            out.push((req.proof.clone(), ok));
            if r.is_err() {
                break;
            }
        }
        node.close().await;
        out
    })
}

async fn client_all(client: &mut ZkChannel, s: &Session) -> [anyhow::Result<()>; 3] {
    let a = client.request(&s.nk.0, None).await.map(|c| assert!(c.iter().all(|x| x.ok)));
    let b = client.request(&s.c2s.0, Some(&s.c2s.1)).await.map(|_| ());
    let c = client.request(&s.c3s.0, Some(&s.c3s.1)).await.map(|_| ());
    [a, b, c]
}

#[test]
fn demand_fits_default_prealloc() {
    let s = session();
    let nk = ot_demand_with(&s.nk.0, &s.nk.1).unwrap();
    let c2 = ot_demand_with(&s.c2s.0, &s.c2s.1).unwrap();
    let c3 = ot_demand_with(&s.c3s.0, &s.c3s.1).unwrap();
    eprintln!("ot demand: pi_nk={nk} pi_c2s={c2} pi_c3s={c3}");
    let d = Prealloc::default();
    assert!(nk <= d.nk, "pi_nk {nk} > {}", d.nk);
    assert!(c2 + c3 <= d.cp, "pi_c2s+pi_c3s {} > {}", c2 + c3, d.cp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preprocess_then_prove_all_three() {
    let (a, b, counters) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    let (mut client, node) = open_pair(a, b, Prealloc::default()).await;
    let after_setup = counters.total();
    // Armed: idle a little before the claim.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (nk_avail, cp_avail) = client.available();
    let node_task = spawn_node(node, session());
    let s = session();
    let t = Instant::now();
    let r = client_all(&mut client, &s).await;
    let claim = t.elapsed();
    for x in &r {
        assert!(x.is_ok(), "{r:?}");
    }
    let (nk_after, cp_after) = client.available();
    client.close().await;
    let served = node_task.await.unwrap();
    assert_eq!(
        served,
        vec![("pi_nk".into(), true), ("pi_c2s".into(), true), ("pi_c3s".into(), true)]
    );
    let claim_bytes = counters.total() - after_setup;
    eprintln!(
        "setup {after_setup} B; claim (3 proofs) {claim_bytes} B in {claim:?}; avail nk {nk_avail}->{nk_after} cp {cp_avail}->{cp_after}"
    );
    // No Ferret extension at claim time: the proofs only consume.
    assert!(nk_after < nk_avail && cp_after < cp_avail);
    assert!(claim_bytes < 200_000, "claim moved {claim_bytes} bytes: an extension ran online");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_preallocation_extends_online() {
    let (a, b, counters) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    // Far less than any proof needs: every chain must extend during the proofs.
    let pre = Prealloc { nk: 1000, cp: 1000 };
    let (mut client, node) = open_pair(a, b, pre).await;
    let after_setup = counters.total();
    let node_task = spawn_node(node, session());
    let s = session();
    let r = client_all(&mut client, &s).await;
    for x in &r {
        assert!(x.is_ok(), "{r:?}");
    }
    client.close().await;
    let served = node_task.await.unwrap();
    assert!(served.iter().all(|(_, ok)| *ok), "{served:?}");
    assert!(counters.total() - after_setup > 200_000, "expected an online extension");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_cannot_raise_the_preallocation() {
    let (a, b, _counters) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    // A client asking for the most correlations gets the node's (smaller) amount.
    let greedy = Prealloc { nk: 1 << 25, cp: 1 << 25 };
    let c = tokio::spawn(async move { ZkChannel::open(a, Party::Client, greedy).await });
    let n = tokio::spawn(async move { ZkChannel::open(b, Party::Node, Prealloc::default()).await });
    let (mut client, node) = (c.await.unwrap().expect("client open"), n.await.unwrap().expect("node open"));
    let (nk, cp) = node.available();
    assert_eq!(client.available(), (nk, cp));
    // Ferret's next sizes up are n = 1024k (nk) and 2048k (cp).
    assert!(nk < 1 << 20 && cp < 1 << 21, "node preallocated nk {nk} cp {cp}");
    // The proofs still run on the agreed chains.
    let node_task = spawn_node(node, session());
    let r = client_all(&mut client, &session()).await;
    assert!(r.iter().all(|x| x.is_ok()), "{r:?}");
    client.close().await;
    assert!(node_task.await.unwrap().iter().all(|(_, ok)| *ok));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_proof_fails_and_poisons() {
    let (a, b, _) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    let (mut client, node) = open_pair(a, b, Prealloc::default()).await;
    let node_task = spawn_node(node, session());
    let s = session();
    client.request(&s.nk.0, None).await.expect("pi_nk");
    // The client proves π_C2S from the wrong secret (s_ap_0 instead of c_ap_1).
    let wrong = fixtures::pi_c3s().1;
    let _ = client.request(&s.c2s.0, Some(&wrong)).await;
    // Whatever the client saw, the node rejected it and closed the channel.
    let served = tokio::time::timeout(Duration::from_secs(30), node_task).await.unwrap().unwrap();
    assert_eq!(served[0], ("pi_nk".into(), true));
    assert_eq!(served[1], ("pi_c2s".into(), false), "{served:?}");
    assert_eq!(served.len(), 2);
    // No further proof runs on this channel.
    let r = tokio::time::timeout(Duration::from_secs(30), client.request(&s.c3s.0, Some(&s.c3s.1))).await;
    assert!(matches!(r, Ok(Err(_))), "a proof ran after the failure");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_node_proof_fails_on_the_client() {
    let (a, b, _) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    let (mut client, node) = open_pair(a, b, Prealloc::default()).await;
    let mut s = session();
    // The node proves π_NK with another API key than the published C_1 holds.
    if let Witness::NodeKey { key, .. } = &mut s.nk.1 {
        key[0] ^= 1;
    }
    let node_task = spawn_node(node, s);
    let honest = session();
    let r = tokio::time::timeout(Duration::from_secs(30), client.request(&honest.nk.0, None)).await.unwrap();
    assert!(r.is_err(), "client accepted a wrong π_NK");
    assert!(client.is_poisoned());
    client.close().await;
    let _ = tokio::time::timeout(Duration::from_secs(30), node_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_loss_then_per_proof_fallback() {
    let (a, b, _) = emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    let (mut client, node) = open_pair(a, b, Prealloc::default()).await;
    // The connection dies while armed (the node side goes away).
    node.close().await;
    let s = session();
    let r = tokio::time::timeout(Duration::from_secs(30), client.request(&s.nk.0, None)).await.unwrap();
    assert!(r.is_err(), "a proof cannot run over a dead channel");
    assert!(client.is_poisoned());
    // Fallback: the per-proof path (fresh OT per proof) still works.
    for (p, w) in [s.nk, s.c2s, s.c3s] {
        let out = run_pair_transport(Duration::ZERO, f64::INFINITY, &p, &w).await.unwrap();
        assert!(out.ok);
    }
}

/// Emulated home uplink (25 ms one way; client→node 20 Mbit/s, node→client
/// 100 Mbit/s): per-proof cold path vs the pre-warmed channel. Run with
/// `--ignored --nocapture` for the numbers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn wan_cold_vs_warm() {
    // Override with ZK_DELAY_MS / ZK_UP_MBIT / ZK_DOWN_MBIT.
    let env = |k: &str, d: f64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let delay = Duration::from_secs_f64(env("ZK_DELAY_MS", 25.0) / 1e3);
    let (up, down) = (env("ZK_UP_MBIT", 20.0) * 1e6 / 8.0, env("ZK_DOWN_MBIT", 100.0) * 1e6 / 8.0);
    eprintln!("link: {:?} one way, up {} Mbit/s, down {} Mbit/s", delay, up * 8.0 / 1e6, down * 8.0 / 1e6);
    let s = session();
    // Cold: one fresh connection + full OT setup per proof. In π_NK the client
    // is the verifier, in π_C2S/π_C3S the prover; a = prover end.
    let mut cold = Vec::new();
    for (name, (p, w), client_proves) in [("pi_nk", s.nk.clone(), false), ("pi_c2s", s.c2s.clone(), true), ("pi_c3s", s.c3s.clone(), true)] {
        let (pr_rate, vr_rate) = if client_proves { (up, down) } else { (down, up) };
        let (ep_p, ep_v, counters) = emulated_link(delay, pr_rate, vr_rate);
        let t = Instant::now();
        let (p2, w2, p3) = (p.clone(), w.clone(), p.clone());
        let pt = tokio::spawn(async move { zkbench::run_io(ep_p, zkbench::Role::Prover, &p2, Some(&w2)).await });
        let vt = tokio::spawn(async move { zkbench::run_io(ep_v, zkbench::Role::Verifier, &p3, None).await });
        pt.await.unwrap().unwrap();
        vt.await.unwrap().unwrap();
        cold.push((name, t.elapsed(), counters.total()));
    }
    for (n, d, b) in &cold {
        eprintln!("cold {n}: {:>7.1} ms  {b} B", d.as_secs_f64() * 1e3);
    }
    // Warm: one channel, preprocessed (timed separately), then the 3 proofs.
    let (a, b, counters) = emulated_link(delay, up, down);
    let t = Instant::now();
    let (mut client, node) = open_pair(a, b, Prealloc::default()).await;
    eprintln!("warm setup (arm, off the request path): {:>7.1} ms  {} B", t.elapsed().as_secs_f64() * 1e3, counters.total());
    let (ntx, mut nrx) = tokio::sync::mpsc::unbounded_channel();
    let node_task = spawn_node_notify(node, session(), Some(ntx));
    let before = counters.total();
    let t = Instant::now();
    let mut each = Vec::new();
    for (p, w) in [(&s.nk.0, None), (&s.c2s.0, Some(&s.c2s.1)), (&s.c3s.0, Some(&s.c3s.1))] {
        let t1 = Instant::now();
        client.request(p, w).await.unwrap();
        let client_done = t1.elapsed();
        // The proof is done when both sides are: the node verifies π_C2S and
        // π_C3S (the client only sends), the client verifies π_NK.
        let node_done = nrx.recv().await.unwrap().duration_since(t1);
        each.push(client_done.max(node_done));
    }
    eprintln!(
        "warm proofs (both sides done): pi_nk {:.1} ms, pi_c2s {:.1} ms, pi_c3s {:.1} ms (total {:.1} ms, {} B)",
        each[0].as_secs_f64() * 1e3,
        each[1].as_secs_f64() * 1e3,
        each[2].as_secs_f64() * 1e3,
        t.elapsed().as_secs_f64() * 1e3,
        counters.total() - before
    );
    client.close().await;
    let served = node_task.await.unwrap();
    assert!(served.iter().all(|(_, ok)| *ok));
}

// --- cu-prover --channel (the client process) against an in-process node ---

fn frame(ch: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![ch];
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

async fn next_ctl(rx: &mut tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(60), rx.recv()).await.unwrap().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cu_prover_channel_mode() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let mut child = Command::new(env!("CARGO_BIN_EXE_cu-prover"))
        .arg("--channel")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // The node end: an in-memory duplex whose far side is relayed to and from
    // the child's channel 0 (what the WebSocket does in deployment).
    let (node_io, relay) = tokio::io::duplex(1 << 22);
    let (mut relay_r, mut relay_w) = tokio::io::split(relay);
    let node = tokio::spawn(async move { ZkChannel::open(node_io.compat(), Party::Node, Prealloc::default()).await });

    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    tokio::spawn(async move {
        loop {
            let mut hdr = [0u8; 5];
            if stdout.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
            let mut data = vec![0u8; len];
            if stdout.read_exact(&mut data).await.is_err() {
                break;
            }
            if hdr[0] == 0 {
                if relay_w.write_all(&data).await.is_err() {
                    break;
                }
            } else {
                let _ = ctl_tx.send(serde_json::from_slice(&data).unwrap());
            }
        }
        // The child's stdout closed: EOF to the node (as the WebSocket does).
        let _ = relay_w.shutdown().await;
    });
    let (to_child_tx, mut to_child_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let net_tx = to_child_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match relay_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if net_tx.send(frame(0, &buf[..n])).is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(f) = to_child_rx.recv().await {
            if stdin.write_all(&f).await.is_err() {
                break;
            }
            let _ = stdin.flush().await;
        }
    });

    let ready = next_ctl(&mut ctl_rx).await;
    assert_eq!(ready["ev"], "ready", "{ready}");
    let node = node.await.unwrap().unwrap();
    let node_task = spawn_node(node, session());

    let s = session();
    let cmds = [
        serde_json::json!({"cmd":"verify","id":1,"proof":"pi_nk","params":s.nk.0}),
        serde_json::json!({"cmd":"prove","id":2,"proof":"pi_c2s","params":s.c2s.0,"witness":s.c2s.1}),
        serde_json::json!({"cmd":"prove","id":3,"proof":"pi_c3s","params":s.c3s.0,"witness":s.c3s.1}),
    ];
    // A wrong command for the role is refused without touching the channel.
    to_child_tx
        .send(frame(1, serde_json::json!({"cmd":"prove","id":0,"proof":"pi_nk","params":s.nk.0}).to_string().as_bytes()))
        .unwrap();
    let r = next_ctl(&mut ctl_rx).await;
    assert_eq!((r["id"].as_i64(), r["ok"].as_bool()), (Some(0), Some(false)), "{r}");
    // So are params for another proof than the one named; the channel stays
    // usable for every proof afterwards.
    for bad in [
        serde_json::json!({"cmd":"verify","id":-1,"proof":"pi_nk","params":s.c2s.0}),
        serde_json::json!({"cmd":"prove","id":-2,"proof":"pi_c2s","params":s.c3s.0,"witness":s.c3s.1}),
    ] {
        to_child_tx.send(frame(1, bad.to_string().as_bytes())).unwrap();
        let r = next_ctl(&mut ctl_rx).await;
        assert_eq!((r["id"].clone(), r["ok"].as_bool()), (bad["id"].clone(), Some(false)), "{r}");
        assert!(r["err"].as_str().unwrap().contains("params are for"), "{r}");
    }
    for c in cmds {
        to_child_tx.send(frame(1, c.to_string().as_bytes())).unwrap();
        let r = next_ctl(&mut ctl_rx).await;
        assert_eq!(r["ev"], "done");
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["id"], c["id"]);
    }
    to_child_tx.send(frame(1, br#"{"cmd":"close"}"#)).unwrap();
    let served = tokio::time::timeout(Duration::from_secs(30), node_task).await.unwrap().unwrap();
    assert_eq!(
        served,
        vec![("pi_nk".into(), true), ("pi_c2s".into(), true), ("pi_c3s".into(), true)]
    );
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait()).await.unwrap().unwrap();
    assert!(status.success());
}
