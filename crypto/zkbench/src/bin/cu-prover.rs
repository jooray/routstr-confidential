//! `cu-prover` — the client-side VOLE-ZK process.
//!
//! Two modes:
//!
//! * **stdio** (used by the e2e driver): the mpz framed protocol is carried as
//!   raw bytes on stdin/stdout; the proof type, role, public params and
//!   (optionally) the private witness are read either from stdin itself
//!   (`--job-stdin`: a 4-byte big-endian length and the JSON job, before the
//!   mpz bytes, so the witness never touches the disk) or from a JSON file
//!   (`--proof-file`).
//! * **channel** (`--channel`, protocol v2): one long-lived process per
//!   session holding the session's proof channel (`zkbench::channel`). stdin
//!   and stdout carry frames `[1 byte channel][4 bytes BE length][payload]`:
//!   channel 0 = network bytes to/from the node's `/zk?proof=zkchan`
//!   WebSocket, channel 1 = control JSON, one object per frame:
//!
//!   ```text
//!   out {"ev":"ready","timings":[..],"avail":[nk,cp]}      after preprocessing
//!   in  {"cmd":"verify"|"prove","id":n,"proof":"pi_nk"|"pi_c2s"|"pi_c3s",
//!        "params":{..},"witness":{..}}                        (witness: prove only)
//!   out {"ev":"done","id":n,"proof":..,"ok":true,"checks":[{"label","ok"}],
//!        "ms":..,"bytes_sent":..,"bytes_recv":..}
//!   out {"ev":"done","id":n,"proof":..,"ok":false,"err":".."} (channel closed)
//!   in  {"cmd":"close"}                                      → flush, exit 0
//!   out {"ev":"error","msg":..} and exit 1 on a channel failure
//!   ```
//!
//!   Witnesses arrive on stdin only and are never written anywhere.
//! * **bench**: runs every statement over the `local` and `wan` (25 ms
//!   one-way = 50 ms RTT, 100 Mbit/s) transports.
//!
//! stdout carries *only* mpz bytes in stdio mode; all logging goes to stderr.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use zkbench::proofs::{PairOutcome, run_io, run_pair_transport, stats};
use zkbench::statements::{Params, Proof, Witness};
use zkbench::{Role, fixtures};

#[derive(Debug, Serialize, Deserialize)]
struct ProofFile {
    proof: String,
    params: Params,
    #[serde(default)]
    witness: Option<Witness>,
}

/// The outbound (duplex → stdout) forwarder, kept so `run_stdio` can wait for
/// it to drain before the process exits.
struct StdioBridge {
    out: tokio::task::JoinHandle<()>,
}

impl StdioBridge {
    /// Drain stdout. The caller must drop the duplex endpoint (which `run_io`
    /// does when it returns) first, so the forwarder reaches EOF and writes the
    /// protocol's final bytes to the OS pipe. Exiting before this loses those
    /// bytes and stalls the peer's verifier until its timeout.
    async fn finish(self) {
        let _ = self.out.await;
    }
}

fn stdio_duplex(mut stdin: tokio::io::Stdin) -> (Compat<tokio::io::DuplexStream>, StdioBridge) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let out = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stdout.flush().await;
                }
            }
        }
    });
    (a.compat(), StdioBridge { out })
}

fn parse_role(s: &str) -> Result<Role> {
    match s {
        "prover" => Ok(Role::Prover),
        "verifier" => Ok(Role::Verifier),
        other => anyhow::bail!("unknown role {other}"),
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

async fn run_stdio(args: &[String]) -> Result<()> {
    let role = parse_role(&arg_value(args, "--role").unwrap_or_else(|| "prover".into()))?;
    let mut stdin = tokio::io::stdin();
    let pf: ProofFile = if args.iter().any(|a| a == "--job-stdin") {
        let mut len = [0u8; 4];
        stdin.read_exact(&mut len).await.context("reading the job length")?;
        let len = u32::from_be_bytes(len) as usize;
        if len > 16 << 20 {
            anyhow::bail!("job of {len} bytes is too large");
        }
        let mut job = vec![0u8; len];
        stdin.read_exact(&mut job).await.context("reading the job")?;
        serde_json::from_slice(&job).context("parsing the job")?
    } else {
        let path = arg_value(args, "--proof-file").context("--job-stdin or --proof-file is required")?;
        serde_json::from_str(&std::fs::read_to_string(&path)?)
            .with_context(|| format!("parsing {path}"))?
    };
    // The job names its proof; the params must be that proof's, or the
    // process would run (and report under the name) a different statement.
    if Proof::from_name(&pf.proof) != Some(pf.params.proof()) {
        anyhow::bail!("the job is for {}, its params are for {}", pf.proof, pf.params.proof().name());
    }
    eprintln!(
        "cu-prover: proof={} role={:?} params_ok=true",
        pf.proof, role
    );
    let (io, bridge) = stdio_duplex(stdin);
    // `run_io` consumes and drops its endpoint, so once it returns the stdout
    // forwarder can reach EOF. Wait for it before this process exits, or the
    // protocol's final bytes are lost and the peer stalls.
    let result = run_io(io, role, &pf.params, pf.witness.as_ref()).await;
    bridge.finish().await;
    eprintln!("cu-prover: proof={} role={:?} drained", pf.proof, role);
    let results = result?;
    if role == Role::Verifier {
        let all = results.iter().all(|r| r.ok);
        eprintln!("cu-prover: verifier checks: {results:?}");
        if !all {
            anyhow::bail!("verifier checks failed");
        }
    }
    Ok(())
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1_000_000 {
        format!("{:.2} MB", b as f64 / 1e6)
    } else if b >= 1000 {
        format!("{:.1} kB", b as f64 / 1e3)
    } else {
        format!("{b} B")
    }
}

#[derive(Serialize)]
struct BenchRow {
    proof: String,
    transport: String,
    wall_ms: f64,
    p2v_bytes: u64,
    v2p_bytes: u64,
    sha256_compressions: usize,
    aes_blocks: usize,
    ok: bool,
}

async fn bench_one(name: &str, params: &Params, witness: &Witness, wan: bool) -> Result<BenchRow> {
    let (delay, rate, label) = if wan {
        (Duration::from_millis(25), 12.5e6, "wan")
    } else {
        (Duration::ZERO, f64::INFINITY, "local")
    };
    let PairOutcome {
        counters,
        elapsed,
        ok,
        ..
    } = run_pair_transport(delay, rate, params, witness).await?;
    let st = stats(params);
    Ok(BenchRow {
        proof: name.to_string(),
        transport: label.to_string(),
        wall_ms: elapsed.as_secs_f64() * 1e3,
        p2v_bytes: counters.p2v(),
        v2p_bytes: counters.v2p(),
        sha256_compressions: st.sha256_compressions,
        aes_blocks: st.aes_blocks,
        ok,
    })
}

async fn run_bench(args: &[String]) -> Result<()> {
    let out_path = arg_value(args, "--json").unwrap_or_else(|| "bench.json".into());
    let mut rows = Vec::new();
    for (name, params, witness) in fixtures::all() {
        for wan in [false, true] {
            eprintln!("bench: {name} {}", if wan { "wan" } else { "local" });
            let row = bench_one(name, &params, &witness, wan).await?;
            eprintln!(
                "  {:>9.1} ms  p2v={} v2p={}  ok={}",
                row.wall_ms,
                fmt_bytes(row.p2v_bytes),
                fmt_bytes(row.v2p_bytes),
                row.ok
            );
            rows.push(row);
        }
    }

    println!();
    println!(
        "| statement | transport | wall ms | prover->verifier | verifier->prover | SHA-256 compr. | AES blocks |"
    );
    println!("|---|---|---|---|---|---|---|");
    for r in &rows {
        println!(
            "| {} | {} | {:.1} | {} | {} | {} | {} |",
            r.proof,
            r.transport,
            r.wall_ms,
            fmt_bytes(r.p2v_bytes),
            fmt_bytes(r.v2p_bytes),
            r.sha256_compressions,
            r.aes_blocks
        );
    }
    std::fs::write(&out_path, serde_json::to_string_pretty(&rows)?)?;
    eprintln!("wrote {out_path}");
    Ok(())
}

// ---------------------------------------------------------------------------
// --channel
// ---------------------------------------------------------------------------

const MAX_FRAME: usize = 16 << 20;

type Out = tokio::sync::mpsc::UnboundedSender<(u8, Vec<u8>)>;

fn emit(out: &Out, v: serde_json::Value) {
    let _ = out.send((1, serde_json::to_vec(&v).expect("json")));
}

fn emit_timings(_out: &Out, ch: &mut zkbench::channel::ZkChannel) -> serde_json::Value {
    serde_json::to_value(ch.take_timings()).unwrap_or_default()
}

async fn channel_loop(
    out: Out,
    mut ctl: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    io: tokio::io::DuplexStream,
    prealloc: zkbench::channel::Prealloc,
) -> Result<()> {
    use serde_json::json;
    use zkbench::channel::{Party, ZkChannel};
    let mut ch = ZkChannel::open(io.compat(), Party::Client, prealloc).await?;
    let timings = emit_timings(&out, &mut ch);
    let (nk, cp) = ch.available();
    emit(&out, json!({"ev":"ready","timings":timings,"avail":[nk,cp]}));
    while let Some(cmd) = ctl.recv().await {
        let id = cmd.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let name = cmd.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
        if name == "close" {
            break;
        }
        if name != "prove" && name != "verify" {
            emit(&out, json!({"ev":"done","id":id,"ok":false,"err":format!("unknown command {name:?}")}));
            continue;
        }
        let proof = cmd.get("proof").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let res: Result<Vec<zkbench::proofs::CheckResult>> = async {
            let want = if name == "prove" { Role::Prover } else { Role::Verifier };
            if ch.role_for(&proof)? != want {
                anyhow::bail!("{proof}: the client does not {name} on the channel");
            }
            let params: Params = serde_json::from_value(cmd.get("params").cloned().unwrap_or_default())
                .map_err(|e| anyhow::anyhow!("bad params: {e}"))?;
            // Refused here, before anything reaches the channel: a mismatch
            // must not consume the proof's single run or poison the channel.
            if params.proof().name() != proof {
                anyhow::bail!("{proof}: the params are for {}", params.proof().name());
            }
            // Never echo the witness parser's message: it may quote the value.
            let witness: Option<Witness> = match cmd.get("witness") {
                Some(w) if !w.is_null() => Some(serde_json::from_value(w.clone()).map_err(|_| anyhow::anyhow!("bad witness"))?),
                _ => None,
            };
            if want == Role::Prover && witness.is_none() {
                anyhow::bail!("{proof}: prove needs a witness");
            }
            let r = tokio::time::timeout(Duration::from_secs(60), ch.request(&params, witness.as_ref())).await;
            match r {
                Ok(r) => r,
                Err(_) => {
                    ch.poison();
                    anyhow::bail!("{proof}: timed out on the proof channel")
                }
            }
        }
        .await;
        let t = ch.take_timings();
        let (ms, sent, recv) = t.last().map(|x| (x.ms, x.bytes_sent, x.bytes_recv)).unwrap_or((0.0, 0, 0));
        match res {
            Ok(checks) => {
                let cs: Vec<_> = checks.iter().map(|c| json!({"label":c.label,"ok":c.ok})).collect();
                emit(&out, json!({"ev":"done","id":id,"proof":proof,"ok":true,"checks":cs,
                                  "ms":(ms * 1000.0).round() / 1000.0,"bytes_sent":sent,"bytes_recv":recv}));
            }
            Err(e) => {
                emit(&out, json!({"ev":"done","id":id,"proof":proof,"ok":false,"err":format!("{e:#}"),"ms":ms}));
            }
        }
    }
    ch.close().await;
    Ok(())
}

async fn run_channel(args: &[String]) -> Result<()> {
    use tokio::sync::mpsc;
    let mut prealloc = zkbench::channel::Prealloc::default();
    if let Some(v) = arg_value(args, "--prealloc-nk") {
        prealloc.nk = v.parse().context("--prealloc-nk")?;
    }
    if let Some(v) = arg_value(args, "--prealloc-cp") {
        prealloc.cp = v.parse().context("--prealloc-cp")?;
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u8, Vec<u8>)>();
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<serde_json::Value>();
    let (party_io, bridge) = tokio::io::duplex(4 << 20);
    let (mut br, mut bw) = tokio::io::split(bridge);

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
                    emit(&o, serde_json::json!({"ev":"error","msg":"stdin frame too large"}));
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
                1 => match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(v) => {
                        let _ = ctl_tx.send(v);
                    }
                    Err(_) => {
                        if let Some(o) = err_out.upgrade() {
                            emit(&o, serde_json::json!({"ev":"error","msg":"bad control JSON"}));
                        }
                    }
                },
                _ => {}
            }
        }
        // EOF on stdin: the network input ends too, and so does the control
        // channel (ctl_tx dropped), which closes the proof channel.
        let _ = bw.shutdown().await;
    });

    let res = channel_loop(out_tx.clone(), ctl_rx, party_io, prealloc).await;
    if let Err(e) = &res {
        emit(&out_tx, serde_json::json!({"ev":"error","msg":format!("{e:#}")}));
    }
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
    res
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.iter().any(|a| a == "--channel") {
        run_channel(&args).await
    } else if args.iter().any(|a| a == "--bench") {
        run_bench(&args).await
    } else {
        run_stdio(&args).await
    };
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("cu-prover: error: {e:#}");
            std::process::exit(1)
        }
    }
}
