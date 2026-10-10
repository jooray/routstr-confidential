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
//! * **bench**: runs every statement (v1, then v2; `--v2` for v2 only) over
//!   the `local` and `wan` (25 ms one-way = 50 ms RTT, 100 Mbit/s) transports.
//!
//! stdout carries *only* mpz bytes in stdio mode; all logging goes to stderr.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use zkbench::proofs::{PairOutcome, run_io, run_pair_transport, stats};
use zkbench::statements::{Params, Witness};
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
    let v2_only = args.iter().any(|a| a == "--v2");
    let set: Vec<_> = if v2_only {
        fixtures::all_v2()
    } else {
        fixtures::all().into_iter().chain(fixtures::all_v2()).collect()
    };
    for (name, params, witness) in set {
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.iter().any(|a| a == "--bench") {
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
