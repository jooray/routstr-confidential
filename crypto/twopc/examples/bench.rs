//! Benchmark of the two-party key schedule (`split-public-1`: node-only
//! authenticated garbling, split key schedule) on emulated links (`zkbench::transport::emulated_link`:
//! per-direction rate, pipelined one-way delay).
//!
//! `cargo run --release -p twopc --example bench [-- --runs N] [--only <scenario prefix>]`
//!
//! Wall time is a full cold session (Party::new → preprocess → key_share →
//! handshake → application) until *both* parties are done. Bytes are what
//! crossed the link in each direction (mux headers and all OT traffic).

use std::time::{Duration, Instant};

use p256::ProjectivePoint;
use p256::elliptic_curve::PrimeField;
use twopc::{Party, Role, circuit_stats};
use zkbench::transport::emulated_link;

fn server_share() -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b[0] &= 0x7f;
    let s = p256::Scalar::from_repr(b.into()).unwrap();
    let p = (ProjectivePoint::GENERATOR * s).to_affine();
    p.to_encoded_point(false).as_bytes().try_into().unwrap()
}

type Steps = Vec<(&'static str, f64, u64, u64)>;

struct Res {
    wall_ms: f64,
    c2n: u64,
    n2c: u64,
    c_steps: Steps,
    n_steps: Steps,
}

async fn session(delay: Duration, up: f64, down: f64) -> Res {
    // a = C: a→b is C's uplink.
    let (io_c, io_n, counters) = emulated_link(delay, up, down);
    let share = server_share();
    let th_sh = [1u8; 32];
    let th_sf = [2u8; 32];
    let t0 = Instant::now();
    let run = move |role, io| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.preprocess().await.unwrap();
        p.key_share().await.unwrap();
        p.handshake(&share, th_sh).await.unwrap();
        p.application(th_sf).await.unwrap();
        let t: Steps = p
            .take_timings()
            .into_iter()
            .map(|s| (s.step, s.ms, s.bytes_sent, s.bytes_recv))
            .collect();
        p.close().await;
        t
    };
    let (c, n) = tokio::join!(tokio::spawn(run(Role::C, io_c)), tokio::spawn(run(Role::N, io_n)));
    let (c, n) = (c.unwrap(), n.unwrap());
    Res {
        wall_ms: t0.elapsed().as_secs_f64() * 1e3,
        c2n: counters.p2v(),
        n2c: counters.v2p(),
        c_steps: c,
        n_steps: n,
    }
}

fn mb(b: u64) -> String {
    format!("{:.2}", b as f64 / 1e6)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().skip_while(|a| *a != name).nth(1).cloned();
    let runs: usize = arg("--runs").and_then(|s| s.parse().ok()).unwrap_or(3);
    let only = arg("--only");

    let s = circuit_stats();
    println!("| circuit | AND | XOR | SHA-256 compressions | C in | N in | digest in | out |");
    println!("|---|---|---|---|---|---|---|---|");
    println!(
        "| {} | {} | {} | {} | {} | {} | {} | {} |",
        s.name, s.and_gates, s.xor_gates, s.compressions, s.c_input_bits, s.n_input_bits, s.digest_input_bits, s.output_bits
    );
    let (c2n, n2c) = twopc::message_sizes();
    println!(
        "\nAND gates at the end of each stage {:?}; protocol messages (computed, excl. OT): C→N {c2n} B, N→C {n2c} B",
        twopc::stage_and_ends()
    );
    for (what, bytes) in twopc::download_breakdown() {
        println!("  N→C {what}: {bytes} B");
    }
    println!();

    let mbit = |x: f64| x * 1e6 / 8.0;
    let scenarios: Vec<(&str, Duration, f64, f64)> = vec![
        ("local (no delay, unlimited)", Duration::ZERO, f64::INFINITY, f64::INFINITY),
        ("home: 40 ms one-way, 2 Mbit/s up, 50 Mbit/s down", Duration::from_millis(40), mbit(2.0), mbit(50.0)),
        ("home: 40 ms one-way, 7 Mbit/s up, 50 Mbit/s down", Duration::from_millis(40), mbit(7.0), mbit(50.0)),
        ("symmetric: 25 ms one-way, 100 Mbit/s", Duration::from_millis(25), mbit(100.0), mbit(100.0)),
        ("slow down: 40 ms one-way, 2 Mbit/s up, 10 Mbit/s down", Duration::from_millis(40), mbit(2.0), mbit(10.0)),
    ];

    // Warm-up (circuit construction, page faults).
    let _ = session(Duration::ZERO, f64::INFINITY, f64::INFINITY).await;
    for (name, delay, up, down) in &scenarios {
        if let Some(o) = &only {
            if !name.starts_with(o.as_str()) {
                continue;
            }
        }
        // Per-step medians over the runs (C's and N's view).
        let mut all: Vec<Res> = Vec::new();
        for _ in 0..runs {
            all.push(session(*delay, *up, *down).await);
        }
        let med = |mut v: Vec<f64>| -> f64 {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let r = &all[0];
        println!("## {name}\n");
        println!(
            "cold session {:.2} s (median of {runs}), C→N {} MB, N→C {} MB\n",
            med(all.iter().map(|r| r.wall_ms).collect()) / 1e3,
            mb(r.c2n),
            mb(r.n2c)
        );
        println!("| step | C ms | N ms | C sent | C recv |");
        println!("|---|---|---|---|---|");
        for (i, (s, _, snt, rcv)) in r.c_steps.iter().enumerate() {
            let c_ms = med(all.iter().map(|r| r.c_steps[i].1).collect());
            let n_ms = med(all.iter().map(|r| r.n_steps[i].1).collect());
            println!("| {s} | {c_ms:.1} | {n_ms:.1} | {snt} | {rcv} |");
        }
        println!();
    }
}
