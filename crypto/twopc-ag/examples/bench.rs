//! Benchmark: garbler-only authenticated garbling (`twopc-ag`) vs the deployed
//! dual execution (`twopc`) on the same emulated links
//! (`zkbench::transport::emulated_link`: per-direction rate, one-way delay).
//!
//! `cargo run --release -p twopc-ag --example bench [-- --runs N] [--quick]`
//!
//! Wall time is a full cold session (Party::new → preprocess → key_share →
//! handshake → application) until *both* parties are done.

use std::time::{Duration, Instant};

use p256::ProjectivePoint;
use p256::elliptic_curve::PrimeField;
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum Proto {
    AgFerret,
    AgKos,
    DualEx,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::AgFerret => "AG (N garbles; MAC COTs: Ferret)",
            Proto::AgKos => "AG (N garbles; MAC COTs: KOS)",
            Proto::DualEx => "DualEx (deployed twopc)",
        }
    }
}

type Steps = Vec<(&'static str, f64, u64, u64)>;

struct Res {
    wall_ms: f64,
    c2n: u64,
    n2c: u64,
    c_steps: Steps,
}

async fn session(proto: Proto, delay: Duration, up: f64, down: f64) -> Res {
    // a = C: a→b is C's uplink.
    let (io_c, io_n, counters) = emulated_link(delay, up, down);
    let share = server_share();
    let th_sh = [1u8; 32];
    let th_sf = [2u8; 32];
    let t0 = Instant::now();
    let (c, _n) = match proto {
        Proto::AgFerret | Proto::AgKos => {
            let cfg = twopc_ag::Config {
                mac_cot: if proto == Proto::AgKos {
                    twopc_ag::MacCot::Kos
                } else {
                    twopc_ag::MacCot::Ferret
                },
            };
            let run = move |role, io| async move {
                let mut p = twopc_ag::Party::with_config(role, io, cfg).await.unwrap();
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
            let (c, n) = tokio::join!(
                tokio::spawn(run(twopc_ag::Role::C, io_c)),
                tokio::spawn(run(twopc_ag::Role::N, io_n))
            );
            (c.unwrap(), n.unwrap())
        }
        Proto::DualEx => {
            let run = move |role, io| async move {
                let mut p = twopc::Party::new(role, io).await.unwrap();
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
            let (c, n) = tokio::join!(
                tokio::spawn(run(twopc::Role::C, io_c)),
                tokio::spawn(run(twopc::Role::N, io_n))
            );
            (c.unwrap(), n.unwrap())
        }
    };
    let wall_ms = t0.elapsed().as_secs_f64() * 1e3;
    Res {
        wall_ms,
        c2n: counters.p2v(),
        n2c: counters.v2p(),
        c_steps: c,
    }
}

fn mb(b: u64) -> String {
    format!("{:.2}", b as f64 / 1e6)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let runs: usize = args
        .iter()
        .skip_while(|a| *a != "--runs")
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let quick = args.iter().any(|a| a == "--quick");
    let only: Option<String> = args.iter().skip_while(|a| *a != "--only").nth(1).cloned();

    let (c2n, n2c) = twopc_ag::message_sizes();
    println!("Protocol messages (AG, computed, excl. OT extension): C→N {c2n} B, N→C {n2c} B\n");

    let mbit = |x: f64| x * 1e6 / 8.0;
    let scenarios: Vec<(&str, Duration, f64, f64)> = vec![
        ("local (no delay, unlimited)", Duration::ZERO, f64::INFINITY, f64::INFINITY),
        ("home: 40 ms one-way, 2 Mbit/s up, 50 Mbit/s down", Duration::from_millis(40), mbit(2.0), mbit(50.0)),
        ("home: 40 ms one-way, 7 Mbit/s up, 50 Mbit/s down", Duration::from_millis(40), mbit(7.0), mbit(50.0)),
        ("symmetric: 25 ms one-way, 100 Mbit/s", Duration::from_millis(25), mbit(100.0), mbit(100.0)),
    ];
    let protos = [Proto::AgFerret, Proto::AgKos, Proto::DualEx];

    // Warm-up (circuit construction, page faults).
    let _ = session(Proto::AgFerret, Duration::ZERO, f64::INFINITY, f64::INFINITY).await;
    let _ = session(Proto::DualEx, Duration::ZERO, f64::INFINITY, f64::INFINITY).await;

    for (name, delay, up, down) in scenarios {
        if let Some(o) = &only {
            if !name.starts_with(o.as_str()) {
                continue;
            }
        }
        println!("## {name}\n");
        println!("| protocol | cold session wall (s), median | C→N (MB) | N→C (MB) |");
        println!("|---|---|---|---|");
        let mut details = Vec::new();
        for proto in protos {
            // DualEx on a 2 Mbit/s uplink takes ~1.5 min per session.
            let n = if quick || (proto == Proto::DualEx && up.is_finite() && up < mbit(10.0)) {
                1
            } else {
                runs
            };
            let mut walls = Vec::new();
            let mut last = None;
            for _ in 0..n {
                let r = session(proto, delay, up, down).await;
                walls.push(r.wall_ms);
                last = Some(r);
            }
            walls.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let r = last.unwrap();
            println!(
                "| {} | {:.2} (n={}) | {} | {} |",
                proto.name(),
                walls[walls.len() / 2] / 1e3,
                n,
                mb(r.c2n),
                mb(r.n2c)
            );
            details.push((proto, r));
        }
        println!();
        for (proto, r) in details {
            println!("{} — C's steps (ms; bytes C sent / received during the step):\n", proto.name());
            println!("| step | ms | C sent | C recv |");
            println!("|---|---|---|---|");
            for (s, ms, snt, rcv) in &r.c_steps {
                println!("| {s} | {ms:.1} | {snt} | {rcv} |");
            }
            println!();
        }
    }
}
