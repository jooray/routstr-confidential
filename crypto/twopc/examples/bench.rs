//! Benchmark: wall time and transport bytes per step, locally and over an
//! emulated WAN (25 ms one-way, 100 Mbit/s and 20 Mbit/s).
//!
//! `cargo run --release -p twopc --example bench [-- --runs N]`

use std::collections::BTreeMap;
use std::time::Duration;

use p256::ProjectivePoint;
use p256::elliptic_curve::PrimeField;
use twopc::testutil::emulated_pair;
use twopc::{Party, Role, StepTiming, circuit_stats};

fn server_share() -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b[0] &= 0x7f;
    let s = p256::Scalar::from_repr(b.into()).unwrap();
    let p = (ProjectivePoint::GENERATOR * s).to_affine();
    p.to_encoded_point(false).as_bytes().try_into().unwrap()
}

async fn session(delay: Duration, rate: f64) -> (Vec<StepTiming>, Vec<StepTiming>) {
    let (io_c, io_n) = emulated_pair(delay, rate);
    let share = server_share();
    let th_sh = [1u8; 32];
    let th_sf = [2u8; 32];
    let run = move |role: Role, io| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.preprocess().await.unwrap();
        p.key_share().await.unwrap();
        p.handshake(&share, th_sh).await.unwrap();
        p.application(th_sf).await.unwrap();
        let t = p.take_timings();
        p.close().await;
        t
    };
    let (c, n) = tokio::join!(
        tokio::spawn(run(Role::C, io_c)),
        tokio::spawn(run(Role::N, io_n))
    );
    (c.unwrap(), n.unwrap())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let runs: usize = std::env::args()
        .skip_while(|a| a != "--runs")
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    println!("## Circuits\n");
    println!("| circuit | AND | XOR | SHA-256 compressions | C input bits | N input bits | output bits |");
    println!("|---|---|---|---|---|---|---|");
    for s in circuit_stats() {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            s.name, s.and_gates, s.xor_gates, s.compressions, s.c_input_bits, s.n_input_bits, s.output_bits
        );
    }

    let scenarios: [(&str, Duration, f64); 3] = [
        ("local (no delay, unlimited)", Duration::ZERO, f64::INFINITY),
        ("WAN 50 ms RTT, 100 Mbit/s", Duration::from_millis(25), 100e6 / 8.0),
        ("WAN 50 ms RTT, 20 Mbit/s", Duration::from_millis(25), 20e6 / 8.0),
    ];
    for (name, delay, rate) in scenarios {
        // warm-up (circuit construction, page faults)
        let _ = session(delay, rate).await;
        let mut acc: BTreeMap<&'static str, (Vec<f64>, u64, u64, usize)> = BTreeMap::new();
        let mut order: Vec<&'static str> = Vec::new();
        for _ in 0..runs {
            let (c, n) = session(delay, rate).await;
            for t in c {
                if !order.contains(&t.step) {
                    order.push(t.step);
                }
                let e = acc.entry(t.step).or_insert((Vec::new(), 0, 0, 0));
                e.0.push(t.ms);
                e.1 = t.bytes_sent;
                e.3 += 1;
            }
            // N→C bytes from N's own view (what N wrote during that step).
            for t in n {
                if let Some(e) = acc.get_mut(t.step) {
                    e.2 = t.bytes_sent;
                }
            }
        }
        println!("\n## {name} (ms: C's view, median of {runs}; bytes: written by each side during its step)\n");
        println!("| step | ms | C→N bytes | N→C bytes |");
        println!("|---|---|---|---|");
        let mut total = 0.0;
        for step in order {
            let (ms, s, r, _) = &acc[step];
            let mut v = ms.clone();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = v[v.len() / 2];
            total += med;
            println!("| {step} | {med:.1} | {s} | {r} |");
        }
        println!("| **total** | {total:.1} | | |");
    }
}
