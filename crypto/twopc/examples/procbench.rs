//! CPU time and peak memory of one party, measured in its own process.
//!
//! `bench` runs both parties in one process, so it cannot tell their CPU or
//! memory apart. Here each role is a process and the sessions run over
//! loopback TCP (no link emulation):
//!
//! ```text
//! procbench n 127.0.0.1:7461 <sessions>     # the node: accepts, one task per connection
//! procbench c 127.0.0.1:7461 <sessions> [--sequential]
//! ```
//!
//! The client starts its sessions at once unless `--sequential` is given.
//! Each process prints one
//! line: wall time, user and system CPU (`getrusage(RUSAGE_SELF)`) and the
//! peak resident set size.

use std::time::Instant;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use twopc::{Party, Role};

const SERVER_SHARE_SCALAR: [u8; 32] = [7u8; 32];

fn server_share() -> [u8; 65] {
    use p256::elliptic_curve::PrimeField;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let s = p256::Scalar::from_repr(SERVER_SHARE_SCALAR.into()).unwrap();
    let p = (p256::ProjectivePoint::GENERATOR * s).to_affine();
    p.to_encoded_point(false).as_bytes().try_into().unwrap()
}

async fn session(role: Role, io: TcpStream) {
    io.set_nodelay(true).unwrap();
    let mut p = Party::new(role, io.compat()).await.unwrap();
    p.preprocess().await.unwrap();
    p.key_share().await.unwrap();
    p.handshake(&server_share(), [1u8; 32]).await.unwrap();
    p.application([2u8; 32]).await.unwrap();
    p.close().await;
}

fn rusage() -> (f64, f64, f64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    // ru_maxrss: bytes on macOS, kilobytes on Linux.
    let rss = if cfg!(target_os = "macos") { ru.ru_maxrss as f64 } else { ru.ru_maxrss as f64 * 1024.0 };
    (tv(ru.ru_utime), tv(ru.ru_stime), rss / (1024.0 * 1024.0))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = match args.get(1).map(String::as_str) {
        Some("n") => Role::N,
        Some("c") => Role::C,
        _ => panic!("usage: procbench n|c <addr> <sessions> [--sequential]"),
    };
    let addr = args.get(2).expect("address").clone();
    let sessions: usize = args.get(3).expect("sessions").parse().unwrap();
    let sequential = args.iter().any(|a| a == "--sequential");
    let t0 = Instant::now();
    if role == Role::N {
        let l = TcpListener::bind(&addr).await.unwrap();
        let mut tasks = Vec::new();
        for _ in 0..sessions {
            let (io, _) = l.accept().await.unwrap();
            tasks.push(tokio::spawn(session(Role::N, io)));
        }
        for t in tasks {
            t.await.unwrap();
        }
    } else {
        let mut tasks = Vec::new();
        for _ in 0..sessions {
            let io = loop {
                match TcpStream::connect(&addr).await {
                    Ok(io) => break io,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
            };
            let t = tokio::spawn(session(Role::C, io));
            if sequential {
                t.await.unwrap();
            } else {
                tasks.push(t);
            }
        }
        for t in tasks {
            t.await.unwrap();
        }
    }
    let (user, sys, rss) = rusage();
    println!(
        "{} sessions={sessions}{} wall={:.2}s user={user:.2}s sys={sys:.2}s peak_rss={rss:.0}MiB",
        if role == Role::N { "N" } else { "C" },
        if sequential { " sequential" } else { "" },
        t0.elapsed().as_secs_f64(),
    );
}
