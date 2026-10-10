//! End-to-end tests: correctness against cu-crypto's reference key schedule,
//! and the malicious-party tests.

use std::time::Duration;

use cu_crypto::hkdf::{hkdf_extract, sha256};
use cu_crypto::keyschedule::KeySchedule;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use rand::RngExt;

use super::*;
use crate::testutil::emulated_pair;

struct Server {
    b: Scalar,
    share: [u8; 65],
}

fn server() -> Server {
    let mut rng = os_rng();
    let b = random_scalar(&mut rng);
    let share = encode_point(&(ProjectivePoint::GENERATOR * b));
    Server { b, share }
}

fn reference(server: &Server, joint: &[u8; 65], th_sh: [u8; 32], th_sf: [u8; 32]) -> KeySchedule {
    let p = parse_point(joint).unwrap();
    let z = (p * server.b).to_affine().to_encoded_point(false);
    let x: [u8; 32] = z.x().unwrap().as_slice().try_into().unwrap();
    let hs = hkdf_extract(&circuits::derived_es(), &x);
    KeySchedule::from_handshake(hs, th_sh, th_sf)
}

type Outcome = (
    Result<[u8; 65]>,
    Result<HsSecrets>,
    Result<ApOut>,
);

/// Runs a whole session; `c_th`/`n_th` are (th_sh, th_sf) per party.
async fn session(
    cheat_c: Cheat,
    cheat_n: Cheat,
    c_th: ([u8; 32], [u8; 32]),
    n_th: ([u8; 32], [u8; 32]),
    srv: &Server,
) -> (Outcome, Outcome) {
    let (io_c, io_n) = emulated_pair(Duration::ZERO, f64::INFINITY);
    let share = srv.share;
    let run = |role: Role, io, cheat: Cheat, th: ([u8; 32], [u8; 32])| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.cheat = cheat;
        p.preprocess().await.unwrap();
        let ks = p.key_share().await;
        if ks.is_err() {
            return (ks, Err(Error::State("skipped")), Err(Error::State("skipped")));
        }
        let hs = p.handshake(&share, th.0).await;
        if hs.is_err() {
            return (ks, hs, Err(Error::State("skipped")));
        }
        let ap = p.application(th.1).await;
        p.close().await;
        (ks, hs, ap)
    };
    let c = tokio::spawn(run(Role::C, io_c, cheat_c, c_th));
    let n = tokio::spawn(run(Role::N, io_n, cheat_n, n_th));
    let (c, n) = tokio::join!(c, n);
    (c.unwrap(), n.unwrap())
}

fn ths() -> ([u8; 32], [u8; 32]) {
    let mut rng = os_rng();
    (rng.random(), rng.random())
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_matches_reference() {
    for _ in 0..2 {
        let srv = server();
        let th = ths();
        let ((ks_c, hs_c, ap_c), (ks_n, hs_n, ap_n)) =
            session(Cheat::None, Cheat::None, th, th, &srv).await;
        let joint = ks_c.unwrap();
        assert_eq!(joint, ks_n.unwrap());
        let ks = reference(&srv, &joint, th.0, th.1);
        let (hs_c, hs_n) = (hs_c.unwrap(), hs_n.unwrap());
        assert_eq!(&hs_c.c_hs, ks.client_hs.as_bytes());
        assert_eq!(&hs_c.s_hs, ks.server_hs.as_bytes());
        assert_eq!(hs_c.c_hs, hs_n.c_hs);
        assert_eq!(hs_c.s_hs, hs_n.s_hs);
        let mut kiv = ks.c_ap_0.key().to_vec();
        kiv.extend_from_slice(&ks.c_ap_0.iv());
        match (ap_c.unwrap(), ap_n.unwrap()) {
            (
                ApOut::C {
                    s_ap_0,
                    c_ap_1,
                    h1,
                    h2,
                    hk,
                },
                ApOut::N {
                    k0,
                    iv0,
                    h1: h1n,
                    h2: h2n,
                    hk: hkn,
                },
            ) => {
                assert_eq!(&s_ap_0, ks.s_ap_0.as_bytes());
                assert_eq!(&c_ap_1, ks.c_ap_1.as_bytes());
                assert_eq!(k0, ks.c_ap_0.key());
                assert_eq!(iv0, ks.c_ap_0.iv());
                assert_eq!(h1, sha256(ks.c_ap_1.as_bytes()));
                assert_eq!(h2, sha256(ks.s_ap_0.as_bytes()));
                assert_eq!(hk, sha256(&kiv));
                assert_eq!((h1, h2, hk), (h1n, h2n, hkn));
            }
            _ => panic!("wrong output variants"),
        }
    }
}

fn assert_abort_at_phase(o: &Outcome, phase: usize) {
    match phase {
        0 => {
            assert!(o.0.is_ok());
            assert!(matches!(o.1, Err(Error::Abort(_))), "phase A must abort: {:?}", o.1);
        }
        _ => {
            assert!(o.1.is_ok());
            assert!(matches!(o.2, Err(Error::Abort(_))), "phase B must abort: {:?}", o.2);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_gate_aborts() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        // N garbles run 1: C's decoded vector is wrong.
        let (c, n) = session(Cheat::None, Cheat::CorruptGate(phase), th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
        // C garbles run 2: N's decoded vector is wrong.
        let (c, n) = session(Cheat::CorruptGate(phase), Cheat::None, th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn flipped_decoding_bit_aborts() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::FlipDecode(phase), th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
        let (c, n) = session(Cheat::FlipDecode(phase), Cheat::None, th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inconsistent_inputs_across_runs_abort() {
    let srv = server();
    let th = ths();
    // Phase A: bit 256 is the first MS-mask bit, bit 0 the first x-share bit.
    // Phase B: bit 0 is the first MS-share bit, bit 256 the first output mask bit.
    for (phase, bit) in [(0, 0), (0, 256), (1, 0), (1, 256)] {
        let ch = Cheat::InconsistentInput { phase, bit };
        let (c, n) = session(Cheat::None, ch, th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
        let (c, n) = session(ch, Cheat::None, th, th, &srv).await;
        assert_abort_at_phase(&c, phase);
        assert_abort_at_phase(&n, phase);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn inconsistent_transcript_aborts() {
    let srv = server();
    let th = ths();
    let mut other = th;
    other.0[5] ^= 1;
    let (c, n) = session(Cheat::None, Cheat::None, th, other, &srv).await;
    assert_abort_at_phase(&c, 0);
    assert_abort_at_phase(&n, 0);
    let mut other = th;
    other.1[31] ^= 0x80;
    let (c, n) = session(Cheat::None, Cheat::None, th, other, &srv).await;
    assert_abort_at_phase(&c, 1);
    assert_abort_at_phase(&n, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn rogue_key_share_aborts() {
    let srv = server();
    let th = ths();
    let (_c, n) = session(Cheat::BadOpen, Cheat::None, th, th, &srv).await;
    assert!(matches!(n.0, Err(Error::Abort(_))), "{:?}", n.0);
    assert!(n.1.is_err() && n.2.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_server_share_rejected() {
    let srv = server();
    let th = ths();
    let mut bad = srv.share;
    bad[40] ^= 1; // off the curve
    let bad_srv = Server { b: srv.b, share: bad };
    let (c, n) = session(Cheat::None, Cheat::None, th, th, &bad_srv).await;
    assert!(matches!(c.1, Err(Error::Input(_))));
    assert!(matches!(n.1, Err(Error::Input(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn wan_session_works() {
    let srv = server();
    let th = ths();
    let (io_c, io_n) = emulated_pair(Duration::from_millis(25), 100e6 / 8.0);
    let share = srv.share;
    let run = |role: Role, io| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.preprocess().await.unwrap();
        let joint = p.key_share().await.unwrap();
        let hs = p.handshake(&share, th.0).await.unwrap();
        let ap = p.application(th.1).await.unwrap();
        p.close().await;
        (joint, hs, ap)
    };
    let (c, n) = tokio::join!(
        tokio::spawn(run(Role::C, io_c)),
        tokio::spawn(run(Role::N, io_n))
    );
    let (c, n) = (c.unwrap(), n.unwrap());
    let ks = reference(&srv, &c.0, th.0, th.1);
    assert_eq!(&n.1.c_hs, ks.client_hs.as_bytes());
    if let ApOut::N { k0, .. } = n.2 {
        assert_eq!(k0, ks.c_ap_0.key());
    } else {
        panic!()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn close_is_prompt() {
    let srv = server();
    let th = ths();
    let (io_c, io_n) = emulated_pair(Duration::ZERO, f64::INFINITY);
    let share = srv.share;
    let run = |role: Role, io| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.preprocess().await.unwrap();
        p.key_share().await.unwrap();
        p.handshake(&share, th.0).await.unwrap();
        p.application(th.1).await.unwrap();
        let t = std::time::Instant::now();
        p.close().await;
        t.elapsed()
    };
    let (c, n) = tokio::join!(
        tokio::spawn(run(Role::C, io_c)),
        tokio::spawn(run(Role::N, io_n))
    );
    let (c, n) = (c.unwrap(), n.unwrap());
    assert!(c < Duration::from_secs(1) && n < Duration::from_secs(1), "{c:?} {n:?}");
}
