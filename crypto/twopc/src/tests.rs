//! End-to-end tests: correctness against cu-crypto's reference key schedule,
//! the three-halves gate in isolation, and malicious-party tests (each
//! deviation of N must make C abort before any output is used, and C must
//! not be able to change N's outputs).

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

/// HKDF-Extract salt for the handshake secret (public TLS 1.3 constant).
fn derived_es() -> [u8; 32] {
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    cu_crypto::hkdf::derive_secret(&early, "derived", b"")
}

fn reference(server: &Server, joint: &[u8; 65], th_sh: [u8; 32], th_sf: [u8; 32]) -> KeySchedule {
    let p = parse_point(joint).unwrap();
    let z = (p * server.b).to_affine().to_encoded_point(false);
    let x: [u8; 32] = z.x().unwrap().as_slice().try_into().unwrap();
    let hs = hkdf_extract(&derived_es(), &x);
    KeySchedule::from_handshake(hs, th_sh, th_sf)
}

#[derive(Debug)]
struct Outcome {
    pre: Result<()>,
    ks: Result<[u8; 65]>,
    hs: Result<HsSecrets>,
    ap: Result<ApOut>,
}

fn skipped<T>() -> Result<T> {
    Err(Error::State("skipped"))
}

async fn session_th(
    cheat_c: Cheat,
    cheat_n: Cheat,
    c_th: ([u8; 32], [u8; 32]),
    n_th: ([u8; 32], [u8; 32]),
    srv: &Server,
) -> (Outcome, Outcome) {
    let (io_c, io_n) = emulated_pair(Duration::ZERO, f64::INFINITY);
    let share = srv.share;
    let run = move |role: Role, io, cheat: Cheat, th: ([u8; 32], [u8; 32])| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.cheat = cheat;
        let pre = p.preprocess().await;
        if pre.is_err() {
            return Outcome { pre, ks: skipped(), hs: skipped(), ap: skipped() };
        }
        let ks = p.key_share().await;
        if ks.is_err() {
            return Outcome { pre, ks, hs: skipped(), ap: skipped() };
        }
        let hs = p.handshake(&share, th.0).await;
        if hs.is_err() {
            return Outcome { pre, ks, hs, ap: skipped() };
        }
        let ap = p.application(th.1).await;
        p.close().await;
        Outcome { pre, ks, hs, ap }
    };
    let c = tokio::spawn(run(Role::C, io_c, cheat_c, c_th));
    let n = tokio::spawn(run(Role::N, io_n, cheat_n, n_th));
    let (c, n) = tokio::join!(c, n);
    (c.unwrap(), n.unwrap())
}

async fn session(
    cheat_c: Cheat,
    cheat_n: Cheat,
    th: ([u8; 32], [u8; 32]),
    srv: &Server,
) -> (Outcome, Outcome) {
    session_th(cheat_c, cheat_n, th, th, srv).await
}

fn ths() -> ([u8; 32], [u8; 32]) {
    let mut rng = os_rng();
    (rng.random(), rng.random())
}

fn check_honest(c: Outcome, n: Outcome, srv: &Server, th: ([u8; 32], [u8; 32])) {
    c.pre.unwrap();
    n.pre.unwrap();
    let joint = c.ks.unwrap();
    assert_eq!(joint, n.ks.unwrap());
    let ks = reference(srv, &joint, th.0, th.1);
    let (hs_c, hs_n) = (c.hs.unwrap(), n.hs.unwrap());
    assert_eq!(&hs_c.c_hs, ks.client_hs.as_bytes());
    assert_eq!(&hs_c.s_hs, ks.server_hs.as_bytes());
    assert_eq!(hs_c.c_hs, hs_n.c_hs);
    assert_eq!(hs_c.s_hs, hs_n.s_hs);
    let mut kiv = ks.c_ap_0.key().to_vec();
    kiv.extend_from_slice(&ks.c_ap_0.iv());
    match (c.ap.unwrap(), n.ap.unwrap()) {
        (
            ApOut::C { s_ap_0, c_ap_1, h1, h2, hk },
            ApOut::N { k0, iv0, h1: h1n, h2: h2n, hk: hkn },
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

#[test]
fn garble_evaluate_matches_plaintext() {
    // The bare half-gates garbler/evaluator of this crate on phase A.
    let s = spec(0);
    let mut rng = os_rng();
    let mut delta = Block::random(&mut rng);
    delta.set_lsb(true);
    let n_in = s.circ.inputs().len();
    let in_keys: Vec<Block> = (0..n_in).map(|_| Block::random(&mut rng)).collect();
    let (k, tables) = gc::garble(&s.circ, delta, &in_keys, 0, &mut rng);
    let input: Vec<bool> = (0..n_in).map(|_| rng.random()).collect();
    let in_l: Vec<Block> = input.iter().zip(&in_keys).map(|(b, k)| *k ^ sel(*b, delta)).collect();
    let l = gc::evaluate(&s.circ, &in_l, &tables, 0);
    let want = s.circ.evaluate(input).unwrap();
    for (o, w) in s.circ.outputs().zip(want) {
        assert_eq!(l[o], k[o] ^ sel(w, delta));
    }
}

#[test]
fn three_halves_gate_all_cases() {
    // Every permute-bit pair, every dicing pair, every colour pair: the
    // evaluator gets K0 ⊕ (a·b)·Δ. Also exercises the debug consistency
    // assertions of the garbler's linear system.
    let mut rng = os_rng();
    let cipher = &*mpz_core::aes::FIXED_KEY_AES;
    for trial in 0..64 {
        let mut delta = Block::random(&mut rng);
        delta.set_lsb(true);
        for pa in [false, true] {
            for pb in [false, true] {
                for dice in 0..4u8 {
                    let mut a0 = Block::random(&mut rng);
                    a0.set_lsb(pa);
                    let mut b0 = Block::random(&mut rng);
                    b0.set_lsb(pb);
                    let gid = trial as u128 * 17 + dice as u128;
                    let (k0, g) = gc::and_garble3(cipher, a0, b0, delta, gid, [dice & 1 == 1, dice & 2 == 2]);
                    for a in [false, true] {
                        for b in [false, true] {
                            let la = a0 ^ sel(a, delta);
                            let lb = b0 ^ sel(b, delta);
                            let out = gc::and_eval3(cipher, la, lb, &g, gid);
                            assert_eq!(out, k0 ^ sel(a & b, delta), "pa={pa} pb={pb} dice={dice} a={a} b={b}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn three_halves_control_bits_hide_permute_bits() {
    // The evaluator's decrypted dicing bits r (hence its matrix R_st) are
    // uniform for every (permute bits, colours): count over many gates.
    let mut rng = os_rng();
    let cipher = &*mpz_core::aes::FIXED_KEY_AES;
    let mut delta = Block::random(&mut rng);
    delta.set_lsb(true);
    for pa in [false, true] {
        for pb in [false, true] {
            let mut hist = [0u32; 4];
            for gid in 0..4000u128 {
                let mut a0 = Block::random(&mut rng);
                a0.set_lsb(pa);
                let mut b0 = Block::random(&mut rng);
                b0.set_lsb(pb);
                let r: u8 = rng.random();
                let (_, g) = gc::and_garble3(cipher, a0, b0, delta, gid, [r & 1 == 1, r & 2 == 2]);
                // Evaluate on colours (0,0) and record the hash-independent part.
                let s = false;
                let t = false;
                let la = if pa { a0 ^ delta } else { a0 }; // colour 0
                let lb = if pb { b0 ^ delta } else { b0 };
                assert!(!la.lsb() && !lb.lsb());
                let mut h = [la, lb, la ^ lb];
                let tw = |k: u128| Block::new((gid * 3 + k).to_le_bytes());
                cipher.tccr_many(&[tw(0), tw(1), tw(2)], &mut h);
                let bit = |x: Block| (u128::from_le_bytes(x.to_bytes()) >> 127) & 1 == 1;
                let z = |k: u8| (g.z >> k) & 1 == 1;
                let r0 = z(0) ^ (s & z(2)) ^ ((s ^ t) & z(4)) ^ bit(h[0]) ^ bit(h[2]);
                let r1 = z(1) ^ (t & z(3)) ^ ((s ^ t) & z(4)) ^ bit(h[1]) ^ bit(h[2]);
                hist[(r0 as usize) | (r1 as usize) << 1] += 1;
            }
            for c in hist {
                assert!((850..1150).contains(&c), "pa={pa} pb={pb} hist={hist:?}");
            }
        }
    }
}

#[test]
fn chi_is_never_zero_and_unchanged_otherwise() {
    // A non-zero first draw is the plain hash (what earlier builds computed),
    // so both parties agree across versions except with probability 2^-128.
    let mut rng = os_rng();
    for _ in 0..64 {
        let seed: [u8; 32] = rng.random();
        let h: [u8; 32] = Sha256::new()
            .chain_update(TAG_CHI)
            .chain_update(seed)
            .chain_update(b"check0")
            .finalize()
            .into();
        assert_eq!(chi(&seed, b"check0"), Block::new(h[..16].try_into().unwrap()));
    }
    // A zero draw is re-drawn with the next counter, deterministically.
    let seed = [7u8; 32];
    let c = first_nonzero(|ctr| if ctr < 2 { Block::ZERO } else { chi_draw(&seed, b"dvzk", ctr) });
    assert_eq!(c, chi_draw(&seed, b"dvzk", 2));
    assert_ne!(c, Block::ZERO);
    assert_ne!(chi_draw(&seed, b"dvzk", 1), chi_draw(&seed, b"dvzk", 0));
}

#[test]
fn tables_roundtrip() {
    let mut rng = os_rng();
    let t: Vec<gc::Gate3> = (0..1001)
        .map(|_| gc::Gate3 { g: [rng.random(), rng.random(), rng.random()], z: rng.random::<u8>() & 0x1f })
        .collect();
    let b = gc::tables_to_bytes(&t);
    assert_eq!(b.len(), gc::tables_len(t.len()));
    assert_eq!(gc::tables_from_bytes(&b, t.len()).unwrap(), t);
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_matches_reference() {
    for _ in 0..2 {
        let srv = server();
        let th = ths();
        let (c, n) = session(Cheat::None, Cheat::None, th, &srv).await;
        check_honest(c, n, &srv, th);
    }
}

fn c_err(c: &Outcome, phase: usize) -> String {
    let e = if phase == 0 { c.hs.as_ref().err() } else { c.ap.as_ref().err() };
    format!("{:?}", e.expect("C must fail"))
}

fn assert_c_aborts_with(c: &Outcome, n: &Outcome, phase: usize, what: &str) {
    assert_c_aborts_at(c, n, phase);
    let e = c_err(c, phase);
    assert!(e.contains(what), "phase {phase}: expected '{what}', got {e}");
}

fn assert_c_aborts_at(c: &Outcome, n: &Outcome, phase: usize) {
    c.pre.as_ref().unwrap();
    assert!(c.ks.is_ok());
    match phase {
        0 => {
            assert!(matches!(c.hs, Err(Error::Abort(_))), "C must abort in phase A: {:?}", c.hs);
            assert!(matches!(n.hs, Err(Error::Abort(_))), "N must see the abort: {:?}", n.hs);
        }
        _ => {
            assert!(c.hs.is_ok());
            assert!(matches!(c.ap, Err(Error::Abort(_))), "C must abort in phase B: {:?}", c.ap);
            assert!(matches!(n.ap, Err(Error::Abort(_))), "N must see the abort: {:?}", n.ap);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_garbled_table_detected_by_evaluator() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::CorruptGate(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_control_bits_detected_by_evaluator() {
    // Three-halves specific: wrong dicing bits make the evaluator use the
    // wrong R matrix (a garbage label); the consistency check catches it.
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::CorruptControlBits(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_check_rows_detected() {
    // 64-bit check rows: N perturbs every row (random 64-bit offsets).
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::BadRows(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn check_rows_bound_to_session_salt() {
    // The 64-bit check rows are keyed by a salt from C's challenge seed; rows
    // computed under any other salt (e.g. precomputed before the seed) fail.
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::WrongSalt(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logic_change_and_to_nand_detected() {
    // N commits a flipped mask for one AND output: tables and all other
    // material are consistent with the flipped mask, so only the AND-gate
    // consistency check can catch it.
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::FlipLambda(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_and_product_detected_in_preprocessing() {
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::BadT, th, &srv).await;
    assert!(matches!(&c.pre, Err(Error::Abort(m)) if m.contains("AND-product")), "{:?}", c.pre);
    assert!(n.pre.is_err() || n.ks.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn lying_about_output_mask_detected() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, _n) = session(Cheat::None, Cheat::LieOpen(phase), th, &srv).await;
        assert!(matches!(&c.pre, Err(Error::Abort(m)) if m.contains("opened masks")), "{:?}", c.pre);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_check_value_detected() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::BadYn(phase), th, &srv).await;
        assert_c_aborts_with(&c, &n, phase, "consistency check");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_garbler_input_label_detected() {
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::None, Cheat::BadInputLabel(phase), th, &srv).await;
        assert_c_aborts_at(&c, &n, phase);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_ot_correlation_detected() {
    // N runs the OT for C's input labels with a Δ other than the garbling Δ.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::KosDelta, th, &srv).await;
    assert_c_aborts_at(&c, &n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_transcript_hash_from_garbler_detected() {
    let srv = server();
    let th = ths();
    let mut other = th;
    other.0[5] ^= 1;
    let (c, n) = session_th(Cheat::None, Cheat::None, th, other, &srv).await;
    assert_c_aborts_with(&c, &n, 0, "pointer bits");
    let mut other = th;
    other.1[31] ^= 0x80;
    let (c, n) = session_th(Cheat::None, Cheat::None, th, other, &srv).await;
    assert_c_aborts_with(&c, &n, 1, "pointer bits");
}

#[tokio::test(flavor = "multi_thread")]
async fn cheating_evaluator_cannot_change_n_outputs() {
    // C reports a flipped output bit (e.g. to shift N's K_0 or a public
    // anchor); without the inactive label it cannot authenticate it.
    let srv = server();
    let th = ths();
    for phase in 0..2 {
        let (c, n) = session(Cheat::FlipOutput(phase), Cheat::None, th, &srv).await;
        match phase {
            0 => assert!(matches!(&n.hs, Err(Error::Abort(m)) if m.contains("output labels")), "{:?}", n.hs),
            _ => {
                assert!(n.hs.is_ok());
                assert!(matches!(&n.ap, Err(Error::Abort(m)) if m.contains("output labels")), "{:?}", n.ap);
            }
        }
        let _ = c;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rogue_key_share_aborts() {
    let srv = server();
    let th = ths();
    let (_c, n) = session(Cheat::BadOpen, Cheat::None, th, &srv).await;
    assert!(matches!(n.ks, Err(Error::Abort(_))), "{:?}", n.ks);
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
    let (c, n) = tokio::join!(tokio::spawn(run(Role::C, io_c)), tokio::spawn(run(Role::N, io_n)));
    let (c, n) = (c.unwrap(), n.unwrap());
    let ks = reference(&srv, &c.0, th.0, th.1);
    assert_eq!(&n.1.c_hs, ks.client_hs.as_bytes());
    if let ApOut::N { k0, .. } = n.2 {
        assert_eq!(k0, ks.c_ap_0.key());
    } else {
        panic!()
    }
}
