//! End-to-end tests: correctness against cu-crypto's reference key schedule,
//! the hashes and the three-halves gate in isolation (with the vectors of
//! `crypto/conformance/twopc-hash-vectors.json`), the version tag, the
//! message order, the share conversion under deviations, and malicious-party
//! tests: each deviation of N must make C abort before any output of that
//! stage is used, with one message that looks the same whatever failed, and
//! C must not be able to change what N learns (the public `IS_k`, the
//! handshake secrets, K_0, the anchors) or evaluate a stage on another inner
//! digest than the one N labelled.
//!
//! Cheats that name a stage run once per stage (A1, A2, A3, B1, B2 = 0..5);
//! stages 0..3 belong to `handshake`, 3..5 to `application`.

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

fn reference_z(z: &[u8; 32], th_sh: [u8; 32], th_sf: [u8; 32]) -> KeySchedule {
    KeySchedule::from_handshake(hkdf_extract(&derived_es(), z), th_sh, th_sf)
}

/// The ECDHE x-coordinate of an honest run, big-endian.
fn true_z(server: &Server, joint: &[u8; 65]) -> [u8; 32] {
    let p = parse_point(joint).unwrap();
    let z = (p * server.b).to_affine().to_encoded_point(false);
    z.x().unwrap().as_slice().try_into().unwrap()
}

#[derive(Debug)]
struct Outcome {
    pre: Result<()>,
    ks: Result<[u8; 65]>,
    hs: Result<HsSecrets>,
    ap: Result<ApOut>,
    /// (step, bytes received) of every step that ran.
    recv: Vec<(&'static str, u64)>,
    /// The party's ECtF output (little-endian), if it ran.
    share: Option<[u8; 32]>,
}

fn skipped<T>() -> Result<T> {
    Err(Error::State("skipped"))
}

type Ths = ([u8; 32], [u8; 32]);

async fn session_v(cheat_c: Cheat, cheat_n: Cheat, c_th: Ths, n_th: Ths, srv: &Server) -> (Outcome, Outcome) {
    let (io_c, io_n) = emulated_pair(Duration::ZERO, f64::INFINITY);
    let share = srv.share;
    let run = move |role: Role, io, cheat: Cheat, th: Ths| async move {
        let mut p = Party::new(role, io).await.unwrap();
        p.cheat = cheat;
        let recv = |p: &mut Party| p.take_timings().iter().map(|t| (t.step, t.bytes_recv)).collect();
        let pre = p.preprocess().await;
        if pre.is_err() {
            return Outcome { pre, ks: skipped(), hs: skipped(), ap: skipped(), recv: recv(&mut p), share: None };
        }
        let ks = p.key_share().await;
        if ks.is_err() {
            return Outcome { pre, ks, hs: skipped(), ap: skipped(), recv: recv(&mut p), share: None };
        }
        let hs = p.handshake(&share, th.0).await;
        if hs.is_err() {
            return Outcome { pre, ks, hs, ap: skipped(), recv: recv(&mut p), share: p.ectf_share };
        }
        let ap = p.application(th.1).await;
        let recv = recv(&mut p);
        let share = p.ectf_share;
        p.close().await;
        Outcome { pre, ks, hs, ap, recv, share }
    };
    let c = tokio::spawn(run(Role::C, io_c, cheat_c, c_th));
    let n = tokio::spawn(run(Role::N, io_n, cheat_n, n_th));
    let (c, n) = tokio::join!(c, n);
    (c.unwrap(), n.unwrap())
}

async fn session(cheat_c: Cheat, cheat_n: Cheat, th: Ths, srv: &Server) -> (Outcome, Outcome) {
    session_v(cheat_c, cheat_n, th, th, srv).await
}

fn ths() -> Ths {
    let mut rng = os_rng();
    (rng.random(), rng.random())
}

fn check_honest(c: Outcome, n: Outcome, srv: &Server, th: Ths) {
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
    // The bare three-halves garbler/evaluator of this crate on the split
    // circuit, evaluated stage by stage.
    let sp = &*circuits::SPLIT;
    let mut rng = os_rng();
    let mut delta = Block::random(&mut rng);
    delta.set_lsb(true);
    let hg = gc::HashG::new(&rng.random());
    let n_in = sp.circ.inputs().len();
    let in_keys: Vec<Block> = (0..n_in).map(|_| Block::random(&mut rng)).collect();
    let (k, tables) = gc::garble(&sp.circ, &hg, delta, &in_keys, &mut rng);
    let input: Vec<bool> = (0..n_in).map(|_| rng.random()).collect();
    let in_l: Vec<Block> = input.iter().zip(&in_keys).map(|(b, k)| *k ^ sel(*b, delta)).collect();
    let l = gc::evaluate(&sp.circ, &hg, &in_l, &tables);
    let mut l2 = vec![Block::ZERO; sp.circ.feed_count()];
    l2[..n_in].copy_from_slice(&in_l);
    for sh in gc::stage_shapes(&sp.circ, &sp.gate_end) {
        gc::evaluate_range(&sp.circ, &hg, &mut l2, &tables, sh.gates.clone(), sh.ands.start);
    }
    assert_eq!(l, l2);
    let want = sp.circ.evaluate(input).unwrap();
    for (o, w) in sp.circ.outputs().zip(want) {
        assert_eq!(l[o], k[o] ^ sel(w, delta));
    }
}

#[test]
fn stage_rows_cover_every_and_input() {
    // The row wires of a stage: the wires entering it (C's and N's inputs,
    // the digest inputs, the wires crossing from earlier stages) and every
    // AND output of the stage. Every AND input of the stage must be a linear
    // combination of row wires of that stage.
    let sp = &*circuits::SPLIT;
    let shapes = gc::stage_shapes(&sp.circ, &sp.gate_end);
    let ands = gc::and_gates(&sp.circ);
    let n_in = sp.circ.inputs().len();
    let mut total = 0;
    for (s, sh) in shapes.iter().enumerate() {
        assert_eq!(sh.rows.len(), sh.entering + sh.ands.len());
        let mut lin = vec![false; sp.circ.feed_count()];
        for &w in &sh.rows[..sh.entering] {
            lin[w] = true;
        }
        for g in &sp.circ.gates()[sh.gates.clone()] {
            match g {
                mpz_circuits::Gate::Xor { x, y, z } => lin[z.id()] = lin[x.id()] && lin[y.id()],
                mpz_circuits::Gate::Inv { x, z } | mpz_circuits::Gate::Id { x, z } => lin[z.id()] = lin[x.id()],
                mpz_circuits::Gate::And { x, y, z } => {
                    assert!(lin[x.id()] && lin[y.id()], "stage {s}: an AND input is not covered");
                    lin[z.id()] = true;
                }
            }
        }
        for (k, &(_, _, o)) in ands[sh.ands.clone()].iter().enumerate() {
            assert_eq!(sh.rows[sh.entering + k], o);
        }
        // Every input wire of the stage has a row of its own: a label N
        // sends online that is not one of the wire's two labels changes the
        // check sum. (C's and N's x shares in A1, the digests later.)
        let entering = &sh.rows[..sh.entering];
        let mut inputs: Vec<usize> = sp.digs_of(s).iter().flat_map(|&j| sp.dig[j].clone()).collect();
        if s == 0 {
            inputs.extend(sp.xc.clone().chain(sp.xn.clone()));
        }
        for w in &inputs {
            assert!(entering.contains(w), "stage {s}: input wire {w} has no check row");
        }
        assert_eq!(entering.iter().filter(|&&w| w < n_in).count(), inputs.len(), "stage {s}");
        // Crossing wires: one OS_k (256) from the stage before; B2 also
        // takes s_ap_0 (for h2).
        let crossing = entering.iter().filter(|&&w| w >= n_in).count();
        assert_eq!(crossing, [0, 256, 256, 256, 512][s], "stage {s}");
        total += sh.rows.len();
        eprintln!("stage {s}: {} AND, {} entering wires ({crossing} crossing)", sh.ands.len(), sh.entering);
    }
    assert!(total < sp.circ.and_count() + 5000);
}

/// The outputs, their stage and who learns them, as the specification's
/// stage table has them; the reported ones get a label-check pair each.
#[test]
fn output_groups_are_as_specified() {
    use circuits::OutKind::*;
    let want = [
        ("IS_HS", 0, Pub, 256),
        ("c_hs", 1, Pub, 256),
        ("s_hs", 1, Pub, 256),
        ("IS_dHS", 1, Pub, 256),
        ("IS_MS", 2, Pub, 256),
        ("s_ap_0", 3, ToC, 256),
        ("IS_c0", 3, Pub, 256),
        ("c_ap_1", 4, ToC, 256),
        ("kiv", 4, ToN, 224),
        ("h1", 4, Pub, 256),
        ("h2", 4, Pub, 256),
        ("hk", 4, Pub, 256),
    ];
    let got: Vec<_> = circuits::SPLIT.outs.iter().map(|g| (g.name, g.stage, g.kind, g.len)).collect();
    assert_eq!(got, want);
    // 2 528 reported wires, one label-check pair each.
    assert_eq!(lay().n_pairs, 9 * 256 + 224);
    // Opened to C: its 256 input wires and the 9 × 256 digest wires.
    assert_eq!(lay().open_in.len(), 256 + 9 * 256);
}

#[test]
fn three_halves_gate_all_cases() {
    // Every permute-bit pair, every dicing pair, every colour pair: the
    // evaluator gets K0 ⊕ (a·b)·Δ. Also exercises the debug consistency
    // assertions of the garbler's linear system. Fresh hash parameters per
    // trial, the last trials with u1 = u2 = 0.
    let mut rng = os_rng();
    for trial in 0..64 {
        let mut hp: [u8; 32] = rng.random();
        if trial >= 60 {
            hp[16..].fill(0);
        }
        let hg = gc::HashG::new(&hp);
        let mut delta = Block::random(&mut rng);
        delta.set_lsb(true);
        for pa in [false, true] {
            for pb in [false, true] {
                for dice in 0..4u8 {
                    let mut a0 = Block::random(&mut rng);
                    a0.set_lsb(pa);
                    let mut b0 = Block::random(&mut rng);
                    b0.set_lsb(pb);
                    let gid = if trial == 63 { 479_021 } else { trial as u64 * 17 + dice as u64 };
                    let (k0, g) = gc::and_garble3(&hg, a0, b0, delta, gid, [dice & 1 == 1, dice & 2 == 2]);
                    for a in [false, true] {
                        for b in [false, true] {
                            let la = a0 ^ sel(a, delta);
                            let lb = b0 ^ sel(b, delta);
                            let out = gc::and_eval3(&hg, la, lb, &g, gid);
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
    let hg = gc::HashG::new(&rng.random());
    let mut delta = Block::random(&mut rng);
    delta.set_lsb(true);
    for pa in [false, true] {
        for pb in [false, true] {
            let mut hist = [0u32; 4];
            for gid in 0..4000u64 {
                let mut a0 = Block::random(&mut rng);
                a0.set_lsb(pa);
                let mut b0 = Block::random(&mut rng);
                b0.set_lsb(pb);
                let r: u8 = rng.random();
                let (_, g) = gc::and_garble3(&hg, a0, b0, delta, gid, [r & 1 == 1, r & 2 == 2]);
                // Evaluate on colours (0,0) and record the hash-independent part.
                let s = false;
                let t = false;
                let la = if pa { a0 ^ delta } else { a0 }; // colour 0
                let lb = if pb { b0 ^ delta } else { b0 };
                assert!(!la.lsb() && !lb.lsb());
                let uu = |x: Block| u128::from_le_bytes(x.to_bytes());
                let h = hg.h_many([uu(la), uu(lb), uu(la ^ lb)], [3 * gid, 3 * gid + 1, 3 * gid + 2]);
                let bit = |x: u128| (x >> 127) & 1 == 1;
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
    for _ in 0..3 {
        let srv = server();
        let th = ths();
        let (c, n) = session(Cheat::None, Cheat::None, th, &srv).await;
        check_honest(c, n, &srv, th);
    }
}

/// The version tag (spec §4): the first bytes on the transport in each
/// direction. A peer that sends anything else is refused with
/// `twopc_version_mismatch`, for either role, before any protocol message.
#[tokio::test(flavor = "multi_thread")]
async fn version_tag_first_and_mismatch_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;
    assert_eq!(VERSION_TAG, b"routstr-2pc/split-public-2\n");
    let v2_frame: &[u8] = &[1, 0, 0, 0, 16, 9, 9, 9];
    for role in [Role::C, Role::N] {
        // The previous variant (same length, last digit differs), another
        // name, a v2 multiplexer frame, the right text with the wrong end.
        for other in [
            &b"routstr-2pc/split-public-1\n"[..],
            &b"routstr-2pc/split-proven-1\n"[..],
            v2_frame,
            &b"routstr-2pc/split-public-2 "[..],
        ] {
            let (a, mut b) = tokio::io::duplex(1 << 16);
            b.write_all(other).await.unwrap();
            let r = Party::new(role, a.compat()).await;
            let e = r.err().expect("a peer with another tag is refused");
            assert!(matches!(e, Error::VersionMismatch(_)), "{e:?}");
            assert!(e.to_string().starts_with("twopc_version_mismatch: "), "{e}");
            assert!(e.to_string().starts_with(VERSION_MISMATCH));
            // This side's own first bytes are the tag, and nothing follows.
            let mut got = Vec::new();
            b.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, VERSION_TAG);
        }
        // The right tag is accepted (and counted as transport bytes).
        let (a, mut b) = tokio::io::duplex(1 << 16);
        b.write_all(VERSION_TAG).await.unwrap();
        let p = Party::new(role, a.compat()).await.unwrap();
        assert_eq!(p.counters().recv(), VERSION_TAG.len() as u64);
        assert_eq!(p.counters().sent(), VERSION_TAG.len() as u64);
    }
}

fn is_hs(stage: usize) -> bool {
    stage < HS_STAGES
}

fn c_err(c: &Outcome, stage: usize) -> String {
    let e = if is_hs(stage) { c.hs.as_ref().err() } else { c.ap.as_ref().err() };
    format!("{:?}", e.expect("C must fail"))
}

fn assert_c_aborts_with(c: &Outcome, n: &Outcome, stage: usize, what: &str) {
    assert_c_aborts_at(c, n, stage);
    let e = c_err(c, stage);
    assert!(e.contains(what), "stage {stage}: expected '{what}', got {e}");
}

/// C aborts in the call that runs `stage`, and N sees that abort there.
fn assert_c_aborts_at(c: &Outcome, n: &Outcome, stage: usize) {
    c.pre.as_ref().unwrap();
    assert!(c.ks.is_ok());
    if is_hs(stage) {
        assert!(matches!(c.hs, Err(Error::Abort(_))), "C must abort in stage {stage}: {:?}", c.hs);
        assert!(matches!(n.hs, Err(Error::Abort(_))), "N must see the abort: {:?}", n.hs);
    } else {
        assert!(c.hs.is_ok(), "{:?}", c.hs);
        assert!(matches!(c.ap, Err(Error::Abort(_))), "C must abort in stage {stage}: {:?}", c.ap);
        assert!(matches!(n.ap, Err(Error::Abort(_))), "N must see the abort: {:?}", n.ap);
    }
}

/// N rejects in `handshake` (`hs`) or `application` with `what`. `c_fails`:
/// C needed N's answer to go on, so it must fail in the same call (a C that
/// cheats in the last message of a call has its own outputs already, as in
/// v2; N's are what the test protects).
fn assert_n_rejects(c: &Outcome, n: &Outcome, hs: bool, what: &str, c_fails: bool) {
    let (rn, c_failed) = if hs {
        (n.hs.as_ref().err(), c.hs.is_err())
    } else {
        assert!(n.hs.is_ok(), "{:?}", n.hs);
        (n.ap.as_ref().err(), c.ap.is_err())
    };
    let e = format!("{:?}", rn.expect("N must fail"));
    assert!(matches!(rn, Some(Error::Abort(_))) && e.contains(what), "expected '{what}', got {e}");
    assert!(c_failed || !c_fails, "C must not get an output");
}

/// Runs `cheat(stage)` by N in every stage and expects C to abort with `what`.
async fn n_cheat_all_stages(cheat: fn(usize) -> Cheat, what: &str) {
    let srv = server();
    let th = ths();
    for stage in 0..N_STAGES {
        let (c, n) = session(Cheat::None, cheat(stage), th, &srv).await;
        assert_c_aborts_with(&c, &n, stage, what);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_garbled_table_detected_by_evaluator() {
    n_cheat_all_stages(Cheat::CorruptGate, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_control_bits_detected_by_evaluator() {
    // Three-halves specific: wrong dicing bits make the evaluator use the
    // wrong R matrix (a garbage label); the consistency check catches it.
    n_cheat_all_stages(Cheat::CorruptControlBits, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_check_rows_detected() {
    // 64-bit check rows: N perturbs every row (random 64-bit offsets).
    n_cheat_all_stages(Cheat::BadRows, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn check_rows_bound_to_session_seed() {
    // The 64-bit check rows are keyed by row parameters from C's challenge
    // seed; rows computed under a key from any other seed (e.g. precomputed
    // before the seed) fail.
    n_cheat_all_stages(Cheat::WrongRowKey, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn logic_change_and_to_nand_detected() {
    // N commits a flipped mask for one AND output: tables and all other
    // material are consistent with the flipped mask, so only the AND-gate
    // consistency check of that stage can catch it.
    n_cheat_all_stages(Cheat::FlipLambda, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_check_value_detected() {
    n_cheat_all_stages(Cheat::BadYn, "consistency check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_label_check_pair_detected() {
    // N's pair for one reported wire does not match the labels: C aborts
    // before it sends anything derived from its labels.
    n_cheat_all_stages(Cheat::BadPair, "output label check").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn inconsistent_label_check_pair_is_a_selective_abort() {
    // The pairs of a stage's first reported group are right for the bit 0
    // and wrong for the bit 1 (N expects labels that are not the wire's):
    // C aborts unless all 256 (224) pointer bits are 0, and tells N nothing
    // else: no pointer bit, no label hash.
    n_cheat_all_stages(Cheat::BadPairHalf, "output label check").await;
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
    for stage in 0..N_STAGES {
        let (c, _n) = session(Cheat::None, Cheat::LieOpen(stage), th, &srv).await;
        assert!(matches!(&c.pre, Err(Error::Abort(m)) if m.contains("opened masks")), "{:?}", c.pre);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lying_about_an_input_mask_detected() {
    // The masks C checks pointer bits against (its own input wires and the
    // digest input wires) are opened in preprocessing under their MACs. A
    // lie about one of them (it would let N pass the label of the other
    // digest bit) fails the MAC hash there, before any input exists.
    let srv = server();
    let th = ths();
    // C's first input wire; a wire of the first, of a middle and of the last
    // digest (d_c in A2, d_c0 in B1, d_upd in B2).
    for j in [0, 256, 256 + 4 * 256 + 17, 256 + 9 * 256 - 1] {
        let (c, _n) = session(Cheat::None, Cheat::LieOpenIn(j), th, &srv).await;
        assert!(matches!(&c.pre, Err(Error::Abort(m)) if m.contains("opened masks")), "{:?}", c.pre);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_garbler_input_label_detected() {
    // Stage 0: N's own input label (sent in preprocessing; no commitment, its
    // mask is not opened) is not a label: the consistency check catches it.
    // Later stages: N's label for a digest input is not one of the wire's two
    // labels (its pointer bit is right): it does not open N's commitment.
    let srv = server();
    let th = ths();
    for stage in 0..N_STAGES {
        let (c, n) = session(Cheat::None, Cheat::BadInputLabel(stage), th, &srv).await;
        assert_c_aborts_with(&c, &n, stage, if stage == 0 { "consistency check" } else { "input label" });
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn third_label_for_c_input_detected() {
    // A third label with the right pointer bit for C's first input wire, in
    // N's corrections: it does not open the commitment N made before the seed.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::BadInputLabelC, th, &srv).await;
    assert_c_aborts_with(&c, &n, 0, "does not open N's commitment");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_digest_label_from_garbler_detected() {
    // N hands C the label of the other bit value for a digest input (it
    // tries to run the stage on another inner digest than the right one):
    // the pointer bit does not match the opened mask and C's own digest.
    let srv = server();
    let th = ths();
    for stage in 1..N_STAGES {
        let (c, n) = session(Cheat::None, Cheat::FlipDigestLabel(stage), th, &srv).await;
        assert_c_aborts_with(&c, &n, stage, "pointer bits");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn labels_for_another_digest_detected() {
    // N sends valid labels, but of another inner digest: the digest of the
    // stage's next message block (in B2 that would put c_ap_1's digest on
    // the wires of K_0's, so that N's output is half of c_ap_1; in B1 it
    // would swap c_ap_0 and s_ap_0), or of a modified block where the stage
    // has one digest. C computed the digests itself and aborts.
    let srv = server();
    let th = ths();
    for stage in 1..N_STAGES {
        let (c, n) = session(Cheat::None, Cheat::OtherDigest(stage), th, &srv).await;
        assert_c_aborts_with(&c, &n, stage, "pointer bits");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_ot_correlation_detected() {
    // N runs the COTs for C's inputs with a Δ other than the garbling Δ.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::KosDelta, th, &srv).await;
    assert_c_aborts_at(&c, &n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn different_transcript_hash_detected() {
    // The transcript hashes enter the inner digests: N's digest labels do
    // not match the digests C computed over its own hash (pointer bits).
    let srv = server();
    let th = ths();
    let mut other_sh = th;
    other_sh.0[5] ^= 1;
    let mut other_sf = th;
    other_sf.1[31] ^= 0x80;
    let (c, n) = session_v(Cheat::None, Cheat::None, th, other_sh, &srv).await;
    assert_c_aborts_with(&c, &n, 1, "pointer bits");
    let (c, n) = session_v(Cheat::None, Cheat::None, th, other_sf, &srv).await;
    assert_c_aborts_with(&c, &n, 3, "pointer bits");
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_looks_the_same_whatever_failed() {
    // One observable outcome per stage: whichever of C's checks fails (the
    // pointer bits of N's digest labels, the consistency check, the label
    // check), N receives the same single byte at the same point, after C
    // evaluated the whole stage. N's view: the same error and the same
    // number of bytes received in that call.
    let srv = server();
    let th = ths();
    for (stage, step) in [(1, "phase_a"), (4, "phase_b")] {
        let mut views = Vec::new();
        for cheat in [
            Cheat::FlipDigestLabel(stage),
            Cheat::OtherDigest(stage),
            Cheat::BadInputLabel(stage),
            Cheat::CorruptGate(stage),
            Cheat::BadPair(stage),
            Cheat::BadPairHalf(stage),
        ] {
            let (c, n) = session(Cheat::None, cheat, th, &srv).await;
            assert_c_aborts_at(&c, &n, stage);
            let e = if is_hs(stage) { n.hs.err() } else { n.ap.err() };
            let bytes = n.recv.iter().find(|(s, _)| *s == step).expect("the step ran").1;
            views.push((format!("{:?}", e.unwrap()), bytes));
        }
        assert!(views.windows(2).all(|w| w[0] == w[1]), "stage {stage}: {views:?}");
        assert!(views[0].0.contains("peer aborted"), "{views:?}");
    }
}

/// The output groups C reports, with their stage.
const REPORTED: [(&str, usize); 10] = [
    ("IS_HS", 0),
    ("c_hs", 1),
    ("s_hs", 1),
    ("IS_dHS", 1),
    ("IS_MS", 2),
    ("IS_c0", 3),
    ("kiv", 4),
    ("h1", 4),
    ("h2", 4),
    ("hk", 4),
];

#[tokio::test(flavor = "multi_thread")]
async fn cheating_evaluator_cannot_misreport() {
    // C reports a flipped bit of a public inner state `IS_k` (N would label
    // the digests of a state C chose), of c_hs / s_hs, of N's K_0 ‖ IV_0 or
    // of an anchor. Without the inactive label it cannot authenticate it; N
    // rejects before it sends the next stage's labels.
    let srv = server();
    let th = ths();
    assert_eq!(
        REPORTED.to_vec(),
        (0..N_STAGES)
            .flat_map(|s| lay().reported(s).into_iter().map(move |gi| (lay().sp.outs[gi].name, s)))
            .collect::<Vec<_>>()
    );
    for (name, stage) in REPORTED {
        let (c, n) = session(Cheat::FlipReported(name), Cheat::None, th, &srv).await;
        // Except in the last stage of a call, C needs N's next labels.
        let c_needs_n = stage != HS_STAGES - 1 && stage != N_STAGES - 1;
        assert_n_rejects(&c, &n, is_hs(stage), "output labels", c_needs_n);
        if c_needs_n {
            let e = c_err(&c, stage);
            assert!(e.contains("N rejected"), "{name}: {e}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn evaluating_with_another_digest_rejected() {
    // C evaluates a stage with another label than the one N sent for a
    // digest input (C has one label per wire; the label of the other bit
    // needs Δ_A, so it can only guess), ignores its own checks and reports
    // what it computed: N's label hash fails.
    let srv = server();
    let th = ths();
    for stage in 1..N_STAGES {
        let (c, n) = session(Cheat::FeedOther(stage), Cheat::None, th, &srv).await;
        assert_n_rejects(&c, &n, is_hs(stage), "output labels", false);
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

// ------------------------------------------------------------ hashes --

fn h128(x: u128) -> String {
    format!("{x:032x}")
}

fn h64(x: u64) -> String {
    format!("{x:016x}")
}

fn ub(b: Block) -> u128 {
    u128::from_le_bytes(b.to_bytes())
}

fn bu(x: u128) -> Block {
    Block::new(x.to_le_bytes())
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// A field element from a big-endian hex integer.
fn fp_hex(s: &str) -> Fp {
    fp_from_be(&hex::decode(s).unwrap()).unwrap()
}

fn fp_be_hex(x: Fp) -> String {
    let mut le: [u8; 32] = x.into();
    le.reverse();
    hex::encode(le)
}

/// Bit-serial reference: carry-less product, then reduction by
/// x^64 = x^4 + x^3 + x + 1.
fn gf64_mul_ref(a: u64, b: u64) -> u64 {
    let mut p: u128 = 0;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            p ^= (a as u128) << i;
        }
    }
    for i in (64..128).rev() {
        if (p >> i) & 1 == 1 {
            p ^= (1u128 << i) ^ (0x1bu128 << (i - 64));
        }
    }
    p as u64
}

const HP1: &str = "000102030405060708090a0b0c0d0e0fefcdab896745230178695a4b3c2d1e0f";
const X: u128 = 0x00112233445566778899aabbccddeeff;
const SEED1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn hp2() -> [u8; 32] {
    Sha256::digest(b"routstr twopc vectors: hash parameters 2").into()
}

fn seed2() -> [u8; 32] {
    Sha256::digest(b"routstr twopc vectors: seed 2").into()
}

/// A 32-byte value from a label, with its top byte (big-endian) set to `top`
/// (so that the value is below p and its size is known).
fn fp_labelled(label: &str, top: u8) -> Fp {
    let mut be: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    be[0] = top;
    fp_from_be(&be).unwrap()
}

/// Every vector of `crypto/conformance/twopc-hash-vectors.json`. Integers
/// are hex, most significant digit first; byte strings are hex in order.
fn vectors() -> serde_json::Value {
    use serde_json::json;
    let hp1 = hex32(HP1);
    let hp2 = hp2();

    let pairs: [(u64, u64); 8] = [
        (0, 0x0123456789abcdef),
        (0x8000000000000000, 2),
        (0xffffffffffffffff, 0xffffffffffffffff),
        (0x0123456789abcdef, 0xfedcba9876543210),
        (1, 0xdeadbeefcafef00d),
        (0x1b, 0x8000000000000000),
        (2, 2),
        (0x9e3779b97f4a7c15, 0xc2b2ae3d27d4eb4f),
    ];
    let gf64: Vec<_> = pairs
        .iter()
        .map(|&(a, b)| json!({"a": h64(a), "b": h64(b), "product": h64(gc::gf64::mul(a, b))}))
        .collect();
    let xt: Vec<_> = [0x8000000000000000u64, 0x0123456789abcdef]
        .iter()
        .map(|&a| json!({"a": h64(a), "xtime": h64(gc::gf64::xtime(a))}))
        .collect();
    let sig: Vec<_> = [
        0x80000000000000000000000000000001u128,
        0x80000000000000008000000000000000,
        0,
        0x0123456789abcdeffedcba9876543210,
    ]
    .iter()
    .map(|&y| json!({"y": h128(y), "sigma": h128(gc::gf64::sigma(y))}))
    .collect();

    let mut hg_cases = Vec::new();
    for hp in [hp1, hp2] {
        let hg = gc::HashG::new(&hp);
        let u1 = u64::from_le_bytes(hp[16..24].try_into().unwrap());
        let u2 = u64::from_le_bytes(hp[24..32].try_into().unwrap());
        let um = gc::gf64::UMap::new(u1, u2);
        let aes = mpz_core::aes::AesEncryptor::new(Block::new(hp[..16].try_into().unwrap()));
        for (gid, slot) in [(0u64, 0u64), (5, 1), (479_021, 2)] {
            let tau = 3 * gid + slot;
            let y = X ^ um.at(tau);
            let out = aes.encrypt_block(bu(y));
            let h = hg.h(X, tau);
            assert_eq!(h, ub(out) ^ gc::gf64::sigma(y));
            hg_cases.push(json!({
                "hparams": hex::encode(hp), "x": h128(X), "gid": gid, "slot": slot, "tau": tau,
                "u": h128(um.at(tau)), "y": h128(y),
                "aes_in": hex::encode(bu(y).to_bytes()), "aes_out": hex::encode(out.to_bytes()),
                "h_g": h128(h), "half": h64(h as u64), "bit": (h >> 127) as u8,
            }));
        }
    }

    let mut rp_cases = Vec::new();
    let mut row_cases = Vec::new();
    for (seed, hp) in [(hex32(SEED1), hp1), (seed2(), hp2)] {
        let rp = row_params(&seed, &hp);
        rp_cases.push(json!({
            "seed": hex::encode(seed), "hparams": hex::encode(hp), "rparams": hex::encode(rp),
            "k_r": hex::encode(&rp[..16]),
            "u_r1": h64(u64::from_le_bytes(rp[16..24].try_into().unwrap())),
            "u_r2": h64(u64::from_le_bytes(rp[24..32].try_into().unwrap())),
        }));
        if hp != hp1 {
            continue;
        }
        let hg = gc::HashG::new(&hp);
        let rh = gc::RowHash::new(&hg, &rp);
        for (st, idx) in [(0usize, 0usize), (3, 70_000), (0, 70_000), (3, 0)] {
            let (inner, ur, ain, aout) = rh.trace(bu(X), st, idx);
            let tau = ((st as u64) << 32) | idx as u64;
            row_cases.push(json!({
                "hparams": hex::encode(hp), "rparams": hex::encode(rp), "x": h128(X),
                "stage": st, "idx": idx, "tau": h64(tau), "tau_row": h64(gc::ROW_TWEAK | tau),
                "h_g": h128(inner), "u_r": h128(ur), "aes_in": h128(ain), "aes_out": h128(aout),
                "row": h64(rh.row(bu(X), st, idx)),
            }));
        }
    }

    // One whole gate.
    let hg = gc::HashG::new(&hp1);
    let a0 = bu(X);
    let b0 = bu(0xfedcba98765432100f1e2d3c4b5a6979);
    let delta = bu(0x243f6a8885a308d313198a2e03707345);
    let (gid, dice) = (12_345u64, [true, false]);
    let (k0, g) = gc::and_garble3(&hg, a0, b0, delta, gid, dice);
    let mut evals = Vec::new();
    for (a, b) in [(false, false), (false, true), (true, false), (true, true)] {
        let la = a0 ^ sel(a, delta);
        let lb = b0 ^ sel(b, delta);
        let out = gc::and_eval3(&hg, la, lb, &g, gid);
        assert_eq!(out, k0 ^ sel(a & b, delta));
        evals.push(json!({"a": a as u8, "b": b as u8, "label_a": h128(ub(la)), "label_b": h128(ub(lb)), "out": h128(ub(out))}));
    }
    let gate = json!({
        "hparams": hex::encode(hp1), "a0": h128(ub(a0)), "b0": h128(ub(b0)), "delta": h128(ub(delta)),
        "gid": gid, "dice": [dice[0] as u8, dice[1] as u8],
        "k0": h128(ub(k0)), "g": [h64(g.g[0]), h64(g.g[1]), h64(g.g[2])], "z": g.z, "eval": evals,
    });

    let salt1: [u8; 16] = core::array::from_fn(|i| 0x40 + i as u8);
    let salt2: [u8; 16] = core::array::from_fn(|i| 0x50 + i as u8);
    let mut com_cases = Vec::new();
    for (salt, w, p, x) in [
        (salt1, 0usize, true, X),
        (salt1, 2815, false, X ^ 1),
        (salt2, 17, false, X ^ 1),
        (salt2, 512, true, X),
    ] {
        com_cases.push(json!({
            "in_salt": hex::encode(salt), "w": w, "p": p as u8, "label": hex::encode(bu(x).to_bytes()),
            "com": hex::encode(in_com(&salt, w, p, bu(x))),
        }));
    }

    let mut mi = Vec::new();
    let cases = [
        (
            fp_hex("ec84613b712fe298ab201ef439c561a99be471f2bc284379e063c8a9123786eb"),
            fp_hex("0ddbc6c1d81a078b803040a615f91362642e985d2737a945535b86da2681952f"),
            fp_hex("1de5ff44fea6e14e0a6af64e0a8459b395b6da4eb6564a134078f3ca3f81e9bd"),
        ),
        // x_N < ρ: δ wraps below 0.
        (fp_labelled("x_n 2", 0x01), fp_labelled("rho 2", 0xd0), fp_labelled("x_c 2", 0x42)),
        // x_C + δ ≥ p: C's sum wraps.
        (fp_labelled("x_n 3", 0xe0), fp_labelled("rho 3", 0x10), fp_labelled("x_c 3", 0xf0)),
    ];
    for (x_n, rho, x_c) in cases {
        let delta = x_n - rho;
        let x_c2 = x_c + delta;
        assert_eq!(fp_be_hex(x_c2 + rho), fp_be_hex(x_c + x_n));
        let d_le: [u8; 32] = delta.into();
        mi.push(json!({
            "x_n": fp_be_hex(x_n), "rho": fp_be_hex(rho), "delta": fp_be_hex(delta), "delta_le": hex::encode(d_le),
            "x_c": fp_be_hex(x_c), "x_c_prime": fp_be_hex(x_c2), "sum": fp_be_hex(x_c2 + rho),
        }));
    }

    json!({
        "description": "split-public-2: the garbling hash H_g, the check-row hash, the row parameters, one three-halves gate, the input-label commitments and the masked input",
        "conventions": "a 128-bit value is a u128 whose 16 bytes are little-endian; integers are hex, most significant digit first; byte strings are hex in order; GF(2^64) = GF(2)[x]/(x^64+x^4+x^3+x+1), bit i = coefficient of x^i; field elements are integers mod the P-256 prime",
        "xtime": xt,
        "gf64_mul": gf64,
        "sigma": sig,
        "h_g": hg_cases,
        "row_params": rp_cases,
        "row": row_cases,
        "gate": gate,
        "input_label_commitment": com_cases,
        "masked_input": mi,
    })
}

#[test]
fn gf64_arithmetic() {
    use gc::gf64::{mul, sigma, xtime};
    assert_eq!(xtime(0x8000000000000000), 0x1b);
    assert_eq!(mul(0xffffffffffffffff, 0xffffffffffffffff), 0x5555555555555513);
    assert_eq!(mul(0x0123456789abcdef, 0xfedcba9876543210), 0x48827ab55d976fa0);
    assert_eq!(mul(0, 0x0123456789abcdef), 0);
    assert_eq!(mul(0x8000000000000000, 2), 0x1b);
    assert_eq!(sigma(0x80000000000000000000000000000001), 0x000000000000001b0000000000000002);
    let mut rng = os_rng();
    for _ in 0..10_000 {
        let (a, b): (u64, u64) = (rng.random(), rng.random());
        assert_eq!(mul(a, b), gf64_mul_ref(a, b));
        assert_eq!(mul(a, 2), xtime(a));
        assert_eq!(mul(a, b), mul(b, a));
        let um = gc::gf64::UMap::new(a, b);
        let t: u64 = rng.random();
        assert_eq!(um.at(t), ((mul(a, t) as u128) << 64) | mul(b, t) as u128);
    }
    // x^(2^64) = x: 64 squarings of x.
    let mut v = 2u64;
    for _ in 0..64 {
        v = mul(v, v);
    }
    assert_eq!(v, 2);
}

#[test]
fn hash_g_and_row_hash_vectors() {
    // The cross-check values computed by an independent script.
    let hp1 = hex32(HP1);
    let hg = gc::HashG::new(&hp1);
    let h = hg.h(X, 0);
    assert_eq!(h, 0x4db48ee174ffe499ec7c0a0ee1985afe);
    let aes = mpz_core::aes::AesEncryptor::new(Block::new(hp1[..16].try_into().unwrap()));
    assert_eq!(hex::encode(bu(X).to_bytes()), "ffeeddccbbaa99887766554433221100");
    assert_eq!(hex::encode(aes.encrypt_block(bu(X)).to_bytes()), "1b872378795f4ffd772855fc87ca964d");
    let um = gc::gf64::UMap::new(0x0123456789abcdef, 0x0f1e2d3c4b5a6978);
    assert_eq!(um.at(16), 0x123456789abcdef0f1e2d3c4b5a69780);
    assert_eq!(hg.h(X, 16), 0x89714516773290286fb8dfff75afba7d);
    assert_eq!(hg.h(X, 16) >> 127, 1);
    assert_eq!(um.at(1_437_065), 0x3027fa4f03152a427d769842e4e4c235);
    assert_eq!(hg.h(X, 1_437_065), 0x17732667f079fc8c25c300f48fb2b850);
    assert_eq!(hg.h(X, 1_437_065) >> 127, 0);

    let rp = row_params(&hex32(SEED1), &hp1);
    assert_eq!(hex::encode(rp), "8ca93c8d10659702fca83b6bcf5486fca5e60c1a8ffe57551dba1e2c5395a41f");
    assert_eq!(u64::from_le_bytes(rp[16..24].try_into().unwrap()), 0x5557fe8f1a0ce6a5);
    assert_eq!(u64::from_le_bytes(rp[24..32].try_into().unwrap()), 0x1fa495532c1eba1d);
    let rh = gc::RowHash::new(&hg, &rp);
    assert_eq!(rh.row(bu(X), 0, 0), 0xdc7956767bd47e26);
    let inner = 0x7e299be3d86c2b81c4e40a55293043fa;
    assert_eq!(rh.trace(bu(X), 0, 0), (inner, 0, inner, 0x0eccedbc26d24057dc7956767bd47e26));
    assert_eq!(rh.row(bu(X), 3, 70_000), 0x3b5c2b5394fd4ca8);
    assert_eq!(
        rh.trace(bu(X), 3, 70_000),
        (
            0x08034b4806276ed131da5db121eb5eec,
            0x52f3d584460db5f4eb4e284b62155c7b,
            0x5af09ecc402adb25da9475fa43fe0297,
            0xbb6cf335be7053503b5c2b5394fd4ca8
        )
    );

    let salt: [u8; 16] = core::array::from_fn(|i| 0x40 + i as u8);
    assert_eq!(hex::encode(in_com(&salt, 0, true, bu(X))), "0fccf73249dc5a3283c8b11f03f299c9");
    assert_eq!(hex::encode(in_com(&salt, 2815, false, bu(X ^ 1))), "40bfa0806e2f8179092578ee0b39f8a7");

    let x_n = fp_hex("ec84613b712fe298ab201ef439c561a99be471f2bc284379e063c8a9123786eb");
    let rho = fp_hex("0ddbc6c1d81a078b803040a615f91362642e985d2737a945535b86da2681952f");
    let x_c = fp_hex("1de5ff44fea6e14e0a6af64e0a8459b395b6da4eb6564a134078f3ca3f81e9bd");
    let delta = x_n - rho;
    assert_eq!(fp_be_hex(delta), "dea89a799915db0d2aefde4e23cc4e4737b5d99594f09a348d0841ceebb5f1bc");
    let d_le: [u8; 32] = delta.into();
    assert_eq!(hex::encode(d_le), "bcf1b5ebce41088d349af09495d9b537474ecc234edeef2a0ddb1599799aa8de");
    assert_eq!(fp_be_hex(x_c + delta), "fc8e99be97bcbc5b355ad49c2e50a7facd6cb3e44b46e447cd8135992b37db79");
    assert_eq!(fp_be_hex(x_c + delta + rho), "0a6a60816fd6c3e5b58b15424449bb5d319b4c40727e8d8d20dcbc7351b970a9");
}

/// The conformance file is what this build computes. `TWOPC_WRITE_VECTORS=1`
/// (re)writes it.
#[test]
fn hash_vectors_match_conformance_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../conformance/twopc-hash-vectors.json");
    let mut want = serde_json::to_string_pretty(&vectors()).unwrap();
    want.push('\n');
    if std::env::var_os("TWOPC_WRITE_VECTORS").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let got = std::fs::read_to_string(&path).expect("conformance file (TWOPC_WRITE_VECTORS=1 writes it)");
    assert_eq!(got, want, "{} is stale", path.display());
    // The masked-input cases cover a wrapping δ and a wrapping sum.
    let v = vectors();
    let mi = v["masked_input"].as_array().unwrap();
    let int = |s: &serde_json::Value| u128::from_str_radix(&s.as_str().unwrap()[..32], 16).unwrap();
    assert!(int(&mi[1]["x_n"]) < int(&mi[1]["rho"]));
    let p_hi = 0xffffffff00000001000000000000000u128;
    assert!(int(&mi[2]["x_c"]) + int(&mi[2]["delta"]) > p_hi);
}

#[test]
fn different_hash_parameters_give_different_tables() {
    let mut rng = os_rng();
    let mut delta = Block::random(&mut rng);
    delta.set_lsb(true);
    let (a0, b0) = (Block::random(&mut rng), Block::random(&mut rng));
    let (h1, h2) = (gc::HashG::new(&rng.random()), gc::HashG::new(&rng.random()));
    for gid in [0u64, 1, 479_021] {
        let (k1, g1) = gc::and_garble3(&h1, a0, b0, delta, gid, [false, true]);
        let (k2, g2) = gc::and_garble3(&h2, a0, b0, delta, gid, [false, true]);
        assert_ne!(g1.g, g2.g);
        assert_ne!(k1, k2);
    }
}

#[test]
fn swapped_labels_fail_the_row_sum() {
    // The swap that left the salted row sum of `split-public-1` unchanged
    // for every salt: C holds the label of wire b' on wire b and that of b
    // on b'. With u1 = u2 = 0 (N's best case) the garbling hash ignores its
    // tweak, so the inner hashes of the swapped labels coincide across the
    // two wires and only the outer cipher, keyed by the seed after N
    // committed, separates them: whatever u_r N guessed, the sum changes.
    let mut rng = os_rng();
    let mut hp: [u8; 32] = rng.random();
    hp[16..].fill(0);
    let hg = gc::HashG::new(&hp);
    for _ in 0..500 {
        let rh = gc::RowHash::new(&hg, &rng.random());
        let (p, q) = (Block::random(&mut rng), Block::random(&mut rng));
        let s = rng.random_range(0..N_STAGES);
        let (i, j) = (rng.random_range(0..200_000usize), rng.random_range(200_000..400_000usize));
        assert_eq!(rh.trace(q, s, i).0, rh.trace(q, s, j).0, "u = 0: the inner hash ignores the tweak");
        let honest = rh.row(p, s, i) ^ rh.row(q, s, j);
        let swapped = rh.row(q, s, i) ^ rh.row(p, s, j);
        assert_ne!(honest, swapped);
    }
}

// ----------------------------------------------------- message order --

#[tokio::test(flavor = "multi_thread")]
async fn hparams_precede_tables() {
    // C reads exactly 32 bytes of hash parameters before any table byte: a
    // node that starts with the tables fails C's length check (no hang).
    let srv = server();
    let (c, n) = session(Cheat::None, Cheat::OmitHparams, ths(), &srv).await;
    let e = format!("{:?}", c.pre.as_ref().expect_err("C must fail"));
    assert!(e.contains("unexpected message length") && e.contains("expected 32"), "{e}");
    assert!(n.pre.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn gl_precedes_seed() {
    // C sends its seed only after N's input labels arrived: fed the
    // commitments where the labels belong, it fails without sending the
    // seed, and N, waiting for it, sees the transport close.
    let srv = server();
    let (c, n) = session(Cheat::None, Cheat::OmitGl, ths(), &srv).await;
    let e = format!("{:?}", c.pre.as_ref().expect_err("C must fail"));
    assert!(e.contains("unexpected message length") && e.contains("expected 4096"), "{e}");
    assert!(matches!(n.pre, Err(Error::Io(_))), "N must not get a seed: {:?}", n.pre);
}

#[tokio::test(flavor = "multi_thread")]
async fn in_com_precedes_seed() {
    let srv = server();
    let (c, n) = session(Cheat::None, Cheat::ShortInCom, ths(), &srv).await;
    let e = format!("{:?}", c.pre.as_ref().expect_err("C must fail"));
    assert!(e.contains("unexpected message length") && e.contains("expected 81920"), "{e}");
    assert!(matches!(n.pre, Err(Error::Io(_))), "N must not get a seed: {:?}", n.pre);
}

#[tokio::test(flavor = "multi_thread")]
async fn n_with_degenerate_hparams_completes() {
    // C applies no check to N's hash parameters: they protect only N.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::DegenerateHparams, th, &srv).await;
    check_honest(c, n, &srv, th);
}

#[tokio::test(flavor = "multi_thread")]
async fn delta_out_of_range_rejected() {
    let srv = server();
    let (c, n) = session(Cheat::None, Cheat::DeltaOutOfRange, ths(), &srv).await;
    assert!(matches!(&c.hs, Err(Error::Protocol(m)) if m.contains("δ is not below p")), "{:?}", c.hs);
    assert!(n.hs.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_input_commitment_is_a_selective_abort() {
    // A wrong commitment for the pointer bit 1 of one input wire: C aborts
    // in that wire's stage iff its label has pointer bit 1 (one predicate,
    // the stage's abort); otherwise the session is honest. C's input wire 3
    // (stage A1) and a wire of d_c (stage A2).
    let srv = server();
    let th = ths();
    for (j, stage) in [(3usize, 0usize), (256 + 10, 1)] {
        let (mut aborted, mut passed) = (0, 0);
        for _ in 0..16 {
            let (c, n) = session(Cheat::None, Cheat::BadInCom(j), th, &srv).await;
            if c.hs.is_ok() {
                check_honest(c, n, &srv, th);
                passed += 1;
            } else {
                assert_c_aborts_with(&c, &n, stage, "does not open N's commitment");
                aborted += 1;
            }
        }
        assert!(aborted > 0 && passed > 0, "wire {j}: {aborted} aborts, {passed} passes");
    }
}

// ------------------------------------------------- adder switch attack --

/// The planted NAND of `Cheat::AdderSwitch`: an AND gate of stage A1 well
/// after the first adder.
const ADDER_NAND: usize = 1000;

/// `gc::garble_dev` for the attack: the even gates 0, 2, …, 254 of the first
/// adder (their A input is C's bit, B is N's bit, both XOR the carry) become
/// `(¬A)∧B`, whose violation is `B` = N's bit while the carry is 0; gate
/// `ADDER_NAND` becomes a NAND (always violated).
pub(crate) fn adder_switch_gates(a: usize) -> (bool, bool) {
    (a < 255 && a % 2 == 0, a == ADDER_NAND)
}

/// After the seed: the input bits x_r (on bits 2r of N's input, the odd bits
/// 0) with Σ x_r·χ^(2r+1) = χ^(ADDER_NAND+1), so that the stage-A1 check sum
/// E = Σ_k χ^(k+1)·e_k vanishes when every switch sees a dead carry.
pub(crate) fn adder_switch_solution(chi0: Block) -> Zeroizing<[u8; 32]> {
    let pw: Vec<u128> = gc::powers(chi0, ADDER_NAND + 1).into_iter().map(ub).collect();
    // Gaussian elimination over GF(2): rows (vector, which x_r it combines).
    let mut basis: Vec<(u128, u128)> = Vec::new();
    for r in 0..128 {
        let (mut v, mut c) = (pw[2 * r], 1u128 << r);
        for &(bv, bc) in &basis {
            if v ^ bv < v {
                v ^= bv;
                c ^= bc;
            }
        }
        if v != 0 {
            basis.push((v, c));
            basis.sort_by(|a, b| b.0.cmp(&a.0));
        }
    }
    let (mut t, mut c) = (pw[ADDER_NAND], 0u128);
    for &(bv, bc) in &basis {
        if t ^ bv < t {
            t ^= bv;
            c ^= bc;
        }
    }
    assert_eq!(t, 0, "χ in a subfield: no solution");
    let mut v = [0u8; 32];
    for r in 0..128 {
        if (c >> r) & 1 == 1 {
            v[(2 * r) / 8] |= 1 << ((2 * r) % 8);
        }
    }
    Zeroizing::new(v)
}

#[tokio::test(flavor = "multi_thread")]
async fn adder_switch_attack_caught() {
    // N garbles the even adder gates as (¬A)∧B and plants a NAND later in
    // stage A1, then solves 128 linear equations over GF(2) for the input
    // bits that cancel the NAND in the check of stage A1 (the solution
    // depends on the challenge).
    let srv = server();
    let th = ths();
    let sp = &*circuits::SPLIT;
    let ands = gc::and_gates(&sp.circ);
    assert!(sp.xc.contains(&ands[0].0) && sp.xn.contains(&ands[0].1), "gate 0 is AND(x_C[0], x_N[0])");

    // The order of `split-public-1` (a test hook): N's input labels after
    // the seed, for the solution, and a C input whose carries die. The check
    // of stage A1 passes with a wrong evaluation in every run: the test can
    // see the attack.
    for _ in 0..3 {
        let (c, n) = session(Cheat::DeadCarries(true), Cheat::AdderSwitchLate, th, &srv).await;
        c.pre.as_ref().unwrap();
        n.pre.as_ref().unwrap();
        let joint = *c.ks.as_ref().unwrap();
        let hs = c.hs.as_ref().expect("old order: the check of stage A1 passes");
        let ks = reference(&srv, &joint, th.0, th.1);
        assert_ne!(&hs.c_hs, ks.client_hs.as_bytes(), "the evaluation is wrong");
    }
    // `split-public-2`: N's input labels (of ρ) were fixed before the seed,
    // so the solution can only go into δ. C aborts in stage A1 in every run,
    // with a uniform input and with the input of dead carries alike.
    for cheat_c in [Cheat::None, Cheat::DeadCarries(false)] {
        for _ in 0..3 {
            let (c, n) = session(cheat_c, Cheat::AdderSwitch, th, &srv).await;
            assert_c_aborts_with(&c, &n, 0, "consistency check");
        }
    }
}

// --------------------------------------------------------------- ECtF --

/// A uniform point a·S of P-256 and its coordinates.
fn ectf_point(s: &ProjectivePoint) -> (ProjectivePoint, Fp, Fp) {
    let a = random_scalar(&mut os_rng());
    let q = *s * a;
    let ep = q.to_affine().to_encoded_point(false);
    (q, fp_from_be(ep.x().unwrap()).unwrap(), fp_from_be(ep.y().unwrap()).unwrap())
}

fn x_of(p: &ProjectivePoint) -> Fp {
    fp_from_be(p.to_affine().to_encoded_point(false).x().unwrap()).unwrap()
}

type EctfOut = Result<(Fp, ectf::Trace)>;

/// One ECtF run, C on `qc`, N on `qn` with the deviations of `dev_n`; each
/// side in its own task, so that one side's error closes the transport for
/// the other. Returns both results and N's ROLE shares b.
async fn ectf_run(qc: (Fp, Fp), qn: (Fp, Fp), mut dev_n: ectf::Dev) -> (EctfOut, EctfOut, Vec<Fp>) {
    use tokio_util::compat::TokioAsyncReadCompatExt;
    let (a, b) = tokio::io::duplex(1 << 20);
    let mut rng = os_rng();
    let mut sc_c = ectf::Sc::new_sender(&mut rng);
    let mut sc_n = ectf::Sc::new_receiver(&mut rng);
    let c = tokio::spawn(async move {
        let mut ctx = Context::new_single_threaded(a.compat());
        sc_c.preprocess(&mut ctx).await?;
        let mut dev = ectf::Dev::default();
        let x = sc_c.point_add_x(&mut ctx, qc.0, qc.1, &mut dev).await?;
        Ok((x, dev.trace.unwrap()))
    });
    let n = tokio::spawn(async move {
        let mut ctx = Context::new_single_threaded(b.compat());
        let r = async {
            sc_n.preprocess(&mut ctx).await?;
            let x = sc_n.point_add_x(&mut ctx, qn.0, qn.1, &mut dev_n).await?;
            Ok((x, dev_n.trace.unwrap()))
        }
        .await;
        (r, sc_n.role_b())
    });
    let (c, n) = tokio::join!(c, n);
    let (n, b) = n.unwrap();
    (c.unwrap(), n, b)
}

fn bit(x: Fp, j: usize) -> bool {
    let le: [u8; 32] = x.into();
    (le[j / 8] >> (j % 8)) & 1 == 1
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_n_substitutes_its_point() {
    use mpz_fields::Field;
    // The conversion as a function: N's substituted inputs give
    // multiplicative shares of in_C + in_N' and additive shares of c_C·c_N.
    let s = ProjectivePoint::GENERATOR * random_scalar(&mut os_rng());
    for on_curve in [true, false] {
        let (_, x1, y1) = ectf_point(&s);
        let (qn, x2, y2) = ectf_point(&s);
        let (x2s, y2s) = if on_curve {
            let p = (qn + ProjectivePoint::GENERATOR).to_affine().to_encoded_point(false);
            (fp_from_be(p.x().unwrap()).unwrap(), fp_from_be(p.y().unwrap()).unwrap())
        } else {
            (x2 + Fp::one(), y2)
        };
        let (c, n, _) = ectf_run((x1, y1), (x2s, y2s), ectf::Dev::default()).await;
        let ((_, tc), (_, tn)) = (c.unwrap(), n.unwrap());
        assert_eq!(tc.m[0] * tn.m[0], y2s - y1);
        assert_eq!(tc.m[1] * tn.m[1], x2s - x1);
        assert_eq!(tc.d + tn.d, tc.c * tn.c);
    }
    // In a session: no error on C up to the end of stage A3, but the
    // handshake secrets are not those of the server's Z, so the server's
    // first record does not open.
    let srv = server();
    let th = ths();
    for on_curve in [true, false] {
        let (c, n) = session(Cheat::None, Cheat::EctfOtherPoint(on_curve), th, &srv).await;
        let hs = c.hs.as_ref().expect("C sees no error");
        assert!(n.hs.is_ok());
        let ks = reference(&srv, c.ks.as_ref().unwrap(), th.0, th.1);
        assert_ne!(&hs.s_hs, ks.server_hs.as_bytes());
        let rec = cu_crypto::aesgcm::gcm_seal(&ks.server_hs.key(), &ks.server_hs.iv(), 0, b"aad", b"server flight");
        let mine = cu_crypto::keyschedule::Secret::new(hs.s_hs);
        assert!(cu_crypto::aesgcm::gcm_open(&mine.key(), &mine.iv(), 0, b"aad", &rec).is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_n_zero_m2a_input() {
    let s = ProjectivePoint::GENERATOR * random_scalar(&mut os_rng());
    let (_, x1, y1) = ectf_point(&s);
    let (_, x2, y2) = ectf_point(&s);
    let dev = ectf::Dev { zero_c: true, ..Default::default() };
    let (c, n, _) = ectf_run((x1, y1), (x2, y2), dev).await;
    let ((sc, _), (_, tn)) = (c.unwrap(), n.unwrap());
    assert_eq!(sc, -tn.d - x1);
    // In a session: the outputs are those of Z' = x_C + x_N, not of Z, and C
    // does not abort.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::EctfZeroC, th, &srv).await;
    let hs = c.hs.as_ref().expect("C sees no error");
    let zp = fp_from_le(c.share.unwrap()) + fp_from_le(n.share.unwrap());
    let z2 = hex32(&fp_be_hex(zp));
    assert_eq!(&hs.c_hs, reference_z(&z2, th.0, th.1).client_hs.as_bytes());
    let z = true_z(&srv, c.ks.as_ref().unwrap());
    assert_ne!(z, z2);
}

fn fp_from_le(le: [u8; 32]) -> Fp {
    Fp::try_from(le).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_n_shifted_share() {
    use mpz_fields::Field;
    // N adds 1 to its share (in δ): the outputs are those of Z + 1.
    let srv = server();
    let th = ths();
    let (c, n) = session(Cheat::None, Cheat::EctfShift, th, &srv).await;
    let hs = c.hs.as_ref().expect("C sees no error");
    assert!(n.hs.is_ok());
    let z = fp_from_be(&true_z(&srv, c.ks.as_ref().unwrap())).unwrap();
    let z1 = hex32(&fp_be_hex(z + Fp::one()));
    assert_eq!(&hs.c_hs, reference_z(&z1, th.0, th.1).client_hs.as_bytes());
    let ks = reference(&srv, c.ks.as_ref().unwrap(), th.0, th.1);
    let rec = cu_crypto::aesgcm::gcm_seal(&ks.server_hs.key(), &ks.server_hs.iv(), 0, b"", b"server flight");
    let mine = cu_crypto::keyschedule::Secret::new(hs.s_hs);
    assert!(cu_crypto::aesgcm::gcm_open(&mine.key(), &mine.iv(), 0, b"", &rec).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_c_abort_is_not_n_selectable() {
    use mpz_fields::Field;
    // C's degenerate-share abort depends on C's own randomness only: over
    // 200 runs with random deviations of N, C never sees it.
    let s = ProjectivePoint::GENERATOR * random_scalar(&mut os_rng());
    let mut rng = os_rng();
    for i in 0..200 {
        let (_, x1, y1) = ectf_point(&s);
        let (qn, x2, y2) = ectf_point(&s);
        let mut dev = ectf::Dev::default();
        let q = match rng.random_range(0..3) {
            0 => {
                let p = (qn + ProjectivePoint::GENERATOR).to_affine().to_encoded_point(false);
                (fp_from_be(p.x().unwrap()).unwrap(), fp_from_be(p.y().unwrap()).unwrap())
            }
            1 => (x2 + Fp::one(), y2),
            _ => {
                dev.zero_c = true;
                (x2, y2)
            }
        };
        let (c, n, _) = ectf_run((x1, y1), q, dev).await;
        assert!(c.is_ok(), "run {i}: {:?}", c.err());
        assert!(n.is_ok(), "run {i}: {:?}", n.err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_c_inconsistent_masks() {
    // C sends one correlation of the second A2M with a_j ≠ a: N's share is
    // right iff its ROT bit δ_j is 0 and wrong (the handshake would fail)
    // otherwise; no error, no other outcome.
    let s = ProjectivePoint::GENERATOR * random_scalar(&mut os_rng());
    let (mut ones, runs) = (0, 32);
    for _ in 0..runs {
        let (qc, x1, y1) = ectf_point(&s);
        let (qn, x2, y2) = ectf_point(&s);
        let w = fp_from_le(*random_fp_le(&mut os_rng()));
        let dev = ectf::Dev { c_masks: Some(ectf::lab::CMasks { j: 7, w, force: false }), ..Default::default() };
        let (c, n, b) = ectf_run((x1, y1), (x2, y2), dev).await;
        let ((sc, _), (sn, _)) = (c.unwrap(), n.unwrap());
        let dj = bit(b[1], 7);
        ones += dj as usize;
        assert_eq!(sc + sn == x_of(&(qc + qn)), !dj);
    }
    assert!((4..=28).contains(&ones), "δ_j = 1 in {ones} of {runs} runs");
}

#[tokio::test(flavor = "multi_thread")]
async fn ectf_c_forces_degenerate_share() {
    // C makes N's second A2M share 2^j·δ_j·w: N fails with "degenerate share"
    // iff δ_j = 0, and otherwise completes with a wrong share.
    let s = ProjectivePoint::GENERATOR * random_scalar(&mut os_rng());
    let (mut aborts, runs) = (0, 32);
    for _ in 0..runs {
        let (qc, x1, y1) = ectf_point(&s);
        let (qn, x2, y2) = ectf_point(&s);
        let w = fp_from_le(*random_fp_le(&mut os_rng()));
        let dev = ectf::Dev { c_masks: Some(ectf::lab::CMasks { j: 7, w, force: true }), ..Default::default() };
        let (c, n, b) = ectf_run((x1, y1), (x2, y2), dev).await;
        let dj = bit(b[1], 7);
        match n {
            Err(e) => {
                assert!(!dj);
                assert_eq!(e.to_string(), "protocol: ectf: degenerate share");
                aborts += 1;
            }
            Ok((sn, _)) => {
                assert!(dj);
                let (sc, _) = c.unwrap();
                assert_ne!(sc + sn, x_of(&(qc + qn)));
            }
        }
    }
    assert!((4..=28).contains(&aborts), "{aborts} aborts in {runs} runs");
}
