//! End-to-end tests: correctness against cu-crypto's reference key schedule,
//! the three-halves gate in isolation, the version tag, and malicious-party
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

#[derive(Debug)]
struct Outcome {
    pre: Result<()>,
    ks: Result<[u8; 65]>,
    hs: Result<HsSecrets>,
    ap: Result<ApOut>,
    /// (step, bytes received) of every step that ran.
    recv: Vec<(&'static str, u64)>,
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
            return Outcome { pre, ks: skipped(), hs: skipped(), ap: skipped(), recv: recv(&mut p) };
        }
        let ks = p.key_share().await;
        if ks.is_err() {
            return Outcome { pre, ks, hs: skipped(), ap: skipped(), recv: recv(&mut p) };
        }
        let hs = p.handshake(&share, th.0).await;
        if hs.is_err() {
            return Outcome { pre, ks, hs, ap: skipped(), recv: recv(&mut p) };
        }
        let ap = p.application(th.1).await;
        let recv = recv(&mut p);
        p.close().await;
        Outcome { pre, ks, hs, ap, recv }
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
    let n_in = sp.circ.inputs().len();
    let in_keys: Vec<Block> = (0..n_in).map(|_| Block::random(&mut rng)).collect();
    let (k, tables) = gc::garble(&sp.circ, delta, &in_keys, 0, &mut rng);
    let input: Vec<bool> = (0..n_in).map(|_| rng.random()).collect();
    let in_l: Vec<Block> = input.iter().zip(&in_keys).map(|(b, k)| *k ^ sel(*b, delta)).collect();
    let l = gc::evaluate(&sp.circ, &in_l, &tables, 0);
    let mut l2 = vec![Block::ZERO; sp.circ.feed_count()];
    l2[..n_in].copy_from_slice(&in_l);
    for sh in gc::stage_shapes(&sp.circ, &sp.gate_end) {
        gc::evaluate_range(&sp.circ, &mut l2, &tables, sh.gates.clone(), sh.ands.start, 0);
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
    assert_eq!(VERSION_TAG, b"routstr-2pc/split-public-1\n");
    let v2_frame: &[u8] = &[1, 0, 0, 0, 16, 9, 9, 9];
    for role in [Role::C, Role::N] {
        for other in [&b"routstr-2pc/split-proven-1\n"[..], v2_frame, &b"routstr-2pc/split-public-1 "[..]] {
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
async fn check_rows_bound_to_session_salt() {
    // The 64-bit check rows are keyed by a salt from C's challenge seed; rows
    // computed under any other salt (e.g. precomputed before the seed) fail.
    n_cheat_all_stages(Cheat::WrongSalt, "consistency check").await;
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
    // Stage 0: N's own input label is not a label. Later stages: N's label
    // for a digest input is not one of the wire's two labels (its pointer
    // bit is right, so only the consistency check can catch it).
    let srv = server();
    let th = ths();
    for stage in 0..N_STAGES {
        let (c, n) = session(Cheat::None, Cheat::BadInputLabel(stage), th, &srv).await;
        assert_c_aborts_with(&c, &n, stage, "consistency check");
    }
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
