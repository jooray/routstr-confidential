//! Native == ZK property tests for all four statements, plus soundness
//! (single-bit mutation of a public input must fail verification).

use zkbench::fixtures;
use zkbench::proofs::run_pair_ideal;
use zkbench::statements::Params;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_n_native_eq_zk() {
    let (params, witness) = fixtures::pi_n();
    let results = run_pair_ideal(&params, &witness).await.expect("proof ok");
    assert!(results.iter().all(|r| r.ok), "{results:?}");
}

/// A π_N statement for an alphabet the fixed-size circuit does not implement
/// must fail to build, rather than silently proving the wrong alphabet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_n_rejects_unsupported_alphabet() {
    let (mut params, witness) = fixtures::pi_n();
    if let Params::PiN(p) = &mut params {
        p.key_alphabet = "[A-Z]".to_string();
    }
    let res = run_pair_ideal(&params, &witness).await;
    assert!(res.is_err(), "unsupported alphabet must fail, got {res:?}");
}

/// π_N for the supported alphabet still verifies (the alphabet is now an
/// explicit, checked proof parameter).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_n_accepts_supported_alphabet() {
    let (params, witness) = fixtures::pi_n();
    if let Params::PiN(p) = &params {
        assert_eq!(
            p.key_alphabet,
            zkbench::statements::SUPPORTED_KEY_ALPHABET
        );
    }
    let results = run_pair_ideal(&params, &witness).await.expect("proof ok");
    let alph = results.iter().find(|r| r.label == "key_alphabet").expect("check");
    assert!(alph.ok, "{results:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_c1_native_eq_zk() {
    let (params, witness) = fixtures::pi_c1();
    let results = run_pair_ideal(&params, &witness).await.expect("proof ok");
    assert!(results.iter().all(|r| r.ok), "{results:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_c2_native_eq_zk() {
    let (params, witness) = fixtures::pi_c2();
    let results = run_pair_ideal(&params, &witness).await.expect("proof ok");
    assert!(results.iter().all(|r| r.ok), "{results:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_c3_native_eq_zk() {
    let (params, witness) = fixtures::pi_c3();
    let results = run_pair_ideal(&params, &witness).await.expect("proof ok");
    assert!(results.iter().all(|r| r.ok), "{results:?}");
}

/// A single-bit mutation of a public input must make verification fail.
async fn mutation_fails(mut params: Params, witness: zkbench::Witness) {
    match &mut params {
        Params::PiC1(p) => p.s[3] ^= 1,
        Params::PiC2(p) => p.expected[0] ^= 1,
        Params::PiC3(p) => p.expected[0] ^= 1,
        Params::PiN(p) => p.c_commit[0] ^= 1,
    }
    let res = run_pair_ideal(&params, &witness).await;
    let ok = matches!(&res, Ok(rs) if rs.iter().all(|r| r.ok));
    assert!(!ok, "mutation must fail, got {res:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutations_fail() {
    for (_, params, witness) in fixtures::all() {
        mutation_fails(params, witness).await;
    }
}

#[test]
fn stats_are_sane() {
    for (_, params, _) in fixtures::all() {
        let s = zkbench::stats(&params);
        assert!(s.sha256_compressions >= 4);
        if !matches!(params, Params::PiN(_)) {
            assert!(s.aes_blocks >= 2);
        }
    }
}
