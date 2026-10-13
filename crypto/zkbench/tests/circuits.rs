//! Soundness of every statement: a single-bit mutation of a public input must
//! fail verification. Plus the analytic statistics.

use zkbench::fixtures;
use zkbench::proofs::run_pair_ideal;
use zkbench::statements::Params;

/// A single-bit mutation of a public input must make verification fail.
async fn mutation_fails(mut params: Params, witness: zkbench::Witness) {
    match &mut params {
        Params::PiNK(p) => p.c_commit[0] ^= 1,
        Params::PiC2S(p) => p.expected[0] ^= 1,
        Params::PiC3S(p) => p.expected[0] ^= 1,
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
        assert!(s.aes_blocks >= 2);
    }
}

#[test]
fn circuit_cache_is_bounded() {
    use zkbench::gadgets::{
        CIRCUIT_CACHE_MAX_ENTRIES, CIRCUIT_CACHE_MAX_GATES, circuit_cache_usage, concat_circuit, select_circuit,
    };
    let within = || {
        let (entries, gates) = circuit_cache_usage();
        assert!(entries <= CIRCUIT_CACHE_MAX_ENTRIES && gates <= CIRCUIT_CACHE_MAX_GATES, "{entries} / {gates}");
    };
    // Many distinct per-session shapes (as response lengths would produce).
    for n in 0..2 * CIRCUIT_CACHE_MAX_ENTRIES {
        let c = select_circuit(64 + n, n % 64, 32);
        assert_eq!(c.gates().len(), 32 * 8);
        within();
    }
    // Large ones: the gate budget, not the entry count, bounds them.
    for n in 0..64 {
        let c = concat_circuit(&[4096 + n, 4096]);
        assert_eq!(c.gates().len(), (8192 + n) * 8);
        within();
    }
    // A circuit bigger than the whole budget is built but never cached.
    let big = CIRCUIT_CACHE_MAX_GATES / 8 + 1;
    assert_eq!(concat_circuit(&[big]).gates().len(), big * 8);
    within();
    // After eviction a shape is rebuilt identically.
    let a = select_circuit(100, 3, 7);
    for n in 0..CIRCUIT_CACHE_MAX_ENTRIES {
        select_circuit(200 + n, 0, 1);
    }
    let b = select_circuit(100, 3, 7);
    assert_eq!(format!("{:?}", a.gates()), format!("{:?}", b.gates()));
}
