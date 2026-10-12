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
