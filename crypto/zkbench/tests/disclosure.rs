//! π_C2/π_C3 reveal one bit: the verifier learns *whether* the decrypted
//! range equals the public expected bytes, never the plaintext itself. A
//! verifier that picks another window learns nothing else.

use zkbench::fixtures;
use zkbench::proofs::run_pair_ideal;
use zkbench::statements::Params;

fn only_bit(got: &str) -> bool {
    got == "01" || got == "00"
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_suffix_and_usage_prove_with_one_bit() {
    for (params, witness) in [fixtures::pi_c2(), fixtures::pi_c3()] {
        let res = run_pair_ideal(&params, &witness).await.unwrap();
        assert!(res.iter().all(|r| r.ok), "{res:?}");
        let last = res.last().unwrap();
        assert_eq!(last.got, "01", "decoded value must be the equality bit");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_chosen_window_reveals_no_plaintext() {
    // The record is 400 × 'x' then the suffix. A malicious verifier moves the
    // window onto the private 'x' bytes while keeping the expected suffix.
    let (params, witness) = fixtures::pi_c2_after(400);
    let Params::PiC2(mut p) = params else { unreachable!() };
    p.sel_start = 0;
    let res = run_pair_ideal(&Params::PiC2(p), &witness).await;
    if let Ok(res) = res {
        let last = res.last().unwrap();
        assert!(!last.ok);
        assert!(only_bit(&last.got), "leaked bytes: {}", last.got);
        assert!(!last.got.contains("78"), "plaintext 'x' bytes decoded");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usage_disclosure_wrong_expected_fails_with_one_bit() {
    let (params, witness) = fixtures::pi_c3();
    let Params::PiC3(mut p) = params else { unreachable!() };
    // Claim a different R of the same length: the check fails, and the
    // verifier still sees only the bit.
    let n = p.expected.len();
    p.expected = vec![b'y'; n];
    let res = run_pair_ideal(&Params::PiC3(p), &witness).await.unwrap();
    let last = res.last().unwrap();
    assert!(!last.ok);
    assert_eq!(last.got, "00");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_head_with_skip_proves_without_the_body() {
    // The fixture's record content is 500 × 'y' followed by R. Treat the first
    // 40 bytes of R as the "head" and the rest as the undisclosed body.
    let (params, witness) = fixtures::pi_c3();
    let Params::PiC3(mut p) = params else { unreachable!() };
    let r = p.expected.clone();
    p.expected = r[..40].to_vec();
    p.skip = r.len() - 40;
    let res = run_pair_ideal(&Params::PiC3(p.clone()), &witness).await.unwrap();
    assert!(res.iter().all(|x| x.ok), "{res:?}");
    // A skip that points elsewhere fails.
    p.skip += 1;
    let res = run_pair_ideal(&Params::PiC3(p), &witness).await.unwrap();
    assert!(!res.last().unwrap().ok);
}
