//! Malformed public parameters make a statement fail to build with an error,
//! on both sides, never panic: the parameters can come from the peer.

use std::panic::{AssertUnwindSafe, catch_unwind};

use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::memory::correlated::Delta;
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use zkbench::fixtures;
use zkbench::statements::{Params, Witness, build};
use zkbench::Role;

/// Build `params` on a fresh prover (with `witness`) and a fresh verifier.
/// Panics are caught and reported as such, so a regression names the case.
fn build_both(params: &Params, witness: Option<&Witness>) -> [Result<(), String>; 2] {
    let (ot_send, ot_recv) = ideal_rcot(Block::ZERO, Block::ONE);
    let mut prover = Prover::new(ProverConfig::default(), ot_recv);
    let mut verifier = Verifier::new(VerifierConfig::default(), Delta::new(Block::ONE), ot_send);
    let p = catch_unwind(AssertUnwindSafe(|| build(&mut prover, Role::Prover, params, witness)));
    let v = catch_unwind(AssertUnwindSafe(|| build(&mut verifier, Role::Verifier, params, None)));
    let flat = |r: std::thread::Result<anyhow::Result<_>>| match r {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("error: {e:#}")),
        Err(_) => Err("panic".to_string()),
    };
    [flat(p), flat(v)]
}

fn assert_rejected(case: &str, params: &Params, witness: Option<&Witness>) {
    for (side, r) in ["prover", "verifier"].iter().zip(build_both(params, witness)) {
        match r {
            Err(e) if e.starts_with("error:") => {}
            other => panic!("{case} ({side}): expected an error, got {other:?}"),
        }
    }
}

#[test]
fn honest_v1_params_build() {
    for (name, params, witness) in fixtures::all() {
        for (side, r) in ["prover", "verifier"].iter().zip(build_both(&params, Some(&witness))) {
            assert!(r.is_ok(), "{name} ({side}): {r:?}");
        }
    }
}

#[test]
fn pi_n_malformed_params_are_errors() {
    let (params, witness) = fixtures::pi_n();
    let Params::PiN(p) = params else { unreachable!() };
    let cases: Vec<(&str, Box<dyn Fn(&mut zkbench::statements::PiN)>)> = vec![
        ("template shorter than head_len", Box::new(|p| { p.template.pop(); })),
        ("head_len larger than template", Box::new(|p| p.head_len += 1)),
        ("fewer offsets than key bytes", Box::new(|p| { p.key_offsets.pop(); })),
        ("zero-length key", Box::new(|p| { p.key_len = 0; p.key_offsets.clear(); })),
        ("offset outside the head", Box::new(|p| p.key_offsets[0] = p.head_len)),
        ("duplicate offsets", Box::new(|p| p.key_offsets[1] = p.key_offsets[0])),
        ("keystream not |head|+1", Box::new(|p| { p.s.pop(); })),
    ];
    for (case, mutate) in cases {
        let mut q = p.clone();
        mutate(&mut q);
        assert_rejected(case, &Params::PiN(q), Some(&witness));
    }
    // A well-formed statement whose key length differs from the prover's key:
    // only the prover can tell, and it refuses.
    let mut q = p;
    q.key_len -= 1;
    q.key_offsets.pop();
    let [prover, _] = build_both(&Params::PiN(q), Some(&witness));
    assert!(matches!(&prover, Err(e) if e.starts_with("error:")), "{prover:?}");
}

#[test]
fn pi_c1_malformed_params_are_errors() {
    let (params, witness) = fixtures::pi_c1();
    let Params::PiC1(p) = params else { unreachable!() };
    let mut short = p.clone();
    short.s.truncate(short.s.len() - 20);
    assert_rejected("keystream shorter than head_len", &Params::PiC1(short), Some(&witness));
    let mut long = p.clone();
    long.head_len += 1;
    assert_rejected("head_len past the keystream", &Params::PiC1(long), Some(&witness));
    let mut empty = p;
    empty.head_len = 0;
    empty.s.clear();
    assert_rejected("empty record", &Params::PiC1(empty), Some(&witness));
}

#[test]
fn pi_c2_window_overflow_is_an_error() {
    let (params, witness) = fixtures::pi_c2();
    let Params::PiC2(mut p) = params else { unreachable!() };
    p.sel_start = usize::MAX;
    assert_rejected("sel_start + sel_len overflows", &Params::PiC2(p), Some(&witness));
}

#[test]
fn wrong_witness_kind_is_an_error() {
    let (params, _) = fixtures::pi_c1();
    let (_, key) = fixtures::pi_n();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let (_, ot_recv) = ideal_rcot(Block::ZERO, Block::ONE);
        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        build(&mut prover, Role::Prover, &params, Some(&key)).map(|_| ())
    }));
    assert!(matches!(r, Ok(Err(_))), "π_C1 with a key witness must be an error");
    let (params, _) = fixtures::pi_n();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let (_, ot_recv) = ideal_rcot(Block::ZERO, Block::ONE);
        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        build(&mut prover, Role::Prover, &params, None).map(|_| ())
    }));
    assert!(matches!(r, Ok(Err(_))), "π_N without a witness must be an error");
}
