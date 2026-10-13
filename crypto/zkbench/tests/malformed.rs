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
fn honest_params_build() {
    for (name, params, witness) in fixtures::all() {
        for (side, r) in ["prover", "verifier"].iter().zip(build_both(&params, Some(&witness))) {
            assert!(r.is_ok(), "{name} ({side}): {r:?}");
        }
    }
}

#[test]
fn pi_nk_malformed_params_are_errors() {
    let (params, witness) = fixtures::pi_nk();
    let Params::PiNK(p) = params else { unreachable!() };
    let cases: Vec<(&str, Box<dyn Fn(&mut zkbench::statements::PiNK)>)> = vec![
        ("template shorter than head_len", Box::new(|p| { p.template.pop(); })),
        ("head_len larger than template", Box::new(|p| p.head_len += 1)),
        ("fewer offsets than key bytes", Box::new(|p| { p.key_offsets.pop(); })),
        ("zero-length key", Box::new(|p| { p.key_len = 0; p.key_offsets.clear(); })),
        ("offset outside the head", Box::new(|p| p.key_offsets[0] = p.head_len)),
        ("duplicate offsets", Box::new(|p| p.key_offsets[1] = p.key_offsets[0])),
        ("unsupported alphabet", Box::new(|p| p.key_alphabet = "[A-Z]".into())),
    ];
    for (case, mutate) in cases {
        let mut q = p.clone();
        mutate(&mut q);
        assert_rejected(case, &Params::PiNK(q), Some(&witness));
    }
    // A well-formed statement whose key length differs from the prover's key:
    // only the prover can tell, and it refuses.
    let mut q = p;
    q.key_len -= 1;
    q.key_offsets.pop();
    let [prover, _] = build_both(&Params::PiNK(q), Some(&witness));
    assert!(matches!(&prover, Err(e) if e.starts_with("error:")), "{prover:?}");
}

#[test]
fn pi_c2s_window_overflow_is_an_error() {
    let (params, witness) = fixtures::pi_c2s();
    let Params::PiC2S(mut p) = params else { unreachable!() };
    p.sel_start = usize::MAX;
    assert_rejected("sel_start + sel_len overflows", &Params::PiC2S(p), Some(&witness));
}

#[test]
fn wrong_witness_kind_is_an_error() {
    let (params, _) = fixtures::pi_c2s();
    let (_, key) = fixtures::pi_nk();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let (_, ot_recv) = ideal_rcot(Block::ZERO, Block::ONE);
        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        build(&mut prover, Role::Prover, &params, Some(&key)).map(|_| ())
    }));
    assert!(matches!(r, Ok(Err(_))), "π_C2S with a node-key witness must be an error");
    let (params, _) = fixtures::pi_nk();
    let r = catch_unwind(AssertUnwindSafe(|| {
        let (_, ot_recv) = ideal_rcot(Block::ZERO, Block::ONE);
        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        build(&mut prover, Role::Prover, &params, None).map(|_| ())
    }));
    assert!(matches!(r, Ok(Err(_))), "π_NK without a witness must be an error");
}

#[test]
fn pi_c2s_sel_len_mismatch_is_an_error() {
    let (params, witness) = fixtures::pi_c2s();
    let Params::PiC2S(mut p) = params else { unreachable!() };
    p.sel_len -= 1;
    assert_rejected("sel_len != |expected|", &Params::PiC2S(p), Some(&witness));
}

#[test]
fn pi_c3s_malformed_params_are_errors() {
    use zkbench::statements::{MAX_INNER_PLAINTEXT, MAX_SERVER_KEY_UPDATES, PiC3S};
    let (params, witness) = fixtures::pi_c3s_records(&[300, 600]);
    let Params::PiC3S(p) = params else { unreachable!() };
    let cases: Vec<(&str, Box<dyn Fn(&mut PiC3S)>)> = vec![
        ("no records", Box::new(|p| p.records.clear())),
        ("empty R", Box::new(|p| p.expected.clear())),
        ("too many KeyUpdates", Box::new(|p| p.key_updates = MAX_SERVER_KEY_UPDATES + 1)),
        ("a later record at an offset", Box::new(|p| p.records[1].off = 16)),
        ("first offset not block-aligned", Box::new(|p| p.records[0].off = 8)),
        ("a record without content", Box::new(|p| p.records[0].ct.truncate(1))),
        ("a record past the TLS limit", Box::new(|p| p.records[0].off = MAX_INNER_PLAINTEXT)),
        ("offset overflows", Box::new(|p| p.records[0].off = usize::MAX - 15)),
        ("records do not cover R plus skip", Box::new(|p| p.skip = 900)),
        ("skip overflows", Box::new(|p| p.skip = usize::MAX)),
    ];
    for (case, mutate) in cases {
        let mut q = p.clone();
        mutate(&mut q);
        assert_rejected(case, &Params::PiC3S(q), Some(&witness));
    }
}

#[test]
fn pi_c3s_record_count_is_capped() {
    use zkbench::statements::MAX_C3S_RECORDS;
    // Short records: the count, not the bytes, is what is refused.
    let mut lens = vec![40; MAX_C3S_RECORDS];
    lens[MAX_C3S_RECORDS - 1] = 120;
    let (params, witness) = fixtures::pi_c3s_records(&lens);
    for (side, r) in ["prover", "verifier"].iter().zip(build_both(&params, Some(&witness))) {
        assert!(r.is_ok(), "{MAX_C3S_RECORDS} records ({side}): {r:?}");
    }
    lens.insert(0, 40);
    let (params, witness) = fixtures::pi_c3s_records(&lens);
    for r in build_both(&params, Some(&witness)) {
        assert!(matches!(&r, Err(e) if e.contains("records (limit")), "{r:?}");
    }
}

#[test]
fn pi_c3s_aggregate_bytes_are_capped() {
    use zkbench::statements::MAX_C3S_BYTES;
    // Records of 16 KiB content (16385 ciphertext bytes with the content
    // type), plus a last one that lands exactly on the limit.
    let full = 1 << 14;
    let n = MAX_C3S_BYTES / (full + 1);
    let mut lens = vec![full; n];
    lens.push(MAX_C3S_BYTES - n * (full + 1) - 1);
    let (params, witness) = fixtures::pi_c3s_records(&lens);
    let Params::PiC3S(p) = &params else { unreachable!() };
    assert_eq!(p.records.iter().map(|r| r.ct.len()).sum::<usize>(), MAX_C3S_BYTES);
    for (side, r) in ["prover", "verifier"].iter().zip(build_both(&params, Some(&witness))) {
        assert!(r.is_ok(), "exactly at the limit ({side}): {r:?}");
    }
    *lens.last_mut().unwrap() += 1;
    let (params, witness) = fixtures::pi_c3s_records(&lens);
    for r in build_both(&params, Some(&witness)) {
        assert!(matches!(&r, Err(e) if e.contains("ciphertext bytes in all")), "{r:?}");
    }
}

#[test]
fn witness_debug_is_redacted() {
    let (_, nk) = fixtures::pi_nk();
    let (_, c3s) = fixtures::pi_c3s();
    assert_eq!(format!("{c3s:?}"), "Witness::Secret(<redacted>)");
    assert_eq!(format!("{nk:?}"), "Witness::NodeKey { <redacted>, key_len: 42 }");
}

#[test]
fn largest_honest_disclosures_fit_the_caps() {
    use zkbench::statements::{MAX_C3S_BYTES, MAX_C3S_NEED, MAX_C3S_RECORDS};
    let build_ok = |case: &str, total: usize, record_len: usize, r_len: usize, skip: usize| {
        let (params, witness) = fixtures::pi_c3s_disclosure(total, record_len, r_len, skip);
        let Params::PiC3S(p) = &params else { unreachable!() };
        let bytes: usize = p.records.iter().map(|r| r.ct.len()).sum();
        assert!(p.records.len() <= MAX_C3S_RECORDS && bytes <= MAX_C3S_BYTES, "{case}: {} records, {bytes} bytes", p.records.len());
        for (side, r) in ["prover", "verifier"].iter().zip(build_both(&params, Some(&witness))) {
            assert!(r.is_ok(), "{case} ({side}): {r:?}");
        }
    };
    // A usage event as large as the sidecar accepts (16 KiB), in full-size
    // records, at every block alignment of the first covered record.
    for k in 0..16 {
        build_ok("16 KiB usage R", 300_000 + k, 1 << 14, 16 << 10, 0);
    }
    // An error head of 16 KiB plus as large a body as always fits.
    for k in 0..16 {
        build_ok("16 KiB head + body", 300_000 + k, 1 << 14, 16 << 10, MAX_C3S_NEED - (16 << 10));
    }
    // A short head and the largest body, in small records (most records).
    let small = MAX_C3S_NEED.div_ceil(MAX_C3S_RECORDS - 1);
    for k in 0..16 {
        build_ok("short head, many records", 200_000 + k, small, 600, MAX_C3S_NEED - 600);
    }
}
