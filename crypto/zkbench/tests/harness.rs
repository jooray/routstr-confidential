//! Sanity check of the mpz VOLE-ZK driver pattern used by `zkbench::run_io`.
//! Mirrors mpz's own `test_zk` but with the two sides on separate tasks over a
//! tokio duplex, which is how zkbench runs them.

use mpz_circuits::AES128;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{
    Call, Execute,
    memory::{
        Array,
        binary::U8,
        correlated::Delta,
    },
    prelude::*,
};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use rand::RngExt;
use tokio_util::compat::TokioAsyncReadCompatExt;

fn delta_and_seeds() -> (Delta, Block, Block) {
    let mut rng = rand::rng();
    (Delta::random(&mut rng), rng.random(), rng.random())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zk_driver_smoke() {
    let (delta, s1, s2) = delta_and_seeds();
    let (ot_send, ot_recv) = ideal_rcot(s1, delta.into_inner());

    let mut prover = Prover::new(ProverConfig::default(), ot_recv);
    let mut verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

    let (ep_p, ep_v) = tokio::io::duplex(1 << 20);
    let mut ctx_p = Context::new_single_threaded(ep_p.compat());
    let mut ctx_v = Context::new_single_threaded(ep_v.compat());
    let _ = s2;

    let pt = tokio::spawn(async move {
        let key: Array<U8, 16> = prover.alloc().unwrap();
        let msg: Array<U8, 16> = prover.alloc().unwrap();
        let ct: Array<U8, 16> = prover
            .call(Call::builder(AES128.clone()).arg(key).arg(msg).build().unwrap())
            .unwrap();
        prover.mark_private(key).unwrap();
        prover.mark_public(msg).unwrap();
        prover.assign(key, [0u8; 16]).unwrap();
        prover.assign(msg, [42u8; 16]).unwrap();
        prover.commit(key).unwrap();
        prover.commit(msg).unwrap();
        let mut out = prover.decode(ct).unwrap();
        prover.execute_all(&mut ctx_p).await.unwrap();
        out.try_recv().unwrap().unwrap()
    });

    let vt = tokio::spawn(async move {
        let key: Array<U8, 16> = verifier.alloc().unwrap();
        let msg: Array<U8, 16> = verifier.alloc().unwrap();
        let ct: Array<U8, 16> = verifier
            .call(Call::builder(AES128.clone()).arg(key).arg(msg).build().unwrap())
            .unwrap();
        verifier.mark_blind(key).unwrap();
        verifier.mark_public(msg).unwrap();
        verifier.assign(msg, [42u8; 16]).unwrap();
        verifier.commit(key).unwrap();
        verifier.commit(msg).unwrap();
        let mut out = verifier.decode(ct).unwrap();
        verifier.execute_all(&mut ctx_v).await.unwrap();
        out.try_recv().unwrap().unwrap()
    });

    let a = pt.await.unwrap();
    let b = vt.await.unwrap();
    assert_eq!(a, b);
}
