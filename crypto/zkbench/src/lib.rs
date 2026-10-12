//! `zkbench` — VOLE-ZK circuits for the confidential-upstream protocol.
//!
//! Implements the three proofs of a session on the pinned TLSNotary `mpz2`
//! (rev 8f89783): π_NK (head template under `K_0`), π_C2S (body suffix) and
//! π_C3S (usage disclosure). Native advice lives in `cu-crypto`; the circuits
//! here mirror it exactly.

pub mod channel;
pub mod fixtures;
pub mod mux;
pub mod gadgets;
pub mod proofs;
pub mod statements;
pub mod transport;

/// Which side of a proof we are building.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Prover,
    Verifier,
}

pub use proofs::{CheckResult, run_io, run_pair_ideal, stats, Stats};
pub use statements::{Check, Params, PiC2S, PiC3S, PiNK, Proof, Witness};
