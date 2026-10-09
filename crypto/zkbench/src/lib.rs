//! `zkbench` — VOLE-ZK circuits for the confidential-upstream protocol.
//!
//! Implements the four proofs of SPEC §5 on the pinned TLSNotary `mpz2`
//! (rev 8f89783): π_C1 (credential-record material), π_N (head template),
//! π_C2 (body suffix) and π_C3 (usage disclosure). Native advice lives in
//! `cu-crypto`; the circuits here mirror it exactly.

pub mod fixtures;
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
pub use statements::{Check, Params, PiC1, PiC2, PiC3, PiN, Proof, SessionPublic, Witness};
