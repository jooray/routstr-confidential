//! `cu-crypto` — the single source of truth for the TLS 1.3 key schedule and
//! AES-GCM record math used by the confidential-upstream protocol.
//!
//! Everything here is RFC 8448 and NIST SP 800-38D tested (see `tests/`). The
//! ZK circuits in `zkbench` mirror exactly the same statements, and the TS
//! client fork is cross-checked against the JSON fixtures in [`fixtures`].

pub mod aesgcm;
pub mod fixtures;
pub mod hkdf;
pub mod keyschedule;
pub mod transcript;

pub use hkdf::{
    derive_secret, derive_secret_hash, expand_label, hkdf_expand, hkdf_expand_label, hkdf_extract,
    verify_data,
};

/// Length of a SHA-256 digest / TLS 1.3 traffic secret.
pub const HASH_LEN: usize = 32;
/// AES-128 key length.
pub const KEY_LEN: usize = 16;
/// AES-GCM IV length used by TLS 1.3.
pub const IV_LEN: usize = 12;
/// GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// TLS 1.3 record header length.
pub const RECORD_HEADER_LEN: usize = 5;

/// Convenience: hex-decode.
pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod smoke {
    use super::*;

    #[test]
    fn hex_decodes_with_whitespace() {
        assert_eq!(hex("00 01 ff"), vec![0, 1, 255]);
    }
}
