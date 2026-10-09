//! Handshake transcript hashing (RFC 8446 §4.4.1).

use crate::hkdf::sha256;
use sha2::{Digest, Sha256};

/// Incremental SHA-256 transcript over the plaintext handshake messages.
#[derive(Debug, Default, Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb a raw handshake message (header included, exactly as it appears
    /// on the wire before record protection).
    pub fn update(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    /// Current transcript hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

/// One-shot SHA-256 over a byte string.
pub fn hash(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// SHA-256 of the empty string (used as the context of
/// `Derive-Secret(.., "derived", "")`).
pub const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_matches_sha256_of_empty() {
        assert_eq!(hash(&[]), EMPTY_HASH);
    }
}
