//! HKDF (RFC 5869) and the TLS 1.3 `HKDF-Expand-Label` / `Derive-Secret`
//! constructions (RFC 8446 §7.1).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// `HKDF-Extract(salt, IKM)` -> PRK (RFC 5869 §2.2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// `HKDF-Expand(PRK, info, L)` (RFC 5869 §2.3). Supports L up to 255*32.
pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * 32, "HKDF-Expand output too long");
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut mac = HmacSha256::new_from_slice(prk).expect("hmac accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// The `HkdfLabel` structure (RFC 8446 §7.1) serialised as `info`.
pub fn hkdf_label(label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// `HKDF-Expand-Label(secret, label, context, length)` (RFC 8446 §7.1).
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let info = hkdf_label(label, context, length as u16);
    hkdf_expand(secret, &info, length)
}

/// Alias used in the plan/spec text.
pub fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    hkdf_expand_label(secret, label, context, length)
}

/// `Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label,
/// SHA256(messages), 32)`.
pub fn derive_secret(secret: &[u8], label: &str, messages: &[u8]) -> [u8; 32] {
    derive_secret_hash(secret, label, &sha256(messages))
}

/// `Derive-Secret` with a precomputed transcript hash (the common case).
pub fn derive_secret_hash(secret: &[u8], label: &str, transcript_hash: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_label(secret, label, transcript_hash, 32)
        .try_into()
        .expect("32 bytes")
}

/// `HKDF-Expand-Label(base, "finished", "", 32)` — the Finished key.
pub fn finished_key(base: &[u8]) -> [u8; 32] {
    hkdf_expand_label(base, "finished", &[], 32)
        .try_into()
        .expect("32 bytes")
}

/// `verify_data = HMAC(finished_key, transcript_hash)`.
pub fn verify_data(finished_key: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(finished_key).expect("hmac accepts any key length");
    mac.update(transcript_hash);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Test Case 1.
    #[test]
    fn rfc5869_case1() {
        let ikm = vec![0x0b; 22];
        let salt = crate::hex("000102030405060708090a0b0c");
        let info = crate::hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            crate::hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(okm, crate::hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    #[test]
    fn hkdf_label_layout() {
        // RFC 8448 "key info": 00 10 09 "tls13 key" 00
        assert_eq!(
            hkdf_label("key", &[], 16),
            crate::hex("00100974 6c733133 206b6579 00")
        );
        // RFC 8448 iv info
        assert_eq!(
            hkdf_label("iv", &[], 12),
            crate::hex("000c0874 6c733133 20697600")
        );
    }
}
