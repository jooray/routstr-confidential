//! The TLS 1.3 key schedule chain (RFC 8446 §7.1) as used by the protocol.
//!
//! The chain implemented here is the single source of truth that the ZK
//! circuits mirror:
//!
//! ```text
//! client_hs = HKDF-Expand-Label(HS, "c hs traffic", th_SH, 32)
//! server_hs = HKDF-Expand-Label(HS, "s hs traffic", th_SH, 32)
//! derived   = Derive-Secret(HS, "derived", "")
//! MS        = HKDF-Extract(salt=derived, IKM=0^32)
//! c_ap_0    = HKDF-Expand-Label(MS, "c ap traffic", th_SF, 32)
//! s_ap_0    = HKDF-Expand-Label(MS, "s ap traffic", th_SF, 32)
//! c_ap_{i+1}= HKDF-Expand-Label(c_ap_i, "traffic upd", "", 32)
//! K_i       = HKDF-Expand-Label(secret_i, "key", "", 16)
//! IV_i      = HKDF-Expand-Label(secret_i, "iv", "", 12)
//! ```

use crate::hkdf::{derive_secret_hash, hkdf_expand_label, hkdf_extract};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte TLS 1.3 traffic secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub [u8; 32]);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    pub const ZERO: Secret = Secret([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Secret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the AES-128 write key from this secret.
    pub fn key(&self) -> [u8; 16] {
        hkdf_expand_label(&self.0, "key", &[], 16)
            .try_into()
            .expect("16 bytes")
    }

    /// Derive the 12-byte write IV from this secret.
    pub fn iv(&self) -> [u8; 12] {
        hkdf_expand_label(&self.0, "iv", &[], 12)
            .try_into()
            .expect("12 bytes")
    }
}

/// Derive the two handshake traffic secrets from `HS` and `th_SH`.
pub fn handshake_secrets(hs: &[u8; 32], th_sh: &[u8; 32]) -> (Secret, Secret) {
    let c = hkdf_expand_label(hs, "c hs traffic", th_sh, 32)
        .try_into()
        .unwrap();
    let s = hkdf_expand_label(hs, "s hs traffic", th_sh, 32)
        .try_into()
        .unwrap();
    (Secret(c), Secret(s))
}

/// `derived = Derive-Secret(HS, "derived", "")`.
pub fn derived_secret(hs: &[u8; 32]) -> [u8; 32] {
    derive_secret_hash(hs, "derived", &crate::transcript::EMPTY_HASH)
}

/// `MS = HKDF-Extract(salt=Derive-Secret(HS, "derived", ""), IKM=0^32)`.
pub fn master_secret(hs: &[u8; 32]) -> Secret {
    let derived = derived_secret(hs);
    Secret(hkdf_extract(&derived, &[0u8; 32]))
}

/// Derive `c_ap_0` and `s_ap_0` from the master secret and `th_SF`.
pub fn application_secrets(ms: &Secret, th_sf: &[u8; 32]) -> (Secret, Secret) {
    let c = hkdf_expand_label(&ms.0, "c ap traffic", th_sf, 32)
        .try_into()
        .unwrap();
    let s = hkdf_expand_label(&ms.0, "s ap traffic", th_sf, 32)
        .try_into()
        .unwrap();
    (Secret(c), Secret(s))
}

/// KeyUpdate: `secret' = HKDF-Expand-Label(secret, "traffic upd", "", 32)`.
pub fn traffic_update(secret: &Secret) -> Secret {
    Secret(hkdf_expand_label(&secret.0, "traffic upd", &[], 32).try_into().unwrap())
}

/// All secrets the protocol needs, precomputed.
#[derive(Debug)]
pub struct KeySchedule {
    pub hs: [u8; 32],
    pub th_sh: [u8; 32],
    pub th_sf: [u8; 32],
    pub client_hs: Secret,
    pub server_hs: Secret,
    pub master_secret: Secret,
    pub c_ap_0: Secret,
    pub s_ap_0: Secret,
    pub c_ap_1: Secret,
    pub c_ap_2: Secret,
}

impl KeySchedule {
    pub fn from_handshake(hs: [u8; 32], th_sh: [u8; 32], th_sf: [u8; 32]) -> Self {
        let (client_hs, server_hs) = handshake_secrets(&hs, &th_sh);
        let ms = master_secret(&hs);
        let (c_ap_0, s_ap_0) = application_secrets(&ms, &th_sf);
        let c_ap_1 = traffic_update(&c_ap_0);
        let c_ap_2 = traffic_update(&c_ap_1);
        Self {
            hs,
            th_sh,
            th_sf,
            client_hs,
            server_hs,
            master_secret: ms,
            c_ap_0,
            s_ap_0,
            c_ap_1,
            c_ap_2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn arr32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// RFC 8448 §3 "Simple 1-RTT Handshake": reproduce the whole chain from
    /// the documented intermediate values.
    #[test]
    fn rfc8448_key_schedule() {
        let hs = arr32("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        let th_sh = arr32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let th_sf = arr32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

        let (c_hs, s_hs) = handshake_secrets(&hs, &th_sh);
        assert_eq!(
            c_hs.as_bytes(),
            &arr32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            s_hs.as_bytes(),
            &arr32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );

        assert_eq!(
            derived_secret(&hs),
            arr32("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")
        );

        let ms = master_secret(&hs);
        assert_eq!(
            ms.as_bytes(),
            &arr32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );

        let (c_ap, s_ap) = application_secrets(&ms, &th_sf);
        assert_eq!(
            c_ap.as_bytes(),
            &arr32("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        assert_eq!(
            s_ap.as_bytes(),
            &arr32("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );

        // Server handshake write key + IV (RFC 8448 "derive write traffic keys
        // for handshake data").
        assert_eq!(
            s_hs.key(),
            hex("3fce516009c21727d0f2e4e86ee403bc").as_slice()
        );
        assert_eq!(s_hs.iv(), hex("5d313eb2671276ee13000b30").as_slice());

        // Server application write key + IV (RFC 8448 "derive write traffic
        // keys for application data").
        assert_eq!(s_ap.key(), hex("9f02283b6c9c07efc26bb9f2ac92e356").as_slice());
        assert_eq!(s_ap.iv(), hex("cf782b88dd83549aadf1e984").as_slice());

        // Client handshake read key + IV.
        assert_eq!(c_hs.key(), hex("dbfaa693d1762c5b666af5d950258d01").as_slice());
        assert_eq!(c_hs.iv(), hex("5bd3c71b836e0b76bb73265f").as_slice());

        // traffic_update chain does not accidentally equal c_ap_0.
        let c1 = traffic_update(&c_ap);
        let c2 = traffic_update(&c1);
        assert_ne!(c1.as_bytes(), c_ap.as_bytes());
        assert_ne!(c2.as_bytes(), c1.as_bytes());

        let ks = KeySchedule::from_handshake(hs, th_sh, th_sf);
        assert_eq!(ks.c_ap_1.as_bytes(), c1.as_bytes());
        assert_eq!(ks.c_ap_2.as_bytes(), c2.as_bytes());
    }
}
