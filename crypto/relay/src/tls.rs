//! TLS 1.3 record framing and fail-closed handshake verification.
//!
//! The sidecar never speaks TLS itself: it relays records and, once the client
//! discloses the handshake traffic secrets, verifies the relayed handshake
//! (certificate chain to the Mozilla roots, hostname, CertificateVerify and
//! both Finished messages) using `cu-crypto` for the key schedule.

use anyhow::{anyhow, bail, Context, Result};
use tracing::info;
use cu_crypto::aesgcm;
use cu_crypto::hkdf;
use cu_crypto::keyschedule::{self, Secret};
use rustls_pki_types::{CertificateDer, DnsName, ServerName, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use sha2::{Digest, Sha256};

pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;

/// A framed TLS record.
#[derive(Debug, Clone)]
pub struct Record {
    pub ctype: u8,
    pub header: [u8; 5],
    pub payload: Vec<u8>,
}

impl Record {
    /// The full wire bytes of the record.
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = self.header.to_vec();
        v.extend_from_slice(&self.payload);
        v
    }
}

/// Parse as many complete records as `buf` contains; returns them and the
/// number of bytes consumed.
pub fn parse_records(buf: &[u8]) -> (Vec<Record>, usize) {
    let mut out = Vec::new();
    let mut off = 0usize;
    while buf.len() >= off + 5 {
        let len = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if buf.len() < off + 5 + len {
            break;
        }
        let mut header = [0u8; 5];
        header.copy_from_slice(&buf[off..off + 5]);
        out.push(Record {
            ctype: header[0],
            header,
            payload: buf[off + 5..off + 5 + len].to_vec(),
        });
        off += 5 + len;
    }
    (out, off)
}

/// Split a byte stream of plaintext handshake messages into `(type, full_msg)`.
pub fn parse_handshake_messages(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while bytes.len() >= off + 4 {
        let ty = bytes[off];
        let len = ((bytes[off + 1] as usize) << 16)
            | ((bytes[off + 2] as usize) << 8)
            | (bytes[off + 3] as usize);
        if bytes.len() < off + 4 + len {
            break;
        }
        out.push((ty, bytes[off..off + 4 + len].to_vec()));
        off += 4 + len;
    }
    out
}

/// Disclosed handshake traffic secrets from the client.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HsSecrets {
    pub client_hs: [u8; 32],
    pub server_hs: [u8; 32],
}

/// Everything the sidecar learned about the handshake.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub client_hs: [u8; 32],
    pub server_hs: [u8; 32],
    pub th_sh: [u8; 32],
    pub th_sf: [u8; 32],
    pub cert_chain_hash: [u8; 32],
    pub leaf_der: Vec<u8>,
    /// Number of server APPLICATION_DATA records consumed by the handshake.
    pub server_handshake_records: usize,
    /// Number of client APPLICATION_DATA records consumed by the handshake.
    pub client_handshake_records: usize,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Verify the relayed handshake against the disclosed secrets.
///
/// `client_bytes`/`server_bytes` are the raw relayed byte streams.
pub fn verify_handshake(
    client_bytes: &[u8],
    server_bytes: &[u8],
    secrets: &HsSecrets,
    host: &str,
) -> Result<HandshakeInfo> {
    let (client_records, _) = parse_records(client_bytes);
    let (server_records, _) = parse_records(server_bytes);

    // --- plaintext ClientHello / ServerHello -----------------------------
    let ch = client_records
        .iter()
        .find(|r| r.ctype == CT_HANDSHAKE)
        .ok_or_else(|| anyhow!("no ClientHello"))?;
    let sh = server_records
        .iter()
        .find(|r| r.ctype == CT_HANDSHAKE)
        .ok_or_else(|| anyhow!("no ServerHello"))?;
    let ch_msgs = parse_handshake_messages(&ch.payload);
    let sh_msgs = parse_handshake_messages(&sh.payload);
    let (ch_ty, ch_msg) = ch_msgs
        .first()
        .ok_or_else(|| anyhow!("empty ClientHello record"))?;
    let (sh_ty, sh_msg) = sh_msgs
        .first()
        .ok_or_else(|| anyhow!("empty ServerHello record"))?;
    if *ch_ty != HS_CLIENT_HELLO || *sh_ty != HS_SERVER_HELLO {
        bail!("unexpected first handshake messages ({ch_ty}, {sh_ty})");
    }

    let th_sh = sha256(&[ch_msg.as_slice(), sh_msg.as_slice()].concat());

    // --- disclosed handshake traffic secrets ----------------------------
    // HS is NOT disclosed: MS and every application secret are one HKDF step
    // from HS, so receiving it would let the node read prompt and response.
    // s_hs is authenticated below by the server records decrypting under it
    // and the server Finished MAC; c_hs by the client Finished. The derivation
    // HS -> (c_hs, s_hs) under th_SH is part of every π_C statement (ZK).
    let c_hs = keyschedule::Secret::new(secrets.client_hs);
    let s_hs = keyschedule::Secret::new(secrets.server_hs);

    // --- decrypt server handshake records (seq from 0) -------------------
    let sk = s_hs.key();
    let siv = s_hs.iv();
    let mut server_seq: u64 = 0;
    let mut plaintext_stream: Vec<u8> = Vec::new();
    let mut saw_sh = false;
    for r in &server_records {
        if r.ctype == CT_CHANGE_CIPHER_SPEC {
            continue;
        }
        if r.ctype == CT_HANDSHAKE && !saw_sh {
            // the ServerHello record is plaintext
            saw_sh = true;
            continue;
        }
        if r.ctype == CT_APPLICATION_DATA {
            // Stop once the server's Finished has been assembled; later records
            // are application data under s_ap_0.
            if parse_handshake_messages(&plaintext_stream)
                .iter()
                .any(|(t, _)| *t == HS_FINISHED)
            {
                break;
            }
            let pt = aesgcm::gcm_open(&sk, &siv, server_seq, &r.header, &r.payload)
                .ok_or_else(|| anyhow!("server handshake record {server_seq}: bad GCM tag"))?;
            server_seq += 1;
            plaintext_stream.extend_from_slice(handshake_inner(&pt)?);
        }
    }

    let msgs = parse_handshake_messages(&plaintext_stream);
    let ee = msgs
        .iter()
        .find(|(t, _)| *t == HS_ENCRYPTED_EXTENSIONS)
        .ok_or_else(|| anyhow!("no EncryptedExtensions"))?;
    let cert = msgs
        .iter()
        .find(|(t, _)| *t == HS_CERTIFICATE)
        .ok_or_else(|| anyhow!("no Certificate"))?;
    let cv = msgs
        .iter()
        .find(|(t, _)| *t == HS_CERTIFICATE_VERIFY)
        .ok_or_else(|| anyhow!("no CertificateVerify"))?;
    let sfin = msgs
        .iter()
        .find(|(t, _)| *t == HS_FINISHED)
        .ok_or_else(|| anyhow!("no server Finished"))?;

    // transcript through Certificate: this is what CertificateVerify signs
    let th_certs = sha256(&[ch_msg.as_slice(), sh_msg.as_slice(), &ee.1, &cert.1].concat());
    // transcript through CertificateVerify: the server Finished covers this
    let th_cv = sha256(
        &[ch_msg.as_slice(), sh_msg.as_slice(), &ee.1, &cert.1, &cv.1].concat(),
    );

    // --- server Finished ------------------------------------------------
    let sf_key = hkdf::finished_key(s_hs.as_bytes());
    let sf_body = &sfin.1[4..];
    let expect = hkdf::verify_data(&sf_key, &th_cv);
    if !ct_eq(sf_body, &expect) {
        bail!("server Finished verify_data mismatch");
    }

    // transcript for app secrets: CH..SFin
    let th_sf = sha256(
        &[
            ch_msg.as_slice(),
            sh_msg.as_slice(),
            &ee.1,
            &cert.1,
            &cv.1,
            &sfin.1,
        ]
        .concat(),
    );

    // --- certificate chain + hostname -----------------------------------
    let certs = parse_certificate_message(&cert.1[4..])?;
    if certs.is_empty() {
        bail!("empty certificate chain");
    }
    let leaf_der = certs[0].clone();
    let anchors: &[rustls_pki_types::TrustAnchor<'static>] = &webpki_roots::TLS_SERVER_ROOTS;
    let leaf_cert = CertificateDer::from(leaf_der.clone());
    let end_entity = EndEntityCert::try_from(&leaf_cert)
        .map_err(|e| anyhow!("leaf cert parse: {e}"))?;
    let intermediates: Vec<CertificateDer> = certs[1..]
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            anchors,
            &intermediates,
            UnixTime::now(),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| anyhow!("certificate chain verification failed: {e}"))?;
    let dns = DnsName::try_from(host.to_string()).map_err(|e| anyhow!("bad hostname: {e}"))?;
    end_entity
        .verify_is_valid_for_subject_name(&ServerName::DnsName(dns))
        .map_err(|e| anyhow!("hostname verification failed: {e}"))?;

    // --- CertificateVerify ----------------------------------------------
    verify_certificate_verify(&end_entity, &cv.1[4..], &th_certs)?;

    // --- client Finished -------------------------------------------------
    let ck = c_hs.key();
    let civ = c_hs.iv();
    let mut client_seq: u64 = 0;
    let mut client_handshake_plain: Vec<u8> = Vec::new();
    for r in &client_records {
        if r.ctype == CT_HANDSHAKE || r.ctype == CT_CHANGE_CIPHER_SPEC {
            continue;
        }
        if r.ctype == CT_APPLICATION_DATA {
            if parse_handshake_messages(&client_handshake_plain)
                .iter()
                .any(|(t, _)| *t == HS_FINISHED)
            {
                break;
            }
            let pt = aesgcm::gcm_open(&ck, &civ, client_seq, &r.header, &r.payload)
                .ok_or_else(|| anyhow!("client handshake record {client_seq}: bad GCM tag"))?;
            client_seq += 1;
            client_handshake_plain.extend_from_slice(handshake_inner(&pt)?);
        }
    }
    let cmsgs = parse_handshake_messages(&client_handshake_plain);
    let cfin = cmsgs
        .iter()
        .find(|(t, _)| *t == HS_FINISHED)
        .ok_or_else(|| anyhow!("no client Finished"))?;
    let cf_key = hkdf::finished_key(c_hs.as_bytes());
    let expect = hkdf::verify_data(&cf_key, &th_sf);
    if !ct_eq(&cfin.1[4..], &expect) {
        bail!("client Finished verify_data mismatch");
    }

    let cert_chain_hash = sha256(&certs.concat());

    Ok(HandshakeInfo {
        client_hs: secrets.client_hs,
        server_hs: secrets.server_hs,
        th_sh,
        th_sf,
        cert_chain_hash,
        leaf_der,
        server_handshake_records: server_seq as usize,
        client_handshake_records: client_seq as usize,
    })
}

/// The content of a decrypted handshake-epoch record (RFC 8446 §5.4): strip
/// the zero padding, then require the inner content type to be handshake.
pub fn handshake_inner(pt: &[u8]) -> Result<&[u8]> {
    let end = pt.iter().rposition(|b| *b != 0).ok_or_else(|| anyhow!("empty encrypted handshake record"))?;
    if pt[end] != CT_HANDSHAKE {
        bail!("encrypted handshake record has inner content type {}", pt[end]);
    }
    Ok(&pt[..end])
}

/// Extract the DER certificates from a Certificate handshake message body.
fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    // body: context(1) + list_len(3) + entries[ cert_len(3) + cert + ext_len(2)+ext ]
    if body.len() < 4 {
        bail!("certificate message too short");
    }
    let ctx = body[0];
    if ctx != 0 {
        bail!("unexpected certificate request context");
    }
    let list_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    let mut off = 4;
    let end = (4 + list_len).min(body.len());
    let mut certs = Vec::new();
    while off + 3 <= end {
        let len = ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | body[off + 2] as usize;
        off += 3;
        if off + len > end {
            bail!("certificate entry out of bounds");
        }
        certs.push(body[off..off + len].to_vec());
        off += len;
        if off + 2 > end {
            break;
        }
        let ext_len = ((body[off] as usize) << 8) | body[off + 1] as usize;
        off += 2 + ext_len;
    }
    Ok(certs)
}

fn verify_certificate_verify(cert: &EndEntityCert, body: &[u8], th_cv: &[u8; 32]) -> Result<()> {
    if body.len() < 4 {
        bail!("CertificateVerify too short");
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        bail!("CertificateVerify signature truncated");
    }
    let sig = &body[4..4 + sig_len];
    info!(scheme = format!("{scheme:#06x}"), sig_len, "CertificateVerify");

    // RFC 8446 §4.4.3: 64 spaces || context string || 0x00 || transcript hash
    let mut msg = vec![0x20u8; 64];
    msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    msg.push(0x00);
    msg.extend_from_slice(th_cv);

    let alg: &dyn rustls_pki_types::SignatureVerificationAlgorithm = match scheme {
        0x0403 => webpki::aws_lc_rs::ECDSA_P256_SHA256,
        0x0503 => webpki::aws_lc_rs::ECDSA_P384_SHA384,
        0x0603 => webpki::aws_lc_rs::ECDSA_P521_SHA512,
        0x0804 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => webpki::aws_lc_rs::ED25519,
        // RSASSA-PKCS1-v1_5 is not allowed in a TLS 1.3 CertificateVerify
        // (RFC 8446 §4.4.3), so 0x0401 falls through to the refusal.
        other => bail!("unsupported CertificateVerify scheme {other:#06x}"),
    };
    cert.verify_signature(alg, &msg, sig)
        .map_err(|e| anyhow!("CertificateVerify signature invalid: {e}"))?;
    Ok(())
}

/// Derive the app-data write key for a given traffic secret.
pub fn app_key(secret: &Secret) -> ([u8; 16], [u8; 12]) {
    (secret.key(), secret.iv())
}

/// Helper: `Secret` from bytes.
pub fn secret_from(b: [u8; 32]) -> Secret {
    Secret::new(b)
}

/// Re-export for session assembly.
pub use aesgcm::record_header;

/// Compute the 5-byte AAD header for a record with `ct_len` ciphertext bytes.
pub fn aad_for(ct_len: usize) -> [u8; 5] {
    record_header(ct_len)
}

/// Convenience: hex of a byte slice.
pub fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

/// Constant-time byte comparison (the lengths are public).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod ct_eq_tests {
    #[test]
    fn ct_eq_compares_length_and_bytes() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
    }
}

#[cfg(test)]
mod inner_type_tests {
    use super::{handshake_inner, CT_HANDSHAKE};

    #[test]
    fn padding_is_stripped_and_the_type_checked() {
        assert_eq!(handshake_inner(&[1, 2, CT_HANDSHAKE]).unwrap(), &[1, 2]);
        assert_eq!(handshake_inner(&[1, 2, CT_HANDSHAKE, 0, 0]).unwrap(), &[1, 2]);
        assert!(handshake_inner(&[1, 2, 0x17]).is_err());
        assert!(handshake_inner(&[0, 0]).is_err());
        assert!(handshake_inner(&[]).is_err());
    }
}
