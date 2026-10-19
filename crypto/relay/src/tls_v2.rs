//! Protocol v2 (two-party handshake): the ClientHello and ServerHello checks
//! the sidecar enforces before relaying, and the early transcript hash it
//! feeds into the second 2PC phase.
//!
//! In v2 neither party holds the ECDHE secret. That holds only if the single
//! key share U sees is the joint point `P = P_C + P_N`: a ClientHello with any
//! other share (or a second one, or a PSK) would let C finish the handshake
//! alone. So the sidecar parses the ClientHello and relays it only if it offers
//! exactly TLS 1.3, `TLS_AES_128_GCM_SHA256`, secp256r1 and the joint share.

use anyhow::{anyhow, bail, Result};
use cu_crypto::{aesgcm, hkdf, keyschedule};
use sha2::{Digest, Sha256};

use crate::tls::{
    parse_handshake_messages, parse_records, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE, HS_CLIENT_HELLO, HS_FINISHED, HS_SERVER_HELLO,
};

pub const SUITE_AES128_GCM_SHA256: u16 = 0x1301;
pub const GROUP_SECP256R1: u16 = 0x0017;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const TLS13: u16 = 0x0304;
/// `legacy_version` of a TLS 1.3 ClientHello and ServerHello (RFC 8446 §4.1).
const LEGACY_VERSION: u16 = 0x0303;

/// SHA-256("HelloRetryRequest"), the ServerHello.random of an HRR.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, off: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.off.checked_add(n).ok_or_else(|| anyhow!("length overflow"))?;
        if end > self.b.len() {
            bail!("truncated hello message");
        }
        let s = &self.b[self.off..end];
        self.off = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.off == self.b.len()
    }
}

/// Extensions as (type, body), rejecting duplicates (RFC 8446 §4.2).
fn extensions(block: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Reader::new(block);
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while !r.done() {
        let ty = r.u16()?;
        let body = r.vec16()?;
        if out.iter().any(|(t, _)| *t == ty) {
            bail!("duplicate extension {ty}");
        }
        out.push((ty, body));
    }
    Ok(out)
}

fn ext<'a>(exts: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    exts.iter().find(|(t, _)| *t == ty).map(|(_, b)| *b)
}

/// Check a full ClientHello handshake message (with its 4-byte header)
/// against the v2 profile and the joint key share.
pub fn check_client_hello(msg: &[u8], joint: &[u8; 65]) -> Result<()> {
    if msg.len() < 4 || msg[0] != HS_CLIENT_HELLO {
        bail!("not a ClientHello");
    }
    let mut r = Reader::new(&msg[4..]);
    if r.u16()? != LEGACY_VERSION {
        bail!("ClientHello legacy_version must be TLS 1.2");
    }
    r.take(32)?; // random
    r.vec8()?; // legacy_session_id
    let suites = r.vec16()?;
    if suites != SUITE_AES128_GCM_SHA256.to_be_bytes() {
        bail!("ClientHello must offer exactly TLS_AES_128_GCM_SHA256");
    }
    if r.vec8()? != [0] {
        bail!("ClientHello compression methods must be [null]");
    }
    let exts = extensions(r.vec16()?)?;
    if !r.done() {
        bail!("trailing bytes after ClientHello extensions");
    }
    if ext(&exts, EXT_PRE_SHARED_KEY).is_some() || ext(&exts, EXT_EARLY_DATA).is_some() {
        bail!("ClientHello must not offer a PSK or early data");
    }
    let versions = ext(&exts, EXT_SUPPORTED_VERSIONS).ok_or_else(|| anyhow!("no supported_versions"))?;
    let mut vr = Reader::new(versions);
    if vr.vec8()? != TLS13.to_be_bytes() || !vr.done() {
        bail!("ClientHello must offer exactly TLS 1.3");
    }
    let groups = ext(&exts, EXT_SUPPORTED_GROUPS).ok_or_else(|| anyhow!("no supported_groups"))?;
    let mut gr = Reader::new(groups);
    if gr.vec16()? != GROUP_SECP256R1.to_be_bytes() || !gr.done() {
        bail!("ClientHello must offer exactly secp256r1");
    }
    let shares = ext(&exts, EXT_KEY_SHARE).ok_or_else(|| anyhow!("no key_share"))?;
    let mut kr = Reader::new(shares);
    let mut list = Reader::new(kr.vec16()?);
    if !kr.done() {
        bail!("trailing bytes in key_share");
    }
    let group = list.u16()?;
    let share = list.vec16()?;
    if !list.done() {
        bail!("ClientHello must carry exactly one key share");
    }
    if group != GROUP_SECP256R1 || share != joint.as_slice() {
        bail!("ClientHello key share is not the joint P-256 share");
    }
    Ok(())
}

/// The server's P-256 key share from a ServerHello (with its 4-byte header),
/// after checking it negotiated TLS 1.3 and the one offered suite.
pub fn server_hello_share(msg: &[u8]) -> Result<[u8; 65]> {
    if msg.len() < 4 || msg[0] != HS_SERVER_HELLO {
        bail!("not a ServerHello");
    }
    let mut r = Reader::new(&msg[4..]);
    if r.u16()? != LEGACY_VERSION {
        bail!("ServerHello legacy_version must be TLS 1.2");
    }
    if r.take(32)? == HRR_RANDOM {
        bail!("HelloRetryRequest is not supported");
    }
    r.vec8()?;
    if r.u16()? != SUITE_AES128_GCM_SHA256 {
        bail!("server selected a suite that was not offered");
    }
    if r.u8()? != 0 {
        bail!("ServerHello compression method must be null");
    }
    let exts = extensions(r.vec16()?)?;
    if !r.done() {
        bail!("trailing bytes after ServerHello extensions");
    }
    // Without a PSK offered, a TLS 1.3 ServerHello carries only these two.
    if exts.iter().any(|(t, _)| *t != EXT_SUPPORTED_VERSIONS && *t != EXT_KEY_SHARE) {
        bail!("ServerHello carries an extension other than supported_versions and key_share");
    }
    let v = ext(&exts, EXT_SUPPORTED_VERSIONS).ok_or_else(|| anyhow!("ServerHello: no supported_versions"))?;
    if v != TLS13.to_be_bytes() {
        bail!("server did not negotiate TLS 1.3");
    }
    let ks = ext(&exts, EXT_KEY_SHARE).ok_or_else(|| anyhow!("ServerHello: no key_share"))?;
    let mut kr = Reader::new(ks);
    if kr.u16()? != GROUP_SECP256R1 {
        bail!("server key share is not secp256r1");
    }
    let share = kr.vec16()?;
    if !kr.done() {
        bail!("trailing bytes in the server key share");
    }
    share.try_into().map_err(|_| anyhow!("server P-256 share must be 65 bytes"))
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The first ClientHello and ServerHello messages in the relayed streams, if
/// both have arrived complete.
pub fn hellos(client_bytes: &[u8], server_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (c, _) = parse_records(client_bytes);
    let (s, _) = parse_records(server_bytes);
    let ch = c.iter().find(|r| r.ctype == CT_HANDSHAKE)?;
    let sh = s.iter().find(|r| r.ctype == CT_HANDSHAKE)?;
    let (cty, cmsg) = parse_handshake_messages(&ch.payload).into_iter().next()?;
    let (sty, smsg) = parse_handshake_messages(&sh.payload).into_iter().next()?;
    (cty == HS_CLIENT_HELLO && sty == HS_SERVER_HELLO).then_some((cmsg, smsg))
}

/// th_SH = SHA-256(ClientHello ‖ ServerHello).
pub fn th_sh(ch: &[u8], sh: &[u8]) -> [u8; 32] {
    sha256(&[ch, sh])
}

/// th_SF once the server's encrypted flight is complete: decrypt it under
/// s_hs, check the server Finished MAC, and hash CH..server Finished. `None`
/// while the flight is still arriving. (The full verification, including the
/// certificate chain and the client Finished, runs later in `verify_handshake`.)
pub fn th_sf(ch: &[u8], sh: &[u8], server_bytes: &[u8], s_hs: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    let (records, _) = parse_records(server_bytes);
    let s = keyschedule::Secret::new(*s_hs);
    let (key, iv) = (s.key(), s.iv());
    let mut seq = 0u64;
    let mut plain: Vec<u8> = Vec::new();
    let mut saw_sh = false;
    for r in &records {
        match r.ctype {
            CT_CHANGE_CIPHER_SPEC => continue,
            CT_HANDSHAKE if !saw_sh => {
                saw_sh = true;
                continue;
            }
            CT_APPLICATION_DATA => {
                if parse_handshake_messages(&plain).iter().any(|(t, _)| *t == HS_FINISHED) {
                    break;
                }
                let pt = aesgcm::gcm_open(&key, &iv, seq, &r.header, &r.payload)
                    .ok_or_else(|| anyhow!("server handshake record {seq}: bad GCM tag"))?;
                seq += 1;
                plain.extend_from_slice(crate::tls::handshake_inner(&pt)?);
            }
            _ => {}
        }
    }
    let Some([ee, cert, cv, fin]) = crate::tls::server_flight(&plain)? else { return Ok(None) };
    let (ee, cert, cv, fin) = (ee.as_slice(), cert.as_slice(), cv.as_slice(), fin.as_slice());
    let th_cv = sha256(&[ch, sh, ee, cert, cv]);
    if fin.len() < 4 || fin[4..] != hkdf::verify_data(&hkdf::finished_key(s_hs), &th_cv) {
        bail!("server Finished verify_data mismatch");
    }
    Ok(Some(sha256(&[ch, sh, ee, cert, cv, fin])))
}

/// One TLS 1.3 record under (key, iv) at `seq`: `inner` content plus the inner
/// content type, sealed with AES-128-GCM.
pub fn seal_record(key: &[u8; 16], iv: &[u8; 12], seq: u64, inner: &[u8], ctype: u8) -> Vec<u8> {
    let mut pt = inner.to_vec();
    pt.push(ctype);
    let header = aesgcm::record_header(pt.len());
    let mut rec = header.to_vec();
    rec.extend_from_slice(&aesgcm::gcm_seal(key, iv, seq, &header, &pt));
    rec
}

/// KeyUpdate(update_not_requested) handshake message.
pub const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [24, 0, 0, 1, 0];

#[cfg(test)]
mod tests {
    use super::*;

    fn joint() -> [u8; 65] {
        let mut p = [7u8; 65];
        p[0] = 4;
        p
    }

    fn ext_bytes(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut v = ty.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn client_hello(suites: &[u16], groups: &[u16], shares: &[(u16, Vec<u8>)], extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1u8; 32]);
        body.push(0);
        let s: Vec<u8> = suites.iter().flat_map(|x| x.to_be_bytes()).collect();
        body.extend_from_slice(&(s.len() as u16).to_be_bytes());
        body.extend_from_slice(&s);
        body.extend_from_slice(&[1, 0]);
        let mut exts = ext_bytes(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]);
        let g: Vec<u8> = groups.iter().flat_map(|x| x.to_be_bytes()).collect();
        let mut gb = (g.len() as u16).to_be_bytes().to_vec();
        gb.extend_from_slice(&g);
        exts.extend(ext_bytes(EXT_SUPPORTED_GROUPS, &gb));
        let mut ks = Vec::new();
        for (grp, key) in shares {
            ks.extend_from_slice(&grp.to_be_bytes());
            ks.extend_from_slice(&(key.len() as u16).to_be_bytes());
            ks.extend_from_slice(key);
        }
        let mut kb = (ks.len() as u16).to_be_bytes().to_vec();
        kb.extend_from_slice(&ks);
        exts.extend(ext_bytes(EXT_KEY_SHARE, &kb));
        for (t, b) in extra {
            exts.extend(ext_bytes(*t, b));
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![HS_CLIENT_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn accepts_the_v2_profile() {
        let ch = client_hello(&[0x1301], &[0x17], &[(0x17, joint().to_vec())], &[]);
        check_client_hello(&ch, &joint()).unwrap();
    }

    #[test]
    fn rejects_an_extra_or_foreign_key_share() {
        let x25519 = (0x1d, vec![9u8; 32]);
        let ch = client_hello(&[0x1301], &[0x17], &[(0x17, joint().to_vec()), x25519.clone()], &[]);
        assert!(check_client_hello(&ch, &joint()).is_err());
        let ch = client_hello(&[0x1301], &[0x17, 0x1d], &[(0x17, joint().to_vec())], &[]);
        assert!(check_client_hello(&ch, &joint()).is_err());
        let mut other = joint();
        other[10] ^= 1;
        let ch = client_hello(&[0x1301], &[0x17], &[(0x17, other.to_vec())], &[]);
        assert!(check_client_hello(&ch, &joint()).is_err());
    }

    #[test]
    fn rejects_psk_early_data_and_other_suites() {
        let share = [(0x17, joint().to_vec())];
        let ch = client_hello(&[0x1301], &[0x17], &share, &[(EXT_PRE_SHARED_KEY, vec![0, 0])]);
        assert!(check_client_hello(&ch, &joint()).is_err());
        let ch = client_hello(&[0x1301], &[0x17], &share, &[(EXT_EARLY_DATA, vec![])]);
        assert!(check_client_hello(&ch, &joint()).is_err());
        let ch = client_hello(&[0x1301, 0x1302], &[0x17], &share, &[]);
        assert!(check_client_hello(&ch, &joint()).is_err());
    }

    fn server_hello(random: [u8; 32], suite: u16, group: u16, key: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        let mut exts = ext_bytes(EXT_SUPPORTED_VERSIONS, &TLS13.to_be_bytes());
        let mut ks = group.to_be_bytes().to_vec();
        ks.extend_from_slice(&(key.len() as u16).to_be_bytes());
        ks.extend_from_slice(key);
        exts.extend(ext_bytes(EXT_KEY_SHARE, &ks));
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![HS_SERVER_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn extracts_the_server_share() {
        let sh = server_hello([2u8; 32], 0x1301, 0x17, &joint());
        assert_eq!(server_hello_share(&sh).unwrap(), joint());
        assert!(server_hello_share(&server_hello(HRR_RANDOM, 0x1301, 0x17, &joint())).is_err());
        assert!(server_hello_share(&server_hello([2u8; 32], 0x1302, 0x17, &joint())).is_err());
        assert!(server_hello_share(&server_hello([2u8; 32], 0x1301, 0x1d, &[1u8; 32])).is_err());
    }

    #[test]
    fn sealed_record_opens() {
        let (k, iv) = ([3u8; 16], [4u8; 12]);
        let rec = seal_record(&k, &iv, 1, &KEY_UPDATE_NOT_REQUESTED, 22);
        assert_eq!(rec.len(), 5 + 5 + 1 + 16);
        assert_eq!(rec[..5], [0x17, 3, 3, 0, 22]);
        let pt = aesgcm::gcm_open(&k, &iv, 1, &rec[..5], &rec[5..]).unwrap();
        assert_eq!(pt, [24, 0, 0, 1, 0, 22]);
    }
}
