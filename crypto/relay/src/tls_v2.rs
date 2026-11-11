//! The two-party handshake: the ClientHello and ServerHello checks the
//! sidecar enforces before relaying, and the early transcript hash it feeds
//! into the second 2PC phase.
//!
//! Neither party holds the ECDHE secret. That holds only if the single key
//! share U sees is the joint point `P = P_C + P_N`: a ClientHello with any
//! other share (or a second one, or a PSK) would let C finish the handshake
//! alone. So the sidecar relays a ClientHello only if it is the **canonical**
//! one (`canonical_client_hello`): every byte fixed by the offer's host, the
//! framing and the joint share, except the random and the session id.

use anyhow::{anyhow, bail, Result};
use cu_crypto::{aesgcm, hkdf, keyschedule};
use sha2::{Digest, Sha256};

use crate::tls::{
    parse_handshake_messages, parse_records, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE, HS_CLIENT_HELLO, HS_FINISHED, HS_SERVER_HELLO,
};

pub const SUITE_AES128_GCM_SHA256: u16 = 0x1301;
pub const GROUP_SECP256R1: u16 = 0x0017;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
/// Framing "1.1": the credential record is an HTTP/1.1 head, which a provider
/// that negotiated h2 would refuse.
const ALPN_HTTP11: &[u8] = b"http/1.1";
/// Framing "2": the credential record is an HTTP/2 connection head.
const ALPN_H2: &[u8] = b"h2";
/// The record header's `legacy_record_version` the clients write.
pub const RECORD_VERSION: [u8; 2] = [3, 3];
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

fn ext_bytes(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut v = ty.to_be_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// The one ClientHello handshake message (with its 4-byte header) the sidecar
/// relays, for a given random, session id, host, joint share and framing.
///
/// ```text
/// 01 <len:3>                      ClientHello
/// 03 03                           legacy_version
/// <random: 32>                    free
/// 20 <session id: 32>             free
/// 00 02 13 01                     TLS_AES_128_GCM_SHA256 only
/// 01 00                           no compression
/// <extensions length: 2>, then exactly these, in this order:
/// ff 01 00 01 00                  renegotiation_info, empty
/// 00 00 ..  00 <len:2> <host>     server_name = the offer's upstream_host
/// 00 0a 00 04 00 02 00 17         supported_groups: secp256r1
/// 00 23 00 00                     session_ticket, empty
/// 00 2b 00 03 02 03 04            supported_versions: TLS 1.3
/// 00 0d 00 0e 00 0c 04 03 05 03 08 04 04 01 05 01 06 01   signature_algorithms
/// 00 33 00 47 00 45 00 17 00 41 <joint share: 65>         key_share: one, the joint point
/// 00 10 ..  "h2" (framing "2") | "http/1.1" (framing "1.1")   ALPN, one protocol
/// ```
///
/// This is what the three client stacks write, byte for byte: the reference
/// driver (`crypto/client/vendor/tls`), the SDK's TLS fork and the browser
/// library's fork share `utils/client-hello.js` and call it with the same
/// options (one suite, TLS 1.3 only, secp256r1, the default signature
/// algorithms, one ALPN protocol, no `psk_key_exchange_modes`, a random
/// 32-byte session id). The browser library has no framing "2" yet, so it
/// sends only the `http/1.1` form. No stack sends a hello without ALPN.
///
/// Why canonical and not "anything that offers the joint share": what a
/// client can vary in its ClientHello it can use to make the provider (or
/// the CDN in front of it) drop the connection before a ServerHello: another
/// SNI, an extension the edge refuses, a malformed list. The sidecar counts
/// such a drop against framing "2" (`H2Guard`), so a client could withdraw
/// "2" for every client. With this check the bytes U receives before its
/// ServerHello are a function of the offer and of three values a TLS server
/// treats as opaque:
///
/// - the random (32 bytes, any value: a TLS 1.3 server gives the client
///   random no meaning, the downgrade sentinels live in the server random);
/// - the session id (32 bytes, any value: echoed, never looked up, since
///   TLS 1.3 has no session-id resumption and the hello offers no TLS 1.2);
/// - the key share: the joint point, a valid P-256 point that the client
///   cannot choose (it commits to its own share before it sees the node's,
///   `twopc::Party::key_share`).
///
/// The record around it is fixed too (`check_hello` in `main.rs`: one record,
/// one message, record version `03 03`), and the sidecar writes it at once
/// after the TCP connection is up, so the client has no timing to play with
/// before the ServerHello either.
pub fn canonical_client_hello(random: &[u8; 32], session_id: &[u8; 32], host: &str, joint: &[u8; 65], h2: bool) -> Result<Vec<u8>> {
    // A DNS name as the clients write it (ASCII, as in the offer).
    if host.is_empty() || host.len() > 253 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        bail!("upstream host {host:?} is not a plain DNS name");
    }
    if joint[0] != 4 {
        bail!("the joint share is not an uncompressed point");
    }
    let mut exts = vec![0xff, 0x01, 0x00, 0x01, 0x00];
    let mut name = vec![0u8];
    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name.extend_from_slice(host.as_bytes());
    let mut sni = (name.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&name);
    exts.extend(ext_bytes(0, &sni));
    exts.extend(ext_bytes(10, &[0, 2, 0, 0x17]));
    exts.extend(ext_bytes(35, &[]));
    exts.extend(ext_bytes(EXT_SUPPORTED_VERSIONS, &[2, 3, 4]));
    exts.extend(ext_bytes(13, &[0, 12, 4, 3, 5, 3, 8, 4, 4, 1, 5, 1, 6, 1]));
    let mut ks = vec![0, 69, 0, 0x17, 0, 65];
    ks.extend_from_slice(joint);
    exts.extend(ext_bytes(EXT_KEY_SHARE, &ks));
    let proto = if h2 { ALPN_H2 } else { ALPN_HTTP11 };
    let mut alpn = ((proto.len() + 1) as u16).to_be_bytes().to_vec();
    alpn.push(proto.len() as u8);
    alpn.extend_from_slice(proto);
    exts.extend(ext_bytes(16, &alpn));

    let mut body = LEGACY_VERSION.to_be_bytes().to_vec();
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[0, 2]);
    body.extend_from_slice(&SUITE_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut msg = vec![HS_CLIENT_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Offsets of the two free fields in a canonical ClientHello message.
const CH_RANDOM: std::ops::Range<usize> = 6..38;
const CH_SESSION_ID: std::ops::Range<usize> = 39..71;

/// Check a full ClientHello handshake message (with its 4-byte header): it
/// must be the canonical one for this host, joint share and framing (`h2` =
/// framing "2"). The error names the first field that differs.
pub fn check_client_hello(msg: &[u8], joint: &[u8; 65], host: &str, h2: bool) -> Result<()> {
    if msg.len() < 4 || msg[0] != HS_CLIENT_HELLO {
        bail!("not a ClientHello");
    }
    if msg.len() < CH_SESSION_ID.end || msg[CH_RANDOM.end] != 32 {
        bail!("ClientHello must carry a 32-byte session id");
    }
    let random: [u8; 32] = msg[CH_RANDOM].try_into()?;
    let session_id: [u8; 32] = msg[CH_SESSION_ID].try_into()?;
    let want = canonical_client_hello(&random, &session_id, host, joint, h2)?;
    if msg == want.as_slice() {
        return Ok(());
    }
    // Not canonical: say where. Walk both messages field by field.
    let field = |m: &[u8]| -> Result<Vec<(String, Vec<u8>)>> {
        let mut r = Reader::new(&m[4..]);
        let mut out = vec![("legacy_version".to_string(), r.take(2)?.to_vec())];
        r.take(32)?;
        r.vec8()?;
        out.push(("cipher suites (exactly TLS_AES_128_GCM_SHA256)".into(), r.vec16()?.to_vec()));
        out.push(("compression methods".into(), r.vec8()?.to_vec()));
        let exts = extensions(r.vec16()?)?;
        if !r.done() {
            bail!("trailing bytes after ClientHello extensions");
        }
        out.push(("extension list (types and order)".into(), exts.iter().flat_map(|(t, _)| t.to_be_bytes()).collect()));
        for (t, b) in exts {
            let name = match t {
                0 => "server_name (the offer's upstream host)".to_string(),
                10 => "supported_groups (exactly secp256r1)".into(),
                13 => "signature_algorithms".into(),
                16 if h2 => "ALPN (exactly h2 for framing 2)".into(),
                16 => "ALPN (exactly http/1.1 for framing 1.1)".into(),
                EXT_SUPPORTED_VERSIONS => "supported_versions (exactly TLS 1.3)".into(),
                EXT_KEY_SHARE => "key_share (exactly one, the joint P-256 share)".into(),
                t => format!("extension {t}"),
            };
            out.push((name, b.to_vec()));
        }
        Ok(out)
    };
    let got = field(msg).map_err(|e| anyhow!("ClientHello is not canonical: {e}"))?;
    let want = field(&want)?;
    for (g, w) in got.iter().zip(&want) {
        if g.1 != w.1 {
            bail!("ClientHello is not canonical: {} differs", w.0);
        }
    }
    bail!("ClientHello is not canonical: its length fields differ")
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
/// both have arrived complete (a ServerHello may span several records). An
/// error for a server stream that cannot yield a ServerHello.
pub fn hellos(client_bytes: &[u8], server_bytes: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let (c, _) = parse_records(client_bytes);
    let (s, _) = parse_records(server_bytes);
    let Some(smsg) = crate::tls::server_hello_message(&s)? else { return Ok(None) };
    let Some(ch) = c.iter().find(|r| r.ctype == CT_HANDSHAKE) else { return Ok(None) };
    let Some((cty, cmsg)) = parse_handshake_messages(&ch.payload).into_iter().next() else { return Ok(None) };
    Ok((cty == HS_CLIENT_HELLO).then_some((cmsg, smsg)))
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
/// content type, sealed with AES-128-GCM. Content longer than one record
/// allows is refused.
pub fn seal_record(key: &[u8; 16], iv: &[u8; 12], seq: u64, inner: &[u8], ctype: u8) -> Result<Vec<u8>> {
    if inner.len() + 1 > aesgcm::MAX_INNER_PLAINTEXT {
        bail!("record content of {} bytes exceeds one TLS record", inner.len());
    }
    let mut pt = inner.to_vec();
    pt.push(ctype);
    let header = aesgcm::record_header(pt.len());
    let mut rec = header.to_vec();
    rec.extend_from_slice(&aesgcm::gcm_seal(key, iv, seq, &header, &pt));
    Ok(rec)
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

    const HOST: &str = "api.example.com";

    fn canon(h2: bool) -> Vec<u8> {
        canonical_client_hello(&[1u8; 32], &[2u8; 32], HOST, &joint(), h2).unwrap()
    }

    /// A ClientHello with the canonical front and the given extension list.
    fn with_exts(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1u8; 32]);
        body.push(32);
        body.extend_from_slice(&[2u8; 32]);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        let e: Vec<u8> = exts.iter().flat_map(|(t, b)| ext_bytes(*t, b)).collect();
        body.extend_from_slice(&(e.len() as u16).to_be_bytes());
        body.extend_from_slice(&e);
        let mut msg = vec![HS_CLIENT_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    /// The canonical extension list, as (type, body).
    fn canon_exts(h2: bool) -> Vec<(u16, Vec<u8>)> {
        let c = canon(h2);
        let mut r = Reader::new(&c[4..]);
        r.take(2 + 32).unwrap();
        r.vec8().unwrap();
        r.vec16().unwrap();
        r.vec8().unwrap();
        extensions(r.vec16().unwrap()).unwrap().into_iter().map(|(t, b)| (t, b.to_vec())).collect()
    }

    fn refused(msg: &[u8], h2: bool, why: &str) {
        let e = check_client_hello(msg, &joint(), HOST, h2).expect_err(why);
        assert!(format!("{e:#}").contains("not canonical") || format!("{e:#}").contains("ClientHello"), "{why}: {e:#}");
    }

    /// The bytes the three client stacks write (captured from the reference
    /// driver's fork, the SDK's fork and the browser library's fork with the
    /// options their sessions pass; random = aa.., session id = bb.., the
    /// share = the P-256 generator, host api.venice.ai). All three agree.
    const STACK_H2: &str = "010000df0303aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002130101000094ff0100010000000012001000000d6170692e76656e6963652e6169000a00040002001700230000002b0003020304000d000e000c04030503080404010501060100330047004500170041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5001000050003026832";
    const STACK_H11: &str = "010000e50303aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000213010100009aff0100010000000012001000000d6170692e76656e6963652e6169000a00040002001700230000002b0003020304000d000e000c04030503080404010501060100330047004500170041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50010000b000908687474702f312e31";

    #[test]
    fn the_client_stacks_write_the_canonical_hello() {
        let g: [u8; 65] = hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap().try_into().unwrap();
        for (h2, stack) in [(true, STACK_H2), (false, STACK_H11)] {
            let msg = hex::decode(stack).unwrap();
            assert_eq!(canonical_client_hello(&[0xaa; 32], &[0xbb; 32], "api.venice.ai", &g, h2).unwrap(), msg);
            check_client_hello(&msg, &g, "api.venice.ai", h2).unwrap();
            // The other framing, host or share: refused.
            assert!(check_client_hello(&msg, &g, "api.venice.ai", !h2).is_err());
            assert!(check_client_hello(&msg, &g, "api.venice.ai.example", h2).is_err());
            assert!(check_client_hello(&msg, &joint(), "api.venice.ai", h2).is_err());
        }
    }

    #[test]
    fn random_and_session_id_are_free_and_nothing_else() {
        for h2 in [true, false] {
            let c = canon(h2);
            check_client_hello(&c, &joint(), HOST, h2).unwrap();
            assert_eq!(with_exts(&canon_exts(h2)), c);
            // Flip every byte in turn: accepted exactly inside the two free fields.
            for i in 0..c.len() {
                let mut m = c.clone();
                m[i] ^= 0x40;
                let free = CH_RANDOM.contains(&i) || CH_SESSION_ID.contains(&i);
                assert_eq!(check_client_hello(&m, &joint(), HOST, h2).is_ok(), free, "byte {i}");
            }
            // Truncated or extended.
            assert!(check_client_hello(&c[..c.len() - 1], &joint(), HOST, h2).is_err());
            let mut m = c.clone();
            m.push(0);
            assert!(check_client_hello(&m, &joint(), HOST, h2).is_err());
        }
    }

    #[test]
    fn rejects_an_extra_or_foreign_key_share() {
        let mut exts = canon_exts(false);
        let i = exts.iter().position(|(t, _)| *t == EXT_KEY_SHARE).unwrap();
        let mut two = vec![0, 69 + 36, 0, 0x17, 0, 65];
        two.extend_from_slice(&joint());
        two.extend_from_slice(&[0, 0x1d, 0, 32]);
        two.extend_from_slice(&[9u8; 32]);
        exts[i].1 = two;
        refused(&with_exts(&exts), false, "a second share");
        let mut exts = canon_exts(false);
        exts[2].1 = vec![0, 4, 0, 0x17, 0, 0x1d];
        refused(&with_exts(&exts), false, "a second group");
        let mut other = joint();
        other[10] ^= 1;
        let e = check_client_hello(&canonical_client_hello(&[1; 32], &[2; 32], HOST, &other, false).unwrap(), &joint(), HOST, false).unwrap_err();
        assert!(format!("{e:#}").contains("key_share"), "{e:#}");
    }

    #[test]
    fn rejects_every_non_canonical_shape() {
        for h2 in [true, false] {
            let base = canon_exts(h2);
            // An added extension: PSK, early data, psk modes, padding, ECH,
            // status_request, a GREASE value, an unknown one.
            for (t, b) in [(41u16, vec![0, 0]), (42, vec![]), (45, vec![1, 1]), (21, vec![0; 16]), (0xfe0d, vec![0; 8]), (5, vec![1, 0, 0, 0, 0]), (0x0a0a, vec![]), (0x7777, vec![1, 2, 3])] {
                let mut e = base.clone();
                e.push((t, b.clone()));
                refused(&with_exts(&e), h2, "added last");
                let mut e = base.clone();
                e.insert(0, (t, b));
                refused(&with_exts(&e), h2, "added first");
            }
            // A missing extension, a reordered list.
            for i in 0..base.len() {
                let mut e = base.clone();
                e.remove(i);
                refused(&with_exts(&e), h2, "one extension missing");
                let mut e = base.clone();
                e.swap(i, (i + 1) % base.len());
                refused(&with_exts(&e), h2, "two extensions swapped");
            }
            // Another value in each extension.
            for (t, b) in [
                (0xff01u16, vec![]),
                (0, b"\x00\x0e\x00\x00\x0bexample.com".to_vec()),
                (0, b"\x00\x12\x00\x00\x0fAPI.example.com".to_vec()),
                (0, b"\x00\x24\x00\x00\x0fapi.example.com\x00\x00\x0fapi.example.org".to_vec()),
                (35, vec![1, 2, 3]),
                (EXT_SUPPORTED_VERSIONS, vec![4, 3, 4, 3, 3]),
                (13, vec![0, 2, 4, 3]),
                (16, b"\x00\x0c\x02h2\x08http/1.1".to_vec()),
                (16, b"\x00\x0c\x08http/1.1\x02h2".to_vec()),
                (16, b"\x00\x09\x08http/1.0".to_vec()),
                (16, vec![]),
            ] {
                let mut e = base.clone();
                let i = e.iter().position(|(x, _)| *x == t).unwrap();
                e[i].1 = b;
                refused(&with_exts(&e), h2, "another extension value");
            }
        }
        // Another suite list, session id length, compression, version.
        let c = canon(true);
        let mut m = c.clone();
        m[73..75].copy_from_slice(&[0x13, 0x02]);
        refused(&m, true, "another suite");
        let mut m = c.clone();
        m[4] = 2;
        refused(&m, true, "another legacy_version");
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1u8; 32]);
        body.push(0);
        body.extend_from_slice(&c[71..]);
        let mut m = vec![HS_CLIENT_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
        m.extend_from_slice(&body);
        refused(&m, true, "an empty session id");
    }

    #[test]
    fn alpn_is_exactly_the_framings() {
        // Framing "2": h2. Framing "1.1": http/1.1. Never the other, never none.
        let h2 = canon(true);
        let h11 = canon(false);
        check_client_hello(&h2, &joint(), HOST, true).unwrap();
        check_client_hello(&h11, &joint(), HOST, false).unwrap();
        let e = check_client_hello(&h2, &joint(), HOST, false).unwrap_err();
        assert!(format!("{e:#}").contains("http/1.1"), "{e:#}");
        let e = check_client_hello(&h11, &joint(), HOST, true).unwrap_err();
        assert!(format!("{e:#}").contains("h2"), "{e:#}");
        for f in [true, false] {
            let mut e = canon_exts(f);
            e.pop();
            refused(&with_exts(&e), f, "no ALPN");
        }
    }

    #[test]
    fn the_host_must_be_a_plain_dns_name() {
        for bad in ["", "a b", "api.example.com:443", "h\u{e9}te.example"] {
            assert!(canonical_client_hello(&[0; 32], &[0; 32], bad, &joint(), true).is_err(), "{bad:?}");
        }
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
        let rec = seal_record(&k, &iv, 1, &KEY_UPDATE_NOT_REQUESTED, 22).unwrap();
        assert_eq!(rec.len(), 5 + 5 + 1 + 16);
        assert_eq!(rec[..5], [0x17, 3, 3, 0, 22]);
        let pt = aesgcm::gcm_open(&k, &iv, 1, &rec[..5], &rec[5..]).unwrap();
        assert_eq!(pt, [24, 0, 0, 1, 0, 22]);
        // Content past one record is refused, not sealed under a wrapped length.
        assert!(seal_record(&k, &iv, 0, &vec![0; 1 << 14], 23).is_ok());
        assert!(seal_record(&k, &iv, 0, &vec![0; (1 << 14) + 1], 23).is_err());
        assert!(seal_record(&k, &iv, 0, &vec![0; 65520], 23).is_err());
    }
}
