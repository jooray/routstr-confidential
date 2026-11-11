//! HPACK (RFC 7541) as protocol v3 needs it on the node: decoding one
//! response header block **without a dynamic table**. N's epoch-0 SETTINGS set
//! `HEADER_TABLE_SIZE = 0`, so a compliant encoder uses only the static table
//! and literals; a block that refers to a dynamic entry or raises the table
//! size is refused.

use anyhow::{anyhow, bail, Result};

/// The static table (RFC 7541 Appendix A), index 1 first.
pub const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The Huffman code (RFC 7541 Appendix B): `(code, bit length)` per symbol,
/// 256 = EOS.
const HUFFMAN: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
    (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
    (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
    (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
    (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
    (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
    (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
    (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
    (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
    (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
    (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
    (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
    (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
    (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
    (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
    (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
    (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
    (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
];

/// Longest header block the node decodes (a response head is about 1 kB).
pub const MAX_BLOCK: usize = 16 << 10;

fn huffman_map() -> &'static std::collections::HashMap<(u32, u8), u16> {
    static MAP: std::sync::OnceLock<std::collections::HashMap<(u32, u8), u16>> = std::sync::OnceLock::new();
    MAP.get_or_init(|| HUFFMAN.iter().enumerate().map(|(sym, (code, len))| ((*code, *len), sym as u16)).collect())
}

/// Decode a Huffman-coded string. The padding must be fewer than 8 bits, all
/// ones (a prefix of EOS); EOS itself is an error.
pub fn huffman_decode(data: &[u8]) -> Result<Vec<u8>> {
    let map = huffman_map();
    let mut out = Vec::with_capacity(data.len() * 2);
    let (mut code, mut len) = (0u32, 0u8);
    for byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | ((byte >> bit) & 1) as u32;
            len += 1;
            if let Some(sym) = map.get(&(code, len)) {
                if *sym == 256 {
                    bail!("hpack: EOS inside a Huffman string");
                }
                out.push(*sym as u8);
                code = 0;
                len = 0;
            } else if len >= 30 {
                bail!("hpack: invalid Huffman code");
            }
        }
    }
    if len >= 8 || code != (1u32 << len) - 1 {
        bail!("hpack: bad Huffman padding");
    }
    Ok(out)
}

/// Huffman-encode (tests, and the reference for the client's decoder).
#[cfg(test)]
pub fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u64, 0u32, Vec::new());
    for b in data {
        let (code, len) = HUFFMAN[*b as usize];
        acc = (acc << len) | code as u64;
        bits += len as u32;
        while bits >= 8 {
            out.push((acc >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    if bits > 0 {
        out.push(((acc << (8 - bits)) as u8) | (0xff >> bits));
    }
    out
}

/// An HPACK integer with an `n`-bit prefix at `block[*i]`.
fn integer(block: &[u8], i: &mut usize, n: u8) -> Result<usize> {
    let mask = (1usize << n) - 1;
    let first = *block.get(*i).ok_or_else(|| anyhow!("hpack: truncated integer"))? as usize & mask;
    *i += 1;
    if first < mask {
        return Ok(first);
    }
    let mut value = mask;
    for shift in [0u32, 7, 14, 21] {
        let b = *block.get(*i).ok_or_else(|| anyhow!("hpack: truncated integer"))?;
        *i += 1;
        value += ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("hpack: integer too long")
}

fn string(block: &[u8], i: &mut usize) -> Result<Vec<u8>> {
    let huffman = block.get(*i).ok_or_else(|| anyhow!("hpack: truncated string"))? & 0x80 != 0;
    let len = integer(block, i, 7)?;
    let end = i.checked_add(len).filter(|e| *e <= block.len()).ok_or_else(|| anyhow!("hpack: string past the block"))?;
    let raw = &block[*i..end];
    *i = end;
    if huffman { huffman_decode(raw) } else { Ok(raw.to_vec()) }
}

fn static_entry(index: usize) -> Result<(&'static str, &'static str)> {
    if index == 0 {
        bail!("hpack: index 0");
    }
    STATIC_TABLE.get(index - 1).copied().ok_or_else(|| anyhow!("hpack: index {index} refers to the dynamic table (its size is 0)"))
}

/// Decode a header block with an empty dynamic table. Accepted: indexed
/// fields from the static table, literals of all three kinds (one "with
/// incremental indexing" adds nothing to a table of size 0), and a table size
/// update to 0 before the first field.
pub fn decode_block(block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if block.len() > MAX_BLOCK {
        bail!("hpack: block of {} bytes (limit {MAX_BLOCK})", block.len());
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            let (n, v) = static_entry(integer(block, &mut i, 7)?)?;
            out.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
            continue;
        }
        let prefix = if b & 0x40 != 0 {
            6
        } else if b & 0x20 != 0 {
            let size = integer(block, &mut i, 5)?;
            if size != 0 || !out.is_empty() {
                bail!("hpack: dynamic table size update to {size} (only 0, before the first field)");
            }
            continue;
        } else {
            4
        };
        let index = integer(block, &mut i, prefix)?;
        let name = if index == 0 { string(block, &mut i)? } else { static_entry(index)?.0.as_bytes().to_vec() };
        let value = string(block, &mut i)?;
        out.push((name, value));
    }
    Ok(out)
}

/// The `:status` of a response header block: the block's first field, the
/// only pseudo-header, three digits.
pub fn response_status(block: &[u8]) -> Result<u16> {
    let fields = decode_block(block)?;
    let (name, value) = fields.first().ok_or_else(|| anyhow!("hpack: empty header block"))?;
    if name != b":status" {
        bail!("hpack: the block does not start with :status");
    }
    if fields[1..].iter().any(|(n, _)| n.first() == Some(&b':')) {
        bail!("hpack: a second pseudo-header");
    }
    if value.len() != 3 || !value.iter().all(|b| b.is_ascii_digit()) {
        bail!("hpack: :status is not three digits");
    }
    Ok(std::str::from_utf8(value)?.parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_examples() {
        // C.4.1: "www.example.com"
        let enc = hex::decode("f1e3c2e5f23a6ba0ab90f4ff").unwrap();
        assert_eq!(huffman_decode(&enc).unwrap(), b"www.example.com");
        assert_eq!(huffman_encode(b"www.example.com"), enc);
        // C.6.1 (first response, Huffman), decoded statelessly: the literals
        // are "with incremental indexing", which a size-0 table drops.
        let block = hex::decode(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        )
        .unwrap();
        let f = decode_block(&block).unwrap();
        assert_eq!(f[0], (b":status".to_vec(), b"302".to_vec()));
        assert_eq!(f[3], (b"location".to_vec(), b"https://www.example.com".to_vec()));
        assert_eq!(response_status(&block).unwrap(), 302);
        // C.6.2 refers to the dynamic table (index 62+): refused.
        let block = hex::decode("4883640effc1c0bf").unwrap();
        assert!(decode_block(&block).is_err());
    }

    #[test]
    fn every_symbol_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
        for s in [&b""[..], b"4", b"404", b"429", b"application/json; charset=utf-8"] {
            assert_eq!(huffman_decode(&huffman_encode(s)).unwrap(), s);
        }
    }

    #[test]
    fn bad_huffman_is_refused() {
        // A whole byte of padding, zero padding, and EOS.
        let mut e = huffman_encode(b"404");
        e.push(0xff);
        assert!(huffman_decode(&e).is_err());
        // "0" (5 bits) then three zero bits: not EOS padding.
        assert!(huffman_decode(&[0x00]).is_err());
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn status_forms() {
        // indexed static 404 (index 13), size update 0 first
        assert_eq!(response_status(&[0x20, 0x8d, 0x00, 0x01, b'x', 0x01, b'y']).unwrap(), 404);
        // literal without indexing, name index 8 (:status), raw "429"
        assert_eq!(response_status(&[0x08, 0x03, b'4', b'2', b'9']).unwrap(), 429);
        // the same, Huffman
        let h = huffman_encode(b"429");
        let mut b = vec![0x08, 0x80 | h.len() as u8];
        b.extend_from_slice(&h);
        assert_eq!(response_status(&b).unwrap(), 429);
        // never indexed (0001xxxx)
        assert_eq!(response_status(&[0x18, 0x03, b'5', b'0', b'3']).unwrap(), 503);
        // not first, two pseudo-headers, bad digits, dynamic index, size > 0, late size update
        assert!(response_status(&[0x00, 0x01, b'x', 0x01, b'y', 0x8d]).is_err());
        assert!(response_status(&[0x8d, 0x88]).is_err());
        assert!(response_status(&[0x08, 0x03, b'4', b'x', b'9']).is_err());
        assert!(response_status(&[0x08, 0x04, b'4', b'0', b'4', b'0']).is_err());
        assert!(response_status(&[0xbe]).is_err());
        assert!(response_status(&[0x3f, 0xe1, 0x1f, 0x8d]).is_err());
        assert!(response_status(&[0x8d, 0x20]).is_err());
        assert!(response_status(&[]).is_err());
        // truncated string / integer
        assert!(response_status(&[0x08, 0x05, b'4']).is_err());
        assert!(response_status(&[0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
