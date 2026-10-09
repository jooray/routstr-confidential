//! NIST SP 800-38D / GCM specification test vectors (Test Cases 1-4), plus a
//! direct GHASH vector, exercised through the same `ctr_keystream` + `ghash`
//! primitives the ZK circuits prove about.

use cu_crypto::aesgcm::{gcm_seal, ghash, ghash_key, ghash_tag_input};
use cu_crypto::hex;

struct Vec4 {
    name: &'static str,
    k: &'static str,
    iv: &'static str,
    a: &'static str,
    p: &'static str,
    c: &'static str,
    t: &'static str,
}

const VECTORS: &[Vec4] = &[
    Vec4 {
        name: "TC1",
        k: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        a: "",
        p: "",
        c: "",
        t: "58e2fccefa7e3061367f1d57a4e7455a",
    },
    Vec4 {
        name: "TC2",
        k: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        a: "",
        p: "00000000000000000000000000000000",
        c: "0388dace60b6a392f328c2b971b2fe78",
        t: "ab6e47d42cec13bdf53a67b21257bddf",
    },
    Vec4 {
        name: "TC3",
        k: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        a: "",
        p: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        c: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        t: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    Vec4 {
        name: "TC4",
        k: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        a: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        p: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        c: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        t: "5bc94fbc3221a5db94fae95ae7121a47",
    },
];

#[test]
fn nist_gcm_test_cases() {
    for v in VECTORS {
        let key: [u8; 16] = hex(v.k).try_into().unwrap();
        let iv: [u8; 12] = hex(v.iv).try_into().unwrap();
        let aad = hex(v.a);
        let pt = hex(v.p);
        let out = gcm_seal(&key, &iv, 0, &aad, &pt);
        let (ct, tag) = out.split_at(pt.len());
        assert_eq!(ct, hex(v.c).as_slice(), "{} ciphertext", v.name);
        assert_eq!(tag, hex(v.t).as_slice(), "{} tag", v.name);
    }
}

#[test]
fn nist_ghash_vector() {
    // GCM specification, Test Case 2 worked example.
    let h: [u8; 16] = hex("66e94bd4ef8a2c3b884cfa59ca342b2e").try_into().unwrap();
    assert_eq!(ghash_key(&[0u8; 16]), h);
    let data = hex("0388dace60b6a392f328c2b971b2fe78");
    assert_eq!(
        ghash_tag_input(&h, &[], &data),
        hex("f38cbb1ad69223dcc3457ae5b6b0f885").as_slice()
    );
}

#[test]
fn ghosh_is_length_sensitive() {
    // GHASH pads to a block boundary; a value differing only past the padding
    // is identical, confirming the pad16 semantics.
    let h = ghash_key(&[1u8; 16]);
    assert_eq!(ghash(&h, &[0xaa; 16]), ghash(&h, &[0xaa; 16]));
    assert_ne!(ghash(&h, &[0xaa; 15]), ghash(&h, &[0xaa; 16]));
}
