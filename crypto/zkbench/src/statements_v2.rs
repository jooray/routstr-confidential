//! Protocol v2 statements (two-party handshake, `docs/TWOPC-DESIGN.md`).
//!
//! In v2 nobody knows `HS`. The 2PC hands the client `c_ap_1` and `s_ap_0`,
//! the node `K_0`/`IV_0`, and both sides the public anchors
//!
//! ```text
//! h1 = SHA256(c_ap_1)   h2 = SHA256(s_ap_0)   hk = SHA256(K_0 ‖ IV_0)
//! ```
//!
//! so each statement is anchored by a hash of its own secret instead of the
//! v1 key-schedule prefix:
//!
//! * **π_C2S** (client proves): the final body record (epoch 1, under
//!   `c_ap_1`) decrypts, at the public window, to the pinned suffix.
//! * **π_C3S** (client proves): the tail server records (under `s_ap_0`)
//!   end with the disclosed `R` (plus `skip` undisclosed bytes).
//! * **π_NK** (node proves): the credential record (epoch 0, seq 0, under
//!   `K_0`/`IV_0`) is the published template with alphabet-constrained key
//!   bytes; the ciphertext is bound by `c_commit = SHA256(header ‖ C_1)` as in
//!   v1 π_N.
//!
//! The anchor digests are decoded (they equal public values); every
//! plaintext comparison is a one-bit in-circuit equality (`eq_bytes`).

use mpz_vm_core::{
    Call, CallableExt, Vm,
    memory::{
        Array, ToRaw, Vector,
        binary::{Binary, U8},
    },
};

use crate::Role;
use crate::gadgets::{
    aes_block, alphabet_circuit, concat, ctr_block, decrypt_record_tail, decrypt_window,
    eq_bytes, expand_label, public_bytes, record_keys_keyed, secret_bytes, select, sha256_bytes,
    splice_circuit, xor_bytes,
};
use crate::statements::{Check, SUPPORTED_KEY_ALPHABET, TailRecord, Witness, default_key_alphabet};

/// π_C2S public parameters: the v1 π_C2 window, anchored by `h1` instead of
/// the session's handshake values.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiC2S {
    /// `SHA256(c_ap_1)`, output publicly by the 2PC.
    pub h1: [u8; 32],
    /// Record sequence number within epoch 1 (the body starts at 0).
    pub seq: u64,
    /// Public ciphertext window `ct[off .. off+w]`.
    pub ct_window: Vec<u8>,
    /// Inner-plaintext offset of the window start.
    pub off: usize,
    pub w: usize,
    /// Sub-range inside the window that must match `expected`.
    pub sel_start: usize,
    pub sel_len: usize,
    /// The pinned suffix (compared inside the circuit; one bit is revealed).
    pub expected: Vec<u8>,
}

/// π_C3S public parameters: v1 π_C3 anchored by `h2`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiC3S {
    /// `SHA256(s_ap_0)`, output publicly by the 2PC.
    pub h2: [u8; 32],
    /// Tail records in wire order (earliest first).
    pub records: Vec<TailRecord>,
    /// The disclosed plaintext `R` (compared inside the circuit).
    pub expected: Vec<u8>,
    /// Content bytes after `R` up to the end of the records.
    #[serde(default)]
    pub skip: usize,
    /// Server KeyUpdates before the covered records: they are encrypted under
    /// `s_ap_k`, `k` "traffic upd" steps from the anchored `s_ap_0`, and their
    /// sequence numbers count from the start of that epoch. 0 (and omitted on
    /// the wire) when the server never rotated its keys.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub key_updates: u32,
}

/// Most server KeyUpdates a π_C3S may step through (each costs 4 compressions).
pub const MAX_SERVER_KEY_UPDATES: u32 = 16;

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// π_NK public parameters: v1 π_N with the public keystream `s` replaced by
/// the anchor `hk` (the keystream is computed in-circuit from `K_0`/`IV_0`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiNK {
    /// `SHA256(K_0 ‖ IV_0)` (28 bytes hashed), output publicly by the 2PC.
    pub hk: [u8; 32],
    pub head_len: usize,
    pub key_len: usize,
    #[serde(default = "default_key_alphabet")]
    pub key_alphabet: String,
    /// Byte offsets of the API key inside the head record.
    pub key_offsets: Vec<usize>,
    /// Head template with placeholders (0x00) at `key_offsets`.
    pub template: Vec<u8>,
    /// `SHA256(header ‖ C_1)` where `C_1` is the
    /// `head_len + 1`-byte ciphertext (tag excluded) of `head ‖ 0x17` under
    /// `K_0`, nonce `IV_0 xor 0`, counter from 2.
    pub c_commit: [u8; 32],
    /// The record header (`record_header(head_len + 1)`).
    pub header: [u8; 5],
}

fn secret_of(w: Option<&Witness>) -> Option<&[u8; 32]> {
    match w {
        Some(Witness::Secret(s)) => Some(s),
        _ => None,
    }
}

/// Allocate the 32-byte traffic secret, check its hash against the anchor and
/// derive `(K, IV)`.
fn anchored_keys<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    label: &str,
    anchor: &[u8; 32],
    witness: Option<&Witness>,
) -> anyhow::Result<(Check, Array<U8, 16>, Array<U8, 12>)> {
    anchored_keys_after_updates(vm, role, label, anchor, witness, 0)
}

/// [`anchored_keys`] for the traffic secret `updates` KeyUpdates after the
/// anchored one (RFC 8446 §7.2: `HKDF-Expand-Label(s, "traffic upd", "", 32)`).
fn anchored_keys_after_updates<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    label: &str,
    anchor: &[u8; 32],
    witness: Option<&Witness>,
    updates: u32,
) -> anyhow::Result<(Check, Array<U8, 16>, Array<U8, 12>)> {
    let secret = secret_of(witness);
    if role == Role::Prover && secret.is_none() {
        anyhow::bail!("{label}: the prover needs a Secret witness");
    }
    let s = secret_bytes(vm, role, 32, secret.map(|s| s.as_slice()))?;
    let digest: Vector<U8> = sha256_bytes(vm, &s)?.into();
    let mut cur = s;
    for _ in 0..updates {
        cur = expand_label(vm, &cur, "traffic upd", &[], 32)?;
    }
    let (k, iv) = record_keys_keyed(vm, &cur)?;
    Ok((Check::full(label, digest, anchor.to_vec()), k, iv))
}

pub fn build_pi_c2s<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiC2S,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    if p.sel_len != p.expected.len() {
        anyhow::bail!("π_C2S: sel_len {} != |expected| {}", p.sel_len, p.expected.len());
    }
    let (anchor, k, iv) = anchored_keys(vm, role, "h1", &p.h1, witness)?;
    let ct = public_bytes(vm, &p.ct_window)?;
    let out = decrypt_window(vm, &k, &iv, p.seq, &ct, p.off, p.w, p.sel_start, p.sel_len)?;
    let expected = public_bytes(vm, &p.expected)?;
    let eq = eq_bytes(vm, &out, &expected)?;
    Ok(vec![anchor, Check::full("suffix", eq, vec![1u8])])
}

pub fn build_pi_c3s<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiC3S,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    if p.records.is_empty() || p.expected.is_empty() {
        anyhow::bail!("π_C3S: no records or empty R");
    }
    if p.key_updates > MAX_SERVER_KEY_UPDATES {
        anyhow::bail!("π_C3S: {} server KeyUpdates (limit {MAX_SERVER_KEY_UPDATES})", p.key_updates);
    }
    let (anchor, k, iv) = anchored_keys_after_updates(vm, role, "h2", &p.h2, witness, p.key_updates)?;
    let mut contents = Vec::with_capacity(p.records.len());
    for (i, r) in p.records.iter().enumerate() {
        if i > 0 && r.off != 0 {
            anyhow::bail!("π_C3S: only the first record may start at an offset");
        }
        let ct = public_bytes(vm, &r.ct)?;
        contents.push(decrypt_record_tail(vm, &k, &iv, r.seq, &ct, r.off)?);
    }
    let all = concat(vm, &contents)?;
    let start = all
        .len()
        .checked_sub(p.expected.len())
        .and_then(|x| x.checked_sub(p.skip))
        .ok_or_else(|| anyhow::anyhow!("π_C3S: records do not cover R plus skip"))?;
    let out = select(vm, &all, start, p.expected.len())?;
    let expected = public_bytes(vm, &p.expected)?;
    let eq = eq_bytes(vm, &out, &expected)?;
    Ok(vec![anchor, Check::full("disclosure", eq, vec![1u8])])
}

pub fn build_pi_nk<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiNK,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    if p.key_alphabet != SUPPORTED_KEY_ALPHABET {
        anyhow::bail!(
            "unsupported key alphabet {:?}: the π_NK circuit is fixed to {:?}",
            p.key_alphabet,
            SUPPORTED_KEY_ALPHABET
        );
    }
    if p.template.len() != p.head_len
        || p.key_offsets.len() != p.key_len
        || p.key_len == 0
        || p.key_offsets.iter().any(|&o| o >= p.head_len)
    {
        anyhow::bail!("π_NK: inconsistent template/key offsets");
    }
    let mut sorted = p.key_offsets.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != p.key_offsets.len() {
        anyhow::bail!("π_NK: duplicate key offsets");
    }

    // Witness: K_0 ‖ IV_0 (28 bytes) and the API key.
    let (kiv_bytes, key_bytes) = match witness {
        Some(Witness::NodeKey { k0, iv0, key }) => {
            let mut kiv = k0.to_vec();
            kiv.extend_from_slice(iv0);
            (Some(kiv), Some(key.as_slice()))
        }
        _ => (None, None),
    };
    if role == Role::Prover {
        let k = key_bytes.ok_or_else(|| anyhow::anyhow!("π_NK: the prover needs a NodeKey witness"))?;
        if k.len() != p.key_len {
            anyhow::bail!("π_NK: key is {} bytes, statement says {}", k.len(), p.key_len);
        }
    }

    let kiv = secret_bytes(vm, role, 28, kiv_bytes.as_deref())?;
    let key = secret_bytes(vm, role, p.key_len, key_bytes)?;
    let template = public_bytes(vm, &p.template)?;

    // hk = SHA256(K_0 ‖ IV_0)
    let hk: Vector<U8> = sha256_bytes(vm, &kiv)?.into();
    let k0: Array<U8, 16> = select(vm, &kiv, 0, 16)?.try_into().expect("16 bytes");
    let iv0: Array<U8, 12> = select(vm, &kiv, 16, 12)?.try_into().expect("12 bytes");

    // P := template with key bytes spliced in, then || 0x17.
    let circ = splice_circuit(p.head_len, &p.key_offsets);
    let call = Call::builder(circ)
        .arg(template.to_raw())
        .arg(key.to_raw())
        .build()
        .expect("splice input length");
    let head: Vector<U8> = vm.call(call)?;
    let ct_byte = public_bytes(vm, &[0x17])?;
    let plaintext = concat(vm, &[head, ct_byte])?;

    // C_1 = P XOR AES-CTR(K_0, IV_0 xor 0, counter 2..)
    let n = plaintext.len();
    let mut blocks = Vec::with_capacity(n.div_ceil(16));
    for i in 0..n.div_ceil(16) {
        let ctr = ctr_block(vm, &iv0, 0, (i + 2) as u32)?;
        blocks.push(aes_block(vm, &k0, &ctr)?.into());
    }
    let ks_all = concat(vm, &blocks)?;
    let ks = select(vm, &ks_all, 0, n)?;
    let c1 = xor_bytes(vm, &plaintext, &ks)?;

    let mut checks = Vec::new();

    let alph = alphabet_circuit(p.key_len);
    let call = Call::builder(alph).arg(key.to_raw()).build().unwrap();
    let ok: Vector<U8> = vm.call(call)?;
    checks.push(Check::full("key_alphabet", ok, vec![1u8]));

    // c_commit = SHA256(header ‖ C_1)
    let header = public_bytes(vm, &p.header)?;
    let rec = concat(vm, &[header, c1])?;
    let digest: Vector<U8> = sha256_bytes(vm, &rec)?.into();
    checks.push(Check::full("c_commit", digest, p.c_commit.to_vec()));

    checks.push(Check::full("hk", hk, p.hk.to_vec()));
    Ok(checks)
}
