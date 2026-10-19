//! The three ZK statements of a session (`docs/TWOPC-DESIGN.md`).
//!
//! Nobody knows `HS`. The two-party key schedule hands the client `c_ap_1`
//! and `s_ap_0`, the node `K_0`/`IV_0`, and both sides the public anchors
//!
//! ```text
//! h1 = SHA256(c_ap_1)   h2 = SHA256(s_ap_0)   hk = SHA256(K_0 ‖ IV_0)
//! ```
//!
//! so each statement is anchored by a hash of its own secret:
//!
//! * **π_C2S** (client proves): the final body record (epoch 1, under
//!   `c_ap_1`) decrypts, at the public window, to the pinned suffix.
//! * **π_C3S** (client proves): the tail server records (under `s_ap_0`)
//!   end with the disclosed `R` (plus `skip` undisclosed bytes).
//! * **π_NK** (node proves): the credential record (epoch 0, seq 0, under
//!   `K_0`/`IV_0`) is the published template with alphabet-constrained key
//!   bytes; the ciphertext is bound by `c_commit = SHA256(header ‖ C_1)`.
//!
//! The anchor digests are decoded (they equal public values); every
//! plaintext comparison is a one-bit in-circuit equality (`eq_bytes`).
//!
//! Each statement is built exactly once per proof, with the *same* sequence of
//! memory allocations and circuit calls on the prover and the verifier side.
//! The two sides differ only in how inputs are marked (private/blind) and in
//! who assigns values.
//!
//! # What the circuits do not check
//!
//! The record statements (π_C2S/π_C3S) prove AES-CTR decryption of public
//! ciphertext only; none of them recomputes the GCM tag (π_NK likewise binds
//! only the CTR ciphertext it commits to). They are sound because the
//! verifier never takes record ciphertext from the prover: the sidecar builds
//! these parameters from its own relay transcript (the client's final body
//! record it holds and then forwards; the server records it read from its own
//! connection to the provider), and the client checks the node's parameters
//! against the records it sent or received. A tag would add nothing on top:
//! for the server records the client holds the traffic secret and could
//! compute a valid tag itself, and the body record's tag is checked by the
//! provider, which rejects the record otherwise. Whoever calls these
//! statements with ciphertext it did not observe itself gets no assurance
//! that the record was ever sent.

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

/// The one key alphabet the fixed-size π_NK membership circuit implements.
///
/// `alphabet_circuit` is a fixed-size membership check over exactly this set.
/// The offer's `key_alphabet` is carried through [`PiNK`] so both sides bind the
/// alphabet explicitly: a statement built for another alphabet is rejected
/// instead of silently proving membership in the wrong set.
pub const SUPPORTED_KEY_ALPHABET: &str = "[A-Za-z0-9_-]";

/// An upper bound on a TLS 1.3 record's inner plaintext (content, content
/// type and padding): the 2^14 + 256-byte ciphertext limit of RFC 8446 §5.2,
/// which also covers the 2^14 + 1-byte plaintext limit. Record-shaped public
/// parameters beyond it are rejected before any circuit is built.
pub const MAX_INNER_PLAINTEXT: usize = (1 << 14) + 256;

/// The three proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// Head template under K_0 (N proves; anchored by `hk`).
    PiNK,
    /// Body suffix under c_ap_1 (anchored by `h1`).
    PiC2S,
    /// Usage disclosure under s_ap_0 (anchored by `h2`).
    PiC3S,
}

impl Proof {
    pub fn name(&self) -> &'static str {
        match self {
            Proof::PiNK => "pi_nk",
            Proof::PiC2S => "pi_c2s",
            Proof::PiC3S => "pi_c3s",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "pi_nk" => Some(Proof::PiNK),
            "pi_c2s" => Some(Proof::PiC2S),
            "pi_c3s" => Some(Proof::PiC3S),
            _ => None,
        }
    }
    /// True when the client (prover side process) is the prover.
    pub fn client_proves(&self) -> bool {
        !matches!(self, Proof::PiNK)
    }
}

pub(crate) fn default_key_alphabet() -> String {
    SUPPORTED_KEY_ALPHABET.to_string()
}

/// One tail server record for π_C3S (ciphertext to the record's end).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TailRecord {
    pub seq: u64,
    /// The record's ciphertext (tag excluded) from inner-plaintext offset
    /// `off` to its end.
    pub ct: Vec<u8>,
    /// Block-aligned offset of `ct` in the record (only the first covered
    /// record may start later than 0, so the proof decrypts only the bytes it
    /// needs). Omitted on the wire when 0.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub off: usize,
}

fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

/// π_C2S public parameters: a window of the final body record, anchored by
/// `h1`.
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

/// π_C3S public parameters: the tail server records, anchored by `h2`.
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

/// Most tail records a π_C3S may cover (the sidecar's disclosure limit). An
/// honest disclosure covers one or two: the terminal usage event, or a short
/// error head and its body.
pub const MAX_C3S_RECORDS: usize = 64;

/// Most ciphertext bytes, summed over the covered records, that a π_C3S may
/// decrypt. Proof cost grows with every decrypted byte (about 400
/// correlations each), so this bounds the work either side can be made to do
/// to about 10 M correlations (about 5 s with real OT on an M2 Max; a browser
/// prover is several times slower), well inside the sidecar's 30 s proof
/// timeout. It covers the largest `R` the sidecar accepts (16 KiB) plus the
/// first record's block alignment, the content-type bytes and `skip`. Only the
/// first record's unneeded head is trimmed (`TailRecord::off`), so an honest
/// minimal tail is at most `|R| + skip` plus 15 alignment bytes and one byte
/// per record. An honest usage disclosure is a few hundred bytes.
pub const MAX_C3S_BYTES: usize = (16 << 10) + (8 << 10);

/// The largest `|R| + skip` that always fits [`MAX_C3S_BYTES`] when the
/// covered records are the minimal tail (the sidecar's choice): the proof
/// decrypts `|R| + skip`, at most 15 bytes of block alignment in the first
/// record, and one content-type byte per record. A disclosure source should
/// refuse anything larger up front.
pub const MAX_C3S_NEED: usize = MAX_C3S_BYTES - 15 - MAX_C3S_RECORDS;

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// π_NK public parameters: the head template, anchored by `hk` (the keystream
/// is computed in-circuit from `K_0`/`IV_0`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiNK {
    /// `SHA256(K_0 ‖ IV_0)` (28 bytes hashed), output publicly by the 2PC.
    pub hk: [u8; 32],
    pub head_len: usize,
    pub key_len: usize,
    /// The key alphabet the statement is bound to. Must equal
    /// [`SUPPORTED_KEY_ALPHABET`] (the fixed-size circuit's set), otherwise the
    /// statement builder fails rather than proving the wrong alphabet.
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

/// Proof parameters (prover and verifier share the same value).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Params {
    PiNK(PiNK),
    PiC2S(PiC2S),
    PiC3S(PiC3S),
}

impl Params {
    pub fn proof(&self) -> Proof {
        match self {
            Params::PiNK(_) => Proof::PiNK,
            Params::PiC2S(_) => Proof::PiC2S,
            Params::PiC3S(_) => Proof::PiC3S,
        }
    }
}

/// Private witness (only the prover holds this). Its bytes are wiped on drop
/// and `Debug` prints only the variant.
#[derive(Clone, serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub enum Witness {
    /// π_C2S/π_C3S: a 32-byte traffic secret (c_ap_1 or s_ap_0).
    Secret([u8; 32]),
    /// π_NK: the epoch-0 AES key and IV and the API key bytes.
    NodeKey {
        k0: [u8; 16],
        iv0: [u8; 12],
        key: Vec<u8>,
    },
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Witness::Secret(_) => f.write_str("Witness::Secret(<redacted>)"),
            Witness::NodeKey { key, .. } => write!(f, "Witness::NodeKey {{ <redacted>, key_len: {} }}", key.len()),
        }
    }
}

/// A single value the verifier must check after decoding.
#[derive(Debug)]
pub struct Check {
    pub label: String,
    pub value: Vector<U8>,
    pub expected: Vec<u8>,
    /// Only the first `compare_len` bytes are compared (defaults to all).
    pub compare_len: Option<usize>,
}

impl Check {
    pub(crate) fn full(label: impl Into<String>, value: Vector<U8>, expected: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            value,
            expected,
            compare_len: None,
        }
    }
}

/// Build the circuit for `params` on one side. Returns the checks to verify.
pub fn build<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    params: &Params,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    match params {
        Params::PiNK(p) => build_pi_nk(vm, role, p, witness),
        Params::PiC2S(p) => build_pi_c2s(vm, role, p, witness),
        Params::PiC3S(p) => build_pi_c3s(vm, role, p, witness),
    }
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
    // The compared range is the window's end and its last byte is the inner
    // content type (application data): the statement itself says the record
    // ends with the suffix, not only the parameters the verifier chose.
    if p.sel_start.checked_add(p.sel_len) != Some(p.w) || p.ct_window.len() != p.w {
        anyhow::bail!("π_C2S: the compared range must end the window");
    }
    if p.expected.last() != Some(&0x17) {
        anyhow::bail!("π_C2S: the compared range must end with the inner content type 0x17");
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
    if p.records.len() > MAX_C3S_RECORDS {
        anyhow::bail!("π_C3S: {} records (limit {MAX_C3S_RECORDS})", p.records.len());
    }
    let total = p.records.iter().try_fold(0usize, |acc, r| acc.checked_add(r.ct.len()));
    if total.is_none_or(|t| t > MAX_C3S_BYTES) {
        anyhow::bail!("π_C3S: the records exceed {MAX_C3S_BYTES} ciphertext bytes in all");
    }
    let (anchor, k, iv) = anchored_keys_after_updates(vm, role, "h2", &p.h2, witness, p.key_updates)?;
    let mut contents = Vec::with_capacity(p.records.len());
    let mut types = Vec::with_capacity(p.records.len());
    for (i, r) in p.records.iter().enumerate() {
        if i > 0 && r.off != 0 {
            anyhow::bail!("π_C3S: only the first record may start at an offset");
        }
        let ct = public_bytes(vm, &r.ct)?;
        let (content, ctype) = decrypt_record_tail(vm, &k, &iv, r.seq, &ct, r.off)?;
        contents.push(content);
        types.push(ctype);
    }
    let all = concat(vm, &contents)?;
    let start = all
        .len()
        .checked_sub(p.expected.len())
        .and_then(|x| x.checked_sub(p.skip))
        .ok_or_else(|| anyhow::anyhow!("π_C3S: records do not cover R plus skip"))?;
    let out = select(vm, &all, start, p.expected.len())?;
    // Every covered record is unpadded application data: R cannot be read
    // out of a handshake or alert record. One comparison keeps the result
    // a single bit.
    types.insert(0, out);
    let out = concat(vm, &types)?;
    let mut want = p.expected.clone();
    want.resize(p.expected.len() + p.records.len(), 0x17);
    let expected = public_bytes(vm, &want)?;
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
        || p.head_len >= MAX_INNER_PLAINTEXT
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
            let mut kiv = zeroize::Zeroizing::new(Vec::with_capacity(28));
            kiv.extend_from_slice(k0);
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

    let kiv = secret_bytes(vm, role, 28, kiv_bytes.as_deref().map(|v| v.as_slice()))?;
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
