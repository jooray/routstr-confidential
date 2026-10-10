//! The four ZK statements (π_C1, π_N, π_C2, π_C3).
//!
//! Each statement is built exactly once per proof, with the *same* sequence of
//! memory allocations and circuit calls on the prover and the verifier side.
//! The two sides differ only in how inputs are marked (private/blind) and in
//! who assigns values.

use mpz_vm_core::{
    Call, CallableExt, Vm,
    memory::{
        Array, MemoryExt, ToRaw, Vector, ViewExt,
        binary::{Binary, U8},
    },
};
use mpz_hash::sha256::Sha256;

use crate::Role;
use crate::gadgets::{
    aes_block, alphabet_circuit, concat, ctr_block, expand_label, hmac_sha256, public_bytes,
    eq_bytes, record_keys, secret_bytes, select, splice_circuit, xor_bytes,
};

/// The one key alphabet the fixed-size π_N membership circuit implements.
///
/// `alphabet_circuit` is a fixed-size membership check over exactly this set.
/// The offer's `key_alphabet` is carried through [`PiN`] so both sides bind the
/// alphabet explicitly: a statement built for another alphabet is rejected
/// instead of silently proving membership in the wrong set.
pub const SUPPORTED_KEY_ALPHABET: &str = "[A-Za-z0-9_-]";

/// The four proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    PiC1,
    PiN,
    PiC2,
    PiC3,
}

impl Proof {
    pub fn name(&self) -> &'static str {
        match self {
            Proof::PiC1 => "pi_c1",
            Proof::PiN => "pi_n",
            Proof::PiC2 => "pi_c2",
            Proof::PiC3 => "pi_c3",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "pi_c1" => Some(Proof::PiC1),
            "pi_n" => Some(Proof::PiN),
            "pi_c2" => Some(Proof::PiC2),
            "pi_c3" => Some(Proof::PiC3),
            _ => None,
        }
    }
    /// True when the client (prover side process) is the prover.
    pub fn client_proves(&self) -> bool {
        !matches!(self, Proof::PiN)
    }
}

/// Public session values binding every proof to the relayed handshake.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionPublic {
    pub client_hs: [u8; 32],
    pub server_hs: [u8; 32],
    pub th_sh: [u8; 32],
    pub th_sf: [u8; 32],
}

/// π_C1 public parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiC1 {
    pub session: SessionPublic,
    pub head_len: usize,
    /// The record-material keystream `S` (|head| bytes).
    pub s: Vec<u8>,
    pub h1: [u8; 16],
    pub t0: [u8; 16],
}

/// π_N public parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiN {
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
    pub s: Vec<u8>,
    pub c_commit: [u8; 32],
    pub header: [u8; 5],
}

fn default_key_alphabet() -> String {
    SUPPORTED_KEY_ALPHABET.to_string()
}

/// A tail-window decryption statement (shared by π_C2 and π_C3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Window {
    pub session: SessionPublic,
    pub seq: u64,
    /// Public ciphertext window `ct[off .. off+w]`.
    pub ct_window: Vec<u8>,
    /// Inner-plaintext offset of the window start.
    pub off: usize,
    pub w: usize,
    /// Sub-range inside the window that must match `expected`.
    pub sel_start: usize,
    pub sel_len: usize,
    /// The expected bytes (the pinned suffix). Compared inside the circuit:
    /// the verifier learns one bit, never the decrypted window.
    pub expected: Vec<u8>,
}

/// π_C2 = body suffix on the last epoch-2 record.
pub type PiC2 = Window;

/// One tail server record for π_C3 (full ciphertext, inner-plaintext length).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TailRecord {
    pub seq: u64,
    pub ct: Vec<u8>,
}

/// π_C3 = usage disclosure across the final server records.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiC3 {
    pub session: SessionPublic,
    /// Tail records in wire order (earliest first); each contributes its
    /// content (inner plaintext minus the trailing content-type byte).
    pub records: Vec<TailRecord>,
    /// The disclosed plaintext `R`. Compared inside the circuit: the verifier
    /// learns one bit, never the decrypted records.
    pub expected: Vec<u8>,
    /// Content bytes after `R` up to the end of the records. 0 for the usage
    /// event (R ends the transcript); for an upstream error R is the response
    /// head and `skip` is the (undisclosed) body length that follows it.
    #[serde(default)]
    pub skip: usize,
}

/// Proof parameters (prover and verifier share the same value).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Params {
    PiC1(PiC1),
    PiN(PiN),
    PiC2(PiC2),
    PiC3(PiC3),
}

impl Params {
    pub fn proof(&self) -> Proof {
        match self {
            Params::PiC1(_) => Proof::PiC1,
            Params::PiN(_) => Proof::PiN,
            Params::PiC2(_) => Proof::PiC2,
            Params::PiC3(_) => Proof::PiC3,
        }
    }
}

/// Private witness (only the prover holds this).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Witness {
    /// π_C1/π_C2/π_C3: the TLS 1.3 handshake secret `HS`.
    Hs([u8; 32]),
    /// π_N: the API key bytes.
    Key(Vec<u8>),
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
    fn full(label: impl Into<String>, value: Vector<U8>, expected: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            value,
            expected,
            compare_len: None,
        }
    }
    fn prefix(label: impl Into<String>, value: Vector<U8>, expected: Vec<u8>, len: usize) -> Self {
        Self {
            label: label.into(),
            value,
            expected,
            compare_len: Some(len),
        }
    }
}

struct SessionDerived {
    c_hs: Vector<U8>,
    s_hs: Vector<U8>,
    c_ap_0: Vector<U8>,
    s_ap_0: Vector<U8>,
}

/// The common key-schedule prefix: binds `HS` to the session's public traffic
/// secrets. This is what makes every proof session-specific (invariants I3/I6).
fn derive_session<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    s: &SessionPublic,
    hs: Option<&[u8; 32]>,
) -> anyhow::Result<SessionDerived> {
    let hs32 = secret_bytes(vm, role, 32, hs.map(|h| h.as_slice()))?;

    let c_hs = expand_label(vm, &hs32, "c hs traffic", &s.th_sh, 32)?;
    let s_hs = expand_label(vm, &hs32, "s hs traffic", &s.th_sh, 32)?;
    let derived = expand_label(vm, &hs32, "derived", &cu_crypto::transcript::EMPTY_HASH, 32)?;

    // MS = HKDF-Extract(salt = derived, IKM = 0^32)
    let zeros = public_bytes(vm, &[0u8; 32])?;
    let ms: Vector<U8> = hmac_sha256(vm, &derived, &zeros)?.into();

    let c_ap_0 = expand_label(vm, &ms, "c ap traffic", &s.th_sf, 32)?;
    let s_ap_0 = expand_label(vm, &ms, "s ap traffic", &s.th_sf, 32)?;

    Ok(SessionDerived {
        c_hs,
        s_hs,
        c_ap_0,
        s_ap_0,
    })
}

fn key_schedule_check<VM: Vm<Binary>>(
    vm: &mut VM,
    d: &SessionDerived,
    s: &SessionPublic,
) -> anyhow::Result<Check> {
    let joined = concat(vm, &[d.c_hs, d.s_hs])?;
    let mut expected = s.client_hs.to_vec();
    expected.extend_from_slice(&s.server_hs);
    Ok(Check::full("key_schedule", joined, expected))
}

/// Build the circuit for `params` on one side. Returns the checks to verify.
pub fn build<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    params: &Params,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    match params {
        Params::PiC1(p) => build_pi_c1(vm, role, p, witness),
        Params::PiN(p) => build_pi_n(vm, role, p, witness),
        Params::PiC2(p) => build_pi_c2(vm, role, p, witness),
        Params::PiC3(p) => build_pi_c3(vm, role, p, witness),
    }
}

fn hs_of(w: Option<&Witness>) -> Option<&[u8; 32]> {
    match w {
        Some(Witness::Hs(h)) => Some(h),
        _ => None,
    }
}

fn build_pi_c1<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiC1,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    let d = derive_session(vm, role, &p.session, hs_of(witness))?;
    let c_ap_1 = expand_label(vm, &d.c_ap_0, "traffic upd", &[], 32)?;
    let (k1, iv1) = record_keys(vm, &c_ap_1)?;

    let mut checks = vec![key_schedule_check(vm, &d, &p.session)?];

    // Keystream blocks: S[i*16 ..] = AES_K1(J0 + (i+1)), i.e. counter field i+2.
    let nblocks = p.head_len.div_ceil(16);
    for i in 0..nblocks {
        let ctr = ctr_block(vm, &iv1, 0, (i + 2) as u32)?;
        let ks: Vector<U8> = aes_block(vm, &k1, &ctr)?.into();
        let take = (p.head_len - i * 16).min(16);
        let expected = p.s[i * 16..i * 16 + take].to_vec();
        checks.push(Check::prefix(format!("S[{i}]"), ks, expected, take));
    }

    // H1 = AES_K1(0^128)
    let zero = public_bytes(vm, &[0u8; 16])?;
    let zero_arr: Array<U8, 16> = zero.try_into().expect("16 bytes");
    let h1: Vector<U8> = aes_block(vm, &k1, &zero_arr)?.into();
    checks.push(Check::full("H1", h1, p.h1.to_vec()));

    // T0 = AES_K1(J0)  (counter field 1)
    let j0 = ctr_block(vm, &iv1, 0, 1)?;
    let t0: Vector<U8> = aes_block(vm, &k1, &j0)?.into();
    checks.push(Check::full("T0", t0, p.t0.to_vec()));

    Ok(checks)
}

fn build_pi_c2<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &Window,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    let d = derive_session(vm, role, &p.session, hs_of(witness))?;
    // c_ap_2 = traffic_update(traffic_update(c_ap_0))
    let a = expand_label(vm, &d.c_ap_0, "traffic upd", &[], 32)?;
    let secret = expand_label(vm, &a, "traffic upd", &[], 32)?;
    let (k, iv) = record_keys(vm, &secret)?;

    let mut checks = vec![key_schedule_check(vm, &d, &p.session)?];
    let ct = public_bytes(vm, &p.ct_window)?;
    if p.sel_len != p.expected.len() {
        anyhow::bail!("π_C2: sel_len {} != |expected| {}", p.sel_len, p.expected.len());
    }
    let out = crate::gadgets::decrypt_window(
        vm, &k, &iv, p.seq, &ct, p.off, p.w, p.sel_start, p.sel_len,
    )?;
    let expected = public_bytes(vm, &p.expected)?;
    let eq = eq_bytes(vm, &out, &expected)?;
    checks.push(Check::full("suffix", eq, vec![1u8]));
    Ok(checks)
}

fn build_pi_c3<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiC3,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    let d = derive_session(vm, role, &p.session, hs_of(witness))?;
    let (k, iv) = record_keys(vm, &d.s_ap_0)?;

    let mut checks = vec![key_schedule_check(vm, &d, &p.session)?];
    let mut contents = Vec::with_capacity(p.records.len());
    for r in &p.records {
        let ct = public_bytes(vm, &r.ct)?;
        contents.push(crate::gadgets::decrypt_record_content(vm, &k, &iv, r.seq, &ct)?);
    }
    let all = concat(vm, &contents)?;
    let start = all
        .len()
        .checked_sub(p.expected.len())
        .and_then(|x| x.checked_sub(p.skip))
        .ok_or_else(|| anyhow::anyhow!("π_C3: records do not cover R plus skip"))?;
    let out = select(vm, &all, start, p.expected.len())?;
    let expected = public_bytes(vm, &p.expected)?;
    let eq = eq_bytes(vm, &out, &expected)?;
    checks.push(Check::full("disclosure", eq, vec![1u8]));
    Ok(checks)
}

fn build_pi_n<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    p: &PiN,
    witness: Option<&Witness>,
) -> anyhow::Result<Vec<Check>> {
    // The circuit is a fixed-size membership check over SUPPORTED_KEY_ALPHABET.
    // Fail loud rather than prove membership in an alphabet we did not build.
    if p.key_alphabet != SUPPORTED_KEY_ALPHABET {
        anyhow::bail!(
            "unsupported key alphabet {:?}: the π_N circuit is fixed to {:?}",
            p.key_alphabet,
            SUPPORTED_KEY_ALPHABET
        );
    }
    let key_bytes = match witness {
        Some(Witness::Key(k)) => Some(k.as_slice()),
        _ => None,
    };
    if role == Role::Prover {
        assert_eq!(key_bytes.expect("prover must supply key").len(), p.key_len);
    }

    let template = public_bytes(vm, &p.template)?;
    let key = secret_bytes(vm, role, p.key_len, key_bytes)?;

    // P := template with key bytes spliced in.
    let circ = splice_circuit(p.head_len, &p.key_offsets);
    let call = Call::builder(circ)
        .arg(template.to_raw())
        .arg(key.to_raw())
        .build()
        .expect("splice input length");
    let head: Vector<U8> = vm.call(call)?;

    // TLS 1.3 inner plaintext = content || content_type(0x17).
    let ct_byte = public_bytes(vm, &[0x17])?;
    let plaintext = concat(vm, &[head, ct_byte])?;

    // C1 = P XOR S
    let s = public_bytes(vm, &p.s)?;
    let c1 = xor_bytes(vm, &plaintext, &s)?;

    let mut checks = Vec::new();

    // Key alphabet membership, AND-reduced: must be 0x01. The circuit folds the
    // seven constant-zero trailer outputs away, so the decoded value is one
    // byte; `check_results` requires an exact-length match for `full` checks.
    let alph = alphabet_circuit(p.key_len);
    let call = Call::builder(alph).arg(key.to_raw()).build().unwrap();
    let ok: Vector<U8> = vm.call(call)?;
    checks.push(Check::full("key_alphabet", ok, vec![1u8]));

    // SHA256(header || C1) == C_commit
    let header = public_bytes(vm, &p.header)?;
    let mut h = Sha256::new();
    h.update(&header);
    h.update(&c1);
    let digest: Array<U8, 32> = h.finalize(vm)?;
    checks.push(Check::full("c_commit", digest.into(), p.c_commit.to_vec()));

    Ok(checks)
}
