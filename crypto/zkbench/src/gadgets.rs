//! Reusable ZK gadgets: linear (XOR/rewiring) circuits plus an in-circuit
//! HMAC-SHA256 built from `mpz-hash`'s SHA-256 and the AES-128 circuit.
//!
//! Linear circuits (XOR, select, splice, pad) add no AND gates, so they are
//! effectively free in the VOLE protocol; all the cost is SHA-256 and AES.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use mpz_circuits::{Circuit, CircuitBuilder};
use mpz_vm_core::{
    Call, CallableExt, Vm, VmError,
    memory::{
        Array, MemoryExt, Slice, ToRaw, Vector, ViewExt,
        binary::{Binary, U8},
    },
};
use mpz_hash::sha256::Sha256;

use crate::Role;

/// Which side of the protocol we are building circuits for.
// Kept in this module so the gadgets can branch on it without a cycle.

/// Most gates the circuit cache holds in all. Several families (`concat`,
/// `select`, `eq`, `splice`) take their shape from per-session lengths, so a
/// long-running process would otherwise keep one circuit per distinct
/// response shape forever.
pub const CIRCUIT_CACHE_MAX_GATES: usize = 4 << 20;
/// Most circuits the cache holds.
pub const CIRCUIT_CACHE_MAX_ENTRIES: usize = 1024;

struct CircuitCache {
    map: HashMap<(&'static str, Vec<usize>), Arc<Circuit>>,
    gates: usize,
}

static CACHE: LazyLock<Mutex<CircuitCache>> =
    LazyLock::new(|| Mutex::new(CircuitCache { map: HashMap::new(), gates: 0 }));

/// The circuit for family `family` with shape parameters `shape`, built once
/// while it stays cached.
///
/// The cache is keyed by the full `(family, shape)` tuple, so two different
/// shapes can never share an entry (a hash collision cannot hand a statement
/// a circuit of the wrong shape). It is bounded by
/// [`CIRCUIT_CACHE_MAX_GATES`] and [`CIRCUIT_CACHE_MAX_ENTRIES`]: when a new
/// circuit would exceed either, the cache is emptied first, and a circuit
/// larger than the whole budget is not cached at all. A circuit is a pure
/// function of its shape, so eviction only costs a rebuild; prover and
/// verifier get identical circuits either way.
fn cache<F>(family: &'static str, shape: &[usize], build: F) -> Arc<Circuit>
where
    F: FnOnce() -> Circuit,
{
    let key = (family, shape.to_vec());
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = guard.map.get(&key) {
        return c.clone();
    }
    let c = Arc::new(build());
    let size = c.gates().len();
    if size > CIRCUIT_CACHE_MAX_GATES {
        return c;
    }
    if guard.gates + size > CIRCUIT_CACHE_MAX_GATES || guard.map.len() >= CIRCUIT_CACHE_MAX_ENTRIES {
        guard.map.clear();
        guard.gates = 0;
    }
    guard.gates += size;
    guard.map.insert(key, c.clone());
    c
}

/// The circuit cache's current `(entries, gates)`, for tests and diagnostics.
pub fn circuit_cache_usage() -> (usize, usize) {
    let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    (guard.map.len(), guard.gates)
}

/// A constant bit as a *real* gate output (never a raw const node, which the
/// circuit builder cannot renumber).
fn cbit(b: &mut CircuitBuilder, node: mpz_circuits::Node<mpz_circuits::Feed>, bit: bool) -> mpz_circuits::Node<mpz_circuits::Feed> {
    if bit {
        let inv = b.add_inv_gate(node);
        b.add_xor_gate(node, inv)
    } else {
        b.add_xor_gate(node, node)
    }
}

/// `n`-bit XOR of two `n`-bit inputs.
pub fn xor_circuit(n_bits: usize) -> Arc<Circuit> {
    cache(
        "xor",
        &[n_bits],
        || {
            let mut b = CircuitBuilder::new();
            let a: Vec<_> = (0..n_bits).map(|_| b.add_input()).collect();
            let c: Vec<_> = (0..n_bits).map(|_| b.add_input()).collect();
            for i in 0..n_bits {
                let out = b.add_xor_gate(a[i], c[i]);
                b.add_output(out);
            }
            b.build().unwrap()
        },
    )
}

/// Key padding for HMAC: 32-byte key -> 64-byte block (`key || 0^32`).
pub fn pad_key_circuit() -> Arc<Circuit> {
    cache("pad_key", &[], || {
        let mut b = CircuitBuilder::new();
        let key: Vec<_> = (0..256).map(|_| b.add_input()).collect();
        for bit in &key {
            let out = b.add_id_gate(*bit);
            b.add_output(out);
        }
        for _ in 0..256 {
            let z = cbit(&mut b, key[0], false);
            b.add_output(z);
        }
        b.build().unwrap()
    })
}

/// Extract `len` bytes starting at byte `start` from an `in_len`-byte input.
pub fn select_circuit(in_len: usize, start: usize, len: usize) -> Arc<Circuit> {
    cache("select", &[in_len, start, len], || {
        let mut b = CircuitBuilder::new();
        let inp: Vec<_> = (0..in_len * 8).map(|_| b.add_input()).collect();
        for bit in &inp[start * 8..(start + len) * 8] {
            let out = b.add_id_gate(*bit);
            b.add_output(out);
        }
        b.build().unwrap()
    })
}

/// Concatenate several byte vectors into one contiguous output (pure rewiring).
pub fn concat_circuit(sizes: &[usize]) -> Arc<Circuit> {
    cache("concat", sizes, || {
        let mut b = CircuitBuilder::new();
        let inputs: Vec<_> = (0..sizes.iter().sum::<usize>() * 8)
            .map(|_| b.add_input())
            .collect();
        for bit in &inputs {
            let out = b.add_id_gate(*bit);
            b.add_output(out);
        }
        b.build().unwrap()
    })
}

/// Build the head plaintext `P` from a public template and a private key.
///
/// Inputs: template (`head_len` bytes) then key (`L` bytes). Outputs:
/// `head_len` bytes where each `{KEY}` position takes the next key byte.
pub fn splice_circuit(head_len: usize, key_offsets: &[usize]) -> Arc<Circuit> {
    let l = key_offsets.len();
    let mut shape = Vec::with_capacity(l + 1);
    shape.push(head_len);
    shape.extend_from_slice(key_offsets);
    cache("splice", &shape, || {
        let mut b = CircuitBuilder::new();
        let template: Vec<_> = (0..head_len * 8).map(|_| b.add_input()).collect();
        let keybits: Vec<_> = (0..l * 8).map(|_| b.add_input()).collect();
        for i in 0..head_len {
            let source = match key_offsets.iter().position(|&o| o == i) {
                Some(j) => &keybits[j * 8..j * 8 + 8],
                None => &template[i * 8..i * 8 + 8],
            };
            for bit in source {
                let out = b.add_id_gate(*bit);
                b.add_output(out);
            }
        }
        b.build().unwrap()
    })
}

/// GCM counter block: `out = (iv XOR seq) || counter`, where `iv` is 96 bits,
/// `seq` 64 bits and `counter` a public 32-bit input.
pub fn ctr_block_circuit() -> Arc<Circuit> {
    cache("ctr_block", &[], || {
        let mut b = CircuitBuilder::new();
        let iv: Vec<_> = (0..96).map(|_| b.add_input()).collect();
        let seq: Vec<_> = (0..64).map(|_| b.add_input()).collect();
        let counter: Vec<_> = (0..32).map(|_| b.add_input()).collect();
        // iv[0..32] unchanged
        for bit in &iv[0..32] {
            let out = b.add_id_gate(*bit);
            b.add_output(out);
        }
        // iv[32..96] XOR seq[0..64]
        for i in 0..64 {
            let out = b.add_xor_gate(iv[32 + i], seq[i]);
            b.add_output(out);
        }
        // counter (big-endian bytes were fed in)
        for bit in &counter {
            let out = b.add_id_gate(*bit);
            b.add_output(out);
        }
        b.build().unwrap()
    })
}

/// Byte-string equality of two `len`-byte inputs, AND-reduced to one bit.
///
/// Used so a proof reveals only *whether* a decrypted range equals the
/// expected public bytes, never the decrypted bytes themselves: a verifier
/// that chose a window over some other plaintext learns nothing beyond one bit.
pub fn eq_circuit(len: usize) -> Arc<Circuit> {
    cache("eq", &[len], || {
        let mut b = CircuitBuilder::new();
        let a: Vec<_> = (0..len * 8).map(|_| b.add_input()).collect();
        let c: Vec<_> = (0..len * 8).map(|_| b.add_input()).collect();
        let mut acc = None;
        for i in 0..len * 8 {
            let x = b.add_xor_gate(a[i], c[i]);
            let same = b.add_inv_gate(x);
            acc = Some(match acc {
                None => same,
                Some(prev) => b.add_and_gate(prev, same),
            });
        }
        let all = acc.expect("eq_circuit needs len > 0");
        // Emit a whole byte so the output is a `Vector<U8>` (1 == equal).
        b.add_output(all);
        for _ in 0..7 {
            let z = cbit(&mut b, all, false);
            b.add_output(z);
        }
        b.build().unwrap()
    })
}

/// Membership of every byte in `[A-Za-z0-9_-]`, AND-reduced to one bit.
pub fn alphabet_circuit(len: usize) -> Arc<Circuit> {
    cache("alphabet", &[len], || {
        const CHARS: &[u8] = b"-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut b = CircuitBuilder::new();
        let data: Vec<_> = (0..len * 8).map(|_| b.add_input()).collect();
        let mut byte_ok = Vec::with_capacity(len);
        for byte_idx in 0..len {
            let bits = &data[byte_idx * 8..byte_idx * 8 + 8];
            let mut terms = Vec::with_capacity(CHARS.len());
            for &c in CHARS {
                // equality = AND over bits of NOT(bit XOR const_bit)
                let mut eq_bits = Vec::with_capacity(8);
                for i in 0..8 {
                    let cbit = (c >> i) & 1 == 1;
                    let x = b.add_xor_gate(bits[i], if cbit { b.get_const_one() } else { b.get_const_zero() });
                    eq_bits.push(b.add_inv_gate(x));
                }
                let mut acc = eq_bits[0];
                for bit in &eq_bits[1..] {
                    acc = b.add_and_gate(acc, *bit);
                }
                terms.push(acc);
            }
            // OR-reduce the terms
            let mut acc = terms[0];
            for t in &terms[1..] {
                let a_xor_b = b.add_xor_gate(acc, *t);
                let a_and_b = b.add_and_gate(acc, *t);
                acc = b.add_xor_gate(a_xor_b, a_and_b);
            }
            byte_ok.push(acc);
        }
        let mut all = byte_ok[0];
        for t in &byte_ok[1..] {
            all = b.add_and_gate(all, *t);
        }
        // Emit a whole byte so the output is a `Vector<U8>` (1 == all allowed).
        b.add_output(all);
        for _ in 0..7 {
            let z = cbit(&mut b, all, false);
            b.add_output(z);
        }
        b.build().unwrap()
    })
}

// ---------------------------------------------------------------------------
// VM-level helpers
// ---------------------------------------------------------------------------

/// Allocate a public vector of bytes (both sides assign it).
pub fn public_bytes<VM: Vm<Binary>>(vm: &mut VM, data: &[u8]) -> anyhow::Result<Vector<U8>> {
    let v: Vector<U8> = vm.alloc_vec(data.len())?;
    vm.mark_public(v)?;
    vm.assign(v, data.to_vec())?;
    vm.commit(v)?;
    Ok(v)
}

/// Allocate a private (prover) / blind (verifier) vector of bytes.
pub fn secret_bytes<VM: Vm<Binary>>(
    vm: &mut VM,
    role: Role,
    len: usize,
    data: Option<&[u8]>,
) -> anyhow::Result<Vector<U8>> {
    let v: Vector<U8> = vm.alloc_vec(len)?;
    match role {
        Role::Prover => {
            let data = data.ok_or_else(|| anyhow::anyhow!("the prover needs a witness for this statement"))?;
            if data.len() != len {
                anyhow::bail!("witness is {} bytes, the statement needs {len}", data.len());
            }
            vm.mark_private(v)?;
            vm.assign(v, data.to_vec())?;
            vm.commit(v)?;
        }
        Role::Verifier => {
            vm.mark_blind(v)?;
            vm.commit(v)?;
        }
    }
    Ok(v)
}

/// XOR two equal-length byte vectors (linear, free).
pub fn xor_bytes<VM: Vm<Binary>>(
    vm: &mut VM,
    a: &Vector<U8>,
    b: &Vector<U8>,
) -> anyhow::Result<Vector<U8>> {
    if a.len() != b.len() {
        anyhow::bail!("xor_bytes: lengths {} and {} differ", a.len(), b.len());
    }
    let circ = xor_circuit(a.len() * 8);
    let call = Call::builder(circ)
        .arg(a.to_raw())
        .arg(b.to_raw())
        .build()
        .expect("xor input length");
    Ok(vm.call(call)?)
}

/// One byte, 1 iff `a == b` (both `len` bytes); nothing else is revealed.
pub fn eq_bytes<VM: Vm<Binary>>(
    vm: &mut VM,
    a: &Vector<U8>,
    b: &Vector<U8>,
) -> anyhow::Result<Vector<U8>> {
    if a.len() != b.len() || a.len() == 0 {
        anyhow::bail!("eq_bytes: lengths {} and {} differ or are zero", a.len(), b.len());
    }
    let call = Call::builder(eq_circuit(a.len()))
        .arg(a.to_raw())
        .arg(b.to_raw())
        .build()
        .expect("eq input length");
    Ok(vm.call(call)?)
}

/// XOR a vector with a constant byte string.
pub fn xor_const<VM: Vm<Binary>>(
    vm: &mut VM,
    a: &Vector<U8>,
    constant: &[u8],
) -> anyhow::Result<Vector<U8>> {
    let c = public_bytes(vm, constant)?;
    xor_bytes(vm, a, &c)
}

/// Extract `len` bytes from `a` starting at byte `start`.
pub fn select<VM: Vm<Binary>>(
    vm: &mut VM,
    a: &Vector<U8>,
    start: usize,
    len: usize,
) -> anyhow::Result<Vector<U8>> {
    if len == 0 || start.checked_add(len).is_none_or(|end| end > a.len()) {
        anyhow::bail!("select [{start}, +{len}) out of range for {} bytes", a.len());
    }
    let circ = select_circuit(a.len(), start, len);
    let call = Call::builder(circ).arg(a.to_raw()).build().unwrap();
    Ok(vm.call(call)?)
}

/// Concatenate byte vectors into one contiguous vector.
pub fn concat<VM: Vm<Binary>>(vm: &mut VM, parts: &[Vector<U8>]) -> anyhow::Result<Vector<U8>> {
    let sizes: Vec<usize> = parts.iter().map(|p| p.len()).collect();
    let circ = concat_circuit(&sizes);
    let mut builder = Call::builder(circ);
    for p in parts {
        builder = builder.arg(p.to_raw());
    }
    Ok(vm.call(builder.build().unwrap())?)
}

/// In-circuit AES-128 block encryption.
pub fn aes_block<VM: Vm<Binary>>(
    vm: &mut VM,
    key: &Array<U8, 16>,
    msg: &Array<U8, 16>,
) -> anyhow::Result<Array<U8, 16>> {
    let call = Call::builder(mpz_circuits::AES128.clone())
        .arg(key.to_raw())
        .arg(msg.to_raw())
        .build()
        .unwrap();
    Ok(vm.call(call)?)
}

/// In-circuit HMAC-SHA256 with a 32-byte key and a public message.
pub fn hmac_sha256<VM: Vm<Binary>>(
    vm: &mut VM,
    key: &Vector<U8>,
    msg: &Vector<U8>,
) -> anyhow::Result<Array<U8, 32>> {
    assert_eq!(key.len(), 32);
    let pad = Call::builder(pad_key_circuit()).arg(key.to_raw()).build().unwrap();
    let key64: Vector<U8> = vm.call(pad)?;

    let ipad = public_bytes(vm, &[0x36u8; 64])?;
    let opad = public_bytes(vm, &[0x5cu8; 64])?;
    let ipad_x = xor_bytes(vm, &key64, &ipad)?;
    let opad_x = xor_bytes(vm, &key64, &opad)?;

    let mut inner = Sha256::new();
    inner.update(&ipad_x);
    inner.update(msg);
    let inner_digest: Array<U8, 32> = inner.finalize(vm)?;

    let mut outer = Sha256::new();
    outer.update(&opad_x);
    outer.update(&inner_digest.into());
    Ok(outer.finalize(vm)?)
}

/// `HKDF-Expand-Label(secret, label, context, len)` computed in-circuit.
/// The full Expand-Label info is public; only `secret` is hidden.
pub fn expand_label<VM: Vm<Binary>>(
    vm: &mut VM,
    secret: &Vector<U8>,
    label: &str,
    context: &[u8],
    len: usize,
) -> anyhow::Result<Vector<U8>> {
    let mut info = cu_crypto::hkdf::hkdf_label(label, context, len as u16);
    info.push(0x01); // T(1)
    let msg = public_bytes(vm, &info)?;
    let full = hmac_sha256(vm, secret, &msg)?;
    if len == 32 {
        Ok(full.into())
    } else {
        select(vm, &full.into(), 0, len)
    }
}

/// Build the GCM counter block for `counter` from a 12-byte IV and 8-byte seq.
pub fn ctr_block<VM: Vm<Binary>>(
    vm: &mut VM,
    iv: &Array<U8, 12>,
    seq: u64,
    counter: u32,
) -> anyhow::Result<Array<U8, 16>> {
    let seq_bytes = public_bytes(vm, &seq.to_be_bytes())?;
    let ctr_bytes = public_bytes(vm, &counter.to_be_bytes())?;
    let circ = ctr_block_circuit();
    let call = Call::builder(circ)
        .arg(iv.to_raw())
        .arg(seq_bytes.to_raw())
        .arg(ctr_bytes.to_raw())
        .build()
        .unwrap();
    let out: Vector<U8> = vm.call(call)?;
    Ok(out.try_into().expect("16-byte counter block"))
}

/// Decrypt `w` bytes of a record starting at inner-plaintext offset `off`,
/// producing exactly the bytes at `[sel_start, sel_start+sel_len)`.
///
/// `ct_window` is the public ciphertext window `ct[off .. off+w]`.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_window<VM: Vm<Binary>>(
    vm: &mut VM,
    key: &Array<U8, 16>,
    iv: &Array<U8, 12>,
    seq: u64,
    ct_window: &Vector<U8>,
    off: usize,
    w: usize,
    sel_start: usize,
    sel_len: usize,
) -> anyhow::Result<Vector<U8>> {
    if ct_window.len() != w
        || w == 0
        || sel_len == 0
        || sel_start.checked_add(sel_len).is_none_or(|end| end > w)
        || off.checked_add(w).is_none_or(|end| end > crate::statements::MAX_INNER_PLAINTEXT)
    {
        anyhow::bail!("decrypt_window: inconsistent window (w={w}, sel={sel_start}+{sel_len})");
    }
    let block_start = off / 16;
    let prefix = off % 16;
    let nblocks = (prefix + w).div_ceil(16);

    let mut ks_blocks: Vec<Vector<U8>> = Vec::with_capacity(nblocks);
    for j in 1..=nblocks {
        // J0 has counter field 1; keystream block `j` has counter `block_start + j + 1`.
        let ctr = ctr_block(vm, iv, seq, (block_start + j + 1) as u32)?;
        let ks = aes_block(vm, key, &ctr)?;
        ks_blocks.push(ks.into());
    }
    let ks_all = concat(vm, &ks_blocks)?;
    let ks_used = select(vm, &ks_all, prefix, w)?;
    let pt = xor_bytes(vm, ct_window, &ks_used)?;
    select(vm, &pt, sel_start, sel_len)
}

/// Decrypt the tail of a record, from block-aligned inner-plaintext offset
/// `off` to its end (`ct` is that tail's ciphertext), and return its content
/// (minus the trailing content-type byte).
pub fn decrypt_record_tail<VM: Vm<Binary>>(
    vm: &mut VM,
    key: &Array<U8, 16>,
    iv: &Array<U8, 12>,
    seq: u64,
    ct: &Vector<U8>,
    off: usize,
) -> anyhow::Result<Vector<U8>> {
    if ct.len() < 2 {
        anyhow::bail!("decrypt_record_tail: record has no content");
    }
    if off.checked_add(ct.len()).is_none_or(|end| end > crate::statements::MAX_INNER_PLAINTEXT) {
        anyhow::bail!("decrypt_record_tail: {} bytes at offset {off} exceed a record", ct.len());
    }
    if off % 16 != 0 {
        anyhow::bail!("decrypt_record_tail: offset {off} is not block-aligned");
    }
    let first = off / 16;
    let nblocks = ct.len().div_ceil(16);
    let mut ks_blocks: Vec<Vector<U8>> = Vec::with_capacity(nblocks);
    for j in 1..=nblocks {
        // keystream block `first + j` has counter field `first + j + 1`.
        let ctr = ctr_block(vm, iv, seq, (first + j + 1) as u32)?;
        ks_blocks.push(aes_block(vm, key, &ctr)?.into());
    }
    let ks_all = concat(vm, &ks_blocks)?;
    let ks_used = select(vm, &ks_all, 0, ct.len())?;
    let pt = xor_bytes(vm, ct, &ks_used)?;
    select(vm, &pt, 0, ct.len() - 1)
}

/// Slice a `Vector<U8>` into a raw `Slice` view (helper for callers).
pub fn raw(v: &Vector<U8>) -> Slice {
    v.to_raw()
}

/// SHA-256 of a byte vector computed in-circuit.
pub fn sha256_bytes<VM: Vm<Binary>>(vm: &mut VM, data: &Vector<U8>) -> anyhow::Result<Array<U8, 32>> {
    let mut h = Sha256::new();
    h.update(data);
    Ok(h.finalize(vm)?)
}

/// HMAC-SHA256 keyed once: the ipad/opad blocks of a 32-byte key are
/// compressed a single time, so every further MAC under the same key costs two
/// compressions instead of four.
#[derive(Debug, Clone)]
pub struct HmacKeyed {
    inner: Sha256,
    outer: Sha256,
}

impl HmacKeyed {
    pub fn new<VM: Vm<Binary>>(vm: &mut VM, key: &Vector<U8>) -> anyhow::Result<Self> {
        assert_eq!(key.len(), 32);
        let pad = Call::builder(pad_key_circuit()).arg(key.to_raw()).build().unwrap();
        let key64: Vector<U8> = vm.call(pad)?;
        let ipad = public_bytes(vm, &[0x36u8; 64])?;
        let opad = public_bytes(vm, &[0x5cu8; 64])?;
        let ipad_x = xor_bytes(vm, &key64, &ipad)?;
        let opad_x = xor_bytes(vm, &key64, &opad)?;
        let mut inner = Sha256::new();
        inner.update(&ipad_x);
        inner.compress(vm)?;
        let mut outer = Sha256::new();
        outer.update(&opad_x);
        outer.compress(vm)?;
        Ok(Self { inner, outer })
    }

    pub fn mac<VM: Vm<Binary>>(&self, vm: &mut VM, msg: &Vector<U8>) -> anyhow::Result<Array<U8, 32>> {
        let mut inner = self.inner.clone();
        inner.update(msg);
        let d = inner.finalize(vm)?;
        let mut outer = self.outer.clone();
        outer.update(&d.into());
        Ok(outer.finalize(vm)?)
    }

    /// `HKDF-Expand-Label(secret, label, context, len)` (`len` ≤ 32) under
    /// this keyed state.
    pub fn expand_label<VM: Vm<Binary>>(
        &self,
        vm: &mut VM,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> anyhow::Result<Vector<U8>> {
        let mut info = cu_crypto::hkdf::hkdf_label(label, context, len as u16);
        info.push(0x01); // T(1)
        let msg = public_bytes(vm, &info)?;
        let full: Vector<U8> = self.mac(vm, &msg)?.into();
        if len == 32 { Ok(full) } else { select(vm, &full, 0, len) }
    }
}

/// Derive `(K, IV)` from a traffic secret with one keyed HMAC state
/// (6 compressions instead of 8).
pub fn record_keys_keyed<VM: Vm<Binary>>(
    vm: &mut VM,
    secret: &Vector<U8>,
) -> anyhow::Result<(Array<U8, 16>, Array<U8, 12>)> {
    let h = HmacKeyed::new(vm, secret)?;
    let k = h.expand_label(vm, "key", &[], 16)?;
    let iv = h.expand_label(vm, "iv", &[], 12)?;
    Ok((
        k.try_into().expect("16-byte AES key"),
        iv.try_into().expect("12-byte IV"),
    ))
}
