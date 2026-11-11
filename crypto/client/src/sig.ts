// Signatures the reference client verifies: ed25519 (a sidecar's own key) and
// BIP-340 Schnorr over SHA-256 of the signed bytes (a node's Nostr key).

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'

import { schnorr } from '@noble/curves/secp256k1'

/** A Nostr pubkey as lower-case x-only hex, from 64-hex or an `npub1…`; null if neither. */
export function pubkeyHex(input: string): string | null {
  const s = input.trim()
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase()
  const lower = s.toLowerCase()
  if (!lower.startsWith('npub1') || lower.length < 12) return null
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const data: number[] = []
  for (const c of lower.slice(5)) {
    const v = CHARSET.indexOf(c)
    if (v < 0) return null
    data.push(v)
  }
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  const hrp = [...'npub'].map((c) => c.charCodeAt(0))
  for (const v of [...hrp.map((c) => c >> 5), 0, ...hrp.map((c) => c & 31), ...data]) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i]!
  }
  if (chk !== 1) return null
  let acc = 0
  let bits = 0
  const out: number[] = []
  for (const v of data.slice(0, -6)) {
    acc = ((acc << 5) | v) & 0xfff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0 || out.length !== 32) return null
  return out.map((b) => b.toString(16).padStart(2, '0')).join('')
}

function verifyEd25519Raw(json: string, sigHex: string, pubHex: string): boolean {
  try {
    const raw = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(pubHex, 'hex'),
    ])
    const key = createPublicKey({ key: raw, format: 'der', type: 'spki' })
    return cryptoVerify(null, Buffer.from(json), key, Buffer.from(sigHex, 'hex'))
  } catch {
    return false
  }
}

function verifySchnorrRaw(json: string, sigHex: string, pubHex: string): boolean {
  try {
    const msg = createHash('sha256').update(Buffer.from(json, 'utf8')).digest()
    return schnorr.verify(Buffer.from(sigHex, 'hex'), msg, Buffer.from(pubHex, 'hex'))
  } catch {
    return false
  }
}

export function verifySig(json: string, sigHex: string | undefined, pubHex: string, scheme: string | undefined): boolean {
  if (!sigHex || !pubHex) return false
  if (scheme === 'schnorr-secp256k1') return verifySchnorrRaw(json, sigHex, pubHex)
  return verifyEd25519Raw(json, sigHex, pubHex)
}
