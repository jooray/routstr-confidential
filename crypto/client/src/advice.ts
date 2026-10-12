// Native TLS 1.3 advice helpers (node:crypto).
//
// These mirror cu-crypto exactly and are cross-checked against the JSON
// fixtures exported by `cu-crypto-fixtures`.

import { createCipheriv, createHash, createHmac } from 'node:crypto'

export function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex')
}

export function fromHex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'hex'))
}

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

export function hmac(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', key).update(msg).digest())
}

export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmac(salt, ikm)
}

export function hkdfExpand(prk: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len)
  let t = new Uint8Array(0)
  let counter = 1
  let o = 0
  while (o < len) {
    t = hmac(prk, concat(t, info, new Uint8Array([counter])))
    const take = Math.min(t.length, len - o)
    out.set(t.subarray(0, take), o)
    o += take
    counter++
  }
  return out
}

export function hkdfLabel(label: string, context: Uint8Array, length: number): Uint8Array {
  const full = Buffer.from('tls13 ' + label, 'ascii')
  const buf = Buffer.alloc(2 + 1 + full.length + 1 + context.length)
  buf.writeUInt16BE(length, 0)
  buf.writeUInt8(full.length, 2)
  full.copy(buf, 3)
  buf.writeUInt8(context.length, 3 + full.length)
  Buffer.from(context).copy(buf, 4 + full.length)
  return new Uint8Array(buf)
}

export function expandLabel(secret: Uint8Array, label: string, context: Uint8Array, len: number): Uint8Array {
  // HKDF-Expand appends the block counter (0x01 for a single block).
  const info = hkdfLabel(label, context, len)
  return hkdfExpand(secret, info, len).subarray(0, len)
}

export function trafficUpdate(secret: Uint8Array): Uint8Array {
  return expandLabel(secret, 'traffic upd', new Uint8Array(0), 32)
}

export function aesEcbBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  const c = createCipheriv('aes-128-ecb', key, null)
  c.setAutoPadding(false)
  return new Uint8Array(Buffer.concat([c.update(Buffer.from(block)), c.final()]))
}

export function j0(iv: Uint8Array, seq: bigint): Uint8Array {
  const nonce = new Uint8Array(iv)
  const s = Buffer.alloc(8)
  s.writeBigUInt64BE(seq)
  for (let i = 0; i < 8; i++) nonce[4 + i] ^= s[i]
  const block = new Uint8Array(16)
  block.set(nonce.subarray(0, 12), 0)
  block[12] = 0
  block[13] = 0
  block[14] = 0
  block[15] = 1
  return block
}

export function ctrKeystream(key: Uint8Array, iv: Uint8Array, seq: bigint, len: number): Uint8Array {
  let ctr = j0(iv, seq)
  const blocks = Math.ceil(len / 16)
  const out = new Uint8Array(blocks * 16)
  for (let i = 0; i < blocks; i++) {
    // increment the 32-bit counter
    let c = (ctr[12] << 24) | (ctr[13] << 16) | (ctr[14] << 8) | ctr[15]
    c = (c + 1) >>> 0
    ctr[12] = (c >>> 24) & 0xff
    ctr[13] = (c >>> 16) & 0xff
    ctr[14] = (c >>> 8) & 0xff
    ctr[15] = c & 0xff
    out.set(aesEcbBlock(key, ctr), i * 16)
  }
  return out.subarray(0, len)
}

export function ghashKey(key: Uint8Array): Uint8Array {
  return aesEcbBlock(key, new Uint8Array(16))
}

export function recordHeader(ctLen: number): Uint8Array {
  const h = new Uint8Array(5)
  h[0] = 0x17
  h[1] = 0x03
  h[2] = 0x03
  h[3] = ((ctLen + 16) >> 8) & 0xff
  h[4] = (ctLen + 16) & 0xff
  return h
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]
  return out
}
