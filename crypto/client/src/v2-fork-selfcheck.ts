// Offline self-check of the fork's v2 hooks (external key schedule).
//
//   node --experimental-strip-types src/v2-fork-selfcheck.ts
//
// Checks: the ClientHello shape in external mode (one secp256r1 key share,
// supported_groups = [secp256r1], one suite, TLS 1.3 only, no PSK /
// early_data / psk_key_exchange_modes); HelloRetryRequest and a non-P-256
// server share are rejected before any hook runs; bad options are refused;
// the v1 ClientHello is unchanged in shape.

import { p256 } from '@noble/curves/p256'

import { makeTLSClient } from '../vendor/tls/lib/index.js'
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'
import { concat, hex } from './advice.ts'

setCryptoImplementation(webcryptoCrypto)

const quiet = { trace() {}, debug() {}, info() {}, warn() {}, error() {} } as any
let failures = 0
function check(name: string, ok: boolean, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`)
  if (!ok) failures++
}

const HRR_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex')

type Hello = { suites: string[]; exts: Map<number, Uint8Array> }
function parseClientHello(rec: Uint8Array): Hello {
  // record header(5) handshake header(4) version(2) random(32)
  const ch = rec.slice(5)
  let o = 4 + 2 + 32
  o += 1 + ch[o]
  const csLen = (ch[o] << 8) | ch[o + 1]
  const suites: string[] = []
  for (let i = 0; i < csLen; i += 2) suites.push(hex(ch.slice(o + 2 + i, o + 4 + i)))
  o += 2 + csLen
  o += 1 + ch[o]
  const extEnd = o + 2 + ((ch[o] << 8) | ch[o + 1])
  o += 2
  const exts = new Map<number, Uint8Array>()
  while (o < extEnd) {
    const t = (ch[o] << 8) | ch[o + 1]
    const l = (ch[o + 2] << 8) | ch[o + 3]
    if (exts.has(t)) throw new Error(`duplicate extension ${t}`)
    exts.set(t, ch.slice(o + 4, o + 4 + l))
    o += 4 + l
  }
  if (o !== extEnd || extEnd !== ch.length) throw new Error('ClientHello length mismatch')
  return { suites, exts }
}

function u16(n: number) {
  return new Uint8Array([n >> 8, n & 0xff])
}
function ext(type: number, data: Uint8Array) {
  return concat(u16(type), u16(data.length), data)
}
/** A plaintext ServerHello record (TLS 1.3, suite 0x1301). */
function serverHelloRecord(random: Uint8Array, keyShareExt: Uint8Array): Uint8Array {
  const exts = concat(ext(0x002b, new Uint8Array([0x03, 0x04])), ext(0x0033, keyShareExt))
  const body = concat(
    new Uint8Array([0x03, 0x03]),
    random,
    new Uint8Array([0x20]),
    new Uint8Array(32),
    new Uint8Array([0x13, 0x01, 0x00]),
    u16(exts.length),
    exts,
  )
  const hs = concat(new Uint8Array([0x02, 0, body.length >> 8, body.length & 0xff]), body)
  return concat(new Uint8Array([0x16, 0x03, 0x03]), u16(hs.length), hs)
}

function newExternal(keyShare: Uint8Array, opts: Record<string, unknown> = {}) {
  const writes: Uint8Array[] = []
  const calls: string[] = []
  const tls = makeTLSClient({
    host: 'api.venice.ai',
    applicationLayerProtocols: ['http/1.1'],
    logger: quiet,
    write: ({ header, content }: any) => {
      writes.push(concat(header, content))
    },
    external: {
      keyShare,
      async onServerHello() {
        calls.push('onServerHello')
        return { clientHs: new Uint8Array(32), serverHs: new Uint8Array(32) }
      },
      async onServerFinished() {
        calls.push('onServerFinished')
        return { serverAp0: new Uint8Array(32), clientAp1: new Uint8Array(32) }
      },
    },
    ...opts,
  } as any)
  return { tls, writes, calls }
}

async function rejects(p: Promise<unknown>, re: RegExp): Promise<string> {
  try {
    await p
    return 'did not throw'
  } catch (e: any) {
    return re.test(String(e?.message)) ? '' : `wrong error: ${e?.message}`
  }
}
function throwsSync(f: () => unknown, re: RegExp): string {
  try {
    f()
    return 'did not throw'
  } catch (e: any) {
    return re.test(String(e?.message)) ? '' : `wrong error: ${e?.message}`
  }
}

async function main() {
  const keyShare = p256.ProjectivePoint.BASE.multiply(
    BigInt('0x' + hex(p256.utils.randomPrivateKey())),
  ).toRawBytes(false)

  // 1. ClientHello shape (external)
  {
    const { tls, writes } = newExternal(keyShare)
    await tls.startHandshake()
    const h = parseClientHello(writes[0])
    check('external: one cipher suite TLS_AES_128_GCM_SHA256', h.suites.length === 1 && h.suites[0] === '1301', h.suites.join(','))
    const groups = h.exts.get(0x000a)!
    check('external: supported_groups = [secp256r1]', hex(groups) === '00020017', hex(groups))
    const ks = h.exts.get(0x0033)!
    const ksOk =
      ks.length === 2 + 4 + 65 &&
      ((ks[0] << 8) | ks[1]) === 69 &&
      hex(ks.slice(2, 4)) === '0017' &&
      ((ks[4] << 8) | ks[5]) === 65 &&
      hex(ks.slice(6)) === hex(keyShare)
    check('external: exactly one key share = given P-256 point', ksOk)
    check('external: supported_versions = [TLS 1.3]', hex(h.exts.get(0x002b)!) === '020304')
    check('external: no pre_shared_key / early_data / psk_key_exchange_modes',
      !h.exts.has(0x0029) && !h.exts.has(0x002a) && !h.exts.has(0x002d))
    check('external: ALPN http/1.1', h.exts.has(0x0010))
  }

  // 2. v1 ClientHello unchanged in shape
  {
    const writes: Uint8Array[] = []
    const tls = makeTLSClient({
      host: 'api.venice.ai',
      cipherSuites: ['TLS_AES_128_GCM_SHA256'],
      supportedProtocolVersions: ['TLS1_3'],
      namedCurves: ['X25519'],
      applicationLayerProtocols: ['http/1.1'],
      logger: quiet,
      write: ({ header, content }: any) => {
        writes.push(concat(header, content))
      },
    } as any)
    await tls.startHandshake()
    const h = parseClientHello(writes[0])
    const ks = h.exts.get(0x0033)!
    check('v1: X25519 key share, psk_key_exchange_modes kept',
      hex(h.exts.get(0x000a)!) === '0002001d' && hex(ks.slice(2, 4)) === '001d' && h.exts.has(0x002d))
  }

  // 3. HelloRetryRequest rejected, no hook called
  {
    const { tls, calls } = newExternal(keyShare)
    await tls.startHandshake()
    const err = await rejects(tls.handleReceivedBytes(serverHelloRecord(HRR_RANDOM, new Uint8Array([0x00, 0x17]))), /HelloRetryRequest/)
    check('external: HelloRetryRequest rejected', !err && calls.length === 0 && tls.hasEnded(), err)
  }

  // 4. server picks X25519 → rejected before onServerHello
  {
    const { tls, calls } = newExternal(keyShare)
    await tls.startHandshake()
    const x25519 = p256.utils.randomPrivateKey() // any 32 bytes is a valid X25519 public value
    const err = await rejects(
      tls.handleReceivedBytes(serverHelloRecord(new Uint8Array(32).fill(7), concat(u16(0x001d), u16(32), x25519))),
      /secp256r1/,
    )
    check('external: non-P-256 server share rejected', !err && calls.length === 0, err)
  }

  // 5. server P-256 share → onServerHello gets the raw point and th_SH
  {
    let got: Uint8Array | undefined
    let thSH: Uint8Array | undefined
    const S = p256.ProjectivePoint.BASE.multiply(5n).toRawBytes(false)
    const t2 = makeTLSClient({
      host: 'api.venice.ai',
      applicationLayerProtocols: ['http/1.1'],
      logger: quiet,
      write: () => {},
      external: {
        keyShare,
        async onServerHello(s: Uint8Array, th: Uint8Array) {
          got = s
          thSH = th
          return { clientHs: new Uint8Array(32).fill(1), serverHs: new Uint8Array(32).fill(2) }
        },
        async onServerFinished() {
          throw new Error('unreachable')
        },
      },
    } as any)
    await t2.startHandshake()
    await t2.handleReceivedBytes(serverHelloRecord(new Uint8Array(32).fill(9), concat(u16(0x0017), u16(65), S)))
    const { createHash } = await import('node:crypto')
    const msgs = t2.getHandshakeMessages()
    const expTh = createHash('sha256').update(msgs[0]).update(msgs[1]).digest('hex')
    const hs = t2.getHandshakeSecrets()
    check('external: onServerHello(serverShare, thSH) and secrets installed',
      !!got && hex(got) === hex(S) && !!thSH && hex(thSH) === expTh &&
      hex(t2.getTranscriptHashes().thSH!) === expTh &&
      hs.masterSecret === undefined && hs.clientSecret[0] === 1 && hs.serverSecret[0] === 2)
  }

  // 6. bad options
  check('external: 33-byte key share refused', !throwsSync(() => newExternal(new Uint8Array(33)), /65-byte/))
  check('external: two cipher suites refused',
    !throwsSync(() => newExternal(keyShare, { cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'] }), /exactly one/))
  check('external: TLS 1.2 refused',
    !throwsSync(() => newExternal(keyShare, { supportedProtocolVersions: ['TLS1_3', 'TLS1_2'] }), /TLS 1.3 only/))
  {
    const off = keyShare.slice()
    off[64] ^= 1
    const { tls } = newExternal(off)
    const err = await rejects(tls.startHandshake(), /./)
    check('external: off-curve key share refused at startHandshake', !err, err)
  }
  {
    const { tls } = newExternal(keyShare)
    const err = await rejects(tls.startHandshake({ psk: {} as any }), /PSK/)
    check('external: PSK refused', !err, err)
  }

  console.log(failures ? `${failures} FAILED` : 'all checks passed')
  process.exit(failures ? 1 : 0)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
