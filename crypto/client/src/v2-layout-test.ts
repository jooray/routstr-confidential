// v2 wire-layout test against the real provider (no node, no 2PC).
//
// Simulates the protocol-v2 two-party handshake locally: two random P-256
// scalars a_C, a_N, key share (a_C + a_N)·G, and the TLS 1.3 key schedule
// computed here to answer the fork's external hooks. Then it emulates N:
// the credential record at epoch-0 seq 0 under K_0/IV_0 and
// KeyUpdate(update_not_requested) at epoch-0 seq 1, after which the fork
// writes the body in epoch 1 (c_ap_1, from seq 0) with the suffix as its own
// final record, and the response is read under s_ap_0.
//
// First lists the provider's text models over a plain handshake (X25519, no
// hooks), which also checks that the fork's default path still works.
//
//   VENICE_API_KEY=… node --experimental-strip-types src/v2-layout-test.ts [--model m] [--max-tokens n]
//
// The API key is only ever placed inside the encrypted credential record; it
// is never printed, logged or written anywhere.

import { connect, type Socket } from 'node:net'
import { createCipheriv } from 'node:crypto'
import { argv } from 'node:process'
import { p256 } from '@noble/curves/p256'

import { makeTLSClient } from '../vendor/tls/lib/index.js'
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'
import { concat, expandLabel, hex, hkdfExtract, sha256, trafficUpdate } from './advice.ts'

setCryptoImplementation(webcryptoCrypto)

const HOST = 'api.venice.ai'
const arg = (k: string, d?: string) => {
  const i = argv.indexOf(k)
  return i >= 0 ? argv[i + 1] : d
}
const MAX_TOKENS = Number(arg('--max-tokens', '16'))
const quiet = { trace() {}, debug() {}, info() {}, warn() {}, error() {} } as any
const enc = new TextEncoder()
const dec = new TextDecoder()

function scrub(s: string): string {
  const k = process.env.VENICE_API_KEY
  return k ? s.split(k).join('<redacted>') : s
}

// ---------------------------------------------------------------------------
// TLS 1.3 key schedule (RFC 8446 §7.1), SHA-256
// ---------------------------------------------------------------------------
const Z32 = new Uint8Array(32)
const EMPTY_HASH = sha256(new Uint8Array(0))
const EARLY = hkdfExtract(Z32, Z32)
const DERIVED_ES = expandLabel(EARLY, 'derived', EMPTY_HASH, 32)

function gcmSeal(key: Uint8Array, iv: Uint8Array, seq: number, inner: Uint8Array): Uint8Array {
  const nonce = Buffer.from(iv)
  const s = Buffer.alloc(8)
  s.writeBigUInt64BE(BigInt(seq))
  for (let i = 0; i < 8; i++) nonce[4 + i] ^= s[i]
  const len = inner.length + 16
  const aad = Buffer.from([0x17, 0x03, 0x03, len >> 8, len & 0xff])
  const c = createCipheriv('aes-128-gcm', key, nonce)
  c.setAAD(aad)
  const ct = Buffer.concat([c.update(inner), c.final(), c.getAuthTag()])
  return concat(aad, ct)
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------
function open(): Promise<Socket> {
  return new Promise((res, rej) => {
    const s = connect(443, HOST, () => res(s))
    s.setNoDelay(true)
    s.once('error', rej)
  })
}

// ---------------------------------------------------------------------------
// HTTP/1.1 response parsing (Content-Length or chunked)
// ---------------------------------------------------------------------------
function parseHttp(raw: Uint8Array): { status: string; headers: string; body: string; complete: boolean } | undefined {
  const text = Buffer.from(raw).toString('latin1')
  const he = text.indexOf('\r\n\r\n')
  if (he < 0) return undefined
  const head = text.slice(0, he)
  const status = head.split('\r\n')[0]
  let rest = text.slice(he + 4)
  if (/^transfer-encoding:\s*chunked/im.test(head)) {
    let out = ''
    let complete = false
    while (true) {
      const le = rest.indexOf('\r\n')
      if (le < 0) break
      const n = parseInt(rest.slice(0, le), 16)
      if (Number.isNaN(n)) break
      if (n === 0) {
        complete = true
        break
      }
      if (rest.length < le + 2 + n + 2) break
      out += rest.slice(le + 2, le + 2 + n)
      rest = rest.slice(le + 2 + n + 2)
    }
    return { status, headers: head, body: Buffer.from(out, 'latin1').toString('utf8'), complete }
  }
  const m = /^content-length:\s*(\d+)/im.exec(head)
  const cl = m ? Number(m[1]) : -1
  const body = Buffer.from(rest, 'latin1')
  return { status, headers: head, body: body.toString('utf8'), complete: cl >= 0 && body.length >= cl }
}

// ---------------------------------------------------------------------------
// Plain X25519 handshake (the fork's default path), GET /api/v1/models
// ---------------------------------------------------------------------------
async function listModels(): Promise<string[]> {
  const t0 = Date.now()
  const sock = await open()
  let resp = new Uint8Array(0)
  let tHs = 0
  const done = new Promise<void>((res, rej) => {
    const tls = makeTLSClient({
      host: HOST,
      verifyServerCertificate: true,
      cipherSuites: ['TLS_AES_128_GCM_SHA256'],
      supportedProtocolVersions: ['TLS1_3'],
      namedCurves: ['X25519'],
      applicationLayerProtocols: ['http/1.1'],
      logger: quiet,
      write: ({ header, content }: any) => {
        sock.write(concat(header, content))
      },
      onApplicationData: (b: Uint8Array) => {
        resp = concat(resp, b)
        const p = parseHttp(resp)
        if (p?.complete) res()
      },
      onHandshake: async () => {
        tHs = Date.now()
        await tls.write(
          enc.encode(
            `GET /api/v1/models?type=text HTTP/1.1\r\nHost: ${HOST}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`,
          ),
        )
      },
      onTlsEnd: (e?: Error) => (e ? rej(e) : res()),
    } as any)
    let chain = Promise.resolve()
    sock.on('data', (d) => {
      chain = chain.then(() => tls.handleReceivedBytes(new Uint8Array(d))).catch(rej)
    })
    sock.on('close', () => chain.then(() => res()))
    tls.startHandshake().catch(rej)
  })
  await Promise.race([done, new Promise((_, rej) => setTimeout(() => rej(new Error('plain handshake timeout')), 20000))])
  sock.destroy()
  const p = parseHttp(resp)
  if (!p) throw new Error('plain handshake: no HTTP response')
  const ids: string[] = JSON.parse(p.body).data.map((m: any) => m.id)
  console.log(`[plain] X25519 handshake ${tHs - t0} ms, total ${Date.now() - t0} ms; ${p.status}; ${ids.length} text models`)
  return ids
}

// ---------------------------------------------------------------------------
// v2 layout test
// ---------------------------------------------------------------------------
async function runV2(model: string) {
  const apiKey = process.env.VENICE_API_KEY
  if (!apiKey) throw new Error('VENICE_API_KEY not set')
  const n = p256.CURVE.n
  const scalar = () => BigInt('0x' + hex(p256.utils.randomPrivateKey()))
  const aC = scalar()
  const aN = scalar()
  const G = p256.ProjectivePoint.BASE
  // P = P_C + P_N
  const P = G.multiply(aC).add(G.multiply(aN))
  if (!P.equals(G.multiply((aC + aN) % n))) throw new Error('key share mismatch')
  const keyShare = P.toRawBytes(false)

  // Secrets the 2PC would produce (here: computed in the clear, locally).
  let MS: Uint8Array | undefined
  let cAp0: Uint8Array | undefined
  const T: Record<string, number> = {}
  const t0 = Date.now()

  const suffix =
    `,"model":${JSON.stringify(model)},"max_tokens":${MAX_TOKENS},` +
    `"max_completion_tokens":${MAX_TOKENS},"n":1,"stream":true,` +
    `"stream_options":{"include_usage":true},` +
    `"venice_parameters":{"enable_web_search":"off","include_venice_system_prompt":false}}`
  const priv = `{"messages":[{"role":"user","content":"Say hello in five words."}]`
  const bodyPriv = enc.encode(priv)
  const bodySuffix = enc.encode(suffix)
  const head = enc.encode(
    `POST /api/v1/chat/completions HTTP/1.1\r\nHost: ${HOST}\r\nAuthorization: Bearer ${apiKey}\r\n` +
      `Content-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n` +
      `Content-Length: ${bodyPriv.length + bodySuffix.length}\r\n\r\n`,
  )

  const sock = await open()
  T.tcp = Date.now() - t0
  const wire: { dir: string; desc: string; len: number }[] = []
  let resp = new Uint8Array(0)
  let respRecords = 0
  let ttfb = 0
  let phase = 'handshake'
  let clientHello: Uint8Array | undefined

  const done = new Promise<void>((res, rej) => {
    const tls = makeTLSClient({
      host: HOST,
      verifyServerCertificate: true,
      cipherSuites: ['TLS_AES_128_GCM_SHA256'],
      supportedProtocolVersions: ['TLS1_3'],
      applicationLayerProtocols: ['http/1.1'],
      logger: quiet,
      external: {
        keyShare,
        async onServerHello(S: Uint8Array, thSH: Uint8Array) {
          T.serverHello = Date.now() - t0
          // ECtF simulation: Q_C = a_C·S, Q_N = a_N·S, x = x(Q_C + Q_N).
          const Sp = p256.ProjectivePoint.fromHex(S)
          const Q = Sp.multiply(aC).add(Sp.multiply(aN))
          const x = Q.toRawBytes(false).slice(1, 33)
          const HS = hkdfExtract(DERIVED_ES, x)
          MS = hkdfExtract(expandLabel(HS, 'derived', EMPTY_HASH, 32), Z32)
          const msgs = tls.getHandshakeMessages()
          clientHello = msgs[0]
          if (hex(sha256(msgs[0], msgs[1])) !== hex(thSH)) throw new Error('thSH mismatch')
          return {
            clientHs: expandLabel(HS, 'c hs traffic', thSH, 32),
            serverHs: expandLabel(HS, 's hs traffic', thSH, 32),
          }
        },
        async onServerFinished(thSF: Uint8Array) {
          T.serverFinished = Date.now() - t0
          cAp0 = expandLabel(MS!, 'c ap traffic', thSF, 32)
          return {
            serverAp0: expandLabel(MS!, 's ap traffic', thSF, 32),
            clientAp1: trafficUpdate(cAp0),
          }
        },
      },
      write: ({ header, content }: any) => {
        const rec = concat(header, content)
        const desc =
          phase === 'body' ? 'epoch 1 (c_ap_1) body record' : header[0] === 0x16 ? 'ClientHello' : 'client Finished (c_hs)'
        wire.push({ dir: 'C→U', desc, len: rec.length })
        sock.write(rec)
      },
      onApplicationData: (b: Uint8Array) => {
        if (!ttfb) ttfb = Date.now() - t0
        respRecords++
        resp = concat(resp, b)
        const p = parseHttp(resp)
        if (p?.complete) res()
      },
      onHandshake: async () => {
        try {
          T.handshake = Date.now() - t0
          const k = tls.getKeys()!
          if (k.recordSendCount !== 0 || k.recordRecvCount !== 0) throw new Error('counters not reset')
          // N: epoch 0 under K_0 / IV_0 = Expand-Label(c_ap_0, "key"/"iv").
          const K0 = expandLabel(cAp0!, 'key', new Uint8Array(0), 16)
          const IV0 = expandLabel(cAp0!, 'iv', new Uint8Array(0), 12)
          const cred = gcmSeal(K0, IV0, 0, concat(head, new Uint8Array([0x17])))
          const ku = gcmSeal(K0, IV0, 1, new Uint8Array([0x18, 0x00, 0x00, 0x01, 0x00, 0x16]))
          sock.write(cred)
          wire.push({ dir: 'N→U', desc: 'epoch 0 seq 0 credential record (K_0)', len: cred.length })
          sock.write(ku)
          wire.push({ dir: 'N→U', desc: 'epoch 0 seq 1 KeyUpdate(update_not_requested)', len: ku.length })
          // C: body in epoch 1 from seq 0; the suffix is its own final record.
          phase = 'body'
          await tls.write(bodyPriv)
          await tls.write(bodySuffix)
          T.bodySent = Date.now() - t0
          phase = 'response'
        } catch (e) {
          rej(e)
        }
      },
      onTlsEnd: (e?: Error) => (e ? rej(e) : res()),
    } as any)
    let chain = Promise.resolve()
    sock.on('data', (d) => {
      chain = chain.then(() => tls.handleReceivedBytes(new Uint8Array(d))).catch(rej)
    })
    sock.on('close', () => chain.then(() => res()))
    sock.on('error', rej)
    tls.startHandshake().catch(rej)
  })
  await Promise.race([done, new Promise((_, rej) => setTimeout(() => rej(new Error('v2 timeout')), 60000))])
  T.total = Date.now() - t0
  T.ttfb = ttfb
  sock.destroy()

  if (clientHello) describeClientHello(clientHello)
  for (const w of wire) console.log(`[v2] wire ${w.dir} ${w.desc} (${w.len} B)`)
  const p = parseHttp(resp)
  if (!p) throw new Error('v2: no HTTP response')
  console.log(`[v2] status: ${p.status}  (${respRecords} application-data records, complete=${p.complete})`)
  let content = ''
  let usage: unknown
  for (const line of p.body.split('\n')) {
    if (!line.startsWith('data: ') || line.includes('[DONE]')) continue
    try {
      const ev = JSON.parse(line.slice(6))
      content += ev.choices?.[0]?.delta?.content ?? ''
      if (ev.usage) usage = ev.usage
    } catch {
      /* partial */
    }
  }
  if (!p.status.includes(' 200')) console.log(`[v2] body: ${scrub(p.body.slice(0, 500))}`)
  console.log(`[v2] content: ${JSON.stringify(content)}`)
  console.log(`[v2] usage: ${JSON.stringify(usage)}`)
  console.log(`[v2] timings (ms from TCP connect start): ${JSON.stringify(T)}`)
  return p.status.includes(' 200') && !!usage
}

function describeClientHello(ch: Uint8Array) {
  // handshake header(4) version(2) random(32) sid
  let o = 4 + 2 + 32
  o += 1 + ch[o]
  const csLen = (ch[o] << 8) | ch[o + 1]
  const suites = hex(ch.slice(o + 2, o + 2 + csLen))
  o += 2 + csLen
  o += 1 + ch[o]
  const extEnd = o + 2 + ((ch[o] << 8) | ch[o + 1])
  o += 2
  const exts: string[] = []
  while (o < extEnd) {
    const t = (ch[o] << 8) | ch[o + 1]
    const l = (ch[o + 2] << 8) | ch[o + 3]
    const d = ch.slice(o + 4, o + 4 + l)
    if (t === 0x0a) exts.push(`supported_groups=${hex(d.slice(2))}`)
    else if (t === 0x33) exts.push(`key_share=[group ${hex(d.slice(2, 4))}, ${(d[4] << 8) | d[5]} B, total ${d.length - 2} B]`)
    else exts.push(`0x${t.toString(16).padStart(4, '0')}`)
    o += 4 + l
  }
  console.log(`[v2] ClientHello suites=${suites} ext: ${exts.join(' ')}`)
}

async function main() {
  const ids = await listModels()
  const pref = arg('--model') ?? ['llama-3.2-3b', 'qwen3-4b', 'venice-uncensored'].find((m) => ids.includes(m)) ?? ids[0]
  console.log(`[v2] model ${pref}, max_tokens ${MAX_TOKENS}`)
  const ok = await runV2(pref)
  console.log(ok ? 'RESULT: OK' : 'RESULT: FAIL')
  process.exit(ok ? 0 : 1)
}

main().catch((e) => {
  console.error('ERROR:', scrub(String(e?.stack ?? e)))
  process.exit(1)
})
