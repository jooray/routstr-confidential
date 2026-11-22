// Offline check of the vendored TLS fork's record rules (FORK PATCH TLS-15,
// TLS-16) and of what it accepts as a server flight (TLS-17).
//
//   node --experimental-strip-types test/tls-fork-records-check.ts
//
// In protocol v2 and v3 the node holds c_hs and s_hs (public outputs of the
// two-party key schedule), so a record sealed under s_hs is the node's, not
// the provider's. Application data is not in the handshake transcript: a
// node could put its own "response" between the ServerHello and the real
// server flight, and CertificateVerify and Finished would still verify.
//
// Checks, against a fake TLS 1.3 server driving the fork in `external` mode
// (certificates generated at run time, nothing stored):
//   - application data under s_hs is refused, before and inside the server
//     flight, and nothing reaches onApplicationData;
//   - application data under s_ap_0 after the handshake is delivered;
//   - a plaintext handshake record (during and after the handshake) and a
//     plaintext alert are refused once the handshake keys are installed;
//   - the compatibility ChangeCipherSpec and an encrypted KeyUpdate still work;
//   - one accepted flight per signature (TLS-17). The node can open the
//     flight, change it and recompute the Finished; the provider's signature
//     covers the transcript up to Certificate only. Each case below has a
//     Finished that is correct for the changed transcript: bytes after the
//     signature in CertificateVerify, an ECDSA signature in another encoding
//     than DER, a message between CertificateVerify and Finished, a message
//     type that is not part of the flight, a handshake length with its top
//     byte set, handshake bytes after the Finished in its record.
//
// Self-contained: imports only the vendored fork and its dependencies.

import * as x509 from '@peculiar/x509'

import { makeTLSClient } from '../vendor/tls/lib/index.js'
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'
import { deriveTrafficKeysForSide } from '../vendor/tls/lib/utils/decryption-utils.js'
import { packFinishMessagePacket } from '../vendor/tls/lib/utils/finish-messages.js'
import { concatenateUint8Arrays } from '../vendor/tls/lib/utils/generics.js'
import { getSignatureDataTls13 } from '../vendor/tls/lib/utils/parse-certificate.js'
import { encryptWrappedRecord } from '../vendor/tls/lib/utils/wrapped-record.js'
import { loadX509FromDer } from '../vendor/tls/lib/utils/x509.js'

setCryptoImplementation(webcryptoCrypto)
x509.cryptoProvider.set(globalThis.crypto)

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const
const HOST = 'api.venice.ai'
const SUITE = 'TLS_AES_128_GCM_SHA256'
const quiet = { trace() {}, debug() {}, info() {}, warn() {}, error() {} } as any

let failures = 0
function check(name: string, ok: boolean, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`)
  if (!ok) failures++
}
/** The promise must reject with a message matching `re`. */
async function rejects(name: string, p: Promise<unknown>, re: RegExp) {
  try {
    await p
    check(name, false, 'accepted')
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    check(name, re.test(msg), re.test(msg) ? '' : msg)
  }
}

type Issued = { cert: x509.X509Certificate; keys: CryptoKeyPair }
let serial = 1
async function issue(subject: string, opts: { issuer?: Issued; ca?: boolean; san?: string[] }): Promise<Issued> {
  const keys = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair
  const extensions: x509.Extension[] = []
  if (opts.ca !== undefined) extensions.push(new x509.BasicConstraintsExtension(opts.ca, undefined, true))
  extensions.push(
    new x509.KeyUsagesExtension(
      opts.ca ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign : x509.KeyUsageFlags.digitalSignature,
      true,
    ),
  )
  if (opts.san) {
    extensions.push(new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1']))
    extensions.push(new x509.SubjectAlternativeNameExtension(opts.san.map((value) => ({ type: 'dns' as const, value }))))
  }
  extensions.push(await x509.SubjectKeyIdentifierExtension.create(keys.publicKey))
  if (opts.issuer) extensions.push(await x509.AuthorityKeyIdentifierExtension.create(opts.issuer.keys.publicKey))
  const now = Date.now()
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: (serial++).toString(16).padStart(2, '0'),
    subject,
    issuer: opts.issuer ? opts.issuer.cert.subject : subject,
    notBefore: new Date(now - 3600_000),
    notAfter: new Date(now + 86400_000),
    publicKey: keys.publicKey,
    signingKey: opts.issuer ? opts.issuer.keys.privateKey : keys.privateKey,
    signingAlgorithm: ALG,
    extensions,
  })
  return { cert, keys }
}

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff]
const u24 = (n: number) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
const ext = (type: number, data: number[]) => [...u16(type), ...u16(data.length), ...data]
function hsMsg(type: number, body: number[] | Uint8Array): Uint8Array {
  const b = Array.from(body)
  return new Uint8Array([type, ...u24(b.length), ...b])
}
/** CertificateVerify (ecdsa_secp256r1_sha256) with the given signature bytes. */
function cvMsg(sig: number[], trailing: number[] = []): Uint8Array {
  return hsMsg(0x0f, [0x04, 0x03, ...u16(sig.length), ...sig, ...trailing])
}
/** A plaintext record. */
function plain(type: number, body: number[] | Uint8Array): Uint8Array {
  return new Uint8Array([type, 0x03, 0x03, ...u16(body.length), ...Array.from(body)])
}
async function p256Point(): Promise<Uint8Array> {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  return new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
}
/** ECDSA r‖s (WebCrypto) → DER, as TLS carries it. */
function derEcdsaSig(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    let v = Array.from(b.slice(i))
    if (v[0] & 0x80) v = [0, ...v]
    return [0x02, v.length, ...v]
  }
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))]
  return new Uint8Array([0x30, body.length, ...body])
}

/** The server side of one handshake; seals records under `secret`. */
class FakeServer {
  transcript: Uint8Array[] = []
  secret: Uint8Array
  seq = 0
  constructor(secret: Uint8Array, clientHello?: Uint8Array) {
    this.secret = secret
    if (clientHello) this.transcript.push(clientHello)
  }
  async serverHello(): Promise<Uint8Array> {
    const exts = [...ext(0x002b, [0x03, 0x04]), ...ext(0x0033, [0x00, 0x17, ...u16(65), ...Array.from(await p256Point())])]
    const body = [0x03, 0x03, ...Array.from(crypto.getRandomValues(new Uint8Array(32))), 0x00, ...u16(0x1301), 0x00, ...u16(exts.length), ...exts]
    const msg = hsMsg(0x02, body)
    this.transcript.push(msg)
    return plain(0x16, msg)
  }
  encryptedExtensions(): Uint8Array {
    const msg = hsMsg(0x08, [0x00, 0x00])
    this.transcript.push(msg)
    return msg
  }
  certificate(chain: Issued[]): Uint8Array {
    const list: number[] = []
    for (const c of chain) {
      const der = new Uint8Array(c.cert.rawData)
      list.push(...u24(der.length), ...Array.from(der), 0x00, 0x00)
    }
    const msg = hsMsg(0x0b, [0x00, ...u24(list.length), ...list])
    this.transcript.push(msg)
    return msg
  }
  /** The signer's ECDSA signature (DER) over the transcript so far. */
  async signature(signer: Issued): Promise<number[]> {
    const data = await getSignatureDataTls13(this.transcript, SUITE)
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signer.keys.privateKey, data))
    return Array.from(derEcdsaSig(raw))
  }
  async certificateVerify(signer: Issued): Promise<Uint8Array> {
    return this.add(cvMsg(await this.signature(signer)))
  }
  /** Any handshake message, as given, into the transcript. */
  add(msg: Uint8Array): Uint8Array {
    this.transcript.push(msg)
    return msg
  }
  async finished(): Promise<Uint8Array> {
    const msg = (await packFinishMessagePacket({ secret: this.secret, handshakeMessages: this.transcript, cipherSuite: SUITE })) as Uint8Array
    this.transcript.push(msg)
    return msg
  }
  /** One encrypted record of inner content type `type`. */
  async seal(content: Uint8Array, type = 0x16): Promise<Uint8Array> {
    const { encKey, iv } = await deriveTrafficKeysForSide(this.secret, SUITE)
    const { ciphertext } = (await encryptWrappedRecord(concatenateUint8Arrays([content, new Uint8Array([type])]), {
      key: encKey,
      iv,
      recordNumber: this.seq++,
      cipherSuite: SUITE,
      version: 'TLS1_3',
      recordHeaderOpts: { type: 'WRAPPED_RECORD', version: 'TLS1_2' },
    } as any)) as { ciphertext: Uint8Array }
    return plain(0x17, ciphertext)
  }
}

const root = await issue('CN=Test Root', { ca: true })
const leaf = await issue(`CN=${HOST}`, { issuer: root, ca: false, san: [HOST] })

/** A client in external mode that has processed the ServerHello. */
async function afterServerHello() {
  const written: Uint8Array[] = []
  const appData: Uint8Array[] = []
  const ended: unknown[] = []
  let handshakes = 0
  const sHs = crypto.getRandomValues(new Uint8Array(32))
  const client = makeTLSClient({
    host: HOST,
    rootCAs: [loadX509FromDer(new Uint8Array(root.cert.rawData))],
    cipherSuites: [SUITE],
    supportedProtocolVersions: ['TLS1_3'],
    namedCurves: ['SECP256R1'],
    applicationLayerProtocols: ['http/1.1'],
    logger: quiet,
    write: async ({ content }: { content: Uint8Array }) => {
      written.push(content)
    },
    onHandshake: () => {
      handshakes++
    },
    onApplicationData: (d: Uint8Array) => {
      appData.push(d)
    },
    onTlsEnd: (err?: Error) => {
      ended.push(err)
    },
    external: {
      keyShare: await p256Point(),
      onServerHello: async () => ({ clientHs: crypto.getRandomValues(new Uint8Array(32)), serverHs: sHs }),
      onServerFinished: async () => ({
        serverAp0: crypto.getRandomValues(new Uint8Array(32)),
        clientAp1: crypto.getRandomValues(new Uint8Array(32)),
      }),
    },
  } as any)
  await client.startHandshake()
  const server = new FakeServer(sHs, written[0])
  await client.handleReceivedBytes(await server.serverHello())
  return { client, server, appData, ended, handshakes: () => handshakes }
}
type Started = Awaited<ReturnType<typeof afterServerHello>>
async function flight(c: Started, from = 0) {
  const steps = [
    async () => c.server.encryptedExtensions(),
    async () => c.server.certificate([leaf]),
    async () => c.server.certificateVerify(leaf),
    async () => c.server.finished(),
  ]
  for (const step of steps.slice(from)) await c.client.handleReceivedBytes(await c.server.seal(await step()))
}
/** A client with a completed handshake, and a server sealing under s_ap_0. */
async function completed() {
  const c = await afterServerHello()
  await flight(c)
  const post = new FakeServer((c.client.getKeys() as { serverSecret: Uint8Array }).serverSecret)
  return { ...c, post }
}

const FORGED = new TextEncoder().encode(
  'HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\ndata: {"choices":[{"delta":{"content":"FORGED"}}]}\n\n',
)

{
  const c = await afterServerHello()
  await rejects(
    'application data under s_hs right after the ServerHello is refused',
    c.client.handleReceivedBytes(await c.server.seal(FORGED, 0x17)),
    /application data before the handshake completed/,
  )
  check('  nothing was delivered and the client ended', c.appData.length === 0 && c.client.hasEnded() && c.ended.length === 1)
  // The real flight, re-sealed with the next sequence numbers, completes nothing.
  await flight(c)
  check('  the real server flight after it completes nothing', c.handshakes() === 0 && c.appData.length === 0)
}
{
  const c = await afterServerHello()
  await c.client.handleReceivedBytes(await c.server.seal(c.server.encryptedExtensions()))
  await c.client.handleReceivedBytes(await c.server.seal(c.server.certificate([leaf])))
  await c.client.handleReceivedBytes(await c.server.seal(await c.server.certificateVerify(leaf)))
  await rejects(
    'application data under s_hs before the server Finished is refused',
    c.client.handleReceivedBytes(await c.server.seal(FORGED, 0x17)),
    /application data before the handshake completed/,
  )
  check('  nothing was delivered', c.appData.length === 0 && c.handshakes() === 0)
}
{
  const c = await completed()
  check('the full server flight completes the handshake (control)', c.handshakes() === 1 && !c.client.hasEnded())
  await c.client.handleReceivedBytes(await c.post.seal(FORGED, 0x17))
  check(
    'application data under s_ap_0 after the handshake is delivered (control)',
    c.appData.length === 1 && Buffer.from(c.appData[0]).equals(Buffer.from(FORGED)),
  )
}
{
  const c = await afterServerHello()
  await rejects(
    'a plaintext handshake record after the ServerHello is refused',
    c.client.handleReceivedBytes(plain(0x16, c.server.encryptedExtensions())),
    /plaintext record/,
  )
  check('  the client ended', c.client.hasEnded())
}
{
  const c = await completed()
  await rejects(
    'a plaintext KeyUpdate after the handshake is refused',
    c.client.handleReceivedBytes(plain(0x16, hsMsg(24, [0]))),
    /plaintext record/,
  )
  await c.client.handleReceivedBytes(await c.post.seal(FORGED, 0x17))
  check('  nothing is delivered after it', c.appData.length === 0 && c.client.hasEnded())
}
{
  const c = await completed()
  await rejects(
    'a plaintext close_notify after the handshake is refused',
    c.client.handleReceivedBytes(plain(0x15, [0x01, 0x00])),
    /plaintext record/,
  )
  check('  the connection ended with an error, not a clean close', c.ended.length === 1 && c.ended[0] instanceof Error)
}
{
  const c = await afterServerHello()
  await c.client.handleReceivedBytes(plain(0x14, [0x01]))
  await flight(c)
  check('the compatibility ChangeCipherSpec is still accepted', c.handshakes() === 1 && !c.client.hasEnded())
  const sAp0 = (c.client.getKeys() as { serverSecret: Uint8Array }).serverSecret
  const post = new FakeServer(sAp0)
  await c.client.handleReceivedBytes(await post.seal(hsMsg(24, [0])))
  const next = (c.client.getKeys() as { serverSecret: Uint8Array }).serverSecret
  check('an encrypted KeyUpdate still rotates the read key', !c.client.hasEnded() && !Buffer.from(next).equals(Buffer.from(sAp0)))
}

// --- one accepted flight per signature (TLS-17) ----------------------------

/** A client that has processed the flight up to Certificate. */
async function afterCertificate() {
  const c = await afterServerHello()
  await c.client.handleReceivedBytes(await c.server.seal(c.server.encryptedExtensions()))
  await c.client.handleReceivedBytes(await c.server.seal(c.server.certificate([leaf])))
  return c
}
/** Feeds `msgs` (already in the server's transcript) and then the Finished. */
async function rest(c: Started, msgs: Uint8Array[], finished = true) {
  for (const m of msgs) await c.client.handleReceivedBytes(await c.server.seal(m))
  if (finished) await c.client.handleReceivedBytes(await c.server.seal(await c.server.finished()))
}
async function refused(name: string, build: (s: FakeServer) => Promise<Uint8Array[]>, re: RegExp) {
  const c = await afterCertificate()
  await rejects(name, rest(c, await build(c.server)), re)
  check('  no handshake completed and the client ended', c.handshakes() === 0 && c.client.hasEnded())
}
const withTopLengthByte = (msg: Uint8Array) => {
  const m = msg.slice()
  m[1] = 0x01
  return m
}

await refused(
  'bytes after the signature in CertificateVerify are refused',
  async (s) => [s.add(cvMsg(await s.signature(leaf), [0xaa, 0xbb, 0xcc]))],
  /trailing bytes in CertificateVerify/,
)
const NOT_DER: [string, (der: number[]) => number[]][] = [
  ['a byte after the SEQUENCE', (der) => [...der, 0x00]],
  ['a long-form SEQUENCE length', (der) => [0x30, 0x81, der[1], ...der.slice(2)]],
  ['r with one more leading zero byte', (der) => [0x30, der[1] + 1, 0x02, der[3] + 1, 0x00, ...der.slice(4)]],
  ['a third element', (der) => [0x30, der[1] + 2, ...der.slice(2), 0x05, 0x00]],
]
for (const [what, variant] of NOT_DER) {
  await refused(
    `an ECDSA signature with ${what} is refused`,
    async (s) => [s.add(cvMsg(variant(await s.signature(leaf))))],
    /not DER encoded/,
  )
}
await refused(
  'an ECDSA signature whose r lacks its sign byte is refused',
  async (s) => {
    for (;;) {
      const der = await s.signature(leaf)
      if (der[3] === 33) return [s.add(cvMsg([0x30, der[1] - 1, 0x02, 32, ...der.slice(5)]))]
    }
  },
  /not DER encoded/,
)
const TICKET = hsMsg(0x04, [0, 0, 0, 60, 0, 0, 0, 0, 1, 0, ...u16(4), 1, 2, 3, 4, 0, 0])
for (const [what, extra] of [
  ['a message of an unknown type', hsMsg(0xfe, [1, 2, 3])],
  ['a NewSessionTicket', TICKET],
  ['a CertificateRequest', hsMsg(0x0d, [0, 0, 0])],
] as [string, Uint8Array][]) {
  await refused(
    `${what} between CertificateVerify and Finished is refused`,
    async (s) => [await s.certificateVerify(leaf), s.add(extra)],
    /between CertificateVerify and Finished/,
  )
}
{
  const c = await afterServerHello()
  await c.client.handleReceivedBytes(await c.server.seal(c.server.encryptedExtensions()))
  await rejects(
    'a message type that is not part of the server flight is refused',
    c.client.handleReceivedBytes(await c.server.seal(c.server.add(hsMsg(0xfe, [])))),
    /unexpected handshake message/,
  )
}
{
  // Read with two length bytes these are the unchanged messages; read in
  // full they are 64 kB long and do not end here.
  const c = await afterCertificate()
  await rest(c, [c.server.add(withTopLengthByte(cvMsg(await c.server.signature(leaf))))])
  check('a CertificateVerify header with its top length byte set completes nothing', c.handshakes() === 0)
  const d = await afterCertificate()
  await rest(d, [await d.server.certificateVerify(leaf)], false)
  await d.client.handleReceivedBytes(await d.server.seal(withTopLengthByte(await d.server.finished())))
  check('a Finished header with its top length byte set completes nothing', d.handshakes() === 0)
}
{
  const c = await afterCertificate()
  await rest(c, [await c.server.certificateVerify(leaf)], false)
  const record = concatenateUint8Arrays([await c.server.finished(), hsMsg(24, [0])])
  await rejects(
    'handshake bytes after the Finished in its record are refused',
    c.client.handleReceivedBytes(await c.server.seal(record)),
    /after the server Finished/,
  )
  check('  no handshake completed and the client ended', c.handshakes() === 0 && c.client.hasEnded())
}
{
  const c = await afterCertificate()
  await rest(c, [await c.server.certificateVerify(leaf)])
  check('the unchanged flight completes the handshake (control)', c.handshakes() === 1 && !c.client.hasEnded())
}

if (failures) {
  console.error(`tls-fork-records-check: ${failures} check(s) FAILED`)
  process.exit(1)
}
console.log('tls-fork-records-check: all checks passed')
