// Session driver: C side of the confidential-upstream protocol (v2,
// docs/TWOPC-DESIGN.md).
//
// C is the TLS 1.3 client of the upstream session. It runs the key schedule
// with the node as a two-party computation and gets c_ap_1 and s_ap_0; the
// node gets only K_0/IV_0, the key of the credential record, which C never
// holds.
//
// Two deployments:
//   * direct  (--sidecar http://127.0.0.1:7443): the prototype layout, C talks
//     to cu-sidecar's /session and /zk directly (sidecar signs with ed25519).
//   * node    (--node http://127.0.0.1:8000): C talks to the routstr node's
//     /v1/confidential/ws and /v1/confidential/zk proxies; the node reserves
//     the model's max cost on the bearer (--auth: sk- key or Cashu token),
//     settles the verified usage on it and signs with its Nostr key (schnorr).
//
// Pre-warm: --arm performs everything up to π_NK (setup, 2PC, TLS handshake,
// node handshake verification, π_NK on the credential record) and then waits
// for a claim; --pool N keeps N armed sessions ready.
//
// See docs/TWOPC-DESIGN.md and docs/APPROACH.md.

import { createHash, createPublicKey, randomUUID, verify as cryptoVerify } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { argv } from 'node:process'

// Temporary/low-noise tracing: `CU_TRACE=1` prints every control frame with a
// millisecond timestamp to stderr. Off by default so normal runs stay quiet.
const T0 = Date.now()
const TRACE = process.env.CU_TRACE === '1'
const trace = (label: string, extra = '') =>
  TRACE ? process.stderr.write(`[t+${String(Date.now() - T0).padStart(6)}] ${label} ${extra}\n`) : undefined

import { schnorr } from '@noble/curves/secp256k1'

import { makeTLSClient } from '../vendor/tls/lib/index.js'
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'

import { concat, hex, sha256 } from './advice.ts'
import { runZk } from './zkbridge.ts'
import { checkHeadTemplate, checkPiC2SParams, checkPiC3SParams, serverTailEpoch, type ServerPostRecord } from './params.ts'
import { TwoPc, type ApOut } from './twopc.ts'
import { ZkChan } from './zkchan.ts'

setCryptoImplementation(webcryptoCrypto)

function arg(name: string, dflt?: string): string | undefined {
  const i = argv.indexOf(name)
  return i >= 0 ? argv[i + 1] : dflt
}

const NODE = arg('--node')
const SIDECAR = arg('--sidecar', 'http://127.0.0.1:7443')!
const MODEL = arg('--model', 'mistral-small-3-2-24b-instruct')!
const MAX_TOKENS = Number(arg('--max-tokens', '12'))
const PROMPT = arg('--prompt', 'Say hi in three words.')!
const DECOY = arg('--decoy-model')
// --- adversarial GAP-1 probes (crypto/tools/adversarial-model-swap) ---------
// Craft a suffix whose model differs from the setup model, ignoring the node's
// canonical suffix — the sidecar must reject it.
const ADV_SUFFIX_MODEL = arg('--adv-suffix-model')
// Never declare the body suffix at all; harvest whatever response the sidecar
// forwards, to measure the residual exposure of a client that withholds π_C2S.
const ADV_NO_SUFFIX = argv.includes('--adv-no-suffix')
// Claim the node's canonical suffix in `body_suffix` while the body actually
// ends with ADV_SUFFIX_MODEL's suffix: π_C2S itself must then fail.
const ADV_CLAIM_CANONICAL = argv.includes('--adv-claim-canonical')
// Adversarial probe: put our own P-256 key share in the ClientHello instead
// of the joint one (we would then hold the whole ECDHE secret). The node must
// refuse to relay it.
const ADV_OWN_SHARE = argv.includes('--adv-own-keyshare')
// The only protocol version: 2 = two-party handshake (docs/TWOPC-DESIGN.md).
// Protocol v1 is retired (branch v1-poc); an offer naming it is refused.
const PROTO = 2
const ARM = argv.includes('--arm')
// Arm one session (setup, 2PC preprocessing, proof channel) and close it
// unused: with an abandon fee, the node charges exactly that fee.
const ABANDON = argv.includes('--abandon')
// Behave like a client that does not know about session fees (no echo).
const NO_ACCEPT_FEE = argv.includes('--no-accept-fee')
// π_C2S and π_C3S both run in one session. Serial (default) waits for π_C2S
// before starting π_C3S; `--parallel-proofs` lets them overlap, for the stall study.
const SERIAL_PROOFS = !argv.includes('--parallel-proofs')
const POOL = Number(arg('--pool', '0'))
// Run π_NK/π_C2S/π_C3S over the session's pre-warmed proof channel
// (`zkchan`, OT/VOLE set up while arming). `--no-zkchan` forces the per-proof
// path (fresh OT per proof), e.g. for before/after measurements.
const ZKCHAN = !argv.includes('--no-zkchan')
// The node bearer(s): an sk- key or Cashu token(s), comma-separated for --pool.
// (--escrow-token is accepted as an alias.)
const ESCROW_TOKENS = (arg('--auth') ?? arg('--escrow-token') ?? '')
  .split(',')
  .map((t) => t.trim())
  .filter(Boolean)
const VERIFY_OFFER = NODE ? !argv.includes('--no-verify-offer') : false
const RUNS = arg('--runs-dir', new URL('../../runs', import.meta.url).pathname)!
const NODE_MODE = !!NODE
// Optional pin of the node's signing key (hex x-only, e.g. from its Nostr
// announcement). Without it the offer is only self-consistent, not authentic.
const NODE_PUBKEY = arg('--node-pubkey')
let OFFER_PUBKEY: string | undefined
// Escrow (sats) the node requires for this body: MODEL at MAX_TOKENS.
let OFFER: any = null
// The signature of the offer we verified: the node settles at its rates.
let OFFER_SIG: string | undefined
/** The signed offer's fee on a completed request (msats); 0 when none. */
let SESSION_FEE = 0
/** The signed offer's fee for a session that ends unused (msats, ≥ SESSION_FEE). */
let ABANDON_FEE = 0

// ---------------------------------------------------------------------------
// Minimal message bus
// ---------------------------------------------------------------------------

class Bus {
  private pending = new Map<string, unknown[]>()
  private waiters = new Map<string, ((m: unknown) => void)[]>()
  emit(msg: any) {
    const w = this.waiters.get(msg.type)
    if (w && w.length) w.shift()!(msg)
    else {
      const p = this.pending.get(msg.type) ?? []
      p.push(msg)
      this.pending.set(msg.type, p)
    }
  }
  wait(type: string): Promise<any> {
    const p = this.pending.get(type)
    if (p && p.length) return Promise.resolve(p.shift())
    return new Promise((res) => {
      const w = this.waiters.get(type) ?? []
      w.push(res)
      this.waiters.set(type, w)
    })
  }
}

// ---------------------------------------------------------------------------
// Body construction (SPEC §5.5)
// ---------------------------------------------------------------------------

const SUFFIX_MODEL = ADV_SUFFIX_MODEL ?? MODEL
// Adversarial probe only: pin a *different* max_tokens in the body than in the
// setup (the body is what the upstream sees; the suffix check is what would
// catch it, so this matters only when the suffix is withheld).
const BODY_MAX_TOKENS = Number(arg('--adv-body-max-tokens', String(MAX_TOKENS)))
const suffix =
  `,"model":${JSON.stringify(SUFFIX_MODEL)},"max_tokens":${BODY_MAX_TOKENS},` +
  `"max_completion_tokens":${BODY_MAX_TOKENS},"n":1,"stream":true,` +
  `"stream_options":{"include_usage":true},` +
  `"venice_parameters":{"include_venice_system_prompt":false,"enable_web_search":"off"}}`
let priv = `{"messages":[{"role":"user","content":${JSON.stringify(PROMPT)}}]`
if (DECOY) priv += `,"model":${JSON.stringify(DECOY)}`
// Test hook: extra private JSON members (e.g. a field the provider rejects, to
// exercise the upstream-error path).
const PRIVATE_EXTRA = arg('--private-extra')
if (PRIVATE_EXTRA) priv += `,${PRIVATE_EXTRA}`
const bodyText = priv + suffix
const body = new TextEncoder().encode(bodyText)
const suffixBytes = new TextEncoder().encode(suffix)

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

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

function verifySig(json: string, sigHex: string | undefined, pubHex: string, scheme: string | undefined): boolean {
  if (!sigHex || !pubHex) return false
  if (scheme === 'schnorr-secp256k1') return verifySchnorrRaw(json, sigHex, pubHex)
  return verifyEd25519Raw(json, sigHex, pubHex)
}

// ---------------------------------------------------------------------------
// One session
// ---------------------------------------------------------------------------

class Session {
  readonly label: string
  readonly token: string | undefined
  readonly uuid = randomUUID()
  readonly bus = new Bus()
  ws!: WebSocket
  wsOpen = false
  private outbox: Uint8Array[] = []
  private wsResolve!: () => void
  readonly wsReady: Promise<void>
  // Set when the sidecar sends an explicit {type:"error"} (e.g. the GAP-3
  // modality gate). Every protocol wait races it so the session fails fast.
  private errRej!: (e: Error) => void
  private errP!: Promise<never>
  tls!: ReturnType<typeof makeTLSClient>
  handshakeP!: Promise<void>
  flushChain: Promise<void> = Promise.resolve()
  responseChunks: Uint8Array[] = []
  responseBytes = new Uint8Array(0)
  responseRecordCount = 0
  serverRecords: Uint8Array[] = []
  // Encrypted server records after the handshake (π_C3S derives the covered
  // records' key epoch and counts seqs from its start).
  postHandshake = false
  serverPost: ServerPostRecord[] = []
  serverPending: Uint8Array = new Uint8Array(0)
  // Set once the body is written: its records are kept for the π_C2S check.
  inBody = false
  bodyRecords: Uint8Array[] = []
  attJson: string | undefined

  trackServerRecords(bytes: Uint8Array): void {
    let buf = concat(this.serverPending, bytes)
    while (buf.length >= 5) {
      const len = (buf[3]! << 8) | buf[4]!
      if (buf.length < 5 + len) break
      if (buf[0] === 0x17) this.serverRecords.push(buf.slice(5, 5 + len))
      buf = buf.subarray(5 + len)
    }
    this.serverPending = buf.slice()
  }
  ttft = 0
  sid = ''
  ready: any = null
  log: (o: unknown) => void = () => {}
  tlsEnded = false

  constructor(label: string, token?: string) {
    this.label = label
    this.token = token
    this.wsReady = new Promise<void>((r) => (this.wsResolve = r))
    this.errP = new Promise<never>((_, rej) => (this.errRej = rej))
    this.errP.catch(() => {}) // avoid an unhandled rejection when not raced
  }

  private controlUrl(): string {
    if (NODE_MODE) {
      const base = NODE!.replace(/^http/, 'ws').replace(/\/$/, '')
      return `${base}/v1/confidential/ws?session_id=${this.uuid}&v=${PROTO}`
    }
    return `${SIDECAR.replace(/^http/, 'ws')}/session`
  }

  zkUrl(proof: string, sid: string): string {
    if (NODE_MODE) {
      const base = NODE!.replace(/^http/, 'ws').replace(/\/$/, '')
      return `${base}/v1/confidential/zk?proof=${proof}&session_id=${sid}`
    }
    return `${SIDECAR.replace(/^http/, 'ws')}/zk?proof=${proof}&sid=${sid}`
  }

  connect(): Promise<void> {
    this.ws = new WebSocket(this.controlUrl())
    this.ws.binaryType = 'arraybuffer'
    this.ws.onopen = () => {
      this.wsOpen = true
      for (const b of this.outbox) this.ws.send(b)
      this.outbox.length = 0
      this.wsResolve()
    }
    this.ws.onerror = () => {
      console.error(`[client ${this.label}] websocket error`)
      process.exit(2)
    }
    this.ws.onclose = (ev: any) => {
      // A close with a reason is a rejection (e.g. the node's escrow check);
      // surface it instead of waiting out a protocol timeout.
      const reason = ev?.reason
      if (reason) this.errRej(new Error(`connection closed: ${reason}`))
    }
    this.ws.onmessage = (ev) => {
      const d = ev.data
      if (typeof d === 'string') {
        const m = JSON.parse(d)
        process.stderr.write(`[client ${this.label}] <- ${m.type}\n`)
        trace('<-', m.type)
        if (m.type === 'error') this.errRej(new Error(`sidecar rejected: ${m.reason}`))
        this.bus.emit(m)
        return
      }
      const bytes = new Uint8Array(d as ArrayBuffer)
      this.trackServerRecords(bytes)
      this.flushChain = this.flushChain
        .then(() => this.tls.handleReceivedBytes(bytes))
        .catch((e) => console.error(`[client ${this.label}] handleReceivedBytes:`, e))
    }
    return this.wsReady
  }

  /** The TLS client; `external` hands its key schedule to the 2PC. */
  makeTls(external: any): void {
      this.tls = makeTLSClient({
        external,
        host: 'api.venice.ai',
        verifyServerCertificate: true,
        cipherSuites: ['TLS_AES_128_GCM_SHA256'],
        supportedProtocolVersions: ['TLS1_3'],
        namedCurves: ['SECP256R1'],
        applicationLayerProtocols: ['http/1.1'],
        write: (packet: { header: Uint8Array; content: Uint8Array }) => {
          const record = concat(packet.header, packet.content)
          if (this.inBody) this.bodyRecords.push(record)
          this.sendBytes(record)
        },
        onRead: (rec: { content: Uint8Array }, ctx?: { type?: string; contentType?: string }) => {
          if (!this.postHandshake || ctx?.type !== 'ciphertext') return
          this.serverPost.push({
            data: ctx.contentType === 'APPLICATION_DATA',
            keyUpdates: ctx.contentType === 'HANDSHAKE' ? countKeyUpdates(rec.content) : 0,
          })
        },
        onApplicationData: (rec: Uint8Array) => {
          if (!this.ttft) this.ttft = Date.now()
          this.responseChunks.push(rec)
          this.responseBytes = concat(this.responseBytes, rec)
          this.responseRecordCount++
        },
        onTlsEnd: () => {
          this.tlsEnded = true
        },
        onHandshake: () => {
          this.postHandshake = true
          this.handshakeDone()
        },
        logger: { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      })
  }

  private handshakeDone!: () => void
  sendText(obj: unknown) {
    this.ws.send(JSON.stringify(obj))
  }
  waitT(type: string, ms: number): Promise<any> {
    return Promise.race([this.bus.wait(type), this.errP, timeout(ms, type)])
  }
  sendBytes(b: Uint8Array) {
    if (this.wsOpen) this.ws.send(b)
    else this.outbox.push(b)
  }
  close() {
    this.zkchan?.close()
    try {
      this.ws.close()
    } catch {
      /* ignore */
    }
  }

  /** setup → ready → 2PC → TLS handshake → hs_verified. Leaves the session armed. */
  async arm(): Promise<void> {
    await this.wsReady
    const nonceC = hex(cryptoRandom(32))
    if (NODE_MODE) {
      const setup: any = {
        type: 'setup',
        nonce_c: nonceC,
        model: MODEL,
        max_tokens: MAX_TOKENS,
        len: body.length,
        armed: ARM,
      }
      setup.auth = this.token ?? ''
      if (OFFER_SIG) setup.offer_sig = OFFER_SIG
      // Accept the signed offer's fees (the node refuses a setup that does
      // not echo them).
      if (SESSION_FEE > 0 && !NO_ACCEPT_FEE) setup.session_fee_msat = SESSION_FEE
      if (ABANDON_FEE > 0 && !NO_ACCEPT_FEE) setup.abandon_fee_msat = ABANDON_FEE
      this.sendText(setup)
    } else {
      this.sendText({
        type: 'setup',
        nonce_c: nonceC,
        model: MODEL,
        max_tokens: MAX_TOKENS,
        len: body.length,
        escrow_e: 1000,
      })
    }
    this.ready = await this.waitT('ready', 30000)
    this.sid = this.ready.sid
    this.tReady = Date.now()
    console.log(`[client ${this.label}] sid=${this.sid} head_len=${this.ready.head_len}`)

    if (this.ready.v !== 2) throw new Error('node did not start a v2 session')
    this.twopc = new TwoPc()
    this.twopc.start(this.zkUrl('twopc', this.sid))
    if (ZKCHAN) {
      // The proof channel's OT/VOLE setup runs alongside the 2PC preprocessing.
      this.zkchan = new ZkChan()
      this.zkchan.start(this.zkUrl('zkchan', this.sid))
    }
    const t2pc = Date.now()
    let keyShare = await this.twopc.keyShare()
    if (ADV_OWN_SHARE) {
      const { p256 } = await import('@noble/curves/p256')
      keyShare = p256.getPublicKey(p256.utils.randomPrivateKey(), false)
    }
    this.tKeyShare = Date.now()
    this.log({ ev: 'twopc_key_share', ms: this.tKeyShare - t2pc })
    // A TLS handshake with no local ECDHE: the fork hands the key schedule to
    // the 2PC.
    this.makeTls({
      keyShare,
      onServerHello: async (serverShare: Uint8Array, thSH: Uint8Array) => {
        this.thSH = thSH
        const t = Date.now()
        const out = await this.twopc!.handshake(serverShare, thSH)
        this.tPhaseA = Date.now() - t
        return out
      },
      onServerFinished: async (thSF: Uint8Array) => {
        this.thSF = thSF
        const t = Date.now()
        this.ap = await this.twopc!.application(thSF)
        this.tPhaseB = Date.now() - t
        return { serverAp0: this.ap.serverAp0, clientAp1: this.ap.clientAp1 }
      },
    })
    this.handshakeP = new Promise<void>((res) => (this.handshakeDone = res))
    await this.tls.startHandshake()
    await Promise.race([this.handshakeP, this.errP, timeout(30000, 'handshake')])
    await this.waitT('hs_verified', 30000)
    this.tHs = Date.now()
    this.log({ ev: 'hs_verified', phase_a_ms: this.tPhaseA, phase_b_ms: this.tPhaseB })
  }

  twopc: TwoPc | undefined
  zkchan: ZkChan | undefined
  zkTimes: Record<string, any> = {}
  ap: ApOut | undefined

  /**
   * One proof, over the pre-warmed channel when it is usable, else the
   * per-proof path. Fallback only while no proof has started on the channel:
   * once one has, a channel failure ends the session (the node aborts it).
   */
  async proofV2(proof: string, cmd: 'prove' | 'verify', params: unknown, witness?: unknown): Promise<void> {
    const t = Date.now()
    const ch = this.zkchan
    if (ch && (ch.used || (await ch.ready(120_000)))) {
      const m = await ch.run(cmd, proof, params, witness)
      this.zkTimes[proof] = { via: 'zkchan', ms: Date.now() - t, inner_ms: m.ms, bytes_sent: m.bytes_sent, bytes_recv: m.bytes_recv }
      trace(`zk ${proof}`, `zkchan ${Date.now() - t}ms`)
      return
    }
    if (ch) this.log({ ev: 'zkchan_fallback', proof, err: String(ch.failure) })
    const prof = await runZk(this.zkUrl(proof, this.sid), { proof, role: cmd === 'prove' ? 'prover' : 'verifier', params, witness })
    this.zkTimes[proof] = { via: 'per-proof', ms: Date.now() - t, ...prof }
    trace(`zk ${proof}`, `per-proof ${Date.now() - t}ms`)
  }
  tKeyShare = 0
  tPhaseA = 0
  tPhaseB = 0

  thSH!: Uint8Array
  thSF!: Uint8Array
  tReady = 0
  tHs = 0
  tNkStart = 0
  tProofsReady = 0
  tRecordStart = 0
  tHeadWritten = 0
  tBodyWrite = 0
  prepared = false
  runDir = ''
  logLines: string[] = []

  /** Phase 1, safe to run while arming: π_NK on the credential record. */
  async prepareProofs(): Promise<void> {
    if (this.prepared) return
    this.runDir = `${RUNS}/${this.sid}`
    mkdirSync(this.runDir, { recursive: true })
    this.log = (o: unknown) => this.logLines.push(JSON.stringify(o))

    // π_NK: the node's head record under K_0 is the published template with
    // an alphabet key, and K_0 is the one the 2PC anchored (hk).
    this.tNkStart = Date.now()
    const commit = await this.waitT('c_commit', 60000)
    checkPiNKParams(commit.params, OFFER, this.ap!, body.length)
    await this.proofV2('pi_nk', 'verify', commit.params)
    this.log({ ev: 'pi_nk_ok' })
    this.tProofsReady = Date.now()
    this.prepared = true
  }

  /** Phase 2, request-bound: credential record, body, response, settle. */
  async finish(tClaim: number): Promise<any> {
    const runDir = this.runDir
    const logLines = this.logLines

    this.tRecordStart = Date.now()
    // The node writes epoch 0 (credential + KeyUpdate); we start epoch 1.
    this.sendText({ type: 'release_head' })
    await this.waitT('head_written', 30000)
    this.tHeadWritten = Date.now()
    this.log({ ev: 'head_written' })

    const tBodyWrite = Date.now()
    this.tBodyWrite = tBodyWrite
    // The pinned suffix in its own final record (held by the node until π_C2S).
    this.inBody = true
    await this.tls.write(body.subarray(0, body.length - suffixBytes.length))
    await this.tls.write(suffixBytes)
    this.log({ ev: 'body_sent', len: body.length })

    if (ADV_NO_SUFFIX) {
      // Malicious probe: never declare the suffix, just harvest whatever the
      // sidecar forwards before the idle upstream closes. Records the response
      // and exits without settling.
      const t0 = Date.now()
      while (!this.tlsEnded && Date.now() - t0 < 20_000) {
        await new Promise((r) => setTimeout(r, 20))
      }
      const text = Buffer.from(this.responseBytes).toString('utf8')
      writeFileSync(`${runDir}/adv-response.txt`, text)
      const hasContent = /"content":\s*"[^"]/.test(text)
      console.log(
        `ADV_NO_SUFFIX ${JSON.stringify({
          response_bytes: this.responseBytes.length,
          tls_ended: this.tlsEnded,
          has_model_output: hasContent,
          snippet: text.slice(-300),
        })}`,
      )
      return { adv: 'no-suffix', response_bytes: this.responseBytes.length, has_model_output: hasContent, sid: this.sid }
    }

    // π_C2S runs concurrently with generation and does not gate settlement on
    // the client side; a failure is logged but never stalls the receipt.
    // (A malicious client ignores the node's canonical suffix — ADV_* probes.)
    if (!ADV_SUFFIX_MODEL && this.ready.suffix !== undefined && this.ready.suffix !== suffix) {
      throw new Error('node expects a different pinned suffix than ours')
    }
    const claimed = ADV_CLAIM_CANONICAL ? new TextEncoder().encode(this.ready.suffix) : suffixBytes
    this.sendText({ type: 'body_suffix', suffix: hex(claimed) })
    const c2params = await this.waitT('zk_params', 30000)
    const lastBody = this.bodyRecords[this.bodyRecords.length - 1] ?? new Uint8Array(0)
    if (!ADV_SUFFIX_MODEL && !ADV_CLAIM_CANONICAL) {
      checkPiC2SParams(c2params.params, { h1: this.ap!.h1, seq: this.bodyRecords.length - 1, record: lastBody, suffix: suffixBytes })
    }
    const c2Promise = this.proofV2('pi_c2s', 'prove', c2params.params, { Secret: Array.from(this.ap!.clientAp1) })
      .then(() => this.log({ ev: 'pi_c2_ok' }))
      .catch((e) => this.log({ ev: 'pi_c2_fail', err: String(e) }))

    const attMsg = await Promise.race([
      this.bus.wait('attestation'),
      this.errP,
      timeout(600000, 'attestation'), // the node attests when the response ends: long answers take minutes
    ])
    const attJson: string = attMsg.a_json ?? JSON.stringify(attMsg.a)
    this.attJson = attMsg.a_json
    if (OFFER_PUBKEY && this.ready.pubkey !== OFFER_PUBKEY) {
      throw new Error('session pubkey differs from the signed offer key')
    }
    const attOk = verifySig(attJson, attMsg.sig, this.ready.pubkey, attMsg.sig_scheme)
    this.log({ ev: 'attestation', sig_ok: attOk })
    if (!attOk) throw new Error('attestation signature invalid')
    // The signed attestation must name this session and the handshake we did.
    const a = JSON.parse(attJson)
    if (a?.sid !== this.sid || a.th_sh !== hex(this.thSH) || a.th_sf !== hex(this.thSF)) {
      throw new Error('attestation names another session or handshake')
    }

    await settleFlush(this)
    // Serial mode (default): finish π_C2S before starting π_C3S. The node
    // refuses to settle without a verified π_C2S, so a failure here is fatal. The stall
    // study's `--parallel-proofs` skips this to test proof overlap.
    if (SERIAL_PROOFS) {
      await c2Promise
      if (this.logLines.some((l) => l.includes('"pi_c2_fail"'))) {
        throw new Error('π_C2S failed; the node will not settle without it')
      }
    }

    // An upstream HTTP error carries no usage event: disclose only its head
    // (status line + headers); π_C3S proves where it sits and the body stays
    // private (the node settles 4xx/503 at zero cost).
    const statusLine = Buffer.from(this.responseBytes.subarray(0, 64)).toString('latin1')
    const upstreamStatus = Number(/^HTTP\/1\.\d (\d{3})/.exec(statusLine)?.[1] ?? 0)
    if (upstreamStatus >= 400) {
      console.log(`[client ${this.label}] upstream error ${upstreamStatus}: ${Buffer.from(this.responseBytes).toString('utf8').split('\r\n\r\n')[1]?.slice(0, 200)}`)
    }
    let r: Uint8Array | null
    let skip = 0
    if (upstreamStatus >= 400) {
      const headEnd = Buffer.from(this.responseBytes).indexOf('\r\n\r\n')
      if (headEnd < 0) throw new Error('upstream error response has no head')
      r = this.responseBytes.slice(0, headEnd + 4)
      skip = this.responseBytes.length - r.length
    } else {
      r = extractR(this.responseBytes)
    }
    if (!r) throw new Error('could not extract a valid usage disclosure R')
    const tailLens: number[] = []
    let acc = 0
    for (let i = this.responseChunks.length - 1; i >= 0 && acc < r.length + skip; i--) {
      tailLens.push(this.responseChunks[i]!.length + 1)
      acc += this.responseChunks[i]!.length
    }
    const epoch = serverTailEpoch(this.serverPost, tailLens.length)
    const disclose: any = { type: 'disclose', r: hex(r), tail_lens: tailLens, skip, trailing: epoch.trailing }
    if (epoch.keyUpdates > 0) {
      disclose.key_updates = epoch.keyUpdates
      disclose.epoch_start = epoch.epochStart
    }
    this.sendText(disclose)

    const c3 = await this.waitT('zk_params', 30000)
    const handshakeRecords = this.serverRecords.length - this.serverPost.length
    checkPiC3SParams(c3.params, {
      h2: this.ap!.h2,
      serverRecords: this.serverRecords,
      r,
      skip,
      keyUpdates: epoch.keyUpdates,
      epochBase: handshakeRecords >= 0 ? handshakeRecords + epoch.epochStart : undefined,
      trailing: epoch.trailing,
    })
    await this.proofV2('pi_c3s', 'prove', c3.params, { Secret: Array.from(this.ap!.serverAp0) })
    this.twopc?.close()
    this.zkchan?.close()
    this.log({ ev: 'pi_c3_ok' })

    const terminal = await Promise.race([
      this.bus.wait('receipt').then((m) => ({ kind: 'receipt' as const, m })),
      this.bus.wait('usage').then((m) => ({ kind: 'usage' as const, m })),
      this.errP,
      timeout(60000, 'receipt/usage'),
    ])
    let receipt: any
    let receiptJson: string
    let sigHex: string | undefined
    let scheme: string | undefined
    if (terminal.kind === 'receipt') {
      // The signed bytes are the receipt; the envelope beside them is ignored.
      receiptJson = terminal.m.receipt_json ?? JSON.stringify(terminal.m.receipt)
      receipt = JSON.parse(receiptJson)
      sigHex = terminal.m.sig
      scheme = terminal.m.sig_scheme
    } else {
      // Direct-sidecar node-settles deployment: the node (absent here) would
      // have signed. Record the verified usage unsigned so the flow completes.
      receipt = { sid: this.sid, model: terminal.m.model, usage: terminal.m.usage, unsigned: true }
      receiptJson = JSON.stringify(receipt)
      sigHex = undefined
    }
    const okSig = verifySig(receiptJson, sigHex, this.ready.pubkey, scheme)
    if (terminal.kind === 'receipt') {
      if (!okSig) throw new Error('receipt signature invalid')
      if (receipt.sid !== this.sid) throw new Error(`receipt is for session ${receipt.sid}, not ${this.sid}`)
      if (this.attJson !== undefined && receipt.attestation_hash !== hex(sha256(new TextEncoder().encode(this.attJson)))) {
        throw new Error("receipt is not bound to this session's attestation")
      }
    }

    // A receipt may never name a larger session fee than the signed offer.
    if ((receipt.session_fee_msat ?? 0) > SESSION_FEE || (receipt.abandon_fee_msat ?? 0) > ABANDON_FEE) {
      throw new Error('receipt names larger fees than the signed offer')
    }
    if (upstreamStatus >= 400) {
      // A provider refusal (4xx/503) costs at most the session fee.
      const unbilled = upstreamStatus === 503 || upstreamStatus < 500
      const errOk =
        receipt.usage?.error_status === upstreamStatus && (!unbilled || (receipt.cost_msats ?? 0) <= SESSION_FEE)
      console.log(
        `[client ${this.label}] error receipt: status=${upstreamStatus} cost_msats=${receipt.cost_msats} ok=${errOk} signature_ok=${okSig}`,
      )
      if (!errOk) throw new Error('error receipt does not match the disclosed upstream error')
      return { sid: this.sid, upstream_status: upstreamStatus, cost_msats: receipt.cost_msats, receipt_sig_ok: okSig }
    }

    const text = Buffer.from(this.responseBytes).toString('utf8')
    const parts = Buffer.from(r).toString('utf8').split('data: ')
    const usageSeg = parts.length >= 2 ? parts[parts.length - 2]! : '{}'
    const ownUsage = JSON.parse(usageSeg.split('\r\n')[0]!.split('\n\n')[0]!.trim())
    const usageMatch =
      receipt.usage?.usage?.prompt_tokens === ownUsage.usage?.prompt_tokens &&
      receipt.usage?.usage?.completion_tokens === ownUsage.usage?.completion_tokens &&
      receipt.model === ownUsage.model
    // The node may charge less than the signed rates (cached input), never
    // more; the rates include any surcharge, the session fee comes on top.
    const rates = OFFER?.price_list?.[MODEL]
    const maxCost = rates
      ? Math.ceil(
          (rates.in * (ownUsage.usage?.prompt_tokens ?? 0) +
            rates.out * (ownUsage.usage?.completion_tokens ?? 0)) / 1000,
        ) + SESSION_FEE
      : Infinity
    const costOk = (receipt.cost_msats ?? 0) <= maxCost
    console.log(
      `[client ${this.label}] receipt: model=${receipt.model} cost_msats=${receipt.cost_msats} ` +
        `reserved_msats=${receipt.reserved_msats} balance_msats=${receipt.balance_msats} ` +
        `session_fee_msat=${receipt.session_fee_msat ?? 0} abandon_fee_msat=${receipt.abandon_fee_msat ?? 0} ` +
        `rate_surcharge_pct=${receipt.rate_surcharge_pct ?? 0} ` +
        `usage_match=${usageMatch} cost_ok=${costOk} signature_ok=${okSig}`,
    )
    if (!usageMatch) throw new Error('receipt usage does not match our own plaintext')
    if (!costOk) throw new Error(`receipt cost exceeds the usage at the signed rates + session fee (${maxCost} msats)`)

    const modelMatch = [...text.matchAll(/"model":"([^"]+)"/g)].map((m) => m[1])
    const effective = modelMatch[modelMatch.length - 1]
    if (effective !== MODEL) throw new Error(`effective model ${effective} != ${MODEL}`)

    this.log({ ev: 'receipt', ok_sig: okSig, receipt })
    writeFileSync(`${runDir}/client.jsonl`, logLines.join('\n') + '\n')
    writeFileSync(`${runDir}/response.txt`, text)
    writeFileSync(`${runDir}/receipt.json`, JSON.stringify(receipt, null, 2))
    if (attMsg.a) writeFileSync(`${runDir}/attestation.json`, JSON.stringify(attMsg.a, null, 2))

    const tEnd = Date.now()
    const ttftAbs = this.ttft || tEnd
    const phases = {
      ready_ms: Math.max(0, this.tReady - tClaim),
      handshake_ms: Math.max(0, this.tHs - this.tReady),
      pi_nk_ms: this.tProofsReady - this.tNkStart,
      twopc_key_share_ms: this.tKeyShare - this.tReady,
      twopc_phase_a_ms: this.tPhaseA,
      twopc_phase_b_ms: this.tPhaseB,
      twopc: this.twopc?.timings,
      record_ms: this.tHeadWritten - this.tRecordStart,
      zk: this.zkTimes,
      zkchan_ready_ms: this.zkchan?.tReady ? this.zkchan.tReady - this.zkchan.tStart : undefined,
      zkchan_setup: this.zkchan?.readyInfo?.timings,
      claim_to_body_ms: tBodyWrite - tClaim,
      upstream_ttft_ms: ttftAbs - tBodyWrite,
    }
    return {
      sid: this.sid,
      uuid: this.uuid,
      armed: ARM || POOL > 0,
      ttft_ms: ttftAbs - tClaim,
      ttft_body_ms: ttftAbs - tBodyWrite,
      total_ms: tEnd - tClaim,
      model: effective,
      receipt_sig_ok: okSig,
      usage_match: usageMatch,
      cost_ok: costOk,
      cost_msats: receipt.cost_msats,
      reserved_msats: receipt.reserved_msats,
      balance_msats: receipt.balance_msats,
      phases,
      protocol: PROTO,
      proofs: ['twopc', 'pi_nk', 'pi_c2s', 'pi_c3s'],
    }
  }
}

// ---------------------------------------------------------------------------
// R extraction
// ---------------------------------------------------------------------------

function parseChunks(b: Uint8Array): { start: number; data: Uint8Array }[] | null {
  let off = 0
  const out: { start: number; data: Uint8Array }[] = []
  for (;;) {
    let nl = -1
    for (let i = off; i + 1 < b.length; i++) {
      if (b[i] === 13 && b[i + 1] === 10) {
        nl = i
        break
      }
    }
    if (nl < 0) return null
    const line = Buffer.from(b.subarray(off, nl)).toString('ascii').trim()
    if (!/^[0-9a-fA-F]+$/.test(line)) return null
    const len = parseInt(line, 16)
    const dataStart = nl + 2
    if (len === 0) {
      if (b.length !== dataStart + 2) return null
      return out
    }
    if (b.length < dataStart + len + 2) return null
    if (b[dataStart + len] !== 13 || b[dataStart + len + 1] !== 10) return null
    out.push({ start: off, data: b.subarray(dataStart, dataStart + len) })
    off = dataStart + len + 2
  }
}

function endsWithUsageEvent(joined: Uint8Array): boolean {
  const text = Buffer.from(joined).toString('utf8')
  const tail = 'data: [DONE]\n\n'
  if (!text.endsWith(tail)) return false
  const before = text.slice(0, text.length - tail.length)
  const idx = before.lastIndexOf('data: ')
  const evText = (idx >= 0 ? before.slice(idx + 6) : before).trim()
  if (!evText) return false
  try {
    const v = JSON.parse(evText)
    return Array.isArray(v.choices) && v.choices.length === 0 && v.usage && v.usage.prompt_tokens !== undefined
  } catch {
    return false
  }
}

/** SSE data of an R that starts at "\ndata: " inside a chunk (data runs to the first CRLF). */
function dechunkLineStart(r: Uint8Array): Uint8Array | null {
  if (Buffer.from(r.subarray(0, 7)).toString('latin1') !== '\ndata: ') return null
  let end = -1
  for (let i = 0; i + 1 < r.length; i++) {
    if (r[i] === 13 && r[i + 1] === 10) {
      end = i
      break
    }
  }
  if (end < 0) return null
  const rest = parseChunks(r.subarray(end + 2))
  if (!rest) return null
  return concat(r.subarray(1, end), ...rest.map((c) => c.data))
}

function extractR(b: Uint8Array): Uint8Array | null {
  let bodyStart = 0
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) {
      bodyStart = i + 4
      break
    }
  }
  const body = b.subarray(bodyStart)
  const all = parseChunks(body)
  if (!all) return null
  // Prefer R starting at the usage event's own line ("\ndata: " inside a
  // chunk), so the proof's work follows the event, not the chunk size.
  for (let i = body.length - 7; i >= 0 && body.length - i <= 1 << 16; i--) {
    if (body[i] !== 10 || body[i + 1] !== 100) continue
    const r = body.subarray(i)
    const joined = dechunkLineStart(r)
    if (!joined || !endsWithUsageEvent(joined)) continue
    const text = Buffer.from(joined).toString('utf8')
    if (text.startsWith('data: ') && text.indexOf('\n\ndata: ') === text.lastIndexOf('\n\ndata: ')) return r
  }
  for (let i = all.length - 1; i >= 0; i--) {
    const r = body.subarray(all[i].start)
    const chunks = parseChunks(r)
    if (!chunks) continue
    const joined = concat(...chunks.map((c) => c.data))
    if (endsWithUsageEvent(joined)) return r
  }
  return null
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function cryptoRandom(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

function timeout(ms: number, what: string): Promise<never> {
  return new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${what}`)), ms))
}

async function settleFlush(s: Session): Promise<void> {
  // Let every queued handleReceivedBytes call finish so the last records
  // (with data: [DONE] and the terminal chunk) are decrypted.
  for (let i = 0; i < 200; i++) {
    const c = s.flushChain
    await c
    if (c === s.flushChain && s.tlsEnded) break
    await new Promise((r) => setTimeout(r, 5))
  }
}

function waitForGo(): Promise<void> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin })
    rl.on('line', (line) => {
      if (line.trim().toLowerCase() === 'go' || line.trim() === '') {
        rl.close()
        resolve()
      }
    })
  })
}

/**
 * π_NK: rebuild the statement from the signed offer, our body length and
 * the anchor hk our own 2PC output, so the node cannot prove a different
 * template, key placement or key.
 */
function checkPiNKParams(params: any, offer: any, ap: ApOut, bodyLen: number): void {
  const p = params?.PiNK
  if (!p) throw new Error('π_NK params missing')
  const tpl: string = offer?.head_template ?? ''
  const keyLen: number = offer?.key_length ?? p.key_len
  const alphabet: string = offer?.key_alphabet ?? '[A-Za-z0-9_-]'
  const token = `{KEY:${keyLen}}`
  if (!tpl.includes(token)) throw new Error('π_NK: template lacks key token')
  checkHeadTemplate(tpl, offer?.upstream_host ?? '')
  if ((p.key_alphabet ?? alphabet) !== alphabet) throw new Error('π_NK: key alphabet differs from the offer')
  const filled = new TextEncoder().encode(tpl.replace(token, '\u0000'.repeat(keyLen)).replace('{LEN}', String(bodyLen)))
  const offs: number[] = []
  filled.forEach((b, i) => b === 0 && offs.push(i))
  const eq = (a: ArrayLike<number>, b: ArrayLike<number>) => a.length === b.length && Array.from(a).every((x, i) => x === b[i])
  if (p.key_len !== keyLen || offs.length !== keyLen) throw new Error('π_NK: key length mismatch')
  if (!eq(p.template, filled)) throw new Error('π_NK: template differs from the published one')
  if (!eq(p.key_offsets, offs)) throw new Error('π_NK: key offsets differ from the template')
  if (p.head_len !== filled.length) throw new Error('π_NK: head_len mismatch')
  if (!eq(p.hk, ap.hk)) throw new Error('π_NK: hk is not the anchor from our 2PC')
  const n = filled.length + 1
  if (!eq(p.header, [0x17, 0x03, 0x03, (n + 16) >> 8, (n + 16) & 0xff])) throw new Error('π_NK: record header mismatch')
}

/** An offer that names another protocol than v2 (v1 is retired) is refused. */
function checkOfferVersion(offer: any): void {
  if (offer && offer.v !== undefined && offer.v !== PROTO) {
    console.error(`[client] the offer is for protocol v${offer.v}; this client speaks only v${PROTO}`)
    process.exit(4)
  }
}

async function verifyOffer(): Promise<void> {
  if (!VERIFY_OFFER) {
    try {
      if (!NODE) {
        // Direct sidecar mode: the sidecar's /offer (template, no price list).
        OFFER = await (await fetch(`${SIDECAR.replace(/\/$/, '')}/offer`)).json()
        checkOfferVersion(OFFER)
        return
      }
      const raw = await (await fetch(`${NODE!.replace(/\/$/, '')}/v1/confidential/offer`)).json()
      OFFER = raw.sig_payload ? JSON.parse(raw.sig_payload) : raw
      OFFER_SIG = raw.sig
    } catch (e) {
      console.error('[client] could not fetch the offer:', e)
    }
    checkOfferVersion(OFFER)
    return
  }
  try {
    const base = NODE!.replace(/\/$/, '')
    const resp = await fetch(`${base}/v1/confidential/offer`)
    const offer = await resp.json()
    const payload: string = offer.sig_payload ?? JSON.stringify(offer)
    const parsed = offer.sig_payload ? JSON.parse(offer.sig_payload) : offer
    const ok = verifySig(payload, offer.sig, parsed.notary_pubkey, 'schnorr-secp256k1')
    console.log(
      `[client] offer v=${parsed.v} host=${parsed.upstream_host} prewarm=${parsed.prewarm} ` +
        `models=${Object.keys(parsed.price_list ?? {}).length} sig_ok=${ok}`,
    )
    if (!ok) throw new Error('offer signature invalid')
    if (NODE_PUBKEY && parsed.notary_pubkey !== NODE_PUBKEY) {
      throw new Error('offer is not signed by the pinned node key')
    }
    OFFER_PUBKEY = parsed.notary_pubkey
    OFFER = parsed
    checkOfferVersion(OFFER)
    OFFER_SIG = offer.sig
    for (const k of ['session_fee_msat', 'abandon_fee_msat']) {
      const v = parsed[k]
      if (v !== undefined && !(Number.isSafeInteger(v) && v >= 0)) throw new Error(`offer ${k} is malformed`)
    }
    SESSION_FEE = parsed.session_fee_msat ?? 0
    ABANDON_FEE = Math.max(parsed.abandon_fee_msat ?? 0, SESSION_FEE)
    console.log(
      `[client] offer session_fee_msat=${SESSION_FEE} abandon_fee_msat=${ABANDON_FEE} ` +
        `rate_surcharge_pct=${parsed.rate_surcharge_pct ?? 0}`,
    )
  } catch (e) {
    console.error('[client] offer verification failed:', e)
    process.exit(4)
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  await verifyOffer()

  if (ABANDON) {
    const s = new Session('abandon', ESCROW_TOKENS[0])
    await s.connect()
    await s.arm()
    await s.prepareProofs()
    console.log(`ABANDONED sid=${s.sid} (armed, closed unused; abandon fee ${ABANDON_FEE} msats)`)
    s.close()
    process.exit(0)
  }

  if (ARM || POOL > 0) {
    const n = Math.max(1, POOL || 1)
    const sessions: Session[] = []
    for (let i = 0; i < n; i++) {
      const s = new Session(`pool-${i}`, ESCROW_TOKENS[i] ?? ESCROW_TOKENS[0])
      sessions.push(s)
    }
    const tArmStart = Date.now()
    await Promise.all(sessions.map((s) => s.connect()))
    await Promise.all(sessions.map((s) => s.arm()))
    // Run π_NK while arming: it is bound to the session keys and the head
    // length, not to the request content, so the claim path is just the
    // credential record + body.
    await Promise.all(sessions.map((s) => s.prepareProofs()))
    const tArmDone = Date.now()
    console.log(`ARMED pool=${n} sids=${sessions.map((s) => s.sid).join(',')}`)
    console.log('READY (send "go" on stdin to claim a session)')
    await waitForGo()
    const tClaim = Date.now()
    const out = await sessions[0]!.finish(tClaim)
    out.arm_ms = tArmDone - tArmStart
    for (const s of sessions.slice(1)) s.close()
    console.log('E2E_JSON ' + JSON.stringify(out))
    sessions[0]!.close()
    process.exit(0)
  }

  const s = new Session('single', ESCROW_TOKENS[0])
  await s.connect()
  const tClaim = Date.now()
  await s.arm()
  await s.prepareProofs()
  const out = await s.finish(tClaim)
  console.log('E2E_JSON ' + JSON.stringify(out))
  s.close()
  process.exit(out.receipt_sig_ok ? 0 : 3)
}

main().catch((e) => {
  console.error('[client] FAILED:', e)
  process.exit(1)
})

/** KeyUpdate messages (type 24) in a decrypted handshake record. */
function countKeyUpdates(content: Uint8Array): number {
  let n = 0
  let i = 0
  while (i + 4 <= content.length) {
    if (content[i] === 24) n++
    i += 4 + ((content[i + 1]! << 16) | (content[i + 2]! << 8) | content[i + 3]!)
  }
  return n
}
