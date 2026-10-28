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
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { argv } from 'node:process'
import { fileURLToPath } from 'node:url'

// Temporary/low-noise tracing: `CU_TRACE=1` prints every control frame with a
// millisecond timestamp to stderr. Off by default so normal runs stay quiet.
const T0 = Date.now()
const TRACE = process.env.CU_TRACE === '1'
const trace = (label: string, extra = '') =>
  TRACE ? process.stderr.write(`[t+${String(Date.now() - T0).padStart(6)}] ${label} ${extra}\n`) : undefined

import { schnorr } from '@noble/curves/secp256k1'

/**
 * A node-chosen value as it may appear on the terminal: a number or a plain
 * token as is, anything else truncated, JSON-quoted and ASCII only (no
 * terminal escapes).
 */
export function shown(v: unknown, max = 120): string {
  if (typeof v === 'number' || typeof v === 'boolean' || v === undefined || v === null) return String(v)
  let s = typeof v === 'string' ? v : (JSON.stringify(v) ?? String(v))
  if (/^[A-Za-z0-9_.:/+-]+$/.test(s) && s.length <= max) return s
  if (s.length > max) s = `${s.slice(0, max)}...`
  return termSafe(JSON.stringify(s))
}

/**
 * Text for the terminal: control and format characters (escape sequences,
 * bidi overrides, line separators) escaped, newlines too unless kept.
 */
export function termSafe(s: string, keepNewlines = false): string {
  return s.replace(/[\p{C}\p{Zl}\p{Zp}]/gu, (c) => {
    if (keepNewlines && c === '\n') return c
    const cp = c.codePointAt(0)!
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, '0')}`
  })
}

/** An error for the terminal: its message escaped and bounded (the stack only under CU_TRACE). */
const errText = (e: unknown): string => {
  const text = e instanceof Error ? (TRACE && e.stack ? e.stack : `${e.name}: ${e.message}`) : String(e)
  return termSafe(text.length > 2000 ? `${text.slice(0, 2000)}...` : text, TRACE)
}

/** The protocol sid: a 32-byte digest in lowercase hex. */
export const SID_RE = /^[0-9a-f]{64}$/

/** Evidence files hold plaintext (prompt, response, receipt): owner-only. */
const writePrivate = (path: string, data: string | Uint8Array) => writeFileSync(path, data, { mode: 0o600 })

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
// Chat with an image input: --attach PATH puts the file in the private body as
// a data URI image part (the node never sees it; the provider bills it as
// prompt tokens, provider-profile-check.py A13). Needs a vision model.
const ATTACH = arg('--attach')
// Image generation (docs/CONFIDENTIAL-IMAGES.md): --image [--count N]
// [--variant <id>] (node offer) or [--resolution 1K|2K|4K] (direct sidecar).
const IMAGE = argv.includes('--image')
const IMAGE_COUNT = Number(arg('--count', '1'))
const IMAGE_VARIANT = arg('--variant')
const IMAGE_RESOLUTION = arg('--resolution')
// Adversarial image probes: pin a different count in the body suffix than the
// setup names, and accept the response whatever its status (a dishonest client).
const ADV_IMAGE_COUNT = arg('--adv-image-count') === undefined ? undefined : Number(arg('--adv-image-count'))
const ADV_ACCEPT_ANY = argv.includes('--adv-accept-any')
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
// Skipping the offer signature check is for tests against a throwaway node
// only, as in the SDK: it needs ROUTSTR_CONFIDENTIAL_INSECURE_TESTING=1.
if (NODE && argv.includes('--no-verify-offer') && process.env.ROUTSTR_CONFIDENTIAL_INSECURE_TESTING !== '1') {
  console.error('[client] --no-verify-offer needs ROUTSTR_CONFIDENTIAL_INSECURE_TESTING=1 (tests only)')
  process.exit(2)
}
const VERIFY_OFFER = NODE ? !argv.includes('--no-verify-offer') : false
const RUNS = arg('--runs-dir', new URL('../../runs', import.meta.url).pathname)!
const NODE_MODE = !!NODE
// Pin of the node's signing key (hex x-only, e.g. from its Nostr
// announcement; also CU_NODE_PUBKEY). Without it the offer is only
// self-consistent, not authentic, so it is required for a node off this host
// unless --allow-unpinned.
const NODE_PUBKEY = arg('--node-pubkey') ?? (process.env.CU_NODE_PUBKEY || undefined)
if (NODE) {
  let url: URL | undefined
  try {
    url = new URL(NODE)
  } catch {}
  const host = (url?.hostname ?? '').replace(/^\[|\]$/g, '').toLowerCase()
  const local = host === 'localhost' || host === '::1' || /^127\./.test(host)
  // The setup carries the bearer (an sk- key or Cashu token): only an
  // encrypted transport may take it off this host (as in the SDK).
  const encrypted = url?.protocol === 'https:' || host.endsWith('.onion')
  if (!url || !/^https?:$/.test(url.protocol)) {
    console.error(`[client] --node ${shown(NODE)} is not an http(s) URL`)
    process.exit(2)
  }
  if (!local && !encrypted && !argv.includes('--allow-insecure-transport')) {
    console.error('[client] a remote node must be https (or onion): the setup sends your credential (--allow-insecure-transport to override)')
    process.exit(2)
  }
  if (!local && VERIFY_OFFER && !NODE_PUBKEY && !argv.includes('--allow-unpinned')) {
    console.error("[client] a remote node needs --node-pubkey (or CU_NODE_PUBKEY): without it the offer's own key is not authenticated (--allow-unpinned to override)")
    process.exit(2)
  }
}
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
const IMAGE_MIME: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' }
function userContent(): unknown {
  if (!ATTACH) return PROMPT
  const mime = IMAGE_MIME[ATTACH.split('.').pop()!.toLowerCase()]
  if (!mime) throw new Error(`--attach: not an image file (${Object.keys(IMAGE_MIME).join(', ')}): ${ATTACH}`)
  const url = `data:${mime};base64,${readFileSync(ATTACH).toString('base64')}`
  return [{ type: 'text', text: PROMPT }, { type: 'image_url', image_url: { url } }]
}
let priv = `{"messages":[{"role":"user","content":${JSON.stringify(userContent())}}]`
if (DECOY) priv += `,"model":${JSON.stringify(DECOY)}`
// Test hook: extra private JSON members (e.g. a field the provider rejects, to
// exercise the upstream-error path).
const PRIVATE_EXTRA = arg('--private-extra')
if (PRIVATE_EXTRA) priv += `,${PRIVATE_EXTRA}`
let suffix = ''
let bodyText = ''
let body = new Uint8Array(0)
let suffixBytes = new Uint8Array(0)

/** Compact JSON with object members sorted (the sidecar's serde_json form). */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

/** The chat suffix the offer's `chat` block defines (docs/CHAT-SUFFIX.md). */
export function renderChatSuffix(chat: any, model: string, maxTokens: number): string {
  const parts = [`"model":${JSON.stringify(model)}`]
  for (const k of chat.cap_keys) parts.push(`${JSON.stringify(k)}:${maxTokens}`)
  for (const [k, v] of chat.fixed_pins) parts.push(`${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `,${parts.join(',')}}`
}

const CAP_KEYS = ['max_tokens', 'max_completion_tokens', 'max_output_tokens']
const PIN_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/
const pinValueOk = (v: unknown): boolean =>
  typeof v === 'boolean' ||
  (typeof v === 'number' && Number.isSafeInteger(v)) ||
  (typeof v === 'string' && /^[\x20-\x7e]*$/.test(v) && !/["\\]/.test(v)) ||
  (Array.isArray(v) && v.every(pinValueOk)) ||
  (v !== null && typeof v === 'object' && !Array.isArray(v) && Object.entries(v).every(([k, x]) => PIN_KEY.test(k) && pinValueOk(x)))
/** A pin that switches something off: `false`, `"off"`, `[]`, or a non-empty object of those. */
const pinIsOff = (v: unknown): boolean =>
  v === false || v === 'off' || (Array.isArray(v) && v.length === 0) ||
  (v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length > 0 && Object.values(v).every(pinIsOff))
/** Key prefixes under which `false` turns a feature on. */
const NEGATING_PREFIXES = ['disable', 'no_', 'skip', 'without', 'exclude', 'omit', 'hide']
/** Key words naming a protection: pinning one can only switch it off, so it stays the provider's default. */
const PROTECTION_WORDS = ['safe', 'moderat', 'filter', 'nsfw', 'censor', 'guard']
/** The first pin key, at any depth, that is negating or names a protection, or null. */
export function refusedPinKey(k: string, v: unknown): string | null {
  const l = k.toLowerCase()
  if (NEGATING_PREFIXES.some((p) => l.startsWith(p)) || PROTECTION_WORDS.some((w) => l.includes(w))) return k
  return refusedMemberKey(v)
}
function refusedMemberKey(v: unknown): string | null {
  const members: [string | null, unknown][] = Array.isArray(v)
    ? v.map((x) => [null, x])
    : v !== null && typeof v === 'object' ? Object.entries(v) : []
  for (const [m, x] of members) {
    const bad = m === null ? refusedMemberKey(x) : refusedPinKey(m, x)
    if (bad !== null) return bad
  }
  return null
}

/** Why the offer's chat block is outside the policy every client applies, or null. */
export function chatBlockProblem(offer: any): string | null {
  const c = offer?.chat
  if (!c || typeof c !== 'object' || !Array.isArray(c.cap_keys) || !Array.isArray(c.fixed_pins)) return 'no chat block'
  if (c.cap_keys.length === 0) return 'no cap key'
  const seen = new Set<string>()
  for (const k of c.cap_keys) {
    if (!CAP_KEYS.includes(k) || seen.has(k)) return `cap key ${JSON.stringify(k)}`
    seen.add(k)
  }
  for (const p of c.fixed_pins) {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== 'string') return 'a malformed pin'
    const [k, v] = p
    if (!PIN_KEY.test(k) || k === 'model' || CAP_KEYS.includes(k) || seen.has(k)) return `pin key ${JSON.stringify(k)}`
    seen.add(k)
    if (!pinValueOk(v)) return `pin ${k} outside the grammar`
    const refused = refusedPinKey(k, v)
    if (refused !== null) return `pin key ${JSON.stringify(refused)} negates or names a protection`
    const ok = k === 'stream' ? v === true
      : k === 'n' ? v === 1
      : k === 'stream_options' ? canonicalJson(v) === '{"include_usage":true}'
      : pinIsOff(v)
    if (!ok) return `pin ${k}=${JSON.stringify(v)} is not allowed`
  }
  if (!seen.has('stream') || !seen.has('stream_options')) return 'stream and stream_options must be pinned'
  const pins = c.fixed_pins.map(([k, v]: [string, unknown]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')
  if (pins.length > 1024) return 'pins too long'
  const keys = ['model', ...c.cap_keys, ...c.fixed_pins.map((p: [string, unknown]) => p[0])]
  if (JSON.stringify(offer.suffix_keys) !== JSON.stringify(keys)) return `suffix_keys ${JSON.stringify(offer.suffix_keys)} are not ${JSON.stringify(keys)}`
  return null
}

/** Build the chat body once the offer is known: private messages + pinned suffix. */
function setupChatBody(): void {
  if (chatBlockProblem(OFFER)) throw new Error(`the offer's chat block is refused: ${chatBlockProblem(OFFER)}`)
  suffix = renderChatSuffix(OFFER.chat, SUFFIX_MODEL, BODY_MAX_TOKENS)
  bodyText = priv + suffix
  body = new TextEncoder().encode(bodyText)
  suffixBytes = new TextEncoder().encode(suffix)
}

/** The offer's images block: the node's signed one, or the sidecar's endpoint. */
function imagesOffer(): any {
  const im = OFFER?.images ?? OFFER?.endpoints?.images
  if (!im) throw new Error('offer_no_images: the offer has no images endpoint')
  checkImagesBlock(im)
  return im
}

/** The variant pin keys a client lets the node pin (the price axes). */
const VARIANT_PIN_KEYS = new Set(['resolution', 'quality', 'format'])

/**
 * The node signs the images block, but its pins reach the provider as the
 * request's last word: a fixed pin may only switch a provider extra off
 * (`false` or `[]`), a variant may only pin a price axis to a value the
 * offer's parameter space lists, and the numbers stay in the ranges the relay
 * enforces. Anything else is refused rather than rendered.
 */
export function checkImagesBlock(im: any): void {
  const bad = (why: string): never => {
    throw new Error(`offer_malformed: images block ${why}`)
  }
  const countKey = im.count_key ?? 'variants'
  if (typeof countKey !== 'string' || !countKey) bad('count_key')
  if (!(Number.isSafeInteger(im.max_count) && im.max_count >= 1 && im.max_count <= 4)) bad('max_count must be 1..4')
  if (im.response_idle_s !== undefined && !(Number.isSafeInteger(im.response_idle_s) && im.response_idle_s >= 30 && im.response_idle_s <= 600)) {
    bad('response_idle_s must be 30..600')
  }
  const space = im.param_space ?? {}
  if (typeof space !== 'object' || Array.isArray(space)) bad('param_space')
  for (const [k, v] of Object.entries(space)) {
    if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) bad(`param_space.${k}`)
  }
  const fixed: unknown[] = im.fixed_pins ?? []
  if (!Array.isArray(fixed)) bad('fixed_pins')
  const fixedKeys = new Set<string>()
  for (const pin of fixed) {
    if (!Array.isArray(pin) || pin.length !== 2 || typeof pin[0] !== 'string') bad('fixed_pins entry')
    const [k, v] = pin as [string, unknown]
    if (!(v === false || (Array.isArray(v) && v.length === 0))) bad(`fixed pin ${k} does not switch an extra off`)
    if (refusedPinKey(k, v) !== null) bad(`fixed pin ${k} negates or names a protection`)
    if (k === 'model' || k === countKey || fixedKeys.has(k)) bad(`fixed pin ${k} repeats a pinned key`)
    fixedKeys.add(k)
  }
  for (const [model, variants] of Object.entries(im.price_list ?? {})) {
    if (!Array.isArray(variants) || variants.length === 0) bad(`price_list.${model}`)
    const ids = new Set<string>()
    for (const v of variants as any[]) {
      if (typeof v?.id !== 'string' || ids.has(v.id)) bad(`variant ids of ${model}`)
      ids.add(v.id)
      if (!(Number.isSafeInteger(v.msat_per_image) && v.msat_per_image > 0)) bad(`${model}/${v.id} msat_per_image`)
      if (v.max_count !== undefined && !(Number.isSafeInteger(v.max_count) && v.max_count >= 1 && v.max_count <= im.max_count)) {
        bad(`${model}/${v.id} max_count`)
      }
      const keys = new Set<string>()
      for (const pin of v.pins ?? []) {
        if (!Array.isArray(pin) || pin.length !== 2) bad(`${model}/${v.id} pin`)
        const [k, val] = pin
        if (!VARIANT_PIN_KEYS.has(k) || keys.has(k) || fixedKeys.has(k)) bad(`${model}/${v.id} pins ${k}`)
        if (typeof val !== 'string' || !(space[k] ?? []).includes(val)) bad(`${model}/${v.id} pins ${k} outside param_space`)
        keys.add(k)
      }
    }
  }
}

/** The pinned image suffix (docs/CONFIDENTIAL-IMAGES.md §0.3), byte-exact. */
export function renderImagesSuffix(im: any, model: string, count: number, pins: [string, unknown][]): string {
  const parts = [`"model":${JSON.stringify(model)}`, `${JSON.stringify(im.count_key)}:${JSON.stringify(count)}`]
  for (const [k, v] of [...(im.fixed_pins ?? []), ...pins]) parts.push(`${JSON.stringify(k)}:${JSON.stringify(v)}`)
  return `,${parts.join(',')}}`
}

let IMAGE_PINS: [string, unknown][] = []
let IMAGE_VARIANT_ID: string | undefined
let IMAGE_MSAT = 0

/** Build the image body once the offer is known: private prompt + suffix. */
function setupImageBody(): void {
  const im = imagesOffer()
  const variants: any[] | undefined = im.price_list?.[MODEL]
  const chosen = variants ? (IMAGE_VARIANT ? variants.find((x) => x.id === IMAGE_VARIANT) : variants[0]) : undefined
  // A variant may allow fewer images per request than the offer (4K: one).
  const maxCount = Math.min(im.max_count, chosen?.max_count ?? im.max_count)
  if (!(Number.isSafeInteger(IMAGE_COUNT) && IMAGE_COUNT >= 1 && IMAGE_COUNT <= maxCount)) {
    throw new Error(`--count must be 1..${maxCount}`)
  }
  if (variants) {
    const v = chosen
    if (!v) throw new Error(`no offered variant ${IMAGE_VARIANT ?? ''} for ${MODEL}`)
    IMAGE_PINS = v.pins
    IMAGE_VARIANT_ID = v.id
    IMAGE_MSAT = v.msat_per_image
  } else {
    if (IMAGE_RESOLUTION) IMAGE_PINS.push(['resolution', IMAGE_RESOLUTION])
    IMAGE_PINS.push(['format', 'webp'])
  }
  suffix = renderImagesSuffix(im, SUFFIX_MODEL, ADV_IMAGE_COUNT ?? IMAGE_COUNT, IMAGE_PINS)
  let p = `{"prompt":${JSON.stringify(PROMPT)}`
  if (PRIVATE_EXTRA) p += `,${PRIVATE_EXTRA}`
  bodyText = p + suffix
  body = new TextEncoder().encode(bodyText)
  suffixBytes = new TextEncoder().encode(suffix)
}

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
  cCommitHex: string | undefined

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
      // The node's per-session /zk token (from `ready`): the sid alone admits nothing.
      const token = typeof this.ready?.zk_token === 'string' ? `&zk_token=${encodeURIComponent(this.ready.zk_token)}` : ''
      return `${base}/v1/confidential/zk?proof=${encodeURIComponent(proof)}&session_id=${encodeURIComponent(sid)}${token}`
    }
    return `${SIDECAR.replace(/^http/, 'ws')}/zk?proof=${encodeURIComponent(proof)}&sid=${encodeURIComponent(sid)}`
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
      if (reason) this.errRej(new Error(`connection closed: ${shown(reason, 300)}`))
    }
    this.ws.onmessage = (ev) => {
      const d = ev.data
      if (typeof d === 'string') {
        const m = JSON.parse(d)
        process.stderr.write(`[client ${this.label}] <- ${shown(m.type)}\n`)
        trace('<-', shown(m.type))
        if (m.type === 'error') this.errRej(new Error(`sidecar rejected: ${shown(m.reason, 300)}`))
        this.bus.emit(m)
        return
      }
      const bytes = new Uint8Array(d as ArrayBuffer)
      this.trackServerRecords(bytes)
      this.flushChain = this.flushChain
        .then(() => this.tls.handleReceivedBytes(bytes))
        .catch((e) => console.error(`[client ${this.label}] handleReceivedBytes: ${errText(e)}`))
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
      const setup: any = IMAGE
        ? { type: 'setup', kind: 'images', nonce_c: nonceC, model: MODEL, variant: IMAGE_VARIANT_ID, count: IMAGE_COUNT, len: body.length }
        : {
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
      this.sendText(
        IMAGE
          ? { type: 'setup', kind: 'images', nonce_c: nonceC, model: MODEL, count: IMAGE_COUNT, suffix, len: body.length, escrow_e: 1000 }
          : {
              type: 'setup',
              nonce_c: nonceC,
              model: MODEL,
              max_tokens: MAX_TOKENS,
              len: body.length,
              escrow_e: 1000,
            },
      )
    }
    this.ready = await this.waitT('ready', 30000)
    // The sid names the run directory and goes into URLs: only the digest form.
    if (typeof this.ready?.sid !== 'string' || !SID_RE.test(this.ready.sid)) {
      throw new Error(`the node's sid ${shown(this.ready?.sid)} is not a 64-digit hex digest`)
    }
    this.sid = this.ready.sid
    this.tReady = Date.now()
    console.log(`[client ${this.label}] sid=${this.sid} head_len=${shown(this.ready.head_len)}`)

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
    mkdirSync(this.runDir, { recursive: true, mode: 0o700 })
    this.log = (o: unknown) => this.logLines.push(JSON.stringify(o))

    // π_NK: the node's head record under K_0 is the published template with
    // an alphabet key, and K_0 is the one the 2PC anchored (hk).
    this.tNkStart = Date.now()
    const commit = await this.waitT('c_commit', 60000)
    checkPiNKParams(commit.params, IMAGE ? { ...OFFER, head_template: imagesOffer().head_template } : OFFER, this.ap!, body.length)
    // The attestation must later name the commitment π_NK proves; the frame
    // has to carry exactly it.
    this.cCommitHex = hex(Uint8Array.from(commit.params.PiNK.c_commit))
    if (commit.c_commit !== this.cCommitHex) throw new Error("c_commit: the frame's commitment is not the one π_NK proves")
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
      writePrivate(`${runDir}/adv-response.txt`, text)
      const hasContent = /"content":\s*"[^"]/.test(text) || /"images"\s*:\s*\[\s*"/.test(text)
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
    if (IMAGE && this.ready.suffix === undefined) throw new Error('the node named no pinned suffix for this image session')
    if (!ADV_SUFFIX_MODEL && ADV_IMAGE_COUNT === undefined && this.ready.suffix !== undefined && this.ready.suffix !== suffix) {
      throw new Error('node expects a different pinned suffix than ours')
    }
    const claimed = ADV_CLAIM_CANONICAL ? new TextEncoder().encode(this.ready.suffix) : suffixBytes
    this.sendText({ type: 'body_suffix', suffix: hex(claimed) })
    const c2params = await this.waitT('zk_params', 30000)
    const lastBody = this.bodyRecords[this.bodyRecords.length - 1] ?? new Uint8Array(0)
    if (!ADV_SUFFIX_MODEL && ADV_IMAGE_COUNT === undefined && !ADV_CLAIM_CANONICAL) {
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
    if (!this.cCommitHex || a.c_commit !== this.cCommitHex) {
      throw new Error('attestation names a different head-record commitment')
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
    // Interim 1xx heads are skipped; the final head is the status. (The
    // template never asks for one, so an interim head before an error means
    // the error head cannot start the first record: it is not disclosed.)
    const finalHead = finalHeadOffset(this.responseBytes)
    const statusLine = Buffer.from(this.responseBytes.subarray(finalHead, finalHead + 64)).toString('latin1')
    const upstreamStatus = Number(/^HTTP\/1\.\d (\d{3})/.exec(statusLine)?.[1] ?? 0)
    if (finalHead > 0 && upstreamStatus >= 400) throw new Error('an interim 1xx head precedes the error head; it cannot be disclosed')
    if (upstreamStatus >= 400) {
      console.log(`[client ${this.label}] upstream error ${upstreamStatus}: ${shown(Buffer.from(this.responseBytes).toString('utf8').split('\r\n\r\n')[1], 200)}`)
    }
    // Only a 2xx is accepted; any other status either discloses its error head
    // (>= 400) or fails without accepting. ADV_ACCEPT_ANY is the dishonest client.
    if (IMAGE && ((upstreamStatus >= 200 && upstreamStatus < 300) || (ADV_ACCEPT_ANY && upstreamStatus > 0))) {
      return await this.acceptImages(runDir, tClaim, tBodyWrite, attMsg, attOk)
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
      tailLens,
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
      if (receipt.sid !== this.sid) throw new Error(`receipt is for session ${shown(receipt.sid)}, not ${this.sid}`)
      if (this.attJson !== undefined && receipt.attestation_hash !== hex(sha256(new TextEncoder().encode(this.attJson)))) {
        throw new Error("receipt is not bound to this session's attestation")
      }
    }

    // A receipt may never name a larger session fee than the signed offer.
    if ((receipt.session_fee_msat ?? 0) > SESSION_FEE || (receipt.abandon_fee_msat ?? 0) > ABANDON_FEE) {
      throw new Error('receipt names larger fees than the signed offer')
    }
    if (upstreamStatus >= 400) {
      // A request the provider rejected (a 4xx other than those below) costs
      // the abandon fee: the node did the 2PC for it. Refusals for the
      // provider's capacity (429, 503) or the node's own key or account (401,
      // 402, 403) cost the session fee. Any other error costs at most the
      // reservation, which for an image session is its flat price plus the
      // larger fee.
      const cost = receipt.cost_msats
      let costOk: boolean
      // Less than the rule allows only favours us, so the checks are bounds.
      if ([401, 402, 403, 429, 503].includes(upstreamStatus)) costOk = cost <= SESSION_FEE
      else if (upstreamStatus < 500) costOk = cost <= Math.max(SESSION_FEE, ABANDON_FEE)
      else {
        const bound = IMAGE
          ? IMAGE_MSAT * IMAGE_COUNT + ABANDON_FEE
          : Math.max(SESSION_FEE, typeof receipt.reserved_msats === 'number' ? receipt.reserved_msats : 0)
        costOk = Number.isSafeInteger(cost) && cost >= 0 && cost <= bound
      }
      // An image session's error receipt carries its terms.
      const termsOk =
        !IMAGE ||
        !NODE_MODE ||
        (receipt.kind === 'images' && receipt.model === MODEL && receipt.variant === IMAGE_VARIANT_ID && receipt.count === IMAGE_COUNT)
      const errOk = receipt.usage?.error_status === upstreamStatus && (!NODE_MODE || (costOk && termsOk))
      console.log(
        `[client ${this.label}] error receipt: status=${upstreamStatus} cost_msats=${shown(receipt.cost_msats)} ok=${errOk} signature_ok=${okSig}`,
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
    const maxCost = rates ? maxUsageCharge(rates, ownUsage.usage ?? {}) + SESSION_FEE : Infinity
    const costOk = (receipt.cost_msats ?? 0) <= maxCost
    console.log(
      `[client ${this.label}] receipt: model=${shown(receipt.model)} cost_msats=${shown(receipt.cost_msats)} ` +
        `reserved_msats=${shown(receipt.reserved_msats)} balance_msats=${shown(receipt.balance_msats)} ` +
        `session_fee_msat=${shown(receipt.session_fee_msat ?? 0)} abandon_fee_msat=${shown(receipt.abandon_fee_msat ?? 0)} ` +
        `rate_surcharge_pct=${shown(receipt.rate_surcharge_pct ?? 0)} ` +
        `usage_match=${usageMatch} cost_ok=${costOk} signature_ok=${okSig}`,
    )
    if (!usageMatch) throw new Error('receipt usage does not match our own plaintext')
    if (!costOk) throw new Error(`receipt cost exceeds the usage at the signed rates + session fee (${maxCost} msats)`)

    const modelMatch = [...text.matchAll(/"model":"([^"]+)"/g)].map((m) => m[1])
    const effective = modelMatch[modelMatch.length - 1]
    if (effective !== MODEL) throw new Error(`effective model ${shown(effective)} != ${MODEL}`)

    this.log({ ev: 'receipt', ok_sig: okSig, receipt })
    writePrivate(`${runDir}/client.jsonl`, logLines.join('\n') + '\n')
    writePrivate(`${runDir}/response.txt`, text)
    writePrivate(`${runDir}/receipt.json`, JSON.stringify(receipt, null, 2))
    if (attMsg.a) writePrivate(`${runDir}/attestation.json`, JSON.stringify(attMsg.a, null, 2))

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

  /** A successful image response: accept it (no disclosure) and check the flat charge. */
  async acceptImages(runDir: string, tClaim: number, tBodyWrite: number, attMsg: any, attOk: boolean): Promise<any> {
    this.sendText({ type: 'accept' })
    const terminal = await Promise.race([
      this.bus.wait('receipt').then((m) => ({ kind: 'receipt' as const, m })),
      this.bus.wait('usage').then((m) => ({ kind: 'usage' as const, m })),
      this.errP,
      timeout(60000, 'receipt/usage'),
    ])
    this.twopc?.close()
    this.zkchan?.close()
    let receipt: any
    let okSig = false
    if (terminal.kind === 'receipt') {
      const receiptJson = terminal.m.receipt_json ?? JSON.stringify(terminal.m.receipt)
      receipt = JSON.parse(receiptJson)
      okSig = verifySig(receiptJson, terminal.m.sig, this.ready.pubkey, terminal.m.sig_scheme)
      if (!okSig) throw new Error('receipt signature invalid')
      if (receipt.sid !== this.sid) throw new Error(`receipt is for session ${shown(receipt.sid)}, not ${this.sid}`)
      if (this.attJson !== undefined && receipt.attestation_hash !== hex(sha256(new TextEncoder().encode(this.attJson)))) {
        throw new Error("receipt is not bound to this session's attestation")
      }
    } else {
      receipt = { sid: this.sid, model: terminal.m.model, usage: terminal.m.usage, unsigned: true }
    }
    // Flat charge: exactly the signed per-image price × count + the session fee.
    let costOk = true
    if (NODE_MODE) {
      const want = IMAGE_MSAT * IMAGE_COUNT + SESSION_FEE
      costOk = receipt.cost_msats === want && receipt.variant === IMAGE_VARIANT_ID && receipt.count === IMAGE_COUNT
      if (!costOk) throw new Error(`image receipt charges ${shown(receipt.cost_msats)}, not ${want} for ${IMAGE_COUNT} × ${IMAGE_VARIANT_ID}`)
    } else if (receipt.usage?.flat !== true || receipt.usage?.count !== IMAGE_COUNT) {
      throw new Error('usage frame is not a flat charge for the pinned count')
    }
    // The charge was fixed at setup and accepting cannot change it (not
    // accepting would cost the reservation), so what the response is short of
    // is reported, not thrown: framing, image count, the provider's echo.
    const warnings: string[] = []
    let json: any = {}
    try {
      json = JSON.parse(Buffer.from(responseBody(this.responseBytes)).toString('utf8'))
    } catch (e) {
      warnings.push(`response body is incomplete or not JSON: ${String(e)}`)
    }
    const shape = imagesOffer().response_shape
    const images: string[] = shape === 'venice' ? json.images ?? [] : (json.data ?? []).map((d: any) => d.b64_json)
    if (images.length !== IMAGE_COUNT) warnings.push(`${images.length} of ${IMAGE_COUNT} images returned`)
    // What the provider says it ran (Venice echoes the effective request).
    const meta: Record<string, unknown> = { ...json }
    delete meta.images
    delete meta.data
    writePrivate(`${runDir}/response-meta.json`, JSON.stringify(meta, null, 2))
    const req = json.request?.data ?? json.request ?? {}
    const echo: Record<string, unknown> = {}
    for (const k of ['model', 'variants', 'resolution', 'format', 'enhance_prompt', 'enable_web_search', 'return_binary', 'style_references']) {
      if (k in req) echo[k] = req[k]
    }
    const countKey = imagesOffer().count_key ?? 'variants'
    if ('model' in req && req.model !== MODEL) warnings.push(`the provider ran ${shown(req.model)}, not ${MODEL}`)
    if (countKey in req && req[countKey] !== IMAGE_COUNT) warnings.push(`the provider ran ${shown(req[countKey])} images, not ${IMAGE_COUNT}`)
    for (const w of warnings) console.log(`[client ${this.label}] warning: ${w}`)
    const files = images.map((b64, i) => {
      const f = `${runDir}/image-${i}.webp`
      writePrivate(f, Buffer.from(b64, 'base64'))
      return f
    })
    writePrivate(`${runDir}/client.jsonl`, this.logLines.join('\n') + '\n')
    writePrivate(`${runDir}/receipt.json`, JSON.stringify(receipt, null, 2))
    if (attMsg.a) writePrivate(`${runDir}/attestation.json`, JSON.stringify(attMsg.a, null, 2))
    const tEnd = Date.now()
    console.log(
      `[client ${this.label}] images: ${images.length} of ${IMAGE_COUNT} (${files.join(', ')}) response_bytes=${this.responseBytes.length} ` +
        `cost_msats=${shown(receipt.cost_msats)} cost_ok=${costOk} signature_ok=${okSig} attestation_ok=${attOk}`,
    )
    return {
      sid: this.sid,
      kind: 'images',
      model: MODEL,
      count: IMAGE_COUNT,
      images: images.length,
      files,
      response_bytes: this.responseBytes.length,
      upstream_status: Number(/^HTTP\/1\.\d (\d{3})/.exec(Buffer.from(this.responseBytes.subarray(finalHeadOffset(this.responseBytes), finalHeadOffset(this.responseBytes) + 64)).toString('latin1'))?.[1] ?? 0),
      echo,
      warnings,
      cost_msats: receipt.cost_msats,
      cost_ok: costOk,
      receipt_sig_ok: okSig || !NODE_MODE,
      total_ms: tEnd - tClaim,
      upstream_ms: (this.ttft || tEnd) - tBodyWrite,
      zk: this.zkTimes,
    }
  }
}

// ---------------------------------------------------------------------------
// R extraction
// ---------------------------------------------------------------------------

/** Where the final response head starts, after any interim 1xx heads. */
function finalHeadOffset(b: Uint8Array): number {
  let off = 0
  for (;;) {
    const line = Buffer.from(b.subarray(off, off + 16)).toString('latin1')
    if (!/^HTTP\/1\.\d 1\d\d/.test(line)) return off
    const end = Buffer.from(b).indexOf('\r\n\r\n', off)
    if (end < 0) return off
    off = end + 4
  }
}

/** The HTTP response body (de-chunked when chunked), after any interim heads. */
function responseBody(full: Uint8Array): Uint8Array {
  const b = full.subarray(finalHeadOffset(full))
  const headEnd = Buffer.from(b).indexOf('\r\n\r\n')
  if (headEnd < 0) throw new Error('response has no head')
  const head = Buffer.from(b.subarray(0, headEnd)).toString('latin1').toLowerCase()
  const rest = b.subarray(headEnd + 4)
  if (!/\r\ntransfer-encoding:\s*chunked/.test(head)) {
    const len = /\r\ncontent-length:\s*(\d+)/.exec(head)
    if (len && rest.length !== Number(len[1])) throw new Error(`body is ${rest.length} bytes, Content-Length says ${len[1]}`)
    return rest
  }
  const out: Uint8Array[] = []
  let i = 0
  for (;;) {
    const eol = Buffer.from(rest.subarray(i)).indexOf('\r\n')
    if (eol < 0) throw new Error('truncated chunk size')
    const n = parseInt(Buffer.from(rest.subarray(i, i + eol)).toString('latin1'), 16)
    if (!Number.isFinite(n)) throw new Error('bad chunk size')
    i += eol + 2
    if (n === 0) break
    out.push(rest.subarray(i, i + n))
    i += n + 2
  }
  return Buffer.concat(out)
}

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
  const keyLen: number = offer?.key_length
  if (!(Number.isSafeInteger(keyLen) && keyLen > 0)) throw new Error('π_NK: the offer names no key length')
  const alphabet: string = offer?.key_alphabet ?? '[A-Za-z0-9_-]'
  const token = `{KEY:${keyLen}}`
  if (!tpl.includes(token)) throw new Error('π_NK: template lacks key token')
  checkHeadTemplate(tpl, offer?.upstream_host ?? '', IMAGE ? 'images' : 'chat')
  // The route is exactly a trusted API base plus the endpoint (CU_API_BASES,
  // comma-separated; default the two common bases, as the SDK's bare host).
  const bases = (process.env.CU_API_BASES ?? '/v1,/api/v1').split(',')
  const ends = IMAGE ? ['/image/generate', '/images/generations'] : ['/chat/completions']
  const route = /^POST (\S+) /.exec(tpl)?.[1]
  if (!bases.some((b) => ends.some((e) => route === b + e))) throw new Error(`π_NK: route ${shown(route)} is not a trusted API base plus the endpoint`)
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
  if (!Array.isArray(p.c_commit) || p.c_commit.length !== 32) throw new Error('π_NK: c_commit missing')
}

/**
 * An offer that names another protocol than v2 (v1 is retired), or a chat
 * block outside the policy (docs/CHAT-SUFFIX.md), is refused.
 */
function checkOfferVersion(offer: any): void {
  if (offer && offer.v !== undefined && offer.v !== PROTO) {
    console.error(`[client] the offer is for protocol v${shown(offer.v)}; this client speaks only v${PROTO}`)
    process.exit(4)
  }
  const problem = offer ? chatBlockProblem(offer) : null
  if (problem) {
    console.error(`[client] the offer's chat block is refused: ${termSafe(problem)}`)
    process.exit(4)
  }
  // The chat head template is held to its syntax before any setup (π_NK checks it again).
  if (offer && !IMAGE) {
    try {
      checkHeadTemplate(offer.head_template ?? '', offer.upstream_host ?? '', 'chat')
    } catch (e) {
      console.error(`[client] the offer's head template is refused: ${errText(e)}`)
      process.exit(4)
    }
  }
}

/** A token count as the node reads one (a non-negative integer, else 0). */
function tokenCount(v: unknown): number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v > 0 ? v : 0
}

/**
 * The most the node may charge for a usage at the signed rates (msats, no
 * fee): prompt tokens at `in`, less cached reads at `cached_in` (never above
 * `in`) and prompt-cache writes at `cache_write` (`in` when the offer has
 * none), both counted inside `prompt_tokens`; the larger of that, the formula
 * without writes and the uncached one (as the SDK's maxChargeMsats).
 */
function maxUsageCharge(rates: any, usage: any): number {
  const inRate = Number(rates.in)
  const outRate = Number(rates.out)
  const prompt = tokenCount(usage.prompt_tokens)
  const completion = tokenCount(usage.completion_tokens)
  const d = usage.prompt_tokens_details && typeof usage.prompt_tokens_details === 'object' ? usage.prompt_tokens_details : {}
  const cached = Math.min(tokenCount(d.cached_tokens), prompt)
  const written = Math.min(
    [d.cache_creation_input_tokens, d.cache_write_tokens, d.cache_creation_tokens, usage.cache_creation_input_tokens]
      .map(tokenCount)
      .find((n) => n > 0) ?? 0,
    prompt - cached,
  )
  const cachedRate = Math.min(Number(rates.cached_in ?? inRate), inRate)
  const writeRate = Number(rates.cache_write ?? inRate)
  const cost = (c: number, w: number) =>
    Math.ceil((inRate * (prompt - c - w) + cachedRate * c + writeRate * w + outRate * completion) / 1000)
  return Math.max(cost(0, 0), cost(cached, 0), cost(cached, written))
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
      console.error(`[client] could not fetch the offer: ${errText(e)}`)
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
      `[client] offer v=${shown(parsed.v)} host=${shown(parsed.upstream_host)} prewarm=${shown(parsed.prewarm)} ` +
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
        `rate_surcharge_pct=${shown(parsed.rate_surcharge_pct ?? 0)}`,
    )
  } catch (e) {
    console.error(`[client] offer verification failed: ${errText(e)}`)
    process.exit(4)
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  await verifyOffer()
  if (IMAGE) {
    if (ARM || POOL > 0) throw new Error('image sessions are never armed')
    setupImageBody()
  } else {
    setupChatBody()
  }

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

// Run only as the entry point, so the offer checks above can be imported offline.
const isEntry = (() => {
  try {
    return !!argv[1] && realpathSync(argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
})()
if (isEntry) {
  main().catch((e) => {
    console.error(`[client] FAILED: ${errText(e)}`)
    process.exit(1)
  })
}

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
