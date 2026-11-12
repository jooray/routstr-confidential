// Reference driver: the client (C) of routstr-confidential protocol v3
// (PROTOCOL-V3.md; the wire format is its §12), for both framings.
//
// C is the TLS 1.3 client of the provider. It runs the key schedule with the
// node as a two-party computation and gets c_ap_1 and s_ap_0; the node gets
// only K_0/IV_0, the key of the head record with the credential, which C
// never holds. A connection carries requests: many, one after another, in
// framing "2" (HTTP/2, driver-h2.ts), exactly one in framing "1.1"
// (HTTP/1.1, driver-h11.ts).
//
// Two deployments:
//   * direct  (--sidecar http://127.0.0.1:7443): C talks to cu-sidecar's
//     /offer, /session and /zk (the "S" messages of §12; ed25519 signatures).
//   * node    (--node http://127.0.0.1:8000): C talks to the routstr node's
//     /v1/confidential/{offer,ws,zk} (the "N" messages; the node reserves a
//     connection deposit at the setup and each request at its `request`,
//     settles the verified usage and signs with its Nostr key).
//
// Flags (defaults in brackets):
//   --http 2|1.1|auto [auto]   the framing; auto = the first entry of the verified offer's `http`,
//                              with the fallback of §2.3 (--http2 = --http 2)
//   --requests N [1]           N requests: on one connection (framing "2"), or one connection each ("1.1")
//   --model M  --max-tokens N  --prompt TEXT  --attach IMAGE  --private-extra JSON-MEMBERS [--private-extra-at N]
//   --models a,b,…  --kinds chat,images,…   per-request model and kind (also --h2-models, --h2-kinds)
//   --image [--image-model M] [--variant ID] [--count N] [--resolution 1K|2K|4K]
//   --body-bytes N             pad the prompt to about N bytes (a big body)
//   --arm                      pre-warm: setup with armed:true, 2PC preprocessing, key share and proof
//                              channel, then wait for "go" on stdin and send the request
//   --abandon                  arm a connection and close it unused
//   --refuse-first             before request 1, send a request the peer must refuse (request_refused),
//                              then the good one on the same connection with the same n
//   --retry-refused-ms N       (node) a request refused with 402 is sent again after N ms, same n
//   --offer-at K               (node) request K names the offer as refetched just before it; on
//                              `offer_changed` it is sent again naming the connection's own offer
//   --pause-ms N  --linger-ms N  --h2-chunk N  --max-deposit MSAT [100000]  --no-zkchan  --no-topup
//   --auth CREDENTIAL  --node-pubkey HEX|npub  --trusted-host H  --runs-dir DIR  --no-accept-fee
//   --legacy-v2-socket [--legacy-no-v]   open a protocol-v2 socket and print the peer's answer (LEGACY_JSON)
//   --adv MODE [--adv-at N]    an attack on request N (also --adv-h2):
//       both framings: suffix (another suffix: --adv-suffix-model M = model swap, --adv-body-max-tokens N =
//                      cap swap, --adv-image-count N), padding, early-record, no-proof, own-keyshare, twopc-tag
//       framing "2":   hidden-headers, path [--adv-h2-path P], replay-usage
//       framing "1.1": not-alone (the suffix is not alone in the final record)
//       cancel-and-reuse (a later request that refers to the credential unbilled):
//         framing "2": rst-reuse / rst-reuse-same (after body_released: RST_STREAM, then a HEADERS record
//         for the next / the same stream with no `request`), rst-before-final (the last DATA record never
//         released, RST_STREAM, then the next `request`), rst-after-release (RST_STREAM after
//         body_released, no disclosure, then the next `request`), ctl-headers (a record declared as a
//         PING ACK that carries a HEADERS frame);
//         framing "1.1": extra-record (after body_released, one more record carrying a second HTTP
//         request); a second request inside the body is --private-extra with raw CRLF text
//     --adv-accept-any (accept an image response whatever its status), --decoy-model M (neutralised)
//
// Output: `E2E_JSON {…}` (every request with its bytes each way and times), one `BENCH {…}` line per
// request (cold / armed / open), `ADV {…}` for an attack. Exit: 0 every request settled (or the attack
// was refused), 1 failure, 2 usage, 3 a receipt was not verified, 4 the offer is refused, 5 an attack
// was not refused, 6 node_protocol_outdated, 7 upgrade_required (the peer refused our protocol version).

import { randomUUID, createHash } from 'node:crypto'
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { argv } from 'node:process'
import { fileURLToPath } from 'node:url'

// `CU_TRACE=1` prints every control frame with a millisecond timestamp to stderr.
const T0 = Date.now()
const TRACE = process.env.CU_TRACE === '1'
const trace = (label: string, extra = '') =>
  TRACE ? process.stderr.write(`[t+${String(Date.now() - T0).padStart(6)}] ${label} ${extra}\n`) : undefined

import { makeTLSClient } from '../vendor/tls/lib/index.js'
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'

import { concat, hex, sha256 } from './advice.ts'
import { Bus, waitMsg } from './bus.ts'
import { RequestRefused, advOutcome, type Ctx, type Framing, type ImageTerms, type ReqBody } from './ctx.ts'
import { H11 } from './driver-h11.ts'
import { H2Conn, runHttp2 } from './driver-h2.ts'
import { MAX_DATA_IN_RECORD, chatPath, checkH2Offer, checkPiNKParamsH2, type H2OfferBlock } from './h2.ts'
import { chatBlockProblem, checkImagesBlock, maxUsageCharge, padBody, renderChatSuffix, renderImagesSuffix } from './offer.ts'
import { checkHeadTemplate, checkPiNKParams, type ServerPostRecord } from './params.ts'
import { pubkeyHex, verifySig } from './sig.ts'
import { errText, shown, termSafe } from './term.ts'
import { TwoPc, type ApOut } from './twopc.ts'
import { runZk } from './zkbridge.ts'
import { ZkChan } from './zkchan.ts'

export { shown, termSafe } from './term.ts'
export { chatBlockProblem, checkImagesBlock, refusedPinKey, renderChatSuffix, renderImagesSuffix } from './offer.ts'

setCryptoImplementation(webcryptoCrypto)

/** The protocol version, and the key-schedule protocol this client implements (§4). */
const PROTO = 3
const TWOPC = 'split-public-1'

/** The protocol sid: a 32-byte digest in lowercase hex. */
export const SID_RE = /^[0-9a-f]{64}$/

/** Evidence files hold plaintext (prompt, response, receipt): owner-only. */
const writePrivate = (path: string, data: string | Uint8Array) => writeFileSync(path, data, { mode: 0o600 })

function arg(name: string, dflt?: string): string | undefined {
  const i = argv.indexOf(name)
  return i >= 0 ? argv[i + 1] : dflt
}
const usage = (what: string): never => {
  console.error(`[client] ${what}`)
  process.exit(2)
}

const NODE = arg('--node')
const SIDECAR = arg('--sidecar', 'http://127.0.0.1:7443')!
const NODE_MODE = !!NODE
const MODEL = arg('--model', 'mistral-small-3-2-24b-instruct')!
const MAX_TOKENS = Number(arg('--max-tokens', '12'))
const PROMPT = arg('--prompt', 'Say hi in three words.')!
// Chat with an image input: --attach PATH puts the file in the private body as
// a data URI image part (the node never sees it; the provider bills it as
// prompt tokens). Needs a vision model.
const ATTACH = arg('--attach')
const HTTP_MODE = arg('--http') ?? (argv.includes('--http2') ? '2' : 'auto')
if (!['2', '1.1', 'auto'].includes(HTTP_MODE)) usage('--http must be 2, 1.1 or auto')
const REQUESTS = Number(arg('--requests', '1'))
// Per-request models and kinds (request i uses entry i, then --model / chat or, with --image, images).
const MODELS = (arg('--models') ?? arg('--h2-models') ?? '').split(',').filter(Boolean)
const KINDS = (arg('--kinds') ?? arg('--h2-kinds') ?? '').split(',').filter(Boolean)
const IMAGE = argv.includes('--image')
const IMAGE_MODEL = arg('--image-model')
const IMAGE_COUNT = Number(arg('--count', '1'))
const IMAGE_VARIANT = arg('--variant')
const IMAGE_RESOLUTION = arg('--resolution')
// Test hook: extra private JSON members (e.g. a field the provider rejects, to
// exercise the error-head path); --private-extra-at N: for request N only.
const PRIVATE_EXTRA = arg('--private-extra')
const PRIVATE_EXTRA_AT = Number(arg('--private-extra-at', '0'))
// A second `model` member in the private part: neutralised (the pinned suffix comes last).
const DECOY = arg('--decoy-model')
const PAUSE_MS = Number(arg('--pause-ms', '0'))
const BODY_BYTES = Number(arg('--body-bytes', '0'))
// Optional body-size bucket (off by default): --pad-bucket N (a multiple of N
// bytes) or pow2; JSON whitespace before the canonical suffix.
const PAD_ARG = arg('--pad-bucket')
const PAD_BUCKET: number | 'pow2' | undefined = PAD_ARG === undefined ? undefined : PAD_ARG === 'pow2' ? 'pow2' : Number(PAD_ARG)
const H2_CHUNK = Number(arg('--h2-chunk', String(MAX_DATA_IN_RECORD)))
const LINGER_MS = Number(arg('--linger-ms', '0'))
const MAX_DEPOSIT = Number(arg('--max-deposit', '100000'))
const ARM = argv.includes('--arm')
const ABANDON = argv.includes('--abandon')
const REFUSE_FIRST = argv.includes('--refuse-first')
// Node mode, test hooks for a refused request on a connection that stays (§12.4):
// --retry-refused-ms N: a request refused with 402 is sent again after N ms (a
// test tops the balance up meanwhile; `REFUSED_WAIT` is printed first).
// --offer-at K: request K names the offer as fetched just before it; when the
// node answers `offer_changed`, the request is sent again naming the offer the
// connection was opened on.
const RETRY_REFUSED_MS = Number(arg('--retry-refused-ms', '0'))
const OFFER_AT = Number(arg('--offer-at', '0'))
/** Every `request_refused` the hooks above saw. */
const REFUSALS: any[] = []
// Behave like a client that does not echo the offer's fees.
const NO_ACCEPT_FEE = argv.includes('--no-accept-fee')
// Proofs run over the connection's pre-warmed proof channel; `--no-zkchan`
// forces one socket per proof (at most 6 `/zk` sockets per connection).
const ZKCHAN = !argv.includes('--no-zkchan')
// Framing "2": the proof channel is topped up after the head and after each
// settlement (PROTOCOL-V3.md §9.2); `--no-topup` leaves it to extend online.
const TOPUP = !argv.includes('--no-topup')
const LEGACY = argv.includes('--legacy-v2-socket')
// --- attacks by a malicious client (crypto/tools/v3-check.sh) -----------------
const ADV_SUFFIX_MODEL = arg('--adv-suffix-model')
const ADV_BODY_MAX_TOKENS = arg('--adv-body-max-tokens') === undefined ? undefined : Number(arg('--adv-body-max-tokens'))
const ADV_IMAGE_COUNT = arg('--adv-image-count') === undefined ? undefined : Number(arg('--adv-image-count'))
const ADV_ACCEPT_ANY = argv.includes('--adv-accept-any')
const ADV_MODE: string | undefined =
  arg('--adv') ?? arg('--adv-h2') ??
  (argv.includes('--adv-no-proof') || argv.includes('--adv-no-suffix') ? 'no-proof'
    : argv.includes('--adv-own-keyshare') ? 'own-keyshare'
    : ADV_SUFFIX_MODEL !== undefined || ADV_BODY_MAX_TOKENS !== undefined || ADV_IMAGE_COUNT !== undefined ? 'suffix'
    : undefined)
const ADV_MODES: Record<string, Framing[]> = {
  suffix: ['2', '1.1'], padding: ['2', '1.1'], 'early-record': ['2', '1.1'], 'no-proof': ['2', '1.1'], 'own-keyshare': ['2', '1.1'], 'twopc-tag': ['2', '1.1'],
  'hidden-headers': ['2'], path: ['2'], 'replay-usage': ['2'], 'not-alone': ['1.1'],
  // A cancelled request whose credential reference a later one reuses, unbilled:
  'rst-reuse': ['2'], 'rst-reuse-same': ['2'], 'rst-before-final': ['2'], 'rst-after-release': ['2'], 'ctl-headers': ['2'],
  'extra-record': ['1.1'],
}
if (ADV_MODE !== undefined && !ADV_MODES[ADV_MODE]) usage(`--adv ${ADV_MODE}: one of ${Object.keys(ADV_MODES).join(', ')}`)
const ADV_AT = Number(arg('--adv-at', ADV_MODE === 'replay-usage' ? '2' : '1'))
const ADV_PATH = arg('--adv-h2-path', '/api/v1/api_keys/abcdefg')
// The node credential: an sk- key or a Cashu token (--escrow-token is an alias).
const AUTH = (arg('--auth') ?? arg('--escrow-token') ?? '').trim()
// Skipping the offer signature check is for tests against a throwaway node
// only, as in the SDK: it needs ROUTSTR_CONFIDENTIAL_INSECURE_TESTING=1.
if (NODE && argv.includes('--no-verify-offer') && process.env.ROUTSTR_CONFIDENTIAL_INSECURE_TESTING !== '1') {
  usage('--no-verify-offer needs ROUTSTR_CONFIDENTIAL_INSECURE_TESTING=1 (tests only)')
}
const VERIFY_OFFER = NODE ? !argv.includes('--no-verify-offer') : false
const RUNS = arg('--runs-dir', new URL('../../runs', import.meta.url).pathname)!
// Pin of the node's signing key (hex x-only, e.g. from its Nostr
// announcement; also CU_NODE_PUBKEY). Without it the offer is only
// self-consistent, not authentic, so it is required for a node off this host
// unless --allow-unpinned.
const NODE_PUBKEY_RAW = arg('--node-pubkey') ?? (process.env.CU_NODE_PUBKEY || undefined)
const NODE_PUBKEY = NODE_PUBKEY_RAW === undefined ? undefined : pubkeyHex(NODE_PUBKEY_RAW)
if (NODE_PUBKEY_RAW !== undefined && NODE_PUBKEY === null) usage(`--node-pubkey ${shown(NODE_PUBKEY_RAW)} is neither a 64-hex key nor an npub`)
// Provider hosts this client will run a TLS session with: the offer's
// upstream_host must be one of them (as the SDK's trusted hosts). The default
// is the case-study provider; extend with --trusted-host (repeatable) or
// CU_TRUSTED_HOSTS (comma-separated).
const TRUSTED_HOSTS = [
  'api.venice.ai',
  ...(process.env.CU_TRUSTED_HOSTS ?? '').split(','),
  ...argv.flatMap((a, i) => (a === '--trusted-host' && argv[i + 1] !== undefined ? [argv[i + 1]!] : [])),
]
  .map((h) => h.trim().toLowerCase())
  .filter((h) => h !== '')
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
/** The trusted API bases: a route is one of them plus the endpoint (CU_API_BASES, comma-separated). */
const API_BASES = (process.env.CU_API_BASES ?? '/v1,/api/v1').split(',')

let OFFER_PUBKEY: string | undefined
let OFFER: any = null
/** The signature of the offer we verified: every `setup` and `request` names it. */
let OFFER_SIG: string | undefined
/** The signed offer's fee on a connection's first settled request (msats); 0 when none. */
let SESSION_FEE = 0
/** The signed offer's fee for a request that is dropped before its body is released (msats, ≥ SESSION_FEE). */
let ABANDON_FEE = 0
/** The signed offer's connection deposit (msats; a sidecar's own offer has none). */
let DEPOSIT = 0
/** The framings of the offer this client supports, in the operator's order. */
let OFFER_HTTP: Framing[] = []
let H2_BLOCK: H2OfferBlock | undefined

// ---------------------------------------------------------------------------
// Offer (§2.3, §12.1)
// ---------------------------------------------------------------------------

function offerRefused(what: string, code = 4): never {
  console.error(`[client] ${what}`)
  process.exit(code)
}

/** Everything the client holds an offer to before a `setup`. */
function checkOffer(offer: any): void {
  if (!offer || typeof offer !== 'object') offerRefused('no offer')
  // An older node: not used for confidential requests (§11).
  if (offer.v === undefined || (typeof offer.v === 'number' && offer.v < PROTO)) {
    offerRefused(`node_protocol_outdated: the offer is for protocol v${shown(offer.v ?? 'unknown')}; this client speaks only v${PROTO} (the node needs an update)`, 6)
  }
  if (offer.v !== PROTO) offerRefused(`offer_unsupported_version: the offer is for protocol v${shown(offer.v)}; this client speaks only v${PROTO}`)
  if (offer.twopc !== TWOPC) offerRefused(`offer_unsupported_twopc: the offer names the key-schedule protocol ${shown(offer.twopc)}; this client implements ${TWOPC}`)
  const http = offer.http === undefined ? ['1.1'] : offer.http
  if (!Array.isArray(http) || http.length === 0 || new Set(http).size !== http.length || !http.every((h: unknown) => h === '2' || h === '1.1')) {
    offerRefused(`offer_malformed: http ${shown(offer.http)} is not a list of "2" and "1.1"`)
  }
  OFFER_HTTP = [...http]
  const host = typeof offer.upstream_host === 'string' ? offer.upstream_host.toLowerCase() : ''
  if (!TRUSTED_HOSTS.includes(host)) {
    offerRefused(`the offer's upstream_host ${shown(offer.upstream_host)} is not trusted (${TRUSTED_HOSTS.join(', ')}; --trusted-host or CU_TRUSTED_HOSTS to add one)`)
  }
  const problem = chatBlockProblem(offer)
  if (problem) offerRefused(`the offer's chat block is refused: ${termSafe(problem)}`)
  try {
    // The head template is held to its syntax before any setup (π_NK checks it again in framing "1.1").
    checkHeadTemplate(offer.head_template ?? '', offer.upstream_host ?? '', 'chat')
    if (OFFER_HTTP.includes('2')) H2_BLOCK = checkH2Offer(offer, API_BASES)
    else H2_BLOCK = undefined
  } catch (e) {
    offerRefused(`the offer is refused: ${errText(e)}`)
  }
  if (NODE_MODE) {
    const d = offer.connection_deposit_msat
    if (!(Number.isSafeInteger(d) && d >= 0)) offerRefused('offer_malformed: connection_deposit_msat')
    if (d > MAX_DEPOSIT) offerRefused(`the node's connection deposit of ${d} msat exceeds --max-deposit ${MAX_DEPOSIT}`)
    DEPOSIT = d
    const idle = offer.idle_timeout_s
    if (!(Number.isSafeInteger(idle) && idle >= 10 && (!H2_BLOCK || idle <= H2_BLOCK.idle_secs))) offerRefused('offer_malformed: idle_timeout_s')
  }
}

/** The provider host of the TLS session: the offer's `upstream_host`, which `checkOffer` held to the trusted list. */
function upstreamHost(): string {
  const h = typeof OFFER?.upstream_host === 'string' ? OFFER.upstream_host.toLowerCase() : undefined
  if (h === undefined || !TRUSTED_HOSTS.includes(h)) throw new Error(`upstream host ${shown(h)} is not trusted`)
  return h
}

async function fetchOffer(): Promise<void> {
  if (!NODE) {
    // A sidecar's own offer (no price list, no signature).
    let offer: any
    try {
      offer = await (await fetch(`${SIDECAR.replace(/\/$/, '')}/offer`)).json()
    } catch (e) {
      offerRefused(`could not fetch the offer: ${errText(e)}`, 1)
    }
    OFFER = offer
    checkOffer(OFFER)
    return
  }
  // `?v=3`: an old node's access log shows that v3 clients are asking (§11).
  const url = `${NODE.replace(/\/$/, '')}/v1/confidential/offer?v=${PROTO}`
  let raw: any
  try {
    raw = await (await fetch(url)).json()
  } catch (e) {
    offerRefused(`could not fetch the offer: ${errText(e)}`, 1)
  }
  const payload: string = raw.sig_payload ?? JSON.stringify(raw)
  let parsed: any
  try {
    parsed = raw.sig_payload ? JSON.parse(raw.sig_payload) : raw
  } catch {
    offerRefused('offer_malformed: the signed payload is not JSON')
  }
  if (VERIFY_OFFER) {
    const ok = verifySig(payload, raw.sig, parsed.notary_pubkey, 'schnorr-secp256k1')
    console.log(
      `[client] offer v=${shown(parsed.v)} http=${shown(parsed.http)} host=${shown(parsed.upstream_host)} ` +
        `models=${Object.keys(parsed.price_list ?? {}).length} sig_ok=${ok}`,
    )
    if (!ok) offerRefused('offer verification failed: offer signature invalid')
    if (NODE_PUBKEY && (typeof parsed.notary_pubkey !== 'string' || pubkeyHex(parsed.notary_pubkey) !== NODE_PUBKEY)) {
      offerRefused('offer verification failed: the offer is not signed by the pinned node key')
    }
    OFFER_PUBKEY = parsed.notary_pubkey
  }
  OFFER = parsed
  OFFER_SIG = raw.sig
  checkOffer(OFFER)
  for (const k of ['session_fee_msat', 'abandon_fee_msat']) {
    const v = parsed[k]
    if (v !== undefined && !(Number.isSafeInteger(v) && v >= 0)) offerRefused(`offer_malformed: ${k}`)
  }
  SESSION_FEE = parsed.session_fee_msat ?? 0
  ABANDON_FEE = Math.max(parsed.abandon_fee_msat ?? 0, SESSION_FEE)
  console.log(
    `[client] offer session_fee_msat=${SESSION_FEE} abandon_fee_msat=${ABANDON_FEE} connection_deposit_msat=${DEPOSIT} ` +
      `idle_timeout_s=${shown(parsed.idle_timeout_s)} rate_surcharge_pct=${shown(parsed.rate_surcharge_pct ?? 0)}`,
  )
}

// ---------------------------------------------------------------------------
// Request bodies: the private part, then the pinned suffix
// ---------------------------------------------------------------------------

const IMAGE_MIME: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' }
function userContent(text: string): unknown {
  if (!ATTACH) return text
  const mime = IMAGE_MIME[ATTACH.split('.').pop()!.toLowerCase()]
  if (!mime) throw new Error(`--attach: not an image file (${Object.keys(IMAGE_MIME).join(', ')}): ${ATTACH}`)
  const url = `data:${mime};base64,${readFileSync(ATTACH).toString('base64')}`
  return [{ type: 'text', text }, { type: 'image_url', image_url: { url } }]
}

/** The offer's images block: the node's signed one, or the sidecar's endpoint. */
function imagesOffer(): any {
  const im = OFFER?.images ?? OFFER?.endpoints?.images
  if (!im) throw new Error('offer_no_images: the offer has no images endpoint')
  checkImagesBlock(im)
  checkHeadTemplate(im.head_template ?? '', OFFER.upstream_host ?? '', 'images')
  return im
}

const kindOf = (g: number): 'chat' | 'images' => ((KINDS[g - 1] ?? (IMAGE ? 'images' : 'chat')) === 'images' ? 'images' : 'chat')

let imageTerms: { model: string; im: any; pins: [string, unknown][]; terms: ImageTerms } | undefined
/** The variant, its price and the images route, from the offer's images block. */
function imageRequest(): NonNullable<typeof imageTerms> {
  if (imageTerms) return imageTerms
  const im = imagesOffer()
  const model = IMAGE_MODEL ?? (IMAGE ? MODEL : undefined)
  if (!model) throw new Error('an image request needs --image-model')
  const variants: any[] | undefined = im.price_list?.[model]
  const v = variants ? (IMAGE_VARIANT ? variants.find((x) => x.id === IMAGE_VARIANT) : variants[0]) : undefined
  if (variants && !v) throw new Error(`no offered variant ${IMAGE_VARIANT ?? ''} for ${model}`)
  if (NODE_MODE && !v) throw new Error(`the signed offer does not price images of ${model}`)
  // A variant may allow fewer images per request than the offer.
  const maxCount = Math.min(im.max_count, v?.max_count ?? im.max_count)
  if (!(Number.isSafeInteger(IMAGE_COUNT) && IMAGE_COUNT >= 1 && IMAGE_COUNT <= maxCount)) throw new Error(`--count must be 1..${maxCount}`)
  // Without a node (a sidecar's own offer has no variants): WebP at the default tier.
  const pins: [string, unknown][] = v ? v.pins ?? [] : [...(IMAGE_RESOLUTION ? [['resolution', IMAGE_RESOLUTION] as [string, unknown]] : []), ['format', 'webp']]
  imageTerms = {
    model, im, pins,
    terms: { variant: v?.id, count: IMAGE_COUNT, path: chatPath(im.head_template), headTemplate: im.head_template, responseShape: im.response_shape, msatPerImage: v?.msat_per_image ?? 0 },
  }
  return imageTerms
}

/** Another model id of the same length (so that only the proof can tell the suffixes apart). */
const otherModel = (m: string) => m.slice(0, -1) + (m.endsWith('x') ? 'y' : 'x')

function buildBody(g: number): ReqBody {
  const enc = new TextEncoder()
  // The attacks that put another suffix at the end of the body than the request names.
  const wrong = !!ADV_MODE && ['suffix', 'no-proof'].includes(ADV_MODE) && ADV_AT === g
  const extra = PRIVATE_EXTRA && (PRIVATE_EXTRA_AT === 0 || PRIVATE_EXTRA_AT === g) ? `,${PRIVATE_EXTRA}` : ''
  if (kindOf(g) === 'images') {
    const { model, im, pins, terms } = imageRequest()
    const canonicalSuffix = renderImagesSuffix(im, model, terms.count, pins)
    // The attack: a suffix that orders more images than the request pays for, or another model.
    const sfx = wrong ? renderImagesSuffix(im, ADV_SUFFIX_MODEL ?? model, ADV_SUFFIX_MODEL !== undefined ? ADV_IMAGE_COUNT ?? terms.count : ADV_IMAGE_COUNT ?? terms.count + 1, pins) : canonicalSuffix
    const p = `{"prompt":${JSON.stringify(PROMPT)}${extra}`
    return { kind: 'images', model, maxTokens: 0, body: padBody(enc.encode(p), enc.encode(sfx), PAD_BUCKET), suffix: enc.encode(sfx), canonicalSuffix, image: terms }
  }
  const model = MODELS[g - 1] ?? MODEL
  const canonicalSuffix = renderChatSuffix(OFFER.chat, model, MAX_TOKENS)
  const sfx = wrong
    ? renderChatSuffix(OFFER.chat, ADV_SUFFIX_MODEL ?? (ADV_BODY_MAX_TOKENS === undefined ? otherModel(model) : model), ADV_BODY_MAX_TOKENS ?? MAX_TOKENS)
    : canonicalSuffix
  let content = REQUESTS > 1 ? `${PROMPT} (request ${g})` : PROMPT
  if (BODY_BYTES > content.length) content += ` Ignore this filler: ${'lorem ipsum '.repeat(Math.ceil((BODY_BYTES - content.length) / 12))}`
  let p = `{"messages":[{"role":"user","content":${JSON.stringify(userContent(content))}}]`
  if (DECOY) p += `,"model":${JSON.stringify(DECOY)}`
  p += extra
  return { kind: 'chat', model, maxTokens: MAX_TOKENS, body: padBody(enc.encode(p), enc.encode(sfx), PAD_BUCKET), suffix: enc.encode(sfx), canonicalSuffix }
}

// ---------------------------------------------------------------------------
// One connection: what both framings share (§3, §12.2-12.5)
// ---------------------------------------------------------------------------

/** The peer's `error` frame: it ends the connection. */
class PeerError extends Error {
  readonly frame: any
  constructor(m: any) {
    const parts = [`sidecar rejected: ${shown(m.reason, 300)}`]
    if (typeof m.code === 'string') parts.push(`code ${shown(m.code)}`)
    if (typeof m.status === 'number') parts.push(`node status ${m.status}`)
    if (typeof m.fault === 'string') parts.push(`fault ${shown(m.fault)}`)
    super(parts.length > 1 ? `${parts[0]} (${parts.slice(1).join(', ')})` : parts[0])
    this.frame = m
  }
}

/** The peer speaks another protocol version (a 426 `upgrade_required`, or a sidecar's `code`). */
const isUpgradeRequired = (m: any): boolean => m?.type === 'error' && (m.code === 'upgrade_required' || (m.status === 426 && m.reason === 'upgrade_required'))

const wsBase = () => (NODE_MODE ? NODE! : SIDECAR).replace(/^http/, 'ws').replace(/\/$/, '')

class Session {
  readonly label: string
  readonly framing: Framing
  readonly uuid = randomUUID()
  readonly bus = new Bus()
  ws!: WebSocket
  wsOpen = false
  private outbox: Uint8Array[] = []
  private wsResolve!: () => void
  readonly wsReady: Promise<void>
  // Rejected by the peer's `error` frame, a refused or failed socket: every protocol wait races it.
  private errRej!: (e: Error) => void
  readonly errP: Promise<never>
  /** The peer's `error` frame, when it sent one. */
  peerError: any
  tls!: ReturnType<typeof makeTLSClient>
  handshakeP!: Promise<void>
  private handshakeDone!: () => void
  flushChain: Promise<void> = Promise.resolve()
  // Framing "1.1": the response as it arrives.
  responseChunks: Uint8Array[] = []
  responseBytes = new Uint8Array(0)
  /** Encrypted server records (payloads of outer type 23), handshake flight included. */
  serverRecords: Uint8Array[] = []
  // Encrypted server records after the handshake (π_C3S derives the covered
  // records' key epoch and counts sequence numbers from its start).
  postHandshake = false
  serverPost: ServerPostRecord[] = []
  serverPending: Uint8Array = new Uint8Array(0)
  /** Framing "1.1": set once the head is written; the body's records are kept for the π_WIN check. */
  inBody = false
  bodyRecords: Uint8Array[] = []
  cCommitHex: string | undefined
  /** SHA-256 of every upstream byte and the count of complete upstream records (every content type). */
  recvHash = createHash('sha256')
  recvRecords = 0
  /** SHA-256 of the provider's certificate DERs, concatenated in order. */
  certChainHash: Uint8Array | undefined
  ttft = 0
  sid = ''
  ready: any = null
  tlsEnded = false
  /** A `body_released` arrived: from here no retry elsewhere (§2.3). */
  bodyReleased = false
  /** A request of the connection was settled (the deposit is released by the first). */
  settledOnce = false
  /** The connection deposit's outcome, as the node reported it (a receipt, or its last frame). */
  deposit: { msat: number; outcome: string; reason: string; signed: boolean } | undefined
  closedReason: string | undefined
  /** When each kind of control frame first arrived (measurements). */
  tFirst: Record<string, number> = {}
  /** Bytes on the session socket: control frames and relayed TLS records, each way. */
  bytes = { control_sent: 0, control_recv: 0, relay_sent: 0, relay_recv: 0 }
  private zkExtra = { sent: 0, recv: 0 }
  /** The byte counters when the request was claimed (0, or after arming). */
  claimBytes: Record<string, number> = {}
  setupBytes: Record<string, number> | undefined
  /** The HTTP/2 connection of a framing-"2" session. */
  h2: H2Conn | undefined
  twopc: TwoPc | undefined
  zkchan: ZkChan | undefined
  zkTimes: Record<string, any> = {}
  ap: ApOut | undefined
  thSH!: Uint8Array
  thSF!: Uint8Array
  tStart = Date.now()
  tReady = 0
  tKeyShare = 0
  tPhaseA = 0
  tPhaseB = 0
  tHs = 0
  tNkStart = 0
  tProofsReady = 0
  tHeadWritten = 0
  tOpen = 0
  runDir = ''
  logLines: string[] = []
  log = (o: unknown): void => void this.logLines.push(JSON.stringify(o))

  constructor(label: string, framing: Framing) {
    this.label = label
    this.framing = framing
    this.wsReady = new Promise<void>((r) => (this.wsResolve = r))
    this.errP = new Promise<never>((_, rej) => (this.errRej = rej))
    this.errP.catch(() => {}) // never an unhandled rejection when not raced
  }

  private controlUrl(): string {
    return NODE_MODE ? `${wsBase()}/v1/confidential/ws?session_id=${this.uuid}&v=${PROTO}` : `${wsBase()}/session`
  }

  zkUrl(proof: string): string {
    const sid = encodeURIComponent(this.sid)
    if (!NODE_MODE) return `${wsBase()}/zk?proof=${encodeURIComponent(proof)}&sid=${sid}`
    // The node's per-connection /zk token (from `ready`): the sid alone admits nothing.
    const token = typeof this.ready?.zk_token === 'string' ? `&zk_token=${encodeURIComponent(this.ready.zk_token)}` : ''
    return `${wsBase()}/v1/confidential/zk?proof=${encodeURIComponent(proof)}&sid=${sid}&session_id=${sid}${token}`
  }

  async connect(): Promise<void> {
    this.ws = new WebSocket(this.controlUrl())
    this.ws.binaryType = 'arraybuffer'
    this.ws.onopen = () => {
      this.wsOpen = true
      for (const b of this.outbox) this.ws.send(b)
      this.outbox.length = 0
      this.wsResolve()
    }
    this.ws.onerror = () => this.errRej(new Error('session websocket error'))
    this.ws.onclose = (ev: any) => {
      this.errRej(new Error(`connection closed${ev?.reason ? `: ${shown(ev.reason, 300)}` : ''}`))
    }
    this.ws.onmessage = (ev) => {
      const d = ev.data
      if (typeof d === 'string') {
        this.bytes.control_recv += d.length
        const m = JSON.parse(d)
        process.stderr.write(`[client ${this.label}] <- ${shown(m.type)}\n`)
        trace('<-', shown(m.type))
        if (typeof m.type === 'string' && this.tFirst[m.type] === undefined) this.tFirst[m.type] = Date.now()
        if (m.type === 'body_released') this.bodyReleased = true
        if (m.type === 'upstream_closed_early') {
          console.log(`[client ${this.label}] the provider closed before the request was written in full (response_bytes=${shown(m.response_bytes)})`)
        }
        if (m.type === 'closed' || m.type === 'error') this.onLastFrame(m)
        if (m.type === 'error') {
          this.peerError = m
          if (isUpgradeRequired(m)) {
            console.error(`[client ${this.label}] upgrade_required: the peer refuses protocol v${PROTO} (min_v=${shown(m.min_v)}): ${shown(m.detail ?? m.reason, 300)}`)
          }
          this.errRej(new PeerError(m))
        }
        this.h2?.onControl(m)
        // A connection runs many proofs: their parameters are keyed by proof and purpose.
        if (m.type === 'zk_params') m.type = `zk_params:${m.proof}:${m.purpose ?? ''}`
        this.bus.emit(m)
        return
      }
      const bytes = new Uint8Array(d as ArrayBuffer)
      this.bytes.relay_recv += bytes.length
      this.trackServerRecords(bytes)
      this.flushChain = this.flushChain
        .then(() => this.tls.handleReceivedBytes(bytes))
        .catch((e) => {
          console.error(`[client ${this.label}] handleReceivedBytes: ${errText(e)}`)
          this.errRej(e as Error)
        })
    }
    await Promise.race([this.wsReady, this.errP])
  }

  /** The node's last frame (`closed` or `error`): it may carry the deposit's outcome, signed (§12.9). */
  private onLastFrame(m: any): void {
    if (m.type === 'closed') {
      this.closedReason = String(m.reason ?? '')
      console.log(`[client ${this.label}] closed: reason=${shown(m.reason)}`)
    }
    if (m.deposit === undefined) return
    const json: string = typeof m.deposit_json === 'string' ? m.deposit_json : JSON.stringify(m.deposit)
    let signed = false
    let d: any
    try {
      d = JSON.parse(json)
      // Before `ready` (a setup the node could not serve) the key is the signed offer's.
      signed = verifySig(json, m.deposit_sig, this.ready?.pubkey ?? OFFER_PUBKEY, m.sig_scheme) && (d.sid === this.sid || d.sid === null)
    } catch {
      d = {}
    }
    this.deposit = { msat: Number(d.msat), outcome: String(d.outcome), reason: String(d.reason), signed }
    console.log(
      `[client ${this.label}] deposit: outcome=${shown(d.outcome)} reason=${shown(d.reason)} msat=${shown(d.msat)} ` +
        `balance_msats=${shown(d.balance_msats)} signed=${signed}`,
    )
  }

  trackServerRecords(bytes: Uint8Array): void {
    this.recvHash.update(bytes)
    let buf = concat(this.serverPending, bytes)
    while (buf.length >= 5) {
      const len = (buf[3]! << 8) | buf[4]!
      if (buf.length < 5 + len) break
      this.recvRecords += 1
      if (buf[0] === 0x17) this.serverRecords.push(buf.slice(5, 5 + len))
      buf = buf.subarray(5 + len)
    }
    this.serverPending = buf.slice()
  }

  sendText(obj: unknown): void {
    const text = JSON.stringify(obj)
    this.bytes.control_sent += text.length
    trace('->', shown((obj as any)?.type))
    this.ws.send(text)
  }
  sendBytes(b: Uint8Array): void {
    this.bytes.relay_sent += b.length
    if (this.wsOpen) this.ws.send(b)
    else this.outbox.push(b)
  }
  /** The next control frame of `type` (or of any of several types); also ends on `stops`. */
  waitT(type: string | string[], ms: number, ...stops: Promise<unknown>[]): Promise<any> {
    return waitMsg(this.bus, type, ms, this.errP, ...stops)
  }
  /** Bytes each way so far: the session socket, the 2PC channel and the proof channel (or proof sockets). */
  allBytes(): Record<string, number> {
    return {
      ...this.bytes,
      twopc_sent: this.twopc?.bytesSent ?? 0,
      twopc_recv: this.twopc?.bytesRecv ?? 0,
      zk_sent: (this.zkchan?.bytesSent ?? 0) + this.zkExtra.sent,
      zk_recv: (this.zkchan?.bytesRecv ?? 0) + this.zkExtra.recv,
    }
  }
  close(): void {
    this.zkchan?.close()
    this.twopc?.close()
    try {
      this.ws.close()
    } catch {
      /* ignore */
    }
  }

  /** `setup` → `ready` (§12.3): no request terms; a node gets the credential and the offer's signature. */
  async setup(armed: boolean): Promise<void> {
    const setup: any = { type: 'setup', v: PROTO, http: this.framing, nonce_c: hex(cryptoRandom(32)), armed }
    if (NODE_MODE) {
      setup.auth = AUTH
      if (OFFER_SIG) setup.offer_sig = OFFER_SIG
    } else setup.escrow_e = 1000
    this.sendText(setup)
    const ready = (this.ready = await this.waitT('ready', 30000))
    // The sid names the run directory and goes into URLs: only the digest form.
    if (typeof ready?.sid !== 'string' || !SID_RE.test(ready.sid)) throw new Error(`the node's sid ${shown(ready?.sid)} is not a 64-digit hex digest`)
    this.sid = ready.sid
    this.tReady = Date.now()
    console.log(`[client ${this.label}] sid=${this.sid} http=${shown(ready.http)} armed=${shown(ready.armed)} head_len=${shown(ready.head_len)}`)
    if (ready.v !== PROTO) throw new Error(`the node did not open a v${PROTO} connection`)
    if (ready.http !== this.framing) throw new Error(`the node opened framing ${shown(ready.http)}, not "${this.framing}"`)
    if (ready.armed !== undefined && ready.armed !== armed) throw new Error('ready names another armed state than the setup')
    if (OFFER_PUBKEY && ready.pubkey !== OFFER_PUBKEY) throw new Error('the connection key differs from the signed offer key')
    if (NODE_MODE && ready.deposit_msat !== DEPOSIT) {
      throw new Error(`the node reserved a deposit of ${shown(ready.deposit_msat)} msat, the signed offer's is ${DEPOSIT}`)
    }
    this.runDir = `${RUNS}/${this.sid}`
    mkdirSync(this.runDir, { recursive: true, mode: 0o700 })
  }

  /** 2PC preprocessing, the joint key share and the proof channel: an armed connection stops here. */
  async prewarm(adv?: string): Promise<Uint8Array> {
    if (adv === 'twopc-tag') {
      // A 2PC peer of another version: the first bytes on the channel are another tag.
      const ws = new WebSocket(this.zkUrl('twopc'))
      ws.binaryType = 'arraybuffer'
      ws.onopen = () => ws.send(new TextEncoder().encode('routstr-2pc/split-proven-1\n'))
      await this.waitT('error', 30000)
      throw new Error('the node answered another 2PC version tag with no error')
    }
    this.twopc = new TwoPc()
    this.twopc.start(this.zkUrl('twopc'))
    if (ZKCHAN) {
      // The proof channel's OT/VOLE setup runs alongside the 2PC preprocessing.
      this.zkchan = new ZkChan()
      this.zkchan.start(this.zkUrl('zkchan'))
    }
    let keyShare = await Promise.race([this.twopc.keyShare(180_000), this.errP])
    if (adv === 'own-keyshare') {
      // Our own share instead of the joint one: we would hold the whole ECDHE secret.
      const { p256 } = await import('@noble/curves/p256')
      keyShare = p256.getPublicKey(p256.utils.randomPrivateKey(), false)
    }
    this.tKeyShare = Date.now()
    this.log({ ev: 'twopc_key_share', ms: this.tKeyShare - this.tReady })
    return keyShare
  }

  /** The ClientHello with exactly the joint share; the key schedule runs on the 2PC channel (§12.5). */
  startTls(keyShare: Uint8Array): Promise<void> {
    this.tls = makeTLSClient({
      // No local ECDHE: the fork hands the key schedule to the 2PC.
      external: {
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
      },
      host: upstreamHost(),
      verifyServerCertificate: true,
      cipherSuites: ['TLS_AES_128_GCM_SHA256'],
      supportedProtocolVersions: ['TLS1_3'],
      namedCurves: ['SECP256R1'],
      applicationLayerProtocols: [this.framing === '2' ? 'h2' : 'http/1.1'],
      write: (packet: { header: Uint8Array; content: Uint8Array }) => {
        const record = concat(packet.header, packet.content)
        if (this.inBody) this.bodyRecords.push(record)
        this.h2?.onWrite(record)
        this.sendBytes(record)
      },
      onRead: (rec: { content: Uint8Array }, ctx?: { type?: string; contentType?: string }) => {
        this.h2?.onRead(ctx)
        if (!this.postHandshake || ctx?.type !== 'ciphertext') return
        this.serverPost.push({
          data: ctx.contentType === 'APPLICATION_DATA',
          keyUpdates: ctx.contentType === 'HANDSHAKE' ? countKeyUpdates(rec.content) : 0,
        })
      },
      onApplicationData: (rec: Uint8Array) => {
        if (this.h2) return this.h2.onData(rec)
        if (!this.ttft) this.ttft = Date.now()
        this.responseChunks.push(rec)
        this.responseBytes = concat(this.responseBytes, rec)
      },
      onRecvCertificates: ({ certificates }: { certificates: { internal: { rawData: ArrayBuffer } }[] }) => {
        // After the fork validated the chain: checked against the attestation.
        this.certChainHash = sha256(concat(...certificates.map((c) => new Uint8Array(c.internal.rawData))))
      },
      onTlsEnd: () => {
        this.tlsEnded = true
      },
      onHandshake: () => {
        this.postHandshake = true
        this.handshakeDone()
      },
      logger: { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
    } as any)
    this.handshakeP = new Promise<void>((res) => (this.handshakeDone = res))
    return this.tls.startHandshake()
  }

  /** The handshake to `hs_verified`: the node verified chain, hostname, CertificateVerify and both Finished. */
  async handshake(keyShare: Uint8Array): Promise<void> {
    await this.startTls(keyShare)
    await Promise.race([this.handshakeP, this.errP, timeout(30000, 'handshake')])
    await this.waitT('hs_verified', 30000)
    this.tHs = Date.now()
    this.log({ ev: 'hs_verified', phase_a_ms: this.tPhaseA, phase_b_ms: this.tPhaseB })
  }

  /**
   * `c_commit` and π_NK: the node's head record under K_0 is the head of the
   * framing with a key of the offer's alphabet, and K_0 is the one the 2PC
   * anchored (hk). Framing "1.1": the head of our request 1.
   */
  async proveHead(req?: { kind: 'chat' | 'images'; bodyLen: number; headLen: number; headTemplate: string }): Promise<void> {
    this.tNkStart = Date.now()
    const commit = await this.waitT('c_commit', 60000)
    if (this.framing === '2') {
      checkPiNKParamsH2(commit.params, { host: OFFER.upstream_host, probePath: H2_BLOCK!.probe_path, keyLength: OFFER.key_length, keyAlphabet: OFFER.key_alphabet, hk: this.ap!.hk })
      if (this.ready.head_len !== commit.params.PiNK.head_len) throw new Error('ready names another head length than π_NK proves')
    } else {
      checkPiNKParams(commit.params, { offer: { ...OFFER, head_template: req!.headTemplate }, hk: this.ap!.hk, bodyLen: req!.bodyLen, kind: req!.kind, apiBases: API_BASES })
      if (req!.headLen !== commit.params.PiNK.head_len) throw new Error('request_ok names another head length than π_NK proves')
    }
    // The attestation must later name the commitment π_NK proves; the frame has to carry exactly it.
    this.cCommitHex = hex(Uint8Array.from(commit.params.PiNK.c_commit))
    if (commit.c_commit !== this.cCommitHex) throw new Error("c_commit: the frame's commitment is not the one π_NK proves")
    for (const [k, v] of [['h1', this.ap!.h1], ['h2', this.ap!.h2], ['hk', this.ap!.hk]] as const) {
      if (commit[k] !== undefined && commit[k] !== hex(v)) throw new Error(`c_commit: anchor ${k} is not the one from our 2PC`)
    }
    await this.proof('pi_nk', 'verify', commit.params)
    this.log({ ev: 'pi_nk_ok' })
    this.tProofsReady = Date.now()
  }

  /**
   * One proof, over the pre-warmed channel when it is usable, else on a
   * socket of its own. Fallback only while no proof has started on the
   * channel: once one has, a channel failure ends the connection.
   */
  async proof(proof: string, cmd: 'prove' | 'verify', params: unknown, witness?: unknown): Promise<void> {
    const t = Date.now()
    const ch = this.zkchan
    if (ch && (ch.used || (await ch.ready(120_000)))) {
      const m = await ch.run(cmd, proof, params, witness)
      this.zkTimes[proof] = { via: 'zkchan', ms: Date.now() - t, inner_ms: m.ms, bytes_sent: m.bytes_sent, bytes_recv: m.bytes_recv }
      trace(`zk ${proof}`, `zkchan ${Date.now() - t}ms`)
      return
    }
    if (ch) this.log({ ev: 'zkchan_fallback', proof, err: String(ch.failure) })
    const prof = await runZk(this.zkUrl(proof), { proof, role: cmd === 'prove' ? 'prover' : 'verifier', params, witness })
    this.zkExtra.sent += prof.bytes_sent
    this.zkExtra.recv += prof.bytes_recv
    this.zkTimes[proof] = { via: 'per-proof', ms: Date.now() - t, ...prof }
    trace(`zk ${proof}`, `per-proof ${Date.now() - t}ms`)
  }

  /** The connection's phases, for the measurements. */
  phases(tClaim: number): Record<string, unknown> {
    return {
      ready_ms: this.tReady - this.tStart,
      twopc_key_share_ms: this.tKeyShare - this.tReady,
      twopc_phase_a_ms: this.tPhaseA,
      twopc_phase_b_ms: this.tPhaseB,
      handshake_ms: this.tHs ? this.tHs - Math.max(tClaim, this.tKeyShare) : undefined,
      pi_nk_ms: this.tProofsReady ? this.tProofsReady - this.tNkStart : undefined,
      head_ms: this.tHeadWritten ? this.tHeadWritten - this.tProofsReady : undefined,
      settings_ms: this.tOpen ? this.tOpen - this.tHeadWritten : undefined,
      connect_ms: (this.tOpen || this.tHeadWritten) ? (this.tOpen || this.tHeadWritten) - tClaim : undefined,
      zk_nk: this.zkTimes.pi_nk,
      zkchan_ready_ms: this.zkchan?.tReady ? this.zkchan.tReady - this.zkchan.tStart : undefined,
      zkchan_setup: this.zkchan?.readyInfo?.timings,
      twopc: this.twopc?.timings,
    }
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function cryptoRandom(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

/**
 * Rejects after `ms`. The timer is never cleared (the waits race it), so it is
 * unref'd: a wait that already ended must not keep the process alive for the
 * rest of its timeout. While a connection runs, its sockets do.
 */
function timeout(ms: number, what: string): Promise<never> {
  return new Promise((_, rej) => {
    const t = setTimeout(() => rej(new Error(`timeout waiting for ${what}`)), ms)
    t.unref?.()
  })
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

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

/**
 * Node mode: a request's signed receipt against the signed offer. A receipt
 * never names larger fees than the offer; the session fee is charged with the
 * connection's first settlement only; the charge is at most what the usage at
 * the signed rates (or the error status) allows, and exactly the flat price
 * for accepted images.
 */
function checkReceipt(label: string): NonNullable<Ctx['checkReceipt']> {
  return (receipt, q) => {
    const feeDue = q.first ? SESSION_FEE : 0
    if ((receipt.session_fee_msat ?? 0) > feeDue || (receipt.abandon_fee_msat ?? 0) > ABANDON_FEE) {
      throw new Error(`receipt ${q.n} names larger fees than the signed offer allows for this request`)
    }
    const cost = receipt.cost_msats
    let bound: number
    if (q.status >= 400 && !(q.image && receipt.usage?.flat === true)) {
      // 429/503 and 401/402/403 (the provider's capacity, the node's own key
      // or account): the session fee if still due; any other 4xx: the abandon
      // fee; other 5xx: at most the reservation.
      if ([401, 402, 403, 429, 503].includes(q.status)) bound = feeDue
      else if (q.status < 500) bound = Math.max(feeDue, ABANDON_FEE)
      else bound = Math.max(feeDue, typeof receipt.reserved_msats === 'number' ? receipt.reserved_msats : 0)
      if (q.image && !(receipt.kind === 'images' && receipt.model === q.model && receipt.variant === q.image.variant && receipt.count === q.image.count)) {
        throw new Error(`error receipt ${q.n} does not carry the image request's terms`)
      }
    } else if (q.image) {
      const want = q.image.msatPerImage * q.image.count + feeDue
      const ok =
        receipt.kind === 'images' && receipt.usage?.flat === true && receipt.model === q.model && receipt.variant === q.image.variant &&
        receipt.count === q.image.count && receipt.msat_per_image === q.image.msatPerImage && receipt.cost_msats === want
      console.log(
        `[client ${label}] receipt ${q.n}: images variant=${shown(receipt.variant)} count=${shown(receipt.count)} cost_msats=${shown(cost)} ` +
          `reserved_msats=${shown(receipt.reserved_msats)} balance_msats=${shown(receipt.balance_msats)} want_msats=${want} cost_ok=${ok}`,
      )
      if (!ok) throw new Error(`image receipt ${q.n} is not ${q.image.count} × ${shown(q.image.variant)} at ${q.image.msatPerImage} msat + fee (${want} msat)`)
      return
    } else {
      // At most the usage at the signed rates (the node may charge less, for cached input) plus the fee.
      const rates = OFFER?.price_list?.[q.model]
      if (!rates) throw new Error(`the signed offer does not price ${shown(q.model)}`)
      bound = maxUsageCharge(rates, q.usage ?? {}) + feeDue
    }
    const costOk = Number.isSafeInteger(cost) && cost >= 0 && cost <= bound
    console.log(
      `[client ${label}] receipt ${q.n}: http=${q.http} status=${q.status} cost_msats=${shown(cost)} reserved_msats=${shown(receipt.reserved_msats)} ` +
        `balance_msats=${shown(receipt.balance_msats)} session_fee_msat=${shown(receipt.session_fee_msat ?? 0)} bound_msats=${bound} cost_ok=${costOk}`,
    )
    if (!costOk) throw new Error(`receipt ${q.n} charges ${shown(cost)} msats, more than the ${bound} its ${q.status >= 400 ? 'error status' : 'usage at the signed rates'} allows`)
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

interface ConnOut {
  s: Session
  results: any[]
  adv?: any
  lingered?: number
  tClaim: number
  armed: boolean
}

function makeCtx(label: string): Ctx {
  const requestExtras: Record<string, unknown> = {}
  if (NODE_MODE) {
    requestExtras.auth = AUTH
    if (OFFER_SIG) requestExtras.offer_sig = OFFER_SIG
    // The offer's fees are echoed (a request that does not is refused: session_fee_not_accepted).
    if (!NO_ACCEPT_FEE) {
      requestExtras.session_fee_msat = SESSION_FEE
      requestExtras.abandon_fee_msat = ABANDON_FEE
    }
  }
  return {
    offer: OFFER,
    h2: H2_BLOCK,
    nodeMode: NODE_MODE,
    depositMsat: DEPOSIT,
    requestExtras,
    checkReceipt: NODE_MODE ? checkReceipt(label) : undefined,
    requests: REQUESTS,
    pauseMs: PAUSE_MS,
    topup: TOPUP,
    lingerMs: LINGER_MS,
    chunk: H2_CHUNK,
    buildBody,
    refuseFirst: REFUSE_FIRST,
    beforeRequest: NODE_MODE && OFFER_AT > 0 ? async (n) => {
      if (n !== OFFER_AT) return
      const raw: any = await (await fetch(`${NODE!.replace(/\/$/, '')}/v1/confidential/offer?v=${PROTO}`)).json()
      const payload: string = raw.sig_payload ?? JSON.stringify(raw)
      if (!verifySig(payload, raw.sig, OFFER_PUBKEY ?? JSON.parse(payload).notary_pubkey, 'schnorr-secp256k1')) throw new Error('the refetched offer is not signed by the node')
      console.log(`[client ${label}] request ${n} names the offer as refetched now (${raw.sig === OFFER_SIG ? 'the same offer' : 'another offer'})`)
      requestExtras.offer_sig = raw.sig
    } : undefined,
    onRefused: NODE_MODE && (OFFER_AT > 0 || RETRY_REFUSED_MS > 0) ? async (n, m, attempt) => {
      const type = m?.detail?.error?.type
      REFUSALS.push({ n, status: m.status, type, reason: typeof m.reason === 'string' ? m.reason.slice(0, 200) : undefined })
      if (attempt > 1) return false
      if (OFFER_AT === n && type === 'offer_changed' && requestExtras.offer_sig !== OFFER_SIG) {
        console.log(`OFFER_CHANGED n=${n} status=${shown(m.status)}: refused; sending it again naming the offer the connection was opened on`)
        requestExtras.offer_sig = OFFER_SIG
        return true
      }
      if (RETRY_REFUSED_MS > 0 && m.status === 402) {
        console.log(`REFUSED_WAIT n=${n} status=402 type=${shown(type)}: sending it again in ${RETRY_REFUSED_MS} ms`)
        await sleep(RETRY_REFUSED_MS)
        return true
      }
      return false
    } : undefined,
    adv: ADV_MODE ? { mode: ADV_MODE, at: ADV_AT, path: ADV_PATH } : undefined,
    acceptAny: ADV_ACCEPT_ANY,
    verifySig,
    shown,
    writePrivate,
    log: () => {},
  }
}

/** Opened or armed: setup, 2PC preprocessing, key share; with `arm`, wait for "go". */
async function openConnection(framing: Framing, label: string, arm: boolean, ctx: Ctx): Promise<{ s: Session; keyShare: Uint8Array; tClaim: number }> {
  const s = new Session(label, framing)
  current = s
  ctx.log = s.log
  await s.connect()
  await s.setup(arm)
  const earlyAdv = ctx.adv && ['twopc-tag', 'own-keyshare'].includes(ctx.adv.mode) ? ctx.adv.mode : undefined
  const keyShare = await s.prewarm(earlyAdv)
  let tClaim = s.tStart
  if (arm) {
    // Pre-warm: the proof channel's correlations are part of it. Nothing binds
    // the connection to a request: only the credential (a node) is named.
    if (s.zkchan && !(await s.zkchan.ready(180_000))) throw new Error(`the proof channel did not come up: ${String(s.zkchan.failure)}`)
    const armBytes = s.allBytes()
    console.log(`ARMED sid=${s.sid} http=${framing} arm_ms=${Date.now() - s.tStart} arm_bytes=${JSON.stringify(armBytes)}`)
    if (ABANDON) return { s, keyShare, tClaim }
    console.log('READY (send "go" on stdin to send the request)')
    await Promise.race([waitForGo(), s.errP])
    tClaim = Date.now()
    s.claimBytes = armBytes
  }
  return { s, keyShare, tClaim }
}

/** The session in flight (for the fallback decision and the attack's outcome). */
let current: Session | undefined

/** A framing-"2" connection: requests `from`… one after another. */
async function serveH2(from: number, arm: boolean): Promise<ConnOut> {
  const ctx = makeCtx('h2')
  if (!H2_BLOCK) throw new Error('offer_no_http2: the offer does not list http 2')
  for (let g = from; g <= REQUESTS; g++) {
    if (kindOf(g) === 'images' && !H2_BLOCK.kinds.includes('images')) throw new Error('offer_no_http2_images: the offer serves no image requests on framing "2"')
  }
  const { s, keyShare, tClaim } = await openConnection('2', 'h2', arm, ctx)
  const conn = new H2Conn(s, ctx)
  s.h2 = conn
  if (ABANDON) return { s, results: [], tClaim, armed: arm }
  await s.handshake(keyShare)
  await s.proveHead()
  const out = await runHttp2(s, conn, from)
  return { s, ...out, tClaim, armed: arm }
}

/** A framing-"1.1" connection: request `g` of the run, request 1 of the connection. */
async function serve11(g: number, arm: boolean): Promise<ConnOut> {
  const ctx = makeCtx('h11')
  if (!OFFER_HTTP.includes('1.1')) throw new Error('offer_no_http11: the offer does not list http 1.1')
  const attack = ctx.adv && ctx.adv.at === g ? ctx.adv.mode : undefined
  const h = { v: undefined as H11 | undefined }
  const { s, keyShare, tClaim } = await openConnection('1.1', REQUESTS > 1 ? `h11-${g}` : 'h11', arm, ctx)
  if (ABANDON) return { s, results: [], tClaim, armed: arm }
  try {
    const h11 = (h.v = new H11(s, ctx, g))
    if (attack === 'early-record') {
      // The ClientHello before `request` 1 was accepted: a protocol error.
      await s.startTls(keyShare)
      await s.waitT('error', 15000)
      throw new Error('the node answered a ClientHello with no request with no error')
    }
    await h11.open()
    await s.handshake(keyShare)
    const b = h11.b
    await s.proveHead({ kind: b.kind, bodyLen: b.body.length, headLen: h11.ok.head_len, headTemplate: b.image ? b.image.headTemplate : OFFER.head_template })
    const r = await h11.run(tClaim)
    if (r.adv) {
      // no-proof: the final record was withheld by the node, or it was not.
      return { s, results: [], adv: { mode: attack, http: '1.1', at: g, refused: r.adv.withheld, reason: r.adv.withheld ? 'the final record was held' : 'the provider answered', ...r.adv }, tClaim, armed: arm }
    }
    console.log(
      `[client ${s.label}] request ${g}: status=${r.status} released_ms=${r.released_ms} ttft_ms=${r.ttft_ms} total_ms=${r.total_ms} ` +
        `usage=${JSON.stringify(r.usage ?? null)} receipt_sig_ok=${r.receipt_sig_ok}`,
    )
    r.g = g
    if (attack) return { s, results: [r], adv: { mode: attack, http: '1.1', at: g, refused: false, detail: 'the request settled' }, tClaim, armed: arm }
    return { s, results: [r], tClaim, armed: arm }
  } catch (e) {
    if (!attack) throw e
    return { s, results: [], adv: await advOutcome(s, ctx, e, { at: g, body_released: s.bodyReleased, response_bytes: s.responseBytes.length }), tClaim, armed: arm }
  }
}

/** `--legacy-v2-socket`: what a protocol-v2 client gets from this peer (§11, §12.2). */
async function legacySocket(): Promise<never> {
  const noV = argv.includes('--legacy-no-v')
  const url = NODE_MODE ? `${wsBase()}/v1/confidential/ws?session_id=${randomUUID()}${noV ? '' : '&v=2'}` : `${wsBase()}/session`
  const ws = new WebSocket(url)
  const answer = await new Promise<any>((res) => {
    const t = setTimeout(() => res({ timeout: true }), 15000)
    const done = (v: any) => (clearTimeout(t), res(v))
    // A v2-shaped setup: request terms, no `v`. No credential is sent to a peer that should refuse it.
    ws.onopen = () => ws.send(JSON.stringify({ type: 'setup', nonce_c: hex(cryptoRandom(32)), model: MODEL, max_tokens: MAX_TOKENS, len: 100, armed: false, ...(NODE_MODE ? { auth: '' } : { escrow_e: 1000 }) }))
    ws.onmessage = (ev) => {
      try {
        done(typeof ev.data === 'string' ? JSON.parse(ev.data) : { binary: true })
      } catch {
        done({ unparsable: true })
      }
    }
    ws.onerror = () => done({ socket_error: true })
    ws.onclose = (ev: any) => done({ closed: true, code: ev?.code, reason: String(ev?.reason ?? '') })
  })
  try {
    ws.close()
  } catch {
    /* ignore */
  }
  const upgrade = isUpgradeRequired(answer)
  console.log(`[client] legacy v2 socket: ${upgrade ? 'refused with upgrade_required' : 'NOT refused with upgrade_required'}: ${shown(answer, 400)}`)
  console.log('LEGACY_JSON ' + JSON.stringify({ upgrade_required: upgrade, answer }))
  process.exit(upgrade ? 0 : 5)
}

async function main() {
  if (LEGACY) await legacySocket()
  await fetchOffer()
  if (!(Number.isSafeInteger(REQUESTS) && REQUESTS >= 0 && REQUESTS <= 1000)) usage('--requests must be 0..1000')
  if (HTTP_MODE !== 'auto' && !OFFER_HTTP.includes(HTTP_MODE as Framing)) {
    throw new Error(`${HTTP_MODE === '2' ? 'offer_no_http2' : 'offer_no_http11'}: the offer lists http ${JSON.stringify(OFFER_HTTP)}, not "${HTTP_MODE}"`)
  }
  // §2.3: the first entry of the offer's list this client supports and has not marked bad.
  const bad = new Set<Framing>()
  const pick = (): Framing => {
    const f = HTTP_MODE === 'auto' ? OFFER_HTTP.find((x) => !bad.has(x)) : (HTTP_MODE as Framing)
    if (!f) throw new Error('no framing of the offer is left to try')
    return f
  }
  if (ADV_MODE && !ADV_MODES[ADV_MODE]!.includes(pick())) usage(`--adv ${ADV_MODE} does not apply to framing "${pick()}"`)
  if (REQUESTS === 0 && pick() !== '2' && !ABANDON) usage('--requests 0 needs framing "2" (a framing-"1.1" connection opens with its request)')
  if (H2_BLOCK && pick() === '2' && REQUESTS > H2_BLOCK.max_requests) usage(`--requests must be 0..${H2_BLOCK.max_requests} on one framing-"2" connection`)
  // Build every body before any setup: a bad flag or offer block fails here.
  for (let g = 1; g <= REQUESTS; g++) buildBody(g)

  const results: any[] = []
  const conns: any[] = []
  let adv: any
  let fallback: any
  let lastClosed: any
  let g = 1
  let first = true
  while (g <= REQUESTS || first) {
    const framing = pick()
    const arm = (ARM || ABANDON) && first
    let out: ConnOut
    try {
      out = framing === '2' ? await serveH2(g, arm) : await serve11(g, arm)
    } catch (e) {
      const s = current
      const pe = s?.peerError
      // §2.3: a framing-"2" connection that fails before the body of its first
      // request was released is retried on "1.1" on the same node. Not after a
      // body was released; not when the request itself or the setup was refused.
      const refusedByTerms = e instanceof RequestRefused || (typeof pe?.status === 'number' && pe.status >= 400 && pe.status < 500)
      if (ADV_MODE && s !== undefined) {
        // An attack on the connection itself (another 2PC version, our own key share): how it ended.
        adv = await advOutcome(s, makeCtx(s.label), e, { at: 0 })
        s.close()
        break
      }
      if (HTTP_MODE === 'auto' && framing === '2' && OFFER_HTTP.includes('1.1') && s !== undefined && !s.bodyReleased && !refusedByTerms && !ADV_MODE) {
        bad.add('2')
        fallback = { from: '2', to: '1.1', at: g, reason: errText(e).slice(0, 300), code: pe?.code, fault: pe?.fault, sid: s.sid || undefined }
        console.log(`[client] FALLBACK framing "2" failed before a body was released (${fallback.reason}); marked bad, serving request ${g} on "1.1"`)
        s.close()
        first = false
        continue
      }
      throw e
    }
    first = false
    const { s } = out
    if (ABANDON) {
      console.log(`ABANDONED sid=${s.sid} http=${framing} (armed, closed unused)`)
      s.close()
      await sleep(600)
      process.exit(0)
    }
    // Per request: where it ran, and the measurement line.
    out.results.forEach((r, i) => {
      r.g = r.g ?? r.n
      r.sid = s.sid
      const firstOnConn = i === 0
      r.mode = !firstOnConn ? 'open' : out.armed ? 'armed' : 'cold'
      const at = r.at
      delete r.at
      if (firstOnConn && framing === '2') {
        // From the claim (the connection's start, or "go" on an armed one) to request 1.
        r.from_claim = { released_ms: at?.released ? at.released - out.tClaim : undefined, ttft_ms: at?.first_data ? at.first_data - out.tClaim : undefined }
        const now = s.setupBytes ?? {}
        r.connect_bytes = Object.fromEntries(Object.keys(now).map((k) => [k, now[k]! - (s.claimBytes[k] ?? 0)]))
      }
      const b = { ...r.bytes }
      if (r.connect_bytes) for (const k of Object.keys(b)) b[k] += r.connect_bytes[k] ?? 0
      console.log(
        'BENCH ' +
          JSON.stringify({
            http: framing, mode: r.mode, g: r.g, n: r.n, kind: r.kind ?? 'chat', status: r.status, body_len: r.body_len,
            ttft_ms: r.from_claim?.ttft_ms ?? r.ttft_ms, released_ms: r.from_claim?.released_ms ?? r.released_ms, total_ms: r.total_ms,
            bytes: {
              session_sent: b.control_sent + b.relay_sent, session_recv: b.control_recv + b.relay_recv,
              twopc_sent: b.twopc_sent, twopc_recv: b.twopc_recv, zk_sent: b.zk_sent, zk_recv: b.zk_recv,
            },
          }),
      )
    })
    results.push(...out.results)
    lastClosed = s.closedReason === undefined ? undefined : { reason: s.closedReason, idle_ms: out.lingered }
    conns.push({
      sid: s.sid, http: framing, armed: out.armed, requests: out.results.length, phases: s.phases(out.tClaim),
      setup_bytes: s.setupBytes, total_bytes: s.allBytes(), deposit: s.deposit, closed: lastClosed,
      topups: s.zkchan?.topups.length ? s.zkchan.topups : undefined,
    })
    writePrivate(`${s.runDir}/client.jsonl`, s.logLines.join('\n') + '\n')
    adv = out.adv
    s.close()
    g += Math.max(1, out.results.length)
    // An attack ends the run; so does an error status (the connection is over, and so is the example).
    if (adv || out.results.some((r) => r.status >= 400) || out.results.length === 0) break
    if (g <= REQUESTS && framing === '1.1' && PAUSE_MS > 0) await sleep(PAUSE_MS)
  }
  const last = conns[conns.length - 1]
  const summary = {
    protocol: PROTO,
    http: last?.http,
    sid: last?.sid,
    requests: results,
    adv,
    fallback,
    refusals: REFUSALS.length ? REFUSALS : undefined,
    deposit: last?.deposit,
    closed: lastClosed,
    phases: last?.phases,
    setup_bytes: last?.setup_bytes,
    total_bytes: last?.total_bytes,
    connections: conns,
    receipt_sig_ok: results.length > 0 && results.every((r) => r.receipt_sig_ok),
  }
  if (adv) console.log('ADV ' + JSON.stringify(adv))
  console.log('E2E_JSON ' + JSON.stringify(summary))
  await sleep(600) // the proof channel's orderly close
  if (ADV_MODE) process.exit(adv?.refused ? 0 : 5)
  // A connection opened and left without a request (--requests 0): nothing to verify but its end.
  if (REQUESTS === 0) process.exit(0)
  const complete = results.length === REQUESTS || results.some((r) => r.status >= 400)
  process.exit(complete && summary.receipt_sig_ok ? 0 : 3)
}

// Run only as the entry point, so the checks above can be imported offline.
const isEntry = (() => {
  try {
    return !!argv[1] && realpathSync(argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
})()
if (isEntry) {
  main().catch(async (e) => {
    const pe = current?.peerError
    if (e instanceof RequestRefused) console.error(`[client] REFUSED: ${errText(e)}`)
    console.error(`[client] FAILED: ${errText(e)}`)
    current?.close()
    await sleep(100)
    process.exit(pe && isUpgradeRequired(pe) ? 7 : 1)
  })
}
