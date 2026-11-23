// The offer rules the reference driver holds a node (or a sidecar) to before
// any `setup` (PROTOCOL-V3.md §2.3, §12.1). Pure functions, so that they have
// offline tests (test/offer-check.ts); the driver turns an `OfferRefused`
// into its exit code.

import type { Framing } from './ctx.ts'
import { checkH2Offer, type H2OfferBlock } from './h2.ts'
import { chatBlockProblem, checkImagesBlock, contextLengthsProblem, upstreamModelsProblem } from './offer.ts'
import { checkHeadTemplate } from './params.ts'
import { errText, shown, termSafe } from './term.ts'

/** The protocol version, and the key-schedule protocol this client implements (§4). */
export const PROTO = 3
export const TWOPC = 'split-public-3'
/** Earlier key schedules of protocol v3: a node that offers one is outdated. */
export const TWOPC_RETIRED = ['split-public-2', 'split-public-1']

/** An offer this client does not use; `code` is the driver's exit code (4, or 6 for an older node). */
export class OfferRefused extends Error {
  readonly code: number
  constructor(message: string, code = 4) {
    super(message)
    this.code = code
  }
}

/** What the client trusts and allows, independent of any offer. */
export interface OfferPolicy {
  /** Provider hosts this client will run a TLS session with (lowercase). */
  trustedHosts: string[]
  /** The API bases a route may start with (`/v1`, `/api/v1`). */
  apiBases: string[]
  /** A node's signed offer (with a deposit and an idle timeout), not a sidecar's own. */
  nodeMode: boolean
  /** The largest connection deposit this client accepts (msat). */
  maxDeposit: number
}

/** What the checked offer gives the driver. */
export interface CheckedOffer {
  /** The framings of the offer this client supports, in the operator's order. */
  http: Framing[]
  h2?: H2OfferBlock
  /** The connection deposit (msat; a sidecar's own offer: 0). */
  deposit: number
}

/**
 * The provider hosts this client trusts: `CU_TRUSTED_HOSTS` (comma-separated)
 * and every `--trusted-host H`. There is no built-in host: an empty list
 * refuses every offer.
 */
export function trustedHosts(env: string | undefined, args: readonly string[]): string[] {
  return [
    ...(env ?? '').split(','),
    ...args.flatMap((a, i) => (a === '--trusted-host' && args[i + 1] !== undefined ? [args[i + 1]!] : [])),
  ]
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h !== '')
}

/** The request paths a head template may name, per kind (after one of the trusted API bases). */
const TEMPLATE_PATHS: Record<'chat' | 'images', readonly string[]> = {
  chat: ['/chat/completions'],
  images: ['/image/generate', '/images/generations'],
}

/**
 * Why a head template's route is not exactly one of the trusted API bases
 * followed by the kind's endpoint (`/api/v1` + `/chat/completions`), or
 * `undefined` when it is. The node writes the request head (framing "1.1")
 * or names its `:path` from the same template (framing "2"), so a route of
 * the same provider that merely ends in the endpoint is refused.
 */
export function headRouteProblem(tpl: unknown, bases: readonly string[], kind: 'chat' | 'images'): string | undefined {
  const m = typeof tpl === 'string' ? /^POST (\S+) HTTP\/1\.1\r\n/.exec(tpl) : null
  if (!m) return 'template is not an HTTP/1.1 POST'
  const allowed = bases.flatMap((b) => TEMPLATE_PATHS[kind].map((end) => b + end))
  return allowed.includes(m[1]!) ? undefined : `template route ${shown(m[1], 120)} is not one the trusted API bases allow (${allowed.join(', ')})`
}

/** The offer's images block (a node's signed `images`, or a sidecar's `endpoints.images`), held to its rules and its route. */
export function imagesBlock(offer: any, apiBases: readonly string[]): any {
  const im = offer?.images ?? offer?.endpoints?.images
  if (!im) throw new Error('offer_no_images: the offer has no images endpoint')
  checkImagesBlock(im)
  checkHeadTemplate(im.head_template ?? '', offer.upstream_host ?? '', 'images')
  const route = headRouteProblem(im.head_template, apiBases, 'images')
  if (route) throw new Error(`offer_malformed: images head_template: ${route}`)
  return im
}

/** Everything the client holds an offer to before a `setup`; throws `OfferRefused`. */
export function checkOffer(offer: any, policy: OfferPolicy): CheckedOffer {
  const refuse = (what: string, code = 4): never => {
    throw new OfferRefused(what, code)
  }
  if (!offer || typeof offer !== 'object') refuse('no offer')
  // An older node: not used for confidential requests (§11).
  if (offer.v === undefined || (typeof offer.v === 'number' && offer.v < PROTO)) {
    refuse(`node_protocol_outdated: the offer is for protocol v${shown(offer.v ?? 'unknown')}; this client speaks only v${PROTO} (the node needs an update)`, 6)
  }
  if (offer.v !== PROTO) refuse(`offer_unsupported_version: the offer is for protocol v${shown(offer.v)}; this client speaks only v${PROTO}`)
  if (typeof offer.twopc === 'string' && TWOPC_RETIRED.includes(offer.twopc)) {
    refuse(`node_protocol_outdated: the node runs the key-schedule protocol ${offer.twopc}; this client implements ${TWOPC} (the node needs an update)`, 6)
  }
  if (offer.twopc !== TWOPC) refuse(`offer_unsupported_twopc: the offer names the key-schedule protocol ${shown(offer.twopc)}; this client implements ${TWOPC}`)
  const http = offer.http === undefined ? ['1.1'] : offer.http
  if (!Array.isArray(http) || http.length === 0 || new Set(http).size !== http.length || !http.every((h: unknown) => h === '2' || h === '1.1')) {
    refuse(`offer_malformed: http ${shown(offer.http)} is not a list of "2" and "1.1"`)
  }
  if (policy.trustedHosts.length === 0) refuse('no trusted provider host: pass --trusted-host H or set CU_TRUSTED_HOSTS')
  const host = typeof offer.upstream_host === 'string' ? offer.upstream_host.toLowerCase() : ''
  if (!policy.trustedHosts.includes(host)) {
    refuse(`the offer's upstream_host ${shown(offer.upstream_host)} is not trusted (${policy.trustedHosts.join(', ')}; --trusted-host or CU_TRUSTED_HOSTS to add one)`)
  }
  const problem = chatBlockProblem(offer)
  if (problem) refuse(`the offer's chat block is refused: ${termSafe(problem)}`)
  const upstream = upstreamModelsProblem(offer)
  if (upstream) refuse(`offer_malformed: ${termSafe(upstream)}`)
  const contexts = contextLengthsProblem(offer)
  if (contexts) refuse(`offer_malformed: ${termSafe(contexts)}`)
  let h2: H2OfferBlock | undefined
  try {
    // The head template is held to its syntax before any setup (π_NK checks it again in framing "1.1").
    checkHeadTemplate(offer.head_template ?? '', offer.upstream_host ?? '', 'chat')
    if (http.includes('2')) h2 = checkH2Offer(offer, policy.apiBases)
  } catch (e) {
    refuse(`the offer is refused: ${errText(e)}`)
  }
  // Both framings: the chat route is a trusted API base plus the endpoint
  // (framing "2" sends it as the `:path` of every chat request).
  const route = headRouteProblem(offer.head_template, policy.apiBases, 'chat')
  if (route) refuse(`the offer is refused: head_template: ${route}`)
  let deposit = 0
  if (policy.nodeMode) {
    const d = offer.connection_deposit_msat
    if (!(Number.isSafeInteger(d) && d >= 0)) refuse('offer_malformed: connection_deposit_msat')
    if (d > policy.maxDeposit) refuse(`the node's connection deposit of ${d} msat exceeds --max-deposit ${policy.maxDeposit}`)
    deposit = d
    const idle = offer.idle_timeout_s
    if (!(Number.isSafeInteger(idle) && idle >= 10 && (!h2 || idle <= h2.idle_secs))) refuse('offer_malformed: idle_timeout_s')
    // The minimum age before an unused connection may be evicted (absent from
    // an older node's offer).
    const evict = offer.evict_unused_after_s
    if (evict !== undefined && !(Number.isSafeInteger(evict) && evict >= 0)) refuse('offer_malformed: evict_unused_after_s')
  }
  return { http: [...http], h2, deposit }
}
