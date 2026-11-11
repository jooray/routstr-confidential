// What the reference driver hands the two framings (its flags, the verified
// offer and helpers), and what both do the same way: the `request` message
// and its answer (PROTOCOL-V3.md §12.4), and a request's receipt (§12.8).

import { hex, sha256 } from './advice.ts'
import type { H2OfferBlock } from './h2.ts'

export type Framing = '2' | '1.1'

/** The terms of an image request: the offered variant (a node's offer), the count, the images route and the price. */
export interface ImageTerms {
  variant?: string
  count: number
  /** The route of the images head template (framing "2": the `:path`). */
  path: string
  headTemplate: string
  responseShape: string
  msatPerImage: number
}

/** One request: its terms, its body and the pinned suffix. */
export interface ReqBody {
  kind: 'chat' | 'images'
  model: string
  maxTokens: number
  body: Uint8Array
  /** The suffix the body ends in (an attack: not the canonical one). */
  suffix: Uint8Array
  canonicalSuffix: string
  image?: ImageTerms
}

export interface Ctx {
  offer: any
  /** The offer's checked `h2` block (framing "2"). */
  h2?: H2OfferBlock
  nodeMode: boolean
  /** The offer's connection deposit (msat; a sidecar's own offer: 0). */
  depositMsat: number
  /** Node mode: fields every `request` carries (credential, offer signature, fee echoes). */
  requestExtras: Record<string, unknown>
  /** Node mode: check a request's signed receipt (the charge against our own usage or the error status); throws. */
  checkReceipt?: (receipt: any, q: { n: number; http: Framing; model: string; status: number; usage: any; image?: ImageTerms; first: boolean }) => void
  /** Requests asked for (`--requests`). */
  requests: number
  pauseMs: number
  /** After the last request: wait this long for the node to close the idle connection. */
  lingerMs?: number
  /** Framing "2": largest DATA payload per record. */
  chunk: number
  /** The body of request `g` (1, 2, … over the whole run). */
  buildBody: (g: number) => ReqBody
  /** Send a request the peer must refuse before request 1, then the good one with the same `n`. */
  refuseFirst: boolean
  /** Adversarial mode and the request it applies to. */
  adv?: { mode: string; at: number; path?: string }
  /** A dishonest client: `accept` an image response whatever its status. */
  acceptAny: boolean
  verifySig: (json: string, sig: string | undefined, pub: string, scheme: string | undefined) => boolean
  shown: (v: unknown, max?: number) => string
  writePrivate: (path: string, data: string | Uint8Array) => void
  log: (o: unknown) => void
}

/** The peer refused a `request` (`request_refused`): the connection is still usable. */
export class RequestRefused extends Error {
  readonly status: number
  readonly reason: string
  constructor(m: any) {
    super(`request ${m?.n} refused: ${typeof m?.reason === 'string' ? m.reason.slice(0, 300) : JSON.stringify(m?.reason ?? null).slice(0, 300)} (status ${m?.status})`)
    this.status = Number(m?.status)
    this.reason = String(m?.reason)
  }
}

/** The `request` message of §12.4; `bad`: terms the peer must refuse. */
export function requestMessage(ctx: Ctx, n: number, b: ReqBody, bodyLen: number, bad = false): Record<string, unknown> {
  const m: Record<string, unknown> = b.image
    ? {
        type: 'request', n, kind: 'images', model: b.model,
        // A node takes the variant and renders the suffix itself; a sidecar is handed the suffix.
        ...(ctx.nodeMode ? { variant: b.image.variant, count: b.image.count } : { count: b.image.count, suffix: b.canonicalSuffix }),
        body_len: bodyLen,
      }
    : { type: 'request', n, kind: 'chat', model: b.model, max_tokens: b.maxTokens, body_len: bodyLen }
  Object.assign(m, ctx.requestExtras)
  if (bad) {
    const cap = ctx.offer?.max_tokens_cap
    // A node: a model it does not serve. A sidecar: `max_tokens` above its
    // cap, or (images, or no cap in the offer) a body over the 8 MiB limit.
    if (ctx.nodeMode) m.model = 'no-such-model-refuse-first'
    else if (!b.image && Number.isSafeInteger(cap)) m.max_tokens = cap + 1
    else m.body_len = (8 << 20) + 1
  }
  return m
}

/**
 * Send `request` n and wait for its answer. No record of the request may be
 * sent before this returns (framing "1.1": not even the ClientHello). With
 * `refuseFirst`, a request the peer must refuse goes first; it must leave the
 * connection as it was, and the good request then carries the same `n`.
 */
export async function openRequest(
  s: any,
  ctx: Ctx,
  n: number,
  b: ReqBody,
  bodyLen: number,
  refuseFirst: boolean,
  send: (o: unknown) => void,
  wait: (types: string[], ms: number) => Promise<any>,
): Promise<{ ok: any; refused?: { status: number; reason: string } }> {
  let refused: { status: number; reason: string } | undefined
  if (refuseFirst) {
    send(requestMessage(ctx, n, b, bodyLen, true))
    const m = await wait(['request_refused', 'request_ok'], 30000)
    if (m.type !== 'request_refused') throw new Error('the peer accepted a request it had to refuse')
    if (m.n !== n || !Number.isSafeInteger(m.status) || m.status < 400 || m.status > 599) throw new Error('request_refused names another request or no status')
    refused = { status: m.status, reason: typeof m.reason === 'string' ? m.reason.slice(0, 200) : JSON.stringify(m.reason ?? null).slice(0, 200) }
    console.log(`[client ${s.label}] request ${n} refused as expected: status=${m.status} reason=${ctx.shown(m.reason, 200)}; sending the good request with the same n`)
  }
  send(requestMessage(ctx, n, b, bodyLen))
  const m = await wait(['request_ok', 'request_refused'], 30000)
  if (m.type === 'request_refused') throw new RequestRefused(m)
  if (m.n !== n || (m.sid !== undefined && m.sid !== s.sid)) throw new Error('request_ok names another connection or request')
  if (typeof m.suffix !== 'string') throw new Error('request_ok names no pinned suffix')
  return { ok: m, refused }
}

/**
 * The request's receipt: signed by the connection's key and bound to the
 * connection, the framing, the request and its attestation. With a sidecar
 * whose node settles (and no node here) the unsigned `usage` frame instead.
 */
export async function takeReceipt(s: any, ctx: Ctx, n: number, attJson: string, wait: (types: string[], ms: number) => Promise<any>): Promise<any> {
  const m = await wait(['receipt', 'usage'], 60000)
  if (m.type === 'usage') {
    if (m.n !== n || m.http !== s.framing || m.sid !== s.sid) throw new Error('usage frame is for another connection, framing or request')
    return { sid: s.sid, http: m.http, n, model: m.model, usage: m.usage, unsigned: true }
  }
  // The signed bytes are the receipt; the envelope beside them is ignored.
  const receiptJson: string = m.receipt_json ?? JSON.stringify(m.receipt)
  const receipt = JSON.parse(receiptJson)
  if (!ctx.verifySig(receiptJson, m.sig, s.ready.pubkey, m.sig_scheme)) throw new Error('receipt signature invalid')
  if (receipt.sid !== s.sid || receipt.n !== n) throw new Error('receipt is for another connection or request')
  if (receipt.http !== s.framing) throw new Error(`receipt names http ${ctx.shown(receipt.http)}, the connection's framing is "${s.framing}"`)
  if (typeof receipt.attestation_hash !== 'string' || receipt.attestation_hash !== hex(sha256(new TextEncoder().encode(attJson)))) {
    throw new Error("receipt is not bound to this request's attestation")
  }
  ctx.log({ ev: 'receipt', n, receipt })
  return receipt
}

/** The deposit a settled request's receipt releases (node mode): the connection's first settlement, the offer's amount. */
export function noteDepositRelease(s: any, ctx: Ctx, receipt: any, n: number): void {
  const released = receipt.deposit_released_msat
  if (released === undefined) {
    if (ctx.nodeMode && !s.settledOnce && ctx.depositMsat > 0) throw new Error(`receipt ${n} settles the connection's first request and does not release the deposit`)
  } else {
    if (s.settledOnce) throw new Error(`receipt ${n} releases the deposit again`)
    if (released !== ctx.depositMsat) throw new Error(`receipt ${n} releases a deposit of ${ctx.shown(released)} msat, the offer's is ${ctx.depositMsat}`)
    s.deposit = { msat: released, outcome: 'released', reason: 'request_settled', signed: !receipt.unsigned }
    console.log(`[client ${s.label}] deposit: outcome=released reason=request_settled msat=${released} signed=${!receipt.unsigned}`)
  }
  s.settledOnce = true
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

/**
 * How an attack ended. It counts as refused only when the peer said so in an
 * `error` frame (a failed proof or a protocol violation ends the connection
 * that way); a timeout or a local failure is not a refusal.
 */
export async function advOutcome(s: any, ctx: Ctx, e: unknown, extra: Record<string, unknown>): Promise<any> {
  // Our prover may notice the failed proof before the peer's frame arrives.
  for (let i = 0; i < 100 && !s.peerError; i++) await sleep(30)
  const pe = s.peerError
  return {
    mode: ctx.adv?.mode,
    http: s.framing,
    refused: !!pe,
    reason: pe ? String(pe.reason ?? '') : String((e as Error)?.message ?? e),
    code: pe?.code,
    local: String((e as Error)?.message ?? e).slice(0, 200),
    ...extra,
  }
}
