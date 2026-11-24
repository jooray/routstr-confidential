// Node mode: a request's signed receipt against the signed offer and what the
// node announced for the request (`request_ok`). Kept apart from the driver so
// that `test/receipt-check.ts` can run it offline.

import type { ImageTerms } from './ctx.ts'
import { maxUsageCharge, pinnedModel } from './offer.ts'
import { shown } from './term.ts'

/** The offer terms a receipt is checked against (read when a receipt is checked). */
export interface ReceiptTerms {
  offer: any
  sessionFee: number
  abandonFee: number
}

/** What the driver knows of the request when its receipt arrives. */
export interface ReceiptQuery {
  n: number
  http: string
  model: string
  status: number
  usage: any
  image?: ImageTerms
  first: boolean
  /** `request_ok.reserved_msats`: what the node reserved for the request, if it said. */
  reserved?: number
  /** A provider refusal we disclosed (`disclose_reset`): `rst_stream` or `goaway`. */
  refusal?: string
  /** The node reported `body_released` for the request (absent: assumed). */
  released?: boolean
}

/** `request_ok.reserved_msats`: absent, or a non-negative safe integer (anything else is refused). */
export function announcedReserve(m: any): number | undefined {
  const v = m?.reserved_msats
  if (v === undefined) return undefined
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`request_ok names reserved_msats ${shown(v)}, not a non-negative integer`)
  return v
}

/**
 * The prompt limit the signed offer names for `model` (`context_lengths`,
 * PROTOCOL-V3.md §12.1): the number the node sizes a chat reservation by.
 * Undefined when the offer names none (or no positive integer).
 */
export function signedContextLength(offer: any, model: string): number | undefined {
  const m = offer?.context_lengths
  const v = m && typeof m === 'object' && !Array.isArray(m) && Object.hasOwn(m, model) ? m[model] : undefined
  return Number.isSafeInteger(v) && v > 0 ? v : undefined
}

/**
 * The most an honest node reserves for a chat request on this offer (msat),
 * by its formula (§12.10) from signed numbers only: the offer's
 * `context_lengths` entry (never the `/v1/models` row, which may be another
 * upstream's), its rates, `reserve_margin_tokens` and fees. The node's
 * `min_request_msat` is not in the offer, so the bound is never below the
 * connection deposit plus the fee (a deposit above 0 is at least the minimum
 * request). Undefined, i.e. no ceiling: no entry for the model, no usable
 * rates, or no deposit.
 */
export function reservationCeiling(offer: any, model: string, maxTokens: number, depositMsat: number): number | undefined {
  const rates = offer?.price_list && Object.hasOwn(offer.price_list, model) ? offer.price_list[model] : undefined
  const limit = signedContextLength(offer, model)
  if (!rates || limit === undefined || !(depositMsat > 0)) return undefined
  const rate = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0)
  const inRate = Math.max(rate(rates.in), rate(rates.cache_write))
  const outRate = rate(rates.out)
  if (!inRate || !outRate || !(maxTokens > 0)) return undefined
  const count = (v: unknown) => (Number.isSafeInteger(v) && (v as number) > 0 ? (v as number) : 0)
  const margin = count(offer.reserve_margin_tokens)
  const fee = Math.max(count(offer.session_fee_msat), count(offer.abandon_fee_msat))
  const usage = Math.ceil((limit * inRate + (maxTokens + margin) * outRate) / 1000)
  return Math.max(usage, depositMsat) + fee
}

/**
 * A receipt never names larger fees than the offer; the session fee is
 * charged with the connection's first settlement only; the charge is at most
 * what the usage at the signed rates (or the error status) allows, and
 * exactly the flat price for accepted images. A 5xx other than 503 after
 * `body_released` may cost the reservation (before it, the abandon fee), and the bound for it is the number the node announced in
 * `request_ok` before the request was released, never the receipt's own: a
 * node that announced none gets at most the session fee if still due.
 * Whatever the settlement, a node that announced a reservation never charges
 * more than it, and every receipt repeats it.
 */
export function makeReceiptChecker(label: string, terms: () => ReceiptTerms): (receipt: any, q: ReceiptQuery) => void {
  return (receipt, q) => {
    const { offer, sessionFee, abandonFee } = terms()
    const feeDue = q.first ? sessionFee : 0
    // A chat receipt names the public id (`model`) and, where it differs, the
    // provider's id the suffix pinned (`upstream_model`).
    if (!q.image && q.model !== undefined && (receipt.upstream_model ?? receipt.model) !== pinnedModel(offer, q.model)) {
      throw new Error(`receipt ${q.n} names the pinned model ${shown(receipt.upstream_model ?? receipt.model)}, not ${pinnedModel(offer, q.model)}`)
    }
    if ((receipt.session_fee_msat ?? 0) > feeDue || (receipt.abandon_fee_msat ?? 0) > abandonFee) {
      throw new Error(`receipt ${q.n} names larger fees than the signed offer allows for this request`)
    }
    if (q.reserved !== undefined && receipt.reserved_msats !== q.reserved) {
      throw new Error(`receipt ${q.n} names reserved_msats ${shown(receipt.reserved_msats)}, the node announced ${q.reserved}`)
    }
    const cost = receipt.cost_msats
    // The announced reservation is the most any settlement of the request costs.
    const held = q.reserved ?? Infinity
    let bound: number
    if (q.refusal !== undefined) {
      // A stream the provider refused without processing it (§12.10): like a
      // 429, the session fee if still due, nothing else.
      if (receipt.usage?.refused !== q.refusal) {
        throw new Error(`refusal receipt ${q.n} names ${shown(receipt.usage?.refused)}, not the ${q.refusal} we disclosed`)
      }
      bound = feeDue
    } else if (q.status >= 400 && !(q.image && receipt.usage?.flat === true)) {
      // 429/503 and 401/402/403 (the provider's capacity, the node's own key
      // or account): the session fee if still due; any other 4xx, and any
      // other error before the request was released (the provider never had
      // all of it): the abandon fee; other 5xx: at most the reservation the
      // node announced.
      if ([401, 402, 403, 429, 503].includes(q.status)) bound = feeDue
      else if (q.status < 500 || q.released === false) bound = Math.max(feeDue, abandonFee)
      else if (q.reserved === undefined) bound = feeDue
      else bound = q.reserved
      if (q.image) {
        if (!(receipt.kind === 'images' && receipt.model === q.model && receipt.variant === q.image.variant && receipt.count === q.image.count)) {
          throw new Error(`error receipt ${q.n} does not carry the image request's terms`)
        }
        // Never more than the images themselves and a fee.
        bound = Math.min(bound, q.image.msatPerImage * q.image.count + Math.max(feeDue, abandonFee))
      }
    } else if (q.image) {
      const want = q.image.msatPerImage * q.image.count + feeDue
      const ok =
        receipt.kind === 'images' && receipt.usage?.flat === true && receipt.model === q.model && receipt.variant === q.image.variant &&
        receipt.count === q.image.count && receipt.msat_per_image === q.image.msatPerImage && receipt.cost_msats === want
      console.log(
        `[client ${label}] receipt ${q.n}: images variant=${shown(receipt.variant)} count=${shown(receipt.count)} cost_msats=${shown(cost)} ` +
          `reserved_msats=${shown(receipt.reserved_msats)} announced_reserved_msats=${shown(q.reserved)} balance_msats=${shown(receipt.balance_msats)} want_msats=${want} cost_ok=${ok}`,
      )
      if (!ok) throw new Error(`image receipt ${q.n} is not ${q.image.count} × ${shown(q.image.variant)} at ${q.image.msatPerImage} msat + fee (${want} msat)`)
      if (want > held) throw new Error(`image receipt ${q.n} charges ${want} msats, more than the ${held} the node announced as reserved`)
      return
    } else {
      // At most the usage at the signed rates (the node may charge less, for cached input) plus the fee.
      const rates = offer?.price_list?.[q.model]
      if (!rates) throw new Error(`the signed offer does not price ${shown(q.model)}`)
      bound = maxUsageCharge(rates, q.usage ?? {}) + feeDue
    }
    if (held < bound) {
      if (Number.isSafeInteger(cost) && cost > held) throw new Error(`receipt ${q.n} charges ${shown(cost)} msats, more than the ${held} the node announced as reserved`)
      bound = held
    }
    const costOk = Number.isSafeInteger(cost) && cost >= 0 && cost <= bound
    console.log(
      `[client ${label}] receipt ${q.n}: http=${q.http} status=${q.status} cost_msats=${shown(cost)} reserved_msats=${shown(receipt.reserved_msats)} ` +
        `announced_reserved_msats=${shown(q.reserved)} balance_msats=${shown(receipt.balance_msats)} session_fee_msat=${shown(receipt.session_fee_msat ?? 0)} ` +
        `bound_msats=${bound} cost_ok=${costOk}`,
    )
    if (!costOk) throw new Error(`receipt ${q.n} charges ${shown(cost)} msats, more than the ${bound} its ${q.status >= 400 ? 'error status' : 'usage at the signed rates'} allows`)
  }
}
