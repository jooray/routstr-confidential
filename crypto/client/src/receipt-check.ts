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
}

/** `request_ok.reserved_msats`: absent, or a non-negative safe integer (anything else is refused). */
export function announcedReserve(m: any): number | undefined {
  const v = m?.reserved_msats
  if (v === undefined) return undefined
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`request_ok names reserved_msats ${shown(v)}, not a non-negative integer`)
  return v
}

/**
 * A receipt never names larger fees than the offer; the session fee is
 * charged with the connection's first settlement only; the charge is at most
 * what the usage at the signed rates (or the error status) allows, and
 * exactly the flat price for accepted images. A 5xx other than 503 may cost
 * the reservation, and the bound for it is the number the node announced in
 * `request_ok` before the request was released, never the receipt's own: a
 * node that announced none gets at most the session fee if still due.
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
    if (q.reserved !== undefined && receipt.reserved_msats !== undefined && receipt.reserved_msats !== q.reserved) {
      throw new Error(`receipt ${q.n} names reserved_msats ${shown(receipt.reserved_msats)}, the node announced ${q.reserved}`)
    }
    const cost = receipt.cost_msats
    let bound: number
    if (q.status >= 400 && !(q.image && receipt.usage?.flat === true)) {
      // 429/503 and 401/402/403 (the provider's capacity, the node's own key
      // or account): the session fee if still due; any other 4xx: the abandon
      // fee; other 5xx: at most the reservation the node announced.
      if ([401, 402, 403, 429, 503].includes(q.status)) bound = feeDue
      else if (q.status < 500) bound = Math.max(feeDue, abandonFee)
      else if (q.reserved === undefined) bound = feeDue
      else {
        if (receipt.reserved_msats !== q.reserved) {
          throw new Error(`error receipt ${q.n} names reserved_msats ${shown(receipt.reserved_msats)}, the node announced ${q.reserved}`)
        }
        bound = Math.max(feeDue, q.reserved)
      }
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
      return
    } else {
      // At most the usage at the signed rates (the node may charge less, for cached input) plus the fee.
      const rates = offer?.price_list?.[q.model]
      if (!rates) throw new Error(`the signed offer does not price ${shown(q.model)}`)
      bound = maxUsageCharge(rates, q.usage ?? {}) + feeDue
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
