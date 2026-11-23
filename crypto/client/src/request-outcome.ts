// The node's signed outcome of a request it finalized without a receipt
// (`request_outcome` on the connection's last frame, PROTOCOL-V3.md §12.9,
// §12.10), held to what the client saw of the request. Detection only: the
// client reports a deviation, it cannot undo a charge.

/** The reasons a node names in `request_outcome.reason` (§12.10). */
export const REQUEST_OUTCOME_REASONS = new Set([
  'request_received',
  'settlement_failed',
  'settled_without_receipt',
  'provider_refused',
  'provider_unreachable',
  'sidecar_failure',
  'request_abandoned',
  'evicted',
  'unattested',
  'not_started',
])

/** Reasons that may charge more than a fee: the provider had the request in full. */
const AFTER_RELEASE_REASONS = new Set(['request_received', 'settlement_failed'])

/** The request the client had open when the last frame arrived. */
export interface OpenRequest {
  n: number
  /** The node accepted it (`request_ok`). */
  accepted: boolean
  /** `request_ok.reserved_msats`, when the node announced it. */
  reservedMsats?: number
  /** A `body_released` for it arrived. */
  bodyReleased: boolean
}

export interface RequestOutcomeContext {
  sid: string
  framing: string
  /** The request neither refused nor settled (none: no request open). */
  open?: OpenRequest
  /** The most a request not written in full may cost: max(session fee if still due, abandon fee). */
  feeMsat: number
}

/**
 * Why the node's request outcome deviates from what the client saw, one
 * entry per rule. `o` is the parsed `request_outcome_json` (undefined: the
 * frame carries none), `signed` whether the node's signature over it
 * verified.
 */
export function requestOutcomeProblems(o: any, signed: boolean, c: RequestOutcomeContext): string[] {
  const open = c.open
  if (o === undefined || o === null) {
    return open?.accepted ? [`no signed outcome for request ${open.n}, which the node accepted and did not settle`] : []
  }
  const p: string[] = []
  const shown = (v: unknown) => JSON.stringify(v ?? null).slice(0, 64)
  if (!signed) p.push('without a valid signature of the node')
  if (o.sid !== c.sid) p.push(`it names connection ${shown(o.sid)}`)
  if (o.http !== c.framing) p.push(`it names framing ${shown(o.http)}`)
  if (!open) p.push(`an outcome for request ${shown(o.n)}, though no request was open`)
  else if (o.n !== open.n) p.push(`it names request ${shown(o.n)}, the open one is ${open.n}`)
  if (o.outcome !== 'charged' && o.outcome !== 'released') p.push(`an outcome ${shown(o.outcome)}`)
  if (typeof o.reason !== 'string' || !REQUEST_OUTCOME_REASONS.has(o.reason)) p.push(`a reason ${shown(o.reason)}`)
  const cost = o.cost_msats
  if (!(Number.isSafeInteger(cost) && cost >= 0)) {
    p.push(`a cost of ${shown(cost)}`)
    return p
  }
  if ((o.outcome === 'charged') !== cost > 0) p.push(`outcome ${shown(o.outcome)} with a cost of ${cost} msat`)
  if (open?.reservedMsats !== undefined) {
    if (o.reserved_msats !== open.reservedMsats) p.push(`reserved_msats ${shown(o.reserved_msats)}, request_ok announced ${open.reservedMsats}`)
    if (cost > open.reservedMsats) p.push(`a cost of ${cost} msat above the announced reservation of ${open.reservedMsats}`)
  } else if (Number.isSafeInteger(o.reserved_msats) && cost > o.reserved_msats) {
    p.push(`a cost of ${cost} msat above its own reservation of ${o.reserved_msats}`)
  }
  if (open && !open.bodyReleased && cost > c.feeMsat) {
    p.push(`a cost of ${cost} msat for a request never written in full (at most the published fee, ${c.feeMsat} msat)`)
  }
  if (open && !open.bodyReleased && typeof o.reason === 'string' && AFTER_RELEASE_REASONS.has(o.reason)) {
    p.push(`reason ${shown(o.reason)}, though no body_released arrived`)
  }
  return p
}
