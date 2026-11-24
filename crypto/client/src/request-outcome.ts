// The node's signed outcome of a request it finalized without a receipt
// (`request_outcome` on the connection's last frame, PROTOCOL-V3.md §12.9,
// §12.10), held to what the client saw of the request. Detection only: the
// client reports a deviation, it cannot undo a charge.

/**
 * The most a request outcome may cost under each reason, as the node computes
 * it (routstr-core `confidential_ws.py`: `_finalize_unsettled`, `_settle`,
 * `_refuse_unattested`). `before`: no `body_released` arrived for the request;
 * `after`: one did. `null`: the node never names that reason then.
 * `zero` nothing; `session_fee` the offer's session fee if still due (none
 * once the connection settled a request); `abandon_fee` max(the abandon fee,
 * the session fee if still due); `reservation` the announced reservation.
 * `disclosed`: only after the client disclosed (or accepted) the request's
 * answer. The same table is in crypto/conformance/request-outcome-vectors.json.
 */
export type Ceiling = 'zero' | 'session_fee' | 'abandon_fee' | 'reservation' | null
export const REQUEST_OUTCOME_RULES: Record<string, { before: Ceiling; after: Ceiling; disclosed?: boolean }> = {
  request_received: { before: null, after: 'reservation' },
  settlement_failed: { before: 'zero', after: 'reservation' },
  settled_without_receipt: { before: 'abandon_fee', after: 'reservation', disclosed: true },
  unattested: { before: 'zero', after: 'zero' },
  provider_refused: { before: 'session_fee', after: null },
  provider_unreachable: { before: 'zero', after: null },
  sidecar_failure: { before: 'zero', after: null },
  evicted: { before: 'zero', after: null },
  request_abandoned: { before: 'abandon_fee', after: null },
  not_started: { before: 'zero', after: null },
}

/** The reasons a node names in `request_outcome.reason` (§12.10). */
export const REQUEST_OUTCOME_REASONS = new Set(Object.keys(REQUEST_OUTCOME_RULES))

/** The request the client had open when the last frame arrived. */
export interface OpenRequest {
  n: number
  /** The node accepted it (`request_ok`). */
  accepted: boolean
  /** `request_ok.reserved_msats`, when the node announced it. */
  reservedMsats?: number
  /** A `body_released` for it arrived. */
  bodyReleased: boolean
  /** The client sent `disclose`, `disclose_head`, `disclose_reset` or `accept` for it (undefined: not tracked). */
  disclosed?: boolean
}

export interface RequestOutcomeContext {
  sid: string
  framing: string
  /** The request neither refused nor settled (none: no request open). */
  open?: OpenRequest
  /** The session fee if still due for this request (0 once the connection settled one). */
  sessionFeeMsat: number
  /** max(the offer's abandon fee, the session fee if still due). */
  abandonFeeMsat: number
  /** The last frame that carries the outcome (`closed` or `error`), when judged. */
  frame?: { type?: unknown; reason?: unknown; fault?: unknown }
  /** The deposit outcome on the same frame (parsed), when there is one. */
  deposit?: { outcome?: unknown; reason?: unknown }
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
  const rule = typeof o.reason === 'string' && Object.prototype.hasOwnProperty.call(REQUEST_OUTCOME_RULES, o.reason) ? REQUEST_OUTCOME_RULES[o.reason] : undefined
  if (!rule) p.push(`a reason ${shown(o.reason)}`)
  const cost = o.cost_msats
  if (!(Number.isSafeInteger(cost) && cost >= 0)) {
    p.push(`a cost of ${shown(cost)}`)
    return p
  }
  if ((o.outcome === 'charged') !== cost > 0) p.push(`outcome ${shown(o.outcome)} with a cost of ${cost} msat`)
  let reserved: number | undefined
  if (open?.reservedMsats !== undefined) {
    reserved = open.reservedMsats
    if (o.reserved_msats !== open.reservedMsats) p.push(`reserved_msats ${shown(o.reserved_msats)}, request_ok announced ${open.reservedMsats}`)
    if (cost > open.reservedMsats) p.push(`a cost of ${cost} msat above the announced reservation of ${open.reservedMsats}`)
  } else if (Number.isSafeInteger(o.reserved_msats) && o.reserved_msats >= 0) {
    reserved = o.reserved_msats
    if (cost > o.reserved_msats) p.push(`a cost of ${cost} msat above its own reservation of ${o.reserved_msats}`)
  }
  if (open && rule) {
    const ceiling = open.bodyReleased ? rule.after : rule.before
    if (ceiling === null) {
      p.push(open.bodyReleased ? `reason ${shown(o.reason)} after body_released` : `reason ${shown(o.reason)}, though no body_released arrived`)
    } else {
      const max = ceiling === 'zero' ? 0 : ceiling === 'session_fee' ? c.sessionFeeMsat : ceiling === 'abandon_fee' ? c.abandonFeeMsat : reserved
      if (max !== undefined && cost > max) p.push(`a cost of ${cost} msat with reason ${shown(o.reason)} (at most ${max} msat)`)
    }
    if (rule.disclosed && open.disclosed === false) p.push(`reason ${shown(o.reason)}, though the client disclosed nothing for request ${open.n}`)
  }
  // The outcome against the frame that carries it.
  if (cost > 0 && c.deposit?.outcome === 'charged') {
    p.push('a charge on the same frame as a charged deposit (the deposit is the price of the request it abandoned)')
  }
  const f = c.frame
  if (f && cost > 0 && o.reason === 'request_abandoned' && f.type === 'error' && (f.fault === 'node' || f.fault === 'upstream')) {
    p.push(`the abandon fee after a fault of the ${f.fault === 'node' ? 'node' : 'provider'}`)
  }
  if (f) {
    const evictedFrame = f.type === 'closed' && f.reason === 'evicted'
    if (evictedFrame && o.reason !== 'evicted') p.push(`reason ${shown(o.reason)} on an eviction (the request of an evicted connection is released as "evicted")`)
    if (!evictedFrame && o.reason === 'evicted') p.push('reason "evicted", but the last frame is not `closed` `evicted`')
  }
  return p
}
