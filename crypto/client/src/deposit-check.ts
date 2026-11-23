// The connection deposit's outcome as the node reports it in its last frame
// (`closed` or `error`, PROTOCOL-V3.md §12.9), held to the signed terms and
// the table of §12.10. Detection only: the client reports a deviation, it
// cannot undo a charge.

/** The reasons of §12.10 under which the node releases a connection's deposit. */
export const DEPOSIT_RELEASED_REASONS = new Set([
  'request_settled',
  'not_started',
  'provider_unreachable',
  'sidecar_failure',
  'provider_closed',
  'node_failure',
  'request_received',
  'provider_refused',
  // An older node released the deposit of an evicted lone spare under this
  // reason; the current one always charges an evicted unused connection.
  'evicted_released',
])

/** What the client knows of the connection when the last frame arrives. */
export interface DepositContext {
  /** The connection's sid; '' before `ready`. */
  sid: string
  /** The signed offer's deposit (msat). */
  depositMsat: number
  /** A receipt of this connection released the deposit. */
  releasedByReceipt: boolean
  /** The outcome's signature verified (default: not judged). */
  signed?: boolean
  /** A `request` of the client is neither refused nor settled (default: not judged). */
  requestOpen?: boolean
  /** The node accepted the open request (`request_ok`; default: not judged). */
  openAccepted?: boolean
  /** The connection's framing (default: not judged). */
  framing?: string
  /** The client wrote its ClientHello (default: not judged). */
  helloSent?: boolean
  /** The signed offer's `evict_unused_after_s` (undefined: the offer has none, an older node). */
  evictAfterS?: number
  /** Seconds from the client's `setup` to the last frame (default: not judged). */
  ageS?: number
}

/** The outcome as parsed from `deposit_json` (or `deposit`). */
export interface DepositOutcome {
  sid?: unknown
  msat?: unknown
  outcome?: unknown
  reason?: unknown
  /** An eviction under slot pressure: the evictable unused connections its address held. */
  evicted?: unknown
}

/** `evicted.unused_at_address` of a deposit outcome, if well formed (an older node also sent `charge_from`, ignored). */
function evictionCount(d: DepositOutcome): number | undefined {
  const e = d.evicted as { unused_at_address?: unknown } | undefined
  if (!e || typeof e !== 'object') return undefined
  const n = e.unused_at_address
  return Number.isSafeInteger(n) && (n as number) >= 1 ? (n as number) : undefined
}

/**
 * Why the node's deposit outcome deviates from its signed terms, one entry
 * per rule (none: it does not). `frame` is the last frame (`closed` or
 * `error`), `d` the outcome it carries.
 */
export function depositProblems(frame: any, d: DepositOutcome, c: DepositContext): string[] {
  const problems: string[] = []
  // `sid: null` only for a setup the node could not serve, before `ready`.
  if (!(d.sid === c.sid || (d.sid === null && c.sid === ''))) {
    problems.push(`it names connection ${JSON.stringify(d.sid ?? null).slice(0, 80)}, not ${c.sid ? c.sid.slice(0, 16) : 'none (before ready)'}`)
  }
  if (d.outcome !== 'released' && d.outcome !== 'charged') problems.push(`an outcome ${JSON.stringify(d.outcome ?? null).slice(0, 40)}`)
  if (d.msat !== c.depositMsat) problems.push(`a deposit of ${JSON.stringify(d.msat ?? null).slice(0, 32)} msat, the signed offer's is ${c.depositMsat} msat`)
  if (d.outcome === 'charged') {
    if (c.releasedByReceipt) problems.push('charged, though a receipt of this connection released it')
    if (frame?.type === 'error' && (frame.fault === 'node' || frame.fault === 'upstream')) {
      problems.push(`charged after a fault of the ${frame.fault === 'node' ? 'node' : 'provider'} (released by §12.10 rows 3 and 4)`)
    }
    if (typeof d.reason === 'string' && DEPOSIT_RELEASED_REASONS.has(d.reason)) {
      problems.push(`charged with reason ${JSON.stringify(d.reason)}, which releases it`)
    }
    if (c.signed === false) problems.push('charged without a valid signature of the node')
    // Row 13: a newer setup closed the connection while it held its slot
    // unused (§8.4), always charged. Only on that `closed` frame, only past
    // the signed offer's `evict_unused_after_s`, and never with a request
    // the node had accepted, except a framing-"1.1" request 1 whose
    // ClientHello the client had not written.
    const evictedUnused = frame?.type === 'closed' && frame.reason === 'evicted' && frame.unused === true
    if (d.reason === 'evicted' && !evictedUnused) problems.push('charged as evicted, but the last frame is not `closed` `evicted` with `unused: true`')
    if (evictedUnused && d.reason !== 'evicted') problems.push(`charged with reason ${JSON.stringify(d.reason ?? null).slice(0, 40)} on an eviction (row 13 names "evicted")`)
    if (frame?.type === 'closed' && frame.reason === 'evicted' && frame.unused !== true) {
      problems.push('charged on the eviction of a used connection (it holds no deposit)')
    }
    if (d.reason === 'evicted') {
      if (evictionCount(d) === undefined) problems.push('charged as evicted without the signed count of the address\'s unused connections')
      if (c.evictAfterS === 0) problems.push('charged as evicted, though the signed offer says unused connections are never evicted (evict_unused_after_s 0)')
      else if (c.evictAfterS !== undefined && c.ageS !== undefined && c.ageS < c.evictAfterS) {
        problems.push(`charged as evicted ${Math.floor(c.ageS)} s after the setup, before the signed offer's evict_unused_after_s of ${c.evictAfterS} s`)
      }
      if (c.openAccepted === true && !(c.framing === '1.1' && c.helloSent === false)) {
        problems.push('charged as evicted, though the node had accepted a request of it (never evicted)')
      }
    }
    // Row 5: the provider closed the open connection while no request of the
    // client was open, and not after control frames of the client alone.
    if (frame?.type === 'closed' && frame.reason === 'upstream_closed' && frame.after_client_frames !== true && c.requestOpen === false) {
      problems.push('charged though the provider closed the connection with no request open (released by §12.10 row 5)')
    }
  }
  return problems
}

/**
 * A connection that reserved a deposit ended with a last frame of the node
 * (`closed` or `error`) and no deposit outcome, though no receipt released
 * it (§12.9: the last frame carries the outcome). Null when nothing is
 * missing: no deposit, before `ready`, released by a receipt, or an outcome
 * was reported.
 */
export function missingDepositProblem(c: DepositContext, sawLastFrame: boolean, reported: boolean): string | null {
  if (!sawLastFrame || reported || c.releasedByReceipt || !(c.depositMsat > 0) || c.sid === '') return null
  return `no deposit outcome in the node's last frame for a deposit of ${c.depositMsat} msat`
}

/**
 * The session socket ended without the node's last frame (`closed` or
 * `error`) and not by the client's own close, though the node holds money of
 * the connection: a deposit no receipt released, or a request it accepted
 * and did not settle. Whatever the node did with them, it said nothing
 * signed (§12.9: the outcomes travel on the last frame). Null when nothing is
 * held. Detection only; a lost network path looks the same.
 */
export function missingLastFrameProblem(c: {
  sid: string
  depositMsat: number
  releasedByReceipt: boolean
  /** The request the node accepted and did not settle, if any. */
  openAccepted?: number
}): string | null {
  if (c.sid === '') return null
  const held: string[] = []
  if (c.depositMsat > 0 && !c.releasedByReceipt) held.push(`the deposit of ${c.depositMsat} msat`)
  if (c.openAccepted !== undefined) held.push(`the reservation of request ${c.openAccepted}`)
  return held.length ? `the socket ended without the node's last frame: no signed outcome for ${held.join(' and ')} (check the balance)` : null
}
