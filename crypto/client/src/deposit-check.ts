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
}

/** The outcome as parsed from `deposit_json` (or `deposit`). */
export interface DepositOutcome {
  sid?: unknown
  msat?: unknown
  outcome?: unknown
  reason?: unknown
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
