// Offline checks of the deposit-outcome rules the reference client holds a
// node to (`src/deposit-check.ts`, PROTOCOL-V3.md §12.9, §12.10).
//   node --experimental-strip-types test/deposit-check.ts
import assert from 'node:assert/strict'
import { DEPOSIT_RELEASED_REASONS, depositProblems, missingDepositProblem } from '../src/deposit-check.ts'

const SID = 'ab'.repeat(32)
const ctx = { sid: SID, depositMsat: 7000, releasedByReceipt: false }
const closed = { type: 'closed' }
const d = (o: Record<string, unknown>) => ({ sid: SID, msat: 7000, outcome: 'charged', reason: 'unused', ...o })

// Honest outcomes.
assert.deepEqual(depositProblems(closed, d({}), ctx), [])
assert.deepEqual(depositProblems(closed, d({ reason: 'idle' }), ctx), [])
assert.deepEqual(depositProblems({ type: 'error', code: 'frame_too_large', status: 413 }, d({}), ctx), [])
assert.deepEqual(depositProblems({ type: 'error' }, d({ reason: 'request_abandoned' }), ctx), [])
for (const reason of DEPOSIT_RELEASED_REASONS) assert.deepEqual(depositProblems(closed, d({ outcome: 'released', reason }), ctx), [], reason)
// Released after a receipt released it: the same word twice, no deviation.
assert.deepEqual(depositProblems(closed, d({ outcome: 'released', reason: 'request_settled' }), { ...ctx, releasedByReceipt: true }), [])

// The amount is the signed offer's.
assert.match(depositProblems(closed, d({ msat: 7001 }), ctx).join(), /7001 msat, the signed offer's is 7000/)
assert.match(depositProblems(closed, d({ msat: '7000' }), ctx).join(), /signed offer's is 7000/)
assert.match(depositProblems(closed, d({ outcome: 'released', reason: 'request_settled', msat: 0 }), ctx).join(), /signed offer's/)

// Charged though a receipt of this connection released it.
assert.match(depositProblems(closed, d({ reason: 'idle' }), { ...ctx, releasedByReceipt: true }).join(), /receipt of this connection released it/)

// Charged with the last frame carrying a fault of the node or the provider.
assert.match(depositProblems({ type: 'error', fault: 'upstream' }, d({}), ctx).join(), /fault of the provider/)
assert.match(depositProblems({ type: 'error', fault: 'node' }, d({}), ctx).join(), /fault of the node/)
// A `closed` frame does not carry a fault; another fault value is not a rule.
assert.deepEqual(depositProblems({ type: 'closed', fault: 'upstream' }, d({}), ctx), [])

// Charged with a reason that releases it.
for (const reason of DEPOSIT_RELEASED_REASONS) {
  assert.match(depositProblems(closed, d({ reason }), ctx).join(), /which releases it/, reason)
}

// `sid: null` only before `ready`; another sid never.
assert.deepEqual(depositProblems(closed, d({ sid: null }), { ...ctx, sid: '' }), [])
assert.match(depositProblems(closed, d({ sid: null }), ctx).join(), /names connection null/)
assert.match(depositProblems(closed, d({ sid: 'cd'.repeat(32) }), ctx).join(), /names connection/)
assert.match(depositProblems(closed, d({ sid: SID }), { ...ctx, sid: '' }).join(), /before ready/)

// An outcome that is neither word.
assert.match(depositProblems(closed, d({ outcome: 'kept' }), ctx).join(), /an outcome "kept"/)

// Several rules at once: each is named.
assert.equal(depositProblems({ type: 'error', fault: 'node' }, d({ msat: 1, reason: 'node_failure' }), { ...ctx, releasedByReceipt: true }).length, 4)

// A charge needs the node's signature; a release is judged by its content.
assert.match(depositProblems(closed, d({}), { ...ctx, signed: false }).join(), /without a valid signature/)
assert.deepEqual(depositProblems(closed, d({}), { ...ctx, signed: true }), [])
assert.deepEqual(depositProblems(closed, d({ outcome: 'released', reason: 'provider_closed' }), { ...ctx, signed: false }), [])

// Row 5: the provider closed the open connection with no request of the
// client open. Charged then only after control frames of the client alone.
const upClosed = { type: 'closed', reason: 'upstream_closed' }
assert.match(depositProblems(upClosed, d({}), { ...ctx, requestOpen: false }).join(), /row 5/)
assert.deepEqual(depositProblems({ ...upClosed, after_client_frames: true }, d({}), { ...ctx, requestOpen: false }), [])
assert.deepEqual(depositProblems(upClosed, d({ reason: 'request_abandoned' }), { ...ctx, requestOpen: true }), [])
assert.deepEqual(depositProblems({ type: 'closed', reason: 'idle' }, d({ reason: 'idle' }), { ...ctx, requestOpen: false }), [])
assert.deepEqual(depositProblems(upClosed, d({ outcome: 'released', reason: 'provider_closed' }), { ...ctx, requestOpen: false }), [])

// A last frame with no outcome for a deposit nothing released.
assert.match(missingDepositProblem(ctx, true, false) ?? '', /no deposit outcome .* 7000 msat/)
assert.equal(missingDepositProblem(ctx, true, true), null)
assert.equal(missingDepositProblem(ctx, false, false), null) // the client left first
assert.equal(missingDepositProblem({ ...ctx, releasedByReceipt: true }, true, false), null)
assert.equal(missingDepositProblem({ ...ctx, depositMsat: 0 }, true, false), null)
assert.equal(missingDepositProblem({ ...ctx, sid: '' }, true, false), null) // refused before ready

// Row 13: closed for a newer setup while unused. Legitimate when signed, on
// `closed` `evicted` `unused: true`, with no receipt and no request written in full.
const evicted = { type: 'closed', reason: 'evicted', unused: true }
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, signed: true, requestOpen: false }), [])
// A first request accepted and stalled: evicted too, its reservation released.
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, signed: true, requestOpen: true, requestReleased: false }), [])
assert.match(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, releasedByReceipt: true }).join(), /receipt of this connection released it/)
assert.match(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, signed: false }).join(), /without a valid signature/)
assert.match(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, requestOpen: true, requestReleased: true }).join(), /written in full/)
assert.match(depositProblems(closed, d({ reason: 'evicted' }), ctx).join(), /not `closed` `evicted`/)
assert.match(depositProblems({ type: 'closed', reason: 'evicted' }, d({ reason: 'evicted' }), ctx).join(), /used connection/)
assert.match(depositProblems(evicted, d({ reason: 'unused' }), ctx).join(), /on an eviction/)
assert.deepEqual(depositProblems(evicted, d({ outcome: 'released', reason: 'not_started' }), ctx), [])

console.log('deposit-check: ok')
