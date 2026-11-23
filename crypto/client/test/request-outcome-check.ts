// Offline checks of the rules the reference client holds a node's signed
// request outcome to (`src/request-outcome.ts`, PROTOCOL-V3.md §12.9, §12.10).
//   node --experimental-strip-types test/request-outcome-check.ts
import assert from 'node:assert/strict'
import { requestOutcomeProblems } from '../src/request-outcome.ts'

const SID = 'ab'.repeat(32)
const open = { n: 2, accepted: true, reservedMsats: 9000, bodyReleased: true }
const ctx = { sid: SID, framing: '2', open, feeMsat: 500 }
const o = (x: Record<string, unknown> = {}) => ({
  v: 1, sid: SID, http: '2', n: 2, outcome: 'charged', reason: 'request_received', cost_msats: 9000, reserved_msats: 9000, balance_msats: 1, time: 1, ...x,
})

// Honest outcomes.
assert.deepEqual(requestOutcomeProblems(o(), true, ctx), [])
const notWritten = { ...ctx, open: { ...open, bodyReleased: false } }
assert.deepEqual(requestOutcomeProblems(o({ reason: 'request_abandoned', cost_msats: 500 }), true, notWritten), [])
assert.deepEqual(requestOutcomeProblems(o({ reason: 'evicted', outcome: 'released', cost_msats: 0 }), true, notWritten), [])
assert.deepEqual(requestOutcomeProblems(o({ reason: 'provider_refused', cost_msats: 300 }), true, notWritten), [])
assert.deepEqual(requestOutcomeProblems(o({ reason: 'not_started', outcome: 'released', cost_msats: 0 }), true, { ...ctx, open: { n: 2, accepted: false, bodyReleased: false } }), [])
// No outcome needed: no request open, or one the node never accepted.
assert.deepEqual(requestOutcomeProblems(undefined, false, { ...ctx, open: undefined }), [])
assert.deepEqual(requestOutcomeProblems(undefined, false, { ...ctx, open: { n: 1, accepted: false, bodyReleased: false } }), [])

// Missing where the node accepted the request and settled nothing.
assert.match(requestOutcomeProblems(undefined, false, ctx).join(), /no signed outcome for request 2/)
// Signature, binding.
assert.match(requestOutcomeProblems(o(), false, ctx).join(), /without a valid signature/)
assert.match(requestOutcomeProblems(o({ sid: 'cd'.repeat(32) }), true, ctx).join(), /names connection/)
assert.match(requestOutcomeProblems(o({ n: 3 }), true, ctx).join(), /names request 3, the open one is 2/)
assert.match(requestOutcomeProblems(o({ http: '1.1' }), true, ctx).join(), /names framing/)
assert.match(requestOutcomeProblems(o(), true, { ...ctx, open: undefined }).join(), /no request was open/)
// Amounts.
assert.match(requestOutcomeProblems(o({ cost_msats: 9001 }), true, ctx).join(), /above the announced reservation/)
assert.match(requestOutcomeProblems(o({ reserved_msats: 9500, cost_msats: 9500 }), true, ctx).join(), /request_ok announced 9000/)
assert.match(requestOutcomeProblems(o({ reason: 'request_abandoned', cost_msats: 501 }), true, notWritten).join(), /never written in full/)
assert.match(requestOutcomeProblems(o({ cost_msats: 0 }), true, ctx).join(), /outcome "charged" with a cost of 0/)
assert.match(requestOutcomeProblems(o({ cost_msats: -1 }), true, ctx).join(), /a cost of -1/)
assert.match(requestOutcomeProblems(o({ cost_msats: 400 }), true, notWritten).join(), /no body_released/)
assert.match(requestOutcomeProblems(o({ reason: 'whatever' }), true, ctx).join(), /a reason "whatever"/)
// Without an announcement the outcome's own reservation bounds it.
assert.match(requestOutcomeProblems(o({ cost_msats: 9900, reserved_msats: 9000 }), true, { ...ctx, open: { n: 2, accepted: true, bodyReleased: true } }).join(), /its own reservation/)

console.log('request-outcome-check: ok')
