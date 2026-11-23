// Offline checks of the rules the reference client holds a node's signed
// request outcome to (`src/request-outcome.ts`, PROTOCOL-V3.md §12.9, §12.10),
// on the vectors shared with the SDK and the browser library
// (crypto/conformance/request-outcome-vectors.json).
//   node --experimental-strip-types test/request-outcome-check.ts
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { REQUEST_OUTCOME_RULES, requestOutcomeProblems } from '../src/request-outcome.ts'

const vectors = JSON.parse(readFileSync(new URL('./fixtures/request-outcome-vectors.json', import.meta.url), 'utf8'))

// The per-reason table is the one the node computes.
assert.deepEqual(REQUEST_OUTCOME_RULES, vectors.rules)

for (const v of vectors.cases) {
  const p = requestOutcomeProblems(v.outcome, v.signed, v.ctx)
  if (v.ok) assert.deepEqual(p, [], v.name)
  else assert.ok(p.some((x) => x.includes(v.match)), `${v.name}: ${JSON.stringify(p)}`)
}

// No outcome needed: no request open, or one the node never accepted.
const ctx = { sid: 'ab'.repeat(32), framing: '2', sessionFeeMsat: 300, abandonFeeMsat: 500 }
assert.deepEqual(requestOutcomeProblems(undefined, false, ctx), [])
assert.deepEqual(requestOutcomeProblems(undefined, false, { ...ctx, open: { n: 1, accepted: false, bodyReleased: false } }), [])
// Missing where the node accepted the request and settled nothing.
assert.match(requestOutcomeProblems(undefined, false, { ...ctx, open: { n: 2, accepted: true, bodyReleased: true } }).join(), /no signed outcome for request 2/)
// An outcome with no request open.
const o = { v: 1, sid: ctx.sid, http: '2', n: 2, outcome: 'released', reason: 'not_started', cost_msats: 0, reserved_msats: 10 }
assert.match(requestOutcomeProblems(o, true, ctx).join(), /no request was open/)
// Without an announcement the outcome's own reservation bounds it.
assert.match(
  requestOutcomeProblems({ ...o, outcome: 'charged', reason: 'request_received', cost_msats: 9900, reserved_msats: 9000 }, true, { ...ctx, open: { n: 2, accepted: true, bodyReleased: true } }).join(),
  /its own reservation/,
)

console.log(`request-outcome-check: ok (${vectors.cases.length} shared vectors)`)
