// Offline checks of the deposit-outcome rules the reference client holds a
// node to (`src/deposit-check.ts`, PROTOCOL-V3.md §12.9, §12.10).
//   node --experimental-strip-types test/deposit-check.ts
import assert from 'node:assert/strict'
import { DEPOSIT_RELEASED_REASONS, depositProblems, missingDepositProblem, missingLastFrameProblem, refusalMarksNodeFailure } from '../src/deposit-check.ts'

const SID = 'ab'.repeat(32)
const ctx = { sid: SID, depositMsat: 7000, releasedByReceipt: false }
const closed = { type: 'closed' }
const d = (o: Record<string, unknown>) => {
  const x: Record<string, unknown> = { sid: SID, msat: 7000, outcome: 'charged', reason: 'unused', ...o }
  return { cost_msats: x.outcome === 'charged' ? x.msat : 0, ...x }
}

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
const evicted0 = () => ({ type: 'closed', reason: 'evicted', unused: true })
assert.match(depositProblems(upClosed, d({}), { ...ctx, requestOpen: false }).join(), /row 5/)
assert.deepEqual(depositProblems({ ...upClosed, after_client_frames: true }, d({}), { ...ctx, requestOpen: false }), [])
assert.deepEqual(depositProblems(upClosed, d({ reason: 'request_abandoned' }), { ...ctx, requestOpen: true }), [])
assert.deepEqual(depositProblems({ type: 'closed', reason: 'idle' }, d({ reason: 'idle' }), { ...ctx, requestOpen: false }), [])
assert.deepEqual(depositProblems(upClosed, d({ outcome: 'released', reason: 'provider_closed' }), { ...ctx, requestOpen: false }), [])

// Row 6: a 5xx refusal of the node's own, no request accepted after it.
assert.match(depositProblems(closed, d({}), { ...ctx, refused5xx: true }).join(), /row 6/)
assert.match(depositProblems(closed, d({ reason: 'request_abandoned' }), { ...ctx, refused5xx: true }).join(), /row 6/)
assert.match(depositProblems(evicted0(), d({ reason: 'evicted', evicted: { unused_at_address: 2 } }), { ...ctx, refused5xx: true }).join(), /row 6/)
assert.deepEqual(depositProblems(closed, d({ outcome: 'released', reason: 'node_failure' }), { ...ctx, refused5xx: true }), [])
assert.deepEqual(depositProblems(closed, d({}), { ...ctx, refused5xx: false }), [])
// Which refusals mark it: a 5xx of a request that named an API key, not a
// Cashu token, and not `wallet_busy`.
assert.equal(refusalMarksNodeFailure({ status: 500, reason: 'reservation failed' }, 'sk-abc'), true)
assert.equal(refusalMarksNodeFailure({ status: 503, detail: { error: { type: 'wallet_busy' } } }, 'sk-abc'), false)
assert.equal(refusalMarksNodeFailure({ status: 500 }, 'cashuBo2F0gaJhaUgA'), false)
assert.equal(refusalMarksNodeFailure({ status: 500 }, undefined), false)
assert.equal(refusalMarksNodeFailure({ status: 402 }, 'sk-abc'), false)
assert.equal(refusalMarksNodeFailure({ status: '500' }, 'sk-abc'), false)

// What the credential paid: the deposit when charged, nothing when released.
assert.match(depositProblems(closed, d({ cost_msats: 6999 }), ctx).join(), /cost of 6999 msat, the deposit is 7000/)
assert.match(depositProblems(closed, d({ cost_msats: undefined }), ctx).join(), /cost of null msat/)
assert.match(depositProblems(closed, d({ outcome: 'released', reason: 'node_failure', cost_msats: 7000 }), ctx).join(), /released at a cost of 7000/)
assert.match(depositProblems(closed, d({ outcome: 'released', reason: 'node_failure', cost_msats: undefined }), ctx).join(), /released at a cost of null/)

// A last frame with no outcome for a deposit nothing released.
assert.match(missingDepositProblem(ctx, true, false) ?? '', /no deposit outcome .* 7000 msat/)
assert.equal(missingDepositProblem(ctx, true, true), null)
assert.equal(missingDepositProblem(ctx, false, false), null) // the client left first
assert.equal(missingDepositProblem({ ...ctx, releasedByReceipt: true }, true, false), null)
assert.equal(missingDepositProblem({ ...ctx, depositMsat: 0 }, true, false), null)
assert.equal(missingDepositProblem({ ...ctx, sid: '' }, true, false), null) // refused before ready

// Row 13: closed for a newer setup while unused. Charged when signed, on
// `closed` `evicted` `unused: true`: always charged, with the node's signed
// count of its address's unused connections, no releasing receipt, past the
// signed offer's minimum age, and no request the node had accepted (except a
// framing-"1.1" request 1 whose ClientHello the client had not written).
const evicted = { type: 'closed', reason: 'evicted', unused: true }
const hoard = { evicted: { unused_at_address: 5 } }
const lone = { evicted: { unused_at_address: 1 } }
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', ...hoard }), { ...ctx, signed: true, requestOpen: false }), [])
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, requestOpen: false }), [])
// An older node's fields: a released lone spare, and a charge_from beside the count.
assert.deepEqual(depositProblems(evicted, d({ outcome: 'released', reason: 'evicted_released', evicted: { unused_at_address: 1, charge_from: 5 } }), { ...ctx, signed: true }), [])
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', evicted: { unused_at_address: 5, charge_from: 5 } }), { ...ctx, signed: true }), [])
assert.match(depositProblems(evicted, d({ reason: 'evicted' }), { ...ctx, signed: true }).join(), /without the signed count/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', evicted: { unused_at_address: 0 } }), { ...ctx, signed: true }).join(), /without the signed count/)
assert.match(depositProblems(evicted, d({ reason: 'evicted_released', ...lone }), ctx).join(), /which releases it/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...hoard }), { ...ctx, releasedByReceipt: true }).join(), /receipt of this connection released it/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...hoard }), { ...ctx, signed: false }).join(), /without a valid signature/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...hoard }), { ...ctx, requestOpen: true, openAccepted: true }).join(), /had accepted a request/)
// Framing "1.1": request 1 comes before the 2PC and the ClientHello; without the ClientHello it does not hold the slot.
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, requestOpen: true, openAccepted: true, framing: '1.1', helloSent: false }), [])
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, openAccepted: true, framing: '1.1', helloSent: true }).join(), /had accepted a request/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, openAccepted: true, framing: '2', helloSent: false }).join(), /had accepted a request/)
// The signed offer's minimum age (absent: an older node, not judged).
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, evictAfterS: 60, ageS: 61 }), [])
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, evictAfterS: 60, ageS: 30 }).join(), /before the signed offer's evict_unused_after_s of 60 s/)
assert.match(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, evictAfterS: 0, ageS: 900 }).join(), /never evicted/)
assert.deepEqual(depositProblems(evicted, d({ reason: 'evicted', ...lone }), { ...ctx, signed: true, ageS: 1 }), [])
assert.match(depositProblems(closed, d({ reason: 'evicted', ...hoard }), ctx).join(), /not `closed` `evicted`/)
assert.match(depositProblems({ type: 'closed', reason: 'evicted' }, d({ reason: 'evicted', ...hoard }), ctx).join(), /used connection/)
assert.match(depositProblems(evicted, d({ reason: 'unused' }), ctx).join(), /on an eviction/)

// The socket ended without the node's last frame while the node held money.
assert.equal(missingLastFrameProblem({ sid: '', depositMsat: 7000, releasedByReceipt: false }), null)
assert.equal(missingLastFrameProblem({ sid: SID, depositMsat: 7000, releasedByReceipt: true }), null)
assert.match(String(missingLastFrameProblem({ sid: SID, depositMsat: 7000, releasedByReceipt: false })), /the deposit of 7000 msat/)
assert.match(String(missingLastFrameProblem({ sid: SID, depositMsat: 0, releasedByReceipt: true, openAccepted: 3 })), /the reservation of request 3/)

console.log('deposit-check: ok')
