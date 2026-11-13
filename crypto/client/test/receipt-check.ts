// Offline checks of the receipt rules the reference client holds a node to
// (`src/receipt-check.ts`), in particular the bound of a 5xx charge: the
// reservation the node announced in `request_ok`, never the receipt's own.
//   node --experimental-strip-types test/receipt-check.ts
import assert from 'node:assert/strict'
import { announcedReserve, makeReceiptChecker, type ReceiptQuery } from '../src/receipt-check.ts'

const quiet = console.log
console.log = () => {}
try {
  const offer = { price_list: { m: { in: 1000, out: 2000 } } }
  const check = makeReceiptChecker('t', () => ({ offer, sessionFee: 100, abandonFee: 300 }))
  const q = (o: Partial<ReceiptQuery>): ReceiptQuery => ({ n: 1, http: '2', model: 'm', status: 500, usage: undefined, first: true, ...o })
  const r = (o: Record<string, unknown>) => ({ model: 'm', ...o })

  // request_ok.reserved_msats: absent or a non-negative safe integer.
  assert.equal(announcedReserve({}), undefined)
  assert.equal(announcedReserve({ reserved_msats: 0 }), 0)
  assert.equal(announcedReserve({ reserved_msats: 5000 }), 5000)
  for (const bad of [-1, 1.5, '5000', null, 2 ** 60]) assert.throws(() => announcedReserve({ reserved_msats: bad }), /reserved_msats/)

  // 5xx with an announced reservation: up to it, and the receipt must name it.
  check(r({ cost_msats: 5000, reserved_msats: 5000 }), q({ reserved: 5000 }))
  assert.throws(() => check(r({ cost_msats: 5001, reserved_msats: 5000 }), q({ reserved: 5000 })), /more than the 5000/)
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 9000 }), q({ reserved: 5000 })), /announced 5000/)
  assert.throws(() => check(r({ cost_msats: 100 }), q({ reserved: 5000 })), /announced 5000/)
  // The session fee when it is more than the reservation.
  check(r({ cost_msats: 100, reserved_msats: 40 }), q({ reserved: 40 }))
  // 5xx and nothing announced: the receipt's own number does not raise the bound.
  check(r({ cost_msats: 100, reserved_msats: 9000 }), q({}))
  assert.throws(() => check(r({ cost_msats: 101, reserved_msats: 9000 }), q({})), /more than the 100/)
  assert.throws(() => check(r({ cost_msats: 1, reserved_msats: 9000 }), q({ first: false })), /more than the 0/)
  // 503 and the 4xx rules are as before.
  assert.throws(() => check(r({ cost_msats: 101, reserved_msats: 5000 }), q({ status: 503, reserved: 5000 })), /more than the 100/)
  check(r({ cost_msats: 300, reserved_msats: 5000 }), q({ status: 400, reserved: 5000 }))
  assert.throws(() => check(r({ cost_msats: 301, reserved_msats: 5000 }), q({ status: 400, reserved: 5000 })), /more than the 300/)
  // A success receipt naming another reservation is refused too.
  const usage = { prompt_tokens: 10, completion_tokens: 10 }
  check(r({ cost_msats: 50, reserved_msats: 5000 }), q({ status: 200, usage, reserved: 5000 }))
  assert.throws(() => check(r({ cost_msats: 50, reserved_msats: 4000 }), q({ status: 200, usage, reserved: 5000 })), /announced 5000/)

  // Images: an error receipt is also capped at the images' price plus a fee.
  const image = { variant: 'v', count: 2, path: '/x', headTemplate: '', responseShape: 'venice', msatPerImage: 1000 }
  const ir = (o: Record<string, unknown>) => ({ kind: 'images', model: 'm', variant: 'v', count: 2, ...o })
  check(ir({ cost_msats: 2300, reserved_msats: 9000 }), q({ image, reserved: 9000 }))
  assert.throws(() => check(ir({ cost_msats: 2301, reserved_msats: 9000 }), q({ image, reserved: 9000 })), /more than the 2300/)
  check(ir({ cost_msats: 1500, reserved_msats: 1500 }), q({ image, reserved: 1500 }))
  assert.throws(() => check(ir({ cost_msats: 1501, reserved_msats: 1500 }), q({ image, reserved: 1500 })), /more than the 1500/)
  assert.throws(() => check(ir({ cost_msats: 1, reserved_msats: 1500, count: 1 }), q({ image, reserved: 1500 })), /image request's terms/)
  // A disclosed refusal (`disclose_reset`): the session fee if still due, nothing else.
  const refused = { refused: 'rst_stream', error_code: 7, choices: [] }
  check(r({ cost_msats: 100, reserved_msats: 5000, usage: refused }), q({ status: 0, refusal: 'rst_stream', reserved: 5000 }))
  check(r({ cost_msats: 0, reserved_msats: 5000, usage: refused }), q({ status: 0, refusal: 'rst_stream', reserved: 5000, first: false }))
  assert.throws(() => check(r({ cost_msats: 101, reserved_msats: 5000, usage: refused }), q({ status: 0, refusal: 'rst_stream', reserved: 5000 })), /more than the 100/)
  assert.throws(() => check(r({ cost_msats: 1, reserved_msats: 5000, usage: refused }), q({ status: 0, refusal: 'rst_stream', reserved: 5000, first: false })), /more than the 0/)
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 5000, usage: refused }), q({ status: 0, refusal: 'goaway', reserved: 5000 })), /not the goaway/)
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 4000, usage: refused }), q({ status: 0, refusal: 'rst_stream', reserved: 5000 })), /announced 5000/)
  // An accepted image is the flat price exactly.
  check(ir({ cost_msats: 2100, usage: { flat: true }, msat_per_image: 1000 }), q({ status: 200, image }))
} finally {
  console.log = quiet
}
console.log('receipt-check: ok')
