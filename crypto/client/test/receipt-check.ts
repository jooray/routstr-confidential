// Offline checks of the receipt rules the reference client holds a node to
// (`src/receipt-check.ts`), in particular the bound of a 5xx charge: the
// reservation the node announced in `request_ok`, never the receipt's own;
// and the attestation's certificate chain against the client's own.
//   node --experimental-strip-types test/receipt-check.ts
import assert from 'node:assert/strict'
import { hex } from '../src/advice.ts'
import { certChainProblem } from '../src/ctx.ts'
import { announcedReserve, makeReceiptChecker, reservationCeiling, signedContextLength, type ReceiptQuery } from '../src/receipt-check.ts'

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
  // A 5xx before body_released (the provider never had the whole request): the abandon fee.
  check(r({ cost_msats: 300, reserved_msats: 5000 }), q({ status: 502, reserved: 5000, released: false }))
  assert.throws(() => check(r({ cost_msats: 5000, reserved_msats: 5000 }), q({ status: 502, reserved: 5000, released: false })), /more than the 300/)
  check(r({ cost_msats: 5000, reserved_msats: 5000 }), q({ status: 502, reserved: 5000, released: true }))
  // Never more than the announced reservation, whatever the settlement:
  // a fee, a 4xx, a refusal, usage at the signed rates, images.
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 40 }), q({ reserved: 40 })), /more than the 40/)
  check(r({ cost_msats: 40, reserved_msats: 40 }), q({ reserved: 40 }))
  assert.throws(() => check(r({ cost_msats: 300, reserved_msats: 250 }), q({ status: 400, reserved: 250 })), /more than the 250 the node announced/)
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 99 }), q({ status: 429, reserved: 99 })), /more than the 99 the node announced/)
  {
    // Usage worth 580 msat at the signed rates (+ the fee), announced 100: 100 is the bound.
    const big = { prompt_tokens: 80, completion_tokens: 250 }
    check(r({ cost_msats: 100, reserved_msats: 100 }), q({ status: 200, usage: big, reserved: 100 }))
    assert.throws(() => check(r({ cost_msats: 580, reserved_msats: 100 }), q({ status: 200, usage: big, reserved: 100 })), /more than the 100 the node announced/)
    check(r({ cost_msats: 680, reserved_msats: 5000 }), q({ status: 200, usage: big, reserved: 5000 }))
    assert.throws(() => check(r({ cost_msats: 681, reserved_msats: 5000 }), q({ status: 200, usage: big, reserved: 5000 })), /more than the 680/)
    // A receipt that names no reservation, when one was announced.
    assert.throws(() => check(r({ cost_msats: 50 }), q({ status: 200, usage: big, reserved: 5000 })), /announced 5000/)
    // Prompt-cache writes are billed at the signed `cache_write`, also when it is below `in`.
    const cheap = { price_list: { m: { in: 1000, cached_in: 100, cache_write: 500, out: 2000 } } }
    const dear = { price_list: { m: { in: 1000, cached_in: 100, cache_write: 1250, out: 2000 } } }
    const cu = { prompt_tokens: 1000, completion_tokens: 10, prompt_tokens_details: { cached_tokens: 600, cache_creation_input_tokens: 400 } }
    const at = (o: any) => makeReceiptChecker('t', () => ({ offer: o, sessionFee: 0, abandonFee: 0 }))
    at(cheap)(r({ cost_msats: 280 }), q({ status: 200, usage: cu }))
    assert.throws(() => at(cheap)(r({ cost_msats: 281 }), q({ status: 200, usage: cu })), /more than the 280/)
    at(dear)(r({ cost_msats: 580 }), q({ status: 200, usage: cu }))
    assert.throws(() => at(dear)(r({ cost_msats: 581 }), q({ status: 200, usage: cu })), /more than the 580/)
  }
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
  // An image request's refusal receipt names its terms, as an error receipt does.
  check(ir({ cost_msats: 100, reserved_msats: 9000, usage: refused }), q({ status: 0, refusal: 'rst_stream', image, reserved: 9000 }))
  assert.throws(() => check(ir({ count: 1, cost_msats: 100, reserved_msats: 9000, usage: refused }), q({ status: 0, refusal: 'rst_stream', image, reserved: 9000 })), /image request's terms/)
  assert.throws(() => check(r({ cost_msats: 100, reserved_msats: 9000, usage: refused }), q({ status: 0, refusal: 'rst_stream', image, reserved: 9000 })), /image request's terms/)
  // An accepted image is the flat price exactly, and within the announced reservation.
  check(ir({ cost_msats: 2100, usage: { flat: true }, msat_per_image: 1000 }), q({ status: 200, image }))
  check(ir({ cost_msats: 2100, usage: { flat: true }, msat_per_image: 1000, reserved_msats: 2100 }), q({ status: 200, image, reserved: 2100 }))
  assert.throws(() => check(ir({ cost_msats: 2100, usage: { flat: true }, msat_per_image: 1000, reserved_msats: 2000 }), q({ status: 200, image, reserved: 2000 })), /more than the 2000 the node announced/)

  // The reservation ceiling: the node's formula from the signed offer only
  // (`context_lengths`, never the listing's row), as routstr-core's reserve().
  const rates = { in: 1000, cached_in: 500, out: 2000 }
  const signed = { price_list: { m: rates }, context_lengths: { m: 40_000 } }
  assert.equal(signedContextLength(signed, 'm'), 40_000)
  // 40000*1 + 8*2 msat (the node's test of the signed limit reserves exactly this)
  assert.equal(reservationCeiling(signed, 'm', 8, 1000), 40_016)
  // The dearer of in and cache_write, the margin and the larger fee.
  const dear = { price_list: { m: { ...rates, cache_write: 1500 } }, context_lengths: { m: 1000 }, reserve_margin_tokens: 16, session_fee_msat: 100, abandon_fee_msat: 300 }
  assert.equal(reservationCeiling(dear, 'm', 8, 1000), 1500 + 48 + 300)
  // Never below the deposit (plus the fee): the node's min_request_msat is not signed.
  assert.equal(reservationCeiling({ ...signed, context_lengths: { m: 10 } }, 'm', 8, 1000), 1000)
  // No ceiling: no entry, no deposit, a model the offer does not price, a bad entry.
  for (const [o, mid, dep] of [
    [{ price_list: { m: rates } }, 'm', 1000],
    [signed, 'm', 0],
    [{ ...signed, context_lengths: { x: 5 } }, 'x', 1000],
    ...[0, -1, 1.5, '40000', null, 2 ** 60].map((v) => [{ ...signed, context_lengths: { m: v } }, 'm', 1000]),
    [{ ...signed, context_lengths: [40_000] }, 'm', 1000],
  ] as [any, string, number][]) {
    assert.equal(reservationCeiling(o, mid, 8, dep), undefined, JSON.stringify(o))
  }
  // An inherited key is not an entry.
  assert.equal(signedContextLength({ context_lengths: Object.create({ m: 5 }) }, 'm'), undefined)

  // The attestation's certificate chain is always compared with the one our handshake validated.
  const chain = Uint8Array.from([1, 2, 3])
  assert.equal(certChainProblem(chain, hex(chain)), undefined)
  assert.match(certChainProblem(chain, hex(Uint8Array.from([1, 2, 4]))) ?? '', /different certificate chain/)
  assert.match(certChainProblem(chain, undefined) ?? '', /different certificate chain/)
  assert.match(certChainProblem(undefined, hex(chain)) ?? '', /no certificate chain was captured/)
  assert.match(certChainProblem(undefined, undefined) ?? '', /no certificate chain was captured/)
} finally {
  console.log = quiet
}
console.log('receipt-check: ok')
