// Offline checks of the offer rules the reference client holds a node to
// (`src/offer.ts`): the receipt's upper bound and the image count key.
//   node --experimental-strip-types test/offer-check.ts
import assert from 'node:assert/strict'
import { MAX_BODY_LEN, checkImagesBlock, imageCountKeyForRoute, maxUsageCharge, padBody, paddedBodyLength } from '../src/offer.ts'

// The bound is the node's own formula: a usage with cached reads is bounded
// at the cached price, never at the uncached one.
const rates = { in: 1000, out: 2000, cached_in: 100, cache_write: 1250 }
const usage = (cached: number, written = 0) => ({
  prompt_tokens: 1000,
  completion_tokens: 10,
  prompt_tokens_details: { cached_tokens: cached, cache_creation_input_tokens: written },
})
assert.equal(maxUsageCharge(rates, usage(0)), 1000 + 20)
assert.equal(maxUsageCharge(rates, usage(1000)), 100 + 20)
assert.equal(maxUsageCharge(rates, usage(600)), 400 + 60 + 20)
// Writes at `cache_write` when dearer than `in`; at `in` when the write rate is lower.
assert.equal(maxUsageCharge(rates, usage(600, 400)), 500 + 60 + 20)
assert.equal(maxUsageCharge({ ...rates, cache_write: 500 }, usage(600, 400)), 400 + 60 + 20)
// No cached rate in the offer: cached reads cost `in`.
assert.equal(maxUsageCharge({ in: 1000, out: 2000 }, usage(1000)), 1000 + 20)
// A cached rate above `in` is capped at `in`.
assert.equal(maxUsageCharge({ in: 1000, out: 2000, cached_in: 5000 }, usage(1000)), 1000 + 20)

// The count key is the one the route reads.
const head = (path: string) => `POST ${path} HTTP/1.1\r\nHost: api.example.com\r\n\r\n`
assert.equal(imageCountKeyForRoute(head('/api/v1/image/generate')), 'variants')
assert.equal(imageCountKeyForRoute(head('/v1/images/generations')), 'n')
assert.equal(imageCountKeyForRoute(head('/v1/images/generations?x=1')), 'n')
assert.equal(imageCountKeyForRoute(head('/v1/chat/completions')), undefined)
assert.equal(imageCountKeyForRoute(undefined), undefined)
const block = (path: string, count_key?: string) => ({ head_template: head(path), count_key, max_count: 4, fixed_pins: [], param_space: {}, variants: [] })
checkImagesBlock(block('/api/v1/image/generate', 'variants'))
checkImagesBlock(block('/api/v1/image/generate'))
checkImagesBlock(block('/v1/images/generations', 'n'))
assert.throws(() => checkImagesBlock(block('/api/v1/image/generate', 'n')), /count_key/)
assert.throws(() => checkImagesBlock(block('/v1/images/generations', 'variants')), /count_key/)
assert.throws(() => checkImagesBlock(block('/v1/images/generations')), /count_key/)
assert.throws(() => checkImagesBlock(block('/v1/images/edits', 'n')), /head_template/)
// The optional body-size bucket: off, a multiple, a power of two, the cap.
assert.equal(paddedBodyLength(1234, undefined), 1234)
assert.equal(paddedBodyLength(1234, 4096), 4096)
assert.equal(paddedBodyLength(4096, 4096), 4096)
assert.equal(paddedBodyLength(4097, 4096), 8192)
assert.equal(paddedBodyLength(100, 'pow2'), 1024)
assert.equal(paddedBodyLength(5000, 'pow2'), 8192)
assert.equal(paddedBodyLength(MAX_BODY_LEN - 5, 'pow2'), MAX_BODY_LEN)
assert.equal(paddedBodyLength(MAX_BODY_LEN - 5, 3 << 20), MAX_BODY_LEN)
assert.throws(() => paddedBodyLength(10, 3), /bucket/)
{
  const enc = new TextEncoder()
  const body = padBody(enc.encode('{"messages":[]'), enc.encode(',"model":"m"}'), 64)
  assert.equal(body.length, 64)
  assert.deepEqual(JSON.parse(new TextDecoder().decode(body)), { messages: [], model: 'm' })
  assert.ok(new TextDecoder().decode(body).endsWith(' ,"model":"m"}'))
}
console.log('offer-check: ok')
