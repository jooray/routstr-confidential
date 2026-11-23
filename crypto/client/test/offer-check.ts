// Offline checks of the offer rules the reference client holds a node to
// (`src/offer.ts`, `src/check-offer.ts`): the receipt's upper bound, the
// image count key, the request routes and the trusted-host requirement.
//   node --experimental-strip-types test/offer-check.ts
import assert from 'node:assert/strict'
import { OfferRefused, checkOffer, headRouteProblem, imagesBlock, trustedHosts } from '../src/check-offer.ts'
import { MAX_BODY_LEN, checkImagesBlock, imageCountKeyForRoute, maxUsageCharge, padBody, paddedBodyLength, pinnedModel, renderChatSuffix, upstreamModelsProblem, contextLengthsProblem } from '../src/offer.ts'

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
// Writes at the signed `cache_write`, dearer than `in` or cheaper: the node's formula exactly.
assert.equal(maxUsageCharge(rates, usage(600, 400)), 500 + 60 + 20)
assert.equal(maxUsageCharge({ ...rates, cache_write: 500 }, usage(600, 400)), 200 + 60 + 20)
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

// upstream_models: the suffix pins the provider's own id for a public id.
{
  const offer = { price_list: { 'kimi-k3.1-pro': rates, same: rates }, upstream_models: { 'kimi-k3.1-pro': 'moonshotai/kimi-k3.1-pro' } }
  assert.equal(upstreamModelsProblem(offer), null)
  assert.equal(upstreamModelsProblem({ price_list: {} }), null)
  assert.equal(pinnedModel(offer, 'kimi-k3.1-pro'), 'moonshotai/kimi-k3.1-pro')
  assert.equal(pinnedModel(offer, 'same'), 'same')
  assert.equal(pinnedModel({}, 'x'), 'x')
  const chat = { cap_keys: ['max_tokens'], fixed_pins: [['stream', true]] }
  assert.equal(renderChatSuffix(chat, pinnedModel(offer, 'kimi-k3.1-pro'), 9), ',"model":"moonshotai/kimi-k3.1-pro","max_tokens":9,"stream":true}')
  for (const bad of [[], 'x', { other: 'a/b' }, { same: 'same' }, { same: 'a"b' }, { same: 'a\\b' }, { same: '' }, { same: 'a b' }, { same: 7 }]) {
    assert.notEqual(upstreamModelsProblem({ price_list: offer.price_list, upstream_models: bad }), null, JSON.stringify(bad))
  }
  const ok1 = 'llama-3.2-1b-instruct', ok2 = 'lfm-2.5-2.6b:free'
  assert.equal(upstreamModelsProblem({ price_list: { [ok1]: rates }, upstream_models: { [ok1]: '@cf/meta/llama-3.2-1b-instruct' } }), null)
  assert.equal(upstreamModelsProblem({ price_list: { [ok2]: rates }, upstream_models: { [ok2]: 'liquid/lfm-2.5-2.6b:free' } }), null)
  assert.equal(upstreamModelsProblem({ price_list: { 'claude-fable-latest': rates }, upstream_models: { 'claude-fable-latest': '~anthropic/claude-fable-latest' } }), null)
  // Only a provider prefix may differ; another model under the
  // public id is refused (the node would pin it, and the receipt verify it).
  for (const swap of ['qwen/qwen3.8-27b', 'claude-opus-4.5-x', 'xclaude-opus-4.5', 'a/claude-opus-4.5/x', '/claude-opus-4.5x']) {
    const p = upstreamModelsProblem({ price_list: { 'claude-opus-4.5': rates }, upstream_models: { 'claude-opus-4.5': swap } })
    assert.match(p ?? '', /names another model/, swap)
  }
}
console.log('offer-check: ok')

{
  const pl = { a: {}, b: {} }
  assert.equal(contextLengthsProblem({ price_list: pl }), null)
  assert.equal(contextLengthsProblem({ price_list: pl, context_lengths: { a: 8192 } }), null)
  for (const bad of [null, [], 'x', { c: 8192 }, { a: 0 }, { a: -1 }, { a: 1.5 }, { a: '8192' }, { a: 2 ** 60 }]) {
    assert.notEqual(contextLengthsProblem({ price_list: pl, context_lengths: bad }), null, JSON.stringify(bad))
  }
  console.log('context_lengths checks ok')
}

// The offer check (`src/check-offer.ts`): request routes on a trusted API base, both framings.
{
  const H = 'api.example.com'
  const tpl = (path: string) =>
    `POST ${path} HTTP/1.1\r\nHost: ${H}\r\nAuthorization: Bearer {KEY:42}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n`
  const base = (http: string[], chatPath = '/api/v1/chat/completions', imagesPath = '/api/v1/image/generate') => ({
    v: 3, twopc: 'split-public-3', http, upstream_host: H, head_template: tpl(chatPath),
    key_length: 42, chat: { cap_keys: ['max_tokens'], fixed_pins: [['n', 1], ['stream', true], ['stream_options', { include_usage: true }]] },
    suffix_keys: ['model', 'max_tokens', 'n', 'stream', 'stream_options'],
    h2: { probe_path: '/api/v1/models', idle_secs: 300 },
    endpoints: { images: { head_template: tpl(imagesPath), count_key: imagesPath.endsWith('/generations') ? 'n' : 'variants', max_count: 4 } },
  })
  const policy = { trustedHosts: [H], apiBases: ['/v1', '/api/v1'], nodeMode: false, maxDeposit: 100000 }
  // The honest offer, each framing.
  for (const http of [['2', '1.1'], ['2'], ['1.1']]) {
    const c = checkOffer(base(http), policy)
    assert.deepEqual(c.http, http)
    assert.equal(c.h2 !== undefined, http.includes('2'))
  }
  assert.equal(checkOffer(base(['1.1'], '/v1/chat/completions'), policy).http[0], '1.1')
  // An earlier key schedule of v3: the node is outdated (exit code 6); another name is unsupported (4).
  for (const old of ['split-public-2', 'split-public-1']) {
    assert.throws(() => checkOffer({ ...base(['2']), twopc: old }, policy), (e: unknown) => e instanceof OfferRefused && /node_protocol_outdated/.test(e.message) && e.code === 6, old)
  }
  assert.throws(() => checkOffer({ ...base(['2']), twopc: 'split-proven-1' }, policy), (e: unknown) => e instanceof OfferRefused && /offer_unsupported_twopc/.test(e.message) && e.code === 4)
  // A chat route that only ends in the endpoint: refused for either framing.
  for (const http of [['2'], ['1.1'], ['2', '1.1']]) {
    for (const path of ['/api/v1/admin/chat/completions', '/v2/chat/completions', '/chat/completions', '/api/v1/x/v1/chat/completions']) {
      assert.throws(() => checkOffer(base(http, path), policy), (e: unknown) => e instanceof OfferRefused && /route/.test(e.message) && e.code === 4, `${http} ${path}`)
    }
  }
  // The API bases are the client's: another list moves what is allowed.
  assert.throws(() => checkOffer(base(['1.1']), { ...policy, apiBases: ['/v1'] }), /route/)
  assert.equal(headRouteProblem(tpl('/api/v1/chat/completions'), ['/api/v1'], 'chat'), undefined)
  assert.match(headRouteProblem(tpl('/api/v1/chat/completions'), ['/api/v1'], 'images') ?? '', /route/)
  assert.match(headRouteProblem('GET / HTTP/1.1\r\n', ['/api/v1'], 'chat') ?? '', /POST/)
  // The images route, on the same rule.
  imagesBlock(base(['2']), policy.apiBases)
  imagesBlock(base(['2'], undefined, '/v1/images/generations'), policy.apiBases)
  for (const path of ['/api/v1/admin/image/generate', '/v9/images/generations']) {
    assert.throws(() => imagesBlock(base(['2'], undefined, path), policy.apiBases), /route/, path)
  }
  assert.throws(() => imagesBlock({ ...base(['2']), endpoints: {} }, policy.apiBases), /offer_no_images/)
  // No built-in trusted host: an empty list refuses every offer and says how to add one.
  assert.deepEqual(trustedHosts(undefined, []), [])
  assert.deepEqual(trustedHosts(' API.Example.com ,', ['x', '--trusted-host', 'Other.example', '--trusted-host']), ['api.example.com', 'other.example'])
  assert.throws(() => checkOffer(base(['2']), { ...policy, trustedHosts: [] }), /--trusted-host .*CU_TRUSTED_HOSTS/)
  assert.throws(() => checkOffer(base(['2']), { ...policy, trustedHosts: ['other.example'] }), /not trusted/)
  // An older node's offer: exit code 6.
  assert.throws(() => checkOffer({ ...base(['1.1']), v: 2 }, policy), (e: unknown) => e instanceof OfferRefused && e.code === 6)
  // A node's offer: the deposit within --max-deposit, the idle time within h2.idle_secs.
  const node = { ...base(['2', '1.1']), connection_deposit_msat: 2000, idle_timeout_s: 120 }
  assert.equal(checkOffer(node, { ...policy, nodeMode: true }).deposit, 2000)
  assert.throws(() => checkOffer(node, { ...policy, nodeMode: true, maxDeposit: 1999 }), /max-deposit/)
  assert.throws(() => checkOffer({ ...node, idle_timeout_s: 301 }, { ...policy, nodeMode: true }), /idle_timeout_s/)
  console.log('route and trusted-host checks ok')
}
