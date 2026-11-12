// What the reference client holds an offer to before it opens a connection
// (PROTOCOL-V3.md §2.3, §12.1), and the byte-exact suffixes it renders from
// it (docs/CHAT-SUFFIX.md, docs/CONFIDENTIAL-IMAGES.md).

/** Compact JSON with object members sorted (the sidecar's serde_json form). */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

/** The chat suffix the offer's `chat` block defines (docs/CHAT-SUFFIX.md). */
export function renderChatSuffix(chat: any, model: string, maxTokens: number): string {
  const parts = [`"model":${JSON.stringify(model)}`]
  for (const k of chat.cap_keys) parts.push(`${JSON.stringify(k)}:${maxTokens}`)
  for (const [k, v] of chat.fixed_pins) parts.push(`${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `,${parts.join(',')}}`
}

/**
 * The id the chat suffix pins for `model` (a public id of `price_list`): the
 * offer's `upstream_models` entry where the provider's own id differs (an
 * `org/` prefix), else the id itself (PROTOCOL-V3.md §12.1).
 */
export function pinnedModel(offer: any, model: string): string {
  const m = offer?.upstream_models
  return m && Object.hasOwn(m, model) ? m[model] : model
}

/** Why the offer's `upstream_models` is refused, or null (absent is fine). */
export function upstreamModelsProblem(offer: any): string | null {
  const m = offer?.upstream_models
  if (m === undefined) return null
  if (m === null || typeof m !== 'object' || Array.isArray(m)) return 'upstream_models is not an object'
  for (const [pub, id] of Object.entries(m)) {
    if (!Object.hasOwn(offer.price_list ?? {}, pub)) return `upstream_models names ${JSON.stringify(pub)}, which price_list does not`
    // Rendered into the suffix as a JSON string: printable ASCII, no quote or backslash.
    if (typeof id !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(id) || /["\\]/.test(id) || id === pub) {
      return `upstream_models[${JSON.stringify(pub)}] is not a provider model id`
    }
  }
  return null
}

const CAP_KEYS = ['max_tokens', 'max_completion_tokens', 'max_output_tokens']
const PIN_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/
const pinValueOk = (v: unknown): boolean =>
  typeof v === 'boolean' ||
  (typeof v === 'number' && Number.isSafeInteger(v)) ||
  (typeof v === 'string' && /^[\x20-\x7e]*$/.test(v) && !/["\\]/.test(v)) ||
  (Array.isArray(v) && v.every(pinValueOk)) ||
  (v !== null && typeof v === 'object' && !Array.isArray(v) && Object.entries(v).every(([k, x]) => PIN_KEY.test(k) && pinValueOk(x)))
/** A pin that switches something off: `false`, `"off"`, `[]`, or a non-empty object of those. */
const pinIsOff = (v: unknown): boolean =>
  v === false || v === 'off' || (Array.isArray(v) && v.length === 0) ||
  (v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length > 0 && Object.values(v).every(pinIsOff))
/** Key prefixes under which `false` turns a feature on. */
const NEGATING_PREFIXES = ['disable', 'no_', 'skip', 'without', 'exclude', 'omit', 'hide']
/** Key words naming a protection: pinning one can only switch it off, so it stays the provider's default. */
const PROTECTION_WORDS = ['safe', 'moderat', 'filter', 'nsfw', 'censor', 'guard']
/** The first pin key, at any depth, that is negating or names a protection, or null. */
export function refusedPinKey(k: string, v: unknown): string | null {
  const l = k.toLowerCase()
  if (NEGATING_PREFIXES.some((p) => l.startsWith(p)) || PROTECTION_WORDS.some((w) => l.includes(w))) return k
  return refusedMemberKey(v)
}
function refusedMemberKey(v: unknown): string | null {
  const members: [string | null, unknown][] = Array.isArray(v)
    ? v.map((x) => [null, x])
    : v !== null && typeof v === 'object' ? Object.entries(v) : []
  for (const [m, x] of members) {
    const bad = m === null ? refusedMemberKey(x) : refusedPinKey(m, x)
    if (bad !== null) return bad
  }
  return null
}

/** Why the offer's chat block is outside the policy every client applies, or null. */
export function chatBlockProblem(offer: any): string | null {
  const c = offer?.chat
  if (!c || typeof c !== 'object' || !Array.isArray(c.cap_keys) || !Array.isArray(c.fixed_pins)) return 'no chat block'
  if (c.cap_keys.length === 0) return 'no cap key'
  const seen = new Set<string>()
  for (const k of c.cap_keys) {
    if (!CAP_KEYS.includes(k) || seen.has(k)) return `cap key ${JSON.stringify(k)}`
    seen.add(k)
  }
  for (const p of c.fixed_pins) {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== 'string') return 'a malformed pin'
    const [k, v] = p
    if (!PIN_KEY.test(k) || k === 'model' || CAP_KEYS.includes(k) || seen.has(k)) return `pin key ${JSON.stringify(k)}`
    seen.add(k)
    if (!pinValueOk(v)) return `pin ${k} outside the grammar`
    const refused = refusedPinKey(k, v)
    if (refused !== null) return `pin key ${JSON.stringify(refused)} negates or names a protection`
    const ok = k === 'stream' ? v === true
      : k === 'n' ? v === 1
      : k === 'stream_options' ? canonicalJson(v) === '{"include_usage":true}'
      : pinIsOff(v)
    if (!ok) return `pin ${k}=${JSON.stringify(v)} is not allowed`
  }
  if (!seen.has('stream') || !seen.has('stream_options')) return 'stream and stream_options must be pinned'
  const pins = c.fixed_pins.map(([k, v]: [string, unknown]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')
  if (pins.length > 1024) return 'pins too long'
  const keys = ['model', ...c.cap_keys, ...c.fixed_pins.map((p: [string, unknown]) => p[0])]
  if (JSON.stringify(offer.suffix_keys) !== JSON.stringify(keys)) return `suffix_keys ${JSON.stringify(offer.suffix_keys)} are not ${JSON.stringify(keys)}`
  return null
}

/**
 * The request key an image endpoint reads the image count from, by the route
 * its head template names: `n` for the OpenAI-style `/images/generations`,
 * `variants` for `/image/generate`. Undefined for any other route.
 */
export function imageCountKeyForRoute(headTemplate: unknown): string | undefined {
  const path = typeof headTemplate === 'string' ? (/^POST (\S+) HTTP\/1\.1\r\n/.exec(headTemplate)?.[1]?.split('?')[0] ?? '') : ''
  if (path.endsWith('/images/generations')) return 'n'
  if (path.endsWith('/image/generate')) return 'variants'
  return undefined
}

/** The variant pin keys a client lets the node pin (the price axes). */
const VARIANT_PIN_KEYS = new Set(['resolution', 'quality', 'format'])

/**
 * The node signs the images block, but its pins reach the provider as the
 * request's last word: a fixed pin may only switch a provider extra off
 * (`false` or `[]`), a variant may only pin a price axis to a value the
 * offer's parameter space lists, and the numbers stay in the ranges the relay
 * enforces. Anything else is refused rather than rendered.
 */
export function checkImagesBlock(im: any): void {
  const bad = (why: string): never => {
    throw new Error(`offer_malformed: images block ${why}`)
  }
  const countKey = im.count_key ?? 'variants'
  if (typeof countKey !== 'string' || !countKey) bad('count_key')
  // The count is pinned under this key and the charge is the price × count:
  // under a key the endpoint does not read, the provider would make its
  // default number of images while the client paid for `count`.
  const routeKey = imageCountKeyForRoute(im.head_template)
  if (routeKey === undefined) bad('head_template does not name an image endpoint with a known count key')
  if (countKey !== routeKey) bad(`count_key ${JSON.stringify(countKey)} is not the one the endpoint reads (${JSON.stringify(routeKey)})`)
  if (!(Number.isSafeInteger(im.max_count) && im.max_count >= 1 && im.max_count <= 4)) bad('max_count must be 1..4')
  if (im.response_idle_s !== undefined && !(Number.isSafeInteger(im.response_idle_s) && im.response_idle_s >= 30 && im.response_idle_s <= 600)) {
    bad('response_idle_s must be 30..600')
  }
  const space = im.param_space ?? {}
  if (typeof space !== 'object' || Array.isArray(space)) bad('param_space')
  for (const [k, v] of Object.entries(space)) {
    if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) bad(`param_space.${k}`)
  }
  const fixed: unknown[] = im.fixed_pins ?? []
  if (!Array.isArray(fixed)) bad('fixed_pins')
  const fixedKeys = new Set<string>()
  for (const pin of fixed) {
    if (!Array.isArray(pin) || pin.length !== 2 || typeof pin[0] !== 'string') bad('fixed_pins entry')
    const [k, v] = pin as [string, unknown]
    if (!(v === false || (Array.isArray(v) && v.length === 0))) bad(`fixed pin ${k} does not switch an extra off`)
    if (refusedPinKey(k, v) !== null) bad(`fixed pin ${k} negates or names a protection`)
    if (k === 'model' || k === countKey || fixedKeys.has(k)) bad(`fixed pin ${k} repeats a pinned key`)
    fixedKeys.add(k)
  }
  for (const [model, variants] of Object.entries(im.price_list ?? {})) {
    if (!Array.isArray(variants) || variants.length === 0) bad(`price_list.${model}`)
    const ids = new Set<string>()
    for (const v of variants as any[]) {
      if (typeof v?.id !== 'string' || ids.has(v.id)) bad(`variant ids of ${model}`)
      ids.add(v.id)
      if (!(Number.isSafeInteger(v.msat_per_image) && v.msat_per_image > 0)) bad(`${model}/${v.id} msat_per_image`)
      if (v.max_count !== undefined && !(Number.isSafeInteger(v.max_count) && v.max_count >= 1 && v.max_count <= im.max_count)) {
        bad(`${model}/${v.id} max_count`)
      }
      const keys = new Set<string>()
      for (const pin of v.pins ?? []) {
        if (!Array.isArray(pin) || pin.length !== 2) bad(`${model}/${v.id} pin`)
        const [k, val] = pin
        if (!VARIANT_PIN_KEYS.has(k) || keys.has(k) || fixedKeys.has(k)) bad(`${model}/${v.id} pins ${k}`)
        if (typeof val !== 'string' || !(space[k] ?? []).includes(val)) bad(`${model}/${v.id} pins ${k} outside param_space`)
        keys.add(k)
      }
    }
  }
}

/** The pinned image suffix (docs/CONFIDENTIAL-IMAGES.md §0.3), byte-exact. */
export function renderImagesSuffix(im: any, model: string, count: number, pins: [string, unknown][]): string {
  const parts = [`"model":${JSON.stringify(model)}`, `${JSON.stringify(im.count_key)}:${JSON.stringify(count)}`]
  for (const [k, v] of [...(im.fixed_pins ?? []), ...pins]) parts.push(`${JSON.stringify(k)}:${JSON.stringify(v)}`)
  return `,${parts.join(',')}}`
}

/** A token count as the node reads one (a non-negative integer, else 0). */
export function tokenCount(v: unknown): number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v > 0 ? v : 0
}

/**
 * The most the node may charge for a usage at the signed rates (msats, no
 * fee). The node computes its charge from the same disclosed usage: prompt
 * tokens at `in`, less cached reads at `cached_in` (never above `in`) and
 * prompt-cache writes at `cache_write` (`in` when the offer has none), both
 * counted inside `prompt_tokens`. The bound is that formula, or the same with
 * the writes billed at `in` when that is larger (a node that read no write
 * count bills them so). It is never the uncached price for a usage that
 * reports cached reads: a charge that ignores the cache discount is an
 * overcharge (as the SDK's maxChargeMsats).
 */
export function maxUsageCharge(rates: any, usage: any): number {
  const inRate = Number(rates.in)
  const outRate = Number(rates.out)
  const prompt = tokenCount(usage.prompt_tokens)
  const completion = tokenCount(usage.completion_tokens)
  const d = usage.prompt_tokens_details && typeof usage.prompt_tokens_details === 'object' ? usage.prompt_tokens_details : {}
  const cached = Math.min(tokenCount(d.cached_tokens), prompt)
  const written = Math.min(
    [d.cache_creation_input_tokens, d.cache_write_tokens, d.cache_creation_tokens, usage.cache_creation_input_tokens]
      .map(tokenCount)
      .find((n) => n > 0) ?? 0,
    prompt - cached,
  )
  const cachedRate = Math.min(Number(rates.cached_in ?? inRate), inRate)
  const writeRate = Number(rates.cache_write ?? inRate)
  const cost = (c: number, w: number) =>
    Math.ceil((inRate * (prompt - c - w) + cachedRate * c + writeRate * w + outRate * completion) / 1000)
  // `cost(cached, 0)` is the uncached price when no cached reads are reported.
  return Math.max(cost(cached, 0), cost(cached, written))
}

/** The largest request body a node takes (`body_len`, PROTOCOL-V3.md §12.4). */
export const MAX_BODY_LEN = 8 << 20

/**
 * The optional body-size bucket (off by default): the body's length rounded
 * up to the next multiple of `bucket` bytes, or with `'pow2'` to the next
 * power of two (at least 1 KiB), never above `MAX_BODY_LEN`. The client pads
 * with JSON whitespace between the private part and the canonical suffix, so
 * the provider parses the same object and `body_len`, the record sizes and
 * the ciphertext show the bucket, not the length. (The node still learns the
 * prompt's token count at settlement: this hides sizes from observers of the
 * connections, not from the node.)
 */
export function paddedBodyLength(len: number, bucket: number | 'pow2' | undefined): number {
  if (bucket === undefined || len >= MAX_BODY_LEN) return len
  let want = len
  if (bucket === 'pow2') {
    want = 1024
    while (want < len) want *= 2
  } else {
    if (!Number.isSafeInteger(bucket) || bucket < 16) throw new Error('a padding bucket is an integer of at least 16 bytes, or pow2')
    want = Math.ceil(len / bucket) * bucket
  }
  return Math.min(want, MAX_BODY_LEN)
}

/** `prefix` ‖ spaces ‖ `suffix`, `paddedBodyLength` bytes long (UTF-8). */
export function padBody(prefix: Uint8Array, suffix: Uint8Array, bucket: number | 'pow2' | undefined): Uint8Array {
  const len = prefix.length + suffix.length
  const out = new Uint8Array(paddedBodyLength(len, bucket))
  out.set(prefix, 0)
  out.fill(0x20, prefix.length, out.length - suffix.length)
  out.set(suffix, out.length - suffix.length)
  return out
}
