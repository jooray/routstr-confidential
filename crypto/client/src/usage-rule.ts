/**
 * The usage event rule (PROTOCOL-V3.md §5.4), as the sidecar's usage_rule.rs:
 * token counts, and `choices` either `[]` or one choice with no content
 * (`index`, `finish_reason` from the OpenAI list or null, an identifier or
 * null as `native_finish_reason`, `logprobs: null`, and a `delta` holding at
 * most `role: "assistant"`, empty or null `content`/`reasoning`/
 * `reasoning_content`/`refusal` and an empty `tool_calls`).
 * Top level: only `choices`, `usage`, the labels `id`, `object`, `model`,
 * `provider`, `service_tier`, `system_fingerprint` (null or at most 128
 * characters of `[A-Za-z0-9 ._:/@+-]`) and `created` (an unsigned integer).
 * `cost` (Venice) is null, a number or a numeric object like `usage`.
 * `usage` holds only numbers (of magnitude below 2^53), booleans, nulls and nested objects of such
 * (keys `[A-Za-z0-9_]{1,64}`, at most 3 levels counting `usage`). Any other
 * field could carry prompt- or output-derived data to the node.
 * Vectors: crypto/relay/usage-event-vectors.json.
 */
export const FINISH_REASONS = ['stop', 'length', 'tool_calls', 'content_filter', 'function_call']
const EMPTY_TEXT_FIELDS = ['content', 'reasoning', 'reasoning_content', 'refusal']

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const uint = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0

const LABEL_FIELDS = ['id', 'object', 'model', 'provider', 'service_tier', 'system_fingerprint']
const LABEL_RE = /^[A-Za-z0-9 ._:/@+-]{0,128}$/
const USAGE_KEY_RE = /^[A-Za-z0-9_]{1,64}$/
/** A number every implementation reads the same: magnitude below 2^53. */
const plainNumber = (x: unknown): boolean => typeof x === 'number' && Number.isFinite(x) && Math.abs(x) < 2 ** 53

/** `depth` counts `usage` itself as 1; at most 3. */
const numericObject = (v: unknown, depth: number): boolean =>
  isObj(v) && depth <= 3 && Object.entries(v).every(([k, x]) =>
    USAGE_KEY_RE.test(k) && (x === null || typeof x === 'boolean' || plainNumber(x) || (isObj(x) && numericObject(x, depth + 1))))

/** Why `ev` is not a usage event, or null. */
export function usageEventProblem(ev: unknown): string | null {
  if (!isObj(ev)) return 'not an object'
  for (const [k, x] of Object.entries(ev)) {
    const ok = k === 'choices' || k === 'usage' ? true
      : k === 'created' ? uint(x)
        : k === 'cost' ? x === null || plainNumber(x) || numericObject(x, 1)
          : LABEL_FIELDS.includes(k) ? x === null || (typeof x === 'string' && LABEL_RE.test(x))
          : false
    if (!ok) return `the event carries the top-level field ${JSON.stringify(k)}`
  }
  const choices = ev.choices
  if (!Array.isArray(choices)) return 'no choices array'
  if (choices.length > 1) return 'more than one choice'
  for (const c of choices) {
    if (!isObj(c)) return 'a choice is not an object'
    for (const [k, v] of Object.entries(c)) {
      let ok: boolean
      if (k === 'index') ok = uint(v)
      else if (k === 'finish_reason') ok = v === null || (typeof v === 'string' && FINISH_REASONS.includes(v))
      else if (k === 'native_finish_reason') ok = v === null || (typeof v === 'string' && /^[A-Za-z_]{1,32}$/.test(v))
      else if (k === 'logprobs') ok = v === null
      else if (k === 'delta') {
        ok = isObj(v) && Object.entries(v).every(([dk, dv]) =>
          dk === 'role' ? dv === null || dv === 'assistant'
            : dk === 'tool_calls' ? dv === null || (Array.isArray(dv) && dv.length === 0)
              : EMPTY_TEXT_FIELDS.includes(dk) ? dv === null || dv === ''
                : false)
      } else ok = false
      if (!ok) return `the choice carries ${JSON.stringify(k)}`
    }
  }
  const u = ev.usage
  if (!isObj(u) || !uint(u.prompt_tokens) || !uint(u.completion_tokens)) return 'no token counts'
  if (!numericObject(u, 1)) return 'usage carries something other than numbers'
  return null
}
