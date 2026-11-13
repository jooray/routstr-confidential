# OpenRouter through protocol v3: what the offer pins, what the node filters

*Measured 2026-11-13 on openrouter.ai with the owner's credit (total spend
$0.254). Evidence: `crypto/runs/openrouter-pins-2026-11-13/`. Suggested
offer: `crypto/relay/offer.openrouter.json`.*

## The problem

The client's part of a chat request is private. The node bills the
`prompt_tokens` and `completion_tokens` the provider reports, at the signed
offer's rates for the pinned model (the catalogue price times the provider
fee, 1.06 for OpenRouter). Anything OpenRouter honours in the private part
that raises its charge without showing up in those two counts at those
rates is paid by the node.

The defence is the chat suffix (`docs/CHAT-SUFFIX.md`). It closes the JSON
object, so its keys are the last ones OpenRouter parses. Its fixed pins may
only switch things off (`false`, `"off"`, `[]`, or an object whose members
are all off). Where no such pin exists, the node keeps the model out of its
chat offer instead.

## How it was measured

`tools/pinprobe.py` sends each request the way the sidecar does: one HTTPS/1.1
POST with the sidecar's head, and a body made of `{`, the private part, and
the canonical suffix. The private part asks for the expensive thing. The
suffix carries the pin being tested. For each request the tool records:

- the stream's usage event, including `cost`;
- OpenRouter's generation record (`/api/v1/generation?id=…`: `total_cost`,
  provider, model, search count, service tier);
- the ratio of OpenRouter's charge to the token counts at the pinned model's
  catalogue rates.

A ratio above 1.06 means the node loses money on that request. All 100
requests are in `probe.jsonl` and `probe-summary.tsv`. The case files are
`cases1-6.json`: the two largest bodies are trimmed there, and their notes say
how they were built.

Duplicate keys: for every pinned key the private part held a different value
and the suffix's value won. That includes the nested objects: a private
`provider: {"only": ["mistral"], ...}` against the pinned
`{"allow_fallbacks": false}` was served by Io Net, not Mistral, so
OpenRouter replaces the whole object and does not merge it. For `n`,
`stream` and `stream_options`, `debug.echo_upstream_body` showed the body
OpenRouter sent upstream: no `n`, `stream: true`, `include_usage: true`.

## Fields

| Field (private part) | Observed without a defence | Defence | Verified |
|---|---|---|---|
| `plugins: [{"id":"web"}]` | Exa search, $0.0070 for 508 tokens (475x the token rate) | pin `plugins: []` | yes: no search, 0.76x |
| other plugins (`fusion`, `auto-router`, `pareto`, `switchyard`, `moderation`, `response-healing`, `context-compression`, ...) | not run (same array) | pin `plugins: []` replaces the array | yes (array replaced) |
| `tools: [{"type":"openrouter:web_search"}]` (server tools) | gpt-oss-20b: 2 searches and a 3-step loop, $0.0142 (73x); 612 completion tokens against a 600 cap | pin `tools: []` | yes: no search, 1.07x |
| `max_tool_calls: 0` as a way to stop server tools | 4 searches still ran, $0.0284 (75x) | none: use `tools: []` | yes (does not work) |
| `models: [...]` (fallback list) | with an image sent to text-only nemo, OpenRouter fell back to gpt-4o-mini: 8 516 prompt tokens, $0.00128, billed by the node at nemo's rate (5.2x) | pin `models: []` | yes: 404 "no endpoints support image input", settled as an error head |
| `route: "fallback"` | no effect while the primary works | `models: []` makes it moot | yes |
| `provider` (`only`, `order`, `sort`, `allow_fallbacks`, `max_price`, `data_collection`, `zdr`, `quantizations`, ...) | `only: ["mistral"]`: Mistral's endpoint at 5.04x | pin `provider: {"allow_fallbacks": false}` (replaces the whole object; only the top-ranked endpoint serves, no fallback) | yes: every nemo request with the pin went to Io Net (13 probes and every e2e request; 0.64-0.67x). `{"only": []}` is refused (404 "No allowed providers"). `{"order": []}` replaces too but keeps default routing |
| `preset: "@preset/..."` | resolved against the node's account (404 "not found for this user" for a missing one); a real preset could add tools or plugins | pin `preset: "off"` (a bare slug is ignored) | yes |
| `web_search_options` | gpt-4o and gpt-4o-mini reject it (400). Perplexity `sonar*` searches on every request ($0.005 per request, `pricing.web_search`) | pin `web_search_options: false` (accepted, the client's value dropped); the node also keeps models that list it in `supported_parameters` out of the offer | yes (pin); filter by unit test and the e2e offer (18 models) |
| `service_tier: "priority"` | glm-5.3-flash on Parasail's priority endpoint: 7.07x | pin `service_tier: "off"` | yes: no priority tier. Default routing still went to dearer endpoints (2.8x, 5.6x) without the provider pin |
| `modalities: ["image","text"]` | gemini-3.1-flash-lite-image: 1 120 image tokens reported as completion tokens, $0.0336 (20x) | node: no model whose output modalities include anything but text | yes. A pin `modalities: []` does **not** stop it (still one image, 20x) |
| audio input (`input_audio`) | gemini-3.1-flash-lite: 82 prompt tokens at the audio rate, 1.61x | node: `exclude_if_priced: ["audio"]` | yes (36 models) |
| `cache_control` top level, `ttl: "1h"` | claude-haiku-5.5: 15 010 tokens written at the 1 h rate, 1.60x (the node bills writes at the 5 min `input_cache_write`) | node: `exclude_if_priced: ["input_cache_write_1h"]`. A pin cannot do it: `cache_control: false` is refused (400), and block-level markers sit inside the private messages | yes (36 models) |
| `cache_control`, 5 min | 1.00x: the node bills cache writes at `input_cache_write` | none needed | yes |
| long prompts on tiered models (`pricing.overrides`) | claude-haiku-5.5 at 275 013 prompt tokens: $0.1375, **5.00x** (tier above 100 k). Honest requests hit this too | node: `exclude_if_priced: ["overrides"]` | yes (81 models) |
| PDF (`file` part) | text-only nemo: Mistral OCR, $0.002 a page (1 page 2 025x, 3 pages 3 974x); `plugins: []` changes nothing | **none under the client policy** (see below) | yes, the loss is shown end to end |
| `reasoning` (`effort`, `max_tokens`), `reasoning_effort`, `include_reasoning`, `verbosity` | completion stays within the pinned cap (reasoning included: 20/20 on gpt-oss and on haiku with a 2 000-token reasoning budget), billed at the completion rate | none needed | yes |
| `prediction` | 25 completion tokens against a cap of 20, billed at the completion rate (the reservation covers it) | none needed | yes |
| `logprobs`, `top_logprobs`, `transforms`, `usage`, `user`, `metadata`, `trace`, `session_id`, `debug` | no change in cost | none | yes (first four) |
| `n`, `stream`, `stream_options` | the pins win (upstream body echoed) | already pinned | yes |
| `image_config`, `prompt_cache_options` (`ttl: "12h"`, GPT-5.6+), `deferred_tools`, `stop_server_tools_when` | not run | image models are not offered; `deferred_tools` and `stop_server_tools_when` need `tools`; `ttl: "12h"` is a residual (below) | no |
| `model` variants (`:online`, `:nitro`, `:floor`), `@preset` in `model` | `model` is pinned, and π_WIN binds it | already pinned | (earlier gates) |

## The offer

```json
"chat": {
  "cap_keys": ["max_tokens", "max_completion_tokens"],
  "fixed_pins": [
    ["n", 1], ["stream", true], ["stream_options", {"include_usage": true}],
    ["plugins", []], ["models", []], ["provider", {"allow_fallbacks": false}],
    ["tools", []], ["preset", "off"], ["web_search_options", false], ["service_tier", "off"]
  ]
},
"chat_model_filter": {
  "exclude_if_supports": ["web_search_options"],
  "exclude_if_priced": ["overrides", "input_cache_write_1h", "audio", "request"]
}
```

Every pin is inside the client policy: `[]`, `false`, `"off"`, and an object
whose only member is `false`. The full suffix was sent to seven models
(nemo, gpt-oss-20b, claude-haiku-5.5, gpt-4o-mini, glm-5.3-flash,
gpt-5-nano, llama-3.1-8b) and was accepted by all of them. One request
carried every attack field at once in the private part:

- on nemo it was served by Io Net at 0.64x, with no search and no image;
- on glm-5.3-flash it was served by Relace at 1.00x.

`request` in `exclude_if_priced` covers per-request fees. No model has one
today. The node already keeps models with image, audio or video output out
of the offer, so `image_output` and `audio_output` are not listed.

## The node filter (routstr-core)

- **Output modalities** (always on): a model is offered for chat only if
  every output modality is `text`, both on the listed model and on the
  provider row the sidecar host bills by. This rule used to require only
  that `text` be one of them, so models that output `image`+`text`,
  `text`+`audio` or `text`+`video` were offered. Venice is unchanged: its
  text models have exactly `["text"]`.
- **`chat_model_filter`** (sidecar offer file; the sidecar checks its shape
  and passes it on in `GET /offer`; the node does not sign it into its own
  offer):
  - `exclude_if_supports`: request parameters. A model whose catalogue
    `supported_parameters` lists one is not offered.
  - `exclude_if_priced`: pricing components. A model is not offered if a
    `Pricing` rate is above zero (`web_search`, `request`, …) or if the
    catalogue has a non-zero member that `Pricing` has no field for
    (`overrides`, `audio`, `input_cache_write_1h`, …). Those members are
    kept as `Model.extra_pricing_keys`.

  It fails closed: with a filter set, a model whose catalogue row lists no
  parameters is not offered. A malformed block refuses the offer.
- Effect on today's catalogue: 172 of 475 models are filtered out, and 282
  are offered. Of the 172:
  - 81 have tiered pricing;
  - 36 have an audio rate;
  - 36 have a 1 h cache-write rate;
  - 18 support `web_search_options`;
  - 19 have non-text output.

  By family: OpenAI 53, Google 39, Anthropic 32, x-ai 10.

## End to end (a scratch node, `v3-node-check.sh`, `CU_PIN_ATTACKS=1`)

24 of 24 cases pass. They ran on `mistral-nemo` and both framings, with
F = 3 000, A = 5 000 and D = 7 000 msat. `tools/orcost.py` compared each
request's cost at OpenRouter with the node's charge. The node priced the
model at 7.48e-7 USD per msat. "Usage" below is the charge without the
session fee.

| Case | Node charge (msat) | OpenRouter | Node usage part | Verdict |
|---|---|---|---|---|
| h2-one, h11-one, h2-decoy, h11-decoy | 3 001 | $0.000000235 | $0.000000748 | OK |
| h2-three (3 requests) | 3 001, 1, 1 | $0.00000032-36 each | $0.00000075 each | OK |
| h2-c-model-swap | 3 001 + A on the refused request 2 | $0.00000032 | $0.00000075 | OK |
| h11-c-model-swap | D (`request_abandoned`) | nothing sent | | OK |
| h2/h11-p-plugins | 3 002 | $0.00000055-59, no search | $0.0000015 | OK |
| h2/h11-p-tools | 3 002 | $0.00000046-48, no search | $0.0000015 | OK |
| h2/h11-p-provider | 3 001 | $0.000000235, on Io Net | $0.00000075 | OK |
| h2-p-preset, h2-p-tier | 3 001 | $0.000000235 | $0.00000075 | OK |
| h2-p-wso | 3 002 | $0.000000455 | $0.0000015 | OK |
| h2/h11-p-all (every field) | 3 002 | $0.00000046-48 | $0.0000015 | OK |
| h2/h11-p-models-image | 5 000 (A, error head 404) | nothing charged | | OK |
| h2-p-image-model, h2-p-filtered | D (`unused`); 400 "not served confidentially" | nothing sent | | OK |
| **h2/h11-p-pdf** (3 pages) | 3 003 | **$0.0060** | $0.0000022 | **LOSS** (the session fee covers $0.0022) |

Gate output: `node/run.txt`, `node/summary.tsv`, `node/api_keys.tsv`. The
cost comparison is in `node/orcost.tsv` and `node/orcost.json`, and the
node's signed offer in `node/offer.json`.

Run it again with:

```bash
cd crypto/runs/providers-2026-11-12/tools
CU_TRUSTED_HOSTS=openrouter.ai CU_V3_OFFER=$PWD/../../../relay/offer.openrouter.json \
  CU_UPSTREAM=openrouter.ai:443 CU_UPSTREAM_BASE=https://openrouter.ai/api/v1 \
  CU_PROVIDER_TYPE=openrouter CU_HOST_MATCH=openrouter CU_MODEL=mistral-nemo \
  CU_SWAP_MODEL=gpt-4o-mini CU_DECOY_MODEL=openai/gpt-4o-mini CU_NO_IMAGES=1 \
  CU_V3_PORT=7492 CU_NODE_PORT=8462 CU_NODE_OUT=<a 0700 scratch dir> \
  CU_PIN_ATTACKS=1 CU_PIN_PRICEY_PROVIDER=mistral CU_PIN_IMAGE_MODEL=gemini-3.1-flash-lite-image \
  CU_PIN_FILTERED_MODEL=claude-haiku-5.5 CU_CASES="h2-one h11-one … h2-p-pdf h11-p-pdf" \
  python3 withkey.py openrouter ../../../tools/v3-node-check.sh
python3 ../../openrouter-pins-2026-11-13/tools/orcost.py <scratch dir>
```

## Why the pins cannot be cheated

1. The suffix is the last record, or on framing 2 the tail of the last DATA
   frame. π_WIN proves it is the canonical suffix, and nothing follows it.
2. OpenRouter parses duplicate keys last-wins at the top level, and it
   replaces objects and arrays instead of merging them. This was checked
   live for every pinned key. Each private value was overridden, including
   `provider` with `only`, `order`, `sort` and `allow_fallbacks` against a
   one-member pinned object.
3. Each pinned value was seen to switch the feature off, and the
   same request without the pin was seen to cost more. The table above
   lists both.
4. What a pin cannot reach, the node does not offer: image, audio or video
   output, audio input rates, 1 h cache writes, tiered prices, models with
   native search parameters. The client cannot name a model outside the
   signed offer, because the node refuses it before it reserves anything.

## What remains

- **PDF parsing (not defended by the offer).** A `file` part in the
  private messages makes OpenRouter OCR the PDF with Mistral OCR at $2 per
  1 000 pages when the model has no native file input, with or without
  `plugins`. A pin that would stop it,
  `plugins: [{"id":"file-parser","pdf":{"engine":"cloudflare-ai"}}]`, works
  (3 pages: $0.0000024, 0.64x) but is outside the client policy: it is a
  non-empty array. The policy was not loosened. A file URL keeps the body
  small, so one request can buy thousands of pages. Until this is closed,
  **do not offer OpenRouter on an account whose PDF engine is the default**.
  There are two fixes:
  - set OpenRouter's account default for the file parser to `cloudflare-ai`
    with "Prevent overrides" (Settings > Plugins). This is not verified
    here, because it changes the owner's account;
  - allow this one pin in the client policy (SDK, web library, reference
    client and sidecar).
- **Provider price spread (not defended by any off pin).** One model has
  endpoints at different prices, and the node bills the catalogue price.
  Honest requests measured against the node's rate:
  - nemo with no provider pin: Mistral's endpoint at 5.04x (1 of 12 baseline requests);
  - Llama 3.1 8B with no provider pin: Cloudflare at 7.3x;
  - Llama 3.1 8B with the proposed suffix: Groq at 2.3x;
  - Llama 3.1 8B with only the provider pin: DeepInfra at 1.0x;
  - glm-5.3-flash with no provider pin: 2.8x and 5.6x.

  With the full suffix, `tools: []` seems to steer routing towards endpoints
  that support tools. `provider: {"allow_fallbacks": false}` stops the
  client from choosing the endpoint. It does not make the top-ranked
  endpoint the cheapest. The right pin is `provider: {"sort": "price"}`
  (or a per-model `max_price`), and the policy forbids it. Options:
  - allow `sort: "price"` in the policy (it can only lower the price);
  - set the account's default provider sort to price, which a pinned
    object without `sort` leaves in force (not verified);
  - have the node bill OpenRouter models at the highest endpoint price.

  Until one of these is in place, budget for it: the 1.06 provider fee does
  not cover a 2-7x spread.
- **Function calling.** `tools: []` also removes the client's own function
  tools, so on OpenRouter a confidential client must not send `tools`
  (clients refuse such requests with `pinned_parameter`). Server tools
  cannot be told apart from function tools inside the private part, and
  `max_tool_calls: 0` does not stop them.
- **Fewer models.** The filter drops tiered, audio-priced and 1 h-cache
  models, which is most of Anthropic, Google and the newest OpenAI models.
  Billing those components would bring them back:
  - the highest `overrides` tier for the full-context reservation and the
    tier the usage falls in;
  - cache writes at the 1 h rate;
  - audio tokens at the audio rate. The usage reports them in
    `prompt_tokens_details.audio_tokens`.
- **`prompt_cache_options.ttl: "12h"`** (GPT-5.6 and newer) is billed at a
  higher cache-write rate than the catalogue's `input_cache_write`. This
  was not measured. Those models are tiered (`overrides`) and are filtered
  today.
- **Account settings sit outside the offer.** Account default plugins
  still run when the request sends `plugins: []`; the docs say a request
  overrides a default only for a plugin it names. Do not enable paid
  default plugins on the node's account. Presets, guardrails and the
  default provider sort are also account settings.
- **BYOK.** If the account has its own provider keys, OpenRouter routes
  those requests through them and charges a fee. The usage marks them
  `is_byok`. The pins do not change that, and the node does not check it.
- **OpenRouter changes.** New plugins, server tools, request fields or
  pricing members are not covered until someone tests them. Re-run
  `tools/pinprobe.py` against new fields, and the catalogue scan in this
  document. `exclude_if_priced` only knows the member names it is given.
- **Provider outages** under `allow_fallbacks: false` end in a refusal,
  settled as an error head with the abandon fee. The client pays that fee,
  so an outage is no loss to the node.
