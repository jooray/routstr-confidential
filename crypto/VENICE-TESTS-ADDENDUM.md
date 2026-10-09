# Venice behaviour tests — addendum: multimodal token amplification (GAP-3)

*2026-10-09. Extends `docs/original/VENICE-TESTS.md` (which is read-only here).
That file's procedure (`stream_options.include_usage`, read `prompt_tokens`
from the final event) is reused unchanged.*

**Scripts (this repo):**
- `crypto/tools/probe-modality.py` — the probe below, one tiny request per
  (model, case); writes `crypto/runs/modality/probe.json`.
- `crypto/tools/regression-modality.py` — the regression test; reads the
  advertised models from `crypto/relay/offer.venice.json` and asserts the gate
  holds; writes `crypto/runs/modality/regression.json`.

**Setup.** Model list = the 15 models the local node advertises confidentially
(plus the upstream test model and decoy). Endpoint `api.venice.ai`, streaming,
`max_tokens`/`max_completion_tokens` 4, `venice_parameters.include_venice_system_prompt:false`,
`enable_web_search:"off"`. Spend negligible.

## The question

Escrow prices the prompt as `prompt_tokens ≤ LEN`, where `LEN` is the request
body **byte** length (SPEC §5.1). Does an `image_url` content part — a few
dozen body bytes — expand to more prompt tokens than the bytes it costs?

## Result — confirmed

One ~50-byte URL to a public JPEG (`gstatic.com/webp/gallery/…`):

| case | body bytes | prompt_tokens | verdict |
|---|---|---|---|
| text only (`deepseek-v4-flash`, baseline) | 327 | 9 | — |
| `image_url` small (550×368), `mistral-small-3-2-24b-instruct` | 418 | 301 | accepted |
| `image_url` large (1200×800), same model | 418 | **1071** | amplified (2.6× the bytes) |
| `image_url` small, `gemini-3-flash-preview` | 423 | **1085** | amplified |
| `image_url` small, `inkling` | 408 | 554 | amplified |
| `image_url` large, `inkling` | 408 | **2050** | amplified (5× the bytes) |
| `image_url` small, `seed-2-1-turbo` | 415 | **1328** | amplified |
| `data:image/png;base64,…` (any model) | ~490 | — | **400** "Supplied image did not pass validation checks" |

The token count depends on the **image**, not the body bytes: the same 50-byte
URL costs 301 tokens for one image and 1071 for a larger one. The attacker
chooses the image, so `prompt_tokens ≤ LEN` does not hold for a model that
accepts the part. Venice also accepts `supportsMultipleImages` up to
`maxImages` (10 for mistral), multiplying the blow-up. Data URIs are rejected
today (a safe outcome, but not a guarantee for other providers).

## Models that reject `image_url` (400)

Eight models the node advertises confidentially return
`400 Invalid request parameters` for any `image_url` part — they cannot be
amplified and are the only safe set:

`qwen3-235b-a22b-thinking-2507`, `hermes-3-llama-3.1-405b`, `deepseek-v4-pro`,
`deepseek-v4-flash`, `deepseek-v4-flash-0731`, `deepseek-v3.2`,
`deepseek-v4-pro-0813`, `mercury-2`.

Vision-capable models (from `GET /models`, `supportsVision=true`) that accept
images — and are therefore **excluded** from the confidential offer:
`mistral-small-3-2-24b-instruct`, `google-gemma-3-27b-it`,
`gemini-3-flash-preview`, `claude-opus-5`, `claude-sonnet-5`, `claude-fable-5`,
`kimi-k3`, `inkling`, `seed-2-1-turbo`.

## Mitigation and regression

- `crypto/relay/offer.venice.json` now lists only the eight safe models in
  `price_list` and marks them `text_only_ok`.
- `cu-sidecar` refuses any `setup` for a model not marked `text_only_ok` when
  the map is non-empty (before the credential record is written; the node
  refunds on abort).
- `crypto/tools/regression-modality.py` re-runs this check after any provider
  change and fails if an advertised model starts accepting images.

**Re-run (VENICE-TESTS procedure), 2026-10-09:** `regression-modality.py`
→ `PASS: all 8 advertised models reject image parts (GAP-3 gate holds)`.

**Provider requirement.** This joins SPEC §7.6 (per-provider regression suite):
for every offered model, probe `image_url` **and** `data_uri`; advertise only
models that reject them (or whose token count is proven within the LEN bound —
not merely ≤ bytes for one sampled image, since the image is client-chosen).
