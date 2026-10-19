# Confidential image generation: feasibility and specification

Status: implemented and deployed (2026-10-19), with the decisions in section 0. The study sections
below were written before the implementation, so their code references are to `twopc-v2` (this repo),
`confidential-2pc` (routstr-core, routstr-sdk), the web library at `2af9a79` and the PWA at `ec06e83`;
where they differ from section 0 or from the notes in this paragraph, those win:
the image gate is `provider-profile-check.py --images`, checks I1 to I9 (output in `docs/evidence/`);
`accept` is a claim, not a proof (an honest client sends it only for a 2xx; a dishonest one that
accepts a 5xx pays the flat price instead of the reservation, at most `max(f_s, f_a) - f_s` less); the
Venice endpoint caps the response at 48 MiB, and a 4K variant carries `max_count: 1` (one busy 4K WebP took
44 s and 5.9 MB of response; four could pass the provider CDN's ~100 s idle limit); only per-image books
with resolution/quality tiers and WebP output are offered, so megapixel books, other tier keys or response
shapes need code. Clients take nothing in the offer's images block on trust: a fixed pin must be `false` or
`[]`, a variant pins only resolution, quality or format to a `param_space` value, a private option that names
a pinned key is refused, the head template must be the image path with exactly the six fixed headers, and
the numbers stay in range (integer prices, `max_count` 1..4, unique variant ids, `response_idle_s` 30..600).
Errors: a 429 or 503 costs the session fee, any other 4xx the abandon fee, other 5xx up to the reservation;
an image error receipt carries the session's kind, model, variant and count.

Question: can `POST /v1/images/generations` go through confidential mode (protocol v2) so that the
node sees neither the image prompt nor the image, with the same properties the paper claims for chat
(P1 to P6, `paper/paper.md` §2)?

Short answer: yes, and with fewer moving parts than chat. Image prices are a function of the request
parameters, not of anything the provider reports, so every price-relevant parameter can go into the
pinned suffix that π_C2S already proves. The charge is then the signed per-image price times the
pinned count, known before the provider starts. A successful response needs **no disclosure and no
π_C3S at all**. π_C3S is used only on the error path, unchanged, to prove an error head and get the
reservation released. No circuit changes. The work is in the offer format, the sidecar's setup and
suffix handling, the node's reservation and settlement, the clients' response handling (large bodies)
and the PWA.

## 0. Decisions (binding for the implementation; they override the sections below where they differ)

1. **Route:** Venice uses its native `POST /api/v1/image/generate` (`response_shape: "venice"`). The
   route lives in the offer's `head_template`, so another provider can use `/images/generations`.
2. **Count:** `count` 1..4, sent at setup, pinned in the suffix under the offer's `count_key`
   (`"variants"` for Venice). `max_count` in the node offer is 4. A response with fewer images than
   `count` is still charged `msat_per_image × count + f_s` (client's residual risk).
3. **Suffix, byte-exact** (sidecar Rust, SDK and web TS must agree; shared test vectors):
   `suffix = "," + join(",", ["\"model\":" + json(M), json(count_key) + ":" + json(count)] +
   [json(k) + ":" + json(v) for (k, v) in fixed_pins ++ V.pins]) + "}"`
   with compact JSON. `fixed_pins` no longer contains the count key. Venice `fixed_pins`:
   `[["return_binary", false], ["enhance_prompt", false], ["enable_web_search", false],
   ["style_references", []]]`.
   Test vector: M = `z-image-turbo`, count_key `variants`, count 2, V.pins `[["format","webp"]]` →
   `,"model":"z-image-turbo","variants":2,"return_binary":false,"enhance_prompt":false,"enable_web_search":false,"style_references":[],"format":"webp"}`
4. **Formats:** WebP only (`param_space.format = ["webp"]`).
5. **No padding** of the private prefix (images or chat).
6. **5xx after release:** the chat rule (charge the reservation) for now; the live gate records
   whether Venice bills failed generations, and the rule changes only if it does not.
7. **No pre-arm for images, ever.** The node refuses `armed: true` for `kind: "images"`; clients never
   pool image sessions and never call the chat pre-warm `setTarget` for an image model.
8. **PWA on mobile:** allowed; the image button shows the per-image data cost (~26 MB) and warns once
   when `navigator.connection` reports a metered or `saveData` connection. The PWA re-encodes the
   received WebP client-side (canvas, ≤1200 px, WebP 0.75, JPEG 0.8 fallback) before storing it.
9. Variant aspect ratios: Venice tiers are `resolution` (where the model declares them) and
   `aspect_ratio`, which does not change the price, so it stays **private** (in the client's prefix,
   not pinned).
10. Later phases (not now): an offer-driven suffix for chat, and token-metered image models.

## 1. What exists today

### 1.1 The chat-specific pieces

| Piece | Where | What is chat-specific |
|---|---|---|
| Head template | `crypto/relay/offer.venice.json:3`, default in `crypto/relay/src/main.rs:119-123` | the path `/api/v1/chat/completions`; one template per offer |
| Pinned suffix | `main.rs:1525-1543` (`SUFFIX_KEYS`, `canonical_suffix`), web `src/suffix.ts:20`, SDK `client/confidential/suffix.ts` | hard-coded keys and values (`max_tokens`, `stream`, `stream_options`, `venice_parameters`); the offer only names the keys (`main.rs:559-564` refuses an offer naming others) |
| Setup | `main.rs:661-680` (`ClientMsg::Setup`), node `confidential_ws.py:244-276` (`validate_setup`), `:107` (`_SIDECAR_SETUP_FIELDS`) | `model` + `max_tokens` are the only pricing inputs |
| Usage disclosure | `main.rs:2081-2154` (`validate_r`), SDK `session.ts:958` (`extractUsageDisclosure`) | SSE usage event + `[DONE]`, end-anchored |
| Error-head disclosure | `main.rs:1367`, `:1400`, `:2044-2079` (`validate_error_head`); SDK `session.ts:949-958` | generic: any HTTP/1.x head with status 400-599 |
| Reservation | `routstr-core/routstr/confidential.py:726-815` | full context × in-rate + (max_tokens + margin) × out-rate, plus `max(fee, abandon)` (`:800`) |
| Settlement | `confidential.py:818-834`, `confidential_ws.py:642-659` | tokens × frozen per-1k rates; `error_status` in `UNBILLED_ERROR_STATUSES` (`confidential.py:64`, 4xx and 503) releases less the session fee |
| Abort accounting | `confidential_ws.py:734-762` | body released and nothing settled: charge the reservation |

Everything below the HTTP layer is generic: the 2PC, the epochs, π_NK (its template is a parameter),
π_C2S (the expected suffix is a parameter, `crypto/zkbench/src/statements.rs:343-357`) and π_C3S (R
and `skip` are parameters, `statements.rs:360-404`).

### 1.2 Upstream per-image billing (PR #773)

`routstr-core/routstr/payment/image_pricing.py` holds a per-model `ImagePricing` book with three units
(`image`, `token`, `megapixel`):

- `select_image_price_usd` (`image_pricing.py:330`) picks the tier from `resolution` (or `size`, or
  `width`/`height`, mapped to 1K/2K/4K by area) and `quality`. An undeclared tier is priced at the
  ceiling.
- `per_image_sats` (`:369`) scales the model's sats ceiling by the tier's share of `max_usd`.
- `requested_image_count` (`:485`) takes the larger of `n` and `variants` and refuses more than
  `MAX_RESERVED_IMAGES = 10` (`:85`).
- `image_reservation_msats` (`:509`) reserves tier × count (+ reference-image surcharge + a token
  book's input ceiling).
- `settle_image_sats` (`:436`) charges, in order: the upstream's own USD cost if trusted; reported
  image tokens; else tier price × **images returned** + reference surcharge.
- Venice's book is built from the model listing (`routstr/upstream/venice.py:497-540`); the unpriced
  options `enhance_prompt` and `enable_web_search` are refused (`venice.py:44`, `:263-272`).
- On the plain path, `handle_image_generation` (`routstr/upstream/base.py:2352-2470`) reads the whole
  body (capped at `image_max_response_bytes`, 40 MiB, `core/settings.py:51-53`), counts the images
  (`upstream/image_generation.py:60-65`, `:90-131`) and settles.

The confidential path cannot count returned images (the body is private) and cannot read the request
(the node must not). Both are answered by pinning: the count and the tier are in the suffix.

### 1.3 Venice's image API (from the public OpenAPI spec, `https://api.venice.ai/doc/api/swagger.yaml`, version 20261019)

Two routes, both `additionalProperties: false` (unknown fields rejected, per the spec):

| | `POST /api/v1/images/generations` (OpenAI-compatible) | `POST /api/v1/image/generate` (native) |
|---|---|---|
| Count | `n`, minimum 1, **maximum 1** | `variants` 1-4 (only with `return_binary: false`) |
| Size | `size` enum: auto, 256x256, 512x512, 1024x1024, 1536x1024, 1024x1536, 1792x1024, 1024x1792 | `width`/`height` ≤ 1280, `resolution` (1K/2K/4K), `aspect_ratio` |
| Quality | `quality` enum, documented as "not used" | `quality` low/medium/high, "can increase the final request charge" |
| Paid extras | none in the schema | `enhance_prompt`, `enable_web_search` (extra credits), `style_references` (per-reference surcharge on some models) |
| Model | defaults to Venice's default image model; **an unknown model silently falls back to the default** | required |
| Prompt limit | 1500 characters | per model (`promptCharacterLimit`, up to 32768) |
| Moderation | `moderation` auto/low | `safe_mode` |
| Output | `output_format` png (default)/jpeg/webp; `response_format` b64_json (default) or `url`, which is a **data URL**, not a hosted link | `format` webp (default)/png/jpeg; `return_binary` |
| Response body | `{"created", "data":[{"b64_json"}]}` | `{"id", "images":[b64], "request" (echo of the request body), "timing"}` |
| Streaming | no | no |
| Usage or cost in the response | **none** | **none** |
| Response headers | `x-venice-is-blurred`, `x-venice-is-content-violation`, deprecation headers | same, plus `x-venice-enhanced-prompt` when enhancement ran |
| Errors | 400, 401, 402, 403, 415, 429, 500 ("inference processing failed"), 503 ("at capacity") | same |

The free model listing (`GET /api/v1/models?type=image`, fetched for this study) prices 44 models. Flat
per-image models (`generation`): cheapest at $0.01 (`venice-sd35`, `z-image-turbo`, `chroma`,
`wai-Illustrious`, `lustify-*`). Tiered by resolution: e.g. `nano-banana-pro` 1K $0.18 / 2K $0.23 / 4K
$0.35. Tiered by resolution and quality: e.g. `gpt-image-2` 1K low $0.02 ... 4K high $0.83. No model
lists a steps-dependent price or an `inputImages` surcharge at present.

The spec says nothing about duplicate JSON keys. The chat route's last-wins and replace-not-merge
behaviour was verified live (paper App. A.1); for the image routes it is an untested assumption. It is
likely the same parser (JavaScript `JSON.parse` keeps the last duplicate by specification), but this
must go into the live gate (§7.3) before anything ships.

## 2. Feasibility (question 1)

### 2.1 Billing without a usage event

For a flat-priced model the provider's charge is `price(model, tier) × count`, where every argument is
a request parameter. If the suffix pins model, tier parameters and count, then:

- π_C2S proves the provider received exactly those values (as the effective ones, given last-wins),
  before the final body record is released (`main.rs:1557-1590`, held record at `:1581`).
- N knows the charge at setup. It reserves exactly `price × count + max(f_s, f_a)` and, on success,
  charges `price × count + f_s`.
- C knows the charge from the signed offer and checks the receipt for equality.

So the usage disclosure is not needed. What remains is the success/failure distinction, which today's
error path already covers: on an HTTP error C proves the error head (π_C3S, `skip` = error body
length) and N releases the reservation (less f_s) for 4xx/503. On success C sends a new, proof-less
`accept` message and N charges the flat price. A client that sends neither (it left, or it is
withholding) is charged the reservation, exactly as chat's "released, no usage disclosed" row
(`confidential_ws.py:734-762`). The reservation exceeds the flat charge only by `max(f_s, f_a) - f_s`,
so accepting is always in C's interest, and withholding gains nothing.

Is a "success proof" over the response head needed? No. Its only use would be to let N refuse to
charge on a non-200, which is against N's own interest; N is protected because a refund needs a proof
and a charge does not. C is protected because the charge is fixed in advance. This also avoids
disclosing the success head, which on Venice carries `x-venice-is-blurred` and
`x-venice-is-content-violation`: N does not learn whether the image was adult content.

Which pricing units fit:

- `image` books (Venice, flat or tiered): yes.
- `megapixel` books (Together): yes if width, height and steps are pinned (the price is then a
  function of pinned values, `image_pricing.py:369`).
- `token` books (OpenAI `gpt-image-*`) and `trust_upstream_cost` books (OpenRouter): no, the charge
  depends on reported usage. These need a usage disclosure (§5.3, deferred). The first version offers
  only models whose price is a pure function of the pinned parameters.

### 2.2 P1 to P6

| | Holds? | Notes |
|---|---|---|
| P1 credential | yes, unchanged | different head template, same π_NK. Profile item 8 (no reflection of the request head): the native route echoes the request **body** (`request`), not the headers; the spec lists no header echo. Gate it (§7.3). |
| P2 content | yes, with the leakage listed below | N never sees the prompt, the image, or (on success) the response head |
| P3 integrity | yes, unchanged | C verifies every response record's GCM tag natively; the request is C's body behind the proven suffix |
| P4 accounting | in a different form | the charge is computed from the proven request parameters at signed per-image prices, not from a provider-reported number. C can check it exactly. N bears the risk that its price book is wrong (as on the plain path) |
| P5 authenticity | yes, unchanged | |
| P6 freshness | yes, unchanged | |

### 2.3 What N learns

- The model, the pinned tier parameters (size or resolution, quality, output format) and the count:
  public by design, as model and max_tokens are for chat.
- The body length `len` (setup). This bounds the prompt length. C can pad: JSON whitespace before the
  suffix is legal, so the SDK should pad the private prefix to a bucket (for example the next 512
  bytes). The same mitigation applies to chat today and is not implemented there either.
- The response size and timing. Compressed image size is a weak signal about the image's content
  (flat or dark images compress better), and timing about the model's work. The paper already lists
  traffic volume and timing as a non-goal (§2); for images the volume is a larger share of what
  happens, so the residual should be stated explicitly. Pinning `jpeg` or `webp` narrows the range
  but does not remove it. Nothing at the protocol level can pad the provider's response.
- The outcome bit (success via `accept`, or the error status via the error head). Chat leaks the same.
- Not learned: the prompt, any non-price option C left in the private prefix (moderation / safe_mode,
  seed, negative prompt, aspect ratio where it does not change the price, background), the image, the
  success headers.

Non-price options must therefore **not** be pinned: pinning `safe_mode` or `moderation` would publish
them to N.

### 2.4 Errors, refusals, partial success

| Response | Outcome | Rationale |
|---|---|---|
| 4xx (400 validation, 401, 402, 403, 415, 429) | C proves the error head; N releases less f_s | provider did no work; existing path (`confidential_ws.py:646-651`) |
| 503 | same | "at capacity", no work |
| 500 "inference processing failed", 502, 504 | charged the reservation (chat rule, `:652-654`) | unclear whether Venice bills it; **open question** (§8). An images-specific rule could release instead |
| 200 with `x-venice-is-content-violation: true` or a blurred image | flat charge | the plain path charges it too (it counts the returned image, `base.py:2399-2403`); Venice presumably bills it. Open question |
| 200 with an error object in the body | flat charge | a refund would need a body disclosure. The OpenAI-compatible convention is a 4xx for errors, and the Venice spec has no 200 error shape. C bears this residual |
| 200 with fewer images than pinned | flat charge for the pinned count | does not arise with `n = 1`. With native `variants > 1` it is C's residual risk; see §4.1 (pin 1 in the first version) |
| Response larger than the sidecar's cap | sidecar aborts after the body was released: charged the reservation, and C gets no image | must not happen for an honest provider: the offer refuses variants whose worst case exceeds the cap (§3.4) |

The error head stays unambiguous for image bodies, for the same reason as chat's (paper §4.8): the head
must start the first covered record and its records must end the transcript (`main.rs:1400`), and
`validate_error_head` (`main.rs:2044-2079`) needs `\r\n\r\n`, a status line with spaces and
`Name: value` lines. Base64 has no spaces, CR or LF; JSON strings cannot hold raw CR/LF; with chunked
framing the only `\r\n\r\n` is the terminal `0\r\n\r\n`, whose preceding line `0` is not a header.
A 200 response of megabytes also cannot be passed off as an error head: `skip` would exceed
`MAX_C3S_NEED` (about 24.5 KB, `statements.rs:193`).

### 2.5 Injecting unpriced options before the suffix

The argument is the chat one (paper §3.1 items 5 and 6, App. A): the private prefix may contain any
key; the provider keeps the last duplicate, so the suffix's values win; a later object or array
replaces an earlier one; unknown fields and malformed JSON are rejected, so the prefix cannot leave a
string or object open for the suffix to land in. Concretely:

- Model, count, size/resolution, quality, format: pinned, so a prefix value is overridden.
- Paid extras on the native route (`enhance_prompt`, `enable_web_search`, `style_references`): must be
  pinned (`false`, `false`, `[]`). On the compatible route they are not in the schema, so
  `additionalProperties: false` should reject them with a 400 (free, and released); this must be
  confirmed live, because if Venice accepted and honoured them the node would pay unpriced credits.
- The compatible route's silent model fallback does not let C pick another model (the suffix's model
  wins), but it means a pinned model id that Venice retires is silently replaced by the default model
  at the default model's price. The node then charges its own price for the pinned id. That is a
  node-side pricing risk, not a client attack; the node should drop models Venice marks deprecated
  (the listing and the `x-venice-deprecated` header) from the offer. The native route requires the
  model and is expected to 404 an unknown one; gate it.
- Duplicate-key behaviour on the image routes: **not documented**. Required live checks in §7.3.

Conclusion: feasible, with the same trust properties, on condition that the image routes pass the
same profile checks as the chat route.

## 3. Response size (question 2)

### 3.1 Sizes

A 1K PNG is typically 1.5 to 2.5 MB, so 2 to 3.4 MB as base64 JSON; WebP or JPEG at 1K is a few hundred
KB. A 4K PNG can reach 20 to 30 MB raw, 27 to 40 MB as base64. (Estimates; the live check in §7.3
records real sizes per model and format.)

### 3.2 Sidecar

- `MAX_SERVER_BYTES = 64 MiB` (`main.rs:241`) caps all upstream bytes of a session (`:440-450`). Enough
  for 1K and 2K in any format and 4K in WebP/JPEG; marginal for 4K PNG. Make it a per-endpoint value
  from the sidecar offer (`max_response_bytes`, ≤ 64 MiB) rather than raising it.
- The sidecar does not buffer the response: after the handshake it only hashes and counts upstream
  bytes (`:440-450`) and keeps the last `SERVER_TAIL_RECORDS` application records (`:214`, `:415-422`),
  so memory is bounded at about 81 records × 16 KiB per session regardless of image size.
- Flow control: the upstream reader reads 64 KiB at a time (`:841`) against `TO_CLIENT_BUDGET = 4 MiB`
  (`:244`, `:851`), so a slow client back-pressures the provider socket. No change.
- π_C3S caps (`MAX_C3S_RECORDS = 64`, `MAX_C3S_BYTES = 24 KiB`, `statements.rs:174`, `:186`) are only
  relevant on the error path, where the error body is small. No change. They make a head-only success
  proof with `skip` = body length impossible, which is fine because none is needed (§2.1).
- `SESSION_TIMEOUT = 600 s` (`main.rs:202`) covers slow models.

### 3.3 Node

The node relays sidecar frames to the client; the sidecar sends at most 64 KiB per frame, and the node's
WebSocket limit is 12 MiB (`confidential_ws.py:90`). No change. The node's plain-path cap
`image_max_response_bytes` does not apply (the node never parses the body).

### 3.4 Clients (must change)

- SDK `session.ts:605` appends every decrypted record with `concat(this.responseBytes, rec)`, which
  copies the whole buffer per record: quadratic. For a 3 MB image (about 190 records) that is about
  290 MB of copying; for a 30 MB image about 28 GB. The web library has the same line
  (`src/session.ts:613`). Replace it with a growing buffer (capacity doubling) or a chunk list joined
  once. The same function also keeps `responseChunks`, and `trackServerRecords` keeps every ciphertext
  record (`session.ts:645`, web `:649`): three copies of the response. For images keep the ciphertext
  only for the last `MAX_C3S_RECORDS + 17` records (π_C3S parameters are checked only against the tail,
  `checkPiC3SParams`), and decode the base64 straight into a `Blob` in the browser.
- The attestation wait is an idle timeout of 60 s with no response bytes (`session.ts:225-240`, used at
  `:915`). An image response sends nothing until the image is done, and slow models (`gpt-image-2`
  high, 4K) can take longer than 60 s. Use a per-kind timeout (300 s for images, from the offer's
  `response_idle_s`).
- Cloudflare in front of Venice typically ends an origin request that sends nothing for about 100 s
  with a 524. That would be a 5xx after the body was released, so charged. The offer should leave out
  variants that are known to run that long, or the 5xx rule for images should release (open question).
- Parsing: the SDK's `parseHttpResponse` decodes the body to text (`bodyText`) and checks the effective
  model from it (`session.ts:1064-1067`). For images, skip the text decoding, parse JSON once and
  convert the native shape (`images: [...]`) to the OpenAI shape (`data: [{b64_json}]`).

## 4. Provider independence (question 3)

### 4.1 What is Venice-specific

| Item | Venice value | How the offer carries it |
|---|---|---|
| Path | `/api/v1/images/generations` or `/api/v1/image/generate` | the endpoint's `head_template` |
| Count key | `n` (max 1) or `variants` | a pin in `fixed_pins` (`"n":1` or `"variants":1`) |
| Tier keys | `size` (compat) or `resolution`/`quality`/`width`/`height`/`aspect_ratio` (native) | per-variant pins (§5.1) |
| Paid extras to switch off | native: `enhance_prompt`, `enable_web_search`, `style_references` | `fixed_pins` |
| Output keys | `response_format` + `output_format` (compat), `format` + `return_binary` (native) | `fixed_pins` or per-variant pins |
| Response shape | `data[].b64_json` or `images[]` | `response_shape: "openai" \| "venice"` (client-side conversion only) |
| Pricing unit | per image, by tier | the node's price books (PR #773) produce per-variant msat prices |
| Keys that must not exist | compat route rejects unknown keys, so pinning e.g. `stream:false` would break it | the suffix is whatever the offer says; nothing is hard-coded |

Generic OpenAI-compatible upstreams: OpenAI itself meters tokens (not flat; deferred), OpenRouter
reports cost (deferred), Together prices per megapixel × steps (flat if `width`, `height`, `steps` are
pinned). The design keeps every provider-specific value in the signed offer, so a second flat-priced
provider is a new sidecar offer file plus a profile run, not a code change in the sidecar or the
clients. This is a step beyond chat, where the suffix is still code (`main.rs:1538-1543`, paper §3.1
last paragraph).

### 4.2 Which Venice route

Recommendation: the **native route** for Venice, because the model is required (no silent fallback),
the tier parameters that change the price are explicit and pinnable, and the paid extras are
documented and can be pinned off. The compatible route is simpler (n is capped at 1, no paid extras
exist) but cannot select 2K/4K or quality, so tiered models are only available at their default tier,
and its model fallback is a pricing hazard. Both are expressible in the format below; the gate (§7.3)
decides. For other upstreams the compatible shape is the default profile.

## 5. Specification (question 4)

### 5.1 Offer

Additive. The top-level chat fields stay as they are, so old clients see an unchanged chat offer.

Sidecar offer file (operator config), new optional block:

```json
"endpoints": {
  "images": {
    "head_template": "POST /api/v1/image/generate HTTP/1.1\r\nHost: api.venice.ai\r\nAuthorization: Bearer {KEY:42}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {LEN}\r\n\r\n",
    "billing": "flat",
    "response_shape": "venice",
    "fixed_pins": [["variants", 1], ["return_binary", false], ["enhance_prompt", false],
                   ["enable_web_search", false], ["style_references", []]],
    "param_space": {"resolution": ["1K", "2K", "4K"], "quality": ["low", "medium", "high"],
                    "format": ["webp", "jpeg", "png"]},
    "max_response_bytes": 67108864,
    "response_idle_s": 300
  }
}
```

The node adds, in the signed offer it serves, the per-model variant list it can price:

```json
"capabilities": ["chat", "images"],
"images": {
  "head_template": "...as above, key length filled in...",
  "response_shape": "venice",
  "response_idle_s": 300,
  "max_count": 1,
  "price_list": {
    "z-image-turbo": [
      {"id": "webp", "pins": [["format", "webp"]], "msat_per_image": 10350}
    ],
    "nano-banana-pro": [
      {"id": "1K-webp", "pins": [["resolution", "1K"], ["format", "webp"]], "msat_per_image": 186300},
      {"id": "2K-webp", "pins": [["resolution", "2K"], ["format", "webp"]], "msat_per_image": 238050}
    ]
  }
}
```

The suffix for (model M, variant V) is defined once, byte-exactly, and rendered identically by the
sidecar (Rust) and both clients (TypeScript):

```
suffix = "," + join(",", [ "\"model\":" + json(M) ] + [ json(k) + ":" + json(v) for (k, v) in fixed_pins ++ V.pins ]) + "}"
```

with `json` = compact serialization (no whitespace, `serde_json::to_string` / `JSON.stringify` agree for
strings, integers, booleans, `[]`). Keys are unique across `fixed_pins` and `V.pins` (the sidecar refuses
an offer that repeats one). Every key in the variant's pins must be in `param_space`, and every key the
price function reads must be pinned (the node checks this when it builds the list; §5.4).

Rules for the node when it builds `price_list`:

- Only models with `produces_images(model)` (`image_pricing.py:504`), a candidate on the sidecar host,
  a book with `unit == "image"` (or `megapixel` with every input pinned), not `trust_upstream_cost`,
  and no reference-image surcharge reachable (the extras are pinned off).
- One variant per combination of the model's declared tiers (`resolutions` × `qualities`) and each
  allowed format, priced as `per_image_sats(model, {pins})` (`image_pricing.py:369`) in msat, rounded
  up, with the rate surcharge applied. Models without tiers get one variant per format.
- Leave out variants whose worst-case response exceeds `max_response_bytes` (4K PNG) and models marked
  deprecated.
- Image models must not appear in the chat `price_list`. Today `usable_price_entry` accepts zero
  rates (`payment/rates.py:29-41`), so an image model with zero token prices from the Venice provider
  would be offered for chat at zero rates (`confidential.py:398-412`). The deployed node's offer does not
  list any image model today, so this is latent; add a `produces_images` filter in `priced_models`.

### 5.2 Setup and settlement messages

Client → node `setup` (new fields; chat setups unchanged):

```json
{"type": "setup", "kind": "images", "model": "nano-banana-pro", "variant": "1K-webp", "count": 1,
 "len": 812, "nonce_c": "...", "offer_sig": "...", "auth": "...",
 "session_fee_msat": 0, "abandon_fee_msat": 2000}
```

`max_tokens` is absent for `kind: "images"`. `armed` must be false (or absent) for images; the node
refuses an armed image setup (§5.7).

Node → sidecar: the node validates and reserves, then forwards `kind`, `model`, `len`, `nonce_c`,
`escrow` and the **rendered `suffix`** (taken from its own signed offer). Add `kind` and `suffix` to
`_SIDECAR_SETUP_FIELDS` (`confidential_ws.py:107`) and to `sidecar_setup` (`:279-284`). The sidecar
already trusts the node, so taking the suffix from it is consistent with today's model.

Sidecar → client `ready`: unchanged, carries `suffix` and `head_len` (`main.rs:1262-1268`). The client
requires `suffix` to equal its own rendering from the signed offer, as today.

After the attestation (unchanged), the client sends one of:

- `{"type": "accept"}` for a 2xx. No proof.
- `{"type": "disclose", "r": <head>, "skip": ..., ...}` for an error status, exactly as today.

Sidecar → node on `accept`: `{"type": "usage", "sid": ..., "model": M, "usage": {"flat": true,
"kind": "images"}}`. On an error-head disclosure: the existing `{"error_status": ...}` usage after
π_C3S.

Node receipt (new fields; same signature scheme):

```json
{"v": 1, "kind": "images", "sid": "...", "model": "...", "variant": "1K-webp", "count": 1,
 "msat_per_image": 186300, "usage": {"flat": true}, "cost_msats": 186300,
 "reserved_msats": 188300, "balance_msats": ..., "session_fee_msat": 0, "abandon_fee_msat": 2000,
 "notary_pubkey": "...", "attestation_hash": "...", "time": ...}
```

The client checks `cost_msats == msat_per_image × count + f_s` with `msat_per_image` from the signed
offer it verified, plus the sid and attestation hash checks it already does.

### 5.3 Sidecar (`crypto/relay/src/main.rs`)

1. `Offer` (`:56-87`): add `endpoints: Option<Endpoints>` with the images block. At startup validate it
   like the chat template (`with_key_length`, alphabet check at `:566-577`), and check that
   `fixed_pins` keys are unique, that `param_space` keys do not collide with them, and that the
   template is HTTP/1.1 with `Connection: close` and `Accept-Encoding: identity`.
2. `ClientMsg::Setup` (`:661-680`): add `kind` (default `chat`) and `suffix: Option<String>`. Use
   `#[serde(deny_unknown_fields)]`-style strictness or an explicit `kind` check so an unknown kind is
   refused, never treated as chat.
3. `handle_setup` (`:1201-1269`): for images, require the endpoint block, ignore `max_tokens`, check
   the suffix's structure (it parses as the tail of a JSON object: `{"a":0` + suffix is valid JSON with
   unique keys; it starts with `,"model":` + json(model); it contains every `fixed_pins` pair in
   order) and store it. Build `head_len` from the images template (`placeholder_head`, `:146`) and use
   that template for the credential record and π_NK.
4. `BodySuffix` (`:1300-1335`): compare with the stored suffix instead of `canonical_suffix`. The
   window and π_C2S parameters are unchanged.
5. `Disclose` (`:1336-1438`): for images accept only an error head (`r` starting with `HTTP/1.`);
   refuse a usage disclosure.
6. New `ClientMsg::Accept {}`: only in state `Attested`, only for images, only once, and only after
   `c2_ok`; send the `usage` frame with `flat: true` and move to `Settled`. Refuse after a `disclose`.
7. `server_bytes` (`:440-450`): use the endpoint's `max_response_bytes` for images.
8. The sidecar offer endpoint (`/offer`) serves the `endpoints` block to the node.

### 5.4 Circuits (`crypto/zkbench`)

No new statement and no circuit change:

- π_NK: same statement, the images head template is a parameter (`build_pi_nk`). The template grows by
  a few bytes; cost is linear in the head length.
- π_C2S: same statement (`statements.rs:343-357`); `expected` is the images suffix (about 150 to 200
  bytes, smaller than chat's 230), so it is no slower.
- π_C3S: only on the error path, unchanged.

Tests to add: `tests/v2.rs` cases with an images head and suffix, so the vendored web copies need no
re-vendoring (nothing changes in `cu-crypto`, `twopc` or `zkbench` sources).

### 5.5 Node (`routstr-core`)

- `confidential.py`:
  - `build_offer` (`:487-543`): add `capabilities` and the `images` block built per §5.1 from
    `priced_image_models(side)`; remember the image price list in `OfferTerms` so it is frozen per
    signature like the chat rates.
  - `priced_models` (`:398-412`): exclude `produces_images` models.
  - `reserve_image(auth, model, variant, count, offer_sig, fees)`: frozen `msat_per_image` from the
    signed terms; refuse an unknown variant or `count` above the offer's `max_count`; reservation
    `msat_per_image × count + max(f_s, f_a)` through `pay_for_request`, as `reserve` does (`:726-815`).
  - `settle_flat(billing)`: charge `msat_per_image × count + f_s`, capped at the reservation.
- `confidential_ws.py`:
  - `validate_setup` (`:244-276`): branch on `kind`; for images require `variant` (string), `count`
    (int, 1..max_count), refuse `armed: true` and `max_tokens`.
  - `_open_session` (`:446-516`): call `reserve_image`; check the sidecar offer advertises the images
    endpoint before dialing; forward `kind` and the rendered `suffix`.
  - `_apply_settlement` (`:642-659`): `usage.flat` → `settle_flat` (requires `billing.kind ==
    "images"`; a flat usage on a chat session is a protocol breach and charges the reservation);
    `error_status` → unchanged.
  - Receipt (`_settle`): add `kind`, `variant`, `count`, `msat_per_image`.
- `/v1/models` `confidential_upstream` field (`models_fields`, `confidential.py:555-576`): list image
  models too, with `"kind": "images"`.

### 5.6 SDK (`routstr-sdk/client/confidential`) and web library (`routstr-confidential-web/src`)

Shared by both:

- `offer.ts`: parse and validate `capabilities` and `images`; render suffixes per §5.1 (one function,
  with test vectors shared with the sidecar's Rust tests).
- `session.ts`: a `kind` option. For images: setup without `max_tokens`; body = padded private JSON +
  suffix (`buildConfidentialBody`, web `suffix.ts`); per-kind idle timeout; growing response buffer and
  bounded ciphertext retention (§3.4); after attestation send `accept` for 2xx or the error head for
  ≥ 400; receipt check `cost == msat_per_image × count + f_s` (`verifyFlatReceipt` in `receipt.ts`),
  replacing the usage check at `session.ts:1038-1058`.
- Response conversion: venice shape → `{"created", "data": [{"b64_json"}]}`.
- `transport.ts` (SDK): route `POST /v1/images/generations` with the confidential opt-in to an image
  session; the caller's body is split into the private part (prompt and non-price options) and the
  variant (chosen from the caller's `model`, `size`/`resolution`/`quality`/`output_format`, refused
  if no offered variant matches; no silent substitution, no fallback to the plain path).
- Pre-warm: image sessions never use or create armed sessions. The pre-warm pool key is
  (node, model, max_tokens, credential) (SDK `prewarm.ts:17`, `:282`); image requests must not call
  `setTarget` (web `client.ts:197`, `:461`, `:520`), or selecting an image model would arm a chat
  session for it. Image activity may still count as user activity for the chat pool.

routstrd: pass the opt-in header through for `/v1/images/generations` (`src/daemon/http/index.ts`).
Optional for the first release.

### 5.7 PWA

- An "Image" mode next to chat, with a model picker built from `offer.images.price_list` and the
  variant choices (resolution, quality, format) shown with their per-image price in sats.
- **No pre-arm for images, on demand only.** The pre-warm setting stays a chat setting. The PWA's
  current default is pre-warm on (`src/main.ts:96`); that must not extend to image mode.
- Before the first image, say what a request costs in data: about 22 MB download and 1.2 MB upload of
  setup per image, plus the image. Offer WebP as the default format.
- Progress stages from the session events: secure setup (with byte counter), handshake, waiting for
  the provider, downloading (bytes), verifying, receipt.
- Cancel: before the request is sent, "released (less the unused-session fee)"; after, "charged".
- Show the signed receipt (price, variant, attestation) as for chat. Keep images in IndexedDB locally
  only, with a delete action.
- Version bump; the PWA's existing version check and automatic refresh apply.

### 5.8 Latency and cost of a cold image request

From `crypto/twopc/BENCH.md` (cold 2PC, 22.12 MB down / 1.21 MB up per session), plus about 1.5 MB per
proof over per-proof channels for π_NK and π_C2S (paper §6.2; π_C3S is not run on success):

| Client link | 2PC (cold) | + proofs and handshake | Overhead before the provider starts |
|---|---|---|---|
| local | 0.63 s | ~0.3 s | ~1 s |
| 25 ms, 100/100 Mbit/s | 3.05 s | ~2.5 s | ~5.5 s |
| 40 ms, 7 up / 50 down | 5.41 s | ~3 s | ~8 s |
| 40 ms, 2 up / 50 down | 7.38 s | ~3.5 s | ~11 s |
| 40 ms, 2 up / 10 down | 20.0 s | ~5 s | ~25 s |

(The proof column is an estimate from the 50 ms RTT proof timings, 1.2 to 1.3 s each, run partly in
parallel with the 2PC when the proof channel is opened alongside it, as the reference client does.)

Image generation itself takes about 5 to 60 s depending on the model, so on a good link the protocol
adds roughly 10 to 50 %. Per image the client moves about 26 MB of protocol data plus the image; 100
images on mobile data is about 2.6 GB. The node uploads about 22 MB and spends about 0.5 s CPU per
image. The abandon fee still applies to a cancelled image setup, so the node is paid for wasted
sessions; there is no armed waste because nothing is armed.

## 6. Versioning and rollout (question 5)

- **Protocol version stays 2.** The TLS epochs, the 2PC and the three statements are unchanged; only
  the HTTP-level content changes. Images are an **offer capability** (`capabilities: ["chat",
  "images"]` and the `images` block), covered by the offer signature.
- Old client, new node: ignores the new fields; chat unchanged.
- New client, old node: no `images` capability, so the client refuses a confidential image request
  with a clear error (`offer_no_images`) and never falls back to the plain path.
- New node, old sidecar: the sidecar offer has no `endpoints.images`, so the node advertises no
  images. If a misconfigured node forwarded an image setup anyway, an old sidecar would ignore `kind`
  and use the chat template and suffix; the client's π_NK parameter check (template from the signed
  offer) and suffix check then fail before anything is sent to the provider, so it still fails
  closed. The node check is still required.
- New sidecar, old node: the old node never sends `kind`; chat unchanged.
- Rollout order: sidecar, then node, then web library + PWA and SDK, then routstrd. Deploy sidecar and
  node together on the live host (as for the last content-type change).

### 6.1 Test plan

Unit:

- Sidecar: endpoint parsing and refusal cases; suffix structure check (open string, open object,
  duplicate keys, wrong model, missing fixed pin); `accept` state machine (before attestation, twice,
  after `disclose`, on a chat session); usage disclosure refused for images; images head template
  through `placeholder_head` and π_NK parameters; per-endpoint `max_response_bytes`.
- zkbench: π_NK and π_C2S with an images template and suffix (`tests/v2.rs`).
- Node: offer variant generation from Venice books (flat, resolution tiers, resolution × quality),
  exclusion rules (token / trust_upstream_cost books, deprecated models, oversize variants, image
  models out of the chat list); `reserve_image` and `settle_flat` arithmetic with fees and surcharge;
  4xx/503 release; flat usage on a chat session charges the reservation; receipt fields.
- SDK and web: suffix rendering against shared vectors from the Rust tests; variant selection from an
  OpenAI-style request; flat receipt check; response conversion; growing buffer (a 40 MB synthetic
  response in under a second); idle timeout per kind; image requests never touch the pre-warm pool.

Adversarial (extend `crypto/tools/adversarial-model-swap.sh` into an images gate on a dedicated node):

- Model swap: pricier model in the private prefix, cheap one pinned → provider must use the pinned one
  (check with `GET /api/v1/billing/usage`, below).
- Tier swap: `resolution: "4K"` / `quality: "high"` in the prefix with `1K`/`low` pinned.
- Count swap: `variants: 4` (native) or `n: 4` (compat) in the prefix.
- Option injection: `enhance_prompt: true`, `enable_web_search: true`, a `style_references` entry in
  the prefix (native, pinned off); the same keys on the compat route (must be a 400).
- A prefix that leaves a string or object open (must be a 400, released).
- A client that proves a different suffix (cheaper variant than set up) → sidecar refuses before
  release; a client that sends records after the suffix → refused.
- A client that disclaims a 200 as an error (fabricated head) → π_C3S fails, reservation charged.
- Oversized response: a fake upstream sending more than `max_response_bytes` → session ends, charged;
  and the offer must not contain a variant that can reach it.
- Honest control: one flat image, `accept`, receipt equals the signed price.

Live:

- Extend `crypto/tools/provider-profile-check.py` with an images section, I1 to I10:
  1. TLS 1.3 / P-256 / HTTP/1.1 / mid-request KeyUpdate on the image route.
  2. No processing before the full body (incomplete body for 8 s: no response, no charge).
  3. Last-wins per pinned key, good-then-bad → 400 (free) and bad-then-good → 200 (paid).
  4. Replace-not-merge for an array (`style_references`) and an object.
  5. Unknown top-level field → 400; malformed JSON and an open string → 400.
  6. Paid extras: rejected (compat) or overridden by the pin (native).
  7. Unknown model → 404/400 on native; record the fallback on compat.
  8. No reflection of the `Authorization` header in any error body or header.
  9. Error statuses: an invalid size, an over-long prompt, a content-policy prompt; record status and
     whether Venice billed.
  10. Charge check: after the paid cases, read `GET /api/v1/billing/usage` and confirm each charge
      equals the tier price the node priced (this verifies the node's tier mapping without trusting
      the response).
- Cheapest model for the paid cases: `z-image-turbo` (or `venice-sd35`/`chroma`), $0.01 per image. The
  gate needs about 10 paid requests, about $0.10, plus one 1K run of a tiered model to check the tier
  mapping (`qwen-image-2-1-turbo` at $0.02).
- End to end with the reference client (`crypto/client/src/driver.ts`, a new `--images` mode) and the
  PWA against a local node, then the deployed node.

## 7. Risks, open questions, effort (question 6)

### 7.1 Risks

- **Image routes may not satisfy the profile.** Duplicate-key and strictness behaviour is documented
  only as `additionalProperties: false`. If a route keeps the first duplicate, pinning fails and the
  route cannot be offered. Mitigated only by the live gate.
- **Price drift.** The node charges its signed price; Venice charges its current price. A Venice price
  change or a silent model fallback costs the node until the next offer. Same exposure as the plain
  path (which also bills from the book), but the confidential node cannot see the effective model in
  the response. Mitigation: refresh books often, drop deprecated models, alert on billing-usage
  mismatches.
- **Client pays for 200-with-error, blurred or content-violation images.** No refund without
  disclosing the body or the success head. Same outcome as on the plain path for violations.
- **Response size side channel.** Compressed size and timing leak a little about the image.
- **Slow models and proxy timeouts** (100 s at Cloudflare) turn into charged 5xx responses.
- **Client memory** on large images until §3.4 is done (quadratic copy).
- **Data cost** for mobile users: about 26 MB per image before the image itself.

### 7.2 Open questions for Juraj

1. Native or compatible route for Venice? (Recommendation: native, for tiers and explicit pins; the
   compatible route only allows default tiers.)
2. Count: pin 1 in the first version (simplest; partial success cannot arise), or allow native
   `variants` 2 to 4 charged as `price × count`?
3. For images, should 500/502/504 after release be charged (chat rule) or released? It depends on
   whether Venice bills failed generations; the live gate can tell for the cases it can provoke.
4. Should the SDK pad the prompt to fixed buckets (for images and for chat)? Costs a few hundred bytes.
5. Which formats to offer by default: WebP only (smallest, least side channel range), or PNG too
   (4K PNG excluded by size)?
6. Is the extra price in data (about 26 MB per image) acceptable for the PWA's mobile users, or should
   image mode be desktop-first with a warning on metered connections?
7. Do you want the generalized, offer-driven suffix (§5.1) to replace chat's hard-coded suffix later?
   It would close the gap the paper names in §3.1 (a second provider needs code changes).
8. Is the token-metered case (OpenAI `gpt-image-*` directly, via a usage-tail disclosure of the JSON
   body's final `"usage":{...}}`) worth a later phase?

### 7.3 Effort

| Component | Work | Estimate |
|---|---|---|
| Sidecar | endpoints in the offer, setup kind and suffix, `accept`, disclosure restriction, per-endpoint cap, tests | 2-3 days |
| zkbench | tests only | 0.5 day |
| Node | offer variants from price books, `reserve_image`/`settle_flat`, ws branches, receipt, chat-list filter, tests | 3 days |
| SDK | offer parsing, suffix renderer, image session path, buffers, flat receipt, transport route, tests | 3 days |
| Web library | same as SDK in the browser library, Blob output | 2 days |
| PWA | image mode, variant picker, progress, receipt, storage, no pre-arm | 2-3 days |
| routstrd | opt-in passthrough for the images path | 0.5 day |
| Provider gate and adversarial scripts | I1-I10, billing-usage check, images adversarial gate | 1.5 days |
| Docs | paper (§3.1 profile for images, §4.8 flat settlement, §8 opt-in), APPROACH, AGENTS | 1 day |
| **Total** | | **about 3 weeks** |

## 8. Summary of the design

- Same protocol v2, same circuits. New: an offer capability `images` with a head template, fixed pins
  and a signed per-model list of variants with a per-image msat price.
- The suffix pins model, count, tier parameters, output format and the provider's paid extras; π_C2S
  proves it before the provider sees a complete request.
- The charge is `msat_per_image × count + f_s`, fixed at setup. Success needs no disclosure: the client
  sends `accept` and gets a signed receipt. Errors use the existing error-head π_C3S for a release.
- N learns the model, variant, count, body length, response size and timing, and the outcome; not the
  prompt, the image, non-price options, or the success headers.
- Required before shipping: the image-route profile checks (§6.1, live), and the client buffer fix.
