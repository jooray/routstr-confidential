# Providers: which upstreams work with protocol v3

Measured on 2026-11-12 against the live providers, free models only (Venice:
the earlier reference measurement); Cloudflare and OpenCode Zen end to end on
2026-11-13 (`crypto/runs/providers-2026-11-13/`). Provider front ends change; re-run the
checks before you rely on a row. Raw outputs (keys never present) are in
`crypto/runs/providers-2026-11-12/`, with the scripts that produced them.

**What was run.** For each provider an offer file (host, chat path, key
length, the `chat` block with the generic pins `n`, `stream`,
`stream_options.include_usage`, an `h2` block with the provider's `/models` as
`probe_path`), then the steps below. The checks of `provider-profile-check.py`
are numbered A1–A13 (HTTP/1.1) and H1–H8 (HTTP/2); the per-provider notes name
them next to what they mean, for operators who re-run the check.

1. `provider-profile-check.py` HTTP/1.1 items A1, A2, A4, A5, A6, A7, A9, A10,
   A11, A12 (A3 is Venice-only; A8 and A13 need specific model pairs and were
   not run). The check reproduces the client's TLS profile exactly (TLS 1.3,
   only `TLS_AES_128_GCM_SHA256`, P-256 only, a KeyUpdate after the head).
   Its expected error texts are Venice's, so a rejection with another status
   or message shows as FAIL; the table reads the evidence (which request was
   served or refused), not the raw verdict.
2. `--h2 --h2-no-images --h2-body-bytes 20000`, first with `--h2-idle 60`,
   then again with `--h2-idle` set to the recommended `idle_secs` (H1-H8).
3. The idle close of one silent HTTP/2 connection (`keepalive.py none 1200 10`),
   and whether a client PING every 120 s holds it 15 min (`ping 900 120`);
   where PINGs did not help, a chat request every 150-200 s (`request`) tells
   an idle limit from an age limit.
4. End to end through the real protocol, for the providers whose chat profile
   holds: `crypto/tools/v3-check.sh` (our cu-sidecar with the provider's offer
   file and the reference driver: framing "2", framing "1.1", three requests
   on one HTTP/2 connection, a second request after 60 s idle, a 200 kB body,
   the decoy model in the private part, the model-swap attack).
5. Through a scratch routstr-core node (2026-11-12, after the two fixes below):
   `crypto/tools/v3-node-check.sh` with `CU_PROVIDER_TYPE`/`CU_HOST_MATCH` and the
   cases `h2-one h11-one h2-three h2-decoy h11-decoy h2-c-model-swap
   h11-c-model-swap`: chat on both framings, three requests on one HTTP/2
   connection, the decoy model in the private part (the provider must report the
   pinned model), the model-swap attack on both framings, every receipt verified
   (signature, sid, framing, request, the public id as `model`, the provider's id
   as `upstream_model`) and the money of every case exact in the node's database.
   For xKiro also `v3-routstrd-check.sh` (routstrd, 10 cases) and the SDK gate
   (`scripts/confidential-v3-e2e.ts`). The node runs on scratch state in a 0700
   directory and its database (which holds the provider key) is deleted at the end.

## Summary

| Provider | Works (chat) | HTTP/2 | HTTP/1.1 | Idle HTTP/2 kept for | Chat | Images | E2E | Node |
|:--|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **[Venice](#venice-reference)** (reference) | ✓ | ✓ | ✓ | 400 s | ✓ | ✓ | ✓ | ✓ |
| **[Numes](#numes)** | ✓ | ✓ | ✓ | 600 s | ✓ | ? | ✓ | ✓ |
| **[xKiro](#xkiro)** | ✓ pin price fields | ✓ (error text not checked) | ✓ unknown fields accepted | 400 s | ✓ | ? | ✓ | ✓ |
| **[OpenRouter](#openrouter)** | ✓ pin price fields | ✓ (error text not checked) | ✓ | 400 s | ✓ | ✗ only via chat | ✓ | ✓ |
| **[Cloudflare Workers AI](#cloudflare-workers-ai)** | ✓ pin price fields | ✓ (error text not checked) | ✓ unknown fields accepted | 400 s | ✓ | ? | ✓ | ✓ |
| **[NVIDIA NIM](#nvidia-nim)** | ✗ | ✓ | ✗ first `model` wins | 340 s (TCP close) | ✗ | ? | ✗ decoy runs | – |
| **[Google AI Studio](#google-ai-studio)** | ✗ | ✗ usage in content | ✗ usage in content | 240 s | ✗ | ? | – | – |
| **[UnoRouter](#unorouter)** | ✗ | ✗ usage not last | ✗ cap overrun | ? | ✗ | ? | – | – |
| **[OpenCode Go](#opencode-go)** | ✗ | ✗ no HTTP/2 | ✗ needs extra header | – | ✗ | ? | – | – |
| **[OpenCode Zen](#opencode-zen)** | ? free quota never served | ✗ no HTTP/2 | ? 429 on every chat | – | ? | ? | ? only 429s | – |

✓ works, ✗ does not, ? not tested or not available, – not run or not
applicable. "pin price fields" = the provider honours request fields the protocol does not
fix, so the operator pins the price-changing ones off in the offer
([below](#what-pin-means)). "Idle HTTP/2 kept for" = how long the provider
keeps a silent HTTP/2 connection open before it closes it (GOAWAY unless noted);
the `idle_secs` to offer is in each provider's notes. "E2E" = through our
sidecar with the reference driver (stub receipts, no node). "Node" = through a
scratch routstr-core node: the node's signed offer, its receipts and its
database (step 5). The reasons behind each mark, with the profile item numbers,
are below.

### What "pin" means

The client's part of the request body is private: the node never sees it, and
the provider reads it before the pinned suffix. A field the provider honours
there that changes the price without changing the pinned model, the caps or the
usage token counts is a loss for the node, because the node bills the reported
tokens at the offer's rates. The operator therefore lists such fields in the
offer's `chat.fixed_pins` with an "off" value (`false`, `"off"`, `[]`, or an
object whose members are all off; `docs/CHAT-SUFFIX.md`). The suffix comes last
and the provider keeps the last value of a duplicate key, so the pin wins. This
is a setting of the sidecar's offer file, not a protocol change. Which fields
need it is to verify per provider, from its documentation and with one request
each where that is free.

## Per provider

### Venice (reference)

**✓ works.** The deployed provider.

- Endpoint: `api.venice.ai/api/v1`. Ids carry no prefix, so its offer has no
  `upstream_models` and is unchanged.
- Profile: every HTTP/1.1 item (A1-A13) and every HTTP/2 item (H1-H8) passes.
- Idle: a silent HTTP/2 connection is closed after 400 s (GOAWAY). A PING or an
  empty SETTINGS every 2-5 min holds it 16+ min. Suggested `idle_secs`: 390
  (production).
- Images: ✓ native `/api/v1/image/generate`.
- E2E: chat ✓ / ✓ (v3 gates, production), follow-up on a kept connection ✓,
  image ✓, chat + image on one connection ✓.
- Node: chat ✓ / ✓ (`v3-node-check.sh`: 63/63, with the new decoy cases;
  routstrd 11/11), follow-up ✓, receipts and money ✓ exact.

### Numes

**✓ works.**

- Endpoint: `api.numes.ai/api/v1`.
- Model: free `moonshotai/kimi-k3.1-pro`, offered as `kimi-k3.1-pro` (15
  models in the node's offer, all via `upstream_models`).
- HTTP/1.1: the profile holds (A1, A2, A5, A6, A7, A9, A11, A12). An unknown
  field gets a 502: passed on and refused upstream, not ignored (A4). Of the
  price fields, `service_tier` and `web_search_options` get a 400, `prediction`
  is accepted (A10).
- HTTP/2: every item passes (H1-H8) at 590 s; the error-path probe (H7) uses a
  bad `service_tier`, since an unknown field is a 502.
- Idle: 600 s (GOAWAY). PINGs do not reset it; a request every 200 s keeps it
  (an idle limit, not an age limit). Suggested `idle_secs`: 590.
- Images: ? no image models.
- E2E: chat ✓ / ✓; follow-up ✓ (3 on one connection; after 60 s idle).
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection); ✓ exact; the decoy ran
  the pinned model, model swap refused on both framings.
- Watch: slow at times (time to first token up to 69 s): one `h2-three` run
  hit the 180 s case limit and passed with 600 s.

### xKiro

**✓ works, pin price fields** ([what pin means](#what-pin-means)). FreeLLMAPI key.

- Endpoint: `api.xkiro.com/v1`.
- Model (node): `mistral-small-2603` → `mistralai/mistral-small-2603`. The node
  prices 44 of xKiro's 69 models; `ministral-3b` is not among them, so the
  sidecar-level model could not be used.
- HTTP/1.1: the profile holds (A1, A2, A5, A6, A7, A9, A11, A12), but unknown
  fields (A4) and price fields (A10) are accepted silently; even
  `"temperature":"hot"` is a 200.
- HTTP/2: passes (H1-H6, H8) at 390 s. The check that no error response
  carries the key (H7) is incomplete: the 401 and 404 responses carry none, but
  no request field gets a 4xx, so there is no field error to read.
- Idle: 400 s (GOAWAY). A PING every 120 s holds it. Suggested `idle_secs`: 390.
- Pin: the same rule as OpenRouter. Since xKiro accepts any field without
  complaint, which ones it honours is to verify per field before a paid
  account is offered.
- Images: ? no image models.
- E2E: chat ✓ / ✓; follow-up ✓ (3 on one connection; after 60 s idle).
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection; routstrd: 5 on one);
  ✓ exact; decoy and model swap as Numes; routstrd gate 10/10 and SDK gate (20
  requests, all cases).

### OpenRouter

**✓ chat, pin price fields** ([what pin means](#what-pin-means)), **✗ images.**
FreeLLMAPI key, account with credit.

- Endpoint: `openrouter.ai/api/v1`.
- Model: sidecar `liquid/lfm-2.5-2.6b:free`. Node: routstr's OpenRouter
  catalogue drops `:free` ids, so a node offers paid models only: tested with
  `mistral-nemo` → `mistralai/mistral-nemo` ($0.00000024 a request).
- HTTP/1.1: the profile holds (A1, A2, A9, A11). The usage event (A7) passes
  under the §5.4 rule: one choice with an empty delta, `finish_reason`,
  `native_finish_reason` (it failed before the fix). The SSE framing (A12)
  passes on the re-run: the `: OPENROUTER PROCESSING` comment lines come first
  and are no part of the usage tail. Unknown fields are accepted (A4).
- HTTP/2: passes (H1-H6, H8) at 390 s; the error-text check (H7) is
  incomplete, since an unknown field is accepted.
- Idle: 400 s (GOAWAY). A PING every 120 s holds it. Suggested `idle_secs`: 390.
- Pin, to verify per field: `plugins` (e.g. paid web search, which is not in
  the token usage), `models` (fallback routing to another model), `provider`
  (routing preferences), `web_search_options`, and `modalities` (image output,
  billed at the image rate). `modalities` cannot be pinned under the clients'
  pin policy (only off values are allowed, so `["text"]` is refused): the way
  out is for the node not to offer image-output models for chat.
- Images: ✗ images come through chat (`modalities`); not supported
  ([below](#images-through-openrouter-chat)). E2E image ✗, chat + image on one
  connection ✗.
- E2E (sidecar, `liquid/lfm-2.5-2.6b:free`): chat ✓ / ✓ (one, three on a
  connection, decoy, model swap); follow-up ✓.
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection); ✓ exact; decoy and
  model swap as Numes. This account's data policy allows no endpoint of
  `liquid/lfm-2.5-2.6b` (404: settled as an error head, the abandon fee,
  exactly).

### Cloudflare Workers AI

**✓ works, pin price fields** ([what pin means](#what-pin-means)); the signed
offer publishes the account id. FreeLLMAPI key.

- Endpoint: `api.cloudflare.com/client/v4/accounts/<account>/ai/v1`.
- Model: free tier `@cf/meta/llama-3.2-1b-instruct` (sidecar); the node offers
  it as `meta/llama-3.2-1b-instruct` → `@cf/meta/llama-3.2-1b-instruct`
  (`upstream_models`).
- HTTP/1.1: the profile holds (A1, A2, A5, A6, A9, A11, A12). The usage event
  (A7) passes under the §5.4 rule: the usage is on every chunk and the last one
  has an empty `delta` and a `finish_reason`; only the last event is disclosed
  (it failed before the fix). Unknown fields (A4) and price fields (A10) are
  accepted.
- HTTP/2: passes (H1-H6, H8) at 390 s, measured with the probe
  `/client/v4/user/tokens/verify`. The clients accept only an API base plus
  `/models` as the probe, so the end-to-end offer uses
  `/client/v4/accounts/<account>/ai/v1/models`: a 405 without the key in it,
  and the probe's answer is discarded (the probe only carries the credential
  into the HPACK table).
- Idle: 400 s (GOAWAY). A PING every 120 s holds it. Suggested `idle_secs`: 390.
- Images: ? image models only on `/ai/run/@cf/...`;
  `/ai/v1/images/generations`: "No route for that URI".
- E2E (2026-11-13, `v3-check.sh`, 17/17): one request on each framing, three on
  one HTTP/2 connection, two HTTP/1.1 connections, a 200 kB body on both
  framings, a second request after 60 s idle, armed connections on both
  framings, a refused request then the good one on both, the decoy on both (the
  provider ran and reported the pinned model), the suffix and model-swap attacks
  refused on both framings.
- Node (2026-11-13, `v3-node-check.sh`, 8/8): chat ✓ / ✓, three on one
  connection, two HTTP/1.1 connections, decoy on both framings, model swap
  refused on both; every receipt verified and the money exact. Workers AI has
  no `/models` listing (405), so the node's `generic` provider found no models;
  the model was added through the node's admin API
  (`POST /admin/api/upstream-providers/{id}/models`, priced by hand; the gate's
  `CU_NODE_MODELS`).
- Watch: the account id is in the chat path, so the head template and the
  probe path of the signed offer publish it. Pin: the same rule as OpenRouter;
  which Workers AI fields change the price is to verify.

### NVIDIA NIM

**✗ blocked by model binding.** FreeLLMAPI key.

- Endpoint: `integrate.api.nvidia.com/v1`.
- HTTP/1.1: the **first** `model` key wins (routing), `max_tokens` the last
  (profile item A2). The rest holds (A1, A4 with a 400, A5, A6, A7, A9, A11,
  A12); price fields are accepted (A10).
- HTTP/2: every item passes (H1-H8) at 330 s.
- Idle: 340 s, TCP close **without** GOAWAY. A PING every 120 s holds it.
  Suggested `idle_secs`: 330.
- Chat: ✗ the pinned model can be overridden by a `model` in the private part.
- Images: ? image models are on `ai.api.nvidia.com/v1/genai/...`, another host
  and route.
- E2E: chat ✓ / ✓, but ✗ decoy (both framings: the request went to the decoy
  model and did not finish in 180 s); follow-up ✓ (3 on one connection).
- Node: not run (blocked by the model binding; not fixable by configuration).

### Google AI Studio

**✗ usage event shape.** FreeLLMAPI key.

- Endpoint: `generativelanguage.googleapis.com/v1beta/openai`.
- HTTP/1.1: the usage is merged into the last content chunk (A7). Only one cap
  key is accepted: `max_tokens` with `max_completion_tokens` is a 400 (A6), and
  completion tokens are 0 at `finish_reason: length` (thinking not reported).
  The rest holds (A1, A2, A4 with a 400, A5, A9, A11, A12).
- HTTP/2: a request without a key gets 400, not 401 (H5), and the usage is not
  its own event (H8); H1-H4 and H6 pass.
- Idle: 240 s, GOAWAY `session_timed_out`. PINGs do not reset it; a request
  every 150 s keeps it. Suggested `idle_secs`: 230.
- Images: ? no free image model.
- E2E and node: not run (blocked).
- Key: this key has a `.` (the sidecar accepts only `[A-Za-z0-9_-]`: π_NK
  alphabet); classic `AIza…` keys fit.

### UnoRouter

**✗ cap overrun, usage event not last.** FreeLLMAPI key.

- Endpoint: `api.unorouter.com/v1`. Free models: 1 request/min per model.
- HTTP/1.1: 64 completion tokens at a cap of 20 (A6); duplicate keys refused in
  both orders (A2); an incomplete answer (A11); an intermittent 403
  `consent_required`; `: PING` comments; the model reported without `:free`.
- HTTP/2: after 173 s idle the last event before `[DONE]` was not the usage
  event (H8; H5 fails with it); H1-H4 and H6 pass.
- Idle: ? not measured (1 request/min).
- Images: ? free FLUX models on `/v1/images/generations`, but the account's
  image budget answered 429.
- E2E and node: not run (blocked).

### OpenCode Go

**✗ needs a session header.** Flat-rate subscription; tested with
`glm-5.3-flash`.

- Endpoint: `opencode.ai/zen/go/v1`.
- HTTP/1.1: every request needs an `x-opencode-session` header (400
  `MissingSessionID`); the head template allows only Host, Authorization,
  Content-Type, Accept-Encoding, Connection, Content-Length. With the header
  added the profile holds (A1, A2, A6, A7, A9, A11, A12); unknown and price
  fields are accepted (A4, A10).
- HTTP/2: no `h2` in ALPN (H1).
- E2E and node: not run (blocked). What carrying the header would take:
  [below](#what-blocks-whom).

### OpenCode Zen

**? untested: the free quota is never available to this key.** OpenCode Go key.

- Endpoint: `opencode.ai/zen/v1`. 47 models, 11 free (`/zen/v1/models`).
- Quota: every chat request is a 429 `FreeUsageLimitError` ("Free models work
  in OpenCode; subscribe to OpenCode Go to keep going"), for
  `deepseek-v4.1-flash-free`, `glm-5.3-flash-free`, `mimo-v2.6-flash-free` and
  `nemotron-3.5-lightning-free`, with or without `x-opencode-session`. Tried
  2026-11-12 ~20:30 UTC (`retry-after` 12 655 s), 2026-11-12 23:36 UTC
  (`retry-after` 1405 s, counting down to 00:00 UTC) and 2026-11-13 00:00:35 UTC:
  still a 429, now with `retry-after` 86 364 s (the window moved on by a day).
  The free models appear to be meant for the OpenCode client only. Paid models
  need a balance (402).
- HTTP/1.1: the TLS profile passes (A9); every other item is inconclusive on
  the 429.
- HTTP/2: no `h2` in ALPN (H1), so HTTP/1.1 only (offer `http: ["1.1"]`, no
  `h2` block).
- E2E (2026-11-13, `v3-check.sh` with `CU_HTTP=1.1`): the protocol runs against
  Zen on HTTP/1.1 (handshake, π_NK, credential head, body, π_WIN); the 429 head
  was disclosed through π_C3S and settled as an error, the receipt verified; the
  model-swap attack was refused. Chat itself (usage event, decoy, caps) is
  untested; no node run (it would only settle the same 429).
- Unlike Go, Zen does not ask for `x-opencode-session` (an unknown model
  without it is a 400 "Model is unavailable", not `MissingSessionID`).

## What blocks whom

- **Usage event shape (Google only now).** The usage event is the last event
  before `[DONE]`; since 2026-11-12 its `choices` may be `[]` or one choice with
  no content (an allow-list of empty fields, PROTOCOL-V3.md §5.4; vectors in
  `crypto/relay/usage-event-vectors.json`), which accepts OpenRouter's and
  Cloudflare's shape (Cloudflare's usage on every chunk: only the last event
  is disclosed). Google merges the usage into the last content chunk: disclosing
  it would disclose output, so it stays refused.
- **First-wins model routing (NVIDIA).** The suffix pins `model` as the last
  key; NVIDIA routes by the first. A client can name another model in the
  private part and be billed at the pinned model's rates. Not fixable by
  configuration.
- **Unknown fields accepted (xKiro, OpenRouter, Cloudflare, OpenCode Go).**
  The private part can carry fields the suffix does not pin. On a free tier
  that costs the operator nothing; on a paid account every price-changing field
  the provider honours must be pinned off in the `chat` block
  ([what pin means](#what-pin-means); the OpenRouter candidates are in its
  notes).
- **Extra request header (OpenCode Go).** Needs a template header the sidecar
  and clients do not allow. OpenCode Zen (`opencode.ai/zen/v1`, same key) does
  not ask for it. What carrying it would take (not built):
  - *A fixed value per node* (e.g. a UUID in the sidecar's offer file, written
    into `head_template` and, for framing "2", into the connection head and the
    pinned request HEADERS block). It is then public template bytes: π_NK and
    π_WIN are unchanged, the client checks it like every other template byte.
    The clients' head-template policy would have to allow that one header name
    with a strict value alphabet (`[A-Za-z0-9-]`, fixed length) so a node cannot
    smuggle CR/LF or another header through it. Every client of the node shares
    the value, which links nothing the shared provider key does not already
    link. This is the safe and simple option, if OpenCode accepts a constant.
  - *A value per connection* chosen by the node: a second slot in the template
    that the node fills and discloses to the client before π_NK (the client
    rebuilds the head with it and checks the alphabet and length). Safe under the
    same alphabet rule, but it changes the template format, `c_commit` and the
    clients' rebuild.
  - *A value per request*: the client would write it in each request's HEADERS
    record, and π_WIN would have to pin its format instead of its bytes. Most
    work, and nothing gained unless the provider demands a fresh value.
- **Key alphabet (this Google key).** π_NK proves the key over `[A-Za-z0-9_-]`.
- **The node (fixed 2026-11-12).** routstr-core offered a model confidentially
  only when its public id equalled the id the provider is sent; the public id
  drops the `org/` prefix, so Numes, xKiro, OpenRouter and NVIDIA got no model
  into the offer. The node now offers such a model under its public id and pins
  the provider's own id in the suffix; the signed offer lists the pairs in
  `upstream_models` (PROTOCOL-V3.md §12.1), the receipt names both (`model`,
  `upstream_model`). Venice's ids have no prefix: its offer is unchanged.
- **OpenRouter's `:free` models through a node.** routstr-core's OpenRouter
  catalogue drops `:free` ids (`routstr/upstream/base.py`), so a node offers
  paid OpenRouter models only. The sidecar-level runs use a `:free` model.
- **xKiro's catalogue at the node.** The node prices 44 of xKiro's 69 models
  (`mistralai/ministral-3b` is not among them); the node runs used
  `mistralai/mistral-small-2603`.

## Images through OpenRouter chat

OpenRouter generates images through chat completions with
`"modalities": ["image","text"]`; the image arrives base64 in a delta and
the usage counts it as completion tokens. One live request
(`google/gemini-3.1-flash-lite-image`, $0.034): `completion_tokens` 1120, all
of them `completion_tokens_details.image_tokens`, billed by OpenRouter at the
`image_output` rate ($0.00003/token), twenty times the `completion` rate.
The protocol cannot serve this as it stands:

1. (no longer a blocker) the usage event's choice is an empty delta with the
   finish reason, which §5.4 accepts since 2026-11-12; the image itself comes in
   an earlier delta;
2. the node prices `completion_tokens` at the model's completion rate, so it
   would charge about 1/20 of the cost; it would need `image_tokens` priced at
   `image_output` (or settle on the reported `cost`, which π_C3S proves came
   from the provider);
3. the chat suffix does not pin `modalities`: any image-capable model offered
   for chat lets a client ask for images in the private part at text rates. Such
   models must be excluded from the chat offer, or the `chat` block must pin
   `modalities` (and the image price live in the offer);
4. the response is about 1.1 MB for one small image: the chat response limits
   and the client's tail handling need to allow it.

## Re-running

```bash
cd routstr-confidential
T=crypto/tools/provider-profile-check.py
python3 -I $T --offer my-offer.json --key-env MY_KEY --model <cheap chat model>
python3 -I $T --offer my-offer.json --key-env MY_KEY --model <same> --h2 --h2-no-images --h2-body-bytes 20000 --h2-idle 60
# then with --h2-idle set to the idle_secs you will offer (below the idle close you measured)
CU_V3_OFFER=my-offer.json CU_KEY_ENV=MY_KEY CU_UPSTREAM=<host>:443 CU_MODEL=<model> CU_SWAP_MODEL=<other model> \
  CU_TRUSTED_HOSTS=<host> CU_NO_IMAGES=1 CU_V3_PORT=7491 \
  CU_CASES="h2-one h11-one h2-three h2-decoy h11-decoy h2-c-model-swap" crypto/tools/v3-check.sh
```

Through a node: the same with `crypto/tools/v3-node-check.sh`, plus `CU_UPSTREAM_BASE=<API base URL>`,
`CU_PROVIDER_TYPE=generic` (or the provider's type), `CU_HOST_MATCH=<host part>`, `CU_V3_PORT`/`CU_NODE_PORT`.
Other knobs of both gates: `CU_HTTP=1.1` for a provider without HTTP/2 (an offer with `http: ["1.1"]` and no
`h2` block; only the `h11-*` cases run), `CU_API_BASES=<API base>` when the base is not `/v1` or `/api/v1` (the
reference driver accepts only those by default), and, for the node, `CU_NODE_MODELS=<file>` to add models
through the admin API when the node cannot list the provider's `/models` (Cloudflare). Invocations for
Cloudflare and OpenCode Zen are in `crypto/runs/providers-2026-11-13/README.md`.

The idle close: `crypto/runs/providers-2026-11-12/tools/keepalive.py <provider> none 1200 10`
(and `ping 900 120`, `request 900 200`); it uses the same connection code as
the profile check. The scripts in that directory read FreeLLMAPI's keys in
memory and pass them only through the environment of the processes that use
them.
