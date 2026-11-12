# Providers: which upstreams work with protocol v3

Measured on 2026-11-12 against the live providers, free models only (Venice:
the earlier reference measurement). Provider front ends change; re-run the
checks before you rely on a row. Raw outputs (keys never present) are in
`crypto/runs/providers-2026-11-12/`, with the scripts that produced them.

**What was run.** For each provider an offer file (host, chat path, key
length, the `chat` block with the generic pins `n`, `stream`,
`stream_options.include_usage`, an `h2` block with the provider's `/models` as
`probe_path`), then:

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

| Provider | Works (chat) | HTTP/2 | HTTP/1.1 | Idle close → `idle_secs` | Chat | Images | E2E | Node |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| [Venice](#venice-reference) (reference) | ✓ | ✓ | ✓ | 400 s → 390 | ✓ | ✓ | ✓ | ✓ |
| [Numes](#numes) | ✓ | ✓ | ✓ | 600 s → 590 | ✓ | ? | ✓ | ✓ |
| [xKiro](#xkiro) | ✓ pin | ✓ H7 ? | ✓ A4, A10 ✗ | 400 s → 390 | ✓ | ? | ✓ | ✓ |
| [OpenRouter](#openrouter) | ✓ pin | ✓ H7 ? | ✓ | 400 s → 390 | ✓ | ✗ | ✓ | ✓ |
| [NVIDIA NIM](#nvidia-nim) | ✗ | ✓ | ✗ A2 | 340 s → 330 | ✗ | ? | ✗ decoy | – |
| [Google AI Studio](#google-ai-studio) | ✗ | ✗ H5, H8 | ✗ A7 | 240 s → 230 | ✗ | ? | – | – |
| [Cloudflare Workers AI](#cloudflare-workers-ai) | partial | ✓ H7 ? | ✓ | 400 s → 390 | ? | ? | – | – |
| [UnoRouter](#unorouter) | ✗ | ✗ H8 | ✗ A6 | ? | ✗ | ? | – | – |
| [OpenCode Go](#opencode-go) | ✗ | ✗ no h2 | ✗ header | – | ✗ | ? | – | – |
| [OpenCode Zen](#opencode-zen) | ? untested | ✗ no h2 | ? 429 | – | ? | ? | – | – |

✓ works, ✗ does not, partial = the profile holds but it was not run end to
end, ? not tested or not available, – not run or not applicable. "pin" = the
provider accepts unknown fields, so on a paid account its price-changing
fields must be pinned off in the `chat` block. "Idle close" = when a silent
HTTP/2 connection is closed; `idle_secs` = the value to offer.
"E2E" = through our sidecar with the reference driver (stub receipts, no node).
"Node" = through a scratch routstr-core node: the node's signed offer, its
receipts and its database (step 5). The reasons behind each mark are below.

## Per provider

### Venice (reference)

**✓ works.** The deployed provider.

- Endpoint: `api.venice.ai/api/v1`. Ids carry no prefix, so its offer has no
  `upstream_models` and is unchanged.
- Profile: HTTP/1.1 ✓ A1-A13; HTTP/2 ✓ H1-H8.
- Idle: 400 s, GOAWAY. Keepalive ✓: a PING or an empty SETTINGS every 2-5 min
  holds it 16+ min. `idle_secs` 390 (production).
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
- HTTP/1.1: ✓ A1, A2, A5, A6, A7, A9, A11, A12. A4: an unknown field gets
  502 (passed on, refused upstream, not ignored). A10: `service_tier`,
  `web_search_options` 400, `prediction` accepted.
- HTTP/2: ✓ H1-H8 at 590 s (the error-path probe uses a bad `service_tier`,
  since an unknown field is a 502).
- Idle: 600 s, GOAWAY. Keepalive ✗: PINGs do not reset it; a request every
  200 s keeps it (idle limit, not age). `idle_secs` 590.
- Images: ? no image models.
- E2E: chat ✓ / ✓; follow-up ✓ (3 on one connection; after 60 s idle).
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection); ✓ exact; the decoy ran
  the pinned model, model swap refused on both framings.
- Watch: slow at times (time to first token up to 69 s): one `h2-three` run
  hit the 180 s case limit and passed with 600 s.

### xKiro

**✓ works** (pin price fields on a paid account). FreeLLMAPI key.

- Endpoint: `api.xkiro.com/v1`.
- Model (node): `mistral-small-2603` → `mistralai/mistral-small-2603`. The node
  prices 44 of xKiro's 69 models; `ministral-3b` is not among them, so the
  sidecar-level model could not be used.
- HTTP/1.1: ✓ A1, A2, A5, A6, A7, A9, A11, A12; ✗ A4, A10: unknown and price
  fields accepted silently.
- HTTP/2: ✓ H1-H6, H8 at 390 s. H7 ?: the 401 and 404 responses carry no key,
  but no request field gets a 4xx (even `"temperature":"hot"` is a 200).
- Idle: 400 s, GOAWAY. Keepalive ✓ (PING every 120 s). `idle_secs` 390.
- Chat: ✓ (caveat A4/A10). Images: ? no image models.
- E2E: chat ✓ / ✓; follow-up ✓ (3 on one connection; after 60 s idle).
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection; routstrd: 5 on one);
  ✓ exact; decoy and model swap as Numes; routstrd gate 10/10 and SDK gate (20
  requests, all cases).

### OpenRouter

**✓ chat, ✗ images.** FreeLLMAPI key, account with credit.

- Endpoint: `openrouter.ai/api/v1`.
- Model: sidecar `liquid/lfm-2.5-2.6b:free`. Node: routstr's OpenRouter
  catalogue drops `:free` ids, so a node offers paid models only: tested with
  `mistral-nemo` → `mistralai/mistral-nemo` ($0.00000024 a request).
- HTTP/1.1: ✓ A1, A2, A9, A11. ✓ A7 under the §5.4 rule (one choice with an
  empty delta, `finish_reason`, `native_finish_reason`; it failed before the
  fix). A12 ✓ on the re-run (the `: OPENROUTER PROCESSING` comment lines come
  first and are no part of the usage tail). A4: unknown fields accepted.
- HTTP/2: ✓ H1-H6, H8 at 390 s (H7 incomplete: unknown field accepted).
- Idle: 400 s, GOAWAY. Keepalive ✓ (PING every 120 s). `idle_secs` 390.
- Images: ✗ images come through chat (`modalities`); not supported
  ([below](#images-through-openrouter-chat)). E2E image ✗, chat + image on one
  connection ✗.
- E2E (sidecar, `liquid/lfm-2.5-2.6b:free`): chat ✓ / ✓ (one, three on a
  connection, decoy, model swap); follow-up ✓.
- Node: chat ✓ / ✓; follow-up ✓ (3 on one connection); ✓ exact; decoy and
  model swap as Numes. This account's data policy allows no endpoint of
  `liquid/lfm-2.5-2.6b` (404: settled as an error head, the abandon fee,
  exactly).
- Pin: on a paid account pin `plugins`, `models`, `provider` off.

### NVIDIA NIM

**✗ blocked by model binding.** FreeLLMAPI key.

- Endpoint: `integrate.api.nvidia.com/v1`.
- HTTP/1.1: ✗ A2: the **first** `model` key wins (routing), `max_tokens` the
  last; ✓ A1, A4 (400), A5, A6, A7, A9, A11, A12; A10 accepted.
- HTTP/2: ✓ H1-H8 at 330 s.
- Idle: 340 s, TCP close **without** GOAWAY. Keepalive ✓ (PING every 120 s).
  `idle_secs` 330.
- Chat: ✗ the pinned model can be overridden by a `model` in the private part.
- Images: ? image models are on `ai.api.nvidia.com/v1/genai/...`, another host
  and route.
- E2E: chat ✓ / ✓, but ✗ decoy (both framings: the request went to the decoy
  model and did not finish in 180 s); follow-up ✓ (3 on one connection).
- Node: not run (blocked by the model binding; not fixable by configuration).

### Google AI Studio

**✗ usage event shape.** FreeLLMAPI key.

- Endpoint: `generativelanguage.googleapis.com/v1beta/openai`.
- HTTP/1.1: ✗ A7: usage merged into the last content chunk; A6: `max_tokens`
  with `max_completion_tokens` is a 400 (one cap key only); completion tokens 0
  at `finish_reason: length` (thinking not reported). ✓ A1, A2, A4 (400), A5,
  A9, A11, A12.
- HTTP/2: ✗ H5 (no key gives 400, not 401), H8 (usage is not its own event);
  ✓ H1-H4, H6.
- Idle: 240 s, GOAWAY `session_timed_out`. Keepalive ✗: PINGs do not reset it;
  a request every 150 s keeps it. `idle_secs` 230.
- Images: ? no free image model.
- E2E and node: not run (blocked).
- Key: this key has a `.` (the sidecar accepts only `[A-Za-z0-9_-]`: π_NK
  alphabet); classic `AIza…` keys fit.

### Cloudflare Workers AI

**Partial: the profile holds, not run end to end.** FreeLLMAPI key.

- Endpoint: `api.cloudflare.com/client/v4/accounts/<account>/ai/v1`.
- HTTP/1.1: ✓ A7 under the §5.4 rule (usage on every chunk; the last one has
  an empty `delta` and `finish_reason`; it failed before the fix); A4, A10
  accepted. ✓ A1, A2, A5, A6, A9, A11, A12.
- HTTP/2: ✓ H1-H6, H8 at 390 s (`/ai/v1/models` is 405: probe
  `/client/v4/user/tokens/verify`).
- Idle: 400 s, GOAWAY. Keepalive ✓ (PING every 120 s). `idle_secs` 390.
- Chat: ? the usage shape is accepted now; not run end to end.
- Images: ? image models only on `/ai/run/@cf/...`;
  `/ai/v1/images/generations`: "No route for that URI".
- Watch: the account id sits in the path, so the signed offer publishes it;
  the node would need a provider type that lists Workers AI models.

### UnoRouter

**✗ cap overrun, usage event not last.** FreeLLMAPI key.

- Endpoint: `api.unorouter.com/v1`. Free models: 1 request/min per model.
- HTTP/1.1: ✗ A6: 64 completion tokens at cap 20; A2: refused in both orders;
  A11: incomplete answer; intermittent 403 `consent_required`; `: PING`
  comments; model reported without `:free`.
- HTTP/2: ✗ H8: after 173 s idle the last event before `[DONE]` was not the
  usage event (H5 fails with it); ✓ H1-H4, H6.
- Idle: ? not measured (1 request/min).
- Images: ? free FLUX models on `/v1/images/generations`, but the account's
  image budget answered 429.
- E2E and node: not run (blocked).

### OpenCode Go

**✗ needs a session header.** Flat-rate subscription; tested with
`glm-5.3-flash`.

- Endpoint: `opencode.ai/zen/go/v1`.
- HTTP/1.1: ✗ every request needs an `x-opencode-session` header (400
  `MissingSessionID`); the head template allows only Host, Authorization,
  Content-Type, Accept-Encoding, Connection, Content-Length. With the header
  added: ✓ A1, A2, A6, A7, A9, A11, A12; A4, A10 accepted.
- HTTP/2: ✗ H1: no `h2` in ALPN.
- E2E and node: not run (blocked). What carrying the header would take:
  [below](#what-blocks-whom).

### OpenCode Zen

**? untested (free quota).** OpenCode Go key.

- Endpoint: `opencode.ai/zen/v1`. 47 models, 11 free (`/zen/v1/models`).
- HTTP/1.1: ✓ A9 (TLS profile); A1-A12 ? not run: every chat request is a 429
  `FreeUsageLimitError` ("Free models work in OpenCode"; `retry-after`
  12 655 s), for `deepseek-v4.1-flash-free` and `glm-5.3-flash-free`, with or
  without `x-opencode-session`; paid models need a balance (402).
- HTTP/2: ✗ H1: no `h2` in ALPN. HTTP/1.1 only, once the free quota allows a
  profile run.
- Unlike Go, Zen does not demand `x-opencode-session` (an unknown model
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
  that costs the operator nothing; on a paid account any price-changing field
  the provider knows (OpenRouter: `plugins`, `models`, `provider`;
  `service_tier`) would have to be pinned off in the `chat` block.
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

The idle close: `crypto/runs/providers-2026-11-12/tools/keepalive.py <provider> none 1200 10`
(and `ping 900 120`, `request 900 200`); it uses the same connection code as
the profile check. The scripts in that directory read FreeLLMAPI's keys in
memory and pass them only through the environment of the processes that use
them.
