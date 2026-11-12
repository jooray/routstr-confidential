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
5. Through a scratch routstr-core node (`v3-node-check.sh` with the provider
   row's `provider_type` changed): see "The node" below; it offered no model
   for any provider tested here.

## Table

✓ works, ✗ does not (reason), ? not tested or not available (reason).
"E2E" = through our sidecar with the reference driver (stub receipts, no node).

| Provider | Endpoint | HTTP/1.1 (profile) | HTTP/2 (H items) | Idle close (silent) | Keepalive holds 15 min | Recommended `idle_secs` | Chat | Images | E2E chat (2 / 1.1) | Follow-up on kept connection | E2E image | Chat + image on one connection | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Venice (reference) | `api.venice.ai/api/v1` | ✓ A1-A13 | ✓ H1-H8 | 400 s, GOAWAY | ✓ PING or empty SETTINGS every 2-5 min: 16+ min | 390 (production) | ✓ | ✓ native `/api/v1/image/generate` | ✓ / ✓ (v3 gates, production) | ✓ | ✓ | ✓ | the deployed provider |
| Numes | `api.numes.ai/api/v1` | ✓ A1, A2, A5, A6, A7, A9, A11, A12; A4: an unknown field gets 502 (passed on, refused upstream, not ignored); A10: `service_tier`, `web_search_options` 400, `prediction` accepted | ✓ H1-H8 at 590 s (the error-path probe uses a bad `service_tier`, since an unknown field is a 502) | 600 s, GOAWAY | ✗ PINGs do not reset it; a request every 200 s keeps it (idle limit, not age) | 590 | ✓ | ? no image models | ✓ / ✓ | ✓ (3 on one connection; after 60 s idle) | ? | ? | free: `moonshotai/kimi-k3.1-pro` and others priced 0. E2E 9/9: decoy neutralised, model swap refused. Node: 0 models (prefixed ids) |
| xKiro (FreeLLMAPI key) | `api.xkiro.com/v1` | ✓ A1, A2, A5, A6, A7, A9, A11, A12; ✗ A4, A10: unknown and price fields accepted silently | ✓ H1-H6, H8 at 390 s; H7 ?: the 401 and 404 responses carry no key, but no request field gets a 4xx (even `"temperature":"hot"` is a 200) | 400 s, GOAWAY | ✓ PING every 120 s | 390 | ✓ (caveat A4/A10) | ? no image models | ✓ / ✓ | ✓ (3 on one connection; after 60 s idle) | ? | ? | the catalogue's `:free` ids are not in xKiro's `/models`; used `mistralai/ministral-3b` (catalogue: free, 500K tokens/day). E2E 9/9. Node: 0 models (prefixed ids) |
| OpenRouter (FreeLLMAPI key) | `openrouter.ai/api/v1` | ✗ A7: the usage event carries a non-empty `choices`; A12: `: OPENROUTER PROCESSING` comment lines; A4: unknown fields accepted. ✓ A1, A2, A9, A11 | ✓ H1-H6, H8 at 390 s (H7 incomplete: unknown field accepted) | 400 s, GOAWAY | ✓ PING every 120 s | 390 | ✗ settlement: the client and sidecar refuse a usage event with non-empty `choices` | ✗ images come through chat (`modalities`); the protocol cannot serve them as it stands (below) | ✗ / ✗ "the last event before data: [DONE] is not a usage event" | ✗ | ✗ | ✗ | free tier: 50 requests/day per account |
| NVIDIA NIM (FreeLLMAPI key) | `integrate.api.nvidia.com/v1` | ✗ A2: the **first** `model` key wins (routing), `max_tokens` the last; ✓ A1, A4 (400), A5, A6, A7, A9, A11, A12; A10 accepted | ✓ H1-H8 at 330 s | 340 s, TCP close **without** GOAWAY | ✓ PING every 120 s | 330 | ✗ the pinned model can be overridden by a `model` in the private part | ? image models are on `ai.api.nvidia.com/v1/genai/...`, another host and route | ✓ / ✓, but ✗ decoy (both framings: the request went to the decoy model and did not finish in 180 s) | ✓ (3 on one connection) | ? | ? | blocked by model binding |
| Google AI Studio (FreeLLMAPI key) | `generativelanguage.googleapis.com/v1beta/openai` | ✗ A7: usage merged into the last content chunk; A6: `max_tokens` with `max_completion_tokens` is a 400 (one cap key only); completion tokens 0 at `finish_reason: length` (thinking not reported). ✓ A1, A2, A4 (400), A5, A9, A11, A12 | ✗ H5 (no key gives 400, not 401), H8 (usage is not its own event); ✓ H1-H4, H6 | 240 s, GOAWAY `session_timed_out` | ✗ PINGs do not reset it; a request every 150 s keeps it | 230 | ✗ | ? no free image model | not run (blocked) | ? | ? | ? | this key has a `.` (the sidecar accepts only `[A-Za-z0-9_-]`: π_NK alphabet); classic `AIza…` keys fit |
| Cloudflare Workers AI (FreeLLMAPI key) | `api.cloudflare.com/client/v4/accounts/<account>/ai/v1` | ✗ A7: usage on every chunk, the last one with a non-empty `choices`; A4, A10 accepted. ✓ A1, A2, A5, A6, A9, A11, A12 | ✓ H1-H6, H8 at 390 s (`/ai/v1/models` is 405: probe `/client/v4/user/tokens/verify`) | 400 s, GOAWAY | ✓ PING every 120 s | 390 | ✗ | ? image models only on `/ai/run/@cf/...`; `/ai/v1/images/generations`: "No route for that URI" | not run (blocked) | ? | ? | ? | the account id sits in the path, so the signed offer publishes it |
| UnoRouter (FreeLLMAPI key) | `api.unorouter.com/v1` | ✗ A6: 64 completion tokens at cap 20; A2: refused in both orders; A11: incomplete answer; intermittent 403 `consent_required`; `: PING` comments; model reported without `:free` | ✗ H8: after 173 s idle the last event before `[DONE]` was not the usage event (H5 fails with it); ✓ H1-H4, H6 | ? not measured (1 request/min) | ? | ? | ✗ | ? free FLUX models on `/v1/images/generations`, but the account's image budget answered 429 | not run (blocked) | ? | ? | ? | free models: 1 request/min per model |
| OpenCode Go | `opencode.ai/zen/go/v1` | ✗ every request needs an `x-opencode-session` header (400 `MissingSessionID`); the head template allows only Host, Authorization, Content-Type, Accept-Encoding, Connection, Content-Length. With the header added: ✓ A1, A2, A6, A7, A9, A11, A12; A4, A10 accepted | ✗ H1: no `h2` in ALPN | – | – | – | ✗ | ? | not run (blocked) | ? | ? | ? | flat-rate subscription; tested with `glm-5.3-flash` |

## What blocks whom

- **Usage event shape (OpenRouter, Google, Cloudflare).** The sidecar
  (`validate_r`, `h2.rs`) and the clients take the last event before
  `[DONE]` as the usage event and require `choices: []`. These providers put
  `usage` into a chunk that still carries a choice (an empty delta with the
  finish reason on OpenRouter and Cloudflare, the last content on Google). A
  relaxed rule (a choice whose delta has no content) would accept OpenRouter and
  Cloudflare; Google's merged chunk would disclose the last output text.
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
  and clients do not allow.
- **Key alphabet (this Google key).** π_NK proves the key over `[A-Za-z0-9_-]`.
- **The node (all prefixed-id providers).** routstr-core offers a model
  confidentially only when its public id equals the id the provider is sent
  (`offered_models` in `routstr/confidential.py`). The public id drops the
  `org/` prefix (`algorithm.py`, `get_base_model_id`) and a forwarded id equal
  to the model id is ignored, so with provider types `custom` and `generic`
  Numes listed 11 priced models and the confidential `price_list` was empty.
  This affects every provider whose ids carry an `org/` prefix (Numes, xKiro,
  OpenRouter, NVIDIA). The node-level end-to-end runs (receipts and money in
  the node's database) therefore could not run for any provider here; the
  sidecar-level runs above cover the protocol.

## Images through OpenRouter chat

OpenRouter generates images through chat completions with
`"modalities": ["image","text"]`; the image arrives base64 in a delta and
the usage counts it as completion tokens. One live request
(`google/gemini-3.1-flash-lite-image`, $0.034): `completion_tokens` 1120, all
of them `completion_tokens_details.image_tokens`, billed by OpenRouter at the
`image_output` rate ($0.00003/token), twenty times the `completion` rate.
The protocol cannot serve this as it stands:

1. the usage event has a non-empty `choices` (as for chat);
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
