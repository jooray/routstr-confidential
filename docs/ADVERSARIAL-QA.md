# Adversarial Q&A — routstr confidential upstream

*First written 2026-10-09 against the prototype; updated 2026-10-10 to the
integration branches. Adversarial review of the
confidential-upstream protocol against three questions: (Q1) model-name
binding to the reservation, (Q2) transferability beyond Venice, (Q3) what the
node learns and how the reservation economics close. Every specific claim is
grounded in the documents and code listed below; anything not verifiable from
them is marked **unknown** together with the test that would settle it.*

**Sources.** Citations are into this repository; `docs/original/*` are the
authors' working documents and are not published:

- `SPEC` — `docs/original/SPEC-confidential-upstream.md` (protocol contract, v0.1)
- `PLAN` — `docs/original/PLAN-confidential-upstream.md` (implementation contract)
- `WIRE-UP` — `docs/original/WIRE-UP-confidential-upstream.md` (integration spec)
- `VENICE-TESTS` — `docs/original/VENICE-TESTS.md` (provider behaviour, first
  round; the live gate is now `crypto/tools/provider-profile-check.py`)
- `BENCH` — `docs/original/BENCHMARK-keyupdate.md`; current figures: paper §6.2
- Code, cited by symbol rather than line number: `crypto/relay/src/main.rs`
  (the sidecar, N's TLS relay: `handle_setup`, the `Session` struct,
  `canonical_suffix`, the `ClientMsg::BodySuffix` and `ClientMsg::Disclose`
  handlers, `validate_r`, `validate_error_head`), `crypto/zkbench/src/statements.rs`
  (`build_pi_c1`, `build_pi_n`, `build_pi_c2`, `build_pi_c3`),
  `routstr-core/routstr/confidential.py` (`reserve`, `settle`,
  `frozen_cost_msats`, `prompt_token_limit`),
  `routstr-core/routstr/confidential_ws.py` (`_apply_settlement`), and the
  clients' parameter checks in `routstr-sdk/client/confidential/params.ts` and
  `crypto/client/src/params.ts`.

> **Current state (integration branches, 2026-10-10).** GAP-1, GAP-2 and GAP-3
> are **closed**; the prototype analysis that found them is kept in
> Appendix C for the record.
>
> - **Q1, model binding.** The sidecar (N's TLS relay) builds the canonical
>   suffix from the setup values and accepts no other. It holds the record that
>   completes the body until π_C2 proves the suffix, so the provider never sees
>   a complete request with another model or cap. The disclosed usage must name
>   the setup model, checked in the sidecar and again by the node before it
>   charges.
> - **Q3, money.** There is no protocol-specific escrow. The client
>   authenticates with its ordinary node credential (API key or Cashu token)
>   and names the signed offer it verified. The node freezes that offer's rates
>   and reserves `max(min_request_msat, ⌈(prompt_limit·in + max_tokens·out)/1000⌉)`,
>   where `prompt_limit` is the model's full context length: the opaque prompt
>   is never discounted (and never reduced by the model's own completion
>   limit, which the pinned cap rarely reaches). It charges exactly the frozen-rate
>   cost of the π_C3-verified usage. It releases the reservation if the provider
>   never received the complete request or answered a 4xx/503, and charges the
>   reservation for another 5xx or if the client withholds its disclosure.
> - **Q3, the prompt.** The node sees only ciphertext. π_C2 and π_C3 compare
>   inside the circuit and reveal one bit; the client validates their
>   parameters, so the node cannot aim them at other plaintext. On an upstream
>   error the client discloses only the response head.
>
> The provider assumptions are re-checked live by
> `crypto/tools/provider-profile-check.py` (A1–A11, 11/11 for Venice on
> 2026-10-10). "Escrow" in SPEC and in Appendix C means what is now the node's
> reservation.

---

## Q1. Can the client change the model name? Is it verified by the node?

### 1.1 Where the model appears in the protocol

There are exactly four places the model string exists, plus one place it must
never appear:

1. **Setup (plaintext to N).** C chooses `model`, `max_tokens` (≤ cap) and the
   body length `LEN` (SPEC §5.1 step 1). The node reserves for this model
   (`confidential.py` `reserve`); model identity is not private between C and
   N, by design.
2. **The request body (ciphertext to N).** The body is
   `body_private ‖ suffix` under `c_ap_2`, a key N cannot derive (SPEC §5.5,
   §6 row P2). Both `body_private` and the suffix may contain a `"model"` key.
   N never sees either in plaintext.
3. **The public suffix (plaintext to N, proven in ZK).** The suffix is the
   byte string `,"model":"<M>","max_tokens":<T>,…}` built by the sidecar's
   `canonical_suffix` from the setup values. It is sent to C in `ready`, C
   sends it as `body_suffix`, and it is the public `expected` value of π_C2
   (`statements.rs` `Window.expected`, `build_pi_c2`).
4. **The upstream usage event (disclosed at settlement).** Venice's final SSE
   event carries `"model"` alongside `usage` and `cost`. It is disclosed as
   `R` and bound to the server ciphertext by π_C3 (SPEC §5.7 steps 1–2).
5. **Never in the head.** N writes the request head; the head template
   contains the path, host, Authorization, and `Content-Length`, but no model
   (`main.rs` `default_head_template_for`; offer `head_template`). So N cannot
   inject or alter the model, and the model cannot be used to smuggle data
   into N's record.

**Effective-model semantics.** Venice keeps the *last* value of duplicate JSON
keys, normalizes escaped keys, and rejects malformed JSON and unknown fields
with 400 (SPEC §5.5; VENICE-TESTS "Duplicate keys and malformed JSON";
provider-profile checks A2–A5). Since the suffix is the last bytes of the body,
the suffix's `"model"` is the effective one. This is tested: the `b-decoy`
case of `crypto/tools/adversarial-model-swap.sh` runs the full protocol with a
decoy model in the private part and confirms the session settles as the
suffix model.

### 1.2 The attack

The reservation is priced per model (the offer's `price_list`). A malicious
client wants inference from a 100× more expensive model than the one it
reserved for:

1. At setup, declare `model = cheap`; the node reserves for `cheap`.
2. In the body, make the *effective* model `expensive`, either by putting
   `"model":"expensive"` in the private part or by putting it in the suffix
   itself, or withhold the suffix.
3. Settle. If the node prices `cost = price(cheap, usage)`, or prices
   correctly but the cost exceeds the reservation, the node pays Venice more
   than it collected.

For this to work, the attacker must break **at least one** of three bindings:
(i) suffix model vs setup model, (ii) effective model vs suffix model,
(iii) charged model vs effective model. We take them in turn.

### 1.3 Binding (ii): effective model ≡ suffix model — SOUND (tested)

- The private part cannot win: last-duplicate-key semantics, including escaped
  keys, verified on real Venice (VENICE-TESTS rows 1–3; provider-profile A2;
  `b-decoy` end-to-end).
- The client cannot smuggle the suffix out of reach of the parser: unterminated
  strings, trailing garbage after an early `}`, an unclosed `messages` array,
  `NaN`, trailing commas and comments all yield 400s, i.e. no inference happens
  and no usage event exists (VENICE-TESTS "malformed JSON" rows;
  provider-profile A5).
- π_C2 proves, in ZK, that the last `|suffix|` bytes of the epoch-2 plaintext
  equal the public suffix (`build_pi_c2`). The comparison is inside the
  circuit; the verifier learns one bit. The proof anchors to the session key
  schedule, so it cannot be replayed from another session (`derive_session`,
  `key_schedule_check`).
- The client cannot choose the suffix *after* seeing anything useful: π_C2
  proves equality against the final body record that was **already relayed
  and logged** (the `BodySuffix` handler takes the window from the last record
  in the relay log), and the client's own parameter check requires the window
  to end at the end of that record. There is no time-of-check/time-of-use gap
  between the proven suffix and the body.

So the effective model is always the suffix model. The question reduces to:
**is the suffix model bound to the reserved (setup) model?**

### 1.4 Binding (i): suffix model ≡ setup model — SOUND (GAP-1 closed)

- `handle_setup` stores `model` and `max_tokens` in the `Session` struct after
  checking them (non-empty model, `1 ≤ max_tokens ≤ cap`, body length in
  `[1, max_body]`); the node validates the same values before it reserves.
- The `ClientMsg::BodySuffix` handler rebuilds `canonical_suffix(model,
  max_tokens)` and refuses any `body_suffix` that is not byte-equal to it
  ("body suffix does not match the canonical suffix for model/max_tokens").
  That reconstruction is π_C2's public `expected` value. Because the suffix
  pins `max_completion_tokens`, `n`, `stream`, `stream_options` and
  `venice_parameters` too, the whole cost-parameter surface is bound at once.
- The record that completes the body is held until π_C2 verifies. A client
  that sends another suffix, or none, never gets a complete request to the
  provider: no inference, reservation released.
- The node computes the reservation itself from the setup model and the frozen
  rates of the offer the client verified (`reserve`); no client-computed amount
  is trusted.

### 1.5 Binding (iii): charged model ≡ effective model — SOUND (GAP-2 closed)

- The `ClientMsg::Disclose` handler runs `validate_r` (chunk framing, the
  `data: [DONE]` terminator, empty `choices`, the token counts and a `model`
  field) and then refuses the disclosure unless the usage event's `model`
  equals the setup model.
- The node checks again in `_apply_settlement`: a usage event whose `model`
  differs from the reserved model is charged the full reservation.
- The charge uses the node's frozen rates for the setup model
  (`frozen_cost_msats`), never a client-reported price or model.

The direct (no-node) deployment's Rust `settle()` stub still carries a default
model string, but it runs only after the `Disclose` handler's check, and the
node deployment (`--node-settles`) does not use it.

### 1.6 Remaining model-related attacks and their disposition

| # | Attack | Disposition |
|---|---|---|
| 1 | Private-part `"model":"cheap→expensive"` (decoy) | **Sound.** Last-wins, tested incl. escaped keys (VENICE-TESTS; `b-decoy` settles as the setup model). |
| 2 | Suffix model ≠ setup model | **Sound (GAP-1 closed).** Refused by the `BodySuffix` handler; `a-suffix-mismatch` refused, reservation released. |
| 3 | Change suffix between setup and π_C2 | **Sound.** The suffix is π_C2's public input, checked against the already-relayed final body record (`BodySuffix` handler; client parameter check). No TOCTOU. |
| 4 | `max_completion_tokens` bypassing `max_tokens` | **Sound (regressed once, fixed).** Venice lets `max_completion_tokens` override `max_tokens`; the suffix pins both (VENICE-TESTS rows 4–5; provider-profile A6). The per-provider regression gate must keep this case. |
| 5 | `"n":3` for 3× output | **Sound.** Pinned `"n":1` in the suffix; Venice 500s on n>1 anyway (VENICE-TESTS). |
| 6 | Cost-relevant `venice_parameters` (web search, system prompt) | **Sound.** The suffix sets the *whole* `venice_parameters` object; last-wins replaces it wholesale, so nothing inside can survive from the private part (tested: web search off, 16 vs 4675 prompt tokens; VENICE-TESTS). `include_venice_system_prompt:false` pins the ~1.7k-token system prompt (provider-profile A7). |
| 7 | Reasoning tokens inflation | **Sound (bounded).** Reasoning counts toward completion tokens and is capped by the pinned token limit (tested, VENICE-TESTS `reasoning_effort` row; A6). `reasoning_effort` itself is not pinned and does not need to be, because its cost is bounded by `max_completion_tokens`. Any future parameter whose cost is *not* token-bounded (per-call fees) **would** need pinning — see §2.2 item C7. |
| 8 | Cached-token pricing games | **Sound.** Cached tokens are *cheaper*; the reservation uses the uncached `in` rate, and settlement charges `min(cached, prompt)` tokens at `min(cached_in, in)` (`frozen_cost_msats`). |
| 9 | Unknown/novel cost fields in the private part | **Sound, with maintenance burden.** Venice's strict schema 400s unknown fields (sampled: provider-profile A4, A10). The residual risk is *schema evolution*: Venice adding a new cost-relevant known field. The regression gate is the mitigation; the offer's `suffix_keys` must be extended whenever one appears. |
| 10 | Endpoint swap to a differently-priced API | **Sound.** The request line (`POST /api/v1/chat/completions`) is inside N's head record, proven by π_N against the offer template (`build_pi_n`). The client cannot reach `/v1/responses`, embeddings, etc.; the SDK and routstrd also refuse any endpoint but chat completions before a credential is used. |
| 11 | **Model aliases**: the requested name resolves server-side to a differently-priced backend while the usage event reports the requested name | **Unknown — testable, bounded by ops.** Venice's usage event reports the requested string. If Venice ever aliases across price tiers, settlement by the node's price list under-charges while Venice's bill is higher. Mitigation: node-side monitoring comparing realized `cost` against `price_list` per model. **Test:** for each offered model, diff Venice's `cost` against the published per-token price over a sample of requests; alert on drift. |
| 12 | Multimodal token amplification (image URL in `messages` → thousands of image tokens from ~100 body bytes) | **Bounded by the reservation (GAP-3 closed).** The reservation covers the model's full context at the input rate, whatever the body bytes. The offer also lists only models that reject image parts; `regression-modality.py` enforces both `image_url` and data-URI rejection (8/8 live). |
| 13 | Malicious *node* downgrading the model to pocket the spread | **Sound.** The node writes only the head (no model field); the body is sealed under keys it never holds (SPEC §6 P2). It cannot alter the suffix or the private part. |

### 1.7 Q1 verdict

The model is bound at four points, and each is enforced:

1. **Setup.** The node validates the setup and reserves the declared model's
   full-context prompt plus the pinned `max_tokens`, at the frozen rates of
   the offer the client verified.
2. **Suffix.** The sidecar builds the canonical suffix from the setup values
   and accepts no other.
3. **Before the upstream can start.** The sidecar holds the record that
   completes the body until π_C2 proves the body ends with that suffix.
   Last-wins makes the suffix the effective request. The upstream has an
   incomplete request until then, so a client that swaps the model or the cap,
   or withholds the suffix, gets no inference at all.
4. **Settlement.** The π_C3-disclosed usage event must name the setup model
   (sidecar `Disclose` handler; node `_apply_settlement`).

Evidence: the regression gate `crypto/tools/adversarial-model-swap.sh` runs an
honest control and five attack cases against a live node and sidecar, with an
expected outcome per case and a money assertion against the node's billing
log, and exits non-zero on any deviation. Live run 2026-10-10, **6/6 PASS**:

| Case | Expected and observed |
|---|---|
| `control` | honest session settles, verified receipt |
| `a-suffix-mismatch` | refused (suffix ≠ canonical), reservation released |
| `b-decoy` | settles as the setup model |
| `d-no-suffix-swap` (pricier offered model, no suffix) | withheld, 0 response bytes, reservation released |
| `e-unoffered-model` (`claude-fable-5`, no suffix) | withheld, 0 response bytes, reservation released |
| `f-claim-canonical` (body ends with another suffix, client claims the canonical one) | refused by π_C2, reservation released |

No attack case reached the upstream as a complete request; the honest
control and `b-decoy` were charged 19 msats each. The gate writes this table
as `summary.tsv` in its output directory. The files in
`crypto/runs/adversarial/` from 2026-10-09 (`ledger.txt`, `NOTES.md`, showing
`status=kept`) record an interim escrow policy and are not evidence for the
current billing.

---

## Q2. Transferability to other OpenAI-compatible providers

### 2.1 What is Venice-specific vs generic

**Generic (provider-independent) machinery:**

| Piece | Evidence |
|---|---|
| TLS 1.3-only client, single suite `TLS_AES_128_GCM_SHA256`, one key share, tickets off | SPEC §3; PLAN §4 |
| The KeyUpdate epoch dance (KU0 → N's credential record → KU1 → body) | SPEC §4–5.4 |
| Key-schedule derivation and the in-circuit chain (`key_schedule_zk`, RFC 8448-tested) | PLAN §1–2; `crypto/cu-crypto`; `statements.rs` `derive_session`, `key_schedule_check` |
| GCM record assembly from keystream material (CTR/GHASH math) + π_C1/π_N structure | SPEC §5.4; `main.rs` `assemble`; `statements.rs` `build_pi_c1`, `build_pi_n` |
| Head template mechanism (`{KEY:L}`, `{LEN}`, alphabet proof) — works for any static bearer credential in a fixed header position | SPEC §5.0/§5.4; `main.rs` `default_head_template_for`, `placeholder_head` |
| π_C2 "last bytes of body equal public suffix" and π_C3 "disclosed tail decrypts from final server records" as *statements* | `statements.rs` `build_pi_c2`, `build_pi_c3` |
| Reservation/settlement/attestation skeleton (node credential, sid, signed receipt) | `confidential.py` `reserve`, `settle`; `confidential_ws.py` |
| The four proofs' cost profile (π_C1/π_C2/π_C3 ≈ 0.47 s local / ≈ 1.53 s WAN and ≈ 1.6 MB each; π_N ≈ 0.09 s / 0.76 s and ≈ 0.95 MB; ≈ 5.9 MB per session both directions; added TTFT ≈ +1.1 s cold, +0.25–0.3 s pre-warmed reference client) | paper §6.2 |

**Venice-specific (must be re-established per provider):**

| Piece | Venice value | Where pinned |
|---|---|---|
| Head template: path `/api/v1/chat/completions`, `Host`, `Authorization: Bearer {KEY:42}` | Venice path + 42-char key | `main.rs` `default_head_template_for`; offer `head_template` |
| Suffix key set | `model,max_tokens,max_completion_tokens,n,stream,stream_options,venice_parameters` | SPEC §5.0/§5.5; `main.rs` `canonical_suffix` |
| Duplicate-key last-wins + escaped-key normalization + strict-schema 400s | Tested for Venice only | VENICE-TESTS |
| `venice_parameters` semantics (system prompt, web search billing) | Venice-only fields | VENICE-TESTS |
| Usage event shape: last `data:` event before `[DONE]`, `choices:[]`, `usage{prompt_tokens,completion_tokens[,prompt_tokens_details]}`, **`cost{usd,diem}`** | Venice format | VENICE-TESTS; SPEC §5.7 |
| `cost` object as ground-truth billing | Venice-only (OpenRouter has an analogue, §2.4) | VENICE-TESTS |
| TLS behaviour: KeyUpdate accepted mid-request, `update_requested` honoured mid-stream, ALPN `http/1.1` | Tested for Venice only | VENICE-TESTS "TLS"; SPEC §3 |
| "No raw CR/LF inside SSE events" (R-anchoring invariant) | Tested for Venice, incl. adversarial model output | VENICE-TESTS "Adversarial model output"; SPEC §5.7 step 3 |

### 2.2 The provider profile — checklist (critique and extension of SPEC §7)

SPEC §7 lists six upstream requirements. They are correct but incomplete.
Reproduced and extended (**C1–C6** are the SPEC's, sharpened; **C7–C12** are
new):

- **C1 (SPEC §7.1).** TLS 1.3 with AES-128-GCM offered to a restricted client;
  **client KeyUpdate accepted mid-request** and `update_requested` honoured
  mid-stream. *Sharpening:* the test must cover the exact choreography
  (KU → appdata → KU → body), not just "KeyUpdate accepted" — Venice was
  tested exactly this way with the Reclaim client (VENICE-TESTS "TLS" row 5).
- **C2 (SPEC §7.2).** HTTP/1.1 with `Connection: close`; server honours
  `Accept-Encoding: identity` (no gzip/br on the SSE stream — compression would
  destroy the plaintext anchoring π_C3 relies on); ALPN `http/1.1` selectable.
  An h2-only endpoint is disqualifying (record-level tricks need record
  boundaries to align with HTTP framing as the client controls it).
- **C3 (SPEC §7.3).** JSON parser keeps the **last** duplicate key (including
  after escape normalization), rejects malformed JSON and unknown fields.
  *Sharpening:* for **gateway** providers that parse and re-serialize the body
  (OpenRouter, LiteLLM-style proxies), the semantics of the *re-serializer* are
  what matters, not the origin model's parser — a gateway that dedupes
  keeping the *first* occurrence silently defeats the suffix. This must be
  tested on the wire, not read from docs.
- **C4 (SPEC §7.4).** Every cost-relevant parameter is suffix-overridable, and
  the set of cost-relevant parameters is *enumerable* (strict schema helps).
- **C5 (SPEC §7.5).** Streaming usage via `stream_options.include_usage` (or
  equivalent) emitted as the **last** data event before `[DONE]`.
- **C6 (SPEC §7.6).** A per-provider regression suite for C1–C5 is maintained.
- **C7 (new).** *All* cost drivers are token-bounded by pinned parameters **or
  pinnable off**: per-call billed features (web search, code execution,
  retrieval, hosted tools), non-token surcharges (`service_tier`/priority
  tiers), routing/fallback that changes the effective model or price. If a
  billed feature is enabled by a *private-part* field the client legitimately
  controls (e.g. `tools`), and cannot be disabled by a suffix key, the profile
  fails (duplicate keys can overwrite a value, never delete a key — the only
  available pin is an overriding empty value like `"tools":[]`, which itself
  needs a behaviour test).
- **C8 (new).** The usage event carries the **served model** (for the §1.5
  cross-check) and token counts; ideally also the **billed cost** (Venice
  `cost`, OpenRouter `cost`/`cost_details.upstream_inference_cost`), which
  lets settlement track the real bill instead of trusting a static price list.
- **C9 (new).** Static credential in a fixed header at a fixed offset with a
  fixed length/alphabet (π_N needs the template + alphabet proof). API keys in
  a header (`Authorization: Bearer`, `x-api-key`, `api-key`) work. **Request-
  dependent credentials do not**: AWS SigV4 signs the *body hash*, so the
  credential cannot live in a node-written head without the node seeing the
  body — Bedrock is out by construction. Short-lived OAuth tokens (Vertex)
  work mechanically but are an ops burden (template length changes, rotation).
- **C10 (new).** Input-side cost is bounded by the reservation: the node
  reserves the model's full context at the input rate (§3.2), so this item
  needs only that the provider's context limit is known per model. Restricting
  the offer to models that reject multimodal parts (as the Venice offer does)
  remains a conservative choice (§3.4).
- **C11 (new).** SSE hygiene compatible with `R` anchoring: no raw CR/LF
  inside event payloads (JSON string escaping guarantees this for `data:`
  lines — tested adversarially for Venice), and any SSE *comment* lines
  (e.g. OpenRouter's `: OPENROUTER PROCESSING` keepalives) must be tolerated
  by the `R` dechunker/parser. Mid-stream error events (`data: {"error":…}`)
  are acceptable: they mean no usage event, which routes to the abort path
  (SPEC §5.8), not to a wrong settlement.
- **C12 (new).** A machine-readable, stable per-model price surface for the
  offer's `price_list`, plus a monitoring hook comparing billed cost vs price
  list (alias detection, §1.6 row 11).

**Providers that fail structurally (different design, not a profile):**
h2/gRPC-only APIs (Vertex AI gRPC transport), body-signing credentials
(Bedrock SigV4), providers without any streaming usage event and no other
server-signed usage oracle. Fallbacks in §2.6.

### 2.3 OpenRouter — assessment against the checklist

| Item | Status | Notes |
|---|---|---|
| C1 TLS 1.3 + KeyUpdate | **Unknown — testable.** | OpenRouter is Cloudflare-fronted; Venice (also Cloudflare/GTS, VENICE-TESTS "TLS") passed. The same 30-minute test applies: `openssl s_client` `k`/`K` mid-request, then the full Reclaim-client choreography. |
| C2 HTTP/1.1 + identity | **Known-good, verify on wire.** | OpenRouter's API is plain REST/SSE and works with HTTP/1.1 clients; compression behaviour of the SSE stream must still be observed (C2 test). |
| C3 duplicate keys | **Unknown — the critical gateway question.** | OpenRouter is a *gateway*: it parses the body and forwards a re-serialized request to the selected upstream. Whether duplicates survive, and which occurrence wins after re-serialization, is a wire test only (§2.2 C3). If first-wins, the suffix mechanism fails outright for OpenRouter. |
| C4/C7 cost-parameter surface | **Larger than Venice; enumerable.** | Beyond the OpenAI keys: `provider` routing preferences (`order`, `allow_fallbacks`, `sort`, `ignore`), a `models` fallback array, `plugins` (the web plugin bills per search), `transforms` (middle-out compression changes prompt tokens), `reasoning` (token-bounded), `usage:{include:true}`. All are JSON fields, hence pinnable by the suffix **if** C3 holds. Routing/fallback must be pinned to a single provider with no fallback, otherwise the served model legitimately differs from the requested one and the §1.5 model check would fail honest sessions (or worse, priced differently). |
| C5/C8 usage event | **Known-good (documented).** | OpenRouter supports `stream_options.include_usage` and `usage:{include:true}`; the final chunk carries `usage` with `prompt_tokens`/`completion_tokens`, `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`, **`cost`** and **`cost_details.upstream_inference_cost`** — richer than Venice and directly usable for ground-truth settlement (C8). It also documents the served-model field on chunks. |
| C9 credential | **Known-good.** | `Authorization: Bearer sk-or-…` static key; alphabet within `[A-Za-z0-9_-]`; length is a profile constant to measure. |
| C11 SSE hygiene | **Needs parser work, not a redesign.** | OpenRouter interleaves `: OPENROUTER PROCESSING` comment lines; the `R` validator must skip comment lines when locating the last data event. Mid-stream `data: {"error":…}` events route to the abort path (C11). The no-raw-CR/LF invariant holds by JSON escaping but must be re-verified on the wire. |
| C10 amplification | **Bounded by the full-context reservation**, as for Venice; OpenRouter-specific billed plugins must be pinned off, which works if C3 holds. | |
| C12 pricing | **Known-good.** | OpenRouter publishes per-model pricing; `cost` in the usage event gives the realized bill. |

**Verdict for OpenRouter:** the most promising second provider — the usage/cost
event is *better* than Venice's. Two wire tests are decisive: duplicate-key
semantics through the gateway (C3) and KeyUpdate mid-request (C1). If C3 fails
(first-wins re-serialization), the suffix design does not transfer and the
fallback is §2.6.

### 2.4 Groq, together.ai, OpenAI, Anthropic — shorter assessments

**Groq.**
C2: HTTP/1.1 REST, fine. C5: OpenAI-compatible streaming; usage-in-stream
support must be confirmed on the wire (documented for the API generally —
*unknown until tested*). C8: usage event has token counts but **no cost
object** — settlement prices from the node's price list (acceptable; Groq's
pricing is public and simple). C3: duplicate-key behaviour **unknown —
testable** (their backend's JSON parser; also confirms strictness — Groq 400s
on unsupported fields like `n>1`, which is encouraging for C4). C7: cost
surface is small (no hosted billed tools in chat completions); `service_tier`
variants if offered must be pinned. C1: **unknown — testable** (same test as
always). C9: static Bearer key, fine.
**Verdict:** plausible profile; cheaper to test than OpenRouter because the
cost surface is small. Blocking unknowns: C1, C3, C5-on-the-wire.

**together.ai.** Same shape as Groq: OpenAI-compatible, HTTP/1.1, static
Bearer key, no cost object in usage (node price list). Blocking unknowns: C1,
C3, and the exact final-event format (C5). No hosted billed tools in the chat
completions path, so C7 looks satisfiable.

**OpenAI (api.openai.com).**
C5/C8: `stream_options.include_usage` is supported; the usage chunk is the
last data event with `choices:[]` — matches the Venice anchoring shape; **no
cost object** (price list needed). C2: HTTP/1.1 works against the API.
C1: **unknown — testable.** C3: **unknown — testable** (parser strictness
matters doubly here: a lenient schema lets the client add *known but unpinned*
cost fields, and OpenAI's known-field surface is large). **C7 is the problem:**
hosted tools
(`web_search_preview`, code interpreter, file search) are billed **per call**
and are enabled via the private `tools` field, which the suffix cannot remove
— the only candidate pin is an overriding `"tools":[]`, whose effective
behaviour is *unknown — testable*. If it doesn't reliably disable hosted
tools, the profile must either exclude models/modes with hosted tools or
accept an unbounded reservation (unacceptable, §3.4). Also `service_tier:
"priority"` is a billed tier that must be pinned (pinnable — it's a plain
field). **Verdict:** transferable *conditionally*, gated on the `tools:[]`
semantics test plus C1/C3; otherwise offer only tool-free sessions on OpenAI.

**Anthropic (api.anthropic.com and Anthropic-compatible gateways).**
Fails C5-as-written, needs a **profile variant**, not just a profile:
- Streaming usage is **split**: input tokens arrive in the `message_start`
  event (beginning of stream), output tokens in `message_delta`
  (`usage.output_tokens`, near the end), terminated by `message_stop` — there
  is no single final usage event. π_C3's current statement anchors `R` at the
  transcript **end** (`statements.rs` `build_pi_c3`; tail-record selection
  in the `main.rs` `Disclose` handler). An Anthropic profile needs *two* disclosed ranges (head
  `message_start` + tail through `message_stop`), i.e. a modified π_C3
  statement — moderate design change, same cryptography.
- Suffix keys differ (`max_tokens` is *required* — good for pinning; no
  `stream_options`; web search/fetch are server-side billed tools toggled in
  the request — same C7 problem as OpenAI, needs a pin test).
- Credential is `x-api-key` + a required `anthropic-version` header — the
  head-template mechanism handles this unchanged (C9 OK).
- C1/C2/C3: unknown — testable.
**Verdict:** portable with a per-provider π_C3 variant; not a drop-in.

**Structural non-candidates (need a different design, not a profile):**
AWS Bedrock (SigV4 signs the body hash — the credential is request-dependent,
violating C9 fundamentally); gRPC/h2-only transports (Vertex AI gRPC). For
these, the answer is §2.6.

### 2.5 The HTTP/1.1 + KeyUpdate landscape

The record-level choreography requires HTTP/1.1 (record boundaries the client
controls) and no response compression (C2). Current landscape:

- **Verified:** Venice (VENICE-TESTS "TLS": KeyUpdate accepted mid-request,
  `update_requested` honoured mid-stream, ALPN `http/1.1`; HTTP/1.1 +
  `Connection: close` + `Accept-Encoding: identity` throughout the test
  suite).
- **HTTP/1.1 available (known), KeyUpdate untested:** OpenRouter, Groq,
  together.ai, OpenAI, Anthropic, Azure OpenAI, Google AI Studio (Gemini REST)
  all serve plain HTTP/1.1 REST/SSE. For every one of them, KeyUpdate
  mid-request is **unknown — testable in under an hour** with the exact
  VENICE-TESTS procedure (`openssl s_client -alpn http/1.1`, `k`/`K`
  commands, then the Reclaim-client KU→Authorization→KU→body sequence). The
  fact that Venice passes while sitting behind Cloudflare/GTS is mildly
  encouraging for other Cloudflare-fronted providers, but middleboxes are
  per-property: treat as open.
- **h2-only / gRPC:** Vertex AI's gRPC transport and similar — disqualifying
  (C2 fails).

### 2.6 Fallbacks when the checklist fails

1. **MPC-TLS variant (SPEC §9, "Design A").** Same trust properties with the
   roles flipped (C = TLSNotary prover, N = verifier; API key is N's private
   input). Works over TLS 1.2, needs no KeyUpdate and no suffix semantics —
   the request is proven directly. Cost: measured 5.8 s / 41.5 MB at 2 KB,
   34 s / 377 MB at 32 KB, 129 s / 1.44 GB at 128 KB, and **no live
   streaming** (SPEC §9 measurements, tlsn @4415391, M2 Max). Suitable for
   small-prompt providers that fail C1–C3 but still have a usable usage
   response (usage disclosure via TLSN selective disclosure).
2. **The existing non-confidential path.** routstr-core's current proxy
   (`WIRE-UP §1.1`, pattern 5/13): node sees the prompt, optional TLSN
   verification rail. This is the honest answer for providers failing C2/C7/
   C9 structurally (Bedrock, gRPC): the confidential path should simply not be
   offered for them, with fail-closed client behaviour per WIRE-UP §4
   ("requested-but-unavailable must fail closed by default").
3. **No third option is claimed.** A provider without a server-emitted usage
   oracle of any kind cannot give P4 (verifiable accounting); the design
   correctly does not pretend otherwise.


---

## Q3. Does the node see the prompt? What does it know about size? Reservation economics

### 3.1 Information flow — exactly what N knows at each stage

| Stage | N learns | N never learns |
|---|---|---|
| Setup | `model`, `max_tokens`, `LEN`, `nonce_C`, the client's credential (validated by the node, not forwarded to the sidecar), the signature of the offer the client verified; `sid` | — |
| Handshake | Full handshake transcript; cert chain/hostname/CertificateVerify/Finished verified from the disclosed *handshake* traffic secrets. Application secrets are underivable from these | `HS`, all `*_ap_*` secrets |
| Epoch 0/1 | `\|head\|` (its own template), keystream material `S, H1, T0` for epoch-1 seq 0 (recovering `K1` from it is AES key recovery), the head plaintext `P` (it wrote it), the credential record ciphertext; from π_C1 only the material itself | `K1`, `c_ap_1`, `c_ap_2`; the credential record is never forwarded to C (P1) |
| Body | Record count, each record's ciphertext length (⇒ total body size = `LEN` + framing, consistent with the `Content-Length` N itself wrote), timing; the **suffix** (public, built by the sidecar); π_C2's one-bit result | `body_private`, i.e. the prompt and any tools; π_C2 decodes no decrypted byte, even when it fails |
| Response | Ciphertext, record boundaries (the token-length sequence of a stream), total length, timing, close time; signs the attestation over hashes | All response plaintext (P2) |
| Settlement | Either `R` = usage event + `[DONE]` + chunk framing (⇒ **actual** `prompt_tokens`, `completion_tokens`, served model, Venice `cost`), or for an upstream error only the response head: status line and headers, plus the body length as `skip`. Bound to the wire by π_C3, whose comparison yields one bit | Everything outside `R`, including the error body |

So: **no, the node does not see the prompt** (P2). The proofs that decrypt
under C's keys reveal one equality bit, and C validates their parameters
against its own records (`params.ts`), so the node cannot point them at other
plaintext. **Yes, the node knows the input size exactly**: `LEN` is declared
at setup, written by N into `Content-Length`, and visible as ciphertext length.
N needs it for the `Content-Length` header it writes, not for pricing: the
reservation does not depend on it (§3.2).

**Traffic analysis.** N sees body length, the size of every response record,
timing, and at settlement the exact token counts. Streaming providers emit one
record per token or small token group, so the record sizes form the response's
token-length sequence, a side channel known to reconstruct a large share of
LLM responses (paper §5, residual risk 2). Against the existing Routstr design,
where the node sees plaintext, this is strictly less exposure; against "the
node sees ciphertext only", it is more than volume and timing. C cannot pad
the provider's records; the prompt side can be padded inside the JSON body.
The model identity is not private (N priced it).

### 3.2 Reservation sizing

The prompt is opaque to the node, so the reservation never discounts it
(`confidential.py` `reserve`):

- `reserved = max(min_request_msat, ⌈(prompt_limit · in + max_tokens · out) / 1000⌉)`
  msats, at the per-1k rates of the signed offer the client verified (frozen
  for the session by `offer_sig`). `prompt_limit` is the model's context
  length (`prompt_token_limit`). It is deliberately *not* the visible-body
  helper's "context minus the model's completion limit": the pinned cap is
  usually far below that limit, so the provider accepts a prompt of up to
  context − cap tokens, and the capped charge would leave the difference
  unbilled. Without a known context length the node
  reserves the model's undiscounted maximum cost; fixed-pricing deployments
  keep their per-request reservation.
- Example (2026-10-10, `deepseek-v4-flash`): `prompt_limit` 104,858 tokens at
  21.16 msat/1k plus 40 × 1565.58 msat/1k → **2,282 msats** reserved; the
  session cost 63 msats.
- **Completion side:** exactly bounded. The suffix pins `max_tokens` **and**
  `max_completion_tokens` to `T ≤ max_tokens_cap` (the cap is checked by the
  node and in `handle_setup`; the dual pin exists because Venice otherwise lets
  `max_completion_tokens` override `max_tokens`). Reasoning tokens count toward
  completion tokens (provider-profile A6). Small overshoots on tiny caps
  (3 → up to 6 observed) fall well inside the full-context prompt side.
- **Prompt side:** the full context window, so prompt size, images or file
  references need no separate bound. The Venice system prompt is pinned off in
  the suffix so the provider does not add tokens of its own.
- **Prepaid, because nothing better exists.** Even with the prompt visible, a
  node cannot know the token count before the upstream tokenizes it; routstr's
  ordinary flow already reserves the maximum and settles the actual cost. The
  confidential path keeps that shape and changes only who can read the prompt.
- **Client side.** The SDK deposits for the same full-context amount
  (`sats_pricing.max_prompt_cost` + completion × `max_tokens`, 5% margin,
  capped at `max_cost`), so a fresh Cashu credential covers the reservation.

### 3.3 Settlement, aborts, and who pays what

- **Happy path.** π_C3-verified usage → `cost = ⌈(in·(prompt − cached) +
  min(cached_in, in)·cached + out·completion)/1000⌉`, capped at the
  reservation (`frozen_cost_msats`), finalized through the node's existing
  path; the rest of the reservation stays on the credential. A zero cost
  releases the reservation. The client checks `cost ≤ usage × signed rates`,
  which holds exactly because the node charged at those rates.
- **Abort before the final body record is released** (including a failed or
  withheld π_C2, or any refusal at setup): the upstream never received a
  complete request, so the reservation is released.
- **Upstream HTTP error** (400, 429, 503 …): C discloses only the response head
  under π_C3 (`validate_error_head`); the body stays private. 4xx and 503 →
  reservation released; other 5xx → reservation charged (the provider may
  have billed work).
- **Abort after release, no usage event** (client abort, mid-stream error): the
  node charges the reservation. This is self-punishing for a malicious client
  and covers N's outlay if Venice bills partial generation.
- **Settlement failure** (a database error): the node finalizes exactly once,
  charging the reservation if the request reached the provider and releasing
  it otherwise, and sends an error frame.
- **Receipt.** Signed (BIP-340 Schnorr over the canonical receipt JSON):
  `v, sid, model, usage, cost_msats, reserved_msats, balance_msats, rates,
  notary_pubkey, attestation_hash, time`. The client requires the signature,
  reads every field from the signed bytes, and checks `sid` and
  `attestation_hash = sha256(a_json)` against its own session. Unused balance
  is withdrawn with the node's ordinary `/v1/wallet/refund`.

### 3.4 The failure mode: actual cost exceeds the reservation

If the provider's cost exceeded the reservation, the node would absorb the
difference. Every cost driver must therefore be bounded by what the
reservation priced: `(setup model, full context, max_tokens, pinned params)`.

| Cost driver | Bounded by | Status |
|---|---|---|
| Model / cap swapped, or suffix withheld | final body record held until π_C2 verifies | **Sound** (gate cases a, d, e, f: refused or withheld, released) |
| Output tokens (incl. reasoning) | `max_tokens` + `max_completion_tokens` pins; small overshoots on tiny caps fall inside the full-context reservation | **Sound** (provider-profile A6) |
| `n > 1` | `"n":1` pin | **Sound** (Venice 500s otherwise) |
| Venice system prompt | `include_venice_system_prompt:false` pin | **Sound** (A7: 224-byte request billed 6 prompt tokens) |
| Web search (≈4.6k tokens/call) | `venice_parameters.enable_web_search:"off"` pin; the whole `venice_parameters` object is replaced by the suffix | **Sound** (tested: 4675 → 16) |
| Huge prompt | reservation covers the full context window | **Sound** (by construction) |
| Cached tokens | cheaper, not dearer | **Sound** |
| Schema-novel cost fields | strict-schema 400s (sampled, A4/A10) + per-provider regression gate | **Sound, maintained** |
| Multimodal amplification | full-context reservation; the offer also lists only models that reject image parts | **Sound** (`regression-modality.py`, `image_url` and data URI, 8/8) |
| Alias/routing to a dearer backend | ops monitoring vs Venice `cost` (§1.6 row 11) | **Unknown — testable** |

### 3.5 Q3 verdict

- The node never sees the prompt or the response; the decrypting proofs reveal
  one bit each, on parameters the client has checked. It knows the prompt's
  **byte size exactly** and its **token count only at settlement**, from the
  upstream's own proven usage event; on an upstream error it learns the status
  line, the response headers and the body length.
- The reservation is the full-context maximum at the signed rates, because the
  prompt is opaque and token counts are unknowable before tokenization; the
  settlement charges the provider-reported usage at the same rates.
- The cost cannot exceed the reservation for any of the drivers above except
  model aliasing, which is an operational check, not a protocol property.

---

## Appendix A — GAP summary

| ID | Status | One-liner | Where it is closed |
|---|---|---|---|
| GAP-1 | **CLOSED** | The suffix (incl. `model`) was client-supplied and not bound to the setup values | `crypto/relay/src/main.rs`: `handle_setup` stores model/max_tokens in `Session`; `BodySuffix` handler requires byte-equality with `canonical_suffix`; final body record held until π_C2 verifies. Node-side reservation in `confidential.py` `reserve`. Gate case `a-suffix-mismatch`. |
| GAP-2 | **CLOSED** | The usage-event model was not checked against the session model | `main.rs` `Disclose` handler (usage `model` must equal the setup model); `confidential_ws.py` `_apply_settlement` (mismatch → reservation charged). |
| GAP-3 | **CLOSED** | The `LEN`→token prompt bound broke under image token amplification | Full-context reservation (`confidential.py` `reserve`, `prompt_token_limit`); the offer lists only text-only models, enforced at setup (`text_only_ok`) and by `regression-modality.py`. |
| GAP-4 | **CLOSED** | A client could withhold or swap the suffix after the body reached the provider | `main.rs` `Body` state holds the record that completes the body until π_C2 verifies. |

## Appendix B — Citation index

- Model choice & reservation: SPEC §5.0–5.1; `confidential.py` `reserve`; `main.rs` `handle_setup`
- Suffix semantics & last-duplicate-key: SPEC §5.5; VENICE-TESTS; provider-profile A2–A5; `main.rs` `canonical_suffix`
- π_C2 statement/public inputs: `statements.rs` `Window`, `build_pi_c2`, `eq_bytes` (in-circuit equality); `main.rs` `BodySuffix` handler; client checks in `params.ts`
- π_C3, `R` validation, settlement: `statements.rs` `PiC3`, `build_pi_c3`; `main.rs` `Disclose` handler, `validate_r`, `validate_error_head`; `confidential_ws.py` `_apply_settlement`; `confidential.py` `settle`, `frozen_cost_msats`
- Head template / π_N / endpoint pinning: SPEC §5.4; `main.rs` `default_head_template_for`, `placeholder_head`, `assemble`; `statements.rs` `build_pi_n`
- Aborts & non-disclosure: SPEC §5.8; `confidential_ws.py` `_finalize`, `_finalize_unsettled`
- Provider requirements & fallback: SPEC §7, §9; `crypto/tools/provider-profile-check.py`
- Benchmarks: paper §6.2
- Known prior art on model-swap risk in the non-confidential rail: `docs/original/REPLY-to-red.md` item 2 ("upstream_models comes from the node, so a node can make a cheap-model swap look verified") — the threat class GAP-1 belongs to, previously flagged for the TLSN rail.

## Appendix C — Historical prototype analysis (2026-10-09, before integration)

The first version of this document reviewed the standalone prototype, whose
sidecar settled with a stub escrow. Its findings are kept here; none applies
to the integration branches, and its line numbers referred to a prototype
revision of `main.rs` that no longer exists.

- **GAP-1 (HIGH).** The prototype's `Setup` carried `model` and `max_tokens`,
  but the session discarded the model; `BodySuffix` was hex-decoded and used
  verbatim as π_C2's `expected`. A client could reserve for a cheap model, put
  an expensive one in the suffix and still pass π_C2. The proposed fix
  (store the setup values, rebuild the canonical suffix on N's side, price on
  N's side) is what the integration implements (Appendix A).
- **GAP-2 (MEDIUM).** The prototype's `validate_r` checked chunk framing, the
  terminator, empty `choices` and the token counts, but not the usage model;
  its stub `settle()` defaulted a missing model to a fixed string.
- **GAP-3 (HIGH if vision models were offered).** The prototype's escrow
  bounded the prompt by body bytes (`prompt_tokens ≤ LEN` plus a margin, at
  the `in` rate). A probe confirmed that a ~50-byte `image_url` can expand to
  over 1,000 prompt tokens on vision models (`crypto/runs/modality/`), which
  breaks that bound. The integration reserves for the full context instead and
  offers only models that reject image parts.
- **Escrow stub.** `escrow_e` was a client-declared integer hashed into `sid`
  and never priced; settlement used Venice's own `cost.usd` against a
  hard-coded pseudo-escrow. The node's ordinary reservation replaced it.
