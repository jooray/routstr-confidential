# Adversarial Q&A — routstr confidential upstream

*2026-10-09. Adversarial review of the confidential-upstream protocol against three
questions: (Q1) model-name binding to escrow, (Q2) transferability beyond Venice,
(Q3) what the node learns and how escrow economics close. Every specific claim is
grounded in the documents and prototype code listed below; anything not verifiable
from them is marked **unknown** together with the test that would settle it.*

**Sources.** Citations are into this repository; `docs/original/*` are the
authors' working documents and are not published:

- `SPEC` — `docs/original/SPEC-confidential-upstream.md` (protocol contract, v0.1)
- `PLAN` — `docs/original/PLAN-confidential-upstream.md` (implementation contract)
- `WIRE-UP` — `docs/original/WIRE-UP-confidential-upstream.md` (integration spec)
- `VENICE-TESTS` — `docs/original/VENICE-TESTS.md` (verified upstream behaviour)
- `PROGRESS` — `docs/original/PROGRESS.md` (prototype status + invariant self-check)
- `BENCH` — `docs/original/BENCHMARK-keyupdate.md` (measured proofs + latency)
- Code: `crypto/relay/src/main.rs` (sidecar), `crypto/zkbench/src/statements.rs`
  (ZK statements), `crypto/client/src/driver.ts` (client driver)

> **Current state (integration branches).** The analysis below was written
> against the prototype; its gaps (GAP-1…4) are closed. In the implementation
> now:
>
> - **Q1, model binding.** The node builds the canonical suffix from the setup
>   values. The sidecar holds the record that completes the body until π_C2
>   proves the suffix, so the provider never sees a complete request with
>   another model or cap. The disclosed usage must name the setup model.
> - **Q3, money.** There is no protocol-specific escrow. The client
>   authenticates with its ordinary node credential (API key or Cashu token).
>   The node reserves the model's maximum cost with its normal
>   `pay_for_request`, sized like any request whose prompt it cannot read (a
>   full context window on the prompt side, the pinned cap on the completion
>   side). It charges the π_C3-verified usage with `adjust_payment_for_tokens`.
>   It releases the reservation if the provider never received the request or
>   answered a 4xx/503, and charges the reservation if the client withholds its
>   disclosure.
> - **Q3, the prompt.** The node sees only ciphertext, as before.
>
> The provider assumptions are re-checked live by
> `crypto/tools/provider-profile-check.py` (10/10 for Venice). Read "escrow"
> below as "the node's reservation".

---

## Q1. Can the client change the model name? Is it verified by the node?

### 1.1 Where the model appears in the protocol

There are exactly four places the model string exists, plus one place it must
never appear:

1. **Setup (plaintext to N).** "C chooses `model`, `max_tokens` (≤ cap) and the
   body length `LEN`" (SPEC §5.1 step 1). Escrow is computed from this choice:
   `E = price(model, LEN_upper_bound_tokens, max_tokens)` (SPEC §5.1 step 2).
   The node therefore *knows* the escrowed model — model identity is not private
   between C and N, by design.
2. **The request body (ciphertext to N).** The body is
   `body_private ‖ suffix` under `c_ap_2`, a key N cannot derive (SPEC §5.5,
   §6 row P2). Both `body_private` and the suffix may contain a `"model"` key.
   N never sees either in plaintext.
3. **The public suffix (plaintext to N, proven in ZK).** The suffix is the
   byte string `,"model":"<M>","max_tokens":<T>,…}` (SPEC §5.5). It travels on
   the control channel as `body_suffix` (PROGRESS, invariant I2: "`/session`
   carries only … `body_suffix` (public)") and is a **public input** to π_C2
   (`crypto/zkbench/src/statements.rs:103-108`, the `Window.expected` field).
4. **The upstream usage event (disclosed at settlement).** Venice's final SSE
   event carries `"model":"mistral-small-3-2-24b-instruct"` alongside `usage`
   and `cost` (VENICE-TESTS, "Final streaming events"). It is disclosed as part
   of `R` and bound to the server ciphertext by π_C3 (SPEC §5.7 steps 1–2).
5. **Never in the head.** N writes the request head; the head template contains
   the path, host, Authorization, and `Content-Length` — but no model
   (`crypto/relay/src/main.rs:60-62`). So N cannot inject or alter the model,
   and the model cannot be used to smuggle data into N's record.

**Effective-model semantics.** Venice keeps the *last* value of duplicate JSON
keys, normalizes escaped keys, and rejects malformed JSON and unknown fields
with 400 (SPEC §5.5; VENICE-TESTS "Duplicate keys and malformed JSON"). Since
the suffix is the last bytes of the body, the suffix's `"model"` is the
effective one. This is not assumed — it is tested: the `--decoy-model
google-gemma-3-27b-it` regression runs the full protocol with a decoy model in
the private part and confirms the effective model is the suffix model
(PLAN phase 7; PROGRESS phase 7 ✅; BENCH §3, "Decoy regression";
`crypto/client/src/driver.ts:112`).

### 1.2 The attack

Escrow is priced per model (SPEC §5.0 `price_list`). A malicious client wants
inference from a 100× more expensive model than the one it escrowed for:

1. At setup, declare `model = cheap`, escrow `E = price(cheap, …)`.
2. In the body, make the *effective* model `expensive` — either by putting
   `"model":"expensive"` in the private part (relying on it not being
   overridden) or by putting it in the suffix itself.
3. Settle. If the node prices `cost = price_list(cheap, usage)` — or prices
   correctly but `cost(expensive, usage) > E` — the node pays Venice more than
   it collected. The node loses `cost − E`.

For this to work, the attacker must break **at least one** of three bindings:
(i) suffix model vs setup model, (ii) effective model vs suffix model,
(iii) charged model vs effective model. We take them in turn.

### 1.3 Binding (ii): effective model ≡ suffix model — SOUND (tested)

- The private part cannot win: last-duplicate-key semantics, including escaped
  keys, verified on real Venice (VENICE-TESTS rows 1–3; decoy regression
  end-to-end, BENCH §3).
- The client cannot smuggle the suffix out of reach of the parser: unterminated
  strings, trailing garbage after an early `}`, an unclosed `messages` array,
  `NaN`, trailing commas and comments all yield 400s, i.e. no inference happens
  and no usage event exists (VENICE-TESTS "malformed JSON" rows; abort
  economics in §3.4 below make this self-punishing for the client).
- π_C2 proves, in ZK, that the last `|suffix|` bytes of the epoch-2 plaintext
  equal the public suffix (SPEC §5.5; `statements.rs:291-310`; verified against
  real Venice, PROGRESS phase 4). The proof anchors to the session key
  schedule, so it cannot be replayed from another session (PLAN §2,
  `key_schedule_zk`; `statements.rs:195-231`).
- The client cannot choose the suffix *after* seeing anything useful: the
  suffix is fixed at `body_suffix` time, but π_C2 proves equality against the
  body ciphertext that was **already relayed and logged** before that
  (`crypto/relay/src/main.rs:644-664` reads the last body record from the relay
  log). There is no time-of-check/time-of-use gap between the proven suffix
  and the body.

So the effective model is always the suffix model. The entire question reduces
to: **is the suffix model bound to the escrowed (setup) model?**

### 1.4 Binding (i): suffix model ≡ setup model — **GAP-1 (HIGH) in the prototype; a spec-precision issue in SPEC**

This is where the design has a real hole.

**What the SPEC intends.** SPEC §5.5 says "The suffix is fixed by the offer"
and shows the template with `<M>` and `<T>` — the `model` and `max_tokens`
chosen at setup (§5.1). The clear intent is that the suffix is a *deterministic
function of the offer and the setup values*, both of which N knows. If so,
binding (i) holds by construction: N reconstructs the suffix byte-for-byte and
uses it as π_C2's public input; a client that puts any other model in the
suffix simply fails π_C2 verification.

**What the SPEC fails to say.** Nowhere does SPEC state that the suffix is an
*agreed* public input reconstructed (or validated) by the node. §5.5's π_C2
paragraph says only "C proves that the last |suffix| bytes of the epoch-2
plaintext equal the suffix". PLAN §2 makes `suffix` a public input to π_C2 but
likewise does not say who computes it.

**What the prototype does.** The suffix is **client-supplied and never checked
against setup**:

- `Setup` carries `model` and `max_tokens`
  (`crypto/relay/src/main.rs:244-245`), but the handler only checks
  `max_tokens ≤ max_tokens_cap` (`main.rs:556-559`) and then **discards the
  model** — the `Session` struct has no `model` or `max_tokens` field at all
  (`main.rs:502-517`).
- `BodySuffix` is hex-decoded and used verbatim as π_C2's `expected` public
  input (`main.rs:644-664`). No byte of it is compared to the setup values.
- The honest client builds the suffix correctly from its own `--model`
  (`crypto/client/src/driver.ts:106-110`), which is why all tests pass — but a
  malicious client need not.
- The escrow itself is a stub: `escrow_e` is a client-declared `u64` that is
  only hashed into `sid` (`main.rs:244-247, 564-566`); nothing prices it.
  Settlement is explicitly a stub using Venice's own `cost.usd`, with a
  hardcoded 1000-diem pseudo-escrow (`main.rs:912-938`, comment at
  `main.rs:915-916`; PROGRESS phase 5 "stub pricing").

**Consequence.** Against the prototype as written, a client can escrow (in the
real system: prepay) for `mistral-small-3-2-24b-instruct`, put
`"model":"venice-uncensored"`-or-anything in the suffix, pass π_C2, and have
the expensive model run. In the *production* settlement described by SPEC
§5.7 step 4 (`cost = price_list(model, usage)`), two readings both lose:

- If `model` means the **setup model**, the node charges the cheap rate while
  paying Venice the expensive one — direct theft, bounded only by LEN and
  max_tokens.
- If `model` means the **usage-event model** (what the prototype's `settle()`
  actually does, `main.rs:921-925`), the charge tracks reality, but
  `cost > E` is now possible and `refund = E − cost` goes negative — the node
  eats `cost − E` (the prototype caps the refund at 0, `main.rs:932`, which
  confirms the node absorbs the excess).

Either way, the escrow economics Q1 asks about are broken **unless the suffix
is bound to setup**.

> ### **GAP-1 — suffix is not bound to the setup model/max_tokens (HIGH)**
>
> **Where.** SPEC §5.5 (ambiguity: who fixes the suffix); prototype
> `crypto/relay/src/main.rs:502-517` (Session drops `model`), `main.rs:644-664`
> (`BodySuffix` accepted unvalidated), `main.rs:556-579` (escrow unpriced —
> stub).
>
> **Exploit.** Escrow for a cheap model; suffix with an expensive model; π_C2
> verifies (it only proves body-ends-with-client-supplied-suffix); node pays
> the difference `cost(expensive) − E`.
>
> **Fix (exact).**
> 1. `Session` must store `model`, `max_tokens`, `LEN` from `Setup`
>    (`main.rs:556`).
> 2. The node must **reconstruct the canonical suffix itself** from
>    (offer, setup) — exact bytes, the SPEC §5.5 key order and formatting —
>    and use that as π_C2's `expected`; if the client also sends `body_suffix`,
>    the handler must require byte-equality with the reconstruction and abort
>    otherwise. (This also pins `max_completion_tokens`, `n`, `stream`,
>    `stream_options`, `venice_parameters` to setup/offer values, closing the
>    whole cost-parameter surface at once, not just the model.)
> 3. SPEC §5.5 should state explicitly: *"the suffix is an agreed public input:
>    `suffix = canonical(offer.suffix_template, setup.model, setup.max_tokens)`,
>    reconstructed by N; π_C2's public input is N's reconstruction."*
> 4. In production settlement (moved to routstr-core per WIRE-UP §2.3/§6.1),
>    the **node** computes `E = price_list(setup.model, bound(LEN),
>    setup.max_tokens)` and verifies the redeemed Cashu token's amount ≥ E —
>    never trusting a client-computed `E` (WIRE-UP §4 step 5 currently says
>    "Client computes E"; the node must recompute and check).
> 5. Bind the setup parameters into `sid` (e.g.
>    `sid = SHA256(nonce_C ‖ nonce_N ‖ model ‖ max_tokens ‖ LEN ‖
>    SHA256(cashu_token))`) so the attestation/receipt chain commits to them
>    for disputes (SPEC §5.1 step 3 currently binds only nonces + token).

### 1.5 Binding (iii): charged model ≡ effective model — **GAP-2 (MEDIUM): PLAN-specified check missing from the implementation**

Even with GAP-1 fixed, settlement must not take the model from the client
anywhere. The design has the right mechanism — the upstream's own usage event:

- Venice's final SSE event contains the served `model` (VENICE-TESTS "Final
  streaming events"), disclosed inside `R` and bound to server ciphertext by
  π_C3 (SPEC §5.7; `statements.rs:312-338`).
- PLAN §5 rule (b) requires: *"the usage event must parse as JSON with
  `"choices":[]`, `usage{prompt_tokens, completion_tokens}`, and **`model` ==
  suffix model**"* (PLAN §5, line "(b)").

But the prototype's `validate_r` does **not** implement the model check: it
verifies chunk framing, the `data: [DONE]` terminator, empty `choices`, and the
presence of the two token counts — and nothing else
(`crypto/relay/src/main.rs:859-910`). Worse, `settle()` takes `model` from the
usage event with a **hardcoded fallback to `"mistral-small-3-2-24b-instruct"`**
if the field is missing (`main.rs:921-925`), so a usage event without a model
would silently be receipted as the default model.

> ### **GAP-2 — usage-event model not checked against the session model (MEDIUM)**
>
> **Where.** `crypto/relay/src/main.rs:859-910` (`validate_r` omits the PLAN §5
> rule (b) check), `main.rs:921-925` (hardcoded default). PLAN §5(b) specified
> the check; the implementation dropped it.
>
> **Exploit (post-GAP-1-fix).** Limited but real: if Venice ever serves a
> session whose usage event names a different model than requested (alias,
> silent routing, A/B), the node prices by its own assumption instead of
> failing loudly. Combined with a missing GAP-1 fix, it removes the second
> line of defence entirely.
>
> **Fix (exact).** In `validate_r` (or immediately after π_C3 verification):
> require `usage_event.model` to be present and byte-equal to the **setup**
> model (which, after fix GAP-1, equals the suffix model). Fail settlement
> otherwise (keep `E`; the client can dispute with its full plaintext). Also
> delete the hardcoded fallback in `settle()`: a usage event without a model
> is a settlement failure, not a default. SPEC §5.7 step 4 should pin down
> that `price_list(model, …)` means the *setup* model, validated against the
> usage event — never a client-reported one.

### 1.6 Remaining model-related attacks and their disposition

| # | Attack | Disposition |
|---|---|---|
| 1 | Private-part `"model":"cheap→expensive"` (decoy) | **Sound.** Last-wins, tested incl. escaped keys (VENICE-TESTS; BENCH §3). |
| 2 | Suffix model ≠ setup model | **GAP-1** — fix in §1.4. |
| 3 | Change suffix between setup and π_C2 | **Sound.** The suffix only exists as π_C2's public input; the proof checks it against the already-relayed body ciphertext (`main.rs:644-664`). No TOCTOU. |
| 4 | `max_completion_tokens` bypassing `max_tokens` | **Sound (regressed once, fixed).** Venice lets `max_completion_tokens` override `max_tokens`; pinning both in the suffix fixed it (VENICE-TESTS rows 4–5). This is exactly the class of bug that SPEC §7 item 6's per-provider regression suite exists for — the test must never be dropped. |
| 5 | `"n":3` for 3× output | **Sound.** Pinned `"n":1` in the suffix; Venice 500s on n>1 anyway (VENICE-TESTS). |
| 6 | Cost-relevant `venice_parameters` (web search, system prompt) | **Sound.** The suffix sets the *whole* `venice_parameters` object; last-wins replaces it wholesale, so nothing inside can survive from the private part (tested: web search off, 16 vs 4675 prompt tokens; VENICE-TESTS). `include_venice_system_prompt:false` pins the +1767-token system prompt (VENICE-TESTS "Final streaming events" notes). |
| 7 | Reasoning tokens inflation | **Sound (bounded).** Reasoning counts toward completion tokens and is capped by the pinned token limit (tested, VENICE-TESTS `reasoning_effort` row). Note `reasoning_effort` itself is *not* pinned — it doesn't need to be, because its cost is bounded by `max_completion_tokens`. Any future parameter whose cost is *not* token-bounded (per-call fees) **would** need pinning — see §2.2 item C7. |
| 8 | Cached-token pricing games | **Sound.** Cached tokens are *cheaper* (`cached_in` in the offer price list, SPEC §5.0; Venice reports `prompt_tokens_details.cached_tokens`, VENICE-TESTS). Pricing escrow at the uncached `in` rate is conservative for the node; settlement can refund the cached share since `cached_tokens` is inside the disclosed `R`. |
| 9 | Unknown/novel cost fields in the private part | **Sound, with maintenance burden.** Venice's strict schema 400s unknown fields (VENICE-TESTS). The residual risk is *schema evolution*: Venice adding a new cost-relevant known field. SPEC §7 item 6 (per-provider regression suite) is the mitigation; the offer's `suffix_keys` must be extended whenever one appears. |
| 10 | Endpoint swap to a differently-priced API | **Sound.** The request line (`POST /api/v1/chat/completions`) is inside N's head record, proven by π_N against the offer template (SPEC §5.4 step 5; `statements.rs:340-391`). The client cannot reach `/v1/responses`, embeddings, etc. |
| 11 | **Model aliases**: escrowed name resolves server-side to a differently-priced backend while the usage event reports the requested name | **Unknown — testable, bounded by ops.** Venice's usage event reports the requested string (VENICE-TESTS shows the requested model echoed). If Venice ever aliases across price tiers, settlement by the node's price list under-charges while Venice's bill is higher. Two mitigations already exist: (a) settle on Venice's own `cost.usd/diem × markup` (SPEC §5.7 step 4, second option) so the charge tracks the real bill — but then `E` must still cover worst-case cost, see §3.4; (b) node-side monitoring comparing realized `cost` against `price_list` per model. **Test:** for each offered model, diff Venice's `cost` against the published per-token price over a sample of requests; alert on drift. |
| 12 | Multimodal token amplification (image URL in `messages` → thousands of image tokens from ~100 body bytes) | **Not a model-string attack — it breaks the LEN→token bound, not the model binding. See GAP-3 in §3.4.** Note the test model `mistral-small-3-2-24b-instruct` is vision-capable, so this is not hypothetical for the current offer. |
| 13 | Malicious *node* downgrading the model to pocket the spread | **Sound.** The node writes only the head (no model field); the body is sealed under keys it never holds (SPEC §6 P2; `main.rs` state machine gates, PROGRESS I4/I5). It cannot alter the suffix or the private part. |

### 1.7 Q1 verdict

The model is bound at four points, and each is enforced by the node:

1. **Setup.** The node reserves the declared model's maximum cost on the
   client's credential, with the completion side at the pinned `max_tokens`.
2. **Suffix.** The node builds the canonical suffix from the setup values and
   accepts no other (GAP-1 closed).
3. **Before the upstream can start.** The sidecar holds the record that
   completes the body until π_C2 proves the body ends with that suffix.
   Last-wins makes the suffix the effective request. The upstream has an
   incomplete request until then, so a client that swaps the model, the cap,
   or withholds the suffix gets no inference at all.
4. **Settlement.** The π_C3-disclosed usage event must name the setup model
   (GAP-2 closed).

Tested live against Venice:
- a mismatched suffix is rejected;
- a decoy model in the private part is billed as the setup model;
- a pricier model with no suffix gets 0 response bytes (both an offered model
  and an un-offered one, `claude-fable-5`);
- a claimed canonical suffix the body does not end with fails π_C2.

Every attack session is refunded and never reaches the upstream as a complete
request (`crypto/tools/adversarial-model-swap.sh`).

---

## Q2. Transferability to other OpenAI-compatible providers

### 2.1 What is Venice-specific vs generic

**Generic (provider-independent) machinery:**

| Piece | Evidence |
|---|---|
| TLS 1.3-only client, single suite `TLS_AES_128_GCM_SHA256`, one key share, tickets off | SPEC §3; PLAN §4 |
| The KeyUpdate epoch dance (KU0 → N's credential record → KU1 → body) | SPEC §4–5.4 |
| Key-schedule derivation and the in-circuit chain (`key_schedule_zk`, RFC 8448-tested) | PLAN §1–2; `crypto/cu-crypto`; `statements.rs:195-231` |
| GCM record assembly from keystream material (CTR/GHASH math) + π_C1/π_N structure | SPEC §5.4; `main.rs:755-783`; `statements.rs:255-289, 340-391` |
| Head template mechanism (`{KEY:L}`, `{LEN}`, alphabet proof) — works for any static bearer credential in a fixed header position | SPEC §5.0/§5.4; `main.rs:60-87` |
| π_C2 "last bytes of body equal public suffix" and π_C3 "disclosed tail decrypts from final server records" as *statements* | `statements.rs:291-338` |
| Escrow/settlement/attestation skeleton (Cashu, sid, receipt) | SPEC §5.1/§5.6/§5.7; WIRE-UP §4/§6 |
| The four proofs' cost profile (~0.5 s local / ~1.5 s WAN each; +485 ms TTFT e2e) | BENCH §1–2 |

**Venice-specific (must be re-established per provider):**

| Piece | Venice value | Where pinned |
|---|---|---|
| Head template: path `/api/v1/chat/completions`, `Host`, `Authorization: Bearer {KEY:42}` | Venice path + 42-char key | `main.rs:60-62`; offer |
| Suffix key set | `model,max_tokens,max_completion_tokens,n,stream,stream_options,venice_parameters` | SPEC §5.0/§5.5; `main.rs:180-188` |
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
- **C10 (new).** Token amplification is bounded by body bytes: text-only
  models, or a verified rejection of multimodal content parts on the offered
  models (see GAP-3, §3.4).
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
| C10 amplification | **Same GAP-3 exposure as Venice**, plus OpenRouter-specific billed plugins — pinnable if C3 holds. | |
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
accept an unbounded escrow (unacceptable, §3.4). Also `service_tier:
"priority"` is a billed tier that must be pinned (pinnable — it's a plain
field). **Verdict:** transferable *conditionally*, gated on the `tools:[]`
semantics test plus C1/C3; otherwise offer only tool-free sessions on OpenAI.

**Anthropic (api.anthropic.com and Anthropic-compatible gateways).**
Fails C5-as-written, needs a **profile variant**, not just a profile:
- Streaming usage is **split**: input tokens arrive in the `message_start`
  event (beginning of stream), output tokens in `message_delta`
  (`usage.output_tokens`, near the end), terminated by `message_stop` — there
  is no single final usage event. π_C3's current statement anchors `R` at the
  transcript **end** (`statements.rs:312-338`; tail-record selection in
  `main.rs:666-719`). An Anthropic profile needs *two* disclosed ranges (head
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

## Q3. Does the node see the prompt? What does it know about size? Escrow economics

### 3.1 Information flow — exactly what N knows at each stage

| Stage | N learns | N never learns |
|---|---|---|
| Setup (SPEC §5.1) | `model`, `max_tokens`, `LEN`, escrow amount, `nonce_C`; `sid` | — |
| Handshake (§5.2) | Full handshake transcript; cert chain/hostname/CV/Finished verified from disclosed *handshake* traffic secrets. Application secrets are underivable from these (§5.2 final note) | `HS`, all `*_ap_*` secrets |
| Epoch 0/1 (§5.3–5.4) | `\|head\|` (its own template), keystream material `S, H1, T0` for epoch-1 seq 0 (two known-plaintext AES pairs + a keystream segment; recovering `K1` from them is AES key recovery), the head plaintext `P` (it wrote it), the credential record ciphertext | `K1`, `c_ap_1`, `c_ap_2`; the credential record is never forwarded to C (P1, §2/§5.4 step 6) |
| Body (§5.5) | Record count, each record's ciphertext length (⇒ total body size = `LEN` + framing, consistent with the `Content-Length` N itself wrote), timing; the **suffix** in plaintext (public input to π_C2) | `body_private` — the prompt and any tools |
| Response (§5.6) | Ciphertext, record boundaries, total length, timing, close time; signs attestation over hashes | All response plaintext (P2) |
| Settlement (§5.7) | `R` = usage event + `[DONE]` + chunk framing (⇒ **actual** `prompt_tokens`, `completion_tokens`, served model, Venice `cost`), bound to the wire by π_C3 | Everything outside `R` |

So: **no, the node does not see the prompt** (P2; verified in the prototype by
invariant I2 — "sidecar never receives `c_ap_2`, `s_ap_0`, body or response
plaintext", PROGRESS I2 PASS). **Yes, the node knows the input size exactly** —
`LEN` is disclosed at setup *and* written by N into `Content-Length` *and*
visible anyway as ciphertext length. It **needs** `LEN`: it is the only
prompt-size signal escrow can be priced on (§3.2).

**Traffic-analysis caveat (you asked: does it matter?).** N sees body
ciphertext length (≈ prompt size), response ciphertext length (≈ output
size), timing/TTFT, and at settlement the exact token counts. Hiding any of
that is an explicit **non-goal** (SPEC §1: "hiding traffic volume and timing
from the node"). The model identity is likewise not private (N priced it).
Nothing in the threat model requires otherwise: the node's privacy promise is
about *content*, and content never leaks — lengths do not constrain plaintext
in any way an LLM prompt is vulnerable to beyond coarse size, which the
protocol discloses deliberately anyway. It does not matter for the stated
goals; it would matter for a stronger goal (e.g. hiding that a user sends
~100 KB prompts every weekday at 09:00), which the SPEC correctly declines.

### 3.2 Escrow sizing — why prepaid-at-max is necessary and sufficient

Per SPEC §5.1 step 2: `E = price(model, LEN_upper_bound_tokens, max_tokens)`,
prepaid as Cashu and bound to `sid` (§5.1 step 3; WIRE-UP §4 step 5). The
components:

- **Completion side:** exactly bounded. The suffix pins `max_tokens` **and**
  `max_completion_tokens` to `T ≤ max_tokens_cap` (the cap is enforced,
  `main.rs:556-559`; the dual pin exists because Venice otherwise lets
  `max_completion_tokens` override `max_tokens` — VENICE-TESTS row 4).
  Reasoning tokens count toward completion tokens (tested), so `T` bounds all
  output-side cost.
- **Prompt side:** bounded by `LEN`. The client's prompt lives inside a body
  of exactly `LEN` bytes, and each token covers ≥ 1 byte, so
  `prompt_tokens ≤ LEN` is a provably safe (if ~4× loose for English) bound;
  add a small fixed margin for chat-template framing and, for Venice, the
  system prompt — the latter is already pinned off
  (`venice_parameters.include_venice_system_prompt:false`; without the pin it
  cost 1767 tokens on "Say hi", VENICE-TESTS). Escrow prices
  `prompt_bound(LEN) = LEN + margin` at the `in` rate.
- **Prepaid, because nothing better exists.** Even with the prompt fully
  visible, a node cannot know the token count before the upstream tokenizes
  it — routstr's *current, non-confidential* flow already prepays at maximum
  and refunds (`pay_for_request`, WIRE-UP §1.1 step 4). The confidential path
  changes nothing about that economic shape; it only changes *who can read
  the prompt* (nobody but C and U). Refund flow: `refund = E − cost` as Cashu,
  with a signed receipt (SPEC §5.7 step 4); if C withholds disclosure, N keeps
  `E` — and since `E` is sized to the maximum, disclosure is always in C's
  interest (SPEC §5.7 step 6).
- **Cached tokens:** priced conservatively at the `in` rate in `E`; the
  refund can credit the cheaper `cached_in` rate because Venice reports
  `prompt_tokens_details.cached_tokens` inside the disclosed `R`
  (VENICE-TESTS; offer carries `cached_in`, SPEC §5.0).

### 3.3 Settlement, aborts, and who eats what

- **Happy path.** π_C3-verified usage → `cost = price_list(setup_model,
  usage)` (or Venice `cost × markup`, §5.7 step 4) → `refund = E − cost`.
  Overpay (the common case, since `E` is at the bound) is refunded; underpay
  cannot happen for the client by construction (`cost ≤ E`, given §3.2's
  bounds and the pins).
- **Abort before the final body record is released** (including a failed or
  withheld π_C2): the upstream never received a complete request, so there is
  no upstream cost and N refunds `E`. The client claims it with
  `POST /v1/confidential/refund` if the socket is gone.
- **Upstream HTTP error** (400, 503 …): C discloses the complete error
  response under π_C3 and N settles at zero cost, a full refund. An honest
  client bug that Venice rejects costs nothing.
- **Abort after release, no usage event** (client abort, mid-stream error):
  N keeps `E`, "as with today's prepaid flow". This is self-punishing for a
  malicious client and covers N's outlay if Venice bills partial generation.
- **Receipt/disputes:** signed receipt + attestation; disputes published as
  Nostr events (SPEC §5.7 step 5). Production settlement moves into
  routstr-core (Cashu + Nostr key stay in Python; WIRE-UP §2.3, §6.1).

### 3.4 The failure mode: actual usage exceeds escrow

If `cost > E`, the node already paid Venice and can only withhold the refund;
it eats `cost − E`. The protocol's defence is that every cost driver must be
bounded by what `E` priced: `(setup_model, LEN, max_tokens, pinned params)`.
Enumerating the escape hatches:

| Cost driver | Bounded by | Status |
|---|---|---|
| Model / cap swapped, or suffix withheld | final body record held until π_C2 verifies | **Sound** (tested live: no response, refunded) |
| Output tokens (incl. reasoning) | `max_tokens` + `max_completion_tokens` pins; small overshoots on tiny caps (3 → up to 6 observed) fall well inside the reservation, whose prompt side is a full context window | **Sound** (tested, `provider-profile-check.py` A2/A6) |
| `n > 1` | `"n":1` pin | **Sound** (Venice 500s otherwise) |
| Venice system prompt | `include_venice_system_prompt:false` pin | **Sound** (tested: 1767 → 16 tokens) |
| Web search (≈4.6k tokens/call) | `venice_parameters.enable_web_search:"off"` pin — the whole `venice_parameters` object is replaced by the suffix | **Sound** (tested: 4675 → 16) |
| Huge prompt bytes | `E` scales with `LEN`, priced node-side; `prompt_tokens ≤ LEN` with the system prompt pinned off (224 bytes → 6 tokens) | **Sound** (tested, A7) |
| Cached tokens | cheaper, not dearer | **Sound** |
| Schema-novel cost fields | strict-schema 400s + per-provider regression suite (SPEC §7.6) | **Sound, maintained** |
| Multimodal amplification | only text-only models are offered; they reject image parts | **Sound** (tested, A8; GAP-3 below for the background) |
| Alias/routing to a dearer backend | ops monitoring vs Venice `cost` (§1.6 row 11) | **Unknown — testable** |

> ### **GAP-3 — token amplification beyond `LEN` via multimodal inputs (HIGH if vision/audio models are offered on the confidential path; otherwise N/A)**
>
> **Where.** Escrow's prompt bound assumes prompt tokens scale with body bytes
> (SPEC §5.1: `LEN_upper_bound_tokens`). A `messages` entry containing an
> image URL (~100 bytes) can expand to thousands of image tokens server-side;
> the suffix pins no modality, and nothing in the offer restricts models to
> text-only. The test model `mistral-small-3-2-24b-instruct` is itself
> vision-capable, so this is not hypothetical. Whether Venice (a) accepts
> image content parts on the offered models, (b) fetches URLs server-side,
> and (c) counts image tokens in `prompt_tokens` is **unknown — testable in
> one request per model** (send a small image URL; read the usage event's
> `prompt_tokens`).
>
> **Exploit (if confirmed).** Escrow for `LEN` = 2 KB, embed an image URL;
> `prompt_tokens` ≫ priced bound; `cost > E`; node eats the difference.
>
> **Fix (exact).** (1) Allow-list only models verified to reject multimodal
> content parts (400) in the confidential offer — a per-provider regression
> test, joining SPEC §7.6; and/or (2) pin any provider field that disables
> vision/tools if one exists; failing both, (3) price `E` at the model's full
> context window (expensive for users — last resort). Until (1) is done, do
> not advertise vision-capable models on the confidential path. Add the three
> probe questions above to VENICE-TESTS.

Two smaller prototype notes on this axis (not design flaws): the stub
`settle()` hardcodes a 1000-diem pseudo-escrow (`main.rs:932`) rather than
using `escrow_e`, and `escrow_e` itself is never priced (`main.rs:564-566`) —
both are documented stubs (PROGRESS phase 5) whose production replacements
live in routstr-core (WIRE-UP §6.1), where the GAP-1 fix 4 makes the node the
sole pricer of `E`.

### 3.5 Q3 verdict

- The node never sees the prompt (P2, implemented and self-checked); it knows
  the prompt's **byte size exactly** and its **token count only at
  settlement**, from the upstream's own proven usage event. It needs the
  former for pricing and gets the latter for settlement; it needs nothing
  else.
- Escrow is prepaid-at-maximum because token counts are unknowable pre-
  tokenization even in principle; the design's refund-at-settlement mirrors
  routstr's existing prepaid flow, now with a ZK-bound usage oracle instead
  of trust.
- `cost ≤ E` — and hence node solvency — holds **only if** every cost driver
  is pinned or byte-bounded: true and tested for output tokens, reasoning,
  `n`, system prompt and web search; **open for multimodal amplification
  (GAP-3)** and dependent on the GAP-1/GAP-2 fixes for model binding. Those
  three fixes together close the escrow economics; none requires new
  cryptography.

---

## Appendix A — GAP summary

| ID | Severity | One-liner | Fix location |
|---|---|---|---|
| GAP-1 | **HIGH** (prototype; SPEC ambiguity) | Suffix (incl. `model`) is client-supplied and never bound to the setup/escrow values | §1.4: node reconstructs canonical suffix from (offer, setup); store setup in `Session`; node-side pricing of `E`; bind setup into `sid` |
| GAP-2 | **MEDIUM** | `validate_r` omits the PLAN §5(b) `usage.model == session model` check; `settle()` has a hardcoded model fallback | §1.5: enforce equality in `validate_r`; delete the fallback; SPEC §5.7 to name the setup model as the pricing key |
| GAP-3 | **HIGH if multimodal models offered, else N/A** | Escrow's `LEN`→token bound breaks under image/audio token amplification | §3.4: text-only allow-list + regression test, or modality pin, or full-context pricing (last resort) |

## Appendix B — Citation index

- Model choice & escrow: SPEC §5.0–5.1; WIRE-UP §4 step 5; `main.rs:244-247, 556-579`
- Suffix semantics & last-duplicate-key: SPEC §5.5; VENICE-TESTS ("Duplicate keys and malformed JSON", "Final streaming events", "Adversarial model output"); `driver.ts:106-115`
- π_C2 statement/public inputs: PLAN §2; `statements.rs:90-108, 291-310`; `main.rs:644-664`
- π_C3, `R` validation, settlement: SPEC §5.7; PLAN §5; `statements.rs:312-338`; `main.rs:666-719, 859-938`; PROGRESS deviations 2 & 5
- Head template / π_N / endpoint pinning: SPEC §5.4; `main.rs:60-87, 755-783`; `statements.rs:340-391`
- Aborts & non-disclosure: SPEC §5.8, §5.7 step 6
- Provider requirements & fallback: SPEC §7, §9; VENICE-TESTS "TLS"
- Benchmarks: BENCH §1–2; SPEC §11
- Invariant self-check (incl. I2 no-plaintext, I6 suffix keys): PROGRESS "Security invariants"
- Prototype stubs (escrow/pricing): `main.rs:912-938`; PROGRESS phase 5; PLAN §0 scope
- Known prior art on model-swap risk in the non-confidential rail: `docs/original/REPLY-to-red.md` item 2 ("upstream_models comes from the node, so a node can make a cheap-model swap look verified") — the threat class GAP-1 belongs to, previously flagged for the TLSN rail.
