# PROGRESS-CONFIDENTIAL — node integration + pre-warm

*Implementation of `WIRE-UP-confidential-upstream.md` (node side) and the
"pre-warmed sessions" section of `docs/APPROACH.md`, on top of the verified
prototype in `crypto/PROGRESS.md`. All commands run from
the project root.*

The prototype (all four ZK proofs against real Venice) is unchanged and still
green. This phase adds the node integration, a config-file/offer mode for the
sidecar, real Cashu escrow, and the arm/pool pre-warm path.

## Phase status

| Phase | What | Status |
|---|---|---|
| N1 | routstr-core: `GET /v1/confidential/offer` (Nostr-signed), WS proxies, additive `/v1/models` field, config-gated | ✅ done |
| N2 | routstr-core escrow/settlement in Python (Cashu redeem, π_C3 cost, refund, Nostr receipt, session ledger) | ✅ done |
| N3 | cu-sidecar: config-file offer + `GET /offer` + `--node-settles` (settlement moved to the node) | ✅ done |
| N4 | Reference client: node mode, Schnorr offer/receipt/attestation verification, escrow token | ✅ done |
| P1 | Real Cashu end-to-end (escrow → redeem → settle → refund → client verifies) | ✅ done |
| P2 | Pre-warm (`--arm`) + pool (`--pool 2`) | ✅ done |
| P3 | rayon in the release build + before/after bench | ✅ done (opt-in; see notes) |
| P4 | Cold vs warm TTFT benchmark + `BENCHMARK-WARM.md` | ✅ done |

## Layout

```
crypto/
  relay/            cu-sidecar: + GET /offer, --node-settles, config-file offer, --host
  client/src/       driver.ts: node mode, Schnorr verify, --arm/--pool, phase timings
                    zkbridge.ts: takes a full zk URL (sidecar or node proxy)
  tools/cu_cashu.py mint/redeem helper (uv ephemeral env)
routstr-core/       routstr/confidential.py, routstr/confidential_ws.py, settings,
                    main.py wiring, payment/models.py field, tests/unit/test_confidential.py,
                    README-CONFIDENTIAL.md
```

## Exact reproduction commands

### 1. Local Cashu mint (Nutshell `mint`, no Docker needed)

The venv's cashu 0.20.0 works for the mint; pin `limits<4` and `marshmallow<4`
(the pinned `limits` in the main venv rejects `fixed-window-elastic-expiry`).

```bash
uv venv --python 3.12 /tmp/cu-mint-venv
uv pip install --python /tmp/cu-mint-venv/bin/python "cashu==0.20.0" "limits<4" "marshmallow<4"
mkdir -p /tmp/cu-mint/data
cd /tmp/cu-mint
MINT_BACKEND_BOLT11_SAT=FakeWallet MINT_PRIVATE_KEY=TEST_PRIVATE_KEY \
MINT_LISTEN_HOST=127.0.0.1 MINT_LISTEN_PORT=3338 \
MINT_DATABASE=/tmp/cu-mint/data/mint MINT_INPUT_FEE_PPK=0 \
/tmp/cu-mint-venv/bin/mint
curl -s http://127.0.0.1:3338/v1/info
```

### 2. Sidecar (node-settles, config-file offer, rayon)

```bash
cd crypto
cargo build --release -p cu-sidecar            # rayon is on by default
RUST_LOG=cu_sidecar=info ./zkbench/target/release/cu-sidecar \
  --listen 127.0.0.1:7443 --upstream api.venice.ai:443 --key-env VENICE_API_KEY \
  --offer relay/offer.venice.json --node-settles
curl -s http://127.0.0.1:7443/offer
```

### 3. Node

```bash
cd routstr-core
export DATABASE_URL="sqlite+aiosqlite:////tmp/cu-node/node.db"
export NSEC="$(cat /tmp/cu-node-nsec)"                # any test identity
export CONFIDENTIAL_SIDECAR_URL="http://127.0.0.1:7443"
export CASHU_MINTS="http://127.0.0.1:3338"
export UPSTREAM_BASE_URL="https://api.venice.ai/api/v1"
export UPSTREAM_API_KEY="$VENICE_API_KEY"
export FIXED_PRICING=true FIXED_PER_1K_INPUT_TOKENS=1 FIXED_PER_1K_OUTPUT_TOKENS=1
export HTTP_URL="http://127.0.0.1:8000"
.venv/bin/uvicorn routstr.core.main:app --host 127.0.0.1 --port 8000
curl -s http://127.0.0.1:8000/v1/confidential/offer | head -c 400
curl -s http://127.0.0.1:8000/v1/models | grep -o confidential_upstream | head -1
```

### 4. Mint an escrow token and run a full session

```bash
cd crypto/tools/.cashu
TOKEN=$(uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
  python ../cu_cashu.py mint --mint http://127.0.0.1:3338 --sats 20 | tail -1)

cd ../../client
CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --node http://127.0.0.1:8000 \
  --model deepseek-v4-flash --max-tokens 12 --escrow-token "$TOKEN" \
  --prompt 'Say hi in three words.'
# prints E2E_JSON with receipt_sig_ok=true, usage_match=true, refund_math=true
```

> The model must be on the sidecar's `text_only_ok` allow-list (GAP-3 gate).
> `deepseek-v4-flash` is; the vision-capable `gemini-3-flash-preview` used in
> earlier runs is now refused at setup (escrow refunded). See the "Fix pass"
> section and `VENICE-TESTS-ADDENDUM.md`.

Verify the node's refund token is real money:

```bash
cd ../tools/.cashu
uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
  python ../cu_cashu.py redeem --token "$(cat /tmp/cu-refund-token.txt)"
# -> {"redeemed_sats": 19, "mint": "http://127.0.0.1:3338"}
```

### 5. Pre-warm (`--arm`) and pool (`--pool 2`)

```bash
# arm one session, claim on "go"
(sleep 1; echo go) | CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --node http://127.0.0.1:8000 \
  --model deepseek-v4-flash --max-tokens 12 --escrow-token "$TOKEN" --arm

# pool of two armed sessions (two tokens), claim the first
CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --node http://127.0.0.1:8000 \
  --model deepseek-v4-flash --max-tokens 12 --escrow-token "$T1,$T2" --pool 2
```

### 6. Benchmarks

```bash
cd crypto/client && ./bench-warm.sh 5          # cold / warm / baseline, medians
cd crypto && ./zkbench/target/release/cu-prover --bench --json /tmp/bench-rayon.json
# rayon off:
cargo build --release -p zkbench --bin cu-prover --no-default-features
./zkbench/target/release/cu-prover --bench --json /tmp/bench-no-rayon.json
```

### 7. Tests

```bash
cd routstr-core
.venv/bin/python -m pytest tests/unit/test_confidential.py -q
.venv/bin/python -m pytest tests/unit -q          # full unit suite
```

## Payments evidence (real, no stubs)

* Mint: local Nutshell 0.20.0 (`FakeWallet`, `MINT_INPUT_FEE_PPK=0`), keyset
  `01d8a630…c039f6bc`, `http://127.0.0.1:3338`.
* Escrow: client mints **20 sat**, sends the token in `setup`; the node redeems
  it on its own mint (`POST /v1/swap`, verified in the mint log) → `escrow_sats=20`.
* Settlement: π_C3-verified usage → node cost = **14 msats = 1 sat**
  (`cost_sats=1`), refund **19 sat** as a fresh Cashu token.
* The returned `refund_token` was redeemed at the mint for **19 sat** — real
  money, not a stub.
* Abort path (spec §5.8): sessions that never wrote the credential record
  (`head_written=0`) show `status="refunded"`, `refund_sats=20` in the
  `confidential_sessions` table.

`confidential_sessions` sample (from the live run):

```
sid=05e398…  mode=escrow model=gemini-3-flash-preview escrow_sats=20 cost_msats=14 refund_sats=19 status=settled head_written=1
sid=cd5f0d…  mode=escrow model=gemini-3-flash-preview escrow_sats=20 cost_msats=0  refund_sats=20 status=refunded head_written=0
```

Across the whole session (all live Venice runs): 45 `settled` (900 sat escrowed,
590 msat charged, 855 sat refunded), 13 `refunded` (abort before the credential
record → full refund), 10 `kept` (abort after the credential record → node keeps
E, per SPEC §5.8; these are the stalled-proof sessions, see Deviations 5).

Node commit: `4521f959` on branch `confidential-upstream` (not pushed).

## Security invariants (PLAN §7)

| ID | Check | Result |
|---|---|---|
| I1 (P1) | API key only in sidecar memory + the one credential record | **PASS** — `grep -rF "$VENICE_API_KEY" crypto/runs/ /tmp/cu-sidecar.log /tmp/cu-node/node.log` finds nothing; the sidecar logs `key_len=42` only; the node never receives the key. The node's escrow/refund path touches only the Cashu wallet. |
| I2 (P2) | Node/sidecar never receive `c_ap_2`, `s_ap_0`, body or response plaintext | **PASS** — the node's frames are `setup`, `hs_secrets`, `c1_material`, body as **ciphertext** (binary passthrough), `body_suffix` (public), `ku1`, `disclose` (R + tail lengths); `/zk` carries proof I/O only. `grep -rE "c_ap_2|s_ap_0" crypto/runs/` finds nothing. |
| I3 | Circuits implement SPEC §1 exactly | **PASS** (prototype) ��� unchanged; `cargo test --release -p zkbench` native==ZK + mutations. |
| I4 | Ordering: π_C1 verified before assembly; π_N verified by C before the wire write | **PASS** — `assemble()` is called only from `ZkDone(pi_c1)`; the record is written only in the `ku1` handler; the node's proxy does not reorder frames. |
| I5 | Epoch-1 record count/length gate | **PASS** (prototype, unchanged): epoch 0 accepts exactly one 27-byte client record; epoch 1 exactly one 22-byte KeyUpdate. |
| I6–I10 | suffix pins, π_C3 anchoring, freshness, fail-closed handshake, signature verification | **PASS** (prototype) + **node**: the client verifies the node's BIP-340 Schnorr offer/attestation/receipt signatures; the node re-signs the sidecar's attestation so the client trusts the node's key. |

## Deviations / notes

1. **The node's `/v1/confidential/zk` `session_id` is the protocol `sid`** (a
   32-hex digest), not the uuid from `WIRE-UP`. The client only learns the sid
   after `ready`, so it cannot be the control connection's pre-chosen uuid; the
   zk route accepts uuid **or** 64-hex.
2. **Pre-warm moves π_C1/π_N into the arm step**, not just the handshake. The
   plan/APPROACH framed π_C1 as request-bound because `|head|` depends on the
   body-length digits. In practice the client knows its request size, so arming
   with that `len` lets π_C1 be verified during arming and the credential record
   pre-assembled; the claim path is then only KU1 + body. This is what takes the
   added TTFT from hundreds of ms to ~0 (see `BENCHMARK-WARM.md`). A claim with
   a *different* `len` digit count would need a fresh π_C1; the reference client
   arms per request shape (the pool uses one body size).
3. **OT/VOLE correlation precompute is not used.** It is not needed once π_C1
   moves into the arm step, and mpz2's `mpz-zk` exposes no separate
   preprocessing (its `Execute::wants_preprocess` is `false`; Ferret extends on
   demand inside the ZK flush). Recorded here rather than attempted. The arm
   step therefore runs the *whole* π_C1 (not just its correlation) before the
   request exists — the maximum that works, and it removes π_C1 from the claim
   path entirely.
4. **`rayon` is opt-in, not the default build.** `cargo build --features rayon`
   cuts the proof bench by 30–44 % locally and 5–11 % on WAN (see
   `BENCHMARK-WARM.md` §2). The stall once attributed to rayon was root-caused
   in the stdio/ws drain (Deviation 5, fixed this pass): with the fix, 20/20
   sessions succeed with rayon on as well as off. The default build still keeps
   rayon off (conservative; the shipped path is the one the verified prototype
   used); the feature is available and measured.
5. **Intermittent proof stalls — ROOT-CAUSED AND FIXED (this pass).** The
   stall was not in mpz2 and not proof concurrency: it was a lost-final-bytes
   race in our stdio/ws framing. `cu-prover` returned from `run_io` and called
   `std::process::exit(0)` before its stdout forwarder task had drained the
   duplex, so the prover's last protocol message never reached the pipe; the
   sidecar verifier waited for it until its 30 s timeout (and symmetrically the
   sidecar's ws pump could drop the verifier's last message). Evidence: sidecar
   `zk proof timed out (30s)` on π_C1, π_C2 and π_C3 across attempts, while the
   client's `cu-prover` for that proof had already exited and the client had
   moved on to a later proof (`crypto/runs/stall/`). Fix: await the forwarder
   before exit in `cu-prover`, and `WsBridge::finish()` in the sidecar's
   `zk_inner`. Measured after the fix: **20/20** serial, **20/20** parallel
   (`--parallel-proofs`), **20/20** with rayon on, and `bench-warm.sh 5` cold
   **5/5** / warm **5/5** (previously 5/7, 5/6). The 30 s sidecar timeout,
   per-session proof lock, and client-side timeouts remain as defence in depth.
6. **Settlement is entirely in the node.** The sidecar runs `--node-settles`:
   it emits the π_C3-verified `usage` and never touches money. The prototype's
   Rust settlement stub still exists for the direct (no-node) deployment.
7. **Fixed pricing in the test deployment.** The node is run with
   `FIXED_PRICING=true` + `FIXED_PER_1K_*`, so the offer's price list and the
   settlement both come from the node's own cost path; a real deployment with
   per-model pricing works the same way (`_confidential_price_list` uses the
   node's `_get_pricing_rates`).
8. **The reference client escrows at arm time** (its sid is bound to the Cashu
   token, SPEC §5.1); a Cashu session therefore cannot be armed *without* a
   token. The account/balance pre-warm path (escrow deferred to claim) is the
   routstrd/SDK side (not this repo); the node advertises `prewarm` and accepts
   armed sessions.

---

# Fix pass (2026-10-09) — GAP-3 + proof stall

Two open items from `docs/ADVERSARIAL-QA.md` (§3.4/GAP-3) and Deviation 5.

## GAP-3 — multimodal token amplification: **CONFIRMED**, now gated

**Probe** (`crypto/tools/probe-modality.py`, real Venice; full results in
`crypto/VENICE-TESTS-ADDENDUM.md` and `crypto/runs/modality/probe.json`). A
~50-byte `image_url` URL expands to image tokens chosen by the attacker, not
bounded by body bytes:

| model | text baseline (`prompt_tokens` / body bytes) | small image | large image | verdict |
|---|---|---|---|---|
| `mistral-small-3-2-24b-instruct` | 8 / 340 | 301 / 418 | **1071 / 418** | accepts → unsafe |
| `gemini-3-flash-preview` | 5 / 332 | **1085 / 423** | **1107 / 423** | accepts → unsafe |
| `inkling` | 19 / 317 | **554 / 408** | **2050 / 408** | accepts → unsafe |
| `seed-2-1-turbo` | 50 / 324 | **1328 / 415** | 1323 / 415 | accepts → unsafe |
| `deepseek-v4-flash` | 9 / 327 | 400 (rejected) | 400 | **safe** |

`data:image/png;base64,…` is rejected (400) on every model today. Escrow prices
`prompt_tokens ≤ LEN` (SPEC §5.1), so for the accepting models `cost > E` is
reachable: escrow a small `LEN`, embed a large image URL.

**Mitigation (both, as prescribed):**
- *(a) allow-list gate* — `crypto/relay/offer.venice.json` now advertises only
  the eight models verified to reject `image_url` (400), and marks them
  `text_only_ok`; `relay/src/main.rs` refuses any `setup` for a model not marked
  `text_only_ok` (before the credential record; the node refunds on abort).
  Models gated out: `mistral-small-3-2-24b-instruct`, `google-gemma-3-27b-it`,
  `gemini-3-flash-preview`, `claude-{opus,sonnet,fable}-5`, `kimi-k3`,
  `inkling`, `seed-2-1-turbo`.
- *(b) regression test* — `crypto/tools/regression-modality.py` re-probes the
  advertised models after provider changes; it reads the allow-list from the
  offer and **fails** if any advertised model starts accepting images. Run
  2026-10-09: `PASS: all 8 advertised models reject image parts`.

**Node-side follow-up (not applied here — `routstr-core/` is out of scope for
this pass).** The node's `_confidential_price_list` (`routstr/confidential.py`)
builds its `price_list` from its own model list filtered only by upstream host,
so it still advertises the seven vision models; the sidecar gate then refuses
them at setup (fail-closed, escrow refunded, but a wasted escrow/redeem for the
client). To make the advertisement match the gate, the node must intersect that
list with the sidecar offer's `text_only_ok` keys — e.g. inside
`_confidential_price_list`, after computing `prices`, drop any model not in
`(await fetch_sidecar_offer()).get("text_only_ok", {})` (and likewise gate the
`/v1/models` `confidential_upstream` block in `payment/models.py`). This is a
one-line intersection in each place and needs no new cryptography.

**Bench note.** With the gate, the e2e/bench model moved from
`gemini-3-flash-preview` (vision, gated out) to `deepseek-v4-flash`;
`client/bench-warm.sh` now defaults to the latter.

## Task 2 — proof stall: **ROOT-CAUSED AND FIXED**

See `crypto/runs/stall/NOTES.md` for the full evidence trail. Summary: the
prover process exited before its stdout pump drained the final protocol bytes
(`cu-prover`), and symmetrically the sidecar's ws pump could drop the verifier's
last message; the peer then waited out its 30 s proof timeout. It is not an
mpz2 bug and not proof concurrency. Fixed by awaiting the forwarder before exit
(`zkbench/src/bin/cu-prover.rs`) and by `WsBridge::finish()` in the sidecar
(`relay/src/wsio.rs`, `relay/src/main.rs`).

Measured success rate (sequential cold e2e, tiny `max_tokens`):

| configuration | before | after |
|---|---|---|
| serial π_C2→π_C3 (default) | 8/10, 9/12 | **20/20** |
| `--parallel-proofs` | — | **20/20** |
| rayon on (sidecar + prover) | intermittent stalls | **20/20** |
| `bench-warm.sh 5` | cold 5/7, warm 5/6 | **cold 5/5, warm 5/5** |

`crypto/tools/stall-repro.sh <N> <label>` reproduces the measurement.

## Adversarial GAP-1 verification (malicious client)

`crypto/tools/adversarial-model-swap.sh` → evidence in
`crypto/runs/adversarial/`.

| case | attempt | result |
|---|---|---|
| **(a)** suffix model ≠ setup model | `--adv-suffix-model deepseek-v4-pro` | sidecar rejects: *"body suffix does not match the canonical suffix for model/max_tokens"*; node ledger `status=kept head_written=1` — no settlement, attacker gets nothing |
| **(b)** private-part decoy, honest suffix | `--decoy-model deepseek-v4-pro` | settles; effective model = **suffix** model (`deepseek-v4-flash`), `usage_match=true` |
| **(c)** escrow below requirement | 1 sat, ~2 KB body | node rejects: *"escrow 1 sat < required 3 sat; refund=…"*, escrow refunded |
| **(d)** | body model ≠ setup **and** no `body_suffix` | the sidecar holds the final body record until π_C2 verifies; without it the upstream never gets a complete request: **0 response bytes**, ledger `refunded` |

(a)/(b) confirm the GAP-1 fix and the decoy binding. (c) confirms the node-side
escrow requirement. All of (a), (c) and (d) end before the upstream receives a
complete request, so they are refunded and cost the node nothing.

> **GAP-4 (closed by ordering).** The sidecar forwards body records as they
> arrive *except* the one that completes the body, which carries the pinned
> suffix. That one is released only after π_C2 verifies; the upstream (verified:
> Venice) does nothing until the full `Content-Length` body has arrived. A
> client that withholds or falsifies the suffix therefore gets no inference,
> and the node refunds `E` because the upstream never saw a complete request.
> Escrow is sized for the setup model alone. See the section below.

## Benchmarks after the changes

- `cu-prover --bench` (`/tmp/bench-verify.json`): π_C1 462 ms local / 1547 ms
  WAN, π_N 86/778, π_C2 457/1549, π_C3 468/1556 — **unchanged** vs
  `BENCHMARK-WARM.md` §2 (the drain fix is off the proof path).
- `client/bench-warm.sh 5` (model `deepseek-v4-flash`): cold TTFT 1804 ms,
  claim→body 641 ms, π_C1 485 ms; warm claim→body **2 ms**, `arm_ms` 623 ms;
  **5/5 cold, 5/5 warm with zero retries**. `BENCHMARK-WARM.md` §4 updated.

## Files touched

- `crypto/zkbench/src/bin/cu-prover.rs` — stdout drain before exit.
- `crypto/relay/src/wsio.rs`, `crypto/relay/src/main.rs` — `WsBridge::finish`,
  `text_only_ok` gate, explicit `{type:"error"}` rejection, drain outbound queue.
- `crypto/relay/offer.venice.json` — text-only allow-list / price_list.
- `crypto/client/src/driver.ts` — `--adv-*` probes, `--parallel-proofs`,
  fail-fast on `error`/close, `CU_TRACE` tracing.
- `crypto/tools/` — `probe-modality.py`, `regression-modality.py`,
  `adversarial-model-swap.sh`, `stall-repro.sh`.
- `crypto/VENICE-TESTS-ADDENDUM.md`, `crypto/runs/{modality,stall,adversarial}/`,
  `crypto/BENCHMARK-WARM.md`, this file. (`docs/` and `routstr-core/` untouched.)

## GAP-2 re-check (no change made)

`relay/src/main.rs` `validate_r` now requires the usage event's `model` and the
`Disclose` handler rejects it if it differs from the pinned setup model
(`main.rs` ~899), so a missing/mismatched model is a settlement failure rather
than a default. The hardcoded `"mistral-small-3-2-24b-instruct"` fallback still
present in the stub `settle()` is unreachable on that path (it is only reached
after `validate_r` passed, and only in the direct `--node-settles`-absent
deployment). No change required for this pass; noted for the prototype stub's
eventual removal.

## Node unit tests

`cd routstr-core && .venv/bin/python -m pytest tests/unit -q` →
**2406 passed, 1 skipped** (2m44s). The expected 2405 baseline plus the
confidential tests; no `routstr-core` file was modified in this pass.

---

# GAP-4 — model/cap swap closed by holding the final body record

## Mechanism

- **`crypto/relay/src/main.rs`.** In the `Body` state, the record that
  completes the declared body length is held (`Session.held`) instead of being
  written upstream. When π_C2 verifies against the node's canonical suffix, the
  record is written and a `{type:"body_released"}` frame goes to the node. A
  failed or absent π_C2 closes the session with the record unreleased.
- **Clients** (`client/src/driver.ts`, SDK `session.ts`). The suffix is written
  as its own final TLS record, so it always fits one record and the held record
  is small.
- **Node billing** (`routstr-core/routstr/confidential.py`). There is no
  protocol-specific escrow; sessions are billed through the node's normal path.
  - The setup carries the client's ordinary bearer (an `sk-` key or a Cashu
    token): `validate_bearer_key`, then `pay_for_request` reserves the model's
    max cost, with the completion side trimmed to the pinned `max_tokens`.
  - `adjust_payment_for_tokens` charges the π_C3-verified usage at the rates
    of the candidate whose provider host is the sidecar's upstream.
  - The reservation is released before `body_released` and for 4xx/503
    upstream errors, and charged in full when a released request gets no
    usage disclosure.
  - Unused balance is withdrawn with the existing `/v1/wallet/refund`.
- **Offer.** Carries a signed rate snapshot computed with the same rate
  function billing uses; the client checks `cost ≤ usage × rates`.
  `modality_allowed()` keeps the sidecar's `text_only_ok` allow-list (empty map
  = allow all).

## Adversarial results (real Venice, node :8010, sidecar :7444)

`crypto/tools/adversarial-model-swap.sh` → `crypto/runs/adversarial/`.

| case | result |
|---|---|
| (a) suffix model ≠ setup model | rejected: *"body suffix does not match the canonical suffix"*; reservation released |
| (b) decoy model, honest suffix | settles as the setup model (`deepseek-v4-flash`), `usage_match=true` |
| (d) pricier offered model + cap 600, no `body_suffix` | 0 response bytes; reservation released, record never released |
| (e) un-offered `claude-fable-5`, no `body_suffix` | 0 response bytes; reservation released, record never released |
| (f) body ends with `claude-opus-5`, client claims the canonical suffix | π_C2 fails on `suffix`; record never released; reservation released |

Provider assumptions are re-checked live by `crypto/tools/provider-profile-check.py`
(10/10 for Venice).

## #18 / #19

- **#18a** `crypto/relay/src/main.rs` fails at startup for an unsupported
  `key_alphabet` (`Error: unsupported key_alphabet "[A-Z]": the π_N circuit is
  fixed to "[A-Za-z0-9_-]"`); the alphabet travels in `PiN.key_alphabet` and is
  checked by the statement builder. `key_length` was already a proof parameter,
  not compile-time constrained.
- **#18b** `check_results` now requires an exact-length match for `full` checks;
  `zkbench/src/proofs.rs` unit tests cover "longer than expected must fail".
- **#18c** `cu-sidecar --runs-dir <dir>` (default unchanged:
  `CARGO_MANIFEST_DIR/../runs`); verified a session writes to the override dir.
- **#19** any session abort sends `{type:"error", reason}` before closing; the
  reference client already surfaces it. Direct check: a malformed control frame
  now returns `{"reason":"bad control: ...","type":"error"}` instead of a bare
  close. Case (a) shows it end-to-end through the node proxy.

## Measured (this pass)

- Offer intersection: node offer and `/v1/models` both drop from **15 → 8**
  models (the 7 vision models the sidecar refuses are no longer advertised).
- Required escrow at fixed pricing (1 msat/token): **1 sat** for a 330-byte
  body at `max_tokens 12`; **7 sats** for 2000 bytes at `max_tokens 4096`.
- Cold e2e (`deepseek-v4-flash`, max_tokens 12): `required_escrow_sats=5`,
  escrow 20, cost 1, refund 19; `receipt_sig_ok/usage_match/refund_math=true`;
  TTFT 2006 ms, total 2560 ms, π_C1 758 ms.
- Armed session: `claim_to_body_ms=2`, TTFT 825 ms, `arm_ms=608`.
- `client/bench-warm.sh 5`: **cold 5/5, warm 5/5, zero retries**; cold TTFT
  1349 / total 1948 ms; warm TTFT 1038 / total 1567 ms, claim→body 2 ms,
  arm 615 ms.
- `cargo test -p zkbench --release --tests`: 8/8 circuits + harness smoke.
- Node unit suite: **2409 passed, 1 skipped** (2m22s) — the 2406 baseline plus
  the three new confidential tests.

## Exact repro

```bash
# node
cd routstr-core && .venv/bin/python -m pytest tests/unit -q
# sidecar
cd crypto && cargo build --release
RUST_LOG=cu_sidecar=info ./zkbench/target/release/cu-sidecar \
  --listen 127.0.0.1:7443 --upstream api.venice.ai:443 --key-env VENICE_API_KEY \
  --offer relay/offer.venice.json --node-settles
# adversarial suite (mint :3338 + node :8000 must be up)
./tools/adversarial-model-swap.sh
# cold / warm benchmark
cd client && ./bench-warm.sh 5
```
