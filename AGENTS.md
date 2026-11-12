# AGENTS.md — orientation for agents working in routstr-confidential

**What this is.** A routstr node can serve an LLM request *without seeing the
prompt or the response* and *without giving the client its provider API key*.
The client (routstrd) is the TLS 1.3 client of the provider (Venice); the node
only relays TLS records and writes one record containing its API key. Zero-
knowledge proofs pin what each side may write, and billing uses the usage the
provider itself reported. No trusted hardware, no MPC over the payload.

Start with `PROTOCOL-V3.md` (normative; §3 the lifecycle, §12 the complete
wire format), `paper/paper.md` §4 (protocol) and §8 (how it plugs into
routstr), then this file's "Wiring" section.

## Layout

This directory is the repo **github.com/jooray/routstr-confidential**. The
three routstr repos are separate git checkouts inside it (git-ignored here).
Each has `origin` = Routstr upstream and `fork` = `jooray/<repo>`.

| Path | Git | What |
|---|---|---|
| `routstr-core/` | **`confidential-v3`** (v3, local, from `confidential-2pc`); `confidential-2pc` (v2: the open upstream PR, and what routstr.cypherpunk.today runs until v3 is deployed); `confidential-upstream` (retired v1, unmaintained) | the node (Python/FastAPI) |
| `routstr-sdk/` | **`confidential-v3`** (v3, local); `confidential-2pc` (v2, the open PR); `confidential-upstream` (retired v1, unmaintained) | client SDK (TypeScript) |
| `routstrd/` | **`confidential-v3`** (v3, local, from `confidential-upstream`); `confidential-upstream` (v2, the open PR) | client daemon (TypeScript/Bun) |
| `crypto/` | this repo, branch **`v3-h2`** (v3; `twopc-v2` is v2 and still the default branch, `v1-poc` is v1) | the protocol implementation: `cu-crypto` (TLS 1.3 key schedule, GCM, RFC 8448/NIST vectors), `twopc` (the two-party key schedule `split-public-1` + `cu-2pc` binary), `zkbench` (mpz2 VOLE-ZK statements π_NK, π_WIN, π_C3S; `cu-prover` binary), `relay/` (**cu-sidecar**, the node's Rust side), `client/` (reference TS client `driver.ts`), `tools/` (gates, the provider profile check, `shape-proxy.py`), `runs/` (evidence) |
| `paper/` | — | the paper (`paper.md` → `build.sh` → `paper.pdf`) |
| `docs/` | — | engineering docs and research (below) |
| `PROTOCOL-V3.md` | — | the v3 specification; `PROTOCOL-V3-DRAFT.md` has the reasoning |

The upstream PRs are still the protocol v2 ones: core
[#855](https://github.com/Routstr/routstr-core/pull/855), SDK
[#112](https://github.com/Routstr/routstr-sdk/pull/112), routstrd
[#155](https://github.com/Routstr/routstrd/pull/155), from the v2 branches
above, rebased on upstream `main` (2026-11-09). routstrd's CI (`validate`) stays
red until an SDK with the transport is on npm: it installs the published SDK.
The v3 branches are local and not pushed. The v1 PRs (core #824, SDK
#90, routstrd #137) are closed; their branches
(`confidential-upstream` in core and SDK) are frozen with an "unmaintained"
README note. Do not rebase or update them.

## Docs map

| File | Read it for |
|---|---|
| `docs/ONE-PAGER.md` / `.pdf` | the user-facing summary (three common objections) |
| `docs/APPROACH.md` | engineering overview: properties, components, negotiation, pre-warm |
| `docs/ADVERSARIAL-QA.md` | model binding, provider transferability (OpenRouter, Groq…), what the node learns, cost bounds (starts with a current-state box) |
| `docs/REVIEW-2026-10-09.md` | every bug found and fixed (numbered findings), measurements, the plug-in refactor (§8) |
| `PROTOCOL-V3.md` | **the protocol**: lifecycle, both framings, `split-public-1`, π_WIN, money, §12 wire format, §5.6 what framing "2" needs from a provider |
| `docs/V2-V3-ONE-PAGER.md` / `.pdf` | v2 vs v3 for operators and users (what changes, what to do) |
| `docs/SETUP.md` | how to try it and how to run a node (operator settings: `http`, `h2`, deposit, idle time) |
| `docs/TWOPC-DESIGN.md` | the two-party handshake, epochs, the 2PC security model |
| `docs/CHAT-SUFFIX.md` | the offer-driven chat suffix: the `chat` block, byte-exact rendering, the client policy, the caller-conflict rule |
| `docs/TWOPC-NODE-GARBLING.md` | the node-only authenticated garbling: construction, security argument, the download cuts (64-bit salted rows, three-halves; why h1/h2/hk stay SHA-256) |
| `docs/V1-V2-ONE-PAGER.md` / `.pdf` | v1 vs v2 trade-offs (data, speed, security); historical, v1 is retired |
| `docs/original/*` | **local only, not published** (git-ignored). The rows below describe what is in it |
| `docs/original/SPEC-confidential-upstream.md` | the original protocol spec (frames, epochs, proofs); the code has since moved on (see REVIEW) |
| `docs/original/PLAN-…`, `WIRE-UP-…` | original implementation plan and routstr wiring spec |
| `docs/original/VENICE-TESTS.md` | original provider behaviour tests; superseded by `crypto/tools/provider-profile-check.py` |
| `docs/original/BENCHMARK-*.md`, `PROGRESS.md` | prototype benchmarks (incl. MPC-TLS comparison numbers) |
| `docs/original/REPORT-*.md`, `REPLY-to-red.md`, `FAQ.md` | background research: TLSN/proverd "verified mode", Peer/zkp2p, Reclaim |
| `crypto/PROGRESS-CONFIDENTIAL.md` | integration log, reproduction commands, adversarial results |

## Wiring

```
app ──OpenAI API──► routstrd ──routeRequests(confidential)──► SDK RoutstrClient
                                                                │ _makeRequest: transport branch
                                                                ▼
             client/confidential/transport.ts → h2pool/h2conn (framing "2") | session.ts (framing "1.1")
                                   │           (TLS fork + cu-2pc + cu-prover)
                                   │ WebSocket /v1/confidential/ws?v=3 (+ /zk: 2PC, proof channel)
                                   ▼
            routstr-core confidential_ws.py ──WebSocket──► cu-sidecar (Rust, loopback)
            (deposit and per-request billing via the        │ TCP :443 relay, writes the
             node's normal reservation/settlement path)     ▼ connection head with the credential
                                                         provider (Venice: api.venice.ai)
```

The three legs: the app speaks HTTP/1.1 to routstrd; routstrd speaks
WebSocket to the node; inside it runs one TLS 1.3 connection from the client
to the provider, whose **framing** is `"2"` (HTTP/2, many sequential requests)
or `"1.1"` (one request). An application never sees the framing.

**One connection (protocol v3, the only protocol; `PROTOCOL-V3.md` §3, §12).**
1. *Offer.* The sidecar's offer file says which framings it serves (`http`,
   in the operator's order; `"2"` needs the `h2` block). The node signs an
   offer with `v: 3`, `http`, `h2`, `twopc: "split-public-1"`,
   `connection_deposit_msat`, `idle_timeout_s` and the v2 fields (host, head
   template, `chat`, `images`, price list, fees). The client verifies it and
   takes the first framing it supports and has not marked bad for the node.
2. *Setup.* `setup {v:3, http, nonce_c, armed, auth, offer_sig}`: no request
   terms. The node checks the credential and **reserves the connection
   deposit**, only then dials the sidecar and forwards the setup without the
   credential. `ready` names the connection (`sid`).
3. *Preprocessing and key share.* The node garbles the key schedule
   (`split-public-1`: 16.4 MB down, 1.1 MB up) and streams it to the client
   (`cu-2pc`); both run the joint P-256 key share. An **armed** connection
   stops here, bound to the credential only; the sidecar has no provider
   connection yet.
4. *Request, framing "1.1".* `request` 1 comes **before** the ClientHello
   (the HTTP/1.1 head names the path and the length): the node reserves it,
   the sidecar answers `request_ok` with the canonical suffix.
5. *Handshake.* The client sends the **canonical ClientHello** (every byte
   fixed by the offer's host, the framing's ALPN and the joint share; only
   the random and the session id are free: `tls_v2::canonical_client_hello`).
   The sidecar dials the provider only now. The key schedule runs jointly:
   the client gets the handshake secrets, `s_ap_0` and `c_ap_1`, the node
   only `K_0, IV_0`. The sidecar verifies the certificate chain, hostname,
   CertificateVerify, both Finished, and for framing "2" that `h2` was
   selected.
6. *Connection head.* The sidecar builds the head record under `K_0`:
   framing "2", the HTTP/2 preface, SETTINGS, WINDOW_UPDATE and a probe GET
   whose header block stores the credential in the provider's HPACK table
   (index 62), reset at once; framing "1.1", request 1's head with the
   credential. π_NK proves to the client that the record matches the
   template (it does not bind other records the node could write in epoch
   0; paper residual risk 1). On `release_head` the sidecar writes it and a
   KeyUpdate in one write (`head_written`).
7. *Request, framing "2".* `request` k (after `settings_seen`): the node
   validates the credential (it may differ from the setup's), freezes the
   named offer's rates and **reserves** a full-context prompt plus
   `max_tokens` (images: `msat_per_image × count`). A refused request
   (`request_refused`) leaves the connection usable and does not use up `n`.
8. *Records.* Framing "2": one HTTP/2 frame per TLS record; HEADERS names
   the credential by index only, DATA carries the body, the canonical suffix
   ends the last one. **The sidecar writes no client record before a π_WIN
   that covers it has verified** (frame headers, the last byte, the whole
   HEADERS record, the suffix), and none beyond the client's `release`.
   Framing "1.1": body records are relayed, the suffix alone in the final
   record is held until a one-window π_WIN verifies. Then `body_released`.
9. *Response and end of a request.* The client decrypts and verifies the
   response. Chat 2xx: `disclose` the usage event, π_C3S. Images 2xx:
   `accept`. Status ≥ 400: `disclose_head` (framing "2": π_WIN under
   `s_ap_0`; "1.1": π_C3S head mode). The sidecar signs an attestation per
   request (sid, n, stream, the request's interval of server records, record
   counts and hashes, both transcript hashes, `c_commit`); the node re-signs
   it, settles, and returns a signed receipt bound to sid, n and the
   attestation. The proofs compare inside the circuit (the node learns one
   bit), and the client checks every proof parameter against its own records
   (`params.ts`, `checkPiWinParams`).
10. *Money.* Usage at the frozen rates (or the flat image price); the session
    fee once per connection, at its first settlement; 429/503 and 401/402/403
    cost the session fee if still due, any other 4xx the abandon fee. The
    **deposit is released by the connection's first settlement**; a
    connection that ends without one is charged the deposit unless the end
    was the node's, the sidecar's or the provider's (§12.10 has every row).
    After `body_released` with no disclosure the reservation is charged, and
    the clients do not retry on another node.
11. *End.* Framing "2" is READY again after a settled 2xx, until
    `h2.max_requests`, `h2.max_lifetime_s`, 1 GiB received, or the idle limit
    (`idle_timeout_s` on the node, `h2.idle_secs` on the sidecar behind it);
    an error head ends the connection (`error_settled`). Framing "1.1" ends
    with `done`. `closed` carries the signed deposit outcome.

**Withdrawal of framing "2"** (§2.1, `H2Guard` in `main.rs`). After 5
consecutive HTTP/2 connections that failed to open, the sidecar drops `"2"`
from `GET /offer` and refuses setups for it (`h2_withdrawn`) for 10 minutes.
The withdrawal is for every client, so only what **no client can cause**
counts: the provider closing without a byte after the canonical ClientHello;
a verified handshake that did not select `h2`; the provider closing within
10 s of the connection head with no client record written and the head
written within 15 s of the dial. The table in `H2Guard`'s doc comment lists
every lever a client has and why it does not count. A client falls back to
"1.1" on the same node by itself (§2.3).

**Image requests** (`kind: "images"`, `docs/CONFIDENTIAL-IMAGES.md`, §0 has
the binding decisions). The same connection and proofs, with these
differences: the offer has `capabilities: ["chat","images"]` and an `images`
block (built by the node from the sidecar offer's `endpoints.images` and
per-image price books; Venice native `/api/v1/image/generate`; `h2.kinds`
says whether framing "2" serves them); the `request` names `variant` and
`count` (1-4) instead of `max_tokens`; the node renders the suffix (model,
count, fixed pins, variant pins) and forwards it to the sidecar, which
checks it byte-exactly; the count key must be the one the route reads
(`variants` for `/image/generate`, `n` for `/images/generations`; sidecar
and clients refuse another); on a 2xx the client sends `accept` after the
response ended and the node charges `msat_per_image × count` plus the
session fee if still due (`settle_flat`); an error head works as for chat.
Live checks: `provider-profile-check.py --images` (I1-I9), `driver.ts
--image`, the image cases of `v3-check.sh`.

**Protocols v1 and v2 are retired.** v1 (the client ran the TLS handshake
alone with X25519; proofs π_C1, π_N, π_C2, π_C3) lives on the `v1-poc`
branch here and the `confidential-upstream` branches of routstr-core and
routstr-sdk. v2 (one session = one request over HTTP/1.1, π_C2S, a
full-context reservation at the setup, 22 MB of 2PC) lives on `twopc-v2`
here and `confidential-2pc` in routstr-core and routstr-sdk; the earlier
dual-execution 2PC is the tag `v2-symmetric`. There is no fallback: a v3 node
answers a v2 socket with `error 426 upgrade_required` (`min_v: 3`), the
sidecar refuses a `setup` without `"v":3` and an offer file naming another
`v`, a v3 client reports `node_protocol_outdated` for an offer with `v < 3`,
and the 2PC channel starts with the tag `routstr-2pc/split-public-1`
(`twopc_version_mismatch`). `docs/V2-V3-ONE-PAGER.md` says what changes for
operators and users.

**Where the code is.**

| Concern | File |
|---|---|
| sidecar: setup, limits, framing "1.1" (`request_11`, `final_record_params`, `disclose_11`), the offer and its validation, `H2Guard` (withdrawal of "2"), error-head disclosure | `crypto/relay/src/main.rs` (`handle_setup`, `handle_control`, `check_hello`, `validate_error_head`; + `tls.rs` handshake verification) |
| sidecar: framing "2" (requests, record hold, π_WIN windows, `release`, `settings_seen`, intervals, disclosures) | `crypto/relay/src/h2_session.rs`, `h2.rs` (connection head, request block, frame rules), `hpack.rs` |
| the canonical ClientHello, the ServerHello checks, the early transcript hashes | `crypto/relay/src/tls_v2.rs` (`canonical_client_hello`, `check_client_hello`) |
| two-party key schedule (`split-public-1`), `cu-2pc` | `crypto/twopc` (`BENCH.md` has the measurements); `docs/TWOPC-NODE-GARBLING.md` |
| chat suffix (offer `chat` block: render + policy) | sidecar `ChatSuffix` in `main.rs`; SDK and web `suffix.ts` (`validateChatSuffix`, `canonicalSuffix`); reference client `offer.ts` (`chatBlockProblem`); shared vectors `chat-suffix-vectors.json` (SDK `tests/unit/fixtures`, web `test/fixtures`) |
| ZK statements / circuits (`pi_nk`, `pi_win`, `pi_c3s`; one-bit equality `eq_bytes`), the proof channel | `crypto/zkbench/src/statements.rs`, `gadgets.rs`, `channel.rs`, `bin/cu-prover.rs` (`--channel`, `--job-stdin`); tests in `zkbench/tests` |
| reference client | `crypto/client/src/driver.ts` (connection, offer checks, flags), `driver-h2.ts` + `h2.ts` (framing "2"), `driver-h11.ts` + `http1.ts` (framing "1.1"), `ctx.ts`, `offer.ts` (suffix, images block, receipt bound), `params.ts` (proof parameter checks); offline checks `src/{h2-selfcheck,h2-conn-test,fork-selfcheck}.ts`, `test/{tls-fork-records-check,offer-check}.ts` |
| node offer (v3 fields, `pin_offer`, `check_request_offer`), model→provider candidate, billing glue (deposit, session fee once per connection; images: `images_offer_block`, `reserve_image`, `settle_flat`) | `routstr-core/routstr/confidential.py` |
| node relay + interception (one path for both framings: setup and deposit, each `request` reserved and settled, the deposit outcome) | `routstr-core/routstr/confidential_ws.py` (`_run_h2_session`) |
| node hooks | `core/main.py` (routes), `core/settings.py` (`CONFIDENTIAL_SIDECAR_URL`, `CONFIDENTIAL_SIDECAR_TOKEN`, `CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT`, `CONFIDENTIAL_IDLE_TIMEOUT_S`), `payment/models.py` (`confidential_upstream` field) |
| SDK transport + connections | `routstr-sdk/client/confidential/{transport,h2,h2conn,h2pool,session,offer,suffix,receipt,hosts,prewarm}.ts`, vendored TLS fork in `tls-fork/` (MIT, see `FORK-NOTES.md`) |
| SDK hooks | `client/RoutstrClient.ts` (`confidential` param, transport branch, `finalize` awaits settlement, `setConfidentialTransport` registry on `globalThis`), `client/resolveRequestContext.ts` (`requireConfidential` filter), `core/types.ts`, `bun.ts`/`node.ts` (register the transport) |
| routstrd hooks | `src/utils/config.ts` (`confidentialUpstream`, with `http2`), `src/daemon/index.ts`, `src/daemon/http/index.ts` (opt-in header → `routeRequests`) |

## Running it locally (real Venice, nothing announced)

**Sidecar and reference client only** (no node, no money; the sidecar signs
stub receipts). This is what `v3-check.sh` and `bench.sh` use.

```bash
P=$(pwd)   # project root
cd $P/crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc
./zkbench/target/release/cu-sidecar --listen 127.0.0.1:7444 --upstream api.venice.ai:443 \
  --key-env VENICE_API_KEY --offer relay/offer.venice.json &
#   offer.venice.json: "http": ["2","1.1"] + the h2 block; offer.venice.http11.json: ["1.1"] only
#   (limits: --max-sessions 32, --max-body 8388608; 15 s setup, 180 s 2PC, 600 s to head_written,
#    600 s per request phase; run files kept --runs-keep-hours 24, 0 = removed at the end)
cd $P/crypto/client && export CU_PROVER=../zkbench/target/release/cu-prover CU_2PC=../zkbench/target/release/cu-2pc
node --experimental-strip-types src/driver.ts --sidecar http://127.0.0.1:7444 \
  --model mistral-small-3-2-24b-instruct --max-tokens 40 --http 2 --requests 3     # or --http 1.1 | auto
#   more: --arm (armed, then "go" on stdin), --image --image-model z-image-turbo, --body-bytes N,
#   --refuse-first, --adv MODE (the attacks of v3-check.sh), --legacy-v2-socket
```

**With a node** (money: deposit, reservations, receipts). The node agent's
gate `crypto/tools/v3-node-check.sh` starts all of this on scratch state by
itself; by hand:

```bash
# mint (fake wallet)
cd /tmp/cu-mint && MINT_BACKEND_BOLT11_SAT=FakeWallet MINT_PRIVATE_KEY=TEST_PRIVATE_KEY \
  MINT_LISTEN_HOST=127.0.0.1 MINT_LISTEN_PORT=3338 MINT_DATABASE=/tmp/cu-mint/data/mint \
  MINT_INPUT_FEE_PPK=0 /tmp/cu-mint-venv/bin/mint &
# sidecar: as above, plus --node-settles (it hands the verified usage to the node)
#   (on loopback no token is needed; off loopback it requires CU_SIDECAR_TOKEN, and the
#    node sends the same value as CONFIDENTIAL_SIDECAR_TOKEN)
# node (routstr-core on confidential-v3): RELAYS points nowhere so nothing is published to
# Nostr. Unset OPENAI_API_KEY, ANTHROPIC_API_KEY and the like first: each one seeds its provider.
cd $P/routstr-core && DATABASE_URL=sqlite+aiosqlite:////tmp/node.db NSEC=<test nsec> \
  CONFIDENTIAL_SIDECAR_URL=http://127.0.0.1:7444 CASHU_MINTS=http://127.0.0.1:3338 \
  UPSTREAM_BASE_URL=https://api.venice.ai/api/v1 UPSTREAM_API_KEY=$VENICE_API_KEY \
  HTTP_URL=http://127.0.0.1:8010 RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false \
  .venv/bin/uvicorn routstr.core.main:app --host 127.0.0.1 --port 8010 --ws-ping-timeout 300 &
#   v3 settings: CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT (default max(abandon fee, session fee, 1000)),
#   CONFIDENTIAL_IDLE_TIMEOUT_S (default 120, at most the sidecar's h2.idle_secs)
# UPSTREAM_BASE_URL seeds a `custom` provider, whose offer has 0 models (its public ids differ
# from the provider's). No env selects `venice`: stop the node after its first start, run this,
# and start it again; the offer's price_list then has the models.
sqlite3 /tmp/node.db "delete from upstream_providers where base_url not like '%venice%'; update upstream_providers set provider_type='venice';"
# credit without a mint (the key is <hex>, the credential sk-<hex>)
sqlite3 /tmp/node.db "insert into api_keys(hashed_key,balance,total_spent,total_requests,reserved_balance) values('<hex>',200000000,0,0,0);"
# reference client (credential: sk- key from /v1/balance/create, or a Cashu token);
# take a model from `curl -s 'http://127.0.0.1:8010/v1/confidential/offer?v=3'` (price_list)
cd $P/crypto/client && node --experimental-strip-types src/driver.ts --node http://127.0.0.1:8010 \
  --model <model from price_list> --max-tokens 40 --http auto --requests 2 --auth <sk-…|cashu…>
```

For routstrd, use a scratch `ROUTSTRD_DIR` and add a `confidentialUpstream`
block (`routstrd/docs/confidential-upstream.md`). Run it with Bun and send
`x-routstr-verify: confidential`.

**Checks.**
- `crypto/tools/v3-check.sh` (**the sidecar + reference client gate**; real
  provider, no node; `CU_V3_PORT` picks the sidecar port): the offline
  self-checks, then 49 cases, both framings: honest (one, several, error
  head, 200 kB body, decoy model, armed, refused-then-good, image), a v2
  socket, every attack (hidden HEADERS, TLS padding, suffix/model/cap swap,
  path, usage replay, image suffix, early record, no proof, own key share,
  2PC version tag), and the forced failure of "2" (fallback, withdrawal,
  return). `v3_eval.py` judges each case from the driver's output and the
  sidecar's own run files; exit ≠ 0 on any deviation. Two paid images
  (`CU_NO_IMAGES=1` skips them).
- `crypto/tools/v3-node-check.sh` + `v3_node_eval.py` (**the node gate, owned
  by the node work in routstr-core `confidential-v3`**): starts a sidecar and
  a node on scratch state and checks every case's money outcome (deposit,
  reservation, fees) in the node's database.
- `crypto/tools/v3-h2-routstrd-check.sh`: sidecar, node, stub mint and a
  scratch routstrd; curl through the local API (sequential, burst, forced
  "1.1"). Needs the SDK and routstrd checkouts built.
- `crypto/tools/provider-profile-check.py` (`--offer FILE --key-env VAR
  --model ID` for another provider): the provider assumptions A1–A13, live
  (A9 = the client's TLS offer, P-256 only; A11 = a KeyUpdate between head
  and body; A12 = the LF-only SSE framing the usage proof parses; A13 = a
  vision model bills an image as prompt tokens); `--images` I1–I9 (three paid
  images); **`--h2` H1–H8** (§5.6: what framing "2" needs; idles one
  connection for `--h2-idle`, default the offer's `h2.idle_secs`, sends one
  body of `--h2-body-bytes`, default 8 MiB, one paid image; ends with
  `offer "2": yes | no, because …`). `--self-test` proves the negative
  controls of A and H offline. Needs OpenSSL ≥ 1.1.1 (`CU_OPENSSL`).
- `crypto/client/bench.sh [runs]` (bytes each way and time to first token:
  cold, armed, open connection, per framing) and `crypto/tools/shape-proxy.py`
  (a rate-limiting TCP proxy to put in front of the sidecar or node for
  shaped-link numbers: `--up-mbit 2 --down-mbit 50 --delay-ms 40`).
- `crypto/tools/adversarial-images.sh`, `stall-repro.sh` (repeated
  connections, fails below a success rate): ported to the v3 driver.
- `crypto/tools/regression-modality.py`: image/data-URI rejection per model (only relevant if you restrict models with the sidecar offer's `model_allowlist`; the shipped offer leaves it empty, since the node reserves a full-context prompt). Vision models are served and FAIL it by design: chat with image input works (`driver.ts --attach`, the PWA's Image button).
- Unit tests:
  - `crypto`: `cargo test --release -p cu-sidecar` (97), `-p zkbench`, `-p twopc`
  - `routstr-core`: `.venv/bin/python -m pytest tests/unit -q`
  - `routstr-sdk`: `npx vitest run`, `npx tsc --noEmit`, `bun test tests/bun` (vitest
    reports those two files as failed: it cannot load `bun:test`)
  - `routstrd`: `bun test`
- Under a sandbox, some routstrd tests fail the same way on `origin/main`
  (subprocess and network tests).
- After a rebase on upstream, run all the unit tests and a live connection (the
  reference driver and the SDK's `fetchConfidential`). Upstream changes can break
  this code without a conflict: `_get_pricing_rates` gained a return value,
  `usable_price_entry` read the resulting error as "unpriced", and the offer had
  no models.

## Protocol v3: state (2026-11-12)

| Part | State |
|---|---|
| `crypto/zkbench`, `crypto/twopc` | done: `pi_nk`, `pi_win`, `pi_c3s`; `split-public-1` with the version tag |
| `crypto/relay` (sidecar) | done; 97 unit tests; `v3-check.sh` clean in one run (49 cases, 2026-11-12). Canonical ClientHello; a failed HTTP/2 open counts only what no client can cause |
| `crypto/client` (reference driver) | done for both framings; run live against the sidecar by `v3-check.sh` and against a node by the node gate |
| `provider-profile-check.py` | A1–A13, `--images` I1–I9 and `--h2` H1–H8 pass against Venice (2026-11-12; H5 with 300 s idle, H6 with 8 MiB) |
| measurements | loopback and shaped links (2/50, 2/10 Mbit/s, 40 ms one way) with `bench.sh` + `shape-proxy.py`: `crypto/PROGRESS-CONFIDENTIAL.md` |
| `routstr-core` (node), `routstr-sdk`, `routstrd` | branches `confidential-v3`, local; their state and commands are reported by the agents working there (`routstr-core/docs/confidential-upstream.md`, `routstrd/docs/confidential-upstream.md`) |
| browser library, PWA | **not ported**: they speak v2 and do not work against a v3 node (their ClientHello is already the canonical `http/1.1` one) |
| deployment | routstr.cypherpunk.today still runs v2; nothing of v3 is pushed or deployed |

Notes that outlive the port: the client needs `cu-2pc` next to `cu-prover`
(or `CU_2PC`). The sidecar dials the provider only when the ClientHello
arrives, so armed connections hold no provider connection. The node's uvicorn
needs `--ws-ping-timeout 300` (`docs/SETUP.md`). routstr-core persists most
settings in its DB, but `confidential_sidecar_url` is env-only (the routes
are mounted at startup), and the node must run as a single worker (offers,
connections and `/zk` admission are per process); it refuses to start in
confidential mode when it detects more than one.

## Browser client (separate repos)

`~/projects/routstr-confidential-web` (github jooray/routstr-confidential-web): the browser library
(`crates/client-wasm` = the client side of `twopc` + proof channel compiled to wasm, vendored copies of
`cu-crypto`/`twopc`/`zkbench` plus a wasm patch in `patches/`; TS package at the root).
`~/projects/routstr-confidential-pwa` (github jooray/routstr-confidential-pwa): the demo PWA, deployed by
GitHub Actions to https://jooray.github.io/routstr-confidential-pwa/ (pins the library by commit:
`node scripts/pin-lib.mjs <sha>`). Changes to `crypto/twopc` or `zkbench` here must be re-vendored there.
Both still speak protocol v2 (branch `twopc-v2` crates); the v3 port is open.

## Gotchas

- **Never log or commit `VENICE_API_KEY`**, node nsecs or Cashu tokens. Scan
  diffs before committing.
- **The sidecar trusts its peer to be the node.** It does not check client
  credentials (the node does, before dialing it), so whoever reaches it spends
  the provider key. Off loopback it requires the node's token
  (`CU_SIDECAR_TOKEN` / `--token-env` on the sidecar, `CONFIDENTIAL_SIDECAR_TOKEN`
  on the node, env-only); never publish its port.
- **Never let a test node announce itself.** Set `RELAYS` to an unreachable
  relay, and stop test nodes when done (a forgotten node without `RELAYS`
  keeps re-announcing). The listing code now skips loopback/private URLs (merged
  upstream, PR #823).
- **Client and node trust the same roots** (the client a subset). The TLS
  fork's `utils/mozilla-root-cas.js` (SDK, `crypto/client/vendor/tls`, web
  library) is generated from the sidecar's pinned `webpki-roots` by
  `crypto/tools/gen-client-roots.py`, which drops the anchors with name
  constraints (the fork cannot enforce them); re-run it on all three copies
  after a `webpki-roots` bump.
- **The reference driver against a remote node** needs `--node-pubkey` (or
  `CU_NODE_PUBKEY`, which the `tools/*.sh` scripts pass through) and an
  https/onion URL; loopback nodes need neither. `--no-verify-offer` needs
  `ROUTSTR_CONFIDENTIAL_INSECURE_TESTING=1`.
- **Rebuild after SDK changes.** routstrd uses the SDK via a
  `node_modules/@routstr/sdk` symlink to `../routstr-sdk`, which loads
  `dist/`, so rebuild it (`npm run build`), then routstrd's own `dist/`
  (`bun run build`), which bundles the SDK.
- **Test a routstrd bundle with `start` or `daemon`, not `--version`.** The CLI
  imports the daemon lazily, so a load-time failure shows only there. The
  `reflect-metadata` import at the top of both entry points must stay first:
  `@peculiar/x509` needs it before tsyringe loads, and in `dist/` its own import
  of it runs too late.
- **Each SDK entrypoint is its own bundle.** The confidential transport is
  registered on a `globalThis` symbol by the Bun/Node entrypoints; the
  browser-safe bundle never imports it.
- **routstrd needs Nostr discovery to fetch a node's models.** It only fetches
  models for discovered nodes, so a private, unannounced node must be in its
  provider list. This is a pre-existing limitation, not confidential-specific.
- **`crypto/` builds into `zkbench/target`** (see `crypto/.cargo/config.toml`).
- **A client can never withdraw framing "2".** If you touch `H2Guard`, the
  ClientHello check or what the sidecar writes before the provider's first
  response, keep the rule: a failed open is only what no client can cause
  (the table in `H2Guard`'s doc comment). The three client stacks must keep
  writing the canonical ClientHello (`tls_v2.rs` has their bytes as a test
  vector); a fork change that adds or reorders an extension breaks every
  connection.
- **Check a provider before offering "2".** `provider-profile-check.py --h2`
  must end in `offer "2": yes` for the offer file you deploy, with the idle
  time you put in `h2.idle_secs`. Never rely on a Venice-specific behaviour:
  everything provider-specific lives in the offer file.
- **Ports.** `v3-check.sh` defaults to 7462 and the node gate to 7461/8431;
  pick others (`CU_V3_PORT`) when several agents work at once, and stop every
  process you start.
- **Open items.**
  - `split-public-1` costs 16.4 MB node→client and 1.1 MB client→node per
    **connection**, plus about 1.5 MB each way for the proof channel's
    correlations; a cold request takes about 12 s on a 2/50 Mbit/s link
    (the uplink is the limit) against about 1.4 s on an armed connection
    and under 1 s on an open one. A cheating node can learn at most
    log2 8 = 3 bits per connection about fresh, single-use values, assuming
    ECtF's semi-honest share conversion leaks nothing beyond its outcome.
    The garbler-only construction, π_WIN and the frame rules have no
    published proof and need external review (`PROTOCOL-V3.md` §4, §10).
  - The sidecar's guard does not see a provider that fails only once a
    request's records arrive (the body is the client's); the profile check
    and the client's fallback cover that.
  - Pre-warming (SDK `client/confidential/prewarm.ts`, routstrd
    `confidentialUpstream.prewarm`): an armed connection is bound to the
    credential only, with one pre-warmed proof channel
    (`/zk?proof=zkchan`, `cu-prover --channel`, `zkbench/src/channel.rs`)
    holding the correlations for π_NK and the first π_WIN and π_C3S;
    per-proof `/zk?proof=pi_*` is the fallback.
  - The browser library and the PWA are not ported to v3.
  - v3 is not pushed, not deployed and not in the upstream PRs; the SDK
    release and routstrd's `@routstr/sdk` bump are the maintainers' step.
  - The sidecar and prover are not yet in any upstream repo.
