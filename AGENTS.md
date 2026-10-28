# AGENTS.md — orientation for agents working in routstr-confidential

**What this is.** A routstr node can serve an LLM request *without seeing the
prompt or the response* and *without giving the client its provider API key*.
The client (routstrd) is the TLS 1.3 client of the provider (Venice); the node
only relays TLS records and writes one record containing its API key. Zero-
knowledge proofs pin what each side may write, and billing uses the usage the
provider itself reported. No trusted hardware, no MPC over the payload.

Start with `paper/paper.md` §4 (protocol) and §8 (how it plugs into routstr),
then this file's "Wiring" section.

## Layout

This directory is the repo **github.com/jooray/routstr-confidential**. The
three routstr repos are separate git checkouts inside it (git-ignored here).
Each has `origin` = Routstr upstream and `fork` = `jooray/<repo>`.

| Path | Git | What |
|---|---|---|
| `routstr-core/` | **`confidential-2pc`** (v2, the only protocol; deployed on routstr.cypherpunk.today); `confidential-upstream` (retired v1, unmaintained) | the node (Python/FastAPI) |
| `routstr-sdk/` | **`confidential-2pc`** (v2 + pre-warming); `confidential-upstream` (retired v1, unmaintained) | client SDK (TypeScript) |
| `routstrd/` | **`confidential-upstream`** (uses the SDK's `confidential-2pc` build; pre-warm config) | client daemon (TypeScript/Bun) |
| `crypto/` | this repo | the protocol implementation: `cu-crypto` (TLS 1.3 key schedule, GCM, RFC 8448/NIST vectors), `twopc` (v2 two-party key schedule + `cu-2pc` binary), `zkbench` (mpz2 VOLE-ZK circuits π_NK, π_C2S, π_C3S; `cu-prover` binary), `relay/` (**cu-sidecar**, the node's Rust side), `client/` (reference TS client `driver.ts`), `tools/` (test scripts), `runs/` (session evidence) |
| `paper/` | — | the paper (`paper.md` → `build.sh` → `paper.pdf`) |
| `docs/` | — | engineering docs and research (below) |

The upstream PRs for protocol v2 are open: core
[#855](https://github.com/Routstr/routstr-core/pull/855), SDK
[#112](https://github.com/Routstr/routstr-sdk/pull/112), routstrd
[#155](https://github.com/Routstr/routstrd/pull/155), from the fork branches
above, rebased on upstream `main` (2026-10-23). The v1 PRs (core #824, SDK
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
| `docs/TWOPC-DESIGN.md` | protocol v2: the two-party handshake, epochs, session flow, the 2PC security model |
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
                       client/confidential/transport.ts → session.ts (TLS fork + cu-prover)
                                   │ WebSocket /v1/confidential/ws (+ /zk per proof)
                                   ▼
            routstr-core confidential_ws.py ──WebSocket──► cu-sidecar (Rust, loopback)
            (billing via the node's normal                  │ TCP :443 relay, writes the
             reservation/settlement path)                   ▼ credential record
                                                         Venice (api.venice.ai)
```

**One session (protocol v2, the only protocol).**
1. *Setup.* The client sends its ordinary node credential (`sk-` key or Cashu
   token) in `setup.auth` and the signature of the offer it verified in
   `setup.offer_sig`. The node validates the setup and the credential
   (`validate_bearer_key`), freezes that offer's rates, reserves a full-context
   prompt plus the pinned `max_tokens` (`pay_for_request`), and only then
   dials the sidecar and forwards the setup *without* the credential.
2. *Preprocessing and key share.* The node garbles the key-schedule circuits
   and streams them to the client (`cu-2pc`); both run the joint P-256 key
   share. A pre-warmed ("armed") session stops here and waits for a request.
   The sidecar has no provider connection yet.
3. *Handshake.* The client's ClientHello must carry exactly the joint share;
   the sidecar dials Venice only now. The two parties run the key schedule
   jointly: the client gets the handshake secrets, `s_ap_0` and `c_ap_1`, the
   node gets only `K_0, IV_0`. The sidecar verifies the certificate chain,
   hostname, CertificateVerify and both Finished messages.
4. *Credential record.* The sidecar builds the head record with the API key
   under `K_0`; π_NK proves to the client that the head record's content
   matches the published template (it does not bind other records the node
   could write in epoch 0; paper residual risk 1). On the client's `release_head` the sidecar writes it and a
   KeyUpdate (epoch 0) in one write.
5. *Body.* The client sends the body under `c_ap_1`, with the pinned JSON
   suffix (model, caps, …) as its own final record. The suffix is described
   by the offer's `chat` block (cap keys + fixed pins, from the sidecar offer
   file; `docs/CHAT-SUFFIX.md` has the rendering and the policy clients hold
   it to). **The sidecar holds that record until π_C2S proves it is the
   canonical suffix**, so Venice cannot start on anything else.
6. *Response.* It streams back; the client decrypts and verifies it. When
   Venice closes the connection the sidecar signs an attestation (sid,
   certificate-chain hash, both handshake transcript hashes, record counts
   (the client's body records, every server record)
   and SHA-256 of all bytes in each direction, `c_commit`, time) with its
   per-process Ed25519 key; the node re-signs it with its Nostr key, and the
   client checks that signature and that the sid and transcript hashes are
   its own.
7. *Settlement.* π_C3S proves the disclosed usage event (or, for an upstream
   HTTP error, only the response head; the body stays private). The node
   charges the usage at the frozen offer rates (EHBP's
   `finalize_ehbp_actual_cost_payment`), or releases the reservation for an
   upstream refusal (less the session fee for 429/503 and for 401/402/403,
   the node's own provider key or account; less the abandon fee for any other
   4xx), and returns a signed receipt bound to the sid and attestation.
   π_C2S/π_C3S compare inside the circuit (the node learns one bit), and the
   client checks every proof parameter against its own records (`params.ts`).
8. *Abort.* Before the final body record is released: release (less any
   abandon fee). After it, with no disclosure: charge the reservation.

**Image sessions** (`kind: "images"`, `docs/CONFIDENTIAL-IMAGES.md`, §0 has
the binding decisions). Same steps and circuits, with these differences: the
offer has `capabilities: ["chat","images"]` and an `images` block (built by
the node from the sidecar offer's `endpoints.images` and per-image price
books; Venice native `/api/v1/image/generate`); the setup names `variant`
and `count` (1-4) instead of `max_tokens` and is never armed; the node
renders the suffix (model, count, fixed pins, variant pins) and forwards it
to the sidecar, which checks it byte-exactly; the credential record uses the
images head template; on a 2xx the client sends `accept` instead of a usage
disclosure and the node charges `msat_per_image × count + f_s` (`settle_flat`);
an error head works as for chat. Live check: `provider-profile-check.py
--images` (I1-I9), `driver.ts --image`.

**Protocol v1 is retired.** The earlier design (the client ran the TLS
handshake alone with X25519; proofs π_C1, π_N, π_C2, π_C3; the client's KU1)
is no longer in the code here, in routstr-core or in routstr-sdk. It lives on
the `v1-poc` branch here and the `confidential-upstream` branches of
routstr-core and routstr-sdk. The sidecar refuses `--protocol 1`, the node
offers only `v = 2` and closes a `v=1` session socket, and the SDK refuses an
offer without v2 (`offer_unsupported_version`).

**Where the code is.**

| Concern | File |
|---|---|
| sidecar state machine, setup gate and limits, record hold, tail anchoring, error-head disclosure | `crypto/relay/src/main.rs` (`handle_setup`, `handle_control`, `validate_error_head`; + `tls.rs` handshake verification) |
| chat suffix (offer `chat` block: render + policy) | sidecar `ChatSuffix` in `main.rs`; SDK and web `suffix.ts` (`validateChatSuffix`, `canonicalSuffix`); `driver.ts` (`chatBlockProblem`); shared vectors `chat-suffix-vectors.json` (SDK `tests/unit/fixtures`, web `test/fixtures`) |
| ZK statements / circuits (one-bit equality `eq_bytes`) | `crypto/zkbench/src/statements.rs`, `gadgets.rs`, `bin/cu-prover.rs` (`--job-stdin`); tests `tests/v2.rs`, `tests/malformed.rs` |
| node offer, model→provider candidate, billing glue (images: `images_offer_block`, `reserve_image`, `settle_flat`) | `routstr-core/routstr/confidential.py` |
| node relay + interception | `routstr-core/routstr/confidential_ws.py` |
| node hooks | `core/main.py` (routes), `core/settings.py` (`CONFIDENTIAL_SIDECAR_URL`, `CONFIDENTIAL_SIDECAR_TOKEN`), `payment/models.py` (`confidential_upstream` field) |
| SDK transport + session | `routstr-sdk/client/confidential/{transport,session,offer,suffix,receipt,hosts}.ts`, vendored TLS fork in `tls-fork/` (MIT, see `FORK-NOTES.md`) |
| SDK hooks | `client/RoutstrClient.ts` (`confidential` param, transport branch, `finalize` awaits settlement, `setConfidentialTransport` registry on `globalThis`), `client/resolveRequestContext.ts` (`requireConfidential` filter), `core/types.ts`, `bun.ts`/`node.ts` (register the transport) |
| routstrd hooks | `src/utils/config.ts` (`confidentialUpstream`), `src/daemon/index.ts`, `src/daemon/http/index.ts` (opt-in header → `routeRequests`) |

## Running it locally (real Venice, nothing announced)

```bash
P=$(pwd)   # project root, with routstr-core/, routstr-sdk/, routstrd/ checked out inside
# mint (fake wallet)
cd /tmp/cu-mint && MINT_BACKEND_BOLT11_SAT=FakeWallet MINT_PRIVATE_KEY=TEST_PRIVATE_KEY \
  MINT_LISTEN_HOST=127.0.0.1 MINT_LISTEN_PORT=3338 MINT_DATABASE=/tmp/cu-mint/data/mint \
  MINT_INPUT_FEE_PPK=0 /tmp/cu-mint-venv/bin/mint &
# sidecar
cd $P/crypto && cargo build --release -p cu-sidecar -p zkbench
./zkbench/target/release/cu-sidecar --listen 127.0.0.1:7444 --upstream api.venice.ai:443 \
  --key-env VENICE_API_KEY --offer relay/offer.venice.json --node-settles &
#   (limits: --max-sessions 32, --max-body 8388608; 15 s setup / 600 s session timeouts;
#    run files kept --runs-keep-hours 24, 0 = removed at the session's end)
#   (on loopback no token is needed; off loopback it requires CU_SIDECAR_TOKEN, and the
#    node sends the same value as CONFIDENTIAL_SIDECAR_TOKEN)
# node: RELAYS points nowhere so nothing is published to Nostr
cd $P/routstr-core && DATABASE_URL=sqlite+aiosqlite:////tmp/node.db NSEC=<test nsec> \
  CONFIDENTIAL_SIDECAR_URL=http://127.0.0.1:7444 CASHU_MINTS=http://127.0.0.1:3338 \
  UPSTREAM_BASE_URL=https://api.venice.ai/api/v1 UPSTREAM_API_KEY=$VENICE_API_KEY \
  HTTP_URL=http://127.0.0.1:8010 RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false \
  .venv/bin/uvicorn routstr.core.main:app --host 127.0.0.1 --port 8010 &
# reference client (credential: sk- key from /v1/balance/create, or a Cashu token)
cd $P/crypto/client && CU_PROVER=../zkbench/target/release/cu-prover node --experimental-strip-types \
  src/driver.ts --node http://127.0.0.1:8010 --model hermes-3-llama-3.1-405b --max-tokens 40 --auth <sk-…|cashu…>
```

For routstrd, use a scratch `ROUTSTRD_DIR` and add a `confidentialUpstream`
block (`routstrd/docs/confidential-upstream.md`). Run it with Bun and send
`x-routstr-verify: confidential`.

**Checks.**
- `crypto/tools/provider-profile-check.py`: the provider assumptions A1–A13,
  live (A12 = the LF-only SSE framing the usage proof parses; A13 = a vision
  model bills an image as prompt tokens, so chat with image input settles
  correctly); `--self-test` proves the negative controls.
- `crypto/tools/regression-modality.py`: image/data-URI rejection per model (only relevant if you restrict models with the sidecar offer's `model_allowlist`; the shipped offer leaves it empty, since the node reserves a full-context prompt). Vision models are served and FAIL it by design: chat with image input works (`driver.ts --attach`, the PWA's Image button).
- `crypto/tools/adversarial-model-swap.sh` (with `AUTH=… CU_NODE=…
  NODE_LOG=routstr-core/logs/app_<date>.log` on a dedicated node): the
  model/cap swap attacks plus an honest control, as a gate (exit ≠ 0 on any
  deviation).
- `crypto/tools/stall-repro.sh`: repeated sessions, fails below a success rate.
- Unit tests:
  - `routstr-core`: `.venv/bin/python -m pytest tests/unit -q`
  - `routstr-sdk`: `npx vitest run`, `npx tsc --noEmit`
  - `routstrd`: `bun test`
- Under a sandbox, some routstrd tests fail the same way on `origin/main`
  (subprocess and network tests).

## Protocol v2 (branch `twopc-v2`)

v2 closes P1: client and node run the TLS 1.3 key schedule as a two-party
computation, so the client never holds the key of the credential record
(`docs/TWOPC-DESIGN.md`, trade-offs in `docs/V1-V2-ONE-PAGER.md`). Branches:
`twopc-v2` here, `confidential-2pc` in routstr-core and routstr-sdk (routstrd
needs no change). Pieces: `crypto/twopc` (ECtF + the key schedule as
node-only authenticated garbling: N garbles with three-halves tables, its
wire masks are authenticated to C by IT-MACs from Ferret COTs, C runs a
salted 64-bit consistency check of every AND gate before using any output;
`cu-2pc` binary for the client; construction, security argument and cuts in
`docs/TWOPC-NODE-GARBLING.md`, measurements in `crypto/twopc/BENCH.md`),
`zkbench` statements
(`pi_nk`, `pi_c2s`, `pi_c3s`), the sidecar (`relay/src/tls_v2.rs`
checks the ClientHello carries exactly the joint P-256 share; `--protocol 2`
is accepted but optional), the TLS fork's `external` hooks, `driver.ts` and
the SDK `session.ts`. The client needs `cu-2pc` next to `cu-prover` (or
`CU_2PC`). The sidecar dials the provider
only when the ClientHello arrives, so pre-warmed (armed) sessions hold no
provider connection. The node's uvicorn needs `--ws-ping-timeout 300`
(docs/SETUP.md). This branch (`twopc-v2`) is the repo's default branch; the
v1 proof of concept is the `v1-poc` branch. The earlier dual-execution 2PC
(both parties garble, label equality check; ~21 MB upload per session) is
the tag `v2-symmetric` in this repo, routstr-core and routstr-sdk. Note:
routstr-core persists most settings in its DB, but `confidential_sidecar_url`
is env-only (the routes are mounted at startup), and the node must run as a
single worker (offers, sessions and `/zk` admission are per process); it
refuses to start in confidential mode when it detects more than one.

## Browser client (separate repos)

`~/projects/routstr-confidential-web` (github jooray/routstr-confidential-web): the browser library
(`crates/client-wasm` = the client side of `twopc` + proof channel compiled to wasm, vendored copies of
`cu-crypto`/`twopc`/`zkbench` plus a wasm patch in `patches/`; TS package at the root).
`~/projects/routstr-confidential-pwa` (github jooray/routstr-confidential-pwa): the demo PWA, deployed by
GitHub Actions to https://jooray.github.io/routstr-confidential-pwa/ (pins the library by commit:
`node scripts/pin-lib.mjs <sha>`). Changes to `crypto/twopc` or `zkbench` here must be re-vendored there.

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
  `dist/`, so rebuild it (`npm run build`).
- **Each SDK entrypoint is its own bundle.** The confidential transport is
  registered on a `globalThis` symbol by the Bun/Node entrypoints; the
  browser-safe bundle never imports it.
- **routstrd needs Nostr discovery to fetch a node's models.** It only fetches
  models for discovered nodes, so a private, unannounced node must be in its
  provider list. This is a pre-existing limitation, not confidential-specific.
- **`crypto/` builds into `zkbench/target`** (see `crypto/.cargo/config.toml`).
- **Open items.**
  - v2's 2PC costs ~22 MB node→client and ~1.2 MB
    client→node per request (cold ~7.4 s on a 2/50 Mbit/s link), and a
    cheating node can learn ≤ log2 6 ≈ 2.6 bits per session about fresh,
    single-use values. The garbler-only variant has no published proof and
    needs external review (`docs/TWOPC-DESIGN.md`, "Security model").
  - Pre-warming (SDK `client/confidential/prewarm.ts`, routstrd
    `confidentialUpstream.prewarm`) arms sessions up to the joint key share
    only while there is traffic, plus one pre-warmed proof channel per
    session (`/zk?proof=zkchan`, `cu-prover --channel`,
    `zkbench/src/channel.rs`) holding the OT/VOLE correlations for π_NK,
    π_C2S and π_C3S; per-proof `/zk?proof=pi_*` is the fallback. The
    browser library keeps one armed session and arms only after a first
    chat request with the current key.
  - The SDK release (version bump) and routstrd's `@routstr/sdk` bump are
    the maintainers' step.
  - The sidecar and prover are not yet in any upstream repo.
