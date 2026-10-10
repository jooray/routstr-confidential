# AGENTS.md — orientation for agents working in routstr-confidential

**What this is.** A routstr node can serve an LLM request *without seeing the
prompt or the response* and *without giving the client its provider API key*.
The client (routstrd) is the TLS 1.3 client of the provider (Venice); the node
only relays TLS records and writes one record containing its API key. Zero-
knowledge proofs pin what each side may write, and billing uses the usage the
provider itself reported. No trusted hardware, no MPC over the payload.

Start with `paper/paper.md` §4 (protocol) and §7 (how it plugs into routstr),
then this file's "Wiring" section.

## Layout

This directory is the repo **github.com/jooray/routstr-confidential**. The
three routstr repos are separate git checkouts inside it (git-ignored here).
Each has `origin` = Routstr upstream and `fork` = `jooray/<repo>`.

| Path | Git | What |
|---|---|---|
| `routstr-core/` | branch **`confidential-upstream`** → PR [Routstr/routstr-core#824](https://github.com/Routstr/routstr-core/pull/824); **`fix/no-announce-unroutable-urls`** → PR [#823](https://github.com/Routstr/routstr-core/pull/823) | the node (Python/FastAPI) |
| `routstr-sdk/` | branch **`confidential-upstream`** → PR [Routstr/routstr-sdk#90](https://github.com/Routstr/routstr-sdk/pull/90) | client SDK (TypeScript) |
| `routstrd/` | branch **`confidential-upstream`** → PR [Routstr/routstrd#137](https://github.com/Routstr/routstrd/pull/137) | client daemon (TypeScript/Bun) |
| `crypto/` | this repo | the protocol implementation: `cu-crypto` (TLS 1.3 key schedule, GCM, RFC 8448/NIST vectors), `zkbench` (mpz2 VOLE-ZK circuits π_C1, π_N, π_C2, π_C3 + `cu-prover` binary), `relay/` (**cu-sidecar**, the node's Rust side), `client/` (reference TS client `driver.ts`), `tools/` (test scripts), `runs/` (session evidence) |
| `paper/` | — | the paper (`paper.md` → `build.sh` → `paper.pdf`) |
| `docs/` | — | engineering docs and research (below) |

Each confidential branch is one commit on `origin/main`. Merge order: SDK
first and release it; then routstrd (bump `@routstr/sdk`); the node PR and
#823 are independent. Local-only branches `confidential-upstream-on-tlsn`
(core, SDK) are pre-rebase snapshots on top of unmerged TLSN work. Ignore
them.

## Docs map

| File | Read it for |
|---|---|
| `docs/ONE-PAGER.md` / `.pdf` | the user-facing summary (three common objections) |
| `docs/APPROACH.md` | engineering overview: properties, components, negotiation, pre-warm |
| `docs/ADVERSARIAL-QA.md` | model binding, provider transferability (OpenRouter, Groq…), what the node learns, cost bounds (starts with a current-state box) |
| `docs/REVIEW-2026-10-09.md` | every bug found and fixed (numbered findings), measurements, the plug-in refactor (§8) |
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

**One session.**
1. *Setup.* The client sends its ordinary node credential (`sk-` key or Cashu
   token) in `setup.auth` and the signature of the offer it verified in
   `setup.offer_sig`. The node validates the setup and the credential
   (`validate_bearer_key`), freezes that offer's rates, reserves a full-context
   prompt plus the pinned `max_tokens` (`pay_for_request`), and only then
   dials the sidecar and forwards the setup *without* the credential. The
   sidecar opens no provider connection before a valid setup.
2. *Handshake.* The client does the TLS handshake with Venice through the relay
   and discloses only the handshake traffic secrets. The sidecar verifies the
   certificate chain, hostname, CertificateVerify and both Finished messages.
3. *Credential record.* KeyUpdate. π_C1 proves the one-shot record material.
   The sidecar writes the head record with the API key; π_N proves to the
   client that it matches the published template. Then KU1.
4. *Body.* The client sends the body, with the pinned JSON suffix (model, caps,
   …) as its own final record. **The sidecar holds that record until π_C2
   proves it is the canonical suffix**, so Venice cannot start on anything
   else.
5. *Response.* It streams back; the client decrypts and verifies it.
6. *Settlement.* π_C3 proves the disclosed usage event (or, for an upstream
   HTTP error, only the response head; the body stays private). The node
   charges the usage at the frozen offer rates (EHBP's
   `finalize_ehbp_actual_cost_payment`), or releases the reservation for a
   4xx/503, and returns a signed receipt bound to the sid and attestation.
   π_C2/π_C3 compare inside the circuit (the node learns one bit), and the
   client checks every proof parameter against its own records (`params.ts`).
7. *Abort.* Before the record is released: release. After it, with no
   disclosure: charge the reservation.

**Where the code is.**

| Concern | File |
|---|---|
| sidecar state machine, setup gate and limits, record hold, tail anchoring, error-head disclosure | `crypto/relay/src/main.rs` (`handle_setup`, `handle_control`, `validate_error_head`; + `tls.rs` handshake verification) |
| ZK statements / circuits (one-bit equality `eq_bytes`) | `crypto/zkbench/src/statements.rs`, `gadgets.rs`, `bin/cu-prover.rs` (`--job-stdin`); tests `tests/disclosure.rs` |
| node offer, model→provider candidate, billing glue | `routstr-core/routstr/confidential.py` |
| node relay + interception | `routstr-core/routstr/confidential_ws.py` |
| node hooks | `core/main.py` (routes), `core/settings.py` (`CONFIDENTIAL_SIDECAR_URL`), `payment/models.py` (`confidential_upstream` field) |
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
#   (limits: --max-sessions 32, --max-body 8388608; 15 s setup / 600 s session timeouts)
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
block (`routstrd/docs/confidential-upstream.md`). Run it with Bun ≥ 1.4 and send
`x-routstr-verify: confidential`.

**Checks.**
- `crypto/tools/provider-profile-check.py`: the provider assumptions A1–A11,
  live (11/11); `--self-test` proves the negative controls.
- `crypto/tools/regression-modality.py`: image/data-URI rejection per model.
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
needs no change). Pieces: `crypto/twopc` (ECtF + dual-execution garbled
key schedule, `cu-2pc` binary for the client), `zkbench` v2 statements
(`pi_nk`, `pi_c2s`, `pi_c3s`), sidecar `--protocol 2` (`relay/src/tls_v2.rs`
checks the ClientHello carries exactly the joint P-256 share), the TLS fork's
`external` hooks, and the v2 paths in `driver.ts` / the SDK `session.ts`.
Run a v2 stack like the v1 one with `--protocol 2` on the sidecar; the client
needs `cu-2pc` next to `cu-prover` (or `CU_2PC`). Note: routstr-core persists
settings in its DB, so a copied DB keeps the old `confidential_sidecar_url`.

## Gotchas

- **Never log or commit `VENICE_API_KEY`**, node nsecs or Cashu tokens. Scan
  diffs before committing.
- **Never let a test node announce itself.** Set `RELAYS` to an unreachable
  relay, and stop test nodes when done (a forgotten node without `RELAYS`
  keeps re-announcing). The listing code now skips loopback/private URLs (the
  `fix/no-announce-unroutable-urls` branch).
- **Rebuild after SDK changes.** routstrd uses the SDK via a
  `node_modules/@routstr/sdk` symlink to `../routstr-sdk`, which loads
  `dist/`, so rebuild it (`npm run build`).
- **Each SDK entrypoint is its own bundle.** The confidential transport is
  registered on a `globalThis` symbol by the Bun/Node entrypoints; the
  browser-safe bundle never imports it.
- **Bun < 1.4 lacks WebCrypto X25519.** The session fails fast with a clear
  error.
- **routstrd needs Nostr discovery to fetch a node's models.** It only fetches
  models for discovered nodes, so a private, unannounced node must be in its
  provider list. This is a pre-existing limitation, not confidential-specific.
- **`crypto/` builds into `zkbench/target`** (see `crypto/.cargo/config.toml`).
- **Open items.**
  - P1 rests on the client never seeing the N→U ciphertext (paper §5); a 2PC
    handshake would remove that, as a new protocol version.
  - routstrd does not pre-warm.
  - The SDK release (version bump) and routstrd's `@routstr/sdk` bump are
    the maintainers' step.
  - The sidecar and prover are not yet in any upstream repo.
