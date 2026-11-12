# routstr-confidential

Confidential and verifiable upstream inference for [Routstr](https://github.com/Routstr). A node can serve an LLM request:

- **without seeing the prompt or the response**;
- **without giving its upstream API key to the client**;
- running **exactly the model and token limit the client asked for**;
- with **billing tied to the usage the provider itself reported**.

It needs only standard TLS 1.3, a two-party computation of the handshake key schedule and interactive zero-knowledge proofs: no trusted hardware, no MPC over the payload.

The client is the TLS 1.3 client of the provider *through* the node. Client and node compute the TLS keys jointly, so the node alone gets the key for the one record that carries its API key and the client alone gets the keys for the prompt and the response. The node relays the other encrypted records. Zero-knowledge proofs pin what each side may write.

## Status: protocol v3

The protocol is **v3** ([`PROTOCOL-V3.md`](PROTOCOL-V3.md), the normative specification). The unit is a **connection** that carries **requests**: the two-party handshake is paid once per connection, not once per request.

- Two framings, listed by the operator in the node's signed offer in order of preference. **`"2"` (HTTP/2):** the node writes its API key once, in the connection's opening; it then sits in the provider's HPACK table and each later request, written by the client, names it by a one-byte index. Requests are sequential on a connection, and the client keeps connections in a pool. **`"1.1"` (HTTP/1.1):** one request per connection, v2's flow. A client falls back from `"2"` to `"1.1"` on the same node when an HTTP/2 connection fails before a body was released.
- A smaller two-party key schedule (`split-public-1`): 16.4 MB node→client instead of 22.1 MB.
- One client statement, **π_WIN**, replaces π_C2S: the node holds every client record until it verifies.
- Money: a connection deposit at the setup, a reservation per request, the session fee once per connection.
- **v3 only.** A v3 node answers a v2 client with `upgrade_required`; a v3 client reports `node_protocol_outdated` for a v2-only node. v2 (one handshake per request) is retired and archived on the branch `v2` here and `confidential-v2` in routstr-core, routstr-sdk and routstrd; v1 (no two-party computation) on `v1-poc`.
- Limits: π_WIN, the HTTP/2 frame rules and the key schedule have had no external review; one provider (Venice) was tested; requests on one HTTP/2 connection are linkable for the provider.

What changed and how to upgrade: [`docs/V2-V3-ONE-PAGER.md`](docs/V2-V3-ONE-PAGER.md). The reasoning: [`PROTOCOL-V3-DRAFT.md`](PROTOCOL-V3-DRAFT.md). The paper describes the guarantees and the two-party handshake.

- **Introduction (blog post):** [Confidential inference on Routstr without trusted hardware](https://juraj.bednar.io/en/blog-en/2026/10/10/confidential-inference-on-routstr-without-trusted-hardware/).
- **Programmer's guide (book):** [How routstr confidential mode works](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-for-programmers.pdf) (PDF, 72 pages; in Slovak: [Ako funguje dôverný režim routstr](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-pre-programatorov.pdf)).
- **The protocol as a magic show (blog post):** [Seven magic tricks inside one AI request](https://juraj.bednar.io/en/blog-en/2026/10/12/seven-magic-tricks-inside-one-ai-request/), with an illustrated video (in Slovak: [Sedem kúzelníckych trikov v jednej AI požiadavke](https://juraj.bednar.io/blog/2026/10/12/sedem-kuzelnickych-trikov-v-jednej-ai-poziadavke/)).
- **Paper:** [`paper/paper.pdf`](paper/paper.pdf).
- **User-facing summary:** [`docs/ONE-PAGER.pdf`](docs/ONE-PAGER.pdf).
- **New here (human or agent)?** Read [`AGENTS.md`](AGENTS.md).

## What is here

| Path | What |
|---|---|
| `crypto/relay` | **cu-sidecar**: the node-side Rust process that relays TLS, verifies the handshake, writes the connection head with the credential (HTTP/2 or HTTP/1.1), holds the client's records until π_WIN verifies, and verifies the client's proofs |
| `crypto/twopc` | the two-party TLS key schedule `split-public-1` (P-256 share conversion, then node-only authenticated garbling: the node garbles with three-halves tables, the client checks every gate against IT-MACs on the node's wire masks) and the client-side `cu-2pc` binary. Design: [`docs/TWOPC-DESIGN.md`](docs/TWOPC-DESIGN.md), [`docs/TWOPC-NODE-GARBLING.md`](docs/TWOPC-NODE-GARBLING.md); the earlier dual-execution version is the tag `v2-symmetric` |
| `crypto/zkbench` | VOLE-ZK circuits (mpz2) for π_NK, π_WIN, π_C3S and the **`cu-prover`** binary used by clients |
| `crypto/cu-crypto` | TLS 1.3 key schedule and AES-GCM record math (RFC 8448 / NIST vectors) |
| `crypto/client` | reference TypeScript client (`driver.ts`) |
| `crypto/tools` | validation gates, each exits non-zero on any deviation: `provider-profile-check.py` (live provider-profile gate A1–A13, incl. the pinned TLS suite, a mid-request KeyUpdate and the LF-only SSE framing), `regression-modality.py` (optional: the given models reject image URL and data-URI parts, for a text-only offer), `adversarial-model-swap.sh` (malicious-client attack cases plus an honest control), `stall-repro.sh` (N cold sessions, success-rate threshold); for v3 `provider-profile-check.py --h2` (what HTTP/2 framing needs from a provider), `v3-check.sh`, `v3-node-check.sh` and `v3-routstrd-check.sh` (honest cases, attacks and the money outcome, against a sidecar, a node and routstrd). Also `probe-modality.py` (exploratory modality/token-amplification probe) and `cu_cashu.py` (test-mint helper: mint, balance, redeem) |
| `paper/` | the paper (`paper.md` → `build.sh`) |
| `PROTOCOL-V3.md` | the protocol specification (lifecycle, framings, key schedule, proofs, money, wire format) |
| `docs/` | `APPROACH.md` (engineering overview), `V2-V3-ONE-PAGER.md` (what changed, how to upgrade), `ADVERSARIAL-QA.md`, `TWOPC-DESIGN.md`, `CHAT-SUFFIX.md`, `CONFIDENTIAL-IMAGES.md`, `SETUP.md`, `REVIEW-2026-10-09.md` (findings and fixes), `ONE-PAGER.md` |

## Routstr integration (branches)

Protocol v3 is on the branch `main` here and on the fork branches below, which are the pull requests open
upstream (core [#855](https://github.com/Routstr/routstr-core/pull/855), SDK
[#112](https://github.com/Routstr/routstr-sdk/pull/112), routstrd
[#155](https://github.com/Routstr/routstrd/pull/155)). The node at routstr.cypherpunk.today runs v3 since
2026-11-12. To try it: [`docs/SETUP.md`](docs/SETUP.md).

| Repo | Branch | What |
|---|---|---|
| [jooray/routstr-core](https://github.com/jooray/routstr-core/tree/confidential-2pc) | `confidential-2pc` | v3 node side: offer, connection deposit, per-request reservation and settlement; inert until `CONFIDENTIAL_SIDECAR_URL` is set |
| [jooray/routstr-sdk](https://github.com/jooray/routstr-sdk/tree/confidential-2pc) | `confidential-2pc` | v3 client transport: both framings, the HTTP/2 pool, pre-warm |
| [jooray/routstrd](https://github.com/jooray/routstrd/tree/confidential-upstream) | `confidential-upstream` | v3 opt-in header and config (`confidentialUpstream`, incl. `http2`, `prewarm`); the local OpenAI API is unchanged |

The retired protocol v2 is archived on `confidential-v2` in all three forks. In this repo protocol v3 is the default branch `main`; `v2` holds the retired protocol v2 (the same as the old `twopc-v2`) and `v1-poc` the retired v1 proof of concept.

## In the browser

A browser version runs the same client (2PC and proofs in WebAssembly) inside a static web page:
library [jooray/routstr-confidential-web](https://github.com/jooray/routstr-confidential-web), demo PWA
[jooray/routstr-confidential-pwa](https://github.com/jooray/routstr-confidential-pwa), live at
<https://jooray.github.io/routstr-confidential-pwa/>. Both speak protocol v3 (branch `main`; v2 is archived on their `v2` branches).

## Build

```bash
cd crypto
cargo build --release -p cu-sidecar -p zkbench   # cu-sidecar + cu-prover in zkbench/target/release/
cargo test --release -p cu-crypto -p zkbench
```

Running a node with the sidecar, routstrd setup and the test scripts: [`AGENTS.md`](AGENTS.md) and [`crypto/PROGRESS-CONFIDENTIAL.md`](crypto/PROGRESS-CONFIDENTIAL.md).

## License

MIT (see `LICENSE`). The vendored TLS library under `crypto/client/vendor/tls` is MIT, © CreatorOS Inc.
