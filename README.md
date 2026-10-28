# routstr-confidential

Confidential and verifiable upstream inference for [Routstr](https://github.com/Routstr). A node can serve an LLM request:

- **without seeing the prompt or the response**;
- **without giving its upstream API key to the client**;
- running **exactly the model and token limit the client asked for**;
- with **billing tied to the usage the provider itself reported**.

It needs only standard TLS 1.3, a two-party computation of the handshake key schedule and interactive zero-knowledge proofs: no trusted hardware, no MPC over the payload.

The client is the TLS 1.3 client of the provider *through* the node. Client and node compute the TLS keys jointly, so the node alone gets the key for the one record that carries its API key and the client alone gets the keys for the prompt and the response. The node relays the other encrypted records. Zero-knowledge proofs pin what each side may write. An earlier single-party variant (v1, no two-party computation) is retired; the paper explains the trade-off, and v1 remains on the `v1-poc` branch.

- **Introduction (blog post):** [Confidential inference on Routstr without trusted hardware](https://juraj.bednar.io/en/blog-en/2026/10/10/confidential-inference-on-routstr-without-trusted-hardware/).
- **Programmer's guide (book):** [How routstr confidential mode works](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-for-programmers.pdf) (PDF, 72 pages; in Slovak: [Ako funguje dôverný režim routstr](https://juraj.bednar.io/wp-content/uploads/2026/10/routstr-confidential-pre-programatorov.pdf)).
- **The protocol as a magic show (blog post):** [Seven magic tricks inside one AI request](https://juraj.bednar.io/en/blog-en/2026/10/12/seven-magic-tricks-inside-one-ai-request/), with an illustrated video (in Slovak: [Sedem kúzelníckych trikov v jednej AI požiadavke](https://juraj.bednar.io/blog/2026/10/12/sedem-kuzelnickych-trikov-v-jednej-ai-poziadavke/)).
- **Paper:** [`paper/paper.pdf`](paper/paper.pdf).
- **User-facing summary:** [`docs/ONE-PAGER.pdf`](docs/ONE-PAGER.pdf).
- **New here (human or agent)?** Read [`AGENTS.md`](AGENTS.md).

## What is here

| Path | What |
|---|---|
| `crypto/relay` | **cu-sidecar**: the node-side Rust process that relays TLS, verifies the handshake, holds the request's final record until the suffix proof verifies, writes the credential record, and verifies the client's proofs |
| `crypto/twopc` | the two-party TLS key schedule (P-256 share conversion, then node-only authenticated garbling: the node garbles with three-halves tables, the client checks every gate against IT-MACs on the node's wire masks) and the client-side `cu-2pc` binary. Design: [`docs/TWOPC-DESIGN.md`](docs/TWOPC-DESIGN.md), [`docs/TWOPC-NODE-GARBLING.md`](docs/TWOPC-NODE-GARBLING.md); the earlier dual-execution version is the tag `v2-symmetric` |
| `crypto/zkbench` | VOLE-ZK circuits (mpz2) for π_NK, π_C2S, π_C3S and the **`cu-prover`** binary used by clients |
| `crypto/cu-crypto` | TLS 1.3 key schedule and AES-GCM record math (RFC 8448 / NIST vectors) |
| `crypto/client` | reference TypeScript client (`driver.ts`) |
| `crypto/tools` | validation gates, each exits non-zero on any deviation: `provider-profile-check.py` (live provider-profile gate A1–A13, incl. the pinned TLS suite, a mid-request KeyUpdate and the LF-only SSE framing), `regression-modality.py` (optional: the given models reject image URL and data-URI parts, for a text-only offer), `adversarial-model-swap.sh` (malicious-client attack cases plus an honest control), `stall-repro.sh` (N cold sessions, success-rate threshold). Also `probe-modality.py` (exploratory modality/token-amplification probe) and `cu_cashu.py` (test-mint helper: mint, balance, redeem) |
| `paper/` | the paper (`paper.md` → `build.sh`) |
| `docs/` | `APPROACH.md` (engineering overview), `ADVERSARIAL-QA.md`, `REVIEW-2026-10-09.md` (findings and fixes), `ONE-PAGER.md` |

## Routstr integration (branches)

The upstream pull requests are closed while this is tested on fork branches; they will be reopened after
user testing. To try it: [`docs/SETUP.md`](docs/SETUP.md).

| Repo | Branch | What |
|---|---|---|
| [jooray/routstr-core](https://github.com/jooray/routstr-core/tree/confidential-2pc) | `confidential-2pc` | node side (offer, relay, normal billing); inert until `CONFIDENTIAL_SIDECAR_URL` is set |
| [jooray/routstr-sdk](https://github.com/jooray/routstr-sdk/tree/confidential-2pc) | `confidential-2pc` | client transport (protocol v2), traffic-driven pre-warming |
| [jooray/routstrd](https://github.com/jooray/routstrd/tree/confidential-upstream) | `confidential-upstream` | opt-in header and config (`confidentialUpstream`, incl. `prewarm`) |

This repo's default branch is `twopc-v2` (protocol v2, the only supported protocol); the retired v1 proof of concept is the `v1-poc` branch.

## In the browser

A browser version runs the same client (2PC and proofs in WebAssembly) inside a static web page:
library [jooray/routstr-confidential-web](https://github.com/jooray/routstr-confidential-web), demo PWA
[jooray/routstr-confidential-pwa](https://github.com/jooray/routstr-confidential-pwa), live at
<https://jooray.github.io/routstr-confidential-pwa/>.

## Build

```bash
cd crypto
cargo build --release -p cu-sidecar -p zkbench   # cu-sidecar + cu-prover in zkbench/target/release/
cargo test --release -p cu-crypto -p zkbench
```

Running a node with the sidecar, routstrd setup and the test scripts: [`AGENTS.md`](AGENTS.md) and [`crypto/PROGRESS-CONFIDENTIAL.md`](crypto/PROGRESS-CONFIDENTIAL.md).

## License

MIT (see `LICENSE`). The vendored TLS library under `crypto/client/vendor/tls` is MIT, © CreatorOS Inc.
