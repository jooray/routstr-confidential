# routstr-confidential

Confidential and verifiable upstream inference for [Routstr](https://github.com/Routstr). A node can serve an LLM request:

- **without seeing the prompt or the response**;
- **without giving its upstream API key to the client**;
- running **exactly the model and token limit the client asked for**;
- with **billing tied to the usage the provider itself reported**.

It needs only standard TLS 1.3 and interactive zero-knowledge proofs: no trusted hardware, no MPC over the payload.

The client is the TLS 1.3 client of the provider *through* the node. The node relays encrypted records and writes the one record that carries its API key. Zero-knowledge proofs pin what each side may write.

- **Paper:** [`paper/paper.pdf`](paper/paper.pdf).
- **User-facing summary:** [`docs/ONE-PAGER.pdf`](docs/ONE-PAGER.pdf).
- **New here (human or agent)?** Read [`AGENTS.md`](AGENTS.md).

## What is here

| Path | What |
|---|---|
| `crypto/relay` | **cu-sidecar**: the node-side Rust process that relays TLS, verifies the handshake, holds the request's final record until the suffix proof verifies, writes the credential record, and verifies the client's proofs |
| `crypto/zkbench` | VOLE-ZK circuits (mpz2) for π_C1, π_N, π_C2, π_C3 and the **`cu-prover`** binary used by clients |
| `crypto/cu-crypto` | TLS 1.3 key schedule and AES-GCM record math (RFC 8448 / NIST vectors) |
| `crypto/client` | reference TypeScript client (`driver.ts`) |
| `crypto/tools` | validation gates, each exits non-zero on any deviation: `provider-profile-check.py` (live provider-profile gate A1–A11, incl. the pinned TLS suite and a mid-request KeyUpdate), `regression-modality.py` (every offered model rejects image URL and data-URI parts), `adversarial-model-swap.sh` (malicious-client attack cases plus an honest control), `stall-repro.sh` (N cold sessions, success-rate threshold). Also `probe-modality.py` (exploratory modality/token-amplification probe) and `cu_cashu.py` (test-mint helper: mint, balance, redeem) |
| `paper/` | the paper (`paper.md` → `build.sh`) |
| `docs/` | `APPROACH.md` (engineering overview), `ADVERSARIAL-QA.md`, `REVIEW-2026-10-09.md` (findings and fixes), `ONE-PAGER.md` |

## Routstr integration (pull requests)

| Repo | PR | Merge |
|---|---|---|
| routstr-sdk | [Routstr/routstr-sdk#90](https://github.com/Routstr/routstr-sdk/pull/90): confidential transport (Bun/Node) | **first**, then release the SDK |
| routstr-core | [Routstr/routstr-core#824](https://github.com/Routstr/routstr-core/pull/824): node side (offer, relay, normal billing) | independent; inert until `CONFIDENTIAL_SIDECAR_URL` is set |
| routstrd | [Routstr/routstrd#137](https://github.com/Routstr/routstrd/pull/137): opt-in requests | **after** the SDK release (bump `@routstr/sdk`) |
| routstr-core | [Routstr/routstr-core#823](https://github.com/Routstr/routstr-core/pull/823): never announce loopback/private URLs | independent small fix |

## Build

```bash
cd crypto
cargo build --release -p cu-sidecar -p zkbench   # cu-sidecar + cu-prover in zkbench/target/release/
cargo test --release -p cu-crypto -p zkbench
```

Running a node with the sidecar, routstrd setup and the test scripts: [`AGENTS.md`](AGENTS.md) and [`crypto/PROGRESS-CONFIDENTIAL.md`](crypto/PROGRESS-CONFIDENTIAL.md).

## License

MIT (see `LICENSE`). The vendored TLS library under `crypto/client/vendor/tls` is MIT, © CreatorOS Inc.
