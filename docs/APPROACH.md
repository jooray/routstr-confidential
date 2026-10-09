# The confidential-upstream approach

*2026-10-09. This document is the engineering overview. The formal protocol is in `original/SPEC-confidential-upstream.md`; the implementation contract in `original/PLAN-confidential-upstream.md`; the routstr wiring in `original/WIRE-UP-confidential-upstream.md`; measured results in `original/BENCHMARK-keyupdate.md`; the paper in `../paper/paper.pdf`.*

## The problem

A routstr node forwards a user's LLM request to an upstream provider (Venice, OpenRouter, …) using the node's own API key. Today the node is a full man-in-the-middle: it reads every prompt, it can alter requests and responses, and the user must trust its accounting. The existing "verified mode" (TLSN/MPC-TLS, see `original/REPORT-proverd-update.md`) fixes only part of this, at enormous cost (3–66 s per request, hundreds of MB), and it still cannot hide the prompt from the node.

## The idea

Flip the TLS client: the **user (C) is the TLS 1.3 client of the upstream**, and the node (N) is only a TCP relay. C does a normal TLS 1.3 handshake with the upstream through N, and then keeps all application keys to itself. For exactly one key epoch, C hands N the *record material* (CTR keystream, GHASH key, tag mask) for one sequence number, and proves in interactive ZK (VOLE-based, TLSNotary's mpz) that this material is correctly derived from the session's handshake secret. With it, N can write exactly **one** TLS record: the HTTP request head containing its `Authorization` header. C never receives that record's ciphertext, so the API key stays N's. C then rotates keys twice (TLS 1.3 `KeyUpdate`), so N's material is useless for everything that follows: the prompt body and the streamed response run under keys only C holds, at native speed, streamed live.

Verification is symmetric:

- **N verifies the upstream** from the disclosed *handshake* secrets: certificate chain to Mozilla roots, hostname, CertificateVerify, server and client Finished. (Application secrets cannot be derived from handshake secrets, so this disclosure costs nothing.)
- **C verifies the request and the bill**: N proves in ZK that the head it wrote matches the published template with only its key bytes free (π_N); C proves the last bytes of its body equal the agreed public JSON suffix that pins every cost-relevant parameter (π_C2); and C proves the upstream's final usage/cost SSE event is authentic (π_C3). Settlement refunds escrow minus the usage the upstream itself reported.

Why it is fast: there is **no MPC over the payload**. The only ZK work is the TLS key schedule (tens of SHA-256 compressions) and a handful of AES blocks, per session. Everything else is ordinary TLS at line speed.

## Properties

| Property | Mechanism |
|---|---|
| Credential confidentiality | Key appears only in N's one record; C never receives its ciphertext; the material is ZK-proven before use |
| Content confidentiality | C alone holds application secrets; N sees ciphertext only |
| Integrity | Head template proven by π_N; body suffix proven by π_C2 *before* the upstream gets the complete request (N holds the final body record until it verifies); response GCM tags verified natively by C |
| Verifiable accounting | π_C3 binds the upstream's usage/cost event to the session; signed receipt + attestation |
| Upstream authenticity | Both sides verify the certificate/finished messages |
| Freshness | Session id binds fresh nonces + the node's one-time reservation id; fresh TLS randoms |

No trusted hardware, no enclave attestation, no model-weight proofs, no hiding of traffic volume — stated non-goals.

## Components (as built)

```
crypto/cu-crypto    Rust  native TLS 1.3 key schedule, GCM record math (GHASH), RFC 8448 + NIST vectors
crypto/zkbench      Rust  mpz2 VOLE-ZK circuits for π_C1, π_N, π_C2, π_C3 + cu-prover/verifier + benches
crypto/relay        Rust  cu-sidecar: WS control/relay/zk endpoints, TCP relay, handshake verification,
                          credential-record assembly, attestation; settlement moves to the node (Python)
crypto/client       TS    reference client: fork of @reclaimprotocol/tls + session driver (spawns cu-prover)
```

Integration (branches `confidential-upstream`):

```
routstr-core  Python   /v1/confidential/offer (Nostr-signed), WS proxies to the sidecar, billing through
                       the node's normal reservation/settlement, receipt signing, additive /v1/models field
routstr-sdk   TS       client/confidential/*: offer verify, session driver, prover backend, and a transport
                       that RoutstrClient uses instead of fetch() for opted-in requests
routstrd      TS/Bun   config block (trusted hosts with wildcards, node pins, prover path) + passing the
                       x-routstr-verify: confidential opt-in into the normal routeRequests call
```

## Negotiation and billing (stateless, per request)

1. Node publishes a Nostr-signed offer: `GET /v1/confidential/offer` (version, `upstream_host`, caps, `price_list`, mints, notary pubkey, accepted upstream hostnames).
2. `/v1/models` gains one additive field per model pointing at the offer; older clients ignore it.
3. Client opts in per request if: user-enabled ∧ version range ∧ signature verifies with a pinned node key ∧ **upstream hostname matches its trusted list (wildcards allowed)**; it routes only to nodes advertising the model confidentially.
4. Billing is the node's ordinary path: the setup carries the client's usual bearer (API key or Cashu token), the node reserves the model's max cost (`pay_for_request`), charges the π_C3-verified usage (`adjust_payment_for_tokens`), releases the reservation if the upstream never got the request or answered a 4xx/503, and charges it if the client withholds its disclosure. No other model or cap can run: the sidecar releases the final body record (the pinned suffix) only after π_C2 verifies.

## Latency: pre-warmed sessions (account path)

The critical path is: KeyUpdate → |head| exchange → **π_C1** (~0.47 s, of which most is VOLE setup and proof transport) → credential record → body → **π_C2** on the held final record (~0.4 s) → upstream starts. Two facts make it compressible:

1. **The VOLE/OT correlation is input-independent** — it depends only on circuit sizes, not on secrets or the request. It can be computed before a request exists (mpz2 separates setup from extend).
2. **Everything up to the request-bound part can be pre-done**: the TLS handshake with the upstream, handshake verification by the node, the first KeyUpdate (a fixed 22-byte record), the derivation of `c_ap_1`/`K1`/`IV1`/`H1`/`T0`, and the proof correlation. Only `|head|` (depends on the body-length digits) and the request-bound proof remain for the arrive path.

So a client can keep **armed sessions** ready: setup, handshake, KU0, π_C1 and π_N done ahead, with a reservation on its credential. An arriving request claims one, sends the credential record, the body and π_C2 (which depends on the prompt and cannot be pre-done), and returns tokens with about +0.3 s added instead of about +1.1 s. A discarded armed session releases its reservation (the upstream never got a request). The reference client implements arming (`--arm`, `--pool`); routstrd does not pre-warm yet.

## Running it

Prototype (unchanged from the verified build): `crypto/PROGRESS.md` has exact commands. Integration branches: `docs/confidential-upstream.md` in routstr-core and routstrd, `client/confidential/README.md` in routstr-sdk; the PRs are listed in `README.md`.

## Status / evidence

- All four proofs verified against real `api.venice.ai`; full sessions with receipt + attestation: `original/PROGRESS.md`, `crypto/runs/`.
- Proof cost: ~0.4–0.5 s and ~1.6 MB per proof locally; added time to first token vs direct HTTPS: **about +1.1 s cold, +0.3 s pre-warmed** (medians, one host; the paper §6.2 has the breakdown).
- Provider profile: `crypto/tools/provider-profile-check.py` re-checks every assumption live (10/10 pass for Venice).
- Provider verification: Venice (live). See `original/VENICE-TESTS.md` for the exact upstream behaviours the design relies on and the provider-profile checklist for others.

## Known limits (honest list)

- Interactive proofs require N online (fine: N is the proxy) and no replayable proofs to third parties (optional non-interactive variant in SPEC §10).
- π_N binds the head *content*; the wire bytes are invisible to C by design, so binding to the exact wire record is post-hoc (attestation covers the sent transcript). Harm is bounded by response/usage verification.
- C sees traffic volume; N sees timing/volume (non-goal).
- Provider profile must hold (HTTP/1.1, TLS 1.3 AES-GCM, KeyUpdate accepted, strict JSON, streaming usage). Not universal; see the paper's comparison and Appendix.
- DoS/size limits on the public WS endpoints are inherited from the proverd discussion and must be handled at deployment.
