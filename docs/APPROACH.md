# The confidential-upstream approach

*2026-10-10. This document is the engineering overview. The formal protocol is in `original/SPEC-confidential-upstream.md`; the implementation contract in `original/PLAN-confidential-upstream.md`; the routstr wiring in `original/WIRE-UP-confidential-upstream.md`; measured results in `original/BENCHMARK-keyupdate.md`; the paper in `../paper/paper.pdf`.*

## The problem

A routstr node forwards a user's LLM request to an upstream provider (Venice, OpenRouter, …) using the node's own API key. Today the node is a full man-in-the-middle: it reads every prompt, it can alter requests and responses, and the user must trust its accounting. The existing "verified mode" (TLSN/MPC-TLS, see `original/REPORT-proverd-update.md`) fixes only part of this, at enormous cost (3–66 s per request, hundreds of MB), and it still cannot hide the prompt from the node.

## The idea

Flip the TLS client: the **user (C) is the TLS 1.3 client of the upstream**, and the node (N) is only a TCP relay. C does a normal TLS 1.3 handshake with the upstream through N, and then keeps all application keys to itself. For exactly one key epoch, C hands N the *record material* (CTR keystream, GHASH key, tag mask) for one sequence number, and proves in interactive ZK (VOLE-based, TLSNotary's mpz) that this material is correctly derived from the session's handshake secret. With it, N can write exactly **one** TLS record: the HTTP request head containing its `Authorization` header. C never receives that record's ciphertext, so the API key stays N's. C then rotates keys twice (TLS 1.3 `KeyUpdate`), so N's material is useless for everything that follows: the prompt body and the streamed response run under keys only C holds, at native speed, streamed live.

Verification is symmetric:

- **N verifies the upstream** from the disclosed *handshake* secrets: certificate chain to Mozilla roots, hostname, CertificateVerify, server and client Finished. (Application secrets cannot be derived from handshake secrets, so this disclosure costs nothing.)
- **C verifies the request and the bill**: N proves in ZK that the head it wrote matches the published template with only its key bytes free (π_N); C proves the last bytes of its body equal the agreed public JSON suffix that pins every cost-relevant parameter (π_C2); and C proves the upstream's final usage/cost SSE event is authentic (π_C3). The node charges the usage the upstream itself reported, at the rates of the offer the client verified.

π_C2 and π_C3 compare the decrypted range with the public expected bytes *inside* the circuit; the verifier decodes one bit (equal or not), never the decrypted bytes, even when a proof fails. The client also checks every proof parameter the node sends before proving (`params.ts` in the SDK and the reference client): π_C1 must cover exactly the material it sent, π_C2 a window ending at the end of its own final body record with its own suffix as the expected value, and π_C3 the final server records exactly as it received them (one trailing close_notify allowed) with its own disclosure as the expected value. The node therefore cannot point a proof, or even its one-bit result, at other plaintext.

Why it is fast: there is **no MPC over the payload**. The only ZK work is the TLS key schedule (tens of SHA-256 compressions) and a handful of AES blocks, per session. Everything else is ordinary TLS at line speed.

## Properties

| Property | Mechanism |
|---|---|
| Credential confidentiality | Key appears only in N's one record; C never receives its ciphertext; the material is ZK-proven before use. Rests on no observer of the N→U ciphertext colluding with C (paper §5) |
| Content confidentiality | C alone holds application secrets; N sees ciphertext only |
| Integrity | Head template *content* proven by π_N (not the exact wire bytes, see Known limits); body suffix proven by π_C2 *before* the upstream gets the complete request (N holds the final body record until it verifies); response GCM tags verified natively by C |
| Verifiable accounting | π_C3 binds the upstream's usage/cost event to the session; signed receipt + attestation |
| Upstream authenticity | Both sides verify the certificate/finished messages |
| Freshness | Session id binds fresh nonces + the node's one-time reservation id; fresh TLS randoms |

No trusted hardware, no enclave attestation, no model-weight proofs, no hiding of traffic volume — stated non-goals.

## Components (as built)

```
crypto/cu-crypto    Rust  native TLS 1.3 key schedule, GCM record math (GHASH), RFC 8448 + NIST vectors
crypto/zkbench      Rust  mpz2 VOLE-ZK circuits for π_C1, π_N, π_C2, π_C3 + cu-prover/verifier + benches
crypto/relay        Rust  cu-sidecar: WS control/relay/zk endpoints, TCP relay, handshake verification,
                          credential-record assembly, attestation; settlement is in the node (Python)
crypto/client       TS    reference client: fork of @reclaimprotocol/tls + session driver (spawns cu-prover)
```

Integration (branches `confidential-upstream`):

```
routstr-core  Python   /v1/confidential/offer (Nostr-signed), WS proxies to the sidecar, billing through
                       the node's normal reservation/settlement, receipt signing, additive /v1/models field
routstr-sdk   TS       client/confidential/*: offer verify, session driver, prover backend, and a transport
                       that RoutstrClient uses instead of fetch() for opted-in requests
routstrd      TS/Bun   config block (trusted hosts with wildcards, node pins, prover path) + passing the
                       x-routstr-verify: confidential opt-in into the normal routeRequests call; fails
                       closed (HTTP 400) when the mode is off or the endpoint is not chat completions
```

## Negotiation and billing (stateless, per request)

1. Node publishes a Nostr-signed offer: `GET /v1/confidential/offer` (version, `upstream_host`, caps, `price_list`, mints, notary pubkey, accepted upstream hostnames).
2. `/v1/models` gains one additive field per model pointing at the offer, only for models with a signed price entry; older clients ignore it.
3. Client opts in per request if: user-enabled ∧ version range ∧ signature verifies with a pinned node key ∧ **upstream hostname matches its trusted list (wildcards allowed; an empty or missing list refuses every host)**; it routes only to nodes advertising the model confidentially. The offer cache re-applies these checks under each call's own policy. Only `POST /v1/chat/completions` is carried; any other endpoint is refused before a credential or deposit is touched.
4. Billing is the node's ordinary path. The setup carries the client's usual bearer (API key or Cashu token) and `offer_sig`, the signature of the offer it verified. The node keeps the offers it signed in the last 10 minutes and freezes that offer's rates for the session (unknown or expired → 409 `offer_expired`; the SDK refetches and retries once). It reserves `max(min_request_msat, ⌈(prompt_limit·in + max_tokens·out)/1000⌉)` msats with `pay_for_request`, where `prompt_limit` is the model's full context minus its completion limit: the prompt is opaque, so it is never discounted. It charges exactly the frozen-rate cost of the π_C3-verified usage (capped at the reservation) through the node's existing finalize path, releases the reservation if the upstream never got the request or answered a 4xx/503, and charges it in full for another 5xx or when the client withholds its disclosure. No other model or cap can run: the sidecar releases the final body record (the pinned suffix) only after π_C2 verifies.
5. The signed receipt carries `sid`, model, usage, cost, reservation, balance, rates and the hash of the attestation. The client requires its signature, reads every field from the signed bytes, checks `sid` and the attestation hash against its own session, and checks the usage and `cost ≤ usage × signed rates`.
6. Upstream errors: for a status ≥ 400 the client discloses only the response head (status line and headers); π_C3 proves it sits the given number of bytes before the end of the response, so the error body stays private.
7. Limits: both the node and the sidecar validate the setup (model; `max_tokens` an integer in [1, cap]; body length in [1, 8 MiB]) and reserve before any provider connection opens; 15 s to the setup, 600 s per session, 32 concurrent sessions each; every refusal is an explicit error frame.

## Latency: pre-warmed sessions (account path)

The critical path is: KeyUpdate → |head| exchange → **π_C1** (~0.47 s, of which most is VOLE setup and proof transport) → credential record → body → **π_C2** on the held final record (~0.4 s) → upstream starts. Two facts make it compressible:

1. **The VOLE/OT correlation is input-independent** — it depends only on circuit sizes, not on secrets or the request. It can be computed before a request exists (mpz2 separates setup from extend).
2. **Everything up to the request-bound part can be pre-done**: the TLS handshake with the upstream, handshake verification by the node, the first KeyUpdate (a fixed 22-byte record), the derivation of `c_ap_1`/`K1`/`IV1`/`H1`/`T0`, and the proof correlation. Only `|head|` (depends on the body-length digits) and the request-bound proof remain for the arrive path.

So a client can keep **armed sessions** ready: setup, handshake, KU0, π_C1 and π_N done ahead, with a reservation on its credential. An arriving request claims one, sends the credential record, the body and π_C2 (which depends on the prompt and cannot be pre-done), and returns tokens with about +0.3 s added instead of about +1.1 s. A discarded armed session releases its reservation (the upstream never got a request). The reference client implements arming (`--arm`, `--pool`); routstrd does not pre-warm yet.

## Running it

Prototype (unchanged from the verified build): `crypto/PROGRESS.md` has exact commands. Integration branches: `docs/confidential-upstream.md` in routstr-core and routstrd, `client/confidential/README.md` in routstr-sdk; the PRs are listed in `README.md`.

## Status / evidence

- All four proofs verified against real `api.venice.ai`; full sessions with receipt + attestation: `crypto/PROGRESS-CONFIDENTIAL.md`, `crypto/runs/`.
- Proof cost locally: π_C1, π_C2, π_C3 ≈ 0.4–0.5 s and ≈ 1.6 MB each; π_N ≈ 0.09 s and ≈ 0.95 MB; ≈ 5.9 MB per session in both directions. Added time to first token vs direct HTTPS: **about +1.1 s cold, +0.25–0.3 s pre-warmed** (medians, one host; the paper §6.2 has the breakdown).
- Validation gates (`crypto/tools/`, each exits non-zero on any deviation): `provider-profile-check.py` re-checks the provider assumptions live (A1–A11, 11/11 for Venice; 429/5xx/timeouts count as inconclusive, never as a pass); `regression-modality.py` requires every offered model to reject both `image_url` and data-URI parts; `adversarial-model-swap.sh` runs the swap attacks plus an honest control and asserts the money outcome in the node log; `stall-repro.sh` fails below a success threshold.

## Known limits (honest list)

- P1 (the API key stays N's) rests on the client never seeing the N→U ciphertext of the credential record: an observer on N's egress path colluding with C, or an upstream that reflects request bytes, would expose the key. Removing the assumption needs a new protocol version with a two-party handshake (new key ownership and proof binding, paper §5), not a drop-in change. Short-lived, capped provider keys limit the loss; they are not equivalent security.
- The key commitment sent to C is `SHA256(header ‖ C1)` without a salt; its safety rests on the API key's entropy (42 random characters for Venice).
- Interactive, designated-verifier proofs: N must be online (it is the proxy) and there is no artifact a third party can check. A non-interactive proof backend alone would not change this, because C holds the server's application keys and could forge server records; that needs an independent transcript attestation or MPC-TLS.
- π_N binds the head *content* and length, not the exact wire bytes, which C cannot see. N could write a different head of the same length (another account, another endpoint); C cannot detect it. Harm is bounded by C's own authenticated records and response/usage verification.
- N sees timing and record sizes (the token-length sequence of a streamed response), the body length, the usage event, and on an upstream error the status line, response headers and body length.
- Provider profile must hold (HTTP/1.1, TLS 1.3 AES-GCM, KeyUpdate accepted, strict JSON, streaming usage). Not universal; see the paper's comparison and Appendix.
- The client's TLS validator implements RFC 5280 path validation against the WebPKI roots; it does no revocation or certificate-policy checking.
- routstrd does not pre-warm sessions yet.
