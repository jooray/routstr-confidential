# PROGRESS — confidential upstream prototype

*Implementation of `SPEC-confidential-upstream.md` per `PLAN-confidential-upstream.md`.
All commands are run from `repos/prover-approach/`.*

## Phase status

| Phase | What | Status |
|---|---|---|
| 0 | Setup: vendor the TLS fork, plain TLS 1.3 call to Venice through a dumb relay | ✅ done (the full e2e subsumes it) |
| 1 | `cu-crypto`: RFC 8448 key schedule + NIST GCM/GHASH vectors + JSON fixtures | ✅ done |
| 2 | `zkbench`: native==ZK property tests for π_C1/π_N/π_C2/π_C3 + mutations | ✅ done |
| 3 | E2E without proofs (`--insecure-no-proofs`) | ✅ done |
| 4 | Proofs wired (π_C1, π_N, π_C2, π_C3) | ✅ done |
| 5 | Settlement: attestation, R validation, receipt, client-side check | ✅ done (stub pricing) |
| 6 | Benchmarks: proof table (local + WAN); e2e vs baseline | ✅ done |
| 7 | Regression: `--decoy-model` through the full protocol | ✅ done |

## Layout

```
cu-crypto/      Rust lib: TLS 1.3 key schedule, AES-GCM record math, fixtures
zkbench/        Rust lib + `cu-prover` bin: the four VOLE-ZK statements, bench harness
relay/          Rust bin `cu-sidecar`: WS relay, handshake verification, credential record, attestation
client/         TypeScript: vendored @reclaimprotocol/tls fork + session driver + baseline
runs/<sid>/     per-session artifacts (attestation.json, receipt.json, client.jsonl, response.txt)
```

`zkbench`'s pinned mpz2 (rev `8f89783`) artifacts are shared via `.cargo/config.toml`
(`build.target-dir = "zkbench/target"`); the pin is unchanged.

## Phase 1 — cu-crypto

```
cargo test -p cu-crypto                              # 7 lib + 3 NIST integration tests
cargo run  --release -p cu-crypto --bin cu-crypto-fixtures -- /tmp/fixtures.json
```

Tests: RFC 5869 HKDF, RFC 8448 key schedule (HS→client_hs/server_hs/derived→MS→
c_ap_0/s_ap_0, keys and IVs) and the RFC 8448 **full GCM record** round-trip
(server handshake record, 679 bytes), plus NIST SP 800-38D GCM Test Cases 1–4 and a
direct GHASH vector.

## Phase 2 — zkbench

```
cargo test --release -p zkbench            # 6 tests: 4 native==ZK + mutations + stats
```

* `pi_n_native_eq_zk`, `pi_c1_native_eq_zk`, `pi_c2_native_eq_zk`, `pi_c3_native_eq_zk`
  prove the statement with an in-process prover‖verifier over ideal OT and check
  every verifier output against the native value computed by `cu-crypto`.
* `mutations_fail` flips one bit of a public input and asserts verification fails.
* `harness` sanity-checks the mpz driver pattern.

## Phase 3/4/5/7 — end-to-end against real Venice

Start the sidecar (reads the key from `$VENICE_API_KEY`; logs only its length):

```
RUST_LOG=cu_sidecar=info ./zkbench/target/release/cu-sidecar \
  --listen 127.0.0.1:7443 --upstream api.venice.ai:443 --key-env VENICE_API_KEY
```

Run the protocol (in `client/`):

```
CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --prompt 'Say hi in three words.'
```

Regression (decoy model in the private part; the suffix must win):

```
CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --prompt 'Say hi in three words.' \
  --decoy-model google-gemma-3-27b-it
```

Test mode without the ZK proofs (π_C1 and π_N checked natively; π_C2/π_C3 still run):

```
./zkbench/target/release/cu-sidecar --listen 127.0.0.1:7443 \
  --upstream api.venice.ai:443 --key-env VENICE_API_KEY --insecure-no-proofs
CU_PROVER=../zkbench/target/release/cu-prover \
  node --experimental-strip-types src/driver.ts --insecure-no-proofs
```

Observed order of a green run: `ready → TLS 1.3 handshake → hs_verified →
KU0 forwarded → π_C1 ok → c_commit → π_N ok → credential record + KU1 written →
body → π_C2 ok → attestation → disclose → π_C3 ok → receipt (signature ok)`.

## Phase 6 — benchmarks

```
./zkbench/target/release/cu-prover --bench --json bench.json     # local + WAN proof table
./client/latency.sh 10                                           # e2e vs baseline, medians
```

Results are in `BENCHMARK-keyupdate.md`.

## Deviations from the plan (also noted in the PLAN)

1. **TLS 1.3 inner content type.** The credential record plaintext is
   `head ‖ 0x17` (the application-data content type), so `|plaintext| = |head| + 1`.
   The plan's §5.4 wrote `P = head`; a real TLS 1.3 record must carry the trailing
   type byte. π_C1 proves the keystream over `|head|+1` bytes and π_N splices the
   `0x17` byte before the XOR.
2. **π_C3 spans several tail records.** The usage event and `data: [DONE]` can fall
   across a TLS record boundary, so π_C3 decrypts the minimal suffix of server
   records covering `R` and selects the last `|R|` bytes, rather than decrypting a
   window of a single record. The client identifies the exact records by their
   ciphertext lengths (the node supplies the ciphertexts).
3. **OT is interleaved, not separable.** mpz2 (Ferret) extends the correlation on
   demand inside the ZK flush, so the benchmark reports total wall time/bytes; it
   does not report a separate OT-preprocessing figure.
4. **`--insecure-no-proofs`** performs the native π_C1 and π_N checks but still runs
   the real π_C2 and π_C3 (they are off the critical path); it is bound to
   `127.0.0.1`.
5. **Residual gaps (documented, intentional).** For π_N the record bytes are
   invisible to C by design, so the commitment + attestation binding is post-hoc.
   For π_C3 the node cannot tell a close_notify alert record from a content record
   (both are outer `0x17`), so it relies on the client identifying the tail records
   by ciphertext length; the range always reaches the transcript end.
6. **`cu-prover` is the client-side ZK process.** It speaks the mpz framed protocol
   on stdin/stdout (not JSON-RPC), with the proof type/params/witness in a JSON file;
   the driver bridges stdio to the sidecar's `/zk` WebSocket.

## Security invariants (PLAN §7) — self-check

| ID | Check | Result |
|---|---|---|
| I1 (P1) | API key only in sidecar memory + the one credential record | **PASS** — `grep -rF "$VENICE_API_KEY" runs/ /tmp/*.log` finds nothing; the sidecar logs only `key_len=42`; the only write of the key is `assemble()`'s record bytes to the TCP socket |
| I2 (P2) | Sidecar never receives `c_ap_2`, `s_ap_0`, body or response plaintext | **PASS** — `/session` carries only `setup`, `hs_secrets`, `c1_material`, `body_suffix` (public), `ku1`, `disclose` (`R`, `tail_lens`); `/zk` carries only proof I/O; body and response are relayed as ciphertext |
| I3 | Circuits implement exactly §1 | **PASS** — `native==ZK` tests against RFC-8448-tested `cu-crypto`; mutation tests |
| I4 | π_C1 before assembly; π_N before wire write | **PASS** — `assemble()` is called only from `ZkDone(pi_c1)`; the record is written only in the `ku1` handler, and the client sends KU1 only after its π_N verifier returns |
| I5 | Epoch-1 record count/length gate | **PASS** — in epoch 0 exactly one 27-byte client record (5 header + 22 ciphertext) is accepted, else abort; no client records are accepted in the π_C1/π_N window |
| I6 (P3) | Suffix pins exactly the SPEC key set; π_C2 checks the last-record suffix | **PASS** — the suffix is exactly `model,max_tokens,max_completion_tokens,n,stream,stream_options,venice_parameters`; π_C2 verifies it inside the last epoch-2 record; the fork verifies all response GCM tags |
| I7 (P4) | π_C3 anchored at transcript end; §5 validation; receipt == client plaintext | **PASS** — the tail records are the final content records; `validate_r` de-chunks and parses the usage event; the receipt embeds it and the client asserts it equals its own plaintext |
| I8 (P6) | Fresh nonces → fresh sid; fresh TLS randoms; no tickets | **PASS** — `sid = SHA256(nonce_C‖nonce_N‖SHA256("stub-cashu"‖E))` with fresh nonces; the fork generates a fresh 32-byte client random; no session-ticket flow |
| I9 (P5) | Handshake verification fail-closed | **PASS** — chain to Mozilla roots, hostname, CertificateVerify (ECDSA P-256 / RSA-PSS / Ed25519), server Finished and client Finished; any failure aborts |
| I10 | Attestation/receipt signatures verify on the announced key | **PASS** — the client verifies both ed25519 signatures against `offer.notary_pubkey` (stub for the Nostr key) |

Residual gaps (also in Deviations): for π_N the wire bytes are invisible to C by
design, so the binding is post-hoc; for π_C3 the node cannot distinguish a
close_notify alert record from a content record, so it trusts the client's
ciphertext-length identification of the tail (the range always reaches the end).
