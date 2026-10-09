# BENCHMARK — confidential upstream (VOLE-ZK proofs + e2e latency)

*Measured on an Apple M2 Max, macOS, Rust 1.99 (release), node v26.
mpz2 pinned at rev `8f89783`. All numbers are measured, not estimated.*

## 1. Per-proof wall time and bytes (local and emulated WAN)

Command:

```
./zkbench/target/release/cu-prover --bench --json bench.json
```

`local` = in-process duplex, no delay. `wan` = 25 ms one-way delay and a
12.5 MB/s (100 Mbps) token bucket, applied by the in-process proxy that also
counts bytes in each direction.

| statement | transport | wall ms | prover→verifier | verifier→prover | SHA-256 compr. | AES-128 blocks |
|---|---|---|---|---|---|---|
| π_C1 | local | 473.5 | 574.3 kB | 1.09 MB | 32 | 18 |
| π_C1 | wan | 1531.9 | 574.3 kB | 1.09 MB | 32 | 18 |
| π_N | local | 86.1 | 463.7 kB | 484.2 kB | 4 | 0 |
| π_N | wan | 760.5 | 463.7 kB | 484.2 kB | 4 | 0 |
| π_C2 | local | 465.4 | 575.5 kB | 1.09 MB | 36 | 6 |
| π_C2 | wan | 1533.7 | 575.5 kB | 1.09 MB | 36 | 6 |
| π_C3 | local | 473.5 | 578.9 kB | 1.09 MB | 28 | 38 |
| π_C3 | wan | 1537.5 | 578.9 kB | 1.09 MB | 28 | 38 |

Notes:

* The SHA-256 / AES columns are the exact circuit sizes reported by
  `zkbench::stats` (π_C3's AES count is dominated by decrypting the tail records
  that carry `R`).
* The bytes are dominated by the VOLE correlation and the prover's adjust bits;
  the WAN cost is the round-trip latency (the proof itself is well under one
  bandwidth-delay product of data).
* **OT preprocessing is not separable here.** mpz2's Ferret extension runs on
  demand inside the ZK flush, so the table is the *total*; there is no separate
  offline OT figure to report (deviation recorded in PROGRESS.md).
* π_C1 is the only proof on the critical path before the first token; π_N gates
  the wire write; π_C2 and π_C3 run off the critical path (π_C2 concurrently with
  generation, π_C3 after close).

## 2. End-to-end latency vs a plain TLS 1.3 call

Command (sidecar running on 127.0.0.1:7443):

```
./client/latency.sh 10
```

The confidential-upstream run issues its request only after π_C1 and π_N have
verified; TTFT is measured from the moment the request body is written to the
upstream, `total` through the receipt.

| metric | baseline (direct HTTPS) | confidential upstream | added |
|---|---|---|---|
| TTFT (median) | 598 ms (10 runs) | 1083 ms (7 runs) | **+485 ms** |
| total (median) | 679 ms (10 runs) | 1574 ms (7 runs) | **+895 ms** |

The added TTFT is essentially one π_C1 (the credential proof precedes the request
write); the added total pays π_N on the critical path and π_C3 after close. π_C2
overlaps generation.

Raw data: `/tmp/cu-latency/{e2e.jsonl,baseline.json,summary.json}`.

## 3. End-to-end evidence

One full run against real `api.venice.ai`:

* TLS 1.3 `TLS_AES_128_GCM_SHA256`, X25519, ALPN `http/1.1`.
* Sidecar handshake verification: certificate chain to the Mozilla roots,
  hostname `api.venice.ai`, CertificateVerify (ECDSA P-256), server Finished and
  client Finished — all pass.
* π_C1 (credential record material), π_N (head template), π_C2 (body suffix) and
  π_C3 (usage disclosure) all verify.
* Upstream returns HTTP 200 with the streamed completion; the usage event
  (`prompt_tokens`, `completion_tokens`, Venice `cost`) is disclosed and checked.
* The receipt signature verifies against the sidecar's announced ed25519 key.
* Decoy regression: a `"model":"google-gemma-3-27b-it"` in the private body is
  overridden by the public suffix — the effective model is
  `mistral-small-3-2-24b-instruct`.

Artifacts: `runs/<sid>/{attestation.json,receipt.json,client.jsonl,response.txt}`.
