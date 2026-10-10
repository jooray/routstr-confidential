# zkbench: v2 statements vs v1

Measured 2026-10-10 on an Apple M2 Max, release build, with real OT (Chou-Orlandi, KOS, Ferret). Command:
`zkbench/target/release/cu-prover --bench` (v1 and v2) or `--bench --v2` (v2 only). Prover and verifier
run in one process over the emulated transport (`src/transport.rs`):

- `local`: no delay.
- `wan`: 25 ms one way (50 ms RTT) and 100 Mbit/s.

Fixtures are in `src/fixtures.rs` and use the RFC 8448 session. v2 uses its c_ap_1 and s_ap_0, and
K_0/IV_0 derived from its c_ap_0. The workload matches v1: a 479-byte body record (inner plaintext) with a 78-byte suffix,
one 596-byte server record with a 95-byte R, and a 228-byte head with a 42-byte key.

| proof | replaces | local | 50 ms RTT | P→V | V→P | total | SHA-256 compr. | AES blocks |
|---|---|---|---|---|---|---|---|---|
| π_C1 (v1) | n/a | 0.46 s | 1.51 s | 574 kB | 1.09 MB | 1.66 MB | 32 | 18 |
| π_N (v1) | n/a | 0.08 s | 0.79 s | 464 kB | 484 kB | 0.95 MB | 4 | 0 |
| π_C2 (v1) | n/a | 0.45 s | 1.51 s | 576 kB | 1.09 MB | 1.67 MB | 36 | 6 |
| π_C3 (v1) | n/a | 0.46 s | 1.53 s | 579 kB | 1.09 MB | 1.67 MB | 28 | 38 |
| **π_NK** | π_N (π_C1 is gone) | 0.16–0.19 s | 1.16–1.19 s | 481 kB | 964 kB | 1.45 MB | 5 | 15 |
| **π_C2S** | π_C2 | 0.10–0.12 s | 0.78–0.79 s | 475 kB | 484 kB | 0.96 MB | 7 | 6 |
| **π_C3S** | π_C3 | 0.20–0.24 s | 1.21–1.23 s | 504 kB | 964 kB | 1.47 MB | 7 | 38 |

Ranges come from three runs.

## Reading

- **π_C2S and π_C3S** no longer recompute the key schedule from HS. v1 needs 7–9 HMACs (28–36 compressions).
  v2 needs one SHA-256 of the secret, the keyed HMAC ipad/opad states once, and two 2-compression expansions
  for K and IV: 7 compressions in all. π_C2S takes about a quarter of π_C2's time and about half of its
  bytes.
- **π_NK** costs more than v1 π_N because the keystream is no longer a public input. The node proves its
  own AES-CTR over the 229-byte inner plaintext (15 blocks) plus hk. It still replaces the v1 pair
  π_C1 + π_N, which took 0.54 s locally and 2.3 s at 50 ms RTT, so the credential record proof costs about two thirds
  less locally and about half less at 50 ms RTT.
- The byte counts move in steps (about 0.48 MB and 0.96 MB per direction) because Ferret extends OT in
  fixed chunks. A statement that needs slightly more correlations than one chunk pays for a second one.
  That is why π_NK and π_C3S cost 1.45 MB rather than about 1 MB.
- At 50 ms RTT, round trips dominate (OT setup plus the VOLE-ZK flush): about 0.7 s of fixed cost per
  proof.

## Per-session total (proof work on the request path)

| | local | 50 ms RTT | bytes |
|---|---|---|---|
| v1: π_C1 + π_N + π_C2 + π_C3 | 1.45 s | 5.3 s | 5.9 MB |
| v2: π_NK + π_C2S + π_C3S | 0.5 s | 3.2 s | 3.9 MB |

The v2 numbers leave out the 2PC handshake (`crypto/twopc`), which is benchmarked separately.
