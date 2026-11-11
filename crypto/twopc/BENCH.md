# twopc benchmark (two-party key schedule)

**Branch `v3-twopc-split`: the split key schedule (protocol v3, option B), a prototype.** Design, security
assessment and limits: `docs/TWOPC-SPLIT.md`. The garbling machinery is v2's (node-only authenticated
garbling, three-halves tables, 64-bit salted check rows, Ferret MAC COTs; `docs/TWOPC-DESIGN.md`). v2's
numbers are kept below, re-measured on the same machine and day.

`cargo run --release -p twopc --example bench -- --runs 3` on an Apple M2 Max, with both parties in one
process. Link emulation is `zkbench::transport::emulated_link`: a rate per direction and a pipelined one-way
delay. Wall time covers a whole cold session (new → preprocess → key share → ECtF + handshake stages →
application stages) until both parties finish. Medians of 3 runs. MB = 10^6 bytes on the wire, counting mux
headers and all OT traffic.

Two variants were built (`twopc::Variant`; `--variant proven|public` in the bench, `TWOPC_VARIANT=public` for
the binaries):

- **proven** (spec B.2): `IS_k` to C only, C proves the inner digests and h1, h2 in zero knowledge, N proves hk.
- **public IS**: `IS_k` is a public output, the inner digests are public inputs pinned by pointer checks, no
  proofs, the anchors stay garbled.

## Circuits

| design | garbled AND gates | garbled SHA-256 compressions | AND gates in proofs |
|---|---|---|---|
| v2 (phase A 298 088 + phase B 358 091) | 656 179 | 31 | 0 |
| **proven (B.2)** | **414 740** | **19** | C 206 529 (9 inner digests × 18 045, h1 and h2 × 22 062), N 22 029 (hk) |
| **public IS** | **479 022** | **22** | 0 |
| B.3 aggressive (circuit built for the count only) | 328 056 | 15 | not built |

AND gates at the end of each stage (A1, A2, A3, B1, B2): proven 87 674 / 196 696 / 262 376 / 349 727 /
414 740; public IS 87 674 / 196 696 / 262 376 / 371 181 / 479 022. A full SHA-256 compression is 22 573 AND
gates; an inner digest over a public block needs 18 045 in the proof (the message schedule is public).

## Bytes per session

| | client up | client down |
|---|---|---|
| v2 | 1.21 MB | 22.12 MB |
| proven (B.2) | 1.60 MB (+32 %) | 14.74 MB (−33 %) |
| public IS | 1.13 MB (−7 %) | 16.38 MB (−26 %) |

Where they go (computed from the circuit; OT traffic measured as the rest):

| | proven | public IS |
|---|---|---|
| three-halves tables | 10.21 MB | 11.80 MB |
| check rows (8 B per AND gate and per entering wire) | 3.33 MB | 3.85 MB |
| mask commitment bits | 0.10 MB | 0.12 MB |
| label-check pairs (32 B per reported or converted output wire) | 73 kB | 73 kB |
| online labels and corrections, N→C | 45 kB | 45 kB |
| online reports and proofs, C→N | 26.6 kB | 0.5 kB |
| MAC COTs (Ferret, C sender, Δ_B), measured: C→N / N→C | 1.09 MB / 0.45 MB | 1.09 MB / 0.45 MB |
| COTs under Δ_A (N sender), measured: C→N / N→C | Ferret over KOS: 0.45 MB / 0.48 MB | KOS, 256 COTs: 12 kB / 4 kB |

The upload of *proven* is the KOS bootstrap of its second Ferret: 27 377 base COTs with C as receiver, 16 B
each. mpz2 fixes that count. The Δ_B Ferret now needs under a million COTs instead of 1.31 million, which saves
one level of its second iteration (64 kB of upload: 1.09 MB instead of 1.16 MB).

## Cold session, per link

| link | v2 | proven (B.2) | public IS |
|---|---|---|---|
| local, unlimited | 0.67 s | 0.56 s | **0.46 s** |
| 40 ms, 2 Mbit/s up / 50 down | 7.42 s | 8.93 s | **7.05 s** |
| 40 ms, 7 Mbit/s up / 50 down | 5.50 s | 4.96 s | **4.70 s** |
| 25 ms, 100 Mbit/s symmetric | 3.14 s | **2.62 s** | 2.70 s |
| 40 ms, 2 Mbit/s up / 10 down | 20.12 s | 15.70 s | **15.64 s** |

- On a 2 Mbit/s uplink the upload is the critical path (v2: 1.2 MB, about 4.9 s). *Proven* adds 0.39 MB of
  upload there and loses 1.5 s against v2 although it downloads 7.4 MB less. *Public IS* uploads slightly less
  than v2.
- Where the download is the bottleneck (10 Mbit/s down) both variants save 4.4 s.
- The cold numbers include about 0.5 s (*proven*) or 0.3 s (*public IS*) of additional online round trips, see
  below.

## Online round trips (the request path, also of a pre-warmed session)

Every stage after the first needs the inner digests of the previous stage's `IS_k`, and N releases their
labels only after C's report (and, in *proven*, proof). That is one round trip per stage which v2 does not
have.

| C's view, from the call to its return | v2 | proven | public IS |
|---|---|---|---|
| `handshake` after ECtF (stages A1, A2, A3) | 1 | 3 | 3 |
| `application` (stages B1, B2, anchors) | 1 | 3 | 1.5 (N's first labels need no message from C; 2.5 if N starts later than C) |
| N returns after C by | 0.5 | 0.5 | 0.5 |

Measured, C's view (ms):

| link | step | v2 | proven | public IS |
|---|---|---|---|---|
| local | handshake stages / application | 40 / 51 | 63 / 81 | 37 / 30 |
| 40 ms, 2 Mbit/s up / 50 down | handshake stages / application | 132 / 150 | 422 / 456 | 329 / 233 |
| 40 ms, 7 Mbit/s up / 50 down | | 152 / 164 | 378 / 397 | 339 / 230 |
| 25 ms, 100 Mbit/s | | 111 / 126 | 279 / 279 | 225 / 170 |

At 80 ms round-trip time a session spends about 0.6 s more (*proven*) or 0.3 s more (*public IS*) between
the ServerHello and the first application record than v2. *Proven* also sends 26.6 kB of proofs online, which
is 100 ms of a 2 Mbit/s uplink. Local CPU: *proven* adds about 50 ms per session for proving and verifying
229 000 AND gates; *public IS* is faster than v2 (fewer gates).

Preprocessing CPU (local, C's view): v2 567 ms, proven 407 ms, public IS 380 ms.

## Steps at 40 ms, 2 Mbit/s up / 50 Mbit/s down (C's view)

| step | proven: ms | C sent | C recv | public IS: ms | C sent | C recv |
|---|---|---|---|---|---|---|
| preprocess | 7 818 | 1 569 738 | 14 695 980 | 6 190 | 1 133 521 | 16 337 598 |
| key_share | 86 | 41 | 74 | 88 | 41 | 74 |
| ectf | 171 | 231 | 4 235 | 170 | 231 | 4 235 |
| handshake stages | 422 | 9 340 | 20 507 | 329 | 253 | 20 507 |
| application | 456 | 17 273 | 23 357 | 233 | 180 | 20 498 |

## Live (real Venice, sidecar and reference driver on one host, 2026-11-11)

`driver.ts --sidecar` against `cu-sidecar` on loopback (stub settlement, no node), `deepseek-v4-flash`,
40 tokens, the split `cu-2pc` on the client and the split `twopc` in the sidecar. π_NK, π_C2S and π_C3S ran
unchanged over the anchors hk, h1, h2 that the split protocol produced.

| run | cu-2pc preprocess | bytes C sent / received | handshake stages / application | receipt, usage |
|---|---|---|---|---|
| proven, cold | 379 ms | 1 569 783 / 14 695 878 | 58 / 74 ms | ok, match |
| proven, `--arm` | 397 ms | 1 569 783 / 14 695 980 | 58 / 76 ms | ok, match (claim → body 9 ms) |
| public IS, cold | 412 ms | 1 133 526 / 16 337 598 | 32 / 27 ms | ok, match |

Tracing: `TWOPC_TRACE=1` prints preprocessing milestones and per-channel byte counts to stderr. It prints
timings and counts only, never secrets.

## Before: v2 (for comparison, same machine, 2026-11-11)

| step, 40 ms, 2/50 Mbit/s | ms | C sent | C recv |
|---|---|---|---|
| preprocess | 6 836 | 1 213 910 | 22 072 758 |
| phase_a | 132 | 73 | 20 498 |
| phase_b | 150 | 238 | 24 077 |

Download: three-halves tables 16.2 MB, check rows 5.3 MB. Earlier history (dual execution: 21 MB each way,
85 s on a 2 Mbit/s uplink; the PoC without the cuts) is in `docs/TWOPC-NODE-GARBLING.md`.
