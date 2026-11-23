# twopc benchmark (two-party key schedule, `split-public-3`)

The numbers below were measured on `split-public-2` (2026-11-22). `split-public-3` (2026-11-23) is its
final form under a new tag and offer value: the same bytes, the last digit of the 27-byte tag aside.

Protocol v3's key schedule (`PROTOCOL-V3.md` §4, `docs/TWOPC-DESIGN.md`, `docs/TWOPC-NODE-GARBLING.md`):
node-only authenticated garbling with three-halves tables and 64-bit check rows, as in v2, over the split
circuit (key-pad states and outer compressions only, `IS_k` public).

`split-public-3` changes against `split-public-1` (section "split-public-3 against split-public-1" below has
the measurements): the garbling hash is `AES_k(Y) ⊕ σ(Y)`, `Y = X ⊕ U(τ)`, with N's per-session parameters
(32 bytes before the tables) instead of mpz2's fixed-key TCCR, so a gate costs N 6 AES calls and C 3 instead
of 12 and 6; the check rows are keyed by row parameters from C's seed; N's garbled input is a random mask ρ
whose labels go out before the seed (its share follows as δ = x_N − ρ in the handshake); N commits to both
labels of the other 2 560 input wires before the seed, under a 16-byte salt from C. The circuit is the same. The **v2** column is v2's own
measurement from this file's earlier version (branch `twopc-v2`, same machine, 2026-11-11); CPU and memory of
v2 were measured now, from the v2 sources at commit `17540f8`, with the same `procbench`.

Apple M2 Max, 2026-11-11. MB = 10^6 bytes on the wire, counting mux headers and all OT traffic.

- `cargo run --release -p twopc --example bench -- --runs 3`: both parties in one process on an emulated link
  (`zkbench::transport::emulated_link`: a rate per direction and a pipelined one-way delay). Wall time covers
  a whole cold run (new → preprocess → key share → ECtF + stages A1–A3 → stages B1, B2) until both parties
  finish. Medians of 3 runs.
- `cargo run --release -p twopc --example procbench -- n|c <addr> <sessions>`: one party per process over
  loopback TCP; user and system CPU and peak resident set size from `getrusage`.

## Circuit

| | v2 | v3 |
|---|---|---|
| garbled AND gates | 656 179 (phase A 298 088 + phase B 358 091) | **479 022** |
| garbled SHA-256 compressions | 31 | **22** |
| XOR gates | | 2 305 963 |
| inputs: C / N / public digests (bits) | 1 280 / 992 / 512 (transcript hashes) | 256 / 256 / 2 304 |
| output bits | | 3 040 |

AND gates at the end of each stage (A1, A2, A3, B1, B2): 87 674 / 196 696 / 262 376 / 349 727 / 479 022.

## Bytes per run

| | v2 | v3 (`split-public-1`) | | v3 (`split-public-3`) |
|---|---|---|---|---|
| client up | 1.21 MB | 1.13 MB | −7 % | **1.13 MB** (+25 B) |
| client down | 22.12 MB | 16.38 MB | −26 % | **16.47 MB** (+82 006 B, +0.5 %) |

By phase, C's view (v2's phases A and B correspond to `handshake` and `application`):

| phase | v2: C sent | v2: C received | v3: C sent | v3: C received |
|---|---|---|---|---|
| version tag | | | 27 | 27 |
| preprocess | 1 213 910 | 22 072 758 | 1 133 521 | 16 339 646 |
| key share | | | 147 | 74 |
| ECtF | | | 125 | 130 |
| `handshake` stages (v2: phase A) | 73 | 20 498 | 327 | 24 612 |
| `application` stages (v2: phase B) | 238 | 24 077 | 240 | 20 498 |

(The v3 rows above are `split-public-1`'s, computed from the message sizes plus framing: the last report of a
call and N's first labels cross the step boundary in the measured per-step counters below. `split-public-3`
moves N's 4 096 bytes of input labels into preprocessing and adds 32 bytes of δ to the handshake; the next
section has its measured counters.)

Where v3's bytes go (computed from the circuit; OT traffic measured):

| | bytes |
|---|---|
| three-halves tables, N→C | 11 795 917 |
| check rows and Y_N (8 B per AND gate and per entering wire), N→C | 3 864 984 |
| mask commitment bits, N→C | 120 108 |
| label-check pairs (32 B per reported output wire), N→C | 80 896 |
| online labels and corrections, N→C | 45 056 (`split-public-3`: 4 096 of them in preprocessing, + 32 δ) |
| hash parameters, N→C (`split-public-3`) | 32 |
| input-label commitments, N→C (`split-public-3`: 2 560 wires × 2 × 16 B) | 81 920 |
| reports, d bits, seed, key share, C→N | 674 (`split-public-3`: 690, the 16-byte salt) |
| MAC COTs (Ferret over KOS, C sender, Δ_B): C→N / N→C | 1.09 MB / 0.45 MB |
| COTs for C's input (KOS, N sender, Δ_A): C→N / N→C | 12 kB / 4 kB |

v2: tables 16.2 MB, check rows 5.3 MB, MAC COTs 1.16 MB / 0.5 MB. v3's Ferret needs 960 988 COTs instead of
1.31 million, which saves one level of its second iteration.

## Cold run, per link

| link | v2 | v3 | |
|---|---|---|---|
| local, unlimited | 0.67 s | **0.45 s** | −33 % |
| 40 ms one-way, 2 Mbit/s up / 50 down | 7.42 s | **7.02 s** | −5 % |
| 40 ms one-way, 2 Mbit/s up / 10 down | 20.12 s | **15.61 s** | −22 % |
| 40 ms one-way, 7 Mbit/s up / 50 down | 5.50 s | **4.65 s** | −15 % |
| 25 ms one-way, 100 Mbit/s symmetric | 3.14 s | **2.68 s** | −15 % |

- On a 2 Mbit/s uplink with a fast downlink the upload is the critical path (1.09 MB of Ferret, 4.4 s), then
  the d bits, the seed and 3.9 MB of rows. v3 gains little there, and spends 0.3 s more online.
- Where the download is the bottleneck (10 Mbit/s down) v3 saves 4.5 s: 16.4 MB take 13.1 s of the 15.6.

## Wall time per step and side

v3, milliseconds, C / N:

| step | local | 2 up / 50 down | 2 up / 10 down | 7 up / 50 down | 100 symmetric |
|---|---|---|---|---|---|
| preprocess | 369 / 328 | 6 129 / 5 444 | 14 693 / 11 475 | 3 797 / 3 115 | 2 090 / 1 726 |
| key share | 3 / 45 | 86 / 819 | 86 / 3 346 | 86 / 816 | 55 / 437 |
| ECtF | 5 / 3 | 172 / 86 | 175 / 86 | 171 / 86 | 111 / 55 |
| `handshake` stages | 37 / 40 | 320 / 405 | 317 / 406 | 305 / 389 | 220 / 276 |
| `application` stages | 29 / 29 | 224 / 224 | 223 / 224 | 203 / 205 | 155 / 154 |

N's preprocessing ends when it has handed the rows to the transport; its key-share step then waits for C,
which is still receiving them. That is why N's key share looks slow and its preprocessing fast.

v2, C's view (from the earlier version of this file):

| step | local | 2 up / 50 down | 7 up / 50 down | 100 symmetric |
|---|---|---|---|---|
| preprocess | 567 | 6 836 | | |
| phase A / phase B | 40 / 51 | 132 / 150 | 152 / 164 | 111 / 126 |

## Online round trips (the request path, also of a pre-warmed session)

Every stage after A1 needs the inner digests of the previous stage's `IS_k`, and N sends their labels only
after C's report of that stage. That is one round trip per stage that v2 does not have.

| C's view, from the call to its return | v2 | v3 |
|---|---|---|
| `handshake` after ECtF | 1 | 3 (A1: d → corrections; A2 and A3: report → labels) |
| `application` | 1 | 1.5 (N sends the B1 labels unasked; B2: report → labels). 2.5 if N starts the call later than C |
| N returns after C by | 0.5 | 0.5 |

At 80 ms round-trip time that is about 0.19 s more in `handshake` and 0.07 s more in `application` than v2
(measured above: 320 and 224 ms against 132 and 150 ms), between the ServerHello and the first application
record. Local CPU online is lower than v2's (37 + 29 ms against 40 + 51 ms).

## CPU per side

`procbench`, loopback, user + system CPU of the process.

| | v2: C | v2: N | v3: C | v3: N |
|---|---|---|---|---|
| one run in a fresh process (includes building the circuit once) | 0.52 s | 0.60 s | **0.37 s** | **0.47 s** |
| per run, 8 runs one after another | 0.44 s | 0.53 s | **0.31 s** | **0.40 s** |
| per run, 8 runs at once | 0.51 s | 0.66 s | 0.38 s | 0.50 s |

48 runs one after another: C 0.30 s, N 0.39 s per run.

## Peak memory

`procbench`, peak resident set size of the process (`ru_maxrss`), macOS.

| | v2: C | v2: N | v3: C | v3: N |
|---|---|---|---|---|
| one run | 410 MiB | 517 MiB | **353 MiB** | **457 MiB** |
| 8 runs at once | 1 950 MiB | 2 600 MiB | 1 640 MiB | **2 130 MiB** |
| per additional concurrent run | 220 MiB | 300 MiB | 185 MiB | **240 MiB** |
| 8 runs one after another | 1 005 MiB | 1 026 MiB | 670 MiB | 683 MiB |

- The node's peak is in preprocessing: the zero-labels and MACs of all 2.8 million wires (46 MB each), the
  Ferret receiver, the tables and their serialised copy, the check rows. After preprocessing N keeps the labels
  of the circuit's inputs and outputs only (under 0.2 MB by construction; not measured separately), so an
  armed session waiting for a request is cheap on the node. On a slow link the peak state lives until C's
  seed arrives.
- One run of v3 peaked at 569 MiB on N before the check-row scratch values were made per stage (they were
  five vectors over the whole circuit); that change costs N about 0.03 s of CPU per run.
- The process does not return to its one-run size between runs: N's resident size grows over the first ~25
  sequential runs and then stays at 1.25 GB (flat from run 28 to 48; C: 0.98 GB). That is the allocator
  keeping freed regions (macOS), not a leak that keeps growing. Not measured on Linux, where the sidecar
  runs.
- C holds more than N after preprocessing: the tables (15 MB in memory), one label per wire (46 MB), the
  check keys (23 MB) and the rows, until each stage has used them.

## Table scheduling

N streams the tables in two parts around C's Ferret upload (`TABLES_GATE`: part 1, stages A1–A3, 6.5 MB, once
64 KiB of MAC-COT bytes arrived; part 2 once 500 000 bytes arrived, i.e. after the small N→C Ferret message
between the upload's two parts). The upload's first part is 484 184 bytes for v3's COT count as it was for
v2's, so the thresholds still sit where they should. Re-measured for this circuit (medians of 3):

| gates (bytes) | 2 up / 50 down | 2 up / 10 down | 100 symmetric |
|---|---|---|---|
| **65 536, 500 000** (kept) | 7.00 s | 15.63 s | 2.62 s |
| 8 192, 500 000 | 7.09 s | 15.49 s | 2.67 s |
| 2 048, 500 000 | 7.98 s | 17.21 s | 2.58 s |
| 65 536, 0 (one part) | 7.24 s | 17.66 s | 2.66 s |
| 65 536, 300 000 | 7.32 s | 17.67 s | |
| 200 000, 500 000 | | 16.22 s | 2.69 s |

Nothing beats the v2 setting by more than the noise (about 0.1 s), and opening either gate early costs up
to 2 s: a small OT message then waits behind megabytes of tables in the transport's buffers. Left as it is.

What is left on the 2/10 link: 16.4 MB at 10 Mbit/s is 13.1 s; the rest is 1.1 s before the first table byte
(the OT bootstrap), 0.7 s of turn-arounds (between the table parts, and d bits → seed → rows) and 0.8 s of
key share, ECtF and stages. The rows cannot be sent earlier: they depend on C's seed, which C sends only
after the tables and commitments arrived.

## `split-public-3` against `split-public-1`

Apple M2 Max, 2026-11-22, `examples/bench.rs --runs 3` built from both commits one after the other on the same
machine (medians of 3). Payload (`message_sizes()`): N→C 15 907 762 → 15 989 746 B (+81 984: 32 hash
parameters, 81 920 commitments, 32 δ), C→N 674 → 690 B (+16 salt); 4 more frames (3 N→C, 1 C→N).

Transport bytes per session including the tag, mux headers and OT traffic:

| | `split-public-1` | `split-public-3` | |
|---|---|---|---|
| C received | 16 384 987 | 16 466 993 | +82 006 (payload +81 984, +12 frame prefixes, the rest mux headers) |
| C sent | 1 134 221 | 1 134 246 | +25 (16 + 4 + one 5-byte mux header) |
| C received in preprocessing | 16 339 646 | 16 425 716 | +86 070 (N's input labels moved here) |
| C received in ECtF + stages A1–A3 | 24 742 | 20 678 | −4 064 |

Wall time, C's view, ms (cold session in seconds):

| link | step | `split-public-1` | `split-public-3` |
|---|---|---|---|
| local | cold session | 0.48 s | 0.46 s |
| local | preprocess / ECtF / `handshake` stages / `application` stages | 391 / 5.1 / 37.9 / 30.3 | 393 / 5.3 / 30.8 / 25.3 |
| 40 ms, 2 up / 50 down | cold session | 7.15 s | 7.09 s |
| 40 ms, 2 up / 50 down | ECtF + `handshake` stages / `application` stages | 171 + 337 / 230 | 172 + 320 / 206 |
| 40 ms, 7 up / 50 down | ECtF + `handshake` stages | 171 + 332 | 169 + 334 |
| 25 ms, 100 symmetric | ECtF + `handshake` stages / `application` stages | 110 + 240 / 169 | 111 + 228 / 149 |
| 40 ms, 2 up / 10 down | cold session | 15.67 s | 15.71 s |

δ adds no round trip: from ECtF to the end of stage A3 the time is unchanged on every link (a round trip is
50 to 80 ms there). The online stages are faster by the halved AES count (local: 38 → 31 ms and 30 → 25 ms).
Preprocessing is unchanged within noise; it is bound by the link and the OTs.

Live, through a loopback sidecar against the real provider (`driver.ts --sidecar`, 2026-11-22, model
`mistral-small-3-2-24b-instruct`, 20 tokens): `twopc_recv` 16 466 998, `twopc_sent` 1 134 422 for both framings
(`split-public-1`: 16 384 987 / 1 134 397); cu-2pc preprocess 432 ms, ECtF 0.4 ms, `handshake` stages 25 ms,
`application` stages 22 ms.

## The key-share proof (added to `split-public-2` in place, 2026-11-22/23)

N's key-share message is `P_N ‖ e ‖ s` (129 bytes) instead of `P_N` (65): a Schnorr proof of knowledge of
N's scalar, which C verifies before it opens its commitment (`PROTOCOL-V3.md` §4.1). The numbers in the
sections above are from before this change. Apple M2 Max, 2026-11-22, `examples/bench.rs --runs 3` from the
commit before and from this one, one after the other.

| | before | after | |
|---|---|---|---|
| payload N→C (`message_sizes()`) | 15 989 746 | 15 989 810 | +64 |
| payload C→N | 690 | 690 | |
| frames | | | none added (the proof is in the frame of `P_N`) |
| C received per session (transport) | 16 466 993 | 16 467 057 | +64 |
| C sent per session (transport) | 1 134 246 | 1 134 246 | |
| C received in the key share | 74 | 138 | +64 |

Key-share step, C's view, ms (N's view in brackets; N's step also waits for C to finish receiving the rows,
see "Wall time per step and side"):

| link | before | after |
|---|---|---|
| local | 2.5 (45.8) | 2.8 (46.7) |
| 40 ms one-way, 2 up / 50 down | 83.9 (830.8) | 85.5 (832.6) |
| 40 ms one-way, 7 up / 50 down | 83.8 (809.1) | 84.6 (824.1) |
| 25 ms one-way, 100 symmetric | 53.9 (450.2) | 55.0 (456.0) |
| 40 ms one-way, 2 up / 10 down | 85.1 (3 358.0) | 84.9 (3 350.3) |

The step is one round trip before and after (commitment, N's message, then the opening without waiting for
an answer): 80 ms on the 40 ms links, 50 ms on the 25 ms link. The proof adds no round trip. It costs N two
fixed-base multiplications instead of one and C one double multiplication, about 0.3 ms at C locally. Cold
session, before → after: local 0.46 → 0.45 s, 2/50 7.06 → 7.03 s, 7/50 4.72 → 4.69 s, 100 symmetric
2.71 → 2.69 s, 2/10 15.69 → 15.81 s (noise).

Live, through a loopback sidecar against the real provider (the runs of `v3-check.sh`, 2026-11-22, both
framings): `twopc_recv` 16 467 057 (16 467 062 where the multiplexer cut one chunk more), `twopc_sent`
1 134 417 or 1 134 422; before the change 16 466 998 and 1 134 422.

## Live (real provider, sidecar and reference driver on one host, 2026-11-11)

`driver.ts --sidecar` against this branch's `cu-sidecar` on loopback (stub settlement, no node), model
`deepseek-v4-flash`, 40 tokens, this branch's `cu-2pc` and `cu-prover`. π_NK, π_C2S and π_C3S ran unchanged
over the anchors hk, h1, h2 that the key schedule produced.

| run | cu-2pc preprocess | bytes C sent / received | `handshake` / `application` stages | receipt, usage |
|---|---|---|---|---|
| v3, cold | 411 ms | 1 133 526 / 16 339 646 | 30 / 25 ms | signature ok, usage matches |
| a v2 `cu-2pc` against the v3 sidecar | | | | refused: the sidecar logs `twopc_version_mismatch` (the peer's first byte was `0x00`), before any provider connection |

Tracing: `TWOPC_TRACE=1` prints preprocessing milestones and per-channel byte counts to stderr. It prints
timings and counts only, never secrets.

## History

Dual execution (21 MB each way, 85 s on a 2 Mbit/s uplink), the PoC without the download cuts, and the
removed `Proven` variant (14.74 MB down, 1.60 MB up, 8.93 s at 2/50) are in `docs/TWOPC-NODE-GARBLING.md` §9.
