# twopc benchmark (protocol v2 two-party key schedule)

Node-only authenticated garbling: three-halves tables, 64-bit salted check rows, Ferret MAC COTs
(`docs/TWOPC-DESIGN.md`, "Security model"). Until 2026-10 this crate ran dual execution; its numbers are kept
below for comparison.

`cargo run --release -p twopc --example bench -- --runs 3` on an Apple M2 Max, with both parties in one
process. Link emulation is `zkbench::transport::emulated_link`: a rate per direction and a pipelined one-way
delay. Wall time covers a whole cold session (new → preprocess → key share → ECtF + phase A → phase B) until
both parties finish. Medians of 3 runs, except dual execution on uplinks ≤ 7 Mbit/s (1 run each). MB = 10^6
bytes on the wire, counting mux headers and all OT traffic.

## Circuits

| circuit | AND | XOR | SHA-256 compressions | C input bits | N input bits | output bits |
|---|---|---|---|---|---|---|
| phase A | 298 088 | 1 421 372 | 14 | 512 | 512 | 768 |
| phase B | 358 091 | 1 705 600 | 17 | 768 | 480 | 1504 |

N garbles each circuit once: 656 179 AND gates per session.

## Cold session, per link

| link | dual execution (before) | node-only PoC, no cuts (Ferret) | **now** | client up / down, now | before (dual ex.) |
|---|---|---|---|---|---|
| local, unlimited | 0.17 s | 0.67 s | **0.63 s** | 1.21 / 22.12 MB | 21.1 / 21.1 MB |
| 40 ms, 2 Mbit/s up / 50 down | 85.2 s | 11.6 s | **7.38 s** | 1.21 / 22.12 MB | 21.1 / 21.1 MB |
| 40 ms, 7 Mbit/s up / 50 down | 24.9 s | 8.27 s | **5.41 s** | 1.21 / 22.12 MB | 21.1 / 21.1 MB |
| 25 ms, 100 Mbit/s symmetric | 2.27 s | 4.07 s | **3.05 s** | 1.21 / 22.12 MB | 21.1 / 21.1 MB |
| 40 ms, 2 Mbit/s up / 10 down | 85.2 s | 32.2 s | **20.0 s** | 1.21 / 22.12 MB | 21.1 / 21.1 MB |

The PoC without cuts moved 1.21 MB up and 32.23 MB down (Ferret), or 0.06 up and 52.84 MB down (KOS MAC COTs).

Where the 10 MB (−31 %) of download went, measured:

- Check rows projected to 64 bits: −5.3 MB.
- Three-halves tables (24 B + 5 bits per AND instead of 32 B): −4.8 MB.

Where the time went, beyond the bytes. Ferret's 1.2 MB upload has two parts, separated by a 65-byte N→C
message, so any small N→C message queued behind megabytes of tables stalls an OT round trip. N therefore
schedules the tables around C's upload. Phase A's tables start once C is uploading (64 KiB received). Phase
B's tables start once C has passed Ferret's last interactive point (500 kB received), or once N's COTs are
done (`TABLES_GATE`). The tables go on a low-priority bulk channel of the mux. N computes the two phases'
check rows in parallel (80 ms instead of 200 ms).

| link | cuts, FIFO (Ferret) | cuts, FIFO (KOS MACs) | cuts + scheduling (Ferret, shipped) |
|---|---|---|---|
| local | 0.68 s | 0.51 s | 0.63 s |
| 2 / 50 Mbit/s | 9.97 s | 8.05 s | 7.38 s |
| 7 / 50 Mbit/s | 6.66 s | 7.98 s | 5.41 s |
| 100 / 100 Mbit/s | 3.25 s | 4.29 s | 3.05 s |
| 2 / 10 Mbit/s | 24.1 s | 35.4 s | 20.0 s |

**MAC-COT backend: Ferret, the only one.** KOS uploads nothing (0.06 MB) but makes N send 16 B per COT: 42.7 MB
down instead of 22.1 MB. With scheduling, Ferret is faster on every measured link, and on a 10 Mbit/s
downlink by 15 s. KOS would only win on uplinks well below 2 Mbit/s with a fast downlink. A KOS fallback would
add a negotiated mode for that corner, so there is none.

## Steps at 40 ms, 2 Mbit/s up / 50 Mbit/s down (C's view)

| step | ms | C sent | C recv |
|---|---|---|---|
| preprocess | 6 819.6 | 1 213 910 | 22 072 758 |
| key_share | 84.3 | 41 | 74 |
| ectf | 170.4 | 231 | 12 427 |
| phase_a | 126.4 | 73 | 8 201 |
| phase_b | 131.2 | 238 | 24 077 |

The critical path of preprocessing on a slow uplink is C's Ferret upload (1.2 MB, about 4.9 s at 2 Mbit/s),
followed by the d bits, the seed, and the check rows (5.3 MB). Online: about 1.5 round trips per phase, and
no separate equality-check round trip (dual execution needed 2).

## Local (no delay)

| step | ms | C sent | C recv |
|---|---|---|---|
| preprocess | 552.5 | 1 213 910 | 22 072 758 |
| key_share | 2.4 | 41 | 74 |
| ectf | 4.8 | 231 | 12 427 |
| phase_a | 32.8 | 73 | 8 201 |
| phase_b | 40.0 | 238 | 24 077 |

CPU: N garbles (six TCCR per AND), runs Ferret, computes the check material, about 0.5 s per session in
total. C's preprocessing is about 0.4 s (Ferret, key propagation). Each online phase takes 35–45 ms
(evaluation plus the check).

## Live (real Venice, local node and sidecar, 2026-10-10)

`deepseek-v4-flash`, 40 tokens, client and node on one host:

| run | cu-2pc preprocess | bytes C sent / received | phase A / B | receipt, usage |
|---|---|---|---|---|
| reference client, cold | 758 ms | 1 213 915 / 22 072 656 | 32 / 39 ms | ok, match |
| reference client, `--arm` | 701 ms | 1 213 915 / 22 072 758 | 47 / 40 ms | ok, match (claim → body 5 ms) |
| SDK `ConfidentialSession` | 840 ms | n/a | 32 / 38 ms | ok, match |

Tracing: `TWOPC_TRACE=1` prints preprocessing milestones and per-channel byte counts to stderr. It prints
timings and counts only, never secrets.

## Before: dual execution (for comparison)

Each circuit was garbled twice, once per party: 1 312 358 AND gates per session, 32 B each, about 21 MB in
each direction. At 50 ms RTT and 100 Mbit/s the preprocessing took 1.8 s; at 20 Mbit/s, 8.6 s. Online, each
phase was 1 RTT of evaluation plus 1 RTT of equality check.
