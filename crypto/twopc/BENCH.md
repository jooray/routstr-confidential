# twopc benchmark (protocol v2 two-party key schedule)

`cargo run --release -p twopc --example bench -- --runs 5` on an Apple M2 Max,
both parties in one process (tokio multi-thread), median of 5 sessions after a
warm-up. Times are C's wall clock per API step. Bytes are what each side wrote
to the transport during its own step (mux frame headers included).

WAN emulation (`twopc::testutil::emulated_pair`): 25 ms one-way latency
(50 ms RTT), and a serial link per direction at the given rate (full duplex).
Unlike `zkbench::transport`, latency is pipelined (it is not charged again for
every 64 KiB chunk), so bulk transfers are bandwidth-bound as on a real link.

## Circuits

| circuit | AND | XOR | SHA-256 compressions | C input bits | N input bits | output bits |
|---|---|---|---|---|---|---|
| phase A | 298 088 | 1 421 372 | 14 | 512 | 512 | 768 |
| phase B | 358 091 | 1 705 600 | 17 | 768 | 480 | 1504 |

Each circuit is garbled twice (dual execution): 1 312 358 AND gates garbled per
session, 656 179 by each party.

Phase A compressions: HS = HMAC(public salt, x) 2 (the salt's ipad/opad states
are constants) · HS keyed states 2 · c_hs 2 · s_hs 2 — **8 on the critical
path to c_hs/s_hs** — plus derived_hs 2 · its keyed states 2 · MS 2 = 6.
Plus a 256-bit modular adder (x_C + x_N mod p, ~770 AND).
Phase B: MS keyed states 2 · c_ap_0 2 · s_ap_0 2 · c_ap_0 keyed states 2 ·
c_ap_1 2 · K_0 2 · IV_0 2 · h1, h2, hk 1 each = 17.
Every HKDF-Expand-Label here fits one inner block (info + 0x01 ≤ 55 bytes).

## Local (no delay, unlimited bandwidth)

| step | ms | C→N bytes | N→C bytes |
|---|---|---|---|
| preprocess | 126.5 | 21 061 301 | 21 049 065 |
| key_share | 2.6 | 41 | 74 |
| ectf | 4.9 | 231 | 81 |
| phase_a (eval) | 23.8 | 20 566 | 20 620 |
| check_a | 2.4 | 109 | 41 |
| phase_b (eval) | 26.5 | 24 182 | 24 224 |
| check_b | 2.5 | 109 | 41 |
| **total** | 189.3 | | |

## WAN 50 ms RTT, 100 Mbit/s

| step | ms | C→N bytes | N→C bytes |
|---|---|---|---|
| preprocess | 1 834.6 | 21 036 708 | 21 049 065 |
| key_share | 57.1 | 24 634* | 74 |
| ectf | 108.5 | 231 | 81 |
| phase_a (eval) | 75.7 | 20 566 | 20 620 |
| check_a | 55.1 | 109 | 41 |
| phase_b (eval) | 79.2 | 24 182 | 24 224 |
| check_b | 54.4 | 114 | 114 |
| **total** | 2 264.6 | | |

## WAN 50 ms RTT, 20 Mbit/s

| step | ms | C→N bytes | N→C bytes |
|---|---|---|---|
| preprocess | 8 558.4 | 21 036 708 | 21 049 065 |
| key_share | 65.1 | 24 634* | 74 |
| ectf | 113.7 | 231 | 81 |
| phase_a (eval) | 85.7 | 20 566 | 20 620 |
| check_a | 58.7 | 109 | 41 |
| phase_b (eval) | 92.2 | 24 182 | 24 224 |
| check_b | 56.3 | 109 | 41 |
| **total** | 9 030.0 | | |

\* The tail of C's preprocessing (the KOS extension message for its 1 280
evaluator inputs, queued behind the garbled tables) leaves the mux after
`preprocess` returns, so it is counted in `key_share`. The key share itself is
~115 bytes.

## Round trips (online)

| step | round trips | notes |
|---|---|---|
| key_share | 1.5 (C waits 1) | C→N commit, N→C P_N, C→N open |
| ectf | 1.5 | A2M (N→C offsets, C→N masked) then M2A (both directions). The measured ~2 RTT includes C waiting for N to finish key_share; in the real flow ClientHello/ServerHello sit in between |
| phase eval | 1 | `d` and garbler-own labels both ways at once, then the derandomised evaluator labels; both runs run concurrently |
| equality check | 1 | commitments both ways, then openings both ways |

So after the ServerHello: ECtF + phase A ≈ 3.5 RTT + ~30 ms compute (≈ 210–240 ms
at 50 ms RTT); after the server Finished: phase B ≈ 2 RTT + ~30 ms (≈ 130–150 ms).

## Cost summary

- Preprocessing moves ~21 MB in each direction per session (the garbled tables:
  656 k AND × 32 B per run) and is bandwidth-bound: ~1.8 s at 100 Mbit/s,
  ~8.6 s at 20 Mbit/s. It is input independent and can run in a pre-warm.
- Online traffic is ~45 kB each way for the whole session.
- CPU: ~130 ms per party per session for garbling + evaluation (single
  session, M2 Max).
