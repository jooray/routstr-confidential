# BENCHMARK — pre-warmed sessions (arm/pool) and rayon

*Measured on an Apple M2 Max, macOS, Rust 1.99 (release), node v26.
All numbers are medians of ≥5 successful runs unless stated. Model
`gemini-3-flash-preview`, `max_tokens 12`, against real `api.venice.ai`.*

Two questions:

1. How much of the confidential-upstream latency can a **pre-warmed (armed)
   session** remove from the request path?
2. Does enabling the **`rayon`** feature of `mpz-zk` help the proof bench?

## 1. Cold vs warm end-to-end latency

Command (sidecar on `127.0.0.1:7443 --node-settles`, node on `127.0.0.1:8000`,
local Cashu mint):

```
cd crypto/client && ./bench-warm.sh 5
```

`cold` = a full session per request (setup → handshake → KU0 → π_C1 → π_N →
credential record → body). `warm` = a session armed first (`--arm`: setup →
handshake → KU0 → π_C1 → π_N done up front) and claimed with a `go`; the timed
path is claim → KU1 + record → body. `baseline` = the same request as a plain
direct HTTPS streaming call. TTFT is measured from the request's start (for warm,
from the claim).

| metric | baseline (direct HTTPS) | cold | warm (armed) |
|---|---|---|---|
| **TTFT (median)** | 1189 ms | 1562 ms | 1318 ms |
| added TTFT vs baseline | — | **+373 ms** | **+129 ms** |
| total (median) | 1234 ms | 2018 ms | 1806 ms |
| added total | — | +784 ms | +572 ms |

Successful runs: cold 5/7 attempts, warm 5/6 attempts (see §4).

Phase breakdown (medians, ms):

| phase | cold | warm |
|---|---|---|
| ready (setup round-trip) | 53 | (done arming) |
| TLS handshake | 92 | (done arming) |
| KU0 | ~0 | (done arming) |
| **π_C1 + π_N** | **482** | (done arming) |
| credential record + KU1 | 1 | 1 |
| **claim → body write** | **621** | **1** |
| upstream TTFT (body → first token) | 909 | 1316 |
| — one-time arming cost (`arm_ms`, off the critical path) | — | 624 |

**Reading this:** the whole pre-request protocol — handshake, KU0, π_C1 and π_N,
and the credential-record assembly — moves into the arm step, which is paid once
and off the request path. The **protocol overhead before the body write drops
from 621 ms to 1 ms**. The end-to-end "added TTFT" is noisier because the
baseline run happened to see a faster upstream (909 ms) than the warm runs
(1316 ms): arming removes the *protocol* cost, not upstream variance. An earlier
run measured the same protocol drop (claim→body 620 ms → 1 ms) with added TTFT
**+633 ms cold → +24 ms warm**, so the honest headline is:

> Arming removes the entire pre-request protocol from the request path
> (**620 ms → 1 ms** of claim→body overhead); the residual added TTFT is the
> upstream's own variance around **+24…+129 ms**, well below the prototype's
> **+485 ms** cold figure.

Raw data: `/tmp/cu-warm/{cold.jsonl,warm.jsonl,baseline.json,summary.json}`
(copied to `runs/bench-warm/summary.json`).

## 2. rayon: proof bench before / after

Command:

```
cd crypto
cargo build --release -p zkbench --bin cu-prover --no-default-features   # rayon off
./zkbench/target/release/cu-prover --bench --json /tmp/bench-no-rayon.json
cargo build --release -p zkbench --bin cu-prover --features rayon        # rayon on
./zkbench/target/release/cu-prover --bench --json /tmp/bench-rayon.json
```

| statement | transport | no rayon (ms) | rayon (ms) | Δ |
|---|---|---|---|---|
| π_C1 | local | 468.3 | **324.1** | −31 % |
| π_C1 | wan | 1576.1 | **1442.2** | −8 % |
| π_N | local | 84.6 | **52.2** | −38 % |
| π_N | wan | 808.7 | **769.7** | −5 % |
| π_C2 | local | 457.2 | **290.4** | −36 % |
| π_C2 | wan | 1553.8 | **1400.3** | −10 % |
| π_C3 | local | 466.1 | **258.6** | −44 % |
| π_C3 | wan | 1567.6 | **1399.0** | −11 % |

`rayon` parallelises the proof-side hashing; it cuts local proof time by ~30–44 %
and WAN time by ~5–11 % (WAN is latency-bound). Bytes are unchanged.

**Caveat (important):** with `rayon` enabled on the *sidecar verifier*, the
concurrent e2e (π_C2 overlapping π_C3) stalled intermittently (>30 s) in
repeated runs. The feature is therefore **opt-in** (`--features rayon`), not the
default build, and the numbers above are used to quantify the benefit, not as
the shipped configuration. See `PROGRESS-CONFIDENTIAL.md` §Deviations.

## 3. How the arm path works

`--arm` performs setup, the TLS 1.3 handshake, KU0, the `c1_material` exchange,
π_C1 (verified by the sidecar, which then assembles the credential record) and
π_N. `--pool N` keeps N such sessions ready. A claim sends KU1 (which makes the
sidecar write the pre-assembled credential record + KU1 atomically) and the body.

Security is unchanged: π_C1's public inputs are `(client_hs, server_hs, th_SH,
th_SF, |head|, S, H1, T0)`, all bound to *this* session's TLS 1.3 key schedule and
to the head length; the request body itself is not part of π_C1. Arming binds the
session to the head length implied by the declared body length, so a claim whose
body length changes the `Content-Length` digit count would need a fresh π_C1
(the reference client arms per request shape; the pool uses one body size).

## 4. Run reliability

*(Updated after the proof-stall fix — `PROGRESS-CONFIDENTIAL.md` "Fix pass",
`crypto/runs/stall/NOTES.md`.)*

The intermittent ZK stall (one proof never returning) was a lost-final-bytes
race in the stdio/ws framing, not mpz2: `cu-prover` exited before its stdout
pump drained the prover's last message, and the sidecar's ws pump could drop the
verifier's last message. Both ends now await their outbound pump before
returning. With the fix, **`bench-warm.sh 5` completed cold 5/5 and warm 5/5
with zero retries** (previously cold 5/7, warm 5/6), and 20/20 sequential cold
sessions succeeded in each of three configurations (serial, parallel, rayon
on). The decisive arm-path metric (claim→body **1–2 ms**) held in every sample.

Fresh run, model `deepseek-v4-flash` (a `text_only_ok` model after the GAP-3
gate; see `crypto/VENICE-TESTS-ADDENDUM.md`):

| metric | baseline (direct HTTPS) | cold | warm (armed) |
|---|---|---|---|
| **TTFT (median)** | 1013 ms | 1804 ms | 777 ms |
| total (median) | 1398 ms | 2445 ms | 1848 ms |
| claim → body write | — | 641 ms | **2 ms** |
| π_C1 (median) | — | 485 ms | (done arming) |
| arm (off critical path) | — | — | 623 ms |

Successful runs: cold 5/5, warm 5/5. (Absolute TTFT is upstream-noise
dominated and not comparable across models; the protocol cost — claim→body
641 ms → 2 ms — is the stable result.)
