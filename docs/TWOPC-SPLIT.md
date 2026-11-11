# Split key schedule (protocol v3, option B): prototype report

Status (2026-11-11): **feasibility prototype** on branch `v3-twopc-split`, `crypto/twopc` only. Not reviewed, not
deployed. The `Party` API, its outputs and their meaning are unchanged, so `zkbench`, the sidecar and the
clients build and run against it as they are. Measurements: `crypto/twopc/BENCH.md`. Tests:
`cargo test --release -p twopc` (32 unit tests, 3 tests of the `cu-2pc` binary). A live session through the
sidecar to Venice passed with both variants.

The base design is v2's node-only authenticated garbling (`docs/TWOPC-DESIGN.md`,
`docs/TWOPC-NODE-GARBLING.md`). This file describes only what changed.

## 1. Idea

`HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))`, with `f` the SHA-256 compression function,
`IS_k = f(IV, k ⊕ ipad)` and `OS_k = f(IV, k ⊕ opad)`. Every HMAC message of the TLS 1.3 key schedule is public
(labels and transcript hashes). The garbled circuit therefore computes only:

- the key-pad states `IS_k`, `OS_k` of the four secret HMAC keys (HS, the derived secret, MS, c_ap_0);
- the outer compressions `f(OS_k, pad(d))`.

The inner digests `d = f(IS_k, m)` are computed outside the circuit. `OS_k` never leaves the circuit.

| design | garbled AND gates | garbled compressions |
|---|---|---|
| v2 | 656 179 | 31 |
| **B.2 "proven"** (built) | 414 740 | 19 |
| **public IS** (built) | 479 022 | 22 |
| B.3 "aggressive" (circuit built for the count only) | 328 056 | 15 |

## 2. What was built

One circuit, evaluated in five stages. Two variants of how the inner digests are bound
(`twopc::Variant`, chosen with `TWOPC_VARIANT=public` or `Party::set_variant`; the default is `Proven`).

| stage | garbled | outputs |
|---|---|---|
| A1 | `Z = x_C + x_N mod p`; `HS = HMAC(salt, Z)` (2); `IS_HS`, `OS_HS` (2) | `IS_HS` |
| A2 | `c_hs`, `s_hs`, `dHS = f(OS_HS, ·)` (3); `IS_dHS`, `OS_dHS` (2) | `c_hs`, `s_hs` (public), `IS_dHS` |
| A3 | `MS = f(OS_dHS, d_0)` (1); `IS_MS`, `OS_MS` (2) | `IS_MS` |
| B1 | `c_ap_0`, `s_ap_0 = f(OS_MS, ·)` (2); `IS_c0`, `OS_c0` (2) | `s_ap_0` (C), `IS_c0` |
| B2 | `K_0`, `IV_0`, `c_ap_1 = f(OS_c0, ·)` (3) | `c_ap_1` (C), `K_0 ‖ IV_0` (N) |

`handshake` runs A1–A3, `application` runs B1–B2.

**One circuit, not five.** `OS_k` is an internal wire that continues into the next stage. The alternative
(separate circuits, the crossing state as XOR shares, as MS crossed between v2's phases) lets C shift the
state by a difference of its choice (it re-inputs its share), which turns `f(OS ⊕ δ, d)` into a related-key
question for the compression function. With one circuit there is nothing to re-input. MS no longer crosses as
shares either, and the output masks `r_C, r_N, m_C, m_N` are gone: an output is opened to its owner only
(C: N opens the mask in preprocessing; N: C reports the pointer bit).

**Per-stage consistency check.** v2's check (one 64-bit salted row per base wire, `Y_N`, C's keys) runs once
per stage, over exactly that stage's AND gates, with its own χ and its own row-hash tweaks. C runs it before
it decodes, converts, reports or otherwise uses any output of the stage. A wire that crosses a stage boundary
is a *row wire* of the later stage in its own right, like a circuit input: its mask is a committed linear
combination, C holds its label, and its row is padded by hashes of its two labels. (Without that cut a later
stage needs a row for most base wires of the earlier stages: 7.6 MB of rows instead of 3.3 MB. Measured, then
fixed.) Rows per session: AND gates + 256 crossing wires and the inputs per stage.

### 2.1 Variant `Proven` (spec B.2)

`IS_k` is opened to C only. C proves each inner digest to N in zero knowledge; N turns the proven digest into
the next stage's input labels. h1 and h2 are proven by C in the same way, hk by N.

Messages added to v2 (sizes for this circuit):

| when | direction | content |
|---|---|---|
| preprocess | both | Ferret over the existing KOS with N as sender (Δ_A): 208 961 random COTs for C (256 inputs, 1 536 conversions, 206 529 proof ANDs, 5 × 128 masks) |
| preprocess | N→C | *label-check pairs*: for each of the 2 272 output wires C reports or converts, two salted 128-bit hashes (72 kB) |
| after A1, A2, B1 | C→N | in the stage report: conversion bits `d = IS ⊕ r` and one hash over `label ⊕ M_r`; the proof of the next stage's digests (one correction bit per AND, then `U, V`) |
| after that | N→C | label corrections `k_w ⊕ K_d`, 16 B per digest bit, **only after** the report hash and the proof verified |
| start of `application` | C→N | the proof of `d_c0, d_s0` (they need `th_SF`) |
| after B2 | C→N | conversion bits for `c_ap_1` (those for `s_ap_0` went with B1), proof of h1, h2, the two hashes and one hash of their MACs |
| then | N→C | proof of hk, hk, one hash of its MACs |
| last | C→N | one byte: C's verdict on the hk proof (so that the session ends with a message from C, as in v2; the client's transport treats a close before its own result as an error) |

The proof system (`zk.rs`) is QuickSilver over GF(2^128) using `gc::dvzk_prover_acc` / `dvzk_verifier_acc`:
XOR, INV and AND-with-a-public-bit are local, an AND of two committed bits takes one random COT and one
correction bit, and all ANDs of a statement are checked with one pair `(U, V)` masked by 128 more COTs. The
message block is public, so the message schedule costs nothing: 18 045 COT-ANDs per inner digest (a full
compression has 22 573 AND gates), 22 062 for h1 and for h2, 22 029 for hk.
The challenge is Fiat–Shamir over the session seed, the statement and every correction bit (an interactive
challenge would cost one more round trip per stage).

**Deviation from the spec: C's labels are not used as commitments.** The spec says C's active label
`k_w ⊕ z·Δ_A` *is* an IT-MAC on `z`, so the outputs `IS_k` are commitments "with no extra message". That holds
only if every label C can hold is one of two labels at distance exactly Δ_A, and the consistency check does
not establish that: it pins each row wire to *some* pair of labels N had in mind, by pointer bit. N can garble
so that a wire's two labels differ by another offset, most simply an AND gate one of whose inputs is N's own
input. If C fed such a label into QuickSilver as a MAC, the check value `U` would no longer be simulatable:
`U ⊕ V·Δ_A ⊕ (N's side)` becomes a sum of terms `z_i·K_j·(D_i ⊕ Δ_A)`, i.e. it leaks witness bits to N with no
abort. For h2 the witness is `s_ap_0`.

What the prototype does instead:

1. C commits to each output bit `z` with a fresh random COT under Δ_A: `(r, M_r = K_r ⊕ r·Δ_A)`, sends
   `d = z ⊕ r`. All proof inputs are these COT commitments, so zero knowledge is QuickSilver's, whatever N did
   to the labels.
2. Binding to the circuit: `X = label ⊕ M_r` must equal `k_w ⊕ K_r ⊕ d·Δ_A`. N sends, in preprocessing, the
   salted hashes of both candidates (`d = 0, 1`): the label-check pair. C checks its `X` against the half for
   its `d` **before** it sends anything, and aborts on a mismatch. Then it sends `d` and one hash over all `X`;
   N compares. C cannot send a wrong `d` (it would need `X ⊕ Δ_A`).
3. With honest labels the pair check always passes. With inconsistent ones, N must guess the bit to make it
   pass: a selective-failure abort, not a silent leak.

The same pair check now also covers the outputs C reports to N (`c_hs`, `s_hs`, `K_0 ‖ IV_0`): v2's report
hash is replaced by "check N's pair, then send the hash". See §4.1.

An enumeration of all three-halves control-bit patterns (32 per gate; a throw-away script, not in the repo)
shows: for an AND gate whose inputs are Δ_A-consistent and all four input combinations reachable, a
consistent garbling of a 3–1 truth table forces the output offset to Δ_A; the 2–2 tables (projection, XOR)
leave half of the offset free but compute another function, which the consistency check catches unless N
knows one input. So for this circuit the spec's shortcut is probably sound up to selective failure, but that
is an argument about one garbling scheme and one circuit; the construction above does not need it.

**hk under Δ_B** works as the spec says, with no conversion: N's mask `λ_w` of an output wire is
authenticated by a COT whose keys are C's own, so `M[λ_w]` is a MAC on `z = Λ_w ⊕ λ_w` under the key
`K[λ_w] ⊕ Λ_w·Δ_B`, where `Λ_w` is the pointer bit C saw and reported (N accepted it only with the label
hash). The proof's COTs come from the existing MAC pool.

### 2.2 Variant `PublicIs` (not in the spec)

`IS_k` is a **public** output. Both parties compute the inner digests; N sends the labels of the digest input
wires and C pins them with pointer checks against opened, authenticated masks, exactly as v2 pins the
transcript hash. No proofs, no COTs under Δ_A beyond C's 256 input bits, no dual use of Δ_A. The anchors stay
garbled (22 compressions).

Why it is enough: the spec needs the proofs because the digest is C's *private input*, so C could feed the
digest of another label. If N supplies the label itself, C has one label per wire and nothing to choose. And C
checks N: a label for another digest fails the pointer check (deterministically, independent of any secret).

Cost in assumptions: N learns `IS_k` too. See §4.2.

A third option was not built: `IS_k` to N only, N proves the digests under Δ_B (the MAC pool has spare COTs,
so no second Ferret and no upload), digests public, h1/h2 garbled, hk proven. It puts the extra assumption
on the side of P2 instead of P1 and costs about the same as `PublicIs`.

## 3. Measurements (summary; `crypto/twopc/BENCH.md` has the tables)

| | v2 | `Proven` | `PublicIs` |
|---|---|---|---|
| client download | 22.12 MB | 14.74 MB | 16.38 MB |
| client upload | 1.21 MB | 1.60 MB | 1.13 MB |
| online round trips for C, `handshake` after ECtF | 1 | 3 | 3 |
| online round trips for C, `application` | 1 | 3 | 1.5–2.5 |

- `Proven` uploads more: the second Ferret (C is the receiver under Δ_A) bootstraps from 27 377 KOS COTs, and
  the KOS receiver sends 16 B per COT (438 kB). mpz2 fixes that bootstrap size. On a 2 Mbit/s uplink the upload
  is the critical path, so `Proven` is slower there than v2.
- Each stage needs one round trip that v2 did not have: C must report or prove before N releases the next
  stage's labels. That is +2 round trips per call (+4 per session) on the request path, also for a pre-warmed
  session. v2 spends the bytes in preprocessing instead.

## 4. Security assessment

What is argued here is argued informally, for a prototype. Nothing below is proven, and v2's own caveats
(no published proof of the garbler-only variant, semi-honest ECtF, Ferret/KOS assumed from mpz2) all remain.

### 4.1 Selective failure: outcomes per session

v2 counts seven outcomes: C's degenerate-share abort in ECtF; per phase "C aborted" and "C's output labels
rejected"; the server Finished failing between the phases; success.

With five stages N observes, in order, with the session ending at the first failure:

| # | outcome |
|---|---|
| 1 | ECtF: C's degenerate-share abort |
| 2–4 | C aborts in A1, A2, A3 (pointer bits, consistency check or label check: one byte, same message) |
| 5 | the server Finished fails between the calls |
| 6–7 | C aborts in B1, B2 |
| 8 | success |

**Eight outcomes, ≤ 3 bits per session** (v2: seven, 2.8), for both variants, under the same conditions as v2
(fresh single-use values; ECtF leaks nothing beyond its outcome).

"Labels rejected" is no longer an outcome, and this is the reason for the label-check pairs. In v2, C sends N
a hash of its output labels. v2's count treats N's comparison as one bit. But the hash is a value N can test
against as many candidate label sets as it likes, offline. If N can make C hold a label that passes the
consistency check and yet depends on an internal value, the hash tells N that value with no abort, and the
bound is the number of candidates N can enumerate, not one bit. Whether N can do that through SHA-256's AND
layers is not settled by the argument in `TWOPC-DESIGN.md`; I found no concrete attack (offsets other than Δ_A
do not survive an AND gate with four reachable input combinations without a value-dependent abort), but the
argument does not exclude it either. With the pairs, N commits to what it expects before C reveals anything,
C compares first, and a mismatch is an abort inside the stage's one outcome. **This would be a cheap
hardening for v2 as well** (32 B per reported output wire, no extra message).

Things that do **not** add outcomes:

- N's verification of C's proofs: its result is a function of N's own inputs and of C's messages, which are
  simulatable (correction bits padded by COT bits, `(U, V)` masked by a committed random element), provided the
  COTs are consistent (Ferret/KOS against a malicious sender, assumed, as for π_C2S/π_C3S today).
- C's verification of N's hk proof: it depends on N's messages and Δ_B, not on C's secrets.
- A wrong label or label correction for a digest input: the label is shifted by an amount N knows, independent
  of the digest. Either the pointer bit is wrong or the row hash is, for every digest alike.
- `PublicIs`: the digest labels are checked against a public value.

N can still aim the per-stage abort at any wire of that stage (rows are per wire), including now the bits of
the inner digests and of `IS_k`, which in `Proven` are C's.

Soundness of the checks themselves: five consistency checks at ≤ 2^-63 each instead of two; the proofs at
about 2^-110 work-normalised (Fiat–Shamir, ≤ 70 000 ANDs per statement) plus 2^-127 per attempt.

### 4.2 Does revealing `IS_k` need a new assumption?

Yes, a mild and standard one, and it is the same one whoever holds `IS_k`.

v2 uses HMAC-SHA256 as a black box: the only assumption is that HMAC (HKDF-Expand-Label) is a PRF. Here a
party knows `IS_k` and must not learn `f(OS_k, pad(d))` for the outputs that are not its own. That needs:

1. `f(·, x)` keyed by its chaining input is a PRF (so the outer compression under the unknown `OS_k` hides
   every output not handed out, including from someone who knows all inner digests);
2. `OS_k = f(IV, k ⊕ opad)` is pseudorandom given `IS_k = f(IV, k ⊕ ipad)` (the compression function keyed
   through its message input is a PRF under the related keys ipad/opad);
3. `IS_k` does not reveal `k` (implied by 2).

1 and 2 are exactly the two assumptions of Bellare's proof that HMAC is a PRF (CRYPTO 2006), so nothing is
assumed that the usual justification of HMAC does not already assume. But they are used directly here, not
through "HMAC is a PRF", and the party sees a value (`IS_k`) no HMAC user ever sees. The inner hash also loses
its secret key: with `IS_k` known, distinct messages must have distinct inner digests by plain collision
resistance. The messages are the fixed labels with the handshake's transcript hashes, which N checks itself,
so nobody gets to choose them.

Who carries it:

| variant | against a malicious C (protects K_0, the API key) | against a malicious N (protects s_ap_0, c_ap_1) |
|---|---|---|
| v2 | HMAC is a PRF | HMAC is a PRF |
| `Proven` (spec B.2) | 1 + 2, C knows all four `IS_k` | HMAC is a PRF |
| `PublicIs` | 1 + 2 | 1 + 2 |
| B.3 (not built) | 1 + 2 | 1 + 2 and N knows `OS_HS`, `OS_c0` |

C's view in `PublicIs` equals its view in `Proven`. The difference is N's.

### 4.3 Δ_A as garbling offset and as MAC key

Only `Proven` uses Δ_A for proofs.

- **What a malicious C learns from the check values.** Nothing is sent to C in its own proofs; it sees only
  whether N goes on. Every key of N is affine in Δ_A with coefficients C knows, so "N accepts" means "Δ_A is a
  root of a polynomial of degree ≤ 2 that C chose". A cheating C thus tests at most two guesses of a 127-bit
  value, once (the session ends on a failure, Δ_A is per session). There is no predicate on single bits of Δ_A.
- **What C holds under Δ_A.** COT outputs `K ⊕ r·Δ_A` with independent random keys: the same kind of value as
  the input labels of v2, which already come from a KOS run under Δ_A. The label-check pairs give C, for a
  value `X` it knows, a hash of `X ⊕ Δ_A`: what a garbled row gives it too, here with SHA-256. The correction
  `k_w ⊕ K_d` turns C's MAC on the proven bit into that bit's label and nothing else.
- **What is new for Δ_A.** In v2 only 1 280 KOS COTs run under Δ_A with C as receiver. Now a Ferret does, with
  209 000. Its security against a malicious receiver (C) protects Δ_A, and with Δ_A the API key. mpz2's Ferret
  is assumed for the mirrored role already (N as receiver against C's Δ_B, and in π_NK); this is the same
  primitive, with more at stake on this side.
- **What a malicious N can do with wrong corrections.** Nothing value-dependent, §4.1.
- **What a malicious N can do with inconsistent labels.** That is the deviation of §2.1: used as commitments
  they would leak silently; as built, N gets one guess per stage and an abort.

`PublicIs` has none of these questions.

### 4.4 Malicious C, per requirement of the spec

| attempt | result | test |
|---|---|---|
| prove a digest over another label's block | product check fails (N's keys of the public block bits differ by Δ_A) | `digest_for_the_wrong_label_rejected` |
| a wrong wire value inside a proof | product check fails | `wrong_proof_bit_rejected` |
| commit to another `IS_k`, `s_ap_0`, `c_ap_1` than the circuit gave | report hash fails (needs the inactive label) | `cheating_evaluator_cannot_change_n_outputs` |
| evaluate a stage with another digest than proven | C has one label per wire; with any other value the next report fails | `feeding_another_digest_than_proven_rejected` |
| open another anchor than proven | MAC hash fails | `lying_about_an_anchor_rejected` |
| another transcript hash than N's | N verifies over its own hash | `different_transcript_hash_detected` |

N sends label corrections only after the report hash and the proof verified. Otherwise C could evaluate the
next stage on an unproven digest and read that stage's outputs (its masks are opened in preprocessing) before
N notices.

## 5. Deviations from the spec

1. Labels are not used as commitments; conversion COTs and label-check pairs instead (§2.1).
2. One circuit for all five stages; no MS shares, no output masks (§2).
3. The label-check pairs also replace v2's bare report hash for N's outputs (§4.1).
4. The proof challenge is Fiat–Shamir.
5. A second variant, `PublicIs`, that needs no proofs (§2.2).
6. B.3 is not built; its circuit is, for the count. B.3 needs N to prove `c_hs`, `s_hs` and its own
   `K_0`, `IV_0` derivation under Δ_B from committed `OS_HS`, `OS_c0`, and C to open `d_c`, `d_s`, `d_key`,
   `d_iv`. Expected: about 11.9 MB down, the same upload and round trips as `Proven`.
7. The spec's stage table gives "A 8, B 7" for B.3; the circuit has A 10, B 5 (same total, 15).

## 6. Not done

- No proof, no external review. The staged check, the label-check pairs, the conversion and the
  Fiat–Shamir challenge are all new relative to v2.
- B.3.
- The browser library (`routstr-confidential-web` vendors `twopc`) and the docs outside this file are not
  updated; `AGENTS.md` and `TWOPC-DESIGN.md` still describe v2.
- No negotiation: both sides must run the same build and variant. A mismatch fails in preprocessing.
- Upload of `Proven`: the KOS bootstrap of the second Ferret. Options: a base OT extension with a cheaper
  receiver (SoftSpoken), or the "IS to N" variant, which needs no second Ferret.
- The table scheduling (`TABLES_GATE`) is v2's, tuned for v2's byte counts.
- Memory on the node is lower than v2 (it keeps input and output labels only), not measured.
