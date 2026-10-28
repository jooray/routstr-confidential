# Node-only garbling: design notes and PoC report

Status (2026-10-10): **integrated and the only 2PC.** The PoC crate `crypto/twopc-ag` was merged into
`crypto/twopc` (same `Party` API, same outputs, binary `cu-2pc`), and dual execution was deleted. The security
model is in `docs/TWOPC-DESIGN.md` ("Security model of the 2PC") and the measurements are in
`crypto/twopc/BENCH.md`. Tests: `cargo test --release -p twopc` (21 unit tests and 2 tests of the `cu-2pc`
binary). This file keeps the PoC report (§1–§7, as written before integration) and records the three download
cuts (§0).

## 0. The download cuts (verified, built, measured)

| | client up | client down | cold, 2/50 Mbit/s | 7/50 | 100/100 | 2/10 |
|---|---|---|---|---|---|---|
| dual execution (before) | 21.1 MB | 21.1 MB | 85.2 s | 24.9 s | 2.27 s | 85.2 s |
| PoC (Ferret), no cuts | 1.21 MB | 32.2 MB | 11.6 s | 8.27 s | 4.07 s | 32.2 s |
| **shipped**: cuts 1+2, Ferret, scheduling | 1.21 MB | 22.1 MB | **7.38 s** | **5.41 s** | 3.05 s | **20.0 s** |

The PoC's projection was ~5–6 s at 2/50. The floor is C's Ferret upload: 1.2 MB, about 4.9 s at 2 Mbit/s.
Everything after it (the d bits, the seed, 5.3 MB of check rows) is on the critical path.

**Cut 1: check rows over 64 bits (−5.3 MB). Built, with a fix.**
- What changed: only the comparison is projected. Rows and Y_N travel as their low 64 bits (π, GF(2)-linear),
  and C accepts iff π(Y_N ⊕ Y_C ⊕ K_tot) = 0. MACs, Δ_B, χ and the product check stay in GF(2^128).
- A wrong evaluation (E ≠ 0) passes only if π(Δ_B·E) hits a value fixed without knowledge of Δ_B. For E ≠ 0
  this is ≤ 2^-63 per phase (Δ_B has 127 random bits, and Δ ↦ π(Δ·E) is onto). With lsb Δ_B fixed to 1 the
  image of the admissible Δ_B is all of GF(2)^64 (2^-64) or, for the ~2^-64 fraction of E whose kernel lies in
  lsb = 0, a 63-dimensional coset (2^-63); 2^-63 is the worst case, ≤ 2^-62 per session. There is nothing to
  grind, because N learns nothing about Δ_B.
- E = 0 with some e_k ≠ 0 still needs 2^128 work (χ in GF(2^128), drawn after N's commitments).
- **What the plain projection did not cover.** With E = 0, a *garbage* label that has the right pointer bit
  changes only the hash term of the check, and with 64-bit rows the hash matches w.p. 2^-64. A garbler
  that keeps Δ_A and its keys fixed across sessions could precompute (once, ~2^64 TCCR calls, e.g. a table
  tweak δ in the left half of an AND output) a deviation whose truncated hash matches. That deviation passes
  the check and changes no output, but C's output-label hash then reveals which path the evaluation took. That
  is silent leakage, bit by bit, and not an abort.
- **Fix: a per-session salt.** The check-row hash tweak is keyed by a salt from C's challenge seed, which N
  sees only after it has committed its tables, d bits, Δ_A and keys. Everything that fixes such a label is then
  committed before the salt, so the hash difference is a fresh 64-bit value: 2^-64, no precomputation.
- Labels N chooses online (its own inputs, the transcript hash, the corrections for C's inputs) shift by
  amounts N knows, so they reveal nothing about C. The test is `check_rows_bound_to_session_salt`.

**Cut 2: three-halves garbling (−4.8 MB). Built.**
- `gc::and_garble3` / `and_eval3`: 3 × 64-bit halves plus 5 control bits per AND. The evaluator makes 3 TCCR
  calls, the garbler 6, with tweaks (phase, gate, slot) disjoint from the check tweaks.
- The garbler solves the 2×5 linear system per gate. The evaluator's matrix R_st is uniform in the coset
  Rp[s][t] + span(S1, S2).
- Composition with the check: the check uses only colour bits (lsb) and the fact that an honest evaluation
  ends with one of two Δ_A-related labels per base wire. Three-halves keeps both properties: free XOR, lsb
  Δ = 1, outputs K0 ⊕ v·Δ. The check rows need no re-derivation. Wrong control bits or ciphertexts give
  garbage labels, which the check catches.
- Tests:
  - `three_halves_gate_all_cases`: every permute pair, every dicing pair, every colour pair, 64 trials.
  - `three_halves_control_bits_hide_permute_bits`: the decrypted control bits are uniform for every permute
    pair.
  - `garble_evaluate_matches_plaintext`, `tables_roundtrip`.
  - `corrupt_control_bits_detected_by_evaluator`, `corrupt_garbled_table_detected_by_evaluator`.
- Caveat: the paper (eprint 2021/749) could not be fetched here (Cloudflare challenge). The scheme was
  rebuilt from its structure: V_st = [[1,0,s,0,s⊕t],[0,1,0,t,s⊕t]] and dicing randomness r$. The evaluator
  matrices (S1, S2, Rp) come from a public C++ reimplementation, read as reference only. The garbler is
  derived independently and checked exhaustively. **The external review must compare the matrices with
  RR21's figure.** Correctness does not depend on them, but the privacy argument does.

**Cut 3: dropping the h1/h2/hk compressions (~−2 MB). Not done; the hashes stay.** What a replacement must do:
- bind C's witness in π_C2S/π_C3S to the c_ap_1/s_ap_0 the 2PC produced, against a malicious C;
- bind N's witness in π_NK to K_0‖IV_0, against a malicious N;
- be checkable in QuickSilver;
- leak nothing usable about the secrets to the other party.

Options:
- *Linear / universal hash keyed by the verifier.* Not binding if the key is known before the witness is
  committed. If the key stays secret, the public anchor itself leaks a 128-bit linear function of c_ap_1 to N.
- *IT-MAC import* (sound, zero AND gates).
  - C's mask bits are already authenticated under Δ_A: the KOS COT gives C, for x = d ⊕ b, the MAC
    M = K ⊕ x·Δ_A. N's mask bits are authenticated under Δ_B through λ and Λ.
  - Each proof would commit the mask as its witness and then, after a verifier challenge χ, open the same
    random linear combination Σχ^j·x_j ⊕ r both in the ZK VM and under the 2PC MACs. r is committed in both
    systems beforehand.
  - This removes SHA-256 from the 2PC (about 63k AND, ~2.1 MB) and from all three proofs.
  - Cost: a two-stage commit in the zkbench statements, exporting MAC material from cu-2pc to cu-prover and
    keeping it in the sidecar, new message flows on the proof channel, param changes in both clients, and a
    new cross-system argument for review.
  - That is weeks of work and new attack surface for ~9 % of the download. It is worth doing later together
    with removing SHA-256 from the proofs, not as a bandwidth cut now.
- *AES-based Davies–Meyer anchor* (one AES-128 per anchor, ~6.4k AND instead of ~21k). It saves ~1.45 MB.
  It needs second-preimage resistance of DM with adversary-chosen AES-128 keys (ideal-cipher model), which is
  a non-standard assumption for a binding anchor. Rejected.
- *One compression over c_ap_1 ‖ s_ap_0* (a single anchor for π_C2S and π_C3S). It saves ~0.7 MB and changes
  the witness of both proofs and both clients' params. Too little for the churn.

## Verdict (PoC, before integration)

It works. With N as the only garbler, a cold session moves **0.06–1.2 MB from the client** instead of 21 MB. On a
2 Mbit/s home uplink the cold session drops from **85 s to 9.6 s**, and on 7 Mbit/s from 25 s to 8.4 s. The client
now mostly downloads (32–53 MB), so it is bound by its downlink.

Security is the same class as the deployed dual execution: malicious security for both sides, and inputs are never
revealed. A cheating N can only cause an abort that depends on C's values (selective failure), a constant number of
bits per session (§3), like dual execution's equality check. Nothing that reaches C's outputs or N's view can be
wrong without detection, except with probability about 2^-128.

On a symmetric 100 Mbit/s link it is slower than dual execution (4.1 s vs 2.3 s): 32 MB goes one way instead of
21 MB each way in parallel, and preprocessing has a few more sequential steps. That case is pre-warm material anyway.

## 1. Choice of approach

**(a) Authenticated garbling with evaluator-shared masks (WRK17 / KRRW18 / DILO22 / CWYY23): not feasible in this
PoC.**
- Removing the last bit of leakage needs the evaluator's share of every wire mask, which needs authenticated AND
  triples with cross terms.
- KRRW-style leaky-AND triple generation costs about 5κ+ bits per AND, in both directions. That is worse than dual
  execution.
- DILO/CWYY's compressed preprocessing (2 bits per AND, one way) needs block-COT/subfield-VOLE with L ≈ 1,000 keys
  (L = 2ρ·log(√e·n/2ρ)), F_{2^ρ} VOLE and "dual-key authentication". mpz2 has none of these; porting them is a
  multi-week job plus review.

**(a′) Garbler-only authenticated garbling with garbler-held masks and an IT-MAC consistency check: implemented.**
- N garbles plain half-gates.
- N's point-and-permute masks λ are authenticated to C under Δ_B.
- A CWYY-style batched check (one ciphertext per wire) verifies every AND gate.
- Leakage is selective failure, the class dual execution already accepts in `TWOPC-DESIGN.md`.
- Uses only KOS, Ferret and fixed-key-AES TCCR from mpz2.

**(b) N proves garbling correctness in ZK (QuickSilver): impractical.**
- Half-gates computes 4 fixed-key-AES calls per AND gate, at about 6,400 AND per AES. That is
  656,179 × 4 × 6,400 ≈ 16.8 billion AND gates of statement.
- QuickSilver needs about 1 bit per AND (about 2.1 GB of prover→verifier traffic) and about 19 minutes at 15M AND/s.

**(c) Keep dual execution and shrink it: not built.**
- Three-halves garbling: 21.0 → 16.2 MB per direction.
- Dropping the 3 anchor compressions (h1, h2, hk; about −63k AND): 18.8 MB with half-gates, 14.5 MB with
  three-halves.
- Best case is about 14.5 MB of client upload: 58 s at 2 Mbit/s, 17 s at 7 Mbit/s.
- It needs a new garbler in mpz2 and a two-stage ZK commit for the anchors, and its ceiling is far below (a′).

## 2. Protocol (as implemented)

Notation:
- The label of wire w with pointer bit Λ is `P_{w,Λ} = k_w ⊕ (Λ⊕λ_w)·Δ_A`, where k_w is N's zero-label and
  λ_w = lsb(k_w).
- C holds `P_{w,Λ_w}`, where Λ_w = z_w ⊕ λ_w and z_w is the true value.
- IT-MACs over GF(2^128): N holds (x, M[x]), C holds (K[x], Δ_B), and M = K ⊕ x·Δ_B.

**Preprocess** (input independent, can run in the pre-warm):
1. N garbles phase A and phase B once (half-gates with Δ_A, `gc::garble`) and streams the tables (32 B per AND). The
   circuits are `twopc::circuits`, reused unchanged: phase A has 298,088 AND gates, phase B 358,091.
2. Random "MAC COTs" are generated with C as the sender (Δ_B), using Ferret over KOS or KOS alone
   (`Config::mac_cot`). N fixes, with `d = x ⊕ r` (1 bit each, N→C):
   - λ for every circuit input and every AND output (the base wires). Every other mask follows by linearity, and
     INV adds the constant 1.
   - `t_k = λ_i·λ_j` for every AND gate.
   - Separately, KOS random COT with N as the sender (Δ_A) covers C's 1,280 input bits, as in `twopc`.
3. C sends a 32-byte seed (χ), only after N's tables and commitments have arrived.
4. N sends:
   - The product check for all t_k (QuickSilver): `U = Σχ^k·M_i·M_j ⊕ M_{a*}` and
     `V = Σχ^k·(M_i·λ_j ⊕ M_j·λ_i ⊕ M_t) ⊕ a*`. C checks `Σχ^k·(K_i·K_j ⊕ K_t·Δ_B) ⊕ K_{a*} = U ⊕ V·Δ_B`.
   - Openings of λ on C's input wires, the transcript-hash wires and all output wires: the bits plus one hash of
     their MACs.
   - Check rows, built as follows:
     - For AND gate k = (i, j → o) the relation is `e_k = λ_o ⊕ t_k ⊕ Λ_i·λ_j ⊕ Λ_j·λ_i ⊕ Λ_o ⊕ Λ_i·Λ_j = 0`.
     - Under the MACs, `Σχ^k·(M_o ⊕ M_t ⊕ Λ_i·M_j ⊕ Λ_j·M_i) = K_tot`, where
       `K_tot := Σχ^k·(K_o ⊕ K_t ⊕ Λ_i·K_j ⊕ Λ_j·K_i) ⊕ Δ_B·Σχ^k·(Λ_o ⊕ Λ_i·Λ_j)`. This holds iff every e_k = 0.
     - N does not know the Λ. It collects `X_w = Σχ^k·(MAC of the other input)` per wire and pushes X through the
       XOR/INV/ID gates onto the base wires (Λ is linear in the base Λ).
     - N sends one row per base wire, `T_b = H(P_{b,0}) ⊕ H(P_{b,1}) ⊕ X_b`, and
       `Y_N = Σχ^k·(M_o ⊕ M_t) ⊕ Σ_b H(P_{b,0})` (`gc::check_material`).
5. C verifies the product check and the openings, and precomputes its check keys.

**Phase** (online; A after ServerHello, B after the server Finished):
1. C sends `d = x ⊕ b` for its inputs. At the same time N sends the labels of its own inputs and of the transcript
   hash, then the corrections `k ⊕ R ⊕ d·Δ_A`.
2. C checks the pointer bits of its input labels against `x ⊕ λ` and of the transcript-hash labels against
   `th ⊕ λ`, using the opened, authenticated masks.
3. C evaluates and runs the check: `Y_C = Σ_b [H(ℓ_b) ⊕ lsb(ℓ_b)·T_b]` (one AES call per base wire). It accepts iff
   `Y_N ⊕ Y_C = K_tot`, which costs XORs plus one multiplication. It decodes its outputs with the opened λ.
4. Only then does C send `1 ‖ output pointer bits ‖ SHA256(output labels)`. N recomputes the labels from the bits
   and its keys, checks the hash and decodes.
5. On any failure C sends `0` and both abort.

Online cost:
- Phase A takes about 1.5 RTT (dual execution: 2), and about 35 ms of local CPU per phase.
- Online bytes C→N: 73 B in phase A, 238 B in phase B.

Outputs are identical to `twopc`:
- c_hs and s_hs go to both parties.
- s_ap_0 and c_ap_1 go to C; K_0 and IV_0 go to N.
- h1, h2 and hk are public.
- MS is split into XOR shares.

## 3. Security argument and assumptions

Assumptions:
- Fixed-key AES is a (circular) correlation-robust hash: the half-gates assumption, as in mpz2.
- KOS and Ferret are secure against a malicious receiver.
- C samples Δ_B and χ honestly; they only protect C.

**Malicious N against C:**
- **Binding.** N fixes every base λ and every t_k before it sees χ. Δ_B is independent of N's view (COT security).
  The products are covered by the QuickSilver argument, with error ≤ 2n/2^128.
- **Soundness of the AND check.** Let E = Σχ^k·e_k. C accepts iff `Δ_B·E = R`, where R is a value N can compute for
  any hypothetical C input from its own tables, rows, Y_N and labels.
  - If E ≠ 0, acceptance has probability 2^-128 over Δ_B.
  - If some e_k ≠ 0, then E = 0 with probability ≤ n/2^128 over χ.
  - N chooses its own input labels online after seeing χ, but grinding for E = 0 would take about 2^128
    evaluations inside a 15 s handshake window.
- **Correctness once accepted.** All e_k = 0 means z_w = Λ_w ⊕ λ_w satisfies every gate. C's inputs and the
  transcript hash are pinned by the pointer checks against the opened masks, and C decodes with authenticated λ.
  So C's outputs are the correct function of C's input, N's effective input and the real transcript. Logic changes,
  flipped decoding bits, a wrong transcript and a wrong OT correlation are all caught (tests below).
- **Privacy.** Before C's verdict, N sees only `d = x ⊕ b` (b uniform), the seed and the χ-independent traffic. N's
  view depends on C's private values only through abort events:
  - C's verdict, which N can make value-dependent by corrupting rows, check rows or the OT correlation (selective
    failure).
  - N's own output-label check, if N engineers non-standard labels that still pass C's check.
  - The predicate can involve internal wires, not only C's inputs: N can corrupt the check row of any wire,
    including internal HKDF wires, so a leaked bit can be a bit of s_ap_0 or c_ap_1.
  - Per phase N sees one of {C aborts, labels rejected, success}, and the session stops at the first failure.
    ECtF adds two outcomes (C's degenerate-share abort, and the server Finished failing between the phases).
    That is seven outcomes, ≤ log2 7 ≈ 2.8 bits per session, against log2 3 ≈ 1.6 for dual execution,
    assuming ECtF's semi-honest A2M/M2A gives a malicious N nothing beyond its outcome (`TWOPC-DESIGN.md`).
  - All shares, masks and scalars are fresh per session, and the session is discarded on abort, as
    `TWOPC-DESIGN.md` argues for dual execution.
  - Removing this leakage entirely needs evaluator-shared masks (option (a), §1).

**Malicious C against N.** C is the evaluator. It sees:
- the garbled tables;
- uniformly random labels and pointer bits Λ (the masks of N's inputs and of internal wires stay hidden);
- the opened λ for its own inputs, the public transcript hash and the outputs, which it also decodes in dual
  execution. N's private outputs stay masked by m_N, and MS by r_N;
- the `d` bits, padded by N's COT choice bits;
- the product-check pair, masked by a random VOLE;
- the check rows, padded by `H(P_{b,1−Λ_b})`, which needs Δ_A;
- `Y_N`, which equals `Y_C ⊕ K_tot`, a value C can compute itself.

C cannot report a wrong output (K_0⊕m_N, the public anchors, the masked MS) without an inactive output label, which
needs Δ_A (test `cheating_evaluator_cannot_change_n_outputs`). Its own input choice is free, as in any 2PC.
Inconsistent MS shares across phases yield a key nobody knows, as in v2.

**Not covered:**
- ECtF stays semi-honest, unchanged.
- No external review yet.
- KOS's documented consistency-check leakage applies to the MAC-COT layer (Δ_B, only C's concern) and to the
  KOS run for C's input labels (Δ_A, where C is the receiver). Both are negligible: forging with Δ_A needs all
  128 bits, and the leak is a few bits with correspondingly small probability.

**Tests** (all pass):

| test | what it shows |
|---|---|
| `honest_matches_reference` (×2) | outputs equal cu-crypto's `KeySchedule` |
| `honest_matches_reference_kos_macs` | same, with KOS MAC COTs |
| `garble_evaluate_matches_plaintext` | own half-gates garbler and evaluator are correct |
| `wan_session_works` | runs over the emulated WAN link |
| `corrupt_garbled_table_detected_by_evaluator` | corrupted tables: C aborts in the consistency check, N sees the abort |
| `logic_change_and_to_nand_detected` | a flipped mask on an internal AND gate (all else consistent) is caught only by the AND check |
| `wrong_and_product_detected_in_preprocessing` | wrong t_k: product check fails |
| `lying_about_output_mask_detected` | wrong opened decoding bit: MAC hash fails |
| `bad_check_value_detected` | wrong Y_N: check fails |
| `garbage_garbler_input_label_detected` | N's input label is not a valid label: check fails |
| `wrong_ot_correlation_detected` | C's input OT run with Δ' ≠ Δ_A: C aborts |
| `wrong_transcript_hash_from_garbler_detected` | wrong transcript hash: pointer check fails (both phases) |
| `cheating_evaluator_cannot_change_n_outputs` | C flips a reported output bit: N rejects (both phases) |
| `rogue_key_share_aborts` | key-share commitment check, as in `twopc` |

## 4. Measurements

Apple M2 Max, both parties in one process, `zkbench::transport::emulated_link` (per-direction rate, pipelined
one-way delay). Wall time is a whole cold session (new → preprocess → key share → ECtF + phase A → phase B) until
both parties finish. Median of 3 runs; dual execution on ≤ 7 Mbit/s uplinks is 1 run. MB = 10^6 bytes on the wire,
including mux headers and all OT traffic.

| link | protocol | cold session | C→N | N→C |
|---|---|---|---|---|
| local | AG, Ferret MAC COTs | 0.68 s | 1.21 MB | 32.2 MB |
| | AG, KOS MAC COTs | 0.51 s | 0.06 MB | 52.8 MB |
| | dual execution | 0.17 s | 21.1 MB | 21.1 MB |
| 40 ms, 2 Mbit/s up / 50 down | AG, Ferret | 11.5 s | 1.21 MB | 32.2 MB |
| | AG, KOS | **9.6 s** | 0.06 MB | 52.8 MB |
| | dual execution | 85.1 s | 21.1 MB | 21.1 MB |
| 40 ms, 7 Mbit/s up / 50 down | AG, Ferret | **8.4 s** | 1.21 MB | 32.2 MB |
| | AG, KOS | 9.6 s | 0.06 MB | 52.8 MB |
| | dual execution | 24.9 s | 21.1 MB | 21.1 MB |
| 25 ms, 100 Mbit/s symmetric | AG, Ferret | 4.1 s | 1.21 MB | 32.2 MB |
| | AG, KOS | 5.1 s | 0.06 MB | 52.8 MB |
| | dual execution | **2.3 s** | 21.1 MB | 21.1 MB |

Online steps at 40 ms one-way, AG vs dual execution:
- key share: 84 ms vs 84–190 ms;
- ECtF: 169 ms vs 170 ms;
- phase A: 121 ms vs 207 ms (123 ms evaluation + 84 ms equality check);
- phase B: 126 ms vs 287 ms (204 + 83 ms).

AG is about 80–200 ms faster online because there is no separate equality-check round trip.

Where the AG bytes go per session:
- N→C:
  - garbled tables: 21.0 MB;
  - check rows: 10.5 MB;
  - commitment bits d: 0.16 MB;
  - MAC COTs: about 0.5 MB with Ferret, or about 21 MB with KOS (N is the KOS receiver);
  - other (input OT, ECtF, online, key share): about 0.1 MB.
- C→N:
  - MAC COTs: about 1.15 MB with Ferret (C is the Ferret sender and uploads the GGM-tree messages), or about 4 KB
    with KOS;
  - other: about 0.06 MB.

Local CPU in preprocessing is 430–600 ms against 115 ms for dual execution. It is single-threaded: Ferret LPN, about
6 GF(2^128) multiplications per AND gate on each side, and label/key propagation. The two phases are independent and
could run in parallel. Online CPU is about 35–45 ms per phase.

## 5. Cold session on a home uplink (2 Mbit/s up, 50 Mbit/s down, 80 ms RTT)

| | client upload | client download | cold 2PC |
|---|---|---|---|
| today (dual execution) | 21.1 MB | 21.1 MB | 85 s |
| PoC, KOS MAC COTs | 0.06 MB | 52.8 MB | 9.6 s |
| PoC, Ferret MAC COTs | 1.21 MB | 32.2 MB | 11.5 s |
| projected with the cuts below (Ferret) | ~1.2 MB | ~22 MB | ~5–6 s (projected) |

- At 7 Mbit/s up, Ferret is the better choice (8.4 s vs 24.9 s).
- At ≤ 3 Mbit/s up, KOS is better: it uploads 62 KB but adds 21 MB of download.
- Either can be picked per client from a link estimate.

Download cuts (extrapolated, not implemented):
- check rows over GF(2^64) instead of GF(2^128): −5.3 MB, with 2^-64 soundness (still above ρ = 40);
- three-halves garbling (Rosulek–Roy) for N's tables: −5.2 MB;
- dropping the h1/h2/hk compressions: about −2 MB.

With all three, N→C is about 20 MB with Ferret, giving roughly 4–5 s at 50 Mbit/s down, plus round trips.

## 6. Integration plan and effort

The API is identical to `twopc::Party` (`new`, `preprocess`, `key_share`, `handshake`, `application`, `close`), with
the same outputs and circuits. `PiNK`, `PiC2S` and `PiC3S` are untouched because h1, h2 and hk are unchanged.

1. **Version.** Add a 2PC sub-version to the offer, e.g. `twopc: "ag1"`, or move to `v: 3`.
2. **Sidecar.** It must support both versions. As the garbler it now sends about 32 MB per session instead of 21 MB
   and uses about 0.5 s of CPU.
3. **`cu-2pc`.** Add a twopc-ag mode for the C side over the existing stdin/stdout transport.
4. **Relay.** Swap the N-side `Party` behind the same `/zk` WebSocket channel, and pass the `mac_cot` choice as a
   client hint in setup.
5. **Pre-warm.** Unchanged, since preprocessing is input independent. The client now downloads about 32 MB per
   pre-warmed session instead of exchanging 21 MB each way.
6. **Hardening:**
   - parallel per-phase preprocessing;
   - streamed, bounded-memory check rows (now about 11 MB held per phase);
   - constant-size abort messages;
   - parser fuzzing;
   - the three download cuts;
   - an external review of §3, especially the output-label predicate and the Ferret malicious-receiver assumption.

Effort:
- integration: about 1–1.5 weeks;
- hardening and performance: about 1 week;
- GF(2^64) rows: 1–2 days;
- three-halves garbling: about 1 week (mpz2 has no implementation);
- external review: separate.

## 7. Risks

- **Leakage class.** Selective failure remains: up to about 2.8 bits per session (conditional on ECtF) against about 1.6 for dual
  execution. That fits the v2 model but is not CWYY's no-leakage guarantee. Fixing it means evaluator-shared masks, a
  larger separate project.
- **Proof.** The soundness argument is a sketch, and this garbler-held-mask variant has no published proof.
- **Downlink.** On a 10 Mbit/s downlink, 32–53 MB takes 26–42 s, and symmetric links get slower than today.
  Mitigations: keep dual execution as a negotiable option, apply the §5 cuts, and pre-warm.
- **Node resources.** The node's egress rises about 50 % (32 vs 21 MB per session) and it spends about 0.5 s of CPU
  per session.
- **Ferret dependence.** Ferret's malicious-receiver security in mpz2 is assumed. KOS-only mode avoids that
  dependency at the cost of about 21 MB more download.
