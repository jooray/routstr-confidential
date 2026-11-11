# Node-only authenticated garbling: the construction

Status (2026-11-11): this is the garbling layer of the two-party key schedule `split-public-1` (protocol v3,
`PROTOCOL-V3.md` §4), implemented in `crypto/twopc` (`lib.rs`, `gc.rs`, `circuits.rs`). The protocol around it
(what is computed, the stages, who learns what, the security model and its limits) is in
`docs/TWOPC-DESIGN.md`; measurements are in `crypto/twopc/BENCH.md`. This file describes how one garbler and
one evaluator run the circuit: the garbling, the authenticated masks, the consistency check, the stages, the
labels N sends online and the label-check pairs. §9 is the history (dual execution, the PoC, v2).

Only N (the node) garbles. C (the client) evaluates and checks. Nobody opens an input afterwards.

## 1. Notation

- Δ_A: N's garbling offset (free XOR), 128 bits with lsb 1. Δ_B: C's MAC key, 128 bits with lsb 1 (127
  random bits). Both are fresh per session.
- k_w: N's zero-label of wire w. λ_w = lsb(k_w) is the wire's mask (the point-and-permute bit).
- The label of wire w with pointer bit Λ is `P_{w,Λ} = k_w ⊕ (Λ ⊕ λ_w)·Δ_A`. C holds `P_{w,Λ_w}` with
  Λ_w = z_w ⊕ λ_w, where z_w is the wire's true value. C sees Λ_w and, unless λ_w is opened to it, nothing
  about z_w.
- IT-MACs over GF(2^128): N holds (x, M[x]), C holds (K[x], Δ_B), and M[x] = K[x] ⊕ x·Δ_B.
- Base wires: the circuit inputs and every AND output. Every other wire is an XOR of base wires (INV adds the
  constant 1), so its mask, MAC and key follow by linearity.
- f: the SHA-256 compression function. TCCR: mpz2's fixed-key-AES hash, the hash of the garbling scheme and of
  the check rows.

## 2. The circuit and its stages

`circuits::SPLIT`: 479 022 AND gates, 22 SHA-256 compressions, evaluated in five stages (A1, A2, A3, B1, B2;
`docs/TWOPC-DESIGN.md` has the table of what each computes). Inputs: C's and N's shares of the ECDHE
x-coordinate (256 bits each) and nine inner digests of 256 bits (public values; N supplies their labels
online). Outputs are grouped by who learns them:

| kind | groups | mask | C reports to N |
|---|---|---|---|
| public | `IS_HS`, `c_hs`, `s_hs`, `IS_dHS`, `IS_MS`, `IS_c0`, `h1`, `h2`, `hk` | opened to C | pointer bits |
| C's | `s_ap_0`, `c_ap_1` | opened to C | nothing |
| N's | `K_0 ‖ IV_0` | stays with N | pointer bits |

**One circuit, not five.** The outer state `OS_k` of an HMAC key is an internal wire that continues into the
next stage. The alternative (separate circuits, the crossing state as XOR shares) would let C shift the state
by a difference of its choice when it re-inputs its share, and `f(OS ⊕ δ, d)` is then a related-key question
for the compression function. With one circuit there is nothing to re-input, and no output needs a mask
input: an output is opened to its owner only (C: N opens λ in preprocessing; N: C reports the pointer bit).

**Stage shapes** (`gc::stage_shapes`). The consistency check of a stage covers exactly the AND gates of that
stage. Its *row wires* are the wires that enter the stage and that an AND input of the stage depends on
(circuit inputs used there, and wires crossing from earlier stages), followed by every AND output of the
stage. A crossing wire is a row wire of the later stage in its own right, like a circuit input: its mask is a
committed linear combination, C holds its label, and its row is padded by hashes of its two labels. Without
that cut a later stage would need a row for most base wires of the earlier stages (measured: 7.6 MB of rows
instead of 3.85 MB). Crossing wires per stage: 256 (`OS_k`), and 512 into B2 (`OS_c0` and `s_ap_0`, which the
anchor h2 hashes). Rows per session: 479 022 AND outputs and 4 096 entering wires.

## 3. Preprocessing (input independent; runs in the pre-warm)

1. **Version tag.** The first bytes each party writes are `routstr-2pc/split-public-1\n`. A peer that sent
   anything else is refused (`twopc_version_mismatch`).
2. **Tables.** N garbles the circuit once with three-halves garbling (§6) and streams the tables: 24 B plus 5
   control bits per AND gate, 11.8 MB.
3. **Authenticated masks.** Random COTs with C as sender (Ferret over KOS, Δ_B; 960 988 of them) give N
   `(r, M[r])` and C `K[r]`. N fixes, with one bit `d = x ⊕ r` each: λ of every base wire, and
   `t_k = λ_i·λ_j` of every AND gate k = (i, j → o). 128 more COTs mask the product check.
4. **COTs for C's input.** KOS with N as sender (Δ_A): 256 random COTs, one per bit of C's share.
5. **Challenge.** C sends a 32-byte seed only after the tables and the d bits arrived. From it both derive χ
   for the product check, one χ_s per stage for the consistency check, and the salt.
6. N sends, all computed from values it committed before the seed:
   - *Product check* for all t_k (QuickSilver, batched with χ): `U = Σχ^k·M_i·M_j ⊕ M[a*]` and
     `V = Σχ^k·(M_i·λ_j ⊕ M_j·λ_i ⊕ M_t) ⊕ a*`. C checks `Σχ^k·(K_i·K_j ⊕ K_t·Δ_B) ⊕ K[a*] = U ⊕ V·Δ_B`.
   - *Openings*: λ of C's 256 input wires, of the 2 304 digest input wires and of every public or C's output
     wire, as bits plus one hash of their MACs. C recomputes the hash from its keys. These are the masks C
     later decodes with and checks pointer bits against.
   - *Check rows and Y_N*, per stage (§4): 8 B per row wire.
   - *Label-check pairs* (§7): 32 B per output wire C will report, 2 528 wires.
7. C verifies the product check and the openings and precomputes its check keys per stage.

Messages are sized by the circuit, which is fixed: C accepts each only at its exact length, and each
multiplexer channel has a cap on what the peer may send.

## 4. The consistency check (per stage)

For AND gate k = (i, j → o) the pointer bits C observes must satisfy

`e_k = λ_o ⊕ t_k ⊕ Λ_i·λ_j ⊕ Λ_j·λ_i ⊕ Λ_o ⊕ Λ_i·Λ_j = 0`,

which says z_o = z_i·z_j for z = Λ ⊕ λ. Under the MACs,
`Σχ^k·(M_o ⊕ M_t ⊕ Λ_i·M_j ⊕ Λ_j·M_i) = K_tot` with
`K_tot := Σχ^k·(K_o ⊕ K_t ⊕ Λ_i·K_j ⊕ Λ_j·K_i) ⊕ Δ_B·Σχ^k·(Λ_o ⊕ Λ_i·Λ_j)`, and this holds iff every e_k = 0
(except with probability n/2^128 over χ).

N does not know the Λ. It collects `X_w = Σχ^k·(MAC of the other input)` per wire, pushes X through the
stage's XOR/INV gates onto the stage's row wires (Λ is linear in their Λ), and sends per row wire b

`T_b = H(P_{b,0}) ⊕ H(P_{b,1}) ⊕ X_b`, and once `Y_N = Σχ^k·(M_o ⊕ M_t) ⊕ Σ_b H(P_{b,0})`.

C computes `Y_C = Σ_b [H(ℓ_b) ⊕ Λ_b·T_b]` from its active labels ℓ_b (one TCCR call per row wire) and accepts
iff `π(Y_N ⊕ Y_C ⊕ K_tot) = 0`.

- **64-bit rows.** Rows and Y_N travel projected to their low 64 bits (π, a GF(2)-linear map). MACs, Δ_B, χ
  and the product check stay in GF(2^128). A wrong evaluation (E = Σχ^k·e_k ≠ 0) passes only if π(Δ_B·E)
  equals a value N fixed without any information on Δ_B. For E ≠ 0 the map Δ ↦ π(Δ·E) is onto GF(2)^64; with
  lsb Δ_B fixed to 1 the image of the admissible Δ_B is all of GF(2)^64 (2^-64) or, for the ~2^-64 fraction
  of E whose kernel lies in lsb = 0, a 63-dimensional coset (2^-63). So ≤ 2^-63 per stage, ≤ 2^-60.6 for the
  five stages, and nothing to grind: N learns nothing about Δ_B and the first failure ends the session.
- **The salt.** H is TCCR with the tweak (salt, stage, row index); the salt comes from C's seed. With E = 0,
  a label that is not one of the wire's two labels but has the right pointer bit changes only the hash term of
  the sum, and a 64-bit hash matches with probability 2^-64. A garbler that reuses Δ_A and its keys across
  sessions could otherwise precompute (once, about 2^64 hash calls) a table deviation whose truncated hash
  difference is 0. Everything that fixes such a label (tables, Δ_A, N's keys) is committed before the salt is
  known, so the difference is a fresh 64-bit value. Test: `check_rows_bound_to_session_salt`.
- **Stage separation.** Each stage has its own χ_s and its own tweak space, and C takes each stage's rows and
  check keys once (`stage already used`).

C runs the check of a stage **before** it decodes, reports or otherwise uses any output of that stage.

## 5. Online, per stage

Stage A1:
1. C sends `d = x_C ⊕ b` (b = its COT choice bits). N sends the labels of its own input x_N, then the
   corrections `k_w ⊕ K_j ⊕ d_j·Δ_A`, which turn C's COT messages into the labels of x_C.
2. C checks the pointer bits of its input labels against `x_C ⊕ λ` (opened masks).

Stages A2, A3, B1, B2:
1. Both parties compute the inner digests `d = f(IS_k, m)` of the stage's inputs from the public `IS_k` of
   the stage before and their own transcript hash (`circuits::digest_blocks`: the HKDF-Expand-Label blocks).
2. N sends `k_w ⊕ d_i·Δ_A` for every digest wire. C checks each label's pointer bit against `d_i ⊕ λ_w`,
   with its own d and the opened, authenticated λ_w. C has one label per digest wire and no choice.

Every stage:
3. C evaluates the stage's gates, runs the stage's consistency check, and checks the label-check pair of
   every output wire it is about to report (§7).
4. If the pointer bits, the consistency check and the pairs all pass, C decodes the stage's outputs with the
   opened masks and sends `1 ‖ pointer bits of the public and N's outputs ‖ SHA256(their labels)`. Otherwise
   it sends the single byte `0` and aborts. Whatever failed, C evaluates the whole stage first and sends the
   same byte, so N cannot tell the three checks apart.
5. N recomputes the labels from the bits and its keys and compares the hash, decodes with its λ, and only then
   goes on to the next stage's digest labels. If the hash is wrong it sends `0` and aborts.

In B2, C also compares the anchors with its own outputs (h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0)) before it
sends the report; N compares hk with SHA256 of the `K_0 ‖ IV_0` it decoded.

Online bytes: 24.6 kB of labels N→C in `handshake` and 20.5 kB in `application`; C→N 32 B of d bits and
0.5 kB of reports in all. One round trip per stage.

**Labels N chooses online.** The check rows are committed in preprocessing, so the salt argument of §4
covers the tables and everything derived from them. The labels N sends online (its own input, the
corrections, the digest labels) are chosen when N already knows the salt. This is not a gap:

- a digest label of the other bit value (shift Δ_A) has the wrong pointer bit, and C aborts whatever its
  secrets are (C computed the digest itself);
- any other label is the right one shifted by an X that N knows, with lsb(X) = 0. The wire has a check row of
  its own (the test `stage_rows_cover_every_and_input` asserts this for every input wire), so the sum is off
  by `π(H(ℓ ⊕ X) ⊕ H(ℓ))`. N can grind X until that is zero (about 2^64 hash calls per attempt, online), but
  the first AND gate the wire reaches then outputs a pseudo-random label, and so does everything after it in
  the compression. Each of those is a row wire with a committed row, and their labels depend on `OS_k`,
  which N does not know, so N cannot aim X at a zero total. And every digest input reaches an output that is
  pair-checked in its stage (or, for `s_ap_0`, row-checked and anchored in B2), where a pseudo-random label
  fails the 128-bit pair hash.

Tests: `garbage_garbler_input_label_detected`, `wrong_digest_label_from_garbler_detected`,
`labels_for_another_digest_detected`, `lying_about_an_input_mask_detected`.

## 6. Three-halves garbling

`gc::and_garble3` / `and_eval3` (Rosulek–Roy, CRYPTO 2021): three 64-bit half-ciphertexts and five control
bits per AND gate (24.6 B instead of half-gates' 32 B), free XOR. The evaluator makes 3 TCCR calls, the
garbler 6, with tweaks (gate, slot) disjoint from the check tweaks (bit 127).

- The garbler solves the 2×5 linear system per gate. The evaluator's matrix R_st is uniform in the coset
  Rp[s][t] + span(S1, S2), so the control bits it decrypts do not depend on the permute bits.
- Composition with the check: the check uses only pointer bits and the fact that an honest evaluation ends
  with one of two Δ_A-related labels per row wire. Three-halves keeps both (free XOR, lsb Δ = 1, outputs
  `K0 ⊕ v·Δ`). Wrong control bits or ciphertexts give pseudo-random labels, which the check catches.
- Tests: `three_halves_gate_all_cases` (every permute pair, dicing pair and colour pair),
  `three_halves_control_bits_hide_permute_bits`, `garble_evaluate_matches_plaintext`, `tables_roundtrip`,
  `corrupt_control_bits_detected_by_evaluator`, `corrupt_garbled_table_detected_by_evaluator`.
- Caveat: the paper (eprint 2021/749) could not be fetched when this was built. The scheme was rebuilt from
  its structure, V_st = [[1,0,s,0,s⊕t],[0,1,0,t,s⊕t]] and dicing randomness. The evaluator matrices (S1, S2,
  Rp) come from a public C++ reimplementation, read as reference only; the garbler is derived independently
  and checked exhaustively. **The external review must compare the matrices with RR21's figure.**
  Correctness does not depend on them, but the privacy argument does.

## 7. Label-check pairs

For every output wire o that C reports to N (the public outputs and N's own: 2 528 wires), N sends in
preprocessing the pair

`( H(salt ‖ o ‖ 0 ‖ P_{o,0}), H(salt ‖ o ‖ 1 ‖ P_{o,1}) )`, SHA-256 truncated to 128 bits,

one half per pointer bit. Before C sends a stage's report it checks that the label it holds for each such
wire hashes to the half of its pointer bit, and aborts otherwise (the same single byte as any other failed
check of the stage).

Why. C's report carries a hash of its output labels, so that it cannot report a bit it has no label for. In
v2 that hash was sent bare. But it is a value N can test offline against as many candidate label sets as it
likes. The consistency check pins each row wire to *some* pair of labels N had in mind, by pointer bit; it
does not show that the two labels differ by Δ_A, or that a wire can carry only two labels. N can garble a
gate so that an output label depends on more than the wire's value (most simply an AND gate one of whose
inputs is N's own). If C held such a label, the bare hash would tell N which one, with no abort, and the
leakage would be bounded by the number of candidates N can enumerate, not by one bit. With the pairs N
commits, before C reveals anything, to the two labels it expects per wire; C compares first; a third label
is an abort inside the stage's one outcome; and the report hash is then a function of the pointer bits and
of N's own commitments. No concrete attack on the bare hash was found; the pairs remove the question for
81 kB of download and no extra message.

What the pairs cost a malicious C: nothing. A half is a salted hash of the label C does not hold, which
needs Δ_A.

Tests: `wrong_label_check_pair_detected`, `inconsistent_label_check_pair_is_a_selective_abort`,
`abort_looks_the_same_whatever_failed`, `cheating_evaluator_cannot_misreport`.

## 8. Why the anchors stay SHA-256

h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0) and hk = SHA256(K_0 ‖ IV_0) are computed in the circuit (three
compressions, about 63k AND gates, 2.1 MB of download). A replacement must bind C's witness in π_C2S/π_C3S
to the c_ap_1/s_ap_0 the 2PC produced against a malicious C, bind N's witness in π_NK to K_0 ‖ IV_0 against
a malicious N, be checkable in QuickSilver, and leak nothing usable to the other party.

- *Linear / universal hash keyed by the verifier.* Not binding if the key is known before the witness is
  committed; if the key stays secret, the public anchor leaks a 128-bit linear function of c_ap_1 to N.
- *IT-MAC import* (sound, zero AND gates). C's input bits are authenticated under Δ_A and N's masks under
  Δ_B; each proof would commit its witness and open the same random linear combination in the ZK VM and
  under the 2PC MACs. It removes SHA-256 from the 2PC and from all three proofs. It needs a two-stage commit
  in the zkbench statements, MAC material exported from `cu-2pc` to `cu-prover` and kept in the sidecar, new
  message flows and a new cross-system argument. Worth doing together with removing SHA-256 from the proofs,
  not as a bandwidth cut.
- *Proving the anchors in zero knowledge inside the 2PC* (the `Proven` prototype, §9): it needs C's output
  labels as commitments, which the consistency check does not justify (§7), or conversion COTs and a second
  Ferret. Removed.
- *AES-based Davies–Meyer anchor.* Needs second-preimage resistance of DM with adversary-chosen AES-128
  keys, a non-standard assumption for a binding anchor. Rejected.
- *One compression over c_ap_1 ‖ s_ap_0.* Saves 0.7 MB and changes the witness of both proofs and both
  clients' params. Too little for the churn.

## 9. History

- **Dual execution** (tag `v2-symmetric`): each side garbled once and the outputs were compared. 21.1 MB
  each way per session, 85 s cold on a 2 Mbit/s uplink. Leakage log2 3 ≈ 1.6 bits per session.
- **Choice of approach** (2026-10). Authenticated garbling with evaluator-shared masks
  (WRK17/KRRW18/DILO22/CWYY23) removes selective failure but needs authenticated triples (KRRW: about 5κ bits
  per AND, both ways) or DILO/CWYY's compressed preprocessing, which mpz2 does not have. Proving garbling
  correctness in zero knowledge is about 16.8 billion AND gates of statement. Shrinking dual execution
  bottoms out near 14.5 MB of client upload. Garbler-held masks with an IT-MAC consistency check (this
  construction) need only KOS, Ferret and TCCR from mpz2, at the price of selective failure.
- **PoC** (`crypto/twopc-ag`, half-gates, 128-bit rows): 1.21 MB up, 32.2 MB down, 11.5 s cold at 2/50
  Mbit/s. With KOS instead of Ferret for the MAC COTs: 0.06 MB up, 52.8 MB down.
- **v2** (branch `twopc-v2`): the PoC integrated, with 64-bit salted rows (−5.3 MB) and three-halves tables
  (−4.8 MB), two phase circuits (656 179 AND gates, 31 compressions), MS crossing between the phases as XOR
  shares, outputs masked by input masks, a bare report hash. 1.21 MB up, 22.1 MB down, 7.4 s cold at 2/50.
  Seven observable outcomes, log2 7 ≈ 2.8 bits per session.
- **Split key schedule, two prototypes** (2026-11): `Proven` (spec option B.2: `IS_k` to C only; C proves
  each inner digest and h1, h2 in zero knowledge under Δ_A with QuickSilver, N proves hk under Δ_B; 19
  compressions, 414 740 AND gates, 14.7 MB down but 1.60 MB up, because the second Ferret bootstraps from
  27 377 KOS COTs with C as receiver; slower than v2 on a 2 Mbit/s uplink) and `PublicIs` (this protocol).
  `Proven` also needed conversion COTs because C's labels cannot serve as commitments (§7), and it used Δ_A
  both as garbling offset and as MAC key. It was removed on 2026-11-11; it is in the history of the branch
  `v3-twopc-split` (commit `369517d` and before).
- A third variant was never built: `IS_k` to N only, N proves the digests under Δ_B. It would put the
  compression-function assumptions on N's side only and cost about the same as `PublicIs`.
