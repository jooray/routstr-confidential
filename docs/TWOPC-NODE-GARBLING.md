# Node-only authenticated garbling: the construction

Status (2026-11-22): this is the garbling layer of the two-party key schedule `split-public-2` (protocol v3,
`PROTOCOL-V3.md` §4), implemented in `crypto/twopc` (`lib.rs`, `gc.rs`, `circuits.rs`). The protocol around it
(what is computed, the stages, who learns what, the security model and its limits) is in
`docs/TWOPC-DESIGN.md`; measurements are in `crypto/twopc/BENCH.md`. This file describes how one garbler and
one evaluator run the circuit: the garbling, the authenticated masks, the consistency check, the stages, the
input labels and their commitments, and the label-check pairs. §9 is the history (dual execution, the PoC,
v2, `split-public-1`). The construction has no published proof and has had no external review.

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
- f: the SHA-256 compression function. `H_g`: the garbling hash, keyed by N's per-session parameters (§6).
  `row`: the check-row hash, keyed by row parameters from C's seed (§4).

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

1. **Version tag.** The first bytes each party writes are `routstr-2pc/split-public-2\n`. A peer that sent
   anything else is refused (`twopc_version_mismatch`).
2. **C's salt.** C's first message is `in_salt`, 16 random bytes, the salt of N's input-label commitments
   (step 6).
3. **Tables.** N draws the hash parameters (32 bytes, §6) and its input mask ρ, garbles the circuit once with
   three-halves garbling and sends the hash parameters (32 bytes), then the tables: 24 B plus 5 control bits
   per AND gate, 11.8 MB.
4. **Authenticated masks.** Random COTs with C as sender (Ferret over KOS, Δ_B; 960 988 of them) give N
   `(r, M[r])` and C `K[r]`. N fixes, with one bit `d = x ⊕ r` each: λ of every base wire, and
   `t_k = λ_i·λ_j` of every AND gate k = (i, j → o). 128 more COTs mask the product check.
5. **COTs for C's input.** KOS with N as sender (Δ_A): 256 random COTs, one per bit of C's share.
6. **N's input and the input-label commitments** (§5). After the d bits N sends `gl`, the labels of ρ on its
   256 input wires (4 096 B), then `in_com`: for each of the other 2 560 input wires (C's 256, then the 2 304
   digest wires, the order of the opened input masks) the commitments to both labels, 32 B per wire,
   81 920 B.
7. **Challenge.** C sends a 32-byte seed only after the hash parameters, the tables, the d bits, `gl` and
   `in_com` arrived. From it both derive χ for the product check, one χ_s per stage for the consistency
   check, the salt of the label-check pairs, and the row parameters (§4).
8. N sends, all computed from values it committed before the seed:
   - *Product check* for all t_k (QuickSilver, batched with χ): `U = Σχ^k·M_i·M_j ⊕ M[a*]` and
     `V = Σχ^k·(M_i·λ_j ⊕ M_j·λ_i ⊕ M_t) ⊕ a*`. C checks `Σχ^k·(K_i·K_j ⊕ K_t·Δ_B) ⊕ K[a*] = U ⊕ V·Δ_B`.
   - *Openings*: λ of C's 256 input wires, of the 2 304 digest input wires and of every public or C's output
     wire, as bits plus one hash of their MACs. C recomputes the hash from its keys. These are the masks C
     later decodes with and checks pointer bits against.
   - *Check rows and Y_N*, per stage (§4): 8 B per row wire.
   - *Label-check pairs* (§7): 32 B per output wire C will report, 2 528 wires.
9. C verifies the product check and the openings and precomputes its check keys per stage.

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

`T_b = row(P_{b,0}) ⊕ row(P_{b,1}) ⊕ X_b`, and once `Y_N = Σχ^k·(M_o ⊕ M_t) ⊕ Σ_b row(P_{b,0})`.

C computes `Y_C = Σ_b [row(ℓ_b) ⊕ Λ_b·T_b]` from its active labels ℓ_b (two AES calls per row wire) and
accepts iff `π(Y_N ⊕ Y_C ⊕ K_tot) = 0`.

- **64-bit rows.** Rows and Y_N travel projected to their low 64 bits (π, a GF(2)-linear map). MACs, Δ_B, χ
  and the product check stay in GF(2^128). A wrong evaluation (E = Σχ^k·e_k ≠ 0) passes only if π(Δ_B·E)
  equals a value N fixed without any information on Δ_B. For E ≠ 0 the map Δ ↦ π(Δ·E) is onto GF(2)^64; with
  lsb Δ_B fixed to 1 the image of the admissible Δ_B is all of GF(2)^64 (2^-64) or, for the ~2^-64 fraction
  of E whose kernel lies in lsb = 0, a 63-dimensional coset (2^-63). So ≤ 2^-63 per stage, ≤ 2^-60.6 for the
  five stages, and nothing to grind: N learns nothing about Δ_B and the first failure ends the session.
  The bound is statistical and per connection. Across connections it adds up: Δ_B, χ and the row parameters
  are fresh each time, so a node that tries on every connection passes somewhere with probability at most
  k·2^-60.6 after k connections (about 2^-40.6 after 2^20), each failed try being an abort the client sees.
- **What the check proves.** With `K = M ⊕ λΔ_B`, C's test is `π(Δ_B·E(Λ)) = π(R)`, where
  `E(Λ) = Σχ^k e_k` is computed from the pointer bits C actually observed and `R` from N's messages, C's
  labels and Λ, none of which depends on Δ_B. If `E ≠ 0` the test passes with probability ≤ 2^-63, also when
  KOS leaked c bits of Δ_B (that leak goes unnoticed with probability 2^-c). If all `e_k = 0`, the values
  `Λ ⊕ λ` are the circuit's, whatever labels carried them. Between the two lies "`E = 0` although some
  `e_k ≠ 0`": probability ≤ n_s/2^128 over χ_s for the n_s AND gates of the stage (below 2^18) **if the
  pointer bits do not depend on χ**. No label and no hash enters this argument except through Λ.
- **N has no choice after the challenge.** The seed is sent in preprocessing. Before it N has sent the
  tables, the hash parameters, the masks, the labels of its own garbled input and commitments to both labels
  of every other input wire (§5). Its garbled input is a random mask ρ < p; in the handshake it sends
  `δ = x_N − ρ mod p` in the clear and C adds δ to its own share, which N cannot predict (below). C
  checks every input label it receives against the commitments. So C's evaluation, and with it Λ and E, is a
  function of what N sent before the seed, of C's input `x_C + δ` and of the digests C computes itself. What
  N sends after the seed (rows, Y_N, openings, pairs, corrections, digest labels) enters R and the abort
  conditions, and nothing else. Two places remain where N acts with χ known.
  (1) *δ and N's inputs to ECtF.* They change C's input only through C's point `Q_C = a_C·S`: C's share is
  `x_C = k·λ'^2 − x1 − d'` for values `k, d'` and a point `(x2', y2')` of N's choice
  (`TWOPC-DESIGN.md`, ECtF), so `x_C + δ` is a function of N's view and of `Q_C`. It is therefore not
  uniform given N's view, whatever N feeds into the conversion (N holds `a_C·G` and S, which determine
  `Q_C`); it is hidden only computationally. As a function of `Q_C` on the curve the map has degree ≤ 6,
  so each value has at most 6 preimages. For a uniform point independent of N's view, C's input would hit
  the set of inputs on which a prepared violation passes with probability at most `6·n_0/2^128`, averaged
  over χ_0 and for every choice N makes with χ_0 known. That the real `Q_C` gives N no more is
  **assumed**: DDH in P-256, for every N (not only one that feeds 0 into the conversion). Before stage A1
  ends N also holds U's flight, encrypted under keys derived from Z; that it does not help is the
  oracle-model step of the ECtF argument. The reduction is not written out. For a server share N chose
  itself no claim is made, and that connection ends at CertificateVerify.
  (2) *The transcript hashes.* N relays the ServerHello and the server flight and so can influence `th_SH`
  and `th_SF`. N holds `s_hs`: it can open U's flight, change it, seal it again and recompute the
  Finished, with χ and `IS_MS` known. What C accepts is then N's choice of `th_SF`, so C must accept only
  what U's signature fixes. The signature covers the transcript up to Certificate. C's TLS stack requires
  that CertificateVerify ends with its signature, that an ECDSA signature is the DER encoding of `(r, s)`,
  that the Finished follows directly, and that no other message type appears (the three client stacks:
  `FORK-NOTES.md`, TLS-17). An ECDSA signature `(r, s)` also verifies as `(r, n − s)`, so N has at most two
  values of `th_SF`: a factor 2 on stage B1's term. A stack that accepts q flights per signature gives
  `q·n_3/2^128` there; the stacks released with `split-public-1` accepted any number (among others,
  bytes after the signature were ignored), which made that term a bound on N's work (at most about
  2^-111 per flight tried) and not a statistical one. `th_SH`
  is fixed before stage A1 runs, when N does not know `IS_HS`, and a flight of U that N has not opened yet
  is fixed with it; that a choice of `th_SH` with χ known does not raise the later terms noticeably is
  **assumed** (it holds if `f` keyed by its chaining input behaves as a random function). Under these
  assumptions the bound per connection is
  `5·2^-63 + (6·n_0 + n_1 + n_2 + 2·n_3 + n_4)·2^-128 + ε_QS ≤ 2^-60.6` for a connection whose server
  share N did not choose (ε_QS: the product check's error). **Argued**, new in `split-public-2`, no
  review. Tests: `adder_switch_attack_caught`, `gl_precedes_seed`, `in_com_precedes_seed`,
  `delta_out_of_range_rejected`; for the flights C accepts, the TLS-17 tests of the three client stacks.
- **`split-public-1` did not have this (found 2026-11-22).** There N sent the labels of its input `x_N` in
  the handshake, after the seed, so with χ known. Garbling every second gate of the adder as `(¬A)∧B` makes
  that gate's `e_k` equal to a bit of `x_N` whenever the carry into it is 0; N then solves 128 linear
  equations over GF(2) for an input with `E = 0`, and the carries are 0 often enough: a wrong sum passed
  stage A1 with probability about 2^-23 per connection instead of 2^-63 (measured with the check code of
  this repository; `adder_switch_attack_caught` runs it in the old message order through a test hook and
  sees it pass). The sum was then wrong, so Z was wrong, C failed on the provider's first encrypted record,
  and the later stages did not run. No use against a traffic secret is known.
- **The row hash.** `row(X; s, idx) = lo64(AES_{k_r}(H_g(X, 2^63 | τ) ⊕ U_r(τ)))` with `τ = s·2^32 | idx`
  (idx = the position of the wire among the stage's row wires). The inner call is a query of the garbling
  hash on a tweak no gate uses (bit 63 set), so the pad of the label C lacks is covered by the same
  assumption as the tables (§6; the extension of that game by these queries is argued), and the outer call is a bijection whatever key C's seed produces. `k_r` and
  `U_r` come from `SHA256("routstr-twopc-ag chi" ‖ seed ‖ "row-params" ‖ hparams)`, read with the layout of
  the hash parameters, after N committed to the tables and masks: a change of labels on different wires
  that N fixed before the seed changes C's sum by a fresh 64-bit value (AES as a PRP; this is defence in
  depth, the argument above does not use it). Two labels of the same wire with equal `H_g` (a collision N
  could search for with about 2^64 work, since it knows the key) give equal rows; the row hash does not
  exclude that, and on input wires the commitments of §5 do.
  Tests: `check_rows_bound_to_session_seed`, `swapped_labels_fail_the_row_sum`.
- **The salt of `split-public-1`, corrected.** In `split-public-1` the row hash was mpz2's fixed-key TCCR with
  the tweak (salt, stage, row index), the salt from C's seed XORed into the tweak. This file said that a
  label with the right pointer bit that is not one of the wire's two labels changes the sum by a 64-bit
  hash difference, which matches with probability 2^-64. That is false for pairs of wires: the salt cancels
  between the tweaks of two wires, so for any two row wires N could compute, without knowing the salt, a
  pair of labels (each derived from the other wire's label and the salt-free tweak difference) that left
  the sum unchanged for every salt when C held them. It did not affect correctness, which does not rest on
  the row hash (the bullets above), and no exploit was found. `split-public-2` keys the outer cipher
  instead, so such a pair changes the sum (`swapped_labels_fail_the_row_sum`).
- **Stage separation.** Each stage has its own χ_s and its own tweak space, and C takes each stage's rows and
  check keys once (`stage already used`).

C runs the check of a stage **before** it decodes, reports or otherwise uses any output of that stage.

## 5. Online, per stage

Stage A1:
1. N sends `δ = (x_N − ρ) mod p` (32 bytes, little-endian) as soon as its ECtF returned. C refuses a δ ≥ p
   and computes `x_C' = (x_C + δ) mod p`. The circuit adds ρ, whose labels C already holds, so it computes
   `x_C' + ρ = x_C + x_N mod p`.
2. C sends `d = x_C' ⊕ b` (b = its COT choice bits). N sends the corrections `k_w ⊕ K_j ⊕ d_j·Δ_A`, which turn
   C's COT messages into the labels of `x_C'`.
3. C checks the pointer bits of its input labels against `x_C' ⊕ λ` (opened masks) and checks each label
   against N's commitment.

Stages A2, A3, B1, B2:
1. Both parties compute the inner digests `d = f(IS_k, m)` of the stage's inputs from the public `IS_k` of
   the stage before and their own transcript hash (`circuits::digest_blocks`: the HKDF-Expand-Label blocks).
2. N sends `k_w ⊕ d_i·Δ_A` for every digest wire. C checks each label's pointer bit against `d_i ⊕ λ_w`,
   with its own d and the opened, authenticated λ_w, and checks the label against N's commitment. C has one
   label per digest wire and no choice.

Every stage:
3. C evaluates the stage's gates, runs the stage's consistency check, and checks the label-check pair of
   every output wire it is about to report (§7).
4. If the pointer bits, the commitments, the consistency check and the pairs all pass, C decodes the stage's outputs with the
   opened masks and sends `1 ‖ pointer bits of the public and N's outputs ‖ SHA256(their labels)`. Otherwise
   it sends the single byte `0` and aborts. Whatever failed, C evaluates the whole stage first and sends the
   same byte, so N cannot tell the checks apart.
5. N recomputes the labels from the bits and its keys and compares the hash, decodes with its λ, and only then
   goes on to the next stage's digest labels. If the hash is wrong it sends `0` and aborts.

In B2, C also compares the anchors with its own outputs (h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0)) before it
sends the report; N compares hk with SHA256 of the `K_0 ‖ IV_0` it decoded.

Online bytes: 20.5 kB N→C in `handshake` (δ, the corrections, the digest labels) and 20.5 kB in
`application`; C→N 32 B of d bits and 0.5 kB of reports in all. One round trip per stage. δ adds no round
trip: it leaves N when its ECtF returns and reaches C with N's last ECtF message, which C needs anyway
before it can form d (measured: the time from ECtF to the end of stage A3 is unchanged, `BENCH.md`).

**The input labels are committed before the seed.** Every label C holds on an input wire is fixed by what N
sent before the seed:

- *N's own input wires* carry ρ, and their labels `gl` are sent before the seed. They need no commitment and
  have no pointer check (their masks are not opened).
- *C's input wires and the digest wires.* Before the seed N sends, for each such wire w in the order of the
  opened input masks, `com(w, 0, P_{w,0}) ‖ com(w, 1, P_{w,1})` with
  `com(w, p, L) = SHA256("routstr-twopc-ag input label" ‖ in_salt ‖ w_be32 ‖ p ‖ L)[0..16]`: w the wire's
  feed id as 4 big-endian bytes, p the label's pointer bit as one byte, L the 16 label bytes, `in_salt` the
  16 bytes C sent first. For each label L it obtains later, C checks `com(w, lsb(L), L)` against the
  entry for `lsb(L)` of w's pair in `in_com` (the pair's position in that order, not w: the feed ids of N's
  own input wires lie between C's and the digest wires'), in addition to the pointer bit. A mismatch counts as a failed
  input check: C evaluates the stage and aborts with the same single byte as for any other failed check.
- After the seed, the label C holds on such a wire is the unique label with the right pointer bit that
  opens the commitment, unless N found two labels with one commitment: a collision of a 128-bit hash under
  a salt it learned in this session (about 2^64 work within one session). **Argued.**
- What the commitments cost N: C sees a hash of the label it does not hold, as in the label-check pairs.
  That SHA-256 hides a 128-bit value related to other values by Δ_A is **assumed**, as for the pairs.
- Selective failure: a wrong commitment for one pointer bit of one wire makes C abort iff that wire has that
  value. That is one predicate, observed as the stage's abort, which N could already plant with a wrong
  label or a wrong half of a label-check pair; the count of outcomes does not change.

In `split-public-1` these labels were not committed: C checked only their pointer bit, and N chose them with
the salt and the challenge known. This file argued, heuristically and for this circuit only, that such a
label leads to a pseudo-random label behind the next AND gate and so to an abort. The argument skipped the
step from "the check passes" to "every gate is consistent", which needs N not to adapt the pointer bits to
the challenge; a label of N's choice after the seed is such an adaptation. No attack through these labels
was shown for this circuit; `split-public-2` removes the question by the commitments.

Tests: `third_label_for_c_input_detected`, `wrong_input_commitment_is_a_selective_abort`, `in_com_precedes_seed`,
`garbage_garbler_input_label_detected`, `wrong_digest_label_from_garbler_detected`,
`labels_for_another_digest_detected`, `lying_about_an_input_mask_detected`.

## 6. Three-halves garbling

`gc::and_garble3` / `and_eval3` (Rosulek–Roy, CRYPTO 2021): three 64-bit half-ciphertexts and five control
bits per AND gate (24.6 B instead of half-gates' 32 B), free XOR. The evaluator makes 3 calls of `H_g`, the
garbler 6, one AES call each, with tweaks `3·gid + slot` (gid the global index of the AND gate, slot 0 for
A, 1 for B, 2 for A ⊕ B), all below 2^63 and so disjoint from the row tweaks (bit 63 set).

**The hash** (`gc::HashG`). `H_g(X, τ) = AES_k(Y) ⊕ σ(Y)` with `Y = X ⊕ U(τ)`, the family Rosulek and Roy
recommend. 128-bit values are `u128`, their 16 bytes little-endian. `U(τ) = (u1·τ) ‖ (u2·τ)` (high half,
low half) and `σ(Y_hi ‖ Y_lo) = (x·Y_hi) ‖ (x·Y_lo)`, both in GF(2^64) = GF(2)[x]/(x^64 + x^4 + x^3 + x + 1),
where a `u64` is the polynomial whose coefficient of x^i is bit i (`xtime(a) = (a << 1) ⊕ (0x1b & −(a >> 63))`).
The parameters `hparams` are 32 bytes: k (bytes 0..16, the AES-128 key as given to the cipher), u1 (16..24)
and u2 (24..32), both little-endian. N draws them per session from a generator seeded by the OS, before garbling, and
sends them right before the first table byte; C reads exactly 32 bytes there and applies no check to them:
no argument that protects C uses `H_g` (§4), so a weak choice (say `u1 = u2 = 0`) weakens only N's own
protection (`n_with_degenerate_hparams_completes`). The gate takes the masking half from the low 64 bits of
`H_g` and the control bit from bit 127. Against `split-public-1`'s fixed-key TCCR (two AES calls per hash)
this halves the AES calls per AND gate: N 6 instead of 12, C 3 instead of 6. The conformance vectors are in
`crypto/conformance/twopc-hash-vectors.json` (`hash_vectors_match_conformance_file`).

- The garbler solves the 2×5 linear system per gate. The evaluator's matrix R_st is uniform in the coset
  Rp[s][t] + span(S1, S2), so the control bits it decrypts do not depend on the permute bits.
- Composition with the check: the check uses only pointer bits and the fact that an honest evaluation ends
  with one of two Δ_A-related labels per row wire. Three-halves keeps both (free XOR, lsb Δ = 1, outputs
  `K0 ⊕ v·Δ`). Wrong control bits or ciphertexts give pseudo-random labels, which the check catches.
- Tests: `three_halves_gate_all_cases` (every permute pair, dicing pair and colour pair),
  `three_halves_control_bits_hide_permute_bits`, `garble_evaluate_matches_plaintext`, `tables_roundtrip`,
  `corrupt_control_bits_detected_by_evaluator`, `corrupt_garbled_table_detected_by_evaluator`.
- Compared with the paper (eprint 2021/749) on 2026-11-21. `S1`, `S2` are the basis matrices of its Figure 3
  and `Rp` the marginal views of `R_p` in Figure 4 (rows `R_00..R_11`, columns `A_L, A_R, B_L, B_R`), bit for
  bit. The evaluator's equations are Figure 6 with the `V` of section 5.1 (`V_01 = [[1,0,0,0,1],[0,1,0,1,1]]`,
  `V_10 = [[1,0,1,0,1],[0,1,0,0,1]]`, `V_11 = [[1,0,1,0,0],[0,1,0,1,0]]`), the hash part `[[1,0,1],[0,1,1]]`
  and `DecodeR` for an odd-parity gate. The garbler's control bits equal the paper's distribution
  `R = R_p + a R_a + b R_b + R_$` with `a = not pa`, `b = not pb`: `r0 = d0 + a t + b (s+t)`,
  `r1 = d1 + a (s+t) + b s` over GF(2), which is what `and_garble3` computes. One difference remains, a
  relabelling: the colour bit is in the half we call R (the paper puts it in the first half), and the
  masking half is the low half of the hash output. The full-width linear functions of the game are
  `(Δ_hi, Δ_lo) ↦ (0, aΔ_hi ⊕ bΔ_lo)`, a, b ∈ {0, 1}, and `σ ⊕ L` is invertible for each of them, which is
  the condition of the paper's Lemma 5. Since `split-public-2` the hash is the paper's recommended family.
  (`split-public-1` used mpz2's fixed-key TCCR `π(π(x) ⊕ i) ⊕ π(x)` (GKWY20) truncated to 64 bits plus one
  bit; a TCCR for `{0, Δ}` does not give RTCCR for the four half-Δ functions by definition, so that
  instantiation was covered by no cited theorem.)
- **Status.** Privacy and authenticity of the tables are **proven** by RR21's Theorem 3 for a garbling with
  inputs fixed before the garbled circuit is seen, with the hash drawn from an RTCCR family; the family used
  is RTCCR by the paper's Lemmas 5 and 6, under: `AES_k ⊕ σ` is a PRF for a random secret key; AES under
  the fixed, revealed key modelled as an ideal permutation (the key is fresh and random per session, never
  a constant and never chosen by C, the adversary of the game); u1, u2 uniform and independent of the
  labels. The RTCCR relaxation (the adversary gets the hash's description only after the garbler's oracle
  queries) is met: N makes all queries while it garbles, on its own labels and on tweaks fixed by the
  circuit, before it sends `hparams`, and nothing C sends influences them. That `gc.rs` is the scheme of the
  paper's figures up to the relabelling is a comparison, not a proof. The check rows extend the game by one
  full-width query per row label on a tweak no gate uses; the row is a public bijection of the answer, so
  the pad of the label C lacks is uniform in the ideal game whatever key C's seed produces (**argued**).
  **Not covered by the theorem, assumed:** (1) the use of the tables: they and the opened output masks reach
  C in preprocessing, C's and N's inputs come later, and the digest inputs of stage s+1 depend on outputs
  of stage s. A simulator must then fix the active path before it knows the outputs, which needs a
  programmable ideal permutation; this is so for every protocol that sends tables in preprocessing, and the
  new hash does not change it. (2) Other material under the same Δ_A: the label-check pairs and the
  input-label commitments (SHA-256 of labels) and the KOS correlations, including KOS's leakage of a few
  bits of Δ_A with selective failure. (3) The ideal-permutation model itself.

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
  construction) need only KOS and Ferret from mpz2 (until `split-public-2` also its TCCR), at the price of
  selective failure.
- **PoC** (`crypto/twopc-ag`, half-gates, 128-bit rows): 1.21 MB up, 32.2 MB down, 11.5 s cold at 2/50
  Mbit/s. With KOS instead of Ferret for the MAC COTs: 0.06 MB up, 52.8 MB down.
- **v2** (archive branch `v2`, the old `twopc-v2`): the PoC integrated, with 64-bit salted rows (−5.3 MB) and three-halves tables
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
- **`split-public-1`** (the `PublicIs` protocol as deployed from 2026-11-12; tag
  `routstr-2pc/split-public-1`): the circuit and stages of `split-public-2`, with mpz2's fixed-key TCCR as
  the garbling hash (12 AES calls per AND gate for N, 6 for C), check rows hashed with a salt from C's seed
  XORed into the tweak (§4: the salt cancels between two wires), N's input labels sent in the handshake after
  the challenge (§4: a prepared N passed stage A1 with a wrong sum with probability about 2^-23 per
  connection), and the input labels of C and of the digests not committed (§5). 16.38 MB down, 1.13 MB up.
  `split-public-2` (2026-11-22) changes these four points, adds 81 984 B to the download and 16 B to the
  upload, and no round trip.
