# Security claims: what is proven, argued or assumed

For an outside reviewer of protocol v3 (`PROTOCOL-V3.md`). Each claim says its status:

- **proven**: follows from a published theorem whose assumptions this code meets as written;
- **argued**: an informal argument in the named document, no published proof;
- **assumed**: taken from a library or a primitive without an argument of ours;
- **tested**: exercised by the named tests or gates, which show behaviour, not security.

Roles: C is the client, N the node with its sidecar, U the provider. Paths are relative to the repository
root; Rust tests run with `cargo test --release -p <crate>` in `crypto/`, the gates are in `crypto/tools/`.

Claims 1 to 7 are about the two-party key schedule `split-public-2` (`PROTOCOL-V3.md` §4). As a whole that
construction has no published proof, and it has had no external review.

## Claims

| # | Claim | Status | Where argued | Exercised by |
|---|---|---|---|---|
| 1 | N never learns C's traffic secrets (`c_ap_1`, `s_ap_0`), so it cannot read a prompt or a response. | argued, conditional on 2–5 | `docs/TWOPC-DESIGN.md` (Security model), `docs/TWOPC-NODE-GARBLING.md` | `crypto/twopc/src/tests.rs` (`abort_looks_the_same_whatever_failed`, `wrong_label_check_pair_detected`, `lying_about_an_input_mask_detected`) |
| 2 | A wrong evaluation by a malicious N passes the per-stage consistency checks with probability ≤ 2^-60.6 per connection (k·2^-60.6 over k connections), for a connection whose server share N did not choose. The check binds the pointer bits C observes to the masks N committed, through the IT-MACs under Δ_B. N fixes everything that determines those pointer bits before it learns the challenge: the tables, the masks, the labels of its own garbled input (a random mask ρ; its share enters as a public correction δ to C's input) and commitments to both labels of every other input wire. It assumes that C's share is hidden from N (ECtF; DDH in P-256 when N feeds 0 into its conversion) and, for the one transcript hash N can influence before stage A2, that the compression function keyed by its chaining input behaves as a random function. In `split-public-1` N sent its input labels after the challenge; there a prepared N passed stage A1 with a wrong sum with probability about 2^-23 per connection (found 2026-11-22). The handshake then failed at C (wrong Z), and no use against a traffic secret is known. `split-public-2` removes it. | argued (no published proof for the garbler-only variant; the 64-bit projection bound is elementary; the step "N has no choice after the challenge" is new in `split-public-2` and has had no review) | `TWOPC-NODE-GARBLING.md` §4, §5 | `adder_switch_attack_caught` (the attack passes in the old message order through a test hook and is caught in the new one), `gl_precedes_seed`, `in_com_precedes_seed`, `third_label_for_c_input_detected`, `wrong_input_commitment_is_a_selective_abort`, `delta_out_of_range_rejected`, `check_rows_bound_to_session_seed`, `corrupt_garbled_table_detected_by_evaluator` |
| 3 | A malicious N learns at most 3 bits per connection (8 observable outcomes) about fresh 256-bit secrets of that connection, which leaves each at least 253 bits of min-entropy. The eight outcomes are those after preprocessing. In preprocessing N can also observe whether its KOS consistency checks, the product check and the openings pass; these are predicates on C's fresh OT keys (Δ_B, the Δ of the ECtF instance), not on a key-schedule value. | argued in an idealized abort model; not a full enumeration of N's observations. 3 bits is a conservative count: N cannot select outcome 1 (C's degenerate share) at all | `TWOPC-DESIGN.md` (Leakage, Why 3 bits per connection is harmless) | `abort_looks_the_same_whatever_failed` (selected cheats at two stages), `ectf_c_abort_is_not_n_selectable` |
| 4 | Both parties seeing the inner states `IS_k` reveals no output that is not theirs. | assumed (assumptions 1–3: the two of Bellare's HMAC proof, and distinct inner digests under one key; assumption 4: the public anchors are hashes of secrets that are also used as keys); the composed proof is **not written** | `TWOPC-DESIGN.md` (Assumptions: both parties see `IS_k`) | `evaluating_with_another_digest_rejected`, `different_transcript_hash_detected` |
| 5 | The share conversion (ECtF) gives neither party more than stated here. **Malicious N (OLE receiver):** it can substitute its inputs to the three OLEs and so skew C's share (`Z' = k·λ'^2 − x1 + c` for values of its choice); its view is simulatable without C's point; it cannot cause C's degenerate-share abort. Every effective deviation makes the handshake fail before stage B1, so no application secret of that connection exists; the handshake-stage values N then holds are for a secret it can compute only by solving CDH for C's share and the server's. **Malicious C (OLE sender):** two predicates of its choice on N's ROLE bits, observed as N's degenerate-share abort and as handshake failure: 3 outcomes, ≤ log2 3 bits about N's fresh share. Confidentiality of a recorded connection against N rests on the 128-bit KOS Δ of this instance, with KOS's selective leakage. | argued (mpz2 documents its A2M/M2A as secure against semi-honest parties only; the argument for this code is ours): in the ROT-hybrid model, with HKDF-Extract as a random oracle and strong DH in P-256 (CDH with a DDH oracle); mpz2's KOS and base OT assumed. Without the oracle model the last step for malicious N needs a correlated-input assumption on HMAC-SHA256 that is not standard. The 3-outcome bound for C is an enumeration of this code's error paths | `TWOPC-DESIGN.md` (ECtF) | `ectf_n_substitutes_its_point`, `ectf_n_zero_m2a_input`, `ectf_n_shifted_share`, `ectf_c_abort_is_not_n_selectable`, `ectf_c_inconsistent_masks`, `ectf_c_forces_degenerate_share` |
| 6 | Three-halves garbling hides N's masks and the wire values from C, and C cannot forge a label. | **proven only in part**, so as a whole **assumed**: proven for the garbling scheme with inputs fixed before garbling (Rosulek–Roy, CRYPTO 2021, Theorem 3), with the hash family the paper recommends, `AES_k(X ⊕ U(τ)) ⊕ σ(X ⊕ U(τ))`, key and `U` fresh per session (RTCCR by its Lemmas 5 and 6: AES-128 a PRF for a random key; AES under the revealed key modelled as an ideal permutation). The code was compared with the paper's figures (2026-11-21); the choice of halves is a relabelling (argued). A check row is a public function (one more AES call under a key from C's seed) of a further full-width query of the same oracle (argued). **Not covered by the theorem, assumed:** the tables reach C in preprocessing and the inputs arrive later, stage by stage, with stage inputs that depend on earlier outputs (a simulation needs a programmable ideal permutation, as in every protocol with garbled preprocessing); the label-check pairs and the input-label commitments (SHA-256 of labels) and the KOS correlations under the same Δ_A | `TWOPC-NODE-GARBLING.md` §6 | `three_halves_gate_all_cases`, `three_halves_control_bits_hide_permute_bits` (correctness only), `hash_vectors_match_conformance_file`, `different_hash_parameters_give_different_tables` |
| 7 | C cannot learn `K_0`, `IV_0` or the credential, and cannot misreport a 2PC output. | argued | `TWOPC-DESIGN.md` (Malicious C) | `cheating_evaluator_cannot_misreport`, `evaluating_with_another_digest_rejected` |
| 8 | π_NK, π_WIN and π_C3S are zero-knowledge and sound; the verifier learns one bit. | proven for the proof system (QuickSilver/Wolverine over mpz2's VOLE), **assuming** mpz2's implementation; the statements themselves are tested | `PROTOCOL-V3.md` §7, `crypto/zkbench/src/statements.rs` | `crypto/zkbench/tests/statements.rs`, `tests/win.rs` (`any_wrong_window_byte_gives_zero`, `wrong_anchor_or_secret_fails`) |
| 9 | C cannot send U a request N did not price: every HEADERS record is proven whole, frames cannot hide in DATA records or move by TLS padding, the suffix ends the body, nothing is written before its π_WIN verifies, and a cancelled request cannot lend its credential reference. | argued | `PROTOCOL-V3.md` §5.1–§5.3.1, §12.6 | `win.rs` (`a_frame_hidden_in_a_data_record_is_refused`, `tls_padding_cannot_move_the_frame_boundary`, `wrong_suffix_or_header_block_is_refused`); `crypto/relay/src/h2_session.rs` (`nothing_reaches_the_upstream_unproven_or_unreleased`, `a_cancelled_request_lends_its_credential_reference_to_nothing`); the attack cases of `v3-check.sh` and `v3-node-check.sh` |
| 10 | The usage N bills is the provider's own usage event for this request: π_C3S over the end of the response, within the request's interval, under the grammar of §5.4. | argued (grammar and interval rule); proof system as 8 | `PROTOCOL-V3.md` §5.4, §12.8 | `crypto/relay/src/h2.rs` (`model_output_cannot_fake_a_tail`, `usage_tail_*`), `h2_session.rs` (`usage_disclosure_is_bound_to_the_interval_and_the_end`, `an_earlier_requests_tail_is_outside_the_interval`) |
| 11 | An error head or a provider refusal (`disclose_reset`) cannot be fabricated from model output or another stream. | argued; rests on U's frame boundaries (`PROTOCOL-V3.md` §10, risks 5 and 12) | §5.4, §5.4.1 | `h2.rs` (`error_head_forms`, `refusal_forms`, `refusals_that_do_not_count`), `h2_session.rs` (`no_refusal_after_a_response_on_the_stream`, `a_goaway_after_the_window_does_not_refuse_an_unwritten_request`, `a_goaway_after_a_late_first_write_does_not_refuse_the_request`) |
| 12 | A wrong claim of the server's key epoch (`key_updates`, `epoch_start`) gains C nothing. | argued | `PROTOCOL-V3.md` §7.1 | `win.rs` (`key_updates_step_the_secret`) |
| 13 | The ClientHello is canonical, so no client can make N's guard withdraw framing `"2"`, and C cannot add a key share of its own. | tested; the rule is argued in `H2Guard`'s doc comment | `PROTOCOL-V3.md` §2.1, §12.5 | `crypto/relay/src/tls_v2.rs` (`the_client_stacks_write_the_canonical_hello`, `rejects_an_extra_or_foreign_key_share`), `crypto/conformance/client-hello-vectors.json` (asserted by every client stack), `main.rs` (`framing_2_is_withdrawn_after_five_failed_opens_and_comes_back`) |
| 14 | N verifies U's certificate chain, hostname, CertificateVerify and both Finished before it writes the credential; C trusts a subset of N's roots. | tested | `PROTOCOL-V3.md` §3.2, §12.5 | `crypto/relay/src/tls.rs`, `crypto/tools/gen-client-roots.py` (CI compares its output with the vendored root store) |
| 15 | N cannot charge more than the reservation it announced in `request_ok`, and every charge is in a signed receipt or deposit outcome the client checks. | tested (money rules are implementation, not cryptography) | `PROTOCOL-V3.md` §12.10 | `v3-node-check.sh` + `v3_node_eval.py` (every case's money in the node's database); the client stacks' receipt checks |

## What is outside the claims

- Provider behaviour: U must not echo the credential (profile check H7), must bill the pinned model and cap,
  and must keep the HTTP/2 rules of §5.6. `crypto/tools/provider-profile-check.py` checks these per provider;
  they are properties of a provider, not of the protocol.
- Linkability of requests on one HTTP/2 connection, and the private nature of receipts (§10, risks 1 and 8).
- A malicious N writing further epoch-0 records (§10, risk 7, and the paragraph on the framings below it).

## Side channels

- The sidecar's AES-GCM (`crypto/cu-crypto/src/aesgcm.rs`): the GHASH multiply uses masks, with no branch on
  the hash key or the state. The browser library vendors `cu-crypto` and carries the change only after it is
  vendored again and its wasm rebuilt.
- The proofs and the 2PC run in mpz2 and in `twopc`; neither has been examined for timing. Known: mpz2's KOS
  sender selects on bits of its Δ with a branch. In `twopc`, `xtime` and σ of the garbling hash and the
  evaluator's `r_matrix` use masks instead of branches or lookups on label bits (`split-public-2`).
- The clients are JavaScript (TLS fork, SDK, browser library): no constant-time guarantee; traffic secrets
  are cleared when a connection closes, best effort (§10, risk 9).

## Suggested order of review

1. **The garbler-only consistency check** (`TWOPC-NODE-GARBLING.md` §4, §5; `crypto/twopc/src/gc.rs`,
   `lib.rs`): soundness with garbler-held masks, the 64-bit projection, and that N has no choice left after
   the challenge (the masked input ρ and δ, the input-label commitments, the transcript hashes).
2. **Three-halves garbling** (§6): the relabelling of halves against RR21's figures, and the extension of
   the hash's RTCCR game by the check rows.
3. **Composition with public intermediate states** (`TWOPC-DESIGN.md`, assumptions 1–3): the hybrids over
   both directions and every value revealed together, including the label-check pairs (§7) and the anchors.
4. **The share conversion, both ways** (`crypto/twopc/src/ectf.rs`; mpz2's `mpz-share-conversion`,
   `mpz-ole`): what a malicious N and a malicious C (the OLE sender) can learn or bias; the simulator for a
   malicious N in `TWOPC-DESIGN.md` (ECtF).
5. **π_WIN with the frame and interval rules** (`PROTOCOL-V3.md` §5, §7.1, §12.6–§12.8;
   `crypto/zkbench/src/statements.rs`, `crypto/relay/src/h2.rs`, `h2_session.rs`): that every byte U acts on
   is proven, and that disclosures cannot come from model output.
6. **The pinned mpz2 revision** (`eaca5f9d9f30167c9525716e8f0aa9e33d886e5e`, `crypto/Cargo.lock`): KOS,
   Ferret, the VOLE-based proofs, the OLE, against what the code above relies on.
7. **Side channels** (above).
