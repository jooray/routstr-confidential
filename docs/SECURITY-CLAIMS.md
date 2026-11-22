# Security claims: what is proven, argued or assumed

For an outside reviewer of protocol v3 (`PROTOCOL-V3.md`). Each claim says its status:

- **proven**: follows from a published theorem whose assumptions this code meets as written;
- **argued**: an informal argument in the named document, no published proof;
- **assumed**: taken from a library or a primitive without an argument of ours;
- **tested**: exercised by the named tests or gates, which show behaviour, not security.

Roles: C is the client, N the node with its sidecar, U the provider. Paths are relative to the repository
root; Rust tests run with `cargo test --release -p <crate>` in `crypto/`, the gates are in `crypto/tools/`.

## Claims

| # | Claim | Status | Where argued | Exercised by |
|---|---|---|---|---|
| 1 | N never learns C's traffic secrets (`c_ap_1`, `s_ap_0`), so it cannot read a prompt or a response. | argued, conditional on 2–5 | `docs/TWOPC-DESIGN.md` (Security model), `docs/TWOPC-NODE-GARBLING.md` | `crypto/twopc/src/tests.rs` (`abort_looks_the_same_whatever_failed`, `wrong_label_check_pair_detected`, `lying_about_an_input_mask_detected`) |
| 2 | A malicious N's wrong evaluation passes the per-stage consistency check with probability ≤ 2^-60.6 per connection; k·2^-60.6 over k connections. | argued (no published proof for the garbler-only variant); the 64-bit projection bound is elementary | `TWOPC-NODE-GARBLING.md` §4 | `check_rows_bound_to_session_salt`, `corrupt_garbled_table_detected_by_evaluator` |
| 3 | A malicious N learns at most 3 bits per connection (8 observable outcomes) about fresh 256-bit secrets of that connection, which leaves each at least 253 bits of min-entropy. | argued in an idealized abort model; not a full enumeration of N's observations | `TWOPC-DESIGN.md` (Leakage, Why 3 bits per connection is harmless) | `abort_looks_the_same_whatever_failed` (selected cheats at two stages) |
| 4 | Both parties seeing the inner states `IS_k` reveals no output that is not theirs. | assumed (assumptions 1–3: the two of Bellare's HMAC proof, and distinct inner digests under one key); the composed proof is **not written** | `TWOPC-DESIGN.md` (Assumptions: both parties see `IS_k`) | `evaluating_with_another_digest_rejected`, `different_transcript_hash_detected` |
| 5 | The share conversion (ECtF) leaks nothing beyond its outcome. Against a malicious N: no argument. Against a malicious C (the OLE sender): at most a selective failure, ≤ log2 3 bits about N's fresh share. | assumed / argued; mpz2's A2M/M2A are semi-honest | `TWOPC-DESIGN.md` (ECtF) | `crypto/twopc/src/ectf.rs`; no malicious-party test |
| 6 | Three-halves garbling hides N's masks and the wire values from C. | assumed: RR21's theorem. The matrices, the evaluator's equations and the garbler's control-bit distribution were compared with the paper (2026-11-21, they match); what remains is to show that the fixed-key-AES TCCR instantiation fits its hash assumption (RTCCR for the four half-Δ functions) | `TWOPC-NODE-GARBLING.md` §6 | `three_halves_gate_all_cases`, `three_halves_control_bits_hide_permute_bits` (correctness only) |
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
- The proofs and the 2PC run in mpz2 and in `twopc`; neither has been examined for timing.
- The clients are JavaScript (TLS fork, SDK, browser library): no constant-time guarantee; traffic secrets
  are cleared when a connection closes, best effort (§10, risk 9).

## Suggested order of review

1. **The garbler-only consistency check** (`TWOPC-NODE-GARBLING.md` §4, §5; `crypto/twopc/src/gc.rs`,
   `lib.rs`): soundness with garbler-held masks, the 64-bit projection, the salt, the labels N chooses
   online.
2. **Three-halves garbling** (§6): compare the evaluator matrices with RR21's figure; the TCCR instantiation.
3. **Composition with public intermediate states** (`TWOPC-DESIGN.md`, assumptions 1–3): the hybrids over
   both directions and every value revealed together, including the label-check pairs (§7) and the anchors.
4. **The share conversion, both ways** (`crypto/twopc/src/ectf.rs`; mpz2's `mpz-share-conversion`,
   `mpz-ole`): what a malicious N and a malicious C (the OLE sender) can learn or bias.
5. **π_WIN with the frame and interval rules** (`PROTOCOL-V3.md` §5, §7.1, §12.6–§12.8;
   `crypto/zkbench/src/statements.rs`, `crypto/relay/src/h2.rs`, `h2_session.rs`): that every byte U acts on
   is proven, and that disclosures cannot come from model output.
6. **The pinned mpz2 revision** (`eaca5f9d9f30167c9525716e8f0aa9e33d886e5e`, `crypto/Cargo.lock`): KOS,
   Ferret, the VOLE-based proofs, the OLE, against what the code above relies on.
7. **Side channels** (above).
