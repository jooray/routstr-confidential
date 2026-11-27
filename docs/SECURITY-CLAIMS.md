# Security claims: what is proven, argued or assumed

For an outside reviewer of protocol v3 (`PROTOCOL-V3.md`). Each claim says its status:

- **proven**: follows from a published theorem whose assumptions this code meets as written;
- **argued**: an informal argument in the named document, no published proof;
- **assumed**: taken from a library or a primitive without an argument of ours;
- **tested**: exercised by the named tests or gates, which show behaviour, not security.

Roles: C is the client, N the node with its sidecar, U the provider. Paths are relative to the repository
root; Rust tests run with `cargo test --release -p <crate>` in `crypto/`, the gates are in `crypto/tools/`.

Claims 1 to 7 are about the two-party key schedule `split-public-3` (`PROTOCOL-V3.md` §4). As a whole that
construction has no published proof, and it has had no external review.

## Claims

| # | Claim | Status | Where argued | Exercised by |
|---|---|---|---|---|
| 1 | N never learns C's traffic secrets (`c_ap_1`, `s_ap_0`), so it cannot read a prompt or a response. | argued, conditional on 2–5 | `docs/TWOPC-DESIGN.md` (Security model), `docs/TWOPC-NODE-GARBLING.md` | `crypto/twopc/src/tests.rs` (`abort_looks_the_same_whatever_failed`, `wrong_label_check_pair_detected`, `lying_about_an_input_mask_detected`) |
| 2 | A wrong evaluation by a malicious N passes the per-stage consistency checks with probability ≤ 2^-60.6 per connection (k·2^-60.6 over k connections), for a connection whose server share N did not choose. The check binds the pointer bits C observes to the masks N committed, through the IT-MACs under Δ_B. N fixes everything that determines those pointer bits before it learns the challenge: the tables, the masks, the labels of its own garbled input (a random mask ρ; its share enters as a public correction δ to C's input) and commitments to both labels of every other input wire. It assumes that C's share is hidden from N (DDH in P-256: the share is a function of N's view and of C's Diffie-Hellman point, hidden only computationally, whatever N feeds into the conversion; the reduction is not written out. A sketch of it needs the discrete logarithm of N's key share: N proves that it knows it, with a Schnorr proof that C verifies before it opens its own share, and the sketch extracts it by rewinding, with SHA-256 in the proof's challenge as a random oracle, for one connection at a time. It then covers all five stages with HKDF-Extract as a random oracle, and it reads N's masks from N's queries to the hash of mpz2's base OT, modelled as a random oracle. Until 2026-11-22 N gave no such proof, and N's knowledge of that discrete logarithm was an assumption for the stages after A1), that C's TLS stack accepts at most two server flights per signature of U (two for an ECDSA signature, `(r, s)` and `(r, n − s)`; one for an RSA signature, which must have the length of the modulus: until 2026-11-23 a client on OpenSSL's WebCrypto also accepted an RSA signature with its leading zero bytes dropped, a second flight for one RSA-PSS signature in 256, still within the factor of two; N holds `s_hs` and picks `th_SF` among the flights C accepts; the stacks released with `split-public-1` accepted any number, which made the terms of stages B1 and B2 a bound on N's work, at most about 2^-111 per flight tried, and not a statistical one) and, for the transcript hash N can influence before stage A2, that the compression function keyed by its chaining input behaves as a random function. In `split-public-1` N sent its input labels after the challenge; there a prepared N passed stage A1 with a wrong sum with probability about 2^-23 per connection (found 2026-11-22). The handshake then failed at C (wrong Z), and no use against a traffic secret is known. `split-public-2` removed it, and `split-public-3` is its final form under a new tag. | argued (no published proof for the garbler-only variant; the 64-bit projection bound is elementary; the step "N has no choice after the challenge" is new since `split-public-2` and has had no review) | `TWOPC-NODE-GARBLING.md` §4, §5 | `adder_switch_attack_caught` (the attack passes in the old message order through a test hook and is caught in the new one), `gl_precedes_seed`, `in_com_precedes_seed`, `third_label_for_c_input_detected`, `wrong_input_commitment_is_a_selective_abort`, `delta_out_of_range_rejected`, `check_rows_bound_to_session_seed`, `corrupt_garbled_table_detected_by_evaluator`; N's proof of knowledge: `key_share_proof_refused_before_the_opening`, `key_share_proof_checks`, `key_share_proof_vector`; the flights C accepts: the TLS-17, TLS-18 and TLS-20 cases of `crypto/client/test/tls-fork-records-check.ts` and of the SDK's and the web library's `confidential-tls` tests |
| 3 | A malicious N learns at most 3 bits per connection (8 observable outcomes) about fresh 256-bit secrets of that connection, which leaves each at least 253 bits of average min-entropy (an outcome N makes rare, of probability 2^-t, tells t bits when it occurs; over the outcomes the best guess improves by a factor of at most 8). The eight outcomes are those after preprocessing. In preprocessing N can also observe whether its KOS consistency checks, the product check and the openings pass; these are predicates on C's fresh OT keys (Δ_B, the Δ of the ECtF instance), not on a key-schedule value. | argued in an idealized abort model; not a full enumeration of N's observations. 3 bits is a conservative count: N cannot select outcome 1 (C's degenerate share) at all | `TWOPC-DESIGN.md` (Leakage, Why 3 bits per connection is harmless) | `abort_looks_the_same_whatever_failed` (selected cheats at two stages), `ectf_c_abort_is_not_n_selectable` |
| 4 | Both parties seeing the inner states `IS_k` reveals no output that is not theirs. | assumed (assumptions 1–3: the two of Bellare's HMAC proof, and distinct inner digests under one key; assumption 4: the public anchors are hashes of secrets that are also used as keys); the composed proof is **not written** | `TWOPC-DESIGN.md` (Assumptions: both parties see `IS_k`) | `evaluating_with_another_digest_rejected`, `different_transcript_hash_detected` |
| 5 | The share conversion (ECtF) gives neither party more than stated here. **Malicious N (OLE receiver):** it can substitute its inputs to the three OLEs and so skew C's share (`Z' = k·λ'^2 − x1 + c` for values of its choice); its view is simulatable without C's point; it cannot cause C's degenerate-share abort. Every effective deviation makes the handshake fail before stage B1, so no application secret of that connection exists; the handshake-stage values N then holds are for a secret it can compute only by solving CDH for C's share and the server's. **Malicious C (OLE sender):** two predicates of its choice on N's ROLE bits, observed as N's degenerate-share abort and as handshake failure: 3 outcomes, ≤ log2 3 bits about N's fresh share. Confidentiality of a recorded connection against N rests on the 128-bit KOS Δ of this instance, with KOS's selective leakage. | argued (mpz2 documents its A2M/M2A as secure against semi-honest parties only; the argument for this code is ours): in the ROT-hybrid model, with HKDF-Extract as a random oracle and strong DH in P-256 (CDH with a DDH oracle); mpz2's KOS and base OT assumed. Without the oracle model the last step for malicious N needs a correlated-input assumption on HMAC-SHA256 that is not standard. The 3-outcome bound for C is an enumeration of this code's error paths | `TWOPC-DESIGN.md` (ECtF) | `ectf_n_substitutes_its_point`, `ectf_n_zero_m2a_input`, `ectf_n_shifted_share`, `ectf_c_abort_is_not_n_selectable`, `ectf_c_inconsistent_masks`, `ectf_c_forces_degenerate_share` |
| 6 | Three-halves garbling hides N's masks and the wire values from C, and C cannot forge a label. | **proven only in part**, so as a whole **assumed**: proven for the garbling scheme with inputs fixed before garbling (Rosulek–Roy, CRYPTO 2021, Theorem 3), with the hash family the paper recommends, `AES_k(X ⊕ U(τ)) ⊕ σ(X ⊕ U(τ))`, key and `U` fresh per session (RTCCR by its Lemmas 5 and 6: AES-128 a PRF for a random key; AES under the revealed key modelled as an ideal permutation). The code was compared with the paper's figures (2026-11-21); the choice of halves is a relabelling (argued). A check row is a public function (one more AES call under a key from C's seed) of a further full-width query of the same oracle (argued). **Not covered by the theorem, assumed:** the tables reach C in preprocessing and the inputs arrive later, stage by stage, with stage inputs that depend on earlier outputs (a simulation needs a programmable ideal permutation, as in every protocol with garbled preprocessing); the label-check pairs and the input-label commitments (SHA-256 of labels) and the KOS correlations under the same Δ_A | `TWOPC-NODE-GARBLING.md` §6 | `three_halves_gate_all_cases`, `three_halves_control_bits_hide_permute_bits` (correctness only), `hash_vectors_match_conformance_file`, `different_hash_parameters_give_different_tables` |
| 7 | C cannot learn `K_0`, `IV_0` or the credential, and cannot misreport a 2PC output. C cannot choose the joint key share: it commits to its point before it sees N's. N's proof of knowledge of its key-share scalar tells C nothing about the scalar. | argued; the proof of knowledge is zero-knowledge with SHA-256 as a programmable random oracle (the standard simulation of a Schnorr proof; scalar and nonce are used for one connection). C gives no proof for its own scalar, and no argument here needs one | `TWOPC-DESIGN.md` (Malicious C) | `cheating_evaluator_cannot_misreport`, `evaluating_with_another_digest_rejected`, `rogue_key_share_aborts` |
| 8 | π_NK, π_WIN and π_C3S are zero-knowledge and sound; the verifier learns one bit. | proven for the proof system (QuickSilver/Wolverine over mpz2's VOLE), **assuming** mpz2's implementation; the statements themselves are tested | `PROTOCOL-V3.md` §7, `crypto/zkbench/src/statements.rs` | `crypto/zkbench/tests/statements.rs`, `tests/win.rs` (`any_wrong_window_byte_gives_zero`, `wrong_anchor_or_secret_fails`) |
| 9 | C cannot send U a request N did not price: every HEADERS record is proven whole, frames cannot hide in DATA records or move by TLS padding, the suffix ends the body, nothing is written before its π_WIN verifies, and a cancelled request cannot lend its credential reference. | argued | `PROTOCOL-V3.md` §5.1–§5.3.1, §12.6 | `win.rs` (`a_frame_hidden_in_a_data_record_is_refused`, `tls_padding_cannot_move_the_frame_boundary`, `wrong_suffix_or_header_block_is_refused`); `crypto/relay/src/h2_session.rs` (`nothing_reaches_the_upstream_unproven_or_unreleased`, `a_cancelled_request_lends_its_credential_reference_to_nothing`); the attack cases of `v3-check.sh` and `v3-node-check.sh` |
| 10 | The usage N bills is the provider's own usage event for this request: π_C3S over the end of the response, within the request's interval, under the grammar of §5.4. | argued (grammar and interval rule); proof system as 8 | `PROTOCOL-V3.md` §5.4, §12.8 | `crypto/relay/src/h2.rs` (`model_output_cannot_fake_a_tail`, `usage_tail_*`), `h2_session.rs` (`usage_disclosure_is_bound_to_the_interval_and_the_end`, `an_earlier_requests_tail_is_outside_the_interval`) |
| 11 | An error head or a provider refusal (`disclose_reset`) cannot be fabricated from model output or another stream. | argued; rests on U's frame boundaries (`PROTOCOL-V3.md` §10, risks 5 and 12) | §5.4, §5.4.1 | `h2.rs` (`error_head_forms`, `refusal_forms`, `refusals_that_do_not_count`), `h2_session.rs` (`no_refusal_after_a_response_on_the_stream`, `a_goaway_after_the_window_does_not_refuse_an_unwritten_request`, `a_goaway_after_a_late_first_write_does_not_refuse_the_request`, `a_refusal_received_before_request_ok_counts_only_as_a_raced_goaway`, `a_goaway_that_raced_request_ok_refuses_the_request`, `a_two_goaway_shutdown_around_request_ok_refuses_the_request`, `a_close_after_the_client_held_the_body_back_is_not_the_providers_answer`: a control record inside the request, before or after its first record, and an owed PING ACK that does not mark it; `owed_ping_acks_are_bounded_and_need_a_server_record_each`) |
| 12 | A wrong claim of the server's key epoch (`key_updates`, `epoch_start`) gains C nothing. `epoch_start` must fit the KeyUpdate count and lie within the server records N received, in every disclosure of both framings. | argued | `PROTOCOL-V3.md` §7.1 | `win.rs` (`key_updates_step_the_secret`), `h2_session.rs` (`an_epoch_start_out_of_range_is_refused`), `main.rs` (`an_epoch_start_out_of_range_is_refused_in_framing_11`) |
| 13 | The ClientHello is canonical, so no client can make N's guard withdraw framing `"2"`, and C cannot add a key share of its own. | tested; the rule is argued in `H2Guard`'s doc comment | `PROTOCOL-V3.md` §2.1, §12.5 | `crypto/relay/src/tls_v2.rs` (`the_client_stacks_write_the_canonical_hello`, `rejects_an_extra_or_foreign_key_share`), `crypto/conformance/client-hello-vectors.json` (asserted by every client stack), `main.rs` (`framing_2_is_withdrawn_after_five_failed_opens_and_comes_back`) |
| 14 | N verifies U's certificate chain, hostname, CertificateVerify and both Finished before it writes the credential; C trusts a subset of N's roots. | tested | `PROTOCOL-V3.md` §3.2, §12.5 | `crypto/relay/src/tls.rs`, `crypto/tools/gen-client-roots.py` (CI compares its output with the vendored root store) |
| 15 | An honest N never charges a request more than the reservation it announced in `request_ok`. Signed by N: every **settled** request (a receipt); every deposit still held at a connection's end (the deposit outcome, also when a newer setup closed an unused connection under slot pressure: always charged, `evicted`, with the address's signed count, row 13); and every accepted request N finalized without a receipt (`request_outcome` on the last frame: `sid`, `http`, `n`, `outcome`, `reason`, `cost_msats`, `reserved_msats`, `balance_msats`, `time`), whether written in full and never settled (the reservation), abandoned (the abandon fee, or a release when the deposit is charged for it; since 2026-11-24 also every early provider close with no disclosed answer), released in full, or settled in the database with a billing write or deposit release that failed (a failed billing write before `body_released` releases the request in full). The clients refuse a receipt that names another reservation or charges more than the announced one, a usage charge above the node's formula at the signed rates, and an error charge above the abandon fee for a 5xx settled before `body_released`; they report a deposit charged against the table of §12.10 (an eviction charge without the signed count, earlier than the signed offer's `evict_unused_after_s` after the client's setup, or with a request the node had accepted, included), a control socket that ended without the node's last frame while the node held a deposit or an accepted request (all three clients, also after a socket error or a malformed frame), and a request outcome that is missing, unsigned, for another request, above the announced reservation, above the ceiling of its reason (zero for the reasons that release, the session fee for a provider refusal, the abandon fee for an abandoned request or for one settled without a receipt before `body_released`, the reservation only after `body_released`), a charge beside a charged deposit, or the abandon fee after a fault of the node or the provider. Not covered: a client that left before the last frame receives no outcome (the charge is the same), and N's stated reason is its word, checked only against what C saw (`PROTOCOL-V3.md` §10, risk 14). A cheating N is detected by these checks, not prevented from debiting a balance it keeps. | tested (money rules are implementation, not cryptography) | `PROTOCOL-V3.md` §8.4, §12.9, §12.10 | `v3-node-check.sh` + `v3_node_eval.py` (every case's money in the node's database; the attack cases require the signed request outcome; `h2-n-evict-lone`, `h2-n-evict-own`, `h2-n-silent-2pc`); routstr-core `test_confidential_v3.py` (eviction and outcome tests); the client stacks' receipt, deposit and request-outcome checks (`crypto/client/test/{deposit,request-outcome}-check.ts`, SDK `confidential-connection.test.ts` and `request-outcome-vectors.test.ts`, web `v3-errors.test.ts` and `sdk-request-outcome-vectors.test.ts`, all on `crypto/conformance/request-outcome-vectors.json`) |
| 16 | A client cannot end a request (or its connection) for less than an abandoned request costs by making the provider close before the body is complete. N cannot read the provider's bytes, and the client can make a TLS 1.3 provider close at will (a record with a wrong GCM tag: π_WIN proves the CTR ciphertext, not the tag; in framing `"1.1"` an unproven body record of random bytes; an unsolicited SETTINGS ACK), so `upstream_closed_early` settles nothing by its response bytes: only an answer C discloses within 60 s does (`disclose_reset`, or the provider's error head, `disclose_head`; none after a close S marked `client_caused`), at that answer's price; else the abandon fee, or the deposit on a connection with no settlement (`PROTOCOL-V3.md` §5.4.2). Until 2026-11-24 the node released the deposit for such a close and kept only the session fee (0 by default). The cost to an honest client: a provider close with nothing provable (a TLS alert only, a GOAWAY with an error code) costs it the abandon fee or the deposit (risk 16). | tested | `PROTOCOL-V3.md` §5.4.2, §12.9, §12.10 | sidecar `an_error_head_settles_a_request_after_the_providers_early_close`, `a_control_record_between_requests_marks_the_next_one_within_the_window`, `upstream_close_by_request_state`; routstr-core `test_deposit_when_the_provider_closed_early_with_nothing_disclosed`, `test_an_error_head_disclosed_after_an_early_close_settles_the_request`, `test_provider_closing_before_the_body_completes`; the gates' `h2-t-bad-tag`, `h2-t-bad-tag-2`, `h11-t-bad-record` (`v3-check.sh`: the sidecar settles nothing; `v3-node-check.sh`: the deposit charged or the abandon fee kept); reference client `h2-conn-test.ts` case 8 |

## The model

No claim above is in the standard model. Taken together they use: SHA-256 as a random oracle (the key-share
proof's challenge, the anchors `h1`, `h2`, `hk`, the commitments), HKDF-Extract as a random oracle (claims 2
and 5), the random oracle of mpz2's base OT (BLAKE3; claim 2 reads N's masks from N's queries to it), a
programmable ideal permutation for the fixed-key AES of the garbling hash (claim 6: the tables are sent
before the inputs are known), DDH and a strong Diffie-Hellman assumption in P-256, and the assumptions on
HMAC's compression function of claim 4. The reductions are sketched, not written out, and they are
sketched for one connection at a time: the extraction of N's key-share scalar is by rewinding, which does
not extend to many interleaved connections of one N without a loss that nobody has bounded. A straight-line
extractable proof would remove that gap at the cost of 1 to 2 kB in N's key-share message; it is not done.
The composition of the five stages with public inner states (claim 4) and the preprocessed, staged use of
the garbled circuit under one Δ_A (claim 6) have no proof. None of this is hidden in the table above; this
section says it in one place.

## What is outside the claims

- Provider behaviour: U must not echo the credential (profile check H7), must bill the pinned model and cap,
  and must keep the HTTP/2 rules of §5.6. `crypto/tools/provider-profile-check.py` checks these per provider;
  they are properties of a provider, not of the protocol.
- Linkability of requests on one HTTP/2 connection, and the private nature of receipts (§10, risks 1 and 8).
- A malicious N writing further epoch-0 records (§10, risk 7, and the paragraph on the framings below it).

## Side channels

Nothing here is claimed to be constant-time as compiled. No timing side channel was measured. One function
was disassembled (below). What was read in the source (2026-11-23):

- **Our code.** The sidecar's AES-GCM (`crypto/cu-crypto/src/aesgcm.rs`): the GHASH multiply uses masks, with
  no branch on the hash key or the state; the browser library vendors the same file (checked mechanically,
  `npm run check:vendor`). In `twopc`, `xtime` and σ of the garbling hash and the evaluator's `r_matrix` use
  masks instead of branches or lookups on label bits, and so does `sel` (a label or Δ times a bit, `lib.rs`
  and `gc.rs`: `Block::mask` since 2026-11-24, before a read of `Block::SELECT_MASK` at the bit; same
  values). Still indexed by a secret bit: the two-entry arrays of a commitment pair or a label-check pair
  read at a label's pointer bit (32 bytes in all; not measured). C's opened masks (`lam_in`,
  `lam_out`) and the d bits of its input are wiped on drop (`Zeroizing`); in the browser the wasm memory
  and the JavaScript heap give no such promise. N's key-share proof uses the `p256` crate's
  constant-time point multiplication and scalar arithmetic for the nonce and the scalar, as the key share
  and the ECDHE share do; the crate's claim was not measured here.
- **mpz2 is pinned to a fork with branch-free selects.** The pin is `github.com/jooray/mpz2`, branch
  `routstr-ct-selects`, commit `eba78e02cb237cf1501ff0d8a492ef5fc849e135`: upstream `eaca5f9` plus four
  commits that replace every select on a secret bit we found on the paths we use with mask arithmetic,
  and every load or store at a secret index with a masked pass over the whole vector. The values computed
  are the same, so no wire byte and no proof byte changes (the twopc byte counts per connection and the
  proof sizes of `cu-prover --bench` are identical before and after; the conformance vectors are unchanged).
  The masks are derived from the bit by arithmetic (`Block::mask`, `Block::mask_eq`, `Block::select` in
  `core/src/block.rs`) and pass through `core::hint::black_box`, so that the optimizer does not turn them back
  into a branch; that is a barrier against the compiler, not a guarantee. Branch-free in source now:
  - The QuickSilver prover's multiplication check (`zk-core/src/check.rs`, `check_prover`): once per AND
    gate it selected on the value of each input wire (the low bit of the wire's MAC is the wire's value,
    not masked); now `mask(bit) & y`. The prover is N in π_NK, where the wires depend on `K_0`, `IV_0` and
    the provider's API key, and C in π_WIN and π_C3S, where they depend on `c_ap_1` or `s_ap_0`.
    **Disassembled**: the release `cu-prover` built here (aarch64-apple-darwin, rustc 1.97.1) has no
    conditional branch in the loop body that computes the per-gate terms: the mask is `sbfx` of the wire's
    low bit, then `and`. The build before the change had none either (LLVM had compiled the `if` to
    `cmeq`/`bsl`), which is what the source did not guarantee. Other targets, other compiler versions and
    the wasm build of the browser library were not disassembled.
  - The KOS sender (`ot-core/src/kos/sender.rs`): the 128 selects on the bits of its Δ in the extension and
    the 128 in its consistency check; the check also no longer stops at the first mismatching row (it
    accumulates the differences and fails once). Every Δ is fresh per connection or per proof chain (N's
    Δ_A, C's Δ_B, C's Δ of the share conversion, the verifier's Δ of a proof).
  - The Chou–Orlandi receiver (`chou_orlandi/receiver.rs`): the same Δ bits, as base-OT choices, in the
    blinded choice (`RistrettoPoint::conditional_select` of `subtle`) and in the decryption.
  - The OLE receiver (`ole-core/src/lib.rs`): N's random share in the share conversion; the bit becomes a
    field element through a new `Field::from_bit` (for P-256 crypto-bigint's constant-time select).
  - The Ferret receiver with regular LPN, the one we use: the SPCOT receiver's select on the bits of each
    noise position, the store of the punctured leaf and the read of `chis` at the noise position
    (`ferret/spcot/receiver.rs`); the GGM tree's reconstruction of the punctured path, which cleared and
    wrote nodes at the secret position and folded one parity chosen by a secret bit (`core/src/ggm.rs`,
    `new_partial`); the store of the noise into the LPN error vector and the select on the receiver's
    choice bits (`ferret/receiver.rs`); a `%` on the noise position, now a mask (`ferret/mpcot/receiver.rs`).
    The receiver is the prover of a proof, and N for the MAC COTs.

  Not changed, and why: the Ferret receiver with uniform LPN (its cuckoo hashing places secret positions
  with data-dependent loops and indexed accesses) is not on a path we use; both `zkbench` and `twopc`
  configure regular LPN. The noise positions are drawn with `random_range` (rand's rejection sampling: the
  number of draws depends on discarded random words, not on the position kept). `bit_vartime` of the P-256
  field (`fields/src/p256.rs`) is variable only in a public bit index and is not on a path we use. The
  Ferret SPCOT sender and the COT derandomization select on bits their peer sent. The GF(2^128) multiply is
  the `clmul` crate's software backend in this build (the `pmull` backend needs `--cfg clmul_armv8`), which
  uses integer multiplications with masks; it was not changed or disassembled.

  Measured cost (this machine, Apple M2 Max): one cold two-party key schedule, in-process, no link delay,
  median of 7, twice each: 0.46 s before and after, preprocessing 390-393 ms (C) before, 389-392 ms after;
  `cu-prover --bench` local, median of 5: π_NK 159.8 / 165.1 ms, π_WIN 163.3 / 164.1 ms, π_C3S
  203.5 / 207.8 ms (before / after); mpz2's criterion benches: `prover/check` 22.5 / 21.2 ms for 200 000 AND
  gates, `ggm::reconstruction::1K` 4.61 / 5.21 µs, a Ferret receiver extension with regular LPN 879 / 887 ms
  (single-threaded) and 862 / 901 ms (multi-threaded).
- **Who could measure what.** The other party of the protocol sees when a whole message arrives, through a
  WebSocket and the node's relay. Any signal the selects above could have given was at most microseconds
  per proof, one number per proof, far below that jitter; for the long-lived API key it was a constant
  offset with nothing to compare it to. We know no use of it. An observer **on the same machine** as the
  party (a shared core or cache) is a different matter: branches and secret-indexed accesses are a
  plausible cache or branch-predictor channel, and the API key is the one target that repeated observation
  helps with, because it is the only long-lived secret that enters them. The fork removes the ones listed
  above from the source; it does not make the code constant-time as compiled on every target, and the
  rest of mpz2 and of its dependencies was not reviewed for this. Such an observer stays outside the threat
  model. Operators should not run the sidecar on hardware shared with tenants they do not trust.
- The clients are JavaScript (TLS fork, SDK, browser library): no constant-time guarantee; traffic secrets
  are cleared when a connection closes, best effort (§10, risk 9).

## Suggested order of review

1. **The garbler-only consistency check** (`TWOPC-NODE-GARBLING.md` §4, §5; `crypto/twopc/src/gc.rs`,
   `lib.rs`): soundness with garbler-held masks, the 64-bit projection, and that N has no choice left after
   the challenge (the masked input ρ and δ, the input-label commitments, the transcript hashes); what the
   key-share proof of knowledge hashes, and the extraction step of the reduction sketch (§4, item 1).
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
6. **The pinned mpz2 revision** (`jooray/mpz2` at `eba78e02cb237cf1501ff0d8a492ef5fc849e135`: upstream
   `eaca5f9d9f30167c9525716e8f0aa9e33d886e5e` plus the branch-free selects above; `crypto/Cargo.lock`): KOS,
   Ferret, the VOLE-based proofs, the OLE, against what the code above relies on.
7. **Side channels** (above).
