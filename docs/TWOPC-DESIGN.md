# The two-party key schedule (`split-public-1`, protocol v3)

Status (2026-11-11): implemented in `crypto/twopc` on the branch `v3-twopc-split`, as the only two-party key
schedule of protocol v3 (`PROTOCOL-V3.md` §4 is the normative text). Tested against the reference key
schedule and against a cheating party on either side (`cargo test --release -p twopc`: 32 unit tests, 4 tests
of the `cu-2pc` binary), and run end to end through the sidecar against api.venice.ai. Not reviewed
externally. It is not compatible with v2 on purpose: the first bytes on the 2PC channel are a version tag, and
a v2 peer is refused. Construction details: `docs/TWOPC-NODE-GARBLING.md`. Measurements:
`crypto/twopc/BENCH.md`. Framings, proofs and money: `PROTOCOL-V3.md`.

## Goal

If C ran the TLS handshake alone it would know every traffic secret, and anyone who sees the ciphertext of
the credential record and colludes with C could decrypt the API key. So C (the client) and N (the node) run
the client side of the TLS 1.3 key schedule (ECDHE P-256, SHA-256) jointly:

| Value | C | N |
|---|---|---|
| ECDHE scalar / shared x-coordinate | additive share only | additive share only |
| HS, derived_hs, MS, c_ap_0 | never | never |
| `OS_k`: the outer HMAC state of each of those four keys | never | never |
| `IS_k`: the inner HMAC state of each of those four keys | yes | yes (public) |
| c_hs, s_hs (handshake traffic secrets) | yes | yes |
| s_ap_0 (server→client, the response) | yes | **never** |
| c_ap_1 (the client's body epoch) | yes | **never** |
| K_0, IV_0 (c_ap_0's AES key and IV) | **never** | yes |
| h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0) | yes | yes (public anchors for π_C2S/π_C3S) |
| hk = SHA256(K_0 ‖ IV_0) | yes | yes (public anchor for π_NK) |

c_hs, s_hs, s_ap_0, c_ap_1, K_0 and IV_0 are one-way HKDF-Expand-Label outputs (RFC 8446 §7.1), so a subset
of them does not yield a secret in the other party's column. That `IS_k` can be public is the one thing this
protocol assumes beyond v2 ("Assumptions", below).

Epochs, as far as the key schedule is concerned (the framings are in `PROTOCOL-V3.md` §5 and §6):

| Epoch | Key | Writer | Content |
|---|---|---|---|
| Handshake | c_hs / s_hs | C | ClientHello, client Finished (computed by C from c_hs) |
| 0 | c_ap_0 (K_0, IV_0) | **N** | the record with the credential, then `KeyUpdate(update_not_requested)` |
| 1 | c_ap_1 | C | everything C sends |
| Response | s_ap_0 | provider | everything the provider sends |

## Idea: split HMAC at the compression function

`HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))`, with f the SHA-256 compression function,
`IS_k = f(IV, k ⊕ ipad)` and `OS_k = f(IV, k ⊕ opad)`. Every HMAC message of the TLS 1.3 key schedule is public
(a label and a transcript hash). So the garbled circuit computes only

- the key-pad states `IS_k`, `OS_k` of the four secret HMAC keys (HS, the derived secret, MS, c_ap_0),
- the outer compressions `f(OS_k, pad(d))`,
- and the three anchors.

`IS_k` is a **public output**. Both parties compute the inner digest `d = f(IS_k, m)` in the clear, and d
enters the next stage as an input whose labels N supplies. `OS_k` never leaves the circuit.

| design | garbled AND gates | garbled compressions |
|---|---|---|
| v2 (whole key schedule in the circuit) | 656 179 | 31 |
| **`split-public-1`** | **479 022** | **22** |

## Stages

One circuit, five stages, a consistency check per stage before C uses any output of that stage.

| Stage | Call | Inputs | Garbled (compressions) | Opened |
|---|---|---|---|---|
| A1 | `handshake` | x_C, x_N | `Z = x_C + x_N mod p`; `HS = HMAC(salt, Z)` (2); `IS_HS`, `OS_HS` (2) | `IS_HS` (public) |
| A2 | `handshake` | d_c, d_s, d_der | `c_hs`, `s_hs`, `dHS = f(OS_HS, ·)` (3); `IS_dHS`, `OS_dHS` (2) | `c_hs`, `s_hs`, `IS_dHS` (public) |
| A3 | `handshake` | d_0 | `MS = f(OS_dHS, ·)` (1); `IS_MS`, `OS_MS` (2) | `IS_MS` (public) |
| B1 | `application` | d_c0, d_s0 | `c_ap_0`, `s_ap_0 = f(OS_MS, ·)` (2); `IS_c0`, `OS_c0` (2) | `s_ap_0` (C), `IS_c0` (public) |
| B2 | `application` | d_key, d_iv, d_upd | `K_0`, `IV_0`, `c_ap_1 = f(OS_c0, ·)` (3); `h1`, `h2`, `hk` (3) | `c_ap_1` (C), `K_0 ‖ IV_0` (N), `h1`, `h2`, `hk` (public) |

The inner digests: d_c, d_s over "c hs traffic" / "s hs traffic" with th_SH, d_der over "derived" with
SHA256(""), all under `IS_HS`; d_0 over 32 zero bytes under `IS_dHS`; d_c0, d_s0 over "c ap traffic" /
"s ap traffic" with th_SF under `IS_MS`; d_key, d_iv, d_upd over "key", "iv", "traffic upd" under `IS_c0`.
The HS salt is a public constant, so its key-pad states are constants.

It is one circuit because `OS_k` must cross from a stage to the next without either party touching it
(`docs/TWOPC-NODE-GARBLING.md` §2).

## Session flow

1. **Version tag.** The first bytes each party writes on the 2PC channel are the ASCII tag
   `routstr-2pc/split-public-1\n`. A party that reads anything else stops with `twopc_version_mismatch`
   (`twopc::Error::VersionMismatch`; `cu-2pc` reports it as `{"ev":"error","code":"twopc_version_mismatch",…}`
   on its control channel, prints the code on stderr and exits with status 3). A v2 peer starts with a
   multiplexer frame header and is refused at its first byte.
2. **Preprocessing** (input independent; in the pre-warm). N garbles the circuit and streams the tables. N's
   wire masks are authenticated to C by IT-MACs under C's key Δ_B and checked. N opens the masks C will need
   (its input wires, the digest input wires, the outputs C decodes), sends the check rows per stage and the
   label-check pairs. KOS gives C the COTs for its 256 input bits; ECtF prepares its OLEs.
3. **Joint key share.** C commits to `P_C = a_C·G` (SHA-256 of the SEC1 point and a 32-byte nonce), N sends
   `P_N = a_N·G`, C opens. Both compute `P = P_C + P_N`. Committing first prevents `P_C = T − P_N`. A
   pre-warmed session stops here.
4. **ClientHello.** C builds it with exactly one key share, group secp256r1, value P, and one cipher suite,
   TLS_AES_128_GCM_SHA256; no PSK, no early data. N parses and enforces this before relaying (otherwise C
   could add a share of its own). N takes the server share S from the ServerHello.
5. **ECtF.** `Q_C = a_C·S`, `Q_N = a_N·S`; point-addition share conversion (two A2M and one M2A over P-256)
   gives additive shares `x_C + x_N = x(Q_C + Q_N) mod p`.
6. **`handshake(S, th_SH)`: stages A1, A2, A3.** Per stage: C gets its input labels, evaluates, checks, and
   reports; N answers with the next stage's digest labels. Both hold c_hs and s_hs after A2 and `IS_MS` after
   A3.
7. C decrypts the server flight with s_hs, verifies the certificate chain, CertificateVerify and the server
   Finished, and sends its Finished. N verifies the same with c_hs and s_hs.
8. **`application(th_SF)`: stages B1, B2.** N sends the B1 digest labels at once (it has `IS_MS`). After B2,
   C holds s_ap_0 and c_ap_1, N holds K_0 and IV_0, both hold h1, h2, hk.
9. The proofs π_NK, π_C2S, π_C3S (and π_WIN) run over the anchors, as `PROTOCOL-V3.md` §7 describes.

### Messages

| when | direction | content | bytes |
|---|---|---|---|
| start | both | version tag | 27 |
| preprocess | N→C | three-halves tables (bulk channel) | 11.80 MB |
| preprocess | both | Ferret over KOS, C sender (Δ_B): 960 988 MAC COTs | C→N 1.09 MB, N→C 0.45 MB |
| preprocess | both | KOS, N sender (Δ_A): 256 COTs for C's input | C→N 12 kB, N→C 4 kB |
| preprocess | N→C | mask commitment bits d (one per base wire and per AND product) | 0.12 MB |
| preprocess | C→N | challenge seed, after the tables and d arrived | 32 |
| preprocess | N→C | product check (U, V); opened masks and one MAC hash; per stage check rows and Y_N; label-check pairs | 32; 0.7 kB; 3.86 MB; 81 kB |
| key share | C→N, N→C, C→N | commitment; P_N; opening | 32; 65; 97 |
| A1 | C→N | `d = x_C ⊕ b` | 32 |
| A1 | N→C | labels of x_N; corrections for x_C | 4 096 + 4 096 |
| each stage | C→N | report: `1 ‖ pointer bits ‖ SHA256(labels)`, or `0` (abort) | 65–157 |
| A2, A3, B1, B2 | N→C | labels of the stage's digests (16 B per bit), or `0` (N rejected the report) | 12 288; 4 096; 8 192; 12 288 |

The report of a stage is C's only message in that stage. N sends the next stage's labels only after the
report's label hash verified.

## Security model

Each party is protected against a malicious peer, and neither ever reveals its inputs. What follows is
argued informally. Nothing here has a published proof or an external review.

**Construction** (`docs/TWOPC-NODE-GARBLING.md`): three-halves garbling by N with a global Δ_A; N's mask of
every base wire and the product t_k = λ_i·λ_j of every AND gate committed by IT-MACs under C's Δ_B before C's
challenge; a QuickSilver product check; openings under one MAC hash; per stage, an AND-gate consistency check
with one salted 64-bit row per row wire; label-check pairs for the outputs C reports; C's report
authenticated by a hash of its labels.

### Malicious N (protects the client's s_ap_0, c_ap_1 and shares)

- *Correctness.* If any AND gate of a stage is evaluated inconsistently with the committed masks, that
  stage's check fails except with probability ≤ 2^-63 (N would have to hit π(Δ_B·E) without knowing anything
  about Δ_B; the first failure ends the session). With all gates consistent, the values behind C's pointer
  bits are the correct function of C's input, N's effective input and the digests C computed itself: C's
  input labels and the digest labels are pinned by pointer checks against opened, MAC-checked masks, and C
  decodes with such masks. Soundness is about 2^-60 per session (five checks).
- *Digest labels.* N sends them, and N knows `IS_k`. A label for another digest bit fails the pointer check
  whatever C's secrets are, because C computed the digest itself. A value that is not a label of the wire
  fails the consistency check or a label-check pair (`TWOPC-NODE-GARBLING.md` §5). So the stage runs on the
  digest of the right message under the right state, or C aborts.
- *Leakage: selective failure only.* N can make C abort depending on C's private values: a corrupted table,
  row, pair or OT correlation makes the abort a predicate of the values on the wires N aims at, and those
  include internal wires and C's own outputs. What N observes is the first of these events:

  | # | outcome |
  |---|---|
  | 1 | ECtF: C's degenerate-share abort |
  | 2–4 | C aborts in A1, A2 or A3 |
  | 5 | the server Finished fails between the calls (a shifted Z) |
  | 6–7 | C aborts in B1 or B2 |
  | 8 | success |

  **Eight outcomes, at most log2 8 = 3 bits per connection** about fresh, single-use values (the ECDHE
  share, the session's secrets), provided ECtF gives a malicious N nothing beyond its outcome (below). N may
  choose its predicate for a later stage after seeing the earlier stages' public outputs; that does not add
  outcomes.
- *Why an abort is one outcome per stage.* C's three checks of a stage (input pointer bits, consistency
  check, label-check pairs) end in the same single byte, sent after C evaluated the whole stage
  (`abort_looks_the_same_whatever_failed`). There is no "N rejected C's labels" outcome: the label-check
  pairs make N commit, in preprocessing, to the two labels it expects per reported wire, C compares before it
  reveals anything, and the report hash is then a function of the pointer bits and N's own commitments
  (`TWOPC-NODE-GARBLING.md` §7). What the pointer bits say is the stage's intended output, by the
  correctness argument.
- Removing selective failure needs evaluator-shared masks (WRK17/KRRW18-style triples), which cost more than
  the whole protocol's bandwidth.

### Malicious C (protects the node's K_0, IV_0 and the API key)

C sees the tables, its active labels and pointer bits, the opened masks (its input wires, the digest wires,
the outputs it decodes), COT corrections padded by N's choice bits, the product-check pair (masked by a
random VOLE), check rows padded by hashes of inactive labels, label-check pairs (hashes of inactive labels),
and Y_N, which C can compute itself. The mask of `K_0 ‖ IV_0` is never opened.

- C cannot report a wrong bit to N (a public `IS_k`, c_hs, s_hs, an anchor, a bit of K_0): the label hash
  needs the inactive label, which needs Δ_A (`cheating_evaluator_cannot_misreport`, every reported group).
- C cannot evaluate a stage on another digest: N computes the digest from the `IS_k` that C reported under
  its labels and from N's own transcript hash, and sends one label per wire
  (`evaluating_with_another_digest_rejected`, `different_transcript_hash_detected`).
- C's own input is free, as in any 2PC. C learns each stage's outputs before N does and can stop there. It
  then holds public values, or secrets of a connection on which N never writes the credential.

### Assumptions: both parties see `IS_k`

v2 used HMAC-SHA256 as a black box: "HMAC (HKDF-Expand-Label) is a PRF" was the only assumption on the hash.
Here a party knows `IS_k` and must not learn `f(OS_k, pad(d))` for the outputs that are not its own. That
needs:

1. `f(·, x)` keyed by its chaining input is a PRF, so that the outer compression under the unknown `OS_k`
   hides every output not handed out, also from someone who knows all inner digests;
2. `OS_k = f(IV, k ⊕ opad)` is pseudorandom given `IS_k = f(IV, k ⊕ ipad)` (f keyed through its message
   input, under the related keys ipad and opad). In particular `IS_k` does not reveal k.

These are the two assumptions of Bellare's proof that HMAC is a PRF (CRYPTO 2006). Nothing is assumed that
the usual justification of HMAC does not assume, but here they are used directly, and a party sees a value no
HMAC user ever sees. The inner hash also loses its secret key: with `IS_k` known, distinct messages must have
distinct inner digests by plain collision resistance of f. The messages are fixed labels with the handshake's
transcript hashes, which each party computes itself, so nobody chooses them.

| who relies on 1 and 2 | to protect | against |
|---|---|---|
| N | K_0, IV_0 (and with them the API key) | C, who knows `IS_c0`, c_ap_1, hk and all inner digests |
| C | s_ap_0, c_ap_1 | N, who knows `IS_MS`, `IS_c0`, K_0, IV_0, h1, h2 |
| both | HS, derived_hs, MS, c_ap_0 and the ECDHE secret | the other party and anyone who learns `IS_k` |

`IS_k` is "public" between C and N. Neither sends it anywhere else, and nothing requires that.

### The order of messages

Who learns what first, and what a party can still decide at that point:

- C's input is fixed before it sees anything of N's: it sends `d = x_C ⊕ b` first, and b is uniform to N. N's
  input is fixed by the labels it sends for x_N; the tables, masks, rows and pairs were fixed in
  preprocessing. After A1 neither party has an input left to choose. The digests are determined by `IS_k`
  and the transcript, and each party uses its own transcript hash (a difference is an abort).
- In every stage C learns the outputs first (it decodes), N second (from the report). C can stop after seeing
  `IS_k` or its own outputs; N can stop after a report. Stopping gives the other party no output it should
  not have and gives the stopping party nothing but what the stage hands out anyway. Neither can go back and
  evaluate a stage again: C takes a stage's check keys and rows once, N accepts one report per stage.
- `IS_k` is a deterministic function of the inputs fixed in A1, so there is nothing to bias by aborting and
  retrying: a new session has fresh shares, labels and offsets.
- N chooses the digest labels after it has seen `IS_k` and C's reports. All it can do with that is abort
  (unconditionally, or through a predicate it could have planted in the rows anyway).

### The anchors

h1, h2 and hk are computed in stage B2 over the very wires that carry c_ap_1, s_ap_0 and `K_0 ‖ IV_0`, and
opened as public outputs. C checks h1 and h2 against its own outputs before it sends the B2 report (N gets
K_0 with that report); N checks hk against SHA256 of what it decoded. A wrong anchor would need a wrong
evaluation that passes the B2 check. s_ap_0 is decoded by C in B1 and anchored in B2: its wires cross into B2
as row wires. Why the anchors are still SHA-256 in the circuit: `TWOPC-NODE-GARBLING.md` §8.

### ECtF

mpz2's OLE-based A2M/M2A, proven secure against semi-honest parties only. We do not argue that it stays
private against a malicious N; the leakage bound is conditional on that. Under that assumption a deviation
either shifts the result (a wrong ECDHE secret, which the TLS handshake detects: the server Finished under
s_hs fails) or trips C's degenerate-share check, and N can make either depend on C's share: outcomes 1 and 5.
Every session uses fresh scalars, shares, labels, Δ_A and Δ_B.

### What is proven, what is argued, what is assumed

| part | status |
|---|---|
| QuickSilver product check, IT-MAC openings | standard (QuickSilver/Wolverine soundness), GF(2^128) |
| three-halves garbling privacy and authenticity | Rosulek–Roy proof, under their hash assumption (instantiated, as in mpz2, with fixed-key-AES TCCR); the matrices need comparing with the paper |
| AND-gate consistency check with garbler-held masks, 64-bit projection, salt | argued; **no published proof** for this garbler-only variant |
| the check run per stage, crossing wires as row wires | argued (`TWOPC-NODE-GARBLING.md` §2, §4); new in v3 |
| label-check pairs | argued (`TWOPC-NODE-GARBLING.md` §7); new in v3 |
| public `IS_k`, digest labels from N pinned by pointer checks | argued above; assumptions 1 and 2; new in v3 |
| leakage bound (≤ 3 bits per connection) | counting argument above, conditional on ECtF |
| Ferret/KOS against a malicious receiver (N for the MAC COTs under Δ_B; C for the 256 COTs under Δ_A), KOS consistency-check leakage of a few Δ bits with negligible probability | assumed from mpz2 |
| ECtF | semi-honest only; no argument for a malicious N |
| external review | **none yet** |

## Review as an adversary (2026-11-11)

Done once more when `split-public-1` became the only variant. Nothing was found broken. Each row names the
test that exercises it.

| question | finding |
|---|---|
| Is C's pointer check of a digest label against an authenticated, already opened mask? | Yes: the 2 304 digest wires are in the opening of preprocessing, under the MAC hash (`lying_about_an_input_mask_detected`). |
| Can N choose digest labels after seeing something secret-dependent? | It sends them after `IS_k` and C's report, both of which it may know. The other bit's label fails the pointer check for every secret alike; any other value ends in an abort (`wrong_digest_label_from_garbler_detected`, `labels_for_another_digest_detected`, `garbage_garbler_input_label_detected`). |
| N knows the salt when it chooses labels online. | Doubtful in form, fine in effect: the salt argument covers only what is committed before the seed. An online label that collides in its own 64-bit row still produces pseudo-random labels behind the next AND gate, which depend on `OS_k` (`TWOPC-NODE-GARBLING.md` §5). |
| Does the order of messages let a party bias or learn something? | No ("The order of messages"). |
| How many outcomes does N observe? | Eight. The three checks of a stage are indistinguishable (`abort_looks_the_same_whatever_failed`); N's own rejection of a report is not reachable by a C that passed its pair checks. |
| The anchors in B2. | Hardened: C now compares h1 and h2 with its outputs before the B2 report instead of after it. h2 moved from B1 to B2, as the specification has it. |
| Cheating C: another digest, a misreported `IS_k`, misreported outputs. | Rejected by N's label hash (`evaluating_with_another_digest_rejected`, `cheating_evaluator_cannot_misreport` for all ten reported groups). |
| Doubtful: N's inconsistent labels. | The consistency check does not show that a wire's two labels differ by Δ_A. Nothing in this protocol uses a label of C as a commitment, and reported labels go through the pairs, so the effect is an abort. It stays an argument about this circuit, not a proof. |
| Doubtful: 3 bits per connection. | A connection now carries many requests (`PROTOCOL-V3.md` §10, risk 6), so the bits are about values that protect more traffic than in v2. |

## Cost

`crypto/twopc/BENCH.md` has the tables. Per connection the client uploads 1.13 MB and downloads 16.4 MB
(tables 11.8 MB, check rows 3.9 MB); v2 moved 1.21 MB and 22.1 MB per request. A cold key schedule takes
7.0 s on a 2/50 Mbit/s link with 80 ms round-trip time (v2: 7.4 s) and 15.6 s with a 10 Mbit/s
downlink (v2: 20.1 s). Each stage after A1 costs one round trip that v2 did not have: from C's side `handshake` takes 3
instead of 1 and `application` 1.5 instead of 1 (N's B1 labels need no message from C).

## History: v2 and `Proven`

- **v2** (branch `twopc-v2`; `confidential-2pc` in routstr-core and routstr-sdk): the whole key schedule in
  two garbled phase circuits, MS crossing between them as XOR shares, a bare report hash, seven outcomes
  (2.8 bits) per request. Deployed until v3.
- **`Proven`** (prototype, removed 2026-11-11): `IS_k` to C only, the inner digests and anchors proven in
  zero knowledge. Fewer gates (19 compressions) but a larger upload, a second Ferret under Δ_A, and Δ_A used
  both as garbling offset and as MAC key. It kept the hash assumptions of v2 on C's side.
  `TWOPC-NODE-GARBLING.md` §9 has the numbers.

## Components

- `crypto/twopc`: `lib.rs` (the protocol, `Party`), `gc.rs` (garbling, MAC bookkeeping, check), `circuits.rs`
  (the circuit and the HKDF message blocks), `ectf.rs`, `mux.rs`, and the `cu-2pc` binary (C's side, spawned
  by the clients).
- `crypto/relay`: the sidecar runs N's side (`run_twopc_n`).
- The browser library vendors `crypto/twopc`; it has to be re-vendored for v3.
