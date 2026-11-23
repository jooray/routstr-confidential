# The two-party key schedule (`split-public-3`, protocol v3)

Status (2026-11-23): implemented in `crypto/twopc`, as the only two-party key
schedule of protocol v3 (`PROTOCOL-V3.md` §4 is the normative text). Against `split-public-1` (deployed
from 2026-11-12) the circuit and the stages are the same, the garbling hash, the check-row
hash and the handling of the input labels are new ("Changes from `split-public-1`", below). Tested against the
reference key schedule and against a cheating party on either side (`cargo test --release -p twopc`: 55 unit
tests, 4 tests of the `cu-2pc` binary), and run end to end through a loopback sidecar against api.venice.ai.
The construction has no published proof and has had no external review. It is not compatible with v2 or with
an earlier variant on purpose: the first bytes on the 2PC channel are a version tag, and such a peer is refused.
History: `split-public-2` replaced `split-public-1` on 2026-11-22 with a hard switch. On 2026-11-22/23 its
key-share message gained N's proof of knowledge (step 3 below) under the unchanged tag, so for a day two builds
with the same tag did not interoperate. `split-public-3` (2026-11-23) is byte-identical to the final
`split-public-2` except for the tag and the offer value; the new name lets every older peer be refused at
the tag.
Construction details: `docs/TWOPC-NODE-GARBLING.md`. Measurements:
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
`IS_k = f(IV, k ⊕ ipad)` and `OS_k = f(IV, k ⊕ opad)`. Every inner digest that moves out of the circuit has a
public message (a fixed label and a transcript hash). The one HMAC of the key schedule with a secret message,
the extraction `HS = HMAC(salt, Z)`, stays whole inside the circuit (stage A1). So the garbled circuit computes only

- the key-pad states `IS_k`, `OS_k` of the four secret HMAC keys (HS, the derived secret, MS, c_ap_0),
- the outer compressions `f(OS_k, pad(d))`,
- and the three anchors.

`IS_k` is a **public output**. Both parties compute the inner digest `d = f(IS_k, m)` in the clear, and d
enters the next stage as an input whose labels N supplies. `OS_k` never leaves the circuit.

| design | garbled AND gates | garbled compressions |
|---|---|---|
| v2 (whole key schedule in the circuit) | 656 179 | 31 |
| **`split-public-1`, `split-public-3`** | **479 022** | **22** |

## Stages

One circuit, five stages, a consistency check per stage before C uses any output of that stage.

| Stage | Call | Inputs | Garbled (compressions) | Opened |
|---|---|---|---|---|
| A1 | `handshake` | x_C' = x_C + δ, ρ | `Z = x_C' + ρ = x_C + x_N mod p`; `HS = HMAC(salt, Z)` (2); `IS_HS`, `OS_HS` (2) | `IS_HS` (public) |
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
   `routstr-2pc/split-public-3\n`. A party that reads anything else stops with `twopc_version_mismatch`
   (`twopc::Error::VersionMismatch`; `cu-2pc` reports it as `{"ev":"error","code":"twopc_version_mismatch",…}`
   on its control channel, prints the code on stderr and exits with status 3). A v2 peer starts with a
   multiplexer frame header and is refused at its first byte; a `split-public-2` or `split-public-1` peer differs in the tag's
   last bytes (tested by the case `h2-j-twopc-tag-old` of `v3-check.sh`).
2. **Preprocessing** (input independent; in the pre-warm). C sends a 16-byte salt. N draws the garbling
   hash's parameters and a random mask ρ < p as its own circuit input, garbles the circuit and streams the
   hash parameters, then the tables. N's wire masks are authenticated to C by IT-MACs under C's key Δ_B. N
   sends the labels of ρ and commitments to both labels of every other input wire (C's 256, the 2 304
   digest wires); only then does C send its challenge seed. N proves the products, opens the masks C will
   need (its input wires, the digest input wires, the outputs C decodes), sends the check rows per stage and
   the label-check pairs. KOS gives C the COTs for its 256 input bits; ECtF prepares its OLEs.
3. **Joint key share.** C commits to `P_C = a_C·G` (SHA-256 of the SEC1 point and a 32-byte nonce). N sends
   `P_N = a_N·G` with a proof that it knows `a_N`. C verifies the proof and only then opens. Both compute
   `P = P_C + P_N`. Committing first prevents `P_C = T − P_N`. The proof is a Schnorr proof made
   non-interactive with SHA-256: `R = k·G`, `e = SHA256(tag ‖ rparams ‖ com ‖ P_N ‖ R)`,
   `s = k + e·a_N mod n`, sent as `e ‖ s` (64 bytes). `com` is C's commitment and `rparams` the row
   parameters of this preprocessing, so a proof from another key share does not verify here. C refuses a
   point that is not a canonical uncompressed encoding of a curve point, an `s ≥ n`, and a proof whose
   recomputed challenge differs; it then stops without opening, and N learns nothing from that, because
   it could have run the check itself. `PROTOCOL-V3.md` §4.1 has the bytes. C gives no proof for `a_C`
   ("Malicious C" below). A pre-warmed session stops here.
4. **ClientHello.** C builds it with exactly one key share, group secp256r1, value P, and one cipher suite,
   TLS_AES_128_GCM_SHA256; no PSK, no early data. N parses and enforces this before relaying (otherwise C
   could add a share of its own). N takes the server share S from the ServerHello.
5. **ECtF.** `Q_C = a_C·S`, `Q_N = a_N·S`; point-addition share conversion (two A2M and one M2A over P-256)
   gives additive shares `x_C + x_N = x(Q_C + Q_N) mod p`.
6. **`handshake(S, th_SH)`: stages A1, A2, A3.** N sends `δ = x_N − ρ mod p`; C's circuit input is
   `x_C' = x_C + δ mod p`. Per stage: C gets its input labels, checks them against the opened masks and N's
   commitments, evaluates, checks, and reports; N answers with the next stage's digest labels. Both hold
   c_hs and s_hs after A2 and `IS_MS` after A3.
7. C decrypts the server flight with s_hs, verifies the certificate chain, CertificateVerify and the server
   Finished, and sends its Finished. N verifies the same with c_hs and s_hs. C accepts only a flight that
   U's signature fixes (no message besides the four, nothing after the signature, one encoding of it):
   N holds s_hs and could otherwise choose `th_SF` (`TWOPC-NODE-GARBLING.md` §4).
8. **`application(th_SF)`: stages B1, B2.** N sends the B1 digest labels at once (it has `IS_MS`). After B2,
   C holds s_ap_0 and c_ap_1, N holds K_0 and IV_0, both hold h1, h2, hk.
9. The proofs π_NK, π_C2S, π_C3S (and π_WIN) run over the anchors, as `PROTOCOL-V3.md` §7 describes.

### Messages

| when | direction | content | bytes |
|---|---|---|---|
| start | both | version tag | 27 |
| preprocess | C→N | `in_salt`, the salt of the input-label commitments (first message) | 16 |
| preprocess | N→C | hash parameters, then the three-halves tables (bulk channel) | 32; 11.80 MB |
| preprocess | both | Ferret over KOS, C sender (Δ_B): 960 988 MAC COTs | C→N 1.09 MB, N→C 0.45 MB |
| preprocess | both | KOS, N sender (Δ_A): 256 COTs for C's input | C→N 12 kB, N→C 4 kB |
| preprocess | N→C | mask commitment bits d (one per base wire and per AND product) | 0.12 MB |
| preprocess | N→C | labels of ρ on N's 256 input wires; commitments to both labels of the other 2 560 input wires | 4 096; 81 920 |
| preprocess | C→N | challenge seed, after all of the above arrived | 32 |
| preprocess | N→C | product check (U, V); opened masks and one MAC hash; per stage check rows and Y_N; label-check pairs | 32; 0.7 kB; 3.86 MB; 81 kB |
| key share | C→N, N→C, C→N | commitment; `P_N` with the proof `e ‖ s`; opening (after the proof verified) | 32; 129; 97 |
| A1 | N→C | `δ = x_N − ρ mod p` | 32 |
| A1 | C→N | `d = x_C' ⊕ b` | 32 |
| A1 | N→C | corrections for x_C' | 4 096 |
| each stage | C→N | report: `1 ‖ pointer bits ‖ SHA256("routstr-twopc-split output labels" ‖ stage ‖ labels)` (the stage index as one byte), or `0` (abort) | 65–157 |
| A2, A3, B1, B2 | N→C | labels of the stage's digests (16 B per bit), or `0` (N rejected the report) | 12 288; 4 096; 8 192; 12 288 |

The report of a stage is C's only message in that stage. N sends the next stage's labels only after the
report's label hash verified.

Payload per session (`twopc::message_sizes`, without OT traffic and the tag): N→C 15 989 810 B, C→N 690 B.
On the wire with the OT traffic and the multiplexer: C receives 16 467 057 B and sends 1 134 246 B
(`crypto/twopc/BENCH.md`).

## Security model

Each party is protected against a malicious peer, and neither ever reveals its inputs. What follows is
argued informally. Nothing here has a published proof or an external review.

**Construction** (`docs/TWOPC-NODE-GARBLING.md`): three-halves garbling by N with a global Δ_A; N's mask of
every base wire and the product t_k = λ_i·λ_j of every AND gate committed by IT-MACs under C's Δ_B before C's
challenge; N's own circuit input a random mask ρ whose labels, like commitments to both labels of every other
input wire, precede the challenge; a QuickSilver product check; openings under one MAC hash; per stage, an
AND-gate consistency check with one 64-bit row per row wire, hashed under a key from C's seed; label-check
pairs for the outputs C reports; C's report authenticated by a hash of its labels.

### Malicious N (protects the client's s_ap_0, c_ap_1 and shares)

- *Correctness.* If any AND gate of a stage is evaluated inconsistently with the committed masks, that
  stage's check fails except with probability ≤ 2^-63 (N would have to hit π(Δ_B·E) without knowing anything
  about Δ_B; the first failure ends the session). With all gates consistent, the values behind C's pointer
  bits are the correct function of C's input, N's effective input and the digests C computed itself: C's
  input labels and the digest labels are pinned by pointer checks against opened, MAC-checked masks, and C
  decodes with such masks. The check equation contains a label only through its pointer bit and its row
  hash, and with all gates consistent the decoded values are right whatever labels carried them. For
  "passes ⇒ all gates consistent" N must not be able to adapt the pointer bits to the challenge. It cannot:
  its own input labels (of ρ) and commitments to all other input labels precede the challenge, and after it
  N only sends δ, which shifts C's input, and that input stays hidden from N under DDH in P-256
  (`TWOPC-NODE-GARBLING.md` §4 has the argument, its assumptions and the remaining influence of N on the
  transcript hashes).
  Soundness is about 2^-60 per connection (five checks), for a connection whose server share N did not
  choose. **Argued**, no review.
- *Soundness is statistical, per connection, and adds up.* The 2^-60.6 bound (five stages at ≤ 2^-63 each,
  `TWOPC-NODE-GARBLING.md` §4) is the chance that one connection's wrong evaluation passes. Every connection
  draws a fresh Δ_B, χ and row key, so a node that cheats on every connection succeeds somewhere with
  probability at most k·2^-60.6 over k connections: about 2^-40.6 after a million connections (2^20),
  2^-30.6 after a billion. Each failed attempt is an abort the client sees.
- *Stage A1 in `split-public-1` (found 2026-11-22).* There N sent the labels of its own input after it
  knew that stage's challenge χ. With adder gates garbled so that a violation depends on a bit of N's
  input, N could choose its input so that the violations cancel in the check; a prepared node passed with a
  wrong sum with probability about 2^-23 per connection. Z was then wrong, C failed on the provider's first
  encrypted record and the later stages never ran; no use against a traffic secret is known.
  `split-public-3` sends the labels of the mask ρ before the seed and only δ after it
  (`adder_switch_attack_caught`).
- *Digest labels.* N sends them, and N knows `IS_k`. A label for another digest bit fails the pointer check
  whatever C's secrets are, because C computed the digest itself. A value that is not one of the wire's two
  committed labels fails the commitment check (`TWOPC-NODE-GARBLING.md` §5). So the stage runs on the
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

  Outcome 1 depends on C's randomness only; N cannot select it (ECtF, below). Outcome 5 occurs for every
  effective deviation of N in ECtF and is not a predicate N can aim there. So 3 bits is a conservative count.
  The eight outcomes are those after preprocessing: in preprocessing N also observes whether its KOS
  consistency checks, the product check and the openings pass, which are predicates on C's fresh OT keys
  (Δ_B, the Δ of the ECtF instance), not on a key-schedule value.

  **Eight outcomes, so at most log2 8 = 3 bits per connection of additional selective-failure leakage**
  about fresh, single-use values (the ECDHE share, the session's secrets), **in the idealized abort model
  stated here**: every deviation of N ends in one of these eight outcomes, which N observes and nothing else.
  It is conditional on the ECtF argument (below: a malicious N is limited to input substitution) and on the
  garbling argument (`TWOPC-NODE-GARBLING.md`, no published proof). It is not a bound on everything N learns: N also
  receives the outputs it is meant to have (the public `IS_k`, c_hs, s_hs, the anchors, `K_0 ‖ IV_0`). N may
  choose its predicate for a later stage after seeing the earlier stages' public outputs; that does not add
  outcomes. What a full proof must still enumerate: every externally distinguishable result of a malicious
  ECtF, OT and preprocessing, of every stage, of N's own report checks, of the TLS verification, timeouts and
  error messages; the tests compare selected cheats at two stages (`abort_looks_the_same_whatever_failed`).
  Observations outside the table that the code has today: which check of preprocessing failed (KOS, the
  product check, the openings), whether C accepted N's key-share proof and δ (both N's own public values),
  which TLS check failed at C as far as its error text and timing show it, and whether C retries. None of
  them was found to be a predicate on a key-schedule value that the eight outcomes do not already count, but
  that is a reading of the code, not a proof.
- *Why 3 bits per connection is harmless.* The values N can aim a selective failure at are C's ECDHE share
  `x_C`, the point `Q_C = a_C·S` (when N feeds 0 into ECtF, C's circuit input is a known shift of its
  x-coordinate) and the secrets of the schedule (HS, MS, c_hs, s_hs, c_ap_1, s_ap_0): each is a fresh, uniformly
  distributed (or pseudorandom) value of 256 bits, drawn for this connection and used on no other. No prompt,
  no response, no credential and no other low-entropy or long-lived value enters the circuit: C encrypts its
  records outside the 2PC with keys derived from c_ap_1, and N writes the credential under `K_0` outside it.
  A leak with at most 8 outcomes lowers the (average) min-entropy of a secret by at most log2 8 = 3 bits
  (the standard bound of Dodis, Ostrovsky, Reyzin and Smith: H̃∞(X | L) ≥ H∞(X) − log2 |L| for a leak L with |L| outcomes), so it multiplies the success probability of any guess
  by at most 8: a 256-bit secret keeps at least 253 bits, and the AES-128 keys derived from c_ap_1 and s_ap_0
  stay at most 8 times easier to guess than without the leak (≤ 2^-125). The bits do not accumulate across
  connections, since no secret is used twice; within a connection they cover every request it carries
  (§10 of `PROTOCOL-V3.md`, risk 6), which is why the bound is per connection.
- *Why an abort is one outcome per stage.* C's checks of a stage (input pointer bits and commitments,
  consistency check, label-check pairs) end in the same single byte, sent after C evaluated the whole stage
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
- C does not prove knowledge of its key-share scalar, and nothing here needs it. Its commitment fixes
  `P_C` before it sees `P_N`, so it cannot choose the joint share
  (`rogue_key_share_aborts`). With the commitment hash as a random oracle a reduction reads `P_C` from C's
  query, without rewinding, and can make the joint share any point it wants by its choice of `P_N`. A C
  that does not know `a_C` cannot compute its input to ECtF: the handshake fails, and N has written
  nothing.
- N's proof of knowledge gives C nothing about `a_N`: with a uniform nonce it can be simulated without
  `a_N` by programming the challenge hash (zero knowledge in the random-oracle model). `a_N` and the
  nonce are used for one connection.

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
HMAC user ever sees. Bellare's theorem is about one key and an adversary who sees neither pad state; it is
not by itself a proof of this system, where both parties see `IS_k` of a chain of derived keys
(HS → derived → MS → c_ap_0), several outer outputs per key go to different parties, the anchors are
public and selective failure is possible. That proof is a chain of hybrids over both adversary directions
and all values revealed together, and it is **not written yet**.

3. **Distinct inner digests under one key (cross-label collision resistance).** The inner hash loses its
   secret key. Under one `OS_k` the circuit computes several outputs, and two equal inner digests give
   equal outputs: in B1 `c_ap_0 = f(OS_MS, pad(d_c0))` and `s_ap_0 = f(OS_MS, pad(d_s0))`, so
   `d_c0 = d_s0` would hand C (who holds `s_ap_0`) `c_ap_0`, hence `K_0, IV_0`, and break P1; in A2
   `c_hs`, `s_hs` and the derived secret come from `OS_HS`, and a collision of the `"derived"` digest with
   `d_c` or `d_s` would make the derived secret one a party holds, and with it MS. So the requirement is
   that the inner digests of one key are pairwise distinct: for the exact HKDF message blocks of the
   schedule, `f(IS_k, m) ≠ f(IS_k, m')` for `m ≠ m'`. **Justification:** the messages of one key differ in
   their fixed HKDF labels (`c hs traffic`, `s hs traffic`, `derived`; `c ap traffic`, `s ap traffic`),
   which sit at fixed positions of the message block, so `m ≠ m'` always; `IS_k` is known to both
   parties, so an equal pair is a collision of the SHA-256 compression function under a known (random,
   not chosen) chaining value. Neither party chooses the labels; the transcript hashes it can influence
   (C picks its random, N relays) sit in both messages alike. Finding such a collision costs about 2^128
   compressions by the generic attack, and it is a property SHA-256 is relied on for everywhere. In v2 the
   inner key was secret and the PRF assumption covered this; since `split-public-1` it is an explicit
   assumption of its own. (A reviewed domain-separation construction could remove it; none is used.)
4. **The anchors.** `h1 = SHA256(c_ap_1)`, `h2 = SHA256(s_ap_0)` and `hk = SHA256(K_0 ‖ IV_0)` are public,
   while the same secrets are used as HKDF keys (key update, key and IV derivation) and as an AES-GCM key
   and IV. That a plain hash of a key does not weaken HMAC or AES-GCM under that key is not implied by
   assumptions 1 to 3; it holds with SHA-256 as a random oracle. **Assumed.**

| who relies on 1 and 2 | to protect | against |
|---|---|---|
| N | K_0, IV_0 (and with them the API key) | C, who knows `IS_c0`, c_ap_1, hk and all inner digests |
| C | s_ap_0, c_ap_1 | N, who knows `IS_MS`, `IS_c0`, K_0, IV_0, h1, h2 |
| both | HS, derived_hs, MS, c_ap_0 and the ECDHE secret | the other party and anyone who learns `IS_k` |

`IS_k` is "public" between C and N. Neither sends it anywhere else, and nothing requires that.

### The order of messages

Who learns what first, and what a party can still decide at that point:

- Before C's challenge seed N has fixed the tables, the hash parameters, the masks, the labels of its
  circuit input ρ and the commitments to the labels of every other input wire. After the seed N's choices
  are δ (which only shifts C's input), the rows, openings and pairs (which can only make C abort) and the
  relayed transcript (`TWOPC-NODE-GARBLING.md` §4). C's input is fixed when it sends `d = x_C' ⊕ b`, and b is
  uniform to N. After A1 neither party has an input left to choose. The digests are determined by `IS_k`
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

mpz2's OLE-based A2M/M2A (`mpz-share-conversion`), which mpz2 documents as secure against semi-honest
parties only. The argument below for malicious parties is ours, for this code; it has no published proof
and no review. The roles (`crypto/twopc/src/ectf.rs`, `lib.rs`): **C is the OLE sender**
(`ShareConversionSender`, a KOS COT sender, Chou–Orlandi receiver for its base OTs), **N is the OLE
receiver** (`ShareConversionReceiver`). C inputs `[−y1, −x1]`, N `[y2, x2]`, the coordinates of each party's
`a·S`, where S is the provider's share of this handshake and `a_C`, `a_N` are fresh scalars of this
connection. Two A2M give each party a multiplicative share; each computes `c = (m[0]/m[1])^2` locally; one
M2A on `c`; the share is `d − x_own`. Both parties check their own multiplicative share for zero
(`ectf: degenerate share`) and abort. In the M2A both parties send their offset before they read the
other's, so either can wait for the other's offset first.

What N sends in the conversion: Chou–Orlandi sender messages, the KOS extension matrix and its consistency
check, two A2M offsets and one M2A offset. What it receives: Chou–Orlandi receiver points, the KOS challenge
seed, the three masked correlations of the OLEs, two masked values and C's M2A offset.

*Against a malicious N* (protecting C's `x_C`). **Argued**, in the ROT-hybrid model, under the assumptions
listed at the end of this item.

- *N is limited to input substitution.* In ROLE generation N sends nothing after the OTs; its choice bits
  fix its three OLE inputs. In A2M and M2A it sends one field element per conversion, and any value is the
  honest message for some input. Beyond that it could send inconsistent KOS columns; the KOS check is run,
  and a receiver that passes behaves as one with consistent choice bits, except that it learns c bits of C's
  KOS Δ with probability 2^-c of not being caught (**assumed** from KOS15 as revised and mpz2's code).
- *N's view is simulatable without C's point.* A simulator that plays C records N's ROT choices, sends
  uniform correlations, forwards N's substituted inputs to an ideal functionality and computes the masked
  messages from its answers and N's own OLE outputs; the real messages have the same distribution because
  each carries a uniform OLE value unknown to N. So N's view is two multiplicative shares, uniform in `F_p^*` unless N's substituted input
  equals C's coordinate, plus values N could sample itself. That equality test needs a guess of `y1` or `x1`,
  which gives `Q_C = a_C·S` up to 3 candidates: CDH for `(P_C, S)`.
- *C's degenerate-share abort depends on C's own randomness only.* N cannot trigger or bias it (outcome 1).
- *What a deviation gives.* N's total effect is `Z' = k·λ'^2 − x1 + c` for values `k, c, (x2', y2')` of its
  choice, with `λ' = (y2' − y1)/(x2' − x1)`. As a function of `Q_C` on the curve, `Z'` is never constant
  (degree ≤ 6, so each value has at most 6 preimages), and it equals the true Z identically only for the
  honest inputs. To make `Z'` a value it knows, N must know `Q_C`, which is CDH for `(P_C, S)`, or replace S
  by a share of its own, which ends at C's check of CertificateVerify (N has no signature of U over that
  transcript). With the genuine S, C decrypts U's flight with a wrong `s_hs`, the AEAD fails (N cannot read
  the flight, which needs the true Z, nor make one, which needs U's signature), and stages B1 and B2 never
  run: **that connection carries no record of C and has no `c_ap_1`, `s_ap_0`.**
- *The handshake-stage outputs for `Z'` give N nothing* if HKDF-Extract is a random oracle: they are then
  independent of everything else unless N queries the oracle at `Z'`, and such a query yields `Q_C` up to 6
  candidates, so N's advantage is that of CDH with a list of candidates, or tightly that of strong DH (CDH
  with a DDH oracle). Without the oracle model this step needs HMAC-SHA256 with a public key to be secure for
  inputs related by the rational maps above, a correlated-input assumption that no standard assumption
  covers. It concerns only a connection that never carries data.
- *Consequence.* If N knew C's KOS Δ of the ECtF instance in full, it would know both ROT messages and so
  Z. Confidentiality of a recorded connection against N rests on that 128-bit Δ (128 − c bits with
  probability 2^-c), as for the other KOS and Ferret instances.
- Assumptions: mpz2's KOS and Chou–Orlandi (assumed), its fixed-key TCCR in the ROT randomization (assumed,
  ideal-permutation model), HKDF-Extract as a random oracle, strong DH in P-256. Tests:
  `ectf_n_substitutes_its_point` (one substituted point on the curve, one off it: the conversion behaves as
  the model says, C sees no error up to stage A3, and the server's first record does not open under C's
  `s_hs`), `ectf_n_zero_m2a_input`, `ectf_n_shifted_share`, `ectf_c_abort_is_not_n_selectable` (200 runs
  with random deviations of N, no degenerate-share abort on C).

*Against a malicious C* (protecting N's `x_N`, and with it the ECDHE secret, `K_0` and the credential). As
the OLE sender C may send arbitrary correlations, masked values and offsets. N's multiplicative share is
then an affine function, of C's choice, of N's 256 ROLE bits, and N's additive share likewise through the
M2A. That gives C two predicates on N's ROLE bits: N's degenerate-share abort, and whether the handshake
succeeds (C can aim the second at one guess by shifting its own circuit input). C cannot test candidates
offline (it does not know Z, which needs `a_N·S`), and it cannot cancel N's unknown bits to make `Z'` a value
it knows. **3 outcomes, ≤ log2 3 ≈ 1.6 bits per connection about `(x2, y2)`. Argued** for this code, by
enumeration of its error paths, assuming that Chou–Orlandi gives a malicious receiver one seed per base OT
(otherwise C would learn all of N's choice bits, hence Z and `K_0`), the PRG, and the oracle model for the
extract. That value is fresh and single-use (a new `a_N` and a new S per connection), so "Why 3 bits per
connection is harmless" above applies with 1.6 bits. A wrong ECDHE secret gives C nothing either: N writes
the credential only after it verified the provider's Finished under its own handshake secrets, and `K_0` is
an output of the 2PC that only N decodes. Tests: `ectf_c_inconsistent_masks` (one correlation with another
OLE value: N's share is right or wrong depending on one of its ROT bits, no error and no other outcome),
`ectf_c_forces_degenerate_share`.

Two small facts. N's OLE value b is 256 uniform bits reduced mod p, so each offset N sends is not exactly
uniform (statistical distance about 2^-32; for C at most a factor 2 on a guess). mpz2 before revision
`eaca5f9` computed N's additive share from the bits of the reduced b while the ROT used the unreduced bits;
for about 2^-30 of connections N's share was wrong and the handshake failed, with no leak. The pin moved to
`eaca5f9` on 2026-11-22, the upstream fix.

A second conversion with the roles swapped and an equality check in the circuit (TLSNotary's measure) is not
used: a consistent substitution passes it, it would make N an OLE sender towards C and so give N the
selective-failure predicate C has here, and the handshake already detects a wrong Z.

Every session uses fresh scalars, shares, labels, Δ_A and Δ_B.

### What is proven, what is argued, what is assumed

| part | status |
|---|---|
| QuickSilver product check, IT-MAC openings | standard (QuickSilver/Wolverine soundness), GF(2^128) |
| three-halves garbling privacy and authenticity | **proven** for inputs fixed before garbling (Rosulek–Roy, CRYPTO 2021, Theorem 3), with the paper's recommended hash family `AES_k(X ⊕ U(τ)) ⊕ σ(X ⊕ U(τ))`, RTCCR by its Lemmas 5 and 6 (AES-128 a PRF for a random key; AES under the revealed key an ideal permutation); the matrices were compared with the paper's figures (2026-11-21) and the choice of halves is a relabelling (argued); the extension to the check rows is argued. **Assumed, not covered by the theorem:** tables sent in preprocessing and inputs that arrive later, stage by stage (needs a programmable ideal permutation); SHA-256 hashes of labels and KOS correlations under the same Δ_A (`TWOPC-NODE-GARBLING.md` §6) |
| AND-gate consistency check with garbler-held masks, 64-bit projection, row hash keyed by C's seed | argued; **no published proof** for this garbler-only variant |
| the check run per stage, crossing wires as row wires | argued (`TWOPC-NODE-GARBLING.md` §2, §4); new in v3 |
| label-check pairs | argued (`TWOPC-NODE-GARBLING.md` §7); new in v3 |
| public `IS_k`, digest labels from N pinned by pointer checks | argued above; assumptions 1 and 2; new in v3 |
| leakage bound (≤ 3 bits per connection) | counting argument in the idealized abort model above, conditional on ECtF and the garbling argument; not a full enumeration of a malicious N's observations |
| harmlessness of the leak | argued above: every value it can concern is a fresh secret of 256 bits, used for one connection; min-entropy loss ≤ log2 of the outcomes |
| soundness of the consistency check | statistical: ≤ 2^-60.6 per connection, k·2^-60.6 over k connections, for a connection whose server share N did not choose; argued, under DDH in P-256 (C's share is hidden from N only computationally; the reduction is not written out; a sketch of it extracts the discrete logarithm of N's key share from N's proof of knowledge by rewinding and needs SHA-256 in that proof, HKDF-Extract and the hash of mpz2's base OT as random oracles), a client TLS stack that accepts at most two server flights per signature of U, and the random-function behaviour of `f` for the transcript hash N relays before stage A2 (`TWOPC-NODE-GARBLING.md` §4). In `split-public-1` stage A1 had only about 2^-23 against a prepared node, with a failed handshake as the outcome |
| distinct inner digests under one key (assumption 3) | assumed: compression-function collision resistance under a known chaining value |
| the chained multi-output composition with public `IS_k` | **not written** (hybrids over both directions and every value revealed together) |
| N's input is fixed before the challenge, the other input labels are committed before it | argued (`TWOPC-NODE-GARBLING.md` §4, §5); new since `split-public-2`; in `split-public-1` neither held |
| Ferret/KOS against a malicious receiver (N for the MAC COTs under Δ_B; C for the 256 COTs under Δ_A), KOS consistency-check leakage of a few Δ bits with negligible probability | assumed from mpz2 |
| N's proof of knowledge of its key-share scalar | Schnorr with the Fiat–Shamir transform: a proof of knowledge in the random-oracle model, extraction by rewinding (forking lemma), zero knowledge with a programmed oracle; standard results, applied here to one connection at a time. No statement for interleaved key shares, no straight-line extraction. Tests: `key_share_proof_refused_before_the_opening`, `key_share_proof_checks`, `key_share_proof_vector` |
| ECtF | mpz2 documents it as semi-honest. Malicious N: limited to input substitution, view simulatable, every effective deviation ends the handshake before B1 (argued above, ROT-hybrid model, HKDF-Extract as a random oracle, strong DH in P-256). Malicious C: 3 outcomes, ≤ log2 3 bits per connection (argued above, by enumeration of this code's error paths; base-OT security assumed) |
| the KOS Δ of the ECtF instance (confidentiality of a recorded connection against N rests on it) | assumed from mpz2, with KOS's selective leakage of a few bits |
| the anchors are public while the same secrets are keys (assumption 4) | assumed (holds with SHA-256 as a random oracle) |
| external review | **none yet** |

## Review as an adversary (2026-11-11)

Done once more when `split-public-1` became the only variant. Nothing was found broken at the time. Each row
names the test that exercises it. Two answers did not hold up (2026-11-22): the row on online labels that N
chooses with the salt known (a label chosen after the challenge lets N adapt pointer bits to it, so its
effect is not limited to an abort), and the soundness of stage A1 (Security model, above). `split-public-3` commits those labels and
fixes N's input before the challenge.

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

`crypto/twopc/BENCH.md` has the tables. Per connection the client uploads 1.13 MB and downloads 16.47 MB
(tables 11.8 MB, check rows 3.9 MB, input-label commitments 82 kB); v2 moved 1.21 MB and 22.1 MB per request.
`split-public-3` adds 82 048 B of payload to the download and 16 B to the upload against `split-public-1`,
and no round trip (64 of these bytes are the key-share proof, added in place on 2026-11-22/23). A cold key schedule takes 7.1 s on a 2/50 Mbit/s link with 80 ms round-trip time (v2:
7.4 s) and 15.7 s with a 10 Mbit/s downlink (v2: 20.1 s). The halved AES count per gate (N 6, C 3, from 12
and 6) shortens the online stages: locally 31 and 25 ms instead of 38 and 30 ms. Each stage after A1 costs one round trip that v2 did not have: from C's side `handshake` takes 3
instead of 1 and `application` 1.5 instead of 1 (N's B1 labels need no message from C).

## Changes from `split-public-1`

`split-public-1` (deployed from 2026-11-12) and `split-public-3` have the same circuit, stages,
ECtF, OT layers, 64-bit rows, label-check pairs and anchors. `split-public-3` changes (all but the last two
rows since `split-public-2`, 2026-11-22):

| | `split-public-1` | `split-public-3` |
|---|---|---|
| garbling hash | mpz2's fixed-key TCCR, 12 AES calls per AND gate for N, 6 for C | `AES_k(Y) ⊕ σ(Y)`, `Y = X ⊕ U(τ)`, N's 32-byte parameters per session, sent before the tables; 6 and 3 AES calls |
| check rows | TCCR with C's salt XORed into the tweak (the salt cancels between two wires) | `lo64(AES_{k_r}(H_g(X, 2^63 \| τ) ⊕ U_r(τ)))`, `k_r`, `U_r` from SHA-256 of C's seed and N's parameters |
| N's circuit input | its share `x_N`, labels sent in the handshake after the challenge | a random mask ρ < p, labels sent before the challenge; the share follows as `δ = x_N − ρ mod p` |
| other input labels (C's share, the digests) | pointer bit checked only | committed before the challenge under C's 16-byte salt, each label checked |
| stage A1 against a prepared N | wrong sum passes with about 2^-23 per connection | within the 2^-60.6 bound (argued) |
| N's key share | `P_N` | `P_N` and a proof of knowledge of `a_N` (added to `split-public-2` in place on 2026-11-22/23) |
| bytes | 16.38 MB down, 1.13 MB up | +82 048 B down, +16 B up, no added round trip |
| tag, offer | `routstr-2pc/split-public-1`, `"split-public-1"` | `routstr-2pc/split-public-3`, `"split-public-3"` (2026-11-22 to 23: `split-public-2`); no two variants interoperate |

## History: v2 and `Proven`

- **v2** (archive branch `v2`, the old `twopc-v2`; `confidential-v2` in routstr-core and routstr-sdk): the whole key schedule in
  two garbled phase circuits, MS crossing between them as XOR shares, a bare report hash, seven outcomes
  (2.8 bits) per request. Deployed until v3 (2026-11-12).
- **`Proven`** (prototype, removed 2026-11-11): `IS_k` to C only, the inner digests and anchors proven in
  zero knowledge. Fewer gates (19 compressions) but a larger upload, a second Ferret under Δ_A, and Δ_A used
  both as garbling offset and as MAC key. It kept the hash assumptions of v2 on C's side.
  `TWOPC-NODE-GARBLING.md` §9 has the numbers.

## Components

- `crypto/twopc`: `lib.rs` (the protocol, `Party`), `gc.rs` (garbling, MAC bookkeeping, check), `circuits.rs`
  (the circuit and the HKDF message blocks), `ectf.rs`, `mux.rs`, and the `cu-2pc` binary (C's side, spawned
  by the clients).
- `crypto/relay`: the sidecar runs N's side (`run_twopc_n`).
- The browser library vendors `crypto/twopc` (`crates/vendor/twopc` there, with `split-public-3`); a change
  to `crypto/twopc` has to be re-vendored.
