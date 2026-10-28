# Protocol v2: two-party handshake (closes P1)

Status: implemented on the `twopc-v2` branch (and `confidential-2pc` in routstr-core and routstr-sdk), verified end to end
against api.venice.ai. v1 is retired: the sidecar, the node and the clients speak only v2 (the signed offer
names `v = 2`), and v1 remains on the `v1-poc` branch. Trade-offs and measurements: `docs/V1-V2-ONE-PAGER.md`; component benchmarks:
`crypto/twopc/BENCH.md`, `crypto/zkbench/BENCH-v2.md`.

## Goal

In v1 C runs the TLS handshake alone and knows every traffic secret, so anyone who sees the N→U ciphertext of
the credential record and colludes with C can decrypt the API key (P1 rests on "no egress observer"). In v2,
C and N run the handshake key schedule jointly so that:

| Value | C | N |
|---|---|---|
| ECDHE scalar / shared x-coordinate | additive share only | additive share only |
| HS, derived_hs, MS, c_ap_0 | never | never |
| c_hs, s_hs (handshake traffic secrets) | yes | yes |
| s_ap_0 (server→client, the response) | yes | **never** (P2) |
| c_ap_1 (client body epoch) | yes | **never** (P2) |
| K_0, IV_0 (c_ap_0's AES key/IV) | **never** (P1) | yes |
| h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0) | yes | yes (public anchors for π_C2S/π_C3S) |
| hk = SHA256(K_0 ‖ IV_0) | yes | yes (public anchor for π_NK) |

All of c_hs, s_hs, s_ap_0, c_ap_1, K_0, IV_0 are one-way HKDF-Expand-Label outputs (RFC 8446 §7.1), so knowing
any subset above never yields a secret in the other party's column.

## Epochs (v2)

| Epoch | Key | Writer | Content |
|---|---|---|---|
| Handshake | c_hs / s_hs | C | ClientHello, client Finished (computed by C from c_hs) |
| 0 | c_ap_0 (K_0, IV_0) | **N** | seq 0: the credential record (head with `Authorization`); seq 1: `KeyUpdate(update_not_requested)` |
| 1 | c_ap_1 | C | the JSON body; its final record is the suffix, held by N until π_C2S |
| Response | s_ap_0 | U | streamed response |

C sends nothing in epoch 0. There is no π_C1 and no KU0/KU1 from C.

## Session flow

1. **Setup** as v1 (credential, offer_sig, reservation). `ready` carries `v: 2`.
2. **Preprocessing** (before ClientHello; in pre-warm, off the request path): N garbles both phase circuits
   once and streams the tables to C; N's wire masks are authenticated to C (IT-MACs under C's key) and checked
   (see "Security model"); OT setup for C's inputs; ECtF OLEs. A pre-warmed session stops after step 3 and
   waits for a request; N opens the connection to U only when the ClientHello arrives. In parallel, one proof
   channel per session (`zkchan`) generates the OT/VOLE correlations for π_NK, π_C2S and π_C3S, so the proofs
   on the request path need only a few round trips.
3. **Joint key share (P-256 only).** C commits to `P_C = a_C·G` (SHA-256 of the SEC1 point + 32-byte nonce),
   N sends `P_N = a_N·G`, C opens. Both compute `P = P_C + P_N`. (Commit-first prevents a rogue-key choice
   `P_C = T − P_N`.) Fresh scalars per session.
4. **ClientHello.** C builds it with exactly one key share, group secp256r1, value P; `supported_groups` =
   [secp256r1]; one cipher suite TLS_AES_128_GCM_SHA256; no PSK / early_data. **N parses and enforces all of
   this before relaying** (else C could add its own X25519 share and learn everything). HelloRetryRequest →
   abort. N checks ServerHello: group secp256r1, suite as offered; extracts the server share S.
5. **ECtF.** `Q_C = a_C·S`, `Q_N = a_N·S`. Point-addition share conversion (two A2M + one M2A over P-256, as in
   TLSNotary's key-exchange) gives additive shares `x_C + x_N = x(Q_C + Q_N) mod p`.
6. **Phase A (N garbles, C evaluates; before client Finished, the server allows ~15 s).** Inputs x_C, x_N
   (circuit adds mod p), th_SH, output masks. Computes HS (salt public), keyed HS states, c_hs, s_hs,
   derived_hs, MS. Outputs c_hs, s_hs public; MS leaves as XOR shares (masked with both parties' masks).
   C runs the consistency check before it decodes; N gets its outputs only from C's authenticated report.
7. C decrypts the server flight with s_hs, verifies the certificate (WebPKI), CertificateVerify and server
   Finished, and sends client Finished. N does the same verification with c_hs/s_hs (as in v1 §4.2).
8. **Phase B (N garbles, C evaluates).** Inputs MS shares, th_SF. Computes c_ap_0, s_ap_0, c_ap_1, K_0, IV_0,
   h1, h2, hk. Outputs to C: s_ap_0, c_ap_1 (masked with C's mask); to N: K_0, IV_0 (masked with N's mask);
   public: h1, h2, hk. Same check and report as phase A.
9. **π_NK (N→C):** knowledge of K_0, IV_0 with SHA256(K_0‖IV_0) = hk, and the head record's ciphertext
   CTR-decrypts (seq 0) to the published template with key positions in the alphabet. N holds C's records
   after the client Finished until C has verified π_NK and sent `release_head`; N then writes the
   credential record (seq 0) and the KeyUpdate (seq 1) under K_0 in one write.
10. **Body** under c_ap_1 from seq 0; final record = suffix, held until **π_C2S**: witness c_ap_1,
    public h1; derive K_1, IV_1; decrypt the window; one-bit equality with the suffix.
11. **Response** under s_ap_0; **π_C3S**: witness s_ap_0, public h2; otherwise as v1's π_C3 (records from
    the end, `skip`, one-bit equality).
    The circuits check AES-CTR decryption only, not GCM tags: π_C2S and π_C3S are sound because N takes the
    ciphertexts from its own relay transcript (the body record it holds, the server records it read from U),
    never from C. A tag check would not help, since C holds s_ap_0 and can compute valid server tags itself.
12. Attestation, settlement and receipt as in v1. When U closes the connection, N's relay signs (with a
    per-process Ed25519 key) an attestation binding the sid, the certificate-chain hash, both handshake
    transcript hashes, the record counts (the client's body records and all server records) and the SHA-256 of all bytes in each direction, `c_commit` (a
    hash of the credential record as written) and the time; the node re-signs it with its Nostr key, and
    C checks that signature and that the sid and transcript hashes are its own.

## Security model of the 2PC

Each party must be protected against a malicious peer, and **neither ever reveals its inputs** (unlike
TLSNotary's DEAP or Garble-then-Prove, where one side opens its shares afterwards). Since 2026-10 the garbled
circuits are **node-only authenticated garbling**: only N garbles, C evaluates and checks. It replaces the
earlier dual execution (each side garbled once, outputs compared), which cost the client a 21 MB upload per
session. There is one version; nothing is negotiated.

**Construction** (`crypto/twopc`, `lib.rs` and `gc.rs`):

- *Garbling.* N garbles each phase once with three-halves garbling (Rosulek–Roy, CRYPTO 2021): free XOR with
  a global Δ_A, 1.5κ + 5 bits per AND gate (24.6 B instead of half-gates' 32 B). The hash is mpz2's
  fixed-key-AES TCCR. Every wire's point-and-permute mask is λ_w = lsb of N's zero-label, and C sees only the
  pointer bits Λ_w = z_w ⊕ λ_w.
- *Authenticated masks.* Random COTs with C as sender (Ferret over KOS; C holds Δ_B, a 128-bit key with
  127 random bits) authenticate, by `Fix`, N's mask λ of every circuit input and AND output, and
  t_k = λ_i·λ_j for every AND gate. That is 1.3 M IT-MACs, with M = K ⊕ x·Δ_B over GF(2^128). The other
  wires' masks follow by linearity. N commits all of this and the tables before C sends its challenge seed.
- *Product check.* QuickSilver-style over GF(2^128), batched with χ from C's seed. Error ≤ 2n/2^128.
- *Openings.* Masks of C's input wires, of the transcript-hash wires and of every output wire, with one hash
  of their MACs. C decodes only with authenticated masks.
- *AND-gate consistency check.* For gate k = (i, j → o) the relation is
  e_k = λ_o ⊕ t_k ⊕ Λ_i·λ_j ⊕ Λ_j·λ_i ⊕ Λ_o ⊕ Λ_i·Λ_j = 0. N sends one check row per base wire (circuit
  inputs and AND outputs), each padded by hashes of that wire's two labels, plus Y_N. C combines them with
  its active labels and its MAC keys, and accepts iff π(Y_N ⊕ Y_C ⊕ K_tot) = 0. Rows and Y_N travel
  projected to 64 bits (π = the low 64 bits; all arithmetic stays in GF(2^128)). The row hash is tweaked by a
  per-session salt from C's seed, revealed only after the tables are committed.
- *Output.* C decodes, then sends N the output pointer bits and a hash of its output labels. N recomputes the
  labels from its keys and checks the hash, so C cannot change N's outputs without an inactive label, which
  needs Δ_A. No output is used (sent to U, used to encrypt, or revealed) before these checks pass.

**Malicious N (protects the client's s_ap_0, c_ap_1 and shares):**

- *Correctness.* If any AND gate is evaluated inconsistently with the committed masks, then
  E = Σχ^k·e_k ≠ 0, except with probability n/2^128 over χ (chosen after N committed). C then accepts only
  if π(Δ_B·E) equals a value N fixed without any information on Δ_B. For E ≠ 0 the map Δ ↦ π(Δ·E) is onto
  GF(2)^64, so this has probability ≤ 2^-63 per phase (Δ_B has 127 uniform bits) and N cannot grind: it learns
  nothing about Δ_B, and the first failure ends the session. With all gates consistent, C's outputs are the
  correct function of its input, N's effective input and the real transcript: C's inputs and the transcript
  hash are pinned by pointer checks against opened masks. Soundness is about 2^-62 per session.
- *Why the salt matters for 64-bit rows.* With E = 0, a label that is not N's honest label but has the
  right pointer bit cannot change any output. It only changes the check sum by the difference of two
  truncated hashes. Without a salt, a garbler that reuses its labels across sessions could precompute (about
  2^64 work, once) a table deviation whose 64-bit hash difference is 0. That would leak, without an abort,
  which of two paths C's evaluation took (via the output-label hash). With the salt, everything that fixes
  such a label (tables, Δ_A, N's keys) is committed before the salt is known, so the difference is a fresh
  64-bit value: the check fails except with probability 2^-64. Labels N picks online (its own inputs, the
  transcript hash, the corrections for C's inputs) shift by amounts N already knows, so they carry no
  information about C. The test `check_rows_bound_to_session_salt` covers this.
- *Leakage: selective failure only.* N can make C abort depending on C's private values: corrupted tables,
  rows or OT correlations make the abort a predicate of C's inputs, and since N can corrupt the check row of
  any wire, including internal HKDF wires, also of internal wire values (in phase B these include C's own
  outputs s_ap_0 and c_ap_1). Per phase N observes one of {C aborted, C's output labels rejected, success},
  and the session ends at the first failure. ECtF adds two more observable outcomes: C's degenerate-share
  abort (C's multiplicative share of x2 − x1 is zero) and the server Finished failing between the phases
  after a shifted Z. That is at most seven outcomes, log2 7 ≈ 2.8 bits per session about fresh, single-use
  values (the ECDHE share, the MS share, the masks, the session's traffic secrets), **provided ECtF gives a
  malicious N nothing beyond its outcome** (below). Dual execution leaked log2 3 ≈ 1.6. Removing this leakage needs evaluator-shared masks (WRK17/KRRW18-style triples), which
  cost more than dual execution's bandwidth.

**Malicious C (protects the node's K_0, IV_0 and the API key):** C sees the tables, its active labels and
pointer bits, the opened masks (its own inputs, the public transcript hash, the outputs it decodes anyway),
COT corrections padded by N's choice bits, the product-check pair (masked by a random VOLE), check rows
padded by hashes of inactive labels (which need Δ_A), and Y_N, which C can compute itself. N's private outputs
stay masked by m_N and MS by r_N. C cannot report a wrong output to N. Its own input choice is free, as in
any 2PC. Inconsistent MS shares across phases yield a key nobody knows.

**ECtF**: mpz2's OLE-based A2M/M2A, proven secure against semi-honest parties only. We do not argue that it
stays private against a malicious N (that N's own OLE messages cannot extract more about C's share than an
abort shows); the leakage bound above is conditional on that. Under that assumption a deviation either shifts
the result (wrong ECDHE), which the TLS handshake detects (the server Finished under s_hs fails), or trips C's
degenerate-share check, and N can make either depend on C's share: the two ECtF outcomes counted above. Every session
uses fresh ephemeral scalars, shares, masks, labels, Δ_A and Δ_B.

**What is proven, what is argued, what is assumed:**

| part | status |
|---|---|
| QuickSilver product check, IT-MAC openings | standard (QuickSilver/Wolverine soundness), GF(2^128) |
| three-halves garbling privacy and authenticity | Rosulek–Roy proof, under their hash assumption (instantiated, as in mpz2, with fixed-key-AES TCCR) |
| AND-gate consistency check with garbler-held masks, 64-bit projection, salt | argued above; **no published proof** for this garbler-only variant |
| leakage bound (≤ log2 7 bits per session) | counting argument above, conditional on ECtF (next rows) |
| Ferret/KOS against a malicious receiver (N), KOS consistency-check leakage of a few Δ bits with negligible probability (Δ_B for the MAC COTs, where C is the sender; Δ_A for C's input labels, where C is the KOS receiver and N the sender: harmless, since an inactive label needs all 128 bits) | assumed from mpz2 |
| Ferret/KOS against a malicious sender (N is the RCOT sender for C's proofs π_C2S/π_C3S, so their zero knowledge relies on it; the SPCOT consistency check is in the pinned mpz2) | assumed from mpz2 |
| ECtF | semi-honest only, as before; no argument for a malicious N |
| external review | **none yet** |

**Cost** (`crypto/twopc/BENCH.md`): per session the client uploads 1.21 MB (Ferret) and downloads 22.1 MB
(three-halves tables 16.2 MB, check rows 5.3 MB). A cold 2PC takes 7.4 s on a 2/50 Mbit/s, 80 ms RTT home link,
5.4 s at 7/50, 3.1 s on a 100 Mbit/s symmetric link, and 20 s with a 10 Mbit/s downlink. Dual execution took
85 s, 25 s, 2.3 s and 85 s. The anchors h1, h2 and hk stay SHA-256: the reasons, and a sound zero-AND
replacement (IT-MAC import) for later, are in `docs/TWOPC-NODE-GARBLING.md` §0.

Correctness against the reference key schedule and every deviation listed in the tests (corrupt tables or
control bits, a logic change, a wrong product, a lying output mask, a bad check value, bad or wrongly salted
rows, garbage garbler labels, a wrong OT correlation, a wrong transcript hash, and a cheating evaluator) are
covered by `cargo test --release -p twopc`.

## Residual differences vs v1

- N holds K_0 instead of one-shot material: it can write any number of epoch-0 records, not only one head of
  fixed length. C never saw N's wire bytes in v1 either (residual risk 1); this widens that gap, it does not
  open a new one for C's data (epoch 0 carries no C data).
- P-256 instead of X25519 for the key exchange.

## Components (branch `twopc-v2`)

- `crypto/twopc`: the 2PC crate (ECtF, key-schedule circuits, node-only authenticated garbling with
  three-halves tables and the IT-MAC consistency check) and the `cu-2pc` binary (C side, spawned by the
  client).
- `crypto/zkbench`: v2 statements `PiNK`, `PiC2S`, `PiC3S` (secret-anchored).
- `crypto/relay`: sidecar v2 flow.
- `crypto/client`: TLS fork hooks (external key share and injected secrets) and the v2 driver.
- `routstr-core`: allow the `twopc` channel on the `/zk` proxy; offer `v: 2`.
