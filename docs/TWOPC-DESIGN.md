# Protocol v2: two-party handshake (closes P1)

Status: implemented on the `twopc-v2` branch (and `confidential-2pc` in routstr-core and routstr-sdk), verified end to end
against api.venice.ai. v1 (paper §4) stays as is; a sidecar runs one version (`--protocol 2`) and clients take it from
the signed offer's `v`. Trade-offs and measurements: `docs/V1-V2-ONE-PAGER.md`; component benchmarks:
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
| h1 = SHA256(c_ap_1), h2 = SHA256(s_ap_0) | yes | yes (public anchors for π_C2/π_C3) |
| hk = SHA256(K_0 ‖ IV_0) | yes | yes (public anchor for π_N) |

All of c_hs, s_hs, s_ap_0, c_ap_1, K_0, IV_0 are one-way HKDF-Expand-Label outputs (RFC 8446 §7.1), so knowing
any subset above never yields a secret in the other party's column.

## Epochs (v2)

| Epoch | Key | Writer | Content |
|---|---|---|---|
| Handshake | c_hs / s_hs | C | ClientHello, client Finished (computed by C from c_hs) |
| 0 | c_ap_0 (K_0, IV_0) | **N** | seq 0: the credential record (head with `Authorization`); seq 1: `KeyUpdate(update_not_requested)` |
| 1 | c_ap_1 | C | the JSON body; its final record is the suffix, held by N until π_C2 |
| Response | s_ap_0 | U | streamed response |

C sends nothing in epoch 0. There is no π_C1 and no KU0/KU1 from C.

## Session flow

1. **Setup** as v1 (credential, offer_sig, reservation). `ready` carries `v: 2`.
2. **Preprocessing** (before ClientHello; in pre-warm, off the request path): OT setup, both garbled circuits
   for both phases generated and transferred (dual execution).
3. **Joint key share (P-256 only).** C commits to `P_C = a_C·G` (SHA-256 of the SEC1 point + 32-byte nonce),
   N sends `P_N = a_N·G`, C opens. Both compute `P = P_C + P_N`. (Commit-first prevents a rogue-key choice
   `P_C = T − P_N`.) Fresh scalars per session.
4. **ClientHello.** C builds it with exactly one key share, group secp256r1, value P; `supported_groups` =
   [secp256r1]; one cipher suite TLS_AES_128_GCM_SHA256; no PSK / early_data. **N parses and enforces all of
   this before relaying** (else C could add its own X25519 share and learn everything). HelloRetryRequest →
   abort. N checks ServerHello: group secp256r1, suite as offered; extracts the server share S.
5. **ECtF.** `Q_C = a_C·S`, `Q_N = a_N·S`. Point-addition share conversion (two A2M + one M2A over P-256, as in
   TLSNotary's key-exchange) gives additive shares `x_C + x_N = x(Q_C + Q_N) mod p`.
6. **Phase A (dual execution GC; before client Finished, the server allows ~15 s).** Inputs x_C, x_N
   (circuit adds mod p), th_SH, output masks. Computes HS (salt public), keyed HS states, c_hs, s_hs,
   derived_hs, MS. Outputs c_hs, s_hs public; MS leaves as XOR shares (masked with both parties' masks).
   Equality check before either party uses an output.
7. C decrypts the server flight with s_hs, verifies the certificate (WebPKI), CertificateVerify and server
   Finished, and sends client Finished. N does the same verification with c_hs/s_hs (as in v1 §4.2).
8. **Phase B (dual execution GC).** Inputs MS shares, th_SF. Computes c_ap_0, s_ap_0, c_ap_1, K_0, IV_0, h1, h2,
   hk. Outputs to C: s_ap_0, c_ap_1 (masked with C's mask); to N: K_0, IV_0 (masked with N's mask); public:
   h1, h2, hk. Equality check.
9. **π_N (N→C):** knowledge of K_0, IV_0 with SHA256(K_0‖IV_0) = hk, and the head record's ciphertext
   CTR-decrypts (seq 0) to the published template with key positions in the alphabet. N then writes the
   credential record (seq 0) and the KeyUpdate (seq 1) under K_0 after C's Finished.
10. **Body** under c_ap_1 from seq 0; final record = suffix, held until **π_C2**: witness c_ap_1,
    public h1; derive K_1, IV_1; decrypt the window; one-bit equality with the suffix.
11. **Response** under s_ap_0; **π_C3**: witness s_ap_0, public h2; otherwise as v1 (records from the end,
    `skip`, one-bit equality).
12. Settlement, receipt: unchanged.

## Security model of the 2PC

Each party must be protected against a malicious peer, and **neither ever reveals its inputs** (unlike
TLSNotary's DEAP or Garble-then-Prove, where one side opens its shares afterwards).

- **Garbled circuits: dual execution** (Mohassel–Franklin 2006; Huang–Katz–Evans 2012) on mpz2's semi-honest
  half-gates garbler. Each phase is garbled twice: run 1 N garbles / C evaluates, run 2 C garbles / N
  evaluates. Private outputs are XOR-masked with the owner's random mask input, so each evaluator learns
  only masked vectors. **Equality check on output labels** (HKE12): C computes
  `s_C = H(A_i^{v1_i} ‖ B_i^{v1_i})_i` (A = labels of N's circuit it evaluated, B = its own labels for the
  value it decoded), N computes `s_N = H(A_i^{v2_i} ‖ B_i^{v2_i})_i`; compare by commit-then-open. A cheating
  party learns at most one bit (whether the check passed) and the session aborts. No output is used (sent to U,
  used to encrypt, or revealed) before the check passes.
- **ECtF**: semi-honest M2A/A2M over OLE/OT. A deviation only shifts the result (wrong ECDHE), which the TLS
  handshake itself detects (server Finished under s_hs fails), or a selective failure of ≤ 1 bit. Every
  session uses fresh ephemeral scalars, so per-session leakage of a bit or two of a one-time share is harmless.
- **Phase consistency**: a party feeding different shares/masks across phases or runs gets an abort
  (mismatch) or a key unknown to everyone (rejected by U); it never gets a key it can read.

## Residual differences vs v1

- N holds K_0 instead of one-shot material: it can write any number of epoch-0 records, not only one head of
  fixed length. C never saw N's wire bytes in v1 either (residual risk 1); this widens that gap, it does not
  open a new one for C's data (epoch 0 carries no C data).
- P-256 instead of X25519 for the key exchange.

## Components (branch `twopc-v2`)

- `crypto/twopc`: the 2PC crate (ECtF, dual-execution key-schedule circuits, equality check) and the
  `cu-2pc` binary (C side, spawned by the client).
- `crypto/zkbench`: v2 statements `PiNK`, `PiC2S`, `PiC3S` (secret-anchored).
- `crypto/relay`: sidecar v2 flow.
- `crypto/client`: TLS fork hooks (external key share and injected secrets) and the v2 driver.
- `routstr-core`: allow the `twopc` channel on the `/zk` proxy; offer `v: 2`.
