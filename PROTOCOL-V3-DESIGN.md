# Protocol v3: design for the feasibility prototype

2026-11-11. Companion to `PROTOCOL-V3-DRAFT.md` (the analysis). This file is the specification the prototype
is built from. Two independent options:

- **Option A (`http: 2`)**: one two-party handshake per HTTP/2 connection; the credential is referenced by
  HPACK index; many sequential requests per connection.
- **Option B (split key schedule)**: the same 2PC outputs with about half the garbled gates. Internal to
  `crypto/twopc`; no wire or API change outside the 2PC channel.

**v2 stays.** A provider without HTTP/2 (or a client that does not ask for it) gets today's flow, byte for
byte. Option A is selected per session by the client, only when the signed offer advertises it.

Naming: C client, N node (sidecar), U upstream. "Record" = TLS 1.3 record. "Frame" = HTTP/2 frame
(9-byte header: 24-bit length, type, flags, 31-bit stream id).

---

## A. HTTP/2 sessions

### A.1 Negotiation

- Sidecar offer file: optional block `h2`:
  `{"probe_path": "/api/v1/models", "idle_secs": 300, "max_requests": 100}`.
  Present ⇒ the sidecar's offer lists `"http": ["1.1", "2"]` and echoes the block. Absent ⇒ `["1.1"]`.
- The node copies `http` and `h2` into its signed offer unchanged.
- Client: `setup.http = 2` selects option A. Missing or `1.1` ⇒ v2, unchanged. A client must refuse to send
  `http: 2` if the verified offer does not list it.
- An `http: 2` setup carries **no** `kind`, `model`, `max_tokens`, `variant`, `count` or body length. Those
  belong to requests (A.5). `armed` keeps its meaning: stop after the joint key share and wait.

### A.2 Handshake differences

- ClientHello: as v2 (one P-256 share = the joint share, one suite, no PSK), plus ALPN with exactly one
  protocol, `h2`. In v2 mode the sidecar's ClientHello check is unchanged.
- N decrypts the server flight with `s_hs` (it already does, to verify the handshake) and requires
  EncryptedExtensions to select `h2`. Otherwise abort before the credential record.
- 2PC, ECtF, anchors, π_NK: unchanged.

### A.3 Epoch 0: the connection head (written by N)

One record (seq 0) with exactly these bytes, then the KeyUpdate (seq 1), in one write, on `release_head`
as in v2:

```
"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"                       24 bytes
SETTINGS (stream 0):  HEADER_TABLE_SIZE (0x1) = 0
                      ENABLE_PUSH       (0x2) = 0
                      INITIAL_WINDOW_SIZE (0x4) = 2^31-1
WINDOW_UPDATE (stream 0): increment 2^31-1-65535
HEADERS (stream 1, END_STREAM|END_HEADERS), header block, no Huffman:
    0x82                         :method GET            (static 2)
    0x87                         :scheme https          (static 7)
    0x01 len <host>              :authority, literal without indexing
    0x04 len <probe_path>        :path, literal without indexing
    0x57 len "Bearer " <KEY>     authorization, literal WITH incremental indexing (static name 23)
RST_STREAM (stream 1, CANCEL)
```

- After this block the client→server dynamic table holds exactly one entry, `authorization: Bearer <KEY>`,
  at index 62. Nothing C is allowed to send adds an entry, so the index never moves.
- The head has a fixed length (no `Content-Length` digits). The key bytes are at fixed offsets, so π_NK
  works unchanged with this template. The client rebuilds the template from the offer (host, `probe_path`,
  key length) and checks every byte of it, as it does for the v2 head.
- `HEADER_TABLE_SIZE = 0` tells U's encoder not to use a dynamic table for **response** headers. Every
  response header block is then decodable on its own (static table + literals, Huffman allowed), which A.7
  needs.
- `ENABLE_PUSH = 0`: no PUSH_PROMISE (which would carry server-chosen request headers).
- The probe stream is reset at once. U may still send a HEADERS/DATA for stream 1; C ignores them.

Verified live (Venice, 2026-11-11): after exactly this flight, a request with `authorization` by index only
returns 200.

### A.4 What C may write (epoch 1 onwards)

Rules, enforced by N for **every** record C sends after the handshake:

1. One frame per record. Inner content type 0x17, no TLS padding.
2. N forwards a record to U only after a proof that covers it has verified.
3. For each record the proof shows: bytes `[0, 9)` equal the frame header N expects, and the last byte of
   the inner plaintext is 0x17. The frame header's length field must equal `inner_len - 1 - 9`, where
   `inner_len` is the record's ciphertext length minus the 16-byte tag. (Without the last-byte check, TLS
   padding would let C shift the frame boundary and hide a HEADERS frame in a later payload.)
4. Allowed frames:

| Frame | Stream | Proven | Notes |
|---|---|---|---|
| SETTINGS, ACK flag, length 0 | 0 | whole record | answer to U's SETTINGS |
| PING, ACK flag, length 8 | 0 | header + type byte | payload free |
| WINDOW_UPDATE, length 4 | 0 | header + type byte | rarely needed (windows are 2^31-1) |
| RST_STREAM, length 4 | current request's | header + type byte | cancel |
| HEADERS, END_HEADERS | request stream | **whole record** equals the public block (A.5) | |
| DATA | request stream | header + type byte; the last one also the suffix | END_STREAM only on the last |

Anything else: N closes the session.

**π_WIN** (new statement, `pi_win`): witness one 32-byte traffic secret; public: `anchor = SHA256(secret)`,
`key_updates`, and a list of windows `{seq, off, ct, sel_start, expected}` (a block-aligned ciphertext slice
of record `seq`, and the bytes its plaintext must equal from `sel_start`). All windows are compared in one
equality; the verifier decodes the anchor and one bit. It is π_C2S with several windows; it does CTR
decryption only, and N takes every `ct` from its own relay buffer. With `c_ap_1` it proves C's records
(anchor `h1`); with `s_ap_0` it proves response heads (anchor `h2`, A.7). Limits: at most 2 200 windows and
64 KiB of ciphertext per proof.

### A.5 A request

Requests are sequential. Request *k* (k = 1, 2, …) uses stream `2k + 1`.

1. C → N `request {n: k, kind, model, max_tokens | variant+count, body_len, auth, offer_sig, …}`: the fields
   v2's setup carries. N (the node) validates, freezes the offer rates and reserves, exactly as for a v2
   setup. The sidecar validates as in `handle_setup` and renders/accepts the suffix as today.
2. C sends the request's records over the relay: HEADERS, then DATA records. N buffers them (cap: the
   declared body plus framing).
   HEADERS block (public, C and N build the same bytes from the offer):
   ```
   0x83                    :method POST   (static 3)
   0x87                    :scheme https
   0x01 len <host>         :authority, literal without indexing
   0x04 len <path>         :path = the offer's chat or images route, literal without indexing
   0x0f 0x10 len "application/json"    content-type (static name 31), literal without indexing
   0xbe                    authorization: indexed, dynamic index 62
   ```
   The body is the same JSON as v2 (private part, then the canonical suffix as the tail of the last DATA
   frame). There is no `Content-Length`, so no padding to a pre-declared length.
3. One π_WIN over all of the request's records: the HEADERS record in full, every DATA record's header and
   type byte, and the last record's tail = suffix ‖ 0x17.
4. N releases the records to U. Flow control: U's initial stream window is U's setting, which only C can
   read. C sends `release {upto}` as the window allows; N never releases an unproven record and never
   releases beyond `upto`. (First version: C may simply release everything when the body fits U's
   announced window, and otherwise step with U's WINDOW_UPDATEs.)
5. The response streams back to C. C handles U's control frames (SETTINGS → ACK, PING → ACK) with records
   proven per rule 4; these may be interleaved at any time.
6. Disclosure and settlement (A.6, A.7), then the session is idle again and accepts request *k+1*.

N records, when it writes the first record of request *k* to U, the index `S_k` of the next server record
it will receive. Server records with index ≥ `S_k` are the request's **interval**. It ends when the
disclosure is verified.

### A.6 Success: the usage disclosure

- C sends `disclose` with `R` = the plaintext from the first byte of the usage event (`data: {…"usage"…}`)
  to the **last server byte N has received**. `skip = 0`. π_C3S as today (tail records under `s_ap_0`),
  restricted to records with index ≥ `S_k`.
- N parses `R` with this grammar: SSE text and frames alternate. After an event's blank line, the next
  byte is either `d` (more text in the same DATA frame) or the start of a frame header (its first byte is
  0x00 for any frame under 64 KiB; never valid in SSE text). Accepted frames: DATA on the request's stream
  (payload continues the text), and control frames on stream 0 (SETTINGS, PING, WINDOW_UPDATE, GOAWAY).
  Required: exactly one usage event (validated as today), `data: [DONE]`, and a DATA or HEADERS frame on the
  request's stream with END_STREAM. Nothing else on any other stream.
- Why this binds the usage to the request: the event lies in the interval (after `S_k`), an earlier
  request's event lies before it; the END_STREAM frame names the stream; and text the client controls
  cannot contain a raw blank line or a 0x00 byte (JSON string escaping), the same argument v2 uses for its
  event framing.
- If more server bytes arrive between C building `R` and N checking it, N answers `disclose_retry` and C
  rebuilds.
- Settlement, receipt: as v2, per request. The attestation is per request: sid, `n`, stream id, `S_k`, the
  interval's record count and SHA-256, the request's record count and SHA-256, plus the connection-level
  fields (certificate-chain hash, transcript hashes, `c_commit`).

### A.7 Errors: the response head

- For a status ≥ 400, C sends `disclose_head` naming a server record index `i ≥ S_k` and `R` = one complete
  HEADERS frame (stream = the request's, END_HEADERS) that starts at byte 0 of record `i`.
- π_WIN under `s_ap_0` (anchor `h2`): record `i` (and following records if the frame spans them) decrypts
  to `R` from offset 0.
- N decodes the header block without any dynamic table (A.3 set the table size to 0; a block that uses a
  dynamic index or resizes the table above 0 is refused), requires `:status ≥ 400`, and settles as v2 does
  for an error head. The error body stays private.
- Same residual risk as v2's risk 13, and somewhat smaller: a fabricated head would need the bytes of a
  binary frame header at the start of a server record inside a response body.
- Prototype rule: after an error, an abort or any proof failure the connection is closed. Only a settled
  2xx request leaves it open.

### A.8 Limits and lifecycle

- Idle: the sidecar closes a connection `h2.idle_secs` after its last settlement (or after `connected`).
  `h2.max_requests` per connection. The existing per-session time limits apply per request.
- GOAWAY from U, or U closing: the session ends; a request in flight settles by the usual abort rules.
- C keeps no armed objects other than connections. A connection opened ahead of need is the same object.
- Fees: none new in the prototype. (Later: the abandon fee becomes a per-connection deposit.)

### A.9 Why the credential cannot be read back (answer to "is it echoed?")

- An HPACK entry is a (name, value) **pair**. There are two ways to use one: the *indexed* form emits the
  whole pair, and the *name reference* form reuses only the **name** with a new literal value. No encoding
  reuses a stored value under a different name, so C cannot turn the stored value into some other header
  that a server might echo.
- The table is **per direction**. The request table lives in U's decoder and is written only by request
  header blocks. U's responses are encoded with a separate table that U fills from its own response
  headers. A response can never point into the request table.
- HPACK matches whole fields only (it was designed after CRIME): there is no partial-match or length oracle
  on the value.
- So the only way the value comes back is U's application copying the request header into a response.
  That is profile item 8, the same condition as on HTTP/1.1. Checked live over HTTP/2 with the credential
  sent by index only: a 200 GET, a 404 path, malformed JSON (400), an unknown model (404), an unknown field
  (400), a wrong method, a CORS preflight naming `authorization`, and a chat completion asking the model to
  print it. Decoded response headers and bodies contained no part of the key.
- C's own header blocks are pinned in full by π_WIN, so C cannot pick a path or method (TRACE, a debug
  route) that reflects.
- Server push is disabled by N's SETTINGS; C verifies that through the π_NK template.

### A.10 Out of scope for the prototype

Parallel streams on one connection; client KeyUpdates after epoch 0; image requests over `http: 2` (the
design allows them; build chat first); connection deposits; the browser library.

---

## B. Split key schedule

Goal: the same `twopc::Party` API and the same outputs (`c_hs`, `s_hs` to both; `s_ap_0`, `c_ap_1` to C;
`K_0`, `IV_0` to N; public `h1`, `h2`, `hk`), with fewer garbled AND gates. Nothing outside `crypto/twopc`
changes (the web library re-vendors later).

### B.1 Idea

`HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))` with `f` the SHA-256 compression function, `IS_k = f(IV, k ⊕ ipad)`,
`OS_k = f(IV, k ⊕ opad)`. Every HKDF message in the schedule is public (labels and transcript hashes).

- The garbled circuit computes only what nobody may know: the states `IS_k`, `OS_k` and the outer
  compressions.
- `IS_k` is revealed **to C**. C computes each inner digest `d = f(IS_k, m)` locally, and **proves it in
  zero knowledge** to N. The digest then enters the next garbled stage as C's input.
- The proof system is the IT-MAC/QuickSilver machinery `twopc` already has (`gc.rs`: `dvzk_*`,
  `propagate_*`), not mpz's VM:
  - With free XOR, C's active label of a wire is `k_w ⊕ z·Δ_A`: an IT-MAC on the value `z` under N's key.
    C's output wires for `IS_k` are therefore already commitments of C towards N. No extra message.
  - C evaluates `f` on committed bits. XOR is free. Each AND needs one fresh committed bit: a random COT
    under Δ_A (N sender, C receiver; the kind that already covers C's input bits) plus one correction bit,
    and one QuickSilver product check over all ANDs of the stage.
  - The proven digest bits are again values `d` with MACs `K_d ⊕ d·Δ_A`. N turns them into the garbled
    circuit's input labels with the usual correction `k_w ⊕ K_d` per bit. C's input to the next stage is
    thereby **bound** to the proven digest; C cannot substitute another one.
- The anchors `h1 = SHA256(c_ap_1)`, `h2 = SHA256(s_ap_0)` are proven the same way by C (its output labels
  are the commitment), and `hk = SHA256(K_0 ‖ IV_0)` by N towards C under Δ_B (N's authenticated masks plus
  the public pointer bits are an IT-MAC on N's outputs; N's ANDs use the MAC COTs where C is the sender).
  The anchors stay public values with the same meaning, so `zkbench`, the sidecar and the clients do not
  change.

Why the proofs are not optional: without them C could input the inner digest of a different label. For
example `d_s := d_c` in phase B would make C's `s_ap_0` output equal `c_ap_0`, from which `K_0` follows.

### B.2 Stages (conservative variant, build this first)

All outer compressions stay garbled; only inner digests and anchors move to ZK.

| Stage | Garbled | Revealed / input |
|---|---|---|
| A1 | `Z = x_C + x_N mod p`; `HS = HMAC(salt, Z)` (2; the salt's states are public constants); `IS_HS`, `OS_HS` (2) | `IS_HS` → C |
| — | C proves `d_c`, `d_s`, `d_der` = `f(IS_HS, label(…, th_SH))` | |
| A2 | `c_hs = f(OS_HS, d_c)`, `s_hs = f(OS_HS, d_s)`, `dHS = f(OS_HS, d_der)` (3); `IS_dHS`, `OS_dHS` (2) | `c_hs`, `s_hs` public; `IS_dHS` → C |
| — | C proves `d_0 = f(IS_dHS, 0^32)` | |
| A3 | `MS = f(OS_dHS, d_0)` (1); `IS_MS`, `OS_MS` (2) | `IS_MS` → C |
| — | handshake completes; `th_SF` known; C proves `d_c0`, `d_s0` | |
| B1 | `c_ap_0 = f(OS_MS, d_c0)`, `s_ap_0 = f(OS_MS, d_s0)` (2); `IS_c0`, `OS_c0` (2) | `s_ap_0`, `IS_c0` → C |
| — | C proves `d_key`, `d_iv`, `d_upd` | |
| B2 | `K_0`, `IV_0`, `c_ap_1` = `f(OS_c0, ·)` (3) | `K_0`, `IV_0` → N; `c_ap_1` → C |
| — | C proves `h1`, `h2`; N proves `hk` | |

Garbled compressions: 4 + 5 + 3 + 4 + 3 = **19** (v2: 31). Expected download about 13.5 MB instead of 22.1.

A1-A3 can be one garbled circuit evaluated in steps (internal wires such as `OS_HS` simply continue), or
separate circuits with the crossing state as masked shares, as `MS` crosses today. Prefer whichever fits
`gc.rs` with the consistency check intact: **every stage's AND gates must be covered by the existing
check before any of its outputs is used**, as now.

### B.3 Aggressive variant (second, if the first works)

Where an HMAC output belongs to N or is public, reveal `OS_k` to N and let N compute the outer compression
locally: `c_hs`, `s_hs` (N proves them to C under Δ_B) and `K_0`, `IV_0` (C sends N the proven `d_key`,
`d_iv` in the clear). Garbled: A 8, B 7 = **15**, about 10.7 MB. Extra conditions: C never sends N an inner
digest whose output is not N's or public (`d_der`, `d_0`, `d_c0`, `d_s0`, `d_upd` stay committed, never
opened), and the security argument needs `f(·, x)` keyed by its chaining input to be a PRF with half the
HMAC state known to each side.

### B.4 Security notes to keep

- A stage's outputs are used only after its consistency check passed (unchanged rule).
- The transcript hashes no longer enter the garbled circuit; they enter the proven digests as public
  message bytes. N checks the proofs against the `th_SH`, `th_SF` it computed itself from the relayed
  handshake. Both parties must use the same value or the proof fails.
- Selective failure: each additional point where C's abort or N's rejection is observable adds an outcome.
  Count them in the write-up; the invariant (fresh, single-use values) is unchanged.
- Malicious C in the digest proofs: QuickSilver soundness, N verifies. Malicious N in the digest proofs: N
  is the verifier and learns nothing but accept/reject (zero knowledge from the random COT masks); a wrong
  correction makes C's next-stage label invalid, which the consistency check turns into an abort (a
  selective-failure outcome, to be counted).
- All of this needs the same external review as the v2 garbling. The prototype answers "how much does it
  save and does it interoperate", not "is it proven".

### B.5 Deliverables

- `circuit_stats()` and `BENCH.md`-style numbers: AND gates, bytes each way, cold time on the same emulated
  links as `crypto/twopc/BENCH.md`.
- `cargo test --release -p twopc` green, including: outputs equal the reference key schedule; a C that
  proves a digest for the wrong label is rejected; a C that feeds a different digest than it proved is
  rejected; every existing cheating test still passes.
- A live v2 session (driver against the sidecar and Venice) with the new `cu-2pc` on both sides.
