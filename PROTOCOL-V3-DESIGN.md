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

- Idle: the node closes a connection `h2.idle_timeout_s` after `head_written` or its last settlement (A.12);
  the sidecar's own limit, `h2.idle_secs`, is a backstop that is never shorter.
  `h2.max_requests` per connection. The existing per-session time limits apply per request.
- GOAWAY from U, or U closing: the session ends; a request in flight settles by the usual abort rules.
- C keeps no armed objects other than connections. A connection opened ahead of need is the same object.
- Fees: the connection deposit (A.12), reserved at the setup and released with the first settled request.

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
design allows them; build chat first); the browser library.

### A.11 Wire format (as implemented)

Prototype on branch `v3-h2`: sidecar (`crypto/relay/src/{h2,h2_session,hpack}.rs`), statement
(`crypto/zkbench/src/statements.rs`, `PiWin`), reference client (`crypto/client/src/{h2,driver-h2}.ts`), gate
`crypto/tools/v3-h2-check.sh`; the node on branch `confidential-v3` of routstr-core
(`routstr/confidential_ws.py`, `_run_h2_session`), gate `crypto/tools/v3-h2-node-check.sh`. This section is
what the SDK needs; where it differs from A.1-A.8 it says so ("differs"). The messages below are the
sidecar's; **"Through a node"** at the end lists what a node adds, strips and changes, and is what a client
of a node implements. All messages are JSON text frames on the session WebSocket (`/session` on the sidecar,
`/v1/confidential/ws` on the node) unless marked binary. Byte strings in JSON are lower-case hex, except inside
`params`, where they are arrays of numbers (as in v2). A v2 session (`setup` without `http`) is unchanged.

#### Offer

Sidecar offer file: optional block `"h2": {"probe_path": "/api/v1/models", "idle_secs": 300, "max_requests": 100}`
(`idle_secs` 10..3600, default 300; `max_requests` 1..1000, default 100; `probe_path` canonical, under 127
bytes; host under 127 bytes; key at most 119 bytes). The sidecar's `/offer` then carries the block unchanged
and `"http": ["1.1", "2"]`; without the block `"http": ["1.1"]`. The node copies both into its signed offer.
The request path is not a new field: it is the path of the offer's `head_template` (`POST <path> HTTP/1.1`).

A node's signed offer adds two fields to the block (A.12; a sidecar's own offer has neither):
`"connection_deposit_msat"` (integer ≥ 0; absent = 0) and `"idle_timeout_s"` (integer, 10..`idle_secs`; absent =
`idle_secs`).

Client checks before a `setup` with `http: 2`: `http` lists `"2"`; the `h2` block is in range; `probe_path` is a
trusted API base plus `/models` (`checkH2Offer`); `connection_deposit_msat` is at most the client's configured
maximum (default 100 000 msat; above it the client opens no connection and uses the v2 flow); the usual v2 offer
checks (host, chat block, head template).

#### Setup

`C → N  {"type":"setup","http":2,"nonce_c":<64 hex>,"armed":<bool>}` plus, towards a node, `auth` and
`offer_sig` (required there, and stripped by the node: "Through a node"; with a direct sidecar
`escrow_e`/`escrow` as in v2). `http` may be the
number 2 or the string `"2"`; absent, `1.1` or `"1.1"` is v2. A setup with `http: 2` that names `kind`, `model`,
`max_tokens`, `len`, `suffix` or `count` is refused.

`N → C  {"type":"ready","sid","nonce_n","pubkey","head_len":170,"armed","v":2,"http":2,"h2":{…block…}}`.
No `suffix`. `sid` is computed as in v2 and names the **connection**; a request is `(sid, n)`.

Then exactly as v2: `/zk?proof=twopc`, `/zk?proof=zkchan` (the client's `cu-prover --channel --multi`), the
ClientHello (ALPN must be exactly `h2`), `hs_verified` (N also requires EncryptedExtensions to select `h2`),
`c_commit` with the π_NK parameters, π_NK, `release_head`, `head_written`.

π_NK parameters are the v2 `PiNK` object; `template` is the connection head of A.3 with zero bytes at the key
positions, `key_offsets` the 42 (key length) consecutive positions, `head_len` its length (170 for Venice).
Head bytes, in order: the 24-byte preface; `00 00 12 04 00 00000000` + `0001 00000000`, `0002 00000000`,
`0004 7fffffff`; `00 00 04 08 00 00000000` + `7fff0000`; `00 00 LL 01 05 00000001` + block
`82 87 01 <len> <host> 04 <len> <probe_path> 57 <7+keylen> "Bearer " <key>`; `00 00 04 03 00 00000001` +
`00000008`. The client rebuilds this from the offer (`h2Head`) and compares every byte.

A client record (binary) between its Finished and `head_written` is refused in an `http: 2` session.

#### After `head_written`: client records

Every binary message after `head_written` is TLS records under `c_ap_1` (sequence numbers from 0). **One HTTP/2
frame per record**: inner plaintext = 9-byte frame header ‖ payload ‖ `0x17`, no padding; at most 2^14 content
bytes, so a DATA payload is at most 16 375 bytes. N classifies each record when it arrives, queues it, and
writes it to the provider only after a π_WIN that covers it verified (and, for a request's record, within
`release`). Records are written in arrival order, which is their sequence order.

- A record is a **control record** iff the text frame right before it was
  `C → N  {"type":"ctl","frame":"settings_ack"|"ping_ack"|"window_update"|"rst_stream"}` (differs: the spec did
  not say how N learns the kind). Inner lengths must be 10, 18, 14, 14. `window_update` is on stream 0;
  `rst_stream` is on the current request's stream and only accepted once that request's records are all
  received. At most 16 unproven control records.
- Any other record belongs to the open request (below): the first must be the HEADERS record (inner length
  9 + block + 1), the rest are DATA records until their payloads sum to `body_len`. Not allowed: an empty DATA
  frame, a last DATA frame shorter than the suffix, more than `3 + body_len/4096` records, any record when no
  request is open or after the request is complete.

#### A request

1. `C → N  {"type":"request","n":k,"kind":"chat","model","max_tokens","body_len"}` (`kind` optional; only chat;
   `suffix` optional and must equal the canonical one). Towards a node it also carries what a v2 setup carries
   for billing: `auth`, `offer_sig`, `session_fee_msat`, `abandon_fee_msat`; **the node reserves here** and
   forwards the request without those four ("Through a node"). `n` must be the previous `n` + 1 (first: 1), at most `max_requests`, and no
   request may be in flight. `body_len` is the sum of the DATA payloads (the JSON body), suffix included.
   `N → C  {"type":"request_ok","sid","n","stream":2k+1,"suffix":<the canonical suffix string>}`.
   The client may send its records without waiting for `request_ok`.
2. Records: `HEADERS` (flags END_HEADERS = 0x04, stream 2k+1) with the block
   `83 87 01 <len> <host> 04 <len> <path> 0f 10 10 "application/json" be`, then DATA frames (flags 0, the last
   one END_STREAM = 0x01 and ending in the suffix).
3. When the request is complete and no π_WIN is in flight, N sends
   `{"type":"zk_params","proof":"pi_win","purpose":"records","first_seq":s,"count":c,"params":{"PiWin":…}}`
   covering **all** unproven queued records (control records included), sequence numbers `s … s+c-1`. While a
   request is open but incomplete N sends none (so a `settings_ack` sent after `request` joins that request's
   proof). With no request open, a control record gets its own `zk_params` at once. The client checks the
   parameters (below) and proves `pi_win` on the proof channel (witness `c_ap_1`).
4. `C → N  {"type":"release","n":k,"upto":u}`: the first `u` records of request `k` (HEADERS is 1) may be written
   once proven. `u` only grows; it may be sent before the proof. The client follows the provider's flow control:
   stream credit = the provider's `INITIAL_WINDOW_SIZE` + WINDOW_UPDATEs on the stream, connection credit = 65 535
   + WINDOW_UPDATEs on stream 0 − DATA bytes of earlier requests.
5. When the last record of the request is written: `N → C  {"type":"body_released","n":k}`. The node treats the
   reservation as at stake from here, as for v2's `body_released`.

π_WIN parameters (`PiWin`): `{"anchor":[32 bytes],"key_updates":0,"windows":[{"seq","off","ct":[…],"sel_start","expected":[…]}]}`
(`off`, `sel_start`, `key_updates` omitted when 0). Plaintext of record `seq` at `[off+sel_start, …)` must equal
`expected`; `ct` is the record's ciphertext `[off, off+|ct|)`, `off` a multiple of 16. For client records
`anchor = h1`. N's windows per record:

| Record | Windows |
|---|---|
| control, HEADERS | whole record if header ‖ `17` is all of it (SETTINGS ACK, HEADERS: the full frame ‖ `17`); else `[0,9)` = the expected frame header, and the last byte = `17` |
| DATA, not last | `[0,9)` = `len 00 00 stream` with `len = inner_len − 10`; last byte = `17` |
| DATA, last | `[0,9)` = the same with flags `01`; the last `|suffix|+1` bytes = suffix ‖ `17` |

Limits: 2 200 windows, 64 KiB of ciphertext, per proof. Client-side check (`checkPiWinParams`): `anchor` is our
`h1`; every window names one of the `count` records, its `ct` is our ciphertext at a block-aligned offset, and
the compared bytes equal our plaintext and lie inside a range that is public for that record (frame header
`[0,9)`; the last byte; the whole HEADERS / SETTINGS-ACK record; the suffix tail). Every record of the batch is
named by at least one window.

Cost: 7 SHA-256 compressions plus one AES block per distinct 16-byte block touched. 308 k correlations for a
300-byte body (23 blocks), 457 k for a 200 kB body in 13 DATA records (46 blocks): about 160 k + 6.4 k per block.

#### Success: disclosure, attestation, settlement

`C → N  {"type":"disclose","n":k,"r":<hex>,"tail_lens":[…],"skip":0,"server_records":m[,"key_updates","epoch_start"]}`

- `server_records` (differs: new, replaces v2's `trailing`): the number of server records of outer type 23 the
  client had received since the connection began (handshake flight included) when it built `R`. If N holds more:
  `N → C  {"type":"disclose_retry","n":k,"server_records":<N's count>}`, nothing else changes, the client
  rebuilds. If N holds fewer: error.
- `tail_lens`: inner lengths (content + 1) of the last records, last first; they must be exactly N's last
  `|tail_lens|` records, all with index ≥ `S_k` (the count of such records when N wrote the request's first
  record). `skip` must be 0 and `trailing` absent. `key_updates`/`epoch_start` as in v2.
- `R` (differs from A.6 in where it starts): a suffix of the server plaintext that starts **either** with the
  9-byte header of a DATA frame on the request's stream (when the usage event begins a frame), **or** with the
  line feed that precedes `data: ` (when the event begins inside a frame; this is v2's rule, and anchors the
  event at a line start). From there text runs to the next `0x00`, which starts a frame header; accepted frames:
  DATA on the stream (flags 0 or END_STREAM), one HEADERS on the stream with flags exactly `05` (trailers),
  SETTINGS / PING / GOAWAY on stream 0, WINDOW_UPDATE on stream 0 or the request's stream. A frame may split the
  text anywhere (differs: A.6 mentions only event boundaries). The stream must end inside `R` (END_STREAM), and
  the DATA payloads together must be exactly `data: <usage JSON>\n\ndata: [DONE]\n\n`, the JSON on one line with
  empty `choices` and integer `usage.prompt_tokens`, `usage.completion_tokens`.

N answers, in this order:

`{"type":"attestation","n":k,"a":{…},"sig":<ed25519 over the serialized a>}` with
`a = {"sid","http":2,"n","stream","s_k","server_records","sha256_recv","client_records","sha256_sent","cert_chain_hash","th_sh","th_sf","c_commit","time"}`:
`server_records` and `sha256_recv` cover the outer-type-23 server records with index in `[s_k, s_k+server_records)`
(each as header ‖ payload); for a usage disclosure that interval ends at the disclosure's `server_records`.
`client_records`/`sha256_sent` cover the request's own records (HEADERS, DATA) written to the provider, not
control records. The node re-signs it as for v2 (`a_json`, `sig_scheme`).

`{"type":"zk_params","proof":"pi_c3s","n":k,"params":{"PiC3S":…}}`: as v2, `skip` 0, record `seq` = index −
handshake records − `epoch_start`. The client checks it as in v2 (`checkPiC3SParams` with `trailing: 0`) and
proves with `s_ap_0`.

Settlement, when the proof verifies: with `--node-settles`
`{"type":"usage","sid","http":2,"n":k,"model":<pinned>,"usage":<the usage event>[,"reported_model"]}` (v2's frame
plus `http` and `n`; the node settles and signs the receipt, which carries `http` and `n`); without it the sidecar's
stub `{"type":"receipt","n":k,"receipt":{"sid","http":2,"n",…,"attestation_hash"},"receipt_json","sig"}`.
The connection is then idle and accepts `request` `k+1`.

#### Error: the response head

`C → N  {"type":"disclose_head","n":k,"record":i,"r":<hex>[,"key_updates","epoch_start"]}`: `r` is exactly one
HEADERS frame on the request's stream with END_HEADERS (END_STREAM allowed; no padding or priority), at most
16 KiB, starting at byte 0 of server record `i` (index as in `server_records`), `i ≥ S_k`, spanning at most 8
records. Its block must decode with an empty dynamic table: static indices 1..61, literals of any kind, a size
update to 0 before the first field; `:status` first, no other pseudo-header, three digits, 400..599.
Allowed as soon as the request's first record was written (differs: not only after `body_released`, because a
refused request may never get the window to release its body), and only when none of the client's records is
unproven.

N answers `attestation` (as above; the interval ends at N's current record count), then
`{"type":"zk_params","proof":"pi_win","purpose":"error_head","n":k,"record":i,"params":{"PiWin":…}}` with
`anchor = h2`, `key_updates`, and per covered record: the frame's bytes from offset 0, and the record's last
byte = `17` (differs: added, so the head cannot be read out of a non-application record). The client checks
that the windows touch only the frame's bytes and those last bytes of its own received records, and proves with
`s_ap_0`. Settlement as above with `usage = {"error_status":<status>,"choices":[]}`; the node applies v2's
error-head rules. Then `{"type":"closed","reason":"error_settled"}` and the socket closes.

#### Lifecycle and failures

- `{"type":"closed","reason":"idle"|"max_requests"|"error_settled"|"upstream_closed"|"connection_lifetime"}`: an
  orderly end with no request in flight. Idle: `h2.idle_secs` after `head_written` or the last settlement.
  Differs: a connection also ends 3 600 s after `head_written` (at its next settlement).
- Time limits per request: 600 s from `request` to `body_released`, 600 s from there to settlement.
- The provider closes: no request in flight → `closed`; a request not fully released →
  `{"type":"upstream_closed_early","n","response_bytes"}` then an error; a released request may still be
  disclosed until its time limit.
- `{"type":"error","reason"}` and a closed socket for everything else, including any failed proof. A request
  in flight then falls under v2's abort rules (before `body_released`: release the reservation; after it, with
  no settlement: charge it).
- Proofs: `pi_win` and `pi_c3s` run once per `zk_params` (on the channel, or `/zk?proof=pi_win|pi_c3s`). The
  channel preallocates as for v2 and extends online when it runs out (about 0.48 MB node → client per
  extension; in steady state about 1 MB per request).

#### Through a node

The client talks to the node's `/v1/confidential/ws?session_id=<uuid>&v=2` and `/v1/confidential/zk` exactly as
for v2 (`zk_token` from `ready`; `/zk?proof=pi_win` is admitted). The node relays every frame not listed here
unchanged, in both directions.

**Offer.** The node's signed offer carries the sidecar's `http` and `h2` unchanged, and only when the sidecar
offers `"2"` with an `h2` block. Without them the offer names neither (read an absent `http` as `["1.1"]`),
so a node on an HTTP/1.1-only sidecar signs what it signed before.

**Setup.** `C → node  {"type":"setup","http":2,"nonce_c","armed","auth","offer_sig"}`.

- `auth` (the `sk-` key or Cashu token) and `offer_sig` are required, as for v2. No request terms and no
  `session_fee_msat`/`abandon_fee_msat` (refused, 400): fees are accepted per request.
- The node checks, before it dials the sidecar: its sidecar offers `http: 2` (else 400); `offer_sig` names an
  offer it signed and still remembers (else 409 `offer_expired`); the credential is valid with an available
  balance of at least `max(1 msat, MIN_REQUEST_MSAT, that offer's session fee, its abandon fee)` (else 401/402
  with the node's usual error body). A Cashu token is redeemed here. Then it **reserves the connection
  deposit** of that offer (A.12) from the credential; a balance that does not cover it is refused with 402,
  `detail.error.type = "connection_deposit_unfunded"` (the node's usual 402 body otherwise, plus
  `connection_deposit_msat`). No request is reserved. A client without funds gets no garbled circuit.
- The sidecar sees `{"type":"setup","http":2,"nonce_c","armed","escrow":"h2-<id>"}`: no credential, no
  offer signature. `escrow` only makes the sid unique (the deposit's reservation id, or a random one when the
  offer asks for no deposit; v2 passes the session's reservation id there).
- `ready` gains `zk_token`, `pubkey` (the node's) and `sig_scheme`, as for v2, and `deposit_msat`: what the
  setup reserved, which the client requires to equal the offer's `connection_deposit_msat`.

**Request.** `C → node  {"type":"request","n":k,"kind":"chat","model","max_tokens","body_len","auth","offer_sig"
[,"session_fee_msat","abandon_fee_msat"][,"suffix"]}`.

- The node validates the shape (`n` = the last forwarded request + 1; `kind` absent or `chat`; `max_tokens` in
  `[1, max_tokens_cap]`; `body_len` in `[1, 8 MiB]`), then does what it does for a v2 setup: the model must be
  one the node serves confidentially (400 otherwise) and priced by the offer `offer_sig` names (409
  `offer_expired`), the fees of that offer must be echoed (409 `session_fee_not_accepted`), the credential is
  validated, and a full-context prompt plus `max_tokens` (plus the larger fee) is reserved at that offer's
  rates (402 when the balance does not cover it).
- `auth` and `offer_sig` are per request. A request may name another credential than the setup or the previous
  request (a fresh Cashu token, another key), and a newer offer. The node remembers a signed offer for 10
  minutes after it last served it, so a client that keeps a connection must refetch and verify
  `/v1/confidential/offer` within that time and use the signature it gets; the connection-level fields of the
  newer offer (`upstream_host`, `head_template`, `chat`, `h2`) must be the ones the connection was opened on,
  or the client opens a new connection.
- The sidecar sees `{"type":"request","n","kind","model","max_tokens","body_len"[,"suffix"]}` only.
- **A request the node refuses ends the connection**: `{"type":"error","status","reason","detail"}` (the fields
  of a refused v2 setup), nothing reserved, socket closed. Reason: the client may send the request's records
  without waiting for `request_ok`, and the sidecar could not place them. Earlier requests stay settled.
- One request at a time: a `request` while one is in flight is refused (409) and ends the connection; the
  request in flight is then finalized by the abort rules.
- Frames the client sends after `request` are forwarded only once the reservation is made, in order.

**Settlement.** The sidecar's `usage` frame is consumed by the node (the client never sees it). The node
re-signs `attestation` as for v2 (`a_json`, `sig`, `sig_scheme`, `sidecar_sig`), settles as v2 does (usage at
the frozen rates plus the session fee; an error head by v2's status rules) and sends

`{"type":"receipt","receipt":{…v2's fields…,"http":2,"n":k},"receipt_json","sig","sig_scheme"}`.

The receipt of the connection's first settled request also carries `"deposit_released_msat": <the deposit>`
(A.12); no other receipt does. `receipt.sid` is the connection's sid, `receipt.n` the request, `attestation_hash` the SHA-256 of that
request's `a_json`. `reserved_msats`, `cost_msats`, `balance_msats`, `rates` and the fee fields are that
request's. The client checks what it checks for v2 plus `http`, `n` and that the attestation's `n`, `stream`
and `s_k` are its own. An `attestation` or `usage` that names another request than the one in flight is
dropped by the node. If the node cannot sign a receipt (no attestation, a failed billing write) it sends an
`error` and ends the connection.

**Aborts** (per request, v2's rules with "session" read as "request"):

| The connection ends… | The request's reservation |
|---|---|
| with no request in flight (idle, `closed`, the client leaves, never used) | nothing is held for a request (the deposit: A.12) |
| before the sidecar's `request_ok` | released in full |
| after `request_ok`, before `body_released` (a failed π_WIN, the client leaves) | released; the abandon fee is kept if the offer has one, except when this is the connection's first request and the deposit is charged for it (A.12: one price for the unused handshake, not two) |
| before `body_released`, the provider answered and closed (`upstream_closed_early` with response bytes) | released; the session fee is kept if the offer has one |
| after `body_released` with no settlement | charged in full |

**Limits.** An `http: 2` connection takes one of the node's session slots (32 per process) for its whole
life. It counts against its address's unused-session limit (`CONFIDENTIAL_MAX_UNUSED_PER_IP`, default 12) from
the setup until its **first `body_released`** (differs from v2, where `head_written` ends it: there a
reservation is held by then, here none is). Time limits: 10 minutes from the websocket accept to
`head_written` (an armed connection included); idle, the offer's `h2.idle_timeout_s` (A.12; the node sends
`closed`, reason `idle`); per request, 10 minutes from `request` to
`body_released` and 10 minutes from there to the settlement, as for v2 (`error` with status 408). Each
request's reservation has its own lease, taken at the `request`.

**Open, by design of the prototype** (see also "Not implemented"):

- With the node's default settings the connection deposit is 0 (it defaults to the abandon fee, which is
  off by default), and an unused connection is then free as before A.12.
- A first request that the node refuses for lack of funds costs the deposit: the refusal ends the
  connection, and the connection carried no request. A client must hold the deposit plus the request's
  reservation when it sends request 1. The `request_refused` frame below would let it top up and retry on
  the same connection.
- The session fee is charged per request, as the v2 code does per session, although the 2PC it pays for now
  happens once per connection. Whether it should move to the connection is undecided.
- The setup's `offer_sig` is checked only for being known. The node does not record which offer a connection
  was opened on, nor compare it with the offers its requests name.
- A refusal that costs the connection (402 on request *k*) makes the client redo the handshake. An
  alternative is a `request_refused` frame that leaves the connection idle, for clients that wait for
  `request_ok` before sending records.

#### Not implemented

Images over `http: 2`; client KeyUpdates; parallel streams; a server KeyUpdate inside or after a disclosed tail
(the disclosure then fails; one before the tail is handled by `key_updates`/`epoch_start` but is untested live);
a session fee per connection instead of per request; the web library.

### A.12 Connection deposit and idle timeout

Opening a connection makes N garble a key schedule (about 22 MB, 0.5 s of CPU) before any request exists. The
setup therefore reserves a deposit, and the node closes connections that sit idle.

**Offer.** The node adds to the signed `h2` block `connection_deposit_msat` (node setting
`CONFIDENTIAL_H2_CONNECTION_DEPOSIT_MSAT`; default: the abandon fee, the price the node already puts on a
handshake nobody used; never below the node's minimum reservation when above 0; 0 = no deposit) and
`idle_timeout_s` (`CONFIDENTIAL_H2_IDLE_TIMEOUT_S`, default 120, at least 10, never above the sidecar's
`idle_secs`). The client knows both before it opens. (`PROTOCOL-V3.md` lists the two at the offer's top level,
because there they apply to both framings; in this prototype only `http: 2` connections have them.)

**Reservation.** The deposit goes through the node's ordinary reservation (`pay_for_request`, a
`ReservationRelease` row with a lease, the calls `release` and `finalize_ehbp_actual_cost_payment`): there is
no second ledger. It is reserved from the setup's credential after the credential check and before the
sidecar is dialed. The setup's `offer_sig` names the offer whose deposit is taken; the setup carries no extra
acceptance field (the client verified that offer). Its lease covers the setup phase, one idle period and a
first request.

**Release.** The deposit is released when the connection's first request reaches a settlement: a usage
disclosure or an error head of any status, i.e. any request the provider answered. That request's receipt
carries `deposit_released_msat`. From then on the connection holds nothing between requests.

**A connection that ends with no settled request.** Exactly one of these rows applies, top to bottom:

| # | How the connection ended | Deposit | `reason` |
|---|---|---|---|
| 1 | the setup was refused before the sidecar was dialed: bad credential, balance below the deposit, unknown offer | never reserved | (the `error`) |
| 2 | no session slot, or the sidecar unreachable, after the deposit was reserved | released | `not_started` |
| 3 | the sidecar refused the setup (no `ready`) | released | `not_started` |
| 4 | the sidecar could not reach the provider (`error` with `"fault":"upstream"`: the TCP connect failed or timed out) | released | `provider_unreachable` |
| 5 | the sidecar failed (`error` with `"fault":"node"`: a panic), or its socket ended without `error` or `closed` while the client was connected | released | `sidecar_failure` |
| 6 | the provider closed the open, idle connection before any request (`closed`, reason `upstream_closed`) | released | `provider_closed` |
| 7 | the node refused the first request with a 5xx (its reservation or its sidecar offer failed) | released | `node_failure` |
| 8 | the first request was settled by the sidecar and the node's billing write failed, or the usage came without an attestation | released | `node_failure` |
| 9 | the first request was written to the provider in full (`body_released`) and never settled | released (the request's reservation is charged in full) | `request_received` |
| 10 | the provider answered the first request and closed before its body was complete (`upstream_closed_early` with response bytes) | released (the request keeps the session fee) | `provider_refused` |
| 11 | the first request was reserved and ended before `body_released` for any other reason: a failed π_WIN, a malformed record, the client leaving, the request's time limit | **charged**; the request's reservation is released in full | `request_abandoned` |
| 12 | the node refused the first request with a 4xx: 402 on its reservation, an expired offer, a model it does not serve, a malformed `request` | **charged** | `request_refused` |
| 13 | no request in flight for `idle_timeout_s` after `head_written` | **charged** | `idle` |
| 14 | `head_written` not reached within 10 minutes of the socket's accept (an armed connection included) | **charged** | `setup_timeout` |
| 15 | anything else with no request: the client left, a failed handshake or π_NK, a protocol error, the provider closing during the handshake | **charged** | `unused` |

Rows 4-8 are "the node, the sidecar or the provider failed before the client could have a request settled".
Row 15 includes failures a client can cause at will (a bad Finished makes the provider close), which is why
a provider closing during the handshake is charged; row 4 is limited to what the client cannot cause. If the
node process dies, the lease lapses and the node's stale-reservation sweeper releases the deposit.

**Telling the client.** Release by a settlement: the signed receipt (`deposit_released_msat`). Otherwise the
connection's last frame carries the outcome, signed with the node's key like a receipt:

```
{"type":"closed"|"error", …the frame's own fields…,
 "deposit":{"sid","msat","outcome":"released"|"charged","reason","cost_msats","balance_msats","time"},
 "deposit_json":<the signed bytes>,"deposit_sig":<hex>,"sig_scheme":"schnorr-secp256k1"}
```

For that, the node holds the sidecar's `error` or `closed` back until the deposit is decided and sends it
last; when the node ends the connection itself the frame is its own (`closed` reason `idle`; `error` 408;
the refusal of a request; `error` 502 "confidential sidecar connection lost"; `closed` reason `ended` when
neither side had a last word). A client that already left learns nothing; row 8 sends its `error` before the
deposit is decided and so reports no outcome (the deposit is released).

**Idle.** The node closes a connection that had no request in flight for `idle_timeout_s`, counted from
`head_written` or from the last settlement: `{"type":"closed","reason":"idle"}` (with `deposit` under row 13).
After its first settled request an idle connection holds no reservation. A client's pool closes its idle
connections earlier (the SDK: 20 s earlier, at most a quarter of the timeout) and never keeps one longer than
the node would. The sidecar's limits are unchanged and fit: its idle limit `h2.idle_secs` (300 s in the
shipped offer) is the ceiling of `idle_timeout_s`, so the node always closes first; before `head_written`
the sidecar allows 600 s like the node. How long the provider keeps an idle HTTP/2 connection was not
measured for this section (the gate idles for 12 s); row 6 covers a provider that closes earlier than the
node, and a client's pool treats a dead connection as a cache miss.

**Checked by** `crypto/tools/v3-h2-node-check.sh` (cases `low-balance`, `open-drop`, `idle-drop`,
`idle-after`, and the deposit's return in every case whose first request settles; balances exact) and the
unit tests `tests/unit/test_confidential_http2.py` in routstr-core (every row).

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
