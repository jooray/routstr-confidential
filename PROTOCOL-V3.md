# routstr-confidential protocol v3

2026-11-11. Normative specification. It replaces protocol v2. `PROTOCOL-V3-DRAFT.md` has the reasoning. §12
is the complete wire format; the list at the end names what changed from the 2026-11-11 draft.

Words: C = client, N = node (the routstr node and its sidecar; "node" and "sidecar" where the difference
matters), U = the upstream provider. "Record" = TLS 1.3 record. "Frame" = HTTP/2 frame. MUST/SHOULD/MAY as in
RFC 2119.

## 1. What changes from v2, in one page

| | v2 | v3 |
|---|---|---|
| Unit | a session = one request | a **connection** that carries **requests** `(sid, n)` |
| HTTP to the provider | HTTP/1.1 | **framing** `"2"` (HTTP/2, many sequential requests) or `"1.1"` (one request), chosen per connection from the offer |
| Two-party key schedule | 31 garbled SHA-256 compressions, 22.1 MB down | split key schedule, public inner states: 22 compressions, 16.4 MB down |
| Proof that C's records are what they must be | π_C2S (one record) | **π_WIN** (any number of windows, any number of records) |
| Held at the setup | a full-context reservation | a **connection deposit** |
| Reservation | per session, at the setup | per request, at the `request` |
| Pre-warm object | a session bound to model, `max_tokens`, body length | a connection bound to the credential only |
| Version | `v = 2` | `v = 3`; a v3 node refuses v2, a v3 client refuses a v2-only node, both with an explicit upgrade error (§11) |

What does **not** change: the trust model and the confidentiality guarantees of the paper's §2 (P1, the key
stays from C; P2, prompt and response stay from N; the binding of model, caps and usage), under the extra
assumptions and with the residual risks of §4 and §10; the roles (C is the TLS
client of U, N relays records and writes the credential in epoch 0); ECtF and the joint P-256 share; the
node-only authenticated garbling construction; π_NK and π_C3S; the chat suffix and its offer block
(`docs/CHAT-SUFFIX.md`); image rules (`docs/CONFIDENTIAL-IMAGES.md`); the attestation and receipt signatures;
the usage-based settlement and the abort rules, read per request.

What **does** change for privacy beyond confidentiality (§9.1, §10): requests on one framing-`"2"`
connection are linkable for the provider, its CDN and network observers; the connection's traffic secrets
protect up to `h2.max_requests` requests; receipts and attestations of one connection are linkable to each
other; and the body length is exact unless the client pads (§9.3). A user who does not want connection
linkage turns reuse or HTTP/2 off (§9.1).

The three legs, to avoid confusion about "HTTP versions":

```
app ──HTTP/1.1, OpenAI API──► routstrd ──WebSocket──► node ──► sidecar ──TCP──► provider
                                 └────────── TLS 1.3, framing "2" or "1.1" ─────────────┘
```

The local API of routstrd does not change. The framing is a property of the inner TLS connection to the
provider only. An application never sees it.

## 2. Offer and negotiation

### 2.1 Sidecar offer file (the operator's switch)

The operator states what their upstream supports. Nothing is probed or assumed.

```json
"http": ["2", "1.1"],
"h2": {"probe_path": "/api/v1/models", "max_requests": 100, "max_lifetime_s": 3600}
```

- `http`: the framings this sidecar serves for this upstream, **in the operator's order of preference**.
  At least one. `"2"` requires the `h2` block. Default when absent: `["1.1"]`.
- `h2.probe_path`: a cheap authenticated GET path of the provider (§5.2). `max_requests` 1..1000 (default
  100). `max_lifetime_s` 60..86400 (default 3600). `idle_secs` 10..3600 (default 300): the sidecar's own
  idle limit and the ceiling of the node's `idle_timeout_s`; an operator sets it no longer than the idle
  time `provider-profile-check.py --h2` passed H5 with (the shipped Venice file: 300). `kinds`: §12.1.
- The sidecar stops offering `"2"` after 5 consecutive HTTP/2 connections failed to open, logs it, and
  offers it again after 10 minutes. The withdrawal is for every client, so a failed open is only what no
  client can cause. It is one of: the provider closed without sending a byte in answer to the ClientHello
  (which is canonical, §12.5, so its bytes are the offer's up to three opaque values); a verified
  handshake did not select `h2`; the provider closed within 10 s of the connection head, with no response
  to a request yet, no client record written to it since the head, and the head written within 15 s of
  the dial (a client that delays `release_head`, or whose own record made the provider close, is not
  counted). (N cannot see a GOAWAY: it is encrypted. It sees the close that follows.) A response to the
  connection's first request resets the count. A provider that fails only once a request's records
  arrive is not detected here (the body is the client's): the profile check and the client's fallback
  (§2.3) cover it. While withdrawn, a `setup` for `"2"` is refused with `code: "h2_withdrawn"` and
  `GET /offer` lists `"2"` no longer.
- `crypto/tools/provider-profile-check.py --h2` checks what framing `"2"` needs from a provider (§5.6) and
  is what an operator runs before adding `"2"`.

### 2.2 Node offer (signed)

`GET /v1/confidential/offer` returns the signed offer with:

- `v: 3` (exactly; no list).
- `http`, `h2`: copied from the sidecar.
- `twopc: "split-public-1"`: the key-schedule protocol (§4).
- `connection_deposit_msat`, `idle_timeout_s` (§8).
- everything v2's offer has: `upstream_host`, `head_template` (framing `"1.1"`), `chat`, `images`,
  `price_list`, `session_fee_msat`, `abandon_fee_msat`, `max_tokens_cap`, …

### 2.3 Client choice

1. C verifies the offer as in v2, plus: `v == 3`, `twopc` is one it implements, `http` is a non-empty list
   of known values, the `h2` block is in range and `probe_path` is a trusted API base plus `/models`,
   `connection_deposit_msat` is at most the client's configured maximum.
2. C takes the first entry of `http` that it supports and has not marked bad for this node.
3. **Fallback.** If a connection with framing `"2"` fails before the body of its first request was released
   (handshake, ALPN, connection head, the provider closing), C marks `("2", node)` bad for 10 minutes and
   serves the request on `"1.1"` on the same node, when the offer lists it. After a body was released the
   v2 rule holds: no retry elsewhere.
4. A client MAY be configured to use only one framing (`confidential.http: "2" | "1.1" | "auto"`, default
   `auto`).

## 3. Connection lifecycle

One state machine for both framings. Messages are JSON text frames on `/v1/confidential/ws?session_id=<uuid>&v=3`;
TLS records are binary frames; proofs run on `/v1/confidential/zk` (the pre-warmed proof channel, or one
socket per proof).

```
          setup                2PC preprocessing, key share
 C ──────────────► N   OPENED ─────────────────────────────► ARMED
                                                               │ ClientHello (framing "1.1": after request 1)
                                                               ▼
                         HANDSHAKE ── joint key schedule, N verifies the handshake ──► π_NK, release_head
                                                                                              │ head_written
                                                                                              ▼
            ┌──────────────────────────────────────────────────────────────────────────── READY
            │ request n            records, π_WIN, release        response      disclose / accept / disclose_head
            └─► REQUEST(n) ───────────────────────────────► RELEASED ─────────► settlement, receipt ──► READY | CLOSED
```

| State | Framing `"2"` | Framing `"1.1"` |
|---|---|---|
| ARMED | waits for the ClientHello | waits for `request` 1, then the ClientHello |
| connection head (epoch 0, written by N) | preface, SETTINGS, WINDOW_UPDATE, the probe request with the credential, RST_STREAM (§5.2) | the request head of request 1 with the credential (§6.1) |
| READY after `head_written` | accepts `request` *k* | request 1 is already open; its records follow |
| after a settled 2xx | READY | CLOSED |
| requests per connection | up to `h2.max_requests`, sequential | exactly 1 |

Why the order differs in one place: an HTTP/1.1 head names the path and `Content-Length`, so it belongs to
a request, and N must know the request before it commits to the head. The HTTP/2 connection head names no
request.

### 3.1 `setup`

`C → N  {"type":"setup","v":3,"http":"2"|"1.1","nonce_c":<64 hex>,"armed":<bool>,"auth":<credential>,"offer_sig":<sig>}`

- No request terms (`kind`, `model`, `max_tokens`, `variant`, `count`, `len`, `suffix`) and no fee fields:
  a setup that names one is refused.
- The node, before it dials the sidecar: `http` is offered; `offer_sig` names an offer it signed and
  remembers; the credential is valid; the **deposit is reserved** (§8). Not enough balance: `error` 402,
  nothing garbled. The node records which offer the connection was opened on.
- `N → C  {"type":"ready","v":3,"http","sid","nonce_n","pubkey","zk_token","sig_scheme","armed","head_len"?,"h2"?,"deposit_msat"}`.
  `sid` names the connection.
- Then the 2PC preprocessing (§4) and the joint key share. `armed: true` stops here; the sidecar has no
  provider connection. An armed connection lives at most 10 minutes.

### 3.2 Handshake and connection head

As v2 (ClientHello with exactly the joint share, one suite, no PSK; N verifies the certificate chain, the
hostname, CertificateVerify and both Finished messages), with:

- The ClientHello is the canonical one of §12.5; N relays no other.
- ALPN: framing `"2"` exactly `h2`, and N requires EncryptedExtensions to select it; framing `"1.1"` exactly
  `http/1.1`.
- C gets `c_hs`, `s_hs`, `s_ap_0`, `c_ap_1`; N gets `K_0`, `IV_0`. Anchors `h1 = SHA256(c_ap_1)`,
  `h2 = SHA256(s_ap_0)`, `hk` as v2.
- `c_commit`, π_NK over the connection head template of the framing, `release_head`; N writes the head
  record and a KeyUpdate in one write; `head_written`.
- C sends no record between its Finished and `head_written`.

### 3.3 `request`

`C → N  {"type":"request","n":k,"kind":"chat"|"images","model", "max_tokens" | "variant","count", "body_len","auth","offer_sig","session_fee_msat","abandon_fee_msat"}`

- `n` = the number of the last accepted request + 1, first 1 (a refused request does not use up its
  number). One request at a time.
- The node does what a v2 setup did: the model is served confidentially and priced by the named offer, the
  fees are echoed, the credential is validated (it may differ from the setup's), and the request is
  **reserved**: chat, a full-context prompt plus `max_tokens`; images, `msat_per_image × count`. The named
  offer's connection-level fields (§12.1) MUST equal those of the offer the connection was opened on, else
  the request is refused with `offer_changed` (C opens a new connection, or names the old offer).
- `N → C  {"type":"request_ok","sid","n","suffix", "stream"? (framing "2"), "head_len"? (framing "1.1")}`.
- **A refused request leaves the connection READY** (`{"type":"request_refused","n","status","reason"}`)
  when C has sent no record for it. C MUST wait for `request_ok` before sending records. (The prototype
  ended the connection; a 402 then cost a handshake.) In framing `"1.1"` a refused request 1 may be
  followed by another `request` 1 while the connection is still ARMED.
- The node remembers a signed offer for 10 minutes after it last served it **or while a connection opened
  on it is alive** (for the comparison of connection-level fields). Rates are frozen per request from the
  offer the request names, and a request may name an offer only **while the node serves it or for 10
  minutes after it stopped** (else `offer_expired`): old prices never outlive a price change by more than
  that, whatever the connection's lifetime. C refetches the offer on `offer_expired` (and SHOULD every 10
  minutes) and names the newest; a price-only change keeps the connection.
- **Security-relevant changes retire live connections.** Once the node serves an offer whose `v`, `twopc`,
  `upstream_host`, `head_template`, `chat`, `h2` or `images` block (prices aside) differs from the offer a
  connection was opened on, that connection takes no further request (`offer_changed`, whichever offer the
  request names): a changed suffix or head is in force for every request from then on. A changed
  `connection_deposit_msat` or `idle_timeout_s` applies to new connections only; framing `"2"` withdrawn
  (§2.1) does not end live connections. Rotating the provider credential means restarting the sidecar,
  which ends every live connection (`fault`, deposits released, §12.10 row 4).

### 3.4 Records, proof, release

C sends the request's records (§5.3, §6.2). N holds them as the framing says, sends `zk_params` for
π_WIN (§7.1), C proves, N writes the records to U and sends `{"type":"body_released","n"}`. From here the
reservation is at stake.

### 3.5 End of a request

| Outcome | C sends | Proof | Node |
|---|---|---|---|
| chat, 2xx | `disclose` (the usage event to the end of the response) | π_C3S | charges the usage at the frozen rates |
| images, 2xx | `accept` | none | charges `msat_per_image × count` |
| status ≥ 400 | `disclose_head` | framing `"2"`: π_WIN under `s_ap_0`; `"1.1"`: π_C3S head mode, as v2 | v2's error rules by status |

N answers with the attestation (per request), then the receipt (signed by the node, bound to `sid`, `n` and
the attestation). Framing `"1.1"`: the attestation is sent when the provider closes the connection, before
C's disclosure (its anchor is the end of the connection). Abort rules: §12.10.

### 3.6 End of a connection

`{"type":"closed","reason":"idle"|"max_requests"|"max_lifetime"|"max_bytes"|"upstream_closed"|"error_settled"|"done"|"ended","deposit":{…}}`
(§12.9 says when each applies). `done` is the normal end of a `"1.1"` connection. The `deposit` object is §8's outcome. Any protocol
violation or failed proof: `{"type":"error","status","reason"}` and the socket closes.

## 4. Two-party key schedule: `split-public-1`

Base: v2's node-only authenticated garbling (`docs/TWOPC-NODE-GARBLING.md`): N garbles with three-halves
tables, its wire masks are authenticated to C by IT-MACs over Ferret COTs, C checks every AND gate with a
salted 64-bit row before it uses an output. ECtF is unchanged.

Change: `HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))`, `f` the SHA-256 compression function. Every inner digest
moved out of the circuit has a public message (a fixed HKDF label and a transcript hash); the extraction
`HS = HMAC(salt, Z)`, whose message is the secret `Z`, stays whole in the circuit. The circuit computes only the pad states `IS_k`, `OS_k` of the four
secret keys (HS, the derived secret, MS, `c_ap_0`), the outer compressions, and the three anchors.
`IS_k` is a **public output** of its stage; both parties compute the inner digest `f(IS_k, m)` in the
clear; N sends the labels of the digest's input wires; C pins them by pointer checks against opened,
authenticated masks (as v2 pins the transcript hash). `OS_k` never leaves the circuit.

One circuit, five stages, a consistency check per stage before C uses any output of that stage:

| Stage | Garbled | Opened |
|---|---|---|
| A1 | `Z = x_C + x_N mod p`; `HS = HMAC(salt, Z)`; `IS_HS`, `OS_HS` | `IS_HS` (public) |
| A2 | `c_hs`, `s_hs`, `dHS` from `OS_HS`; `IS_dHS`, `OS_dHS` | `c_hs`, `s_hs` (public), `IS_dHS` (public) |
| A3 | `MS` from `OS_dHS`; `IS_MS`, `OS_MS` | `IS_MS` (public) |
| B1 | `c_ap_0`, `s_ap_0` from `OS_MS`; `IS_c0`, `OS_c0` | `s_ap_0` (C), `IS_c0` (public) |
| B2 | `K_0`, `IV_0`, `c_ap_1` from `OS_c0`; `h1`, `h2`, `hk` | `c_ap_1` (C), `K_0 ‖ IV_0` (N), anchors (public) |

- 22 garbled compressions, 479 022 AND gates. Measured: 16.38 MB node → client, 1.13 MB client → node.
- **Label-check pairs** (new, mandatory): for every output wire C reports to N, N sends in preprocessing
  the salted hashes of both candidate labels. C checks its label against the pair before it reveals
  anything and aborts on a mismatch. The pairs **augment** the report hash (C still sends one hash over
  its reported labels, so it cannot report a bit it has no label for); what they remove is v2's weakness
  that the bare hash was a value N could test offline against candidate labels.
- The variant with zero-knowledge proofs of the inner digests (`Proven` in the prototype) is not part of
  v3 and is removed from the code.
- **Version tag.** The first message of the 2PC channel in each direction is the ASCII tag
  `routstr-2pc/split-public-1\n`. A peer that reads another tag ends with `twopc_version_mismatch`.

Security statement (informal; no proof, external review outstanding, as for v2):

- A cheating node learns at most log2 8 = 3 bits per **connection** of additional selective-failure leakage
  about fresh, single-use values, **in the idealized abort model** (eight observable outcomes: the ECtF
  abort, an abort in each of the five stages, the server Finished failing, success), conditional on ECtF
  leaking nothing beyond its outcome and on the garbling argument. It is not a bound on all N learns: N
  also gets its intended outputs (`IS_k`, `c_hs`, `s_hs`, the anchors, `K_0 ‖ IV_0`). A full proof must
  enumerate every distinguishable result of malicious ECtF, OT, preprocessing, report checks, TLS
  verification, timeouts and errors; that is not done.
- Assumptions beyond "HMAC-SHA256 is a PRF", for both parties, because both see `IS_k`: (1) `f` keyed by
  its chaining input is a PRF; (2) `OS_k` is pseudorandom given `IS_k` (the two assumptions of Bellare's
  HMAC proof, CRYPTO 2006, used directly; his theorem is for one key with hidden pad states and does not
  by itself prove this chain of keys with public `IS_k`, several outputs per key for different parties
  and public anchors: that hybrid argument is not written); (3) **the inner digests of one key are
  pairwise distinct**: under one `OS_k` the circuit derives several outputs, and two equal inner digests
  give equal outputs (`d_c0 = d_s0` would make `c_ap_0 = s_ap_0`, which C holds, and give C `K_0`; a
  `"derived"` digest equal to `d_c` or `d_s` would expose the derived secret and MS). The messages of
  one key always differ in their fixed HKDF labels at fixed positions of the block, and `IS_k` is known,
  so an equal pair is a collision of the SHA-256 compression function under a known, unchosen chaining
  value (generic cost about 2^128). In v2 the secret inner key covered this; here it is an explicit
  assumption (`docs/TWOPC-DESIGN.md`, "Assumptions").
- Round trips compared with v2, measured: +2 in the handshake call (A1, A2, A3: each stage's public output
  must reach N before it sends the next stage's digest labels) and +0.5 in the application call (N sends
  the B1 labels without waiting for C; B2 needs C's B1 report).
- Where the stages run: A1, A2 and A3 run in one call that starts when the ServerHello arrives. After A2
  both parties hold `c_hs` and `s_hs`; A3 follows at once, while C decrypts and verifies the server flight,
  so A3 is done before C sends its Finished. B1 and B2 run after the server Finished (they need `th_SF`);
  N has `K_0` only after it verified the handshake inputs it fed in.

## 5. Framing `"2"` (HTTP/2)

### 5.1 Rules for everything C writes after the handshake

1. One frame per record. Inner plaintext = 9-byte frame header ‖ payload ‖ `0x17`, no TLS padding.
2. N writes a record to U only after a π_WIN that covers it has verified.
3. For each record π_WIN shows bytes `[0, 9)` equal the frame header N expects and the **last byte is
   `0x17`**; the header's length field equals `inner_len − 10`. (Without the last-byte check, TLS padding
   would move the frame boundary and hide a HEADERS frame in a later payload.)
4. Allowed frames: SETTINGS ACK, PING ACK, RST_STREAM on the current request's stream (announced by a `ctl`
   message each); no WINDOW_UPDATE (the head opens both windows to 2^31-1 and a connection is retired after
   1 GiB, so C never needs one, and its increment would be a client-chosen payload: zero is a connection
   error and any positive increment on stream 0 overflows the window); for a request, one HEADERS (END_HEADERS; the whole record
   is proven equal to the public block) and DATA frames (END_STREAM only on the last, whose tail is proven
   equal to the suffix). Anything else ends the connection.
5. C never sends a KeyUpdate, a header block that adds a dynamic-table entry, a table size update, or a
   second stream while one is open.

### 5.2 Connection head (epoch 0, one record, then KeyUpdate)

```
"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS:       HEADER_TABLE_SIZE = 0, ENABLE_PUSH = 0, INITIAL_WINDOW_SIZE = 2^31-1
WINDOW_UPDATE:  stream 0, 2^31-1-65535
HEADERS stream 1 (END_STREAM|END_HEADERS), no Huffman:
    82  87  01 <len> <host>  04 <len> <probe_path>  57 <len> "Bearer " <KEY>
RST_STREAM stream 1 (CANCEL)
```

`0x57` is "literal with incremental indexing, name = static 23 (authorization)": after this block the
provider's request table holds one entry, `authorization: Bearer <KEY>`, at index 62. Fixed length; the key
is at fixed offsets; π_NK covers the template. C rebuilds the template from the offer and compares every
byte.

### 5.3 A request

Stream `2k + 1`. HEADERS block, public, built by both from the offer:

```
83  87  01 <len> <host>  04 <len> <path>  0f 10 10 "application/json"  be
```

`be` = indexed field 62, the credential. `<path>` is the chat or images path of the offer. DATA frames
carry the JSON body; the canonical suffix is the tail of the last one. π_WIN: the HEADERS record in full;
each DATA record's header and last byte; the last record's tail = suffix ‖ `0x17`. C follows U's flow
control with `release {n, upto}`; N never writes an unproven record nor beyond `upto`. **No record of a
request is written before every record of the request is proven**: a body whose windows exceed one π_WIN
(§7.1 limits) is proven in several consecutive, disjoint batches while N buffers, and the first record goes
out only after the last batch verified. So every body the record rules allow (up to `3 + body_len/4096`
records, 8 MiB) is provable, and no inference starts on a request that fails a proof.

### 5.3.1 A cancelled request cannot lend its credential reference

The attack: C force-stops request k (RST_STREAM) and starts another HTTP request that names the stored
`authorization` entry (index 62), so that the provider serves it and N bills nothing for it. It fails, in
every form, because a request record exists for N only inside an accepted `request` and every record is
classified and proven before it is written:

- *A HEADERS record with no `request`* (for the next stream, or the same stream again, after RST_STREAM):
  once request k is complete, any record that is not a declared control frame is refused before it is
  queued (`a client record outside a request`): it never reaches the provider, and the connection ends.
  Request k, released and not settled, is charged its full reservation.
- *RST_STREAM before the last DATA record is released*: RST_STREAM is accepted only once all of the
  request's records are in, and it is queued behind them, so it cannot overtake the unreleased last record;
  the provider holds a body without END_STREAM (no inference, provider item 1) and the next `request` is
  refused while k is in flight. k ends before `body_released`: released less the abandon fee (the deposit,
  on a connection with no settlement yet).
- *RST_STREAM after `body_released`, no disclosure*: k can only end by its own disclosure (a usage event
  the provider produced, i.e. the work done) or an error head of the provider's; otherwise it is charged its
  full reservation, the bound C accepted. A cancelled request is never cheaper than its bound, and no next
  `request` is accepted while it is in flight.
- *A control record carrying a HEADERS frame*: a control record's frame header (and its last byte) are
  proven against the declared kind, its length is fixed (PING ACK 8, RST_STREAM 4, SETTINGS ACK 0), and
  WINDOW_UPDATE is not allowed at all, so its payload cannot hold a frame: the proof fails, nothing is
  written.
- *Framing "1.1"*: the head pins `Content-Length` and `Connection: close`; content bytes beyond `body_len`
  are refused (`client body exceeds declared length`), so a record after the final one cannot carry a
  second request; a second request inside the body is body bytes (one JSON body, refused by the provider
  as malformed); TLS padding can only make the delivered body shorter than `Content-Length`, which stalls
  C's own request and gives the provider nothing more.
- *A new connection*: the HPACK table belongs to one HTTP/2 connection (RFC 7541 §2.3.2); on a new TCP/TLS
  connection index 62 is out of range, and C never holds `K_0` to write a credential of its own.

**Can request k still be generating while k+1 runs, and can k+1's disclosure absorb k's?** Requests are
sequential: N accepts `request` k+1 only after k's settlement, and only a usage settlement leaves the
connection open (an error head closes it; anything else charges k and ends it). The usage event comes at
the end of k's stream, so when k+1 runs, k's generation is over. Frames of stream k that a misbehaving
provider still sent later would lie in k+1's interval, and the tail grammar (§5.4) refuses a frame on any
stream but 0, the probe stream 1 and the request's own: k+1's disclosure would fail and k+1 be charged in
full. A usage event of stream k is not
the usage event of k+1 (the stream id is in the frame headers N parses). So k's usage can neither be hidden
in nor counted as k+1's; the frames of a misbehaving provider can only cost C, never N. The node gate runs
every case above with exact money (`h2-k-*`, `h11-k-extra-record`, `h11-k-pipelined`).

### 5.4 Usage disclosure, error head

- `disclose`: `R` runs to the last server byte N has received, within the request's interval (server
  records with index ≥ `S_k`, the count when N wrote the request's first record). `R` starts either with
  the 9-byte header of a DATA frame on the request's stream, or with the line feed before `data: ` inside
  such a frame. N parses text and frames alternately; the DATA payload bytes on the request's stream from
  `R`'s start to END_STREAM must be exactly `data: <usage JSON>\n\ndata: [DONE]\n\n`, and the stream must
  end inside `R`. π_C3S, unchanged circuit.
- **The probe stream.** The provider may still answer the probe (stream 1, reset by N in the connection
  head), late. Complete frames of stream 1 of the kinds a GET response consists of (HEADERS, CONTINUATION,
  DATA, RST_STREAM, WINDOW_UPDATE) are **skipped** by the tail grammar: their payloads are no part of the
  request's event stream, and the usage, END_STREAM and stream rules are unchanged. A frame on any stream
  other than 0, 1 and the request's is refused. So billing does not depend on when the probe's answer
  arrives (before or after `S_k`).
- `disclose_head`: `R` runs from **byte 0 of a server record** in the interval to the end of one complete
  HEADERS frame of the request's stream; the frames before it in that record are disclosed with it and may
  only be SETTINGS, PING, GOAWAY on stream 0, WINDOW_UPDATE on stream 0 or the request's stream, and frames
  of the probe stream. π_WIN under `s_ap_0` over those bytes; the block decoded with an empty dynamic
  table, `:status` 400..599. The connection closes after an error head is settled. Why this widens nothing
  N can be made to accept: the claim is still anchored at a record's byte 0, as before, and walking the
  disclosed frames from there lands on the HEADERS frame exactly where the provider's framing puts it; a
  fabricated head still needs a frame header (with its zero bytes) at byte 0 of a record, which JSON text
  never has (risk 5). The prefix frames carry nothing of C's: the request's stream has nothing before its
  response head. What remains a provider requirement (§5.6, H9): a response head lies in a record that
  starts at a frame boundary.
- Images: the response is one JSON body in DATA frames; C sends `accept` after END_STREAM on the request's
  stream (never by a length). N's connection head opens the windows to 2^31-1, so C sends no flow-control
  frame for a response; the connection is retired after 1 GiB received (`closed`, `max_bytes`).

### 5.5 Why the credential cannot be read back

An HPACK entry is a (name, value) pair: the indexed form emits the pair, the name-reference form reuses
only the name. No encoding reuses a stored value under another name. Tables are per direction: a response
cannot point into the request table. HPACK matches whole fields, so there is no partial-match oracle. Push
is disabled in the head. C's header blocks are pinned in full, so C cannot pick a reflecting method or
path. What remains is the provider's application copying the request header into a response, the same
condition as on HTTP/1.1 (provider profile item 8).

### 5.6 What framing `"2"` needs from a provider

Checked by `provider-profile-check.py --h2`; an operator offers `"2"` only when all hold:

| # | Requirement |
|---|---|
| H1 | TLS 1.3 with ALPN `h2` on the API host |
| H2 | accepts a TLS KeyUpdate right after the first flight of an HTTP/2 connection |
| H3 | keeps the request dynamic table (default size ≥ the credential entry) and does not shrink it by SETTINGS |
| H4 | honours `HEADER_TABLE_SIZE = 0` for response headers |
| H5 | a request naming `authorization` by index only is authenticated, also after `idle_timeout_s` of idle |
| H6 | request bodies up to the node's body limit pass flow control |
| H7 | no response path reflects the `authorization` value (same list as item 8) |
| H8 | the streamed usage event and `[DONE]` end the stream as §5.4 parses them |
| H9 | an error response's HEADERS frame lies in a record that starts at a frame boundary (the frames before it in the record being of the kinds §5.4 allows) |

H9 is not checked by the profile tool (it sees no record boundaries); the clients check it on every error
head and the gates exercise it. A provider that splits a frame across records right before an error head
makes that error undisclosable, and after `body_released` an undisclosed request is charged in full: the
money consequence of H9 failing.

N MUST end the connection if U's SETTINGS set `HEADER_TABLE_SIZE` below the size of the credential entry
(H3 at run time; C reports the value in `settings_seen`, §12.6, and a lying C only harms itself: its
next request is unauthenticated). Because the value is C's claim, this end does not count towards the
withdrawal of §2.1 and the deposit is charged like any unused connection. H5 is checked for the idle time
the node offers: `idle_timeout_s` MUST NOT exceed `h2.idle_secs`, and the operator sets `h2.idle_secs` no
higher than the idle time the profile check ran with.

## 6. Framing `"1.1"` (HTTP/1.1)

v2's flow inside the v3 lifecycle.

### 6.1 Connection head

The head record is the offer's `head_template` for the request's kind (chat or images path),
`Content-Length: <body_len>`, `Connection: close`, with the credential. So `request` 1 MUST precede the
ClientHello. π_NK as v2.

### 6.2 Records

The body under `c_ap_1`; the canonical suffix is its own final record. N forwards body records as they
arrive and holds the final record until π_WIN (one window: the whole record = suffix ‖ `0x17`) verifies.
π_C2S no longer exists.

### 6.3 End

Usage disclosure, `accept` and the error head exactly as v2 (π_C3S; the provider closes the connection).
Then `closed` with reason `done`.

## 7. Proof statements

| Statement | Prover, witness | Shows | Used |
|---|---|---|---|
| π_NK | N, `K_0 ‖ IV_0` and the key | the head record's content equals the public template outside the key positions (anchor `hk`) | once per connection |
| π_WIN | C, a traffic secret | several plaintext windows of several records equal public bytes (anchor `h1` or `h2`) | per request; control records; `"2"` error heads |
| π_C3S | C, `s_ap_0` | the disclosed tail (or, `"1.1"`, the response head) is the plaintext of the last server records | per request |

### 7.1 π_WIN

Public: `anchor = SHA256(secret)`, `key_updates`, windows `{seq, off, ct, sel_start, expected}`. For each
window, the plaintext of record `seq` (AES-GCM CTR stream under the key and IV derived from the secret
after `key_updates` updates) at `[off + sel_start, off + sel_start + |expected|)` equals `expected`; `ct`
is the record's ciphertext `[off, off + |ct|)`, `off` a multiple of 16. All windows are compared in one
equality; the verifier learns one bit. N takes every `ct` from its own relay buffer. Limits: 2 200 windows,
64 KiB of ciphertext per proof. C checks before proving that every window lies in a range that is public
for that record (§5.1) and that every record of the batch is named.

Cost: 7 SHA-256 compressions plus one AES block per distinct 16-byte block touched (about 160 k
correlations + 6.4 k per block).

## 8. Money

### 8.1 Connection deposit

- `connection_deposit_msat` (signed offer; node setting `CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT`, default
  max(abandon fee, session fee, 1000 msat); 0 = no deposit) is reserved at the `setup` through the node's
  ordinary reservation path, for both framings.
- It is **released when the first request of the connection reaches a settlement** (usage, `accept`, or an
  error head: any request the provider received).
- A connection that ends with no settled request: the deposit is **charged**, except when the end was the
  node's, the sidecar's or the provider's failure and not something C can cause: the provider unreachable,
  `h2` not selected, framing `"2"` withdrawn, a sidecar or node failure, the provider closing an open idle
  connection (not after control frames of C on it, `after_client_frames`). Then it is released. A provider that closes **during the handshake** is charged: a client
  can cause that (a bad Finished). §12.10 has every row.
- The outcome is reported in `closed.deposit = {"msat", "outcome": "released"|"charged", "reason"}` and,
  when it is released by a settlement, in that request's receipt (`deposit_released_msat`).
- An idle connection after its first settlement holds no reservation.

### 8.2 Idle

The node closes a connection with no request in flight `idle_timeout_s` after `head_written` or the last
settlement (`closed`, reason `idle`). The client's pool uses a shorter idle time than the node's.

### 8.3 Fees

- `session_fee_msat` pays for the two-party handshake and falls due **once per connection**, at the first
  settlement of a request the provider received, by v2's rules for the outcome (added to a 2xx; the whole
  charge for 429/503 and 401/402/403). Once a request was settled, no later request keeps or adds it:
  where v2 says "less the session fee", read "less the session fee if it is still due on this connection".
- A request's reservation = the usage bound (a full-context prompt plus `max_tokens`, or the image price)
  + max(session fee if still due, abandon fee).
- `abandon_fee_msat` per request (kept when an accepted request is dropped before `body_released`), except
  on a connection with no settlement yet: there the deposit is charged instead and the abandon fee is not
  kept on top. So it applies to dropped requests on a connection whose deposit was already released.
- Everything else per request, as v2 per session.

### 8.4 Limits

A connection takes one of the node's session slots for its life and counts against its address's
unused-connection limit until its first `body_released`, and against its address's total
(`CONFIDENTIAL_MAX_ACTIVE_PER_IP`, 16) for its life. A setup that finds the node or its address full first
closes the longest-idle **used** connection there (one that settled a request and has none in flight, so it
holds no deposit; `closed`, reason `evicted`) and is refused only when there is none. At most 8 requests in a
row may be refused on one connection; the ninth refusal ends it (`error` 429).

### 8.5 Recurring cost

A request on an open connection moves about 86 kB up and 13 kB down on its own path, plus on average about
0.4 MB down (one 610 kB proof-channel top-up per 1.6 typical requests, §9.2, off the request path; without
top-ups the same correlations cost about 1.0 MB, extended online in smaller Ferret iterations) and costs the
node two proof verifications. At commodity prices that is well under a
millisatoshi of traffic and CPU per request; usage at the frozen rates (plus `rate_surcharge_pct`, if the
operator sets one) covers it except for the very smallest requests, and every request first needs a
reservation of a full-context prompt plus `max_tokens`, so requests cannot be sent unfunded. Refused requests
hold nothing and are bounded by §8.4. No per-request fee is defined; an operator who wants one sets
`rate_surcharge_pct`.

## 9. Client behaviour

### 9.1 Pool (framing `"2"`)

- Key: (node, credential, `reuseScope`). Requests on one connection are linkable for the provider and its
  CDN or gateway (same TCP connection, same TLS session, in order), for a passive observer of the node's
  link to the provider (one long-lived flow), and for a global observer who correlates the client–node and
  node–provider timing and sizes. Under v2 the shared node key gave account-level linkage only. This is a
  deliberate trade (accepted for v3) as long as the user can turn it off: `reuseScope` separates what must
  not be linked; a scope never shares a connection with another; `reuse: none` gives every request its
  own connection; framing `"1.1"` (`confidential.http: "1.1"`, routstrd `confidentialUpstream.http:
  "1.1"`) turns HTTP/2 off.
- A request takes an idle connection of its key, else opens one (up to `maxConnections` per key,
  `maxTotal`). Parallel requests use separate connections.
- routstrd derives `reuseScope` from its local client (the local API key), default on
  (`confidentialUpstream.http2.reuse: "per-client" | "shared" | "none"`). So by default **every request made
  with one local API key is connection-linkable**, across conversations and applications sharing the key.
  A request header `x-routstr-reuse-scope` narrows it (one conversation, one task); it never widens it.
- One-off Cashu bearers: framing `"1.1"` (a connection per token), or `"2"` with `reuse: none`.

### 9.2 Pre-warm

One mechanism: an **armed connection** (deposit held, 2PC preprocessing and key share done, no provider
connection), bound to the credential only.

- Framing `"1.1"`: as v2's armed sessions, minus the model, `max_tokens` and body-length binding and minus
  the full-context reservation.
- Framing `"2"`: the client MAY keep one armed connection per pool key while there is traffic and every
  open connection is busy, so that a burst does not wait for a 2PC.
- The pre-warmed proof channel holds correlations for π_NK and the first π_WIN and π_C3S; on a kept
  connection it is **topped up while idle** (below), so later requests prove from preprocessed
  correlations instead of extending online.

**Top-up (framing `"2"`).** Chain cp (C proves π_WIN and π_C3S, N holds Δ) is a Ferret RCOT chain; a proof
that needs more correlations than it holds extends it online, inside the proof, on the request path (about
0.5–1.5 MB from N per request from the third request on, measured before the top-up existed). Instead:

- **When.** C asks after `head_written` and after each settlement whose connection stays READY, never
  while a request of its own is open (C sends no `request` until its top-up is answered and run; a request
  that arrives meanwhile waits for it, see below). Framing `"1.1"` has one request per connection and never
  asks.
- **What.** One message on the proof channel's control stream, C → N `topup`; N answers `TopupGrant
  {target}`. `target = 0`: nothing (no traffic). Else `target = available + step`, and both parties run one
  Ferret extension of chain cp to `target`, in lockstep, exactly as the preprocessing does (same messages,
  same consistency check; no base OT). `step` is the smaller of the two parties' `topup` in the channel's
  hello (default 900 000: one typical request, π_WIN over the HEADERS, DATA and suffix records and π_C3S
  over the usage tail, about 560 000 measured, with a margin; it is below the 967 135 net correlations of
  one Ferret iteration at n = 1 024 000, so a top-up is exactly one such iteration: about 580 kB N → C and
  30 kB C → N). `step = 0` turns top-ups off.
- **Granted only when** chain cp holds fewer than `step` correlations, N holds no parameters of a proof that
  has not run yet (a request's π_WIN or π_C3S is due: a top-up never delays a proof N asked for), and the
  channel's top-ups so far moved less than 256 MiB. C refuses (and the channel is then closed) any grant
  other than 0 or exactly `available + step`, so N cannot make C hold more than agreed.
- **Bounds.** A top-up leaves at least `step` correlations, and the next one is granted only after proofs
  consumed them, so an idle connection never grows (C does not even ask while the chain holds a step);
  top-ups are bounded by the proofs, which are bounded by the requests (`h2.max_requests`), and in bytes by
  the 256 MiB budget; memory by `2 · step` correlations per chain (about 30 MB of keys at N). Chain cp's
  lifetime cap on the channel's multiplexer is 512 MiB (at 32 MiB a kept connection ran out after about 33
  requests).
- **A request during a top-up waits; it does not cancel.** The extension is a lockstep exchange whose
  partial state cannot be dropped on one side only, so cancelling would need an abort protocol that poisons
  the channel. Waiting costs at most the remainder of one iteration (about 170 ms on loopback, 0.1 s of
  transfer at 50 Mbit/s), which is what the request would otherwise spend extending online; in the usual
  case the top-up is done long before the request's first proof, which follows the `request` round trip,
  the records and `zk_params`.
- **Failure.** A top-up that fails or times out closes the proof channel, as a failed proof does; the
  connection's next proof cannot run and the connection ends (deposit and request outcomes as for a client
  that does not prove). Old clients (channel version 1) do not open the channel against a version-2 node
  and prove one proof per socket.
- **Measured** (loopback through a node, real provider, five requests on one connection with 3 s idle
  between them): requests 3–5 downloaded 0.98–1.45 MB on the request path before, 13–15 kB after (the
  request itself); the top-ups moved 610 kB each, three for the five requests, off the request path.

### 9.3 Body size

The body length (`body_len`, the record sizes, the ciphertext) is exact unless C pads. A client MAY pad with
JSON whitespace between the private part and the canonical suffix to a bucket (SDK `confidential.padBucket`,
reference driver `--pad-bucket`: a multiple of N bytes or the next power of two, at most 8 MiB). **Off by
default**: the node learns the prompt's token count at settlement anyway, so padding hides the size only
from observers of the connections (and from the provider), and it costs upload, the scarce direction on the
links measured. A client that cares about passive observers turns it on.

### 9.4 Checks C makes

Everything v2 checks (`params.ts`), with: π_WIN parameters (§7.1); the receipt's and attestation's `n`,
`stream`, `s_k`; the connection head template per framing; U's certificate chain, hostname and handshake
by its own TLS stack.

## 10. Residual risks that are new or changed

| # | Risk | Status |
|---|---|---|
| 1 | Requests on one HTTP/2 connection are linkable for the provider | by design; `reuseScope`, §9.1 |
| 2 | π_WIN, the frame rules and the interval rule of §5.4 are new | no external review |
| 3 | `split-public-1`: staged check, label-check pairs, both parties see `IS_k` | no external review; assumptions in §4 |
| 4 | A provider that changes HTTP/2 behaviour (table size, KeyUpdate) breaks framing `"2"` | detected, §2.1 auto-disable, §2.3 fallback |
| 5 | A fabricated error head would need a binary frame header at byte 0 of a server record in the interval (with only stream-0, own-stream WINDOW_UPDATE and probe-stream frames before the head, §5.4) | smaller than v2's equivalent |
| 6 | 3 bits per connection instead of 2.8 per request (idealized abort model, §4) | fewer connections than requests; with one request per connection it is slightly more |
| 7 | A malicious N can write more epoch-0 records than the proven head (π_NK binds the head's content only): HEADERS frames that change the provider's request table, so that index 62 no longer names the proven credential entry, or that change the connection's state | C's own header blocks stay proven; it cannot reveal the prompt or the key, but it can change how C's requests authenticate or make them fail. Inherited from risk 1 of v2, with a new effect |
| 8 | Receipts and attestations of one connection repeat `sid`, the transcript hashes, `c_commit`, the certificate-chain hash and the request numbers and intervals | anyone shown several of them can link them and see their order and gaps: they are **private documents** of the client. Showing them to third parties unlinkably would need a new signed presentation format; redacting fields of the signed ones breaks their signatures |
| 9 | Compromise scope: one `c_ap_1`/`s_ap_0` pair protects up to `h2.max_requests` requests (C may not KeyUpdate under π_WIN's rules). A live compromise of C exposes the connection's current and later traffic; a later forensic compromise of retained secrets exposes the whole recorded connection, not one request | clients erase traffic secrets when a connection closes (and keep them out of logs and swap where they can); operators keep `h2.max_requests` and `h2.max_lifetime_s` in proportion. A per-request ratchet needs a new anchor protocol |
| 10 | The credential lives in the provider's HPACK decoder state for the connection's life (provider, CDN or gateway memory, crash dumps) | v3 does not reduce provider-side exposure; requests by index still decode to the full field at the provider |

v2's residual risks carry over unchanged (π_NK does not bind other epoch-0 records; provider reflection;
ECtF semi-honest; no proof of the garbler-only construction).

## 11. Versions and upgrade

- A v3 node offers `v: 3` only. A socket with `v=2` (or none): the node accepts it, sends
  `{"type":"error","status":426,"reason":"upgrade_required","min_v":3,"detail":"this node speaks routstr-confidential v3; update your client"}`
  and closes. v2 clients already refuse an offer without `v = 2` (`offer_unsupported_version`).
- A v3 client that reads an offer with `v < 3`: it does not use the node for confidential requests and
  reports `node_protocol_outdated` (routstrd: logged once per node per day, and in the error body when no
  other node can serve the request). It requests offers as `/v1/confidential/offer?v=3`, so an old node's
  access log shows that v3 clients are asking.
- The node's Nostr listing carries the confidential version (`confidential: 3`), so clients can filter
  before fetching offers.
- There is no v2 fallback in clients or nodes. The v2 code stays on the branches `twopc-v2` (this repo)
  and `confidential-2pc` (routstr-core, routstr-sdk).

## 12. Wire format

The complete message reference. **S** marks what the sidecar speaks on its own sockets (`/offer`, `/session`,
`/zk`); **N** what a client of a node sees (`/v1/confidential/offer`, `/v1/confidential/ws`,
`/v1/confidential/zk`). A node relays every frame not listed under "node" unchanged, in both directions.
Control messages are JSON text frames; TLS records are binary frames. Byte strings in JSON are lower-case
hex, except inside `params`, where they are arrays of numbers. `http` is always the string `"2"` or `"1.1"`.

### 12.1 Offer

**Sidecar offer file** (operator): the v2 fields (`upstream_host`, `head_template`, `key_alphabet`, `chat`,
`max_tokens_cap`, `model_allowlist`, `endpoints.images`) plus

```json
"http": ["2", "1.1"],
"h2": {"probe_path": "/api/v1/models", "max_requests": 100, "max_lifetime_s": 3600, "idle_secs": 300, "kinds": ["chat", "images"]}
```

| Field | Range, default | Meaning |
|---|---|---|
| `http` | non-empty, distinct, each `"2"` or `"1.1"`; default `["1.1"]` | framings served, in the operator's order of preference. `"2"` requires `h2` |
| `h2.probe_path` | canonical path under 127 bytes | the GET of the connection head (§5.2) |
| `h2.max_requests` | 1..1000, 100 | requests per connection |
| `h2.max_lifetime_s` | 60..86400, 3600 | a connection is closed at the first settlement after this long since `head_written` |
| `h2.idle_secs` | 10..3600, 300 | the sidecar's own idle limit; the ceiling of the node's `idle_timeout_s` |
| `h2.kinds` | `["chat"]` (default, not serialized) or `["chat","images"]` (needs `endpoints.images`) | request kinds on a framing-`"2"` connection |

Also required for `"2"`: host under 127 bytes, key at most 119 bytes. Framing `"1.1"` serves chat always and
images when `endpoints.images` exists.

**S** `GET /offer`: the file's content with `v: 3`, `twopc: "split-public-1"`, `notary_pubkey`,
`node_settles`, and `http` as currently served: `"2"` is left out while it is withdrawn (§2.1; the `h2`
block stays). An offer file that names `v` other than 3 is refused at startup.

**N** `GET /v1/confidential/offer[?v=3]` (the query is ignored by the node; clients send it): the signed
offer. Fields: `v: 3`; `http`, `h2` (the sidecar's; `kinds` lists `images` only when the offer has an
`images` block; `h2` only when `http` lists `"2"`); `twopc`; `connection_deposit_msat` (integer ≥ 0);
`idle_timeout_s` (integer ≥ 10, at most `h2.idle_secs` when `"2"` is offered; node setting
`CONFIDENTIAL_IDLE_TIMEOUT_S`, default 120; the deposit's default is max(abandon fee, session fee,
1000 msat), 0 settable, a value above 0 at least the node's minimum request); and everything the v2 offer had
(`upstream_host`, `head_template`, `chat`, `images`, `capabilities`, `price_list`, `session_fee_msat`,
`abandon_fee_msat`, `max_tokens_cap`, `node_pubkey`, `sig`, …), unchanged in meaning.

Client checks before a `setup` (§2.3): `v == 3`; `twopc == "split-public-1"`; `http` non-empty, known
values, the chosen framing listed; for `"2"` the `h2` block in range and `probe_path` a trusted API base
plus `/models`; `connection_deposit_msat` at most the client's maximum (reference driver: 100 000 msat);
the v2 checks (signature, host, chat block, head template, images block). An offer with `v < 3`:
`node_protocol_outdated`.

**N** The node's Nostr listing (kind 38421) carries the tag `["confidential","3"]` while a sidecar is
configured (§11), and each confidential model in `GET /v1/models` has
`confidential_upstream: {"v":3,"offer_url"[,"session_fee_msat","abandon_fee_msat","rate_surcharge_pct"][,"kind":"images"]}`.

**Connection-level fields** of an offer: `v`, `twopc`, `upstream_host`, `head_template`, `chat`, `h2`,
`connection_deposit_msat`, `idle_timeout_s`, and the `images` block without its `price_list`. A `request`
that names an offer in which one of these differs from the offer of the `setup`, or whose `http` no longer
lists the connection's framing, is refused with `offer_changed` (12.4).

### 12.2 Sockets

| Socket | S | N |
|---|---|---|
| session | `/session` | `/v1/confidential/ws?session_id=<uuid>&v=3` |
| 2PC | `/zk?proof=twopc&sid=<sid>` | `/v1/confidential/zk?proof=twopc&sid=<sid>&zk_token=<token>` |
| proof channel | `/zk?proof=zkchan&sid=` | same path, `proof=zkchan` |
| one proof | `/zk?proof=pi_nk`, `pi_win`, `pi_c3s` | same |

**N** A session socket whose `v` is not `3` (absent, `2`, anything else), or whose first frame is a `setup`
without `"v":3`: the node accepts the socket, sends
`{"type":"error","status":426,"reason":"upgrade_required","min_v":3,"detail":"this node speaks routstr-confidential v3; update your client"}`
and closes. **S** refuses a `setup` without `"v":3` with an `error` whose `code` is `upgrade_required`.

The 2PC channel begins with the version tag of §4 in each direction. The client's `cu-2pc` exits with
status 3 and code `twopc_version_mismatch` on another tag; the sidecar ends the connection with an `error`
whose `code` is `twopc_version_mismatch`. `pi_win` and `pi_c3s` run once per `zk_params` on the channel
(`cu-prover --channel`; the earlier `--multi` is the only mode) or on a socket of their own; `pi_nk` once
per connection.

**Proof channel** (`zkbench::channel`, version 2). One socket per connection; its bytes are mux frames
`[u8 stream][u32 BE length][payload]`, streams 0 = control, 1 = chain nk (N proves π_NK), 2 = chain cp (C
proves π_WIN, π_C3S); lifetime inbound caps 1 MiB, 32 MiB and 512 MiB. Control messages (bincode, in
order):

| Direction | Message | When |
|---|---|---|
| both | `Hello {version: 2, nk, cp, topup}` | first; each chain's preallocation and the top-up step are the smaller of the two; another version ends the channel (the client proves per socket) |
| C → N | `ProofReq {proof: "pi_nk" \| "pi_win" \| "pi_c3s"}` | then the proof on its chain, against N's own `zk_params` |
| C → N | `ProofReq {proof: "topup"}` | framing `"2"`, idle (§9.2); C sends it only while chain cp holds fewer than `step` |
| N → C | `TopupGrant {target: u64}` | the answer: 0, or `available + step`, then one Ferret extension of chain cp to `target` |

The client process (`cu-prover --channel`, the browser library's wasm driver) takes `{"cmd":"topup","id"}`
and answers `{"ev":"done","proof":"topup","ok","granted","before","after","bytes","ms","avail":[nk,cp]}`;
it runs its commands in order, so a proof sent after a top-up waits for it.

### 12.3 `setup`, `ready`

**N** `C → N  {"type":"setup","v":3,"http":"2"|"1.1","nonce_c":<64 hex>,"armed":<bool>,"auth":<sk- key or Cashu token>,"offer_sig":<sig of the verified offer>}`

- Refused (400) when it names `kind`, `model`, `max_tokens`, `variant`, `count`, `len`, `body_len`,
  `suffix`, `session_fee_msat` or `abandon_fee_msat`.
- Node checks, in order, before it dials the sidecar: the shape; `http` is in its current offer (400);
  `offer_sig` names an offer it signed and remembers (409 `offer_expired`); the credential is valid with an
  available balance of at least `max(1 msat, the node's minimum request, that offer's session fee, its
  abandon fee)` (401/402, the node's usual error body; a Cashu token is redeemed here); the deposit of that
  offer is reserved (402 with `detail.error.type = "connection_deposit_unfunded"` and
  `connection_deposit_msat`). A refusal is `{"type":"error","status","reason","detail"}` and the socket
  closes.
- **S** sees `{"type":"setup","v":3,"http","nonce_c","armed","escrow":"conn-<id>"}`: no credential, no
  offer signature. `escrow` makes the sid unique. A direct client of a sidecar may send `escrow` or
  `escrow_e` itself.

**S** `N → C  {"type":"ready","v":3,"http","sid","nonce_n","pubkey","armed"}` plus, framing `"2"`,
`"head_len"` (the connection head's length) and `"h2"` (the block). `sid = SHA256(nonce_c ‖ nonce_n ‖
SHA256(escrow))` names the connection. **N** adds `zk_token`, `sig_scheme`, replaces `pubkey` by the
node's, and adds `deposit_msat` (what the setup reserved; the client requires it to equal the offer's
`connection_deposit_msat`).

Then `/zk?proof=twopc` (preprocessing, key share) and `/zk?proof=zkchan`. `armed` changes nothing in what
the sidecar does: in both framings it dials the provider only when the ClientHello arrives. An armed
connection that sent no ClientHello within 600 s of its socket's accept is ended.

### 12.4 `request`, `request_ok`, `request_refused`

**N** `C → N  {"type":"request","n":k,"kind":"chat","model","max_tokens","body_len","auth","offer_sig","session_fee_msat","abandon_fee_msat"}`
or `{"type":"request","n":k,"kind":"images","model","variant","count","body_len","auth","offer_sig","session_fee_msat","abandon_fee_msat"}`.

- `n` is the number of the last **accepted** request (`request_ok`) plus 1; the first is 1. A refused
  request does not use up its number. One request at a time.
- `kind` absent = `chat`. `max_tokens` 1..`max_tokens_cap`. `count` 1..the offer's and the variant's
  `max_count`. `body_len` = the JSON body's length, suffix included, more than the suffix, at most 8 MiB.
- `auth`, `offer_sig` are per request (another credential, a newer offer). The fee fields echo that offer's
  fees (409 `session_fee_not_accepted`).
- **When.** Framing `"2"`: after `head_written` and a `settings_seen` (12.6). Framing `"1.1"`: after
  `ready`, **before the ClientHello**; exactly one request is accepted on the connection.
- The node validates, reserves (chat: a full-context prompt plus `max_tokens`; images:
  `msat_per_image × count`; each plus `max(session fee still due, abandon fee)`), and forwards
  **S** `{"type":"request","n","kind","model","max_tokens","body_len"}` or
  `{"type":"request","n","kind":"images","model","count","body_len","suffix":<the node's rendering>}`.
  A chat request may carry `suffix`; it must equal the canonical one.
- **S** `N → C  {"type":"request_ok","sid","n","suffix":<the canonical suffix>}` plus `"stream": 2k+1`
  (framing `"2"`) or `"head_len"` (framing `"1.1"`: the length of the request head N will write).
- **C MUST NOT send a record of the request (framing `"1.1"`: the ClientHello) before `request_ok`.**

`N → C  {"type":"request_refused","n","status","reason"[,"detail"]}`: the request is not accepted, nothing
is held for it, and the connection stays as it was (READY, or ARMED in framing `"1.1"`). The next `request`
carries the same `n`.

| From | `status` | `reason` |
|---|---|---|
| node | 400 | a malformed `request`; a model the node does not serve confidentially; a kind the connection does not serve |
| node | 401 / 402 | the credential, or its balance against the reservation (the node's usual error body in `detail`) |
| node | 409 | `offer_expired`, `offer_changed`, `session_fee_not_accepted` |
| node | 5xx | the node could not reserve (its own failure; counts for the deposit, 12.10) |
| sidecar | 400 | terms the sidecar does not serve: `model_allowlist`, `max_tokens` above the cap, `body_len` out of range, an image suffix outside the offer |

The node releases the reservation in full when the sidecar refuses. **Not** a refusal but a protocol error
that ends the connection (`error`): a wrong `n`, a `request` while one is in flight, a `request` before
`head_written` or without `settings_seen` (framing `"2"`), a second accepted request (framing `"1.1"`), a
record sent before `request_ok`.

### 12.5 Handshake and connection head (both framings)

1. C sends the ClientHello (binary): one record (`16 03 03 <len>`), one message, **canonical**: N compares
   every byte except the random and the session id and refuses anything else before it dials.
   `01 <len:3> 0303 <random:32> 20 <session id:32> 0002 1301 0100 <len:2>` and exactly these extensions in
   this order: `ff01 0001 00` (renegotiation_info), `0000` server_name = the offer's `upstream_host`,
   `000a 0004 0002 0017` (secp256r1), `0023 0000` (session_ticket, empty), `002b 0003 02 0304`,
   `000d 000e 000c 0403 0503 0804 0401 0501 0601`, `0033 0047 0045 0017 0041 <the joint P-256 share:65>`,
   `0010` ALPN with one protocol: `h2` (framing `"2"`) or `http/1.1` (framing `"1.1"`). No PSK, no
   `psk_key_exchange_modes`, nothing else. (This is what the reference client, the SDK and the browser
   library write; the reason is §2.1.) Framing `"1.1"`: only after `request_ok`. N dials the provider now.
2. The joint key schedule runs on the 2PC channel; C relays ChangeCipherSpec and its Finished.
3. `N → C  {"type":"hs_verified"}`: N verified chain, hostname, CertificateVerify and both Finished;
   framing `"2"`: EncryptedExtensions selected `h2`, else `error` with `code: "h2_not_selected"`.
4. `N → C  {"type":"c_commit","params":{"PiNK":…},"c_commit","h1","h2","hk"}`. `params.template` is the head
   with zero bytes at the key positions: framing `"2"` the connection head of §5.2, bytes
   `PREFACE ‖ 000012 04 00 00000000 ‖ 0001 00000000 ‖ 0002 00000000 ‖ 0004 7fffffff ‖ 000004 08 00 00000000 ‖
   7fff0000 ‖ 0000LL 01 05 00000001 ‖ 82 87 01 <len> <host> 04 <len> <probe_path> 57 <7+keylen> "Bearer " <key>
   ‖ 000004 03 00 00000001 ‖ 00000008`; framing `"1.1"` the offer's `head_template` of the request's kind
   (`images.head_template` for images) with `{LEN}` = `body_len`. C rebuilds it and compares every byte,
   `head_len` and `key_offsets`.
5. π_NK (`pi_nk`); `C → N  {"type":"release_head"}`; N writes the head record (epoch 0, seq 0) and a
   KeyUpdate (seq 1) in one write; `N → C  {"type":"head_written"}`.

A binary frame between C's Finished and `head_written` is refused in framing `"2"`; in framing `"1.1"` body
records sent early are held and relayed after the head (as v2).

### 12.6 Framing `"2"`: records, control frames, π_WIN, release

Every binary message after `head_written` is TLS records under `c_ap_1` (sequence numbers from 0), one
HTTP/2 frame per record (§5.1), a DATA payload at most 16 375 bytes.

- `C → N  {"type":"settings_seen","header_table_size":<integer or null>}`: the value of
  `SETTINGS_HEADER_TABLE_SIZE` in the provider's SETTINGS frames so far (the last one; `null` when the
  provider never sent the parameter, i.e. the default 4096). Required before the first `request`; sent again
  whenever a later SETTINGS frame carries the parameter. A value below `32 + 13 + 7 + key_length` (the size
  of the credential entry): `error` with `code: "h2_table_size"`.
- `C → N  {"type":"ctl","frame":"settings_ack"|"ping_ack"|"rst_stream"}`: the next record is that control
  frame (inner lengths 10, 18, 14). `rst_stream` on the current request's stream, once its records are all
  received. At most 16 unproven control records. (`window_update` is refused: §5.1 rule 4.)
- Any other record belongs to the open request: first the HEADERS record (flags `04`, stream `2k+1`, block
  `83 87 01 <len> <host> 04 <len> <path> 0f 10 10 "application/json" be`, `<path>` the route of
  `head_template` or `images.head_template`), then DATA records (flags `00`, the last `01`) until the
  payloads sum to `body_len`. Refused: an empty DATA frame, a last DATA frame shorter than the suffix, more
  than `3 + body_len/4096` records, a record with no request open.
- `N → C  {"type":"zk_params","proof":"pi_win","purpose":"records","first_seq":s,"count":c,"params":{"PiWin":…}}`:
  the next unproven queued records, sequence numbers `s … s+c-1`, as many as one π_WIN holds (§7.1
  limits). Sent when the request is complete (control records sent meanwhile join it) or, with no request
  open, per control record; one at a time, and the next batch after the previous one verified. A long body
  takes several batches; none of its records is written before the last one verified.
- `C → N  {"type":"release","n":k,"upto":u}`: the first `u` records of request `k` may be written once
  proven; `u` only grows. C follows the provider's flow control (stream credit = the provider's
  `INITIAL_WINDOW_SIZE` + WINDOW_UPDATEs on the stream; connection credit = 65 535 + WINDOW_UPDATEs on
  stream 0 − DATA bytes of earlier requests).
- `N → C  {"type":"body_released","n":k}` when the last record of the request is written.

`PiWin = {"anchor":[32],"key_updates":0,"windows":[{"seq","off","ct":[…],"sel_start","expected":[…]}]}` (`off`,
`sel_start`, `key_updates` omitted when 0). Windows per record:

| Record | Windows |
|---|---|
| control, HEADERS | the whole record when header ‖ `17` is all of it (SETTINGS ACK; HEADERS: frame ‖ `17`); else `[0,9)` = the frame header and the last byte = `17` |
| DATA, not last | `[0,9)` = `len 00 00 stream`, `len = inner_len − 10`; last byte = `17` |
| DATA, last | `[0,9)` with flags `01`; the last `|suffix|+1` bytes = suffix ‖ `17` |
| framing `"1.1"`, the final record | the whole record = suffix ‖ `17` |

C's check (`checkPiWinParams`): `anchor` is its `h1`; every window names one of the `count` records, `ct` is
its own ciphertext at a block-aligned offset, the compared bytes equal its plaintext and lie in a range that
is public for that record; every record of the batch is named.

### 12.7 Framing `"1.1"`: records, π_WIN

After `head_written` C sends the body as records under `c_ap_1`: content bytes summing to `body_len`, the
canonical suffix alone in the final record. N writes each record but the final one to the provider as it
arrives. When the final record is there (content = `|suffix|` bytes exactly; anything else is an `error`):

`N → C  {"type":"zk_params","proof":"pi_win","purpose":"records","first_seq":<its sequence number>,"count":1,"params":{"PiWin":…}}`
(one window, the whole record). C checks and proves with `c_ap_1`; N writes the record;
`N → C  {"type":"body_released","n":1}`. There is no `body_suffix`, `ctl`, `release` or `settings_seen` in
framing `"1.1"`.

### 12.8 End of a request

**Framing `"2"`.** `server_records` = the server records of outer type 23 the client has received since the
connection began (handshake flight included).

- Chat 2xx: `C → N  {"type":"disclose","n","r":<hex>,"tail_lens":[…],"skip":0,"server_records":m[,"key_updates","epoch_start"]}`.
  `tail_lens`: inner lengths of the last records, last first; they must be N's last records, all with index
  ≥ `S_k`. `r` starts with the 9-byte header of a DATA frame on the request's stream or with the line feed
  before `data: `; text runs to the next `00`, which starts a frame header; accepted frames: DATA on the
  stream, one trailers HEADERS (flags `05`), SETTINGS / PING / GOAWAY on stream 0, WINDOW_UPDATE on stream 0
  or the stream; the stream must end inside `r`; the DATA payloads together are exactly
  `data: <usage JSON>\n\ndata: [DONE]\n\n`. N holds more records than `m`:
  `N → C  {"type":"disclose_retry","n","server_records"}` and C rebuilds. Then `attestation`, then
  `{"type":"zk_params","proof":"pi_c3s","n","params":{"PiC3S":…}}`, C proves with `s_ap_0`.
- Images 2xx: `C → N  {"type":"accept","n","server_records":m}` after END_STREAM
  (`{"type":"accept_retry","n","server_records"}` when N holds more); `attestation`; settlement.
- Status ≥ 400: `C → N  {"type":"disclose_head","n","record":i,"r":<hex>[,"key_updates","epoch_start"]}`: `r`
  is the plaintext from byte 0 of server record `i ≥ S_k` to the end of one HEADERS frame of the stream with
  END_HEADERS; before it only the frames §5.4 allows; at most 16 KiB and 8 records, the block decodable with
  an empty dynamic table, `:status` first, 400..599. Allowed once the request's first
  record was written and no client record is unproven. `attestation`, then
  `{"type":"zk_params","proof":"pi_win","purpose":"error_head","n","record","params"}` (`anchor = h2`; per
  record the frame's bytes from offset 0 and the last byte = `17`).

**Framing `"1.1"`.** The provider closes the connection after its response. N then sends the `attestation`
on its own. After it:

- Chat 2xx: `C → N  {"type":"disclose","n":1,"r","tail_lens","skip":0[,"trailing","key_updates","epoch_start"]}`
  (v2's usage disclosure: `r` from the line feed before the usage event's `data: ` to the end of the chunked
  response) → `{"type":"zk_params","proof":"pi_c3s","n":1,"params"}`.
- Images 2xx: `C → N  {"type":"accept","n":1}`.
- Status ≥ 400: `C → N  {"type":"disclose_head","n":1,"r","tail_lens","skip"[,"trailing","key_updates","epoch_start"]}`:
  `r` is the response head (`HTTP/1.1 <status> …\r\n\r\n`) starting the first covered record, `skip` the
  body bytes after it → `{"type":"zk_params","proof":"pi_c3s","purpose":"error_head","n":1,"params"}`.
  A `disclose` whose `r` is a response head is refused.

**Attestation** (S): `{"type":"attestation","n","a":{…},"sig":<ed25519 over the serialized a>}`.

| Framing | `a` |
|---|---|
| `"2"` | `sid`, `http:"2"`, `n`, `stream`, `s_k`, `server_records`, `sha256_recv` (the type-23 server records of the request's interval, header ‖ payload), `client_records`, `sha256_sent` (the request's HEADERS and DATA records), `cert_chain_hash`, `th_sh`, `th_sf`, `c_commit`, `time` |
| `"1.1"` | `sid`, `http:"1.1"`, `n:1`, `server_records` (all records), `sha256_recv` (every byte received), `client_records` (body records), `sha256_sent` (every byte written), `cert_chain_hash`, `th_sh`, `th_sf`, `c_commit`, `time` |

**N** re-signs it and sends
`{"type":"attestation","n","a":{…},"a_json","sig","sig_scheme":"schnorr-secp256k1","sidecar_sig"}`: `a` is the
sidecar's object unchanged; `a_json` is its canonical JSON (keys sorted, no whitespace, UTF-8), the text the
node signed; `sig` is the node's BIP-340 signature over SHA-256 of `a_json`; `sidecar_sig` is the sidecar's
signature (the `sig` of the S frame). The node signs only an attestation whose `a.sid` is the connection's
and whose `n` is the request in flight; any other is dropped. A receipt's `attestation_hash` is SHA-256 of
`a_json`.

**Settlement.** S with `--node-settles`:
`{"type":"usage","sid","http","n","model":<pinned>,"usage":<the usage event | {"error_status","choices":[]} | {"flat":true,"kind":"images","count"}>[,"reported_model"]}`;
without it a stub `{"type":"receipt","n","receipt":{"sid","http","n",…},"receipt_json","sig"}`.
**N** consumes `usage` (it is not relayed) and sends
`{"type":"receipt","receipt":{…},"receipt_json","sig","sig_scheme":"schnorr-secp256k1"}`. `receipt_json` is the
receipt's canonical JSON, the text the node signed (`sig`: BIP-340 over its SHA-256). The receipt:

| Field | Present | Meaning |
|---|---|---|
| `v` | always | `1`, the receipt format |
| `sid`, `http`, `n` | always | the connection, its framing, the request |
| `model` | always | the pinned model |
| `usage` | always | the `usage` of the S frame: the provider's usage event, `{"error_status","choices":[]}`, or `{"flat":true,"kind":"images","count"}` |
| `cost_msats` | always | what the request was charged |
| `reserved_msats` | always | what was reserved for it |
| `balance_msats` | always | the credential's balance after the charge (`null` if the key is gone) |
| `rates` | chat | the frozen rates `{"in","cached_in","cache_write","out"}`, msat per 1000 tokens |
| `kind:"images"`, `variant`, `count`, `msat_per_image` | images | the frozen variant and price (no `rates`) |
| `session_fee_msat` | when this request owed it | the offer's session fee; absent (0) after the connection's first settlement, and when the offer has none |
| `abandon_fee_msat` | when the offer has one | the offer's abandon fee (never below the session fee) |
| `rate_surcharge_pct` | when the offer has one | the offer's surcharge |
| `deposit_released_msat` | on the connection's first settled request, when a deposit was held | the deposit this settlement released |
| `notary_pubkey` | always | the node's key (x-only, hex) |
| `attestation_hash` | always | SHA-256 of the request's `a_json`, hex |
| `time` | always | Unix seconds |

A `usage` with no attestation before it, or a settlement the node cannot write, gives no receipt: the node
ends the connection with `error` (`fault: "node"`, 12.9).

After a settled 2xx a framing-`"2"` connection is READY again. Otherwise the connection ends (12.9).

### 12.9 `closed`, `error`, limits

`N → C  {"type":"closed","reason"}`: an orderly end with no request in flight.

| `reason` | When |
|---|---|
| `done` | framing `"1.1"`: its request was settled (2xx) |
| `error_settled` | an error head was settled (both framings) |
| `idle` | no request in flight for the idle limit (the node's `idle_timeout_s`; the sidecar's `h2.idle_secs` behind it) |
| `max_requests`, `max_lifetime`, `max_bytes` | framing `"2"`: at the settlement that reached `h2.max_requests`, `h2.max_lifetime_s`, or 1 GiB received |
| `upstream_closed` | the provider closed an open connection with no request in flight; `"after_client_frames": true` when C had control frames written on a connection that carried no request (the close may be C's doing: not row 5 of 12.10) |
| `evicted` | node only: a newer setup took the slot of this idle, used connection (§8.4) |
| `ended` | node only: neither side had a last word |

`N → C  {"type":"error","reason"[,"status"][,"code"][,"fault"]}` and the socket closes: every protocol
violation and failed proof. `fault` is `"upstream"` (the provider could not be reached or did not behave as
the framing needs) or `"node"` (the sidecar failed). `code`, when present: `upgrade_required`,
`twopc_version_mismatch`, `upstream_unreachable`, `h2_not_selected`, `h2_withdrawn`, `h2_table_size`.
`{"type":"upstream_closed_early","n","response_bytes"}` precedes the `error` when the provider closed before
the request was fully written (N relays it).

**N** sends its own `error` frames as `{"type":"error","status","reason","detail"[,"fault":"node"]}`: a
refused setup (12.3; the socket then closes), a protocol error in a `request` (12.4), a time limit (408),
and its own failures, which carry `fault: "node"`: the sidecar's socket ending without a last frame (502),
a `usage` without an attestation (502), a settlement that could not be written (500; `detail.error` is
`{"type":"settlement_failed","outcome"}`). The sidecar's `closed` or `error` is held back until the node
has finalized what the connection still holds, and is then sent as the connection's last frame.

**N** adds to the connection's last frame (`closed` or `error`) the signed deposit outcome when a deposit
was reserved and not released by a settlement (12.10). That includes the `error` of a setup the node
refused after it reserved the deposit (no session slot, the sidecar unreachable: row 2); a setup refused
earlier (row 1) reserved nothing and carries none. When neither side had a last word (the client left),
the frame would be `{"type":"closed","reason":"ended"}`.

| Limit | Value |
|---|---|
| setup frame after the socket opens | 15 s (S), 10 s (N) |
| 2PC preprocessing and key share | 180 s |
| socket accept to `head_written` (armed time included) | 600 s |
| `request_ok` to `body_released`; `body_released` to settlement | 600 s each |
| idle | `idle_timeout_s` (N), `h2.idle_secs` (S) |
| body | 8 MiB (`--max-body`) |
| response | chat 64 MiB; images `images.max_response_bytes`; a framing-`"2"` connection 1 GiB + two responses |
| π_WIN | 2 200 windows, 64 KiB ciphertext |
| π_C3S | `r` ≤ 16 KiB; the limits of `zkbench::statements` |
| control message | 256 KiB |
| sessions | 32 per process (S and N); per address: `CONFIDENTIAL_MAX_UNUSED_PER_IP` (12) unused, counted until the first `body_released`, and `CONFIDENTIAL_MAX_ACTIVE_PER_IP` (16) in all; a full node or address evicts its longest-idle used connection first (§8.4) |
| refused requests | 8 in a row per connection; the ninth ends it (`error` 429) |
| `/zk` sockets per connection | 6 |

### 12.10 Money (N)

**Per request** (v2's rules, "session" read as "request"):

| The request ends… | Its reservation |
|---|---|
| refused (`request_refused`) | never made, or released in full |
| accepted, the connection ends before `body_released` (a failed π_WIN, the client leaves, the time limit) | released; the abandon fee is kept, except when the deposit is charged for it (below) |
| accepted, the connection ends before `body_released` with the sidecar's `fault` (`"upstream"`, `"node"`) or with its socket lost | released in full: not the client's doing |
| before `body_released`, the provider answered and closed (`upstream_closed_early` with response bytes) | released; the session fee is kept if still due |
| after `body_released` with no settlement | charged in full |
| settled 2xx | usage at the frozen rates (chat) or `msat_per_image × count` (images), plus the session fee if still due |
| settled error head | 429/503 and 401/402/403: the session fee if still due; any other 4xx: the abandon fee; other 5xx: the reservation |

The session fee is "still due" until the connection's first settlement.

**Connection deposit.** Reserved at the `setup` from its credential (`ready.deposit_msat`), released by the
connection's first settlement (`deposit_released_msat` in that receipt). A connection that ends with no
settled request, first matching row:

| # | How the connection ended | Deposit | `reason` |
|---|---|---|---|
| 1 | the setup was refused before the sidecar was dialed | never reserved | (the `error`) |
| 2 | no session slot, the sidecar unreachable, or it refused the setup | released | `not_started` |
| 3 | the sidecar reported `fault: "upstream"` (the provider unreachable, `h2` not selected, framing `"2"` withdrawn) | released | `provider_unreachable` |
| 4 | the sidecar reported `fault: "node"`, or its socket ended without `error` or `closed` | released | `sidecar_failure` |
| 5 | the provider closed the open, idle connection before any request (`closed`, `upstream_closed`, without `after_client_frames`) | released | `provider_closed` |
| 6 | the node refused a request of this connection with a 5xx, or a settlement's billing write failed | released | `node_failure` |
| 7 | a request was written in full (`body_released`) and never settled | released (the reservation is charged) | `request_received` |
| 8 | the provider answered a request and closed before its body was complete | released (the request keeps the session fee) | `provider_refused` |
| 9 | a request was accepted and the connection ended before its `body_released` for any other reason | **charged**; the reservation is released in full | `request_abandoned` |
| 10 | no request in flight for `idle_timeout_s` | **charged** | `idle` |
| 11 | `head_written` not reached within 600 s | **charged** | `setup_timeout` |
| 12 | anything else: the client left, a failed handshake or π_NK, a protocol error, the provider closing during the handshake or after the client's control frames (`after_client_frames`), only refused requests | **charged** | `unused` |

A refused request (4xx) by itself costs nothing; the connection stays, and the deposit follows how the
connection ends.

```
{"type":"closed"|"error", …,
 "deposit":{"sid","msat","outcome":"released"|"charged","reason","cost_msats","balance_msats","time"},
 "deposit_json":<the signed bytes>,"deposit_sig":<hex>,"sig_scheme":"schnorr-secp256k1"}
```

| `deposit` field | Meaning |
|---|---|
| `sid` | the connection (`null` when the sidecar never sent `ready`: rows 2 and 3 before it) |
| `msat` | the deposit that was reserved (`ready.deposit_msat`) |
| `outcome` | `"released"` or `"charged"` |
| `reason` | the row's `reason` above |
| `cost_msats` | what the credential paid for it: `msat` when charged, `0` when released |
| `balance_msats` | the credential's balance afterwards (`null` if the key is gone) |
| `time` | Unix seconds |

`deposit_json` is the canonical JSON of `deposit` (keys sorted, no whitespace), `deposit_sig` the node's
BIP-340 signature over its SHA-256, as for a receipt. Before `ready` the client verifies it with the key of
the signed offer. An offer with `connection_deposit_msat: 0` reserves nothing and reports nothing.

**Order at a connection's end.** The node first decides the deposit, then finalizes a request still in
flight, then sends the last frame; a client that is already gone changes none of it. A client that leaves
is never row 4: that row needs the sidecar's socket to end while the client's is still open.

## 13. Conformance: what "done" means

1. Gates, all against a real provider with a real key, nothing announced: sidecar + reference client
   (honest cases for both framings; the attacks: hidden request in a body record, TLS padding shift, wrong
   suffix, wrong path, usage replay across requests, a `Proven`/v2 2PC peer, a v2 socket); node (the money
   outcome of every case in the node's database, including every deposit outcome); SDK; routstrd (curl
   through the local API: sequential, burst, forced `"1.1"`, fallback from a failing `"2"`); browser
   library and PWA.
2. Measurements for both framings: bytes each way and time to first token, cold, armed and on an open
   connection, on loopback and on shaped links (2/50 and 2/10 Mbit/s).
3. Unit tests in every repository; the statement tests (`zkbench`), the 2PC tests (`twopc`).
4. Documents: this file with §12 complete; the paper and its PDF; `docs/TWOPC-DESIGN.md`,
   `docs/TWOPC-NODE-GARBLING.md`, `docs/APPROACH.md`, `docs/ONE-PAGER.md` (+ PDF), `docs/ADVERSARIAL-QA.md`,
   `docs/SETUP.md`, `docs/CONFIDENTIAL-IMAGES.md`, `AGENTS.md`; the routstr-core, SDK and routstrd docs.

## Changes from the 2026-11-11 draft

| Change | Where |
|---|---|
| §12 is the wire reference; the prototype notes are removed | §12 |
| `http` is the string `"2"` or `"1.1"` in every message (setup, ready, attestation, usage, receipt) | §12 |
| a refused request does not use up its number `n`; `offer_changed` is a `request_refused`, not an error | §3.3, §12.4 |
| framing `"1.1"`: `request_ok` carries `head_len` (`ready` has none); the attestation is sent when the provider closes, before the disclosure; the error head is `disclose_head` with π_C3S | §3.5, §12.7, §12.8 |
| `h2.idle_secs` and `h2.kinds` are part of the block; `max_lifetime_s` replaces the fixed 3600 s | §2.1, §12.1 |
| what counts as a failed HTTP/2 open (N cannot see GOAWAY); the `settings_seen` end does not count and charges the deposit | §2.1, §5.6 |
| `closed` reasons `max_bytes`, `ended`; error `code`s | §3.6, §12.9 |
| round trips: +2 in the handshake call, +0.5 in the application call; where A3 runs | §4 |
| the disclosure start, frames of other streams in a tail, the probe stream | §5.4 |
| default deposit max(abandon fee, session fee, 1000 msat); a provider closing during the handshake is charged | §8.1 |
| session fee due once per connection at the first settlement; reservation formula; deposit instead of abandon fee before the first settlement | §8.3 |
| the paper's §2, not §3 | §1 |
| the node's exact `receipt`, `attestation` and `deposit` fields; the node's own `error` frames and `fault: "node"`; the order at a connection's end | §12.8, §12.9, §12.10 |
| the deposit outcome is also on the `error` of a setup refused after the deposit was reserved (row 2) | §12.9 |
| a request in flight when the sidecar reports a `fault` (or its socket is lost) before `body_released` is released in full, no abandon fee | §12.10 |
| N relays `upstream_closed_early`; a framing-`"2"` `request` before `head_written` is refused by the node itself | §12.9, §12.4 |
| the Nostr listing's tag is `["confidential","3"]`; the `confidential_upstream` field of `/v1/models` | §12.1 |
| a long body is proven in several disjoint π_WIN batches, none of its records written before the last verified | §5.3, §12.6 |
| no client WINDOW_UPDATE | §5.1, §12.6 |
| late probe-stream frames are skipped by the tail grammar; an error head may follow stream-0, own-stream WINDOW_UPDATE and probe frames in its record; H9 | §5.4, §5.6, §12.8 |
| request-offer age (prices end 10 min after the offer stops being served); security-relevant offer changes retire live connections | §3.3 |
| `after_client_frames`; `evicted`; the per-address total and the eviction of idle used connections; 8 refused requests in a row; recurring cost | §8, §12.9, §12.10 |
| the `split-public-1` statement: the inner-digest message rule, assumption (3), the idealized 3-bit model, label-check pairs augment the report hash | §4 |
| privacy: linkability and its off switches, body padding (off by default), residual risks 7-10 | §1, §9.1, §9.3, §10 |
| a cancelled request cannot lend its credential reference (the attack and why each form fails) | §5.3.1 |
| the proof channel's top-up between requests (channel version 2: `topup`, `TopupGrant`, step, bounds, a request waits for it); chain cp's mux cap 512 MiB | §8.5, §9.2, §12.2 |
