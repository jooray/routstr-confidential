# routstr-confidential protocol v3

2026-11-11. Normative specification. It replaces protocol v2. `PROTOCOL-V3-DRAFT.md` has the reasoning,
`PROTOCOL-V3-DESIGN.md` the prototype notes this was built from (its A.11 is the byte-level wire format of
the HTTP/2 prototype and stays valid except where this file says otherwise; it is folded into §12 here when
the implementation is complete and is then removed).

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

What does **not** change: the trust model and every guarantee of the paper's §3; the roles (C is the TLS
client of U, N relays records and writes the credential in epoch 0); ECtF and the joint P-256 share; the
node-only authenticated garbling construction; π_NK and π_C3S; the chat suffix and its offer block
(`docs/CHAT-SUFFIX.md`); image rules (`docs/CONFIDENTIAL-IMAGES.md`); the attestation and receipt signatures;
the usage-based settlement and the abort rules, read per request.

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
  100). `max_lifetime_s` 60..86400 (default 3600).
- The sidecar SHOULD stop offering `"2"` after 5 consecutive HTTP/2 connections fail before their first
  request's response began (ALPN not selected, the provider closing on the connection head, GOAWAY), log
  it, and offer it again after 10 minutes. This protects clients from a provider that changed behaviour.
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

- ALPN: framing `"2"` exactly `h2`, and N requires EncryptedExtensions to select it; framing `"1.1"` exactly
  `http/1.1` or none, as v2.
- C gets `c_hs`, `s_hs`, `s_ap_0`, `c_ap_1`; N gets `K_0`, `IV_0`. Anchors `h1 = SHA256(c_ap_1)`,
  `h2 = SHA256(s_ap_0)`, `hk` as v2.
- `c_commit`, π_NK over the connection head template of the framing, `release_head`; N writes the head
  record and a KeyUpdate in one write; `head_written`.
- C sends no record between its Finished and `head_written`.

### 3.3 `request`

`C → N  {"type":"request","n":k,"kind":"chat"|"images","model", "max_tokens" | "variant","count", "body_len","auth","offer_sig","session_fee_msat","abandon_fee_msat"}`

- `n` = previous `n` + 1, first 1. One request at a time.
- The node does what a v2 setup did: the model is served confidentially and priced by the named offer, the
  fees are echoed, the credential is validated (it may differ from the setup's), and the request is
  **reserved**: chat, a full-context prompt plus `max_tokens`; images, `msat_per_image × count`. The named
  offer's connection-level fields MUST equal those of the offer the connection was opened on, else
  `offer_changed` (C opens a new connection).
- `N → C  {"type":"request_ok","sid","n","suffix", "stream"?}`.
- **A refused request leaves the connection READY** (`{"type":"request_refused","n","status","reason"}`)
  when C has sent no record for it. C MUST wait for `request_ok` before sending records. (The prototype
  ended the connection; a 402 then cost a handshake.) In framing `"1.1"` a refused request 1 may be
  followed by another `request` 1 while the connection is still ARMED.
- The node remembers a signed offer for 10 minutes after it last served it **or while a connection opened
  on it is alive**, so a client that keeps a connection does not have to refetch the offer for it. Rates
  are frozen per request from the offer the request names; C SHOULD refetch the offer every 10 minutes and
  name the newest.

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
the attestation). Abort rules: v2's table with "session" read as "request" (`PROTOCOL-V3-DESIGN.md`, "Through
a node", Aborts).

### 3.6 End of a connection

`{"type":"closed","reason":"idle"|"max_requests"|"max_lifetime"|"upstream_closed"|"error_settled"|"done","deposit":{…}}`.
`done` is the normal end of a `"1.1"` connection. The `deposit` object is §8's outcome. Any protocol
violation or failed proof: `{"type":"error","status","reason"}` and the socket closes.

## 4. Two-party key schedule: `split-public-1`

Base: v2's node-only authenticated garbling (`docs/TWOPC-NODE-GARBLING.md`): N garbles with three-halves
tables, its wire masks are authenticated to C by IT-MACs over Ferret COTs, C checks every AND gate with a
salted 64-bit row before it uses an output. ECtF is unchanged.

Change: `HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))`, `f` the SHA-256 compression function. Every HMAC message of
the TLS 1.3 key schedule is public. The circuit computes only the pad states `IS_k`, `OS_k` of the four
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
  anything and aborts on a mismatch. This replaces v2's bare report hash, which N could test offline
  against candidates.
- The variant with zero-knowledge proofs of the inner digests (`Proven` in the prototype) is not part of
  v3 and is removed from the code.
- **Version tag.** The first message of the 2PC channel in each direction is the ASCII tag
  `routstr-2pc/split-public-1\n`. A peer that reads another tag ends with `twopc_version_mismatch`.

Security statement (informal; no proof, external review outstanding, as for v2):

- A cheating node learns at most log2 8 = 3 bits per **connection** about fresh, single-use values (eight
  observable outcomes: the ECtF abort, an abort in each of the five stages, the server Finished failing,
  success), under v2's conditions.
- Assumptions beyond "HMAC-SHA256 is a PRF", for both parties, because both see `IS_k`: (1) `f` keyed by
  its chaining input is a PRF; (2) `OS_k` is pseudorandom given `IS_k`. These are the two assumptions of
  Bellare's HMAC proof (CRYPTO 2006), used directly.
- Round trips: +2 per call compared with v2 (each stage's public output must reach N before it sends the
  next stage's digest labels).

## 5. Framing `"2"` (HTTP/2)

### 5.1 Rules for everything C writes after the handshake

1. One frame per record. Inner plaintext = 9-byte frame header ‖ payload ‖ `0x17`, no TLS padding.
2. N writes a record to U only after a π_WIN that covers it has verified.
3. For each record π_WIN shows bytes `[0, 9)` equal the frame header N expects and the **last byte is
   `0x17`**; the header's length field equals `inner_len − 10`. (Without the last-byte check, TLS padding
   would move the frame boundary and hide a HEADERS frame in a later payload.)
4. Allowed frames: SETTINGS ACK, PING ACK, WINDOW_UPDATE on stream 0, RST_STREAM on the current request's
   stream (announced by a `ctl` message each); for a request, one HEADERS (END_HEADERS; the whole record
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
control with `release {n, upto}`; N never writes an unproven record nor beyond `upto`.

### 5.4 Usage disclosure, error head

- `disclose`: `R` runs from the usage event to the last server byte N has received, within the request's
  interval (server records with index ≥ `S_k`, the count when N wrote the request's first record). N
  parses text and frames alternately; the DATA payloads on the request's stream must be exactly
  `data: <usage JSON>\n\ndata: [DONE]\n\n` and the stream must end inside `R`. π_C3S, unchanged circuit.
- `disclose_head`: one complete HEADERS frame of the request's stream at byte 0 of a server record in the
  interval, π_WIN under `s_ap_0`, decoded with an empty dynamic table, `:status` 400..599. The connection
  closes after an error head is settled.
- Images: the response is one JSON body in DATA frames; C sends `accept` after END_STREAM. (Detail in
  `PROTOCOL-V3-DESIGN.md`, images section.)

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

N MUST end the connection if U's SETTINGS set `HEADER_TABLE_SIZE` below the size of the credential entry
(H3 at run time; C reports U's SETTINGS values in `settings_seen`, and a lying C only harms itself: its
next request is unauthenticated).

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

- `connection_deposit_msat` (signed offer; node setting, default = the abandon fee, at least the session
  fee) is reserved at the `setup` through the node's ordinary reservation path.
- It is **released when the first request of the connection reaches a settlement** (usage, `accept`, or an
  error head: any request the provider received).
- A connection that ends with no settled request: the deposit is **charged**, except when the end was the
  node's, the sidecar's or the provider's failure before C could have had a request settled (2PC failure
  on N's side, the provider refusing the handshake or the connection head, sidecar loss): then released.
- The outcome is reported in `closed.deposit = {"msat", "outcome": "released"|"charged", "reason"}` and,
  when it is released by a settlement, in that request's receipt (`deposit_released_msat`).
- An idle connection after its first settlement holds no reservation.

### 8.2 Idle

The node closes a connection with no request in flight `idle_timeout_s` after `head_written` or the last
settlement (`closed`, reason `idle`). The client's pool uses a shorter idle time than the node's.

### 8.3 Fees

- `session_fee_msat` pays for the two-party handshake and is charged **once per connection**, with the
  settlement of request 1. Requests 2… pay usage only.
- `abandon_fee_msat` per request, v2's rule (kept when a reserved request is dropped before
  `body_released`).
- Everything else per request, as v2 per session.

### 8.4 Limits

A connection takes one of the node's session slots for its life and counts against its address's
unused-connection limit until its first `body_released`.

## 9. Client behaviour

### 9.1 Pool (framing `"2"`)

- Key: (node, credential, `reuseScope`). Requests on one connection are linkable for the provider (same
  TCP connection, same TLS session), as requests under one API key already are for a non-confidential
  client. `reuseScope` is the caller's tool to separate what must not be linked; a scope never shares a
  connection with another.
- A request takes an idle connection of its key, else opens one (up to `maxConnections` per key,
  `maxTotal`). Parallel requests use separate connections.
- routstrd derives `reuseScope` from its local client (the local API key), default on
  (`confidentialUpstream.http2.reuse: "per-client" | "shared" | "none"`).
- One-off Cashu bearers: framing `"1.1"` (a connection per token), or `"2"` with `reuse: none`.

### 9.2 Pre-warm

One mechanism: an **armed connection** (deposit held, 2PC preprocessing and key share done, no provider
connection), bound to the credential only.

- Framing `"1.1"`: as v2's armed sessions, minus the model, `max_tokens` and body-length binding and minus
  the full-context reservation.
- Framing `"2"`: the client MAY keep one armed connection per pool key while there is traffic and every
  open connection is busy, so that a burst does not wait for a 2PC.
- The pre-warmed proof channel holds correlations for π_NK and the first π_WIN and π_C3S; on a kept
  connection it is topped up while idle.

### 9.3 Checks C makes

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
| 5 | A fabricated error head would need a binary frame header at byte 0 of a server record in the interval | smaller than v2's equivalent |
| 6 | 3 bits per connection instead of 2.8 per request | fewer connections than requests |

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

Until the implementation is complete: `PROTOCOL-V3-DESIGN.md` A.11 (framing `"2"`, including "Through a
node") with the changes of this file:

| Change | Where |
|---|---|
| `setup.v = 3`, `http` a string, `auth`/`offer_sig` as before; `ready.deposit_msat` | §3.1 |
| deposit at the setup; `closed.deposit`; receipt `deposit_released_msat` | §8.1 |
| `request_refused` keeps the connection; C waits for `request_ok` | §3.3 |
| offer kept alive by its connections; `offer_changed` | §3.3 |
| session fee once per connection | §8.3 |
| framing `"1.1"` uses the same `setup` / `request` / `body_released` / `closed` messages; π_WIN replaces π_C2S | §3, §6 |
| `settings_seen`, table-size guard | §5.6 |
| 2PC tag and `split-public-1` | §4 |
| upgrade errors | §11 |

The implementer replaces this section with the complete message reference (every message, field, limit and
error reason for both framings, sidecar-facing and client-facing) and removes `PROTOCOL-V3-DESIGN.md`.

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
