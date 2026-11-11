# Protocol v3 (draft): one two-party handshake per connection, not per request

Status: **decided and built, 2026-11-11.** This file is the analysis that led to protocol v3 and is kept
as the reasoning; it is not the specification. **The normative text is `PROTOCOL-V3.md`.** Where the two
differ, `PROTOCOL-V3.md` wins. What was decided:

- **Proposal A (§3) and proposal B (§4) are combined as protocol v3.** A: one two-party handshake per
  HTTP/2 connection, the credential written once in epoch 0 and named by HPACK index afterwards (framing
  `"2"`). B: the smaller key schedule, in the variant with **public inner states** ("public IS": the inner
  HMAC states are public outputs and the inner digests are computed in the clear; `split-public-1`, 22
  garbled compressions, 16.38 MB down). The variant that proves the inner digests in zero knowledge was
  not adopted.
- **HTTP/1.1 stays as framing `"1.1"`** inside the same connection lifecycle, for providers without
  usable HTTP/2, and as the client's fallback on the same node.
- **v2 is retired.** Nodes and clients speak v3 only (`upgrade_required`, `node_protocol_outdated`); §7's
  "v2 stays for HTTP/1.1-only providers" was replaced by framing `"1.1"`.
- The statement called π_REQ below was built as **π_WIN** (several windows over several records) and also
  replaces π_C2S. The connection deposit, the per-request reservation, the idle rule and `reuseScope` are
  as proposed in §3.3 and §3.5, with the details in `PROTOCOL-V3.md` §8 and §9.
- Of the live checks listed as "Not checked yet" in §3.6, these were done against Venice: a KeyUpdate on
  an HTTP/2 connection is accepted, `HEADER_TABLE_SIZE = 0` is honoured, an index-only `authorization` is
  valid after 150 s of idle, the probe request followed by RST_STREAM loads the table, and no credential
  bytes appeared in eight response paths. Not done: a second provider; the provider's idle limit and
  GOAWAY behaviour beyond what the node's own idle timeout and `max_requests` cover.
- Still open from §8: external review of the new statement, the frame rules and the key schedule; a
  second provider.

The text below is unchanged from the proposal, so its "not implemented", "suggested" and "open" wording
describes the state before the decision. Baseline at the time: protocol v2.
Baseline: protocol v2 as in `docs/TWOPC-DESIGN.md`, `docs/TWOPC-NODE-GARBLING.md` and `paper/paper.md` §4-§6.

## 1. Summary

- Pre-warming exists because v2 pays a full two-party key schedule (22 MB down, 1.2 MB up, 5-20 s on a home
  link) for **every request**, and the result is single-use. The cost itself is not the problem; paying it
  per request is.
- For a provider that authenticates with a static bearer key, the 2PC per **TLS connection** cannot be
  avoided without giving up P1 (§2). No other primitive I looked at removes it (§6).
- It can be paid once per connection instead of once per request. Over HTTP/2, N writes the credential once
  in epoch 0, which puts it in the server's HPACK dynamic table. Every later request header block, written
  by C, refers to it by a one-byte index. C never holds the key and N never writes again. **This works on
  Venice today** (§3.6).
- The remaining per-connection 2PC can be roughly halved (22 MB to about 11-13 MB) by garbling only the
  compressions whose inputs nobody may know, and moving the rest to the existing ZK system (§4).
- With both, speculative pre-warming is no longer needed for a client that is already talking to a node:
  the second and later requests cost no 2PC, no TLS handshake and no garbled tables. A cold first request
  costs about half of today's. An optional pre-warmed connection becomes generic: it is no longer tied to a
  model, a `max_tokens` value, a body length or a request kind, and it holds no reservation.
- The price: an HTTP/2 framing layer in the sidecar and all three clients, one new proof statement, a
  reworked usage anchoring, and one privacy regression that the client must manage (requests on one
  connection are linkable for the provider, §5).

## 2. What v2 pays for, and what cannot be removed

Why the 2PC exists at all:

- TLS 1.3 derives every client application key from one chain: `MS → c_ap_0 → c_ap_1 → …`. Whoever holds
  `c_ap_i` holds every later epoch.
- N needs one place to write the credential under a key C does not know (P1 against a C that sees N's
  egress). C needs the body and the response under keys N does not know (P2).
- So the split must happen at `c_ap_0`: N gets `K_0, IV_0`, C gets `c_ap_1` and `s_ap_0`, and nobody may
  hold `Z`, `HS`, `MS` or `c_ap_0`. Computing a hash chain over values nobody holds is a two-party
  computation. This is inherent for any design in which the credential travels as a secret inside the TLS
  stream that C terminates.

Why it is paid per request in v2:

- HTTP/1.1 puts the `Authorization` header in every request head. On a kept-alive connection the second
  head would have to be written by N after C's first body, in an epoch C already owns. N can write only in
  epoch 0, so v2 uses `Connection: close` and one connection per request.

What pre-warming costs because of this (all from the paper and `APPROACH.md`):

| Cost | Where it comes from |
|---|---|
| 22 MB node egress and 0.5 s node CPU per request, used or not | single-use tables |
| An armed session is bound to (node, model, `max_tokens`, credential) and a body-length bucket, with JSON padding | the reservation is made at setup, and the HTTP/1.1 head carries `Content-Length` |
| A full-context reservation (about 120-160 sats) held per armed session | same |
| Abandon fee, per-address unused-session caps, the pending pool | armed sessions are free to waste otherwise |
| Armed sessions expire after 480 s; an idle client holds none; the browser holds one | they pin node resources |
| Image sessions are never armed; a cold image request sets up about 26 MB | the setup names variant and count |
| Mispredictions fall back to a cold path of 5-20 s (a minute on a bad downlink) | prediction |

## 3. Proposal A: credential by reference (HTTP/2, HPACK)

### 3.1 Mechanism

HPACK (RFC 7541) lets a client add a header field to a per-connection dynamic table held by the server, and
refer to it later by index. The reference is one byte and does not contain the value.

- Epoch 0 (N, under `K_0`, as today): the HTTP/2 client preface, a SETTINGS frame, a connection
  WINDOW_UPDATE, and one HEADERS frame whose block contains `authorization: Bearer <key>` as a *literal with
  incremental indexing*, without Huffman coding (so the key sits at fixed byte positions and π_NK works as
  it does now). Then the KeyUpdate.
- Epoch 1 onwards (C, under `c_ap_1`): every request is a HEADERS frame that names `authorization` by its
  dynamic-table index (62 for the first entry), followed by DATA frames. C can use the credential and
  cannot read it.

What N's epoch-0 HEADERS frame belongs to is a design choice:

1. *A throwaway stream*: a cheap authenticated GET (or HEADERS followed by RST_STREAM in the same flight).
   The connection is then generic. This is the variant that makes a pre-warmed connection independent of
   the request. To be tested: that a reset stream's header block still updates the table (the RFC requires
   the block to be decoded) and that the provider's response to the throwaway request reflects nothing
   (profile item 8).
2. *The first request's head*: one round trip less on a cold start, but epoch 0 then fixes the path.

### 3.2 What C must now prove

In v2, N bounds C by byte counting: one request, `Content-Length` bytes, `Connection: close`. On HTTP/2
that is gone. A C whose records N cannot read could open a second stream, or send a HEADERS frame to another
path (key management, billing) using the indexed credential. So N must know the *framing* of everything C
writes, without learning DATA payloads:

- C sends one HTTP/2 frame per TLS record (a frame of at most 16 375 payload bytes fits a record).
- N holds every record of a request until **π_REQ** verifies. π_REQ generalises π_C2S: same witness
  (`c_ap_1`), same CTR-only decryption of ciphertext N took from its own relay, same one-bit result, but
  over several byte ranges:
  - the HEADERS record equals the public header block in full (method, path, authority, content type, the
    index reference; no secrets, and literals *without* indexing so the table never changes);
  - the first 9 bytes of every DATA record equal the frame header N expects (length = record length,
    type DATA, the stream id, END_STREAM only on the last);
  - the last record's payload ends in the canonical suffix, as today.
- Cost: one AES block per body record plus the head and suffix blocks. A 1 MB body is 64 records, about
  0.4 M AND gates in QuickSilver, against 0.24 M for today's π_C2S; the 8 MiB cap is about 512 blocks.
  It scales with the body at one block per 16 KB. To be measured.
- Control frames C must send (SETTINGS ACK, PING ACK, WINDOW_UPDATE, RST_STREAM to cancel) are public
  content. C proves each against an allowed form; N tracks nothing but their type and stream.
- Because N now holds the whole body until the proof, **profile item 4 (no processing before the complete
  body) is no longer needed**: the provider sees nothing of a request before π_REQ.

One complication: the provider's initial stream window was 65 536 bytes in the live check. A body larger
than the window must be released in step with the server's WINDOW_UPDATE frames, which only C can read. C
tells N how far to release (C gains nothing by lying; its own request stalls or fails). The cost in round
trips for large bodies is unknown and must be measured.

### 3.3 Requests on a live connection

1. C sends `request {kind, model, max_tokens | variant, count, offer_sig, auth}` on the control channel. N
   validates and reserves exactly as in v2's setup. **The reservation is made here, per request**, not when
   the connection is set up.
2. C sends the records. N buffers them (at most the declared body, as now).
3. π_REQ on the session's proof channel. N releases the records.
4. The response streams to C under `s_ap_0`.
5. Disclosure and π_C3S, settlement, signed receipt: as today, with the anchoring of §3.4.

No 2PC, no handshake, no tables. Against today's armed path this also removes the relayed TLS handshake and
the online 2PC phases (about 0.5 s at 80 ms RTT). The proof channel lives as long as the connection and
tops up its correlations when idle, so there is no per-request OT setup either.

### 3.4 Usage anchoring

v2 anchors the usage event at the end of the transcript, which is the end of the connection. With several
requests per connection:

- **Sequential requests only** in the first version: N does not release request *k+1* before request *k*
  is settled. N knows the server-ciphertext offset at which it released request *k*; every server byte from
  there until the disclosure belongs to request *k* or is a control frame.
- C discloses the tail of that interval, including the HTTP/2 frame headers (they replace today's chunk
  framing in R). The live check shows the shape: a DATA frame with the usage event, a 14-byte DATA frame
  with `data: [DONE]`, and an empty DATA frame carrying END_STREAM. The END_STREAM frame header names the
  stream id, which N knows from π_REQ, so the event is bound to the request by more than its position.
- A usage event from an earlier, cheaper request on the same connection lies before the release offset and
  cannot be presented.
- Still to argue: that client-controlled text cannot produce bytes that parse as a frame header followed by
  a usage event inside one DATA payload (the same kind of argument as residual risk 13; JSON escaping of
  control bytes is what it rests on).
- Parallel requests use parallel connections, each with its own 2PC. Interleaved streams on one connection
  would need a proof over every server frame header (thousands of AES blocks per streamed response). Not
  proposed.

The attestation becomes per request (interval hashes and record counts) plus a connection-level part (sid,
certificate-chain hash, transcript hashes, `c_commit`).

### 3.5 What this does to pre-warming

| | v2 | v3-A |
|---|---|---|
| 2PC per request | 1 | 1 per connection; 0 for a request on a live connection |
| Reservation while waiting | full context, per armed session | none; a small connection deposit if the node wants one |
| What a warm object is bound to | node, model, `max_tokens`, credential, body-length bucket | node and provider host |
| Images | never armed | same connection as chat (the path is in C's header block) |
| Body padding | to the bucket | none (HTTP/2 has no `Content-Length` to fix in advance) |
| Prediction | per key, by traffic | "is this client active" |
| Provider connection held while idle | no | yes, one per live connection |

The last row is the trade. v2 deliberately holds no provider connection for an armed session. v3-A holds one
idle HTTP/2 connection per active client, with an idle timeout at N. A client that wants zero cold starts
can still open a connection speculatively; it is the same object, and it is useful for any request.

DoS changes shape: the expensive step (tables) happens once per connection, so the abandon fee becomes a
connection fee or deposit, and the per-address cap counts connections. Per-request work for N drops to a
reservation, buffering and two proofs.

### 3.6 Live check (2026-11-11, api.venice.ai)

A raw HTTP/2 client (Python `ssl`, `hpack`, `hyperframe`), one connection:

| Step | Result |
|---|---|
| ALPN `h2` over TLS 1.3 | negotiated |
| Server SETTINGS | MAX_CONCURRENT_STREAMS 256, INITIAL_WINDOW_SIZE 65 536, MAX_FRAME_SIZE 16 777 215; no HEADER_TABLE_SIZE, so the default 4096 |
| GET on an authenticated path, no `authorization` | 402 |
| Same, literal `authorization` with incremental indexing | 200 |
| Same, header block of 5 bytes, index references only, key bytes absent | 200 |
| Same, by index, after 150 s idle | 200 |
| Streamed chat completion, credential by index, body in two DATA frames | 200; DATA frames 367, 173, 1509, 14, then 0 bytes with END_STREAM; the usage event and `data: [DONE]` at the tail |

Not checked yet:

- a client KeyUpdate on an `h2` connection with the pinned suite and group (the check negotiated
  AES-256-GCM because it did not pin; the handshake and KeyUpdate are below ALPN, so the v2 results should
  carry over, but that is an expectation, not a measurement);
- the idle limit, and when the edge sends GOAWAY (after how long or how many requests);
- HEADERS followed by RST_STREAM as the table-loading step;
- window updates for large bodies;
- any second provider. HPACK indexing is mandatory for an HTTP/2 server unless it advertises a table size
  of 0, so this is a profile item ("HTTP/2 with a dynamic table of at least ~128 bytes"), not a provider
  feature. A provider that speaks only HTTP/1.1, or sets the table to 0, stays on the v2 flow.

## 4. Proposal B: a smaller two-party key schedule

Independent of A, and useful for HTTP/1.1 providers too. Two changes, both known ideas, neither built here.

**B1. Use the wire labels as proof commitments (drop h1, h2, hk).** This is "cut 3" of
`TWOPC-NODE-GARBLING.md`. With free XOR, C's active label of a wire is `k_w ⊕ z_w·Δ_A`: an IT-MAC on the
wire's value under N's key. C's output wires for `c_ap_1` and `s_ap_0` are therefore already QuickSilver
commitments towards N, and N's outputs `K_0, IV_0` are committed towards C under Δ_B through the
authenticated masks. The proofs can take their witnesses from there, and the three SHA-256 anchors leave
both the 2PC and the proofs. 31 → 28 compressions.

**B2. Garble only what nobody may know.** `HMAC(k, m) = f(OS_k, f(IS_k, m))`, where `IS_k`, `OS_k` are the
compression states after the key pads. Every HKDF-Expand-Label message in the schedule is public. If the
circuit reveals `IS_k` to one party, that party computes the inner digest locally and proves it in ZK
against the commitment from B1 (a few bits per AND gate instead of 33 bytes), and the digest re-enters the
garbled circuit as an input whose labels are that same commitment. DECO uses the inner-state reveal for the
TLS 1.2 PRF. Where the output of an HMAC goes to one party anyway (`c_hs`, `s_hs`, `K_0`, `IV_0`), `OS_k`
can go to that party and the outer compression leaves the circuit too.

My count of what stays garbled (to be confirmed by building the circuits):

| | v2 | B1 + inner digests in ZK | + outer states to N where N owns the output |
|---|---|---|---|
| Phase A | 14 | 10 | 8 |
| Phase B | 17 | 9 | 7 |
| Total compressions | 31 | 19 | 15 |
| Download at today's 33.6 B per AND | 22.1 MB | about 13.5 MB | about 10.7 MB |

Caveats:

- Revealing `IS_k` to C and `OS_k` to N is safe only if the compression function keyed through its chaining
  input is a PRF and neither party ever gets the other half's inputs (C must never send N the inner digest
  for a label whose output is C's or nobody's). This needs its own written argument, and review.
- A party that supplies a wrong inner digest could turn one HKDF label into another (for example make N's
  "K_0" equal the first bytes of `c_ap_1`). The ZK proof of each digest against the committed state is what
  prevents this; it is not optional.
- More reveal points mean more observable abort outcomes. The selective-failure bound grows from log2 7
  to perhaps 3.5-4 bits per session. It stays on fresh, single-use values.
- More online round trips per phase (the circuit pauses for each digest). At 80 ms RTT that is a few
  hundred milliseconds, at connection setup only if A is in place.
- `TWOPC-NODE-GARBLING.md` estimated the cross-system link alone as weeks of work plus a new argument for
  review. B2 builds on it.

There is a floor. Tables cost 24.6 B per AND gate with any single-garbling scheme, and compressed
authenticated-garbling preprocessing (DILO, CWYY) shrinks the preprocessing, not the tables. Below roughly
10 MB per connection the only lever is fewer connections, which is A.

## 5. Guarantees: what stays, what changes

| | v2 | v3 (A + B) |
|---|---|---|
| P1 credential | C never holds `K_0` | same. In addition C can *use* the credential by index for the life of the connection, but only in header blocks π_REQ has pinned. HPACK matches whole fields only, so there is no compression oracle on the value. |
| P2 content | N sees ciphertext, sizes, timing, the suffix, the usage event | same, plus the HTTP/2 framing of C's records (lengths N sees anyway) |
| P3 integrity, model pinning | suffix held until π_C2S | suffix and all framing held until π_REQ; stronger, since no body byte reaches U before the proof |
| P4 billing | usage event at the end of the transcript | usage event at the end of the request's interval, bound to its stream id |
| P5, P6 | per session | per connection for the handshake; per request for sid, reservation, receipt |
| Residual risk 1 (N controls epoch 0) | any epoch-0 records | same class; N also sets the connection's SETTINGS and the first table entries |
| Selective failure | ≤ 2.8 bits per session | somewhat more per connection with B2, but far fewer 2PC runs |

New or changed risks:

1. **Linkability at the provider.** Requests on one connection are visibly from one client. Today each
   request is its own connection from N's address. The client must scope a connection to what is linkable
   anyway (one conversation, one agent run) and open a new one otherwise. For N the same holds when the
   client pays with fresh Cashu tokens per request: the connection links them.
2. **A longer-lived shared state.** One `s_ap_0`/`c_ap_1` chain now protects many requests. A compromise of
   C's process exposes the whole connection, not one request. (C can send KeyUpdates of its own to ratchet,
   as proven control records, if that matters.)
3. **Provider drift has a new surface**: HTTP/2 settings, table size, GOAWAY policy, window behaviour. New
   profile checks are needed (§7).
4. **Rate limits and GOAWAY** end a connection for reasons outside either party's control; the next request
   is cold. Clients must treat a live connection as a cache, never as a promise.

## 6. Other primitives considered

| Idea | Verdict |
|---|---|
| HTTP/1.1 keep-alive | N would have to write a head in a later epoch, which C already owns. Not possible without more 2PC. |
| Extend the 2PC by two epochs per further request (N gets `K_2`, C gets `K_3`, …) | 16 compressions, about 11 MB, per extra request. Half of today, still per request. Dominated by A. |
| TLS 1.3 resumption (PSK) for later connections | Whoever knows the PSK knows the session. The PSK would have to be shared and the resumed key schedule run in 2PC again, with more compressions (binder). Saves only ECtF. |
| Full authenticated garbling (WRK/KRRW, DILO, CWYY), DiStefano | Removes the selective-failure bits. Does not remove the tables; costs more preprocessing. No help for pre-warm. |
| Prove the garbling in ZK | 16.8 billion AND gates (already rejected in `TWOPC-NODE-GARBLING.md`). |
| Cut-and-choose over seeds | The one evaluated circuit is still sent in full. Covert security only. |
| Secret-sharing MPC over silent OT (GMW style) | A few bits per AND gate, but one round per AND depth: thousands of round trips for a SHA-256 chain. |
| Dual execution with B1/B2 | About 10-13 MB each way. The upload is what made dual execution unusable on home links. |
| v1 (no 2PC) with a patch for the egress observer | If C knows the record key, the ciphertext is the credential. Nothing on N's side of the wire fixes that. |
| MPC-TLS over the payload | Cost grows with the payload, no streaming (paper §9). |
| TEE | A stated non-goal. |

**Auth classes where no 2PC is needed.** These depend on how a provider authenticates, so they can only ever
be optional fast paths, never the design (the protocol must work with any OpenAI-compatible upstream):

- *Signed requests* (SigV4-style: the signature covers a hash of the body). C runs plain TLS alone. N signs
  the canonical request and never puts a secret on the wire. The suffix needs no ZK at all: C reveals the
  SHA-256 chaining state after its private prefix, N finishes the hash over the public suffix and signs
  that. Usage still needs π_C3S.
- *Ephemeral, capped credentials* (a provider that mints a one-request key with a spend limit). P1 becomes
  "C learns a key that is worthless after this request".

Neither applies to the bearer-key providers routstr targets today. They are listed because the offer could
name an `auth_class` later without changing the rest.

## 7. Suggested order of work

1. **Finish the live checks** (days): the items under "Not checked yet" in §3.6, as new entries in
   `provider-profile-check.py`, and against at least one more HTTP/2 provider. If KeyUpdate on `h2`, the
   table-loading step or the connection lifetime fail, A is dead and only B remains.
2. **A, single request per connection.** HTTP/2 framing in the sidecar and the reference driver, π_REQ,
   the per-interval usage anchoring. This alone gives generic sessions (no model, cap or length binding,
   images armable) with v2's cost profile.
3. **A, sequential reuse.** Per-request reservation and settlement on a live session, connection deposit,
   idle and GOAWAY handling, client-side linkability scopes. This is the step that retires speculative
   pre-warming for active clients.
4. **B1, then B2**, in parallel with 2-3 if there is capacity; they touch `twopc` and `zkbench`, not the
   framing. Re-vendor to the web library after each.
5. SDK, routstrd and the browser library follow the driver. The offer gains `v = 3` and an `http` field;
   v2 stays for HTTP/1.1-only providers.

Each of 2-4 changes a security argument (π_REQ and framing; anchoring; the split HMAC), so each needs the
same adversarial gates as v2 and belongs in the external review that v2's garbling still lacks.

## 8. Open questions

- Does any provider behind a different edge (not Cloudflare) cap or disable the HPACK table?
- How long does an idle connection really live, and does the edge migrate or GOAWAY under load?
- Throwaway stream or first-request head in epoch 0?
- Is holding one idle provider connection per active client acceptable to node operators and to providers'
  connection limits, compared with 22 MB per request today?
- Can the frame-header argument for the usage disclosure be made as tight as today's end-of-transcript
  anchor, or should the server-side frame chain be proven for the last few frames?
- B2: is the PRF-with-revealed-half-state argument acceptable to a reviewer, or should only the
  conservative column (inner digests only, 19 compressions) be built?
