# The confidential-upstream approach

*2026-10-10, rewritten 2026-11-11 for protocol v3. This document is the engineering overview. The normative specification is `../PROTOCOL-V3.md` (wire format in its §12); the reasoning behind v3 is in `../PROTOCOL-V3-DRAFT.md`, the two-party handshake in `TWOPC-DESIGN.md` and `TWOPC-NODE-GARBLING.md`, the threat model and guarantees in the paper (`../paper/paper.md`). The authors' original working documents (`original/*`) are local only and not published.*

*Protocol versions. The protocol is **v3**: a two-party TLS handshake per **connection**, and one or many requests on that connection. **v2** (one two-party handshake per request, HTTP/1.1 only) and **v1** (the client ran the handshake alone) are retired. v2's code is on the branches `twopc-v2` (this repo) and `confidential-2pc` (routstr-core, routstr-sdk); v1's on `v1-poc`. What changed from v2: `V2-V3-ONE-PAGER.md`. From v1 to v2: `V1-V2-ONE-PAGER.md` (historical).*

## The problem

A routstr node forwards a user's LLM request to an upstream provider (Venice, OpenRouter, …) using the node's own API key. Without this protocol the node is a full man-in-the-middle: it reads every prompt, it can alter requests and responses, and the user must trust its accounting. MPC-TLS ("verified mode", TLSNotary) fixes only part of this, at a high cost per request, and it still cannot hide the prompt from the node.

## The idea

Flip the TLS client: the **user (C) is the TLS 1.3 client of the upstream (U)**, and the node (N) relays TLS records. Three mechanisms make this safe for both sides.

1. **A two-party handshake.** C and N run the TLS 1.3 key schedule as a two-party computation over a joint P-256 key share. C gets the handshake secrets, the response secret `s_ap_0` and its own write secret `c_ap_1`. N gets only the key of the first client key epoch, `K_0, IV_0`. Nobody holds the master secret.
2. **The node writes epoch 0, the client writes everything after it.** N writes one record with its API key under `K_0`, then a TLS KeyUpdate. From then on the client's direction runs under `c_ap_1`, which only C holds. C cannot decrypt the credential record even if it records the node's traffic, and N cannot read or change anything C writes or U answers.
3. **One-bit zero-knowledge proofs pin what each side wrote.** N proves its record matches the published template with only the key bytes free (π_NK). C proves that the public parts of its own records are what the offer says (π_WIN), and N holds C's records back until that proof verifies. C proves the provider's usage report (π_C3S), and the node bills from it.

There is no MPC over the payload. The cryptographic work is the key schedule (once per connection) and a few AES blocks per proof. Prompt and response are ordinary TLS at line speed.

v3 adds one thing to this: **the credential is written once per connection and reused.** With the HTTP/2 framing the head that N writes loads the credential into the provider's HPACK table, and each later request, written by C, names it by a one-byte index. So the two-party handshake is paid once per connection instead of once per request.

The three legs, to avoid confusion about "HTTP versions":

```
app ──HTTP/1.1, OpenAI API──► routstrd ──WebSocket──► node ──► sidecar ──TCP──► provider
                                 └────────── TLS 1.3, framing "2" or "1.1" ─────────────┘
```

The local OpenAI API of routstrd is unchanged. The framing is a property of the inner TLS connection only; an application never sees it.

## Properties

| Property | Mechanism |
|---|---|
| Credential confidentiality | C never holds `K_0`, the key of the record that carries the credential (two-party key schedule). With framing `"2"` C's requests name the credential by HPACK index; no HPACK encoding returns a stored value to the client (`PROTOCOL-V3.md` §5.5) |
| Content confidentiality | C alone holds the secrets of its requests and of the responses; N sees ciphertext only |
| Integrity of the request | N's head: content proven by π_NK (not the exact wire bytes, see Known limits). C's public parts (frame headers, the HTTP/2 header block, the suffix with model and caps) proven by π_WIN **before** N writes the record to U. Response GCM tags verified by C |
| Verifiable accounting | π_C3S binds the provider's usage event to the request; signed attestation and receipt per request |
| Upstream authenticity | C and N both verify the certificate chain, hostname, CertificateVerify and Finished |
| Freshness | The connection id binds fresh nonces; fresh TLS randoms; requests are numbered `(sid, n)` |

No trusted hardware, no enclave attestation, no model-weight proofs, no hiding of traffic volume: stated non-goals.

## Components

```
crypto/cu-crypto    Rust  TLS 1.3 key schedule, GCM record math (GHASH), RFC 8448 + NIST vectors
crypto/twopc        Rust  two-party key schedule split-public-1 (ECtF + node-only authenticated garbling),
                          cu-2pc binary for the client
crypto/zkbench      Rust  mpz2 VOLE-ZK circuits: π_NK, π_WIN, π_C3S; cu-prover, the pre-warmed proof channel
crypto/relay        Rust  cu-sidecar: connection state machine, TCP relay, handshake verification, the
                          connection head (HTTP/2 or HTTP/1.1), record hold, HTTP/2 framing and HPACK,
                          attestation. Settlement is in the node (Python)
crypto/client       TS    reference client: fork of @reclaimprotocol/tls + driver (spawns cu-prover, cu-2pc)
```

Integration:

```
routstr-core  Python   /v1/confidential/offer (Nostr-signed), WebSocket proxy to the sidecar, the connection
                       deposit, per-request reservation and settlement through the node's normal billing,
                       receipt signing, additive /v1/models field
routstr-sdk   TS       client/confidential/*: offer verification, connection and request driver, the
                       HTTP/2 pool, pre-warm, and a transport RoutstrClient uses instead of fetch()
routstrd      TS/Bun   config block (trusted hosts, node pins, prover path, pooling, pre-warm) and the
                       x-routstr-verify: confidential opt-in; fails closed (HTTP 400) when the mode is off
                       or the endpoint is not chat completions or image generation
```

Browser: the same client in WebAssembly (`routstr-confidential-web`, demo PWA `routstr-confidential-pwa`).

## The framing and how it is negotiated

A connection has one of two framings.

| | Framing `"2"` (HTTP/2) | Framing `"1.1"` (HTTP/1.1) |
|---|---|---|
| Requests per connection | up to `h2.max_requests` (default 100), sequential | exactly 1 |
| What N writes in epoch 0 | preface, SETTINGS, WINDOW_UPDATE, a probe request (a cheap authenticated GET) that carries the credential, RST_STREAM | the request head of request 1 with the credential |
| How a request names the credential | HPACK index 62, one byte | it is in the head N wrote |
| What π_WIN covers | each record's frame header and last byte, the whole HEADERS record, the suffix at the tail of the last DATA record | the final record = the suffix |
| When a request must be known | after the connection is ready | before the ClientHello (the head names path and `Content-Length`) |

Negotiation:

1. **The operator states it.** The sidecar offer file lists `"http": ["2", "1.1"]` in the operator's order of preference; `"2"` needs an `h2` block (`probe_path`, `max_requests`, `max_lifetime_s`). Nothing is probed or assumed. Absent: `["1.1"]`. `crypto/tools/provider-profile-check.py --h2` checks what framing `"2"` needs from a provider (H1–H8, `PROTOCOL-V3.md` §5.6) and is what an operator runs before listing `"2"`.
2. **The node signs it.** `GET /v1/confidential/offer` carries `v: 3`, `http`, `h2`, `twopc: "split-public-1"`, `connection_deposit_msat`, `idle_timeout_s` and everything v2's offer had (`upstream_host`, `head_template`, the `chat` block, `images`, `price_list`, fees, `max_tokens_cap`).
3. **The client chooses.** It verifies the offer (signature with a pinned node key, trusted upstream hostname, `v == 3`, a key schedule it implements, the `h2` block in range, the deposit at most its configured maximum) and takes the first entry of `http` it supports. `confidential.http` can force `"2"` or `"1.1"`; the default is `auto`.
4. **Fallback.** If an HTTP/2 connection fails before the body of its first request was released (handshake, ALPN, the connection head, the provider closing), the client marks `"2"` bad for this node for 10 minutes and serves the request on `"1.1"` on the same node, when the offer lists it. After a body was released there is no retry elsewhere. The sidecar itself stops offering `"2"` after 5 consecutive early failures and offers it again after 10 minutes.

## Connection lifecycle

One state machine for both framings (`PROTOCOL-V3.md` §3).

1. **Setup.** C sends `setup` with `v: 3`, the framing, a nonce, its node credential and the signature of the offer it verified. It names no model, cap, body length or kind. The node checks the framing is offered, the offer is one it signed, the credential is valid, and **reserves the connection deposit**; only then does it dial the sidecar. Not enough balance: 402, nothing garbled.
2. **Preprocessing and key share.** N garbles the key schedule and streams it to C; both run the joint P-256 key share. An **armed** connection stops here. The sidecar holds no provider connection yet, and an armed connection lives at most 10 minutes.
3. **Handshake.** C's ClientHello must carry exactly the joint share (ALPN `h2` for framing `"2"`); the sidecar dials the provider only now. The key schedule runs jointly in five stages. N verifies the certificate chain, hostname, CertificateVerify and both Finished messages; C verifies the same with its own TLS stack.
4. **Connection head.** N builds the head record under `K_0`, π_NK proves it against the template of the framing, and on C's `release_head` N writes it and a KeyUpdate in one write. C sends no record before `head_written`.
5. **Request.** C sends `request` with `n`, kind, model, `max_tokens` (or image variant and count), body length, its credential, the offer signature and the fees it accepts. The node does what a v2 setup did: it checks the model and price against the named offer, validates the credential and **reserves the request** (chat: a full-context prompt plus `max_tokens`; images: `msat_per_image × count`). It answers `request_ok` with the canonical suffix. A refused request (`request_refused`, for example 402) leaves the connection ready when C has sent no record for it. In framing `"1.1"` step 5 comes before step 3.
6. **Records, proof, release.** C sends the request's records. N holds them as the framing says, C proves π_WIN, N writes them to U and sends `body_released`. From here the reservation is at stake.
7. **End of the request.** Chat 2xx: C discloses the usage event, π_C3S, the node charges the usage at the frozen rates. Images 2xx: C sends `accept`, the node charges the flat price. Status ≥ 400: C discloses only the response head (π_WIN under `s_ap_0` on HTTP/2, π_C3S head mode on HTTP/1.1) and v2's error rules apply by status. N sends the attestation and the receipt, both per request and bound to `(sid, n)`.
8. **Next request or close.** Framing `"2"` returns to ready after a settled 2xx; an error head closes the connection. Framing `"1.1"` closes (`done`). The node also closes on idle, `max_requests`, `max_lifetime_s` or the provider closing, and reports the deposit's outcome in `closed`.

HTTP/2 rules for what C may write (`PROTOCOL-V3.md` §5.1): one frame per TLS record, no TLS padding; only SETTINGS ACK, PING ACK, WINDOW_UPDATE on stream 0, RST_STREAM on the current stream, and per request one HEADERS and its DATA frames; no KeyUpdate from C, no header block that changes the dynamic table, no second stream while one is open. Anything else ends the connection. Requests are sequential; parallel requests use separate connections.

## Key schedule: `split-public-1`

The construction is v2's node-only authenticated garbling (N garbles with three-halves tables, its wire masks are authenticated to C by IT-MACs over Ferret COTs, C checks every AND gate with a salted 64-bit row before it uses an output). The change is in what is garbled. `HMAC(k, m) = f(OS_k, pad(f(IS_k, m)))`, and every HMAC message of the TLS 1.3 key schedule is public. The circuit computes only the pad states of the four secret keys, the outer compressions and the three anchors. The inner state `IS_k` is a public output of its stage and both parties compute the inner digest in the clear; `OS_k` never leaves the circuit.

| | v2 | v3 (`split-public-1`) |
|---|---|---|
| Garbled SHA-256 compressions | 31 | 22 |
| Node → client | 22.12 MB | 16.38 MB |
| Client → node | 1.21 MB | 1.13 MB |
| Cold, simulated 2 Mbit/s up, 50 down | 7.42 s | 7.02 s |
| Cold, simulated 2 up, 10 down | 20.12 s | 15.61 s |
| Cold, local | 0.67 s | 0.45 s |
| Online round trips | 1 + 1 | 3 + 1.5 |
| Node peak memory per run | 517 MiB | 457 MiB |

New and mandatory: **label-check pairs**. For every output wire C reports to N, N sends in preprocessing the salted hashes of both candidate labels, and C checks its label against the pair before it reveals anything. A cheating node learns at most 3 bits per connection about fresh, single-use values (eight observable outcomes), under v2's conditions. Both parties see `IS_k`, so the argument uses two assumptions beyond "HMAC-SHA256 is a PRF": the compression function keyed by its chaining input is a PRF, and `OS_k` is pseudorandom given `IS_k`. There is no published proof and no external review (`TWOPC-DESIGN.md`).

## Money

Billing is the node's ordinary reservation and settlement path. The client's credential is its usual bearer (API key or Cashu token).

| Item | When | Amount |
|---|---|---|
| Connection deposit | reserved at the `setup` | `connection_deposit_msat` from the signed offer (node setting; default the abandon fee, at least the session fee and at least 1 sat) |
| Request reservation | at each `request` | chat: `max(min_request_msat, ⌈(prompt_limit·max(in, cache_write) + (max_tokens + margin)·out)/1000⌉)` with `prompt_limit` the model's full context; images: `msat_per_image × count` |
| Session fee | once per connection, with the settlement of request 1 | `session_fee_msat`; requests 2… pay usage only |
| Abandon fee | per request dropped after its reservation and before `body_released`, unless the deposit is charged for it | `abandon_fee_msat` |
| Usage | per settled chat request | the π_C3S-verified usage at the rates of the offer the request named, capped at the reservation |

The deposit:

- It is **released when the first request of the connection reaches a settlement** (usage, `accept` or an error head: any request the provider received). The receipt of that request says so (`deposit_released_msat`).
- A connection that was opened and ends with no settled request is **wasted**, and the deposit is **charged**: the client left, the idle timeout, `head_written` not reached within 600 s, a failed handshake or π_NK, a protocol error, only refused requests, or a request that was accepted and abandoned before its `body_released` (that request's reservation is then released in full). This is what makes an unused two-party handshake cost something.
- It is **released** when the end was not the client's doing: no session slot, the sidecar unreachable or failing, the provider unreachable or not selecting `h2`, framing `"2"` withdrawn, the provider closing an idle connection before any request, a node-side 5xx. It is also released when a request was written in full and never settled (the reservation is charged instead). The full table is `PROTOCOL-V3.md` §12.10.
- The outcome is signed by the node in the connection's last frame (`closed` or `error`, field `deposit`).
- After its first settlement an idle connection holds no reservation.

Rates are frozen per request from the offer the request names. The node remembers a signed offer for 10 minutes after it last served it or while a connection opened on it is alive. The connection-level fields of the named offer must equal those of the offer the connection was opened on, else `offer_changed` and the client opens a new connection.

The outcomes per request are v2's per session: the reservation is released if the provider never got the request (less the abandon fee) or refused it (less the session fee for a 429/503 or 401/402/403, the abandon fee for any other 4xx), and charged in full for another 5xx or when the client withholds its disclosure after the release. A usage event that names another model id is logged, not refused: π_WIN already bound the model.

Idle: the node closes a connection with no request in flight `idle_timeout_s` after `head_written` or the last settlement. A connection takes one of the node's session slots for its life and counts against its address's unused-connection limit until its first `body_released`.

## Latency: pooling and pre-warm

**Pooling (framing `"2"`).** The client keeps HTTP/2 connections open and reuses them. The pool key is (node, credential, `reuseScope`). A request takes an idle connection of its key, else opens one (up to `maxConnections` per key and `maxTotal`). Parallel requests use separate connections. The client's idle time is shorter than the node's, so the client closes first.

Requests on one connection are linkable for the provider: same TCP connection, same TLS session. Requests under one API key are already linkable for a non-confidential client. `reuseScope` is the caller's tool to separate what must not be linked; a scope never shares a connection with another. routstrd derives it from the local API key (`confidentialUpstream.http2.reuse: "per-client" | "shared" | "none"`, default per client). One-off Cashu bearers use framing `"1.1"` or `"2"` without reuse.

**Pre-warm.** One mechanism: an **armed connection** (deposit held, preprocessing and key share done, no provider connection), bound to the credential only. It is no longer bound to a model, `max_tokens`, a body length or a request kind, and it holds no full-context reservation.

- Framing `"1.1"`: armed connections play the role of v2's armed sessions.
- Framing `"2"`: a kept connection replaces pre-warming for a client that is already talking to a node. The client may keep one armed connection per pool key while there is traffic and every open connection is busy, so a burst does not wait for a 2PC.
- The pre-warmed proof channel holds correlations for π_NK and the first π_WIN and π_C3S; on a kept connection it is topped up while idle.

Measured on the final build (Apple M2 Max, provider Venice, `mistral-small-3-2-24b-instruct`, medians,
2026-11-12; time to first token from the connection's start, the claim of an armed connection, or the
request on an open one):

| | Data (up / down) | Loopback, through the node | 2/50 Mbit/s, 40 ms | 2/10 Mbit/s, 40 ms |
|---|---|---|---|---|
| Cold request, framing "2" | 2.63 MB / 17.97 MB | 1.38 s | 12.1 s | 18.9 s |
| Cold request, framing "1.1" | about the same | 1.52 s | 11.8 s | 19.2 s |
| Armed connection, "2" / "1.1" | 83 kB / 87 kB; 77 kB / 93 kB | 0.81 / 0.76 s | 1.43 / 1.38 s | 1.59 / 1.85 s |
| Request on an open HTTP/2 connection | 81 kB / 12 kB on its path (plus a 610 kB proof-channel top-up per ~1.6 requests while idle; before the top-up, up to 1.45 MB on the path) | 0.57 s | 0.92 s | 1.23 s |
| v2, pre-warmed session, for comparison | about 28 MB per request | 0.9–1.5 s | | |

(The shaped rows are the reference client against the sidecar through `shape-proxy.py`; the loopback row
goes through the node.) An image request on an open connection moved 36 kB up and the image plus about 9 kB
down (prototype). At 2 Mbit/s up the cold time is the 2.63 MB upload. Not measured yet: any of this from a
remote client against a deployed node `[TO MEASURE]`.

## Upgrade

v3 only. There is no v2 fallback in clients or nodes.

- A v3 node offers `v: 3`. To a socket with `v=2` (or none) it answers `{"type":"error","status":426,"reason":"upgrade_required","min_v":3,…}` and closes.
- A v3 client that reads an offer with `v < 3` does not use the node for confidential requests and reports `node_protocol_outdated` (routstrd: logged once per node per day, and in the error body when no other node can serve the request). It requests offers as `/v1/confidential/offer?v=3`, so an old node's access log shows that v3 clients are asking.
- The node's Nostr listing carries `confidential: 3`, so clients can filter before fetching offers.
- The 2PC channel starts with the tag `routstr-2pc/split-public-1`; a peer with another key schedule ends with `twopc_version_mismatch`.

Operator: update the node and the sidecar together; add `http` (and `h2`, after `provider-profile-check.py --h2` passes) to the sidecar offer file; set the deposit and the idle timeout or keep the defaults. Client: update routstrd (or the SDK, or the web library) and `cu-2pc`/`cu-prover`; no configuration change is needed. Steps: `SETUP.md`; side by side with v2: `V2-V3-ONE-PAGER.md`.

## Limits and timeouts

Both the node and the sidecar validate the `setup` and every `request` (model; `max_tokens` an integer in [1, cap]; body length in [1, 8 MiB]) and reserve before any record for it is accepted. Every refusal is an explicit `error` or `request_refused` frame.

| Limit | Value |
|---|---|
| setup frame after the socket opens | 15 s (sidecar), 10 s (node) |
| 2PC preprocessing and key share | 180 s |
| socket accept to `head_written`, armed time included | 600 s |
| `request_ok` to `body_released`; `body_released` to settlement | 600 s each |
| idle, no request in flight | `idle_timeout_s` |
| request body | 8 MiB |
| response | chat 64 MiB; images `images.max_response_bytes`; an HTTP/2 connection 1 GiB in all |
| π_WIN | 2 200 windows, 64 KiB of ciphertext per proof |
| requests per HTTP/2 connection, lifetime | `h2.max_requests` (1..1000, default 100), `h2.max_lifetime_s` (60..86400, default 3600) |
| connections | 32 per process; 12 unused per client address, counted until the first `body_released` |

## Status / evidence

- Built on the branch `v3-h2` here and `confidential-v3` in routstr-core, routstr-sdk and routstrd: the statement π_WIN, the sidecar's HTTP/2 mode, the reference driver, the node, the SDK pool and routstrd's pass-through. The repository `README.md` has the current state of each piece.
- Live against Venice: a TLS KeyUpdate on an HTTP/2 connection is accepted; `HEADER_TABLE_SIZE = 0` is honoured for response headers; a request that names `authorization` by index only is authenticated, also after 150 s of idle; no credential bytes appeared in eight response paths.
- Gates (`crypto/tools/`, each exits non-zero on any deviation): `provider-profile-check.py` (A1–A13; `--h2` for H1–H8; `--images` for I1–I9), `v3-h2-check.sh` (honest cases, attacks, against its own sidecar), `v3-h2-node-check.sh` (every case's money outcome in the node's database), `v3-h2-routstrd-check.sh` (through a scratch routstrd), `adversarial-model-swap.sh`, `stall-repro.sh`.

## Known limits

- **No external review** of π_WIN, the HTTP/2 frame rules, the usage interval rule or `split-public-1`. The garbler-only 2PC has no published proof. A cheating node can learn at most 3 bits per connection about single-use values, assuming ECtF's semi-honest share conversion leaks nothing beyond its outcome.
- **One provider tested** (Venice). The design is for any OpenAI-compatible upstream that meets the provider profile; framing `"2"` additionally needs H1–H8. A provider that changes its HTTP/2 behaviour breaks framing `"2"`; this is detected (the sidecar stops offering it, clients fall back to `"1.1"`).
- **Linkability.** Requests on one HTTP/2 connection are linkable for the provider. `reuseScope` separates them at the cost of more connections.
- N holds `K_0`, so it can write any number of epoch-0 records, not only the proven head. π_NK binds the head's content and length, not the exact wire bytes, which C cannot see. N could write another head of the same length (another account, another path for the probe, a header that changes how the provider handles the connection). Epoch 0 carries no client data, and with framing `"2"` C's own header blocks are proven in full.
- The provider's application could copy the request's `authorization` header into a response. This is the same condition on both framings (provider profile; H7).
- Interactive, designated-verifier proofs: N must be online and there is no artifact a third party can check.
- N sees timing and record sizes (the token-length sequence of a streamed response), the body length, the usage event, on an upstream error the status and response headers, and with framing `"2"` which requests share a connection.
- The client's TLS validator implements RFC 5280 path validation against the WebPKI roots; it does no revocation or certificate-policy checking.
- The sidecar trusts its peer to be the node. It holds the provider key but does not check client credentials (the node does, and reserves, before dialing it). Off loopback it requires the node's bearer token (`CU_SIDECAR_TOKEN` / `CONFIDENTIAL_SIDECAR_TOKEN`); the node→sidecar link is plain HTTP/WebSocket, so keep it on a private network and never publish the port (`SETUP.md`).
