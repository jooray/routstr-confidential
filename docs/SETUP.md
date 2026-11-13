# Trying confidential mode

Confidential mode lets a Routstr node serve your LLM request without seeing the prompt or the answer, and
without you ever being able to recover the node's provider API key. How it works:
[`paper/paper.pdf`](../paper/paper.pdf); the protocol: [`PROTOCOL-V3.md`](../PROTOCOL-V3.md).

This file describes **protocol v3**, the only protocol the current code speaks. What changed from v2, for
users and operators, on one page: [`V2-V3-ONE-PAGER.pdf`](V2-V3-ONE-PAGER.pdf) ([source](V2-V3-ONE-PAGER.md)).
In short: the expensive two-party handshake is paid once per **connection** instead of once per request,
and a connection to a provider that speaks HTTP/2 carries many requests. Operators: see "Upgrading from
v2" at the end.

This is **experimental**: the code lives on branches, not in Routstr releases yet, and the two-party
computation is not externally reviewed. Use small amounts.

| Repo | Branch (v3) | What |
|---|---|---|
| jooray/routstr-confidential | `main` | provers (`cu-prover`, `cu-2pc`), the node's sidecar (`cu-sidecar`), protocol, paper |
| jooray/routstr-sdk | `confidential-2pc` | the client transport |
| jooray/routstrd | `confidential-upstream` | the daemon (opt-in header, config) |
| jooray/routstr-core | `confidential-2pc` | the node |

Protocol v2 is retired and archived on the branches `v2` (this repo) and `confidential-v2` (routstr-core,
routstr-sdk, routstrd); the v2 edition of this file is on the
[`v2`](https://github.com/jooray/routstr-confidential/tree/v2) branch. v2 and v3 do not interoperate: a v3 node answers a v2 client with `upgrade_required`, and a v3 client reports
`node_protocol_outdated` for a v2 node.

You need: git, Rust (stable), Bun, Node.js/npm (to build the SDK).

## 1. Client only (use an existing node)

If you only want to try it as a user, you need routstrd and the two prover binaries. You then need a node
that runs confidential mode with the same protocol version as your client (a node's signed offer says so:
`"v": 3`; its Nostr listing carries `confidential: 3`). **https://routstr.cypherpunk.today** runs confidential
mode with protocol v3 and Venice as the provider (framings `"2"` and `"1.1"`, a 2 sat connection deposit;
it is announced on Nostr, so routstrd finds it).

**Build the provers.**

```sh
git clone https://github.com/jooray/routstr-confidential    # default branch: main
cd routstr-confidential/crypto
cargo build --release -p zkbench --bin cu-prover -p twopc --bin cu-2pc
# binaries: crypto/zkbench/target/release/{cu-prover,cu-2pc} (keep them in one directory)
cd ../..
```

**Build the SDK branch and routstrd against it.**

```sh
git clone -b confidential-2pc https://github.com/jooray/routstr-sdk
(cd routstr-sdk && npm install && npm run build)

git clone -b confidential-upstream https://github.com/jooray/routstrd
cd routstrd
bun install
# use the SDK branch instead of the npm release
rm -rf node_modules/@routstr/sdk && ln -s "$PWD/../routstr-sdk" node_modules/@routstr/sdk
bun run build       # after the link: dist/ bundles the SDK
bun link            # installs dist/index.js as `routstrd` in ~/.bun/bin
```

`~/.bun/bin` (`$BUN_INSTALL/bin`) has to be on your `PATH`. Without the build, `bun link` reports success but
installs no `routstrd`. Without the SDK link, the daemon fails at startup (`Export named
'closeConfidentialPrewarm' not found`), because no npm release of the SDK has the confidential transport yet.
After updating either checkout, run `npm run build` in `routstr-sdk`, then `bun run build` in `routstrd`.

**Configure.** Set up and fund routstrd as usual (`routstrd onboard`, then `routstrd receive <cashu token>`
or `routstrd receive <sats>` for Lightning). Then add to `~/.routstrd/config.json`:

```json
{
  "confidentialUpstream": {
    "enabled": true,
    "trusted_hosts": ["api.venice.ai"],
    "node_pubkeys": ["<the node's Nostr pubkey, hex or npub>"],
    "prover_path": "/absolute/path/to/crypto/zkbench/target/release/cu-prover"
  }
}
```

- `trusted_hosts`: the provider hostnames whose TLS certificate you accept. This is what you trust instead of
  an enclave: your client checks the provider's certificate itself.
- `node_pubkeys`: nodes whose signed offers you accept (for routstr.cypherpunk.today:
  `2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7`). Optional: without it, routstrd
  accepts an offer signed by a key that announced that node's URL on Nostr and has a positive review
  (anyone can announce any URL, so an unreviewed announcement is never a pin), for https and onion
  nodes only. Set it to pin specific nodes; set `"pin_from_announcement": false` to require it.
- `cu-2pc` is found next to `cu-prover` (or set `CU_2PC`).

**Use it.** Start the daemon (`routstrd start`, optionally `--provider https://<node>` to pin one node) and
send chat completions with the opt-in header:

```sh
curl http://127.0.0.1:8008/v1/chat/completions \
  -H 'content-type: application/json' -H 'x-routstr-verify: confidential' \
  -d '{"model":"deepseek-v4-flash","max_tokens":200,"stream":true,
       "messages":[{"role":"user","content":"Say hi in three words."}]}'
```

Any OpenAI-compatible client works if it can add that header (OpenAI Python:
`default_headers={"x-routstr-verify": "confidential"}`). With the header, a request is either confidential or
refused: it is never silently sent in the clear. Only `POST /v1/chat/completions` is supported, `max_tokens`
is required (it is pinned and reserved for; a value above the node's cap is lowered to the cap, and the
response then carries `x-routstr-confidential-max-tokens: <cap>; requested=<yours>`), and only models the node lists in its confidential offer are
used (`GET https://<node>/v1/confidential/offer`).

What to expect. Opening a **connection** runs a two-party computation with the node, in which the client
receives about 16.4 MB and sends about 1.1 MB, plus about 1.5 MB each way to prepare the zero-knowledge
proofs. What happens next depends on the framing the node offers for its provider (`http` in the signed
offer; an application never sees it):

- **Framing `"2"` (HTTP/2).** The connection stays open and carries your next requests, one after the
  other. Each later request costs about 85 kB up and 1 MB down and no two-party computation. Requests on
  one connection are linkable for the provider (as requests under one API key are anyway); routstrd's
  `http2.reuse` setting controls which requests may share one.
- **Framing `"1.1"` (HTTP/1.1).** One request per connection, as in v2; routstrd pre-warms (below).

Measured with the reference client against a sidecar and Venice (medians; time to the first token, of which
about 0.45 s is the provider's own latency):

| Link | cold (open + first request) | on an armed connection | on an open HTTP/2 connection |
|---|---|---|---|
| loopback | 1.2 s | 0.8 s | 0.56 s |
| 2 Mbit/s up, 50 down, 40 ms one way | 12 s | 1.4 s | 0.9 s |
| 2 Mbit/s up, 10 down, 40 ms one way | 19 s | 1.6 s | 1.2 s |

On a slow uplink the cold time is the upload (2.6 MB at 2 Mbit/s is 10.5 s); on a slow downlink it is the
16.4 MB download. The answer streams as usual. The node's signed receipt is checked against the usage the
provider reported; a failed check fails the request.

**Pre-warming** hides the cold cost: after a confidential request, routstrd **arms** a connection in the
background (setup, deposit, the two-party preprocessing; no connection to the provider yet), bound to your
credential only, not to a model or a body length as in v2. On framing `"2"` an open connection already
serves the next request, so a second one is armed only while every open connection is busy. An armed
connection lives at most 10 minutes; an idle routstrd keeps nothing open and nothing reserved. The
settings (`confidentialUpstream.prewarm`, `confidentialUpstream.http2`, the largest deposit you accept)
are described in `routstrd/docs/confidential-upstream.md`.

**What you pay.** A confidential request costs the provider's usage at the rates in the node's signed
offer, as a normal request does. Money is held at two moments:

- *Opening a connection* reserves the node's **connection deposit** (`connection_deposit_msat` in the
  offer; by default the larger of the node's fees and 1 sat). It is released when the first request on the
  connection is settled. A connection that you open and never use (or abandon, or let idle out) loses the
  deposit; one that fails because of the node, its sidecar or the provider does not. The outcome is signed
  by the node in the connection's last message.
- *Each request* reserves the worst case: a full-context prompt plus your `max_tokens` and a small
  completion margin (`reserve_margin_tokens` in the offer, 16 tokens by default), released down to the
  usage at the settlement.

A node may also charge for its own work (section 2): a percentage surcharge, already included in the
offer's rates; a **session fee** (`session_fee_msat`), now due **once per connection**, with its first
settled request; and an **abandon fee** (`abandon_fee_msat`) for a request that is accepted and then
dropped before it reaches the provider, on a connection whose deposit was already released. The client
accepts the fees from the signed offer and checks every receipt against usage × the signed rates (cached
tokens at the cached rate) + the fee that was due (a 429 or 503, or a 401/402/403 caused by the node's
own provider key, costs the session fee if still due, any other 4xx the abandon fee). Most nodes charge
no fees; then only the deposit is new.

Nodes refuse more than 12 unused connections per client address by default (see section 2); a client
behind a shared address (NAT, Tor) shares that limit with others.

**In a browser.** The demo app <https://jooray.github.io/routstr-confidential-pwa/> (protocol v3; a testing
guide is at <https://jooray.github.io/routstr-confidential-pwa/testing/>) does the same in a web page: fund it with Lightning or a Cashu token, chat, and see the provider's certificate chain, the proofs
and the signed receipt. The library behind it, for your own web app:
[jooray/routstr-confidential-web](https://github.com/jooray/routstr-confidential-web).

## 2. Running a node

A confidential node is a normal Routstr node plus `cu-sidecar`, a small Rust service that relays the TLS
connection to the provider, writes the one record carrying the API key, and verifies the proofs. Billing uses
the node's normal reservation and settlement.

**Provider requirements.** Confidential mode needs a provider whose API behaves predictably (it waits for the
full request body, applies the last duplicate JSON key, enforces token caps, reports usage in the stream).
Check yours before offering it, with the offer file you will deploy and the variable that holds its key
(the key is sent only to the offer's `upstream_host`; needs OpenSSL 1.1.1 or later):

```sh
T=crypto/tools/provider-profile-check.py
python3 -I $T --offer my-offer.json --key-env MY_PROVIDER_KEY --model <a cheap chat model>            # A1-A14: every item must pass
python3 -I $T --offer my-offer.json --key-env MY_PROVIDER_KEY --model <...> --h2                      # H1-H8: before you offer HTTP/2
python3 -I $T --offer my-offer.json --key-env MY_PROVIDER_KEY --image-model <...> --images            # I1-I10: before you offer images
```

**Framings: the `http` list and the `h2` block.** The offer file says how clients talk to your provider.
Nothing is probed or assumed: you state it.

```json
"http": ["2", "1.1"],
"h2": {"probe_path": "/api/v1/models", "max_requests": 100, "max_lifetime_s": 3600, "idle_secs": 300, "kinds": ["chat", "images"]}
```

| Field | Range, default | Meaning |
|---|---|---|
| `http` | `"2"` and/or `"1.1"`, in your order of preference; default `["1.1"]` | `"1.1"`: one request per connection (works with every provider that passes A1-A13). `"2"`: an HTTP/2 connection that carries many requests; needs the `h2` block and a provider that passes `--h2` |
| `h2.probe_path` | a path under 127 bytes | a cheap authenticated `GET` of the provider (its models list). The sidecar sends it once per connection: it is the request that stores the API key in the provider's header table |
| `h2.max_requests` | 1..1000, 100 | requests per connection |
| `h2.max_lifetime_s` | 60..86400, 3600 | a connection is closed at the first settlement after this long |
| `h2.idle_secs` | 10..3600, 300 | the sidecar's idle limit, and the ceiling of the node's `CONFIDENTIAL_IDLE_TIMEOUT_S`. **Not longer than the idle time your `--h2` run passed H5 with** |
| `h2.kinds` | `["chat"]` (default) or `["chat","images"]` | request kinds on an HTTP/2 connection (`images` needs `endpoints.images`) |

**Run `--h2` before you add `"2"`.** It opens connections exactly as a confidential client and the sidecar
do together (the client's TLS offer with ALPN `h2`, the connection head, a TLS KeyUpdate, requests that
name the API key by its header-table index) and checks the eight things framing `"2"` needs (H1-H8 of
`PROTOCOL-V3.md` §5.6): TLS 1.3 with `h2`; the KeyUpdate is accepted; the provider keeps its header table
and the key in it, also after the idle time; it honours a zero-size table for response headers; a body of
the sidecar's `--max-body` passes flow control; no response reflects the key; the usage event ends the
stream as the proof parses it. It idles one connection for `--h2-idle` seconds (default: the file's
`h2.idle_secs`, so 5 minutes), sends one body of `--h2-body-bytes` (default 8 MiB, mostly whitespace) and,
when `h2.kinds` lists images, generates one image. It ends with a verdict:

```
offer "2": yes. api.venice.ai does what framing "2" needs (H1-H8).
  "http": ["2", "1.1"] with "h2": {"probe_path": "/api/v1/models", "idle_secs": at most 300}; the sidecar's --max-body at most 8388608.
```

or `offer "2": no, because H5: …` (keep `"http": ["1.1"]`), or `not yet` when a check was inconclusive (an
outage, a rate limit: run it again). Run it again after the provider changes its front end. List `"1.1"`
after `"2"` unless you have a reason not to: clients fall back to it by themselves when an HTTP/2
connection fails.

**The sidecar watches framing `"2"` at run time.** After 5 consecutive HTTP/2 connections that failed to
open, it logs `framing "2" withdrawn from the offer`, stops listing `"2"` in its offer and refuses setups
for it for 10 minutes, then offers it again (`framing "2" is offered again`). Clients use `"1.1"`
meanwhile. Only failures that no client can cause count (the provider closing on the ClientHello, not
selecting `h2`, or closing on the connection head), so a client cannot switch HTTP/2 off for others. If
you see the withdrawal repeat, run `--h2` and, if it fails, remove `"2"` from the file.

The sidecar ships with an offer for Venice (`crypto/relay/offer.venice.json`: host, request-head template,
the `chat` block that describes the pinned suffix); adapt it for another OpenAI-compatible provider. The
`chat` block names the request keys that carry the token cap and the pins that follow (`docs/CHAT-SUFFIX.md`):
without it the sidecar pins `max_tokens`, `max_completion_tokens`, `n`, `stream` and `stream_options` only;
Venice's file adds `venice_parameters` to keep Venice's own system prompt and web search off the bill. The
sidecar refuses at startup a block that clients would refuse (a pin may only switch something off, under a
key that is not negated or protective), and a block that does not pin `n` to 1 and both `max_tokens` and
`max_completion_tokens`. A
deployment that copies the offer file (for example to mount it) must add the block to its copy. **Models and prices come from the
node:** every model the node serves through the sidecar's provider host is offered confidentially, at the
node's normal rates (plus any surcharge). The node reserves a full-context prompt, so image inputs need no
separate gate. The reservation is `max(MIN_REQUEST_MSAT, ⌈(context_length·in + (max_tokens + margin)·out)/1000⌉)`
msat plus the larger of the session and abandon fees below, where `margin` is
`CONFIDENTIAL_RESERVE_MARGIN_TOKENS` (default 16, published in the signed offer as `reserve_margin_tokens`):
providers may bill a few tokens beyond `max_tokens`, the charge is capped at the reservation, and anything
beyond the margin is the node's loss. The offer file carries no prices. To restrict the models, list their ids in its
`model_allowlist` (empty = all), which the sidecar and the node both enforce (the earlier name
`text_only_ok`, a map `{"id": true}`, is still read).

**Confidential images** need the offer file's `endpoints.images` block (the shipped Venice offer has one:
the native `POST /api/v1/image/generate` head template, `count_key` `"variants"`, the `fixed_pins` that
switch Venice's paid extras off, `param_space` with the resolution tiers and `format: ["webp"]`,
`max_response_bytes`, `response_idle_s`). A node only advertises images (`capabilities: ["chat", "images"]`
and an `images` price list in its signed offer) when its sidecar serves that block, and only for image models
it can price per image: the provider must list them with per-image books (on routstr-core, a `venice`-type
provider row; a `generic` row lists no image models). Each variant is priced at the node's per-image price
for that tier, plus any surcharge; settlement is flat (`msat_per_image × count` plus the session fee) after
the client's `accept`, with no usage proof. A deployment that copies the
offer file (for example to mount it) must add the block to its copy. Check the provider with
`crypto/tools/provider-profile-check.py --images` (checks I1 to I9: duplicates, unknown fields and
models, head reflection, open strings, paid extras and arrays, incomplete body, TLS with P-256, and a
KeyUpdate between head and body; three paid images). The `count_key` must be the one the route reads
(`variants` for `/image/generate`, `n` for `/images/generations`): the sidecar refuses another at startup,
and so do clients.

**1. The sidecar** (container build, from the `main` checkout):

```sh
podman build -f crypto/Containerfile.sidecar -t cu-sidecar crypto   # or docker
```

Run it in the same container network as the node, with no published port. It needs the provider API key
(the same one the node uses) and a token it shares with the node:

```sh
openssl rand -hex 32    # the shared token: CU_SIDECAR_TOKEN here, CONFIDENTIAL_SIDECAR_TOKEN on the node
podman run -d --name cu-sidecar --network <node network> -e UPSTREAM_API_KEY=... -e CU_SIDECAR_TOKEN=... cu-sidecar \
  --listen 0.0.0.0:7444 --upstream api.venice.ai:443 --key-env UPSTREAM_API_KEY \
  --offer /etc/cu-sidecar/offer.json --node-settles --runs-dir /runs
```

**Run files.** For each connection that wrote a credential record, the sidecar keeps its log, attestation
and (without `--node-settles`) receipt under `--runs-dir`, readable by its own user only. Nothing needs
them after the session ends: the node settles from its own records and the client holds the attestation
and receipt. They are kept 24 hours for debugging and then removed (checked every ten minutes);
`--runs-keep-hours N` changes that, and `--runs-keep-hours 0` removes them as each session ends.

**The token.** The sidecar does not check client credentials: the node checks them and reserves the payment
before it connects to the sidecar. Anyone who reaches the sidecar directly could therefore run sessions on
your provider key without paying. So the sidecar requires `Authorization: Bearer <token>` on every request
(the token is read from the environment variable named by `--token-env`, default `CU_SIDECAR_TOKEN`, at least
16 characters) and refuses to start on a non-loopback `--listen` without one. A sidecar on `127.0.0.1` may run
without a token, but then every local user on that host can reach it; set one anyway if the host is shared.
Keep the port unpublished in any case. The sidecar speaks plain HTTP/WebSocket, so the token crosses the
node→sidecar link in cleartext: run that link over loopback or a private container network on the same
host, or through an encrypted tunnel (WireGuard, or a TLS terminator in front of the sidecar with an
`https://` `CONFIDENTIAL_SIDECAR_URL`), never over a network others can read. To rotate the token, change it
on both sides and restart both.

**Denial-of-service limit.** The node refuses a new confidential connection (HTTP 429, WebSocket close
1013) from a client address that already has `CONFIDENTIAL_MAX_UNUSED_PER_IP` (default 12, 0 disables)
unused connections. A connection counts as unused from the moment its deposit is reserved until the body of
its first request is released to the provider (or the connection ends). Armed connections count. Connections that have not reserved yet (waiting for
the setup frame, which must come within 10 s and be at most 256 KiB, or with the reservation in progress) are a
separate pending pool: at most 4 per address (IPv6 grouped by /64) and 1024 in all; when either is full, the
oldest connection still waiting for its setup is evicted. The limit is
only as good as the node's idea of the client address, which depends on how the node is reached:

| Deployment | What to set | Result |
|---|---|---|
| Node reached directly (no reverse proxy, no port-forwarding layer that rewrites the source address) | nothing | the TCP peer address is the client |
| Reverse proxy on the same host (nginx, Caddy, Traefik) connecting to the node over loopback | `CONFIDENTIAL_TRUSTED_PROXIES=127.0.0.1,::1`, and the proxy must append `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`) | the rightmost `X-Forwarded-For` entry, the one the proxy added |
| Reverse proxy that reaches the node from another address (another host, a container network) | `CONFIDENTIAL_TRUSTED_PROXIES` = that address | as above |
| Rootless container with a published port (podman/docker forwarder: the node sees its **own** address for every connection) behind a reverse proxy | `CONFIDENTIAL_TRUSTED_PROXIES=127.0.0.1,::1,self` | as above; `self` means the node's own addresses |
| Same, **without** a reverse proxy | do not trust `self` (anyone could then set the header); either put a proxy in front, run the container with host networking, or raise/disable the limit | otherwise every client shares one address and one limit |
| Proxy that puts the client in another header (e.g. Cloudflare's `CF-Connecting-IP`) | `CONFIDENTIAL_CLIENT_IP_HEADER` = that header | used as is |
| Tor onion service | nothing | all Tor clients arrive from the Tor daemon's address and share one limit |

Only peers in `CONFIDENTIAL_TRUSTED_PROXIES` (default: none) can name the client by header; for any other
peer the header is ignored, so a remote client cannot choose its own address. If you trust loopback, a process
on the node's own host that connects to the node's port directly can set the header and pick any address; if
you do not trust local users, keep the node's port reachable only by the proxy (or trust only the proxy's
address). Never trust an address that something else (a Tor daemon, a port forwarder) also connects from
without overwriting the header.

**Deposit, idle time, surcharge and fees.** Opening a connection costs the node about 16.4 MB of upload
for the two-party computation (about 18 MB with the proofs, below) and under 0.5 s of CPU, before any
request exists. The settings:

| Setting | Default | Effect |
|---|---|---|
| `CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT` | max(abandon fee, session fee, 1000 msat) | reserved at the setup, released by the connection's first settled request, **charged** when a connection ends without one through the client's doing (opened and unused, abandoned, idled out, a failed handshake or proof). Released when the end was the node's, the sidecar's or the provider's. `0` = no deposit |
| `CONFIDENTIAL_IDLE_TIMEOUT_S` | 120 | the node closes a connection with no request in flight after this long; at least 10, at most the sidecar's `h2.idle_secs` |
| `CONFIDENTIAL_RATE_SURCHARGE_PCT` | 0 | percentage added to the per-token rates of confidential requests (the signed offer lists the surcharged rates) |
| `CONFIDENTIAL_SESSION_FEE_MSAT` | 0 | flat fee for the two-party handshake, due **once per connection**, with its first settled request: added to a 2xx; the whole charge when the provider is limiting or at capacity (429/503) or refuses the node's own key or account (401/402/403), or answers and closes before the request body is complete |
| `CONFIDENTIAL_ABANDON_FEE_MSAT` | the session fee | kept when an accepted request is dropped before it reached the provider, on a connection whose deposit was already released; also the charge for a 4xx other than the above |

The deposit is the anti-DoS mechanism: together with the per-address limit above, every connection that
is opened and wasted costs its holder the deposit, while a connection that is used costs only the session
fee. A connection holds no reservation while it idles after its first settlement, so the idle timeout is
what bounds how long a client can keep one of the node's connection slots (`--max-sessions`, 32) for free;
with framing `"2"` a slot serves many requests, so size the slots to your concurrent clients, not to your
request rate. All values go into the signed offer, so clients see them before they pay; a client that
does not accept the fees is refused (409 `session_fee_not_accepted`), and one whose maximum deposit is
below yours does not use the node. Like the other settings, they are persisted in the node's database
after the first start (change them with `PATCH /admin/api/settings`). Size the deposit to what one
connection's ~18 MB of egress and CPU cost the node. See `routstr-core/docs/confidential-upstream.md` for
the exact rules, and `PROTOCOL-V3.md` §12.10 for every outcome.

The sidecar speaks only protocol v3 (it refuses `--protocol`, an offer file naming another `v`, and a
setup without `"v": 3`). Limits: `--max-sessions` (32 connections) and `--max-body` (8 MiB per request).
A connection has 600 s from its socket's accept (armed time included) until the connection head is
written; a request has 600 s from `request_ok` until its last record is released to the provider, and a
fresh 600 s from there for the response and the disclosure. The node's limits match. Client bytes held
before a proof covers them are capped at about the declared body length, and a client cannot raise the
proof channel's preallocation above the sidecar's own.

**2. The node**: build routstr-core from the `confidential-2pc` branch of jooray/routstr-core (its `Dockerfile` is the upstream one)
and set

```sh
CONFIDENTIAL_SIDECAR_URL=http://cu-sidecar:7444
CONFIDENTIAL_SIDECAR_TOKEN=<the sidecar's CU_SIDECAR_TOKEN>
```

The sidecar URL is read only from the environment (the confidential routes are mounted at startup; it is
not stored in the database and cannot be changed through the admin API). Run the node as a single worker:
offers, sessions and `/zk` admission are kept per process, and the node refuses to start when it detects
more than one worker (`--workers`, `WEB_CONCURRENCY`, gunicorn `-w`, or a second process on the same
sidecar and database). The token is read only from the environment (never stored in the
database, shown as `[REDACTED]` by the admin API). The node then serves `GET /v1/confidential/offer` (signed with its Nostr
key) and marks the offered models in `/v1/models` with `confidential_upstream`. Its reverse proxy must pass
WebSockets for `/v1/confidential/ws` and `/v1/confidential/zk` (`Upgrade`/`Connection` headers, read timeout
of a few minutes). Run the node's server with a long WebSocket ping timeout, e.g.
`uvicorn routstr:fastapi_app --host 0.0.0.0 --port 8000 --proxy-headers --ws-ping-interval 20
--ws-ping-timeout 300` instead of the image's default `fastapi run routstr`: while ~16 MB of 2PC data is on
its way to a client on a slow link, the keepalive waits behind it, and the default 20 s timeout drops the
connection. uvicorn's `--ws-max-size` (default 16 MiB) bounds each frame a client can send before it is
authenticated; do not set it below 12 MiB, since a client may send a whole 8 MiB request body in one frame.

**Do not log the query strings of the confidential routes.** `/v1/confidential/zk` carries `session_id`
and `zk_token` in its query string (a WebSocket upgrade has no other place for them in a browser).
Together they admit to that live connection's proof channel until the connection ends, so a proxy or CDN
in front of the node must not write them to its access log. (`/v1/confidential/ws` carries only a
random `session_id`; treat it the same way.) nginx logs `$request`, which includes the query string, in
its default format; for these two locations use a format without `$request`, `$request_uri` or `$args`,
or turn the access log off:

```nginx
log_format confidential '$remote_addr [$time_local] "$request_method $uri" $status $body_bytes_sent $request_time';

location ~ ^/v1/confidential/(ws|zk)$ {
    access_log /var/log/nginx/confidential.log confidential;   # or: access_log off;
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 600s;
}
```

The same holds for anything else that sees the URL: a CDN's request logs, a WAF, a load balancer, an
error log that records the request line.

**3. Check it.**

```sh
curl -s 'https://<node>/v1/confidential/offer?v=3' | jq '{v, http, h2, twopc, connection_deposit_msat, idle_timeout_s, upstream_host, models: (.price_list|keys)}'
```

`v` must be `3`, `twopc` `"split-public-1"`, and `http` what your offer file lists (without `"2"` while the
sidecar has withdrawn it). Then run requests through routstrd as in section 1, or with the reference
client below (`--http 2 --requests 3`, then `--http 1.1`). On the sidecar, each connection logs the 2PC,
`ClientHello checked: canonical, one P-256 share, the joint key`, `credential record + KeyUpdate written
to upstream`, and per request the proofs and the settlement.

**Bandwidth and CPU.** Each connection costs the node about 18 MB of upload: 16.4 MB for the two-party
computation (its garbled circuit cannot be reused, so an armed connection that is never used costs this
too) and the rest for the proofs, and under 0.5 s of CPU. On framing `"2"` each further request costs
about 1 MB of upload (the proof correlations) and no two-party computation; on framing `"1.1"` every
request is a connection. Normal (non-confidential) requests are unaffected.

## Reference client

`crypto/client/src/driver.ts` is a self-contained client that opens connections to a node and prints every
check (`node --experimental-strip-types src/driver.ts --node https://<node> --node-pubkey <hex or npub>
--model <m> --max-tokens 40 --http auto --requests 2 --auth <sk-… or cashu…>`; `--http 2` or `--http 1.1`
forces a framing); see `AGENTS.md` for running the whole stack locally, the gates and the measurements.

## Upgrading from v2

v3 is a breaking change: there is no v2 fallback in nodes or clients. Upgrade the sidecar and the node
together; clients must be v3 to use the node afterwards.

1. **Sidecar.** Build from `main`. Remove `--protocol 2` from its command line (the flag is refused).
   Your v2 offer file works as it is and then serves framing `"1.1"` only (the default when `http` is
   absent). A deployment that copies the offer file must copy the new `http` and `h2` fields too.
2. **Node.** Build routstr-core from `confidential-2pc` (v3 now; your v2 build came from the same branch, now archived as `confidential-v2`). New settings: `CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT`
   and `CONFIDENTIAL_IDLE_TIMEOUT_S` (table above); the fee settings keep their names, but the session fee
   is now charged once per connection. Keep `--ws-ping-timeout 300` and the single worker.
3. **Check** the offer (`"v": 3`, `"http": ["1.1"]`) and run one request.
4. **HTTP/2, when you want it.** Run `provider-profile-check.py --h2` against your provider with your
   offer file. On `offer "2": yes`, add `"http": ["2", "1.1"]` and the `h2` block (with `idle_secs` no
   longer than the idle time the check ran with), restart the sidecar, and check the offer again.
5. **Clients.** v2 clients get `error 426 upgrade_required` (`min_v: 3`) from your node; v3 clients ask
   for `/v1/confidential/offer?v=3`, so before you upgrade, your access log shows whether v3 clients are
   already asking. A v3 client does not use a v2 node (`node_protocol_outdated`).
6. **What your users see.** The first request to your node costs them 16.4 MB instead of 22 MB; with
   HTTP/2 the following requests cost about 1 MB. They need a balance that covers your connection deposit.

