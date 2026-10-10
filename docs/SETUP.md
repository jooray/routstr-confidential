# Trying confidential mode

Confidential mode lets a Routstr node serve your LLM request without seeing the prompt or the answer, and
(protocol v2) without you ever being able to recover the node's provider API key. How it works:
[`paper/paper.pdf`](../paper/paper.pdf); trade-offs between v1 and v2: [`V1-V2-ONE-PAGER.pdf`](V1-V2-ONE-PAGER.pdf).

This is **experimental**: the code lives on branches, not in Routstr releases yet, and the two-party
computation is not externally reviewed. Use small amounts.

| Repo | Branch | What |
|---|---|---|
| [jooray/routstr-confidential](https://github.com/jooray/routstr-confidential/tree/twopc-v2) | `twopc-v2` | provers (`cu-prover`, `cu-2pc`), the node's sidecar (`cu-sidecar`), paper |
| [jooray/routstr-sdk](https://github.com/jooray/routstr-sdk/tree/confidential-2pc) | `confidential-2pc` | the client transport |
| [jooray/routstrd](https://github.com/jooray/routstrd/tree/confidential-upstream) | `confidential-upstream` | the daemon (opt-in header, config) |
| [jooray/routstr-core](https://github.com/jooray/routstr-core/tree/confidential-2pc) | `confidential-2pc` | the node |

You need: git, Rust (stable), Bun ≥ 1.4, Node.js/npm (to build the SDK).

## 1. Client only (use an existing node)

If you only want to try it as a user, you need routstrd and the two prover binaries. You then need a node
that runs confidential mode; for example **https://routstr.cypherpunk.today** runs protocol v2 with Venice as
the provider (it is announced on Nostr, so routstrd finds it).

**Build the provers.**

```sh
git clone -b twopc-v2 https://github.com/jooray/routstr-confidential
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
bun link            # puts `routstrd` on your PATH
```

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
  `2ca46ee98f3134c4e11a638663a45983b590bfdefd31588f9c2f03455fba15e7`).
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
is required (it is pinned and reserved for), and only models the node lists in its confidential offer are
used (`GET https://<node>/v1/confidential/offer`).

What to expect: each request first runs a two-party computation with the node, in which the client
receives about 22 MB and sends about 1.2 MB. A cold request's waiting time is dominated by receiving those
22 MB: seconds on a fast connection (about 3 s on a 100 Mbit/s link, about 7 s on a home connection with
a 2 Mbit/s uplink and a 50 Mbit/s downlink), but about a minute on a slow or congested one (45-70 s to the
first token, measured from a laptop on poor Wi-Fi behind a satellite link that got only 2-5 Mbit/s from
the node). The TLS session and the proofs then add a few seconds. routstrd therefore **pre-warms**: once
you send confidential requests, it prepares the expensive part for the next one in the background (see
below), which hides it. The answer streams as usual. The node's signed receipt is checked against the
usage the provider reported; a failed check fails the request.

**Pre-warming** is on by default and driven by your traffic. After a confidential request for a node,
model and `max_tokens`, routstrd arms a session in the background (setup, reservation, the two-party
preprocessing; no connection to the provider yet), so the next matching request skips the preprocessing.
It keeps one armed session while requests keep coming, two on bursts or overlapping requests, and closes
them a few minutes after the last request: an idle routstrd keeps nothing open and nothing reserved. Each
armed session reserves funds on your node credential until it is used or closed (released, no charge),
and costs about 22 MB of download and 1.2 MB of upload to prepare. Tune or disable it in `config.json`:

```json
"confidentialUpstream": {
  "prewarm": { "enabled": true, "activityWindowMinutes": 10, "maxPerKey": 2, "maxTotal": 2, "maxAgeSeconds": 480 }
}
```

Nodes refuse more than 3 unused sessions per client address by default (see section 2), so keep
`maxTotal` at 2 or lower; a client behind a shared address (NAT, Tor) shares that limit with others.
A request uses an armed session only if its model and `max_tokens` match exactly (they are pinned at
setup) and its body fits the armed length; otherwise it runs cold. Responses carry
`x-routstr-confidential-prewarmed: 1` when they used one. A pre-warmed request reaches its first token in
about 2-3 s (the armed session also pre-generates the setup of the zero-knowledge proofs, so they take well
under a second; most of a warm request is the provider's own latency, and a session armed through the
handshake reached it in about 1 s). Arming runs in the background and takes about as long as the cold
two-party computation.

## 2. Running a node

A confidential node is a normal Routstr node plus `cu-sidecar`, a small Rust service that relays the TLS
connection to the provider, writes the one record carrying the API key, and verifies the proofs. Billing uses
the node's normal reservation and settlement.

**Provider requirements.** Confidential mode needs a provider whose API behaves predictably (it waits for the
full request body, applies the last duplicate JSON key, enforces token caps, reports usage in the stream).
Check yours before offering it:

```sh
crypto/tools/provider-profile-check.py --help    # run it against your provider; it must pass every item
crypto/tools/regression-modality.py --help       # models must reject image inputs
```

The sidecar ships with an offer for Venice (`crypto/relay/offer.venice.json`: host, request-head template and
the models offered confidentially); adapt it for another OpenAI-compatible provider.

**1. The sidecar** (container build, from the `twopc-v2` checkout):

```sh
podman build -f crypto/Containerfile.sidecar -t cu-sidecar crypto   # or docker
```

Run it in the same container network as the node, with no published port. It needs the provider API key
(the same one the node uses):

```sh
podman run -d --name cu-sidecar --network <node network> -e UPSTREAM_API_KEY=... cu-sidecar \
  --listen 0.0.0.0:7444 --upstream api.venice.ai:443 --key-env UPSTREAM_API_KEY \
  --offer /etc/cu-sidecar/offer.json --node-settles --protocol 2 --runs-dir /runs
```

**Denial-of-service limit.** The node refuses a new confidential session (HTTP 429, WebSocket close
1013) from a client address that already has `CONFIDENTIAL_MAX_UNUSED_PER_IP` (default 3, 0 disables)
unused sessions: set up but with no credential record written yet. Pre-warmed sessions count. The limit is
only as good as the node's idea of the client address, which depends on how the node is reached:

| Deployment | What to set | Result |
|---|---|---|
| Node reached directly (no reverse proxy, no port-forwarding layer that rewrites the source address) | nothing | the TCP peer address is the client |
| Reverse proxy on the same host (nginx, Caddy, Traefik) connecting to the node over loopback | nothing, if the proxy appends `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`) | the rightmost `X-Forwarded-For` entry, the one the proxy added |
| Reverse proxy that reaches the node from another address (another host, a container network) | `CONFIDENTIAL_TRUSTED_PROXIES` = that address | as above |
| Rootless container with a published port (podman/docker forwarder: the node sees its **own** address for every connection) behind a reverse proxy | `CONFIDENTIAL_TRUSTED_PROXIES=127.0.0.1,::1,self` | as above; `self` means the node's own addresses |
| Same, **without** a reverse proxy | do not trust `self` (anyone could then set the header); either put a proxy in front, run the container with host networking, or raise/disable the limit | otherwise every client shares one address and one limit |
| Proxy that puts the client in another header (e.g. Cloudflare's `CF-Connecting-IP`) | `CONFIDENTIAL_CLIENT_IP_HEADER` = that header | used as is |
| Tor onion service | nothing | all Tor clients arrive from the Tor daemon's address and share one limit |

Only peers in `CONFIDENTIAL_TRUSTED_PROXIES` (default `127.0.0.1,::1`) can name the client by header; for
any other peer the header is ignored, so a client cannot choose its own address.

`--protocol 2` selects the two-party handshake (`1` is the single-party variant). Limits: `--max-sessions`
(32) and `--max-body` (8 MiB); sessions time out after 600 s.

**2. The node**: build routstr-core from the `confidential-2pc` branch (its `Dockerfile` is the upstream one)
and set

```sh
CONFIDENTIAL_SIDECAR_URL=http://cu-sidecar:7444
```

routstr-core persists settings in its database: if the node has run before, set it once through
`PATCH /admin/api/settings` as well. The node then serves `GET /v1/confidential/offer` (signed with its Nostr
key) and marks the offered models in `/v1/models` with `confidential_upstream`. Its reverse proxy must pass
WebSockets for `/v1/confidential/ws` and `/v1/confidential/zk` (`Upgrade`/`Connection` headers, read timeout
of a few minutes). Run the node's server with a long WebSocket ping timeout, e.g.
`uvicorn routstr:fastapi_app --host 0.0.0.0 --port 8000 --proxy-headers --ws-ping-interval 20
--ws-ping-timeout 300` instead of the image's default `fastapi run routstr`: while ~22 MB of 2PC data is on
its way to a client on a slow link, the keepalive waits behind it, and the default 20 s timeout drops the
session.

**3. Check it.**

```sh
curl -s https://<node>/v1/confidential/offer | jq '{v, upstream_host, models: (.price_list|keys)}'
```

`v` must be `2`. Then run one request through routstrd as in section 1. On the node, each session logs the
2PC, `credential record + KeyUpdate written to upstream (epoch 0)`, the three proofs and the settlement.

**Bandwidth and CPU.** Each confidential request costs the node about 24 MB of upload (the two-party
computation's garbled circuits cannot be reused) and about 0.5 s of CPU to garble and prepare the checks,
so budget roughly 0.3 Gbit/s at 100 requests per minute. Normal
(non-confidential) requests are unaffected.

## Reference client

`crypto/client/src/driver.ts` is a self-contained client that runs one session against a node and prints every
check (`node --experimental-strip-types src/driver.ts --node https://<node> --model <m> --max-tokens 40
--auth <sk-… or cashu…>`); see `AGENTS.md` for running the whole stack locally.
