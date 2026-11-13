# Provider runs, 2026-11-13: Cloudflare Workers AI and OpenCode Zen end to end

Follows `../providers-2026-11-12/` (same scripts, `tools/` there). Keys stayed in
memory (FreeLLMAPI keys decrypted by `prov.py`; the OpenCode key from the
environment) and went only to their own provider. The Cloudflare account id is
replaced by `<account>` in every saved file; every file was scanned for every
key form and the account id before it was committed.

| Path | What |
|---|---|
| `e2e/v3.cloudflare.txt`, `e2e/cloudflare/` | `crypto/tools/v3-check.sh` through our sidecar (17 cases, both framings) |
| `node/node.cloudflare.txt`, `node/cloudflare/` | `crypto/tools/v3-node-check.sh` through a scratch node (8 cases); `cf-node-models.json` is the model row added through the node's admin API |
| `zen/` | OpenCode Zen: the HTTP/1.1 profile and what followed (see `zen/notes.txt`) |
| `tools/collect.py` | copies evidence with keys and the account id redacted |

## Invocations (from `../providers-2026-11-12/tools`, `~/.extra` sourced)

Cloudflare: the offer `offer.cloudflare.models-probe.json` (probe `…/ai/v1/models`:
the clients accept only an API base plus `/models` as the HTTP/2 probe; a 405
without the key, and its answer is discarded). `withkey.py` fills `ACCOUNT` in
the offer (a copy in a 0700 temporary directory), `CU_UPSTREAM_BASE` and
`CU_API_BASES` in memory.

```bash
CU_API_BASES=/client/v4/accounts/ACCOUNT/ai/v1 CU_V3_OFFER=../offers/offer.cloudflare.models-probe.json \
  CU_UPSTREAM=api.cloudflare.com:443 CU_MODEL=@cf/meta/llama-3.2-1b-instruct \
  CU_SWAP_MODEL=@cf/meta/llama-3.1-8b-instruct CU_TRUSTED_HOSTS=api.cloudflare.com CU_NO_IMAGES=1 \
  CU_V3_PORT=7491 CU_PAUSE=60 CU_CASES='h2-one h11-one h2-three h11-two h2-big h11-big h2-decoy h11-decoy
  h2-armed h11-armed h2-refused h11-refused h2-idle h2-c-model-swap h11-c-model-swap h2-c-suffix h11-c-suffix' \
  python3 -I withkey.py cloudflare ../../../tools/v3-check.sh

CU_API_BASES=/client/v4/accounts/ACCOUNT/ai/v1 CU_V3_OFFER=../offers/offer.cloudflare.models-probe.json \
  CU_UPSTREAM=api.cloudflare.com:443 CU_UPSTREAM_BASE=https://api.cloudflare.com/client/v4/accounts/ACCOUNT/ai/v1 \
  CU_PROVIDER_TYPE=generic CU_HOST_MATCH=cloudflare CU_NODE_MODELS=../../providers-2026-11-13/node/cf-node-models.json \
  CU_MODEL=meta/llama-3.2-1b-instruct CU_SWAP_MODEL=@cf/meta/llama-3.1-8b-instruct \
  CU_TRUSTED_HOSTS=api.cloudflare.com CU_NO_IMAGES=1 CU_V3_PORT=7492 CU_NODE_PORT=8461 \
  CU_CASES='h2-one h11-one h2-three h11-two h2-decoy h11-decoy h2-c-model-swap h11-c-model-swap' \
  python3 -I withkey.py cloudflare ../../../tools/v3-node-check.sh
```

OpenCode Zen (HTTP/1.1 only): the offer `offer.opencodezen.h11.json` (`http: ["1.1"]`, no
`h2` block), `CU_HTTP=1.1`, `CU_API_BASES=/zen/v1`; see `zen/notes.txt`.
