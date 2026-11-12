# Provider measurements, 2026-11-12

Evidence for `docs/PROVIDERS.md`. Every file was scanned for every provider
key (and its base64 forms), the Cloudflare account id and FreeLLMAPI's
encryption key before it was committed: no hits. The scripts print and store
keys only as `***`.

| Directory | What |
|---|---|
| `offers/` | the offer file per provider (`ACCOUNT` in the Cloudflare one is filled in memory) |
| `profile/` | `provider-profile-check.py` outputs: `smoke.*` (A9, A7), `a.*` (HTTP/1.1 items), `h2.*` (H items, idle 60 s), `h2final.*` (H items at the recommended idle time; `*.errfield` with a field that gets a 4xx in place of the unknown field), `a.opencodego*` (without and with the `x-opencode-session` header) |
| `keepalive/` | `<provider>.none` (silent connection, up to 1200 s), `.ping` (PING every 120 s for 900 s), `.request` (a chat request every 150-200 s) |
| `e2e/` | `crypto/tools/v3-check.sh` through our sidecar: `v3.<provider>.txt` (the run), `<provider>/` (summary, driver output per case, the sidecar's offer and log) |
| `node-attempt/` | `v3-node-check.sh` with Numes as a `generic` provider: the node priced 11 models, the confidential `price_list` stayed empty (`offer.json`, `models-raw.json`) |
| `node/` | after the two fixes (org/ ids, usage event rule): `v3-node-check.sh` through a scratch node per provider (`<provider>.txt` the run, `<provider>/` its `summary.tsv`, the node's signed `offer.json` with `upstream_models`, the keys' final balances); `routstrd-xkiro/` (`v3-routstrd-check.sh`) and `sdk-xkiro/` (routstr-sdk's `confidential-v3-e2e.ts`) |
| `e2e/v3.openrouter.free-after-fix.txt` | `v3-check.sh` with OpenRouter's `liquid/lfm-2.5-2.6b:free` after the usage event fix (the decoy cases twice: the first run hit an evaluator bug with `:` in model ids) |
| `profile/a7rule.*` | A7 and A12 again for OpenRouter and Cloudflare under the §5.4 rule; `a.opencodezen.txt`, `opencodezen.notes.txt` (OpenCode Zen) |
| `tools/` | the scripts (below) |

Scripts (`tools/`, run from that directory; Python stdlib, Node 24 for the decryption):

- `prov.py`: keys in memory. FreeLLMAPI's `api_keys` rows (AES-256-GCM, 16-byte IV
  and tag, key `ENCRYPTION_KEY` from `~/.config/freellmapi/env`) are decrypted by a
  Node child process over stdin/stdout; Numes and OpenCode Go from the environment.
- `loader.py`: loads `crypto/tools/provider-profile-check.py` for one provider with
  the key in the process environment, scrubs stdout; options `PP_GAP` (seconds
  between requests), `PP_MODEL_ALIAS`, `PP_ERROR_FIELD`, `PP_EXTRA_HEADER`.
- `check.py <provider> a [items]` / `check.py <provider> h2 [flags]`.
- `keepalive.py <provider> none|ping|settings|request <total_s> <every_s>`.
- `withkey.py <provider> <cmd…>`: runs a command (e.g. `v3-check.sh`) with the key
  in `CU_PROVIDER_KEY` only, output scrubbed.
- `dup.py` (which of two `model` keys is served), `tail.py` (the last events of a
  stream), `body.py`, `orimg.py` (one OpenRouter image through chat), `imgprobe.py`,
  `discover.py`, `peek.py`; `scan.py` (the secret scan: prints only file names).

OpenRouter image through chat (`orimg.py google/gemini-3.1-flash-lite-image`, one
request, $0.034): 200, 1 127 261 bytes, no CR, no comment lines; last event before
`[DONE]`: `choices:[{"delta":{"content":"","role":"assistant"},"finish_reason":"stop",…}]`,
`usage: {"prompt_tokens":8,"completion_tokens":1120,…,"cost":0.033602,
"completion_tokens_details":{"image_tokens":1120,…}}`.
