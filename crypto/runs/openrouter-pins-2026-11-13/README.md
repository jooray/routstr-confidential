# OpenRouter pins and filters, 2026-11-13

Evidence for `docs/providers/OPENROUTER.md`. Spend at OpenRouter: $0.254. That
is the key's usage counter, from $0.0336 before to $0.2874 after. It includes
one $0.1375 request: a 275 k-token prompt that checked the tiered price.

| Path | What |
|---|---|
| `cases1.json` … `cases6.json` | the probe requests: model, private part, suffix pins, note. Two bodies are trimmed in `cases3.json`/`cases5.json`: the 275 k-token filler and a 3 s 440 Hz WAV |
| `probe.jsonl` | one record per request: the exact body (bodies over 4 000 bytes shortened), status, usage event, generation record, OpenRouter's charge, the token-rate cost, the ratio |
| `probe-summary.tsv` | the same as a table |
| `batches/` | console output of batches 3 and 5 |
| `node/` | `v3-node-check.sh` with `CU_PIN_ATTACKS=1` through a scratch node: `run.txt`, `summary.tsv` (24/24 PASS), `api_keys.tsv` (final balances), `offer.json` (the node's signed offer), `orcost.tsv`/`orcost.json` (OpenRouter's cost per request against the node's charge) |
| `tools/pinprobe.py` | the probe: `pinprobe.py <cases.json> <out.jsonl> [ids]` |
| `tools/orcost.py` | the cost comparison for a gate run's evidence directory |
| `tools/keyusage.py` | the key's usage counters (spend log) |

The tools import `../../providers-2026-11-12/tools/prov.py`. It decrypts the
OpenRouter key from FreeLLMAPI in memory, and the key goes only to
openrouter.ai. Every file here was scanned for every provider key and its
base64 forms with `providers-2026-11-12/tools/scan.py`, with no hits. The
scratch node's database was removed by the gate, and its directory was
deleted afterwards.
