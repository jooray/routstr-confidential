# Provider evidence

Live runs against api.venice.ai behind Appendix A of the paper, 2026-10-19 UTC. No file contains
the API key.

| File | What |
|---|---|
| `provider-profile-check-2026-10-19.txt` | `crypto/tools/provider-profile-check.py`, checks A1-A12 (12 PASS), completion margin 16 |
| `provider-profile-check-self-test-2026-10-19.txt` | the same script with `--self-test` (mocked transport, 13/13 negative controls) |
| `regression-modality-2026-10-19.{txt,json}` | `crypto/tools/regression-modality.py` on 8 text models (8 PASS) |
| `manual-provider-checks-2026-10-19.txt` | `manual-provider-checks.py`: token-cap overshoot, the system-prompt pin, a prompt asking for fake usage events |
| `provider-profile-check-2026-10-28.txt` | the same gate with A13 (a vision model bills an image as prompt tokens), 13 PASS |
| `provider-profile-check-images-2026-10-19.txt` | `provider-profile-check.py --images`, the image route (`/api/v1/image/generate`, z-image-turbo), checks I1-I9 (10 PASS, three paid images) |
| `image-session-direct-2026-10-19.txt` | a confidential image session through a local sidecar in direct mode (`driver.ts --image`, stub settlement), client and sidecar logs, local paths shortened |

The chat gate offers X25519 (A9, A11); the P-256 key share that v2 uses is exercised by the live v2
sessions and, on the image route, by checks I8 and I9.

## measure-2026-10-19/

End-to-end timings of protocol v2 with the node-only garbling, one JSON line per session, from the
reference client (`crypto/client/src/driver.ts`): `local-cold`/`local-arm` (client, node and sidecar on
one host, live api.venice.ai, `deepseek-v4-flash`, 40 tokens, 5 sessions each) and
`deployed-cold`/`deployed-arm` (from a home connection to routstr.cypherpunk.today, 3 each). `arm`
means the reference client's `--arm` (armed through the handshake and pi_NK, then claimed at once).
These are the figures in paper §6.3.

## adversarial-2026-10-19/

Malicious-client gates against a local node and sidecar (one host, live api.venice.ai), 2026-10-19.

- `chat/`: `crypto/tools/adversarial-model-swap.sh`, 6/6 as expected (control, suffix mismatch,
  decoy model, withheld suffix twice, claimed canonical suffix).
- `images/`: `crypto/tools/adversarial-images.sh`, 11 cases: control; decoy expensive model, count
  injection (`"variants":4`), paid-extra injection and resolution injection in the private part, all
  neutralised by the pinned suffix (the provider's echo in `runs/*/response-meta.json` shows the pinned
  model, count, extras and 1K resolution; flat charge at the signed price); count and model mismatch in
  the suffix refused by the sidecar or by pi_C2S, and a withheld suffix, each released; an honest
  provider error (400) charged nothing; and a client that sends `accept` after the 400, charged the
  flat price for no image (the bounded residual of paper §4.10). In the full run,
  `img-resolution-inject` was flagged only because a unit-test fixture line written to the same node
  log file at that moment (empty sid, a fee this node does not charge) fell into its time window; the
  case itself was correct and passes on its own in `images-rerun/`.
- Image runs keep receipts, attestations and the response metadata, not the images.

## deployed-receipts/

Signed receipts and session attestations of confidential chat sessions against the deployed node
routstr.cypherpunk.today (node key `2ca46ee9…`), copied unchanged from the reference client's run
directories (`receipt.json`, `attestation.json`; responses and client logs are not included). Behind
paper §8.1.

| Date (UTC) | Model | Sessions | Charged (msat) | Reserved (msat) |
|---|---|---|---|---|
| 2026-10-10 | `deepseek-v4-flash-0731` | `c44c02c8…` | 25 | 80,434 |
| 2026-10-19 | `deepseek-v4-flash-0731` | `36cecedb…`, `6dbeedfe…`, `1f30bdbb…` | 26, 27, 27 | 159,272, 159,272, 160,151 |
| 2026-10-19 | `deepseek-v4-flash` | `68697f69…`, `2f44da07…`, `76b96697…`, `f9961e48…`, `b5eed3d6…`, `135d5942…` | 11 each | 119,256, then 119,229 |

The 2026-10-19 sessions produced 35 to 40 output tokens each (`usage` in each receipt); the node's offer carried an abandon fee of 2000 msat
(`abandon_fee_msat` in each receipt) and no session fee. No abandoned session's charge is archived.

## mpc-tls-2026-10-09/

`wan_100_50.txt`: the raw result lines of the MPC-TLS (TLSNotary) comparison in paper §9, one sample per
request size (2, 8, 32 and 128 KB), prover and verifier over an emulated 100 Mbit/s link with 50 ms RTT,
against TLSNotary's local TLS 1.2 test server with deferred decryption. `pre_ms` is the preprocessing before the
connection opens, `resp_ms` the time after it opens until the response was available, `online_ms` the
whole part after it opens, `total_ms` the whole session, `tot_MB` the bytes between prover and
verifier.
