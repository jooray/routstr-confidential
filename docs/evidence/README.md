# Provider evidence

Live runs against api.venice.ai behind Appendix A of the paper, 2026-10-19 UTC. No file contains
the API key.

| File | What |
|---|---|
| `provider-profile-check-2026-10-19.txt` | `crypto/tools/provider-profile-check.py`, checks A1-A12 (12 PASS), completion margin 16 |
| `provider-profile-check-self-test-2026-10-19.txt` | the same script with `--self-test` (mocked transport, 13/13 negative controls) |
| `regression-modality-2026-10-19.{txt,json}` | `crypto/tools/regression-modality.py` on 8 text models (8 PASS) |
| `manual-provider-checks-2026-10-19.txt` | `manual-provider-checks.py`: token-cap overshoot, the system-prompt pin, a prompt asking for fake usage events |
| `provider-profile-check-images-2026-10-19.txt` | `provider-profile-check.py --images`, the image route (`/api/v1/image/generate`, z-image-turbo), checks I1-I9 (10 PASS, three paid images) |
| `image-session-direct-2026-10-19.txt` | a confidential image session through a local sidecar in direct mode (`driver.ts --image`, stub settlement), client and sidecar logs, local paths shortened |

The chat gate offers X25519 (A9, A11); the P-256 key share that v2 uses is exercised by the live v2
sessions and, on the image route, by checks I8 and I9.
