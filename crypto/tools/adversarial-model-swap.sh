#!/usr/bin/env bash
# Model/parameter-swap verification with a MALICIOUS client.
#
#   ./adversarial-model-swap.sh
#
# Requires node, sidecar and mint running (see PROGRESS-CONFIDENTIAL.md) and
# AUTH set to a node credential (sk- key or Cashu token); CU_NODE selects the
# node (default :8000). Writes evidence to crypto/runs/adversarial/.
#
# Cases:
#   a  suffix model != setup model (a real body tail carrying the other model)
#      -> sidecar must reject the suffix and the node must not settle cheaply
#   b  private-part decoy model, honest suffix
#      -> effective model must equal the suffix model
#   d  body model != setup model AND no body_suffix at all
#      -> the final body record is held: the upstream never answers
#   e  as d with a model the node does not offer
#   f  body_suffix claims the canonical suffix the body does not end with
#      -> π_C2 fails; the final body record is never released
set -uo pipefail
cd "$(dirname "$0")/../client"

NODE="${CU_NODE:-http://127.0.0.1:8000}"
MINT="${MINT:-http://127.0.0.1:3338}"
OUT="$(cd ../runs && pwd)/adversarial"
mkdir -p "$OUT"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"

mint() {
  (cd ../tools/.cashu && uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
    python ../cu_cashu.py mint --mint "$MINT" --sats "$1" 2>/dev/null | tail -1)
}

run() {
  local label="$1"; shift
  echo "== $label =="
  timeout 90 node --experimental-strip-types src/driver.ts --node "$NODE" "$@" \
    > "$OUT/$label.out" 2> "$OUT/$label.err"
  local rc=$?
  echo "  rc=$rc"
  grep -E 'sid=|receipt:|E2E_JSON|ADV_|FAILED' "$OUT/$label.out" "$OUT/$label.err" 2>/dev/null | sed 's/^/  /' | head -8
  echo "  -> $OUT/$label.{out,err}"
}

# (a) setup = cheap text-only model; body suffix = a different (pricier)
#     text-only model, so the modality gate passes and the *canonical suffix*
#     check is what must fire.
run a-suffix-mismatch --model deepseek-v4-flash --adv-suffix-model deepseek-v4-pro \
  --max-tokens 12 --auth "$AUTH" --prompt 'Say hi in three words.'

# (b) honest suffix, decoy model in the private part.
run b-decoy --model deepseek-v4-flash --decoy-model deepseek-v4-pro \
  --max-tokens 12 --auth "$AUTH" --prompt 'Say hi in three words.'

# (d) body carries a pricier model and a larger max_tokens than the setup, and
#     NO body_suffix is declared. The sidecar holds the record that completes
#     the body until π_C2 verifies, so the upstream never gets a complete
#     request: expect no response at all (no inference, no cost).
run d-no-suffix-swap --model deepseek-v4-flash --adv-suffix-model deepseek-v4-pro \
  --adv-body-max-tokens 600 --adv-no-suffix --max-tokens 12 \
  --auth "$AUTH" --prompt 'Name five planets, one per line.'
# (e) the same with a model this node does not offer at all (a far pricier one).
run e-unoffered-model --model deepseek-v4-flash --adv-suffix-model claude-fable-5 \
  --adv-body-max-tokens 600 --adv-no-suffix --max-tokens 12 \
  --auth "$AUTH" --prompt 'Name five planets, one per line.'
# (f) body ends with another model's suffix but body_suffix claims the
#     canonical one: π_C2 must fail and the held record is never released.
#     Model names of equal length, so the length check passes and π_C2 runs.
run f-claim-canonical --model deepseek-v3.2 --adv-suffix-model claude-opus-5 \
  --adv-claim-canonical --max-tokens 12 \
  --auth "$AUTH" --prompt 'Say hi in three words.'
