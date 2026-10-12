#!/usr/bin/env bash
# Cold vs pre-warmed (armed) confidential-upstream latency, plus a direct-HTTPS
# baseline, all against the same node + sidecar + reference client.
#
#   ./bench-warm.sh [runs]           # default 5 runs each
#
# Requires: sidecar on 127.0.0.1:7443 (--node-settles), node on 127.0.0.1:8000
# with CONFIDENTIAL_SIDECAR_URL set and a local Cashu mint (MINT env).
set -euo pipefail
cd "$(dirname "$0")"

N="${1:-5}"
MINT="${MINT:-http://127.0.0.1:3338}"
# Default to a model on the sidecar's text_only_ok allow-list (GAP-3 gate):
# vision-capable models are refused by the sidecar at setup.
MODEL="${CU_MODEL:-deepseek-v4-flash}"
NODE="${CU_NODE:-http://127.0.0.1:8000}"
RUNS_DIR="$PWD/../runs"
OUT=/tmp/cu-warm
mkdir -p "$OUT"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"

mint_token() {
  (cd ../tools/.cashu && uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
      python ../cu_cashu.py mint --mint "$MINT" --sats 20 2>/dev/null | tail -1)
}

echo "== cold ($N successful runs) =="
: > "$OUT/cold.jsonl"
cold_attempts=0
while [ "$(wc -l < "$OUT/cold.jsonl")" -lt "$N" ] && [ "$cold_attempts" -lt $((N * 3)) ]; do
  cold_attempts=$((cold_attempts + 1))
  TOKEN=$(mint_token)
  node --experimental-strip-types src/driver.ts --node "$NODE" --model "$MODEL" \
    --max-tokens 12 --escrow-token "$TOKEN" --prompt 'Say hi in three words.' 2>/dev/null \
    | grep '^E2E_JSON ' | sed 's/^E2E_JSON //' >> "$OUT/cold.jsonl" || true
  echo "  cold attempt $cold_attempts ($(wc -l < "$OUT/cold.jsonl")/$N ok)"
done

echo "== warm / armed ($N successful runs) =="
: > "$OUT/warm.jsonl"
warm_attempts=0
while [ "$(wc -l < "$OUT/warm.jsonl")" -lt "$N" ] && [ "$warm_attempts" -lt $((N * 3)) ]; do
  warm_attempts=$((warm_attempts + 1))
  TOKEN=$(mint_token)
  (sleep 1; echo go) | node --experimental-strip-types src/driver.ts --node "$NODE" \
    --model "$MODEL" --max-tokens 12 --escrow-token "$TOKEN" --arm \
    --prompt 'Say hi in three words.' 2>/dev/null \
    | grep '^E2E_JSON ' | sed 's/^E2E_JSON //' >> "$OUT/warm.jsonl" || true
  echo "  warm attempt $warm_attempts ($(wc -l < "$OUT/warm.jsonl")/$N ok)"
done

echo "== baseline direct HTTPS ($N runs) =="
CU_MODEL="$MODEL" CU_MAX_TOKENS=12 node --experimental-strip-types src/baseline.ts "$N" \
  > "$OUT/baseline.json" 2>/dev/null

CU_ATTEMPTS="{\"cold\":$cold_attempts,\"warm\":$warm_attempts}" node - "$OUT" <<'EOF'
const fs = require('fs')
const dir = process.argv[2]
const readJsonl = (p) => fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
const cold = readJsonl(`${dir}/cold.jsonl`)
const warm = readJsonl(`${dir}/warm.jsonl`)
const base = JSON.parse(fs.readFileSync(`${dir}/baseline.json`, 'utf8'))
const attempts = JSON.parse(process.env.CU_ATTEMPTS || '{}')
const med = (xs) => { const s = [...xs].sort((a,b)=>a-b); const m=Math.floor(s.length/2); return s.length%2?s[m]:(s[m-1]+s[m])/2 }
const pick = (rows, k) => rows.map(r => r[k]).filter(x => typeof x === 'number')
const bT = base.ttft_median_ms
const out = {
  runs: { cold: cold.length, warm: warm.length, baseline: base.runs, attempts },
  model: (cold[0]||warm[0]||{}).model || process.env.CU_MODEL,
  baseline: { ttft_ms: bT, total_ms: base.total_median_ms },
  cold: { ttft_ms: med(pick(cold,'ttft_ms')), ttft_body_ms: med(pick(cold,'ttft_body_ms')), total_ms: med(pick(cold,'total_ms')),
          pi_nk_ms: med(cold.map(r=>r.phases.pi_nk_ms)), claim_to_body_ms: med(cold.map(r=>r.phases.claim_to_body_ms)),
          handshake_ms: med(cold.map(r=>r.phases.handshake_ms)), upstream_ttft_ms: med(cold.map(r=>r.phases.upstream_ttft_ms)) },
  warm: { ttft_ms: med(pick(warm,'ttft_ms')), ttft_body_ms: med(pick(warm,'ttft_body_ms')), total_ms: med(pick(warm,'total_ms')),
          pi_nk_ms: med(warm.map(r=>r.phases.pi_nk_ms)), claim_to_body_ms: med(warm.map(r=>r.phases.claim_to_body_ms)),
          arm_ms: med(pick(warm,'arm_ms')), upstream_ttft_ms: med(warm.map(r=>r.phases.upstream_ttft_ms)) },
}
out.added = {
  cold_ttft_ms: out.cold.ttft_ms - bT,
  warm_ttft_ms: out.warm.ttft_ms - bT,
  cold_total_ms: out.cold.total_ms - base.total_median_ms,
  warm_total_ms: out.warm.total_ms - base.total_median_ms,
  warm_minus_cold_ttft_ms: out.warm.ttft_ms - out.cold.ttft_ms,
}
fs.writeFileSync(`${dir}/summary.json`, JSON.stringify(out, null, 2))
console.log(JSON.stringify(out, null, 2))
EOF
echo "wrote $OUT/summary.json"
