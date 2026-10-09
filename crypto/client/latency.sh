#!/usr/bin/env bash
# End-to-end latency comparison: 10 confidential-upstream runs vs 10 baseline
# direct HTTPS runs. Requires the sidecar to be running on 127.0.0.1:7443.
set -euo pipefail
cd "$(dirname "$0")"
N="${1:-10}"
OUT=/tmp/cu-latency
mkdir -p "$OUT"

echo "== e2e ($N runs) =="
: > "$OUT/e2e.jsonl"
for i in $(seq 1 "$N"); do
  CU_PROVER=../zkbench/target/release/cu-prover node --experimental-strip-types src/driver.ts \
    --prompt 'Say hi in three words.' 2>/dev/null \
    | grep '^E2E_JSON ' | sed 's/^E2E_JSON //' >> "$OUT/e2e.jsonl" || true
  echo "  run $i done"
done

echo "== baseline ($N runs) =="
node --experimental-strip-types src/baseline.ts "$N" > "$OUT/baseline.json" 2>/dev/null

node -e '
const fs=require("fs");
const lines=fs.readFileSync("/tmp/cu-latency/e2e.jsonl","utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
const b=JSON.parse(fs.readFileSync("/tmp/cu-latency/baseline.json","utf8"));
const med=xs=>{const s=[...xs].sort((a,b)=>a-b);const m=Math.floor(s.length/2);return s.length%2?s[m]:(s[m-1]+s[m])/2};
const e2eTtft=med(lines.map(r=>r.ttft_ms));
const e2eTotal=med(lines.map(r=>r.total_ms));
const out={
  runs:lines.length,
  e2e:{ttft_ms:e2eTtft,total_ms:e2eTotal,all:lines},
  baseline:{ttft_ms:b.ttft_median_ms,total_ms:b.total_median_ms,all:b.all},
  added:{ttft_ms:e2eTtft-b.ttft_median_ms,total_ms:e2eTotal-b.total_median_ms},
};
fs.writeFileSync("/tmp/cu-latency/summary.json",JSON.stringify(out,null,2));
console.log(JSON.stringify(out.added,null,2));
console.log("wrote /tmp/cu-latency/summary.json");
'
