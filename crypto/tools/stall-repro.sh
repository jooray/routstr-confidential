#!/usr/bin/env bash
# Sequential cold e2e sessions against the live node+sidecar, to measure the
# intermittent proof stall (PROGRESS-CONFIDENTIAL.md Deviation 5).
#
#   ./stall-repro.sh [runs] [label]
#
# Per run: mint a 20-sat escrow token, run the reference client with a hard
# wall-clock timeout, record status (ok / fail / timeout) + wall ms.
# Output: /tmp/cu-stall/<label>.jsonl  (one JSON object per attempt).
set -uo pipefail
cd "$(dirname "$0")/../client"

N="${1:-20}"
LABEL="${2:-run}"
# Gate-safe default (GAP-3 text_only_ok); override with CU_MODEL.
MODEL="${CU_MODEL:-deepseek-v4-flash}"
NODE="${CU_NODE:-http://127.0.0.1:8000}"
MINT="${MINT:-http://127.0.0.1:3338}"
TIMEOUT="${CU_TIMEOUT:-75}"
OUT=/tmp/cu-stall
mkdir -p "$OUT"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"
: > "$OUT/$LABEL.jsonl"

mint_token() {
  (cd ../tools/.cashu && uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
      python ../cu_cashu.py mint --mint "$MINT" --sats 20 2>/dev/null | tail -1)
}

ok=0; fail=0; to=0
for i in $(seq 1 "$N"); do
  TOKEN=$(mint_token)
  start=$(python3 -c 'import time;print(int(time.time()*1000))')
  out=$(CU_PROVER="$CU_PROVER" timeout "$TIMEOUT" node --experimental-strip-types src/driver.ts \
        --node "$NODE" --model "$MODEL" --max-tokens 12 --escrow-token "$TOKEN" \
        ${CU_EXTRA:-} --prompt 'Say hi in three words.' 2>"$OUT/$LABEL.$i.err") ; rc=$?
  end=$(python3 -c 'import time;print(int(time.time()*1000))')
  wall=$((end - start))
  case $rc in
    0) status=ok; ok=$((ok+1));;
    124) status=timeout; to=$((to+1));;
    *) status=fail; fail=$((fail+1));;
  esac
  json=$(printf '%s' "$out" | grep -o '^E2E_JSON .*' | sed 's/^E2E_JSON //')
  phase='{}'
  if [ -n "$json" ]; then
    p=$(printf '%s' "$json" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(json.dumps(d.get("phases",{})))' 2>/dev/null)
    [ -n "$p" ] && phase="$p"
  fi
  printf '{"i":%d,"status":"%s","rc":%d,"wall_ms":%d,"phases":%s}\n' "$i" "$status" "$rc" "$wall" "$phase" >> "$OUT/$LABEL.jsonl"
  echo "  [$LABEL] $i/$N $status (${wall}ms)  ok=$ok fail=$fail timeout=$to"
done
echo "== $LABEL: ok=$ok fail=$fail timeout=$to of $N =="
python3 - "$OUT/$LABEL.jsonl" <<'EOF'
import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
n=len(rows); ok=sum(r['status']=='ok' for r in rows)
print(f"success rate {ok}/{n} = {100*ok/n:.0f}%")
EOF
