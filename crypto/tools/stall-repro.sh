#!/usr/bin/env bash
# Regression gate for the intermittent proof stall (PROGRESS-CONFIDENTIAL.md
# Deviation 5): N sequential cold end-to-end sessions against a live
# node+sidecar; exit non-zero if the success rate is below a threshold.
#
#   crypto/tools/stall-repro.sh [--min-success PCT] [runs] [label]
#
#   runs           number of sessions (default 20)
#   label          output name (default "run")
#   --min-success  required success rate in percent (default 100; env CU_MIN_SUCCESS)
#
# An attempt is "ok" only if the driver exits 0 AND prints E2E_JSON with a
# verified receipt (receipt_sig_ok, usage_match, cost_ok all true). Anything
# else is "fail", "timeout" (wall-clock limit hit) or "mint_fail".
#
# Environment:
#   CU_NODE     node base URL (default http://127.0.0.1:8000)
#   AUTH        optional node credential (sk- key) used for every run; when
#               unset, a fresh 20-sat Cashu token is minted per run from $MINT
#   MINT        mint URL (default http://127.0.0.1:3338)
#   CU_MODEL    model (default deepseek-v4-flash, gate-safe per GAP-3)
#   CU_TIMEOUT  per-run wall-clock limit in seconds (default 75)
#   CU_PROVER   cu-prover binary (default ../zkbench/target/release/cu-prover)
#   CU_EXTRA    extra driver flags, word-split (e.g. "--parallel-proofs")
#   CU_DRIVER   command that runs the reference client (default
#               "node --experimental-strip-types src/driver.ts", run from crypto/client)
#   CU_STALL_OUT  output directory (default /tmp/cu-stall)
# Output: $CU_STALL_OUT/<label>.jsonl (one JSON object per attempt) and
# per-run stderr in $CU_STALL_OUT/<label>.<i>.err.
set -euo pipefail

MIN_SUCCESS="${CU_MIN_SUCCESS:-100}"
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --min-success) MIN_SUCCESS="${2:?--min-success needs a percentage}"; shift 2 ;;
    --min-success=*) MIN_SUCCESS="${1#*=}"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) POS+=("$1"); shift ;;
  esac
done
N="${POS[0]:-20}"
LABEL="${POS[1]:-run}"
if ! [[ "$N" =~ ^[0-9]+$ ]] || [ "$N" -lt 1 ]; then echo "runs must be a positive integer" >&2; exit 2; fi
if ! [[ "$MIN_SUCCESS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then echo "--min-success must be a number (percent)" >&2; exit 2; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../client"

MODEL="${CU_MODEL:-deepseek-v4-flash}"
NODE="${CU_NODE:-http://127.0.0.1:8000}"
MINT="${MINT:-http://127.0.0.1:3338}"
TIMEOUT="${CU_TIMEOUT:-75}"
OUT="${CU_STALL_OUT:-/tmp/cu-stall}"
mkdir -p "$OUT"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"
read -r -a EXTRA <<< "${CU_EXTRA:-}"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }
PY="$(command -v python3)"
: > "$OUT/$LABEL.jsonl"

mint_token() {
  (cd "$HERE/.cashu" && uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
      python ../cu_cashu.py mint --mint "$MINT" --sats 20 2>/dev/null | tail -1)
}
now_ms() { "$PY" -I -c 'import time;print(int(time.time()*1000))'; }

# Classify one attempt from the driver's rc and stdout. Prints "status<TAB>phases-json".
CLASSIFY_PY=$(cat <<'PYEOF'
import json, sys
rc = int(sys.argv[1]); out = open(sys.argv[2], errors="replace").read()
e2e = None
for line in out.splitlines():
    if line.startswith("E2E_JSON "):
        try: e2e = json.loads(line[9:])
        except ValueError: pass
if rc in (124, 137):
    status = "timeout"
elif rc == 0 and e2e and all(e2e.get(k) is True for k in ("receipt_sig_ok", "usage_match", "cost_ok")):
    status = "ok"
else:
    status = "fail"
print(status + "\t" + json.dumps((e2e or {}).get("phases", {})))
PYEOF
)

ok=0; fail=0; to=0
for i in $(seq 1 "$N"); do
  auth="${AUTH:-}"
  if [ -z "$auth" ]; then auth="$(mint_token || true)"; fi
  start=$(now_ms)
  rc=0
  if [ -z "$auth" ]; then
    status=mint_fail; phase='{}'; rc=-1
  else
    CU_PROVER="$CU_PROVER" "$TIMEOUT_BIN" -k 5 "$TIMEOUT" "${DRIVER[@]}" \
      --node "$NODE" --model "$MODEL" --max-tokens 12 --auth "$auth" \
      ${EXTRA[@]+"${EXTRA[@]}"} --prompt 'Say hi in three words.' \
      > "$OUT/$LABEL.$i.out" 2> "$OUT/$LABEL.$i.err" || rc=$?
    res="$("$PY" -I -c "$CLASSIFY_PY" "$rc" "$OUT/$LABEL.$i.out" 2>/dev/null || printf 'fail\t{}')"
    IFS=$'\t' read -r status phase <<< "$res"
  fi
  end=$(now_ms)
  wall=$((end - start))
  case "$status" in
    ok) ok=$((ok + 1)) ;;
    timeout) to=$((to + 1)) ;;
    *) fail=$((fail + 1)) ;;
  esac
  printf '{"i":%d,"status":"%s","rc":%d,"wall_ms":%d,"phases":%s}\n' "$i" "$status" "$rc" "$wall" "$phase" >> "$OUT/$LABEL.jsonl"
  echo "  [$LABEL] $i/$N $status rc=$rc (${wall}ms)  ok=$ok fail=$fail timeout=$to"
done

echo
echo "== $LABEL summary ($MODEL via $NODE) =="
printf '%-10s %s\n' ok "$ok" fail "$fail" timeout "$to" total "$N"
rate_ok="$("$PY" -I -c 'import sys; ok,n,m=int(sys.argv[1]),int(sys.argv[2]),float(sys.argv[3]); r=100*ok/n; print(f"{r:.1f} {int(r + 1e-9 >= m)}")' "$ok" "$N" "$MIN_SUCCESS")"
read -r rate pass <<< "$rate_ok"
echo "success rate ${rate}% (threshold ${MIN_SUCCESS}%)  -> $OUT/$LABEL.jsonl"
if [ "$pass" != 1 ]; then
  echo "GATE FAILED: success rate ${rate}% < ${MIN_SUCCESS}%"
  exit 1
fi
echo "GATE PASSED"
