#!/usr/bin/env bash
# Protocol v3 measurements with the reference client: bytes each way and time
# to first token, per framing, for a request on a cold connection, on an armed
# one, and on an open one (framing "2").
#
#   ./bench.sh [runs]            # default 5 runs of each
#
# Against a running sidecar (CU_SIDECAR, default http://127.0.0.1:7443) or,
# with CU_NODE and AUTH (an sk- key), a node. Loopback numbers; shape the link
# yourself for the others. Every request is real (max_tokens 12).
#
# Environment: CU_SIDECAR | CU_NODE + AUTH, CU_MODEL, CU_FRAMINGS ("2 1.1"),
# CU_BENCH_OUT (default /tmp/cu-bench), CU_PROVER, CU_2PC.
set -euo pipefail
cd "$(dirname "$0")"

N="${1:-5}"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
OUT="${CU_BENCH_OUT:-/tmp/cu-bench}"
mkdir -p "$OUT"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"
export CU_2PC="${CU_2PC:-../zkbench/target/release/cu-2pc}"
if [ -n "${CU_NODE:-}" ]; then PEER=(--node "$CU_NODE" --auth "${AUTH:?set AUTH to an sk- key of the node}"); else PEER=(--sidecar "${CU_SIDECAR:-http://127.0.0.1:7443}"); fi
drv() { node --experimental-strip-types src/driver.ts "${PEER[@]}" --model "$MODEL" --max-tokens 12 --runs-dir "$OUT/runs" "$@"; }

: > "$OUT/bench.jsonl"
for h in ${CU_FRAMINGS:-2 1.1}; do
  echo "== framing $h: cold x$N =="
  for _ in $(seq 1 "$N"); do drv --http "$h" < /dev/null 2>/dev/null | grep '^BENCH ' | sed 's/^BENCH //' >> "$OUT/bench.jsonl" || true; done
  echo "== framing $h: armed x$N =="
  for i in $(seq 1 "$N"); do
    : > "$OUT/armed.out"
    ( while ! grep -q '^READY' "$OUT/armed.out" 2>/dev/null; do sleep 0.2; done; sleep 1; echo go ) | drv --http "$h" --arm 2>/dev/null > "$OUT/armed.out" || true
    grep '^BENCH ' "$OUT/armed.out" | sed 's/^BENCH //' >> "$OUT/bench.jsonl" || true
  done
  if [ "$h" = 2 ]; then
    echo "== framing 2: open (one connection, $N requests after the first) =="
    drv --http 2 --requests "$((N + 1))" < /dev/null 2>/dev/null | grep '^BENCH ' | sed 's/^BENCH //' | grep '"mode":"open"' >> "$OUT/bench.jsonl" || true
  fi
done

node - "$OUT/bench.jsonl" <<'JS'
const rows = require('fs').readFileSync(process.argv[2], 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.status === 200)
const med = (xs) => { const s = xs.filter((x) => typeof x === 'number').sort((a, b) => a - b); const m = s.length >> 1; return s.length ? (s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2)) : null }
const out = []
for (const http of ['2', '1.1']) for (const mode of ['cold', 'armed', 'open']) {
  const g = rows.filter((r) => r.http === http && r.mode === mode)
  if (!g.length) continue
  const b = (k) => med(g.map((r) => r.bytes[k]))
  out.push({ http, mode, runs: g.length, ttft_ms: med(g.map((r) => r.ttft_ms)), released_ms: med(g.map((r) => r.released_ms)),
    up_bytes: b('session_sent') + b('twopc_sent') + b('zk_sent'), down_bytes: b('session_recv') + b('twopc_recv') + b('zk_recv'),
    session: [b('session_sent'), b('session_recv')], twopc: [b('twopc_sent'), b('twopc_recv')], zk: [b('zk_sent'), b('zk_recv')] })
}
console.log('medians; bytes are [client to node, node to client]; for "armed" they count from the claim (the arming itself is not included)')
console.table(out)
console.log('BENCH_JSON ' + JSON.stringify(out))
JS
