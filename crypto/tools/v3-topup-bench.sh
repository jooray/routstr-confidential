#!/usr/bin/env bash
# Measurement for the proof-channel top-up (PROTOCOL-V3.md §9.2): N chat
# requests on one kept framing-"2" connection through a routstr node, with an
# idle pause between them, against the real provider. Prints per request the
# time to first token, the bytes each way (session and proof channel), and
# the proof channel's bytes for π_WIN and π_C3S on the request path.
#
#   VENICE_API_KEY=... crypto/tools/v3-topup-bench.sh [label]
#
# Starts a cu-sidecar and a routstr-core node on scratch state (the node
# announces nothing), funds one key in the scratch database, runs the
# reference driver, stops everything and removes the database.
#
# Environment: CU_CORE, CU_V3_PORT (7444), CU_NODE_PORT (8431), CU_MODEL,
# CU_REQUESTS (5), CU_PAUSE_MS (3000), CU_MAX_TOKENS (40), CU_BENCH_OUT
# (crypto/runs/v3-topup-bench), CU_NO_TOPUP=1 (the client asks for no top-up).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
CORE="${CU_CORE:-$CRYPTO/../routstr-core}"
LABEL="${1:-run}"
OUT="${CU_BENCH_OUT:-$CRYPTO/runs/v3-topup-bench}/$LABEL"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
SPORT="${CU_V3_PORT:-7444}"
NPORT="${CU_NODE_PORT:-8431}"
REQUESTS="${CU_REQUESTS:-5}"
PAUSE="${CU_PAUSE_MS:-3000}"
MAX_TOKENS="${CU_MAX_TOKENS:-40}"
export CU_PROVER="${CU_PROVER:-$CRYPTO/zkbench/target/release/cu-prover}"
export CU_2PC="${CU_2PC:-$CRYPTO/zkbench/target/release/cu-2pc}"
PY="$(command -v python3)"
[ -n "${VENICE_API_KEY:-}" ] || { echo "VENICE_API_KEY is not set" >&2; exit 2; }
BIN="$CRYPTO/zkbench/target/release/cu-sidecar"
[ -x "$BIN" ] || { echo "build first" >&2; exit 2; }
CORE="$(cd "$CORE" && pwd)"

rm -rf "$OUT"
mkdir -p "$OUT/node" "$OUT/sidecar-runs" "$OUT/client-runs"
OUT="$(cd "$OUT" && pwd)"
ln -s "$CORE/migrations" "$OUT/node/migrations"
DB="$OUT/node.db"
NODE="http://127.0.0.1:$NPORT"
SIDECAR_PID=""
NODE_PID=""
stop() { [ -n "$1" ] || return 0; kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
cleanup() {
  stop "$NODE_PID"; stop "$SIDECAR_PID"
  rm -f "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT

"$BIN" --listen "127.0.0.1:$SPORT" --upstream api.venice.ai:443 --key-env VENICE_API_KEY \
  --offer "$CRYPTO/relay/offer.venice.json" --node-settles --runs-dir "$OUT/sidecar-runs" >> "$OUT/sidecar.log" 2>&1 &
SIDECAR_PID=$!
for _ in $(seq 1 50); do curl -fsS -o /dev/null "http://127.0.0.1:$SPORT/offer" 2>/dev/null && break; sleep 0.2; done

NSEC="$(openssl rand -hex 32)"
start_node() {
  (
    cd "$OUT/node"
    provider_key="$VENICE_API_KEY"
    for v in $(compgen -e); do
      case "$v" in PATH|HOME|TMPDIR) ;; *) unset "$v" 2>/dev/null || true ;; esac
    done
    export DATABASE_URL="sqlite+aiosqlite:///$DB" NSEC="$NSEC" \
      CONFIDENTIAL_SIDECAR_URL="http://127.0.0.1:$SPORT" CASHU_MINTS=http://127.0.0.1:3338 \
      UPSTREAM_BASE_URL=https://api.venice.ai/api/v1 UPSTREAM_API_KEY="$provider_key" \
      HTTP_URL="$NODE" RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false
    exec "$CORE/.venv/bin/uvicorn" --app-dir "$CORE" routstr.core.main:app --host 127.0.0.1 --port "$NPORT" \
      --ws-ping-timeout 300
  ) >> "$OUT/node.out" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 300); do
    curl -fsS -o /dev/null "$NODE/v1/confidential/offer?v=3" 2>/dev/null && return 0
    sleep 0.2
  done
  echo "node did not start" >&2; exit 2
}
start_node
stop "$NODE_PID"; NODE_PID=""
sqlite3 "$DB" "delete from upstream_providers where base_url not like '%venice%'; update upstream_providers set provider_type='venice';"
start_node
for _ in $(seq 1 150); do
  curl -fsS "$NODE/v1/confidential/offer?v=3" > "$OUT/offer.json" 2>/dev/null \
    && "$PY" -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if sys.argv[2] in o.get("price_list", {}) else 1)' "$OUT/offer.json" "$MODEL" && break
  sleep 0.4
done
KEY="$(openssl rand -hex 32)"
sqlite3 "$DB" "insert into api_keys(hashed_key,balance,total_spent,total_requests,reserved_balance) values('$KEY',200000000,0,0,0);"

cd "$CRYPTO/client"
node --experimental-strip-types src/driver.ts --node "$NODE" --http 2 --requests "$REQUESTS" --pause-ms "$PAUSE" \
  --model "$MODEL" --max-tokens "$MAX_TOKENS" --prompt "Name one prime number and nothing else." \
  --auth "sk-$KEY" --runs-dir "$OUT/client-runs" ${CU_NO_TOPUP:+--no-topup} > "$OUT/driver.out" 2> "$OUT/driver.err" || { echo "driver failed; see $OUT/driver.err" >&2; tail -5 "$OUT/driver.err" >&2; exit 1; }

"$PY" -I - "$OUT/driver.out" <<'PYEOF'
import json, sys
line = [l for l in open(sys.argv[1]) if l.startswith('E2E_JSON ')][-1]
s = json.loads(line[len('E2E_JSON '):])
print(f"{'n':>2} {'ttft_ms':>8} {'total_ms':>8} {'down_B':>9} {'up_B':>8} {'zk_down':>9} {'zk_up':>8}  proofs (recv B)")
for r in s['requests']:
    b = r['bytes']
    down = b.get('control_recv', 0) + b.get('relay_recv', 0) + b.get('zk_recv', 0) + b.get('twopc_recv', 0)
    up = b.get('control_sent', 0) + b.get('relay_sent', 0) + b.get('zk_sent', 0) + b.get('twopc_sent', 0)
    pr = ' '.join(f"{p['proof']}:{p.get('bytes_recv')}/{p.get('inner_ms')}ms" for p in r.get('proofs', []))
    print(f"{r['n']:>2} {r.get('ttft_ms') or 0:>8} {r['total_ms']:>8} {down:>9} {up:>8} {b.get('zk_recv',0):>9} {b.get('zk_sent',0):>8}  {pr}")
tops = [t for c in s.get('connections', []) for t in (c.get('topups') or [])]
print(f"top-ups (off the request path): {len(tops)}, {sum(t['bytes'] for t in tops)} B, " + ', '.join(f"{t['bytes']} B/{t['ms']:.0f} ms" for t in tops))
PYEOF
grep -h "zkchan" "$OUT/sidecar.log" | grep -v "zk start" | sed -e 's/\x1b\[[0-9;]*m//g' | tail -20 > "$OUT/zkchan.log" || true
echo "evidence: $OUT"
