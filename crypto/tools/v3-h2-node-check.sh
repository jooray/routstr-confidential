#!/usr/bin/env bash
# Gate for protocol v3, option A (`http: 2`, PROTOCOL-V3-DESIGN.md A) through a
# routstr node: the node reserves and settles every request of a connection.
# Starts a cu-sidecar and a routstr-core node on scratch state, runs the cases
# with the reference driver against the real provider, checks the money
# outcome of each case in the node's database, stops everything. Exit 0 only
# if every case ends exactly as expected.
#
#   VENICE_API_KEY=... crypto/tools/v3-h2-node-check.sh
#
# The node announces nothing (its relay list points nowhere) and runs with a
# clean environment, so no other provider key seeds a provider. Its database
# holds the provider key while it runs, so it is removed at the end (the test
# keys' final balances are kept in api_keys.tsv). Credits are
# written into its scratch database (one fresh key per case); no mint is
# needed. Every request is small (max_tokens 20).
#
# Environment:
#   CU_CORE          the routstr-core checkout, on a branch with http: 2 sessions
#                    (default ../routstr-core next to crypto/, with its .venv)
#   CU_H2_PORT       loopback port of the sidecar (default 7470)
#   CU_NODE_PORT     loopback port of the node (default 8010)
#   CU_H2_OFFER      sidecar offer file (default relay/offer.venice.h2.json)
#   CU_KEY_ENV       variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM      provider host:port (default api.venice.ai:443)
#   CU_UPSTREAM_BASE the provider's API base for the node (default https://api.venice.ai/api/v1)
#   CU_MODEL         chat model (default mistral-small-3-2-24b-instruct)
#   CU_CASES         optional space-separated subset of case ids (v2 always runs:
#                    the other cases compare their reservation with it)
#   CU_H2_PAUSE      seconds of idle time in the `idle` case (default 0 = skip)
#   CU_CASE_TIMEOUT  per-case limit in seconds (default 180, plus the pause)
#   CU_H2_NODE_OUT   scratch and evidence directory (default crypto/runs/v3-h2-node-check;
#                    removed and recreated)
#
# Cases (machine-checked by v3_h2_node_eval.py; each has its own funded key):
#   v2              an unchanged protocol v2 session through the same node
#   three           three requests on one connection: each reserved as a v2 setup
#                   reserves, each settled at the usage the provider reported
#   idle            (CU_H2_PAUSE > 0) two requests with that pause between them: the
#                   idle connection holds no reservation
#   provider-error  request 2 carries a parameter the provider refuses (400): its
#                   error head is disclosed, its reservation released (v2's rule)
#   unknown-model   request 2 names a model the node does not sell: refused by
#                   the node, nothing reserved; request 1 stays settled
#   wrong-suffix    request 2's body ends in another model's suffix: π_WIN fails,
#                   the provider never has the request, its reservation is released
#   replay-usage    request 2 is released and "settled" with request 1's usage: the
#                   sidecar refuses, and the node charges request 2's reservation
#                   (what v2 charges for a released request with no disclosure)
#   no-funds        a setup with an unfunded key: refused (402) before the sidecar
#                   is dialed, so it gets no garbled circuit
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
CORE="${CU_CORE:-$CRYPTO/../routstr-core}"
OUT="${CU_H2_NODE_OUT:-$CRYPTO/runs/v3-h2-node-check}"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-180}"
PAUSE="${CU_H2_PAUSE:-0}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
SPORT="${CU_H2_PORT:-7470}"
NPORT="${CU_NODE_PORT:-8010}"
START_BALANCE=200000000
export CU_PROVER="${CU_PROVER:-$CRYPTO/zkbench/target/release/cu-prover}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"
PY="$(command -v python3)"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }
command -v sqlite3 > /dev/null || { echo "need sqlite3" >&2; exit 2; }
[ -n "${!KEY_ENV:-}" ] || { echo "$KEY_ENV is not set" >&2; exit 2; }
BIN="$CRYPTO/zkbench/target/release/cu-sidecar"
[ -x "$BIN" ] || { echo "build first: (cd crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc)" >&2; exit 2; }
CORE="$(cd "$CORE" && pwd)" || { echo "no routstr-core checkout at ${CU_CORE:-$CRYPTO/../routstr-core}" >&2; exit 2; }
[ -x "$CORE/.venv/bin/uvicorn" ] || { echo "no $CORE/.venv/bin/uvicorn" >&2; exit 2; }
grep -q '_run_h2_session' "$CORE/routstr/confidential_ws.py" || { echo "$CORE has no http: 2 sessions (branch confidential-v3)" >&2; exit 2; }

listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; }
for port in "$SPORT" "$NPORT"; do
  if listening "$port"; then echo "port $port is in use" >&2; exit 2; fi
done

rm -rf "$OUT"
mkdir -p "$OUT/node" "$OUT/sidecar-runs" "$OUT/client-runs"
OUT="$(cd "$OUT" && pwd)"
# The node resolves its migrations and writes its logs relative to its
# working directory: it runs in the scratch directory.
ln -s "$CORE/migrations" "$OUT/node/migrations"
DB="$OUT/node.db"
NODE="http://127.0.0.1:$NPORT"
SIDECAR="http://127.0.0.1:$SPORT"

SIDECAR_PID=""
NODE_PID=""
stop() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop "$NODE_PID"; NODE_PID=""
  stop "$SIDECAR_PID"; SIDECAR_PID=""
  # The node stores its provider key in its database (provider row and
  # settings): keep the keys' final balances as evidence and remove it.
  if [ -f "$DB" ]; then
    sqlite3 -header -separator $'\t' "$DB" \
      "select hashed_key, balance, reserved_balance, total_spent, total_requests from api_keys;" > "$OUT/api_keys.tsv" 2>/dev/null || true
    rm -f "$DB" "$DB-wal" "$DB-shm"
  fi
}
trap cleanup EXIT

"$BIN" --listen "127.0.0.1:$SPORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" --key-env "$KEY_ENV" \
  --offer "${CU_H2_OFFER:-$CRYPTO/relay/offer.venice.h2.json}" --node-settles --runs-dir "$OUT/sidecar-runs" > "$OUT/sidecar.log" 2>&1 &
SIDECAR_PID=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "$SIDECAR/offer" 2>/dev/null && break
  kill -0 "$SIDECAR_PID" 2>/dev/null || { echo "the sidecar did not start; see $OUT/sidecar.log" >&2; exit 2; }
  sleep 0.2
done
curl -fsS "$SIDECAR/offer" | grep -Eq '"http": *\[[^]]*"2"' || { echo "the sidecar does not offer http 2" >&2; exit 2; }

# A clean environment: no other provider key may seed a provider, and nothing
# is published (the relay list points nowhere). The node's signing key is a
# throwaway one.
NSEC="$(openssl rand -hex 32)"
UPSTREAM_BASE="${CU_UPSTREAM_BASE:-https://api.venice.ai/api/v1}"
start_node() {
  (
    cd "$OUT/node"
    provider_key="${!KEY_ENV}"
    # Unset everything exported except what the node needs (the key never
    # appears on a command line).
    for v in $(compgen -e); do
      case "$v" in PATH|HOME|TMPDIR) ;; *) unset "$v" 2>/dev/null || true ;; esac
    done
    export DATABASE_URL="sqlite+aiosqlite:///$DB" NSEC="$NSEC" \
      CONFIDENTIAL_SIDECAR_URL="$SIDECAR" CASHU_MINTS=http://127.0.0.1:3338 \
      UPSTREAM_BASE_URL="$UPSTREAM_BASE" UPSTREAM_API_KEY="$provider_key" \
      HTTP_URL="$NODE" RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false
    exec "$CORE/.venv/bin/uvicorn" --app-dir "$CORE" routstr.core.main:app --host 127.0.0.1 --port "$NPORT" \
      --ws-ping-timeout 300
  ) >> "$OUT/node.out" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 300); do
    curl -fsS -o /dev/null "$NODE/v1/confidential/offer" 2>/dev/null && return 0
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 0.2
  done
  echo "the node did not start; see $OUT/node.out" >&2
  exit 2
}
# The first start seeds a `custom` provider from UPSTREAM_BASE_URL, whose
# offer has no models; as `venice` (AGENTS.md) the second start prices them.
start_node
stop "$NODE_PID"; NODE_PID=""
sqlite3 "$DB" "delete from upstream_providers where base_url not like '%venice%'; update upstream_providers set provider_type='venice';"
start_node
for _ in $(seq 1 150); do
  curl -fsS "$NODE/v1/confidential/offer" > "$OUT/offer.json" 2>/dev/null \
    && "$PY" -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if sys.argv[2] in o.get("price_list", {}) else 1)' "$OUT/offer.json" "$MODEL" && break
  sleep 0.4
done
"$PY" -I - "$OUT/offer.json" "$MODEL" <<'PYEOF' || { echo "the node's offer is not usable; see $OUT/offer.json and $OUT/node.out" >&2; exit 2; }
import json, sys
o = json.load(open(sys.argv[1]))
ok = sys.argv[2] in o.get("price_list", {}) and "2" in (o.get("http") or []) and isinstance(o.get("h2"), dict) and o.get("sig")
sys.exit(0 if ok else 1)
PYEOF

# Offline first: the client's HTTP/2 layer against the sidecar's vectors.
(cd "$CRYPTO/client" && node --experimental-strip-types src/h2-selfcheck.ts) || { echo "h2-selfcheck failed" >&2; exit 1; }

SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tevidence\n' > "$SUMMARY"
failures=0
ran=0
V2_RESERVED=0

log_lines() { cat "$OUT"/node/logs/*.log 2>/dev/null | wc -l | tr -d ' '; }
handshakes() { grep -c '2pc end' "$OUT/sidecar.log" || true; }

# run_case <id> <expectation> <balance> -- driver args...
run_case() {
  local id="$1" expect="$2" balance="$3"; shift 4
  if [ -n "${CU_CASES:-}" ] && [ "$id" != v2 ] && [[ " $CU_CASES " != *" $id "* ]]; then return 0; fi
  ran=$((ran + 1))
  echo "== $id (expect: $expect) =="
  # The case's own credential: `sk-<hex>`, stored under the hex itself.
  local key skip hs0 rc=0
  # The signed offer the driver is about to fetch (rates move with the exchange rate).
  curl -fsS "$NODE/v1/confidential/offer" > "$OUT/$id.offer.json"
  key="$(openssl rand -hex 32)"
  sqlite3 "$DB" "insert into api_keys(hashed_key,balance,total_spent,total_requests,reserved_balance) values('$key',$balance,0,0,0);"
  skip="$(log_lines)"
  hs0="$(handshakes)"
  (cd "$CRYPTO/client" && "$TIMEOUT_BIN" -k 5 "$((CASE_TIMEOUT + PAUSE))" "${DRIVER[@]}" --node "$NODE" --model "$MODEL" \
    --max-tokens 20 --auth "sk-$key" --runs-dir "$OUT/client-runs" "$@") > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  "$PY" -I - "$OUT/$id.ctx.json" <<PYEOF
import json, sys
json.dump({"db": "$DB", "key": "$key", "start_balance": $balance, "log_dir": "$OUT/node/logs", "log_skip": $skip,
           "offer": "$OUT/$id.offer.json", "v2_offer": "$OUT/v2.offer.json", "model": "$MODEL",
           "client_runs": "$OUT/client-runs", "v2_reserved": $V2_RESERVED,
           "sidecar_sessions": $(handshakes) - $hs0}, open(sys.argv[1], "w"))
PYEOF
  local res verdict evidence
  res="$("$PY" -I "$HERE/v3_h2_node_eval.py" "$id" "$expect" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$OUT/$id.ctx.json" 2>&1)" \
    || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"
  IFS=$'\t' read -r verdict evidence <<< "$res"
  printf '%s\t%s\t%s\t%s\n' "$id" "$expect" "$verdict" "$evidence" >> "$SUMMARY"
  echo "   $verdict"
  echo "   $evidence"
  case "$verdict" in PASS) ;; *) failures=$((failures + 1)) ;; esac
}

run_case v2 "v2" "$START_BALANCE" --
# What a v2 setup reserves for this model and cap: every http: 2 request must reserve the same.
V2_RESERVED="$("$PY" -I -c '
import json, sys
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("E2E_JSON "):
        print(int(json.loads(line[9:]).get("reserved_msats") or 0)); break
else:
    print(0)' "$OUT/v2.out")"
run_case three          "settled:3" "$START_BALANCE" -- --http2 --requests 3
if [ "$PAUSE" -gt 0 ]; then
  run_case idle         "settled:2" "$START_BALANCE" -- --http2 --requests 2 --pause-ms "$((PAUSE * 1000))"
fi
run_case provider-error "error:2:400" "$START_BALANCE" -- --http2 --requests 3 --private-extra '"temperature":"hot"' --private-extra-at 2
run_case unknown-model  "node-refused:2:not served confidentially" "$START_BALANCE" -- --http2 --requests 3 --h2-models "$MODEL,no-such-model-xyz"
run_case wrong-suffix   "released:2:pi_win failed" "$START_BALANCE" -- --http2 --requests 2 --adv-h2 suffix --adv-at 2
run_case replay-usage   "charged:2:interval" "$START_BALANCE" -- --http2 --requests 2 --adv-h2 replay-usage
run_case no-funds       "no-funds:402" 0 -- --http2

cleanup
still=""
for port in "$SPORT" "$NPORT"; do
  for _ in $(seq 1 25); do listening "$port" || break; sleep 0.2; done
  if listening "$port"; then still="$still $port"; fi
done

echo
column -t -s $'\t' "$SUMMARY" 2>/dev/null | cut -c1-260 || cat "$SUMMARY"
echo
if [ -n "$still" ]; then echo "FAILED: still listening on port(s)$still"; exit 1; fi
if [ "$failures" -gt 0 ]; then echo "FAILED: $failures of $ran cases deviated (evidence in $OUT)"; exit 1; fi
echo "OK: all $ran cases as expected; sidecar and node stopped (evidence in $OUT)"
