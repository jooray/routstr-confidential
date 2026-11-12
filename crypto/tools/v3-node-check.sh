#!/usr/bin/env bash
# Gate for protocol v3 (PROTOCOL-V3.md) through a routstr node, both framings:
# the node reserves a connection deposit at the setup, reserves and settles
# every request, and this script checks the money outcome of each case in the
# node's database, to the millisat.
#
#   VENICE_API_KEY=... crypto/tools/v3-node-check.sh
#
# It starts a cu-sidecar and a routstr-core node on scratch state, runs the
# cases with the reference driver against the real provider, and stops
# everything. Exit 0 only if every case ends exactly as expected.
#
# The node announces nothing (its relay list points nowhere) and runs with a
# clean environment, so no other provider key seeds a provider. Its database
# holds the provider key while it runs, so it is removed at the end (the test
# keys' final balances are kept in api_keys.tsv). Credits are written into
# its scratch database (one fresh key per case); no mint is needed.
#
# The node charges a session fee, an abandon fee and a connection deposit
# that are all non-zero and different (3000, 5000, 7000 msat), so each rule of
# PROTOCOL-V3.md §8 and §12.10 shows in the arithmetic.
#
# Cost at the provider: every chat request is small (max_tokens 20), two send
# a ~200 kB prompt, and two honest image cases generate one image each of the
# cheapest model the node prices (about $0.01 each; CU_NO_IMAGES=1 skips them).
#
# Environment:
#   CU_CORE          the routstr-core checkout, protocol v3 (default ../routstr-core
#                    next to crypto/, with its .venv)
#   CU_V3_PORT       loopback port of the sidecar (default 7461)
#   CU_NODE_PORT     loopback port of the node (default 8431)
#   CU_V3_OFFER      sidecar offer file (default relay/offer.venice.json)
#   CU_KEY_ENV       variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM      provider host:port (default api.venice.ai:443)
#   CU_UPSTREAM_BASE the provider's API base for the node (default https://api.venice.ai/api/v1)
#   CU_MODEL         chat model (default mistral-small-3-2-24b-instruct)
#   CU_SWAP_MODEL    the model of the model-swap attacks (default deepseek-v4-pro)
#   CU_IMAGE_MODEL   image model (default venice-sd35; its first offered variant, one image)
#   CU_DECOY_MODEL   the model the decoy cases name in the private part (default CU_SWAP_MODEL)
#   CU_PROVIDER_TYPE the node's provider_type for the provider row (default venice; generic,
#                    openrouter, … for other providers)
#   CU_HOST_MATCH    a substring of the provider's base URL: the other provider rows are
#                    deleted (default venice)
#   CU_NO_IMAGES     1: skip the two paid image cases
#   CU_CASES         optional space-separated subset of case ids ("fb" selects the
#                    whole fallback group)
#   CU_SLOW          1: also run setup-timeout (an armed connection left for 600 s)
#   CU_CASE_TIMEOUT  per-case limit in seconds (default 180)
#   CU_NODE_OUT      scratch and evidence directory (default crypto/runs/v3-node-check;
#                    removed and recreated)
#
# Cases (machine-checked by v3_node_eval.py; each has its own funded key).
# `h2-` = framing "2", `h11-` = framing "1.1". F = session fee, A = abandon
# fee, D = deposit.
#  honest
#   h2-one, h11-one         one chat request: usage + F, D back in its receipt
#   h2-three                three requests on one connection: F once
#   h11-two                 two requests, one connection each: F and D each time
#   h2-decoy, h11-decoy     another model named in the private part: the pinned one runs and is billed
#   h2-big, h11-big         a ~200 kB body
#   h2-armed, h11-armed     a connection armed first (bound to the credential only)
#   h2-chat-image           a chat request, then an image request on one connection:
#                           the image costs its signed price, no second F
#   h11-image               an image request: price + F
#   h2-error                request 2 is refused by the provider (400): A, `error_settled`
#   h2-error-first, h11-error   the same as request 1: A (which covers F), D back
#   h2-refused, h11-refused a request the node refuses (400), then the good one, same n
#   h2-402, h11-402         request 1 refused with 402 (the balance covers D, not the
#                           reservation), topped up, accepted on the same connection
#   h2-offer-changed        the node's offer changes (idle timeout) between two requests:
#                           request 2 naming the new offer is refused (`offer_changed`),
#                           naming the connection's own offer it is served
#   h2-unknown-model        request 2 names a model the node does not sell: refused,
#                           nothing reserved; request 1 stays settled
#   h11-unknown-model       the same as request 1: the connection ends unused, D charged
#   h2-no-fee-echo          a request that does not echo the fees: refused (409), D charged
#   h2-idle-after           one request, then idle: closed after the idle timeout, nothing held
#  attacks (refused by the sidecar; the node's money outcome)
#   h2-a-hidden-headers, h2-b-padding, h2-c-model-swap, h2-f-image-suffix
#                           on request 2: never released, A is kept
#   h2-c-suffix, h11-c-suffix, h11-c-model-swap, h11-b-padding, h11-f-image-suffix
#                           on request 1: D is charged (`request_abandoned`), the
#                           reservation released in full
#   h2-d-replay-usage       request 2 is released and "settled" with request 1's usage:
#                           refused, its reservation is charged in full
#   h2-g-early-record, h2-i-own-keyshare
#                           the connection itself: D charged (`unused`)
#  cancel and reuse (a force-stopped request whose credential reference a later one rides on)
#   h2-k-rst-reuse, h2-k-rst-reuse-same   request 2 released, RST_STREAM, then a HEADERS record for
#                           the next / the same stream with no `request`: refused before it is queued
#                           (nothing reaches the provider), request 2's reservation charged in full
#   h2-k-rst-before-final   request 2's last DATA record never released, RST_STREAM (held behind it),
#                           then `request` 3: refused (one request at a time), request 2 released less A
#   h2-k-rst-after-release  RST_STREAM after body_released, no disclosure, then `request` 3: refused,
#                           request 2 charged in full (a cancelled request is never cheaper than its bound)
#   h2-k-ctl-headers        a record declared as a PING ACK carrying a HEADERS frame: π_WIN fails,
#                           nothing written, request 2 released less A
#   h11-k-extra-record      a record carrying a second HTTP request after the final one: refused,
#                           request 1 charged in full
#   h11-k-pipelined         a second HTTP request inside the body: one body to the provider (400),
#                           settled as an error head (A)
#  the deposit table (§12.10)
#   no-funds                row 1: a setup with an unfunded key (402), sidecar not dialed
#   low-balance             row 1: funds below D (402 `connection_deposit_unfunded`)
#   sidecar-down            row 2: the sidecar is gone at the setup: D released (`not_started`)
#   fb-h2                   row 3: the HTTP/2 open fails (test hook): D released
#                           (`provider_unreachable`)
#   sidecar-killed          row 4: the sidecar dies under an open connection: D released
#                           (`sidecar_failure`)
#   h2-received, h11-received  row 7: request 1 is written in full and the client is
#                           killed: the reservation is charged, D released
#   h2-c-suffix …           row 9 (above)
#   idle-drop               row 10: opened and left idle: D charged (`idle`), signed
#   setup-timeout           row 11 (CU_SLOW=1): armed and left for 600 s: D charged
#   open-drop, armed-drop   row 12: opened (or armed) and dropped: D charged (`unused`)
#   (rows 5, 6 and 8 need the provider or the node's database to fail: unit tests)
#  versions
#   legacy-v2, legacy-no-v  a v2 socket, a socket with no version: 426 `upgrade_required`
#  fallback (the sidecar's test hooks; framing "2" is made to fail)
#   fb-1 … fb-4             `--http auto` falls back to "1.1" on the same node; the
#                           failed connection's D is released, the request settles
#   fb-offer-11             after five failures the node's offer lists only "1.1"
#   fb-auto-11              `--http auto` opens "1.1" at once
#   fb-offer-back           the failure is lifted: the offer lists "2" again
#   fb-auto-2               `--http auto` is on framing "2" again
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
CORE="${CU_CORE:-$CRYPTO/../routstr-core}"
OUT="${CU_NODE_OUT:-$CRYPTO/runs/v3-node-check}"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
SWAP_MODEL="${CU_SWAP_MODEL:-deepseek-v4-pro}"
IMAGE_MODEL="${CU_IMAGE_MODEL:-venice-sd35}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-180}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
SPORT="${CU_V3_PORT:-7461}"
NPORT="${CU_NODE_PORT:-8431}"
START_BALANCE=200000000
FEE=3000
ABANDON=5000
DEPOSIT=7000
IDLE=12
# The sidecar offers "2" again this long after it withdrew it: longer than the
# 30 s the node caches the sidecar's offer, so the node's offer shows the withdrawal.
RETRY_SECS=45
MAX_TOKENS=20
export CU_PROVER="${CU_PROVER:-$CRYPTO/zkbench/target/release/cu-prover}"
export CU_2PC="${CU_2PC:-$CRYPTO/zkbench/target/release/cu-2pc}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"
PY="$(command -v python3)"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }
command -v sqlite3 > /dev/null || { echo "need sqlite3" >&2; exit 2; }
[ -n "${!KEY_ENV:-}" ] || { echo "$KEY_ENV is not set" >&2; exit 2; }
BIN="${CU_SIDECAR_BIN:-$CRYPTO/zkbench/target/release/cu-sidecar}"
[ -x "$BIN" ] || { echo "build first: (cd crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc)" >&2; exit 2; }
CORE="$(cd "$CORE" && pwd)" || { echo "no routstr-core checkout at ${CU_CORE:-$CRYPTO/../routstr-core}" >&2; exit 2; }
[ -x "$CORE/.venv/bin/uvicorn" ] || { echo "no $CORE/.venv/bin/uvicorn" >&2; exit 2; }
grep -q 'CONFIDENTIAL_VERSION = 3' "$CORE/routstr/confidential.py" || { echo "$CORE does not speak protocol v3 (branch confidential-v3)" >&2; exit 2; }

listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; }
for port in "$SPORT" "$NPORT"; do
  if listening "$port"; then echo "port $port is in use" >&2; exit 2; fi
done

rm -rf "$OUT"
mkdir -p "$OUT/node" "$OUT/sidecar-runs" "$OUT/client-runs"
# The node's database holds the provider key while it runs: owner only.
chmod 700 "$OUT"
OUT="$(cd "$OUT" && pwd)"
# The node resolves its migrations and writes its logs relative to its
# working directory: it runs in the scratch directory.
ln -s "$CORE/migrations" "$OUT/node/migrations"
DB="$OUT/node.db"
NODE="http://127.0.0.1:$NPORT"
SIDECAR="http://127.0.0.1:$SPORT"
FAIL_FILE="$OUT/h2-fail"

SIDECAR_PID=""
NODE_PID=""
stop() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  rm -f "$FAIL_FILE"
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

start_sidecar() {
  CU_TEST_H2_FAIL_FILE="$FAIL_FILE" CU_TEST_H2_RETRY_SECS="$RETRY_SECS" \
    "$BIN" --listen "127.0.0.1:$SPORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" --key-env "$KEY_ENV" \
    --offer "${CU_V3_OFFER:-$CRYPTO/relay/offer.venice.json}" --node-settles --runs-dir "$OUT/sidecar-runs" >> "$OUT/sidecar.log" 2>&1 &
  SIDECAR_PID=$!
  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "$SIDECAR/offer" 2>/dev/null && return 0
    kill -0 "$SIDECAR_PID" 2>/dev/null || break
    sleep 0.2
  done
  echo "the sidecar did not start; see $OUT/sidecar.log" >&2
  exit 2
}
start_sidecar

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
      HTTP_URL="$NODE" RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false \
      CONFIDENTIAL_SESSION_FEE_MSAT="$FEE" CONFIDENTIAL_ABANDON_FEE_MSAT="$ABANDON" \
      CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT="$DEPOSIT" CONFIDENTIAL_IDLE_TIMEOUT_S="$IDLE"
    exec "$CORE/.venv/bin/uvicorn" --app-dir "$CORE" routstr.core.main:app --host 127.0.0.1 --port "$NPORT" \
      --ws-ping-timeout 300
  ) >> "$OUT/node.out" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 300); do
    curl -fsS -o /dev/null "$NODE/v1/confidential/offer?v=3" 2>/dev/null && return 0
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
sqlite3 "$DB" "delete from upstream_providers where base_url not like '%${CU_HOST_MATCH:-venice}%'; update upstream_providers set provider_type='${CU_PROVIDER_TYPE:-venice}';"
# An admin token for the one case that changes a setting while the node runs.
ADMIN_TOKEN="$(openssl rand -hex 24)"
sqlite3 "$DB" "insert into cli_tokens(id,token,name,created_at) values('v3-node-check','$ADMIN_TOKEN','v3-node-check',strftime('%s','now'));"
start_node
fetch_offer() { curl -fsS "$NODE/v1/confidential/offer?v=3"; }
for _ in $(seq 1 150); do
  fetch_offer > "$OUT/offer.json" 2>/dev/null \
    && "$PY" -I -c 'import json,sys; o=json.load(open(sys.argv[1])); sys.exit(0 if sys.argv[2] in o.get("price_list", {}) else 1)' "$OUT/offer.json" "$MODEL" && break
  sleep 0.4
done
"$PY" -I - "$OUT/offer.json" "$MODEL" "$FEE" "$ABANDON" "$DEPOSIT" "$IDLE" "$IMAGE_MODEL" "${CU_NO_IMAGES:-0}" <<'PYEOF' || { echo "the node's offer is not usable; see $OUT/offer.json and $OUT/node.out" >&2; exit 2; }
import json, sys
o = json.load(open(sys.argv[1]))
model, fee, abandon, deposit, idle, image_model, no_images = sys.argv[2:9]
problems = []
if model not in o.get("price_list", {}): problems.append(f"no price for {model}")
if o.get("v") != 3 or o.get("twopc") != "split-public-1": problems.append("not a v3 offer")
if o.get("http") != ["2", "1.1"] or not isinstance(o.get("h2"), dict): problems.append(f"http is {o.get('http')}")
if not o.get("sig"): problems.append("unsigned")
want = {"session_fee_msat": int(fee), "abandon_fee_msat": int(abandon), "connection_deposit_msat": int(deposit), "idle_timeout_s": int(idle)}
for k, v in want.items():
    if o.get(k) != v: problems.append(f"{k} is {o.get(k)}, not {v}")
if no_images != "1":
    if o["h2"].get("kinds") != ["chat", "images"]: problems.append("no images on framing 2")
    if image_model not in (o.get("images") or {}).get("price_list", {}): problems.append(f"no image price for {image_model}")
if problems:
    print("offer: " + "; ".join(problems), file=sys.stderr)
    sys.exit(1)
PYEOF
curl -fsS "$NODE/v1/models" | "$PY" -I -c '
import json, sys
d = json.load(sys.stdin)
json.dump([{k: m.get(k) for k in ("id", "context_length", "top_provider")} for m in d.get("data", d)], sys.stdout)' > "$OUT/models.json"

# Offline first: the client's HTTP/2 layer against the sidecar's vectors.
(cd "$CRYPTO/client" && node --experimental-strip-types src/h2-selfcheck.ts > /dev/null) || { echo "h2-selfcheck failed" >&2; exit 1; }

SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tevidence\n' > "$SUMMARY"
failures=0
ran=0

selected() { # "fb" selects every fb-* case
  [ -z "${CU_CASES:-}" ] || [[ " $CU_CASES " == *" $1 "* ]] || { [[ "$1" == fb-* ]] && [[ " $CU_CASES " == *" fb "* ]]; }
}
log_lines() { cat "$OUT"/node/logs/*.log 2>/dev/null | wc -l | tr -d ' '; }
handshakes() { grep -c '2pc end' "$OUT/sidecar.log" || true; }
record() { # id expect verdict evidence
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$SUMMARY"
  echo "   $3"
  echo "   $4"
  case "$3" in PASS) ;; *) failures=$((failures + 1)) ;; esac
}
set_idle() { # the node's idle timeout, through its admin API (changes the signed offer)
  curl -fsS -o /dev/null -X PATCH -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"confidential_idle_timeout_s\": $1}" "$NODE/admin/api/settings"
}
# wait_for <file> <pattern> <seconds>: until the driver printed the pattern.
wait_for() {
  local i
  for i in $(seq 1 $(($3 * 10))); do
    grep -q -- "$2" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# run_case <id> <expectation> <balance> <hook> -- driver args...
# Hooks (what the script does while the driver runs):
#   none          nothing
#   go            an armed connection waits for "go" on stdin: sent once it is ready
#   hold          stdin stays open and silent (an armed connection that is never claimed)
#   topup         when the driver reports a 402 refusal, add funds to the key
#   offer         after the first receipt, change the node's idle timeout (a new offer)
#   kill-driver   kill the driver when it sees `body_released`
#   kill-sidecar  kill the sidecar when the connection head is written
run_case() {
  local id="$1" expect="$2" balance="$3" hook="$4"; shift 5
  selected "$id" || return 0
  ran=$((ran + 1))
  echo "== $id (expect: $expect) =="
  # The case's own credential: `sk-<hex>`, stored under the hex itself.
  local key skip hs0 rc=0 topup=0 limit="$CASE_TIMEOUT" watcher=""
  local max_tokens="$MAX_TOKENS" prev="" arg
  for arg in "$@"; do
    if [ "$prev" = --max-tokens ]; then max_tokens="$arg"; fi
    prev="$arg"
  done
  # The signed offer before the case (rates move with the exchange rate).
  fetch_offer > "$OUT/$id.offer.json"
  key="$(openssl rand -hex 32)"
  sqlite3 "$DB" "insert into api_keys(hashed_key,balance,total_spent,total_requests,reserved_balance) values('$key',$balance,0,0,0);"
  skip="$(log_lines)"
  hs0="$(handshakes)"
  : > "$OUT/$id.out"; : > "$OUT/$id.err"
  case "$hook" in
    topup)
      topup=1000000
      ( wait_for "$OUT/$id.out" '^REFUSED_WAIT' "$CASE_TIMEOUT" && sqlite3 "$DB" "update api_keys set balance = balance + $topup where hashed_key='$key';" ) & watcher=$! ;;
    offer)
      ( wait_for "$OUT/$id.out" 'receipt 1:' "$CASE_TIMEOUT" && set_idle "$((IDLE + 1))" ) & watcher=$! ;;
    kill-driver)
      ( wait_for "$OUT/$id.err" '<- body_released' "$CASE_TIMEOUT" && pkill -9 -f -- "--auth sk-$key" ) & watcher=$! ;;
    kill-sidecar)
      ( wait_for "$OUT/$id.err" '<- head_written' "$CASE_TIMEOUT" && kill -9 "$SIDECAR_PID" ) & watcher=$! ;;
    hold) limit=700 ;;
  esac
  (
    cd "$CRYPTO/client"
    # The case's own flags come first: the driver takes the first of a repeated flag.
    run() { "$TIMEOUT_BIN" -k 5 "$limit" "${DRIVER[@]}" "$@" --node "$NODE" --model "$MODEL" --max-tokens "$MAX_TOKENS" \
      --auth "sk-$key" --runs-dir "$OUT/client-runs"; }
    case "$hook" in
      go) ( wait_for "$OUT/$id.out" '^READY' "$CASE_TIMEOUT"; sleep 1; echo go ) | run "$@" ;;
      hold) sleep "$limit" | run "$@" ;;
      *) run "$@" < /dev/null ;;
    esac
  ) > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  if [ -n "$watcher" ]; then kill "$watcher" 2>/dev/null || true; wait "$watcher" 2>/dev/null || true; fi
  if [ "$hook" = offer ]; then set_idle "$IDLE"; fi
  # The signed offer after the case, too: a receipt's rates are one of the two.
  fetch_offer > "$OUT/$id.offer-after.json" 2>/dev/null || cp "$OUT/$id.offer.json" "$OUT/$id.offer-after.json"
  if [ "$hook" = topup ] && ! grep -q '^REFUSED_WAIT' "$OUT/$id.out"; then topup=0; fi
  sleep 0.5
  "$PY" -I - "$OUT/$id.ctx.json" <<PYEOF
import json, sys
json.dump({"db": "$DB", "key": "$key", "start_balance": $balance, "topup": $topup, "log_dir": "$OUT/node/logs", "log_skip": $skip,
           "offers": ["$OUT/$id.offer.json", "$OUT/$id.offer-after.json"], "models": json.load(open("$OUT/models.json")),
           "model": "$MODEL", "max_tokens": $max_tokens, "client_runs": "$OUT/client-runs",
           "handshakes": $(handshakes) - $hs0}, open(sys.argv[1], "w"))
PYEOF
  local res verdict evidence
  res="$("$PY" -I "$HERE/v3_node_eval.py" "$id" "$expect" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$OUT/$id.ctx.json" 2>&1)" \
    || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"
  IFS=$'\t' read -r verdict evidence <<< "$res"
  record "$id" "$expect" "$verdict" "$evidence"
}

# check_offer <id> <expected http list> <seconds>: the node's signed offer lists these framings (within the time).
offer_http() { fetch_offer | "$PY" -I -c 'import json,sys; print(",".join(json.load(sys.stdin).get("http") or []))'; }
check_offer() {
  local id="$1" want="$2" secs="$3" got="" i
  selected "$id" || return 0
  ran=$((ran + 1))
  echo "== $id (expect: the node's offer lists http $want) =="
  for i in $(seq 1 "$secs"); do
    got="$(offer_http 2>/dev/null || true)"
    [ "$got" = "$want" ] && break
    sleep 1
  done
  if [ "$got" = "$want" ]; then record "$id" "$want" PASS "offer http = $got"; else record "$id" "$want" "DEVIATION: the offer's http is $got" "-"; fi
}

B="$START_BALANCE"
BIG='Reply with the single word OK.'
RED='a red circle on a white background'
ERR=(--private-extra '"temperature":"hot"')
IMG=(--image-model "$IMAGE_MODEL" --prompt "$RED")
# Covers the deposit and the setup's floor, not a request's reservation.
LOW=$((DEPOSIT + ABANDON + 8000))

# --- honest ------------------------------------------------------------------
run_case h2-one        "settled:2:chat:nofallback"      "$B" none -- --http 2
run_case h11-one       "settled:1.1:chat"               "$B" none -- --http 1.1
run_case h2-three      "settled:2:chat,chat,chat"       "$B" none -- --http 2 --requests 3
run_case h11-two       "settled:1.1:chat,chat"          "$B" none -- --http 1.1 --requests 2
run_case h2-decoy      "settled:2:chat:decoy"           "$B" none -- --http 2 --decoy-model "${CU_DECOY_MODEL:-$SWAP_MODEL}"
run_case h11-decoy     "settled:1.1:chat:decoy"         "$B" none -- --http 1.1 --decoy-model "${CU_DECOY_MODEL:-$SWAP_MODEL}"
run_case h2-big        "settled:2:chat:big"             "$B" none -- --http 2 --body-bytes 200000 --prompt "$BIG"
run_case h11-big       "settled:1.1:chat:big"           "$B" none -- --http 1.1 --body-bytes 200000 --prompt "$BIG"
run_case h2-armed      "settled:2:chat:armed"           "$B" go   -- --http 2 --arm
run_case h11-armed     "settled:1.1:chat:armed"         "$B" go   -- --http 1.1 --arm
if [ "${CU_NO_IMAGES:-0}" != 1 ]; then
  run_case h2-chat-image "settled:2:chat,images"        "$B" none -- --http 2 --requests 2 --kinds chat,images "${IMG[@]}"
  run_case h11-image     "settled:1.1:images"           "$B" none -- --http 1.1 --image "${IMG[@]}"
fi
run_case h2-error       "error:2:2:400"                 "$B" none -- --http 2 --requests 3 "${ERR[@]}" --private-extra-at 2
run_case h2-error-first "error:2:1:400"                 "$B" none -- --http 2 "${ERR[@]}"
run_case h11-error      "error:1.1:1:400"               "$B" none -- --http 1.1 "${ERR[@]}"
run_case h2-refused     "settled:2:chat:refused400"     "$B" none -- --http 2 --refuse-first
run_case h11-refused    "settled:1.1:chat:refused400"   "$B" none -- --http 1.1 --refuse-first
run_case h2-402         "settled:2:chat:refused402"     "$LOW" topup -- --http 2 --retry-refused-ms 4000
run_case h11-402        "settled:1.1:chat:refused402"   "$LOW" topup -- --http 1.1 --retry-refused-ms 4000
run_case h2-offer-changed "settled:2:chat,chat:offerchanged" "$B" offer -- --http 2 --requests 2 --pause-ms 4000 --offer-at 2
run_case h2-unknown-model  "node-refused:2:2:400:not served confidentially"   "$B" none -- --http 2 --requests 3 --models "$MODEL,no-such-model-xyz"
run_case h11-unknown-model "node-refused:1.1:1:400:not served confidentially" "$B" none -- --http 1.1 --models no-such-model-xyz
run_case h2-no-fee-echo    "node-refused:2:1:409:must accept"                 "$B" none -- --http 2 --no-accept-fee
run_case h2-idle-after  "settled:2:chat:idle"           "$B" none -- --http 2 --linger-ms "$(((IDLE + 20) * 1000))"

# --- attacks -----------------------------------------------------------------
run_case h2-a-hidden-headers "attack:2:2:abandoned:pi_win failed" "$B" none -- --http 2 --requests 2 --adv hidden-headers --adv-at 2
run_case h2-b-padding        "attack:2:2:abandoned:pi_win failed" "$B" none -- --http 2 --requests 2 --adv padding --adv-at 2
run_case h2-c-model-swap     "attack:2:2:abandoned:pi_win failed" "$B" none -- --http 2 --requests 2 --adv suffix --adv-suffix-model "$SWAP_MODEL" --adv-at 2
run_case h2-c-suffix         "attack:2:1:abandoned:pi_win failed" "$B" none -- --http 2 --adv suffix
run_case h2-d-replay-usage   "attack:2:2:charged:interval"        "$B" none -- --http 2 --requests 2 --adv replay-usage
run_case h2-f-image-suffix   "attack:2:2:abandoned:pi_win failed" "$B" none -- --http 2 --requests 2 --kinds chat,images "${IMG[@]}" --adv suffix --adv-at 2
run_case h2-g-early-record   "attack:2:0:unused:."                "$B" none -- --http 2 --adv early-record
run_case h2-i-own-keyshare   "attack:2:0:unused:share"            "$B" none -- --http 2 --adv own-keyshare
run_case h11-c-suffix        "attack:1.1:1:abandoned:pi_win failed" "$B" none -- --http 1.1 --adv suffix
run_case h11-c-model-swap    "attack:1.1:1:abandoned:."             "$B" none -- --http 1.1 --adv suffix --adv-suffix-model "$SWAP_MODEL"
run_case h11-b-padding       "attack:1.1:1:abandoned:pi_win failed" "$B" none -- --http 1.1 --adv padding
run_case h11-f-image-suffix  "attack:1.1:1:abandoned:pi_win failed" "$B" none -- --http 1.1 --image "${IMG[@]}" --adv suffix
run_case h2-k-rst-reuse        "attack:2:2:charged:outside a request" "$B" none -- --http 2 --requests 2 --adv rst-reuse --adv-at 2
run_case h2-k-rst-reuse-same   "attack:2:2:charged:outside a request" "$B" none -- --http 2 --requests 2 --adv rst-reuse-same --adv-at 2
run_case h2-k-rst-before-final "attack:2:2:abandoned:already in flight" "$B" none -- --http 2 --requests 2 --adv rst-before-final --adv-at 2
run_case h2-k-rst-after-release "attack:2:2:charged:already in flight" "$B" none -- --http 2 --requests 2 --adv rst-after-release --adv-at 2
run_case h2-k-ctl-headers      "attack:2:2:abandoned:pi_win failed"   "$B" none -- --http 2 --requests 2 --adv ctl-headers --adv-at 2
run_case h11-k-extra-record    "attack:1.1:1:charged:exceeds declared length" "$B" none -- --http 1.1 --adv extra-record
run_case h11-k-pipelined       "error:1.1:1:400" "$B" none -- --http 1.1 --private-extra $'"x":1}\r\n\r\nPOST /api/v1/chat/completions HTTP/1.1\r\nHost: x\r\n\r\n{'

# --- the deposit table, versions ---------------------------------------------
run_case no-funds      "setup-refused:402:insufficient"      0                 none -- --http 2
run_case low-balance   "setup-refused:402:connection deposit" "$((DEPOSIT - 1))" none -- --http 1.1
run_case open-drop     "unused:unused"                       "$B" none -- --http 2 --requests 0
run_case armed-drop    "unused:unused"                       "$B" none -- --http 1.1 --abandon
run_case idle-drop     "unused:idle"                         "$B" none -- --http 2 --requests 0 --linger-ms "$(((IDLE + 20) * 1000))"
run_case h2-received   "received:2"                          "$B" kill-driver -- --http 2 --max-tokens 600 --prompt 'Write a 400 word essay about rivers.'
run_case h11-received  "received:1.1"                        "$B" kill-driver -- --http 1.1 --max-tokens 600 --prompt 'Write a 400 word essay about rivers.'
run_case legacy-v2     "legacy"                              "$B" none -- --legacy-v2-socket
run_case legacy-no-v   "legacy"                              "$B" none -- --legacy-v2-socket --legacy-no-v
if [ "${CU_SLOW:-0}" = 1 ]; then
  run_case setup-timeout "unused:setup_timeout:anyrc"        "$B" hold -- --http 2 --arm
fi

# --- forced failure of framing "2": the deposit, the fallback, the offer ---------
if [ -z "${CU_CASES:-}" ] || [[ " $CU_CASES " == *" fb"* ]]; then
  touch "$FAIL_FILE"
  run_case fb-h2 "released:provider_unreachable:anyrc" "$B" none -- --http 2
  for i in 1 2 3 4; do run_case "fb-$i" "settled:1.1:chat:fallback" "$B" none -- --http auto; done
  # Five opens failed: the sidecar withdrew "2"; the node's offer follows (it
  # caches the sidecar's offer for 30 s).
  check_offer fb-offer-11 "1.1" 45
  run_case fb-auto-11 "settled:1.1:chat:nofallback" "$B" none -- --http auto
  rm -f "$FAIL_FILE"
  check_offer fb-offer-back "2,1.1" "$((RETRY_SECS + 45))"
  run_case fb-auto-2 "settled:2:chat:nofallback" "$B" none -- --http auto
fi

# --- the sidecar fails (last: it is not started again) ---------------------------
run_case sidecar-killed "released:sidecar_failure:anyrc" "$B" kill-sidecar -- --http 2 --requests 0 --linger-ms 20000
if selected sidecar-down; then
  kill -9 "$SIDECAR_PID" 2>/dev/null || true
  wait "$SIDECAR_PID" 2>/dev/null || true
  # The node still serves its signed offer (it remembers the sidecar's for a while).
  run_case sidecar-down "released:not_started:anyrc" "$B" none -- --http 2
fi

cleanup
still=""
for port in "$SPORT" "$NPORT"; do
  for _ in $(seq 1 25); do listening "$port" || break; sleep 0.2; done
  if listening "$port"; then still="$still $port"; fi
done

echo
column -t -s $'\t' "$SUMMARY" 2>/dev/null | cut -c1-250 || cat "$SUMMARY"
echo
if [ -n "$still" ]; then echo "FAILED: still listening on port(s)$still"; exit 1; fi
if [ "$ran" -eq 0 ]; then echo "no case selected"; exit 2; fi
if [ "$failures" -gt 0 ]; then echo "FAILED: $failures of $ran cases deviated (evidence in $OUT)"; exit 1; fi
echo "OK: all $ran cases as expected; sidecar and node stopped (evidence in $OUT)"
