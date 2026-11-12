#!/usr/bin/env bash
# Gate for protocol v3 (PROTOCOL-V3.md §13) through routstrd: OpenAI-style
# requests by curl → a scratch routstrd → a scratch routstr node → cu-sidecar
# → the real provider. Starts everything on scratch state, runs the cases,
# checks them in the responses, the routstrd log, the node's log and the
# node's database, prints the timings, stops everything. Exit 0 only if every
# case ends as expected.
#
#   VENICE_API_KEY=... crypto/tools/v3-routstrd-check.sh
#
# Needs: routstr-core on protocol v3 (with its .venv), routstr-sdk and
# routstrd on `confidential-v3`, built (`npm run build` in routstr-sdk, then
# `bun run build` in routstrd, whose node_modules/@routstr/sdk links the SDK
# checkout), and cu-sidecar, cu-prover and cu-2pc built in
# crypto/zkbench/target/release.
#
# Nothing is announced or published: the node's and routstrd's relay lists
# point nowhere, and routstrd runs with a scratch HOME, ROUTSTRD_DIR and
# COCOD_DIR (your own routstrd, its wallet and a legacy ~/.cocod are never
# touched) and a dead proxy for every non-loopback HTTP request. Its wallet is
# a throwaway one whose default mint is a local stub (helpers in
# v3-routstrd/); the node credential is credited in the node's scratch
# database and seeded into routstrd's store, so no mint is involved. The
# provider key is passed by environment only. About 25 small requests
# (max_tokens 20) and one image.
#
# Environment:
#   CU_SCRATCH       scratch and evidence directory (default: a fresh mktemp -d,
#                    removed on success; a given one is kept, minus the secrets)
#   CU_KEEP=1        keep the evidence of a successful run as well
#   CU_V3_PORT       sidecar port (default 7471)
#   CU_NODE_PORT     node port (default 8441)
#   CU_RD_PORT       routstrd port (default 8141)
#   CU_MINT_PORT     stub mint port (default 3358)
#   CU_FAKE_PORT     port of the fake v2 node (default 8442)
#   CU_CORE, CU_SDK, CU_ROUTSTRD   the checkouts (default: next to crypto/)
#   CU_V3_OFFER      sidecar offer file (default relay/offer.venice.json)
#   CU_KEY_ENV       variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM      provider host:port (default api.venice.ai:443)
#   CU_UPSTREAM_BASE the provider's API base for the node (default https://api.venice.ai/api/v1)
#   CU_MODEL         chat model (default mistral-small-3-2-24b-instruct)
#   CU_IMAGE_MODEL   image model of the image case (default z-image-turbo; empty: skip)
#   CU_PAUSE         seconds between the requests of a pre-warmed run (default 4:
#                    the next armed connection is prepared meanwhile)
#
# The node charges a session fee, an abandon fee and a connection deposit that
# are non-zero and different (3000, 5000, 7000 msat).
#
# Cases (routstrd's `confidentialUpstream` settings in brackets; two local
# clients A and B are two API keys in the Authorization header):
#   sequential   [http auto] 5 sequential streaming chat completions of client A
#                with `x-routstr-verify: confidential`: all 200 with content, one
#                framing-"2" connection (new, then reused 2..5), 5 reserved +
#                settled pairs with n 1..5 at the node, the session fee once
#   burst        3 parallel requests of client A: all 200, on 3 connections
#   image        one image request (POST /v1/images/generations, one image: about
#                $0.01 at the provider) on an open connection: 200 with a WebP
#                image, settled flat at the node (CU_IMAGE_MODEL= skips the case)
#   clients      client B's request opens its own connection; A and B then each
#                reuse their own (`http2.reuse: per-client`, the default)
#   refused      the node refuses a request (402: the credential's balance is
#                lowered in the node's database to below the reservation), the
#                caller gets the error; with the balance restored the next
#                request runs on the same connection with the number the refused
#                one did not use up
#   fallback     the sidecar's HTTP/2 open is made to fail (its test hook): the
#                request is served on framing "1.1" on the same node and "2" is
#                marked bad in routstrd's log
#   forced-1.1   [http "1.1"] 2 sequential requests, a connection each
#   armed-1.1    [http "1.1", prewarm on] 3 requests: the 2nd and 3rd are served by
#                armed connections
#   armed-2      [http "2", http2.reuse none, prewarm on] 3 requests: the 2nd and 3rd
#                are served by armed connections
#   upgrade      routstrd's one provider is a fake v2 node: the request fails with
#                `node_protocol_outdated` in the error body, the offer was asked
#                for with `?v=3`, and routstrd logs the node once for two requests
#   money        the credential's balance in the node's database is the start
#                minus the charges the node logged and the deposits of the armed
#                connections that were never used; nothing stays reserved
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
HELP="$HERE/v3-routstrd"
CORE="${CU_CORE:-$CRYPTO/../routstr-core}"
SDK="${CU_SDK:-$CRYPTO/../routstr-sdk}"
RD="${CU_ROUTSTRD:-$CRYPTO/../routstrd}"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
IMAGE_MODEL="${CU_IMAGE_MODEL-z-image-turbo}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
SPORT="${CU_V3_PORT:-7471}"
NPORT="${CU_NODE_PORT:-8441}"
RPORT="${CU_RD_PORT:-8141}"
MPORT="${CU_MINT_PORT:-3358}"
FPORT="${CU_FAKE_PORT:-8442}"
PAUSE="${CU_PAUSE:-4}"
FEE=3000
ABANDON=5000
DEPOSIT=7000
START_BALANCE=200000000
NODE="http://127.0.0.1:$NPORT"
SIDECAR="http://127.0.0.1:$SPORT"
MINT="http://127.0.0.1:$MPORT"
PROVER="$CRYPTO/zkbench/target/release/cu-prover"

die() { echo "$*" >&2; exit 2; }
for tool in bun curl sqlite3 openssl lsof; do command -v "$tool" > /dev/null || die "need $tool"; done
[ -n "${!KEY_ENV:-}" ] || die "$KEY_ENV is not set"
for bin in cu-sidecar cu-prover cu-2pc; do
  [ -x "$CRYPTO/zkbench/target/release/$bin" ] || die "build first: (cd crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc)"
done
CORE="$(cd "$CORE" 2> /dev/null && pwd)" || die "no routstr-core checkout (CU_CORE)"
SDK="$(cd "$SDK" 2> /dev/null && pwd)" || die "no routstr-sdk checkout (CU_SDK)"
RD="$(cd "$RD" 2> /dev/null && pwd)" || die "no routstrd checkout (CU_ROUTSTRD)"
[ -x "$CORE/.venv/bin/uvicorn" ] || die "no $CORE/.venv/bin/uvicorn"
grep -q 'CONFIDENTIAL_VERSION = 3' "$CORE/routstr/confidential.py" || die "$CORE does not speak protocol v3"
[ -d "$SDK/node_modules/@noble/curves" ] || die "$SDK has no node_modules (npm install)"
grep -q 'node_protocol_outdated' "$RD/dist/index.js" 2> /dev/null \
  || die "$RD/dist does not speak protocol v3: branch confidential-v3, then (cd routstr-sdk && npm run build) and (cd routstrd && bun run build)"

listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2> /dev/null | grep -q LISTEN; }
for port in "$SPORT" "$NPORT" "$RPORT" "$MPORT" "$FPORT"; do
  if listening "$port"; then die "port $port is in use"; fi
done

if [ -n "${CU_SCRATCH:-}" ]; then
  OUT="$CU_SCRATCH"; OWN_OUT=0
  mkdir -p "$OUT"
  [ -z "$(ls -A "$OUT")" ] || die "CU_SCRATCH ($OUT) is not empty"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/v3-routstrd.XXXXXX")"; OWN_OUT=1
fi
OUT="$(cd "$OUT" && pwd)"
chmod 700 "$OUT"
mkdir -p "$OUT/node" "$OUT/sidecar-runs" "$OUT/home/.cocod" "$OUT/rd" "$OUT/ev"
ln -s "$CORE/migrations" "$OUT/node/migrations"
DB="$OUT/node.db"
EV="$OUT/ev"

SIDECAR_PID=""; NODE_PID=""; MINT_PID=""; RD_PID=""; FAKE_PID=""
FAIL_FILE="$OUT/h2-fail"
stop() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill "$pid" 2> /dev/null || true
  wait "$pid" 2> /dev/null || true
}
STATUS=1
cleanup() {
  rm -f "$FAIL_FILE"
  stop "$RD_PID"; RD_PID=""
  stop "$FAKE_PID"; FAKE_PID=""
  stop "$NODE_PID"; NODE_PID=""
  stop "$SIDECAR_PID"; SIDECAR_PID=""
  stop "$MINT_PID"; MINT_PID=""
  # The node's database holds the provider key; its secret key file, the test
  # credential and the throwaway wallet go with it.
  rm -f "$DB" "$DB-shm" "$DB-wal" "$OUT/routstr_secret.key" "$OUT/node/routstr_secret.key"
  rm -rf "$OUT/rd/wallet" "$OUT/rd/routstr.db" "$OUT/rd/routstr.db-shm" "$OUT/rd/routstr.db-wal" "$OUT/rd/config.json"
  local still=""
  for port in "$SPORT" "$NPORT" "$RPORT" "$MPORT" "$FPORT"; do
    for _ in $(seq 1 25); do listening "$port" || break; sleep 0.2; done
    if listening "$port"; then still="$still $port"; fi
  done
  if [ -n "$still" ]; then echo "FAILED: still listening on port(s)$still" >&2; STATUS=1; fi
  if [ "$STATUS" = 0 ] && [ "$OWN_OUT" = 1 ] && [ "${CU_KEEP:-0}" != 1 ]; then
    rm -rf "$OUT"
  else
    echo "evidence (no secrets) in $OUT"
  fi
  exit "$STATUS"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
fail() { echo "FAILED: $*" >&2; exit 1; }

# --- sidecar, stub mint, node ----------------------------------------------------
# A clean environment for each; the provider key stays in the environment
# (never an argument, never a file of ours).
(
  key="${!KEY_ENV}"
  for v in $(compgen -e); do
    case "$v" in PATH|HOME|TMPDIR) ;; *) unset "$v" 2> /dev/null || true ;; esac
  done
  export CU_GATE_KEY="$key" CU_TEST_H2_FAIL_FILE="$FAIL_FILE" CU_TEST_H2_RETRY_SECS=8
  unset key
  exec "$CRYPTO/zkbench/target/release/cu-sidecar" --listen "127.0.0.1:$SPORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" \
    --key-env CU_GATE_KEY --offer "${CU_V3_OFFER:-$CRYPTO/relay/offer.venice.json}" --node-settles --runs-dir "$OUT/sidecar-runs"
) > "$OUT/sidecar.log" 2>&1 &
SIDECAR_PID=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "$SIDECAR/offer" 2> /dev/null && break
  kill -0 "$SIDECAR_PID" 2> /dev/null || fail "the sidecar did not start; see $OUT/sidecar.log"
  sleep 0.2
done
curl -fsS "$SIDECAR/offer" > "$EV/sidecar-offer.json" 2> /dev/null
grep -Eq '"http": *\[[^]]*"2"' "$EV/sidecar-offer.json" || fail "the sidecar does not offer http 2"

(cd "$HELP" && exec env -i PATH="$PATH" HOME="$OUT/home" CU_SDK="$SDK" bun stub-mint.ts "$MPORT") > "$OUT/mint.log" 2>&1 &
MINT_PID=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "$MINT/v1/keysets" 2> /dev/null && break
  kill -0 "$MINT_PID" 2> /dev/null || fail "the stub mint did not start; see $OUT/mint.log"
  sleep 0.2
done

NSEC="$(openssl rand -hex 32)"
start_node() {
  (
    cd "$OUT/node"
    key="${!KEY_ENV}"
    for v in $(compgen -e); do
      case "$v" in PATH|HOME|TMPDIR) ;; *) unset "$v" 2> /dev/null || true ;; esac
    done
    export DATABASE_URL="sqlite+aiosqlite:///$DB" NSEC="$NSEC" \
      CONFIDENTIAL_SIDECAR_URL="$SIDECAR" CASHU_MINTS="$MINT" \
      UPSTREAM_BASE_URL="${CU_UPSTREAM_BASE:-https://api.venice.ai/api/v1}" UPSTREAM_API_KEY="$key" \
      HTTP_URL="$NODE" RELAYS='["ws://127.0.0.1:9"]' ENABLE_ANALYTICS_SHARING=false \
      CONFIDENTIAL_SESSION_FEE_MSAT="$FEE" CONFIDENTIAL_ABANDON_FEE_MSAT="$ABANDON" \
      CONFIDENTIAL_CONNECTION_DEPOSIT_MSAT="$DEPOSIT" CONFIDENTIAL_IDLE_TIMEOUT_S=120
    unset key
    exec "$CORE/.venv/bin/uvicorn" --app-dir "$CORE" routstr.core.main:app --host 127.0.0.1 --port "$NPORT" \
      --ws-ping-timeout 300
  ) >> "$OUT/node.out" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 300); do
    curl -fsS -o /dev/null "$NODE/v1/confidential/offer?v=3" 2> /dev/null && return 0
    kill -0 "$NODE_PID" 2> /dev/null || break
    sleep 0.2
  done
  fail "the node did not start; see $OUT/node.out"
}
# The first start seeds a `custom` provider from UPSTREAM_BASE_URL, whose offer
# has no models; as `venice` (AGENTS.md) the second start prices them.
start_node
stop "$NODE_PID"; NODE_PID=""
sqlite3 "$DB" "delete from upstream_providers where base_url not like '%venice%'; update upstream_providers set provider_type='venice';"
# The test credential: `sk-<hex>`, stored under the hex itself.
KEY="$(openssl rand -hex 32)"
sqlite3 "$DB" "insert into api_keys(hashed_key,balance,total_spent,total_requests,reserved_balance) values('$KEY',$START_BALANCE,0,0,0);"
start_node
for _ in $(seq 1 150); do
  curl -fsS "$NODE/v1/confidential/offer?v=3" > "$EV/offer.json" 2> /dev/null && grep -q "\"$MODEL\"" "$EV/offer.json" && break
  sleep 0.4
done
grep -q "\"$MODEL\"" "$EV/offer.json" || fail "the node's offer does not price $MODEL; see $EV/offer.json and $OUT/node.out"
grep -Eq '"http": *\[[^]]*"2"' "$EV/offer.json" || fail "the node's offer does not list http 2"
PUBKEY="$(bun -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).notary_pubkey)' "$EV/offer.json")"

# --- routstrd ----------------------------------------------------------------------
# Scratch HOME and state directories; every non-loopback HTTP request goes to
# a dead proxy, so the daemon reaches only the local node and the stub mint.
CU_TEST_KEY="sk-$KEY" bun "$HELP/seed.ts" init "$OUT/rd" "$RD" "$NODE" "$MINT" "$RPORT" "$PROVER" "$PUBKEY" \
  || fail "could not write routstrd's scratch state"
rd_log() { cat "$OUT"/rd/logs/*.log 2> /dev/null; }
rd_lines() { rd_log | wc -l | tr -d ' '; }
node_log() { cat "$OUT"/node/logs/*.log 2> /dev/null; }
node_lines() { node_log | wc -l | tr -d ' '; }
start_rd() {
  # Ready once it listens and its first refresh has fetched the node's models.
  local skip
  skip="$(rd_lines)"
  (cd "$RD" && exec env -i PATH="$PATH" HOME="$OUT/home" ROUTSTRD_DIR="$OUT/rd" COCOD_DIR="$OUT/home/.cocod" \
    HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost \
    https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 no_proxy=127.0.0.1,localhost \
    bun dist/index.js daemon --port "$RPORT") >> "$OUT/rd.out" 2>&1 &
  RD_PID=$!
  for _ in $(seq 1 300); do
    if listening "$RPORT" && [ "$(rd_log | tail -n +"$((skip + 1))" | grep -c 'Initial refresh: ')" -gt 0 ]; then return 0; fi
    kill -0 "$RD_PID" 2> /dev/null || break
    sleep 0.2
  done
  fail "routstrd did not start; see $OUT/rd.out and $OUT/rd/logs"
}

CLIENT_A="sk-local-client-a-$(openssl rand -hex 8)"
CLIENT_B="sk-local-client-b-$(openssl rand -hex 8)"
# one <run> <i> [client key]: one streaming chat completion by curl; its
# timings and response headers as one JSON line.
one() {
  local run="$1" i="$2" client="${3:-$CLIENT_A}" t0
  t0="$(bun -e 'console.log(Date.now())')"
  curl -sS -N -m 180 -D "$EV/$run-$i.headers" "http://127.0.0.1:$RPORT/v1/chat/completions" \
    -H 'content-type: application/json' -H 'x-routstr-verify: confidential' -H "authorization: Bearer $client" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the number $i and nothing else.\"}],\"max_tokens\":20,\"stream\":true}" \
    2>> "$EV/curl.err" | bun "$HELP/stamp.ts" "$t0" "$run-$i" "$EV/$run-$i.headers"
}
# Slices of the two logs since `begin_case`.
NSKIP=0; RSKIP=0
begin_case() { echo "== $1 =="; NSKIP="$(node_lines)"; RSKIP="$(rd_lines)"; }
end_case() {
  # Settlement of the last request ends a moment after its stream.
  sleep 2
  node_log | tail -n +"$((NSKIP + 1))" > "$EV/node-$1.log"
  rd_log | tail -n +"$((RSKIP + 1))" > "$EV/rd-$1.log"
}
# run_case <run> seq|burst <count> [pause]: the requests, then this run's slices of the logs.
run_case() {
  local run="$1" how="$2" count="$3" pause="${4:-0}"
  begin_case "$run: $count $how request(s)"
  if [ "$how" = seq ]; then
    for i in $(seq 1 "$count"); do
      if [ "$i" -gt 1 ] && [ "$pause" != 0 ]; then sleep "$pause"; fi
      one "$run" "$i" | tee -a "$EV/results-$run.jsonl"
    done
  else
    local pids=""
    for i in $(seq 1 "$count"); do
      one "$run" "$i" >> "$EV/results-$run.jsonl" &
      pids="$pids $!"
    done
    # shellcheck disable=SC2086
    wait $pids
    cat "$EV/results-$run.jsonl"
  fi
  end_case "$run"
}
# restart_rd <json>: routstrd again with <json> merged into confidentialUpstream.
# Stopping it closes its connections; an armed one that was never used loses its deposit.
restart_rd() {
  stop "$RD_PID"; RD_PID=""
  bun "$HELP/seed.ts" set "$OUT/rd" "$1" || fail "could not rewrite routstrd's config"
  start_rd
}
balance_sql() { sqlite3 "$DB" "$1"; }

# --- http auto, no pre-warm, per-client reuse ---------------------------------------
start_rd
run_case seq seq 5
run_case burst burst 3
if [ -n "$IMAGE_MODEL" ]; then
  # One image request on a connection the chat requests left open.
  begin_case "image: 1 image request"
  t0="$(bun -e 'console.log(Date.now())')"
  curl -sS -m 300 -D "$EV/image-1.headers" -o "$EV/image-1.body" "http://127.0.0.1:$RPORT/v1/images/generations" \
    -H 'content-type: application/json' -H 'x-routstr-verify: confidential' -H "authorization: Bearer $CLIENT_A" \
    -d "{\"model\":\"$IMAGE_MODEL\",\"prompt\":\"a red circle on a white background\",\"n\":1,\"output_format\":\"webp\"}" 2>> "$EV/curl.err" || true
  bun "$HELP/image.ts" "$t0" image-1 "$EV/image-1.headers" "$EV/image-1.body" | tee "$EV/results-image.jsonl"
  # The image itself is not evidence: keep its summary only.
  : > "$EV/image-1.body"
  end_case image
fi

# Two local clients: B opens its own connection, then each reuses its own.
begin_case "clients: A and B"
one clients 1 "$CLIENT_B" | tee -a "$EV/results-clients.jsonl"
one clients 2 "$CLIENT_A" | tee -a "$EV/results-clients.jsonl"
one clients 3 "$CLIENT_B" | tee -a "$EV/results-clients.jsonl"
end_case clients

# A refused request: the node's balance for the credential falls below the
# reservation (it still covers nothing new: the connection is open, its
# deposit long released), the request is refused with 402, the balance is
# restored, and the next request runs on the same connection.
begin_case "refused: a 402 and then a good request"
SAVED="$(balance_sql "select balance from api_keys where hashed_key='$KEY'")"
balance_sql "update api_keys set balance=9000 where hashed_key='$KEY'"
one refused 1 "$CLIENT_B" | tee -a "$EV/results-refused.jsonl"
SPENT_MEANWHILE="$((9000 - $(balance_sql "select balance from api_keys where hashed_key='$KEY'")))"
balance_sql "update api_keys set balance=$SAVED - $SPENT_MEANWHILE where hashed_key='$KEY'"
echo "{\"spent_while_low\":$SPENT_MEANWHILE}" > "$EV/refused-money.json"
one refused 2 "$CLIENT_B" | tee -a "$EV/results-refused.jsonl"
end_case refused

# Fallback: the sidecar fails every HTTP/2 open while the file exists. A new
# local client (no open connection of its own) is served on "1.1".
begin_case "fallback: framing 2 fails to open"
: > "$FAIL_FILE"
CLIENT_C="sk-local-client-c-$(openssl rand -hex 8)"
one fallback 1 "$CLIENT_C" | tee -a "$EV/results-fallback.jsonl"
one fallback 2 "$CLIENT_C" | tee -a "$EV/results-fallback.jsonl"
rm -f "$FAIL_FILE"
end_case fallback
# The sidecar offers "2" again once its retry time passed.
sleep 9

# --- the framings forced, cold and armed ----------------------------------------------
restart_rd '{"http":"1.1","prewarm":{"enabled":false}}'
run_case forced11 seq 2
restart_rd "{\"http\":\"1.1\",\"prewarm\":{\"enabled\":true,\"maxDepositMsat\":$DEPOSIT}}"
run_case armed11 seq 3 "$PAUSE"
restart_rd "{\"http\":\"2\",\"http2\":{\"reuse\":\"none\"},\"prewarm\":{\"enabled\":true,\"maxDepositMsat\":$DEPOSIT}}"
run_case armed2 seq 3 "$PAUSE"

# --- a node that still runs protocol v2 --------------------------------------------------
stop "$RD_PID"; RD_PID=""
(cd "$HELP" && exec env -i PATH="$PATH" HOME="$OUT/home" bun fake-v2-node.ts "$FPORT" "$NODE") > "$OUT/fake-v2.log" 2>&1 &
FAKE_PID=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:$FPORT/v1/models" 2> /dev/null && break
  kill -0 "$FAKE_PID" 2> /dev/null || fail "the fake v2 node did not start; see $OUT/fake-v2.log"
  sleep 0.2
done
bun "$HELP/seed.ts" provider "$OUT/rd" "http://127.0.0.1:$FPORT" || fail "could not point routstrd at the fake v2 node"
bun "$HELP/seed.ts" set "$OUT/rd" '{"http":"auto","http2":{"reuse":"per-client"},"prewarm":{"enabled":false}}' || fail "could not rewrite routstrd's config"
start_rd
run_case upgrade seq 2
cp "$OUT/fake-v2.log" "$EV/fake-v2.log"

# Stopping routstrd closes its connections; the node then settles what they held.
stop "$RD_PID"; RD_PID=""
stop "$FAKE_PID"; FAKE_PID=""
for _ in $(seq 1 100); do
  [ "$(sqlite3 "$DB" "select reserved_balance from api_keys where hashed_key='$KEY'")" = 0 ] && break
  sleep 0.2
done
sleep 1
node_log > "$EV/node-all.log"
rd_log > "$EV/rd-all.log"
sqlite3 "$DB" "select '{\"start\":$START_BALANCE,\"balance\":' || balance || ',\"reserved\":' || reserved_balance || '}' from api_keys where hashed_key='$KEY'" > "$EV/money.json"
echo "{\"fee\":$FEE,\"abandon\":$ABANDON,\"deposit\":$DEPOSIT,\"image\":$([ -n "$IMAGE_MODEL" ] && echo true || echo false)}" > "$EV/terms.json"

# No file of ours may hold the provider key or the test credential (both are
# handed to the scan by environment).
CU_SCAN_A="${!KEY_ENV}" CU_SCAN_B="$KEY" bun "$HELP/scan.ts" "$EV" "$OUT/sidecar.log" "$OUT/node.out" "$OUT/rd.out" \
  "$OUT/mint.log" "$OUT/fake-v2.log" "$OUT/rd/logs" "$OUT/node/logs" "$OUT/sidecar-runs" || fail "a secret appears in the files above"

if bun "$HELP/eval.ts" "$EV"; then
  echo
  echo "OK: all cases as expected"
  STATUS=0
else
  echo
  echo "FAILED: see the deviations above"
  STATUS=1
fi
