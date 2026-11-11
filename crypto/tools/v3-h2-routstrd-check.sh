#!/usr/bin/env bash
# Gate for protocol v3, option A (`http: 2`, PROTOCOL-V3-DESIGN.md A) through
# routstrd: OpenAI-style requests by curl → a scratch routstrd → a scratch
# routstr node → cu-sidecar → the real provider. Starts everything on scratch
# state, runs the cases, checks them in the routstrd log, the node's log and
# the node's database, prints the timings, stops everything. Exit 0 only if
# every case ends as expected.
#
#   VENICE_API_KEY=... crypto/tools/v3-h2-routstrd-check.sh
#
# Needs: routstr-core on a branch with http: 2 sessions (`confidential-v3`,
# with its .venv), routstr-sdk and routstrd on `confidential-v3`, built
# (`npm run build` in routstr-sdk, then `bun run build` in routstrd, whose
# node_modules/@routstr/sdk links the SDK checkout), and cu-sidecar, cu-prover
# and cu-2pc built in crypto/zkbench/target/release.
#
# Nothing is announced or published: the node's and routstrd's relay lists
# point nowhere, and routstrd runs with a scratch HOME, ROUTSTRD_DIR and
# COCOD_DIR (your own routstrd, its wallet and a legacy ~/.cocod are never
# touched) and a dead proxy for every non-loopback HTTP request. Its wallet is
# a throwaway one whose default mint is a local stub (helpers in
# v3-h2-routstrd/); the node credential is credited in the node's scratch
# database and seeded into routstrd's store, so no mint is involved. The
# provider key is passed by environment only. 13 small requests (max_tokens 20)
# and one image.
#
# Environment:
#   CU_SCRATCH       scratch and evidence directory (default: a fresh mktemp -d,
#                    removed on success; a given one is kept, minus the secrets)
#   CU_KEEP=1        keep the evidence of a successful run as well
#   CU_H2_PORT       sidecar port (default 7480)
#   CU_NODE_PORT     node port (default 8421)
#   CU_RD_PORT       routstrd port (default 8121)
#   CU_MINT_PORT     stub mint port (default 3348)
#   CU_CORE, CU_SDK, CU_ROUTSTRD   the checkouts (default: next to crypto/)
#   CU_H2_OFFER      sidecar offer file (default relay/offer.venice.h2.json)
#   CU_KEY_ENV       variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM      provider host:port (default api.venice.ai:443)
#   CU_UPSTREAM_BASE the provider's API base for the node (default https://api.venice.ai/api/v1)
#   CU_MODEL         chat model (default mistral-small-3-2-24b-instruct)
#   CU_IMAGE_MODEL   image model of the h2-image case (default z-image-turbo; empty: skip)
#   CU_PAUSE         seconds between sequential requests (default 3: the v2
#                    run's pre-warm pool arms the next session meanwhile)
#
# Cases:
#   h2-sequential  http2 on: 5 sequential streaming chat completions with
#                  `x-routstr-verify: confidential`: all 200 with content, one
#                  connection (new, then reused 2..5) in the routstrd log, 5
#                  "request reserved"/"settled" pairs with n in the node log, no
#                  plain chat/completions request at the node
#   h2-burst       http2 on: 3 parallel requests: all 200, 3 reserved + 3 settled
#   h2-image       http2 on: one image request (POST /v1/images/generations, the
#                  cheapest model, one image: about $0.01 at the provider) on a
#                  connection the chat requests left: 200 with a WebP image, a
#                  reused connection, one image reservation settled flat at the
#                  node (CU_IMAGE_MODEL= skips the case)
#   v2-sequential  http2 disabled in the routstrd config (routstrd restarted):
#                  5 sequential requests settle through the v2 flow
#   money          the credential's balance in the node's database is the start
#                  minus the charges the node logged; nothing stays reserved.
#                  The node takes a connection deposit (CU_H2_DEPOSIT, default
#                  7000 msat): every connection routstrd opened got it back with
#                  its first request, none was charged
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
HELP="$HERE/v3-h2-routstrd"
CORE="${CU_CORE:-$CRYPTO/../routstr-core}"
SDK="${CU_SDK:-$CRYPTO/../routstr-sdk}"
RD="${CU_ROUTSTRD:-$CRYPTO/../routstrd}"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
IMAGE_MODEL="${CU_IMAGE_MODEL-z-image-turbo}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
SPORT="${CU_H2_PORT:-7480}"
NPORT="${CU_NODE_PORT:-8421}"
RPORT="${CU_RD_PORT:-8121}"
MPORT="${CU_MINT_PORT:-3348}"
PAUSE="${CU_PAUSE:-3}"
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
grep -q '_run_h2_session' "$CORE/routstr/confidential_ws.py" || die "$CORE has no http: 2 sessions (branch confidential-v3)"
[ -d "$SDK/node_modules/@noble/curves" ] || die "$SDK has no node_modules (npm install)"
grep -q 'confidential http2' "$RD/dist/index.js" 2> /dev/null \
  || die "$RD/dist has no http: 2 support: branch confidential-v3, then (cd routstr-sdk && npm run build) and (cd routstrd && bun run build)"

listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2> /dev/null | grep -q LISTEN; }
for port in "$SPORT" "$NPORT" "$RPORT" "$MPORT"; do
  if listening "$port"; then die "port $port is in use"; fi
done

if [ -n "${CU_SCRATCH:-}" ]; then
  OUT="$CU_SCRATCH"; OWN_OUT=0
  mkdir -p "$OUT"
  [ -z "$(ls -A "$OUT")" ] || die "CU_SCRATCH ($OUT) is not empty"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/v3-h2-routstrd.XXXXXX")"; OWN_OUT=1
fi
OUT="$(cd "$OUT" && pwd)"
chmod 700 "$OUT"
mkdir -p "$OUT/node" "$OUT/sidecar-runs" "$OUT/home/.cocod" "$OUT/rd" "$OUT/ev"
ln -s "$CORE/migrations" "$OUT/node/migrations"
DB="$OUT/node.db"
EV="$OUT/ev"

SIDECAR_PID=""; NODE_PID=""; MINT_PID=""; RD_PID=""
stop() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill "$pid" 2> /dev/null || true
  wait "$pid" 2> /dev/null || true
}
STATUS=1
cleanup() {
  stop "$RD_PID"; RD_PID=""
  stop "$NODE_PID"; NODE_PID=""
  stop "$SIDECAR_PID"; SIDECAR_PID=""
  stop "$MINT_PID"; MINT_PID=""
  # The node's database holds the provider key; its secret key file, the test
  # credential and the throwaway wallet go with it.
  rm -f "$DB" "$DB-shm" "$DB-wal" "$OUT/routstr_secret.key" "$OUT/node/routstr_secret.key"
  rm -rf "$OUT/rd/wallet" "$OUT/rd/routstr.db" "$OUT/rd/routstr.db-shm" "$OUT/rd/routstr.db-wal" "$OUT/rd/config.json"
  local still=""
  for port in "$SPORT" "$NPORT" "$RPORT" "$MPORT"; do
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
  export CU_GATE_KEY="$key"
  unset key
  exec "$CRYPTO/zkbench/target/release/cu-sidecar" --listen "127.0.0.1:$SPORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" \
    --key-env CU_GATE_KEY --offer "${CU_H2_OFFER:-$CRYPTO/relay/offer.venice.h2.json}" --node-settles --runs-dir "$OUT/sidecar-runs"
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
      CONFIDENTIAL_H2_CONNECTION_DEPOSIT_MSAT="${CU_H2_DEPOSIT:-7000}"
    unset key
    exec "$CORE/.venv/bin/uvicorn" --app-dir "$CORE" routstr.core.main:app --host 127.0.0.1 --port "$NPORT" \
      --ws-ping-timeout 300
  ) >> "$OUT/node.out" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 300); do
    curl -fsS -o /dev/null "$NODE/v1/confidential/offer" 2> /dev/null && return 0
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
  curl -fsS "$NODE/v1/confidential/offer" > "$EV/offer.json" 2> /dev/null && grep -q "\"$MODEL\"" "$EV/offer.json" && break
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

# one <run> <i>: one streaming chat completion by curl; its timings and
# response headers as one JSON line.
one() {
  local run="$1" i="$2" t0
  t0="$(bun -e 'console.log(Date.now())')"
  curl -sS -N -m 180 -D "$EV/$run-$i.headers" "http://127.0.0.1:$RPORT/v1/chat/completions" \
    -H 'content-type: application/json' -H 'x-routstr-verify: confidential' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the number $i and nothing else.\"}],\"max_tokens\":20,\"stream\":true}" \
    2>> "$EV/curl.err" | bun "$HELP/stamp.ts" "$t0" "$run-$i" "$EV/$run-$i.headers"
}
# run_case <run> seq|burst <count>: the requests, then this run's slices of the logs.
run_case() {
  local run="$1" how="$2" count="$3" nskip rskip
  echo "== $run: $count $how request(s) =="
  nskip="$(node_lines)"; rskip="$(rd_lines)"
  if [ "$how" = seq ]; then
    for i in $(seq 1 "$count"); do
      if [ "$i" -gt 1 ]; then sleep "$PAUSE"; fi
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
  # Settlement of the last request ends a moment after its stream.
  sleep 2
  node_log | tail -n +"$((nskip + 1))" > "$EV/node-$run.log"
  rd_log | tail -n +"$((rskip + 1))" > "$EV/rd-$run.log"
}

start_rd
run_case h2seq seq 5
run_case h2burst burst 3
if [ -n "$IMAGE_MODEL" ]; then
  # One image request on a connection the chat requests left open.
  echo "== h2image: 1 image request =="
  nskip="$(node_lines)"; rskip="$(rd_lines)"
  t0="$(bun -e 'console.log(Date.now())')"
  curl -sS -m 300 -D "$EV/h2image-1.headers" -o "$EV/h2image-1.body" "http://127.0.0.1:$RPORT/v1/images/generations" \
    -H 'content-type: application/json' -H 'x-routstr-verify: confidential' \
    -d "{\"model\":\"$IMAGE_MODEL\",\"prompt\":\"a red circle on a white background\",\"n\":1,\"output_format\":\"webp\"}" 2>> "$EV/curl.err" || true
  bun "$HELP/image.ts" "$t0" h2image-1 "$EV/h2image-1.headers" "$EV/h2image-1.body" | tee "$EV/results-h2image.jsonl"
  # The image itself is not evidence: keep its summary only.
  : > "$EV/h2image-1.body"
  sleep 2
  node_log | tail -n +"$((nskip + 1))" > "$EV/node-h2image.log"
  rd_log | tail -n +"$((rskip + 1))" > "$EV/rd-h2image.log"
fi

# The same daemon with http2 disabled: the v2 flow and its pre-warming.
stop "$RD_PID"; RD_PID=""
bun "$HELP/seed.ts" http2 "$OUT/rd" off || fail "could not rewrite routstrd's config"
start_rd
run_case v2seq seq 5
# Stopping routstrd closes its armed sessions; the node then releases their reservations.
stop "$RD_PID"; RD_PID=""
for _ in $(seq 1 100); do
  [ "$(sqlite3 "$DB" "select reserved_balance from api_keys where hashed_key='$KEY'")" = 0 ] && break
  sleep 0.2
done
node_log > "$EV/node-all.log"
sqlite3 "$DB" "select '{\"start\":$START_BALANCE,\"balance\":' || balance || ',\"reserved\":' || reserved_balance || '}' from api_keys where hashed_key='$KEY'" > "$EV/money.json"

# No file of ours may hold the provider key or the test credential (both are
# handed to the scan by environment).
CU_SCAN_A="${!KEY_ENV}" CU_SCAN_B="$KEY" bun "$HELP/scan.ts" "$EV" "$OUT/sidecar.log" "$OUT/node.out" "$OUT/rd.out" \
  "$OUT/mint.log" "$OUT/rd/logs" "$OUT/node/logs" "$OUT/sidecar-runs" || fail "a secret appears in the files above"

if bun "$HELP/eval.ts" "$EV"; then
  echo
  echo "OK: all cases as expected"
  STATUS=0
else
  echo
  echo "FAILED: see the deviations above"
  STATUS=1
fi
