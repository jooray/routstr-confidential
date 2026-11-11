#!/usr/bin/env bash
# Gate for protocol v3, option A (`http: 2`, PROTOCOL-V3-DESIGN.md A): honest
# sessions and attacks by a malicious client, against a cu-sidecar and the
# real provider. Exit 0 only if every case ends exactly as expected.
#
#   VENICE_API_KEY=... crypto/tools/v3-h2-check.sh
#
# The script starts its own cu-sidecar on loopback (with relay/offer.venice.h2.json,
# no node: the sidecar signs stub receipts) and stops it when done. No routstr
# node is involved. Every request is small (max_tokens 20); the flow-control
# case sends one ~200 kB prompt. The image case generates one image of the
# cheapest model (real money: about $0.01); the image attack costs nothing.
#
# Environment:
#   CU_SIDECAR      use this running sidecar instead of starting one (it must
#                   offer http 2 and run without --node-settles); then also set
#                   CU_SIDECAR_RUNS to its --runs-dir
#   CU_H2_PORT      loopback port for the started sidecar (default 7462)
#   CU_H2_OFFER     offer file (default relay/offer.venice.h2.json)
#   CU_KEY_ENV      variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM     provider host:port (default api.venice.ai:443)
#   CU_MODEL        chat model (default mistral-small-3-2-24b-instruct)
#   CU_IMAGE_MODEL  image model (default z-image-turbo; one image, the default variant)
#   CU_CASES        optional space-separated subset of case ids
#   CU_H2_PAUSE     seconds of idle time in the `idle` case (default 0 = skip;
#                   150 for the long check)
#   CU_CASE_TIMEOUT per-case limit in seconds (default 180, plus the pause)
#   CU_H2_OUT       evidence directory (default crypto/runs/v3-h2-check)
#
# Cases (machine-checked by v3_h2_eval.py):
#   h2-one            one request on one connection: 200, verified receipt
#   h2-three          three sequential requests on one connection (streams 3, 5, 7)
#   h2-error          request 2 names an unknown model: its 404 head is disclosed
#                     and settled by π_WIN over the response head (A.7)
#   h2-big            a body larger than the provider's 65 536-byte stream window,
#                     released in steps (A.5 step 4)
#   idle              (CU_H2_PAUSE > 0) two requests with that pause between them
#   a-hidden-headers  a HEADERS frame for another stream inside a "DATA" record
#   b-padding         TLS record padding that shifts the frame boundary (A.4 rule 3)
#   c-suffix          the body ends in another model's suffix
#   e-path            a HEADERS block with another :path of the same length
#   e-path-long       the same with a longer path (refused on the record length)
#   d-replay-usage    request 1's usage tail presented as request 2's disclosure
#   h2-image          an image request on a connection (A.13): its body is proven
#                     like a chat body, the response (one JSON body over DATA
#                     frames) is accepted and settled flat
#   f-image-suffix    an image request whose body ends in a suffix ordering one
#                     image more than the request names
#   v2                an unchanged protocol v2 (HTTP/1.1) session on the same sidecar
# For a, b, c, e, f the sidecar must refuse (a failed π_WIN, or the record shape)
# and its own log must show that no record of the attacked request was written
# to the provider. For d the request itself is honest and reaches the provider;
# what must be refused is its settlement on the earlier request's usage.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
OUT="${CU_H2_OUT:-$CRYPTO/runs/v3-h2-check}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
IMAGE_MODEL="${CU_IMAGE_MODEL:-z-image-turbo}"
PAUSE="${CU_H2_PAUSE:-0}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-180}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
export CU_PROVER="${CU_PROVER:-$CRYPTO/zkbench/target/release/cu-prover}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"
PY="$(command -v python3)"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }

SIDECAR_PID=""
cleanup() {
  if [ -n "$SIDECAR_PID" ]; then kill "$SIDECAR_PID" 2>/dev/null || true; wait "$SIDECAR_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [ -n "${CU_SIDECAR:-}" ]; then
  SIDECAR="$CU_SIDECAR"
  RUNS="${CU_SIDECAR_RUNS:?set CU_SIDECAR_RUNS to the --runs-dir of that sidecar}"
else
  [ -n "${!KEY_ENV:-}" ] || { echo "$KEY_ENV is not set" >&2; exit 2; }
  BIN="$CRYPTO/zkbench/target/release/cu-sidecar"
  [ -x "$BIN" ] || { echo "build first: (cd crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc)" >&2; exit 2; }
  PORT="${CU_H2_PORT:-7462}"
  RUNS="$OUT/sidecar-runs"
  mkdir -p "$RUNS"
  "$BIN" --listen "127.0.0.1:$PORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" --key-env "$KEY_ENV" \
    --offer "${CU_H2_OFFER:-$CRYPTO/relay/offer.venice.h2.json}" --runs-dir "$RUNS" > "$OUT/sidecar.log" 2>&1 &
  SIDECAR_PID=$!
  SIDECAR="http://127.0.0.1:$PORT"
  for _ in $(seq 1 50); do
    curl -fsS "$SIDECAR/offer" > "$OUT/offer.json" 2>/dev/null && break
    kill -0 "$SIDECAR_PID" 2>/dev/null || { echo "the sidecar did not start; see $OUT/sidecar.log" >&2; exit 2; }
    sleep 0.2
  done
fi
curl -fsS "$SIDECAR/offer" > "$OUT/offer.json" || { echo "no offer from $SIDECAR" >&2; exit 2; }
grep -Eq '"http": *\[[^]]*"2"' "$OUT/offer.json" || { echo "the sidecar at $SIDECAR does not offer http 2" >&2; exit 2; }

# Offline first: the client's HTTP/2 layer against the sidecar's vectors.
(cd "$CRYPTO/client" && node --experimental-strip-types src/h2-selfcheck.ts) || { echo "h2-selfcheck failed" >&2; exit 1; }

SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tevidence\n' > "$SUMMARY"
failures=0
ran=0

# run_case <id> <expectation> [extra timeout seconds] -- driver args...
run_case() {
  local id="$1" expect="$2" extra="$3"; shift 4
  if [ -n "${CU_CASES:-}" ] && [[ " $CU_CASES " != *" $id "* ]]; then return 0; fi
  ran=$((ran + 1))
  echo "== $id (expect: $expect) =="
  local rc=0
  (cd "$CRYPTO/client" && "$TIMEOUT_BIN" -k 5 "$((CASE_TIMEOUT + extra))" "${DRIVER[@]}" --sidecar "$SIDECAR" --model "$MODEL" \
    --max-tokens 20 --runs-dir "$OUT/client-runs" "$@") > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  local res verdict evidence
  res="$("$PY" -I "$HERE/v3_h2_eval.py" "$id" "$expect" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$RUNS" 2>&1)" \
    || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"
  IFS=$'\t' read -r verdict evidence <<< "$res"
  printf '%s\t%s\t%s\t%s\n' "$id" "$expect" "$verdict" "$evidence" >> "$SUMMARY"
  echo "   $verdict"
  echo "   $evidence"
  case "$verdict" in PASS) ;; *) failures=$((failures + 1)) ;; esac
}

run_case h2-one   "settled:1" 0 -- --http2
run_case h2-three "settled:3" 0 -- --http2 --requests 3
run_case h2-error "error:2:404" 0 -- --http2 --requests 3 --h2-models "$MODEL,no-such-model-xyz"
run_case h2-big   "big:13" 0 -- --http2 --body-bytes 200000 --prompt "Reply with the single word OK."
if [ "$PAUSE" -gt 0 ]; then
  run_case idle "settled:2" "$PAUSE" -- --http2 --requests 2 --pause-ms "$((PAUSE * 1000))"
fi
run_case a-hidden-headers "refused:2:pi_win failed" 0 -- --http2 --requests 2 --adv-h2 hidden-headers --adv-at 2
run_case b-padding        "refused:2:pi_win failed" 0 -- --http2 --requests 2 --adv-h2 padding --adv-at 2
run_case c-suffix         "refused:2:pi_win failed" 0 -- --http2 --requests 2 --adv-h2 suffix --adv-at 2
run_case e-path           "refused:2:pi_win failed" 0 -- --http2 --requests 2 --adv-h2 path --adv-at 2
run_case e-path-long      "refused:1:not its HEADERS frame" 0 -- --http2 --adv-h2 path --adv-h2-path /api/v1/api_keys/rate_limits
run_case d-replay-usage   "replay:2:interval" 0 -- --http2 --requests 2 --adv-h2 replay-usage
run_case h2-image         "image:1" 120 -- --http2 --image --image-model "$IMAGE_MODEL" --prompt "a red circle on a white background"
run_case f-image-suffix   "refused:1:pi_win failed" 0 -- --http2 --image --image-model "$IMAGE_MODEL" --prompt "a red circle" --adv-h2 suffix --adv-at 1
run_case v2 "v2" 0 --

echo
column -t -s $'\t' "$SUMMARY" 2>/dev/null | cut -c1-230 || cat "$SUMMARY"
echo
if [ "$ran" -eq 0 ]; then echo "no case selected"; exit 2; fi
if [ "$failures" -gt 0 ]; then echo "FAILED: $failures of $ran cases deviated (evidence in $OUT)"; exit 1; fi
echo "OK: all $ran cases as expected (evidence in $OUT)"
