#!/usr/bin/env bash
# Gate for protocol v3 (PROTOCOL-V3.md), sidecar + reference client, both
# framings: honest connections and attacks by a malicious client, against a
# cu-sidecar and the real provider. Exit 0 only if every case ends exactly as
# expected.
#
#   VENICE_API_KEY=... crypto/tools/v3-check.sh
#
# The script starts its own cu-sidecar on loopback (relay/offer.venice.json:
# http ["2", "1.1"]; no node, so the sidecar signs stub receipts) and stops it
# when done. No routstr node is involved; nothing is announced. Every request
# is small (max_tokens 20); the big-body cases send one ~200 kB prompt each.
# The two image cases generate one image each of the cheapest model (real
# money: about $0.01 each); the image attacks cost nothing.
#
# Environment:
#   CU_SIDECAR      use this running sidecar instead of starting one (it must
#                   offer both framings and run without --node-settles); then
#                   also set CU_SIDECAR_RUNS to its --runs-dir. The fallback
#                   cases are skipped (they need the sidecar's test hooks).
#   CU_V3_PORT      loopback port for the started sidecar (default 7462)
#   CU_V3_OFFER     offer file (default relay/offer.venice.json)
#   CU_KEY_ENV      variable holding the provider key (default VENICE_API_KEY)
#   CU_UPSTREAM     provider host:port (default api.venice.ai:443)
#   CU_MODEL        chat model (default mistral-small-3-2-24b-instruct)
#   CU_SWAP_MODEL   the model of the model-swap attacks (default deepseek-v4-pro)
#   CU_IMAGE_MODEL  image model (default z-image-turbo; one image, the default variant)
#   CU_NO_IMAGES    1: skip the two paid image cases
#   CU_CASES        optional space-separated subset of case ids
#   CU_PAUSE        seconds of idle time in the `h2-idle` case (default 0 = skip)
#   CU_CASE_TIMEOUT per-case limit in seconds (default 180, plus the pause)
#   CU_V3_OUT       evidence directory (default crypto/runs/v3-check)
#
# Cases (machine-checked by v3_eval.py); `h2-` = framing "2", `h11-` = framing "1.1":
#   h2-one, h11-one       one request: 200, verified receipt (h11: closed `done`)
#   h2-three              three sequential requests on one connection (streams 3, 5, 7)
#   h11-two               two requests, one connection each
#   h2-error, h11-error   an unknown model: the 404 head is disclosed and settled
#                         (framing "2": π_WIN over the response head; "1.1": π_C3S
#                         head mode), the connection closes `error_settled`
#   h2-big, h11-big       a ~200 kB body (framing "2": released in steps as the
#                         provider's window opens)
#   h2-decoy, h11-decoy   another model in the private part of the body: neutralised,
#                         the provider runs the pinned model (the suffix comes last)
#   h2-armed, h11-armed   a connection armed first (setup armed:true, 2PC
#                         preprocessing, key share, proof channel), then the request
#   h2-refused, h11-refused   a request the sidecar refuses (max_tokens above the
#                         cap): request_refused, then the good request with the
#                         same n on the same connection
#   h2-image, h11-image   an image request: the body is proven like a chat body,
#                         the response is accepted and settled flat
#   h2-idle               (CU_PAUSE > 0) two requests with that pause between them
#   legacy-v2             a v2-shaped setup: `error` with code upgrade_required
# Attacks; the sidecar must refuse with an `error` frame, and its own log must
# show that the attacked request never reached the provider complete:
#   h2-a-hidden-headers   a HEADERS frame for another stream inside a "DATA" record
#   h2-b-padding          TLS record padding that shifts the frame boundary (§5.1 rule 3)
#   h2-c-suffix           the body ends in another model's suffix of the same length
#   h2-c-model-swap       … in the suffix of a pricier model
#   h2-c-cap-swap         … in a suffix with a larger max_tokens
#   h2-e-path             a HEADERS block with another :path of the same length
#   h2-e-path-long        the same with a longer path (refused on the record length)
#   h2-d-replay-usage     request 1's usage tail presented as request 2's disclosure
#                         (the request is honest; its settlement must be refused)
#   h2-f-image-suffix     an image body whose suffix orders one image more
#   h2-g-early-record     a record with no request open
#   h2-h-no-proof         the records are never proven: held, the provider answers nothing
#   h2-i-own-keyshare     the client's own key share instead of the joint one
#   h2-j-twopc-tag        a 2PC peer of another version (twopc_version_mismatch)
#   h11-c-suffix          the final record is another model's suffix of the same length (π_WIN fails)
#   h11-c-model-swap      … the suffix of a pricier model (another length: not the suffix alone)
#   h11-c-cap-swap        … a suffix with a larger max_tokens of the same length (π_WIN fails)
#   h11-k-not-alone       the suffix shares its final record with private bytes
#   h11-b-padding         a final record of the right size with a shorter text and TLS padding
#   h11-f-image-suffix    an image body whose suffix orders one image more
#   h11-g-early-record    the ClientHello before request 1
#   h11-h-no-proof        the final record is never proven: held, the provider answers nothing
#   h11-i-own-keyshare    the client's own key share instead of the joint one
# Fallback (§2.1, §2.3; the sidecar's test hooks, only with a sidecar started here):
#   fb-1 … fb-5           every framing-"2" open is made to fail: `--http auto` falls
#                         back to "1.1" on the same sidecar and settles there
#   fb-offer-11           after five failures GET /offer lists only "1.1"
#   fb-auto-11            `--http auto` now opens "1.1" at once (no fallback)
#   fb-http2-refused      `--http 2` is refused on the offer
#   fb-offer-back         the failure is lifted: after the retry time /offer lists "2" again
#   fb-auto-2             `--http auto` is on framing "2" again
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRYPTO="$(cd "$HERE/.." && pwd)"
OUT="${CU_V3_OUT:-$CRYPTO/runs/v3-check}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
MODEL="${CU_MODEL:-mistral-small-3-2-24b-instruct}"
SWAP_MODEL="${CU_SWAP_MODEL:-deepseek-v4-pro}"
IMAGE_MODEL="${CU_IMAGE_MODEL:-z-image-turbo}"
PAUSE="${CU_PAUSE:-0}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-180}"
KEY_ENV="${CU_KEY_ENV:-VENICE_API_KEY}"
RETRY_SECS=8
export CU_PROVER="${CU_PROVER:-$CRYPTO/zkbench/target/release/cu-prover}"
export CU_2PC="${CU_2PC:-$CRYPTO/zkbench/target/release/cu-2pc}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"
PY="$(command -v python3)"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }

SIDECAR_PID=""
FAIL_FILE="$OUT/h2-fail"
rm -f "$FAIL_FILE"
cleanup() {
  rm -f "$FAIL_FILE"
  if [ -n "$SIDECAR_PID" ]; then kill "$SIDECAR_PID" 2>/dev/null || true; wait "$SIDECAR_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

OWN_SIDECAR=0
if [ -n "${CU_SIDECAR:-}" ]; then
  SIDECAR="$CU_SIDECAR"
  RUNS="${CU_SIDECAR_RUNS:?set CU_SIDECAR_RUNS to the --runs-dir of that sidecar}"
else
  [ -n "${!KEY_ENV:-}" ] || { echo "$KEY_ENV is not set" >&2; exit 2; }
  BIN="$CRYPTO/zkbench/target/release/cu-sidecar"
  [ -x "$BIN" ] || { echo "build first: (cd crypto && cargo build --release -p cu-sidecar -p zkbench -p twopc)" >&2; exit 2; }
  PORT="${CU_V3_PORT:-7462}"
  RUNS="$OUT/sidecar-runs"
  mkdir -p "$RUNS"
  CU_TEST_H2_FAIL_FILE="$FAIL_FILE" CU_TEST_H2_RETRY_SECS="$RETRY_SECS" \
    "$BIN" --listen "127.0.0.1:$PORT" --upstream "${CU_UPSTREAM:-api.venice.ai:443}" --key-env "$KEY_ENV" \
    --offer "${CU_V3_OFFER:-$CRYPTO/relay/offer.venice.json}" --runs-dir "$RUNS" > "$OUT/sidecar.log" 2>&1 &
  SIDECAR_PID=$!
  OWN_SIDECAR=1
  SIDECAR="http://127.0.0.1:$PORT"
  for _ in $(seq 1 50); do
    curl -fsS "$SIDECAR/offer" > "$OUT/offer.json" 2>/dev/null && break
    kill -0 "$SIDECAR_PID" 2>/dev/null || { echo "the sidecar did not start; see $OUT/sidecar.log" >&2; exit 2; }
    sleep 0.2
  done
fi
curl -fsS "$SIDECAR/offer" > "$OUT/offer.json" || { echo "no offer from $SIDECAR" >&2; exit 2; }
offer_http() { curl -fsS "$SIDECAR/offer" | "$PY" -I -c 'import json,sys; print(",".join(json.load(sys.stdin).get("http") or []))'; }
[ "$(offer_http)" = "2,1.1" ] || { echo "the sidecar at $SIDECAR does not offer http [\"2\", \"1.1\"] (got $(offer_http))" >&2; exit 2; }

# Offline first: the client's HTTP/2 layer against the sidecar's vectors, the
# parameter checks, the message handling, the TLS fork's hooks and its record
# rules (no application data before the handshake is done, no plaintext
# handshake or alert record under record protection) and the offer rules
# (the receipt bound, the image count key).
(cd "$CRYPTO/client" && node --experimental-strip-types src/h2-selfcheck.ts && node --experimental-strip-types src/h2-conn-test.ts \
  && node --experimental-strip-types src/fork-selfcheck.ts > /dev/null \
  && node --experimental-strip-types test/tls-fork-records-check.ts > /dev/null \
  && node --experimental-strip-types test/offer-check.ts > /dev/null) || { echo "offline self-checks failed" >&2; exit 1; }

SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tevidence\n' > "$SUMMARY"
failures=0
ran=0

selected() { [ -z "${CU_CASES:-}" ] || [[ " $CU_CASES " == *" $1 "* ]]; }
record() { # id expect verdict evidence
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$SUMMARY"
  echo "   $3"
  echo "   $4"
  case "$3" in PASS) ;; *) failures=$((failures + 1)) ;; esac
}

# run_case <id> <expectation> <extra timeout seconds> <stdin: go|none> -- driver args...
run_case() {
  local id="$1" expect="$2" extra="$3" input="$4"; shift 5
  selected "$id" || return 0
  ran=$((ran + 1))
  echo "== $id (expect: $expect) =="
  local rc=0
  (
    cd "$CRYPTO/client"
    if [ "$input" = go ]; then
      # An armed connection waits for "go": sent once the driver says it is ready.
      ( while ! grep -q '^READY' "$OUT/$id.out" 2>/dev/null; do sleep 0.2; done; sleep 1; echo go ) | \
        "$TIMEOUT_BIN" -k 5 "$((CASE_TIMEOUT + extra))" "${DRIVER[@]}" --sidecar "$SIDECAR" --model "$MODEL" --max-tokens 20 --runs-dir "$OUT/client-runs" "$@"
    else
      "$TIMEOUT_BIN" -k 5 "$((CASE_TIMEOUT + extra))" "${DRIVER[@]}" --sidecar "$SIDECAR" --model "$MODEL" --max-tokens 20 --runs-dir "$OUT/client-runs" "$@" < /dev/null
    fi
  ) > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  local res verdict evidence
  res="$("$PY" -I "$HERE/v3_eval.py" "$id" "$expect" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$RUNS" 2>&1)" \
    || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"
  IFS=$'\t' read -r verdict evidence <<< "$res"
  record "$id" "$expect" "$verdict" "$evidence"
}

# check <id> <what> <command...>: a check of the sidecar itself (its offer).
check() {
  local id="$1" what="$2"; shift 2
  selected "$id" || return 0
  ran=$((ran + 1))
  echo "== $id (expect: $what) =="
  local got
  got="$("$@" 2>&1 || true)"
  if [ "$got" = "$what" ]; then record "$id" "$what" PASS "offer http = $got"; else record "$id" "$what" "DEVIATION: offer http is $got" "-"; fi
}

BIG='Reply with the single word OK.'
RED='a red circle on a white background'

# --- honest ------------------------------------------------------------------
run_case h2-one      "settled:2:1"   0 none -- --http 2
run_case h11-one     "settled:1.1:1" 0 none -- --http 1.1
run_case h2-three    "settled:2:3"   0 none -- --http 2 --requests 3
run_case h11-two     "settled:1.1:2" 0 none -- --http 1.1 --requests 2
run_case h2-error    "error:2:2:404"   0 none -- --http 2 --requests 3 --models "$MODEL,no-such-model-xyz"
run_case h11-error   "error:1.1:1:404" 0 none -- --http 1.1 --models no-such-model-xyz
run_case h2-big      "big:2:13"   0 none -- --http 2 --body-bytes 200000 --prompt "$BIG"
run_case h11-big     "big:1.1:13" 0 none -- --http 1.1 --body-bytes 200000 --prompt "$BIG"
run_case h2-decoy    "decoy:2:$MODEL"   0 none -- --http 2 --decoy-model "$SWAP_MODEL"
run_case h11-decoy   "decoy:1.1:$MODEL" 0 none -- --http 1.1 --decoy-model "$SWAP_MODEL"
run_case h2-armed    "armed:2"   0 go -- --http 2 --arm
run_case h11-armed   "armed:1.1" 0 go -- --http 1.1 --arm
run_case h2-refused  "refusedfirst:2"   0 none -- --http 2 --refuse-first
run_case h11-refused "refusedfirst:1.1" 0 none -- --http 1.1 --refuse-first
if [ "${CU_NO_IMAGES:-0}" != 1 ]; then
  run_case h2-image  "image:2:1"   120 none -- --http 2 --image --image-model "$IMAGE_MODEL" --prompt "$RED"
  run_case h11-image "image:1.1:1" 120 none -- --http 1.1 --image --image-model "$IMAGE_MODEL" --prompt "$RED"
fi
if [ "$PAUSE" -gt 0 ]; then
  run_case h2-idle "settled:2:2" "$PAUSE" none -- --http 2 --requests 2 --pause-ms "$((PAUSE * 1000))"
fi
run_case legacy-v2 "legacy" 0 none -- --legacy-v2-socket

# --- attacks, framing "2" ------------------------------------------------------
run_case h2-a-hidden-headers "refused:2:2:pi_win failed" 0 none -- --http 2 --requests 2 --adv hidden-headers --adv-at 2
run_case h2-b-padding        "refused:2:2:pi_win failed" 0 none -- --http 2 --requests 2 --adv padding --adv-at 2
run_case h2-c-suffix         "refused:2:2:pi_win failed" 0 none -- --http 2 --requests 2 --adv suffix --adv-at 2
run_case h2-c-model-swap     "refused:2:1:pi_win failed" 0 none -- --http 2 --adv suffix --adv-suffix-model "$SWAP_MODEL"
run_case h2-c-cap-swap       "refused:2:1:pi_win failed" 0 none -- --http 2 --adv suffix --adv-body-max-tokens 4000
run_case h2-e-path           "refused:2:2:pi_win failed" 0 none -- --http 2 --requests 2 --adv path --adv-at 2
run_case h2-e-path-long      "refused:2:1:not its HEADERS frame" 0 none -- --http 2 --adv path --adv-h2-path /api/v1/api_keys/rate_limits
run_case h2-d-replay-usage   "replay:2:interval" 0 none -- --http 2 --requests 2 --adv replay-usage
run_case h2-f-image-suffix   "refused:2:1:pi_win failed" 0 none -- --http 2 --image --image-model "$IMAGE_MODEL" --prompt "$RED" --adv suffix
run_case h2-g-early-record   "refused:2:0:." 0 none -- --http 2 --adv early-record
run_case h2-h-no-proof       "withheld:2:1" 0 none -- --http 2 --adv no-proof
run_case h2-i-own-keyshare   "refused:2:0:share" 0 none -- --http 2 --adv own-keyshare
run_case h2-j-twopc-tag      "refused:2:0:twopc_version_mismatch" 0 none -- --http 2 --adv twopc-tag

# --- attacks, framing "1.1" ----------------------------------------------------
run_case h11-c-suffix        "refused:1.1:1:pi_win failed" 0 none -- --http 1.1 --adv suffix
run_case h11-c-model-swap    "refused:1.1:1:." 0 none -- --http 1.1 --adv suffix --adv-suffix-model "$SWAP_MODEL"
run_case h11-c-cap-swap      "refused:1.1:1:pi_win failed" 0 none -- --http 1.1 --adv suffix --adv-body-max-tokens 99
run_case h11-k-not-alone     "refused:1.1:1:." 0 none -- --http 1.1 --adv not-alone
run_case h11-b-padding       "refused:1.1:1:pi_win failed" 0 none -- --http 1.1 --adv padding
run_case h11-f-image-suffix  "refused:1.1:1:pi_win failed" 0 none -- --http 1.1 --image --image-model "$IMAGE_MODEL" --prompt "$RED" --adv suffix
run_case h11-g-early-record  "refused:1.1:0:." 0 none -- --http 1.1 --adv early-record
run_case h11-h-no-proof      "withheld:1.1:1" 0 none -- --http 1.1 --adv no-proof
run_case h11-i-own-keyshare  "refused:1.1:0:share" 0 none -- --http 1.1 --adv own-keyshare

# --- forced failure of framing "2": fallback, withdrawal, return -----------------
if [ "$OWN_SIDECAR" = 1 ] && { [ -z "${CU_CASES:-}" ] || [[ " $CU_CASES " == *" fb-"* ]]; }; then
  touch "$FAIL_FILE"
  for i in 1 2 3 4 5; do run_case "fb-$i" "auto:1.1:yes" 0 none -- --http auto; done
  check fb-offer-11 "1.1" offer_http
  run_case fb-auto-11 "auto:1.1:no" 0 none -- --http auto
  run_case fb-http2-refused "nohttp2" 0 none -- --http 2
  rm -f "$FAIL_FILE"
  sleep "$((RETRY_SECS + 2))"
  check fb-offer-back "2,1.1" offer_http
  run_case fb-auto-2 "auto:2:no" 0 none -- --http auto
fi

echo
column -t -s $'\t' "$SUMMARY" 2>/dev/null | cut -c1-230 || cat "$SUMMARY"
echo
if [ "$ran" -eq 0 ]; then echo "no case selected"; exit 2; fi
if [ "$failures" -gt 0 ]; then echo "FAILED: $failures of $ran cases deviated (evidence in $OUT)"; exit 1; fi
echo "OK: all $ran cases as expected (evidence in $OUT)"
