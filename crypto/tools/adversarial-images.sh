#!/usr/bin/env bash
# Regression gate for confidential image generation (protocol v3, through a
# node): parameter-injection and suffix attacks by a MALICIOUS client, plus an
# honest control. Exit 0 only if every case ends exactly as expected. Run from
# anywhere, against a dedicated node (it must serve no other confidential
# connection meanwhile: the node's log lines are attributed by time window).
# The sidecar-level image attacks of both framings are in v3-check.sh; this
# gate is what needs a node: the signed prices and the provider's echo.
#
#   AUTH=sk-... CU_NODE=http://127.0.0.1:8010 NODE_LOG=.../routstr-core/logs/app_YYYY-MM-DD.log \
#     crypto/tools/adversarial-images.sh
#
# Paid: about five cheap images (z-image-turbo $0.01, one qwen-image-2-1-turbo $0.02).
#
# Environment:
#   AUTH        required: an sk- key of the node with a balance for the images
#   CU_NODE     node base URL (default http://127.0.0.1:8000)
#   CU_HTTP     the framing: 2, 1.1 or auto (default auto: the offer's first)
#   NODE_LOG    optional: the node's JSON log file; when set, the money outcome
#               is asserted from the node's own lines
#   NODE_LOG_WAIT, CU_CASES, CU_CASE_TIMEOUT, CU_PROVER, CU_DRIVER, CU_ADV_OUT
# CHEAP / TIERED   the flat and the tiered model (default z-image-turbo /
#                  qwen-image-2-1-turbo); EXPENSIVE the decoy (nano-banana-pro).
#
# Expected outcomes (machine-checked):
#   img-control           honest, count 1: one image, receipt verified, flat charge
#                         at the signed price; node: "settled".
#   img-decoy-model       an expensive model in the private part, honest suffix:
#                         neutralised (last key wins): one image, charged the cheap
#                         model's price, provider echo names the cheap model.
#   img-count-inject      "variants":4 in the private part, suffix pins 1: exactly
#                         one image, flat charge for one.
#   img-paid-extras       enhance_prompt/enable_web_search true in the private part:
#                         overridden by the pins (echo false), flat charge.
#   img-resolution-inject private "resolution":"4K" on the 1K variant of a tiered
#                         model: a 1K image (longest side <= 1536 px), 1K price.
#   img-count-mismatch    the request names count 1, the body's suffix pins 4: the
#                         proof of the suffix (pi_WIN) fails; the body is never
#                         released; node: outcome=released.
#   img-suffix-model      the request names the cheap model, the body's suffix the
#                         expensive one: refused; node: outcome=released.
#   img-no-proof-swap     the suffix pins count 4 and is never proven: the sidecar
#                         holds the record(s); zero response bytes; node: released.
#   img-error-honest      a field the provider rejects: 400, error head proven,
#                         charged nothing (no session fee configured).
#   img-accept-on-error   the same, but the client sends `accept` anyway: the node
#                         cannot see the status and charges the flat price. This
#                         is the documented residual (paper §4.10: a dishonest
#                         accept gains at most max(f_s, f_a) - f_s); the gate
#                         records it and requires exactly the flat charge.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../client"

: "${AUTH:?set AUTH to a node credential (sk- key)}"
NODE="${CU_NODE:-http://127.0.0.1:8000}"
NODE_LOG="${NODE_LOG:-}"
NODE_LOG_WAIT="${NODE_LOG_WAIT:-10}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-180}"
CHEAP="${CHEAP:-z-image-turbo}"
TIERED="${TIERED:-qwen-image-2-1-turbo}"
EXPENSIVE="${EXPENSIVE:-nano-banana-pro}"
OUT="${CU_ADV_OUT:-$HERE/../runs/adversarial-images}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"

TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }
if [ -n "$NODE_LOG" ] && [ ! -f "$NODE_LOG" ]; then
  echo "NODE_LOG=$NODE_LOG does not exist" >&2; exit 2
fi

# The signed per-image prices, for the flat-charge checks.
OFFER_JSON="$OUT/offer.json"
curl -sf "$NODE/v1/confidential/offer?v=3" > "$OFFER_JSON"

# Evaluate one case. Args: case expect reason_re rc out err nodelog_slice model variant count runs_dir_glob
EVAL_PY=$(cat <<'PYEOF'
import glob, json, os, re, struct, sys
case, expect, reason_re, rc, out_f, err_f, slice_f, model, variant, count, offer_f = sys.argv[1:12]
rc = int(rc); count = int(count)
out = open(out_f, errors="replace").read(); err = open(err_f, errors="replace").read()
both = out + "\n" + err
offer = json.load(open(offer_f))
if "sig_payload" in offer: offer = json.loads(offer["sig_payload"])
def price(m, v):
    for x in offer["images"]["price_list"].get(m, []):
        if v in (None, "", x["id"]): return x["msat_per_image"], x["id"]
    return None, None
flat, vid = price(model, variant)
dev = []
e2e = None; adv = None
for line in out.splitlines():
    if line.startswith("E2E_JSON "):
        try: e2e = json.loads(line[9:])
        except ValueError: pass
    if line.startswith("ADV "):
        try: adv = json.loads(line[4:])
        except ValueError: pass
# One request per run: its result carries the image fields.
req = ((e2e or {}).get("requests") or [None])[0]
released_body = "<- body_released" in both
m = re.search(r"(sidecar rejected: .*|connection closed: .*)", both)
refusal = m.group(1)[:140] if m else None

def webp_size(path):
    b = open(path, "rb").read(64)
    if b[:4] != b"RIFF" or b[8:12] != b"WEBP": return None
    kind = b[12:16]
    if kind == b"VP8X": return (1 + int.from_bytes(b[24:27], "little"), 1 + int.from_bytes(b[27:30], "little"))
    if kind == b"VP8 ": w, h = struct.unpack("<HH", b[26:30]); return (w & 0x3FFF, h & 0x3FFF)
    if kind == b"VP8L":
        v = int.from_bytes(b[21:25], "little"); return (1 + (v & 0x3FFF), 1 + ((v >> 14) & 0x3FFF))
    return None

drv = f"rc={rc}"
if rc in (124, 137):
    dev.append(f"TIMEOUT (rc={rc})")
elif expect in ("images", "accept-residual"):
    if req is None:
        dev.append("no settled request in E2E_JSON" + (f" ({refusal})" if refusal else ""))
    else:
        e2e = req
        files = e2e.get("files") or []
        sizes = [webp_size(f) for f in files]
        want_images = count if expect == "images" else 0
        drv = (f"rc={rc} images={e2e.get('images')} sizes={sizes} cost_msats={e2e.get('cost_msats')} flat={flat}x{count} "
               f"sig={e2e.get('receipt_sig_ok')} status={e2e.get('status')} echo={json.dumps(e2e.get('echo'), sort_keys=True)}")
        if rc != 0: dev.append("driver failed")
        if e2e.get("images") != want_images: dev.append(f"expected {want_images} image(s)")
        if e2e.get("receipt_sig_ok") is not True: dev.append("receipt not verified")
        if flat is None or e2e.get("cost_msats") != flat * count: dev.append("charge is not the signed flat price x count")
        echo = e2e.get("echo") or {}
        if expect == "images":
            if "model" in echo and echo["model"] != model: dev.append(f"provider ran {echo['model']}")
            if "variants" in echo and echo["variants"] != count: dev.append(f"provider ran variants={echo['variants']}")
            for k in ("enhance_prompt", "enable_web_search"):
                if echo.get(k) not in (None, False, "off", "false"): dev.append(f"provider ran {k}={echo[k]}")
            if case == "img-resolution-inject":
                if not sizes or sizes[0] is None or max(sizes[0]) > 1536: dev.append(f"image larger than 1K: {sizes}")
                if "resolution" in echo and str(echo["resolution"]).upper() != "1K": dev.append(f"provider ran resolution={echo['resolution']}")
        else:
            if not (e2e.get("status") or 0) >= 400: dev.append("the residual case did not get an upstream error")
elif expect == "error-released":
    drv = f"rc={rc} " + (f"status={req.get('status')} cost_msats={req.get('cost_msats')} sig={req.get('receipt_sig_ok')}" if req else "no error receipt")
    if rc != 0 or not req or not (req.get("status") or 0) >= 400 or req.get("cost_msats") != 0 or req.get("receipt_sig_ok") is not True:
        dev.append("expected a verified zero-cost error receipt")
else:  # refused / withheld
    if released_body: dev.append("final body record was released to the provider")
    if req and req.get("receipt_sig_ok"): dev.append("attack produced a receipt")
    # The driver exits 0 when the attack was refused (5 when it was not) and reports it in its ADV line.
    if adv is None: dev.append("no ADV line (driver crash?)")
    elif expect == "refused":
        drv = f"rc={rc} refused={adv.get('refused')}: {str(adv.get('reason'))[:140]}"
        if rc != 0 or adv.get("refused") is not True: dev.append("the attack was not refused")
        elif adv.get("body_released"): dev.append("the body was released")
        elif not re.search(reason_re, str(adv.get("reason")), re.I): dev.append(f"refused for the wrong reason (want /{reason_re}/)")
    else:
        d = adv.get("detail") if isinstance(adv.get("detail"), dict) else adv
        drv = f"rc={rc} withheld={adv.get('refused')}: response_bytes={d.get('response_bytes')} response_frames={d.get('response_frames')}"
        if rc != 0 or adv.get("refused") is not True: dev.append("provider answered a request the sidecar should have held")
node = "n/a (NODE_LOG unset)"
if slice_f != "-":
    lines = []
    for raw in open(slice_f, errors="replace"):
        try: j = json.loads(raw)
        except ValueError: j = {"message": raw}
        msg = str(j.get("message", ""))
        if msg.startswith("confidential ws: session aborted"):
            o = j.get("outcome") or (re.search(r"outcome\W+(\w+)", raw) or [None, "?"])[1]
            lines.append(f"aborted outcome={o}")
        elif msg.startswith("confidential ws: settled"):
            lines.append(f"settled cost_msats={j.get('cost_msats')}")
    node = "; ".join(lines) or "no session line"
    want = "settled" if expect in ("images", "accept-residual", "error-released") else "aborted outcome=released"
    if len(lines) != 1: dev.append(f"node: expected exactly one session line, got {len(lines)}")
    elif not lines[0].startswith(want): dev.append(f"node: expected '{want}'")
verdict = "PASS" if not dev else "DEVIATION: " + "; ".join(dev)
if verdict == "PASS" and expect == "accept-residual": verdict = "PASS (documented residual)"
print(f"{verdict}\t{drv}\t{node}")
PYEOF
)

PY="$(command -v python3)"
SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tdriver\tnode\n' > "$SUMMARY"
failures=0
ran=0

# run_case <id> <expect> <reason regex> <model> <variant> <count> -- driver args...
run_case() {
  local id="$1" expect="$2" reason="$3" model="$4" variant="$5" count="$6"; shift 7
  if [ -n "${CU_CASES:-}" ] && [[ " $CU_CASES " != *" $id "* ]]; then return 0; fi
  ran=$((ran + 1))
  local off=0
  if [ -n "$NODE_LOG" ]; then off=$(wc -c < "$NODE_LOG" | tr -d ' '); fi
  echo "== $id (expect: $expect) =="
  local rc=0
  local vargs=()
  if [ -n "$variant" ]; then vargs=(--variant "$variant"); fi
  "$TIMEOUT_BIN" -k 5 "$CASE_TIMEOUT" "${DRIVER[@]}" --node "$NODE" --http "${CU_HTTP:-auto}" --image --model "$model" --count "$count" \
    "${vargs[@]}" --runs-dir "$OUT/runs" --auth "$AUTH" "$@" > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  local slice="-"
  if [ -n "$NODE_LOG" ]; then
    slice="$OUT/$id.nodelog"
    local waited=0
    while :; do
      local size; size=$(wc -c < "$NODE_LOG" | tr -d ' ')
      if [ "$size" -lt "$off" ]; then off=0; fi
      tail -c +"$((off + 1))" "$NODE_LOG" | grep -E 'confidential ws: (session aborted|settled)' > "$slice" || true
      if [ -s "$slice" ] || [ "$waited" -ge "$NODE_LOG_WAIT" ]; then break; fi
      sleep 1; waited=$((waited + 1))
    done
    sleep 1
    tail -c +"$((off + 1))" "$NODE_LOG" | grep -E 'confidential ws: (session aborted|settled)' > "$slice" || true
  fi
  local res verdict drv nodeev
  res="$("$PY" -I -c "$EVAL_PY" "$id" "$expect" "$reason" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$slice" \
    "$model" "$variant" "$count" "$OFFER_JSON" 2>&1)" || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"$'\t-'
  IFS=$'\t' read -r verdict drv nodeev <<< "$res"
  echo "  $verdict"
  echo "  driver: $drv"
  echo "  node:   $nodeev"
  case "$verdict" in PASS*) ;; *) failures=$((failures + 1)) ;; esac
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$expect" "$verdict" "$drv" "$nodeev" >> "$SUMMARY"
}

P='A small red bicycle leaning on a white wall, watercolor'

run_case img-control images '' "$CHEAP" '' 1 -- --prompt "$P"
run_case img-decoy-model images '' "$CHEAP" '' 1 -- --prompt "$P" \
  --private-extra "\"model\":\"$EXPENSIVE\""
run_case img-count-inject images '' "$CHEAP" '' 1 -- --prompt "$P" --private-extra '"variants":4'
run_case img-paid-extras images '' "$CHEAP" '' 1 -- --prompt "$P" \
  --private-extra '"enhance_prompt":true,"enable_web_search":true'
run_case img-resolution-inject images '' "$TIERED" 1K-webp 1 -- --prompt "$P" --private-extra '"resolution":"4K"'
run_case img-count-mismatch refused 'pi_win' "$CHEAP" '' 1 -- --prompt "$P" --adv suffix --adv-image-count 4
run_case img-suffix-model refused '.' "$CHEAP" '' 1 -- --prompt "$P" --adv suffix --adv-suffix-model "$EXPENSIVE"
run_case img-no-proof-swap withheld '' "$CHEAP" '' 1 -- --prompt "$P" --adv no-proof --adv-image-count 4
run_case img-error-honest error-released '' "$CHEAP" '' 1 -- --prompt "$P" --private-extra '"bogus_field_xyz":1'
run_case img-accept-on-error accept-residual '' "$CHEAP" '' 1 -- --prompt "$P" --private-extra '"bogus_field_xyz":1' --adv-accept-any

echo
echo "== summary ($ran cases; node: $NODE) =="
if command -v column >/dev/null 2>&1; then cut -f1-3 "$SUMMARY" | column -t -s $'\t'; else cut -f1-3 "$SUMMARY"; fi
if [ -z "$NODE_LOG" ]; then
  echo "NOTE: NODE_LOG unset - driver-side assertions only; the node's money outcome was NOT checked."
fi
echo "details: $SUMMARY"
if [ "$ran" -eq 0 ]; then echo "GATE FAILED: no case ran (CU_CASES='${CU_CASES:-}')"; exit 1; fi
if [ "$failures" -ne 0 ]; then echo "GATE FAILED: $failures of $ran cases deviated"; exit 1; fi
echo "GATE PASSED: $ran of $ran cases as expected"
