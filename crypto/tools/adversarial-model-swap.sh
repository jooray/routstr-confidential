#!/usr/bin/env bash
# Regression gate: model/parameter-swap attacks by a MALICIOUS client, plus an
# honest control. Exit 0 only if every case ends exactly as expected.
#
#   AUTH=sk-... CU_NODE=http://127.0.0.1:8010 NODE_LOG=.../routstr-core/logs/app_YYYY-MM-DD.log \
#     crypto/tools/adversarial-model-swap.sh
#
# Requires node, sidecar (and a mint if AUTH=mint) running; see
# crypto/PROGRESS-CONFIDENTIAL.md. The node must not serve other confidential
# sessions while this runs (node log lines carry a redacted sid, so the gate
# attributes them by time window).
#
# Environment:
#   AUTH        required. Node credential for every case: an sk- key with a
#               balance of a few sats, or the literal `mint` to mint a fresh
#               Cashu token per case from $MINT (a Cashu token is single-use).
#   CU_NODE     node base URL (default http://127.0.0.1:8000)
#   MINT        mint URL for AUTH=mint (default http://127.0.0.1:3338)
#   MINT_SATS   sats per minted token (default 20)
#   CU_PROVER   cu-prover binary (default ../zkbench/target/release/cu-prover)
#   NODE_LOG    optional: the node's JSON log file (routstr-core/logs/app_<date>.log;
#               the plain console log drops the `outcome` field). When set, the
#               money outcome is asserted from the node's own lines
#               "confidential ws: session aborted ... outcome=released|charged_reservation"
#               and "confidential ws: settled". When unset, only driver-side
#               assertions apply and the summary says so.
#   NODE_LOG_WAIT  seconds to wait for the node's line after a case (default 10)
#   CU_CASES    optional space-separated subset of case ids to run
#   CU_CASE_TIMEOUT  per-case wall-clock limit in seconds (default 120)
#   CU_DRIVER   command that runs the reference client (default
#               "node --experimental-strip-types src/driver.ts", run from crypto/client).
#               Tests point it at a stub.
#   CU_ADV_OUT  evidence directory (default crypto/runs/adversarial)
#
# Expected outcomes (machine-checked):
#   control            honest session, same model: exit 0, verified receipt
#                      (signature, usage and cost checks), effective model ==
#                      setup model; node: "settled".
#   a-suffix-mismatch  suffix model != setup model -> sidecar refuses the
#                      suffix (reason mentions "suffix"); the final body record
#                      is never released; node: outcome=released.
#   b-decoy            decoy model in the private part, honest suffix -> the
#                      attack is neutralised, not refused: the provider uses the
#                      last `model` key (the pinned suffix), so the session
#                      settles at the setup model; node: "settled".
#   d-no-suffix-swap   body model/max_tokens != setup, no body_suffix declared ->
#                      the sidecar holds the final record: zero response bytes,
#                      no model output (or a refusal); node: outcome=released.
#   e-unoffered-model  as d, with a model the node does not offer.
#   f-claim-canonical  body ends with another model's suffix but claims the
#                      canonical one -> π_C2 fails (reason mentions pi_c2);
#                      node: outcome=released.
# For every attack case the driver must never have seen `body_released` (the
# provider never got the complete request). A driver crash, a timeout, a
# refusal for the wrong reason, a refusal before the session was set up, or
# outcome=charged_reservation is a deviation.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../client"

: "${AUTH:?set AUTH to a node credential (sk- key) or to 'mint'}"
NODE="${CU_NODE:-http://127.0.0.1:8000}"
MINT="${MINT:-http://127.0.0.1:3338}"
MINT_SATS="${MINT_SATS:-20}"
NODE_LOG="${NODE_LOG:-}"
NODE_LOG_WAIT="${NODE_LOG_WAIT:-10}"
CASE_TIMEOUT="${CU_CASE_TIMEOUT:-120}"
OUT="${CU_ADV_OUT:-$HERE/../runs/adversarial}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export CU_PROVER="${CU_PROVER:-../zkbench/target/release/cu-prover}"
read -r -a DRIVER <<< "${CU_DRIVER:-node --experimental-strip-types src/driver.ts}"

TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { echo "need GNU timeout (coreutils)" >&2; exit 2; }
if [ -n "$NODE_LOG" ] && [ ! -f "$NODE_LOG" ]; then
  echo "NODE_LOG=$NODE_LOG does not exist" >&2; exit 2
fi

mint() {
  (cd "$HERE/.cashu" && uv run --python 3.12 --with 'cashu==0.20.0' --with 'marshmallow<4' \
    python ../cu_cashu.py mint --mint "$MINT" --sats "$1" 2>/dev/null | tail -1)
}

# Evaluate one case. Args: case expect reason_re rc out err nodelog_slice setup_model
# Prints "VERDICT<TAB>driver evidence<TAB>node evidence".
EVAL_PY=$(cat <<'PYEOF'
import json, re, sys
case, expect, reason_re, rc, out_f, err_f, slice_f, model = sys.argv[1:9]
rc = int(rc)
out = open(out_f, errors="replace").read(); err = open(err_f, errors="replace").read()
both = out + "\n" + err
dev = []
released_body = "<- body_released" in both
has_sid = re.search(r"\bsid=[0-9a-f]{16,}", out) is not None
m = re.search(r"(sidecar rejected: .*|connection closed: .*)", both)
refusal = m.group(1)[:110] if m else None
e2e = None
for line in out.splitlines():
    if line.startswith("E2E_JSON "):
        try: e2e = json.loads(line[9:])
        except ValueError: pass
adv = None
for line in out.splitlines():
    if line.startswith("ADV_NO_SUFFIX "):
        try: adv = json.loads(line[14:])
        except ValueError: pass
if rc in (124, 137):
    dev.append(f"TIMEOUT (rc={rc})")
    drv = "timeout"
elif expect == "settled":
    ok = (rc == 0 and e2e is not None and e2e.get("receipt_sig_ok") is True and e2e.get("usage_match") is True
          and e2e.get("cost_ok") is True and e2e.get("model") == model)
    drv = (f"rc={rc} model={e2e.get('model')} sig={e2e.get('receipt_sig_ok')} usage={e2e.get('usage_match')} "
           f"cost={e2e.get('cost_ok')} cost_msats={e2e.get('cost_msats')}") if e2e else f"rc={rc} no E2E_JSON" + (f" ({refusal})" if refusal else "")
    if not ok: dev.append("expected a verified, settled session at the setup model")
else:
    if released_body: dev.append("final body record was released to the provider")
    if e2e and e2e.get("receipt_sig_ok"): dev.append("attack produced a receipt")
    if expect == "refused" or (expect == "withheld" and adv is None):
        if rc == 0: dev.append("driver exited 0")
        if refusal is None:
            dev.append("CRASH: no refusal from node/sidecar" if rc != 0 else "no refusal")
        elif not has_sid:
            dev.append("refused before the session was set up (wrong check fired)")
        elif expect == "refused" and not re.search(reason_re, refusal, re.I):
            dev.append(f"refused for the wrong reason (want /{reason_re}/)")
        drv = f"rc={rc} refused: {refusal}"
    else:  # withheld, ADV_NO_SUFFIX seen
        if rc not in (0, 3): dev.append(f"CRASH: unexpected rc={rc}")
        if adv.get("response_bytes") != 0 or adv.get("has_model_output"):
            dev.append("provider answered a request the sidecar should have held")
        drv = f"rc={rc} withheld: response_bytes={adv.get('response_bytes')} model_output={adv.get('has_model_output')}"
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
    want = "settled" if expect == "settled" else "aborted outcome=released"
    if len(lines) != 1:
        dev.append(f"node: expected exactly one session line, got {len(lines)} (is the node dedicated to this run?)")
    elif not lines[0].startswith(want):
        dev.append(f"node: expected '{want}'")
verdict = "PASS" if not dev else "DEVIATION: " + "; ".join(dev)
print(f"{verdict}\t{drv}\t{node}")
PYEOF
)

PY="$(command -v python3)"
SUMMARY="$OUT/summary.tsv"
printf 'case\texpected\tverdict\tdriver\tnode\n' > "$SUMMARY"
failures=0
ran=0

# run_case <id> <expect: settled|refused|withheld> <reason regex> <setup model> -- driver args...
run_case() {
  local id="$1" expect="$2" reason="$3" model="$4"; shift 5
  if [ -n "${CU_CASES:-}" ] && [[ " $CU_CASES " != *" $id "* ]]; then return 0; fi
  ran=$((ran + 1))
  local auth="$AUTH"
  if [ "$AUTH" = mint ]; then
    auth="$(mint "$MINT_SATS" || true)"
    if [ -z "$auth" ]; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$expect" "DEVIATION: mint failed" "-" "-" >> "$SUMMARY"
      failures=$((failures + 1)); echo "== $id: mint failed"; return 0
    fi
  fi
  local off=0
  if [ -n "$NODE_LOG" ]; then off=$(wc -c < "$NODE_LOG" | tr -d ' '); fi
  echo "== $id (expect: $expect) =="
  local rc=0
  "$TIMEOUT_BIN" -k 5 "$CASE_TIMEOUT" "${DRIVER[@]}" --node "$NODE" --model "$model" --auth "$auth" "$@" \
    > "$OUT/$id.out" 2> "$OUT/$id.err" || rc=$?
  local slice="-"
  if [ -n "$NODE_LOG" ]; then
    slice="$OUT/$id.nodelog"
    local waited=0
    while :; do
      local size; size=$(wc -c < "$NODE_LOG" | tr -d ' ')
      if [ "$size" -lt "$off" ]; then off=0; fi   # rotated/truncated
      tail -c +"$((off + 1))" "$NODE_LOG" | grep -E 'confidential ws: (session aborted|settled)' > "$slice" || true
      if [ -s "$slice" ] || [ "$waited" -ge "$NODE_LOG_WAIT" ]; then break; fi
      sleep 1; waited=$((waited + 1))
    done
    sleep 1   # let a late duplicate line land, so "exactly one" is meaningful
    tail -c +"$((off + 1))" "$NODE_LOG" | grep -E 'confidential ws: (session aborted|settled)' > "$slice" || true
  fi
  local res verdict drv nodeev
  res="$("$PY" -I -c "$EVAL_PY" "$id" "$expect" "$reason" "$rc" "$OUT/$id.out" "$OUT/$id.err" "$slice" "$model" 2>&1)" \
    || res=$'DEVIATION: evaluator error\t'"${res//$'\n'/ }"$'\t-'
  IFS=$'\t' read -r verdict drv nodeev <<< "$res"
  echo "  $verdict"
  echo "  driver: $drv"
  echo "  node:   $nodeev"
  echo "  -> $OUT/$id.{out,err}"
  [ "$verdict" = PASS ] || failures=$((failures + 1))
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$expect" "$verdict" "$drv" "$nodeev" >> "$SUMMARY"
}

# Honest control: must succeed, so an all-refusing stack cannot pass the gate.
run_case control settled '' deepseek-v4-flash -- \
  --max-tokens 12 --prompt 'Say hi in three words.'

# (a) setup = cheap text-only model; body suffix = a different (pricier)
#     text-only model, so the modality gate passes and the canonical-suffix
#     check is what must fire.
run_case a-suffix-mismatch refused 'suffix' deepseek-v4-flash -- \
  --adv-suffix-model deepseek-v4-pro --max-tokens 12 --prompt 'Say hi in three words.'

# (b) honest suffix, decoy model in the private part: neutralised (last key wins).
run_case b-decoy settled '' deepseek-v4-flash -- \
  --decoy-model deepseek-v4-pro --max-tokens 12 --prompt 'Say hi in three words.'

# (d) body carries a pricier model and a larger max_tokens than the setup, and
#     NO body_suffix is declared. The sidecar holds the record that completes
#     the body until π_C2 verifies, so the upstream never gets a complete request.
run_case d-no-suffix-swap withheld 'suffix|pi_c2|π_C2' deepseek-v4-flash -- \
  --adv-suffix-model deepseek-v4-pro --adv-body-max-tokens 600 --adv-no-suffix \
  --max-tokens 12 --prompt 'Name five planets, one per line.'

# (e) the same with a model this node does not offer at all (a far pricier one).
run_case e-unoffered-model withheld 'suffix|pi_c2|π_C2' deepseek-v4-flash -- \
  --adv-suffix-model claude-fable-5 --adv-body-max-tokens 600 --adv-no-suffix \
  --max-tokens 12 --prompt 'Name five planets, one per line.'

# (f) body ends with another model's suffix but body_suffix claims the
#     canonical one: π_C2 must fail and the held record is never released.
#     Model names of equal length, so the length check passes and π_C2 runs.
run_case f-claim-canonical refused 'pi_c2|π_C2' deepseek-v3.2 -- \
  --adv-suffix-model claude-opus-5 --adv-claim-canonical --max-tokens 12 \
  --prompt 'Say hi in three words.'

echo
echo "== summary ($ran cases; node: $NODE) =="
if command -v column >/dev/null 2>&1; then
  cut -f1-3 "$SUMMARY" | column -t -s $'\t'
else
  cut -f1-3 "$SUMMARY"
fi
if [ -z "$NODE_LOG" ]; then
  echo "NOTE: NODE_LOG unset - driver-side assertions only; the node's money outcome (released vs charged) was NOT checked."
fi
echo "details: $SUMMARY"
if [ "$ran" -eq 0 ]; then echo "GATE FAILED: no case ran (CU_CASES='${CU_CASES:-}')"; exit 1; fi
if [ "$failures" -ne 0 ]; then echo "GATE FAILED: $failures of $ran cases deviated"; exit 1; fi
echo "GATE PASSED: $ran of $ran cases as expected"
