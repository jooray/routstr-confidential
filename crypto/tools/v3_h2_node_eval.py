"""Evaluate one case of v3-h2-node-check.sh. Prints "VERDICT<TAB>evidence".

Arguments: case expect driver_rc driver_out driver_err context.json
The context names the node's database and log, the case's own credential (a
fresh key per case, so the key's row is the case's whole money outcome), the
signed offer, the client's run directory, how many two-party handshakes the
sidecar ran during the case, and what the v2 control session reserved.

`expect` is one of:
  settled:<n>              n requests on one connection, each reserved, settled at
                           the usage the provider reported, with a verified receipt
  error:<n>:<status>       request n is refused by the provider with that status:
                           its error head is disclosed and its reservation released
  node-refused:<n>:<regex> the node refuses request n for that reason and reserves
                           nothing for it
  released:<n>:<regex>     an attack on request n is refused for that reason before
                           the provider has the request: its reservation is released
  charged:<n>:<regex>      request n reaches the provider and its settlement is
                           refused for that reason: its reservation is charged (what
                           v2 charges for a released request with no disclosure)
  no-funds:<status>        a setup with an unfunded credential is refused with that
                           status before the sidecar is dialed
  v2                       an unchanged protocol v2 session settles
In every case the key's balance must equal its start minus exactly the charges
named above, with nothing left reserved.
"""
import json
import math
import os
import re
import sqlite3
import sys
import time

case, expect, rc, out_f, err_f, ctx_f = sys.argv[1:7]
rc = int(rc)
ctx = json.load(open(ctx_f))
out = open(out_f, errors="replace").read()
err = open(err_f, errors="replace").read()
both = out + "\n" + err
dev = []
kind, _, rest = expect.partition(":")


def tagged(tag):
    for line in out.splitlines():
        if line.startswith(tag + " "):
            try:
                return json.loads(line[len(tag) + 1:])
            except ValueError:
                return None
    return None


e2e = tagged("E2E_JSON")
adv = tagged("ADV_H2")
sid = (re.search(r"\bsid=([0-9a-f]{64})", out) or [None, None])[1]
offer = json.load(open(ctx["offer"]))


def node_events():
    """The node's log lines of this case (confidential_ws only)."""
    lines = []
    for name in sorted(os.listdir(ctx["log_dir"])):
        if name.endswith(".log"):
            lines += open(os.path.join(ctx["log_dir"], name), errors="replace").read().splitlines()
    evs = []
    for line in lines[ctx["log_skip"]:]:
        try:
            j = json.loads(line)
        except ValueError:
            continue
        # Lines of this case's session only (the node logs the sid's first 12
        # characters), so a later case's lines never count.
        if j.get("name") == "routstr.confidential_ws" and (not sid or j.get("sid") == sid[:12]):
            evs.append(j)
    return evs


def key_row():
    db = sqlite3.connect(f"file:{ctx['db']}?mode=ro", uri=True, timeout=10)
    try:
        return db.execute(
            "select balance, reserved_balance, total_spent from api_keys where hashed_key = ?", (ctx["key"],)
        ).fetchone()
    finally:
        db.close()


def msg(evs, text):
    return [e for e in evs if text in e.get("message", "")]


# The node decides an aborted request after the client is gone (it first hears
# the sidecar's last frames): wait for the session's end and a settled row.
ends = "http 2 connection ended" if kind not in ("v2", "no-funds") else None
for _ in range(120):
    evs = node_events()
    row = key_row()
    if row and row[1] == 0 and (ends is None or msg(evs, ends) or not sid):
        break
    time.sleep(0.25)


def same_rates_as_v2():
    """Whether the v2 control session saw the same rates (they follow the exchange rate)."""
    try:
        v2 = json.load(open(ctx["v2_offer"]))
    except (OSError, ValueError, KeyError):
        return False
    return v2.get("price_list", {}).get(ctx["model"]) == offer.get("price_list", {}).get(ctx["model"])


def usage_cost(rec, usage):
    """The node's charge for a usage event at the rates its receipt names,
    which must be the signed offer's (the driver verified that signature)."""
    rates = rec.get("rates") or {}
    if rates != offer["price_list"].get(rec.get("model")):
        return None
    prompt, completion = usage["prompt_tokens"], usage["completion_tokens"]
    d = usage.get("prompt_tokens_details") or {}
    cached = min(max(int(d.get("cached_tokens") or 0), 0), prompt)
    written = 0
    for v in (d.get("cache_creation_input_tokens"), d.get("cache_write_tokens"), d.get("cache_creation_tokens"),
              usage.get("cache_creation_input_tokens")):
        if isinstance(v, int) and v > 0:
            written = min(v, prompt - cached)
            break
    cost = (rates["in"] * (prompt - cached - written) + min(rates["cached_in"], rates["in"]) * cached
            + rates.get("cache_write", rates["in"]) * written + rates["out"] * completion)
    return math.ceil(cost / 1000) + int(offer.get("session_fee_msat") or 0)


def receipt(n):
    try:
        return json.load(open(os.path.join(ctx["client_runs"], sid or "-", f"receipt-{n}.json")))
    except (OSError, ValueError):
        return None


reqs = (e2e or {}).get("requests") or []
reserved = {e.get("n"): e.get("reserved_msats") for e in msg(evs, "request reserved")}
settled = {e.get("n"): e.get("cost_msats") for e in msg(evs, "confidential ws: settled")}
aborted = [e.get("outcome") for e in msg(evs, "session aborted")]
ended = msg(evs, "http 2 connection ended")
charges = []  # what the key must have paid, in order
evidence = f"rc={rc}"


def check_settled(count):
    """Requests 1..count: 200, reserved, settled at the reported usage, receipt verified."""
    for r in reqs[:count]:
        n = r.get("n")
        rec = receipt(n) or {}
        want = usage_cost(rec, (rec.get("usage") or {}).get("usage")) if (rec.get("usage") or {}).get("usage") else None
        u = r.get("usage") or {}
        ru = (rec.get("usage") or {}).get("usage") or {}
        if r.get("status") != 200 or r.get("receipt_sig_ok") is not True:
            dev.append(f"request {n}: not a 200 with a verified receipt")
        elif (u.get("prompt_tokens"), u.get("completion_tokens")) != (ru.get("prompt_tokens"), ru.get("completion_tokens")):
            dev.append(f"request {n}: the receipt's usage is not the client's own")
        elif not (r.get("cost_msats") == rec.get("cost_msats") == settled.get(n) == want):
            dev.append(f"request {n}: charged {r.get('cost_msats')} (node log {settled.get(n)}), the usage at the signed rates is {want}")
        elif rec.get("http") != 2 or rec.get("n") != n:
            dev.append(f"request {n}: the receipt does not name http 2 and the request")
        elif reserved.get(n) != rec.get("reserved_msats") or not reserved.get(n):
            dev.append(f"request {n}: the node log shows no reservation of the receipt's {rec.get('reserved_msats')} msats")
        elif not ctx.get("v2_reserved"):
            dev.append("no v2 reservation to compare with")
        elif same_rates_as_v2() and reserved.get(n) != ctx["v2_reserved"]:
            dev.append(f"request {n}: reserved {reserved.get(n)}, a v2 setup reserves {ctx['v2_reserved']}")
        charges.append(r.get("cost_msats") or 0)
    if len(reqs) < count:
        dev.append(f"expected {count} settled request(s), the driver reports {len(reqs)}")
    if len({r.get("balance_msats") for r in reqs[:count]}) != min(count, len(reqs)) and any(charges):
        dev.append("the receipts' balances do not move with the charges")


def trace():
    return " ".join(
        f"[{r.get('n')}:{r.get('status')} reserved={reserved.get(r.get('n'))} cost={r.get('cost_msats')} balance={r.get('balance_msats')}]"
        for r in reqs
    )


if rc in (124, 137):
    dev.append(f"TIMEOUT (rc={rc})")
elif kind == "v2":
    ok = (rc == 0 and e2e and e2e.get("receipt_sig_ok") is True and e2e.get("usage_match") is True
          and e2e.get("cost_ok") is True and e2e.get("http") is None)
    if not ok:
        dev.append("the v2 session did not settle with a verified receipt")
    else:
        charges.append(e2e.get("cost_msats"))
        if settled.get(None) != e2e.get("cost_msats"):
            dev.append("the node log does not show the receipt's charge")
    evidence += f" cost={e2e and e2e.get('cost_msats')} reserved={e2e and e2e.get('reserved_msats')}"
elif kind == "no-funds":
    refusal = re.search(r"sidecar rejected: .*?\(node status (\d+)\)", both)
    evidence += f" refusal={refusal.group(0)[:160] if refusal else None} sidecar_sessions={ctx.get('sidecar_sessions')}"
    if rc == 0 or e2e:
        dev.append("the session was not refused")
    elif not refusal or refusal.group(1) != rest:
        dev.append(f"expected the node to refuse the setup with status {rest}")
    if sid or ctx.get("sidecar_sessions") != 0:
        dev.append("the sidecar was dialed for an unfunded credential")
    if reserved or settled:
        dev.append("something was reserved or settled")
elif kind == "settled":
    n = int(rest)
    evidence += " " + trace()
    if rc != 0 or not e2e or e2e.get("http") != 2:
        dev.append("no http: 2 result")
    else:
        check_settled(n)
        if len(reqs) != n or [r.get("stream") for r in reqs] != [2 * i + 3 for i in range(n)]:
            dev.append(f"expected {n} requests on streams 3, 5, ...")
        if sorted(reserved) != list(range(1, n + 1)) or len({e.get("sid") for e in msg(evs, "request reserved")}) != 1:
            dev.append(f"the node log does not show {n} reservations on one connection")
        if not ended or ended[-1].get("requests") != n or ended[-1].get("settled") != n:
            dev.append(f"the node did not end one connection with {n} settled requests")
        if ctx.get("sidecar_sessions") != 1:
            dev.append(f"the sidecar ran {ctx.get('sidecar_sessions')} sessions, not one")
        if aborted:
            dev.append(f"a reservation was finalized by an abort ({aborted})")
elif kind == "error":
    n, status = (int(x) for x in rest.split(":"))
    evidence += " " + trace()
    if rc != 0 or not e2e or e2e.get("http") != 2:
        dev.append("no http: 2 result")
    else:
        check_settled(n - 1)
        last = reqs[-1] if len(reqs) == n else {}
        rec = receipt(n) or {}
        # v2's rule for an error head: a 4xx the provider answers before any
        # inference keeps at most a fee; with no fee the reservation is released.
        fee = max(int(offer.get("session_fee_msat") or 0), int(offer.get("abandon_fee_msat") or 0))
        if last.get("status") != status or last.get("receipt_sig_ok") is not True:
            dev.append(f"expected request {n} to end in a disclosed {status} with a verified receipt")
        elif (rec.get("usage") or {}).get("error_status") != status or rec.get("n") != n:
            dev.append("the error receipt does not name the request and its status")
        elif not any(p.get("purpose") == "error_head" for p in last.get("proofs", [])):
            dev.append("the error was not settled by an error-head proof")
        elif not reserved.get(n):
            dev.append(f"request {n} was not reserved")
        elif last.get("cost_msats") != settled.get(n) or last.get("cost_msats", 1) > fee:
            dev.append(f"request {n}: charged {last.get('cost_msats')} for a {status} (at most the fee, {fee})")
        charges.append(last.get("cost_msats") or 0)
        if aborted:
            dev.append(f"a reservation was finalized by an abort ({aborted})")
elif kind == "node-refused":
    n, _, reason = rest.partition(":")
    n = int(n)
    refusal = re.search(r"sidecar rejected: (.*?)\(node status (\d+)\)", both)
    evidence += f" refusal={refusal.group(0)[:160] if refusal else None}"
    # The driver stops at the refusal, so the earlier requests are judged from
    # the node's log and their receipts.
    for k in range(1, n):
        rec = receipt(k) or {}
        ru = (rec.get("usage") or {}).get("usage")
        if not ru or rec.get("cost_msats") != settled.get(k) or settled.get(k) != usage_cost(rec, ru):
            dev.append(f"request {k} did not settle at its reported usage")
        charges.append(settled.get(k) or 0)
    if rc == 0:
        dev.append("the driver exited 0")
    if not refusal or not re.search(reason, refusal.group(1), re.I):
        dev.append(f"request {n} was not refused by the node for /{reason}/")
    if n in reserved or n in settled:
        dev.append(f"the node reserved or settled the refused request {n}")
    if aborted:
        dev.append(f"a reservation was finalized by an abort ({aborted})")
    evidence += f" reserved={sorted(reserved)} settled={settled}"
else:  # released / charged: an attack on request n
    n, _, reason = rest.partition(":")
    n = int(n)
    evidence += f" {trace()} aborted={aborted} adv={json.dumps(adv)[:200] if adv else None}"
    if rc != 0 or not adv:
        dev.append("CRASH or attack not refused (driver exit != 0 or no ADV_H2 line)")
    elif adv.get("refused") is not True:
        dev.append("the attack was NOT refused")
    elif not re.search(reason, adv.get("reason", ""), re.I):
        dev.append(f"refused for the wrong reason (want /{reason}/)")
    check_settled(n - 1)
    if len(reqs) != n - 1:
        dev.append(f"expected {n - 1} honest request(s) before the attack")
    if not reserved.get(n):
        dev.append(f"request {n} was never reserved (the probe did not reach the node's billing)")
    if n in settled:
        dev.append(f"request {n} was settled with a receipt")
    if kind == "released":
        if adv and adv.get("body_released"):
            dev.append("the driver saw body_released for the attacked request")
        if aborted != ["released"]:
            dev.append(f"the attacked request's reservation was not released (node: {aborted})")
    else:
        if aborted != ["charged_reservation"]:
            dev.append(f"the withheld request's reservation was not charged (node: {aborted})")
        charges.append(reserved.get(n) or 0)

# The money outcome: the key paid exactly the charges above.
row = key_row()
if row is None:
    dev.append("the case's key is not in the node's database")
else:
    balance, still_reserved, spent = row
    want = ctx["start_balance"] - sum(c or 0 for c in charges)
    evidence += f" | db: start={ctx['start_balance']} charges={charges} balance={balance} reserved={still_reserved}"
    if still_reserved != 0:
        dev.append(f"{still_reserved} msats are still reserved")
    if balance != want or spent != sum(c or 0 for c in charges):
        dev.append(f"balance {balance} (spent {spent}), expected {want}")
print(("PASS" if not dev else "DEVIATION: " + "; ".join(dev)) + "\t" + evidence)
