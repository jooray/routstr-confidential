"""Evaluate one case of v3-h2-check.sh. Prints "VERDICT<TAB>evidence".

Arguments: case expect driver_rc driver_out driver_err sidecar_runs_dir
`expect` is one of:
  settled:<n>            n requests on one connection, each a 200 with a verified receipt
  error:<n>:<status>     n requests; the last one a disclosed error head with that status
  big:<records>          one 200 whose request went in at least that many records
  refused:<n>:<regex>    the attack on request n is refused by the sidecar for that
                         reason; request n never reaches the provider
  replay:<n>:<regex>     the stale disclosure for request n is refused for that reason;
                         request n is never settled
  v2                     a protocol v2 (HTTP/1.1) session settles
"""
import json
import os
import re
import sys
import time

case, expect, rc, out_f, err_f, runs = sys.argv[1:7]
rc = int(rc)
out = open(out_f, errors="replace").read()
err = open(err_f, errors="replace").read()
dev = []


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


def sidecar_events():
    """The sidecar's own log of the session (written when the session ends)."""
    if not sid:
        return None
    path = os.path.join(runs, sid, "sidecar.jsonl")
    for _ in range(50):
        if os.path.exists(path):
            return [json.loads(l).get("ev", "") for l in open(path) if l.strip()]
        time.sleep(0.1)
    return None


kind, _, rest = expect.partition(":")
evidence = f"rc={rc}"
if rc in (124, 137):
    dev.append(f"TIMEOUT (rc={rc})")
elif kind == "v2":
    ok = rc == 0 and e2e and e2e.get("receipt_sig_ok") is True and e2e.get("usage_match") is True and e2e.get("http") is None
    evidence += f" sig={e2e and e2e.get('receipt_sig_ok')} usage_match={e2e and e2e.get('usage_match')}"
    if not ok:
        dev.append("the v2 session did not settle with a verified receipt")
elif kind in ("settled", "error", "big"):
    reqs = (e2e or {}).get("requests") or []
    evidence += " " + " ".join(
        f"[{r.get('n')}:{r.get('status')} rel={r.get('released_ms')}ms ttft={r.get('ttft_ms')}ms rec={r.get('records')}]" for r in reqs
    )
    if rc != 0 or not e2e or e2e.get("http") != 2:
        dev.append("no http: 2 result")
    elif any(r.get("receipt_sig_ok") is not True for r in reqs):
        dev.append("a receipt was not verified")
    elif kind == "settled":
        n = int(rest)
        if len(reqs) != n or any(r.get("status") != 200 or not r.get("usage") for r in reqs):
            dev.append(f"expected {n} settled 200 requests on one connection")
        if [r.get("stream") for r in reqs] != [2 * i + 3 for i in range(len(reqs))]:
            dev.append("requests did not use streams 3, 5, ...")
    elif kind == "error":
        n, status = (int(x) for x in rest.split(":"))
        if len(reqs) != n or reqs[-1].get("status") != status or any(r.get("status") != 200 for r in reqs[:-1]):
            dev.append(f"expected {n} requests, the last one a disclosed {status}")
        elif not any(p.get("purpose") == "error_head" for p in reqs[-1].get("proofs", [])):
            dev.append("the error was not settled by an error-head proof")
    else:
        if len(reqs) != 1 or reqs[0].get("status") != 200 or reqs[0].get("records", 0) < int(rest):
            dev.append(f"expected one 200 request in at least {rest} records")
        elif reqs[0].get("body_len", 0) <= 65536:
            dev.append("the body does not exceed the provider's initial stream window")
else:
    n, _, reason = rest.partition(":")
    n = int(n)
    evs = sidecar_events()
    evidence += f" adv={json.dumps(adv)[:260] if adv else None}"
    if rc != 0 or not adv:
        dev.append("CRASH or attack not refused (driver exit != 0 or no ADV_H2 line)")
    elif adv.get("refused") is not True:
        dev.append("the attack was NOT refused")
    elif not re.search(reason, adv.get("reason", ""), re.I):
        dev.append(f"refused for the wrong reason (want /{reason}/)")
    if e2e and len(e2e.get("requests") or []) != n - 1:
        dev.append(f"expected {n - 1} honest request(s) before the attack")
    if evs is None:
        dev.append("no sidecar log for the session")
    elif kind == "refused":
        if adv and adv.get("body_released"):
            dev.append("the driver saw body_released for the attacked request")
        if any(e.startswith(f"request n={n} first record written") or e.startswith(f"request n={n} released") for e in evs):
            dev.append(f"a record of request {n} reached the provider")
        if not any(e.startswith(f"request n={n} ") for e in evs):
            dev.append(f"the sidecar never saw request {n} (wrong check fired)")
    else:  # replay: the request itself is honest and released; its settlement is what is refused
        if any(e.startswith(f"request n={n} settled") or e.startswith(f"attestation n={n} ") for e in evs):
            dev.append(f"request {n} was attested or settled on the stale disclosure")
        if not any(e.startswith(f"request n={n} released") for e in evs):
            dev.append(f"request {n} was never released (the probe did not reach the disclosure check)")
print(("PASS" if not dev else "DEVIATION: " + "; ".join(dev)) + "\t" + evidence)
