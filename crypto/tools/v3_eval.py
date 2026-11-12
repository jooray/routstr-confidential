"""Evaluate one case of v3-check.sh. Prints "VERDICT<TAB>evidence".

Arguments: case expect driver_rc driver_out driver_err sidecar_runs_dir
`expect` is one of (H is the framing, "2" or "1.1"):
  settled:H:<n>          n requests, each a 200 with a verified receipt (framing "2": on one
                         connection, streams 3, 5, ...; framing "1.1": one connection each, closed `done`)
  error:H:<n>:<status>   n requests; the last one a disclosed error head with that status,
                         the connection closed `error_settled`
  big:H:<records>        one 200 whose body of more than 65 536 bytes went in at least that many records
  image:H:<n>            n image requests, each a 200 whose body holds the images asked for,
                         accepted and settled flat, with no usage proof
  armed:H                one 200 on a connection that was armed first (no provider connection
                         before the request was claimed)
  decoy:H:<model>        one settled 200 whose private part named another model: the provider
                         ran the pinned one (it reports it in its usage event)
  refusedfirst:H         a refused request, then a settled one on the same connection with the same n
  auto:H:<yes|no>        `--http auto` settled one request on framing H, with (yes) or without (no)
                         the fallback from "2"
  nohttp2                `--http 2` is refused before any setup: the offer no longer lists "2"
  refused:H:<n>:<regex>  the attack on request n is refused by the sidecar (an `error` frame) for
                         that reason; the attacked request never reaches the provider complete
                         (n = 0: the attack is on the connection, before any request)
  withheld:H:<n>         the client never proves its records: the sidecar holds them, the provider
                         answers nothing
  replay:<n>:<regex>     (framing "2") the stale disclosure for request n is refused for that
                         reason; request n is never settled
  legacy                 a protocol-v2 setup is answered with `upgrade_required`
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
adv = tagged("ADV")
sids = re.findall(r"\bsid=([0-9a-f]{64})", out)


def sidecar_events(sid):
    """The sidecar's own log of a connection (written when it ends)."""
    if not sid:
        return None
    path = os.path.join(runs, sid, "sidecar.jsonl")
    for _ in range(50):
        if os.path.exists(path):
            return [json.loads(l).get("ev", "") for l in open(path) if l.strip()]
        time.sleep(0.1)
    return None


def reached_provider(http, n, evs):
    """The attacked request was written to the provider in full (or, framing "2", at all)."""
    if http == "2":
        return any(e.startswith(f"request n={n} first record written") or e.startswith(f"request n={n} released") for e in evs)
    return any("final body record released" in e for e in evs)


kind, _, rest = expect.partition(":")
evidence = f"rc={rc}"
reqs = (e2e or {}).get("requests") or []
conns = (e2e or {}).get("connections") or []


def req_line():
    return " ".join(
        f"[{r.get('http')}/{r.get('n')}:{r.get('status')} {r.get('mode')} rel={r.get('released_ms')}ms ttft={r.get('ttft_ms')}ms rec={r.get('records')}]" for r in reqs
    )


def honest(http, n):
    """n settled requests on framing `http`, every receipt verified, the framing named everywhere."""
    if rc != 0 or not e2e or e2e.get("protocol") != 3:
        dev.append("no protocol-v3 result (driver exit != 0 or no E2E_JSON)")
        return False
    if len(reqs) != n:
        dev.append(f"expected {n} request(s), got {len(reqs)}")
        return False
    if any(r.get("http") != http for r in reqs) or any(c.get("http") != http for c in conns[-1:]):
        dev.append(f"a request did not run on framing {http}")
    if any(r.get("receipt_sig_ok") is not True for r in reqs):
        dev.append("a receipt was not verified")
    return not dev


if rc in (124, 137):
    dev.append(f"TIMEOUT (rc={rc})")
elif kind == "legacy":
    leg = tagged("LEGACY_JSON")
    evidence += f" answer={json.dumps((leg or {}).get('answer'))[:200]}"
    if rc != 0 or not leg or leg.get("upgrade_required") is not True:
        dev.append("a v2-shaped setup was not answered with upgrade_required")
elif kind == "nohttp2":
    evidence += " " + (re.search(r"FAILED: .*", err) or [""])[0][:160]
    if rc == 0 or "offer_no_http2" not in err or sids:
        dev.append("--http 2 was not refused on the offer (before any setup)")
elif kind in ("settled", "error", "big", "image", "armed", "refusedfirst", "auto", "decoy"):
    # A model id may itself hold ":" (OpenRouter's `:free`): only the decoy names one, last.
    parts = rest.split(":", 1) if kind == "decoy" else rest.split(":")
    http = parts[0]
    evidence += " " + req_line()
    if kind == "settled":
        n = int(parts[1])
        if honest(http, n):
            if any(r.get("status") != 200 or not r.get("usage") for r in reqs):
                dev.append(f"expected {n} settled 200 requests")
            if http == "2" and ([r.get("stream") for r in reqs] != [2 * i + 3 for i in range(n)] or len(conns) != 1):
                dev.append("requests did not use streams 3, 5, ... on one connection")
            if http == "1.1" and (len(conns) != n or any((c.get("closed") or {}).get("reason") != "done" for c in conns)):
                dev.append("a framing-1.1 connection did not end with closed: done")
            if reqs and reqs[0].get("mode") != "cold" or any(r.get("mode") != ("open" if http == "2" else "cold") for r in reqs[1:]):
                dev.append("unexpected request modes")
    elif kind == "error":
        n, status = int(parts[1]), int(parts[2])
        if honest(http, n):
            if reqs[-1].get("status") != status or any(r.get("status") != 200 for r in reqs[:-1]):
                dev.append(f"expected {n} requests, the last one a disclosed {status}")
            elif not any(p.get("purpose") == "error_head" for p in reqs[-1].get("proofs", [])):
                dev.append("the error was not settled by an error-head proof")
            elif (e2e.get("closed") or {}).get("reason") != "error_settled":
                dev.append(f"the connection did not end with closed: error_settled (got {e2e.get('closed')})")
    elif kind == "big":
        if honest(http, 1):
            if reqs[0].get("status") != 200 or reqs[0].get("records", 0) < int(parts[1]):
                dev.append(f"expected one 200 request in at least {parts[1]} records")
            elif reqs[0].get("body_len", 0) <= 65536:
                dev.append("the body does not exceed 65 536 bytes")
    elif kind == "image":
        n = int(parts[1])
        evidence += " " + " ".join(f"[images={r.get('images')}/{r.get('count')} bytes={r.get('response_bytes')} total={r.get('total_ms')}ms]" for r in reqs)
        if honest(http, n):
            evs = sidecar_events(e2e.get("sid")) or []
            if any(r.get("status") != 200 or r.get("kind") != "images" for r in reqs):
                dev.append(f"expected {n} image request(s) with status 200")
            elif any(r.get("images") != r.get("count") or not r.get("response_bytes") or r.get("warnings") for r in reqs):
                dev.append("a response does not hold the images asked for")
            elif any(p.get("proof") == "pi_c3s" for r in reqs for p in r.get("proofs", [])):
                dev.append("an image request ran a usage proof")
            elif not any("flat" in e for e in evs):
                dev.append("the sidecar did not settle the image request flat on accept")
    elif kind == "armed":
        m = re.search(r"^ARMED sid=([0-9a-f]{64}) http=(\S+)", out, re.M)
        if honest(http, 1):
            if reqs[0].get("status") != 200 or reqs[0].get("mode") != "armed" or not m or m.group(2) != http:
                dev.append("the request did not run on an armed connection")
            else:
                evs = sidecar_events(m.group(1)) or []
                setup = next((e for e in evs if e.startswith("setup ")), "")
                evidence += f" [{setup[-40:]}]"
                if "armed=true" not in setup:
                    dev.append("the sidecar did not see an armed setup")
    elif kind == "decoy":
        if honest(http, 1):
            evidence += f" reported_model={reqs[0].get('reported_model')}"
            if reqs[0].get("status") != 200 or reqs[0].get("reported_model") != parts[1] or reqs[0].get("model") != parts[1]:
                dev.append("the provider did not run the pinned model")
    elif kind == "refusedfirst":
        if honest(http, 1):
            rf = reqs[0].get("refused_first") or {}
            evidence += f" refused_first={json.dumps(rf)[:140]}"
            if reqs[0].get("status") != 200 or reqs[0].get("n") != 1 or not (400 <= rf.get("status", 0) < 500):
                dev.append("expected a refused request, then a settled request 1 on the same connection")
            elif len(conns) != 1:
                dev.append("the good request ran on another connection")
    else:  # auto
        want_fb = parts[1] == "yes"
        fb = (e2e or {}).get("fallback")
        evidence += f" fallback={json.dumps(fb)[:200] if fb else None}"
        if honest(http, 1):
            if reqs[0].get("status") != 200:
                dev.append("the request did not settle")
            if want_fb and not (fb and fb.get("from") == "2" and fb.get("to") == "1.1"):
                dev.append("expected the fallback from framing 2 to 1.1")
            if not want_fb and fb:
                dev.append("an unexpected fallback")
elif kind in ("refused", "withheld"):
    http, n, *more = rest.split(":", 2)
    n = int(n)
    reason = more[0] if more else ""
    evidence += f" adv={json.dumps(adv)[:300] if adv else None}"
    sid = sids[-1] if sids else None
    evs = sidecar_events(sid)
    if rc != 0 or not adv:
        dev.append("CRASH or attack not refused (driver exit != 0 or no ADV line)")
    elif adv.get("refused") is not True:
        dev.append("the attack was NOT refused")
    elif adv.get("http") != http:
        dev.append(f"the attack did not run on framing {http}")
    elif kind == "refused" and not re.search(reason, f"{adv.get('reason', '')} {adv.get('code') or ''}", re.I):
        dev.append(f"refused for the wrong reason (want /{reason}/)")
    if http == "2" and n > 0 and e2e and len(reqs) != n - 1:
        dev.append(f"expected {n - 1} honest request(s) before the attack")
    if evs is None:
        # The sidecar keeps no log of a connection that ended before its handshake.
        if n > 0:
            dev.append("no sidecar log for the connection")
    elif n > 0:
        if adv and adv.get("body_released"):
            dev.append("the driver saw body_released for the attacked request")
        if reached_provider(http, n, evs):
            dev.append(f"request {n} reached the provider")
        if not any(e.startswith(f"request n={n} ") for e in evs):
            dev.append(f"the sidecar never saw request {n} (wrong check fired)")
    elif any(e.startswith("request n=") for e in evs) and http == "2":
        dev.append("a request was opened on the attacked connection")
    elif any(e.startswith("credential_written") for e in evs) and "early-record" not in case:
        dev.append("the head with the credential was written on the attacked connection")
elif kind == "replay":
    n, _, reason = rest.partition(":")
    n = int(n)
    evs = sidecar_events(sids[-1] if sids else None)
    evidence += f" adv={json.dumps(adv)[:260] if adv else None}"
    if rc != 0 or not adv:
        dev.append("CRASH or attack not refused (driver exit != 0 or no ADV line)")
    elif adv.get("refused") is not True:
        dev.append("the attack was NOT refused")
    elif not re.search(reason, adv.get("reason", ""), re.I):
        dev.append(f"refused for the wrong reason (want /{reason}/)")
    if e2e and len(reqs) != n - 1:
        dev.append(f"expected {n - 1} honest request(s) before the attack")
    if evs is None:
        dev.append("no sidecar log for the connection")
    else:  # the request itself is honest and released; its settlement is what is refused
        if any(e.startswith(f"request n={n} settled") or e.startswith(f"attestation n={n} ") for e in evs):
            dev.append(f"request {n} was attested or settled on the stale disclosure")
        if not any(e.startswith(f"request n={n} released") for e in evs):
            dev.append(f"request {n} was never released (the probe did not reach the disclosure check)")
else:
    dev.append(f"unknown expectation {expect}")
print(("PASS" if not dev else "DEVIATION: " + "; ".join(dev)) + "\t" + evidence)
