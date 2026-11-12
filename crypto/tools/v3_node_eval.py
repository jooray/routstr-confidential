"""Evaluate one case of v3-node-check.sh. Prints "VERDICT<TAB>evidence".

Arguments: case expect driver_rc driver_out driver_err context.json

The context names the node's database and log, the case's own credential (a
fresh key per case, so the key's row is the case's whole money outcome), the
signed offer as fetched before and after the case (rates follow the exchange
rate), the node's model list (context lengths), the client's run directory and
how many two-party handshakes the sidecar ran during the case.

The node under test charges a session fee F, an abandon fee A (>= F) and a
connection deposit D, all non-zero and different, so that every rule shows in
the arithmetic. `expect` is one of (H is the framing, "2" or "1.1"):

  settled:H:<kinds>[:<flags>]   requests of these kinds (`chat`, `images`, comma-separated), each
                                reserved and settled: chat at the usage the provider reported at the
                                signed rates, an image at the signed price x count; the session fee F
                                with the first settlement of each connection only; the deposit
                                released by that settlement. Framing "2": one connection; "1.1": one
                                connection per request. Flags (comma-separated):
                                  armed      the first connection was armed before its request
                                  big        a body of at least 200 kB
                                  idle       the node then closes the idle connection (`closed`, idle)
                                  refused400 a request the node refuses (400) came first, same n
                                  refused402 request 1 was refused with 402, the balance topped up,
                                             and the same request accepted on the same connection
                                  offerchanged  request 2 named a changed offer (409 offer_changed),
                                             then the connection's own offer, on the same connection
                                  fallback   a framing-"2" open failed first (deposit released,
                                             `provider_unreachable`) and the request ran on "1.1"
                                  nofallback no fallback happened
  error:H:<n>:<status>          requests 1..n-1 settle, request n ends in a disclosed error head:
                                429/503/401/402/403 cost F if still due, another 4xx A, another 5xx
                                the reservation; the connection closes `error_settled`
  node-refused:H:<n>:<status>:<regex>
                                the node refuses request n (`request_refused`) and the client
                                leaves: nothing was reserved for it; with n = 1 the connection ends
                                unused and the deposit is charged
  attack:H:<n>:<how>:<regex>    an attack on request n is refused for that reason. <how>:
                                  abandoned  before `body_released`: with n = 1 the deposit is charged
                                             (`request_abandoned`) and the reservation released in
                                             full; with n > 1 the abandon fee A is kept
                                  charged    after `body_released` (the settlement is refused): the
                                             reservation is charged in full
                                  unused     the connection itself (n = 0): the deposit is charged
  unused:<reason>[:anyrc]       a connection is opened and ends without a request: the deposit is
                                charged for that reason (`unused`, `idle`, `setup_timeout`)
  released:<reason>[:anyrc]     a connection that could not be used through no fault of the client:
                                the deposit is released for that reason, signed, nothing is charged
                                (`provider_unreachable`, `sidecar_failure`, `not_started`)
  received:H                    request 1 is written in full and the client disappears: the
                                reservation is charged, the deposit released (`request_received`)
  setup-refused:<status>:<regex>  the setup is refused before the sidecar is dialed: nothing reserved
  legacy                        a protocol-v2 socket gets `error` 426 `upgrade_required`
In every case the key's balance must equal its start (plus any top-up) minus
exactly the charges named above, with nothing left reserved.
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
REFUSALS = {401, 402, 403, 429, 503}


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
legacy = tagged("LEGACY_JSON")
sids = list(dict.fromkeys(re.findall(r"\bsid=([0-9a-f]{64})", out)))
offers = [json.load(open(p)) for p in ctx["offers"] if os.path.exists(p)]
offer = offers[0]
FEE = int(offer.get("session_fee_msat") or 0)
ABANDON = max(int(offer.get("abandon_fee_msat") or 0), FEE)
DEP = int(offer.get("connection_deposit_msat") or 0)
MARGIN = int(offer.get("reserve_margin_tokens") or 0)
IDLE = int(offer.get("idle_timeout_s") or 0)
if not (FEE > 0 and ABANDON > FEE and DEP > 0 and DEP not in (FEE, ABANDON)):
    dev.append(f"the node's fees do not show in the arithmetic (F={FEE} A={ABANDON} D={DEP})")


def node_events():
    """The node's confidential_ws log lines since the case began."""
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
        if j.get("name") == "routstr.confidential_ws":
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


def msg(evs, text, sid=None):
    return [e for e in evs if text in e.get("message", "") and (sid is None or e.get("sid") == sid[:12])]


def deposit_events(evs):
    return [
        (e["message"].rsplit(" ", 1)[1], e.get("reason"), e.get("deposit_msat"), e.get("sid") or "")
        for e in evs
        if e.get("message", "").startswith("confidential ws: connection deposit ")
        and e["message"].rsplit(" ", 1)[1] in ("charged", "released")
    ]


# The node decides an aborted request after the client is gone (it first hears
# the sidecar's last frames): wait until every connection of the case ended
# and every deposit it reserved has its outcome.
for _ in range(160):
    evs = node_events()
    row = key_row()
    opened = len(msg(evs, "connection deposit reserved"))
    if (row and row[1] == 0 and all(msg(evs, "connection ended", s) for s in sids)
            and len(deposit_events(evs)) >= opened):
        break
    time.sleep(0.25)

reserved = {}  # (sid12, n) -> [reserved_msats, …] (a request sent again is reserved again)
reserved_kind = {}
for e in msg(evs, "request reserved"):
    reserved.setdefault((e.get("sid"), e.get("n")), []).append(e.get("reserved_msats"))
    reserved_kind[(e.get("sid"), e.get("n"))] = e.get("kind")
settled = {(e.get("sid"), e.get("n")): e.get("cost_msats") for e in msg(evs, "confidential ws: settled")}
aborted = [e.get("outcome") for e in msg(evs, "session aborted")]
deposits = deposit_events(evs)
charges = []  # what the key must have paid, in order
reqs = (e2e or {}).get("requests") or []
conns = (e2e or {}).get("connections") or []


def deposit_of(sid):
    return [(o, r, m) for o, r, m, s in deposits if s == (sid or "")[:12]]


def receipt(sid, n):
    try:
        return json.load(open(os.path.join(ctx["client_runs"], sid or "-", f"receipt-{n}.json")))
    except (OSError, ValueError):
        return None


def context_length(model):
    for m in ctx.get("models") or []:
        if m.get("id") == model:
            top = (m.get("top_provider") or {}).get("context_length")
            return max(int(x) for x in (top, m.get("context_length")) if isinstance(x, int) and x > 0)
    return None


def chat_reservations(model, max_tokens):
    """What a chat request may reserve: a full-context prompt plus the cap
    (and the margin) at the signed rates, plus the larger fee; one value per
    offer seen during the case."""
    limit = context_length(model)
    outv = set()
    for o in offers:
        rates = (o.get("price_list") or {}).get(model)
        if not rates or not limit:
            continue
        bound = math.ceil((limit * max(rates["in"], rates.get("cache_write", 0.0)) + (max_tokens + MARGIN) * rates["out"]) / 1000)
        outv.add(bound + ABANDON)
    return outv


def usage_cost(rates, usage):
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
    return math.ceil(cost / 1000)


def image_variant(model, variant):
    for o in offers:
        for v in ((o.get("images") or {}).get("price_list") or {}).get(model, []):
            if v.get("id") == variant:
                return v
    return None


seen_first = set()  # connections whose first settlement was checked


def check_request(r, status=200):
    """One settled request: its reservation, its charge, its receipt, the
    node's log and the deposit. Appends the charge."""
    n, sid = r.get("n"), r.get("sid")
    tag = f"request {r.get('g', n)}"
    rec = receipt(sid, n) or {}
    first = sid not in seen_first
    seen_first.add(sid)
    fee = FEE if first else 0
    cost = r.get("cost_msats")
    res = reserved.get(((sid or "")[:12], n)) or []
    if r.get("status") != status or r.get("receipt_sig_ok") is not True:
        dev.append(f"{tag}: not a {status} with a verified receipt")
    if rec.get("http") != r.get("http") or rec.get("n") != n or rec.get("sid") != sid:
        dev.append(f"{tag}: the receipt does not name the connection, the framing and the request")
    if not (cost == rec.get("cost_msats") == settled.get(((sid or "")[:12], n))):
        dev.append(f"{tag}: the driver, the receipt and the node log disagree on the charge ({cost}, {rec.get('cost_msats')}, {settled.get(((sid or '')[:12], n))})")
    if not res or res[-1] != rec.get("reserved_msats"):
        dev.append(f"{tag}: the node log shows no reservation of the receipt's {rec.get('reserved_msats')} msat ({res})")
    # The session fee is named (and charged) with the connection's first settlement only.
    if int(rec.get("session_fee_msat") or 0) != fee:
        dev.append(f"{tag}: the receipt names a session fee of {rec.get('session_fee_msat')}, {fee} is due")
    if int(rec.get("abandon_fee_msat") or 0) != ABANDON:
        dev.append(f"{tag}: the receipt names an abandon fee of {rec.get('abandon_fee_msat')}")
    # The deposit goes back with the connection's first settlement, once.
    if rec.get("deposit_released_msat") != (DEP if first else None):
        dev.append(f"{tag}: deposit_released_msat is {rec.get('deposit_released_msat')}, first settlement: {first}")
    if r.get("kind") == "images":
        v = image_variant(r.get("model"), r.get("variant"))
        if not v:
            dev.append(f"{tag}: the signed offer has no variant {r.get('variant')} of {r.get('model')}")
            charges.append(cost or 0)
            return
        price = v["msat_per_image"] * r.get("count", 0)
        if (rec.get("kind"), rec.get("variant"), rec.get("count"), rec.get("msat_per_image")) != ("images", r.get("variant"), r.get("count"), v["msat_per_image"]):
            dev.append(f"{tag}: the receipt does not name the variant, the count and the signed price")
        if res and res[-1] != price + ABANDON:
            dev.append(f"{tag}: reserved {res[-1]}, an image request reserves {price} + {ABANDON}")
        if reserved_kind.get(((sid or "")[:12], n)) != "images":
            dev.append(f"{tag}: not reserved as an image request")
        if status == 200:
            if r.get("images") != r.get("count") or not r.get("response_bytes") or r.get("warnings"):
                dev.append(f"{tag}: the response does not hold the {r.get('count')} image(s) asked for")
            if (rec.get("usage") or {}).get("flat") is not True or cost != price + fee:
                dev.append(f"{tag}: charged {cost}, the signed price is {price} + fee {fee}")
            if any(p.get("proof") == "pi_c3s" for p in r.get("proofs", [])):
                dev.append(f"{tag}: an image request ran a usage proof")
    else:
        rates = rec.get("rates") or {}
        if rates not in [(o.get("price_list") or {}).get(rec.get("model")) for o in offers]:
            dev.append(f"{tag}: the receipt's rates are not the signed offer's")
        want_res = chat_reservations(r.get("model"), ctx["max_tokens"])
        if res and res[-1] not in want_res:
            dev.append(f"{tag}: reserved {res[-1]}, a full-context prompt plus the cap plus the abandon fee is {sorted(want_res)}")
        if status == 200:
            ru = (rec.get("usage") or {}).get("usage") or {}
            u = r.get("usage") or {}
            if not ru or (u.get("prompt_tokens"), u.get("completion_tokens")) != (ru.get("prompt_tokens"), ru.get("completion_tokens")):
                dev.append(f"{tag}: the receipt's usage is not the client's own")
            elif rates and cost != usage_cost(rates, ru) + fee:
                dev.append(f"{tag}: charged {cost}, the usage at the signed rates is {usage_cost(rates, ru)} + fee {fee}")
    if status != 200:
        if (rec.get("usage") or {}).get("error_status") != status:
            dev.append(f"{tag}: the receipt does not name the status {status}")
        if status in REFUSALS:
            want = fee
        elif status < 500:
            want = ABANDON
        else:
            want = rec.get("reserved_msats")
        if cost != want:
            dev.append(f"{tag}: charged {cost} for a {status}, the rule says {want}")
        if not any(p.get("purpose") == "error_head" for p in r.get("proofs", [])):
            dev.append(f"{tag}: the error was not settled by an error-head proof")
    if first and deposit_of(sid) != [("released", "request_settled", DEP)]:
        dev.append(f"{tag}: the deposit was not released by the connection's first settlement (node: {deposit_of(sid)})")
    charges.append(cost or 0)


def check_connections(http, n):
    """Framing "2": one connection for all n requests; "1.1": one each."""
    used = list(dict.fromkeys(r.get("sid") for r in reqs))
    want = 1 if http == "2" else n
    if len(used) != want or any(r.get("http") != http for r in reqs):
        dev.append(f"expected {want} framing-{http} connection(s), the requests ran on {len(used)}")
    for sid in used:
        mine = [r for r in reqs if r.get("sid") == sid]
        ended = msg(evs, "connection ended", sid)
        if not ended or ended[-1].get("requests") != len(mine) or ended[-1].get("http") != http:
            dev.append(f"the node did not end connection {sid[:8]} after {len(mine)} request(s) on framing {http}")
        if http == "2" and [r.get("stream") for r in mine] != [2 * i + 3 for i in range(len(mine))]:
            dev.append("expected streams 3, 5, …")
        c = next((c for c in conns if c.get("sid") == sid), {})
        dep = c.get("deposit") or {}
        if (dep.get("outcome"), dep.get("msat"), dep.get("signed")) != ("released", DEP, True):
            dev.append(f"the client did not see the deposit of {sid[:8]} released ({dep})")


def trace():
    return " ".join(
        f"[{r.get('g', r.get('n'))}:{r.get('http')}:{r.get('kind', 'chat')}:{r.get('status')}:{r.get('mode')} "
        f"reserved={r.get('reserved_msats')} cost={r.get('cost_msats')}]"
        for r in reqs
    )


def money():
    return f"F={FEE} A={ABANDON} D={DEP} deposit={[d[:2] for d in deposits]} aborted={aborted}"


evidence = f"rc={rc}"

if rc in (124,) or (rc == 137 and kind != "received"):
    dev.append(f"TIMEOUT (rc={rc})")
elif kind == "legacy":
    a = (legacy or {}).get("answer") or {}
    evidence += f" answer={json.dumps(a)[:200]}"
    if rc != 0 or not legacy or legacy.get("upgrade_required") is not True:
        dev.append("the v2 socket was not refused with upgrade_required")
    elif (a.get("type"), a.get("status"), a.get("reason"), a.get("min_v")) != ("error", 426, "upgrade_required", 3):
        dev.append("not the error frame of §11")
    if evs and (msg(evs, "deposit") or reserved):
        dev.append("something was reserved for a v2 socket")
elif kind == "setup-refused":
    status, _, reason = rest.partition(":")
    refusal = re.search(r"sidecar rejected: (.*?)\(node status (\d+)\)", both, re.S)
    evidence += f" refusal={refusal.group(0)[:200] if refusal else None} handshakes={ctx.get('handshakes')}"
    if rc == 0 or e2e:
        dev.append("the setup was not refused")
    elif not refusal or refusal.group(2) != status or not re.search(reason, refusal.group(1), re.I | re.S):
        dev.append(f"expected the node to refuse the setup with status {status} for /{reason}/")
    if sids or ctx.get("handshakes") != 0:
        dev.append("the sidecar was dialed for a setup the node had to refuse")
    if reserved or settled or deposits or msg(evs, "connection deposit reserved"):
        dev.append("something was reserved or settled")
elif kind == "unused":
    reason, _, flag = rest.partition(":")
    c = conns[-1] if conns else {}
    dep = c.get("deposit") or (e2e or {}).get("deposit") or {}
    told = re.search(r"deposit: outcome=(\w+) reason=(\w+) msat=(\d+) .*signed=(\w+)", out)
    evidence += f" {money()} told={told.group(0)[9:] if told else None}"
    if flag != "anyrc" and rc != 0:
        dev.append("the driver failed")
    if reqs:
        dev.append("a request was settled")
    if [d[:3] for d in deposits] != [("charged", reason, DEP)]:
        dev.append(f"the deposit was not charged for /{reason}/ (node: {deposits})")
    if reserved or settled or aborted:
        dev.append("a request was reserved or settled")
    if ctx.get("handshakes") != 1:
        dev.append(f"the sidecar ran {ctx.get('handshakes')} handshakes, not one")
    if reason in ("idle", "setup_timeout"):
        # The node ended the connection and said what became of the deposit, signed.
        if not told or told.groups() != ("charged", reason, str(DEP), "true"):
            dev.append("the client was not told, signed, that the deposit was charged")
    if reason == "idle":
        closed = (e2e or {}).get("closed") or {}
        if closed.get("reason") != "idle":
            dev.append(f"the node did not close the idle connection (closed: {closed})")
        elif not IDLE * 1000 - 3000 <= (closed.get("idle_ms") or 0) <= IDLE * 1000 + 8000:
            dev.append(f"closed after {closed.get('idle_ms')} ms, the offer's idle_timeout_s is {IDLE}")
    charges.append(DEP)
elif kind == "released":
    reason, _, flag = rest.partition(":")
    told = re.search(r"deposit: outcome=(\w+) reason=(\w+) msat=(\d+) .*signed=(\w+)", out)
    evidence += f" {money()} told={told.group(0)[9:] if told else None}"
    if flag != "anyrc" and rc != 0:
        dev.append("the driver failed")
    if [d[:3] for d in deposits] != [("released", reason, DEP)]:
        dev.append(f"the deposit was not released for /{reason}/ (node: {deposits})")
    if not told or told.groups() != ("released", reason, str(DEP), "true"):
        dev.append("the client was not told, signed, that the deposit was released")
    if reserved or settled or aborted or reqs:
        dev.append("a request was reserved or settled")
elif kind == "received":
    sid = sids[0] if sids else None
    res = reserved.get(((sid or "")[:12], 1)) or []
    evidence += f" {money()} reserved={res}"
    if not sid or not res:
        dev.append("request 1 was never reserved")
    if "<- body_released" not in err:
        dev.append("the client did not see body_released")
    if settled:
        dev.append("the request was settled")
    if aborted != ["charged_reservation"]:
        dev.append(f"the reservation was not charged (node: {aborted})")
    if deposit_of(sid) != [("released", "request_received", DEP)]:
        dev.append(f"the deposit was not released for /request_received/ (node: {deposits})")
    if res and res[-1] not in chat_reservations(ctx["model"], ctx["max_tokens"]):
        dev.append(f"reserved {res[-1]}, expected one of {sorted(chat_reservations(ctx['model'], ctx['max_tokens']))}")
    charges.append(res[-1] if res else 0)
elif kind == "settled":
    http, kinds, flags = (rest.split(":") + ["", ""])[:3]
    want_kinds = kinds.split(",")
    flags = set(filter(None, flags.split(",")))
    n = len(want_kinds)
    evidence += f" {trace()} {money()}"
    if rc != 0 or not e2e:
        dev.append("no result (driver exit != 0 or no E2E_JSON)")
    else:
        if [r.get("kind", "chat") for r in reqs] != want_kinds:
            dev.append(f"expected requests of kinds {want_kinds}, the driver reports {[r.get('kind', 'chat') for r in reqs]}")
        for r in reqs:
            check_request(r)
        check_connections(http, n)
        expected_handshakes = (1 if http == "2" else n) + (1 if "fallback" in flags else 0)
        if ctx.get("handshakes") != expected_handshakes:
            dev.append(f"the sidecar ran {ctx.get('handshakes')} handshakes, not {expected_handshakes}")
        if aborted:
            dev.append(f"a reservation was finalized by an abort ({aborted})")
        refusals = e2e.get("refusals") or []
        if http == "1.1" and any((c.get("closed") or {}).get("reason") != "done" for c in conns if c.get("requests")):
            dev.append("a framing-1.1 connection did not close with `done`")
        if "armed" in flags and (not reqs or reqs[0].get("mode") != "armed" or "ARMED sid=" not in out):
            dev.append("the first connection was not armed before its request")
        if "big" in flags and (not reqs or (reqs[0].get("body_len") or 0) < 200000 or (reqs[0].get("usage") or {}).get("prompt_tokens", 0) < 20000):
            dev.append("not a big body")
        if "idle" in flags:
            closed = e2e.get("closed") or {}
            evidence += f" closed={json.dumps(closed)}"
            if closed.get("reason") != "idle":
                dev.append(f"the node did not close the idle connection (closed: {closed})")
            elif not IDLE * 1000 - 3000 <= (closed.get("idle_ms") or 0) <= IDLE * 1000 + 8000:
                dev.append(f"closed after {closed.get('idle_ms')} ms, the offer's idle_timeout_s is {IDLE}")
        if "refused400" in flags:
            evidence += f" refused_first={bool(re.search(r'refused as expected: status=400', out))}"
            if not re.search(r"refused as expected: status=400", out):
                dev.append("no request was refused first")
            if any(len(v) != 1 for v in reserved.values()):
                dev.append("the refused request was reserved")
        if "refused402" in flags:
            evidence += f" refusals={json.dumps(refusals)[:160]} topup={ctx.get('topup')}"
            if [(x.get("n"), x.get("status")) for x in refusals] != [(1, 402)] or not ctx.get("topup"):
                dev.append("request 1 was not refused with 402 and sent again after a top-up")
            if any(len(v) != 1 for v in reserved.values()) or len(sids) != 1:
                dev.append("the refused request was reserved, or a second connection was opened")
            if ctx["start_balance"] < DEP + ABANDON or ctx["start_balance"] >= DEP + min(chat_reservations(ctx["model"], ctx["max_tokens"]) or {0}):
                dev.append("the starting balance must cover the deposit and not the reservation")
        if "offerchanged" in flags:
            evidence += f" refusals={json.dumps(refusals)[:200]}"
            if [(x.get("n"), x.get("status"), x.get("type")) for x in refusals] != [(2, 409, "offer_changed")]:
                dev.append("request 2 was not refused with offer_changed")
            if "naming the offer the connection was opened on" not in out or len(offers) < 2 or offers[0].get("sig") == offers[-1].get("sig"):
                dev.append("the offer did not change during the case")
            if any(len(v) != 1 for v in reserved.values()):
                dev.append("the refused request was reserved")
        fb = e2e.get("fallback")
        if "fallback" in flags:
            evidence += f" fallback={json.dumps(fb)[:200]}"
            first_sid = (fb or {}).get("sid")
            if not fb or fb.get("from") != "2" or fb.get("to") != "1.1" or fb.get("fault") != "upstream":
                dev.append("expected the fallback from framing 2 to 1.1 on an upstream fault")
            elif deposit_of(first_sid) != [("released", "provider_unreachable", DEP)]:
                dev.append(f"the failed framing-2 connection's deposit was not released (node: {deposits})")
        elif fb:
            dev.append("an unexpected fallback")
elif kind == "error":
    http, n, status = rest.split(":")
    n, status = int(n), int(status)
    evidence += f" {trace()} {money()}"
    if rc != 0 or not e2e:
        dev.append("no result (driver exit != 0 or no E2E_JSON)")
    elif len(reqs) != n:
        dev.append(f"expected {n} requests, the last one a disclosed {status}")
    else:
        for r in reqs[:-1]:
            check_request(r)
        check_request(reqs[-1], status)
        if (conns[-1].get("closed") or {}).get("reason") != "error_settled":
            dev.append("the connection did not close with `error_settled`")
        if aborted:
            dev.append(f"a reservation was finalized by an abort ({aborted})")
elif kind == "node-refused":
    http, n, status, reason = rest.split(":", 3)
    n = int(n)
    refusal = re.search(rf"request {n} refused: (.*?) \(status (\d+)\)", err, re.S)
    evidence += f" refusal={refusal.group(0)[:160] if refusal else None} {money()}"
    sid = sids[0] if sids else None
    if rc == 0:
        dev.append("the driver exited 0")
    if not refusal or refusal.group(2) != status or not re.search(reason, refusal.group(1), re.I | re.S):
        dev.append(f"request {n} was not refused by the node with {status} for /{reason}/")
    # The driver stops at the refusal: the earlier requests are judged from
    # their receipts and the node's log.
    for k in range(1, n):
        rec = receipt(sid, k) or {}
        check_request({"n": k, "sid": sid, "http": http, "status": 200, "receipt_sig_ok": True, "model": rec.get("model"),
                       "cost_msats": rec.get("cost_msats"), "usage": (rec.get("usage") or {}).get("usage")})
    if ((sid or "")[:12], n) in reserved or ((sid or "")[:12], n) in settled:
        dev.append(f"the node reserved or settled the refused request {n}")
    if aborted:
        dev.append(f"a reservation was finalized by an abort ({aborted})")
    if n == 1:
        if deposit_of(sid) != [("charged", "unused", DEP)]:
            dev.append(f"the unused connection's deposit was not charged (node: {deposits})")
        charges.append(DEP)
else:  # attack
    http, n, how, reason = rest.split(":", 3)
    n = int(n)
    sid = (adv or {}).get("sid") or (sids[-1] if sids else None)
    res = reserved.get(((sid or "")[:12], n)) or []
    evidence += f" {trace()} {money()} adv={json.dumps(adv)[:160] if adv else None}"
    if rc != 0 or not adv:
        dev.append("CRASH or attack not refused (driver exit != 0 or no ADV line)")
    elif adv.get("refused") is not True:
        dev.append("the attack was NOT refused")
    elif not re.search(reason, adv.get("reason", ""), re.I):
        dev.append(f"refused for the wrong reason (want /{reason}/)")
    if len(reqs) != max(n - 1, 0):
        dev.append(f"expected {max(n - 1, 0)} honest request(s) before the attack")
    for r in reqs:
        check_request(r)
    if ((sid or "")[:12], n) in settled:
        dev.append(f"request {n} was settled with a receipt")
    if how == "unused":
        if reserved or aborted:
            dev.append("a request was reserved")
        if [d[:3] for d in deposits] != [("charged", "unused", DEP)]:
            dev.append(f"the deposit was not charged (node: {deposits})")
        charges.append(DEP)
    else:
        if not res:
            dev.append(f"request {n} was never reserved (the attack did not reach the node's billing)")
        if how == "abandoned":
            if adv and adv.get("body_released"):
                dev.append("the driver saw body_released for the attacked request")
            if n == 1:
                # No settlement yet: the deposit is the price, the reservation goes back in full.
                if aborted != ["released"] or deposit_of(sid) != [("charged", "request_abandoned", DEP)]:
                    dev.append(f"expected the deposit charged and the reservation released (node: {deposits}, {aborted})")
                charges.append(DEP)
            else:
                if aborted != [f"charged_abandon_fee:{ABANDON}"]:
                    dev.append(f"the abandoned request did not keep the abandon fee (node: {aborted})")
                charges.append(ABANDON)
        else:
            if aborted != ["charged_reservation"]:
                dev.append(f"the withheld request's reservation was not charged (node: {aborted})")
            if n == 1 and deposit_of(sid) != [("released", "request_received", DEP)]:
                dev.append(f"the deposit was not released for /request_received/ (node: {deposits})")
            charges.append(res[-1] if res else 0)

# The money outcome: the key paid exactly the charges above.
row = key_row()
if row is None:
    dev.append("the case's key is not in the node's database")
else:
    balance, still_reserved, spent = row
    start = ctx["start_balance"] + int(ctx.get("topup") or 0)
    want = start - sum(c or 0 for c in charges)
    evidence += f" | db: start={start} charges={charges} balance={balance} reserved={still_reserved}"
    if still_reserved != 0:
        dev.append(f"{still_reserved} msats are still reserved")
    if balance != want or spent != sum(c or 0 for c in charges):
        dev.append(f"balance {balance} (spent {spent}), expected {want}")
print(("PASS" if not dev else "DEVIATION: " + "; ".join(dev)) + "\t" + evidence)
