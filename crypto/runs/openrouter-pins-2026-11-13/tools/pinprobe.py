"""pinprobe.py: does an OpenRouter chat suffix pin win against the private part, and what did OpenRouter charge?

Each case sends one request built as the protocol builds it: "{" + private part + canonical
suffix (docs/CHAT-SUFFIX.md rendering of model, caps and the fixed pins), over HTTPS/1.1 with
the sidecar's head (Content-Length, Connection: close). It reads the SSE stream (the usage
event and its `cost`), then OpenRouter's generation record (/api/v1/generation?id=...) for
the charged total, the provider, the model and the search count, and compares the charge
with the token counts at the pinned model's catalogue rates (what the node bills, before its
provider fee).

  pinprobe.py <cases.json> <out.jsonl> [case ids...]

cases.json: [{"id", "model", "private": "<JSON members>", "pins": [[k, v], ...] (default
offer pins), "max_tokens": 20, "note"}]. The key: FreeLLMAPI's OpenRouter key, decrypted in
memory (../../providers-2026-11-12/tools/prov.py); it goes only to openrouter.ai and never to
disk; output is scrubbed. A running spend total is printed and stored with each record.
"""
import http.client, json, os, ssl, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "providers-2026-11-12", "tools"))
import prov  # noqa: E402

HOST = "openrouter.ai"
BASE_PINS = [["n", 1], ["stream", True], ["stream_options", {"include_usage": True}]]
CAPS = ["max_tokens", "max_completion_tokens"]


def J(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def suffix(model, cap, pins):
    parts = ['"model":' + J(model)] + [J(k) + ":" + str(cap) for k in CAPS] + [J(k) + ":" + J(v) for k, v in pins]
    return "," + ",".join(parts) + "}"


def catalogue():
    with urllib.request.urlopen("https://openrouter.ai/api/v1/models", timeout=60) as r:
        return {m["id"]: m for m in json.load(r)["data"]}


def post(key, body: bytes):
    ctx = ssl.create_default_context()
    c = http.client.HTTPSConnection(HOST, 443, timeout=180, context=ctx)
    c.putrequest("POST", "/api/v1/chat/completions", skip_host=True, skip_accept_encoding=True)
    for k, v in (("Host", HOST), ("Authorization", "Bearer " + key), ("Content-Type", "application/json"),
                 ("Accept-Encoding", "identity"), ("Connection", "close"), ("Content-Length", str(len(body)))):
        c.putheader(k, v)
    c.endheaders()
    c.send(body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data.decode("utf-8", "replace")


def get(key, path):
    ctx = ssl.create_default_context()
    c = http.client.HTTPSConnection(HOST, 443, timeout=60, context=ctx)
    c.request("GET", path, headers={"Authorization": "Bearer " + key})
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    c.close()
    return r.status, data


def sse(text):
    evs = []
    for block in text.split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data: ") and line[6:].strip() != "[DONE]":
                try:
                    evs.append(json.loads(line[6:]))
                except Exception:
                    pass
    return evs


def generation(key, gid):
    for i in range(12):
        time.sleep(1.5 if i < 4 else 4)
        st, txt = get(key, "/api/v1/generation?id=" + gid)
        if st == 200:
            return json.loads(txt).get("data")
    return None


def main():
    cases = json.load(open(sys.argv[1]))
    out = sys.argv[2]
    only = set(sys.argv[3:])
    key = prov.all_keys()["openrouter"]
    secrets = [key]
    cat = catalogue()
    spent = 0.0
    if os.path.exists(out):
        for line in open(out):
            try:
                spent += float(json.loads(line).get("charged_usd") or 0)
            except Exception:
                pass
    for c in cases:
        if only and c["id"] not in only:
            continue
        model = c["model"]
        pins = c.get("pins", BASE_PINS)
        cap = c.get("max_tokens", 20)
        body = "{" + c["private"] + suffix(model, cap, pins)
        json.loads(body)  # must parse (duplicates allowed by Python: last wins)
        t0 = time.time()
        st, txt = post(key, body.encode())
        evs = sse(txt)
        rec = {"id": c["id"], "note": c.get("note", ""), "model": model, "body": body if len(body) < 4000 else body[:1500] + f"...<{len(body)} bytes>...", "status": st,
               "secs": round(time.time() - t0, 2)}
        if st != 200 or not evs:
            rec["error"] = prov.scrub(txt[:800], secrets)
        usage = next((e["usage"] for e in reversed(evs) if isinstance(e.get("usage"), dict)), None)
        rec["usage"] = usage
        rec["served_models"] = sorted({e.get("model") for e in evs if e.get("model")})
        rec["providers"] = sorted({e.get("provider") for e in evs if e.get("provider")})
        text = "".join((ch.get("delta") or {}).get("content") or "" for e in evs for ch in (e.get("choices") or []))
        rec["text"] = text[:300]
        rec["images_in_stream"] = sum(len((ch.get("delta") or {}).get("images") or []) for e in evs for ch in (e.get("choices") or []))
        rec["annotations"] = sum(len((ch.get("delta") or {}).get("annotations") or []) for e in evs for ch in (e.get("choices") or []))
        dbg = [e.get("debug") for e in evs if e.get("debug")]
        if dbg:
            rec["debug_upstream_body"] = prov.scrub(json.dumps(dbg[0])[:3000], secrets)
        gid = next((e.get("id") for e in evs if e.get("id")), None)
        rec["gen_id"] = gid
        g = generation(key, gid) if gid and st == 200 else None
        if g:
            rec["generation"] = {k: g.get(k) for k in ("model", "provider_name", "total_cost", "usage", "upstream_inference_cost", "cache_discount",
                                                     "tokens_prompt", "tokens_completion", "native_tokens_prompt", "native_tokens_completion",
                                                     "native_tokens_reasoning", "native_tokens_cached", "native_tokens_completion_images",
                                                     "num_search_results", "num_media_prompt", "num_media_completion", "is_byok",
                                                     "web_search_engine", "router", "service_tier", "finish_reason", "api_type")}
        # The stream's usage.cost covers every inner generation of a server-tool loop; the
        # generation record of the first id can be the loop's wrapper (total_cost 0).
        costs = [float(x) for x in ((g or {}).get("total_cost"), (usage or {}).get("cost")) if x is not None]
        charged = max(costs) if costs else None
        rec["charged_usd"] = charged
        m = cat.get(model)
        if usage and m:
            p, q = float(m["pricing"]["prompt"]), float(m["pricing"]["completion"])
            pt, ct = usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
            det = usage.get("prompt_tokens_details") or {}
            cr = float(m["pricing"].get("input_cache_read") or p)
            cw = float(m["pricing"].get("input_cache_write") or p)
            cached, written = det.get("cached_tokens") or 0, det.get("cache_write_tokens") or 0
            rate_usd = p * (pt - cached - written) + cr * cached + cw * written + q * ct
            rec["node_rate_usd"] = rate_usd
            rec["ratio_charged_over_rate"] = round(charged / rate_usd, 3) if charged and rate_usd else None
        spent += charged or 0.0
        rec["spent_total_usd"] = round(spent, 6)
        line = prov.scrub(json.dumps(rec), secrets)
        assert not prov.contains(line, secrets)
        with open(out, "a") as f:
            f.write(line + "\n")
        print(f"{c['id']}: {st} served={rec['served_models']} prov={rec['providers']} usage={json.dumps(usage)[:260] if usage else None} "
              f"gen={json.dumps(rec.get('generation'))[:400] if g else None} charged={charged} rate={rec.get('node_rate_usd')} "
              f"ratio={rec.get('ratio_charged_over_rate')} spent={spent:.6f} {('ERR ' + rec['error'][:300]) if 'error' in rec else ''}")
        sys.stdout.flush()
        if spent > 0.9:
            print("STOP: spend above $0.90")
            break


if __name__ == "__main__":
    main()
