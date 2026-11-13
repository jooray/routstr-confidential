"""orcost.py <v3-node-check OUT dir> [--fee F] [--session-fee MSAT] [cases...]: what OpenRouter charged
for each request of a v3-node-check.sh run, against what the node charged for it.

For every case's sessions (sid= in <case>.out) it reads the client's plaintext response
(client-runs/<sid>/response-<n>.txt: the generation id and the usage event's `cost`) and the
node's signed receipt (receipt-<n>.json: `cost_msats`), asks OpenRouter for the generation
record (/api/v1/generation?id=..., its `total_cost`), and converts the node's charge to USD
at the exchange rate the node priced the model with: USD per msat = the model's catalogue
prompt price x the provider fee / the signed offer's `in` rate per token.

  node_usage = the charge less the session fee where this request paid it (the first
  settlement of the connection); verdict OK when OpenRouter's cost <= node_usage in USD
  (the node never pays more for the request than it bills for the tokens), FEE when it is
  covered only with the session fee, LOSS otherwise.

The key is read in memory (prov.py) and sent only to openrouter.ai; nothing secret is written.
"""
import glob, json, os, re, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pinprobe  # noqa: E402

args = sys.argv[1:]
out = args.pop(0)
fee = 1.06
sfee = 3000
if "--fee" in args:
    i = args.index("--fee"); fee = float(args[i + 1]); del args[i:i + 2]
if "--session-fee" in args:
    i = args.index("--session-fee"); sfee = int(args[i + 1]); del args[i:i + 2]
only = set(args)
key = pinprobe.prov.all_keys()["openrouter"]
with urllib.request.urlopen("https://openrouter.ai/api/v1/models", timeout=60) as r:
    cat = {m["id"]: m for m in json.load(r)["data"]}
rows = []
for f in sorted(glob.glob(os.path.join(out, "*.out"))):
    case = os.path.basename(f)[:-4]
    if only and case not in only:
        continue
    text = open(f, errors="replace").read()
    sids = list(dict.fromkeys(re.findall(r"\bsid=([0-9a-f]{64})", text)))
    try:
        offer = json.load(open(os.path.join(out, case + ".offer.json")))
    except Exception:
        continue
    for sid in sids:
        d = os.path.join(out, "client-runs", sid)
        first = True
        for rf in sorted(glob.glob(os.path.join(d, "receipt-*.json")), key=lambda p: int(re.findall(r"(\d+)", os.path.basename(p))[0])):
            n = int(re.findall(r"(\d+)", os.path.basename(rf))[0])
            rec = json.load(open(rf))
            charge = rec.get("cost_msats")
            model = rec.get("model")
            resp = os.path.join(d, f"response-{n}.txt")
            body = open(resp, errors="replace").read() if os.path.exists(resp) else ""
            evs = pinprobe.sse(body)
            gid = next((e.get("id") for e in evs if isinstance(e.get("id"), str) and e["id"].startswith("gen-")), None)
            usage = next((e["usage"] for e in reversed(evs) if isinstance(e.get("usage"), dict)), {}) or {}
            g = pinprobe.generation(pinprobe.prov.all_keys()["openrouter"], gid) if gid else None
            costs = [float(x) for x in ((g or {}).get("total_cost"), usage.get("cost")) if x is not None]
            or_cost = max(costs) if costs else None
            pinned = (offer.get("upstream_models") or {}).get(model, model)
            rates = (offer.get("price_list") or {}).get(model) or {}
            cm = cat.get(pinned)
            usd_per_msat = None
            if cm and rates.get("in"):
                usd_per_msat = float(cm["pricing"]["prompt"]) * fee / (rates["in"] / 1000.0)
            paid_fee = sfee if (first and isinstance(charge, int) and charge >= sfee and (rec.get("usage") or {}).get("error_status") is None) else 0
            node_usage = (charge - paid_fee) if isinstance(charge, int) else None
            verdict = "-"
            if or_cost is not None and usd_per_msat and isinstance(charge, int):
                verdict = "OK" if or_cost <= node_usage * usd_per_msat + 1e-12 else ("FEE" if or_cost <= charge * usd_per_msat else "LOSS")
            rows.append(dict(case=case, n=n, sid=sid[:12], model=pinned, gen_id=gid, provider=(g or {}).get("provider_name"),
                             search_results=(g or {}).get("num_search_results"), prompt_tokens=usage.get("prompt_tokens"),
                             completion_tokens=usage.get("completion_tokens"), openrouter_usd=or_cost, node_charge_msat=charge,
                             node_usage_msat=node_usage, node_charge_usd=(charge * usd_per_msat if usd_per_msat and isinstance(charge, int) else None),
                             node_usage_usd=(node_usage * usd_per_msat if usd_per_msat and node_usage is not None else None),
                             usd_per_msat=usd_per_msat, verdict=verdict, receipt_usage=rec.get("usage")))
            first = False
print("case\tn\tmodel\tprovider\tsearch\tpt\tct\topenrouter_usd\tnode_usage_usd\tnode_charge_usd\tnode_charge_msat\tverdict")
for r in rows:
    fmt = lambda v: f"{v:.9f}" if isinstance(v, float) else str(v)
    print("\t".join(fmt(r[k]) for k in ("case", "n", "model", "provider", "search_results", "prompt_tokens", "completion_tokens",
                                       "openrouter_usd", "node_usage_usd", "node_charge_usd", "node_charge_msat", "verdict")))
json.dump(rows, open(os.path.join(out, "orcost.json"), "w"), indent=1)
total = sum(r["openrouter_usd"] or 0 for r in rows)
print(f"\nOpenRouter total for these requests: ${total:.6f}; usd_per_msat={rows[0]['usd_per_msat'] if rows else None}")
