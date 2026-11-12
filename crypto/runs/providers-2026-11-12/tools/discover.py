"""Key shapes and /models of each provider (keys never printed)."""
import json, sys, urllib.request, urllib.error
sys.path.insert(0, __import__("os").path.dirname(__file__))
import prov

HOSTS = {
    "numes": ("api.numes.ai", "/api/v1/models"),
    "openrouter": ("openrouter.ai", "/api/v1/models"),
    "google": ("generativelanguage.googleapis.com", "/v1beta/openai/models"),
    "nvidia": ("integrate.api.nvidia.com", "/v1/models"),
    "cloudflare": ("api.cloudflare.com", "/client/v4/user/tokens/verify"),
    "unorouter": ("api.unorouter.com", "/v1/models"),
    "xkiro": ("api.xkiro.com", "/v1/models"),
}

keys = prov.all_keys()
secrets = list(keys.values()) + [prov.bearer(p, k) for p, k in keys.items()]
only = sys.argv[1:] or list(HOSTS)
for p in only:
    if p not in keys:
        print(p, "no key"); continue
    host, path = HOSTS[p]
    b = prov.bearer(p, keys[p])
    print(f"== {p}: bearer {prov.shape(b)}" + (" (stored as account:token)" if p == "cloudflare" else ""))
    if p == "cloudflare":
        acct = prov.cf_account(keys[p])
        secrets.append(acct)
        paths = [path, f"/client/v4/accounts/{acct}/tokens/verify", f"/client/v4/accounts/{acct}/ai/models/search?per_page=5"]
    else:
        paths = [path]
    for pth in paths:
        req = urllib.request.Request(f"https://{host}{pth}", headers={"Authorization": "Bearer " + b, "User-Agent": "provider-check"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                st, body = r.status, r.read().decode("utf8", "replace")
        except urllib.error.HTTPError as e:
            st, body = e.code, e.read().decode("utf8", "replace")
        except Exception as e:
            st, body = 0, repr(e)
        shown = pth.replace(acct, "<account>") if p == "cloudflare" else pth
        print(f"  GET {shown} -> {st} ({len(body)} bytes)")
        try:
            j = json.loads(body)
        except Exception:
            print("  ", prov.scrub(body[:200], secrets)); continue
        data = j.get("data") if isinstance(j, dict) else None
        if isinstance(data, list):
            ids = [m.get("id") for m in data]
            free = [m.get("id") for m in data if ":free" in str(m.get("id")) or (isinstance(m.get("pricing"), dict) and all(str(v) in ("0", "0.0", "0.00", "") for v in m["pricing"].values() if not isinstance(v, dict)))]
            print(f"  {len(ids)} models; free-looking ({len(free)}): {free[:40]}")
            if p == "numes":
                for m in data:
                    if "kimi" in m.get("id", "") or m.get("id") in free[:10]:
                        print("   ", prov.scrub(json.dumps({k: m.get(k) for k in ("id", "pricing", "context_length", "architecture", "supported_parameters", "free", "tier")})[:600], secrets))
        else:
            print("  ", prov.scrub(json.dumps(j)[:300], secrets))
