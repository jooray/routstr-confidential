import json, sys, urllib.request, os
sys.path.insert(0, os.path.dirname(__file__)); import prov
keys = prov.all_keys(); p = sys.argv[1]; host, path = sys.argv[2], sys.argv[3]
b = prov.bearer(p, keys[p])
req = urllib.request.Request(f"https://{host}{path}", headers={"Authorization": "Bearer " + b, "User-Agent": "provider-check"})
try:
    r = urllib.request.urlopen(req, timeout=30); body = r.read().decode(); st = r.status
except urllib.error.HTTPError as e:
    st, body = e.code, e.read().decode()
j = json.loads(body) if body.startswith(("{","[")) else body
expr = sys.argv[4] if len(sys.argv) > 4 else "j"
out = eval(expr)
print(st, prov.scrub(out if isinstance(out, str) else json.dumps(out, indent=None)[:20000], list(keys.values())))
