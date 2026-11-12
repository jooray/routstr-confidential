"""imgprobe.py <provider> <host> <path> <json body>: one POST, status and a scrubbed snippet."""
import json, os, sys, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import prov
p, host, path, body = sys.argv[1:5]
keys = prov.all_keys(); k = keys[p]; b = prov.bearer(p, k)
sec = [k, b] + ([prov.cf_account(k)] if p == "cloudflare" else [])
path = path.replace("ACCOUNT", prov.cf_account(k)) if p == "cloudflare" else path
req = urllib.request.Request(f"https://{host}{path}", data=body.encode(), method="POST",
      headers={"Authorization": "Bearer " + b, "Content-Type": "application/json", "User-Agent": "provider-check"})
try:
    r = urllib.request.urlopen(req, timeout=120); st, t = r.status, r.read()
except urllib.error.HTTPError as e:
    st, t = e.code, e.read()
t = t.decode("utf8", "replace")
print(st, prov.scrub(t[:400], sec), f"({len(t)} bytes)")
