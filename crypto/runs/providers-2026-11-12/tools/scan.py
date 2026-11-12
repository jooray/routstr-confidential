"""scan.py <paths...>: report files containing any form of any provider key (or the Cloudflare account id); prints only file names."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prov
keys = prov.all_keys()
secrets = []
for p, k in keys.items():
    secrets += [k, prov.bearer(p, k)]
    if p == "cloudflare":
        secrets.append(prov.cf_account(k))
for v in ("VENICE_API_KEY",):
    if os.environ.get(v): secrets.append(os.environ[v])
# the FreeLLMAPI encryption key too
for line in open(prov.ENVF):
    if line.startswith("ENCRYPTION_KEY="): secrets.append(line.split("=", 1)[1].strip().strip('"\''))
hits, n = [], 0
for root in sys.argv[1:]:
    files = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
    for f in files:
        n += 1
        data = open(f, "rb").read().decode("latin1")
        if prov.contains(data, secrets):
            hits.append(f)
print(f"scanned {n} files against {len(secrets)} secret values (+ base64 forms): {len(hits)} hit(s)")
for h in hits: print("HIT", h)
sys.exit(1 if hits else 0)
