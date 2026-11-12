"""body.py <provider> <model> <json body fragment after messages>: one request, status + scrubbed tail."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader
p, m, frag = sys.argv[1:4]
ppc = loader.load(p, [], model=m)
body = "{" + ppc.MSG + "," + frag + "}"
r = ppc.TRANSPORT["http"](body)
print(r.status, ppc.snip(r.text, 300) if r.status != 200 else ppc.snip(r.text[-500:], 500))
