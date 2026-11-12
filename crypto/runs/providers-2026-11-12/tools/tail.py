"""tail.py <provider> [model]: the last events of one cheap stream (scrubbed)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader
p = sys.argv[1]
ppc = loader.load(p, [], model=sys.argv[2] if len(sys.argv) > 2 else None)
r = ppc.TRANSPORT["http"](ppc.BASE)
print("status", r.status, {k: v for k, v in r.headers.items() if k in ("content-type", "transfer-encoding", "connection", "server")})
evs = r.text.split("\n\n")
print(f"{len(evs)} blocks, CR present: {chr(13) in r.text}")
for e in evs[-4:]:
    print(repr(e[:700]))
