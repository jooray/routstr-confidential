"""dup.py <provider> <model1> <model2>: which of two "model" keys the provider serves (and reports)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader
p, m1, m2 = sys.argv[1:4]
ppc = loader.load(p, [], model=m2)
body = "{" + ppc.MSG + f',"model":"{m1}","max_tokens":4,' + ppc.STREAM + f',"model":"{m2}"' + "}"
r = ppc.TRANSPORT["http"](body)
u = ppc.usage_of(r.text)
ids = sorted({e.get("model") for e in ppc.events(r.text)})
print(f"model {m1!r} then {m2!r} -> {r.status}; models named in events: {ids}; usage model: {u.get('model')}; {ppc.snip(r.text, 120) if r.status != 200 else ''}")
