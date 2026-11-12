"""One OpenRouter chat-completions image request (modalities image,text), stream; prints the shape, not the image."""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader
m = sys.argv[1]
ppc = loader.load("openrouter", [], model=m)
body = '{"messages":[{"role":"user","content":"A red circle on white. Tiny."}],"modalities":["image","text"],"model":"%s","max_tokens":2000,%s}' % (m, ppc.STREAM)
r = ppc.TRANSPORT["http"](body)
print("status", r.status, "bytes", len(r.text), "CR", "\r" in r.text)
blocks = [b for b in r.text.split("\n\n") if b]
print("blocks", len(blocks), "comment blocks", sum(b.startswith(":") for b in blocks))
for b in blocks[-3:]:
    print(re.sub(r"data:image/[a-z]+;base64,[A-Za-z0-9+/=]{40,}", "<base64 image>", b)[:1500])
big = [b for b in blocks if "base64" in b]
print("events with an image:", len(big), "largest event bytes:", max((len(b) for b in big), default=0))
