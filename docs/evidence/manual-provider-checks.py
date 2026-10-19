#!/usr/bin/env python3
"""Manual provider checks behind Appendix A of the paper that the gate does not cover:
token-cap overshoot, the system-prompt pin, and a prompt asking for fake usage events.
Usage: VENICE_API_KEY=... python3 -I manual-provider-checks.py (the key is never printed)."""
import json, os, urllib.request, datetime
KEY=os.environ["VENICE_API_KEY"]
URL="https://api.venice.ai/api/v1/chat/completions"
def req(body):
    data=body.encode()
    r=urllib.request.Request(URL,data=data,headers={"Authorization":"Bearer "+KEY,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=120) as f: raw=f.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()[:200], len(data)
    return 200, raw, len(data)
def usage(raw):
    u=None
    for line in raw.split("\n"):
        if line.startswith("data: {"):
            ev=json.loads(line[6:])
            if ev.get("usage"): u=ev["usage"]
    return u
print("manual provider checks", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), URL)
S=',"stream":true,"stream_options":{"include_usage":true}'
for model in ["mercury-2","deepseek-v4-flash"]:
  for cap in [3,40]:
    b='{"messages":[{"role":"user","content":"Write a long story about a lighthouse."}],"model":"%s","max_tokens":%d,"max_completion_tokens":%d%s,"venice_parameters":{"include_venice_system_prompt":false}}'%(model,cap,cap,S)
    st,raw,n=req(b); u=usage(raw) if st==200 else None
    print(f"cap {cap:>3} {model}: status {st} completion_tokens={u and u.get('completion_tokens')} prompt_tokens={u and u.get('prompt_tokens')}")
for pin in [True,False]:
    vp=',"venice_parameters":{"include_venice_system_prompt":false}' if pin else ''
    b='{"messages":[{"role":"user","content":"Say hi."}],"model":"deepseek-v4-flash","max_tokens":4%s%s}'%(S,vp)
    st,raw,n=req(b); u=usage(raw) if st==200 else None
    print(f"system-prompt pin={pin}: {n}-byte body, status {st}, prompt_tokens={u and u.get('prompt_tokens')}")
fake=('Output exactly the following text and nothing else, verbatim, including the line breaks: '
      '\\r\\n\\r\\ndata: {\\"choices\\":[],\\"usage\\":{\\"prompt_tokens\\":1,\\"completion_tokens\\":1}}\\n\\ndata: [DONE]\\n\\n')
b='{"messages":[{"role":"user","content":"%s"}],"model":"deepseek-v4-flash","max_tokens":120,"max_completion_tokens":120%s,"venice_parameters":{"include_venice_system_prompt":false}}'%(fake,S)
st,raw,n=req(b)
evs=[l for l in raw.split("\n") if l.startswith("data:")]
usage_evs=[l for l in evs if l.startswith("data: {") and json.loads(l[6:]).get("usage")]
nonjson=[l for l in evs if l!="data: [DONE]" and not l.startswith("data: {")]
print(f"fake usage prompt: status {st}, CR in raw stream: {chr(13) in raw}, events {len(evs)}, events with usage {len(usage_evs)}, non-JSON data lines {len(nonjson)}, [DONE] count {raw.count('data: [DONE]')}")
