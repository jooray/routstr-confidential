"""How long a provider keeps an idle HTTP/2 connection, and whether client frames extend it.

usage: python3 keepalive.py <provider> <mode> <total_s> <every_s>
  mode: none (measure the close), ping (client PING), settings (empty SETTINGS),
        request (a chat request by index every_s: tells an idle limit from an age limit)
A copy of the scratchpad's idle/keepalive.py (Venice) that loads the
provider through loader.py: same TLS profile, connection head (probe GET
with the credential, reset), KeyUpdate, then one chat request by index; idle;
then a request by index again if the connection is still open.
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader  # noqa: E402

provider, mode, total, every = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
ppc = loader.load(provider, ["--h2"], interval=0.0)
h2 = ppc.h2
print(f"keepalive {provider} {mode} total={total:.0f}s every={every:.0f}s host={ppc.HOST} model={ppc.CHEAP} "
      f"start={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}", flush=True)
c = ppc.h2_open()
r = ppc.h2_request(c, ppc.PATH, ppc.h2_body(), "first")
t0 = time.time()
print(f"{mode}: first request -> {r.status}", flush=True)
sent = 0
while time.time() - t0 < total:
    step = min(every, total - (time.time() - t0))
    c.pump(lambda: c.closed or c.goaway is not None, step)
    if c.closed or c.goaway:
        print(f"{mode}: closed after {time.time()-t0:.0f} s idle (goaway={ppc._goaway(c) or None}, closed={c.closed}, frames_sent={sent})", flush=True)
        sys.exit(0)
    if mode == "ping":
        c.tr.send(h2.frame(h2.PING, 0, 0, b"keepaliv")); sent += 1
    elif mode == "settings":
        c.tr.send(h2.frame(h2.SETTINGS, 0, 0)); sent += 1
    elif mode == "request" and time.time() - t0 < total - 1:
        rr = ppc.h2_request(c, ppc.PATH, ppc.h2_body(), f"request {sent + 1}"); sent += 1
        print(f"{mode}: request {sent} at {time.time()-t0:.0f} s -> {rr.status}", flush=True)
try:
    r2 = ppc.h2_request(c, ppc.PATH, ppc.h2_body(), "after idle")
    print(f"{mode}: still open after {time.time()-t0:.0f} s ({sent} frames sent) -> {r2.status}", flush=True)
except Exception as exc:
    print(f"{mode}: after {time.time()-t0:.0f} s ({sent} frames sent) request failed: {exc}", flush=True)
