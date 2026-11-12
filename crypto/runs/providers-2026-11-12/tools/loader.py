"""Load crypto/tools/provider-profile-check.py for one provider, key in memory.

The key goes into this process's environment as CU_KEY (never to disk) and
the check is pointed at it with --key-env CU_KEY; it only sends it to the
offer's upstream_host. stdout is scrubbed of every known key form (and of the
Cloudflare account id) before it is written anywhere.
"""
import importlib.util, io, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prov  # noqa: E402

TOOLS = "/Users/juraj/projects/routstr-confidential/crypto/tools"
OFFERS = os.path.join(HERE, "offers")
if not os.path.isdir(OFFERS):  # the committed layout: offers/ next to tools/
    OFFERS = os.path.join(HERE, "..", "offers")

# provider -> (offer file, cheap model, min seconds between requests)
PROVIDERS = {
    "numes": ("offer.numes.json", "moonshotai/kimi-k3.1-pro", 1.0),
    "openrouter": ("offer.openrouter.json", "liquid/lfm-2.5-2.6b:free", 3.0),
    "google": ("offer.google.json", "gemini-flash-lite-latest", 5.0),
    "nvidia": ("offer.nvidia.json", "nvidia/nemotron-3.5-bolt-e4b", 2.0),
    "cloudflare": ("offer.cloudflare.json", "@cf/meta/llama-3.2-1b-instruct", 1.0),
    "unorouter": ("offer.unorouter.json", "glm-5.3-flash:free", 62.0),
    "opencodego": ("offer.opencodego.json", "glm-5.3-flash", 1.0),
    "xkiro": ("offer.xkiro.json", "mistralai/ministral-3b", 1.0),
}


class Scrub(io.TextIOBase):
    def __init__(self, out, secrets):
        self.out, self.secrets = out, secrets

    def write(self, s):
        self.out.write(prov.scrub(s, self.secrets))
        return len(s)

    def flush(self):
        self.out.flush()


def load(provider: str, flags: list, model: str | None = None, interval: float | None = None):
    offer, cheap, gap = PROVIDERS[provider]
    model = model or os.environ.get("PP_MODEL") or cheap
    keys = prov.all_keys()
    key = keys[provider]
    b = prov.bearer(provider, key)
    secrets = [key, b]
    acct = prov.cf_account(key) if provider == "cloudflare" else None
    if acct:
        secrets.append(acct)
    del keys
    os.environ["CU_KEY"] = b
    for k in ("CU_REASONING_MODEL", "CU_TEXT_ONLY_MODEL", "CU_VISION_MODEL"):
        os.environ.setdefault(k, model)
    sys.stdout = Scrub(sys.__stdout__, secrets)
    sys.stderr = Scrub(sys.__stderr__, secrets)
    sys.argv = ["provider-profile-check.py", "--offer", os.path.join(OFFERS, offer), "--key-env", "CU_KEY", "--model", model] + flags
    sys.path.insert(0, TOOLS)
    spec = importlib.util.spec_from_file_location("ppc", os.path.join(TOOLS, "provider-profile-check.py"))
    ppc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ppc)
    if acct:
        ppc.PATH = ppc.PATH.replace("ACCOUNT", acct)
        ppc.H2_PROBE = ppc.H2_PROBE.replace("ACCOUNT", acct)
    # Provider-specific expected rejections, from PP_EXPECT (JSON {name: [status, regex]}).
    for name, v in json.loads(os.environ.get("PP_EXPECT", "{}")).items():
        setattr(ppc, name, (int(v[0]), v[1]))
    # Rate limiting: a minimum interval between requests.
    gap = interval if interval is not None else float(os.environ.get("PP_GAP", gap))
    last = [0.0]

    def spaced(fn):
        def w(*a, **k):
            d = last[0] + gap - time.time()
            if d > 0:
                time.sleep(d)
            try:
                return fn(*a, **k)
            finally:
                last[0] = time.time()
        return w

    for t in ("http", "partial", "s_client"):
        ppc.TRANSPORT[t] = spaced(ppc.TRANSPORT[t])
    ppc.h2.H2Client.request = spaced(ppc.h2.H2Client.request)
    # PP_MODEL_ALIAS: the provider reports the model under another spelling
    # (the protocol passes it on as reported_model); count it as the pinned one.
    alias = os.environ.get("PP_MODEL_ALIAS")
    if alias:
        orig = ppc.usage_of

        def usage_of(text):
            ev = orig(text)
            if ev.get("model") == alias:
                ev = dict(ev, model=ppc.CHEAP)
            return ev
        ppc.usage_of = usage_of
        orig_events = ppc.events

        def events(text):
            return [dict(e, model=ppc.CHEAP) if e.get("model") == alias else e for e in orig_events(text)]
        ppc.events = events
        print(f"  note: the provider reports {ppc.CHEAP} as {alias}; counted as the pinned model (reported_model)")
    # PP_ERROR_FIELD: the field the --h2 run's "chat, unknown field" request
    # carries, for a provider that answers an unknown field with a 5xx (the
    # check retries 5xx as transient); a known field with a bad value gives
    # the 4xx error path H7 must read.
    ef = os.environ.get("PP_ERROR_FIELD")
    if ef:
        orig_body = ppc.h2_body

        def h2_body(filler=0, model=None, extra=""):
            return orig_body(filler, model, ef if extra == '"bogus_field_xyz":1,' else extra)
        ppc.h2_body = h2_body
        print(f"  note: the 'chat, unknown field' request carries {ef} instead of an unknown field")
    # PP_EXTRA_HEADER: one more request header line in the HTTP/1.1 head (the
    # sidecar's head template cannot carry it today; this only shows whether
    # the rest of the profile would hold if it could).
    xh = os.environ.get("PP_EXTRA_HEADER")
    if xh:
        orig_head = ppc.head

        def head(length, path=""):
            h = orig_head(length, path)
            return h[:-2] + xh.encode() + b"\r\n\r\n"
        ppc.head = head
        print(f"  note: every HTTP/1.1 request carries the extra header {xh.split(':')[0]}")
    ppc._PP_SECRETS = secrets
    return ppc
