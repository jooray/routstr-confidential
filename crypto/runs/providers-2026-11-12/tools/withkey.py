"""withkey.py <provider> <cmd...>: run cmd with the provider's bearer key in CU_PROVIDER_KEY
(and, if PP_NODE_KEY=1, also in CU_NODE_KEY for the node's model listing); the output is scrubbed.

Cloudflare: the account id is part of the chat path. `ACCOUNT` in CU_UPSTREAM_BASE and CU_API_BASES is
replaced by it in the child's environment, and the offer file named by CU_V3_OFFER is
copied with `ACCOUNT` filled in into a 0700 temporary directory (removed at the end),
which CU_V3_OFFER then names. The account id is scrubbed from the output like the key."""
import os, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prov
p, cmd = sys.argv[1], sys.argv[2:]
k = prov.all_keys()[p]; b = prov.bearer(p, k)
secrets = [k, b]
env = dict(os.environ, CU_PROVIDER_KEY=b, CU_KEY_ENV="CU_PROVIDER_KEY")
for v in ("NUMES_API_KEY", "OPENCODE_GO_API_KEY", "VENICE_API_KEY"):
    env.pop(v, None)
if os.environ.get("PP_NODE_KEY") == "1":
    env["CU_NODE_KEY"] = b
tmp = None
if p == "cloudflare":
    acct = prov.cf_account(k)
    secrets.append(acct)
    for v in ("CU_UPSTREAM_BASE", "CU_API_BASES"):
        if v in env:
            env[v] = env[v].replace("ACCOUNT", acct)
    if "CU_V3_OFFER" in env:
        tmp = tempfile.mkdtemp(prefix="cf-offer-")
        os.chmod(tmp, 0o700)
        dst = os.path.join(tmp, "offer.json")
        with open(env["CU_V3_OFFER"]) as f:
            data = f.read().replace("ACCOUNT", acct)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        env["CU_V3_OFFER"] = dst
try:
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    for line in proc.stdout:
        sys.stdout.write(prov.scrub(line, secrets)); sys.stdout.flush()
    rc = proc.wait()
finally:
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
sys.exit(rc)
