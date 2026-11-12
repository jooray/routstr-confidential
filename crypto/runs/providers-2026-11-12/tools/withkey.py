"""withkey.py <provider> <cmd...>: run cmd with the provider's bearer key in CU_PROVIDER_KEY
(and, if PP_NODE_KEY=1, also in CU_NODE_KEY for the node's model listing); the output is scrubbed."""
import os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prov
p, cmd = sys.argv[1], sys.argv[2:]
k = prov.all_keys()[p]; b = prov.bearer(p, k)
env = dict(os.environ, CU_PROVIDER_KEY=b, CU_KEY_ENV="CU_PROVIDER_KEY")
for v in ("NUMES_API_KEY", "OPENCODE_GO_API_KEY", "VENICE_API_KEY"):
    env.pop(v, None)
if os.environ.get("PP_NODE_KEY") == "1":
    env["CU_NODE_KEY"] = b
proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
for line in proc.stdout:
    sys.stdout.write(prov.scrub(line, [k, b])); sys.stdout.flush()
sys.exit(proc.wait())
