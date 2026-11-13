"""collect.py <provider> <src> <dst> [glob...]: copy evidence files, every known key form and
the Cloudflare account id replaced (the account id by `<account>`, keys by `***`)."""
import fnmatch, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "providers-2026-11-12", "tools"))
import prov
p, src, dst, globs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:] or ["*"]
keys = prov.all_keys()
secrets = []
for name, k in keys.items():
    secrets += [k, prov.bearer(name, k)]
acct = prov.cf_account(keys["cloudflare"])
os.makedirs(dst, exist_ok=True)
n = 0
for f in sorted(os.listdir(src)):
    path = os.path.join(src, f)
    if not os.path.isfile(path) or not any(fnmatch.fnmatch(f, g) for g in globs):
        continue
    text = open(path, "rb").read().decode("utf-8", "replace")
    text = prov.scrub(text.replace(acct, "<account>"), secrets)
    open(os.path.join(dst, f), "w").write(text)
    n += 1
print(f"{n} files copied to {dst}")
