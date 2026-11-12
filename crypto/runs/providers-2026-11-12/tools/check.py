"""usage: check.py <provider> a [A-items comma list] | h2 [check flags...]

a:  the HTTP/1.1 items (default A9,A11,A1,A2,A4,A5,A6,A7,A12,A10; A3 is
    Venice-only, A8/A13 need specific models)
h2: --h2 --h2-no-images plus the given flags (--h2-idle, --h2-body-bytes)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loader  # noqa: E402

provider, mode, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
if mode == "a":
    items = (rest[0] if rest else "A9,A11,A1,A2,A4,A5,A6,A7,A12,A10").upper().split(",")
    ppc = loader.load(provider, [])
    by = {ppc.tag(f): f for f in ppc.CHECKS}
    ppc.CHECKS = [by[i] for i in items]
    print(f"  items: {','.join(items)}")
elif mode == "h2":
    ppc = loader.load(provider, ["--h2", "--h2-no-images"] + rest)
else:
    sys.exit(__doc__)
rc = ppc.main()
print(f"exit status {rc}")
sys.exit(rc)
