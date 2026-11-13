"""keyusage.py: the OpenRouter key's own usage counters (GET /api/v1/key) and the account credits; prints no key."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pinprobe
key = pinprobe.prov.all_keys()["openrouter"]
st, t = pinprobe.get(key, "/api/v1/key")
d = json.loads(t).get("data", {}) if st == 200 else {}
print(json.dumps({k: d.get(k) for k in ("usage", "usage_daily", "limit", "limit_remaining", "is_free_tier", "include_byok_in_limit", "byok_usage")}))
st, t = pinprobe.get(key, "/api/v1/credits")
print("credits", st, pinprobe.prov.scrub(t[:300], [key]))
