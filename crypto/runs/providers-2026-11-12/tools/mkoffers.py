import json, os
P = {
 # name: host, chat path, probe path, key length (measured from the stored key's shape)
 "numes": ("api.numes.ai", "/api/v1/chat/completions", "/api/v1/models", 76),
 "openrouter": ("openrouter.ai", "/api/v1/chat/completions", "/api/v1/models", 73),
 "google": ("generativelanguage.googleapis.com", "/v1beta/openai/chat/completions", "/v1beta/openai/models", 53),
 "nvidia": ("integrate.api.nvidia.com", "/v1/chat/completions", "/v1/models", 70),
 # ACCOUNT is replaced in memory by the account id (never written)
 "cloudflare": ("api.cloudflare.com", "/client/v4/accounts/ACCOUNT/ai/v1/chat/completions", "/client/v4/accounts/ACCOUNT/ai/v1/models", 53),
 "unorouter": ("api.unorouter.com", "/v1/chat/completions", "/v1/models", 51),
 "opencodego": ("opencode.ai", "/zen/go/v1/chat/completions", "/zen/go/v1/models", 51),
 "xkiro": ("api.xkiro.com", "/v1/chat/completions", "/v1/models", 54),
}
import sys
for n, (host, path, probe, kl) in P.items():
    if sys.argv[1:] and n not in sys.argv[1:]: continue
    o = {
      "http": ["2", "1.1"],
      "upstream_host": host,
      "head_template": f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {{KEY:{kl}}}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {{LEN}}\r\n\r\n",
      "key_alphabet": "[A-Za-z0-9_-]",
      "key_length": kl,
      "chat": {"cap_keys": ["max_tokens", "max_completion_tokens"],
               "fixed_pins": [["n", 1], ["stream", True], ["stream_options", {"include_usage": True}]]},
      "max_tokens_cap": 4096, "notary_pubkey": "", "model_allowlist": [],
      "h2": {"probe_path": probe, "idle_secs": 300, "max_requests": 100, "max_lifetime_s": 3600, "kinds": ["chat"]},
    }
    json.dump(o, open(f"offers/offer.{n}.json", "w"), indent=2)
print("ok")
