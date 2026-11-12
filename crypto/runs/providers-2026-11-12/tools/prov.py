"""Provider keys in memory only.

FreeLLMAPI keys: AES-256-GCM (16-byte IV, 16-byte tag, hex fields) with
ENCRYPTION_KEY from ~/.config/freellmapi/env (server/src/lib/crypto.ts).
Decryption runs in a node child process that gets the ciphertext and the
encryption key on stdin and answers on stdout; nothing touches the disk.
Numes: NUMES_API_KEY from the environment (the caller sources ~/.extra).

Never print a key. `scrub(text)` removes every known key form from text.
"""
import base64, json, os, re, sqlite3, subprocess

DB = os.path.expanduser("~/.local/share/freellmapi/freeapi.db")
ENVF = os.path.expanduser("~/.config/freellmapi/env")
NODE = "/opt/homebrew/opt/node@24/bin/node"

_JS = r"""
const crypto = require('crypto');
let s=''; process.stdin.on('data', d => s += d); process.stdin.on('end', () => {
  const j = JSON.parse(s); const key = Buffer.from(j.k, 'hex'); const out = {};
  for (const r of j.rows) {
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(r.iv, 'hex'), { authTagLength: 16 });
    d.setAuthTag(Buffer.from(r.tag, 'hex'));
    out[r.p] = d.update(r.enc, 'hex', 'utf8') + d.final('utf8');
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def freellm_keys() -> dict:
    ek = None
    for line in open(ENVF):
        if line.startswith("ENCRYPTION_KEY="):
            ek = line.split("=", 1)[1].strip().strip('"').strip("'")
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    rows = [dict(p=p, enc=e, iv=i, tag=t) for p, e, i, t in con.execute(
        "select platform, encrypted_key, iv, auth_tag from api_keys where enabled=1 and platform != 'brave'")]
    con.close()
    out = subprocess.run([NODE, "-e", _JS], input=json.dumps({"k": ek, "rows": rows}).encode(),
                         capture_output=True, check=True).stdout
    return json.loads(out)


def all_keys() -> dict:
    k = freellm_keys()
    if os.environ.get("NUMES_API_KEY"):
        k["numes"] = os.environ["NUMES_API_KEY"]
    if os.environ.get("OPENCODE_GO_API_KEY"):
        k["opencodego"] = os.environ["OPENCODE_GO_API_KEY"]
        # OpenCode Zen takes the same key (https://opencode.ai/zen/v1).
        k["opencodezen"] = os.environ["OPENCODE_GO_API_KEY"]
    return k


def bearer(platform: str, key: str) -> str:
    """The value that goes after 'Bearer ' (Cloudflare stores account_id:token)."""
    return key.split(":", 1)[1] if platform == "cloudflare" else key


def cf_account(key: str) -> str:
    return key.split(":", 1)[0]


def shape(v: str) -> str:
    cls = []
    for name, pat in (("a-z", "[a-z]"), ("A-Z", "[A-Z]"), ("0-9", "[0-9]"), ("_", "_"), ("-", "-"), (".", r"\."), (":", ":")):
        if re.search(pat, v):
            cls.append(name)
    other = set(re.sub(r"[A-Za-z0-9_.:-]", "", v))
    m = re.match(r"^([a-z]+[-_])", v)
    return f"len={len(v)} chars={''.join(cls)}{' other=' + repr(sorted(other)) if other else ''} prefix={m.group(1) if m else '-'}"


def forms(v: str) -> list:
    return [v, base64.b64encode(v.encode()).decode(), base64.b64encode(b"Bearer " + v.encode()).decode()]


def scrub(text: str, secrets: list) -> str:
    for s in secrets:
        if not s:
            continue
        for f in forms(s):
            text = text.replace(f, "***")
    return text


def contains(text: str, secrets: list) -> bool:
    return any(f in text for s in secrets if s for f in forms(s))
