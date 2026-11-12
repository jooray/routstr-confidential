// Scratch state of the routstrd that v3-routstrd-check.sh starts: a fresh
// throwaway wallet whose default mint is the local stub, the daemon config,
// and, in the SDK store, the private node (provider list, manual enable) with
// its credential (credited in the node's database, so no mint is needed).
//   bun seed.ts init     <routstrd dir> <routstrd checkout> <node url> <mint url> <routstrd port> <cu-prover> <node pubkey>   (the credential: env CU_TEST_KEY)
//   bun seed.ts set      <routstrd dir> <json>     merge <json> into confidentialUpstream (a null value removes the key)
//   bun seed.ts provider <routstrd dir> <node url> the daemon's one provider (added to the store with a placeholder credential)
import { Database } from "bun:sqlite";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const [mode, dir, ...rest] = process.argv.slice(2);
const configFile = `${dir}/config.json`;

function put(db: Database, k: string, v: unknown): void {
  db.run("INSERT INTO sdk_storage(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [k, JSON.stringify(v)]);
}

if (mode === "set") {
  const c = JSON.parse(readFileSync(configFile, "utf8"));
  for (const [k, v] of Object.entries(JSON.parse(rest[0]!))) {
    if (v === null) delete c.confidentialUpstream[k];
    else c.confidentialUpstream[k] = v;
  }
  writeFileSync(configFile, JSON.stringify(c, null, 2), { mode: 0o600 });
  process.exit(0);
}
if (mode === "provider") {
  const url = rest[0]!.replace(/\/$/, "") + "/";
  const c = JSON.parse(readFileSync(configFile, "utf8"));
  c.provider = rest[0];
  writeFileSync(configFile, JSON.stringify(c, null, 2), { mode: 0o600 });
  const db = new Database(`${dir}/routstr.db`);
  const get = (k: string): any[] => JSON.parse((db.query("SELECT value FROM sdk_storage WHERE key=?").get(k) as { value: string } | null)?.value ?? "[]");
  const urls = get("base_urls_list");
  if (!urls.includes(url)) put(db, "base_urls_list", [...urls, url]);
  const enabled = get("manually_enabled_providers");
  if (!enabled.includes(url)) put(db, "manually_enabled_providers", [...enabled, url]);
  const keys = get("api_keys");
  // A placeholder credential: the node behind this URL is never paid.
  if (!keys.some((k: any) => k.baseUrl === url)) put(db, "api_keys", [...keys, { baseUrl: url, key: "sk-" + "0".repeat(64), balance: 200000, reserved: 0, lastUsed: null }]);
  db.close();
  process.exit(0);
}
if (mode !== "init") throw new Error("usage: seed.ts init … | set <dir> <json> | provider <dir> <url>");

const [checkout, nodeUrl, mintUrl, port, prover, pubkey] = rest;
const key = process.env.CU_TEST_KEY;
if (!key) throw new Error("CU_TEST_KEY is not set");
const { generateMnemonic } = await import(`${checkout}/node_modules/@scure/bip39/index.js`);
const { wordlist } = await import(`${checkout}/node_modules/@scure/bip39/wordlists/english.js`);

mkdirSync(`${dir}/wallet`, { recursive: true, mode: 0o700 });
chmodSync(dir!, 0o700);
writeFileSync(
  `${dir}/wallet/config.json`,
  JSON.stringify(
    { version: 1, mnemonic: generateMnemonic(wordlist), encrypted: false, createdAt: new Date().toISOString(), defaultMintUrl: mintUrl },
    null,
    2,
  ),
  { mode: 0o600 },
);
writeFileSync(
  configFile,
  JSON.stringify(
    {
      port: Number(port),
      host: "127.0.0.1",
      provider: nodeUrl,
      mode: "apikeys",
      autoModelPath: false,
      updateCheck: false,
      maxTokens: 40,
      autoRefresh: { enabled: false },
      // Nothing is announced or fetched: the relay list points nowhere.
      relays: ["ws://127.0.0.1:9"],
      confidentialUpstream: {
        enabled: true,
        trusted_hosts: ["api.venice.ai"],
        node_pubkeys: [pubkey],
        prover_path: prover,
        http: "auto",
        prewarm: { enabled: false },
        http2: { reuse: "per-client" },
      },
    },
    null,
    2,
  ),
  { mode: 0o600 },
);

const url = nodeUrl!.replace(/\/$/, "") + "/";
const db = new Database(`${dir}/routstr.db`);
db.run("CREATE TABLE IF NOT EXISTS sdk_storage (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
put(db, "base_urls_list", [url]);
// The provider list never goes stale during the check (a refresh would need Nostr).
put(db, "lastBaseUrlsUpdate", Date.now() + 86_400_000);
put(db, "manually_enabled_providers", [url]);
put(db, "api_keys", [{ baseUrl: url, key, balance: 200000, reserved: 0, lastUsed: null }]);
db.close();
