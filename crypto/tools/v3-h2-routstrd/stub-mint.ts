// A stand-in Cashu mint for the scratch routstrd wallet of
// v3-h2-routstrd-check.sh: it serves mint info and one keyset, so the wallet
// starts with a reachable default mint. It mints nothing (the test credential
// is credited in the node's database).
//   CU_SDK=<routstr-sdk checkout> bun stub-mint.ts <port>
const sdk = process.env.CU_SDK;
if (!sdk) throw new Error("CU_SDK is not set");
const { secp256k1 } = await import(`${sdk}/node_modules/@noble/curves/secp256k1.js`);
const { sha256 } = await import(`${sdk}/node_modules/@noble/hashes/sha2.js`);
const { bytesToHex } = await import(`${sdk}/node_modules/@noble/hashes/utils.js`);

const port = Number(process.argv[2] ?? 3348);
const keys: Record<string, string> = {};
const pubs: Uint8Array[] = [];
for (let i = 0; i < 32; i++) {
  const priv = sha256(new TextEncoder().encode(`stub-mint-key-${i}`));
  const pub: Uint8Array = secp256k1.getPublicKey(priv, true);
  keys[String(2 ** i)] = bytesToHex(pub);
  pubs.push(pub);
}
const all = new Uint8Array(pubs.length * 33);
pubs.forEach((p, i) => all.set(p, i * 33));
const id = "00" + bytesToHex(sha256(all)).slice(0, 14);
const info = {
  name: "stub mint (test)",
  pubkey: keys["1"],
  version: "Nutshell/0.17.0",
  description: "serves keys only",
  contact: [],
  nuts: {
    "4": { methods: [{ method: "bolt11", unit: "sat" }], disabled: true },
    "5": { methods: [{ method: "bolt11", unit: "sat" }], disabled: true },
    "7": { supported: true },
    "8": { supported: true },
    "9": { supported: true },
    "10": { supported: true },
    "11": { supported: true },
    "12": { supported: true },
  },
};
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });

Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch(req) {
    const path = new URL(req.url).pathname.replace(/\/$/, "");
    if (path === "/v1/info") return json(info);
    if (path === "/v1/keysets") return json({ keysets: [{ id, unit: "sat", active: true, input_fee_ppk: 0 }] });
    if (path === "/v1/keys" || path === `/v1/keys/${id}`) return json({ keysets: [{ id, unit: "sat", keys }] });
    if (path === "/v1/checkstate") return json({ states: [] });
    return json({ detail: "not supported by the stub mint", code: 0 }, 400);
  },
});
console.log(`stub mint on 127.0.0.1:${port}, keyset ${id}`);
