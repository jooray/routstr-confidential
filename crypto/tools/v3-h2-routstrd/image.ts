// Summarizes one image response of v3-h2-routstrd-check.sh as a JSON line:
// its status and confidential headers, and whether the body holds WebP images.
//   bun image.ts <t0 ms> <label> <header file> <body file>
import { readFileSync } from "node:fs";

const [t0, label, headerFile, bodyFile] = process.argv.slice(2);
const total = Date.now() - Number(t0);
let headers = "";
let images: string[] = [];
try {
  headers = readFileSync(headerFile!, "utf8");
  const json = JSON.parse(readFileSync(bodyFile!, "utf8")) as { data?: { b64_json?: string }[] };
  images = (json.data ?? []).map((d) => d.b64_json ?? "");
} catch {
  /* reported as zero images */
}
const h = (name: string) => new RegExp(`^${name}: (.*)$`, "im").exec(headers)?.[1]?.trim();
const webp = images.filter((b64) => {
  const b = Buffer.from(b64, "base64");
  return b.subarray(0, 4).toString("latin1") === "RIFF" && b.subarray(8, 12).toString("latin1") === "WEBP";
});
console.log(
  JSON.stringify({
    label,
    status: Number(/^HTTP\/\S+ (\d+)/m.exec(headers)?.[1] ?? 0),
    total_ms: total,
    http: h("x-routstr-confidential-http") ?? "1.1",
    connection: h("x-routstr-confidential-connection"),
    sid: h("x-routstr-confidential-sid")?.slice(0, 8),
    verify: h("x-routstr-verify"),
    variant: h("x-routstr-confidential-variant"),
    cost_msats: Number(h("x-routstr-cost-msats") ?? 0),
    warnings: h("x-routstr-confidential-warnings"),
    images: images.length,
    webp: webp.length,
    image_bytes: webp.reduce((n, b64) => n + Buffer.from(b64, "base64").length, 0),
  }),
);
