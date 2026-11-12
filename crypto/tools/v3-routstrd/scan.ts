// Fails (exit 1, naming the files) if any file under the given paths contains
// one of the secrets in the environment (CU_SCAN_A, CU_SCAN_B).
//   CU_SCAN_A=… CU_SCAN_B=… bun scan.ts <path>...
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";

const secrets = [process.env.CU_SCAN_A, process.env.CU_SCAN_B].filter((s): s is string => !!s && s.length >= 8);
const hits: string[] = [];
function scan(path: string): void {
  if (!existsSync(path)) return;
  if (statSync(path).isDirectory()) {
    for (const name of readdirSync(path)) scan(`${path}/${name}`);
    return;
  }
  const data = readFileSync(path);
  if (secrets.some((s) => data.includes(s))) hits.push(path);
}
for (const p of process.argv.slice(2)) scan(p);
for (const h of hits) console.error(`secret found in ${h}`);
process.exit(hits.length ? 1 : 0);
