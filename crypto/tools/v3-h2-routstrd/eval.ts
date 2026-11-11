// Verdicts and the timing table of v3-h2-routstrd-check.sh.
//   bun eval.ts <evidence dir>
// Reads what the script collected there: the curl results of each run
// (results-<run>.jsonl, from stamp.ts), the node's log lines of each run
// (node-<run>.log), the routstrd log lines (rd-<run>.log) and money.json.
import { existsSync, readFileSync } from "node:fs";

const dir = process.argv[2]!;
const lines = (f: string) => (existsSync(`${dir}/${f}`) ? readFileSync(`${dir}/${f}`, "utf8").split("\n").filter(Boolean) : []);
const jsonl = (f: string): any[] =>
  lines(f).flatMap((l) => {
    try {
      return [JSON.parse(l)];
    } catch {
      return [];
    }
  });
const results = (run: string) => jsonl(`results-${run}.jsonl`).sort((a, b) => String(a.label).localeCompare(String(b.label)));
const nodeLog = (run: string) => jsonl(`node-${run}.log`);
const msg = (log: any[], m: string) => log.filter((l) => l.message === m);
/** routstrd's per-request statistics lines. */
const stats = (run: string): any[] =>
  lines(`rd-${run}.log`).flatMap((l) => {
    const m = /\[confidential http2\] request (\{.*\})\s*$/.exec(l);
    try {
      return m ? [JSON.parse(m[1]!)] : [];
    } catch {
      return [];
    }
  });
const plain = (run: string) => lines(`node-${run}.log`).filter((l) => l.includes("chat/completions")).length;

const verdicts: [string, boolean, string][] = [];
const verdict = (id: string, problems: string[], evidence: string) =>
  verdicts.push([id, problems.length === 0, problems.length ? problems.join("; ") : evidence]);
const okResult = (r: any) => r.status === 200 && r.verify === "confidential" && typeof r.text === "string" && r.text.length > 0 && r.ttft_ms > 0;

// (1) http2 on: 5 sequential requests on one connection.
{
  const p: string[] = [];
  const rs = results("h2seq");
  const log = nodeLog("h2seq");
  const st = stats("h2seq");
  if (rs.length !== 5) p.push(`${rs.length} of 5 responses`);
  if (!rs.every(okResult)) p.push("a response is not a 200 with content");
  if (!rs.every((r) => r.http === "2")) p.push("a response did not run as http 2");
  const sids = new Set(rs.map((r) => r.sid));
  if (sids.size !== 1) p.push(`${sids.size} connections in the response headers, expected 1`);
  const want = ["new; request=1", "reused; request=2", "reused; request=3", "reused; request=4", "reused; request=5"];
  if (rs.map((r) => r.connection).join("|") !== want.join("|")) p.push(`connection headers: ${rs.map((r) => r.connection).join(" | ")}`);
  if (st.map((s) => `${s.n}:${s.reused}:${s.status}`).join(" ") !== "1:false:200 2:true:200 3:true:200 4:true:200 5:true:200" || new Set(st.map((s) => s.sid)).size !== 1) {
    p.push(`routstrd log: ${st.map((s) => `${String(s.sid).slice(0, 8)} n=${s.n} reused=${s.reused}`).join(", ") || "no request lines"}`);
  }
  const reserved = msg(log, "confidential ws: request reserved");
  const settled = msg(log, "confidential ws: settled");
  const ns = (ls: any[]) => ls.map((l) => l.n).join(",");
  if (ns(reserved) !== "1,2,3,4,5" || ns(settled) !== "1,2,3,4,5") p.push(`node log: reserved n=${ns(reserved)} settled n=${ns(settled)}`);
  if (new Set([...reserved, ...settled].map((l) => l.sid)).size > 1) p.push("node log: more than one connection");
  if (plain("h2seq") > 0) p.push("the node log has a plain chat/completions line");
  verdict("h2-sequential", p, `5 × 200 on connection ${[...sids][0]}; node: 5 reserved + 5 settled (n 1..5), no plain request`);
}

// (2) http2 on: a burst of 3 parallel requests.
{
  const p: string[] = [];
  const rs = results("h2burst");
  const log = nodeLog("h2burst");
  if (rs.length !== 3) p.push(`${rs.length} of 3 responses`);
  if (!rs.every(okResult) || !rs.every((r) => r.http === "2")) p.push("a response is not a 200 with content over http 2");
  const reserved = msg(log, "confidential ws: request reserved").length;
  const settled = msg(log, "confidential ws: settled").length;
  if (reserved !== 3 || settled !== 3) p.push(`node log: ${reserved} reserved, ${settled} settled, expected 3 and 3`);
  if (plain("h2burst") > 0) p.push("the node log has a plain chat/completions line");
  verdict("h2-burst", p, `3 × 200 on ${new Set(rs.map((r) => r.sid)).size} connection(s) (${rs.map((r) => r.connection).join(" | ")}); node: 3 reserved + 3 settled`);
}

// (3) http2 off: the v2 flow (one session per request, pre-warmed after the first).
{
  const p: string[] = [];
  const rs = results("v2seq");
  const log = nodeLog("v2seq");
  if (rs.length !== 5) p.push(`${rs.length} of 5 responses`);
  if (!rs.every(okResult)) p.push("a response is not a 200 with content");
  if (rs.some((r) => r.http === "2")) p.push("a response ran as http 2 although it is disabled");
  if (new Set(rs.map((r) => r.sid)).size !== rs.length) p.push("two responses share a session");
  const settled = msg(log, "confidential ws: settled");
  if (settled.length !== 5) p.push(`node log: ${settled.length} settled, expected 5`);
  if (msg(log, "confidential ws: request reserved").length > 0 || settled.some((l) => l.n !== undefined)) p.push("node log: an http 2 request in the v2 run");
  if (plain("v2seq") > 0) p.push("the node log has a plain chat/completions line");
  verdict("v2-sequential", p, `5 × 200, 5 sessions (pre-warmed: ${rs.map((r) => r.prewarmed ?? "-").join(",")}); node: 5 settled`);
}

// (4) money: the balance is the start minus the charges; nothing stays reserved.
{
  const p: string[] = [];
  const m = JSON.parse(readFileSync(`${dir}/money.json`, "utf8"));
  const settled = msg(jsonl("node-all.log"), "confidential ws: settled");
  const charges = settled.reduce((n, l) => n + (Number(l.cost_msats) || 0), 0);
  if (settled.length !== 13) p.push(`${settled.length} settlements in the node log, expected 13`);
  if (m.reserved !== 0) p.push(`reserved_balance ${m.reserved}`);
  if (m.balance !== m.start - charges) p.push(`balance ${m.balance} != start ${m.start} - charges ${charges}`);
  if (charges <= 0) p.push("no charge in the node log");
  verdict("money", p, `balance ${m.balance} msats = ${m.start} - ${charges} (${settled.length} settlements), reserved 0`);
}

// The table.
const mb = (n: number | undefined) => (n === undefined ? "-" : n >= 1e6 ? `${(n / 1e6).toFixed(2)} MB` : `${Math.round(n / 1e3)} kB`);
const rows: string[][] = [["run", "request", "ttft ms", "total ms", "connection", "node→client", "client→node", "to open: node→client", "client→node"]];
for (const run of ["h2seq", "h2burst", "v2seq"]) {
  const st = stats(run === "v2seq" ? "none" : run);
  for (const r of results(run)) {
    const n = Number(/request=(\d+)/.exec(r.connection ?? "")?.[1]);
    const s = st.find((x) => String(x.sid).startsWith(r.sid) && x.n === n);
    rows.push([
      run,
      String(r.label).replace(/^.*-/, ""),
      String(r.ttft_ms ?? "-"),
      String(r.total_ms ?? "-"),
      run === "v2seq" ? `v2 session${r.prewarmed === "1" ? " (pre-warmed)" : r.prewarmed === "0" ? " (cold)" : ""}` : (r.connection ?? "-"),
      mb(s?.bytesRecv),
      mb(s?.bytesSent),
      mb(s?.connectBytesRecv),
      mb(s?.connectBytesSent),
    ]);
  }
}
const width = rows[0]!.map((_, i) => Math.max(...rows.map((r) => r[i]!.length)));
console.log();
for (const r of rows) console.log(r.map((c, i) => c.padEnd(width[i]!)).join("  "));
console.log("(bytes: 2PC, proofs, relayed records and control frames between routstrd and the node; routstrd logs them for http 2 requests only)");
console.log();
for (const [id, ok, evidence] of verdicts) console.log(`${ok ? "PASS" : "DEVIATION"}  ${id.padEnd(14)}  ${evidence}`);
process.exit(verdicts.every(([, ok]) => ok) ? 0 : 1);
