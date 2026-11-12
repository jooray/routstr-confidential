// Verdicts and the timing table of v3-routstrd-check.sh.
//   bun eval.ts <evidence dir>
// Reads what the script collected there: the curl results of each run
// (results-<run>.jsonl, from stamp.ts / image.ts), the node's log lines of each
// run (node-<run>.log), routstrd's (rd-<run>.log), money.json and terms.json.
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
const byLabel = (a: any, b: any) => Number(String(a.label).split("-").pop()) - Number(String(b.label).split("-").pop());
const results = (run: string) => jsonl(`results-${run}.jsonl`).sort(byLabel);
const nodeLog = (run: string) => jsonl(`node-${run}.log`);
const msg = (log: any[], m: string) => log.filter((l) => l.message === m);
/** routstrd's per-request statistics lines. */
const stats = (run: string): any[] =>
  lines(`rd-${run}.log`).flatMap((l) => {
    const m = /\[confidential\] request (\{.*\})\s*$/.exec(l);
    try {
      return m ? [JSON.parse(m[1]!)] : [];
    } catch {
      return [];
    }
  });
const plain = (run: string) => lines(`node-${run}.log`).filter((l) => /"POST \/v1\/chat\/completions/.test(l)).length;
const terms = JSON.parse(readFileSync(`${dir}/terms.json`, "utf8")) as { fee: number; abandon: number; deposit: number; image: boolean };

const verdicts: [string, boolean, string][] = [];
const verdict = (id: string, problems: string[], evidence: string) =>
  verdicts.push([id, problems.length === 0, problems.length ? problems.join("; ") : evidence]);
const okResult = (r: any) => r.status === 200 && r.verify === "confidential" && typeof r.text === "string" && r.text.length > 0 && r.ttft_ms > 0;
const conns = (rs: any[]) => rs.map((r) => r.connection).join(" | ");
const ns = (ls: any[]) => ls.map((l) => l.n).join(",");

// sequential: one framing-2 connection, requests 1..5, the session fee once.
{
  const p: string[] = [];
  const rs = results("seq");
  const log = nodeLog("seq");
  if (rs.length !== 5 || !rs.every(okResult)) p.push(`${rs.filter(okResult).length} of 5 responses are a 200 with content`);
  if (!rs.every((r) => r.http === "2")) p.push(`framings ${rs.map((r) => r.http).join(",")}`);
  if (new Set(rs.map((r) => r.sid)).size !== 1) p.push("more than one connection");
  const want = ["new; request=1", "reused; request=2", "reused; request=3", "reused; request=4", "reused; request=5"];
  if (conns(rs) !== want.join(" | ")) p.push(`connection headers: ${conns(rs)}`);
  const reserved = msg(log, "confidential ws: request reserved");
  const settled = msg(log, "confidential ws: settled");
  if (ns(reserved) !== "1,2,3,4,5" || ns(settled) !== "1,2,3,4,5") p.push(`node: reserved n=${ns(reserved)} settled n=${ns(settled)}`);
  const costs = settled.map((l) => Number(l.cost_msats));
  if (!(costs[0]! >= terms.fee && costs.slice(1).every((c) => c < terms.fee))) p.push(`costs ${costs.join(",")}: the session fee is not charged exactly once`);
  if (plain("seq") > 0) p.push("a plain chat/completions request reached the node");
  verdict("sequential", p, `5 × 200 on connection ${rs[0]?.sid} (${conns(rs)}); node costs ${costs.join(",")} msat (fee once)`);
}

// burst: 3 overlapping requests, on 3 connections.
{
  const p: string[] = [];
  const rs = results("burst");
  if (rs.length !== 3 || !rs.every(okResult) || !rs.every((r) => r.http === "2")) p.push("not 3 × 200 with content on framing 2");
  const sids = new Set(rs.map((r) => r.sid));
  if (sids.size !== 3) p.push(`${sids.size} connection(s)`);
  const settled = msg(nodeLog("burst"), "confidential ws: settled").length;
  if (settled !== 3) p.push(`node: ${settled} settled`);
  verdict("burst", p, `3 × 200 on ${sids.size} connections (${conns(rs)})`);
}

// image: on an open framing-2 connection, settled flat.
if (terms.image) {
  const p: string[] = [];
  const r = results("image")[0] ?? {};
  const settled = msg(nodeLog("image"), "confidential ws: settled");
  const reserved = msg(nodeLog("image"), "confidential ws: request reserved");
  if (r.status !== 200 || r.verify !== "confidential") p.push(`status ${r.status}`);
  if (r.http !== "2" || !/^reused; request=\d+$/.test(String(r.connection))) p.push(`not on an open framing-2 connection (${r.http}, ${r.connection})`);
  if (r.images !== 1 || r.webp !== 1 || r.warnings) p.push(`${r.webp} WebP of ${r.images}${r.warnings ? `, warnings: ${r.warnings}` : ""}`);
  if (reserved.length !== 1 || reserved[0].kind !== "images") p.push(`node: ${reserved.length} reservation(s) of kind ${reserved[0]?.kind}`);
  if (settled.length !== 1 || Number(settled[0].cost_msats) !== r.cost_msats || !(r.cost_msats > 0)) p.push(`node settled ${settled[0]?.cost_msats}, the response says ${r.cost_msats}`);
  verdict("image", p, `200, 1 WebP (${r.image_bytes} bytes) in ${r.total_ms} ms (${r.connection}), flat ${r.cost_msats} msat (no second fee)`);
}

// clients: B gets its own connection; each reuses its own.
{
  const p: string[] = [];
  const rs = results("clients");
  const seqSid = results("seq")[0]?.sid;
  if (rs.length !== 3 || !rs.every(okResult)) p.push("not 3 × 200 with content");
  const [b1, a2, b2] = rs;
  if (b1?.connection !== "new; request=1") p.push(`client B's first request: ${b1?.connection}`);
  if (![seqSid, ...results("burst").map((r) => r.sid)].includes(a2?.sid) || !/^reused/.test(String(a2?.connection))) p.push(`client A did not reuse its connection (${a2?.sid}, ${a2?.connection})`);
  if (b2?.sid !== b1?.sid || b2?.connection !== "reused; request=2") p.push(`client B did not reuse its own (${b2?.sid}, ${b2?.connection})`);
  if (b1?.sid === a2?.sid) p.push("A and B share a connection");
  verdict("clients", p, `B: ${b1?.sid} (${b1?.connection}, then ${b2?.connection}); A: ${a2?.sid} (${a2?.connection})`);
}

// refused: 402 to the caller, the connection kept, the next request on it with the same number.
{
  const p: string[] = [];
  const [r1, r2] = results("refused");
  const log = nodeLog("refused");
  const before = results("clients")[2];
  if (r1?.status !== 402) p.push(`the refused request answered ${r1?.status} (${r1?.error_type ?? ""} ${r1?.error ?? ""})`);
  if (!okResult(r2 ?? {})) p.push(`the next request answered ${r2?.status}`);
  if (r2?.sid !== before?.sid || r2?.connection !== "reused; request=3") p.push(`the next request ran on ${r2?.sid} (${r2?.connection}), not B's connection as request 3`);
  // The node's refusal reached routstrd as the 402 of the request (routstrd then tries a top-up,
  // which the empty scratch wallet cannot pay, and returns the error).
  const refusedAtNode = lines("rd-refused.log").filter((l) => /Upstream error response/.test(l) && /"status":402/.test(l) && /insufficient_balance/.test(l)).length;
  if (refusedAtNode !== 1) p.push(`routstrd saw ${refusedAtNode} 402 answer(s) from the node`);
  const settled = msg(log, "confidential ws: settled");
  if (settled.length !== 1) p.push(`node: ${settled.length} settled`);
  const spent = JSON.parse(readFileSync(`${dir}/refused-money.json`, "utf8")).spent_while_low;
  if (spent !== 0) p.push(`the refusal cost ${spent} msat`);
  verdict("refused", p, `402 (${String(r1?.error ?? "").slice(0, 90)}), cost 0; then 200 on the same connection as request 3 (the node's request_refused reached routstrd as its 402)`);
}

// fallback: served on 1.1 on the same node, "2" marked bad.
{
  const p: string[] = [];
  const rs = results("fallback");
  if (rs.length !== 2 || !rs.every(okResult)) p.push("not 2 × 200 with content");
  if (!rs.every((r) => r.http === "1.1")) p.push(`framings ${rs.map((r) => r.http).join(",")}`);
  const marked = lines("rd-fallback.log").filter((l) => /framing "2" marked bad/.test(l)).length;
  if (marked !== 1) p.push(`routstrd logged ${marked} bad mark(s)`);
  const charged = msg(nodeLog("fallback"), "confidential ws: connection deposit charged");
  if (charged.length) p.push(`the failed open's deposit was charged (${charged.map((l) => l.reason).join(",")})`);
  verdict("fallback", p, `2 × 200 on "1.1" (${conns(rs)}); "2" marked bad once; the failed open's deposit released`);
}

// forced 1.1: a connection each.
{
  const p: string[] = [];
  const rs = results("forced11");
  if (rs.length !== 2 || !rs.every(okResult) || !rs.every((r) => r.http === "1.1" && r.connection === "new; request=1")) p.push(`${conns(rs)} / ${rs.map((r) => r.http).join(",")}`);
  if (new Set(rs.map((r) => r.sid)).size !== 2) p.push("one connection for two requests");
  const costs = msg(nodeLog("forced11"), "confidential ws: settled").map((l) => Number(l.cost_msats));
  if (!costs.every((c) => c >= terms.fee)) p.push(`costs ${costs.join(",")}: each connection pays the fee`);
  verdict("forced-1.1", p, `2 × 200, 2 connections, fee on each (${costs.join(",")} msat)`);
}

// armed: the 2nd and 3rd request served by armed connections.
for (const [run, http] of [["armed11", "1.1"], ["armed2", "2"]] as const) {
  const p: string[] = [];
  const rs = results(run);
  if (rs.length !== 3 || !rs.every(okResult) || !rs.every((r) => r.http === http)) p.push(`not 3 × 200 on "${http}"`);
  const want = ["new; request=1", "armed; request=1", "armed; request=1"];
  if (conns(rs) !== want.join(" | ")) p.push(`connection headers: ${conns(rs)}`);
  if (rs.map((r) => r.prewarmed).join(",") !== "0,1,1") p.push(`prewarmed ${rs.map((r) => r.prewarmed).join(",")}`);
  verdict(`armed-${http}`, p, `${conns(rs)}; ttft ${rs.map((r) => r.ttft_ms).join(", ")} ms`);
}

// upgrade: node_protocol_outdated in the error body, ?v=3, one log line for two requests.
{
  const p: string[] = [];
  const rs = results("upgrade");
  if (rs.length !== 2 || !rs.every((r) => r.status >= 400 && r.error_type === "node_protocol_outdated")) {
    p.push(`answers: ${rs.map((r) => `${r.status} ${r.error_type} ${String(r.error ?? "").slice(0, 80)}`).join(" | ")}`);
  }
  if (!rs.every((r) => /node_protocol_outdated/.test(String(r.error)))) p.push("the error message does not name node_protocol_outdated");
  const asked = lines("fake-v2.log").filter((l) => l.startsWith("offer "));
  if (!asked.length || !asked.every((l) => /\?v=3$/.test(l))) p.push(`offer requests: ${asked.join(", ") || "none"}`);
  const logged = lines("rd-upgrade.log").filter((l) => /\[confidential\] node_protocol_outdated: \S+ offers routstr-confidential v2/.test(l)).length;
  if (logged !== 1) p.push(`routstrd logged it ${logged} time(s)`);
  if (lines("fake-v2.log").some((l) => l.startsWith("unexpected"))) p.push("routstrd sent the fake node a request");
  verdict("upgrade", p, `2 × ${rs[0]?.status} node_protocol_outdated ("${String(rs[0]?.error ?? "").slice(0, 100)}"); offers asked as ${asked[0]}; logged once`);
}

// money: start − charges − deposits charged = balance; nothing reserved.
{
  const p: string[] = [];
  const m = JSON.parse(readFileSync(`${dir}/money.json`, "utf8"));
  const all = jsonl("node-all.log");
  const settled = msg(all, "confidential ws: settled");
  const charges = settled.reduce((n, l) => n + (Number(l.cost_msats) || 0), 0);
  const lost = msg(all, "confidential ws: connection deposit charged");
  const lostMsat = lost.reduce((n, l) => n + (Number(l.deposit_msat) || 0), 0);
  const back = msg(all, "confidential ws: connection deposit released");
  const taken = msg(all, "confidential ws: connection deposit reserved");
  if (m.reserved !== 0) p.push(`reserved_balance ${m.reserved}`);
  if (m.balance !== m.start - charges - lostMsat) p.push(`balance ${m.balance} != ${m.start} - ${charges} - ${lostMsat}`);
  // Only armed connections that were never used may lose their deposit.
  if (lost.some((l) => l.reason !== "unused" && l.reason !== "idle")) p.push(`deposits charged for ${lost.map((l) => l.reason).join(",")}`);
  if (taken.length !== back.length + lost.length) p.push(`${taken.length} deposits reserved, ${back.length} released, ${lost.length} charged`);
  verdict(
    "money",
    p,
    `balance ${m.balance} = ${m.start} - ${charges} (${settled.length} settlements) - ${lostMsat} (${lost.length} unused armed connection(s)); ` +
      `${taken.length} deposits: ${back.length} released, ${lost.length} charged; reserved 0`,
  );
}

// The table: time to first token at the local API, bytes between routstrd and the node.
const kb = (n: number | undefined) => (n === undefined ? "-" : n >= 1e6 ? `${(n / 1e6).toFixed(2)} MB` : `${(n / 1e3).toFixed(1)} kB`);
const rows: string[][] = [["run", "#", "http", "found", "ttft ms", "total ms", "node→client", "client→node", "arming: node→client", "client→node"]];
for (const run of ["seq", "burst", "clients", "refused", "fallback", "forced11", "armed11", "armed2"]) {
  const st = stats(run);
  for (const r of results(run)) {
    const n = Number(/request=(\d+)/.exec(r.connection ?? "")?.[1]);
    const s = st.find((x) => String(x.sid).startsWith(r.sid) && x.n === n);
    rows.push([
      run,
      String(r.label).split("-").pop()!,
      String(r.http ?? "-"),
      String(s?.warm ?? (r.status === 200 ? "?" : "-")),
      String(r.ttft_ms ?? "-"),
      String(r.total_ms ?? "-"),
      kb(s?.bytesRecv),
      kb(s?.bytesSent),
      kb(s?.armBytesRecv),
      kb(s?.armBytesSent),
    ]);
  }
}
const width = rows[0]!.map((_, i) => Math.max(...rows.map((r) => r[i]!.length)));
console.log();
for (const r of rows) console.log(r.map((c, i) => c.padEnd(width[i]!)).join("  "));
console.log("(found: cold = a connection opened for the request, armed = a pre-warmed one, open = an open framing-2 connection; bytes: 2PC, proofs, relayed records and control frames between routstrd and the node; arming = the 2PC preprocessing and key share, paid before the request when armed)");
console.log();
for (const [id, ok, evidence] of verdicts) console.log(`${ok ? "PASS" : "DEVIATION"}  ${id.padEnd(11)}  ${evidence}`);
process.exit(verdicts.every(([, ok]) => ok) ? 0 : 1);
