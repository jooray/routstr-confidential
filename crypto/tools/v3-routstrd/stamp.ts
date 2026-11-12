// Reads an SSE chat-completion stream on stdin (from curl -N) and prints when
// the first content token and the end arrived, relative to <t0 ms> (argv[2]).
//   curl -sS -N ... | bun stamp.ts <t0> <label> <header file>
import { readFileSync } from "node:fs";

const t0 = Number(process.argv[2]);
const label = process.argv[3] ?? "";
const headerFile = process.argv[4];
let firstByte: number | undefined;
let firstToken: number | undefined;
let text = "";
let buf = "";
let all = "";
const dec = new TextDecoder();
for await (const chunk of Bun.stdin.stream()) {
  const now = Date.now();
  if (firstByte === undefined) firstByte = now - t0;
  const piece = dec.decode(chunk, { stream: true });
  if (all.length < 4096) all += piece;
  buf += piece;
  let i: number;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.startsWith("data: {")) continue;
    try {
      const c = JSON.parse(line.slice(6)).choices?.[0]?.delta?.content;
      if (typeof c === "string" && c.length) {
        if (firstToken === undefined) firstToken = now - t0;
        text += c;
      }
    } catch {
      /* not JSON */
    }
  }
  if (buf.includes("[DONE]")) text += "";
}
const total = Date.now() - t0;
let errorBody: any;
try {
  if (firstToken === undefined && all.trim().startsWith("{")) errorBody = JSON.parse(all);
} catch {
  /* not JSON */
}
let headers = "";
try {
  headers = readFileSync(headerFile!, "utf8");
} catch {
  /* none */
}
const h = (name: string) => new RegExp(`^${name}: (.*)$`, "im").exec(headers)?.[1]?.trim();
console.log(
  JSON.stringify({
    label,
    status: Number(/^HTTP\/\S+ (\d+)/m.exec(headers)?.[1] ?? 0),
    // An error's body (no stream): its type and message, for the verdicts.
    error_type: errorBody?.error_type,
    error: typeof errorBody?.error === "string" ? errorBody.error.slice(0, 300) : errorBody?.error?.message?.slice?.(0, 300) ?? (errorBody ? JSON.stringify(errorBody).slice(0, 300) : undefined),
    first_byte_ms: firstByte,
    ttft_ms: firstToken,
    total_ms: total,
    http: h("x-routstr-confidential-http"),
    connection: h("x-routstr-confidential-connection"),
    prewarmed: h("x-routstr-confidential-prewarmed"),
    sid: h("x-routstr-confidential-sid")?.slice(0, 8),
    verify: h("x-routstr-verify"),
    text: text.slice(0, 40),
  }),
);
