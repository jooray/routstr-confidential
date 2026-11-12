// A node that still runs protocol v2, for v3-routstrd-check.sh: it lists the
// real node's models (so routstrd routes to it) and serves a v2 confidential
// offer. A v3 client must not use it and must say `node_protocol_outdated`.
//   bun fake-v2-node.ts <port> <real node url>
// Prints one line per offer request (path and query) on stdout.
const port = Number(process.argv[2]);
const real = process.argv[3]!.replace(/\/$/, "");
const offer = (await (await fetch(`${real}/v1/confidential/offer?v=3`)).json()) as Record<string, unknown>;
// The v2 shape: no framing list, no key-schedule name, no connection terms; unsigned
// (the version is read before anything else, whoever signed the offer).
const { sig: _s, sig_payload: _p, twopc: _t, http: _h, h2: _b, connection_deposit_msat: _d, idle_timeout_s: _i, ...rest } = offer;
const v2 = { ...rest, v: 2, min_v: 2, max_v: 2 };
Bun.serve({
  port,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/v1/confidential/offer") {
      console.log(`offer ${url.pathname}${url.search}`);
      return Response.json(v2);
    }
    if (req.method === "GET") {
      // Models, info: the real node's, with this node's URL in place of its own.
      const r = await fetch(`${real}${url.pathname}${url.search}`);
      const text = (await r.text()).split(real).join(`http://127.0.0.1:${port}`);
      return new Response(text, { status: r.status, headers: { "content-type": r.headers.get("content-type") ?? "application/json" } });
    }
    console.log(`unexpected ${req.method} ${url.pathname}`);
    return Response.json({ detail: "this fake node serves nothing" }, { status: 503 });
  },
});
console.log(`fake v2 node on ${port}`);
