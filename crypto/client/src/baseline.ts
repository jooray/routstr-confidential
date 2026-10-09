// Baseline: the same request as a plain direct HTTPS streaming call, for the
// end-to-end latency comparison (SPEC §11).
//
// Usage: VENICE_API_KEY=... node --experimental-strip-types src/baseline.ts [runs]

import { request } from 'node:https'

const RUNS = Number(process.argv[2] ?? '10')
const MODEL = process.env.CU_MODEL ?? 'mistral-small-3-2-24b-instruct'
const MAX_TOKENS = Number(process.env.CU_MAX_TOKENS ?? '12')
const PROMPT = process.env.CU_PROMPT ?? 'Say hi in three words.'

const suffix =
  `,"model":${JSON.stringify(MODEL)},"max_tokens":${MAX_TOKENS},` +
  `"max_completion_tokens":${MAX_TOKENS},"n":1,"stream":true,` +
  `"stream_options":{"include_usage":true},` +
  `"venice_parameters":{"include_venice_system_prompt":false,"enable_web_search":"off"}}`
const body = `{"messages":[{"role":"user","content":${JSON.stringify(PROMPT)}}]` + suffix

function oneRun(): Promise<{ ttft: number; total: number; bytes: number }> {
  return new Promise((resolve, reject) => {
    const key = process.env.VENICE_API_KEY
    if (!key) return reject(new Error('VENICE_API_KEY not set'))
    const start = Date.now()
    let ttft = 0
    let bytes = 0
    const req = request(
      {
        host: 'api.venice.ai',
        path: '/api/v1/chat/completions',
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          Accept: 'text/event-stream',
          'Accept-Encoding': 'identity',
          Connection: 'close',
        },
      },
      (res) => {
        res.on('data', (chunk: Buffer) => {
          if (!ttft) ttft = Date.now() - start
          bytes += chunk.length
        })
        res.on('end', () => resolve({ ttft, total: Date.now() - start, bytes }))
      },
    )
    req.on('error', reject)
    req.end(body)
  })
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b)
  const m = Math.floor(s.length / 2)
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

const runs: { ttft: number; total: number; bytes: number }[] = []
for (let i = 0; i < RUNS; i++) {
  const r = await oneRun()
  runs.push(r)
  process.stderr.write(`run ${i + 1}/${RUNS}: ttft=${r.ttft}ms total=${r.total}ms bytes=${r.bytes}\n`)
}
const out = {
  runs: RUNS,
  ttft_median_ms: median(runs.map((r) => r.ttft)),
  total_median_ms: median(runs.map((r) => r.total)),
  all: runs,
}
console.log(JSON.stringify(out, null, 2))
