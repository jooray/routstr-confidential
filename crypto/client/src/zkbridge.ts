// Bridge between a spawned `cu-prover` process and a ZK WebSocket.
//
// The URL is supplied by the driver so it can point either at the sidecar
// directly (`/zk?proof=..&sid=..`) or at the node's proxy
// (`/v1/confidential/zk?proof=..&session_id=..`).

import { spawn } from 'node:child_process'

export const CU_PROVER =
  process.env.CU_PROVER ||
  new URL('../../zkbench/target/release/cu-prover', import.meta.url).pathname

export interface ZkJob {
  proof: string
  role: 'prover' | 'verifier'
  params: unknown
  witness?: unknown
}

/** Run one proof end-to-end: spawn cu-prover and pipe it to the ZK websocket. */
export interface ZkProfile {
  /** WebSocket open, from the call. */
  ws_open_ms: number
  /** First proof byte from the peer, from the call. */
  first_byte_ms: number
  /** cu-prover exit, from the call. */
  total_ms: number
  bytes_sent: number
  bytes_recv: number
}

export async function runZk(zkUrl: string, job: ZkJob, timeoutMs = 60_000): Promise<ZkProfile> {
  const t0 = Date.now()
  const prof: ZkProfile = { ws_open_ms: 0, first_byte_ms: 0, total_ms: 0, bytes_sent: 0, bytes_recv: 0 }
  const ws = new WebSocket(zkUrl)
  ws.binaryType = 'arraybuffer'

  // The job (params + witness) goes to cu-prover on stdin, length-prefixed,
  // ahead of the proof bytes: the witness never touches the disk.
  const child = spawn(CU_PROVER, ['--job-stdin', '--role', job.role], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: process.env,
  })
  const jobBytes = Buffer.from(JSON.stringify({ proof: job.proof, params: job.params, witness: job.witness ?? null }))
  const lenPrefix = Buffer.alloc(4)
  lenPrefix.writeUInt32BE(jobBytes.length)
  child.stdin.write(Buffer.concat([lenPrefix, jobBytes]))

  const pending: Buffer[] = []
  let wsOpen = false
  child.stdout.on('data', (chunk: Buffer) => {
    prof.bytes_sent += chunk.length
    if (wsOpen && ws.readyState === WebSocket.OPEN) ws.send(chunk)
    else pending.push(chunk)
  })

  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await new Promise<void>((resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`zk timeout (${timeoutMs}ms) for ${job.proof}`)),
        timeoutMs,
      )
      // A proof connection the node refuses closes without opening: fail at
      // once instead of waiting for the timeout.
      ws.onerror = () => reject(new Error(`zk ws error for ${job.proof}`))
      ws.onclose = () => reject(new Error(`zk ws closed before the ${job.proof} proof started`))
      ws.onopen = () => {
        prof.ws_open_ms = Date.now() - t0
        wsOpen = true
        for (const chunk of pending) ws.send(chunk)
        pending.length = 0
        ws.onmessage = (ev) => {
          const data = ev.data
          if (!prof.first_byte_ms) prof.first_byte_ms = Date.now() - t0
          prof.bytes_recv += (data as ArrayBuffer).byteLength ?? 0
          if (data instanceof ArrayBuffer) child.stdin.write(Buffer.from(data))
          else if (ArrayBuffer.isView(data)) child.stdin.write(Buffer.from(data.buffer))
        }
        ws.onerror = () => reject(new Error(`zk ws error for ${job.proof}`))
        ws.onclose = () => {
          try {
            child.stdin.end()
          } catch {
            /* ignore */
          }
        }
        child.on('close', (code) => {
          // 'close' (not 'exit') so all stdout data has been delivered before we
          // resolve and the caller closes the websocket: resolving on 'exit' can
          // drop the prover's final flush bytes and stall the peer's verifier.
          prof.total_ms = Date.now() - t0
          if (code === 0) resolve()
          else reject(new Error(`cu-prover exited ${code} for ${job.proof}`))
        })
        child.on('error', reject)
      }
    })
  } finally {
    if (timer) clearTimeout(timer)
    try {
      ws.close()
    } catch {
      /* ignore */
    }
    try {
      child.kill()
    } catch {
      /* ignore */
    }
  }
  return prof
}
