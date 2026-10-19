// Bridge between a long-lived `cu-prover --channel` process and the node's
// `zkchan` WebSocket: the v2 session's proof channel. The OT/VOLE setup for
// π_NK, π_C2S and π_C3S runs once, when the session is armed; each proof at
// claim time then costs a couple of round trips.
//
// stdin/stdout carry frames [channel u8][len u32 BE][payload]: channel 0 is
// the proof protocol (relayed to the WebSocket), channel 1 is control JSON.
// Witnesses go to the process on stdin only; nothing here logs them.

import { spawn, type ChildProcess } from 'node:child_process'

export const CU_PROVER =
  process.env.CU_PROVER ||
  new URL('../../zkbench/target/release/cu-prover', import.meta.url).pathname

function frame(ch: number, payload: Uint8Array): Buffer {
  const b = Buffer.alloc(5 + payload.length)
  b[0] = ch
  b.writeUInt32BE(payload.length, 1)
  Buffer.from(payload).copy(b, 5)
  return b
}

export interface ZkDone {
  ok: boolean
  proof: string
  checks?: { label: string; ok: boolean }[]
  ms?: number
  bytes_sent?: number
  bytes_recv?: number
  err?: string
}

export class ZkChan {
  private child!: ChildProcess
  private ws!: WebSocket
  private buf = Buffer.alloc(0)
  private wsOpen = false
  private outbox: Buffer[] = []
  private nextId = 1
  private pending = new Map<number, { res: (m: ZkDone) => void; rej: (e: Error) => void }>()
  private readyP: Promise<any>
  private readyRes!: (m: any) => void
  private readyRej!: (e: Error) => void
  failure: Error | undefined
  /** At least one proof was started on the channel (no per-proof fallback after this). */
  used = false
  readyInfo: any
  readonly tStart = Date.now()
  tReady = 0

  constructor() {
    this.readyP = new Promise((res, rej) => {
      this.readyRes = res
      this.readyRej = rej
    })
    // Never an unhandled rejection: callers look at `failure`.
    this.readyP.catch(() => {})
  }

  start(url: string): void {
    this.ws = new WebSocket(url)
    this.ws.binaryType = 'arraybuffer'
    this.ws.onopen = () => {
      this.wsOpen = true
      for (const b of this.outbox) this.ws.send(b)
      this.outbox.length = 0
    }
    this.ws.onmessage = (ev) => {
      const d = ev.data
      const bytes = d instanceof ArrayBuffer ? new Uint8Array(d) : new Uint8Array((d as any).buffer ?? d)
      this.child.stdin?.write(frame(0, bytes))
    }
    this.ws.onerror = () => this.fail(new Error('proof channel websocket error'))
    this.ws.onclose = () => this.fail(new Error('proof channel websocket closed'))
    const args = ['--channel']
    if (process.env.CU_PREALLOC_NK) args.push('--prealloc-nk', process.env.CU_PREALLOC_NK)
    if (process.env.CU_PREALLOC_CP) args.push('--prealloc-cp', process.env.CU_PREALLOC_CP)
    this.child = spawn(CU_PROVER, args, { stdio: ['pipe', 'pipe', 'inherit'], env: process.env })
    this.child.on('error', (e) => this.fail(e))
    this.child.on('close', (code) => this.fail(new Error(`cu-prover --channel exited ${code}`)))
    this.child.stdout!.on('data', (chunk: Buffer) => this.onData(chunk))
  }

  private onData(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk])
    while (this.buf.length >= 5) {
      const len = this.buf.readUInt32BE(1)
      if (this.buf.length < 5 + len) break
      const ch = this.buf[0]
      const payload = this.buf.subarray(5, 5 + len)
      this.buf = this.buf.subarray(5 + len)
      if (ch === 0) {
        const out = Buffer.from(payload)
        if (this.wsOpen) this.ws.send(out)
        else this.outbox.push(out)
      } else if (ch === 1) {
        this.onControl(JSON.parse(payload.toString('utf8')))
      }
    }
  }

  private onControl(m: any): void {
    if (m.ev === 'ready') {
      this.tReady = Date.now()
      this.readyInfo = m
      this.readyRes(m)
    } else if (m.ev === 'done') {
      const w = this.pending.get(m.id)
      if (w) {
        this.pending.delete(m.id)
        w.res(m)
      }
    } else if (m.ev === 'error') {
      this.fail(new Error(`cu-prover: ${m.msg}`))
    }
  }

  private fail(e: Error): void {
    if (this.failure) return
    this.failure = e
    this.readyRej(e)
    for (const w of this.pending.values()) w.rej(e)
    this.pending.clear()
  }

  /** Resolves when both correlation chains are preprocessed; false if the channel failed. */
  async ready(ms = 120_000): Promise<boolean> {
    if (this.failure) return false
    let t: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([
        this.readyP,
        new Promise((_, rej) => (t = setTimeout(() => rej(new Error('proof channel not ready in time')), ms))),
      ])
      return !this.failure
    } catch (e) {
      this.fail(e as Error)
      return false
    } finally {
      if (t) clearTimeout(t)
    }
  }

  /** Run one proof on the channel. Throws if it fails (the session is then over). */
  async run(cmd: 'prove' | 'verify', proof: string, params: unknown, witness?: unknown, ms = 60_000): Promise<ZkDone> {
    if (this.failure) throw this.failure
    this.used = true
    const id = this.nextId++
    const p = new Promise<ZkDone>((res, rej) => {
      const t = setTimeout(() => {
        this.pending.delete(id)
        rej(new Error(`proof channel: ${proof} timed out`))
      }, ms)
      this.pending.set(id, {
        res: (m) => (clearTimeout(t), res(m)),
        rej: (e) => (clearTimeout(t), rej(e)),
      })
    })
    this.child.stdin?.write(frame(1, Buffer.from(JSON.stringify({ cmd, id, proof, params, witness: witness ?? null }))))
    const m = await p
    if (!m.ok) throw new Error(`proof channel: ${proof} failed: ${m.err}`)
    // A verification with no checks proved nothing: refused like a failed one.
    if (cmd === 'verify' && !(m.checks?.length && m.checks.every((c) => c.ok))) throw new Error(`proof channel: ${proof} checks failed`)
    return m
  }

  close(): void {
    try {
      this.child.stdin?.write(frame(1, Buffer.from(JSON.stringify({ cmd: 'close' }))))
      this.child.stdin?.end()
    } catch {
      /* ignore */
    }
    // Give the process a moment to flush its last bytes before the socket goes.
    setTimeout(() => {
      try {
        this.ws.close()
      } catch {
        /* ignore */
      }
      try {
        this.child.kill()
      } catch {
        /* ignore */
      }
    }, 500).unref?.()
  }
}
