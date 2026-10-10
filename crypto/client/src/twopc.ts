// Bridge between a spawned `cu-2pc` process (the client side of the protocol
// v2 two-party handshake) and the node's `twopc` WebSocket.
//
// stdin/stdout carry frames [channel u8][len u32 BE][payload]: channel 0 is
// the 2PC protocol (relayed to the WebSocket), channel 1 is control JSON.
// The secrets the process returns stay in this process; none is logged.

import { spawn, type ChildProcess } from 'node:child_process'

import { fromHex, hex } from './advice.ts'

export const CU_2PC =
  process.env.CU_2PC || new URL('../../zkbench/target/release/cu-2pc', import.meta.url).pathname

export interface HsOut {
  clientHs: Uint8Array
  serverHs: Uint8Array
}

export interface ApOut {
  serverAp0: Uint8Array
  clientAp1: Uint8Array
  h1: Uint8Array
  h2: Uint8Array
  hk: Uint8Array
}

function frame(ch: number, payload: Uint8Array): Buffer {
  const b = Buffer.alloc(5 + payload.length)
  b[0] = ch
  b.writeUInt32BE(payload.length, 1)
  Buffer.from(payload).copy(b, 5)
  return b
}

export class TwoPc {
  private child!: ChildProcess
  private ws!: WebSocket
  private buf = Buffer.alloc(0)
  private waiters = new Map<string, { res: (m: any) => void; rej: (e: Error) => void }>()
  private queued = new Map<string, any>()
  private failure: Error | undefined
  private wsOpen = false
  private outbox: Buffer[] = []
  readonly timings: any[] = []

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
    this.ws.onerror = () => this.fail(new Error('2PC websocket error'))
    this.ws.onclose = () => {
      if (!this.waiters.size) return
      this.fail(new Error('2PC websocket closed'))
    }
    this.child = spawn(CU_2PC, [], { stdio: ['pipe', 'pipe', 'inherit'], env: process.env })
    this.child.on('error', (e) => this.fail(e))
    this.child.on('close', (code) => {
      if (code !== 0) this.fail(new Error(`cu-2pc exited ${code}`))
    })
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
    if (m.ev === 'timing') {
      this.timings.push(m)
      return
    }
    if (m.ev === 'error') {
      this.fail(new Error(`cu-2pc: ${m.msg}`))
      return
    }
    const w = this.waiters.get(m.ev)
    if (w) {
      this.waiters.delete(m.ev)
      w.res(m)
    } else this.queued.set(m.ev, m)
  }

  private fail(e: Error): void {
    if (this.failure) return
    this.failure = e
    for (const w of this.waiters.values()) w.rej(e)
    this.waiters.clear()
  }

  private wait(ev: string, ms: number): Promise<any> {
    if (this.failure) return Promise.reject(this.failure)
    const q = this.queued.get(ev)
    if (q) {
      this.queued.delete(ev)
      return Promise.resolve(q)
    }
    return new Promise((res, rej) => {
      const t = setTimeout(() => {
        this.waiters.delete(ev)
        rej(new Error(`timeout waiting for 2PC ${ev}`))
      }, ms)
      this.waiters.set(ev, {
        res: (m) => (clearTimeout(t), res(m)),
        rej: (e) => (clearTimeout(t), rej(e)),
      })
    })
  }

  private send(cmd: object): void {
    this.child.stdin?.write(frame(1, Buffer.from(JSON.stringify(cmd))))
  }

  /** Preprocessing plus the commit-then-open joint key share P = P_C + P_N. */
  async keyShare(ms = 120_000): Promise<Uint8Array> {
    const m = await this.wait('key_share', ms)
    return fromHex(m.p)
  }

  /** ECtF + phase A: the handshake traffic secrets. */
  async handshake(serverShare: Uint8Array, thSH: Uint8Array, ms = 12_000): Promise<HsOut> {
    this.send({ cmd: 'handshake', s: hex(serverShare), th_sh: hex(thSH) })
    const m = await this.wait('hs', ms)
    return { clientHs: fromHex(m.c_hs), serverHs: fromHex(m.s_hs) }
  }

  /** Phase B: s_ap_0 and c_ap_1 for us; h1, h2, hk public. */
  async application(thSF: Uint8Array, ms = 30_000): Promise<ApOut> {
    this.send({ cmd: 'app', th_sf: hex(thSF) })
    const m = await this.wait('ap', ms)
    return {
      serverAp0: fromHex(m.s_ap_0),
      clientAp1: fromHex(m.c_ap_1),
      h1: fromHex(m.h1),
      h2: fromHex(m.h2),
      hk: fromHex(m.hk),
    }
  }

  close(): void {
    try {
      this.child.stdin?.end()
    } catch {
      /* ignore */
    }
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
  }
}
