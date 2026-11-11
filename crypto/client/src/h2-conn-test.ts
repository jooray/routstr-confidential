// Offline tests of the framing-"2" connection's message handling (H2Conn) with
// a fake session: no node, no provider, no prover.
//
//   node --experimental-strip-types src/h2-conn-test.ts

import { Bus, waitMsg } from './bus.ts'
import { H2Conn, type H2Ctx } from './driver-h2.ts'
import { FRAME, type RxFrame } from './h2.ts'

let checks = 0
function ok(cond: unknown, what: string): void {
  checks++
  if (!cond) {
    console.error(`FAIL: ${what}`)
    process.exit(1)
  }
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
const within = <T>(p: Promise<T>, ms: number, what: string): Promise<T> =>
  Promise.race([p, sleep(ms).then(() => Promise.reject(new Error(`${what}: no outcome within ${ms} ms`)))])

/** A session as far as H2Conn uses it; `wire` is what reaches the node, in order. */
function fakeSession(writeDelayMs = 0) {
  const bus = new Bus()
  const errP = new Promise<never>(() => {})
  const wire: string[] = []
  const s: any = {
    bus,
    errP,
    label: 'test',
    postHandshake: true,
    serverPost: [{ data: true, keyUpdates: 0 }],
    serverRecords: [],
    waitT: (type: string | string[], ms: number, ...stops: Promise<unknown>[]) => waitMsg(bus, type, ms, errP, ...stops),
    framing: '2',
    sendText: (o: any) => wire.push(o.type === 'ctl' ? `ctl:${o.frame}` : o.type),
    tls: {
      writeInner: async (plain: Uint8Array) => {
        // Sealing a record is asynchronous (WebCrypto).
        await sleep(writeDelayMs)
        const record = new Uint8Array(5 + plain.length + 16)
        record[0] = 0x17
        conn.onWrite(record)
        wire.push('record')
      },
    },
  }
  const ctx = { log: () => {} } as unknown as H2Ctx
  const conn: any = new H2Conn(s, ctx)
  return { s, conn, bus, wire }
}

function cur(n: number): any {
  return { n, stream: 2 * n - 1, model: 'm', tStart: 0, recvAtSend: 0, seqs: [], dataLens: [], upto: 0, streamCredit: 65535, released: true, parts: [], ended: true }
}

// 1. A waiter that lost a race must not stay on the bus. Request 1 settles on
//    its `attestation`; request 2's `disclose_retry` must reach request 2.
{
  const { s, conn, bus } = fakeSession()
  conn.drained = async () => {}
  conn.usageDisclosure = () => ({ r: new Uint8Array(1), tailLens: [1], serverRecords: 1, ownUsage: {}, text: '' })
  conn.checkAttestation = async () => {
    throw new Error('stop: attestation')
  }
  let retried = 0
  conn.until = async () => {
    retried++
    throw new Error('stop: retry')
  }
  const sent = () => new Promise<void>((res) => {
    const orig = s.sendText
    s.sendText = (o: any) => {
      orig(o)
      if (o.type === 'disclose') {
        s.sendText = orig
        setTimeout(res, 5)
      }
    }
  })

  let d = sent()
  const r1 = conn.settleUsage(cur(1)).catch((e: Error) => e)
  await d
  bus.emit({ type: 'attestation' })
  ok(String(await within(r1, 1000, 'request 1')).includes('stop: attestation'), 'request 1 settles on its attestation')

  d = sent()
  const r2 = conn.settleUsage(cur(2)).catch((e: Error) => e)
  await d
  bus.emit({ type: 'disclose_retry', n: 2, server_records: 2 })
  const e2 = await within(r2, 1000, 'request 2').catch((e: Error) => e)
  ok(String(e2).includes('stop: retry') && retried === 1, `request 2 gets its own disclose_retry (got: ${e2})`)
}

// 2. A timed-out wait is withdrawn: the frame it waited for goes to the next wait.
{
  const bus = new Bus()
  const e = await waitMsg(bus, 'x', 5).catch((err: Error) => err)
  ok(String(e).includes('timeout waiting for x'), 'the wait times out')
  bus.emit({ type: 'x', v: 1 })
  ok((await within(waitMsg(bus, 'x', 1000), 1000, 'second wait')).v === 1, 'the next wait gets the frame')
}

// 3. A `ctl` text frame is directly followed by its record: nothing the
//    connection sends meanwhile (here a `release`) gets in between.
{
  const { conn, wire } = fakeSession(20)
  const c = cur(1)
  c.released = false
  c.dataLens = [10]
  conn.cur = c
  const f = (type: number, flags: number, payload: Uint8Array): RxFrame => ({ type, flags, stream: 0, payload, off: 0 })
  conn.onFrame(f(FRAME.PING, 0, new Uint8Array(8)))
  // The PING's acknowledgement is being sealed when a WINDOW_UPDATE arrives.
  for (let i = 0; i < 50 && !wire.includes('ctl:ping_ack'); i++) await sleep(1)
  ok(wire.includes('ctl:ping_ack'), 'the ping acknowledgement started')
  conn.onFrame(f(FRAME.WINDOW_UPDATE, 0, Uint8Array.from([0, 0, 0x10, 0])))
  for (let i = 0; i < 200 && wire.length < 3; i++) await sleep(1)
  await sleep(30)
  const at = wire.indexOf('ctl:ping_ack')
  ok(wire[at + 1] === 'record', `ctl is followed by its record (wire: ${wire.join(', ')})`)
  ok(wire.includes('release'), 'the release was sent')
}

console.log(`h2-conn-test: ${checks} checks passed`)
process.exit(0)
