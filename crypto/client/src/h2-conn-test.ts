// Offline tests of the framing-"2" connection's message handling (H2Conn) with
// a fake session: no node, no provider, no prover.
//
//   node --experimental-strip-types src/h2-conn-test.ts

import { Bus, waitMsg } from './bus.ts'
import { H2Conn, type H2Ctx } from './driver-h2.ts'
import { FLAG, FRAME, type RxFrame } from './h2.ts'

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

// 4-7. One request against the provider's frames (review of PR
//      Routstr/routstr-sdk#112): the node accepts it, the records go out, and
//      the frames below arrive. `wire` shows what the node is sent.
const enc = new TextEncoder()
function requestRig(initialWindow = 65535) {
  const rig: any = fakeSession()
  const { s, conn, bus, wire } = rig
  const suffix = ',"model":"m","max_tokens":9}'
  const body = enc.encode(`{"messages":[]${suffix}`)
  Object.assign(conn.ctx, {
    offer: { upstream_host: 'api.example', head_template: 'POST /v1/chat/completions HTTP/1.1\r\n' },
    buildBody: () => ({ kind: 'chat', model: 'm', maxTokens: 9, body, suffix: enc.encode(suffix), canonicalSuffix: suffix }),
    shown: (v: unknown) => String(v),
    writePrivate: () => {},
    depositMsat: 0,
  })
  Object.assign(s, { sid: 'sid', runDir: '/nonexistent', allBytes: () => ({}), flushChain: Promise.resolve() })
  const send = s.sendText
  s.sendText = (o: any) => {
    send(o)
    if (o.type === 'request') {
      rig.onRequest()
      setTimeout(() => bus.emit({ type: 'request_ok', n: o.n, suffix, stream: 2 * o.n + 1 }), 1)
    }
    if (o.type === 'release') rig.releases.push(o.upto)
  }
  conn.initialWindow = initialWindow
  conn.settleErrorHead = async () => {
    wire.push('disclose_head')
    return { status: conn.cur.status }
  }
  return Object.assign(rig, { releases: [] as number[], onRequest: () => {} })
}
const fr = (type: number, flags: number, stream: number, payload = new Uint8Array(0)): RxFrame => ({ type, flags, stream, payload, off: 0 })
const status429 = Uint8Array.from([0x08, 0x03, ...enc.encode('429')])
const opened = async (conn: any) => {
  for (let i = 0; i < 500 && !conn.cur?.seqs.length; i++) await sleep(2)
  await sleep(10)
}

// 4. Finding 18: an error head with END_STREAM followed by RST_STREAM(NO_ERROR)
//    in one record (both frames parsed before the wait wakes) is disclosed.
{
  const { conn, wire } = requestRig()
  const r = conn.request(1).catch((e: Error) => e)
  await opened(conn)
  conn.onFrame(fr(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, 3, status429))
  conn.onFrame(fr(FRAME.RST_STREAM, 0, 3, new Uint8Array(4)))
  const out = await within(r, 5000, 'error head + reset')
  ok(out?.status === 429 && wire.includes('disclose_head'), `an error head before a reset is disclosed (got: ${out?.message ?? JSON.stringify(out?.status)})`)
}

// 5. The follow-on: an error head without END_STREAM, then a reset, ends the
//    error-body wait at once; a reset without an error head still fails.
{
  const { conn, wire } = requestRig()
  const r = conn.request(1).catch((e: Error) => e)
  await opened(conn)
  conn.onFrame(fr(FRAME.HEADERS, FLAG.END_HEADERS, 3, status429))
  await sleep(20)
  const t = Date.now()
  conn.onFrame(fr(FRAME.RST_STREAM, 0, 3, new Uint8Array(4)))
  const out = await within(r, 5000, 'error head, then reset')
  ok(out?.status === 429 && wire.includes('disclose_head') && Date.now() - t < 1000, `the error-body wait ends on the reset (${Date.now() - t} ms)`)
}
{
  const { conn, wire } = requestRig()
  const r = conn.request(1).catch((e: Error) => e)
  await opened(conn)
  conn.onFrame(fr(FRAME.RST_STREAM, 0, 3, Uint8Array.from([0, 0, 0, 2])))
  const out = await within(r, 5000, 'reset alone')
  ok(String(out).includes('reset stream 3') && !wire.includes('disclose_head'), `a reset without an error head fails the request (got: ${out})`)
}

// 6. GOAWAY: a stream above its last-stream-id is not released, and the
//    request ends without waiting out its timeouts.
{
  const rig = requestRig(0)
  const { conn, releases } = rig
  // The GOAWAY (last stream 1, the probe's) arrives while the node accepts the request.
  rig.onRequest = () => conn.onFrame(fr(FRAME.GOAWAY, 0, 0, Uint8Array.from([0, 0, 0, 1, 0, 0, 0, 0])))
  const r = conn.request(1).catch((e: Error) => e)
  const out = await within(r, 5000, 'goaway')
  ok(String(out).includes("GOAWAY (last stream 1) excludes stream 3") && releases.length === 0, `nothing of a stream beyond GOAWAY is released (got: ${out}, releases ${releases})`)
}

// 7. SETTINGS_INITIAL_WINDOW_SIZE applies to the open stream (RFC 9113 §6.9.2).
{
  const { conn, releases } = requestRig(0)
  const r = conn.request(1).catch((e: Error) => e)
  await opened(conn)
  ok(releases.join() === '1', `only the HEADERS record is released without stream credit (${releases})`)
  conn.onFrame(fr(FRAME.SETTINGS, 0, 0, Uint8Array.from([0x00, 0x04, 0x00, 0x01, 0x00, 0x00])))
  await sleep(5)
  ok(conn.cur.streamCredit === 0x10000 && releases.join() === '1,2', `the new initial window releases the body (${releases})`)
  conn.failRej(new Error('stop'))
  await r
}

console.log(`h2-conn-test: ${checks} checks passed`)
process.exit(0)
