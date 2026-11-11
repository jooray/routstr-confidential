// Framing "2" of the reference driver (PROTOCOL-V3.md §5, §12.6, §12.8): one
// two-party handshake, the node writes the HTTP/2 connection head with the
// credential in epoch 0, and this client then sends sequential requests on
// the same TLS connection, naming the credential by HPACK index.
//
// Everything up to `head_written` (setup, 2PC, handshake, π_NK) is the
// driver's `Session`; this file is the connection after it: the frame layer,
// `settings_seen`, the proof pump for the client's records (π_WIN), flow
// control by `release`, and the per-request disclosure, attestation and
// receipt.

import { createHash } from 'node:crypto'

import { concat, hex } from './advice.ts'
import { advOutcome, noteDepositRelease, openRequest, takeReceipt, type Ctx, type ImageTerms } from './ctx.ts'
import {
  FLAG, FRAME, FrameReader, chatPath, checkPiWinParams, decodeBlock, frame, frameHeader,
  requestBlock, requestStream, splitBody, type RxFrame, type WinSource,
} from './h2.ts'
import { checkPiC3SParams, serverTailEpoch } from './params.ts'

export type H2Ctx = Ctx

/** One record this client sent after the handshake. */
interface OutRec {
  seq: number
  wire: Uint8Array
  plain: Uint8Array
  pub: [number, number][]
}

interface Desc {
  plain: Uint8Array
  pub: [number, number][]
}

/** The request in flight. */
interface Cur {
  n: number
  stream: number
  model: string
  tStart: number
  /** Server application-data records we had received when we sent it. */
  recvAtSend: number
  /** Stream offset of the first frame on the request's stream. */
  firstFrameOff?: number
  seqs: number[]
  dataLens: number[]
  upto: number
  streamCredit: number
  released: boolean
  tReleased?: number
  tFirstData?: number
  status?: number
  head?: { off: number; raw: Uint8Array }
  parts: { off: number; data: Uint8Array }[]
  ended: boolean
  reset?: number
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
const u32 = (b: Uint8Array, i = 0) => ((b[i]! << 24) | (b[i + 1]! << 16) | (b[i + 2]! << 8) | b[i + 3]!) >>> 0

export class H2Conn {
  readonly s: any
  readonly ctx: H2Ctx
  readonly reader = new FrameReader()
  /** Encrypted server records of the handshake flight. */
  hsCipher = 0
  private curAbs = -1
  /** Inner plaintext (with type byte and padding) of post-handshake server records, by index. */
  private plain = new Map<number, Uint8Array>()
  private out = new Map<number, OutRec>()
  private nextSeq = 0
  private pendingDesc: Desc | undefined
  private tx: Promise<void> = Promise.resolve()
  private failRej!: (e: Error) => void
  readonly failP: Promise<never>
  // The provider's settings and our send credit.
  gotSettings = false
  initialWindow = 65535
  connCredit = 65535
  private unackedSettings = 0
  private requestOpen = false
  goaway = false
  cur: Cur | undefined
  proofs: any[] = []
  /** The last usage disclosure sent (the replay probe presents it again). */
  private lastDisclosure: any
  /** The provider's SETTINGS_HEADER_TABLE_SIZE (the last value it sent; null: never, the default 4096). */
  tableSize: number | null = null
  private settingsSeenSent = false

  constructor(s: any, ctx: H2Ctx) {
    this.s = s
    this.ctx = ctx
    this.failP = new Promise<never>((_, rej) => (this.failRej = rej))
    this.failP.catch(() => {})
  }

  // --- hooks called by the driver's TLS callbacks -------------------------

  /** A record the TLS client wrote (the driver relays it). */
  onWrite(record: Uint8Array): void {
    const d = this.pendingDesc
    if (!d) return // handshake records
    this.pendingDesc = undefined
    const seq = this.nextSeq++
    this.out.set(seq, { seq, wire: record, plain: d.plain, pub: d.pub })
    this.lastSeq = seq
  }
  private lastSeq = -1

  /** Every record the TLS client read (before it is processed). */
  onRead(ctx: any): void {
    if (ctx?.type !== 'ciphertext') return
    if (!this.s.postHandshake) {
      this.hsCipher++
      return
    }
    this.curAbs = this.hsCipher + this.s.serverPost.length
    if (ctx.plaintext) this.plain.set(this.curAbs, ctx.plaintext)
  }

  /** Decrypted application data of the record `onRead` just announced. */
  onData(content: Uint8Array): void {
    try {
      for (const f of this.reader.push(content, this.curAbs)) this.onFrame(f)
    } catch (e) {
      this.failRej(e as Error)
    }
  }

  onControl(m: any): void {
    if (m.type === 'body_released' && this.cur && m.n === this.cur.n) {
      this.cur.released = true
      this.cur.tReleased = Date.now()
    }
  }

  /** §12.6: the provider's HEADER_TABLE_SIZE so far; before the first request and whenever a later SETTINGS carries it. */
  sendSettingsSeen(): void {
    this.settingsSeenSent = true
    this.sendOrdered({ type: 'settings_seen', header_table_size: this.tableSize })
  }

  private onFrame(f: RxFrame): void {
    const cur = this.cur
    if (cur && f.stream === cur.stream && cur.firstFrameOff === undefined) cur.firstFrameOff = f.off
    switch (f.type) {
      case FRAME.SETTINGS: {
        if (f.flags & FLAG.ACK) break
        let carried = false
        for (let i = 0; i + 6 <= f.payload.length; i += 6) {
          const id = (f.payload[i]! << 8) | f.payload[i + 1]!
          const v = u32(f.payload, i + 2)
          if (id === 4) this.initialWindow = v
          if (id === 1) {
            this.tableSize = v
            carried = true
          }
        }
        this.gotSettings = true
        this.ctx.log({ ev: 'h2_settings', initial_window: this.initialWindow, header_table_size: this.tableSize })
        if (carried && this.settingsSeenSent) this.sendSettingsSeen()
        // Acknowledged with the next request's records (one π_WIN for both)
        // when none is open, else at once.
        if (this.requestOpen) void this.sendCtl('settings_ack', new Uint8Array(0))
        else this.unackedSettings++
        break
      }
      case FRAME.PING:
        if (!(f.flags & FLAG.ACK)) void this.sendCtl('ping_ack', f.payload)
        break
      case FRAME.WINDOW_UPDATE: {
        const inc = u32(f.payload) & 0x7fffffff
        if (f.stream === 0) this.connCredit += inc
        else if (cur && f.stream === cur.stream) cur.streamCredit += inc
        this.updateRelease()
        break
      }
      case FRAME.GOAWAY:
        this.goaway = true
        this.ctx.log({ ev: 'h2_goaway' })
        break
      case FRAME.RST_STREAM:
        if (cur && f.stream === cur.stream) cur.reset = u32(f.payload)
        break
      case FRAME.HEADERS: {
        if (!cur || f.stream !== cur.stream) break // the probe stream's answer, if any
        if (!(f.flags & FLAG.END_HEADERS) || f.flags & (FLAG.PADDED | FLAG.PRIORITY)) {
          throw new Error('h2: a response HEADERS frame with CONTINUATION, padding or priority')
        }
        const status = decodeBlock(f.payload).find(([n]) => n === ':status')?.[1]
        if (status !== undefined && (cur.status === undefined || cur.status < 200)) {
          cur.status = Number(status)
          cur.head = { off: f.off, raw: concat(frameHeader(f.payload.length, f.type, f.flags, f.stream), f.payload) }
        }
        if (f.flags & FLAG.END_STREAM) cur.ended = true
        break
      }
      case FRAME.DATA:
        if (!cur || f.stream !== cur.stream) break
        if (f.flags & FLAG.PADDED) throw new Error('h2: a padded DATA frame')
        if (!cur.tFirstData) cur.tFirstData = Date.now()
        cur.parts.push({ off: f.off + 9, data: f.payload })
        if (f.flags & FLAG.END_STREAM) cur.ended = true
        break
      default:
        break
    }
  }

  // --- sending --------------------------------------------------------------

  /** One record: `content` is one frame; the inner plaintext adds the type byte. */
  private sendRecord(content: Uint8Array, pub: [number, number][], ctl?: string, rawInner?: Uint8Array): Promise<number> {
    const plain = rawInner ?? concat(content, Uint8Array.from([0x17]))
    const p = this.tx.then(async () => {
      if (ctl) this.s.sendText({ type: 'ctl', frame: ctl })
      this.pendingDesc = { plain, pub }
      await this.s.tls.writeInner(plain)
      return this.lastSeq
    })
    this.tx = p.then(() => {}, (e) => this.failRej(e))
    return p
  }

  /**
   * A text frame in order with the records: a `ctl` must be directly
   * followed by its record, so nothing may be sent while one is sealed.
   */
  private sendOrdered(obj: unknown): void {
    this.tx = this.tx.then(() => this.s.sendText(obj)).then(() => {}, (e) => this.failRej(e))
  }

  private sendCtl(name: string, payload: Uint8Array): Promise<number> {
    const f =
      name === 'settings_ack' ? frame(FRAME.SETTINGS, FLAG.ACK, 0)
      : name === 'ping_ack' ? frame(FRAME.PING, FLAG.ACK, 0, payload)
      : frame(FRAME.WINDOW_UPDATE, 0, 0, payload)
    // The frame header and the final type byte are public; a PING's opaque
    // payload is the provider's and stays out of the proof.
    return this.sendRecord(f, [[0, 9], [f.length, f.length + 1]], name)
  }

  /** Release as many of the request's records as the provider's windows allow. */
  private updateRelease(): void {
    const cur = this.cur
    if (!cur || cur.dataLens.length === 0) return
    const credit = Math.min(cur.streamCredit, this.connCredit)
    let upto = 1
    let sum = 0
    for (const len of cur.dataLens) {
      if (sum + len > credit) break
      sum += len
      upto++
    }
    if (upto > cur.upto) {
      cur.upto = upto
      this.sendOrdered({ type: 'release', n: cur.n, upto })
    }
  }

  // --- the proof pump for our own records -----------------------------------

  /** Prove every batch of our records the node asks for, in order. */
  async proofPump(): Promise<void> {
    for (;;) {
      const m = await this.s.bus.wait('zk_params:pi_win:records')
      try {
        await this.proveRecords(m)
      } catch (e) {
        this.failRej(e as Error)
        return
      }
    }
  }

  private source(seq: number): WinSource | undefined {
    const r = this.out.get(seq)
    return r && { ct: r.wire.subarray(5, r.wire.length - 16), plain: r.plain, pub: r.pub }
  }

  private async proveRecords(m: any): Promise<void> {
    const first = m.first_seq
    const count = m.count
    if (!Number.isSafeInteger(first) || !Number.isSafeInteger(count) || count < 1) throw new Error('π_WIN: malformed batch')
    const covered = Array.from({ length: count }, (_, i) => first + i)
    let shape = { windows: m.params?.PiWin?.windows?.length ?? 0, ctBytes: 0 }
    if (!this.advActive) {
      shape = checkPiWinParams(m.params, {
        anchor: this.s.ap.h1,
        lookup: (seq) => (seq >= first && seq < first + count ? this.source(seq) : undefined),
        covered,
      })
    }
    const t = Date.now()
    await this.s.proof('pi_win', 'prove', m.params, { Secret: Array.from(this.s.ap.clientAp1) })
    const z = this.s.zkTimes.pi_win
    this.proofs.push({ proof: 'pi_win', purpose: 'records', n: this.cur?.n ?? 0, records: count, ...shape, ms: Date.now() - t, inner_ms: z?.inner_ms, bytes_sent: z?.bytes_sent, bytes_recv: z?.bytes_recv })
    this.ctx.log({ ev: 'pi_win_ok', first_seq: first, count, windows: shape.windows })
    for (const seq of covered) {
      // Kept only while the request is unsettled (the attestation hashes them).
      if (!this.cur?.seqs.includes(seq)) this.out.delete(seq)
    }
  }
  advActive = false

  // --- waiting ----------------------------------------------------------------

  private async until(pred: () => boolean, what: string, ms: number): Promise<void> {
    const t0 = Date.now()
    while (!pred()) {
      if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${what}`)
      await Promise.race([sleep(3), this.s.errP, this.failP])
    }
  }

  /** The next control frame of `type` (or of any of several: the frame's `type` tells which). */
  private wait(type: string | string[], ms: number): Promise<any> {
    return this.s.waitT(type, ms, this.failP)
  }

  /** Every received byte decrypted and parsed. */
  private async drained(): Promise<void> {
    for (let i = 0; i < 400; i++) {
      const c = this.s.flushChain
      await c
      if (c === this.s.flushChain) return
    }
  }

  private recvCount(): number {
    return this.hsCipher + this.s.serverPost.length
  }

  // --- one request ------------------------------------------------------------

  /** Wait for the provider's SETTINGS (its stream window), then the connection is ready. */
  async open(): Promise<void> {
    await this.until(() => this.gotSettings, "the provider's SETTINGS", 15000)
  }

  async request(n: number): Promise<any> {
    const { ctx, s } = this
    const b = ctx.buildBody(n)
    const adv = ctx.adv && ctx.adv.at === n ? ctx.adv.mode : undefined
    if (adv) this.advActive = true
    const stream = requestStream(n)
    const host: string = ctx.offer.upstream_host
    const path = adv === 'path' ? ctx.adv!.path! : b.image ? b.image.path : chatPath(ctx.offer.head_template)
    const suffixLen = b.suffix.length

    // The records of the request: HEADERS, then DATA frames.
    type Plan = { content: Uint8Array; pub: [number, number][]; raw?: Uint8Array; data: number }
    const plan: Plan[] = []
    const headers = frame(FRAME.HEADERS, FLAG.END_HEADERS, stream, requestBlock(host, path))
    plan.push({ content: headers, pub: [[0, headers.length + 1]], data: -1 })
    const parts = splitBody(b.body, suffixLen, ctx.chunk)
    const dataRec = (part: Uint8Array, last: boolean): Plan => {
      const f = frame(FRAME.DATA, last ? FLAG.END_STREAM : 0, stream, part)
      const pub: [number, number][] = [[0, 9], [f.length - (last ? suffixLen : 0), f.length + 1]]
      return { content: f, pub, data: part.length }
    }
    if (adv === 'hidden-headers') {
      // (a) A HEADERS frame for another stream inside what the node takes for
      // a DATA record: a short DATA frame, then the hidden frame.
      const hidden = frame(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, stream + 2, hiddenBlock(host, ctx.h2!.probe_path))
      const first = parts.length > 1 ? parts[0]! : b.body.subarray(0, b.body.length - suffixLen)
      const rest = parts.length > 1 ? parts.slice(1) : [b.body.subarray(b.body.length - suffixLen)]
      const content = concat(frame(FRAME.DATA, 0, stream, first), hidden)
      plan.push({ content, pub: [], data: content.length - 9 })
      rest.forEach((p, i) => plan.push(dataRec(p, i === rest.length - 1)))
    } else if (adv === 'padding') {
      // (b) Record A claims the DATA length the node derives from its size
      // but carries `d` bytes less, then the type byte and `d` bytes of TLS
      // padding. The provider would take the first `d` bytes of record B as
      // the rest of that frame, and find a hidden HEADERS frame behind them.
      const d = 16
      const privLen = b.body.length - suffixLen
      const aLen = Math.max(d + 1, Math.min(privLen, 200))
      const a = concat(frameHeader(aLen, FRAME.DATA, 0, stream), b.body.subarray(0, aLen - d))
      const rawA = concat(a, Uint8Array.from([0x17]), new Uint8Array(d))
      const hidden = frame(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, stream + 2, hiddenBlock(host, ctx.h2!.probe_path))
      const tail = frame(FRAME.DATA, FLAG.END_STREAM, stream, b.body.subarray(aLen - d))
      const bLen = d + hidden.length + tail.length - 9
      const bContent = concat(frameHeader(bLen, FRAME.DATA, FLAG.END_STREAM, stream), new Uint8Array(d - 9).fill(0x20), hidden, tail)
      plan.push({ content: a, raw: rawA, pub: [], data: aLen })
      plan.push({ content: bContent, pub: [], data: bLen })
    } else {
      parts.forEach((p, i) => plan.push(dataRec(p, i === parts.length - 1)))
    }
    const bodyLen = plan.reduce((sum, p) => sum + Math.max(p.data, 0), 0)

    const cur: Cur = {
      n, stream, model: b.model, tStart: Date.now(), recvAtSend: this.recvCount(), seqs: [], dataLens: [],
      upto: 0, streamCredit: this.initialWindow, released: false, parts: [], ended: false,
    }
    this.cur = cur
    const bytes0 = s.allBytes()
    const proofs0 = this.proofs.length

    if (adv === 'early-record') {
      // A record of a request the node has not accepted: a protocol error, the connection ends.
      await this.sendRecord(plan[0]!.content, plan[0]!.pub)
      await this.wait('error', 15000)
      throw new Error('the node answered a record with no request open with no error')
    }
    // `request`, then its answer; only then the records (§12.4). A refused
    // request leaves the connection READY and its number unused.
    const { ok, refused } = await openRequest(s, ctx, n, b, bodyLen, ctx.refuseFirst && n === 1, (o) => this.sendOrdered(o), (t, ms) => this.wait(t, ms))
    if (ok.stream !== stream) throw new Error('request_ok names another stream')
    if (!adv && ok.suffix !== b.canonicalSuffix) throw new Error('node expects a different pinned suffix than ours')
    // Any SETTINGS acknowledgement and the records go as one π_WIN batch.
    this.requestOpen = true
    while (this.unackedSettings > 0) {
      this.unackedSettings--
      void this.sendCtl('settings_ack', new Uint8Array(0))
    }
    for (const p of plan) cur.seqs.push(await this.sendRecord(p.content, p.pub, undefined, p.raw))
    cur.dataLens = plan.slice(1).map((p) => p.data)
    this.updateRelease()
    ctx.log({ ev: 'h2_request_sent', n, records: plan.length, body_len: bodyLen })

    if (adv === 'replay-usage') return await this.replayUsage(cur)

    // Released (in steps, as the provider's window opens) or refused early.
    await this.until(() => cur.released || (cur.status ?? 0) >= 400 || cur.reset !== undefined, `body_released for request ${n}`, 180000)
    await this.until(() => cur.ended || cur.reset !== undefined || (cur.status ?? 0) >= 400, `the response to request ${n}`, 600000)
    if (cur.reset !== undefined) throw new Error(`the provider reset stream ${stream} (code ${cur.reset})`)
    const status = cur.status ?? 0
    let receipt: any
    let ownUsage: any
    let text = ''
    let imageOut: any
    if (b.image && ((status >= 200 && status < 300) || (ctx.acceptAny && status > 0))) {
      await this.until(() => cur.ended, 'the end of the stream', 600000)
      receipt = await this.settleAccept(cur)
      imageOut = this.imageResult(cur, b.image)
    } else if (status >= 200 && status < 300) {
      await this.until(() => cur.ended, 'the end of the stream', 600000)
      ;({ receipt, ownUsage, text } = await this.settleUsage(cur))
    } else if (status >= 400) {
      // The error body is short; give it a moment for the evidence, no more.
      await Promise.race([this.until(() => cur.ended, 'the error body', 3000).catch(() => {}), sleep(3000)])
      receipt = await this.settleErrorHead(cur)
      text = Buffer.from(concat(...cur.parts.map((p) => p.data))).toString('utf8')
      console.log(`[client ${s.label}] request ${n}: upstream error ${status}: ${ctx.shown(text, 200)}`)
    } else {
      throw new Error(`request ${n}: status ${status} is neither a success nor a disclosable error`)
    }
    ctx.checkReceipt?.(receipt, { n, http: '2', model: b.model, status, usage: ownUsage?.usage, image: b.image, first: !s.settledOnce })
    const tEnd = Date.now()
    noteDepositRelease(s, ctx, receipt, n)

    // The request is settled: its records and its part of the stream go.
    this.connCredit -= bodyLen
    for (const seq of cur.seqs) this.out.delete(seq)
    this.reader.dropBefore(this.reader.total)
    this.plain.clear()
    this.cur = undefined
    this.requestOpen = false

    const bytes1 = s.allBytes()
    const delta: Record<string, number> = {}
    for (const k of Object.keys(bytes1)) delta[k] = (bytes1 as any)[k] - ((bytes0 as any)[k] ?? 0)
    ctx.writePrivate(`${s.runDir}/response-${n}.txt`, text)
    ctx.writePrivate(`${s.runDir}/receipt-${n}.json`, JSON.stringify(receipt, null, 2))
    return {
      n,
      http: '2',
      stream,
      model: b.model,
      refused_first: refused,
      ...(b.image ? { kind: 'images', variant: b.image.variant, count: b.image.count, ...imageOut } : {}),
      status,
      body_len: bodyLen,
      records: plan.length,
      usage: ownUsage?.usage && { prompt_tokens: ownUsage.usage.prompt_tokens, completion_tokens: ownUsage.usage.completion_tokens },
      receipt_sig_ok: receipt.unsigned ? false : true,
      cost_msats: receipt.cost_msats,
      reserved_msats: receipt.reserved_msats,
      balance_msats: receipt.balance_msats,
      released_ms: cur.tReleased ? cur.tReleased - cur.tStart : undefined,
      ttft_ms: cur.tFirstData ? cur.tFirstData - cur.tStart : undefined,
      total_ms: tEnd - cur.tStart,
      at: { start: cur.tStart, released: cur.tReleased, first_data: cur.tFirstData },
      proofs: this.proofs.slice(proofs0),
      bytes: delta,
    }
  }

  // --- disclosures ------------------------------------------------------------

  /**
   * The usage disclosure of a finished stream (A.6): R runs from the usage
   * event (its DATA frame header, or the line feed before it inside a frame)
   * to the last server byte received.
   */
  private usageDisclosure(cur: Cur): { r: Uint8Array; tailLens: number[]; serverRecords: number; ownUsage: any; text: string } {
    if (!this.reader.atBoundary()) throw new Error('the received stream does not end at a frame boundary')
    const text = Buffer.from(concat(...cur.parts.map((p) => p.data))).toString('latin1')
    const done = 'data: [DONE]\n\n'
    if (!text.endsWith(done)) throw new Error('the stream does not end with data: [DONE]')
    const before = text.slice(0, text.length - done.length)
    const at = before.lastIndexOf('\n\ndata: ', before.length - 3)
    const evStart = at >= 0 ? at + 2 : 0
    if (!before.startsWith('data: ', evStart) || !before.endsWith('\n\n')) throw new Error('no usage event before data: [DONE]')
    const ownUsage = JSON.parse(Buffer.from(before.slice(evStart + 6, before.length - 2), 'latin1').toString('utf8'))
    if (!Array.isArray(ownUsage.choices) || ownUsage.choices.length !== 0 || ownUsage.usage?.prompt_tokens === undefined) {
      throw new Error('the last event before data: [DONE] is not a usage event')
    }
    // Where the event starts in the received stream.
    let acc = 0
    let start = -1
    for (const p of cur.parts) {
      if (evStart < acc + p.data.length) {
        const within = evStart - acc
        start = within === 0 ? p.off - 9 : p.off + within - 1
        break
      }
      acc += p.data.length
    }
    if (start < 0) throw new Error('usage event not found in the received frames')
    const r = this.reader.slice(start, this.reader.total)
    const first = this.reader.recordAt(start)
    const recs = this.reader.records.filter((x) => x.abs >= first.abs)
    for (let i = 1; i < recs.length; i++) {
      if (recs[i]!.abs !== recs[i - 1]!.abs + 1) throw new Error('a record without response bytes sits inside the disclosed tail')
    }
    const serverRecords = this.recvCount()
    if (recs[recs.length - 1]!.abs !== serverRecords - 1) throw new Error('a record without response bytes follows the disclosed tail')
    return { r, tailLens: recs.map((x) => x.content.length + 1).reverse(), serverRecords, ownUsage, text: Buffer.from(text, 'latin1').toString('utf8') }
  }

  private async settleUsage(cur: Cur): Promise<{ receipt: any; ownUsage: any; text: string }> {
    const { s } = this
    for (let attempt = 0; ; attempt++) {
      await this.drained()
      const d = this.usageDisclosure(cur)
      const epoch = serverTailEpoch(s.serverPost, d.tailLens.length)
      const msg: any = { type: 'disclose', n: cur.n, r: hex(d.r), tail_lens: d.tailLens, skip: 0, server_records: d.serverRecords }
      if (epoch.keyUpdates > 0) {
        msg.key_updates = epoch.keyUpdates
        msg.epoch_start = epoch.epochStart
      }
      this.lastDisclosure = msg
      this.sendOrdered(msg)
      // One wait for either frame: a separate wait that lost would stay on
      // the bus and take the next request's frame.
      const m = await this.wait(['disclose_retry', 'attestation'], 60000)
      const next = m.type === 'disclose_retry' ? { retry: m } : { att: m }
      if ('retry' in next) {
        // More server records reached the node than we had parsed: catch up.
        if (attempt >= 20) throw new Error('the node keeps asking for a newer disclosure')
        const want = next.retry.server_records
        await this.until(() => this.recvCount() >= want, 'the server records the node counts', 15000)
        continue
      }
      const attJson = await this.checkAttestation(next.att, cur, d.serverRecords)
      const c3 = await this.wait('zk_params:pi_c3s:', 30000)
      checkPiC3SParams(c3.params, {
        h2: s.ap.h2,
        serverRecords: s.serverRecords.slice(0, d.serverRecords),
        r: d.r,
        skip: 0,
        keyUpdates: epoch.keyUpdates,
        epochBase: this.hsCipher + epoch.epochStart,
        trailing: 0,
        tailLens: d.tailLens,
      })
      const t = Date.now()
      await s.proof('pi_c3s', 'prove', c3.params, { Secret: Array.from(s.ap.serverAp0) })
      const z = s.zkTimes.pi_c3s
      this.proofs.push({ proof: 'pi_c3s', n: cur.n, r_len: d.r.length, records: d.tailLens.length, ms: Date.now() - t, inner_ms: z?.inner_ms, bytes_sent: z?.bytes_sent, bytes_recv: z?.bytes_recv })
      const receipt = await this.receipt(cur, attJson)
      const u = receipt.usage?.usage
      if (u?.prompt_tokens !== d.ownUsage.usage.prompt_tokens || u?.completion_tokens !== d.ownUsage.usage.completion_tokens) {
        throw new Error('receipt usage does not match our own plaintext')
      }
      if (receipt.model !== cur.model) throw new Error('receipt names another model than the request pinned')
      return { receipt, ownUsage: d.ownUsage, text: d.text }
    }
  }

  /**
   * A successful image response (A.13): `accept` names the server records we
   * have seen, the node closes the request's interval there, attests it and
   * settles at the flat price. Nothing is disclosed and nothing proven.
   */
  private async settleAccept(cur: Cur): Promise<any> {
    for (let attempt = 0; ; attempt++) {
      await this.drained()
      const serverRecords = this.recvCount()
      this.sendOrdered({ type: 'accept', n: cur.n, server_records: serverRecords })
      const m: any = await this.wait(['accept_retry', 'attestation'], 60000)
      const next = m.type === 'accept_retry' ? { retry: m } : { att: m }
      if ('retry' in next) {
        // More server records reached the node than we had parsed: catch up.
        if (attempt >= 20) throw new Error('the node keeps asking for a newer accept')
        const want = next.retry.server_records
        await this.until(() => this.recvCount() >= want, 'the server records the node counts', 15000)
        continue
      }
      const attJson = await this.checkAttestation(next.att, cur, serverRecords)
      const receipt = await this.receipt(cur, attJson)
      if (receipt.usage?.flat !== true) throw new Error('the settlement of an accepted image request is not flat')
      if (receipt.model !== cur.model) throw new Error('receipt names another model than the request pinned')
      return receipt
    }
  }

  /** The images of an accepted response: the body is the DATA payloads up to END_STREAM, one JSON object. */
  private imageResult(cur: Cur, image: ImageTerms): any {
    const { s, ctx } = this
    const bodyBytes = concat(...cur.parts.map((p) => p.data))
    const warnings: string[] = []
    let json: any = {}
    try {
      json = JSON.parse(Buffer.from(bodyBytes).toString('utf8'))
    } catch (e) {
      warnings.push(`response body is incomplete or not JSON: ${String(e)}`)
    }
    const images: string[] = image.responseShape === 'venice' ? json.images ?? [] : (json.data ?? []).map((d: any) => d.b64_json)
    if (images.length !== image.count) warnings.push(`${images.length} of ${image.count} images returned`)
    const files = images.map((b64, i) => {
      const f = `${s.runDir}/image-${cur.n}-${i}.webp`
      ctx.writePrivate(f, Buffer.from(b64, 'base64'))
      return f
    })
    for (const w of warnings) console.log(`[client ${s.label}] warning: ${w}`)
    console.log(`[client ${s.label}] request ${cur.n}: images ${images.length} of ${image.count} (${files.join(', ')}) response_bytes=${bodyBytes.length} frames=${cur.parts.length}`)
    return { images: images.length, files, response_bytes: bodyBytes.length, response_frames: cur.parts.length, warnings }
  }

  /** The error head (A.7): the response HEADERS frame, which must start a record. */
  private async settleErrorHead(cur: Cur): Promise<any> {
    const { s } = this
    await this.drained()
    // Our own records must be proven first (one π_WIN at a time).
    await this.until(() => [...this.out.keys()].every((seq) => cur.seqs.includes(seq)) && this.proofs.some((p) => p.proof === 'pi_win' && p.n === cur.n), 'our records to be proven', 60000)
    const head = cur.head!
    const rec = this.reader.recordAt(head.off)
    if (rec.start !== head.off) throw new Error('the error head does not start a server record: it cannot be disclosed')
    const postIdx = rec.abs - this.hsCipher
    let keyUpdates = 0
    let epochStart = 0
    for (let i = 0; i < postIdx; i++) {
      if (s.serverPost[i].keyUpdates > 0) {
        keyUpdates += s.serverPost[i].keyUpdates
        epochStart = i + 1
      }
    }
    const msg: any = { type: 'disclose_head', n: cur.n, record: rec.abs, r: hex(head.raw) }
    if (keyUpdates > 0) {
      msg.key_updates = keyUpdates
      msg.epoch_start = epochStart
    }
    this.sendOrdered(msg)
    const attJson = await this.checkAttestation(await this.wait('attestation', 60000), cur, undefined)
    const m = await this.wait('zk_params:pi_win:error_head', 30000)
    // The windows may touch only the head's bytes and each record's final type byte.
    const chunks = new Map<number, number>()
    let left = head.raw.length
    for (const x of this.reader.records.filter((x) => x.abs >= rec.abs)) {
      if (left <= 0) break
      const take = Math.min(left, x.content.length)
      chunks.set(x.abs, take)
      left -= take
    }
    const shape = checkPiWinParams(m.params, {
      anchor: s.ap.h2,
      keyUpdates,
      lookup: (seq) => {
        const abs = this.hsCipher + epochStart + seq
        const take = chunks.get(abs)
        const plain = this.plain.get(abs)
        const wire: Uint8Array | undefined = s.serverRecords[abs]
        if (take === undefined || !plain || !wire) return undefined
        return { ct: wire.subarray(0, wire.length - 16), plain, pub: [[0, take], [plain.length - 1, plain.length]] }
      },
      covered: [...chunks.keys()].map((abs) => abs - this.hsCipher - epochStart),
    })
    const t = Date.now()
    await s.proof('pi_win', 'prove', m.params, { Secret: Array.from(s.ap.serverAp0) })
    const z = s.zkTimes.pi_win
    this.proofs.push({ proof: 'pi_win', purpose: 'error_head', n: cur.n, ...shape, ms: Date.now() - t, inner_ms: z?.inner_ms, bytes_sent: z?.bytes_sent, bytes_recv: z?.bytes_recv })
    const receipt = await this.receipt(cur, attJson)
    if (receipt.usage?.error_status !== cur.status) throw new Error('error receipt does not match the disclosed status')
    return receipt
  }

  /**
   * The per-request attestation: signed by the session key, naming this
   * session, handshake and request, an interval that starts no earlier than
   * the request and no later than its response, and hashes we can recompute
   * from our own records. Returns the signed bytes.
   */
  private async checkAttestation(m: any, cur: Cur, upto: number | undefined): Promise<string> {
    const { s, ctx } = this
    const attJson: string = m.a_json ?? JSON.stringify(m.a)
    if (!ctx.verifySig(attJson, m.sig, s.ready.pubkey, m.sig_scheme)) throw new Error('attestation signature invalid')
    const a = JSON.parse(attJson)
    if (a.sid !== s.sid || a.http !== '2' || a.n !== cur.n || a.stream !== cur.stream) throw new Error('attestation names another session or request')
    if (a.th_sh !== hex(s.thSH) || a.th_sf !== hex(s.thSF)) throw new Error('attestation names another handshake')
    if (!s.cCommitHex || a.c_commit !== s.cCommitHex) throw new Error('attestation names a different head-record commitment')
    if (s.certChainHash && a.cert_chain_hash !== hex(s.certChainHash)) throw new Error('attestation names a different certificate chain')
    const sK = a.s_k
    const count = a.server_records
    if (!Number.isSafeInteger(sK) || !Number.isSafeInteger(count) || count < 0) throw new Error('attestation interval malformed')
    const firstAbs = cur.firstFrameOff === undefined ? undefined : this.reader.recordAt(cur.firstFrameOff).abs
    if (sK < cur.recvAtSend || (firstAbs !== undefined && sK > firstAbs)) throw new Error('attestation interval does not start at our request')
    const end = sK + count
    if (upto !== undefined && end !== upto) throw new Error('attestation interval does not end at our disclosure')
    await this.until(() => s.serverRecords.length >= end, 'the records the attestation counts', 15000)
    const h = createHash('sha256')
    for (let i = sK; i < end; i++) {
      const p: Uint8Array = s.serverRecords[i]
      h.update(Uint8Array.from([0x17, 0x03, 0x03, p.length >> 8, p.length & 0xff]))
      h.update(p)
    }
    if (a.sha256_recv !== h.digest('hex')) throw new Error('attestation hashes different upstream records than we received')
    const sent = a.client_records
    if (!Number.isSafeInteger(sent) || sent > cur.seqs.length || (cur.released && sent !== cur.seqs.length)) {
      throw new Error('attestation counts other request records than we sent')
    }
    const hs = createHash('sha256')
    for (const seq of cur.seqs.slice(0, sent)) hs.update(this.out.get(seq)!.wire)
    if (a.sha256_sent !== hs.digest('hex')) throw new Error('attestation hashes different request records than we sent')
    ctx.writePrivate(`${s.runDir}/attestation-${cur.n}.json`, JSON.stringify(a, null, 2))
    ctx.log({ ev: 'attestation', n: cur.n, s_k: sK, server_records: count })
    return attJson
  }

  private receipt(cur: Cur, attJson: string): Promise<any> {
    return takeReceipt(this.s, this.ctx, cur.n, attJson, (t, ms) => this.wait(t, ms))
  }

  /**
   * Adversarial probe (d): present the previous request's usage disclosure
   * for this one, as soon as this request is released.
   */
  private async replayUsage(cur: Cur): Promise<any> {
    const { s } = this
    if (!this.lastDisclosure) throw new Error('replay-usage needs an earlier settled request on the connection')
    await this.until(() => cur.released, 'body_released', 120000)
    const stale = { ...this.lastDisclosure, n: cur.n }
    this.sendOrdered(stale)
    for (;;) {
      const m = await this.wait(['disclose_retry', 'attestation'], 30000)
      const next = m.type === 'disclose_retry' ? { retry: m } : { att: m }
      if ('att' in next) return { adv: 'replay-usage', accepted: true }
      // The node saw newer records: claim them, with the old bytes.
      this.sendOrdered({ ...stale, server_records: next.retry.server_records })
    }
  }
}

/** The header block of the hidden request the adversarial probes try to smuggle. */
function hiddenBlock(host: string, path: string): Uint8Array {
  const str = (s: string) => concat(Uint8Array.from([s.length]), new TextEncoder().encode(s))
  return concat(Uint8Array.from([0x82, 0x87, 0x01]), str(host), Uint8Array.from([0x04]), str(path), Uint8Array.from([0xbe]))
}

/**
 * Serve requests `from`… on a framing-"2" connection whose head is proven
 * (π_NK) and not yet written. Returns the settled requests and, for an
 * attack, how it ended.
 */
export async function runHttp2(s: any, conn: H2Conn, from: number): Promise<{ results: any[]; adv?: any; lingered?: number }> {
  const { ctx } = conn
  s.sendText({ type: 'release_head' })
  await Promise.race([s.waitT('head_written', 30000), conn.failP])
  s.tHeadWritten = Date.now()
  ctx.log({ ev: 'head_written' })
  void conn.proofPump()
  await conn.open()
  conn.sendSettingsSeen()
  s.tOpen = Date.now()
  s.setupBytes = s.allBytes()
  const results: any[] = []
  let adv: any
  for (let n = from; n <= ctx.requests; n++) {
    if (n > from && ctx.pauseMs > 0) {
      console.log(`[client ${s.label}] idle for ${ctx.pauseMs} ms before request ${n}`)
      await Promise.race([sleep(ctx.pauseMs), s.errP, conn.failP])
    }
    const attack = ctx.adv && ctx.adv.at === n
    try {
      const r = await conn.request(n)
      if (r.adv) {
        adv = { mode: ctx.adv!.mode, http: '2', at: n, refused: false, detail: r }
        break
      }
      results.push(r)
      console.log(
        `[client ${s.label}] request ${n}: status=${r.status} released_ms=${r.released_ms} ttft_ms=${r.ttft_ms} total_ms=${r.total_ms} ` +
          `usage=${JSON.stringify(r.usage ?? null)} receipt_sig_ok=${r.receipt_sig_ok}`,
      )
      if (attack) {
        adv = { mode: ctx.adv!.mode, http: '2', at: n, refused: false, detail: 'the request settled' }
        break
      }
      if (r.status >= 400) break // the node closes the connection after an error
    } catch (e) {
      if (!attack) throw e
      const cur = conn.cur
      adv = await advOutcome(s, ctx, e, { at: n, body_released: !!cur?.released, response_frames: cur?.parts.length ?? 0, status: cur?.status ?? null })
      break
    }
  }
  let lingered: number | undefined
  if (results.some((r) => r.status >= 400)) {
    // An error head was settled: the node ends the connection (`closed`, `error_settled`).
    await Promise.race([s.waitT('closed', 5000).catch(() => {}), conn.failP.catch(() => {})])
  } else if ((ctx.lingerMs ?? 0) > 0 && !adv) {
    // Stay idle: the node closes the connection after its `idle_timeout_s`.
    const t0 = Date.now()
    console.log(`[client ${s.label}] idle for up to ${ctx.lingerMs} ms, waiting for the node to close the connection`)
    await Promise.race([s.waitT('closed', ctx.lingerMs!).catch(() => {}), conn.failP.catch(() => {})])
    lingered = Date.now() - t0
    console.log(`[client ${s.label}] connection closed: reason=${ctx.shown(s.closedReason)} after_ms=${lingered}`)
  }
  return { results, adv, lingered }
}
