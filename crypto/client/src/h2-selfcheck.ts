// Offline self-check of the reference client's HTTP/2 layer (protocol v3,
// framing "2") against the vectors the sidecar's tests generate
// (`h2-vectors.json`, `cargo test -p cu-sidecar client_vectors`), of the
// π_WIN parameter checks of both framings, and of the `request` message.
//
//   node --experimental-strip-types src/h2-selfcheck.ts

import { readFileSync } from 'node:fs'

import { RequestRefused, openRequest, requestMessage, type ReqBody } from './ctx.ts'
import {
  FLAG, FRAME, FrameReader, checkH2Offer, errorHeadPrefixProblem, refusalProblem, checkPiNKParamsH2, checkPiWinFinalRecord, checkPiWinParams, decodeBlock, frame, h2Head, huffmanDecode,
  requestBlock, splitBody, type WinSource,
} from './h2.ts'

const v = JSON.parse(readFileSync(new URL('./h2-vectors.json', import.meta.url), 'utf8'))
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'))
let checks = 0
function ok(cond: unknown, what: string): void {
  checks++
  if (!cond) {
    console.error(`FAIL: ${what}`)
    process.exit(1)
  }
}
function throws(f: () => unknown, what: string, re?: RegExp): void {
  try {
    f()
  } catch (e) {
    ok(!re || re.test(String(e)), `${what}: wrong error ${e}`)
    checks++
    return
  }
  ok(false, `${what}: accepted`)
}

// The connection head and the request block, byte for byte as the sidecar builds them.
const head = h2Head(v.head.host, v.head.probe_path, v.head.key_len)
ok(hex(head.template) === v.head.template, 'head template')
ok(head.offsets[0] === v.head.first_offset && head.offsets.length === v.head.key_len, 'head key offsets')
ok(head.offsets.every((o) => head.template[o] === 0), 'head key placeholders')
ok(hex(requestBlock(v.request_block.host, v.request_block.path)) === v.request_block.block, 'request block')

// HPACK without a dynamic table.
for (const b of v.blocks) ok(JSON.stringify(decodeBlock(unhex(b.block))) === JSON.stringify(b.fields), `block ${b.block}`)
for (const b of v.refused_blocks) throws(() => decodeBlock(unhex(b)), `refused block ${b}`)
const all = huffmanDecode(unhex(v.huffman_all_bytes))
ok(all.length === 256 && all.every((x, i) => x === i), 'huffman: every byte')
throws(() => huffmanDecode(Uint8Array.from([0x00])), 'huffman zero padding')
throws(() => huffmanDecode(Uint8Array.from([0xff, 0xff, 0xff, 0xff])), 'huffman EOS')

// Frames across record boundaries.
const rd = new FrameReader()
const stream = Buffer.concat([frame(FRAME.SETTINGS, 0, 0, new Uint8Array(6)), frame(FRAME.DATA, FLAG.END_STREAM, 3, new TextEncoder().encode('hello'))])
const got = [...rd.push(stream.subarray(0, 11), 7), ...rd.push(stream.subarray(11, 20), 8), ...rd.push(stream.subarray(20), 9)]
ok(got.length === 2 && got[0]!.type === FRAME.SETTINGS && got[1]!.stream === 3 && got[1]!.off === 15, 'frame reassembly')
ok(Buffer.from(got[1]!.payload).toString() === 'hello' && rd.atBoundary(), 'frame payload')
ok(rd.recordAt(15).abs === 8 && rd.recordAt(15).start === 11, 'record of a stream offset')
ok(Buffer.from(rd.slice(15, stream.length)).equals(stream.subarray(15)), 'stream slice')

// A frame above 16 KiB (the head never raises SETTINGS_MAX_FRAME_SIZE) is refused
// from its header alone, before it is reassembled; one of exactly 16 KiB is read.
throws(() => new FrameReader().push(Uint8Array.from([0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 1]), 0), 'a frame above 16 KiB', /FRAME_SIZE_ERROR/)
ok(new FrameReader().push(frame(FRAME.DATA, 0, 1, new Uint8Array(1 << 14)), 0).length === 1, 'a frame of 16 KiB')

// Body split: every frame within the limit, the last one holds the suffix.
for (const [len, sfx, chunk] of [[10, 4, 100], [100, 30, 40], [81, 30, 40], [16375 * 3 + 5, 200, 16375], [200, 200, 16375]] as const) {
  const parts = splitBody(new Uint8Array(len), sfx, chunk)
  ok(parts.reduce((n, p) => n + p.length, 0) === len && parts.every((p) => p.length > 0 && p.length <= chunk), `split ${len}`)
  ok(parts[parts.length - 1]!.length >= sfx, `split ${len}: suffix in the last frame`)
}

// The offer's h2 block.
const offer = { http: ['2', '1.1'], upstream_host: 'api.venice.ai', h2: { probe_path: '/api/v1/models', idle_secs: 300, max_requests: 100, max_lifetime_s: 3600 } }
const bases = ['/v1', '/api/v1']
ok(checkH2Offer(offer, bases).probe_path === '/api/v1/models', 'offer accepted')
throws(() => checkH2Offer({ ...offer, http: ['1.1'] }, bases), 'offer without http 2', /offer_no_http2/)
throws(() => checkH2Offer({ ...offer, h2: undefined }, bases), 'offer without the block')
for (const probe_path of ['/api/v1/api_keys', '/api/v1/../v1/models', '/api/v1/models?x=1', '/models', 'api/v1/models']) {
  throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, probe_path } }, bases), `probe path ${probe_path}`)
}
throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, idle_secs: 0 } }, bases), 'idle_secs')
throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, max_requests: 100000 } }, bases), 'max_requests')
throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, max_lifetime_s: 30 } }, bases), 'max_lifetime_s')
ok(checkH2Offer({ ...offer, h2: { probe_path: '/api/v1/models' } }, bases).max_lifetime_s === 3600, 'h2 defaults')

// π_NK: only the offer's connection head.
const hk = new Uint8Array(32).fill(9)
const nk = () => ({
  PiNK: {
    hk: Array.from(hk), head_len: head.template.length, key_len: 42, key_alphabet: '[A-Za-z0-9_-]', key_offsets: head.offsets.slice(),
    template: Array.from(head.template), c_commit: new Array(32).fill(1),
    header: [0x17, 3, 3, (head.template.length + 17) >> 8, (head.template.length + 17) & 0xff],
  },
})
const ownNk = { host: 'api.venice.ai', probePath: '/api/v1/models', keyLength: 42, hk }
checkPiNKParamsH2(nk(), ownNk)
checks++
const tamper = (f: (p: any) => void) => {
  const p = nk()
  f(p.PiNK)
  return p
}
// A head that enables push or a response table, another probe path, a moved key, another anchor.
throws(() => checkPiNKParamsH2(tamper((p) => (p.template[44] = 1)), ownNk), 'ENABLE_PUSH = 1')
throws(() => checkPiNKParamsH2(tamper((p) => (p.template[38] = 0x10)), ownNk), 'HEADER_TABLE_SIZE > 0')
throws(() => checkPiNKParamsH2(tamper((p) => (p.template[100] ^= 1)), ownNk), 'another probe path')
throws(() => checkPiNKParamsH2(tamper((p) => p.key_offsets[0]--), ownNk), 'moved key')
throws(() => checkPiNKParamsH2(tamper((p) => (p.hk[0] ^= 1)), ownNk), 'another anchor')
throws(() => checkPiNKParamsH2(tamper((p) => (p.key_alphabet = '[a-z]')), ownNk), 'another alphabet')
throws(() => checkPiNKParamsH2(nk(), { ...ownNk, probePath: '/v1/models' }), 'offer with another probe path')

// π_WIN: the node may compare only public bytes of our own records.
const anchor = new Uint8Array(32).fill(5)
const plain = new Uint8Array(5001)
plain.set(frame(FRAME.DATA, 0, 3, new Uint8Array(4991).fill(0x61)))
plain[5000] = 0x17
const ct = plain.map((b, i) => b ^ ((i * 7 + 3) & 0xff))
const src: WinSource = { ct, plain, pub: [[0, 9], [5000, 5001]] }
const lookup = (seq: number) => (seq === 4 ? src : undefined)
const win = (w: Record<string, unknown>[]) => ({ PiWin: { anchor: Array.from(anchor), windows: w } })
const headWin = { seq: 4, ct: Array.from(ct.subarray(0, 16)), expected: Array.from(plain.subarray(0, 9)) }
const lastWin = { seq: 4, off: 4992, ct: Array.from(ct.subarray(4992)), sel_start: 8, expected: [0x17] }
ok(checkPiWinParams(win([headWin, lastWin]), { anchor, lookup, covered: [4] }).windows === 2, 'honest windows')
const bad = (w: Record<string, unknown>[], what: string, own: any = {}) => throws(() => checkPiWinParams(win(w), { anchor, lookup, ...own }), what, /π_WIN/)
// A guess at private payload bytes (the equality bit would confirm it).
bad([{ seq: 4, ct: Array.from(ct.subarray(0, 16)), expected: Array.from(plain.subarray(0, 10)) }], 'one private byte after the frame header')
bad([{ seq: 4, off: 16, ct: Array.from(ct.subarray(16, 32)), expected: Array.from(plain.subarray(16, 32)) }], 'a private block')
bad([{ ...lastWin, sel_start: 7, expected: [0x61, 0x17] }], 'the byte before the type byte')
// Bytes that are public but not what the record holds, foreign ciphertext, other records.
bad([{ ...headWin, expected: [0, 0x13, 0x7f, 1, 4, 0, 0, 0, 3] }], 'a wrong frame header')
bad([{ ...headWin, ct: Array.from(ct.subarray(0, 16)).map((b, i) => (i === 3 ? b ^ 1 : b)) }], 'ciphertext not ours')
bad([{ ...headWin, seq: 5 }], 'a record that is not in the batch')
bad([{ ...headWin, off: 8, ct: Array.from(ct.subarray(8, 24)) }], 'an unaligned offset')
bad([{ ...lastWin, ct: [...Array.from(ct.subarray(4992)), 1, 2] }], 'ciphertext past the record (the tag)')
bad([{ ...headWin, expected: [] }], 'nothing compared')
bad([headWin], 'a record of the batch left uncovered', { covered: [4, 5] })
bad([], 'no windows')
throws(() => checkPiWinParams({ PiWin: { anchor: Array.from(anchor).reverse(), windows: [headWin] } }, { anchor: new Uint8Array(32).fill(6), lookup }), 'another anchor')
throws(() => checkPiWinParams({ PiWin: { anchor: Array.from(anchor), key_updates: 1, windows: [headWin] } }, { anchor, lookup }), 'another key epoch')
// A whole-record window over adjacent public ranges (a last DATA frame that is all suffix).
const small = frame(FRAME.DATA, FLAG.END_STREAM, 3, new TextEncoder().encode(',"model":"m"}'))
const sp = Uint8Array.from([...small, 0x17])
const sc = sp.map((b) => b ^ 0x5a)
const whole = { seq: 1, ct: Array.from(sc), expected: Array.from(sp) }
ok(
  checkPiWinParams({ PiWin: { anchor: Array.from(anchor), windows: [whole] } }, { anchor, lookup: () => ({ ct: sc, plain: sp, pub: [[0, 9], [9, sp.length]] }) }).windows === 1,
  'adjacent public ranges',
)

// Framing "1.1": one window, the whole final record = suffix ‖ 0x17, at our own sequence number.
{
  const suffix = new TextEncoder().encode(',"model":"m","max_tokens":12,"stream":true}')
  const fp = Uint8Array.from([...suffix, 0x17])
  const fc = fp.map((b, i) => b ^ ((i * 11 + 1) & 0xff))
  const wire = Uint8Array.from([0x17, 3, 3, 0, fc.length + 16, ...fc, ...new Uint8Array(16)])
  const own = { anchor, seq: 13, wire, suffix }
  const msg = (w: Record<string, unknown>[], first_seq = 13, count = 1) => ({ first_seq, count, params: { PiWin: { anchor: Array.from(anchor), windows: w } } })
  const full = { seq: 13, ct: Array.from(fc), expected: Array.from(fp) }
  ok(checkPiWinFinalRecord(msg([full]), own).windows === 1, 'framing 1.1: the whole final record')
  const refuse = (m: any, what: string, o: any = own) => throws(() => checkPiWinFinalRecord(m, o), `framing 1.1: ${what}`, /π_WIN/)
  refuse(msg([full], 12), 'another sequence number')
  refuse(msg([{ ...full, seq: 12 }]), 'a window on another record')
  refuse(msg([full], 13, 2), 'a batch of two records')
  refuse(msg([full, full]), 'two windows')
  refuse(msg([{ seq: 13, ct: Array.from(fc.subarray(0, 16)), expected: Array.from(fp.subarray(0, 16)) }]), 'a partial window')
  refuse(msg([{ ...full, expected: Array.from(fp).map((b, i) => (i === 3 ? b ^ 1 : b)) }]), 'bytes that are not our suffix')
  refuse(msg([{ ...full, ct: Array.from(fc).map((b, i) => (i === 0 ? b ^ 1 : b)) }]), 'ciphertext not ours')
  // Our own final record must be the suffix alone: a longer record is not proven as a whole.
  const longer = Uint8Array.from([0x17, 3, 3, 0, fc.length + 17, 0x20, ...fc, ...new Uint8Array(16)])
  refuse(msg([full]), 'a final record that is not the suffix alone', { ...own, wire: longer })
}

// The `request` message (§12.4) and its answer: nothing is sent between `request` and `request_ok`;
// a refused request is followed by the good one with the same n.
{
  const enc = new TextEncoder()
  const b: ReqBody = { kind: 'chat', model: 'm', maxTokens: 12, body: enc.encode('{"messages":[],"model":"m"}'), suffix: enc.encode(',"model":"m"}'), canonicalSuffix: ',"model":"m"}' }
  const base: any = { offer: { max_tokens_cap: 4096 }, nodeMode: false, requestExtras: {}, shown: String }
  const direct = requestMessage(base, 1, b, 27)
  ok(JSON.stringify(direct) === '{"type":"request","n":1,"kind":"chat","model":"m","max_tokens":12,"body_len":27}', 'request to a sidecar')
  ok((requestMessage(base, 1, b, 27, true) as any).max_tokens === 4097, 'a request a sidecar must refuse: max_tokens above the cap')
  const node: any = { ...base, nodeMode: true, requestExtras: { auth: 'sk-x', offer_sig: 'ab', session_fee_msat: 5, abandon_fee_msat: 7 } }
  const viaNode: any = requestMessage(node, 2, b, 27)
  ok(viaNode.auth === 'sk-x' && viaNode.offer_sig === 'ab' && viaNode.session_fee_msat === 5 && viaNode.abandon_fee_msat === 7 && viaNode.n === 2, 'request to a node')
  ok((requestMessage(node, 1, b, 27, true) as any).model !== 'm', 'a request a node must refuse: a model it does not serve')
  const img: ReqBody = { ...b, kind: 'images', image: { variant: 'v1', count: 2, path: '/api/v1/image/generate', headTemplate: '', responseShape: 'venice', msatPerImage: 9 } }
  const im: any = requestMessage(base, 1, img, 30)
  ok(im.kind === 'images' && im.count === 2 && im.suffix === b.canonicalSuffix && im.variant === undefined && im.max_tokens === undefined, 'image request to a sidecar')
  const imN: any = requestMessage(node, 1, img, 30)
  ok(imN.variant === 'v1' && imN.count === 2 && imN.suffix === undefined, 'image request to a node')

  const sent: any[] = []
  const answers: any[] = [{ type: 'request_refused', n: 1, status: 400, reason: 'max_tokens above the cap' }, { type: 'request_ok', sid: 's', n: 1, suffix: b.canonicalSuffix, stream: 3 }]
  const quiet = console.log
  console.log = () => {}
  const r = await openRequest({ sid: 's', label: 't' }, base, 1, b, 27, true, (o) => sent.push(o), async () => answers.shift())
  console.log = quiet
  ok(sent.length === 2 && sent[0].n === 1 && sent[1].n === 1 && sent[0].max_tokens === 4097 && sent[1].max_tokens === 12, 'refuse-first: the good request carries the same n')
  ok(r.refused?.status === 400 && r.ok.stream === 3, 'refuse-first: outcome')
  const refused = await openRequest({ sid: 's', label: 't' }, base, 1, b, 27, false, () => {}, async () => ({ type: 'request_refused', n: 1, status: 402, reason: 'balance' })).catch((e) => e)
  ok(refused instanceof RequestRefused && refused.status === 402, 'a refused request is reported as such')
  const other = await openRequest({ sid: 's', label: 't' }, base, 1, b, 27, false, () => {}, async () => ({ type: 'request_ok', sid: 'x', n: 1, suffix: '' })).catch((e) => e)
  ok(other instanceof Error && !(other instanceof RequestRefused), 'request_ok for another connection')
  const accepted = await openRequest({ sid: 's', label: 't' }, base, 1, b, 27, true, () => {}, async () => ({ type: 'request_ok', sid: 's', n: 1, suffix: '' })).catch((e) => e)
  ok(String(accepted).includes('had to refuse'), 'refuse-first: an accepted bad request is a failure')
}

// The frames a response head may follow in its record (disclosed with it).
{
  const wu = (s: number) => frame(FRAME.WINDOW_UPDATE, 0, s, new Uint8Array([0, 0, 1, 0]))
  const ping = frame(FRAME.PING, FLAG.ACK, 0, new Uint8Array(8))
  const probe = frame(FRAME.DATA, FLAG.END_STREAM, 1, new TextEncoder().encode('{"data":[]}'))
  const cat = (...xs: Uint8Array[]) => Uint8Array.from(xs.flatMap((x) => [...x]))
  ok(errorHeadPrefixProblem(new Uint8Array(0), 3) === undefined, 'error head prefix: none')
  ok(errorHeadPrefixProblem(cat(wu(0), wu(3), ping, probe, frame(FRAME.SETTINGS, FLAG.ACK, 0)), 3) === undefined, 'error head prefix: control and probe frames')
  ok(errorHeadPrefixProblem(frame(FRAME.DATA, 0, 3, new Uint8Array([1])), 3) !== undefined, 'error head prefix: our own DATA is never disclosed')
  ok(errorHeadPrefixProblem(wu(5), 3) !== undefined, 'error head prefix: another stream')
  ok(errorHeadPrefixProblem(ping.subarray(0, 12), 3) !== undefined, 'error head prefix: a frame running into the head')

  // `disclose_reset` (§5.4): the same cases as the sidecar's `refusal_forms`
  // and `refusals_that_do_not_count`.
  const u32b = (x: number) => Uint8Array.from([x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255])
  const rst = (stream: number, code: number) => frame(FRAME.RST_STREAM, 0, stream, u32b(code))
  const goaway = (last: number, code: number, debug = new Uint8Array(0)) => frame(FRAME.GOAWAY, 0, 0, cat(u32b(last), u32b(code), debug))
  ok(refusalProblem(rst(3, 7), 3) === undefined, 'refusal: RST_STREAM(REFUSED_STREAM)')
  ok(refusalProblem(goaway(1, 0), 3) === undefined && refusalProblem(goaway(1, 0), 3, false) === undefined, 'refusal: GOAWAY below the stream')
  ok(refusalProblem(goaway(0x80000001, 0), 5) === undefined, 'refusal: GOAWAY, reserved bit ignored')
  ok(refusalProblem(goaway(3, 0, new TextEncoder().encode('bye')), 5) === undefined, 'refusal: GOAWAY with debug data')
  const before = [wu(0), wu(3), frame(FRAME.SETTINGS, 0, 0, Uint8Array.from([0, 3, 0, 0, 0, 100])), frame(FRAME.SETTINGS, FLAG.ACK, 0), ping, probe, rst(1, 7), goaway(3, 0), goaway(0x7fffffff, 0)]
  ok(refusalProblem(cat(...before, rst(3, 7)), 3) === undefined, 'refusal: after control, probe and non-refusing GOAWAY frames')
  for (const [what, r, rstOk] of [
    ['another code', rst(3, 8), true], ['NO_ERROR reset', rst(3, 0), true], ['another stream', rst(5, 7), true],
    ['the probe stream', rst(1, 7), true], ['a reset before anything was written', rst(3, 7), false],
    ['GOAWAY covering the stream', goaway(3, 0), true], ['GOAWAY with an error', goaway(1, 1), true],
    ['a long reset', frame(FRAME.RST_STREAM, 0, 3, Uint8Array.from([0, 0, 0, 7, 0])), true], ['nothing', new Uint8Array(0), true],
  ] as [string, Uint8Array, boolean][]) {
    ok(refusalProblem(r, 3, rstOk) !== undefined, `refusal refused: ${what}`)
  }
  ok(refusalProblem(rst(1, 7), 1) !== undefined, 'refusal refused: of the probe stream itself')
  for (const bad of [frame(FRAME.HEADERS, FLAG.END_HEADERS, 3, Uint8Array.from([0x88])), frame(FRAME.DATA, 0, 3, new Uint8Array([1])), frame(FRAME.DATA, 0, 5, new Uint8Array([1])), frame(FRAME.PING, 0, 3, new Uint8Array(8)), goaway(1, 2)]) {
    ok(refusalProblem(cat(bad, rst(3, 7)), 3) !== undefined && refusalProblem(cat(bad, goaway(1, 0)), 3) !== undefined, `refusal refused after a frame of type ${bad[3]} on stream ${bad[8]}`)
  }
  ok(refusalProblem(cat(rst(3, 7), ping), 3) !== undefined, 'refusal refused: bytes after the refusal')
  ok(refusalProblem(rst(3, 7).subarray(0, 12), 3) !== undefined, 'refusal refused: a partial reset')
}

// The usage event rule (§5.4): the shared vectors, and the HTTP/1.1 R locator
// with usage on every chunk (Cloudflare): R starts at the last event only.
{
  const { usageEventProblem } = await import('./usage-rule.ts')
  const { extractR } = await import('./http1.ts')
  const { readFileSync } = await import('node:fs')
  const vec = JSON.parse(readFileSync(new URL('../../relay/usage-event-vectors.json', import.meta.url), 'utf8'))
  for (const t of vec.vectors) ok((usageEventProblem(t.event) === null) === t.ok, `usage vector: ${t.name}`)
  const content = '{"choices":[{"index":0,"delta":{"content":"Hello"}}],"usage":{"prompt_tokens":0,"completion_tokens":1}}'
  const last = '{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":14,"completion_tokens":3}}'
  const sse = `data: ${content}\n\ndata: ${last}\n\ndata: [DONE]\n\n`
  const resp = new TextEncoder().encode(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${sse.length.toString(16)}\r\n${sse}\r\n0\r\n\r\n`)
  const r = extractR(resp)
  ok(r !== null && new TextDecoder().decode(r).startsWith(`\ndata: ${last}`), 'usage on every chunk: R starts at the last event')
  const merged = `data: ${last}\n\ndata: ${content}\n\ndata: [DONE]\n\n`
  ok(extractR(new TextEncoder().encode(`HTTP/1.1 200 OK\r\n\r\n${merged.length.toString(16)}\r\n${merged}\r\n0\r\n\r\n`)) === null, 'usage merged into content: no R')
}

console.log(`h2-selfcheck: ${checks} checks passed`)
