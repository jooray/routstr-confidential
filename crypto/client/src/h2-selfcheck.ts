// Offline self-check of the reference client's HTTP/2 layer (protocol v3,
// option A) against the vectors the sidecar's tests generate
// (`h2-vectors.json`, `cargo test -p cu-sidecar client_vectors`), and of the
// π_WIN parameter checks.
//
//   node --experimental-strip-types src/h2-selfcheck.ts

import { readFileSync } from 'node:fs'

import {
  FLAG, FRAME, FrameReader, checkH2Offer, checkPiNKParamsH2, checkPiWinParams, decodeBlock, frame, h2Head, huffmanDecode,
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

// Body split: every frame within the limit, the last one holds the suffix.
for (const [len, sfx, chunk] of [[10, 4, 100], [100, 30, 40], [81, 30, 40], [16375 * 3 + 5, 200, 16375], [200, 200, 16375]] as const) {
  const parts = splitBody(new Uint8Array(len), sfx, chunk)
  ok(parts.reduce((n, p) => n + p.length, 0) === len && parts.every((p) => p.length > 0 && p.length <= chunk), `split ${len}`)
  ok(parts[parts.length - 1]!.length >= sfx, `split ${len}: suffix in the last frame`)
}

// The offer's h2 block.
const offer = { http: ['1.1', '2'], upstream_host: 'api.venice.ai', h2: { probe_path: '/api/v1/models', idle_secs: 300, max_requests: 100 } }
const bases = ['/v1', '/api/v1']
ok(checkH2Offer(offer, bases).probe_path === '/api/v1/models', 'offer accepted')
throws(() => checkH2Offer({ ...offer, http: ['1.1'] }, bases), 'offer without http 2', /offer_no_http2/)
throws(() => checkH2Offer({ ...offer, h2: undefined }, bases), 'offer without the block')
for (const probe_path of ['/api/v1/api_keys', '/api/v1/../v1/models', '/api/v1/models?x=1', '/models', 'api/v1/models']) {
  throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, probe_path } }, bases), `probe path ${probe_path}`)
}
throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, idle_secs: 0 } }, bases), 'idle_secs')
throws(() => checkH2Offer({ ...offer, h2: { ...offer.h2, max_requests: 100000 } }, bases), 'max_requests')

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

console.log(`h2-selfcheck: ${checks} checks passed`)
