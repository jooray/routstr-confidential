// HTTP/1.1 response parsing for framing "1.1": the final head after interim
// ones, the de-chunked body, and the usage disclosure R (PROTOCOL-V3.md §12.8).

import { concat } from './advice.ts'

/** Where the final response head starts, after any interim 1xx heads. */
export function finalHeadOffset(b: Uint8Array): number {
  let off = 0
  for (;;) {
    const line = Buffer.from(b.subarray(off, off + 16)).toString('latin1')
    if (!/^HTTP\/1\.\d 1\d\d/.test(line)) return off
    const end = Buffer.from(b).indexOf('\r\n\r\n', off)
    if (end < 0) return off
    off = end + 4
  }
}

/** The HTTP response body (de-chunked when chunked), after any interim heads. */
export function responseBody(full: Uint8Array): Uint8Array {
  const b = full.subarray(finalHeadOffset(full))
  const headEnd = Buffer.from(b).indexOf('\r\n\r\n')
  if (headEnd < 0) throw new Error('response has no head')
  const head = Buffer.from(b.subarray(0, headEnd)).toString('latin1').toLowerCase()
  const rest = b.subarray(headEnd + 4)
  if (!/\r\ntransfer-encoding:\s*chunked/.test(head)) {
    const len = /\r\ncontent-length:\s*(\d+)/.exec(head)
    if (len && rest.length !== Number(len[1])) throw new Error(`body is ${rest.length} bytes, Content-Length says ${len[1]}`)
    return rest
  }
  const out: Uint8Array[] = []
  let i = 0
  for (;;) {
    const eol = Buffer.from(rest.subarray(i)).indexOf('\r\n')
    if (eol < 0) throw new Error('truncated chunk size')
    const n = parseInt(Buffer.from(rest.subarray(i, i + eol)).toString('latin1'), 16)
    if (!Number.isFinite(n)) throw new Error('bad chunk size')
    i += eol + 2
    if (n === 0) break
    out.push(rest.subarray(i, i + n))
    i += n + 2
  }
  return Buffer.concat(out)
}

function parseChunks(b: Uint8Array): { start: number; data: Uint8Array }[] | null {
  let off = 0
  const out: { start: number; data: Uint8Array }[] = []
  for (;;) {
    let nl = -1
    for (let i = off; i + 1 < b.length; i++) {
      if (b[i] === 13 && b[i + 1] === 10) {
        nl = i
        break
      }
    }
    if (nl < 0) return null
    const line = Buffer.from(b.subarray(off, nl)).toString('ascii').trim()
    if (!/^[0-9a-fA-F]+$/.test(line)) return null
    const len = parseInt(line, 16)
    const dataStart = nl + 2
    if (len === 0) {
      if (b.length !== dataStart + 2) return null
      return out
    }
    if (b.length < dataStart + len + 2) return null
    if (b[dataStart + len] !== 13 || b[dataStart + len + 1] !== 10) return null
    out.push({ start: off, data: b.subarray(dataStart, dataStart + len) })
    off = dataStart + len + 2
  }
}

function endsWithUsageEvent(joined: Uint8Array): boolean {
  const text = Buffer.from(joined).toString('utf8')
  const tail = 'data: [DONE]\n\n'
  if (!text.endsWith(tail)) return false
  const before = text.slice(0, text.length - tail.length)
  const idx = before.lastIndexOf('data: ')
  const evText = (idx >= 0 ? before.slice(idx + 6) : before).trim()
  if (!evText) return false
  try {
    const v = JSON.parse(evText)
    return Array.isArray(v.choices) && v.choices.length === 0 && v.usage && v.usage.prompt_tokens !== undefined
  } catch {
    return false
  }
}

/** SSE data of an R that starts at "\ndata: " inside a chunk (data runs to the first CRLF). */
function dechunkLineStart(r: Uint8Array): Uint8Array | null {
  if (Buffer.from(r.subarray(0, 7)).toString('latin1') !== '\ndata: ') return null
  let end = -1
  for (let i = 0; i + 1 < r.length; i++) {
    if (r[i] === 13 && r[i + 1] === 10) {
      end = i
      break
    }
  }
  if (end < 0) return null
  const rest = parseChunks(r.subarray(end + 2))
  if (!rest) return null
  return concat(r.subarray(1, end), ...rest.map((c) => c.data))
}

export function extractR(b: Uint8Array): Uint8Array | null {
  let bodyStart = 0
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) {
      bodyStart = i + 4
      break
    }
  }
  const body = b.subarray(bodyStart)
  const all = parseChunks(body)
  if (!all) return null
  // Prefer R starting at the usage event's own line ("\ndata: " inside a
  // chunk), so the proof's work follows the event, not the chunk size.
  for (let i = body.length - 7; i >= 0 && body.length - i <= 1 << 16; i--) {
    if (body[i] !== 10 || body[i + 1] !== 100) continue
    const r = body.subarray(i)
    const joined = dechunkLineStart(r)
    if (!joined || !endsWithUsageEvent(joined)) continue
    const text = Buffer.from(joined).toString('utf8')
    if (text.startsWith('data: ') && text.indexOf('\n\ndata: ') === text.lastIndexOf('\n\ndata: ')) return r
  }
  for (let i = all.length - 1; i >= 0; i--) {
    const r = body.subarray(all[i].start)
    const chunks = parseChunks(r)
    if (!chunks) continue
    const joined = concat(...chunks.map((c) => c.data))
    if (endsWithUsageEvent(joined)) return r
  }
  return null
}
