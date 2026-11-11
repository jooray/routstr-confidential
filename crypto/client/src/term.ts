// Terminal output of node-chosen values, escaped and bounded.

const TRACE = process.env.CU_TRACE === '1'

/**
 * A node-chosen value as it may appear on the terminal: a number or a plain
 * token as is, anything else truncated, JSON-quoted and ASCII only (no
 * terminal escapes).
 */
export function shown(v: unknown, max = 120): string {
  if (typeof v === 'number' || typeof v === 'boolean' || v === undefined || v === null) return String(v)
  let s = typeof v === 'string' ? v : (JSON.stringify(v) ?? String(v))
  if (/^[A-Za-z0-9_.:/+-]+$/.test(s) && s.length <= max) return s
  if (s.length > max) s = `${s.slice(0, max)}...`
  return termSafe(JSON.stringify(s))
}

/**
 * Text for the terminal: control and format characters (escape sequences,
 * bidi overrides, line separators) escaped, newlines too unless kept.
 */
export function termSafe(s: string, keepNewlines = false): string {
  return s.replace(/[\p{C}\p{Zl}\p{Zp}]/gu, (c) => {
    if (keepNewlines && c === '\n') return c
    const cp = c.codePointAt(0)!
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, '0')}`
  })
}

/** An error for the terminal: its message escaped and bounded (the stack only under CU_TRACE). */
export const errText = (e: unknown): string => {
  const text = e instanceof Error ? (TRACE && e.stack ? e.stack : `${e.name}: ${e.message}`) : String(e)
  return termSafe(text.length > 2000 ? `${text.slice(0, 2000)}...` : text, TRACE)
}
