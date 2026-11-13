// Framing "1.1" of the reference driver (PROTOCOL-V3.md §6, §12.5, §12.7,
// §12.8): one request on the connection. `request` 1 goes before the
// ClientHello, because the head the node writes in epoch 0 names the path and
// the body length; the body follows under c_ap_1 with the canonical suffix
// alone in the final record, which the node holds until π_WIN (one window,
// the whole record) verifies; the provider closes after its response, the
// node attests, and the client discloses the usage event (or the error head),
// or accepts an image response.
//
// Everything a connection has in both framings (setup, 2PC, handshake, π_NK)
// is the driver's `Session`.

import { concat, hex } from './advice.ts'
import { noteDepositRelease, openRequest, takeReceipt, type Ctx, type ReqBody } from './ctx.ts'
import { checkPiWinFinalRecord } from './h2.ts'
import { extractR, finalHeadOffset, responseBody } from './http1.ts'
import { checkPiC3SParams, serverTailEpoch } from './params.ts'

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

export class H11 {
  readonly s: any
  readonly ctx: Ctx
  /** The request's index in the run (`buildBody`); on the connection it is request 1. */
  readonly g: number
  readonly b: ReqBody
  ok: any
  refused: { status: number; reason: string } | undefined
  reserved: number | undefined
  proofs: any[] = []

  constructor(s: any, ctx: Ctx, g: number) {
    this.s = s
    this.ctx = ctx
    this.g = g
    this.b = ctx.buildBody(g)
  }

  get adv(): string | undefined {
    return this.ctx.adv && this.ctx.adv.at === this.g ? this.ctx.adv.mode : undefined
  }

  /** `request` 1 and its answer, before the ClientHello (§12.4). */
  async open(): Promise<void> {
    const { s, ctx, b } = this
    const { ok, refused, reserved } = await openRequest(s, ctx, 1, b, b.body.length, ctx.refuseFirst && this.g === 1, (o) => s.sendText(o), (t, ms) => s.waitT(t, ms))
    if (!this.adv && ok.suffix !== b.canonicalSuffix) throw new Error('node expects a different pinned suffix than ours')
    if (!Number.isSafeInteger(ok.head_len) || ok.head_len <= 0) throw new Error('request_ok names no head length')
    this.ok = ok
    this.refused = refused
    this.reserved = reserved
  }

  /** After π_NK: the head, the body, π_WIN, the response and the settlement. */
  async run(tStart: number): Promise<any> {
    const { s, ctx, b } = this
    const adv = this.adv
    const bytes0 = s.claimBytes
    s.sendText({ type: 'release_head' })
    await s.waitT('head_written', 30000)
    s.tHeadWritten = Date.now()
    ctx.log({ ev: 'head_written' })

    // The body under c_ap_1: the private part, then the suffix alone in the final record.
    const tBody = Date.now()
    const priv = b.body.subarray(0, b.body.length - b.suffix.length)
    s.inBody = true
    if (adv === 'not-alone') {
      // The suffix shares its record with the last private bytes.
      const cut = Math.max(1, priv.length - 8)
      await s.tls.write(priv.subarray(0, cut))
      await s.tls.write(b.body.subarray(cut))
    } else if (adv === 'padding') {
      // A final record of the right size that holds a shorter text, the type
      // byte and TLS padding: the whole-record window cannot hold.
      const d = 4
      await s.tls.write(priv)
      await s.tls.writeInner(concat(b.suffix.subarray(0, b.suffix.length - d), Uint8Array.from([0x17]), new Uint8Array(d)))
    } else {
      await s.tls.write(priv)
      await s.tls.write(b.suffix)
    }
    const finalSeq = s.bodyRecords.length - 1
    const finalRecord: Uint8Array = s.bodyRecords[finalSeq]
    ctx.log({ ev: 'body_sent', len: b.body.length, records: s.bodyRecords.length })

    if (adv === 'no-proof') {
      // Never prove the final record: the node must hold it, so the provider
      // has no complete request and answers nothing.
      const t0 = Date.now()
      while (!s.tlsEnded && !s.peerError && Date.now() - t0 < 20_000) await sleep(20)
      const text = Buffer.from(s.responseBytes).toString('utf8')
      const hasOutput = /"content":\s*"[^"]/.test(text) || /"images"\s*:\s*\[\s*"/.test(text)
      return { adv: { withheld: s.responseBytes.length === 0 && !hasOutput && !s.tFirst.body_released, response_bytes: s.responseBytes.length, has_model_output: hasOutput } }
    }

    // π_WIN, sent by the node on its own once the final record is there.
    const zp = await s.waitT('zk_params:pi_win:records', 30000)
    let shape = { windows: zp.params?.PiWin?.windows?.length ?? 0, ctBytes: 0 }
    if (!adv) shape = checkPiWinFinalRecord(zp, { anchor: s.ap.h1, seq: finalSeq, wire: finalRecord, suffix: b.suffix })
    let t = Date.now()
    await s.proof('pi_win', 'prove', zp.params, { Secret: Array.from(s.ap.clientAp1) })
    this.pushProof({ proof: 'pi_win', purpose: 'records', n: 1, records: 1, ...shape, ms: Date.now() - t }, 'pi_win')
    ctx.log({ ev: 'pi_win_ok', first_seq: finalSeq })
    const rel = await s.waitT('body_released', 60000)
    if (rel.n !== 1) throw new Error('body_released names another request')
    const tReleased = Date.now()
    if (adv === 'extra-record') {
      // One more record after the proven final one, carrying a second request.
      const enc = new TextEncoder()
      await s.tls.write(enc.encode('POST /api/v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}'))
      const t0 = Date.now()
      while (!s.peerError && Date.now() - t0 < 30000) await sleep(20)
      throw new Error(`refused: ${String(s.peerError?.reason ?? 'not refused')}`)
    }

    // The provider closes after its response; the node then attests on its own.
    const attMsg = await s.waitT('attestation', 600000)
    const attJson = await this.checkAttestation(attMsg)
    await this.drained()

    // Interim 1xx heads are skipped; the final head is the status.
    const resp: Uint8Array = s.responseBytes
    const finalHead = finalHeadOffset(resp)
    const statusLine = Buffer.from(resp.subarray(finalHead, finalHead + 64)).toString('latin1')
    const status = Number(/^HTTP\/1\.\d (\d{3})/.exec(statusLine)?.[1] ?? 0)
    if (finalHead > 0 && status >= 400) throw new Error('an interim 1xx head precedes the error head; it cannot be disclosed')
    if (status >= 400) console.log(`[client ${s.label}] upstream error ${status}: ${ctx.shown(Buffer.from(resp).toString('utf8').split('\r\n\r\n')[1], 200)}`)

    const wait = (types: string[], ms: number) => s.waitT(types, ms)
    let receipt: any
    let ownUsage: any
    let text = ''
    let imageOut: any
    if (b.image && ((status >= 200 && status < 300) || (ctx.acceptAny && status > 0))) {
      // Only a 2xx is accepted (`acceptAny` is the dishonest client): nothing is disclosed or proven.
      s.sendText({ type: 'accept', n: 1 })
      receipt = await takeReceipt(s, ctx, 1, attJson, wait)
      if (receipt.usage?.flat !== true) throw new Error('the settlement of an accepted image request is not flat')
      if (receipt.model !== b.model) throw new Error('receipt names another model than the request pinned')
      imageOut = this.imageResult(resp)
    } else if (status >= 200 && status < 300 && !b.image) {
      const r = extractR(resp)
      if (!r) throw new Error('could not extract a valid usage disclosure R')
      await this.disclose('disclose', r, 0)
      receipt = await takeReceipt(s, ctx, 1, attJson, wait)
      const parts = Buffer.from(r).toString('utf8').split('data: ')
      const usageSeg = parts.length >= 2 ? parts[parts.length - 2]! : '{}'
      ownUsage = JSON.parse(usageSeg.split('\r\n')[0]!.split('\n\n')[0]!.trim())
      const u = receipt.usage?.usage
      if (u?.prompt_tokens !== ownUsage.usage?.prompt_tokens || u?.completion_tokens !== ownUsage.usage?.completion_tokens) {
        throw new Error('receipt usage does not match our own plaintext')
      }
      if (receipt.model !== b.model) throw new Error('receipt names another model than the request pinned')
      const pinned = b.pinned ?? b.model
      if (ownUsage.model !== pinned) console.log(`[client ${s.label}] note: the provider reported model ${ctx.shown(ownUsage.model)} for the pinned ${pinned}`)
      text = Buffer.from(resp).toString('utf8')
    } else if (status >= 400) {
      // No usage event: disclose only the head (status line and headers); the body stays private.
      const headEnd = Buffer.from(resp).indexOf('\r\n\r\n')
      if (headEnd < 0) throw new Error('upstream error response has no head')
      const r = resp.slice(0, headEnd + 4)
      await this.disclose('disclose_head', r, resp.length - r.length)
      receipt = await takeReceipt(s, ctx, 1, attJson, wait)
      if (receipt.usage?.error_status !== status) throw new Error('error receipt does not match the disclosed status')
      text = Buffer.from(resp).toString('utf8')
    } else {
      throw new Error(`status ${status} is neither a success nor a disclosable error`)
    }
    ctx.checkReceipt?.(receipt, { n: 1, http: '1.1', model: b.model, status, usage: ownUsage?.usage, image: b.image, first: !s.settledOnce, reserved: this.reserved })
    noteDepositRelease(s, ctx, receipt, 1)
    const tEnd = Date.now()
    // The connection's orderly end: `done` after a settled 2xx, `error_settled` after an error head.
    await s.waitT('closed', 5000).catch(() => {})
    if (s.closedReason === undefined) console.log(`[client ${s.label}] warning: no closed frame after the settlement`)

    const bytes1 = s.allBytes()
    const delta: Record<string, number> = {}
    for (const k of Object.keys(bytes1)) delta[k] = bytes1[k] - (bytes0[k] ?? 0)
    ctx.writePrivate(`${s.runDir}/response-1.txt`, b.image ? '' : text)
    ctx.writePrivate(`${s.runDir}/receipt-1.json`, JSON.stringify(receipt, null, 2))
    const ttftAbs: number | undefined = s.ttft || undefined
    return {
      n: 1,
      http: '1.1',
      model: b.model,
      refused_first: this.refused,
      ...(b.image ? { kind: 'images', variant: b.image.variant, count: b.image.count, ...imageOut } : {}),
      status,
      body_len: b.body.length,
      records: s.bodyRecords.length,
      reported_model: ownUsage?.model,
      usage: ownUsage?.usage && { prompt_tokens: ownUsage.usage.prompt_tokens, completion_tokens: ownUsage.usage.completion_tokens },
      receipt_sig_ok: receipt.unsigned ? false : true,
      cost_msats: receipt.cost_msats,
      reserved_msats: receipt.reserved_msats,
      balance_msats: receipt.balance_msats,
      released_ms: tReleased - tStart,
      ttft_ms: ttftAbs ? ttftAbs - tStart : undefined,
      ttft_body_ms: ttftAbs ? ttftAbs - tBody : undefined,
      total_ms: tEnd - tStart,
      at: { start: tStart, released: tReleased, first_data: ttftAbs },
      proofs: this.proofs,
      bytes: delta,
    }
  }

  private pushProof(p: Record<string, unknown>, name: string): void {
    const z = this.s.zkTimes[name]
    this.proofs.push({ ...p, inner_ms: z?.inner_ms, bytes_sent: z?.bytes_sent, bytes_recv: z?.bytes_recv })
  }

  /** Every received byte decrypted (the last records carry `data: [DONE]` and the terminal chunk). */
  private async drained(): Promise<void> {
    const { s } = this
    for (let i = 0; i < 200; i++) {
      const c = s.flushChain
      await c
      if (c === s.flushChain && s.tlsEnded) break
      await sleep(5)
    }
  }

  /**
   * The attestation of the connection's one request: signed by the
   * connection's key, naming this connection, framing, request and handshake,
   * the head-record commitment π_NK proved, and counts and a hash we can
   * recompute from our own records. Returns the signed bytes.
   */
  private async checkAttestation(m: any): Promise<string> {
    const { s, ctx } = this
    // The signed bytes, or the attestation as we serialize it: the receipt must hash exactly what we verified.
    const attJson: string = m.a_json ?? JSON.stringify(m.a)
    if (!ctx.verifySig(attJson, m.sig, s.ready.pubkey, m.sig_scheme)) throw new Error('attestation signature invalid')
    const a = JSON.parse(attJson)
    if (a?.sid !== s.sid || a.http !== '1.1' || a.n !== 1 || (m.n !== undefined && m.n !== 1)) throw new Error('attestation names another connection, framing or request')
    if (a.th_sh !== hex(s.thSH) || a.th_sf !== hex(s.thSF)) throw new Error('attestation names another handshake')
    if (!s.cCommitHex || a.c_commit !== s.cCommitHex) throw new Error('attestation names a different head-record commitment')
    if (s.certChainHash && a.cert_chain_hash !== hex(s.certChainHash)) throw new Error('attestation names a different certificate chain')
    // Records may still be on their way to us when the attestation arrives.
    for (let i = 0; i < 1000 && s.recvRecords < a.server_records; i++) await sleep(5)
    if (a.server_records !== s.recvRecords) throw new Error(`attestation counts ${ctx.shown(a.server_records)} upstream records, we received ${s.recvRecords}`)
    if (a.sha256_recv !== s.recvHash.copy().digest('hex')) throw new Error('attestation hashes different upstream bytes than we received')
    if (a.client_records !== s.bodyRecords.length) throw new Error(`attestation counts ${ctx.shown(a.client_records)} body records, we sent ${s.bodyRecords.length}`)
    ctx.writePrivate(`${s.runDir}/attestation-1.json`, JSON.stringify(a, null, 2))
    ctx.log({ ev: 'attestation', n: 1, server_records: a.server_records })
    return attJson
  }

  /** `disclose` (the usage tail) or `disclose_head` (the response head), then π_C3S over the last server records. */
  private async disclose(type: 'disclose' | 'disclose_head', r: Uint8Array, skip: number): Promise<void> {
    const { s } = this
    const tailLens: number[] = []
    let acc = 0
    for (let i = s.responseChunks.length - 1; i >= 0 && acc < r.length + skip; i--) {
      tailLens.push(s.responseChunks[i].length + 1)
      acc += s.responseChunks[i].length
    }
    const epoch = serverTailEpoch(s.serverPost, tailLens.length)
    const msg: any = { type, n: 1, r: hex(r), tail_lens: tailLens, skip, trailing: epoch.trailing }
    if (epoch.keyUpdates > 0) {
      msg.key_updates = epoch.keyUpdates
      msg.epoch_start = epoch.epochStart
    }
    s.sendText(msg)
    const purpose = type === 'disclose_head' ? 'error_head' : ''
    const c3 = await s.waitT(`zk_params:pi_c3s:${purpose}`, 30000)
    if (c3.n !== undefined && c3.n !== 1) throw new Error('π_C3S parameters name another request')
    const handshakeRecords = s.serverRecords.length - s.serverPost.length
    checkPiC3SParams(c3.params, {
      h2: s.ap.h2,
      serverRecords: s.serverRecords,
      r,
      skip,
      keyUpdates: epoch.keyUpdates,
      epochBase: handshakeRecords >= 0 ? handshakeRecords + epoch.epochStart : undefined,
      trailing: epoch.trailing,
      tailLens,
    })
    const t = Date.now()
    await s.proof('pi_c3s', 'prove', c3.params, { Secret: Array.from(s.ap.serverAp0) })
    this.pushProof({ proof: 'pi_c3s', purpose: purpose || undefined, n: 1, r_len: r.length, records: tailLens.length, ms: Date.now() - t }, 'pi_c3s')
    this.ctx.log({ ev: 'pi_c3s_ok', purpose })
  }

  /** The images of an accepted response: one JSON body. What it is short of is reported, not thrown (the charge is flat). */
  private imageResult(resp: Uint8Array): any {
    const { s, ctx, b } = this
    const image = b.image!
    const warnings: string[] = []
    let json: any = {}
    let bodyBytes = new Uint8Array(0)
    try {
      bodyBytes = responseBody(resp)
      json = JSON.parse(Buffer.from(bodyBytes).toString('utf8'))
    } catch (e) {
      warnings.push(`response body is incomplete or not JSON: ${String(e)}`)
    }
    const images: string[] = image.responseShape === 'venice' ? json.images ?? [] : (json.data ?? []).map((d: any) => d.b64_json)
    if (images.length !== image.count) warnings.push(`${images.length} of ${image.count} images returned`)
    // What the provider says it ran, when it echoes the effective request.
    const meta: Record<string, unknown> = { ...json }
    delete meta.images
    delete meta.data
    ctx.writePrivate(`${s.runDir}/response-meta.json`, JSON.stringify(meta, null, 2))
    const req = json.request?.data ?? json.request ?? {}
    const echo: Record<string, unknown> = {}
    const countKey: string = ctx.offer?.images?.count_key ?? ctx.offer?.endpoints?.images?.count_key ?? 'variants'
    for (const k of ['model', countKey, 'resolution', 'format', 'enhance_prompt', 'enable_web_search', 'return_binary', 'style_references']) {
      if (k in req) echo[k] = req[k]
    }
    if ('model' in req && req.model !== b.model) warnings.push(`the provider ran ${ctx.shown(req.model)}, not ${b.model}`)
    if (countKey in req && req[countKey] !== image.count) warnings.push(`the provider ran ${ctx.shown(req[countKey])} images, not ${image.count}`)
    const files = images.map((b64, i) => {
      const f = `${s.runDir}/image-1-${i}.webp`
      ctx.writePrivate(f, Buffer.from(b64, 'base64'))
      return f
    })
    for (const w of warnings) console.log(`[client ${s.label}] warning: ${w}`)
    console.log(`[client ${s.label}] request 1: images ${images.length} of ${image.count} (${files.join(', ')}) response_bytes=${bodyBytes.length}`)
    return { images: images.length, files, response_bytes: bodyBytes.length, echo, warnings }
  }
}
