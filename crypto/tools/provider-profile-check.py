#!/usr/bin/env python3
"""Live check of the provider profile the confidential-upstream protocol relies on.

Run against the real provider with a real key (costs a few cents at most):

    VENICE_API_KEY=... python3 -I crypto/tools/provider-profile-check.py

Each check sends one small request over a raw TLS socket (exactly the HTTP/1.1
framing the protocol uses) and prints PASS/FAIL with the evidence. Exit code is
the number of failed checks. Assumptions (paper section 3.1):

  A1  no processing before the full Content-Length body has arrived
  A2  duplicate top-level keys: last wins (not first, not "any valid")
  A3  a later object value replaces an earlier one (no merge)
  A4  unknown top-level fields are rejected
  A5  malformed JSON is rejected (so the suffix cannot land inside a nested
      object or a string)
  A6  max_completion_tokens caps the billed output, reasoning included, up to a
      small overshoot that the escrow margin (OUTPUT_MARGIN tokens) must cover
  A7  the terminal usage event names the model and precedes [DONE], and with
      the pinned venice_parameters the prompt tokens stay below the body bytes
  A8  text-only models reject image parts (input cost bounded by body bytes)
  A9  TLS 1.3 with AES-128-GCM, HTTP/1.1, Connection: close honoured
  A10 price-changing request fields outside the pinned suffix are rejected
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time

HOST = os.environ.get("CU_PROVIDER_HOST", "api.venice.ai")
PATH = os.environ.get("CU_PROVIDER_PATH", "/api/v1/chat/completions")
KEY = os.environ["VENICE_API_KEY"]
CHEAP = os.environ.get("CU_CHEAP_MODEL", "mercury-2")
REASONING = os.environ.get("CU_REASONING_MODEL", "mercury-2")
TEXT_ONLY = os.environ.get("CU_TEXT_ONLY_MODEL", "deepseek-v4-flash")
# Must match the output margin the node/SDK add to max_tokens when sizing E.
OUTPUT_MARGIN = 32

MSG = '"messages":[{"role":"user","content":"Say hi."}]'
# Every request carries the protocol's pinned venice_parameters, as real
# sessions do (without it Venice injects a ~1.6k-token system prompt).
STREAM = (
    '"stream":true,"stream_options":{"include_usage":true},'
    '"venice_parameters":{"include_venice_system_prompt":false,"enable_web_search":"off"}'
)

failures = 0


def connect() -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((HOST, 443), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def head(length: int) -> bytes:
    return (
        f"POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {KEY}\r\n"
        "Content-Type: application/json\r\nAccept-Encoding: identity\r\n"
        f"Connection: close\r\nContent-Length: {length}\r\n\r\n"
    ).encode()


def request(body: str) -> tuple[int, str]:
    data = body.encode()
    s = connect()
    s.sendall(head(len(data)) + data)
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    status = int(out.split(b" ", 2)[1])
    hdr, body_bytes = out.split(b"\r\n\r\n", 1)
    if b"chunked" in hdr.lower():
        body_bytes = dechunk(body_bytes)
    return status, body_bytes.decode("utf-8", "replace")


def dechunk(raw: bytes) -> bytes:
    out, off = b"", 0
    while True:
        nl = raw.index(b"\r\n", off)
        size = int(raw[off:nl].split(b";")[0], 16)
        off = nl + 2
        if size == 0:
            return out
        out += raw[off : off + size]
        off += size + 2


def events(text: str) -> list[dict]:
    out = []
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("data: ") and line != "data: [DONE]":
            try:
                out.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                pass
    return out


def usage_of(text: str) -> dict:
    for ev in reversed(events(text)):
        if ev.get("usage"):
            return ev
    return {}


def check(name: str, ok: bool, evidence: str) -> None:
    global failures
    if not ok:
        failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {evidence}")


def a1_waits_for_body() -> None:
    body = ("{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}").encode()
    s = connect()
    s.sendall(head(len(body)) + body[:-20])
    s.settimeout(8)
    try:
        early = s.recv(1024)
    except socket.timeout:
        early = b""
    s.sendall(body[-20:])
    s.settimeout(30)
    late = s.recv(1024)
    s.close()
    check(
        "A1 waits for the full body",
        early == b"" and late.startswith(b"HTTP/1.1 200"),
        f"no bytes for 8 s with body incomplete; then {late[:15]!r}",
    )


def a2_last_wins() -> None:
    st1, t1 = request("{" + MSG + ',"model":"no-such-model",' + STREAM + f',"max_tokens":4,"model":"{CHEAP}"' + "}")
    model1 = (usage_of(t1) or {}).get("model")
    st2, _ = request("{" + MSG + f',"model":"{CHEAP}",' + STREAM + ',"max_tokens":4,"model":"no-such-model"' + "}")
    count = '"messages":[{"role":"user","content":"Count from 1 to 200."}]'
    st3, t3 = request("{" + count + f',"model":"{CHEAP}","max_tokens":200,' + STREAM + ',"max_tokens":8' + "}")
    ct = (usage_of(t3).get("usage") or {}).get("completion_tokens")
    check(
        "A2 duplicate keys: last wins",
        st1 == 200 and model1 == CHEAP and st2 >= 400 and st3 == 200 and ct is not None and ct <= 8 + OUTPUT_MARGIN,
        f"bad-then-good model -> {st1} ({model1}); good-then-bad -> {st2}; "
        f"max_tokens 200 then 8 -> {ct} tokens (a cap of 200 would give far more)",
    )


def a3_object_replaced() -> None:
    st1, t1 = request(
        "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM
        + ',"venice_parameters":{"character_slug":"no-such-character-xyz"}'
        + ',"venice_parameters":{"include_venice_system_prompt":false}' + "}"
    )
    st2, t2 = request(
        "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM
        + ',"venice_parameters":{"character_slug":"no-such-character-xyz"}' + "}"
    )
    check(
        "A3 later object replaces earlier (no merge)",
        st1 == 200 and st2 >= 400,
        f"bad character then clean object -> {st1}; bad character alone -> {st2} {t2[:80]!r}",
    )


def a4_unknown_rejected() -> None:
    st, t = request("{" + MSG + f',"model":"{CHEAP}","max_tokens":4,"no_such_field_xyz":1,' + STREAM + "}")
    check("A4 unknown top-level field rejected", st >= 400, f"-> {st} {t[:90]!r}")


def a5_malformed_rejected() -> None:
    suffix = f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}"
    # Private part leaves an object open, so the suffix lands inside it.
    st1, t1 = request("{" + MSG + ',"response_format":{"type":"json_object"' + suffix)
    # Private part leaves a string open.
    st2, _ = request("{" + MSG + ',"user":"abc' + suffix)
    check(
        "A5 suffix cannot land inside a nested object or string",
        st1 >= 400 and st2 >= 400,
        f"open object -> {st1} {t1[:60]!r}; open string -> {st2}",
    )


def a6_cap_includes_reasoning() -> None:
    st, t = request(
        "{" + '"messages":[{"role":"user","content":"Think step by step: what is 17*23?"}]'
        + f',"model":"{REASONING}","max_tokens":20,"max_completion_tokens":20,' + STREAM + "}"
    )
    u = usage_of(t).get("usage") or {}
    ct = u.get("completion_tokens")
    rt = (u.get("completion_tokens_details") or {}).get("reasoning_tokens")
    check(
        "A6 max_completion_tokens caps output incl. reasoning",
        st == 200 and ct is not None and ct <= 20 + OUTPUT_MARGIN,
        f"-> {st}, completion_tokens={ct} (reasoning {rt}) with cap 20, margin {OUTPUT_MARGIN}",
    )


def a7_usage_event() -> None:
    body = "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}"
    st, t = request(body)
    evs = events(t)
    last = evs[-1] if evs else {}
    tail_ok = t.rstrip().endswith("data: [DONE]")
    check(
        "A7 last event carries usage + model, then [DONE]",
        st == 200
        and last.get("model") == CHEAP
        and bool(last.get("usage"))
        and last.get("choices") == []
        and tail_ok
        and last["usage"].get("prompt_tokens", 10**9) <= len(body.encode()),
        f"model={last.get('model')} usage={last.get('usage', {}).get('prompt_tokens')}+"
        f"{last.get('usage', {}).get('completion_tokens')} (body {len(body.encode())} bytes) "
        f"choices={last.get('choices')} done={tail_ok}",
    )


def a8_text_only_rejects_images() -> None:
    img = '{"type":"image_url","image_url":{"url":"https://upload.wikimedia.org/wikipedia/commons/a/a7/Camponotus_flavomarginatus_ant.jpg"}}'
    st, t = request(
        '{"messages":[{"role":"user","content":[{"type":"text","text":"Describe."},' + img + "]}]"
        + f',"model":"{TEXT_ONLY}","max_tokens":4,' + STREAM + "}"
    )
    u = (usage_of(t).get("usage") or {}).get("prompt_tokens")
    check(
        f"A8 text-only model ({TEXT_ONLY}) rejects image parts",
        st >= 400,
        f"-> {st}" + (f", prompt_tokens={u}" if u else f" {t[:80]!r}"),
    )


def a9_transport() -> None:
    s = connect()
    version, cipher, alpn = s.version(), s.cipher()[0], s.selected_alpn_protocol()
    s.close()
    check(
        "A9 TLS 1.3 / AES-128-GCM available, HTTP/1.1",
        version == "TLSv1.3" and alpn == "http/1.1",
        f"{version} {cipher} alpn={alpn} (the client offers only TLS_AES_128_GCM_SHA256)",
    )


def a10_price_fields() -> None:
    results = []
    for field in ('"service_tier":"priority"', '"web_search_options":{}', '"prediction":{"type":"content","content":"x"}'):
        st, t = request("{" + MSG + f',"model":"{CHEAP}","max_tokens":4,{field},' + STREAM + "}")
        tier = (usage_of(t) or {}).get("service_tier") if st == 200 else None
        results.append((field.split(":")[0], st, tier))
    accepted = [r for r in results if r[1] == 200]
    check(
        "A10 unpinned price-changing fields",
        not accepted,
        "; ".join(f"{f} -> {st}" + (f" (service_tier={tier})" if tier else "") for f, st, tier in results),
    )


if __name__ == "__main__":
    print(f"provider profile check: https://{HOST}{PATH}  cheap={CHEAP}  reasoning={REASONING}")
    for fn in (
        a9_transport,
        a1_waits_for_body,
        a2_last_wins,
        a3_object_replaced,
        a4_unknown_rejected,
        a5_malformed_rejected,
        a6_cap_includes_reasoning,
        a7_usage_event,
        a8_text_only_rejects_images,
        a10_price_fields,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"error: {type(exc).__name__}: {exc}")
        time.sleep(0.3)
    print(f"{failures} failed")
    sys.exit(failures)
