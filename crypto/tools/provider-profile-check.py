#!/usr/bin/env python3
"""Live gate for the provider profile the confidential-upstream protocol relies on.

Run against the real provider with a real key (costs a fraction of a cent):

    VENICE_API_KEY=... python3 -I crypto/tools/provider-profile-check.py
    python3 -I crypto/tools/provider-profile-check.py --self-test   # offline, mocked

Each check prints one line, PASS / FAIL / INCONCLUSIVE, with short evidence. The
header records the provider host, the provider build (``x-venice-version``), the
models and the UTC time. Exit status: 0 only if every check PASSes; 1 if any
check FAILs; 2 if none FAIL but at least one is INCONCLUSIVE (the gate is still
closed). The key is never printed (evidence strings are redacted as well).

Rules:

* Every rejection check asserts the exact client-error status and error category
  the provider returns (observed values are pinned in ``EXPECT_*`` below) and
  sends a matched positive control: the same request without the offending part
  must succeed (200, complete stream with a usage event). An outage or a bad key
  therefore cannot pass a rejection check.
* 429, 5xx, timeouts and connection errors are *inconclusive*: retried with
  backoff (``RETRIES``), and if still inconclusive the check is reported
  INCONCLUSIVE and the gate fails. Inconclusive is never PASS.
* A9 and A11 use ``openssl s_client`` (OpenSSL >= 1.1.1, not LibreSSL), because
  Python's ``ssl`` cannot restrict the TLS 1.3 suites. The client's profile is
  reproduced exactly: TLS 1.3 only, ``TLS_AES_128_GCM_SHA256`` as the *only*
  offered suite, X25519, ALPN ``http/1.1``. Set ``CU_OPENSSL`` to pick a binary.

Assumptions (paper section 3.1):

  A1  no processing before the full Content-Length body has arrived
  A2  duplicate top-level keys: last wins (not first, not "any valid")
  A3  a later object value replaces an earlier one (no merge)
  A4  unknown top-level fields are rejected (400, unrecognized key)
  A5  malformed JSON is rejected (400), so the suffix cannot land inside a
      nested object or a string
  A6  max_completion_tokens caps the billed output, reasoning included, up to a
      small overshoot that the reservation margin (OUTPUT_MARGIN tokens) must cover
  A7  the terminal usage event names the model and precedes [DONE], and with
      the pinned venice_parameters the prompt tokens stay below the body bytes
  A8  text-only models reject image parts (400, image not supported)
  A9  TLS 1.3 handshake succeeds when the client offers only
      TLS_AES_128_GCM_SHA256 + X25519 + ALPN http/1.1, and negotiates exactly that
  A10 price-changing request fields outside the pinned suffix are rejected
      (400, unrecognized key)
  A11 a client KeyUpdate sent in the middle of the request body (s_client's
      ``k`` command) is accepted: the provider answers the request correctly
      (200, usage event for the pinned model, [DONE], terminal chunk) and then
      closes the connection itself (``Connection: close`` honoured; our side of
      the pipe stays open, so the close is the server's)
  A12 the event stream is framed the way the usage proof parses it: LF-only
      line endings (no CR anywhere in the dechunked body), every event a single
      ``data: `` line of JSON followed by a blank line, and the stream
      ending in exactly ``data: [DONE]\n\n``. The sidecar and the client
      locate the usage event by a raw ``\ndata: `` and end each chunk's data
      at the first CRLF, so CRLF events or multi-line JSON would break them

A real session sends two client KeyUpdates (KU0 after the handshake, KU1
before the credential record); A11 sends one, mid-body, which is the same
mechanism. Every end-to-end session (``crypto/client/src/driver.ts``) also
exercises both.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

HOST = os.environ.get("CU_PROVIDER_HOST", "api.venice.ai")
PATH = os.environ.get("CU_PROVIDER_PATH", "/api/v1/chat/completions")
KEY = os.environ.get("VENICE_API_KEY", "")
CHEAP = os.environ.get("CU_CHEAP_MODEL", "mercury-2")
REASONING = os.environ.get("CU_REASONING_MODEL", "mercury-2")
TEXT_ONLY = os.environ.get("CU_TEXT_ONLY_MODEL", "deepseek-v4-flash")
# The completion margin the node reserves beyond max_tokens (routstr-core
# CONFIDENTIAL_RESERVE_MARGIN_TOKENS, 16 by default, published in the offer as
# reserve_margin_tokens). Set CU_OUTPUT_MARGIN to the node's value if it differs.
OUTPUT_MARGIN = int(os.environ.get("CU_OUTPUT_MARGIN", "16"))
SUITE = "TLS_AES_128_GCM_SHA256"

# Retry policy for inconclusive outcomes (429, 5xx, timeouts, connection errors).
RETRIES = int(os.environ.get("CU_RETRIES", "2"))
BACKOFF = [2.0, 6.0, 15.0]

# Expected rejections: (status, regex the error body must match). Observed
# against api.venice.ai on 2026-10-10; a change here is a profile drift and
# must be re-reviewed, not silently widened.
EXPECT_UNKNOWN_FIELD = (400, r"Unrecognized key")  # zod "unrecognized_keys"
EXPECT_BAD_JSON = (400, r"Invalid JSON request")
EXPECT_BAD_MODEL = (404, r"model not found")
EXPECT_BAD_CHARACTER = (404, r"character")
EXPECT_IMAGE_REJECTED = (400, r"Image content is not supported")

MSG = '"messages":[{"role":"user","content":"Say hi."}]'
# Every request carries the fixed pins of the shipped offer's chat block
# (docs/CHAT-SUFFIX.md), rendered as the sidecar renders them, as real
# sessions do (without venice_parameters Venice injects a ~1.6k-token system
# prompt). CU_OFFER names another sidecar offer file.
_OFFER_FILE = os.environ.get(
    "CU_OFFER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay", "offer.venice.json")
)
with open(_OFFER_FILE) as _f:
    _CHAT = json.load(_f)["chat"]
STREAM = ",".join(
    json.dumps(k) + ":" + json.dumps(v, sort_keys=True, separators=(",", ":")) for k, v in _CHAT["fixed_pins"]
)
# Positive-control body for CHEAP (well-formed, nothing offending).
BASE = "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}"


# ---------------------------------------------------------------------------
# Transport (all network I/O goes through TRANSPORT so --self-test can mock it)
# ---------------------------------------------------------------------------


class TransportError(Exception):
    """Timeout / connection error / truncated response: inconclusive."""


class Inconclusive(Exception):
    pass


@dataclass
class Resp:
    status: int
    text: str
    headers: dict = field(default_factory=dict)


@dataclass
class SClient:
    rc: int | None  # None: killed after timeout
    out: str
    err: str
    exited_by_itself: bool  # True if s_client exited while our stdin was open


def connect() -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((HOST, 443), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def head(length: int, path: str = "") -> bytes:
    return (
        f"POST {path or PATH} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {KEY}\r\n"
        "Content-Type: application/json\r\nAccept-Encoding: identity\r\n"
        f"Connection: close\r\nContent-Length: {length}\r\n\r\n"
    ).encode()


def parse_http(raw: bytes) -> Resp:
    if b"\r\n\r\n" not in raw:
        raise TransportError(f"incomplete HTTP response ({len(raw)} bytes)")
    hdr, body = raw.split(b"\r\n\r\n", 1)
    lines = hdr.decode("latin1").split("\r\n")
    m = re.match(r"HTTP/1\.[01] (\d{3})", lines[0])
    if not m:
        raise TransportError(f"bad status line {lines[0][:40]!r}")
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = dechunk(body)
    return Resp(int(m.group(1)), body.decode("utf-8", "replace"), headers)


def dechunk(raw: bytes) -> bytes:
    out, off = b"", 0
    while True:
        try:
            nl = raw.index(b"\r\n", off)
            size = int(raw[off:nl].split(b";")[0], 16)
        except ValueError as exc:
            raise TransportError("truncated chunked body") from exc
        off = nl + 2
        if size == 0:
            return out
        if off + size > len(raw):
            raise TransportError("truncated chunked body")
        out += raw[off : off + size]
        off += size + 2


def _recv_all(s: ssl.SSLSocket) -> bytes:
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            return out
        out += chunk


def _http_real(body: str, path: str = "") -> Resp:
    data = body.encode()
    try:
        s = connect()
        try:
            s.sendall(head(len(data), path) + data)
            raw = _recv_all(s)
        finally:
            s.close()
    except (OSError, ssl.SSLError) as exc:  # socket.timeout is an OSError
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    return parse_http(raw)


def _partial_real(body: str, hold_s: float, cut: int, path: str = "") -> tuple[bytes, Resp]:
    """Send all but the last ``cut`` body bytes, wait ``hold_s``, send the rest."""
    data = body.encode()
    try:
        s = connect()
        try:
            s.sendall(head(len(data), path) + data[:-cut])
            s.settimeout(hold_s)
            try:
                early = s.recv(1024)
            except socket.timeout:
                early = b""
            s.settimeout(30)
            s.sendall(data[-cut:])
            raw = early + _recv_all(s)
        finally:
            s.close()
    except (OSError, ssl.SSLError) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    return early, parse_http(raw)


def find_openssl() -> str | None:
    """A real OpenSSL >= 1.1.1 (LibreSSL lacks -ciphersuites)."""
    cands = []
    if os.environ.get("CU_OPENSSL"):
        cands.append(os.environ["CU_OPENSSL"])
    brew = shutil.which("brew")
    if brew:
        try:
            pre = subprocess.run([brew, "--prefix", "openssl@3"], capture_output=True, text=True, timeout=20).stdout.strip()
            if pre:
                cands.append(os.path.join(pre, "bin", "openssl"))
        except (OSError, subprocess.SubprocessError):
            pass
    cands += ["/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"]
    if shutil.which("openssl"):
        cands.append(shutil.which("openssl"))
    for c in cands:
        if not c or not os.access(c, os.X_OK):
            continue
        try:
            v = subprocess.run([c, "version"], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", v)
        if m and tuple(map(int, m.groups())) >= (1, 1, 1):
            return c
    return None


def _s_client_real(brief: bool, steps: list, keep_open: bool, timeout_s: float, groups: str = "X25519") -> SClient:
    """Run s_client with the client's exact TLS profile.

    ``steps`` is a list of bytes (written to stdin) or floats (sleep seconds),
    performed after the handshake. With ``keep_open`` stdin is left open and we
    wait for s_client to exit on its own (the server closing the connection);
    otherwise stdin is closed after the steps, which ends the session.
    """
    exe = find_openssl()
    if not exe:
        raise Inconclusive("no OpenSSL >= 1.1.1 found (set CU_OPENSSL); LibreSSL cannot pin TLS 1.3 suites")
    args = [
        exe, "s_client", "-connect", f"{HOST}:443", "-servername", HOST,
        "-tls1_3", "-ciphersuites", SUITE, "-groups", groups, "-alpn", "http/1.1",
        "-verify_return_error",
    ]
    if brief:
        args.append("-brief")
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    bufs = {"o": b"", "e": b""}

    def rd(k: str, f) -> None:
        for c in iter(lambda: f.read1(65536), b""):
            bufs[k] += c

    ts = [threading.Thread(target=rd, args=(k, f), daemon=True) for k, f in (("o", p.stdout), ("e", p.stderr))]
    for t in ts:
        t.start()
    marker_key, marker = ("e", b"CONNECTION ESTABLISHED") if brief else ("o", b"Verify return code")
    t0 = time.time()
    while marker not in bufs[marker_key] and p.poll() is None and time.time() - t0 < 20:
        time.sleep(0.05)
    exited = False
    try:
        if p.poll() is None and marker in bufs[marker_key]:
            for st in steps:
                if isinstance(st, (int, float)):
                    time.sleep(st)
                else:
                    p.stdin.write(st)
                    p.stdin.flush()
            if not keep_open:
                p.stdin.close()
        try:
            p.wait(timeout=timeout_s)
            exited = keep_open
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            for t in ts:
                t.join(2)
            return SClient(None, bufs["o"].decode("latin1"), bufs["e"].decode("latin1"), False)
    except BrokenPipeError:
        p.wait(timeout=10)
    for t in ts:
        t.join(5)
    try:
        p.stdin.close()
    except (OSError, ValueError):
        pass
    return SClient(p.returncode, bufs["o"].decode("latin1"), bufs["e"].decode("latin1"), exited)


TRANSPORT: dict[str, Callable] = {"http": _http_real, "partial": _partial_real, "s_client": _s_client_real}


def transient(status: int) -> bool:
    return status == 429 or status >= 500


def with_retries(op: Callable, label: str):
    """Run ``op`` (returns a Resp, or a tuple whose last element is a Resp).

    Transient outcomes are retried; if they persist, raise Inconclusive.
    """
    last = ""
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        try:
            res = op()
        except TransportError as exc:
            last = str(exc)
            continue
        r = res[-1] if isinstance(res, tuple) else res
        if transient(r.status):
            last = f"HTTP {r.status} {snip(r.text)}"
            continue
        return res
    raise Inconclusive(f"{label}: still transient after {RETRIES + 1} attempts (last: {last})")


def request(body: str, label: str = "request") -> Resp:
    return with_retries(lambda: TRANSPORT["http"](body), label)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


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


def snip(text: str, n: int = 90) -> str:
    return repr(text[:n])


def stream_ok(r: Resp, model: str) -> bool:
    """A complete, successful stream: 200, usage event for ``model``, [DONE]."""
    u = usage_of(r.text)
    return r.status == 200 and u.get("model") == model and bool(u.get("usage")) and "data: [DONE]" in r.text


def rejected(r: Resp, expect: tuple[int, str]) -> bool:
    return r.status == expect[0] and re.search(expect[1], r.text, re.I) is not None


def control(body: str, model: str, label: str) -> tuple[bool, str]:
    r = request(body, label)
    ok = stream_ok(r, model)
    return ok, f"control -> {r.status}{'' if ok else ' ' + snip(r.text, 60)}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

RESULTS: list[tuple[str, str, str]] = []


def redact(s: str) -> str:
    return s.replace(KEY, "***") if KEY else s


def check(name: str, ok: bool, evidence: str) -> None:
    RESULTS.append((name, "PASS" if ok else "FAIL", redact(evidence)))


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def a1_waits_for_body() -> None:
    body = "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}"
    early, r = with_retries(lambda: TRANSPORT["partial"](body, 8.0, 20), "A1")
    check(
        "A1 waits for the full body",
        early == b"" and stream_ok(r, CHEAP),
        f"{len(early)} bytes in 8 s with body incomplete; then {r.status} complete={stream_ok(r, CHEAP)}",
    )


def a2_last_wins() -> None:
    r1 = request("{" + MSG + ',"model":"no-such-model",' + STREAM + f',"max_tokens":4,"model":"{CHEAP}"' + "}", "A2.1")
    r2 = request("{" + MSG + f',"model":"{CHEAP}",' + STREAM + ',"max_tokens":4,"model":"no-such-model"' + "}", "A2.2")
    count = '"messages":[{"role":"user","content":"Count from 1 to 200."}]'
    r3 = request("{" + count + f',"model":"{CHEAP}","max_tokens":200,' + STREAM + ',"max_tokens":8' + "}", "A2.3")
    ct = (usage_of(r3.text).get("usage") or {}).get("completion_tokens")
    check(
        "A2 duplicate keys: last wins",
        stream_ok(r1, CHEAP) and rejected(r2, EXPECT_BAD_MODEL) and stream_ok(r3, CHEAP)
        and ct is not None and ct <= 8 + OUTPUT_MARGIN,
        f"bad-then-good model -> {r1.status} ({usage_of(r1.text).get('model')}); good-then-bad -> {r2.status} "
        f"{snip(r2.text, 50)}; max_tokens 200 then 8 -> {ct} tokens",
    )


def a3_object_replaced() -> None:
    r1 = request(
        "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM
        + ',"venice_parameters":{"character_slug":"no-such-character-xyz"}'
        + ',"venice_parameters":{"include_venice_system_prompt":false}' + "}", "A3.1"
    )
    r2 = request(
        "{" + MSG + f',"model":"{CHEAP}","max_tokens":4,' + STREAM
        + ',"venice_parameters":{"character_slug":"no-such-character-xyz"}' + "}", "A3.2"
    )
    check(
        "A3 later object replaces earlier (no merge)",
        stream_ok(r1, CHEAP) and rejected(r2, EXPECT_BAD_CHARACTER),
        f"bad character then clean object -> {r1.status}; bad character alone -> {r2.status} {snip(r2.text, 60)}",
    )


def a4_unknown_rejected() -> None:
    ok_c, ev_c = control(BASE, CHEAP, "A4 control")
    r = request("{" + MSG + f',"model":"{CHEAP}","max_tokens":4,"no_such_field_xyz":1,' + STREAM + "}", "A4")
    ok = rejected(r, EXPECT_UNKNOWN_FIELD) and "no_such_field_xyz" in r.text
    check("A4 unknown top-level field rejected", ok_c and ok, f"{ev_c}; with field -> {r.status} {snip(r.text, 70)}")


def a5_malformed_rejected() -> None:
    ok_c, ev_c = control(BASE, CHEAP, "A5 control")
    suffix = f',"model":"{CHEAP}","max_tokens":4,' + STREAM + "}"
    # Private part leaves an object open, so the suffix lands inside it.
    r1 = request("{" + MSG + ',"response_format":{"type":"json_object"' + suffix, "A5.1")
    # Private part leaves a string open.
    r2 = request("{" + MSG + ',"user":"abc' + suffix, "A5.2")
    check(
        "A5 suffix cannot land inside a nested object or string",
        ok_c and rejected(r1, EXPECT_BAD_JSON) and rejected(r2, EXPECT_BAD_JSON),
        f"{ev_c}; open object -> {r1.status} {snip(r1.text, 40)}; open string -> {r2.status} {snip(r2.text, 40)}",
    )


def a6_cap_includes_reasoning() -> None:
    r = request(
        "{" + '"messages":[{"role":"user","content":"Think step by step: what is 17*23?"}]'
        + f',"model":"{REASONING}","max_tokens":20,"max_completion_tokens":20,' + STREAM + "}", "A6"
    )
    u = usage_of(r.text).get("usage") or {}
    ct = u.get("completion_tokens")
    rt = (u.get("completion_tokens_details") or {}).get("reasoning_tokens")
    check(
        "A6 max_completion_tokens caps output incl. reasoning",
        stream_ok(r, REASONING) and ct is not None and ct <= 20 + OUTPUT_MARGIN,
        f"-> {r.status}, completion_tokens={ct} (reasoning {rt}) with cap 20, margin {OUTPUT_MARGIN}",
    )


def a7_usage_event() -> None:
    r = request(BASE, "A7")
    evs = events(r.text)
    last = evs[-1] if evs else {}
    tail_ok = r.text.rstrip().endswith("data: [DONE]")
    usage = last.get("usage") or {}
    check(
        "A7 last event carries usage + model, then [DONE]",
        r.status == 200
        and last.get("model") == CHEAP
        and bool(usage)
        and last.get("choices") == []
        and tail_ok
        and usage.get("prompt_tokens", 10**9) <= len(BASE.encode()),
        f"-> {r.status} model={last.get('model')} usage={usage.get('prompt_tokens')}+"
        f"{usage.get('completion_tokens')} (body {len(BASE.encode())} bytes) choices={last.get('choices')} done={tail_ok}",
    )


def a12_sse_framing() -> None:
    r = request(BASE, "A12")
    text = r.text
    problems = []
    if "\r" in text:
        problems.append("CR in the event stream")
    if not text.endswith("data: [DONE]\n\n"):
        problems.append(f"does not end in data: [DONE]\\n\\n ({snip(text[-24:], 24)})")
    blocks = text.split("\n\n")
    if blocks and blocks[-1] == "":
        blocks.pop()
    for b in blocks:
        if "\n" in b or not b.startswith("data: "):
            problems.append(f"event is not one data: line {snip(b, 40)}")
            break
        if b == "data: [DONE]":
            continue
        try:
            json.loads(b[6:])
        except json.JSONDecodeError:
            problems.append(f"event is not JSON {snip(b, 40)}")
            break
    check(
        "A12 SSE framing: LF-only, one data: line per event",
        stream_ok(r, CHEAP) and not problems,
        f"-> {r.status}, {len(blocks)} events" + (f", {problems[0]}" if problems else ", LF-only"),
    )


def a8_text_only_rejects_images() -> None:
    text = '{"type":"text","text":"Describe."}'
    img = '{"type":"image_url","image_url":{"url":"https://www.gstatic.com/webp/gallery/1.jpg"}}'
    tail = f',"model":"{TEXT_ONLY}","max_tokens":4,' + STREAM + "}"
    ok_c, ev_c = control('{"messages":[{"role":"user","content":[' + text + "]}]" + tail, TEXT_ONLY, "A8 control")
    r = request('{"messages":[{"role":"user","content":[' + text + "," + img + "]}]" + tail, "A8")
    pt = (usage_of(r.text).get("usage") or {}).get("prompt_tokens")
    check(
        f"A8 text-only model ({TEXT_ONLY}) rejects image parts",
        ok_c and rejected(r, EXPECT_IMAGE_REJECTED),
        f"{ev_c}; with image_url -> {r.status}" + (f", prompt_tokens={pt}" if pt else f" {snip(r.text[r.text.find('Image'):] if 'Image' in r.text else r.text, 50)}"),
    )


def _handshake_fields(text: str) -> dict:
    def grab(pat: str) -> str | None:
        m = re.search(pat, text)
        return m.group(1).strip() if m else None

    return {
        "protocol": grab(r"Protocol(?: version)?\s*:\s*(\S+)"),
        "cipher": grab(r"Cipher(?:suite)?(?: is|:)\s*(\S+)"),
        "alpn": grab(r"ALPN protocol:\s*(\S+)"),
        "verify": grab(r"Verify return code:\s*(\d+)"),
        "group": grab(r"(?:Peer|Server) Temp Key:\s*([A-Za-z0-9_]+)"),
    }


_HS_FAIL = re.compile(r"handshake failure|no shared cipher|no suitable|wrong version|protocol version|alert", re.I)


def a9_transport() -> None:
    last = ""
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        sc = TRANSPORT["s_client"](False, [], False, 30.0)
        f = _handshake_fields(sc.out)
        if f["protocol"] and f["cipher"]:
            break
        if sc.rc not in (0, None) and _HS_FAIL.search(sc.err):
            # The server refused the client's offer: a real FAIL, not an outage.
            check("A9 TLS 1.3 / AES-128-GCM only / X25519 / ALPN http/1.1", False,
                  f"handshake refused: {snip(sc.err.strip().splitlines()[-1] if sc.err.strip() else '', 80)}")
            return
        last = f"rc={sc.rc} {snip(sc.err.strip()[-80:])}"
    else:
        raise Inconclusive(f"A9: no handshake after {RETRIES + 1} attempts (last: {last})")
    ok = (
        f["protocol"] == "TLSv1.3"
        and f["cipher"] == SUITE
        and f["alpn"] == "http/1.1"
        and f["verify"] == "0"
        and f["group"] == "X25519"
    )
    check(
        "A9 TLS 1.3 / AES-128-GCM only / X25519 / ALPN http/1.1",
        ok,
        f"offered only {SUITE}+X25519+http/1.1 -> {f['protocol']} {f['cipher']} group={f['group']} "
        f"alpn={f['alpn']} verify={f['verify']}",
    )


def a11_keyupdate_mid_request() -> None:
    body = BASE.encode()
    # The resumed chunk must not start with an s_client command letter.
    assert body[30:31] not in (b"k", b"K", b"Q", b"R", b"C")
    steps = [head(len(body)) + body[:30], 0.5, b"k\n", 0.5, body[30:]]
    last = ""
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        sc = TRANSPORT["s_client"](True, steps, True, 45.0)
        f = _handshake_fields(sc.err)
        if "HTTP/1." not in sc.out and sc.rc not in (0, None) and _HS_FAIL.search(sc.err):
            check("A11 client KeyUpdate mid-body; complete answer; server closes", False,
                  f"handshake refused: {snip(sc.err.strip().splitlines()[-1] if sc.err.strip() else '', 80)}")
            return
        if "HTTP/1." not in sc.out:
            last = f"rc={sc.rc} no response {snip(sc.err.strip()[-60:])}"
            continue
        try:
            r = parse_http(sc.out.encode("latin1"))
        except TransportError as exc:
            last = str(exc)
            continue
        if transient(r.status):
            last = f"HTTP {r.status}"
            continue
        break
    else:
        raise Inconclusive(f"A11: {last} after {RETRIES + 1} attempts")
    ku = "KEYUPDATE" in sc.err or "KEYUPDATE" in sc.out
    complete = sc.out.rstrip("\r\n").endswith("0") or "chunked" not in r.headers.get("transfer-encoding", "")
    ok = (
        ku
        and f["protocol"] == "TLSv1.3"
        and f["cipher"] == SUITE
        and stream_ok(r, CHEAP)
        and complete
        and sc.exited_by_itself
    )
    check(
        "A11 client KeyUpdate mid-body; complete answer; server closes",
        ok,
        f"keyupdate_sent={ku} {f['protocol']} {f['cipher']} -> {r.status} complete_stream={stream_ok(r, CHEAP) and complete} "
        f"server_closed={sc.exited_by_itself} conn_hdr={r.headers.get('connection')}",
    )


def a10_price_fields() -> None:
    ok_c, ev_c = control(BASE, CHEAP, "A10 control")
    parts, all_ok = [], ok_c
    for fld in ('"service_tier":"priority"', '"web_search_options":{}', '"prediction":{"type":"content","content":"x"}'):
        name = fld.split(":")[0].strip('"')
        r = request("{" + MSG + f',"model":"{CHEAP}","max_tokens":4,{fld},' + STREAM + "}", f"A10 {name}")
        ok = rejected(r, EXPECT_UNKNOWN_FIELD) and name in r.text
        all_ok = all_ok and ok
        parts.append(f"{name} -> {r.status}{'' if ok else ' ' + snip(r.text, 50)}")
    check("A10 unpinned price-changing fields rejected", all_ok, f"{ev_c}; " + "; ".join(parts))


CHECKS = [
    a9_transport,
    a11_keyupdate_mid_request,
    a1_waits_for_body,
    a2_last_wins,
    a3_object_replaced,
    a4_unknown_rejected,
    a5_malformed_rejected,
    a6_cap_includes_reasoning,
    a7_usage_event,
    a12_sse_framing,
    a8_text_only_rejects_images,
    a10_price_fields,
]


def tag(fn: Callable) -> str:
    return fn.__name__.split("_")[0].upper()


def run_all(pause: float = 0.3, quiet: bool = False, checks: list | None = None) -> int:
    RESULTS.clear()
    for fn in checks or CHECKS:
        n = len(RESULTS)
        try:
            fn()
        except Inconclusive as exc:
            RESULTS.append((f"{tag(fn)} ({fn.__name__})", "INCONCLUSIVE", redact(str(exc))))
        except Exception as exc:  # noqa: BLE001
            RESULTS.append((f"{tag(fn)} ({fn.__name__})", "FAIL", redact(f"error: {type(exc).__name__}: {exc}")))
        if not quiet:
            for name, verdict, ev in RESULTS[n:]:
                print(f"{verdict:12s} {name}: {ev}", flush=True)
        time.sleep(pause)
    fails = sum(v == "FAIL" for _, v, _ in RESULTS)
    inc = sum(v == "INCONCLUSIVE" for _, v, _ in RESULTS)
    passed = sum(v == "PASS" for _, v, _ in RESULTS)
    if not quiet:
        print(f"summary: {passed} PASS, {fails} FAIL, {inc} INCONCLUSIVE of {len(RESULTS)}")
    return 1 if fails else (2 if inc else 0)


# ---------------------------------------------------------------------------
# Image route (--images, paid: three cheap images). The confidential image
# session pins model, count and the paid extras in a suffix and charges a flat
# price, so the route must keep the last duplicate (arrays replaced, not
# merged), reject unknown keys and unknown models (no silent fallback), never
# reflect the request head (success or error), wait for the whole body before
# it starts, and speak the v2 transport: TLS 1.3, the one suite, P-256 only,
# and a client KeyUpdate in the middle of the body.
#   I1 last duplicate wins (count, model)        I6 paid extras and arrays pinned
#   I2 unknown keys rejected                     I7 waits for the full body
#   I3 unknown model refused, no fallback        I8 TLS 1.3 / suite / P-256 / ALPN
#   I4 no head reflection (success and error)    I9 KeyUpdate mid-body
#   I5 an open string cannot swallow the suffix
# ---------------------------------------------------------------------------

IMAGE_PATH = os.environ.get("CU_IMAGE_PATH", "/api/v1/image/generate")
IMAGE_MODEL = os.environ.get("CU_IMAGE_MODEL", "z-image-turbo")
IMAGE_PINS = ('"return_binary":false,"enhance_prompt":false,"enable_web_search":false,'
              '"style_references":[],"format":"webp"')


def image_request(body: str, label: str) -> Resp:
    return with_retries(lambda: TRANSPORT["http"](body, IMAGE_PATH), label)


def _reflects(r: Resp) -> bool:
    return "authorization" in r.text.lower() or bool(KEY and KEY in r.text)


def _image_json(r: Resp) -> dict:
    try:
        d = json.loads(r.text)
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def i1_image_last_wins() -> None:
    # Every value the suffix pins appears earlier with a dearer or different
    # value: the count, each paid extra, the binary switch, a non-empty array
    # (which must be replaced, not merged) and an unknown model.
    r = image_request(
        '{"prompt":"a red apple on a white table","variants":4,"enhance_prompt":true,"enable_web_search":true,'
        '"return_binary":true,"style_references":["https://example.com/style.png"],'
        f'"model":"no-such-model","model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}', "I1")
    d = _image_json(r)
    echo = (d.get("request") or {}).get("data") or {}
    n = len(d.get("images") or [])
    check(
        "I1 image route: last duplicate wins (count, model)",
        r.status == 200 and n == 1 and echo.get("model") == IMAGE_MODEL and echo.get("variants") == 1,
        f"{r.status}; {n} image(s), echoed variants={echo.get('variants')} model={echo.get('model')}",
    )
    extras = {k: echo.get(k) for k in ("enhance_prompt", "enable_web_search", "return_binary", "style_references")}
    # The echo leaves out an empty array; a merged one would still hold the URL.
    check(
        "I6 image route: paid extras and arrays take the pinned value (array replaced, not merged)",
        r.status == 200 and r.headers.get("content-type", "").startswith("application/json")
        and extras["enhance_prompt"] is False and extras["enable_web_search"] is False
        and extras["return_binary"] is False and extras["style_references"] in (None, [])
        and "example.com/style.png" not in json.dumps(echo),
        f"{r.status} {r.headers.get('content-type', '?')}; echoed {extras}",
    )
    check("I4 image route: no request-head reflection (success)", r.status == 200 and not _reflects(r),
          f"{r.status}; response {'reflects' if _reflects(r) else 'does not reflect'} the request head")


def i2_image_unknown_rejected() -> None:
    r = image_request(f'{{"prompt":"x","bogus_field_xyz":1,"model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}', "I2")
    check("I2 image route: unknown keys rejected (free)", rejected(r, EXPECT_UNKNOWN_FIELD), f"{r.status} {snip(r.text, 60)}")
    check("I4e image route: no request-head reflection (error body, free)", 400 <= r.status < 500 and not _reflects(r),
          f"{r.status}; error body {'reflects' if _reflects(r) else 'does not reflect'} the request head")


def i7_image_waits_for_body() -> None:
    body = f'{{"prompt":"a small blue cup","model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}'
    early, r = with_retries(lambda: TRANSPORT["partial"](body, 8.0, 20, IMAGE_PATH), "I7")
    n = len(_image_json(r).get("images") or [])
    check("I7 image route: waits for the full body (paid)", early == b"" and r.status == 200 and n == 1,
          f"{len(early)} bytes in 8 s with body incomplete; then {r.status}, {n} image(s)")


def i8_image_tls_p256() -> None:
    # The v2 client offers only P-256 (the joint key share), with the one suite.
    sc = TRANSPORT["s_client"](False, [], False, 30.0, "P-256")
    f = _handshake_fields(sc.out)
    if not (f["protocol"] and f["cipher"]) and not (sc.rc not in (0, None) and _HS_FAIL.search(sc.err)):
        raise Inconclusive(f"I8: no handshake (rc={sc.rc} {snip(sc.err.strip()[-60:])})")
    p256 = "prime256v1" in sc.out or "P-256" in sc.out or f["group"] in ("P-256", "prime256v1")
    check("I8 TLS 1.3 / AES-128-GCM / P-256 only / ALPN http/1.1 (free)",
          f["protocol"] == "TLSv1.3" and f["cipher"] == SUITE and f["alpn"] == "http/1.1" and f["verify"] == "0" and p256,
          f"offered only {SUITE}+P-256+http/1.1 -> {f['protocol']} {f['cipher']} group={f['group']} p256={p256} "
          f"alpn={f['alpn']} verify={f['verify']}")


def i9_image_keyupdate_mid_body() -> None:
    body = f'{{"prompt":"a small green leaf","model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}'.encode()
    assert body[30:31] not in (b"k", b"K", b"Q", b"R", b"C")
    steps = [head(len(body), IMAGE_PATH) + body[:30], 0.5, b"k\n", 0.5, body[30:]]
    sc = TRANSPORT["s_client"](True, steps, True, 90.0, "P-256")
    if "HTTP/1." not in sc.out:
        raise Inconclusive(f"I9: no response (rc={sc.rc} {snip(sc.err.strip()[-60:])})")
    r = parse_http(sc.out.encode("latin1"))
    ku = "KEYUPDATE" in sc.err or "KEYUPDATE" in sc.out
    n = len(_image_json(r).get("images") or [])
    check("I9 image route: client KeyUpdate mid-body; image returned; server closes (paid)",
          ku and r.status == 200 and n == 1 and sc.exited_by_itself,
          f"keyupdate_sent={ku} -> {r.status}, {n} image(s), server_closed={sc.exited_by_itself}")


def i3_image_unknown_model() -> None:
    r = image_request(f'{{"prompt":"x","model":"{IMAGE_MODEL}","model":"no-such-model","variants":1,{IMAGE_PINS}}}', "I3")
    check("I3 image route: unknown model refused, no fallback (free)", 400 <= r.status < 500 and r.status != 429,
          f"{r.status} {snip(r.text, 60)}")


def i5_image_malformed() -> None:
    r = image_request(f'{{"prompt":"x,"model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}', "I5")
    check("I5 image route: an open string cannot swallow the suffix (free)", 400 <= r.status < 500 and r.status != 429,
          f"{r.status} {snip(r.text, 60)}")


IMAGE_CHECKS = [i8_image_tls_p256, i2_image_unknown_rejected, i3_image_unknown_model, i5_image_malformed,
                i1_image_last_wins, i7_image_waits_for_body, i9_image_keyupdate_mid_body]


def provider_build() -> str:
    try:
        r = TRANSPORT["http"](BASE)
        return r.headers.get("x-venice-version", "?") + f" (probe {r.status})"
    except Exception as exc:  # noqa: BLE001
        return f"? ({type(exc).__name__})"


# ---------------------------------------------------------------------------
# --self-test: mocked transport, proves the negative controls
# ---------------------------------------------------------------------------


class MockProvider:
    """A minimal model of the provider profile, with fault injection."""

    ALLOWED = {"messages", "model", "max_tokens", "max_completion_tokens", "n", "stream",
               "stream_options", "venice_parameters", "response_format", "user"}
    MODELS = {CHEAP, REASONING, TEXT_ONLY}

    def __init__(self, status: int | None = None, lenient: bool = False, cipher: str = SUITE,
                 hs_refuse: bool = False, timeout: bool = False, early: bool = False,
                 no_close: bool = False, no_ku: bool = False, crlf: bool = False,
                 pretty: bool = False) -> None:
        self.status, self.lenient, self.cipher = status, lenient, cipher
        self.hs_refuse, self.timeout, self.early = hs_refuse, timeout, early
        self.no_close, self.no_ku = no_close, no_ku
        self.crlf, self.pretty = crlf, pretty

    def _answer(self, body: str) -> Resp:
        if self.timeout:
            raise TransportError("timeout")
        if self.status is not None:
            return Resp(self.status, '{"error":"mock"}')
        try:
            d = json.loads(body)  # duplicate keys: last wins, objects replaced
        except json.JSONDecodeError:
            return Resp(400, '{"error":"Invalid JSON request"}')
        extra = set(d) - self.ALLOWED
        if extra and not self.lenient:
            return Resp(400, '{"error":"Invalid request parameters","details":{"_errors":["Unrecognized key(s) in object: '
                        + ", ".join(f"'{k}'" for k in sorted(extra)) + '"]}}')
        if d.get("model") not in self.MODELS:
            return Resp(404, '{"error":"Specified model not found: x"}')
        if (d.get("venice_parameters") or {}).get("character_slug"):
            return Resp(404, '{"error":"No character could be found from the provided character_slug"}')
        content = d["messages"][0]["content"]
        if isinstance(content, list) and any(p.get("type") == "image_url" for p in content) and d["model"] == TEXT_ONLY:
            return Resp(400, '{"error":"Invalid request parameters","details":{"messages":{"_errors":["Image content is not supported by this model."]}}}')
        cap = min(d.get("max_completion_tokens") or 10**6, d.get("max_tokens") or 10**6)
        ct = min(cap, 10)
        u = {"model": d["model"], "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": ct}}
        usage = json.dumps(u, indent=1) if self.pretty else json.dumps(u, separators=(",", ":"))
        text = 'data: {"model":"%s","choices":[{"delta":{"content":"hi"}}]}\n\ndata: %s\n\ndata: [DONE]\n\n' % (d["model"], usage)
        if self.crlf:
            text = text.replace("\n", "\r\n")
        return Resp(200, text, {"x-venice-version": "mock"})

    def http(self, body: str) -> Resp:
        return self._answer(body)

    def partial(self, body: str, hold_s: float, cut: int, path: str = "") -> tuple[bytes, Resp]:
        r = self._answer(body)
        return (b"HTTP/1.1 400" if self.early else b""), r

    def s_client(self, brief: bool, steps: list, keep_open: bool, timeout_s: float, groups: str = "X25519") -> SClient:
        if self.timeout:
            return SClient(None, "", "connect: Operation timed out", False)
        if self.hs_refuse:
            return SClient(1, "", "error:0A000410:SSL routines::ssl/tls alert handshake failure", False)
        if brief:
            err = f"CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: {self.cipher}\nPeer Temp Key: X25519, 253 bits\n"
            if not self.no_ku:
                err += "KEYUPDATE\n"
            raw = b"".join(s for s in steps if isinstance(s, bytes) and s != b"k\n")
            body = raw.split(b"\r\n\r\n", 1)[1].decode()
            r = self._answer(body)
            chunk = r.text.encode()
            out = (f"HTTP/1.1 {r.status} X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                   f"{len(chunk):x}\r\n").encode() + chunk + b"\r\n0\r\n\r\n"
            if self.no_close:
                return SClient(None, out.decode("latin1"), err, False)
            return SClient(0, out.decode("latin1"), err, True)
        out = (f"New, TLSv1.3, Cipher is {self.cipher}\nPeer Temp Key: X25519, 253 bits\nProtocol: TLSv1.3\n"
               "ALPN protocol: http/1.1\nVerify return code: 0 (ok)\n")
        return SClient(0, out, "", False)


def self_test() -> int:
    global RETRIES, BACKOFF, KEY
    RETRIES, BACKOFF = 1, [0.0]
    KEY = KEY or "sk-selftest-not-a-key"
    saved = dict(TRANSPORT)
    # (name, provider, predicate over {check: verdict}, what it proves)
    def verdicts() -> dict:
        return {name.split()[0]: v for name, v, _ in RESULTS}

    rejection = ["A2", "A3", "A4", "A5", "A8", "A10"]
    scenarios = [
        ("healthy provider passes", MockProvider(),
         lambda v, rc: rc == 0 and all(x == "PASS" for x in v.values())),
        ("outage: 503 everywhere is never PASS", MockProvider(status=503),
         lambda v, rc: rc != 0 and all(v.get(k) == "INCONCLUSIVE" for k in rejection + ["A1", "A6", "A7", "A11", "A12"])),
        ("rate limit: 429 everywhere is never PASS", MockProvider(status=429),
         lambda v, rc: rc != 0 and not any(v.get(k) == "PASS" for k in rejection)),
        ("timeouts are inconclusive, gate closed", MockProvider(timeout=True),
         lambda v, rc: rc != 0 and all(x == "INCONCLUSIVE" for x in v.values())),
        ("bad key: 401 everywhere fails the controls", MockProvider(status=401),
         lambda v, rc: rc == 1 and not any(v.get(k) == "PASS" for k in rejection)),
        ("wrong cipher (CHACHA20) fails A9/A11", MockProvider(cipher="TLS_CHACHA20_POLY1305_SHA256"),
         lambda v, rc: rc == 1 and v.get("A9") == "FAIL" and v.get("A11") == "FAIL"),
        ("AES-128-only offer refused fails A9", MockProvider(hs_refuse=True),
         lambda v, rc: rc == 1 and v.get("A9") == "FAIL" and v.get("A11") == "FAIL"),
        ("lenient provider (accepts unknown fields) fails A4/A10", MockProvider(lenient=True),
         lambda v, rc: rc == 1 and v.get("A4") == "FAIL" and v.get("A10") == "FAIL"),
        ("early answer on partial body fails A1", MockProvider(early=True),
         lambda v, rc: rc == 1 and v.get("A1") == "FAIL"),
        ("server never closes after the answer fails A11", MockProvider(no_close=True),
         lambda v, rc: rc == 1 and v.get("A11") == "FAIL"),
        ("KeyUpdate not sent fails A11", MockProvider(no_ku=True),
         lambda v, rc: rc == 1 and v.get("A11") == "FAIL"),
        ("CRLF event stream fails A12", MockProvider(crlf=True),
         lambda v, rc: rc == 1 and v.get("A12") == "FAIL"),
        ("multi-line (pretty-printed) usage event fails A12", MockProvider(pretty=True),
         lambda v, rc: rc == 1 and v.get("A12") == "FAIL"),
    ]
    bad = 0
    try:
        for label, mock, pred in scenarios:
            TRANSPORT.update(http=mock.http, partial=mock.partial, s_client=mock.s_client)
            rc = run_all(pause=0.0, quiet=True)
            v = verdicts()
            ok = pred(v, rc)
            bad += not ok
            summary = " ".join(f"{k}={x[0]}" for k, x in v.items())
            print(f"{'ok  ' if ok else 'BAD '} {label}: exit={rc} [{summary}]")
    finally:
        TRANSPORT.update(saved)
    print(f"self-test: {len(scenarios) - bad}/{len(scenarios)} scenarios behave as required")
    return 1 if bad else 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if not KEY:
        print("VENICE_API_KEY is not set", file=sys.stderr)
        return 2
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"provider profile check  {now}")
    print(f"  provider: https://{HOST}{PATH}  build: {provider_build()}")
    print(f"  models: cheap={CHEAP} reasoning={REASONING} text_only={TEXT_ONLY}")
    print(f"  openssl: {find_openssl() or 'NOT FOUND'}  retries={RETRIES}")
    if "--images" in sys.argv[1:]:
        print(f"  image route: {IMAGE_PATH} model={IMAGE_MODEL} (three paid images)")
        return run_all(checks=IMAGE_CHECKS)
    return run_all()


if __name__ == "__main__":
    sys.exit(main())
