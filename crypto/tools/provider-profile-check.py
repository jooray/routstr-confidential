#!/usr/bin/env python3
"""Live gate for the provider profile the confidential-upstream protocol relies on.

Run against the real provider with a real key (costs a fraction of a cent):

    VENICE_API_KEY=... python3 -I crypto/tools/provider-profile-check.py            # A1-A14
    VENICE_API_KEY=... python3 -I crypto/tools/provider-profile-check.py --images   # I1-I10 (paid)
    VENICE_API_KEY=... python3 -I crypto/tools/provider-profile-check.py --h2       # H1-H8
    python3 -I crypto/tools/provider-profile-check.py --self-test   # offline, mocked

Any other argument (a mistyped mode, ``--h2`` with ``--images``, an option
without its value) is refused with exit status 2 before anything runs.

The provider is the one a sidecar offer file names: ``--offer FILE`` (default
``crypto/relay/offer.venice.json``) gives the host, the chat route, the fixed
pins and the ``h2`` block; ``--key-env NAME`` (default ``VENICE_API_KEY``) the
variable that holds the key; ``--model ID`` a cheap chat model of that provider.
The key is sent only to the offer's ``upstream_host``.

``--h2`` checks what framing "2" of protocol v3 needs from a provider
(PROTOCOL-V3.md section 5.6) and ends with a verdict line, ``offer "2": yes``
or ``no, because ...``. Run it before adding ``"2"`` to the offer's ``http``
list. It idles one connection for ``--h2-idle SECS`` (default: the offer's
``h2.idle_secs``, 300), sends one body of ``--h2-body-bytes N`` (default
8388608, the sidecar's ``--max-body``), and, when the offer serves images over
HTTP/2, generates one image (``--h2-no-images`` skips that path and leaves H7
open for images).

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
* A9, A11 and every ``--h2`` item use ``openssl s_client`` (OpenSSL >= 1.1.1,
  not LibreSSL), because Python's ``ssl`` cannot restrict the TLS 1.3 suites
  or send a KeyUpdate. The client's profile is reproduced: TLS 1.3 only,
  ``TLS_AES_128_GCM_SHA256`` as the *only* offered suite, P-256 as the only
  group (the joint key share), ALPN ``http/1.1`` (framing "1.1") or ``h2``
  (framing "2"). Set ``CU_OPENSSL`` to pick a binary.

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
  A13 a vision model bills an image part as prompt tokens: an inline (data
      URI) image raises prompt_tokens over the same request without it, and
      the usage event reports nothing besides the token counts the node prices
      (prompt, completion, cached reads, cache writes), so the settlement at
      the frozen rates covers the image. Whether the provider's own charge is
      tokens x rate is not visible in the API; it was measured on Venice
      against the account balance (crypto/PROGRESS-CONFIDENTIAL.md)
  A9  TLS 1.3 handshake succeeds when the client offers only
      TLS_AES_128_GCM_SHA256 + P-256 + ALPN http/1.1, and negotiates exactly that
  A10 price-changing request fields outside the pinned suffix are rejected
      (400, unrecognized key)
  A11 a client KeyUpdate sent between the request head and the body
      (s_client's ``k`` command; where the node's KeyUpdate sits in framing
      "1.1") is accepted: the provider answers the request correctly
      (200, usage event for the pinned model, [DONE], terminal chunk) and then
      closes the connection itself (``Connection: close`` honoured; our side of
      the pipe stays open, so the close is the server's)
  A14 an output cap the provider recognizes under another name than the
      offer's cap keys (``max_output_tokens``; any of max_tokens /
      max_completion_tokens the offer does not pin) in the private part of the
      body does not lift the pinned cap: the request is refused, or its
      completion stays within the pinned cap (plus OUTPUT_MARGIN)
  A12 the event stream is framed the way the usage proof parses it: LF-only
      line endings (no CR anywhere in the dechunked body), every event a single
      ``data: `` line of JSON followed by a blank line, and the stream
      ending in exactly ``data: [DONE]\n\n``. The sidecar and the client
      locate the usage event by a raw ``\ndata: `` and end each chunk's data
      at the first CRLF, so CRLF events or multi-line JSON would break them

A real framing-"1.1" connection has exactly this KeyUpdate: the node writes
the request head with the credential under the epoch-0 key and a KeyUpdate in
one write, and the client's body follows under the next key. Every end-to-end
connection (``crypto/client/src/driver.ts``) exercises it as well.

Framing "2" (``--h2``, PROTOCOL-V3.md section 5.6):

  H1  TLS 1.3 with ALPN h2 on the API host, for the client's exact offer
      (the one suite, P-256 only)
  H2  a TLS KeyUpdate right after the first flight of an HTTP/2 connection
      (the connection head) is accepted: the next request is answered.
      Control: the same connection without the KeyUpdate
  H3  the provider keeps the request dynamic table: its SETTINGS leave
      HEADER_TABLE_SIZE at the default 4096 or above (a smaller table needs
      a table size update the pinned request block cannot carry; nghttp2
      answers with COMPRESSION_ERROR), and a request that names the
      credential by index (``be``) is authenticated
  H4  HEADER_TABLE_SIZE = 0 is honoured for response headers: every response
      header block decodes with an empty dynamic table
  H5  a request naming ``authorization`` by index only is authenticated right
      after the head and again after the idle time; control: the same request
      with no authorization field is refused (401, 402 or 403)
  H6  a request body of the node's body limit passes the provider's flow
      control and is answered
  H7  no response reflects the credential: headers (Huffman decoded),
      trailers and bodies of the probe GET, a chat 200, chat errors (unknown
      model, unknown field, no authorization) and, for image offers, the image
      error and the image success (the paths of item 8 / I4)
  H8  the event stream of a 200 ends the way the usage disclosure parses it:
      ``data: <usage JSON>\n\ndata: [DONE]\n\n`` up to END_STREAM, LF only,
      only the frames section 5.4 allows in between, within 16 KiB
"""

from __future__ import annotations

import base64
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I leaves it out
import cu_h2 as h2  # noqa: E402
from dataclasses import dataclass, field
from typing import Callable



# Every option this script takes. Anything else is refused before any check
# runs: a mistyped or unsupported mode must never fall back to another check
# and end in a PASS for something that was not checked.
_VALUE_OPTIONS = ("--offer", "--key-env", "--model", "--image-model", "--h2-idle", "--h2-body-bytes")
_SWITCHES = ("--self-test", "--h2", "--images", "--h2-no-images")


def _argv_problem(argv: list[str]) -> str | None:
    """Why ``argv`` (without the program name) is refused, or ``None``."""
    i = 0
    seen: set[str] = set()
    while i < len(argv):
        a = argv[i]
        if a in seen:
            return f"{a} given twice"
        seen.add(a)
        if a in _VALUE_OPTIONS:
            if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
                return f"{a} needs a value"
            i += 2
            continue
        if a not in _SWITCHES:
            return f"unknown argument {a!r}"
        i += 1
    if "--h2" in seen and "--images" in seen:
        return "--h2 and --images are separate runs"
    if "--h2-no-images" in seen and "--h2" not in seen:
        return "--h2-no-images belongs to --h2"
    for a in ("--h2-idle", "--h2-body-bytes"):
        if a in seen and "--h2" not in seen:
            return f"{a} belongs to --h2"
    return None


if __name__ == "__main__" and (_problem := _argv_problem(sys.argv[1:])):
    print(f"provider-profile-check: {_problem}", file=sys.stderr)
    print("usage: provider-profile-check.py [--self-test | --images | --h2 [--h2-idle S] [--h2-body-bytes N] "
          "[--h2-no-images]] [--offer FILE] [--key-env VAR] [--model ID] [--image-model ID]", file=sys.stderr)
    sys.exit(2)


def _flag(name: str, default: str | None = None) -> str | None:
    a = sys.argv[1:]
    return a[a.index(name) + 1] if name in a and a.index(name) + 1 < len(a) else default


def _route(head_template: str) -> str:
    m = re.match(r"POST (\S+) HTTP/1\.1\r\n", head_template or "")
    return m.group(1) if m else ""


# The provider is the one the sidecar offer file names.
_OFFER_FILE = _flag("--offer") or os.environ.get(
    "CU_OFFER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay", "offer.venice.json")
)
with open(_OFFER_FILE) as _f:
    OFFER = json.load(_f)
_CHAT = OFFER["chat"]
_IMAGES = (OFFER.get("endpoints") or {}).get("images") or {}
HOST = os.environ.get("CU_PROVIDER_HOST") or OFFER.get("upstream_host") or "api.venice.ai"
PATH = os.environ.get("CU_PROVIDER_PATH") or _route(OFFER.get("head_template", "")) or "/api/v1/chat/completions"
KEY_ENV = _flag("--key-env") or os.environ.get("CU_KEY_ENV", "VENICE_API_KEY")
KEY = os.environ.get(KEY_ENV, "")
CHEAP = _flag("--model") or os.environ.get("CU_CHEAP_MODEL", "mistral-small-3-2-24b-instruct")
REASONING = os.environ.get("CU_REASONING_MODEL", "openai-gpt-oss-120b")
TEXT_ONLY = os.environ.get("CU_TEXT_ONLY_MODEL", "deepseek-v4-flash")
VISION = os.environ.get("CU_VISION_MODEL", "mistral-small-3-2-24b-instruct")
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
# Every request carries the fixed pins of the offer's chat block
# (docs/CHAT-SUFFIX.md), rendered as the sidecar renders them, as real
# connections do (without venice_parameters Venice injects a ~1.6k-token
# system prompt).
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


def _s_client_real(brief: bool, steps: list, keep_open: bool, timeout_s: float, groups: str = "P-256", alpn: str = "http/1.1") -> SClient:
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
        "-tls1_3", "-ciphersuites", SUITE, "-groups", groups, "-alpn", alpn,
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


class SClientH2:
    """A TLS connection with the client's exact offer and ALPN h2, through
    ``openssl s_client`` (for its KeyUpdate), as a ``cu_h2`` transport.

    s_client reads stdin in chunks of 8 kB and takes a chunk that starts with
    a command letter (``k`` = KeyUpdate, ``Q`` = quit) as a command. So every
    write here is at most one chunk and starts with a frame header (a zero
    byte) or the preface, the writes are spaced, and the checks keep letters
    out of the bulk of a large body.
    """

    def __init__(self) -> None:
        exe = find_openssl()
        if not exe:
            raise Inconclusive("no OpenSSL >= 1.1.1 found (set CU_OPENSSL); LibreSSL cannot pin TLS 1.3 suites")
        self.p = subprocess.Popen(
            [exe, "s_client", "-connect", f"{HOST}:443", "-servername", HOST, "-tls1_3", "-ciphersuites", SUITE,
             "-groups", "P-256", "-alpn", "h2", "-verify_return_error", "-brief"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.out, self.err, self.eof = bytearray(), b"", False
        self.cv = threading.Condition()
        threading.Thread(target=self._rd_out, daemon=True).start()
        threading.Thread(target=self._rd_err, daemon=True).start()
        t0 = time.time()
        while b"CONNECTION ESTABLISHED" not in self.err and self.p.poll() is None and time.time() - t0 < 20:
            time.sleep(0.05)
        time.sleep(0.2)  # the rest of the brief summary
        if b"CONNECTION ESTABLISHED" not in self.err:
            err = self.err.decode("latin1").strip()
            self.close()
            raise TransportError(f"no TLS connection: {snip(err[-80:])}")

    def _rd_out(self) -> None:
        for c in iter(lambda: self.p.stdout.read1(65536), b""):
            with self.cv:
                self.out += c
                self.cv.notify_all()
        with self.cv:
            self.eof = True
            self.cv.notify_all()

    def _rd_err(self) -> None:
        for c in iter(lambda: self.p.stderr.read1(65536), b""):
            self.err += c

    def now(self) -> float:
        return time.monotonic()

    def settle(self) -> None:
        time.sleep(0.3)

    def _write(self, data: bytes) -> None:
        try:
            self.p.stdin.write(data)
            self.p.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise h2.TransportClosed(f"s_client is gone ({type(exc).__name__})") from exc

    def send(self, data: bytes) -> None:
        assert len(data) <= 8192 and data[:1] in (b"\x00", b"P")
        self._write(data)
        time.sleep(0.004)

    def key_update(self) -> None:
        time.sleep(0.4)
        self._write(b"k\n")
        time.sleep(0.4)

    def recv(self, timeout: float) -> bytes:
        with self.cv:
            if not self.out and not self.eof and timeout > 0:
                self.cv.wait(timeout)
            if self.out:
                data = bytes(self.out)
                self.out.clear()
                return data
            if self.eof:
                raise h2.TransportClosed("the provider closed the connection")
            return b""

    def info(self) -> dict:
        err = self.err.decode("latin1")
        f = _handshake_fields(err)
        return {"protocol": f["protocol"], "cipher": f["cipher"], "key_updates": err.count("KEYUPDATE")}

    def close(self) -> None:
        try:
            self.p.kill()
            self.p.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass


TRANSPORT: dict[str, Callable] = {"http": _http_real, "partial": _partial_real, "s_client": _s_client_real, "h2": SClientH2}


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


# Output caps some providers recognize besides the ones the offer pins. A raw
# client may put any of them in the private part of the body, where the suffix
# cannot replace it (it pins only the offer's own cap keys).
CAP_ALIASES = ("max_tokens", "max_completion_tokens", "max_output_tokens")
A14_PINNED_CAP = 8
A14_ALIAS_CAP = 400


def _client_refused(r: Resp) -> bool:
    """A client-error refusal of the request itself (not auth, payment, rate)."""
    return 400 <= r.status < 500 and r.status not in (401, 402, 403, 404, 429)


def a14_cap_alias_in_private_part() -> None:
    aliases = [k for k in CAP_ALIASES if k not in _CHAT["cap_keys"]]
    count = '"messages":[{"role":"user","content":"Count from 1 to 300, one number per line."}]'
    suffix = "," + ",".join([f'"model":"{CHEAP}"'] + [f'"{k}":{A14_PINNED_CAP}' for k in _CHAT["cap_keys"]]) + "," + STREAM + "}"
    ok_c, ev_c = control("{" + count + suffix, CHEAP, "A14 control")
    parts, all_ok = [], ok_c
    for alias in aliases:
        r = request("{" + count + f',"{alias}":{A14_ALIAS_CAP}' + suffix, f"A14 {alias}")
        ct = (usage_of(r.text).get("usage") or {}).get("completion_tokens")
        if _client_refused(r):
            ok, what = True, f"refused {r.status} {snip(r.text, 50)}"
        elif stream_ok(r, CHEAP) and isinstance(ct, int):
            ok, what = ct <= A14_PINNED_CAP + OUTPUT_MARGIN, f"{r.status}, completion_tokens={ct}"
        else:
            ok, what = False, f"{r.status} {snip(r.text, 50)}"
        all_ok = all_ok and ok
        parts.append(f"{alias}:{A14_ALIAS_CAP} -> {what}")
    check(
        "A14 a recognized cap alias in the private part does not lift the pinned cap",
        all_ok,
        f"{ev_c}; pinned {'/'.join(_CHAT['cap_keys'])}={A14_PINNED_CAP} (margin {OUTPUT_MARGIN}); "
        + ("; ".join(parts) if parts else "no other cap key to try"),
    )


def a7_usage_event() -> None:
    r = request(BASE, "A7")
    evs = events(r.text)
    last = evs[-1] if evs else {}
    tail_ok = r.text.rstrip().endswith("data: [DONE]")
    usage = last.get("usage") or {}
    check(
        "A7 last event carries usage + model (choices without content, §5.4), then [DONE]",
        r.status == 200
        and last.get("model") == CHEAP
        and bool(usage)
        and h2.usage_event_problem(last) is None
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


def _is_p256(text: str, f: dict) -> bool:
    return "prime256v1" in text or "P-256" in text or f["group"] in ("P-256", "prime256v1")


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
            check("A9 TLS 1.3 / AES-128-GCM only / P-256 only / ALPN http/1.1", False,
                  f"handshake refused: {snip(sc.err.strip().splitlines()[-1] if sc.err.strip() else '', 80)}")
            return
        last = f"rc={sc.rc} {snip(sc.err.strip()[-80:])}"
    else:
        raise Inconclusive(f"A9: no handshake after {RETRIES + 1} attempts (last: {last})")
    p256 = _is_p256(sc.out, f)
    ok = f["protocol"] == "TLSv1.3" and f["cipher"] == SUITE and f["alpn"] == "http/1.1" and f["verify"] == "0" and p256
    check(
        "A9 TLS 1.3 / AES-128-GCM only / P-256 only / ALPN http/1.1",
        ok,
        f"offered only {SUITE}+P-256+http/1.1 -> {f['protocol']} {f['cipher']} group={f['group']} p256={p256} "
        f"alpn={f['alpn']} verify={f['verify']}",
    )


def a11_keyupdate_mid_request() -> None:
    body = BASE.encode()
    # The KeyUpdate sits where the node's does in framing "1.1": after the
    # request head, before the body. (The body must not start with an
    # s_client command letter.)
    assert body[:1] not in (b"k", b"K", b"Q", b"R", b"C")
    steps = [head(len(body)), 0.5, b"k\n", 0.5, body]
    last = ""
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        sc = TRANSPORT["s_client"](True, steps, True, 45.0)
        f = _handshake_fields(sc.err)
        if "HTTP/1." not in sc.out and sc.rc not in (0, None) and _HS_FAIL.search(sc.err):
            check("A11 client KeyUpdate between head and body; complete answer; server closes", False,
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
        "A11 client KeyUpdate between head and body; complete answer; server closes",
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


def _png(w: int = 64, h: int = 64) -> bytes:
    """A small RGB gradient PNG (Venice refuses images under 64x64)."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    rows = b"".join(b"\0" + bytes(c for x in range(w) for c in (x * 255 // w, y * 255 // h, 128)) for y in range(h))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


# The usage members the node prices (routstr-core confidential.py
# frozen_cost_msats; the top-level cache_* members repeat prompt_tokens_details,
# as Venice reports them for Gemini); anything else in a vision answer could be
# a charge the settlement never sees.
BILLED_USAGE = {"prompt_tokens", "completion_tokens", "total_tokens", "prompt_tokens_details",
                "completion_tokens_details", "cache_creation_input_tokens", "cache_read_input_tokens"}
# A 256x256 image: a few dozen to a few hundred tokens depending on the
# model's patching (a 64x64 one was only 12 on mistral-small-3-2-24b-instruct).
IMAGE_SIDE = 256
IMAGE_MIN_TOKENS = 16


def a13_image_billed_as_prompt() -> None:
    text = '{"type":"text","text":"Describe."}'
    img = json.dumps({"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(_png(IMAGE_SIDE, IMAGE_SIDE)).decode()}})
    tail = f',"model":"{VISION}","max_tokens":4,' + STREAM + "}"
    rc = request('{"messages":[{"role":"user","content":[' + text + "]}]" + tail, "A13 control")
    ri = request('{"messages":[{"role":"user","content":[' + text + "," + img + "]}]" + tail, "A13")
    uc = usage_of(rc.text).get("usage") or {}
    ui = usage_of(ri.text).get("usage") or {}
    pc, pi = uc.get("prompt_tokens"), ui.get("prompt_tokens")
    extra = sorted(set(ui) - BILLED_USAGE)
    total_ok = "total_tokens" not in ui or ui.get("total_tokens") == (pi or 0) + (ui.get("completion_tokens") or 0)
    counted = isinstance(pc, int) and isinstance(pi, int) and pi - pc >= IMAGE_MIN_TOKENS
    check(
        f"A13 vision model ({VISION}) bills an image as prompt tokens",
        stream_ok(rc, VISION) and stream_ok(ri, VISION) and counted and not extra and total_ok,
        f"control -> {rc.status} prompt_tokens={pc}; with a {IMAGE_SIDE}x{IMAGE_SIDE} data URI -> {ri.status} prompt_tokens={pi}"
        + ("" if counted else f", image added fewer than {IMAGE_MIN_TOKENS} tokens")
        + (f", unpriced usage members {extra}" if extra else "")
        + ("" if total_ok else f", total_tokens={ui.get('total_tokens')} != prompt+completion"),
    )


CHECKS = [
    a9_transport,
    a11_keyupdate_mid_request,
    a1_waits_for_body,
    a2_last_wins,
    a3_object_replaced,
    a4_unknown_rejected,
    a5_malformed_rejected,
    a6_cap_includes_reasoning,
    a14_cap_alias_in_private_part,
    a7_usage_event,
    a12_sse_framing,
    a8_text_only_rejects_images,
    a13_image_billed_as_prompt,
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
# it starts, and speak the protocol's transport: TLS 1.3, the one suite, P-256
# only, and a KeyUpdate between the request head and the body (framing "1.1").
# Framing "2" image requests are covered by --h2 (H7 reads the image paths).
#   I1 last duplicate wins (count, model)        I6 paid extras and arrays pinned
#   I2 unknown keys rejected                     I7 waits for the full body
#   I3 unknown model refused, no fallback        I8 TLS 1.3 / suite / P-256 / ALPN
#   I4 no head reflection (success and error)    I9 KeyUpdate after the head
#   I5 an open string cannot swallow the suffix  I10 aliases in the private part
#                                                    (the other count key, an explicit
#                                                    size, the other format key) lose
#                                                    to the pins or are refused
# ---------------------------------------------------------------------------

IMAGE_PATH = os.environ.get("CU_IMAGE_PATH") or _route(_IMAGES.get("head_template", "")) or "/api/v1/image/generate"
IMAGE_MODEL = _flag("--image-model") or os.environ.get("CU_IMAGE_MODEL", "z-image-turbo")
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
    # The client offers only P-256 (the joint key share), with the one suite.
    sc = TRANSPORT["s_client"](False, [], False, 30.0, "P-256")
    f = _handshake_fields(sc.out)
    if not (f["protocol"] and f["cipher"]) and not (sc.rc not in (0, None) and _HS_FAIL.search(sc.err)):
        raise Inconclusive(f"I8: no handshake (rc={sc.rc} {snip(sc.err.strip()[-60:])})")
    p256 = _is_p256(sc.out, f)
    check("I8 TLS 1.3 / AES-128-GCM / P-256 only / ALPN http/1.1 (free)",
          f["protocol"] == "TLSv1.3" and f["cipher"] == SUITE and f["alpn"] == "http/1.1" and f["verify"] == "0" and p256,
          f"offered only {SUITE}+P-256+http/1.1 -> {f['protocol']} {f['cipher']} group={f['group']} p256={p256} "
          f"alpn={f['alpn']} verify={f['verify']}")


def i9_image_keyupdate_mid_body() -> None:
    body = f'{{"prompt":"a small green leaf","model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}'.encode()
    assert body[:1] not in (b"k", b"K", b"Q", b"R", b"C")
    steps = [head(len(body), IMAGE_PATH), 0.5, b"k\n", 0.5, body]
    sc = TRANSPORT["s_client"](True, steps, True, 90.0, "P-256")
    if "HTTP/1." not in sc.out:
        raise Inconclusive(f"I9: no response (rc={sc.rc} {snip(sc.err.strip()[-60:])})")
    r = parse_http(sc.out.encode("latin1"))
    ku = "KEYUPDATE" in sc.err or "KEYUPDATE" in sc.out
    n = len(_image_json(r).get("images") or [])
    check("I9 image route: client KeyUpdate between head and body; image returned; server closes (paid)",
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


IMAGE_COUNT_KEY = _IMAGES.get("count_key") or ("variants" if "/image/generate" in IMAGE_PATH else "n")
IMAGE_SHAPE = _IMAGES.get("response_shape", "venice")
# Keys a provider may read for the same thing: the count, the size, the format.
COUNT_KEYS = ("variants", "n")
FORMAT_KEYS = ("format", "output_format")


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def _image_suffix(pins: list) -> str:
    """The suffix as the node renders it: model, count 1, the fixed pins, the variant pins."""
    parts = [f'"model":{_canon(IMAGE_MODEL)}', f'"{IMAGE_COUNT_KEY}":1']
    parts += [f"{_canon(k)}:{_canon(v)}" for k, v in _IMAGES.get("fixed_pins", [])]
    parts += [f"{_canon(k)}:{_canon(v)}" for k, v in pins]
    return "," + ",".join(parts) + "}"


def image_info(raw: bytes) -> tuple[str, int, int] | None:
    """Format and size of a PNG, JPEG or WebP image (None if unrecognized)."""
    import struct
    if raw[:8] == b"\x89PNG\r\n\x1a\n" and len(raw) >= 24:
        w, h = struct.unpack(">II", raw[16:24])
        return "png", w, h
    if raw[:2] == b"\xff\xd8":
        i = 2
        while i + 9 <= len(raw):
            if raw[i] != 0xFF:
                return None
            m, n = raw[i + 1], struct.unpack(">H", raw[i + 2:i + 4])[0]
            if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                h, w = struct.unpack(">HH", raw[i + 5:i + 9])
                return "jpeg", w, h
            i += 2 + n
        return None
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP" and len(raw) >= 30:
        kind = raw[12:16]
        if kind == b"VP8X":
            return "webp", 1 + int.from_bytes(raw[24:27], "little"), 1 + int.from_bytes(raw[27:30], "little")
        if kind == b"VP8 ":
            w, h = struct.unpack("<HH", raw[26:30])
            return "webp", w & 0x3FFF, h & 0x3FFF
        if kind == b"VP8L" and len(raw) >= 25:
            b = int.from_bytes(raw[21:25], "little")
            return "webp", 1 + (b & 0x3FFF), 1 + ((b >> 14) & 0x3FFF)
    return None


def _images_of(r: Resp) -> list[bytes]:
    d = _image_json(r)
    items = d.get("images") if IMAGE_SHAPE == "venice" else [x.get("b64_json") for x in d.get("data") or [] if isinstance(x, dict)]
    out = []
    for b64 in items or []:
        try:
            out.append(base64.b64decode(b64 or ""))
        except (ValueError, TypeError):
            out.append(b"")
    return out


def _image_alias_plan() -> tuple[list, list]:
    """The variant pins this check uses and, per alias, (what, private-part JSON, judge).

    The pins take the first allowed value of the offer's size and format keys;
    each alias names the same thing under a key the suffix does not pin, with
    another value."""
    space = _IMAGES.get("param_space") or {}
    pins = []
    dim_key = next((k for k in ("resolution", "size") if k in space), None)
    if dim_key:
        pins.append((dim_key, space[dim_key][0]))
    fmt_key = next((k for k in FORMAT_KEYS if k in space), None)
    if fmt_key:
        pins.append((fmt_key, space[fmt_key][0]))
    other_count = next(k for k in COUNT_KEYS if k != IMAGE_COUNT_KEY)
    # An odd, non-square size that no pinned resolution produces.
    dims = '"size":"1536x640"' if "width" in space else '"width":1536,"height":640'
    pinned_fmt = fmt_key and space[fmt_key][0]
    alias_fmt_key = next(k for k in FORMAT_KEYS if k != (fmt_key or "format"))
    alias_fmt = "png" if pinned_fmt != "png" else "jpeg"
    aliases = [
        ("count", f'"{other_count}":4', lambda imgs, ctl: len(imgs) == 1),
        ("size", dims, lambda imgs, ctl: len(imgs) == 1 and ctl is not None and image_info(imgs[0]) is not None
         and image_info(imgs[0])[1:] == ctl[1:]),
        ("format", f'"{alias_fmt_key}":"{alias_fmt}"', lambda imgs, ctl: len(imgs) == 1 and ctl is not None
         and image_info(imgs[0]) is not None and image_info(imgs[0])[0] == ctl[0]),
    ]
    return pins, aliases


def i10_image_aliases_in_private_part() -> None:
    pins, aliases = _image_alias_plan()
    suffix = _image_suffix(pins)
    prompt = '{"prompt":"a small yellow star on a black background"'
    c = image_request(prompt + suffix, "I10 control")
    imgs = _images_of(c)
    ctl = image_info(imgs[0]) if len(imgs) == 1 else None
    if c.status != 200 or ctl is None:
        check("I10 image route: recognized aliases in the private part do not override the pins (paid)", False,
              f"control (pins {pins}) -> {c.status}, {len(imgs)} image(s), {ctl} {snip(c.text, 60)}")
        return
    parts, all_ok = [f"control (pins {dict(pins)}) -> {ctl[0]} {ctl[1]}x{ctl[2]}"], True
    for what, private, judge in aliases:
        r = image_request(prompt + "," + private + suffix, f"I10 {what}")
        if _client_refused(r):
            ok, ev = True, f"refused {r.status}"
        else:
            got = _images_of(r)
            info = [image_info(x) for x in got]
            ok, ev = r.status == 200 and judge(got, ctl), f"{r.status}, {len(got)} image(s) {info[:4]}"
        all_ok = all_ok and ok
        parts.append(f"{what} {{{private}}} -> {ev}")
    check("I10 image route: recognized aliases in the private part do not override the pins (paid)", all_ok, "; ".join(parts))


IMAGE_CHECKS = [i8_image_tls_p256, i2_image_unknown_rejected, i3_image_unknown_model, i5_image_malformed,
                i1_image_last_wins, i7_image_waits_for_body, i9_image_keyupdate_mid_body,
                i10_image_aliases_in_private_part]


# ---------------------------------------------------------------------------
# Framing "2" (--h2): PROTOCOL-V3.md section 5.6, H1-H8. Every connection is
# what a framing-"2" connection puts on the wire: the client's TLS offer with
# ALPN h2, the connection head of section 5.2 (the probe GET stores the
# credential at index 62 of the provider's request table), a TLS KeyUpdate,
# then requests whose header block names the credential by index only.
# ---------------------------------------------------------------------------

_H2 = OFFER.get("h2") or {}
H2_PROBE = _H2.get("probe_path", "")
H2_OFFER_IDLE = int(_H2.get("idle_secs", 300))
H2_IDLE = float(_flag("--h2-idle") or H2_OFFER_IDLE)
H2_BODY_BYTES = int(_flag("--h2-body-bytes") or 8 << 20)
H2_IMAGES = "images" in (_H2.get("kinds") or []) and bool(_IMAGES)
H2_NAMES = {
    "H1": "H1 TLS 1.3 with ALPN h2 (the one suite, P-256 only)",
    "H2": "H2 KeyUpdate right after the connection head is accepted",
    "H3": "H3 the request dynamic table is kept (credential entry fits; SETTINGS do not shrink it)",
    "H4": "H4 HEADER_TABLE_SIZE = 0 honoured for response headers",
    "H5": "H5 authorization by index only is authenticated, also after the idle time",
    "H6": "H6 a body of the node's limit passes flow control",
    "H7": "H7 no response reflects the credential",
    "H8": "H8 the usage event and [DONE] end the stream as the disclosure parses it",
}


# What a request without a credential gets (402: a provider that then asks for payment).
H2_UNAUTH = (401, 402, 403)


class ConnLost(Exception):
    """The provider ended the HTTP/2 connection."""


def h2_body(filler: int = 0, model: str | None = None, extra: str = "") -> str:
    """A small chat request; ``filler`` bytes of JSON whitespace make it large
    without prompt tokens (and without s_client command letters)."""
    return "{" + MSG + "," + " " * filler + extra + f'"model":"{model or CHEAP}","max_tokens":4,' + STREAM + "}"


def h2_open(reset_probe: bool = True, key_update: bool = True) -> h2.H2Client:
    """A connection up to where the first request may go."""
    c = h2.H2Client(TRANSPORT["h2"](), HOST, KEY)
    c.open(H2_PROBE, reset_probe)
    if key_update:
        c.key_update()
    # The provider's SETTINGS and its answer to ours; then what it still has
    # to say about the probe (section 5.4: C waits for it, or 2 s).
    c.pump(lambda: bool(c.peer_settings) and c.settings_acked, 10.0)
    c.pump(lambda: c.streams[1].ended, 2.0)
    if c.closed or c.goaway:
        raise ConnLost(f"the provider closed the connection after the head{_goaway(c)}")
    if not c.peer_settings:
        raise TransportError("no SETTINGS from the provider in 10 s")
    return c


def _goaway(c: h2.H2Client) -> str:
    return f" (GOAWAY error {c.goaway[0]} {snip(c.goaway[1].decode('latin1'), 40)})" if c.goaway else ""


def h2_request(c: h2.H2Client, path: str, body: str, label: str, by_index: bool = True, timeout: float = 120.0) -> h2.StreamResp:
    """One request; transient outcomes are retried on the same connection."""
    last = ""
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        try:
            r = c.request(path, body.encode(), by_index, timeout)
        except h2.TransportClosed as exc:
            raise ConnLost(f"{label}: {exc}{_goaway(c)}") from exc
        H2_SEEN.append((label, r))
        if not r.ended and r.reset is None:
            if c.closed or c.goaway:
                raise ConnLost(f"{label}: the provider closed the connection{_goaway(c)}")
            last = f"no answer in {timeout:.0f} s"
            continue
        if r.reset is not None and not r.headers:
            last = f"RST_STREAM {r.reset}"
            continue
        if r.status and transient(r.status):
            last = f"HTTP {r.status} {snip(r.text, 60)}"
            continue
        return r
    raise Inconclusive(f"{label}: still transient after {RETRIES + 1} attempts (last: {last})")


H2_SEEN: list[tuple[str, "h2.StreamResp"]] = []


def h2_stream_ok(r: h2.StreamResp, model: str) -> bool:
    u = usage_of(r.text)
    return r.status == 200 and r.ended and u.get("model") == model and bool(u.get("usage"))


def _key_forms() -> list[bytes]:
    k = KEY.encode()
    return [k, base64.b64encode(k), base64.b64encode(b"Bearer " + k)]


def h2_reflection(r: h2.StreamResp) -> str | None:
    """Where a response carries the credential, or None."""
    for part, data in (
        ("headers", "\n".join(f"{n}: {v}" for n, v in r.headers).encode("latin1", "replace")),
        ("trailers", "\n".join(f"{n}: {v}" for n, v in r.trailers).encode("latin1", "replace")),
        ("body", r.body),
    ):
        if KEY and any(k in data for k in _key_forms()):
            return part
    return None


def run_h2() -> int:
    """H1-H8. Returns the exit status and prints the verdict line."""
    RESULTS.clear()
    H2_SEEN.clear()
    res: dict[str, tuple[str, str]] = {}
    entry = h2.credential_entry_size(len(KEY))

    def put(item: str, verdict: str, evidence: str) -> None:
        if item not in res:
            res[item] = (verdict, redact(evidence))
            if not QUIET:
                print(f"{verdict:12s} {H2_NAMES[item]}: {res[item][1]}", flush=True)

    def guarded(items: list[str], fn: Callable) -> None:
        """Run a phase; what it leaves open is inconclusive (or failed, when
        the provider ended the connection)."""
        try:
            fn()
        except Inconclusive as exc:
            for it in items:
                put(it, "INCONCLUSIVE", str(exc))
        except TransportError as exc:
            for it in items:
                put(it, "INCONCLUSIVE", f"transport: {exc}")
        except ConnLost as exc:
            for it in items:
                put(it, "FAIL", str(exc))
        except (h2.H2Error, h2.FlowStall) as exc:
            for it in items:
                put(it, "FAIL", f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            for it in items:
                put(it, "FAIL", f"error: {type(exc).__name__}: {exc}")

    conns: list[h2.H2Client] = []
    state: dict = {}

    # ---- H1: the handshake, for the client's exact offer.
    def p_h1() -> None:
        last = ""
        for attempt in range(RETRIES + 1):
            if attempt:
                time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
            sc = TRANSPORT["s_client"](False, [], False, 30.0, "P-256", "h2")
            f = _handshake_fields(sc.out)
            if f["protocol"] and f["cipher"]:
                p256 = _is_p256(sc.out, f)
                ok = f["protocol"] == "TLSv1.3" and f["cipher"] == SUITE and f["alpn"] == "h2" and f["verify"] == "0" and p256
                put("H1", "PASS" if ok else "FAIL",
                    f"offered only {SUITE}+P-256+h2 -> {f['protocol']} {f['cipher']} p256={p256} alpn={f['alpn']} verify={f['verify']}")
                return
            if sc.rc not in (0, None) and _HS_FAIL.search(sc.err):
                put("H1", "FAIL", f"handshake refused: {snip(sc.err.strip().splitlines()[-1] if sc.err.strip() else '', 80)}")
                return
            last = f"rc={sc.rc} {snip(sc.err.strip()[-80:])}"
        raise Inconclusive(f"H1: no handshake after {RETRIES + 1} attempts (last: {last})")

    guarded(["H1"], p_h1)
    if res.get("H1", ("", ""))[0] == "FAIL":
        for it in ("H2", "H3", "H4", "H5", "H6", "H7", "H8"):
            put(it, "FAIL", "not checked: no HTTP/2 connection (H1)")
        return _h2_verdict(res)

    # ---- The probe, left open: is the key accepted, and what does it answer?
    def p_probe() -> None:
        c = h2_open(reset_probe=False, key_update=False)
        conns.append(c)
        c.pump(lambda: c.streams[1].ended or c.streams[1].reset is not None, 30.0)
        r = c.streams[1]
        H2_SEEN.append(("probe GET", r))
        state["probe"] = r
        if transient(r.status) or not r.ended:
            raise Inconclusive(f"probe GET {H2_PROBE}: {r.status or 'no answer'}")
        # Control for H2: the same connection without a KeyUpdate answers a request.
        state["control"] = h2_request(c, PATH, h2_body(), "control (no KeyUpdate)")

    guarded([], p_probe)  # what it leaves open, connection A settles
    probe = state.get("probe")
    ctl = state.get("control")
    if probe is not None and probe.status in H2_UNAUTH:
        for it in ("H2", "H3", "H5", "H6", "H8"):
            put(it, "FAIL", f"the key is refused: probe GET {H2_PROBE} with the literal credential -> {probe.status}")
    elif ctl is not None and 400 <= ctl.status < 500 and ctl.status not in H2_UNAUTH:
        # Not the provider's HTTP/2: the plain request itself is refused (the
        # model, the body). Nothing can be concluded from such a run.
        for it in ("H2", "H3", "H4", "H5", "H6", "H7", "H8"):
            put(it, "INCONCLUSIVE", f"the check's own chat request is refused: {ctl.status} {snip(ctl.text, 70)} (name a chat model of this provider with --model)")
        for c in conns:
            c.tr.close()
        return _h2_verdict(res)

    # ---- Connection A: head, KeyUpdate, requests by index; later the idle time.
    def p_main() -> None:
        try:
            a = h2_open()
        except ConnLost as exc:
            if ctl is not None and h2_stream_ok(ctl, CHEAP):
                put("H2", "FAIL", f"{exc}; control without KeyUpdate -> {ctl.status}")
            raise
        conns.append(a)
        state["a"] = a
        try:
            r1 = h2_request(a, PATH, h2_body(), "chat by index")
        except ConnLost as exc:
            if ctl is not None and h2_stream_ok(ctl, CHEAP):
                put("H2", "FAIL", f"{exc}; control without KeyUpdate -> {ctl.status}")
            raise
        state["r1"] = r1
        ku = a.tr.info()["key_updates"]
        ok1 = h2_stream_ok(r1, CHEAP)
        ctl_ok = ctl is not None and h2_stream_ok(ctl, CHEAP)
        if ok1 and ku >= 1:
            put("H2", "PASS", f"head, KeyUpdate (sent={ku}), then a request -> {r1.status}, complete stream; control without KeyUpdate -> {ctl.status if ctl else '?'}")
        elif ku < 1:
            put("H2", "INCONCLUSIVE", "s_client did not send the KeyUpdate")
        elif not ctl_ok:
            put("H2", "INCONCLUSIVE" if ctl is None or transient(ctl.status) else "FAIL",
                f"request after the KeyUpdate -> {r1.status} {snip(r1.text, 50)}; the control without KeyUpdate fails too ({ctl.status if ctl else 'none'})")
        else:
            put("H2", "FAIL", f"request after the KeyUpdate -> {r1.status} {snip(r1.text, 50)}; control without KeyUpdate -> {ctl.status}")
        # H3: the table size the provider announced, and the index worked.
        hts = a.header_table_size
        sizes = [s[h2.S_HEADER_TABLE_SIZE] for c in conns for s in c.peer_settings if h2.S_HEADER_TABLE_SIZE in s]
        # Below the default the decoder expects a table size update the pinned
        # request block cannot carry (RFC 7541 §4.2; the sidecar refuses it).
        size_ok = all(v >= max(entry, 4096) for v in sizes)
        put("H3", "PASS" if size_ok and r1.status == 200 else "FAIL",
            f"SETTINGS HEADER_TABLE_SIZE={'default 4096' if hts is None else hts} (needs >= 4096; credential entry {entry} bytes, "
            f"{len(a.peer_settings)} SETTINGS frame(s)); request naming index 62 -> {r1.status}")
        # H5, first half and its control.
        r_no = h2_request(a, PATH, h2_body(), "chat without authorization", by_index=False)
        state["noauth"] = r_no
        # Error paths (H7, and more header blocks for H4).
        state["e_model"] = h2_request(a, PATH, h2_body(model="no-such-model-xyz"), "chat, unknown model")
        state["e_field"] = h2_request(a, PATH, h2_body(extra='"bogus_field_xyz":1,'), "chat, unknown field")
        state["idle_from"] = a.tr.now()

    guarded(["H2", "H3", "H5"], p_main)
    a = state.get("a")

    # The idle time runs on connection A (answering PINGs) while the others work.
    idler = None
    if a is not None and "idle_from" in state:
        idler = threading.Thread(target=lambda: a.idle(H2_IDLE), daemon=True)
        idler.start()

    # ---- H6: one large body on a connection of its own.
    def p_big() -> None:
        b = h2_open()
        conns.append(b)
        body = h2_body(filler=max(0, H2_BODY_BYTES - len(h2_body())))
        try:
            r = h2_request(b, PATH, body, f"chat, {len(body)} byte body", timeout=300.0)
        except h2.FlowStall as exc:
            put("H6", "FAIL", f"{exc}; provider window {b.peer_initial_window}, {b.window_updates} WINDOW_UPDATE frames")
            return
        ok = h2_stream_ok(r, CHEAP)
        put("H6", "PASS" if ok else "FAIL",
            f"{len(body)} byte body in {-(-len(body) // h2.DATA_CHUNK)} DATA frames, provider window {b.peer_initial_window}, "
            f"{b.window_updates} WINDOW_UPDATE frames -> {r.status}{'' if ok else ' ' + snip(r.text, 60)}"
            + ("" if ok or r.status != 413 else f" (the provider refuses a body this large: run the sidecar with a smaller --max-body and check that size with --h2-body-bytes)"))

    guarded(["H6"], p_big)

    # ---- The image paths of H7 (item 8 / I4): error (free), success (paid).
    def p_images() -> None:
        c = h2_open()
        conns.append(c)
        state["i_err"] = h2_request(c, IMAGE_PATH, f'{{"prompt":"x","bogus_field_xyz":1,"model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}', "image, unknown field")
        state["i_ok"] = h2_request(c, IMAGE_PATH, f'{{"prompt":"a red dot","model":"{IMAGE_MODEL}","variants":1,{IMAGE_PINS}}}', "image", timeout=180.0)

    if H2_IMAGES and not NO_H2_IMAGES:
        guarded(["H7"], p_images)

    # ---- H5, second half: the same connection after the idle time.
    def p_idle() -> None:
        if idler is None:
            return
        idler.join()
        idle_s = a.tr.now() - state["idle_from"]
        r1, r_no = state["r1"], state["noauth"]
        if a.closed or a.goaway:
            put("H5", "FAIL", f"indexed -> {r1.status}; the provider closed the idle connection within {idle_s:.0f} s{_goaway(a)}")
            return
        r2 = h2_request(a, PATH, h2_body(), f"chat by index after {idle_s:.0f} s idle")
        state["r2"] = r2
        ok = r1.status == 200 and r2.status == 200 and h2_stream_ok(r2, CHEAP) and r_no.status in H2_UNAUTH
        ev = (f"indexed -> {r1.status}; no authorization field -> {r_no.status} (control); idle {idle_s:.0f} s "
              f"({a.pings} PING answered), then indexed -> {r2.status}")
        if ok and H2_IDLE < H2_OFFER_IDLE:
            put("H5", "INCONCLUSIVE", ev + f"; but the offer's h2.idle_secs is {H2_OFFER_IDLE}: run with --h2-idle {H2_OFFER_IDLE} or lower h2.idle_secs to {H2_IDLE:.0f}")
        else:
            put("H5", "PASS" if ok else "FAIL", ev + ("" if r_no.status in H2_UNAUTH else "; the control was not refused, so the index proves nothing"))

    guarded(["H5"], p_idle)

    # ---- H4: every response header block, with an empty dynamic table.
    blocks = sum(c.blocks for c in conns)
    errs = [c.hpack_error for c in conns if c.hpack_error]
    updates = sorted({u for c in conns for u in c.dec.size_updates})
    ok200 = sum(1 for _, r in H2_SEEN if r.status == 200)
    if errs:
        put("H4", "FAIL", f"{errs[0]} ({blocks} header blocks)")
    elif blocks >= 4 and ok200 >= 2:
        put("H4", "PASS", f"{blocks} response header blocks on {len(conns)} connections decode with an empty dynamic table"
            + (f"; table size updates: {updates}" if updates else "; no table size update") )
    else:
        put("H4", "INCONCLUSIVE", f"only {blocks} response header blocks and {ok200} answered requests seen")

    # ---- H7: every response read.
    want = ["probe GET", "chat by index", "chat without authorization", "chat, unknown model", "chat, unknown field"]
    if H2_IMAGES and not NO_H2_IMAGES:
        want += ["image, unknown field", "image"]
    seen = {}
    for label, r in H2_SEEN:
        if r.headers or r.body:
            seen.setdefault(label.split(" after ")[0] if label.startswith("chat by index") else label, []).append(r)
    leaks = [f"{label} ({r.status}): {h2_reflection(r)}" for label, rs in seen.items() for r in rs if h2_reflection(r)]
    missing = [w for w in want if w not in seen]
    classes = {
        "chat by index": lambda r: r.status == 200, "probe GET": lambda r: r.status == 200,
        "chat without authorization": lambda r: 400 <= r.status < 500, "chat, unknown model": lambda r: 400 <= r.status < 500,
        "chat, unknown field": lambda r: 400 <= r.status < 500, "image, unknown field": lambda r: 400 <= r.status < 500,
        "image": lambda r: r.status == 200,
    }
    off = [f"{w} -> {seen[w][-1].status}" for w in want if w in seen and not any(classes[w](r) for r in seen[w])]
    paths = "; ".join(f"{w} {seen[w][-1].status}" for w in want if w in seen)
    if leaks:
        put("H7", "FAIL", "the credential comes back in: " + "; ".join(leaks))
    elif missing or off:
        put("H7", "INCONCLUSIVE", f"not every response path was read (missing: {missing or '-'}; unexpected status: {off or '-'}); clean so far: {paths}")
    elif H2_IMAGES and NO_H2_IMAGES:
        put("H7", "INCONCLUSIVE", f"the image paths were skipped (--h2-no-images) though the offer serves images over HTTP/2; clean: {paths}")
    else:
        put("H7", "PASS", f"headers, trailers and bodies carry no credential: {paths}")

    # ---- H8: the tail of every 200 stream.
    tails = [(label, r) for label, r in H2_SEEN if r.status == 200 and label.startswith("chat")]
    probs = [f"{label}: {h2.tail_problem(r)}" for label, r in tails if h2.tail_problem(r)]
    if probs:
        put("H8", "FAIL", probs[0])
    elif len(tails) >= 2:
        r = tails[0][1]
        tail = r.body[r.body.rfind(b"\ndata: ", 0, len(r.body) - 16) + 1 :]
        put("H8", "PASS", f"{len(tails)} streams end in the usage event and [DONE] ({len(tail)} byte tail, LF only), END_STREAM "
            + ("on trailers" if r.trailers else "on the last DATA frame"))
    else:
        put("H8", "INCONCLUSIVE", f"only {len(tails)} complete 200 stream(s) seen")

    for c in conns:
        c.tr.close()
    return _h2_verdict(res)


QUIET = False
NO_H2_IMAGES = "--h2-no-images" in sys.argv[1:]


def _h2_verdict(res: dict) -> int:
    for item in H2_NAMES:
        v, ev = res.get(item, ("INCONCLUSIVE", "not reached"))
        RESULTS.append((H2_NAMES[item], v, ev))
    fails = [n.split()[0] for n, v, _ in RESULTS if v == "FAIL"]
    inc = [n.split()[0] for n, v, _ in RESULTS if v == "INCONCLUSIVE"]
    if not QUIET:
        print(f"summary: {len(RESULTS) - len(fails) - len(inc)} PASS, {len(fails)} FAIL, {len(inc)} INCONCLUSIVE of {len(RESULTS)}")
        why = lambda items: "; ".join(f"{n.split()[0]}: {ev}" for n, v, ev in RESULTS if n.split()[0] in items)  # noqa: E731
        if fails:
            print(f'offer "2": no, because {why(fails)}')
            print(f'  keep "http": ["1.1"] in the offer file for {HOST}.')
        elif inc:
            print(f'offer "2": not yet, because the check is incomplete ({why(inc)})')
            print('  run it again; add "2" only after a run in which H1-H8 all pass.')
        else:
            print(f'offer "2": yes. {HOST} does what framing "2" needs (H1-H8).')
            print(f'  "http": ["2", "1.1"] with "h2": {{"probe_path": {json.dumps(H2_PROBE)}, "idle_secs": at most {H2_IDLE:.0f}}}; '
                  f"the sidecar's --max-body at most {H2_BODY_BYTES}.")
    return 1 if fails else (2 if inc else 0)


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
    MODELS = {CHEAP, REASONING, TEXT_ONLY, VISION}

    def __init__(self, status: int | None = None, lenient: bool = False, cipher: str = SUITE,
                 hs_refuse: bool = False, timeout: bool = False, early: bool = False,
                 no_close: bool = False, no_ku: bool = False, crlf: bool = False,
                 pretty: bool = False, image_free: bool = False, image_fee: bool = False,
                 h2_alpn: bool = True, open_auth: bool = False, reflect_body: bool = False, h2: dict | None = None,
                 alias_cap: bool = False, image_alias: bool = False, image_lenient: bool = False) -> None:
        self.h2_alpn, self.open_auth, self.reflect_body, self.h2_faults = h2_alpn, open_auth, reflect_body, h2 or {}
        # alias_cap: max_output_tokens accepted and obeyed over the pinned caps;
        # image_alias: the other count key, width/height and output_format
        # accepted and obeyed over the pins; image_lenient: accepted, ignored.
        self.alias_cap, self.image_alias, self.image_lenient = alias_cap, image_alias, image_lenient
        self.status, self.lenient, self.cipher = status, lenient, cipher
        self.hs_refuse, self.timeout, self.early = hs_refuse, timeout, early
        self.no_close, self.no_ku = no_close, no_ku
        self.crlf, self.pretty = crlf, pretty
        self.image_free, self.image_fee = image_free, image_fee

    def _answer(self, body: str) -> Resp:
        if self.timeout:
            raise TransportError("timeout")
        if self.status is not None:
            return Resp(self.status, '{"error":"mock"}')
        try:
            d = json.loads(body)  # duplicate keys: last wins, objects replaced
        except json.JSONDecodeError:
            return Resp(400, '{"error":"Invalid JSON request"}')
        extra = set(d) - self.ALLOWED - ({"max_output_tokens"} if self.alias_cap else set())
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
        if self.alias_cap and "max_output_tokens" in d:
            ct = d["max_output_tokens"]
        u = {"model": d["model"], "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": ct}}
        if isinstance(content, list) and any(p.get("type") == "image_url" for p in content):
            u["usage"]["prompt_tokens"] += 0 if self.image_free else 80
            if self.image_fee:
                u["usage"]["image_cost"] = 0.001
        usage = json.dumps(u, indent=1) if self.pretty else json.dumps(u, separators=(",", ":"))
        text = 'data: {"model":"%s","choices":[{"delta":{"content":"hi"}}]}\n\ndata: %s\n\ndata: [DONE]\n\n' % (d["model"], usage)
        if self.crlf:
            text = text.replace("\n", "\r\n")
        return Resp(200, text, {"x-venice-version": "mock"})

    IMAGE_ALLOWED = {"prompt", "model", "variants", "return_binary", "enhance_prompt", "enable_web_search",
                     "style_references", "resolution", "quality", "format"}

    @staticmethod
    def _fake_image(fmt: str, w: int, h: int) -> bytes:
        """The header of an image of that format and size (all ``image_info`` reads)."""
        if fmt == "png":
            return b"\x89PNG\r\n\x1a\n" + b"\0\0\0\x0dIHDR" + w.to_bytes(4, "big") + h.to_bytes(4, "big") + b"\x08\x02\0\0\0"
        if fmt == "jpeg":
            return b"\xff\xd8\xff\xc0\x00\x11\x08" + h.to_bytes(2, "big") + w.to_bytes(2, "big") + b"\x03" + b"\0" * 9
        return b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0" + (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little")

    def _image(self, body: str) -> Resp:
        if self.timeout:
            raise TransportError("timeout")
        if self.status is not None:
            return Resp(self.status, '{"error":"mock"}')
        try:
            d = json.loads(body)
        except json.JSONDecodeError:
            return Resp(400, '{"error":"Invalid JSON request"}')
        extra = set(d) - self.IMAGE_ALLOWED - {IMAGE_COUNT_KEY}
        if extra and not (self.image_alias or self.image_lenient):
            return Resp(400, '{"error":"Unrecognized key(s) in object: ' + ", ".join(f"'{k}'" for k in sorted(extra)) + '"}')
        count = d.get(IMAGE_COUNT_KEY, 1)
        side = {"1K": 1024, "2K": 2048, "4K": 4096}.get(d.get("resolution"), 1024)
        w, h, fmt = side, side, d.get("format", "webp")
        if self.image_alias:
            count = next((d[k] for k in COUNT_KEYS if k != IMAGE_COUNT_KEY and k in d), count)
            w, h = d.get("width", w), d.get("height", h)
            fmt = d.get("output_format", fmt)
        imgs = [base64.b64encode(self._fake_image(fmt, w, h)).decode() for _ in range(count)]
        out = {"images": imgs} if IMAGE_SHAPE == "venice" else {"data": [{"b64_json": x} for x in imgs]}
        return Resp(200, json.dumps(out), {"content-type": "application/json"})

    def http(self, body: str, path: str = "") -> Resp:
        if path and path == IMAGE_PATH:
            return self._image(body)
        return self._answer(body)

    def h2_app(self, path: str, body: str, authorized: bool) -> tuple[int, str, str]:
        """One request on a mock HTTP/2 connection."""
        if self.status is not None:
            return self.status, "application/json", '{"error":"mock"}'
        if not authorized and not self.open_auth:
            return 401, "application/json", '{"error":"Authentication failed"}'
        if path == H2_PROBE:
            return 200, "application/json", '{"data":[]}'
        if path == IMAGE_PATH:
            try:
                d = json.loads(body)
            except json.JSONDecodeError:
                return 400, "application/json", '{"error":"Invalid JSON request"}'
            if "bogus_field_xyz" in d:
                note = f" (request by Bearer {KEY})" if self.reflect_body else ""
                return 400, "application/json", json.dumps({"error": "Unrecognized key(s) in object: 'bogus_field_xyz'" + note})
            return 200, "application/json", '{"images":["AAAA"],"request":{"data":{"model":"m","variants":1}}}'
        r = self._answer(body)
        return r.status, ("text/event-stream" if r.status == 200 else "application/json"), r.text

    def h2(self):
        if self.timeout:
            raise TransportError("timeout")
        return h2.MockH2(KEY, self.h2_app, **self.h2_faults)

    def partial(self, body: str, hold_s: float, cut: int, path: str = "") -> tuple[bytes, Resp]:
        r = self._answer(body)
        return (b"HTTP/1.1 400" if self.early else b""), r

    def s_client(self, brief: bool, steps: list, keep_open: bool, timeout_s: float, groups: str = "P-256", alpn: str = "http/1.1") -> SClient:
        if self.timeout:
            return SClient(None, "", "connect: Operation timed out", False)
        if self.hs_refuse:
            return SClient(1, "", "error:0A000410:SSL routines::ssl/tls alert handshake failure", False)
        if brief:
            err = f"CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: {self.cipher}\nPeer Temp Key: ECDH, prime256v1, 256 bits\n"
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
        got = alpn if alpn != "h2" or self.h2_alpn else None
        out = (f"New, TLSv1.3, Cipher is {self.cipher}\nPeer Temp Key: ECDH, prime256v1, 256 bits\nProtocol: TLSv1.3\n"
               + (f"ALPN protocol: {got}\n" if got else "No ALPN negotiated\n") + "Verify return code: 0 (ok)\n")
        return SClient(0, out, "", False)


def _self_test_argv() -> bool:
    """The argument check: every mode and option is known, anything else refused."""
    good = [[], ["--h2"], ["--images"], ["--self-test"], ["--h2", "--h2-idle", "30", "--h2-body-bytes", "1024", "--h2-no-images"],
            ["--offer", "f.json", "--key-env", "K", "--model", "m", "--image-model", "i"]]
    bad = [["--h3"], ["--h2", "--images"], ["--offer"], ["--offer", "--h2"], ["--h2-idle", "30"], ["--h2-no-images"],
           ["--model", "a", "--model", "b"], ["h2"], ["--self-test", "extra"]]
    ok = all(_argv_problem(a) is None for a in good) and all(_argv_problem(a) for a in bad)
    print(f"  {'PASS' if ok else 'FAIL'}  unknown or conflicting arguments are refused, the known ones accepted")
    return ok


def self_test() -> int:
    global RETRIES, BACKOFF, KEY
    if not _self_test_argv():
        return 1
    RETRIES, BACKOFF = 1, [0.0]
    KEY = KEY or "sk-selftest-not-a-key"
    saved = dict(TRANSPORT)
    # (name, provider, predicate over {check: verdict}, what it proves)
    def verdicts() -> dict:
        return {name.split()[0]: v for name, v, _ in RESULTS}

    rejection = ["A2", "A3", "A4", "A5", "A8", "A10", "A14"]
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
        ("image not counted in prompt_tokens fails A13", MockProvider(image_free=True),
         lambda v, rc: rc == 1 and v.get("A13") == "FAIL"),
        ("image billed outside the token counts fails A13", MockProvider(image_fee=True),
         lambda v, rc: rc == 1 and v.get("A13") == "FAIL"),
        ("a cap alias (max_output_tokens) obeyed over the pinned cap fails A14", MockProvider(alias_cap=True),
         lambda v, rc: rc == 1 and v.get("A14") == "FAIL" and v.get("A4") == "PASS"),
    ]
    # The image route (--images): I10 alone, offline; the other image checks
    # read the provider's own echo and run live only.
    image_scenarios = [
        ("images: aliases refused passes I10", MockProvider(),
         lambda v, rc: rc == 0 and v.get("I10") == "PASS"),
        ("images: aliases accepted and ignored passes I10", MockProvider(image_lenient=True),
         lambda v, rc: rc == 0 and v.get("I10") == "PASS"),
        ("images: aliases obeyed over the pins fail I10", MockProvider(image_alias=True),
         lambda v, rc: rc == 1 and v.get("I10") == "FAIL"),
        ("images: outage (503) is inconclusive", MockProvider(status=503),
         lambda v, rc: rc == 2 and v.get("I10") == "INCONCLUSIVE"),
        ("images: bad key (401) fails the control", MockProvider(status=401),
         lambda v, rc: rc == 1 and v.get("I10") == "FAIL"),
        ("images: timeouts are inconclusive", MockProvider(timeout=True),
         lambda v, rc: rc == 2 and v.get("I10") == "INCONCLUSIVE"),
    ]
    # Framing "2" (--h2): the same rules. A healthy provider passes H1-H8; each
    # fault fails its item; an outage or a timeout is never PASS.
    global QUIET, H2_IMAGES, H2_IDLE, H2_BODY_BYTES, H2_PROBE
    QUIET, H2_IMAGES, H2_BODY_BYTES, H2_PROBE = True, True, 300_000, H2_PROBE or "/v1/models"
    H2_IDLE = float(H2_OFFER_IDLE)
    hs = ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"]
    h2_scenarios = [
        ("h2: healthy provider passes H1-H8", MockProvider(),
         lambda v, rc: rc == 0 and all(v.get(k) == "PASS" for k in hs)),
        ("h2: ALPN h2 not selected fails H1, nothing passes", MockProvider(h2_alpn=False),
         lambda v, rc: rc == 1 and v.get("H1") == "FAIL" and not any(x == "PASS" for x in v.values())),
        ("h2: wrong cipher fails H1", MockProvider(cipher="TLS_CHACHA20_POLY1305_SHA256"),
         lambda v, rc: rc == 1 and v.get("H1") == "FAIL"),
        ("h2: connection closed on the KeyUpdate fails H2", MockProvider(h2={"close_on_ku": True}),
         lambda v, rc: rc == 1 and v.get("H2") == "FAIL" and v.get("H5") != "PASS"),
        ("h2: SETTINGS HEADER_TABLE_SIZE 0 fails H3", MockProvider(h2={"table_size": 0}),
         lambda v, rc: rc == 1 and v.get("H3") == "FAIL" and v.get("H5") != "PASS"),
        ("h2: a table too small for the credential fails H3", MockProvider(h2={"table_size": 40}),
         lambda v, rc: rc == 1 and v.get("H3") == "FAIL"),
        ("h2: a table below the default 4096 fails H3", MockProvider(h2={"table_size": 1024}),
         lambda v, rc: rc == 1 and v.get("H3") == "FAIL"),
        ("h2: response headers through the dynamic table fail H4", MockProvider(h2={"dynamic_responses": True}),
         lambda v, rc: rc == 1 and v.get("H4") == "FAIL"),
        ("h2: credential forgotten while idle fails H5", MockProvider(h2={"forget_after_idle": True}),
         lambda v, rc: rc == 1 and v.get("H5") == "FAIL" and v.get("H2") == "PASS"),
        ("h2: an endpoint that needs no credential fails H5 (control)", MockProvider(open_auth=True),
         lambda v, rc: rc == 1 and v.get("H5") == "FAIL"),
        ("h2: no WINDOW_UPDATE for a large body fails H6", MockProvider(h2={"stall": True}),
         lambda v, rc: rc == 1 and v.get("H6") == "FAIL" and v.get("H2") == "PASS"),
        ("h2: credential in a (Huffman-coded) response header fails H7", MockProvider(h2={"reflect_header": True}),
         lambda v, rc: rc == 1 and v.get("H7") == "FAIL"),
        ("h2: credential in an error body fails H7", MockProvider(reflect_body=True),
         lambda v, rc: rc == 1 and v.get("H7") == "FAIL"),
        ("h2: CRLF event stream fails H8", MockProvider(crlf=True),
         lambda v, rc: rc == 1 and v.get("H8") == "FAIL"),
        ("h2: multi-line usage event fails H8", MockProvider(pretty=True),
         lambda v, rc: rc == 1 and v.get("H8") == "FAIL"),
        ("h2: outage (503 everywhere) passes nothing beyond the handshake", MockProvider(status=503),
         lambda v, rc: rc == 2 and not any(v.get(k) == "PASS" for k in hs[1:])),
        ("h2: rate limit (429 everywhere) passes nothing beyond the handshake", MockProvider(status=429),
         lambda v, rc: rc == 2 and not any(v.get(k) == "PASS" for k in hs[1:])),
        ("h2: timeouts are inconclusive, gate closed", MockProvider(timeout=True),
         lambda v, rc: rc == 2 and all(x == "INCONCLUSIVE" for x in v.values())),
        ("h2: a silent connection is inconclusive, gate closed", MockProvider(h2={"dead": True}),
         lambda v, rc: rc == 2 and not any(v.get(k) == "PASS" for k in hs[1:])),
        ("h2: bad key (401 everywhere) passes nothing beyond the handshake", MockProvider(status=401),
         lambda v, rc: rc == 1 and not any(v.get(k) == "PASS" for k in hs[1:])),
    ]
    bad = 0
    try:
        for label, mock, pred in h2_scenarios:
            TRANSPORT.update(http=mock.http, partial=mock.partial, s_client=mock.s_client, h2=mock.h2)
            rc = run_h2()
            v = verdicts()
            ok = pred(v, rc)
            bad += not ok
            summary = " ".join(f"{k}={x[0]}" for k, x in v.items())
            print(f"{'ok  ' if ok else 'BAD '} {label}: exit={rc} [{summary}]")
        for label, mock, pred in scenarios:
            TRANSPORT.update(http=mock.http, partial=mock.partial, s_client=mock.s_client)
            rc = run_all(pause=0.0, quiet=True)
            v = verdicts()
            ok = pred(v, rc)
            bad += not ok
            summary = " ".join(f"{k}={x[0]}" for k, x in v.items())
            print(f"{'ok  ' if ok else 'BAD '} {label}: exit={rc} [{summary}]")
        for label, mock, pred in image_scenarios:
            TRANSPORT.update(http=mock.http, partial=mock.partial, s_client=mock.s_client)
            rc = run_all(pause=0.0, quiet=True, checks=[i10_image_aliases_in_private_part])
            v = verdicts()
            ok = pred(v, rc)
            bad += not ok
            summary = " ".join(f"{k}={x[0]}" for k, x in v.items())
            print(f"{'ok  ' if ok else 'BAD '} {label}: exit={rc} [{summary}]")
    finally:
        TRANSPORT.update(saved)
    total = len(scenarios) + len(h2_scenarios) + len(image_scenarios)
    print(f"self-test: {total - bad}/{total} scenarios behave as required")
    return 1 if bad else 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if not KEY:
        print(f"{KEY_ENV} is not set", file=sys.stderr)
        return 2
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"provider profile check  {now}")
    print(f"  provider: https://{HOST}{PATH}  build: {provider_build()}")
    print(f"  models: cheap={CHEAP} reasoning={REASONING} text_only={TEXT_ONLY} vision={VISION}")
    print(f"  offer file: {os.path.relpath(_OFFER_FILE)}  key: ${KEY_ENV}")
    print(f"  openssl: {find_openssl() or 'NOT FOUND'}  retries={RETRIES}")
    if "--h2" in sys.argv[1:]:
        if not H2_PROBE:
            print('the offer file has no "h2" block: add one with a probe_path (a cheap authenticated GET, '
                  'e.g. the models list) to check framing "2"', file=sys.stderr)
            return 2
        print(f"  framing \"2\": probe {H2_PROBE}, idle {H2_IDLE:.0f} s (offer h2.idle_secs {H2_OFFER_IDLE}), "
              f"body {H2_BODY_BYTES} bytes, images {'yes: one paid image of ' + IMAGE_MODEL if H2_IMAGES and not NO_H2_IMAGES else 'no'}")
        return run_h2()
    if "--images" in sys.argv[1:]:
        print(f"  image route: {IMAGE_PATH} model={IMAGE_MODEL} (three paid images, and up to four for I10)")
        return run_all(checks=IMAGE_CHECKS)
    return run_all()


if __name__ == "__main__":
    sys.exit(main())
