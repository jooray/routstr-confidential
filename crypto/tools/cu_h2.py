"""HTTP/2 pieces of ``provider-profile-check.py --h2`` (PROTOCOL-V3.md §5.6).

Pure protocol code, no network: HPACK (RFC 7541; decoding with Huffman, the
few literal encodings the checks write), frames (RFC 9113), a client that
speaks exactly what a framing-"2" connection puts on the wire (the connection
head of §5.2 with the credential stored at index 62, then requests that name
it by index), and a mock provider for ``--self-test``.

The client talks through a transport with ``send(bytes)``, ``recv(timeout)``
(bytes, ``b""`` on a timeout; ``TransportClosed`` once the peer has closed and
nothing is left), ``key_update()`` and ``now()``.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Callable

STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""),
    ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""),
    ("content-length", ""), ("content-location", ""), ("content-range", ""),
    ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""),
    ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""),
    ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""),
    ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
]

# (code, bit length) per symbol; 256 is EOS.
HUFFMAN = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
    (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
    (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
    (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
    (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
    (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
    (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
    (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
    (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
    (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
    (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
    (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
    (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
    (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
    (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
    (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
    (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
    (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
]


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0, 1, 3, 4, 6, 7, 8, 9
END_STREAM, ACK, END_HEADERS, PADDED, PRIORITY = 0x1, 0x1, 0x4, 0x8, 0x20
S_HEADER_TABLE_SIZE, S_ENABLE_PUSH, S_INITIAL_WINDOW_SIZE, S_MAX_FRAME_SIZE = 1, 2, 4, 5
FRAME_NAMES = {0: "DATA", 1: "HEADERS", 3: "RST_STREAM", 4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
# One DATA frame per write, small enough for one read of `openssl s_client`.
DATA_CHUNK = 8192 - 9


class TransportClosed(Exception):
    """The peer closed the connection."""


class H2Error(Exception):
    """The peer broke HTTP/2 or HPACK as a framing-"2" connection needs it."""


class FlowStall(Exception):
    """The peer stopped opening its flow-control window."""


# --------------------------------------------------------------------------- HPACK

_HUFF_BY_CODE = {(code, bits): sym for sym, (code, bits) in enumerate(HUFFMAN)}


def huffman_decode(data: bytes) -> bytes:
    out, code, bits = bytearray(), 0, 0
    for byte in data:
        for i in range(7, -1, -1):
            code, bits = (code << 1) | ((byte >> i) & 1), bits + 1
            sym = _HUFF_BY_CODE.get((code, bits))
            if sym is not None:
                if sym == 256:
                    raise H2Error("HPACK: EOS inside a Huffman string")
                out.append(sym)
                code, bits = 0, 0
            elif bits > 30:
                raise H2Error("HPACK: bad Huffman code")
    if bits > 7 or code != (1 << bits) - 1:
        raise H2Error("HPACK: bad Huffman padding")
    return bytes(out)


def huffman_encode(data: bytes) -> bytes:
    acc, bits = 0, 0
    for b in data:
        code, n = HUFFMAN[b]
        acc, bits = (acc << n) | code, bits + n
    pad = (8 - bits % 8) % 8
    acc, bits = (acc << pad) | ((1 << pad) - 1), bits + pad
    return acc.to_bytes(bits // 8, "big")


def enc_int(value: int, prefix: int, flags: int = 0) -> bytes:
    cap = (1 << prefix) - 1
    if value < cap:
        return bytes([flags | value])
    out, value = bytearray([flags | cap]), value - cap
    while value >= 128:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    out.append(value)
    return bytes(out)


def dec_int(buf: bytes, off: int, prefix: int) -> tuple[int, int]:
    if off >= len(buf):
        raise H2Error("HPACK: truncated integer")
    cap = (1 << prefix) - 1
    value = buf[off] & cap
    off += 1
    if value < cap:
        return value, off
    shift = 0
    while True:
        if off >= len(buf) or shift > 28:
            raise H2Error("HPACK: bad integer")
        b = buf[off]
        off += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, off


def enc_str(s: bytes, huffman: bool = False) -> bytes:
    if huffman:
        h = huffman_encode(s)
        return enc_int(len(h), 7, 0x80) + h
    return enc_int(len(s), 7) + s


class Decoder:
    """An HPACK decoder whose dynamic table may hold ``max_size`` bytes.

    With ``max_size = 0`` (what the connection head announces for response
    headers, H4) any reference to a dynamic entry and any table size update
    above 0 is an ``H2Error``.
    """

    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self.limit = max_size
        self.table: list[tuple[bytes, bytes]] = []
        self.size_updates: list[int] = []
        self.inserted = 0

    def _size(self) -> int:
        return sum(len(n) + len(v) + 32 for n, v in self.table)

    def _evict(self) -> None:
        while self.table and self._size() > self.limit:
            self.table.pop()

    def _entry(self, idx: int) -> tuple[bytes, bytes]:
        if idx == 0:
            raise H2Error("HPACK: index 0")
        if idx <= len(STATIC):
            n, v = STATIC[idx - 1]
            return n.encode(), v.encode()
        d = idx - len(STATIC) - 1
        if d >= len(self.table):
            raise H2Error(f"HPACK: index {idx} names a dynamic entry that the table (size limit {self.limit}) does not hold")
        return self.table[d]

    def _str(self, buf: bytes, off: int) -> tuple[bytes, int]:
        if off >= len(buf):
            raise H2Error("HPACK: truncated string")
        huff = bool(buf[off] & 0x80)
        n, off = dec_int(buf, off, 7)
        if off + n > len(buf):
            raise H2Error("HPACK: truncated string")
        raw = buf[off : off + n]
        return (huffman_decode(raw) if huff else raw), off + n

    def decode(self, block: bytes) -> list[tuple[bytes, bytes]]:
        out, off = [], 0
        while off < len(block):
            b = block[off]
            if b & 0x80:
                idx, off = dec_int(block, off, 7)
                out.append(self._entry(idx))
            elif b & 0xC0 == 0x40 or b & 0xE0 == 0x00:
                indexing = b & 0xC0 == 0x40
                idx, off = dec_int(block, off, 6 if indexing else 4)
                if idx:
                    name = self._entry(idx)[0]
                else:
                    name, off = self._str(block, off)
                value, off = self._str(block, off)
                out.append((name, value))
                if indexing:
                    self.inserted += 1
                    self.table.insert(0, (name, value))
                    self._evict()
            elif b & 0xE0 == 0x20:
                size, off = dec_int(block, off, 5)
                self.size_updates.append(size)
                if size > self.max_size:
                    raise H2Error(f"HPACK: table size update to {size}, above the announced {self.max_size}")
                self.limit = size
                self._evict()
            else:
                raise H2Error("HPACK: unknown representation")
        return out


# --------------------------------------------------------------------------- frames


def frame(ftype: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream) + payload


def parse_frames(buf: bytes) -> tuple[list[tuple[int, int, int, bytes]], bytes]:
    out, off = [], 0
    while len(buf) - off >= 9:
        n = int.from_bytes(buf[off : off + 3], "big")
        if len(buf) - off < 9 + n:
            break
        out.append((buf[off + 3], buf[off + 4], int.from_bytes(buf[off + 5 : off + 9], "big") & 0x7FFFFFFF, buf[off + 9 : off + 9 + n]))
        off += 9 + n
    return out, buf[off:]


def credential_entry_size(key_len: int) -> int:
    """The HPACK size of ``authorization: Bearer <key>`` (RFC 7541 §4.1)."""
    return 32 + len("authorization") + len("Bearer ") + key_len


def conn_head(host: str, probe_path: str, key: str, reset_probe: bool = True) -> bytes:
    """The connection head of PROTOCOL-V3.md §5.2, byte for byte.

    ``57`` = literal with incremental indexing, name = static 23
    (authorization): afterwards the peer's request table holds the credential
    at index 62. ``reset_probe = False`` leaves the probe stream open, so its
    response can be read (H7).
    """
    block = (b"\x82\x87\x01" + enc_str(host.encode()) + b"\x04" + enc_str(probe_path.encode())
             + b"\x57" + enc_str(b"Bearer " + key.encode()))
    out = PREFACE
    out += frame(SETTINGS, 0, 0, struct.pack(">HIHIHI", S_HEADER_TABLE_SIZE, 0, S_ENABLE_PUSH, 0, S_INITIAL_WINDOW_SIZE, 0x7FFFFFFF))
    out += frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7FFFFFFF - 65535))
    out += frame(HEADERS, END_STREAM | END_HEADERS, 1, block)
    if reset_probe:
        out += frame(RST_STREAM, 0, 1, struct.pack(">I", 8))
    return out


def request_block(host: str, path: str, by_index: bool = True) -> bytes:
    """The request header block of §5.3; ``be`` = indexed field 62, the credential."""
    block = b"\x83\x87\x01" + enc_str(host.encode()) + b"\x04" + enc_str(path.encode()) + b"\x0f\x10" + enc_str(b"application/json")
    return block + (b"\xbe" if by_index else b"")


@dataclass
class StreamResp:
    stream: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    trailers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    ended: bool = False
    reset: int | None = None
    # Frames that arrived on the connection while the stream was open, in
    # order: (type, flags, stream, payload length, body length before it).
    frames: list[tuple[int, int, int, int, int]] = field(default_factory=list)
    hpack_error: str | None = None

    @property
    def status(self) -> int:
        for n, v in self.headers:
            if n == ":status" and v.isdigit():
                return int(v)
        return 0

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str:
        return next((v for n, v in self.headers if n == name), "")


class H2Client:
    """What C and N together write on a framing-"2" connection."""

    def __init__(self, tr, host: str, key: str) -> None:
        self.tr, self.host, self.key = tr, host, key
        self.buf = b""
        self.dec = Decoder(0)  # the head announces HEADER_TABLE_SIZE = 0
        self.streams: dict[int, StreamResp] = {}
        self.peer_settings: list[dict[int, int]] = []
        self.header_table_size: int | None = None
        self.peer_initial_window = 65535
        self.peer_max_frame = 16384
        self.conn_credit = 65535
        self.credit: dict[int, int] = {}
        self.settings_acked = False
        self.goaway: tuple[int, bytes] | None = None
        self.closed = False
        self.window_updates = 0
        self.pings = 0
        self.hpack_error: str | None = None
        self.blocks = 0
        self._cont: tuple[int, int, bytes] | None = None
        self.next_stream = 3

    # ---- receiving

    def _on_headers(self, stream: int, flags: int, block: bytes) -> None:
        r = self.streams.setdefault(stream, StreamResp(stream))
        self.blocks += 1
        try:
            fields = [(n.decode("latin1"), v.decode("latin1")) for n, v in self.dec.decode(block)]
        except H2Error as exc:
            self.hpack_error = self.hpack_error or f"stream {stream}: {exc}"
            r.hpack_error = str(exc)
            fields = []
        if r.headers and not any(n == ":status" for n, _ in fields):
            r.trailers = fields
        else:
            # An interim (1xx) head is replaced by the final one.
            r.headers = fields
        if flags & END_STREAM:
            r.ended = True

    def _on_frame(self, t: int, flags: int, stream: int, payload: bytes) -> None:
        for r in self.streams.values():
            if not r.ended and r.reset is None:
                r.frames.append((t, flags, stream, len(payload), len(r.body)))
        if self._cont is not None and t != CONTINUATION:
            raise H2Error("a frame inside a header block")
        if t == SETTINGS:
            if flags & ACK:
                self.settings_acked = True
                return
            params = {}
            for i in range(0, len(payload) - 5, 6):
                ident, value = struct.unpack(">HI", payload[i : i + 6])
                params[ident] = value
            self.peer_settings.append(params)
            if S_HEADER_TABLE_SIZE in params:
                self.header_table_size = params[S_HEADER_TABLE_SIZE]
            if S_INITIAL_WINDOW_SIZE in params:
                delta = params[S_INITIAL_WINDOW_SIZE] - self.peer_initial_window
                self.peer_initial_window = params[S_INITIAL_WINDOW_SIZE]
                for s in self.credit:
                    self.credit[s] += delta
            if S_MAX_FRAME_SIZE in params:
                self.peer_max_frame = params[S_MAX_FRAME_SIZE]
            self.tr.send(frame(SETTINGS, ACK, 0))
        elif t == PING:
            if not flags & ACK:
                self.pings += 1
                self.tr.send(frame(PING, ACK, 0, payload))
        elif t == WINDOW_UPDATE:
            inc = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            self.window_updates += 1
            if stream == 0:
                self.conn_credit += inc
            else:
                self.credit[stream] = self.credit.get(stream, self.peer_initial_window) + inc
        elif t == GOAWAY:
            self.goaway = (int.from_bytes(payload[4:8], "big"), payload[8:])
        elif t == RST_STREAM:
            self.streams.setdefault(stream, StreamResp(stream)).reset = int.from_bytes(payload[:4], "big")
        elif t in (HEADERS, CONTINUATION):
            if t == HEADERS:
                if flags & PADDED:
                    payload = payload[1 : len(payload) - payload[0]]
                if flags & PRIORITY:
                    payload = payload[5:]
                self._cont = (stream, flags, payload)
            else:
                if self._cont is None or self._cont[0] != stream:
                    raise H2Error("CONTINUATION without HEADERS")
                self._cont = (stream, self._cont[1] | (flags & END_HEADERS), self._cont[2] + payload)
            if self._cont[1] & END_HEADERS:
                s, f, block = self._cont
                self._cont = None
                self._on_headers(s, f, block)
        elif t == DATA:
            r = self.streams.setdefault(stream, StreamResp(stream))
            if flags & PADDED:
                payload = payload[1 : len(payload) - payload[0]]
            r.body += payload
            if flags & END_STREAM:
                r.ended = True

    def pump(self, done: Callable[[], bool], timeout: float) -> bool:
        """Read and answer frames until ``done()``; False on a timeout or a close."""
        end = self.tr.now() + timeout
        while not done():
            left = end - self.tr.now()
            if left <= 0 or self.closed:
                return False
            try:
                data = self.tr.recv(min(left, 1.0))
            except TransportClosed:
                self.closed = True
                return done()
            if not data:
                continue
            frames, self.buf = parse_frames(self.buf + data)
            for f in frames:
                self._on_frame(*f)
        return True

    # ---- sending

    def open(self, probe_path: str, reset_probe: bool = True) -> None:
        self.tr.send(conn_head(self.host, probe_path, self.key, reset_probe))
        self.streams[1] = StreamResp(1)

    def key_update(self) -> None:
        self.tr.key_update()

    def idle(self, seconds: float) -> None:
        """Stay idle, answering what the peer sends (PING, SETTINGS)."""
        self.pump(lambda: False, seconds)

    def request(self, path: str, body: bytes, by_index: bool = True, timeout: float = 120.0) -> StreamResp:
        """One request as §5.3 writes it: HEADERS, then DATA under the peer's flow control."""
        if self.closed:
            raise TransportClosed("the connection is closed")
        stream, self.next_stream = self.next_stream, self.next_stream + 2
        r = self.streams[stream] = StreamResp(stream)
        self.credit[stream] = self.peer_initial_window
        self.tr.send(frame(HEADERS, END_HEADERS, stream, request_block(self.host, path, by_index)))
        off, chunk = 0, min(DATA_CHUNK, self.peer_max_frame)
        while off < len(body):
            room = min(self.conn_credit, self.credit[stream])
            if room <= 0:
                if r.ended or r.reset is not None:
                    return r  # refused before the body was complete
                if not self.pump(lambda: min(self.conn_credit, self.credit[stream]) > 0 or r.ended or r.reset is not None, 30.0):
                    if self.closed:
                        raise TransportClosed(f"closed with {off} of {len(body)} body bytes sent")
                    raise FlowStall(f"no WINDOW_UPDATE for 30 s after {off} of {len(body)} body bytes")
                continue
            n = min(chunk, room, len(body) - off)
            last = off + n == len(body)
            if last and len(body) > chunk:
                self.tr.settle()  # the tail starts its own read of the transport
            self.tr.send(frame(DATA, END_STREAM if last else 0, stream, body[off : off + n]))
            self.conn_credit -= n
            self.credit[stream] -= n
            off += n
            # Take what has arrived (window updates, an early refusal).
            self._drain()
        self.pump(lambda: r.ended or r.reset is not None or self.goaway is not None, timeout)
        return r

    def _drain(self) -> None:
        try:
            data = self.tr.recv(0)
        except TransportClosed:
            self.closed = True
            return
        if data:
            frames, self.buf = parse_frames(self.buf + data)
            for f in frames:
                self._on_frame(*f)


def tail_problem(r: StreamResp) -> str | None:
    """Why a 2xx event stream does not end the way §5.4 parses it (H8), or None.

    From the line feed before the usage event's ``data: `` to END_STREAM the
    DATA payload must be exactly ``data: <usage JSON>\\n\\ndata: [DONE]\\n\\n``,
    one line of JSON, LF only; the stream must end (END_STREAM on a DATA frame
    or on one trailers HEADERS); the frames in between may only be DATA on the
    stream, that trailers frame, SETTINGS / PING / GOAWAY on stream 0 and
    WINDOW_UPDATE on stream 0 or the stream; the tail with its frame headers
    fits the 16 KiB a disclosure may hold.
    """
    body = r.body
    if not r.ended:
        return "the stream did not end"
    if b"\r" in body:
        return "CR in the event stream"
    end = b"\n\ndata: [DONE]\n\n"
    if not body.endswith(end):
        return f"the stream does not end in data: [DONE] and a blank line (ends {body[-24:]!r})"
    start = body.rfind(b"\ndata: ", 0, len(body) - len(end) + 1)
    if start < 0:
        return "no event before [DONE]"
    usage = body[start + 7 : len(body) - len(end)]
    if b"\n" in usage or b"\x00" in usage:
        return "the last event before [DONE] is not one line"
    try:
        ev = json.loads(usage)
    except ValueError:
        return "the last event before [DONE] is not JSON"
    if not isinstance(ev, dict) or not isinstance(ev.get("usage"), dict):
        return "the last event before [DONE] is not the usage event"
    size, trailers = len(body) - start, 0
    for t, flags, stream, n, before in r.frames:
        if before + (n if t == DATA and stream == r.stream else 0) <= start:
            continue  # before the tail
        size += 9
        if t == DATA and stream == r.stream:
            continue
        if t == HEADERS and stream == r.stream and flags & END_STREAM and flags & END_HEADERS:
            trailers += 1
            size += n
            if trailers > 1:
                return "more than one trailers frame"
        elif (t in (SETTINGS, PING, GOAWAY) and stream == 0) or (t == WINDOW_UPDATE and stream in (0, r.stream)):
            size += n
        else:
            return f"a {FRAME_NAMES.get(t, t)} frame on stream {stream} inside the usage tail"
    if size > 16384:
        return f"the usage tail is {size} bytes (a disclosure holds 16 KiB)"
    return None


# --------------------------------------------------------------------------- mock provider


class MockH2:
    """An in-memory HTTP/2 provider with fault injection (``--self-test``).

    ``app(path, body, authorized) -> (status, content_type, text)`` answers a
    request. Time is virtual: an empty ``recv`` advances the clock.
    """

    def __init__(self, key: str, app: Callable, *, close_on_ku: bool = False, table_size: int | None = None,
                 dynamic_responses: bool = False, forget_after_idle: bool = False, stall: bool = False,
                 reflect_header: bool = False, dead: bool = False, window: int = 65535) -> None:
        self.key, self.app = key, app
        self.close_on_ku, self.table_size, self.dynamic_responses = close_on_ku, table_size, dynamic_responses
        self.forget_after_idle, self.stall, self.reflect_header, self.dead = forget_after_idle, stall, reflect_header, dead
        self.window = window
        self.clock = 0.0
        self.last_send = 0.0
        self.inbuf = b""
        self.out = b""
        self.closed = False
        self.preface = False
        self.dec = Decoder(4096 if table_size is None else table_size)
        self.reqs: dict[int, dict] = {}
        self.responses = 0
        self.key_updates = 0
        self.sent_settings = False

    def now(self) -> float:
        return self.clock

    def settle(self) -> None:
        pass

    def info(self) -> dict:
        return {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "key_updates": self.key_updates}

    def close(self) -> None:
        pass

    def key_update(self) -> None:
        self.key_updates += 1
        if self.close_on_ku:
            self.closed = True

    def recv(self, timeout: float) -> bytes:
        if self.out and not self.dead:
            out, self.out = self.out, b""
            return out
        if self.closed:
            raise TransportClosed("mock closed")
        self.clock += timeout
        return b""

    def send(self, data: bytes) -> None:
        if self.closed or self.dead:
            return
        if self.forget_after_idle and self.clock - self.last_send >= 5:
            self.dec.table.clear()
        self.last_send = self.clock
        self.inbuf += data
        if not self.preface:
            if len(self.inbuf) < len(PREFACE):
                return
            self.inbuf, self.preface = self.inbuf[len(PREFACE):], True
        frames, self.inbuf = parse_frames(self.inbuf)
        for t, flags, stream, payload in frames:
            self._frame(t, flags, stream, payload)

    def _frame(self, t: int, flags: int, stream: int, payload: bytes) -> None:
        if t == SETTINGS and not flags & ACK:
            if not self.sent_settings:
                params = struct.pack(">HIHI", 3, 100, S_INITIAL_WINDOW_SIZE, self.window)
                if self.table_size is not None:
                    params += struct.pack(">HI", S_HEADER_TABLE_SIZE, self.table_size)
                self.out += frame(SETTINGS, 0, 0, params)
                self.sent_settings = True
            self.out += frame(SETTINGS, ACK, 0)
        elif t == PING and not flags & ACK:
            self.out += frame(PING, ACK, 0, payload)
        elif t == RST_STREAM:
            self.reqs.pop(stream, None)
        elif t == HEADERS:
            try:
                fields = dict((n.decode(), v.decode()) for n, v in self.dec.decode(payload))
            except H2Error:
                self.out += frame(GOAWAY, 0, 0, struct.pack(">II", 0, 9))  # COMPRESSION_ERROR
                self.closed = True
                return
            self.reqs[stream] = {"fields": fields, "body": b""}
            if flags & END_STREAM:
                self._respond(stream)
        elif t == DATA and stream in self.reqs:
            self.reqs[stream]["body"] += payload
            if not self.stall and payload:
                inc = struct.pack(">I", len(payload))
                self.out += frame(WINDOW_UPDATE, 0, 0, inc) + frame(WINDOW_UPDATE, 0, stream, inc)
            if flags & END_STREAM:
                self._respond(stream)

    def _respond(self, stream: int) -> None:
        q = self.reqs.pop(stream)
        f = q["fields"]
        authorized = f.get("authorization") == "Bearer " + self.key
        status, ctype, text = self.app(f.get(":path", ""), q["body"].decode("utf-8", "replace"), authorized)
        self.responses += 1
        block = b"\x20" if self.responses == 1 else b""  # table size update to 0, as asked
        block += b"\x08" + enc_str(str(status).encode())  # :status, literal, name = static 8
        block += b"\x0f\x10" + enc_str(ctype.encode(), huffman=True)
        if self.dynamic_responses:
            # Ignores HEADER_TABLE_SIZE = 0: stores a field, then names it by index.
            block = block[1:] if self.responses == 1 else block
            block += (b"\x40" + enc_str(b"x-served-by") + enc_str(b"mock")) if self.responses == 1 else b"\xbe"
        if self.reflect_header:
            block += b"\x00" + enc_str(b"x-request-authorization", huffman=True) + enc_str(f.get("authorization", "").encode(), huffman=True)
        self.out += frame(HEADERS, END_HEADERS, stream, block)
        data = text.encode()
        cut = max(1, len(data) // 2)
        self.out += frame(DATA, 0, stream, data[:cut]) + frame(DATA, END_STREAM, stream, data[cut:])
