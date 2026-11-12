#!/usr/bin/env python3
"""A rate-limiting TCP proxy for measurements on a shaped link (stdlib only).

    python3 -I crypto/tools/shape-proxy.py --listen 127.0.0.1:7445 --target 127.0.0.1:7444 \
        --up-mbit 2 --down-mbit 50 --delay-ms 40

Put it between a client and a sidecar (or a node): the client talks to
``--listen``, the proxy to ``--target``. WebSockets are TCP, so every socket
of a connection (session, 2PC, proofs) goes through it. "Up" is client to
target, "down" is target to client.

The model is one link per direction, shared by all connections: bytes are
sent in segments of at most 1460 bytes, one after the other at the link's
rate, and each segment arrives ``--delay-ms`` later (one way; the round trip
is twice that). A reader is paused while the link is busy, so the sender sees
back-pressure as on a real slow link. There is no loss and no jitter. The TCP
handshake of the proxied connection itself is not delayed.

It prints the bytes carried in each direction when it stops (Ctrl-C, SIGTERM)
and on SIGUSR1.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys

SEGMENT = 1460


class Link:
    """One direction: a serial line of ``rate`` bytes per second plus a delay."""

    def __init__(self, mbit: float, delay_s: float) -> None:
        self.rate = mbit * 1e6 / 8 if mbit > 0 else 0.0
        self.delay = delay_s
        self.free_at = 0.0
        self.bytes = 0

    async def carry(self, loop: asyncio.AbstractEventLoop, data: bytes, deliver) -> None:
        """Send ``data``; returns once the line is free again."""
        for i in range(0, len(data), SEGMENT):
            seg = data[i : i + SEGMENT]
            now = loop.time()
            # A reader that woke late does not lose line time (up to 20 ms).
            start = max(now - 0.02, self.free_at)
            self.free_at = start + (len(seg) / self.rate if self.rate else 0.0)
            self.bytes += len(seg)
            loop.call_at(self.free_at + self.delay, deliver, seg)
            if self.free_at > now:
                await asyncio.sleep(self.free_at - now)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, link: Link) -> None:
    loop = asyncio.get_running_loop()

    def deliver(seg: bytes) -> None:
        if not writer.is_closing():
            writer.write(seg)

    def finish() -> None:
        if not writer.is_closing():
            try:
                writer.write_eof()
            except (OSError, RuntimeError):
                writer.close()

    try:
        while True:
            data = await reader.read(SEGMENT)
            if not data:
                break
            await link.carry(loop, data, deliver)
            # Do not let the receiver fall far behind what the link delivered.
            if writer.transport.get_write_buffer_size() > 1 << 20:
                await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    # The close travels the link like the data before it.
    loop.call_at(max(loop.time(), link.free_at) + link.delay, finish)


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:7445")
    ap.add_argument("--target", required=True)
    ap.add_argument("--up-mbit", type=float, default=2.0, help="client to target, Mbit/s (0 = unlimited)")
    ap.add_argument("--down-mbit", type=float, default=50.0, help="target to client, Mbit/s (0 = unlimited)")
    ap.add_argument("--delay-ms", type=float, default=40.0, help="one-way delay, each direction")
    a = ap.parse_args()
    lh, lp = a.listen.rsplit(":", 1)
    th, tp = a.target.rsplit(":", 1)
    up, down = Link(a.up_mbit, a.delay_ms / 1000), Link(a.down_mbit, a.delay_ms / 1000)
    conns = 0

    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        nonlocal conns
        conns += 1
        try:
            tr, tw = await asyncio.open_connection(th, int(tp))
        except OSError as exc:
            print(f"shape-proxy: cannot reach {a.target}: {exc}", file=sys.stderr)
            cw.close()
            return
        try:
            await asyncio.gather(pipe(cr, tw, up), pipe(tr, cw, down))
            await asyncio.sleep(2 * a.delay_ms / 1000 + 1)
        finally:
            for w in (cw, tw):
                w.close()

    def report(*_: object) -> None:
        print(f"shape-proxy: {conns} connections, {up.bytes} bytes up, {down.bytes} bytes down", file=sys.stderr, flush=True)

    server = await asyncio.start_server(handle, lh, int(lp))
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    loop.add_signal_handler(signal.SIGUSR1, report)
    print(f"shape-proxy: {a.listen} -> {a.target}, up {a.up_mbit} Mbit/s, down {a.down_mbit} Mbit/s, "
          f"{a.delay_ms:.0f} ms one way", file=sys.stderr, flush=True)
    async with server:
        await stop.wait()
        report()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
