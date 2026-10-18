"""Record every value change (type-5 AND type-2) with timestamps.

Usage: python record_changes.py <host> --seconds 60 [--settle 12] [--out changes.tsv]
Passive listener: performs the standard handshake then only records pushes.
Prints a settle summary to stderr, then TSV lines to stdout/file:
    t  type  addr  old_u32  new_u32  old_f  new_f
"""
from __future__ import annotations

import argparse
import asyncio
import os
import struct
import sys
import time

import _bootstrap  # noqa: F401  (path setup; must precede the client import)
from client import MackieClient  # noqa: E402


def as_float(raw: int) -> float:
    return struct.unpack(">f", struct.pack(">I", raw & 0xFFFFFFFF))[0]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--settle", type=float, default=30.0,
                    help="bulk type-2 dump arrives ~15-30s in; shorter settles miss it")
    ap.add_argument("--out", default="")
    ap.add_argument("--flush-every", type=float, default=5.0)
    args = ap.parse_args()

    seen5: dict[int, int] = {}
    seen2: dict[int, int] = {}
    rows: list[str] = []
    watching = False
    t0 = time.monotonic()
    out_f = open(args.out, "a") if args.out else None

    def persist() -> None:
        if out_f and rows:
            out_f.write("\n".join(rows) + "\n")
            out_f.flush()
            rows.clear()

    def emit(typ: int, addr: int, old: int, new: int) -> None:
        t = time.monotonic() - t0
        rows.append(
            f"{t:8.2f}\t{typ}\t{addr}\t{old}\t{new}\t"
            f"{as_float(old):.6g}\t{as_float(new):.6g}"
        )

    def on5(address: int, raw: int) -> None:
        prev = seen5.get(address)
        seen5[address] = raw
        if watching and prev is not None and prev != raw:
            emit(5, address, prev, raw)

    def on2(address: int, raw: int) -> None:
        prev = seen2.get(address)
        seen2[address] = raw
        if watching and prev is not None and prev != raw:
            emit(2, address, prev, raw)

    client = MackieClient(args.host, port=args.port)
    unsub5 = client.subscribe_all(on5)
    # type-2 has per-address listener dict; hook a few known + catch-all via
    # direct dict access is not public, so subscribe the known range instead.
    unsubs = [unsub5]
    for a in range(1, 108):
        unsubs.append(client.subscribe_type2(a, on2))
    await client.connect()
    await asyncio.sleep(args.settle)
    note = (f"# settled: {len(seen5)} type5, {len(seen2)} type2; "
            f"watching {args.seconds}s")
    print(note, file=sys.stderr)
    if out_f:
        out_f.write(note + "\n")
        out_f.flush()
    watching = True
    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        await asyncio.sleep(min(args.flush_every, deadline - time.monotonic()))
        persist()
    watching = False
    for u in unsubs:
        u()
    await client.close()
    persist()
    if out_f:
        out_f.close()
    elif rows:
        print("\n".join(rows))


if __name__ == "__main__":
    asyncio.run(main())
