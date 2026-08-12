#!/usr/bin/env python3
"""Collect the mixer's value space passively. WRITES NOTHING.

After init the mixer PUSHES its entire value space (on the reference DL32S: 3072
values from address 1, then 2185 more from 3073). So discovery does not need to
poll - connect, sit still, and record what arrives.

    python3 tools/discover/listen_mackie.py <mixer-ip> --model dl32s > dump.tsv

``--watch`` keeps listening after the initial settle and reports every change as
it happens. That is the mode for pinning down an unknown field: move one control
in Master Fader and the address responsible prints itself, with before and after
values. Nothing needs to be guessed.

Run this on a machine on the same LAN as the desk. Over a VPN the init burst can
straddle the settle window and you will silently collect a partial space.
"""
from __future__ import annotations

import argparse
import asyncio
import struct
import sys
import time

import _bootstrap  # noqa: F401  (path setup; must precede the client import)
from client import MackieClient  # noqa: E402


def as_float(raw: int) -> float:
    return struct.unpack(">f", struct.pack(">I", raw))[0]


def fmt_float(raw: int) -> str:
    f = as_float(raw)
    return f"{f:.6g}" if -1e12 < f < 1e12 else "-"


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--model", default="dl32s")
    ap.add_argument("--settle", type=float, default=15.0,
                    help="seconds to collect the initial push before reporting")
    ap.add_argument("--watch", type=float, default=0.0,
                    help="after settling, watch this long and log every change")
    args = ap.parse_args()

    seen: dict[int, int] = {}
    changes: list[tuple[float, int, int, int]] = []
    watching = False
    t0 = time.monotonic()

    def on_value(address: int, raw: int) -> None:
        prev = seen.get(address)
        seen[address] = raw
        if watching and prev is not None and prev != raw:
            changes.append((time.monotonic() - t0, address, prev, raw))

    client = MackieClient(args.host, args.port, mixer_model=args.model)
    client.subscribe_all(on_value)
    await client.connect()
    print(f"# connected to {args.host}:{args.port} model={args.model}", file=sys.stderr)

    await asyncio.sleep(args.settle)
    print(f"# {len(seen)} addresses collected during settle", file=sys.stderr)

    if args.watch > 0:
        watching = True
        print(f"# WATCHING {args.watch}s - move ONE control in Master Fader now",
              file=sys.stderr, flush=True)
        await asyncio.sleep(args.watch)
        watching = False
        print(f"# {len(changes)} changes observed", file=sys.stderr)

    print("addr\traw_u32\thex\tfloat32")
    for addr in sorted(seen):
        raw = seen[addr]
        print(f"{addr}\t{raw}\t0x{raw:08x}\t{fmt_float(raw)}")

    if changes:
        print("\n# --- changes ---")
        print("# t\taddr\tfrom\tto\tfrom_f\tto_f")
        for t, addr, prev, raw in changes:
            print(f"# {t:.2f}\t{addr}\t{prev}\t{raw}\t{fmt_float(prev)}\t{fmt_float(raw)}")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
