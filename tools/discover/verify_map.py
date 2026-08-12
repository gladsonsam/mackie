#!/usr/bin/env python3
"""Check addressmap.py against a real dump. WRITES NOTHING.

    python3 tools/discover/listen_mackie.py <mixer-ip> > dump.tsv
    python3 tools/discover/verify_map.py dump.tsv --model dl32s

Run this after a mixer firmware update. The protocol is undocumented and Mackie
owe us no stability, so a map that was right in August may be wrong later; this
catches a shifted layout in seconds instead of during a service.

What it checks:

* structural   - every offset in the strip is accounted for, and the anchor
                 addresses land where two independent sources say they should
* plausibility - booleans really are 0/1 across all channels, and bounded fields
                 sit inside their declared range

Plausibility is a weak test on any single channel and a strong one across 32:
a one-word shift turns a column of booleans into a column of floats immediately.
"""
from __future__ import annotations

import argparse
import struct
import sys

import _bootstrap  # noqa: F401
from addressmap import get_map  # noqa: E402


def read_dump(path: str) -> dict[int, int]:
    vals: dict[int, int] = {}
    with open(path) as fh:
        for line in fh:
            if not line.strip() or line.startswith(("addr", "#")):
                continue
            parts = line.split("\t")
            vals[int(parts[0])] = int(parts[1])
    return vals


def as_float(raw: int) -> float:
    return struct.unpack(">f", struct.pack(">I", raw))[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", help="TSV from listen_mackie.py")
    ap.add_argument("--model", default="dl32s")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    vals = read_dump(args.dump)
    block = get_map(args.model).inputs
    problems: list[str] = []

    # --- structural -------------------------------------------------------
    offsets = {f.offset for f in block.fields}
    missing = sorted(set(range(block.stride)) - offsets)
    if missing:
        problems.append(f"offsets with no field: {missing}")
    dupes = len(block.fields) - len(offsets)
    if dupes:
        problems.append(f"{dupes} offsets mapped by more than one field")

    # Anchors: channel 2's mute address is the classic off-by-one detector, and
    # the send-block start is where DigiMixer and this map must agree.
    if args.model == "dl32s":
        for key, ch, expect in (("mute", 2, 114), ("fader", 1, 9), ("aux1_level", 1, 51)):
            got = block.address(ch, key)
            if got != expect:
                problems.append(f"anchor {key} ch{ch}: expected address {expect}, got {got}")

    # --- plausibility -----------------------------------------------------
    checked = 0
    for fld in block.fields:
        if not fld.verified:
            continue
        for ch in range(1, block.count + 1):
            raw = vals.get(block.address(ch, fld.key))
            if raw is None:
                continue
            checked += 1
            if fld.encoding == "bool" and raw not in (0, 1):
                problems.append(f"{fld.key} ch{ch}: not boolean (raw {raw})")
            elif fld.encoding in ("db", "float") and fld.limits:
                v = as_float(raw)
                lo, hi = fld.limits
                if not lo - 1e-3 <= v <= hi + 1e-3:
                    problems.append(f"{fld.key} ch{ch}: {v:.4g} outside {lo}..{hi}")

    if not args.quiet:
        print(f"model            {args.model}")
        print(f"addresses in dump{len(vals):>6}")
        print(f"fields mapped    {len(block.fields):>6}  ({sum(1 for f in block.fields if not f.verified)} unverified)")
        print(f"value checks     {checked:>6}")

    if problems:
        print(f"\nFAIL - {len(problems)} problem(s):")
        for p in problems[:40]:
            print(f"  {p}")
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more")
        return 1

    print("\nOK - map is consistent with this dump")
    return 0


if __name__ == "__main__":
    sys.exit(main())
