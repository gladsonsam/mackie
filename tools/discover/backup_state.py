"""Read-only backup: Show.zip + type-2 mute-group state + snapshot names.

Usage: python backup_state.py <host> [--port 50001] --out <dir>
Writes Show.zip, show-names.txt, type2.json. Never writes to the mixer
beyond the standard handshake/keepalive/file-read requests.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import _bootstrap  # noqa: F401  (path setup; must precede the client import)
from client import MackieClient  # noqa: E402
from client import parse_show_archive  # noqa: E402


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    client = MackieClient(args.host, port=args.port)
    await client.connect()
    try:
        # Let the connect burst (type-5 + type-2 dumps, names) arrive.
        await asyncio.sleep(12)
        archive = await client.download_file("Show.zip")
        with open(os.path.join(args.out, "Show.zip"), "wb") as f:
            f.write(archive)
        names = parse_show_archive(archive)
        with open(os.path.join(args.out, "show-names.txt"), "w") as f:
            for num in sorted(names):
                f.write(f"{num}\t{names[num]}\n")
        type2 = {a: client._type2_values.get(a) for a in range(1, 108)}
        with open(os.path.join(args.out, "type2.json"), "w") as f:
            json.dump(type2, f, indent=1)
        print(f"Show.zip bytes={len(archive)} snapshots={len(names)}")
        print("type2[11..16] =", [type2.get(a) for a in range(11, 17)])
        print("snapshot names:", names)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
