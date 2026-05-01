import argparse
import asyncio

from custom_components.mackie_dl.client import MackieClient


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=50001)
    sub = ap.add_subparsers(dest="cmd", required=True)

    mute = sub.add_parser("mute")
    mute.add_argument("channel", type=int)
    mute.add_argument("state", choices=["on", "off"])

    fader = sub.add_parser("fader")
    fader.add_argument("channel", type=int)
    fader.add_argument("level", type=float)

    args = ap.parse_args()

    c = MackieClient(args.host, args.port)
    await c.connect()
    try:
        if args.cmd == "mute":
            await c.set_input_mute(args.channel, args.state == "on")
        elif args.cmd == "fader":
            await c.set_input_fader(args.channel, args.level)
    finally:
        await c.close()


if __name__ == "__main__":
    asyncio.run(main())

