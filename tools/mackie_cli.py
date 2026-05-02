import os
import sys
import argparse
import asyncio
import importlib.util
from types import ModuleType
import time
import struct

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_CLIENT_PATH = os.path.join(_REPO_ROOT, "custom_components", "mackie_dl", "client.py")
_spec = importlib.util.spec_from_file_location("mackie_dl_client", _CLIENT_PATH)
assert _spec and _spec.loader
_mod: ModuleType = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[assignment]
MackieClient = _mod.MackieClient
MackieCommand = _mod.MackieCommand


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument(
        "--model",
        choices=["auto", "dl16s", "dl32r", "dl32s"],
        default="auto",
        help="dl16s=DL16 map (stride 100); dl32r=DL32R map (41+132); dl32s=DL32S (stride 106, DL32 meter init); auto=handshake.",
    )
    ap.add_argument(
        "--i-understand-this-writes-to-the-mixer",
        action="store_true",
        help="Required for dangerous commands (raw/scan/detect).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    mute = sub.add_parser("mute")
    mute.add_argument("channel", type=int)
    mute.add_argument("state", choices=["on", "off"])

    fader = sub.add_parser("fader")
    fader.add_argument("channel", type=int)
    fader.add_argument("db", type=float)

    faderlevel = sub.add_parser("faderlevel")
    faderlevel.add_argument("channel", type=int)
    faderlevel.add_argument("level", type=float)

    raw = sub.add_parser("raw")
    raw.add_argument("address", type=int)
    raw_group = raw.add_mutually_exclusive_group(required=True)
    raw_group.add_argument("--int", dest="int_value", type=int)
    raw_group.add_argument("--float", dest="float_value", type=float)

    listen = sub.add_parser("listen")
    listen.add_argument("address", type=int)
    listen.add_argument("--seconds", type=float, default=10.0)

    sniff = sub.add_parser("sniff")
    sniff.add_argument("--seconds", type=float, default=5.0)

    get = sub.add_parser("get")
    get.add_argument("address", type=int)

    scanfloat = sub.add_parser("scanfloat")
    scanfloat.add_argument("start_address", type=int)
    scanfloat.add_argument("--count", type=int, default=32)
    scanfloat.add_argument("--value", type=float, default=-30.0)

    handshake = sub.add_parser("handshake")

    detect = sub.add_parser("detect_inputs")
    detect.add_argument("--channels", type=int, default=32)
    detect.add_argument("--start", type=int, default=1, help="Input1 start address guess")
    detect.add_argument("--size", type=int, default=100, help="Per-input block size guess")
    detect.add_argument("--offset_min", type=int, default=5)
    detect.add_argument("--offset_max", type=int, default=15)

    info = sub.add_parser("info")
    info.add_argument("--probe-general", action="store_true", help="Probe general info request types 1..20")

    names = sub.add_parser("names")
    names.add_argument("--start", type=int, default=1)
    names.add_argument("--count", type=int, default=64)

    probe_channels = sub.add_parser(
        "probe-channels",
        help="Read mute+fader addresses for each input (diagnose map; use --model dl32r for DL32S).",
    )
    probe_channels.add_argument("--channels", type=int, default=32)

    recall_snap = sub.add_parser(
        "recall-snapshot",
        help="Recall show snapshot using Master Fader wire sequence (cmd 0x07); same as HA with snapshot address 0.",
    )
    recall_snap.add_argument("snapshot", type=int, help="Snapshot index (1-based).")

    args = ap.parse_args()

    c = MackieClient(args.host, args.port, mixer_model=args.model)
    await c.connect()
    try:
        if args.cmd == "mute":
            await c.set_input_mute(args.channel, args.state == "on")
            print(f"OK: input {args.channel} mute -> {args.state}")
        elif args.cmd == "fader":
            await c.set_input_fader_db(args.channel, args.db)
            print(f"OK: input {args.channel} fader_db -> {args.db}")
        elif args.cmd == "faderlevel":
            await c.set_input_fader(args.channel, args.level)
            print(f"OK: input {args.channel} fader_level(0-1) -> {args.level}")
        elif args.cmd == "raw":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing to run raw write without --i-understand-this-writes-to-the-mixer"
                )
            if args.int_value is not None:
                await c.raw_set_value_int(args.address, args.int_value)
                print(f"OK: set address {args.address} int -> {args.int_value}")
            else:
                await c.raw_set_value_float(args.address, args.float_value)
                print(f"OK: set address {args.address} float -> {args.float_value}")
        elif args.cmd == "listen":
            start = time.monotonic()

            def _on_update(raw_u32: int) -> None:
                elapsed = time.monotonic() - start
                print(f"{elapsed:7.3f}s addr={args.address} u32=0x{int(raw_u32) & 0xFFFFFFFF:08x} int={int(raw_u32)}")

            unsub = c.subscribe_value(args.address, _on_update)
            try:
                cached = c.get_cached_u32(args.address)
                if cached is not None:
                    print(f"cached addr={args.address} u32=0x{int(cached) & 0xFFFFFFFF:08x} int={int(cached)}")
                # Trigger a fresh channel dump (if supported) after subscribing.
                try:
                    await c.send_request(MackieCommand.CHANNEL_INFO_CONTROL, bytes([0, 0, 0, 6]))
                except Exception:
                    pass
                await asyncio.sleep(max(0.0, float(args.seconds)))
            finally:
                unsub()
        elif args.cmd == "sniff":
            start = time.monotonic()

            def _on_any(addr: int, raw_u32: int) -> None:
                elapsed = time.monotonic() - start
                print(f"{elapsed:7.3f}s addr={addr} u32=0x{int(raw_u32) & 0xFFFFFFFF:08x} int={int(raw_u32)}")

            unsub = c.subscribe_all(_on_any)
            try:
                try:
                    await c.send_request(MackieCommand.CHANNEL_INFO_CONTROL, bytes([0, 0, 0, 6]))
                except Exception:
                    pass
                await asyncio.sleep(max(0.0, float(args.seconds)))
            finally:
                unsub()
        elif args.cmd == "get":
            v = await c.request_value_u32(args.address)
            if v is None:
                print(f"addr={args.address} -> (no response value)")
            else:
                print(f"addr={args.address} u32=0x{int(v) & 0xFFFFFFFF:08x} int={int(v)}")
        elif args.cmd == "scanfloat":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing to run scanfloat without --i-understand-this-writes-to-the-mixer"
                )
            start = int(args.start_address)
            count = int(args.count)
            value = float(args.value)
            print(f"Scanning float-writable addresses from {start}..{start+count-1} using value={value}...")
            for addr in range(start, start + count):
                try:
                    await c.raw_set_value_float(addr, value)
                except Exception:
                    continue
                print(f"OK float addr={addr}")
        elif args.cmd == "handshake":
            resp = await c.send_request(MackieCommand.CLIENT_HANDSHAKE, b"")
            body = resp.body
            print(f"handshake body len={len(body)} bytes chunks={len(body)//4}")
            print(body.hex())
        elif args.cmd == "info":
            # Firmware info
            try:
                fw = await c.request_firmware_info()
                print(f"firmware_info chunks={len(fw.body)//4} bytes={len(fw.body)}")
                # Key/value pairs, with key=2 being firmware version in DigiMixer
                if len(fw.body) >= 8:
                    pairs = []
                    for i in range(4, len(fw.body) - 3, 8):
                        key = struct.unpack_from(">I", fw.body, i)[0]
                        val = struct.unpack_from(">I", fw.body, i + 4)[0]
                        pairs.append((key, val))
                    fw_ver = next((v for (k, v) in pairs if k == 2), None)
                    if fw_ver is not None:
                        print(f"firmware_version=0x{fw_ver:08x}")
            except Exception as e:
                print(f"firmware_info error: {e}")

            # Mixer name (often general info type 3)
            for t in [3, 2, 7, 18]:
                try:
                    gi = await c.request_general_info(t)
                    data = gi.body
                    if len(data) >= 4:
                        text = data[4:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                        print(f"general_info[{t}]={text!r}")
                except Exception:
                    pass

            if args.probe_general:
                for t in range(1, 21):
                    try:
                        gi = await c.request_general_info(t)
                        data = gi.body
                        text = data[4:].split(b"\x00", 1)[0].decode("utf-8", errors="replace") if len(data) >= 4 else ""
                        print(f"probe general_info[{t}] len={len(data)} text={text!r}")
                    except Exception:
                        continue
        elif args.cmd == "names":
            msg = await c.request_channel_names(args.start, args.count)
            body = msg.body
            if len(body) < 8:
                print("no names body")
            else:
                start = struct.unpack_from(">I", body, 0)[0]
                meta = struct.unpack_from(">I", body, 4)[0]
                count = (meta >> 16) & 0xFFFF
                raw = body[8:]
                all_text = raw.decode("utf-8", errors="replace")
                parts = all_text.split("\x00")
                for i in range(min(count, len(parts))):
                    print(f"{start + i}: {parts[i]}")
        elif args.cmd == "probe-channels":
            print(f"input_map start={c.input_map_start} stride={c.input_map_stride}")
            rows = await c.probe_input_channels(int(args.channels))
            for ch, ma, fa, md, fd in rows:
                print(f"ch{ch:02d}  mute@{ma:5d} fader@{fa:5d}  read_mute={md:18s} read_fader={fd}")
        elif args.cmd == "recall-snapshot":
            await c.recall_snapshot(0, int(args.snapshot))
            print(f"OK: recall snapshot {int(args.snapshot)} (Master Fader cmd 0x07 sequence)")
        elif args.cmd == "detect_inputs":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing to run detect_inputs without --i-understand-this-writes-to-the-mixer"
                )
            channels = int(args.channels)
            start = int(args.start)
            size = int(args.size)
            offset_min = int(args.offset_min)
            offset_max = int(args.offset_max)

            # Heuristic detection:
            # - "int-type" addresses accept int 0/1 but reject float 0.33 (non-zero bits)
            # - "float-type" addresses accept float 0.33
            async def int_ok(addr: int) -> bool:
                try:
                    await c.raw_set_value_int(addr, 0)
                    return True
                except Exception:
                    return False

            async def float_ok(addr: int) -> bool:
                try:
                    await c.raw_set_value_float(addr, 0.33)
                    return True
                except Exception:
                    return False

            async def float_reject(addr: int) -> bool:
                try:
                    await c.raw_set_value_float(addr, 0.33)
                    return False
                except Exception:
                    return True

            print("ch,mute_addr,fader_addr")
            for ch in range(1, channels + 1):
                base = start + (ch - 1) * size
                addrs = list(range(base + offset_min, base + offset_max + 1))

                mute_addr = None
                fader_addr = None

                for a in addrs:
                    if await int_ok(a) and await float_reject(a):
                        mute_addr = a
                        break

                for a in addrs:
                    if await float_ok(a):
                        fader_addr = a
                        break

                print(f"{ch},{mute_addr if mute_addr is not None else ''},{fader_addr if fader_addr is not None else ''}")
    finally:
        await c.close()


if __name__ == "__main__":
    asyncio.run(main())

