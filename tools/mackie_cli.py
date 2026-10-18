import os
import sys
import argparse
import asyncio
import importlib.util
from types import ModuleType
import re
import time
import struct

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_CLIENT_PATH = os.path.join(_REPO_ROOT, "custom_components", "mackie_dl", "client.py")
if not os.path.isfile(_CLIENT_PATH):
    # Flat deployment: client.py sits next to this script instead of in
    # a repo checkout.
    _CLIENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py")
_spec = importlib.util.spec_from_file_location("mackie_dl_client", _CLIENT_PATH)
assert _spec and _spec.loader
_mod: ModuleType = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[assignment]
MackieClient = _mod.MackieClient
MackieCommand = _mod.MackieCommand


def _parse_name_slot(target: str) -> int:
    """Resolve a rename target to a CHANNEL_NAMES table slot (SPEC.md "Names").

    Accepts a bare slot number or an alias: ch<N>/input<N> -> 1-32, aux<N> ->
    50-57, sub<N> -> 58-63, mg<N> -> 64-69 (via mute_group_name_slot), vca<N> ->
    70-75. Raises ValueError for anything else, including out-of-range aliases.
    """
    t = str(target).strip().lower()
    if re.fullmatch(r"\d+", t):
        slot = int(t)
        if slot < 1:
            raise ValueError("slot must be >= 1")
        return slot
    m = re.fullmatch(r"(ch|input|aux|sub|mg|vca)(\d+)", t)
    if not m:
        raise ValueError(f"unknown channel-or-slot {target!r}")
    kind, n = m.group(1), int(m.group(2))
    if kind in ("ch", "input"):
        if not 1 <= n <= 32:
            raise ValueError("input channel must be 1..32")
        return n
    if kind == "aux":
        if not 1 <= n <= 8:
            raise ValueError("aux output must be 1..8")
        return 49 + n
    if kind == "sub":
        if not 1 <= n <= 6:
            raise ValueError("subgroup must be 1..6")
        return 57 + n
    if kind == "mg":
        return _mod.mute_group_name_slot(n)  # validates 1..6
    if not 1 <= n <= 6:
        raise ValueError("VCA must be 1..6")
    return 69 + n


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

    rename = sub.add_parser(
        "rename",
        help="Write one CHANNEL_NAMES (0x18) slot. Target: slot number, or "
        "ch<N>, aux<N> (output 50-57), sub<N> (58-63), mg<N> (64-69), vca<N> (70-75).",
    )
    rename.add_argument("target", help="Channel-or-slot: e.g. 3, ch3, aux1, sub2, mg1, vca1.")
    rename.add_argument("name", help="New name (ASCII, max 63 chars).")

    meters = sub.add_parser(
        "meters",
        help="Enable meter reports briefly (METER_LAYOUT + BROADCAST_CONTROL) "
        "and print every meter value that arrives.",
    )
    meters.add_argument("--seconds", type=float, default=5.0)

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

    mg = sub.add_parser("mutegroup", help="Set mute group master (type-2 address space).")
    mg.add_argument("group", type=int, help="Mute group 1-6.")
    mg.add_argument("state", choices=["on", "off"], help="on=mute, off=unmute.")

    auxmute = sub.add_parser(
        "auxmute",
        help="Set an input's aux send mute (per-input send block; the aux "
        "output master strips are unmapped, so nothing writes there).",
    )
    auxmute.add_argument("channel", type=int)
    auxmute.add_argument("aux", type=int, help="Aux send 1-8 (DL16S: 1-6).")
    auxmute.add_argument("state", choices=["on", "off"])

    auxfader = sub.add_parser(
        "auxfader",
        help="Set an input's aux send level in dB (-120..+10), same grid as auxmute.",
    )
    auxfader.add_argument("channel", type=int)
    auxfader.add_argument("aux", type=int, help="Aux send 1-8 (DL16S: 1-6).")
    auxfader.add_argument("db", type=float)

    submute = sub.add_parser(
        "subgroupmute",
        help="Set a subgroup master mute (DL32S map only - use --model dl32s; "
        "DL16S/DL32R maps carry no subgroup block).",
    )
    submute.add_argument("group", type=int, help="Subgroup 1-6.")
    submute.add_argument("state", choices=["on", "off"])

    subgroupfader = sub.add_parser(
        "subgroupfader",
        help="Set a subgroup master fader in dB (DL32S map only - use --model dl32s).",
    )
    subgroupfader.add_argument("group", type=int, help="Subgroup 1-6.")
    subgroupfader.add_argument("db", type=float)

    mainmute = sub.add_parser("mainmute", help="Set main master mute (DL32S only).")
    mainmute.add_argument("state", choices=["on", "off"])
    mainfader = sub.add_parser("mainfader", help="Set main master fader in dB (DL32S only).")
    mainfader.add_argument("db", type=float)
    auxmmute = sub.add_parser("auxmastermute", help="Set an aux master mute (DL32S only).")
    auxmmute.add_argument("aux", type=int, help="Aux 1-8.")
    auxmmute.add_argument("state", choices=["on", "off"])
    auxmfader = sub.add_parser("auxmasterfader", help="Set an aux master fader in dB (DL32S only).")
    auxmfader.add_argument("aux", type=int, help="Aux 1-8.")
    auxmfader.add_argument("db", type=float)

    auxpan = sub.add_parser("auxpan", help="Set an input's aux send pan (-1..+1).")
    auxpan.add_argument("channel", type=int)
    auxpan.add_argument("aux", type=int, help="Aux send 1-8 (DL16S: 1-6).")
    auxpan.add_argument("pan", type=float)

    snap_save = sub.add_parser("snapshot-save", help="Save show snapshot with name (0x07 op 5).")
    snap_save.add_argument("slot", type=int, help="Snapshot index (1-based).")
    snap_save.add_argument("name", help="Snapshot name.")

    snap_list = sub.add_parser("snapshot-list", help="Download Show.zip and list snapshot names.")

    dl_show = sub.add_parser("show-download", help="Download Show.zip from the mixer.")
    dl_show.add_argument("--out", default="Show.zip")

    ul_show = sub.add_parser("show-upload", help="Upload a show archive (POST FILE sequence, experimental).")
    ul_show.add_argument("file", help="Local .zip to upload as Show.zip.")
    ul_show.add_argument("--file-type", type=int, default=4)

    set_crc = sub.add_parser("set-file-crc", help="SET FILE CRC commit step (0x13 write, experimental).")
    set_crc.add_argument("address", type=int)
    set_crc.add_argument("crc", type=lambda s: int(s, 0))

    proc_files = sub.add_parser("process-files", help="Ask the mixer to process uploaded files (0x06 op 10).")

    set_multi = sub.add_parser(
        "set-multi",
        help="Write several raw u32 addresses (one single write each; the "
        "app's pairs layout is misparsed by DL32S firmware).",
    )
    set_multi.add_argument("pairs", nargs="+", help="ADDR:U32 items, U32 parsed as int(x, 0).")

    snap_del = sub.add_parser("snapshot-delete", help="Delete a snapshot slot (0x07 op 3).")
    snap_del.add_argument("slot", type=int, help="Snapshot index (1-based).")

    reboot = sub.add_parser("reboot", help="Reboot the mixer (DANGEROUS: drops audio).")
    reboot.add_argument("--mode", type=int, default=1, choices=[1, 2],
                        help="1 = normal reboot, 2 = firmware updater.")

    disc = sub.add_parser("disconnect-notice", help="Tell the mixer this client is leaving.")

    trstat = sub.add_parser("transport-status", help="Ask for transport status (0x0E).")
    trstat.add_argument("kind", nargs="?", default="transport",
                        choices=["transport", "multitrack", "music"])

    showinfo = sub.add_parser("show-info", help="Ask for show info (FILE_INFO [5]).")

    showok = sub.add_parser("show-ok", help="Send SHOW OK (0x07 [10]).")

    showcrc = sub.add_parser("show-crc", help="Ask for a show/file CRC (0x12, experimental).")
    showcrc.add_argument("pid", type=lambda s: int(s, 0))

    setshowp = sub.add_parser("set-show-parameter", help="Write a show parameter (0x13, experimental).")
    setshowp.add_argument("pid", type=lambda s: int(s, 0))
    setshowp.add_argument("value", type=lambda s: int(s, 0))

    setshown = sub.add_parser("set-show-name", help="Set the show name (0x18, experimental).")
    setshown.add_argument("pid", type=lambda s: int(s, 0))
    setshown.add_argument("name")

    devname = sub.add_parser("device-name", help="Get/set the mixer device name.")
    devname.add_argument("--set", default=None, help="New name (writes to the mixer).")

    devip = sub.add_parser("ip-address", help="Read the mixer IPv4 address.")
    lockstat = sub.add_parser("lock-status", help="Read the show-lock word.")
    staticip = sub.add_parser("static-ip", help="Read the static-IP config.")
    subdev = sub.add_parser("subdevice-name", help="Read the option-card subdevice name.")
    maxwords = sub.add_parser("max-words", help="Read max message size in words.")
    netcfg = sub.add_parser("network-config", help="Read the 65-word NetworkInfo struct.")
    survey = sub.add_parser("site-survey", help="Run a Wi-Fi site survey.")

    setstatic = sub.add_parser("set-static-ip", help="Set static IP config (DANGEROUS: can strand the mixer).")
    setstatic.add_argument("address")
    setstatic.add_argument("mask")
    setstatic.add_argument("gateway")
    setstatic.add_argument("--dhcp", action="store_true", help="Write with static flag off.")

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
        elif args.cmd == "meters":
            start = time.monotonic()

            def _on_meter(addr: int, raw_u32: int) -> None:
                elapsed = time.monotonic() - start
                f = struct.unpack(">f", struct.pack(">I", int(raw_u32) & 0xFFFFFFFF))[0]
                print(
                    f"{elapsed:7.3f}s meter addr={addr:5d} "
                    f"u32=0x{int(raw_u32) & 0xFFFFFFFF:08x} float={f:.4g}"
                )

            unsub = c.subscribe_all_meters(_on_meter)
            try:
                # METER_LAYOUT + BROADCAST_CONTROL turn the periodic reports on
                # (connect() does it once already; sent again so this command
                # works standalone). Reports stop when the client disconnects.
                await c.enable_meter_reports()
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
            # The mixer pushes the whole name table at connect and ignores
            # explicit read requests (empty body, like CHANNEL_VALUES reads),
            # so print the pushed cache after it settles.
            await asyncio.sleep(45.0)
            for slot in range(int(args.start), int(args.start) + int(args.count)):
                name = c.get_name(slot)
                if name:
                    print(f"{slot}: {name}")
        elif args.cmd == "rename":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing rename without --i-understand-this-writes-to-the-mixer"
                )
            slot = _parse_name_slot(args.target)
            await c.set_channel_name(slot, args.name)
            print(f"OK: renamed slot {slot} -> {args.name!r}")
        elif args.cmd == "probe-channels":
            print(f"input_map start={c.input_map_start} stride={c.input_map_stride}")
            rows = await c.probe_input_channels(int(args.channels))
            for ch, ma, fa, md, fd in rows:
                print(f"ch{ch:02d}  mute@{ma:5d} fader@{fa:5d}  read_mute={md:18s} read_fader={fd}")
        elif args.cmd == "recall-snapshot":
            await c.recall_snapshot(0, int(args.snapshot))
            print(f"OK: recall snapshot {int(args.snapshot)} (Master Fader cmd 0x07 sequence)")
        elif args.cmd == "mutegroup":
            await c.set_mute_group(int(args.group), args.state == "on")
            print(f"OK: mute group {int(args.group)} -> {args.state}")
        elif args.cmd == "auxmute":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing auxmute without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_aux_mute(int(args.channel), int(args.aux), args.state == "on")
            print(f"OK: input {args.channel} aux send {args.aux} mute -> {args.state}")
        elif args.cmd == "auxfader":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing auxfader without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_aux_fader_db(int(args.channel), int(args.aux), float(args.db))
            print(f"OK: input {args.channel} aux send {args.aux} level -> {args.db} dB")
        elif args.cmd == "subgroupmute":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing subgroupmute without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_subgroup_mute(int(args.group), args.state == "on")
            print(f"OK: subgroup {args.group} master mute -> {args.state}")
        elif args.cmd == "subgroupfader":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing subgroupfader without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_subgroup_fader_db(int(args.group), float(args.db))
            print(f"OK: subgroup {args.group} master fader -> {args.db} dB")
        elif args.cmd in ("mainmute", "mainfader", "auxmastermute", "auxmasterfader"):
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    f"Refusing {args.cmd} without --i-understand-this-writes-to-the-mixer"
                )
            if args.cmd == "mainmute":
                await c.set_main_mute(args.state == "on")
                print(f"OK: main master mute -> {args.state}")
            elif args.cmd == "mainfader":
                await c.set_main_fader_db(float(args.db))
                print(f"OK: main master fader -> {float(args.db)} dB")
            elif args.cmd == "auxmastermute":
                await c.set_auxmaster_mute(int(args.aux), args.state == "on")
                print(f"OK: aux {int(args.aux)} master mute -> {args.state}")
            else:
                await c.set_auxmaster_fader_db(int(args.aux), float(args.db))
                print(f"OK: aux {int(args.aux)} master fader -> {float(args.db)} dB")
        elif args.cmd == "auxpan":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing auxpan without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_aux_pan(int(args.channel), int(args.aux), float(args.pan))
            print(f"OK: input {args.channel} aux send {args.aux} pan -> {args.pan}")
        elif args.cmd == "snapshot-save":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing snapshot-save without --i-understand-this-writes-to-the-mixer"
                )
            await c.save_snapshot(int(args.slot), args.name)
            print(f"OK: saved snapshot {int(args.slot)} as {args.name!r}")
        elif args.cmd == "snapshot-list":
            names = await c.refresh_snapshot_names()
            for num in sorted(names):
                print(f"{num}: {names[num]}")
        elif args.cmd == "show-download":
            data = await c.download_file("Show.zip")
            with open(args.out, "wb") as f:
                f.write(data)
            print(f"OK: Show.zip bytes={len(data)} -> {args.out}")
        elif args.cmd == "show-upload":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing show-upload without --i-understand-this-writes-to-the-mixer"
                )
            with open(args.file, "rb") as f:
                data = f.read()
            await c.upload_file("Show.zip", data, file_type=int(args.file_type))
            print(f"OK: uploaded {len(data)} bytes as Show.zip (then close; CRC/process steps are separate)")
        elif args.cmd == "set-file-crc":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing set-file-crc without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_file_crc(int(args.address), int(args.crc))
            print(f"OK: set-file-crc addr={int(args.address)} crc=0x{int(args.crc) & 0xFFFFFFFF:08x}")
        elif args.cmd == "process-files":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing process-files without --i-understand-this-writes-to-the-mixer"
                )
            await c.process_files()
            print("OK: process-files sent")
        elif args.cmd == "set-multi":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing set-multi without --i-understand-this-writes-to-the-mixer"
                )
            values = {}
            for item in args.pairs:
                addr_s, val_s = item.split(":", 1)
                values[int(addr_s, 0)] = int(val_s, 0)
            await c.set_values(values)
            print(f"OK: set {len(values)} addresses (pairs format)")
        elif args.cmd == "snapshot-delete":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing snapshot-delete without --i-understand-this-writes-to-the-mixer"
                )
            await c.delete_snapshot(int(args.slot))
            print(f"OK: deleted snapshot {int(args.slot)}")
        elif args.cmd == "reboot":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing reboot without --i-understand-this-writes-to-the-mixer"
                )
            await c.reboot(int(args.mode))
            print(f"OK: reboot mode {int(args.mode)} sent (mixer is going down)")
        elif args.cmd == "disconnect-notice":
            await c.disconnect_notice()
            print("OK: disconnect notice sent")
        elif args.cmd == "transport-status":
            msg = await c.get_transport_status(args.kind)
            print(f"transport-status[{args.kind}] words={len(msg.body)//4} body={msg.body.hex()}")
        elif args.cmd == "show-info":
            msg = await c.get_show_info()
            print(f"show-info words={len(msg.body)//4} body={msg.body.hex()}")
        elif args.cmd == "show-ok":
            await c.show_ok()
            print("OK: SHOW OK sent")
        elif args.cmd == "show-crc":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing show-crc without --i-understand-this-writes-to-the-mixer"
                )
            msg = await c.get_show_crc(int(args.pid))
            print(f"show-crc words={len(msg.body)//4} body={msg.body.hex()}")
        elif args.cmd == "set-show-parameter":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing set-show-parameter without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_show_parameter(int(args.pid), int(args.value))
            print(f"OK: set-show-parameter pid={int(args.pid)} value={int(args.value)}")
        elif args.cmd == "set-show-name":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing set-show-name without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_show_name(int(args.pid), args.name)
            print(f"OK: set-show-name pid={int(args.pid)} name={args.name!r}")
        elif args.cmd == "device-name":
            if args.set is None:
                print(await c.get_device_name())
            else:
                if not args.i_understand_this_writes_to_the_mixer:
                    raise SystemExit(
                        "Refusing device-name --set without --i-understand-this-writes-to-the-mixer"
                    )
                await c.set_device_name(args.set)
                print(f"OK: device name -> {args.set!r}")
        elif args.cmd == "ip-address":
            print(await c.get_ip_address())
        elif args.cmd == "lock-status":
            print(await c.get_lock_status())
        elif args.cmd == "static-ip":
            cfg = await c.get_static_ip_config()
            print(f"static={cfg['static']} address={cfg['address']} mask={cfg['mask']} gateway={cfg['gateway']}")
        elif args.cmd == "subdevice-name":
            print(await c.get_subdevice_name())
        elif args.cmd == "max-words":
            print(await c.get_max_message_words())
        elif args.cmd == "network-config":
            words = await c.get_network_config()
            print(f"words={len(words)}")
            print(" ".join(f"{w:08x}" for w in words))
        elif args.cmd == "site-survey":
            entries = await c.site_survey()
            print(f"entries={len(entries)}")
            for e in entries:
                print(" ".join(f"{w:08x}" for w in e))
        elif args.cmd == "set-static-ip":
            if not args.i_understand_this_writes_to_the_mixer:
                raise SystemExit(
                    "Refusing set-static-ip without --i-understand-this-writes-to-the-mixer"
                )
            await c.set_static_ip_config(
                not args.dhcp, args.address, args.mask, args.gateway
            )
            print(f"OK: static-ip static={not args.dhcp} {args.address}/{args.mask} gw={args.gateway}")
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

