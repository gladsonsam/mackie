"""Analyse a Master Fader <-> Mackie DL capture.

Unlike tools/parse_pcap_mackie.py (client->mixer only, no timestamps) this reads
BOTH directions and keeps per-frame time, which is what name tables and
step correlation need: the mixer answers name requests, so everything we are
looking for arrives mixer->client.

    python3 analyze_capture.py mackie-*.pcapng --steps steps-*.tsv

Modes (default: all of summary/steps/strings):
    --frames            dump every frame, one line each
    --cmd 0x18          restrict output to one command
    --strings           string hunt only
    --token SNAPTOKEN   extra token to hunt for (repeatable)
"""

from __future__ import annotations

import argparse
import bisect
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

MIXER_PORT = 50001

COMMANDS = {
    0x01: "KEEP_ALIVE",
    0x03: "CLIENT_HANDSHAKE",
    0x04: "FIRMWARE_INFO",
    0x06: "CHANNEL_INFO_CONTROL",
    0x07: "SHOW_SNAPSHOT",
    0x0E: "GENERAL_INFO",
    0x13: "CHANNEL_VALUES",
    0x15: "BROADCAST_CONTROL",
    0x16: "METER_LAYOUT",
    0x18: "CHANNEL_NAMES",
}
TYPES = {0: "Req", 1: "Resp", 5: "Err", 8: "Bcast"}

# Tokens the capture script asks you to type into Master Fader. Finding these
# in a frame body is what identifies the name tables.
DEFAULT_TOKENS = ["SNAPTOKEN", "MGTOKEN"]


# --------------------------------------------------------------------------- #
# pcapng
# --------------------------------------------------------------------------- #

def read_pcapng(data: bytes):
    """Yield (epoch_seconds, packet_bytes). Handles endianness and if_tsresol."""
    off = 0
    endian = "<"
    tsresol: dict[int, float] = {}
    linktypes: dict[int, int] = {}
    iface_n = 0

    while off + 12 <= len(data):
        # The SHB magic is a palindrome, so it reads the same either way.
        btype_le = struct.unpack_from("<I", data, off)[0]
        if btype_le == 0x0A0D0D0A:
            magic = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if magic == 0x1A2B3C4D else ">"
            iface_n = 0

        btype = struct.unpack_from(endian + "I", data, off)[0]
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8 : off + blen - 4]

        if btype == 0x00000001:  # IDB
            linktypes[iface_n] = struct.unpack_from(endian + "H", body, 0)[0]
            tsresol[iface_n] = _parse_tsresol(body[8:], endian)
            iface_n += 1

        elif btype == 0x00000006 and len(body) >= 20:  # EPB
            ifid, ts_hi, ts_lo, caplen = struct.unpack_from(endian + "IIII", body, 0)
            div = tsresol.get(ifid, 1e6)
            ts = ((ts_hi << 32) | ts_lo) / div
            yield ts, body[20 : 20 + caplen], linktypes.get(ifid, 1)

        off += blen


def _parse_tsresol(opts: bytes, endian: str) -> float:
    """if_tsresol (option 9): one byte, high bit set => 2**n, else 10**n."""
    i = 0
    while i + 4 <= len(opts):
        code, olen = struct.unpack_from(endian + "HH", opts, i)
        val = opts[i + 4 : i + 4 + olen]
        if code == 0:
            break
        if code == 9 and olen >= 1:
            n = val[0]
            return float(2**(n & 0x7F)) if n & 0x80 else float(10**n)
        i += 4 + ((olen + 3) // 4) * 4
    return 1e6


# --------------------------------------------------------------------------- #
# TCP
# --------------------------------------------------------------------------- #

def parse_tcp(pkt: bytes, linktype: int):
    """Return (flow, seq, payload) for any TCP packet on the mixer port."""
    if linktype == 1:  # Ethernet
        if len(pkt) < 16:
            return None
        et = struct.unpack_from("!H", pkt, 12)[0]
        ip_start = 14
        if et == 0x8100:  # VLAN tag
            if len(pkt) < 18:
                return None
            et = struct.unpack_from("!H", pkt, 16)[0]
            ip_start = 18
        if et != 0x0800:
            return None
    elif linktype == 101:  # raw IP
        ip_start = 0
    else:
        return None

    if len(pkt) < ip_start + 20 or pkt[ip_start + 9] != 6:
        return None
    ihl = (pkt[ip_start] & 0x0F) * 4
    sip = ".".join(str(b) for b in pkt[ip_start + 12 : ip_start + 16])
    dip = ".".join(str(b) for b in pkt[ip_start + 16 : ip_start + 20])

    tcp = ip_start + ihl
    if len(pkt) < tcp + 20:
        return None
    sport, dport = struct.unpack_from("!HH", pkt, tcp)
    if MIXER_PORT not in (sport, dport):
        return None
    seq = struct.unpack_from("!I", pkt, tcp + 4)[0]
    doff = (pkt[tcp + 12] >> 4) * 4
    payload = pkt[tcp + doff :]
    if not payload:
        return None
    return (sip, sport, dip, dport), seq, payload


def reassemble(packets):
    """Merge each flow in seq order, keeping an offset->timestamp index.

    Returns {flow: (blob, marks)} where marks is a sorted list of
    (offset_in_blob, timestamp) so a frame's time can be recovered after merge.
    """
    by_flow = defaultdict(list)
    for ts, pkt, linktype in packets:
        p = parse_tcp(pkt, linktype)
        if p:
            flow, seq, payload = p
            by_flow[flow].append((seq, ts, payload))

    out = {}
    for flow, segs in by_flow.items():
        segs.sort(key=lambda t: t[0])
        blob = bytearray()
        marks: list[tuple[int, float]] = []
        next_seq: int | None = None
        for seq, ts, data in segs:
            if next_seq is None:
                marks.append((len(blob), ts))
                blob.extend(data)
                next_seq = seq + len(data)
                continue
            if seq >= next_seq:
                marks.append((len(blob), ts))
                blob.extend(data)
                next_seq = seq + len(data)
            else:
                overlap = next_seq - seq          # retransmit / partial overlap
                if overlap < len(data):
                    marks.append((len(blob), ts))
                    blob.extend(data[overlap:])
                    next_seq = seq + len(data)
        out[flow] = (bytes(blob), marks)
    return out


# --------------------------------------------------------------------------- #
# Mackie framing  (see custom_components/mackie_dl/SPEC.md)
# --------------------------------------------------------------------------- #

def frame_len(buf: bytes, start: int) -> int | None:
    """Length of the frame at `start`, or None if this is not a real frame.

    Resyncing on the 0xAB sync byte alone is not safe: CHANNEL_VALUES bodies are
    dense IEEE-754 floats and contain 0xAB constantly. A false lock invents a
    huge bogus frame and swallows every real frame inside it. The header
    checksum (0xFFFF minus the sum of the first six bytes) is what makes
    resynchronisation trustworthy, so validate it before accepting a frame.
    """
    if start + 8 > len(buf) or buf[start] != 0xAB:
        return None
    if buf[start + 4] not in TYPES:
        return None
    want = struct.unpack_from(">H", buf, start + 6)[0]
    if (0xFFFF - sum(buf[start : start + 6])) & 0xFFFF != want:
        return None
    chunks = struct.unpack_from(">H", buf, start + 2)[0]
    return 8 if chunks == 0 else 8 + chunks * 4 + 4


def iter_frames(blob: bytes, marks: list[tuple[int, float]]):
    offsets = [m[0] for m in marks]
    i = 0
    while i < len(blob):
        j = blob.find(b"\xab", i)
        if j < 0:
            break
        flen = frame_len(blob, j)
        if flen is None or j + flen > len(blob):
            i = j + 1
            continue
        chunks = struct.unpack_from(">H", blob, j + 2)[0]
        body = blob[j + 8 : j + 8 + chunks * 4] if chunks else b""
        k = bisect.bisect_right(offsets, j) - 1
        ts = marks[k][1] if k >= 0 else 0.0
        yield {
            "ts": ts,
            "seq": blob[j + 1],
            "type": blob[j + 4],
            "cmd": blob[j + 5],
            "body": body,
        }
        i = j + flen


def cmd_name(c: int) -> str:
    return COMMANDS.get(c, f"UNKNOWN_0x{c:02X}")


# --------------------------------------------------------------------------- #
# strings
# --------------------------------------------------------------------------- #

def word_swap(body: bytes) -> bytes:
    """Reverse the bytes inside each 4-byte word.

    Mackie stores text as little-endian characters within each 32-bit word of an
    otherwise big-endian protocol, so 'MGZU' goes on the wire as 55 5a 47 4d.
    Undo that and the names read forwards.
    """
    out = bytearray()
    for i in range(0, len(body) - len(body) % 4, 4):
        out += body[i : i + 4][::-1]
    return bytes(out)


def extract_strings(body: bytes) -> list[tuple[str, str]]:
    """Return (encoding, text) for printable runs of 3+ chars."""
    found = []
    for label, buf in (("ascii", body), ("swapped", word_swap(body))):
        for m in re.finditer(rb"[ -~]{3,}", buf):
            found.append((label, m.group().decode("ascii")))
    for m in re.finditer(rb"(?:[ -~]\x00){3,}", body):
        found.append(("utf16le", m.group().decode("utf-16-le")))
    for m in re.finditer(rb"(?:\x00[ -~]){3,}", body):
        found.append(("utf16be", m.group().decode("utf-16-be")))
    return found


def decode_name_table(body: bytes) -> tuple[int, int, list[str]]:
    """Decode a CHANNEL_NAMES body into (start_index, count, names).

    Layout mirrors CHANNEL_VALUES: chunk 0 is the start index, chunk 1 is
    count/type, and the rest is a word-swapped stream of NUL-terminated names.
    """
    if len(body) < 8:
        return 0, 0, []
    start = struct.unpack_from(">I", body, 0)[0]
    meta = struct.unpack_from(">I", body, 4)[0]
    count = (meta >> 16) & 0xFFFF
    raw = word_swap(body[8:])
    names = [n.decode("ascii", "replace") for n in raw.split(b"\x00")]
    return start, count, names


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #

def load_steps(path: Path) -> list[tuple[float, int, str]]:
    steps = []
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 3:
            steps.append((int(parts[0]) / 1000.0, int(parts[1]), parts[2]))
    return sorted(steps)


def step_for(ts: float, steps) -> tuple[int, str]:
    """Which step was in progress at ts (i.e. the step logged just after it)."""
    for i, (t, n, label) in enumerate(steps):
        if ts < t:
            return n, label
    return 999, "after end"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--steps", type=Path)
    ap.add_argument("--frames", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--cmd", type=lambda s: int(s, 0))
    ap.add_argument("--token", action="append", default=[])
    ap.add_argument("--names", action="store_true", help="decode CHANNEL_NAMES tables")
    args = ap.parse_args()

    tokens = DEFAULT_TOKENS + args.token
    steps = load_steps(args.steps) if args.steps else []

    packets = list(read_pcapng(args.pcap.read_bytes()))
    print(f"packets: {len(packets)}")
    if not packets:
        print("nothing captured - wrong interface, or the filter matched nothing")
        return 1

    flows = reassemble(packets)
    t0 = min(p[0] for p in packets)

    frames = []
    for flow, (blob, marks) in flows.items():
        sip, sport, dip, dport = flow
        direction = "C>M" if dport == MIXER_PORT else "M>C"
        print(f"  flow {sip}:{sport} -> {dip}:{dport}  [{direction}]  {len(blob)} bytes")
        for f in iter_frames(blob, marks):
            f["dir"] = direction
            frames.append(f)
    frames.sort(key=lambda f: f["ts"])
    print(f"mackie frames: {len(frames)}\n")

    show_all = not (args.frames or args.strings or args.names)

    # --- name tables ---------------------------------------------------------
    if args.names:
        print("=== CHANNEL_NAMES (0x18) decoded ===")
        for f in frames:
            if f["cmd"] != 0x18 or not f["body"]:
                continue
            start, count, names = decode_name_table(f["body"])
            print(
                f"t+{f['ts'] - t0:7.2f}s {f['dir']} {TYPES.get(f['type'], f['type']):5} "
                f"start={start} count={count} len={len(f['body'])}"
            )
            # Empty slots are real slots: a name-less channel is just a NUL, so
            # filtering blanks before numbering shifts every index after it.
            for i, n in enumerate(names):
                if n:
                    print(f"      [{start + i:>3}] {n!r}")
        return 0

    # --- command inventory ---------------------------------------------------
    if show_all or args.frames:
        inv = defaultdict(lambda: defaultdict(int))
        for f in frames:
            inv[f["cmd"]][(f["dir"], f["type"])] += 1
        print("=== command inventory ===")
        for c in sorted(inv):
            name = cmd_name(c)
            flag = "   <-- UNKNOWN, investigate" if c not in COMMANDS else ""
            parts = ", ".join(
                f"{d}/{TYPES.get(t, t)}={n}" for (d, t), n in sorted(inv[c].items())
            )
            print(f"  0x{c:02X} {name:22} {parts}{flag}")
        print()

    # --- token hunt ----------------------------------------------------------
    print("=== token hunt ===")
    hits = 0
    for f in frames:
        strs = extract_strings(f["body"])
        for enc, text in strs:
            if any(tok in text for tok in tokens):
                hits += 1
                sn, _ = step_for(f["ts"], steps) if steps else (0, "")
                print(
                    f"  t+{f['ts'] - t0:7.2f}s step={sn:<3} {f['dir']} "
                    f"0x{f['cmd']:02X} {cmd_name(f['cmd']):20} {TYPES.get(f['type'], f['type']):5} "
                    f"[{enc}] {text!r}"
                )
                print(f"      body ({len(f['body'])}B): {f['body'][:96].hex()}")
    if not hits:
        print("  no tokens found - did the renames actually save?")
        print(f"  (looked for: {', '.join(tokens)})")
    print()

    # --- all strings ---------------------------------------------------------
    if args.strings or show_all:
        print("=== name-like strings, by command ===")
        # CHANNEL_VALUES broadcasts are dense float data; decoding them as text
        # produces pages of noise ('Bp', '/ZBp' - those are IEEE-754 exponent
        # bytes, not names). Skip them unless explicitly asked, and require a
        # real run of letters so only plausible names survive.
        by_cmd = defaultdict(set)
        for f in frames:
            if f["cmd"] == 0x13 and not args.strings:
                continue
            for enc, text in extract_strings(f["body"]):
                if len(text.strip()) >= 4 and re.search(r"[A-Za-z]{3}", text):
                    by_cmd[(f["cmd"], f["dir"])].add((enc, text))
        if not by_cmd:
            print("  (none - pass --strings to include CHANNEL_VALUES noise)")
        for (c, d), vals in sorted(by_cmd.items()):
            print(f"  0x{c:02X} {cmd_name(c)} [{d}]")
            for enc, text in sorted(vals)[:40]:
                print(f"      [{enc}] {text!r}")
        print()

    # --- per-step breakdown --------------------------------------------------
    if steps and show_all:
        print("=== per-step activity (excluding keepalives) ===")
        buckets = defaultdict(lambda: defaultdict(int))
        singles = defaultdict(list)
        for f in frames:
            if f["cmd"] == 0x01:
                continue
            n, _ = step_for(f["ts"], steps)
            buckets[n][(f["dir"], f["cmd"])] += 1
            if f["cmd"] == 0x13 and f["dir"] == "C>M":
                s = _single_write(f["body"])
                if s:
                    singles[n].append(s)
        for t, n, label in steps:
            if n in (0, 999):
                continue
            print(f"  step {n}: {label}")
            for (d, c), cnt in sorted(buckets[n].items()):
                print(f"      {d} 0x{c:02X} {cmd_name(c):22} x{cnt}")
            for s in singles[n][:20]:
                print(f"      WRITE {s}")
        print()

    # --- raw frame dump ------------------------------------------------------
    if args.frames:
        print("=== frames ===")
        for f in frames:
            if args.cmd is not None and f["cmd"] != args.cmd:
                continue
            if args.cmd is None and f["cmd"] == 0x01:
                continue
            sn, _ = step_for(f["ts"], steps) if steps else (0, "")
            print(
                f"t+{f['ts'] - t0:7.2f}s step={sn:<3} {f['dir']} seq={f['seq']:<3} "
                f"{TYPES.get(f['type'], f['type']):5} 0x{f['cmd']:02X} {cmd_name(f['cmd']):22} "
                f"len={len(f['body']):<5} {f['body'][:64].hex()}"
            )

    return 0


def _single_write(body: bytes) -> str | None:
    """Format a CHANNEL_VALUES write of exactly one value: address + both readings."""
    if len(body) < 12:
        return None
    addr = struct.unpack_from(">I", body, 0)[0]
    meta = struct.unpack_from(">I", body, 4)[0]
    if ((meta >> 16) & 0xFFFF) != 1:
        return None
    raw = struct.unpack_from(">I", body, 8)[0]
    as_int = struct.unpack(">i", struct.pack(">I", raw))[0]
    as_float = struct.unpack(">f", struct.pack(">I", raw))[0]
    return f"addr={addr:<6} 0x{raw:08x} int={as_int} float={as_float:.5g}"


if __name__ == "__main__":
    raise SystemExit(main())
