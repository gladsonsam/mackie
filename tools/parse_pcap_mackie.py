"""Extract Mackie frames from pcapng (EPB); TCP-reassemble client->tcp/50001."""
from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path


def iter_epb_payloads(pcapng: bytes) -> list[bytes]:
    off = 0
    packets: list[bytes] = []
    while off + 8 <= len(pcapng):
        block_type, block_len = struct.unpack_from("<II", pcapng, off)
        if block_len < 12 or off + block_len > len(pcapng):
            break
        blk = pcapng[off : off + block_len]
        if block_type == 6 and len(blk) >= 28:
            caplen = struct.unpack_from("<I", blk, 20)[0]
            packets.append(blk[28 : 28 + caplen])
        off += block_len
    return packets


def _ethertype_and_payload_start(pkt: bytes) -> tuple[int, int] | None:
    if len(pkt) < 16:
        return None
    et = struct.unpack_from("!H", pkt, 12)[0]
    off = 14
    if et == 0x8100:
        if len(pkt) < 18:
            return None
        et = struct.unpack_from("!H", pkt, 16)[0]
        off = 18
    return et, off


def parse_tcp_payload_to_port(pkt: bytes, dst_port_wanted: int):
    er = _ethertype_and_payload_start(pkt)
    if er is None:
        return None
    et, ip_start = er
    if et != 0x0800 or len(pkt) < ip_start + 20:
        return None
    ihl = (pkt[ip_start] & 0x0F) * 4
    if pkt[ip_start + 9] != 6:
        return None
    sip = bytes(pkt[ip_start + 12 : ip_start + 16])
    dip = bytes(pkt[ip_start + 16 : ip_start + 20])
    tcp_start = ip_start + ihl
    if len(pkt) < tcp_start + 20:
        return None
    sport, dst_port = struct.unpack_from("!HH", pkt, tcp_start)
    if dst_port != dst_port_wanted:
        return None
    seq = struct.unpack_from("!I", pkt, tcp_start + 4)[0]
    doff = (pkt[tcp_start + 12] >> 4) * 4
    pay_start = tcp_start + doff
    if pay_start > len(pkt):
        return None
    return (sip, sport, dip, dst_port), seq, pkt[pay_start:]


def reassemble_tcp_streams(pkts: list[bytes], *, dst_port: int = 50001) -> dict:
    by_flow: dict = defaultdict(list)
    for pkt in pkts:
        p = parse_tcp_payload_to_port(pkt, dst_port)
        if not p or not p[2]:
            continue
        flow, seq, payload = p
        by_flow[flow].append((seq, payload))

    out: dict = {}
    for flow, segs in by_flow.items():
        segs.sort(key=lambda t: t[0])
        merged = bytearray()
        next_seq: int | None = None
        for seq, data in segs:
            if next_seq is None:
                merged.extend(data)
                next_seq = seq + len(data)
                continue
            if seq >= next_seq:
                merged.extend(data)
                next_seq = seq + len(data)
            else:
                overlap = next_seq - seq
                if overlap < len(data):
                    merged.extend(data[overlap:])
                    next_seq = seq + len(data)
        out[flow] = bytes(merged)
    return out


def mackie_frame_length_from_header(buf: bytes, start: int) -> int | None:
    if start + 8 > len(buf) or buf[start] != 0xAB:
        return None
    chunk_count = struct.unpack_from(">H", buf, start + 2)[0]
    if chunk_count == 0:
        return 8
    return 8 + chunk_count * 4 + 4


def parse_mackie_frame(buf: bytes) -> dict | None:
    if len(buf) < 8 or buf[0] != 0xAB:
        return None
    chunk_count = struct.unpack_from(">H", buf, 2)[0]
    msg_type, cmd = buf[4], buf[5]
    rest = buf[8:]
    if chunk_count == 0:
        return {"seq": buf[1], "chunks": chunk_count, "type": msg_type, "cmd": cmd, "body": b""}
    body_len = chunk_count * 4
    if len(rest) < body_len + 4:
        return None
    return {
        "seq": buf[1],
        "chunks": chunk_count,
        "type": msg_type,
        "cmd": cmd,
        "body": rest[:body_len],
    }


def iter_mackie_frames(buf: bytes):
    i = 0
    while i < len(buf):
        j = buf.find(b"\xab", i)
        if j < 0:
            break
        flen = mackie_frame_length_from_header(buf, j)
        if flen is None or j + flen > len(buf):
            i = j + 1
            continue
        sub = buf[j : j + flen]
        parsed = parse_mackie_frame(sub)
        if parsed:
            yield j, parsed
        i = j + flen


def _collect_single(body: bytes, singles: dict[int, list[str]]) -> None:
    if len(body) < 12:
        return
    start = struct.unpack_from(">I", body, 0)[0]
    meta = struct.unpack_from(">I", body, 4)[0]
    cnt = (meta >> 16) & 0xFFFF
    if cnt != 1:
        return
    raw = struct.unpack_from(">I", body, 8)[0]
    sint = struct.unpack(">i", struct.pack(">I", raw))[0]
    fd = struct.unpack(">f", struct.pack(">I", raw))[0]
    singles.setdefault(int(start), []).append(f"0x{raw:08x} int={sint} f={fd:.5g}")


def main() -> int:
    pcap_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[1] / "channel2 mute and unmute.pcapng"
    )
    pkts = iter_epb_payloads(pcap_path.read_bytes())
    print("EPB packets:", len(pkts))

    streams = reassemble_tcp_streams(pkts, dst_port=50001)
    print("TCP flows to :50001:", len(streams))

    cmd_channel_values = 0x13
    cmd_show_snapshot = 0x07
    singles: dict[int, list[str]] = {}
    n_channel_values = 0

    for flow, blob in streams.items():
        sip = ".".join(str(b) for b in flow[0])
        print(f"  flow {sip}:{flow[1]} -> :50001  bytes={len(blob)}")
        for _, parsed in iter_mackie_frames(blob):
            if parsed["cmd"] == cmd_show_snapshot:
                b, mt = parsed["body"], parsed["type"]
                if len(b) >= 8:
                    u1, u2 = struct.unpack_from(">II", b, 0)
                    print(f"    SHOW_SNAPSHOT msg_type={mt} u32={u1},{u2}")
                elif len(b) >= 4:
                    (u1,) = struct.unpack_from(">I", b, 0)
                    print(f"    SHOW_SNAPSHOT msg_type={mt} u32={u1}")
            elif parsed["cmd"] == cmd_channel_values:
                n_channel_values += 1
                _collect_single(parsed["body"], singles)

    print("channel_values frames (reassembled):", n_channel_values)
    print("--- single-value CHANNEL_VALUES (count=1) ---")
    for addr in sorted(singles):
        u = sorted(set(singles[addr]))
        print(f"addr {addr}: {len(singles[addr])} writes, {u[:15]}{'...' if len(u) > 15 else ''}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
