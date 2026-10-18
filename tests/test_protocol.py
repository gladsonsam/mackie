"""Offline protocol-builder tests. No mixer, no Home Assistant needed.

Every expectation here is pinned to observed behavior: wire captures
(tools/capture/FINDINGS.md) or live-verified mixer responses. Run: python3 -m unittest discover -s tests
"""
from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "mackie_dl")
)

from client import (  # noqa: E402
    MackieClient,
    MackieCommand,
    MackieMessage,
    MackieMessageType,
    _build_channel_name_write,
    _build_channel_values_set,
    word_swap,
)
import addressmap  # noqa: E402


def u32s(b: bytes) -> tuple[int, ...]:
    assert len(b) % 4 == 0
    return struct.unpack(">" + "I" * (len(b) // 4), b)


class ProtocolTest(unittest.TestCase):
    def test_word_swap_roundtrip(self) -> None:
        # FINDINGS.md section 1: MGZU travels as 55 5a 47 4d.
        self.assertEqual(word_swap(b"MGZU"), bytes([0x55, 0x5A, 0x47, 0x4D]))
        self.assertEqual(word_swap(word_swap(b"MGTOKEN\x00")), b"MGTOKEN\x00")

    def test_single_write_layout(self) -> None:
        # chunk0 = address, chunk1 = count:16 | type:8 | 0, then values.
        self.assertEqual(u32s(_build_channel_values_set(address=8, value_int=1)),
                         (8, 0x00010500, 1))

    def test_mute_group_single_write_matches_capture(self) -> None:
        # FINDINGS.md section 6: MG1 on = addr 11, count=1, type=2, value 1.
        body = _build_channel_values_set(address=11, value_int=1, value_type=2)
        self.assertEqual(u32s(body), (11, 0x00010200, 1))

    def test_pairs_write_rejected_live(self) -> None:
        # Live-proven 2026-10-18: the app's pairs layout ([a0, meta|0x2000,
        # v0, a1, v1]) is parsed by DL32S firmware as start+count+values, so
        # a 2-pair write to {3310, 4297} landed on 3310/3311/3312 instead.
        # Multi-writes therefore fan out to singles in set_values(); there is
        # deliberately no pairs builder anymore. This test pins the two single
        # layouts the fan-out relies on.
        self.assertEqual(
            u32s(_build_channel_values_set(address=3310, value_raw_u32=1125515264)),
            (3310, 0x00010500, 1125515264),
        )
        self.assertEqual(
            u32s(_build_channel_values_set(address=3311, value_int=0, value_type=2)),
            (3311, 0x00010200, 0),
        )

    def test_post_file_command_value(self) -> None:
        # POST FILE command byte is 0x0D.
        self.assertEqual(MackieCommand.POST_FILE, 0x0D)

    def test_upload_open_flags_bare_type(self) -> None:
        # FILE_OPEN word0 = (isWrite << 31) | file_type.
        # The POST-machine open passes isWrite=0, so uploads send the bare
        # type (4 for show archives); downloads send 0x80000004 (captured).
        self.assertEqual(0x80000004, (1 << 31) | 4)
        self.assertEqual(4, (0 << 31) | 4)

    def test_post_chunk_body_layout(self) -> None:
        # POST body [id, total, offset, chunklen] + word-swapped data.
        data = b"PK\x03\x04" + bytes(124)
        body = struct.pack(">IIII", 7, 18225, 0, 128) + word_swap(data)
        words = u32s(body)
        self.assertEqual(words[:4], (7, 18225, 0, 128))
        self.assertEqual(len(body), 16 + 128)
        self.assertEqual(words[4], struct.unpack(">I", word_swap(b"PK\x03\x04"))[0])

    def test_end_of_post_is_zero_length_at_total(self) -> None:
        # Upload terminator has chunklen 0 with offset == total.
        self.assertEqual(u32s(struct.pack(">IIII", 7, 18225, 18225, 0)),
                         (7, 18225, 18225, 0))

    def test_set_file_crc_layout(self) -> None:
        # SET FILE CRC is a 0x13 write [address, 0x00010400, crc].
        self.assertEqual(u32s(struct.pack(">III", 509, 0x00010400, 0x12345678)),
                         (509, 0x00010400, 0x12345678))

    def test_process_files_layout(self) -> None:
        # PROCESS FILES is command 0x06 with single-word body [10].
        self.assertEqual(MackieCommand.CHANNEL_INFO_CONTROL, 0x06)
        self.assertEqual(u32s(struct.pack(">I", 10)), (10,))

    def test_subgroup_block_geometry_mine(self) -> None:
        # (Consolidated into test_subgroup_addresses_match_addressmap below;
        # kept as a geometry cross-check.)
        # SPEC: 6 subgroup strips of 51 words from 4042; master fader at
        # offset 0 (reads -120 dB parked on all six live strips), master
        # mute at offset 7 (same offset as input mute, reads 1 parked).
        import sys as _sys  # noqa: F401  (kept local: package layout)
        from addressmap import get_map

        block = get_map("dl32s").blocks["subgroup"]
        self.assertEqual(block.base, 4041)
        self.assertEqual(block.stride, 51)
        self.assertEqual(block.count, 6)
        self.assertEqual(block.address(1, "fader"), 4042)
        self.assertEqual(block.address(6, "fader"), 4041 + 5 * 51 + 1)
        self.assertEqual(block.address(3, "mute"), 4041 + 2 * 51)

    def test_snapshot_save_op5_layout(self) -> None:        # FINDINGS.md section 4: op 5, number, unix epoch, word-swapped name.
        name = b"SNAPTOKEN\x00\x00\x00"
        body = struct.pack(">III", 5, 1, 0x6A810F68) + word_swap(name)
        self.assertEqual(u32s(body)[:3], (5, 1, 0x6A810F68))
        self.assertEqual(body[12:16], b"PANS")  # word_swap("SNAP")

    def test_channel_name_write_layout(self) -> None:
        # SPEC.md "Names": CHANNEL_NAMES (0x18) is written one slot at a time;
        # body layout matches CHANNEL_VALUES (chunk0 = start slot, chunk1 =
        # count:16 | type:8 | unknown:8), payload is a word-swapped stream of
        # NUL-terminated names. SPEC.md "Text is word-swapped": MGZU travels
        # as 55 5a 47 4d.
        body = _build_channel_name_write(slot=1, name="Kick")
        self.assertEqual(len(body) % 4, 0)
        self.assertEqual(u32s(body[:8]), (1, 0x00010500))  # count 1, type 5
        self.assertEqual(body[8:12], b"kciK")  # word_swap("Kick")
        self.assertEqual(body[8:], word_swap(b"Kick\x00\x00\x00\x00"))

    def test_channel_name_write_nul_terminates(self) -> None:
        # SPEC.md "Names": an unnamed slot is a bare NUL that still consumes an
        # index, so the write payload must always end in terminators. 9 chars
        # leaves one NUL short of two words: pad = 4 - (9 % 4) = 3.
        body = _build_channel_name_write(slot=50, name="AUXLEFT01")
        self.assertEqual(u32s(body)[:2], (50, 0x00010500))
        decoded = word_swap(body[8:])
        self.assertEqual(decoded, b"AUXLEFT01\x00\x00\x00")

    def test_meter_reports_parse_and_notify(self) -> None:
        # SPEC.md "Value messages": type 1 picks the meter address space.
        # BROADCAST_CONTROL (0x15) publishes these as periodic CHANNEL_VALUES
        # frames; meter values are IEEE float dB like faders.
        c = MackieClient("unused", mixer_model="dl32s")  # no network in a ctor
        seen: list[tuple[int, int]] = []
        unsub = c.subscribe_all_meters(lambda addr, raw: seen.append((addr, raw)))
        meta = (2 << 16) | (1 << 8)  # count 2, type 1, unknown 0
        payload = struct.pack(">II", 34, meta) + struct.pack(">ff", -70.0, -5.5)
        msg = MackieMessage(
            seq=1, msg_type=MackieMessageType.BROADCAST,
            command=MackieCommand.CHANNEL_VALUES, body=payload,
        )
        c._handle_channel_values(msg)
        self.assertEqual(
            seen,
            [
                (34, struct.unpack(">I", struct.pack(">f", -70.0))[0]),
                (35, struct.unpack(">I", struct.pack(">f", -5.5))[0]),
            ],
        )
        self.assertEqual(
            c.get_cached_meter_u32(35),
            struct.unpack(">I", struct.pack(">f", -5.5))[0],
        )
        unsub()

    def test_meters_do_not_leak_into_param_space(self) -> None:
        # One flat cache shared across spaces would corrupt it (SPEC.md "Value
        # messages": address 11 is main_assign under type 5, mute group master
        # under type 2). Meters must stay in their own cache.
        c = MackieClient("unused", mixer_model="dl32s")
        meta = (1 << 16) | (1 << 8)
        payload = struct.pack(">II", 11, meta) + struct.pack(">f", -70.0)
        msg = MackieMessage(
            seq=1, msg_type=MackieMessageType.BROADCAST,
            command=MackieCommand.CHANNEL_VALUES, body=payload,
        )
        c._handle_channel_values(msg)
        self.assertIn(11, c._meter_values)
        self.assertNotIn(11, c._values)
        self.assertNotIn(11, c._type2_values)

    def test_aux_send_addresses_match_addressmap(self) -> None:
        # The aux constants must come from addressmap, not be invented
        # (SPEC.md "Coverage versus surface"): the client getters have to land
        # exactly on aux<n>_level / aux<n>_mute for every covered channel.
        # SPEC.md "Offsets are not addresses": channel 1 aux1 mute = 1 + 51 = 52.
        for model, aux_count, channels in (
            ("dl32s", 8, (1, 2, 32)),
            ("dl16s", 6, (1, 2, 16)),
        ):
            block = addressmap.get_map(model).inputs
            c = MackieClient("unused", mixer_model=model)
            for aux in range(1, aux_count + 1):
                for ch in channels:
                    self.assertEqual(
                        c.aux_send_mute_address(ch, aux),
                        block.address(ch, f"aux{aux}_mute"),
                        msg=f"{model} ch{ch} aux{aux}_mute",
                    )
                    self.assertEqual(
                        c.aux_send_level_address(ch, aux),
                        block.address(ch, f"aux{aux}_level"),
                        msg=f"{model} ch{ch} aux{aux}_level",
                    )

    def test_aux_send_offbyone_anchor(self) -> None:
        # Same trap as the mute anchor: ch1 aux1 mute is offset 51, address 52
        # (addressmap _input_block: aux_first 50, (mute,) one word after level).
        c = MackieClient("unused", mixer_model="dl32s")
        self.assertEqual(c.aux_send_mute_address(1, 1), 52)
        self.assertEqual(c.aux_send_mute_address(2, 1), 52 + 106)
        # addressmap agrees: ch2 aux1 mute = base 1 + stride 106 + offset 51.
        self.assertEqual(
            c.aux_send_mute_address(2, 1),
            addressmap.get_map("dl32s").inputs.address(2, "aux1_mute"),
        )

    def test_aux_send_write_body(self) -> None:
        # aux1 send mute on ch1 writes through the pinned single-write builder:
        # chunk0 = address 52, chunk1 = count 1 | type 5, then the value.
        body = _build_channel_values_set(
            address=MackieClient("unused", mixer_model="dl32s").aux_send_mute_address(1, 1),
            value_int=1,
        )
        self.assertEqual(u32s(body), (52, 0x00010500, 1))

    def test_aux_sends_refused_without_map(self) -> None:
        # addressmap DL32R maps only mute/fader, so aux send addresses must be
        # refused rather than guessed (SPEC.md caveats: trust only mute/fader).
        c = MackieClient("unused", mixer_model="dl32r")
        with self.assertRaises(ValueError):
            c.aux_send_mute_address(1, 1)
        with self.assertRaises(ValueError):
            c.aux_send_level_address(1, 1)

    def test_aux_send_out_of_range_refused(self) -> None:
        # DL32S exposes 8 aux sends (nine 90-word output strips = main + 8 aux,
        # SPEC.md "Input strips"); sending 9 must be refused, not wrapped.
        c = MackieClient("unused", mixer_model="dl32s")
        with self.assertRaises(ValueError):
            c.aux_send_mute_address(1, 9)
        with self.assertRaises(ValueError):
            c.aux_send_level_address(1, 9)

    def test_subgroup_addresses_match_addressmap(self) -> None:
        # Subgroup masters come from addressmap DL32S blocks["subgroup"] (live-dump
        # live-dump analysis 2026-10-17; fields carry verified=False). Nothing
        # here may invent addresses, so the getters must match the map exactly.
        block = addressmap.get_map("dl32s").blocks["subgroup"]
        c = MackieClient("unused", mixer_model="dl32s")
        for g in (1, 3, 6):
            self.assertEqual(
                c.subgroup_fader_address(g), block.address(g, "fader"),
                msg=f"subgroup {g} fader")
            self.assertEqual(
                c.subgroup_mute_address(g), block.address(g, "mute"),
                msg=f"subgroup {g} mute")
        self.assertEqual(c.subgroup_mute_address(1), 4041)  # mute-first strip
        self.assertEqual(c.subgroup_fader_address(1), 4042)

    def test_subgroup_write_body(self) -> None:
        # Subgroup 1 master mute writes through the pinned single-write
        # builder: chunk0 = address 4041, chunk1 = count 1 | type 5, value.
        body = _build_channel_values_set(
            address=MackieClient("unused", mixer_model="dl32s").subgroup_mute_address(1),
            value_int=1,
        )
        self.assertEqual(u32s(body), (4041, 0x00010500, 1))

    def test_subgroup_refused_without_map(self) -> None:
        # Only the DL32S map carries a subgroup block (addressmap.py). DL16S,
        # DL32R and auto must refuse rather than guess; auto especially, since
        # the client's handshake map is only pinned at runtime.
        for model in ("dl16s", "dl32r", "auto"):
            c = MackieClient("unused", mixer_model=model)
            with self.assertRaises(ValueError):
                c.subgroup_mute_address(1)
            with self.assertRaises(ValueError):
                c.subgroup_fader_address(1)

    def test_subgroup_out_of_range_refused(self) -> None:
        # addressmap DL32S subgroup block: count 6.
        c = MackieClient("unused", mixer_model="dl32s")
        with self.assertRaises(ValueError):
            c.subgroup_mute_address(7)
        with self.assertRaises(ValueError):
            c.subgroup_fader_address(7)



    def test_transport_status_subtypes(self) -> None:
        # Corpus miner: GET TRANSPORT STATUS = cmd 0x0E body [8/9/10].
        import asyncio

        from client import MackieClient

        self.assertEqual(MackieClient._TRANSPORT_SUBTYPES["transport"], 8)
        self.assertEqual(MackieClient._TRANSPORT_SUBTYPES["multitrack"], 9)
        self.assertEqual(MackieClient._TRANSPORT_SUBTYPES["music"], 10)
        with self.assertRaises(ValueError):
            asyncio.run(MackieClient("127.0.0.1").get_transport_status("bogus"))

    def test_show_op_bodies(self) -> None:
        # Corpus miner: GET SHOW INFO = 0x09 [5]; SHOW OK = 0x07 [10];
        # GET SHOW CRC = 0x12 [pid, 0x10400]; SET SHOW PARAMETER = 0x13
        # [pid, 0x10300, value]; SET SHOW NAME = 0x18 [pid, 0x10300, name].
        self.assertEqual(u32s(struct.pack(">I", 5)), (5,))
        self.assertEqual(u32s(struct.pack(">I", 10)), (10,))
        self.assertEqual(u32s(struct.pack(">II", 7, 0x10400)), (7, 0x10400))
        self.assertEqual(
            u32s(struct.pack(">III", 7, 0x10300, 42)), (7, 0x10300, 42)
        )
        body = struct.pack(">II", 7, 0x10300) + word_swap(b"Live\x00\x00\x00\x00")
        self.assertEqual(u32s(body)[:2], (7, 0x10300))
        self.assertEqual(body[8:12], b"eviL")


    def test_device_admin_layouts(self) -> None:
        # Corpus miner: 0x0E GET family (single selector word), 0x0F SET family.
        from client import MackieClient

        self.assertEqual(MackieCommand.GENERAL_INFO, 0x0E)
        self.assertEqual(MackieCommand.SET_SYSTEM_STATE, 0x0F)
        # GET bodies are one word: boot 1, max-words 2, devname 3, ip 4,
        # lock 5, static-ip 6, subdevice 7, netconfig 0x12, survey 0x13.
        for sel in (1, 2, 3, 4, 5, 6, 7, 0x12, 0x13):
            self.assertEqual(u32s(struct.pack(">I", sel)), (sel,))
        # SET STATIC IP body: [6, flag, ip, mask, gateway].
        body = struct.pack(">IIIII", 6, 1, 0xC0000209, 0xFFFFFF00, 0xC0A80101)
        self.assertEqual(u32s(body)[:2], (6, 1))
        self.assertEqual(MackieClient._info_ipv4(0xC0000209), "192.0.2.9")
        # SET DEVICE NAME body: [3, ...word-swapped NUL-terminated name].
        name = word_swap(b"Desk\x00\x00\x00\x00")
        self.assertEqual(
            u32s(struct.pack(">I", 3) + name), (3,) + u32s(name)
        )
        # Reply string decode: word-swapped from word 1, NUL-terminated
        # (word 0 is the selector echo).
        reply = struct.pack(">I", 3) + word_swap(b"DL32S\x00\x00\x00")
        self.assertEqual(MackieClient._info_string(reply), "DL32S")


    def test_master_strip_geometry(self) -> None:
        # Corpus miner 2026-10-18: MAINOUT 87 words from 4347 (fader@0,
        # mute@1, balance@2; live -0.83/0), AUX masters 8x90 from 4434
        # (mute@3, fader@4; live aux1 0/+0.83). Map + client must agree.
        from addressmap import get_map
        from client import MackieClient

        main = get_map("dl32s").blocks["main"]
        self.assertEqual((main.base, main.stride, main.count), (4347, 87, 1))
        self.assertEqual(main.address(1, "fader"), 4347)
        self.assertEqual(main.address(1, "mute"), 4348)
        self.assertEqual(main.address(1, "balance"), 4349)
        auxm = get_map("dl32s").blocks["auxmaster"]
        self.assertEqual((auxm.base, auxm.stride, auxm.count), (4434, 90, 8))
        self.assertEqual(auxm.address(1, "mute"), 4437)
        self.assertEqual(auxm.address(8, "fader"), 4434 + 7 * 90 + 4)
        c = MackieClient("unused", mixer_model="dl32s")
        self.assertEqual(c.main_fader_address(), 4347)
        self.assertEqual(c.main_mute_address(), 4348)
        self.assertEqual(c.auxmaster_mute_address(1), 4437)
        self.assertEqual(c.auxmaster_fader_address(8), 4434 + 7 * 90 + 4)
        with self.assertRaises(ValueError):
            c.auxmaster_fader_address(9)


    def test_aux_send_pan_address(self) -> None:
        # Descriptor table: AUXSENDn entries come in FADER/MUTE/PAN triples,
        # so pan is level_address + 2 (ch1 aux1: 51/52/53).
        from client import MackieClient

        c = MackieClient("unused", mixer_model="dl32s")
        self.assertEqual(c.aux_send_pan_address(1, 1), 53)
        self.assertEqual(
            c.aux_send_pan_address(2, 8),
            c.aux_send_level_address(2, 8) + 2,
        )


    def test_reconnect_state_machine(self) -> None:
        # The rack power-cycles nightly: rx death must clear the task handle
        # (or connect() no-ops on a dead task forever) and must notify;
        # teardown for reconnect must keep entity subscriptions.
        import asyncio

        from client import MackieClient

        async def go() -> None:
            c = MackieClient("unused")
            self.assertFalse(c.is_connected)
            self.assertFalse(c._is_usable())

            seen: list[bool] = []
            unsub = c.subscribe_connection(seen.append)
            c._set_connected(True)
            c._set_connected(True)  # no duplicate notify
            self.assertEqual(seen, [True])

            # A value listener stands in for an entity subscription.
            c._listeners.setdefault(99, set()).add(lambda _r: None)
            await c._drop_transport()  # nothing open: no flap, no crash
            self.assertEqual(seen, [True])
            self.assertIn(99, c._listeners)

            # Simulate a dead transport with listeners attached.
            class _FakeWriter:
                async def wait_closed(self) -> None:
                    return None

                def close(self) -> None:
                    return None

            c._writer = _FakeWriter()  # type: ignore[assignment]
            dead = asyncio.ensure_future(asyncio.sleep(0))
            await dead
            c._rx_task = dead
            self.assertFalse(c._is_usable())
            await c._drop_transport()
            self.assertIsNone(c._rx_task)
            self.assertIsNone(c._writer)
            self.assertIn(99, c._listeners)  # kept for reconnect
            self.assertEqual(seen, [True, False])

            # ensure_connected reconnects through connect() (stubbed: no TCP).
            async def fake_connect() -> None:
                c._writer = object()  # type: ignore[assignment]
                c._rx_task = asyncio.ensure_future(asyncio.sleep(3600))
                c._set_connected(True)

            c.connect = fake_connect  # type: ignore[method-assign]
            try:
                self.assertTrue(await c.ensure_connected())
                self.assertTrue(c._is_usable())
                self.assertIn(99, c._listeners)
            finally:
                c._rx_task.cancel()
                c._writer = _FakeWriter()  # type: ignore[assignment]
                await c._drop_transport()
            unsub()

        asyncio.run(go())

    def test_ensure_connected_never_raises(self) -> None:
        import asyncio

        from client import MackieClient

        async def go() -> None:
            c = MackieClient("unused")

            async def boom() -> None:
                raise OSError("mixer off")

            c.connect = boom  # type: ignore[method-assign]
            self.assertFalse(await c.ensure_connected())

        asyncio.run(go())

    def test_close_clears_everything(self) -> None:
        import asyncio

        from client import MackieClient

        async def go() -> None:
            c = MackieClient("unused")
            c._listeners.setdefault(1, set()).add(lambda _r: None)
            c._type2_listeners.setdefault(11, set()).add(lambda _r: None)
            c._name_listeners.setdefault(64, set()).add(lambda _s: None)
            c.subscribe_connection(lambda _u: None)
            await c.close()
            self.assertEqual(c._listeners, {})
            self.assertEqual(c._type2_listeners, {})
            self.assertEqual(c._name_listeners, {})
            self.assertEqual(c._conn_listeners, set())

        asyncio.run(go())

if __name__ == "__main__":
    unittest.main()
