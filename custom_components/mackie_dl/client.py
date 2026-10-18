from __future__ import annotations

import asyncio
import io
import struct
import time
import zipfile
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Dict, Optional


class MackieMessageType(IntEnum):
    REQUEST = 0
    RESPONSE = 1
    ERROR = 5
    BROADCAST = 8


class MackieCommand(IntEnum):
    KEEP_ALIVE = 0x01
    CLIENT_HANDSHAKE = 0x03
    FIRMWARE_INFO = 0x04
    # Reboot into normal (1) or updater (2) mode: len-1 body holding the
    # mode word, as used by the firmware-update flow.
    REBOOT = 0x05
    CHANNEL_INFO_CONTROL = 0x06
    # Master Fader snapshot/show recall (observed on wire; not in public DigiMixer enum).
    SHOW_SNAPSHOT = 0x07
    # File transfer, used to fetch Show.zip (which is where snapshot names live).
    # See tools/capture/FINDINGS.md section 3.
    FILE_INFO = 0x09
    FILE_OPEN = 0x0A
    FILE_CLOSE = 0x0B
    FILE_READ = 0x0C
    # File upload chunks (POST FILE): body [id, total, offset, chunklen,
    # ...data], data words word-swapped like everything else.
    POST_FILE = 0x0D
    GENERAL_INFO = 0x0E
    # SET SYSTEM STATE family (0x0F), sub-selected by body word 0, mirroring
    # the 0x0E GET family: 1 boot code, 3 device name, 6 static IP config,
    # 0x12 network config. Determined by protocol analysis.
    SET_SYSTEM_STATE = 0x0F
    SHOW_STATUS = 0x12
    CHANNEL_VALUES = 0x13
    BROADCAST_CONTROL = 0x15
    METER_LAYOUT = 0x16
    CHANNEL_NAMES = 0x18


HEADER0 = 0xAB

#: The `type` byte in a CHANNEL_VALUES meta word selects the address space, it is
#: not a data-type tag. Address 11 is input 1's `main_assign` under type 5 and
#: mute group 1's master under type 2, so the two must never share a cache.
VALUE_TYPE_PARAM = 5
VALUE_TYPE_MUTE_GROUP = 2
#: Meters ride CHANNEL_VALUES too (see the chunk-1 comment in SPEC.md, "Value
#: messages": type 5 = values, 1 = meters, 2 = mute groups).
VALUE_TYPE_METER = 1

MUTE_GROUP_COUNT = 6
#: Mute group N master mute. Verified for all six on a DL32S.
MUTE_GROUP_BASE_ADDRESS = 10
#: Mute group N name, in the flat CHANNEL_NAMES table (channels 1-32, aux 50-57,
#: subgroups 58-63, mute groups 64-69, VCAs 70-75).
MUTE_GROUP_NAME_SLOT_BASE = 63


def mute_group_master_address(group_1_based: int) -> int:
    if not 1 <= group_1_based <= MUTE_GROUP_COUNT:
        raise ValueError(f"mute group must be 1..{MUTE_GROUP_COUNT}")
    return MUTE_GROUP_BASE_ADDRESS + int(group_1_based)


def mute_group_name_slot(group_1_based: int) -> int:
    if not 1 <= group_1_based <= MUTE_GROUP_COUNT:
        raise ValueError(f"mute group must be 1..{MUTE_GROUP_COUNT}")
    return MUTE_GROUP_NAME_SLOT_BASE + int(group_1_based)


def word_swap(data: bytes) -> bytes:
    """Reverse the bytes within each 4-byte word.

    Mackie stores text as little-endian characters inside an otherwise big-endian
    protocol, so "MGZU" travels as 55 5a 47 4d. Applies to channel names, snapshot
    names and file-transfer payloads alike. Trailing bytes past the last whole
    word are dropped, which is correct: the protocol always pads to a word.
    """
    out = bytearray()
    for i in range(0, len(data) - len(data) % 4, 4):
        out += data[i : i + 4][::-1]
    return bytes(out)


@dataclass(frozen=True)
class MackieMessage:
    seq: int
    msg_type: MackieMessageType
    command: MackieCommand
    body: bytes  # network order, len multiple of 4

    @property
    def chunk_count(self) -> int:
        return len(self.body) // 4

    def to_bytes(self) -> bytes:
        if len(self.body) % 4 != 0:
            raise ValueError("Body length must be multiple of 4")

        header = bytearray(6)
        header[0] = HEADER0
        header[1] = self.seq & 0xFF
        struct.pack_into(">H", header, 2, self.chunk_count)
        header[4] = int(self.msg_type) & 0xFF
        header[5] = int(self.command) & 0xFF

        header_checksum = 0xFFFF
        for b in header:
            header_checksum = (header_checksum - b) & 0xFFFF

        out = bytearray()
        out.extend(header)
        out.extend(struct.pack(">H", header_checksum))

        if self.chunk_count == 0:
            return bytes(out)

        out.extend(self.body)
        body_checksum = 0xFFFFFFFF
        for b in self.body:
            body_checksum = (body_checksum - b) & 0xFFFFFFFF
        out.extend(struct.pack(">I", body_checksum))
        return bytes(out)


class MackieProtocolError(Exception):
    pass


def _normalize_mixer_model(raw: str) -> str:
    m = (raw or "auto").strip().lower()
    if m == "dl32sr":
        return "dl32s"
    if m in ("auto", "dl16s", "dl32r", "dl32s"):
        return m
    return "auto"


def _apply_dl16s_input_map(client: "MackieClient") -> None:
    """Address map from DigiMixer DL16S profile (Jon Skeet)."""
    client._input_start_address = 1
    client._input_stride = 100
    client._input_mute_offset = 7
    client._input_fader_offset = 8


def _apply_dl32s_input_map(client: "MackieClient") -> None:
    """DL32S per-wire observation: same offsets as DL16S but stride 106 between inputs (ch2 mute @114)."""
    client._input_start_address = 1
    client._input_stride = 106
    client._input_mute_offset = 7
    client._input_fader_offset = 8


def _apply_dl32r_input_map(client: "MackieClient") -> None:
    """Address map from DigiMixer DL32R profile (Jon Skeet)."""
    client._input_start_address = 41
    client._input_stride = 132
    client._input_mute_offset = 7
    client._input_fader_offset = 8


def _apply_handshake_input_map(client: "MackieClient", handshake_body: bytes) -> bool:
    """
    Heuristic from DigiMixer: DL32R handshake often has body[1]==5; DL16S uses 0x09.

    Returns True if this alone pinned the map. If False (unknown firmware / odd length),
    the caller should run address probing for ``auto``mode.
    """
    if client._mixer_model != "auto":
        return True
    if len(handshake_body) >= 2:
        if handshake_body[1] == 5:
            _apply_dl32r_input_map(client)
            return True
        if handshake_body[1] == 9:
            _apply_dl16s_input_map(client)
            return True
    return False


def _mute_u32_plausible(raw: int | None) -> bool:
    """Input mute channel-values are small integers 0/1 on the wire."""
    if raw is None:
        return False
    return (int(raw) & 0xFFFFFFFF) in (0, 1)


async def _probe_auto_input_map(client: "MackieClient") -> None:
    """
    Disambiguate DL16S (mute@8) vs DL32R/S (mute@48) by reading likely input1 mute slots.
    """
    if client._mixer_model != "auto":
        return
    try:
        m8 = await client.request_value_u32(8, timeout=2.5)
        m48 = await client.request_value_u32(48, timeout=2.5)
    except Exception:
        return
    ok8 = _mute_u32_plausible(m8)
    ok48 = _mute_u32_plausible(m48)
    if ok48 and not ok8:
        _apply_dl32r_input_map(client)
        return
    if ok8 and not ok48:
        _apply_dl16s_input_map(client)
        return
    if ok48 and ok8:
        try:
            m108 = await client.request_value_u32(108, timeout=2.5)
            m180 = await client.request_value_u32(180, timeout=2.5)
        except Exception:
            return
        if _mute_u32_plausible(m180) and not _mute_u32_plausible(m108):
            _apply_dl32r_input_map(client)
        elif _mute_u32_plausible(m108) and not _mute_u32_plausible(m180):
            _apply_dl16s_input_map(client)


# After GeneralInfo, DigiMixer sends MeterLayout then BroadcastControl so the mixer
# publishes meters and accepts channel-value writes across the full map (DL32R etc.).
DIGIMIXER_BROADCAST_CONTROL_BODY = bytes(
    [0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x5A, 0x00, 0x01]
)


def _dl32r_meter_addresses() -> list[int]:
    """Same meter order as DigiMixer.Mackie DL32RProfile (inputs → returns → FX in → aux → FX out → mains)."""
    addrs: list[int] = []
    for z in range(32):
        addrs.append(34 + z * 7)
    for z in range(4):
        addrs.append(258 + z * 4 + 1)
    for z in range(4):
        addrs.append(274 + z)
    for z in range(14):
        addrs.append(318 + z * 4)
    for z in range(4):
        addrs.append(278 + z * 2)
    addrs.extend([310, 311])
    return addrs


def _dl16s_meter_addresses() -> list[int]:
    """DigiMixer DL16SProfile meter list."""
    addrs: list[int] = []
    for z in range(16):
        addrs.append(34 + z * 7)
    for z in range(2):
        addrs.append(146 + z * 4 + 1)
    for z in range(4):
        addrs.append(154 + z)
    for z in range(6):
        addrs.append(198 + z * 4)
    for z in range(4):
        addrs.append(158 + z * 2)
    addrs.extend([190, 191])
    return addrs


def _meter_layout_body(addresses: list[int]) -> bytes:
    out = bytearray(4)
    out[3] = 1
    for a in addresses:
        out.extend(struct.pack(">i", int(a)))
    return bytes(out)


# Aux sends sit inside each input strip as (level, mute, pan) triples
# starting at offset 50: aux N level at 50 + (N-1)*3, its mute one word later,
# pan two words later. addressmap.py pins the layout (_input_block:
# aux_first = 50, stride 3); only the count varies by model (DL32S stride 106
# = 8 sends, DL16S 100 = 6, DL32R unmapped). Cross-checked against addressmap
# in tests/test_protocol.py so these constants can never drift from the map.
AUX_SEND_FIRST_OFFSET = 50
AUX_SEND_STRIDE = 3

# Subgroup master strips come from addressmap.py (DL32S blocks["subgroup"]):
# six 51-word strips from 4041, master mute at offset 0, master fader at
# offset 1 (mute-first layout cross-checked against parameter metadata; 4049 is COMP
# ENABLE, not mute). Main-out: 87 words from 4347 (fader@0, mute@1, bal@2).
# Aux masters: 8 x 90 words from 4434 (mute@3, fader@4). All verified=False
# in the map - confirming them is a planned +/-1 dB nudge trial. The
# constants here are cross-checked against the map in tests/test_protocol.py,
# and writes are gated to mixer_model == "dl32s" only.
_SUBGROUP_STRIP_BASE = 4041
_SUBGROUP_STRIP_STRIDE = 51
_SUBGROUP_COUNT = 6
_SUBGROUP_FADER_OFFSET = 1
_SUBGROUP_MUTE_OFFSET = 0
_MAIN_FADER_ADDRESS = 4347
_MAIN_MUTE_ADDRESS = 4348
_MAIN_BAL_ADDRESS = 4349
_AUXMASTER_BASE = 4434
_AUXMASTER_STRIDE = 90
_AUXMASTER_COUNT = 8
_AUXMASTER_FADER_OFFSET = 4
_AUXMASTER_MUTE_OFFSET = 3


class MackieClient:
    """
    Minimal async client for Mackie DL-series TCP protocol (port 50001).

    This implements message framing + request/response correlation by sequence number.
    """

    def __init__(
        self,
        host: str,
        port: int = 50001,
        *,
        mixer_model: str = "auto",
        input_start_address: int = 1,
        input_stride: int = 100,
        input_mute_offset: int = 7,
        input_fader_offset: int = 8,
    ) -> None:
        self._host = host
        self._port = port
        self._mixer_model = _normalize_mixer_model(mixer_model)
        self._input_start_address = int(input_start_address)
        self._input_stride = int(input_stride)
        self._input_mute_offset = int(input_mute_offset)
        self._input_fader_offset = int(input_fader_offset)
        if self._mixer_model == "dl16s":
            _apply_dl16s_input_map(self)
        elif self._mixer_model == "dl32r":
            _apply_dl32r_input_map(self)
        elif self._mixer_model == "dl32s":
            # DL32S: not DL32R (41+132); inputs use stride 106 (see wire capture: ch2 mute address 114).
            _apply_dl32s_input_map(self)
        elif self._mixer_model == "auto":
            # Safe default for DL32R/S when handshake/probe are ambiguous (DL16S map rejects writes).
            _apply_dl32r_input_map(self)

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

        self._seq = 0
        self._rx_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None

        self._pending: Dict[int, asyncio.Future[MackieMessage]] = {}
        self._lock = asyncio.Lock()
        self._values: Dict[int, int] = {}  # raw u32 values by address (type 5)
        self._listeners: Dict[int, set[Callable[[int], None]]] = {}
        self._global_listeners: set[Callable[[int, int], None]] = set()

        # Type-2 space. Roughly 107 addresses, of which 11-16 are the mute group
        # masters; the rest is unmapped and includes floats. Kept separate from
        # _values because the two spaces reuse the same low addresses - address 11
        # is input 1's main_assign under type 5. See VALUE_TYPE_MUTE_GROUP.
        self._type2_values: Dict[int, int] = {}
        self._type2_listeners: Dict[int, set[Callable[[int], None]]] = {}

        # Type-1 meter space. Published as periodic CHANNEL_VALUES frames once
        # METER_LAYOUT (0x16) + BROADCAST_CONTROL (0x15) have been sent (SPEC.md
        # command table). Keep it out of _values and _type2_values the same way
        # those two are kept apart: each space reuses low addresses freely.
        self._meter_values: Dict[int, int] = {}
        self._global_meter_listeners: set[Callable[[int, int], None]] = set()

        # CHANNEL_NAMES table, slot -> name. Pushed by the mixer at connect and
        # again, one slot at a time, whenever anyone renames something.
        self._names: Dict[int, str] = {}
        self._name_listeners: Dict[int, set[Callable[[str], None]]] = {}

        # Snapshot index -> name. Seeded from Show.zip, kept current by 0x07 op 5
        # pushes from the mixer.
        self._snapshot_names: Dict[int, str] = {}
        self._snapshot_name_listeners: set[Callable[[], None]] = set()
        #: Last snapshot recalled, learned from 0x07 op 1 relays. Unknown until
        #: something recalls one; the mixer does not report it at connect.
        self._current_snapshot: int | None = None

        # Connection state. The mixer power-cycles with the rack, so dropouts
        # are routine: _rx_task dying means the transport is gone, and the
        # integration reconnects from the poll loop instead of needing HA to
        # reload the entry. Entity listeners are NEVER cleared on drop - only
        # close() (integration unload) clears subscriptions.
        self._connected = False
        self._conn_listeners: set[Callable[[bool], None]] = set()

    async def connect(self) -> None:
        """Open the mixer connection (idempotent).

        Safe to call again after a dropout: any dead transport is torn down
        first, and entity subscriptions are left untouched so entities resume
        without re-subscribing. Raises the underlying OSError if the mixer is
        unreachable - callers that poll (ensure_connected) catch it.
        """
        if self._is_usable():
            return
        await self._drop_transport()
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        self._rx_task = asyncio.create_task(self._rx_loop(), name="mackie_dl_rx")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="mackie_dl_keepalive")
        try:
            await self._initialize_connection()
        except Exception:
            await self._drop_transport()
            raise
        self._set_connected(True)

    async def ensure_connected(self) -> bool:
        """Connect if down, for poll loops. Never raises; True when usable."""
        if self._is_usable():
            return True
        try:
            await self.connect()
        except Exception:
            return False
        return self._is_usable()

    def _is_usable(self) -> bool:
        rx = self._rx_task
        return (
            self._writer is not None
            and rx is not None
            and not rx.done()
        )

    @property
    def is_connected(self) -> bool:
        return self._connected

    def subscribe_connection(self, callback: Callable[[bool], None]) -> Callable[[], None]:
        """Called with True/False on connect/drop. Returns an unsubscribe callable."""
        self._conn_listeners.add(callback)

        def _unsub() -> None:
            self._conn_listeners.discard(callback)

        return _unsub

    def _set_connected(self, value: bool) -> None:
        if self._connected == value:
            return
        self._connected = value
        for cb in list(self._conn_listeners):
            try:
                cb(value)
            except Exception:
                pass

    def _note_transport_lost(self) -> None:
        """Mark this transport dead. Called when the rx loop exits."""
        self._rx_task = None
        self._set_connected(False)

    async def _drop_transport(self) -> None:
        """Tear down tasks/transport WITHOUT clearing subscriptions.

        Shared by close() and the reconnect path. Safe with nothing open.
        Marks the connection down only if something was actually open, so a
        no-op drop never flaps entity availability.
        """
        keepalive, rx, writer = self._keepalive_task, self._rx_task, self._writer
        self._keepalive_task = None
        self._rx_task = None
        if keepalive:
            keepalive.cancel()
        if rx:
            rx.cancel()
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None
        if keepalive is not None or rx is not None or writer is not None:
            self._set_connected(False)

        for fut in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def close(self) -> None:
        await self._drop_transport()

        self._listeners.clear()
        self._global_listeners.clear()
        self._global_meter_listeners.clear()
        self._type2_listeners.clear()
        self._name_listeners.clear()
        self._snapshot_name_listeners.clear()
        self._conn_listeners.clear()

    async def _keepalive_loop(self) -> None:
        # Per protocol notes: send every ~2.5 seconds.
        try:
            while True:
                await asyncio.sleep(2.5)
                await self.send_keepalive()
        except asyncio.CancelledError:
            return

    async def _rx_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                msg = await self._read_one_message()
                if msg.msg_type == MackieMessageType.REQUEST:
                    await self._handle_request(msg)
                elif msg.msg_type == MackieMessageType.BROADCAST:
                    self._handle_broadcast(msg)
                elif msg.msg_type in (MackieMessageType.RESPONSE, MackieMessageType.ERROR):
                    if msg.msg_type == MackieMessageType.RESPONSE and msg.command == MackieCommand.CHANNEL_VALUES:
                        self._handle_channel_values(msg)
                    fut = self._pending.pop(msg.seq, None)
                    if fut and not fut.done():
                        if msg.msg_type == MackieMessageType.ERROR:
                            err = MackieProtocolError(
                                f"Mixer returned ERROR response "
                                f"(seq={msg.seq} cmd=0x{int(msg.command):02x} "
                                f"body={msg.body.hex()})"
                            )
                            fut.set_exception(err)
                        else:
                            fut.set_result(msg)
        except asyncio.CancelledError:
            return
        except Exception as e:
            # Fail all pending requests
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(e)
            self._pending.clear()
        finally:
            # The transport is gone (dropout, close, or failure): mark it so
            # connect()/ensure_connected() will rebuild instead of no-op on a
            # dead _rx_task, and tell entities they are stale. close() also
            # clears _rx_task itself; this is idempotent with that.
            # Guard: a superseded loop (reconnect already built a live one)
            # must not clear the new task.
            rx = self._rx_task
            if rx is None or rx.done():
                self._note_transport_lost()

    async def _read_exactly(self, n: int) -> bytes:
        assert self._reader is not None
        data = await self._reader.readexactly(n)
        return data

    async def _read_one_message(self) -> MackieMessage:
        header_and_checksum = await self._read_exactly(8)
        if header_and_checksum[0] != HEADER0:
            raise MackieProtocolError("Bad header marker")

        seq = header_and_checksum[1]
        chunk_count = struct.unpack_from(">H", header_and_checksum, 2)[0]
        msg_type = MackieMessageType(header_and_checksum[4])
        command = MackieCommand(header_and_checksum[5])

        if chunk_count == 0:
            return MackieMessage(seq=seq, msg_type=msg_type, command=command, body=b"")

        body_len = chunk_count * 4
        body = await self._read_exactly(body_len)
        _body_checksum = await self._read_exactly(4)  # not validated (matches DigiMixer)
        return MackieMessage(seq=seq, msg_type=msg_type, command=command, body=body)

    async def _send_response(self, *, seq: int, command: MackieCommand, body: bytes) -> None:
        if len(body) % 4 != 0:
            raise ValueError("Body must be a multiple of 4 bytes")
        if not self._writer:
            return
        msg = MackieMessage(seq=seq, msg_type=MackieMessageType.RESPONSE, command=command, body=body)
        self._writer.write(msg.to_bytes())
        await self._writer.drain()

    async def _handle_request(self, msg: MackieMessage) -> None:
        """
        The mixer can send request messages and expects a response.

        Based on Jon Skeet's DigiMixer observations, replying to a few commands is
        required for the connection to fully function.
        """
        # NOTE: These constants are taken from DigiMixer's Mackie implementation.
        if msg.command == MackieCommand.CLIENT_HANDSHAKE:
            # TODO: Providing the real MAC would be ideal, but zeroes works.
            await self._send_response(seq=msg.seq, command=msg.command, body=bytes([0x10, 0x40, 0, 0, 0, 0, 0, 0]))
            return

        if msg.command == MackieCommand.GENERAL_INFO:
            await self._send_response(seq=msg.seq, command=msg.command, body=bytes([0, 0, 0, 2, 0, 0, 0x40, 0]))
            return

        if msg.command == MackieCommand.CHANNEL_INFO_CONTROL:
            # Echo back the first chunk (4 bytes) as the response body when present.
            body = msg.body[:4] if len(msg.body) >= 4 else b""
            await self._send_response(seq=msg.seq, command=msg.command, body=body)
            return

        if msg.command == MackieCommand.CHANNEL_VALUES:
            self._handle_channel_values(msg)
            await self._send_response(seq=msg.seq, command=msg.command, body=b"")
            return

        if msg.command == MackieCommand.CHANNEL_NAMES:
            # The mixer pushes the whole table at connect and one slot per
            # rename thereafter. Previously this reply discarded the body, which
            # is why names were never available.
            self._handle_channel_names(msg)
            await self._send_response(seq=msg.seq, command=msg.command, body=b"")
            return

        if msg.command == MackieCommand.SHOW_SNAPSHOT:
            self._handle_snapshot_push(msg)
            await self._send_response(
                seq=msg.seq, command=msg.command, body=msg.body[:4] if msg.body else b""
            )
            return

        # Default: empty response
        await self._send_response(seq=msg.seq, command=msg.command, body=b"")

    def _handle_broadcast(self, msg: MackieMessage) -> None:
        if msg.command == MackieCommand.CHANNEL_VALUES:
            self._handle_channel_values(msg)

    def _handle_snapshot_push(self, msg: MackieMessage) -> None:
        """Learn snapshot names from op-5 (save) frames the mixer relays.

        Body: <op=5> <snapshot number> <unix epoch> <word-swapped name>. The
        mixer relays these to every *other* connected client, so renaming a
        snapshot on the iPad updates us without any polling or file transfer.
        """
        body = msg.body
        if len(body) < 8:
            return
        op, number = struct.unpack_from(">II", body, 0)
        if number < 1:
            return
        # op 1 is a recall. The mixer relays these too, so recalling on the iPad
        # tells us which snapshot is now active.
        if op == 1:
            if self._current_snapshot != int(number):
                self._current_snapshot = int(number)
                self._notify_snapshot_names()
            return
        if op != 5 or len(body) < 12:
            return
        name = word_swap(body[12:]).split(b"\x00")[0]
        try:
            text = name.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        if not text or self._snapshot_names.get(int(number)) == text:
            return
        self._snapshot_names[int(number)] = text
        self._notify_snapshot_names()

    def _notify_snapshot_names(self) -> None:
        for cb in list(self._snapshot_name_listeners):
            try:
                cb()
            except Exception:
                pass

    @property
    def snapshot_names(self) -> Dict[int, str]:
        return dict(self._snapshot_names)

    @property
    def current_snapshot(self) -> int | None:
        return self._current_snapshot

    def subscribe_snapshot_names(self, callback: Callable[[], None]) -> Callable[[], None]:
        self._snapshot_name_listeners.add(callback)

        def _unsub() -> None:
            self._snapshot_name_listeners.discard(callback)

        return _unsub

    def _handle_channel_values(self, msg: MackieMessage) -> None:
        body = msg.body
        if len(body) < 8:
            return
        meta = struct.unpack_from(">I", body, 4)[0]
        value_type = (meta >> 8) & 0xFF
        if value_type == VALUE_TYPE_MUTE_GROUP:
            self._handle_type2_values(body, meta)
            return
        if value_type == VALUE_TYPE_METER:
            # Periodic meter reports (BROADCAST_CONTROL). Previously dropped
            # on the floor, which made meter values unreachable for the CLI.
            self._handle_meter_values(body, meta)
            return
        # Only handle type=5 (normal values); other spaces are routed above.
        if value_type != VALUE_TYPE_PARAM:
            return
        start_addr = struct.unpack_from(">I", body, 0)[0]
        count = (meta >> 16) & 0xFFFF
        # Values follow from chunk 2.
        #
        # count==0 means "as many as fit". After init the DL32S pushes its whole
        # value space as two CHANNEL_VALUES requests (3072 then 2185 values) whose
        # meta word is 0x00000500 - type 5, count 0. Taking min(count, available)
        # there discards every pushed value, which is why nothing ever populated.
        # Small messages do set count, so honour it when present.
        available = (len(body) // 4) - 2
        max_values = min(count, available) if count else available
        for i in range(max_values):
            addr = int(start_addr + i)
            raw = struct.unpack_from(">I", body, (2 + i) * 4)[0]
            old = self._values.get(addr)
            if old == raw:
                continue
            self._values[addr] = raw
            for cb in self._global_listeners:
                try:
                    cb(addr, raw)
                except Exception:
                    pass
            for cb in self._listeners.get(addr, set()):
                try:
                    cb(raw)
                except Exception:
                    # Listener exceptions should never kill RX loop.
                    pass

    # --- mute group masters (type-2 space) ----------------------------------

    def _handle_type2_values(self, body: bytes, meta: int) -> None:
        """Cache the type-2 value space, which carries the mute group masters.

        Two ways this arrives: a bulk dump at connect (start 1, count 0, ~107
        values) that seeds initial state, and single-address pushes when another
        client changes something. The mixer never echoes our own writes back, so
        those are cached locally by `set_mute_group`.

        As with type 5, count == 0 means "as many as fit", not "none".
        """
        start_addr = struct.unpack_from(">I", body, 0)[0]
        count = (meta >> 16) & 0xFFFF
        available = (len(body) // 4) - 2
        n = min(count, available) if count else available
        for i in range(n):
            addr = int(start_addr + i)
            raw = struct.unpack_from(">I", body, (2 + i) * 4)[0]
            if self._type2_values.get(addr) == raw:
                continue
            self._type2_values[addr] = raw
            for cb in self._type2_listeners.get(addr, set()):
                try:
                    cb(raw)
                except Exception:
                    pass

    async def set_mute_group(self, group_1_based: int, muted: bool) -> None:
        """Mute or unmute a mute group master."""
        address = mute_group_master_address(group_1_based)
        body = _build_channel_values_set(
            address=address,
            value_int=1 if muted else 0,
            value_type=VALUE_TYPE_MUTE_GROUP,
        )
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        # No echo comes back for our own write, so cache it ourselves.
        self._type2_values[address] = 1 if muted else 0

    def get_cached_mute_group(self, group_1_based: int) -> bool | None:
        raw = self._type2_values.get(mute_group_master_address(group_1_based))
        return None if raw is None else bool(raw)

    def subscribe_mute_group(
        self, group_1_based: int, callback: Callable[[int], None]
    ) -> Callable[[], None]:
        addr = mute_group_master_address(group_1_based)
        self._type2_listeners.setdefault(addr, set()).add(callback)

        def _unsub() -> None:
            listeners = self._type2_listeners.get(addr)
            if not listeners:
                return
            listeners.discard(callback)
            if not listeners:
                self._type2_listeners.pop(addr, None)

        return _unsub

    # --- meters (type-1 space) ----------------------------------------------

    def _handle_meter_values(self, body: bytes, meta: int) -> None:
        """Cache a periodic meter report (CHANNEL_VALUES with meta type 1).

        METER_LAYOUT (0x16) selects which addresses are reported and
        BROADCAST_CONTROL (0x15) turns the timer on; SPEC.md documents both in
        the command table. As with the other spaces, count == 0 means "as many
        as fit" (SPEC.md, "Bulk pushes carry count = 0"), although periodic
        reports are small enough to set count correctly.
        """
        start_addr = struct.unpack_from(">I", body, 0)[0]
        count = (meta >> 16) & 0xFFFF
        available = (len(body) // 4) - 2
        n = min(count, available) if count else available
        for i in range(n):
            addr = int(start_addr + i)
            raw = struct.unpack_from(">I", body, (2 + i) * 4)[0]
            if self._meter_values.get(addr) == raw:
                continue
            self._meter_values[addr] = raw
            for cb in list(self._global_meter_listeners):
                try:
                    cb(addr, raw)
                except Exception:
                    pass

    def get_cached_meter_u32(self, address: int) -> int | None:
        """Last meter raw u32 seen for an address, or None before the first report."""
        return self._meter_values.get(int(address))

    def subscribe_all_meters(self, callback: Callable[[int, int], None]) -> Callable[[], None]:
        """Subscribe to every meter update. Callback receives (address, raw_u32).

        Meter values are IEEE float dB on the wire, same encoding as faders.
        Returns an unsubscribe callable, mirroring subscribe_all.
        """
        self._global_meter_listeners.add(callback)

        def _unsub() -> None:
            self._global_meter_listeners.discard(callback)

        return _unsub

    async def enable_meter_reports(self) -> None:
        """Send METER_LAYOUT + BROADCAST_CONTROL so the mixer starts publishing meters.

        connect() already sends both once (DigiMixer init order); re-sending is
        harmless and lets a CLI session turn reports on explicitly.
        """
        await self._send_digimixer_meter_and_broadcast()

    # --- channel / mute group / VCA names -----------------------------------

    def _handle_channel_names(self, msg: MackieMessage) -> None:
        """Parse a CHANNEL_NAMES table into the name cache.

        Body mirrors CHANNEL_VALUES: chunk 0 is the start slot, chunk 1 is
        count/type, and the rest is a word-swapped stream of NUL-terminated
        names. An unnamed slot is a bare NUL and still consumes an index, so
        blanks must be kept while numbering or every later slot shifts.
        """
        body = msg.body
        if len(body) < 8:
            return
        start = struct.unpack_from(">I", body, 0)[0]
        raw = word_swap(body[8:])
        for i, chunk in enumerate(raw.split(b"\x00")):
            slot = int(start + i)
            try:
                name = chunk.decode("ascii").strip()
            except UnicodeDecodeError:
                continue
            if self._names.get(slot) == name:
                continue
            self._names[slot] = name
            for cb in self._name_listeners.get(slot, set()):
                try:
                    cb(name)
                except Exception:
                    pass

    def get_name(self, slot: int) -> str | None:
        return self._names.get(int(slot)) or None

    def get_mute_group_name(self, group_1_based: int) -> str | None:
        return self.get_name(mute_group_name_slot(group_1_based))

    def subscribe_name(self, slot: int, callback: Callable[[str], None]) -> Callable[[], None]:
        s = int(slot)
        self._name_listeners.setdefault(s, set()).add(callback)

        def _unsub() -> None:
            listeners = self._name_listeners.get(s)
            if not listeners:
                return
            listeners.discard(callback)
            if not listeners:
                self._name_listeners.pop(s, None)

        return _unsub

    async def set_channel_name(self, slot: int, name: str) -> None:
        """Rename one slot in the CHANNEL_NAMES table (0x18 single-slot write).

        Slot numbering per SPEC.md "Names": 1-32 inputs, 50-57 aux outputs,
        58-63 subgroups, 64-69 mute groups, 70-75 VCAs. The mixer does not echo
        our own writes back (SPEC.md, "Snapshots", about relaying to other
        clients), so cache the name locally like the mute/fader setters do.
        """
        s = int(slot)
        if s < 1:
            raise ValueError("slot must be >= 1")
        body = _build_channel_name_write(slot=s, name=name)
        await self.send_request(MackieCommand.CHANNEL_NAMES, body)
        self._names[s] = str(name).strip()
        for cb in self._name_listeners.get(s, set()):
            try:
                cb(self._names[s])
            except Exception:
                pass

    def subscribe_value(self, address: int, callback: Callable[[int], None]) -> Callable[[], None]:
        """Subscribe to raw u32 updates for a specific address. Returns an unsubscribe callable."""
        addr = int(address)
        self._listeners.setdefault(addr, set()).add(callback)

        def _unsub() -> None:
            listeners = self._listeners.get(addr)
            if not listeners:
                return
            listeners.discard(callback)
            if not listeners:
                self._listeners.pop(addr, None)

        return _unsub

    def subscribe_all(self, callback: Callable[[int, int], None]) -> Callable[[], None]:
        """Subscribe to all value updates. Callback receives (address, raw_u32)."""
        self._global_listeners.add(callback)

        def _unsub() -> None:
            self._global_listeners.discard(callback)

        return _unsub

    def subscribe_type2(self, address: int, callback: Callable[[int], None]) -> Callable[[], None]:
        """Subscribe to raw u32 updates for a type-2 address. Returns an unsubscribe callable."""
        addr = int(address)
        self._type2_listeners.setdefault(addr, set()).add(callback)

        def _unsub() -> None:
            listeners = self._type2_listeners.get(addr)
            if not listeners:
                return
            listeners.discard(callback)
            if not listeners:
                self._type2_listeners.pop(addr, None)

        return _unsub

    def get_cached_u32(self, address: int) -> int | None:
        return self._values.get(int(address))

    def _cache_and_notify_u32(self, address: int, raw_u32: int) -> None:
        addr = int(address)
        raw = int(raw_u32) & 0xFFFFFFFF
        old = self._values.get(addr)
        if old == raw:
            return
        self._values[addr] = raw
        for cb in self._global_listeners:
            try:
                cb(addr, raw)
            except Exception:
                pass
        for cb in self._listeners.get(addr, set()):
            try:
                cb(raw)
            except Exception:
                pass

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFF
        if self._seq == 0:
            self._seq = 1
        return self._seq

    async def send_request(self, command: MackieCommand, body: bytes, timeout: float = 3.0) -> MackieMessage:
        if len(body) % 4 != 0:
            raise ValueError("Body must be a multiple of 4 bytes")
        if not self._writer:
            raise MackieProtocolError("Not connected")

        async with self._lock:
            seq = self._next_seq()
            msg = MackieMessage(seq=seq, msg_type=MackieMessageType.REQUEST, command=command, body=body)
            fut: asyncio.Future[MackieMessage] = asyncio.get_running_loop().create_future()
            self._pending[seq] = fut
            self._writer.write(msg.to_bytes())
            await self._writer.drain()

        return await asyncio.wait_for(fut, timeout=timeout)

    async def _write_message_no_response(
        self,
        msg_type: MackieMessageType,
        command: MackieCommand,
        body: bytes,
    ) -> None:
        """Send a framed message without waiting for a correlating response (used for MF snapshot pair)."""
        if len(body) % 4 != 0:
            raise ValueError("Body must be a multiple of 4 bytes")
        if not self._writer:
            raise MackieProtocolError("Not connected")
        async with self._lock:
            seq = self._next_seq()
            msg = MackieMessage(seq=seq, msg_type=msg_type, command=command, body=body)
            self._writer.write(msg.to_bytes())
            await self._writer.drain()

    async def recall_snapshot_master_fader(self, snapshot_number_1_based: int) -> None:
        """
        Recall a show snapshot the same way Master Fader does (pcap: cmd 0x07).

        Two-part sequence: REQUEST body (u32 1, u32 snapshot_index), then RESPONSE body (u32 1).
        """
        snap = int(snapshot_number_1_based)
        if snap < 1:
            raise ValueError("snapshot_number must be >= 1")
        body_a = struct.pack(">II", 1, snap)
        await self._write_message_no_response(MackieMessageType.REQUEST, MackieCommand.SHOW_SNAPSHOT, body_a)
        body_b = struct.pack(">I", 1)
        await self._write_message_no_response(MackieMessageType.RESPONSE, MackieCommand.SHOW_SNAPSHOT, body_b)

    async def send_keepalive(self) -> None:
        if not self._writer:
            return
        # Same lock as send_request so _next_seq cannot race with user writes.
        async with self._lock:
            msg = MackieMessage(
                seq=self._next_seq(),
                msg_type=MackieMessageType.REQUEST,
                command=MackieCommand.KEEP_ALIVE,
                body=b"",
            )
            self._writer.write(msg.to_bytes())
            await self._writer.drain()

    async def _initialize_connection(self) -> None:
        """
        Minimal init sequence observed in DigiMixer:
        - KeepAlive
        - ChannelInfoControl (8 bytes of zero) to permit large channel value messages
        - ClientHandshake (request, empty body)
        - GeneralInfo request type 2
        - MeterLayout + BroadcastControl (full mixer map; required for DL32-class multi-channel)
        - ChannelInfoControl request type 6 to request channel data
        """
        await self.send_keepalive()
        try:
            await self.send_request(MackieCommand.CHANNEL_INFO_CONTROL, b"\x00" * 8)
        except Exception:
            # Some mixers/firmware may not require this.
            pass
        handshake_locked_map = False
        try:
            hs = await self.send_request(MackieCommand.CLIENT_HANDSHAKE, b"")
            handshake_locked_map = _apply_handshake_input_map(self, hs.body)
        except Exception:
            pass
        try:
            await self.send_request(MackieCommand.GENERAL_INFO, bytes([0, 0, 0, 2]))
        except Exception:
            pass
        if self._mixer_model == "auto" and not handshake_locked_map:
            await _probe_auto_input_map(self)
        try:
            await self._send_digimixer_meter_and_broadcast()
        except Exception:
            pass
        try:
            await self.send_request(MackieCommand.CHANNEL_INFO_CONTROL, bytes([0, 0, 0, 6]))
        except Exception:
            pass

    async def _send_digimixer_meter_and_broadcast(self) -> None:
        """DigiMixer sends these after GeneralInfo so the mixer exposes the full value space."""
        if self._input_start_address == 41 and self._input_stride == 132:
            addrs = _dl32r_meter_addresses()
        elif self._input_start_address == 1 and self._input_stride in (100, 106):
            # DL32S needs the full 32-input DL32-family meter table for LR fader floats on all channels;
            # DL16SProfile only lists 16 input meters which is not enough for a 32-channel surface.
            addrs = (
                _dl32r_meter_addresses()
                if self._mixer_model == "dl32s"
                else _dl16s_meter_addresses()
            )
        else:
            return
        await self.send_request(MackieCommand.METER_LAYOUT, _meter_layout_body(addrs))
        await self.send_request(MackieCommand.BROADCAST_CONTROL, DIGIMIXER_BROADCAST_CONTROL_BODY)

    async def request_firmware_info(self, timeout: float = 3.0) -> MackieMessage:
        return await self.send_request(MackieCommand.FIRMWARE_INFO, b"", timeout=timeout)

    async def request_general_info(self, info_type: int, timeout: float = 3.0) -> MackieMessage:
        body = struct.pack(">I", int(info_type) & 0xFFFFFFFF)
        return await self.send_request(MackieCommand.GENERAL_INFO, body, timeout=timeout)

    async def request_channel_names(self, start_index_1_based: int, count: int, timeout: float = 3.0) -> MackieMessage:
        """
        Request `count` channel names starting at `start_index_1_based`.
        """
        start = int(start_index_1_based)
        c = int(count)
        if start < 1:
            raise ValueError("start_index must be >= 1")
        if c < 1:
            raise ValueError("count must be >= 1")
        type_ = 5
        unknown = 0
        meta = ((c & 0xFFFF) << 16) | ((type_ & 0xFF) << 8) | (unknown & 0xFF)
        body = struct.pack(">II", start & 0xFFFFFFFF, meta & 0xFFFFFFFF)
        return await self.send_request(MackieCommand.CHANNEL_NAMES, body, timeout=timeout)

    # ---- High-level mixer controls (best-effort, based on observed protocol docs) ----

    def _input_base_address(self, input_channel_1_based: int) -> int:
        if input_channel_1_based < 1:
            raise ValueError("input_channel must be >= 1")
        return self._input_start_address + (input_channel_1_based - 1) * self._input_stride

    def input_mute_address(self, input_channel_1_based: int) -> int:
        return self._input_base_address(input_channel_1_based) + self._input_mute_offset

    def input_lr_fader_address(self, input_channel_1_based: int) -> int:
        return self._input_base_address(input_channel_1_based) + self._input_fader_offset

    @property
    def input_map_start(self) -> int:
        return self._input_start_address

    @property
    def input_map_stride(self) -> int:
        return self._input_stride

    async def probe_input_channels(self, max_channel: int = 32) -> list[tuple[int, int, int, str, str]]:
        """
        Diagnostic: try reading mute + LR fader for channels 1..max_channel.
        Returns list of (channel, mute_addr, fader_addr, mute_read, fader_read).
        """
        out: list[tuple[int, int, int, str, str]] = []
        for ch in range(1, max_channel + 1):
            ma = self.input_mute_address(ch)
            fa = self.input_lr_fader_address(ch)
            md = "?"
            fd = "?"
            try:
                mv = await self.request_value_u32(ma, timeout=2.0)
                md = "none" if mv is None else f"0x{int(mv) & 0xFFFFFFFF:08x}"
            except Exception as e:
                md = f"err:{e}"
            try:
                fv = await self.request_value_u32(fa, timeout=2.0)
                fd = "none" if fv is None else f"0x{int(fv) & 0xFFFFFFFF:08x}"
            except Exception as e:
                fd = f"err:{e}"
            out.append((ch, ma, fa, md, fd))
        return out

    async def set_input_mute(self, input_channel_1_based: int, muted: bool) -> None:
        addr = self.input_mute_address(input_channel_1_based)
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, 1 if muted else 0)

    # NOTE: early subgroup helpers that stood here (class-level geometry
    # constants without a model gate) were consolidated into the single
    # gated subgroup block further down, where the map-pinned offsets live.

    async def set_input_fader(self, input_channel_1_based: int, level_0_to_1: float) -> None:
        await self.set_input_fader_level(input_channel_1_based, level_0_to_1)

    async def set_input_fader_db(self, input_channel_1_based: int, db: float) -> None:
        """
        Set LR fader using a dB value on the mixer's scale (-120 .. +10 typical).

        The wire protocol carries **float dB** (DigiMixer / Mackie Master Fader app).
        """
        addr = self.input_lr_fader_address(input_channel_1_based)
        v = float(db)
        lo, hi = _DB_POINTS[0], _DB_POINTS[-1]
        if v <= lo:
            v = lo
        elif v >= hi:
            v = hi
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        raw = struct.unpack(">I", struct.pack(">f", float(v)))[0]
        self._cache_and_notify_u32(addr, raw)

    async def set_input_fader_level(self, input_channel_1_based: int, level_0_to_1: float) -> None:
        """
        Set LR fader using a normalized level 0..1 along the mixer's dB fader curve.

        Values are converted to float dB on the wire (same convention as DigiMixer).
        """
        addr = self.input_lr_fader_address(input_channel_1_based)
        level = float(level_0_to_1)
        if level < 0.0:
            level = 0.0
        if level > 1.0:
            level = 1.0
        db = _level_to_db(level)
        body = _build_channel_values_set(address=addr, value_float=db)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        raw = struct.unpack(">I", struct.pack(">f", float(db)))[0]
        self._cache_and_notify_u32(addr, raw)

    # --- aux sends (per-input send block) ------------------------------------
    #
    # The send block is what the address map actually covers: each input strip
    # carries aux1..auxN (level, mute, pan) triples at offset 50 (pan per
    # parameter metadata; reads center). Aux master strips live in
    # addressmap blocks["auxmaster" ].

    def _aux_send_count(self) -> int:
        """How many aux sends the active input map exposes.

        Both mapped DL16S-family strides keep the send block at offset 50; only
        the count differs with stride (DL32S 106 → 8, DL16S 100 → 6). DL32R has
        no verified send block (addressmap DL32R: mute/fader only), so aux
        sends are refused there rather than guessed.
        """
        if self._input_stride == 106:
            return 8
        if self._input_stride == 100:
            return 6
        raise ValueError("aux sends are only mapped for DL32S/DL16S input strips")

    def _aux_send_address(self, input_channel_1_based: int, aux_send_1_based: int, is_mute: bool) -> int:
        n = int(aux_send_1_based)
        count = self._aux_send_count()
        if not 1 <= n <= count:
            raise ValueError(f"aux send must be 1..{count}")
        offset = AUX_SEND_FIRST_OFFSET + (n - 1) * AUX_SEND_STRIDE + (1 if is_mute else 0)
        return self._input_base_address(input_channel_1_based) + offset

    def aux_send_mute_address(self, input_channel_1_based: int, aux_send_1_based: int) -> int:
        """Address of an input's aux send mute (map field aux<m>_mute)."""
        return self._aux_send_address(input_channel_1_based, aux_send_1_based, is_mute=True)

    def aux_send_level_address(self, input_channel_1_based: int, aux_send_1_based: int) -> int:
        """Address of an input's aux send level (map field aux<m>_level)."""
        return self._aux_send_address(input_channel_1_based, aux_send_1_based, is_mute=False)

    async def set_aux_mute(self, input_channel_1_based: int, aux_send_1_based: int, muted: bool) -> None:
        """Mute or unmute an input's aux send (the aux mix page in Master Fader)."""
        addr = self.aux_send_mute_address(input_channel_1_based, aux_send_1_based)
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, 1 if muted else 0)

    async def set_aux_fader(self, input_channel_1_based: int, aux_send_1_based: int, level_0_to_1: float) -> None:
        """Set an input's aux send level from a normalized 0..1 fader position."""
        level = float(level_0_to_1)
        if level < 0.0:
            level = 0.0
        if level > 1.0:
            level = 1.0
        await self.set_aux_fader_db(input_channel_1_based, aux_send_1_based, _level_to_db(level))

    async def set_aux_fader_db(self, input_channel_1_based: int, aux_send_1_based: int, db: float) -> None:
        """Set an input's aux send level in dB on the mixer's scale (-120..+10 typical)."""
        addr = self.aux_send_level_address(input_channel_1_based, aux_send_1_based)
        v = float(db)
        lo, hi = _DB_POINTS[0], _DB_POINTS[-1]
        if v <= lo:
            v = lo
        elif v >= hi:
            v = hi
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        raw = struct.unpack(">I", struct.pack(">f", float(v)))[0]
        self._cache_and_notify_u32(addr, raw)

    def aux_send_pan_address(self, input_channel_1_based: int, aux_send_1_based: int) -> int:
        """Address of an aux send's pan (third word of the send triple)."""
        return self._aux_send_address(input_channel_1_based, aux_send_1_based, is_mute=False) + 2

    async def set_aux_pan(self, input_channel_1_based: int, aux_send_1_based: int, pan: float) -> None:
        """Set an aux send pan, -1 (left) .. +1 (right), 0 = center."""
        addr = self.aux_send_pan_address(input_channel_1_based, aux_send_1_based)
        v = max(-1.0, min(1.0, float(pan)))
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, struct.unpack(">I", struct.pack(">f", v))[0])

    # --- subgroup masters ----------------------------------------------------

    def _subgroup_address(self, subgroup_1_based: int, offset: int) -> int:
        # Only the DL32S map carries a subgroup block (addressmap.py). For the
        # other models the map must grow first, so refuse rather than guess.
        if self._mixer_model != "dl32s":
            raise ValueError("subgroup masters are only mapped for DL32S")
        n = int(subgroup_1_based)
        if not 1 <= n <= _SUBGROUP_COUNT:
            raise ValueError(f"subgroup must be 1..{_SUBGROUP_COUNT}")
        return _SUBGROUP_STRIP_BASE + (n - 1) * _SUBGROUP_STRIP_STRIDE + offset

    def subgroup_mute_address(self, subgroup_1_based: int) -> int:
        """Address of a subgroup master mute (map field subgroup.mute)."""
        return self._subgroup_address(subgroup_1_based, _SUBGROUP_MUTE_OFFSET)

    def subgroup_fader_address(self, subgroup_1_based: int) -> int:
        """Address of a subgroup master fader (map field subgroup.fader)."""
        return self._subgroup_address(subgroup_1_based, _SUBGROUP_FADER_OFFSET)

    async def set_subgroup_mute(self, subgroup_1_based: int, muted: bool) -> None:
        """Mute or unmute a subgroup master."""
        addr = self.subgroup_mute_address(subgroup_1_based)
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, 1 if muted else 0)

    async def set_subgroup_fader(self, subgroup_1_based: int, level_0_to_1: float) -> None:
        """Set a subgroup master fader from a normalized 0..1 position."""
        level = float(level_0_to_1)
        if level < 0.0:
            level = 0.0
        if level > 1.0:
            level = 1.0
        await self.set_subgroup_fader_db(subgroup_1_based, _level_to_db(level))

    async def set_subgroup_fader_db(self, subgroup_1_based: int, db: float) -> None:
        """Set a subgroup master fader in dB on the mixer's scale (-120..+10 typical)."""
        addr = self.subgroup_fader_address(subgroup_1_based)
        v = float(db)
        lo, hi = _DB_POINTS[0], _DB_POINTS[-1]
        if v <= lo:
            v = lo
        elif v >= hi:
            v = hi
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        raw = struct.unpack(">I", struct.pack(">f", float(v)))[0]
        self._cache_and_notify_u32(addr, raw)

    # --- main / aux master strips (DL32S; see addressmap blocks) --------------

    def _dl32s_only(self) -> None:
        if self._mixer_model != "dl32s":
            raise ValueError("master strips are only mapped for DL32S")

    def main_fader_address(self) -> int:
        return _MAIN_FADER_ADDRESS

    def main_mute_address(self) -> int:
        return _MAIN_MUTE_ADDRESS

    def auxmaster_fader_address(self, aux_1_based: int) -> int:
        n = int(aux_1_based)
        if not 1 <= n <= _AUXMASTER_COUNT:
            raise ValueError(f"aux master must be 1..{_AUXMASTER_COUNT}")
        return _AUXMASTER_BASE + (n - 1) * _AUXMASTER_STRIDE + _AUXMASTER_FADER_OFFSET

    def auxmaster_mute_address(self, aux_1_based: int) -> int:
        n = int(aux_1_based)
        if not 1 <= n <= _AUXMASTER_COUNT:
            raise ValueError(f"aux master must be 1..{_AUXMASTER_COUNT}")
        return _AUXMASTER_BASE + (n - 1) * _AUXMASTER_STRIDE + _AUXMASTER_MUTE_OFFSET

    async def set_main_mute(self, muted: bool) -> None:
        self._dl32s_only()
        addr = self.main_mute_address()
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, 1 if muted else 0)

    async def set_main_fader_db(self, db: float) -> None:
        self._dl32s_only()
        addr = self.main_fader_address()
        v = max(_DB_POINTS[0], min(_DB_POINTS[-1], float(db)))
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, struct.unpack(">I", struct.pack(">f", v))[0])

    async def set_auxmaster_mute(self, aux_1_based: int, muted: bool) -> None:
        self._dl32s_only()
        addr = self.auxmaster_mute_address(aux_1_based)
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, 1 if muted else 0)

    async def set_auxmaster_fader_db(self, aux_1_based: int, db: float) -> None:
        self._dl32s_only()
        addr = self.auxmaster_fader_address(aux_1_based)
        v = max(_DB_POINTS[0], min(_DB_POINTS[-1], float(db)))
        body = _build_channel_values_set(address=addr, value_float=v)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(addr, struct.unpack(">I", struct.pack(">f", v))[0])

    async def raw_set_value_int(self, address: int, value: int) -> None:
        body = _build_channel_values_set(address=address, value_int=int(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(address, int(value))

    async def raw_set_value_float(self, address: int, value: float) -> None:
        body = _build_channel_values_set(address=address, value_float=float(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(address, struct.unpack(">I", struct.pack(">f", float(value)))[0])

    async def set_values(self, values: dict[int, int], value_type: int = 5) -> None:
        """Write several addresses, one single-address message each.

        Master Fader's own messages use (address, value) pairs with a 0x2000 count
        flag, but a live DL32S parses that as start+count+values and the extra
        words spill into neighbouring addresses (proven 2026-10-18: a 2-pair
        write to 3310/4297 landed on 3310/3311/3312 instead). Singles coincide
        under both interpretations, so fan out to singles. See SPEC.md.
        """
        for addr, raw in dict(values).items():
            body = _build_channel_values_set(
                address=int(addr), value_raw_u32=int(raw), value_type=int(value_type)
            )
            await self.send_request(MackieCommand.CHANNEL_VALUES, body)
            if int(value_type) == 5:
                self._cache_and_notify_u32(int(addr), int(raw))
            else:
                self._type2_values[int(addr)] = int(raw) & 0xFFFFFFFF

    async def request_values(self, start_address: int, count: int = 1, timeout: float = 3.0) -> list[int]:
        """
        Request one or more sequential values.

        For requests, the body contains only the 2 header chunks (start + meta).
        The mixer responds with the same header chunks followed by `count` value chunks.
        """
        start = int(start_address)
        c = int(count)
        if c < 1:
            raise ValueError("count must be >= 1")

        type_ = 5
        unknown = 0
        meta = ((c & 0xFFFF) << 16) | ((type_ & 0xFF) << 8) | (unknown & 0xFF)
        body = struct.pack(">II", start & 0xFFFFFFFF, meta & 0xFFFFFFFF)
        resp = await self.send_request(MackieCommand.CHANNEL_VALUES, body, timeout=timeout)

        # Some firmware may return an empty body; treat as unknown values.
        if len(resp.body) < 8:
            return []

        resp_meta = struct.unpack_from(">I", resp.body, 4)[0]
        resp_count = (resp_meta >> 16) & 0xFFFF
        available = max(0, (len(resp.body) // 4) - 2)
        # As in _handle_channel_values: count==0 means "as many as fit", not "none".
        n = min(int(resp_count), available, c) if resp_count else min(available, c)
        out: list[int] = []
        for i in range(n):
            out.append(struct.unpack_from(">I", resp.body, (2 + i) * 4)[0])
        return out

    async def request_value_u32(self, address: int, timeout: float = 3.0) -> int | None:
        values = await self.request_values(address, 1, timeout=timeout)
        return values[0] if values else None

    # --- show archive download ----------------------------------------------
    #
    # Snapshot names are not in the value space or the name table. Master Fader
    # downloads Show.zip from the mixer and reads them out of Show.dat. This is
    # only needed to seed the list: once connected, renames arrive as 0x07 op 5
    # pushes. See tools/capture/FINDINGS.md section 3.

    #: Chunk size Master Fader uses. The mixer will not return an unbounded read.
    _FILE_CHUNK = 0x2FEC

    async def download_file(self, filename: str, timeout: float = 10.0) -> bytes:
        """Download a file from the mixer over the 0x0A/0x09/0x0C/0x0B sequence."""
        name = filename.encode("ascii")
        padded = name + b"\x00" * ((-len(name)) % 4)
        # Chunk 0 is a flag word; the rest is the word-swapped filename.
        open_body = struct.pack(">I", 0x80000004) + word_swap(padded)
        await self.send_request(MackieCommand.FILE_OPEN, open_body, timeout=timeout)

        try:
            info = await self.send_request(
                MackieCommand.FILE_INFO, struct.pack(">II", 2, 0), timeout=timeout
            )
            if len(info.body) < 12:
                raise MackieProtocolError("File info response too short")
            size = struct.unpack_from(">I", info.body, 8)[0]
            if size == 0:
                return b""

            out = bytearray()
            while len(out) < size:
                length = min(self._FILE_CHUNK, size - len(out))
                req = struct.pack(">IIII", 0, size, len(out), length)
                resp = await self.send_request(
                    MackieCommand.FILE_READ, req, timeout=timeout
                )
                # Reply echoes the 16-byte request header, then the payload.
                if len(resp.body) <= 16:
                    raise MackieProtocolError("File read returned no data")
                chunk = word_swap(resp.body[16:])[:length]
                if not chunk:
                    raise MackieProtocolError("File read returned an empty chunk")
                out.extend(chunk)
            return bytes(out[:size])
        finally:
            try:
                await self.send_request(
                    MackieCommand.FILE_CLOSE, struct.pack(">I", 0), timeout=timeout
                )
            except Exception:
                pass

    async def upload_file(
        self, filename: str, data: bytes, file_type: int = 4, timeout: float = 10.0
    ) -> None:
        """Upload a file to the mixer (POST FILE sequence).

        Determined by protocol analysis: FILE_OPEN (write) -> POST FILE
        (0x0D) chunks -> zero-length
        END chunk -> FILE_CLOSE. File bytes travel word-swapped, exactly like
        downloads in the other direction.

        ``file_type``rides in the open flags word: downloads use
        ``0x80000000 | file_type``(observed 0x80000004 for Show.zip) while
        uploads send the bare ``file_type``(RE: POST-machine open call passes
        isWrite=0). Steps after the transfer (GET FILE INFO poll, SET FILE CRC,
        PROCESS FILES) are separate methods so a live trial can confirm each.

        EXPERIMENTAL: upload has not yet been exercised against hardware.
        """
        payload = bytes(data)
        total = len(payload)
        name = filename.encode("ascii")
        padded_name = name + b"\x00" * ((-len(name)) % 4)
        open_body = struct.pack(">I", int(file_type) & 0xFFFFFFFF) + word_swap(padded_name)
        resp = await self.send_request(MackieCommand.FILE_OPEN, open_body, timeout=timeout)
        if len(resp.body) < 8 or struct.unpack_from(">I", resp.body, 0)[0] == 0:
            raise MackieProtocolError(f"File open for upload refused: {resp.body.hex()}")
        file_id = struct.unpack_from(">I", resp.body, 4)[0]
        try:
            offset = 0
            while offset < total:
                length = min(self._FILE_CHUNK, total - offset)
                chunk = word_swap(payload[offset : offset + length])
                # Pad the tail word with zeros like the app does.
                chunk = chunk + b"\x00" * ((-len(chunk)) % 4)
                body = (
                    struct.pack(">IIII", file_id, total, offset, length)
                    + chunk
                )
                ack = await self.send_request(
                    MackieCommand.POST_FILE, body, timeout=timeout
                )
                if len(ack.body) < 4 or struct.unpack_from(">I", ack.body, 0)[0] == 0:
                    raise MackieProtocolError(
                        f"POST chunk @{offset} not acknowledged: {ack.body.hex()}"
                    )
                offset += length
            # Zero-length END chunk at offset == total.
            end = await self.send_request(
                MackieCommand.POST_FILE,
                struct.pack(">IIII", file_id, total, total, 0),
                timeout=timeout,
            )
            if len(end.body) < 4 or struct.unpack_from(">I", end.body, 0)[0] != 0:
                raise MackieProtocolError(f"END of POST not accepted: {end.body.hex()}")
        finally:
            try:
                await self.send_request(
                    MackieCommand.FILE_CLOSE,
                    struct.pack(">I", file_id),
                    timeout=timeout,
                )
            except Exception:
                pass

    async def set_file_crc(self, address: int, crc32: int) -> None:
        """Commit an uploaded file: the SET FILE CRC step (0x13 write).

        From the close path: a CHANNEL_VALUES
        write of body [address, 0x00010400, crc]. The address comes from the
        transfer object's parameter; pass it explicitly until a live trial
        pins down the show-push value.
        """
        body = struct.pack(">III", int(address) & 0xFFFFFFFF, 0x00010400, int(crc32) & 0xFFFFFFFF)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def process_files(self, timeout: float = 10.0) -> None:
        """Ask the mixer to process uploaded files (op 10 on command 0x06)."""
        await self.send_request(
            MackieCommand.CHANNEL_INFO_CONTROL, struct.pack(">I", 10), timeout=timeout
        )

    async def refresh_snapshot_names(self, timeout: float = 10.0) -> Dict[int, str]:
        """Download Show.zip and load snapshot names from it.

        Returns the index -> name mapping, and leaves it in the client's cache
        where the select entity reads it.
        """
        archive = await self.download_file("Show.zip", timeout=timeout)
        names = parse_show_archive(archive)
        if names:
            self._snapshot_names = dict(names)
            self._notify_snapshot_names()
        return dict(self._snapshot_names)

    async def save_snapshot(self, snapshot_number_1_based: int, name: str) -> None:
        """Save the current state to a snapshot slot under `name` (0x07 op 5)."""
        snap = int(snapshot_number_1_based)
        if snap < 1:
            raise ValueError("snapshot_number must be >= 1")
        epoch = int(time.time())
        # Same name encoding as the CHANNEL_NAMES write (NUL-terminated,
        # word-padded, word-swapped); _pack_channel_name keeps the two in step.
        body = struct.pack(">III", 5, snap, epoch) + _pack_channel_name(name)
        await self.send_request(MackieCommand.SHOW_SNAPSHOT, body)
        self._snapshot_names[snap] = str(name).strip()
        self._notify_snapshot_names()

    async def recall_snapshot(self, address: int, snapshot_number_1_based: int) -> None:
        """
        Recall a show snapshot.

        If ``address``is non-zero: legacy single CHANNEL_VALUES int write (some DL32R setups).
        If ``address``is zero: Master Fader sequence (cmd 0x07 x2) observed on DL16S/DL32S captures.
        """
        snap = int(snapshot_number_1_based)
        if snap < 1:
            raise ValueError("snapshot_number must be >= 1")
        if address:
            await self.raw_set_value_int(address, snap)
            return
        await self.recall_snapshot_master_fader(snap)

    async def delete_snapshot(self, snapshot_number_1_based: int) -> None:
        """Delete a snapshot slot (SHOW_SNAPSHOT op 3: [3, id, epoch]).

        Snapshot opcode table, determined by protocol analysis: 1 = LOAD/recall,
        2 = STORE/save, 3 = DELETE, 5 = NAME/rename. Rename needs no separate
        opcode: op 5 carries the new name.
        """
        snap = int(snapshot_number_1_based)
        if not 1 <= snap <= 99:
            raise ValueError("snapshot_number must be 1..99")
        body = struct.pack(">III", 3, snap, int(time.time()))
        await self.send_request(MackieCommand.SHOW_SNAPSHOT, body)
        self._snapshot_names.pop(snap, None)
        self._notify_snapshot_names()

    async def reboot(self, mode: int = 1) -> None:
        """Reboot the mixer (cmd 0x05, body [mode]; 1 = normal, 2 = updater).

        DANGEROUS: drops audio and every client connection. The (2) variant is
        what the app sends after PROCESS FILES in a firmware update and after
        network-config changes.
        """
        if int(mode) not in (1, 2):
            raise ValueError("reboot mode must be 1 or 2")
        await self.send_request(MackieCommand.REBOOT, struct.pack(">I", int(mode)))

    # --- transport + show control (protocol-analysis-derived formats) ----
    #
    # Command 0x0E is one GET family with body[0] subtypes: our general-info
    # types (2/3/7/18) and transport status (8 = TRANSPORT, 9 = MULTITRACK,
    # 10 = MUSIC). Replies carry the discriminator in body[0] and payload
    # from body word 1 on; payloads are opaque status blobs.

    _TRANSPORT_SUBTYPES = {"transport": 8, "multitrack": 9, "music": 10}

    async def get_transport_status(self, kind: str = "transport") -> MackieMessage:
        """Ask for transport/multitrack/music status (0x0E body [8/9/10])."""
        try:
            subtype = self._TRANSPORT_SUBTYPES[str(kind).lower()]
        except KeyError:
            raise ValueError("kind must be transport, multitrack or music")
        return await self.request_general_info(subtype)

    # --- device admin (0x0E GET family / 0x0F SET family) ---------------------
    #
    # One generic builder covers every GET: body [selector]. Sub-opcodes
    # determined from the system-status command family
    # miner): 1 boot code, 2 max message words, 3 device name, 4 IP address,
    # 5 lock status, 6 static IP config, 7 subdevice name, 8/9/10 transport,
    # 0x12 network config, 0x13 site survey. Strings on the wire are
    # word-swapped like everything else.

    @staticmethod
    def _info_string(body: bytes) -> str:
        """Decode a NUL-terminated ASCII string starting at body word 1."""
        if len(body) < 8:
            return ""
        return word_swap(body[4:]).split(b"\x00", 1)[0].decode("ascii", "replace")

    @staticmethod
    def _info_ipv4(word: int) -> str:
        import socket as _socket

        return _socket.inet_ntoa(struct.pack(">I", int(word) & 0xFFFFFFFF))

    async def get_device_name(self, timeout: float = 10.0) -> str:
        """Read the mixer device name (0x0E body [3])."""
        return self._info_string((await self.request_general_info(3, timeout)).body)

    async def get_subdevice_name(self, timeout: float = 10.0) -> str:
        """Read the option-card subdevice name (0x0E body [7])."""
        return self._info_string((await self.request_general_info(7, timeout)).body)

    async def get_ip_address(self, timeout: float = 10.0) -> str:
        """Read the mixer IPv4 address (0x0E body [4], reply [4, ip])."""
        body = (await self.request_general_info(4, timeout)).body
        if len(body) < 8:
            raise MackieProtocolError("IP address reply too short")
        return self._info_ipv4(struct.unpack_from(">I", body, 4)[0])

    async def get_lock_status(self, timeout: float = 10.0) -> int:
        """Read the show-lock word (0x0E body [5], reply [5, lock32])."""
        body = (await self.request_general_info(5, timeout)).body
        if len(body) < 8:
            raise MackieProtocolError("Lock status reply too short")
        return struct.unpack_from(">I", body, 4)[0]

    async def get_static_ip_config(self, timeout: float = 10.0) -> dict:
        """Read the static-IP config (0x0E body [6], reply [6, flag, ip, mask, gw])."""
        body = (await self.request_general_info(6, timeout)).body
        if len(body) < 20:
            raise MackieProtocolError("Static IP config reply too short")
        flag, ip, mask, gw = struct.unpack_from(">IIII", body, 4)
        return {
            "static": bool(flag),
            "address": self._info_ipv4(ip),
            "mask": self._info_ipv4(mask),
            "gateway": self._info_ipv4(gw),
        }

    async def get_max_message_words(self, timeout: float = 10.0) -> int:
        """Read the max message size in words (0x0E body [2], reply [2, n])."""
        body = (await self.request_general_info(2, timeout)).body
        if len(body) < 8:
            raise MackieProtocolError("Max message words reply too short")
        return struct.unpack_from(">I", body, 4)[0]

    async def get_network_config(self, timeout: float = 10.0) -> list[int]:
        """Read the 65-word NetworkInfo struct (0x0E body [0x12]).

        Reply is 66 words; returns words 1..65 verbatim (opaque struct).
        """
        body = (await self.request_general_info(0x12, timeout)).body
        if len(body) < 4 + 65 * 4:
            raise MackieProtocolError("Network config reply too short")
        return list(struct.unpack_from(">65I", body, 4))

    async def site_survey(self, timeout: float = 15.0) -> list[tuple]:
        """Run a Wi-Fi site survey (0x0E body [0x13]).

        Reply: word1 = entry count N, then N x 11-word entries.
        """
        body = (await self.request_general_info(0x13, timeout)).body
        if len(body) < 8:
            return []
        (count,) = struct.unpack_from(">I", body, 4)
        entries = []
        for i in range(min(count, (len(body) - 8) // 44)):
            entries.append(struct.unpack_from(">11I", body, 8 + i * 44))
        return entries

    async def set_device_name(self, name: str, timeout: float = 10.0) -> None:
        """Set the mixer device name (0x0F body [3, ...string words])."""
        text = str(name).encode("ascii", "replace")[:1019]
        padded = text + b"\x00" * ((-len(text) - 1) % 4 + 1)
        body = struct.pack(">I", 3) + word_swap(padded)
        await self.send_request(MackieCommand.SET_SYSTEM_STATE, body, timeout=timeout)

    async def set_static_ip_config(
        self,
        static: bool,
        address: str,
        mask: str,
        gateway: str,
        timeout: float = 10.0,
    ) -> None:
        """Set static IP config (0x0F body [6, flag, ip, mask, gw]).

        WARNING: a wrong address can strand the mixer off-network. The mixer
        reboots itself after applying network changes.
        """
        import socket as _socket

        def _pack_ip(s: str) -> int:
            return struct.unpack(">I", _socket.inet_aton(s))[0]

        body = struct.pack(
            ">IIIII",
            6,
            1 if static else 0,
            _pack_ip(address),
            _pack_ip(mask),
            _pack_ip(gateway),
        )
        await self.send_request(MackieCommand.SET_SYSTEM_STATE, body, timeout=timeout)

    async def get_show_info(self, timeout: float = 10.0) -> MackieMessage:
        """Ask for show info (FILE_INFO body [5])."""
        return await self.send_request(
            MackieCommand.FILE_INFO, struct.pack(">I", 5), timeout=timeout
        )

    async def show_ok(self) -> None:
        """Send SHOW OK (SHOW_SNAPSHOT body [10]), fire-and-forget."""
        await self._write_message_no_response(
            MackieMessageType.REQUEST,
            MackieCommand.SHOW_SNAPSHOT,
            struct.pack(">I", 10),
        )

    async def get_show_crc(self, pid: int, timeout: float = 10.0) -> MackieMessage:
        """Ask for a show/file CRC (SHOW_STATUS body [pid, 0x10400]).

        ``pid``is device-side state (u32 from the transfer object); pass it
        explicitly until a live trial pins down the show-push value.
        """
        return await self.send_request(
            MackieCommand.SHOW_STATUS,
            struct.pack(">II", int(pid) & 0xFFFFFFFF, 0x00010400),
            timeout=timeout,
        )

    async def set_show_parameter(self, pid: int, value: int) -> None:
        """Write a show parameter (0x13 body [pid, 0x10300, value]).

        Same builder as SET FILE CRC with type byte 3 instead of 4.
        """
        body = struct.pack(
            ">III", int(pid) & 0xFFFFFFFF, 0x00010300, int(value) & 0xFFFFFFFF
        )
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def set_show_name(self, pid: int, name: str) -> None:
        """Set the show name (0x18 body [pid, 0x10300, word-swapped name])."""
        text = str(name).encode("ascii", "replace")[:63]
        padded = text + b"\x00" * (4 - len(text) % 4 if len(text) % 4 else 4)
        body = struct.pack(">II", int(pid) & 0xFFFFFFFF, 0x00010300) + word_swap(padded)
        await self.send_request(MackieCommand.CHANNEL_NAMES, body)

    async def disconnect_notice(self) -> None:
        """Tell the mixer this client is leaving (cmd 0x06 body [1, 4]).

        Polite form of close(); the app sends it when tearing down for an
        update. Plain close() stays silent by default.
        """
        await self.send_request(
            MackieCommand.CHANNEL_INFO_CONTROL, struct.pack(">II", 1, 4)
        )


#: Snapshot records inside Show.dat: fixed 72-byte records starting at 0x01a8,
#: name at +0, snapshot index (u32 **little-endian**) at +64, hash at +68. Record
#: order is display order, not index order.
_SHOW_DAT_RECORDS_OFFSET = 0x01A8
_SHOW_DAT_RECORD_STRIDE = 72
_SHOW_DAT_INDEX_OFFSET = 64


def parse_show_archive(archive: bytes) -> Dict[int, str]:
    """Extract {snapshot index: name} from a downloaded Show.zip.

    Inside the archive everything is plain ASCII - the word swap is a transport
    encoding only, already undone by the time the bytes get here.
    """
    if not archive[:4] == b"PK\x03\x04":
        return {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            show = zf.read("Show.dat")
    except (zipfile.BadZipFile, KeyError):
        return {}

    names: Dict[int, str] = {}
    offset = _SHOW_DAT_RECORDS_OFFSET
    while offset + _SHOW_DAT_RECORD_STRIDE <= len(show):
        record = show[offset : offset + _SHOW_DAT_RECORD_STRIDE]
        index = struct.unpack_from("<I", record, _SHOW_DAT_INDEX_OFFSET)[0]
        try:
            name = record.split(b"\x00")[0].decode("ascii").strip()
        except UnicodeDecodeError:
            name = ""
        # Empty-named records are real slots the desk has never used; skip them
        # rather than offering a blank option.
        if index and name:
            names[int(index)] = name
        offset += _SHOW_DAT_RECORD_STRIDE
    return names


def _build_channel_values_set(
    *,
    address: int,
    value_int: int | None = None,
    value_float: float | None = None,
    value_raw_u32: int | None = None,
    value_type: int = VALUE_TYPE_PARAM,
) -> bytes:
    """
    Build a 'channel values' message body that sets a single address.

    Per the protocol docs:
      chunk0 = start address
      chunk1 = Count:16 | Type:8 | Unknown:8
      remaining chunks: one 4-byte value per address

    We use Type=5 (normal channel values) and Unknown=0.
    """
    if sum(x is not None for x in (value_int, value_float, value_raw_u32)) != 1:
        raise ValueError("Provide exactly one of value_int, value_float, value_raw_u32")

    start = address & 0xFFFFFFFF
    count = 1
    unknown = 0
    meta = ((count & 0xFFFF) << 16) | ((int(value_type) & 0xFF) << 8) | (unknown & 0xFF)

    out = bytearray()
    out.extend(struct.pack(">I", start))
    out.extend(struct.pack(">I", meta))

    if value_int is not None:
        out.extend(struct.pack(">I", value_int & 0xFFFFFFFF))
    elif value_raw_u32 is not None:
        out.extend(struct.pack(">I", value_raw_u32 & 0xFFFFFFFF))
    else:
        # Fader positions use IEEE float big-endian **dB**, not a 0..1 linear level.
        out.extend(struct.pack(">f", float(value_float)))
    return bytes(out)


def _pack_channel_name(name: str) -> bytes:
    """Encode one name as a CHANNEL_NAMES payload.

    ASCII, NUL-terminated, zero-padded to a whole word, then word-swapped
    (SPEC.md, "Names" and "Text is word-swapped"). A full extra NUL word is
    appended when the text already ends on a word boundary, so the payload
    always carries at least one terminator - an unnamed slot is a bare NUL
    that still consumes an index.
    """
    raw = str(name).encode("ascii", "replace")[:63]
    pad = 4 - len(raw) % 4 if len(raw) % 4 else 4
    return word_swap(raw + b"\x00" * pad)


def _build_channel_name_write(slot: int, name: str) -> bytes:
    """Build a CHANNEL_NAMES (0x18) body writing one name slot.

    SPEC.md, "Names": the body layout matches CHANNEL_VALUES - chunk0 = start
    slot, chunk1 = count:16 | type:8 | unknown:8 - and the payload is a
    word-swapped stream of NUL-terminated names. Type 5, count 1, unknown 0,
    which is what request_channel_names uses for the read direction too.
    """
    meta = ((1 & 0xFFFF) << 16) | ((VALUE_TYPE_PARAM & 0xFF) << 8)
    return struct.pack(">II", int(slot) & 0xFFFFFFFF, meta) + _pack_channel_name(name)


# Matches DigiMixer's DbFaderScale(-120, -60, -40, -30, -20, -10, -5, 0, 5, 10)
_DB_POINTS = [-120.0, -60.0, -40.0, -30.0, -20.0, -10.0, -5.0, 0.0, 5.0, 10.0]


def _level_to_db(level_0_1: float) -> float:
    lvl = float(level_0_1)
    if lvl <= 0.0:
        return _DB_POINTS[0]
    if lvl >= 1.0:
        return _DB_POINTS[-1]

    seg_count = len(_DB_POINTS) - 1
    pos = lvl * seg_count
    idx = int(pos)
    if idx >= seg_count:
        return _DB_POINTS[-1]
    frac = pos - idx
    a = _DB_POINTS[idx]
    b = _DB_POINTS[idx + 1]
    return a + (b - a) * frac


def _db_to_level(db: float) -> float:
    v = float(db)
    if v <= _DB_POINTS[0]:
        return 0.0
    if v >= _DB_POINTS[-1]:
        return 1.0

    for i in range(len(_DB_POINTS) - 1):
        a = _DB_POINTS[i]
        b = _DB_POINTS[i + 1]
        if a <= v <= b:
            frac = 0.0 if b == a else (v - a) / (b - a)
            return (i + frac) / (len(_DB_POINTS) - 1)
    return 0.0


def input_fader_u32_to_percent(raw_u32: int) -> float:
    """
    Convert a channel-values u32 (IEEE float dB on the wire) to 0..100 for Home Assistant.
    """
    try:
        f = struct.unpack(">f", struct.pack(">I", int(raw_u32) & 0xFFFFFFFF))[0]
    except Exception:
        return 0.0
    if f != f:  # NaN
        return 0.0
    if f <= _DB_POINTS[0]:
        return 0.0
    if f >= _DB_POINTS[-1]:
        return 100.0
    lvl = _db_to_level(float(f))
    return float(max(0.0, min(100.0, lvl * 100.0)))

