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
    CHANNEL_INFO_CONTROL = 0x06
    # Master Fader snapshot/show recall (observed on wire; not in public DigiMixer enum).
    SHOW_SNAPSHOT = 0x07
    # File transfer, used to fetch Show.zip (which is where snapshot names live).
    # See tools/capture/FINDINGS.md section 3.
    FILE_INFO = 0x09
    FILE_OPEN = 0x0A
    FILE_CLOSE = 0x0B
    FILE_READ = 0x0C
    GENERAL_INFO = 0x0E
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
    the caller should run address probing for ``auto`` mode.
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

    async def connect(self) -> None:
        if self._rx_task:
            return
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        self._rx_task = asyncio.create_task(self._rx_loop(), name="mackie_dl_rx")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="mackie_dl_keepalive")

        await self._initialize_connection()

    async def close(self) -> None:
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        if self._rx_task:
            self._rx_task.cancel()
            self._rx_task = None
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None

        for fut in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        self._listeners.clear()
        self._global_listeners.clear()

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
                            fut.set_exception(MackieProtocolError("Mixer returned ERROR response"))
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
        # Only handle type=5 (normal values); type 1 is meters, which we ignore.
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

    async def raw_set_value_int(self, address: int, value: int) -> None:
        body = _build_channel_values_set(address=address, value_int=int(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(address, int(value))

    async def raw_set_value_float(self, address: int, value: float) -> None:
        body = _build_channel_values_set(address=address, value_float=float(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)
        self._cache_and_notify_u32(address, struct.unpack(">I", struct.pack(">f", float(value)))[0])

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
        text = str(name).encode("ascii", "replace")[:63]
        padded = text + b"\x00" * (4 - len(text) % 4 if len(text) % 4 else 4)
        epoch = int(time.time())
        body = struct.pack(">III", 5, snap, epoch) + word_swap(padded)
        await self.send_request(MackieCommand.SHOW_SNAPSHOT, body)
        self._snapshot_names[snap] = str(name).strip()
        self._notify_snapshot_names()

    async def recall_snapshot(self, address: int, snapshot_number_1_based: int) -> None:
        """
        Recall a show snapshot.

        If ``address`` is non-zero: legacy single CHANNEL_VALUES int write (some DL32R setups).
        If ``address`` is zero: Master Fader sequence (cmd 0x07 x2) observed on DL16S/DL32S captures.
        """
        snap = int(snapshot_number_1_based)
        if snap < 1:
            raise ValueError("snapshot_number must be >= 1")
        if address:
            await self.raw_set_value_int(address, snap)
            return
        await self.recall_snapshot_master_fader(snap)


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

    Per reverse-engineered docs:
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

