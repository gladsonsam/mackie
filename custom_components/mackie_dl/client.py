from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional


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
    GENERAL_INFO = 0x0E
    CHANNEL_VALUES = 0x13
    BROADCAST_CONTROL = 0x15
    METER_LAYOUT = 0x16
    CHANNEL_NAMES = 0x18


HEADER0 = 0xAB


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


class MackieClient:
    """
    Minimal async client for Mackie DL-series TCP protocol (port 50001).

    This implements message framing + request/response correlation by sequence number.
    """

    def __init__(self, host: str, port: int = 50001) -> None:
        self._host = host
        self._port = port

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

        self._seq = 0
        self._rx_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None

        self._pending: Dict[int, asyncio.Future[MackieMessage]] = {}
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        if self._rx_task:
            return
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        self._rx_task = asyncio.create_task(self._rx_loop(), name="mackie_dl_rx")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="mackie_dl_keepalive")

        # The protocol usually expects early traffic; keep-alive is safe (empty body).
        await self.send_keepalive()

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
                if msg.msg_type in (MackieMessageType.RESPONSE, MackieMessageType.ERROR):
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

    async def send_keepalive(self) -> None:
        if not self._writer:
            return
        msg = MackieMessage(
            seq=self._next_seq(),
            msg_type=MackieMessageType.REQUEST,
            command=MackieCommand.KEEP_ALIVE,
            body=b"",
        )
        self._writer.write(msg.to_bytes())
        await self._writer.drain()

    # ---- High-level mixer controls (best-effort, based on observed protocol docs) ----

    @staticmethod
    def _input_base_address(input_channel_1_based: int) -> int:
        # From protocol notes (DL16S layout): inputs are 100 bytes each, starting at address 1.
        # DL32S is expected to follow the same input block stride for the first 32 inputs.
        if input_channel_1_based < 1:
            raise ValueError("input_channel must be >= 1")
        return 1 + (input_channel_1_based - 1) * 100

    @classmethod
    def input_mute_address(cls, input_channel_1_based: int) -> int:
        # Offset 8 for mute (1-based address list, so base+7)
        return cls._input_base_address(input_channel_1_based) + 7

    @classmethod
    def input_lr_fader_address(cls, input_channel_1_based: int) -> int:
        # Offset 9 for LR fader (base+8)
        return cls._input_base_address(input_channel_1_based) + 8

    async def set_input_mute(self, input_channel_1_based: int, muted: bool) -> None:
        addr = self.input_mute_address(input_channel_1_based)
        body = _build_channel_values_set(address=addr, value_int=1 if muted else 0)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def set_input_fader(self, input_channel_1_based: int, level_0_to_1: float) -> None:
        addr = self.input_lr_fader_address(input_channel_1_based)
        level = float(level_0_to_1)
        if level < 0.0:
            level = 0.0
        if level > 1.0:
            level = 1.0
        body = _build_channel_values_set(address=addr, value_float=level)
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def raw_set_value_int(self, address: int, value: int) -> None:
        body = _build_channel_values_set(address=address, value_int=int(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def raw_set_value_float(self, address: int, value: float) -> None:
        body = _build_channel_values_set(address=address, value_float=float(value))
        await self.send_request(MackieCommand.CHANNEL_VALUES, body)

    async def recall_snapshot(self, address: int, snapshot_number_1_based: int) -> None:
        """
        Recall a snapshot via a single channel-values write.

        Mackie doesn't publish this, and Jon Skeet's public DigiMixer code doesn't include
        snapshot recall yet. Different firmware/models may use different addresses.

        This method lets us wire snapshot recall cleanly in Home Assistant once the
        correct address is known (set via config).
        """
        if not address:
            raise MackieProtocolError("Snapshot recall address is not configured")
        snap = int(snapshot_number_1_based)
        if snap < 1:
            raise ValueError("snapshot_number must be >= 1")
        await self.raw_set_value_int(address, snap)


def _build_channel_values_set(
    *,
    address: int,
    value_int: int | None = None,
    value_float: float | None = None,
    value_raw_u32: int | None = None,
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
    type_ = 5
    unknown = 0
    meta = ((count & 0xFFFF) << 16) | ((type_ & 0xFF) << 8) | (unknown & 0xFF)

    out = bytearray()
    out.extend(struct.pack(">I", start))
    out.extend(struct.pack(">I", meta))

    if value_int is not None:
        out.extend(struct.pack(">I", value_int & 0xFFFFFFFF))
    elif value_raw_u32 is not None:
        out.extend(struct.pack(">I", value_raw_u32 & 0xFFFFFFFF))
    else:
        out.extend(struct.pack(">f", float(value_float)))
    return bytes(out)

