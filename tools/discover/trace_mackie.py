#!/usr/bin/env python3
"""Frame tracer for the Mackie DL connection. READ-ONLY - sends no value writes.

    python3 tools/discover/trace_mackie.py <mixer-ip> --seconds 12

The init sequence in client.py wraps several steps in ``except: pass``, so a step
the mixer REJECTS looks identical to one that succeeded. When the mixer is
reachable but no values ever arrive, this is the tool that says why: it prints
every frame in both directions with its type, command and body.

This is how the count==0 bulk-push behaviour was found - the frames were plainly
arriving with 3074 chunks while the parser was storing nothing.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

import _bootstrap  # noqa: F401
import client as C  # noqa: E402

T0 = time.monotonic()


def stamp() -> str:
    return f'{time.monotonic() - T0:7.3f}'


def describe(msg: 'C.MackieMessage') -> str:
    try:
        mt = C.MackieMessageType(msg.msg_type).name
    except ValueError:
        mt = f'type{msg.msg_type}'
    try:
        cmd = C.MackieCommand(msg.command).name
    except ValueError:
        cmd = f'cmd0x{msg.command:02x}'
    body = msg.body.hex()
    if len(body) > 160:
        body = body[:160] + f'...(+{(len(msg.body) - 80)}B)'
    return f'{mt:9} {cmd:20} seq={msg.seq:<3} chunks={msg.chunk_count:<4} {body}'


_orig_read = C.MackieClient._read_one_message
_orig_send_request = C.MackieClient.send_request
_orig_send_response = C.MackieClient._send_response


async def traced_read(self):
    msg = await _orig_read(self)
    print(f'{stamp()} RX  {describe(msg)}', flush=True)
    return msg


async def traced_send_request(self, command, body, timeout=3.0):
    try:
        name = C.MackieCommand(command).name
    except ValueError:
        name = str(command)
    print(f'{stamp()} TX  REQUEST   {name:20} body={body.hex()}', flush=True)
    try:
        return await _orig_send_request(self, command, body, timeout=timeout)
    except Exception as exc:
        print(f'{stamp()} !!  {name} FAILED: {type(exc).__name__}: {exc}', flush=True)
        raise


async def traced_send_response(self, *, seq, command, body):
    try:
        name = C.MackieCommand(command).name
    except ValueError:
        name = str(command)
    print(f'{stamp()} TX  RESPONSE  {name:20} seq={seq} body={body.hex()}', flush=True)
    return await _orig_send_response(self, seq=seq, command=command, body=body)


C.MackieClient._read_one_message = traced_read
C.MackieClient.send_request = traced_send_request
C.MackieClient._send_response = traced_send_response


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('--port', type=int, default=50001)
    ap.add_argument('--model', default='dl32s')
    ap.add_argument('--seconds', type=float, default=20.0)
    ap.add_argument('--probe', action='store_true',
                    help='after init, issue a single CHANNEL_VALUES read of address 1')
    args = ap.parse_args()

    cl = C.MackieClient(args.host, args.port, mixer_model=args.model)
    await cl.connect()
    print(f'{stamp()} --- init complete, idling ---', flush=True)

    if args.probe:
        for addr, count in ((1, 1), (1, 8), (8, 1), (9, 1)):
            try:
                vals = await cl.request_values(addr, count, timeout=4.0)
                print(f'{stamp()} ??  request_values({addr},{count}) -> {vals}', flush=True)
            except Exception as exc:
                print(f'{stamp()} ??  request_values({addr},{count}) FAILED {exc}', flush=True)

    await asyncio.sleep(args.seconds)
    print(f'{stamp()} --- done, {len(cl._values)} cached values ---', flush=True)
    await cl.close()


if __name__ == '__main__':
    asyncio.run(main())
