# Capture findings — DL32S

Source: `captures/mackie-session1.pcapng`, two full Master Fader (Windows) sessions,
1879 frames. Captured with `pktmon` on the machine running Master Fader.

## 1. Text on the wire is word-swapped

Every string in the protocol is stored as 4-byte words with the bytes reversed
inside each word — little-endian characters inside an otherwise big-endian
protocol. `MGZU` goes out as `55 5a 47 4d`.

This is why a naive ASCII scan finds nothing. `word_swap()` in
`analyze_capture.py` undoes it.

Confirmed by watching a rename arrive one keystroke at a time:

```
0000474d -> "MG"      005a474d -> "MGZ"     555a474d -> "MGZU"
555a474d 0000554c -> "MGTOKEN"
```

## 2. Mute group names live in the CHANNEL_NAMES table

`CHANNEL_NAMES` (0x18) is one flat table of 75 slots, pushed by the mixer during
the connect handshake and written one slot at a time. Body layout matches
`CHANNEL_VALUES`: chunk 0 is the start index, chunk 1 is count/type, the rest is
a word-swapped stream of NUL-terminated names. Empty slots are a bare NUL and
still consume an index.

| Slots | Contents |
|---|---|
| 1-32 | input channels |
| 33-49 | returns / FX (unnamed on the test desk) |
| 50-57 | 8 aux outputs |
| 58-63 | 6 subgroups |
| **64-69** | **6 mute groups** |
| 70-75 | 6 VCAs |

Renaming mute group 1 wrote slot **64**, so mute group *N* is slot **63 + N**.
The 6/6/6 layout agrees with the input strip's 6 mute-group, 6 subgroup and
6 VCA membership offsets already in `addressmap.py`.

Reading these needs no new command — only parsing the 0x18 response that
`client.py` currently answers and discards.

## 3. Snapshot names live in a show archive, not in the value space

Nothing in the value space or the name table carries snapshot names. Master
Fader downloads `Show.zip` from the mixer over a small file-transfer protocol,
which accounts for five previously unknown commands:

| Command | Role | Body |
|---|---|---|
| `0x0A` | open file | `80000004` + word-swapped filename (`"Show.zip"`) |
| `0x09` op2 | get size | replies `... <u32 size> <u32 id>` |
| `0x0C` | read chunk | `<flags><size><offset><length>`; reply is 16-byte echo + word-swapped data |
| `0x0B` | close | `00000000` |
| `0x12` | status poll | `00000001 00010400` |

Reassembled from this capture, byte-exact at 18225 bytes, magic `PK\x03\x04`:

```
Show.dat  Snapshot1.dat  Snapshot2.dat  Snapshot3.dat
Snapshot5.dat  Snapshot6.dat  Show.png  Notes.txt
```

**Inside the zip the contents are plain ASCII** — the word-swap is a transport
encoding only.

### Show.dat snapshot records

Show name at 0x0008. Snapshot records start at **0x01a8**, stride **72 bytes**:

| Offset in record | Field |
|---|---|
| 0 | name, NUL-padded |
| 64 | snapshot index, u32 **little-endian** |
| 68 | u32 hash / id |

From this capture:

```
0x01a8 'SNAPTOKEN'    index=1      0x0280 'Snapshot E'  index=5
0x01f0 'Snapshot D'   index=6      0x02c8 'Snapshot B'  index=2
0x0238 'Snapshot C'   index=3      0x0310 ''            index=4
```

Record order is display order, not index order. The empty record is index 4, and
the archive has no `Snapshot4.dat` — an independent cross-check that the index
field is read correctly.

## 4. Snapshot save is SHOW_SNAPSHOT op 5

`SHOW_SNAPSHOT` (0x07) is multi-op, selected by the first body word:

- **op 1** — recall. `00000001 <snapshot number>`. Already implemented.
- **op 5** — save with name: `00000005 <number> <unix epoch> <word-swapped name>`

Observed: `00000005 00000001 6a810f68` + `SNAPTOKEN`.

The mixer echoes the same frame back to other connected clients as a Request,
which is how a second client learns about the change.

## 5. Membership offsets verified against hardware

Adding channel 5 to mute group 3 wrote address **509**:

```
509 = 1 + (5-1)*106 + 84      offset 84 = mutegroup3
```

Confirms the existing `addressmap.py` mute-group membership block on live
hardware.

## 6. Mute group masters are a separate type-2 address space

Source: `captures/mackie-mutegroups.pcapng` — all six groups toggled on then off
in order, nothing else touched. Twelve events, perfectly regular:

```
t+41.88  0000000b 00010200 00000001     MG1 on
t+48.89  0000000b 00010200 00000000     MG1 off
t+53.41  0000000c 00010200 00000001     MG2 on
...
t+88.50  00000010 00010200 00000000     MG6 off
```

**Mute group N master = address 10 + N**, written as `CHANNEL_VALUES` with
`count=1`, **`type=2`**, value 1 = muted, 0 = unmuted.

| Group | Address |
|---|---|
| 1-6 | 11, 12, 13, 14, 15, 16 |

The `type` field selects the address space and is not decoration. The ordinary
parameter space is type 5, where address 11 is input channel 1's `main_assign`.
Writing a mute group with type 5 would hit an unrelated parameter.

This also explains the ambiguous frames in the first capture: the `type=2`
address-12 write there was mute group 2, and the `0x20020200` meta belonged to a
different interaction, not to a mute group toggle.

### State is pushed to other clients, never echoed to the sender

The mixer does **not** answer the client that made the change — during twelve
self-driven toggles it sent back only an empty response. That looks like
"write-only" if one client is both actor and observer, and it is not.

Source: `captures/mackie-ipad-push.pcapng` — mute groups toggled **on the iPad**
while the PC's connection was captured and left untouched. The PC received
unsolicited Requests:

```
t+30.48  M>C  addr=11 count=1 type=2 val=1     MG1 muted   (from iPad)
t+35.67  M>C  addr=11 count=1 type=2 val=0     MG1 unmuted
t+38.27  M>C  addr=12 count=1 type=2 val=1     MG2 muted
t+43.67  M>C  addr=12 count=1 type=2 val=0     MG2 unmuted
```

So a Home Assistant switch **can** track changes made from the iPad. Suppressing
the echo to the originating client is normal for this protocol — `SHOW_SNAPSHOT`
op 5 behaves the same way.

Initial state is covered too. At connect the mixer pushes a **bulk type-2 dump**
— start 1, `count = 0`, 436 bytes = 107 values — and the mute group masters are
addresses 11-16 within it:

```
type-2 frame: Req start=1 count=0 meta=0x00000200 bodylen=436
```

As in the type-5 space, `count == 0` means "as many as fit", not "none".

The rest of that 107-address space is unmapped and holds a mix of integers and
floats. Only 11-16 are identified.

Caveat: in the one connect dump captured, all six read 0 while all six groups
were in fact unmuted — consistent, but it does not by itself prove the field is
populated rather than merely zero. Any wrong initial reading self-corrects on
the first change from either side. Confirming it properly means muting a group,
reconnecting, and checking that address 11 reads 1.

### Name changes propagate the same way

Renaming mute group 3 on the iPad arrived on the PC's connection as `0x18`
writes to **slot 66** — one per keystroke, confirming `slot = 63 + N`:

```
slot=66  'M' -> 'MGT' -> 'MGTANG' -> 'MGTANGO'
```

Live name updates therefore need no polling and no file transfer: parse inbound
`0x18` writes. The `Show.zip` download is only needed to seed snapshot names at
connect.
