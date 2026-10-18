# Protocol and address map

The Mackie DL protocol is undocumented. Everything here comes from observation,
either against a DL32S for this project or from [Jon Skeet's DigiMixer][digimixer],
which was derived independently and agrees wherever the two overlap.

[digimixer]: https://github.com/jskeet/DemoCode/tree/main/DigiMixer

## Transport

One client-initiated TCP connection, default port **50001**. All values big-endian.

```
0xAB | seq | chunk count (u16) | type | command | header checksum (u16)
     | body (4-byte chunks) | body checksum (u32)
```

Header checksum is `0xFFFF` minus the sum of the header bytes; body checksum is
`0xFFFFFFFF` minus the sum of the body bytes. With zero chunks, both body and body
checksum are absent.

Message types: Request (0), Response (1), Error (5), Broadcast (8).

The mixer also sends requests *to* the client and expects answers. Ignoring them
stalls the connection, so `_handle_request` replies to `CLIENT_HANDSHAKE`,
`GENERAL_INFO`, `CHANNEL_INFO_CONTROL`, `CHANNEL_VALUES` and `CHANNEL_NAMES`.

| Command | Value | Purpose |
|---|---|---|
| `KEEP_ALIVE` | `0x01` | First request, then every 2.5s |
| `CLIENT_HANDSHAKE` | `0x03` | Exchanged once each way |
| `FIRMWARE_INFO` | `0x04` | Version detail |
| `CHANNEL_INFO_CONTROL` | `0x06` | Message size limit, and request a full value dump |
| `SHOW_SNAPSHOT` | `0x07` | Snapshot recall |
| `GENERAL_INFO` | `0x0E` | Model name and similar |
| `CHANNEL_VALUES` | `0x13` | Read, write and report values |
| `BROADCAST_CONTROL` | `0x15` | Enable periodic meter reports |
| `METER_LAYOUT` | `0x16` | Choose which meters are reported |
| `CHANNEL_NAMES` | `0x18` | Channel name table |

## Two behaviours that will catch you out

### The mixer pushes, it does not serve

After init the mixer sends its **entire value space unprompted**, as `CHANNEL_VALUES`
requests. On a DL32S that is 3072 values from address 1, then 2185 from address 3073.

An explicit `CHANNEL_VALUES` read request returns an **empty body**. Polling does not
work. Listening does. This is why `iot_class` is `local_push`.

### Bulk pushes carry `count = 0`

Those pushes set the meta word to `0x00000500`: type 5, count **zero**, with the real
length implied by the message size. Small messages do set count correctly, so the
field cannot just be ignored:

```python
available = (len(body) // 4) - 2
n = min(count, available) if count else available   # 0 means "as many as fit"
```

Reading count literally makes `min(0, 3072)` discard every pushed value. The
integration can then still write to the mixer but never learns any state back.

Both `_handle_channel_values` and `request_values` need this rule.

## Value messages

```
Chunk 0: start address
Chunk 1: count (u16) | type (u8) | unknown (u8)      type 5 = values, 1 = meters, 2 = mute groups
Chunk 2+: one value per chunk
```

Levels are IEEE-754 floats in dB. Switches and enums are plain `u32`.

### Type selects the address space

`type` is not a data-type tag, it picks which space the address is in. Address 11
is input 1's `main_assign` under type 5 and mute group 1's master under type 2.
Caching both in one dict silently corrupts each other, so `client.py` keeps
`_values` (type 5) and `_type2_values` separate.

Type 2 holds about 107 addresses, pushed in bulk at connect with `count = 0`.
Only 11-16 are identified: **mute group N master = address 10 + N**, 1 = muted.

## Text is word-swapped

Every string on the wire — channel names, snapshot names, filenames, file
payloads — is stored as 4-byte words with the bytes reversed inside each word:
little-endian characters in a big-endian protocol. `MGZU` travels as
`55 5a 47 4d`. `word_swap()` undoes it.

Inside a downloaded archive the contents are plain ASCII; the swap is a transport
encoding only.

## Snapshots

`SHOW_SNAPSHOT` (0x07) is multi-op, selected by the first body word.

- **op 1 — recall.** `00000001 <number>`. The mixer answers `1`.
  (The **snapshot recall address** option can instead select a legacy single
  `CHANNEL_VALUES` write, needed by some DL32R setups. Leave it at 0 otherwise.)
- **op 5 — save with name.** `00000005 <number> <unix epoch> <word-swapped name>`.

The mixer relays both to every *other* connected client as a Request, which is
how a second client learns that a snapshot was recalled or renamed. It does not
echo back to the client that made the change, so a client must cache its own
writes.

### Snapshot names live in a show archive

Names are in neither the value space nor the name table. The client downloads
`Show.zip` from the mixer:

| Command | Role |
|---|---|
| `0x0A` | open file — flag word + word-swapped filename |
| `0x09` op2 | file size |
| `0x0C` | read chunk — `<flags><size><offset><length>`, reply echoes 16 bytes then data |
| `0x0B` | close |

`Show.dat` inside it holds 72-byte snapshot records from `0x01a8`: name at +0,
index as u32 **little-endian** at +64. Record order is display order, not index
order.

This download only seeds the list; op-5 pushes keep it current afterwards.

## Names

`CHANNEL_NAMES` (0x18) is one flat table, pushed at connect and written one slot
at a time on rename. Body layout matches `CHANNEL_VALUES`; the payload is a
word-swapped stream of NUL-terminated names. **An unnamed slot is a bare NUL and
still consumes an index**, so blanks must be kept while numbering.

| Slots | Contents |
|---|---|
| 1-32 | input channels |
| 50-57 | 8 aux outputs |
| 58-63 | 6 subgroups |
| 64-69 | 6 mute groups (group N = slot 63 + N) |
| 70-75 | 6 VCAs |

## Address space

Every parameter has an address in one flat space. A DL32S exposes 5257 of them.
Channel strips are regular arrays:

```
address = base + (channel - 1) * stride + offset
```

### Offsets are not addresses

`addressmap.py` stores **offsets**. Channel 1's mute is offset 7, at address 8.
DigiMixer's notes tabulate channel 1 *addresses*, which read one higher. Confusing
the two is a silent off-by-one where every field reports its neighbour and still
looks plausible.

The check that catches it: **channel 2's mute must be address 114**. `verify_map.py`
asserts exactly that.

### Input strips

| Model | Base | Stride | Inputs | Aux sends |
|---|---|---|---|---|
| DL16S | 1 | 100 | 16 | 6 |
| DL32S | 1 | 106 | 32 | 8 |
| DL32R | 41 | 132 | 32 | not mapped |

Stride 106 was established by scoring all 32 channels: at 106, every channel shows a
boolean at offset 7 and a dB float at offset 8. Strides 100 and 132 score 22/32 and
21/32.

The head of the strip is identical between DL16S and DL32S. The whole stride
difference is two extra aux sends:

```
DL16S  100 = 50 head + 18 (6 aux x 3) + 8 (4 fx x 2) + 24 membership
DL32S  106 = 50 head + 24 (8 aux x 3) + 8 (4 fx x 2) + 24 membership
```

The aux count is corroborated structurally: the value space holds nine 90-word output
strips (main LR plus 8 aux), matching the eight send triples per input.

### DL32S input offsets

| Offset | Field | Offset | Field |
|---|---|---|---|
| 0-2 | `source_a`, `source_b`, `source_select` | 24-25 | `comp_mode`, `comp_on` |
| 3 | `trim` | 26-31 | `comp_p1` to `comp_p6` |
| 4-5 | `icon`, `colour` | 32-33 | `eq_mode`, `eq_on` |
| 6 | `polarity` | 34 | `eq_bands` |
| **7** | **`mute`** | 35-38 | EQ band 4: gain, freq, Q, type |
| **8** | **`fader`** (LR) | 39-42 | EQ band 3 |
| 9-11 | `pan`, `main_assign`, `stereo_link` | 43-46 | EQ band 2 |
| 12 | `gain` | 47-49 | EQ band 1: gain, freq, Q |
| 13 | `phantom` | 50-73 | `aux1` to `aux8`: level, mute, unknown |
| 14-15 | `hpf_on`, `hpf_freq` | 74-81 | `fx1` to `fx4`: level, mute |
| 16 | unknown | 82-87 | mute group membership |
| 17-18 | `gate_mode`, `gate_on` | 88-93 | view membership |
| 19 | `gate_threshold` | 94-99 | subgroup membership |
| 20-23 | `gate_p1` to `gate_p4` | 100-105 | VCA membership |

Band 4 is the top band. Band 1 has three words rather than four, with no filter-type
word.

43 of the 106 fields are marked `verified=False`: their position is certain, but
their meaning is inferred from structure rather than watched changing in response to
a known control movement. `get_parameter` returns this flag.

### Beyond the inputs

Inputs occupy 1-3392. The rest is mapped structurally but deliberately left
unlabelled, since naming a field without watching it change is guesswork.

| Addresses | Structure |
|---|---|
| 3393-4041 | returns, FX outputs, FX parameters, FX inputs |
| 4042-4347 | 6 strips of 51 words: subgroups |
| 4395-5204 | 9 strips of 90 words: main LR plus 8 aux outputs |
| 5226-5257 | 32 sequential integers: output and USB mapping |

## Coverage versus surface

A DL32S input strip has around 50 meaningful fields. An entity per field per channel
would be 1200+ entities, which makes the UI slow and bloats the recorder database.

So the two are separated:

- **Coverage** is the address map plus `set_parameter` and `get_parameter`. Anything
  in `addressmap.py` is reachable immediately, with no new code.
- **Surface** is a small curated set of entities: mute and LR level per channel, and
  snapshot recall.

Adding a parameter means adding one row to `addressmap.py`. Adding an *entity* is a
separate, deliberate decision about what belongs on a dashboard.

## Home Assistant notes

Config entry version 5. Connection settings (`host`, `port`, `channels`,
`mixer_model`) live in `data`; preferences (`device_name`, `snapshot_slots`,
`snapshot_recall_address`) live in `options`. Reads merge both through
`config_entry_merged`.

The resync loop must be created with `entry.async_create_background_task`.
`hass.async_create_task` registers a task Home Assistant waits for during startup,
and since the loop never returns it stalls bootstrap until it times out.

## Working on the protocol

Everything in `tools/discover/` is read-only. `client.py` and `addressmap.py` have no
`homeassistant` imports, so they run under plain Python.

After a firmware update:

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --model dl32s > dump.tsv
python3 tools/discover/verify_map.py dump.tsv --model dl32s
```

To identify an unknown field:

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --settle 15 --watch 30 > out.tsv
# move exactly one control on the mixer during the watch window
tail -20 out.tsv    # the changes block names the address
```

Because the layout is `base + (channel-1) * stride + offset`, solving one offset on
channel 1 solves it for every channel.

If the mixer connects but no values arrive, `trace_mackie.py` prints every frame and
will show which init step is being refused.

Run these on the mixer's network. Over a VPN the init burst can straddle the settle
window and you will silently collect a partial dump.

## Caveats

- Firmware may change the layout. Re-run `verify_map.py` after updates.
- DL16S and DL32R maps are inherited from DigiMixer and unverified here. For the
  DL16S, the head and send block are safe but the EQ block is not.
- DL32R input stride settled at **132**: protocol analysis shows
  the `* 0x86 = 134` accessor reads the DL32R **type-2** list, while the input
  accessor multiplies by 0x84 = 132 with faders landing at 49/181/313... for
  base 41. Trust mute and fader; the rest of the DL32R map is still DigiMixer
  inheritance. (An earlier reading had these backwards: the 134-accessor and
  the 87-stride output accessor index different tables. Open question
  until a DL32R is on the bench.)
- Discovery reads are safe on a live mixer. `raw_set_value` sweeps are not: save the
  show first and work with outputs muted.

## Protocol notes (Master Fader wire behavior)

Message formats below were determined by protocol analysis against Master
Fader 5.2's wire traffic and validated against live hardware; every claim
names its evidence inline.

### Parameter semantics

The DL32S parameter model resolves to `SNAPSHOT_<CHANNEL>_<PARAM>` keys, e.g.
`SNAPSHOT_INPUT2_GATE_ATTACK`, `SNAPSHOT_INPUT2_COMP_RATIO`,
`SNAPSHOT_INPUT2_AUXSEND1_PAN`, `SNAPSHOT_INPUT2_MUTEGROUP3_ASSIGN`,
`SNAPSHOT_SUB_GROUP_P1_MUTE`, `SNAPSHOT_MAIN_OUT_FADER`,
`SNAPSHOT_AUX1_FADER`. The ordering independently confirms: gate =
THRESH/ATTACK/RELEASE/RANGE/HOLD at offsets 19-23, comp =
GAIN/THRESH/ATTACK/RELEASE/RATIO/KNEE at 26-31, aux sends = FADER/MUTE/PAN
triples, membership = MUTEGROUP/USERBANK/SUBGROUP/VCA ASSIG at 82-105
(`USERBANK` keys the view groups in the parameter metadata; the map keeps
calling them `view`).

Two anomalies to know about. First, EQ band parameter order runs
TYPE/GAIN/FREQ/Q while the wire order is GAIN/FREQ/Q/TYPE (proven by live
values: band 4 gain +5.276 dB @35, freq 17250 @36, Q 2.0 @37, type 2 @38).
The gate 21/22/23 assignment (RELEASE/RANGE/HOLD) rests on that ordering plus
tuned-value plausibility and still wants a live knob-move confirmation.
Second, `unknown_16` is resolved: the keys name it `HPF_SLOPE` (constant 2
everywhere).

### Output strips

A re-read overturned the first layout: subgroup strips are
**mute-first** (mute 4041+51i, fader 4042+51i; 4049 is COMP ENABLE, not
mute). MAINOUT is one 87-word strip from **4347** (fader@0, mute@1,
balance@2, HPF 47-50, LPF 51-54). Aux masters are 8x90 from **4434**
(mute@3, fader@4). "4395 stride 90" was a misread: 4395 is MAINOUT's HPF
frequency word. Live corroboration: 4041=0/4042=-120 (x6), 4347=-0.83/4348=0,
4437=0/4438=+0.83. VCA masters have no value-space strips (app-side only).

### Multi-address writes are (address, value) pairs

Master Fader's CHANNEL_VALUES writes use pairs: chunk0 = addr0, chunk1 =
meta, chunk2 = val0, then (addrN, valN). The meta count carries a `0x2000`
flag bit:
`meta = ((count | 0x2000) << 16) | (type << 8)`. Single-address writes coincide
with the old layout except for that bit, so existing single-write paths are
untouched.

**Live correction 2026-10-18:** DL32S firmware parses the pairs layout as
plain start+count+values — a 2-pair write to {3310, 4297} landed on
3310/3311/3312 instead (caught by the recorder, restored immediately). So on
this firmware generation multi-writes fan out to singles in `set_values()`;
there is deliberately no pairs builder. Singles coincide under both
interpretations and are proven live in both directions.

### File upload (POST FILE)

Upload sequence: FILE_OPEN (write) -> POST FILE (`0x0D`) chunks ->
zero-length END chunk -> FILE_CLOSE -> SET FILE CRC -> PROCESS FILES.
Exact wire forms:

- OPEN (write): body `[file_type] + word_swapped(name)` — the bare type, NO
  `0x80000000` bit. Downloads use `0x80000000 | type` (observed `0x80000004`
  for Show.zip); uploads clear the top bit (`word0 = (isWrite << 31) | type`
  with `isWrite = 0`). Reply `[nonzero, id]` = open,
  `[0, error 0-3]` = refused.
- POST chunk: body `[id, total, offset, chunklen] + word_swapped(data)`,
  zero-padded to a word. Reply `[nonzero]` = ack, and the zero-length chunk at
  `offset == total` is the END marker (its ack reads `[0]`).
- CLOSE: body `[id]`. (Downloads close with `[0]`; uploads use the real id.)
- GET FILE INFO poll: body `[2, id]`, same as downloads.
- SET FILE CRC: a **0x13 write** `[address, 0x00010400, crc]`. The address
  comes from the transfer state (not yet pinned for show push — pass
  explicitly; live trial pending).
- PROCESS FILES: command `0x06` with single-word body `[10]` (same command
  value as CHANNEL_INFO_CONTROL, opcode-selected like SHOW_SNAPSHOT).

`upload_file()` implements open/chunks/END/close; CRC/process are separate
methods. The CRC algorithm is presumed `zlib.crc32` over the plain file bytes;
confirm on hardware. Upload is EXPERIMENTAL until a live trial.

### Gate/comp offset semantics

The app's channel view (Gate page knobs: Threshold, Range, Attack, Hold,
Release; Comp page: Threshold, Ratio, Attack, Release, Gain + Soft/Hard Knee)
plus per-channel value analysis on a live DL32S (32 channels, tuned vs factory
`[0, 0, 0.1, 250, 2, 0]`) resolves the DSP blocks. Offsets follow DSP struct
order, NOT UI row order:

- Gate: 19 threshold dB, 20 attack ms (constant 0.1 everywhere), 21 release ms
  (default 250), 22 hold ms (default 60), 23 range (default 0, tuned 150/160,
  unit TBD).
- Comp: 26 gain dB (default 0), 27 threshold dB (default 0, tuned -13..-37),
  28 attack ms (default 0.1), 29 release ms (default 250), 30 ratio (default
  2:1), 31 knee (0 = soft everywhere).

Labels are in `addressmap.py` with `verified=False` (no live knob movement was
observed; that confirmation is still wanted). Aux-send third words are still
unknown (all zero; pre/post is unconfirmed hypothesis). `unknown_16` reads a
constant 2 on all channels (possibly HPF slope).

### Type-2 observations (live)

The connect-time type-2 dump IS populated: on the reference desk address 12
read 1 while mute group 2 was muted, confirming masters 11-16 live (FINDINGS
section 6 caveat resolved). Type-2 **writes** proven live 2026-10-18: MG6
master (addr 16) 0->1->0 via `mutegroup`, confirmed by 30 s-settle bulk
re-reads (bulk carries all 107 values but needs ~15-30 s to arrive; shorter
settles miss it). Type-2 *push* relay to a second client was NOT observed in
~10 min of watching — bulk re-reads are the reliable type-2 observer.
Other nonzero type-2 addresses seen: 1:2, 2:1, 5:2, 6:1, 7:~22.5,
8:0xFFFFFFFF, 9:1, 10:1, 18:-70.0, 20:20.0, 21:1, 22:4017, 88:-71.4, 106:1.
Unmapped; documented for the next pass.

### Live-proven write paths (2026-10-18, DL32S)

- Rename (0x18 single-slot): slot 31 -> PROBE -> blank, confirmed by
  fresh-connection pushes each way.
- Subgroup mute (4296) 0->1->0 and fader (4297) -120->-119->-120, both
  relay-observed on a second client; net-zero verified by full re-dump.
- MG6 master (type-2 addr 16) 0->1->0, confirmed by 30 s bulk re-reads.
- Device name SET (0x0F) proven with read-back (renamed and restored).
  verified.
- Singles writes proven live in both directions (write + relay + read-back).
- Pairs layout disproven on this firmware (see above).
- Still blocked mixer-side: file transfer (FILE_INFO op 2 refused with ERROR
  body 0x0c since the morning service) and transport status (same error).
  Blocked/unattempted on a service day: show upload+CRC+process, snapshot
  save/delete (needs Show.zip), main/aux master writes (audible), reboot,
  static-IP write, gate knob-move semantics (needs UI control).

