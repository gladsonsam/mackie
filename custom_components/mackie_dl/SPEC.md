# Mackie DL integration — technical spec

Reference for maintainers: wire protocol, address maps, Home Assistant behaviour,
and the tooling used to derive all of it.

The protocol is undocumented. Everything here was obtained by observation, either
by this project against a real DL32S or by [Jon Skeet's DigiMixer][digimixer],
whose independent findings agree with ours wherever they overlap.

[digimixer]: https://github.com/jskeet/DemoCode/tree/main/DigiMixer

---

## Transport

- Single outbound TCP connection from the client to the mixer. Default port **50001**.
- Framing: `0xAB`, sequence byte, big-endian chunk count, message type, command,
  header checksum, body (4-byte chunks), body checksum.
- Message types: Request (0), Response (1), Error (5), Broadcast (8).
- The mixer also sends **requests to the client** and expects responses. Failing to
  answer them stalls the connection, so `_handle_request` replies to
  `CLIENT_HANDSHAKE`, `GENERAL_INFO`, `CHANNEL_INFO_CONTROL`, `CHANNEL_VALUES` and
  `CHANNEL_NAMES`.

### ⚠️ The mixer pushes; it does not serve

This is the single most important behaviour to understand, and getting it wrong
silently breaks all state reporting.

Immediately after init the DL32S **pushes its entire value space unprompted**, as
`CHANNEL_VALUES` *requests* — on the reference mixer, 3072 values from address 1
followed by 2185 from address 3073. Meanwhile, an explicit `CHANNEL_VALUES` read
request returns an **empty body**. Polling does not work; listening does.

Worse, those bulk pushes carry **`count = 0`** in the meta word (`0x00000500`
— type 5, count 0), with the real length implied by the message size. Small
messages *do* set count correctly, so the field cannot simply be ignored. The
rule is:

```python
available = (len(body) // 4) - 2
n = min(count, available) if count else available   # count==0 means "all"
```

Before this was understood, `min(count, available)` evaluated to `min(0, 3072)`
and **every pushed value was discarded** — the integration could write to the
mixer but never learned anything back, so entities had no state. Both
`_handle_channel_values` and `request_values` need the rule.

Diagnose with `tools/discover/trace_mackie.py`, which prints every frame in both
directions; the pushes are unmistakable at 3074 chunks.

---

## Message subtypes

| Command | Value | Purpose |
|---|---|---|
| `KEEP_ALIVE` | `0x01` | First request, then every ~2.5s |
| `CLIENT_HANDSHAKE` | `0x03` | Exchanged once each way |
| `FIRMWARE_INFO` | `0x04` | Detailed version info |
| `CHANNEL_INFO_CONTROL` | `0x06` | Max message size / request channel data |
| `SHOW_SNAPSHOT` | `0x07` | Master Fader snapshot recall (not in DigiMixer) |
| `GENERAL_INFO` | `0x0E` | Model name and similar |
| `CHANNEL_VALUES` | `0x13` | Read, write and report values; also meters |
| `BROADCAST_CONTROL` | `0x15` | Ask for periodic meter reporting |
| `METER_LAYOUT` | `0x16` | Which meter values to report |
| `CHANNEL_NAMES` | `0x18` | Channel name table |

### `0x13` channel values

```
Chunk 0: start address
Chunk 1: Count:16 | Type:8 | Unknown:8      (type 5 = normal values, 1 = meters)
Chunk 2+: one value per chunk
```

Levels are IEEE-754 **floats in dB**; switches and enums are plain `u32`.

### `0x07` snapshot recall

Two mechanisms, selected by the **snapshot recall address** option:

- **0 (default) — Master Fader.** Request `0x07`, body two big-endian `u32`:
  `1`, `snapshot_index` (1-based). Response `0x07`, body `1`.
- **Non-zero — legacy.** A single `CHANNEL_VALUES` integer write to that address.
  Only needed on some DL32R setups.

---

## Address space

Every parameter has an address in one flat space. The DL32S reference mixer
exposes **5257 addresses**.

Channel strips are regular arrays:

```
address = base + (channel - 1) * stride + offset
```

### ⚠️ Offsets are not addresses

`addressmap.py` stores **offsets**, so channel 1's mute (offset 7) is at address 8.
DigiMixer's `Protocols/mackie.md` tabulates channel 1 **addresses**, which read one
higher. Mixing the two is a silent off-by-one that still looks plausible — every
field just reports its neighbour.

The cheap check that catches it: **channel 2's mute must be address 114.**
`verify_map.py` asserts exactly this.

### Input strips

| Model | Base | Stride | Inputs | Aux sends | Verified |
|---|---|---|---|---|---|
| DL16S | 1 | 100 | 16 | 6 | DigiMixer only |
| **DL32S** | **1** | **106** | **32** | **8** | **yes — 2026-08-12** |
| DL32R | 41 | 132 | 32 | — | DigiMixer only, mute/fader only |

Stride 106 was confirmed by scoring all 32 channels: at stride 106, 32/32 channels
show a boolean at offset 7 and a dB float at offset 8. Strides 100 and 132 score
22/32 and 21/32.

The head of the strip is **identical between DL16S and DL32S**. The whole stride
difference is two extra aux sends:

```
DL16S  100 = 50 head + 18 (6 aux x 3) + 8 (4 fx x 2) + 24 membership
DL32S  106 = 50 head + 24 (8 aux x 3) + 8 (4 fx x 2) + 24 membership
```

The aux count was corroborated structurally rather than assumed: the value space
contains nine 90-word output strips (main LR plus 8 aux), matching the eight send
triples in each input strip.

#### DL32S input strip offsets

| Offset | Field | Offset | Field |
|---|---|---|---|
| 0–2 | `source_a`, `source_b`, `source_select` | 24–25 | `comp_mode`, `comp_on` |
| 3 | `trim` | 26–31 | `comp_p1`…`comp_p6` |
| 4–5 | `icon`, `colour` | 32–33 | `eq_mode`, `eq_on` |
| 6 | `polarity` | 34 | `eq_bands` (reads 4) |
| **7** | **`mute`** | 35–38 | EQ band 4 — gain, freq, Q, type |
| **8** | **`fader`** (LR) | 39–42 | EQ band 3 |
| 9–11 | `pan`, `main_assign`, `stereo_link` | 43–46 | EQ band 2 |
| 12 | `gain` | 47–49 | EQ band 1 — gain, freq, Q *(no type word)* |
| 13 | `phantom` | 50–73 | `aux1`…`aux8` — level, mute, unknown |
| 14–15 | `hpf_on`, `hpf_freq` | 74–81 | `fx1`…`fx4` — level, mute |
| 16 | unknown | 82–87 | mute-group membership |
| 17–18 | `gate_mode`, `gate_on` | 88–93 | view membership |
| 19 | `gate_threshold` | 94–99 | subgroup membership |
| 20–23 | `gate_p1`…`gate_p4` | 100–105 | VCA membership |

Band 4 is the **top** band — on the reference mixer band 4 sat at 17.25kHz and
band 1 at 100Hz. Band 1 has only three words, presumably a fixed low shelf.

43 of the 106 fields are flagged `verified=False`: their position is certain but
their meaning is inferred from structure rather than observed responding to a
known control movement. `get_parameter` returns this flag so callers can tell.

### Beyond the inputs

Inputs occupy 1–3392. The remainder is **structurally mapped but not labelled**,
because naming a field without watching it change is guessing:

| Addresses | Structure |
|---|---|
| 3393–~4041 | returns, FX outputs, FX parameters, FX inputs |
| 4042–4347 | **6 strips × 51 words** — subgroups (matches DL16S exactly) |
| 4395–5204 | **9 strips × 90 words** — main LR + 8 aux outputs |
| 5226–5257 | 32 sequential integers — output/USB mapping |

To label any of it, use `listen_mackie.py --watch` and move the control in Master
Fader; the address prints itself.

---

## Coverage vs surface

A DL32S input strip has ~50 meaningful fields. Exposing all of them as entities
across 32 channels would mean **1200+ entities**, which makes the HA UI slow, bloats
the recorder database, and produces dropdowns nobody can navigate.

So the two are deliberately separated:

- **Coverage** is the address map plus `set_parameter` / `get_parameter`. Anything
  in `addressmap.py` is reachable immediately — no new entity code.
- **Surface** is a small curated set of entities: per-channel mute and LR level,
  plus snapshot recall.

Adding a parameter means adding a row to `addressmap.py`. Adding an *entity* is a
deliberate decision about what belongs on a dashboard.

---

## Home Assistant behaviour

### Config entry

- **Version** `5` (`config_flow.py`).
- **`data`**: `host`, `port`, `channels`, `mixer_model`
- **`options`**: `device_name`, `snapshot_slots`, `snapshot_recall_address`
- Reads merge both via `config_entry_merged(entry)`.

Flows: **user** (TCP validated before create; `unique_id` is the normalised host),
**reconfigure** (full form, then reload), **options** (preferences only, reload via
`add_update_listener`).

### Entities

All attach to one `DeviceInfo` per entry (`device.py`), `configuration_url` →
`http://<host>`.

| Platform | Entity | Notes |
|---|---|---|
| `switch` | Input *N* mute | Subscribes to the mute address |
| `number` | Input *N* LR level | 0–100 %; wire value is float dB |
| `select` | Show snapshot | `EntityCategory.CONFIG`; `RestoreEntity` |

### Services

| Service | Fields | Purpose |
|---|---|---|
| `set_input_mute` | `channel`, `muted` | Curated shortcut |
| `set_input_fader` | `channel`, `level` (0–100 %) | Curated shortcut |
| `recall_snapshot` | `snapshot` | Uses the configured recall address |
| **`set_parameter`** | `channel`, `field`, `value` | **Any mapped field, natural units** |
| **`get_parameter`** | `channel`, `field` | **Reads cache; returns value + `verified`** |
| `raw_set_value` | `address`, `int_value` \| `float_value` | Escape hatch, no map |

`set_parameter` validates against each field's declared range. `raw_set_value`
does not — it is the deliberate way to poke an unmapped address.

---

## Tooling

All of `tools/discover/` is **read-only** unless stated. `client.py` and
`addressmap.py` carry no `homeassistant` imports so these run under plain Python.

| Tool | Use |
|---|---|
| `listen_mackie.py` | Collect the pushed value space to TSV. `--watch` logs live changes — the discovery mode |
| `trace_mackie.py` | Print every frame both ways. Reach for this when the mixer connects but nothing arrives |
| `verify_map.py` | Check `addressmap.py` against a dump: structural completeness, anchor addresses, per-field plausibility across all channels |
| `mackie_cli.py` | Ad-hoc mute/fader/snapshot commands |
| `parse_pcap_mackie.py` | Offline pcapng analysis (largely superseded by `listen_mackie.py`) |

Run them on the mixer's LAN. Over a VPN the init burst can straddle the settle
window, silently yielding a partial dump.

### Re-deriving the map after a firmware update

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --model dl32s > dump.tsv
python3 tools/discover/verify_map.py dump.tsv --model dl32s
```

If it fails, find the shift with `--watch`: move one known control and read off
the address that changed.

### Discovering an unlabelled field

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --settle 15 --watch 30 > out.tsv
# move exactly one control in Master Fader during the watch window
tail -20 out.tsv    # the changes block names the address
```

Because the layout is `base + (channel-1) * stride + offset`, solving one offset
on channel 1 solves it for all 32 channels.

---

## Caveats

- **The protocol is undocumented and firmware may change it.** Re-run
  `verify_map.py` after updates. The DL32S map records the firmware it was
  verified against.
- **DL16S and DL32R maps are inherited from DigiMixer and unverified here.** For
  the DL16S, head offsets and the send block are safe, but offsets 34–49 reuse the
  DL32S EQ packing and DigiMixer's notes suggest the DL16S differs. For the DL32R,
  trust only mute and fader.
- **`iot_class` is `local_push`** and that is not cosmetic — see the pushes section.
- **Writes go to a live desk.** Discovery reads are safe; `raw_set_value` sweeps
  are not. Snapshot the show first and work with outputs muted.
