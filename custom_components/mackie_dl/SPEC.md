# Mackie DL integration — technical spec

Reference for maintainers: wire protocol assumptions, address maps, Home Assistant behavior, and tooling.

---

## Transport

- Single outbound TCP connection from Home Assistant to the mixer (DigiMixer / Jon Skeet notes).
- Default port **50001**.
- Framing: messages start with `0xAB`, sequence byte, big-endian chunk count, message type, command, checksums, body (4-byte chunks), body checksum.

---

## Mixer models → input address map (`client.py`)

Mute and LR fader use **CHANNEL_VALUES** (`0x13`): one address per field, float dB on the wire for faders (DigiMixer curve).

| Model | Entry `mixer_model` | Base | Stride | Mute offset | LR fader offset |
|-------|---------------------|------|--------|-------------|-----------------|
| DL16S | `dl16s` | 1 | 100 | 7 | 8 |
| DL32R | `dl32r` | 41 | 132 | 7 | 8 |
| DL32S | `dl32s` | 1 | **106** | 7 | 8 |
| Auto | `auto` | Handshake/probe may pick DL32R vs DL16 map; safe default tends DL32R until probed |

**DL32S stride 106** matches Wireshark: Ch2 mute at **114** (= `107 + 7`), not stride 108 from a 100-wide map.

---

## Snapshot recall

Two mechanisms:

### A — Master Fader (default)

When **snapshot recall address** is **0**:

1. **REQUEST**, command **`0x07`**, body: two big-endian `u32`: **`1`**, **`snapshot_index`** (1-based).
2. **RESPONSE**, command **`0x07`**, body: one `u32`: **`1`**.

Implemented as `recall_snapshot_master_fader()` / `SHOW_SNAPSHOT = 0x07`.

### B — Legacy CHANNEL_VALUES

When **snapshot recall address** is **non-zero**: single **CHANNEL_VALUES** write (integer) to that address (DL32R experimentation).

---

## Home Assistant config entry

- **Version** `5` (`config_flow.py`).
- **Split storage** (HA convention):
  - **`data`**: `host`, `port`, `channels`, `mixer_model`
  - **`options`**: `device_name`, `snapshot_slots`, `snapshot_recall_address`
- Reads use `config_entry_merged(entry)` → `{**entry.data, **entry.options}`.

### Flows

- **User**: TCP validation before create; **`unique_id`** = normalized **host** (duplicate → `already_configured`).
- **Reconfigure**: full form; updates data + options; reload.
- **Options**: snapshot/display prefs only; **`async_create_entry`** merges **options**; reload via **`add_update_listener`**.

---

## Entities

All attach to one **DeviceInfo** per entry (`device.py`): manufacturer Mackie, model from map, `configuration_url` → `http://<host>`.

| Platform | Entity | Notes |
|----------|--------|------|
| `switch` | Input *N* mute | Subscribes mute address. |
| `number` | Input *N* LR level | 0–100 %; wire = float dB. |
| `select` | Show snapshot | **`EntityCategory.CONFIG`** (shows under device Configuration); options `1…snapshot_slots`; **`RestoreEntity`** for last selection. |

---

## Services (`DOMAIN`)

| Service | Purpose |
|---------|---------|
| `set_input_mute` | `channel`, `muted` |
| `set_input_fader` | `channel`, `level` (0–100 %) |
| `recall_snapshot` | `snapshot` (uses merged recall address) |
| `raw_set_value` | `address`, `int_value` or `float_value` |

---

## CLI (`tools/mackie_cli.py`)

Examples:

```text
python tools/mackie_cli.py <HOST> --model dl32s mute 2 off
python tools/mackie_cli.py <HOST> --model dl32s fader 2 0
python tools/mackie_cli.py <HOST> --model dl32s recall-snapshot 3
```

---

## PCAP tooling (`tools/parse_pcap_mackie.py`)

Parses **pcapng** EPBs, optionally **TCP-reassembles** streams to **dst port 50001**, scans for Mackie frames. Prints **`SHOW_SNAPSHOT` (0x07)** bodies and single-value **CHANNEL_VALUES** writes for address discovery.

---

## References in repo

- `reference/digimixer/` — DigiMixer / Jon Skeet Mackie notes (protocol layout).
- `reference/digimixer/DigiMixer/Protocols/mackie.md` — DL16 address layout (Jon Skeet).

---

## Caveats

- Protocol is undocumented; behavior can vary by firmware.
- **`iot_class`**: `local_push` — mixer may push channel values after init (broadcast); polling also nudges **CHANNEL_INFO_CONTROL** type 6 periodically.
