# Mackie DL → Home Assistant

Custom integration for **Mackie DL-series** mixers over TCP (**port 50001**).

The DL32S's whole input strip is mapped — gain, phantom, HPF, gate, comp, four EQ
bands, eight aux sends and four FX sends, per channel — reachable through one
generic service. Entities stay a small curated set: mute and LR level per channel,
plus show-snapshot recall.

## Install

1. Copy [`custom_components/mackie_dl`](custom_components/mackie_dl) into your HA
   config as `config/custom_components/mackie_dl`.
2. Restart Home Assistant.
3. **Settings → Devices & services → Add integration → Mackie DL (TCP)**.

Pick **mixer model** (`dl32s`, `dl16s`, `dl32r`, or `auto`). The connection is
tested during setup. `auto` resolves to the DL32S map — the only one verified
against real hardware.

## Features

| Area | What |
|---|---|
| **Device** | One device per mixer; optional friendly device name. |
| **Entities** | Per-channel **mute** (switch) and **LR level** (number, %). **Show snapshot** (select) recalls Master Fader snapshots. |
| **Full parameter access** | `set_parameter` / `get_parameter` reach every mapped field by name, in natural units. |
| **Integration menu** | **Configure**: snapshot list length, recall mode, device name. **Reconfigure**: host, port, channels, model, snapshots. |

### Services

| Service | Fields |
|---|---|
| `set_input_mute` | `channel`, `muted` |
| `set_input_fader` | `channel`, `level` (0–100 %) |
| `recall_snapshot` | `snapshot` |
| `set_parameter` | `channel`, `field`, `value` |
| `get_parameter` | `channel`, `field` → returns value, address, verified flag |
| `raw_set_value` | `address`, `int_value` or `float_value` |

```yaml
# Set channel 4's preamp gain to 18 dB
action: mackie_dl.set_parameter
data: {channel: 4, field: gain, value: 18}

# Pull channel 12's aux 3 send down
action: mackie_dl.set_parameter
data: {channel: 12, field: aux3_level, value: -20}

# Phantom power on channel 7
action: mackie_dl.set_parameter
data: {channel: 7, field: phantom, value: true}
```

Field names live in [`addressmap.py`](custom_components/mackie_dl/addressmap.py);
the full offset table is in [SPEC.md](custom_components/mackie_dl/SPEC.md).

**Snapshots:** leave **snapshot recall address** at **0** for the Master Fader wire
sequence (cmd `0x07`). Non-zero uses a legacy `CHANNEL_VALUES` write for unusual
setups.

## Protocol status

The protocol is undocumented; this map came from observation, and agrees with
[Jon Skeet's DigiMixer](https://github.com/jskeet/DemoCode/tree/main/DigiMixer)
wherever the two overlap.

| Model | Coverage |
|---|---|
| **DL32S** | Full input strip, **verified against hardware 2026-08-12** (stride 106, 8 aux sends) |
| DL16S | Inherited from DigiMixer; head and sends safe, EQ packing unconfirmed |
| DL32R | Inherited from DigiMixer; trust mute and fader only |

Two behaviours are worth knowing before touching the code:

- **The mixer pushes, it does not serve.** Read requests come back empty; the whole
  value space arrives unprompted after init.
- **Bulk pushes carry `count = 0`**, meaning "as many as fit". Reading that as
  "none" discards every value and leaves entities with no state.

Both are explained in [SPEC.md](custom_components/mackie_dl/SPEC.md).

## Tooling

[`tools/discover/`](tools/discover) — all read-only:

| Tool | Use |
|---|---|
| `listen_mackie.py` | Dump the pushed value space; `--watch` logs live changes as you move a control |
| `trace_mackie.py` | Print every protocol frame both ways |
| `verify_map.py` | Check the address map against a dump — run after a firmware update |

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --model dl32s > dump.tsv
python3 tools/discover/verify_map.py dump.tsv --model dl32s
```

Run them on the mixer's LAN, not over a VPN. Also in
[`tools/`](tools): `mackie_cli.py` for ad-hoc commands and `parse_pcap_mackie.py`
for offline captures.
