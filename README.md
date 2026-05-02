# Mackie DL → Home Assistant

Custom integration for **Mackie DL-series** mixers over TCP (**port 50001**): mute + LR fader per input, optional **show snapshot** recall, and services for scripts/automations.


## Install

1. Copy [`custom_components/mackie_dl`](custom_components/mackie_dl) into your HA config as `config/custom_components/mackie_dl`.
2. Restart Home Assistant.
3. **Settings → Devices & services → Add integration → Mackie DL (TCP)**.

Pick **mixer model** (`dl32s`, `dl16s`, `dl32r`, or `auto`). Connection is tested during setup.

## Features (short)

| Area | What |
|------|------|
| **Device** | One device per mixer; optional friendly **device name**. |
| **Entities** | Per-channel **mute** (switch) and **LR level** (number, %). **Show snapshot** (select, Configuration) recalls Master Fader snapshots. |
| **Integration menu** | **Configure** (options): snapshot list length, recall mode, device name. **Reconfigure**: host, port, channels, model, snapshots. |
| **Services** | `set_input_mute`, `set_input_fader`, `recall_snapshot`, `raw_set_value`. |

**Snapshots:** leave **snapshot recall address** at **0** to use the **Master Fader** wire sequence (cmd `0x07`). Non-zero uses a legacy single **CHANNEL_VALUES** write for unusual setups.

## CLI & reference

Repo includes [`tools/mackie_cli.py`](tools/mackie_cli.py) (e.g. `recall-snapshot`, `mute`, `fader`) and [`tools/parse_pcap_mackie.py`](tools/parse_pcap_mackie.py) for captures.

**Protocol, addressing, and HA internals:** [`custom_components/mackie_dl/SPEC.md`](custom_components/mackie_dl/SPEC.md).

