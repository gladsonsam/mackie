# Mackie DL for Home Assistant

Local control of **Mackie DL-series** digital mixers (DL32S, DL16S, DL32R) over TCP,
with no cloud and no Master Fader app running.

The DL32S input strip is fully mapped: gain, phantom power, HPF, gate, compressor,
four EQ bands, eight aux sends and four FX sends, on every channel.

## Install

### HACS

Add this repository as a custom repository (category: Integration), install, then
restart Home Assistant.

### Manual

Copy `custom_components/mackie_dl` into your Home Assistant `config/custom_components/`
directory and restart.

Then go to **Settings > Devices & services > Add integration > Mackie DL (TCP)** and
enter the mixer's IP address. Pick your model, or leave it on `auto`.

## What you get

**Entities**, one set per mixer:

| Entity | Type |
|---|---|
| Input *N* mute | switch |
| Input *N* LR level | number (0-100%) |
| Mute group *N* | switch |
| Show snapshot | select |

Mute group switches and the snapshot selector are labelled with the **names set
on the desk**, and follow renames live — including renames made from the iPad.
The snapshot selector also follows recalls made elsewhere, so it shows what is
actually loaded rather than only what Home Assistant last did.

**Actions**, for automations and scripts:

| Action | Fields |
|---|---|
| `mackie_dl.set_parameter` | `channel`, `field`, `value` |
| `mackie_dl.get_parameter` | `channel`, `field` (returns the value) |
| `mackie_dl.set_input_mute` | `channel`, `muted` |
| `mackie_dl.set_input_fader` | `channel`, `level` (0-100%) |
| `mackie_dl.recall_snapshot` | `snapshot` |
| `mackie_dl.set_mute_group` | `group` (1-6), `muted` |
| `mackie_dl.save_snapshot` | `snapshot`, `name` |
| `mackie_dl.refresh_snapshot_names` | none (returns the name list) |
| `mackie_dl.raw_set_value` | `address`, `int_value` or `float_value` |

`set_parameter` is the general one. It reaches any mapped field by name, in natural
units, without needing an entity per parameter:

```yaml
# Preamp gain on channel 4, in dB
action: mackie_dl.set_parameter
data: {channel: 4, field: gain, value: 18}

# Aux 3 send on channel 12
action: mackie_dl.set_parameter
data: {channel: 12, field: aux3_level, value: -20}

# Phantom power on channel 7
action: mackie_dl.set_parameter
data: {channel: 7, field: phantom, value: true}
```

Field names are defined in [`addressmap.py`](custom_components/mackie_dl/addressmap.py).
Common ones: `mute`, `fader`, `gain`, `trim`, `pan`, `polarity`, `phantom`, `hpf_on`,
`hpf_freq`, `gate_on`, `comp_on`, `eq_on`, `eq1_gain` through `eq4_type`,
`aux1_level` through `aux8_mute`, `fx1_level` through `fx4_mute`.

**Snapshots.** Leave the snapshot recall address at `0` to use the standard recall
sequence. A non-zero value selects a legacy write path needed by some DL32R setups.

## Model support

The protocol is undocumented, so support depends on what has been observed.

| Model | Status |
|---|---|
| **DL32S** | Full input strip, verified against hardware |
| DL16S | Head and sends from [DigiMixer](https://github.com/jskeet/DemoCode/tree/main/DigiMixer), EQ block unconfirmed |
| DL32R | Mute and fader only |


## Tools

`tools/discover/` contains read-only utilities for working on the protocol:

| Tool | Purpose |
|---|---|
| `listen_mackie.py` | Dump the mixer's value space. `--watch` names the address behind a control you move |
| `trace_mackie.py` | Print every protocol frame in both directions |
| `verify_map.py` | Check the address map against a live dump |

```bash
python3 tools/discover/listen_mackie.py <mixer-ip> --model dl32s > dump.tsv
python3 tools/discover/verify_map.py dump.tsv --model dl32s
```

Run them on the same network as the mixer.

## Documentation

[SPEC.md](custom_components/mackie_dl/SPEC.md) covers the wire protocol, the address
map, and how to extend it.

## Credits

Protocol groundwork by [Jon Skeet's DigiMixer](https://github.com/jskeet/DemoCode/tree/main/DigiMixer).

## License

MIT. See [LICENSE](LICENSE).
