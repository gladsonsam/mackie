## Home Assistant → Mackie DL32S control (Python)

This repo contains a **Home Assistant custom integration** that controls a Mackie DL-series mixer (DL32S expected) over the (undocumented) Mackie TCP protocol described in Jon Skeet’s DigiMixer notes.

### What you get

- **Mute switches** for input channels 1–32
- **Fader level numbers** (0.0–1.0) for input channels 1–32 (LR send)
- Home Assistant services to set mute/fader directly
- A **snapshot recall service** (needs the correct recall address)

### Install (manual)

1. Copy `custom_components/mackie_dl` into your Home Assistant config directory:
  - `config/custom_components/mackie_dl`
2. Restart Home Assistant.
3. Add the integration via **Settings → Devices & services → Add integration → “Mackie DL (TCP)”**.

### Notes / caveats

- The Mackie protocol is reverse engineered. This integration targets the basic “channel values” mechanism (mute + LR fader) and may need tweaks once you can test against your DL32S.
- Default mixer TCP port is **50001**.
- **Snapshot recall**: the public reverse-engineered notes we’re using don’t include the snapshot recall address yet. The integration therefore exposes:
  - `mackie_dl.recall_snapshot` (writes the snapshot number to your configured `snapshot_recall_address`)
  - `mackie_dl.raw_set_value` (so you can experiment/capture and then lock in the correct address)

