"""Declarative map of the Mackie DL value space.

Why this exists
---------------
The mixer exposes every parameter as a numbered address in one flat space. The
integration used to hard-code two of them (mute, LR fader) as bare offsets on the
client. That does not scale: a DL32S input strip has ~50 meaningful fields, and
writing a new entity class per field would mean 1200+ entities for 32 channels.

So the map is *data*, and behaviour is derived from it. Adding a parameter means
adding a row here - no new entity code, and the generic ``set_parameter`` service
can reach it immediately. Entities stay a deliberately small curated subset (see
SPEC.md, "Coverage vs surface").

Layout
------
Inputs are a regular array: ``address = base + (channel - 1) * stride + offset``.
Everything below is expressed as offsets within one input strip.

Provenance
----------
Two independent sources agree on the head of the strip:

* ``DL16S``  - Jon Skeet's DigiMixer (``jskeet/DemoCode``), reverse-engineered
  independently of this project.
* ``DL32S``  - verified here against real hardware by reading the whole
  5257-address value space and checking every field for plausibility across all
  32 channels (see ``tools/discover/``).

The head of the strip (offsets 1-49) is **identical** between DL16S and DL32S.
The DL32S's larger stride is entirely accounted for by two extra aux sends
(+6 words) and one trailing word:

    DL16S  100 = 49 head + 18 (6 aux x 3) + 8 (4 fx x 2) + 24 membership + 1
    DL32S  106 = 49 head + 24 (8 aux x 3) + 8 (4 fx x 2) + 24 membership + 1

The aux-send count was confirmed structurally rather than assumed: the value
space contains nine 90-word output strips (main LR + 8 aux), which matches the
eight send triples found in each input strip.

⚠️ Firmware variance is real and undocumented. Re-verify with
``tools/discover/listen_mackie.py`` after a firmware update before trusting a
field. The DL32R map is inherited from DigiMixer and is **not** verified here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Value encodings on the wire. Faders/levels are IEEE-754 floats in dB; switches
# and enums are plain u32.
Encoding = Literal["bool", "db", "float", "enum", "int"]


@dataclass(frozen=True)
class Field:
    """One addressable parameter within a channel strip."""

    key: str
    offset: int
    encoding: Encoding
    label: str
    #: Inclusive (min, max) in natural units, for validation. None = unbounded.
    limits: tuple[float, float] | None = None
    #: False when the semantics are inferred from structure rather than observed
    #: changing in response to a known control movement.
    verified: bool = True


def _sends(prefix: str, label: str, first: int, count: int, stride: int,
           with_third: bool) -> list[Field]:
    """Build a send block.

    Aux sends are (level, non-LR mute, unknown) triples; FX sends drop the third
    word. The third word read as 0 on all 32 channels of the reference mixer, so
    it is mapped but flagged unverified rather than guessed at.
    """
    out: list[Field] = []
    for n in range(1, count + 1):
        base = first + (n - 1) * stride
        out.append(Field(f"{prefix}{n}_level", base, "db",
                         f"{label} {n} send level", (-120.0, 10.0)))
        out.append(Field(f"{prefix}{n}_mute", base + 1, "bool",
                         f"{label} {n} send mute"))
        if with_third:
            out.append(Field(f"{prefix}{n}_unknown", base + 2, "int",
                             f"{label} {n} send (unknown)", verified=False))
    return out


def _membership(prefix: str, label: str, first: int, count: int) -> list[Field]:
    return [
        Field(f"{prefix}{n}", first + n - 1, "bool", f"{label} {n} membership",
              verified=False)
        for n in range(1, count + 1)
    ]


# --- the input channel strip ------------------------------------------------
# Offsets 0-49 are shared by DL16S and DL32S.
#
# ⚠️ Offsets, not addresses. ``address = base + (channel-1)*stride + offset`` with
# base 1, so channel 1's mute (offset 7) lives at address 8. DigiMixer's
# Protocols/mackie.md tabulates channel 1 ADDRESSES, which read one higher than
# the offsets here - an easy and silent off-by-one. The cross-check that catches
# it: channel 2's mute must land on address 114.
#
# Comments give the value the reference DL32S actually reported, as an anchor for
# anyone re-deriving this.

_INPUT_HEAD: list[Field] = [
    Field("source_a", 0, "int", "Input A source"),          # 1000 = mic pre 1
    Field("source_b", 1, "int", "Input B source"),          # 2000 = USB 1
    Field("source_select", 2, "enum", "Source A/B"),
    Field("trim", 3, "db", "Trim", (-30.0, 30.0)),          # -5.92 dB; ch27 read -25
    Field("icon", 4, "int", "Icon"),
    Field("colour", 5, "int", "Colour"),
    Field("polarity", 6, "bool", "Polarity invert"),
    Field("mute", 7, "bool", "Mute"),
    Field("fader", 8, "db", "LR fader", (-120.0, 10.0)),    # -15 dB
    Field("pan", 9, "float", "Pan", (-1.0, 1.0)),
    Field("main_assign", 10, "bool", "Assign to main"),
    Field("stereo_link", 11, "bool", "Stereo link"),
    Field("gain", 12, "db", "Preamp gain", (-20.0, 60.0)),  # 22 dB
    Field("phantom", 13, "bool", "48V phantom"),
    Field("hpf_on", 14, "bool", "HPF on"),
    Field("hpf_freq", 15, "float", "HPF frequency", (20.0, 400.0)),  # 125.5 Hz
    Field("unknown_16", 16, "int", "(unknown)", verified=False),
    Field("gate_mode", 17, "enum", "Gate modern/vintage"),
    Field("gate_on", 18, "bool", "Gate on"),
    Field("gate_threshold", 19, "db", "Gate threshold", (-120.0, 0.0)),  # -80 dB
    Field("gate_p1", 20, "float", "Gate parameter 1", verified=False),
    Field("gate_p2", 21, "float", "Gate parameter 2", verified=False),
    Field("gate_p3", 22, "float", "Gate parameter 3", verified=False),
    Field("gate_p4", 23, "float", "Gate parameter 4", verified=False),
    Field("comp_mode", 24, "enum", "Comp modern/vintage"),
    Field("comp_on", 25, "bool", "Comp on"),
    Field("comp_p1", 26, "float", "Comp parameter 1", verified=False),   # 8.9
    Field("comp_p2", 27, "float", "Comp parameter 2", verified=False),   # -22
    Field("comp_p3", 28, "float", "Comp parameter 3", verified=False),   # 31
    Field("comp_p4", 29, "float", "Comp parameter 4", verified=False),   # 99
    Field("comp_p5", 30, "float", "Comp parameter 5", verified=False),   # 4
    Field("comp_p6", 31, "float", "Comp parameter 6", verified=False),
    Field("eq_mode", 32, "enum", "EQ modern/vintage"),
    Field("eq_on", 33, "bool", "EQ on"),
    Field("eq_bands", 34, "int", "EQ band count"),                       # 4
]

# EQ occupies offsets 34-49 on both models, but is packed differently.
#
#   DL16S  four bands of four words, 34-49.
#   DL32S  a band-count word at 34, then bands 4/3/2 of four words at 35/39/43,
#          then band 1 with only three (gain, freq, Q) at 47-49 - no filter-type
#          word, presumably because the low band is a fixed shelf.
#
# Band 4 is the TOP band: on the reference mixer band 4 sat at 17.25kHz and band 1
# at 100Hz. That ordering is what fixes the numbering as high-to-low.
_INPUT_EQ: list[Field] = []
for _b, _base in ((4, 35), (3, 39), (2, 43), (1, 47)):
    _INPUT_EQ += [
        Field(f"eq{_b}_gain", _base, "db", f"EQ band {_b} gain", (-20.0, 20.0)),
        Field(f"eq{_b}_freq", _base + 1, "float", f"EQ band {_b} frequency",
              (20.0, 20000.0)),
        Field(f"eq{_b}_q", _base + 2, "float", f"EQ band {_b} Q", (0.1, 20.0)),
    ]
    if _b != 1:
        _INPUT_EQ.append(Field(f"eq{_b}_type", _base + 3, "enum",
                               f"EQ band {_b} filter type"))


@dataclass(frozen=True)
class ChannelBlock:
    """A regular array of identical strips in the value space."""

    name: str
    base: int
    stride: int
    count: int
    fields: tuple[Field, ...]

    def address(self, index_1_based: int, key: str) -> int:
        if not 1 <= index_1_based <= self.count:
            raise ValueError(
                f"{self.name} index {index_1_based} out of range 1..{self.count}")
        for f in self.fields:
            if f.key == key:
                return self.base + (index_1_based - 1) * self.stride + f.offset
        raise KeyError(f"unknown {self.name} field {key!r}")

    def field(self, key: str) -> Field:
        for f in self.fields:
            if f.key == key:
                return f
        raise KeyError(f"unknown {self.name} field {key!r}")

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(f.key for f in self.fields)


@dataclass(frozen=True)
class MixerMap:
    model: str
    #: Firmware this map was verified against, or None if inherited unverified.
    verified_firmware: str | None
    inputs: ChannelBlock
    notes: str = ""
    blocks: dict[str, ChannelBlock] = field(default_factory=dict)


def _input_block(stride: int, aux_count: int) -> ChannelBlock:
    """Assemble an input strip. Only the send count varies between DL models."""
    aux_first = 50
    fx_first = aux_first + aux_count * 3
    membership_first = fx_first + 4 * 2
    fields = (
        _INPUT_HEAD
        + _INPUT_EQ
        + _sends("aux", "Aux", aux_first, aux_count, 3, with_third=True)
        + _sends("fx", "FX", fx_first, 4, 2, with_third=False)
        + _membership("mutegroup", "Mute group", membership_first, 6)
        + _membership("view", "View", membership_first + 6, 6)
        + _membership("sub", "Subgroup", membership_first + 12, 6)
        + _membership("vca", "VCA", membership_first + 18, 6)
    )
    return ChannelBlock("input", base=1, stride=stride, count=32,
                        fields=tuple(fields))


DL32S = MixerMap(
    model="dl32s",
    verified_firmware="0106000100000002",   # first chunk of the FIRMWARE_INFO reply
    inputs=_input_block(stride=106, aux_count=8),
    notes=(
        "Verified 2026-08-12 against a live DL32S by dumping all 5257 addresses. "
        "Stride 106 confirmed 32/32 on both the mute and fader signatures; "
        "strides 100 and 132 scored 22/32 and 21/32."
    ),
)

DL16S = MixerMap(
    model="dl16s",
    verified_firmware=None,
    inputs=ChannelBlock("input", base=1, stride=100, count=16,
                        fields=_input_block(stride=100, aux_count=6).fields),
    notes=(
        "Inherited from DigiMixer (jskeet/DemoCode). Not verified here. The head "
        "offsets and the send block are safe - DigiMixer's own constants agree - but "
        "offsets 34-49 reuse the DL32S EQ packing, and DigiMixer's notes suggest the "
        "DL16S instead has four uniform 4-word bands with no band-count word. Treat "
        "eq* on this model as unconfirmed."
    ),
)

# DL32R uses a different base and stride and has NOT been checked against the
# field table above - only its mute/fader offsets are known good. Exposed so the
# generic service can still reach those two safely.
DL32R = MixerMap(
    model="dl32r",
    verified_firmware=None,
    inputs=ChannelBlock(
        "input", base=41, stride=132, count=32,
        fields=(
            Field("polarity", 7, "bool", "Polarity invert", verified=False),
            Field("mute", 7, "bool", "Mute"),
            Field("fader", 8, "db", "LR fader", (-120.0, 10.0)),
        ),
    ),
    notes="Inherited from DigiMixer. Only mute and fader are trustworthy.",
)

MAPS: dict[str, MixerMap] = {m.model: m for m in (DL32S, DL16S, DL32R)}


def get_map(model: str) -> MixerMap:
    """Resolve a configured mixer_model to its map.

    ``auto`` resolves to the DL32S map: it is the only one verified against real
    hardware, and it is the mixer this integration was built for.
    """
    key = (model or "auto").strip().lower()
    if key == "auto":
        return DL32S
    if key not in MAPS:
        raise KeyError(f"no address map for mixer model {model!r}")
    return MAPS[key]
