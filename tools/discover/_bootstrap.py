"""Make ``client`` and ``addressmap`` importable outside Home Assistant.

Both modules are deliberately free of ``homeassistant`` imports so the discovery
tools can drive a real mixer from a plain Python 3.11+ install - typically from a
machine on the same LAN as the desk, since the protocol is chatty and latency
sensitive.
"""
from __future__ import annotations

import pathlib
import sys

_COMPONENT = pathlib.Path(__file__).resolve().parents[2] / "custom_components" / "mackie_dl"

if str(_COMPONENT) not in sys.path:
    sys.path.insert(0, str(_COMPONENT))
