"""Home Assistant device registry helpers."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.helpers.entity import DeviceInfo

from .const import CONF_DEVICE_NAME, CONF_MIXER_MODEL, DOMAIN, config_entry_merged


def mixer_model_label(model_key: str) -> str:
    m = (model_key or "auto").lower()
    return {
        "dl16s": "DL16S",
        "dl32r": "DL32R",
        "dl32s": "DL32S",
        "auto": "DL series",
    }.get(m, m.upper())


def device_info(entry: ConfigEntry) -> DeviceInfo:
    """Single device per config entry: all entities attach here."""
    merged = config_entry_merged(entry)
    host = str(merged[CONF_HOST])
    raw_name = merged.get(CONF_DEVICE_NAME)
    name = (raw_name or "").strip() or f"Mackie ({host})"
    model = mixer_model_label(str(merged.get(CONF_MIXER_MODEL, "auto")))
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name=name,
        manufacturer="Mackie",
        model=model,
        configuration_url=f"http://{host}",
    )
