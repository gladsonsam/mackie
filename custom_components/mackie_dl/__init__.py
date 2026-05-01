from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant

from .client import MackieClient
from .const import (
    CONF_CHANNELS,
    CONF_SNAPSHOT_RECALL_ADDRESS,
    DOMAIN,
    SERVICE_RECALL_SNAPSHOT,
    SERVICE_RAW_SET_VALUE,
    SERVICE_SET_INPUT_FADER,
    SERVICE_SET_INPUT_MUTE,
)

PLATFORMS: list[str] = ["switch", "number"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    host = entry.data[CONF_HOST]
    port = entry.data[CONF_PORT]
    channels = int(entry.data.get(CONF_CHANNELS, 32))
    snapshot_recall_address = int(entry.data.get(CONF_SNAPSHOT_RECALL_ADDRESS, 0))

    client = MackieClient(host=host, port=port)
    await client.connect()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "client": client,
        "channels": channels,
        "snapshot_recall_address": snapshot_recall_address,
    }

    async def handle_set_mute(call):
        ch = int(call.data["channel"])
        muted = bool(call.data["muted"])
        await client.set_input_mute(ch, muted)

    async def handle_set_fader(call):
        ch = int(call.data["channel"])
        level = float(call.data["level"])
        await client.set_input_fader(ch, level)

    async def handle_recall_snapshot(call):
        snap = int(call.data["snapshot"])
        addr = int(hass.data[DOMAIN][entry.entry_id]["snapshot_recall_address"])
        await client.recall_snapshot(addr, snap)

    async def handle_raw_set_value(call):
        addr = int(call.data["address"])
        if "int_value" in call.data and call.data["int_value"] is not None:
            await client.raw_set_value_int(addr, int(call.data["int_value"]))
        elif "float_value" in call.data and call.data["float_value"] is not None:
            await client.raw_set_value_float(addr, float(call.data["float_value"]))
        else:
            raise ValueError("Provide either int_value or float_value")

    if not hass.services.has_service(DOMAIN, SERVICE_SET_INPUT_MUTE):
        hass.services.async_register(DOMAIN, SERVICE_SET_INPUT_MUTE, handle_set_mute)
    if not hass.services.has_service(DOMAIN, SERVICE_SET_INPUT_FADER):
        hass.services.async_register(DOMAIN, SERVICE_SET_INPUT_FADER, handle_set_fader)
    if not hass.services.has_service(DOMAIN, SERVICE_RECALL_SNAPSHOT):
        hass.services.async_register(DOMAIN, SERVICE_RECALL_SNAPSHOT, handle_recall_snapshot)
    if not hass.services.has_service(DOMAIN, SERVICE_RAW_SET_VALUE):
        hass.services.async_register(DOMAIN, SERVICE_RAW_SET_VALUE, handle_raw_set_value)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if data:
        client: MackieClient = data["client"]
        await client.close()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    return unload_ok

