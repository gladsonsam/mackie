from __future__ import annotations

import asyncio
import logging
import struct

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant, ServiceResponse, SupportsResponse
from homeassistant.helpers import entity_registry as er

from .addressmap import get_map
from .client import MackieClient, MackieCommand
from .const import (
    CONF_CHANNELS,
    CONF_DEVICE_NAME,
    CONF_MIXER_MODEL,
    CONFIG_ENTRY_OPTION_KEYS,
    CONF_SNAPSHOT_RECALL_ADDRESS,
    CONF_SNAPSHOT_SLOTS,
    config_entry_merged,
    DEFAULT_CHANNELS,
    DEFAULT_MIXER_MODEL,
    DEFAULT_SNAPSHOT_SLOTS,
    DOMAIN,
    MAX_INPUT_CHANNELS,
    SERVICE_GET_PARAMETER,
    SERVICE_RECALL_SNAPSHOT,
    SERVICE_REFRESH_SNAPSHOT_NAMES,
    SERVICE_RAW_SET_VALUE,
    SERVICE_SAVE_SNAPSHOT,
    SERVICE_SET_INPUT_FADER,
    SERVICE_SET_INPUT_MUTE,
    SERVICE_SET_MUTE_GROUP,
    SERVICE_SET_PARAMETER,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = ["switch", "number", "select"]

#: How often to ask the mixer to re-send its whole value space. State arrives by
#: push, so this only guards against a dropped update; it is not how state is kept
#: current. Each resync moves 5257 values on a DL32S.
RESYNC_INTERVAL_SECONDS = 60


def _as_bool(value) -> bool:
    """Accept the several shapes HA hands a boolean through a service call."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _remove_legacy_mackie_entities(hass: HomeAssistant, config_entry_id: str) -> None:
    """Drop obsolete entities whose unique_id used global mackie_dl_input_* (causes duplicates)."""
    registry = er.async_get(hass)
    for eid, ent in list(registry.entities.items()):
        if ent.config_entry_id != config_entry_id:
            continue
        uid = ent.unique_id or ""
        if uid.startswith("mackie_dl_input_"):
            registry.async_remove(eid)


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate entries to version 5 (data vs options split)."""
    if config_entry.version > 5:
        return False

    if config_entry.version == 5:
        return True

    data = dict(config_entry.data)
    options = dict(config_entry.options)
    ver = config_entry.version

    if ver == 1:
        if int(data.get(CONF_CHANNELS, DEFAULT_CHANNELS)) == 1:
            data[CONF_CHANNELS] = DEFAULT_CHANNELS

    ch = int(data.get(CONF_CHANNELS, DEFAULT_CHANNELS))
    if ch > MAX_INPUT_CHANNELS:
        data[CONF_CHANNELS] = MAX_INPUT_CHANNELS

    if ver < 3:
        _remove_legacy_mackie_entities(hass, config_entry.entry_id)

    data.setdefault(CONF_SNAPSHOT_SLOTS, DEFAULT_SNAPSHOT_SLOTS)

    if ver < 5:
        for key in CONFIG_ENTRY_OPTION_KEYS:
            if key in data:
                options[key] = data.pop(key)
        options.setdefault(CONF_DEVICE_NAME, "")
        options.setdefault(CONF_SNAPSHOT_SLOTS, DEFAULT_SNAPSHOT_SLOTS)
        options.setdefault(CONF_SNAPSHOT_RECALL_ADDRESS, 0)

    hass.config_entries.async_update_entry(
        config_entry,
        data=data,
        options=options,
        version=5,
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    merged = config_entry_merged(entry)

    host = str(merged[CONF_HOST])
    port = int(merged[CONF_PORT])
    channels = min(int(merged.get(CONF_CHANNELS, DEFAULT_CHANNELS)), MAX_INPUT_CHANNELS)
    snapshot_recall_address = int(merged.get(CONF_SNAPSHOT_RECALL_ADDRESS, 0))
    snapshot_slots = int(merged.get(CONF_SNAPSHOT_SLOTS, DEFAULT_SNAPSHOT_SLOTS))
    mixer_model = merged.get(CONF_MIXER_MODEL, DEFAULT_MIXER_MODEL)

    client = MackieClient(
        host=host,
        port=port,
        mixer_model=str(mixer_model),
    )
    await client.connect()

    # Seed snapshot names from the mixer's show archive. Renames after this
    # arrive as pushes, so this download happens once per connection. Failure is
    # not fatal: the select entity falls back to bare slot numbers.
    try:
        await client.refresh_snapshot_names()
    except Exception as err:
        _LOGGER.warning("Could not read snapshot names from %s: %s", host, err)

    async def _poll_loop() -> None:
        """Periodically re-ask the mixer to emit channel values.

        This is a resync safety net, not the main path: the mixer pushes state
        changes as they happen. CHANNEL_INFO_CONTROL type 6 makes it re-send the
        entire value space (5257 values on a DL32S), so it recovers cleanly from a
        missed update - but it is expensive, hence the slow interval. Values that
        have not changed are filtered out before reaching listeners, so a resync
        produces no entity churn.
        """
        try:
            while True:
                await asyncio.sleep(RESYNC_INTERVAL_SECONDS)
                try:
                    await client.send_request(
                        MackieCommand.CHANNEL_INFO_CONTROL,
                        bytes([0, 0, 0, 6]),
                        timeout=3.0,
                    )
                except Exception:
                    pass
        except asyncio.CancelledError:
            return

    async def _update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
        await hass.config_entries.async_reload(entry.entry_id)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "client": client,
        "channels": channels,
        "snapshot_recall_address": snapshot_recall_address,
        "snapshot_slots": min(snapshot_slots, 64),
        # MUST be a background task. hass.async_create_task() registers a task that
        # HA waits for while finishing startup, and this loop never returns - which
        # stalled bootstrap until it timed out ("Setup timed out for bootstrap
        # waiting on mackie_dl_poll") and delayed every restart.
        "poll_task": entry.async_create_background_task(
            hass, _poll_loop(), name="mackie_dl_poll"
        ),
    }

    entry.async_on_unload(entry.add_update_listener(_update_listener))

    async def handle_set_mute(call):
        ch = int(call.data["channel"])
        muted = bool(call.data["muted"])
        await client.set_input_mute(ch, muted)

    async def handle_set_fader(call):
        ch = int(call.data["channel"])
        pct = float(call.data["level"])
        if pct < 0.0:
            pct = 0.0
        if pct > 100.0:
            pct = 100.0
        await client.set_input_fader_level(ch, pct / 100.0)

    async def handle_recall_snapshot(call):
        snap = int(call.data["snapshot"])
        addr = int(hass.data[DOMAIN][entry.entry_id]["snapshot_recall_address"])
        await client.recall_snapshot(addr, snap)

    async def handle_set_mute_group(call):
        group = int(call.data["group"])
        await client.set_mute_group(group, _as_bool(call.data["muted"]))

    async def handle_save_snapshot(call):
        snap = int(call.data["snapshot"])
        await client.save_snapshot(snap, str(call.data["name"]))

    async def handle_refresh_snapshot_names(call) -> ServiceResponse:
        names = await client.refresh_snapshot_names()
        return {"snapshots": {str(k): v for k, v in sorted(names.items())}}

    async def handle_raw_set_value(call):
        addr = int(call.data["address"])
        if "int_value" in call.data and call.data["int_value"] is not None:
            await client.raw_set_value_int(addr, int(call.data["int_value"]))
        elif "float_value" in call.data and call.data["float_value"] is not None:
            await client.raw_set_value_float(addr, float(call.data["float_value"]))
        else:
            raise ValueError("Provide either int_value or float_value")

    # --- map-driven generic access ------------------------------------------
    # These two reach every field in addressmap.py. Adding a parameter to the map
    # makes it callable here immediately - no new service, no new entity.
    mixer_map = get_map(str(mixer_model))

    def _resolve(call):
        ch = int(call.data["channel"])
        key = str(call.data["field"])
        block = mixer_map.inputs
        return block, block.field(key), block.address(ch, key)

    async def handle_set_parameter(call):
        block, fld, address = _resolve(call)
        value = call.data["value"]

        if fld.encoding == "bool":
            await client.raw_set_value_int(address, 1 if _as_bool(value) else 0)
            return
        if fld.encoding in ("enum", "int"):
            await client.raw_set_value_int(address, int(value))
            return

        num = float(value)
        if fld.limits is not None and not fld.limits[0] <= num <= fld.limits[1]:
            raise ValueError(
                f"{fld.key} must be within {fld.limits[0]}..{fld.limits[1]}, got {num}"
            )
        await client.raw_set_value_float(address, num)

    async def handle_get_parameter(call) -> ServiceResponse:
        """Read from the client's cache, which the mixer keeps current by push."""
        block, fld, address = _resolve(call)
        raw = client.get_cached_u32(address)
        if raw is None:
            return {"address": address, "field": fld.key, "value": None,
                    "available": False}
        if fld.encoding in ("db", "float"):
            value: float | int | bool = struct.unpack(">f", struct.pack(">I", raw))[0]
        elif fld.encoding == "bool":
            value = bool(raw)
        else:
            value = raw
        return {
            "address": address,
            "field": fld.key,
            "label": fld.label,
            "encoding": fld.encoding,
            "value": value,
            "verified": fld.verified,
            "available": True,
        }

    if not hass.services.has_service(DOMAIN, SERVICE_SET_PARAMETER):
        hass.services.async_register(DOMAIN, SERVICE_SET_PARAMETER, handle_set_parameter)
    if not hass.services.has_service(DOMAIN, SERVICE_GET_PARAMETER):
        hass.services.async_register(
            DOMAIN,
            SERVICE_GET_PARAMETER,
            handle_get_parameter,
            supports_response=SupportsResponse.ONLY,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_SET_INPUT_MUTE):
        hass.services.async_register(DOMAIN, SERVICE_SET_INPUT_MUTE, handle_set_mute)
    if not hass.services.has_service(DOMAIN, SERVICE_SET_INPUT_FADER):
        hass.services.async_register(DOMAIN, SERVICE_SET_INPUT_FADER, handle_set_fader)
    if not hass.services.has_service(DOMAIN, SERVICE_RECALL_SNAPSHOT):
        hass.services.async_register(DOMAIN, SERVICE_RECALL_SNAPSHOT, handle_recall_snapshot)
    if not hass.services.has_service(DOMAIN, SERVICE_RAW_SET_VALUE):
        hass.services.async_register(DOMAIN, SERVICE_RAW_SET_VALUE, handle_raw_set_value)
    if not hass.services.has_service(DOMAIN, SERVICE_SET_MUTE_GROUP):
        hass.services.async_register(DOMAIN, SERVICE_SET_MUTE_GROUP, handle_set_mute_group)
    if not hass.services.has_service(DOMAIN, SERVICE_SAVE_SNAPSHOT):
        hass.services.async_register(DOMAIN, SERVICE_SAVE_SNAPSHOT, handle_save_snapshot)
    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH_SNAPSHOT_NAMES):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH_SNAPSHOT_NAMES,
            handle_refresh_snapshot_names,
            supports_response=SupportsResponse.ONLY,
        )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if data:
        client: MackieClient = data["client"]
        poll_task = data.get("poll_task")
        if poll_task:
            poll_task.cancel()
        await client.close()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    return unload_ok
