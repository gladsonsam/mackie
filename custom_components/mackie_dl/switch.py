from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import MackieClient
from .const import DOMAIN
from .device import device_info


@dataclass(frozen=True)
class _MuteDesc:
    channel: int


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: MackieClient = data["client"]
    channels: int = int(data["channels"])

    entities = [
        MackieInputMuteSwitch(entry, client, _MuteDesc(ch)) for ch in range(1, channels + 1)
    ]
    async_add_entities(entities)


class MackieInputMuteSwitch(SwitchEntity):
    _attr_has_entity_name = True

    def __init__(self, entry: ConfigEntry, client: MackieClient, desc: _MuteDesc) -> None:
        self._client = client
        self._desc = desc
        self._attr_device_info = device_info(entry)
        self._attr_unique_id = f"{entry.entry_id}_input_{desc.channel}_mute"
        self._attr_name = f"Input {desc.channel} mute"
        self._is_on = False
        self._unsub = None

    @property
    def is_on(self) -> bool:
        return self._is_on

    async def async_added_to_hass(self) -> None:
        addr = self._client.input_mute_address(self._desc.channel)

        cached = self._client.get_cached_u32(addr)
        if cached is not None:
            self._is_on = int(cached) != 0

        def _on_update(raw: int) -> None:
            self._is_on = int(raw) != 0
            self.async_write_ha_state()

        self._unsub = self._client.subscribe_value(addr, _on_update)

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub:
            self._unsub()
            self._unsub = None

    async def async_turn_on(self, **kwargs) -> None:
        await self._client.set_input_mute(self._desc.channel, True)
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        await self._client.set_input_mute(self._desc.channel, False)
        self._is_on = False
        self.async_write_ha_state()

