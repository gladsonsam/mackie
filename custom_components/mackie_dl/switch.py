from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import MackieClient
from .const import DOMAIN


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

    entities = [MackieInputMuteSwitch(client, _MuteDesc(ch)) for ch in range(1, channels + 1)]
    async_add_entities(entities)


class MackieInputMuteSwitch(SwitchEntity):
    _attr_has_entity_name = True

    def __init__(self, client: MackieClient, desc: _MuteDesc) -> None:
        self._client = client
        self._desc = desc
        self._attr_unique_id = f"mackie_dl_input_{desc.channel}_mute"
        self._attr_name = f"Input {desc.channel} Mute"
        self._is_on = False

    @property
    def is_on(self) -> bool:
        return self._is_on

    async def async_turn_on(self, **kwargs) -> None:
        await self._client.set_input_mute(self._desc.channel, True)
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        await self._client.set_input_mute(self._desc.channel, False)
        self._is_on = False
        self.async_write_ha_state()

