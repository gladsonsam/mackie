from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import MackieClient
from .const import DOMAIN


@dataclass(frozen=True)
class _FaderDesc:
    channel: int


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: MackieClient = data["client"]
    channels: int = int(data["channels"])

    entities = [MackieInputFaderNumber(client, _FaderDesc(ch)) for ch in range(1, channels + 1)]
    async_add_entities(entities)


class MackieInputFaderNumber(NumberEntity):
    _attr_has_entity_name = True
    _attr_native_min_value = 0.0
    _attr_native_max_value = 1.0
    _attr_native_step = 0.01

    def __init__(self, client: MackieClient, desc: _FaderDesc) -> None:
        self._client = client
        self._desc = desc
        self._attr_unique_id = f"mackie_dl_input_{desc.channel}_fader"
        self._attr_name = f"Input {desc.channel} Fader"
        self._value = 0.0

    @property
    def native_value(self) -> float:
        return self._value

    async def async_set_native_value(self, value: float) -> None:
        v = float(value)
        await self._client.set_input_fader(self._desc.channel, v)
        # Reflect what we tried to set; true state sync can be added later once tested.
        self._value = max(0.0, min(1.0, v))
        self.async_write_ha_state()

