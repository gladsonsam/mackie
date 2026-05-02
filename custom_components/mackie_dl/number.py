from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client import MackieClient, input_fader_u32_to_percent
from .const import DOMAIN
from .device import device_info


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

    entities = [
        MackieInputFaderNumber(entry, client, _FaderDesc(ch)) for ch in range(1, channels + 1)
    ]
    async_add_entities(entities)


class MackieInputFaderNumber(NumberEntity):
    _attr_has_entity_name = True
    # HA percent; the mixer protocol uses float dB on the wire (DigiMixer convention).
    _attr_native_unit_of_measurement = "%"
    _attr_native_min_value = 0.0
    _attr_native_max_value = 100.0
    _attr_native_step = 1.0
    _attr_mode = NumberMode.SLIDER

    def __init__(self, entry: ConfigEntry, client: MackieClient, desc: _FaderDesc) -> None:
        self._client = client
        self._desc = desc
        self._attr_device_info = device_info(entry)
        self._attr_unique_id = f"{entry.entry_id}_input_{desc.channel}_fader"
        self._attr_name = f"Input {desc.channel} LR level"
        self._value_pct = 0.0
        self._unsub = None

    @property
    def native_value(self) -> float:
        return self._value_pct

    async def async_added_to_hass(self) -> None:
        addr = self._client.input_lr_fader_address(self._desc.channel)

        cached = self._client.get_cached_u32(addr)
        if cached is not None:
            self._value_pct = input_fader_u32_to_percent(cached)

        def _on_update(raw: int) -> None:
            self._value_pct = input_fader_u32_to_percent(raw)
            self.async_write_ha_state()

        self._unsub = self._client.subscribe_value(addr, _on_update)

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub:
            self._unsub()
            self._unsub = None

    async def async_set_native_value(self, value: float) -> None:
        pct = float(value)
        if pct < 0.0:
            pct = 0.0
        if pct > 100.0:
            pct = 100.0

        level = pct / 100.0
        await self._client.set_input_fader_level(self._desc.channel, level)
        self._value_pct = pct
        self.async_write_ha_state()
