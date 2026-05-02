"""Show snapshot selector (Master Fader recall protocol when address is 0)."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .client import MackieClient
from .const import DOMAIN
from .device import device_info


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: MackieClient = data["client"]
    slots: int = int(data["snapshot_slots"])
    addr: int = int(data["snapshot_recall_address"])

    async_add_entities(
        [
            MackieShowSnapshotSelect(
                entry,
                client,
                snapshot_address=addr,
                max_slot=min(slots, 64),
            )
        ]
    )


class MackieShowSnapshotSelect(RestoreEntity, SelectEntity):
    """Pick a snapshot number to recall (same as Master Fader show snapshots)."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.CONFIG
    _attr_translation_key = "show_snapshot"
    _attr_icon = "mdi:image-filter-frames"

    def __init__(
        self,
        entry: ConfigEntry,
        client: MackieClient,
        *,
        snapshot_address: int,
        max_slot: int,
    ) -> None:
        self._client = client
        self._snapshot_address = int(snapshot_address)
        self._attr_device_info = device_info(entry)
        self._attr_unique_id = f"{entry.entry_id}_show_snapshot"
        self._attr_options = [str(n) for n in range(1, max_slot + 1)]
        self._current: str | None = None

    @property
    def current_option(self) -> str | None:
        return self._current

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if (last := await self.async_get_last_state()) is None:
            return
        st = last.state
        if st in ("unknown", "unavailable"):
            return
        if st in self.options:
            self._current = st

    async def async_select_option(self, option: str) -> None:
        try:
            await self._client.recall_snapshot(self._snapshot_address, int(option))
        except Exception as err:
            raise HomeAssistantError(f"Could not recall snapshot: {err}") from err
        self._current = option
        self.async_write_ha_state()
