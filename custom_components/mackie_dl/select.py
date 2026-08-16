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
        self._max_slot = max_slot
        self._current: str | None = None
        self._unsub_names = None
        self._refresh_options()

    def _label(self, number: int) -> str:
        """Option label for a slot: the desk's name when it has one.

        The number stays in the label so options remain unique and stable even
        when two snapshots share a name or a name is blank.
        """
        name = self._client.snapshot_names.get(number)
        return f"{number}: {name}" if name else str(number)

    def _refresh_options(self) -> None:
        self._attr_options = [self._label(n) for n in range(1, self._max_slot + 1)]

    @property
    def current_option(self) -> str | None:
        return self._current

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Expose each snapshot name as its own attribute.

        Consumers that can only read scalars need one variable per snapshot -
        Companion reads `entity.<id>.attributes.snapshot_2` for a button label,
        and cannot index into the `options` list.
        """
        names = self._client.snapshot_names
        attrs: dict[str, str] = {
            f"snapshot_{n}": names.get(n, "")
            for n in range(1, self._max_slot + 1)
            if names.get(n)
        }
        # The slot number on its own. A consumer comparing against the option
        # text would break every time a snapshot is renamed.
        current = self._current
        if current:
            try:
                attrs["current_snapshot"] = str(self._number_from_option(current))
            except ValueError:
                pass
        return attrs

    @staticmethod
    def _number_from_option(option: str) -> int:
        return int(str(option).split(":", 1)[0])

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        def _on_names() -> None:
            """Relabel on rename, and follow recalls made elsewhere.

            Fires for both: a rename (from here or the iPad) and a recall relayed
            by the mixer, so the selected option tracks the desk rather than only
            remembering what Home Assistant last did.
            """
            number = self._client.current_snapshot
            if number is None and self._current:
                try:
                    number = self._number_from_option(self._current)
                except ValueError:
                    number = None
            self._refresh_options()
            if number is not None:
                self._current = self._label(number)
            self.async_write_ha_state()

        self._unsub_names = self._client.subscribe_snapshot_names(_on_names)

        if (last := await self.async_get_last_state()) is None:
            return
        st = last.state
        if st in ("unknown", "unavailable"):
            return
        # A restored state may carry an old label if the snapshot was renamed
        # while we were down, so match on the slot number rather than the text.
        try:
            self._current = self._label(self._number_from_option(st))
        except ValueError:
            if st in self.options:
                self._current = st

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub_names:
            self._unsub_names()
            self._unsub_names = None

    async def async_select_option(self, option: str) -> None:
        try:
            number = self._number_from_option(option)
        except ValueError as err:
            raise HomeAssistantError(f"Unrecognised snapshot option: {option}") from err
        try:
            await self._client.recall_snapshot(self._snapshot_address, number)
        except Exception as err:
            raise HomeAssistantError(f"Could not recall snapshot: {err}") from err
        self._current = self._label(number)
        self.async_write_ha_state()
