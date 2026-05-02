from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import callback

from .client import MackieClient
from .const import (
    CONFIG_ENTRY_DATA_KEYS,
    CONFIG_ENTRY_OPTION_KEYS,
    CONF_CHANNELS,
    CONF_DEVICE_NAME,
    CONF_MIXER_MODEL,
    CONF_SNAPSHOT_RECALL_ADDRESS,
    CONF_SNAPSHOT_SLOTS,
    DEFAULT_CHANNELS,
    DEFAULT_MIXER_MODEL,
    DEFAULT_PORT,
    DEFAULT_SNAPSHOT_SLOTS,
    DOMAIN,
    MAX_INPUT_CHANNELS,
    config_entry_merged,
)


def _defaults_from_merged(merged: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=str(merged.get(CONF_HOST, ""))): str,
            vol.Optional(CONF_PORT, default=int(merged.get(CONF_PORT, DEFAULT_PORT))): int,
            vol.Optional(
                CONF_CHANNELS,
                default=int(merged.get(CONF_CHANNELS, DEFAULT_CHANNELS)),
            ): vol.All(vol.Coerce(int), vol.Range(min=1, max=MAX_INPUT_CHANNELS)),
            vol.Optional(
                CONF_MIXER_MODEL,
                default=str(merged.get(CONF_MIXER_MODEL, DEFAULT_MIXER_MODEL)),
            ): vol.In(["auto", "dl16s", "dl32r", "dl32s"]),
            vol.Optional(
                CONF_DEVICE_NAME,
                default=str(merged.get(CONF_DEVICE_NAME, "")),
            ): str,
            vol.Optional(
                CONF_SNAPSHOT_SLOTS,
                default=int(merged.get(CONF_SNAPSHOT_SLOTS, DEFAULT_SNAPSHOT_SLOTS)),
            ): vol.All(vol.Coerce(int), vol.Range(min=1, max=64)),
            vol.Optional(
                CONF_SNAPSHOT_RECALL_ADDRESS,
                default=int(merged.get(CONF_SNAPSHOT_RECALL_ADDRESS, 0)),
            ): int,
        }
    )


def _split_data_and_options(user_input: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    data = {k: user_input[k] for k in CONFIG_ENTRY_DATA_KEYS}
    options = {k: user_input[k] for k in CONFIG_ENTRY_OPTION_KEYS}
    return data, options


async def _validate_connection(host: str, port: int, mixer_model: str) -> None:
    host = host.strip()
    client = MackieClient(host=host, port=int(port), mixer_model=str(mixer_model))
    try:
        await asyncio.wait_for(client.connect(), timeout=20.0)
    finally:
        await client.close()


class MackieDLConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 5

    @staticmethod
    @callback
    def async_get_options_flow(_entry: config_entries.ConfigEntry) -> MackieDLOptionsFlow:
        return MackieDLOptionsFlow()

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            await self.async_set_unique_id(host.lower())
            self._abort_if_unique_id_configured()

            try:
                await _validate_connection(
                    host,
                    int(user_input[CONF_PORT]),
                    str(user_input[CONF_MIXER_MODEL]),
                )
            except (TimeoutError, asyncio.CancelledError):
                raise
            except Exception:
                errors["base"] = "cannot_connect"
            else:
                data, options = _split_data_and_options(user_input)
                title = (options.get(CONF_DEVICE_NAME) or "").strip() or host
                return self.async_create_entry(title=title, data=data, options=options)

        return self.async_show_form(
            step_id="user",
            data_schema=_defaults_from_merged({}),
            errors=errors,
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        entry = self._get_reconfigure_entry()
        merged = config_entry_merged(entry)
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            try:
                await _validate_connection(
                    host,
                    int(user_input[CONF_PORT]),
                    str(user_input[CONF_MIXER_MODEL]),
                )
            except (TimeoutError, asyncio.CancelledError):
                raise
            except Exception:
                errors["base"] = "cannot_connect"
            else:
                data_updates, options_updates = _split_data_and_options(user_input)
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates=data_updates,
                    options_updates=options_updates,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_defaults_from_merged(merged),
            errors=errors,
        )


class MackieDLOptionsFlow(config_entries.OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DEVICE_NAME,
                    default=str(opts.get(CONF_DEVICE_NAME, "")),
                ): str,
                vol.Optional(
                    CONF_SNAPSHOT_SLOTS,
                    default=int(opts.get(CONF_SNAPSHOT_SLOTS, DEFAULT_SNAPSHOT_SLOTS)),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=64)),
                vol.Optional(
                    CONF_SNAPSHOT_RECALL_ADDRESS,
                    default=int(opts.get(CONF_SNAPSHOT_RECALL_ADDRESS, 0)),
                ): int,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
