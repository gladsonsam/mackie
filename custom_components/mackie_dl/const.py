from homeassistant.const import CONF_HOST, CONF_PORT

DOMAIN = "mackie_dl"

DEFAULT_PORT = 50001
DEFAULT_CHANNELS = 32
MAX_INPUT_CHANNELS = 32

CONF_CHANNELS = "channels"
CONF_DEVICE_NAME = "device_name"
CONF_SNAPSHOT_SLOTS = "snapshot_slots"
CONF_SNAPSHOT_RECALL_ADDRESS = "snapshot_recall_address"
CONF_MIXER_MODEL = "mixer_model"

# Legacy keys (ignored when mixer_model is set); kept for existing config entries.
CONF_INPUT_START_ADDRESS = "input_start_address"
CONF_INPUT_STRIDE = "input_stride"
CONF_INPUT_MUTE_OFFSET = "input_mute_offset"
CONF_INPUT_FADER_OFFSET = "input_fader_offset"

DEFAULT_MIXER_MODEL = "auto"
DEFAULT_SNAPSHOT_SLOTS = 64

# Config entry `data` vs `options` split (per HA: connection in data, preferences in options).
CONFIG_ENTRY_DATA_KEYS = frozenset(
    {CONF_HOST, CONF_PORT, CONF_CHANNELS, CONF_MIXER_MODEL}
)
CONFIG_ENTRY_OPTION_KEYS = frozenset(
    {CONF_DEVICE_NAME, CONF_SNAPSHOT_SLOTS, CONF_SNAPSHOT_RECALL_ADDRESS}
)

SERVICE_SET_INPUT_MUTE = "set_input_mute"
SERVICE_SET_INPUT_FADER = "set_input_fader"
SERVICE_RECALL_SNAPSHOT = "recall_snapshot"
SERVICE_RAW_SET_VALUE = "raw_set_value"


def config_entry_merged(entry) -> dict:
    return {**entry.data, **entry.options}
