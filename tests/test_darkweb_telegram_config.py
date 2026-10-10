from unittest.mock import patch

from cyclothone.darkweb.telegram_config import (
    DEFAULT_PUBLIC_TELEGRAM_CHANNELS,
    configured_telegram_channels,
)


def test_telegram_config_uses_same_defaults_when_unset():
    with patch.dict("os.environ", {}, clear=True):
        assert configured_telegram_channels() == list(DEFAULT_PUBLIC_TELEGRAM_CHANNELS)


def test_telegram_config_explicit_empty_value_disables_source():
    with patch.dict(
        "os.environ",
        {"CYCLOTHONE_DW_TELEGRAM_CHANNELS": ""},
        clear=True,
    ):
        assert configured_telegram_channels() == []


def test_telegram_config_normalizes_and_deduplicates_public_handles():
    with patch.dict(
        "os.environ",
        {
            "CYCLOTHONE_DW_TELEGRAM_CHANNELS": (
                "@ChannelOne,https://t.me/s/ChannelTwo,channelone,"
                "https://t.me/+privateInvite,https://example.com/channel,"
                "invalid handle,tiny"
            )
        },
        clear=True,
    ):
        assert configured_telegram_channels() == ["ChannelOne", "ChannelTwo"]


def test_telegram_config_uses_legacy_env_only_when_new_name_is_unset():
    with patch.dict(
        "os.environ",
        {"SENTINEL_DW_TELEGRAM_CHANNELS": "legacy_channel"},
        clear=True,
    ):
        assert configured_telegram_channels() == ["legacy_channel"]
