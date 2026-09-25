"""Temporary local #84874 carry: real YAML loader and typed-target contracts."""

import logging

import pytest
import yaml

from gateway.config import GatewayConfig, HomeChannel, Platform, PlatformConfig, load_gateway_config


def target(chat="C-OPS", **kw):
    return {"platform": "slack", "chat_id": chat, "name": "Operations", **kw}


def load_yaml(tmp_path, monkeypatch, data):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(data))
    return load_gateway_config()


@pytest.mark.parametrize("shape,expected", [
    ({"slack": {"gateway_restart_channel": target()}}, "C-OPS"),
    ({"platforms": {"slack": {"gateway_restart_channel": target()}}}, "C-OPS"),
    ({"gateway": {"platforms": {"slack": {"gateway_restart_channel": target()}}}}, "C-OPS"),
    ({"gateway": {"platforms": {"slack": {"gateway_restart_channel": target("C-NESTED")}}},
      "platforms": {"slack": {"gateway_restart_channel": target("C-PLATFORMS")}}}, "C-PLATFORMS"),
    ({"gateway": {"platforms": {"slack": {"gateway_restart_channel": target("C-NESTED")}}},
      "platforms": {"slack": {"gateway_restart_channel": target("C-PLATFORMS")}},
      "slack": {"gateway_restart_channel": target("C-ROOT")}}, "C-ROOT"),
    ({"gateway": {"platforms": {"slack": {"gateway_restart_channel": target("C-NESTED")}}},
      "slack": {"typing_indicator": False}}, "C-NESTED"),
    ({"platforms": {"slack": {"gateway_restart_channel": target("C-LOWER")}},
      "slack": {"gateway_restart_channel": None}}, None),
    ({"gateway": {"platforms": {"slack": {"gateway_restart_channel": target("C-LOWER")}}},
      "platforms": {"slack": {"gateway_restart_channel": None}}}, None),
])
def test_yaml_precedence_and_typed_roundtrip(tmp_path, monkeypatch, shape, expected):
    cfg = load_yaml(tmp_path, monkeypatch, shape)
    pc = cfg.platforms[Platform.SLACK]
    assert pc.enabled is False  # The target alone must not activate a native adapter.
    assert pc.home_channel is None
    assert "gateway_restart_channel" not in pc.extra
    actual = pc.gateway_restart_channel
    assert (actual.chat_id if actual else None) == expected
    restored = GatewayConfig.from_dict(cfg.to_dict()).platforms[Platform.SLACK]
    assert restored.gateway_restart_channel == actual
    # Existing positional arguments must not shift when appending the local field.
    home = HomeChannel(Platform.SLACK, "C-HOME", "Home")
    positional = PlatformConfig(True, None, None, home, "all", False, False, "Working", {}, {"kept": True})
    assert positional.home_channel is home
    assert positional.reply_to_mode == "all"
    assert positional.gateway_restart_notification is False
    assert positional.extra == {"kept": True}
    assert positional.gateway_restart_channel is None


_INVALID = [
    "PRIVATE-SENTINEL", ["PRIVATE-SENTINEL"], False, {},
    target(platform="discord"), target(platform="PRIVATE-SENTINEL"),
    target(platform={"PRIVATE-SENTINEL": True}), target(platform=None),
    target(chat=None), target(chat=" \t"), target(chat=False), target(chat=1.5),
    target(chat=["PRIVATE-SENTINEL"]), target(chat={"PRIVATE-SENTINEL": True}),
    target(thread_id=False), target(thread_id=" "), target(thread_id=["PRIVATE-SENTINEL"]),
    target(user_id={"PRIVATE-SENTINEL": True}), target(user_id=" "),
    target(scope_id=False), target(scope_id=["PRIVATE-SENTINEL"]),
    target(name={"PRIVATE-SENTINEL": True}),
]


@pytest.mark.parametrize("raw", _INVALID)
@pytest.mark.parametrize("shape", ["root", "platforms", "gateway"])
def test_invalid_override_warns_privately_and_keeps_platform(tmp_path, monkeypatch, caplog, raw, shape):
    block = {"gateway_restart_channel": raw}
    data = {"platforms": {"slack": {
        "enabled": True, "home_channel": target("C-HOME"),
        "gateway_restart_channel": target("C-LOWER"),
    }}}
    if shape == "root":
        data["slack"] = block
    elif shape == "platforms":
        data["platforms"]["slack"].update(block)
    else:
        data["gateway"] = {"platforms": {"slack": {**data.pop("platforms")["slack"], **block}}}
    with caplog.at_level(logging.WARNING):
        cfg = load_yaml(tmp_path, monkeypatch, data)
    pc = cfg.platforms[Platform.SLACK]
    assert pc.enabled is True
    assert pc.gateway_restart_channel is None
    assert cfg.get_home_channel(Platform.SLACK).chat_id == "C-HOME"
    warnings = [r.getMessage() for r in caplog.records if "gateway_restart_channel" in r.getMessage()]
    assert warnings and all("fall back to the home channel" in w for w in warnings)
    assert "PRIVATE-SENTINEL" not in caplog.text
    assert "C-LOWER" not in caplog.text
    assert "C-HOME" not in caplog.text


@pytest.mark.parametrize("shape", ["root", "platforms", "gateway"])
def test_target_metadata_and_false_flag_load_without_inheritance(tmp_path, monkeypatch, shape):
    block = {"gateway_restart_channel": target(thread_id=0, user_id="U-OPS", scope_id="T-OPS"),
             "gateway_restart_notification": False}
    data = {"slack": block} if shape == "root" else {"platforms": {"slack": block}}
    if shape == "gateway":
        data = {"gateway": data}
    pc = load_yaml(tmp_path, monkeypatch, data).platforms[Platform.SLACK]
    assert pc.gateway_restart_notification is False
    assert pc.gateway_restart_channel.to_dict() == target(thread_id="0", user_id="U-OPS", scope_id="T-OPS")
    assert pc.home_channel is None