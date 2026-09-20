"""Local lifecycle carry only: real runner methods, synthetic config, fake egress."""

import json
from unittest.mock import AsyncMock

import pytest
import yaml

import gateway.run as gateway_run
from gateway.config import HomeChannel, Platform, PlatformConfig, load_gateway_config
from gateway.platforms.base import SendResult
from gateway.session import SessionSource, build_session_key
from tests.gateway.restart_test_helpers import make_restart_runner


class Egress:
    def __init__(self, *, fronts=True, success=True):
        self.fronts = fronts
        self.send = AsyncMock(return_value=SendResult(success=success))
        self.send_for_platform = AsyncMock(return_value=SendResult(success=success))

    def fronts_platform(self, platform):
        return self.fronts and platform == Platform.SLACK


@pytest.fixture
def runner_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    runner, _ = make_restart_runner()
    runner._free_tier_startup_line = lambda: None  # No provider/auth lookup in these transport tests.
    native, relay = Egress(), Egress()
    runner.adapters = {Platform.SLACK: native, Platform.RELAY: relay}
    block = {
        "enabled": True,
        "home_channel": {"platform": "slack", "chat_id": "C-HOME", "thread_id": "home-thread",
                         "name": "Home", "user_id": "U-HOME", "scope_id": "T-HOME"},
        "gateway_restart_channel": {"platform": "slack", "chat_id": "C-OPS", "name": "Ops",
                                    "thread_id": "ops-thread", "user_id": "U-OPS", "scope_id": "T-OPS"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"slack": {
        "gateway_restart_channel": block.pop("gateway_restart_channel")},
        "platforms": {"slack": block, "relay": {"enabled": True}}}))
    runner.config = load_gateway_config()
    return runner, native, relay, tmp_path


async def broadcast(runner, site, **kwargs):
    if site == "startup":
        return await runner._send_home_channel_startup_notifications(**kwargs)
    await runner._notify_active_sessions_of_shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("site", ["startup", "shutdown"])
@pytest.mark.parametrize("has_home", [False, True])
@pytest.mark.parametrize("mode,expected", [
    ("native", "native"), ("failed_native", None), ("relay", "relay"),
    ("unrelated_relay", None), ("disabled_relay", None), ("flag_false", None),
])
async def test_explicit_override_transport_and_destination(runner_env, site, has_home, mode, expected):
    runner, native, relay, _ = runner_env
    pc = runner.config.platforms[Platform.SLACK]
    if not has_home:
        pc.home_channel = None
    if mode in {"failed_native", "relay", "unrelated_relay", "disabled_relay"}:
        runner.adapters.pop(Platform.SLACK)
    if mode in {"relay", "unrelated_relay", "disabled_relay"}:
        pc.enabled = False
    if mode == "unrelated_relay":
        relay.fronts = False
    if mode == "disabled_relay":
        runner.config.platforms[Platform.RELAY].enabled = False
    if mode == "flag_false":
        pc.gateway_restart_notification = False
    delivered = await broadcast(runner, site)
    if expected is None:
        native.send.assert_not_awaited()
        relay.send_for_platform.assert_not_awaited()
        if site == "startup":
            assert delivered == set()
    else:
        call = native.send.await_args if expected == "native" else relay.send_for_platform.await_args
        assert call is not None
        assert (native.send.await_count, relay.send_for_platform.await_count) == (
            (1, 0) if expected == "native" else (0, 1))
        assert call.args[0 if expected == "native" else 1] == "C-OPS"
        metadata = call.kwargs["metadata"]
        assert metadata["thread_id"] == "ops-thread"
        assert "home-thread" not in str(metadata)
        assert "U-HOME" not in str(metadata) and "T-HOME" not in str(metadata)
        if expected == "relay":
            assert call.args[0] == Platform.SLACK
            assert metadata["user_id"] == "U-OPS" and metadata["scope_id"] == "T-OPS"
        if site == "startup":
            assert delivered == {("slack", "C-OPS", "ops-thread")}
    assert runner.config.get_home_channel(Platform.SLACK) is pc.home_channel


@pytest.mark.asyncio
@pytest.mark.parametrize("site", ["startup", "shutdown"])
@pytest.mark.parametrize("override", [None, "mismatch", "blank", "bad_type"])
async def test_unset_and_invalid_keep_native_home_fallback(runner_env, site, override):
    runner, native, relay, _ = runner_env
    pc = runner.config.platforms[Platform.SLACK]
    pc.gateway_restart_channel = {
        None: None,
        "mismatch": HomeChannel(Platform.DISCORD, "C-OPS", "Ops"),
        "blank": HomeChannel(Platform.SLACK, " ", "Ops"),
        "bad_type": HomeChannel(Platform.SLACK, None, "Ops"),
    }[override]
    await broadcast(runner, site)
    native.send.assert_awaited_once()
    assert native.send.await_args.args[0] == "C-HOME"
    assert native.send.await_args.kwargs["metadata"]["thread_id"] == "home-thread"
    relay.send_for_platform.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_unset_preserves_release_relay_asymmetry(runner_env, enabled):
    # The release allows Relay home startup but not Relay home shutdown. The local
    # override must not silently expand shutdown or tighten the unset startup path.
    runner, native, relay, _ = runner_env
    pc = runner.config.platforms[Platform.SLACK]
    pc.gateway_restart_channel = None
    pc.enabled = enabled
    runner.adapters.pop(Platform.SLACK)
    await broadcast(runner, "startup")
    relay.send_for_platform.assert_awaited_once()
    assert relay.send_for_platform.await_args.args[1] == "C-HOME"
    relay.send_for_platform.reset_mock()
    await broadcast(runner, "shutdown")
    relay.send_for_platform.assert_not_awaited()
    native.send.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("site", ["startup", "shutdown"])
async def test_no_home_provenance_inheritance_and_false_send(runner_env, site):
    runner, _, relay, _ = runner_env
    pc = runner.config.platforms[Platform.SLACK]
    pc.enabled = False
    runner.adapters.pop(Platform.SLACK)
    pc.gateway_restart_channel = HomeChannel(Platform.SLACK, "C-OPS", "Ops")
    await broadcast(runner, site)
    metadata = relay.send_for_platform.await_args.kwargs["metadata"]
    assert not metadata.get("user_id") and not metadata.get("scope_id") and not metadata.get("thread_id")
    relay.send_for_platform.reset_mock()
    relay.send_for_platform.return_value = SendResult(success=False, error="synthetic failure")
    delivered = await broadcast(runner, site)
    relay.send_for_platform.assert_awaited_once()
    if site == "startup":
        assert delivered == set()  # Failure is never recorded as delivered or retried at home.


@pytest.mark.asyncio
async def test_active_shutdown_dedup_and_suppression_do_not_redirect_active_notices(runner_env, monkeypatch):
    runner, native, _, _ = runner_env
    source = SessionSource(platform=Platform.SLACK, chat_id="C-ACTIVE", chat_type="group", thread_id="active-thread")
    key = build_session_key(source)
    runner._running_agents = {key: object()}
    runner._cache_session_source(key, source)
    await broadcast(runner, "shutdown")
    assert [c.args[0] for c in native.send.await_args_list] == ["C-ACTIVE", "C-OPS"]
    assert native.send.await_args_list[0].kwargs["metadata"]["thread_id"] == "active-thread"

    native.send.reset_mock()
    runner.config.platforms[Platform.SLACK].gateway_restart_channel = HomeChannel(
        Platform.SLACK, "C-ACTIVE", "Ops", thread_id="active-thread")
    await broadcast(runner, "shutdown")
    native.send.assert_awaited_once()  # Identical chat AND thread dedup against active notice.

    for suppression in ("in_chat", "quiet_drain", "flag_false"):
        native.send.reset_mock()
        runner.config.platforms[Platform.SLACK].gateway_restart_channel = HomeChannel(Platform.SLACK, "C-OPS", "Ops")
        runner._restart_requested = suppression == "in_chat"
        runner._restart_command_source = source if suppression == "in_chat" else None
        runner.config.platforms[Platform.SLACK].gateway_restart_notification = suppression != "flag_false"
        monkeypatch.setattr("gateway.drain_control.drain_notification_suppressed", lambda: suppression == "quiet_drain")
        await broadcast(runner, "shutdown")
        if suppression == "flag_false":
            native.send.assert_not_awaited()
        else:
            native.send.assert_awaited_once()
            assert native.send.await_args.args[0] == "C-ACTIVE"


@pytest.mark.asyncio
async def test_only_planned_startup_and_exact_thread_skip(runner_env, monkeypatch):
    runner, native, _, tmp_path = runner_env
    runner._claim_pending_obligations = AsyncMock(return_value=[])
    runner._redeliver_claimed_obligations = AsyncMock()
    monkeypatch.setattr(gateway_run, "_startup_restore_drain_timeout_secs", lambda: 0)
    await runner._await_startup_boot_sends(planned_restart_notification_pending=False)
    native.send.assert_not_awaited()
    marker = tmp_path / ".restart_pending.json"
    marker.write_text("{}")
    await runner._await_startup_boot_sends(planned_restart_notification_pending=True)
    native.send.assert_awaited_once()
    assert not marker.exists()
    assert native.send.await_args.args[0] == "C-OPS"
    native.send.reset_mock()
    assert await broadcast(runner, "startup", skip_targets={("slack", "C-OPS", "ops-thread")}) == set()
    native.send.assert_not_awaited()
    assert await broadcast(runner, "startup", skip_targets={("slack", "C-OPS", "another-thread")}) == {
        ("slack", "C-OPS", "ops-thread")}


@pytest.mark.asyncio
async def test_restart_requester_and_db_warning_stay_on_original_destinations(runner_env):
    runner, native, _, tmp_path = runner_env
    marker = tmp_path / ".restart_notify.json"
    marker.write_text(json.dumps({"platform": "slack", "chat_id": "C-REQUESTER", "thread_id": "request-thread"}))
    assert await runner._send_restart_notification() == ("slack", "C-REQUESTER", "request-thread")
    assert not marker.exists()
    assert native.send.await_args.args[0] == "C-REQUESTER"
    native.send.reset_mock()
    runner._session_db_init_error = "synthetic unavailable store"
    runner.config.platforms[Platform.SLACK].gateway_restart_notification = False
    await runner._send_session_db_warning_notifications()
    native.send.assert_awaited_once()
    assert native.send.await_args.args[0] == "C-HOME"
    assert native.send.await_args.kwargs["metadata"]["thread_id"] == "home-thread"


@pytest.mark.asyncio
@pytest.mark.parametrize("has_home", [False, True])
async def test_planned_replay_tracks_override_through_failure_and_partial_delivery(runner_env, has_home):
    runner, native, relay, tmp_path = runner_env
    pc = runner.config.platforms[Platform.SLACK]
    if not has_home:
        pc.home_channel = None
    runner.config.platforms[Platform.DISCORD] = PlatformConfig(
        enabled=True, home_channel=HomeChannel(Platform.DISCORD, "D-HOME", "Other"),
    )
    marker = tmp_path / ".restart_pending.json"
    marker.write_text("{}")
    runner.adapters.pop(Platform.SLACK)
    await runner._replay_pending_planned_restart_notification()
    assert marker.exists()
    relay.send_for_platform.assert_not_awaited()  # Never mask the failed enabled native bot.

    runner.adapters[Platform.SLACK] = native
    native.send.return_value = SendResult(success=False, error="synthetic failure")
    await runner._replay_pending_planned_restart_notification()
    native.send.assert_awaited_once()
    assert native.send.await_args.args[0] == "C-OPS"
    assert json.loads(marker.read_text())["delivered_targets"] == []

    native.send.return_value = SendResult(success=True)
    await runner._replay_pending_planned_restart_notification()
    assert json.loads(marker.read_text())["delivered_targets"] == [["slack", "C-OPS", "ops-thread"]]
    assert native.send.await_count == 2
    # A new runner must honor the persisted destination, not a process-local dedup set.
    recovered = object.__new__(type(runner))
    recovered.__dict__.update(runner.__dict__)
    recovered._planned_restart_notice_lock = None
    discord = Egress()
    recovered.adapters[Platform.DISCORD] = discord
    await recovered._replay_pending_planned_restart_notification()
    assert not marker.exists()
    discord.send.assert_awaited_once()
    assert discord.send.await_args.args[0] == "D-HOME"
    assert native.send.await_count == 2
    await recovered._replay_pending_planned_restart_notification()
    discord.send.assert_awaited_once()
    assert native.send.await_count == 2


@pytest.mark.asyncio
async def test_profile_scoped_targets_and_shutdown_warning_policy_do_not_leak(tmp_path, monkeypatch):
    from agent.secret_scope import set_multiplex_active
    from gateway.run import _profile_runtime_scope

    homes = {name: tmp_path / name for name in ("alpha", "beta")}
    for name, home in homes.items():
        home.mkdir()
        (home / "config.yaml").write_text(yaml.safe_dump({
            "slack": {"enabled": True, "gateway_restart_channel": {
                "platform": "slack", "chat_id": f"C-OPS-{name}", "thread_id": f"thread-{name}",
            }},
            "display": {"suppress_warning_notifications": name == "beta"},
        }))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    set_multiplex_active(True)
    try:
        for name in ("alpha", "beta", "alpha"):
            with _profile_runtime_scope(homes[name], prepared_secret_scope={}, hydrate_secrets=False):
                runner, _ = make_restart_runner()
                runner.config = load_gateway_config()
                runner._free_tier_startup_line = lambda: None
                native = Egress()
                runner.adapters = {Platform.SLACK: native}
                await broadcast(runner, "startup")
                await broadcast(runner, "shutdown")
                # Production suppression gates shutdown diagnostics, not the online notice.
                assert native.send.await_count == (1 if name == "beta" else 2)
                assert all(call.args[0] == f"C-OPS-{name}" for call in native.send.await_args_list)
                assert all(call.kwargs["metadata"]["thread_id"] == f"thread-{name}"
                           for call in native.send.await_args_list)
                assert runner.config.get_home_channel(Platform.SLACK) is None
    finally:
        set_multiplex_active(False)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["native", "missing_native", "relay", "unrelated_relay", "opt_out", "broken"])
async def test_served_override_uses_own_config_and_transport_until_replay_completes(
    runner_env, monkeypatch, mode,
):
    """Host-wide replay must not borrow a launch bot or forget an unavailable secondary override."""
    import gateway.delivery as delivery
    from gateway.run import _profile_runtime_scope

    runner, launch, launch_relay, tmp_path = runner_env
    home = tmp_path / "secondary"
    home.mkdir()
    (home / "config.yaml").write_text(yaml.safe_dump({"platforms": {
        "slack": {"enabled": mode not in {"relay", "unrelated_relay"},
                  "gateway_restart_notification": mode != "opt_out",
                  "gateway_restart_channel": {"platform": "slack", "chat_id": "C-SECONDARY", "thread_id": "own-thread"}},
        "relay": {"enabled": True},
    }}))
    with _profile_runtime_scope(home, prepared_secret_scope={}, hydrate_secrets=False):
        secondary_config = load_gateway_config()
    own, relay = Egress(), Egress(fronts=mode != "unrelated_relay")
    runner._profile_configs = {"secondary": secondary_config}
    runner._profile_adapters = {"secondary": {Platform.RELAY: relay}}
    if mode in {"native", "opt_out", "broken"}:
        runner._profile_adapters["secondary"][Platform.SLACK] = own
    resolve = delivery.resolve_delivery_transport

    def possibly_broken(platform, config, adapters):
        if mode == "broken" and config is secondary_config:
            raise RuntimeError("synthetic broken transport")
        return resolve(platform, config, adapters)

    monkeypatch.setattr(delivery, "resolve_delivery_transport", possibly_broken)
    marker = tmp_path / ".restart_pending.json"
    marker.write_text("{}")
    await runner._replay_pending_planned_restart_notification()
    launch.send.assert_awaited_once()
    assert launch.send.await_args.args[0] == "C-OPS"
    launch_relay.send_for_platform.assert_not_awaited()
    if mode in {"native", "relay"}:
        call = own.send.await_args if mode == "native" else relay.send_for_platform.await_args
        assert call.args[0 if mode == "native" else 1] == "C-SECONDARY"
        assert call.kwargs["metadata"]["thread_id"] == "own-thread"
        assert not marker.exists()
    elif mode == "opt_out":
        assert not marker.exists()
        own.send.assert_not_awaited()
        relay.send_for_platform.assert_not_awaited()
    else:
        own.send.assert_not_awaited()
        relay.send_for_platform.assert_not_awaited()
        assert json.loads(marker.read_text())["delivered_targets"] == [["slack", "C-OPS", "ops-thread"]]
        # Recovery discharges only the owning target; the launch destination stays deduplicated.
        monkeypatch.setattr(delivery, "resolve_delivery_transport", resolve)
        secondary_config.platforms[Platform.SLACK].enabled = True
        runner._profile_adapters["secondary"][Platform.SLACK] = own
        await runner._replay_pending_planned_restart_notification()
        own.send.assert_awaited_once()
        assert own.send.await_args.args[0] == "C-SECONDARY"
        assert not marker.exists()
    launch.send.assert_awaited_once()
    assert secondary_config.get_home_channel(Platform.SLACK) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("same_thread", [False, True])
async def test_shared_lifecycle_chat_deduplicates_delivery_but_accounts_for_each_profile(runner_env, same_thread):
    """Upstream shared-chat dedup is preserved for overrides, including marker replay."""
    from gateway.config import GatewayConfig

    runner, launch, _, tmp_path = runner_env
    secondary = GatewayConfig.from_dict(runner.config.to_dict())
    target = secondary.platforms[Platform.SLACK].gateway_restart_channel
    target.thread_id = "ops-thread" if same_thread else "secondary-thread"
    own = Egress()
    runner._profile_configs = {"secondary": secondary}
    runner._profile_adapters = {"secondary": {Platform.SLACK: own}}
    # An unavailable third platform keeps the marker, exposing per-profile accounting.
    runner.config.platforms[Platform.DISCORD] = PlatformConfig(
        enabled=True, home_channel=HomeChannel(Platform.DISCORD, "D-WAIT", "Wait"))
    marker = tmp_path / ".restart_pending.json"
    marker.write_text("{}")
    await runner._replay_pending_planned_restart_notification()
    launch.send.assert_awaited_once()
    assert own.send.await_count == (0 if same_thread else 1)
    assert {tuple(t) for t in json.loads(marker.read_text())["delivered_targets"]} == {
        ("slack", "C-OPS", "ops-thread"), ("secondary:slack", "C-OPS", target.thread_id),
    }
    recovered = object.__new__(type(runner))
    recovered.__dict__.update(runner.__dict__)
    recovered._planned_restart_notice_lock = None
    recovered.adapters[Platform.DISCORD] = Egress()
    await recovered._replay_pending_planned_restart_notification()
    assert not marker.exists()
    launch.send.assert_awaited_once()
    assert own.send.await_count == (0 if same_thread else 1)
