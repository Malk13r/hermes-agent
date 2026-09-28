"""Multi-process contract for named profiles BORROWING the root's single-use Codex grant.

One OAuth grant lives in the global-root ``auth.json``; profiles with no Codex state of their own
read it through the root fallback. Codex refresh tokens are single-use with family revocation, so
every refresh path in every profile must serialize on the OWNER's (root's) lock, re-read the
owner's state under it, and write the rotated pair back only to the owner:

* concurrent refreshes across profiles (pool and singleton paths, mixed) present the refresh
  token exactly once and every process adopts the replacement;
* a terminally rejected grant leaves no profile-local shadow, so the owner's single re-login
  reaches every profile again (no second login);
* a profile that owns its own grant keeps refreshing it locally and never touches root.

Real interpreters (``codex_root_grant_worker.py``) run against disposable homes; the token
endpoint is a file-backed fake and sockets are disabled, so no credential or network is used.
"""

import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.agent.codex_root_grant_worker import fake_jwt, fp

REPO = Path(__file__).resolve().parents[2]
WORKER = Path(__file__).with_name("codex_root_grant_worker.py")
CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
OTHER_PROVIDER_ROW = {
    "id": "or0001", "label": "openrouter", "auth_type": "api_key", "priority": 0,
    "source": "manual", "access_token": "sk-or-synthetic-profile-local",
}


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _grant(family: str, *, expired: bool = True) -> dict:
    return {"access_token": fake_jwt(time.time() + (-60 if expired else 3600), family),
            "refresh_token": f"{family}-rt-0"}


def _codex_store(tokens: dict, *, pool_row_id=None, extra_pool=None) -> dict:
    store = {
        "version": 1,
        "providers": {"openai-codex": {
            "tokens": dict(tokens), "last_refresh": "2026-09-01T00:00:00Z", "auth_mode": "chatgpt"}},
        "credential_pool": dict(extra_pool or {}),
    }
    if pool_row_id:
        store["credential_pool"]["openai-codex"] = [{
            "id": pool_row_id, "label": "device_code", "auth_type": "oauth", "priority": 0,
            "source": "device_code", "base_url": CODEX_BASE_URL,
            "last_refresh": "2026-09-01T00:00:00Z", **tokens}]
    return store


class Lab:
    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.root = self.home / ".hermes"
        self.server = tmp_path / "token-endpoint.json"
        self.root.mkdir(mode=0o700, parents=True)
        (self.root / "config.yaml").write_text("model:\n  provider: openai-codex\n")
        self._seq = 0

    def profile(self, name: str, auth=None) -> Path:
        home = self.root / "profiles" / name
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        (home / "config.yaml").write_text("model:\n  provider: openai-codex\n")
        if auth is not None:
            _write_json(home / "auth.json", auth)
        return home

    def home_of(self, name: str) -> Path:
        return self.root if name == "root" else self.root / "profiles" / name

    def serve(self, *, valid: dict, revoked=()) -> None:
        _write_json(self.server, {"valid": dict(valid), "revoked": list(revoked),
                                  "presented": [], "issued_access": {}})

    def endpoint(self) -> dict:
        return _read_json(self.server)

    def _env(self, hermes_home: Path) -> dict:
        # Built from scratch: no inherited credentials, proxies or PYTEST_CURRENT_TEST.
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
            "HERMES_HOME": str(hermes_home), "PYTHONPATH": str(REPO), "PYTHONDONTWRITEBYTECODE": "1",
            "TZ": "UTC", "LANG": "C.UTF-8", "TMPDIR": str(self.tmp),
        }

    def run(self, jobs, *, before_go=None, **extra) -> list:
        """Start one interpreter per ``(profile, task)``, release them together, collect results.

        Workers load their pool before reporting ready; *before_go* runs after that, just before
        the release, so it brackets only the refresh phase."""
        go = self.tmp / f"go-{self._seq}"
        procs, readies = [], []
        for idx, (name, task) in enumerate(jobs):
            ready = self.tmp / f"ready-{self._seq}-{idx}"
            readies.append(ready)
            home = self.home_of(name)
            spec = {"repo": str(REPO), "expected_root": str(self.root), "hermes_home": str(home),
                    "server": str(self.server), "go": str(go), "ready": str(ready),
                    "task": task, "label": f"{name}:{task}", **extra}
            procs.append(subprocess.Popen(
                [sys.executable, str(WORKER), json.dumps(spec)], env=self._env(home),
                cwd=str(self.tmp), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        self._seq += 1
        deadline = time.monotonic() + 60
        while not all(r.exists() for r in readies) and time.monotonic() < deadline:
            if any(p.poll() is not None for p in procs):
                break
            time.sleep(0.01)
        if before_go is not None:
            before_go()
        go.write_text("go")
        results = []
        for proc in procs:
            out, err = proc.communicate(timeout=120)
            lines = [line for line in out.splitlines() if line.startswith('{"worker"')]
            assert proc.returncode == 0 and lines, f"worker failed rc={proc.returncode}: {err[-2000:]}"
            results.append(json.loads(lines[-1])["worker"])
        return results

    def run_one(self, name: str, task: str, **extra) -> dict:
        return self.run([(name, task)], **extra)[0]

    def profile_has_codex(self, name: str) -> bool:
        """A local singleton block (even token-less) or pool row shadows the root grant."""
        path = self.home_of(name) / "auth.json"
        if not path.exists():
            return False
        store = _read_json(path)
        return "openai-codex" in (store.get("providers") or {}) or bool(
            (store.get("credential_pool") or {}).get("openai-codex"))


@pytest.fixture
def lab(tmp_path):
    return Lab(tmp_path)


def _borrowing_profiles(lab: Lab) -> None:
    lab.profile("assistant")
    lab.profile("coach")
    # An existing store with profile-local state for OTHER providers and an empty Codex slice.
    lab.profile("third", auth={"version": 1, "providers": {},
                               "credential_pool": {"openai-codex": [], "openrouter": [OTHER_PROVIDER_ROW]}})


def _assert_single_rotation_adopted(lab: Lab, results: list) -> None:
    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["root-rt-0"]
    assert endpoint["revoked"] == []
    replacement = fp(endpoint["issued_access"]["root"])
    assert [r["token"] for r in results] == [replacement] * len(results)
    root = _read_json(lab.root / "auth.json")
    assert root["providers"]["openai-codex"]["tokens"]["refresh_token"] == "root-rt-1"
    for row in root.get("credential_pool", {}).get("openai-codex", []):
        assert row["refresh_token"] == "root-rt-1"
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name
    third = _read_json(lab.home_of("third") / "auth.json")
    assert third["credential_pool"]["openrouter"] == [OTHER_PROVIDER_ROW]


@pytest.mark.parametrize("root_pool_row", [True, False], ids=["root-pool-row", "root-singleton-only"])
def test_cross_profile_pool_refreshes_rotate_the_root_grant_once(lab, root_pool_row):
    _write_json(lab.root / "auth.json", _codex_store(
        _grant("root"), pool_row_id="rootdc" if root_pool_row else None))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    results = lab.run([("assistant", "pool"), ("coach", "pool"), ("third", "pool"), ("coach", "pool")])

    _assert_single_rotation_adopted(lab, results)


def test_mixed_singleton_and_pool_paths_rotate_the_root_grant_once(lab):
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    results = lab.run([("assistant", "pool"), ("coach", "singleton"),
                       ("third", "singleton"), ("coach", "pool")])

    _assert_single_rotation_adopted(lab, results)


def test_revoked_root_grant_keeps_fallback_so_one_owner_relogin_serves_every_profile(lab):
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"}, revoked=["root"])

    results = lab.run([("assistant", "pool"), ("coach", "pool"), ("third", "pool")])

    assert [r["token"] for r in results] == [None, None, None]
    presented = lab.endpoint()["presented"]
    # Only the stored token is ever presented, and once: peers read the owner's verdict.
    assert [p["token"] for p in presented] == ["root-rt-0"]
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name
        assert lab.run_one(name, "inspect")["singleton_source"] == "root"

    fresh = _grant("fresh", expired=False)
    lab.serve(valid={"fresh": "fresh-rt-0"}, revoked=["root"])
    assert lab.run_one("root", "relogin", tokens=fresh) == {"relogin": True}

    after = lab.run([("assistant", "pool"), ("coach", "singleton"), ("third", "pool")])

    assert [r["token"] for r in after] == [fp(fresh["access_token"])] * 3
    assert lab.endpoint()["presented"] == []
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


@pytest.mark.parametrize("task", ["pool", "singleton"])
def test_quota_probe_refresh_of_borrowed_row_redeems_root_token_once(lab, task):
    """An expired, rate-limited root row is refreshed before the usage probe; the singleton path
    reaches that probe only when root has no singleton (pool-only root)."""
    store = _codex_store(_grant("root"), pool_row_id="rootdc")
    store["credential_pool"]["openai-codex"][0].update(
        last_status="exhausted", last_status_at=time.time(), last_error_code=429,
        last_error_reason="usage_limit_reached", last_error_reset_at=time.time() + 86400)
    if task == "singleton":
        del store["providers"]["openai-codex"]
    _write_json(lab.root / "auth.json", store)
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    lab.run([("assistant", task), ("coach", task), ("third", task)])

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["root-rt-0"]
    assert endpoint["revoked"] == []
    root = _read_json(lab.root / "auth.json")
    assert root["credential_pool"]["openai-codex"][0]["refresh_token"] == "root-rt-1"
    if task == "pool":
        assert root["providers"]["openai-codex"]["tokens"]["refresh_token"] == "root-rt-1"
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def test_profile_owned_grant_refreshes_locally_without_root(lab):
    root_store = _codex_store(_grant("root"), pool_row_id="rootdc")
    _write_json(lab.root / "auth.json", root_store)
    root_bytes = (lab.root / "auth.json").read_bytes()
    lab.profile("solo", auth=_codex_store(
        _grant("solo"), pool_row_id="solodc", extra_pool={"openrouter": [OTHER_PROVIDER_ROW]}))
    lab.serve(valid={"root": "root-rt-0", "solo": "solo-rt-0"})

    # Hold ROOT's auth lock across the refresh phase: refreshing a grant the profile owns
    # never needs it (the load-time forked-grant heal may, so the lock is taken after load).
    timing = {}
    with open(lab.root / "auth.lock", "a+") as held:
        def hold_root_lock():
            fcntl.flock(held.fileno(), fcntl.LOCK_EX)
            timing["released"] = time.monotonic()

        results = lab.run([("solo", "pool"), ("solo", "pool"), ("solo", "singleton")],
                          before_go=hold_root_lock)
        elapsed = time.monotonic() - timing["released"]
        fcntl.flock(held.fileno(), fcntl.LOCK_UN)

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["solo-rt-0"]
    assert endpoint["revoked"] == []
    assert [r["token"] for r in results] == [fp(endpoint["issued_access"]["solo"])] * 3
    assert elapsed < 12, "a locally owned refresh waited on the root lock"
    assert (lab.root / "auth.json").read_bytes() == root_bytes
    solo = _read_json(lab.home_of("solo") / "auth.json")
    assert solo["providers"]["openai-codex"]["tokens"]["refresh_token"] == "solo-rt-1"
    assert [row["refresh_token"] for row in solo["credential_pool"]["openai-codex"]] == ["solo-rt-1"]
    assert solo["credential_pool"]["openrouter"] == [OTHER_PROVIDER_ROW]
