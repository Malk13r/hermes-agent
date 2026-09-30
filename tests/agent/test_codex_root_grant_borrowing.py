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

from tests.agent.codex_root_grant_worker import CRASH_EXIT, fake_jwt, fp
from tests.network_guard import no_external_network  # noqa: F401  (fixture)

pytestmark = pytest.mark.usefixtures("no_external_network")

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
            if extra.get("fault") == "crash" and proc.returncode == CRASH_EXIT:
                results.append({"crashed": True})
                continue
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


def _root_codex(lab: Lab):
    root = _read_json(lab.root / "auth.json")
    singleton = (root.get("providers") or {}).get("openai-codex") or {}
    return singleton, (root.get("credential_pool") or {}).get("openai-codex") or []


_EVERY_PATH = [("assistant", "pool"), ("coach", "singleton"), ("third", "pool"),
               ("coach", "pool"), ("third", "singleton"), ("root", "singleton"), ("root", "pool")]


@pytest.mark.parametrize("task", ["pool", "singleton"])
@pytest.mark.parametrize("by", ["assistant", "root"], ids=["borrower", "root-owner"])
def test_unwritable_pending_marker_means_zero_post_and_is_not_sticky(lab, task, by):
    """Root cannot record the pre-POST marker: the shared token is never presented — by a borrower
    or by the root owner itself — root is untouched, and once root is writable again the grant
    rotates exactly once for everyone."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    root_bytes = (lab.root / "auth.json").read_bytes()
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    first = lab.run([(by, task), ("coach", task)], fault="marker")

    assert lab.endpoint()["presented"] == []
    assert [r["token"] for r in first] == [None, None]
    assert (lab.root / "auth.json").read_bytes() == root_bytes
    _assert_single_rotation_adopted(lab, lab.run(_EVERY_PATH[:5]))


def _held_refresh_tokens(singleton: dict, rows: list) -> set:
    return {r.get("refresh_token") for r in rows} | {(singleton.get("tokens") or {}).get("refresh_token")} - {None}


@pytest.mark.parametrize("task", ["pool", "singleton"])
@pytest.mark.parametrize("fault", ["commit", "crash", "ambiguous", "status_429", "status_503"])
def test_unrecorded_redemption_is_never_replayed_on_any_path_in_any_profile(lab, fault, task):
    """The POST happened but root never learned its outcome (commit failed, the process died, the
    connection dropped, the endpoint answered 429/503 after rotating). Root still holds only the
    spent token; its durable pending marker makes every later pool AND singleton attempt in every
    profile — root included — fail closed with zero POST, so the family is never revoked, and the
    owner's one ``hermes auth add`` recovers every path. The first failure already says so: an
    answer that does not prove the token unspent is never reported as "still valid, retry"."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    first = lab.run_one("assistant", task, fault=fault)

    assert first.get("token") is None
    if task == "singleton" and fault != "crash":
        assert first["error"] == "codex_refresh_outcome_uncertain"
    assert [p["token"] for p in lab.endpoint()["presented"]] == ["root-rt-0"]
    assert _held_refresh_tokens(*_root_codex(lab)) == {"root-rt-0"}  # never torn, never replaced

    later = lab.run(_EVERY_PATH)
    later += lab.run(_EVERY_PATH)  # a second round in fresh processes: the verdict is durable

    endpoint = lab.endpoint()
    assert len(endpoint["presented"]) == 1 and endpoint["revoked"] == []
    assert [r["token"] for r in later] == [None] * len(later)
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name

    fresh = _grant("fresh", expired=False)
    assert lab.run_one("root", "add_entry", tokens=fresh) == {"added": True}
    after = lab.run(_EVERY_PATH)

    assert [r["token"] for r in after] == [fp(fresh["access_token"])] * len(after)
    assert len(lab.endpoint()["presented"]) == 1 and lab.endpoint()["revoked"] == []
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def _root_layout(layout: str, *, expired: bool = True) -> dict:
    store = _codex_store(_grant("root", expired=expired),
                         pool_row_id=None if layout == "singleton-only" else "rootdc")
    if layout == "pool-only":
        del store["providers"]["openai-codex"]
    return store


def _same_account_cli_login(lab: Lab) -> dict:
    """A valid external Codex CLI login for the SAME account as root (so identity checks pass)."""
    cli = {"access_token": fake_jwt(time.time() + 3600, "root"), "refresh_token": "cli-rt-0"}
    _write_json(lab.home / ".codex" / "auth.json", {"tokens": cli})
    return cli


@pytest.mark.parametrize("fault,task,layout", [
    ("commit", "pool", "mixed"), ("commit", "singleton", "mixed"),
    ("crash", "pool", "mixed"), ("crash", "singleton", "mixed"),
    ("ambiguous", "pool", "mixed"), ("ambiguous", "singleton", "mixed"),
    ("crash", "pool", "pool-only"), ("crash", "singleton", "singleton-only"),
    ("commit", "singleton", "singleton-only"), ("ambiguous", "pool", "pool-only"),
    ("status_429", "pool", "pool-only"), ("status_503", "singleton", "mixed"),
])
@pytest.mark.parametrize("relogin", ["add_entry", "relogin"])
def test_root_owner_unrecorded_redemption_is_never_replayed_anywhere(lab, fault, task, layout, relogin):
    """The ROOT OWNER's own refresh (same profile, classic mode) POSTs, then its outcome is lost.
    Every later pool and singleton attempt — root's own and two+ borrowing profiles' — sends
    nothing more, the family is never revoked, the external Codex CLI login is never auto-adopted
    while the grant is uncertain, and a supervised root sign-in (``hermes auth add`` or the
    singleton login) clears it for every path."""
    _write_json(lab.root / "auth.json", _root_layout(layout))
    _borrowing_profiles(lab)
    cli = _same_account_cli_login(lab)
    lab.serve(valid={"root": "root-rt-0", "cli": "cli-rt-0"})

    first = lab.run_one("root", task, fault=fault)

    assert first.get("token") is None
    assert [p["token"] for p in lab.endpoint()["presented"]] == ["root-rt-0"]
    # Never torn between row and singleton, never replaced (an immediate verdict may clear both).
    assert _held_refresh_tokens(*_root_codex(lab)) <= {"root-rt-0"}

    later = lab.run(_EVERY_PATH)
    later += lab.run(_EVERY_PATH)

    endpoint = lab.endpoint()
    assert len(endpoint["presented"]) == 1 and endpoint["revoked"] == []
    assert [r["token"] for r in later] == [None] * len(later)
    assert fp(cli["access_token"]) not in [r["token"] for r in later]
    singleton, rows = _root_codex(lab)
    assert "cli-rt-0" not in [r.get("refresh_token") for r in rows] + [
        (singleton.get("tokens") or {}).get("refresh_token")]
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name

    fresh = _grant("fresh", expired=False)
    assert lab.run_one("root", relogin, tokens=fresh) in ({"added": True}, {"relogin": True})
    after = lab.run(_EVERY_PATH)

    assert [r["token"] for r in after] == [fp(fresh["access_token"])] * len(after)
    assert len(lab.endpoint()["presented"]) == 1 and lab.endpoint()["revoked"] == []
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


@pytest.mark.parametrize("layout", ["mixed", "singleton-only", "pool-only"])
def test_root_owner_rotation_is_one_commit_every_path_adopts_it(lab, layout):
    """Normal root-owned rotation: root's own refresh presents the token once, row and singleton
    land together, and root + borrowers on both paths adopt the replacement with no second POST."""
    _write_json(lab.root / "auth.json", _root_layout(layout))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    first = lab.run_one("root", "pool" if layout == "pool-only" else "singleton")
    results = [first] + lab.run(_EVERY_PATH)

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["root-rt-0"] and endpoint["revoked"] == []
    assert [r["token"] for r in results] == [fp(endpoint["issued_access"]["root"])] * len(results)
    singleton, rows = _root_codex(lab)
    held = [r["refresh_token"] for r in rows] + ([singleton["tokens"]["refresh_token"]] if singleton else [])
    assert held and set(held) == {"root-rt-1"}
    assert "refresh_outcome_pending" not in _read_json(lab.root / "auth.json") or not any(
        _read_json(lab.root / "auth.json")["refresh_outcome_pending"].get("openai-codex", {}).values())
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def test_root_owner_terminal_rejection_keeps_legitimate_cli_recovery(lab):
    """A DEFINITIVE rejection of root's own token is not an unknown outcome: its marker is cleared
    and the existing same-account Codex CLI recovery still repairs root (no replay, no revocation
    of the CLI's family)."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root")))
    cli = _same_account_cli_login(lab)
    lab.serve(valid={"cli": "cli-rt-0"}, revoked=["root"])

    result = lab.run_one("root", "singleton")

    assert result["token"] == fp(cli["access_token"])
    assert [p["token"] for p in lab.endpoint()["presented"]] == ["root-rt-0"]
    singleton, _ = _root_codex(lab)
    assert singleton["tokens"]["refresh_token"] == "cli-rt-0"
    assert not any((_read_json(lab.root / "auth.json").get("refresh_outcome_pending") or {})
                   .get("openai-codex", {}).values())


@pytest.mark.parametrize("fault", [None, "crash"])
def test_root_owner_quota_probe_refresh_is_marked_and_committed_once(lab, fault):
    """An expired, rate-limited ROOT-owned row is refreshed before the usage probe by root itself:
    the same marker + one-save commit. After a crash mid-probe, nothing is ever re-presented."""
    store = _codex_store(_grant("root"), pool_row_id="rootdc")
    store["credential_pool"]["openai-codex"][0].update(
        last_status="exhausted", last_status_at=time.time(), last_error_code=429,
        last_error_reason="usage_limit_reached", last_error_reset_at=time.time() + 86400)
    del store["providers"]["openai-codex"]
    _write_json(lab.root / "auth.json", store)
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    lab.run_one("root", "pool", fault=fault)
    lab.run(_EVERY_PATH)

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["root-rt-0"] and endpoint["revoked"] == []
    _, rows = _root_codex(lab)
    assert rows[0]["refresh_token"] == ("root-rt-0" if fault else "root-rt-1")
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def _exhausted_root(lab: Lab, layout: str, *, expired: bool) -> str:
    """Root's own grant, rate-limited with a day-long cooldown; returns the stored access token.

    A singleton-only root gets its row the real way: root's pool seeds it from the singleton and a
    429 persists it. The token is then optionally expired on the row and the singleton together."""
    _write_json(lab.root / "auth.json", _root_layout(layout, expired=False))
    if layout == "singleton-only":
        lab.run_one("root", "stale_mark")
    store = _read_json(lab.root / "auth.json")
    (row,) = store["credential_pool"]["openai-codex"]
    assert row["refresh_token"] == "root-rt-0"
    row.update(last_status="exhausted", last_status_at=time.time(), last_error_code=429,
               last_error_reason="usage_limit_reached", last_error_reset_at=time.time() + 86400)
    if expired:
        row["access_token"] = fake_jwt(time.time() - 60, "root")
        if "openai-codex" in store["providers"]:
            store["providers"]["openai-codex"]["tokens"]["access_token"] = row["access_token"]
    _write_json(lab.root / "auth.json", store)
    return row["access_token"]


@pytest.mark.parametrize("layout", ["mixed", "pool-only", "singleton-only"])
@pytest.mark.parametrize("case", ["valid-then-expired", "expired-ambiguous", "expired-commit"])
def test_root_owner_quota_probe_never_posts_unmarked(lab, layout, case):
    """ROOT's own quota probe decides from one expiry check whether to lock, mark and refresh.
    A token still valid at that check skips the lock and marker, so when the clock crosses its
    ``exp`` before the refresh helper re-checks, the helper must not run: an unmarked POST whose
    outcome is lost leaves root holding a spent token that a long-lived peer presents again. The
    still-valid token goes straight to the probe. An expired token still refreshes the normal way:
    root is marked before the POST and the marker survives a lost outcome, so nothing is replayed."""
    crossing = case == "valid-then-expired"
    access = _exhausted_root(lab, layout, expired=not crossing)
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    first = lab.run_one("root", "pool", fault="ambiguous" if crossing else case.split("-")[1],
                        clock_cross=crossing)

    presented = lab.endpoint()["presented"]
    assert _held_refresh_tokens(*_root_codex(lab)) == {"root-rt-0"}
    if crossing:
        assert presented == [] and not _pending_markers(lab)
        assert first["token"] == fp(access)
    else:
        assert [(p["token"], p["root_marked"]) for p in presented] == [("root-rt-0", True)]
        assert _pending_markers(lab)

    later = lab.run(_EVERY_PATH)

    endpoint = lab.endpoint()
    assert endpoint["presented"] == presented and endpoint["revoked"] == []
    if not crossing:
        assert [r["token"] for r in later] == [None] * len(later)
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def test_borrowing_profile_never_auto_adopts_the_external_codex_cli_login(lab):
    """Root's grant is dead and a valid Codex CLI login exists: a borrowing profile must not import
    it (a local shadow = a second account boundary hiding root's re-login), on any path."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _write_json(lab.home / ".codex" / "auth.json", {"tokens": _grant("cli", expired=False)})
    _borrowing_profiles(lab)
    lab.serve(valid={}, revoked=["root"])

    results = lab.run([("assistant", "singleton"), ("coach", "pool"), ("third", "singleton")])
    results += lab.run([("assistant", "singleton"), ("coach", "singleton"), ("third", "pool")])

    assert [r["token"] for r in results] == [None] * len(results)
    assert [p["token"] for p in lab.endpoint()["presented"]] == ["root-rt-0"]
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name
    singleton, rows = _root_codex(lab)
    assert not str(singleton["tokens"].get("refresh_token") or "").startswith("cli-")
    assert all(not str(r.get("refresh_token") or "").startswith("cli-") for r in rows)


def test_profile_owned_singleton_over_root_rows_is_cleared_locally_never_marks_root(lab):
    """Partial ownership A: the profile logged in locally (singleton, no rows) and reads root's rows."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    root_before = _root_codex(lab)
    own = _codex_store(_grant("own"))
    del own["credential_pool"]
    lab.profile("assistant", auth=own)
    lab.serve(valid={"root": "root-rt-0"}, revoked=["own"])

    assert lab.run_one("assistant", "pool")["token"] is None

    assert all(p["token"].startswith("own-") for p in lab.endpoint()["presented"])
    assert _root_codex(lab) == root_before  # root's row neither marked DEAD nor given own tokens
    local = _read_json(lab.home_of("assistant") / "auth.json")
    assert not local["providers"]["openai-codex"]["tokens"].get("refresh_token")
    assert local["providers"]["openai-codex"]["last_auth_error"]["relogin_required"] is True


def test_profile_owned_rows_over_root_singleton_never_write_profile_tokens_to_root(lab):
    """Partial ownership B: the profile owns an independent pool row and reads root's singleton."""
    root_store = _codex_store(_grant("root"))
    del root_store["credential_pool"]
    _write_json(lab.root / "auth.json", root_store)
    own_row = {"id": "owndc", "label": "own", "auth_type": "oauth", "priority": 0,
               "source": "manual:device_code", "base_url": CODEX_BASE_URL, **_grant("own")}
    lab.profile("assistant", auth={"version": 1, "providers": {},
                                   "credential_pool": {"openai-codex": [own_row]}})
    lab.serve(valid={"root": "root-rt-0"}, revoked=["own"])

    lab.run_one("assistant", "pool")

    endpoint = lab.endpoint()
    assert "root" not in endpoint["revoked"]
    singleton, rows = _root_codex(lab)
    assert singleton["tokens"]["refresh_token"].startswith("root-rt-") and rows == []
    assert "last_auth_error" not in singleton
    local = _read_json(lab.home_of("assistant") / "auth.json")
    assert "openai-codex" not in (local.get("providers") or {})  # no local singleton shadow
    assert [r["last_status"] for r in local["credential_pool"]["openai-codex"]] == ["dead"]


def test_root_removed_after_load_then_terminal_error_writes_no_profile_shadow(lab):
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"}, revoked=["root"])

    def drop_root_codex():
        store = _read_json(lab.root / "auth.json")
        store["providers"].pop("openai-codex")
        store["credential_pool"].pop("openai-codex")
        _write_json(lab.root / "auth.json", store)

    results = lab.run([("assistant", "pool"), ("third", "pool")], before_go=drop_root_codex)

    assert [r["token"] for r in results] == [None, None]
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name
    third = _read_json(lab.home_of("third") / "auth.json")
    assert "active_provider" not in third


def test_dead_singleton_only_root_grant_is_recorded_durably_and_never_re_presented(lab):
    root_store = _codex_store(_grant("root"))
    del root_store["credential_pool"]
    _write_json(lab.root / "auth.json", root_store)
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"}, revoked=["root"])

    lab.run([("assistant", "pool"), ("coach", "pool")])
    second = lab.run([("assistant", "pool"), ("coach", "singleton"), ("third", "pool"), ("root", "singleton")])

    assert [p["token"] for p in lab.endpoint()["presented"]] == ["root-rt-0"]
    assert [r["token"] for r in second] == [None] * 4
    singleton, _ = _root_codex(lab)
    assert not singleton["tokens"].get("refresh_token")
    assert singleton["last_auth_error"]["relogin_required"] is True
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def test_singleton_path_honours_a_dead_root_row(lab):
    """A root row already marked DEAD (the singleton still holding that token) is never presented."""
    store = _codex_store(_grant("root"), pool_row_id="rootdc")
    store["credential_pool"]["openai-codex"][0].update(
        last_status="dead", last_status_at=time.time(), last_error_reason="invalid_grant")
    _write_json(lab.root / "auth.json", store)
    _borrowing_profiles(lab)
    lab.serve(valid={}, revoked=["root"])

    results = lab.run([("assistant", "singleton"), ("coach", "singleton"), ("root", "singleton"),
                       ("third", "pool")])

    assert lab.endpoint()["presented"] == []
    assert [r["token"] for r in results] == [None] * 4


@pytest.mark.parametrize("root_pool_row", [True, False], ids=["root-pool-row", "root-singleton-only"])
def test_real_auth_add_at_root_recovers_every_path_in_every_profile(lab, root_pool_row):
    _write_json(lab.root / "auth.json", _codex_store(
        _grant("root"), pool_row_id="rootdc" if root_pool_row else None))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"}, revoked=["root"])
    lab.run([("assistant", "pool"), ("coach", "singleton")])
    dead_presented = len(lab.endpoint()["presented"])

    fresh = _grant("fresh", expired=False)
    assert lab.run_one("root", "add_entry", tokens=fresh) == {"added": True}
    after = lab.run([("assistant", "pool"), ("coach", "singleton"), ("third", "pool"),
                     ("root", "singleton"), ("root", "pool")])

    assert [r["token"] for r in after] == [fp(fresh["access_token"])] * 5
    assert len(lab.endpoint()["presented"]) == dead_presented == 1
    for name in ("assistant", "coach", "third"):
        assert not lab.profile_has_codex(name), name


def test_unopenable_root_lock_is_an_unavailable_credential_not_a_crash(lab):
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    def break_root_lock():
        lock = lab.root / "auth.lock"
        if lock.exists():
            lock.unlink()
        lock.mkdir()

    results = lab.run([("assistant", "pool"), ("coach", "pool")], before_go=break_root_lock)

    assert [r["token"] for r in results] == [None, None]
    assert lab.endpoint()["presented"] == []
    _, rows = _root_codex(lab)
    assert rows[0].get("last_status") in (None, "ok")


def _pending_markers(lab: Lab, name: str = "root") -> dict:
    store = _read_json(lab.home_of(name) / "auth.json")
    return (store.get("refresh_outcome_pending") or {}).get("openai-codex") or {}


@pytest.mark.parametrize("task", ["pool", "singleton"])
@pytest.mark.parametrize("by", ["root", "assistant"], ids=["root-owner", "borrower"])
def test_connection_never_opened_withdraws_the_marker_and_the_grant_stays_usable(lab, task, by):
    """The one failure that PROVES the token never left the host — the connection could not be
    opened — withdraws the pre-POST marker: the grant is not stranded behind a sign-in, and the
    next attempt on any path presents the still-valid token exactly once."""
    _write_json(lab.root / "auth.json", _codex_store(_grant("root"), pool_row_id="rootdc"))
    _borrowing_profiles(lab)
    lab.serve(valid={"root": "root-rt-0"})

    first = lab.run_one(by, task, fault="unsent")

    assert first["token"] is None and lab.endpoint()["presented"] == []
    assert not _pending_markers(lab)
    assert _held_refresh_tokens(*_root_codex(lab)) == {"root-rt-0"}
    later = lab.run([("coach", "singleton"), ("third", "singleton"), ("root", "singleton")])
    later += lab.run([("assistant", "pool"), ("root", "pool")])

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == ["root-rt-0"] and endpoint["revoked"] == []
    assert [r["token"] for r in later] == [fp(endpoint["issued_access"]["root"])] * len(later)
    assert _held_refresh_tokens(*_root_codex(lab)) == {"root-rt-1"}


def _manual_row_store(family: str) -> dict:
    """Pool-only layout: one ``hermes auth add`` row and no singleton to re-seed it from."""
    return {"version": 1, "providers": {}, "credential_pool": {"openai-codex": [{
        "id": f"{family}mn", "label": "manual", "auth_type": "oauth", "priority": 0,
        "source": "manual:device_code", "base_url": CODEX_BASE_URL,
        "last_refresh": "2026-09-01T00:00:00Z", **_grant(family, expired=False)}]}}


@pytest.mark.parametrize("owner,layout", [
    ("root", "mixed"), ("root", "pool-only"), ("solo", "mixed"), ("solo", "pool-only"),
    ("borrowed", "mixed"), ("borrowed", "pool-only"),
])
def test_long_lived_pool_status_write_never_rolls_back_a_peer_rotation(lab, owner, layout):
    """A long-lived pool loaded the row at T0; a peer then rotated it to T1 and cleared its marker.
    The stale pool records an inference 429 — a status-only write that persists its whole snapshot.
    T1 must stay on disk (a rolled-back T0 is a spent token the next process would present and
    revoke the family with), the live pool must adopt T1 without a reload, and a later refresh
    presents T1 once."""
    family = "solo" if owner == "solo" else "root"
    store = (_codex_store(_grant(family, expired=False), pool_row_id=f"{family}dc")
             if layout == "mixed" else _manual_row_store(family))
    if owner == "solo":
        lab.profile("solo", auth=store)
        stale, peer, later = "solo", "solo", "solo"
    else:
        _write_json(lab.root / "auth.json", store)
        _borrowing_profiles(lab)
        stale, peer, later = ("assistant", "coach", "third") if owner == "borrowed" else ("root",) * 3
    lab.serve(valid={family: f"{family}-rt-0"})
    rotated = f"{family}-rt-1"

    (stale_result,) = lab.run([(stale, "stale_mark")],
                              before_go=lambda: lab.run_one(peer, "force_refresh"))

    rows_home = lab.home_of("solo" if owner == "solo" else "root")
    rows = _read_json(rows_home / "auth.json")["credential_pool"]["openai-codex"]
    assert [r["refresh_token"] for r in rows] == [rotated]
    assert stale_result["memory_rt"] == fp(rotated)
    assert not _pending_markers(lab, "solo" if owner == "solo" else "root")

    final = lab.run_one(later, "force_refresh")

    endpoint = lab.endpoint()
    assert [p["token"] for p in endpoint["presented"]] == [f"{family}-rt-0", rotated]
    assert endpoint["revoked"] == []
    assert final["token"] == fp(endpoint["issued_access"][family])
    if owner == "borrowed":
        for name in ("assistant", "coach", "third"):
            assert not lab.profile_has_codex(name), name
