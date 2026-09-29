"""Subprocess worker for ``test_codex_root_grant_borrowing.py`` (not a test module).

One process = one Hermes interpreter bound to one disposable profile home. It refuses to run
unless the engine resolves its global root inside the disposable ``HOME``, replaces the Codex
token endpoint with a fake that records every presented refresh token in a flock-guarded JSON
file, and blocks every real socket connect. Output is one JSON line of fingerprints/codes only.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path


def fake_jwt(exp: float, account: str = "acct-synthetic") -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    claims = {"exp": int(exp), "sub": f"user-{account}",
              "https://api.openai.com/auth": {"chatgpt_account_id": account}}
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


def fp(value) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest()[:12] if value else None


def _no_network(*_args, **_kwargs):
    raise OSError("network disabled in codex_root_grant_worker")


class _Response:
    def __init__(self, status: int, payload: dict):
        self.status_code, self._payload, self.headers, self.text = status, payload, {}, ""

    def json(self):
        return self._payload


class _FakeTokenEndpoint:
    """Rotating single-use refresh tokens with family revocation on reuse."""

    def __init__(self, server: Path, label: str):
        self.server, self.label = server, label

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None):
        """Usage probe: the quota window has reopened."""
        return _Response(200, {"rate_limit": {"primary_window": {"used_percent": 10}}})

    def post(self, url, headers=None, data=None):
        presented = (data or {}).get("refresh_token") or ""
        time.sleep(0.3)  # network latency keeps the read -> POST -> write window open
        with open(self.server, "r+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            state = json.load(handle)
            family = presented.split("-rt-")[0]
            state["presented"].append({"by": self.label, "token": presented})
            current = state["valid"].get(family)
            if family in state["revoked"] or presented != current:
                if family not in state["revoked"]:
                    state["revoked"].append(family)  # rotation-family reuse detection
                response = _Response(401, {"error": "invalid_grant",
                                           "error_description": "refresh token revoked"})
            else:
                seq = int(current.rsplit("-", 1)[1]) + 1
                state["valid"][family] = f"{family}-rt-{seq}"
                state["issued_access"][family] = fake_jwt(time.time() + 3600, family)
                response = _Response(200, {"access_token": state["issued_access"][family],
                                           "refresh_token": state["valid"][family]})
            handle.seek(0)
            handle.truncate()
            json.dump(state, handle)
        return response


def _guard(spec: dict) -> None:
    import pwd

    from hermes_constants import get_default_hermes_root, get_hermes_home

    account_root = (Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes").resolve()
    root = get_default_hermes_root().resolve()
    if (root != Path(spec["expected_root"]).resolve() or root == account_root
            or get_hermes_home().resolve() != Path(spec["hermes_home"]).resolve()
            or os.environ.get("PYTEST_CURRENT_TEST")):
        sys.stdout.write(json.dumps({"worker": {"guard": "root_not_disposable"}}) + "\n")
        sys.stdout.flush()
        os._exit(3)


def _await_go(spec: dict) -> None:
    Path(spec["ready"]).write_text("ready")
    go = Path(spec["go"])
    deadline = time.monotonic() + 60
    while not go.exists():
        if time.monotonic() > deadline:
            raise SystemExit("go_timeout")
        time.sleep(0.005)


CRASH_EXIT = 9


def _inject_fault(spec: dict) -> None:
    """``fault`` (applied after the pool loads, before the refresh phase):

    * ``marker`` — every root save fails, so the pre-POST pending marker cannot be written;
    * ``commit`` — the first root save (the marker) succeeds, every later one fails;
    * ``crash`` — the process dies (``os._exit``) right after the endpoint answered the POST;
    * ``ambiguous`` — the endpoint rotates, then the client sees a network error.

    Profile saves are untouched."""
    import hermes_cli.auth as auth_mod

    fault = spec.get("fault")
    if fault in ("marker", "commit"):
        real_save = auth_mod._save_auth_store
        root_auth = (Path(spec["expected_root"]) / "auth.json").resolve()
        seen = {"root_saves": 0}

        def faulty_save(auth_store, target_path=None):
            target = Path(target_path if target_path is not None else auth_mod._auth_file_path()).resolve()
            if target == root_auth:
                seen["root_saves"] += 1
                if fault == "marker" or seen["root_saves"] > 1:
                    raise OSError("injected root auth.json write failure")
            return real_save(auth_store, target_path=target_path)

        auth_mod._save_auth_store = faulty_save
    elif fault in ("crash", "ambiguous"):
        real_post = _FakeTokenEndpoint.post

        def post_then_fail(self, url, headers=None, data=None):
            real_post(self, url, headers=headers, data=data)
            if fault == "crash":
                os._exit(CRASH_EXIT)
            raise OSError("injected connection reset after the request was sent")

        _FakeTokenEndpoint.post = post_then_fail


def _pool(spec: dict) -> dict:
    from agent.credential_pool import load_pool

    pool = load_pool("openai-codex")
    _inject_fault(spec)
    _await_go(spec)
    entry = pool.select()
    return {"token": fp(entry.access_token) if entry else None, "entries": len(pool.entries())}


def _singleton(spec: dict) -> dict:
    from hermes_cli.auth import AuthError, resolve_codex_runtime_credentials

    _inject_fault(spec)
    _await_go(spec)
    try:
        creds = resolve_codex_runtime_credentials()
    except AuthError as exc:
        return {"token": None, "error": exc.code}
    except OSError as exc:  # the ``ambiguous`` fault: a network error, not an auth verdict
        return {"token": None, "error": type(exc).__name__}
    return {"token": fp(creds.get("api_key")), "source": creds.get("source")}


def _relogin(spec: dict) -> dict:
    """The OWNER (root) signs in again through the singleton login (``hermes model`` persists this)."""
    from hermes_cli.auth import _save_codex_tokens

    _save_codex_tokens(spec["tokens"])
    return {"relogin": True}


def _add_entry(spec: dict) -> dict:
    """The REAL ``hermes auth add openai-codex`` command; only the OAuth browser/device step is
    replaced by synthetic tokens (no OAuth, no network)."""
    import argparse

    import hermes_cli.auth_codex_browser as browser
    from hermes_cli.auth_commands import auth_add_command

    browser.codex_oauth_login = lambda _args: {
        "tokens": dict(spec["tokens"]), "base_url": "https://chatgpt.com/backend-api/codex",
        "last_refresh": "2026-09-28T00:00:00Z", "source": "device_code"}
    auth_add_command(argparse.Namespace(provider="openai-codex", auth_type="", label="relogin",
                                        priority=None))
    return {"added": True}


def _inspect(spec: dict) -> dict:
    from hermes_cli.auth import _load_auth_store, _load_provider_state_with_source, read_credential_pool

    root_auth = (Path(spec["expected_root"]) / "auth.json").resolve()
    state, source = _load_provider_state_with_source(_load_auth_store(), "openai-codex")
    return {
        "singleton_source": None if source is None else
        ("root" if Path(source).resolve() == root_auth else "profile"),
        "singleton_has_refresh": bool(((state or {}).get("tokens") or {}).get("refresh_token")),
        "pool_rows_visible": len(read_credential_pool("openai-codex")),
    }


_TASKS = {"pool": _pool, "singleton": _singleton, "relogin": _relogin, "add_entry": _add_entry,
          "inspect": _inspect}


def main() -> None:
    sys.dont_write_bytecode = True
    spec = json.loads(sys.argv[1])
    sys.path.insert(0, spec["repo"])
    socket.socket.connect = _no_network  # type: ignore[method-assign]
    socket.create_connection = _no_network  # type: ignore[assignment]
    _guard(spec)
    import hermes_cli.auth_codex as auth_codex

    label = spec.get("label", "")
    auth_codex._codex_http_client = lambda **_kw: _FakeTokenEndpoint(Path(spec["server"]), label)
    result = _TASKS[spec["task"]](spec)
    sys.stdout.write(json.dumps({"worker": result}, sort_keys=True) + "\n")
    sys.stdout.flush()
    os._exit(0)  # engine background threads must not keep the worker alive


if __name__ == "__main__":
    main()
