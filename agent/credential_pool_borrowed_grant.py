"""Named profiles borrowing the root's single-use Codex grant: one owner, one lock, one write.

A profile with no Codex state of its own reads the root ``auth.json`` grant through the root
fallback. Its own ``auth.lock`` serializes only that profile's processes, so two profiles could
each read root's refresh token and both redeem it — OpenAI then revokes the whole family. Every
pool refresh of a BORROWED grant therefore also holds ROOT's lock (profile first, root second:
the order ``_provider_state_transaction`` and the forked-grant heal already use), re-reads root's
persisted row under it, and commits the rotated pair to root's row AND singleton in ONE save. A
profile that owns its grant keeps the profile-lock-only path.

A redemption whose outcome root never learned is as dangerous as a replay: the endpoint may have
rotated the token while root still holds it. So every borrowed POST is preceded by a durable
marker in root's store (``refresh_outcome_pending``, keyed by the token's hash) and cleared only
in the save that records the outcome — the rotation commit or a terminal verdict. A crash, a
network/5xx ambiguity or a failed commit leaves it, and ``refresh_codex_oauth_pure`` refuses every
token so marked, in every profile and on every path, until the owner signs in again (a new grant
no longer matches the marker). A marker that cannot be written means no POST.

Ownership is decided per TOKEN, not per profile: the grant is root's when root's store holds the
refresh token about to be spent and the profile's own singleton does not. A profile may own its
singleton while reading root's rows (a profile-local login writes no rows), or own rows while
reading root's singleton; disk shape alone misattributes both.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import hermes_cli.auth as auth_mod

logger = logging.getLogger(__name__)

CODEX_PROVIDER = "openai-codex"
REFRESH_PENDING_KEY = "refresh_outcome_pending"


class BorrowedRootUnavailable(Exception):
    """Root's lock or store cannot be taken or written: the shared grant must not be redeemed."""


def _codex_rows(store: Dict[str, Any]) -> list:
    pool = store.get("credential_pool")
    rows = pool.get(CODEX_PROVIDER) if isinstance(pool, dict) else None
    return rows if isinstance(rows, list) else []


def _singleton_tokens(store: Dict[str, Any]) -> Dict[str, Any]:
    state = auth_mod._provider_state_in(store, CODEX_PROVIDER) or {}
    tokens = state.get("tokens")
    return tokens if isinstance(tokens, dict) else {}


def _rt(value: Any) -> str:
    return str(value or "").strip()


def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _pending_markers(store: Dict[str, Any], *, create: bool = False) -> Dict[str, Any]:
    section = store.get(REFRESH_PENDING_KEY)
    if not isinstance(section, dict):
        if not create:
            return {}
        section = store[REFRESH_PENDING_KEY] = {}
    markers = section.get(CODEX_PROVIDER)
    if not isinstance(markers, dict):
        if not create:
            return {}
        markers = section[CODEX_PROVIDER] = {}
    return markers


def _clear_pending_marker(store: Dict[str, Any], token: str) -> None:
    markers = _pending_markers(store)
    markers.pop(_token_key(token), None)
    if not markers and isinstance(store.get(REFRESH_PENDING_KEY), dict):
        store[REFRESH_PENDING_KEY].pop(CODEX_PROVIDER, None)
        if not store[REFRESH_PENDING_KEY]:
            del store[REFRESH_PENDING_KEY]


def codex_refresh_outcome_uncertain(refresh_token: Optional[str]) -> bool:
    """Whether a pre-POST marker for *refresh_token* is unreconciled in this profile's store or root's.

    Reads both files from disk (no memo): this is the last check before a POST.
    """
    from agent import credential_pool as cp

    token = _rt(refresh_token)
    if not token:
        return False
    paths = [auth_mod._auth_file_path()]
    root = cp._guarded_global_root(auth_mod._global_auth_file_path())
    if root is not None:
        paths.append(root)
    key = _token_key(token)
    return any(key in _pending_markers(cp._load_auth_store(path)) for path in paths)


def mark_codex_refresh_pending(root: Path, refresh_token: str) -> None:
    """Durably record at root, BEFORE the POST, that *refresh_token* is being redeemed; raises
    ``BorrowedRootUnavailable`` when root cannot be written, and the caller must then not POST.
    Caller holds root's lock.

    Markers for tokens root no longer holds (the owner signed in again) are dropped here.
    """
    from agent import credential_pool as cp
    from hermes_constants import get_hermes_home

    try:
        store = cp._load_auth_store(root)
        held = {_token_key(t) for t in [_rt(_singleton_tokens(store).get("refresh_token"))]
                + [_rt(r.get("refresh_token")) for r in _codex_rows(store) if isinstance(r, dict)] if t}
        markers = _pending_markers(store, create=True)
        for key in [k for k in markers if k not in held]:
            del markers[key]
        markers[_token_key(_rt(refresh_token))] = {
            "at": datetime.now(timezone.utc).isoformat(), "pid": os.getpid(), "home": str(get_hermes_home())}
        auth_mod._save_auth_store(store, target_path=root)
    except Exception as exc:
        logger.warning("Codex OAuth refresh skipped: the pending-refresh marker could not be written to "
                       "the root auth store (%s); the shared token was not presented.", exc)
        raise BorrowedRootUnavailable(str(exc)) from exc


def codex_borrowed_root() -> Optional[Path]:
    """Root ``auth.json`` when the active profile may borrow root's Codex grant, else None.

    Decides only whether root's lock is taken (over-locking is harmless); which store OWNS a
    given token is ``codex_grant_owner``. None in classic mode (profile == root), under the pytest
    seat belt, and for a profile that owns both parts.
    """
    from agent import credential_pool as cp

    root = cp._guarded_global_root(auth_mod._global_auth_file_path())
    if root is None:
        return None
    store = auth_mod._load_auth_store()
    owns_singleton = auth_mod._provider_state_in(store, CODEX_PROVIDER) is not None
    owns_rows = bool(_codex_rows(store))
    if owns_singleton and owns_rows:
        return None
    root_store = auth_mod._load_global_auth_store()
    borrows_singleton = not owns_singleton and auth_mod._provider_state_in(root_store, CODEX_PROVIDER) is not None
    borrows_rows = not owns_rows and bool(_codex_rows(root_store))
    return root if borrows_singleton or borrows_rows else None


def codex_grant_owner(root: Optional[Path], refresh_token: Optional[str], entry_id: str) -> Optional[Path]:
    """*root* when root's store holds *refresh_token* (its singleton or row *entry_id*) and the
    profile's own singleton does not; None = the profile owns the token (or root never had it)."""
    from agent import credential_pool as cp

    token = _rt(refresh_token)
    if root is None or not token:
        return None
    if _rt(_singleton_tokens(auth_mod._load_auth_store()).get("refresh_token")) == token:
        return None
    root_store = cp._load_auth_store(root)
    if _rt(_singleton_tokens(root_store).get("refresh_token")) == token:
        return root
    for row in _codex_rows(root_store):
        if isinstance(row, dict) and row.get("id") == entry_id and _rt(row.get("refresh_token")) == token:
            return root
    return None


def codex_token_store(root: Optional[Path], refresh_token: Optional[str], entry_id: str) -> Optional[Path]:
    """The store that OWNS *refresh_token*: root when borrowed (``codex_grant_owner``), else this
    profile's own ``auth.json`` when it holds the token (singleton or row *entry_id*) — in classic
    mode that IS the root owner. None: no Hermes store holds it (never marked or committed)."""
    owner = codex_grant_owner(root, refresh_token, entry_id)
    if owner is not None:
        return owner
    token, store = _rt(refresh_token), auth_mod._load_auth_store()
    if token and (_rt(_singleton_tokens(store).get("refresh_token")) == token or any(
            isinstance(r, dict) and r.get("id") == entry_id and _rt(r.get("refresh_token")) == token
            for r in _codex_rows(store))):
        return auth_mod._auth_file_path()
    return None


def codex_own_row_moved_on(entry_id: str, refresh_token: Optional[str]) -> bool:
    """This profile's persisted row *entry_id* now holds a different token: a peer process rotated
    (or re-logged) it after this pool loaded. The in-memory token is spent — never POST it."""
    token = _rt(refresh_token)
    return any(isinstance(r, dict) and r.get("id") == entry_id and _rt(r.get("refresh_token")) != token
               for r in _codex_rows(auth_mod._load_auth_store()))


def clear_codex_refresh_pending(store_path: Path, refresh_token: str) -> None:
    """Drop *refresh_token*'s marker after the endpoint gave a DEFINITIVE answer that recorded no
    rotation (a terminal rejection handled by the classic path). Caller holds the store's lock."""
    from agent import credential_pool as cp

    store = cp._load_auth_store(store_path)
    if _token_key(_rt(refresh_token)) in _pending_markers(store):
        _clear_pending_marker(store, _rt(refresh_token))
        auth_mod._save_auth_store(store, target_path=store_path)


def codex_grant_uncertain(store_path: Path) -> bool:
    """Whether the Codex grant in *store_path* has an unreconciled redemption: a live (non-DEAD) row
    or the singleton still holds a marked token, or the singleton's standing verdict is "outcome
    unknown" (no refresh token since). External-login recovery must not paper over it."""
    from agent import credential_pool as cp
    from hermes_cli.auth_constants import CODEX_REFRESH_OUTCOME_UNCERTAIN

    store = cp._load_auth_store(store_path)
    markers = _pending_markers(store)
    singleton_rt = _rt(_singleton_tokens(store).get("refresh_token"))
    live = [singleton_rt] + [_rt(r.get("refresh_token")) for r in _codex_rows(store)
                             if isinstance(r, dict) and r.get("last_status") != cp.STATUS_DEAD]
    if any(t and _token_key(t) in markers for t in live):
        return True
    error = (auth_mod._provider_state_in(store, CODEX_PROVIDER) or {}).get("last_auth_error")
    return (not singleton_rt and isinstance(error, dict)
            and error.get("code") == CODEX_REFRESH_OUTCOME_UNCERTAIN)


def commit_borrowed_codex_rotation(
    root: Path, entry_id: Optional[str], spent_refresh: str, *, access_token: str, refresh_token: str,
    last_refresh: Optional[str], clear_status: bool,
) -> None:
    """Write the rotated pair to root's row *entry_id* (None: every row) and singleton, and clear
    the pending marker, in ONE save; raises on failure (the marker then stays: STOP).

    Compare-and-set: only a store part still holding *spent_refresh* is rewritten, so a profile's
    own tokens can never land in root. ``clear_status=False`` keeps a row's quota cooldown. Caller
    holds root's lock.
    """
    from agent import credential_pool as cp
    from hermes_cli.auth_codex import _clear_pool_entry_status

    spent = _rt(spent_refresh)
    store = cp._load_auth_store(root)
    for row in _codex_rows(store):
        if (isinstance(row, dict) and entry_id in (None, row.get("id"))
                and _rt(row.get("refresh_token")) == spent):
            row.update(access_token=access_token, refresh_token=refresh_token)
            if last_refresh:
                row["last_refresh"] = last_refresh
            if clear_status:
                _clear_pool_entry_status(row)
                row["last_status"] = cp.STATUS_OK
    state = auth_mod._provider_state_in(store, CODEX_PROVIDER)
    tokens = (state or {}).get("tokens")
    if isinstance(tokens, dict) and _rt(tokens.get("refresh_token")) == spent:
        state["tokens"] = {**tokens, "access_token": access_token, "refresh_token": refresh_token}
        if last_refresh:
            state["last_refresh"] = last_refresh
        state.pop("last_auth_error", None)
        auth_mod._store_provider_state(store, CODEX_PROVIDER, state, set_active=False)
    _clear_pending_marker(store, spent)
    auth_mod._save_auth_store(store, target_path=root)


def codex_token_is_held(root: Path, refresh_token: Optional[str], entry_id: str) -> bool:
    """Whether the profile's own store or root's still holds *refresh_token* (singleton or row
    *entry_id*). A token no store holds was spent or retired by a peer: never POST it."""
    from agent import credential_pool as cp

    token = _rt(refresh_token)
    for store in (auth_mod._load_auth_store(), cp._load_auth_store(root)):
        if _rt(_singleton_tokens(store).get("refresh_token")) == token:
            return True
        if any(isinstance(r, dict) and r.get("id") == entry_id and _rt(r.get("refresh_token")) == token
               for r in _codex_rows(store)):
            return True
    return False


def record_codex_terminal_verdict(
    root: Path, entry_id: Optional[str], dead_refresh: str, exc: Exception, *, keep_marker: bool = False,
) -> bool:
    """Durably record a dead grant on root: row(s) holding it -> DEAD, singleton tokens cleared with
    ``last_auth_error`` — each only while it still holds *dead_refresh* (a peer's re-login wins).
    Every path in every profile then stops presenting it. Returns whether root changed.

    ``keep_marker``: the verdict is "outcome unknown", not an endpoint answer — the pending marker
    stays so no copy of the token anywhere is ever presented again."""
    from agent import credential_pool as cp

    dead = _rt(dead_refresh)
    code = str(getattr(exc, "code", None) or "invalid_grant")
    changed = False
    with cp._auth_store_lock(target_path=root):
        store = cp._load_auth_store(root)
        for row in _codex_rows(store):
            if (isinstance(row, dict) and entry_id in (None, row.get("id"))
                    and _rt(row.get("refresh_token")) == dead):
                row.update(last_status=cp.STATUS_DEAD, last_status_at=time.time(), last_error_code=None,
                           last_error_reason=code, last_error_message=str(exc))
                changed = True
        state = auth_mod._provider_state_in(store, CODEX_PROVIDER)
        tokens = (state or {}).get("tokens")
        if isinstance(tokens, dict) and _rt(tokens.get("refresh_token")) == dead:
            state["tokens"] = {k: v for k, v in tokens.items() if k not in ("access_token", "refresh_token")}
            state["last_auth_error"] = {
                "provider": CODEX_PROVIDER, "code": code, "message": str(exc),
                "reason": "credential_pool_refresh_failure", "relogin_required": True,
                "at": datetime.now(timezone.utc).isoformat(),
            }
            auth_mod._store_provider_state(store, CODEX_PROVIDER, state, set_active=False)
            changed = True
        if not keep_marker and _token_key(dead) in _pending_markers(store):
            _clear_pending_marker(store, dead)
            changed = True
        if changed:
            auth_mod._save_auth_store(store, target_path=root)
    return changed


class CredentialPoolBorrowedGrantMixin:
    """Owner-aware locking and re-reads for ``CredentialPool`` refreshes of a borrowed Codex grant."""

    @contextmanager
    def _single_use_refresh_lock(self, *, local_lock: bool = True) -> Iterator[Optional[Path]]:
        """Profile auth lock, plus ROOT's lock when this Codex grant may be borrowed; yields that root.

        ``local_lock=False`` keeps a locally owned grant on its historical unlocked path (the
        quota probe) and only serializes borrowed grants. Root's lock failing to open or time out
        raises ``BorrowedRootUnavailable`` — before any token is spent.
        """
        from agent import credential_pool as cp

        timeout = self._single_use_refresh_lock_timeout()
        if not local_lock and (self.provider != CODEX_PROVIDER or codex_borrowed_root() is None):
            yield None
            return
        with cp._auth_store_lock(timeout_seconds=timeout):
            root = codex_borrowed_root() if self.provider == CODEX_PROVIDER else None
            if root is None:
                yield None
                return
            with ExitStack() as stack:
                try:
                    stack.enter_context(cp._auth_store_lock(timeout_seconds=timeout, target_path=root))
                except OSError as exc:  # PermissionError, TimeoutError (lock contention), ...
                    raise BorrowedRootUnavailable(str(exc)) from exc
                yield root

    def _sync_borrowed_codex_row(self, entry, root: Path):
        """Adopt root's persisted row for *entry* (caller holds root's lock).

        Read straight from root's file, not the mtime memo: this is the authoritative
        compare-before-POST. Root's row carries the peer's rotation AND its DEAD verdict; the
        caller must not redeem a token whose owner row is DEAD.
        """
        from agent import credential_pool as cp

        row = next(
            (r for r in _codex_rows(cp._load_auth_store(root)) if isinstance(r, dict) and r.get("id") == entry.id),
            None,
        )
        if row is None:
            return entry
        stored = cp.PooledCredential.from_dict(self.provider, row)
        if not (stored.refresh_token or "").strip():
            return entry
        if (stored.access_token, stored.refresh_token, stored.last_status) == (
            entry.access_token, entry.refresh_token, entry.last_status,
        ):
            return entry
        self._replace_entry(entry, stored)
        return stored

    def _commit_borrowed_rotation_or_fail(self, owner: Path, spent, updated) -> bool:
        """Commit a POSTed rotation to root; on failure the pending marker stays and say so LOUDLY."""
        from agent import credential_pool as cp

        try:
            commit_borrowed_codex_rotation(
                owner, spent.id, spent.refresh_token, access_token=updated.access_token,
                refresh_token=updated.refresh_token, last_refresh=updated.last_refresh,
                clear_status=updated.last_status in (None, cp.STATUS_OK))
            return True
        except Exception as exc:
            log_codex_rotation_unrecorded(exc)
            return False


def log_codex_rotation_unrecorded(exc: Exception) -> None:
    logger.error(
        "Codex OAuth: the grant was rotated but the new token could not be written to its owning "
        "auth store (%s). Its pending-refresh marker stays, so no profile will present the spent "
        "token; sign in again at the root profile with 'hermes auth add openai-codex'.", exc)


def log_codex_refresh_outcome_uncertain() -> None:
    logger.warning(
        "Codex OAuth refresh refused: an earlier redemption of this refresh token never recorded "
        "its outcome (crash, network ambiguity or failed save), so presenting it again could "
        "revoke the whole token family. Sign in again at the root profile with "
        "'hermes auth add openai-codex'.")
