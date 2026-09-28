"""Named profiles borrowing the root's single-use Codex grant: one owner, one lock, one write.

A profile with no Codex state of its own reads the root ``auth.json`` grant through the root
fallback. Its own ``auth.lock`` serializes only that profile's processes, so two profiles could
each read root's refresh token and both redeem it — OpenAI then revokes the whole family. Every
pool refresh of a BORROWED grant therefore also holds ROOT's lock (profile first, root second:
the order ``_provider_state_transaction`` and the forked-grant heal already use), re-reads root's
persisted row under it, and writes the rotated pair back to root only. A profile that owns its
grant keeps the profile-lock-only path.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import hermes_cli.auth as auth_mod

CODEX_PROVIDER = "openai-codex"


def _codex_rows(store: Dict[str, Any]) -> list:
    pool = store.get("credential_pool")
    rows = pool.get(CODEX_PROVIDER) if isinstance(pool, dict) else None
    return rows if isinstance(rows, list) else []


def codex_borrowed_root() -> Optional[Path]:
    """Root ``auth.json`` when the active profile borrows root's Codex grant, else None.

    Borrowing = the profile lacks its own ``providers.openai-codex`` block or its own pool rows
    while root has that part. None in classic mode (profile == root), under the pytest seat belt,
    and for a profile that owns both parts.
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


class CredentialPoolBorrowedGrantMixin:
    """Owner-aware locking and re-reads for ``CredentialPool`` refreshes of a borrowed Codex grant."""

    @contextmanager
    def _single_use_refresh_lock(self, *, local_lock: bool = True) -> Iterator[Optional[Path]]:
        """Profile auth lock, plus ROOT's lock when this Codex grant is borrowed; yields that root.

        ``local_lock=False`` keeps a locally owned grant on its historical unlocked path (the
        quota probe) and only serializes borrowed grants.
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
            with cp._auth_store_lock(timeout_seconds=timeout, target_path=root):
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
