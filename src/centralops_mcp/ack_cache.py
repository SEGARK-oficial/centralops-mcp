from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any


ACK_TTL_SECONDS = 300  # 5 minutes — must stay short


@dataclass(frozen=True)
class _Entry:
    rules_fingerprint: str
    definition_id: str
    expires_at: float


class AckCache:
    """In-memory cache binding `dry_run_mapping` results to `commit_mapping`.

    The CentralOps backend re-runs validation on commit, so this cache is not a
    security boundary — it is a UX guard that prevents the LLM from calling
    `commit_mapping` on rules it never dry-ran. Tokens expire fast (5min) and
    are scoped to (definition_id, rules-fingerprint).
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: dict[str, _Entry] = {}

    def issue(self, definition_id: str, rules: Any) -> str:
        fingerprint = _fingerprint(rules)
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._entries[token] = _Entry(
                rules_fingerprint=fingerprint,
                definition_id=definition_id,
                expires_at=time.monotonic() + ACK_TTL_SECONDS,
            )
            self._gc_locked()
        return token

    def consume(self, token: str, definition_id: str, rules: Any) -> None:
        fingerprint = _fingerprint(rules)
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                raise AckTokenError(
                    "ack_token is unknown or already consumed. "
                    "Call dry_run_mapping again to obtain a fresh token."
                )
            if entry.expires_at < now:
                self._entries.pop(token, None)
                raise AckTokenError(
                    "ack_token expired. Re-run dry_run_mapping to confirm the rules."
                )
            if entry.definition_id != definition_id:
                raise AckTokenError(
                    "ack_token was issued for a different definition_id."
                )
            if entry.rules_fingerprint != fingerprint:
                raise AckTokenError(
                    "rules differ from the dry-run that produced the ack_token. "
                    "Re-run dry_run_mapping with the exact rules you intend to commit."
                )
            self._entries.pop(token, None)

    def _gc_locked(self) -> None:
        now = time.monotonic()
        stale = [token for token, entry in self._entries.items() if entry.expires_at < now]
        for token in stale:
            self._entries.pop(token, None)


class AckTokenError(RuntimeError):
    pass


def _fingerprint(rules: Any) -> str:
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
