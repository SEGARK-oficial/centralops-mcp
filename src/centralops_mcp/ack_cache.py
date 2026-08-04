from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any


ACK_TTL_SECONDS = 300  # 5 minutes — must stay short

#: Hard cap on live entries. Each staged patch holds a full merged rules dict
#: (~30 KB for a 150-rule mapping), so an agent looping over patch proposals
#: without committing would otherwise grow this map without bound. Eviction is
#: oldest-expiry-first, which drops the entries closest to being useless anyway.
MAX_ENTRIES = 64


@dataclass(frozen=True)
class _Entry:
    rules_fingerprint: str
    definition_id: str
    expires_at: float
    #: Present only for patch tokens: the merged rules the agent never saw in
    #: full. Keeping it here is the whole point — ``commit_mapping_patch`` can
    #: send 193 rules to the backend while the model only ever handled the ops.
    staged_rules: Any = None
    #: Version the ops were addressed against. Carried so the commit can send it
    #: as ``base_version_id`` and let the backend reject a lost update.
    base_version_id: str | None = None


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

    def issue_patch(
        self,
        definition_id: str,
        merged_rules: Any,
        *,
        base_version_id: str | None,
        patch_digest: str,
    ) -> str:
        """Stage a merged rules dict and bind a token to the PATCH that made it.

        The binding is on ``patch_digest`` — a hash of (definition_id,
        base_version_id, ops) — rather than on the rules body, because the agent
        never handles the rules body. ``commit_mapping_patch`` re-sends the same
        ops and we recompute the digest, so a token cannot be replayed against a
        different set of ops or a different base version.
        """
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._entries[token] = _Entry(
                rules_fingerprint=patch_digest,
                definition_id=definition_id,
                expires_at=time.monotonic() + ACK_TTL_SECONDS,
                staged_rules=merged_rules,
                base_version_id=base_version_id,
            )
            self._gc_locked()
        return token

    def consume_patch(self, token: str, definition_id: str, patch_digest: str) -> _Entry:
        """Consume a patch token and hand back the staged merge.

        Same single-use/expiry/definition guarantees as :meth:`consume`; the
        difference is what is compared (the patch digest) and what comes back
        (the merged rules, so the caller can POST them without ever having
        materialised them in the conversation).
        """
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                raise AckTokenError(
                    "ack_token is unknown or already consumed. "
                    "Call patch_mapping_rules again to obtain a fresh token."
                )
            if entry.expires_at < now:
                self._entries.pop(token, None)
                raise AckTokenError(
                    "ack_token expired. Re-run patch_mapping_rules to confirm the change."
                )
            if entry.definition_id != definition_id:
                raise AckTokenError("ack_token was issued for a different definition_id.")
            if entry.staged_rules is None:
                raise AckTokenError(
                    "this ack_token came from dry_run_mapping, not patch_mapping_rules. "
                    "Use commit_mapping for that flow."
                )
            if entry.rules_fingerprint != patch_digest:
                raise AckTokenError(
                    "ops differ from the patch that produced the ack_token. "
                    "Re-run patch_mapping_rules with the exact ops you intend to commit."
                )
            self._entries.pop(token, None)
            return entry

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
            if entry.staged_rules is not None:
                raise AckTokenError(
                    "this ack_token came from patch_mapping_rules. "
                    "Use commit_mapping_patch for that flow."
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
        # Staged patches hold a full rules dict each, so expiry alone is not a
        # bound: an agent can mint faster than the TTL retires. Evict by nearest
        # expiry — those are the least useful entries remaining.
        if len(self._entries) > MAX_ENTRIES:
            by_expiry = sorted(self._entries.items(), key=lambda kv: kv[1].expires_at)
            for token, _ in by_expiry[: len(self._entries) - MAX_ENTRIES]:
                self._entries.pop(token, None)


class AckTokenError(RuntimeError):
    pass


def _fingerprint(rules: Any) -> str:
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
