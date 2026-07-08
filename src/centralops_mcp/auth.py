"""MCP authentication settings — Bearer / PAT only.

The MCP authenticates against CentralOps using a Personal Access Token
(or Service Account token) issued at ``/settings/tokens`` in the UI.
Cookie-based session auth was removed in Fase 2 — every operator runs
with a named, revocable, scope-aware credential instead of replaying a
short-lived browser session.

Configuration:

  CENTRALOPS_BASE_URL    e.g. ``https://centralops.internal/api`` (no trailing slash needed)
  CENTRALOPS_API_TOKEN   PAT or SA token starting with ``copsk_`` (required)
  CENTRALOPS_TIMEOUT_S   request timeout in seconds (default 30)
  CENTRALOPS_VERIFY_TLS  set ``0`` / ``false`` to disable cert verification (dev only)

Generate the token at the CentralOps UI:
  /settings/tokens → "Criar token" → copy the ``copsk_…`` value once.

Lost the token? Revoke + create a new one. There is no recovery flow.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


SERVER_VERSION = "0.2.0"
DEFAULT_BASE_URL = "http://localhost:3000/api"
TOKEN_PREFIX = "copsk_"


class ConfigError(RuntimeError):
    """Raised when the MCP cannot authenticate against CentralOps."""


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_token: str
    request_timeout_s: float
    verify_tls: bool

    @property
    def authorization_header(self) -> str:
        return f"Bearer {self.api_token}"

    @property
    def client_header(self) -> str:
        return f"centralops-mcp/{SERVER_VERSION}"


def load_settings() -> Settings:
    base_url = os.environ.get("CENTRALOPS_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    api_token = os.environ.get("CENTRALOPS_API_TOKEN", "").strip()
    if not api_token:
        raise ConfigError(
            "CENTRALOPS_API_TOKEN is required. Generate one at "
            "<base_url>/settings/tokens (replace <base_url> with your "
            "CentralOps host) and export it as an env var. The token must "
            f"start with '{TOKEN_PREFIX}'."
        )
    if not api_token.startswith(TOKEN_PREFIX):
        # Soft check — the backend rejects non-``copsk_`` tokens, but flagging
        # early avoids confusing 401s when the user pasted, say, a session id.
        raise ConfigError(
            f"CENTRALOPS_API_TOKEN must start with '{TOKEN_PREFIX}'. "
            f"Got prefix '{api_token[:8]}...'. The token in /settings/tokens "
            "is the only accepted credential."
        )

    timeout_s = float(os.environ.get("CENTRALOPS_TIMEOUT_S", "30"))
    verify_tls = os.environ.get("CENTRALOPS_VERIFY_TLS", "1") not in {"0", "false", "False"}

    return Settings(
        base_url=base_url,
        api_token=api_token,
        request_timeout_s=timeout_s,
        verify_tls=verify_tls,
    )
