from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from centralops_mcp.client import CentralOpsClient


ToolHandler = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class ToolSpec:
    """One MCP tool: name, description, JSON Schema and async handler.

    The three capability flags below are surfaced to the client as
    ``ToolAnnotations`` so an agent can tell — *before* calling — whether a tool
    only reads or can change the platform. Defaults are the safe reading: a tool
    is read-only and idempotent unless it explicitly says otherwise, so a new
    tool that forgets to declare itself is never advertised as safe-to-retry
    when it writes.

    - ``read_only``: the call cannot change server-side state. ``dry_run_mapping``
      is read-only despite being an HTTP POST — it persists nothing.
    - ``destructive``: the call changes state in a way that is not trivially
      undone (promotes a mapping version, enqueues a backfill, cancels a job).
      Only meaningful when ``read_only`` is False.
    - ``idempotent``: calling twice with the same arguments has the same effect
      as calling once. ``commit_mapping`` is NOT idempotent — it creates a new
      version each time.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True


def _string(description: str, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "description": description, **extra}


def _integer(description: str, **extra: Any) -> dict[str, Any]:
    return {"type": "integer", "description": description, **extra}


def _object(properties: dict[str, Any], required: list[str] | None = None,
            additional: bool = False) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": additional,
    }
    if required:
        schema["required"] = required
    return schema


__all__ = ["ToolSpec", "ToolHandler", "CentralOpsClient", "_string", "_integer", "_object"]
