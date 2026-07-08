from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from centralops_mcp.client import CentralOpsClient


ToolHandler = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


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
