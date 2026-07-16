from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from centralops_mcp import __version__
from centralops_mcp.ack_cache import AckCache, AckTokenError
from centralops_mcp.auth import ConfigError, Settings, load_settings
from centralops_mcp.client import CentralOpsAPIError, CentralOpsClient
from centralops_mcp.tools._base import ToolSpec
from centralops_mcp.tools import backfill as backfill_tools
from centralops_mcp.tools import collectors as collectors_tools
from centralops_mcp.tools import dashboard as dashboard_tools
from centralops_mcp.tools import destinations as destinations_tools
from centralops_mcp.tools import detections as detections_tools
from centralops_mcp.tools import drift as drift_tools
from centralops_mcp.tools import integrations as integrations_tools
from centralops_mcp.tools import mapping as mapping_tools
from centralops_mcp.tools import pipeline_health as pipeline_health_tools
from centralops_mcp.tools import quarantine as quarantine_tools
from centralops_mcp.tools import queries as queries_tools
from centralops_mcp.tools import routes as routes_tools
from centralops_mcp.tools import sophos_licenses as sophos_licenses_tools


SERVER_NAME = "centralops-mcp"


def _build_specs(ack_cache: AckCache) -> dict[str, ToolSpec]:
    specs: list[ToolSpec] = [
        *integrations_tools.specs(),
        *collectors_tools.specs(),
        *drift_tools.specs(),
        *quarantine_tools.specs(),
        *mapping_tools.specs(ack_cache),
        *backfill_tools.specs(),
        *sophos_licenses_tools.specs(),
        *pipeline_health_tools.specs(),
        *destinations_tools.specs(),
        *routes_tools.specs(),
        *detections_tools.specs(),
        *dashboard_tools.specs(),
        *queries_tools.specs(),
    ]
    by_name: dict[str, ToolSpec] = {}
    for spec in specs:
        if spec.name in by_name:
            raise RuntimeError(f"Duplicate MCP tool name: {spec.name}")
        by_name[spec.name] = spec
    return by_name


def _to_text(payload: Any) -> list[TextContent]:
    if isinstance(payload, (dict, list)) or payload is None:
        text = json.dumps(payload, indent=2, default=str, ensure_ascii=False)
    else:
        text = str(payload)
    return [TextContent(type="text", text=text)]


def _error_text(message: str, **fields: Any) -> list[TextContent]:
    payload = {"error": message, **fields}
    return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]


def _build_app(settings: Settings, specs: dict[str, ToolSpec]) -> Server:
    app: Server = Server(SERVER_NAME, version=__version__)

    @app.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name=spec.name, description=spec.description, inputSchema=spec.input_schema)
            for spec in specs.values()
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        spec = specs.get(name)
        if spec is None:
            return _error_text(f"Unknown tool: {name}")

        kwargs = dict(arguments or {})
        try:
            async with CentralOpsClient(settings) as client:
                result = await spec.handler(client, **kwargs)
        except AckTokenError as exc:
            return _error_text(str(exc), error_kind="ack_token_invalid")
        except CentralOpsAPIError as exc:
            return _error_text(
                str(exc),
                error_kind="upstream_http_error",
                http_status=exc.status_code,
                upstream_body=exc.body,
            )
        except ValueError as exc:
            return _error_text(str(exc), error_kind="invalid_argument")
        except TypeError as exc:
            return _error_text(
                f"Invalid arguments for tool '{name}': {exc}",
                error_kind="invalid_argument",
            )
        return _to_text(result)

    return app


async def _serve() -> None:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"[centralops-mcp] config error: {exc}", file=sys.stderr)
        raise SystemExit(2)

    ack_cache = AckCache()
    specs = _build_specs(ack_cache)
    app = _build_app(settings, specs)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main() -> None:
    log_level = os.environ.get("CENTRALOPS_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("centralops-mcp").info(
        "starting centralops-mcp v%s", __version__
    )
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
