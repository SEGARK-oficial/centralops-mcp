from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

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

#: Sent to the client on initialize. This is the ONLY place an agent learns the
#: shape of the platform before it starts calling tools, so it carries the
#: cross-cutting rules that no single tool description can own: scope semantics,
#: which tools write, and the two silent-degradation traps (empty reservoir,
#: dry-run that does not measure OCSF conformance).
SERVER_INSTRUCTIONS = """\
CentralOps is a security data pipeline: collectors pull events from vendors
(Sophos, Wazuh, CrowdStrike, Defender, Okta, Entra ID, FortiGate, Veeam, ...),
a declarative mapping engine normalizes them to OCSF 1.8, and routes dispatch
them to destinations (syslog, Splunk, Elastic, ClickHouse, Security Lake, ...).

## Orientation: which tool answers which question

- "What is connected / is it healthy?" -> list_integrations, get_integration_health,
  get_pipeline_health, list_collection_state.
- "What does this vendor actually send?" -> get_mapping_samples (raw vendor JSON,
  pre-normalization). This is the ground truth for authoring rules.
- "What fields are we ignoring?" -> list_drift_fields, discover_mapping_fields.
- "How is this vendor normalized?" -> list_mappings, then get_mapping.
- "Did normalization fail?" -> list_quarantine, get_quarantine_event.
- "Where did this event go?" -> get_event_lineage, list_destination_lineage.
- "Is data being dropped or delayed?" -> get_route_health, list_destination_dlq,
  list_collection_state (collection lag).

## Scope: read this before trusting an empty result

Every call is scoped by the token. An ORG-SCOPED token sees only its tenant.
A GLOBAL-SCOPED token sees the control plane but, for tenant-owned data, is
FAIL-CLOSED: it returns an EMPTY result rather than aggregating across tenants.

This matters most for the sample reservoir. get_mapping_samples and
dry_run_mapping with a global token and no `organization_id` return
`sample_size: 0` and NOT an error. Empty here means "you did not name a tenant",
not "there is no data". Pass `organization_id` whenever a reservoir-backed call
comes back empty.

## Writes: 4 of these tools change state, the rest only read

Read-only (safe to explore freely): everything not listed below, including
dry_run_mapping — it is an HTTP POST but persists nothing.

State-changing, and each needs explicit human intent before you call it:
- commit_mapping — promotes a new mapping version; live collectors pick it up in
  ~30s. NOT idempotent: each call creates another version. Requires an ack_token
  minted by dry_run_mapping for the same definition_id AND the same rules.
- request_backfill — enqueues a re-collection job; costs vendor API quota.
- cancel_backfill_job — stops a running job.
- reprocess_quarantine — re-injects a quarantined event into the pipeline.

Never call these to "verify" or "test" something. To test a mapping, use
dry_run_mapping.

## Two traps that produce confident wrong answers

1. dry_run_mapping reports whether RULES EXECUTED, not whether the output is
   valid OCSF. It does not return ocsf_validation_stats or mapped_field_ratio.
   "10/10 passed" means no rule crashed. It does NOT mean the events conform to
   OCSF 1.8. Do not report OCSF conformance based on a dry-run.
2. Mapping definitions seeded from repository defaults diverge from the files on
   disk as soon as anyone edits them in the UI. get_mapping is the only source of
   truth for what production actually applies. Never infer live behavior from the
   JSON files in the repo.

## Editing a mapping: the required sequence

list_mappings -> get_mapping (current rules) -> get_mapping_samples (real events)
-> dry_run_mapping (with organization_id, to get a non-empty reservoir) -> read
the output -> commit_mapping with the ack_token and the SAME rules you dry-ran.
The ack_token expires in 5 minutes and is single-use.
"""


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
    app: Server = Server(
        SERVER_NAME, version=__version__, instructions=SERVER_INSTRUCTIONS
    )

    @app.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema,
                annotations=ToolAnnotations(
                    readOnlyHint=spec.read_only,
                    # Only meaningful when the tool writes; the MCP default for
                    # a non-read-only tool is destructive=True, so state it
                    # explicitly rather than relying on the client's default.
                    destructiveHint=spec.destructive,
                    idempotentHint=spec.idempotent,
                ),
            )
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
