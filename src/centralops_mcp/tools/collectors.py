from __future__ import annotations

from typing import Any

from centralops_mcp.tools._base import (
    CentralOpsClient,
    ToolSpec,
    _integer,
    _object,
    _string,
)


async def _list_collector_vendors(client: CentralOpsClient) -> Any:
    return await client.get("/collectors/vendors")


async def _list_collection_state(
    client: CentralOpsClient,
    *,
    integration_id: int | None = None,
) -> Any:
    return await client.get(
        "/collectors/state",
        params={"integration_id": integration_id},
    )


async def _get_collector_summary(client: CentralOpsClient) -> Any:
    return await client.get("/collectors/summary")


def specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="list_collector_vendors",
            description=(
                "List vendor/stream pairs registered in the collector registry — the "
                "static set of (platform, stream) combinations the backend knows how to "
                "poll (e.g. (sophos, alerts), (wazuh, alerts)). Use to know which "
                "streams a vendor exposes for backfill or coverage analysis."
            ),
            input_schema=_object(properties={}),
            handler=_list_collector_vendors,
        ),
        ToolSpec(
            name="list_collection_state",
            description=(
                "List per-(integration, stream) collection state: current cursor, "
                "last_success_at, last_attempt_at, last_error, consecutive_failures, "
                "events_collected_total. This answers 'is this stream up to date and "
                "what was the last error from the vendor?'."
            ),
            input_schema=_object(
                properties={
                    "integration_id": _integer(
                        "Optional — filter to a single integration.", minimum=1
                    ),
                },
            ),
            handler=_list_collection_state,
        ),
        ToolSpec(
            name="get_collector_summary",
            description=(
                "Aggregated view across all integrations the user can see — global "
                "counters, healthy/failing streams, queue depth proxies. Useful as the "
                "first read in a triage session."
            ),
            input_schema=_object(properties={}),
            handler=_get_collector_summary,
        ),
    ]
