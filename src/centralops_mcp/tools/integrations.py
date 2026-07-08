from __future__ import annotations

from typing import Any

from centralops_mcp.tools._base import (
    CentralOpsClient,
    ToolSpec,
    _integer,
    _object,
    _string,
)


async def _list_integrations(client: CentralOpsClient) -> Any:
    return await client.get("/integrations/")


async def _get_integration(client: CentralOpsClient, *, integration_id: int) -> Any:
    return await client.get(f"/integrations/{integration_id}")


async def _get_integration_health(
    client: CentralOpsClient, *, integration_id: int
) -> Any:
    return await client.get(f"/integrations/{integration_id}/health")


async def _get_integration_overview(
    client: CentralOpsClient, *, integration_id: int
) -> Any:
    return await client.get(f"/integrations/{integration_id}/overview")


async def _list_integration_alerts(
    client: CentralOpsClient,
    *,
    integration_id: int,
    limit: int = 25,
    offset: int = 0,
) -> Any:
    return await client.get(
        f"/integrations/{integration_id}/alerts",
        params={"limit": limit, "offset": offset},
    )


async def _list_supported_platforms(client: CentralOpsClient) -> Any:
    return await client.get("/integrations/platforms")


def specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="list_integrations",
            description=(
                "List CentralOps integrations (a vendor connection per row). Each item "
                "has platform (sophos|wazuh|microsoft_defender|ninjaone), is_active, "
                "auth_status, last_checked_at, last_successful_check_at, last_error and "
                "the capabilities the provider exposes. Use this to find integration_id "
                "values for the other tools."
            ),
            input_schema=_object(properties={}),
            handler=_list_integrations,
        ),
        ToolSpec(
            name="get_integration",
            description=(
                "Get a single integration with its full configuration (the secret fields "
                "are masked unless the user has secret.read permission)."
            ),
            input_schema=_object(
                properties={
                    "integration_id": _integer("Integration id.", minimum=1),
                },
                required=["integration_id"],
            ),
            handler=_get_integration,
        ),
        ToolSpec(
            name="get_integration_health",
            description=(
                "Run the live health check for an integration: connectivity to the "
                "vendor APIs, auth status, last sync, sub-component statuses (e.g. "
                "Wazuh manager + indexer). Use this to answer 'is this vendor reachable "
                "and healthy?'."
            ),
            input_schema=_object(
                properties={
                    "integration_id": _integer("Integration id.", minimum=1),
                },
                required=["integration_id"],
            ),
            handler=_get_integration_health,
        ),
        ToolSpec(
            name="get_integration_overview",
            description=(
                "Aggregated dashboard view of an integration: counters, recent activity, "
                "and per-stream collection summary. Best single call to answer 'how is "
                "vendor X behaving right now?'."
            ),
            input_schema=_object(
                properties={
                    "integration_id": _integer("Integration id.", minimum=1),
                },
                required=["integration_id"],
            ),
            handler=_get_integration_overview,
        ),
        ToolSpec(
            name="list_integration_alerts",
            description=(
                "List alerts already collected and normalized from the vendor for this "
                "integration. Use this to inspect what has actually been processed (post "
                "mapping). For raw vendor payloads, see get_mapping_samples or "
                "get_quarantine_event."
            ),
            input_schema=_object(
                properties={
                    "integration_id": _integer("Integration id.", minimum=1),
                    "limit": _integer("Maximum results (default 25).", minimum=1, maximum=200),
                    "offset": _integer("Pagination offset.", minimum=0),
                },
                required=["integration_id"],
            ),
            handler=_list_integration_alerts,
        ),
        ToolSpec(
            name="list_supported_platforms",
            description=(
                "List the platform identifiers the CentralOps backend can connect to "
                "(static — defined in the provider registry). Use to validate vendor "
                "names before creating an integration."
            ),
            input_schema=_object(properties={}),
            handler=_list_supported_platforms,
        ),
    ]
