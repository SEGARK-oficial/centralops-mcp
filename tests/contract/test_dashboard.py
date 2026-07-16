from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import dashboard as dashboard_tools

from .conftest import json_response


V2_PAYLOAD = {
    "schema_version": 2,
    "window": "7d",
    "generated_at": "2026-07-16T12:00:00+00:00",
    "kpis": [
        {
            "id": "ingest_eps",
            "label": "Ingestão (EPS)",
            "value": 12.3,
            "sub": "eventos/s",
            "icon_id": "activity",
            "severity": "ok",
        }
    ],
    "top_buckets": [
        {
            "id": "top_sources_volume",
            "label": "Top fontes por volume",
            "items": [],
            "icon_id": "activity",
            "empty_hint": "Sem dados de ingestão na janela atual.",
        }
    ],
}


@pytest.mark.asyncio
async def test_get_dashboard_summary_passes_filters(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(V2_PAYLOAD)

    client = make_client(handler)
    handler_fn = dashboard_tools.specs()[0].handler

    async with client as c:
        result = await handler_fn(
            c,
            organization_id=3,
            integration_id=17,
            platform="sophos",
            days=30,
        )

    assert result == V2_PAYLOAD
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/dashboard/summary"
    assert request.url.params["organization_id"] == "3"
    assert request.url.params["integration_id"] == "17"
    assert request.url.params["platform"] == "sophos"
    assert request.url.params["days"] == "30"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")
    # Default Accept must request the V2 shape (never the vendored v1 media type)
    assert request.headers["accept"] == "application/json"


@pytest.mark.asyncio
async def test_get_dashboard_summary_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(V2_PAYLOAD)

    client = make_client(handler)
    handler_fn = dashboard_tools.specs()[0].handler

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    assert request.url.path == "/api/dashboard/summary"
    # None values are filtered out before sending
    assert "organization_id" not in request.url.params
    assert "integration_id" not in request.url.params
    assert "platform" not in request.url.params
    # defaults still go through
    assert request.url.params["days"] == "7"
