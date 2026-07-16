from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import pipeline_health as pipeline_health_tools

from .conftest import json_response


def _handler_by_name(name: str):
    by_name = {spec.name: spec for spec in pipeline_health_tools.specs()}
    return by_name[name].handler


@pytest.mark.asyncio
async def test_get_pipeline_health_bulk_no_params(make_client, captured):
    payload = {
        "items": [
            {
                "integration_id": 1,
                "status": "healthy",
                "events_per_minute": 12.5,
                "lag_seconds": 42,
                "last_error": None,
                "last_success_at": "2026-07-16T12:00:00",
                "mapped_field_ratio": 0.98,
                "drift_count_24h": 1,
                "quarantine_count_24h": 0,
                "cached_at": "2026-07-16T12:00:30",
            }
        ],
        "total": 1,
        "cached_at": "2026-07-16T12:00:30",
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_by_name("get_pipeline_health")

    async with client as c:
        result = await handler_fn(c)

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/integrations/pipeline-health"
    # Endpoint takes no query params — nothing may leak into the query string
    assert not dict(request.url.params)
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_get_integration_pipeline_health_builds_path(make_client, captured):
    payload = {
        "integration_id": 42,
        "status": "degraded",
        "events_per_minute": None,
        "lag_seconds": 120,
        "last_error": "vendor timeout",
        "last_success_at": "2026-07-16T11:58:00",
        "mapped_field_ratio": None,
        "drift_count_24h": 0,
        "quarantine_count_24h": 3,
        "cached_at": "2026-07-16T12:00:00",
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_by_name("get_integration_pipeline_health")

    async with client as c:
        result = await handler_fn(c, integration_id=42)

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    # integration_id is a path parameter, not a query parameter
    assert request.url.path == "/api/integrations/42/pipeline-health"
    assert not dict(request.url.params)
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")
