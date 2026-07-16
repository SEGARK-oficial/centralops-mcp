from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import destinations as destinations_tools

from .conftest import json_response


def _handlers():
    return {spec.name: spec.handler for spec in destinations_tools.specs()}


# ── list_destinations ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_destinations_passes_filters(make_client, captured):
    payload = [{"id": "dst-1", "name": "splunk-prod", "kind": "splunk_hec"}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["list_destinations"](
            c,
            org_id=7,
            include_disabled=True,
            offset=5,
            limit=10,
        )

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations"
    assert request.url.params["org_id"] == "7"
    assert request.url.params["include_disabled"] == "true"
    assert request.url.params["offset"] == "5"
    assert request.url.params["limit"] == "10"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_destinations_drops_none_org_id(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)

    async with client as c:
        await _handlers()["list_destinations"](c)

    request = captured[0]
    # None values are filtered out before sending
    assert "org_id" not in request.url.params
    # defaults still go through
    assert request.url.params["include_disabled"] == "false"
    assert request.url.params["offset"] == "0"
    assert request.url.params["limit"] == "50"


# ── get_destinations_health (batch) ───────────────────────────────────


@pytest.mark.asyncio
async def test_get_destinations_health_defaults(make_client, captured):
    payload = {"total": 0, "items": []}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["get_destinations_health"](c)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/health"
    # backend default is include_disabled=True; the tool mirrors it explicitly
    assert request.url.params["include_disabled"] == "true"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"


@pytest.mark.asyncio
async def test_get_destinations_health_passes_include_disabled_false(
    make_client, captured
):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"total": 0, "items": []})

    client = make_client(handler)

    async with client as c:
        await _handlers()["get_destinations_health"](c, include_disabled=False)

    request = captured[0]
    assert request.url.params["include_disabled"] == "false"


# ── get_destination_health (single) ───────────────────────────────────


@pytest.mark.asyncio
async def test_get_destination_health_no_query_params(make_client, captured):
    payload = {"destination_id": "dst-1", "status": "healthy", "enabled": True}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["get_destination_health"](
            c, destination_id="dst-1"
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/dst-1/health"
    assert not dict(request.url.params)
    assert request.headers["x-client"].startswith("centralops-mcp/")


# ── list_destination_dlq ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_destination_dlq_passes_pagination(make_client, captured):
    payload = {
        "destination_id": "dst-1",
        "total": 1,
        "by_error_kind": {"unrouted": 1},
        "entries": [],
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["list_destination_dlq"](
            c, destination_id="dst-1", offset=20, limit=100
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/dst-1/dlq"
    assert request.url.params["offset"] == "20"
    assert request.url.params["limit"] == "100"


@pytest.mark.asyncio
async def test_list_destination_dlq_defaults(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(
            {"destination_id": "__unrouted__", "total": 0, "by_error_kind": {}, "entries": []}
        )

    client = make_client(handler)

    async with client as c:
        await _handlers()["list_destination_dlq"](c, destination_id="__unrouted__")

    request = captured[0]
    assert request.url.path == "/api/collectors/destinations/__unrouted__/dlq"
    assert request.url.params["offset"] == "0"
    assert request.url.params["limit"] == "50"


# ── get_destination_metrics ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_destination_metrics_passes_range(make_client, captured):
    payload = {
        "destination_id": "dst-1",
        "available": True,
        "series": {},
        "gauges": {},
        "dlq_total": 0,
        "dlq_24h": 0,
        "by_error_kind": {},
        "breaker_state": "closed",
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["get_destination_metrics"](
            c, destination_id="dst-1", range_minutes=120
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/dst-1/metrics"
    assert request.url.params["range_minutes"] == "120"


# ── list_destination_audit ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_destination_audit_passes_limit(make_client, captured):
    payload = {"destination_id": "dst-1", "total": 0, "entries": []}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["list_destination_audit"](
            c, destination_id="dst-1", limit=25
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/dst-1/audit"
    assert request.url.params["limit"] == "25"


# ── list_destination_lineage ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_destination_lineage_passes_event_id(make_client, captured):
    payload = {"destination_id": "dst-1", "event_id": "evt-123", "entries": []}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["list_destination_lineage"](
            c, destination_id="dst-1", event_id="evt-123"
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/destinations/dst-1/lineage"
    assert request.url.params["event_id"] == "evt-123"


# ── get_event_lineage ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_event_lineage_passes_org_id(make_client, captured):
    payload = {"event_id": "evt-123", "organization_id": 3, "entries": []}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)

    async with client as c:
        result = await _handlers()["get_event_lineage"](
            c, event_id="evt-123", org_id=3
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/lineage/evt-123"
    assert request.url.params["org_id"] == "3"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"


@pytest.mark.asyncio
async def test_get_event_lineage_drops_none_org_id(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"event_id": "evt-123", "organization_id": 3, "entries": []})

    client = make_client(handler)

    async with client as c:
        await _handlers()["get_event_lineage"](c, event_id="evt-123")

    request = captured[0]
    assert request.url.path == "/api/collectors/lineage/evt-123"
    # None values are filtered out before sending
    assert "org_id" not in request.url.params
