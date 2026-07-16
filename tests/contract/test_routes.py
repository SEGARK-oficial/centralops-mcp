from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import routes as routes_tools

from .conftest import json_response


def _handler_for(name: str):
    by_name = {spec.name: spec for spec in routes_tools.specs()}
    return by_name[name].handler


@pytest.mark.asyncio
async def test_list_routes_passes_params(make_client, captured):
    payload = [{"id": "r-1", "name": "to-siem", "action": "route"}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_for("list_routes")

    async with client as c:
        result = await handler_fn(
            c,
            include_disabled=False,
            offset=10,
            limit=50,
        )

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/routes"
    assert request.url.params["include_disabled"] == "false"
    assert request.url.params["offset"] == "10"
    assert request.url.params["limit"] == "50"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_routes_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    handler_fn = _handler_for("list_routes")

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    # None values are filtered out before sending — the server applies its own
    # defaults (include_disabled=true, offset=0, limit=200).
    assert "include_disabled" not in request.url.params
    assert "offset" not in request.url.params
    assert "limit" not in request.url.params


@pytest.mark.asyncio
async def test_get_routes_topology_no_params(make_client, captured):
    payload = {"destinations": [], "routes": []}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_for("get_routes_topology")

    async with client as c:
        result = await handler_fn(c)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/routes/topology"
    assert not dict(request.url.params)
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_get_routes_flow_no_params(make_client, captured):
    payload = {
        "generated_at": "2026-07-16T00:00:00+00:00",
        "window_minutes": 5,
        "sources": [],
        "routes": [],
        "destinations": [],
        "totals": {
            "ingest_eps": 0.0,
            "routed_per_min": 0.0,
            "drop_per_min": 0.0,
            "delivered_eps": 0.0,
        },
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_for("get_routes_flow")

    async with client as c:
        result = await handler_fn(c)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/routes/flow"
    assert not dict(request.url.params)


@pytest.mark.asyncio
async def test_get_route_health_no_query_params(make_client, captured):
    payload = {
        "route_id": "r-1",
        "status": "healthy",
        "enabled": True,
        "matched_eps": 0.01,
        "matched_1h": 36,
        "routed_1h": 36,
        "dropped_1h": 0,
        "drop_rate": 0.0,
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_for("get_route_health")

    async with client as c:
        result = await handler_fn(c, route_id="r-1")

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/routes/r-1/health"
    assert not dict(request.url.params)
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"


@pytest.mark.asyncio
async def test_get_route_metrics_passes_range(make_client, captured):
    payload = {"route_id": "r-1", "series": {"matched": [], "route": [], "drop": []}}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_for("get_route_metrics")

    async with client as c:
        result = await handler_fn(c, route_id="r-1", range_minutes=120)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/collectors/routes/r-1/metrics"
    assert request.url.params["range_minutes"] == "120"


@pytest.mark.asyncio
async def test_get_route_metrics_drops_none_range(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"route_id": "r-1", "series": {}})

    client = make_client(handler)
    handler_fn = _handler_for("get_route_metrics")

    async with client as c:
        await handler_fn(c, route_id="r-1")

    request = captured[0]
    assert request.url.path == "/api/collectors/routes/r-1/metrics"
    # None is filtered out — the server applies its default (60).
    assert "range_minutes" not in request.url.params
