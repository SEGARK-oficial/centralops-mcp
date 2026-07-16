from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import queries as queries_tools

from .conftest import json_response


def _handler(name: str):
    for spec in queries_tools.specs():
        if spec.name == name:
            return spec.handler
    raise AssertionError(f"tool not found: {name}")


@pytest.mark.asyncio
async def test_list_scheduled_queries_no_params_trailing_slash(make_client, captured):
    payload = [{"id": 1, "query_id": 2, "client_ids": [3]}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("list_scheduled_queries")

    async with client as c:
        result = await handler_fn(c)

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    # trailing slash is significant: the backend registers GET /schedules/
    assert request.url.path == "/api/schedules/"
    assert not request.url.params
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_get_scheduled_query_history_builds_path(make_client, captured):
    payload = [{"id": 10, "search_id": "abc", "schedule_id": 7, "status": "completed"}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("get_scheduled_query_history")

    async with client as c:
        result = await handler_fn(c, schedule_id=7)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/schedules/7/history"
    assert not request.url.params


@pytest.mark.asyncio
async def test_list_search_history_passes_filters(make_client, captured):
    payload = [{"id": 1, "search_id": "s-1", "client_id": 4, "schedule_id": 9}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("list_search_history")

    async with client as c:
        result = await handler_fn(c, client_id=4, schedule_id=9)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/search/history"
    assert request.url.params["client_id"] == "4"
    assert request.url.params["schedule_id"] == "9"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_search_history_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    handler_fn = _handler("list_search_history")

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    assert request.url.path == "/api/search/history"
    # None values are filtered out before sending
    assert "client_id" not in request.url.params
    assert "schedule_id" not in request.url.params
    assert not request.url.params


@pytest.mark.asyncio
async def test_get_search_result_builds_path(make_client, captured):
    payload = {"id": 3, "search_id": "srch-xyz", "status": "completed"}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("get_search_result")

    async with client as c:
        result = await handler_fn(c, search_id="srch-xyz")

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/search/history/result/srch-xyz"
    assert not request.url.params


@pytest.mark.asyncio
async def test_list_audit_log_passes_filters(make_client, captured):
    payload = [
        {
            "id": 1,
            "username": "alice",
            "action": "login",
            "endpoint": "/api/auth/login",
            "created_at": "2026-07-10T12:00:00",
        }
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("list_audit_log")

    async with client as c:
        result = await handler_fn(
            c,
            username="alice",
            ip_address="10.0.0.",
            date_from="2026-07-01",
            date_to="2026-07-10T23:59:59Z",
        )

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/history/audit"
    assert request.url.params["username"] == "alice"
    assert request.url.params["ip_address"] == "10.0.0."
    assert request.url.params["date_from"] == "2026-07-01"
    assert request.url.params["date_to"] == "2026-07-10T23:59:59Z"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_audit_log_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    handler_fn = _handler("list_audit_log")

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    assert request.url.path == "/api/history/audit"
    assert "username" not in request.url.params
    assert "ip_address" not in request.url.params
    assert "date_from" not in request.url.params
    assert "date_to" not in request.url.params
    assert not request.url.params


@pytest.mark.asyncio
async def test_get_query_capabilities_no_params(make_client, captured):
    payload = [
        {
            "dialect": "opensearch_dsl",
            "capability": "query:opensearch_dsl",
            "modes": ["sync"],
            "supports_async": False,
            "supported_by": ["wazuh"],
        }
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler("get_query_capabilities")

    async with client as c:
        result = await handler_fn(c)

    assert result == payload
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/providers/query-capabilities"
    assert not request.url.params
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")
