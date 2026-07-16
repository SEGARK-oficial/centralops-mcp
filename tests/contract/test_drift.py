from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import drift as drift_tools

from .conftest import json_response


@pytest.mark.asyncio
async def test_list_drift_fields_passes_filters(make_client, captured):
    payload = {"total": 0, "items": [], "limit": 50, "offset": 0}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = drift_tools.specs()[0].handler

    async with client as c:
        result = await handler_fn(
            c,
            vendor="sophos",
            event_type="sophos.alert",
            status="new",
            limit=10,
            offset=0,
        )

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/drift"
    assert request.url.params["vendor"] == "sophos"
    assert request.url.params["event_type"] == "sophos.alert"
    assert request.url.params["status"] == "new"
    assert request.url.params["limit"] == "10"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_drift_fields_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"total": 0, "items": [], "limit": 50, "offset": 0})

    client = make_client(handler)
    handler_fn = drift_tools.specs()[0].handler

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    # None values are filtered out before sending
    assert "vendor" not in request.url.params
    assert "event_type" not in request.url.params
    assert "status" not in request.url.params
    # defaults still go through
    assert request.url.params["limit"] == "50"
    assert request.url.params["offset"] == "0"
