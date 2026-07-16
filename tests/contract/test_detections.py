from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import detections as detections_tools

from .conftest import json_response


def _handler_by_name(name: str):
    for spec in detections_tools.specs():
        if spec.name == name:
            return spec.handler
    raise AssertionError(f"tool {name!r} not found in detections specs()")


@pytest.mark.asyncio
async def test_list_detections_passes_filters(make_client, captured):
    payload = [
        {
            "id": 1,
            "organization_id": 3,
            "source": "correlation",
            "severity_id": 4,
            "status": "open",
            "dedup_key": "corr:rule-7",
            "count": 2,
            "suppression_window_seconds": 3600,
        }
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_by_name("list_detections")

    async with client as c:
        result = await handler_fn(c, status_filter="open", limit=25)

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/detections"
    assert request.url.params["status_filter"] == "open"
    assert request.url.params["limit"] == "25"
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")


@pytest.mark.asyncio
async def test_list_detections_drops_none_params(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    handler_fn = _handler_by_name("list_detections")

    async with client as c:
        await handler_fn(c)

    request = captured[0]
    # None values are filtered out before sending
    assert "status_filter" not in request.url.params
    # defaults still go through
    assert request.url.params["limit"] == "100"


@pytest.mark.asyncio
async def test_get_detection_builds_path_no_query_params(make_client, captured):
    payload = {
        "id": 42,
        "organization_id": 3,
        "source": "scheduled_query",
        "severity_id": 5,
        "status": "ack",
        "dedup_key": "sq:11",
        "count": 1,
        "suppression_window_seconds": 3600,
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_by_name("get_detection")

    async with client as c:
        result = await handler_fn(c, detection_id=42)

    assert result == payload
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/detections/42"
    assert not dict(request.url.params)
    assert request.headers["authorization"] == "Bearer copsk_test_aaaaaaaaaaaa"
    assert request.headers["x-client"].startswith("centralops-mcp/")
