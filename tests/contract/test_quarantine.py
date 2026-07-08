from __future__ import annotations

import httpx
import pytest

from centralops_mcp.tools import quarantine as quarantine_tools

from .conftest import error_response, json_response


def _by_name(specs):
    return {s.name: s for s in specs}


@pytest.mark.asyncio
async def test_list_quarantine_endpoint(make_client, captured):
    payload = {"total": 0, "items": [], "limit": 50, "offset": 0}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    spec = _by_name(quarantine_tools.specs())["list_quarantine"]

    async with client as c:
        await spec.handler(c, vendor="sophos", error_kind="mapping_failed")

    assert captured[0].url.path == "/api/quarantine"
    assert captured[0].url.params["error_kind"] == "mapping_failed"


@pytest.mark.asyncio
async def test_reprocess_quarantine_aggregates_results(make_client, captured):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ev-bad/reprocess"):
            return error_response(409, "Evento já foi reprocessado")
        return json_response({"id": request.url.path.split("/")[-2], "status": "ok"})

    client = make_client(handler)
    spec = _by_name(quarantine_tools.specs())["reprocess_quarantine"]

    async with client as c:
        result = await spec.handler(c, event_ids=["ev-1", "ev-bad", "ev-2"])

    assert result["summary"] == {"requested": 3, "succeeded": 2, "failed": 1}
    statuses = [r["status"] for r in result["results"]]
    assert statuses == ["ok", "error", "ok"]
    assert result["results"][1]["http_status"] == 409
    assert len(captured) == 3


@pytest.mark.asyncio
async def test_reprocess_quarantine_rejects_empty(make_client):
    client = make_client(lambda _: json_response({}))
    spec = _by_name(quarantine_tools.specs())["reprocess_quarantine"]

    async with client as c:
        with pytest.raises(ValueError):
            await spec.handler(c, event_ids=[])


@pytest.mark.asyncio
async def test_reprocess_quarantine_rejects_oversize(make_client):
    client = make_client(lambda _: json_response({}))
    spec = _by_name(quarantine_tools.specs())["reprocess_quarantine"]

    async with client as c:
        with pytest.raises(ValueError, match="limit per call"):
            await spec.handler(c, event_ids=[f"ev-{i}" for i in range(60)])
