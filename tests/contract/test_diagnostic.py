"""Diagnostic-flow tools — the read-only set the agent uses to inspect
how a vendor is sending data, what mappings exist, and what is broken."""

from __future__ import annotations

import httpx
import pytest

from centralops_mcp.ack_cache import AckCache
from centralops_mcp.tools import collectors as collectors_tools
from centralops_mcp.tools import integrations as integrations_tools
from centralops_mcp.tools import mapping as mapping_tools
from centralops_mcp.tools import quarantine as quarantine_tools

from .conftest import json_response


def _by_name(specs):
    return {s.name: s for s in specs}


@pytest.mark.asyncio
async def test_list_integrations_hits_root_path(make_client, captured):
    payload = [{"id": 1, "platform": "sophos", "is_active": True}]

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    spec = _by_name(integrations_tools.specs())["list_integrations"]

    async with client as c:
        result = await spec.handler(c)

    assert result == payload
    assert captured[0].url.path == "/api/integrations/"


@pytest.mark.asyncio
async def test_get_integration_health_endpoint(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"status": "healthy", "components": {}})

    client = make_client(handler)
    spec = _by_name(integrations_tools.specs())["get_integration_health"]

    async with client as c:
        await spec.handler(c, integration_id=42)

    assert captured[0].url.path == "/api/integrations/42/health"


@pytest.mark.asyncio
async def test_collection_state_filters_by_integration(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    spec = _by_name(collectors_tools.specs())["list_collection_state"]

    async with client as c:
        await spec.handler(c, integration_id=7)

    assert captured[0].url.path == "/api/collectors/state"
    assert captured[0].url.params["integration_id"] == "7"


@pytest.mark.asyncio
async def test_get_quarantine_event_returns_raw_payload(make_client, captured):
    payload = {
        "id": "ev-1",
        "vendor": "sophos",
        "event_type": "sophos.alert",
        "raw_payload": {"id": "abc", "severity": 5, "fields": {"x": 1}},
        "error_kind": "mapping_failed",
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    spec = _by_name(quarantine_tools.specs())["get_quarantine_event"]

    async with client as c:
        result = await spec.handler(c, event_id="ev-1")

    assert result["raw_payload"]["fields"]["x"] == 1
    assert captured[0].url.path == "/api/quarantine/ev-1"


@pytest.mark.asyncio
async def test_get_mapping_samples_passes_pair(make_client, captured):
    payload = {
        "vendor": "sophos",
        "event_type": "sophos.alert",
        "total_in_reservoir": 3,
        "items": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    spec = _by_name(mapping_tools.specs(AckCache()))["get_mapping_samples"]

    async with client as c:
        result = await spec.handler(
            c, vendor="sophos", event_type="sophos.alert", limit=3
        )

    assert result["total_in_reservoir"] == 3
    assert captured[0].url.path == "/api/mappings/samples"
    assert captured[0].url.params["vendor"] == "sophos"
    assert captured[0].url.params["event_type"] == "sophos.alert"
    assert captured[0].url.params["limit"] == "3"


@pytest.mark.asyncio
async def test_discover_mapping_fields_endpoint(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"fields": []})

    client = make_client(handler)
    spec = _by_name(mapping_tools.specs(AckCache()))["discover_mapping_fields"]

    async with client as c:
        await spec.handler(c, definition_id="def-1")

    assert captured[0].url.path == "/api/mappings/def-1/discover-fields"


@pytest.mark.asyncio
async def test_diff_mapping_versions_endpoint(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"added": [], "removed": [], "modified": []})

    client = make_client(handler)
    spec = _by_name(mapping_tools.specs(AckCache()))["diff_mapping_versions"]

    async with client as c:
        await spec.handler(
            c, definition_id="def-1", version_a_id="v1", version_b_id="v2"
        )

    assert captured[0].url.path == "/api/mappings/def-1/versions/v1/diff/v2"


@pytest.mark.asyncio
async def test_list_mapping_audit_filters(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"total": 0, "items": [], "limit": 50, "offset": 0})

    client = make_client(handler)
    spec = _by_name(mapping_tools.specs(AckCache()))["list_mapping_audit"]

    async with client as c:
        await spec.handler(
            c,
            definition_id="def-1",
            action="rollback",
            from_ts="2026-04-01T00:00:00Z",
        )

    request = captured[0]
    assert request.url.path == "/api/mappings/def-1/audit"
    assert request.url.params["action"] == "rollback"
    assert request.url.params["from_ts"] == "2026-04-01T00:00:00Z"
    # username/to_ts default to None and should be dropped
    assert "username" not in request.url.params
    assert "to_ts" not in request.url.params
