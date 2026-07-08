from __future__ import annotations

import pytest
import httpx

from centralops_mcp.client import CentralOpsAPIError
from centralops_mcp.tools import sophos_licenses as sophos_licenses_tools

from .conftest import json_response, error_response


def _handler_fn():
    return sophos_licenses_tools.specs()[0].handler


# ---------------------------------------------------------------------------
# Happy path: populated list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_returns_licensed_products_when_populated(make_client, captured):
    products = [
        {"id": "prod-1", "name": "Intercept X Advanced", "licenseType": "trial"},
        {"id": "prod-2", "name": "XDR", "licenseType": "paid"},
    ]
    overview = {"id": 42, "kind": "tenant", "licensed_products": products}

    client = make_client(lambda _: json_response(overview))

    async with client as c:
        result = await _handler_fn()(c, integration_id=42)

    assert result == {"licensed_products": products}
    assert captured[0].url.path == "/api/integrations/42/overview"
    assert captured[0].method == "GET"


# ---------------------------------------------------------------------------
# Null path: not a child tenant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_returns_null_with_reason_when_licensed_products_is_none(make_client):
    overview = {"id": 7, "kind": "partner_root", "licensed_products": None}

    client = make_client(lambda _: json_response(overview))

    async with client as c:
        result = await _handler_fn()(c, integration_id=7)

    assert result["licensed_products"] is None
    assert "reason" in result
    assert "child tenant" in result["reason"].lower() or "kind" in result["reason"]


# ---------------------------------------------------------------------------
# Empty list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_returns_empty_with_note_when_licensed_products_is_empty(make_client):
    overview = {"id": 5, "kind": "tenant", "licensed_products": []}

    client = make_client(lambda _: json_response(overview))

    async with client as c:
        result = await _handler_fn()(c, integration_id=5)

    assert result["licensed_products"] == []
    assert "note" in result
    assert "empty" in result["note"].lower() or "license" in result["note"].lower()


# ---------------------------------------------------------------------------
# Backend 404
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_propagates_404_as_api_error(make_client):
    client = make_client(lambda _: error_response(404, "Integration not found"))

    async with client as c:
        with pytest.raises(CentralOpsAPIError) as exc_info:
            await _handler_fn()(c, integration_id=9999)

    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Backend 401
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_propagates_401_as_api_error(make_client):
    client = make_client(lambda _: error_response(401, "Unauthorized"))

    async with client as c:
        with pytest.raises(CentralOpsAPIError) as exc_info:
            await _handler_fn()(c, integration_id=1)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Backend 500
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_propagates_5xx_as_api_error(make_client):
    client = make_client(
        lambda _: httpx.Response(
            status_code=500,
            content=b"Internal Server Error",
            headers={"content-type": "text/plain"},
        )
    )

    async with client as c:
        with pytest.raises(CentralOpsAPIError) as exc_info:
            await _handler_fn()(c, integration_id=1)

    assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("bad_id", [0, -1, -100])
async def test_rejects_invalid_integration_id(make_client, bad_id):
    client = make_client(lambda _: json_response({}))

    async with client as c:
        with pytest.raises(ValueError):
            await _handler_fn()(c, integration_id=bad_id)


# ---------------------------------------------------------------------------
# Tool spec sanity
# ---------------------------------------------------------------------------

def test_spec_name_and_description():
    spec = sophos_licenses_tools.specs()[0]
    assert spec.name == "get_sophos_licenses"
    assert len(spec.description) <= 200
    assert "integration_id" in spec.input_schema["properties"]
    assert spec.input_schema.get("required") == ["integration_id"]
