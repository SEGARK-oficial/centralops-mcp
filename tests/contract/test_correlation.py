"""Correlation tools — the request each one actually sends.

These are contract tests, not integration: they assert the METHOD, the PATH and
the PARAMETERS, because that is where this module can silently lie. Two of the
assertions exist because of defects that already happened elsewhere in the
product:

* ``include_inflight_status`` must travel when asked. Without it the backend
  answers ``not_evaluated_inflight: false`` for every rule, and that false means
  "not calculated", never "the rule is running" — a caller that trusts it paints
  a green light over exactly the rule that is being dropped by the cycle cap.
* ``eval_mode`` must travel on preview. The endpoint's own default is
  ``inflight``, the OPPOSITE of the default a rule is created with; a preview
  that omits it judges a batch rule by the in-flight vocabulary and can return a
  green verdict for a rule the batch engine discards at the first clause.
"""

from __future__ import annotations

import json

import httpx
import pytest

from centralops_mcp.tools import correlation as correlation_tools
from centralops_mcp.tools import mapping as mapping_tools

from .conftest import json_response


def _handler_by_name(name: str, specs):
    for spec in specs:
        if spec.name == name:
            return spec.handler
    raise AssertionError(f"tool {name!r} not found")


def _corr(name: str):
    return _handler_by_name(name, correlation_tools.specs())


@pytest.mark.asyncio
async def test_list_rules_opt_in_travels(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([{"id": 1, "name": "x", "eval_mode": "inflight"}])

    client = make_client(handler)
    async with client as c:
        await _corr("list_correlation_rules")(c, include_inflight_status=True)

    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/correlation-rules"
    assert request.url.params["include_inflight_status"] == "true"


@pytest.mark.asyncio
async def test_list_rules_default_is_the_cheap_call(make_client, captured):
    """The positive next to the negative: by default the opt-in is off (and the
    caller gets the 'not calculated' false), which is what keeps the listing
    from paying a COUNT plus a compilation per organization."""

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response([])

    client = make_client(handler)
    async with client as c:
        await _corr("list_correlation_rules")(c)

    assert captured[0].url.params["include_inflight_status"] == "false"


@pytest.mark.asyncio
async def test_get_rule_builds_path_without_params(make_client, captured):
    payload = {"id": 7, "rule_type": "sequence", "legs": [{"join_path": "normalized.user.name"}]}

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    async with client as c:
        result = await _corr("get_correlation_rule")(c, rule_id=7)

    assert result == payload
    assert captured[0].url.path == "/api/correlation-rules/7"
    assert not dict(captured[0].url.params)


@pytest.mark.asyncio
async def test_rule_metrics_defaults_to_the_retained_window(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"rule_id": 7, "matches": None, "overflow": 0.0, "errors": {}})

    client = make_client(handler)
    async with client as c:
        result = await _corr("get_correlation_rule_metrics")(c, rule_id=7)

    assert captured[0].url.path == "/api/correlation-rules/7/metrics"
    # 1440 min = 24 h, the window the series is actually retained for.
    assert captured[0].url.params["range_minutes"] == "1440"
    # And the null survives the round trip: null is "unknown", not zero.
    assert result["matches"] is None
    assert result["overflow"] == 0.0


@pytest.mark.asyncio
async def test_rule_metrics_honours_a_narrower_window(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"rule_id": 7})

    client = make_client(handler)
    async with client as c:
        await _corr("get_correlation_rule_metrics")(c, rule_id=7, range_minutes=60)

    assert captured[0].url.params["range_minutes"] == "60"


@pytest.mark.asyncio
async def test_limits_drops_the_absent_org(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"organization_id": 3, "truncated_count": 0})

    client = make_client(handler)
    async with client as c:
        await _corr("get_correlation_limits")(c)

    assert captured[0].url.path == "/api/correlation-rules/limits"
    assert "organization_id" not in captured[0].url.params

    async with make_client(handler) as c:
        await _corr("get_correlation_limits")(c, organization_id=9)
    assert captured[1].url.params["organization_id"] == "9"


@pytest.mark.asyncio
async def test_preview_sends_the_mode_and_the_clauses(make_client, captured):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"state": "ok", "matched": 3, "sample_count": 25, "eval_mode": "batch"})

    where = [{"field": "normalized.metadata.event_code", "op": "eq", "value": "XDR-veeam-restorepointremoved"}]
    client = make_client(handler)
    async with client as c:
        await _corr("preview_correlation_rule")(
            c,
            vendor="sophos",
            event_type="sophos.detection",
            where=where,
            eval_mode="batch",
            organization_id=7,
        )

    request = captured[0]
    assert request.method == "POST"
    assert request.url.path == "/api/correlation-rules/preview"
    body = json.loads(request.content)
    assert body["eval_mode"] == "batch"
    assert body["where"] == where
    assert body["limit"] == 25
    assert body["organization_id"] == 7


@pytest.mark.asyncio
async def test_preview_omits_the_org_when_absent(make_client, captured):
    """A null organization_id must not travel as null: the reservoir is
    org-scoped and fail-closed, and an explicit null is not the same request as
    an absent key."""

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"state": "empty"})

    client = make_client(handler)
    async with client as c:
        await _corr("preview_correlation_rule")(
            c, vendor="wazuh", event_type="wazuh.detection", where=[]
        )

    body = json.loads(captured[0].content)
    assert "organization_id" not in body
    assert body["eval_mode"] == "inflight"


@pytest.mark.asyncio
async def test_key_sources_is_reachable_and_org_scoped(make_client, captured, ack_cache):
    payload = {
        "organization_id": 7,
        "from_active_mappings": True,
        "roots": ["_centralops", "normalized", "raw"],
        "suggestions": [
            {"path": "normalized.metadata.event_code", "rule_count": 3, "vendors": ["sophos"], "kind": "mapped"}
        ],
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(payload)

    client = make_client(handler)
    handler_fn = _handler_by_name("list_mapping_key_sources", mapping_tools.specs(ack_cache))
    async with client as c:
        result = await handler_fn(c, organization_id=7)

    assert result == payload
    assert captured[0].url.path == "/api/mappings/key-sources"
    assert captured[0].url.params["organization_id"] == "7"


def test_every_correlation_tool_documents_the_enterprise_boundary():
    """These routes only exist on an Enterprise deployment; on Community the
    call is a 404. A tool that does not say so turns a licensing fact into a
    'the API is broken' conclusion."""
    for spec in correlation_tools.specs():
        assert "Enterprise" in spec.description, spec.name
