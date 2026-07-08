from __future__ import annotations

import json

import httpx
import pytest

from centralops_mcp.tools import backfill as backfill_tools

from .conftest import json_response


def _by_name(specs):
    return {s.name: s for s in specs}


@pytest.mark.asyncio
async def test_request_backfill_posts_window(make_client, captured):
    job = {
        "id": "job-1", "integration_id": 7, "streams": ["alerts"],
        "from_ts": "2026-04-01T00:00:00Z", "to_ts": "2026-04-02T00:00:00Z",
        "status": "pending",
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(job, status=201)

    client = make_client(handler)
    specs = _by_name(backfill_tools.specs())

    async with client as c:
        result = await specs["request_backfill"].handler(
            c, integration_id=7, streams=["alerts"],
            from_ts="2026-04-01T00:00:00Z", to_ts="2026-04-02T00:00:00Z",
        )

    assert result["job"] == job
    assert result["wait_for_backfill_job_input"] == {"job_id": "job-1"}
    assert captured[0].url.path == "/api/integrations/7/backfill"
    body = json.loads(captured[0].content)
    assert body["streams"] == ["alerts"]


@pytest.mark.asyncio
async def test_request_backfill_rejects_empty_streams(make_client):
    client = make_client(lambda _: json_response({}))
    specs = _by_name(backfill_tools.specs())

    async with client as c:
        with pytest.raises(ValueError):
            await specs["request_backfill"].handler(
                c, integration_id=7, streams=[],
                from_ts="2026-04-01T00:00:00Z", to_ts="2026-04-02T00:00:00Z",
            )


@pytest.mark.asyncio
async def test_wait_for_job_returns_terminal_state(make_client):
    states = iter(["running", "running", "completed"])

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"id": "job-1", "status": next(states)})

    client = make_client(handler)
    specs = _by_name(backfill_tools.specs())

    async with client as c:
        result = await specs["wait_for_backfill_job"].handler(
            c, job_id="job-1", timeout_s=5, poll_interval_s=2,
        )

    assert result["terminal"] is True
    assert result["timed_out"] is False
    assert result["job"]["status"] == "completed"


@pytest.mark.asyncio
async def test_wait_for_job_times_out(make_client):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"id": "job-1", "status": "running"})

    client = make_client(handler)
    specs = _by_name(backfill_tools.specs())

    async with client as c:
        result = await specs["wait_for_backfill_job"].handler(
            c, job_id="job-1", timeout_s=1, poll_interval_s=2,
        )

    assert result["timed_out"] is True
    assert result["terminal"] is False


@pytest.mark.asyncio
async def test_wait_for_job_validates_inputs(make_client):
    client = make_client(lambda _: json_response({}))
    specs = _by_name(backfill_tools.specs())

    async with client as c:
        with pytest.raises(ValueError):
            await specs["wait_for_backfill_job"].handler(c, job_id="x", timeout_s=0)
        with pytest.raises(ValueError):
            await specs["wait_for_backfill_job"].handler(c, job_id="x", timeout_s=10000)
