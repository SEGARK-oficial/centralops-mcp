from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from centralops_mcp.ack_cache import AckCache
from centralops_mcp.auth import Settings
from centralops_mcp.client import CentralOpsClient


@pytest.fixture
def settings() -> Settings:
    return Settings(
        base_url="http://centralops.test/api",
        api_token="copsk_test_aaaaaaaaaaaa",
        request_timeout_s=5.0,
        verify_tls=False,
    )


@pytest.fixture
def captured() -> list[httpx.Request]:
    return []


@pytest.fixture
def make_client(settings: Settings, captured: list[httpx.Request]):
    def _factory(handler: Callable[[httpx.Request], httpx.Response]) -> CentralOpsClient:
        def wrapper(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return handler(request)

        transport = httpx.MockTransport(wrapper)
        return CentralOpsClient(settings, transport=transport)

    return _factory


@pytest.fixture
def ack_cache() -> AckCache:
    return AckCache()


def json_response(payload: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=json.dumps(payload, default=str),
        headers={"content-type": "application/json"},
    )


def error_response(status: int, detail: str) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=json.dumps({"detail": detail}),
        headers={"content-type": "application/json"},
    )
