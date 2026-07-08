from __future__ import annotations

from typing import Any, Mapping

import httpx

from centralops_mcp.auth import Settings


class CentralOpsAPIError(RuntimeError):
    def __init__(self, status_code: int, message: str, body: Any = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.body = body


class CentralOpsClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._settings = settings
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "CentralOpsClient":
        kwargs: dict = {
            "base_url": self._settings.base_url,
            "timeout": self._settings.request_timeout_s,
            "headers": {
                "Authorization": self._settings.authorization_header,
                "X-Client": self._settings.client_header,
                "Accept": "application/json",
            },
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        else:
            kwargs["verify"] = self._settings.verify_tls
        self._client = httpx.AsyncClient(**kwargs)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        json: Any | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        return await self._request("POST", path, json=json, params=params)

    async def _request(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
    ) -> Any:
        assert self._client is not None, "Use 'async with' to manage the client lifecycle"
        cleaned_params = (
            {k: v for k, v in params.items() if v is not None} if params else None
        )
        response = await self._client.request(
            method, path, params=cleaned_params, json=json
        )
        if response.status_code >= 400:
            self._raise_for_status(response)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        body: Any
        try:
            body = response.json()
        except ValueError:
            body = response.text

        message = "request failed"
        if isinstance(body, dict):
            detail = body.get("detail")
            if isinstance(detail, str):
                message = detail
            elif isinstance(detail, dict) and "message" in detail:
                message = str(detail["message"])
        elif isinstance(body, str) and body:
            message = body[:500]

        if response.status_code == 401:
            message = (
                "API token rejected by CentralOps. "
                "Verify CENTRALOPS_API_TOKEN: the token may be revoked, "
                "expired, or generated for a different deployment. "
                "Generate a new one at <base_url>/settings/tokens."
            )
        elif response.status_code == 403:
            # Fase 2: scopes — token may be valid but missing the required permission.
            message = (
                f"{message}\n"
                "Hint: if the token has scopes set, ensure they include the "
                "permission required by this endpoint."
            )
        raise CentralOpsAPIError(response.status_code, message, body=body)
