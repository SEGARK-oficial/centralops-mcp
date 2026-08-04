from __future__ import annotations

import json

import httpx
import pytest

from centralops_mcp.ack_cache import AckCache, AckTokenError
from centralops_mcp.tools import mapping as mapping_tools

from .conftest import json_response


def _by_name(specs):
    return {s.name: s for s in specs}


@pytest.mark.asyncio
async def test_list_and_get_mapping(make_client, captured, ack_cache: AckCache):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/mappings":
            return json_response(
                [{"id": "def-1", "vendor": "sophos", "event_type": "sophos.alert",
                  "current_version_id": "v-9"}]
            )
        if request.url.path == "/api/mappings/def-1/versions/v-9":
            return json_response({
                "id": "v-9", "version_number": 4, "commit_message": "fix",
                "rules": {"rules": [{"target": "normalized.class_uid", "const": 2004}]},
                "ocsf_validation_stats": {"checked": 10, "valid": 10},
            })
        if request.url.path == "/api/mappings/def-1":
            return json_response({"id": "def-1", "vendor": "sophos", "versions": []})
        return json_response({}, status=404)

    client = make_client(handler)
    specs = _by_name(mapping_tools.specs(ack_cache))

    async with client as c:
        listing = await specs["list_mappings"].handler(c, include_rules_count=True)
        detail = await specs["get_mapping"].handler(c, definition_id="def-1")
        full = await specs["get_mapping"].handler(
            c, definition_id="def-1", include_versions="full"
        )

    assert listing[0]["id"] == "def-1"
    assert captured[0].url.params["include_rules_count"] == "true"

    # Caminho padrão: resolve a versão vigente pelo PONTEIRO e devolve só ela.
    assert detail["definition"]["id"] == "def-1"
    assert detail["current_version_resolved"] == "pointer"
    assert detail["current_version"]["id"] == "v-9"
    assert detail["current_version"]["rules_count"] == 1
    assert detail["current_rules"]["rules"][0]["const"] == 2004
    assert detail["versions"] == [], "histórico não deve vir sem pedir"
    # ocsf_validation_stats nunca é suprimido: é a única janela para "a versão
    # em produção emite OCSF válido?"
    assert detail["current_version"]["ocsf_validation_stats"]["valid"] == 10

    # 'full' continua sendo o passthrough do endpoint antigo.
    assert full["id"] == "def-1"


@pytest.mark.asyncio
async def test_get_mapping_nunca_baixa_o_historico_por_padrao(make_client, ack_cache: AckCache):
    """A razão de existir da mudança: 4 versões x 51 regras estouravam o contexto."""
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/mappings":
            return json_response([{"id": "d1", "vendor": "wazuh",
                                   "current_version_id": "v1"}])
        if request.url.path == "/api/mappings/d1/versions/v1":
            return json_response({"id": "v1", "rules": {"rules": []}})
        return json_response({}, status=404)

    specs = _by_name(mapping_tools.specs(ack_cache))
    async with make_client(handler) as c:
        await specs["get_mapping"].handler(c, definition_id="d1")

    assert "/api/mappings/d1" not in paths, (
        "get_mapping chamou o endpoint que devolve TODAS as versões com corpo integral"
    )


@pytest.mark.asyncio
async def test_dry_run_issues_ack_token_when_definition_id_present(
    make_client, ack_cache: AckCache, captured
):
    dry_run_payload = {
        "sample_size": 5,
        "ok_count": 5,
        "fail_count": 0,
        "rule_failures": [],
        "output_examples": [],
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return json_response(dry_run_payload)

    client = make_client(handler)
    specs = _by_name(mapping_tools.specs(ack_cache))
    rules = {"preprocess": [], "rules": [{"target": "x", "const": 1}]}

    async with client as c:
        result = await specs["dry_run_mapping"].handler(
            c, rules=rules, definition_id="def-1", vendor="sophos", event_type="sophos.alert"
        )

    assert result["dry_run"] == dry_run_payload
    assert result["ack_token"], "ack_token must be issued when definition_id is set"
    body = json.loads(captured[0].content)
    assert body["rules"] == rules
    assert body["vendor"] == "sophos"


@pytest.mark.asyncio
async def test_dry_run_without_definition_id_skips_token(make_client, ack_cache: AckCache):
    def handler(_: httpx.Request) -> httpx.Response:
        return json_response({"sample_size": 0, "ok_count": 0, "fail_count": 0,
                              "rule_failures": [], "output_examples": []})

    client = make_client(handler)
    specs = _by_name(mapping_tools.specs(ack_cache))

    async with client as c:
        result = await specs["dry_run_mapping"].handler(
            c, rules={"rules": []}, raw_events=[{"a": 1}]
        )

    assert result["ack_token"] is None


@pytest.mark.asyncio
async def test_commit_requires_matching_ack_token(make_client, ack_cache: AckCache):
    rules = {"preprocess": [], "rules": [{"target": "x", "const": 1}]}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/mappings/dry-run":
            return json_response({"sample_size": 1, "ok_count": 1, "fail_count": 0,
                                  "rule_failures": [], "output_examples": []})
        if request.url.path == "/api/mappings/def-1/versions":
            return json_response({"id": "v-1", "version_number": 1}, status=201)
        return json_response({}, status=404)

    client = make_client(handler)
    specs = _by_name(mapping_tools.specs(ack_cache))

    async with client as c:
        dry = await specs["dry_run_mapping"].handler(
            c, rules=rules, definition_id="def-1", vendor="sophos", event_type="sophos.alert"
        )
        token = dry["ack_token"]

        # commit with bad token
        with pytest.raises(AckTokenError):
            await specs["commit_mapping"].handler(
                c, definition_id="def-1", rules=rules,
                commit_message="msg", ack_token="not-a-real-token"
            )

        # commit with mismatched rules
        with pytest.raises(AckTokenError):
            await specs["commit_mapping"].handler(
                c, definition_id="def-1",
                rules={"preprocess": [], "rules": [{"target": "y", "const": 2}]},
                commit_message="msg", ack_token=token
            )

        # commit with correct token + rules succeeds
        result = await specs["commit_mapping"].handler(
            c, definition_id="def-1", rules=rules,
            commit_message="msg", ack_token=token,
        )
        assert result["id"] == "v-1"

        # token cannot be reused
        with pytest.raises(AckTokenError):
            await specs["commit_mapping"].handler(
                c, definition_id="def-1", rules=rules,
                commit_message="msg again", ack_token=token,
            )
