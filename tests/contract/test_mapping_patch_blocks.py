"""Patch por BLOCO: ``preprocess`` e ``raw_reduction`` editáveis como ``rules``.

Antes, o único jeito de mudar um passo de ``preprocess`` era ``commit_mapping``
com o DSL inteiro — 188 regras reenviadas para trocar 1 de 7 passos, e o
operador reconstruindo o dict na mão, que é exatamente o gesto que apagou o
``raw_reduction`` do ``sophos.detection`` em produção.

Estes testes fixam quatro propriedades:

1. o bloco editado é o único que muda; os outros atravessam BYTE-IDÊNTICOS —
   o incidente, como regressão nomeada;
2. o assert de identidade segue o bloco (``expect_target`` → ``expect_path``)
   e ``expect_digest`` vale em qualquer um, sendo o único caminho para o
   ``drop_nulls`` global, que não tem ``path``;
3. o ack é ligado ao bloco: encenar ``preprocess`` e commitar ``rules`` falha;
4. o índice muda de forma por bloco, porque o que distingue os itens é outro.
"""

from __future__ import annotations

import json

import httpx
import pytest

from centralops_mcp.ack_cache import AckCache, AckTokenError
from centralops_mcp.tools import mapping as mapping_tools
from centralops_mcp.tools.mapping import PatchError, _apply_ops, _rule_digest

from .conftest import json_response


def _by_name(specs):
    return {s.name: s for s in specs}


PREPROCESS = [
    {"op": "json_parse", "source": "rawData", "target": "_raw"},
    {"op": "kv_parse", "source": "_raw.cmdline", "target": "_kv", "sep": " "},
    {"op": "json_parse", "source": "details", "target": "_details"},
]

RAW_REDUCTION = [
    {"path": "rawData.items", "max_items": 50},
    {"path": "rawData.blob", "max_bytes": 4096},
    {"drop_nulls": True},  # global: sem path — só endereçável por digest
]

RULES = [
    {"target": "normalized.class_uid", "const": 2004},
    {"target": "normalized.severity_id", "source": "_kv.sev", "default": 0},
]

VERSION_BODY = {
    "id": "v-9",
    "version_number": 9,
    "rules": {
        "preprocess": PREPROCESS,
        "rules": RULES,
        "raw_reduction": RAW_REDUCTION,
        # Bloco que o MCP não conhece: também tem de atravessar.
        "x_future_block": {"keep": "me"},
    },
}


def _handler(commits: list | None = None, dry_runs: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/mappings":
            return json_response([{
                "id": "d1", "vendor": "sophos", "event_type": "sophos.detection",
                "current_version_id": "v-9",
            }])
        if path == "/api/mappings/d1/versions/v-9":
            return json_response(VERSION_BODY)
        if path == "/api/mappings/dry-run":
            if dry_runs is not None:
                dry_runs.append(json.loads(request.content))
            return json_response({"sample_size": 3, "ok_count": 3, "fail_count": 0,
                                  "rule_failures": [], "output_examples": []})
        if path == "/api/mappings/d1/versions":
            body = json.loads(request.content)
            if commits is not None:
                commits.append(body)
            return json_response({"id": "v-10", "version_number": 10})
        return json_response({}, status=404)

    return handler


async def _stage_and_commit(make_client, ack_cache, *, block, ops, commit_block=None):
    """Encena e promove; devolve (resposta do patch, payload commitado)."""
    commits: list = []
    specs = _by_name(mapping_tools.specs(ack_cache))
    async with make_client(_handler(commits)) as c:
        staged = await specs["patch_mapping_rules"].handler(
            c, definition_id="d1", block=block, ops=ops, compare_baseline=False,
        )
        assert "error" not in staged, staged
        await specs["commit_mapping_patch"].handler(
            c, definition_id="d1", block=commit_block or block, ops=ops,
            commit_message="teste", ack_token=staged["ack_token"],
        )
    assert len(commits) == 1
    return staged, commits[0]


class TestBlocosNaoTocadosAtravessam:
    """O incidente do sophos.detection, como regressão."""

    @pytest.mark.asyncio
    async def test_patch_em_preprocess_nao_toca_rules_nem_raw_reduction(
        self, make_client, ack_cache: AckCache
    ):
        staged, committed = await _stage_and_commit(
            make_client, ack_cache, block="preprocess",
            ops=[{"op": "replace", "index": 1, "expect_target": "_kv",
                  "item": {"op": "kv_parse", "source": "_raw.cmdline",
                           "target": "_kv", "sep": "="}}],
        )
        dsl = committed["rules"]
        # Byte-idênticos: comparação canônica, não "parecido".
        canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"))  # noqa: E731
        assert canon(dsl["rules"]) == canon(RULES)
        assert canon(dsl["raw_reduction"]) == canon(RAW_REDUCTION)
        assert canon(dsl["x_future_block"]) == canon({"keep": "me"})
        assert dsl["preprocess"][1]["sep"] == "="
        assert dsl["preprocess"][0] == PREPROCESS[0] and dsl["preprocess"][2] == PREPROCESS[2]
        # E a resposta do patch PROVA que atravessaram, sem carregar o corpo.
        assert staged["block"] == "preprocess"
        assert staged["untouched_blocks"] == {"rules": 2, "raw_reduction": 3}
        assert "rules_count_before" not in staged, "nome histórico só no bloco rules"

    @pytest.mark.asyncio
    async def test_patch_em_raw_reduction_nao_toca_os_outros(
        self, make_client, ack_cache: AckCache
    ):
        _, committed = await _stage_and_commit(
            make_client, ack_cache, block="raw_reduction",
            ops=[{"op": "replace", "index": 0, "expect_path": "rawData.items",
                  "item": {"path": "rawData.items", "max_items": 20}}],
        )
        dsl = committed["rules"]
        assert dsl["preprocess"] == PREPROCESS
        assert dsl["rules"] == RULES
        assert dsl["raw_reduction"][0]["max_items"] == 20
        assert dsl["raw_reduction"][2] == {"drop_nulls": True}

    @pytest.mark.asyncio
    async def test_bloco_rules_mantem_os_nomes_historicos(
        self, make_client, ack_cache: AckCache
    ):
        staged, committed = await _stage_and_commit(
            make_client, ack_cache, block="rules",
            ops=[{"op": "append", "rule": {"target": "normalized.x", "const": 1}}],
        )
        assert staged["rules_count_before"] == 2 and staged["rules_count_after"] == 3
        assert staged["count_before"] == 2 and staged["count_after"] == 3
        assert committed["rules"]["preprocess"] == PREPROCESS


class TestAssertDeIdentidadePorBloco:
    def test_preprocess_usa_expect_target(self):
        out, changes = _apply_ops(
            PREPROCESS,
            [{"op": "remove", "index": 2, "expect_target": "_details"}],
            "preprocess",
        )
        assert [p["target"] for p in out] == ["_raw", "_kv"]
        assert changes[0]["target"] == "_details"

    def test_raw_reduction_usa_expect_path_e_recusa_expect_target(self):
        with pytest.raises(PatchError, match="expect_path"):
            _apply_ops(
                RAW_REDUCTION,
                [{"op": "remove", "index": 0, "expect_target": "rawData.items"}],
                "raw_reduction",
            )
        out, changes = _apply_ops(
            RAW_REDUCTION,
            [{"op": "remove", "index": 0, "expect_path": "rawData.items"}],
            "raw_reduction",
        )
        assert out == RAW_REDUCTION[1:]
        assert changes[0]["path"] == "rawData.items"

    def test_expect_path_errado_e_stale(self):
        with pytest.raises(PatchError, match="stale_index"):
            _apply_ops(
                RAW_REDUCTION,
                [{"op": "remove", "index": 1, "expect_path": "rawData.items"}],
                "raw_reduction",
            )

    def test_drop_nulls_global_so_por_digest(self):
        """O item sem ``path`` não tem identidade nominal — só o digest serve."""
        with pytest.raises(PatchError, match="expect_path"):
            _apply_ops(
                RAW_REDUCTION,
                [{"op": "remove", "index": 2}],
                "raw_reduction",
            )
        out, _ = _apply_ops(
            RAW_REDUCTION,
            [{"op": "remove", "index": 2, "expect_digest": _rule_digest(RAW_REDUCTION[2])}],
            "raw_reduction",
        )
        assert out == RAW_REDUCTION[:2]

    def test_expect_digest_vale_em_qualquer_bloco_e_detecta_mudanca(self):
        digest = _rule_digest(RULES[1])
        out, _ = _apply_ops(
            RULES,
            [{"op": "replace", "index": 1, "expect_digest": digest,
              "rule": {"target": "normalized.severity_id", "const": 3}}],
        )
        assert out[1]["const"] == 3
        # Mesmo target, corpo diferente: expect_target passaria, o digest não.
        with pytest.raises(PatchError, match="digest"):
            _apply_ops(
                RULES,
                [{"op": "remove", "index": 1,
                  "expect_target": "normalized.severity_id",
                  "expect_digest": "000000000000"}],
            )

    def test_item_e_alias_de_rule(self):
        out, _ = _apply_ops(
            PREPROCESS,
            [{"op": "append", "item": {"op": "json_parse", "source": "z", "target": "_z"}}],
            "preprocess",
        )
        assert out[-1]["target"] == "_z"

    def test_bloco_desconhecido_e_recusado_antes_de_qualquer_coisa(self):
        with pytest.raises(PatchError, match="block inválido"):
            _apply_ops(RULES, [], "rulez")


class TestAckLigadoAoBloco:
    @pytest.mark.asyncio
    async def test_encenar_preprocess_e_commitar_rules_falha(
        self, make_client, ack_cache: AckCache
    ):
        """Mesmos ops, bloco diferente: o operador confirmou uma coisa e
        commitaria outra. O digest inclui o bloco justamente para isto."""
        commits: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        ops = [{"op": "remove", "index": 0, "expect_target": "_raw"}]
        async with make_client(_handler(commits)) as c:
            staged = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", block="preprocess", ops=ops, compare_baseline=False,
            )
            with pytest.raises(AckTokenError):
                await specs["commit_mapping_patch"].handler(
                    c, definition_id="d1", block="rules", ops=ops,
                    commit_message="x", ack_token=staged["ack_token"],
                )
        assert commits == [], "nada pode ter chegado ao backend"

    @pytest.mark.asyncio
    async def test_bloco_invalido_no_patch_e_no_commit_sao_erros_locais(
        self, make_client, ack_cache: AckCache
    ):
        commits: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler(commits)) as c:
            out = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", block="rulez", ops=[{"op": "append", "rule": {}}],
            )
            assert "block inválido" in out["error"]
            out = await specs["commit_mapping_patch"].handler(
                c, definition_id="d1", block="rulez", ops=[], commit_message="x",
                ack_token="tok",
            )
            assert "block inválido" in out["error"]
        assert commits == []

    @pytest.mark.asyncio
    async def test_dry_run_recebe_o_dsl_com_o_bloco_editado(
        self, make_client, ack_cache: AckCache
    ):
        """O dry-run compila preprocess no backend — a validação real mora lá."""
        dry_runs: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler(dry_runs=dry_runs)) as c:
            await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", block="preprocess", compare_baseline=False,
                ops=[{"op": "remove", "index": 0, "expect_target": "_raw"}],
            )
        assert len(dry_runs) == 1
        sent = dry_runs[0]["rules"]
        assert [p["target"] for p in sent["preprocess"]] == ["_kv", "_details"]
        assert sent["rules"] == RULES and sent["raw_reduction"] == RAW_REDUCTION


class TestIndicePorBloco:
    @pytest.mark.asyncio
    async def test_preprocess_indexa_por_op_e_source(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(
                c, definition_id="d1", block="preprocess",
            )
        assert out["total"] == 3
        assert out["targets"][1] == {"i": 1, "t": "_kv", "op": "kv_parse", "src": "_raw.cmdline"}
        assert "f" not in out["targets"][0], "flags de regra não fazem sentido aqui"

    @pytest.mark.asyncio
    async def test_contains_casa_no_op_do_preprocess(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(
                c, definition_id="d1", block="preprocess", contains="kv_parse",
            )
        assert [e["i"] for e in out["targets"]] == [1]

    @pytest.mark.asyncio
    async def test_raw_reduction_indexa_por_path_e_o_global_traz_digest(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(
                c, definition_id="d1", block="raw_reduction",
            )
        assert out["targets"][0] == {"i": 0, "t": "rawData.items", "f": "i"}
        assert out["targets"][1] == {"i": 1, "t": "rawData.blob", "f": "b"}
        glob = out["targets"][2]
        assert glob["t"] is None and glob["f"] == "n"
        # O digest do índice é o mesmo que o patch confere — é o contrato.
        assert glob["digest"] == _rule_digest(RAW_REDUCTION[2])
        assert out["duplicate_targets"] == []

    @pytest.mark.asyncio
    async def test_digest_do_indice_bate_com_o_de_get_mapping_rules(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            fatia = await specs["get_mapping_rules"].handler(
                c, definition_id="d1", version_id="v-9", block="raw_reduction", indexes=[2],
            )
        assert fatia["items"][0]["rule_sha256_12"] == _rule_digest(RAW_REDUCTION[2])
