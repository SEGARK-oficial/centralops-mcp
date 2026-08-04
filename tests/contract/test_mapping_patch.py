"""Edição incremental de mappings grandes.

Um mapping maduro tem 150-193 regras (~30 KB em JSON). O fluxo antigo obrigava a
materializar o array inteiro no contexto para trocar UMA regra — e ainda a
relê-lo do `get_mapping`, que devolvia todas as versões com corpo integral.

Estes testes fixam as três propriedades que tornam a edição viável:
índice barato, leitura por fatia, e patch que nunca devolve o array merged.
"""

from __future__ import annotations

import httpx
import pytest

from centralops_mcp.ack_cache import AckCache, AckTokenError
from centralops_mcp.tools import mapping as mapping_tools
from centralops_mcp.tools.mapping import PatchError, _apply_ops

from .conftest import json_response


def _by_name(specs):
    return {s.name: s for s in specs}


#: Mapping realista: mesmo target repetido sob `when` diferentes, que é o caso
#: em que endereçar por target daria a regra errada.
BASE_RULES = [
    {"target": "normalized.class_uid", "const": 2004},
    {"target": "normalized.severity_id", "source": "severity",
     "value_map": {"9": 6, "10": 6}, "default": 0},
    {"target": "normalized.process.file.hashes", "source": "a", "when": {"equals": {"x": 1}}},
    {"target": "normalized.process.file.hashes", "source": "b", "when": {"equals": {"x": 2}}},
    {"target": "normalized.device.uid", "source": "endpoint_id"},
]

VERSION_BODY = {
    "id": "v-1",
    "version_number": 7,
    "commit_message": "estado atual",
    "rules": {
        "preprocess": [{"op": "json_parse", "path": "raw"}],
        "rules": BASE_RULES,
        "raw_reduction": [{"path": "big", "max_bytes": 1024}],
    },
    "ocsf_validation_stats": {"checked": 5, "valid": 5},
}


def _handler(dry_run_bodies: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/mappings":
            return json_response([{
                "id": "d1", "vendor": "wazuh", "event_type": "wazuh.detection",
                "current_version_id": "v-1",
            }])
        if path == "/api/mappings/d1/versions/v-1":
            return json_response(VERSION_BODY)
        if path == "/api/mappings/dry-run":
            if dry_run_bodies is not None:
                import json as _json
                dry_run_bodies.append(_json.loads(request.content))
            return json_response({"sample_size": 10, "ok_count": 10, "fail_count": 0,
                                  "rule_failures": [], "output_examples": [{"a": 1}]})
        if path == "/api/mappings/d1/versions":
            import json as _json
            return json_response({"committed": _json.loads(request.content)})
        return json_response({}, status=404)

    return handler


class TestIndiceEFatia:
    @pytest.mark.asyncio
    async def test_indice_nao_traz_corpo_de_regra(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(c, definition_id="d1")

        assert out["total"] == 5
        assert out["blocks"] == {"rules": 5, "preprocess": 1, "raw_reduction": 1}
        for entry in out["targets"]:
            assert "rule" not in entry, "o índice não pode carregar o corpo"
            assert "value_map" not in entry, "nem pedaços dele"
            assert "i" in entry and "t" in entry

    def test_fluxo_incremental_custa_muito_menos_que_ler_e_reenviar(self):
        """A propriedade que justifica as tools, medida ponta a ponta.

        O ganho decisivo não é o índice isolado (regras reais são curtas, então
        indexá-las nunca vai custar uma fração desprezível do array): é NUNCA
        reenviar o array para commitar. O fluxo antigo paga o array duas vezes —
        uma para ler, outra para commitar.

        Calibrado contra um mapping realista: targets longos, `when` em parte
        das regras, alguns targets repetidos.
        """
        import json as _json
        from centralops_mcp.tools.mapping import _duplicate_targets, _index_entry

        # Calibrado como os mappings de produção: a grande maioria dos targets é
        # única, com um punhado repetido sob `when` diferentes.
        rules = []
        for i in range(153):
            target = (
                "normalized.process.file.hashes"
                if i % 20 == 0
                else f"normalized.process.file.attr_{i}"
            )
            rule = {"target": target, "source": f"rawData.items.value_{i}"}
            if i % 3 == 0:
                rule["when"] = {"equals": {"type": f"t{i}"}}
            if i % 5 == 0:
                rule["value_map"] = {str(k): k for k in range(6)}
            rules.append(rule)

        dups = _duplicate_targets(rules)
        integral = len(_json.dumps({"rules": rules}, separators=(",", ":")))
        entries = [_index_entry(i, r, dups) for i, r in enumerate(rules)]
        indice_todo = len(_json.dumps(entries, separators=(",", ":")))
        # É assim que o agente usa: filtra em vez de baixar o índice inteiro.
        filtrado = len(_json.dumps(
            [e for e in entries if "attr_47" in str(e.get("t"))], separators=(",", ":")
        ))
        uma_regra = len(_json.dumps(rules[47], separators=(",", ":")))
        novo = filtrado + uma_regra * 2 + 400
        antigo = integral * 2  # ler o array e reenviá-lo no commit

        assert novo < antigo / 10, (
            f"fluxo incremental com filtro ({novo} B) precisa custar uma fração "
            f"de ler+reenviar ({antigo} B)"
        )
        assert indice_todo < integral, "mesmo sem filtro, o índice é menor que o array"

    @pytest.mark.asyncio
    async def test_indice_sinaliza_target_ambiguo(self, make_client, ack_cache: AckCache):
        """Target repetido é legítimo e comum — e endereçar por ele é o erro."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(c, definition_id="d1")

        assert out["duplicate_targets"] == ["normalized.process.file.hashes"]
        ambiguos = [t["i"] for t in out["targets"] if t.get("ambiguous")]
        assert ambiguos == [2, 3]
        # `when` só aparece nas ambíguas — e é o que as distingue.
        assert out["targets"][2]["when"] != out["targets"][3]["when"]
        assert "when" not in out["targets"][0], "when é peso morto fora das ambíguas"

    @pytest.mark.asyncio
    async def test_flags_compactam_os_booleanos(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(c, definition_id="d1")

        assert out["targets"][0]["f"] == "c"        # const
        assert "m" in out["targets"][1]["f"]         # value_map
        assert "d" in out["targets"][1]["f"]         # default
        assert "f" not in out["targets"][4]          # nenhum: campo some

    @pytest.mark.asyncio
    async def test_contains_reduz_o_indice_ao_que_interessa(
        self, make_client, ack_cache: AckCache
    ):
        """O filtro é o que torna o índice utilizável em mapping grande."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(
                c, definition_id="d1", contains="severity"
            )

        assert out["total"] == 5, "total continua sendo o do mapping inteiro"
        assert out["matched"] == 1
        assert out["targets"][0]["t"] == "normalized.severity_id"
        # o índice preservado é o ABSOLUTO, não a posição no resultado filtrado
        assert out["targets"][0]["i"] == 1

    @pytest.mark.asyncio
    async def test_contains_sem_resultado_orienta(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["list_mapping_rule_targets"].handler(
                c, definition_id="d1", contains="nao-existe"
            )
        assert out["matched"] == 0
        assert "hint" in out

    @pytest.mark.asyncio
    async def test_fatia_por_indice(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["get_mapping_rules"].handler(
                c, definition_id="d1", version_id="v-1", indexes=[1]
            )

        assert out["returned"] == 1
        assert out["items"][0]["index"] == 1
        assert out["items"][0]["rule"]["value_map"] == {"9": 6, "10": 6}
        assert out["stale"] is False

    @pytest.mark.asyncio
    async def test_fatia_por_target_devolve_todas_as_ocorrencias(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["get_mapping_rules"].handler(
                c, definition_id="d1", version_id="v-1",
                targets=["normalized.process.file.hashes"],
            )
        assert [i["index"] for i in out["items"]] == [2, 3]


class TestApplyOps:
    """Resolução em LOTE: índices são sempre do array base, nunca deslizam."""

    def test_replace_preserva_posicao(self):
        out, changes = _apply_ops(
            BASE_RULES,
            [{"op": "replace", "index": 1, "expect_target": "normalized.severity_id",
              "rule": {"target": "normalized.severity_id", "value_map": {"9": 5}}}],
        )
        assert len(out) == 5
        assert out[1]["value_map"] == {"9": 5}
        assert changes[0]["op"] == "replace"

    def test_remove_e_insert_no_mesmo_lote_usam_indices_da_base(self):
        out, _ = _apply_ops(
            BASE_RULES,
            [
                {"op": "remove", "index": 0, "expect_target": "normalized.class_uid"},
                {"op": "insert", "index": 4, "rule": {"target": "novo"}},
            ],
        )
        # remove(0) NÃO desloca o insert(4): ambos endereçam a base original.
        assert [r.get("target") for r in out] == [
            "normalized.severity_id",
            "normalized.process.file.hashes",
            "normalized.process.file.hashes",
            "novo",
            "normalized.device.uid",
        ]

    def test_expect_target_errado_falha_em_vez_de_corromper(self):
        with pytest.raises(PatchError, match="stale_index"):
            _apply_ops(
                BASE_RULES,
                [{"op": "replace", "index": 1, "expect_target": "normalized.device.uid",
                  "rule": {"target": "x"}}],
            )

    def test_expect_target_ausente_e_recusado(self):
        with pytest.raises(PatchError, match="expect_target"):
            _apply_ops(BASE_RULES, [{"op": "remove", "index": 1}])

    def test_dois_ops_no_mesmo_indice_e_conflito(self):
        with pytest.raises(PatchError, match="conflicting_ops"):
            _apply_ops(
                BASE_RULES,
                [
                    {"op": "replace", "index": 1, "expect_target": "normalized.severity_id",
                     "rule": {"target": "a"}},
                    {"op": "remove", "index": 1, "expect_target": "normalized.severity_id"},
                ],
            )

    def test_indice_fora_da_faixa(self):
        with pytest.raises(PatchError, match="fora da faixa"):
            _apply_ops(BASE_RULES, [{"op": "remove", "index": 99, "expect_target": "x"}])


class TestPatchFlow:
    @pytest.mark.asyncio
    async def test_patch_nao_devolve_o_array_merged(self, make_client, ack_cache: AckCache):
        """O ponto inteiro: o agente vê o que mudou, nunca as 193 regras."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1",
                ops=[{"op": "replace", "index": 1,
                      "expect_target": "normalized.severity_id",
                      "rule": {"target": "normalized.severity_id",
                               "value_map": {"9": 5, "10": 5}}}],
            )

        assert out["rules_count_before"] == 5
        assert out["rules_count_after"] == 5
        assert len(out["changes"]) == 1
        assert out["changes"][0]["before"]["value_map"] == {"9": 6, "10": 6}
        assert out["changes"][0]["after"]["value_map"] == {"9": 5, "10": 5}
        assert out["ack_token"]
        # nenhuma chave carrega o array inteiro
        assert "rules" not in out and "merged" not in out

    @pytest.mark.asyncio
    async def test_patch_preserva_blocos_nao_tocados(self, make_client, ack_cache: AckCache):
        """raw_reduction/preprocess sobrevivem — apagá-los já quebrou produção."""
        bodies: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler(bodies)) as c:
            await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", compare_baseline=False,
                ops=[{"op": "append", "rule": {"target": "novo", "const": 1}}],
            )

        enviado = bodies[0]["rules"]
        assert enviado["raw_reduction"] == [{"path": "big", "max_bytes": 1024}]
        assert enviado["preprocess"] == [{"op": "json_parse", "path": "raw"}]
        assert len(enviado["rules"]) == 6

    @pytest.mark.asyncio
    async def test_compara_com_a_base_por_padrao(self, make_client, ack_cache: AckCache):
        bodies: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler(bodies)) as c:
            out = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1",
                ops=[{"op": "append", "rule": {"target": "novo"}}],
            )
        assert len(bodies) == 2, "deve rodar dry-run do patch E da base"
        assert out["dry_run_baseline"] is not None

    @pytest.mark.asyncio
    async def test_commit_envia_as_regras_staged_e_a_base_version(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        ops = [{"op": "remove", "index": 4, "expect_target": "normalized.device.uid"}]
        async with make_client(_handler()) as c:
            patch = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", ops=ops, compare_baseline=False
            )
            res = await specs["commit_mapping_patch"].handler(
                c, definition_id="d1", ops=ops,
                commit_message="remove device.uid", ack_token=patch["ack_token"],
            )

        enviado = res["committed"]
        assert len(enviado["rules"]["rules"]) == 4, "o merge staged foi enviado"
        assert enviado["base_version_id"] == "v-1", (
            "sem base_version_id o backend não consegue recusar um lost update"
        )

    @pytest.mark.asyncio
    async def test_token_nao_serve_para_outros_ops(self, make_client, ack_cache: AckCache):
        specs = _by_name(mapping_tools.specs(ack_cache))
        ops = [{"op": "append", "rule": {"target": "a"}}]
        async with make_client(_handler()) as c:
            patch = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", ops=ops, compare_baseline=False
            )
            with pytest.raises(AckTokenError, match="ops differ"):
                await specs["commit_mapping_patch"].handler(
                    c, definition_id="d1",
                    ops=[{"op": "append", "rule": {"target": "OUTRO"}}],
                    commit_message="x", ack_token=patch["ack_token"],
                )

    @pytest.mark.asyncio
    async def test_token_de_patch_nao_serve_no_commit_antigo(
        self, make_client, ack_cache: AckCache
    ):
        """Os dois fluxos não se misturam."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            patch = await specs["patch_mapping_rules"].handler(
                c, definition_id="d1", compare_baseline=False,
                ops=[{"op": "append", "rule": {"target": "a"}}],
            )
            with pytest.raises(AckTokenError, match="patch_mapping_rules"):
                await specs["commit_mapping"].handler(
                    c, definition_id="d1", rules={"rules": []},
                    commit_message="x", ack_token=patch["ack_token"],
                )


class TestDryRunBaseline:
    @pytest.mark.asyncio
    async def test_baseline_roda_as_regras_vigentes_sem_receber_rules(
        self, make_client, ack_cache: AckCache
    ):
        bodies: list = []
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler(bodies)) as c:
            out = await specs["dry_run_mapping"].handler(c, definition_id="d1")

        assert out["mode"] == "baseline"
        assert out["base_version_id"] == "v-1"
        assert bodies[0]["rules"]["rules"] == BASE_RULES
        assert bodies[0]["vendor"] == "wazuh"

    @pytest.mark.asyncio
    async def test_baseline_nunca_emite_ack_token(self, make_client, ack_cache: AckCache):
        """Baseline mede; não autoriza. O agente não enumerou regra nenhuma."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["dry_run_mapping"].handler(c, definition_id="d1")
        assert out["ack_token"] is None

    @pytest.mark.asyncio
    async def test_modo_proposed_segue_emitindo_token(self, make_client, ack_cache: AckCache):
        """Compatibilidade: o fluxo antigo não pode ficar inalcançável."""
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["dry_run_mapping"].handler(
                c, definition_id="d1", rules={"rules": []}
            )
        assert out["mode"] == "proposed"
        assert out["ack_token"]

    @pytest.mark.asyncio
    async def test_sem_rules_e_sem_definition_id_da_erro_acionavel(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            out = await specs["dry_run_mapping"].handler(c)
        assert "error" in out

    @pytest.mark.asyncio
    async def test_sumario_por_padrao_envelopes_sob_pedido(
        self, make_client, ack_cache: AckCache
    ):
        specs = _by_name(mapping_tools.specs(ack_cache))
        async with make_client(_handler()) as c:
            curto = await specs["dry_run_mapping"].handler(c, definition_id="d1")
            longo = await specs["dry_run_mapping"].handler(
                c, definition_id="d1", verbose=True
            )
        assert curto["dry_run"]["output_examples_omitted"] == 1
        assert "output_examples" not in curto["dry_run"]
        assert longo["dry_run"]["output_examples"] == [{"a": 1}]
