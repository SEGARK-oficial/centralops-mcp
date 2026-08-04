from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from centralops_mcp.ack_cache import AckCache, _fingerprint
from centralops_mcp.tools._base import (
    CentralOpsClient,
    ToolSpec,
    _integer,
    _object,
    _string,
)


# ── helpers de projeção ───────────────────────────────────────────────
#
# A razão de existirem: um mapping maduro tem 150-193 regras (~30 KB em JSON
# indentado). Materializar isso no contexto para trocar UMA regra é o gargalo
# que estas tools resolvem. Tudo aqui existe para que o array integral trafegue
# no fio e viva na memória deste processo, sem nunca entrar na conversa.

_DEFAULT_BLOCK = "rules"
_BLOCKS = ("rules", "preprocess", "raw_reduction")


async def _resolve_definition(client: CentralOpsClient, definition_id: str) -> dict[str, Any]:
    """Cabeçalho da definição, sem tocar no corpo das regras.

    Usa ``include_rules_count=false`` de propósito: com ``true`` o backend faz
    json.loads do blob de regras de TODO o catálogo só para contar.
    """
    catalog = await client.get("/mappings", params={"include_rules_count": "false"})
    items = catalog if isinstance(catalog, list) else (catalog or {}).get("items") or []
    for item in items:
        if str(item.get("id")) == str(definition_id):
            return item
    raise ValueError(
        f"definition_id {definition_id!r} não encontrado no catálogo. "
        f"Use list_mappings para descobrir o id correto."
    )


async def _fetch_version(
    client: CentralOpsClient, definition_id: str, version_id: str
) -> dict[str, Any]:
    return await client.get(f"/mappings/{definition_id}/versions/{version_id}")


def _dsl_blocks(version: dict[str, Any]) -> dict[str, Any]:
    """Só o bloco DSL v2, nunca as estatísticas.

    ``dry_run_stats`` carrega eventos NORMALIZADOS reais da organização de quem
    fez o commit, e mappings não têm coluna de org — repassá-lo cru seria
    vazamento cross-tenant por leitura.
    """
    rules = version.get("rules")
    return rules if isinstance(rules, dict) else {"rules": rules or []}


def _block_list(dsl: dict[str, Any], block: str) -> list:
    value = dsl.get(block)
    return value if isinstance(value, list) else []


def _rule_digest(rule: Any) -> str:
    """12 hex de sha256. É PRECONDIÇÃO de edição, não identidade criptográfica."""
    return _fingerprint(rule)[:12]


def _when_summary(rule: Any) -> Optional[str]:
    if not isinstance(rule, dict) or "when" not in rule:
        return None
    text = json.dumps(rule["when"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text if len(text) <= 120 else text[:117] + "..."


def _index_entry(idx: int, rule: Any, dup_targets: set[str]) -> dict[str, Any]:
    """Uma linha por regra, o mais enxuta possível.

    O índice só vale a pena se for MUITO menor que o array: emitir dez campos
    por regra faria dele quase uma cópia (medido: 66 KB contra 70 KB do array
    integral, ou seja, ganho nenhum). Por isso só sai o que é falso-por-omissão:
    chaves ausentes significam "não tem", e ``flags`` compacta num único campo o
    que antes eram cinco booleanos.
    """
    if not isinstance(rule, dict):
        return {"i": idx}
    target = rule.get("target")
    # Só índice e target. Regras reais são curtas ("target" + "source"), então
    # qualquer campo extra faz o índice custar quase o mesmo que o array —
    # medido em três mappings de produção: 92%, 93% e 100%. O digest saiu porque
    # ``expect_target`` já é a precondição de edição, e ``source`` porque
    # duplica o corpo que ``get_mapping_rules`` entrega sob demanda.
    entry: dict[str, Any] = {"i": idx, "t": target}

    # Uma string de flags em vez de N booleanos: "cdmwr" = const, default,
    # value_map, when, required. Ausente quando a regra não tem nenhum.
    flags = "".join(
        letter
        for letter, present in (
            ("c", "const" in rule),
            ("d", "default" in rule),
            ("m", "value_map" in rule),
            ("w", "when" in rule),
            ("r", bool(rule.get("required"))),
        )
        if present
    )
    if flags:
        entry["f"] = flags
    if rule.get("kind"):
        entry["kind"] = rule["kind"]
    # ``when_summary`` só onde ele decide algo: quando o target se repete, é a
    # única coisa que distingue as regras entre si. Nas demais, é peso morto.
    if isinstance(target, str) and target in dup_targets:
        entry["ambiguous"] = True
        summary = _when_summary(rule)
        if summary:
            entry["when"] = summary
        # Só aqui o source paga por si: é o que deixa escolher entre duplicatas
        # sem baixar as duas.
        if rule.get("source"):
            entry["src"] = rule["source"]
    return entry


def _duplicate_targets(rules: list) -> set[str]:
    seen: dict[str, int] = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("target"), str):
            seen[rule["target"]] = seen.get(rule["target"], 0) + 1
    return {target for target, count in seen.items() if count > 1}


def _summarize_dry_run(dry_run: Any, verbose: bool) -> dict[str, Any]:
    """Sumário por padrão; envelopes completos só sob pedido."""
    if not isinstance(dry_run, dict):
        return {"raw": dry_run}
    keep = (
        "sample_size", "ok_count", "fail_count", "rule_failures",
        "default_hit_warnings", "mapped_field_ratio", "warnings",
    )
    out: dict[str, Any] = {k: dry_run[k] for k in keep if k in dry_run}
    examples = dry_run.get("output_examples")
    if verbose or not examples:
        # Lista vazia não tem o que omitir — passa adiante para não sumir com um
        # campo que o chamador espera encontrar.
        if examples is not None:
            out["output_examples"] = examples
    else:
        out["output_examples_omitted"] = len(examples)
        out["output_examples_hint"] = "verbose=true devolve os envelopes completos"
    return out


def _patch_digest(definition_id: str, base_version_id: Optional[str], ops: Any) -> str:
    canonical = json.dumps(
        {"definition_id": definition_id, "base_version_id": base_version_id, "ops": ops},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PatchError(ValueError):
    """Patch recusado antes de qualquer chamada ao backend."""


def _apply_ops(base: list, ops: list) -> tuple[list, list[dict[str, Any]]]:
    """Aplica os ops ao array base. Índices são SEMPRE do array base original.

    Resolução em lote, nunca sequencial: aplicar um op de cada vez faria os
    índices seguintes deslizarem e o agente teria de simular a aritmética de
    posição — exatamente o que estas tools existem para evitar.
    """
    replaced: dict[int, Any] = {}
    removed: set[int] = set()
    inserts: dict[int, list] = {}
    appends: list = []
    changes: list[dict[str, Any]] = []

    def _check_index(op: dict, idx: Any) -> int:
        if not isinstance(idx, int) or not (0 <= idx < len(base)):
            raise PatchError(
                f"op {op.get('op')!r}: index {idx!r} fora da faixa 0..{len(base) - 1}. "
                f"Rode list_mapping_rule_targets para reindexar."
            )
        return idx

    def _check_target(op: dict, idx: int) -> None:
        expected = op.get("expect_target")
        if expected is None:
            raise PatchError(
                f"op {op.get('op')!r} no index {idx}: 'expect_target' é obrigatório. "
                f"Ele é o assert que impede editar a regra errada quando o índice envelhece."
            )
        actual = base[idx].get("target") if isinstance(base[idx], dict) else None
        if actual != expected:
            raise PatchError(
                f"patch.stale_index: index {idx} tem target {actual!r}, não {expected!r}. "
                f"O mapping mudou desde a leitura — reindexe com list_mapping_rule_targets."
            )

    for op in ops:
        if not isinstance(op, dict):
            raise PatchError(f"op inválido (esperado objeto): {op!r}")
        kind = op.get("op")
        if kind in ("replace", "remove"):
            idx = _check_index(op, op.get("index"))
            _check_target(op, idx)
            if idx in replaced or idx in removed:
                raise PatchError(
                    f"patch.conflicting_ops: mais de um op muta o index {idx}."
                )
            if kind == "replace":
                if not isinstance(op.get("rule"), dict):
                    raise PatchError("op 'replace' exige 'rule' (objeto).")
                replaced[idx] = op["rule"]
                changes.append({"op": "replace", "index": idx,
                                "target": op.get("expect_target"),
                                "before": base[idx], "after": op["rule"]})
            else:
                removed.add(idx)
                changes.append({"op": "remove", "index": idx,
                                "target": op.get("expect_target"), "before": base[idx]})
        elif kind == "insert":
            idx = op.get("index")
            if not isinstance(idx, int) or not (0 <= idx <= len(base)):
                raise PatchError(
                    f"op 'insert': index {idx!r} fora da faixa 0..{len(base)}."
                )
            if not isinstance(op.get("rule"), dict):
                raise PatchError("op 'insert' exige 'rule' (objeto).")
            inserts.setdefault(idx, []).append(op["rule"])
            changes.append({"op": "insert", "index": idx, "after": op["rule"]})
        elif kind == "append":
            if not isinstance(op.get("rule"), dict):
                raise PatchError("op 'append' exige 'rule' (objeto).")
            appends.append(op["rule"])
            changes.append({"op": "append", "after": op["rule"]})
        else:
            raise PatchError(
                f"op desconhecido: {kind!r}. Use replace, remove, insert ou append."
            )

    out: list = []
    for i, rule in enumerate(base):
        out.extend(inserts.get(i, ()))
        if i in removed:
            continue
        out.append(replaced.get(i, rule))
    out.extend(inserts.get(len(base), ()))
    out.extend(appends)
    return out, changes


#: The `source` grammar is the single most under-documented part of the DSL: the
#: engine compiles it with `jmespath.compile()` and applies NO allow-list, so the
#: full JMESPath language is available — but nothing told an agent that, so
#: generated rules stayed at trivial dot-paths and gave up on messy vendor data.
_SOURCE_GRAMMAR = (
    "`source` is a FULL JMESPath expression, not just a field path. The engine "
    "compiles it with jmespath.compile() and applies no allow-list, so every "
    "JMESPath construct works:\n"
    "  - dot-path: `severity`, `device.name`  <- prefer these, see performance note\n"
    "  - or-fallback: `createdAt || raisedAt`\n"
    "  - filters, to skip vendor placeholder values: "
    "`[data.win.eventdata.param2][?@!='-']|[0]` (Windows sends '-' for empty)\n"
    "  - functions: `to_number(data.win.eventdata.ipPort)`, `length(items)`, "
    "`sort_by(...)`, `join(...)`, `keys(...)`\n"
    "  - combined: "
    "`([data.win.eventdata.subStatus][?@!='0x0']|[0]) || data.win.eventdata.status`\n"
    "CENTRALOPS-SPECIFIC: a `source` starting with `_` does NOT read the raw "
    "event — it reads the `extracted` dict produced by `preprocess`. This is a "
    "CentralOps convention, not JMESPath.\n"
    "PERFORMANCE: only plain ASCII dot-paths (`^[A-Za-z_][A-Za-z0-9_]*(\\.…)*$`) "
    "use the fast resolver. Any filter, pipe or function falls back to the "
    "JMESPath visitor, which profiling measured at 64% of cumulative normalize "
    "time on a large mapping. Use the expressive forms where they earn it (a "
    "placeholder filter that a dot-path cannot express), not by habit."
)

_RULES_SCHEMA = {
    "type": "object",
    "description": (
        "DSL v2 mapping rules. Shape: {preprocess?: array, rules: array}.\n\n"
        "Each rule needs a 'target' (dotted path into the output envelope, e.g. "
        "'normalized.severity_id') and exactly ONE value source: 'source' "
        "(JMESPath), 'const' (literal), or 'kind: array_builder'. Setting both "
        "'source' and 'const' is rejected at validation time.\n\n"
        "Optional per-rule keys, applied in this order: 'default' (used when the "
        "source resolves empty — note it BYPASSES pre_cast and value_map, and "
        "only type_cast is applied to it), 'pre_cast' (normalize before lookup, "
        "e.g. 'lowercase', 'to_str'), 'value_map' (dict translating vendor values "
        "to OCSF enums), 'type_cast' (final coercion), 'fallback_source' "
        "(alternative JMESPath list), 'required' (bool).\n\n" + _SOURCE_GRAMMAR
    ),
    "properties": {
        "preprocess": {
            "type": "array",
            "items": {"type": "object"},
            "description": (
                "Optional pre-extraction steps that populate the `extracted` "
                "dict, referenced by rules whose `source` starts with `_`. Use "
                "for parsing embedded JSON/CSV blobs before mapping them."
            ),
        },
        "rules": {"type": "array", "items": {"type": "object"}},
    },
    "required": ["rules"],
}


async def _list_mappings(
    client: CentralOpsClient,
    *,
    include_rules_count: bool = True,
    only_active: bool = False,
) -> Any:
    return await client.get(
        "/mappings",
        params={
            "include_rules_count": "true" if include_rules_count else "false",
            "only_active": "true" if only_active else "false",
        },
    )


async def _get_mapping(
    client: CentralOpsClient,
    *,
    definition_id: str,
    include_versions: str = "none",
    include_current_rules: bool = True,
) -> Any:
    """Definição + as regras VIGENTES, sem arrastar o histórico.

    O caminho padrão nunca chama ``GET /mappings/{id}`` (que devolve todas as
    versões com corpo integral): resolve a versão corrente pelo ponteiro
    ``current_version_id`` e busca só ela.
    """
    if include_versions == "full":
        return await client.get(f"/mappings/{definition_id}")

    defn = await _resolve_definition(client, definition_id)
    current_id = defn.get("current_version_id")

    payload: dict[str, Any] = {
        "definition": {
            k: defn.get(k)
            for k in ("id", "vendor", "event_type", "ocsf_class_uid",
                      "description", "current_version_id")
        },
        # Distingue "resolvido pelo ponteiro" de "não há versão": a UI e o
        # rollback movem o ponteiro sem criar versão, então escolher pela
        # numeração mais alta daria a versão ERRADA.
        "current_version_resolved": "pointer" if current_id else "none",
        "current_version": None,
        "current_rules": None,
        "versions": [],
    }
    if not current_id:
        payload["hint"] = (
            "definição sem current_version_id: nenhuma regra está em vigor "
            "(o pipeline manda tudo para quarentena com missing_mapping)."
        )
        return payload

    version = await _fetch_version(client, definition_id, current_id)
    dsl = _dsl_blocks(version)
    rules = _block_list(dsl, "rules")
    payload["current_version"] = {
        "id": version.get("id"),
        "version_number": version.get("version_number"),
        "commit_message": version.get("commit_message"),
        "created_at": version.get("created_at"),
        "author_label": version.get("author_label"),
        "rules_count": len(rules),
        "rules_fingerprint": _fingerprint(dsl),
        # Mantido SEMPRE: é a única janela para "a versão em produção emite
        # OCSF válido?" — dry_run_mapping não mede isso.
        "ocsf_validation_stats": version.get("ocsf_validation_stats"),
    }
    if include_current_rules:
        payload["current_rules"] = dsl
    if include_versions == "meta":
        history = await client.get(f"/mappings/{definition_id}/versions")
        items = history if isinstance(history, list) else (history or {}).get("items") or []
        payload["versions"] = [
            {k: v.get(k) for k in ("id", "version_number", "commit_message",
                                   "created_at", "author_label")}
            for v in items
        ]
        payload["versions_count"] = len(items)
    return payload


async def _get_mapping_version(
    client: CentralOpsClient,
    *,
    definition_id: str,
    version_id: str | None = None,
) -> Any:
    if not version_id:
        defn = await _resolve_definition(client, definition_id)
        version_id = defn.get("current_version_id")
        if not version_id:
            return {"error": "definição sem current_version_id", "definition_id": definition_id}
        is_current = True
    else:
        defn = await _resolve_definition(client, definition_id)
        is_current = str(defn.get("current_version_id")) == str(version_id)

    version = await _fetch_version(client, definition_id, version_id)
    dsl = _dsl_blocks(version)
    return {
        "definition_id": definition_id,
        "version_id": version.get("id"),
        "version_number": version.get("version_number"),
        "is_current": is_current,
        "commit_message": version.get("commit_message"),
        "created_at": version.get("created_at"),
        "author_label": version.get("author_label"),
        "rules_count": len(_block_list(dsl, "rules")),
        "rules_fingerprint": _fingerprint(dsl),
        "ocsf_validation_stats": version.get("ocsf_validation_stats"),
        "rules": dsl,
    }


async def _list_mapping_rule_targets(
    client: CentralOpsClient,
    *,
    definition_id: str,
    version_id: str | None = None,
    block: str = _DEFAULT_BLOCK,
    contains: str | None = None,
    offset: int = 0,
    limit: int = 0,
) -> Any:
    if block not in _BLOCKS:
        return {"error": f"block inválido: {block!r}. Use um de {list(_BLOCKS)}."}
    defn = await _resolve_definition(client, definition_id)
    current_id = defn.get("current_version_id")
    target_version = version_id or current_id
    if not target_version:
        return {"error": "definição sem versão vigente", "definition_id": definition_id}

    version = await _fetch_version(client, definition_id, target_version)
    dsl = _dsl_blocks(version)
    rules = _block_list(dsl, block)
    dups = _duplicate_targets(rules)

    # Filtro é a diferença entre "índice grande demais para caber" e "duas
    # linhas". Indexar 153 targets custa quase o mesmo que o array; procurar
    # 'severity' custa quase nada — e é o que o agente realmente faz.
    entries = [_index_entry(i, r, dups) for i, r in enumerate(rules)]
    matched = len(entries)
    if contains:
        needle = contains.lower()
        entries = [
            e for e in entries
            if needle in str(e.get("t") or "").lower()
            or needle in str(e.get("src") or "").lower()
        ]
        matched = len(entries)
    truncated = False
    if limit and limit > 0:
        window = entries[offset : offset + limit]
        truncated = len(window) < len(entries) - offset or offset > 0
        entries = window

    out: dict[str, Any] = {
        "definition_id": definition_id,
        "version_id": version.get("id"),
        "version_number": version.get("version_number"),
        "is_current": str(version.get("id")) == str(current_id),
        "block": block,
        "total": len(rules),
        "matched": matched,
        "returned": len(entries),
        "blocks": {b: len(_block_list(dsl, b)) for b in _BLOCKS},
        "duplicate_targets": sorted(dups),
        "targets": entries,
    }
    if truncated:
        out["truncated"] = True
        out["hint"] = "aumente 'limit' ou avance 'offset' para ver o resto"
    if contains and matched == 0:
        out["hint"] = (
            f"nenhum target contém {contains!r}. Chame sem 'contains' para ver "
            f"todos os {len(rules)}, ou tente um fragmento menor."
        )
    return out


async def _get_mapping_rules(
    client: CentralOpsClient,
    *,
    definition_id: str,
    version_id: str,
    block: str = _DEFAULT_BLOCK,
    indexes: list[int] | None = None,
    targets: list[str] | None = None,
    offset: int = 0,
    limit: int = 25,
) -> Any:
    if block not in _BLOCKS:
        return {"error": f"block inválido: {block!r}. Use um de {list(_BLOCKS)}."}
    defn = await _resolve_definition(client, definition_id)
    current_id = defn.get("current_version_id")
    version = await _fetch_version(client, definition_id, version_id)
    rules = _block_list(_dsl_blocks(version), block)

    if indexes:
        chosen = [i for i in indexes if isinstance(i, int) and 0 <= i < len(rules)]
        invalid = [i for i in indexes if i not in chosen]
    elif targets:
        wanted = set(targets)
        chosen = [
            i for i, r in enumerate(rules)
            if isinstance(r, dict) and r.get("target") in wanted
        ]
        invalid = []
    else:
        chosen = list(range(offset, min(offset + limit, len(rules))))
        invalid = []

    return {
        "definition_id": definition_id,
        "version_id": version.get("id"),
        "is_current": str(version.get("id")) == str(current_id),
        # O agente leu uma versão que já não é a corrente: qualquer índice
        # derivado dela pode apontar para outra regra depois do commit.
        "stale": str(version.get("id")) != str(current_id),
        "block": block,
        "total": len(rules),
        "returned": len(chosen),
        "invalid_indexes": invalid,
        "items": [
            {"index": i, "rule_sha256_12": _rule_digest(rules[i]), "rule": rules[i]}
            for i in chosen
        ],
    }


async def _get_mapping_samples(
    client: CentralOpsClient,
    *,
    vendor: str,
    event_type: str,
    limit: int = 10,
    organization_id: int | None = None,
) -> Any:
    return await client.get(
        "/mappings/samples",
        params={
            "vendor": vendor,
            "event_type": event_type,
            "limit": limit,
            "org_id": organization_id,
        },
    )


async def _discover_mapping_fields(
    client: CentralOpsClient,
    *,
    definition_id: str,
) -> Any:
    return await client.get(f"/mappings/{definition_id}/discover-fields")


async def _diff_mapping_versions(
    client: CentralOpsClient,
    *,
    definition_id: str,
    version_a_id: str,
    version_b_id: str,
) -> Any:
    return await client.get(
        f"/mappings/{definition_id}/versions/{version_a_id}/diff/{version_b_id}"
    )


async def _list_mapping_audit(
    client: CentralOpsClient,
    *,
    definition_id: str,
    limit: int = 50,
    offset: int = 0,
    action: str | None = None,
    username: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> Any:
    return await client.get(
        f"/mappings/{definition_id}/audit",
        params={
            "limit": limit,
            "offset": offset,
            "action": action,
            "username": username,
            "from_ts": from_ts,
            "to_ts": to_ts,
        },
    )


def _make_dry_run_handler(ack_cache: AckCache):
    async def _dry_run_mapping(
        client: CentralOpsClient,
        *,
        rules: dict[str, Any] | None = None,
        definition_id: str | None = None,
        vendor: str | None = None,
        event_type: str | None = None,
        raw_events: list[dict[str, Any]] | None = None,
        limit: int = 100,
        organization_id: int | None = None,
        verbose: bool = False,
    ) -> Any:
        mode = "proposed"
        base_version_id: str | None = None

        if rules is None:
            # Modo BASELINE: mede o que produção aplica agora. Nunca emite
            # ack_token — o agente não enumerou regra nenhuma, então não há
            # intenção a confirmar.
            if not definition_id:
                return {
                    "error": "informe 'rules' (modo proposed) ou 'definition_id' "
                             "(modo baseline, que roda as regras vigentes).",
                }
            mode = "baseline"
            defn = await _resolve_definition(client, definition_id)
            base_version_id = defn.get("current_version_id")
            if not base_version_id:
                return {
                    "mode": "baseline_unavailable",
                    "error": "definição sem versão vigente — nada a executar.",
                    "definition_id": definition_id,
                }
            version = await _fetch_version(client, definition_id, base_version_id)
            rules = _dsl_blocks(version)
            vendor = vendor or defn.get("vendor")
            event_type = event_type or defn.get("event_type")

        body: dict[str, Any] = {"rules": rules, "limit": limit}
        if vendor:
            body["vendor"] = vendor
        if event_type:
            body["event_type"] = event_type
        if raw_events is not None:
            body["raw_events"] = raw_events
        if organization_id is not None:
            body["organization_id"] = organization_id
        result = await client.post("/mappings/dry-run", json=body)

        ack_token: str | None = None
        # Baseline NUNCA emite token: ele autoriza um commit, e no baseline o
        # agente não enumerou nem viu as regras — não há intenção a confirmar.
        if definition_id and mode == "proposed":
            ack_token = ack_cache.issue(definition_id, rules)

        response: dict[str, Any] = {
            "mode": mode,
            "base_version_id": base_version_id,
            "rules_fingerprint": _fingerprint(rules),
            "rules_count": len(_block_list(rules, "rules")) if isinstance(rules, dict) else None,
            "dry_run": _summarize_dry_run(result, verbose),
            "ack_token": ack_token,
            "ack_token_note": (
                "Pass this ack_token into commit_mapping with the same "
                "definition_id and rules within 5 minutes to confirm intent."
                if ack_token
                else (
                    "Baseline mode issues no ack_token — it measures, it does not "
                    "authorize. To change rules, use patch_mapping_rules."
                    if mode == "baseline"
                    else "No ack_token issued: pass `definition_id` to enable commit gating."
                )
            ),
        }
        # Fail-closed sample loading: a global-scope token with no organization
        # gets sample_size=0, which silently degrades the dry-run to syntax-only
        # validation. Surface that instead of letting the agent assume coverage.
        if (
            raw_events is None
            and isinstance(result, dict)
            and result.get("sample_size") == 0
        ):
            if mode == "baseline":
                response["mode"] = "baseline_unavailable"
            response["warning"] = (
                "sample_size=0 — no reservoir samples were exercised, so this "
                "dry-run only validated rule syntax. If you are using a "
                "global-scope token, pass organization_id to pick the tenant "
                "whose sample reservoir should be used, or provide raw_events."
            )
        return response

    return _dry_run_mapping


def _make_patch_handler(ack_cache: AckCache):
    async def _patch_mapping_rules(
        client: CentralOpsClient,
        *,
        definition_id: str,
        ops: list[dict[str, Any]],
        base_version_id: str | None = None,
        organization_id: int | None = None,
        compare_baseline: bool = True,
        verbose: bool = False,
        limit: int = 100,
    ) -> Any:
        defn = await _resolve_definition(client, definition_id)
        current_id = defn.get("current_version_id")
        base_id = base_version_id or current_id
        if not base_id:
            return {"error": "definição sem versão vigente — não há base para o patch."}

        version = await _fetch_version(client, definition_id, base_id)
        dsl = _dsl_blocks(version)
        base_rules = _block_list(dsl, "rules")

        try:
            merged_rules, changes = _apply_ops(base_rules, ops)
        except PatchError as exc:
            return {"error": str(exc), "base_version_id": base_id,
                    "rules_count": len(base_rules)}

        # Preserva TODO bloco top-level que não seja ``rules`` — inclusive
        # desconhecidos. Reconstruir o dict foi o que apagou o ``raw_reduction``
        # do sophos.detection em produção.
        merged = dict(dsl)
        merged["rules"] = merged_rules

        body: dict[str, Any] = {
            "rules": merged, "limit": limit,
            "vendor": defn.get("vendor"), "event_type": defn.get("event_type"),
        }
        if organization_id is not None:
            body["organization_id"] = organization_id
        proposed = await client.post("/mappings/dry-run", json=body)

        baseline = None
        if compare_baseline:
            base_body = dict(body)
            base_body["rules"] = dsl
            baseline = await client.post("/mappings/dry-run", json=base_body)

        digest = _patch_digest(definition_id, base_id, ops)
        ack_token = ack_cache.issue_patch(
            definition_id, merged, base_version_id=base_id, patch_digest=digest
        )

        return {
            "definition_id": definition_id,
            "base_version_id": base_id,
            "base_is_current": str(base_id) == str(current_id),
            "rules_count_before": len(base_rules),
            "rules_count_after": len(merged_rules),
            # Só o que mudou. O array completo fica na memória deste processo
            # até o commit — nunca entra no contexto do modelo.
            "changes": changes,
            "dry_run": _summarize_dry_run(proposed, verbose),
            "dry_run_baseline": _summarize_dry_run(baseline, verbose) if baseline else None,
            "ack_token": ack_token,
            "ack_token_note": (
                "Pass this ack_token to commit_mapping_patch with the SAME "
                "definition_id and ops within 5 minutes. The merged rules are "
                "staged server-side in this MCP process — you never need to "
                "resend them."
            ),
        }

    return _patch_mapping_rules


def _make_commit_patch_handler(ack_cache: AckCache):
    async def _commit_mapping_patch(
        client: CentralOpsClient,
        *,
        definition_id: str,
        ops: list[dict[str, Any]],
        commit_message: str,
        ack_token: str,
        base_version_id: str | None = None,
    ) -> Any:
        digest = _patch_digest(
            definition_id,
            base_version_id or _peek_base(ack_cache, ack_token),
            ops,
        )
        entry = ack_cache.consume_patch(ack_token, definition_id, digest)
        payload: dict[str, Any] = {
            "rules": entry.staged_rules,
            "commit_message": commit_message,
        }
        # Concorrência otimista: o backend recusa (409) se o ponteiro tiver
        # mudado desde a leitura. Backends antigos ignoram o campo — a checagem
        # client-side abaixo continua sendo o piso.
        if entry.base_version_id:
            payload["base_version_id"] = entry.base_version_id
        return await client.post(f"/mappings/{definition_id}/versions", json=payload)

    return _commit_mapping_patch


def _peek_base(ack_cache: AckCache, token: str) -> str | None:
    """Base version do token, sem consumi-lo (o digest depende dela)."""
    entry = ack_cache._entries.get(token)  # noqa: SLF001 — mesmo pacote
    return entry.base_version_id if entry else None


def _make_commit_handler(ack_cache: AckCache):
    async def _commit_mapping(
        client: CentralOpsClient,
        *,
        definition_id: str,
        rules: dict[str, Any],
        commit_message: str,
        ack_token: str,
    ) -> Any:
        ack_cache.consume(ack_token, definition_id, rules)
        return await client.post(
            f"/mappings/{definition_id}/versions",
            json={"rules": rules, "commit_message": commit_message},
        )

    return _commit_mapping


def specs(ack_cache: AckCache) -> list[ToolSpec]:
    return [
        ToolSpec(
            name="get_mapping_samples",
            description=(
                "Read raw vendor events from the sample reservoir for a (vendor, "
                "event_type) pair. THIS is the tool to answer 'what does vendor X "
                "actually send for this event type?' — the items are the original JSON "
                "captured by the collector before normalization. Use the output to "
                "build or fix mapping rules. Returns up to `limit` recent items; older "
                "samples roll out of the reservoir. NOTE: the reservoir is org-scoped "
                "and fail-closed — a global-scope token with no organization always "
                "sees an empty reservoir unless organization_id is provided."
            ),
            input_schema=_object(
                properties={
                    "vendor": _string("Vendor (e.g. 'sophos', 'wazuh')."),
                    "event_type": _string("Event type (e.g. 'sophos.alert')."),
                    "limit": _integer(
                        "Number of samples to return (1-100, default 10).",
                        minimum=1,
                        maximum=100,
                    ),
                    "organization_id": _integer(
                        "Global scope only: the tenant whose sample reservoir to read. "
                        "Ignored for org-scoped tokens.",
                        minimum=1,
                    ),
                },
                required=["vendor", "event_type"],
            ),
            handler=_get_mapping_samples,
        ),
        ToolSpec(
            name="discover_mapping_fields",
            description=(
                "List fields the drift detector has already observed for this mapping's "
                "vendor/event_type — paths, occurrence counts, sample values, "
                "first_seen. Use this for autocomplete-style 'what JMESPath paths "
                "are available?' before authoring rules in dry_run_mapping."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                },
                required=["definition_id"],
            ),
            handler=_discover_mapping_fields,
        ),
        ToolSpec(
            name="diff_mapping_versions",
            description=(
                "Structured diff between two versions of a mapping definition. Returns "
                "added/removed/modified rules keyed by target. Use to review what a "
                "specific commit changed."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id."),
                    "version_a_id": _string("Older version id."),
                    "version_b_id": _string("Newer version id."),
                },
                required=["definition_id", "version_a_id", "version_b_id"],
            ),
            handler=_diff_mapping_versions,
        ),
        ToolSpec(
            name="list_mapping_audit",
            description=(
                "Paginated audit log for a mapping definition: who changed what, when, "
                "and the diff of each change. Use to answer 'who broke this rule?' or "
                "'when did the field name change?'."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id."),
                    "limit": _integer("1-200, default 50.", minimum=1, maximum=200),
                    "offset": _integer("Pagination offset.", minimum=0),
                    "action": _string(
                        "Optional filter (e.g. 'create_version', 'rollback', "
                        "'ignore_field', 'mark_mapped', 'delete_field')."
                    ),
                    "username": _string("Optional username filter."),
                    "from_ts": _string("Optional ISO 8601 lower bound."),
                    "to_ts": _string("Optional ISO 8601 upper bound."),
                },
                required=["definition_id"],
            ),
            handler=_list_mapping_audit,
        ),
        ToolSpec(
            name="list_mappings",
            description=(
                "List mapping definitions in the CentralOps catalog (vendor/event_type "
                "pairs with their current version). Use this before get_mapping to find "
                "the definition_id you want."
            ),
            input_schema=_object(
                properties={
                    "include_rules_count": {
                        "type": "boolean",
                        "description": "If true, include the count of rules in each current version.",
                    },
                    "only_active": {
                        "type": "boolean",
                        "description": (
                            "If true, only mappings whose vendor has an active "
                            "integration in the caller's scope (the UI default). "
                            "Default false = full catalog."
                        ),
                    },
                },
            ),
            handler=_list_mappings,
        ),
        ToolSpec(
            name="get_mapping",
            description=(
                "Read a mapping definition and THE RULES PRODUCTION IS APPLYING "
                "RIGHT NOW.\n\n"
                "THIS IS THE SOURCE OF TRUTH. Mapping definitions are seeded "
                "from repository default JSON files only on first creation; any "
                "later edit through the UI or a commit creates a new version and "
                "the seed never touches that definition again. Live rules "
                "therefore DIVERGE from the files in the repo — never infer "
                "production behavior from those files.\n\n"
                "The current version is resolved by the definition's "
                "`current_version_id` POINTER, not by 'the newest version'. "
                "These differ: a rollback re-points the pointer at an OLD "
                "version without creating a new one, so the highest "
                "version_number is NOT necessarily what production runs. Never "
                "pick a version by ordering.\n\n"
                "Version HISTORY is opt-in and you almost never need it: "
                "`include_versions` defaults to 'none'. 'meta' lists past "
                "versions without their rule bodies; 'full' returns EVERY "
                "version in full and can exhaust a context window — that is "
                "archaeology, not editing.\n\n"
                "SIZE: a mature mapping has 150+ rules (~30 KB). If you only "
                "need to change one rule, do NOT call this — use "
                "list_mapping_rule_targets to find it, then get_mapping_rules "
                "to read just that one."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "include_versions": {
                        "type": "string",
                        "enum": ["none", "meta", "full"],
                        "description": (
                            "Version HISTORY only; the CURRENT rules are always "
                            "returned. Default 'none'."
                        ),
                    },
                    "include_current_rules": {
                        "type": "boolean",
                        "description": "Default true. Set false for the header only.",
                    },
                },
                required=["definition_id"],
            ),
            handler=_get_mapping,
        ),
        ToolSpec(
            name="get_mapping_version",
            description=(
                "Read ONE mapping version by id: rules body, author, commit "
                "message, and the OCSF validation stats recorded at commit "
                "time. Omit `version_id` to read exactly what production runs. "
                "Returns one version, never the history."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "version_id": _string(
                        "Version id. Omit to resolve the current one via the pointer."
                    ),
                },
                required=["definition_id"],
            ),
            handler=_get_mapping_version,
        ),
        ToolSpec(
            name="list_mapping_rule_targets",
            description=(
                "Cheap INDEX of a mapping's rules: one compact line per rule — "
                "no rule bodies. This is the map you navigate before reading or "
                "patching anything.\n\n"
                "USE `contains` — it is the difference between an index that "
                "fits and one that does not. A 153-rule mapping indexes to "
                "~4k tokens; `contains: \"severity\"` gives you the two lines "
                "you actually wanted. It matches the target and, on ambiguous "
                "entries, the source.\n\n"
                "Fields are omitted when absent, so read them as flags: `i` is "
                "the absolute index, `t` the target, and `f` packs c=const, "
                "d=default, m=value_map, w=when, r=required. `when` and `src` "
                "only appear on ambiguous entries, where they are what tells "
                "the duplicates apart.\n\n"
                "TARGET IS NOT A UNIQUE KEY. The same target legitimately "
                "appears many times, gated by different `when` predicates, and "
                "ORDER decides the winner (last write wins). Entries flagged "
                "`ambiguous: true` share a target with another rule — for those, "
                "`when_summary` is the only thing that tells them apart. ALWAYS "
                "address rules by `index`, never by `target`.\n\n"
                "`rule_sha256_12` is a precondition check for editing, not a "
                "cryptographic identity."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "version_id": _string("Omit to index the current version."),
                    "block": {
                        "type": "string",
                        "enum": list(_BLOCKS),
                        "description": "Which DSL block to index. Default 'rules'.",
                    },
                    "contains": _string(
                        "Case-insensitive substring of the target (and of the "
                        "source on ambiguous entries). Use it — it is what "
                        "keeps the index small."
                    ),
                    "offset": _integer("Window start. Default 0.", minimum=0),
                    "limit": _integer(
                        "Max entries to return. 0 (default) means no window.",
                        minimum=0,
                        maximum=500,
                    ),
                },
                required=["definition_id"],
            ),
            handler=_list_mapping_rule_targets,
        ),
        ToolSpec(
            name="get_mapping_rules",
            description=(
                "Read the FULL body of specific rules, by absolute index or by "
                "target. Every item carries its absolute `index` — that index is "
                "what patch_mapping_rules addresses.\n\n"
                "`version_id` is REQUIRED on purpose: committing re-points the "
                "current version, so without pinning, two pages could straddle "
                "different versions and the indexes would silently refer to "
                "different rules. Take the id from list_mapping_rule_targets.\n\n"
                "`stale: true` means the definition moved on while you were "
                "reading — re-run list_mapping_rule_targets before patching."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "version_id": _string("Pin the version (from list_mapping_rule_targets)."),
                    "block": {
                        "type": "string",
                        "enum": list(_BLOCKS),
                        "description": "Default 'rules'.",
                    },
                    "indexes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Absolute indexes to read. Wins over targets/offset.",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Read every rule with these targets (may be several).",
                    },
                    "offset": _integer("Window start when no indexes/targets.", minimum=0),
                    "limit": _integer("Window size (1-100, default 25).", minimum=1, maximum=100),
                },
                required=["definition_id", "version_id"],
            ),
            handler=_get_mapping_rules,
        ),
        ToolSpec(
            name="dry_run_mapping",
            description=(
                "Validate and dry-run mapping rules against the sample reservoir "
                "without persisting anything. Read-only despite being a POST. "
                "Pass `definition_id` to receive an ack_token bound to these "
                "exact rules — required by commit_mapping, expires in 5 minutes, "
                "single-use.\n\n"
                "WHAT 'PASSED' MEANS — read this before reporting a result. This "
                "tool reports whether the RULES EXECUTED, not whether the output "
                "is valid OCSF. It does NOT return ocsf_validation_stats or "
                "mapped_field_ratio. '10/10 passed' means no rule crashed and no "
                "required target came out empty; it does NOT mean the events "
                "conform to OCSF 1.8, that class_uid/activity_id are correct for "
                "the event, or that any field landed in the right OCSF object. "
                "Never claim OCSF conformance on the strength of a dry-run.\n\n"
                "Also check the response: `sample_size: 0` means the reservoir "
                "was empty (usually a global-scope token with no "
                "`organization_id`), which silently degrades this to syntax-only "
                "validation. A `warning` field is added when that happens."
            ),
            input_schema=_object(
                properties={
                    "rules": _RULES_SCHEMA,
                    "definition_id": _string(
                        "Optional. When set, an ack_token is issued for use with commit_mapping."
                    ),
                    "vendor": _string(
                        "Vendor for sample reservoir lookup (required if raw_events is omitted)."
                    ),
                    "event_type": _string(
                        "Event type for sample reservoir lookup (required if raw_events is omitted)."
                    ),
                    "raw_events": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Optional explicit raw events to dry-run against.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Sample size limit (1-500, default 100).",
                        "minimum": 1,
                        "maximum": 500,
                    },
                    "organization_id": _integer(
                        "Global scope only: the tenant whose sample reservoir feeds "
                        "the dry-run. Without it a global token with no organization "
                        "gets sample_size=0 (syntax-only validation). Ignored for "
                        "org-scoped tokens.",
                        minimum=1,
                    ),
                },
                required=["rules"],
            ),
            handler=_make_dry_run_handler(ack_cache),
        ),
        ToolSpec(
            name="commit_mapping",
            description=(
                "Create a new mapping version and promote it to current. Destructive: "
                "downstream collectors will start applying the new rules within ~30s. "
                "Requires a fresh ack_token from dry_run_mapping with matching "
                "definition_id and rules. Backend re-validates and re-runs dry-run on "
                "commit, so this is also a defense-in-depth check.\n\n"
                "NOT IDEMPOTENT: every call creates another version. Do not "
                "retry on an ambiguous result — call get_mapping first to see "
                "whether the version already landed.\n\n"
                "Requires explicit human intent. This is how you change what "
                "production does; it is never the way to test an idea — use "
                "dry_run_mapping for that."
            ),
            read_only=False,
            destructive=True,
            idempotent=False,
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "rules": _RULES_SCHEMA,
                    "commit_message": _string(
                        "Human-readable description of the change (1-2000 chars).",
                        minLength=1,
                        maxLength=2000,
                    ),
                    "ack_token": _string(
                        "Token issued by dry_run_mapping for the same definition_id and rules."
                    ),
                },
                required=["definition_id", "rules", "commit_message", "ack_token"],
            ),
            handler=_make_commit_handler(ack_cache),
        ),
        ToolSpec(
            name="patch_mapping_rules",
            description=(
                "Change specific rules WITHOUT ever handling the whole array. "
                "This is how you edit a 193-rule mapping: describe the ops, and "
                "the merged result is dry-run and staged in this MCP process. "
                "Read-only — it stages and measures, it does not commit.\n\n"
                "Ops address the BASE array by absolute index (from "
                "list_mapping_rule_targets) and are resolved as a BATCH, so "
                "indexes never shift under you:\n"
                "  replace {index, expect_target, rule} — swap the whole rule object\n"
                "  remove  {index, expect_target}\n"
                "  insert  {index, rule} — insert BEFORE base[index]\n"
                "  append  {rule}\n\n"
                "`expect_target` is mandatory on replace/remove and is the "
                "assert that stops you editing the wrong rule when the index has "
                "aged: a mismatch fails the patch instead of corrupting the "
                "mapping. Two ops touching the same index is also an error.\n\n"
                "Blocks other than `rules` (preprocess, raw_reduction, and any "
                "unknown ones) are carried over VERBATIM — rebuilding the dict "
                "is what once silently deleted a mapping's raw_reduction in "
                "production.\n\n"
                "The response returns only what CHANGED, plus the dry-run of the "
                "result and (by default) of the unmodified base for comparison. "
                "The merged array stays server-side; commit it with "
                "commit_mapping_patch and the same ops."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "ops": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "object"},
                        "description": "List of ops. See the tool description for the shapes.",
                    },
                    "base_version_id": _string(
                        "Version the indexes refer to. Omit to use the current one."
                    ),
                    "organization_id": _integer(
                        "Global scope only: tenant whose reservoir feeds the dry-run.",
                        minimum=1,
                    ),
                    "compare_baseline": {
                        "type": "boolean",
                        "description": "Default true: also dry-run the UNMODIFIED base.",
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Include full OCSF output envelopes. Default false.",
                    },
                    "limit": _integer("Dry-run sample size (1-500).", minimum=1, maximum=500),
                },
                required=["definition_id", "ops"],
            ),
            handler=_make_patch_handler(ack_cache),
        ),
        ToolSpec(
            name="commit_mapping_patch",
            description=(
                "Promote the patch staged by patch_mapping_rules. Destructive: "
                "live collectors pick up the new rules within ~30s.\n\n"
                "Resend the SAME definition_id and ops plus the ack_token — the "
                "merged rules are already staged here, so you never resend 193 "
                "rules. The token is single-use, expires in 5 minutes, and is "
                "bound to the exact ops AND the base version they were computed "
                "against.\n\n"
                "The commit carries that base version so the backend can refuse "
                "(409) if someone else changed the mapping meanwhile. On 409, "
                "re-read the index and redo the edit — do NOT retry blindly, "
                "because each call creates another version.\n\n"
                "Requires explicit human intent. To test an idea, use "
                "patch_mapping_rules."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                    "ops": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "object"},
                        "description": "The SAME ops passed to patch_mapping_rules.",
                    },
                    "commit_message": _string(
                        "Human-readable description of the change (1-2000 chars).",
                        minLength=1,
                        maxLength=2000,
                    ),
                    "ack_token": _string("Token issued by patch_mapping_rules."),
                    "base_version_id": _string("Optional; defaults to the staged one."),
                },
                required=["definition_id", "ops", "commit_message", "ack_token"],
            ),
            handler=_make_commit_patch_handler(ack_cache),
            read_only=False,
            destructive=True,
            idempotent=False,
        ),
    ]
