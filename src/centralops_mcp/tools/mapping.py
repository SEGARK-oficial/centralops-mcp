from __future__ import annotations

from typing import Any

from centralops_mcp.ack_cache import AckCache
from centralops_mcp.tools._base import (
    CentralOpsClient,
    ToolSpec,
    _integer,
    _object,
    _string,
)


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
) -> Any:
    return await client.get(f"/mappings/{definition_id}")


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
        rules: dict[str, Any],
        definition_id: str | None = None,
        vendor: str | None = None,
        event_type: str | None = None,
        raw_events: list[dict[str, Any]] | None = None,
        limit: int = 100,
        organization_id: int | None = None,
    ) -> Any:
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
        if definition_id:
            ack_token = ack_cache.issue(definition_id, rules)

        response: dict[str, Any] = {
            "dry_run": result,
            "ack_token": ack_token,
            "ack_token_note": (
                "Pass this ack_token into commit_mapping with the same "
                "definition_id and rules within 5 minutes to confirm intent."
                if ack_token
                else "No ack_token issued: pass `definition_id` to enable commit gating."
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
            response["warning"] = (
                "sample_size=0 — no reservoir samples were exercised, so this "
                "dry-run only validated rule syntax. If you are using a "
                "global-scope token, pass organization_id to pick the tenant "
                "whose sample reservoir should be used, or provide raw_events."
            )
        return response

    return _dry_run_mapping


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
                "Fetch a mapping definition with its full version history. "
                "Returns the current rules and an immutable list of past "
                "versions.\n\n"
                "THIS IS THE SOURCE OF TRUTH for what production applies. "
                "Mapping definitions are seeded from repository default JSON "
                "files only on first creation; any later edit through the UI or "
                "commit_mapping creates a new version and the seed never touches "
                "that definition again. Live rules therefore diverge from the "
                "files in the repo — never infer production behavior from those "
                "files.\n\n"
                "SIZE WARNING: the response carries EVERY version in full, not "
                "just the current one. On a mature definition (100+ rules across "
                "several versions) this is a large payload that can exhaust a "
                "context window. If you only need the current rules, read the "
                "first version entry and discard the rest, or use "
                "diff_mapping_versions to compare two specific versions instead."
            ),
            input_schema=_object(
                properties={
                    "definition_id": _string("Mapping definition id (uuid)."),
                },
                required=["definition_id"],
            ),
            handler=_get_mapping,
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
    ]
