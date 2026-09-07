"""Correlation rules — the CONFIGURATION side of in-pipeline detection.

``detections.py`` already exposed the OUTPUT of correlation (the alerts, with
``source='correlation'``). Without this module an agent could see that a rule
fired and had no way to answer the question that always follows: *which rule,
what does it match, is it even being evaluated, and would this new clause match
anything?* Those four questions are four different endpoints, and three of them
return "no" in a way that is easy to misread — hence the long descriptions.

Read-only by design. Rule authoring happens in the console (the rule Studio),
where the flow graph, the field inventory and the sample preview are shown side
by side; an agent creating an in-flight rule with a bad ``where`` would emit a
Detection per event until someone noticed.
"""

from __future__ import annotations

from typing import Any

from centralops_mcp.tools._base import (
    CentralOpsClient,
    ToolSpec,
    _integer,
    _object,
    _string,
)

#: Mirrors ``RULE_METRIC_WINDOW_MINUTES`` in the Core engine. It is both the
#: default and the ceiling: the series is retained for 25 h, so a wider window
#: would return the expired part as zero — indistinguishable from "did not fire".
RULE_METRIC_WINDOW_MINUTES = 24 * 60


async def _list_correlation_rules(
    client: CentralOpsClient,
    *,
    include_inflight_status: bool = False,
) -> Any:
    return await client.get(
        "/correlation-rules",
        params={"include_inflight_status": include_inflight_status},
    )


async def _get_correlation_rule(
    client: CentralOpsClient,
    *,
    rule_id: int,
) -> Any:
    return await client.get(f"/correlation-rules/{rule_id}")


async def _get_correlation_rule_metrics(
    client: CentralOpsClient,
    *,
    rule_id: int,
    range_minutes: int = RULE_METRIC_WINDOW_MINUTES,
) -> Any:
    return await client.get(
        f"/correlation-rules/{rule_id}/metrics",
        params={"range_minutes": range_minutes},
    )


async def _get_correlation_limits(
    client: CentralOpsClient,
    *,
    organization_id: int | None = None,
) -> Any:
    return await client.get(
        "/correlation-rules/limits",
        params={"organization_id": organization_id},
    )


async def _preview_correlation_rule(
    client: CentralOpsClient,
    *,
    vendor: str,
    event_type: str,
    where: list[dict[str, Any]],
    eval_mode: str = "inflight",
    limit: int = 25,
    organization_id: int | None = None,
) -> Any:
    body: dict[str, Any] = {
        "vendor": vendor,
        "event_type": event_type,
        "where": where,
        "eval_mode": eval_mode,
        "limit": limit,
    }
    if organization_id is not None:
        body["organization_id"] = organization_id
    return await client.post("/correlation-rules/preview", json=body)


_WHERE_FILTER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "One clause. 'field' is a dotted path resolved from the ENVELOPE ROOT "
        "(_centralops, normalized or raw) in in-flight mode; in batch mode it is "
        "a field of the document returned by the federated search."
    ),
    "properties": {
        "field": {"type": "string", "description": "Dotted path, e.g. 'normalized.metadata.event_code'."},
        "op": {
            "type": "string",
            "description": (
                "Comparison. The batch engine knows 7 (eq, ne, contains, gt, lt, "
                "gte, lte); the in-flight engine adds in, nin and exists. Using an "
                "in-flight-only operator with eval_mode='batch' makes the batch "
                "engine DISCARD the whole clause list at the first unknown operator."
            ),
            "enum": ["eq", "ne", "contains", "gt", "lt", "gte", "lte", "in", "nin", "exists"],
        },
        "value": {
            "description": (
                "String for most operators; ARRAY of strings for in/nin; BOOLEAN "
                "for exists. A value of the wrong type for the operator is a 422."
            ),
        },
    },
    "required": ["field", "op"],
    "additionalProperties": False,
}


def specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="list_correlation_rules",
            description=(
                "List the correlation rules visible to the token, newest id first. "
                "A correlation rule is the CONFIGURATION that produces the "
                "detections list_detections returns with source='correlation'. "
                "Each item carries: id, organization_id, name, description, "
                "enabled, severity_id, rule_type ('threshold', 'sequence' or "
                "'absence'), absence_forget_seconds (absence only: after how much "
                "silence a watched key stops being expected; null = 3x the "
                "deadline), "
                "legs (the sequence legs, [] on threshold rules), eval_mode "
                "('batch' = evaluated when a federated search finishes, over its "
                "results; 'inflight' = evaluated PER EVENT in the ingestion "
                "pipeline, before the data reaches the SIEM), eval_priority, "
                "group_by_field, min_count, window_seconds, timestamp_field, "
                "where (the filter clauses), suppression_window_seconds, "
                "emit_event (in-flight only: the Detection also leaves as a routed "
                "OCSF 2004 event), schedule_* (batch only: the rule gets its own "
                "search), max_dedup_keys and created_at.\n\n"
                "IMPORTANT — 'not_evaluated_inflight' is only CALCULATED when you "
                "pass include_inflight_status=true. Without the opt-in the backend "
                "returns false for every rule, and that false means 'I did not "
                "ask', never 'the rule is running'. An enabled in-flight rule can "
                "silently not run for two reasons that both land on this flag: it "
                "fell outside the per-cycle rule cap, or its 'where' does not "
                "compile. Use get_correlation_limits to tell the two apart.\n\n"
                "ABSENCE rules invert the reading of three fields: 'where' is the "
                "event that must KEEP arriving, group_by_field is the WATCHED key "
                "(every distinct value is an entity that has to show up) and "
                "window_seconds is the DEADLINE of tolerated silence (60 s to 7 "
                "days — its own cap, not the 3600 s of the sliding window). The rule "
                "learns keys as it sees them and alerts a known key that goes silent "
                "past the deadline; it forgets a key after absence_forget_seconds. "
                "It only alerts when the engine can prove it was watching — see "
                "get_correlation_rule_metrics (absence_state) and "
                "get_correlation_limits (absence_unobservable_rules).\n\n"
                "Enterprise-only surface: on a Community deployment these routes do "
                "not exist and the call returns HTTP 404."
            ),
            input_schema=_object(
                properties={
                    "include_inflight_status": {
                        "type": "boolean",
                        "description": (
                            "Calculate 'not_evaluated_inflight' per rule. Costs a "
                            "COUNT and a rule compilation per organization in the "
                            "response, so it is opt-in. Pass true whenever you are "
                            "answering 'is this rule actually running?' — the "
                            "default false yields a false that means 'not asked'."
                        ),
                    },
                },
            ),
            handler=_list_correlation_rules,
        ),
        ToolSpec(
            name="get_correlation_rule",
            description=(
                "Fetch a single correlation rule by numeric id, with the same "
                "fields as list_correlation_rules (including the full 'where' "
                "clauses and, for a sequence rule, the 'legs' — each leg being "
                "{label?, stream?, where[], join_path}: one event from one source, "
                "joined to the other legs by the VALUE at join_path, which is a "
                "different path per source).\n\n"
                "Returns 404 both when the rule does not exist and when it belongs "
                "to an organization outside the token's scope — the 404 is "
                "deliberate anti-enumeration, so do not read it as 'deleted'. "
                "Enterprise-only surface: on a Community deployment these routes "
                "do not exist and every call here is a 404 too."
            ),
            input_schema=_object(
                properties={
                    "rule_id": _integer("Correlation rule id.", minimum=1),
                },
                required=["rule_id"],
            ),
            handler=_get_correlation_rule,
        ),
        ToolSpec(
            name="get_correlation_rule_metrics",
            description=(
                "Read the in-flight counters of ONE rule over a time window — the "
                "tool that answers 'is this rule still matching?'. Returns "
                "rule_id, organization_id, range_minutes, matches, overflow and "
                "errors (a reason -> count map, only for reasons attributable to a "
                "single rule, e.g. group_by_unresolved, key_cap, flush_lost, "
                "group_value_truncated).\n\n"
                "READ THE NULLS: every metric is nullable and null is a "
                "first-class value. 0.0 means the series was read and sums to zero "
                "('this rule did not fire'); null means the READ FAILED ('unknown') "
                "— never render or reason about a null as a zero, because the "
                "decision it feeds is usually whether to disable the rule.\n\n"
                "'matches' can be far larger than the number of detections: dedup "
                "and the per-cycle key cap sit between them. High 'matches' WITH "
                "high 'overflow' is a diagnosis of group_by cardinality, not a bug "
                "— matches were dropped because the cycle blew the distinct-key "
                "cap. Only in-flight rules produce these counters; a batch rule "
                "returns zeros.\n\n"
                "ABSENCE rules add four fields read from the LAST TICK, not summed "
                "over the window: absence_tracked (keys under watch), "
                "absence_silent (keys past the deadline right now), absence_state "
                "('ok' = evaluated; 'unobservable' = the flush stopped heartbeating, "
                "so the engine refused to alert; 'lagging' = the pinned source has a "
                "collection backlog; 'unavailable' = Redis did not answer) and "
                "absence_last_tick (epoch seconds). For an absence rule that 'did "
                "not fire', read absence_state BEFORE concluding the source is "
                "silent: 'unobservable' means nobody was watching, which is a "
                "different incident. The error reasons absence_unavailable, "
                "absence_key_cap, absence_unobservable and absence_source_lagging "
                "appear in 'errors' like the others.\n\n"
                "Enterprise-only surface (404 on Community)."
            ),
            input_schema=_object(
                properties={
                    "rule_id": _integer("Correlation rule id.", minimum=1),
                    "range_minutes": _integer(
                        (
                            "Window in minutes (5 to 1440, default 1440 = 24 h). "
                            "1440 is also the ceiling because the underlying series "
                            "is retained for 25 h — a wider window would return the "
                            "expired part as zero, which is indistinguishable from "
                            "'did not fire'."
                        ),
                        minimum=5,
                        maximum=RULE_METRIC_WINDOW_MINUTES,
                    ),
                },
                required=["rule_id"],
            ),
            handler=_get_correlation_rule_metrics,
        ),
        ToolSpec(
            name="get_correlation_limits",
            description=(
                "Why an ENABLED in-flight rule may not be running, for ONE "
                "organization. The caps are per-org and the response is always "
                "about a single org — there is no cross-tenant aggregation, "
                "because a sum of caps describes no organization.\n\n"
                "Returns: creation_cap (how many rules the org may have), "
                "inflight_cap_as_seen_by_api (how many in-flight rules are loaded "
                "and evaluated per collection cycle, as the API process reads the "
                "variable — the workers may read a different one), "
                "inflight_evaluation_enabled (a cap of 0 is a KILL SWITCH, not "
                "absence of rules), inflight_enabled_total, truncated_count (rules "
                "that fell outside the cap; survival is decided by eval_priority "
                "DESC, id ASC, so with everyone at the default 0 the newest rule is "
                "the first one cut) and uncompilable_count (rules INSIDE the cap "
                "that the cycle discards anyway because the filter does not "
                "compile). The two counters are separate on purpose: merging them "
                "would hide the second cause.\n\n"
                "It may also carry the emission gap: inflight_rules_not_emitting "
                "(enabled in-flight rules whose Detection stays in the database "
                "only), emit_env_enabled, detection_routes_count and "
                "default_destination_exists — i.e. 'where does the alert actually "
                "arrive?'.\n\n"
                "absence_unobservable_rules (may be absent on older APIs): enabled "
                "ABSENCE rules whose last tick could not evaluate — no observer "
                "heartbeat, pinned source lagging, or Redis unavailable. This is "
                "'the engine could not say anything', never 'the source is silent'; "
                "a rule that the tick has not visited yet does not count.\n\n"
                "Enterprise-only surface (404 on Community)."
            ),
            input_schema=_object(
                properties={
                    "organization_id": _integer(
                        (
                            "Target organization. Omitted = the caller's own org. A "
                            "global admin with no own org must pass it, otherwise "
                            "the API answers 400."
                        ),
                        minimum=1,
                    ),
                },
            ),
            handler=_get_correlation_limits,
        ),
        ToolSpec(
            name="preview_correlation_rule",
            description=(
                "Evaluate a candidate 'where' against REAL samples from the "
                "reservoir for one (vendor, event_type), without persisting "
                "anything: no Detection, no counter, no dedup. This is how you "
                "check a rule BEFORE it is written — and the only tool here that "
                "returns observed values from customer events, so it needs the "
                "'correlation.preview' permission rather than plain read.\n\n"
                "The response state is a vocabulary, and collapsing it into '0 of "
                "N' loses the answer: 'ok' = evaluated (clauses carries the "
                "per-clause verdict); 'empty' = there are no samples for that "
                "vendor/event_type (NOT 'did not match'); 'unavailable' = the "
                "sample store did not answer (NOT 'did not match'); 'invalid' = "
                "the rule does not compile, with 'reason' in {bad_json, "
                "empty_where, unknown_op, over_cap}.\n\n"
                "Per clause you get path_resolved and matched, which are DIFFERENT "
                "measurements: path_resolved=0 means the field does not exist where "
                "you pointed (usually a path that does not start at the envelope "
                "root); path_resolved=N with matched=0 means the field exists and "
                "the value does not match. 'observed' lists values actually seen — "
                "use it to fix the clause instead of guessing.\n\n"
                "ALWAYS pass eval_mode explicitly. The endpoint defaults to "
                "'inflight', which is the OPPOSITE of the default a new rule is "
                "created with ('batch'): previewing a batch rule without the field "
                "judges it by the 10-operator in-flight vocabulary and can return a "
                "green verdict for a rule the batch engine would discard.\n\n"
                "Enterprise-only surface (404 on Community)."
            ),
            input_schema=_object(
                properties={
                    "vendor": _string("Vendor of the samples, e.g. 'sophos', 'wazuh'."),
                    "event_type": _string(
                        "Event type of the samples, e.g. 'sophos.detection'. The "
                        "reservoir is indexed by vendor + event_type; list_mappings "
                        "shows the pairs that exist."
                    ),
                    "where": {
                        "type": "array",
                        "description": (
                            "The clauses to test. An empty list is refused with "
                            "state='invalid', reason='empty_where' — a rule with no "
                            "predicate would match 100% of events."
                        ),
                        "items": _WHERE_FILTER_SCHEMA,
                    },
                    "eval_mode": {
                        "type": "string",
                        "description": (
                            "Which engine's vocabulary to judge by. Pass the mode of "
                            "the rule you are actually writing — see the warning "
                            "above about the default."
                        ),
                        "enum": ["batch", "inflight"],
                    },
                    "limit": _integer(
                        "How many samples to evaluate (1-50, default 25).",
                        minimum=1,
                        maximum=50,
                    ),
                    "organization_id": _integer(
                        (
                            "Tenant whose sample reservoir to read. The reservoir is "
                            "org-scoped and fail-closed: a global-scope token without "
                            "this gets state='empty', which is NOT 'did not match'."
                        ),
                        minimum=1,
                    ),
                },
                required=["vendor", "event_type", "where"],
            ),
            handler=_preview_correlation_rule,
            # POST, and still read-only: the endpoint evaluates against samples
            # and persists NOTHING — no Detection, no counter, no dedup. Same
            # reading as dry_run_mapping; declared explicitly rather than
            # inherited from the default, because "it is a POST" is exactly the
            # reason someone would assume otherwise.
            read_only=True,
        ),
    ]


__all__ = ["specs"]
