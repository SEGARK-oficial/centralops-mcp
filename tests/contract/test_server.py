from __future__ import annotations

import pytest

from centralops_mcp.ack_cache import AckCache
from centralops_mcp.server import _build_specs


def test_tool_registry_has_expected_names():
    specs = _build_specs(AckCache())
    expected = {
        # Diagnostic / read-only — see the vendor side
        "list_integrations",
        "get_integration",
        "get_integration_health",
        "get_integration_overview",
        "list_integration_alerts",
        "list_supported_platforms",
        "list_collector_vendors",
        "list_collection_state",
        "get_collector_summary",
        "list_drift_fields",
        "list_quarantine",
        "get_quarantine_event",
        "list_mappings",
        "get_mapping",
        "get_mapping_samples",
        "discover_mapping_fields",
        "diff_mapping_versions",
        "list_mapping_audit",
        "list_backfill_jobs",
        "get_backfill_job",
        "backfill_diagnostics",
        "get_collector_cost_summary",
        # Pipeline health
        "get_pipeline_health",
        "get_integration_pipeline_health",
        # Destinations + lineage (ADR-0003/0008)
        "list_destinations",
        "get_destinations_health",
        "get_destination_health",
        "list_destination_dlq",
        "get_destination_metrics",
        "list_destination_audit",
        "list_destination_lineage",
        "get_event_lineage",
        # Routing (ADR-0008)
        "list_routes",
        "get_routes_topology",
        "get_routes_flow",
        "get_route_health",
        "get_route_metrics",
        # Detections
        "list_detections",
        "get_detection",
        # Dashboard
        "get_dashboard_summary",
        # Queries / search / audit history
        "list_scheduled_queries",
        "get_scheduled_query_history",
        "list_search_history",
        "get_search_result",
        "list_audit_log",
        "get_query_capabilities",
        # Mutating — safe
        "dry_run_mapping",
        "request_backfill",
        "reprocess_quarantine",
        "cancel_backfill_job",
        # Destructive — gated
        "commit_mapping",
        # Helper
        "wait_for_backfill_job",
        # Sophos-specific
        "get_sophos_licenses",
    }
    assert set(specs.keys()) == expected


def test_every_spec_has_object_schema_with_no_extra_props():
    specs = _build_specs(AckCache())
    for name, spec in specs.items():
        assert spec.input_schema["type"] == "object", name
        assert spec.input_schema.get("additionalProperties") is False, name
        assert spec.description, f"{name} must have description"


def test_destructive_tool_requires_ack_token():
    specs = _build_specs(AckCache())
    commit = specs["commit_mapping"]
    required = set(commit.input_schema["required"])
    assert {"definition_id", "rules", "commit_message", "ack_token"} <= required
