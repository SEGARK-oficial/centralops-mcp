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
        # Mutating — safe
        "dry_run_mapping",
        "request_backfill",
        "reprocess_quarantine",
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
