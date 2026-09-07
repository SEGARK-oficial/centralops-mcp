"""Contract: capability hints must match what the tools actually do.

An agent decides whether a tool is safe to call from ``ToolAnnotations``. A
write tool that forgets to declare itself is advertised as read-only, which is
exactly the failure mode these tests exist to prevent — so the source of truth
here is the HTTP verb in the handler module, not a hand-maintained list.
"""

from __future__ import annotations

import inspect
import re

import pytest

from centralops_mcp.ack_cache import AckCache
from centralops_mcp.server import SERVER_INSTRUCTIONS, _build_specs


#: Every tool that changes server-side state. ``dry_run_mapping`` is deliberately
#: absent: it POSTs but persists nothing, so it is genuinely read-only.
WRITE_TOOLS = {
    "commit_mapping",
    "commit_mapping_patch",
    "request_backfill",
    "cancel_backfill_job",
    "reprocess_quarantine",
}

#: Writes whose effect is not undone by calling them again.
NON_IDEMPOTENT_TOOLS = {"commit_mapping", "commit_mapping_patch", "request_backfill"}

#: POST but read-only: they compute and stage, they never persist.
READ_ONLY_POSTERS = {"dry_run_mapping", "patch_mapping_rules", "preview_correlation_rule"}

_MUTATING_CALL = re.compile(r"client\.(post|put|patch|delete)\(")


@pytest.fixture(scope="module")
def specs():
    return _build_specs(AckCache())


def test_write_tools_are_not_advertised_as_read_only(specs):
    for name in WRITE_TOOLS:
        assert specs[name].read_only is False, (
            f"{name} changes state but is advertised read_only=True — an agent "
            f"would treat it as safe to call while exploring"
        )
        assert specs[name].destructive is True, f"{name} should be destructive"


def test_non_idempotent_tools_are_declared(specs):
    for name in NON_IDEMPOTENT_TOOLS:
        assert specs[name].idempotent is False, (
            f"{name} creates a new record per call; declaring it idempotent "
            f"invites a retry that duplicates it"
        )


def test_everything_else_is_read_only(specs):
    for name, spec in specs.items():
        if name in WRITE_TOOLS:
            continue
        assert spec.read_only is True, (
            f"{name} is not in WRITE_TOOLS but declares read_only=False. If it "
            f"really writes, add it to WRITE_TOOLS so the contract stays honest."
        )
        assert spec.destructive is False


def test_handlers_that_mutate_are_declared_as_writes(specs):
    """Catches the real regression: a new tool POSTs but forgets the flags.

    Reads the handler's defining module rather than trusting the flag, so a tool
    added later cannot silently ship as read-only.
    """
    for name, spec in specs.items():
        if name in WRITE_TOOLS or name in READ_ONLY_POSTERS:
            continue
        try:
            source = inspect.getsource(inspect.unwrap(spec.handler))
        except (OSError, TypeError):  # pragma: no cover - defensive
            continue
        assert not _MUTATING_CALL.search(source), (
            f"{name} issues a mutating HTTP call but is not declared a write "
            f"tool. Set read_only=False/destructive=True and add it to "
            f"WRITE_TOOLS."
        )


@pytest.mark.parametrize("name", sorted(READ_ONLY_POSTERS))
def test_read_only_posters_are_declared_read_only(specs, name):
    """The intentional exceptions: they POST, but persist nothing.

    `dry_run_mapping` evaluates rules; `patch_mapping_rules` merges and stages
    them in this process; `preview_correlation_rule` evaluates candidate clauses
    against samples and creates no Detection, no counter and no dedup entry.
    None of them writes to the platform.
    """
    assert specs[name].read_only is True
    assert specs[name].destructive is False


def test_dry_run_description_disclaims_ocsf_conformance(specs):
    """The trap that made an agent report conformance it never measured."""
    description = specs["dry_run_mapping"].description
    assert "ocsf_validation_stats" in description
    assert "mapped_field_ratio" in description


def test_get_mapping_warns_that_disk_defaults_diverge(specs):
    """Live rules are the source of truth; repo JSON files are not."""
    description = specs["get_mapping"].description.lower()
    assert "source of truth" in description
    assert "diverge" in description


def test_source_grammar_documents_jmespath_and_extracted_prefix(specs):
    """`source` accepts full JMESPath and `_` switches the root — both were
    undocumented, so generated rules never used either."""
    schema = specs["dry_run_mapping"].input_schema["properties"]["rules"]
    description = schema["description"]
    assert "JMESPath" in description
    assert "fast" in description.lower()  # the performance caveat
    assert "extracted" in description  # the `_` prefix convention


def test_server_instructions_cover_scope_and_writes():
    assert "organization_id" in SERVER_INSTRUCTIONS
    for name in WRITE_TOOLS:
        assert name in SERVER_INSTRUCTIONS, (
            f"{name} changes state but is not called out in the server "
            f"instructions an agent reads on initialize"
        )
