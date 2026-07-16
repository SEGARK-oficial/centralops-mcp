<div align="center">

# CentralOps MCP Server

**Drive the [CentralOps](https://github.com/SEGARK-oficial/CentralOps) security data pipeline from any MCP client — drift triage, mapping edits, routing forensics, backfills and quarantine reprocess without writing raw HTTP calls.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-informational)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/protocol-Model_Context_Protocol-8A2BE2)](https://modelcontextprotocol.io)
[![Docs](https://img.shields.io/badge/docs-docs.segark.com-informational)](https://docs.segark.com)

</div>

---

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes a
curated subset of the CentralOps HTTP API as **53 typed tools**, so an AI agent
(Claude Code, or any MCP client) can operate the pipeline like a SOC engineer:
inspect what a vendor is actually sending, author and dry-run mapping rules, follow
an event's delivery lineage, and reprocess quarantined events — with the destructive
operation gated behind an explicit two-step acknowledgement.

The server runs as a **stdio transport inside a container**: the MCP client spawns
`docker run --rm -i ...` per session. No extra service in your CentralOps stack, no
port exposed.

## Quick start

```bash
# 1. Build the image (from the repo root)
docker build -t centralops-mcp:dev .

# 2. Generate a CentralOps API token (PAT) at  <your-centralops-host>/settings/tokens

# 3. Register the server in your MCP client — e.g. .mcp.json for Claude Code:
```

```json
{
  "mcpServers": {
    "centralops": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "CENTRALOPS_BASE_URL",
        "-e", "CENTRALOPS_API_TOKEN",
        "centralops-mcp:dev"
      ],
      "env": {
        "CENTRALOPS_BASE_URL": "https://centralops.example.com/api",
        "CENTRALOPS_API_TOKEN": "copsk_..."
      }
    }
  }
}
```

Restart the client and run `/mcp` (Claude Code) to confirm the tools are listed.

> [!WARNING]
> The token is sensitive — do not commit `.mcp.json` with a real value. Prefer
> reading it from your shell (`CENTRALOPS_API_TOKEN=$(pbpaste)`) or a secret
> manager (1Password, macOS Keychain, …).

## Tools

53 tools, grouped by what they let the agent see or do. Everything is read-only
except the five tools listed under **Mutating** and **Destructive**.

### Vendor-side visibility

How each vendor is connected, healthy and behaving.

| Tool | Purpose |
| --- | --- |
| `list_integrations` | Vendors connected — status, last_error, capabilities. Filterable (`platform`, `organization_id`, `name`) and paginated (`page`/`size`). |
| `get_integration` | One integration's configuration. Config fields need `secret.read`; real secrets are never returned. |
| `get_integration_health` | Live health check — v2 envelope with data-driven `metrics[]` (`id`, `label`, `value`, `severity`). |
| `get_integration_overview` | Serialized integration + live health + 5-alert preview + `licensed_products` (Sophos child tenants). |
| `list_integration_alerts` | **Live** query against the vendor's own alert store (e.g. Wazuh Indexer), with severity/host/rule/time filters. |
| `list_supported_platforms` | Platform identifiers from the plugin-driven provider registry. |
| `get_sophos_licenses` | Licensed Sophos products for a child tenant (e.g. explain a 403 on detections). |

### Collection pipeline

What is being polled, from where, and at what cost.

| Tool | Purpose |
| --- | --- |
| `list_collector_vendors` | (platform, stream) pairs the collector registry knows how to poll. |
| `list_collection_state` | Per-stream cursor, last_success_at, last_error, consecutive_failures (`include_inactive` to see disabled rows). |
| `get_collector_summary` | Global counters, failing streams, max staleness — the first read in a triage session. |
| `get_collector_cost_summary` | ADR-0011 volume metering: bytes/events in vs out per org, reduction ratio. |
| `get_pipeline_health` | Bulk pipeline health for all visible integrations (60s cache). |
| `get_integration_pipeline_health` | One integration: status, lag, `mapped_field_ratio`, drift/quarantine counts (24h). |

### Raw payloads & drift — *"what is the vendor actually sending?"*

| Tool | Purpose |
| --- | --- |
| `get_mapping_samples` | Raw events from the sample reservoir for a (vendor, event_type). Global-scope tokens must pass `organization_id`. |
| `get_quarantine_event` | One quarantined event with its full `raw_payload`. |
| `list_quarantine` | Quarantined events — filter by vendor, error_kind, lifecycle `status` (pending/reprocessed/all), integration. |
| `list_drift_fields` | Unknown raw fields observed by the drift sampler (`status`: new/ignored/mapped). |
| `discover_mapping_fields` | Fields already discovered for a mapping — JMESPath autocomplete source. |

### Mappings catalog & history

| Tool | Purpose |
| --- | --- |
| `list_mappings` | Catalog of mapping definitions (`only_active` mirrors the UI default). |
| `get_mapping` | Definition + full version history. |
| `diff_mapping_versions` | Structured diff between two versions. |
| `list_mapping_audit` | Who changed what, when — filterable by action/user/time. |

### Destinations & routing (ADR-0003/0008)

Where events go, and why one didn't. All of these require an admin token.

| Tool | Purpose |
| --- | --- |
| `list_destinations` | Configured destinations with status. |
| `get_destinations_health` / `get_destination_health` | Delivery health, batch or per destination. |
| `list_destination_dlq` | Dead-letter queue — error kinds like `unrouted`, `destination_missing`, `cross_tenant_destination`. |
| `get_destination_metrics` | Delivery metrics time series. |
| `list_destination_audit` | Audit trail for a destination. |
| `get_event_lineage` / `list_destination_lineage` | **"Where did event X actually get delivered?"** — per-event delivery lineage. |
| `list_routes` | Routing rules (first-match order). |
| `get_routes_topology` / `get_routes_flow` | Route→destination topology and live flow graph. |
| `get_route_health` / `get_route_metrics` | Per-route matched/routed/dropped counters and series. |

### Detections, dashboard & history

| Tool | Purpose |
| --- | --- |
| `list_detections` / `get_detection` | In-pipeline detections (status: open/ack/closed, OCSF severity). |
| `get_dashboard_summary` | The UI's opening dashboard: KPIs + top-N buckets, org/platform/period filters. |
| `list_scheduled_queries` / `get_scheduled_query_history` | Scheduled queries and their run history. |
| `list_search_history` / `get_search_result` | Saved search runs and their results. |
| `list_audit_log` | Platform audit log (admin token). |
| `get_query_capabilities` | Which query dialects/modes each source platform supports. |

### Backfill

| Tool | Purpose |
| --- | --- |
| `list_backfill_jobs` | Jobs for an integration, filterable by status. |
| `get_backfill_job` | One job: `progress_pct`, events collected/dispatched, `stalled`/`stall_reason`. |
| `wait_for_backfill_job` | Server-side poll until terminal state — avoids LLM polling loops. |
| `backfill_diagnostics` | "Why does backfill never run?" — workers, queue consumers, backlog (global admin). |

### Mutating — safe

| Tool | Purpose |
| --- | --- |
| `dry_run_mapping` | Validate rules against the sample reservoir; issues the `ack_token` needed by `commit_mapping`. |
| `request_backfill` | Enqueue a backfill window (≤ 90 days). |
| `cancel_backfill_job` | Cooperatively cancel a pending/running job. |
| `reprocess_quarantine` | Reprocess up to 50 quarantined events through the destination routing engine. Idempotent (409/410/422 per event). |

### Destructive — gated

| Tool | Purpose |
| --- | --- |
| `commit_mapping` | Promote a new mapping version. Requires a fresh `ack_token` from `dry_run_mapping` for the same definition and rules. |

`commit_mapping` is the only destructive tool. The `ack_token` expires in 5 minutes
and is single-use; the backend re-validates and re-runs the dry-run on commit, so
the token is defense-in-depth, not the security boundary.

## Authentication

The server authenticates with a CentralOps **Personal Access Token (PAT)** or
**Service Account token** — the same credential model used by external
integrations — and sends `Authorization: Bearer <token>` on every request.

1. Log in to CentralOps as the user that should "own" the MCP traffic.
2. Go to **Settings → API Tokens** (`/settings/tokens` on your CentralOps host —
   *not* under `/api`).
3. Create a token, pick an expiration, and **copy the `copsk_…` value once** —
   the UI will not show it again.
4. Optional: restrict scopes. Without scopes the token inherits the full
   permission set of the user. For a read-mostly MCP, e.g.:
   `mapping.read`, `quarantine.read`, `integration.read`, `audit.read`.
5. Export the token in your shell or paste it into the MCP config above.

Tokens are individually revocable from the same page. The client identifies
itself with `User-Agent: centralops-mcp/<version>` (persisted by the backend
audit log, so MCP traffic is distinguishable from UI traffic) plus an
informational `X-Client` header.

When a token is rejected you get a 401 with a regeneration hint; a valid token
missing a scope gets a 403 with a permission hint. Tools that need an admin
token say so in their descriptions.

## Configuration

| Env var | Default | Required | Notes |
| --- | --- | --- | --- |
| `CENTRALOPS_BASE_URL` | `http://localhost:3000/api` | recommended | Trailing `/api` is part of the URL. |
| `CENTRALOPS_API_TOKEN` | — | **yes** | PAT or Service Account token starting with `copsk_`. |
| `CENTRALOPS_TIMEOUT_S` | `30` | no | Per-request timeout. |
| `CENTRALOPS_VERIFY_TLS` | `1` | no | Set to `0` only for self-signed dev environments. |
| `CENTRALOPS_LOG_LEVEL` | `WARNING` | no | `DEBUG` traces requests on stderr. |

## Development

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest pytest-asyncio
.venv/bin/pytest
```

The contract test suite mocks the HTTP transport — no CentralOps instance is
needed to develop or test.

### Smoke test the image

The MCP handshake is `initialize` → `notifications/initialized` → `tools/list`.
The trailing `sleep` keeps stdin open long enough for the second response:

```bash
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 2
} | docker run --rm -i \
      -e CENTRALOPS_BASE_URL="http://localhost:3000/api" \
      -e CENTRALOPS_API_TOKEN="copsk_..." \
      centralops-mcp:dev
```

You should see two JSON-RPC responses; the second lists all 53 tools with their
schemas.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Keep tool descriptions **honest** — they must describe the real backend
   behavior (response fields, permission requirements, org-scoping caveats).
   Every claim in a description should be verifiable in the CentralOps code.
2. Add a contract test for every new tool (see `tests/contract/`) asserting the
   exact method, path, forwarded params and dropped `None` params.
3. Read-only by default. Mutating tools need a clear safety story; destructive
   tools must be gated like `commit_mapping`.
4. Run `.venv/bin/pytest` — the suite must be green.

## License

[Apache-2.0](LICENSE) © SEGARK.

The CentralOps engine itself is a separate project licensed under
[AGPL-3.0](https://github.com/SEGARK-oficial/CentralOps/blob/main/LICENSE).
