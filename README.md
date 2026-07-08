# CentralOps MCP Server

Model Context Protocol (MCP) server that exposes a curated subset of the CentralOps
HTTP API as typed tools, so internal developers can drive drift triage, mapping
edits, backfill jobs and quarantine reprocess from Claude Code without writing raw
HTTP calls.

The server runs as a stdio MCP transport inside a container — Claude Code spawns
`docker run --rm -i ...` per session, no extra service is added to the CentralOps
compose stack, no port is exposed.

## Status

Stable for internal use. Authenticates with a CentralOps **Personal Access Token
(PAT)** or **Service Account token** issued at `/settings/tokens` — the same
credential model used by external integrations. Cookie/session auth was removed
in Fase 2 (commit history under `feat(pat): …`).

## Tools

25 tools, grouped by what they let the agent see or do.

### Vendor-side visibility (read)

How the vendor is connected, healthy and behaving.

| Tool | Purpose |
| --- | --- |
| `list_integrations` | Vendors connected, status, last_error, capabilities. |
| `get_integration` | Full configuration of one integration (secrets masked unless permitted). |
| `get_integration_health` | Live health check (manager + indexer for Wazuh, OAuth for Sophos…). |
| `get_integration_overview` | Aggregated dashboard: counters, recent activity, per-stream summary. |
| `list_integration_alerts` | Alerts already collected and normalized for an integration. |
| `list_supported_platforms` | Platforms the backend can connect to. |

### Collection pipeline (read)

What is being polled and from where.

| Tool | Purpose |
| --- | --- |
| `list_collector_vendors` | (platform, stream) pairs the collector knows how to poll. |
| `list_collection_state` | Per-stream cursor, last_success_at, last_error, consecutive_failures. |
| `get_collector_summary` | Global view across all integrations the user can see. |

### Raw payloads & drift (read — *the "what is the vendor sending?" set*)

| Tool | Purpose |
| --- | --- |
| `get_mapping_samples` | Raw events from the sample reservoir for a (vendor, event_type) — the actual JSON the collector received. |
| `get_quarantine_event` | One quarantined event with its full `raw_payload` — useful when a specific shape broke a mapping. |
| `list_quarantine` | Quarantined events, filterable by vendor/integration/error_kind. |
| `list_drift_fields` | Unknown raw fields the drift sampler observed but no mapping consumes. |
| `discover_mapping_fields` | Fields already discovered for this mapping's vendor/event_type — JMESPath autocomplete source. |

### Mappings catalog & history (read)

| Tool | Purpose |
| --- | --- |
| `list_mappings` | Catalog of mapping definitions. |
| `get_mapping` | Definition + version history for a single mapping. |
| `diff_mapping_versions` | Structured diff between two versions of a mapping. |
| `list_mapping_audit` | Who changed what, when. |

### Backfill (read)

| Tool | Purpose |
| --- | --- |
| `list_backfill_jobs` | Jobs for an integration. |
| `get_backfill_job` | One job snapshot. |

### Mutating — safe

| Tool | Purpose |
| --- | --- |
| `dry_run_mapping` | Validate rules against the sample reservoir. Issues an `ack_token` when called with `definition_id`. |
| `request_backfill` | Enqueue a backfill window (max 90 days). Returns `job_id`. |
| `reprocess_quarantine` | Reprocess up to 50 quarantined events. Backend is idempotent. |

### Destructive — gated

| Tool | Purpose |
| --- | --- |
| `commit_mapping` | Promote a new mapping version. Requires a fresh `ack_token` from `dry_run_mapping` for the same definition_id and rules. |

### Helper

| Tool | Purpose |
| --- | --- |
| `wait_for_backfill_job` | Server-side poll until terminal state. Avoids LLM polling loops. |

`commit_mapping` is the only destructive tool. It requires an `ack_token` issued
by `dry_run_mapping` for the same `definition_id` and rules; the token expires in
5 minutes and is single-use. The CentralOps backend re-validates and re-runs the
dry-run on commit, so this is defense-in-depth, not the security boundary.

## Authentication

The MCP server sends `Authorization: Bearer <token>` on every request. Generate
the token in CentralOps:

1. Log in to CentralOps as the user that should "own" the MCP traffic.
2. Go to **Settings → API Tokens** (`/settings/tokens`).
3. Click **Criar token**, give it a name (e.g. `claude-code-mcp`), pick an
   expiration (or "Nunca" for a stable dev workflow), and **copy the
   `copsk_…` value once** — the UI will not show it again.
4. Optional: select scopes. Without scopes the token inherits the full
   permission set of the user. For an MCP that only needs to read drift /
   mappings, restrict to e.g. `mappings.read`, `quarantine.read`,
   `integrations.read`, `audit.read`.
5. Export the token in your shell or paste it into the MCP config below.

Tokens are revocable individually from the same page — losing the laptop or
ending the contract no longer means rotating a shared cookie.

A `X-Client: centralops-mcp/<version>` header is sent on every request so the
backend audit log can distinguish MCP traffic from UI traffic.

When the token is rejected the tool returns a 401 with a hint to regenerate at
`/settings/tokens`. When the token is *valid* but lacks the scope a tool
requires, the response is 403 with a permission hint.

## Configuration

| Env var | Default | Required | Notes |
| --- | --- | --- | --- |
| `CENTRALOPS_BASE_URL` | `http://localhost:3000/api` | recommended | Trailing `/api` is part of the URL. |
| `CENTRALOPS_API_TOKEN` | — | **yes** | PAT or Service Account token starting with `copsk_`. Generated at `<base_url>/settings/tokens`. |
| `CENTRALOPS_TIMEOUT_S` | `30` | no | Per-request timeout. |
| `CENTRALOPS_VERIFY_TLS` | `1` | no | Set to `0` only for self-signed dev environments. |
| `CENTRALOPS_LOG_LEVEL` | `WARNING` | no | `DEBUG` to trace requests on stderr. |

## Build

```bash
docker build -t centralops-mcp:dev mcp/
```

## Use from Claude Code

Add to `.mcp.json` (project) or your Claude Code user settings:

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
        "CENTRALOPS_BASE_URL": "https://centralops.local/api",
        "CENTRALOPS_API_TOKEN": "copsk_..."
      }
    }
  }
}
```

Then restart Claude Code and run `/mcp` to confirm the tools are listed.

> The token is sensitive — do not commit `.mcp.json` with a real value. Prefer
> reading from your shell, e.g. `CENTRALOPS_API_TOKEN=$(pbpaste)`, or store it
> in a secret manager (1Password, macOS Keychain, etc).

## Local development

```bash
cd mcp
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pytest pytest-asyncio
.venv/bin/pytest
```

## Smoke test the image

The MCP handshake requires `initialize` → `notifications/initialized` →
`tools/list`. The trailing `sleep` keeps stdin open long enough for the server
to emit the second response before EOF closes the pipe:

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

You should see two JSON-RPC responses; the second contains all 11 tools with
their schemas.
