# CEF Syslog Forwarder — Design Spec

**Date:** 2026-06-01
**Status:** Draft
**Scope:** Forward prompt evaluation events from in-memory log to syslog in CEF format

---

## Problem

RAMPART captures prompt evaluation events in an in-memory ring buffer. Security teams need these events forwarded to Splunk (or other SIEM) via syslog for centralized monitoring, alerting, and compliance reporting.

## Overview

A background syslog forwarder reads new entries from the in-memory prompt log and sends them as CEF-formatted messages to a configurable syslog destination. Supports both direct-to-Splunk (TCP/UDP) and local syslog relay configurations. Fully configurable and enable/disable via the admin UI settings page.

## CEF Message Format

```
CEF:0|Engineering|RAMPART|0.1.0|prompt-eval|Prompt Evaluation|<severity>|<extensions>
```

**Header fields:**
- Vendor: `Engineering`
- Product: `RAMPART`
- Version: from app config (`0.1.0`)
- Event ID: `prompt-eval`
- Event Name: `Prompt Evaluation`
- Severity: mapped from RAMPART decision (see below)

**Extension fields:**
- `rt` — event timestamp (epoch ms)
- `src` — source IP of the request
- `duser` — user field (email) if present
- `cs1` / `cs1Label=decision` — accept or fail
- `cs2` / `cs2Label=source` — api, gateway, or playground
- `cs3` / `cs3Label=model` — requested model
- `cs4` / `cs4Label=policyResults` — JSON array of per-policy pass/fail results
- `cs5` / `cs5Label=resolvedGroups` — external group memberships if resolved
- `cs6` / `cs6Label=rampartGroups` — mapped RAMPART group IDs
- `msg` — first user message content (truncated to 1024 chars)
- `outcome` — accept or fail
- `deviceCustomString1` through `deviceCustomString6` used as above

## Severity Mapping

| RAMPART Decision | Highest Violation Severity | CEF Severity |
|---|---|---|
| accept (no violations) | — | 1 |
| accept (warnings only) | — | 3 |
| fail | medium | 5 |
| fail | high | 7 |
| fail | critical | 9 |

The severity is the highest severity among all violations for a failed evaluation.

## Architecture

**Background task** runs on app startup (same pattern as cache persistence):
1. Polls on a configurable interval (default 5 seconds)
2. Reads new entries from the prompt log ring buffer using a cursor
3. Formats each entry as a CEF syslog message
4. Sends via TCP or UDP socket to configured host:port
5. On connection failure: logs warning, skips entries (does not block evaluations)

**Cursor tracking:** The prompt log module exposes a `get_entries_since(cursor)` method that returns new entries and an updated cursor. The forwarder maintains its cursor across poll cycles.

## Configuration

Added to config and runtime settings:

```yaml
syslog:
  enabled: false
  protocol: "udp"  # "tcp" or "udp"
  host: "127.0.0.1"
  port: 514
  send_interval_seconds: 5
```

**Environment variable overrides:**
- `RAMPART_SYSLOG_ENABLED`
- `RAMPART_SYSLOG_PROTOCOL`
- `RAMPART_SYSLOG_HOST`
- `RAMPART_SYSLOG_PORT`

## Admin UI

New fieldset in `/ui/settings` (alongside existing LLM, Vision, Upstream, MCP, User Group Resolver sections):

- Enable/disable toggle
- Protocol dropdown (TCP / UDP)
- Host input
- Port input
- Send interval (seconds)

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Syslog destination unreachable | Log warning, skip entries, retry next cycle |
| TCP connection dropped | Reconnect on next cycle |
| Malformed entry data | Skip entry, continue with next |
| Forwarder disabled | Background task exits immediately |
| Buffer wraps while forwarder is behind | Cursor resets, some entries may be missed (acceptable for best-effort delivery) |

## New Files

| File | Purpose |
|------|---------|
| `rampart/app/syslog_forwarder.py` | CEF formatting, socket send, background loop |

## Modified Files

| File | Change |
|------|--------|
| `rampart/app/prompt_log.py` | Add cursor-based `get_entries_since()` method |
| `rampart/app/config.py` | Add `SyslogConfig` model, add to `AppConfig`, env overrides |
| `rampart/app/settings_store.py` | Add syslog fields to `RuntimeSettings` |
| `rampart/app/main.py` | Start syslog forwarder background task on startup |
| `rampart/app/ui.py` | Add Syslog Forwarder fieldset to `/ui/settings`, update POST handler |
