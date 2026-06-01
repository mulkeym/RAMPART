# CEF Syslog Forwarder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Forward prompt evaluation events from RAMPART's in-memory log to a syslog destination in CEF format.

**Architecture:** A background async task polls new prompt log entries via cursor, formats each as a CEF syslog message, and sends over TCP or UDP socket. Fully configurable and toggle-able via admin UI settings.

**Tech Stack:** Python socket module (TCP/UDP), CEF format string, existing prompt_log ring buffer, FastAPI startup events.

---

## File Structure

**New files:**
| File | Responsibility |
|------|---------------|
| `rampart/app/syslog_forwarder.py` | CEF formatting, socket send, cursor tracking, background loop |
| `tests/test_syslog_forwarder.py` | Tests for CEF formatting, severity mapping, cursor reads |

**Modified files:**
| File | Change |
|------|--------|
| `rampart/app/prompt_log.py` | Add `get_entries_since(cursor)` cursor-based read |
| `rampart/app/config.py` | Add `SyslogConfig` model, add to `AppConfig`, env overrides |
| `rampart/app/settings_store.py` | Add syslog fields to `RuntimeSettings` |
| `rampart/app/main.py` | Start syslog forwarder background task |
| `rampart/app/ui.py` | Add Syslog Forwarder fieldset to settings, update POST handler |

---

### Task 1: Cursor-Based Read for Prompt Log

**Files:**
- Modify: `rampart/app/prompt_log.py`
- Test: `tests/test_syslog_forwarder.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_syslog_forwarder.py
import pytest
from rampart.app.prompt_log import PromptLogEntry, log_prompt, get_entries_since, clear


@pytest.fixture(autouse=True)
def _clear_log():
    clear()
    yield
    clear()


def test_get_entries_since_empty():
    entries, cursor = get_entries_since(0)
    assert entries == []
    assert cursor == 0


def test_get_entries_since_returns_new():
    log_prompt(PromptLogEntry(source="api", decision="accept"))
    log_prompt(PromptLogEntry(source="api", decision="fail"))
    entries, cursor = get_entries_since(0)
    assert len(entries) == 2
    assert entries[0].decision == "accept"
    assert entries[1].decision == "fail"
    assert cursor == 2


def test_get_entries_since_skips_already_read():
    log_prompt(PromptLogEntry(source="api", decision="accept"))
    log_prompt(PromptLogEntry(source="api", decision="fail"))
    _, cursor = get_entries_since(0)
    log_prompt(PromptLogEntry(source="playground", decision="accept"))
    entries, cursor2 = get_entries_since(cursor)
    assert len(entries) == 1
    assert entries[0].source == "playground"
    assert cursor2 == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_syslog_forwarder.py -v`
Expected: FAIL — `get_entries_since` not found

- [ ] **Step 3: Add `get_entries_since` to `prompt_log.py`**

Add after the existing `get_entries` function:

```python
def get_entries_since(cursor: int) -> tuple[list[PromptLogEntry], int]:
    """Return entries added since cursor position. Returns (entries, new_cursor).

    Cursor is the total number of entries ever appended. If the buffer has
    wrapped past the cursor, returns all current entries and resets cursor.
    """
    total_appended = _total_appended
    if cursor >= total_appended:
        return [], cursor
    buf_list = list(_buffer)
    available = total_appended - cursor
    if available > len(buf_list):
        # Buffer wrapped past our cursor — return everything we have
        return buf_list, total_appended
    return buf_list[-available:], total_appended
```

Also add a counter that tracks total appends. Modify the module-level state and `log_prompt`:

```python
_total_appended: int = 0


def log_prompt(entry: PromptLogEntry) -> None:
    global _total_appended
    if not entry.timestamp:
        entry.timestamp = datetime.now(timezone.utc).isoformat()
    _buffer.append(entry)
    _total_appended += 1
```

Update `clear()` to also reset the counter:

```python
def clear() -> None:
    global _total_appended
    _buffer.clear()
    _total_appended = 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_syslog_forwarder.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/prompt_log.py tests/test_syslog_forwarder.py
git commit -m "feat: add cursor-based get_entries_since to prompt log"
```

---

### Task 2: SyslogConfig Model

**Files:**
- Modify: `rampart/app/config.py`
- Test: `tests/test_syslog_forwarder.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_syslog_forwarder.py`:

```python
from rampart.app.config import SyslogConfig


def test_syslog_config_defaults():
    cfg = SyslogConfig()
    assert cfg.enabled is False
    assert cfg.protocol == "udp"
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 514
    assert cfg.send_interval_seconds == 5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_syslog_forwarder.py::test_syslog_config_defaults -v`
Expected: FAIL — cannot import SyslogConfig

- [ ] **Step 3: Add SyslogConfig to `config.py`**

Add before `AppConfig`:

```python
class SyslogConfig(BaseModel):
    enabled: bool = False
    protocol: str = "udp"
    host: str = "127.0.0.1"
    port: int = 514
    send_interval_seconds: int = 5
```

Add to `AppConfig`:

```python
    syslog: SyslogConfig = Field(default_factory=SyslogConfig)
```

Add to `_apply_env_overrides` at the end:

```python
    syslog = config.syslog
    syslog.enabled = _env_bool("RAMPART_SYSLOG_ENABLED", syslog.enabled)
    syslog.protocol = os.getenv("RAMPART_SYSLOG_PROTOCOL", syslog.protocol)
    syslog.host = os.getenv("RAMPART_SYSLOG_HOST", syslog.host)
    if os.getenv("RAMPART_SYSLOG_PORT"):
        syslog.port = int(os.getenv("RAMPART_SYSLOG_PORT"))
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_syslog_forwarder.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add rampart/app/config.py tests/test_syslog_forwarder.py
git commit -m "feat: add SyslogConfig model with env overrides"
```

---

### Task 3: CEF Formatter and Syslog Forwarder

**Files:**
- Create: `rampart/app/syslog_forwarder.py`
- Test: `tests/test_syslog_forwarder.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_syslog_forwarder.py`:

```python
from rampart.app.prompt_log import PolicyResult
from rampart.app.syslog_forwarder import format_cef, map_severity


def test_map_severity_accept():
    assert map_severity("accept", []) == 1


def test_map_severity_accept_with_warnings():
    assert map_severity("accept", [PolicyResult(status="pass")]) == 1


def test_map_severity_fail_medium():
    assert map_severity("fail", [PolicyResult(status="fail", severity="medium")]) == 5


def test_map_severity_fail_high():
    assert map_severity("fail", [PolicyResult(status="fail", severity="high")]) == 7


def test_map_severity_fail_critical():
    assert map_severity("fail", [PolicyResult(status="fail", severity="critical")]) == 9


def test_map_severity_fail_mixed_uses_highest():
    results = [
        PolicyResult(status="fail", severity="medium"),
        PolicyResult(status="fail", severity="critical"),
        PolicyResult(status="pass", severity="high"),
    ]
    assert map_severity("fail", results) == 9


def test_format_cef_basic():
    entry = PromptLogEntry(
        timestamp="2026-06-01T12:00:00+00:00",
        source="api",
        user="jsmith@dha.mil",
        source_ip="10.0.0.1",
        model="gpt-4",
        decision="fail",
        messages=[{"role": "user", "content": "test prompt"}],
        policy_results=[
            PolicyResult(policy_id="no-pii", status="fail", severity="high", action="block", message="PII detected"),
        ],
        resolved_groups=["DHA-Clinical"],
        mapped_rampart_groups=["clinical-staff"],
    )
    cef = format_cef(entry)
    assert cef.startswith("CEF:0|Engineering|RAMPART|")
    assert "|prompt-eval|Prompt Evaluation|7|" in cef
    assert "duser=jsmith@dha.mil" in cef
    assert "src=10.0.0.1" in cef
    assert "cs1=fail" in cef
    assert "cs2=api" in cef
    assert "cs3=gpt-4" in cef
    assert "no-pii" in cef
    assert "DHA-Clinical" in cef
    assert "clinical-staff" in cef
    assert "msg=test prompt" in cef


def test_format_cef_escapes_pipes():
    entry = PromptLogEntry(
        timestamp="2026-06-01T12:00:00+00:00",
        source="api",
        decision="accept",
        messages=[{"role": "user", "content": "test|with|pipes"}],
    )
    cef = format_cef(entry)
    assert "test\\|with\\|pipes" in cef


def test_format_cef_truncates_long_message():
    entry = PromptLogEntry(
        timestamp="2026-06-01T12:00:00+00:00",
        source="api",
        decision="accept",
        messages=[{"role": "user", "content": "A" * 2000}],
    )
    cef = format_cef(entry)
    # msg should be truncated to 1024 chars
    assert "msg=" + "A" * 1024 in cef
    assert "A" * 1025 not in cef
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_syslog_forwarder.py -v -k "cef or severity"`
Expected: FAIL — module not found

- [ ] **Step 3: Write implementation**

```python
# rampart/app/syslog_forwarder.py
"""CEF syslog forwarder for prompt evaluation events."""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

from rampart.app.prompt_log import PolicyResult, PromptLogEntry

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"low": 3, "medium": 5, "high": 7, "critical": 9}
_VERSION = "0.1.0"


def map_severity(decision: str, policy_results: list[PolicyResult]) -> int:
    if decision == "accept":
        has_warnings = any(pr.status == "fail" for pr in policy_results)
        return 3 if has_warnings else 1
    highest = "medium"
    for pr in policy_results:
        if pr.status == "fail" and _SEVERITY_MAP.get(pr.severity, 0) > _SEVERITY_MAP.get(highest, 0):
            highest = pr.severity
    return _SEVERITY_MAP.get(highest, 5)


def format_cef(entry: PromptLogEntry) -> str:
    severity = map_severity(entry.decision, entry.policy_results)
    extensions = _build_extensions(entry)
    return f"CEF:0|Engineering|RAMPART|{_VERSION}|prompt-eval|Prompt Evaluation|{severity}|{extensions}"


def _build_extensions(entry: PromptLogEntry) -> str:
    parts: list[str] = []
    if entry.timestamp:
        try:
            dt = datetime.fromisoformat(entry.timestamp)
            parts.append(f"rt={int(dt.timestamp() * 1000)}")
        except (ValueError, OSError):
            parts.append(f"rt={entry.timestamp}")
    if entry.source_ip:
        parts.append(f"src={_esc(entry.source_ip)}")
    if entry.user:
        parts.append(f"duser={_esc(entry.user)}")
    parts.append(f"cs1={_esc(entry.decision)}")
    parts.append("cs1Label=decision")
    parts.append(f"cs2={_esc(entry.source)}")
    parts.append("cs2Label=source")
    if entry.model:
        parts.append(f"cs3={_esc(entry.model)}")
        parts.append("cs3Label=model")
    if entry.policy_results:
        pr_json = json.dumps(
            [{"id": pr.policy_id, "s": pr.status, "sev": pr.severity} for pr in entry.policy_results],
            separators=(",", ":"),
        )
        parts.append(f"cs4={_esc(pr_json)}")
        parts.append("cs4Label=policyResults")
    if entry.resolved_groups:
        parts.append(f"cs5={_esc(','.join(entry.resolved_groups))}")
        parts.append("cs5Label=resolvedGroups")
    if entry.mapped_rampart_groups:
        parts.append(f"cs6={_esc(','.join(entry.mapped_rampart_groups))}")
        parts.append("cs6Label=rampartGroups")
    msg = _extract_user_message(entry.messages)
    if msg:
        parts.append(f"msg={_esc(msg[:1024])}")
    parts.append(f"outcome={_esc(entry.decision)}")
    return " ".join(parts)


def _extract_user_message(messages: list) -> str:
    for msg in messages:
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    return part["text"]
    return ""


def _esc(value: str) -> str:
    """Escape CEF special characters."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


class SyslogSender:
    """Sends CEF messages over TCP or UDP."""

    def __init__(self, host: str, port: int, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self._tcp_sock: Optional[socket.socket] = None

    def send(self, message: str) -> None:
        data = message.encode("utf-8")
        if self.protocol == "tcp":
            self._send_tcp(data)
        else:
            self._send_udp(data)

    def _send_udp(self, data: bytes) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (self.host, self.port))

    def _send_tcp(self, data: bytes) -> None:
        try:
            if self._tcp_sock is None:
                self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._tcp_sock.settimeout(5.0)
                self._tcp_sock.connect((self.host, self.port))
            self._tcp_sock.sendall(data + b"\n")
        except OSError:
            self._close_tcp()
            raise

    def _close_tcp(self) -> None:
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except OSError:
                pass
            self._tcp_sock = None

    def close(self) -> None:
        self._close_tcp()
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_syslog_forwarder.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/syslog_forwarder.py tests/test_syslog_forwarder.py
git commit -m "feat: add CEF syslog forwarder with severity mapping"
```

---

### Task 4: Settings Store + Config Wiring

**Files:**
- Modify: `rampart/app/settings_store.py`
- Modify: `rampart/app/config.py`

- [ ] **Step 1: Add syslog fields to `RuntimeSettings` in `settings_store.py`**

Add after the existing user_group_resolver fields:

```python
    # Syslog Forwarder
    syslog_enabled: Optional[bool] = None
    syslog_protocol: str = ""
    syslog_host: str = ""
    syslog_port: Optional[int] = None
    syslog_send_interval_seconds: Optional[int] = None
```

- [ ] **Step 2: Add `_apply_local_settings` entries in `config.py`**

Append at the end of `_apply_local_settings`:

```python
    if settings.syslog_enabled is not None:
        config.syslog.enabled = settings.syslog_enabled
    if settings.syslog_protocol:
        config.syslog.protocol = settings.syslog_protocol
    if settings.syslog_host:
        config.syslog.host = settings.syslog_host
    if settings.syslog_port is not None:
        config.syslog.port = settings.syslog_port
    if settings.syslog_send_interval_seconds is not None:
        config.syslog.send_interval_seconds = settings.syslog_send_interval_seconds
```

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add rampart/app/settings_store.py rampart/app/config.py
git commit -m "feat: wire syslog settings into RuntimeSettings and config"
```

---

### Task 5: Background Forwarder Task

**Files:**
- Modify: `rampart/app/main.py`

- [ ] **Step 1: Add syslog background task**

Add a new startup event handler after the existing `_start_cache_persistence`:

```python
@app.on_event("startup")
async def _start_syslog_forwarder():
    config = get_config()
    if not config.syslog.enabled:
        return
    from rampart.app.syslog_forwarder import SyslogSender, format_cef
    from rampart.app.prompt_log import get_entries_since

    sender = SyslogSender(config.syslog.host, config.syslog.port, config.syslog.protocol)
    interval = config.syslog.send_interval_seconds

    async def _forward_loop():
        cursor = 0
        while True:
            await asyncio.sleep(interval)
            try:
                entries, cursor = get_entries_since(cursor)
                for entry in entries:
                    try:
                        sender.send(format_cef(entry))
                    except OSError:
                        logger.warning("Syslog send failed to %s:%d, skipping batch", config.syslog.host, config.syslog.port)
                        break
            except Exception:
                logger.exception("Syslog forwarder error")

    asyncio.create_task(_forward_loop())
```

- [ ] **Step 2: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py
git commit -m "feat: add syslog forwarder background task"
```

---

### Task 6: Admin UI Settings Section

**Files:**
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add Syslog Forwarder fieldset to `_settings_form`**

Find the User Group Resolver `</fieldset>` closing tag (added in previous work). Insert a new fieldset after it, before the `<div class="actions">` save button:

```python
        <fieldset class="fieldset">
          <legend>Syslog Forwarder</legend>
          <div class="hint">Forward prompt evaluation events to a syslog server in CEF format for Splunk/SIEM integration.</div>
          <div>
            <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Enabled <input type="checkbox" name="syslog_enabled" {"checked" if config.syslog.enabled else ""} style="width:auto"></label>
            <div class="hint" style="margin-top:4px">When enabled, new prompt log entries are forwarded on a periodic interval. Requires server restart to take effect.</div>
          </div>
          <label>Protocol
            <select name="syslog_protocol">
              <option value="udp" {"selected" if config.syslog.protocol == "udp" else ""}>UDP</option>
              <option value="tcp" {"selected" if config.syslog.protocol == "tcp" else ""}>TCP</option>
            </select>
          </label>
          <label>Host<input name="syslog_host" value="{get_value("syslog_host", config.syslog.host)}" placeholder="127.0.0.1"></label>
          <label>Port<input name="syslog_port" value="{get_value("syslog_port", config.syslog.port)}" placeholder="514" inputmode="numeric"></label>
          <label>Send Interval (seconds)<input name="syslog_send_interval_seconds" value="{get_value("syslog_send_interval_seconds", config.syslog.send_interval_seconds)}" placeholder="5" inputmode="numeric"></label>
        </fieldset>
```

- [ ] **Step 2: Update `update_settings` POST handler**

Add to the `RuntimeSettings(...)` constructor call:

```python
            syslog_enabled=form.get("syslog_enabled") == "on",
            syslog_protocol=form.get("syslog_protocol", "").strip(),
            syslog_host=form.get("syslog_host", "").strip(),
            syslog_port=_optional_int(form.get("syslog_port", "")),
            syslog_send_interval_seconds=_optional_int(form.get("syslog_send_interval_seconds", "")),
```

(`_optional_int` was added in previous work — already exists.)

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat: add Syslog Forwarder section to /ui/settings"
```

- [ ] **Step 5: Push**

```bash
git push origin master
```
