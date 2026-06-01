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


from rampart.app.prompt_log import PolicyResult, PromptLogEntry
from rampart.app.syslog_forwarder import format_cef, map_severity


def test_map_severity_accept():
    assert map_severity("accept", []) == 1


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
    assert "msg=" + "A" * 1024 in cef
    assert "A" * 1025 not in cef
