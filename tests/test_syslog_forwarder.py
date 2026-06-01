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
