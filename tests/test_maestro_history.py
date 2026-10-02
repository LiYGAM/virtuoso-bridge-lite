from __future__ import annotations

from types import SimpleNamespace

import pytest

from virtuoso_bridge.virtuoso.maestro.history import (
    MaestroHistoryError,
    MaestroHistoryOutcomeUnknown,
    get_history,
    list_histories,
    lock_history,
    set_history_lock,
    unlock_history,
)
from virtuoso_bridge.virtuoso.ops import escape_skill_string


TAG = "VB_MAESTRO_HISTORY_V1"
LOCK_TAG = "VB_MAESTRO_HISTORY_LOCK_V1"


def _inventory(*rows: str) -> str:
    return f'("{TAG}" "ok" ({" ".join(rows)}))'


def _row(name: str, *, locked: bool = False, current: bool = False) -> str:
    escaped_name = escape_skill_string(name)
    return f'("{escaped_name}" {"t" if locked else "nil"} {"t" if current else "nil"})'


class _Client:
    def __init__(self, *results) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, dict]] = []

    def execute_skill(self, expression: str, **kwargs):
        self.calls.append((expression, kwargs))
        if not self.results:
            raise AssertionError("unexpected execute_skill call")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _result(output: str = "nil", *, ok: bool = True, errors=()):
    return SimpleNamespace(ok=ok, output=output, errors=list(errors))


def test_list_histories_returns_lock_and_current_state() -> None:
    client = _Client(_result(_inventory(
        _row("Interactive.0", locked=True),
        _row("corner sweep", current=True),
    )))

    histories = list_histories(client, "fnxSession4")

    assert [item.model_dump() for item in histories] == [
        {"name": "Interactive.0", "locked": True, "current": False},
        {"name": "corner sweep", "locked": False, "current": True},
    ]
    skill, kwargs = client.calls[0]
    assert 'axlGetMainSetupDB("fnxSession4")' in skill
    assert "axlGetHistoryLock(vbEntry)" in skill
    assert "vbCurrent == vbEntry" in skill
    assert "axlGetHistoryCheckpoint" not in skill
    assert kwargs == {"timeout": 30}


def test_list_histories_accepts_empty_inventory() -> None:
    assert list_histories(_Client(_result(_inventory())), "fnxSession1") == []


@pytest.mark.parametrize(
    "payload",
    [
        "nil",
        f'("WRONG" "ok" nil)',
        f'("{TAG}" "ok" (("a" maybe nil)))',
        f'("{TAG}" "ok" (("a" (t) nil)))',
        f'("{TAG}" "ok" (("a" nil nil) ("a" t nil)))',
        f'("{TAG}" "unsupported" "axlGetHistory")',
        f'("{TAG}" "session_not_found" "missing")',
    ],
)
def test_list_histories_fails_closed_on_invalid_or_failed_payload(payload: str) -> None:
    with pytest.raises(MaestroHistoryError):
        list_histories(_Client(_result(payload)), "fnxSession1")


def test_list_histories_requires_explicit_session() -> None:
    client = _Client()
    with pytest.raises(ValueError, match="session"):
        list_histories(client, "")
    assert client.calls == []


def test_history_probe_escapes_session_name() -> None:
    client = _Client(_result(_inventory()))
    list_histories(client, 'session"\\name')
    assert 'session\\"\\\\name' in client.calls[0][0]


def test_get_history_uses_exact_name() -> None:
    client = _Client(_result(_inventory(
        _row("Interactive.1"),
        _row("Interactive.10", locked=True),
    )))
    assert get_history(client, "Interactive.1", session="s").name == "Interactive.1"


def test_get_history_rejects_missing_name() -> None:
    with pytest.raises(MaestroHistoryError, match="was not found"):
        get_history(
            _Client(_result(_inventory(_row("Interactive.10")))),
            "Interactive.1",
            session="s",
        )


def test_set_history_lock_is_idempotent() -> None:
    client = _Client(_result(_inventory(_row("Interactive.1", locked=True))))

    result = lock_history(client, "Interactive.1", session="s")

    assert result.outcome == "already_satisfied"
    assert result.changed is False
    assert len(client.calls) == 1


def test_set_history_lock_applies_and_verifies() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(f'("{LOCK_TAG}" "ok" t)'),
        _result(_inventory(_row("Interactive.1", locked=True))),
    )

    result = lock_history(client, "Interactive.1", session="fnxSession4")

    assert result.outcome == "applied"
    assert result.changed is True
    assert result.before.locked is False
    assert result.after.locked is True
    mutation_skill, kwargs = client.calls[1]
    assert 'maeSetHistoryLock("Interactive.1" t' in mutation_skill
    assert '?session "fnxSession4"' in mutation_skill
    assert kwargs == {"timeout": 30, "retry_connect": False}


def test_unlock_history_applies_nil_lock_value() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1", locked=True))),
        _result(f'("{LOCK_TAG}" "ok" t)'),
        _result(_inventory(_row("Interactive.1"))),
    )

    result = unlock_history(client, "Interactive.1", session="s")

    assert result.after.locked is False
    assert 'maeSetHistoryLock("Interactive.1" nil' in client.calls[1][0]


def test_lock_history_escapes_history_and_session() -> None:
    history = 'run"\\one'
    client = _Client(
        _result(_inventory(_row(history))),
        _result(f'("{LOCK_TAG}" "ok" t)'),
        _result(_inventory(_row(history, locked=True))),
    )

    lock_history(client, history, session='s"\\x')

    skill = client.calls[1][0]
    assert 'run\\"\\\\one' in skill
    assert 's\\"\\\\x' in skill


def test_set_history_lock_rejects_nil_setter_result() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(f'("{LOCK_TAG}" "ok" nil)'),
    )

    with pytest.raises(MaestroHistoryError, match="returned nil"):
        lock_history(client, "Interactive.1", session="s")

    assert len(client.calls) == 2


def test_set_history_lock_rejects_unsupported_setter_without_post_probe() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(f'("{LOCK_TAG}" "unsupported" "maeSetHistoryLock")'),
    )

    with pytest.raises(MaestroHistoryError, match="unsupported"):
        lock_history(client, "Interactive.1", session="s")

    assert len(client.calls) == 2


def test_set_history_lock_rejects_post_state_mismatch() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(f'("{LOCK_TAG}" "ok" t)'),
        _result(_inventory(_row("Interactive.1"))),
    )

    with pytest.raises(MaestroHistoryError, match="post-state mismatch"):
        lock_history(client, "Interactive.1", session="s")


def test_transport_timeout_can_be_confirmed_by_one_post_probe() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(ok=False, errors=["Socket timeout after 30s"]),
        _result(_inventory(_row("Interactive.1", locked=True))),
    )

    result = lock_history(client, "Interactive.1", session="s")

    assert result.outcome == "confirmed_after_unknown"
    assert len(client.calls) == 3


def test_transport_timeout_never_retries_unconfirmed_mutation() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(ok=False, errors=["Socket timeout after 30s"]),
        _result(_inventory(_row("Interactive.1"))),
    )

    with pytest.raises(MaestroHistoryOutcomeUnknown, match="outcome is unknown"):
        lock_history(client, "Interactive.1", session="s")

    assert len(client.calls) == 3
    assert sum("maeSetHistoryLock" in call[0] for call in client.calls) == 1


def test_post_probe_failure_is_unknown_not_retried() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        _result(f'("{LOCK_TAG}" "ok" t)'),
        _result(ok=False, errors=["Socket error: reset"]),
    )

    with pytest.raises(MaestroHistoryOutcomeUnknown, match="post-state"):
        lock_history(client, "Interactive.1", session="s")

    assert sum("maeSetHistoryLock" in call[0] for call in client.calls) == 1


def test_mutation_exception_is_queried_once_without_retry() -> None:
    client = _Client(
        _result(_inventory(_row("Interactive.1"))),
        TimeoutError("connection lost"),
        _result(_inventory(_row("Interactive.1", locked=True))),
    )

    result = lock_history(client, "Interactive.1", session="s")

    assert result.outcome == "confirmed_after_unknown"
    assert len(client.calls) == 3
    assert sum("maeSetHistoryLock" in call[0] for call in client.calls) == 1


def test_set_history_lock_requires_bool() -> None:
    client = _Client()
    with pytest.raises(TypeError, match="bool"):
        set_history_lock(client, "Interactive.1", "yes", session="s")
    assert client.calls == []
