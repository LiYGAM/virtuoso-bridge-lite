from __future__ import annotations

from types import SimpleNamespace

import pytest

from virtuoso_bridge.virtuoso.maestro import lifecycle
from virtuoso_bridge.virtuoso.maestro.reader.state import (
    MaestroSessionState,
    MaestroStateProbeError,
    get_session_state,
    list_session_states,
    parse_maestro_title,
)
class _Client:
    def __init__(self, *outputs: str, errors: list[str] | None = None) -> None:
        self.outputs = list(outputs)
        self.errors = errors or []
        self.calls: list[tuple[str, dict]] = []
        self.ssh_runner = None

    def execute_skill(self, expression: str, **kwargs):
        self.calls.append((expression, kwargs))
        output = self.outputs.pop(0) if self.outputs else "nil"
        return SimpleNamespace(ok=not self.errors, errors=self.errors, output=output)


@pytest.mark.parametrize(
    ("title", "application", "access", "unsaved"),
    [
        ("ADE Assembler Editing: LIB CELL maestro", "assembler", "editing", False),
        ("ADE Assembler Editing: LIB CELL maestro*", "assembler", "editing", True),
        ("ADE Explorer Reading: LIB CELL maestro", "explorer", "reading", False),
        (
            "ADE Assembler Editing: LIB CELL maestro* Version: 7 -CheckedOut",
            "assembler", "editing", True,
        ),
    ],
)
def test_parse_maestro_title_known_shapes(
    title: str, application: str, access: str, unsaved: bool,
) -> None:
    parsed = parse_maestro_title(title)

    assert parsed == {
        "application": application,
        "access": access,
        "unsaved": unsaved,
        "lib": "LIB",
        "cell": "CELL",
        "view": "maestro",
    }


def test_parse_maestro_title_does_not_guess_unknown_mode() -> None:
    assert parse_maestro_title("ADE Assembler Reviewing: LIB CELL maestro") is None
    assert parse_maestro_title("Virtuoso Schematic Editing: LIB CELL schematic") is None


def test_list_session_states_distinguishes_gui_and_headless() -> None:
    client = _Client(
        '("VB_MAESTRO_STATE_V1" '
        '((t 4 "ADE Assembler Editing: LIB CELL maestro* Version: 7 -CheckedOut" '
        '"fnxSession4" "fnxSession4")) '
        '("fnxSession4" "fnxSession9") 4 '
        '"ADE Assembler Editing: LIB CELL maestro* Version: 7 -CheckedOut")'
    )

    states = list_session_states(client)

    assert len(states) == 2
    assert states[0].model_dump() == {
        "context": "gui",
        "access": "editing",
        "unsaved": True,
        "session": "fnxSession4",
        "window_num": 4,
        "application": "assembler",
        "lib": "LIB",
        "cell": "CELL",
        "view": "maestro",
        "title": "ADE Assembler Editing: LIB CELL maestro* Version: 7 -CheckedOut",
        "current": True,
        "source": "window_title",
        "diagnostics": (),
    }
    assert states[1].context == "headless"
    assert states[1].access == "unknown"
    assert states[1].unsaved is None
    assert states[1].session == "fnxSession9"


def test_get_session_state_reports_non_maestro_current_window() -> None:
    client = _Client(
        '("VB_MAESTRO_STATE_V1" '
        '((t 2 "Virtuoso Schematic Editing: LIB CELL schematic" nil nil)) '
        'nil 2 "Virtuoso Schematic Editing: LIB CELL schematic")'
    )

    state = get_session_state(client)

    assert state.context == "non_maestro_window"
    assert state.window_num == 2
    assert state.unsaved is None


def test_get_session_state_reports_no_current_window() -> None:
    client = _Client('("VB_MAESTRO_STATE_V1" nil nil nil nil)')

    state = get_session_state(client)

    assert state.context == "no_window"
    assert state.unsaved is None


def test_window_session_disagreement_is_explicitly_unknown() -> None:
    client = _Client(
        '("VB_MAESTRO_STATE_V1" '
        '((t 4 "ADE Assembler Editing: LIB CELL maestro" '
        '"fnxSession4" "fnxSession5")) '
        '("fnxSession4" "fnxSession5") 4 '
        '"ADE Assembler Editing: LIB CELL maestro")'
    )

    states = list_session_states(client)

    assert {state.session for state in states} == {"fnxSession4", "fnxSession5"}
    assert all(state.context == "unknown" for state in states)
    assert all(state.unsaved is None for state in states)
    assert all("disagree" in state.diagnostics[0] for state in states)


def test_window_session_disagreement_is_not_reclassified_as_headless() -> None:
    payload = (
        '("VB_MAESTRO_STATE_V1" '
        '((t 4 "ADE Assembler Editing: LIB CELL maestro" '
        '"fnxSession4" "fnxSession5")) '
        '("fnxSession4" "fnxSession5") 4 '
        '"ADE Assembler Editing: LIB CELL maestro")'
    )

    exact = get_session_state(_Client(payload), "fnxSession4")
    current = get_session_state(_Client(payload))

    assert exact.context == "unknown"
    assert exact.session == "fnxSession4"
    assert current.context == "unknown"
    assert "disagree" in current.diagnostics[0]


def test_lifecycle_keeps_ambiguous_window_and_blocks_open() -> None:
    client = _Client(
        '("VB_MAESTRO_STATE_V1" '
        '((t 4 "ADE Assembler Editing: LIB CELL maestro" '
        '"fnxSession4" "fnxSession5")) '
        '("fnxSession4" "fnxSession5") 4 '
        '"ADE Assembler Editing: LIB CELL maestro")'
    )

    windows = lifecycle._get_session_windows(client)

    assert len(windows) == 2
    assert all(window["mode"] == "unknown" for window in windows)
    assert all(window["modified"] is None for window in windows)


def test_unknown_gui_title_preserves_session_without_claiming_clean() -> None:
    client = _Client(
        '("VB_MAESTRO_STATE_V1" '
        '((t 4 "ADE Assembler Reviewing: LIB CELL maestro" '
        '"fnxSession4" "fnxSession4")) '
        '("fnxSession4") 4 "ADE Assembler Reviewing: LIB CELL maestro")'
    )

    state = get_session_state(client, "fnxSession4")

    assert state.context == "gui"
    assert state.access == "unknown"
    assert state.unsaved is None
    assert state.source == "window_inventory"


def test_missing_requested_session_is_not_found() -> None:
    client = _Client('("VB_MAESTRO_STATE_V1" nil ("fnxSession2") nil nil)')

    state = get_session_state(client, "fnxSession8")

    assert state.context == "not_found"
    assert state.session == "fnxSession8"


@pytest.mark.parametrize(
    "payload",
    [
        "nil",
        '("WRONG_TAG" nil nil nil nil)',
        '("VB_MAESTRO_STATE_V1" ((t bad nil nil nil)) nil nil nil)',
        '("VB_MAESTRO_STATE_V1" nil ("fnxSession1" "fnxSession1") nil nil)',
    ],
)
def test_malformed_probe_payload_raises(payload: str) -> None:
    with pytest.raises(MaestroStateProbeError):
        list_session_states(_Client(payload))


def test_probe_execution_failure_is_not_no_window() -> None:
    with pytest.raises(MaestroStateProbeError, match="probe failed"):
        get_session_state(_Client("nil", errors=["CIW unavailable"]))


def _window(
    *, session: str = "fnxSession4", lib: str | None = "LIB",
    cell: str | None = "CELL", mode: str = "editing",
    modified: bool | None = False,
) -> dict:
    return {
        "session": session,
        "window_num": 4,
        "mode": mode,
        "modified": modified,
        "ade_type": "assembler",
        "lib": lib,
        "cell": cell,
        "view": "maestro" if lib else None,
        "title": "title",
        "diagnostics": (),
    }


def test_find_session_for_cell_uses_exact_identity(monkeypatch) -> None:
    monkeypatch.setattr(
        lifecycle,
        "_get_session_windows",
        lambda client: [
            _window(session="fnxSession2", cell="amp2"),
            _window(session="fnxSession1", cell="amp"),
        ],
    )

    assert lifecycle._find_session_for_cell(object(), "LIB", "amp") == "fnxSession1"


def test_find_session_for_cell_rejects_ambiguity(monkeypatch) -> None:
    monkeypatch.setattr(
        lifecycle,
        "_get_session_windows",
        lambda client: [_window(), _window(session="fnxSession5")],
    )

    with pytest.raises(RuntimeError, match="More than one"):
        lifecycle._find_session_for_cell(object(), "LIB", "CELL")


def test_open_gui_session_blocks_unknown_existing_window(monkeypatch) -> None:
    client = _Client()
    monkeypatch.setattr(lifecycle, "_close_background_sessions", lambda client: [])
    monkeypatch.setattr(
        lifecycle, "_get_session_windows",
        lambda client: [_window(mode="unknown", modified=None)],
    )

    with pytest.raises(RuntimeError, match="state is unknown"):
        lifecycle.open_gui_session(client, "LIB", "CELL")

    assert client.calls == []


def test_open_gui_session_does_not_discard_read_only_dirty_window(monkeypatch) -> None:
    client = _Client()
    monkeypatch.setattr(lifecycle, "_close_background_sessions", lambda client: [])
    monkeypatch.setattr(
        lifecycle, "_get_session_windows",
        lambda client: [_window(mode="reading", modified=True)],
    )

    with pytest.raises(RuntimeError, match="read-only"):
        lifecycle.open_gui_session(client, "LIB", "OTHER_CELL")

    assert client.calls == []


def test_open_gui_session_blocks_when_background_session_cannot_close(monkeypatch) -> None:
    client = _Client(errors=["close failed"])
    monkeypatch.setattr(
        lifecycle,
        "list_session_states",
        lambda client: [MaestroSessionState(
            context="headless", session="fnxSession9", source="session_inventory",
        )],
    )

    with pytest.raises(RuntimeError, match="Could not close headless session"):
        lifecycle.open_gui_session(client, "LIB", "CELL")

    assert len(client.calls) == 1


def test_close_gui_session_blocks_unknown_state(monkeypatch) -> None:
    client = _Client()
    monkeypatch.setattr(
        lifecycle, "_get_session_windows",
        lambda client: [_window(mode="unknown", modified=None)],
    )

    with pytest.raises(RuntimeError, match="state is unknown"):
        lifecycle.close_gui_session(client, "fnxSession4")

    assert client.calls == []


def test_close_gui_session_does_not_promote_read_only_dirty_window(monkeypatch) -> None:
    client = _Client()
    monkeypatch.setattr(
        lifecycle, "_get_session_windows",
        lambda client: [_window(mode="reading", modified=True)],
    )

    with pytest.raises(RuntimeError, match="read-only"):
        lifecycle.close_gui_session(client, "fnxSession4", save=True)

    assert client.calls == []


def test_close_headless_session_verifies_disappearance(monkeypatch) -> None:
    client = _Client("t")
    monkeypatch.setattr(lifecycle, "_get_session_windows", lambda client: [])
    states = iter([
        MaestroSessionState(
            context="headless", session="fnxSession4", source="session_inventory",
        ),
        MaestroSessionState(
            context="not_found", session="fnxSession4", source="session_inventory",
        ),
    ])
    monkeypatch.setattr(lifecycle, "get_session_state", lambda *args: next(states))

    lifecycle.close_gui_session(client, "fnxSession4")

    assert 'maeCloseSession(?session "fnxSession4" ?forceClose t)' in client.calls[0][0]


def test_close_gui_session_verifies_window_closed_before_purge(monkeypatch) -> None:
    client = _Client("t")
    monkeypatch.setattr(lifecycle, "_get_session_windows", lambda client: [_window()])
    monkeypatch.setattr(
        lifecycle,
        "get_session_state",
        lambda *args: MaestroSessionState(
            context="gui", session="fnxSession4", source="window_inventory",
        ),
    )
    purged: list[bool] = []
    monkeypatch.setattr(
        lifecycle, "_purge_maestro_cellview", lambda *args, **kwargs: purged.append(True),
    )

    with pytest.raises(RuntimeError, match="still has context gui"):
        lifecycle.close_gui_session(client, "fnxSession4")

    assert purged == []


def test_close_gui_session_purges_only_confirmed_closed_target(monkeypatch) -> None:
    client = _Client("t")
    monkeypatch.setattr(lifecycle, "_get_session_windows", lambda client: [_window()])
    monkeypatch.setattr(
        lifecycle,
        "get_session_state",
        lambda *args: MaestroSessionState(
            context="not_found", session="fnxSession4", source="session_inventory",
        ),
    )
    purged: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        lifecycle,
        "_purge_maestro_cellview",
        lambda client, lib, cell, view, **kwargs: purged.append((lib, cell, view)),
    )

    lifecycle.close_gui_session(client, "fnxSession4")

    assert purged == [("LIB", "CELL", "maestro")]


def test_close_gui_window_uses_gui_runner_for_save_dialog(monkeypatch) -> None:
    client = _Client("t")
    daemon_runner = object()
    gui_runner = object()
    client.ssh_runner = daemon_runner
    client.gui_runner = gui_runner
    sent: list[object] = []
    monkeypatch.setattr(lifecycle, "_send_x11_alt_n", sent.append)
    monkeypatch.setattr(
        lifecycle,
        "get_session_state",
        lambda *args: MaestroSessionState(
            context="not_found", session="fnxSession4", source="session_inventory",
        ),
    )

    lifecycle._close_gui_window(client, _window(modified=True), timeout=1)

    assert sent == [gui_runner]
