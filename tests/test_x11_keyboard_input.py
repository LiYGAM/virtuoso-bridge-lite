from types import SimpleNamespace
import base64
import shlex

import pytest

from .test_x11_window_discovery import _load_helper_module, _input_info, _input_windows, _Runner
from virtuoso_bridge.virtuoso import x11
from virtuoso_bridge import cli


@pytest.mark.parametrize("action,payload", [
    ("text", {"text": "a\nb"}), ("text", {"text": "中文"}),
    ("text", {"text": "a" * 257}), ("text", {"text": ""}),
    ("key", {"key": "Ctrl+Ctrl+A"}), ("key", {"key": "A;Return"}),
    ("key", {"key": "Enter", "text": "x"}),
])
def test_invalid_payloads_refused(action, payload):
    with pytest.raises(ValueError):
        _load_helper_module().keyboard_chords(action, **payload)


def test_keyboard_requires_exact_identity_and_no_coordinates():
    h = _load_helper_module()
    with pytest.raises(ValueError, match="exact"):
        h.preflight_window_input(_input_windows(), "0x4203583", "Explorer", "key",
                                 window_info=_input_info(), key="Tab")
    with pytest.raises(ValueError, match="coordinates"):
        h.preflight_window_input(_input_windows(), "0x4203583", "Explorer", "key",
                                 x=1, y=2, window_info=_input_info(), key="Tab")


def fake_keyboard(monkeypatch, *, fail_press=False, focus_error=False):
    h = _load_helper_module()
    events = []
    lib = SimpleNamespace(XOpenDisplay=lambda _: 7, XFlush=lambda _: None,
                          XCloseDisplay=lambda _: events.append("close"))
    def emit(dpy, code, down, delay):
        events.append((code, bool(down)))
        return not (fail_press and code == 38 and down)
    xtst = SimpleNamespace(XTestFakeKeyEvent=emit)
    monkeypatch.setattr(h.ctypes.util, "find_library", lambda n: n)
    monkeypatch.setattr(h.ctypes.cdll, "LoadLibrary", lambda n: lib if n == "X11" else xtst)
    monkeypatch.setattr(h, "_configure_pointer_x11", lambda *a: None)
    monkeypatch.setattr(h, "_configure_keyboard_x11", lambda *a: None)
    def focus(*a):
        if focus_error:
            raise RuntimeError("focus outside target")
        return 0x4203583
    monkeypatch.setattr(h, "_keyboard_focus", focus)
    monkeypatch.setattr(h, "_keyboard_idle", lambda *a: None)
    monkeypatch.setattr(h, "_keyboard_codes", lambda *a: [[37, 38]])
    monkeypatch.setattr(h, "_sync_or_raise", lambda *a: None)
    monkeypatch.setattr(h.time, "sleep", lambda *a: None)
    prepared = h.preflight_window_input(_input_windows(), "0x4203583",
        "ADE Explorer Update and Run", "key", window_info=_input_info(), key="Ctrl+A")
    return h, prepared, events


def test_wrong_focus_emits_no_keys(monkeypatch):
    h, p, events = fake_keyboard(monkeypatch, focus_error=True)
    r = h.send_keyboard_input(":1", p, {"settle_ms": 0}, lambda: p)
    assert not r["sent"] and r["completion"] == "not-sent"
    assert events == ["close"]


def test_partial_failure_releases_all_keys_without_replay(monkeypatch):
    h, p, events = fake_keyboard(monkeypatch, fail_press=True)
    r = h.send_keyboard_input(":1", p, {"settle_ms": 0}, lambda: p)
    assert r["completion"] == "unknown" and not r["retry_safe"]
    assert events == [(37, True), (38, True), (38, False), (37, False), "close"]


def test_dry_run_has_no_key_events(monkeypatch):
    h, p, events = fake_keyboard(monkeypatch)
    r = h.send_keyboard_input(":1", p, {"settle_ms": 0}, lambda: p, True)
    assert r["dry_run"] and not r["sent"] and events == ["close"]


def test_success_releases_reverse_order(monkeypatch):
    h, p, events = fake_keyboard(monkeypatch)
    r = h.send_keyboard_input(":1", p, {"settle_ms": 0}, lambda: p)
    assert r["events_sent"] == 4 and "error" not in r
    assert events == [(37, True), (38, True), (38, False), (37, False), "close"]


def test_wrapper_quotes_text_as_one_shell_argument(monkeypatch):
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    monkeypatch.setattr(x11, "_ensure_helper", lambda *a: "/tmp/helper.py")
    monkeypatch.setattr(x11, "_detect_remote_python", lambda *a: "python3")
    monkeypatch.setattr(x11, "_get_display", lambda *a: ":1")
    runner = _Runner({"--window-input": '{"sent":true}\n'})
    payload = "-net 'quoted' $(literal); <>[]"
    x11.window_input(runner, "user", "0x2", expect_title="Probe", action="text",
                     text=payload, allow_live=True)
    argv = shlex.split(runner.commands[-1])
    assert base64.b64decode(argv[argv.index("--text-base64") + 1]).decode() == payload
    assert "--x" not in argv


def test_cli_keyboard_without_coordinates(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cli_window_input", lambda **kw: calls.append(kw) or 0)
    assert cli.main(["window-input", "0x2", "--expect-title", "Probe", "--action",
                     "text", "--text=-net", "--dry-run"]) == 0
    assert calls[0]["text"] == "-net" and calls[0]["x"] is None


def test_transport_failure_is_not_replayed(monkeypatch):
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    monkeypatch.setattr(x11, "_ensure_helper", lambda *a: "/tmp/helper.py")
    monkeypatch.setattr(x11, "_detect_remote_python", lambda *a: "python3")
    monkeypatch.setattr(x11, "_get_display", lambda *a: ":1")
    calls = []
    def run(*args, **kwargs):
        calls.append(kwargs)
        raise TimeoutError("receipt lost")
    result = x11.window_input(SimpleNamespace(run_command=run), "user", "0x2",
        expect_title="Probe", action="key", key="Enter", allow_live=True)
    assert len(calls) == 1 and calls[0]["retry_transport_errors"] is False
    assert result[0]["completion"] == "unknown" and not result[0]["retry_safe"]
