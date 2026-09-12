from __future__ import annotations

import io
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.virtuoso import x11


def _load_helper_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "virtuoso_bridge"
        / "resources"
        / "x11_dismiss_dialog.py"
    )
    spec = importlib.util.spec_from_file_location("x11_dismiss_dialog_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _xwininfo_window(*, x=0, y=0, w=100, h=100, mapped=True):
    state = "IsViewable" if mapped else "IsUnMapped"
    return f"""
xwininfo: Window id: 0x1

  Absolute upper-left X:  {x}
  Absolute upper-left Y:  {y}
  Width: {w}
  Height: {h}
  Map State: {state}
"""


def test_discover_windows_reports_child_modal_title(monkeypatch) -> None:
    helper = _load_helper_module()

    root = """
xwininfo: Window id: 0xroot (the root window)

  Root window id: 0xroot
  Parent window id: 0x0 (none)
     2 children:
     0xc58227 (has no name): () 843x132+528+477 +528+477
     0xabc000 "Virtuoso Main": ("virtuoso" "virtuoso") 1400x900+0+0 +0+0
"""
    ade_tree = """
xwininfo: Window id: 0xc58227 (has no name)

  Root window id: 0xroot
  Parent window id: 0xroot
     1 child:
     0x4203583 "ADE Explorer Update and Run": ("virtuoso" "virtuoso") 843x132+0+0 +528+477
"""
    main_tree = """
xwininfo: Window id: 0xabc000 "Virtuoso Main"

  Root window id: 0xroot
  Parent window id: 0xroot
     1 child:
     0xabc111 "Virtuoso Schematic Editor": ("virtuoso" "virtuoso") 1400x900+0+0 +0+0
"""

    def fake_check_output(cmd, stderr=None):
        if cmd == ["xwininfo", "-root", "-children"]:
            return root.encode()
        if cmd == ["xwininfo", "-id", "0xc58227"]:
            return _xwininfo_window(x=528, y=477, w=843, h=132).encode()
        if cmd == ["xwininfo", "-id", "0xabc000"]:
            return _xwininfo_window(x=0, y=0, w=1400, h=900).encode()
        if cmd == ["xwininfo", "-id", "0xc58227", "-tree"]:
            return ade_tree.encode()
        if cmd == ["xwininfo", "-id", "0xabc000", "-tree"]:
            return main_tree.encode()
        raise AssertionError(f"unexpected command: {cmd!r}")

    monkeypatch.setattr(helper.subprocess, "check_output", fake_check_output)

    windows = helper.discover_windows(":1")
    ade = next(w for w in windows if w["dismiss_id"] == "0x4203583")
    main = next(w for w in windows if w["dismiss_id"] == "0xabc111")

    assert ade["frame_id"] == "0xc58227"
    assert ade["title"] == "ADE Explorer Update and Run"
    assert ade["kind"] == "known_modal"
    assert ade["suggested_action"] == "enter"
    assert ade["geometry"] == {"w": 843, "h": 132, "x": 528, "y": 477}
    assert main["kind"] == "main_window"
    assert main["suggested_action"] is None

    dialogs = helper.find_dialogs(":1")
    assert [d["window_id"] for d in dialogs] == ["0x4203583"]


def test_discover_windows_collapses_descendants_from_one_frame(monkeypatch) -> None:
    helper = _load_helper_module()

    root = """
xwininfo: Window id: 0xroot (the root window)

  Root window id: 0xroot
  Parent window id: 0x0 (none)
     1 child:
     0xabc000 "Virtuoso Main": ("virtuoso" "virtuoso") 1400x900+0+0 +0+0
"""
    main_tree = """
xwininfo: Window id: 0xabc000 "Virtuoso Main"

  Root window id: 0xroot
  Parent window id: 0xroot
     4 children:
     0xabc111 "Layout Editing": ("virtuoso" "virtuoso") 1400x900+0+0 +0+0
     0xabc112 "virtuoso": ("virtuoso" "virtuoso") 1200x800+0+0 +0+0
     0xabc113 "virtuoso": ("virtuoso" "virtuoso") 200x40+0+0 +0+0
     0xabc114 "virtuoso": ("virtuoso" "virtuoso") 20x20+0+0 +0+0
"""

    def fake_check_output(cmd, stderr=None):
        if cmd == ["xwininfo", "-root", "-children"]:
            return root.encode()
        if cmd == ["xwininfo", "-id", "0xabc000"]:
            return _xwininfo_window(x=0, y=0, w=1400, h=900).encode()
        if cmd == ["xwininfo", "-id", "0xabc000", "-tree"]:
            return main_tree.encode()
        raise AssertionError(f"unexpected command: {cmd!r}")

    monkeypatch.setattr(helper.subprocess, "check_output", fake_check_output)

    windows = helper.discover_windows(":1")

    assert len(windows) == 1
    assert windows[0]["dismiss_id"] == "0xabc111"
    assert windows[0]["title"] == "Layout Editing"


def test_find_x11_env_decodes_pgrep_pid_bytes(monkeypatch) -> None:
    helper = _load_helper_module()
    opened_paths = []

    def fake_check_output(cmd, stderr=None):
        assert cmd == ["pgrep", "-u", "designer", "-x", "virtuoso"]
        return b"123\n"

    def fake_open(path, mode="r"):
        opened_paths.append(path)
        if path == "/proc/123/cmdline":
            return io.BytesIO(b"virtuoso\x00")
        if path == "/proc/123/environ":
            return io.BytesIO(b"DISPLAY=:7\x00XAUTHORITY=/tmp/xauth\x00")
        raise AssertionError(f"unexpected path: {path!r}")

    monkeypatch.setattr(helper.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(helper, "open", fake_open, raising=False)

    env = helper.find_x11_env(user="designer")

    assert env == {"DISPLAY": ":7", "XAUTHORITY": "/tmp/xauth"}
    assert opened_paths == ["/proc/123/cmdline", "/proc/123/environ"]
    assert not any("b'123'" in path for path in opened_paths)


class _Runner:
    def __init__(self, stdout_by_marker: dict[str, str]) -> None:
        self.commands: list[str] = []
        self.uploads: list[tuple[Path, str]] = []
        self.stdout_by_marker = stdout_by_marker

    def run_command(self, command: str, timeout=None):
        self.commands.append(command)
        if command.startswith("mkdir -p "):
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "python3 --version" in command:
            return SimpleNamespace(returncode=0, stdout='Python 3.9\nCMD:python3\n', stderr="")
        for marker, stdout in self.stdout_by_marker.items():
            if marker in command:
                return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def upload(self, local_path: Path, remote_path: str):
        self.uploads.append((local_path, remote_path))


def test_x11_wrapper_lists_and_dismisses_explicit_window(monkeypatch) -> None:
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    runner = _Runner({
        "--list-windows": '{"dismiss_id":"0x4203583","title":"ADE Explorer Update and Run"}\n',
        "--dismiss-window": '{"dismissed":"0x4203583","action":"enter"}\n',
    })

    windows = x11.list_windows(runner, "designer", profile=None)
    result = x11.dismiss_window(runner, "designer", "0x4203583", action="enter")

    assert windows == [{"dismiss_id": "0x4203583", "title": "ADE Explorer Update and Run"}]
    assert result == [{"dismissed": "0x4203583", "action": "enter"}]
    assert any("--list-windows --json :".split()[0] in cmd for cmd in runner.commands)
    assert any("--dismiss-window 0x4203583 --action enter" in cmd for cmd in runner.commands)


def _input_windows():
    return [{
        "dismiss_id": "0x4203583",
        "title": "ADE Explorer Update and Run",
        "mapped": True,
    }]


def _input_info(*, mapped=True):
    return {"mapped": mapped, "geometry": {"x": 528, "y": 477, "w": 843, "h": 132}}


def test_window_input_preflight_converts_relative_coordinates_and_orders_drag() -> None:
    helper = _load_helper_module()

    prepared = helper.preflight_window_input(
        _input_windows(), "0x4203583", "Explorer", "drag", 20, 30, 1, 40, 50,
        _input_info(),
    )

    assert prepared["root"] == {"x": 548, "y": 507, "to_x": 568, "to_y": 527}
    assert helper.build_window_input_events(prepared) == [
        ("motion", 548, 507),
        ("button", 1, True),
        ("motion", 568, 527),
        ("button", 1, False),
    ]


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"action": "key", "x": 1, "y": 1}, "unsupported action"),
        ({"action": "click", "x": 1, "y": 1, "button": 4}, "button must be"),
        ({"action": "click", "x": 843, "y": 1}, "outside current target bounds"),
        ({"action": "drag", "x": 1, "y": 1}, "drag requires both"),
        ({"action": "move", "x": 1, "y": 1, "to_x": 2}, "only valid for drag"),
    ],
)
def test_window_input_preflight_rejects_invalid_actions_and_coordinates(kwargs, error) -> None:
    helper = _load_helper_module()
    options = dict(kwargs)

    with pytest.raises(ValueError, match=error):
        helper.preflight_window_input(
            _input_windows(), "0x4203583", "Explorer", button=options.pop("button", 1),
            to_x=options.pop("to_x", None), to_y=options.pop("to_y", None),
            window_info=_input_info(), **options,
        )


def test_window_input_preflight_rejects_stale_id_unmapped_and_title_mismatch() -> None:
    helper = _load_helper_module()

    with pytest.raises(ValueError, match="currently discovered"):
        helper.preflight_window_input(
            _input_windows(), "0xdead", "Explorer", "move", 1, 1, window_info=_input_info(),
        )
    with pytest.raises(ValueError, match="not mapped"):
        helper.preflight_window_input(
            _input_windows(), "0x4203583", "Explorer", "move", 1, 1,
            window_info=_input_info(mapped=False),
        )
    with pytest.raises(ValueError, match="does not contain"):
        helper.preflight_window_input(
            _input_windows(), "0x4203583", "Wrong", "move", 1, 1, window_info=_input_info(),
        )
    with pytest.raises(ValueError, match="currently discovered"):
        helper.preflight_window_input(
            [{"dismiss_id": "0xframe", "frame_id": "0xframe", "title": "ADE"}],
            "0xframe", "ADE", "move", 1, 1, window_info=_input_info(),
        )


def test_window_input_refreshes_exact_target_before_sending(monkeypatch) -> None:
    helper = _load_helper_module()
    calls = []
    monkeypatch.setattr(helper, "discover_windows", lambda display: calls.append(
        ("discover", display)) or _input_windows())
    monkeypatch.setattr(helper, "_read_window_info", lambda window_id: calls.append(
        ("xwininfo", window_id)) or _input_info())
    monkeypatch.setattr(helper, "send_window_input", lambda display, prepared, **kwargs: calls.append(
        ("send", display, prepared)) or {"sent": True})

    result = helper.window_input(":1", "0x4203583", "Explorer", "click", 2, 3)
    assert result["sent"] is True
    assert result["verified"] is True
    assert result["state_before"]["geometry"] == _input_info()["geometry"]
    assert calls[0:2] == [("discover", ":1"), ("xwininfo", "0x4203583")]
    assert calls[2][0:2] == ("send", ":1")
    assert calls[2][2]["root"] == {"x": 530, "y": 480}


def test_window_input_raises_and_focuses_target_before_xtest(monkeypatch) -> None:
    helper = _load_helper_module()
    calls = []

    class FakeFunction:
        def __init__(self, name, result=1):
            self.name = name
            self.result = result
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            calls.append((self.name, args))
            return self.result

    class FakeLibrary:
        pass

    xlib = FakeLibrary()
    xtst = FakeLibrary()
    for name in ("XCloseDisplay", "XFlush", "XRaiseWindow", "XSetInputFocus", "XSync"):
        setattr(xlib, name, FakeFunction(name))
    xlib.XOpenDisplay = FakeFunction("XOpenDisplay", result=1234)
    xtst.XTestFakeMotionEvent = FakeFunction("XTestFakeMotionEvent")
    xtst.XTestFakeButtonEvent = FakeFunction("XTestFakeButtonEvent")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: name)
    monkeypatch.setattr(
        helper.ctypes.cdll,
        "LoadLibrary",
        lambda name: xlib if name == "X11" else xtst,
    )
    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    prepared = helper.preflight_window_input(
        _input_windows(), "0x4203583", "Explorer", "click", 20, 30, 1,
        window_info=_input_info(),
    )

    result = helper.send_window_input(":1", prepared)

    names = [name for name, _ in calls]
    assert result["sent"] is True
    assert names.index("XRaiseWindow") < names.index("XTestFakeMotionEvent")
    assert names.index("XSetInputFocus") < names.index("XTestFakeMotionEvent")
    assert names.index("XSync") < names.index("XTestFakeMotionEvent")
    assert next(args for name, args in calls if name == "XRaiseWindow")[1] == int(
        "0x4203583", 16
    )


def test_window_input_dry_run_never_opens_x11(monkeypatch) -> None:
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "discover_windows", lambda display: _input_windows())
    monkeypatch.setattr(helper, "_read_window_info", lambda window_id: _input_info())
    monkeypatch.setattr(
        helper, "send_window_input",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not send")),
    )

    result = helper.window_input(
        ":1", "0x4203583", "Explorer", "drag", 2, 3, 1, 4, 5, dry_run=True,
    )

    assert result["sent"] is False
    assert result["dry_run"] is True
    assert result["state_before"]["geometry"] == _input_info()["geometry"]
    assert result["state_after"] is None
    assert result["planned_events"][-1] == ("button", 1, False)


def test_window_input_schedule_supports_bounded_drag_timing() -> None:
    helper = _load_helper_module()
    prepared = helper.preflight_window_input(
        _input_windows(), "0x4203583", "Explorer", "drag", 0, 0, 1, 10, 4,
        _input_info(),
    )
    timing = helper._validate_window_input_timing(50, 20, 100, 2)

    assert helper.build_window_input_schedule(prepared, timing) == [
        ("event", ("motion", 528, 477)),
        ("event", ("button", 1, True)),
        ("sleep", 20),
        ("sleep", 50.0),
        ("event", ("motion", 533, 479)),
        ("sleep", 50.0),
        ("event", ("motion", 538, 481)),
        ("event", ("button", 1, False)),
    ]
    with pytest.raises(ValueError, match="drag_steps"):
        helper._validate_window_input_timing(drag_steps=101)


def test_window_input_rechecks_fingerprint_after_focus_before_xtest(monkeypatch) -> None:
    helper = _load_helper_module()
    calls = []

    class FakeFunction:
        def __init__(self, name, result=1):
            self.name, self.result, self.argtypes, self.restype = name, result, None, None

        def __call__(self, *args):
            calls.append((self.name, args))
            return self.result

    class FakeLibrary:
        pass

    xlib, xtst = FakeLibrary(), FakeLibrary()
    for name in ("XCloseDisplay", "XFlush", "XRaiseWindow", "XSetInputFocus", "XSync"):
        setattr(xlib, name, FakeFunction(name))
    xlib.XOpenDisplay = FakeFunction("XOpenDisplay", result=1234)
    xtst.XTestFakeMotionEvent = FakeFunction("XTestFakeMotionEvent")
    xtst.XTestFakeButtonEvent = FakeFunction("XTestFakeButtonEvent")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: name)
    monkeypatch.setattr(helper.ctypes.cdll, "LoadLibrary", lambda name: xlib if name == "X11" else xtst)
    prepared = helper.preflight_window_input(
        _input_windows(), "0x4203583", "Explorer", "move", 2, 3, window_info=_input_info(),
    )
    changed = dict(prepared)
    changed["fingerprint"] = dict(prepared["fingerprint"], title="Different Window")

    result = helper.send_window_input(
        ":1", prepared, timing=helper._validate_window_input_timing(settle_ms=0),
        refresh_preflight=lambda: changed,
    )

    assert "fingerprint changed" in result["error"]
    assert not any(name.startswith("XTest") for name, _ in calls)


def test_window_input_checks_xtest_status_and_releases_failed_drag(monkeypatch) -> None:
    helper = _load_helper_module()
    calls = []

    class FakeFunction:
        def __init__(self, name, results=None):
            self.name, self.results, self.argtypes, self.restype = name, list(results or [1]), None, None

        def __call__(self, *args):
            calls.append((self.name, args))
            return self.results.pop(0) if self.results else 1

    class FakeLibrary:
        pass

    xlib, xtst = FakeLibrary(), FakeLibrary()
    for name in ("XCloseDisplay", "XFlush", "XRaiseWindow", "XSetInputFocus", "XSync"):
        setattr(xlib, name, FakeFunction(name))
    xlib.XOpenDisplay = FakeFunction("XOpenDisplay", [1234])
    # Start motion succeeds, drag motion fails after button press; finally must release.
    xtst.XTestFakeMotionEvent = FakeFunction("XTestFakeMotionEvent", [1, 0])
    xtst.XTestFakeButtonEvent = FakeFunction("XTestFakeButtonEvent", [1, 1])
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: name)
    monkeypatch.setattr(helper.ctypes.cdll, "LoadLibrary", lambda name: xlib if name == "X11" else xtst)
    prepared = helper.preflight_window_input(
        _input_windows(), "0x4203583", "Explorer", "drag", 2, 3, 1, 4, 5, _input_info(),
    )

    result = helper.send_window_input(
        ":1", prepared, timing=helper._validate_window_input_timing(settle_ms=0),
    )

    assert "XTestFakeMotionEvent returned failure" in result["error"]
    button_events = [args for name, args in calls if name == "XTestFakeButtonEvent"]
    assert button_events[-1][2] is False


def test_window_input_postconditions_are_explicit() -> None:
    helper = _load_helper_module()
    before = {"found": True, "mapped": True, "fingerprint": {"title": "Layout"}}
    after = {"found": False, "mapped": False}

    assert helper._evaluate_window_input_postcondition("unmapped", before, after)["passed"] is True
    assert helper._evaluate_window_input_postcondition("still-mapped", before, after)["passed"] is False
    with pytest.raises(ValueError, match="post-expect-title"):
        helper._evaluate_window_input_postcondition("title-contains", before, before)


def test_window_input_reports_sent_but_unverified_postcondition(monkeypatch) -> None:
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "discover_windows", lambda display: _input_windows())
    monkeypatch.setattr(helper, "_read_window_info", lambda window_id: _input_info())
    monkeypatch.setattr(
        helper, "send_window_input",
        lambda display, prepared, **kwargs: dict(prepared, sent=True),
    )
    monkeypatch.setattr(
        helper, "_capture_window_input_state",
        lambda display, window_id: {"found": False, "window_id": window_id},
    )

    result = helper.window_input(
        ":1", "0x4203583", "Explorer", "click", 2, 3, postcondition="still-mapped",
    )

    assert result["sent"] is True
    assert result["verified"] is False
    assert result["postcondition"] == {"requested": "still-mapped", "passed": False}
    assert result["error"] == "window-input postcondition failed"


def test_x11_wrapper_builds_live_window_input_command(monkeypatch) -> None:
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    runner = _Runner({"--window-input": '{"sent":true,"action":"click"}\n'})

    result = x11.window_input(
        runner, "designer", "0x4203583", expect_title="ADE Explorer", action="click",
        x=20, y=30, button=1, allow_live=True,
    )

    assert result == [{"sent": True, "action": "click"}]
    command = next(cmd for cmd in runner.commands if "--window-input" in cmd)
    assert "--window-input 0x4203583" in command
    assert "--expect-title 'ADE Explorer'" in command
    assert "--action click --x 20 --y 30 --button 1" in command
    assert "--settle-ms 50 --hold-ms 0 --drag-duration-ms 0 --drag-steps 1" in command
    assert "--allow-live" in command


def test_x11_wrapper_refuses_window_input_without_live_acknowledgement(monkeypatch) -> None:
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    runner = _Runner({})

    result = x11.window_input(
        runner, "designer", "0x4203583", expect_title="ADE", action="move", x=1, y=1,
    )

    assert result == [{"error": "--allow-live is required"}]
    assert runner.commands == []


def test_x11_wrapper_allows_dry_run_without_live_acknowledgement(monkeypatch) -> None:
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    runner = _Runner({"--window-input": '{"sent":false,"dry_run":true}\n'})

    result = x11.window_input(
        runner, "designer", "0x4203583", expect_title="ADE", action="move", x=1, y=1,
        dry_run=True, postcondition="still-mapped",
    )

    assert result == [{"sent": False, "dry_run": True}]
    command = next(cmd for cmd in runner.commands if "--window-input" in cmd)
    assert "--dry-run" in command
    assert "--allow-live" not in command
    assert "--postcondition still-mapped" in command


def test_window_input_cli_parser_dispatches_only_with_live_acknowledgement(monkeypatch) -> None:
    calls = []

    def fake_window_input(**kwargs):
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(cli, "cli_window_input", fake_window_input)
    assert cli.main([
        "window-input", "0x4203583", "--expect-title", "ADE", "--action", "move",
        "--x", "20", "--y", "30", "--allow-live",
    ]) == 0
    assert calls == [{
        "window_id": "0x4203583", "expect_title": "ADE", "action": "move",
        "x": 20, "y": 30, "button": 1, "to_x": None, "to_y": None, "allow_live": True,
        "dry_run": False, "settle_ms": 50, "hold_ms": 0,
        "drag_duration_ms": 0, "drag_steps": 1, "postcondition": "none",
        "post_expect_title": None,
    }]
    assert cli.main([
        "window-input", "0x4203583", "--expect-title", "ADE", "--action", "move",
        "--x", "20", "--y", "30", "--dry-run", "--postcondition", "still-mapped",
    ]) == 0
    assert calls[-1]["dry_run"] is True
    assert calls[-1]["allow_live"] is False
    assert calls[-1]["postcondition"] == "still-mapped"


def test_make_ssh_runner_skips_ssh_for_localhost(monkeypatch) -> None:
    def fail_if_instantiated(*args, **kwargs):
        raise AssertionError("local X11 commands should not instantiate SSHRunner")

    monkeypatch.setattr(cli, "_CLI_PROFILE", [None])
    monkeypatch.setenv("VB_REMOTE_HOST", "localhost")
    monkeypatch.setenv("VB_REMOTE_USER", "designer")
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.SSHRunner", fail_if_instantiated)

    runner, user = cli._make_ssh_runner()

    assert runner is None
    assert user == "designer"


def test_make_ssh_runner_uses_profile_backend_settings(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class _CapturedRunner:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(cli, "_CLI_PROFILE", ["worker"])
    monkeypatch.setenv("VB_REMOTE_HOST_worker", "compute")
    monkeypatch.setenv("VB_REMOTE_USER_worker", "designer")
    monkeypatch.setenv("VB_SSH_BACKEND_worker", "paramiko")
    monkeypatch.setenv("VB_SSH_MAX_SESSIONS_worker", "255")
    monkeypatch.setenv("VB_SSH_PROXY_worker", "socks5://127.0.0.1:10800")
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.load_vb_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.SSHRunner", _CapturedRunner)

    runner, user = cli._make_ssh_runner()

    assert runner is not None
    assert user == "designer"
    assert captured["backend"] == "paramiko"
    assert captured["max_sessions"] == 255
    assert captured["proxy_url"] == "socks5://127.0.0.1:10800"


def test_helper_exports_auto_detected_display(monkeypatch, capsys) -> None:
    helper = _load_helper_module()
    calls = []

    def fake_dismiss_window(display, win_id, *args, **kwargs):
        calls.append((display, win_id, helper.os.environ.get("DISPLAY")))
        return {"dismissed": win_id}

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(
        helper,
        "find_x11_envs",
        lambda: [{"DISPLAY": ":7", "XAUTHORITY": ""}],
    )
    monkeypatch.setattr(
        helper,
        "discover_windows",
        lambda _display: [{"frame_id": "0xframe", "dismiss_id": "0xabc"}],
    )
    monkeypatch.setattr(helper, "_verify_dismissal", lambda result: result)
    monkeypatch.setattr(helper, "dismiss_window", fake_dismiss_window)
    monkeypatch.setattr(helper.sys, "argv", ["x11_dismiss_dialog.py", "--dismiss-window", "0xabc"])

    try:
        helper.main()
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [(":7", "0xabc", ":7")]
    assert helper.os.environ["DISPLAY"] == ":7"
    out = capsys.readouterr().out
    assert '"dismissed": "0xabc"' in out


def test_top_level_discovery_returns_one_verified_ciw_per_frame(monkeypatch) -> None:
    helper = _load_helper_module()
    root = """
     1 child:
     0xf00 (has no name): () 1200x800+0+0 +0+0
"""
    children = """
     3 children:
     0xc10 "Virtuoso Command Interpreter Window": ("virtuoso" "Virtuoso") 1200x800+0+0 +0+0
     0xd01 "Virtuoso Command Interpreter Window": ("virtuoso" "Virtuoso") 1200x800+0+0 +0+0
     0xd02 "Virtuoso Command Interpreter Window": ("virtuoso" "Virtuoso") 1200x800+0+0 +0+0
"""

    def fake_check_output(cmd, stderr=None):
        if cmd == ["xwininfo", "-root", "-children"]:
            return root.encode()
        if cmd == ["xwininfo", "-id", "0xf00"]:
            return _xwininfo_window(w=1200, h=800).encode()
        if cmd == ["xwininfo", "-id", "0xf00", "-children"]:
            return children.encode()
        raise AssertionError(f"unexpected command: {cmd!r}")

    monkeypatch.setattr(helper.subprocess, "check_output", fake_check_output)

    windows = helper.discover_windows(":7", top_level=True)

    assert len(windows) == 1
    assert windows[0]["frame_id"] == "0xf00"
    assert windows[0]["dismiss_id"] == "0xc10"
    assert windows[0]["kind"] == "ciw"


def test_bootstrap_refuses_non_ciw_and_injects_only_generated_load(monkeypatch) -> None:
    helper = _load_helper_module()
    typed = []

    monkeypatch.setattr(
        helper,
        "discover_windows",
        lambda _display, top_level=False: [{
            "frame_id": "0xframe",
            "window_id": "0xchild",
            "dismiss_id": "0xchild",
            "title": "Virtuoso Schematic Editor",
            "kind": "main_window",
        }],
    )
    refused = helper.bootstrap_ciw(":7", "0xframe", "/shared/virtuoso_setup.il")
    assert "refusing bootstrap" in refused["error"]

    monkeypatch.setattr(
        helper,
        "discover_windows",
        lambda _display, top_level=False: [{
            "frame_id": "0xframe",
            "window_id": "0xciw",
            "dismiss_id": "0xciw",
            "title": "Virtuoso Command Interpreter Window",
            "kind": "ciw",
        }],
    )
    monkeypatch.setattr(
        helper,
        "_type_ascii_into_window",
        lambda display, window, text: typed.append((display, window, text)) or {"bootstrapped": window},
    )

    result = helper.bootstrap_ciw(":7", "0xframe", "/shared/virtuoso_setup.il")

    assert "error" not in result
    assert typed == [(":7", "0xciw", 'load("/shared/virtuoso_setup.il")')]


def test_bootstrap_does_not_inject_when_window_id_matches_two_displays(monkeypatch, capsys) -> None:
    helper = _load_helper_module()
    monkeypatch.setattr(
        helper,
        "find_x11_envs",
        lambda: [
            {"DISPLAY": ":7", "XAUTHORITY": "/tmp/a"},
            {"DISPLAY": ":8", "XAUTHORITY": "/tmp/b"},
        ],
    )
    monkeypatch.setattr(
        helper,
        "discover_windows",
        lambda _display, top_level=False: [{
            "frame_id": "0xabc",
            "window_id": "0xdef",
            "dismiss_id": "0xdef",
            "title": "Virtuoso Command Interpreter Window",
            "kind": "ciw",
        }],
    )
    monkeypatch.setattr(
        helper,
        "bootstrap_ciw",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("must validate uniqueness before injection")
        ),
    )
    monkeypatch.setattr(
        helper.sys,
        "argv",
        [
            "x11_dismiss_dialog.py",
            "--bootstrap-window",
            "0xabc",
            "--setup-path",
            "/shared/virtuoso_setup.il",
        ],
    )

    try:
        helper.main()
    except SystemExit as exc:
        assert exc.code == 1

    assert "more than one display" in capsys.readouterr().out


def test_x11_wrapper_requests_top_level_mode(monkeypatch) -> None:
    monkeypatch.setattr(x11, "load_vb_env", lambda: None)
    runner = _Runner({"--list-windows": '{"kind":"ciw"}\n'})

    windows = x11.list_windows(runner, "designer", top_level=True)

    assert windows == [{"kind": "ciw"}]
    assert any("--list-windows --json --top-level" in cmd for cmd in runner.commands)


def test_assembler_1749_uses_the_ok_mnemonic() -> None:
    helper = _load_helper_module()

    assert helper._known_action("ADE Assembler Message 1749") == "alt-o"


@pytest.mark.parametrize("operation", ["dismiss", "input"])
@pytest.mark.parametrize("matching_displays", [[], [":7"], [":7", ":8"]])
def test_explicit_window_actions_require_one_display_and_restore_auth(
    monkeypatch, capsys, operation, matching_displays
):
    helper = _load_helper_module()
    calls = []
    monkeypatch.setenv("XAUTHORITY", "/tmp/original")
    monkeypatch.setattr(helper, "find_x11_envs", lambda: [
        {"DISPLAY": ":7", "XAUTHORITY": "/tmp/auth-a"},
        {"DISPLAY": ":8", "XAUTHORITY": "/tmp/auth-b"},
    ])
    monkeypatch.setattr(helper, "discover_windows", lambda display, **kw: [
        {"window_id": "0xabc", "dismiss_id": "0xabc", "frame_id": "0xframe"}
    ] if display in matching_displays else [])
    monkeypatch.setattr(helper, "_verify_dismissal", lambda result: result)

    def capture(display, target, *args, **kwargs):
        calls.append((display, target, helper.os.environ.get("XAUTHORITY")))
        return {"dismissed": target} if operation == "dismiss" else {"sent": False}

    monkeypatch.setattr(helper, "dismiss_window", capture)
    monkeypatch.setattr(helper, "window_input", capture)
    args = ["helper", "--dismiss-window", "0xabc"] if operation == "dismiss" else [
        "helper", "--window-input", "0xabc", "--expect-title", "review",
        "--action", "move", "--x", "1", "--y", "1", "--dry-run",
    ]
    monkeypatch.setattr(helper.sys, "argv", args)
    with pytest.raises(SystemExit) as exited:
        helper.main()
    if len(matching_displays) == 1:
        assert exited.value.code == 0
        assert calls == [(":7", "0xabc", "/tmp/auth-a")]
    else:
        assert exited.value.code != 0
        assert calls == []
        assert "error" in capsys.readouterr().out


def test_apply_x11_env_clears_previous_displays_authority(monkeypatch):
    helper = _load_helper_module()
    monkeypatch.setenv("XAUTHORITY", "/tmp/previous")
    assert helper._apply_x11_env({"DISPLAY": ":7", "XAUTHORITY": None}) == ":7"
    assert "XAUTHORITY" not in helper.os.environ
