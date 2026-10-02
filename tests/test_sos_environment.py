from __future__ import annotations

import os
import shlex
import shutil

import pytest

from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.virtuoso.sos.environment import (
    LocalSOSRunner,
    SOSEnvironmentError,
    resolve_soscmd,
)


class _Runner:
    def __init__(self, result=CommandResult(0, "/opt/sos/bin/soscmd\n", "")):
        self.result = result
        self.commands = []

    def run_command(self, command, *, timeout):
        self.commands.append((command, timeout))
        return self.result


class _Owner:
    _timeout = 60

    def __init__(self, runner=None, profile=None):
        self.sos_runner = runner if runner is not None else _Runner()
        self._tunnel = type("Tunnel", (), {"_profile": profile})() if profile else None


def test_default_discovery_uses_remote_path_then_remote_cliosoft_dir():
    owner = _Owner()
    assert resolve_soscmd(owner, None, timeout=12) == "/opt/sos/bin/soscmd"
    command, timeout = owner.sos_runner.commands[0]
    assert "command -v soscmd" in command
    assert '${CLIOSOFT_DIR:-}' in command
    assert "$CLIOSOFT_DIR/bin/soscmd" in command
    assert timeout == 12


@pytest.mark.parametrize("configured", ["soscmd", "/opt/SOS Suite/bin/soscmd", "/opt/it's/soscmd"])
def test_explicit_command_is_shell_quoted_as_one_value(configured):
    owner = _Owner()
    resolve_soscmd(owner, configured, timeout=5)
    command = owner.sos_runner.commands[0][0]
    assert "command -v " + shlex.quote(configured) in command
    assert "CLIOSOFT_DIR" not in command


def test_profile_override_precedes_global(monkeypatch):
    monkeypatch.setenv("VB_SOS_COMMAND", "/global/soscmd")
    monkeypatch.setenv("VB_SOS_COMMAND_lab", "/profile/soscmd")
    owner = _Owner(profile="lab")
    resolve_soscmd(owner, None, timeout=5)
    command = owner.sos_runner.commands[0][0]
    assert shlex.quote("/profile/soscmd") in command
    assert "/global/soscmd" not in command


def test_global_override_is_used_without_profile_override(monkeypatch):
    monkeypatch.setenv("VB_SOS_COMMAND", "/global/soscmd")
    owner = _Owner(profile="lab")
    resolve_soscmd(owner, None, timeout=5)
    assert shlex.quote("/global/soscmd") in owner.sos_runner.commands[0][0]


def test_explicit_argument_precedes_environment(monkeypatch):
    monkeypatch.setenv("VB_SOS_COMMAND_lab", "/profile/soscmd")
    monkeypatch.setenv("VB_SOS_COMMAND", "/global/soscmd")
    owner = _Owner(profile="lab")
    resolve_soscmd(owner, "/explicit/soscmd", timeout=5)
    command = owner.sos_runner.commands[0][0]
    assert "/explicit/soscmd" in command
    assert "/profile/soscmd" not in command
    assert "/global/soscmd" not in command


@pytest.mark.parametrize(
    "configured",
    ["", "   ", "-wrapper", "relative/path", "bad\npath", "bad\rpath", "bad\tpath"],
)
def test_invalid_override_is_rejected_before_remote_execution(configured):
    owner = _Owner()
    with pytest.raises(ValueError, match="SOS command"):
        resolve_soscmd(owner, configured, timeout=5)
    assert owner.sos_runner.commands == []


@pytest.mark.parametrize("returncode", [126, 127, 1])
def test_discovery_failure_is_closed_and_diagnostic(returncode):
    owner = _Owner(_Runner(CommandResult(returncode, "", "not available")))
    with pytest.raises(SOSEnvironmentError, match=f"Exit {returncode}"):
        resolve_soscmd(owner, None, timeout=5)


def test_bad_explicit_install_does_not_add_fallback():
    owner = _Owner(_Runner(CommandResult(127, "", "missing")))
    with pytest.raises(SOSEnvironmentError):
        resolve_soscmd(owner, "/bad/soscmd", timeout=5)
    command = owner.sos_runner.commands[0][0]
    assert "/bad/soscmd" in command
    assert "CLIOSOFT_DIR" not in command
    assert "command -v soscmd" not in command


@pytest.mark.parametrize("stdout", ["soscmd\n", "./soscmd\n", "/one\n/two\n", "\n"])
def test_ambiguous_or_nonabsolute_discovery_output_is_rejected(stdout):
    owner = _Owner(_Runner(CommandResult(0, stdout, "")))
    with pytest.raises(SOSEnvironmentError, match="ambiguous/non-absolute"):
        resolve_soscmd(owner, None, timeout=5)


def test_local_client_cliosoft_dir_value_is_not_interpolated(monkeypatch):
    monkeypatch.setenv("CLIOSOFT_DIR", "/client-only/should-not-leak")
    owner = _Owner()
    resolve_soscmd(owner, None, timeout=5)
    command = owner.sos_runner.commands[0][0]
    assert "/client-only/should-not-leak" not in command
    assert '${CLIOSOFT_DIR:-}' in command


def test_missing_runner_is_blocked():
    owner = type("Owner", (), {"_tunnel": None, "gui_runner": None})()
    with pytest.raises(SOSEnvironmentError, match="filesystem runner"):
        resolve_soscmd(owner, None, timeout=5)


@pytest.mark.skipif(os.name != "posix" or shutil.which("sh") is None, reason="requires POSIX sh")
def test_local_posix_runner_executes_login_shell():
    result = LocalSOSRunner().run_command("printf '%s\\n' local-posix-ok", timeout=5)
    assert result.returncode == 0
    assert result.stdout == "local-posix-ok\n"
