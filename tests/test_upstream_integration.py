"""Regression checks at the upstream/fork transport integration boundary."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import shlex
import shutil
import subprocess

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.transport.ssh import SSHRunner
from virtuoso_bridge.transport.transfer import build_text_upload_plan
from virtuoso_bridge.transport.tunnel import SSHClient


@pytest.mark.parametrize("persistent", [False, True])
def test_exclusive_upload_preserves_existing_files_and_shell_state(tmp_path, persistent):
    bash = shutil.which("bash")
    if not bash and Path("C:/Program Files/Git/bin/bash.exe").is_file():
        bash = "C:/Program Files/Git/bin/bash.exe"
    if not bash:
        pytest.skip("bash is required to execute the remote upload script")
    target = tmp_path / "owned.txt"
    payload = b"complete payload\n"

    def upload(path):
        plan = build_text_upload_plan(path.as_posix(), payload,
                                      create_parent=False, exclusive_create=True)
        if persistent:
            script = 'umask 022\n' + plan.persistent_command(payload)
            script += '\nrc=$?\n[ "$(umask)" = 0022 ] || exit 99\nexit "$rc"\n'
            return subprocess.run([bash, "-c", script], capture_output=True, timeout=15)
        args = shlex.split(plan.remote_command)
        return subprocess.run([bash, *args[1:]], input=payload,
                              capture_output=True, timeout=15)

    first = upload(target)
    assert first.returncode == 0, first.stderr
    assert target.read_bytes() == payload
    target.write_bytes(b"keep original")
    assert upload(target).returncode != 0
    assert target.read_bytes() == b"keep original"
    directory_target = tmp_path / "existing-directory"
    directory_target.mkdir()
    assert upload(directory_target).returncode != 0
    assert not list(directory_target.iterdir())
    missing = tmp_path / "missing-parent" / "output.txt"
    assert upload(missing).returncode != 0
    assert not missing.parent.exists()
    assert not list(tmp_path.glob(".vbtmp-*"))


def test_split_host_state_reuses_port_only_for_the_same_roles(monkeypatch, tmp_path):
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel._state_file", lambda profile: tmp_path / "state.json")
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.state_dir", lambda: tmp_path)
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.load_vb_env", lambda: None)
    for key, value in {
        "VB_REMOTE_HOST_merge": "legacy",
        "VB_DAEMON_HOST_merge": "compute",
        "VB_GUI_HOST_merge": "gui",
        "VB_DEPLOY_HOST_merge": "gui",
        "VB_SPECTRE_HOST_merge": "simulator",
        "VB_REMOTE_USER_merge": "designer",
        "VB_REMOTE_PORT_merge": "65001",
    }.items():
        monkeypatch.setenv(key, value)
    client = SSHClient(remote_host="legacy", daemon_host="compute", gui_host="gui",
                       deploy_host="gui", spectre_host="simulator", remote_user="designer",
                       port=65001, local_port=65002, profile="merge")
    client.save_state()
    assert SSHClient.staged_profile_config_matches_current("merge")
    restored = SSHClient.from_env(profile="merge", create_auth_token=False)
    assert restored.port == 65002
    assert restored._saved_tunnel_identity_matches(SSHClient.read_state("merge"))
    monkeypatch.setenv("VB_GUI_HOST_merge", "different-gui")
    assert not SSHClient.staged_profile_config_matches_current("merge")
    assert SSHClient.from_env(profile="merge", create_auth_token=False).port == 65001


def test_paramiko_mutation_transport_failure_is_not_replayed(monkeypatch):
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.load_vb_env", lambda: None)
    runner = SSHRunner("fixture", backend="openssh")
    attempts = []

    def command(source, timeout):
        attempts.append(source)
        return 255, "", "connection lost after dispatch"

    runner._paramiko_backend = SimpleNamespace(run_command=command)
    result = runner.run_command("mutating command", retry_transport_errors=False)
    assert result.returncode == 255
    assert attempts == ["mutating command"]


def test_bootstrap_health_check_uses_profile_authentication(monkeypatch):
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(cli, "_get_cli_profile", lambda: "merge")
    monkeypatch.setattr(cli, "_make_ssh_runner", lambda: (None, "fixture"))
    monkeypatch.setattr("virtuoso_bridge.virtuoso.x11.bootstrap_ciw",
                        lambda *a, **k: [{"command": 'load("/owned/setup.il")'}])
    monkeypatch.setattr(SSHClient, "read_state", classmethod(lambda cls, profile: {
        "setup_path": "/owned/setup.il", "port": 65001}))
    monkeypatch.setattr(SSHClient, "from_env", classmethod(lambda cls, **kw: SimpleNamespace(
        port=65001, auth_token="fixture-token", close=lambda: None)))
    observed = []

    def make_client(**kwargs):
        observed.append(kwargs)
        return SimpleNamespace(test_connection=lambda **kw: True)

    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", make_client)
    assert cli.cli_bootstrap(window_id="0x1", timeout=1) == 0
    assert observed[0]["auth_token"] == "fixture-token"
    assert observed[0]["profile"] == "merge"
