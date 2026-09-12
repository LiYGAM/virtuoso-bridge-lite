"""Activation identity and GUI-owned autoload regression checks."""
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import pytest

from virtuoso_bridge.transport import tunnel
from virtuoso_bridge.transport.ssh import CommandResult, _windows_no_window_kwargs
from virtuoso_bridge.transport.tunnel import SSHClient


@pytest.mark.parametrize("gui_host,daemon_host", [("gui-a", "compute-b"), ("gui-a", "localhost")])
def test_autoload_status_reads_gui_home(monkeypatch, gui_host, daemon_host):
    calls = []

    class Runner:
        def __init__(self, **kwargs):
            self.host = kwargs["host"]

        def run_command(self, command, **kwargs):
            calls.append(self.host)
            return CommandResult(0, "__VB_PATH__ /home/user/.cdsinit\n__VB_UID__ 1000\n"
                                 "__VB_MISSING__\n__VB_SETUP_EXISTS__ 1\n", "")

    monkeypatch.setattr(tunnel, "SSHRunner", Runner)
    client = SSHClient(remote_host="legacy", daemon_host=daemon_host, gui_host=gui_host,
                       deploy_host="deploy-c", auth_token="fixture")
    client.autoload_status(expected_setup_path="/shared/setup.il")
    assert calls == [gui_host]


@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_remote_autoload_mutation_uses_only_gui_runner(monkeypatch, action):
    calls = []

    class Runner:
        def __init__(self, **kwargs):
            self.host = kwargs["host"]

        def run_command(self, command, **kwargs):
            calls.append((self.host, "command"))
            return CommandResult(0, "", "")

        def upload_text(self, *args, **kwargs):
            calls.append((self.host, "upload"))
            return CommandResult(0, "", "")

    monkeypatch.setattr(tunnel, "SSHRunner", Runner)
    client = SSHClient(remote_host="compute-b", daemon_host="compute-b", gui_host="gui-a",
                       deploy_host="deploy-c", profile="review", auth_token="fixture")
    client._compat_setup_path = "/shared/setup.il"
    original = "" if action == "install" else tunnel._autoload_block("review", "/shared/setup.il")
    monkeypatch.setattr(client, "_remote_cdsinit_snapshot", lambda *a, **kw: {
        "path": "/home/user/.cdsinit", "target_is_symlink": False,
        "target_exists": True, "target_owned": True, "mode": 0o600, "_text": original,
    })
    getattr(client, "autoload_" + action)()
    assert calls
    assert {host for host, _ in calls} == {"gui-a"}


@pytest.mark.parametrize("action", ["status", "install", "uninstall"])
def test_local_gui_autoload_does_not_use_remote_daemon(monkeypatch, tmp_path, action):
    cdsinit = tmp_path / ".cdsinit"
    setup = tmp_path / "setup.il"
    setup.write_text("t\n")
    cdsinit.write_text("; keep user config\n")
    monkeypatch.setenv("VB_CDSINIT_PATH_review", str(cdsinit))
    client = SSHClient(remote_host="compute-b", daemon_host="compute-b", gui_host="localhost",
                       deploy_host="localhost", profile="review", auth_token="fixture")
    client._compat_setup_path = str(setup)
    monkeypatch.setattr(client, "_require_runner", lambda: pytest.fail("daemon must not own .cdsinit"))
    getattr(client, "autoload_" + action)()
    assert "; keep user config" in cdsinit.read_text()


@pytest.mark.parametrize("identity_case", [
    "matching", "old-il", "old-epoch", "wrong-pid", "wrong-profile", "bad-digest",
    "legacy", "partial", "duplicate", "missing",
])
def test_deployment_status_requires_loaded_identity(monkeypatch, tmp_path, identity_case):
    daemon = tmp_path / "ramic_bridge_daemon_3.py"
    il = tmp_path / "ramic_bridge.il"
    identity = tmp_path / "daemon_identity.txt"
    daemon.write_bytes(b"daemon\n")
    il.write_bytes(b"il\n")
    daemon_sha = hashlib.sha256(daemon.read_bytes()).hexdigest()
    il_sha = hashlib.sha256(il.read_bytes()).hexdigest()
    deployment_id = hashlib.sha256((daemon_sha + "\0" + il_sha).encode()).hexdigest()
    fields = {
        "host": "fixture", "pid": "123", "bind": "127.0.0.1:65432",
        "epoch": "current-epoch", "profile": "review", "deployment_id": deployment_id,
        "il_sha256": il_sha, "identity_complete": "1",
    }
    if identity_case == "old-il":
        fields["il_sha256"] = "0" * 64
        fields["deployment_id"] = "0" * 64
    elif identity_case == "old-epoch":
        fields["epoch"] = "previous-epoch"
    elif identity_case == "wrong-pid":
        fields["pid"] = "456"
    elif identity_case == "wrong-profile":
        fields["profile"] = "other"
    elif identity_case == "bad-digest":
        fields["il_sha256"] = "incomplete"
    elif identity_case == "legacy":
        fields = {key: fields[key] for key in ("host", "pid", "bind")}
    elif identity_case == "partial":
        fields.pop("identity_complete")
    identity.write_text("".join(f"{key}={value}\n" for key, value in fields.items()))
    if identity_case == "duplicate":
        identity.write_text("pid=456\n" + identity.read_text())
    elif identity_case == "missing":
        identity.unlink()
    monkeypatch.setattr(tunnel, "_find_ramic_bridge_daemon", lambda major: daemon)
    monkeypatch.setattr(tunnel, "_find_ramic_bridge_il", lambda: il)
    monkeypatch.setattr(SSHClient, "read_state", lambda profile=None: {
        "mode": "local", "daemon_filename": daemon.name,
        "deployed_daemon_path": str(daemon), "deployed_daemon_sha256": daemon_sha,
        "deployed_il_sha256": il_sha, "identity_path": str(identity), "deployment_id": deployment_id,
    })
    monkeypatch.setattr(SSHClient, "read_request_status", lambda *a, **kw: {
        "daemon_epoch": "current-epoch", "daemon_pid": 123, "daemon_build_sha256": daemon_sha,
        "heartbeat_at_epoch": time.time(),
    })
    status = SSHClient.deployment_status("review")
    assert status["local_matches_deployed"] is True
    assert status["deployed_matches_running"] is (identity_case == "matching")
    assert status["staged_update_pending"] is (identity_case != "matching")


def test_local_setup_carries_the_staged_load_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(tunnel, "state_dir", lambda: tmp_path)
    client = SSHClient(remote_host="localhost", profile="review", auth_token="fixture")
    client.ensure_local_setup()
    setup = Path(client.setup_path).read_text()
    assert f'setShellEnvVar("RB_DEPLOYMENT_ID" "{client._deployment_id}")' in setup
    assert f'setShellEnvVar("RB_IL_SHA256" "{client._deployed_il_sha256}")' in setup
    assert setup.index('"RB_IL_SHA256"') < setup.rindex('load("')


@pytest.mark.parametrize("major", [2, 3])
@pytest.mark.skipif(sys.platform != "linux", reason="daemon parent detection requires Linux /proc")
def test_daemon_banner_identifies_the_current_ledger_epoch(tmp_path, major):
    ledger = tmp_path / "ledger.json"
    messages = queue.Queue()
    proc = subprocess.Popen(
        [sys.executable, str(tunnel._find_ramic_bridge_daemon(major)),
         "127.0.0.1", "0", "", str(ledger), "review"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, **_windows_no_window_kwargs(),
    )

    def read_stderr():
        for line in proc.stderr:
            messages.put(line)
        messages.put(None)

    reader = threading.Thread(target=read_stderr, daemon=True)
    reader.start()
    try:
        deadline = time.monotonic() + 10
        output = []
        while True:
            line = messages.get(timeout=max(0.1, deadline - time.monotonic()))
            assert line is not None, "".join(output)
            output.append(line)
            if line.startswith("[RB-banner]"):
                fields = dict(token.split("=", 1) for token in line.split()[1:])
                state = json.loads(ledger.read_text())
                assert fields["epoch"] == state["daemon_epoch"]
                assert int(fields["pid"]) == state["daemon_pid"] == proc.pid
                break
            assert time.monotonic() < deadline, "".join(output)
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
        reader.join(timeout=5)
        proc.stdin.close()
        proc.stderr.close()
