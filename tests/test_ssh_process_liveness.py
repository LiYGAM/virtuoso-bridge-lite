"""Exercise PID reuse checks against a real disposable process."""
import subprocess
import sys

import pytest

from virtuoso_bridge.transport.ssh import SSHRunner, _process_is_alive, _windows_no_window_kwargs
from virtuoso_bridge.transport.tunnel import SSHClient


def test_external_tunnel_liveness_does_not_terminate_process(monkeypatch):
    monkeypatch.setattr("virtuoso_bridge.transport.ssh.load_vb_env", lambda: None)
    runner = SSHRunner("fixture", backend="openssh")
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **_windows_no_window_kwargs(),
    )
    try:
        runner.tunnel_pid = proc.pid
        monkeypatch.setattr(SSHClient, "read_state", lambda profile=None: {
            "mode": "remote", "tunnel_pid": proc.pid,
        })
        assert runner.is_tunnel_alive
        assert SSHClient.is_running()
        assert runner.is_tunnel_alive
        # A fresh interpreter checks the persisted PID as the next CLI call does.
        result = subprocess.run(
            [sys.executable, "-c",
             "from virtuoso_bridge.transport.ssh import _process_is_alive; "
             f"assert _process_is_alive({proc.pid})"],
            capture_output=True, timeout=10, **_windows_no_window_kwargs(),
        )
        assert result.returncode == 0, result.stderr
        assert proc.poll() is None
        proc.communicate(timeout=5)
        assert not runner.is_tunnel_alive
        assert not SSHClient.is_running()
    finally:
        runner.tunnel_pid = None
        if proc.poll() is None:
            proc.terminate()
            proc.communicate(timeout=5)
        runner.close()


@pytest.mark.parametrize("pid", [0, -1])
def test_invalid_pid_is_not_alive(pid):
    assert not _process_is_alive(pid)
