from types import SimpleNamespace
import json
from virtuoso_bridge.transport.tunnel import SSHClient


def test_remote_ledger_uses_only_recorded_predecessor(monkeypatch):
    commands = []

    def run(command, timeout=None):
        commands.append(command)
        if "/new/" in command:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "requests": [{"request_id": "r", "state": "succeeded"}],
            "daemon_epoch": "epoch"}))

    client = SimpleNamespace(_require_runner=lambda: SimpleNamespace(run_command=run), close=lambda: None)
    monkeypatch.setattr(SSHClient, "read_state", classmethod(lambda cls, profile=None: {
        "mode": "remote", "request_state_path": "/new/request-status.json",
        "previous_setup_path": "/old/setup.il"}))
    monkeypatch.setattr(SSHClient, "from_env", classmethod(lambda cls, **kw: client))
    result = SSHClient.read_request_status("v231", "r")
    assert result["ledger_source_path"] == "/old/request-status.json"
    assert len(commands) == 2
    assert result["request"]["request_id"] == "r"
