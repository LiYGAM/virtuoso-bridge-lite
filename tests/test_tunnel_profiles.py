from __future__ import annotations

import json
import hashlib
import time

from virtuoso_bridge.models import ExecutionStatus, VirtuosoResult
from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.transport.tunnel import (
    SSHClient,
    _profiled_bridge_leaf,
    _profiled_env_key,
    resolve_auth_token,
)
from virtuoso_bridge import cli


class _FakeRunner:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.uploads: dict[str, str] = {}
        self.command_options: list[dict[str, object]] = []
        self.upload_options: list[dict[str, object]] = []

    def run_command(self, command: str, timeout=None, **kwargs) -> CommandResult:
        self.commands.append(command)
        self.command_options.append(dict(kwargs))
        for path, text in self.uploads.items():
            if path in command and "sha256" in command:
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                return CommandResult(returncode=0, stdout=f"{digest}  {path}\n", stderr="")
        return CommandResult(returncode=0, stdout="", stderr="")

    def upload_text(self, text: str, remote_path: str, timeout=None, **kwargs) -> CommandResult:
        self.uploads[remote_path] = text
        self.upload_options.append(dict(kwargs))
        return CommandResult(returncode=0, stdout="", stderr="")


def test_profiled_bridge_leaf_preserves_default_path() -> None:
    assert _profiled_bridge_leaf(None) == "virtuoso_bridge"


def test_profiled_bridge_leaf_adds_profile_suffix() -> None:
    assert _profiled_bridge_leaf("t28_digital") == "virtuoso_bridge_t28_digital"
    assert _profiled_bridge_leaf("t28/io") == "virtuoso_bridge_t28_io"


def test_profiled_env_key_preserves_default_and_suffixes_profiles() -> None:
    assert _profiled_env_key("VB_LOCAL_PORT", None) == "VB_LOCAL_PORT"
    assert _profiled_env_key("VB_LOCAL_PORT", "t180_io") == "VB_LOCAL_PORT_t180_io"


def test_auth_token_is_stable_and_profile_scoped(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.config_dir", lambda: tmp_path)
    monkeypatch.delenv("VB_AUTH_TOKEN_v231", raising=False)
    monkeypatch.delenv("VB_AUTH_TOKEN", raising=False)

    first = resolve_auth_token("v231", create=True)
    second = resolve_auth_token("v231", create=True)

    assert first == second
    assert len(first) >= 32
    assert (tmp_path / "auth" / "auth_v231.token").read_text(
        encoding="utf-8"
    ).strip() == first


def test_remote_setup_path_and_port_are_profile_scoped(monkeypatch) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.delenv("VB_CLIENT_ID_t28_digital", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    fake = _FakeRunner()
    client = SSHClient(
        remote_host="thu-wei",
        remote_user="designer",
        port=65263,
        profile="t28_digital",
    )
    client._ssh_runner = fake
    monkeypatch.setattr(client, "_detect_remote_python", lambda: ("python3", 3, 11))

    client.ensure_remote_setup()

    assert client.remote_work_dir == "/tmp/virtuoso_bridge_designer/90590/virtuoso_bridge_t28_digital"
    setup_path = client.setup_path
    setup = fake.uploads[setup_path]
    compat_setup_path = (
        "/tmp/virtuoso_bridge_designer/90590/"
        "virtuoso_bridge_t28_digital/virtuoso_setup.il"
    )
    assert fake.uploads[compat_setup_path] == setup
    assert 'setShellEnvVar("RB_PORT" "65263")' in setup
    assert 'setShellEnvVar("RB_BIND_HOST" "127.0.0.1")' in setup
    assert 'setShellEnvVar("RB_PROFILE" "t28_digital")' in setup
    assert 'setShellEnvVar("RB_AUTH_TOKEN_FILE" "/tmp/virtuoso_bridge_designer/90590/virtuoso_bridge_t28_digital/auth.token")' in setup
    assert client.auth_token not in setup
    assert any(command.startswith("chmod 600 ") for command in fake.commands)
    assert any(
        command.startswith("chmod 700 ") and "&& chmod 600" in command
        for command in fake.commands
    )
    assert '/tmp/virtuoso_bridge_designer/90590/virtuoso_bridge_t28_digital/ramic_bridge.' in setup
    assert len(client._deployment_id or "") == 64
    assert all(call.get("retry_transport_errors") is False for call in fake.upload_options)


def test_remote_bind_requires_explicit_opt_in(monkeypatch) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    fake = _FakeRunner()
    client = SSHClient(
        remote_host="thu-wei",
        remote_user="designer",
        port=65263,
        profile="t28_digital",
        allow_remote_bind=True,
        auth_token="test-token",
    )
    client._ssh_runner = fake
    monkeypatch.setattr(client, "_detect_remote_python", lambda: ("python3", 3, 11))

    client.ensure_remote_setup()

    setup = fake.uploads[client.setup_path]
    assert 'setShellEnvVar("RB_BIND_HOST" "0.0.0.0")' in setup
    assert 'setShellEnvVar("RB_LOCAL_ONLY" "nil")' in setup


def test_read_request_status_filters_local_ledger(monkeypatch, tmp_path) -> None:
    ledger = tmp_path / "request-status.json"
    ledger.write_text(json.dumps({
        "schema_version": 1,
        "daemon_epoch": "epoch-1",
        "requests": [
            {"request_id": "req-1", "state": "succeeded"},
            {"request_id": "req-2", "state": "timed_out_pending"},
        ],
    }), encoding="utf-8")
    monkeypatch.setattr(
        SSHClient,
        "read_state",
        classmethod(lambda cls, profile=None: {
            "mode": "local", "request_state_path": str(ledger),
        }),
    )

    status = SSHClient.read_request_status("v231", "req-2")

    assert status == {
        "schema_version": 1,
        "daemon_epoch": "epoch-1",
        "request": {"request_id": "req-2", "state": "timed_out_pending"},
    }


def test_deployment_status_verifies_actual_local_bytes_and_fresh_runtime(
    monkeypatch, tmp_path
) -> None:
    daemon = tmp_path / "ramic_bridge_daemon_3.py"
    daemon.write_bytes(b"print('bridge')\n")
    legacy_daemon = tmp_path / "ramic_bridge_daemon_27.py"
    legacy_daemon.write_bytes(b"print 'bridge'\n")
    il = tmp_path / "ramic_bridge.il"
    il.write_bytes(b"t\n")
    daemon_sha = hashlib.sha256(daemon.read_bytes()).hexdigest()
    il_sha = hashlib.sha256(il.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "virtuoso_bridge.transport.tunnel._find_ramic_bridge_daemon",
        lambda major: daemon if major == 3 else legacy_daemon,
    )
    monkeypatch.setattr(
        "virtuoso_bridge.transport.tunnel._find_ramic_bridge_il", lambda: il
    )
    monkeypatch.setattr(
        SSHClient,
        "read_state",
        staticmethod(lambda profile=None: {
            "mode": "local",
            "daemon_filename": daemon.name,
            "deployed_daemon_sha256": daemon_sha,
            "deployed_daemon_path": str(daemon),
            "deployed_il_sha256": il_sha,
        }),
    )
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "daemon_epoch": "epoch-current",
            "daemon_build_sha256": daemon_sha,
            "heartbeat_at_epoch": time.time(),
            "protocol_versions": [2, 3],
            "capabilities": ["protocol-v3-frame-v1"],
        }),
    )

    status = SSHClient.deployment_status("v231")

    assert status["actual_deployed_daemon_sha256"] == daemon_sha
    assert status["local_matches_deployed"] is True
    assert status["deployed_matches_running"] is True
    assert status["running_heartbeat_fresh"] is True


def test_status_infers_profile_scoped_setup_path(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr("virtuoso_bridge.transport.remote_paths.load_vb_env", lambda: None)
    monkeypatch.delenv("VB_REMOTE_SCRATCH_ROOT", raising=False)
    monkeypatch.delenv("VB_CLIENT_ID_t28_io", raising=False)
    monkeypatch.setenv("VB_CLIENT_ID", "90590")
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["t28_io"])
    monkeypatch.setenv("VB_REMOTE_HOST_t28_io", "thu-wei")
    monkeypatch.setenv("VB_REMOTE_USER_t28_io", "designer")

    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return None

        @staticmethod
        def is_running(profile=None):
            return False

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)

    rc = cli._print_status()

    assert rc == 1
    assert (
        'load("/tmp/virtuoso_bridge_designer/90590/virtuoso_bridge_t28_io/virtuoso_setup.il")'
        in capsys.readouterr().out
    )


def test_status_no_response_prints_stale_daemon_hint(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(cli, "_print_spectre_status", lambda profile, suffix: None)
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["t28_io"])
    monkeypatch.setenv("VB_REMOTE_HOST_t28_io", "thu-wei")
    monkeypatch.setenv("VB_REMOTE_USER_t28_io", "designer")

    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return {
                "port": 65271,
                "setup_path": "/tmp/virtuoso_bridge_designer/virtuoso_bridge_t28_io/virtuoso_setup.il",
            }

        @staticmethod
        def is_running(profile=None):
            return True

    class _FakeVirtuosoClient:
        def __init__(self, host, port, timeout, **kwargs):
            pass

        def test_connection(self, timeout=5):
            return False

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)

    rc = cli._print_status()

    out = capsys.readouterr().out
    assert rc == 0
    assert "[daemon] NO RESPONSE" in out
    assert "load() did not replace the existing daemon" in out
    assert "RBStop()" in out
    assert "RBStopAll()" in out


def test_restart_daemon_loads_current_setup_and_accepts_disconnect(monkeypatch, capsys) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            assert profile == "t28_io"
            return {
                "port": 65271,
                "setup_path": '/tmp/bridge path/virtuoso"setup.il',
            }

    class _FakeVirtuosoClient:
        instances: list["_FakeVirtuosoClient"] = []

        def __init__(self, host, port, timeout, log_to_ciw=True, **kwargs):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.log_to_ciw = log_to_ciw
            self.skill: str | None = None
            _FakeVirtuosoClient.instances.append(self)

        def execute_skill(self, skill: str, timeout=5):
            self.skill = skill
            return VirtuosoResult(
                status=ExecutionStatus.ERROR,
                errors=["Empty response from daemon"],
            )

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)
    monkeypatch.setattr(
        "virtuoso_bridge.daemon_guard.check_daemon_user",
        lambda client, profile, timeout=5: type("Check", (), {"ok": True, "error": ""})(),
    )

    cli._restart_daemon_one("t28_io")

    out = capsys.readouterr().out
    client = _FakeVirtuosoClient.instances[0]
    assert client.host == "127.0.0.1"
    assert client.port == 65271
    assert client.log_to_ciw is False
    assert client.skill == 'RBStop()\nload("/tmp/bridge path/virtuoso\\"setup.il")'
    assert "Restarting daemon [t28_io]" in out
    assert "old daemon closed the connection while restarting" in out


def test_restart_daemon_refuses_cross_user_daemon(monkeypatch, capsys) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return {"port": 65271, "setup_path": "/tmp/virtuoso_setup.il"}

    class _FakeVirtuosoClient:
        def __init__(self, host, port, timeout, log_to_ciw=True, **kwargs):
            pass

        def execute_skill(self, skill: str, timeout=5):
            raise AssertionError("restart must not be sent after identity mismatch")

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)
    monkeypatch.setattr(
        "virtuoso_bridge.daemon_guard.check_daemon_user",
        lambda client, profile, timeout=5: type(
            "Check",
            (),
            {"ok": False, "error": "daemon Unix user 'alice' does not match configured VB_REMOTE_USER 'bob'"},
        )(),
    )

    cli._restart_daemon_one(None)

    out = capsys.readouterr().out
    assert "Refusing to restart daemon" in out
    assert "alice" in out
    assert "bob" in out


def test_status_fails_when_daemon_user_differs_from_tunnel_user(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(cli, "_print_spectre_status", lambda profile, suffix: None)
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["t28_io"])
    monkeypatch.setenv("VB_REMOTE_HOST_t28_io", "thu-wei")
    monkeypatch.setenv("VB_REMOTE_USER_t28_io", "designer")
    monkeypatch.delenv("VB_ALLOW_CROSS_USER_DAEMON", raising=False)

    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return {"port": 65271, "setup_path": "/tmp/virtuoso_setup.il"}

        @staticmethod
        def is_running(profile=None):
            return True

    class _FakeVirtuosoClient:
        def __init__(self, host, port, timeout, **kwargs):
            pass

        def test_connection(self, timeout=5):
            return True

        def execute_skill(self, expr, timeout=5):
            values = {
                'getShellEnvVar("USER")': "other_user",
                "getHostName()": "thu-wei",
                "getCurrentTime()": "now",
                "getVersion()": "ICADVM",
                "getWorkingDir()": "/home/other_user/TSMC28",
            }
            return VirtuosoResult(status=ExecutionStatus.SUCCESS, output=values.get(expr, ""))

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)

    rc = cli._print_status()

    out = capsys.readouterr().out
    assert rc == 1
    assert "[daemon identity] FAILED" in out
    assert "other_user" in out
    assert "designer" in out


def test_status_allows_cross_user_with_explicit_override(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(cli, "_print_spectre_status", lambda profile, suffix: None)
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["t28_io"])
    monkeypatch.setenv("VB_REMOTE_HOST_t28_io", "thu-wei")
    monkeypatch.setenv("VB_REMOTE_USER_t28_io", "designer")
    monkeypatch.setenv("VB_ALLOW_CROSS_USER_DAEMON", "1")

    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return {"port": 65271, "setup_path": "/tmp/virtuoso_setup.il"}

        @staticmethod
        def is_running(profile=None):
            return True

    class _FakeVirtuosoClient:
        def __init__(self, host, port, timeout, **kwargs):
            pass

        def test_connection(self, timeout=5):
            return True

        def execute_skill(self, expr, timeout=5):
            values = {
                'getShellEnvVar("USER")': "other_user",
                "getHostName()": "thu-wei",
                "getCurrentTime()": "now",
                "getVersion()": "ICADVM",
                "getWorkingDir()": "/home/other_user/TSMC28",
            }
            return VirtuosoResult(status=ExecutionStatus.SUCCESS, output=values.get(expr, ""))

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)

    rc = cli._print_status()

    out = capsys.readouterr().out
    assert rc == 0
    assert "[daemon identity] FAILED" not in out


def test_tunnel_run_command_only_retries_explicit_read_only_operations() -> None:
    calls: list[bool] = []

    class _Runner:
        def run_command(self, command, timeout=None, *, retry_transport_errors=True):
            calls.append(retry_transport_errors)
            return CommandResult(returncode=0, stdout=command, stderr="")

    client = SSHClient(remote_host="thu-wei", remote_user="designer")
    client._ssh_runner = _Runner()

    client.run_command("touch /tmp/marker", operation_class="mutating")
    client.run_command("test -f /tmp/marker", operation_class="read_only")

    assert calls == [False, True]
