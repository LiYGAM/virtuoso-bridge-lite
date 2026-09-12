from __future__ import annotations

import json
import hashlib
import time

import pytest

from virtuoso_bridge.models import ExecutionStatus, VirtuosoResult
from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.transport.tunnel import (
    SSHClient,
    _copy_private_backup,
    _profiled_bridge_leaf,
    _profiled_env_key,
    resolve_auth_token,
)
from virtuoso_bridge import cli


def _restart_state(profile="v231", *, build="a" * 64):
    il_digest = "b" * 64
    deployment_id = hashlib.sha256(
        (build + "\x00" + il_digest).encode("ascii")
    ).hexdigest()
    root = "/tmp/virtuoso_bridge_release"
    return {
        "state_schema_version": 2,
        "mode": "remote",
        "profile": profile,
        "port": 65271,
        "setup_path": f"{root}/virtuoso_setup.{deployment_id}.il",
        "deployed_daemon_sha256": build,
        "deployed_il_sha256": il_digest,
        "deployed_setup_sha256": "c" * 64,
        "deployment_id": deployment_id,
        "daemon_filename": "ramic_bridge_daemon_3.py",
        "deployed_daemon_path": (
            f"{root}/ramic_bridge_daemon_3.{build}.py"
        ),
        "deployed_il_path": f"{root}/ramic_bridge.{il_digest}.il",
    }


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


def test_auth_token_refuses_non_regular_existing_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.config_dir", lambda: tmp_path)
    monkeypatch.delenv("VB_AUTH_TOKEN_v231", raising=False)
    monkeypatch.delenv("VB_AUTH_TOKEN", raising=False)
    token_path = tmp_path / "auth" / "auth_v231.token"
    token_path.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="auth token"):
        resolve_auth_token("v231", create=True)


def test_private_backup_never_overwrites_existing_path(tmp_path) -> None:
    source = tmp_path / ".cdsinit"
    source.write_text("source\n", encoding="utf-8")
    backup = tmp_path / ".cdsinit.backup"
    backup.write_text("keep\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _copy_private_backup(source, backup)
    assert backup.read_text(encoding="utf-8") == "keep\n"


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
    assert 'setShellEnvVar("RB_IDENTITY_PATH"' in setup
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
        "exclusive_request_id": "req-2",
        "exclusive_request_generation": "generation-2",
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
        "ledger_source_path": str(ledger),
        "daemon_epoch": "epoch-1",
        "exclusive_request_id": "req-2",
        "exclusive_request_generation": "generation-2",
        "request": {"request_id": "req-2", "state": "timed_out_pending"},
    }


@pytest.mark.parametrize(
    "payload",
    (
        [],
        {"requests": "not-a-list"},
        {"requests": ["not-an-object"]},
        {"heartbeat_at_epoch": float("nan"), "requests": []},
    ),
)
def test_read_request_status_rejects_malformed_or_nonfinite_ledger(
    monkeypatch,
    tmp_path,
    payload,
) -> None:
    ledger = tmp_path / "request-status.json"
    ledger.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(
        SSHClient,
        "read_state",
        classmethod(
            lambda cls, profile=None: {
                "mode": "local",
                "request_state_path": str(ledger),
            }
        ),
    )
    assert SSHClient.read_request_status("v231") is None


@pytest.mark.parametrize(
    ("ledger", "reason"),
    (
        ({"queue_depth": -1, "requests": []}, "malformed queue depth"),
        ({"queue_depth": 0, "requests": "bad"}, "malformed request ledger"),
        (
            {
                "queue_depth": 0,
                "requests": [{"request_id": "req", "state": "future_waiting"}],
            },
            "request req has unknown state future_waiting",
        ),
        (
            {
                "exclusive_request_id": "restart",
                "exclusive_request_generation": "generation-1",
                "queue_depth": 0,
                "requests": [],
            },
            "exclusive request restart",
        ),
        (
            {
                "exclusive_request_generation": "orphaned-generation",
                "queue_depth": 0,
                "requests": [],
            },
            "orphaned exclusive request generation",
        ),
    ),
)
def test_restart_busy_guard_fails_closed_on_malformed_or_future_ledger(
    ledger,
    reason,
) -> None:
    assert cli._restart_busy_reason(ledger) == reason


def test_restart_requires_capability_and_exclusive_dispatch_attribution() -> None:
    ledger = {
        "capabilities": ["exclusive-admission-v1"],
        "requests": [
            {
                "request_id": "req-restart",
                "request_digest_sha256": "e" * 64,
                "operation_class": "mutating",
                "admitted_daemon_epoch": "old-epoch",
                "exclusive": True,
            }
        ],
    }
    assert cli._restart_has_exclusive_admission(ledger) is True
    assert cli._restart_has_exclusive_admission({"capabilities": []}) is False
    assert cli._restart_dispatch_attributed(
        ledger, "req-restart", "e" * 64, "old-epoch"
    ) is True
    ledger["requests"][0]["exclusive"] = False
    assert cli._restart_dispatch_attributed(
        ledger, "req-restart", "e" * 64, "old-epoch"
    ) is False


def test_ensure_tunnel_refuses_foreign_reachable_listener(monkeypatch) -> None:
    class _Runner:
        is_tunnel_alive = False
        tunnel_pid = None

    client = SSHClient(
        remote_host="new-host",
        remote_user="designer",
        port=65271,
        local_port=65271,
        profile="v231",
        auth_token="opaque",
    )
    client._ssh_runner = _Runner()
    monkeypatch.setattr(
        "virtuoso_bridge.transport.ssh.SSHRunner.can_reach_port",
        staticmethod(lambda port: True),
    )
    monkeypatch.setattr(
        client,
        "read_state",
        lambda profile=None: {
            "mode": "remote",
            "profile": "v231",
            "port": 65271,
            "tunnel_pid": 123,
            "profile_config": {
                "remote_host": "old-host",
                "remote_user": "designer",
                "remote_port": 65271,
                "local_port": 65271,
                "jump_host": None,
                "jump_user": None,
                "allow_remote_bind": False,
            },
        },
    )
    with pytest.raises(RuntimeError, match="saved tunnel identity does not match"):
        client.ensure_tunnel()


def test_saved_auto_switched_local_port_remains_part_of_profile_identity(
    monkeypatch,
) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda: None)
    monkeypatch.setenv("VB_REMOTE_HOST_v231", "eda-host")
    monkeypatch.setenv("VB_REMOTE_USER_v231", "designer")
    monkeypatch.setenv("VB_REMOTE_PORT_v231", "65271")
    monkeypatch.delenv("VB_LOCAL_PORT_v231", raising=False)
    state = {
        "mode": "remote",
        "profile": "v231",
        "port": 65272,
        "profile_config": {
            "remote_host": "eda-host",
            "remote_user": "designer",
            "remote_port": 65271,
            "local_port": 65272,
            "jump_host": None,
            "jump_user": None,
            "allow_remote_bind": False,
        },
    }
    monkeypatch.setattr(
        SSHClient,
        "read_state",
        classmethod(lambda cls, profile=None: state),
    )

    assert SSHClient.staged_profile_config_matches_current("v231") is True
    client = SSHClient.from_env(profile="v231", create_auth_token=False)
    assert client.port == 65272

    monkeypatch.setenv("VB_REMOTE_HOST_v231", "different-host")
    assert SSHClient.staged_profile_config_matches_current("v231") is False


def test_verify_staged_files_checks_exact_local_bytes(tmp_path) -> None:
    daemon = tmp_path / "daemon.py"
    il = tmp_path / "bridge.il"
    setup = tmp_path / "setup.il"
    daemon.write_bytes(b"daemon\n")
    il.write_bytes(b"il\n")
    setup.write_bytes(b"setup\n")
    state = {
        "mode": "local",
        "deployed_daemon_path": str(daemon),
        "deployed_daemon_sha256": hashlib.sha256(daemon.read_bytes()).hexdigest(),
        "deployed_il_path": str(il),
        "deployed_il_sha256": hashlib.sha256(il.read_bytes()).hexdigest(),
        "setup_path": str(setup),
        "deployed_setup_sha256": hashlib.sha256(setup.read_bytes()).hexdigest(),
    }

    assert SSHClient.verify_staged_files("v231", state) == (True, "verified")
    setup.write_bytes(b"tampered\n")
    ok, reason = SSHClient.verify_staged_files("v231", state)
    assert ok is False
    assert "digest mismatch" in reason


@pytest.mark.parametrize("il_state", ["matching", "outdated", "missing"])
def test_deployment_status_verifies_actual_local_bytes_and_fresh_runtime(
    monkeypatch, tmp_path, il_state
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
            "deployed_il_sha256": il_sha if il_state == "matching" else "0" * 64 if il_state == "outdated" else None,
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
    assert status["local_matches_deployed"] is (il_state == "matching")
    assert status["local_il_matches_deployed"] is (il_state == "matching")
    assert status["staged_update_pending"] is (il_state != "matching")
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
        statuses = [
            {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "d" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [],
            },
            {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "d" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [],
            },
            {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "d" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [],
            },
            {
                "daemon_epoch": "new-epoch",
                "daemon_build_sha256": "a" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [
                    {
                        "request_id": "req-restart",
                        "request_digest_sha256": "e" * 64,
                        "operation_class": "mutating",
                        "admitted_daemon_epoch": "old-epoch",
                        "exclusive": True,
                        "state": "orphaned_unknown_after_daemon_restart",
                    }
                ],
            },
        ]

        @staticmethod
        def read_state(profile=None):
            assert profile == "t28_io"
            return _restart_state("t28_io")

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            return True, "verified"

        @classmethod
        def read_request_status(cls, profile=None, timeout=10.0):
            assert profile == "t28_io"
            return cls.statuses.pop(0)

    class _FakeVirtuosoClient:
        instances: list["_FakeVirtuosoClient"] = []

        def __init__(self, host, port, timeout, log_to_ciw=True, **kwargs):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.log_to_ciw = log_to_ciw
            self.skill: str | None = None
            _FakeVirtuosoClient.instances.append(self)

        def execute_skill(
            self,
            skill: str,
            timeout=5,
            operation_class=None,
            exclusive=False,
        ):
            self.skill = skill
            self.exclusive = exclusive
            return VirtuosoResult(
                status=ExecutionStatus.ERROR,
                errors=["Empty response from daemon"],
                request_id="req-restart",
                metadata={"request_digest_sha256": "e" * 64},
            )

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)
    monkeypatch.setattr(
        "virtuoso_bridge.daemon_guard.check_daemon_user",
        lambda client, profile, timeout=5: type("Check", (), {"ok": True, "error": ""})(),
    )

    assert cli._restart_daemon_one("t28_io") is True

    out = capsys.readouterr().out
    client = _FakeVirtuosoClient.instances[0]
    assert client.host == "127.0.0.1"
    assert client.port == 65271
    assert client.log_to_ciw is False
    assert client.exclusive is True
    assert client.skill.startswith('RBStop()\nload("/tmp/virtuoso_bridge_release/')
    assert "Restarting daemon [t28_io]" in out
    assert "Restart request dispatched [t28_io]" in out
    assert "Daemon restart verified [t28_io]" in out


def test_restart_daemon_refuses_cross_user_daemon(monkeypatch, capsys) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return _restart_state(profile)

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            return True, "verified"

        @staticmethod
        def read_request_status(profile=None, timeout=10.0):
            return {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "d" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [],
            }

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

    assert cli._restart_daemon_one(None) is False

    out = capsys.readouterr().out
    assert "Refusing to restart daemon" in out
    assert "alice" in out
    assert "bob" in out


def test_restart_daemon_refuses_busy_ledger_without_dispatch(monkeypatch, capsys) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return _restart_state(profile)

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            return True, "verified"

        @staticmethod
        def read_request_status(profile=None, timeout=10.0):
            return {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "old-build",
                "active_request_id": "req-live",
                "queue_depth": 0,
                "requests": [
                    {"request_id": "req-live", "state": "late_waiting_operator"}
                ],
            }

    class _UnexpectedVirtuosoClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("busy restart must not open the CIW client")

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr(
        "virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient",
        _UnexpectedVirtuosoClient,
    )

    assert cli._restart_daemon_one("v231") is False
    output = capsys.readouterr().out
    assert "active request req-live" in output


def test_restart_daemon_refuses_unavailable_ledger(monkeypatch, capsys) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return _restart_state(profile)

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            return True, "verified"

        @staticmethod
        def read_request_status(profile=None, timeout=10.0):
            return None

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    assert cli._restart_daemon_one("v231") is False
    assert "request ledger is unavailable" in capsys.readouterr().out


def test_restart_daemon_refuses_tampered_staged_state_before_dispatch(
    monkeypatch,
    capsys,
) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            state = _restart_state(profile)
            state["setup_path"] = "/tmp/arbitrary-user-file.il"
            return state

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            raise AssertionError("invalid staged state must fail before file probing")

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    assert cli._restart_daemon_one("v231") is False
    assert "staged files do not share one deployment directory" in capsys.readouterr().out


def test_restart_daemon_does_not_replay_when_convergence_is_unverified(
    monkeypatch, capsys
) -> None:
    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return _restart_state(profile)

        @staticmethod
        def verify_staged_files(profile, state, timeout=10.0):
            return True, "verified"

        @staticmethod
        def read_request_status(profile=None, timeout=10.0):
            return {
                "daemon_epoch": "old-epoch",
                "daemon_build_sha256": "d" * 64,
                "capabilities": ["exclusive-admission-v1"],
                "heartbeat_at_epoch": time.time(),
                "active_request_id": None,
                "queue_depth": 0,
                "requests": [],
            }

    class _FakeVirtuosoClient:
        dispatch_count = 0

        def __init__(self, *args, **kwargs):
            pass

        def execute_skill(
            self,
            skill: str,
            timeout=5,
            operation_class=None,
            exclusive=False,
        ):
            type(self).dispatch_count += 1
            return VirtuosoResult(status=ExecutionStatus.SUCCESS, output="t")

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr(
        "virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient",
        _FakeVirtuosoClient,
    )
    monkeypatch.setattr(
        "virtuoso_bridge.daemon_guard.check_daemon_user",
        lambda client, profile, timeout=5: type(
            "Check", (), {"ok": True, "error": ""}
        )(),
    )

    assert cli._restart_daemon_one("v231", timeout=0.15) is False
    assert _FakeVirtuosoClient.dispatch_count == 1
    output = capsys.readouterr().out
    assert "outcome is unverified" in output
    assert "was not replayed" in output


def test_restart_one_stages_before_guarded_activation(monkeypatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["v231"])
    monkeypatch.setattr(
        cli,
        "_start_one_profile",
        lambda profile, _deadline=None: order.append(f"stage:{profile}") or 0,
    )
    monkeypatch.setattr(
        cli,
        "_restart_daemon_one",
        lambda profile, timeout=30.0, _deadline=None: (
            order.append(f"restart:{profile}") or True
        ),
    )

    assert cli._restart_one(timeout=12.0) == 0
    assert order == ["stage:v231", "restart:v231"]


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


def test_status_diagnoses_banner_host_when_tunnel_endpoint_is_wrong(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(cli, "_print_spectre_status", lambda profile, suffix: None)
    monkeypatch.setattr(cli, "_CLI_PROFILE", ["split"])
    monkeypatch.setenv("VB_GUI_HOST_split", "gui-a")
    monkeypatch.setenv("VB_DEPLOY_HOST_split", "gui-a")
    monkeypatch.setenv("VB_DAEMON_HOST_split", "gui-a")
    monkeypatch.setenv("VB_REMOTE_USER_split", "designer")

    class _FakeSSHClient:
        @staticmethod
        def read_state(profile=None):
            return {
                "port": 65271,
                "setup_path": "/shared/virtuoso_setup.il",
                "daemon_endpoint_hostname": "gui-a.example.edu",
            }

        @staticmethod
        def is_running(profile=None):
            return True

        @classmethod
        def from_env(cls, **_kwargs):
            return cls()

        def read_daemon_identity(self):
            return {"host": "compute-b", "ip": "192.0.2.20"}

        def probe_daemon_endpoint_hostname(self):
            return "gui-a.example.edu"

        def close(self):
            pass

    class _FakeVirtuosoClient:
        def __init__(self, host, port, timeout):
            pass

        def test_connection(self, timeout=5):
            return False

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.SSHClient", _FakeSSHClient)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.VirtuosoClient", _FakeVirtuosoClient)

    rc = cli._print_status()

    out = capsys.readouterr().out
    assert rc == 0
    assert "[daemon host]" in out
    assert "compute-b" in out
    assert "gui-a.example.edu" in out
    assert "VB_DAEMON_HOST_split=compute-b" in out
