from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.transport.tunnel import (
    SSHClient,
    _atomic_write_bytes,
    _local_autoload_lock,
    _autoload_markers,
)


def _local_client(monkeypatch, tmp_path: Path, profile: str = "v231") -> tuple[SSHClient, Path, Path]:
    cdsinit = tmp_path / ".cdsinit"
    workdir = tmp_path / "work"
    workdir.mkdir()
    setup = workdir / "virtuoso_setup.il"
    setup.write_text("; setup\n", encoding="utf-8")
    monkeypatch.setenv("VB_CDSINIT_PATH_v231", str(cdsinit))
    client = SSHClient(
        remote_host="localhost",
        port=65432,
        profile=profile,
        auth_token="opaque-token",
    )
    client._compat_setup_path = str(setup)
    return client, cdsinit, setup


def test_local_autoload_lock_refuses_concurrent_direct_cli_writer(tmp_path: Path) -> None:
    target = tmp_path / ".cdsinit"
    with _local_autoload_lock(target):
        with pytest.raises(RuntimeError, match="already running"):
            with _local_autoload_lock(target):
                raise AssertionError("concurrent lock must not be acquired")


def test_local_autoload_install_idempotent_and_uninstall_preserves_text(monkeypatch, tmp_path):
    client, cdsinit, setup = _local_client(monkeypatch, tmp_path)
    cdsinit.write_text("; user header\n(setq userValue 1)\n", encoding="utf-8")

    first = client.autoload_install()
    text = cdsinit.read_text(encoding="utf-8")
    assert first["installed"] is True
    assert text.count("when(isFile(") == 1
    assert "token" not in json.dumps(first)
    if os.name != "nt":
        assert os.stat(cdsinit).st_mode & 0o777 == 0o600
    backup_count = len(list(tmp_path.glob(".cdsinit.virtuoso-bridge.*.bak")))

    second = client.autoload_install()
    assert cdsinit.read_text(encoding="utf-8") == text
    assert len(list(tmp_path.glob(".cdsinit.virtuoso-bridge.*.bak"))) == backup_count
    assert second["exact_match"] is True

    removed = client.autoload_uninstall()
    assert removed["installed"] is False
    assert cdsinit.read_text(encoding="utf-8") == "; user header\n(setq userValue 1)\n"
    assert setup.exists()
    after_uninstall_backups = len(
        list(tmp_path.glob(".cdsinit.virtuoso-bridge.*.bak"))
    )
    client.autoload_uninstall()
    assert (
        len(list(tmp_path.glob(".cdsinit.virtuoso-bridge.*.bak")))
        == after_uninstall_backups
    )


def test_local_autoload_replaces_duplicate_and_adopts_legacy(monkeypatch, tmp_path):
    client, cdsinit, setup = _local_client(monkeypatch, tmp_path)
    expected = str(setup).replace("\\", "/")
    legacy = (
        f"; Auto-load virtuoso-bridge-lite profile v231\n"
        f'when(isFile("{expected}")\n'
        f'    load("{expected}")\n'
        ")\n"
    )
    start, end = _autoload_markers("v231")
    managed = f'{start}\nwhen(isFile("old") load("old"))\n{end}\n'
    cdsinit.write_text("before\n" + legacy + managed + managed + "after\n", encoding="utf-8")

    status = client.autoload_status()
    assert status["legacy_exact_match"] is True
    assert status["duplicate_block_count"] == 2
    installed = client.autoload_install()
    text = cdsinit.read_text(encoding="utf-8")
    assert installed["exact_match"] is True
    assert text.count(start) == 1
    assert legacy not in text
    assert text.startswith("before\n") and "after\n" in text


def test_local_autoload_status_reports_mismatch_and_uninstall_keeps_legacy(monkeypatch, tmp_path):
    client, cdsinit, setup = _local_client(monkeypatch, tmp_path)
    cdsinit.write_text(
        "; Auto-load virtuoso-bridge-lite profile v231\n"
        'when(isFile("/other/virtuoso_setup.il") load("/other/virtuoso_setup.il"))\n',
        encoding="utf-8",
    )
    status = client.autoload_status()
    assert status["installed"] is False
    assert status["legacy_exact_match"] is False
    client.autoload_uninstall()
    assert "other/virtuoso_setup.il" in cdsinit.read_text(encoding="utf-8")


def test_install_preserves_incomplete_marker_and_user_text(monkeypatch, tmp_path):
    client, cdsinit, _ = _local_client(monkeypatch, tmp_path)
    start, end = _autoload_markers("v231")
    cdsinit.write_text(
        f"{start}\n"
        "(setq userMustStay 7)\n"
        f"{start}\n"
        'when(isFile("old") load("old"))\n'
        f"{end}\n",
        encoding="utf-8",
    )

    installed = client.autoload_install()
    text = cdsinit.read_text(encoding="utf-8")
    assert installed["exact_match"] is True
    assert text.startswith(f"{start}\n(setq userMustStay 7)\n")
    assert text.count("(setq userMustStay 7)") == 1
    assert 'when(isFile("old")' not in text


def test_local_autoload_refuses_symlink_target(monkeypatch, tmp_path):
    client, cdsinit, _ = _local_client(monkeypatch, tmp_path)
    target = tmp_path / "real-cdsinit"
    target.write_text("; user-owned\n", encoding="utf-8")
    try:
        cdsinit.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    status = client.autoload_status()
    assert status["target_is_symlink"] is True
    with pytest.raises(RuntimeError, match="symlink"):
        client.autoload_install()
    assert target.read_text(encoding="utf-8") == "; user-owned\n"


def test_local_autoload_refuses_non_regular_target(monkeypatch, tmp_path):
    client, cdsinit, _ = _local_client(monkeypatch, tmp_path)
    cdsinit.mkdir()

    status = client.autoload_status()
    assert status["error"] == "target is not a regular file"
    with pytest.raises(RuntimeError, match="non-regular"):
        client.autoload_install()
    assert cdsinit.is_dir()


def test_atomic_local_replace_refuses_concurrent_content_change(tmp_path):
    cdsinit = tmp_path / ".cdsinit"
    cdsinit.write_bytes(b"; newer user edit\n")

    with pytest.raises(RuntimeError, match="concurrent"):
        _atomic_write_bytes(
            cdsinit,
            b"; bridge edit\n",
            expected_current=b"; older snapshot\n",
            expected_exists=True,
        )
    assert cdsinit.read_bytes() == b"; newer user edit\n"


def test_local_autoload_preserves_crlf_line_endings(monkeypatch, tmp_path):
    client, cdsinit, _ = _local_client(monkeypatch, tmp_path)
    cdsinit.write_bytes(b"; user header\r\n")

    client.autoload_install()
    content = cdsinit.read_bytes()
    assert b"; user header\r\n" in content
    assert b"\r\n; >>> virtuoso-bridge autoload profile " in content


def test_parser_exposes_autoload_operations() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["autoload", "status", "-p", "v231"])
    assert args.command == "autoload"
    assert args.action == "status"
    assert args.profile == "v231"
    restart = parser.parse_args(["restart", "-p", "v231", "--timeout", "12.5"])
    assert restart.timeout == 12.5
    for invalid in (
        ["restart", "--timeout", "inf"],
        ["autoload", "status", "--timeout", "nan"],
        ["request-await", "req", "--poll-interval", "inf"],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(invalid)


def test_from_env_status_client_does_not_generate_auth_token(monkeypatch, tmp_path):
    monkeypatch.setenv("VB_REMOTE_HOST_v231", "localhost")
    monkeypatch.setenv("VB_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("VB_AUTH_TOKEN_v231", "")
    monkeypatch.setenv("VB_AUTH_TOKEN", "")

    def unexpected_token() -> str:
        raise AssertionError("read-only autoload client must not generate a token")

    monkeypatch.setattr(
        "virtuoso_bridge.transport.tunnel.secrets.token_urlsafe",
        unexpected_token,
    )
    client = SSHClient.from_env(profile="v231", create_auth_token=False)
    assert client.auth_token == ""


class _RemoteRunner:
    def __init__(
        self,
        cdsinit: str,
        setup_exists: bool = True,
        *,
        owner: str = "1000",
        uid: str = "1000",
        mode: str = "600",
    ):
        self.cdsinit = cdsinit
        self.setup_exists = setup_exists
        self.owner = owner
        self.uid = uid
        self.mode = mode
        self.options: list[dict[str, object]] = []
        self.uploads: list[tuple[str, str]] = []
        self.commands: list[str] = []

    def run_command(self, command, timeout=None, **kwargs):
        self.options.append(dict(kwargs))
        self.commands.append(command)
        if "__VB_PATH__" in command:
            encoded = base64.b64encode(self.cdsinit.encode()).decode()
            setup = "1" if self.setup_exists else "0"
            return CommandResult(
                returncode=0,
                stdout=(
                    "__VB_PATH__ /home/user/.cdsinit\n"
                    f"__VB_UID__ {self.uid}\n"
                    f"__VB_EXISTS__ {self.owner} {self.mode}\n"
                    f"__VB_BASE64__\n{encoded}\n"
                    f"__VB_SETUP_EXISTS__ {setup}\n"
                ),
                stderr="",
            )
        if "chmod 600" in command:
            self.mode = "600"
        return CommandResult(returncode=0, stdout="", stderr="")

    def upload_text(self, text, remote_path, timeout=None, **kwargs):
        self.options.append(dict(kwargs))
        self.uploads.append((remote_path, text))
        if text.count("when(isFile("):
            self.cdsinit = text
        return CommandResult(returncode=0, stdout="", stderr="")


def test_remote_autoload_mutators_disable_transport_retries(monkeypatch):
    runner = _RemoteRunner("; user\n", mode="777")
    client = SSHClient(remote_host="remote", profile="v231", auth_token="opaque")
    client._ssh_runner = runner
    client._compat_setup_path = "/tmp/virtuoso_setup.il"
    result = client.autoload_install()
    assert result["installed"] is True
    assert result["mode_octal"] == "0600"
    assert result["permission_safe"] is True
    assert runner.options
    assert all(item.get("retry_transport_errors") is False for item in runner.options)
    assert runner.uploads[0][0].startswith("/home/user/.cdsinit.")
    assert "$HOME" not in runner.uploads[0][0]
    mutation = next(command for command in runner.commands if "exec 3>" in command)
    assert "exec 9>>" in mutation
    assert "flock -n 9" in mutation
    assert ".cdsinit.virtuoso-bridge.lock" in mutation
    assert "chmod 600" in mutation
    assert "sha256sum" in mutation
    assert "cmp -s" in mutation
    assert "/home/user/.cdsinit.virtuoso-bridge." in mutation
    upload_options = next(
        options
        for options in runner.options
        if options.get("exclusive_create") is True
    )
    assert upload_options.get("create_parent") is False

    upload_count = len(runner.uploads)
    command_count = len(runner.commands)
    again = client.autoload_install()
    assert again["exact_match"] is True
    assert len(runner.uploads) == upload_count
    noop_commands = runner.commands[command_count:]
    assert any("flock -n 9" in command for command in noop_commands)
    assert all("mv -f" not in command for command in noop_commands)


def test_remote_autoload_refuses_owner_mismatch_before_upload():
    runner = _RemoteRunner("; user\n", owner="1001", uid="1000", mode="777")
    client = SSHClient(remote_host="remote", profile="v231", auth_token="opaque")
    client._ssh_runner = runner
    client._compat_setup_path = "/tmp/virtuoso_setup.il"

    with pytest.raises(RuntimeError, match="non-owned"):
        client.autoload_install()
    assert runner.uploads == []


class _StartClient:
    def __init__(self):
        self.warm_calls = 0
        self.close_calls = 0

    def warm(self):
        self.warm_calls += 1

    def close(self):
        self.close_calls += 1


def test_start_running_unchanged_uses_fast_path(monkeypatch, capsys):
    monkeypatch.setenv("VB_REMOTE_HOST_v231", "remote")
    monkeypatch.setattr(
        SSHClient,
        "is_running",
        classmethod(lambda cls, profile=None: True),
    )
    monkeypatch.setattr(
        SSHClient,
        "staged_profile_config_matches_current",
        classmethod(lambda cls, profile=None: True),
    )
    monkeypatch.setattr(
        SSHClient,
        "staged_resources_match_current",
        classmethod(lambda cls, profile=None: True),
    )

    def unexpected_from_env(cls, **kwargs):
        raise AssertionError("unchanged resources must not stage or open CIW")

    monkeypatch.setattr(SSHClient, "from_env", classmethod(unexpected_from_env))
    assert cli._start_one_profile("v231") == 0
    assert "already running" in capsys.readouterr().out


def test_start_running_changed_stages_without_activating(monkeypatch, capsys):
    staged = _StartClient()
    monkeypatch.setenv("VB_REMOTE_HOST_v231", "remote")
    monkeypatch.setattr(
        SSHClient,
        "is_running",
        classmethod(lambda cls, profile=None: True),
    )
    monkeypatch.setattr(
        SSHClient,
        "staged_profile_config_matches_current",
        classmethod(lambda cls, profile=None: True),
    )
    monkeypatch.setattr(
        SSHClient,
        "staged_resources_match_current",
        classmethod(lambda cls, profile=None: False),
    )
    monkeypatch.setattr(
        SSHClient,
        "from_env",
        classmethod(lambda cls, **kwargs: staged),
    )

    assert cli._start_one_profile("v231") == 0
    output = capsys.readouterr().out
    assert staged.warm_calls == 1
    assert staged.close_calls == 1
    assert "without restarting the daemon" in output
    assert "explicit `virtuoso-bridge restart`" in output


def test_start_refuses_running_endpoint_after_profile_identity_change(
    monkeypatch,
    capsys,
):
    monkeypatch.setenv("VB_REMOTE_HOST_v231", "new-host")
    monkeypatch.setattr(
        SSHClient,
        "is_running",
        classmethod(lambda cls, profile=None: True),
    )
    monkeypatch.setattr(
        SSHClient,
        "staged_profile_config_matches_current",
        classmethod(lambda cls, profile=None: False),
    )

    def unexpected_from_env(cls, **kwargs):
        raise AssertionError("mismatched running endpoint must not be reused")

    monkeypatch.setattr(SSHClient, "from_env", classmethod(unexpected_from_env))
    assert cli._start_one_profile("v231") == 1
    assert "Refusing to reuse the running Bridge endpoint" in capsys.readouterr().out
