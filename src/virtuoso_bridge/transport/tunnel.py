"""SSHClient — SSH tunnel + remote RAMIC daemon deployment.

Manages the SSH port-forward tunnel and remote file deployment independently
from the SKILL execution client (VirtuosoClient). VirtuosoClient only needs a
localhost:port TCP endpoint; SSHClient makes that endpoint available.
"""

from __future__ import annotations

import importlib.resources
import hashlib
import json
import logging
import os
import re
import secrets
import shlex
import socket
import sys
import time
from pathlib import Path
from typing import Any

from virtuoso_bridge.env import load_vb_env, resolve_env_path
from virtuoso_bridge.profile import resolve_profile
from virtuoso_bridge.runtime_paths import config_dir, legacy_cache_state_file, state_dir
from virtuoso_bridge.transport.remote_paths import (
    default_virtuoso_bridge_dir,
    resolve_client_id,
    resolve_remote_username,
)
from virtuoso_bridge.transport.ssh import SSHRunner, CommandResult, _TimeoutBudget

logger = logging.getLogger(__name__)

_TUNNEL_STARTUP_SETTLE_SECONDS = 1.0


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_resource_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            tmp_path.chmod(0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _is_localhost(host: str | None) -> bool:
    """Return True if *host* refers to the local machine."""
    if not host:
        return False
    return host.strip().lower() in ("localhost", "127.0.0.1", "::1")


def _state_file(profile: str | None = None) -> Path:
    name = f"state_{profile}.json" if profile else "state.json"
    return state_dir() / name


def _state_file_candidates(profile: str | None = None) -> list[Path]:
    primary = _state_file(profile)
    legacy = legacy_cache_state_file(profile)
    return [primary] if primary == legacy else [primary, legacy]


def _auth_token_file(profile: str | None = None) -> Path:
    name = f"auth_{profile}.token" if profile else "auth.token"
    return config_dir() / "auth" / name


def resolve_auth_token(profile: str | None = None, *, create: bool = False) -> str:
    """Resolve the per-profile daemon token without exposing it in evidence."""
    load_vb_env()
    suffix = f"_{profile}" if profile else ""
    for key in (f"VB_AUTH_TOKEN{suffix}", "VB_AUTH_TOKEN"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    path = _auth_token_file(profile)
    if path.is_file():
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if value:
            return value
    if not create:
        return ""
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(32)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = path.read_text(encoding="utf-8").strip()
        if not existing:
            raise RuntimeError(f"Bridge auth token file is empty: {path}")
        return existing
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o600)
    return value


def remote_bind_allowed(profile: str | None = None) -> bool:
    suffix = f"_{profile}" if profile else ""
    for key in (f"VB_ALLOW_REMOTE_BIND{suffix}", "VB_ALLOW_REMOTE_BIND"):
        if os.getenv(key, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False

# ---------------------------------------------------------------------------
# Resource helpers (moved from bridge.py)
# ---------------------------------------------------------------------------

def _find_ramic_bridge_il() -> Path:
    try:
        resources = importlib.resources.files("virtuoso_bridge.virtuoso.basic.resources")
        il_ref = resources / "ramic_bridge.il"
        with importlib.resources.as_file(il_ref) as il_path:
            if il_path.is_file():
                return il_path
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    raise FileNotFoundError(
        "Cannot locate ramic_bridge.il in virtuoso_bridge.virtuoso.basic.resources."
    )


def _find_ramic_bridge_daemon(python_major: int) -> Path:
    filename = "ramic_bridge_daemon_3.py" if python_major >= 3 else "ramic_bridge_daemon_27.py"
    try:
        resources = importlib.resources.files("virtuoso_bridge.virtuoso.basic.resources")
        daemon_ref = resources / filename
        with importlib.resources.as_file(daemon_ref) as daemon_path:
            if daemon_path.is_file():
                return daemon_path
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    raise FileNotFoundError(f"Cannot locate {filename} in virtuoso_bridge.virtuoso.basic.resources.")



def _generate_virtuoso_setup_il(
    daemon_path: str,
    il_path: str,
    python_cmd: str = "python",
    port: int = 65432,
    *,
    auth_token_path: str = "",
    request_state_path: str = "",
    allow_remote_bind: bool = False,
    profile: str | None = None,
) -> str:
    return (
        "; Virtuoso CIW Setup Script - RAMIC Bridge\n"
        "; Auto-generated by virtuoso-bridge\n"
        f'; Execute in CIW: load("{il_path.replace(chr(0x5c), "/")}")\n'
        "\n"
        "; Set environment variables\n"
        f'setShellEnvVar("RB_DAEMON_PATH" "{daemon_path}")\n'
        f'setShellEnvVar("RB_PYTHON_PATH" "{python_cmd}")\n'
        f'setShellEnvVar("RB_PORT" "{port}")\n'
        f'setShellEnvVar("RB_AUTH_TOKEN_FILE" "{auth_token_path}")\n'
        f'setShellEnvVar("RB_REQUEST_STATE_FILE" "{request_state_path}")\n'
        f'setShellEnvVar("RB_PROFILE" "{profile or ""}")\n'
        f'setShellEnvVar("RB_LOCAL_ONLY" "{"nil" if allow_remote_bind else "t"}")\n'
        f'setShellEnvVar("RB_BIND_HOST" "{"0.0.0.0" if allow_remote_bind else "127.0.0.1"}")\n'
        "\n"
        "; Load RAMIC Bridge IL script\n"
        f'load("{il_path}")\n'
        "\n"
        "; Setup complete!\n"
    )


def _update_env_file(key: str, value: str) -> bool:
    try:
        env_path = resolve_env_path()
    except FileNotFoundError:
        return False
    if env_path is not None and env_path.is_file():
        text = env_path.read_text(encoding="utf-8")
        new_text = re.sub(
            rf"^{re.escape(key)}\s*=.*$",
            f"{key}={value}",
            text,
            flags=re.MULTILINE,
        )
        if new_text != text:
            env_path.write_text(new_text, encoding="utf-8")
            logger.info("Updated %s=%s in %s", key, value, env_path)
            return True
        return False
    return False


def _profiled_bridge_leaf(profile: str | None) -> str:
    """Remote bridge directory leaf for a connection profile."""
    if not profile:
        return "virtuoso_bridge"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", profile.strip())[:64]
    return f"virtuoso_bridge_{safe or 'profile'}"


def _profiled_env_key(base: str, profile: str | None) -> str:
    return f"{base}_{profile}" if profile else base


# ---------------------------------------------------------------------------
# SSHClient
# ---------------------------------------------------------------------------

class SSHClient:
    """Manages SSH tunnel and remote RAMIC daemon deployment.

    Provides a localhost:port TCP endpoint that tunnels to the remote daemon.
    Completely independent of SKILL execution logic.
    """

    def __init__(
        self,
        remote_host: str,
        remote_user: str | None = None,
        port: int = 65432,
        local_port: int | None = None,
        jump_host: str | None = None,
        jump_user: str | None = None,
        timeout: int = 30,
        keep_remote_files: bool = False,
        profile: str | None = None,
        auth_token: str | None = None,
        allow_remote_bind: bool = False,
    ) -> None:
        self._remote_host = remote_host
        self._remote_user = remote_user
        self._port = port  # remote daemon port
        self._local_port = local_port if local_port is not None else port
        self._jump_host = jump_host
        self._jump_user = jump_user
        self._timeout = timeout
        self._keep_remote_files = keep_remote_files
        self._profile = profile
        self._auth_token = auth_token or secrets.token_urlsafe(32)
        self._allow_remote_bind = bool(allow_remote_bind)
        self._request_state_path: str | None = None
        self._deployed_daemon_sha256: str | None = None
        self._deployed_il_sha256: str | None = None
        self._deployed_setup_sha256: str | None = None
        self._deployed_daemon_path: str | None = None
        self._deployed_il_path: str | None = None
        self._compat_setup_path: str | None = None
        self._deployment_id: str | None = None
        self._daemon_filename: str | None = None

        if _is_localhost(remote_host):
            self._ssh_runner = None
        else:
            self._ssh_runner = SSHRunner(
                host=remote_host,
                user=remote_user,
                jump_host=jump_host,
                jump_user=jump_user,
                persistent_shell=True,
                verbose=True,
            )

        self._remote_setup_done = False
        self._remote_work_dir: str | None = None
        self._remote_virtuoso_setup_path: str | None = None

    # -- factory methods ----------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        keep_remote_files: bool = False,
        profile: str | None = None,
        allow_remote_bind: bool | None = None,
        create_auth_token: bool = True,
    ) -> "SSHClient":
        """Create from VB_* environment variables.

        If *profile* is given (e.g. ``"gpu1"``), reads ``VB_REMOTE_HOST_gpu1``
        etc.  Otherwise resolves a profile binding before falling back to the
        default unsuffixed variables.
        """
        profile = resolve_profile(profile)
        load_vb_env()

        suffix = f"_{profile}" if profile else ""

        remote_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()
        if not remote_host:
            var = f"VB_REMOTE_HOST{suffix}"
            raise RuntimeError(f"{var} must be set")

        remote_user = os.getenv(f"VB_REMOTE_USER{suffix}", "").strip() or None
        jump_host = os.getenv(f"VB_JUMP_HOST{suffix}", "").strip() or None
        jump_user = os.getenv(f"VB_JUMP_USER{suffix}", "").strip() or None

        # Port
        from virtuoso_bridge.virtuoso.basic.bridge import _default_remote_port
        try:
            port = int(os.getenv(f"VB_REMOTE_PORT{suffix}", "").strip() or _default_remote_port(remote_user))
        except (ValueError, TypeError):
            port = _default_remote_port(remote_user)

        # Local port (defaults to remote port if not set)
        local_port_str = os.getenv(f"VB_LOCAL_PORT{suffix}", "").strip()
        local_port: int | None = None
        if local_port_str:
            try:
                local_port = int(local_port_str)
            except (ValueError, TypeError):
                pass

        return cls(
            remote_host=remote_host,
            remote_user=remote_user,
            port=port,
            local_port=local_port,
            jump_host=jump_host,
            jump_user=jump_user,
            keep_remote_files=keep_remote_files,
            profile=profile,
            auth_token=(
                resolve_auth_token(profile, create=create_auth_token)
                or secrets.token_urlsafe(32)
            ),
            allow_remote_bind=(
                remote_bind_allowed(profile)
                if allow_remote_bind is None
                else allow_remote_bind
            ),
        )

    # -- properties ---------------------------------------------------------

    @property
    def port(self) -> int:
        """Port that VirtuosoClient should connect to.

        In local mode there is no SSH tunnel, so the client connects
        directly to the daemon port.  In remote mode the client connects
        to the local end of the SSH tunnel.
        """
        if _is_localhost(self._remote_host):
            return self._port
        return self._local_port

    @property
    def remote_host(self) -> str:
        return self._remote_host

    @property
    def ssh_runner(self) -> SSHRunner | None:
        return self._ssh_runner

    def _require_runner(self) -> SSHRunner:
        runner = self._ssh_runner
        if runner is None:
            raise RuntimeError("SSH runner is unavailable in local mode")
        return runner

    @property
    def remote_work_dir(self) -> str | None:
        return self._remote_work_dir

    @property
    def setup_path(self) -> str | None:
        return self._remote_virtuoso_setup_path

    @property
    def auth_token(self) -> str:
        return self._auth_token

    @property
    def request_state_path(self) -> str | None:
        return self._request_state_path

    @property
    def is_tunnel_alive(self) -> bool:
        if self._ssh_runner is None:
            return False
        return self._ssh_runner.is_tunnel_alive

    # -- remote deployment --------------------------------------------------

    def _detect_remote_python(
        self, *, _budget: _TimeoutBudget | None = None
    ) -> tuple[str, int, int]:
        # Try Cadence-bundled Python 3.9+ first (IC23.1+), then system python3,
        # then generic python, then python2.7.
        detect_cmd = (
            '(test -x "$CDSHOME/tools.lnx86/python/64bit/bin/python3" && '
            '$CDSHOME/tools.lnx86/python/64bit/bin/python3 --version 2>&1 && '
            'echo "CMD:$CDSHOME/tools.lnx86/python/64bit/bin/python3") || '
            '(python3 --version 2>&1 && echo "CMD:python3") || '
            '(python --version 2>&1 && echo "CMD:python") || '
            '(python2.7 --version 2>&1 && echo "CMD:python2.7") || '
            'echo "CMD:NONE"'
        )
        runner = self._require_runner()
        budget = _budget or _TimeoutBudget.start(None, self._timeout)
        result = runner.run_command(
            detect_cmd,
            timeout=budget.remaining("detect-remote-python"),
        )
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        logger.info("Remote Python detection output: %s", output)

        python_cmd = None
        python_major = None
        python_minor = 0
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("CMD:"):
                cmd = line[4:]
                if cmd != "NONE":
                    python_cmd = cmd
            elif line.startswith("Python "):
                try:
                    parts = line.split()[1].split(".")
                    python_major = int(parts[0])
                    python_minor = int(parts[1]) if len(parts) > 1 else 0
                except (IndexError, ValueError):
                    pass

        if python_cmd is None or python_major is None:
            details = f"Detection output: {output!r}"
            if stderr:
                details += f". SSH stderr: {stderr!r}"
            if result.returncode != 0:
                details += f". SSH return code: {result.returncode}"
            raise RuntimeError(
                f"No Python interpreter found on {self._remote_host}. "
                f"{details}"
            )
        logger.info("Detected remote Python: %s (version %d.%d)", python_cmd, python_major, python_minor)
        return python_cmd, python_major, python_minor

    def ensure_remote_setup(
        self,
        timeout: float | None = None,
        *,
        _budget: _TimeoutBudget | None = None,
    ) -> None:
        """Upload daemon files and generate virtuoso_setup.il on the remote host."""
        if self._remote_setup_done:
            return

        runner = self._require_runner()
        budget = _budget or _TimeoutBudget.start(timeout, self._timeout)
        try:
            python_cmd, python_major, python_minor = self._detect_remote_python(
                _budget=budget
            )
        except TypeError as exc:
            # Preserve compatibility with lightweight test/client overrides
            # that implement the older zero-argument hook.
            if "_budget" not in str(exc):
                raise
            python_cmd, python_major, python_minor = self._detect_remote_python()
        daemon_local = _find_ramic_bridge_daemon(
            3 if python_major >= 3 else 2
        )
        il_local = _find_ramic_bridge_il()
        daemon_filename = daemon_local.name
        daemon_text = _canonical_resource_text(daemon_local)
        il_text = _canonical_resource_text(il_local)
        daemon_sha256 = _sha256_bytes(daemon_text.encode("utf-8"))
        il_sha256 = _sha256_bytes(il_text.encode("utf-8"))
        deployment_id = _sha256_bytes(
            (daemon_sha256 + "\x00" + il_sha256).encode("ascii")
        )

        remote_username = resolve_remote_username(
            configured_user=self._remote_user,
            runner=runner,
        )
        self._remote_work_dir = default_virtuoso_bridge_dir(
            remote_username,
            _profiled_bridge_leaf(self._profile),
            resolve_client_id(self._profile),
        )

        daemon_stem, daemon_suffix = os.path.splitext(daemon_filename)
        remote_daemon = (
            f"{self._remote_work_dir}/{daemon_stem}.{daemon_sha256}{daemon_suffix}"
        )
        remote_il = f"{self._remote_work_dir}/ramic_bridge.{il_sha256}.il"
        remote_setup = f"{self._remote_work_dir}/virtuoso_setup.{deployment_id}.il"
        remote_compat_setup = f"{self._remote_work_dir}/virtuoso_setup.il"
        remote_token = f"{self._remote_work_dir}/auth.token"
        remote_request_state = f"{self._remote_work_dir}/request-status.json"

        logger.info("Creating remote directory: %s", self._remote_work_dir)
        quoted_work_dir = shlex.quote(self._remote_work_dir)
        mkdir_result = runner.run_command(
            f"if [ -L {quoted_work_dir} ]; then exit 41; fi; "
            f"if [ -e {quoted_work_dir} ] && [ ! -d {quoted_work_dir} ]; then exit 42; fi; "
            f"mkdir -p {quoted_work_dir} || exit 42; "
            f"owner=$(stat -c %u -- {quoted_work_dir}) || exit 43; "
            f"[ \"$owner\" = \"$(id -u)\" ] || exit 44; "
            f"chmod 700 {quoted_work_dir}",
            timeout=budget.remaining("create-remote-bridge-directory"),
            retry_transport_errors=False,
        )
        if mkdir_result.returncode != 0:
            raise RuntimeError(f"Failed to create remote directory: {mkdir_result.stderr.strip()}")

        logger.info("Uploading daemon script (%s) to %s", daemon_filename, remote_daemon)
        up = runner.upload_text(
            daemon_text,
            remote_daemon,
            timeout=budget.remaining("upload-daemon"),
            retry_transport_errors=False,
        )
        if up.returncode != 0:
            raise RuntimeError(f"Failed to upload daemon: {up.stderr.strip()}")

        logger.info("Uploading IL script to %s", remote_il)
        up = runner.upload_text(
            il_text,
            remote_il,
            timeout=budget.remaining("upload-bridge-il"),
            retry_transport_errors=False,
        )
        if up.returncode != 0:
            raise RuntimeError(f"Failed to upload IL script: {up.stderr.strip()}")

        up = runner.upload_text(
            self._auth_token + "\n",
            remote_token,
            timeout=budget.remaining("upload-auth-token"),
            retry_transport_errors=False,
        )
        if up.returncode != 0:
            raise RuntimeError(f"Failed to upload daemon auth token: {up.stderr.strip()}")
        chmod_result = runner.run_command(
            f"chmod 600 {shlex.quote(remote_token)}",
            timeout=budget.remaining("protect-auth-token"),
            retry_transport_errors=False,
        )
        if chmod_result.returncode != 0:
            raise RuntimeError(
                f"Failed to protect daemon auth token: {chmod_result.stderr.strip()}"
            )

        setup_content = _generate_virtuoso_setup_il(
            remote_daemon,
            remote_il,
            python_cmd,
            port=self._port,
            auth_token_path=remote_token,
            request_state_path=remote_request_state,
            allow_remote_bind=self._allow_remote_bind,
            profile=self._profile,
        )
        if not setup_content.endswith("\n"):
            setup_content += "\n"
        setup_sha256 = _sha256_bytes(setup_content.encode("utf-8"))
        logger.info("Uploading setup script to %s", remote_setup)
        up = runner.upload_text(
            setup_content,
            remote_setup,
            timeout=budget.remaining("upload-bridge-setup"),
            retry_transport_errors=False,
        )
        if up.returncode != 0:
            raise RuntimeError(f"Failed to upload setup script: {up.stderr.strip()}")
        compat_up = runner.upload_text(
            setup_content,
            remote_compat_setup,
            timeout=budget.remaining("upload-compatible-bridge-setup"),
            retry_transport_errors=False,
        )
        if compat_up.returncode != 0:
            raise RuntimeError(
                f"Failed to upload compatible setup script: {compat_up.stderr.strip()}"
            )
        permissions_result = runner.run_command(
            "chmod 700 {work_dir} && chmod 600 {daemon} {il} {setup} {compat_setup} {token}".format(
                work_dir=shlex.quote(self._remote_work_dir),
                daemon=shlex.quote(remote_daemon),
                il=shlex.quote(remote_il),
                setup=shlex.quote(remote_setup),
                compat_setup=shlex.quote(remote_compat_setup),
                token=shlex.quote(remote_token),
            ),
            timeout=budget.remaining("finalize-bridge-permissions"),
            retry_transport_errors=False,
        )
        if permissions_result.returncode != 0:
            raise RuntimeError(
                "Failed to finalize daemon file permissions: "
                f"{permissions_result.stderr.strip()}"
            )

        for label, remote_path, expected_sha256 in (
            ("daemon", remote_daemon, daemon_sha256),
            ("SKILL bridge", remote_il, il_sha256),
            ("setup", remote_setup, setup_sha256),
            ("compatible setup", remote_compat_setup, setup_sha256),
        ):
            quoted = shlex.quote(remote_path)
            digest_result = runner.run_command(
                "if command -v sha256sum >/dev/null 2>&1; then "
                f"sha256sum -- {quoted}; "
                "elif command -v shasum >/dev/null 2>&1; then "
                f"shasum -a 256 {quoted}; "
                "elif command -v openssl >/dev/null 2>&1; then "
                f"openssl dgst -sha256 {quoted}; "
                "else exit 127; fi",
                timeout=budget.remaining(f"verify-{label}-digest"),
                retry_transport_errors=True,
            )
            match = re.search(r"(?i)(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])", digest_result.stdout)
            if digest_result.returncode != 0 or not match:
                raise RuntimeError(
                    f"Unable to verify deployed {label} digest: "
                    f"{digest_result.stderr.strip() or digest_result.stdout.strip()}"
                )
            if match.group(1).lower() != expected_sha256:
                raise RuntimeError(f"Deployed {label} digest mismatch")

        self._remote_setup_done = True
        self._remote_virtuoso_setup_path = remote_setup
        self._request_state_path = remote_request_state
        self._deployed_daemon_sha256 = daemon_sha256
        self._deployed_il_sha256 = il_sha256
        self._deployed_setup_sha256 = setup_sha256
        self._deployed_daemon_path = remote_daemon
        self._deployed_il_path = remote_il
        self._compat_setup_path = remote_compat_setup
        self._deployment_id = deployment_id
        self._daemon_filename = daemon_filename
        logger.info("Remote setup complete; setup script at %s (using %s)", remote_setup, python_cmd)

    def ensure_local_setup(self) -> None:
        """Generate virtuoso_setup.il locally (no SSH needed)."""
        if self._remote_setup_done:
            return

        python_cmd = sys.executable
        python_major = sys.version_info[0]

        daemon_local = _find_ramic_bridge_daemon(python_major)
        il_local = _find_ramic_bridge_il()
        daemon_text = _canonical_resource_text(daemon_local)
        il_text = _canonical_resource_text(il_local)
        daemon_sha256 = _sha256_bytes(daemon_text.encode("utf-8"))
        il_sha256 = _sha256_bytes(il_text.encode("utf-8"))
        deployment_id = _sha256_bytes(
            (daemon_sha256 + "\x00" + il_sha256).encode("ascii")
        )

        # Determine local work directory
        if self._profile:
            work_dir = state_dir() / f"local_{self._profile}"
        else:
            work_dir = state_dir() / "local"
        work_dir.mkdir(parents=True, exist_ok=True)

        # Copy daemon and IL files into the work directory
        local_daemon = work_dir / (
            f"{daemon_local.stem}.{daemon_sha256}{daemon_local.suffix}"
        )
        local_il = work_dir / f"ramic_bridge.{il_sha256}.il"
        local_setup = work_dir / f"virtuoso_setup.{deployment_id}.il"
        local_compat_setup = work_dir / "virtuoso_setup.il"
        local_token = _auth_token_file(self._profile)
        local_request_state = work_dir / "request-status.json"

        local_daemon.write_bytes(daemon_text.encode("utf-8"))

        local_il.write_bytes(il_text.encode("utf-8"))

        local_token.parent.mkdir(parents=True, exist_ok=True)
        local_token.write_text(self._auth_token + "\n", encoding="utf-8")
        try:
            local_token.chmod(0o600)
        except OSError:
            pass

        setup_content = _generate_virtuoso_setup_il(
            str(local_daemon),
            str(local_il),
            python_cmd,
            port=self._port,
            auth_token_path=str(local_token),
            request_state_path=str(local_request_state),
            allow_remote_bind=self._allow_remote_bind,
            profile=self._profile,
        )
        if not setup_content.endswith("\n"):
            setup_content += "\n"
        setup_sha256 = _sha256_bytes(setup_content.encode("utf-8"))
        local_setup.write_bytes(setup_content.encode("utf-8"))
        local_compat_setup.write_bytes(setup_content.encode("utf-8"))

        self._remote_setup_done = True
        self._remote_virtuoso_setup_path = str(local_setup)
        self._remote_work_dir = str(work_dir)
        self._request_state_path = str(local_request_state)
        self._deployed_daemon_sha256 = daemon_sha256
        self._deployed_il_sha256 = il_sha256
        self._deployed_setup_sha256 = setup_sha256
        self._deployed_daemon_path = str(local_daemon)
        self._deployed_il_path = str(local_il)
        self._compat_setup_path = str(local_compat_setup)
        self._deployment_id = deployment_id
        self._daemon_filename = daemon_local.name
        logger.info(
            "Local setup complete; setup script at %s (using %s)",
            local_setup, python_cmd,
        )

    # -- SSH tunnel (delegated to SSHRunner) ----------------------------------

    def ensure_tunnel(
        self,
        timeout: float | None = None,
        *,
        _budget: _TimeoutBudget | None = None,
    ) -> None:
        """Ensure SSH tunnel is running, auto-retry on port conflict."""
        if _is_localhost(self._remote_host):
            return
        runner = self._require_runner()
        budget = _budget or _TimeoutBudget.start(timeout, self._timeout)
        if runner.is_tunnel_alive:
            return
        if SSHRunner.can_reach_port(self._local_port):
            # Port reachable (external tunnel) — load PID from state if available
            state = self.read_state(self._profile)
            if state and state.get("tunnel_pid"):
                runner.tunnel_pid = state["tunnel_pid"]
            return

        max_attempts = 10
        local_port = self._local_port
        for attempt in range(max_attempts):
            budget.remaining("start-ssh-tunnel")
            settle = _TUNNEL_STARTUP_SETTLE_SECONDS
            if self._jump_host:
                settle = max(settle, 3.0)
            settle = min(settle, budget.remaining("start-ssh-tunnel"))
            proc = runner.start_port_forward(local_port, settle=settle, remote_port=self._port)
            if proc is None:
                # Reusing existing tunnel
                self._local_port = local_port
                return
            if proc.poll() is None:
                # Tunnel running
                if local_port != self._local_port:
                    logger.info("Local port %d was busy, using port %d", self._local_port, local_port)
                    print(f"[port] {self._local_port} busy, auto-switched to {local_port}", flush=True)
                    self._local_port = local_port
                    _update_env_file(_profiled_env_key("VB_LOCAL_PORT", self._profile), str(local_port))
                logger.info(
                    "SSH tunnel established (PID %d): localhost:%d -> %s:localhost:%d",
                    proc.pid, local_port, self._remote_host, self._port,
                )
                return
            # Failed
            stderr = proc.stderr
            err_msg = stderr.read().decode("utf-8", errors="ignore") if stderr else ""
            if "address already in use" in err_msg.lower() or "cannot listen" in err_msg.lower():
                logger.info("Local port %d in use, trying %d", local_port, local_port + 1)
                local_port += 1
                continue
            raise RuntimeError(f"SSH tunnel failed: {err_msg.strip()}")

        raise RuntimeError(f"No free local port found after {max_attempts} attempts ({self._local_port}-{local_port - 1})")

    # -- high-level lifecycle -----------------------------------------------

    def warm(self, timeout: int = 15) -> None:
        """Full startup: remote setup + persistent shell + tunnel."""
        budget = _TimeoutBudget.start(timeout, self._timeout)
        if _is_localhost(self._remote_host):
            self.ensure_local_setup()
            self.save_state()
            return
        try:
            self.ensure_remote_setup(_budget=budget)
            runner = self._require_runner()
            if runner.persistent_shell_enabled:
                runner.ensure_persistent_shell(_budget=budget)
            self.ensure_tunnel(_budget=budget)
            self.save_state()
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def stop(self) -> None:
        """Kill the tunnel and clean up."""
        if _is_localhost(self._remote_host):
            # Local mode: no tunnel or SSH to tear down — just clear state
            sf = _state_file(self._profile)
            if sf.exists():
                sf.unlink(missing_ok=True)
            return

        runner = self._require_runner()
        # Try state file PID first (may be from a previous session)
        if not runner.is_tunnel_alive:
            state = self.read_state(self._profile)
            if state:
                pid = state.get("tunnel_pid")
                if pid:
                    runner.tunnel_pid = pid

        runner.stop_port_forward()

        if not self._keep_remote_files and self._remote_setup_done and self._remote_work_dir:
            try:
                runner.run_command(f"rm -rf {self._remote_work_dir}")
            except Exception:
                logger.warning("Failed to clean up remote files at %s", self._remote_work_dir)

        try:
            runner.close()
        except Exception:
            pass

        # Clear state
        sf = _state_file(self._profile)
        if sf.exists():
            sf.unlink(missing_ok=True)

    def close(self) -> None:
        """Close SSH runner without killing the tunnel (it survives for other scripts)."""
        if self._ssh_runner is None:
            return
        try:
            self._ssh_runner.close()
        except Exception:
            pass

    # -- state file ---------------------------------------------------------

    def save_state(self) -> None:
        """Save tunnel state so other processes can find the port."""
        state_dir().mkdir(parents=True, exist_ok=True)
        previous_state = self.read_state(self._profile) or {}
        previous_setup_path = previous_state.get("previous_setup_path")
        previous_daemon_sha256 = previous_state.get("previous_deployed_daemon_sha256")
        existing_setup_path = previous_state.get("setup_path")
        if existing_setup_path and existing_setup_path != self._remote_virtuoso_setup_path:
            previous_setup_path = existing_setup_path
            previous_daemon_sha256 = previous_state.get("deployed_daemon_sha256")
        is_local = _is_localhost(self._remote_host)
        tunnel_pid = None
        if not is_local:
            tunnel_pid = self._require_runner().tunnel_pid
        state = {
            "state_schema_version": 2,
            "mode": "local" if is_local else "remote",
            "port": self._port if is_local else self._local_port,
            "tunnel_pid": tunnel_pid,
            "remote_host": self._remote_host,
            "setup_path": self._remote_virtuoso_setup_path,
            "previous_setup_path": previous_setup_path,
            "request_state_path": self._request_state_path,
            "deployed_daemon_sha256": self._deployed_daemon_sha256,
            "deployed_il_sha256": self._deployed_il_sha256,
            "deployed_setup_sha256": self._deployed_setup_sha256,
            "deployed_daemon_path": self._deployed_daemon_path,
            "deployed_il_path": self._deployed_il_path,
            "compat_setup_path": self._compat_setup_path,
            "deployment_id": self._deployment_id,
            "daemon_filename": self._daemon_filename,
            "previous_deployed_daemon_sha256": previous_daemon_sha256,
            "bind_policy": "remote-explicit" if self._allow_remote_bind else "loopback",
            "auth_enabled": bool(self._auth_token),
            "profile": self._profile,
            "started_at": time.time(),
        }
        _atomic_write_json(_state_file(self._profile), state)

    @classmethod
    def read_request_status(
        cls,
        profile: str | None = None,
        request_id: str | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any] | None:
        """Read the daemon ledger over SSH, independent of the SKILL channel."""
        profile = resolve_profile(profile)
        state = cls.read_state(profile)
        if not state:
            return None
        path = str(state.get("request_state_path") or "")
        if not path:
            return None
        if state.get("mode") == "local":
            try:
                payload = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
        else:
            client = cls.from_env(
                keep_remote_files=True,
                profile=profile,
                create_auth_token=False,
            )
            try:
                result = client._require_runner().run_command(
                    f"cat -- {shlex.quote(path)}",
                    timeout=timeout,
                )
                if result.returncode != 0:
                    return None
                payload = json.loads(result.stdout)
            except (OSError, ValueError, json.JSONDecodeError):
                return None
            finally:
                client.close()
        if not request_id:
            return payload
        for entry in payload.get("requests", []):
            if entry.get("request_id") == request_id:
                filtered = {
                    "schema_version": payload.get("schema_version"),
                    "daemon_epoch": payload.get("daemon_epoch"),
                    "request": entry,
                }
                for key in (
                    "protocol_version",
                    "protocol_versions",
                    "daemon_build_sha256",
                    "capabilities",
                    "daemon_started_at_epoch",
                    "heartbeat_at_epoch",
                    "active_request_id",
                    "queue_depth",
                    "queue_capacity",
                ):
                    if key in payload:
                        filtered[key] = payload.get(key)
                return filtered
        filtered = {
            "schema_version": payload.get("schema_version"),
            "daemon_epoch": payload.get("daemon_epoch"),
            "request": None,
        }
        for key in (
            "protocol_version",
            "protocol_versions",
            "daemon_build_sha256",
            "capabilities",
            "daemon_started_at_epoch",
            "heartbeat_at_epoch",
            "active_request_id",
            "queue_depth",
            "queue_capacity",
        ):
            if key in payload:
                filtered[key] = payload.get(key)
        return filtered

    @classmethod
    def deployment_status(
        cls,
        profile: str | None = None,
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Compare local resources, staged files, and the running daemon."""
        profile = resolve_profile(profile)
        state = cls.read_state(profile) or {}
        source_variants: dict[str, str] = {}
        for major in (2, 3):
            daemon_path = _find_ramic_bridge_daemon(major)
            daemon_text = _canonical_resource_text(daemon_path)
            source_variants[daemon_path.name] = _sha256_bytes(daemon_text.encode("utf-8"))
        il_text = _canonical_resource_text(_find_ramic_bridge_il())
        il_sha256 = _sha256_bytes(il_text.encode("utf-8"))
        selected_name = str(state.get("daemon_filename") or "")
        local_daemon_sha256 = source_variants.get(selected_name)
        running = cls.read_request_status(profile, timeout=timeout)
        running_sha256 = (
            str(running.get("daemon_build_sha256") or "") if running else ""
        )
        deployed_sha256 = str(state.get("deployed_daemon_sha256") or "")
        deployed_path = str(state.get("deployed_daemon_path") or "")
        actual_deployed_sha256 = ""
        actual_digest_error: str | None = None
        if deployed_path:
            if state.get("mode") == "local":
                try:
                    actual_deployed_sha256 = _sha256_bytes(Path(deployed_path).read_bytes())
                except OSError as exc:
                    actual_digest_error = str(exc)
            else:
                client = cls.from_env(
                    keep_remote_files=True,
                    profile=profile,
                    create_auth_token=False,
                )
                try:
                    quoted = shlex.quote(deployed_path)
                    result = client._require_runner().run_command(
                        "if command -v sha256sum >/dev/null 2>&1; then "
                        f"sha256sum -- {quoted}; "
                        "elif command -v shasum >/dev/null 2>&1; then "
                        f"shasum -a 256 {quoted}; "
                        "elif command -v openssl >/dev/null 2>&1; then "
                        f"openssl dgst -sha256 {quoted}; "
                        "else exit 127; fi",
                        timeout=timeout,
                        retry_transport_errors=True,
                    )
                    match = re.search(
                        r"(?i)(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])",
                        result.stdout,
                    )
                    if result.returncode == 0 and match:
                        actual_deployed_sha256 = match.group(1).lower()
                    else:
                        actual_digest_error = (
                            result.stderr.strip() or result.stdout.strip()
                            or "remote digest unavailable"
                        )
                except Exception as exc:  # noqa: BLE001
                    actual_digest_error = str(exc)
                finally:
                    client.close()
        heartbeat_value = running.get("heartbeat_at_epoch") if running else None
        heartbeat_age_seconds: float | None = None
        try:
            heartbeat_age_seconds = max(0.0, time.time() - float(heartbeat_value))
        except (TypeError, ValueError):
            pass
        return {
            "schema_version": 1,
            "profile": profile,
            "deployment_id": state.get("deployment_id"),
            "setup_path": state.get("setup_path"),
            "previous_setup_path": state.get("previous_setup_path"),
            "daemon_filename": selected_name or None,
            "local_daemon_sha256": local_daemon_sha256,
            "local_daemon_variants": source_variants,
            "local_il_sha256": il_sha256,
            "deployed_daemon_sha256": deployed_sha256 or None,
            "deployed_daemon_path": deployed_path or None,
            "actual_deployed_daemon_sha256": actual_deployed_sha256 or None,
            "actual_digest_error": actual_digest_error,
            "deployed_il_sha256": state.get("deployed_il_sha256"),
            "deployed_setup_sha256": state.get("deployed_setup_sha256"),
            "running_daemon_sha256": running_sha256 or None,
            "running_daemon_epoch": running.get("daemon_epoch") if running else None,
            "running_heartbeat_age_seconds": heartbeat_age_seconds,
            "running_protocol_versions": running.get("protocol_versions") if running else None,
            "running_capabilities": running.get("capabilities") if running else None,
            "local_matches_deployed": bool(
                local_daemon_sha256
                and deployed_sha256 == local_daemon_sha256
                and actual_deployed_sha256 == deployed_sha256
            ),
            "deployed_matches_running": bool(
                deployed_sha256 and running_sha256 == deployed_sha256
            ),
            "running_available": running is not None,
            "running_heartbeat_fresh": bool(
                heartbeat_age_seconds is not None and heartbeat_age_seconds <= 5.0
            ),
        }

    @staticmethod
    def read_state(profile: str | None = None) -> dict[str, Any] | None:
        """Read saved tunnel state."""
        for sf in _state_file_candidates(profile):
            if not sf.is_file():
                continue
            try:
                return json.loads(sf.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
        return None

    @classmethod
    def is_running(cls, profile: str | None = None) -> bool:
        """Check if a tunnel is running (port reachable or process alive).

        For local mode, the state file existing is sufficient — the daemon
        may not be loaded in CIW yet, so we skip port checks.
        """
        state = cls.read_state(profile)
        if not state:
            return False
        if state.get("mode") == "local":
            return True
        port = state.get("port")
        pid = state.get("tunnel_pid")
        # Primary check: is the port reachable? (works on all platforms)
        if port:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                s.close()
                return True
            except (ConnectionRefusedError, OSError):
                pass
        # Fallback: is the process alive? (os.kill(pid, 0) on Unix)
        if pid:
            try:
                os.kill(pid, 0)
                return True
            except (OSError, PermissionError):
                pass
        return False

    # -- file transfer (delegated to SSHRunner) -----------------------------

    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        timeout: int | None = None,
        *,
        retry_transport_errors: bool = False,
    ) -> CommandResult:
        runner = self._require_runner()
        return runner.upload(
            local_path,
            remote_path,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )

    def download_file(self, remote_path: str, local_path: Path, timeout: int | None = None, recursive: bool = False) -> CommandResult:
        runner = self._require_runner()
        return runner.download(remote_path, local_path, recursive=recursive, timeout=timeout or self._timeout)

    def upload_text(
        self,
        text: str,
        remote_path: str,
        timeout: int | None = None,
        *,
        retry_transport_errors: bool = False,
    ) -> CommandResult:
        runner = self._require_runner()
        return runner.upload_text(
            text,
            remote_path,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )

    def run_command(
        self,
        cmd: str,
        timeout: int | None = None,
        *,
        operation_class: str = "unknown",
        retry_transport_errors: bool | None = None,
    ) -> CommandResult:
        runner = self._require_runner()
        if operation_class not in {"unknown", "read_only", "mutating"}:
            raise ValueError("operation_class must be unknown, read_only, or mutating")
        if retry_transport_errors is None:
            retry_transport_errors = operation_class == "read_only"
        return runner.run_command(
            cmd,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )
