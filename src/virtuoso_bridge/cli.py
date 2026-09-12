"""CLI entry points for virtuoso-bridge."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import hashlib
import io
import json
import math
import os
import re
import shlex
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from virtuoso_bridge.env import default_user_env_path, load_vb_env, set_runtime_env_file
from virtuoso_bridge.models import OperationClass
from virtuoso_bridge.transport.ssh import SSHRunner, remote_ssh_env_from_os


def _env_template_path() -> Path:
    return Path(__file__).with_name("resources") / ".env_template"


def _parse_user_host(s: str) -> tuple[str | None, str]:
    """Split ``user@host`` or ``host`` into ``(user, host)``."""
    if "@" in s:
        user, _, host = s.partition("@")
        return (user or None), host
    return None, s


def _generate_env_template(
    remote_user: str | None = None,
    remote_host: str | None = None,
    jump_user: str | None = None,
    jump_host: str | None = None,
) -> str:
    import getpass
    from virtuoso_bridge.virtuoso.basic.bridge import _default_remote_port

    # Port hash follows the *remote* username when provided — otherwise
    # fall back to the local user so existing init-without-args still
    # picks a stable per-machine default.
    port_user = remote_user
    if not port_user:
        try:
            port_user = getpass.getuser()
        except Exception:
            port_user = ""
    remote_port = _default_remote_port(port_user)
    local_port = remote_port + 1
    text = _env_template_path().read_text(encoding="utf-8").format(
        remote_port=remote_port, local_port=local_port
    )

    def _sub_line(pattern: str, replacement: str) -> str:
        return re.sub(
            pattern, lambda _m: replacement, text, count=1, flags=re.MULTILINE
        )

    if remote_host:
        text = _sub_line(r"^VB_REMOTE_HOST=$", f"VB_REMOTE_HOST={remote_host}")
    if remote_user:
        text = _sub_line(r"^VB_REMOTE_USER=$", f"VB_REMOTE_USER={remote_user}")
    if jump_host:
        text = _sub_line(r"^# VB_JUMP_HOST=$", f"VB_JUMP_HOST={jump_host}")
    if jump_user:
        text = _sub_line(r"^# VB_JUMP_USER=$", f"VB_JUMP_USER={jump_user}")
    return text


_PRINTED_ENV_PATH: Path | None = None


def _load_cli_env() -> Path | None:
    global _PRINTED_ENV_PATH
    env_path = load_vb_env()
    if env_path is not None and env_path != _PRINTED_ENV_PATH:
        print(f"using .env: {env_path}")
        _PRINTED_ENV_PATH = env_path
    return env_path


def cli_profile(*, action: str, profile: str | None = None) -> int:
    """Inspect or edit profile bindings."""
    from virtuoso_bridge.profile import (
        bind_venv_profile,
        clear_venv_profile,
        read_venv_profile,
        resolve_profile_info,
    )

    if action == "bind":
        if profile is None:
            print("profile bind requires a profile name")
            return 2
        try:
            path = bind_venv_profile(profile)
        except Exception as exc:
            print(f"profile bind failed: {exc}")
            return 1
        print(f"Bound current virtualenv to profile {profile!r}")
        print(f"  {path}")
        return 0

    if action == "clear":
        try:
            path = clear_venv_profile()
        except Exception as exc:
            print(f"profile clear failed: {exc}")
            return 1
        print("Cleared current virtualenv profile binding")
        print(f"  {path}")
        return 0

    info = resolve_profile_info()
    venv_path, venv_profile = read_venv_profile()
    print(f"resolved profile : {info.profile or '(default)'}")
    print(f"source           : {info.source}")
    if info.path:
        print(f"source path      : {info.path}")
    print(f"venv binding     : {venv_profile or '(none)'}")
    print(f"venv path        : {venv_path or '(no active virtualenv)'}")
    return 0


def _fmt(seconds: float) -> str:
    return f"{seconds:.3f}s"


# -- init -------------------------------------------------------------------

def cli_init(
    remote: str | None = None,
    jump: str | None = None,
    force: bool = False,
) -> int:
    remote_user = remote_host = None
    if remote:
        remote_user, remote_host = _parse_user_host(remote)
    jump_user = jump_host = None
    if jump:
        jump_user, jump_host = _parse_user_host(jump)

    env_path = default_user_env_path()
    env_path.parent.mkdir(parents=True, exist_ok=True)
    existed = env_path.exists()
    if existed and not force:
        print(f".env already exists at {env_path}")
        if remote or jump:
            print("  (arguments ignored; pass --force to overwrite)")
    else:
        content = _generate_env_template(
            remote_user=remote_user,
            remote_host=remote_host,
            jump_user=jump_user,
            jump_host=jump_host,
        )
        env_path.write_text(content, encoding="utf-8")
        print(f".env {'overwritten' if existed else 'created'} at {env_path}")

    if remote_host and not (existed and not force):
        print("\nNext: run `virtuoso-bridge start`")
    else:
        print("\nNext: edit .env, set VB_REMOTE_HOST, then run: virtuoso-bridge start")
    return 0


# -- start ------------------------------------------------------------------

def _format_ssh_failure(ssh_env) -> None:
    """Print a user-friendly hint after ``warm`` fails for SSH-shaped reasons."""
    print(f"SSH to {ssh_env.remote_host} failed.")
    print(f"  Check VB_REMOTE_HOST and VB_REMOTE_USER in your .env file.")
    if ssh_env.jump_host:
        jump_user = ssh_env.jump_user or ssh_env.remote_user
        print(
            f"  Verify: ssh -J {jump_user}@{ssh_env.jump_host} "
            f"{ssh_env.remote_user}@{ssh_env.remote_host}"
        )
    else:
        print(f"  Verify: ssh {ssh_env.remote_user}@{ssh_env.remote_host}")
    print(f"  For a local VM, use the VM's IP (run `ip addr` inside the VM).")


def _start_one_profile(
    profile: str | None,
    *,
    _deadline: float | None = None,
) -> int:
    """Start tunnel for a single profile (thread-safe, uses explicit profile)."""
    suffix = f"_{profile}" if profile else ""
    remote_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()
    if not remote_host:
        print(
            f"VB_REMOTE_HOST{suffix} is not set. "
            "Use --env FILE, create ./.env, or run `virtuoso-bridge init` to create ~/.virtuoso-bridge/.env."
        )
        return 1

    from virtuoso_bridge.transport.tunnel import SSHClient, _is_localhost

    is_local = _is_localhost(remote_host)

    if SSHClient.is_running(profile):
        profile_matcher = getattr(
            SSHClient,
            "staged_profile_config_matches_current",
            None,
        )
        if profile_matcher is not None:
            try:
                profile_matches = bool(profile_matcher(profile))
            except Exception:
                profile_matches = False
            if not profile_matches:
                print(
                    "[warning] Refusing to reuse the running Bridge endpoint: "
                    "the saved host/user/port identity does not match the current "
                    "profile. Stop the old profile tunnel before starting the "
                    "changed profile."
                )
                return 1
        # A running tunnel is reusable, but the packaged resources or profile
        # inputs may have changed since the last stage.  Refresh immutable
        # files/setup in place and leave CIW/daemon state untouched; only the
        # explicit ``restart`` command may activate the new setup.
        matches = True
        matcher = getattr(SSHClient, "staged_resources_match_current", None)
        if matcher is not None:
            try:
                matches = bool(matcher(profile))
            except Exception:
                matches = False
        if matches:
            msg = "Bridge already running." if is_local else "Tunnel already running."
            print(msg)
            return 0
        label = f" [{profile}]" if profile else ""
        print(
            f"Tunnel already running{label}; packaged resources/profile changed. "
            "Refreshing staged setup without restarting the daemon..."
        )
        ssh = SSHClient.from_env(
            keep_remote_files=True,
            profile=profile,
            allow_remote_bind=_CLI_ALLOW_REMOTE_BIND[0],
        )
        try:
            if _deadline is None:
                ssh.warm()
            else:
                ssh.warm(
                    timeout=_restart_remaining(_deadline, "resource staging")
                )
            print(
                "Running daemon is unchanged; explicit `virtuoso-bridge restart` "
                "is required to activate the staged update."
            )
            return 0
        except Exception as exc:
            if is_local:
                print(f"Local bridge setup refresh failed: {exc}")
            else:
                _format_ssh_failure(remote_ssh_env_from_os(profile))
                print(f"  Details: {str(exc).splitlines()[0] if str(exc) else exc}")
            return 1
        finally:
            ssh.close()

    label = f" [{profile}]" if profile else ""
    if is_local:
        print(f"Setting up local bridge{label}...")
    else:
        print(f"Starting tunnel{label}...")
    ssh = SSHClient.from_env(
        keep_remote_files=True,
        profile=profile,
        allow_remote_bind=_CLI_ALLOW_REMOTE_BIND[0],
    )
    try:
        started = time.monotonic()
        try:
            # No separate SSH precheck — ``warm()`` already performs the
            # real handshake we need.  Probing first doubled the handshake
            # count and, on jump-host setups where cold banner exchange
            # easily exceeds 5 s, made the precheck false-negative while
            # the actual tunnel would have succeeded.
            if _deadline is None:
                ssh.warm()
            else:
                ssh.warm(
                    timeout=_restart_remaining(_deadline, "resource staging")
                )
        except Exception as exc:
            if not is_local:
                _format_ssh_failure(remote_ssh_env_from_os(profile))
                msg = str(exc).strip()
                if msg:
                    print(f"  Details: {msg.splitlines()[0]}")
            else:
                print(f"Local bridge setup failed: {exc}")
            return 1
        elapsed = time.monotonic() - started
        print(f"tunnel.warm = {_fmt(elapsed)}")

        if is_local:
            # For local mode, print setup_path for user to load in CIW
            state = SSHClient.read_state(profile)
            if state:
                setup_path = state.get("setup_path")
                if setup_path:
                    print(f"  Load in Virtuoso CIW: load(\"{setup_path}\")")
            return 0

        settle = 1.0
        if _deadline is not None:
            settle = min(settle, _restart_remaining(_deadline, "tunnel settle"))
        time.sleep(settle)
        if not SSHClient.is_running(profile):
            print("[warning] Tunnel process exited shortly after start.")
            print("Try starting the tunnel manually:")
            ssh_env = remote_ssh_env_from_os(profile)
            port = ssh.port
            manual_cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -N -L {port}:127.0.0.1:{port}"
            if ssh_env.jump_host:
                jump = f"{ssh_env.jump_user or ssh_env.remote_user}@{ssh_env.jump_host}" if (ssh_env.jump_user or ssh_env.remote_user) else ssh_env.jump_host
                manual_cmd += f" -J {jump}"
            target = f"{ssh_env.remote_user}@{ssh_env.remote_host}" if ssh_env.remote_user else ssh_env.remote_host
            manual_cmd += f" {target}"
            print(f"  {manual_cmd}")
            return 1

        return 0
    finally:
        ssh.close()


def _start_one() -> int:
    """Start tunnel for the current profile (read from _CLI_PROFILE)."""
    return _start_one_profile(_get_cli_profile())


def cli_start() -> int:
    _load_cli_env()
    profile = _get_cli_profile()
    if profile is None:
        profiles = _discover_profiles()
        if len(profiles) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(profiles)) as ex:
                list(ex.map(_start_one_profile, profiles))
            return cli_status()
    return _start_one_profile(profile)


# -- stop -------------------------------------------------------------------

def _stop_one() -> int:
    """Stop tunnel for the current profile."""
    profile = _get_cli_profile()
    from virtuoso_bridge.transport.tunnel import SSHClient, resolve_auth_token

    label = f" [{profile}]" if profile else ""
    if not SSHClient.is_running(profile):
        print(f"No tunnel running{label}.")
        return 0

    ssh = SSHClient.from_env(keep_remote_files=True, profile=profile)
    ssh.stop()
    print(f"Tunnel stopped{label}.")
    return 0


def cli_stop() -> int:
    _load_cli_env()
    return _for_each_profile(_stop_one)


# -- restart ----------------------------------------------------------------

_RESTART_ACTIVE_STATES = frozenset(
    {"queued", "running", "timed_out_pending", "late_waiting_operator"}
)
_RESTART_TERMINAL_STATES = frozenset(
    {
        "succeeded",
        "failed",
        "succeeded_after_timeout",
        "failed_after_timeout",
        "response_too_large",
        "failed_internal",
        "orphaned_unknown_after_daemon_restart",
        "orphaned_unknown_response_drain_timeout",
        "orphaned_unknown_response_stream_closed",
    }
)


def _restart_busy_reason(ledger: dict[str, object]) -> str | None:
    exclusive_raw = ledger.get("exclusive_request_id")
    exclusive_generation = ledger.get("exclusive_request_generation")
    if exclusive_raw is not None and not isinstance(exclusive_raw, str):
        return "malformed exclusive request id"
    exclusive_request_id = str(exclusive_raw or "").strip()
    if exclusive_generation is not None and not isinstance(exclusive_generation, str):
        return "malformed exclusive request generation"
    if exclusive_request_id:
        return f"exclusive request {exclusive_request_id}"
    if exclusive_generation:
        return "orphaned exclusive request generation"
    active_raw = ledger.get("active_request_id")
    if active_raw is not None and not isinstance(active_raw, str):
        return "malformed active request id"
    active_request_id = str(active_raw or "").strip()
    if active_request_id:
        return f"active request {active_request_id}"
    queue_depth_raw = ledger.get("queue_depth", 0)
    if isinstance(queue_depth_raw, bool):
        return "malformed queue depth"
    try:
        queue_depth = int(queue_depth_raw or 0)
    except (TypeError, ValueError):
        return "malformed queue depth"
    if queue_depth < 0:
        return "malformed queue depth"
    if queue_depth > 0:
        return f"queue depth is {queue_depth}"
    requests = ledger.get("requests", [])
    if not isinstance(requests, list):
        return "malformed request ledger"
    for request in requests:
        if not isinstance(request, dict):
            return "malformed request ledger"
        request_id = request.get("request_id")
        state = request.get("state")
        if not isinstance(request_id, str) or not request_id.strip():
            return "malformed request ledger"
        if not isinstance(state, str) or not state:
            return f"request {request_id} has malformed state"
        if state in _RESTART_ACTIVE_STATES:
            return f"request {request_id} is {state}"
        if state not in _RESTART_TERMINAL_STATES:
            return f"request {request_id} has unknown state {state}"
    return None


def _restart_has_exclusive_admission(ledger: dict[str, object]) -> bool:
    capabilities = ledger.get("capabilities")
    return bool(
        isinstance(capabilities, list)
        and all(isinstance(item, str) for item in capabilities)
        and "exclusive-admission-v1" in capabilities
    )


def _restart_dispatch_attributed(
    ledger: dict[str, object],
    request_id: str,
    request_digest_sha256: str,
    admitted_daemon_epoch: str,
) -> bool:
    requests = ledger.get("requests")
    if not isinstance(requests, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("request_id") == request_id
        and entry.get("request_digest_sha256") == request_digest_sha256
        and entry.get("operation_class") == "mutating"
        and entry.get("admitted_daemon_epoch") == admitted_daemon_epoch
        and entry.get("exclusive") is True
        for entry in requests
    )


def _restart_remaining(deadline: float, phase: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"Restart timeout exhausted during {phase}")
    return remaining


def _positive_finite_timeout(timeout: float) -> float:
    value = float(timeout)
    if not math.isfinite(value) or value <= 0.0:
        raise ValueError("timeout must be a finite positive number")
    return value


def _restart_timeout(timeout: float) -> float:
    try:
        return _positive_finite_timeout(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("Restart timeout must be a finite positive number") from exc


def _restart_heartbeat_is_fresh(
    ledger: dict[str, object],
    *,
    now: float | None = None,
) -> bool:
    try:
        heartbeat = float(ledger.get("heartbeat_at_epoch"))
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    return heartbeat <= current + 1.0 and current - heartbeat <= 5.0


def _restart_staged_state_reason(
    state: dict[str, object],
    profile: str | None,
) -> str | None:
    try:
        schema_version = int(state.get("state_schema_version"))
    except (TypeError, ValueError):
        return "staged state schema is missing or invalid"
    if schema_version < 2:
        return "staged state schema is too old for guarded restart"
    if state.get("mode") not in {"local", "remote"}:
        return "staged mode is invalid"
    if state.get("profile") != profile:
        return "staged profile identity does not match"

    hash_fields = (
        "deployed_daemon_sha256",
        "deployed_il_sha256",
        "deployed_setup_sha256",
        "deployment_id",
    )
    hashes: dict[str, str] = {}
    for field in hash_fields:
        value = str(state.get(field) or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            return f"{field} is not a full SHA-256 digest"
        hashes[field] = value
    computed_deployment = hashlib.sha256(
        (
            hashes["deployed_daemon_sha256"]
            + "\x00"
            + hashes["deployed_il_sha256"]
        ).encode("ascii")
    ).hexdigest()
    if hashes["deployment_id"] != computed_deployment:
        return "deployment id does not match daemon/IL digests"

    setup_path = str(state.get("setup_path") or "")
    daemon_path = str(state.get("deployed_daemon_path") or "")
    il_path = str(state.get("deployed_il_path") or "")
    daemon_filename = str(state.get("daemon_filename") or "")
    if not all((setup_path, daemon_path, il_path, daemon_filename)):
        return "staged file paths are incomplete"
    normalized = [value.replace("\\", "/") for value in (setup_path, daemon_path, il_path)]
    directories = [value.rsplit("/", 1)[0] for value in normalized]
    if not directories[0] or len(set(directories)) != 1:
        return "staged files do not share one deployment directory"
    daemon_stem, daemon_suffix = os.path.splitext(daemon_filename)
    expected_names = (
        f"virtuoso_setup.{hashes['deployment_id']}.il",
        f"{daemon_stem}.{hashes['deployed_daemon_sha256']}{daemon_suffix}",
        f"ramic_bridge.{hashes['deployed_il_sha256']}.il",
    )
    actual_names = tuple(value.rsplit("/", 1)[-1] for value in normalized)
    if actual_names != expected_names:
        return "staged file names do not match their recorded digests"
    return None


def _restart_daemon_one(
    profile: str | None,
    *,
    timeout: float = 30.0,
    _deadline: float | None = None,
) -> bool:
    """Guard, restart once, then prove the new daemon identity.

    The restart request is never replayed.  A timeout or incomplete
    post-restart proof returns failure even if the daemon may have restarted.
    """
    from virtuoso_bridge.daemon_guard import check_daemon_user
    from virtuoso_bridge.models import ExecutionStatus, OperationClass
    from virtuoso_bridge.transport.tunnel import SSHClient, resolve_auth_token
    from virtuoso_bridge.virtuoso.basic.bridge import VirtuosoClient
    from virtuoso_bridge.virtuoso.ops import escape_skill_string

    try:
        deadline = (
            _deadline
            if _deadline is not None
            else time.monotonic() + _restart_timeout(timeout)
        )
        if not math.isfinite(deadline):
            raise ValueError("Restart deadline must be finite")
        _restart_remaining(deadline, "initialization")
    except (TypeError, ValueError, TimeoutError) as exc:
        print(f"[warning] Refusing daemon restart: {exc}.")
        return False
    state = SSHClient.read_state(profile)
    if not isinstance(state, dict) or not state.get("port"):
        print("[warning] Refusing daemon restart: staged bridge state is unavailable.")
        return False

    state_reason = _restart_staged_state_reason(state, profile)
    if state_reason:
        print(f"[warning] Refusing daemon restart: {state_reason}.")
        return False
    try:
        staged_ok, staged_details = SSHClient.verify_staged_files(
            profile,
            state,
            timeout=_restart_remaining(deadline, "staged file verification"),
        )
    except Exception as exc:
        staged_ok, staged_details = False, str(exc)
    if not staged_ok:
        print(
            "[warning] Refusing daemon restart: staged file verification failed: "
            f"{staged_details}."
        )
        return False

    label = f" [{profile}]" if profile else ""
    setup_path = str(
        state.get("setup_path")
        or state.get("compat_setup_path")
        or state.get("bootstrap_path")
        or ""
    )
    expected_build = str(state.get("deployed_daemon_sha256") or "")
    if not setup_path or not expected_build:
        print(
            f"[warning] Refusing to restart daemon{label}: "
            "staged setup/build identity is incomplete."
        )
        return False

    # Require two consecutive idle snapshots before dispatch.  This does not
    # replace daemon serialization, but it avoids acting on a single stale or
    # partially updated ledger observation.
    preflight: dict[str, object] | None = None
    preflight_identity: tuple[str, str] | None = None
    for observation in range(2):
        try:
            preflight = SSHClient.read_request_status(
                profile,
                timeout=min(5.0, _restart_remaining(deadline, "ledger preflight")),
            )
        except Exception as exc:
            print(f"[warning] Refusing to restart daemon{label}: ledger read failed: {exc}")
            return False
        if not isinstance(preflight, dict):
            print(
                f"[warning] Refusing to restart daemon{label}: "
                "the request ledger is unavailable."
            )
            return False
        busy_reason = _restart_busy_reason(preflight)
        if busy_reason:
            print(f"[warning] Refusing to restart daemon{label}: {busy_reason}.")
            return False
        if not _restart_has_exclusive_admission(preflight):
            print(
                f"[warning] Refusing to restart daemon{label}: "
                "the running daemon does not prove exclusive-admission-v1 support. "
                "A one-time operator-controlled migration is required."
            )
            return False
        identity = (
            str(preflight.get("daemon_epoch") or ""),
            str(preflight.get("daemon_build_sha256") or ""),
        )
        if not all(identity) or not _restart_heartbeat_is_fresh(preflight):
            print(
                f"[warning] Refusing to restart daemon{label}: "
                "the running daemon identity or heartbeat is stale."
            )
            return False
        if preflight_identity is not None and identity != preflight_identity:
            print(
                f"[warning] Refusing to restart daemon{label}: "
                "the daemon identity changed during preflight."
            )
            return False
        preflight_identity = identity
        if observation == 0:
            time.sleep(min(0.05, _restart_remaining(deadline, "stable idle check")))

    old_epoch = str(preflight.get("daemon_epoch") or "")
    running_build = str(preflight.get("daemon_build_sha256") or "")
    if not old_epoch or not running_build:
        print(
            f"[warning] Refusing to restart daemon{label}: "
            "the running daemon identity is incomplete."
        )
        return False

    if setup_path:
        skill = f'RBStop()\nload("{escape_skill_string(setup_path)}")'

    print(f"Restarting daemon{label}...")
    request_timeout = min(5.0, _restart_remaining(deadline, "restart dispatch"))
    client = VirtuosoClient(
        host="127.0.0.1",
        port=int(state["port"]),
        timeout=request_timeout,
        log_to_ciw=False,
        auth_token=resolve_auth_token(profile, create=False),
        profile=profile,
    )
    try:
        user_check = check_daemon_user(
            client,
            profile=profile,
            timeout=min(5.0, _restart_remaining(deadline, "daemon identity check")),
        )
    except Exception as exc:
        print(f"[warning] Could not check daemon before restart{label}: {exc}")
        return False
    if not user_check.ok:
        print(f"[warning] Refusing to restart daemon{label}: {user_check.error}")
        return False

    # Narrow the gap between the last idle observation and RBStop/load.  The
    # profile wrapper lock serializes managed callers; this final read also
    # fails closed if an out-of-band request appeared during the user check.
    try:
        final_preflight = SSHClient.read_request_status(
            profile,
            timeout=min(2.0, _restart_remaining(deadline, "final ledger guard")),
        )
    except Exception as exc:
        print(f"[warning] Refusing to restart daemon{label}: final ledger read failed: {exc}")
        return False
    if not isinstance(final_preflight, dict):
        print(f"[warning] Refusing to restart daemon{label}: final ledger is unavailable.")
        return False
    final_identity = (
        str(final_preflight.get("daemon_epoch") or ""),
        str(final_preflight.get("daemon_build_sha256") or ""),
    )
    final_busy = _restart_busy_reason(final_preflight)
    if (
        final_identity != (old_epoch, running_build)
        or not _restart_has_exclusive_admission(final_preflight)
        or not _restart_heartbeat_is_fresh(final_preflight)
        or final_busy is not None
    ):
        reason = final_busy or "daemon identity/heartbeat changed during the final guard"
        print(f"[warning] Refusing to restart daemon{label}: {reason}.")
        return False

    restart_wall_time = time.time()
    try:
        result = client.execute_skill(
            skill,
            timeout=min(5.0, _restart_remaining(deadline, "restart dispatch")),
            operation_class=OperationClass.MUTATING,
            exclusive=True,
        )
    except Exception as exc:
        print(
            f"[warning] Restart dispatch outcome is unverified{label}: {exc}. "
            "The restart request was not replayed."
        )
        return False
    accepted = result.status == ExecutionStatus.SUCCESS
    details = "; ".join(result.errors) or result.output or "unknown error"
    if not accepted:
        expected_disconnect = (
            "Empty response from daemon",
            "Connection reset",
            "Broken pipe",
        )
        accepted = any(fragment in details for fragment in expected_disconnect)
    if not accepted:
        print(f"[warning] Could not restart daemon{label}: {details}")
        return False

    dispatch_request_id = str(result.request_id or "")
    dispatch_digest = str(
        (result.metadata or {}).get("request_digest_sha256") or ""
    ).lower()
    if not dispatch_request_id or not re.fullmatch(r"[0-9a-f]{64}", dispatch_digest):
        print(
            f"[warning] Restart outcome is unverified{label}: "
            "dispatch identity is incomplete. The restart request was not replayed."
        )
        return False

    print(f"Restart request dispatched{label}; verifying the new daemon...")
    last_reason = "no new ledger observed"
    while True:
        try:
            remaining = _restart_remaining(deadline, "post-restart verification")
        except TimeoutError:
            break
        try:
            current = SSHClient.read_request_status(
                profile,
                timeout=min(2.0, remaining),
            )
        except Exception as exc:
            current = None
            last_reason = f"ledger read failed: {exc}"
        if isinstance(current, dict):
            epoch = str(current.get("daemon_epoch") or "")
            build = str(current.get("daemon_build_sha256") or "")
            heartbeat = current.get("heartbeat_at_epoch")
            try:
                heartbeat_value = float(heartbeat)
                heartbeat_fresh = (
                    heartbeat_value >= restart_wall_time - 1.0
                    and time.time() - heartbeat_value <= 5.0
                )
            except (TypeError, ValueError):
                heartbeat_fresh = False
            dispatch_attributed = _restart_dispatch_attributed(
                current,
                dispatch_request_id,
                dispatch_digest,
                old_epoch,
            )
            if (
                epoch
                and epoch != old_epoch
                and build == expected_build
                and _restart_has_exclusive_admission(current)
                and heartbeat_fresh
                and _restart_busy_reason(current) is None
                and dispatch_attributed
            ):
                print(
                    f"Daemon restart verified{label}: epoch changed and "
                    "staged build is active."
                )
                return True
            if not epoch or epoch == old_epoch:
                last_reason = "daemon epoch has not changed"
            elif build != expected_build:
                last_reason = "running build does not match the staged build"
            elif not heartbeat_fresh:
                last_reason = "new daemon heartbeat is not fresh"
            elif not dispatch_attributed:
                last_reason = "new daemon epoch is not attributable to this restart request"
            else:
                last_reason = _restart_busy_reason(current) or "daemon is not idle"
        try:
            time.sleep(min(0.25, _restart_remaining(deadline, "verification poll")))
        except TimeoutError:
            break

    print(
        f"[warning] Restart outcome is unverified{label}: {last_reason}. "
        "The restart request was not replayed."
    )
    return False


def _restart_one(*, timeout: float = 30.0) -> int:
    """Stage/reuse the tunnel, then perform one guarded daemon restart."""
    profile = _get_cli_profile()
    try:
        deadline = time.monotonic() + _restart_timeout(timeout)
    except (TypeError, ValueError) as exc:
        print(f"[warning] Refusing daemon restart: {exc}.")
        return 1

    rc = _start_one_profile(profile, _deadline=deadline)
    if rc != 0:
        return rc
    return 0 if _restart_daemon_one(profile, _deadline=deadline) else 1


def cli_restart(*, timeout: float = 30.0) -> int:
    _load_cli_env()
    return _for_each_profile(lambda: _restart_one(timeout=timeout))


# -- .cdsinit autoload -----------------------------------------------------

def _autoload_expected_setup(profile: str | None) -> str | None:
    from virtuoso_bridge.transport.tunnel import SSHClient

    state = SSHClient.read_state(profile)
    if not state:
        return None
    return str(
        state.get("compat_setup_path")
        or state.get("bootstrap_path")
        or state.get("setup_path")
        or ""
    ) or None


def _autoload_client(profile: str | None, *, create_auth_token: bool) -> object:
    from virtuoso_bridge.transport.tunnel import SSHClient

    return SSHClient.from_env(
        keep_remote_files=True,
        profile=profile,
        create_auth_token=create_auth_token,
        allow_remote_bind=_CLI_ALLOW_REMOTE_BIND[0],
    )


def _autoload_one(profile: str | None, action: str, timeout: float = 10.0) -> int:
    from virtuoso_bridge.transport.tunnel import SSHClient

    label = f" [{profile}]" if profile else ""
    expected = _autoload_expected_setup(profile)
    if action == "install":
        # ``warm`` can stage immutable files and ensure/reuse the tunnel.  It
        # never calls RBStop/load, so installing autoload cannot restart CIW.
        try:
            ssh = _autoload_client(profile, create_auth_token=True)
        except Exception as exc:
            print(f"autoload install failed{label}: {exc}")
            return 1
        try:
            ssh.warm(timeout=max(15, int(timeout)))
            expected = ssh.compat_setup_path or expected
            result = ssh.autoload_install(
                expected_setup_path=expected,
                timeout=timeout,
            )
            result.pop("token", None)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        except Exception as exc:
            print(f"autoload install failed{label}: {exc}")
            return 1
        finally:
            ssh.close()

    # Read-only status and uninstall intentionally avoid token creation.  No
    # warm/restart/CIW call is made for either operation.
    try:
        ssh = _autoload_client(profile, create_auth_token=False)
    except Exception as exc:
        print(f"autoload {action} failed{label}: {exc}")
        return 1
    try:
        if action == "status":
            result = ssh.autoload_status(
                expected_setup_path=expected,
                timeout=timeout,
            )
        else:
            result = ssh.autoload_uninstall(timeout=timeout)
        result.pop("token", None)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"autoload {action} failed{label}: {exc}")
        return 1
    finally:
        ssh.close()


def cli_autoload(action: str, *, timeout: float = 10.0) -> int:
    timeout = _positive_finite_timeout(timeout)
    _load_cli_env()
    return _for_each_profile(
        lambda: _autoload_one(_get_cli_profile(), action, timeout=timeout)
    )


# -- status -----------------------------------------------------------------

def _print_load_hint(setup_path: str) -> None:
    """Print CIW load command and .cdsinit auto-load suggestion."""
    print(f"\n  Load in Virtuoso CIW:")
    print(f"    load(\"{setup_path}\")")
    print(f"\n  To auto-load on every Virtuoso startup, add to your .cdsinit:")
    print(f"    load(\"{setup_path}\")")


def _print_stale_daemon_hint() -> None:
    """Print recovery guidance for a CIW daemon left from another setup."""
    print("\n  If CIW says \"already running\", load() did not replace the existing daemon.")
    print("  To switch profile/port, run in CIW:")
    print("    RBStop()")
    print("    load(\".../virtuoso_setup.il\")")
    print("  If that does not clear it, use RBStopAll() before loading again.")


def _print_cross_user_daemon_failure(error: str) -> None:
    from virtuoso_bridge.daemon_guard import OVERRIDE_ENV

    print("\n[daemon identity] FAILED")
    print(f"  {error}")
    print(f"  Set {OVERRIDE_ENV}=1 only if this cross-user connection is intentional.")


def _print_status() -> int:
    _load_cli_env()
    profile = _get_cli_profile()
    from virtuoso_bridge.transport.tunnel import (
        SSHClient,
        _is_localhost,
        _profiled_bridge_leaf,
        resolve_auth_token,
    )
    from virtuoso_bridge.virtuoso.basic.bridge import VirtuosoClient

    state = SSHClient.read_state(profile)
    running = SSHClient.is_running(profile)

    from virtuoso_bridge import __version__
    label = f" [{profile}]" if profile else ""
    print(f"  Virtuoso Bridge v{__version__}{label}")

    suffix = f"_{profile}" if profile else ""
    configured_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()
    configured_user = os.getenv(f"VB_REMOTE_USER{suffix}", "").strip()
    jump_host = os.getenv(f"VB_JUMP_HOST{suffix}", "").strip()

    is_local = _is_localhost(configured_host) if configured_host else False

    # Infer setup_path from user config when state is unavailable
    def _infer_setup_path() -> str | None:
        from virtuoso_bridge.transport.remote_paths import (
            default_virtuoso_bridge_dir,
            resolve_client_id,
        )

        user = configured_user
        if not user:
            import getpass
            try:
                user = getpass.getuser()
            except Exception:
                return None
        work_dir = default_virtuoso_bridge_dir(
            user,
            _profiled_bridge_leaf(profile),
            resolve_client_id(profile),
        )
        return f"{work_dir}/virtuoso_setup.il"

    if is_local:
        print(f"\n[mode] local (no SSH tunnel)")
        if state:
            print(f"  port : {state.get('port')}")
            print(f"  bind : {state.get('bind_policy', 'legacy/unknown')}")
            print(f"  auth : {'enabled' if state.get('auth_enabled') else 'legacy/disabled'}")
            setup_path = state.get("setup_path")
        else:
            setup_path = None
    else:
        # Remote tunnel mode
        print(f"\n[tunnel] {'running' if running else 'NOT running'}")
        print(f"  remote host : {configured_host or '(not set)'}")
        print(f"  remote user : {configured_user or '(not set)'}")
        if jump_host:
            print(f"  jump host   : {jump_host}")
        if state:
            print(f"  local port  : {state.get('port')}")
            print(f"  bind policy : {state.get('bind_policy', 'legacy/unknown')}")
            print(f"  auth        : {'enabled' if state.get('auth_enabled') else 'legacy/disabled'}")
            setup_path = state.get("setup_path")
        else:
            setup_path = None

    if not setup_path:
        setup_path = _infer_setup_path()

    # Daemon (Virtuoso CIW)
    # For local mode, check daemon if we have state (don't require 'running')
    daemon_user_ok = True
    can_check_daemon = (is_local and state) or (running and state)
    if can_check_daemon:
        if state is None:
            print("\n[daemon] cannot check (state missing)")
            return 1
        port = state["port"]
        try:
            vc = VirtuosoClient(
                host="127.0.0.1",
                port=port,
                timeout=5,
                auth_token=resolve_auth_token(profile, create=False),
                profile=profile,
            )
            ok = vc.test_connection(timeout=5)
            print(f"\n[daemon] {'OK - connected to Virtuoso CIW' if ok else 'NO RESPONSE'}")
            if ok:
                from virtuoso_bridge.daemon_guard import check_daemon_user

                try:
                    user_check = check_daemon_user(vc, profile=profile, timeout=5)
                    if user_check.daemon_user:
                        print(f"  daemon user: {user_check.daemon_user}")
                    if user_check.expected_user:
                        print(f"  tunnel user: {user_check.expected_user}")
                    if not user_check.ok:
                        daemon_user_ok = False
                        _print_cross_user_daemon_failure(user_check.error)
                except Exception as exc:
                    print(f"  daemon user: unavailable ({exc})")

                # Query Virtuoso environment info
                for skill_expr, label in [
                    ('getHostName()', 'hostname'),
                    ('getCurrentTime()', 'time'),
                    ('getVersion()', 'version'),
                    ('getWorkingDir()', 'workdir'),
                ]:
                    try:
                        r = vc.execute_skill(skill_expr, timeout=5)
                        val = (r.output or "").strip().strip('"')
                        if val:
                            print(f"  {label:<10s}: {val}")
                    except Exception:
                        pass

                # Say hello in Virtuoso CIW with timestamp
                vc.execute_skill(
                    r'printf("\n  [virtuoso-bridge] Status check at %s - connection OK.\n\n" getCurrentTime())',
                    timeout=5,
                )
            if not ok and setup_path:
                _print_load_hint(setup_path)
                _print_stale_daemon_hint()
        except Exception as e:
            print(f"\n[daemon] error: {e}")
    elif not is_local and not running:
        print(f"\n[daemon] cannot check (tunnel not running)")
        if setup_path:
            _print_load_hint(setup_path)

    # Spectre
    if is_local or running:
        _print_spectre_status(profile, suffix)

    print("\n========================================================================")
    if is_local:
        return 0 if daemon_user_ok else 1
    return 0 if running and daemon_user_ok else 1


def _print_spectre_status(profile: str | None, suffix: str) -> None:
    """Check and print Spectre availability.

    For local mode: uses shutil.which and subprocess locally.
    For remote mode: SSH-based check via SSHClient.

    Strategy (remote): try ``which spectre`` directly first (works when the
    user's login shell already has Cadence on PATH).  If that fails and
    VB_CADENCE_CSHRC is set, source it in a csh sub-shell and retry.
    """
    import shutil
    import subprocess

    from virtuoso_bridge.transport.tunnel import SSHClient, _is_localhost

    configured_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()
    is_local = _is_localhost(configured_host) if configured_host else False

    if is_local:
        try:
            spectre_bin = (
                os.getenv(f"VB_SPECTRE_BIN{suffix}", "").strip()
                or os.getenv("VB_SPECTRE_BIN", "").strip()
            )
            spectre_path = spectre_bin or shutil.which("spectre")
            version = None
            if spectre_path:
                try:
                    result = subprocess.run(
                        [spectre_path, "-V"],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in (result.stdout + result.stderr).splitlines():
                        if line.strip().startswith("@(#)$CDS:"):
                            version = line.strip()
                            break
                except Exception:
                    pass
            if spectre_path:
                print(f"\n[spectre] OK")
                print(f"  path    : {spectre_path}")
                if version:
                    print(f"  version : {version}")
            else:
                print(f"\n[spectre] NOT FOUND")
        except Exception as e:
            print(f"\n[spectre] error: {e}")
        return

    # Remote mode — SSH-based check
    ssh = None
    try:
        ssh = SSHClient.from_env(keep_remote_files=True, profile=profile)
        runner = ssh.ssh_runner
        if runner is None:
            print("\n[spectre] local mode (no SSH runner)")
            return
        runner._verbose = False

        spectre_bin = (
            os.getenv(f"VB_SPECTRE_BIN{suffix}", "").strip()
            or os.getenv("VB_SPECTRE_BIN", "").strip()
        )

        if spectre_bin:
            # Explicit binary path — skip auto-detection.
            quoted = shlex.quote(spectre_bin)
            check_cmd = f"{quoted} -V 2>&1 | head -1"
            print("\n[spectre] probing...", flush=True)
            result = runner.run_command(check_cmd, timeout=60)
            stdout = result.stdout.strip()
            version = None
            for line in stdout.splitlines():
                if line.strip().startswith("@(#)$CDS:"):
                    version = line.strip()
                    break
            print("[spectre] OK")
            print(f"  path    : {spectre_bin}")
            if version:
                print(f"  version : {version}")
            return

        # Two detection strategies, fused into a single SSH handshake:
        #
        #   (A) fast path: spectre already on PATH (bash-shell login,
        #       or ssh server configured with Cadence env baked in)
        #   (B) slow path: source VB_CADENCE_CSHRC inside csh, re-check
        #
        # Older revisions issued these as two separate SSH calls. On
        # congested jump hosts / Windows without ControlMaster, each
        # SSH is a fresh TCP + sshd fork, doubling the risk of banner-
        # exchange timeouts that manifested as spurious "NOT FOUND".
        # Bash parses ``A || B | C`` as ``A || (B | C)`` so the
        # ``head -5`` only applies to the csh fallback — same semantics
        # as before, one round-trip instead of two.
        cadence_cshrc = (
            os.getenv(f"VB_CADENCE_CSHRC{suffix}", "").strip()
            or os.getenv("VB_CADENCE_CSHRC", "").strip()
        )
        fast = "which spectre 2>/dev/null && spectre -V 2>&1 | head -1"
        if cadence_cshrc:
            # Keep csh script out of bash's view — ``!`` / backticks /
            # ``$?VAR`` must reach csh verbatim.
            #
            # Seed HOSTNAME/LD_LIBRARY_PATH with non-empty placeholders:
            # some site cshrc files do ``setenv LD_LIBRARY_PATH
            # ${MMSIM_HOME}/tools/lib:$LD_LIBRARY_PATH`` and csh aborts
            # partway through when ``$LD_LIBRARY_PATH`` is undefined —
            # leaving PATH unpatched so ``which spectre`` returns
            # nothing.  An empty string (``""``) was found insufficient
            # in practice; ``blank`` is a harmless throwaway that the
            # subsequent concat safely overwrites.
            csh_script = (
                'setenv HOSTNAME `hostname`; '
                'setenv LD_LIBRARY_PATH blank; '
                f'source {cadence_cshrc}; '
                'which spectre; '
                'spectre -V'
            )
            slow = f"csh -f -c {shlex.quote(csh_script)} 2>&1 | head -5"
            combined = f"{{ {fast}; }} || {{ {slow}; }}"
        else:
            combined = fast
        check_cmd = f"bash -l -c {shlex.quote(combined)}"
        print("\n[spectre] probing...", flush=True)
        result = runner.run_command(check_cmd, timeout=60)
        stdout = result.stdout.strip()

        spectre_path = None
        version = None
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("@(#)$CDS:"):
                version = line
            elif "/" in line and "spectre" in line.lower():
                spectre_path = line

        if spectre_path:
            print("[spectre] OK")
            print(f"  path    : {spectre_path}")
            if version:
                print(f"  version : {version}")
        else:
            print("[spectre] NOT FOUND")
    except Exception as e:
        print(f"[spectre] error: {e}")
    finally:
        if ssh is not None:
            ssh.close()


def _discover_profiles() -> list[str | None]:
    """Scan environment for all VB_REMOTE_HOST* variables and return profile list.

    Returns a list where None represents the default (unsuffixed) profile
    and strings represent named profiles.
    """
    profiles: list[str | None] = []
    pattern = re.compile(r"^VB_REMOTE_HOST(?:_(.+))?$")
    for key in sorted(os.environ):
        m = pattern.match(key)
        if m and os.environ[key].strip():
            profiles.append(m.group(1))  # None for default, name for suffixed
    return profiles


def _for_each_profile(fn: Callable[[], int]) -> int:
    """Run *fn* for each profile. If -p was given, run only that one.

    Returns 0 if any profile succeeded (returned 0), 1 otherwise.
    """
    profile = _get_cli_profile()
    if profile is not None:
        return fn()
    profiles = _discover_profiles()
    if not profiles:
        print("No profiles found. Set VB_REMOTE_HOST in .env first.")
        return 1
    any_ok = False
    for i, p in enumerate(profiles):
        _CLI_PROFILE[0] = p
        ret = fn()
        if ret == 0:
            any_ok = True
        if i < len(profiles) - 1:
            print()
    return 0 if any_ok else 1


def cli_status() -> int:
    _load_cli_env()
    return _for_each_profile(_print_status)


def cli_request_status(
    *, request_id: str | None = None, timeout: float = 10.0
) -> int:
    """Read the daemon request ledger without using the CIW request channel."""
    timeout = _positive_finite_timeout(timeout)
    _load_cli_env()
    from virtuoso_bridge.transport.tunnel import SSHClient

    payload = SSHClient.read_request_status(
        _get_cli_profile(), request_id=request_id, timeout=timeout
    )
    if payload is None:
        print(json.dumps({"status": "unavailable", "request_id": request_id}))
        return 1
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if request_id and payload.get("request") is None:
        return 1
    return 0


def cli_deployment_status(*, timeout: float = 10.0) -> int:
    """Compare packaged, staged, and running daemon identities."""
    timeout = _positive_finite_timeout(timeout)
    _load_cli_env()
    from virtuoso_bridge.transport.tunnel import SSHClient

    payload = SSHClient.deployment_status(
        _get_cli_profile(), timeout=timeout
    )
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if (
        payload.get("local_matches_deployed")
        and payload.get("deployed_matches_running")
        and payload.get("running_heartbeat_fresh")
    ) else 2


_REQUEST_PENDING_STATES = frozenset({
    "queued",
    "running",
    "timed_out_pending",
    "late_waiting_operator",
})
_REQUEST_KNOWN_TERMINAL_STATES = frozenset({
    "succeeded",
    "failed",
    "succeeded_after_timeout",
    "failed_after_timeout",
})


def _is_sha256(value: object) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def _terminal_proof_errors(
    request: dict[str, object],
    request_id: str,
    expected: dict[str, object],
) -> list[str]:
    """Return fail-closed identity/integrity errors for one terminal proof."""
    errors: list[str] = []
    required_expected = {
        "request_digest_sha256",
        "operation_class",
        "daemon_epoch",
        "daemon_build_sha256",
        "request_generation",
        "protocol_version",
    }
    for key in sorted(required_expected):
        if expected.get(key) in (None, ""):
            errors.append(f"missing-expected-{key.replace('_', '-')}")
    if errors:
        return errors

    proof = request.get("terminal_proof")
    if not isinstance(proof, dict):
        return ["terminal-proof-missing"]
    if proof.get("schema_version") != 1:
        errors.append("terminal-proof-schema-unsupported")
    if proof.get("complete_frame") is not True:
        errors.append("terminal-proof-frame-incomplete")

    state = str(request.get("state") or "")
    expected_marker = (
        "STX" if state in {"succeeded", "succeeded_after_timeout"} else "NAK"
    )
    exact_fields = {
        "request_id": request_id,
        "request_digest_sha256": expected["request_digest_sha256"],
        "operation_class": expected["operation_class"],
        "daemon_epoch": expected["daemon_epoch"],
        "daemon_build_sha256": expected["daemon_build_sha256"],
        "request_generation": expected["request_generation"],
        "protocol_version": expected["protocol_version"],
        "state": state,
        "response_marker": expected_marker,
    }
    for key, value in exact_fields.items():
        if proof.get(key) != value:
            errors.append(f"terminal-proof-{key.replace('_', '-')}-mismatch")

    request_fields = {
        "request_id": request_id,
        "request_digest_sha256": expected["request_digest_sha256"],
        "operation_class": expected["operation_class"],
        "admitted_daemon_epoch": expected["daemon_epoch"],
        "admitted_daemon_build_sha256": expected["daemon_build_sha256"],
        "request_generation": expected["request_generation"],
        "protocol_version": expected["protocol_version"],
    }
    for key, value in request_fields.items():
        if request.get(key) != value:
            errors.append(f"request-{key.replace('_', '-')}-mismatch")

    for key in (
        "response_marker",
        "response_digest_sha256",
        "payload_digest_sha256",
        "response_size_bytes",
        "finished_at_epoch",
    ):
        if request.get(key) != proof.get(key):
            errors.append(f"request-terminal-proof-{key.replace('_', '-')}-mismatch")

    for key in (
        "request_digest_sha256",
        "daemon_build_sha256",
        "response_digest_sha256",
        "payload_digest_sha256",
    ):
        if not _is_sha256(proof.get(key)):
            errors.append(f"terminal-proof-{key.replace('_', '-')}-invalid")
    response_size = proof.get("response_size_bytes")
    if (
        isinstance(response_size, bool)
        or not isinstance(response_size, int)
        or response_size < 0
    ):
        errors.append("terminal-proof-response-size-invalid")
    try:
        finished_at = float(proof.get("finished_at_epoch"))
        if not math.isfinite(finished_at) or finished_at <= 0:
            raise ValueError
    except (TypeError, ValueError):
        errors.append("terminal-proof-finished-at-invalid")
    return sorted(set(errors))


def _classify_request_reconciliation(
    payload: dict[str, object] | None,
    request_id: str,
    *,
    expected_terminal_proof: dict[str, object] | None = None,
    require_terminal_proof: bool = False,
) -> dict[str, object]:
    request = payload.get("request") if payload else None
    if not isinstance(request, dict):
        return {
            "request_id": request_id,
            "state": None,
            "terminal": False,
            "outcome": "not_found",
            "safe_to_clear_quarantine": False,
        }

    state = str(request.get("state") or "")
    proof_errors: list[str] = []
    if state in _REQUEST_PENDING_STATES:
        outcome = "in_progress"
        terminal = False
        safe_to_clear = False
    else:
        terminal = True
        known_terminal = state in _REQUEST_KNOWN_TERMINAL_STATES
        if known_terminal and require_terminal_proof:
            proof_errors = _terminal_proof_errors(
                request,
                request_id,
                expected_terminal_proof or {},
            )
            expected = expected_terminal_proof or {}
            if payload.get("daemon_epoch") != expected.get("daemon_epoch"):
                proof_errors.append("ledger-daemon-epoch-mismatch")
            if (
                payload.get("daemon_build_sha256")
                != expected.get("daemon_build_sha256")
            ):
                proof_errors.append("ledger-daemon-build-sha256-mismatch")
            safe_to_clear = not proof_errors
            outcome = "known_terminal" if safe_to_clear else "terminal_proof_invalid"
        else:
            safe_to_clear = known_terminal and not require_terminal_proof
            outcome = "known_terminal" if known_terminal else "indeterminate_terminal"
    result = {
        "request_id": request_id,
        "state": state or None,
        "terminal": terminal,
        "outcome": outcome,
        "safe_to_clear_quarantine": safe_to_clear,
        "response_marker": request.get("response_marker"),
        "operation_class": request.get("operation_class"),
        "request_digest_sha256": request.get("request_digest_sha256"),
        "daemon_epoch": payload.get("daemon_epoch") if payload else None,
        "heartbeat_at_epoch": payload.get("heartbeat_at_epoch") if payload else None,
    }
    if state not in _REQUEST_PENDING_STATES:
        result["terminal_proof"] = request.get("terminal_proof")
        result["proof_errors"] = proof_errors
    return result


def cli_request_await(
    *,
    request_id: str,
    timeout: float = 60.0,
    poll_interval: float = 1.0,
    require_terminal_proof: bool = False,
    expected_request_digest_sha256: str | None = None,
    expected_operation_class: str | None = None,
    expected_daemon_epoch: str | None = None,
    expected_daemon_build_sha256: str | None = None,
    expected_request_generation: str | None = None,
    expected_protocol_version: int | None = None,
) -> int:
    """Wait for a ledger terminal state without replaying the request."""
    timeout = _positive_finite_timeout(timeout)
    poll_interval = _positive_finite_timeout(poll_interval)

    _load_cli_env()
    from virtuoso_bridge.transport.tunnel import SSHClient

    deadline = time.monotonic() + timeout
    first_epoch: str | None = None
    latest: dict[str, object] | None = None
    stable_terminal_signature: str | None = None
    expected_terminal_proof: dict[str, object] = {
        "request_digest_sha256": expected_request_digest_sha256,
        "operation_class": expected_operation_class,
        "daemon_epoch": expected_daemon_epoch,
        "daemon_build_sha256": expected_daemon_build_sha256,
        "request_generation": expected_request_generation,
        "protocol_version": expected_protocol_version,
    }
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            payload = None
        else:
            payload = SSHClient.read_request_status(
                _get_cli_profile(),
                request_id=request_id,
                timeout=min(10.0, remaining),
            )
        if payload is not None:
            latest = dict(payload)
            epoch_value = payload.get("daemon_epoch")
            epoch = str(epoch_value) if epoch_value else None
            if first_epoch is None:
                first_epoch = epoch
            latest["observed_daemon_epoch"] = first_epoch
            latest["daemon_epoch_changed"] = bool(
                first_epoch and epoch and first_epoch != epoch
            )
            reconciliation = _classify_request_reconciliation(
                latest,
                request_id,
                expected_terminal_proof=expected_terminal_proof,
                require_terminal_proof=require_terminal_proof,
            )
            if latest["daemon_epoch_changed"] and reconciliation["outcome"] == "not_found":
                reconciliation = dict(reconciliation)
                reconciliation.update({
                    "terminal": True,
                    "outcome": "indeterminate_terminal",
                    "state": "orphaned_unknown_after_daemon_restart",
                })
            if (
                require_terminal_proof
                and reconciliation["terminal"]
                and reconciliation["safe_to_clear_quarantine"]
            ):
                signature = json.dumps(
                    {
                        "request": latest.get("request"),
                        "daemon_epoch": latest.get("daemon_epoch"),
                        "daemon_build_sha256": latest.get("daemon_build_sha256"),
                        "expected": expected_terminal_proof,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if signature != stable_terminal_signature:
                    stable_terminal_signature = signature
                    reconciliation = dict(reconciliation)
                    reconciliation.update({
                        "terminal": False,
                        "safe_to_clear_quarantine": False,
                        "outcome": "terminal_proof_pending_stability",
                        "stable_reads": 1,
                    })
                else:
                    reconciliation = dict(reconciliation)
                    reconciliation["stable_reads"] = 2
            elif require_terminal_proof:
                stable_terminal_signature = None
            latest["reconciliation"] = reconciliation
            if reconciliation["terminal"]:
                print(json.dumps(latest, ensure_ascii=False, sort_keys=True))
                return 0
        elif require_terminal_proof:
            stable_terminal_signature = None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result = dict(latest or {
                "schema_version": 1,
                "daemon_epoch": None,
                "request": None,
            })
            result["reconciliation"] = {
                "request_id": request_id,
                "state": (
                    result.get("request", {}).get("state")
                    if isinstance(result.get("request"), dict)
                    else None
                ),
                "terminal": False,
                "outcome": "wait_timeout",
                "safe_to_clear_quarantine": False,
            }
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
        time.sleep(min(poll_interval, remaining))


# -- license ----------------------------------------------------------------

def cli_license() -> int:
    _load_cli_env()
    profile = _get_cli_profile()
    suffix = f"_{profile}" if profile else ""
    cadence_cshrc = os.getenv(f"VB_CADENCE_CSHRC{suffix}", "").strip() or os.getenv("VB_CADENCE_CSHRC", "").strip()
    if not cadence_cshrc:
        print("VB_CADENCE_CSHRC is not set.")
        return 1

    from virtuoso_bridge.transport.tunnel import SSHClient
    if not SSHClient.is_running(profile):
        hint = f"Run `virtuoso-bridge start -p {profile}` first." if profile else "Run `virtuoso-bridge start` first."
        print(f"No tunnel running. {hint}")
        return 1

    from virtuoso_bridge.transport.tunnel import _is_localhost
    from virtuoso_bridge.spectre.runner import SpectreSimulator

    suffix = f"_{profile}" if profile else ""
    configured_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()

    ssh = None
    try:
        if _is_localhost(configured_host):
            sim = SpectreSimulator.from_env(profile=profile)
        else:
            # Create SSHRunner with verbose=False to suppress [cmd] output
            ssh = SSHClient.from_env(keep_remote_files=True, profile=profile)
            runner = ssh.ssh_runner
            if runner is None:
                print("No SSH runner available for remote license check.")
                return 1
            runner._verbose = False
            sim = SpectreSimulator.from_env(profile=profile, ssh_runner=runner)

        info = sim.check_license()

        print(f"[spectre] {info.get('spectre_path', 'NOT FOUND')}")
        if info.get("version"):
            print(f"  version: {info['version']}")
        licenses = info.get("licenses", [])
        if licenses:
            print(f"\n[licenses in use] ({len(licenses)} features)")
            for line in licenses:
                print(f"  {line}")

        return 0 if info.get("ok") else 1
    finally:
        if ssh is not None:
            ssh.close()


# -- main -------------------------------------------------------------------

def _make_ssh_runner() -> tuple["SSHRunner | None", str]:
    """Create an SSHRunner from .env config (for X11 commands).

    In local mode (VB_REMOTE_HOST is this machine) return ``(None, user)`` so
    the X11 helper runs locally via subprocess instead of trying to SSH to
    localhost (which fails without passwordless key auth). Mirrors the local
    detection used by the daemon/tunnel path.
    """
    from virtuoso_bridge.transport.ssh import SSHRunner
    from virtuoso_bridge.transport.tunnel import _is_localhost

    profile = _get_cli_profile()
    suffix = f"_{profile}" if profile else ""
    remote_host = os.getenv(f"VB_REMOTE_HOST{suffix}", "").strip()
    remote_user = os.getenv(f"VB_REMOTE_USER{suffix}", "").strip()
    jump_host = os.getenv(f"VB_JUMP_HOST{suffix}", "").strip() or None
    jump_user = os.getenv(f"VB_JUMP_USER{suffix}", remote_user).strip() or None
    if not remote_host:
        raise SystemExit("Error: VB_REMOTE_HOST not set")
    if _is_localhost(remote_host):
        return None, remote_user
    return SSHRunner(host=remote_host, user=remote_user,
                     jump_host=jump_host, jump_user=jump_user), remote_user


def cli_load(*, file: str, timeout: float = 60, quiet: bool = False) -> int:
    """Execute a SKILL .il file in the running Virtuoso session.

    Equivalent to ``load("<file>")`` typed in the CIW: SKILL reads the
    original file directly, so error messages keep the **original file
    path + line numbers** (no temp-wrapper pollution).  In SSH mode
    the file is uploaded first; in local mode the path is forwarded
    as-is.  Both paths land in :meth:`VirtuosoClient.load_il`.

    Output: the full ``VirtuosoResult`` serialised as JSON on stdout
    (status, output, errors, warnings, execution_time, metadata).
    Designed for VS Code tasks / code-runner / wrapper scripts to
    consume without re-parsing terminal text.  ``--quiet`` suppresses
    the JSON; only the exit code remains.

    Returns: 0 on SUCCESS, 1 on SKILL-side error, 2 on missing local
    file.
    """
    import json
    import sys
    from pathlib import Path

    import virtuoso_bridge as _vb_pkg
    from virtuoso_bridge.models import ExecutionStatus

    # Missing file is a common user typo (often from VS Code tasks
    # passing an unsaved/renamed buffer).  Fail fast before loading env
    # so the error message isn't preceded by a "using .env: ..." line.
    p = Path(file)
    if not p.is_file():
        print(f"ERROR: file not found: {p}", file=sys.stderr)
        return 2

    _load_cli_env()
    client = _vb_pkg.VirtuosoClient.from_env(profile=_get_cli_profile())
    result = client.load_il(p, timeout=timeout)

    if not quiet:
        # Stable contract: dump the VirtuosoResult exactly as the model
        # defines it.  Consumers (VS Code task output, scripts) should
        # rely on these field names rather than scraping prose.
        print(json.dumps(
            result.model_dump(mode="json"),
            indent=2, ensure_ascii=False, default=str,
        ))

    return 0 if result.status == ExecutionStatus.SUCCESS else 1


def cli_eval(*, skill: str | None, stdin: bool, timeout: float = 60,
             quiet: bool = False,
             operation_class: OperationClass = OperationClass.UNKNOWN) -> int:
    """Execute a SKILL expression in the running Virtuoso session.

    Companion to :func:`cli_load` for one-liners and round-trip checks
    where wrapping the snippet in a temp ``.il`` file would be friction.
    Source the SKILL from argv (``virtuoso-bridge eval 'getCurrentTime()'``)
    or from stdin (``echo 'expr' | virtuoso-bridge eval --stdin``); the
    latter sidesteps shell-quoting pain for snippets full of ``"``,
    parens, and quoted symbols.

    Output: same JSON shape as :func:`cli_load` so consumers don't need
    to branch on which command produced the result.

    Returns: 0 on SUCCESS, 1 on SKILL-side error, 2 on input misuse
    (no SKILL provided, or both argv and ``--stdin`` given).
    """
    import json
    import sys

    import virtuoso_bridge as _vb_pkg
    from virtuoso_bridge.models import ExecutionStatus

    if stdin and skill is not None:
        print("ERROR: pass SKILL via argv OR --stdin, not both",
              file=sys.stderr)
        return 2
    if stdin:
        skill = sys.stdin.read()
    if skill is None or not skill.strip():
        print("ERROR: empty SKILL expression", file=sys.stderr)
        return 2

    # Wrap in progn(...) on its own lines so that:
    #   * multi-statement inputs (`printf(...) "ret"`) work without the
    #     user adding progn themselves -- the daemon's single-line path
    #     does `let(((__vb_r <code>)) ...)` which only takes one form;
    #   * trailing `; comment` doesn't swallow the closing paren --
    #     the wrapping newline before `)` terminates the line comment;
    #   * embedded newlines (heredoc / multi-line input) flow through
    #     unchanged.
    # The newlines also force the daemon onto its multi-line code path
    # (temp-file + load), which handles `progn` reliably.
    wrapped = f"progn(\n{skill}\n)"

    _load_cli_env()
    client = _vb_pkg.VirtuosoClient.from_env(profile=_get_cli_profile())
    result = client.execute_skill(
        wrapped,
        timeout=timeout,
        operation_class=operation_class,
    )

    if not quiet:
        print(json.dumps(
            result.model_dump(mode="json"),
            indent=2, ensure_ascii=False, default=str,
        ))

    return 0 if result.status == ExecutionStatus.SUCCESS else 1


def cli_dismiss_dialog() -> int:
    """Find and dismiss blocking Virtuoso GUI dialogs via X11."""
    _load_cli_env()
    from virtuoso_bridge.virtuoso import x11
    runner, user = _make_ssh_runner()

    dialogs = x11.dismiss_dialogs(runner, user, profile=_get_cli_profile())
    if not dialogs:
        print("No dialog windows found.")
        return 0

    for d in dialogs:
        if "error" in d:
            print(f"  Error: {d['error']}")
        elif "dismissed" in d:
            print(f"  Dismissed: {d['dismissed']}")
        elif "title" in d:
            print(f'  Found: "{d["title"]}" at ({d.get("x",0)},{d.get("y",0)})')
    return 0


def cli_list_windows(*, json_output: bool = False) -> int:
    """List Virtuoso-related X11 windows without dismissing anything."""
    import json

    if json_output:
        load_vb_env()
    else:
        _load_cli_env()
    from virtuoso_bridge.virtuoso import x11
    runner, user = _make_ssh_runner()

    windows = x11.list_windows(runner, user, profile=_get_cli_profile())
    if json_output:
        print(json.dumps(windows, indent=2, ensure_ascii=False, default=str))
        return 0
    if not windows:
        print("No Virtuoso X11 windows found.")
        return 0
    for w in windows:
        geo = w.get("geometry") or {}
        title = w.get("title") or "(untitled)"
        print(
            f"{w.get('dismiss_id') or w.get('window_id')} "
            f"[{w.get('kind', 'window')}] {title} "
            f"{geo.get('w', 0)}x{geo.get('h', 0)}+{geo.get('x', 0)}+{geo.get('y', 0)} "
            f"action={w.get('suggested_action') or '-'}"
        )
    return 0


def cli_dismiss_window(*, window_id: str, action: str = "enter") -> int:
    """Dismiss one explicit X11 window id via XTest."""
    _load_cli_env()
    from virtuoso_bridge.virtuoso import x11
    runner, user = _make_ssh_runner()

    results = x11.dismiss_window(
        runner,
        user,
        window_id,
        action=action,
        profile=_get_cli_profile(),
    )
    if not results:
        print("No result returned.")
        return 1
    ok = True
    for result in results:
        if "error" in result:
            ok = False
            print(f"  Error: {result['error']}")
        else:
            print(
                f"  Dismissed: {result.get('dismissed', window_id)} "
                f"action={result.get('action', action)}"
            )
    return 0 if ok else 1


def cli_window_input(*, window_id: str, expect_title: str, action: str,
                     x: int, y: int, button: int, to_x: int | None,
                     to_y: int | None, allow_live: bool, dry_run: bool,
                     settle_ms: int, hold_ms: int, drag_duration_ms: int,
                     drag_steps: int, postcondition: str,
                     post_expect_title: str | None) -> int:
    """Perform one explicitly confirmed, bounds-checked X11 pointer action."""
    _load_cli_env()
    from virtuoso_bridge.virtuoso import x11
    runner, user = _make_ssh_runner()
    results = x11.window_input(
        runner,
        user,
        window_id,
        expect_title=expect_title,
        action=action,
        x=x,
        y=y,
        button=button,
        to_x=to_x,
        to_y=to_y,
        allow_live=allow_live,
        dry_run=dry_run,
        settle_ms=settle_ms,
        hold_ms=hold_ms,
        drag_duration_ms=drag_duration_ms,
        drag_steps=drag_steps,
        postcondition=postcondition,
        post_expect_title=post_expect_title,
        profile=_get_cli_profile(),
    )
    print(json.dumps(results, ensure_ascii=False, default=str))
    return 0 if results and not any("error" in item for item in results) else 1



_SCREENSHOT_TARGET: list[str] = ["ciw"]

# Mutable bag for cli_snapshot — set from argparse, read inside the handler.
# `output_root=None` is a sentinel for "user didn't pass -o" — that's what
# selects brief stdout mode.
_SNAPSHOT_OPTS: dict = {
    "output_root": None,
    "json":        False,
    "history":     None,
}

_EXPORT_VISIO_OPTS: dict = {
    "lib":               None,
    "cell":              None,
    "output":            None,
    "stencil":           None,
    "scale":             1.0,
    "exclude_nets":      [],
    "exclude_pins":      ["B"],
    "include_body_pins": False,
    "hidden":            False,
}


def cli_find(*, query: str | None, mode: str, limit: int, include_desc: bool, json_output: bool) -> int:
    """Search SKILL API documentation from Cadence .fnd files.

    On first run for a given server, downloads the SKILL Finder database
    (~tens of MB) to a local cache.  Subsequent runs use the cache.
    """
    import json as _json
    import sys

    _load_cli_env()
    from virtuoso_bridge import VirtuosoClient
    from virtuoso_bridge.virtuoso.skill_finder import SKILLFinder

    client = VirtuosoClient.from_env(profile=_get_cli_profile())

    if not query:
        print("Error: query argument required for 'skill-find'", file=sys.stderr)
        return 1

    results = client.find_skill(query or "", mode=mode, limit=limit, include_desc=include_desc)

    if not query:
        print("Error: query argument required for 'skill-find'", file=sys.stderr)
        return 1

    if json_output:
        print(_json.dumps(results, indent=2, ensure_ascii=False))
    else:
        finder = SKILLFinder()
        from virtuoso_bridge.virtuoso.skill_finder.parser import SkillEntry
        entries = [SkillEntry(**r) for r in results]
        print(finder.format_results(entries, query or ""))

    return 0


def cli_skill_info(*, func_name: str, json_output: bool) -> int:
    """Get More Info documentation for a specific SKILL function."""
    import json as _json

    _load_cli_env()
    from virtuoso_bridge import VirtuosoClient

    client = VirtuosoClient.from_env(profile=_get_cli_profile())
    result = client.get_skill_more_info(func_name)

    if json_output:
        print(_json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if result is None:
            print(f"No More Info found for: {func_name}")
            return 1
        print(f"More Info — {result['func_name']}")
        print(f"  Source  : {result['file_path']}")
        print(f"  Topic   : {result['topic'] or '(whole file)'}")
        print()
        print(result["plain_text"])
    return 0


def cli_doc_search(
    *,
    query: str | None,
    doc_roots: list[Path],
    limit: int,
    list_roots: bool,
    json_output: bool,
    rebuild_index: bool,
) -> int:
    """Search installed Cadence documentation locally or through the bridge."""
    import json as _json
    import sys

    from virtuoso_bridge.runtime_paths import cache_dir as runtime_cache_dir
    from virtuoso_bridge.virtuoso.docs_search import resolve_doc_roots, search_docs

    if doc_roots:
        roots = resolve_doc_roots(doc_roots)
        payload: dict[str, object]
        if list_roots:
            payload = {"ok": True, "doc_roots": [str(root) for root in roots]}
        else:
            if not query:
                print("Error: query argument required for 'doc-search'", file=sys.stderr)
                return 1
            if not roots:
                print("Error: no existing Cadence doc roots found for --doc-root.", file=sys.stderr)
                return 1
            payload = {
                "ok": True,
                "query": query,
                "doc_roots": [str(root) for root in roots],
                "results": search_docs(
                    query,
                    roots,
                    cache_root=runtime_cache_dir("docs_search") / "local",
                    limit=max(limit, 0),
                    rebuild=rebuild_index,
                ),
            }
    else:
        _load_cli_env()
        from virtuoso_bridge import VirtuosoClient

        client = VirtuosoClient.from_env(profile=_get_cli_profile())
        if list_roots:
            client_payload = client.search_docs("", limit=0, rebuild_index=rebuild_index)
            payload = {
                "ok": True,
                "doc_roots": client_payload.get("doc_roots", []),
                "results": [],
            }
        else:
            if not query:
                print("Error: query argument required for 'doc-search'", file=sys.stderr)
                return 1
            client_payload = client.search_docs(query, limit=max(limit, 0), rebuild_index=rebuild_index)
            payload = {
                "ok": True,
                "query": query,
                "doc_roots": client_payload.get("doc_roots", []),
                "results": client_payload.get("results", []),
            }

    if not payload.get("doc_roots") and not list_roots:
        if doc_roots:
            print(
                "Error: no existing Cadence doc roots found for --doc-root.",
                file=sys.stderr,
            )
        else:
            print(
                "Error: no Cadence doc roots found. Pass --doc-root or configure "
                "a Virtuoso Bridge profile with access to the Cadence installation.",
                file=sys.stderr,
            )
        return 1

    if json_output:
        print(_json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if list_roots:
        for root in payload["doc_roots"]:
            print(root)
        return 0

    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        location = result.get("target_relative_path") or result.get("relative_path")
        title = result.get("title") or location
        line = result.get("line")
        suffix = f":{line}" if line else ""
        print(f"{location}{suffix} {title}")
        snippet = result.get("snippet")
        if snippet:
            print(f"  {snippet}")
    return 0


def cli_windows() -> int:
    """List all open Virtuoso windows.

    Annotates the focused line with its bound maestro session (when
    the focused window is an ADE Assembler) and lists all open
    sessions in a footer.  All info comes from a single SKILL round-
    trip — no scp.
    """
    _load_cli_env()
    import sys
    from virtuoso_bridge import VirtuosoClient
    from virtuoso_bridge.virtuoso.maestro.reader._parse_skill import (
        _parse_skill_str_list,
    )

    client = VirtuosoClient.from_env()
    windows = client.list_windows()
    if not windows:
        print("No windows found.")
        return 1

    # One SKILL call → focused window number + focused window's bound
    # maestro session id (via davSession attribute) + all open sessions.
    focused_num = ""
    focused_session = ""
    sessions: list[str] = []
    try:
        r = client.execute_skill(
            "let((w) w = hiGetCurrentWindow() list("
            "if(w sprintf(nil \"%d\" w~>windowNum) \"\")"
            " if(w w->davSession \"\")"
            " maeGetSessions()))"
        )
        out = (r.output or "").strip()
        if out.startswith("(") and out.endswith(")"):
            inner = out[1:-1].strip()
            # First two tokens are quoted strings; the rest is the
            # ``maeGetSessions()`` list literal.
            m = re.match(r'\s*"([^"]*)"\s*"([^"]*)"\s*(.*)', inner, re.DOTALL)
            if m:
                focused_num = m.group(1).strip()
                focused_session = m.group(2).strip()
                sessions = _parse_skill_str_list(m.group(3).strip())
    except Exception:
        pass

    use_color = sys.stdout.isatty()
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    focused_name = next(
        (w["name"] for w in windows if w["num"] == focused_num), "")
    if focused_num:
        label = f"{focused_num}  {focused_name}" if focused_name else focused_num
        suffix = f"  [{focused_session}]" if focused_session else ""
        print(f"Focused: {BOLD}{label}{RESET}{suffix}\n")

    for w in windows:
        is_focused = w["num"] == focused_num
        marker = "*" if is_focused else " "
        name = f"{BOLD}{w['name']}{RESET}" if is_focused else w["name"]
        print(f"{marker} {w['num']:>4}  {name}")

    if sessions:
        print()
        print(f"Maestro sessions ({len(sessions)}): {', '.join(sessions)}")
    return 0


def cli_snapshot() -> int:
    """Snapshot the currently-focused Virtuoso window.

    Three modes:
      default     : brief one-screen summary to stdout (fast —
                     brief_bundle only, ~150ms).
      ``-o ROOT`` : full ``snapshot(output_root=ROOT)`` — pure SKILL +
                     5 scp's; writes maestro.sdb + active.state (raw) +
                     state_from_sdb.xml + state_from_active_state.xml
                     (filtered) + state_from_skill.json + histories.json
                     + latest_history.json + <history>/ run artifacts.
      ``--json``  : full in-memory snapshot dict as JSON to stdout.
    """
    _load_cli_env()
    import json
    import re
    import sys
    from virtuoso_bridge import VirtuosoClient
    from virtuoso_bridge.virtuoso import snapshot as poly_snapshot
    from virtuoso_bridge.virtuoso.snapshot import classify_window

    client = VirtuosoClient.from_env()
    opts = _SNAPSHOT_OPTS

    # Focused window title — decode SKILL octal escapes (e.g. \256 -> ®).
    title = (client.execute_skill(
        'let((cw) cw = hiGetCurrentWindow() if(cw hiGetWindowName(cw) ""))'
    ).output or "").strip().strip('"')
    title = re.sub(r'\\(\d{3})', lambda m: chr(int(m.group(1), 8)), title)
    kind = classify_window(title)

    # Mode 1: -o ROOT — full disk snapshot (maestro only for now).
    if opts["output_root"] is not None:
        if kind != "maestro":
            print(f"[{kind}] {title}", file=sys.stderr)
            print(f"-o ROOT only supports maestro for now.", file=sys.stderr)
            return 1
        result = client.maestro.snapshot(
            output_root=opts["output_root"],
            history=opts.get("history"),
        )
        hist = result.get("latest_history") or ""
        if hist:
            print(f"[snapshot] history: {hist}")
        print(result.get("output_dir", ""))
        return 0

    # Mode 2: --json — full in-memory dict to stdout.
    if opts["json"]:
        result = poly_snapshot(client) if kind != "maestro" else poly_snapshot(client)
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False, default=str)
        sys.stdout.write("\n")
        return 0

    # Mode 3 (default): brief stdout summary.
    if kind == "unknown":
        print(f"no Virtuoso window in focus  ({title or '(no title)'})", file=sys.stderr)
        return 1
    if kind != "maestro":
        # Other kinds: just identify, no commentary.
        print(f"[{kind}] {title}")
        return 0

    # Maestro brief: just call snapshot() (no output_root) and render
    # its sparse dict.  2 SKILL round-trips total, no scp.  ~150ms.
    snap = client.maestro.snapshot()
    _print_maestro_brief(snap)
    return 0


_BRIEF_INCLUDE_PREFIXES = (
    "ddGetObj(",                              # lib readPath
    "maeGetSetup(",                           # test name(s)
    "maeGetEnabledAnalysis(",                 # analysis names
    "maeGetAnalysis(",                        # per-analysis settings
)


def _print_maestro_brief(d: dict) -> None:
    """Dump high-signal SKILL sections to stdout, ``state_from_skill.txt``
    format (``[label]`` + verbatim value).  Whitelist of probe prefixes
    above — new probes default to disk-dump-only.  ``snapshot -o ROOT``
    keeps the full set.  No alist→dict parsing; no path lines (paths
    can't be verified without scp)."""
    from virtuoso_bridge.virtuoso.maestro.reader.snapshot import format_skill_sections
    sections = [(label, raw) for label, raw in (d.get("raw_sections") or [])
                if any(label.startswith(p) for p in _BRIEF_INCLUDE_PREFIXES)]
    text = format_skill_sections(sections)
    if text:
        print(text, end="")


def cli_export_visio() -> int:
    """Export a schematic to Microsoft Visio."""
    _load_cli_env()
    from virtuoso_bridge import VirtuosoClient
    from virtuoso_bridge.virtuoso.visio import export_schematic_to_visio

    opts = _EXPORT_VISIO_OPTS
    client = VirtuosoClient.from_env(profile=_get_cli_profile())
    lib = opts["lib"]
    cell = opts["cell"]
    if not lib or not cell:
        lib, cell, _ = client.get_current_design()
        if not lib or not cell:
            print("Usage: virtuoso-bridge export-visio LIB CELL [-o output.vsdx]")
            print("       or open a schematic in Virtuoso first.")
            return 1

    exclude_pins = [] if opts["include_body_pins"] else opts["exclude_pins"]
    output = opts["output"] or f"{lib}_{cell}.vsdx"
    try:
        model = export_schematic_to_visio(
            client,
            lib,
            cell,
            output_path=output,
            stencil_path=opts["stencil"],
            visible=not opts["hidden"],
            scale=opts["scale"],
            exclude_nets=opts["exclude_nets"],
            exclude_pins=exclude_pins,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1

    print(
        f"Exported {lib}/{cell}/schematic: "
        f"{len(model.instances)} instances, {len(model.nets)} routed nets"
    )
    print(str(output))
    return 0


def cli_screen(output=None, display=None, window_id=None) -> int:
    """Capture desktop independently of the daemon and SKILL channel."""
    _load_cli_env()
    from virtuoso_bridge.virtuoso.x11 import capture_screen
    from virtuoso_bridge.runtime_paths import artifact_dir
    from uuid import uuid4
    runner, user = _make_ssh_runner()
    output = output or artifact_dir("screenshots") / ("desktop-" + uuid4().hex + ".png")
    try:
        result = capture_screen(runner, user, output, profile=_get_cli_profile(), display=display, window_id=window_id)
        print(json.dumps(result))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc), "skill_executed": False}))
        return 1


def cli_screenshot() -> int:
    """Take a screenshot of a Virtuoso window."""
    _load_cli_env()
    from virtuoso_bridge import VirtuosoClient

    client = VirtuosoClient.from_env()
    raw_target = _SCREENSHOT_TARGET[0]

    # Resolve target
    target: str | int
    if raw_target.isdigit():
        target = int(raw_target)
    else:
        target = raw_target

    output = _SCREENSHOT_OUTPUT[0]

    result = client.screenshot(output=output, target=target)
    if result.status.value != "success":
        print(f"Error: {result.errors[0] if result.errors else 'screenshot failed'}")
        return 1
    print(result.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="virtuoso-bridge")
    parser.add_argument(
        "--json-envelope",
        action="store_true",
        help="Emit one stable machine-readable command envelope",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    sp_init = subparsers.add_parser("init", help="Create a starter .env")
    sp_init.add_argument(
        "remote", nargs="?", default=None,
        help="Remote target as [user@]host (e.g. designer1@thu-wei). "
             "Port hash uses the remote username when given.",
    )
    sp_init.add_argument(
        "-J", "--jump", default=None,
        help="Jump host as [user@]host (e.g. designer1@bastion.example.com)",
    )
    sp_init.add_argument(
        "--force", action="store_true",
        help="Overwrite an existing .env",
    )
    for name, hlp in [
        ("start", "Start SSH tunnel + deploy daemon"),
        ("stop", "Stop the SSH tunnel"),
        ("restart", "Stage/reuse the tunnel and perform one guarded daemon restart"),
        ("status", "Check tunnel + daemon status"),
        ("license", "Check Spectre license availability"),
    ]:
        sp = subparsers.add_parser(name, help=hlp)
        sp.add_argument("-p", "--profile", default=None,
                        help="Connection profile (reads VB_*_<profile> env vars)")
        sp.add_argument("--env", default=None,
                        help="Explicit .env file path (highest priority)")
        if name == "start":
            sp.add_argument("--bind-venv", action="store_true",
                            help="Bind the active virtualenv to this -p profile before starting")
        if name in {"start", "restart"}:
            sp.add_argument(
                "--allow-remote-bind",
                action="store_true",
                default=None,
                help="Explicitly expose the daemon beyond loopback (unsafe unless firewalled)",
            )
        if name == "restart":
            sp.add_argument(
                "--timeout",
                type=_restart_timeout,
                default=30.0,
                help="Absolute guard, dispatch, and convergence budget in seconds",
            )

    sp_autoload = subparsers.add_parser(
        "autoload",
        help="Install, inspect, or remove the profile-specific .cdsinit autoload block",
    )
    sp_autoload.add_argument(
        "action", choices=("install", "status", "uninstall"),
        help="Autoload operation; status/uninstall never create an auth token",
    )
    sp_autoload.add_argument("-p", "--profile", default=None,
                             help="Connection profile")
    sp_autoload.add_argument("--env", default=None,
                             help="Explicit .env file path (highest priority)")
    sp_autoload.add_argument("--timeout", type=_positive_finite_timeout, default=10.0,
                             help="Remote file operation timeout in seconds")

    sp_request_status = subparsers.add_parser(
        "request-status",
        help="Read the daemon request ledger without using the CIW channel",
    )
    sp_request_status.add_argument("request_id", nargs="?", default=None)
    sp_request_status.add_argument("-p", "--profile", default=None,
                                   help="Connection profile")
    sp_request_status.add_argument("--env", default=None,
                                   help="Explicit .env file path (highest priority)")
    sp_request_status.add_argument("--timeout", type=_positive_finite_timeout, default=10.0,
                                   help="Ledger read timeout in seconds")

    sp_deployment_status = subparsers.add_parser(
        "deployment-status",
        help="Compare packaged, staged, and running daemon identities",
    )
    sp_deployment_status.add_argument("-p", "--profile", default=None,
                                      help="Connection profile")
    sp_deployment_status.add_argument("--env", default=None,
                                      help="Explicit .env file path (highest priority)")
    sp_deployment_status.add_argument("--timeout", type=_positive_finite_timeout, default=10.0,
                                      help="Status read timeout in seconds")

    for name, help_text in [
        ("request-await", "Wait for a terminal daemon-ledger request state"),
        ("request-reconcile", "Classify a terminal request state without replaying it"),
    ]:
        sp_wait = subparsers.add_parser(name, help=help_text)
        sp_wait.add_argument("request_id")
        sp_wait.add_argument("-p", "--profile", default=None,
                             help="Connection profile")
        sp_wait.add_argument("--env", default=None,
                             help="Explicit .env file path (highest priority)")
        sp_wait.add_argument("--timeout", type=_positive_finite_timeout, default=60.0,
                             help="Absolute ledger wait budget in seconds")
        sp_wait.add_argument("--poll-interval", type=_positive_finite_timeout, default=1.0,
                             help="Ledger poll interval in seconds")

        if name == "request-reconcile":
            sp_wait.add_argument("--expected-request-digest-sha256")
            sp_wait.add_argument(
                "--expected-operation-class",
                choices=("unknown", "read_only", "mutating"),
            )
            sp_wait.add_argument("--expected-daemon-epoch")
            sp_wait.add_argument("--expected-daemon-build-sha256")
            sp_wait.add_argument("--expected-request-generation")
            sp_wait.add_argument(
                "--expected-protocol-version",
                type=int,
            )
    sp_profile = subparsers.add_parser("profile", help="Show or edit profile bindings")
    profile_sub = sp_profile.add_subparsers(dest="profile_action", required=True)
    sp_profile_show = profile_sub.add_parser("show", help="Show resolved profile")
    sp_profile_show.add_argument("--env", default=None,
                                 help="Explicit .env file path (highest priority)")
    sp_profile_bind = profile_sub.add_parser("bind", help="Bind current virtualenv to a profile")
    sp_profile_bind.add_argument("profile", help="Profile name to bind")
    sp_profile_bind.add_argument("--venv", action="store_true",
                                 help="Bind the current virtualenv (the only supported scope)")
    sp_profile_bind.add_argument("--env", default=None,
                                 help="Explicit .env file path (highest priority)")
    sp_profile_clear = profile_sub.add_parser("clear", help="Clear current virtualenv profile binding")
    sp_profile_clear.add_argument("--venv", action="store_true",
                                  help="Clear the current virtualenv binding (the only supported scope)")
    sp_profile_clear.add_argument("--env", default=None,
                                  help="Explicit .env file path (highest priority)")

    sp_load = subparsers.add_parser(
        "load",
        help="Execute a SKILL .il file in the running Virtuoso session",
        description=(
            "Equivalent to typing `load(\"<file>\")` in the CIW.  SKILL\n"
            "reads the original file, so any error keeps the original\n"
            "file path + line number (no temp-wrapper pollution).  In\n"
            "SSH mode the file is uploaded automatically.\n\n"
            "Output: full VirtuosoResult as JSON on stdout (status,\n"
            "output, errors, warnings, execution_time, metadata).\n\n"
            "VSCode .vscode/tasks.json snippet:\n"
            '  { "label": "Load SKILL", "type": "shell",\n'
            '    "command": "virtuoso-bridge load \\"${file}\\"" }'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp_load.add_argument("file", help="Path to the .il file to execute")
    sp_load.add_argument("-p", "--profile", default=None,
                         help="Connection profile (reads VB_*_<profile> env vars)")
    sp_load.add_argument("--env", default=None,
                         help="Explicit .env file path (highest priority)")
    sp_load.add_argument("--timeout", type=float, default=60,
                         help="SKILL execution timeout in seconds (default: 60)")
    sp_load.add_argument("--quiet", action="store_true",
                         help="Suppress JSON output; only the exit code is reported")

    sp_eval = subparsers.add_parser(
        "eval",
        help="Execute a SKILL expression (one-liner) in the running Virtuoso session",
        description=(
            "Run an inline SKILL expression — companion to `load` for\n"
            "one-liners and round-trip checks.\n\n"
            "Two input modes:\n"
            "  virtuoso-bridge eval 'getCurrentTime()'\n"
            "  echo 'printf(\"hi\\n\")' | virtuoso-bridge eval --stdin\n\n"
            "--stdin sidesteps shell quoting for snippets with embedded\n"
            "quotes, parens, or quoted symbols, and is the natural way\n"
            "to feed multi-line SKILL via heredoc.\n\n"
            "Multi-statement input is supported transparently — the\n"
            "expression is wrapped in `progn(...)` before sending, and\n"
            "the value of the last form is returned.\n\n"
            "Output: full VirtuosoResult as JSON on stdout (same shape\n"
            "as `load`)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp_eval.add_argument("skill", nargs="?", default=None,
                         help="SKILL expression to evaluate (omit when using --stdin)")
    sp_eval.add_argument("--stdin", action="store_true",
                         help="Read the SKILL expression from stdin instead of argv")
    sp_eval.add_argument("-p", "--profile", default=None,
                         help="Connection profile (reads VB_*_<profile> env vars)")
    sp_eval.add_argument("--env", default=None,
                         help="Explicit .env file path (highest priority)")
    sp_eval.add_argument("--timeout", type=float, default=60,
                         help="SKILL execution timeout in seconds (default: 60)")
    sp_eval.add_argument(
        "--operation-class",
        type=OperationClass,
        choices=list(OperationClass),
        default=OperationClass.UNKNOWN,
        help="Safety classification for timeout handling (default: unknown)",
    )
    sp_eval.add_argument("--quiet", action="store_true",
                         help="Suppress JSON output; only the exit code is reported")

    sp_dismiss = subparsers.add_parser(
        "dismiss-dialog", help="Find and dismiss blocking Virtuoso GUI dialogs")
    sp_dismiss.add_argument("-p", "--profile", default=None,
                            help="Connection profile")
    sp_dismiss.add_argument("--env", default=None,
                            help="Explicit .env file path (highest priority)")

    sp_screen = subparsers.add_parser("screen", help="Capture X11 desktop without SKILL")
    sp_screen.add_argument("-o", "--output", default=None)
    sp_screen.add_argument("--display", default=None)
    sp_screen.add_argument("--window-id", default=None)
    sp_screen.add_argument("-p", "--profile", default=None)
    sp_screen.add_argument("--env", default=None)

    sp_list_windows = subparsers.add_parser(
        "list-windows", help="List Virtuoso-related X11 windows")
    sp_list_windows.add_argument("--json", action="store_true",
                                 help="Output a JSON array")
    sp_list_windows.add_argument("-p", "--profile", default=None,
                                 help="Connection profile")
    sp_list_windows.add_argument("--env", default=None,
                                 help="Explicit .env file path (highest priority)")

    sp_dismiss_window = subparsers.add_parser(
        "dismiss-window", help="Dismiss one explicit X11 window id")
    sp_dismiss_window.add_argument("window_id", help="X11 window id, e.g. 0x4203583")
    sp_dismiss_window.add_argument(
        "--action",
        default="enter",
        choices=["enter", "escape", "alt-y", "alt-n"],
        help="Key action to send (default: enter)",
    )
    sp_dismiss_window.add_argument("-p", "--profile", default=None,
                                   help="Connection profile")
    sp_dismiss_window.add_argument("--env", default=None,
                                   help="Explicit .env file path (highest priority)")

    sp_window_input = subparsers.add_parser(
        "window-input",
        help="Send an explicitly confirmed XTest pointer action to one Virtuoso child window",
    )
    sp_window_input.add_argument("window_id", help="Child id reported by list-windows")
    sp_window_input.add_argument("--expect-title", required=True,
                                 help="Required substring of the currently discovered child title")
    sp_window_input.add_argument("--action", required=True, choices=["move", "click", "drag"],
                                 help="Pointer action to perform")
    sp_window_input.add_argument("--x", required=True, type=int,
                                 help="Relative X coordinate inside the target window")
    sp_window_input.add_argument("--y", required=True, type=int,
                                 help="Relative Y coordinate inside the target window")
    sp_window_input.add_argument("--to-x", type=int,
                                 help="Drag endpoint relative X coordinate (drag only)")
    sp_window_input.add_argument("--to-y", type=int,
                                 help="Drag endpoint relative Y coordinate (drag only)")
    sp_window_input.add_argument("--button", type=int, default=1, choices=[1, 2, 3],
                                 help="Pointer button for click/drag (default: 1)")
    sp_window_input.add_argument("--allow-live", action="store_true",
                                 help="Required acknowledgement for live X11 input")
    sp_window_input.add_argument("--dry-run", action="store_true",
                                 help="Validate target and coordinates without sending XTest events")
    sp_window_input.add_argument("--settle-ms", type=int, default=50,
                                 help="Delay before postcondition discovery (default: 50)")
    sp_window_input.add_argument("--hold-ms", type=int, default=0,
                                 help="Button hold time for click/drag (default: 0)")
    sp_window_input.add_argument("--drag-duration-ms", type=int, default=0,
                                 help="Total drag interpolation time (default: 0)")
    sp_window_input.add_argument("--drag-steps", type=int, default=1,
                                 help="Number of interpolated drag steps (default: 1)")
    sp_window_input.add_argument(
        "--postcondition",
        choices=["none", "still-mapped", "unmapped", "same-fingerprint", "title-contains"],
        default="none",
        help="Verified state required after the input action",
    )
    sp_window_input.add_argument(
        "--post-expect-title",
        default=None,
        help="Required title substring for the title-contains postcondition",
    )
    sp_window_input.add_argument("-p", "--profile", default=None, help="Connection profile")
    sp_window_input.add_argument("--env", default=None,
                                 help="Explicit .env file path (highest priority)")

    sp_screenshot = subparsers.add_parser(
        "screenshot", help="Take a screenshot of a Virtuoso window")
    sp_screenshot.add_argument(
        "target", nargs="?", default="ciw",
        help="ciw (default), current, a view name (schematic/layout/maestro), or window number")
    sp_screenshot.add_argument("-o", "--output", default=None,
                               help="Output file or directory (default: user artifact screenshots dir)")
    sp_screenshot.add_argument("-p", "--profile", default=None,
                               help="Connection profile")
    sp_screenshot.add_argument("--env", default=None,
                               help="Explicit .env file path (highest priority)")

    sp_skill_find = subparsers.add_parser(
        "skill-find",
        help="Search SKILL API documentation from Cadence .fnd files",
        description=(
            "Queries the Cadence SKILL Finder database (``doc/finder/SKILL/*.fnd``)"
            " on the remote server.  On first run the database is downloaded to the\n"
            "user cache directory under ``skill_finder/<host>``;\n"
            "subsequent runs use the cache without additional network traffic.\n\n"
            "Search modes:\n"
            "  fuzzy   case-insensitive substring match (default)\n"
            "  prefix  name starts with query\n"
            "  suffix  name ends with query\n"
            "  exact   exact name match\n"
            "  regex   Python regular expression match\n\n"
            "Examples:\n"
            "  virtuoso-bridge skill-find dbOpen\n"
            '  virtuoso-bridge skill-find dbOpen --mode prefix\n'
            '  virtuoso-bridge skill-find "^db.*" --mode regex\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp_skill_find.add_argument("query", nargs="?", default=None,
                          help="Search string or pattern (required unless --json is set)")
    sp_skill_find.add_argument("-m", "--mode", default="fuzzy",
                          choices=["fuzzy", "prefix", "suffix", "exact", "regex"],
                          help="Search mode (default: fuzzy)")
    sp_skill_find.add_argument("-n", "--limit", type=int, default=50,
                          help="Maximum results to return (default: 50)")
    sp_skill_find.add_argument("--include-desc", action="store_true",
                          help="Also search in the description field")
    sp_skill_find.add_argument("--json", action="store_true",
                          help="Output results as JSON")
    sp_skill_find.add_argument("-p", "--profile", default=None,
                          help="Connection profile")
    sp_skill_find.add_argument("--env", default=None,
                          help="Explicit .env file path (highest priority)")

    sp_skill_info = subparsers.add_parser(
        "skill-info",
        help="Get More Info documentation for a SKILL function",
        description=(
            "Retrieves the More Info documentation for a specific SKILL function.\n"
            "The More Info system provides detailed HTML documentation for Cadence\n"
            "SKILL functions, indexed in ``doc/api_more_info/api_more_info.tgf``."
        ),
    )
    sp_skill_info.add_argument("func_name", help="SKILL function name to look up")
    sp_skill_info.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    sp_skill_info.add_argument("-p", "--profile", default=None, help="Connection profile")
    sp_skill_info.add_argument("--env", default=None, help="Explicit .env file path (highest priority)")

    sp_doc_search = subparsers.add_parser(
        "doc-search",
        help="Search installed Cadence documentation",
        description=(
            "Searches Cadence documentation roots, including HTML/text content "
            "and .tgf topic maps. Pass --doc-root for explicit local/offline "
            "search, or omit it to discover docs through the active "
            "Virtuoso Bridge profile."
        ),
    )
    sp_doc_search.add_argument("query", nargs="?", default=None, help="Search query")
    sp_doc_search.add_argument(
        "--doc-root",
        type=Path,
        action="append",
        default=[],
        help="Cadence doc root; may be repeated",
    )
    sp_doc_search.add_argument("--list-roots", action="store_true", help="Print resolved doc roots and exit")
    sp_doc_search.add_argument("-n", "--limit", type=int, default=10, help="Maximum results to return")
    sp_doc_search.add_argument("--json", action="store_true", help="Output results as JSON")
    sp_doc_search.add_argument("--rebuild-index", action="store_true", help="Force rebuilding the local documentation search index")
    sp_doc_search.add_argument("-p", "--profile", default=None, help="Connection profile")
    sp_doc_search.add_argument("--env", default=None, help="Explicit .env file path (highest priority)")

    sp_windows = subparsers.add_parser("windows", help="List all open Virtuoso windows")
    sp_windows.add_argument("-p", "--profile", default=None,
                            help="Connection profile")
    sp_windows.add_argument("--env", default=None,
                            help="Explicit .env file path (highest priority)")

    sp_snap = subparsers.add_parser(
        "snapshot",
        help="Brief summary of the focused Virtuoso window "
             "(maestro/schematic/...).  -o ROOT for full disk dump; "
             "--json for full in-memory JSON.")
    sp_snap.add_argument("-o", "--output-root", default=None,
                         help="Full snapshot to disk under this dir "
                              "(slow: includes latest history log + spectre.out tail). "
                              "Without -o, prints a brief summary to stdout.")
    sp_snap.add_argument("--json", action="store_true",
                         help="Print full snapshot dict as JSON to stdout (overrides default brief)")
    sp_snap.add_argument("--history", default=None,
                         help="Pin to a specific maestro history (e.g. Interactive.160). "
                              "Skips the mtime/current-history auto-pick. "
                              "Only meaningful with -o.")
    sp_snap.add_argument("-p", "--profile", default=None,
                         help="Connection profile")
    sp_snap.add_argument("--env", default=None,
                         help="Explicit .env file path (highest priority)")

    sp_visio = subparsers.add_parser(
        "export-visio",
        help="Export a schematic to Microsoft Visio (Windows + pywin32)")
    sp_visio.add_argument("lib", nargs="?", default=None,
                          help="Virtuoso library name")
    sp_visio.add_argument("cell", nargs="?", default=None,
                          help="Virtuoso cell name")
    sp_visio.add_argument("-o", "--output", default=None,
                          help="Output .vsdx/.vsd file path")
    sp_visio.add_argument("--stencil", default=None,
                          help="Visio stencil (.vss/.vssx); defaults to circuit.vss")
    sp_visio.add_argument("--scale", type=float, default=1.0,
                          help="Scale factor applied to Virtuoso coordinates")
    sp_visio.add_argument("--exclude-net", dest="exclude_nets",
                          action="append", default=[],
                          help="Net name to skip while routing (repeatable)")
    sp_visio.add_argument("--exclude-pin", dest="exclude_pins",
                          action="append", default=["B"],
                          help="Pin name to skip while routing (default: B; repeatable)")
    sp_visio.add_argument("--include-body-pins", action="store_true",
                          help="Do not skip MOS body pins")
    sp_visio.add_argument("--hidden", action="store_true",
                          help="Run Visio hidden while exporting")
    sp_visio.add_argument("-p", "--profile", default=None,
                          help="Connection profile")
    sp_visio.add_argument("--env", default=None,
                          help="Explicit .env file path (highest priority)")

    return parser


def _make_stdio_safe() -> None:
    # Window/cell names may contain non-ASCII chars (e.g. '®' in Cadence
    # titles). On hosts whose locale is GBK / cp1252 / etc., the default
    # stdout encoding cannot represent them and print() raises
    # UnicodeEncodeError. Force UTF-8 (every modern terminal renders it
    # regardless of LANG) and keep errors='replace' as a last-resort
    # safety net.
    import sys
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    _make_stdio_safe()
    parser = build_parser()
    args = parser.parse_args(argv)
    _CLI_PROFILE[0] = None
    set_runtime_env_file(getattr(args, "env", None))
    if getattr(args, "bind_venv", False):
        profile_arg = getattr(args, "profile", None)
        if not profile_arg:
            parser.error("--bind-venv requires -p/--profile")
        from virtuoso_bridge.profile import bind_venv_profile
        try:
            bind_venv_profile(profile_arg)
        except Exception as exc:
            parser.error(str(exc))
    from virtuoso_bridge.profile import resolve_profile
    profile = resolve_profile(getattr(args, "profile", None))
    if profile is not None:
        _CLI_PROFILE[0] = profile
    _CLI_ALLOW_REMOTE_BIND[0] = getattr(args, "allow_remote_bind", None)
    dispatch = {
        "init": lambda: cli_init(
            remote=getattr(args, "remote", None),
            jump=getattr(args, "jump", None),
            force=getattr(args, "force", False),
        ),
        "profile": lambda: cli_profile(
            action=getattr(args, "profile_action"),
            profile=getattr(args, "profile", None),
        ),
        "start": cli_start,
        "stop": cli_stop,
        "restart": lambda: cli_restart(timeout=getattr(args, "timeout", 30.0)),
        "autoload": lambda: cli_autoload(
            action=getattr(args, "action"),
            timeout=getattr(args, "timeout", 10.0),
        ),
        "status": cli_status,
        "request-status": lambda: cli_request_status(
            request_id=getattr(args, "request_id", None),
            timeout=getattr(args, "timeout", 10.0),
        ),
        "deployment-status": lambda: cli_deployment_status(
            timeout=getattr(args, "timeout", 10.0),
        ),
        "request-await": lambda: cli_request_await(
            request_id=getattr(args, "request_id"),
            timeout=getattr(args, "timeout", 60.0),
            poll_interval=getattr(args, "poll_interval", 1.0),
        ),
        "request-reconcile": lambda: cli_request_await(
            request_id=getattr(args, "request_id"),
            timeout=getattr(args, "timeout", 60.0),
            poll_interval=getattr(args, "poll_interval", 1.0),
            require_terminal_proof=True,
            expected_request_digest_sha256=getattr(args, "expected_request_digest_sha256"),
            expected_operation_class=getattr(args, "expected_operation_class"),
            expected_daemon_epoch=getattr(args, "expected_daemon_epoch"),
            expected_daemon_build_sha256=getattr(args, "expected_daemon_build_sha256"),
            expected_request_generation=getattr(args, "expected_request_generation"),
            expected_protocol_version=getattr(args, "expected_protocol_version"),
        ),
        "license": cli_license,
        "load": lambda: cli_load(
            file=getattr(args, "file"),
            timeout=getattr(args, "timeout", 60),
            quiet=getattr(args, "quiet", False),
        ),
        "eval": lambda: cli_eval(
            skill=getattr(args, "skill", None),
            stdin=getattr(args, "stdin", False),
            timeout=getattr(args, "timeout", 60),
            quiet=getattr(args, "quiet", False),
            operation_class=getattr(args, "operation_class", OperationClass.UNKNOWN),
        ),
        "screen": lambda: cli_screen(getattr(args, "output", None), getattr(args, "display", None), getattr(args, "window_id", None)),
        "dismiss-dialog": cli_dismiss_dialog,
        "list-windows": lambda: cli_list_windows(
            json_output=getattr(args, "json", False),
        ),
        "dismiss-window": lambda: cli_dismiss_window(
            window_id=getattr(args, "window_id"),
            action=getattr(args, "action", "enter"),
        ),
        "window-input": lambda: cli_window_input(
            window_id=getattr(args, "window_id"),
            expect_title=getattr(args, "expect_title"),
            action=getattr(args, "action"),
            x=getattr(args, "x"),
            y=getattr(args, "y"),
            button=getattr(args, "button", 1),
            to_x=getattr(args, "to_x", None),
            to_y=getattr(args, "to_y", None),
            allow_live=getattr(args, "allow_live", False),
            dry_run=getattr(args, "dry_run", False),
            settle_ms=getattr(args, "settle_ms", 50),
            hold_ms=getattr(args, "hold_ms", 0),
            drag_duration_ms=getattr(args, "drag_duration_ms", 0),
            drag_steps=getattr(args, "drag_steps", 1),
            postcondition=getattr(args, "postcondition", "none"),
            post_expect_title=getattr(args, "post_expect_title", None),
        ),
        "screenshot": cli_screenshot,
        "windows": cli_windows,
        "snapshot": cli_snapshot,
        "export-visio": cli_export_visio,
        "skill-find": lambda: cli_find(
            query=getattr(args, "query", None),
            mode=getattr(args, "mode", "fuzzy"),
            limit=getattr(args, "limit", 50),
            include_desc=getattr(args, "include_desc", False),
            json_output=getattr(args, "json", False),
        ),
        "skill-info": lambda: cli_skill_info(
            func_name=getattr(args, "func_name", None) or "",
            json_output=getattr(args, "json", False),
        ),
        "doc-search": lambda: cli_doc_search(
            query=getattr(args, "query", None),
            doc_roots=getattr(args, "doc_root", []),
            limit=getattr(args, "limit", 10),
            list_roots=getattr(args, "list_roots", False),
            json_output=getattr(args, "json", False),
            rebuild_index=getattr(args, "rebuild_index", False),
        ),
    }
    screenshot_target = getattr(args, "target", None)
    if screenshot_target is not None:
        _SCREENSHOT_TARGET[0] = screenshot_target
    screenshot_output = getattr(args, "output", None)
    if screenshot_output is not None:
        _SCREENSHOT_OUTPUT[0] = screenshot_output
    if args.command == "snapshot":
        for k in _SNAPSHOT_OPTS:
            v = getattr(args, k, None)
            if v is not None:
                _SNAPSHOT_OPTS[k] = v
    if args.command == "export-visio":
        for k in _EXPORT_VISIO_OPTS:
            v = getattr(args, k, None)
            if v is not None:
                _EXPORT_VISIO_OPTS[k] = v
    handler = dispatch[args.command]
    if not getattr(args, "json_envelope", False):
        return handler()

    started = datetime.now(timezone.utc)
    stdout = io.StringIO()
    stderr = io.StringIO()
    caught: Exception | None = None
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            exit_code = int(handler() or 0)
        except Exception as exc:
            caught = exc
            exit_code = 1
    ended = datetime.now(timezone.utc)
    stdout_text = stdout.getvalue().strip()
    stderr_text = stderr.getvalue().strip()
    parsed: object | None = None
    if stdout_text:
        try:
            parsed = json.loads(stdout_text)
        except json.JSONDecodeError:
            parsed = None
    error_items: list[str] = []
    if caught is not None:
        error_items.append(str(caught))
    if exit_code and stderr_text:
        error_items.append(stderr_text)
    data: object = parsed if parsed is not None else {"stdout": stdout_text}
    request_id = None
    if isinstance(parsed, dict):
        request_id = parsed.get("request_id")
        if request_id is None and isinstance(parsed.get("request"), dict):
            request_id = parsed["request"].get("request_id")
    status = "success" if exit_code == 0 else "error"
    envelope = {
        "schema_version": 1,
        "command": args.command,
        "profile": _get_cli_profile(),
        "ok": exit_code == 0,
        "status": status,
        "exit_code": exit_code,
        "request_id": request_id,
        "started_utc": started.isoformat(),
        "ended_utc": ended.isoformat(),
        "data": data,
        "errors": error_items,
        "warnings": [stderr_text] if stderr_text and not exit_code else [],
        "evidence": [],
    }
    print(json.dumps(envelope, ensure_ascii=False, default=str))
    return exit_code


# Global profile for CLI commands (avoids changing all function signatures)
_CLI_PROFILE: list[str | None] = [None]
_CLI_ALLOW_REMOTE_BIND: list[bool | None] = [None]
_SCREENSHOT_OUTPUT: list[str | None] = [None]


def _get_cli_profile() -> str | None:
    return _CLI_PROFILE[0]
