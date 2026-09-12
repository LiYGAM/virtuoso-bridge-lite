"""SSHClient — SSH tunnel + remote RAMIC daemon deployment.

Manages the SSH port-forward tunnel and remote file deployment independently
from the SKILL execution client (VirtuosoClient). VirtuosoClient only needs a
localhost:port TCP endpoint; SSHClient makes that endpoint available.
"""

from __future__ import annotations

import importlib.resources
import base64
from contextlib import contextmanager
import hashlib
import json
import logging
import math
import os
import posixpath
import re
import secrets
import shlex
import shutil
import socket
import stat
import sys
import tempfile
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
from virtuoso_bridge.transport.remote_roles import remote_host_roles_from_os
from virtuoso_bridge.transport.ssh import (
    CommandResult,
    SSHRunner,
    _TimeoutBudget,
    _process_is_alive,
    ssh_backend_env_from_os,
    ssh_proxy_url_from_os,
)

logger = logging.getLogger(__name__)


def _strict_json_loads(raw: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    payload = json.loads(raw, parse_constant=reject_constant)

    def validate(value: Any) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("non-string JSON key")
                validate(item)
        elif isinstance(value, list):
            for item in value:
                validate(item)

    validate(payload)
    return payload

_TUNNEL_STARTUP_SETTLE_SECONDS = 1.0

# ``.cdsinit`` is user-authored configuration.  Keep the bridge's managed
# fragment deliberately small and identify it by both profile and a stable
# digest so two profiles cannot accidentally remove one another's block.
_AUTOLOAD_START_PREFIX = "; >>> virtuoso-bridge autoload profile "
_AUTOLOAD_END_PREFIX = "; <<< virtuoso-bridge autoload profile "
_AUTOLOAD_LEGACY_PREFIX = "; Auto-load virtuoso-bridge-lite profile "


def _autoload_profile_label(profile: str | None) -> str:
    return profile or "default"


def _autoload_profile_key(profile: str | None) -> str:
    label = _autoload_profile_label(profile)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", label).strip("._-") or "default"
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:48]}-{digest}"


def _autoload_markers(profile: str | None) -> tuple[str, str]:
    key = _autoload_profile_key(profile)
    return (
        f"{_AUTOLOAD_START_PREFIX}{key} >>>",
        f"{_AUTOLOAD_END_PREFIX}{key} <<<",
    )


def _skill_path(path: str | os.PathLike[str]) -> str:
    """Render a filesystem path as a SKILL string literal payload."""
    return str(path).replace("\\", "/").replace('"', '\\"')


def _autoload_when_line(setup_path: str | os.PathLike[str]) -> str:
    rendered = _skill_path(setup_path)
    return f'when(isFile("{rendered}") load("{rendered}"))'


def _autoload_legacy_marker(profile: str | None) -> str:
    return f"{_AUTOLOAD_LEGACY_PREFIX}{_autoload_profile_label(profile)}"


def _line_without_ending(line: str) -> str:
    return line.rstrip("\r\n")


def _line_ending_for(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _find_autoload_ranges(
    text: str,
    profile: str | None,
    *,
    expected_setup_path: str | os.PathLike[str] | None = None,
    include_legacy: bool = False,
) -> dict[str, Any]:
    """Inspect/remove-ready ranges without normalizing unrelated text.

    The returned line ranges are half-open indexes into ``splitlines``.  A
    malformed/incomplete managed marker is intentionally left untouched; a
    user may have written it while editing the file and deleting arbitrary
    text after it would be unsafe.
    """
    lines = text.splitlines(keepends=True)
    start, end = _autoload_markers(profile)
    managed: list[tuple[int, int]] = []
    managed_exact = 0
    for index, line in enumerate(lines):
        if _line_without_ending(line) != start:
            continue
        close = None
        for candidate in range(index + 1, len(lines)):
            candidate_line = _line_without_ending(lines[candidate])
            if candidate_line == start:
                # Do not let an incomplete marker consume user text or a
                # later complete managed block.
                break
            if candidate_line == end:
                close = candidate
                break
        if close is None:
            continue
        managed.append((index, close + 1))
        if expected_setup_path is not None:
            expected = (
                start,
                _autoload_when_line(expected_setup_path),
                end,
            )
            actual = tuple(_line_without_ending(item) for item in lines[index : close + 1])
            if actual == expected:
                managed_exact += 1

    legacy: list[tuple[int, int]] = []
    legacy_exact = 0
    if include_legacy and expected_setup_path is not None:
        legacy_marker = _autoload_legacy_marker(profile)
        legacy_when = _autoload_when_line(expected_setup_path)
        expected_path = _skill_path(expected_setup_path)
        legacy_when_open = f'when(isFile("{expected_path}")'
        legacy_load = re.compile(rf'^\s*load\("{re.escape(expected_path)}"\)\s*$')
        for index, line in enumerate(lines[:-1]):
            if _line_without_ending(line) != legacy_marker:
                continue
            if _line_without_ending(lines[index + 1]) == legacy_when:
                legacy.append((index, index + 2))
                legacy_exact += 1
                continue
            if index + 3 < len(lines):
                if (
                    _line_without_ending(lines[index + 1]) == legacy_when_open
                    and legacy_load.match(_line_without_ending(lines[index + 2]))
                    and _line_without_ending(lines[index + 3]) == ")"
                ):
                    legacy.append((index, index + 4))
                    legacy_exact += 1

    return {
        "lines": lines,
        "managed_ranges": managed,
        "managed_count": len(managed),
        "managed_exact_count": managed_exact,
        "legacy_ranges": legacy,
        "legacy_count": len(legacy),
        "legacy_exact_count": legacy_exact,
    }


def _remove_autoload_ranges(
    text: str,
    profile: str | None,
    *,
    expected_setup_path: str | os.PathLike[str] | None = None,
    include_legacy: bool = False,
) -> tuple[str, dict[str, Any]]:
    inspection = _find_autoload_ranges(
        text,
        profile,
        expected_setup_path=expected_setup_path,
        include_legacy=include_legacy,
    )
    ranges = list(inspection["managed_ranges"])
    if include_legacy:
        ranges.extend(inspection["legacy_ranges"])
    if ranges:
        remove_indexes = {
            index
            for first, last in ranges
            for index in range(first, last)
        }
        lines = inspection["lines"]
        text = "".join(line for index, line in enumerate(lines) if index not in remove_indexes)
    return text, inspection


def _autoload_block(
    profile: str | None,
    setup_path: str | os.PathLike[str],
    *,
    line_ending: str = "\n",
) -> str:
    start, end = _autoload_markers(profile)
    return line_ending.join((start, _autoload_when_line(setup_path), end)) + line_ending


def _autoload_render_install(
    text: str,
    profile: str | None,
    setup_path: str | os.PathLike[str],
) -> tuple[str, dict[str, Any]]:
    line_ending = _line_ending_for(text)
    cleaned, inspection = _remove_autoload_ranges(
        text,
        profile,
        expected_setup_path=setup_path,
        include_legacy=True,
    )
    if cleaned and not cleaned.endswith(("\n", "\r")):
        cleaned += line_ending
    rendered = cleaned + _autoload_block(profile, setup_path, line_ending=line_ending)
    return rendered, inspection


def _autoload_render_uninstall(
    text: str,
    profile: str | None,
) -> tuple[str, dict[str, Any]]:
    return _remove_autoload_ranges(text, profile)


def _owner_identity_is_safe(path: Path) -> bool:
    if path.is_symlink():
        return False
    try:
        stat_result = path.stat()
    except OSError:
        return False
    if hasattr(os, "getuid"):
        try:
            return stat_result.st_uid == os.getuid()
        except (AttributeError, OSError):
            return False
    return True


def _local_cdsinit_path(profile: str | None = None) -> Path:
    suffix = f"_{profile}" if profile else ""
    configured = os.getenv(f"VB_CDSINIT_PATH{suffix}", "").strip()
    if not configured:
        configured = os.getenv("VB_CDSINIT_PATH", "").strip()
    if configured:
        return Path(os.path.expandvars(os.path.expanduser(configured)))
    return Path.home() / ".cdsinit"


def _next_backup_path(path: Path, profile: str | None = None) -> Path:
    stamp = time.time_ns()
    stem = f"{path.name}.virtuoso-bridge.{_autoload_profile_key(profile)}.{stamp}"
    candidate = path.with_name(stem + ".bak")
    suffix = 0
    while candidate.exists() or candidate.is_symlink():
        suffix += 1
        candidate = path.with_name(f"{stem}.{suffix}.bak")
    return candidate


def _copy_private_backup(source: Path, backup: Path) -> None:
    """Copy *source* to a new private, non-following backup path."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(backup, flags, 0o600)
    try:
        with source.open("rb") as source_handle, os.fdopen(fd, "wb") as backup_handle:
            fd = -1
            shutil.copyfileobj(source_handle, backup_handle)
            backup_handle.flush()
            os.fsync(backup_handle.fileno())
        try:
            backup.chmod(0o600)
        except OSError:
            pass
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            backup.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    expected_current: bytes | None = None,
    expected_exists: bool | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        if expected_exists is True:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"Refusing changed .cdsinit target: {path}")
            try:
                current = path.read_bytes()
            except OSError as exc:
                raise RuntimeError(
                    f"Unable to re-read .cdsinit before replacement: {path}"
                ) from exc
            if expected_current is None or current != expected_current:
                raise RuntimeError(
                    f"Refusing concurrent .cdsinit change before replacement: {path}"
                )
        elif expected_exists is False and (path.exists() or path.is_symlink()):
            raise RuntimeError(
                f"Refusing newly created .cdsinit target before replacement: {path}"
            )
        os.replace(tmp, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


@contextmanager
def _local_autoload_lock(path: Path):
    """Serialize direct-CLI .cdsinit writers without trusting wrapper locks."""
    lock_path = path.with_name(f"{path.name}.virtuoso-bridge.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError(f"Unable to open .cdsinit mutation lock: {lock_path}") from exc
    locked = False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"Unsafe .cdsinit mutation lock: {lock_path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise RuntimeError(f"Non-owned .cdsinit mutation lock: {lock_path}")
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        if os.name == "nt":
            import msvcrt

            if metadata.st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(
                    f"Another .cdsinit mutation is already running: {path}"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError(
                    f"Another .cdsinit mutation is already running: {path}"
                ) from exc
        locked = True
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _local_autoload_snapshot(
    profile: str | None,
    expected_setup_path: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    path = _local_cdsinit_path(profile)
    exists = path.exists() or path.is_symlink()
    symlink = path.is_symlink()
    owned = False
    mode: int | None = None
    text = ""
    error: str | None = None
    if exists:
        try:
            stat_result = path.lstat()
            mode = stat_result.st_mode & 0o777
            owned = not symlink and _owner_identity_is_safe(path)
            if not symlink and path.is_file():
                text = path.read_bytes().decode("utf-8")
            elif not symlink:
                error = "target is not a regular file"
        except (OSError, UnicodeError) as exc:
            error = str(exc)
    expected = str(expected_setup_path) if expected_setup_path else None
    expected_exists = bool(expected and Path(expected).is_file()) if expected else None
    inspection = _find_autoload_ranges(
        text,
        profile,
        expected_setup_path=expected_setup_path,
        include_legacy=True,
    )
    exact = (
        inspection["managed_count"] == 1
        and inspection["managed_exact_count"] == 1
        and inspection["legacy_count"] == 0
    )
    return {
        "path": str(path),
        "target_exists": exists,
        "target_is_symlink": symlink,
        "target_owned": owned if exists else True,
        "mode": mode,
        "mode_octal": f"{mode:04o}" if mode is not None else None,
        # Windows ACLs do not map reliably to POSIX mode bits; ownership and
        # symlink safety remain meaningful, while the result is explicitly
        # marked best-effort through ``permission_safety`` below.
        "permission_safe": (not exists) or (
            owned and (mode == 0o600 or os.name == "nt")
        ),
        "permission_safety": (
            "best-effort-windows" if os.name == "nt" else "0600-required"
        ),
        "installed": exact,
        "exact_match": exact,
        "duplicate_block_count": inspection["managed_count"],
        "legacy_exact_match": bool(inspection["legacy_exact_count"]),
        "legacy_block_count": inspection["legacy_count"],
        "expected_setup_path": expected,
        "expected_setup_exists": expected_exists,
        "error": error,
        "_text": text,
    }


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


def _read_auth_token_file(path: Path) -> str:
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink Bridge auth token file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"Unable to read Bridge auth token file: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"Bridge auth token path is not a regular file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise RuntimeError(f"Bridge auth token file is not owned by this user: {path}")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            value = handle.read().strip()
    finally:
        if fd >= 0:
            os.close(fd)
    if not value:
        raise RuntimeError(f"Bridge auth token file is empty: {path}")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


def resolve_auth_token(profile: str | None = None, *, create: bool = False) -> str:
    """Resolve the per-profile daemon token without exposing it in evidence."""
    load_vb_env()
    suffix = f"_{profile}" if profile else ""
    for key in (f"VB_AUTH_TOKEN{suffix}", "VB_AUTH_TOKEN"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    path = _auth_token_file(profile)
    if path.exists() or path.is_symlink():
        return _read_auth_token_file(path)
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
        return _read_auth_token_file(path)
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



def _parse_daemon_identity(text: str) -> dict[str, str]:
    identity: dict[str, str] = {}
    allowed = {"host", "ip", "pid", "bind", "epoch", "profile",
               "deployment_id", "il_sha256", "identity_complete"}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in allowed:
            if key in identity:
                return {}
            identity[key] = value.strip()
    # Keep legacy host diagnostics, but incomplete files cannot prove a load.
    if not text.endswith("identity_complete=1\n"):
        identity.pop("identity_complete", None)
    return identity


def _generate_virtuoso_setup_il(
    daemon_path: str,
    il_path: str,
    python_cmd: str = "python",
    port: int = 65432,
    identity_path: str | None = None,
    *,
    auth_token_path: str = "",
    request_state_path: str = "",
    allow_remote_bind: bool = False,
    profile: str | None = None,
    deployment_id: str = "",
    il_sha256: str = "",
) -> str:
    identity_line = (
        f'setShellEnvVar("RB_IDENTITY_PATH" "{identity_path}")\n'
        if identity_path
        else ""
    )
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
        f'setShellEnvVar("RB_DEPLOYMENT_ID" "{deployment_id}")\n'
        f'setShellEnvVar("RB_IL_SHA256" "{il_sha256}")\n'
        f'setShellEnvVar("RB_LOCAL_ONLY" "{"nil" if allow_remote_bind else "t"}")\n'
        f'setShellEnvVar("RB_BIND_HOST" "{"0.0.0.0" if allow_remote_bind else "127.0.0.1"}")\n'
        f"{identity_line}"
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


def _profile_identity_matches(
    saved: dict[str, Any],
    *,
    remote_host: str,
    remote_user: str | None,
    remote_port: int,
    jump_host: str | None,
    jump_user: str | None,
    allow_remote_bind: bool,
    host_roles: dict[str, str] | None = None,
) -> bool:
    expected = {
        "remote_host": remote_host,
        "remote_user": remote_user,
        "remote_port": remote_port,
        "jump_host": jump_host,
        "jump_user": jump_user,
        "allow_remote_bind": allow_remote_bind,
    }
    if not all(key in saved and saved.get(key) == value for key, value in expected.items()):
        return False
    # Missing roles in legacy state retain the original one-host meaning.
    return all(saved.get(key, saved.get("remote_host")) == value
               for key, value in (host_roles or {}).items())


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
        ssh_backend: str | None = None,
        ssh_max_sessions: int | None = None,
        ssh_proxy_url: str | None = None,
        daemon_host: str | None = None,
        deploy_host: str | None = None,
        gui_host: str | None = None,
        spectre_host: str | None = None,
    ) -> None:
        self._daemon_host = daemon_host or remote_host
        self._gui_host = gui_host or remote_host
        self._deploy_host = deploy_host or self._gui_host
        self._spectre_host = spectre_host or remote_host
        # Compatibility: remote_host has historically meant the tunnel target.
        self._remote_host = self._daemon_host
        self._remote_user = remote_user
        self._port = port  # remote daemon port
        self._local_port = local_port if local_port is not None else port
        self._jump_host = jump_host
        self._jump_user = jump_user
        self._timeout = timeout
        self._keep_remote_files = keep_remote_files
        self._profile = profile
        self._auth_token = (
            auth_token if auth_token is not None else secrets.token_urlsafe(32)
        )
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

        self._runner_kwargs = {
            "jump_user": jump_user,
            "backend": ssh_backend,
            "max_sessions": ssh_max_sessions,
            "proxy_url": ssh_proxy_url,
            "verbose": True,
        }
        self._role_runners: dict[str, SSHRunner] = {}

        if _is_localhost(self._daemon_host):
            self._ssh_runner = None
        else:
            self._ssh_runner = self._new_role_runner(
                self._daemon_host,
                role="daemon",
                user=remote_user,
            )

        if _is_localhost(self._deploy_host):
            self._deployment_runner = None
        elif self._deploy_host == self._daemon_host:
            self._deployment_runner = self._ssh_runner
        else:
            self._deployment_runner = self._new_role_runner(
                self._deploy_host,
                role="deploy",
                user=remote_user,
            )

        self._remote_setup_done = False
        self._remote_work_dir: str | None = None
        self._remote_virtuoso_setup_path: str | None = None
        self._remote_identity_path: str | None = None
        self._daemon_endpoint_hostname: str | None = None

    def _new_role_runner(
        self,
        host: str,
        *,
        role: str,
        user: str | None = None,
    ) -> SSHRunner:
        jump_host = self._jump_host
        if jump_host and host.strip().rstrip(".").lower() == jump_host.strip().rstrip(".").lower():
            jump_host = None
        runner = SSHRunner(
            host=host,
            user=user if user is not None else self._remote_user,
            jump_host=jump_host,
            persistent_shell=True,
            **self._runner_kwargs,
        )
        self._role_runners[role] = runner
        return runner

    def _runner_for_role(self, role: str, host: str | None) -> SSHRunner | None:
        if not host or _is_localhost(host):
            return None
        if host == self._daemon_host:
            return self._ssh_runner
        if host == self._deploy_host and self._deploy_host != self._daemon_host:
            return self._deployment_runner
        existing = self._role_runners.get(role)
        if existing is not None:
            return existing
        for runner in self._role_runners.values():
            if runner.host.strip().rstrip(".").lower() == host.strip().rstrip(".").lower():
                self._role_runners[role] = runner
                return runner
        return self._new_role_runner(host, role=role)

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

        roles = remote_host_roles_from_os(profile, load=False)
        remote_host = roles.legacy_host or roles.daemon_host
        if not remote_host or not roles.daemon_host or not roles.deploy_host:
            raise RuntimeError(
                f"No remote host is configured for profile {profile or '(default)'!r}; "
                f"set VB_REMOTE_HOST{suffix}, or set explicit VB_GUI_HOST{suffix} "
                f"and VB_DAEMON_HOST{suffix} roles"
            )

        remote_user = roles.remote_user
        jump_host = roles.jump_host
        jump_user = roles.jump_user
        backend_env = ssh_backend_env_from_os(profile)
        ssh_proxy_url = ssh_proxy_url_from_os(profile)

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

        effective_allow_remote_bind = (
            remote_bind_allowed(profile)
            if allow_remote_bind is None
            else bool(allow_remote_bind)
        )
        if local_port is None:
            # Preserve a previously auto-switched local port only when the
            # saved tunnel identity still matches every connection endpoint.
            # This avoids both needless second tunnels and host A -> host B
            # state corruption after profile edits.
            previous_state = cls.read_state(profile) or {}
            saved_config = previous_state.get("profile_config")
            if isinstance(saved_config, dict) and _profile_identity_matches(
                saved_config,
                remote_host=roles.daemon_host,
                remote_user=remote_user,
                remote_port=port,
                jump_host=jump_host,
                jump_user=jump_user,
                allow_remote_bind=effective_allow_remote_bind,
                host_roles={"gui_host": roles.gui_host, "deploy_host": roles.deploy_host,
                            "spectre_host": roles.spectre_host},
            ):
                try:
                    candidate = int(
                        saved_config.get("local_port")
                        or previous_state.get("port")
                    )
                except (TypeError, ValueError):
                    candidate = 0
                if 1 <= candidate <= 65535:
                    local_port = candidate

        return cls(
            remote_host=remote_host,
            remote_user=remote_user,
            port=port,
            local_port=local_port,
            jump_host=jump_host,
            jump_user=jump_user,
            keep_remote_files=keep_remote_files,
            profile=profile,
            auth_token=resolve_auth_token(profile, create=create_auth_token),
            allow_remote_bind=effective_allow_remote_bind,
            ssh_backend=backend_env.backend,
            ssh_max_sessions=backend_env.max_sessions,
            ssh_proxy_url=ssh_proxy_url,
            daemon_host=roles.daemon_host,
            deploy_host=roles.deploy_host,
            gui_host=roles.gui_host,
            spectre_host=roles.spectre_host,
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
    def daemon_host(self) -> str:
        return self._daemon_host

    @property
    def deploy_host(self) -> str:
        return self._deploy_host

    @property
    def gui_host(self) -> str:
        return self._gui_host

    @property
    def spectre_host(self) -> str:
        return self._spectre_host

    @property
    def ssh_runner(self) -> SSHRunner | None:
        """Runner for the daemon/tunnel endpoint (legacy property)."""
        return self._ssh_runner

    @property
    def deployment_runner(self) -> SSHRunner | None:
        """Runner used for bridge files and Virtuoso-generated artifacts."""
        if self._deploy_host == self._daemon_host:
            return self._ssh_runner
        return self._deployment_runner

    @property
    def gui_runner(self) -> SSHRunner | None:
        """Runner for X11/CIW operations."""
        return self._runner_for_role("gui", self._gui_host)

    @property
    def spectre_runner(self) -> SSHRunner | None:
        """Runner for standalone Spectre jobs."""
        return self._runner_for_role("spectre", self._spectre_host)

    def _require_runner(self) -> SSHRunner:
        runner = self._ssh_runner
        if runner is None:
            raise RuntimeError("SSH runner is unavailable in local mode")
        return runner

    def _require_deployment_runner(self) -> SSHRunner:
        runner = self.deployment_runner
        if runner is None:
            raise RuntimeError("Deployment SSH runner is unavailable in local mode")
        return runner

    def _require_gui_runner(self) -> SSHRunner:
        runner = self.gui_runner
        if runner is None:
            raise RuntimeError("GUI SSH runner is unavailable in local mode")
        return runner

    @property
    def remote_work_dir(self) -> str | None:
        return self._remote_work_dir

    @property
    def setup_path(self) -> str | None:
        return self._remote_virtuoso_setup_path

    @property
    def compat_setup_path(self) -> str | None:
        """Stable setup path intended for CIW/.cdsinit bootstrap loading."""
        return self._compat_setup_path

    @property
    def auth_token(self) -> str:
        return self._auth_token

    @property
    def request_state_path(self) -> str | None:
        return self._request_state_path

    @property
    def identity_path(self) -> str | None:
        return self._remote_identity_path

    @property
    def is_tunnel_alive(self) -> bool:
        if self._ssh_runner is None:
            return False
        return self._ssh_runner.is_tunnel_alive

    # -- remote deployment --------------------------------------------------

    def _detect_remote_python(
        self, runner: SSHRunner | None = None, *, _budget: _TimeoutBudget | None = None
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
        runner = runner or self._require_runner()
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
                f"No Python interpreter found on {self._daemon_host} (daemon host). "
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

        runner = self._require_deployment_runner()
        daemon_runner = self._require_runner()
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
        remote_identity = f"{self._remote_work_dir}/daemon_identity.txt"

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
            identity_path=remote_identity,
            deployment_id=deployment_id,
            il_sha256=il_sha256,
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

        # A split deployment only works when the generated paths are visible
        # from both the CIW and the host where ipcBeginProcess launches Python.
        visibility_checks = [
            ("daemon", daemon_runner, remote_daemon),
            ("GUI", self.gui_runner, remote_setup),
            ("daemon", daemon_runner, remote_token),
            ("GUI", self.gui_runner, remote_il),
        ]
        for label, check_runner, path in visibility_checks:
            if check_runner is None or check_runner is runner:
                continue
            visible = check_runner.run_command(
                f"test -r {shlex.quote(path)}",
                timeout=budget.remaining("verify-shared-deployment-path"),
            )
            if visible.returncode != 0:
                raise RuntimeError(
                    f"Bridge deployment path {path!r} is not readable on the {label} host. "
                    "Set VB_REMOTE_SCRATCH_ROOT to a shared home or scratch directory "
                    "visible to the deployment, GUI, and daemon hosts."
                )

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
        self._remote_identity_path = remote_identity
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
        local_identity = work_dir / "daemon_identity.txt"

        local_daemon.write_bytes(daemon_text.encode("utf-8"))

        local_il.write_bytes(il_text.encode("utf-8"))

        _atomic_write_bytes(
            local_token,
            (self._auth_token + "\n").encode("utf-8"),
        )

        setup_content = _generate_virtuoso_setup_il(
            str(local_daemon),
            str(local_il),
            python_cmd,
            port=self._port,
            identity_path=str(local_identity),
            deployment_id=deployment_id,
            il_sha256=il_sha256,
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
        self._remote_identity_path = str(local_identity)
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

    # -- .cdsinit autoload -------------------------------------------------

    def _remote_cdsinit_snapshot(
        self,
        expected_setup_path: str | os.PathLike[str] | None = None,
        *,
        timeout: float | None = None,
        retry_transport_errors: bool = True,
    ) -> dict[str, Any]:
        """Read remote ``~/.cdsinit`` and safety metadata.

        The first two records are a private framing protocol; the UTF-8 payload
        is base64 so marker-like user text is not mistaken for bridge metadata.
        This operation is
        intentionally a read-only shell command.  Mutating callers pass
        ``retry_transport_errors=False`` for the same fail-closed semantics as
        file uploads and atomic replacement.
        """
        runner = self._require_gui_runner()
        setup_literal = shlex.quote(str(expected_setup_path or ""))
        command = (
            'p="$HOME/.cdsinit"; '
            'printf "__VB_PATH__ %s\\n" "$p"; '
            'printf "__VB_UID__ %s\\n" "$(id -u)"; '
            'if [ -L "$p" ]; then printf "__VB_SYMLINK__\\n"; exit 0; fi; '
            'if [ -e "$p" ] && [ ! -f "$p" ]; then printf "__VB_UNSAFE__\\n"; exit 0; fi; '
            'if [ -e "$p" ] && [ ! -r "$p" ]; then printf "__VB_UNREADABLE__\\n"; exit 0; fi; '
            'if [ ! -e "$p" ]; then printf "__VB_MISSING__\\n"; '
            'else '
            'owner=$(stat -c %u -- "$p" 2>/dev/null || stat -f %u -- "$p" 2>/dev/null || printf "?"); '
            'mode=$(stat -c %a -- "$p" 2>/dev/null || stat -f %Lp -- "$p" 2>/dev/null || printf "?"); '
            'printf "__VB_EXISTS__ %s %s\\n" "$owner" "$mode"; '
            'if ! command -v base64 >/dev/null 2>&1; then exit 49; fi; '
            'printf "__VB_BASE64__\\n"; base64 < "$p" | tr -d "\\n"; printf "\\n"; '
            'fi; '
            f'e={setup_literal}; '
            'if [ -n "$e" ] && [ -f "$e" ]; then printf "__VB_SETUP_EXISTS__ 1\\n"; '
            'else printf "__VB_SETUP_EXISTS__ 0\\n"; fi'
        )
        result = runner.run_command(
            command,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Unable to inspect remote .cdsinit")
        output = result.stdout or ""
        first, separator, rest = output.partition("\n")
        if not separator or not first.startswith("__VB_PATH__ "):
            raise RuntimeError("Malformed remote .cdsinit inspection result")
        target_path = first[len("__VB_PATH__ ") :].strip()
        if not target_path.startswith("/"):
            raise RuntimeError("Malformed remote .cdsinit target path")
        uid_line, separator, rest = rest.partition("\n")
        if not separator or not uid_line.startswith("__VB_UID__ "):
            raise RuntimeError("Malformed remote .cdsinit uid result")
        remote_uid = uid_line[len("__VB_UID__ ") :].strip()
        if not remote_uid.isdigit():
            raise RuntimeError("Malformed remote .cdsinit uid value")
        second, separator, rest = rest.partition("\n")
        if not separator:
            raise RuntimeError("Malformed remote .cdsinit safety framing")
        status = second.strip()
        payload = ""
        owner: str | None = None
        mode: int | None = None
        setup_line = ""
        if status.startswith("__VB_EXISTS__ "):
            fields = status.split()
            if len(fields) != 3 or not fields[1].isdigit():
                raise RuntimeError("Malformed remote .cdsinit owner/mode result")
            owner = fields[1]
            try:
                mode = int(fields[2], 8)
            except ValueError as exc:
                raise RuntimeError("Malformed remote .cdsinit mode result") from exc
            framing, separator, body = rest.partition("\n")
            if not separator:
                raise RuntimeError("Malformed remote .cdsinit payload framing")
            body_without_setup, setup_separator, setup_tail = body.rpartition(
                "\n__VB_SETUP_EXISTS__ "
            )
            setup_values = setup_tail.splitlines()
            if (
                not setup_separator
                or len(setup_values) != 1
                or setup_values[0] not in {"0", "1"}
            ):
                raise RuntimeError("Malformed remote setup-exists trailer")
            setup_line = "__VB_SETUP_EXISTS__ " + setup_values[0]
            body = body_without_setup
            if framing.strip() == "__VB_BASE64__":
                try:
                    text = base64.b64decode(body.strip() or "", validate=True).decode(
                        "utf-8"
                    )
                except (ValueError, UnicodeError) as exc:
                    raise RuntimeError(f"Unable to decode remote .cdsinit: {exc}") from exc
            else:
                raise RuntimeError("Malformed remote .cdsinit payload framing")
            exists = True
        elif status == "__VB_MISSING__":
            text = ""
            exists = False
            setup_lines = rest.splitlines()
            if setup_lines not in (
                ["__VB_SETUP_EXISTS__ 0"],
                ["__VB_SETUP_EXISTS__ 1"],
            ):
                raise RuntimeError("Malformed remote setup-exists trailer")
            setup_line = setup_lines[0]
        elif status in {"__VB_SYMLINK__", "__VB_UNSAFE__", "__VB_UNREADABLE__"}:
            text = ""
            exists = True
        else:
            raise RuntimeError("Malformed remote .cdsinit safety result")
        setup_exists = setup_line.strip() == "__VB_SETUP_EXISTS__ 1"
        expected = str(expected_setup_path) if expected_setup_path else None
        inspection = _find_autoload_ranges(
            text,
            self._profile,
            expected_setup_path=expected_setup_path,
            include_legacy=True,
        )
        exact = (
            inspection["managed_count"] == 1
            and inspection["managed_exact_count"] == 1
            and inspection["legacy_count"] == 0
        )
        owner_safe = status == "__VB_MISSING__"
        permission_safe = status == "__VB_MISSING__"
        if status.startswith("__VB_EXISTS__ "):
            owner_safe = bool(
                owner
                and remote_uid
                and owner.strip() == remote_uid.strip()
                and remote_uid.strip() not in {"", "?"}
            )
            if mode is not None:
                permission_safe = mode == 0o600
            else:
                permission_safe = False
        return {
            "path": target_path,
            "target_exists": exists,
            "target_is_symlink": status == "__VB_SYMLINK__",
            "target_owned": owner_safe,
            "mode": mode,
            "mode_octal": f"{mode:04o}" if mode is not None else None,
            "permission_safe": permission_safe,
            "permission_safety": "0600-required",
            "installed": exact,
            "exact_match": exact,
            "duplicate_block_count": inspection["managed_count"],
            "legacy_exact_match": bool(inspection["legacy_exact_count"]),
            "legacy_block_count": inspection["legacy_count"],
            "expected_setup_path": expected,
            "expected_setup_exists": setup_exists if expected else None,
            "_text": text,
        }

    def _remote_autoload_mutate(
        self,
        *,
        action: str,
        expected_setup_path: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if action not in {"install", "uninstall"}:
            raise ValueError("action must be install or uninstall")
        expected = expected_setup_path or self._compat_setup_path
        if action == "install" and not expected:
            raise RuntimeError("No compatible bridge setup path is staged")
        snapshot = self._remote_cdsinit_snapshot(
            expected,
            timeout=timeout,
            retry_transport_errors=False,
        )
        if snapshot["target_is_symlink"] or (
            snapshot["target_exists"] and not snapshot["target_owned"]
        ):
            raise RuntimeError(
                "Refusing unsafe remote .cdsinit target "
                f"({snapshot['path'] or '$HOME/.cdsinit'}): symlink, non-owned, "
                "non-regular, or unreadable target"
            )
        text = str(snapshot.get("_text") or "")
        if action == "install":
            rendered, _ = _autoload_render_install(text, self._profile, str(expected))
        else:
            rendered, _ = _autoload_render_uninstall(text, self._profile)
        runner = self._require_gui_runner()
        profile_key = _autoload_profile_key(self._profile)
        nonce = f"{os.getpid()}.{time.time_ns()}"
        target_path = str(snapshot.get("path") or "")
        if not target_path.startswith("/"):
            raise RuntimeError("Remote .cdsinit inspection did not return an absolute target path")
        target_dir = posixpath.dirname(target_path) or "/"
        target_name = posixpath.basename(target_path) or ".cdsinit"
        hidden_target_name = (
            target_name if target_name.startswith(".") else f".{target_name}"
        )
        tmp_path = posixpath.join(
            target_dir,
            f"{hidden_target_name}.virtuoso-bridge.{profile_key}.{nonce}.tmp",
        )
        backup_path = posixpath.join(
            target_dir,
            f"{target_name}.virtuoso-bridge.{profile_key}.{nonce}.bak",
        )
        lock_path = target_path + ".virtuoso-bridge.lock"
        quoted_lock = shlex.quote(lock_path)
        lock_prefix = (
            'command -v flock >/dev/null 2>&1 || exit 53; '
            f'lock={quoted_lock}; umask 077; '
            'exec 9>> "$lock" || exit 53; flock -n 9 || exit 54; '
        )
        if rendered == text and (
            not snapshot["target_exists"] or snapshot.get("mode") == 0o600
        ):
            if snapshot["target_exists"]:
                expected_digest = _sha256_bytes(text.encode("utf-8"))
                noop_guard = (
                    '[ -f "$p" ] && [ ! -L "$p" ] || exit 42; '
                    'owner=$(stat -c %u -- "$p" 2>/dev/null || stat -f %u -- "$p" 2>/dev/null || printf "?"); '
                    'uid=$(id -u); [ "$owner" = "$uid" ] || exit 44; '
                    'if command -v sha256sum >/dev/null 2>&1; then '
                    'current=$(sha256sum -- "$p") || exit 47; current=${current%% *}; '
                    'elif command -v shasum >/dev/null 2>&1; then '
                    'current=$(shasum -a 256 "$p") || exit 47; current=${current%% *}; '
                    'elif command -v openssl >/dev/null 2>&1; then '
                    'current=$(openssl dgst -sha256 "$p") || exit 47; current=${current##* }; '
                    'else exit 47; fi; '
                    'current=$(printf "%s" "$current" | tr "A-F" "a-f"); '
                    f'[ "$current" = {shlex.quote(expected_digest)} ] || exit 48; '
                    'mode=$(stat -c %a -- "$p" 2>/dev/null || stat -f %Lp -- "$p" 2>/dev/null || printf "?"); '
                    '[ "$mode" = "600" ] || exit 52; '
                )
            else:
                noop_guard = '[ ! -e "$p" ] && [ ! -L "$p" ] || exit 43; '
            result = runner.run_command(
                f'p={shlex.quote(target_path)}; {lock_prefix}{noop_guard}',
                timeout=timeout or self._timeout,
                retry_transport_errors=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip()
                    or "Remote .cdsinit changed during no-op verification"
                )
            final = self._remote_cdsinit_snapshot(
                expected,
                timeout=timeout,
                retry_transport_errors=False,
            )
            final.pop("_text", None)
            goal_met = (
                bool(final.get("exact_match"))
                if action == "install"
                else not final.get("installed")
                and int(final.get("duplicate_block_count") or 0) == 0
                and int(final.get("legacy_block_count") or 0) == 0
            )
            if not goal_met or not final.get("permission_safe"):
                raise RuntimeError(
                    "Remote .cdsinit changed after no-op verification"
                )
            final["backup_path"] = None
            return final
        upload = runner.upload_text(
            rendered,
            tmp_path,
            timeout=timeout or self._timeout,
            retry_transport_errors=False,
            create_parent=False,
            exclusive_create=True,
        )
        if upload.returncode != 0:
            raise RuntimeError(upload.stderr.strip() or "Unable to stage remote .cdsinit")
        quoted_tmp = shlex.quote(tmp_path)
        quoted_backup = shlex.quote(backup_path)
        if snapshot["target_exists"]:
            expected_digest = _sha256_bytes(text.encode("utf-8"))
            existing_guard = (
                '[ -e "$p" ] || exit 43; '
                'owner=$(stat -c %u -- "$p" 2>/dev/null || stat -f %u -- "$p" 2>/dev/null || printf "?"); '
                'uid=$(id -u); [ "$owner" = "$uid" ] || exit 44; '
                f'[ ! -e {quoted_backup} ] && [ ! -L {quoted_backup} ] || exit 45; '
                'umask 077; set -C; '
                f'exec 3> {quoted_backup} || exit 45; set +C; '
                f'cat -- "$p" >&3 || {{ exec 3>&-; rm -f -- {quoted_backup}; exit 46; }}; '
                f'exec 3>&-; chmod 600 -- {quoted_backup} || '
                f'{{ rm -f -- {quoted_backup}; exit 46; }}; '
                'if command -v sha256sum >/dev/null 2>&1; then '
                f'current=$(sha256sum -- {quoted_backup}) || {{ rm -f -- {quoted_backup}; exit 47; }}; '
                'current=${current%% *}; '
                'elif command -v shasum >/dev/null 2>&1; then '
                f'current=$(shasum -a 256 {quoted_backup}) || {{ rm -f -- {quoted_backup}; exit 47; }}; '
                'current=${current%% *}; '
                'elif command -v openssl >/dev/null 2>&1; then '
                f'current=$(openssl dgst -sha256 {quoted_backup}) || {{ rm -f -- {quoted_backup}; exit 47; }}; '
                'current=${current##* }; '
                f'else rm -f -- {quoted_backup}; exit 47; fi; '
                'current=$(printf "%s" "$current" | tr "A-F" "a-f"); '
                f'[ "$current" = {shlex.quote(expected_digest)} ] || '
                f'{{ rm -f -- {quoted_backup}; exit 48; }}; '
                f'cmp -s -- "$p" {quoted_backup} || '
                f'{{ rm -f -- {quoted_backup}; exit 49; }}; '
            )
        else:
            existing_guard = '[ ! -e "$p" ] || exit 43; '
        command = (
            f'p={shlex.quote(target_path)}; '
            f'{lock_prefix}'
            'if [ -L "$p" ]; then exit 41; fi; '
            'if [ -e "$p" ] && [ ! -f "$p" ]; then exit 42; fi; '
            f'{existing_guard}'
            f'[ -f {quoted_tmp} ] && [ ! -L {quoted_tmp} ] || exit 50; '
            f'chmod 600 -- {quoted_tmp} || exit 50; '
            f'mv -f -- {quoted_tmp} "$p" || exit 51; '
            'chmod 600 -- "$p" || exit 52'
        )
        try:
            result = runner.run_command(
                command,
                timeout=timeout or self._timeout,
                retry_transport_errors=False,
            )
        except Exception:
            try:
                runner.run_command(
                    f"rm -f -- {quoted_tmp}",
                    timeout=timeout or self._timeout,
                    retry_transport_errors=False,
                )
            except Exception:
                pass
            raise
        if result.returncode != 0:
            try:
                runner.run_command(
                    f"rm -f -- {quoted_tmp}",
                    timeout=timeout or self._timeout,
                    retry_transport_errors=False,
                )
            except Exception:
                pass
            raise RuntimeError(result.stderr.strip() or "Unable to atomically update remote .cdsinit")
        final = self._remote_cdsinit_snapshot(
            expected,
            timeout=timeout,
            retry_transport_errors=False,
        )
        final.pop("_text", None)
        final["backup_path"] = backup_path if snapshot["target_exists"] else None
        return final

    def autoload_status(
        self,
        *,
        expected_setup_path: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Return .cdsinit autoload state without staging or token creation."""
        expected = expected_setup_path or self._compat_setup_path
        if _is_localhost(self._gui_host):
            snapshot = _local_autoload_snapshot(self._profile, expected)
        else:
            snapshot = self._remote_cdsinit_snapshot(expected, timeout=timeout)
        snapshot.pop("_text", None)
        snapshot["profile"] = self._profile
        return snapshot

    def autoload_install(
        self,
        *,
        expected_setup_path: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Install/update only this profile's managed .cdsinit block."""
        expected = expected_setup_path or self._compat_setup_path
        if not expected:
            raise RuntimeError("No compatible bridge setup path is staged")
        if _is_localhost(self._gui_host):
            path = _local_cdsinit_path(self._profile)
            with _local_autoload_lock(path):
                snapshot = _local_autoload_snapshot(self._profile, expected)
                if snapshot.get("error") or snapshot["target_is_symlink"] or (
                    snapshot["target_exists"] and not snapshot["target_owned"]
                ):
                    raise RuntimeError(
                        f"Refusing unsafe .cdsinit target {snapshot['path']}: "
                        "symlink, non-owned, non-regular, or unreadable target"
                    )
                text = str(snapshot.get("_text") or "")
                rendered, _ = _autoload_render_install(
                    text, self._profile, str(expected)
                )
                backup_path = None
                mode_ok = snapshot.get("mode") == 0o600 or os.name == "nt"
                if rendered != text or not mode_ok or not path.exists():
                    if path.exists():
                        backup = _next_backup_path(path, self._profile)
                        _copy_private_backup(path, backup)
                        backup_path = str(backup)
                    _atomic_write_bytes(
                        path,
                        rendered.encode("utf-8"),
                        expected_current=text.encode("utf-8"),
                        expected_exists=bool(snapshot["target_exists"]),
                    )
                final = _local_autoload_snapshot(self._profile, expected)
            final.pop("_text", None)
            if backup_path:
                final["backup_path"] = backup_path
            final["profile"] = self._profile
            return final
        result = self._remote_autoload_mutate(
            action="install",
            expected_setup_path=expected,
            timeout=timeout,
        )
        result["profile"] = self._profile
        return result

    def autoload_uninstall(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Remove only this profile's managed block, never touching CIW."""
        expected = self._compat_setup_path
        if _is_localhost(self._gui_host):
            path = _local_cdsinit_path(self._profile)
            with _local_autoload_lock(path):
                snapshot = _local_autoload_snapshot(self._profile, expected)
                if snapshot.get("error") or snapshot["target_is_symlink"] or (
                    snapshot["target_exists"] and not snapshot["target_owned"]
                ):
                    raise RuntimeError(
                        f"Refusing unsafe .cdsinit target {snapshot['path']}: "
                        "symlink, non-owned, non-regular, or unreadable target"
                    )
                text = str(snapshot.get("_text") or "")
                rendered, _ = _autoload_render_uninstall(text, self._profile)
                backup_path = None
                mode_ok = snapshot.get("mode") == 0o600 or os.name == "nt"
                if path.exists() and (rendered != text or not mode_ok):
                    backup = _next_backup_path(path, self._profile)
                    _copy_private_backup(path, backup)
                    backup_path = str(backup)
                    _atomic_write_bytes(
                        path,
                        rendered.encode("utf-8"),
                        expected_current=text.encode("utf-8"),
                        expected_exists=True,
                    )
                final = _local_autoload_snapshot(self._profile, expected)
            final.pop("_text", None)
            if backup_path:
                final["backup_path"] = backup_path
            final["profile"] = self._profile
            return final
        result = self._remote_autoload_mutate(
            action="uninstall",
            expected_setup_path=expected,
            timeout=timeout,
        )
        result["profile"] = self._profile
        return result

    # -- SSH tunnel (delegated to SSHRunner) ----------------------------------

    def _saved_tunnel_identity_matches(self, state: dict[str, Any] | None) -> bool:
        if not isinstance(state, dict) or state.get("mode") != "remote":
            return False
        if state.get("profile") != self._profile:
            return False
        try:
            if int(state.get("port")) != self._local_port:
                return False
        except (TypeError, ValueError):
            return False
        saved = state.get("profile_config")
        if not isinstance(saved, dict) or not _profile_identity_matches(
            saved,
            remote_host=self._remote_host,
            remote_user=self._remote_user,
            remote_port=self._port,
            jump_host=self._jump_host,
            jump_user=self._jump_user,
            allow_remote_bind=self._allow_remote_bind,
            host_roles={"gui_host": self._gui_host, "deploy_host": self._deploy_host,
                        "spectre_host": self._spectre_host},
        ):
            return False
        try:
            return int(saved.get("local_port")) == self._local_port
        except (TypeError, ValueError):
            return False

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
            state = self.read_state(self._profile)
            if not self._saved_tunnel_identity_matches(state):
                raise RuntimeError(
                    f"Refusing to reuse reachable localhost:{self._local_port}: "
                    "the saved tunnel identity does not match this profile. "
                    "Stop the old profile tunnel or choose another VB_LOCAL_PORT."
                )
            try:
                tunnel_pid = int(state.get("tunnel_pid"))
            except (AttributeError, TypeError, ValueError):
                tunnel_pid = 0
            if tunnel_pid <= 0:
                raise RuntimeError(
                    f"Refusing to reuse reachable localhost:{self._local_port}: "
                    "the owning tunnel PID is unavailable."
                )
            runner.tunnel_pid = tunnel_pid
            if not runner.is_tunnel_alive:
                raise RuntimeError(
                    f"Refusing to reuse reachable localhost:{self._local_port}: "
                    "the saved tunnel process is no longer alive."
                )
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
                    print(f"[port] {self._local_port} busy, auto-switched to {local_port}", file=sys.stderr, flush=True)
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

    def connect(self, timeout: float = 15.0) -> dict[str, Any]:
        """Restore transport from saved deployment state without staging files."""
        state = self.read_state(self._profile)
        if not state or not self.staged_profile_config_matches_current(self._profile):
            raise RuntimeError("No matching prepared Bridge state; run explicit start first")
        if not self._auth_token:
            raise RuntimeError("Prepared Bridge authentication is unavailable; run explicit start")
        if not _is_localhost(self._daemon_host):
            self.ensure_tunnel(_budget=_TimeoutBudget.start(timeout, self._timeout))
            # Preserve the staged resource identity when only transport changes.
            if self.read_state(self._profile) != state:
                raise RuntimeError("Bridge state changed during connect; state was not overwritten")
            state["port"] = self._local_port
            state["tunnel_pid"] = self._require_runner().tunnel_pid
            state["profile_config"] = dict(state.get("profile_config") or {}, local_port=self._local_port)
            _atomic_write_json(_state_file(self._profile), state)
        return {"connected": True, "port": state.get("port"), "deployment_changed": False}

    def warm(self, timeout: int = 15) -> None:
        """Full startup: remote setup + persistent shell + tunnel."""
        budget = _TimeoutBudget.start(timeout, self._timeout)
        if _is_localhost(self._remote_host):
            self.ensure_local_setup()
            self._daemon_endpoint_hostname = socket.gethostname()
            self.save_state()
            return
        try:
            self.ensure_remote_setup(_budget=budget)
            runners = {id(runner): runner for runner in self._role_runners.values()}
            for runner in runners.values():
                if runner.persistent_shell_enabled:
                    runner.ensure_persistent_shell(_budget=budget)
            self._daemon_endpoint_hostname = self.probe_daemon_endpoint_hostname(timeout=budget.remaining("probe-daemon-host"))
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
                deployment_runner = self._require_deployment_runner()
                deployment_runner.run_command(f"rm -rf {shlex.quote(self._remote_work_dir)}")
            except Exception:
                logger.warning("Failed to clean up remote files at %s", self._remote_work_dir)

        self.close()

        # Clear state
        sf = _state_file(self._profile)
        if sf.exists():
            sf.unlink(missing_ok=True)

    def close(self) -> None:
        """Close SSH runner without killing the tunnel (it survives for other scripts)."""
        closed: set[int] = set()
        for runner in self._role_runners.values():
            if id(runner) in closed:
                continue
            closed.add(id(runner))
            try:
                runner.close()
            except Exception:
                pass

    def probe_daemon_endpoint_hostname(self, timeout: float | None = None) -> str:
        """Return the OS hostname reached through the configured daemon SSH endpoint."""
        if _is_localhost(self._daemon_host):
            return socket.gethostname()
        result = self._require_runner().run_command(
            "hostname -f 2>/dev/null || hostname 2>/dev/null || true",
            timeout=min(self._timeout, 10) if timeout is None else timeout,
        )
        return next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")

    def read_daemon_identity(self, *, timeout: float | None = None) -> dict[str, str]:
        """Read the banner identity written by the CIW-side loader.

        This path remains usable when the TCP tunnel targets the wrong host,
        which is precisely when a protocol-level identity query cannot work.
        """
        identity_path = self._remote_identity_path
        if not identity_path:
            state = self.read_state(self._profile) or {}
            identity_path = str(state.get("identity_path") or "")
        if not identity_path:
            return {}
        if _is_localhost(self._deploy_host):
            try:
                text = Path(identity_path).read_text(encoding="utf-8")
            except OSError:
                return {}
        else:
            result = self._require_deployment_runner().run_command(
                f"test -r {shlex.quote(identity_path)} && cat {shlex.quote(identity_path)}",
                timeout=min(self._timeout, 10) if timeout is None else timeout,
            )
            if result.returncode != 0:
                return {}
            text = result.stdout
        return _parse_daemon_identity(text)

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
        is_local = _is_localhost(self._daemon_host)
        tunnel_pid = None
        if not is_local:
            tunnel_pid = self._require_runner().tunnel_pid
        state = {
            "state_schema_version": 2,
            "mode": "local" if is_local else "remote",
            "port": self._port if is_local else self._local_port,
            "tunnel_pid": tunnel_pid,
            "remote_host": self._remote_host,
            "daemon_host": self._daemon_host,
            "deploy_host": self._deploy_host,
            "gui_host": self._gui_host,
            "spectre_host": self._spectre_host,
            "daemon_endpoint_hostname": self._daemon_endpoint_hostname,
            "setup_path": self._remote_virtuoso_setup_path,
            "previous_setup_path": previous_setup_path,
            "request_state_path": self._request_state_path,
            "deployed_daemon_sha256": self._deployed_daemon_sha256,
            "deployed_il_sha256": self._deployed_il_sha256,
            "deployed_setup_sha256": self._deployed_setup_sha256,
            "deployed_daemon_path": self._deployed_daemon_path,
            "deployed_il_path": self._deployed_il_path,
            "compat_setup_path": self._compat_setup_path,
            # Alias retained as an explicit bootstrap field for callers that
            # do not know the historical ``compat_setup_path`` name.
            "bootstrap_path": self._compat_setup_path,
            "deployment_id": self._deployment_id,
            "daemon_filename": self._daemon_filename,
            "previous_deployed_daemon_sha256": previous_daemon_sha256,
            "bind_policy": "remote-explicit" if self._allow_remote_bind else "loopback",
            "auth_enabled": bool(self._auth_token),
            "identity_path": self._remote_identity_path,
            "profile": self._profile,
            "profile_config": {
                "remote_host": self._remote_host,
                "remote_user": self._remote_user,
                "remote_port": self._port,
                "local_port": self._local_port,
                "jump_host": self._jump_host,
                "jump_user": self._jump_user,
                "allow_remote_bind": self._allow_remote_bind,
                "gui_host": self._gui_host,
                "deploy_host": self._deploy_host,
                "spectre_host": self._spectre_host,
            },
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
                payload = _strict_json_loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
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
                # A different local account may have staged a new setup while
                # the existing daemon still writes beside the previous setup.
                # Only try the recorded predecessor, never scan other clients.
                previous = str(state.get("previous_setup_path") or "")
                if result.returncode != 0 and previous:
                    previous_path = previous.rsplit("/", 1)[0] + "/request-status.json"
                    if previous_path != path:
                        result = client._require_runner().run_command(
                            f"cat -- {shlex.quote(previous_path)}", timeout=timeout,
                        )
                        if result.returncode == 0:
                            path = previous_path
                if result.returncode != 0:
                    return None
                payload = _strict_json_loads(result.stdout)
            except (OSError, ValueError, json.JSONDecodeError):
                return None
            finally:
                client.close()
        if not isinstance(payload, dict):
            return None
        payload["ledger_source_path"] = path
        requests = payload.get("requests", [])
        if not isinstance(requests, list) or any(
            not isinstance(entry, dict) for entry in requests
        ):
            return None
        if not request_id:
            return payload
        for entry in requests:
            if entry.get("request_id") == request_id:
                filtered = {
                    "schema_version": payload.get("schema_version"),
                    "ledger_source_path": path,
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
                    "exclusive_request_id",
                    "exclusive_request_generation",
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
            "exclusive_request_id",
            "exclusive_request_generation",
            "queue_depth",
            "queue_capacity",
        ):
            if key in payload:
                filtered[key] = payload.get(key)
        return filtered

    @classmethod
    def verify_staged_files(
        cls,
        profile: str | None,
        state: dict[str, Any],
        *,
        timeout: float = 10.0,
    ) -> tuple[bool, str]:
        """Verify exact staged daemon, IL, and setup bytes before activation."""
        expected = {
            str(state.get("deployed_daemon_path") or ""): str(
                state.get("deployed_daemon_sha256") or ""
            ).lower(),
            str(state.get("deployed_il_path") or ""): str(
                state.get("deployed_il_sha256") or ""
            ).lower(),
            str(state.get("setup_path") or ""): str(
                state.get("deployed_setup_sha256") or ""
            ).lower(),
        }
        if any(
            not path or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in expected.items()
        ):
            return False, "staged file identity is incomplete"
        budget = _TimeoutBudget.start(timeout, timeout)
        if state.get("mode") == "local":
            for raw_path, expected_digest in expected.items():
                path = Path(raw_path)
                if path.is_symlink() or not path.is_file():
                    return False, f"staged file is missing or unsafe: {path}"
                try:
                    actual = _sha256_bytes(path.read_bytes())
                except OSError as exc:
                    return False, f"unable to read staged file {path}: {exc}"
                if actual != expected_digest:
                    return False, f"staged file digest mismatch: {path}"
            return True, "verified"

        client = cls.from_env(
            keep_remote_files=True,
            profile=profile,
            create_auth_token=False,
        )
        try:
            runner = client._require_runner()
            for raw_path, expected_digest in expected.items():
                quoted = shlex.quote(raw_path)
                command = (
                    f"p={quoted}; [ -f \"$p\" ] && [ ! -L \"$p\" ] || exit 41; "
                    "if command -v sha256sum >/dev/null 2>&1; then "
                    'value=$(sha256sum -- "$p") || exit 42; value=${value%% *}; '
                    "elif command -v shasum >/dev/null 2>&1; then "
                    'value=$(shasum -a 256 "$p") || exit 42; value=${value%% *}; '
                    "elif command -v openssl >/dev/null 2>&1; then "
                    'value=$(openssl dgst -sha256 "$p") || exit 42; value=${value##* }; '
                    "else exit 43; fi; printf '%s\\n' \"$value\""
                )
                result = runner.run_command(
                    command,
                    timeout=budget.remaining("verify staged Bridge files"),
                    retry_transport_errors=True,
                )
                actual = (result.stdout or "").strip().lower()
                if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", actual):
                    details = result.stderr.strip() or result.stdout.strip()
                    return False, details or f"unable to verify staged file: {raw_path}"
                if actual != expected_digest:
                    return False, f"staged file digest mismatch: {raw_path}"
        except Exception as exc:  # noqa: BLE001
            return False, f"staged file verification failed: {exc}"
        finally:
            client.close()
        return True, "verified"

    @classmethod
    def staged_profile_config_matches_current(
        cls,
        profile: str | None = None,
    ) -> bool:
        """Return whether saved tunnel endpoints match the current profile.

        Legacy remote state without a complete ``profile_config`` fails
        closed.  A saved auto-selected local port remains valid when no
        explicit ``VB_LOCAL_PORT`` override was added later.
        """
        profile = resolve_profile(profile)
        load_vb_env()
        state = cls.read_state(profile)
        if not isinstance(state, dict):
            return False
        saved = state.get("profile_config")
        if not isinstance(saved, dict):
            return False
        suffix = f"_{profile}" if profile else ""
        roles = remote_host_roles_from_os(profile, load=False)
        remote_host = roles.daemon_host or ""
        remote_user = os.getenv(f"VB_REMOTE_USER{suffix}", "").strip() or None
        jump_host = os.getenv(f"VB_JUMP_HOST{suffix}", "").strip() or None
        jump_user = os.getenv(f"VB_JUMP_USER{suffix}", "").strip() or None
        from virtuoso_bridge.virtuoso.basic.bridge import _default_remote_port
        try:
            remote_port = int(
                os.getenv(f"VB_REMOTE_PORT{suffix}", "").strip()
                or _default_remote_port(remote_user)
            )
        except (TypeError, ValueError):
            return False
        allow_remote = remote_bind_allowed(profile)
        if not _profile_identity_matches(
            saved,
            remote_host=remote_host,
            remote_user=remote_user,
            remote_port=remote_port,
            jump_host=jump_host,
            jump_user=jump_user,
            allow_remote_bind=allow_remote,
            host_roles={"gui_host": roles.gui_host, "deploy_host": roles.deploy_host,
                        "spectre_host": roles.spectre_host},
        ):
            return False
        local_port_raw = os.getenv(f"VB_LOCAL_PORT{suffix}", "").strip()
        try:
            local_port = (
                int(local_port_raw)
                if local_port_raw
                else int(saved.get("local_port"))
            )
            state_port = int(state.get("port"))
        except (TypeError, ValueError):
            return False
        expected_mode = "local" if _is_localhost(remote_host) else "remote"
        return (
            state.get("mode") == expected_mode
            and state.get("profile") == profile
            and local_port == state_port
        )

    @classmethod
    def staged_resources_match_current(
        cls,
        profile: str | None = None,
    ) -> bool:
        """Compare packaged resources/profile inputs with saved staged state.

        This check deliberately avoids opening CIW or restarting anything.  A
        missing legacy field is treated as unknown (and therefore compatible)
        so state files written by older bridge versions retain their fast-path
        behavior; newly written state files include ``profile_config`` for a
        stricter comparison.
        """
        profile = resolve_profile(profile)
        state = cls.read_state(profile)
        if not state:
            return False
        if not cls.staged_profile_config_matches_current(profile):
            return False
        daemon_name = str(state.get("daemon_filename") or "")
        if daemon_name:
            daemon_hash = None
            for major in (2, 3):
                try:
                    candidate = _find_ramic_bridge_daemon(major)
                except (FileNotFoundError, OSError):
                    continue
                if candidate.name == daemon_name:
                    daemon_hash = _sha256_bytes(
                        _canonical_resource_text(candidate).encode("utf-8")
                    )
                    break
            if daemon_hash is None:
                return False
            if state.get("deployed_daemon_sha256") not in {None, daemon_hash}:
                return False
        elif state.get("deployed_daemon_sha256"):
            # There is no safe way to identify which Python-major resource was
            # staged in a legacy state lacking ``daemon_filename``.
            return False
        try:
            il_hash = _sha256_bytes(
                _canonical_resource_text(_find_ramic_bridge_il()).encode("utf-8")
            )
        except (FileNotFoundError, OSError):
            return False
        if state.get("deployed_il_sha256") not in {None, il_hash}:
            return False

        return True

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
        local_il_matches_deployed = state.get("deployed_il_sha256") == il_sha256
        selected_name = str(state.get("daemon_filename") or "")
        local_daemon_sha256 = source_variants.get(selected_name)
        running = cls.read_request_status(profile, timeout=timeout)
        running_sha256 = (
            str(running.get("daemon_build_sha256") or "") if running else ""
        )
        deployed_sha256 = str(state.get("deployed_daemon_sha256") or "")
        deployed_path = str(state.get("deployed_daemon_path") or "")
        identity: dict[str, str] = {}
        identity_error: str | None = None
        identity_path = str(state.get("identity_path") or "")
        saved_roles = state.get("profile_config") or {}
        deploy_host = saved_roles.get("deploy_host") if isinstance(saved_roles, dict) else None
        identity_is_local = _is_localhost(deploy_host) if deploy_host else state.get("mode") == "local"
        try:
            if identity_path and identity_is_local:
                identity = _parse_daemon_identity(Path(identity_path).read_text(encoding="utf-8"))
            elif identity_path:
                identity_client = cls.from_env(
                    keep_remote_files=True, profile=profile, create_auth_token=False,
                )
                try:
                    identity = identity_client.read_daemon_identity(timeout=timeout)
                finally:
                    identity_client.close()
        except Exception as exc:  # noqa: BLE001
            identity_error = str(exc)
        running_identity_verified = bool(
            running
            and identity.get("identity_complete") == "1"
            and identity.get("epoch")
            and identity.get("epoch") == running.get("daemon_epoch")
            and identity.get("pid", "").isdigit()
            and identity.get("pid") == str(running.get("daemon_pid"))
            and identity.get("profile") == (profile or "")
            and re.fullmatch(r"[0-9a-f]{64}", identity.get("deployment_id", ""))
            and re.fullmatch(r"[0-9a-f]{64}", identity.get("il_sha256", ""))
        )
        daemon_matches_running = bool(deployed_sha256 and running_sha256 == deployed_sha256)
        deployed_matches_running = bool(
            daemon_matches_running and running_identity_verified
            and identity.get("deployment_id") == state.get("deployment_id")
            and identity.get("il_sha256") == state.get("deployed_il_sha256")
        )
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
            "compat_setup_path": state.get("compat_setup_path") or state.get("bootstrap_path"),
            "bootstrap_path": state.get("bootstrap_path") or state.get("compat_setup_path"),
            "previous_setup_path": state.get("previous_setup_path"),
            "daemon_filename": selected_name or None,
            "local_daemon_sha256": local_daemon_sha256,
            "local_daemon_variants": source_variants,
            "local_il_sha256": il_sha256,
            "local_il_matches_deployed": local_il_matches_deployed,
            "deployed_daemon_sha256": deployed_sha256 or None,
            "deployed_daemon_path": deployed_path or None,
            "actual_deployed_daemon_sha256": actual_deployed_sha256 or None,
            "actual_digest_error": actual_digest_error,
            "deployed_il_sha256": state.get("deployed_il_sha256"),
            "deployed_setup_sha256": state.get("deployed_setup_sha256"),
            "running_daemon_sha256": running_sha256 or None,
            "running_identity_verified": running_identity_verified,
            "running_identity_error": identity_error or (
                None if running_identity_verified else "loaded identity missing, incomplete, or mismatched"
            ),
            "running_deployment_id": identity.get("deployment_id") if running_identity_verified else None,
            "running_il_sha256": identity.get("il_sha256") if running_identity_verified else None,
            "deployed_daemon_matches_running": daemon_matches_running,
            "running_daemon_epoch": running.get("daemon_epoch") if running else None,
            "running_heartbeat_age_seconds": heartbeat_age_seconds,
            "running_protocol_versions": running.get("protocol_versions") if running else None,
            "running_capabilities": running.get("capabilities") if running else None,
            "local_matches_deployed": bool(
                local_daemon_sha256
                and deployed_sha256 == local_daemon_sha256
                and actual_deployed_sha256 == deployed_sha256
                and local_il_matches_deployed
            ),
            "deployed_matches_running": deployed_matches_running,
            "running_available": running is not None,
            "running_heartbeat_fresh": bool(
                heartbeat_age_seconds is not None and heartbeat_age_seconds <= 5.0
            ),
            "staged_update_pending": bool(
                state.get("deployed_daemon_sha256")
                and (not deployed_matches_running
                     or deployed_sha256 != local_daemon_sha256
                     or not local_il_matches_deployed)
            ),
        }

    @staticmethod
    def read_state(profile: str | None = None) -> dict[str, Any] | None:
        """Read saved tunnel state."""
        for sf in _state_file_candidates(profile):
            if not sf.is_file():
                continue
            try:
                payload = _strict_json_loads(sf.read_text(encoding="utf-8"))
                return payload if isinstance(payload, dict) else None
            except (OSError, ValueError, json.JSONDecodeError):
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
        # Query the saved process without sending Windows console events.
        if pid:
            return _process_is_alive(pid)
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
        runner = self._require_deployment_runner()
        return runner.upload(
            local_path,
            remote_path,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )

    def download_file(self, remote_path: str, local_path: Path, timeout: int | None = None, recursive: bool = False) -> CommandResult:
        runner = self._require_deployment_runner()
        return runner.download(remote_path, local_path, recursive=recursive, timeout=timeout or self._timeout)

    def upload_text(
        self,
        text: str,
        remote_path: str,
        timeout: int | None = None,
        *,
        retry_transport_errors: bool = False,
        create_parent: bool = True,
        exclusive_create: bool = False,
    ) -> CommandResult:
        runner = self._require_deployment_runner()
        return runner.upload_text(
            text,
            remote_path,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
            create_parent=create_parent,
            exclusive_create=exclusive_create,
        )

    def run_command(
        self,
        cmd: str,
        timeout: int | None = None,
        *,
        operation_class: str = "unknown",
        retry_transport_errors: bool | None = None,
    ) -> CommandResult:
        runner = self._require_deployment_runner()
        if operation_class not in {"unknown", "read_only", "mutating"}:
            raise ValueError("operation_class must be unknown, read_only, or mutating")
        if retry_transport_errors is None:
            retry_transport_errors = operation_class == "read_only"
        return runner.run_command(
            cmd,
            timeout=timeout or self._timeout,
            retry_transport_errors=retry_transport_errors,
        )
