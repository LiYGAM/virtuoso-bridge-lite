"""X11 dialog detection and dismissal via SSH (bypasses SKILL channel).

When a modal dialog blocks the Virtuoso CIW event loop, all execute_skill()
calls time out.  This module uses direct SSH + remote Python3/Xlib to find
and dismiss those dialogs without touching the SKILL channel.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
from pathlib import Path
from typing import Any

from virtuoso_bridge.env import load_vb_env
from virtuoso_bridge.transport.remote_paths import default_virtuoso_bridge_dir, resolve_client_id
from virtuoso_bridge.transport.ssh import SSHRunner

logger = logging.getLogger(__name__)

_HELPER_SCRIPT = Path(__file__).parent.parent / "resources" / "x11_dismiss_dialog.py"


def _get_display(display: str | None) -> str | None:
    """Resolve display: explicit arg > VB_DISPLAY env var > auto-detect (None)."""
    load_vb_env()
    if display:
        return display
    return os.getenv("VB_DISPLAY") or None


def _run(runner: SSHRunner | None, cmd: str, timeout: int):
    """Dispatch a shell command via SSH or local subprocess.

    Returns an object exposing ``.returncode`` / ``.stdout`` / ``.stderr``
    so the call sites can be agnostic to mode.
    """
    if runner is not None:
        return runner.run_command(cmd, timeout=timeout)
    import subprocess
    from types import SimpleNamespace
    try:
        r = subprocess.run(
            ["sh", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return SimpleNamespace(returncode=124, stdout="", stderr="timeout")
    except FileNotFoundError:
        return SimpleNamespace(returncode=127, stdout="", stderr="no shell")
    return SimpleNamespace(
        returncode=r.returncode,
        stdout=r.stdout or "",
        stderr=r.stderr or "",
    )


def _detect_remote_python(runner: SSHRunner | None) -> str:
    """Find a Python interpreter (remote host or local).

    The X11 helper is intentionally Python 2/3 compatible because older EDA
    hosts often only provide Python 2.7.
    """
    r = _run(
        runner,
        'python3 --version 2>/dev/null && echo "CMD:python3" || '
        '(python --version 2>&1 | grep -q "Python" && echo "CMD:python") || '
        '(python2 --version 2>&1 | grep -q "Python" && echo "CMD:python2") || '
        'echo "CMD:NONE"',
        timeout=10,
    )
    for line in (r.stdout or "").splitlines():
        if line.strip().startswith("CMD:") and line.strip() != "CMD:NONE":
            return line.strip()[4:]
    return "python3"  # fallback; callers surface stderr/returncode as an error


def _ensure_helper(
    runner: SSHRunner | None,
    user: str,
    profile: str | None = None,
) -> str:
    """Resolve the path to the helper script.

    Remote: upload under the client-scoped bridge scratch directory.
    Local: the helper file is part of the installed package — return its
    on-disk path directly, no copy needed.
    """
    if runner is None:
        return str(_HELPER_SCRIPT)
    remote_dir = default_virtuoso_bridge_dir(user, "x11", resolve_client_id(profile))
    remote_path = f"{remote_dir}/x11_dismiss_dialog.py"
    runner.run_command(f"mkdir -p {remote_dir}")
    runner.upload(_HELPER_SCRIPT, remote_path)
    return remote_path


def find_dialogs(
    runner: SSHRunner | None,
    user: str,
    display: str | None = None,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    """Find blocking dialog windows on the X11 display.

    Returns list of dicts: [{"window_id", "title", "x", "y", "w", "h"}, ...]
    """
    load_vb_env()
    script = _ensure_helper(runner, user, profile)
    py = _detect_remote_python(runner)
    resolved = _get_display(display)
    cmd = f"{py} {script}"
    if resolved:
        cmd += f" {resolved}"
    result = _run(runner, cmd, timeout=15)
    return _parse_result(result)


def list_windows(
    runner: SSHRunner | None,
    user: str,
    display: str | None = None,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    """Enumerate Virtuoso-related X11 windows without dismissing anything."""
    load_vb_env()
    script = _ensure_helper(runner, user, profile)
    py = _detect_remote_python(runner)
    resolved = _get_display(display)
    cmd = f"{py} {script} --list-windows --json"
    if resolved:
        cmd += f" {resolved}"
    result = _run(runner, cmd, timeout=15)
    return _parse_result(result)


def dismiss_window(
    runner: SSHRunner | None,
    user: str,
    window_id: str,
    *,
    action: str = "enter",
    display: str | None = None,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    """Dismiss an explicit X11 window id with a requested key action."""
    load_vb_env()
    script = _ensure_helper(runner, user, profile)
    py = _detect_remote_python(runner)
    resolved = _get_display(display)
    cmd = (
        f"{py} {script} --dismiss-window {shlex.quote(window_id)} "
        f"--action {shlex.quote(action)}"
    )
    if resolved:
        cmd += f" {resolved}"
    result = _run(runner, cmd, timeout=15)
    return _parse_result(result)


def window_input(
    runner: SSHRunner | None,
    user: str,
    window_id: str,
    *,
    expect_title: str,
    action: str,
    x: int,
    y: int,
    button: int = 1,
    to_x: int | None = None,
    to_y: int | None = None,
    allow_live: bool = False,
    dry_run: bool = False,
    settle_ms: int = 50,
    hold_ms: int = 0,
    drag_duration_ms: int = 0,
    drag_steps: int = 1,
    postcondition: str = "none",
    post_expect_title: str | None = None,
    display: str | None = None,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    """Send explicitly opted-in pointer input to one discovered child window.

    The remote helper repeats discovery and reads the target's current mapped
    geometry immediately before sending any XTest event.  Keeping the
    confirmation arguments in the command also makes direct helper use obey
    the same safety contract as the public CLI.
    """
    if not allow_live and not dry_run:
        return [{"error": "--allow-live is required"}]
    load_vb_env()
    script = _ensure_helper(runner, user, profile)
    py = _detect_remote_python(runner)
    resolved = _get_display(display)
    cmd = (
        f"{py} {script} --window-input {shlex.quote(window_id)} "
        f"--expect-title {shlex.quote(expect_title)} "
        f"--action {shlex.quote(action)} --x {int(x)} --y {int(y)} "
        f"--button {int(button)} --settle-ms {int(settle_ms)} "
        f"--hold-ms {int(hold_ms)} --drag-duration-ms {int(drag_duration_ms)} "
        f"--drag-steps {int(drag_steps)} --postcondition {shlex.quote(postcondition)}"
    )
    if allow_live:
        cmd += " --allow-live"
    if dry_run:
        cmd += " --dry-run"
    if to_x is not None:
        cmd += f" --to-x {int(to_x)}"
    if to_y is not None:
        cmd += f" --to-y {int(to_y)}"
    if post_expect_title is not None:
        cmd += f" --post-expect-title {shlex.quote(post_expect_title)}"
    if resolved:
        cmd += f" {resolved}"
    return _parse_result(_run(runner, cmd, timeout=15))


def dismiss_dialogs(
    runner: SSHRunner | None,
    user: str,
    display: str | None = None,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    """Find and dismiss all blocking dialog windows.

    Returns list of result dicts (found dialogs + dismissal results).
    """
    load_vb_env()
    script = _ensure_helper(runner, user, profile)
    py = _detect_remote_python(runner)
    resolved = _get_display(display)
    env_prefix = ""
    for key in ("VB_SAVE_DIALOG_POLICY", "VB_SAVE_DIALOG_CONTEXT"):
        val = os.getenv(key)
        if val is not None and val != "":
            env_prefix += f"{key}={shlex.quote(val)} "

    cmd = f"{env_prefix}{py} {script} --dismiss"
    if resolved:
        cmd += f" {resolved}"
    result = _run(runner, cmd, timeout=15)
    return _parse_result(result)


def _parse_result(result) -> list[dict[str, Any]]:
    """Parse helper output and surface command failures as structured errors."""
    parsed = _parse_output(result.stdout)
    if parsed:
        return parsed

    returncode = getattr(result, "returncode", 0)
    stderr = (getattr(result, "stderr", "") or "").strip()
    if returncode:
        return [{
            "error": stderr or f"x11 helper command failed with return code {returncode}",
            "returncode": returncode,
        }]
    if stderr:
        return [{"error": stderr}]
    return []


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    """Parse JSON-lines output from the helper script."""
    results = []
    for line in (stdout or "").strip().splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                logger.debug("Non-JSON line from helper: %s", line)
    return results
