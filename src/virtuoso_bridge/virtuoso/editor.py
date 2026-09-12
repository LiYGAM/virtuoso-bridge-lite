"""Shared helpers for Virtuoso edit context managers."""

from __future__ import annotations

from typing import Any

from virtuoso_bridge.models import CompletionStatus, ExecutionStatus, VirtuosoResult


def ensure_operation_response(response: Any, *, context: str) -> None:
    """Raise a consistent error when an edit batch fails."""
    if isinstance(response, VirtuosoResult):
        if response.status != ExecutionStatus.SUCCESS or response.completion != CompletionStatus.CONFIRMED:
            errors = response.errors or ["unknown failure"]
            raise RuntimeError(f"{context} failed: {errors[0]}")
        if response.output.strip() != "t":
            raise RuntimeError(f"{context} failed: cellview save was not confirmed")
        return

    if not response.get("ok", False):
        raise RuntimeError(f"{context} failed: {response.get('error', 'request failed')}")

    result = response.get("result", {})
    if result.get("status") != "success":
        errors = result.get("errors") or [result.get("status", "unknown failure")]
        raise RuntimeError(f"{context} failed: {errors[0]}")
    if str(result.get("output", "")).strip() != "t":
        raise RuntimeError(f"{context} failed: cellview save was not confirmed")
