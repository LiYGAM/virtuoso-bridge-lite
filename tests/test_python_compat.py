"""Compatibility smoke tests for the declared minimum Python version."""

from __future__ import annotations

import importlib

import pytest

from virtuoso_bridge.models import ExecutionStatus, VirtuosoResult


@pytest.mark.unit
def test_python_39_runtime_annotations_are_importable() -> None:
    """Keep postponed PEP 604 annotations usable on Python 3.9."""
    result = VirtuosoResult(status=ExecutionStatus.SUCCESS, execution_time=None)

    assert result.ok
    assert result.execution_time is None
    assert importlib.import_module("virtuoso_bridge.virtuoso.maestro.writer")
    assert importlib.import_module("virtuoso_bridge.virtuoso.maestro.lifecycle")
