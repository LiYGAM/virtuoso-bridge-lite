from __future__ import annotations

import ast
import errno
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


RESOURCE_DIR = (
    Path(__file__).parents[1]
    / "src"
    / "virtuoso_bridge"
    / "virtuoso"
    / "basic"
    / "resources"
)


class _Reader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)
        self.buffer = self

    def read(self, _size: int) -> bytes:
        return next(self._chunks)


def _load_reader(filename: str, chunks: list[bytes], timed_out: bool):
    source_path = RESOURCE_DIR / filename
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "read_until_delimiter"
    )
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {
        "sys": SimpleNamespace(stdin=_Reader(chunks)),
        "time": SimpleNamespace(sleep=lambda _seconds: None),
        "errno": errno,
        "timeout_flag": timed_out,
    }
    exec(compile(module, str(source_path), "exec"), namespace)
    return namespace["read_until_delimiter"]


def _load_watchdog(filename: str):
    source_path = RESOURCE_DIR / filename
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "watchdog_callback"
    )
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {"timeout_flag": False}
    exec(compile(module, str(source_path), "exec"), namespace)
    return namespace


@pytest.mark.parametrize(
    ("filename", "timeout_result"),
    [
        ("ramic_bridge_daemon_3.py", b"\x15TimeoutError"),
        ("ramic_bridge_daemon_27.py", "\x15TimeoutError"),
    ],
)
def test_timed_out_request_drains_late_response(
    filename: str,
    timeout_result: bytes | str,
) -> None:
    reader = _load_reader(
        filename,
        [b"", b"\x02", b"l", b"a", b"t", b"e", b"\x1e"],
        timed_out=True,
    )

    assert reader() == timeout_result


@pytest.mark.parametrize(
    "filename",
    ["ramic_bridge_daemon_3.py", "ramic_bridge_daemon_27.py"],
)
def test_normal_request_keeps_success_response(filename: str) -> None:
    reader = _load_reader(
        filename,
        [b"\x02", b"o", b"k", b"\x1e"],
        timed_out=False,
    )

    assert bytes(reader()) == b"\x02ok"


@pytest.mark.parametrize(
    "filename",
    ["ramic_bridge_daemon_3.py", "ramic_bridge_daemon_27.py"],
)
def test_watchdog_marks_timeout_without_signaling_virtuoso(filename: str) -> None:
    namespace = _load_watchdog(filename)

    namespace["watchdog_callback"]()

    assert namespace["timeout_flag"] is True
