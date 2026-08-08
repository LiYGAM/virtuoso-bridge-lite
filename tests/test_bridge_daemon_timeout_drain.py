from __future__ import annotations

import ast
import errno
import hashlib
import json
import queue
import socket
import struct
import sys
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from virtuoso_bridge import CompletionStatus, VirtuosoClient


pytestmark = pytest.mark.unit


RESOURCE_DIR = (
    Path(__file__).parents[1]
    / "src"
    / "virtuoso_bridge"
    / "virtuoso"
    / "basic"
    / "resources"
)
DAEMON_FILES = ["ramic_bridge_daemon_3.py", "ramic_bridge_daemon_27.py"]


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _Reader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)
        self.buffer = self

    def read(self, _size: int) -> bytes:
        try:
            return next(self._chunks)
        except StopIteration:
            return b""


class _Event:
    def __init__(self) -> None:
        self.was_set = False

    def set(self) -> None:
        self.was_set = True


class _Connection:
    def __init__(self, chunks: list[bytes | BaseException]) -> None:
        self._chunks = iter(chunks)
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def recv(self, _size: int) -> bytes:
        value = next(self._chunks)
        if isinstance(value, BaseException):
            raise value
        return value


def _load_functions(filename: str, names: set[str], namespace: dict[str, object]) -> dict[str, object]:
    source_path = RESOURCE_DIR / filename
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    module = ast.Module(body=functions, type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(source_path), "exec"), namespace)
    return namespace


def _load_reader(filename: str, chunks: list[bytes]):
    clock = _Clock()
    namespace: dict[str, object] = {
        "sys": SimpleNamespace(stdin=_Reader(chunks)),
        "time": SimpleNamespace(sleep=clock.sleep),
        "errno": errno,
        "_monotonic": clock.monotonic,
        "_MAX_RESPONSE_BYTES": 1024,
    }
    _load_functions(
        filename,
        {"ResponseDrainTimeout", "read_until_delimiter"},
        namespace,
    )
    return namespace["read_until_delimiter"], namespace["ResponseDrainTimeout"], clock


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_late_response_is_drained_and_preserved_for_reconciliation(filename: str) -> None:
    reader, _timeout_error, _clock = _load_reader(
        filename,
        [b"", b"\x02", b"l", b"a", b"t", b"e", b"\x1e"],
    )

    response, overflow, seen = reader(deadline=10.0, max_response_bytes=1024)

    assert bytes(response) == b"\x02late"
    assert overflow is False
    assert seen == 4


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_response_limit_drains_frame_but_bounds_memory(filename: str) -> None:
    reader, _timeout_error, _clock = _load_reader(
        filename,
        [b"\x02", b"a", b"b", b"c", b"d", b"\x1e"],
    )

    response, overflow, seen = reader(deadline=10.0, max_response_bytes=3)

    assert bytes(response) == b"\x02ab"
    assert overflow is True
    assert seen == 4


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_response_drain_deadline_retires_unaligned_stream(filename: str) -> None:
    reader, timeout_error, clock = _load_reader(filename, [b""])

    with pytest.raises(timeout_error):
        reader(deadline=0.003, max_response_bytes=1024)

    assert clock.now >= 0.003


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_watchdog_is_generation_scoped(filename: str) -> None:
    recorded: list[tuple[str, str]] = []
    namespace: dict[str, object] = {
        "_mark_request_timed_out": lambda request_id, generation: recorded.append(
            (request_id, generation)
        )
    }
    _load_functions(filename, {"watchdog_callback"}, namespace)
    event = _Event()

    namespace["watchdog_callback"]("req-timeout", "generation-1", event)

    assert event.was_set is True
    assert recorded == [("req-timeout", "generation-1")]


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_terminal_finalize_cannot_be_overwritten_by_late_watchdog(filename: str) -> None:
    requests = {
        "req-1": {
            "request_id": "req-1",
            "request_generation": "generation-1",
            "state": "running",
        }
    }
    namespace: dict[str, object] = {
        "_STATE_LOCK": threading.Lock(),
        "_REQUESTS": requests,
        "_REQUEST_ORDER": ["req-1"],
        "_RESPONSE_CACHE": {},
        "_RESPONSE_CACHE_BYTES": 0,
        "_MAX_RESPONSE_CACHE_BYTES": 1024,
        "_ACTIVE_STATES": ("running", "timed_out_pending"),
        "_ACTIVE_REQUEST_ID": "req-1",
        "_write_request_state": lambda: None,
        "time": SimpleNamespace(time=lambda: 1.0),
    }
    _load_functions(
        filename,
        {"_store_cached_response_locked", "_finalize_request", "_mark_request_timed_out"},
        namespace,
    )

    assert namespace["_finalize_request"](
        "req-1", "generation-1", "succeeded", response_bytes=b"\x02ok"
    )
    assert not namespace["_mark_request_timed_out"]("req-1", "generation-1")
    assert requests["req-1"]["state"] == "succeeded"


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_response_cache_evicts_old_entries_to_stay_within_byte_budget(filename: str) -> None:
    namespace: dict[str, object] = {
        "_REQUEST_ORDER": ["req-1", "req-2", "req-3"],
        "_RESPONSE_CACHE": {},
        "_RESPONSE_CACHE_BYTES": 0,
        "_MAX_RESPONSE_CACHE_BYTES": 5,
    }
    _load_functions(filename, {"_store_cached_response_locked"}, namespace)
    store = namespace["_store_cached_response_locked"]

    assert store("req-1", b"123") is True
    assert store("req-2", b"456") is True
    assert namespace["_RESPONSE_CACHE"] == {"req-2": b"456"}
    assert namespace["_RESPONSE_CACHE_BYTES"] == 3
    assert store("req-3", b"123456") is False
    assert namespace["_RESPONSE_CACHE_BYTES"] == 3


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_request_read_is_size_and_time_bounded(filename: str) -> None:
    namespace: dict[str, object] = {
        "_monotonic": lambda: 0.0,
        "_REQUEST_READ_TIMEOUT_SECONDS": 5.0,
        "_MAX_REQUEST_BYTES": 4,
        "socket": socket,
    }
    _load_functions(filename, {"RequestProtocolError", "_receive_request"}, namespace)
    protocol_error = namespace["RequestProtocolError"]

    with pytest.raises(protocol_error, match="REQUEST_TOO_LARGE"):
        namespace["_receive_request"](_Connection([b"12345"]))

    with pytest.raises(protocol_error, match="REQUEST_READ_TIMEOUT"):
        namespace["_receive_request"](_Connection([socket.timeout()]))


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_protocol_v3_frame_round_trips_through_client_parser(filename: str) -> None:
    namespace: dict[str, object] = {
        "bytes": bytes,
        "str": str,
        "_text_type": str,
        "hashlib": hashlib,
        "json": json,
        "struct": struct,
        "DAEMON_EPOCH": "epoch-daemon",
        "DAEMON_BUILD_SHA256": "d" * 64,
        "PROTOCOL_VERSIONS": (2, 3),
        "DAEMON_CAPABILITIES": ("protocol-v3-frame-v1",),
        "_V3_MAGIC": b"VBR3\x00",
        "_V3_FOOTER": b"\x1eVBR3-END\x1e",
    }
    _load_functions(filename, {"_build_v3_frame"}, namespace)
    request_digest = "e" * 64

    raw = namespace["_build_v3_frame"](
        "req-frame",
        "succeeded",
        "STX",
        b"3",
        request_digest_sha256=request_digest,
    )
    result = VirtuosoClient._parse_response(
        raw,
        0.1,
        request_id="req-frame",
        request_digest_sha256=request_digest,
    )

    assert result.output == "3"
    assert result.completion == CompletionStatus.CONFIRMED
    assert result.metadata["daemon_epoch"] == "epoch-daemon"
    assert result.metadata["daemon_build_sha256"] == "d" * 64
    assert result.metadata["supported_protocol_versions"] == [2, 3]
    assert result.metadata["daemon_capabilities"] == ["protocol-v3-frame-v1"]


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_bounded_queue_admission_returns_busy_without_dispatch(filename: str) -> None:
    request_queue: queue.Queue[object] = queue.Queue(maxsize=1)
    request_queue.put_nowait(object())
    sent: list[bytes] = []
    requests: dict[str, dict[str, object]] = {}
    namespace: dict[str, object] = {
        "_queue": queue,
        "_REQUEST_QUEUE": request_queue,
        "_QUEUE_CAPACITY": 1,
        "_REJECTED_BUSY_COUNT": 0,
        "_RETIRE_EVENT": threading.Event(),
        "_receive_request": lambda _conn: b"{}",
        "json": json,
        "_validate_request": lambda _data: (
            "1+1", 5.0, "req-busy", "read_only", 3
        ),
        "PROTOCOL_VERSIONS": (2, 3),
        "AUTH_TOKEN": "",
        "_safe_token_equal": lambda _left, _right: True,
        "hashlib": hashlib,
        "uuid": uuid,
        "_STATE_LOCK": threading.Lock(),
        "_REQUESTS": requests,
        "_REQUEST_ORDER": [],
        "_RESPONSE_CACHE": {},
        "_RESPONSE_CACHE_BYTES": 0,
        "_MAX_REQUESTS": 64,
        "_RECOVER_AS_ORPHANED_STATES": ("queued", "running", "timed_out_pending"),
        "_write_request_state": lambda: None,
        "_safe_sendall": lambda _conn, data: sent.append(data),
        "_format_client_response": lambda *_args, **_kwargs: b"V3-BUSY",
        "time": SimpleNamespace(time=lambda: 1.0),
        "traceback": SimpleNamespace(print_exc=lambda: None),
    }
    _load_functions(
        filename,
        {
            "RequestProtocolError",
            "_busy_response",
            "_trim_request_history_locked",
            "_admit_external_connection",
        },
        namespace,
    )

    admitted = namespace["_admit_external_connection"](object(), ("local", 1))

    assert admitted is False
    assert sent == [b"V3-BUSY"]
    assert namespace["_REJECTED_BUSY_COUNT"] == 1
    assert requests == {}


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_queue_admission_records_queued_before_serial_worker(filename: str) -> None:
    request_queue: queue.Queue[object] = queue.Queue(maxsize=2)
    namespace: dict[str, object] = {
        "_queue": queue,
        "_REQUEST_QUEUE": request_queue,
        "_QUEUE_CAPACITY": 2,
        "_REJECTED_BUSY_COUNT": 0,
        "_RETIRE_EVENT": threading.Event(),
        "_receive_request": lambda _conn: b"{}",
        "json": json,
        "_validate_request": lambda _data: (
            "1+1", 5.0, "req-queued", "read_only", 3
        ),
        "PROTOCOL_VERSIONS": (2, 3),
        "AUTH_TOKEN": "",
        "_safe_token_equal": lambda _left, _right: True,
        "hashlib": hashlib,
        "uuid": uuid,
        "_STATE_LOCK": threading.Lock(),
        "_REQUESTS": {},
        "_REQUEST_ORDER": [],
        "_RESPONSE_CACHE": {},
        "_RESPONSE_CACHE_BYTES": 0,
        "_MAX_REQUESTS": 64,
        "_RECOVER_AS_ORPHANED_STATES": ("queued", "running", "timed_out_pending"),
        "_write_request_state": lambda: None,
        "_safe_sendall": lambda *_args: None,
        "_format_client_response": lambda *_args, **_kwargs: b"response",
        "time": SimpleNamespace(time=lambda: 1.0),
        "traceback": SimpleNamespace(print_exc=lambda: None),
    }
    _load_functions(
        filename,
        {
            "RequestProtocolError",
            "_busy_response",
            "_trim_request_history_locked",
            "_admit_external_connection",
        },
        namespace,
    )

    assert namespace["_admit_external_connection"](object(), ("local", 1)) is True
    assert request_queue.qsize() == 1
    entry = namespace["_REQUESTS"]["req-queued"]
    assert entry["state"] == "queued"
    assert entry["operation_class"] == "read_only"
    assert entry["queue_position"] == 1


@pytest.mark.parametrize("filename", DAEMON_FILES)
def test_history_trimming_never_evicts_queued_or_running_requests(filename: str) -> None:
    namespace: dict[str, object] = {
        "_REQUESTS": {
            "active": {"state": "running"},
            "queued": {"state": "queued"},
            "old": {"state": "succeeded"},
        },
        "_REQUEST_ORDER": ["active", "queued", "old"],
        "_RESPONSE_CACHE": {"old": b"ok"},
        "_RESPONSE_CACHE_BYTES": 2,
        "_MAX_REQUESTS": 2,
        "_RECOVER_AS_ORPHANED_STATES": ("queued", "running", "timed_out_pending"),
    }
    _load_functions(filename, {"_trim_request_history_locked"}, namespace)

    namespace["_trim_request_history_locked"]()

    assert namespace["_REQUEST_ORDER"] == ["active", "queued"]
    assert set(namespace["_REQUESTS"]) == {"active", "queued"}
    assert namespace["_RESPONSE_CACHE"] == {}
