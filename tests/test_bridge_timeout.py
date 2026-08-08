from __future__ import annotations

import errno
import hashlib
import json
import socket
import struct
from collections.abc import Iterator
from typing import get_type_hints

import pytest

from virtuoso_bridge import (
    CompletionStatus,
    ExecutionStatus,
    OperationClass,
    VirtuosoClient,
)
from virtuoso_bridge.virtuoso.basic import bridge

pytestmark = pytest.mark.unit


def _v3_frame(
    request_id: str,
    payload: bytes,
    *,
    status: str = "succeeded",
    marker: str = "STX",
    request_digest_sha256: str | None = None,
    **metadata: object,
) -> bytes:
    header = {
        "protocol_version": 3,
        "request_id": request_id,
        "status": status,
        "marker": marker,
        "payload_length": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "daemon_epoch": "epoch-v3",
        "daemon_build_sha256": "a" * 64,
        "request_digest_sha256": request_digest_sha256,
    }
    header.update(metadata)
    header_bytes = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return (
        bridge._V3_MAGIC
        + struct.pack(">I", len(header_bytes))
        + header_bytes
        + payload
        + bridge._V3_FOOTER
    )


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def sleep(self, seconds: float) -> None:
        assert seconds > 0.0
        self.sleeps.append(seconds)
        self.advance(seconds)


class _FakeSocket:
    def __init__(
        self,
        clock: _FakeClock,
        *,
        connect_duration: float = 0.0,
        connect_error: OSError | None = None,
        send_duration: float = 0.0,
        send_error: OSError | None = None,
        shutdown_error: OSError | None = None,
        recv_results: tuple[tuple[float, bytes | OSError], ...] = ((0.0, b""),),
    ) -> None:
        self._clock = clock
        self._connect_duration = connect_duration
        self._connect_error = connect_error
        self._send_duration = send_duration
        self._send_error = send_error
        self._shutdown_error = shutdown_error
        self._recv_results: Iterator[tuple[float, bytes | OSError]] = iter(recv_results)
        self._timeout: float | None = None
        self.phase_timeouts: list[tuple[str, float]] = []
        self.sent_payloads: list[bytes] = []

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout

    def connect(self, _address: tuple[str, int]) -> None:
        self._run_phase("connect", self._connect_duration)
        if self._connect_error is not None:
            raise self._connect_error

    def sendall(self, payload: bytes) -> None:
        self.sent_payloads.append(payload)
        self._run_phase("send", self._send_duration)
        if self._send_error is not None:
            raise self._send_error

    def shutdown(self, _how: int) -> None:
        if self._shutdown_error is not None:
            raise self._shutdown_error

    def recv(self, _size: int) -> bytes:
        duration, result = next(self._recv_results)
        self._run_phase("recv", duration)
        if isinstance(result, OSError):
            raise result
        return result

    def _run_phase(self, phase: str, duration: float) -> None:
        assert self._timeout is not None
        self.phase_timeouts.append((phase, self._timeout))
        if duration > self._timeout:
            self._clock.advance(self._timeout)
            raise socket.timeout
        self._clock.advance(duration)


class _SocketFactory:
    def __init__(self, sockets: list[_FakeSocket]) -> None:
        self._remaining = iter(sockets)
        self.created: list[_FakeSocket] = []

    def __call__(self, *_args: object) -> _FakeSocket:
        fake_socket = next(self._remaining)
        self.created.append(fake_socket)
        return fake_socket


def _use_fake_network(
    monkeypatch: pytest.MonkeyPatch,
    clock: _FakeClock,
    factory: _SocketFactory,
) -> None:
    monkeypatch.setattr(bridge.time, "monotonic", clock)
    monkeypatch.setattr(bridge.time, "sleep", clock.sleep)
    monkeypatch.setattr(bridge.socket, "socket", factory)
    monkeypatch.setenv("VB_JUMP_HOST", "jump.example.com")


def test_execute_skill_uses_one_deadline_across_retry_and_socket_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    refused = _FakeSocket(
        clock,
        connect_duration=0.1,
        connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
    )
    connected = _FakeSocket(
        clock,
        connect_duration=0.1,
        send_duration=0.2,
        recv_results=((0.2, b"\x02partial"), (0.3, b"")),
    )
    factory = _SocketFactory([refused, connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill("1+1", timeout=1.0)

    assert result.status == ExecutionStatus.ERROR
    assert result.errors == ["Socket timeout after 1.0s"]
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN
    assert result.execution_time == pytest.approx(1.0)
    assert clock.sleeps == [0.2]
    assert refused.phase_timeouts == [("connect", pytest.approx(1.0))]
    assert connected.phase_timeouts == [
        ("connect", pytest.approx(0.7)),
        ("send", pytest.approx(0.6)),
        ("recv", pytest.approx(0.4)),
        ("recv", pytest.approx(0.2)),
    ]


def test_execute_skill_timeout_caps_jump_host_retry_grace(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _FakeClock()
    refused_sockets = [
        _FakeSocket(
            clock,
            connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
        )
        for _ in range(20)
    ]
    factory = _SocketFactory(refused_sockets)
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill("1+1", timeout=0.1)

    assert result.status == ExecutionStatus.ERROR
    assert result.errors == ["Socket timeout after 0.1s"]
    assert result.completion == CompletionStatus.NOT_DISPATCHED
    assert result.execution_time == pytest.approx(0.1)
    assert clock.sleeps == [pytest.approx(0.1)]
    assert factory.created[0].phase_timeouts == [("connect", pytest.approx(0.1))]
    assert sum(
        phase == "connect"
        for fake_socket in factory.created
        for phase, _timeout in fake_socket.phase_timeouts
    ) == 1
    assert any("after 0.1s" in message for message in caplog.messages)


def test_execute_skill_timeout_annotation_accepts_float() -> None:
    annotations = get_type_hints(VirtuosoClient.execute_skill)

    assert annotations["timeout"] == float | None


def test_execute_skill_preserves_successful_jump_host_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    refused = _FakeSocket(
        clock,
        connect_duration=0.05,
        connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
    )
    connected = _FakeSocket(
        clock,
        connect_duration=0.05,
        send_duration=0.05,
        recv_results=((0.05, b"\x023"), (0.0, b"")),
    )
    factory = _SocketFactory([refused, connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill("1+2", timeout=1.0)

    assert result.status == ExecutionStatus.SUCCESS
    assert result.output == "3"
    assert result.execution_time == pytest.approx(0.4)
    assert clock.sleeps == [0.2]
    assert len(factory.created) == 2


@pytest.mark.parametrize("phase", ["send", "shutdown", "recv"])
@pytest.mark.parametrize(
    "operation_class", [OperationClass.READ_ONLY, OperationClass.MUTATING]
)
def test_execute_skill_transport_reset_after_dispatch_is_unknown_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    operation_class: OperationClass,
) -> None:
    clock = _FakeClock()
    reset = OSError(10054, "connection reset by peer")
    kwargs: dict[str, object] = {}
    if phase == "send":
        kwargs["send_error"] = reset
    elif phase == "shutdown":
        kwargs["shutdown_error"] = reset
    else:
        kwargs["recv_results"] = ((0.0, reset),)
    connected = _FakeSocket(clock, **kwargs)
    factory = _SocketFactory([connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "dbCreateRect(cv list(0:0 1:1))",
        timeout=1.0,
        operation_class=operation_class,
        request_id="req-reset-001",
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN
    assert result.operation_class == operation_class
    assert result.request_id == "req-reset-001"
    assert result.protocol_version == 3
    assert "10054" in result.errors[0]
    assert len(factory.created) == 1


def test_execute_skill_preserves_pre_dispatch_reset_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    reset = _FakeSocket(
        clock,
        connect_error=OSError(errno.ECONNRESET, "connection reset by peer"),
    )
    connected = _FakeSocket(
        clock,
        recv_results=((0.0, b"\x023"), (0.0, b"")),
    )
    factory = _SocketFactory([reset, connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill("1+2", timeout=1.0)

    assert result.status == ExecutionStatus.SUCCESS
    assert result.output == "3"
    assert len(factory.created) == 2


def test_execute_skill_unretryable_pre_dispatch_error_is_not_dispatched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    unreachable = _FakeSocket(
        clock,
        connect_error=OSError(errno.ENETUNREACH, "network unreachable"),
    )
    factory = _SocketFactory([unreachable])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "1+2", timeout=1.0, request_id="req-unreachable-001"
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.NOT_DISPATCHED
    assert result.request_id == "req-unreachable-001"
    assert result.protocol_version == 3
    assert "network unreachable" in result.errors[0]
    assert len(factory.created) == 1


def test_execute_skill_empty_response_after_dispatch_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    factory = _SocketFactory([_FakeSocket(clock, recv_results=((0.0, b""),))])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "dbSave(cv)",
        timeout=1.0,
        operation_class=OperationClass.MUTATING,
        request_id="req-empty-001",
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN
    assert result.request_id == "req-empty-001"


def test_no_cached_duplicate_response_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    response = b"\x15REQUEST_ALREADY_SEEN_NO_CACHED_RESPONSE"
    factory = _SocketFactory([
        _FakeSocket(clock, recv_results=((0.0, response), (0.0, b"")))
    ])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "dbSave(cv)",
        timeout=1.0,
        operation_class=OperationClass.MUTATING,
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN


def test_execute_skill_gives_daemon_time_to_return_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    connected = _FakeSocket(
        clock,
        recv_results=((0.0, b"\x023"), (0.0, b"")),
    )
    factory = _SocketFactory([connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient(auth_token="test-token").execute_skill(
        "1+2",
        timeout=10.0,
        operation_class=OperationClass.READ_ONLY,
        request_id="req-fixed-001",
    )

    assert result.status == ExecutionStatus.SUCCESS
    request = json.loads(connected.sent_payloads[0].decode("utf-8"))
    assert request["timeout"] == pytest.approx(9.5)
    assert request["protocol_version"] == 3
    assert request["supported_protocol_versions"] == [3, 2]
    assert request["request_id"] == "req-fixed-001"
    assert request["operation_class"] == "read_only"
    assert request["auth_token"] == "test-token"
    assert result.request_id == "req-fixed-001"
    assert result.protocol_version == 2


def test_execute_skill_daemon_timeout_is_unknown_commit_for_mutating_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    connected = _FakeSocket(
        clock,
        recv_results=((0.0, b"\x15TimeoutError: CIW still busy"), (0.0, b"")),
    )
    factory = _SocketFactory([connected])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "dbCreateRect(cv list(0:0 1:1))",
        timeout=1.0,
        operation_class=OperationClass.MUTATING,
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.operation_class == OperationClass.MUTATING
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN


def test_protocol_v3_verified_frame_and_busy_metadata() -> None:
    request_id = "req-v3-busy"
    request_digest = "b" * 64
    raw = _v3_frame(
        request_id,
        b"BRIDGE_BUSY",
        status="busy",
        marker="NAK",
        request_digest_sha256=request_digest,
        retry_after=1.0,
        queue_depth=4,
        queue_capacity=4,
        supported_protocol_versions=[2, 3],
        capabilities=["bounded-queue-v1"],
    )

    result = VirtuosoClient._parse_response(
        raw,
        0.1,
        operation_class=OperationClass.READ_ONLY,
        request_id=request_id,
        request_digest_sha256=request_digest,
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.NOT_DISPATCHED
    assert result.protocol_version == 3
    assert result.metadata["frame_integrity"] == "verified"
    assert result.metadata["retry_after"] == 1.0
    assert result.metadata["queue_depth"] == 4
    assert result.metadata["queue_capacity"] == 4
    assert result.metadata["daemon_capabilities"] == ["bounded-queue-v1"]


@pytest.mark.parametrize("mutation", ["truncate", "payload", "footer", "request-id"])
def test_protocol_v3_rejects_incomplete_or_tampered_frames(mutation: str) -> None:
    request_id = "req-v3-tamper"
    digest = "c" * 64
    raw = _v3_frame(
        request_id,
        b"3",
        request_digest_sha256=digest,
    )
    if mutation == "truncate":
        raw = raw[:-1]
    elif mutation == "payload":
        payload_index = len(raw) - len(bridge._V3_FOOTER) - 1
        raw = raw[:payload_index] + b"4" + raw[payload_index + 1:]
    elif mutation == "footer":
        raw = raw[:-1] + b"!"
    else:
        raw = _v3_frame(
            "another-request",
            b"3",
            request_digest_sha256=digest,
        )

    result = VirtuosoClient._parse_response(
        raw,
        0.1,
        request_id=request_id,
        request_digest_sha256=digest,
    )

    assert result.status == ExecutionStatus.ERROR
    assert result.completion == CompletionStatus.TIMED_OUT_UNKNOWN
    assert result.metadata["frame_integrity"] == "invalid"


def test_protocol_v3_falls_back_only_on_exact_legacy_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    rejected = _FakeSocket(
        clock,
        recv_results=((0.0, b"\x15PROTOCOL_V2_REQUIRED"), (0.0, b"")),
    )
    accepted = _FakeSocket(
        clock,
        recv_results=((0.0, b"\x023"), (0.0, b"")),
    )
    factory = _SocketFactory([rejected, accepted])
    _use_fake_network(monkeypatch, clock, factory)

    result = VirtuosoClient().execute_skill(
        "1+2", timeout=1.0, request_id="req-v3-fallback"
    )

    first = json.loads(rejected.sent_payloads[0].decode("utf-8"))
    second = json.loads(accepted.sent_payloads[0].decode("utf-8"))
    assert result.status == ExecutionStatus.SUCCESS
    assert result.protocol_version == 2
    assert first["protocol_version"] == 3
    assert second["protocol_version"] == 2
    assert first["request_id"] == second["request_id"] == "req-v3-fallback"
    assert len(factory.created) == 2


def test_load_il_classifies_the_request_as_mutating(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    script = tmp_path / "check.il"
    script.write_text("t\n", encoding="utf-8")
    client = VirtuosoClient(log_to_ciw=False)
    observed: dict[str, object] = {}

    def fake_execute(skill_code, timeout=None, operation_class=OperationClass.UNKNOWN):
        observed["skill_code"] = skill_code
        observed["timeout"] = timeout
        observed["operation_class"] = operation_class
        return bridge.VirtuosoResult(status=ExecutionStatus.SUCCESS, output="t")

    monkeypatch.setattr(client, "execute_skill", fake_execute)

    result = client.load_il(script)

    assert result.status == ExecutionStatus.SUCCESS
    assert observed["operation_class"] == OperationClass.MUTATING
