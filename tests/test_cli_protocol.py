from __future__ import annotations

import json

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.transport.tunnel import SSHClient


pytestmark = pytest.mark.unit

_EXPECTED_DIGEST = "a" * 64
_EXPECTED_BUILD = "b" * 64
_EXPECTED_EPOCH = "epoch-proof"
_EXPECTED_GENERATION = "generation-proof"


def _reconcile_cli_args(request_id: str, timeout: str = "1") -> list[str]:
    return [
        "request-reconcile", request_id, "-p", "v231",
        "--timeout", timeout, "--poll-interval", "0.01",
        "--expected-request-digest-sha256", _EXPECTED_DIGEST,
        "--expected-operation-class", "mutating",
        "--expected-daemon-epoch", _EXPECTED_EPOCH,
        "--expected-daemon-build-sha256", _EXPECTED_BUILD,
        "--expected-request-generation", _EXPECTED_GENERATION,
        "--expected-protocol-version", "3",
    ]


def _proven_terminal_request(request_id: str) -> dict[str, object]:
    return {
        "request_id": request_id,
        "state": "succeeded_after_timeout",
        "request_digest_sha256": _EXPECTED_DIGEST,
        "operation_class": "mutating",
        "protocol_version": 3,
        "request_generation": _EXPECTED_GENERATION,
        "admitted_daemon_epoch": _EXPECTED_EPOCH,
        "admitted_daemon_build_sha256": _EXPECTED_BUILD,
        "response_marker": "STX",
        "response_digest_sha256": "c" * 64,
        "payload_digest_sha256": "d" * 64,
        "response_size_bytes": 2,
        "finished_at_epoch": 123.5,
        "terminal_proof": {
            "schema_version": 1,
            "complete_frame": True,
            "state": "succeeded_after_timeout",
            "request_id": request_id,
            "request_digest_sha256": _EXPECTED_DIGEST,
            "operation_class": "mutating",
            "protocol_version": 3,
            "request_generation": _EXPECTED_GENERATION,
            "daemon_epoch": _EXPECTED_EPOCH,
            "daemon_build_sha256": _EXPECTED_BUILD,
            "response_marker": "STX",
            "response_digest_sha256": "c" * 64,
            "payload_digest_sha256": "d" * 64,
            "response_size_bytes": 2,
            "finished_at_epoch": 123.5,
        },
    }


def test_request_status_command_prints_filtered_ledger(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "schema_version": 1,
            "daemon_epoch": "epoch-1",
            "request": {"request_id": request_id, "state": "succeeded"},
        }),
    )

    rc = cli.main(["request-status", "req-1", "-p", "v231"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["request"] == {"request_id": "req-1", "state": "succeeded"}


def test_json_envelope_wraps_request_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "schema_version": 1,
            "daemon_epoch": "epoch-1",
            "request": {"request_id": request_id, "state": "timed_out_pending"},
        }),
    )

    rc = cli.main([
        "--json-envelope", "request-status", "req-timeout", "-p", "v231",
    ])

    assert rc == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["schema_version"] == 1
    assert envelope["command"] == "request-status"
    assert envelope["profile"] == "v231"
    assert envelope["ok"] is True
    assert envelope["exit_code"] == 0
    assert envelope["request_id"] == "req-timeout"
    assert envelope["data"]["request"]["state"] == "timed_out_pending"
    assert envelope["evidence"] == []


def test_json_envelope_converts_handler_exception(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "cli_status", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    rc = cli.main(["--json-envelope", "status", "-p", "v231"])

    assert rc == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert envelope["status"] == "error"
    assert envelope["errors"] == ["boom"]


def test_request_await_polls_until_known_terminal_state(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    states = iter(["running", "timed_out_pending", "succeeded_after_timeout"])

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        return {
            "schema_version": 1,
            "daemon_epoch": "epoch-1",
            "request": {"request_id": request_id, "state": next(states), "response_marker": "STX"},
        }

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    rc = cli.main([
        "request-await", "req-late", "-p", "v231",
        "--timeout", "5", "--poll-interval", "0.01",
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["request"]["state"] == "succeeded_after_timeout"
    assert payload["reconciliation"]["outcome"] == "known_terminal"
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is True



def test_request_reconcile_requires_two_identical_complete_terminal_proofs(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    calls = 0

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        nonlocal calls
        calls += 1
        return {
            "schema_version": 1,
            "daemon_epoch": _EXPECTED_EPOCH,
            "daemon_build_sha256": _EXPECTED_BUILD,
            "heartbeat_at_epoch": 123.5,
            "request": _proven_terminal_request(request_id),
        }

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    rc = cli.main(_reconcile_cli_args("req-proven"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == 2
    assert payload["reconciliation"]["outcome"] == "known_terminal"
    assert payload["reconciliation"]["stable_reads"] == 2
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is True
    assert payload["reconciliation"]["proof_errors"] == []


def test_request_reconcile_rejects_conflicting_terminal_proof(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        request = _proven_terminal_request(request_id)
        request["terminal_proof"]["daemon_epoch"] = "epoch-conflict"
        return {
            "schema_version": 1,
            "daemon_epoch": _EXPECTED_EPOCH,
            "daemon_build_sha256": _EXPECTED_BUILD,
            "request": request,
        }

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))

    rc = cli.main(_reconcile_cli_args("req-conflict"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    reconciliation = payload["reconciliation"]
    assert reconciliation["outcome"] == "terminal_proof_invalid"
    assert reconciliation["safe_to_clear_quarantine"] is False
    assert "terminal-proof-daemon-epoch-mismatch" in reconciliation["proof_errors"]


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    (
        ("finished_at_epoch", float("nan"), "terminal-proof-finished-at-invalid"),
        ("response_size_bytes", True, "terminal-proof-response-size-invalid"),
    ),
)
def test_request_reconcile_rejects_nonfinite_or_noninteger_proof_numbers(
    monkeypatch,
    capsys,
    field,
    value,
    expected_error,
) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        request = _proven_terminal_request(request_id)
        request[field] = value
        request["terminal_proof"][field] = value
        return {
            "schema_version": 1,
            "daemon_epoch": _EXPECTED_EPOCH,
            "daemon_build_sha256": _EXPECTED_BUILD,
            "heartbeat_at_epoch": 123.5,
            "request": request,
        }

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))
    rc = cli.main(_reconcile_cli_args("req-bad-number"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    reconciliation = payload["reconciliation"]
    assert reconciliation["safe_to_clear_quarantine"] is False
    assert expected_error in reconciliation["proof_errors"]





def test_request_reconcile_stability_resets_after_missing_snapshot(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    proven = {
        "schema_version": 1,
        "daemon_epoch": _EXPECTED_EPOCH,
        "daemon_build_sha256": _EXPECTED_BUILD,
        "request": _proven_terminal_request("req-consecutive"),
    }
    snapshots = iter([proven, None, proven, proven])
    calls = 0

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        nonlocal calls
        calls += 1
        return next(snapshots)

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    rc = cli.main(_reconcile_cli_args("req-consecutive"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == 4
    assert payload["reconciliation"]["stable_reads"] == 2
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is True
def test_request_reconcile_without_expected_anchor_fails_closed(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "schema_version": 1,
            "daemon_epoch": _EXPECTED_EPOCH,
            "daemon_build_sha256": _EXPECTED_BUILD,
            "request": _proven_terminal_request(request_id),
        }),
    )

    rc = cli.main([
        "request-reconcile", "req-no-anchor", "-p", "v231",
        "--timeout", "1", "--poll-interval", "0.01",
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    reconciliation = payload["reconciliation"]
    assert reconciliation["outcome"] == "terminal_proof_invalid"
    assert reconciliation["safe_to_clear_quarantine"] is False
    assert any(
        error.startswith("missing-expected-")
        for error in reconciliation["proof_errors"]
    )
def test_request_reconcile_preserves_indeterminate_restart_state(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "schema_version": 1,
            "daemon_epoch": "epoch-2",
            "request": {
                "request_id": request_id,
                "state": "orphaned_unknown_after_daemon_restart",
            },
        }),
    )

    rc = cli.main(_reconcile_cli_args("req-orphan"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["reconciliation"]["outcome"] == "indeterminate_terminal"
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is False


@pytest.mark.parametrize(
    "state",
    ["queued", "late_waiting_operator", "response_too_large", "duplicate_replayed"],
)
def test_request_reconcile_never_clears_unsafe_queue_or_transport_states(
    monkeypatch, capsys, state: str
) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "read_request_status",
        classmethod(lambda cls, profile=None, request_id=None, timeout=10.0: {
            "schema_version": 1,
            "daemon_epoch": "epoch-unsafe",
            "request": {"request_id": request_id, "state": state},
        }),
    )

    rc = cli.main(_reconcile_cli_args("req-unsafe", timeout="0.05"))

    payload = json.loads(capsys.readouterr().out)
    if state in {"queued", "late_waiting_operator"}:
        assert rc == 2
        assert payload["reconciliation"]["outcome"] == "wait_timeout"
    else:
        assert rc == 0
        assert payload["reconciliation"]["outcome"] == "indeterminate_terminal"
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is False


def test_deployment_status_command_is_machine_readable(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    monkeypatch.setattr(
        SSHClient,
        "deployment_status",
        classmethod(lambda cls, profile=None, timeout=10.0: {
            "schema_version": 1,
            "profile": profile,
            "local_matches_deployed": True,
            "deployed_matches_running": True,
            "running_heartbeat_fresh": True,
        }),
    )

    rc = cli.main(["deployment-status", "-p", "v231", "--timeout", "2"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile"] == "v231"
    assert payload["deployed_matches_running"] is True


def test_request_await_retries_missing_snapshot_and_detects_epoch_change(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "_load_cli_env", lambda: None)
    snapshots = iter([
        None,
        {
            "schema_version": 1,
            "daemon_epoch": "epoch-1",
            "request": {"request_id": "req-restart", "state": "running"},
        },
        {
            "schema_version": 1,
            "daemon_epoch": "epoch-2",
            "request": None,
        },
    ])

    def read_status(cls, profile=None, request_id=None, timeout=10.0):
        return next(snapshots)

    monkeypatch.setattr(SSHClient, "read_request_status", classmethod(read_status))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    rc = cli.main([
        "request-await", "req-restart", "-p", "v231",
        "--timeout", "1", "--poll-interval", "0.01",
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["daemon_epoch_changed"] is True
    assert payload["reconciliation"]["state"] == "orphaned_unknown_after_daemon_restart"
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is False
