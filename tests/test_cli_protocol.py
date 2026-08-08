from __future__ import annotations

import json

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.transport.tunnel import SSHClient


pytestmark = pytest.mark.unit


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

    rc = cli.main([
        "request-reconcile", "req-orphan", "-p", "v231",
        "--timeout", "1", "--poll-interval", "0.01",
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["reconciliation"]["outcome"] == "indeterminate_terminal"
    assert payload["reconciliation"]["safe_to_clear_quarantine"] is False


@pytest.mark.parametrize("state", ["queued", "response_too_large", "duplicate_replayed"])
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

    rc = cli.main([
        "request-reconcile", "req-unsafe", "-p", "v231",
        "--timeout", "0.05", "--poll-interval", "0.01",
    ])

    payload = json.loads(capsys.readouterr().out)
    if state == "queued":
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
