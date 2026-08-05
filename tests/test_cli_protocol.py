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
        classmethod(lambda cls, profile=None, request_id=None: {
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
        classmethod(lambda cls, profile=None, request_id=None: {
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
