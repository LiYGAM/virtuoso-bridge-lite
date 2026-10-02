from dataclasses import asdict

import pytest

from virtuoso_bridge.transport.ssh import CommandResult
from virtuoso_bridge.virtuoso.sos import SOSCellViewState, SOSCellViewTarget
from tests.test_sos_cellview import (
    DIRECTORY, MASTER, PATH, ROOT, _Client, _skill_ok, _state, _unmanaged,
)


class DiagnosticClient(_Client):
    def run_command(self, command, *, timeout=None):
        if command.endswith(" version"):
            self.commands.append(command)
            return CommandResult(0, "SOS 7.05.p3", "")
        return super().run_command(command, timeout=timeout)


def receipt(action="ci"):
    before = SOSCellViewState("p", "O", "M", "-", "-", "-", "3")
    if action == "co":
        before = SOSCellViewState("p", "-", "-", "-", "-", "-", "3")
    elif action == "cancel_co":
        before = SOSCellViewState("p", "O", "-", "-", "-", "-", "3")
    elif action == "register":
        before = SOSCellViewState("d", "?", "?", "?", "?", "?", "?")
    target = SOSCellViewTarget("lib", "cell", "schematic_Vt", directory=DIRECTORY,
                               master=MASTER, view_type="schematic", workarea=ROOT, path=PATH)
    return {"action": action, "outcome": "unknown", "before": asdict(before), "target": asdict(target)}


@pytest.mark.parametrize("unmanaged", [False, True])
def test_doctor_queries_capabilities_version_and_target_without_mutation(unmanaged):
    client = DiagnosticClient(before=_unmanaged() if unmanaged else _state("-", "-", "4"))
    result = client.sos.diagnose_cellview("lib", "cell", "schematic_Vt")
    assert result["ok"] and all(check["ok"] for check in result["checks"])
    assert result["eligibility"]["register"]["outcome"] == ("dry_run" if unmanaged else "blocked")
    assert "cancel_co" in result["eligibility"]
    assert not client.writes
    assert not any("history" in cmd or "diff" in cmd for cmd in client.commands)


def test_doctor_missing_sos_is_actionable_and_does_not_write():
    client = DiagnosticClient()
    client.run_command = lambda *a, **kw: CommandResult(127, "", "SOS not installed")
    result = client.sos.diagnose_cellview("lib", "cell", "schematic_Vt")
    assert not result["ok"] and result["outcome"] == "blocked"
    assert "127" in result["checks"][-1]["detail"]
    assert not client.writes


@pytest.mark.parametrize("reason", ["Library is not managed by SOS.", "Required Cadence API unavailable: ddCheckout"])
def test_doctor_missing_integration_or_api_is_blocked(reason):
    import json
    client = DiagnosticClient()
    client.resolution = _skill_ok('(\"blocked\" ' + json.dumps(reason) + ')')
    result = client.sos.diagnose_cellview("lib", "cell", "schematic_Vt")
    assert not result["ok"] and result["eligibility"] == {}
    assert any(reason in check["detail"] for check in result["checks"])
    assert not client.writes


def test_doctor_reports_dirty_target_without_saving_it():
    client = DiagnosticClient(dirty=True)
    result = client.sos.diagnose_cellview("lib", "cell", "schematic_Vt")
    assert result["ok"] and result["target"]["unsaved"]
    assert all(item["outcome"] == "blocked" for item in result["eligibility"].values())
    assert not client.writes
    assert all("dbSave(" not in code for code, _ in client.skill_calls)


@pytest.mark.parametrize("action,after", [
    ("ci", _state("-", "-", "4")), ("co", _state("O", "-", "3")),
    ("cancel_co", _state("-", "-", "3")),
    ("register", _state("-", "-", "1")),
])
def test_reconciliation_observes_expected_state_but_never_confirms_or_retries(action, after):
    client = _Client(before=after)
    result = client.sos.reconcile_cellview("lib", "cell", "schematic_Vt", receipt=receipt(action))
    assert result["assessment"] == "expected_state_observed"
    assert result["outcome"] == "unknown" and not result["ok"] and not result["operation_confirmed"]
    assert not client.writes and len(client.skill_calls) == 1
    assert sum("status -Nhdr" in cmd for cmd in client.commands) == 1


@pytest.mark.parametrize("change,expected", [("path", "target_changed"), ("state", "expected_state_not_observed"),
                                             ("timeout", "unavailable")])
def test_reconciliation_mismatches_and_query_failure_remain_unknown(change, expected):
    old = receipt()
    if change == "path":
        old["target"]["master"] += ".other"
    client = _Client(before=TimeoutError("offline") if change == "timeout" else _state())
    result = client.sos.reconcile_cellview("lib", "cell", "schematic_Vt", receipt=old)
    assert result["assessment"] == expected and result["outcome"] == "unknown"
    assert not client.writes


@pytest.mark.parametrize("field,value", [("outcome", "success"), ("action", "status"), ("before", None),
                                         ("target", {"lib": "other"})])
def test_invalid_receipt_rejected_before_network_access(field, value):
    old = receipt()
    old[field] = value
    client = _Client()
    with pytest.raises(ValueError):
        client.sos.reconcile_cellview("lib", "cell", "schematic_Vt", receipt=old)
    assert not client.commands and not client.skill_calls
