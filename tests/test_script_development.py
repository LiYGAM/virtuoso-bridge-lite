"""Focused regression checks for the script-development review findings."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from virtuoso_bridge import VirtuosoClient
from virtuoso_bridge.models import CompletionStatus, ExecutionStatus, VirtuosoResult
from virtuoso_bridge.script_loading import prepare_script, loaded_scripts, finish_receipt
from virtuoso_bridge.virtuoso.development import context_expression, editor_context, guard_context
from virtuoso_bridge.virtuoso.layout import layout_clear_routing, layout_clear_all_shapes
from virtuoso_bridge.virtuoso.layout.reader import parse_layout_geometry_output
from virtuoso_bridge.recovery import RecoveryEngine, RecoveryStore, RecoveryRefused
from virtuoso_bridge import recovery_cli

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("VB_HOME", str(tmp_path / "runtime"))


def success(**fields):
    return VirtuosoResult(status=ExecutionStatus.SUCCESS, output="t", metadata={"daemon_epoch": "epoch"}, **fields)


def identity_response(prepared):
    result = success()
    key = hashlib.sha256(prepared['source_path'].encode()).hexdigest()
    result.output = f'("epoch" nil 1 (("{key}" "{prepared["load_id"]}")))'
    return result


def test_same_basename_and_repeated_loads_never_share_remote_artifacts(tmp_path):
    files = {}
    class Tunnel:
        remote_work_dir = "/owned"
        def upload_text(self, text, path, **kwargs):
            assert kwargs["exclusive_create"] and not kwargs["retry_transport_errors"]
            assert path not in files
            files[path] = text
            return SimpleNamespace(returncode=0)
    client = SimpleNamespace(_tunnel=Tunnel())
    a, b = tmp_path / "a/helper.il", tmp_path / "b/helper.il"
    for path, text in ((a, "versionA"), (b, "versionB")):
        path.parent.mkdir(); path.write_text(text)
    prepared = [prepare_script(client, p) for p in (a, b, a)]
    assert len({p["artifact_path"] for p in prepared}) == 3
    assert [files[p["artifact_path"]] for p in prepared] == ["versionA", "versionB", "versionA"]


def test_fixed_source_bytes_and_stale_expected_digest(tmp_path):
    source = tmp_path / "source.il"
    original = b't\r\n'
    source.write_bytes(original)
    prepared = prepare_script(SimpleNamespace(_tunnel=None), source)
    source.write_text("nil")
    assert Path(prepared["artifact_path"]).read_bytes() == original
    assert prepared["source_sha256"] == hashlib.sha256(original).hexdigest()
    with pytest.raises(ValueError, match="source-changed"):
        prepare_script(SimpleNamespace(_tunnel=None), source, expected_sha256=prepared["source_sha256"])


def test_declared_sibling_bundle_preserves_lazy_load_paths(tmp_path):
    source = tmp_path / "main.il"
    source.write_text('; Dependency: sibling helper.il\nget_filename(piport)\n')
    helper = tmp_path / "helper.il"; helper.write_text('"captured"')
    prepared = prepare_script(SimpleNamespace(_tunnel=None), source)
    helper.write_text('"new"')
    assert (Path(prepared["artifact_path"]).parent / "helper.il").read_text() == '"captured"'
    assert len(prepared["captured_files"]) == 2 and len(prepared["source_map"]) == 2


def test_missing_declared_dependency_fails_before_dispatch(tmp_path):
    source = tmp_path / "main.il"; source.write_text('; Dependency: sibling missing.il\n')
    with pytest.raises(FileNotFoundError): prepare_script(SimpleNamespace(_tunnel=None), source)


def test_headless_run_has_one_bound_load_save_request(tmp_path, monkeypatch):
    source = tmp_path / "source.il"; source.write_text("t")
    client = VirtuosoClient(log_to_ciw=False)
    calls = []
    monkeypatch.setattr(client, "execute_skill", lambda code, **kw: (calls.append(code), success())[1])
    result = client.run_il_file(source, "fixture", "target", open_window=False, save=True)
    assert result.ok and len(calls) == 1
    assert "geGetEditCellView" not in calls[0]
    assert '"fixture" "target" "layout"' in calls[0]
    assert "dbSave(vbDevTarget)" in calls[0]
    assert calls[0].index("script-changed-bound-target") < calls[0].index("dbSave(")


@pytest.mark.parametrize("text,expected", [("1e-05:2e-05", (1e-5, 2e-5)), ("-.5:+.25", (-.5, .25)), ("1E+3:-2E2", (1000, -200))])
def test_geometry_numbers(text, expected):
    assert parse_layout_geometry_output("instance\txy=" + text)[0]["xy"] == expected


@pytest.mark.parametrize("text", ["1:2:3", "nan:2", "1e:2", "1e999:2"])
def test_geometry_rejects_invalid_numbers(text):
    with pytest.raises(ValueError):
        parse_layout_geometry_output("instance\txy=" + text)


def test_cleanup_requires_scope_and_defaults_to_preview():
    command = layout_clear_routing(lib="owned", cell="fixture", lpps=[("M1", "drawing")])
    assert '"preview"' in command and "dbDeleteObject" not in command and "dbSave" not in command
    assert "!shape~>pin" in command and "techGetLP" in command and "hiGetWindowList" not in command
    with pytest.raises(ValueError):
        layout_clear_routing(lib="owned", cell="fixture", lpps=[])
    with pytest.raises(ValueError, match="expected_context"):
        layout_clear_routing(lib="owned", cell="fixture", lpps=[("M1", "drawing")], apply=True)
    with pytest.raises(ValueError, match="confirm_all"):
        layout_clear_all_shapes(lib="owned", cell="fixture", apply=True)


def test_context_guards_reject_truncation_and_run_before_payload():
    with pytest.raises(ValueError):
        guard_context("mutate()", {"schema_version": 1, "complete": False, "signature": "context", "selection_limit": 1})
    code = guard_context("mutate()", {"schema_version": 1, "complete": True, "signature": "context", "selection_limit": 1})
    assert code.index("editor-context-changed") < code.index("mutate()")
    with pytest.raises(ValueError): context_expression(501)


def test_context_failed_read_is_not_an_empty_success():
    client = SimpleNamespace(execute_skill=lambda *a, **kw: VirtuosoResult(status=ExecutionStatus.ERROR, completion=CompletionStatus.TIMED_OUT_UNKNOWN))
    with pytest.raises(RuntimeError, match="not confirmed"):
        editor_context(client)


def test_receipts_keep_unknown_failed_and_other_epoch_distinct(tmp_path):
    source = tmp_path / "source.il"; source.write_text("t")
    client = VirtuosoClient(log_to_ciw=False)
    for epoch, status, completion in (("old", "success", "confirmed"), ("epoch", "error", "confirmed"), ("epoch", "error", "timed_out_unknown")):
        prepared = prepare_script(client, source); prepared["started_at"] = len(list((tmp_path / "runtime").rglob("*.json")))
        result = VirtuosoResult(status=status, completion=completion, metadata={"daemon_epoch": epoch})
        finish_receipt(client, prepared, result)
    client.execute_skill = lambda *a, **kw: identity_response(prepared)
    result = loaded_scripts(client)
    assert len(result["history"]) == 3 and len(result["latest"]) == 1
    assert result["latest"][0]["status"] == "completion-unknown"
    assert any(r["status"] == "failed-may-be-partial" for r in result["history"])


def test_receipt_write_failure_preserves_completed_result(tmp_path, monkeypatch):
    from virtuoso_bridge import script_loading
    source = tmp_path / "source.il"; source.write_text("t")
    client = VirtuosoClient(log_to_ciw=False)
    prepared = prepare_script(client, source)
    monkeypatch.setattr(script_loading, "write_receipt", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    result = finish_receipt(client, prepared, success())
    assert result.ok and result.warnings and result.metadata["script_load"]["status"] == "load-returned"


def test_unattributed_load_invalidates_older_current_version(tmp_path):
    from virtuoso_bridge.script_loading import write_receipt
    source = tmp_path / "source.il"; source.write_text("t")
    client = VirtuosoClient(log_to_ciw=False)
    prepared = prepare_script(client, source); prepared["started_at"] = 1
    finish_receipt(client, prepared, success())
    pending = prepare_script(client, source); pending.update(started_at=2, status="dispatch-pending-or-unknown")
    write_receipt(client, pending)
    client.execute_skill = lambda *a, **kw: identity_response(prepared)
    assert loaded_scripts(client)["latest"][0]["status"] == "epoch-unattributed-load"


def test_recovery_timeout_and_deadline_do_not_leak(tmp_path, monkeypatch):
    backend = SimpleNamespace(timeout=15, deadline=None, snapshot=lambda: (_ for _ in ()).throw(RecoveryRefused("unavailable")))
    engine = RecoveryEngine(RecoveryStore(tmp_path, "owned"), backend)
    engine.run(timeout=.01)
    assert backend.timeout == 15 and backend.deadline is None
    monkeypatch.setattr(engine.store, "write", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError): engine.run(timeout=.01)
    assert backend.timeout == 15 and backend.deadline is None


def test_monitor_reassesses_late_proof_but_not_heartbeat_noise(tmp_path, monkeypatch):
    store = RecoveryStore(tmp_path, "owned")
    store.write("watch.json", {"enabled": True, "token": "test", "interval": 0})
    ticks = iter(range(10000))
    monkeypatch.setattr(recovery_cli.time, "monotonic", lambda: next(ticks))
    class Engine:
        observations = 0
        attempts = 0
        def inspect(self):
            self.observations += 1
            if self.observations >= 8: store.write("watch.json", {"enabled": False})
            return {"fault_class": "quarantined", "identity": {"epoch": "same"},
                    "quarantine": {"bridgeResult": {"request_id": "original"}},
                    "ledger": {"heartbeat_at": self.observations, "requests": [{"request_id": "original", "state": "timed_out_pending" if self.observations < 5 else "succeeded_after_timeout"}]}}
        def run(self, **kw):
            self.attempts += 1
            return {"recovery_state": "blocked", "stop_reason": "fixture"}
    engine = Engine()
    recovery_cli._watch_worker(SimpleNamespace(watch_token="test", timeout=1), store, engine)
    assert engine.attempts == 2


def test_dependency_hints_ignore_comments_and_strings(tmp_path):
    from virtuoso_bridge.script_dependencies import dependency_hints
    source = tmp_path / "source.il"
    (tmp_path / "child.il").write_text("t")
    source.write_text('; load("fake.il")\n"load(\\\"fake2.il\\\")"\nload("child.il")\nload(dynamicPath)')
    result = dependency_hints(source)
    assert len(result["items"]) == 2 and result["items"][0]["resolved"]
    assert result["items"][1]["expression"] == "dynamic"
