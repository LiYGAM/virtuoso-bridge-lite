"""Recovery policy, proof, persistence and no-replay regression checks."""
import copy
import json
import time
from types import SimpleNamespace

import pytest

from virtuoso_bridge.recovery import RecoveryEngine, RecoveryRefused, RecoveryStore, expected_proof
from .test_cli_protocol import _proven_terminal_request

pytestmark = pytest.mark.unit


class Backend:
    def __init__(self):
        self.calls = []
        self.data = {"identity": {"epoch": "old", "ciw_pid": 3}, "deployment": {"deployment_id": "fixed"},
                     "identity_verified": True, "idle": True, "relaunch_supported": True,
                     "daemon_alive": True, "heartbeat_fresh": True, "transport_available": True}
        self.request = _proven_terminal_request("original")
        self.ledger_result = {"daemon_epoch": "epoch-proof", "daemon_build_sha256": "b" * 64,
                              "requests": [self.request]}
        self.complete = True
        self.health_error = False
        self.change_on_health = None
    def snapshot(self): return copy.deepcopy(self.data)
    def ledger(self, request_id=None): return copy.deepcopy(self.ledger_result)
    def authorize(self, policy): self.calls.append("authorize")
    def revoke(self, policy): self.calls.append("revoke")
    def connect(self, timeout): self.calls.append("connect")
    def health(self, expected):
        self.calls.append("health")
        if self.change_on_health: self.change_on_health()
        if self.health_error: raise RecoveryRefused("fixture-health-failed")
    def lifecycle(self, action, pending, policy, timeout): self.calls.append(action)
    def release(self, pending): self.calls.append("release")
    def resolve(self, pending, epoch):
        self.calls.append("manual-resolve")
        return {"released": True}
    def observe_lifecycle(self, pending):
        self.calls.append("observe")
        if not self.complete: return None
        result = self.snapshot()
        result["identity"]["epoch"] = "new"
        return result


@pytest.fixture
def subject(tmp_path):
    store = RecoveryStore(tmp_path, "fixture")
    backend = Backend()
    return RecoveryEngine(store, backend), store, backend


def quarantine(store, *, operation="read_only", expired=False):
    q = {"schemaVersion": 3, "proofAnchor": {"complete": True, "requestId": "original",
         "requestDigestSha256": "a" * 64, "operationClass": operation, "daemonEpoch": "epoch-proof",
         "daemonBuildSha256": "b" * 64, "requestGeneration": "generation-proof", "protocolVersion": 3},
         "bridgeResult": {"request_id": "original", "completion": "timed_out_unknown", "operation_class": operation,
             "protocol_version": 3, "metadata": {"request_digest_sha256": "a" * 64}}}
    store.quarantine_path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(q, indent=2).encode()
    store.quarantine_path.write_bytes(raw)
    return q, raw


def make_readonly(backend):
    backend.request["operation_class"] = "read_only"
    backend.request["terminal_proof"]["operation_class"] = "read_only"


def test_default_proof_recovery_archives_and_preserves_original(subject):
    engine, store, backend = subject
    q, raw = quarantine(store)
    make_readonly(backend)
    result = engine.run(timeout=1)
    assert result["recovery_state"] == "recovered"
    assert result["quarantine_cleared"] and not store.quarantine_path.exists()
    assert result["original_completion"] == "timed_out_unknown"
    assert not result["original_request_replayed"] and not result["workflow_resume_allowed"]
    archive = json.loads(open(result["archive_path"], encoding="utf-8").read())
    assert archive["originalQuarantineJson"].encode() == raw
    assert backend.calls == ["health"]


@pytest.mark.parametrize("operation", ["read_only", "mutating", "unknown"])
def test_expiry_proof_works_without_complete_execution_frame(subject, operation):
    engine, store, backend = subject
    q, _ = quarantine(store, operation=operation)
    _, expected = expected_proof(q)
    backend.request.clear()
    backend.request.update(expected, request_id="original", state="expired_before_dispatch",
        admitted_daemon_epoch=expected["daemon_epoch"], admitted_daemon_build_sha256=expected["daemon_build_sha256"],
        execution_dispatched=False, finished_at_epoch=123.0,
        pre_dispatch_proof=dict(expected, request_id="original", state="expired_before_dispatch", schema_version=1,
                                execution_dispatched=False, finished_at_epoch=123.0))
    assert engine.run(timeout=1)["quarantine_cleared"]
    assert backend.calls == ["health"]


@pytest.mark.parametrize("fault", ["digest", "generation", "epoch", "stored", "frame", "health", "archive"])
def test_proof_failure_keeps_quarantine(subject, monkeypatch, fault):
    engine, store, backend = subject
    q, raw = quarantine(store)
    make_readonly(backend)
    if fault == "digest": backend.request["request_digest_sha256"] = "x"
    if fault == "generation": backend.request["request_generation"] = "other"
    if fault == "epoch": backend.ledger_result["daemon_epoch"] = "other"
    if fault == "stored":
        q["bridgeResult"]["metadata"]["daemon_epoch"] = "other"
        raw = json.dumps(q).encode(); store.quarantine_path.write_bytes(raw)
    if fault == "frame": backend.request["terminal_proof"]["complete_frame"] = False
    if fault == "health": backend.health_error = True
    if fault == "archive": monkeypatch.setattr(store, "archive", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    result = engine.run(timeout=1)
    assert result["recovery_state"] == "blocked" and not result["quarantine_cleared"]
    assert not result["admission_allowed"]
    assert store.quarantine_path.read_bytes() == raw
    assert not any(c.startswith("daemon_") for c in backend.calls)


def test_mutating_proof_needs_separate_grant(subject):
    engine, store, backend = subject
    quarantine(store, operation="mutating")
    assert engine.run(timeout=1)["stop_reason"] == "action-not-authorized:proven_mutating"
    engine.grant(["proven_mutating"], "permit proven terminal recovery")
    result = engine.run(timeout=1)
    assert result["quarantine_cleared"] and not result["workflow_resume_allowed"]


@pytest.mark.parametrize("fault", ["expired", "revoked", "identity", "deployment", "action"])
def test_grant_boundaries(subject, fault):
    engine, store, backend = subject
    engine.grant(["connect"], "fixture permission")
    policy = store.read("policy.json")
    if fault == "expired": policy["expires_at"] = 1
    if fault == "revoked": policy["revoked"] = True
    if fault == "identity": backend.data["identity"]["ciw_pid"] = 99
    if fault == "deployment": backend.data["deployment"]["deployment_id"] = "unreviewed"
    if fault == "action": policy["actions"] = []
    store.write("policy.json", policy)
    result = engine.run(timeout=1, action="connect")
    assert result["recovery_state"] == "blocked"
    assert backend.calls == ["authorize"]


def test_revoke_during_health_keeps_quarantine(subject):
    engine, store, backend = subject
    quarantine(store)
    make_readonly(backend)
    engine.grant(["proven_read_only"], "fixture")
    backend.change_on_health = lambda: engine.revoke()
    assert not engine.run(timeout=1)["quarantine_cleared"]
    assert store.quarantine_path.exists()


def test_changed_quarantine_during_health_is_not_released(subject):
    engine, store, backend = subject
    quarantine(store); make_readonly(backend)
    backend.change_on_health = lambda: store.quarantine_path.write_text('{"new":"incident"}')
    assert engine.run(timeout=1)["stop_reason"] == "quarantine-changed"
    assert json.loads(store.quarantine_path.read_text()) == {"new": "incident"}


def test_lifecycle_intent_is_observed_once_and_authority_follows_proven_epoch(subject):
    engine, store, backend = subject
    engine.grant(["daemon_restart"], "one bounded restart")
    result = engine.run(timeout=1, action="daemon_restart")
    assert result["recovery_state"] == "recovered"
    assert backend.calls.count("daemon_restart") == 1
    assert not store.read("pending.json")
    assert engine.policy()["identity"]["epoch"] == "new"


def test_lost_lifecycle_reply_is_not_replayed(subject):
    engine, store, backend = subject
    engine.grant(["daemon_restart"], "one bounded restart")
    backend.complete = False
    result = engine.run(timeout=0.05, action="daemon_restart")
    assert result["recovery_state"] == "unknown"
    assert store.read("pending.json")
    again = engine.run(timeout=0.05, action="daemon_restart")
    assert again["recovery_id"] == result["recovery_id"]
    assert backend.calls.count("daemon_restart") == 1
    assert len(store.read("failures.json")) == 1


def test_stale_intent_can_be_verified_without_replay(subject):
    engine, store, backend = subject
    engine.grant(["daemon_restart"], "fixture")
    backend.complete = False
    first = engine.run(timeout=0.02, action="daemon_restart")
    backend.complete = True
    result = engine.run(timeout=1)
    assert result["recovery_state"] == "recovered"
    assert result["recovery_id"] == first["recovery_id"]
    assert backend.calls.count("daemon_restart") == 1


@pytest.mark.parametrize("fault", ["busy", "alive", "quarantine", "limit"])
def test_no_lifecycle_when_guards_fail(subject, fault):
    engine, store, backend = subject
    engine.grant(["daemon_relaunch"], "fixture")
    backend.data["daemon_alive"] = False
    if fault == "busy": backend.data["idle"] = False
    if fault == "alive": backend.data["daemon_alive"] = True
    if fault == "quarantine": quarantine(store)
    if fault == "limit": store.write("failures.json", [time.time(), time.time()])
    assert engine.run(timeout=1, action="daemon_relaunch")["recovery_state"] == "blocked"
    assert "daemon_relaunch" not in backend.calls


def test_executor_lock_rejects_competing_recovery(subject):
    engine, store, backend = subject
    other = RecoveryStore(store.root, store.profile)
    with store.lock(), pytest.raises(RecoveryRefused, match="already-running"):
        with other.lock(): pass


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0, -1, True, 61])
def test_invalid_budget_never_calls_backend(subject, value):
    engine, store, backend = subject
    with pytest.raises(ValueError): engine.run(timeout=value)
    assert not backend.calls


def test_revocation_tombstone_survives_stale_policy_writer(subject):
    engine, store, backend = subject
    original = engine.grant(["daemon_restart"], "fixture")
    with store.lock(): engine.revoke()
    store.write("policy.json", original)
    assert not engine.policy()["active"]
    assert engine.run(timeout=1, action="daemon_restart")["recovery_state"] == "blocked"
    assert "daemon_restart" not in backend.calls


def test_null_filtered_request_is_pending_not_crash(subject):
    engine, store, backend = subject
    quarantine(store)
    backend.ledger_result = {"request": None}
    assert engine.run(timeout=0.02)["stop_reason"] == "recovery-budget-exhausted"
    assert store.quarantine_path.exists()


def test_connect_retries_only_transient_errors_within_budget(subject, monkeypatch):
    from virtuoso_bridge.recovery_backend import BridgeRecoveryBackend
    engine, store, backend = subject
    count = []
    def connect(timeout):
        count.append(timeout)
        if len(count) < 3: raise OSError("Connection reset by peer")
    backend.connect = connect
    backend.transient = BridgeRecoveryBackend.transient
    monkeypatch.setattr(time, "sleep", lambda t: None)
    result = engine.run(timeout=1, action="connect")
    assert result["recovery_state"] == "recovered" and result["attempts"] == 3
    assert len(count) == 3 and all(0 < value <= 1 for value in count)


@pytest.mark.parametrize("message", ["Permission denied (publickey)", "Host key changed", "configuration mismatch"])
def test_connect_does_not_retry_authentication_or_identity_faults(subject, message):
    from virtuoso_bridge.recovery_backend import BridgeRecoveryBackend
    engine, store, backend = subject
    def connect(timeout):
        backend.calls.append("connect")
        raise OSError(message)
    backend.connect = connect
    backend.transient = BridgeRecoveryBackend.transient
    assert engine.run(timeout=1, action="connect")["recovery_state"] == "blocked"
    assert backend.calls == ["connect"]


def test_absolute_backend_budget_expires_between_suboperations(monkeypatch):
    from virtuoso_bridge.recovery_backend import BridgeRecoveryBackend
    backend = object.__new__(BridgeRecoveryBackend)
    backend.timeout, backend.deadline = 15, 5
    monkeypatch.setattr(time, "monotonic", lambda: 4)
    assert backend.budget() == 1
    monkeypatch.setattr(time, "monotonic", lambda: 5)
    with pytest.raises(RecoveryRefused, match="budget-exhausted"): backend.budget()


def test_monitor_waits_for_changes_after_refusal(subject, monkeypatch):
    from virtuoso_bridge.recovery_cli import _watch_worker
    engine, store, backend = subject
    store.write("watch.json", {"enabled": True, "token": "owned", "interval": 0})
    ticks, calls = [], []
    def inspect():
        ticks.append(1)
        if len(ticks) == 8: store.write("watch.json", {"enabled": False})
        return {"fault_class": "daemon-exited", "identity": {"epoch": "same"}, "policy": engine.policy()}
    engine.inspect = inspect
    def run(**kwargs):
        calls.append(kwargs)
        return {"recovery_state": "blocked", "stop_reason": "not-authorized"}
    engine.run = run
    _watch_worker(SimpleNamespace(watch_token="owned", timeout=1), store, engine)
    assert len(calls) == 1 and len(ticks) == 8
    assert store.read("notice.json")["result"]["stop_reason"] == "not-authorized"


def test_proven_original_can_be_reconciled_after_authorized_relaunch(subject):
    engine, store, backend = subject
    engine.grant(["proven_read_only", "daemon_relaunch"], "fixture")
    q, raw = quarantine(store)
    make_readonly(backend)
    backend.data["daemon_alive"] = False
    result = engine.run(timeout=1)
    assert result["quarantine_cleared"] and result["recovery_state"] == "recovered"
    assert result["original_completion"] == "timed_out_unknown" and not result["workflow_resume_allowed"]
    assert backend.calls.count("daemon_relaunch") == 1
    assert not store.quarantine_path.exists()


@pytest.mark.parametrize("missing", ["id", "epoch", "reason", "ack"])
def test_manual_resolution_requires_explicit_review(subject, missing):
    engine, store, backend = subject
    values = {"recovery_id": "owned", "epoch": "fresh", "reason": "reviewed", "acknowledge": True}
    key = {"id": "recovery_id", "epoch": "epoch", "reason": "reason", "ack": "acknowledge"}[missing]
    values[key] = False if missing == "ack" else ""
    with pytest.raises(RecoveryRefused): engine.resolve(**values)
    assert not backend.calls


def test_manual_resolution_archives_unknown_without_replay(subject):
    engine, store, backend = subject
    engine.grant(["daemon_restart"], "fixture")
    backend.complete = False
    original = engine.run(timeout=0.01, action="daemon_restart")
    result = engine.resolve(original["recovery_id"], "fresh", "Inspected the owned session", True)
    assert result["acknowledged_unknown"] and not result["original_outcome_changed"]
    assert backend.calls.count("daemon_restart") == 1 and not store.read("pending.json")
    assert not engine.policy()["active"]


def test_only_attributed_exclusive_lifecycle_orphans_can_be_retired():
    from virtuoso_bridge.resources.recovery_control import retired_lifecycle
    request = {"request_id": "owned", "state": "orphaned_unknown_after_daemon_restart", "exclusive": True,
               "operation_class": "mutating", "admitted_daemon_epoch": "old"}
    assert retired_lifecycle(request, {"owned": "old"})
    assert not retired_lifecycle(request, {})
    assert not retired_lifecycle(request, {"owned": "different"})
    assert not retired_lifecycle(dict(request, exclusive=False), {"owned": "old"})


def test_incomplete_identity_during_reload_is_only_observed():
    from virtuoso_bridge.recovery_backend import BridgeRecoveryBackend
    backend = object.__new__(BridgeRecoveryBackend)
    backend.snapshot = lambda: {"identity_verified": False}
    assert backend.observe_lifecycle({"expected": {}}) is None


@pytest.mark.parametrize("field", ["root", "operator", "profile"])
def test_copied_grant_cannot_authorize_another_context(subject, field):
    engine, store, backend = subject
    policy = engine.grant(["daemon_restart"], "fixture")
    policy[field] = "other"
    store.write("policy.json", policy)
    assert not engine.policy()["active"]
    assert engine.run(timeout=1, action="daemon_restart")["recovery_state"] == "blocked"
    assert "daemon_restart" not in backend.calls
