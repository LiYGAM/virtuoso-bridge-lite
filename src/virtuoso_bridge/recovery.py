"""Bounded, proof-gated recovery. Restoring a channel never replays its request."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
import uuid

from virtuoso_bridge.transport.tunnel import _atomic_write_json

ACTIONS = frozenset({"connect", "proven_read_only", "proven_not_dispatched",
                     "proven_mutating", "daemon_restart", "daemon_relaunch"})
DEFAULT_ACTIONS = frozenset({"connect", "proven_read_only", "proven_not_dispatched"})
LIFECYCLE_ACTIONS = frozenset({"daemon_restart", "daemon_relaunch"})
TERMINAL = frozenset({"succeeded", "failed", "succeeded_after_timeout", "failed_after_timeout",
                      "expired_before_dispatch"})


class RecoveryRefused(RuntimeError):
    pass


def finite_seconds(value, maximum=3600):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError("Invalid recovery time budget")
    return float(value)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def expected_proof(quarantine):
    anchor = quarantine.get("proofAnchor") or {}
    result = quarantine.get("bridgeResult") or {}
    metadata = result.get("metadata") or {}
    expected = {"request_digest_sha256": anchor.get("requestDigestSha256"),
                "operation_class": anchor.get("operationClass"), "daemon_epoch": anchor.get("daemonEpoch"),
                "daemon_build_sha256": anchor.get("daemonBuildSha256"),
                "request_generation": anchor.get("requestGeneration"), "protocol_version": anchor.get("protocolVersion")}
    if (not anchor.get("complete") or result.get("completion") != "timed_out_unknown"
            or anchor.get("requestId") != result.get("request_id")
            or expected["request_digest_sha256"] != metadata.get("request_digest_sha256")
            or expected["operation_class"] != result.get("operation_class")
            or expected["protocol_version"] != result.get("protocol_version")):
        raise RecoveryRefused("quarantine-proof-anchor-mismatch")
    for key in ("daemon_epoch", "daemon_build_sha256", "request_generation"):
        if metadata.get(key) not in (None, "", expected[key]):
            raise RecoveryRefused("quarantine-stored-identity-conflict")
    return result["request_id"], expected


def proven_request(ledger, quarantine):
    from virtuoso_bridge.cli import _terminal_proof_errors
    request_id, expected = expected_proof(quarantine)
    request = next((r for r in (ledger or {}).get("requests", []) if r.get("request_id") == request_id), None)
    if not request and ((ledger or {}).get("request") or {}).get("request_id") == request_id:
        request = ledger["request"]
    if not request or request.get("state") not in TERMINAL:
        raise RecoveryRefused("terminal-proof-not-available")
    if _terminal_proof_errors(request, request_id, expected):
        raise RecoveryRefused("terminal-proof-invalid")
    if any(ledger.get(key) != expected[key] for key in ("daemon_epoch", "daemon_build_sha256")):
        raise RecoveryRefused("terminal-proof-daemon-changed")
    return request, expected


class RecoveryStore:
    def __init__(self, root, profile):
        self.root = Path(root).resolve()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", profile or "") or profile in {".", ".."}:
            raise ValueError("Recovery requires an explicit safe profile")
        self.profile = profile
        self.base = self.root / "tmp/virtuoso_bridge/recovery" / profile
        self.quarantine_path = self.root / "tmp/virtuoso_bridge/quarantine" / (profile + ".json")

    def read(self, name, default=None):
        path = self.base / name
        if path.is_symlink():
            raise RecoveryRefused("recovery-state-symlink")
        return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else default

    def write(self, name, data):
        self.base.mkdir(parents=True, exist_ok=True)
        path = self.base / name
        if path.is_symlink():
            raise RecoveryRefused("recovery-state-symlink")
        _atomic_write_json(path, data)
        if os.name != "nt": os.chmod(path, 0o600)

    @contextmanager
    def lock(self):
        self.base.mkdir(parents=True, exist_ok=True)
        with (self.base / "executor.lock").open("a+b") as stream:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                try:
                    if os.fstat(stream.fileno()).st_size == 0: stream.write(b"0"); stream.flush()
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc: raise RecoveryRefused("recovery-already-running") from exc
            else:
                import fcntl
                try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc: raise RecoveryRefused("recovery-already-running") from exc
            try: yield
            finally:
                if os.name == "nt":
                    stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else: fcntl.flock(stream, fcntl.LOCK_UN)

    def quarantine(self):
        if self.quarantine_path.is_symlink(): raise RecoveryRefused("quarantine-symlink")
        raw = self.quarantine_path.read_bytes() if self.quarantine_path.exists() else None
        return (json.loads(raw.decode("utf-8-sig")), raw) if raw else (None, None)

    def archive(self, original, record):
        if self.quarantine_path.read_bytes() != original: raise RecoveryRefused("quarantine-changed")
        archive_dir = self.quarantine_path.parent / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        path = archive_dir / (self.profile + "-" + uuid.uuid4().hex + ".json")
        data = {"schemaVersion": 1, "profile": self.profile,
                "originalQuarantineJson": original.decode("utf-8-sig"),
                "originalQuarantine": json.loads(original.decode("utf-8-sig")),
                "originalResultReclassified": False, "originalRequestReplayed": False,
                "recovery": record, "archivedUtc": datetime.now(timezone.utc).isoformat()}
        with path.open("xb") as stream:
            stream.write(json.dumps(data, ensure_ascii=False).encode("utf-8")); stream.flush(); os.fsync(stream.fileno())
        if self.quarantine_path.read_bytes() != original: raise RecoveryRefused("quarantine-changed-after-archive")
        self.quarantine_path.unlink()
        return str(path)


class RecoveryEngine:
    def __init__(self, store, backend):
        self.store, self.backend = store, backend

    def policy(self):
        policy = self.store.read("policy.json")
        if not policy:
            return {"policy_id": "built-in", "actions": sorted(DEFAULT_ACTIONS), "active": True,
                    "source": "existing-defaults"}
        policy = dict(policy)
        policy["active"] = (not policy.get("revoked") and policy.get("expires_at", 0) > time.time()
                            and policy.get("root") == str(self.store.root) and policy.get("profile") == self.store.profile
                            and str(policy.get("operator", "")).lower() == getpass.getuser().lower()
                            and not self.store.read("revoked/" + policy["policy_id"] + ".json"))
        return policy

    def grant(self, actions, reason, hours=8):
        hours = finite_seconds(hours, 8)
        if not actions or set(actions) - ACTIONS or not reason.strip():
            raise ValueError("Explicit allowed actions and a nonempty reason are required")
        with self.store.lock():
            snapshot = self.backend.snapshot()
            if not snapshot.get("identity_verified") or not snapshot.get("idle"):
                raise RecoveryRefused("grant-requires-verified-idle-session")
            if LIFECYCLE_ACTIONS.intersection(actions) and not snapshot.get("relaunch_supported"):
                raise RecoveryRefused("session-lifecycle-capability-unavailable")
            policy = {"schema_version": 1, "policy_id": uuid.uuid4().hex, "profile": self.store.profile,
                      "root": str(self.store.root), "actions": sorted(set(actions)), "reason": reason,
                      "operator": getpass.getuser(), "created_at": time.time(), "expires_at": time.time() + hours * 3600,
                      "identity": snapshot["identity"], "deployment": snapshot["deployment"],
                      "revoked": False, "max_incident_seconds": 60, "max_lifecycle_per_incident": 1}
            # A local grant is not active until its target-side authorization exists.
            self.backend.authorize(policy)
            self.store.write("policy.json", policy)
            return self.policy()

    def revoke(self):
        # Revocation must remain usable while a recovery is awaiting its receipt.
        policy = self.store.read("policy.json") or {"policy_id": "revoked-defaults", "actions": []}
        self.store.write("revoked/" + policy["policy_id"] + ".json", {"at": time.time()})
        policy.update(revoked=True, expires_at=0)
        self.store.write("policy.json", policy)
        self.backend.revoke(policy)
        return self.policy()

    def _authorize(self, action, snapshot, policy):
        if not policy.get("active") or action not in policy.get("actions", []):
            raise RecoveryRefused("action-not-authorized:" + action)
        if policy["policy_id"] != "built-in":
            if snapshot.get("identity") != policy.get("identity"):
                raise RecoveryRefused("authorized-session-identity-changed")
            if snapshot.get("deployment") != policy.get("deployment"):
                raise RecoveryRefused("authorized-deployment-changed")

    def resolve(self, recovery_id, epoch, reason, acknowledge=False):
        if not acknowledge or not reason.strip() or not recovery_id or not epoch:
            raise RecoveryRefused("manual-resolution-requires-id-epoch-reason-and-acknowledgement")
        with self.store.lock():
            pending = self.store.read("pending.json")
            if not pending or pending["recovery_id"] != recovery_id:
                raise RecoveryRefused("pending-recovery-id-mismatch")
            self.revoke()
            result = self.backend.resolve(pending, epoch)
            record = {"recovery_id": recovery_id, "reason": reason, "acknowledged_unknown": True,
                      "original_outcome_changed": False, "original_request_replayed": False,
                      "workflow_resume_allowed": False, "resolved_at": time.time(), "evidence": result,
                      "original_pending": pending}
            self.store.write("manual/" + recovery_id + ".json", record)
            self.store.write("pending.json", None)
            return record

    @staticmethod
    def pending_request(snapshot):
        requests = snapshot.get("blocking_requests") or (snapshot.get("ledger") or {}).get("requests", [])
        return next((r for r in requests if r.get("state") in {"timed_out_pending", "late_waiting_operator"}), None)

    def inspect(self):
        snapshot = self.backend.snapshot()
        quarantine, _ = self.store.quarantine()
        fault = "healthy"
        pending_request = self.pending_request(snapshot)
        if quarantine: fault = "quarantined"
        elif not snapshot.get("identity_verified"): fault = "identity-unverified"
        elif not snapshot.get("daemon_alive"): fault = "daemon-exited"
        elif not snapshot.get("heartbeat_fresh"): fault = "daemon-unresponsive"
        elif not snapshot.get("transport_available"): fault = "transport-disconnected"
        elif pending_request:
            fault = "request-needs-attention" if pending_request["state"] == "late_waiting_operator" else "request-timeout-pending"
        elif any(str(r.get("state", "")).startswith("orphaned_") for r in snapshot.get("blocking_requests", [])):
            fault = "unknown-work"
        snapshot.update(fault_class=fault, quarantine=quarantine, policy=self.policy())
        snapshot["activity"] = pending_request["state"] if pending_request else "idle" if snapshot.get("idle") else "running"
        snapshot["pending_request_id"] = (pending_request or {}).get("request_id")
        snapshot["pending"] = self.store.read("pending.json")
        if snapshot["pending"]: snapshot["fault_class"] = "lifecycle-pending"
        return snapshot

    def run(self, *, timeout=60, action="auto", automatic=False):
        previous_deadline = getattr(self.backend, "deadline", None)
        try:
            return self._run_incident(timeout=timeout, action=action, automatic=automatic)
        finally:
            self.backend.deadline = previous_deadline

    def _run_incident(self, *, timeout=60, action="auto", automatic=False):
        timeout = finite_seconds(timeout, 60)
        end = time.monotonic() + timeout
        self.backend.deadline = end
        def remaining():
            value = end - time.monotonic()
            if value <= 0: raise RecoveryRefused("recovery-budget-exhausted")
            return value
        with self.store.lock():
            remaining()
            quarantine, raw = self.store.quarantine()
            record = {"schema_version": 1, "recovery_id": uuid.uuid4().hex, "profile": self.store.profile,
                      "started_at": time.time(), "recovery_state": "inspecting", "actions": [],
                      "trigger": "automatic" if automatic else "explicit", "attempts": 0,
                      "before_identity": None, "after_identity": None,
                      "fault_class": "quarantined" if quarantine else "inspecting",
                      "original_request_id": (quarantine or {}).get("bridgeResult", {}).get("request_id"),
                      "original_completion": "timed_out_unknown" if quarantine else None,
                      "original_request_replayed": False, "workflow_resume_allowed": not bool(quarantine),
                      "transport_available": False, "admission_allowed": False, "quarantine_cleared": False}
            policy = self.policy()
            record["policy_id"] = policy["policy_id"]
            try:
                # Ambiguous lifecycle intents are only observed, never redispatched.
                pending = self.store.read("pending.json")
                if pending:
                    return self._observe_pending(pending, record, policy, remaining)
                if quarantine and action == "auto":
                    while True:
                        remaining()
                        ledger = self.backend.ledger(record["original_request_id"])
                        try:
                            request, expected = proven_request(ledger, quarantine)
                            break
                        except RecoveryRefused as exc:
                            if str(exc) != "terminal-proof-not-available": raise
                            time.sleep(min(0.2, remaining()))
                    proof_action = ("proven_not_dispatched" if request["state"] == "expired_before_dispatch" else
                                    "proven_read_only" if expected["operation_class"] == "read_only" else "proven_mutating")
                    snapshot = self._snapshot_with_retry(remaining, record) if policy["policy_id"] != "built-in" else {}
                    self._authorize(proof_action, snapshot, policy)
                    remaining()
                    second, _ = proven_request(self.backend.ledger(record["original_request_id"]), quarantine)
                    if second != request: raise RecoveryRefused("terminal-proof-not-stable")
                    if snapshot.get("identity_verified") and not snapshot.get("daemon_alive"):
                        record.update(proof_action=proof_action, proven_request=request,
                                      quarantine_sha256=hashlib.sha256(raw).hexdigest())
                        return self._begin_lifecycle("daemon_relaunch", snapshot, record, policy, remaining)
                    if not getattr(self.backend, "transport_available", lambda: True)():
                        self._authorize("connect", snapshot, self.policy())
                        self.backend.connect(remaining())
                    self.backend.health(expected)
                    remaining()
                    self._authorize(proof_action, snapshot, self.policy())
                    record.update(recovery_state="recovered", transport_available=True, admission_allowed=True,
                                  actions=[proof_action], terminal_state=request["state"], attempts=1,
                                  before_identity=expected, after_identity=expected)
                    record["archive_path"] = self.store.archive(raw, record)
                    record["quarantine_cleared"] = True
                else:
                    snapshot = self._snapshot_with_retry(remaining, record)
                    record["before_identity"] = snapshot.get("identity")
                    record["fault_class"] = ("daemon-exited" if not snapshot.get("daemon_alive") else
                                             "transport-disconnected" if not snapshot.get("transport_available") else "channel-present")
                    if quarantine: raise RecoveryRefused("lifecycle-refused-while-quarantined")
                    if action == "auto":
                        pending_request = self.pending_request(snapshot)
                        if pending_request:
                            record.update(fault_class=pending_request["state"], original_request_id=pending_request.get("request_id"),
                                          original_completion="timed_out_unknown")
                            raise RecoveryRefused("original-request-pending-no-replay")
                        if not snapshot.get("identity_verified"): raise RecoveryRefused("identity-unverified")
                        action = "daemon_relaunch" if not snapshot.get("daemon_alive") else "connect"
                    self._authorize(action, snapshot, policy)
                    if action == "connect":
                        for attempt in range(3):
                            remaining()
                            self._authorize(action, snapshot, self.policy())
                            record["attempts"] = attempt + 1
                            try:
                                self.backend.connect(remaining())
                                after = self.backend.snapshot()
                                break
                            except Exception as exc:
                                if attempt == 2 or not getattr(self.backend, "transient", lambda e: False)(exc): raise
                                time.sleep(min(2 ** attempt, remaining()))
                        if (not after.get("identity_verified") or not after.get("transport_available") or not after.get("heartbeat_fresh")
                                or after.get("identity") != snapshot.get("identity")):
                            raise RecoveryRefused("transport-or-daemon-unavailable-after-connect")
                        record.update(recovery_state="recovered" if after.get("idle") else "partial",
                                      actions=[action], transport_available=True,
                                      admission_allowed=after.get("idle", False), after_identity=after.get("identity"))
                        if not after.get("idle"):
                            record.update(stop_reason="channel-available-but-work-unresolved", workflow_resume_allowed=False)
                    elif action in LIFECYCLE_ACTIONS:
                        if automatic and action == "daemon_restart": raise RecoveryRefused("restart-requires-explicit-trigger")
                        return self._begin_lifecycle(action, snapshot, record, policy, remaining)
                    else: raise RecoveryRefused("unsupported-recovery-action")
            except Exception as exc:
                record.update(recovery_state="blocked", stop_reason=str(exc), admission_allowed=False,
                              workflow_resume_allowed=False)
            finally:
                record["ended_at"] = time.time()
                self.store.write("last.json", record)
                self.store.write("incidents/" + record["recovery_id"] + ".json", record)
                self.backend.deadline = None
            return record

    def _snapshot_with_retry(self, remaining, record):
        for attempt in range(3):
            remaining()
            record["inspection_attempts"] = attempt + 1
            try: return self.backend.snapshot()
            except Exception as exc:
                if attempt == 2 or not getattr(self.backend, "transient", lambda e: False)(exc): raise
                time.sleep(min(2 ** attempt, remaining()))

    def _begin_lifecycle(self, action, snapshot, record, policy, remaining):
        self._authorize(action, snapshot, self.policy())
        if not snapshot.get("idle") or not snapshot.get("identity_verified"):
            raise RecoveryRefused("lifecycle-requires-verified-idle-session")
        if action == "daemon_relaunch" and snapshot.get("daemon_alive"):
            raise RecoveryRefused("old-daemon-still-alive")
        failures = self.store.read("failures.json", [])
        if len([t for t in failures if t > time.time() - 900]) >= 2:
            raise RecoveryRefused("lifecycle-failure-limit")
        record.update(recovery_state="intent", actions=[action], expected=snapshot, attempts=1,
                      expires_at=min(time.time() + remaining(), policy["expires_at"]))
        self.store.write("pending.json", record)
        try: self.backend.lifecycle(action, record, policy, remaining())
        except Exception as exc: record["dispatch_error"] = str(exc)
        return self._observe_pending(record, record, policy, remaining)

    def _observe_pending(self, pending, record, policy, remaining):
        record.update(recovery_id=pending["recovery_id"], actions=pending["actions"])
        try:
            while True:
                remaining()
                result = self.backend.observe_lifecycle(pending)
                if result:
                    record.update(recovery_state="recovered", transport_available=True, admission_allowed=True,
                                  after_identity=result["identity"], evidence=result.get("evidence"))
                    current = self.policy()
                    if pending.get("proof_action"):
                        quarantine, raw = self.store.quarantine()
                        if not raw or hashlib.sha256(raw).hexdigest() != pending["quarantine_sha256"]:
                            raise RecoveryRefused("quarantine-changed-during-lifecycle")
                        self._authorize(pending["proof_action"], result if current.get("identity") == result["identity"]
                                        else pending["expected"], current)
                        from virtuoso_bridge.cli import _terminal_proof_errors
                        request_id, expected = expected_proof(quarantine)
                        ledger = self.backend.ledger(request_id)
                        request = next((r for r in (ledger or {}).get("requests", []) if r.get("request_id") == request_id),
                                       (ledger or {}).get("request"))
                        if not request or _terminal_proof_errors(request, request_id, expected):
                            raise RecoveryRefused("original-proof-not-preserved-after-relaunch")
                        for field in ("terminal_proof", "pre_dispatch_proof"):
                            if request.get(field) != pending["proven_request"].get(field):
                                raise RecoveryRefused("original-proof-changed-after-relaunch")
                        record.update(original_request_id=request_id, original_completion="timed_out_unknown",
                                      workflow_resume_allowed=False)
                        record["archive_path"] = self.store.archive(raw, record)
                        record["quarantine_cleared"] = True
                    if current.get("policy_id") == pending["policy_id"] and current.get("active"):
                        current["identity"] = result["identity"]
                        self.backend.authorize(current)
                        self.store.write("policy.json", current)
                    self.backend.release(pending)
                    self.store.write("pending.json", None)
                    return record
                if time.time() >= pending["expires_at"]:
                    raise RecoveryRefused("lifecycle-outcome-unverified-no-replay")
                time.sleep(min(0.5, remaining()))
        except Exception as exc:
            record.update(recovery_state="unknown", stop_reason=str(exc), workflow_resume_allowed=False,
                          admission_allowed=False)
            failures = self.store.read("failures.json", [])
            if not pending.get("failure_recorded"):
                self.store.write("failures.json", [t for t in failures if t > time.time() - 900] + [time.time()])
                pending["failure_recorded"] = True
                self.store.write("pending.json", pending)
            return record
