"""Production adapters for the recovery state machine; no implicit staging."""
from __future__ import annotations

import base64
import importlib.resources
import json
import shlex
import time

from virtuoso_bridge.recovery import RecoveryRefused, TERMINAL
from virtuoso_bridge.transport.tunnel import SSHClient, _is_localhost
from virtuoso_bridge.transport.ssh import SSHRunner
from virtuoso_bridge.resources.recovery_control import retired_lifecycle
from virtuoso_bridge.runtime_paths import state_dir


class RecoverySSHClient(SSHClient):
    """Keep recovery probes independent of a damaged persistent SSH shell."""
    def _new_role_runner(self, host, *, role, user=None):
        jump = self._jump_host
        if jump and host.strip().rstrip(".").lower() == jump.strip().rstrip(".").lower(): jump = None
        options = dict(self._runner_kwargs, control_master=False, verbose=False)
        runner = SSHRunner(host=host, user=user or self._remote_user, jump_host=jump,
                           persistent_shell=False, **options)
        self._role_runners[role] = runner
        return runner


class BridgeRecoveryBackend:
    def __init__(self, profile, timeout=15):
        self.profile, self.timeout = profile, timeout
        self.deadline = None
        self.ssh = RecoverySSHClient.from_env(profile=profile, create_auth_token=False, keep_remote_files=True)

    def close(self): self.ssh.close()

    def budget(self):
        value = self.timeout if self.deadline is None else min(self.timeout, self.deadline - time.monotonic())
        if value <= 0: raise RecoveryRefused("recovery-budget-exhausted")
        return value

    @staticmethod
    def transient(exc):
        message = str(exc).lower()
        if any(s in message for s in ("permission denied", "host key", "identity", "configuration", "authentication")):
            return False
        return any(s in message for s in ("connection reset", "connection refused", "connection timed out",
                                          "network is unreachable", "broken pipe"))

    def _control(self, action, *, state=None, role="gui", **kwargs):
        state = state or SSHClient.read_state(self.profile) or {}
        path = state.get("identity_path")
        if not path: raise RecoveryRefused("identity-path-unavailable")
        args = dict(action=action, identity_path=path, **kwargs)
        source = importlib.resources.files("virtuoso_bridge.resources").joinpath("recovery_control.py").read_text(encoding="utf-8")
        roles = state.get("profile_config") or {}
        hostname = roles.get("gui_host" if role == "gui" else "remote_host")
        if _is_localhost(hostname):
            namespace = {}
            exec(compile(source, "recovery_control.py", "exec"), namespace)
            return namespace["control"](args)
        payload = base64.b64encode(json.dumps(args).encode()).decode()
        program = source + "\nimport base64\nprint(json.dumps(control(json.loads(base64.b64decode('" + payload + "')))))\n"
        runner = self.ssh.gui_runner if role == "gui" else self.ssh.ssh_runner
        # Linux control-plane operations require Python 3; they never execute SKILL.
        encoded = base64.b64encode(program.encode()).decode()
        # Some EDA Python launchers re-parse -c arguments. Stdin preserves source bytes.
        response = runner.run_command("printf %s " + shlex.quote(encoded) + " | base64 -d | python3 -", timeout=self.budget(),
                                      retry_transport_errors=False)
        if response.returncode: raise RecoveryRefused("control-plane-failed: " + (response.stderr or response.stdout)[-1500:])
        return json.loads(response.stdout)

    def ledger(self, request_id=None):
        return RecoverySSHClient.read_request_status(self.profile, request_id=request_id, timeout=self.budget())

    def snapshot(self):
        if not SSHClient.staged_profile_config_matches_current(self.profile):
            raise RecoveryRefused("saved-profile-configuration-mismatch")
        state = SSHClient.read_state(self.profile) or {}
        ledger = self.ledger() or {}
        probe = self._control("inspect", state=state)
        banner, ciw = probe["identity"], probe["ciw"]
        completed = dict(probe.get("completed_recoveries", {}))
        receipts = state_dir() / "verified-restarts" / self.profile
        from virtuoso_bridge.cli import _restart_dispatch_attributed
        for path in receipts.glob("*.json"):
            receipt = json.loads(path.read_text(encoding="utf-8"))
            if (receipt.get("profile") == self.profile and _restart_dispatch_attributed(ledger,
                    receipt.get("request_id"), receipt.get("request_digest_sha256"), receipt.get("old_epoch"))):
                completed[receipt["request_id"]] = receipt["old_epoch"]
        daemon = self._control("daemon-process", state=state, role="daemon", daemon_pid=ledger.get("daemon_pid", 0))
        config = dict(state.get("profile_config") or {})
        config.pop("local_port", None)
        identity = {"profile": self.profile, "configuration": config,
                    "epoch": banner.get("epoch"), "profile_banner": banner.get("profile"),
                    "ciw_pid": banner.get("ciw_pid"), "ciw_session": banner.get("ciw_session"),
                    "ciw_start_ticks": ciw.get("start_ticks"), "ciw_boot_id": ciw.get("boot_id"),
                    "ciw_executable": ciw.get("executable"), "display": ciw.get("display"),
                    "daemon_pid": banner.get("pid"), "deployment_id": banner.get("deployment_id"),
                    "il_sha256": banner.get("il_sha256")}
        deployment = {k: state.get(k) for k in ("deployment_id", "deployed_daemon_sha256", "deployed_il_sha256",
            "deployed_setup_sha256", "deployed_daemon_path", "deployed_il_path", "setup_path", "identity_path", "request_state_path")}
        verified = bool(banner.get("identity_complete") == "1" and ciw.get("alive") and ciw.get("known")
            and ciw.get("start_ticks") and ciw.get("boot_id") and ciw.get("display")
            and banner.get("profile") == self.profile and banner.get("epoch") == ledger.get("daemon_epoch")
            and banner.get("pid") == str(ledger.get("daemon_pid")) and banner.get("deployment_id") == state.get("deployment_id")
            and banner.get("il_sha256") == state.get("deployed_il_sha256")
            and ledger.get("daemon_build_sha256") == state.get("deployed_daemon_sha256")
            and abs(probe["now"] - time.time()) < 5 and daemon.get("known"))
        heartbeat = ledger.get("heartbeat_at_epoch", 0)
        heartbeat_fresh = isinstance(heartbeat, (int, float)) and -1 <= time.time() - heartbeat <= 5
        requests = ledger.get("requests")
        idle = bool(isinstance(requests, list) and ledger.get("queue_depth") == 0
                    and not ledger.get("active_request_id") and not ledger.get("exclusive_request_id")
                    and all(r.get("state") in TERMINAL or retired_lifecycle(r, completed)
                        for r in requests))
        blocking = [{"request_id": r.get("request_id"), "state": r.get("state"),
                     "admitted_daemon_epoch": r.get("admitted_daemon_epoch")}
                    for r in (requests or []) if r.get("state") not in TERMINAL and not retired_lifecycle(r, completed)]
        return {"identity": identity, "deployment": deployment, "identity_verified": verified,
                "blocking_requests": blocking,
                "daemon_alive": daemon.get("alive"), "heartbeat_fresh": heartbeat_fresh, "idle": idle,
                "transport_available": SSHClient.is_running(self.profile), "ledger": ledger,
                "banner": banner, "ciw": ciw, "state": state, "log_cursor": probe.get("log_cursor"),
                "completed_recoveries": completed,
                "relaunch_supported": banner.get("recovery_mailbox_version") == "1"
                    and self.ssh.gui_host == self.ssh.daemon_host}

    def _target_args(self, snapshot):
        return {"state": snapshot["state"], "expected": snapshot["banner"], "ciw": snapshot["ciw"]}

    def authorize(self, policy):
        snapshot = self.snapshot()
        if snapshot["identity"] != policy["identity"]: raise RecoveryRefused("grant-target-changed")
        return self._control("authorize", **self._target_args(snapshot), policy_id=policy["policy_id"],
                             expires_at=policy["expires_at"], actions=policy["actions"],
                             daemon_path=snapshot["state"]["deployed_daemon_path"], setup_path=snapshot["state"]["setup_path"],
                             completed_recoveries=snapshot["completed_recoveries"])

    def revoke(self, policy): return self._control("revoke", policy_id=policy["policy_id"])

    def connect(self, timeout):
        return self.ssh.connect(timeout=min(timeout, self.budget()))

    def transport_available(self): return SSHClient.is_running(self.profile)

    def health(self, expected):
        from virtuoso_bridge.virtuoso.basic.bridge import VirtuosoClient
        from virtuoso_bridge.models import OperationClass
        from virtuoso_bridge.cli import _restart_busy_reason, _restart_heartbeat_is_fresh
        ledger = self.ledger()
        if (not ledger or _restart_busy_reason(ledger) or not _restart_heartbeat_is_fresh(ledger)
                or ledger.get("daemon_epoch") != expected["daemon_epoch"]
                or ledger.get("daemon_build_sha256") != expected["daemon_build_sha256"]):
            raise RecoveryRefused("fresh-idle-daemon-identity-required")
        state = SSHClient.read_state(self.profile) or {}
        client = VirtuosoClient(host="127.0.0.1", port=int(state["port"]), profile=self.profile,
                                auth_token=self.ssh.auth_token, log_to_ciw=False, timeout=min(self.budget(), 5))
        result = client.execute_skill("1+1", timeout=min(self.budget(), 5), operation_class=OperationClass.READ_ONLY)
        if (str(result.completion.value) != "confirmed" or result.output != "2" or result.errors
                or result.protocol_version != 3 or result.metadata.get("frame_integrity") != "verified"
                or any(result.metadata.get(k) != expected[k] for k in ("daemon_epoch", "daemon_build_sha256"))):
            raise RecoveryRefused("fresh-health-proof-failed")
        return result

    def lifecycle(self, action, pending, policy, timeout):
        snapshot = self.snapshot()
        if snapshot["identity"] != pending["expected"]["identity"] or not snapshot["idle"]:
            raise RecoveryRefused("lifecycle-preflight-changed")
        if not snapshot.get("log_cursor"): raise RecoveryRefused("ciw-log-cursor-unavailable")
        files = {snapshot["state"][p]: snapshot["state"][h] for p, h in (
            ("deployed_daemon_path", "deployed_daemon_sha256"), ("deployed_il_path", "deployed_il_sha256"),
            ("setup_path", "deployed_setup_sha256"))}
        self._control("relaunch" if action == "daemon_relaunch" else "claim", **self._target_args(snapshot),
                      recovery_id=pending["recovery_id"], policy_id=policy["policy_id"], files=files,
                      expires_at=pending["expires_at"], ledger_path=snapshot["state"]["request_state_path"],
                      same_host=self.ssh.gui_host == self.ssh.daemon_host)
        if action == "daemon_restart":
            from virtuoso_bridge.cli import _restart_daemon_one
            # The state snapshot pins immutable deployed files, even if local source changed.
            _restart_daemon_one(self.profile, timeout=self.budget(), _state_snapshot=snapshot["state"],
                                _recovery_id=pending["recovery_id"], _recovery_policy=policy,
                                _recovery_expires=pending["expires_at"])

    def observe_lifecycle(self, pending):
        current = self.snapshot()
        old = pending["expected"]
        # RBWriteIdentity publishes its completeness footer last during reload.
        if not current["identity_verified"]: return None
        before = dict(old["identity"])
        after = dict(current["identity"])
        for key in ("epoch", "daemon_pid"):
            before.pop(key, None); after.pop(key, None)
        if before != after or current["deployment"] != old["deployment"]:
            raise RecoveryRefused("lifecycle-target-changed")
        if (not current["heartbeat_fresh"]
                or current["identity"]["epoch"] == old["identity"]["epoch"]): return None
        if current["banner"].get("recovery_id") != pending["recovery_id"]:
            raise RecoveryRefused("new-daemon-not-attributable-to-recovery")
        # The original exclusive restart request may be orphaned by its own daemon replacement.
        others = [r for r in current["ledger"].get("requests", []) if r.get("request_id") != pending["recovery_id"]]
        if any(r.get("state") not in TERMINAL and not retired_lifecycle(r, current["completed_recoveries"]) for r in others):
            raise RecoveryRefused("unknown-work-after-recovery")
        self.health({"daemon_epoch": current["identity"]["epoch"],
                     "daemon_build_sha256": current["deployment"]["deployed_daemon_sha256"]})
        log = self._control("log-window", state=current["state"], cursor=old["log_cursor"])
        if log["errors"]: raise RecoveryRefused("recovery-cds-log-errors:" + "; ".join(log["errors"]))
        current["evidence"] = {"cds_log": log, "recovery_id": pending["recovery_id"]}
        return current

    def release(self, pending):
        snapshot = self.snapshot()
        return self._control("release", **self._target_args(snapshot), recovery_id=pending["recovery_id"],
                             old_epoch=pending["expected"]["identity"]["epoch"])

    def resolve(self, pending, epoch):
        snapshot = self.snapshot()
        ledger = snapshot["ledger"]
        if (not snapshot["identity_verified"] or snapshot["identity"]["epoch"] != epoch
                or ledger.get("active_request_id") or ledger.get("exclusive_request_id") or ledger.get("queue_depth") != 0):
            raise RecoveryRefused("manual-resolution-requires-verified-idle-epoch")
        for request in ledger.get("requests", []):
            if (request.get("state") not in TERMINAL and request.get("request_id") != pending["recovery_id"]
                    and not retired_lifecycle(request, snapshot["completed_recoveries"])):
                raise RecoveryRefused("other-unknown-work-requires-manual-inspection")
        if snapshot["identity"]["ciw_session"] != pending["expected"]["identity"]["ciw_session"]:
            raise RecoveryRefused("manual-resolution-ciw-changed")
        return self._control("release", **self._target_args(snapshot), recovery_id=pending["recovery_id"],
                             old_epoch=pending["expected"]["identity"]["epoch"], manual=True)
