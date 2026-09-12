"""CLI and opt-in monitor for the same recovery executor."""
from contextlib import contextmanager, redirect_stdout
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from virtuoso_bridge.recovery import RecoveryEngine, RecoveryRefused, RecoveryStore, finite_seconds


@contextmanager
def workspace_lock(store):
    path = store.root / "tmp/virtuoso_bridge/locks" / (store.profile + ".lock")
    inherited = os.environ.get("VB_BRIDGE_LOCK_OWNER")
    if inherited:
        from virtuoso_bridge.transport.ssh import _process_is_alive
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data.get("ownerToken") != inherited or not _process_is_alive(data.get("processId", 0)):
            raise RecoveryRefused("invalid-inherited-workspace-lock")
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                           wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        handle = create(str(path), 0xC0000000, 1, None, 4, 0x80, None)
        if handle == ctypes.c_void_p(-1).value: raise RecoveryRefused("workspace-busy")
        try: yield
        finally:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(handle)
    else:
        import fcntl
        with path.open("a+b") as stream:
            try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc: raise RecoveryRefused("workspace-busy") from exc
            try: yield
            finally: fcntl.flock(stream, fcntl.LOCK_UN)


def _watch_start(args, store):
    from virtuoso_bridge.transport.ssh import _process_is_alive
    with store.lock():
        previous = store.read("watch.json", {})
        status = store.read("watch-status.json", {})
        if (previous.get("enabled") and _process_is_alive(previous.get("pid", 0))
                and status.get("token") == previous.get("token") and not status.get("stopped")
                and time.time() - status.get("heartbeat_at", 0) < 90):
            return dict(previous, already_running=True)
        token = uuid.uuid4().hex
        record = {"enabled": True, "token": token, "interval": max(1, args.interval), "started_at": time.time()}
        store.write("watch.json", record)
        command = [sys.executable, "-c", "from virtuoso_bridge.cli import main; raise SystemExit(main())",
                   "recovery", "worker", "--workspace", str(store.root), "-p", store.profile,
                   "--watch-token", token, "--timeout", str(args.timeout)]
        if args.env: command += ["--env", str(Path(args.env).resolve())]
        env = dict(os.environ)
        env.pop("VB_BRIDGE_LOCK_OWNER", None)
        options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        with (store.base / "watch.log").open("ab") as log:
            child = subprocess.Popen(command, cwd=store.root, env=env, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=log, **options)
        record["pid"] = child.pid
        store.write("watch.json", record)
        return record


def _recovery_fingerprint(snapshot):
    """Include decision evidence, excluding heartbeat timestamps and poll noise."""
    request_id = ((snapshot.get("quarantine") or {}).get("bridgeResult", {}).get("request_id")
                  or snapshot.get("pending_request_id"))
    ledger = snapshot.get("ledger") or {}
    requests = ledger.get("requests") or []
    request = {}
    if request_id:
        request = next((r for r in requests if r.get("request_id") == request_id), {})
        single_request = ledger.get("request") or {}
        if not request and single_request.get("request_id") == request_id:
            request = single_request
    return json.dumps({
        "fault": snapshot["fault_class"], "identity": snapshot.get("identity"),
        "policy": {k: (snapshot.get("policy") or {}).get(k) for k in ("policy_id", "active")},
        "request_id": request_id,
        "request": {k: request.get(k) for k in ("state", "request_generation", "terminal_proof", "pre_dispatch_proof")},
        "readiness": {k: snapshot.get(k) for k in ("identity_verified", "daemon_alive", "heartbeat_fresh", "idle", "transport_available")},
        "pending": snapshot.get("pending"),
    }, sort_keys=True, default=str)


def _watch_worker(args, store, engine):
    failures = 0
    last_notice = None
    last_attempt = None
    next_attempt_at = 0.0
    try:
        while True:
            config = store.read("watch.json", {})
            if not config.get("enabled") or config.get("token") != args.watch_token: break
            try:
                snapshot = engine.inspect()
                unhealthy = snapshot["fault_class"] != "healthy"
                failures = failures + 1 if unhealthy else 0
                attempt_key = _recovery_fingerprint(snapshot)
                if failures >= 3 and attempt_key != last_attempt and time.monotonic() >= next_attempt_at:
                    with workspace_lock(store):
                        config = store.read("watch.json", {})
                        if not config.get("enabled") or config.get("token") != args.watch_token: break
                        result = engine.run(timeout=args.timeout, automatic=True)
                    last_attempt = attempt_key
                    next_attempt_at = time.monotonic() + max(1, config.get("interval", 10))
                    notice = (result["recovery_state"], result.get("stop_reason"), result.get("original_request_id"))
                    if notice != last_notice:
                        event = {"at": time.time(), "result": result}
                        store.write("notice.json", event)
                        print(json.dumps(event), flush=True)
                        last_notice = notice
                elif not unhealthy:
                    failures = 0
                    last_notice = None
                    last_attempt = None
                store.write("watch-status.json", {"pid": os.getpid(), "token": args.watch_token, "heartbeat_at": time.time(),
                                                   "fault_class": snapshot["fault_class"], "consecutive_failures": failures})
            except Exception as exc:
                failures += 1
                notice = ("inspection-failed", str(exc))
                if failures >= 3 and notice != last_notice:
                    store.write("notice.json", {"at": time.time(), "stop_reason": str(exc)})
                    last_notice = notice
            until = time.monotonic() + config.get("interval", 10)
            while time.monotonic() < until:
                current = store.read("watch.json", {})
                if not current.get("enabled") or current.get("token") != args.watch_token: return {"stopped": True}
                time.sleep(min(0.5, until - time.monotonic()))
    finally:
        store.write("watch-status.json", {"pid": os.getpid(), "token": args.watch_token,
                                           "stopped": True, "heartbeat_at": time.time()})
    return {"stopped": True}


def command(args, profile):
    from virtuoso_bridge.recovery_backend import BridgeRecoveryBackend
    store = RecoveryStore(args.workspace, profile)
    args.timeout = finite_seconds(args.timeout, 60)
    if args.recovery_action == "policy" and args.policy_action in (None, "status"):
        result = RecoveryEngine(store, None).policy()
        result["monitor"] = store.read("watch.json", {"enabled": False})
        result["pending"] = store.read("pending.json")
        failures = [t for t in store.read("failures.json", []) if t > time.time() - 900]
        result["limits"] = {"incident_seconds": 60, "lifecycle_per_incident": 1,
                            "lifecycle_failures_last_15_minutes": len(failures),
                            "remaining_failures_before_pause": max(0, 2 - len(failures))}
        print(json.dumps(result))
        return 0
    if args.recovery_action == "stop":
        config = store.read("watch.json", {})
        config["enabled"] = False
        store.write("watch.json", config)
        print(json.dumps({"stop_requested": True, "active_action_cancelled": False}))
        return 0
    if args.recovery_action == "watch":
        print(json.dumps(_watch_start(args, store)))
        return 0
    backend = BridgeRecoveryBackend(profile, timeout=min(args.timeout, 15))
    engine = RecoveryEngine(store, backend)
    try:
        with redirect_stdout(sys.stderr):
            if args.recovery_action == "policy":
                if args.policy_action == "grant":
                    with workspace_lock(store):
                        result = engine.grant(args.actions.split(",") if args.actions else [], args.reason, args.hours)
                elif args.policy_action == "revoke": result = engine.revoke()
                else:
                    result = engine.policy()
                    result["monitor"] = store.read("watch.json", {"enabled": False})
                    result["pending"] = store.read("pending.json")
            elif args.recovery_action == "inspect": result = engine.inspect()
            elif args.recovery_action == "worker": result = _watch_worker(args, store, engine)
            elif args.recovery_action == "resolve":
                with workspace_lock(store):
                    result = engine.resolve(args.recovery_id, args.expected_epoch, args.reason, args.acknowledge_unknown)
            else:
                with workspace_lock(store):
                    result = engine.run(timeout=args.timeout, action=args.action, automatic=args.automatic)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if args.automatic or result.get("recovery_state") not in {"blocked", "unknown"} else 2
    finally:
        backend.close()
