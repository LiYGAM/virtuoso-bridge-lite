"""Linux control-plane probes and atomic recovery mailbox writes (stdlib only)."""
import hashlib
import json
import os
import re
import stat
import tempfile
import time


def process(pid):
    if not str(pid).isdigit() or int(pid) <= 0:
        return {"known": False, "alive": False}
    base = "/proc/" + str(pid)
    try:
        with open(base + "/stat") as f: raw = f.read()
    except FileNotFoundError:
        return {"known": True, "alive": False, "pid": int(pid)}
    except OSError:
        return {"known": False, "alive": False, "pid": int(pid)}
    try:
        fields = raw[raw.rfind(")") + 2:].split()
        if fields[0] == "Z": return {"known": True, "alive": False, "pid": int(pid)}
        with open("/proc/sys/kernel/random/boot_id") as f: boot = f.read().strip()
        with open(base + "/environ", "rb") as f:
            env = dict(item.split(b"=", 1) for item in f.read().split(b"\0") if b"=" in item)
        return {"known": True, "alive": fields[0] != "Z", "pid": int(pid), "start_ticks": fields[19],
                "boot_id": boot, "uid": os.stat(base).st_uid,
                "display": env.get(b"DISPLAY", b"").decode("utf-8", "replace"),
                "executable": os.readlink(base + "/exe"), "cwd": os.readlink(base + "/cwd")}
    except (OSError, ValueError, IndexError):
        return {"known": False, "alive": False, "pid": int(pid)}


def _read_json(path):
    try:
        with open(path) as f: return json.load(f)
    except FileNotFoundError: return None


def _identity(path):
    try:
        with open(path) as f:
            return dict(line.rstrip("\n").split("=", 1) for line in f if "=" in line)
    except FileNotFoundError: return {}


def _owned_directory(path):
    if not os.path.isdir(path) or os.path.islink(path): raise RuntimeError("recovery-directory-invalid")
    info = os.stat(path)
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError("recovery-directory-not-private")


def _write(path, data):
    directory = os.path.dirname(path)
    _owned_directory(directory)
    if os.path.islink(path): raise RuntimeError("recovery-file-symlink")
    fd, temp = tempfile.mkstemp(prefix=".recovery-", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.rename(temp, path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def _tokens(values):
    # Data only: lineread parses a flat list of literals; SKILL never evaluates it.
    if any(not isinstance(v, (str, int)) or isinstance(v, bool) for v in values):
        raise ValueError("invalid-recovery-mailbox-value")
    return " ".join(json.dumps(v, ensure_ascii=True) for v in values) + "\n"


def retired_lifecycle(request, completed):
    epoch = completed.get(request.get("request_id"))
    return bool(epoch and request.get("exclusive") is True and request.get("operation_class") == "mutating"
                and request.get("state") == "orphaned_unknown_after_daemon_restart"
                and epoch == request.get("admitted_daemon_epoch"))


def _log_path(pid):
    paths = set()
    try:
        for name in os.listdir("/proc/%s/fd" % pid):
            try: path = os.readlink("/proc/%s/fd/%s" % (pid, name))
            except OSError: continue
            if re.search(r"/CDS\.log(?:\.\d+)?$", path): paths.add(path)
    except OSError: pass
    return next(iter(paths)) if len(paths) == 1 else None


def control(args):
    identity_path = args["identity_path"]
    directory = os.path.dirname(identity_path)
    identity = _identity(identity_path)
    ciw = process(identity.get("ciw_pid", ""))
    result = {"identity": identity, "ciw": ciw, "now": time.time()}
    action = args["action"]
    completed = _read_json(identity_path + ".recovery-completed.json") or {}
    if completed.get("ciw_session") != identity.get("ciw_session"):
        completed = {}
    result["completed_recoveries"] = completed.get("requests", {})
    if action == "inspect":
        if args.get("daemon_pid"):
            result["daemon"] = process(args["daemon_pid"])
        path = _log_path(identity.get("ciw_pid"))
        if path:
            s = os.stat(path)
            result["log_cursor"] = {"path": path, "inode": s.st_ino, "device": s.st_dev, "offset": s.st_size}
        return result
    if action == "daemon-process": return process(args["daemon_pid"])
    if action == "log-window":
        cursor = args["cursor"]
        path = _log_path(identity.get("ciw_pid"))
        if path != cursor["path"]: raise RuntimeError("ciw-log-path-changed")
        s = os.stat(path)
        if s.st_ino != cursor["inode"] or s.st_dev != cursor["device"] or s.st_size < cursor["offset"]:
            raise RuntimeError("ciw-log-rotated-or-truncated")
        if s.st_size - cursor["offset"] > 1048576: raise RuntimeError("ciw-log-window-too-large")
        with open(path, "rb") as f:
            f.seek(cursor["offset"]); data = f.read(s.st_size - cursor["offset"]).decode("utf-8", "replace")
        return {"complete": True, "path": path, "start_offset": cursor["offset"], "end_offset": s.st_size,
                "text": data, "errors": re.findall(r"(?im)^.*(?:\*Error\*|\*WARNING\*.*(?:load|reader)|\(reader\)).*$", data)}
    _owned_directory(directory)
    auth_path = identity_path + ".recovery-auth"
    intent_path = identity_path + ".recovery-intent"
    if action == "revoke":
        # Revocation invalidates any intent not yet consumed by the CIW event loop.
        if not re.fullmatch(r"[A-Za-z0-9_-]+", args["policy_id"]): raise ValueError("invalid-policy-id")
        _write(identity_path + ".recovery-revoked-" + args["policy_id"], "revoked\n")
        _write(auth_path, "nil\n")
        return {"revoked": True}
    expected = args["expected"]
    for key in ("epoch", "profile", "deployment_id", "il_sha256", "ciw_pid", "ciw_session"):
        if identity.get(key) != expected.get(key): raise RuntimeError("target-identity-changed:" + key)
    if not ciw.get("alive") or ciw.get("uid") != os.getuid(): raise RuntimeError("target-ciw-unavailable")
    for key in ("start_ticks", "boot_id", "display", "executable"):
        if ciw.get(key) != args["ciw"].get(key): raise RuntimeError("target-ciw-changed:" + key)
    if action == "authorize":
        if args["expires_at"] <= time.time(): raise RuntimeError("policy-expired")
        if os.path.exists(identity_path + ".recovery-revoked-" + args["policy_id"]): raise RuntimeError("policy-revoked")
        values = [args["policy_id"], expected["epoch"], expected["deployment_id"],
                  expected["ciw_session"], int(args["expires_at"]), ",".join(args["actions"]),
                  args["daemon_path"], args["setup_path"]]
        _write(auth_path, _tokens(values))
        _write(auth_path + ".json", json.dumps(dict(policy_id=args["policy_id"], epoch=expected["epoch"],
                    expires_at=args["expires_at"], actions=args["actions"])))
        if args.get("completed_recoveries"):
            _write(identity_path + ".recovery-completed.json", json.dumps(dict(requests=args["completed_recoveries"],
                    ciw_session=identity["ciw_session"], deployment_id=identity["deployment_id"])))
        return {"authorized": True}
    if action in {"claim", "relaunch", "release"}:
        claim_root = "/tmp/virtuoso-bridge-recovery-%s" % os.getuid()
        if not os.path.exists(claim_root): os.mkdir(claim_root, 0o700)
        _owned_directory(claim_root)
        claim = os.path.join(claim_root, "%s-%s-%s.json" % (ciw["boot_id"], ciw["pid"], ciw["start_ticks"]))
        prior = _read_json(claim)
        if action == "release":
            if prior and prior.get("recovery_id") == args["recovery_id"]:
                if not args.get("manual") and identity.get("recovery_id") != args["recovery_id"]:
                    raise RuntimeError("release-recovery-unverified")
                if args.get("manual"):
                    if prior.get("expires_at", 0) >= time.time(): raise RuntimeError("pending-intent-not-expired")
                requests = completed.get("requests", {})
                requests[args["recovery_id"]] = args["old_epoch"]
                _write(identity_path + ".recovery-completed.json", json.dumps(dict(requests=requests,
                    ciw_session=identity["ciw_session"], deployment_id=identity["deployment_id"])))
                os.unlink(claim)
            return {"released": True}
        if prior: raise RuntimeError("target-recovery-already-claimed")
        auth = _read_json(auth_path + ".json") or {}
        required = "daemon_relaunch" if action == "relaunch" else "daemon_restart"
        if (args["expires_at"] <= time.time() or auth.get("expires_at", 0) <= time.time()
                or auth.get("epoch") != expected["epoch"] or auth.get("policy_id") != args["policy_id"]
                or required not in auth.get("actions", [])
                or os.path.exists(identity_path + ".recovery-revoked-" + args["policy_id"])):
            raise RuntimeError("target-policy-inactive")
        for path, expected_hash in args["files"].items():
            if os.path.islink(path): raise RuntimeError("deployment-symlink")
            with open(path, "rb") as f: actual = hashlib.sha256(f.read()).hexdigest()
            if actual != expected_hash: raise RuntimeError("pinned-deployment-digest-mismatch")
        # O_EXCL coordinates clients even if their local workspaces differ.
        fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"recovery_id": args["recovery_id"], "expires_at": args["expires_at"]}, f)
            f.flush(); os.fsync(f.fileno())
        if action == "relaunch":
            ledger = _read_json(args["ledger_path"])
            if not ledger or ledger.get("daemon_epoch") != expected["epoch"]:
                raise RuntimeError("relaunch-ledger-unavailable")
            if not args.get("same_host"): raise RuntimeError("relaunch-requires-verified-local-ipc-topology")
            daemon = process(ledger.get("daemon_pid"))
            if not daemon.get("known") or daemon.get("alive"): raise RuntimeError("daemon-exit-not-proven")
            if ledger.get("active_request_id") or ledger.get("queue_depth") != 0 or ledger.get("exclusive_request_id"):
                raise RuntimeError("relaunch-ledger-busy")
            terminal = {"succeeded", "failed", "succeeded_after_timeout", "failed_after_timeout", "expired_before_dispatch"}
            if any(r.get("state") not in terminal and not retired_lifecycle(r, completed.get("requests", {}))
                   for r in ledger.get("requests", [])):
                raise RuntimeError("relaunch-has-unknown-requests")
            values = [args["recovery_id"], args["policy_id"], expected["epoch"], expected["deployment_id"],
                      expected["ciw_session"], int(args["expires_at"])]
            _write(intent_path, _tokens(values))
        return {"claimed": True}
    raise ValueError("unsupported recovery control action")
