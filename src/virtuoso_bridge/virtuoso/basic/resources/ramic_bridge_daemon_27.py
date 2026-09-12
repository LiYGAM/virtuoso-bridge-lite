#!/usr/bin/env python2.7
"""RAMIC Bridge Daemon - Virtuoso Skill Bridge Service (Python 2.7 Version)"""

import sys
import socket
import os
import json
import threading
import time
import errno
import hashlib
import hmac
import io
import struct
import traceback
import uuid

try:
    import Queue as _queue
except ImportError:
    import queue as _queue

try:
    _text_type = unicode
except NameError:
    _text_type = str

# Counters surfaced to the SKILL monitor via stderr [RB-stat] lines.
# Throttled to ~1 Hz so heavy traffic doesn't flood stderr.
_RB_START_T = time.time()
_RB_CALLS = 0
_RB_ERRORS = 0
_RB_LAST_STAT_T = 0.0


def _emit_stat(force=False):
    global _RB_LAST_STAT_T
    now = time.time()
    if not force and now - _RB_LAST_STAT_T < 1.0:
        return
    _RB_LAST_STAT_T = now
    try:
        sys.stderr.write(
            "[RB-stat] count={0} errors={1} uptime={2}\n".format(
                _RB_CALLS, _RB_ERRORS, int(now - _RB_START_T)
            )
        )
        sys.stderr.flush()
    except Exception:
        pass


try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None

_fcntl_fn = getattr(_fcntl, "fcntl", None)
_f_getfl = getattr(_fcntl, "F_GETFL", 3)
_f_setfl = getattr(_fcntl, "F_SETFL", 4)
_o_nonblock = int(getattr(os, "O_NONBLOCK", 0))


def _fcntl_or_die(*args):
    if _fcntl_fn is None:
        raise RuntimeError("fcntl is unavailable on this platform")
    return _fcntl_fn(*args)

# Python 2.7 compatibility: try to import psutil, fallback to manual PID detection
psutil = None
try:
    import psutil as _psutil
    psutil = _psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Command line arguments for host and port
HOST = sys.argv[1]
PORT = int(sys.argv[2])
AUTH_TOKEN_FILE = sys.argv[3] if len(sys.argv) > 3 else ""
REQUEST_STATE_FILE = sys.argv[4] if len(sys.argv) > 4 else ""
PROFILE = sys.argv[5] if len(sys.argv) > 5 else ""


def _read_secret(path):
    if not path:
        return ""
    try:
        with io.open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except (IOError, OSError):
        return ""


AUTH_TOKEN = _read_secret(AUTH_TOKEN_FILE)
DAEMON_EPOCH = uuid.uuid4().hex
DAEMON_STARTED_AT_EPOCH = time.time()


def _compute_daemon_build_sha256():
    try:
        with io.open(__file__, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except (IOError, OSError):
        return ""


DAEMON_BUILD_SHA256 = _compute_daemon_build_sha256()
PROTOCOL_VERSIONS = (2, 3)
DAEMON_CAPABILITIES = (
    "auth-token-v1",
    "bounded-queue-v1",
    "queue-deadline-v1",
    "daemon-heartbeat-v1",
    "exclusive-admission-v1",
    "late-completion-witness-v1",
    "operation-class-v1",
    "protocol-v3-frame-v1",
    "request-idempotency-v1",
    "request-ledger-v1",
    "terminal-proof-v1",
    "timeout-drain-v1",
)
_V3_MAGIC = b"VBR3\x00"
_V3_FOOTER = b"\x1eVBR3-END\x1e"


def _build_v3_frame(
    request_id,
    status,
    marker,
    payload,
    request_digest_sha256=None,
    **metadata
):
    if not isinstance(payload, bytes):
        payload = _text_type(payload).encode("utf-8")
    header = {
        "protocol_version": 3,
        "request_id": request_id,
        "status": status,
        "marker": marker,
        "payload_length": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "daemon_epoch": DAEMON_EPOCH,
        "daemon_build_sha256": DAEMON_BUILD_SHA256 or None,
        "supported_protocol_versions": list(PROTOCOL_VERSIONS),
        "capabilities": list(DAEMON_CAPABILITIES),
        "request_digest_sha256": request_digest_sha256,
    }
    header.update(metadata)
    header_bytes = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return (
        _V3_MAGIC
        + struct.pack(">I", len(header_bytes))
        + header_bytes
        + payload
        + _V3_FOOTER
    )


def _format_client_response(
    protocol_version,
    request_id,
    status,
    marker,
    payload,
    request_digest_sha256=None,
    **metadata
):
    if protocol_version == 3:
        return _build_v3_frame(
            request_id,
            status,
            marker,
            payload,
            request_digest_sha256=request_digest_sha256,
            **metadata
        )
    marker_byte = b"\x02" if marker == "STX" else b"\x15"
    if not isinstance(payload, bytes):
        payload = _text_type(payload).encode("utf-8")
    return marker_byte + payload


_REQUESTS = {}
_REQUEST_ORDER = []
_RESPONSE_CACHE = {}
_STATE_LOCK = threading.Lock()
_ACTIVE_REQUEST_ID = None
_MAX_REQUESTS = 64
_RESPONSE_CACHE_BYTES = 0
_HEARTBEAT_AT_EPOCH = DAEMON_STARTED_AT_EPOCH
_REJECTED_BUSY_COUNT = 0
_RETIRE_EVENT = threading.Event()


def _bounded_env_number(name, default, minimum, maximum, as_float=False):
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = float(default)
    value = min(float(maximum), max(float(minimum), value))
    return value if as_float else int(value)


_MAX_REQUEST_BYTES = _bounded_env_number(
    "VB_MAX_REQUEST_BYTES", 4 * 1024 * 1024, 1024, 64 * 1024 * 1024
)
_MAX_RESPONSE_BYTES = _bounded_env_number(
    "VB_MAX_RESPONSE_BYTES", 16 * 1024 * 1024, 1024, 128 * 1024 * 1024
)
_MAX_RESPONSE_CACHE_BYTES = _bounded_env_number(
    "VB_MAX_RESPONSE_CACHE_BYTES", 32 * 1024 * 1024, 1024, 256 * 1024 * 1024
)
_REQUEST_READ_TIMEOUT_SECONDS = _bounded_env_number(
    "VB_REQUEST_READ_TIMEOUT", 5, 1, 300, as_float=True
)
_CLIENT_WRITE_TIMEOUT_SECONDS = _bounded_env_number(
    "VB_CLIENT_WRITE_TIMEOUT", 5, 1, 300, as_float=True
)
_RESPONSE_DRAIN_WARNING_SECONDS = _bounded_env_number(
    "VB_RESPONSE_DRAIN_GRACE", 120, 1, 3600, as_float=True
)
# Kept as an alias for callers/tests that used the old internal name.  The
# value is now only the late-wait warning threshold; it never retires the
# daemon or discards the response stream.
_RESPONSE_DRAIN_GRACE_SECONDS = _RESPONSE_DRAIN_WARNING_SECONDS
_MAX_EXECUTION_TIMEOUT_SECONDS = _bounded_env_number(
    "VB_MAX_EXECUTION_TIMEOUT", 86400, 1, 86400, as_float=True
)
_QUEUE_CAPACITY = _bounded_env_number("VB_QUEUE_DEPTH", 4, 1, 64)
_REQUEST_QUEUE = _queue.Queue(maxsize=_QUEUE_CAPACITY)
_EXCLUSIVE_REQUEST_ID = None
_EXCLUSIVE_REQUEST_GENERATION = None
_monotonic = getattr(time, "monotonic", time.time)
_ACTIVE_STATES = ("running", "timed_out_pending", "late_waiting_operator")
_RECOVER_AS_ORPHANED_STATES = (
    "queued", "running", "timed_out_pending", "late_waiting_operator"
)
_TERMINAL_STATES = (
    "expired_before_dispatch",
    "succeeded",
    "failed",
    "succeeded_after_timeout",
    "failed_after_timeout",
    "response_too_large",
    "failed_internal",
    "orphaned_unknown_after_daemon_restart",
    "orphaned_unknown_response_drain_timeout",
    "orphaned_unknown_response_stream_closed",
)
_EXCLUSIVE_RELEASE_STATES = (
    "expired_before_dispatch",
    "succeeded", "failed", "succeeded_after_timeout", "failed_after_timeout"
)

try:
    _string_types = (basestring,)
except NameError:
    _string_types = (str,)


class RequestProtocolError(Exception):
    pass


class ResponseDrainTimeout(Exception):
    pass

class ResponseStreamClosed(Exception):
    pass


def _load_request_history():
    if not REQUEST_STATE_FILE:
        return
    try:
        with io.open(REQUEST_STATE_FILE, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (IOError, OSError, ValueError):
        return
    for entry in payload.get("requests", [])[-_MAX_REQUESTS:]:
        request_id = str(entry.get("request_id") or "")
        if not request_id:
            continue
        restored = dict(entry)
        restored["restored_from_daemon_epoch"] = payload.get("daemon_epoch")
        if restored.get("state") in _RECOVER_AS_ORPHANED_STATES:
            restored["state"] = "orphaned_unknown_after_daemon_restart"
        _REQUESTS[request_id] = restored
        _REQUEST_ORDER.append(request_id)


_load_request_history()


def _safe_token_equal(left, right):
    try:
        return hmac.compare_digest(str(left), str(right))
    except (AttributeError, TypeError):
        left = str(left)
        right = str(right)
        if len(left) != len(right):
            return False
        result = 0
        for a, b in zip(bytearray(left.encode("utf-8")), bytearray(right.encode("utf-8"))):
            result |= a ^ b
        return result == 0


def _write_request_state():
    if not REQUEST_STATE_FILE:
        return
    payload = {
        "schema_version": 1,
        "protocol_version": 2,
        "protocol_versions": list(PROTOCOL_VERSIONS),
        "daemon_epoch": DAEMON_EPOCH,
        "daemon_build_sha256": DAEMON_BUILD_SHA256 or None,
        "capabilities": list(DAEMON_CAPABILITIES),
        "late_waiting_request_id": (
            _ACTIVE_REQUEST_ID
            if _ACTIVE_REQUEST_ID in _REQUESTS and _REQUESTS[_ACTIVE_REQUEST_ID].get("state") == "late_waiting_operator"
            else None
        ),
        "daemon_started_at_epoch": DAEMON_STARTED_AT_EPOCH,
        "python_major": sys.version_info[0],
        "daemon_pid": os.getpid(),
        "bind_host": HOST,
        "port": PORT,
        "profile": PROFILE or None,
        "auth_enabled": bool(AUTH_TOKEN),
        "active_request_id": _ACTIVE_REQUEST_ID,
        "exclusive_request_id": _EXCLUSIVE_REQUEST_ID,
        "exclusive_request_generation": _EXCLUSIVE_REQUEST_GENERATION,
        "heartbeat_at_epoch": _HEARTBEAT_AT_EPOCH,
        "queue_depth": _REQUEST_QUEUE.qsize(),
        "queue_capacity": _QUEUE_CAPACITY,
        "rejected_busy_count": _REJECTED_BUSY_COUNT,
        "updated_at_epoch": time.time(),
        "requests": [_REQUESTS[key] for key in _REQUEST_ORDER if key in _REQUESTS],
    }
    directory = os.path.dirname(REQUEST_STATE_FILE)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, 0o700)
    tmp_path = "%s.tmp.%d" % (REQUEST_STATE_FILE, os.getpid())
    try:
        with io.open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, REQUEST_STATE_FILE)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def _record_request(request_id, state, **fields):
    global _ACTIVE_REQUEST_ID, _RESPONSE_CACHE_BYTES
    if not request_id:
        return
    with _STATE_LOCK:
        entry = dict(_REQUESTS.get(request_id) or {"request_id": request_id})
        entry.update(fields)
        entry["state"] = state
        entry["updated_at_epoch"] = time.time()
        _REQUESTS[request_id] = entry
        if request_id in _REQUEST_ORDER:
            _REQUEST_ORDER.remove(request_id)
        _REQUEST_ORDER.append(request_id)
        _trim_request_history_locked()
        if state in _ACTIVE_STATES:
            _ACTIVE_REQUEST_ID = request_id
        elif _ACTIVE_REQUEST_ID == request_id:
            _ACTIVE_REQUEST_ID = None
        _write_request_state()


def _trim_request_history_locked():
    """Evict only terminal history; never forget queued or active work."""
    global _RESPONSE_CACHE_BYTES
    while len(_REQUEST_ORDER) > _MAX_REQUESTS:
        expired = next(
            (
                key for key in _REQUEST_ORDER
                if (_REQUESTS.get(key) or {}).get("state")
                not in _RECOVER_AS_ORPHANED_STATES
            ),
            None,
        )
        if expired is None:
            return
        _REQUEST_ORDER.remove(expired)
        _REQUESTS.pop(expired, None)
        expired_response = _RESPONSE_CACHE.pop(expired, None)
        if expired_response is not None:
            _RESPONSE_CACHE_BYTES -= len(expired_response)


def _mark_request_running(request_id, request_generation):
    global _ACTIVE_REQUEST_ID
    with _STATE_LOCK:
        entry = _REQUESTS.get(request_id)
        if (
            not entry
            or entry.get("request_generation") != request_generation
            or entry.get("state") != "queued"
        ):
            return False
        entry = dict(entry)
        entry["state"] = "running"
        entry["started_at_epoch"] = time.time()
        entry["heartbeat_at_epoch"] = time.time()
        entry["updated_at_epoch"] = time.time()
        _REQUESTS[request_id] = entry
        _ACTIVE_REQUEST_ID = request_id
        _write_request_state()
        return True


def _heartbeat_loop():
    global _HEARTBEAT_AT_EPOCH
    while True:
        time.sleep(1.0)
        with _STATE_LOCK:
            now = time.time()
            _HEARTBEAT_AT_EPOCH = now
            if _ACTIVE_REQUEST_ID in _REQUESTS:
                entry = dict(_REQUESTS[_ACTIVE_REQUEST_ID])
                if entry.get("state") in _ACTIVE_STATES:
                    entry["heartbeat_at_epoch"] = now
                    entry["updated_at_epoch"] = now
                    _REQUESTS[_ACTIVE_REQUEST_ID] = entry
            _write_request_state()


def _mark_request_timed_out(request_id, request_generation):
    with _STATE_LOCK:
        entry = _REQUESTS.get(request_id)
        if (
            not entry
            or entry.get("request_generation") != request_generation
            or entry.get("state") != "running"
        ):
            return False
        entry = dict(entry)
        entry["state"] = "timed_out_pending"
        entry["timed_out_at_epoch"] = time.time()
        entry["updated_at_epoch"] = time.time()
        _REQUESTS[request_id] = entry
        _write_request_state()
        return True


def _mark_request_late_waiting(request_id, request_generation):
    """Keep the serial CIW reader alive after the warning threshold."""
    with _STATE_LOCK:
        entry = _REQUESTS.get(request_id)
        if (
            not entry
            or entry.get("request_generation") != request_generation
            or entry.get("state") not in ("running", "timed_out_pending")
        ):
            return False
        entry = dict(entry)
        entry["state"] = "late_waiting_operator"
        entry["late_waiting_at_epoch"] = time.time()
        entry["updated_at_epoch"] = time.time()
        _REQUESTS[request_id] = entry
        _write_request_state()
        return True


def _build_terminal_proof(
    state,
    request_id,
    request_digest_sha256,
    operation_class,
    protocol_version,
    request_generation,
    response_marker,
    response_digest_sha256,
    payload_digest_sha256,
    response_size_bytes,
    finished_at_epoch,
):
    return {
        "schema_version": 1,
        "complete_frame": True,
        "state": state,
        "request_id": request_id,
        "request_digest_sha256": request_digest_sha256,
        "operation_class": operation_class,
        "protocol_version": protocol_version,
        "request_generation": request_generation,
        "daemon_epoch": DAEMON_EPOCH,
        "daemon_build_sha256": DAEMON_BUILD_SHA256 or None,
        "response_marker": response_marker,
        "response_digest_sha256": response_digest_sha256,
        "payload_digest_sha256": payload_digest_sha256,
        "response_size_bytes": response_size_bytes,
        "finished_at_epoch": finished_at_epoch,
    }


def _store_cached_response_locked(request_id, response_bytes):
    global _RESPONSE_CACHE_BYTES
    previous = _RESPONSE_CACHE.pop(request_id, None)
    if previous is not None:
        _RESPONSE_CACHE_BYTES -= len(previous)
    if len(response_bytes) > _MAX_RESPONSE_CACHE_BYTES:
        return False
    while _RESPONSE_CACHE and _RESPONSE_CACHE_BYTES + len(response_bytes) > _MAX_RESPONSE_CACHE_BYTES:
        expired = next(
            (key for key in _REQUEST_ORDER if key in _RESPONSE_CACHE),
            next(iter(_RESPONSE_CACHE)),
        )
        old = _RESPONSE_CACHE.pop(expired)
        _RESPONSE_CACHE_BYTES -= len(old)
    _RESPONSE_CACHE[request_id] = response_bytes
    _RESPONSE_CACHE_BYTES += len(response_bytes)
    return True


def _finalize_request(request_id, request_generation, state, response_bytes=None, **fields):
    global _ACTIVE_REQUEST_ID, _RESPONSE_CACHE_BYTES
    with _STATE_LOCK:
        entry = _REQUESTS.get(request_id)
        if (
            not entry
            or entry.get("request_generation") != request_generation
            or (entry.get("state") not in _ACTIVE_STATES
                and not (state == "expired_before_dispatch" and entry.get("state") == "queued"))
        ):
            return False
        entry = dict(entry)
        entry.update(fields)
        entry["state"] = state
        entry["updated_at_epoch"] = time.time()
        if response_bytes is not None:
            entry["response_cached"] = _store_cached_response_locked(
                request_id, response_bytes
            )
        if state == "orphaned_unknown_response_stream_closed":
            cached = _RESPONSE_CACHE.pop(request_id, None)
            if cached is not None:
                _RESPONSE_CACHE_BYTES -= len(cached)
            entry.pop("response_cached", None)
            entry.pop("terminal_proof", None)
        _REQUESTS[request_id] = entry
        if _ACTIVE_REQUEST_ID == request_id:
            _ACTIVE_REQUEST_ID = None
        _write_request_state()
        return True


def _handle_stream_closed(request_id, request_generation):
    finalized = _finalize_request(
        request_id,
        request_generation,
        "orphaned_unknown_response_stream_closed",
        finished_at_epoch=time.time(),
        response_stream_closed=True,
    )
    _RETIRE_EVENT.set()
    return finalized


def _record_duplicate(request_id, replayed):
    with _STATE_LOCK:
        entry = dict(_REQUESTS.get(request_id) or {"request_id": request_id})
        entry["duplicate_count"] = int(entry.get("duplicate_count") or 0) + 1
        entry["last_duplicate_at_epoch"] = time.time()
        entry["last_duplicate_replayed"] = bool(replayed)
        entry["updated_at_epoch"] = time.time()
        _REQUESTS[request_id] = entry
        _write_request_state()

# Get Virtuoso's PID - this is the process we need to send signals to
if PSUTIL_AVAILABLE and psutil is not None:
    # Use psutil if available
    current_process = psutil.Process()
    parent_process = current_process.parent()
    grandparent_process = parent_process.parent() if parent_process else None
    # Python 2.7 compatibility: handle None case
    if grandparent_process:
        virtuoso_pid = grandparent_process.pid
    else:
        virtuoso_pid = os.getppid()
else:
    # Fallback: use /proc filesystem to get parent process info
    def get_grandparent_pid():
        try:
            # Read current process info from /proc
            with open('/proc/self/stat', 'r') as f:
                stat_data = f.read().split()
                # Parent PID is the 4th field (index 3)
                parent_pid = int(stat_data[3])

                # Now get the parent's parent PID (grandparent)
                with open('/proc/{0}/stat'.format(parent_pid), 'r') as f2:
                    stat_data2 = f2.read().split()
                    # Grandparent PID is the 4th field (index 3) of parent's stat
                    grandparent_pid = int(stat_data2[3])
                    return grandparent_pid
        except:
            # If /proc is not available, raise an error
            raise Exception("Failed to get Virtuoso PID")

    virtuoso_pid = get_grandparent_pid()

# Python 2.7 compatibility: print statement instead of print() function
# print("Virtuoso PID: {0}".format(virtuoso_pid))

# Set stdin to non-blocking mode for reading Virtuoso responses
# Note: Only stdin needs to be non-blocking, stdout should remain blocking
stdin_fd = sys.stdin.fileno()
stdin_fl = _fcntl_or_die(stdin_fd, _f_getfl)
_fcntl_or_die(stdin_fd, _f_setfl, stdin_fl | _o_nonblock)

# Keep stdout blocking for reliable writes
stdout_fd = sys.stdout.fileno()
stdout_fl = _fcntl_or_die(stdout_fd, _f_getfl)
_fcntl_or_die(stdout_fd, _f_setfl, stdout_fl & ~_o_nonblock)  # Ensure blocking

def _safe_sendall(conn, data):
    try:
        conn.settimeout(_CLIENT_WRITE_TIMEOUT_SECONDS)
        conn.sendall(data)
    except (socket.error, socket.timeout):
        pass


def _safe_close_connection(conn):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except socket.error:
        pass
    try:
        conn.close()
    except socket.error:
        pass

def watchdog_callback(request_id, request_generation, timed_out_event):
    """Mark timeout without aborting the active Virtuoso IPC callback.

    An asynchronous SIGINT can prevent RBIpcDataHandler from writing its
    response delimiter.  The TCP client owns the external timeout while this
    daemon waits to drain the eventual response and restore stream alignment.
    """
    timed_out_event.set()
    _mark_request_timed_out(request_id, request_generation)


def late_wait_warning_callback(request_id, request_generation, late_wait_event):
    late_wait_event.set()
    return _mark_request_late_waiting(request_id, request_generation)


def _receive_request(conn):
    deadline = _monotonic() + _REQUEST_READ_TIMEOUT_SECONDS
    chunks = []
    total = 0
    while True:
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise RequestProtocolError("REQUEST_READ_TIMEOUT")
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(min(65536, _MAX_REQUEST_BYTES - total + 1))
        except socket.timeout:
            raise RequestProtocolError("REQUEST_READ_TIMEOUT")
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_REQUEST_BYTES:
            raise RequestProtocolError("REQUEST_TOO_LARGE")
        chunks.append(chunk)
    if not chunks:
        raise RequestProtocolError("EMPTY_REQUEST")
    return b"".join(chunks)


def _validate_request(request_data):
    if not isinstance(request_data, dict):
        raise RequestProtocolError("REQUEST_OBJECT_REQUIRED")
    skill_code = request_data.get("skill")
    if not isinstance(skill_code, _string_types):
        raise RequestProtocolError("SKILL_STRING_REQUIRED")
    try:
        timeout_seconds = float(request_data.get("timeout"))
    except (TypeError, ValueError):
        raise RequestProtocolError("INVALID_TIMEOUT")
    if not 0 < timeout_seconds <= _MAX_EXECUTION_TIMEOUT_SECONDS:
        raise RequestProtocolError("INVALID_TIMEOUT")
    request_id = str(request_data.get("request_id") or "")
    if not request_id or len(request_id) > 256:
        raise RequestProtocolError("INVALID_REQUEST_ID")
    operation_class = str(request_data.get("operation_class") or "unknown")
    if operation_class not in ("unknown", "read_only", "mutating"):
        raise RequestProtocolError("INVALID_OPERATION_CLASS")
    exclusive = request_data.get("exclusive", False)
    if exclusive is None:
        exclusive = False
    if not isinstance(exclusive, bool):
        raise RequestProtocolError("INVALID_EXCLUSIVE_FLAG")
    try:
        protocol_version = int(request_data.get("protocol_version") or 1)
    except (TypeError, ValueError):
        raise RequestProtocolError("PROTOCOL_V2_REQUIRED")
    return (
        skill_code,
        timeout_seconds,
        request_id,
        operation_class,
        protocol_version,
        exclusive,
    )


def read_until_delimiter(
    deadline,
    max_response_bytes=None,
    start_ok=b'\x02',
    start_err=b'\x15',
    end=b'\x1e',
    late_wait_callback=None,
):
    """Read one complete response, even after the request watchdog expires.

    Draining a late response keeps the serial request/response stream aligned
    after a modal form or another callback outlives its client timeout.
    """
    late_wait_notified = False

    if max_response_bytes is None:
        max_response_bytes = _MAX_RESPONSE_BYTES
    result = bytearray()
    overflow = False
    response_bytes_seen = 0

    # Wait for start marker
    while True:
        if deadline is not None and _monotonic() >= deadline:
            if late_wait_callback is None:
                raise ResponseDrainTimeout("RESPONSE_DRAIN_TIMEOUT")
            if not late_wait_notified:
                late_wait_notified = True
                late_wait_callback()
            deadline = None
        try:
            ch = sys.stdin.read(1)
            if ch is None:
                time.sleep(0.001)  # None means would-block on some streams
                continue
            if ch == b"" or ch == "":
                raise ResponseStreamClosed("RESPONSE_STREAM_CLOSED")
            if ch in [start_ok, start_err]:
                break
        except IOError as e:
            if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                time.sleep(0.001)  # Short sleep to avoid busy waiting
                continue
            else:
                raise

    # Python 2.7 compatibility: convert string to bytes for bytearray
    if isinstance(ch, str):
        result.extend(ch.encode('latin1'))
    else:
        result.extend(ch)

    # Read content until end marker
    while True:
        if deadline is not None and _monotonic() >= deadline:
            if late_wait_callback is None:
                raise ResponseDrainTimeout("RESPONSE_DRAIN_TIMEOUT")
            if not late_wait_notified:
                late_wait_notified = True
                late_wait_callback()
            deadline = None
        try:
            ch = sys.stdin.read(1)
            if ch is None:
                time.sleep(0.001)  # None means would-block on some streams
                continue
            if ch == b"" or ch == "":  # Python 2.7: empty string means EOF
                raise ResponseStreamClosed("RESPONSE_STREAM_CLOSED")
            if ch == end:
                break
            # Python 2.7 compatibility: convert string to bytes for bytearray
            if isinstance(ch, str):
                encoded = ch.encode('latin1')
            else:
                encoded = ch
            response_bytes_seen += len(encoded)
            if len(result) < max_response_bytes:
                result.extend(encoded[: max_response_bytes - len(result)])
            if response_bytes_seen > max_response_bytes:
                overflow = True
        except IOError as e:
            if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                time.sleep(0.001)  # Short sleep to avoid busy waiting
                continue
            else:
                raise

    return result, overflow, response_bytes_seen

def _busy_response(protocol_version, request_id, request_digest):
    if protocol_version == 3:
        return _format_client_response(
            3,
            request_id,
            "busy",
            "NAK",
            "BRIDGE_BUSY",
            request_digest_sha256=request_digest,
            retry_after=1.0,
            queue_depth=_REQUEST_QUEUE.qsize(),
            queue_capacity=_QUEUE_CAPACITY,
        )
    return b"\x15BRIDGE_BUSY"


def _late_completion_response(protocol_version, request_id, request_digest):
    if protocol_version == 3:
        return _format_client_response(
            3,
            request_id,
            "busy",
            "NAK",
            "BRIDGE_LATE_COMPLETION_PENDING",
            request_digest_sha256=request_digest,
            retry_after=1.0,
            queue_depth=_REQUEST_QUEUE.qsize(),
            queue_capacity=_QUEUE_CAPACITY,
        )
    return b"\x15BRIDGE_BUSY"


def _admit_external_connection(conn, addr):
    """Validate and enqueue one request without touching the CIW stream."""
    global _REJECTED_BUSY_COUNT, _EXCLUSIVE_REQUEST_ID
    global _EXCLUSIVE_REQUEST_GENERATION
    request_id = ""
    protocol_version = 2
    request_digest = None
    try:
        if _RETIRE_EVENT.is_set():
            _safe_sendall(conn, b"\x15BRIDGE_RETIRED")
            return False
        data = _receive_request(conn)
        request_data = json.loads(data)

        (
            skill_code,
            timeout_seconds,
            request_id,
            operation_class,
            protocol_version,
            exclusive,
        ) = _validate_request(request_data)
        if protocol_version not in PROTOCOL_VERSIONS:
            _safe_sendall(conn, b"\x15PROTOCOL_V2_REQUIRED")
            return False
        supplied_token = request_data.get("auth_token") or ""
        if AUTH_TOKEN and not _safe_token_equal(supplied_token, AUTH_TOKEN):
            _safe_sendall(conn, _format_client_response(
                protocol_version, request_id, "rejected", "NAK", "AUTH_REQUIRED"
            ))
            return False
        skill_text = skill_code.decode("utf-8") if isinstance(skill_code, bytes) else skill_code
        request_digest = hashlib.sha256(
            (operation_class + "\x00" + skill_text).encode("utf-8")
        ).hexdigest()
        request_generation = uuid.uuid4().hex
        admitted = (
            conn,
            addr,
            skill_code,
            timeout_seconds,
            request_id,
            operation_class,
            protocol_version,
            request_digest,
            request_generation,
            exclusive,
            _monotonic() + timeout_seconds,
        )
        response = None
        with _STATE_LOCK:
            previous = _REQUESTS.get(request_id)
            if previous and previous.get("request_digest_sha256") != request_digest:
                response = _format_client_response(
                    protocol_version, request_id, "rejected", "NAK",
                    "REQUEST_ID_CONFLICT", request_digest_sha256=request_digest,
                )
            elif request_id in _RESPONSE_CACHE:
                entry = dict(previous or {"request_id": request_id})
                entry["duplicate_count"] = int(entry.get("duplicate_count") or 0) + 1
                entry["last_duplicate_at_epoch"] = time.time()
                cached_protocol = int(entry.get("protocol_version") or 2)
                if cached_protocol == protocol_version:
                    entry["last_duplicate_replayed"] = True
                    response = _RESPONSE_CACHE[request_id]
                else:
                    entry["last_duplicate_replayed"] = False
                    response = _format_client_response(
                        protocol_version, request_id, "duplicate_pending", "NAK",
                        "REQUEST_PROTOCOL_REPLAY_UNAVAILABLE",
                        request_digest_sha256=request_digest,
                    )
                entry["updated_at_epoch"] = time.time()
                _REQUESTS[request_id] = entry
                _write_request_state()
            elif previous:
                entry = dict(previous)
                entry["duplicate_count"] = int(entry.get("duplicate_count") or 0) + 1
                entry["last_duplicate_at_epoch"] = time.time()
                entry["last_duplicate_replayed"] = False
                entry["updated_at_epoch"] = time.time()
                _REQUESTS[request_id] = entry
                response = _format_client_response(
                    protocol_version, request_id, "duplicate_pending", "NAK",
                    "REQUEST_ALREADY_SEEN_NO_CACHED_RESPONSE",
                    request_digest_sha256=request_digest,
                )
                _write_request_state()
            else:
                exclusive_busy = False
                if exclusive:
                    if _ACTIVE_REQUEST_ID or _REQUEST_QUEUE.qsize() != 0:
                        exclusive_busy = True
                    else:
                        for entry in _REQUESTS.values():
                            if not isinstance(entry, dict):
                                exclusive_busy = True
                                break
                            state = entry.get("state")
                            if state in _RECOVER_AS_ORPHANED_STATES:
                                exclusive_busy = True
                                break
                            if state not in _TERMINAL_STATES:
                                exclusive_busy = True
                                break
                late_waiting = (
                    _ACTIVE_REQUEST_ID in _REQUESTS
                    and (_REQUESTS.get(_ACTIVE_REQUEST_ID) or {}).get("state")
                    == "late_waiting_operator"
                )
                if _EXCLUSIVE_REQUEST_ID:
                    _REJECTED_BUSY_COUNT += 1
                    response = _busy_response(
                        protocol_version, request_id, request_digest
                    )
                    _write_request_state()
                elif exclusive_busy:
                    _REJECTED_BUSY_COUNT += 1
                    response = _busy_response(
                        protocol_version, request_id, request_digest
                    )
                    _write_request_state()
                elif late_waiting:
                    _REJECTED_BUSY_COUNT += 1
                    response = _late_completion_response(
                        protocol_version, request_id, request_digest
                    )
                    _write_request_state()
                elif _REQUEST_QUEUE.full():
                    _REJECTED_BUSY_COUNT += 1
                    response = _busy_response(protocol_version, request_id, request_digest)
                    _write_request_state()
                else:
                    now = time.time()
                    _REQUESTS[request_id] = {
                        "request_id": request_id,
                        "state": "queued",
                        "operation_class": operation_class,
                        "exclusive": exclusive,
                        "request_digest_sha256": request_digest,
                        "admitted_daemon_epoch": DAEMON_EPOCH,
                        "admitted_daemon_build_sha256": DAEMON_BUILD_SHA256 or None,
                        "queued_at_epoch": now,
                        "heartbeat_at_epoch": now,
                        "queue_position": _REQUEST_QUEUE.qsize() + 1,
                        "protocol_version": protocol_version,
                        "request_generation": request_generation,
                        "updated_at_epoch": now,
                    }
                    _REQUEST_ORDER.append(request_id)
                    if exclusive:
                        _EXCLUSIVE_REQUEST_ID = request_id
                        _EXCLUSIVE_REQUEST_GENERATION = request_generation
                    _trim_request_history_locked()
                    try:
                        _write_request_state()
                    except Exception:
                        _REQUESTS.pop(request_id, None)
                        if request_id in _REQUEST_ORDER:
                            _REQUEST_ORDER.remove(request_id)
                        if _EXCLUSIVE_REQUEST_ID == request_id:
                            _EXCLUSIVE_REQUEST_ID = None
                            _EXCLUSIVE_REQUEST_GENERATION = None
                        raise
                    try:
                        _REQUEST_QUEUE.put_nowait(admitted)
                    except _queue.Full:
                        _REQUESTS.pop(request_id, None)
                        if request_id in _REQUEST_ORDER:
                            _REQUEST_ORDER.remove(request_id)
                        if _EXCLUSIVE_REQUEST_ID == request_id:
                            _EXCLUSIVE_REQUEST_ID = None
                            _EXCLUSIVE_REQUEST_GENERATION = None
                        _REJECTED_BUSY_COUNT += 1
                        response = _busy_response(protocol_version, request_id, request_digest)
                        _write_request_state()
        if response is not None:
            _safe_sendall(conn, response)
            return False
        return True
    except RequestProtocolError as exc:
        _safe_sendall(conn, ("\x15{0}".format(str(exc))).encode("utf-8"))
    except ValueError as exc:
        _safe_sendall(
            conn,
            ("\x15JSONDecodeError: {0}".format(str(exc))).encode("utf-8"),
        )
    except Exception as exc:
        traceback.print_exc()
        _safe_sendall(conn, _format_client_response(
            protocol_version,
            request_id,
            "rejected",
            "NAK",
            str(exc),
            request_digest_sha256=request_digest,
        ))
    return False


def _expire_queued_request(request_id, generation, operation_class, protocol, digest, conn):
    """Persist admission-side evidence without claiming a CIW response."""
    finished = time.time()
    proof = {
        "schema_version": 1, "state": "expired_before_dispatch",
        "execution_dispatched": False, "request_id": request_id,
        "request_generation": generation, "request_digest_sha256": digest,
        "operation_class": operation_class, "protocol_version": protocol,
        "daemon_epoch": DAEMON_EPOCH, "daemon_build_sha256": DAEMON_BUILD_SHA256,
        "finished_at_epoch": finished,
    }
    response = _format_client_response(
        protocol, request_id, "expired_before_dispatch", "NAK",
        "REQUEST_EXPIRED_BEFORE_DISPATCH", request_digest_sha256=digest,
    )
    finalized = _finalize_request(request_id, generation, "expired_before_dispatch",
                      response_bytes=response, finished_at_epoch=finished,
                      execution_dispatched=False, pre_dispatch_proof=proof)
    if finalized:
        _safe_sendall(conn, response)


def handle_external_connection(admitted):
    """Execute one admitted request on the serial CIW stream."""
    (
        conn,
        addr,
        skill_code,
        timeout_seconds,
        request_id,
        operation_class,
        protocol_version,
        request_digest,
        request_generation,
        exclusive,
        deadline,
    ) = admitted
    watchdog_timer = None
    timed_out_event = threading.Event()
    late_wait_event = threading.Event()
    tmp_il_path = None

    try:
        if _monotonic() >= deadline:
            _expire_queued_request(request_id, request_generation, operation_class,
                                   protocol_version, request_digest, conn)
            return
        if not _mark_request_running(request_id, request_generation):
            _safe_sendall(conn, _format_client_response(
                protocol_version, request_id, "transport_unknown", "NAK",
                "REQUEST_ADMISSION_LOST", request_digest_sha256=request_digest,
            ))
            return

        # Send skill script to Virtuoso
        # Python 2.7 compatibility: ensure skill_code is string
        if hasattr(skill_code, 'encode'):  # Check if it's unicode
            skill_code = skill_code.encode('utf-8')

        # Clear stdin buffer before writing (non-blocking read until empty)

        while True:
            try:
                ch = sys.stdin.read(1)
                if not ch:  # No more data
                    break
            except IOError as e:
                if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    break  # No data available
                else:
                    break  # Other error, stop clearing

        # Multi-line SKILL: write to temp file and load() it.
        # This preserves comments (;) which would break single-line flattening.
        # We wrap the code so the return value is captured in a global variable,
        # because load() itself only returns t, not the last expression's value.
        if "\n" in skill_code or (hasattr(skill_code, 'decode') and b"\n" in skill_code):
            import tempfile
            fd, tmp_il_path = tempfile.mkstemp(suffix=".il", prefix="vb_eval_")
            f = os.fdopen(fd, "w")
            code_str = skill_code.decode("utf-8") if isinstance(skill_code, bytes) else skill_code
            f.write("_vb_eval_result = progn(\n%s\n)\n" % code_str)
            f.close()
            escaped_path = tmp_il_path.replace("\\", "/")
            send_code = 'load("%s") hiFlush() _vb_eval_result\n' % escaped_path
        else:
            send_code = 'let(((__vb_r %s)) hiFlush() __vb_r)\n' % skill_code

        remaining = deadline - _monotonic()
        if remaining <= 0:
            _expire_queued_request(request_id, request_generation, operation_class,
                                   protocol_version, request_digest, conn)
            return
        sys.stdout.write(send_code)
        sys.stdout.flush()

        # Start watchdog timer
        watchdog_timer = threading.Timer(
            remaining,
            watchdog_callback,
            args=(request_id, request_generation, timed_out_event),
        )
        watchdog_timer.daemon = True
        watchdog_timer.start()

        # Wait for Virtuoso response
        drain_deadline = deadline + _RESPONSE_DRAIN_WARNING_SECONDS
        returnData, response_too_large, response_bytes_seen = read_until_delimiter(
            drain_deadline,
            late_wait_callback=lambda: late_wait_warning_callback(
                request_id, request_generation, late_wait_event
            ),
        )
        was_timed_out = timed_out_event.is_set() or late_wait_event.is_set()

        # Cancel watchdog timer
        watchdog_timer.cancel()

        if isinstance(returnData, bytearray):
            response_bytes = "".join(chr(item) for item in returnData)
        elif isinstance(returnData, unicode):
            response_bytes = returnData.encode("utf-8")
        else:
            response_bytes = returnData
        response_digest = (
            None
            if response_too_large
            else hashlib.sha256(response_bytes).hexdigest()
        )
        first = response_bytes[:1] if response_bytes else b""
        marker = "STX" if first in ("\x02", b"\x02") else "NAK"
        payload_bytes = response_bytes[1:]
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        if response_too_large:
            final_state = "response_too_large"
            response_for_client = _format_client_response(
                protocol_version, request_id, "transport_unknown", "NAK",
                "RESPONSE_TOO_LARGE", request_digest_sha256=request_digest,
            )
            response_for_cache = None
        else:
            final_state = (
                ("succeeded_after_timeout" if marker == "STX" else "failed_after_timeout")
                if was_timed_out
                else ("succeeded" if marker == "STX" else "failed")
            )
            response_for_cache = _format_client_response(
                protocol_version, request_id, final_state, marker, payload_bytes,
                request_digest_sha256=request_digest,
            )
            response_for_client = (
                _format_client_response(
                    protocol_version, request_id, "timed_out_unknown", "NAK",
                    "TimeoutError", request_digest_sha256=request_digest,
                )
                if was_timed_out
                else response_for_cache
            )
        finished_at_epoch = time.time()
        terminal_proof = None
        if not response_too_large:
            terminal_proof = _build_terminal_proof(
                final_state,
                request_id,
                request_digest,
                operation_class,
                protocol_version,
                request_generation,
                marker,
                response_digest,
                payload_digest,
                response_bytes_seen,
                finished_at_epoch,
            )
        finalize_fields = {
            "response_bytes": response_for_cache,
            "finished_at_epoch": finished_at_epoch,
            "response_marker": marker,
            "response_digest_sha256": response_digest,
            "payload_digest_sha256": (
                None if response_too_large else payload_digest
            ),
            "response_size_bytes": response_bytes_seen,
            "response_too_large": response_too_large,
        }
        if terminal_proof is not None:
            finalize_fields["terminal_proof"] = terminal_proof
        _finalize_request(
            request_id,
            request_generation,
            final_state,
            **finalize_fields
        )

        _safe_sendall(conn, response_for_client)

        # Stats: count this call and tag as error if SKILL sent NAK
        # (0x15) or the response is empty/malformed.  Throttled emit
        # below pushes the totals to SKILL via stderr.
        global _RB_CALLS, _RB_ERRORS
        _RB_CALLS += 1
        _first = returnData[:1] if returnData else b""
        if isinstance(_first, str):
            _is_ok = (_first == "\x02")
        else:
            _is_ok = (_first == b"\x02")
        if not _is_ok:
            _RB_ERRORS += 1
        _emit_stat()

        # Clean up temp file if we used one
        if tmp_il_path:
            try:
                os.unlink(tmp_il_path)
            except OSError:
                pass

    except RequestProtocolError as e:
        _safe_sendall(conn, ("\x15{0}".format(str(e))).encode("utf-8"))
    except ValueError as e:
        # Python 2.7 compatibility: handle JSON decode errors
        error_msg = "\x15JSONDecodeError: {0}".format(str(e))
        if hasattr(error_msg, 'encode'):  # Check if it's unicode
            error_msg = error_msg.encode('utf-8')
        _safe_sendall(conn, error_msg)
    except ResponseStreamClosed:
        if request_id and request_generation:
            _handle_stream_closed(request_id, request_generation)
        _safe_sendall(conn, _format_client_response(
            protocol_version if "protocol_version" in locals() else 2,
            request_id, "transport_unknown", "NAK",
            "RESPONSE_STREAM_CLOSED",
            request_digest_sha256=(request_digest if "request_digest" in locals() else None),
        ))
        sys.stderr.write("ERROR: CIW response stream closed; retiring daemon.\n")
        sys.stderr.flush()
        _RETIRE_EVENT.set()
    except ResponseDrainTimeout:
        if request_id and request_generation:
            _finalize_request(
                request_id,
                request_generation,
                "orphaned_unknown_response_drain_timeout",
                finished_at_epoch=time.time(),
            )
        _safe_sendall(conn, _format_client_response(
            protocol_version if "protocol_version" in locals() else 2,
            request_id, "transport_unknown", "NAK",
            "RESPONSE_DRAIN_TIMEOUT_DAEMON_RETIRED",
            request_digest_sha256=(request_digest if "request_digest" in locals() else None),
        ))
        sys.stderr.write("ERROR: response drain deadline exceeded; retiring daemon.\n")
        sys.stderr.flush()
        _RETIRE_EVENT.set()
    except Exception as e:
        # Python 2.7 compatibility: except Exception, e syntax
        traceback.print_exc()
        if request_id and request_generation:
            _finalize_request(
                request_id,
                request_generation,
                "failed_internal",
                finished_at_epoch=time.time(),
            )
        _safe_sendall(conn, _format_client_response(
            protocol_version if "protocol_version" in locals() else 2,
            request_id,
            "transport_unknown" if request_generation else "rejected",
            "NAK",
            str(e),
            request_digest_sha256=(request_digest if "request_digest" in locals() else None),
        ))
    finally:
        if watchdog_timer:
            watchdog_timer.cancel()
        if tmp_il_path:
            try:
                os.unlink(tmp_il_path)
            except OSError:
                pass
        _safe_close_connection(conn)


def _finish_exclusive_request(request_id, request_generation):
    """Release a generation-scoped gate only after a proved terminal frame."""
    global _EXCLUSIVE_REQUEST_ID, _EXCLUSIVE_REQUEST_GENERATION
    with _STATE_LOCK:
        if (
            not request_id
            or _EXCLUSIVE_REQUEST_ID != request_id
            or _EXCLUSIVE_REQUEST_GENERATION != request_generation
        ):
            return False
        entry = _REQUESTS.get(request_id)
        if (
            isinstance(entry, dict)
            and entry.get("request_generation") == request_generation
            and entry.get("state") in _EXCLUSIVE_RELEASE_STATES
        ):
            _EXCLUSIVE_REQUEST_ID = None
            _EXCLUSIVE_REQUEST_GENERATION = None
            try:
                _write_request_state()
            except Exception:
                _EXCLUSIVE_REQUEST_ID = request_id
                _EXCLUSIVE_REQUEST_GENERATION = request_generation
                _RETIRE_EVENT.set()
                raise
            return True
        _RETIRE_EVENT.set()
        _write_request_state()
        return False


def _request_worker():
    while True:
        admitted = _REQUEST_QUEUE.get()
        request_id = admitted[4] if len(admitted) > 4 else None
        request_generation = admitted[8] if len(admitted) > 8 else None
        try:
            handle_external_connection(admitted)
        except BaseException:
            traceback.print_exc()
        finally:
            _finish_exclusive_request(request_id, request_generation)
            _REQUEST_QUEUE.task_done()

def start_server():
    """Start the TCP server to accept client connections."""
    if AUTH_TOKEN_FILE and not AUTH_TOKEN:
        sys.stderr.write("ERROR: daemon auth token file is missing or empty.\n")
        sys.exit(2)
    heartbeat = threading.Thread(target=_heartbeat_loop, name="bridge-heartbeat")
    heartbeat.daemon = True
    heartbeat.start()
    worker = threading.Thread(target=_request_worker, name="bridge-ciw-worker")
    worker.daemon = True
    worker.start()
    _write_request_state()
    # Python 2.7 compatibility: don't use context manager for socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Socket options for address reuse
        # Only use SO_REUSEADDR to allow quick restart after crash
        # Remove SO_REUSEPORT to prevent multiple daemons on same port
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Try to bind with error handling for port conflicts
        try:
            s.bind((HOST, PORT))
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                sys.stderr.write("ERROR: Port {0} is already in use. Another daemon may be running.\n".format(PORT))
                sys.exit(1)
            else:
                raise

        # Keep CIW execution serial, but allow healthy clients to queue while
        # half-open senders are bounded by the request-read deadline.
        s.listen(8)
        s.settimeout(1.0)
        # Banner -- SKILL side parses this from stderr to populate
        # RBLastPid / RBLastBind / RBLastHost / RBLastIP for the monitor
        # display.  Format is frozen:
        #   "[RB-banner] pid=N bind=H:P host=NAME ip=A.B.C.D"
        try:
            _hn = socket.gethostname() or "unknown"
        except Exception:
            _hn = "unknown"
        _ip = ""
        try:
            _probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                _probe.connect(("8.8.8.8", 80))
                _ip = _probe.getsockname()[0]
            finally:
                _probe.close()
        except Exception:
            try:
                _ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                _ip = ""
        sys.stderr.write(
            "[RB-banner] pid={0} bind={1}:{2} host={3} ip={4} build={5} protocols={6} epoch={7}\n".format(
                os.getpid(), HOST, PORT, _hn, (_ip or "unknown"),
                (DAEMON_BUILD_SHA256[:12] or "unknown"),
                ",".join(str(value) for value in PROTOCOL_VERSIONS),
                DAEMON_EPOCH,
            )
        )
        sys.stderr.flush()
        while not _RETIRE_EVENT.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            try:
                if not _admit_external_connection(conn, addr):
                    _safe_close_connection(conn)
            except Exception:
                traceback.print_exc()
                _safe_close_connection(conn)
        raise SystemExit(70)
    finally:
        s.close()

# Start the server
if __name__ == "__main__":
    start_server()
