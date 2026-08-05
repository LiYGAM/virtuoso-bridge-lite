#!/usr/bin/env python3
"""RAMIC Bridge Daemon - Virtuoso Skill Bridge Service (Python 3 Version)"""

import sys
import socket
import os
import json
import threading
import time
import errno
import hashlib
import hmac
import traceback
import uuid

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
            "[RB-stat] count={c} errors={e} uptime={u}\n".format(
                c=_RB_CALLS, e=_RB_ERRORS, u=int(now - _RB_START_T),
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

HOST = sys.argv[1]
PORT = int(sys.argv[2])
AUTH_TOKEN_FILE = sys.argv[3] if len(sys.argv) > 3 else ""
REQUEST_STATE_FILE = sys.argv[4] if len(sys.argv) > 4 else ""
PROFILE = sys.argv[5] if len(sys.argv) > 5 else ""


def _read_secret(path):
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except (OSError, IOError):
        return ""


AUTH_TOKEN = _read_secret(AUTH_TOKEN_FILE)
DAEMON_EPOCH = uuid.uuid4().hex
_REQUESTS = {}
_REQUEST_ORDER = []
_RESPONSE_CACHE = {}
_STATE_LOCK = threading.Lock()
_ACTIVE_REQUEST_ID = None
_MAX_REQUESTS = 64


def _load_request_history():
    if not REQUEST_STATE_FILE:
        return
    try:
        with open(REQUEST_STATE_FILE, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return
    for entry in payload.get("requests", [])[-_MAX_REQUESTS:]:
        request_id = str(entry.get("request_id") or "")
        if not request_id:
            continue
        restored = dict(entry)
        restored["restored_from_daemon_epoch"] = payload.get("daemon_epoch")
        if restored.get("state") in ("running", "timed_out_pending"):
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
        "daemon_epoch": DAEMON_EPOCH,
        "daemon_pid": os.getpid(),
        "bind_host": HOST,
        "port": PORT,
        "profile": PROFILE or None,
        "auth_enabled": bool(AUTH_TOKEN),
        "active_request_id": _ACTIVE_REQUEST_ID,
        "updated_at_epoch": time.time(),
        "requests": [_REQUESTS[key] for key in _REQUEST_ORDER if key in _REQUESTS],
    }
    directory = os.path.dirname(REQUEST_STATE_FILE)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, 0o700)
    tmp_path = "%s.tmp.%d" % (REQUEST_STATE_FILE, os.getpid())
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, REQUEST_STATE_FILE)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def _record_request(request_id, state, **fields):
    global _ACTIVE_REQUEST_ID
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
        while len(_REQUEST_ORDER) > _MAX_REQUESTS:
            expired = _REQUEST_ORDER.pop(0)
            _REQUESTS.pop(expired, None)
            _RESPONSE_CACHE.pop(expired, None)
        _ACTIVE_REQUEST_ID = request_id if state in ("running", "timed_out_pending") else None
        _write_request_state()

timeout_flag = False
current_request_id = None

# Get Virtuoso's PID (grandparent: virtuoso -> sh -> this daemon)
def get_grandparent_pid():
    try:
        with open('/proc/self/stat', 'r') as f:
            parent_pid = int(f.read().split()[3])
        with open(f'/proc/{parent_pid}/stat', 'r') as f:
            return int(f.read().split()[3])
    except Exception:
        raise Exception("Failed to get Virtuoso PID")

virtuoso_pid = get_grandparent_pid()

# Set stdin to non-blocking, keep stdout blocking.
stdin_fd = sys.stdin.fileno()
stdin_fl = _fcntl_or_die(stdin_fd, _f_getfl)
_fcntl_or_die(stdin_fd, _f_setfl, stdin_fl | _o_nonblock)

stdout_fd = sys.stdout.fileno()
stdout_fl = _fcntl_or_die(stdout_fd, _f_getfl)
_fcntl_or_die(stdout_fd, _f_setfl, stdout_fl & ~_o_nonblock)

watchdog_timer = None


def _safe_sendall(conn, data):
    try:
        conn.sendall(data)
    except OSError:
        pass


def _safe_close_connection(conn):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass

def watchdog_callback():
    """Mark the request timed out without asynchronously interrupting CIW.

    SIGINT can unwind RBIpcDataHandler before it writes a framed response,
    leaving the daemon unable to realign its serial response stream.  The
    client still enforces its own socket deadline; this daemon keeps draining
    until the original callback returns.
    """
    global timeout_flag
    if not timeout_flag:
        timeout_flag = True
        request_id = globals().get("current_request_id")
        if request_id and "_record_request" in globals():
            _record_request(request_id, "timed_out_pending")

def read_until_delimiter(start_ok=0x02, start_err=0x15, end=0x1e):
    """Read one complete response, even after the request watchdog expires.

    A timed-out SKILL callback may still return later, especially when it is
    blocked by a modal form.  The response must be drained before accepting
    another request or that late response will be mistaken for the next one.
    """
    result = bytearray()

    # Wait for start marker
    while True:
        try:
            ch = sys.stdin.buffer.read(1)
            if not ch:
                time.sleep(0.001)
                continue
            if ch[0] in (start_ok, start_err):
                result.extend(ch)
                break
        except IOError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                time.sleep(0.001)
                continue
            raise

    # Read content until end marker
    while True:
        try:
            ch = sys.stdin.buffer.read(1)
            if not ch:
                time.sleep(0.001)
                continue
            if ch[0] == end:
                break
            result.extend(ch)
        except IOError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                time.sleep(0.001)
                continue
            raise

    if timeout_flag:
        return b"\x15TimeoutError"
    return result

def handle_external_connection(conn, addr):
    global watchdog_timer, timeout_flag, current_request_id
    request_id = ""

    try:
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        request_data = json.loads(data.decode("utf-8"))

        skill_code = request_data["skill"]
        timeout_seconds = request_data["timeout"]
        request_id = str(request_data.get("request_id") or "")
        operation_class = str(request_data.get("operation_class") or "unknown")
        protocol_version = int(request_data.get("protocol_version") or 1)
        supplied_token = request_data.get("auth_token") or ""
        if AUTH_TOKEN and not _safe_token_equal(supplied_token, AUTH_TOKEN):
            _safe_sendall(conn, b"\x15AUTH_REQUIRED")
            return
        if protocol_version != 2 or not request_id:
            _safe_sendall(conn, b"\x15PROTOCOL_V2_REQUIRED")
            return
        request_digest = hashlib.sha256(
            (operation_class + "\x00" + skill_code).encode("utf-8")
        ).hexdigest()
        previous = _REQUESTS.get(request_id)
        if previous and previous.get("request_digest_sha256") != request_digest:
            _safe_sendall(conn, b"\x15REQUEST_ID_CONFLICT")
            return
        if request_id in _RESPONSE_CACHE:
            _record_request(request_id, "duplicate_replayed", duplicate=True)
            _safe_sendall(conn, _RESPONSE_CACHE[request_id])
            return
        if previous:
            _record_request(request_id, "duplicate_rejected_no_cached_response", duplicate=True)
            _safe_sendall(conn, b"\x15REQUEST_ALREADY_SEEN_NO_CACHED_RESPONSE")
            return

        current_request_id = request_id
        _record_request(
            request_id,
            "running",
            operation_class=operation_class,
            request_digest_sha256=request_digest,
            started_at_epoch=time.time(),
            protocol_version=protocol_version,
        )

        timeout_flag = False

        # Clear stdin buffer before writing
        while True:
            try:
                ch = sys.stdin.buffer.read(1)
                if not ch:
                    break
            except IOError:
                break

        # Multi-line SKILL: write to temp file and load() it.
        # This preserves comments (;) which would break single-line flattening.
        # We wrap the code so the return value is captured in a global variable,
        # because load() itself only returns t, not the last expression's value.
        tmp_il_path = None
        if "\n" in skill_code:
            import tempfile
            fd, tmp_il_path = tempfile.mkstemp(suffix=".il", prefix="vb_eval_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"_vb_eval_result = progn(\n{skill_code}\n)\n")
            escaped_path = tmp_il_path.replace("\\", "/")
            send_code = f'load("{escaped_path}") hiFlush() _vb_eval_result\n'
        else:
            send_code = f'let(((__vb_r {skill_code})) hiFlush() __vb_r)\n'

        sys.stdout.buffer.write(send_code.encode("utf-8"))
        sys.stdout.buffer.flush()

        # Start watchdog timer
        watchdog_timer = threading.Timer(timeout_seconds, watchdog_callback)
        watchdog_timer.daemon = True
        watchdog_timer.start()

        returnData = read_until_delimiter()
        was_timed_out = timeout_flag

        if not timeout_flag:
            timeout_flag = True
        watchdog_timer.cancel()

        response_digest = hashlib.sha256(bytes(returnData)).hexdigest()
        marker = "STX" if returnData[:1] == b"\x02" else "NAK"
        final_state = (
            "completed_after_timeout_unknown"
            if was_timed_out
            else ("succeeded" if marker == "STX" else "failed")
        )
        _RESPONSE_CACHE[request_id] = bytes(returnData)
        _record_request(
            request_id,
            final_state,
            finished_at_epoch=time.time(),
            response_marker=marker,
            response_digest_sha256=response_digest,
        )

        _safe_sendall(conn, returnData)

        # Stats: count this call and tag as error if SKILL sent NAK
        # (0x15) or the response is empty/malformed.  Throttled emit
        # below pushes the totals to SKILL via stderr.
        global _RB_CALLS, _RB_ERRORS
        _RB_CALLS += 1
        if not returnData or returnData[:1] != b"\x02":
            _RB_ERRORS += 1
        _emit_stat()

        # Clean up temp file if we used one
        if tmp_il_path:
            try:
                os.unlink(tmp_il_path)
            except OSError:
                pass

    except json.JSONDecodeError as e:
        _safe_sendall(conn, f"\x15JSONDecodeError: {e}".encode("utf-8"))
    except Exception as e:
        traceback.print_exc()
        if request_id and request_id in _REQUESTS:
            _record_request(request_id, "failed_internal", finished_at_epoch=time.time())
        _safe_sendall(conn, f"\x15{e}".encode("utf-8"))
    finally:
        current_request_id = None
        timeout_flag = True
        if watchdog_timer:
            watchdog_timer.cancel()
        _safe_close_connection(conn)

def start_server():
    if AUTH_TOKEN_FILE and not AUTH_TOKEN:
        sys.stderr.write("ERROR: daemon auth token file is missing or empty.\n")
        sys.exit(2)
    _write_request_state()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                sys.stderr.write(f"ERROR: Port {PORT} is already in use. Another daemon may be running.\n")
                sys.exit(1)
            raise
        s.listen(1)
        # Banner -- SKILL side parses this from stderr to populate
        # RBLastPid / RBLastBind / RBLastHost / RBLastIP for the monitor
        # display.  Format is frozen:
        #   "[RB-banner] pid=N bind=H:P host=NAME ip=A.B.C.D"
        try:
            _hn = socket.gethostname() or "unknown"
        except Exception:
            _hn = "unknown"
        # Best-effort outward-facing IPv4: ask the kernel which source
        # IP it would pick for outbound traffic.  UDP connect() sends
        # nothing on the wire, it just runs the route lookup so that
        # getsockname() returns the chosen local address.  Bypasses
        # /etc/hosts entries that map hostname to 127.0.0.1.
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
            "[RB-banner] pid={pid} bind={host}:{port} host={hn} ip={ip}\n".format(
                pid=os.getpid(), host=HOST, port=PORT, hn=_hn, ip=(_ip or "unknown"),
            )
        )
        sys.stderr.flush()
        while True:
            conn, addr = s.accept()
            try:
                handle_external_connection(conn, addr)
            except Exception:
                traceback.print_exc()
                _safe_close_connection(conn)

if __name__ == "__main__":
    start_server()
