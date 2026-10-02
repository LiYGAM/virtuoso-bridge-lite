#!/usr/bin/env python2
"""X11 dialog finder and dismisser. Runs on the remote Virtuoso host.

Usage:
    python2 x11_dismiss_dialog.py [DISPLAY] [--dismiss]

Output (stdout): JSON lines, one per dialog found:
    {"window_id": "0x2e01f16", "title": "Save Changes", "x": 1010, "y": 378, "w": 239, "h": 142}

With --dismiss: sends Enter key to each dialog found.
DISPLAY auto-detected from running virtuoso process if omitted.

Exit codes: 0 = dialogs found/dismissed, 1 = no dialogs found, 2 = error
"""
import ctypes
import ctypes.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

VIRTUOSO_WM_CLASSES = ["virtuoso", "libManager"]
KNOWN_MODAL_ACTIONS = {
    "ade explorer update and run": "enter",
    "ade assembler message 1749": "alt-o",
}

_INSPECTION_TIMEOUT_SECONDS = 2.0
_INSPECTION_TOTAL_TIMEOUT_SECONDS = 15.0
_MAX_INSPECTION_WINDOWS = 1024
_MAX_OWNERSHIP_DEPTH = 16
_MAX_ROOT_WINDOW_CHILDREN = 16384
_MAX_FRAME_SEARCH_DEPTH = 8
_MAX_X11_NATIVE_QUERIES = 4096


class _InspectionFailure(Exception):
    pass


class _InspectionBudgetExceeded(_InspectionFailure):
    pass


def find_x11_envs(user=None):
    """Return X11 environments for all interactive Virtuoso processes."""
    candidates = []
    try:
        pids = subprocess.check_output(
            ["pgrep", "-u", user or os.environ.get("USER", ""), "-x", "virtuoso"],
            stderr=subprocess.PIPE
        ).decode().split()
        for pid in pids:
            pid = pid.strip()
            if not pid:
                continue
            # Skip batch processes (have -nograph in cmdline)
            try:
                cmdline = open("/proc/%s/cmdline" % pid, "rb").read()
                if b"-nograph" in cmdline:
                    continue
            except (IOError, OSError):
                pass
            env_file = "/proc/%s/environ" % pid
            try:
                data = open(env_file, "rb").read()
                info = {}
                info["DISPLAY"] = None
                info["XAUTHORITY"] = None
                for chunk in data.split(b"\x00"):
                    if chunk.startswith(b"DISPLAY="):
                        info["DISPLAY"] = chunk.split(b"=", 1)[1].decode()
                    elif chunk.startswith(b"XAUTHORITY="):
                        info["XAUTHORITY"] = chunk.split(b"=", 1)[1].decode()
                if info["DISPLAY"]:
                    candidates.append(info)
            except (IOError, OSError):
                continue
    except (subprocess.CalledProcessError, OSError):
        pass

    unique = []
    seen = set()
    for candidate in candidates:
        key = (candidate.get("DISPLAY"), candidate.get("XAUTHORITY"))
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def find_x11_env(user=None):
    """Return the first interactive Virtuoso X11 environment for compatibility."""
    candidates = find_x11_envs(user)
    if not candidates:
        return {"DISPLAY": None, "XAUTHORITY": None}

    return candidates[0]


def _parse_window_line(line):
    """Parse one xwininfo tree/children line."""
    line = line.strip()
    if not line.startswith("0x"):
        return None
    parts = line.split(None, 1)
    if not parts:
        return None
    win = {"id": parts[0], "title": "", "class": [], "geometry": {}}
    if '"' in line:
        try:
            start = line.index('"') + 1
            end = line.index('"', start)
            win["title"] = line[start:end]
        except ValueError:
            pass
    class_match = re.search(r":\s*\(([^)]*)\)", line)
    if class_match:
        win["class"] = re.findall(r'"([^"]*)"', class_match.group(1))
    geo_match = re.search(r"(\d+)x(\d+)([+-]\d+)([+-]\d+)", line)
    if geo_match:
        win["geometry"] = {
            "w": int(geo_match.group(1)),
            "h": int(geo_match.group(2)),
            "x": int(geo_match.group(3)),
            "y": int(geo_match.group(4)),
        }
    return win


def _is_virtuoso_class(classes):
    lowered = [c.lower() for c in (classes or [])]
    for cls in VIRTUOSO_WM_CLASSES:
        if cls.lower() in lowered:
            return True
    return False


def _read_xprop_metadata(win_id):
    """Read title/class without xwininfo's locale-dependent conversion."""
    try:
        output = subprocess.check_output(
            ["xprop", "-id", win_id, "_NET_WM_NAME", "WM_NAME", "WM_CLASS"],
            stderr=subprocess.PIPE
        ).decode("utf-8", "replace")
    except (subprocess.CalledProcessError, OSError):
        return {"title": "", "class": []}
    titles = {}
    classes = []
    for line in output.splitlines():
        values = re.findall(r'"((?:\\.|[^"\\])*)"', line)
        if line.startswith("WM_NAME(") and values:
            titles["wm"] = values[0]
        elif line.startswith("_NET_WM_NAME(") and values:
            titles["net"] = values[0]
        elif line.startswith("WM_CLASS(") and values:
            classes = values
    return {"title": titles.get("wm") or titles.get("net") or "", "class": classes}


def _repair_locale_damaged_metadata(window):
    title = window.get("title") or ""
    if "failure in conversion" not in title.lower():
        return window
    metadata = _read_xprop_metadata(window["id"])
    if metadata.get("title"):
        window["title"] = metadata["title"]
    if metadata.get("class"):
        window["class"] = metadata["class"]
    return window


def _read_window_info(win_id):
    try:
        info = subprocess.check_output(
            ["xwininfo", "-id", win_id],
            stderr=subprocess.PIPE
        ).decode("utf-8", "replace")
    except (subprocess.CalledProcessError, OSError):
        return {"geometry": {}, "mapped": False}
    geometry = {}
    mapped = False
    for il in info.splitlines():
        il = il.strip()
        try:
            if il.startswith("Absolute upper-left X:"):
                geometry["x"] = int(il.split(":")[1].strip())
            elif il.startswith("Absolute upper-left Y:"):
                geometry["y"] = int(il.split(":")[1].strip())
            elif il.startswith("Width:"):
                geometry["w"] = int(il.split(":")[1].strip())
            elif il.startswith("Height:"):
                geometry["h"] = int(il.split(":")[1].strip())
            elif "Map State:" in il and "IsViewable" in il:
                mapped = True
        except (ValueError, IndexError):
            pass
    return {"geometry": geometry, "mapped": mapped}


WINDOW_INPUT_ACTIONS = ("move", "click", "drag", "text", "key")


def keyboard_chords(action, text=None, key=None):
    """Validate a bounded request; never interpret text as shortcuts."""
    names = {"Tab": "Tab", "Enter": "Return", "Return": "Return",
             "Esc": "Escape", "Escape": "Escape", "Backspace": "BackSpace",
             "Delete": "Delete", "Left": "Left", "Right": "Right",
             "Up": "Up", "Down": "Down", "Home": "Home", "End": "End",
             "Space": "space"}
    if action == "text":
        if key is not None or not text or len(text) > 256:
            raise ValueError("text requires 1-256 printable ASCII characters and no key")
        if any(ord(c) < 32 or ord(c) > 126 for c in text):
            raise ValueError("text supports printable ASCII only; use key for control keys")
        return [[ord(c)] for c in text]
    if action == "key":
        if text is not None or not key:
            raise ValueError("key requires one named key/chord and no text")
        parts = key.split("+")
        mods = {"Ctrl": "Control_L", "Shift": "Shift_L", "Alt": "Alt_L"}
        if len(parts) > 4 or len(set(parts[:-1])) != len(parts[:-1]):
            raise ValueError("invalid key modifiers")
        if any(p not in mods for p in parts[:-1]):
            raise ValueError("supported modifiers: Ctrl, Shift, Alt")
        last = parts[-1]
        symbol = names.get(last)
        if symbol is None and len(last) == 1 and ord(last) < 128 and last.isalnum():
            symbol = ord(last.lower())
        if symbol is None:
            raise ValueError("unsupported key name")
        return [[mods[p] for p in parts[:-1]] + [symbol]]
    if text is not None or key is not None:
        raise ValueError("text/key payload is only valid for keyboard actions")
    return None


def _configure_keyboard_x11(xlib, xtst):
    p, u = ctypes.c_void_p, ctypes.c_ulong
    xlib.XGetInputFocus.argtypes = [p, ctypes.POINTER(u), ctypes.POINTER(ctypes.c_int)]
    xlib.XQueryTree.argtypes = [p, u, ctypes.POINTER(u), ctypes.POINTER(u),
                              ctypes.POINTER(ctypes.POINTER(u)), ctypes.POINTER(ctypes.c_uint)]
    xlib.XFree.argtypes = [p]
    xlib.XStringToKeysym.argtypes = [ctypes.c_char_p]
    xlib.XStringToKeysym.restype = u
    xlib.XKeysymToKeycode.argtypes = [p, u]
    xlib.XKeysymToKeycode.restype = ctypes.c_ubyte
    xlib.XKeycodeToKeysym.argtypes = [p, ctypes.c_ubyte, ctypes.c_int]
    xlib.XKeycodeToKeysym.restype = u
    xlib.XQueryKeymap.argtypes = [p, ctypes.c_void_p]
    xlib.XQueryPointer.argtypes = [p, u, ctypes.POINTER(u), ctypes.POINTER(u)] + [ctypes.POINTER(ctypes.c_int)] * 4 + [ctypes.POINTER(ctypes.c_uint)]
    xtst.XTestFakeKeyEvent.argtypes = [p, ctypes.c_uint, ctypes.c_int, u]
    xtst.XTestFakeKeyEvent.restype = ctypes.c_int


def _keyboard_focus(xlib, dpy, target):
    focus, revert = ctypes.c_ulong(), ctypes.c_int()
    xlib.XGetInputFocus(dpy, ctypes.byref(focus), ctypes.byref(revert))
    original = focus.value
    current = original
    for _ in range(64):
        if current == target:
            return original
        if current in (0, 1):
            break
        root, parent, count = ctypes.c_ulong(), ctypes.c_ulong(), ctypes.c_uint()
        children = ctypes.POINTER(ctypes.c_ulong)()
        ok = xlib.XQueryTree(dpy, current, ctypes.byref(root), ctypes.byref(parent),
                            ctypes.byref(children), ctypes.byref(count))
        if children:
            xlib.XFree(children)
        if not ok or parent.value == current:
            break
        current = parent.value
    raise RuntimeError("keyboard focus is outside target window; click the intended field first")


def _keyboard_idle(xlib, dpy, target):
    keys = ctypes.create_string_buffer(32)
    xlib.XQueryKeymap(dpy, keys)
    if any(bytearray(keys.raw)):
        raise RuntimeError("physical keys are held; refusing keyboard input")
    root, child, mask = ctypes.c_ulong(), ctypes.c_ulong(), ctypes.c_uint()
    coords = [ctypes.c_int() for _ in range(4)]
    if not xlib.XQueryPointer(dpy, target, ctypes.byref(root), ctypes.byref(child),
                             ctypes.byref(coords[0]), ctypes.byref(coords[1]),
                             ctypes.byref(coords[2]), ctypes.byref(coords[3]), ctypes.byref(mask)):
        raise RuntimeError("cannot inspect keyboard modifier state")
    # NumLock is harmless for the supported non-keypad symbols; other modifiers
    # (including CapsLock and mouse buttons) can alter input semantics.
    if mask.value & ~16:
        raise RuntimeError("active modifiers/buttons (including CapsLock); refusing input")


def _keyboard_codes(xlib, dpy, chords):
    result = []
    shift = xlib.XKeysymToKeycode(dpy, xlib.XStringToKeysym(b"Shift_L"))
    for chord in chords:
        codes = []
        for symbol in chord:
            sym = symbol if isinstance(symbol, int) else xlib.XStringToKeysym(symbol.encode("ascii"))
            code = xlib.XKeysymToKeycode(dpy, sym)
            if not code:
                raise ValueError("key is absent from current X keyboard map")
            if xlib.XKeycodeToKeysym(dpy, code, 0) != sym:
                if not shift or xlib.XKeycodeToKeysym(dpy, code, 1) != sym:
                    raise ValueError("key requires an unsupported keyboard layout/group")
                if shift not in codes:
                    codes.append(shift)
            if code not in codes:
                codes.append(code)
        result.append(codes)
    return result


def send_keyboard_input(display, prepared, timing, refresh_preflight, dry_run=False):
    """Require existing target focus; release every injected key even on failure."""
    result = dict(prepared)
    result.update(sent=False, events_sent=0, retry_safe=False)
    dpy, held = None, []
    try:
        xlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11") or "libX11.so.6")
        xtst = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Xtst") or "libXtst.so.6")
        _configure_pointer_x11(xlib, xtst)
        _configure_keyboard_x11(xlib, xtst)
        dpy = xlib.XOpenDisplay(display.encode("ascii"))
        if not dpy:
            raise RuntimeError("cannot open display")
        target = int(prepared["window_id"], 0)
        result["focus_before"] = hex(_keyboard_focus(xlib, dpy, target))
        _keyboard_idle(xlib, dpy, target)
        codes = _keyboard_codes(xlib, dpy, prepared["chords"])
        refreshed = refresh_preflight()
        if refreshed["fingerprint"] != prepared["fingerprint"]:
            raise RuntimeError("target fingerprint changed")
        result["dry_run"] = dry_run
        if dry_run:
            result["planned_chords"] = codes
            return result
        if timing["settle_ms"]:
            time.sleep(timing["settle_ms"] / 1000.0)
        for chord in codes:
            _keyboard_focus(xlib, dpy, target)
            _keyboard_idle(xlib, dpy, target)
            for code in chord:
                held.append(code)
                result["sent"] = True
                _xtest_or_raise(xtst.XTestFakeKeyEvent, "XTestFakeKeyEvent", dpy, code, True, 0)
                result["events_sent"] += 1
            for code in reversed(chord):
                _xtest_or_raise(xtst.XTestFakeKeyEvent, "XTestFakeKeyEvent", dpy, code, False, 0)
                held.remove(code)
                result["events_sent"] += 1
            _sync_or_raise(xlib, dpy, "keyboard input")
            time.sleep(0.005)
        result["delivery"] = "events-sent; application effect requires separate verification"
    except Exception as exc:
        result["error"] = str(exc)
        result["completion"] = "unknown" if result["sent"] else "not-sent"
    finally:
        if dpy:
            for code in reversed(held):
                try:
                    xtst.XTestFakeKeyEvent(dpy, code, False, 0)
                except Exception:
                    pass
            xlib.XFlush(dpy)
            xlib.XCloseDisplay(dpy)
    return result
WINDOW_INPUT_POSTCONDITIONS = (
    "none", "still-mapped", "unmapped", "same-fingerprint", "title-contains",
)
_WINDOW_INPUT_MAX_DELAY_MS = 5000
_WINDOW_INPUT_MAX_DRAG_STEPS = 100


def _input_child_candidate(windows, window_id):
    """Return a currently discovered child candidate, never its WM frame."""
    for candidate in windows or []:
        child_id = candidate.get("dismiss_id") or candidate.get("window_id")
        if child_id == candidate.get("frame_id"):
            continue
        if child_id == window_id:
            return candidate
    return None


def _input_fingerprint(candidate):
    """Return the stable identity fields that guard a reused X11 id."""
    return {
        "window_id": candidate.get("dismiss_id") or candidate.get("window_id"),
        "frame_id": candidate.get("frame_id"),
        "title": candidate.get("title") or "",
        "class": list(candidate.get("class") or []),
    }


def _capture_window_input_state(display, window_id):
    """Capture a fresh discovery plus exact child xwininfo state."""
    windows = discover_windows(display)
    candidate = _input_child_candidate(windows, window_id)
    if candidate is None:
        return {"found": False, "window_id": window_id}
    info = _read_window_info(window_id)
    return {
        "found": True,
        "fingerprint": _input_fingerprint(candidate),
        "mapped": bool(info.get("mapped", False)),
        "geometry": info.get("geometry") or {},
    }


def _prepared_window_input_state(prepared):
    return {
        "found": True,
        "fingerprint": prepared["fingerprint"],
        "mapped": True,
        "geometry": dict(prepared["geometry"]),
    }


def _validate_window_input_timing(settle_ms=50, hold_ms=0,
                                  drag_duration_ms=0, drag_steps=1):
    """Normalize bounded timing knobs without changing the default behavior."""
    values = {
        "settle_ms": settle_ms,
        "hold_ms": hold_ms,
        "drag_duration_ms": drag_duration_ms,
        "drag_steps": drag_steps,
    }
    try:
        for key in values:
            values[key] = int(values[key])
    except (TypeError, ValueError):
        raise ValueError("window-input timing values must be integers")
    for key in ("settle_ms", "hold_ms", "drag_duration_ms"):
        if values[key] < 0 or values[key] > _WINDOW_INPUT_MAX_DELAY_MS:
            raise ValueError("%s must be from 0 to %d" % (key, _WINDOW_INPUT_MAX_DELAY_MS))
    if values["drag_steps"] < 1 or values["drag_steps"] > _WINDOW_INPUT_MAX_DRAG_STEPS:
        raise ValueError("drag_steps must be from 1 to %d" % _WINDOW_INPUT_MAX_DRAG_STEPS)
    return values


def preflight_window_input(windows, window_id, expect_title, action, x=None, y=None,
                           button=1, to_x=None, to_y=None, window_info=None,
                           text=None, key=None):
    """Validate a pointer operation without opening X11 or emitting events.

    ``windows`` must be a freshly discovered list from :func:`discover_windows`
    and ``window_info`` must be a fresh exact-target ``xwininfo`` response.
    This deliberately does not accept a WM frame id or cached geometry.
    """
    if not expect_title:
        raise ValueError("--expect-title is required")
    if action not in WINDOW_INPUT_ACTIONS:
        raise ValueError("unsupported action: %s" % action)
    chords = keyboard_chords(action, text, key)
    if chords is not None:
        if any(v is not None for v in (x, y, to_x, to_y)):
            raise ValueError("keyboard actions do not accept pointer coordinates")
        x, y = 0, 0
    try:
        button = int(button)
    except (TypeError, ValueError):
        raise ValueError("button must be an integer from 1 to 3")
    if button not in (1, 2, 3):
        raise ValueError("button must be from 1 to 3")
    try:
        x, y = int(x), int(y)
    except (TypeError, ValueError):
        raise ValueError("x and y must be integers")

    target = _input_child_candidate(windows, window_id)
    if target is None:
        raise ValueError("window id is not a currently discovered Virtuoso child: %s" % window_id)

    title = target.get("title") or ""
    if expect_title not in title:
        raise ValueError("window title does not contain expected text")

    info = window_info or {}
    if not info.get("mapped", False):
        raise ValueError("target window is not mapped/viewable")
    geometry = info.get("geometry") or {}
    try:
        root_x = int(geometry["x"])
        root_y = int(geometry["y"])
        width = int(geometry["w"])
        height = int(geometry["h"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("target window has incomplete current geometry")
    if width <= 0 or height <= 0:
        raise ValueError("target window has invalid current geometry")

    if action == "drag":
        if to_x is None or to_y is None:
            raise ValueError("drag requires both --to-x and --to-y")
        try:
            to_x, to_y = int(to_x), int(to_y)
        except (TypeError, ValueError):
            raise ValueError("drag endpoint must be integer coordinates")
    elif to_x is not None or to_y is not None:
        raise ValueError("--to-x and --to-y are only valid for drag")

    points = [("x/y", x, y)]
    if action == "drag":
        points.append(("to-x/to-y", to_x, to_y))
    for label, point_x, point_y in points:
        if point_x < 0 or point_x >= width or point_y < 0 or point_y >= height:
            raise ValueError("%s is outside current target bounds" % label)

    prepared = {
        "window_id": window_id,
        "fingerprint": _input_fingerprint(target),
        "title": title,
        "action": action,
        "button": button,
        "geometry": {"x": root_x, "y": root_y, "w": width, "h": height},
        "relative": {"x": x, "y": y},
        "root": {"x": root_x + x, "y": root_y + y},
    }
    if chords is not None:
        if expect_title != title:
            raise ValueError("keyboard actions require the exact window title")
        prepared["chords"] = chords
    if action == "drag":
        prepared["relative"].update({"to_x": to_x, "to_y": to_y})
        prepared["root"].update({"to_x": root_x + to_x, "to_y": root_y + to_y})
    return prepared


def build_window_input_events(prepared):
    """Return the XTest event sequence for a validated pointer operation."""
    root = prepared["root"]
    action = prepared["action"]
    button = prepared["button"]
    events = [("motion", root["x"], root["y"])]
    if action == "click":
        events.extend([("button", button, True), ("button", button, False)])
    elif action == "drag":
        events.extend([
            ("button", button, True),
            ("motion", root["to_x"], root["to_y"]),
            ("button", button, False),
        ])
    return events


def build_window_input_schedule(prepared, timing):
    """Return event/sleep steps for a validated pointer operation."""
    action = prepared["action"]
    button = prepared["button"]
    root = prepared["root"]
    schedule = [("event", ("motion", root["x"], root["y"]))]
    if action == "move":
        return schedule
    schedule.append(("event", ("button", button, True)))
    if timing["hold_ms"]:
        schedule.append(("sleep", timing["hold_ms"]))
    if action == "drag":
        steps = timing["drag_steps"]
        start_x, start_y = root["x"], root["y"]
        end_x, end_y = root["to_x"], root["to_y"]
        for step in range(1, steps + 1):
            if timing["drag_duration_ms"]:
                schedule.append(("sleep", float(timing["drag_duration_ms"]) / steps))
            schedule.append(("event", (
                "motion",
                start_x + ((end_x - start_x) * step // steps),
                start_y + ((end_y - start_y) * step // steps),
            )))
    schedule.append(("event", ("button", button, False)))
    return schedule


def _configure_pointer_x11(xlib, xtst):
    """Declare ctypes signatures used by window-input XTest calls."""
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xlib.XFlush.argtypes = [ctypes.c_void_p]
    xlib.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XSetInputFocus.argtypes = [
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong,
    ]
    xlib.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    xlib.XSync.restype = ctypes.c_int
    xtst.XTestFakeMotionEvent.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong,
    ]
    xtst.XTestFakeMotionEvent.restype = ctypes.c_int
    xtst.XTestFakeButtonEvent.argtypes = [
        ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong,
    ]
    xtst.XTestFakeButtonEvent.restype = ctypes.c_int


def _xtest_or_raise(function, name, *args):
    if not function(*args):
        raise RuntimeError("%s returned failure" % name)


def _sync_or_raise(xlib, dpy, phase):
    if not xlib.XSync(dpy, False):
        raise RuntimeError("XSync failed during %s" % phase)


def send_window_input(display, prepared, timing=None, refresh_preflight=None,
                      sleeper=None):
    """Emit a preflighted XTest pointer sequence, releasing a held drag button."""
    timing = timing or _validate_window_input_timing()
    sleeper = sleeper or time.sleep
    xlib_path = ctypes.util.find_library("X11")
    xtst_path = ctypes.util.find_library("Xtst")
    if not xlib_path or not xtst_path:
        return {"error": "libX11 or libXtst not found"}
    xlib = ctypes.cdll.LoadLibrary(xlib_path)
    xtst = ctypes.cdll.LoadLibrary(xtst_path)
    _configure_pointer_x11(xlib, xtst)
    dpy = xlib.XOpenDisplay(None)
    if not dpy:
        return {"error": "cannot open display %s" % display}

    pressed = False
    released = False
    try:
        target_id = int(prepared["window_id"], 16) \
            if prepared["window_id"].startswith("0x") \
            else int(prepared["window_id"])
        xlib.XRaiseWindow(dpy, target_id)
        xlib.XSetInputFocus(dpy, target_id, 1, 0)  # RevertToParent
        _sync_or_raise(xlib, dpy, "focus")
        if refresh_preflight is not None:
            refreshed = refresh_preflight()
            if refreshed["fingerprint"] != prepared["fingerprint"]:
                raise RuntimeError("target window fingerprint changed after focus")
            prepared = refreshed
        if timing["settle_ms"]:
            sleeper(float(timing["settle_ms"]) / 1000.0)
        for step in build_window_input_schedule(prepared, timing):
            if step[0] == "sleep":
                sleeper(float(step[1]) / 1000.0)
                continue
            event = step[1]
            if event[0] == "motion":
                _xtest_or_raise(
                    xtst.XTestFakeMotionEvent, "XTestFakeMotionEvent",
                    dpy, -1, event[1], event[2], 0,
                )
            else:
                if event[2]:
                    # Mark before the call: an exception may follow an accepted
                    # X request, so finally must still attempt the release.
                    pressed = True
                _xtest_or_raise(
                    xtst.XTestFakeButtonEvent, "XTestFakeButtonEvent",
                    dpy, event[1], event[2], 0,
                )
                if not event[2]:
                    released = True
        _sync_or_raise(xlib, dpy, "input")
    except Exception as exc:
        return {"error": "XTest input failed: %s" % str(exc)}
    finally:
        if pressed and not released:
            try:
                xtst.XTestFakeButtonEvent(dpy, prepared["button"], False, 0)
                xlib.XFlush(dpy)
            except Exception:
                pass
        xlib.XCloseDisplay(dpy)
    result = dict(prepared)
    result["sent"] = True
    result["timing"] = dict(timing)
    result["sync"] = {"after_focus": True, "after_input": True}
    return result


def _evaluate_window_input_postcondition(postcondition, before, after,
                                         post_expect_title=None):
    if postcondition not in WINDOW_INPUT_POSTCONDITIONS:
        raise ValueError("unsupported postcondition: %s" % postcondition)
    if postcondition == "none":
        return {"requested": postcondition, "passed": True}
    if postcondition == "still-mapped":
        passed = bool(after.get("found") and after.get("mapped"))
    elif postcondition == "unmapped":
        passed = not (after.get("found") and after.get("mapped"))
    elif postcondition == "same-fingerprint":
        passed = bool(after.get("found") and
                      before.get("fingerprint") == after.get("fingerprint"))
    else:
        if not post_expect_title:
            raise ValueError("title-contains requires --post-expect-title")
        fingerprint = after.get("fingerprint") or {}
        passed = bool(after.get("found") and
                      post_expect_title in (fingerprint.get("title") or ""))
    result = {"requested": postcondition, "passed": passed}
    if postcondition == "title-contains":
        result["expected_title"] = post_expect_title
    return result


def window_input(display, window_id, expect_title, action, x=None, y=None, button=1,
                 to_x=None, to_y=None, dry_run=False, settle_ms=50,
                 hold_ms=0, drag_duration_ms=0, drag_steps=1,
                 postcondition="none", post_expect_title=None, text=None, key=None):
    """Discover, refresh, bounds-check, then send one explicit pointer action."""
    windows = discover_windows(display)
    info = _read_window_info(window_id)
    prepared = preflight_window_input(
        windows, window_id, expect_title, action, x, y, button, to_x, to_y, info, text, key,
    )
    timing = _validate_window_input_timing(
        settle_ms, hold_ms, drag_duration_ms, drag_steps,
    )
    if postcondition not in WINDOW_INPUT_POSTCONDITIONS:
        raise ValueError("unsupported postcondition: %s" % postcondition)
    if postcondition == "title-contains" and not post_expect_title:
        raise ValueError("title-contains requires --post-expect-title")
    state_before = _prepared_window_input_state(prepared)
    if dry_run and action not in ("text", "key"):
        result = dict(prepared)
        result.update({
            "sent": False,
            "dry_run": True,
            "timing": timing,
            "planned_events": build_window_input_events(prepared),
            "state_before": state_before,
            "state_after": None,
            "postcondition": {"requested": postcondition, "passed": None},
        })
        return result

    def refresh_preflight():
        current_windows = discover_windows(display)
        current_info = _read_window_info(window_id)
        return preflight_window_input(
            current_windows, window_id, expect_title, action, x, y, button,
            to_x, to_y, current_info, text, key,
        )

    if action in ("text", "key"):
        result = send_keyboard_input(display, prepared, timing, refresh_preflight, dry_run)
        if dry_run:
            result["state_before"] = state_before
            return result
    else:
        result = send_window_input(
            display, prepared, timing=timing, refresh_preflight=refresh_preflight,
        )
    state_after = _capture_window_input_state(display, window_id)
    result["state_before"] = state_before
    result["state_after"] = state_after
    if "error" not in result:
        post = _evaluate_window_input_postcondition(
            postcondition, state_before, state_after, post_expect_title,
        )
        result["postcondition"] = post
        if not post["passed"]:
            result["verified"] = False
            result["error"] = "window-input postcondition failed"
        else:
            result["verified"] = True
    return result


def _root_frames():
    try:
        tree = subprocess.check_output(
            ["xwininfo", "-root", "-children"],
            stderr=subprocess.PIPE
        ).decode("utf-8", "replace")
    except (subprocess.CalledProcessError, OSError) as e:
        print(json.dumps({"error": "xwininfo failed: %s" % str(e)}))
        return []
    frames = []
    in_children = False
    for line in tree.splitlines():
        if re.search(r"\b(?:child|children)\b\s*:", line.lower()):
            in_children = True
            continue
        if not in_children:
            continue
        frame = _parse_window_line(line)
        if not frame:
            continue
        frame = _repair_locale_damaged_metadata(frame)
        info = _read_window_info(frame["id"])
        frame["geometry"] = info.get("geometry") or frame.get("geometry") or {}
        frame["mapped"] = info.get("mapped", False)
        frames.append(frame)
    return frames


def _frame_children(frame_id, recursive=True):
    try:
        option = "-tree" if recursive else "-children"
        subtree = subprocess.check_output(
            ["xwininfo", "-id", frame_id, option],
            stderr=subprocess.PIPE
        ).decode("utf-8", "replace")
    except (subprocess.CalledProcessError, OSError):
        return []
    children = []
    for line in subtree.splitlines():
        child = _parse_window_line(line)
        if child:
            children.append(_repair_locale_damaged_metadata(child))
    return children


def _geometry_is_dialog_sized(geometry):
    geo_w = int(geometry.get("w") or 0)
    geo_h = int(geometry.get("h") or 0)
    if geo_w < 20 or geo_h < 20:
        return False
    if geo_h > 420:
        return False
    if geo_w > 1000 and geo_h > 300:
        return False
    return True


def _known_action(title):
    title_l = (title or "").lower()
    for needle, action in KNOWN_MODAL_ACTIONS.items():
        if needle in title_l:
            return action
    if ("save as" in title_l) or ("save a copy" in title_l):
        return "escape"
    return None


def _representative_app_window(frame, app_children):
    """Choose one actionable application window for a top-level WM frame."""
    meaningful = []
    for child in app_children:
        title = (child.get("title") or "").strip()
        if title and title.lower() not in ("virtuoso", "libmanager"):
            meaningful.append(child)

    for child in meaningful:
        if _known_action(child.get("title") or ""):
            return child
    if meaningful:
        return meaningful[0]
    if _is_virtuoso_class(frame.get("class")):
        return frame
    if app_children:
        return app_children[0]
    return None


def _looks_like_ciw(title):
    title_l = (title or "").lower()
    return (
        "command interpreter" in title_l
        or bool(re.search(r"\bciw\b", title_l))
        or (title_l.startswith("virtuoso") and " - log:" in title_l)
    )


def classify_windows(windows):
    classified = []
    for win in windows:
        item = dict(win)
        action = _known_action(item.get("title") or "")
        if _looks_like_ciw(item.get("title") or ""):
            item["kind"] = "ciw"
            item["suggested_action"] = None
        elif action:
            item["kind"] = "known_modal"
            item["suggested_action"] = action
        elif _geometry_is_dialog_sized(item.get("geometry") or {}):
            item["kind"] = "dialog_candidate"
            item["suggested_action"] = "enter"
        else:
            item["kind"] = "main_window"
            item["suggested_action"] = None
        classified.append(item)
    return classified


def _decode_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _bounded_check_output(command, env=None, timeout=_INSPECTION_TIMEOUT_SECONDS):
    """Run one inspection probe with a Python 2 compatible wall-clock bound."""
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise _InspectionFailure("cannot run %s: %s" % (command[0], str(exc)))

    timed_out = [False]

    def terminate_on_timeout():
        if process.poll() is None:
            timed_out[0] = True
            try:
                process.kill()
            except OSError:
                pass

    timer = threading.Timer(timeout, terminate_on_timeout)
    timer.daemon = True
    timer.start()
    try:
        stdout, stderr = process.communicate()
    finally:
        timer.cancel()

    if timed_out[0]:
        raise _InspectionFailure("%s timed out" % command[0])
    if process.returncode:
        detail = (_decode_text(stderr) or "").strip()
        if detail:
            raise _InspectionFailure("%s failed: %s" % (command[0], detail))
        raise _InspectionFailure("%s failed with exit code %s" % (command[0], process.returncode))
    return _decode_text(stdout)


def _read_process_x11_env(pid):
    """Read one explicitly selected process; never enumerate other processes."""
    proc_root = "/proc/%d" % pid
    try:
        stat_data = _decode_text(open(proc_root + "/stat", "rb").read())
        cmdline_data = open(proc_root + "/cmdline", "rb").read()
        environ_data = open(proc_root + "/environ", "rb").read()
    except (IOError, OSError) as exc:
        raise _InspectionFailure(
            "process %d is unavailable or stale: %s" % (pid, str(exc))
        )

    stat_tail = stat_data.rsplit(")", 1)
    if len(stat_tail) != 2 or not stat_tail[1].strip():
        raise _InspectionFailure("process %d metadata is unavailable" % pid)
    if stat_tail[1].strip().split(None, 1)[0] == "Z":
        raise _InspectionFailure("process %d is a zombie" % pid)

    argv = [part for part in cmdline_data.split(b"\x00") if part]
    if not argv:
        raise _InspectionFailure("process %d command line is unavailable" % pid)
    executable = os.path.basename(_decode_text(argv[0])).lower()
    decoded_argv = [_decode_text(part) for part in argv]
    if executable != "virtuoso" or "-nograph" in decoded_argv:
        raise _InspectionFailure(
            "process %d is not a live interactive Virtuoso process" % pid
        )

    process_env = {"DISPLAY": None, "XAUTHORITY": None, "HOSTNAME": None}
    for chunk in environ_data.split(b"\x00"):
        if b"=" not in chunk:
            continue
        key, value = chunk.split(b"=", 1)
        key = _decode_text(key)
        if key in process_env:
            process_env[key] = _decode_text(value)
    if not process_env["DISPLAY"]:
        raise _InspectionFailure("process %d has no DISPLAY in its environment" % pid)
    return process_env


def _normalize_xid(value):
    if isinstance(value, integer_types):
        number = int(value)
    elif isinstance(value, string_types):
        text = value.strip().lower()
        if not re.match(r"^(?:0x[0-9a-f]+|[0-9]+)$", text):
            raise ValueError("invalid X11 window id: %s" % value)
        number = int(text, 16 if text.startswith("0x") else 10)
    else:
        raise ValueError("invalid X11 window id: %s" % value)
    if number <= 0:
        raise ValueError("invalid X11 window id: %s" % value)
    return "0x%x" % number


def _parse_xprop_inspection(output):
    metadata = {
        "pid": None,
        "transient_for": None,
        "client_leader": None,
        "client_machine": None,
        "modal": False,
        "title": "",
        "class": [],
    }
    titles = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        values = re.findall(r'"((?:\\.|[^"\\])*)"', line)
        if line.startswith("_NET_WM_PID("):
            match = re.search(r"=\s*([0-9]+)\s*$", line)
            if match and int(match.group(1)) > 0:
                metadata["pid"] = int(match.group(1))
        elif line.startswith("WM_TRANSIENT_FOR("):
            match = re.search(r"(?:#\s*)?(0x[0-9a-fA-F]+|[0-9]+)\s*$", line)
            if match and int(match.group(1), 0) > 0:
                metadata["transient_for"] = _normalize_xid(match.group(1))
        elif line.startswith("WM_CLIENT_LEADER("):
            match = re.search(r"(?:#\s*)?(0x[0-9a-fA-F]+|[0-9]+)\s*$", line)
            if match and int(match.group(1), 0) > 0:
                metadata["client_leader"] = _normalize_xid(match.group(1))
        elif line.startswith("WM_CLIENT_MACHINE(") and values:
            metadata["client_machine"] = values[0]
        elif line.startswith("_NET_WM_STATE("):
            metadata["modal"] = "_NET_WM_STATE_MODAL" in line
        elif line.startswith("WM_NAME(") and values:
            titles["wm"] = values[0]
        elif line.startswith("_NET_WM_NAME(") and values:
            titles["net"] = values[0]
        elif line.startswith("WM_CLASS(") and values:
            metadata["class"] = values
    metadata["title"] = titles.get("wm") or titles.get("net") or ""
    return metadata


def _parse_window_info_text(output):
    geometry = {}
    mapped = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        try:
            if line.startswith("Absolute upper-left X:"):
                geometry["x"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Absolute upper-left Y:"):
                geometry["y"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Width:"):
                geometry["w"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Height:"):
                geometry["h"] = int(line.split(":", 1)[1].strip())
            elif "Map State:" in line and "IsViewable" in line:
                mapped = True
        except (ValueError, IndexError):
            pass
    return {"geometry": geometry, "mapped": mapped}


def _inspection_subprocess_env(process_env):
    env = os.environ.copy()
    env["DISPLAY"] = process_env["DISPLAY"]
    xauthority = process_env.get("XAUTHORITY")
    if xauthority:
        env["XAUTHORITY"] = xauthority
    else:
        env.pop("XAUTHORITY", None)
    return env


class _XWindowAttributes(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int),
        ("y", ctypes.c_int),
        ("width", ctypes.c_int),
        ("height", ctypes.c_int),
        ("border_width", ctypes.c_int),
        ("depth", ctypes.c_int),
        ("visual", ctypes.c_void_p),
        ("root", ctypes.c_ulong),
        ("window_class", ctypes.c_int),
        ("bit_gravity", ctypes.c_int),
        ("win_gravity", ctypes.c_int),
        ("backing_store", ctypes.c_int),
        ("backing_planes", ctypes.c_ulong),
        ("backing_pixel", ctypes.c_ulong),
        ("save_under", ctypes.c_int),
        ("colormap", ctypes.c_ulong),
        ("map_installed", ctypes.c_int),
        ("map_state", ctypes.c_int),
        ("all_event_masks", ctypes.c_long),
        ("your_event_mask", ctypes.c_long),
        ("do_not_propagate_mask", ctypes.c_long),
        ("override_redirect", ctypes.c_int),
        ("screen", ctypes.c_void_p),
    ]


_X_ERROR_HANDLER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)


class _X11InventoryConnection(object):
    """Small read-only Xlib surface used by bounded dialog inspection."""

    def __init__(self, display, process_env):
        xlib_path = ctypes.util.find_library("X11")
        if not xlib_path:
            raise _InspectionFailure("libX11 not found")
        self._xlib = ctypes.cdll.LoadLibrary(xlib_path)
        self._display = None
        self._closed = False
        self._x_error = False
        self._previous_error_handler = None
        self._error_handler_installed = False
        self._error_callback = _X_ERROR_HANDLER(self._handle_x_error)
        self._declare_signatures()

        previous = {}
        missing = object()
        for key in ("DISPLAY", "XAUTHORITY"):
            previous[key] = os.environ.get(key, missing)
        try:
            os.environ["DISPLAY"] = display
            xauthority = process_env.get("XAUTHORITY")
            if xauthority:
                os.environ["XAUTHORITY"] = xauthority
            else:
                os.environ.pop("XAUTHORITY", None)
            display_name = display.encode("utf-8") if display else None
            self._display = self._xlib.XOpenDisplay(display_name)
        finally:
            for key, value in previous.items():
                if value is missing:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        if not self._display:
            raise _InspectionFailure("cannot open display %s" % display)
        self._previous_error_handler = self._xlib.XSetErrorHandler(
            ctypes.cast(self._error_callback, ctypes.c_void_p)
        )
        self._error_handler_installed = True
        self._root = int(self._xlib.XDefaultRootWindow(self._display))

    def _declare_signatures(self):
        window_pointer = ctypes.POINTER(ctypes.c_ulong)
        self._xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self._xlib.XOpenDisplay.restype = ctypes.c_void_p
        self._xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self._xlib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        self._xlib.XDefaultRootWindow.restype = ctypes.c_ulong
        self._xlib.XQueryTree.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(window_pointer),
            ctypes.POINTER(ctypes.c_uint),
        ]
        self._xlib.XQueryTree.restype = ctypes.c_int
        self._xlib.XGetWindowAttributes.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(_XWindowAttributes),
        ]
        self._xlib.XGetWindowAttributes.restype = ctypes.c_int
        self._xlib.XTranslateCoordinates.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self._xlib.XTranslateCoordinates.restype = ctypes.c_int
        self._xlib.XSetErrorHandler.argtypes = [ctypes.c_void_p]
        self._xlib.XSetErrorHandler.restype = ctypes.c_void_p
        self._xlib.XFree.argtypes = [ctypes.c_void_p]
        self._xlib.XFree.restype = ctypes.c_int

    def _handle_x_error(self, _display, _event):
        self._x_error = True
        return 0

    def _begin_request(self):
        self._x_error = False

    def _request_failed(self, status):
        return not status or self._x_error

    def root(self):
        return self._root

    def children(self, window_id):
        root_return = ctypes.c_ulong()
        parent_return = ctypes.c_ulong()
        children_return = ctypes.POINTER(ctypes.c_ulong)()
        count_return = ctypes.c_uint()
        self._begin_request()
        status = self._xlib.XQueryTree(
            self._display,
            int(window_id),
            ctypes.byref(root_return),
            ctypes.byref(parent_return),
            ctypes.byref(children_return),
            ctypes.byref(count_return),
        )
        if self._request_failed(status):
            if children_return:
                self._xlib.XFree(ctypes.cast(children_return, ctypes.c_void_p))
            raise _InspectionFailure(
                "cannot query X11 window tree for %s" % _normalize_xid(window_id)
            )
        try:
            return [int(children_return[index]) for index in range(count_return.value)]
        finally:
            if children_return:
                self._xlib.XFree(ctypes.cast(children_return, ctypes.c_void_p))

    def attributes(self, window_id):
        attributes = _XWindowAttributes()
        self._begin_request()
        status = self._xlib.XGetWindowAttributes(
            self._display, int(window_id), ctypes.byref(attributes)
        )
        if self._request_failed(status):
            raise _InspectionFailure(
                "cannot read X11 window attributes for %s"
                % _normalize_xid(window_id)
            )
        absolute_x = ctypes.c_int(attributes.x)
        absolute_y = ctypes.c_int(attributes.y)
        if attributes.map_state == 2:  # IsViewable
            child_return = ctypes.c_ulong()
            self._begin_request()
            translated = self._xlib.XTranslateCoordinates(
                self._display,
                int(window_id),
                self._root,
                0,
                0,
                ctypes.byref(absolute_x),
                ctypes.byref(absolute_y),
                ctypes.byref(child_return),
            )
            if self._request_failed(translated):
                raise _InspectionFailure(
                    "cannot translate X11 window coordinates for %s"
                    % _normalize_xid(window_id)
                )
        return {
            "mapped": attributes.map_state == 2,  # IsViewable
            "window_class": int(attributes.window_class),
            "depth": int(attributes.depth),
            "override_redirect": bool(attributes.override_redirect),
            "geometry": {
                "x": int(absolute_x.value),
                "y": int(absolute_y.value),
                "w": int(attributes.width),
                "h": int(attributes.height),
            },
        }

    def close(self):
        if not self._closed and self._display:
            self._xlib.XCloseDisplay(self._display)
        if not self._closed and self._error_handler_installed:
            self._xlib.XSetErrorHandler(self._previous_error_handler)
        self._closed = True
        self._display = None


def _open_x11_inventory(display, process_env):
    return _X11InventoryConnection(display, process_env)


def _inspect_window_inventory(
    display, process_env, timeout=_INSPECTION_TOTAL_TIMEOUT_SECONDS
):
    """Collect bounded read-only metadata for relevant mapped X11 shells.

    Xlib filters the root tree in one process, so hundreds of unmapped menu
    windows do not each spawn xwininfo/xprop. Traversal stops at an application
    shell and does not inventory its widget subtree. Non-WM shells hidden below
    more than ``_MAX_FRAME_SEARCH_DEPTH`` anonymous containers are unsupported
    and fail closed instead of producing a clear result. InputOnly nodes cannot
    render dialogs and are omitted; invisible keyboard/pointer grabs are outside
    this visual dialog-shell inspection contract.
    """
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        raise _InspectionFailure("inspection timeout must be positive and finite")
    if isinstance(timeout, bool) or budget <= 0 or budget != budget or budget == float("inf"):
        raise _InspectionFailure("inspection timeout must be positive and finite")
    clock = getattr(time, "monotonic", time.time)
    deadline = clock() + budget

    def check_budget():
        remaining = deadline - clock()
        if remaining <= 0:
            raise _InspectionBudgetExceeded("X11 inspection budget exhausted")
        return remaining

    def probe(command, env):
        remaining = check_budget()
        try:
            return _bounded_check_output(
                command,
                env=env,
                timeout=min(_INSPECTION_TIMEOUT_SECONDS, remaining),
            )
        except _InspectionFailure:
            if deadline - clock() <= 0:
                raise _InspectionBudgetExceeded("X11 inspection budget exhausted")
            raise

    def connection_call(callback, *args):
        native_queries[0] += 1
        if native_queries[0] > _MAX_X11_NATIVE_QUERIES:
            raise _InspectionFailure("too many native X11 queries to inspect safely")
        check_budget()
        value = callback(*args)
        check_budget()
        return value

    properties = [
        "_NET_WM_PID",
        "WM_TRANSIENT_FOR",
        "WM_CLIENT_LEADER",
        "WM_CLIENT_MACHINE",
        "_NET_WM_STATE",
        "_NET_WM_NAME",
        "WM_NAME",
        "WM_CLASS",
        "WM_STATE",
        "_NET_WM_WINDOW_TYPE",
    ]
    env = _inspection_subprocess_env(process_env)
    records = {}
    order = []
    native_queries = [0]
    root_geometry = {}

    def add_record(connection, window_number, frame_number, attributes, metadata_only=False):
        window_id = _normalize_xid(window_number)
        if window_id in records:
            return records[window_id]
        if len(order) >= _MAX_INSPECTION_WINDOWS:
            raise _InspectionFailure("too many relevant X11 windows to inspect safely")
        record = {
            "id": window_id,
            "frame_id": _normalize_xid(frame_number),
            "title": "",
            "class": [],
            "geometry": (attributes or {}).get("geometry") or {},
            "mapped": bool((attributes or {}).get("mapped")),
            "pid": None,
            "transient_for": None,
            "client_leader": None,
            "client_machine": None,
            "modal": False,
        }
        if metadata_only:
            record["metadata_only"] = True
        records[window_id] = record
        order.append(window_id)
        try:
            prop_output = probe(["xprop", "-id", window_id] + properties, env)
            metadata = _parse_xprop_inspection(prop_output)
            for key in (
                "pid", "transient_for", "client_leader", "client_machine", "modal"
            ):
                record[key] = metadata[key]
            record["title"] = metadata.get("title") or ""
            record["class"] = metadata.get("class") or []
            record["client_shell"] = bool(
                re.search(r"(?m)^WM_STATE\(", prop_output)
                or record["pid"] is not None
                or record["transient_for"]
                or record["client_leader"]
                or record["client_machine"]
                or record["modal"]
                or record["class"]
            )
            geometry = record["geometry"]
            root_w = root_geometry.get("w", 0)
            root_h = root_geometry.get("h", 0)
            # A property-free off-screen sentinel is not a visible dialog;
            # this does not assign it a foreign owner or rule out input grabs.
            record["nonvisual_sentinel"] = bool(
                window_number == frame_number
                and not metadata_only
                and not record["client_shell"]
                and not re.search(r"(?m)^\w+\(", prop_output)
                and (attributes or {}).get("override_redirect")
                and geometry.get("w") == 1 and geometry.get("h") == 1
                and root_w > 0 and root_h > 0
                and (geometry.get("x", 0) + 1 <= 0
                     or geometry.get("y", 0) + 1 <= 0
                     or geometry.get("x", 0) >= root_w
                     or geometry.get("y", 0) >= root_h)
            )
        except _InspectionBudgetExceeded:
            raise
        except _InspectionFailure as exc:
            record["metadata_error"] = str(exc)
            record["client_shell"] = False
        return record

    check_budget()
    connection = _open_x11_inventory(display, process_env)
    try:
        check_budget()
        root = connection.root()
        root_attributes = connection_call(connection.attributes, root)
        root_geometry = (root_attributes or {}).get("geometry") or {}
        root_children = connection_call(connection.children, root)
        if len(root_children) > _MAX_ROOT_WINDOW_CHILDREN:
            raise _InspectionFailure("too many root X11 windows to filter safely")

        queue = []
        for window_number in root_children:
            attributes = connection_call(connection.attributes, window_number)
            # InputOnly windows cannot render a dialog. They remain available
            # for on-demand ownership metadata if a client shell references one.
            if (
                attributes is not None
                and attributes.get("mapped")
                and attributes.get("window_class") != 2
            ):
                queue.append((window_number, window_number, 0, attributes))

        visited = set()
        while queue:
            window_number, frame_number, depth, attributes = queue.pop(0)
            window_id = _normalize_xid(window_number)
            if window_id in visited:
                continue
            visited.add(window_id)
            record = add_record(
                connection, window_number, frame_number, attributes
            )
            if record.get("nonvisual_sentinel"):
                continue
            if record.get("client_shell") and (
                depth > 0 or not record.get("metadata_error")
                and record.get("pid") is not None
            ):
                continue
            if depth >= _MAX_FRAME_SEARCH_DEPTH:
                raise _InspectionFailure(
                    "mapped X11 frame %s exceeds supported shell nesting depth"
                    % _normalize_xid(frame_number)
                )
            child_numbers = connection_call(connection.children, window_number)
            for child_number in child_numbers:
                child_attributes = connection_call(
                    connection.attributes, child_number
                )
                if (child_attributes is not None and child_attributes.get("mapped")
                        and child_attributes.get("window_class") != 2):
                    queue.append(
                        (child_number, frame_number, depth + 1, child_attributes)
                    )

        shell_frames = set(
            record["frame_id"] for record in records.values()
            if record.get("client_shell") and record["id"] != record["frame_id"]
        )
        for record in records.values():
            if record["frame_id"] in shell_frames and not record.get("client_shell"):
                record["container"] = True
            elif record.get("mapped") and not record.get("client_shell"):
                record["inspection_unknown"] = True
                if not record.get("metadata_error"):
                    record["metadata_error"] = (
                        "mapped X11 branch has no inspectable client-shell metadata"
                    )

        pending = []
        for record in records.values():
            for field in ("transient_for", "client_leader"):
                if record.get(field):
                    pending.append(record[field])
        while pending:
            related_id = _normalize_xid(pending.pop(0))
            if related_id in records:
                continue
            related_number = int(related_id, 16)
            attributes = connection_call(connection.attributes, related_number)
            related = add_record(
                connection,
                related_number,
                related_number,
                attributes,
                metadata_only=True,
            )
            for field in ("transient_for", "client_leader"):
                if related.get(field) and related[field] not in records:
                    pending.append(related[field])
    finally:
        connection.close()

    return [records[window_id] for window_id in order]


def _local_hostnames(process_env):
    names = set()
    try:
        runtime_hostname = socket.gethostname()
    except (IOError, OSError):
        runtime_hostname = None
    for value in (process_env.get("HOSTNAME"), runtime_hostname):
        if value:
            names.add(value.strip().lower().rstrip("."))
    return names


def _client_machine_status(client_machine, local_hostnames):
    if not client_machine:
        return "absent"
    candidate = client_machine.strip().lower().rstrip(".")
    if not candidate or not local_hostnames:
        return "unknown"
    if candidate in local_hostnames:
        return "local"
    candidate_short = candidate.split(".", 1)[0]
    local_shorts = set(name.split(".", 1)[0] for name in local_hostnames)
    if candidate_short not in local_shorts:
        return "foreign"
    return "unknown"


def _resolve_window_owner(window_id, records, selected_pid, local_hostnames):
    """Resolve an exact PID through bounded X11 ownership relations."""
    def resolve(current_id, trail, depth):
        if depth > _MAX_OWNERSHIP_DEPTH:
            return None, "ownership relation exceeded depth bound"
        if current_id in trail:
            return None, "ownership relation cycle at %s" % current_id
        record = records.get(current_id)
        if record is None:
            return None, "ownership relation references missing window %s" % current_id

        direct_pid = record.get("pid")
        machine = record.get("client_machine")
        machine_status = _client_machine_status(machine, local_hostnames)
        if machine_status == "foreign" and (direct_pid is None or int(direct_pid) == selected_pid):
            return "foreign-client:%s" % machine, None
        if machine_status == "unknown" and (direct_pid is None or int(direct_pid) == selected_pid):
            return None, "cannot match WM_CLIENT_MACHINE %s to the selected process host" % machine
        relation_results = []
        next_trail = trail + (current_id,)
        for field in ("transient_for", "client_leader"):
            related_id = record.get(field)
            if related_id:
                owner, reason = resolve(related_id, next_trail, depth + 1)
                relation_results.append((owner, reason))

        known = set(owner for owner, _reason in relation_results if owner is not None)
        if direct_pid is not None:
            known.add(int(direct_pid))
            if len(known) > 1:
                return None, "contradictory ownership metadata for %s" % current_id
            return int(direct_pid), None
        if len(known) > 1:
            return None, "contradictory ownership metadata for %s" % current_id
        unresolved = [reason for owner, reason in relation_results if owner is None]
        if unresolved:
            return None, unresolved[0]
        if known:
            return list(known)[0], None
        if record.get("metadata_error"):
            return None, record["metadata_error"]
        return None, "window %s has no PID or ownership relation" % current_id

    return resolve(window_id, (), 0)


def _inspection_classification(record):
    window = {
        "frame_id": record.get("frame_id") or record["id"],
        "window_id": record["id"],
        "dismiss_id": record["id"],
        "title": record.get("title") or "",
        "class": record.get("class") or [],
        "geometry": record.get("geometry") or {},
        "mapped": bool(record.get("mapped")),
    }
    classified = classify_windows([window])[0]
    if record.get("modal") and classified.get("kind") not in ("ciw", "known_modal"):
        classified["kind"] = "dialog_candidate"
        classified["suggested_action"] = "enter"
    classified["modal"] = bool(record.get("modal"))
    classified["suggested_action"] = None
    return classified


def _is_inspection_dialog(record, classified):
    if (
        not record.get("mapped")
        or record.get("metadata_only")
        or record.get("container")
        or record.get("nonvisual_sentinel")
        or classified.get("kind") == "ciw"
    ):
        return False
    if record.get("inspection_unknown"):
        return True
    if record.get("modal"):
        return True
    if not _is_virtuoso_class(record.get("class")):
        return False
    return bool(record.get("metadata_error")) or classified.get("kind") in ("known_modal", "dialog_candidate")


def _inspection_result(pid, display, ciw_window, status="indeterminate", diagnostics=None):
    return {
        "status": status,
        "target": {
            "pid": int(pid),
            "display": display,
            "ciw_window": ciw_window,
        },
        "dialogs": [],
        "diagnostics": list(diagnostics or []),
    }


def inspect_dialogs(
    pid, display=None, ciw_window=None,
    timeout=_INSPECTION_TOTAL_TIMEOUT_SECONDS,
):
    """Inspect dialogs for one exact Virtuoso PID without injecting input."""
    if isinstance(pid, bool):
        return _inspection_result(0, display, ciw_window, diagnostics=["pid must be a positive integer"])
    if isinstance(pid, integer_types):
        selected_pid = int(pid)
    elif isinstance(pid, string_types) and re.match(r"^[0-9]+$", pid.strip()):
        selected_pid = int(pid.strip())
    else:
        return _inspection_result(0, display, ciw_window, diagnostics=["pid must be a positive integer"])
    if selected_pid <= 0:
        return _inspection_result(selected_pid, display, ciw_window, diagnostics=["pid must be a positive integer"])
    try:
        inspection_timeout = float(timeout)
    except (TypeError, ValueError):
        return _inspection_result(selected_pid, display, ciw_window, diagnostics=["inspection timeout must be positive and finite"])
    if (
        isinstance(timeout, bool)
        or inspection_timeout <= 0
        or inspection_timeout != inspection_timeout
        or inspection_timeout == float("inf")
    ):
        return _inspection_result(selected_pid, display, ciw_window, diagnostics=["inspection timeout must be positive and finite"])

    result = _inspection_result(selected_pid, display, ciw_window)
    try:
        process_env = _read_process_x11_env(selected_pid)
    except _InspectionFailure as exc:
        result["diagnostics"].append(str(exc))
        return result

    process_display = process_env.get("DISPLAY")
    result["target"]["display"] = process_display
    if not process_display:
        result["diagnostics"].append(
            "process %d has no DISPLAY in its environment" % selected_pid
        )
        return result
    if display is not None and display != process_display:
        result["diagnostics"].append(
            "supplied DISPLAY %s disagrees with process DISPLAY %s"
            % (display, process_display)
        )
        return result

    try:
        inventory = _inspect_window_inventory(
            process_display, process_env, timeout=inspection_timeout
        )
    except _InspectionFailure as exc:
        result["diagnostics"].append(str(exc))
        return result
    except Exception as exc:
        result["diagnostics"].append("X11 inspection failed: %s" % str(exc))
        return result

    records = {}
    for raw_record in inventory:
        record = dict(raw_record)
        try:
            record["id"] = _normalize_xid(record["id"])
            if record.get("frame_id"):
                record["frame_id"] = _normalize_xid(record["frame_id"])
            for field in ("transient_for", "client_leader"):
                if record.get(field):
                    record[field] = _normalize_xid(record[field])
        except (KeyError, ValueError) as exc:
            result["diagnostics"].append("invalid X11 inventory metadata: %s" % str(exc))
            return result
        records[record["id"]] = record

    local_hostnames = _local_hostnames(process_env)

    ciw_candidates = []
    unknown_ciws = []
    for record in records.values():
        if not record.get("mapped"):
            continue
        if not _looks_like_ciw(record.get("title") or ""):
            continue
        if not _is_virtuoso_class(record.get("class")):
            continue
        owner, reason = _resolve_window_owner(
            record["id"], records, selected_pid, local_hostnames
        )
        if owner == selected_pid:
            ciw_candidates.append(record)
        elif owner is None:
            unknown_ciws.append((record, reason))

    selected_ciw = None
    if ciw_window is not None:
        try:
            requested_ciw = _normalize_xid(ciw_window)
        except ValueError as exc:
            result["diagnostics"].append(str(exc))
            return result
        record = records.get(requested_ciw)
        if record is None or not record.get("mapped") or not _looks_like_ciw(record.get("title") or ""):
            result["diagnostics"].append(
                "selected ciw_window is not a mapped CIW"
            )
            return result
        if not _is_virtuoso_class(record.get("class")):
            result["diagnostics"].append(
                "selected ciw_window is not a Virtuoso CIW"
            )
            return result
        owner, reason = _resolve_window_owner(
            requested_ciw, records, selected_pid, local_hostnames
        )
        if owner != selected_pid:
            if owner is None:
                result["diagnostics"].append(
                    "cannot establish selected CIW ownership: %s" % reason
                )
            elif isinstance(owner, integer_types):
                result["diagnostics"].append(
                    "selected CIW belongs to PID %d, not PID %d"
                    % (owner, selected_pid)
                )
            else:
                result["diagnostics"].append(
                    "selected CIW belongs to %s, not selected PID %d"
                    % (owner, selected_pid)
                )
            return result
        selected_ciw = record
    else:
        if len(ciw_candidates) > 1:
            result["diagnostics"].append(
                "more than one CIW belongs to PID %d" % selected_pid
            )
            return result
        if not ciw_candidates:
            if unknown_ciws:
                result["diagnostics"].append(
                    "cannot establish CIW ownership: %s" % unknown_ciws[0][1]
                )
            else:
                result["diagnostics"].append(
                    "no mapped CIW belongs to PID %d" % selected_pid
                )
            return result
        selected_ciw = ciw_candidates[0]
        result["target"]["ciw_window"] = selected_ciw["id"]

    indeterminate = False
    dialogs = []
    for record in records.values():
        classified = _inspection_classification(record)
        if not _is_inspection_dialog(record, classified):
            continue
        owner, reason = _resolve_window_owner(
            record["id"], records, selected_pid, local_hostnames
        )
        if owner is not None and owner != selected_pid:
            continue
        classified["source"] = "unknown"
        classified["ownership"] = "target" if owner == selected_pid else "unknown"
        dialogs.append(classified)
        if owner is None:
            indeterminate = True
            result["diagnostics"].append(
                "cannot establish ownership for dialog %s: %s"
                % (record["id"], reason)
            )

    def xid_sort_key(window):
        try:
            return int(window.get("window_id") or "0", 16)
        except (TypeError, ValueError):
            return 0

    result["dialogs"] = sorted(dialogs, key=xid_sort_key)
    if indeterminate:
        result["status"] = "indeterminate"
    elif dialogs:
        result["status"] = "blocked"
    else:
        result["status"] = "clear"
    return result


def discover_windows(display, top_level=False):
    """Enumerate Virtuoso windows, optionally returning one item per WM frame."""
    os.environ["DISPLAY"] = display
    windows = []
    seen = set()
    for frame in _root_frames():
        if not frame.get("mapped", False):
            continue
        frame_id = frame["id"]
        geometry = frame.get("geometry") or {}
        children = _frame_children(frame_id, recursive=not top_level)
        app_children = [c for c in children if _is_virtuoso_class(c.get("class"))]
        if _is_virtuoso_class(frame.get("class")):
            app_children.append(frame)
        if top_level and app_children:
            ciw = [c for c in app_children if _looks_like_ciw(c.get("title") or frame.get("title") or "")]
            titled = [c for c in app_children if c.get("title")]
            app_children = [(ciw or titled or app_children)[0]]
        if not top_level:
            representative = _representative_app_window(frame, app_children)
            app_children = [representative] if representative else []
        for child in app_children:
            dismiss_id = child["id"]
            key = frame_id if top_level else (frame_id, dismiss_id)
            if key in seen:
                continue
            seen.add(key)
            windows.append({
                "frame_id": frame_id,
                "window_id": dismiss_id,
                "dismiss_id": dismiss_id,
                "title": child.get("title") or frame.get("title") or "",
                "class": child.get("class") or frame.get("class") or [],
                "geometry": {
                    "w": int(geometry.get("w") or 0),
                    "h": int(geometry.get("h") or 0),
                    "x": int(geometry.get("x") or 0),
                    "y": int(geometry.get("y") or 0),
                },
                "mapped": True,
            })
    return classify_windows(windows)


def _auto_dismissable(win):
    return win.get("kind") in ("known_modal", "dialog_candidate")


def find_dialogs(display):
    """Backward-compatible auto-dismiss candidate view of discover_windows()."""
    dialogs = []
    for win in discover_windows(display):
        if not _auto_dismissable(win):
            continue
        geo = win.get("geometry") or {}
        dialogs.append({
            "window_id": win.get("dismiss_id") or win.get("window_id"),
            "frame_id": win.get("frame_id"),
            "title": win.get("title", ""),
            "x": geo.get("x", 0),
            "y": geo.get("y", 0),
            "w": geo.get("w", 0),
            "h": geo.get("h", 0),
            "kind": win.get("kind"),
            "suggested_action": win.get("suggested_action"),
        })
    return dialogs


def _resolve_dismiss_target(display, requested_id):
    """Accept either a WM frame id or an application's dismissable child id."""
    for window in discover_windows(display):
        if requested_id in (
            window.get("frame_id"),
            window.get("window_id"),
            window.get("dismiss_id"),
        ):
            return window.get("dismiss_id") or requested_id
    return requested_id


def _apply_x11_env(x11_env):
    """Make one discovered X11 environment active for ctypes and xwininfo."""
    display = x11_env.get("DISPLAY")
    os.environ["DISPLAY"] = display
    xauth = x11_env.get("XAUTHORITY")
    if isinstance(xauth, string_types) and xauth:
        os.environ["XAUTHORITY"] = xauth
    else:
        os.environ.pop("XAUTHORITY", None)
    return display


def _unique_window_env(x11_envs, requested_id):
    """Resolve an XID before any input; XIDs are only unique within a display."""
    matches = []
    for x11_env in x11_envs:
        active_display = _apply_x11_env(x11_env)
        if any(requested_id in (w.get("frame_id"), w.get("window_id"), w.get("dismiss_id"))
               for w in discover_windows(active_display)):
            matches.append(x11_env)
    if not matches:
        raise ValueError("window id not found on any Virtuoso display")
    if len(matches) != 1:
        raise ValueError("window id found on more than one display; select an explicit DISPLAY")
    return _apply_x11_env(matches[0])


def _verify_dismissal(result):
    """Report whether the target is still mapped after an injected action."""
    if "dismissed" not in result:
        return result
    time.sleep(0.3)
    target = result.get("child") or result.get("dismissed")
    result["still_mapped"] = bool(_read_window_info(target).get("mapped"))
    return result


def _find_app_child(display, frame_id_str):
    """Find the actual app window inside a WM frame (first named child)."""
    try:
        tree = subprocess.check_output(
            ["xwininfo", "-id", frame_id_str, "-children"],
            stderr=subprocess.PIPE
        ).decode("utf-8", "replace")
        for line in tree.splitlines():
            line = line.strip()
            if line.startswith("0x") and '"' in line:
                return line.split()[0]
    except (subprocess.CalledProcessError, OSError):
        pass
    return frame_id_str  # fallback to frame itself


def _send_alt_n(dpy, xlib, xtst):
    """Send Alt+N to trigger the No button mnemonic."""
    keysym_alt_l = 0xffe9  # XK_Alt_L
    keysym_n = 0x006e      # XK_n
    kc_alt = xlib.XKeysymToKeycode(dpy, keysym_alt_l)
    kc_n = xlib.XKeysymToKeycode(dpy, keysym_n)

    xtst.XTestFakeKeyEvent(dpy, kc_alt, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_n, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_n, False, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_alt, False, 0)
    xlib.XFlush(dpy)
    return kc_alt, kc_n


def _send_alt_y(dpy, xlib, xtst):
    """Send Alt+Y to trigger the Yes button mnemonic."""
    keysym_alt_l = 0xffe9  # XK_Alt_L
    keysym_y = 0x0079      # XK_y
    kc_alt = xlib.XKeysymToKeycode(dpy, keysym_alt_l)
    kc_y = xlib.XKeysymToKeycode(dpy, keysym_y)

    xtst.XTestFakeKeyEvent(dpy, kc_alt, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_y, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_y, False, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_alt, False, 0)
    xlib.XFlush(dpy)
    return kc_alt, kc_y


def _send_alt_o(dpy, xlib, xtst):
    """Send Alt+O to activate the standard OK button mnemonic."""
    keysym_alt_l = 0xffe9  # XK_Alt_L
    keysym_o = 0x006f      # XK_o
    kc_alt = xlib.XKeysymToKeycode(dpy, keysym_alt_l)
    kc_o = xlib.XKeysymToKeycode(dpy, keysym_o)

    xtst.XTestFakeKeyEvent(dpy, kc_alt, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_o, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_o, False, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_alt, False, 0)
    xlib.XFlush(dpy)
    return kc_alt, kc_o


def _send_escape(dpy, xlib, xtst):
    """Send Escape key (maps to Cancel on most dialogs)."""
    keysym_esc = 0xff1b  # XK_Escape
    kc_esc = xlib.XKeysymToKeycode(dpy, keysym_esc)
    xtst.XTestFakeKeyEvent(dpy, kc_esc, True, 0)
    xtst.XTestFakeKeyEvent(dpy, kc_esc, False, 0)
    xlib.XFlush(dpy)
    return kc_esc


def _send_enter(dpy, xlib, xtst):
    """Send Return key."""
    keysym = 0xff0d  # XK_Return
    keycode = xlib.XKeysymToKeycode(dpy, keysym)
    xtst.XTestFakeKeyEvent(dpy, keycode, True, 0)
    xtst.XTestFakeKeyEvent(dpy, keycode, False, 0)
    xlib.XFlush(dpy)
    return keycode


def _send_explicit_action(dpy, xlib, xtst, action):
    normalized = (action or "enter").lower().replace("_", "-")
    if normalized == "enter":
        return "enter", {"keycode": int(_send_enter(dpy, xlib, xtst))}
    if normalized in ("escape", "esc"):
        return "escape", {"keycode_esc": int(_send_escape(dpy, xlib, xtst))}
    if normalized in ("alt-y", "yes"):
        kc_alt, kc_y = _send_alt_y(dpy, xlib, xtst)
        return "alt-y", {"keycode_alt": int(kc_alt), "keycode_y": int(kc_y)}
    if normalized in ("alt-o", "ok"):
        kc_alt, kc_o = _send_alt_o(dpy, xlib, xtst)
        return "alt-o", {"keycode_alt": int(kc_alt), "keycode_o": int(kc_o)}
    if normalized in ("alt-n", "no"):
        kc_alt, kc_n = _send_alt_n(dpy, xlib, xtst)
        return "alt-n", {"keycode_alt": int(kc_alt), "keycode_n": int(kc_n)}
    raise ValueError("unsupported action: %s" % action)


_SHIFTED_ASCII = set('~!@#$%^&*()_+{}|:\"<>?')


def _skill_load_expression(setup_path):
    if not setup_path or not setup_path.startswith("/"):
        raise ValueError("setup path must be absolute")
    if os.path.basename(setup_path) != "virtuoso_setup.il":
        raise ValueError("setup path must name generated virtuoso_setup.il")
    if "\n" in setup_path or "\r" in setup_path or "\x00" in setup_path:
        raise ValueError("setup path contains unsupported control characters")
    escaped = setup_path.replace("\\", "\\\\").replace('"', '\\"')
    return 'load("%s")' % escaped


def _type_ascii_into_window(display, window_id, text):
    """Focus one explicit X11 window, type ASCII with XTest, then Return."""
    try:
        text.encode("ascii")
    except UnicodeError:
        return {"error": "bootstrap path must contain ASCII characters"}
    os.environ["DISPLAY"] = display
    xlib_path = ctypes.util.find_library("X11")
    xtst_path = ctypes.util.find_library("Xtst")
    if not xlib_path or not xtst_path:
        return {"error": "libX11 or libXtst not found"}

    xlib = ctypes.cdll.LoadLibrary(xlib_path)
    xtst = ctypes.cdll.LoadLibrary(xtst_path)
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xlib.XFlush.argtypes = [ctypes.c_void_p]
    xlib.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    xlib.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XKeysymToKeycode.restype = ctypes.c_uint
    xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    xtst.XTestFakeKeyEvent.restype = ctypes.c_int

    dpy = xlib.XOpenDisplay(None)
    if not dpy:
        return {"error": "cannot open display %s" % display}
    target = int(window_id, 16) if window_id.startswith("0x") else int(window_id)
    shift_keycode = xlib.XKeysymToKeycode(dpy, 0xffe1)  # XK_Shift_L
    return_keycode = xlib.XKeysymToKeycode(dpy, 0xff0d)  # XK_Return
    strokes = []
    for char in text:
        keycode = xlib.XKeysymToKeycode(dpy, ord(char))
        if not keycode:
            xlib.XCloseDisplay(dpy)
            return {"error": "cannot map bootstrap character %r" % char}
        strokes.append((keycode, char.isupper() or char in _SHIFTED_ASCII))
    if not shift_keycode or not return_keycode:
        xlib.XCloseDisplay(dpy)
        return {"error": "cannot map required Shift/Return key"}

    xlib.XRaiseWindow(dpy, target)
    xlib.XSetInputFocus(dpy, target, 1, 0)
    xlib.XFlush(dpy)
    time.sleep(0.15)
    try:
        for keycode, shifted in strokes:
            if shifted:
                xtst.XTestFakeKeyEvent(dpy, shift_keycode, True, 0)
            xtst.XTestFakeKeyEvent(dpy, keycode, True, 0)
            xtst.XTestFakeKeyEvent(dpy, keycode, False, 0)
            if shifted:
                xtst.XTestFakeKeyEvent(dpy, shift_keycode, False, 0)
        xtst.XTestFakeKeyEvent(dpy, return_keycode, True, 0)
        xtst.XTestFakeKeyEvent(dpy, return_keycode, False, 0)
        xlib.XFlush(dpy)
    except Exception as exc:
        xlib.XCloseDisplay(dpy)
        return {"error": "XTest bootstrap failed: %s" % str(exc)}
    xlib.XCloseDisplay(dpy)
    return {"bootstrapped": window_id, "command": text}


def bootstrap_ciw(display, requested_id, setup_path):
    """Inject only the generated load expression into one verified CIW."""
    matches = []
    for window in discover_windows(display, top_level=True):
        if requested_id in (
            window.get("frame_id"),
            window.get("window_id"),
            window.get("dismiss_id"),
        ):
            matches.append(window)
    if not matches:
        return {"error": "window id is not a top-level Virtuoso window", "window_id": requested_id}
    window = matches[0]
    if window.get("kind") != "ciw":
        return {
            "error": "refusing bootstrap: selected window is not identified as a CIW",
            "window_id": requested_id,
            "title": window.get("title") or "",
        }
    try:
        expression = _skill_load_expression(setup_path)
    except ValueError as exc:
        return {"error": str(exc), "window_id": requested_id}
    target = window.get("dismiss_id") or window.get("window_id") or requested_id
    result = _type_ascii_into_window(display, target, expression)
    result["requested_window_id"] = requested_id
    result["display"] = display
    result["title"] = window.get("title") or ""
    return result


def dismiss_window(display, win_id_str, title="", x=0, y=0, w=0, h=0, action=None):
    """Dismiss a window via XTest.

    Default behavior is Enter.
    For Save As prompts, prefer 'n' (No) to avoid Save/Copy dialog loops.
    """
    os.environ["DISPLAY"] = display
    xlib_path = ctypes.util.find_library("X11")
    xtst_path = ctypes.util.find_library("Xtst")
    if not xlib_path or not xtst_path:
        return {"error": "libX11 or libXtst not found"}

    xlib = ctypes.cdll.LoadLibrary(xlib_path)
    xtst = ctypes.cdll.LoadLibrary(xtst_path)

    # Declare 64-bit-safe signatures. Without argtypes/restype, ctypes defaults
    # to c_int (32-bit) and truncates Display*/Window pointers on x86_64,
    # segfaulting inside libX11 (e.g. XRaiseWindow with a truncated display).
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xlib.XFlush.argtypes = [ctypes.c_void_p]
    xlib.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    xlib.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XKeysymToKeycode.restype = ctypes.c_uint
    xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    xtst.XTestFakeKeyEvent.restype = ctypes.c_int

    dpy = xlib.XOpenDisplay(None)
    if not dpy:
        return {"error": "cannot open display %s" % display}

    # Legacy auto mode accepts a WM frame and resolves to the app child.
    # Explicit dismiss-window mode focuses the exact caller-provided target.
    child_id_str = win_id_str if action else _find_app_child(display, win_id_str)
    child_id = int(child_id_str, 16) if child_id_str.startswith("0x") else int(child_id_str)

    xlib.XRaiseWindow(dpy, child_id)
    xlib.XSetInputFocus(dpy, child_id, 1, 0)  # RevertToParent
    xlib.XFlush(dpy)

    time.sleep(0.15)

    if action:
        try:
            action_name, extra = _send_explicit_action(dpy, xlib, xtst, action)
        except ValueError as exc:
            xlib.XCloseDisplay(dpy)
            return {"error": str(exc), "dismissed": win_id_str, "child": child_id_str}
        xlib.XCloseDisplay(dpy)
        result = {
            "dismissed": win_id_str,
            "child": child_id_str,
            "action": action_name,
            "title": title,
        }
        result.update(extra)
        return result

    title_l = (title or "").lower()
    # Policy values:
    # - smart   : choose action by explicit context (dedupe -> No, default -> Cancel)
    # - discard : always choose No
    # - save    : always choose Yes
    # - cancel  : always choose Cancel
    save_policy = (os.environ.get("VB_SAVE_DIALOG_POLICY", "smart") or "smart").lower()
    save_context = (os.environ.get("VB_SAVE_DIALOG_CONTEXT", "") or "").lower()
    if ("save as" in title_l) or ("save a copy" in title_l):
        try:
            if save_policy == "discard":
                kc_alt, kc_n = _send_alt_n(dpy, xlib, xtst)
                xlib.XCloseDisplay(dpy)
                return {
                    "dismissed": win_id_str,
                    "child": child_id_str,
                    "action": "alt_n_no",
                    "title": title,
                    "policy": save_policy,
                    "keycode_alt": int(kc_alt),
                    "keycode_n": int(kc_n),
                }
            elif save_policy == "save":
                kc_alt, kc_y = _send_alt_y(dpy, xlib, xtst)
                xlib.XCloseDisplay(dpy)
                return {
                    "dismissed": win_id_str,
                    "child": child_id_str,
                    "action": "alt_y_yes",
                    "title": title,
                    "policy": save_policy,
                    "keycode_alt": int(kc_alt),
                    "keycode_y": int(kc_y),
                }
            elif save_policy == "cancel":
                kc_esc = _send_escape(dpy, xlib, xtst)
                xlib.XCloseDisplay(dpy)
                return {
                    "dismissed": win_id_str,
                    "child": child_id_str,
                    "action": "esc_cancel",
                    "title": title,
                    "policy": save_policy,
                    "keycode_esc": int(kc_esc),
                }
            else:
                if save_context == "dedupe":
                    kc_alt, kc_n = _send_alt_n(dpy, xlib, xtst)
                    xlib.XCloseDisplay(dpy)
                    return {
                        "dismissed": win_id_str,
                        "child": child_id_str,
                        "action": "alt_n_no_dedupe",
                        "title": title,
                        "policy": "smart",
                        "context": save_context,
                        "keycode_alt": int(kc_alt),
                        "keycode_n": int(kc_n),
                    }

                kc_esc = _send_escape(dpy, xlib, xtst)
                xlib.XCloseDisplay(dpy)
                return {
                    "dismissed": win_id_str,
                    "child": child_id_str,
                    "action": "esc_cancel_smart",
                    "title": title,
                    "policy": "smart",
                    "context": save_context,
                    "keycode_esc": int(kc_esc),
                }
        except Exception:
            # Fallback: send bare 'n' key and return immediately.
            keysym_n = 0x006e  # XK_n
            kc_n = xlib.XKeysymToKeycode(dpy, keysym_n)
            xtst.XTestFakeKeyEvent(dpy, kc_n, True, 0)
            xtst.XTestFakeKeyEvent(dpy, kc_n, False, 0)
            xlib.XFlush(dpy)
            xlib.XCloseDisplay(dpy)
            return {
                "dismissed": win_id_str,
                "child": child_id_str,
                "keycode": int(kc_n),
                "action": "no_fallback",
                "title": title,
            }
    else:
        keycode = _send_enter(dpy, xlib, xtst)
        action = "enter"

    xlib.XCloseDisplay(dpy)
    return {
        "dismissed": win_id_str,
        "child": child_id_str,
        "keycode": int(keycode),
        "action": action,
        "title": title,
    }


def main():
    args = sys.argv[1:]
    display = None
    do_dismiss = False
    inspect_only = "--inspect-dialogs" in args
    inspect_pid = None
    inspect_ciw = None
    inspect_timeout = _INSPECTION_TOTAL_TIMEOUT_SECONDS
    list_windows = False
    top_level = False
    dismiss_target = None
    bootstrap_target = None
    setup_path = None
    action = "enter"
    input_target = None
    expect_title = None
    input_x = None
    input_text = None
    input_key = None
    input_y = None
    input_to_x = None
    input_to_y = None
    input_button = 1
    allow_live = False
    dry_run = False
    settle_ms = 50
    hold_ms = 0
    drag_duration_ms = 0
    drag_steps = 1
    postcondition = "none"
    post_expect_title = None

    i = 0
    while i < len(args):
        if args[i] == "--dismiss":
            do_dismiss = True
        elif args[i] == "--inspect-dialogs":
            inspect_only = True
        elif args[i] == "--pid":
            if i + 1 >= len(args):
                print(json.dumps(_inspection_result(
                    0, display, inspect_ciw,
                    diagnostics=["--pid requires a positive integer"],
                )))
                sys.exit(2)
            inspect_pid = args[i + 1]
            i += 1
        elif args[i] == "--ciw-window":
            if i + 1 >= len(args):
                print(json.dumps(_inspection_result(
                    0, display, None,
                    diagnostics=["--ciw-window requires an X11 window id"],
                )))
                sys.exit(2)
            inspect_ciw = args[i + 1]
            i += 1
        elif args[i] == "--timeout" and inspect_only:
            if i + 1 >= len(args):
                print(json.dumps(_inspection_result(
                    0, display, inspect_ciw,
                    diagnostics=["--timeout requires a positive finite number"],
                )))
                sys.exit(1)
            try:
                inspect_timeout = float(args[i + 1])
            except ValueError:
                inspect_timeout = 0
            i += 1
        elif args[i] == "--list-windows":
            list_windows = True
        elif args[i] == "--top-level":
            top_level = True
        elif args[i] == "--dismiss-window":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--dismiss-window requires a window id"}))
                sys.exit(2)
            dismiss_target = args[i + 1]
            i += 1
        elif args[i] == "--bootstrap-window":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--bootstrap-window requires a window id"}))
                sys.exit(2)
            bootstrap_target = args[i + 1]
            i += 1
        elif args[i] == "--setup-path":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--setup-path requires a path"}))
                sys.exit(2)
            setup_path = args[i + 1]
            i += 1
        elif args[i] == "--action":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--action requires a value"}))
                sys.exit(2)
            action = args[i + 1]
            i += 1
        elif args[i] == "--window-input":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--window-input requires a window id"}))
                sys.exit(2)
            input_target = args[i + 1]
            i += 1
        elif args[i] in ("--text", "--text-base64", "--key"):
            if i + 1 >= len(args):
                print(json.dumps({"error": "keyboard payload is missing"}))
                sys.exit(2)
            if args[i] == "--text-base64":
                import base64
                try:
                    input_text = base64.b64decode(args[i + 1]).decode("utf-8")
                except Exception:
                    print(json.dumps({"error": "invalid base64 text payload"}))
                    sys.exit(2)
            elif args[i] == "--text":
                input_text = args[i + 1]
            else:
                input_key = args[i + 1]
            i += 1
        elif args[i] == "--expect-title":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--expect-title requires a value"}))
                sys.exit(2)
            expect_title = args[i + 1]
            i += 1
        elif args[i] in (
                "--x", "--y", "--to-x", "--to-y", "--button", "--settle-ms",
                "--hold-ms", "--drag-duration-ms", "--drag-steps"):
            if i + 1 >= len(args):
                print(json.dumps({"error": "%s requires an integer" % args[i]}))
                sys.exit(2)
            try:
                value = int(args[i + 1])
            except ValueError:
                print(json.dumps({"error": "%s requires an integer" % args[i]}))
                sys.exit(2)
            if args[i] == "--x":
                input_x = value
            elif args[i] == "--y":
                input_y = value
            elif args[i] == "--to-x":
                input_to_x = value
            elif args[i] == "--to-y":
                input_to_y = value
            elif args[i] == "--settle-ms":
                settle_ms = value
            elif args[i] == "--hold-ms":
                hold_ms = value
            elif args[i] == "--drag-duration-ms":
                drag_duration_ms = value
            elif args[i] == "--drag-steps":
                drag_steps = value
            else:
                input_button = value
            i += 1
        elif args[i] == "--postcondition":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--postcondition requires a value"}))
                sys.exit(2)
            postcondition = args[i + 1]
            i += 1
        elif args[i] == "--post-expect-title":
            if i + 1 >= len(args):
                print(json.dumps({"error": "--post-expect-title requires a value"}))
                sys.exit(2)
            post_expect_title = args[i + 1]
            i += 1
        elif args[i] == "--allow-live":
            allow_live = True
        elif args[i] == "--dry-run":
            dry_run = True
        elif args[i] == "--json":
            pass
        elif not args[i].startswith("-"):
            display = args[i]
        i += 1

    if inspect_only:
        if inspect_pid is None:
            result = _inspection_result(
                0, display, inspect_ciw,
                diagnostics=["--inspect-dialogs requires --pid"],
            )
        else:
            result = inspect_dialogs(
                inspect_pid,
                display=display,
                ciw_window=inspect_ciw,
                timeout=inspect_timeout,
            )
        print(json.dumps(result, sort_keys=True))
        sys.exit(1 if result.get("status") == "indeterminate" else 0)

    if display:
        x11_envs = [{"DISPLAY": display, "XAUTHORITY": os.environ.get("XAUTHORITY")}]
    else:
        x11_envs = find_x11_envs()
        if not x11_envs:
            print(json.dumps({"error": "cannot detect DISPLAY"}))
            sys.exit(2)

    if input_target:
        try:
            if not dry_run and not allow_live:
                raise ValueError("--allow-live is required")
            if action not in ("text", "key") and (input_x is None or input_y is None):
                raise ValueError("--window-input requires --x and --y")
            active_display = _unique_window_env(x11_envs, input_target)
            result = window_input(
                active_display, input_target, expect_title, action, input_x, input_y,
                input_button, input_to_x, input_to_y, dry_run, settle_ms,
                hold_ms, drag_duration_ms, drag_steps, postcondition,
                post_expect_title, input_text, input_key,
            )
            result["display"] = active_display
        except ValueError as exc:
            result = {"error": str(exc), "window_id": input_target}
        print(json.dumps(result))
        sys.exit(1 if "error" in result else 0)

    if dismiss_target:
        try:
            active_display = _unique_window_env(x11_envs, dismiss_target)
            resolved_target = _resolve_dismiss_target(active_display, dismiss_target)
            result = dismiss_window(active_display, resolved_target, action=action)
            result["display"] = active_display
            result["requested_window_id"] = dismiss_target
            result = _verify_dismissal(result)
        except ValueError as exc:
            result = {"error": str(exc), "window_id": dismiss_target}
        print(json.dumps(result))
        sys.exit(1 if "error" in result or result.get("still_mapped", False) else 0)

    if bootstrap_target:
        if not setup_path:
            print(json.dumps({"error": "bootstrap requires --setup-path"}))
            sys.exit(2)
        matches = []
        refusal = None
        for x11_env in x11_envs:
            active_display = _apply_x11_env(x11_env)
            for window in discover_windows(active_display, top_level=True):
                if bootstrap_target not in (
                    window.get("frame_id"),
                    window.get("window_id"),
                    window.get("dismiss_id"),
                ):
                    continue
                if window.get("kind") != "ciw":
                    refusal = {
                        "error": "refusing bootstrap: selected window is not identified as a CIW",
                        "window_id": bootstrap_target,
                        "title": window.get("title") or "",
                    }
                else:
                    matches.append(x11_env)
        if len(matches) != 1:
            if len(matches) > 1:
                result = {"error": "window id matched more than one display; set VB_DISPLAY explicitly"}
            else:
                result = refusal or {
                    "error": "window id not found on any Virtuoso display",
                    "window_id": bootstrap_target,
                }
            print(json.dumps(result))
            sys.exit(1)
        selected_display = _apply_x11_env(matches[0])
        result = bootstrap_ciw(selected_display, bootstrap_target, setup_path)
        print(json.dumps(result))
        if "error" in result:
            sys.exit(1)
        sys.exit(0)

    if list_windows:
        windows = []
        for x11_env in x11_envs:
            active_display = _apply_x11_env(x11_env)
            for window in discover_windows(active_display, top_level=top_level):
                window["display"] = active_display
                windows.append(window)
                print(json.dumps(window))
        sys.exit(0 if windows else 1)

    dialogs = []
    for x11_env in x11_envs:
        active_display = _apply_x11_env(x11_env)
        for dialog in find_dialogs(active_display):
            dialog["display"] = active_display
            dialogs.append(dialog)
            print(json.dumps(dialog))
    if not dialogs:
        sys.exit(1)

    if do_dismiss:
        failed = False
        for d in dialogs:
            if "window_id" in d:
                explicit_action = d.get("suggested_action")
                result = dismiss_window(
                    d["display"],
                    d["window_id"],
                    d.get("title", ""),
                    d.get("x", 0),
                    d.get("y", 0),
                    d.get("w", 0),
                    d.get("h", 0),
                    explicit_action,
                )
                verified = _verify_dismissal(result)
                print(json.dumps(verified))
                failed = failed or "error" in verified or verified.get("still_mapped", False)
        if failed:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
