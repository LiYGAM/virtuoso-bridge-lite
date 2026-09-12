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
import subprocess
import sys
import time

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)

VIRTUOSO_WM_CLASSES = ["virtuoso", "libManager"]
KNOWN_MODAL_ACTIONS = {
    "ade explorer update and run": "enter",
    "ade assembler message 1749": "alt-o",
}


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


WINDOW_INPUT_ACTIONS = ("move", "click", "drag")
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


def preflight_window_input(windows, window_id, expect_title, action, x, y,
                           button=1, to_x=None, to_y=None, window_info=None):
    """Validate a pointer operation without opening X11 or emitting events.

    ``windows`` must be a freshly discovered list from :func:`discover_windows`
    and ``window_info`` must be a fresh exact-target ``xwininfo`` response.
    This deliberately does not accept a WM frame id or cached geometry.
    """
    if not expect_title:
        raise ValueError("--expect-title is required")
    if action not in WINDOW_INPUT_ACTIONS:
        raise ValueError("unsupported action: %s" % action)
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


def window_input(display, window_id, expect_title, action, x, y, button=1,
                 to_x=None, to_y=None, dry_run=False, settle_ms=50,
                 hold_ms=0, drag_duration_ms=0, drag_steps=1,
                 postcondition="none", post_expect_title=None):
    """Discover, refresh, bounds-check, then send one explicit pointer action."""
    windows = discover_windows(display)
    info = _read_window_info(window_id)
    prepared = preflight_window_input(
        windows, window_id, expect_title, action, x, y, button, to_x, to_y, info,
    )
    timing = _validate_window_input_timing(
        settle_ms, hold_ms, drag_duration_ms, drag_steps,
    )
    if postcondition not in WINDOW_INPUT_POSTCONDITIONS:
        raise ValueError("unsupported postcondition: %s" % postcondition)
    if postcondition == "title-contains" and not post_expect_title:
        raise ValueError("title-contains requires --post-expect-title")
    state_before = _prepared_window_input_state(prepared)
    if dry_run:
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
            to_x, to_y, current_info,
        )

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
            children.append(child)
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
    return "command interpreter" in title_l or bool(re.search(r"\bciw\b", title_l))


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
    return display


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
    list_windows = False
    top_level = False
    dismiss_target = None
    bootstrap_target = None
    setup_path = None
    action = "enter"
    input_target = None
    expect_title = None
    input_x = None
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
            if input_x is None or input_y is None:
                raise ValueError("--window-input requires --x and --y")
            result = window_input(
                display, input_target, expect_title, action, input_x, input_y,
                input_button, input_to_x, input_to_y, dry_run, settle_ms,
                hold_ms, drag_duration_ms, drag_steps, postcondition,
                post_expect_title,
            )
        except ValueError as exc:
            result = {"error": str(exc), "window_id": input_target}
        print(json.dumps(result))
        sys.exit(1 if "error" in result else 0)

    if dismiss_target:
        matches = []
        for x11_env in x11_envs:
            active_display = _apply_x11_env(x11_env)
            resolved_target = _resolve_dismiss_target(active_display, dismiss_target)
            if resolved_target != dismiss_target or any(
                dismiss_target in (w.get("frame_id"), w.get("window_id"), w.get("dismiss_id"))
                for w in discover_windows(active_display)
            ):
                matches.append((active_display, resolved_target))
        if not matches:
            print(json.dumps({"error": "window id not found on any Virtuoso display", "window_id": dismiss_target}))
            sys.exit(1)
        failed = False
        for active_display, resolved_target in matches:
            result = dismiss_window(active_display, resolved_target, action=action)
            result["display"] = active_display
            result["requested_window_id"] = dismiss_target
            verified = _verify_dismissal(result)
            print(json.dumps(verified))
            failed = failed or "error" in verified or verified.get("still_mapped", False)
        sys.exit(1 if failed else 0)

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
