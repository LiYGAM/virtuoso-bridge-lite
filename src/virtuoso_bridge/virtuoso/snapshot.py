"""Polymorphic snapshot of the currently-focused Virtuoso window.

Auto-classifies the focused window (maestro / schematic / layout / ciw /
waveform / hierarchy / unknown) and dispatches to the kind-specific
reader.  Each backend returns a JSON-serializable dict; this wrapper
adds an outer envelope with the kind tag and window title so consumers
can branch on ``result["kind"]``.

Maestro uses its domain aggregator. Layout and schematic use the bounded
editor context reader; unsupported window kinds return supported=False.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from virtuoso_bridge import VirtuosoClient


# ---------------------------------------------------------------------------
# Window-kind classification — pure regex on the title string.
# ---------------------------------------------------------------------------

# (compiled regex, kind).  First match wins; order from specific → general.
# Maestro and schematic both can be wrapped in an "ADE Assembler/Explorer
# Editing/Reading: LIB CELL VIEW" title — distinguish by the trailing VIEW
# token, since Schematic Editor windows aren't always labelled that way.
_KIND_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"ADE\s+(?:Assembler|Explorer)\s+(?:Editing|Reading):"
                r"\s+\S+\s+\S+\s+maestro\b"),                            "maestro"),
    (re.compile(r"ADE\s+(?:Assembler|Explorer)\s+(?:Editing|Reading):"
                r"\s+\S+\s+\S+\s+schematic\b"),                          "schematic"),
    (re.compile(r"Schematic Editor"),                                     "schematic"),
    (re.compile(r"Layout Suite"),                                         "layout"),
    (re.compile(r"Visualization\s*&?\s*Analysis"),                        "waveform"),
    (re.compile(r"Waveform Window"),                                      "waveform"),
    (re.compile(r"Cadence Hierarchy Editor"),                             "hierarchy"),
    (re.compile(r"Virtuoso®?\s+[\d.\-a-z]+\s*-\s*Log:"),                  "ciw"),
)


def classify_window(title: str) -> str:
    """Return the window-kind tag for a Virtuoso window title.

    One of: ``maestro``, ``schematic``, ``layout``, ``waveform``,
    ``hierarchy``, ``ciw``, or ``unknown``.

    Pure function — exposed for callers that want classification without
    actually grabbing the snapshot (e.g. CLI ``virtuoso-bridge windows``
    could colorize by kind).
    """
    if not title:
        return "unknown"
    for pat, kind in _KIND_PATTERNS:
        if pat.search(title):
            return kind
    return "unknown"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _focused_window_title(client: VirtuosoClient) -> str:
    """One SKILL call → focused window title (or ``""`` if no focus)."""
    r = client.execute_skill(
        'let((cw) cw = hiGetCurrentWindow() if(cw hiGetWindowName(cw) ""))', operation_class="read_only"
    )
    if r.status.value != "success" or r.completion.value != "confirmed":
        raise RuntimeError("Focused window query was not confirmed")
    raw = (r.output or "").strip()
    return raw.strip('"') if raw and raw != "nil" else ""


def snapshot(client: VirtuosoClient, *,
             kind: str | None = None,
             **kwargs: Any) -> dict:
    """Snapshot whatever window is currently focused in Virtuoso.

    Auto-detects the kind by parsing the focused window title; pass
    ``kind="maestro"`` (etc.) to override detection.

    Returns::

        {
          "kind":         "maestro" | "schematic" | "layout" | ...,
          "window_title": "<original title>",
          "supported":    True | False,
          "data":         { ... kind-specific dict ... } | None,
        }

    For supported kinds, ``data`` is whatever the kind's aggregator
    returns.  For ``maestro``, that's the dict from
    :func:`virtuoso_bridge.virtuoso.maestro.snapshot` (16 fields:
    ``location`` / ``session`` / ``analyses`` / ``variables`` / ... ).

    For unsupported kinds, ``data`` is ``None`` and ``supported`` is
    ``False``.  ``kwargs`` are forwarded only to the kind-specific
    aggregator — for ``kind="unknown"`` they are ignored.
    """
    title = _focused_window_title(client)
    detected_kind = kind or classify_window(title)

    out: dict = {
        "kind":         detected_kind,
        "window_title": title,
        "supported":    False,
        "data":         None,
    }

    if detected_kind == "maestro":
        from .maestro import snapshot as _maestro_snapshot
        out["data"] = _maestro_snapshot(client, **kwargs)
        out["supported"] = True

    elif detected_kind in {"layout", "schematic"}:
        out["data"] = client.editor_context(**kwargs)
        out["supported"] = True

    return out
