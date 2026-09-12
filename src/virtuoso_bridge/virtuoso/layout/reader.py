"""Layout read/parse utilities."""

from __future__ import annotations

import re
import math
from typing import Any


def _decode_skill_output(raw: str) -> str:
    text = (raw or "").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")


def _parse_skill_numbers(value: str) -> list[float]:
    number = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
    text = value or ""
    if not re.fullmatch(r"[\s():]*(?:" + number + r"(?:[\s():]+" + number + r")*)?[\s():]*", text):
        raise ValueError(f"Invalid SKILL numeric geometry: {value!r}")
    numbers = [float(token) for token in re.findall(number, text)]
    if not all(math.isfinite(n) for n in numbers):
        raise ValueError("Non-finite SKILL geometry")
    return numbers


def _parse_skill_point(value: str) -> tuple[float, float] | None:
    numbers = _parse_skill_numbers(value)
    if len(numbers) != 2:
        raise ValueError(f"Expected exactly two coordinates: {value!r}")
    return (numbers[0], numbers[1])


def _parse_skill_point_list(value: str) -> list[tuple[float, float]] | None:
    numbers = _parse_skill_numbers(value)
    if len(numbers) < 2 or len(numbers) % 2 != 0:
        raise ValueError(f"Expected coordinate pairs: {value!r}")
    return [(numbers[i], numbers[i + 1]) for i in range(0, len(numbers), 2)]


def parse_layout_geometry_output(raw: str) -> list[dict[str, Any]]:
    """Parse the line-oriented geometry dump returned by ``layout_read_geometry``."""
    objects: list[dict[str, Any]] = []
    for line in _decode_skill_output(raw).splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        obj: dict[str, Any] = {"kind": fields[0]}
        for field in fields[1:]:
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            obj[key] = None if value == "nil" else value
        if "bbox" in obj and isinstance(obj["bbox"], str):
            points = _parse_skill_point_list(obj["bbox"])
            if len(points) != 2:
                raise ValueError(f"Expected two bbox corners: {obj['bbox']!r}")
            obj["bbox"] = points
        if "points" in obj and isinstance(obj["points"], str):
            obj["points"] = _parse_skill_point_list(obj["points"])
        if "xy" in obj and isinstance(obj["xy"], str):
            obj["xy"] = _parse_skill_point(obj["xy"])
        objects.append(obj)
    return objects
