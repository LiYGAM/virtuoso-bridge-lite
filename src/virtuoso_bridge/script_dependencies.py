"""Read-only dependency hints; dynamic SKILL is never evaluated."""
import hashlib
from pathlib import Path
import re

from virtuoso_bridge.virtuoso.skill_output import parse_sexpr


def declared_siblings(text):
    names = re.findall(r'^;\s*Dependency:\s*sibling\s+([^\s;]+)', text, re.M)
    if any(Path(name).name != name or name in {".", ".."} for name in names):
        raise ValueError("Sibling dependency must be a filename")
    return names


def dependency_hints(source, *, root=None, text=None):
    source = Path(source).resolve()
    if text is None:
        text = source.read_text(encoding="utf-8-sig")
    tokens = [m.group(0) for m in re.finditer(r';(?:\\\r?\n|[^\n])*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[()]', text, re.S)
              if not m.group(0).startswith((";", "/*"))]
    result = []
    for name in declared_siblings(text):
        dependency = source.parent / name
        item = {"expression": name, "declaration": "sibling", "resolved": dependency.is_file(), "path": str(dependency)}
        if dependency.is_file():
            item["sha256"] = hashlib.sha256(dependency.read_bytes()).hexdigest()
        result.append(item)
    for index, token in enumerate(tokens[:-2]):
        if token not in {"load", "loadi"} or tokens[index + 1] != "(":
            continue
        literal = tokens[index + 2]
        if not literal.startswith('"'):
            result.append({"expression": "dynamic", "resolved": False})
            continue
        value = parse_sexpr(literal)
        path = Path(value)
        candidates = [path] if path.is_absolute() else [source.parent / path] + ([Path(root) / path] if root else [])
        existing = sorted({str(p.resolve()) for p in candidates if p.is_file()})
        item = {"expression": value, "resolved": len(existing) == 1, "candidates": existing}
        if len(existing) == 1:
            item.update(path=existing[0], sha256=hashlib.sha256(Path(existing[0]).read_bytes()).hexdigest())
        result.append(item)
    return {"coverage": "literal dependency observations; runtime resolution and dynamic loads are not proven",
            "items": result}
