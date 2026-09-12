"""Bounded editor context reads and in-request target guards."""
from __future__ import annotations

from virtuoso_bridge.models import CompletionStatus, ExecutionStatus, OperationClass
from virtuoso_bridge.virtuoso.ops import escape_skill_string, default_view_type_for
from virtuoso_bridge.virtuoso.skill_output import parse_sexpr, is_single_complete_skill_list


def skill_string(value):
    return '"' + escape_skill_string(str(value)) + '"'


def context_expression(limit=50):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 500:
        raise ValueError("selection limit must be an integer between 0 and 500")
    return f'''let((w d e h tr tech sels rows n info)
      w=hiGetCurrentWindow()
      d=when(w geGetWindowCellView(w))
      e=when(w geGetEditCellView(w))
      h=when(e geGetInstHierPath(w))
      tr=when(e list(geEditToWindowPoint(w 0:0) geEditToWindowPoint(w 1:0) geEditToWindowPoint(w 0:1)))
      tech=when(e techGetTechFile(e))
      sels=when(e geGetSelSet(w)) rows=nil n=0
      foreach(o sels
        when(n < {limit}
          rows=cons(list(sprintf(nil "%L" o) o~>objType o~>lpp o~>bBox) rows))
        n=n+1)
      info=list(1 if(boundp('RBLastEpoch) RBLastEpoch nil) ipcGetPid()
        if(boundp('RBRecoverySession) RBRecoverySession nil)
        sprintf(nil "%L" w) when(w hiGetWindowName(w))
        when(d list(sprintf(nil "%L" d) d~>libName d~>cellName d~>viewName))
        when(e list(sprintf(nil "%L" e) e~>libName e~>cellName e~>viewName e~>mode e~>DBUPerUU))
        sprintf(nil "%L" h) tr
        when(e list(w~>xSnapSpacing w~>ySnapSpacing))
        when(tech list(techGetTechLibName(ddGetObj(e~>libName)) sprintf(nil "%L" tech)))
        when(e dbIsCellViewModified(e)) n reverse(rows))
      list(sprintf(nil "%L" info) info))'''


def editor_context(client, *, limit=50, timeout=15):
    result = client.execute_skill(context_expression(limit), operation_class=OperationClass.READ_ONLY, timeout=timeout)
    if result.status != ExecutionStatus.SUCCESS or result.completion != CompletionStatus.CONFIRMED:
        raise RuntimeError("Editor context was not confirmed: " + "; ".join(result.errors))
    if not is_single_complete_skill_list(result.output):
        raise ValueError("Malformed editor context response")
    parsed = parse_sexpr(result.output)
    if len(parsed) != 2 or not isinstance(parsed[0], str) or not isinstance(parsed[1], list) or len(parsed[1]) != 15:
        raise ValueError("Invalid editor context schema")
    signature, row = parsed
    def cell(value):
        if not value:
            return None
        item = dict(zip(("id", "lib", "cell", "view", "mode", "dbu_per_uu"), value))
        if item.get("dbu_per_uu") is not None:
            item["dbu_per_uu"] = float(item["dbu_per_uu"])
        return item
    count = int(row[13])
    entries = [dict(zip(("id", "obj_type", "lpp", "bbox"), entry)) for entry in row[14] or []]
    return {"schema_version": 1, "profile": getattr(client, "_profile", None), "daemon_epoch": row[1],
            "ciw_pid": int(row[2]), "ciw_session": row[3], "window_id": row[4], "window_title": row[5],
            "display_cellview": cell(row[6]), "edit_cellview": cell(row[7]), "hierarchy_path": row[8],
            "edit_to_window_basis": row[9], "snap_spacing": row[10],
            "tech_library": row[11][0] if row[11] else None, "tech_file": row[11][1] if row[11] else None,
            "modified": bool(row[12]), "selection_count": count, "selection": entries,
            "selection_limit": limit, "truncated": count > limit,
            "guard": {"schema_version": 1, "signature": signature, "selection_limit": limit, "complete": count <= limit},
            "request_id": result.request_id}


def guard_context(command, expected):
    guard = expected.get("guard", expected)
    if guard.get("schema_version") != 1 or not guard.get("complete") or not isinstance(guard.get("signature"), str):
        raise ValueError("A complete editor context guard is required; truncated snapshots cannot authorize a mutation")
    expression = context_expression(guard.get("selection_limit"))
    return f'''let((vbDevContext)
      vbDevContext={expression}
      unless(equal(car(vbDevContext) {skill_string(guard['signature'])}) error("editor-context-changed\\n"))
      {command}

    )'''


def target_matches(variable, target):
    if set(target) != {"lib", "cell", "view"} or not all(isinstance(v, str) and v for v in target.values()):
        raise ValueError("target requires non-empty lib, cell and view")
    return variable + " && " + " && ".join(f"equal({variable}~>{slot} {skill_string(target[key])})"
                                            for key, slot in (("lib", "libName"), ("cell", "cellName"), ("view", "viewName")))


def targeted_load(command, target, *, mode="a", view_type=None, require_window=False, save=False):
    matches = target_matches("cv", target)
    if mode not in {"r", "a"}:
        raise ValueError("Development loads support r/a mode; destructive creation must use an explicit create API")
    if save and mode == "r":
        raise ValueError("Cannot save a read-only target")
    window_check = (f'unless({target_matches("geGetEditCellView()", target)} '
                    'error("edit-window-target-mismatch\\n"))') if require_window else ""
    opened = "dbOpenCellViewByType(" + " ".join(skill_string(v) for v in (
        target["lib"], target["cell"], target["view"], view_type or default_view_type_for(target["view"]), mode)) + ")"
    saved = 'unless(dbSave(vbDevTarget) error("target-save-failed\\n"))' if save else ""
    return f'''let((cv vbDevTarget vbDevValue)
      {window_check}
      cv={opened} unless({matches} error("load-target-unavailable\\n"))
      unless(equal(cv~>mode {skill_string(mode)}) error("load-target-mode-mismatch\\n"))
      vbDevTarget=cv
      vbDevValue={command}
      unless(equal(cv vbDevTarget) && {matches} error("script-changed-bound-target\\n"))
      {saved}
      vbDevValue)'''
