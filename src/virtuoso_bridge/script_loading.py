"""Immutable entrypoint files and per-request load receipts.

Receipts describe managed loads only; arbitrary SKILL can redefine functions or
load further files, so neither is silently attributed to the entrypoint digest.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from virtuoso_bridge.runtime_paths import state_dir, tmp_dir


def prepare_script(client, path, *, timeout=None, expected_sha256=None):
    deadline = time.monotonic() + timeout if timeout is not None else None
    def remaining():
        if deadline is None:
            return None
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("script-preparation-budget-exhausted")
        return value
    source = Path(path).expanduser().resolve(strict=True)
    content = source.read_bytes()
    # Preserve source bytes, including a possible BOM, in the artifact.
    text = content.decode("utf-8")
    from virtuoso_bridge.script_dependencies import dependency_hints, declared_siblings
    root = next((p for p in source.parents if (p / ".git").exists()), source.parent)
    dependencies = dependency_hints(source, root=root, text=text)
    digest = hashlib.sha256(content).hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        raise ValueError("source-changed-before-load")
    captured = {source: content}
    pending = [source]
    while pending:
        parent = pending.pop()
        body = captured[parent].decode("utf-8-sig")
        # Explicit sibling declarations preserve get_filename(piport)-based
        # lazy loads without rewriting SKILL or guessing dynamic expressions.
        for name in declared_siblings(body):
            dependency = (parent.parent / name).resolve(strict=True)
            if dependency not in captured:
                if len(captured) >= 64:
                    raise ValueError("Script bundle exceeds 64 declared files")
                captured[dependency] = dependency.read_bytes()
                pending.append(dependency)
    bundle_root = Path(os.path.commonpath([str(p.parent) for p in captured]))
    bundle_items = [{"source_path": str(p), "relative_path": p.relative_to(bundle_root).as_posix(),
                     "sha256": hashlib.sha256(data).hexdigest()} for p, data in sorted(captured.items())]
    bundle_digest = hashlib.sha256(json.dumps(bundle_items, sort_keys=True).encode()).hexdigest()
    source_key = hashlib.sha256(str(source).encode()).hexdigest()[:24]
    load_id = uuid.uuid4().hex
    relative = f"script-loads/{source_key}/{bundle_digest}/{load_id}"
    tunnel = getattr(client, "_tunnel", None)
    if tunnel is not None:
        from virtuoso_bridge.transport.remote_paths import (
            default_virtuoso_bridge_dir, resolve_client_id, resolve_remote_username,
        )
        from virtuoso_bridge.transport.tunnel import _profiled_bridge_leaf
        root = tunnel.remote_work_dir
        if not root:
            user = resolve_remote_username(configured_user=getattr(tunnel, "_remote_user", None), runner=tunnel.ssh_runner)
            root = default_virtuoso_bridge_dir(user, _profiled_bridge_leaf(getattr(tunnel, "_profile", None)),
                                               resolve_client_id(getattr(tunnel, "_profile", None)))
        artifact_root = root.rstrip("/") + "/" + relative
        for item in bundle_items:
            data = captured[Path(item["source_path"])].decode("utf-8")
            destination = artifact_root + "/" + item["relative_path"]
            result = tunnel.upload_text(data, destination, timeout=remaining(), retry_transport_errors=False, exclusive_create=True)
            if result.returncode:
                raise RuntimeError(f"Script upload failed: {result.stderr.strip()}")
    else:
        artifact_root = (tmp_dir() / relative).as_posix()
        for item in bundle_items:
            artifact_path = Path(artifact_root) / item["relative_path"]
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            with artifact_path.open("xb") as stream:
                stream.write(captured[Path(item["source_path"])])
    artifact = artifact_root + "/" + source.relative_to(bundle_root).as_posix()
    return {"load_id": load_id, "source_path": str(source), "source_sha256": digest,
            "source_bytes": len(content), "artifact_path": artifact, "uploaded": tunnel is not None,
            "content_binding": "immutable-entrypoint", "bundle_sha256": bundle_digest, "captured_files": bundle_items,
            "source_map": {artifact_root + "/" + item["relative_path"]: item["source_path"] for item in bundle_items},
            "dependencies": dependencies}


def receipt_directory(client):
    endpoint = [getattr(client, "_profile", None), getattr(client, "_host", None), getattr(client, "_port", None)]
    key = hashlib.sha256(json.dumps(endpoint).encode()).hexdigest()
    return state_dir() / "script-loads" / key


def write_receipt(client, receipt):
    directory = receipt_directory(client)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (receipt["load_id"] + ".json")
    temporary = directory / (receipt["load_id"] + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    return str(path)


def finish_receipt(client, prepared, result):
    receipt = dict(prepared, finished_at=time.time(), request_id=result.request_id,
                   daemon_epoch=result.metadata.get("daemon_epoch"), completion=result.completion.value,
                   status="completion-unknown", log_check="not-recorded")
    if result.completion.value == "not_dispatched":
        receipt["status"] = "not-dispatched"
    elif result.completion.value == "confirmed":
        receipt["status"] = "load-returned" if result.status.value == "success" else "failed-may-be-partial"
    result.metadata["script_load"] = receipt
    try:
        result.metadata["load_receipt_path"] = write_receipt(client, receipt)
    except OSError as exc:
        # Do not hide the completed operation or encourage retrying it.
        result.warnings.append(f"Load receipt could not be persisted: {exc}")
    return result


def managed_load_command(command, prepared):
    """Record admission in CIW order, before load can partially redefine functions."""
    from virtuoso_bridge.virtuoso.development import skill_string
    key = hashlib.sha256(prepared["source_path"].encode()).hexdigest()
    load_id = skill_string(prepared["load_id"])
    key_string = skill_string(key)
    return f'''progn(
      unless(boundp('RBDevManagedLoads) RBDevManagedLoads=nil)
      RBDevManagedLoads=cons(list({key_string} {load_id})
        setof(rbDevRecord RBDevManagedLoads !equal(car(rbDevRecord) {key_string})))
      {command}
    )'''


def loaded_scripts(client, *, timeout=15):
    from virtuoso_bridge.models import CompletionStatus, ExecutionStatus, OperationClass
    result = client.execute_skill('list(if(boundp(\'RBLastEpoch) RBLastEpoch nil) '
                                  'if(boundp(\'RBRecoverySession) RBRecoverySession nil) ipcGetPid() '
                                  'if(boundp(\'RBDevManagedLoads) RBDevManagedLoads nil))',
                                  operation_class=OperationClass.READ_ONLY, timeout=timeout)
    if result.status != ExecutionStatus.SUCCESS or result.completion != CompletionStatus.CONFIRMED:
        raise RuntimeError("Current CIW identity could not be confirmed")
    epoch = result.metadata.get("daemon_epoch")
    if not epoch:
        raise RuntimeError("Current daemon epoch is unavailable")
    from virtuoso_bridge.virtuoso.skill_output import parse_sexpr, is_single_complete_skill_list
    identity = parse_sexpr(result.output) if is_single_complete_skill_list(result.output) else None
    if not isinstance(identity, list) or len(identity) != 4 or identity[0] != epoch:
        raise RuntimeError("Managed load identity could not be confirmed")
    markers = {row[0]: row[1] for row in identity[3] or [] if isinstance(row, list) and len(row) == 2}
    records, unreadable = [], []
    for path in receipt_directory(client).glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or not isinstance(record.get("source_path"), str):
                raise ValueError("Invalid load receipt schema")
            record["same_epoch"] = record.get("daemon_epoch") == epoch
            records.append(record)
        except (OSError, ValueError) as exc:
            unreadable.append({"path": str(path), "error": str(exc)})
    records.sort(key=lambda r: r.get("started_at", 0))
    groups = {}
    for record in records:
        groups.setdefault(record["source_path"], []).append(record)
    latest = []
    for source, group in groups.items():
        marker = markers.get(hashlib.sha256(source.encode()).hexdigest())
        selected = next((r for r in group if r.get("load_id") == marker), None)
        unattributed = [r for r in group if not r.get("daemon_epoch") and r.get("status") != "not-dispatched"]
        if unattributed:
            latest.append({"source_path": source, "status": "epoch-unattributed-load",
                           "candidate_load_ids": [r.get("load_id") for r in unattributed]})
        elif selected and selected["same_epoch"]:
            latest.append(selected)
        elif any(r["same_epoch"] for r in group):
            latest.append({"source_path": source, "status": "load-order-unverified", "ciw_load_id": marker})
    return {"daemon_epoch": epoch, "ciw_identity": result.output, "latest": latest,
            "history": records, "unreadable": unreadable,
            "coverage": "managed entrypoint loads from this client endpoint; external redefinitions and nested loads are untracked"}
