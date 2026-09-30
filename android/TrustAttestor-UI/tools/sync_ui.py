#!/usr/bin/env python3
"""Preview or apply a conservative, three-way UI sync without requiring Git."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import uuid


JAVA_ROOT = "app/src/main/java/com/lingqing/trustattestor/"
ROOT_KOTLIN = frozenset({
    "MainActivity.kt", "AppLanguage.kt", "CloudDisclosure.kt", "FindingTextCatalog.kt",
})
UI_ROOT = JAVA_ROOT + "ui/"
RES_ROOT = "app/src/main/res/"
MANIFEST_NAME = "ui-sync-manifest.json"
SYNC_STATUSES = frozenset({"NEW", "UPDATE", "ADOPT"})
WINDOWS_RESERVED_NAMES = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$"}) | {
    prefix + str(number) for prefix in ("com", "lpt") for number in range(1, 10)
}


class SyncError(Exception):
    pass


def _safe_relative(relative: str) -> bool:
    if not isinstance(relative, str) or not relative or any(
        character in relative for character in '\\:<>"|?*'
    ):
        return False
    parts = relative.split("/")
    if any(part in {"", ".", ".."} or part.endswith((" ", "."))
           or any(ord(character) < 32 for character in part)
           or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES for part in parts):
        return False
    return not PurePosixPath(relative).is_absolute()


def allowed_path(relative: str) -> bool:
    """Keep this allowlist independent of the manifest's user-editable contents."""
    if not _safe_relative(relative):
        return False
    if relative.startswith(JAVA_ROOT) and relative[len(JAVA_ROOT):] in ROOT_KOTLIN:
        return True
    if relative.startswith(UI_ROOT) and relative.endswith(".kt"):
        return True
    return relative.startswith(RES_ROOT)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _checked_path(root: Path, relative: str) -> Path:
    """Reject traversal and links, including links into a disallowed local directory."""
    if not _safe_relative(relative):
        raise SyncError(f"Invalid relative path: {relative!r}")
    parts = relative.split("/")
    path = root
    for part in parts:
        path = path / part
        if _is_link(path):
            raise SyncError(f"Symlink/junction is not allowed: {path}")
    try:
        path.resolve().relative_to(root)
    except ValueError as error:
        raise SyncError(f"Path escapes project root: {path}") from error
    return path


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(root: Path, relative: str) -> bytes | None:
    path = _checked_path(root, relative)
    if not path.exists():
        return None
    if not path.is_file():
        raise SyncError(f"Expected a regular file: {path}")
    return path.read_bytes()


def _hash(root: Path, relative: str) -> str | None:
    data = _read(root, relative)
    return None if data is None else _digest(data)


def _candidates(root: Path) -> set[str]:
    result = set()
    for name in ROOT_KOTLIN:
        relative = JAVA_ROOT + name
        if _checked_path(root, relative).exists():
            result.add(relative)
    for relative_dir in (UI_ROOT.rstrip("/"), RES_ROOT.rstrip("/")):
        directory = _checked_path(root, relative_dir)
        if not directory.exists():
            continue
        if not directory.is_dir():
            raise SyncError(f"Expected a directory: {directory}")
        for current, directories, files in os.walk(directory, followlinks=False):
            for name in directories + files:
                path = Path(current) / name
                relative = path.relative_to(root).as_posix()
                _checked_path(root, relative)
            for name in files:
                relative = (Path(current) / name).relative_to(root).as_posix()
                if allowed_path(relative):
                    result.add(relative)
    return result


@dataclass(frozen=True)
class Change:
    path: str
    status: str
    baseline: str | None
    source: str | None
    destination: str | None


@dataclass
class Plan:
    ui_root: Path
    source_root: Path
    destination_root: Path
    manifest: dict
    manifest_bytes: bytes
    changes: list[Change]

    @property
    def conflicts(self) -> list[Change]:
        return [change for change in self.changes if change.status == "CONFLICT"]


def plan_sync(ui_root: Path, target: Path, direction: str = "push") -> Plan:
    if direction not in {"push", "pull"}:
        raise SyncError("direction must be push or pull")
    ui_root = Path(ui_root).resolve(strict=True)
    target = Path(target).resolve(strict=True)
    if not ui_root.is_dir() or not target.is_dir() or ui_root == target:
        raise SyncError("UI project and target must be distinct existing directories")
    manifest_bytes = _read(ui_root, MANIFEST_NAME)
    if manifest_bytes is None:
        raise SyncError(f"Missing {ui_root / MANIFEST_NAME}")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise SyncError(f"Invalid sync manifest: {error}") from error
    if not isinstance(manifest, dict) or type(manifest.get("version")) is not int or manifest["version"] != 1:
        raise SyncError("Sync manifest must have integer version 1")
    baseline = manifest.get("files")
    if not isinstance(baseline, dict):
        raise SyncError("Sync manifest files must be an object of path -> SHA-256")
    for relative, digest in baseline.items():
        if not allowed_path(relative):
            raise SyncError(f"Manifest contains a forbidden path: {relative!r}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise SyncError(f"Invalid baseline SHA-256 for {relative}")
    source, destination = (ui_root, target) if direction == "push" else (target, ui_root)
    paths = set(baseline) | _candidates(source) | _candidates(destination)
    # Reject case aliases even on case-sensitive hosts, so a moved Windows project
    # cannot end up applying two different actions to one physical destination.
    canonical_paths: dict[str, str] = {}
    for relative in paths:
        canonical = relative.casefold()
        if canonical in canonical_paths and canonical_paths[canonical] != relative:
            raise SyncError(f"Case-aliased paths: {canonical_paths[canonical]} and {relative}")
        canonical_paths[canonical] = relative
    changes = []
    for relative in sorted(paths):
        previous = baseline.get(relative)
        previous = previous.lower() if previous is not None else None
        source_hash = _hash(source, relative)
        destination_hash = _hash(destination, relative)
        if previous is not None and (source_hash is None or destination_hash is None):
            status = "DELETE_MANUAL"
        elif source_hash == destination_hash:
            status = "UNCHANGED" if source_hash == previous else "ADOPT"
        elif previous is None:
            if destination_hash is None:
                status = "NEW"
            elif source_hash is None:
                status = "DESTINATION_ONLY"
            else:
                status = "CONFLICT"
        elif destination_hash == previous:
            status = "UPDATE"
        elif source_hash == previous:
            status = "DESTINATION_CHANGED"
        else:
            status = "CONFLICT"
        changes.append(Change(relative, status, previous, source_hash, destination_hash))
    return Plan(ui_root, source, destination, manifest, manifest_bytes, changes)


def _atomic_write(root: Path, relative: str, data: bytes) -> None:
    path = _checked_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = _checked_path(root, relative)
    temporary = path.with_name(path.name + ".ui-sync-" + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply_plan(plan: Plan) -> Path | None:
    """Reject the whole batch on conflicts or changes since planning; never delete files."""
    if plan.conflicts:
        raise SyncError("Conflicts found; no files or manifest were written")
    selected = [change for change in plan.changes if change.status in SYNC_STATUSES]
    if not selected:
        return None
    if _read(plan.ui_root, MANIFEST_NAME) != plan.manifest_bytes:
        raise SyncError("Manifest changed since planning; no files were written")
    for change in plan.changes:
        if (_hash(plan.source_root, change.path) != change.source
                or _hash(plan.destination_root, change.path) != change.destination):
            raise SyncError(f"File changed since planning; no files were written: {change.path}")

    # Keep byte snapshots so source edits cannot change what is copied after preflight.
    payloads: dict[str, bytes] = {}
    originals: dict[str, bytes | None] = {}
    for change in selected:
        source = _read(plan.source_root, change.path)
        destination = _read(plan.destination_root, change.path)
        if (source is None or _digest(source) != change.source
                or (None if destination is None else _digest(destination)) != change.destination):
            raise SyncError(f"File changed during preflight: {change.path}")
        payloads[change.path] = source
        originals[change.path] = destination

    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex
    backup_relative = "build/ui-sync-backups/" + name
    backup = _checked_path(plan.destination_root, backup_relative)
    backup.mkdir(parents=True, exist_ok=False)
    _atomic_write(backup, "ui-sync-manifest.before.json", plan.manifest_bytes)
    for change in selected:
        original = originals[change.path]
        if original is not None:
            _atomic_write(backup, "files/" + change.path, original)
    metadata = {
        "source": str(plan.source_root), "destination": str(plan.destination_root),
        "uiProject": str(plan.ui_root),
        "newFiles": [change.path for change in selected if originals[change.path] is None],
        "files": {change.path: change.source for change in selected},
    }
    _atomic_write(backup, "backup.json", (json.dumps(metadata, indent=2) + "\n").encode())

    updated = dict(plan.manifest)
    updated["files"] = dict(plan.manifest["files"])
    written = []
    try:
        for change in selected:
            if _hash(plan.destination_root, change.path) != change.destination:
                raise SyncError(f"Destination changed before write: {change.path}")
            if change.status != "ADOPT":
                _atomic_write(plan.destination_root, change.path, payloads[change.path])
                written.append(change)
            updated["files"][change.path] = change.source
        if _read(plan.ui_root, MANIFEST_NAME) != plan.manifest_bytes:
            raise SyncError("Manifest changed before commit")
        _atomic_write(plan.ui_root, MANIFEST_NAME,
                      (json.dumps(updated, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    except Exception as error:
        rollback_errors = []
        for change in reversed(written):
            try:
                if _hash(plan.destination_root, change.path) != change.source:
                    raise SyncError("destination changed after sync write")
                original = originals[change.path]
                if original is None:
                    # Only undo a new file created by this failed batch, never a planned deletion.
                    _checked_path(plan.destination_root, change.path).unlink()
                else:
                    _atomic_write(plan.destination_root, change.path, original)
            except Exception as rollback_error:
                rollback_errors.append(f"{change.path}: {rollback_error}")
        suffix = "" if not rollback_errors else "; rollback incomplete: " + "; ".join(rollback_errors)
        raise SyncError(f"Apply failed: {error}; backup: {backup}{suffix}") from error
    return backup


def print_plan(plan: Plan) -> None:
    print(f"Source:      {plan.source_root}")
    print(f"Destination: {plan.destination_root}")
    visible = [change for change in plan.changes if change.status != "UNCHANGED"]
    for change in visible:
        print(f"{change.status:20} {change.path}")
        print("  SHA-256 baseline/source/destination: " + " / ".join(
            digest or "missing" for digest in (change.baseline, change.source, change.destination)))
        if change.status == "DELETE_MANUAL":
            print("  Missing tracked file: resolve deletion manually; neither side will be deleted or restored.")
        if change.status not in {"UPDATE", "CONFLICT"}:
            continue
        source = _read(plan.source_root, change.path)
        destination = _read(plan.destination_root, change.path)
        if source is None or destination is None:
            continue
        if max(len(source), len(destination)) > 512 * 1024 or b"\0" in source or b"\0" in destination:
            print(f"  Binary/large-file difference: source={len(source)}, destination={len(destination)} bytes")
            continue
        try:
            lines = list(difflib.unified_diff(
                destination.decode("utf-8").splitlines(), source.decode("utf-8").splitlines(),
                fromfile="destination/" + change.path, tofile="source/" + change.path, lineterm=""))
        except UnicodeError:
            print(f"  Binary difference: source={len(source)}, destination={len(destination)} bytes")
            continue
        for line in lines[:100]:
            print(line)
        if len(lines) > 100:
            print(f"  ... {len(lines) - 100} more diff lines omitted")
    if not visible:
        print("No changes.")
    if plan.conflicts:
        print("CONFLICT: the entire batch is blocked; no files will be written.")


def main(argv: list[str] | None = None, *, ui_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path, help="Original TA project root")
    parser.add_argument("--direction", choices=("push", "pull"), default="push")
    parser.add_argument("--apply", action="store_true", help="Apply safe changes; default is dry-run")
    args = parser.parse_args(argv)
    try:
        root = ui_root if ui_root is not None else Path(__file__).resolve().parent.parent
        plan = plan_sync(root, args.target, args.direction)
        print_plan(plan)
        if plan.conflicts:
            return 2
        if not args.apply:
            print("DRY RUN: no files or baseline were written. Use --apply to apply safe changes.")
            return 0
        backup = apply_plan(plan)
        print("No files require syncing." if backup is None else f"Applied. Backup: {backup}")
        return 0
    except (SyncError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
