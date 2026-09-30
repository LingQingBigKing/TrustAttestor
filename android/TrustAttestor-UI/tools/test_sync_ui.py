"""Isolated filesystem tests for the UI sync boundary and conflict protection."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("sync_ui", Path(__file__).with_name("sync_ui.py"))
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)

ACTIVITY = sync.JAVA_ROOT + "MainActivity.kt"
HOME = sync.UI_ROOT + "HomeFragment.kt"
RESOURCE = sync.RES_ROOT + "values/strings.xml"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SyncUiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ui = self.root / "Moved UI Project"
        self.target = self.root / "Original TA Project"
        self.ui.mkdir()
        self.target.mkdir()
        self.manifest = {"version": 1, "files": {}, "description": "preserved metadata"}
        self.save_manifest()

    def write(self, root, relative, data):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def save_manifest(self):
        self.write(self.ui, sync.MANIFEST_NAME, json.dumps(self.manifest).encode())

    def read_manifest(self):
        return json.loads((self.ui / sync.MANIFEST_NAME).read_text())

    def tracked(self, relative=ACTIVITY, data=b"baseline\n"):
        self.write(self.ui, relative, data)
        self.write(self.target, relative, data)
        self.manifest["files"][relative] = sha(data)
        self.save_manifest()

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = sync.main(["--target", str(self.target), *args], ui_root=self.ui)
        return result, output.getvalue()

    def test_dry_run_is_default_and_does_not_write(self):
        self.tracked()
        self.write(self.ui, ACTIVITY, b"new UI\n")
        manifest_before = (self.ui / sync.MANIFEST_NAME).read_bytes()
        result, output = self.call()
        self.assertEqual(result, 0)
        self.assertIn("DRY RUN", output)
        self.assertIn("-baseline", output)
        self.assertIn("+new UI", output)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"baseline\n")
        self.assertEqual((self.ui / sync.MANIFEST_NAME).read_bytes(), manifest_before)
        self.assertFalse((self.target / "build").exists())

    def test_push_creates_backup_and_updates_only_successful_baselines(self):
        self.tracked()
        self.tracked(HOME)
        self.write(self.ui, ACTIVITY, b"new activity")
        self.write(self.target, HOME, b"original project edited home")
        plan = sync.plan_sync(self.ui, self.target)
        backup = sync.apply_plan(plan)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"new activity")
        self.assertEqual((backup / "files" / ACTIVITY).read_bytes(), b"baseline\n")
        self.assertEqual((self.target / HOME).read_bytes(), b"original project edited home")
        current = self.read_manifest()
        self.assertEqual(current["files"][ACTIVITY], sha(b"new activity"))
        self.assertEqual(current["files"][HOME], sha(b"baseline\n"))
        self.assertEqual(current["description"], "preserved metadata")
        self.assertEqual(json.loads((backup / "ui-sync-manifest.before.json").read_text()), self.manifest)
        self.assertTrue(backup.is_relative_to(self.target / "build/ui-sync-backups"))

    def test_pull_updates_ui_and_backs_up_actual_receiver(self):
        self.tracked()
        self.write(self.target, ACTIVITY, b"original project update")
        plan = sync.plan_sync(self.ui, self.target, "pull")
        backup = sync.apply_plan(plan)
        self.assertEqual((self.ui / ACTIVITY).read_bytes(), b"original project update")
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"original project update")
        self.assertEqual((backup / "files" / ACTIVITY).read_bytes(), b"baseline\n")
        self.assertTrue(backup.is_relative_to(self.ui / "build/ui-sync-backups"))
        self.assertEqual(self.read_manifest()["files"][ACTIVITY], sha(b"original project update"))

    def test_dual_edit_conflict_blocks_entire_batch(self):
        self.tracked()
        self.tracked(HOME)
        self.write(self.ui, ACTIVITY, b"UI edit")
        self.write(self.target, ACTIVITY, b"original edit")
        self.write(self.ui, HOME, b"otherwise safe edit")
        before = (self.ui / sync.MANIFEST_NAME).read_bytes()
        result, output = self.call("--apply")
        self.assertEqual(result, 2)
        self.assertIn("CONFLICT", output)
        self.assertIn("+UI edit", output)
        self.assertEqual((self.target / HOME).read_bytes(), b"baseline\n")
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"original edit")
        self.assertEqual((self.ui / sync.MANIFEST_NAME).read_bytes(), before)
        self.assertFalse((self.target / "build").exists())

    def test_identical_dual_edits_adopt_shared_baseline(self):
        self.tracked()
        for root in (self.ui, self.target):
            self.write(root, ACTIVITY, b"same edit")
        plan = sync.plan_sync(self.ui, self.target)
        self.assertEqual(plan.changes[0].status, "ADOPT")
        sync.apply_plan(plan)
        self.assertEqual(self.read_manifest()["files"][ACTIVITY], sha(b"same edit"))

    def test_new_nested_ui_and_resource_files_are_allowed(self):
        nested = sync.UI_ROOT + "components/NewCard.kt"
        image = sync.RES_ROOT + "drawable/new_image.png"
        self.write(self.ui, nested, b"class NewCard")
        self.write(self.ui, image, b"\x00\xffPNG")
        backup = sync.apply_plan(sync.plan_sync(self.ui, self.target))
        self.assertEqual((self.target / nested).read_bytes(), b"class NewCard")
        self.assertEqual((self.target / image).read_bytes(), b"\x00\xffPNG")
        self.assertEqual(set(json.loads((backup / "backup.json").read_text())["newFiles"]), {nested, image})
        self.assertEqual(set(self.read_manifest()["files"]), {nested, image})

    def test_new_file_collision_is_a_conflict_without_baseline(self):
        self.write(self.ui, RESOURCE, b"UI strings")
        self.write(self.target, RESOURCE, b"original strings")
        self.assertTrue(sync.plan_sync(self.ui, self.target).conflicts)

    def test_destination_only_file_is_preserved_and_untracked(self):
        self.write(self.target, HOME, b"original only")
        plan = sync.plan_sync(self.ui, self.target)
        self.assertEqual(plan.changes[0].status, "DESTINATION_ONLY")
        self.assertIsNone(sync.apply_plan(plan))
        self.assertFalse((self.ui / HOME).exists())
        self.assertEqual(self.read_manifest()["files"], {})

    def test_forbidden_existing_files_are_never_discovered(self):
        forbidden = [
            sync.JAVA_ROOT + "MainViewModel.kt", sync.JAVA_ROOT + "UiModels.kt",
            sync.JAVA_ROOT + "FindingModels.kt", sync.JAVA_ROOT + "ForensicReportCodec.kt",
            sync.JAVA_ROOT + "TrustAttestorNativeBridge.kt", sync.JAVA_ROOT + "NewRootFile.kt",
            sync.JAVA_ROOT + "cloud/CloudClient.kt", "app/src/main/AndroidManifest.xml",
            "app/src/main/cpp/native.cpp", "app/build.gradle.kts",
            "app/src/preview/java/com/lingqing/trustattestor/MainViewModel.kt",
        ]
        for relative in forbidden:
            self.assertFalse(sync.allowed_path(relative), relative)
            self.write(self.ui, relative, b"preview backend")
            self.write(self.target, relative, b"production backend")
        self.assertEqual(sync.plan_sync(self.ui, self.target).changes, [])
        for relative in forbidden:
            self.assertEqual((self.target / relative).read_bytes(), b"production backend")

    def test_manifest_cannot_expand_allowlist_or_escape_root(self):
        forbidden = [sync.JAVA_ROOT + "MainViewModel.kt", "../escape.kt", "/absolute.kt",
                     "app/src/main/res/../../AndroidManifest.xml", "app\\src\\main\\res\\bad.xml",
                     "app/src/main/res//bad.xml", "C:/outside.xml",
                     sync.UI_ROOT + ".. /MainViewModel.kt", sync.UI_ROOT + "folder./MainViewModel.kt",
                     sync.RES_ROOT + "values/file.xml:stream", sync.RES_ROOT + "NUL.xml"]
        for relative in forbidden:
            with self.subTest(relative=relative):
                self.manifest["files"] = {relative: sha(b"old")}
                self.save_manifest()
                with self.assertRaises(sync.SyncError):
                    sync.plan_sync(self.ui, self.target)
        self.assertFalse((self.target / "build").exists())

    def test_case_aliases_are_rejected_before_writing(self):
        self.manifest["files"] = {RESOURCE: sha(b"same"), RESOURCE.upper(): sha(b"same")}
        self.save_manifest()
        with self.assertRaises(sync.SyncError):
            sync.plan_sync(self.ui, self.target)
        # Also exercise two allowed spellings that differ only within the resource directory.
        self.manifest["files"] = {RESOURCE: sha(b"same"), sync.RES_ROOT + "values/Strings.xml": sha(b"same")}
        self.save_manifest()
        with self.assertRaises(sync.SyncError):
            sync.plan_sync(self.ui, self.target)

    def test_tracked_deletions_require_manual_resolution_and_do_not_change_baseline(self):
        for missing in ("source", "destination", "both"):
            with self.subTest(missing=missing):
                self.tracked()
                if missing in {"source", "both"}:
                    (self.ui / ACTIVITY).unlink()
                if missing in {"destination", "both"}:
                    (self.target / ACTIVITY).unlink()
                plan = sync.plan_sync(self.ui, self.target)
                self.assertEqual(plan.changes[0].status, "DELETE_MANUAL")
                self.assertIsNone(sync.apply_plan(plan))
                self.assertEqual((self.ui / ACTIVITY).exists(), missing == "destination")
                self.assertEqual((self.target / ACTIVITY).exists(), missing == "source")
                self.assertEqual(self.read_manifest()["files"][ACTIVITY], sha(b"baseline\n"))

    def test_changes_after_planning_are_not_overwritten(self):
        self.tracked()
        self.write(self.ui, ACTIVITY, b"UI change")
        plan = sync.plan_sync(self.ui, self.target)
        self.write(self.target, ACTIVITY, b"concurrent target edit")
        with self.assertRaises(sync.SyncError):
            sync.apply_plan(plan)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"concurrent target edit")
        self.assertFalse((self.target / "build").exists())

    def test_manual_deletion_does_not_block_safe_update_or_delete_survivor(self):
        self.tracked()
        self.tracked(HOME)
        (self.ui / HOME).unlink()
        self.write(self.ui, ACTIVITY, b"safe update")
        first_backup = sync.apply_plan(sync.plan_sync(self.ui, self.target))
        self.assertEqual((self.target / HOME).read_bytes(), b"baseline\n")
        self.assertEqual(self.read_manifest()["files"][HOME], sha(b"baseline\n"))
        self.write(self.ui, ACTIVITY, b"another safe update")
        second_backup = sync.apply_plan(sync.plan_sync(self.ui, self.target))
        self.assertNotEqual(first_backup, second_backup)
        self.assertEqual((first_backup / "files" / ACTIVITY).read_bytes(), b"baseline\n")
        self.assertEqual((second_backup / "files" / ACTIVITY).read_bytes(), b"safe update")

    def test_manifest_changes_after_planning_are_not_overwritten(self):
        self.tracked()
        self.write(self.ui, ACTIVITY, b"UI change")
        plan = sync.plan_sync(self.ui, self.target)
        self.manifest["description"] = "concurrent metadata change"
        self.save_manifest()
        with self.assertRaises(sync.SyncError):
            sync.apply_plan(plan)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"baseline\n")

    def test_symlink_cannot_redirect_allowed_file(self):
        self.write(self.target, ACTIVITY, b"target")
        outside = self.root / "outside.kt"
        outside.write_bytes(b"outside")
        link = self.ui / ACTIVITY
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is not permitted on this host")
        with self.assertRaises(sync.SyncError):
            sync.plan_sync(self.ui, self.target)
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_reparse_guard_is_used_even_without_host_symlink_permission(self):
        self.tracked()
        real_check = sync._is_link
        forbidden = self.ui / "app/src/main/java"
        with patch.object(sync, "_is_link", side_effect=lambda path: path == forbidden or real_check(path)):
            with self.assertRaises(sync.SyncError):
                sync.plan_sync(self.ui, self.target)

    def test_failed_manifest_write_rolls_back_destination(self):
        self.tracked()
        self.write(self.ui, ACTIVITY, b"UI change")
        self.write(self.ui, HOME, b"new UI file")
        plan = sync.plan_sync(self.ui, self.target)
        real_write = sync._atomic_write

        def fail_commit(root, relative, data):
            if root == self.ui and relative == sync.MANIFEST_NAME:
                raise OSError("simulated commit failure")
            return real_write(root, relative, data)

        with patch.object(sync, "_atomic_write", side_effect=fail_commit):
            with self.assertRaises(sync.SyncError):
                sync.apply_plan(plan)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"baseline\n")
        self.assertFalse((self.target / HOME).exists())
        self.assertEqual(self.read_manifest(), self.manifest)

    def test_target_is_required_and_direction_defaults_to_push(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            sync.main([], ui_root=self.ui)
        self.assertEqual(error.exception.code, 2)
        self.tracked()
        self.write(self.ui, ACTIVITY, b"default push")
        result, _ = self.call("--apply")
        self.assertEqual(result, 0)
        self.assertEqual((self.target / ACTIVITY).read_bytes(), b"default push")

    def test_invalid_manifest_version_and_hash_are_rejected(self):
        self.manifest["version"] = True
        self.save_manifest()
        with self.assertRaises(sync.SyncError):
            sync.plan_sync(self.ui, self.target)
        self.manifest["version"] = 1
        self.manifest["files"] = {ACTIVITY: "not a hash"}
        self.save_manifest()
        with self.assertRaises(sync.SyncError):
            sync.plan_sync(self.ui, self.target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
