"""Small non-executable fixtures; never start the installer or touch system state."""
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_installer", ROOT / "scripts" / "prepare_installer.py")
patcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = patcher
SPEC.loader.exec_module(patcher)


class PatcherTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="xm-skill-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.source = self.root / "source.bin"
        self.output = self.root / "copy.bin"
        self.report = self.root / "report.json"
        self.original = bytes(range(128))
        modified = bytearray(self.original)
        modified[32:38] = b"PATCH!"
        self.modified = bytes(modified)
        self.profile = patcher._Profile(
            "fixture", len(self.original), hashlib.sha256(self.original).hexdigest(),
            hashlib.sha256(self.modified).hexdigest(), 32, self.original[32:38], b"PATCH!", 8, self.original[8:16])
        self.source.write_bytes(self.original)

    def run_operation(self, command="prepare", **kwargs):
        return patcher._run(command, self.source,
                            None if command == "inspect" else self.output,
                            kwargs.pop("report", None), kwargs.pop("profile", self.profile), **kwargs)

    def assert_rejected(self, code, operation):
        with self.assertRaises(patcher.ValidationError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_prepare_verify_and_reuse_preserve_source(self):
        first = self.run_operation(report=self.report)
        self.assertFalse(first["reused_verified_output"])
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.output.read_bytes(), self.modified)
        self.assertEqual(self.output.stat().st_nlink, 1)
        self.assertEqual(self.run_operation("verify")["checks"]["output_sha256"], self.profile.output_sha256)
        self.assertTrue(self.run_operation()["reused_verified_output"])
        self.assertEqual(list(self.root.glob(".xm-prepare-*")), [])

    def test_inspect_never_creates_output(self):
        self.assertTrue(self.run_operation("inspect")["checks"]["source_matches_supported_build"])
        self.assertFalse(self.output.exists())

    def test_unknown_source_is_rejected_before_output(self):
        data = bytearray(self.original)
        data[70] = 0
        self.source.write_bytes(data)
        self.assert_rejected("unsupported_hash", self.run_operation)
        self.assertFalse(self.output.exists())

    def test_unknown_size_is_rejected(self):
        self.source.write_bytes(self.original + b"x")
        self.assert_rejected("unsupported_size", self.run_operation)

    def test_guard_and_branch_are_independent_checks(self):
        self.assert_rejected("guard_mismatch", lambda: self.run_operation(profile=replace(self.profile, guard=b"other")))
        self.assert_rejected("branch_mismatch", lambda: self.run_operation(profile=replace(self.profile, old=b"other!")))

    def test_unexpected_existing_output_never_overwritten(self):
        self.output.write_bytes(self.original)
        self.assert_rejected("difference_mismatch", self.run_operation)
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_extra_changed_byte_is_rejected(self):
        altered = bytearray(self.modified)
        altered[100] ^= 1
        self.output.write_bytes(altered)
        self.assert_rejected("unexpected_change", lambda: self.run_operation("verify"))

    def test_wrong_value_inside_allowed_range_is_rejected(self):
        altered = bytearray(self.modified)
        altered[32] ^= 1
        self.output.write_bytes(altered)
        self.assert_rejected("output_hash_mismatch", lambda: self.run_operation("verify"))

    def test_failed_preparation_never_publishes_copy(self):
        self.assert_rejected("output_hash_mismatch", lambda: self.run_operation(
            profile=replace(self.profile, output_sha256="0" * 64)))
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".xm-prepare-*")), [])

    def test_concurrent_output_appearance_never_overwrites_it(self):
        real_link = os.link

        def create_competing_output(source, destination):
            Path(destination).write_bytes(b"keep this unrelated file")
            return real_link(source, destination)

        with mock.patch.object(patcher.os, "link", side_effect=create_competing_output):
            self.assert_rejected("output_appeared", self.run_operation)
        self.assertEqual(self.output.read_bytes(), b"keep this unrelated file")
        self.assertEqual(list(self.root.glob(".xm-prepare-*")), [])

    def test_source_output_collision(self):
        self.assert_rejected("path_collision", lambda: patcher._run("prepare", self.source, self.source, None, self.profile))
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_report_collisions_are_rejected_before_preparing(self):
        self.assert_rejected("path_collision", lambda: self.run_operation(report=self.source))
        self.assert_rejected("path_collision", lambda: self.run_operation(report=self.output))
        self.assertFalse(self.output.exists())

    def test_existing_report_is_never_overwritten(self):
        self.report.write_text("keep", encoding="utf-8")
        self.assert_rejected("report_exists", lambda: self.run_operation(report=self.report))
        self.assertEqual(self.report.read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.output.exists())

    def test_hardlink_is_rejected(self):
        try:
            os.link(self.source, self.output)
        except OSError as error:
            self.skipTest(f"Hardlink unavailable: {type(error).__name__}")
        self.assert_rejected("hardlinked_file", self.run_operation)

    def test_symlink_is_rejected(self):
        try:
            self.output.symlink_to(self.source)
        except OSError as error:
            self.skipTest(f"Symlink unavailable: {type(error).__name__}")
        self.assert_rejected("linked_path", self.run_operation)

    def test_report_has_no_machine_paths(self):
        self.run_operation(report=self.report)
        text = self.report.read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(self.source.name, text)
        self.assertFalse(json.loads(text)["target_executed"])

    def test_cli_does_not_accept_custom_profiles(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            patcher.main(["inspect", "--source", str(self.source), "--profile", "custom.json"])
        self.assertEqual(caught.exception.code, 2)

    def test_cli_rejects_tiny_fixture_with_pinned_build(self):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = patcher.main(["inspect", "--source", str(self.source)])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(stderr.getvalue())["code"], "unsupported_size")
        self.assertNotIn(str(self.source), stderr.getvalue())

    def test_public_profile_matches_pinned_constants(self):
        public = json.loads((ROOT / "profiles" / "5.8.1.130.json").read_text(encoding="utf-8"))
        pinned = patcher.SUPPORTED
        self.assertEqual(public["version"], pinned.version)
        self.assertEqual(public["size_bytes"], pinned.size)
        self.assertEqual(public["source_sha256"], pinned.source_sha256)
        self.assertEqual(public["prepared_sha256"], pinned.output_sha256)
        self.assertEqual(int(public["patch"]["file_offset"], 16), pinned.offset)
        self.assertEqual(bytes.fromhex(public["patch"]["original_bytes"]), pinned.old)
        self.assertEqual(bytes.fromhex(public["patch"]["prepared_bytes"]), pinned.new)
        self.assertEqual(int(public["patch"]["guard_file_offset"], 16), pinned.guard_offset)
        self.assertEqual(bytes.fromhex(public["patch"]["guard_bytes"]), pinned.guard)


if __name__ == "__main__":
    unittest.main()
