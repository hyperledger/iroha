#!/usr/bin/env python3
"""Exercise Release consumer orchestration and fail-closed artifact/runtime gates."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_consumers", ROOT / "scripts/check_swift_release_consumers.py")
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


class ReleaseConsumersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="swift-release-consumers-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.archive = self.base / "published.zip"
        self.archive.write_bytes(b"authenticated archive fixture")
        self.sdk = self.base / "reviewed-sdk"
        self.sdk.mkdir()
        (self.sdk / "Package.resolved").write_text('{"version":3,"pins":[]}\n')
        self.arguments = argparse.Namespace(
            archive=self.archive, archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            sdk_path=self.sdk, work_dir=self.base / "consumers", swift=Path("/selected/swift"),
            archive_scratch=self.base / "warm archive", sdk_scratch=self.base / "warm sdk",
            cache_path=self.base / "swift cache",
        )
        self.environment = patch.dict(os.environ, {"MOBILE_SDK_APPLE_ARTIFACT_DIR": "/reviewed/native"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_runs_both_executables_in_release_and_preserves_warm_caches(self) -> None:
        self.arguments.archive_scratch.mkdir()
        sentinel = self.arguments.archive_scratch / "warm-unit"
        sentinel.write_text("retain")
        with patch.object(OWNER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            result = OWNER.run_consumers(self.arguments)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(run.call_args_list), 2)
        for call, product in zip(run.call_args_list, ("ArchiveConsumer", "IrohaNativeConsumer")):
            command = call.args[0]
            self.assertEqual(command[:2], ["/selected/swift", "run"])
            self.assertEqual(command[-1], product)
            self.assertEqual(command[command.index("--configuration") + 1], "release")
            self.assertIn("--disable-automatic-resolution", command)
            self.assertNotIn("--skip-build", command)
            self.assertEqual(call.kwargs["env"]["IROHA_RELEASE_CONSUMER_SDK_PATH"], str(self.sdk))
            self.assertEqual(call.kwargs["env"]["MOBILE_SDK_APPLE_ARTIFACT_DIR"], "/reviewed/native")
        self.assertEqual(sentinel.read_text(), "retain")
        self.assertEqual((self.arguments.work_dir / "archive/NoritoBridge.xcframework.zip").read_bytes(), self.archive.read_bytes())
        self.assertEqual((self.arguments.work_dir / "sdk/Package.resolved").read_bytes(), (self.sdk / "Package.resolved").read_bytes())
        self.assertEqual(json.loads((self.arguments.work_dir / "report.json").read_text())["status"], "passed")

    def test_rejects_changed_archive_before_invoking_swift(self) -> None:
        self.archive.write_bytes(b"changed after producer authentication")
        with patch.object(OWNER.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "authenticated archive SHA-256"):
                OWNER.run_consumers(self.arguments)
        run.assert_not_called()

    def test_runtime_failure_fails_gate_and_records_failure(self) -> None:
        for exit_codes in ((7,), (0, 9)):
            with self.subTest(exit_codes=exit_codes):
                with patch.object(OWNER.subprocess, "run", side_effect=[subprocess.CompletedProcess([], code) for code in exit_codes]) as run:
                    with self.assertRaisesRegex(RuntimeError, "Release consumer failed"):
                        OWNER.run_consumers(self.arguments)
                self.assertEqual(run.call_count, len(exit_codes))
                report = json.loads((self.arguments.work_dir / "report.json").read_text())
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["consumers"][-1]["exit_code"], exit_codes[-1])

    def test_rejects_local_unit_selection_and_source_tree_output(self) -> None:
        with patch.dict(os.environ, {"MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR": "/local-unit"}):
            with self.assertRaisesRegex(ValueError, "local-unit"):
                OWNER.run_consumers(self.arguments)
        self.arguments.work_dir = self.sdk / "generated"
        with self.assertRaisesRegex(ValueError, "outside the reviewed source tree"):
            OWNER.run_consumers(self.arguments)

    def test_staging_rechecks_bytes_and_preserves_existing_archive_on_failure(self) -> None:
        destination = self.base / "staged.zip"
        destination.write_bytes(b"previous generation")
        self.archive.write_bytes(b"changed during staging")
        with self.assertRaisesRegex(ValueError, "authenticated archive SHA-256"):
            OWNER.stage_archive(self.archive, destination, self.arguments.archive_sha256)
        self.assertEqual(destination.read_bytes(), b"previous generation")

    def test_staging_rejects_symlink_or_hardlink_destinations(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                destination = self.base / kind
                if kind == "symlink":
                    destination.symlink_to(self.archive)
                else:
                    os.link(self.archive, destination)
                with self.assertRaisesRegex(ValueError, "single-link regular"):
                    OWNER.write_file(destination, b"must not replace")
        self.assertEqual(self.archive.read_bytes(), b"authenticated archive fixture")

    def test_workflow_authenticates_then_executes_maintained_consumers(self) -> None:
        workflow = (ROOT / ".github/workflows/mobile_sdk_artifacts.yml").read_text()
        section = workflow.split("      - name: Execute packaged ZIP and public Swift SDK consumers in Release\n", 1)[1].split("      - uses:", 1)[0]
        self.assertLess(section.index("scripts/validate_norito_bridge_archive.py"), section.index("scripts/check_swift_release_consumers.py"))
        self.assertIn('--archive-sha256 "$archive_sha256"', section)
        self.assertNotIn("swift build", section)
        self.assertNotIn("cat >", section)
        sdk_manifest = (OWNER.FIXTURES / "sdk/Package.swift").read_text()
        self.assertIn('.executableTarget(', sdk_manifest)
        self.assertIn('.product(name: "IrohaSwift", package: "IrohaSwift")', sdk_manifest)
        for kind, product in (("sdk", "IrohaNativeConsumer"), ("archive", "ArchiveConsumer")):
            manifest = (OWNER.FIXTURES / kind / "Package.swift").read_text()
            self.assertNotIn("unsafeFlags", manifest)
            source = (OWNER.FIXTURES / kind / "Sources" / product / "main.swift").read_text()
            self.assertIn("all-zero peer key", source)
            self.assertIn("== 29", source)
            self.assertIn("changed message", source)


if __name__ == "__main__":
    unittest.main()
