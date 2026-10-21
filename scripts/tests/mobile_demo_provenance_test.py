"""Build-only drift policy tests; no compiler, network, keys or ledger effects."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location(
    "demo_seal_test_owner", Path(__file__).parents[1] / "norito_bridge_source_seal.py"
)
owner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(owner)


class DemoSourceObservations(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.log = self.root / "observations.jsonl"
        self.start = self.root / "source.json"
        self.selected = {
            "schema": owner.SNAPSHOT_SCHEMA, "platform": "android", "targets": ["arm64"],
            "source_commit": "a" * 40, "source_fingerprint_sha256": "b" * 64,
            "source_tree_dirty": False, "source_status": "",
        }
        self.current = {**self.selected, "source_commit": "c" * 40,
                        "source_fingerprint_sha256": "d" * 64}
        self.start.write_text(json.dumps(self.selected))

    def verify(self):
        with patch.object(owner, "snapshot_bytes", return_value=json.dumps(self.current).encode()):
            owner.verify_snapshot(self.root, "android", self.start, self.root / "Cargo.lock")

    def test_default_refuses_changed_source(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                self.verify()
        self.assertFalse(self.log.exists())

    def test_demo_records_both_observations_without_relabeling(self):
        original = self.start.read_bytes()
        with patch.dict(os.environ, MOBILE_SDK_DEMO_SOURCE_DRIFT_LOG=str(self.log)):
            self.verify()
        row = json.loads(self.log.read_text())
        self.assertEqual(row["selected"], self.selected)
        self.assertEqual(row["observed"], self.current)
        self.assertEqual(self.start.read_bytes(), original)
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_demo_still_refuses_changed_platform_and_config(self):
        for field, value in (("platform", "apple"), ("targets", ["other"]),
                             ("cargo_configuration", {"custody": "other"})):
            with self.subTest(field=field):
                self.current = {**self.selected, field: value}
                with patch.dict(os.environ, MOBILE_SDK_DEMO_SOURCE_DRIFT_LOG=str(self.log)):
                    with self.assertRaisesRegex(RuntimeError, "structure"):
                        self.verify()
        self.assertFalse(self.log.exists())

    def test_unwritable_or_symbolic_evidence_cannot_silently_pass(self):
        target = self.root / "target"
        target.write_text("retained")
        self.log.symlink_to(target)
        with patch.dict(os.environ, MOBILE_SDK_DEMO_SOURCE_DRIFT_LOG=str(self.log)):
            with self.assertRaises(OSError):
                self.verify()
        self.assertEqual(target.read_text(), "retained")

    def test_actual_apple_guard_records_drift_and_keeps_strict_default(self):
        scripts = Path(__file__).parents[1]
        source = (scripts / "build_norito_xcframework.sh").read_text()
        function = source.split("assert_bridge_source_seal() {", 1)[1].split(
            '\nif [[ "${NORITO_BRIDGE_SOURCE_SEAL_TEST_ONLY', 1
        )[0]
        program = """set -eu
assert_selected_cargo_lock() { :; }
run_source_git() { printf '%s\\n' observed; }
bridge_source_status() { printf '%s\\n' changed; }
bridge_source_fingerprint() { printf '%s\\n' changed; }
run_isolated_python() { "$PYTHON_TEST_OWNER" -I -S -B "$@"; }
SOURCE_COMMIT_START=selected
SOURCE_STATUS_START=original
SOURCE_FINGERPRINT_START=original
assert_bridge_source_seal() {""" + function + '\nassert_bridge_source_seal "test closure"\n'
        environment = {
            **os.environ, "SOURCE_SEAL_SCRIPT": str(scripts / "norito_bridge_source_seal.py"),
            "PYTHON_TEST_OWNER": sys.executable, "MOBILE_SDK_DEMO_SOURCE_DRIFT_LOG": "",
            "ROOT_DIR": str(self.root),
        }
        strict = subprocess.run(["/bin/bash", "-c", program], env=environment, capture_output=True)
        self.assertEqual(strict.returncode, 1)
        self.assertIn(b"source changed during", strict.stderr)
        environment["MOBILE_SDK_DEMO_SOURCE_DRIFT_LOG"] = str(self.log)
        demo = subprocess.run(["/bin/bash", "-c", program], env=environment, capture_output=True)
        self.assertEqual(demo.returncode, 0, demo.stderr)
        row = json.loads(self.log.read_text())
        self.assertEqual(row["selected"]["commit"], "selected")
        self.assertEqual(row["observed"]["commit"], "observed")


if __name__ == "__main__":
    unittest.main()
