"""Focused receipt/parser tests; no C build or native endpoint calls."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name("run_controls.py")
SPEC = importlib.util.spec_from_file_location("native_probe_controls", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sample(case="malloc"):
    """Create a complete explicit endpoint inventory for parser fault injection."""
    phase = 0 if case == "unadmitted" else 1 if case == "terminal" else 2
    value = {"case": case, "control_passed": True, "abi_version": 1,
             "phase_before_seal": phase, "invalid_flags": 0, "transitions": (8, 10, 14)[phase],
             "profile_qualified": False,
             "endpoints": [{"name": n, "phases": [[0, 0, 0] for _ in range(3)]} for n in MODULE.ENDPOINTS]}
    if case in MODULE.ENDPOINTS:
        value["endpoints"][MODULE.ENDPOINTS.index(case)]["phases"][1] = [1, 77, 0]
    elif case == "terminal":
        value["endpoints"][0]["phases"][1] = [1, 77, 0]
    return value


class ControlsTests(unittest.TestCase):
    def test_positive_and_explicit_phase_endings(self):
        for case in (*MODULE.ENDPOINTS, "empty", "unadmitted", "terminal"):
            MODULE.validate_control(case, sample(case))

    def test_required_endpoint_missing_and_false_success_fail(self):
        value = sample()
        value["endpoints"][0]["phases"][1] = [0, 0, 0]
        with self.assertRaises(ValueError):
            MODULE.validate_control("malloc", value)
        for key, bad in [("control_passed", False), ("invalid_flags", 1), ("phase_before_seal", 1),
                         ("transitions", 8), ("abi_version", 2), ("profile_qualified", True)]:
            value = sample()
            value[key] = bad
            with self.assertRaises(ValueError):
                MODULE.validate_control("malloc", value)

    def test_counter_shapes_sentinels_and_scope_controls(self):
        for counts in ([True, 1, 0], [-1, 0, 0], [1 << 64, 0, 0], [1, 0, 2], [1, 0]):
            value = sample()
            value["endpoints"][0]["phases"][1] = counts
            with self.assertRaises(ValueError):
                MODULE.validate_control("malloc", value)
        for invalid in ([], None, {"control_passed": True}):
            with self.assertRaises(ValueError):
                MODULE.validate_control("malloc", invalid)
        outside = sample("outside")
        with self.assertRaises(ValueError):
            MODULE.validate_control("outside", outside)
        outside["endpoints"][0]["phases"][0][0] = 1
        outside["endpoints"][0]["phases"][2][0] = 1
        MODULE.validate_control("outside", outside)
        outside["endpoints"][0]["phases"][1][0] = 1
        with self.assertRaises(ValueError):
            MODULE.validate_control("outside", outside)
        failed = sample("failure")
        failed["endpoints"][MODULE.ENDPOINTS.index("mmap")]["phases"][1] = [1, 0, 1]
        MODULE.validate_control("failure", failed)

    def test_source_inventory_names_only_owned_c_control_files(self):
        inventory = MODULE.source_inventory()
        self.assertEqual(set(inventory), set(MODULE.SOURCE_NAMES))
        self.assertTrue(all(len(value) == 64 for value in inventory.values()))
        self.assertNotIn("driver.rs", inventory)

    def test_failure_receipt_and_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh"
            with patch.dict(MODULE.os.environ, {"DYLD_FAKE": "1"}):
                result = MODULE.run(output)
            self.assertFalse(result["controls_passed"])
            self.assertIn("failure", json.loads((output / "receipt.json").read_text()))
            with self.assertRaises(FileExistsError):
                MODULE.run(output)

    def test_timeout_preserves_partial_output_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh"
            with patch.dict(MODULE.os.environ, {}, clear=True), patch.object(MODULE.sys, "platform", "darwin"):
                with patch.object(MODULE.subprocess, "run", side_effect=subprocess.TimeoutExpired("xcrun", 60, b"partial", b"err")):
                    result = MODULE.run(output)
            self.assertFalse(result["controls_passed"])
            self.assertEqual(result["commands"][0]["stdout"], "partial")
            self.assertIn("TimeoutExpired", result["failure"])


if __name__ == "__main__":
    unittest.main()
