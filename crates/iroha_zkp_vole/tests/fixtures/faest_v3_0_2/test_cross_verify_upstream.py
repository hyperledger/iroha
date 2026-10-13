"""Independent checks of the cross-verification campaign's test-input grammar."""

import unittest
import json
from pathlib import Path
import tempfile

import cross_verify_upstream as cross


class CampaignInputs(unittest.TestCase):
    def test_completed_cases_survive_rejected_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            first, second = {"case": 1, "signature_hex": "aabb"}, {"case": 2, "signature_hex": "ccdd"}
            cross.append_case(path / "cases.jsonl", first)
            cross.append_case(path / "cases.jsonl", second)
            with self.assertRaisesRegex(RuntimeError, "unqualified report retained"):
                cross.retain_report(path / "report.json", {"records": [first, second]},
                                    {"Cargo.lock": "old", "source.rs": "same"},
                                    {"Cargo.lock": "new", "source.rs": "same"})
            self.assertEqual([json.loads(line) for line in (path / "cases.jsonl").read_text().splitlines()],
                             [first, second])
            report = json.loads((path / "report.json").read_text())
            self.assertEqual(report["records"], [first, second])
            self.assertEqual(report["source_changes"], {"Cargo.lock": {"before": "old", "after": "new"}})
            self.assertFalse(report["source_guard_passed"])
            self.assertFalse(report["security_qualified"])
            self.assertEqual(report["publication_status"], "rejected_source_drift")

    def test_unchanged_inputs_publish_diagnostic_without_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            cross.retain_report(path, {"records": [1]}, {"source": "same"}, {"source": "same"})
            report = json.loads(path.read_text())
            self.assertTrue(report["source_guard_passed"])
            self.assertFalse(report["security_qualified"])
            self.assertEqual(report["publication_status"], "diagnostic_complete")

    def test_added_and_removed_guard_inputs_reject_but_keep_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with self.assertRaises(RuntimeError):
                cross.retain_report(path, {"records": []}, {"removed": "a"}, {"added": "b"})
            changes = json.loads(path.read_text())["source_changes"]
            self.assertEqual(changes, {"added": {"before": None, "after": "b"},
                                       "removed": {"before": "a", "after": None}})

    def test_fresh_public_test_keys_have_all_twelve_admitted_shapes(self):
        expected = [32, 32, 40, 40, 48, 48, 32, 32, 48, 48, 64, 64]
        keys = [cross.fresh_secret_key(name) for name in cross.SETS]
        self.assertEqual([len(key) for key in keys], expected)
        self.assertEqual(len(set(keys)), 12)
        for name, key in zip(cross.SETS, keys):
            key_bytes = int(name.split("_")[-1][:-1]) // 8
            self.assertEqual(key[-key_bytes] & 1, 0)
            self.assertEqual(key, cross.fresh_secret_key(name))
        self.assertNotEqual(cross.material("upstream", 137), cross.material("rust", 137))

    def test_mutations_change_exactly_the_named_input_and_cover_boundaries(self):
        pk, msg, sig = b"key", b"message", bytes(range(20))
        cases = list(cross.negative_cases(pk, msg, sig, [("First", 0, 4), ("Second", 4, 16)]))
        self.assertEqual(len(cases), 9)
        self.assertEqual(cases[0], ("wrong-message", pk, b"lessage", sig))
        self.assertEqual(cases[1], ("wrong-public-key", b"jey", msg, sig))
        for (_, actual_pk, actual_msg, actual_sig), offset in zip(cases[2:4], [0, 4]):
            self.assertEqual((actual_pk, actual_msg), (pk, msg))
            self.assertEqual([a ^ b for a, b in zip(actual_sig, sig)],
                             [int(i == offset) for i in range(20)])
        self.assertEqual([len(case[3]) for case in cases[4:]], [0, 1, 10, 19, 21])
        self.assertEqual(cases[-1][3], sig + b"\0")

    def test_invalid_layout_cannot_silently_drop_a_field(self):
        for layout in ([('zero', 0, 0)], [('outside', 3, 1)], [('negative', -1, 1)]):
            with self.assertRaises(ValueError):
                list(cross.negative_cases(b"key", b"msg", b"sig", layout))


if __name__ == "__main__":
    unittest.main()
