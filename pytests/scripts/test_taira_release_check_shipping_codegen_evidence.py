"""Production feature evidence from required shipping codegen; no Cargo invoked."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/taira_release_check.py"
SPEC = importlib.util.spec_from_file_location("taira_release_check_shipping_codegen", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ShippingCodegenEvidenceTests(unittest.TestCase):
    shipping = ("taira-launcher", "cli-bin", "sorafs-bin", "kagami")
    binaries = ("iroha3d", "iroha", "iroha3d_taira", "sorafs-node", "kagami")

    @staticmethod
    def library(name, features, *, test=False):
        return {"reason": "compiler-artifact", "target": {"name": name, "kind": ["lib"]},
                "profile": {"test": test}, "features": features}

    @staticmethod
    def binary(name):
        return {"reason": "compiler-artifact", "target": {"name": name, "kind": ["bin"]},
                "profile": {"test": False}, "executable": "/warm/" + name,
                "features": ["default"]}

    def events(self):
        return [self.library("iroha_core", ["default", "json"]),
                self.library("iroha_core_zk", ["proofs-halo2", "zk-stark"]),
                self.library("iroha_core_privacy", ["default"]),
                self.library("iroha_torii", ["default", "app_api"]),
                *(self.binary(name) for name in self.binaries)]

    def build(self, events, *, settlement_route_control=False):
        child = MagicMock()
        child.stdout = io.StringIO("".join(json.dumps(event) + "\n" for event in events))
        child.wait.return_value = 0
        process = MagicMock()
        process.__enter__.return_value = child
        with patch.object(gate, "shipping_harnesses", return_value=self.shipping) as shipping, \
             patch.object(gate.subprocess, "Popen", return_value=process) as cargo, \
             patch.object(gate, "isolate_native_artifacts", return_value={}) as isolate, \
             contextlib.redirect_stdout(io.StringIO()):
            result = gate.compile_network_binaries(Path("/frozen"), {"CARGO": "/pinned/cargo"},
                                                    (77,), settlement_route_control=settlement_route_control)
        return result, shipping, cargo, isolate

    def test_required_build_verifies_all_shipping_binaries_and_protected_libraries(self):
        _, shipping, cargo, isolate = self.build(self.events())
        shipping.assert_called_once_with(Path("/frozen"))
        isolate.assert_called_once()
        command = cargo.call_args.args[0]
        self.assertEqual(command[command.index("--manifest-path") - 1], "build")
        self.assertNotIn("check", command)
        self.assertNotIn("--features", command)
        self.assertEqual({command[index + 1] for index, arg in enumerate(command) if arg == "--bin"},
                         set(self.binaries))
        self.assertEqual(cargo.call_args.kwargs["pass_fds"], (77,))

    def test_missing_library_evidence_fails_before_artifact_publication(self):
        for missing in gate.PRODUCTION_LIBRARY_FORBIDDEN_FEATURES:
            events = [event for event in self.events()
                      if event["target"]["name"] != missing]
            with self.subTest(missing=missing), \
                 self.assertRaisesRegex(gate.CheckError, "omitted production library feature evidence: " + missing):
                self.build(events)

    def test_fixture_feature_or_malformed_library_evidence_fails(self):
        for library, feature in gate.PRODUCTION_LIBRARY_FORBIDDEN_FEATURES.items():
            for features in (["default", feature], None, "default", ["default", None]):
                events = self.events()
                next(event for event in events if event["target"]["name"] == library)["features"] = features
                with self.subTest(library=library, features=features), self.assertRaises(gate.CheckError):
                    self.build(events)

    def test_early_feature_failure_drains_large_child_output_before_reporting(self):
        # An early invalid feature must not close Cargo's pipe while it is still
        # producing compiler events. A real child writes well beyond pipe size.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / "producer-finished"
            producer = directory / "producer.py"
            forbidden = self.library("iroha_core", ["iroha-core-tests"])
            producer.write_text(
                "import json\nfrom pathlib import Path\n"
                f"print({json.dumps(json.dumps(forbidden))}, flush=True)\n"
                "for _ in range(256):\n"
                "    print(json.dumps({'reason': 'build-script-executed', 'blob': 'x' * 16384}))\n"
                f"Path({str(marker)!r}).write_text('finished')\n"
            )
            real_popen = subprocess.Popen

            def producing_child(_command, **kwargs):
                return real_popen([sys.executable, "-u", str(producer)], **kwargs)

            with patch.object(gate, "shipping_harnesses", return_value=self.shipping), \
                 patch.object(gate.subprocess, "Popen", side_effect=producing_child), \
                 patch.object(gate, "isolate_native_artifacts") as isolate, \
                 contextlib.redirect_stdout(io.StringIO()), \
                 self.assertRaisesRegex(gate.CheckError, "forbidden fixture feature"):
                gate.compile_network_binaries(Path("/frozen"), {"CARGO": "/not-used"}, ())
            self.assertEqual(marker.read_text(), "finished")
            isolate.assert_not_called()

    def test_nonproduction_library_profile_and_missing_binary_fail(self):
        events = self.events()
        next(event for event in events if event["target"]["name"] == "iroha_core")["profile"]["test"] = True
        with self.assertRaisesRegex(gate.CheckError, "non-production library profile"):
            self.build(events)
        events = [event for event in self.events() if event["target"]["name"] != "kagami"]
        with self.assertRaisesRegex(gate.CheckError, "every required executable artifact"):
            self.build(events)

    def test_explicit_settlement_route_control_fixture_build_is_not_default_shipping_evidence(self):
        event = self.binary("iroha3d")
        _, shipping, cargo, isolate = self.build([event], settlement_route_control=True)
        shipping.assert_not_called()
        isolate.assert_called_once()
        self.assertIn("--features", cargo.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
