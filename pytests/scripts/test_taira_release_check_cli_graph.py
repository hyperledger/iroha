"""Offline CLI test graph and immutable lifetime checks; no Cargo or live inputs."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import MagicMock, patch

import test_taira_release_check as existing
from taira_fake_libtest import executable

gate = existing.gate


class CombinedCliGraphTests(unittest.TestCase):
    env = existing.NativeTestBatchBuildTests.env
    artifact = staticmethod(existing.NativeTestBatchBuildTests.artifact)
    process = existing.NativeTestBatchBuildTests.process

    def test_fifteen_targets_share_one_graph_with_only_required_fixture_feature(self):
        names = ("config", "config-unit", "proof", "proof-flows", "crypto", "p2p", "core", "test-network", "client", "torii-unit", "torii", "torii-lifecycle", "daemon", "network", "cli")
        lines = "".join(self.artifact(name) for name in reversed(names))
        lines += self.artifact("cli")
        with patch.object(gate.subprocess, "Popen", return_value=self.process(lines)) as spawn, \
             patch.object(gate, "isolate_native_artifacts", side_effect=lambda root, env, rows: rows) as isolate, \
             contextlib.redirect_stdout(io.StringIO()):
            rows = gate.compile_test_harnesses(Path("/frozen"), self.env, harnesses=names, lock_fds=(77, 88))
        self.assertEqual(set(rows), set(names))
        self.assertNotEqual(rows["cli"]["executable"], rows["client"]["executable"])
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(isolate.call_count, 1)
        self.assertEqual(spawn.call_args.args[0], [
            "/fixed/cargo", "--config", "/frozen/.cargo/config.toml", "test",
            "--manifest-path", "/frozen/Cargo.toml", "--locked", "--offline",
            "-p", "iroha_config", "-p", "fastpq_prover", "-p", "iroha_crypto", "-p", "iroha_p2p", "-p", "iroha_core",
            "-p", "iroha_test_network", "-p", "iroha", "-p", "iroha_torii",
            "-p", "irohad_lib", "-p", "iroha_cli_lib", "--test", "taira_config_contracts", "--lib", "--test", "fastpq_integration", "--test", "taira_app_contracts",
            "--test", "torii_nexus_sorafs", "--test", "taira_consensus_contracts",
            "--features", "iroha_torii/test-fixtures",
            "--no-run", "--message-format=json-render-diagnostics",
        ])
        self.assertEqual(spawn.call_args.kwargs["pass_fds"], (77, 88))
        self.assertIs(spawn.call_args.kwargs["env"], self.env)

    def test_malformed_binary_selection_fails_before_cargo(self):
        for arguments in (["-p", "iroha_cli", "--bins"],
                          ["-p", "iroha_cli", "--bin", "nonexistent_cli_binary"],
                          ["-p", "iroha_cli", "--bin", "iroha", "--all-targets"]):
            with self.subTest(arguments=arguments), \
                 patch.dict(gate.HARNESS_TARGETS, {"cli": ("native CLI", "iroha", "bin", arguments)}), \
                 patch.object(gate.subprocess, "Popen") as spawn:
                with self.assertRaises(gate.CheckError):
                    gate.compile_test_harnesses(Path("/frozen"), self.env, harnesses=("client", "cli"))
            spawn.assert_not_called()

    def test_cli_selection_requires_bin_test_and_does_not_accept_sdk_or_shipping_cli(self):
        sdk = self.artifact("client")
        cli = json.loads(self.artifact("cli"))
        for replacement in (
            cli | {"profile": {"test": False}},
            cli | {"profile": {"test": 1}},
            cli | {"target": {"name": "iroha_cli", "kind": ["bin"]}},
            cli | {"target": {"name": "nonexistent_cli_binary", "kind": ["bin"]}},
            cli | {"executable": None},
        ):
            with self.subTest(replacement=replacement), \
                 patch.object(gate.subprocess, "Popen", return_value=self.process(sdk + json.dumps(replacement))), \
                 patch.object(gate, "isolate_native_artifacts") as isolate, \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(gate.CheckError):
                    gate.compile_test_harnesses(Path("/frozen"), self.env, harnesses=("client", "cli"))
            isolate.assert_not_called()

    def test_shared_sdk_cli_executable_or_conflicting_cli_metadata_is_rejected(self):
        cli = json.loads(self.artifact("cli"))
        conflicts = (
            self.artifact("client", "/warm/shared") + self.artifact("cli", "/warm/shared"),
            self.artifact("client") + self.artifact("cli") + json.dumps(cli | {"profile": {"test": True, "opt_level": "1"}}),
            self.artifact("client") + self.artifact("cli") + self.artifact("cli", "/warm/second-cli"),
        )
        for lines in conflicts:
            with self.subTest(lines=lines), \
                 patch.object(gate.subprocess, "Popen", return_value=self.process(lines)), \
                 patch.object(gate, "isolate_native_artifacts") as isolate, \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(gate.CheckError):
                    gate.compile_test_harnesses(Path("/frozen"), self.env, harnesses=("client", "cli"))
            isolate.assert_not_called()

    def test_missing_cli_or_late_cargo_failure_cannot_qualify_complete_other_graph(self):
        for lines, code in ((self.artifact("client"), 0),
                            (self.artifact("client") + self.artifact("cli"), 101)):
            with self.subTest(code=code), \
                 patch.object(gate.subprocess, "Popen", return_value=self.process(lines, code)), \
                 patch.object(gate, "isolate_native_artifacts") as isolate, \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(gate.CheckError):
                    gate.compile_test_harnesses(Path("/frozen"), self.env, harnesses=("client", "cli"))
            isolate.assert_not_called()


class CliCopyLifetimeTests(unittest.TestCase):
    def setUp(self):
        existing.NativeArtifactIsolationTests.setUp(self)
        # These tests copy only tiny fixtures and do not test the disk reserve.
        # The existing helper suite exercises low-disk rejection separately.
        capacity = patch.object(gate.shutil, "disk_usage", return_value=MagicMock(free=1024**4))
        capacity.start()
        self.addCleanup(capacity.stop)

    make_fixture_writable = existing.NativeArtifactIsolationTests.make_fixture_writable
    artifact = existing.NativeArtifactIsolationTests.artifact
    isolate = existing.NativeArtifactIsolationTests.isolate
    assert_profile_locked = existing.NativeArtifactIsolationTests.assert_profile_locked
    assert_profile_unlocked = existing.NativeArtifactIsolationTests.assert_profile_unlocked

    def test_same_name_sdk_library_and_cli_test_bin_require_their_exact_manifest(self):
        sdk, sdk_row, _ = self.artifact("client", b"sdk fixture bytes")
        cli, cli_row, _ = self.artifact("cli", b"cli fixture bytes")
        with self.isolate({"client": sdk_row, "cli": cli_row}) as copies:
            self.assertNotEqual(copies["client"], copies["cli"])
            self.assertEqual(Path(copies["client"]).read_bytes(), b"sdk fixture bytes")
            self.assertEqual(Path(copies["cli"]).read_bytes(), b"cli fixture bytes")
            self.assert_profile_unlocked()
        for changed in (dict(cli_row, manifest_path=sdk_row["manifest_path"]),
                        dict(cli_row, manifest_path=str(self.source / "foreign/Cargo.toml")),
                        dict(cli_row, manifest_path=None)):
            with self.subTest(manifest=changed["manifest_path"]):
                with self.assertRaisesRegex(gate.CheckError, "manifest differs"):
                    self.isolate({"client": sdk_row, "cli": changed})
        self.assertTrue(sdk.exists())
        self.assertTrue(cli.exists())

    def run_sequence(self, *, network=True, failure=None):
        fd = os.open(self.directory / "custody.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        locks = (fd,)
        executed = self.directory / "cli-executed"
        payload = executable(("cli_fixture",), executed,
                             failed=("cli_fixture",) if failure == "cli" else ()).encode()
        raw_cli, cli_row, _ = self.artifact("cli", payload)
        rows = {"cli": cli_row}
        if network:
            rows["network"] = self.artifact("network")[1]
        copies = self.isolate(rows)
        copy = Path(copies["cli"])
        original_production = self.artifact("iroha", b"shipping cli retained")[0]
        original_node = self.artifact("iroha3d", b"shipping node retained")[0]
        order = []
        runs = []
        preflight_inventories = []
        real_run_stages = gate.run_stages
        fixture_preflight = gate.preflight_native_test_inventories

        def preflight(*args, **kwargs):
            self.assertEqual(order, ["combined-build"])
            self.assertIs(args[0], copies)
            inventory = fixture_preflight(*args, **kwargs)
            expected = {str(copy): "cli_fixture: test\n"}
            if network:
                expected[copies["network"]] = "".join(
                    name + ": test\n" for _, names in gate.NETWORK_STAGES for name in names
                )
            self.assertEqual(inventory, expected)
            preflight_inventories.append(inventory)
            return inventory

        def run_cli(harness, *args, **kwargs):
            self.assertEqual(harness, str(copy))
            self.assertTrue(copy.exists())
            if network:
                self.assertTrue(Path(copies["network"]).exists(), "network copy remains frozen until unit checks pass")
                self.assertEqual(order, ["combined-build"])
            else:
                self.assertEqual(order, ["combined-build"])
            # Source Cargo outputs may already have changed; use only the copy.
            raw_cli.write_bytes(b"replacement from unrelated later Cargo graph")
            runs.append(harness)
            self.assertEqual(len(preflight_inventories), 1)
            self.assertEqual(kwargs, {"batch": True, "inventories": preflight_inventories[0]})
            self.assertIs(kwargs["inventories"], preflight_inventories[0])
            return real_run_stages(harness, *args, **kwargs)

        def build(*args, **kwargs):
            self.assertEqual(kwargs, {"harnesses": (("network", "cli") if network else ("cli",)), "lock_fds": locks})
            self.assertEqual(order, [])
            order.append("combined-build")
            return copies

        def four_peer(*args, **kwargs):
            self.assertEqual(kwargs, {"harness": copies["network"], "stages": gate.NETWORK_STAGES,
                                      "inventories": preflight_inventories[0]})
            self.assertIs(kwargs["inventories"], preflight_inventories[0])
            order.append("production-build-and-four-peer")
            self.assertFalse(copy.exists(), "release completed CLI copy before production graph")
            self.assertTrue(executed.exists())
            self.assertEqual(stat.S_IMODE(Path(copies["network"]).stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE(copy.parent.stat().st_mode), 0o500)
            # A later Cargo graph can replace the original output; selected
            # execution must remain on the completed immutable CLI test copy.
            raw_cli.write_bytes(b"replacement from unrelated later Cargo graph")
            if failure == "network":
                raise gate.CheckError("synthetic four-peer failure")

        with contextlib.ExitStack() as stack:
            existing.isolate_stage_fixture(stack, keep=("NETWORK_STAGES",))
            stack.enter_context(patch.object(gate, "NETWORK_STAGES", gate.NETWORK_STAGES if network else ()))
            stack.enter_context(patch.object(gate, "STAGES", (("CLI fixture", ("cli_fixture",)),)))
            for function in ("run_lifecycle_source_checks", "run_config_checks",
                             "require_network_fixture_capacity", "check_test_harnesses"):
                stack.enter_context(patch.object(gate, function))
            batch = stack.enter_context(patch.object(gate, "compile_test_harnesses", side_effect=build))
            later_compile = stack.enter_context(patch.object(gate, "compile_harness", side_effect=AssertionError("no separate CLI compilation")))
            peers = stack.enter_context(patch.object(gate, "run_network_checks", side_effect=four_peer))
            inventory_check = stack.enter_context(patch.object(gate, "preflight_native_test_inventories", side_effect=preflight))
            relist = stack.enter_context(patch.object(gate, "native_test_listing", side_effect=AssertionError("reuse the exact preflight inventory")))
            stack.enter_context(patch.object(gate, "run_stages", side_effect=run_cli))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            stack.enter_context(self.assertRaises(gate.CheckError) if failure else contextlib.nullcontext())
            gate.run_checks(self.source, qualification_scope="full", environment=self.env | {"CARGO_HOME": "/isolated"}, source_commit="a" * 40, lock_fds=locks)
        self.assertEqual(batch.call_count, 1)
        self.assertEqual(inventory_check.call_count, 1)
        relist.assert_not_called()
        later_compile.assert_not_called()
        self.assertEqual(peers.call_count, int(network and failure != "cli"))
        self.assertEqual(runs, [str(copy)])
        self.assertFalse(copy.exists())
        self.assertIsNone(copies.directory_fd)
        if network:
            self.assertFalse(Path(copies["network"]).exists())
            self.assertEqual(raw_cli.read_bytes(), b"replacement from unrelated later Cargo graph")
        self.assertEqual(original_production.read_bytes(), b"shipping cli retained")
        self.assertEqual(original_node.read_bytes(), b"shipping node retained")
        # Only the immutable copy executed; the replaced Cargo output never ran.
        self.assertEqual(executed.read_text(), "cli_fixture\n")

    def test_cli_copy_executes_once_before_production_build_and_four_peer(self):
        self.run_sequence()

    def test_network_failure_retains_completed_cli_result_and_releases_copies(self):
        self.run_sequence(failure="network")

    def test_cli_failure_releases_test_copies_without_touching_shipping_snapshots(self):
        self.run_sequence(failure="cli")

    def test_cli_only_gate_still_uses_combined_builder(self):
        self.run_sequence(network=False)


if __name__ == "__main__":
    unittest.main()
