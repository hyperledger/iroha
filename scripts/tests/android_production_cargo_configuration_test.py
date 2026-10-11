"""Production Cargo input custody tests; no compiler or Native artifact is run.

The child is a public command observer/mutator. Successful observation proves
only command routing and before/after guards, never a build or release.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
from unittest import mock

import android_armv7_diagnostic_configuration_test as fixtures

policy, runner, seal = fixtures.policy, fixtures.runner, fixtures.seal


class AndroidProductionCargoConfigurationTests(unittest.TestCase):
    setUp = fixtures.AndroidArmv7DiagnosticConfigurationTests.setUp
    fake_cargo = fixtures.AndroidArmv7DiagnosticConfigurationTests.fake_cargo
    raw_environment_cargo = fixtures.AndroidArmv7DiagnosticConfigurationTests.raw_environment_cargo
    config = fixtures.AndroidArmv7DiagnosticConfigurationTests.config
    seal_environment = fixtures.AndroidArmv7DiagnosticConfigurationTests.seal_environment

    def launch(self, **kwargs):
        return fixtures.AndroidArmv7DiagnosticConfigurationTests.launch(
            self, profile="android-cargo", **kwargs)

    def test_explicit_cli_receipt_has_no_diagnostic_or_release_authority(self):
        argv = [str(Path(sys.executable).resolve()), "-I", "-S",
                str(fixtures.SCRIPTS / "norito_bridge_local_integration.py"),
                "--role", "android-cargo", "--root", str(self.root),
                "--path", str(self.cwd), "--cargo-home", str(self.cache)]
        accepted = subprocess.run(argv, capture_output=True, text=True, check=True)
        value = json.loads(accepted.stdout)
        self.assertEqual(value, policy.android_cargo_configuration(self.root, self.cache, self.cwd))
        self.assertEqual(value["schema"], "iroha.android-cargo-configuration.v1")
        self.assertEqual(value["artifact_scope"], "android-cargo-configuration")
        self.assertFalse(value["release_admitted"])
        self.assertEqual(value["discovery_workspace"]["lock_identity"], None)
        self.assertNotIn(str(self.account / ".cargo/config.toml"), value["configuration_inputs"])
        refused = subprocess.run(argv[:-2], capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(refused.stdout, "")

    def test_each_production_abi_uses_same_root_lock_environment_and_warm_target(self):
        self.raw_environment_cargo()
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            with self.subTest(abi=abi):
                arguments = list(self.arguments); arguments[2] = abi
                result = self.launch(arguments=arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed["argv"], arguments)
                self.assertEqual(observed["cwd"], str(self.cwd))
                self.assertEqual(observed["cache"], str(self.cache))
                self.assertEqual(observed["target"], str(self.target))
                self.assertEqual(set(observed["keys"]), runner.PROFILES["android-cargo"])
        self.assertEqual(self.retained.read_bytes(), b"keep warm target original")

    def test_effective_config_refuses_all_compiler_override_tables_before_child(self):
        for location in (self.cwd / ".cargo/config.toml", self.cache / "config.toml",
                         self.base / ".cargo/config.toml"):
            location.parent.mkdir(exist_ok=True)
            for config in ('[env]\nTEST_ONLY="x"\n', '[build]\njobs=6\n',
                           '[profile.release]\nopt-level=0\n', '[target.armv7-linux-androideabi]\nlinker="fake"\n'):
                with self.subTest(location=location, config=config):
                    location.write_text(config)
                    result = self.launch()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    location.unlink()

    def test_discovery_manifest_same_bytes_replacement_is_detected_after_child(self):
        self.fake_cargo("p=pathlib.Path('Cargo.toml'); b=p.read_bytes(); p.rename('old-manifest'); p.write_bytes(b)")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration or custody changed during invocation", result.stderr)

    def test_discovery_lock_created_by_child_is_refused(self):
        self.fake_cargo("pathlib.Path('Cargo.lock').write_text('version = 4\\n')")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("discovery Cargo.lock must remain absent", result.stderr)

    def test_absent_config_becoming_present_is_refused_after_child(self):
        self.fake_cargo("p=pathlib.Path('.cargo'); p.mkdir(); (p/'config.toml').write_text('[net]\\noffline=true\\n')")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration changed during invocation", result.stderr)

    def test_cache_mode_drift_is_refused_after_child(self):
        self.fake_cargo("pathlib.Path(os.environ['CARGO_HOME']).chmod(0o755)")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode 0700", result.stderr)

    def test_directory_replacement_is_refused_after_child(self):
        self.fake_cargo("p=pathlib.Path.cwd(); p.rename(p.with_name('retained-cwd')); p.mkdir(mode=0o700)")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invocation directory changed", result.stderr)

    def test_root_lock_drift_still_refused_with_external_cwd(self):
        self.fake_cargo("pathlib.Path(" + repr(str(self.root / 'Cargo.lock')) + ").write_text('changed original')")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Android root Cargo.lock changed", result.stderr)

    def test_production_lock_jobs_and_override_refusals_are_unchanged(self):
        variants = [self.arguments + ["--config", "build.jobs=6"],
                    self.arguments + ["--lockfile-path", str(self.cwd / "Cargo.lock")],
                    [value for value in self.arguments if value != "--locked"],
                    self.arguments + ["--jobs=6"]]
        for arguments in variants:
            with self.subTest(arguments=arguments):
                result = self.launch(arguments=arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        for key, value in (("RUSTC_BOOTSTRAP", "1"), ("RUSTFLAGS", "-O"), ("CARGO_BUILD_JOBS", "6")):
            result = self.launch(environment=dict(self.environment, **{key: value}))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_production_metadata_rechecks_discovery_after_actual_command_callback(self):
        tools = [mock.Mock() for _ in range(3)]
        def mutate(*args):
            self.discovery.rename(self.cwd / "retained-Cargo.toml")
            self.discovery.write_bytes(policy.ANDROID_ARMV7_DISCOVERY_MANIFEST)
            return b'{}'
        with mock.patch.dict(os.environ, self.seal_environment(), clear=True), \
             mock.patch.object(seal, "source_seal_tools", return_value=(*tools, Path("/usr/bin/git"))), \
             mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(self.cache)}), \
             mock.patch.object(seal, "run", side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, "Cargo configuration changed during metadata"):
                seal.metadata(self.root, "aarch64-linux-android", self.root / "Cargo.lock")

    def test_production_snapshot_and_verification_bind_selected_configuration(self):
        original = self.base / "source-seal.json"
        with mock.patch.dict(os.environ, self.seal_environment(), clear=True), \
             mock.patch.object(seal, "seal_inputs", return_value=["Cargo.toml", "Cargo.lock"]), \
             mock.patch.object(seal, "source_commit", return_value="1" * 40), \
             mock.patch.object(seal, "status", return_value=""), \
             mock.patch.object(seal, "fingerprint", return_value="2" * 64):
            original.write_bytes(seal.snapshot_bytes(self.root, "android", self.root / "Cargo.lock"))
            seal.verify_snapshot(self.root, "android", original, self.root / "Cargo.lock")
            self.config(self.cwd, '[net]\noffline=true\n')
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                seal.verify_snapshot(self.root, "android", original, self.root / "Cargo.lock")

    def test_gradle_joins_configuration_to_seal_without_changing_production_profile(self):
        text = (fixtures.SCRIPTS.parent / "kotlin/client-android/build.gradle.kts").read_text()
        self.assertIn('(selectedCargoHome == null) == (selectedCargoInvocation == null)', text)
        self.assertIn('val diagnosticConfiguration = if (armv7Diagnostic) cargoConfiguration else null', text)
        self.assertIn('sourceSeal["cargo_configuration"] == JsonSlurper().parse(tools.cargoConfiguration)', text)
        self.assertIn('capturedSeal[configurationField] == JsonSlurper().parse(tools.cargoConfiguration)', text)
        self.assertIn('if (tools.diagnosticConfiguration == null) "android-cargo"', text)
        self.assertEqual(seal.PLATFORM_TARGETS["android"],
                         ("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android"))
        self.assertIn("scripts/norito_bridge_local_integration.py", seal.PLATFORM_ROOT_INPUTS["android"])

    def source_inventory(self):
        return {
            str(path.relative_to(self.root)): (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            )
            for path in [self.root, *self.root.rglob("*")]
        }

    def copy_public_helpers(self):
        destination = self.root / "scripts"
        destination.mkdir()
        for name in ("norito_bridge_local_integration.py", "run_mobile_hermetic_command.py"):
            shutil.copyfile(fixtures.SCRIPTS / name, destination / name)
        return destination

    def gradle_python_launches(self):
        launches = []
        for relative in (
            "kotlin/client-android/build.gradle.kts",
            "gradle/mobile-sdk-external-android-build.settings.gradle.kts",
        ):
            source = (fixtures.SCRIPTS.parent / relative).read_text()
            for match in re.finditer(
                r'(?:candidate|python|tools\.python)\.toString\(\),\s*'
                r'((?:"-[ISB]",\s*)+)', source,
            ):
                launches.append((relative, source.count("\n", 0, match.start()) + 1,
                                 re.findall(r'"(-[ISB])"', match[1])))
        self.assertGreaterEqual(len(launches), 10)
        return launches

    def test_actual_gradle_python_flags_keep_helper_imports_out_of_source(self):
        """Exercise real dynamic imports with each producer command's flags, without Cargo."""
        helpers = self.copy_public_helpers()
        original = self.source_inventory()
        for source, line, flags in self.gradle_python_launches():
            with self.subTest(source=source, line=line):
                result = subprocess.run(
                    [str(Path(sys.executable).resolve()), *flags,
                     str(helpers / "norito_bridge_local_integration.py"),
                     "--role", "android-cargo", "--root", str(self.root),
                     "--path", str(self.cwd), "--cargo-home", str(self.cache)],
                    capture_output=True, text=True, check=True,
                )
                observed = json.loads(result.stdout)
                self.assertEqual(observed["schema"], "iroha.android-cargo-configuration.v1")
                self.assertFalse(observed["release_admitted"])
                self.assertEqual(observed["source_root"], str(self.root))
                self.assertEqual(self.source_inventory(), original)

    def test_isolated_helper_without_no_bytecode_changes_source_even_with_environment_flag(self):
        """The original command reproduces the defect; an environment variable cannot repair it."""
        helpers = self.copy_public_helpers()
        original = self.source_inventory()
        flags = [flag for flag in self.gradle_python_launches()[0][2] if flag != "-B"]
        subprocess.run(
            [str(Path(sys.executable).resolve()), *flags,
             str(helpers / "norito_bridge_local_integration.py"),
             "--role", "android-cargo", "--root", str(self.root),
             "--path", str(self.cwd), "--cargo-home", str(self.cache)],
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, check=True,
        )
        self.assertNotEqual(self.source_inventory(), original)
        self.assertTrue(list((helpers / "__pycache__").glob("run_mobile_hermetic_command.*.pyc")))


if __name__ == "__main__":
    unittest.main()
