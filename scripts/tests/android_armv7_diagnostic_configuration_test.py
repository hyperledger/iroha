"""Private diagnostic config/cwd/cache custody and unchanged production boundaries.

Only synthetic public configuration and fake Cargo executables are used. These
cases never compile native code or load/install/promote a library.

Prerequisites: Python 3.11+ and executable /usr/bin/perl with its core Cwd and
JSON::PP modules. The exact child-environment observer uses Perl because macOS
Python startup can insert __CF_USER_TEXT_ENCODING before Python code runs.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).parents[1]


def module(name: str, filename: str):
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert specification is not None and specification.loader is not None
    value = importlib.util.module_from_spec(specification)
    sys.modules[name] = value
    specification.loader.exec_module(value)
    return value


policy = module("tested_android_diagnostic_policy", "norito_bridge_local_integration.py")
runner = module("tested_android_diagnostic_runner", "run_mobile_hermetic_command.py")
seal = module("tested_android_diagnostic_seal", "norito_bridge_source_seal.py")


class AndroidArmv7DiagnosticConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.account = self.base / "account"
        self.root = self.account / "source"
        self.root.mkdir(parents=True)
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        (self.root / "Cargo.lock").write_text("# public synthetic locked original\n")
        self.cwd = self.base / "private-cwd"
        self.cache = self.base / "private-cache"
        self.cwd.mkdir(mode=0o700)
        self.cache.mkdir(mode=0o700)
        self.discovery = self.cwd / "Cargo.toml"
        self.discovery.write_bytes(b"[workspace]\nmembers = []\n")
        self.target = self.root / "dist/norito-bridge-android-local/gradle-build/iroha_kotlin_sdk/client-android/native/cargo-target/armv7-diagnostic"
        self.target.mkdir(parents=True)
        self.retained = self.target / "retained-compilation"
        self.retained.write_bytes(b"keep warm target original")
        self.staging = self.target.parent.parent / "cargo-ndk-staging/armv7-diagnostic/armeabi-v7a"
        self.staging.mkdir(parents=True)
        self.tools = self.base / "tools"
        self.tools.mkdir()
        for name in ("cargo", "rustc", "rustdoc"):
            tool = self.tools / name
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o755)
        self.environment = {
            "ANDROID_NDK_HOME": str(self.base / "ndk"),
            "ANDROID_NDK_ROOT": str(self.base / "ndk"),
            "CARGO": str(self.tools / "cargo"), "CARGO_BUILD_JOBS": "1",
            "CARGO_HOME": str(self.cache), "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(self.target),
            "HOME": str(self.account), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            runner.WALLET_RUNTIME_AUTHORITY_INPUT: "bpng-taira-v7",
            runner.WALLET_RUNTIME_TRUST_INPUT: "3" * 64,
            "NORITO_SKIP_BINDINGS_SYNC": "1", "PATH": "/usr/bin:/bin",
            "RUSTC": str(self.tools / "rustc"), "RUSTDOC": str(self.tools / "rustdoc"),
            "RUSTUP_HOME": str(self.account / ".rustup"), "TMPDIR": str(self.base),
        }
        self.arguments = ["ndk", "-t", "armeabi-v7a", "-o", str(self.staging),
                          "build", "--locked", "--offline", "--jobs", "1",
                          "--manifest-path", str(self.root / "Cargo.toml"), "--release",
                          "-p", "connect_norito_bridge", "--features", "privacy-production-enabled"]
        self.fake_cargo()

    def fake_cargo(self, mutation: str = ""):
        program = ("#!" + str(Path(sys.executable).resolve()) + "\n"
                   "import json,os,pathlib,sys\n"
                   "print(json.dumps({'cwd':os.getcwd(),'cache':os.environ['CARGO_HOME'],"
                   "'target':os.environ['CARGO_TARGET_DIR'],'argv':sys.argv[1:],"
                   "'keys':sorted(os.environ)}))\n" + mutation + "\n")
        (self.tools / "cargo").write_text(program)
        (self.tools / "cargo").chmod(0o755)

    def raw_environment_cargo(self):
        self.assertTrue(os.access("/usr/bin/perl", os.X_OK),
                        "Exact child-environment observer requires executable /usr/bin/perl")
        program = ("#!/usr/bin/perl -T\n"
                   "use strict; use warnings; use Cwd qw(getcwd); use JSON::PP qw(encode_json);\n"
                   "print encode_json({cwd => getcwd(), cache => $ENV{CARGO_HOME}, "
                   "target => $ENV{CARGO_TARGET_DIR}, argv => \\@ARGV, "
                   "keys => [sort keys %ENV]});\n")
        (self.tools / "cargo").write_text(program)
        (self.tools / "cargo").chmod(0o755)

    def launch(self, *, profile="android-armv7-diagnostic-cargo", cwd=True,
               arguments=None, environment=None):
        command = [str(Path(sys.executable).resolve()), "-I", "-S",
                   str(SCRIPTS / "run_mobile_hermetic_command.py"), "--profile", profile]
        if cwd:
            command += ["--working-directory", str(self.cwd)]
        for name, value in (self.environment if environment is None else environment).items():
            command += ["--set", name + "=" + value]
        command += ["--", str(self.tools / "cargo"), *(self.arguments if arguments is None else arguments)]
        return subprocess.run(command, cwd=self.root, text=True, capture_output=True, check=False)

    def config(self, directory, text):
        path = directory / ".cargo/config.toml"
        path.parent.mkdir(exist_ok=True)
        path.write_text(text)
        return path

    def observe(self):
        return policy.android_armv7_diagnostic_configuration(
            self.root, self.cache, self.cwd, local_integration=True)

    def test_actual_child_uses_private_cwd_cache_and_retains_same_warm_target(self):
        self.raw_environment_cargo()
        # The account config continues to be an invalid production compiler owner.
        global_config = self.config(self.account, '[build]\nrustc-wrapper = "TEST ONLY wrapper"\n[env]\nTEST_ONLY = "synthetic"\n')
        original = global_config.read_bytes()
        accepted = self.launch()
        self.assertEqual(accepted.returncode, 0,
                         "Child observer requires Perl core Cwd and JSON::PP modules: " + accepted.stderr)
        observed = json.loads(accepted.stdout)
        self.assertEqual(observed["cwd"], str(self.cwd))
        self.assertEqual(observed["cache"], str(self.cache))
        self.assertEqual(observed["target"], str(self.target))
        self.assertEqual(observed["argv"], self.arguments)
        self.assertEqual(set(observed["keys"]),
                         runner.PROFILES["android-armv7-diagnostic-cargo"])
        self.assertEqual(global_config.read_bytes(), original)
        self.assertEqual(self.retained.read_bytes(), b"keep warm target original")
        rejected = self.launch(environment=dict(self.environment, CARGO_TARGET_DIR=str(self.cwd)))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("require the fixed warm Cargo target", rejected.stderr)
        self.assertEqual(self.retained.read_bytes(), b"keep warm target original")

    def test_production_explicit_isolation_preserves_profile_and_default_config_refusal(self):
        global_config = self.config(self.account, '[env]\nTEST_ONLY = "synthetic"\n')
        accepted = self.launch(profile="android-cargo")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        observed = json.loads(accepted.stdout)
        self.assertEqual(observed["cwd"], str(self.cwd))
        self.assertEqual(observed["argv"], self.arguments)
        self.assertEqual(global_config.read_text(), '[env]\nTEST_ONLY = "synthetic"\n')
        rejected = self.launch(profile="android-cargo", cwd=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("configuration forbids env", rejected.stderr)

    def test_diagnostic_requires_local_scope_explicit_existing_cache_and_cwd(self):
        with self.assertRaisesRegex(ValueError, "requires local integration"):
            policy.android_armv7_diagnostic_configuration(self.root, self.cache, self.cwd,
                                                        local_integration=False)
        rejected = self.launch(cwd=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("require an authenticated external working directory", rejected.stderr)
        for selected in (self.base / "missing-cache", self.root / "cache"):
            with self.subTest(cache=selected):
                if selected.parent == self.root:
                    selected.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    policy.android_armv7_diagnostic_configuration(self.root, selected, self.cwd,
                                                                local_integration=True)
        self.assertFalse((self.base / "missing-cache").exists())

    def test_private_cache_and_cwd_custody_reject_modes_links_overlap_and_source(self):
        for chosen, kind in ((self.cache, "cache"), (self.cwd, "cwd")):
            with self.subTest(kind=kind):
                chosen.chmod(0o755)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.observe()
                chosen.chmod(0o700)
                moved = chosen.with_name(chosen.name + "-original")
                chosen.rename(moved)
                chosen.symlink_to(moved, target_is_directory=True)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.observe()
                chosen.unlink()
                moved.rename(chosen)
        with self.assertRaisesRegex(ValueError, "must be disjoint"):
            policy.android_armv7_diagnostic_configuration(self.root, self.cache, self.cache,
                                                        local_integration=True)
        with self.assertRaisesRegex(RuntimeError, "disjoint from source"):
            policy.android_armv7_diagnostic_configuration(self.root, self.cache, self.root,
                                                        local_integration=True)
        self.account.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "disjoint from source"):
            policy.android_armv7_diagnostic_configuration(self.root, self.account, self.cwd,
                                                        local_integration=True)
        with mock.patch.object(policy.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned writable"):
                self.observe()

    def test_configuration_inventory_binds_originals_and_absent_ancestor_candidates(self):
        path = self.config(self.cwd, '[net]\noffline = true\n')
        original = self.observe()
        self.assertFalse(original["release_admitted"])
        self.assertEqual(original["artifact_scope"], "android-local-diagnostic")
        self.assertIn(str(self.base / ".cargo/config"), original["configuration_inputs"])
        self.assertIsNone(original["configuration_inputs"][str(self.base / ".cargo/config")])
        self.assertEqual(original, self.observe())
        path.write_text('[net]\noffline = true\n# changed original\n')
        self.assertNotEqual(original, self.observe())

    def test_discovery_workspace_receipt_binds_bytes_identity_and_lock_absence(self):
        original = self.observe()
        discovery = original["discovery_workspace"]
        self.assertEqual(discovery["manifest_path"], str(self.discovery))
        self.assertEqual(discovery["manifest_sha256"],
                         "01682718dc81bf6ca83b17e5a4b7fd755dc44c08357e0c817c20d66e5f474a78")
        self.assertEqual(discovery["lock_path"], str(self.cwd / "Cargo.lock"))
        self.assertIsNone(discovery["lock_identity"])
        # An identical replacement remains a different authenticated original.
        replacement = self.base / "replacement.toml"
        replacement.write_bytes(self.discovery.read_bytes())
        timestamp = self.discovery.stat().st_mtime_ns
        os.utime(replacement, ns=(timestamp, timestamp))
        replacement.replace(self.discovery)
        self.assertNotEqual(original, self.observe())

    def test_discovery_workspace_refuses_missing_or_buildable_manifests(self):
        variants = [None, b"[workspace]\nmembers=['/some/source']\n",
                    b"[package]\nname='injected'\nversion='0.1.0'\n",
                    b"[workspace]\nmembers=[]\n[workspace.dependencies]\nother='1'\n",
                    b"[workspace]\nmembers = []\n# additional content\n"]
        for contents in variants:
            with self.subTest(contents=contents):
                if contents is None:
                    self.discovery.unlink()
                else:
                    self.discovery.write_bytes(contents)
                rejected = self.launch()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn("diagnostic discovery", rejected.stderr)
                self.discovery.write_bytes(b"[workspace]\nmembers = []\n")

    def test_discovery_manifest_refuses_links_nonfiles_and_writable_or_foreign_custody(self):
        original = self.base / "original.toml"
        self.discovery.rename(original)
        self.discovery.symlink_to(original)
        with self.assertRaises((ValueError, OSError)):
            self.observe()
        self.discovery.unlink()
        os.link(original, self.discovery)
        with self.assertRaisesRegex(ValueError, "non-linked bounded regular file"):
            self.observe()
        self.discovery.unlink()
        self.discovery.mkdir()
        with self.assertRaisesRegex(ValueError, "bounded regular file"):
            self.observe()
        self.discovery.rmdir()
        original.rename(self.discovery)
        self.discovery.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "owned non-linked bounded regular file"):
            self.observe()
        self.discovery.chmod(0o600)
        with mock.patch.object(policy.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned non-linked bounded regular file"):
                policy.android_armv7_discovery_workspace(self.cwd)

    def test_discovery_lock_refuses_file_and_dangling_link_before_child(self):
        lock = self.cwd / "Cargo.lock"
        for symbolic in (False, True):
            with self.subTest(symbolic=symbolic):
                if symbolic:
                    lock.symlink_to(self.base / "missing-lock")
                else:
                    lock.write_text("# no packages\n")
                rejected = self.launch()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn("discovery Cargo.lock must remain absent", rejected.stderr)
                lock.unlink()

    def test_discovery_manifest_and_lock_are_rechecked_after_real_child(self):
        chosen = repr(str(self.discovery))
        replacement = repr(str(self.base / "replacement.toml"))
        lock = self.cwd / "Cargo.lock"
        mutations = ["pathlib.Path(" + chosen + ").unlink()",
                     "pathlib.Path(" + chosen + ").write_bytes(b'[package]\\n')",
                     "p=pathlib.Path(" + replacement + "); p.write_bytes(pathlib.Path(" + chosen + ").read_bytes()); p.replace(" + chosen + ")",
                     "pathlib.Path(" + repr(str(lock)) + ").write_text('# injected lock\\n')"]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.fake_cargo(mutation)
                rejected = self.launch()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("diagnostic", rejected.stderr)
                self.discovery.write_bytes(b"[workspace]\nmembers = []\n")
                lock.unlink(missing_ok=True)

    def test_discovery_workspace_is_rechecked_during_source_authentication(self):
        def fingerprint(*args):
            (self.cwd / "Cargo.lock").write_text("# changed during seal\n")
            return "2" * 64
        with mock.patch.dict(os.environ, self.seal_environment()), \
             mock.patch.object(seal, "seal_inputs", return_value=["Cargo.toml", "Cargo.lock"]), \
             mock.patch.object(seal, "source_commit", return_value="1" * 40), \
             mock.patch.object(seal, "status", return_value=""), \
             mock.patch.object(seal, "fingerprint", side_effect=fingerprint):
            with self.assertRaisesRegex(ValueError, "discovery Cargo.lock must remain absent"):
                seal.snapshot(self.root, "android-armv7-diagnostic", self.root / "Cargo.lock")

    def test_each_actual_ancestor_and_cache_keeps_strict_compiler_rejections(self):
        cases = [('[env]\nTEST_ONLY = "synthetic"\n', "forbids env"),
                 ('[build]\nrustc-wrapper = "TEST ONLY wrapper"\n', "compiler envelope"),
                 ('[target.armv7-linux-androideabi]\nlinker = "TEST ONLY linker"\n', "overrides a target"),
                 ('[profile.release]\nopt-level = 1\n', "forbids profile"),
                 ('[alias]\nbuild = "TEST ONLY"\n', "built-in command")]
        for directory in (self.cwd, self.base):
            for contents, error in cases:
                with self.subTest(directory=directory, error=error):
                    path = self.config(directory, contents)
                    rejected = self.launch()
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, "")
                    self.assertIn(error, rejected.stderr)
                    path.unlink()
        for contents, error in cases:
            with self.subTest(cache_error=error):
                path = self.cache / "config.toml"
                path.write_text(contents)
                rejected = self.launch()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn(error, rejected.stderr)
                path.unlink()

    def test_post_child_rechecks_created_ancestor_config_cache_and_cwd_replacements(self):
        path = self.base / ".cargo/config.toml"
        path.parent.mkdir()
        self.fake_cargo("pathlib.Path(" + repr(str(path)) + ").write_text('[net]\\noffline = true\\n')")
        rejected = self.launch()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("configuration changed during invocation", rejected.stderr)
        path.unlink()
        for chosen in (self.cache, self.cwd):
            with self.subTest(replaced=chosen):
                moved = chosen.with_name(chosen.name + "-original")
                self.fake_cargo("p=pathlib.Path(" + repr(str(chosen)) + "); p.rename(" + repr(str(moved)) + "); p.mkdir(mode=0o700)")
                rejected = self.launch()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("changed during invocation", rejected.stderr)
                chosen.rmdir()
                moved.rename(chosen)

    def test_exact_diagnostic_recipe_refuses_other_abis_profiles_outputs_and_features(self):
        variants = []
        for index, value in ((2, "arm64-v8a"), (4, str(self.target)),
                             (11, str(self.base / "Cargo.toml")),
                             (14, "iroha_data_model"), (16, "other-feature")):
            changed = list(self.arguments); changed[index] = value; variants.append(changed)
        variants += [self.arguments + ["--config", "build.jobs=2"],
                     self.arguments + ["-t", "x86_64"],
                     self.arguments[:-2]]
        for changed in variants:
            with self.subTest(arguments=changed):
                rejected = self.launch(arguments=changed)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn("exact single-ABI recipe", rejected.stderr)

    def test_closed_environment_rejects_force_flags_bootstrap_and_other_jobs(self):
        for name, value, error in (("RUSTC_BOOTSTRAP", "1", "environment inventory"),
                                   ("RUSTFLAGS", "TEST ONLY", "environment inventory"),
                                   ("CARGO_BUILD_JOBS", "2", "must be exactly '1'"),
                                   ("CARGO_NET_OFFLINE", "false", "must be exactly 'true'")):
            with self.subTest(name=name):
                rejected = self.launch(environment=dict(self.environment, **{name: value}))
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn(error, rejected.stderr)

    def test_root_lock_identity_is_checked_even_when_actual_child_cwd_is_external(self):
        lock = self.root / "Cargo.lock"
        self.fake_cargo("pathlib.Path(" + repr(str(lock)) + ").write_text('# changed synthetic lock\\n')")
        rejected = self.launch()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("Android root Cargo.lock changed", rejected.stderr)

    def seal_environment(self):
        return {"NORITO_BRIDGE_SEAL_CARGO_HOME": str(self.cache),
                "NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR": str(self.cwd)}

    def metadata(self, diagnostic=True):
        tools = [mock.Mock() for _ in range(3)]
        observed = []
        def actual(invocation, cargo, arguments, environment):
            observed.append((invocation, arguments, environment))
            return b'{"packages":[],"resolve":{"nodes":[]}}'
        with mock.patch.dict(os.environ, self.seal_environment()), \
             mock.patch.object(seal, "source_seal_tools", return_value=(*tools, Path("/usr/bin/git"))), \
             mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(self.cache)}), \
             mock.patch.object(seal, "run", side_effect=actual):
            result = seal.metadata(self.root, "armv7-linux-androideabi", self.root / "Cargo.lock",
                                   android_armv7_diagnostic=diagnostic)
        return result, observed

    def test_metadata_uses_the_same_actual_cwd_cache_target_and_root_manifest(self):
        result, observed = self.metadata()
        self.assertEqual(result["packages"], [])
        self.assertEqual(len(observed), 1)
        invocation, arguments, environment = observed[0]
        self.assertEqual(invocation, self.cwd)
        self.assertEqual(environment["CARGO_HOME"], str(self.cache))
        self.assertEqual(arguments[arguments.index("--manifest-path") + 1], str(self.root / "Cargo.toml"))
        self.assertEqual(arguments[-1], "armv7-linux-androideabi")
        self.assertIn("--locked", arguments)
        self.assertIn("--offline", arguments)
        production, production_observed = self.metadata(diagnostic=False)
        self.assertEqual(production["packages"], [])
        self.assertEqual(production_observed[0][0], self.cwd)

    def test_snapshot_binds_explicit_configuration_without_diagnostic_production_authority(self):
        for platform in ("android-armv7-diagnostic", "android"):
            with self.subTest(platform=platform), mock.patch.dict(os.environ, self.seal_environment()), \
                 mock.patch.object(seal, "seal_inputs", return_value=["Cargo.toml", "Cargo.lock"]), \
                 mock.patch.object(seal, "source_commit", return_value="1" * 40), \
                 mock.patch.object(seal, "status", return_value=""), \
                 mock.patch.object(seal, "fingerprint", return_value="2" * 64):
                result = seal.snapshot(self.root, platform, self.root / "Cargo.lock")
                if platform == "android":
                    self.assertNotIn("diagnostic_configuration", result)
                    self.assertEqual(result["cargo_configuration"],
                                     policy.android_cargo_configuration(self.root, self.cache, self.cwd))
                    self.assertEqual(result["targets"], list(seal.ANDROID_TARGETS))
                else:
                    self.assertEqual(result["diagnostic_configuration"], self.observe())
                    self.assertEqual(result["targets"], ["armv7-linux-androideabi"])
        self.assertIn("scripts/norito_bridge_local_integration.py",
                      seal.PLATFORM_ROOT_INPUTS["android-armv7-diagnostic"])
        self.assertIn("scripts/norito_bridge_local_integration.py",
                      seal.PLATFORM_ROOT_INPUTS["android"])

    def test_snapshot_refuses_configuration_drift_during_source_authentication(self):
        changed = self.cwd / ".cargo/config.toml"
        changed.parent.mkdir()
        def fingerprint(*args):
            changed.write_text('[net]\noffline = true\n')
            return "2" * 64
        with mock.patch.dict(os.environ, self.seal_environment()), \
             mock.patch.object(seal, "seal_inputs", return_value=["Cargo.toml", "Cargo.lock"]), \
             mock.patch.object(seal, "source_commit", return_value="1" * 40), \
             mock.patch.object(seal, "status", return_value=""), \
             mock.patch.object(seal, "fingerprint", side_effect=fingerprint):
            with self.assertRaisesRegex(RuntimeError, "configuration changed while authenticating"):
                seal.snapshot(self.root, "android-armv7-diagnostic", self.root / "Cargo.lock")

    def test_untracked_shipping_framing_module_is_hashed_by_real_git_intake(self):
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.root)], check=True,
                       capture_output=True)
        relative = "crates/iroha_data_model/src/kagemusha/kagemusha_wallet_v1/frame_alignment.rs"
        path = self.root / relative
        path.parent.mkdir(parents=True)
        path.write_text("// public synthetic shipping alignment assertion\nconst _: () = ();\n")
        tools = [mock.Mock() for _ in range(3)]
        environment = {"HOME": str(self.account), "PATH": "/usr/bin:/bin",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_OPTIONAL_LOCKS": "0"}
        with mock.patch.object(seal, "source_seal_tools", return_value=(*tools, Path("/usr/bin/git"))), \
             mock.patch.object(seal, "source_seal_environment", return_value=environment):
            files = seal.listed_files(self.root, ["crates/iroha_data_model"], self.root / "Cargo.lock")
            self.assertIn(relative, files)
            before = seal.fingerprint(self.root, ["crates/iroha_data_model"], self.root / "Cargo.lock")
            path.write_text(path.read_text() + "// changed original\n")
            self.assertNotEqual(before, seal.fingerprint(self.root, ["crates/iroha_data_model"],
                                                       self.root / "Cargo.lock"))

    def test_cli_rejects_path_aliases_before_directory_intake(self):
        command = [str(Path(sys.executable).resolve()), "-I", "-S",
                   str(SCRIPTS / "norito_bridge_local_integration.py"), "--role", "android-armv7-diagnostic",
                   "--root", str(self.root), "--path", str(self.cwd), "--local-integration"]
        for raw in (str(self.cache) + "/", str(self.cache) + "/./", str(self.cache) + "//"):
            with self.subTest(raw=raw):
                result = subprocess.run(command + ["--cargo-home", raw], capture_output=True,
                                        text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("requires explicit canonical cache and cwd", result.stderr)


if __name__ == "__main__":
    unittest.main()
