"""Authenticated native runtime build components, without Cargo or signing keys.

Only signed-source/toolchain selection and compilation are isolated fixtures.
Real files, Cargo locks, Mach-O admission, retained descriptors, digests and
exclusive native directory publication exercise the maintained owner. These
tests establish neither a signed Git decision nor deployment qualification.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "taira_release.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("taira_native_runtime_build_tests", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
HOST = "aarch64-apple-darwin"


def executable(name, cpu=0x100000c):
    return struct.pack("<IIII", 0xfeedfacf, cpu, 0, 2) + b"native runtime fixture " + name.encode()


class NativeRuntimeBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "target").mkdir(mode=0o700)
        self.target = self.root / "target/taira-macos-runtime"
        self.output = self.root / "target/runtime-observation"
        self.source = self.root / "captured-source"
        self.source.mkdir(mode=0o700)
        (self.source / "Cargo.toml").write_text('[workspace.package]\nversion = "2.0.0"\n')
        for _, package, manifest, _ in release.NATIVE_RUNTIME_BINARIES:
            path = self.source / manifest
            path.parent.mkdir(parents=True, mode=0o700)
            path.write_text('[package]\nname = "' + package + '"\nversion.workspace = true\n')
        self.args = argparse.Namespace(repo_root=self.root, output_dir=self.output,
                                       expected_commit="a" * 40, expected_signer="A" * 40)
        self.tool = self.root / "rust-tool"
        self.tool.write_bytes(b"pinned native compiler fixture")
        self.tool.chmod(0o700)
        pin = release.stable_hash_path(self.tool)
        self.tools = [{"name": name, "path": str(self.tool), "sha256": pin.sha256, "size": pin.size}
                      for name in ("cargo", "rustc", "rustdoc")]
        self.edit_emissions = lambda values: None
        self.after_build = lambda: None
        self.snapshots = lambda: [{"path": "Cargo.toml", "sha256": "c" * 64}]
        self.canonical_snapshots = lambda: [{"path": "Cargo.toml", "kind": "regular", "sha256": "c" * 64}]
        self.fingerprint_calls = []
        self.cpu = 0x100000c
        self.before_publish = lambda *_a, **_k: None
        self.after_publish = lambda *_a, **_k: None
        self.native_publish = release.publish_directory_noreplace
        self.builds = 0

    def tearDown(self):
        for path in [self.root, *self.root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        self.temporary.cleanup()

    def compile(self, source, command, environment, log, **locks):
        self.builds += 1
        self.assertEqual(command, release.native_runtime_build_command(source, self.target, str(self.tool), HOST))
        self.assertNotIn("CARGO_BUILD_JOBS", environment)
        self.assertNotIn("CARGO_ZIGBUILD_ZIG_PATH", environment)
        self.assertNotIn("PRIVATE_KEY", environment)
        self.assertNotIn("RUSTFLAGS", environment)
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["IROHA_GIT_COMMIT_HASH"], self.args.expected_commit)
        self.assertEqual(environment["VERGEN_GIT_SHA"], self.args.expected_commit)
        self.assertEqual(locks["label"], "native runtime build")
        os.fstat(locks["lock_fd"])
        os.fstat(locks["mode_lock_fd"])
        with self.assertRaisesRegex(release.PrepareError, "still running"):
            with release.cargo_lane(self.root, self.target, "release"):
                self.fail("native build lost its Cargo lane lock")
        values = []
        for name, package, manifest, entry in release.NATIVE_RUNTIME_BINARIES:
            binary = self.target / HOST / "release" / name
            binary.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            binary.write_bytes(executable(name, self.cpu))
            binary.chmod(0o700)
            parent = (source / manifest).parent
            suffix = "2.0.0" if parent.name == package else package + "@2.0.0"
            values.append({"reason": "compiler-artifact", "package_id": "path+" + parent.as_uri() + "#" + suffix,
                           "manifest_path": str(source / manifest),
                           "target": {"name": name, "kind": ["bin"], "src_path": str(source / entry)},
                           "profile": {"test": False}, "features": ["default"], "filenames": [str(binary)],
                           "executable": str(binary), "fresh": False})
        values.insert(0, {"reason": "compiler-artifact", "target": {"name": "iroha", "kind": ["lib"]},
                          "executable": None})
        self.edit_emissions(values)
        log.write_text("".join(json.dumps(row) + "\n" for row in values)
                       + '{"reason":"build-finished","success":true}\n')
        self.after_build()

    def run_runtime(self, build=None, signed=None, *, runtime=True):
        linker = {"preference": "system", "platform": "darwin", "tools": {}}
        def isolate(_root, _source, env):
            return dict(env, CARGO=str(self.tool), RUSTC=str(self.tool), CARGO_BUILD_JOBS="6",
                        CARGO_ZIGBUILD_ZIG_PATH="unused"), self.tools
        def publish(*args, **kwargs):
            self.before_publish(*args, **kwargs)
            result = self.native_publish(*args, **kwargs)
            self.after_publish(*args, **kwargs)
            return result
        def fingerprints(*args, **kwargs):
            self.fingerprint_calls.append((args, kwargs))
            return contextlib.nullcontext([])
        with contextlib.ExitStack() as stack:
            for owner, name, options in [
                (release, "__file__", {"new": str(self.root / "scripts/taira_release.py")}),
                (release.sys, "platform", {"new": "darwin"}),
                (release, "verify_signed_source", {"side_effect": signed or (lambda *_: "b" * 40)}),
                (release, "commit_entries", {"return_value": b""}),
                (release, "signed_source_size", {"return_value": 0}),
                (release, "capacity_preflight", {"return_value": []}),
                (release, "source_lane", {"side_effect": lambda *_: contextlib.nullcontext((self.source, 88))}),
                (release, "capture_source", {"return_value": self.source}),
                (release, "frozen_snapshot", {"side_effect": lambda *_: self.snapshots()}),
                (release, "canonical_source_snapshot", {"side_effect": lambda *_: self.canonical_snapshots()}),
                (release, "isolated_cargo_environment", {"side_effect": isolate}),
                (release, "preparation_native_linker", {"return_value": linker}),
                (release, "preparation_native_environment", {"side_effect": lambda env, _: env}),
                (release.subprocess, "check_output", {"return_value": "rustc fixture\nhost: " + HOST + "\n"}),
                (release, "local_package_names", {"return_value": {"iroha_cli", "iroha_kagami", "irohad"}}),
                (release, "local_package_roots", {"return_value": {"fixture": self.root}}),
                (release, "admit_source_fingerprints", {"side_effect": lambda *a, **k: self.fingerprint_calls.append((a, k)) or []}),
                (release, "source_fingerprints", {"side_effect": fingerprints}),
                (release, "run_build", {"side_effect": build or self.compile}),
                (release, "publish_directory_noreplace", {"side_effect": publish}),
            ]:
                stack.enter_context(patch.object(owner, name, **options))
            stack.enter_context(patch.dict(os.environ, {"PRIVATE_KEY": "excluded", "RUSTFLAGS": "untrusted",
                                                        "VERGEN_GIT_SHA": "local-fast"}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return (release.prepare_native_runtime(self.args) if runtime
                    else release.prepare_client(self.args))

    def select_canonical_source(self):
        self.args.source_mode = "canonical-checkout"
        for path in self.source.rglob("*"):
            if path.is_file():
                target = self.root / path.relative_to(self.source)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())

    def test_canonical_runtime_routes_compiler_and_fingerprints_to_checkout_only(self):
        self.select_canonical_source()
        result = self.run_runtime()
        self.assertEqual(result["source_mode"], "canonical-checkout")
        self.assertEqual(result["compiler_source_root"], str(self.root))
        self.assertEqual(result["source_root"], str(self.source))
        self.assertEqual(result["source_snapshot_sha256"],
                         hashlib.sha256(release.canonical_json_bytes(self.snapshots())).hexdigest())
        self.assertEqual(result["command"], release.native_runtime_build_command(
            self.root, self.target, str(self.tool), HOST))
        self.assertEqual(len(self.fingerprint_calls), 2)
        for args, kwargs in self.fingerprint_calls:
            self.assertEqual(args[:4], (self.root, self.target, HOST, {"fixture"}))
            self.assertEqual(kwargs["package_roots"], {"fixture": self.root})
            self.assertEqual(kwargs["source_paths"], {self.root / "Cargo.toml"})
        self.assertEqual(release.read_record(self.output / "request.json")["compiler_source_root"], str(self.root))

    def test_canonical_musubi_client_uses_checkout_manifest_and_genuine_emission(self):
        self.args.bin = "musubi"
        self.target = self.root / "target/taira-macos-client"
        name, package, manifest, entry = release.CLIENT_BINARIES[self.args.bin]
        path = self.source / manifest
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text('[package]\nname = "musubi"\nversion.workspace = true\n')
        self.select_canonical_source()
        def compile_client(source, command, environment, log, **locks):
            self.builds += 1
            self.assertEqual(source, self.root)
            self.assertEqual(command, release.client_build_command(
                self.root, self.target, str(self.tool), HOST, "musubi"))
            self.assertNotIn("CARGO_BUILD_JOBS", environment)
            self.assertEqual(locks["label"], "native musubi build")
            os.fstat(locks["lock_fd"])
            os.fstat(locks["mode_lock_fd"])
            binary = self.target / HOST / "debug" / name
            binary.parent.mkdir(mode=0o700, parents=True)
            binary.write_bytes(executable(name))
            binary.chmod(0o700)
            row = {"reason": "compiler-artifact",
                   "package_id": "path+" + (source / manifest).parent.as_uri() + "#2.0.0",
                   "manifest_path": str(source / manifest),
                   "target": {"name": name, "kind": ["bin"], "src_path": str(source / entry)},
                   "profile": {"test": False}, "features": ["default"],
                   "filenames": [str(binary)], "executable": str(binary), "fresh": False}
            log.write_text(json.dumps(row) + '\n{"reason":"build-finished","success":true}\n')
        result = self.run_runtime(build=compile_client, runtime=False)
        self.assertEqual(self.builds, 1)
        self.assertEqual(result["schema"], "taira.local-client-build.v2")
        self.assertEqual(result["source_mode"], "canonical-checkout")
        self.assertEqual(result["compiler_source_root"], str(self.root))
        self.assertEqual(result["source_root"], str(self.source))
        self.assertEqual(result["artifact"]["name"], "musubi")
        self.assertEqual(Path(result["artifact"]["path"]).read_bytes(), executable("musubi"))

    def test_canonical_preflight_refusal_has_no_lane_or_output(self):
        self.select_canonical_source()
        def refuse():
            raise release.PrepareError("canonical compiler HEAD differs")
        self.canonical_snapshots = refuse
        with self.assertRaisesRegex(release.PrepareError, "canonical compiler HEAD differs"):
            self.run_runtime()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.builds, 0)

    def test_canonical_and_authority_drift_both_prevent_package_publication(self):
        self.select_canonical_source()
        for fault in ("canonical", "authority"):
            with self.subTest(fault=fault):
                self.args.output_dir = self.root / "target" / ("canonical-drift-" + fault)
                self.snapshots = lambda: [{"path": "Cargo.toml", "sha256": "c" * 64}]
                self.canonical_snapshots = lambda: [{"path": "Cargo.toml", "kind": "regular", "sha256": "c" * 64}]
                field = "canonical_snapshots" if fault == "canonical" else "snapshots"
                self.after_build = lambda: setattr(self, field, lambda: [{"changed": True}])
                with self.assertRaisesRegex(release.PrepareError, "source changed"):
                    self.run_runtime()
                self.assertTrue((self.args.output_dir / "request.json").is_file())
                self.assertTrue((self.args.output_dir / "cargo.jsonl").is_file())
                self.assertFalse((self.args.output_dir / "bin").exists())
                self.assertFalse((self.args.output_dir / "result.json").exists())

    def test_canonical_mode_rejects_emission_from_authority_capture(self):
        self.select_canonical_source()
        def redirect(values):
            for row in values:
                if row.get("executable"):
                    row["manifest_path"] = str(self.source / Path(row["manifest_path"]).relative_to(self.root))
        self.edit_emissions = redirect
        with self.assertRaisesRegex(release.PrepareError, "artifact differs"):
            self.run_runtime()
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_native_source_modes_are_explicit_and_unknown_mode_is_refused(self):
        for action in ("prepare-client", "prepare-native-runtime"):
            argv = [action, "--expected-commit", "a" * 40, "--expected-signer", "A" * 40,
                    "--output-dir", str(self.output)]
            if action == "prepare-client":
                argv += ["--bin", "musubi"]
            self.assertEqual(release.parser().parse_args(argv).source_mode, "captured")
            self.assertEqual(release.parser().parse_args(argv + ["--source-mode", "canonical-checkout"]).source_mode,
                             "canonical-checkout")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                release.parser().parse_args(argv + ["--source-mode", "alternate-checkout"])
        self.args.source_mode = "alternate-checkout"
        with self.assertRaisesRegex(release.PrepareError, "unsupported compiler source mode"):
            self.run_runtime()
        self.assertEqual(self.builds, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.output.exists())

    def test_one_native_invocation_publishes_exact_complete_retained_package(self):
        result = self.run_runtime()
        self.assertEqual(self.builds, 1)
        self.assertEqual(result["schema"], "taira.native-runtime-build.v1")
        self.assertEqual(result["profile"], "release")
        self.assertEqual(result["jobs"], "cargo-default")
        self.assertEqual(result["compiler_tools"], self.tools)
        for flag in ("qualified", "release_qualified", "deployed"):
            self.assertIs(result[flag], False)
        self.assertTrue(result["source_unchanged"] and result["toolchain_unchanged"])
        self.assertEqual(len(result["cargo_emissions"]), 3)
        self.assertEqual([row["name"] for row in result["artifacts"]], ["iroha", "kagami", "iroha3d"])
        self.assertEqual(set((self.output / "bin").iterdir()), {self.output / "bin" / name for name, *_ in release.NATIVE_RUNTIME_BINARIES})
        for row in result["artifacts"]:
            retained = Path(row["path"])
            self.assertEqual(retained.read_bytes(), executable(row["name"]))
            self.assertEqual(row["sha256"], hashlib.sha256(retained.read_bytes()).hexdigest())
            self.assertEqual(row["identity"], release.native_file_identity(retained.lstat()))
            self.assertEqual(row["identity"]["mode"], 0o500)
            self.assertEqual(row["source_identity"], release.native_file_identity((self.target / HOST / "release" / row["name"]).lstat()))
        self.assertEqual(release.read_record(self.output / "result.json"), result)
        self.assertEqual(stat.S_IMODE((self.output / "bin").stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)

    def test_first_lane_creation_follows_signed_preflight_and_reuses_its_inode(self):
        def signed(*_):
            self.assertFalse(self.target.exists())
            return "b" * 40
        self.run_runtime(signed=signed)
        inode = self.target.stat().st_ino
        cached = self.target / "preserved-cache"
        cached.write_bytes(b"warm")
        self.args.output_dir = self.root / "target/second-observation"
        self.run_runtime()
        self.assertEqual(self.target.stat().st_ino, inode)
        self.assertEqual(cached.read_bytes(), b"warm")

    def test_unsigned_source_never_creates_lane_or_output(self):
        def refuse(*_):
            raise release.PrepareError("source signature refused")
        with self.assertRaisesRegex(release.PrepareError, "signature refused"):
            self.run_runtime(signed=refuse)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.output.exists())

    def test_first_use_also_creates_missing_target_parent_after_admission(self):
        (self.root / "target").rmdir()
        self.run_runtime()
        self.assertEqual(stat.S_IMODE((self.root / "target").stat().st_mode), 0o700)
        self.assertTrue((self.output / "bin/iroha").exists())

    def test_unsafe_existing_lane_is_not_chmodded_or_replaced(self):
        self.target.mkdir(mode=0o755)
        identity = release.file_identity(self.target.lstat())
        with self.assertRaisesRegex(release.ReleaseArtifactError, "owner-held 0700"):
            self.run_runtime()
        self.assertEqual(release.file_identity(self.target.lstat()), identity)
        self.assertEqual(self.builds, 0)

    def test_foreign_missing_duplicate_test_or_malformed_artifact_refuses_package(self):
        def change(field):
            def apply(values):
                value = values[1]
                if field == "missing":
                    values.pop()
                elif field == "duplicate":
                    values.append(dict(value))
                elif field == "kind":
                    value["target"]["kind"] = ["test"]
                elif field == "source":
                    value["target"]["src_path"] = "/foreign/src.rs"
                elif field == "profile":
                    value["profile"] = {"test": True}
                elif field == "package_id":
                    value[field] = "path+file:///foreign#iroha_cli@2.0.0"
                else:
                    value[field] = "/foreign/path"
            return apply
        for field in ("missing", "duplicate", "kind", "source", "profile", "package_id", "manifest_path", "executable"):
            with self.subTest(field=field):
                self.args.output_dir = self.root / "target" / ("refused-" + field)
                self.edit_emissions = change(field)
                with self.assertRaises(release.PrepareError):
                    self.run_runtime()
                self.assertTrue((self.args.output_dir / "request.json").exists())
                self.assertTrue((self.args.output_dir / "cargo.jsonl").exists())
                self.assertFalse((self.args.output_dir / "bin").exists())
                self.assertFalse((self.args.output_dir / "result.json").exists())

    def test_nonexecutable_library_only_exact_null_is_ignored(self):
        self.edit_emissions = lambda values: values[0].update(executable="/foreign/library")
        with self.assertRaises(release.PrepareError):
            self.run_runtime()
        self.assertFalse((self.output / "bin").exists())

    def test_wrong_native_cpu_has_no_partial_published_bin_directory(self):
        self.cpu = 0x1000007
        with self.assertRaisesRegex(release.PrepareError, "native macOS executable"):
            self.run_runtime()
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_source_or_tool_drift_retains_evidence_without_package(self):
        for fault in ("source", "tool"):
            with self.subTest(fault=fault):
                self.args.output_dir = self.root / "target" / ("drift-" + fault)
                self.after_build = (lambda: setattr(self, "snapshots", lambda: [{"changed": True}])) if fault == "source" else (lambda: self.tool.write_bytes(b"changed native compiler"))
                with self.assertRaisesRegex(release.PrepareError, "source changed|reviewed executable"):
                    self.run_runtime()
                self.assertFalse((self.args.output_dir / "bin").exists())
                self.assertFalse((self.args.output_dir / "result.json").exists())

    def test_compiler_failure_retains_request_and_log_without_published_package(self):
        def fail(*args, **kwargs):
            self.compile(*args, **kwargs)
            raise release.PrepareError("native runtime build failed")
        with self.assertRaisesRegex(release.PrepareError, "build failed"):
            self.run_runtime(fail)
        self.assertTrue((self.output / "request.json").exists())
        self.assertTrue((self.output / "cargo.jsonl").exists())
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_atomic_destination_collision_preserves_foreign_directory(self):
        foreign = b"foreign owner output"
        def occupy(_stage, destination, **_):
            destination.mkdir(mode=0o700)
            (destination / "foreign").write_bytes(foreign)
        self.before_publish = occupy
        with self.assertRaisesRegex(release.ReleaseArtifactError, "exclusive directory publication failed"):
            self.run_runtime()
        self.assertEqual((self.output / "bin/foreign").read_bytes(), foreign)
        self.assertFalse((self.output / "result.json").exists())

    def test_short_native_writes_make_progress_without_corrupting_any_retained_copy(self):
        original = os.write
        def short(fd, payload):
            if stat.S_IMODE(os.fstat(fd).st_mode) == 0o755:
                return original(fd, payload[:3])
            return original(fd, payload)
        with patch.object(release.os, "write", side_effect=short):
            result = self.run_runtime()
        for row in result["artifacts"]:
            self.assertEqual(Path(row["path"]).read_bytes(), executable(row["name"]))

    def test_cargo_two_name_aliases_are_retained_and_copies_are_single_link(self):
        def alias():
            directory = self.target / HOST / "release/deps"
            directory.mkdir(mode=0o700)
            for name, *_ in release.NATIVE_RUNTIME_BINARIES:
                os.link(directory.parent / name, directory / (name + "-0123456789abcdef"))
        self.after_build = alias
        result = self.run_runtime()
        for row in result["artifacts"]:
            self.assertEqual(row["source_identity"]["links"], 2)
            self.assertEqual(row["identity"]["links"], 1)
            original = self.target / HOST / "release" / row["name"]
            self.assertEqual(original.stat().st_nlink, 2)
            self.assertEqual(original.read_bytes(), executable(row["name"]))

    def test_warm_lane_path_substitution_is_refused_before_capture(self):
        def substitute():
            self.target.rename(self.target.with_name("retained-original-lane"))
            self.target.mkdir(mode=0o700)
        self.after_build = substitute
        with self.assertRaisesRegex(release.PrepareError, "lane custody changed"):
            self.run_runtime()
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_copy_substitution_before_publication_is_refused_without_success(self):
        original = release.stable_hash_path
        def inspect(path, **kwargs):
            result = original(path, **kwargs)
            if Path(path).name == "iroha3d" and ".native-bin.pending-" in str(path):
                Path(path).chmod(0o700)
                Path(path).write_bytes(b"foreign same-length candidate substitute")
            return result
        with patch.object(release, "stable_hash_path", side_effect=inspect):
            with self.assertRaises((release.PrepareError, release.ReleaseArtifactError)):
                self.run_runtime()
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_created_stage_inode_substitution_with_same_bytes_preserves_foreign_file(self):
        original = release.exclusive_output_fd
        replacement = {}
        @contextlib.contextmanager
        def substitute(path, **kwargs):
            with original(path, **kwargs) as fd:
                yield fd
            if path.name == "iroha" and ".native-bin.pending-" in str(path):
                data = path.read_bytes()
                path.rename(path.with_name("actual-created-copy"))
                path.write_bytes(data)
                path.chmod(0o755)
                replacement.update(path=path, identity=release.file_identity(path.lstat()), bytes=data)
        with patch.object(release, "exclusive_output_fd", side_effect=substitute):
            with self.assertRaisesRegex(release.PrepareError, "created copy custody changed"):
                self.run_runtime()
        self.assertEqual(release.file_identity(replacement["path"].lstat()), replacement["identity"])
        self.assertEqual(replacement["path"].read_bytes(), replacement["bytes"])
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_foreign_published_directory_with_original_file_inodes_is_not_finalized(self):
        foreign = {}
        def substitute(_stage, destination, **_):
            original = destination.with_name("actual-published-directory")
            destination.rename(original)
            destination.mkdir(mode=0o700)
            for name, *_ in release.NATIVE_RUNTIME_BINARIES:
                (original / name).rename(destination / name)
            foreign.update(path=destination, identity=release.file_identity(destination.lstat()))
        self.after_publish = substitute
        with self.assertRaisesRegex(release.PrepareError, "published directory custody changed"):
            self.run_runtime()
        self.assertEqual(release.file_identity(foreign["path"].lstat()), foreign["identity"])
        self.assertEqual(stat.S_IMODE(foreign["path"].stat().st_mode), 0o700)
        for name, *_ in release.NATIVE_RUNTIME_BINARIES:
            self.assertEqual((foreign["path"] / name).read_bytes(), executable(name))
        self.assertFalse((self.output / "result.json").exists())

    def test_late_directory_substitution_before_final_chmod_preserves_foreign_custody(self):
        original = os.fchmod
        foreign = {}
        def substitute(fd, mode):
            if mode == 0o500 and stat.S_ISDIR(os.fstat(fd).st_mode) and not foreign:
                destination = self.output / "bin"
                retained = self.output / "actual-complete-bin"
                destination.rename(retained)
                destination.mkdir(mode=0o700)
                for name, *_ in release.NATIVE_RUNTIME_BINARIES:
                    (retained / name).rename(destination / name)
                foreign.update(path=destination, identity=release.file_identity(destination.lstat()))
            return original(fd, mode)
        with patch.object(release.os, "fchmod", side_effect=substitute):
            with self.assertRaisesRegex(release.PrepareError, "directory custody changed during finalization"):
                self.run_runtime()
        self.assertEqual(release.file_identity(foreign["path"].lstat()), foreign["identity"])
        self.assertEqual(stat.S_IMODE(foreign["path"].stat().st_mode), 0o700)
        self.assertFalse((self.output / "result.json").exists())

    def test_same_bytes_cargo_source_substitution_refuses_foreign_inode(self):
        original = release.cargo_hash_path
        replacement = {}
        def substitute(path, **kwargs):
            pin = original(path, **kwargs)
            if path.name == "iroha" and not replacement:
                data = path.read_bytes()
                path.rename(path.with_name("actual-build-output"))
                path.write_bytes(data)
                path.chmod(0o700)
                replacement.update(path=path, identity=release.file_identity(path.lstat()), bytes=data)
            return pin
        with patch.object(release, "cargo_hash_path", side_effect=substitute):
            with self.assertRaises(release.ReleaseArtifactError):
                self.run_runtime()
        self.assertEqual(release.file_identity(replacement["path"].lstat()), replacement["identity"])
        self.assertEqual(replacement["path"].read_bytes(), replacement["bytes"])
        self.assertFalse((self.output / "bin").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_completed_output_is_never_replayed_or_overwritten(self):
        self.run_runtime()
        before = (self.output / "result.json").read_bytes()
        with self.assertRaisesRegex(release.PrepareError, "fresh directory"):
            self.run_runtime(lambda *_a, **_k: self.fail("replayed completed native build"))
        self.assertEqual((self.output / "result.json").read_bytes(), before)

    def test_observation_cannot_enter_cargo_or_signed_source_custody(self):
        for name in ("taira-macos-runtime", "taira-release-sources", "taira-release-cargo-home"):
            with self.subTest(name=name):
                self.args.output_dir = self.root / "target" / name / "observation"
                with self.assertRaisesRegex(release.PrepareError, "fresh directory|retained signed source"):
                    self.run_runtime()
                self.assertFalse(self.args.output_dir.exists())
                self.assertFalse(self.target.exists())

    def test_parser_and_command_have_exact_packages_with_no_override_or_local_fast_metadata(self):
        args = release.parser().parse_args(["prepare-native-runtime", "--expected-commit", "a" * 40,
                                           "--expected-signer", "A" * 40, "--output-dir", str(self.output)])
        self.assertEqual(args.command, "prepare-native-runtime")
        for field in ("jobs", "target_dir", "profile", "zig", "native_linker"):
            self.assertFalse(hasattr(args, field))
        command = release.native_runtime_build_command(self.source, self.target, "/pinned/cargo", HOST)
        self.assertEqual(command[-12:], ["-p", "iroha_cli", "--bin", "iroha", "-p", "iroha_kagami", "--bin", "kagami", "-p", "irohad", "--bin", "iroha3d"])
        self.assertIn("--locked", command)
        self.assertIn("--offline", command)
        self.assertNotIn("--no-default-features", command)
        self.assertNotIn("--jobs", command)
        with self.assertRaisesRegex(release.PrepareError, "native macOS"):
            release.native_runtime_build_command(self.source, self.target, "/pinned/cargo", release.TARGET)


if __name__ == "__main__":
    unittest.main()
