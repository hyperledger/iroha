"""Local preparation regressions; disposable files and a local Git index, no Cargo or network."""

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
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/taira_release.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("taira_release", SCRIPT)
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
# Tests that exercise development diagnostics import their mutable gate explicitly.
import taira_release_check as development_gate


def elf(machine=183):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", header, 16, 3, machine)
    return bytes(header) + b"disposable binary fixture"


class TairaPrepareTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir(mode=0o700)
        self.target_mode = stat.S_IMODE(self.target.stat().st_mode)
        self.out = self.root / "prepared"
        self.source = self.target / "frozen-source"
        self.zig, self.zigbuild = self.root / "zig", self.root / "cargo-zigbuild"
        for tool in (self.zig, self.zigbuild):
            tool.write_bytes(b"disposable tool fixture")
            tool.chmod(0o755)
        self.args = argparse.Namespace(
            repo_root=SCRIPT.parent.parent, target_dir=self.target,
            native_check_scope="build-only", native_linker="system",
            output_dir=self.out, expected_commit="a" * 40, expected_signer="A" * 40, zig=self.zig,
            zig_sha256=hashlib.sha256(self.zig.read_bytes()).hexdigest(),
            cargo_zigbuild=self.zigbuild,
            cargo_zigbuild_sha256=hashlib.sha256(self.zigbuild.read_bytes()).hexdigest(),
        )

        self.native_tools = []
        for role in ("compiler", "linker"):
            path = self.root / ("native-" + role)
            path.write_bytes(("disposable native " + role).encode())
            path.chmod(0o755)
            self.native_tools.append((role, path, path))

    def tearDown(self):
        for path in [self.root, *self.root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        self.directory.cleanup()

    def binaries(self, machine=183):
        output = self.target / release.TARGET / "release"
        output.parent.mkdir(mode=0o700, exist_ok=True)
        output.mkdir(mode=0o700, exist_ok=True)
        for name, _ in release.BINARIES:
            path = output / name
            path.write_bytes(elf(machine))
            path.chmod(0o755)

    def prepare(self, *, check=None, build=None, snapshot=None, cache_admission=None, source_lane_fd=88,
                isolate=None, native_paths=None, package_names=None):
        def default_build(_root, _command, _env, log):
            self.binaries()
            log.write_bytes(b"fixture compiler output\n")
        def wrapped_build(*args, **kwargs):
            return (build or default_build)(*args)
        with patch.object(release, "source_lane", side_effect=lambda *_: contextlib.nullcontext((self.source, source_lane_fd))), \
             patch.object(release, "source_snapshot", return_value=[]), \
             patch.object(release, "verify_signed_source", return_value="b" * 40), \
             patch.object(release, "commit_entries", return_value=b""), \
             patch.object(release, "signed_source_size", return_value=0), \
             patch.object(release, "capture_source", return_value=self.source), \
             patch.object(release, "frozen_snapshot", side_effect=(lambda *_: snapshot(self.source)) if snapshot else (lambda *_: [])), \
             patch.object(release, "isolated_cargo_environment", side_effect=isolate or (lambda _r, _s, env: (dict(env, CARGO="/fixed/cargo"), []))), \
             patch.object(release.shutil, "which", return_value=str(self.zigbuild)), \
             patch.object(release, "captured_gate", return_value=development_gate), \
             patch.object(release, "local_package_names", side_effect=package_names or (lambda *_: set())), \
             patch.object(release, "admit_source_fingerprints", side_effect=cache_admission or (lambda *_a, **_k: [])), \
             patch.object(release, "source_fingerprints", side_effect=lambda *_a, **_k: contextlib.nullcontext([])), \
             patch.object(development_gate, "run_checks", side_effect=check) as gate, \
             patch.object(release, "run_build", side_effect=wrapped_build) as compile, \
             patch.object(release, "capacity_preflight", return_value=[]), \
             patch.object(release, "system_native_linker_paths", side_effect=native_paths or (lambda: tuple(self.native_tools))), \
             contextlib.redirect_stdout(io.StringIO()):
            result = release.prepare(self.args)
        return result, gate, compile

    def test_offline_package_failure_precedes_attempt_native_gate_and_build(self):
        def must_not_run(*_args, **_kwargs):
            self.fail("missing offline package reached the native gate or build")
        with self.assertRaisesRegex(ValueError, "missing-crate"):
            self.prepare(check=must_not_run, build=must_not_run,
                         package_names=ValueError("offline Cargo package preflight failed: missing-crate"))
        self.assertEqual(list((self.out / "attempts").iterdir()), [])
        self.assertFalse((self.out / "checks.json").exists())

    def test_prepare_orders_gate_build_capture_and_publishes_read_only_files(self):
        events = []
        def check(_root, *, environment, source_commit, lock_fds,
                  completed_independent_checks, update_independent_checks,
                  completed_pre_network_checks, update_pre_network_checks,
                  qualification_scope):
            events.append("gate")
            self.assertEqual(qualification_scope, "basic")
            self.assertIsNone(completed_independent_checks)
            self.assertTrue(callable(update_independent_checks))
            self.assertIsNone(completed_pre_network_checks)
            self.assertTrue(callable(update_pre_network_checks))
            self.assertEqual(environment["CARGO_TARGET_DIR"], str(self.target))
            self.assertEqual(len(lock_fds), 3)
            self.assertEqual(lock_fds[1], 88)  # Existing source-custody fixture descriptor.
            os.fstat(lock_fds[0])
            os.fstat(lock_fds[2])
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.cargo_lane(self.args.repo_root, self.target, "release"):
                    self.fail("prepare mode lock must remain held through native checks")
        def build(_root, command, environment, log):
            events.append("build")
            self.assertEqual(environment["IROHA_GIT_COMMIT_HASH"], self.args.expected_commit)
            self.assertEqual(command, release.build_command(self.source, self.target, "/fixed/cargo"))
            self.binaries()
            log.write_bytes(b"fixture build\n")
        result, gate, compile = self.prepare(check=check, build=build)
        self.assertEqual(events, ["build"])
        gate.assert_not_called()
        self.assertEqual(compile.call_count, 1)
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertFalse(result["release_qualified"])
        self.assertFalse(result["deployed"])
        for row in result["artifacts"]:
            path = Path(row["path"])
            self.assertEqual(path.read_bytes(), elf())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.out / "result.json").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), self.target_mode)

    def test_regression_gate_cannot_block_release_build(self):
        result, gate, build = self.prepare(check=development_gate.CheckError("fixture gate failed"))
        gate.assert_not_called()
        build.assert_called_once()
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertIs(release.read_record(self.out / "checks.json")["passed"], False)

    def test_captured_source_drift_stops_before_linux_build(self):
        snapshots = iter([[], [{"path": "changed"}]])
        with self.assertRaisesRegex(release.PrepareError, "source changed"):
            self.prepare(snapshot=lambda _: next(snapshots))
        self.assertFalse(list(self.out.glob("attempts/*/cargo.log")))
        self.assertFalse((self.out / "result.json").exists())

    def test_changed_tool_after_cache_admission_stops_before_build(self):
        def admit(*_args, **_kwargs):
            self.zig.write_bytes(b"different tool")
            return []
        with self.assertRaisesRegex(release.PrepareError, "reviewed executable"):
            self.prepare(cache_admission=admit)
        self.assertFalse(list(self.out.glob("attempts/*/cargo.log")))
        self.assertFalse((self.out / "result.json").exists())

    def test_wrong_architecture_cannot_publish_result(self):
        def build(_root, _command, _env, log):
            self.binaries(machine=62)
            log.write_bytes(b"fixture wrong architecture\n")
        with self.assertRaisesRegex(release.PrepareError, "AArch64 Linux ELF"):
            self.prepare(build=build)
        self.assertFalse((self.out / "result.json").exists())

    def test_capture_rejects_symlink(self):
        self.binaries()
        self.out.mkdir()
        original = self.target / release.TARGET / "release" / release.BINARIES[0][0]
        original.rename(original.with_suffix(".retained"))
        original.symlink_to(original.with_suffix(".retained"))
        with self.assertRaises(release.ReleaseArtifactError):
            release.capture_artifacts(self.target, self.out)
        self.assertFalse((self.out / "result.json").exists())

    def test_capture_accepts_only_closed_cargo_pair_and_keeps_output_single_link(self):
        self.binaries()
        self.out.mkdir()
        profile = self.target / release.TARGET / 'release'
        deps = profile / 'deps'; deps.mkdir()
        for name, _ in release.BINARIES:
            os.link(profile / name, deps / (name.replace('-', '_') + '-0123456789abcdef'))
        rows = release.capture_artifacts(self.target, self.out)
        self.assertEqual(len(rows), len(release.BINARIES))
        for row in rows:
            captured = Path(row['path'])
            self.assertEqual(captured.read_bytes(), elf())
            self.assertEqual(captured.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(captured.stat().st_mode), 0o500)
            self.assertEqual((profile / row['name']).stat().st_nlink, 2)
        self.assertIn('scripts/taira_cargo_artifact.py', release.BUILD_SOURCES)
        self.assertIn('scripts/taira_cargo_artifact.py', release.BOOTSTRAP_SOURCES)

    def test_artifact_replacement_after_hash_is_rejected(self):
        self.binaries()
        self.out.mkdir()
        original = self.target / release.TARGET / "release" / release.BINARIES[0][0]
        real_open = release.cargo_open_relative
        def replace_before_open(root, relative, *, expected):
            original.rename(original.with_suffix(".retained"))
            original.write_bytes(elf())
            original.chmod(0o755)
            return real_open(root, relative, expected=expected)
        with patch.object(release, "cargo_open_relative", side_effect=replace_before_open):
            with self.assertRaises(release.ReleaseArtifactError):
                release.capture_artifacts(self.target, self.out)

    def test_existing_output_and_symlink_target_fail_before_gate(self):
        self.out.mkdir()
        with patch.object(development_gate, "run_checks") as gate:
            with self.assertRaisesRegex(release.PrepareError, "fresh"):
                release.prepare(self.args)
            gate.assert_not_called()
        alias = self.root / "alias"
        alias.symlink_to(self.target, target_is_directory=True)
        with self.assertRaisesRegex(release.PrepareError, "symlinks"):
            release.real_path(alias)

    def test_same_command_reuses_completed_capture_without_gate_or_build(self):
        first, _, _ = self.prepare()
        second, gate, build = self.prepare()
        self.assertEqual(second, first)
        gate.assert_not_called()
        build.assert_not_called()
        self.assertEqual(len(list((self.out / "attempts").iterdir())), 1)

    def test_failed_build_retry_retains_log_and_reuses_gate_and_warm_lane(self):
        def failed(_root, _command, _environment, log):
            log.write_bytes(b"first build failed")
            raise release.PrepareError("fixture build failed")
        with self.assertRaisesRegex(release.PrepareError, "fixture build failed"):
            self.prepare(build=failed)
        original = self.out / "attempts/000001/cargo.log"
        before = original.read_bytes()
        result, gate, build = self.prepare()
        gate.assert_not_called()
        self.assertEqual(build.call_count, 1)
        self.assertEqual(result["attempt"], "attempts/000002")
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(build.call_args.args[1], release.build_command(self.source, self.target, "/fixed/cargo"))

    def test_crash_after_request_recovers_attempts_directory_before_work(self):
        real_create = release.create_fresh_directory
        def interrupt_attempts(path, *, mode):
            if path == self.out / "attempts":
                raise OSError("fixture crash after durable request")
            return real_create(path, mode=mode)
        with patch.object(release, "create_fresh_directory", side_effect=interrupt_attempts):
            with self.assertRaisesRegex(OSError, "fixture crash after durable request"):
                self.prepare()
        self.assertTrue((self.out / "request.json").is_file())
        self.assertFalse((self.out / "attempts").exists())
        result, gate, build = self.prepare()
        gate.assert_not_called()
        self.assertEqual(build.call_count, 1)
        self.assertEqual(result["attempt"], "attempts/000001")

    def test_resume_restores_actual_environment_before_tool_resolution_and_build(self):
        selected, built = [], []
        first_tmpdir, second_tmpdir = self.root / "session-one-tmp", self.root / "session-two-tmp"
        first_tmpdir.mkdir(mode=0o700)
        second_tmpdir.mkdir(mode=0o700)
        def isolate(_root, _source, environment):
            selected.append(dict(environment))
            return dict(environment, CARGO="/fixed/cargo"), []
        def interrupted(_root, _command, environment, log):
            built.append(dict(environment))
            log.write_text("fixture process interruption")
            raise release.PrepareError("fixture process interruption")
        with patch.dict(os.environ, {"PATH": "/fixture/session-one:/bin", "TMPDIR": str(first_tmpdir)}):
            with self.assertRaisesRegex(release.PrepareError, "process interruption"):
                self.prepare(build=interrupted, isolate=isolate)
        request_before = (self.out / "request.json").read_bytes()
        def resumed(_root, _command, environment, log):
            built.append(dict(environment))
            self.binaries()
            log.write_text("fixture resumed build")
        with patch.dict(os.environ, {"PATH": "/fixture/session-two:/bin", "TMPDIR": str(second_tmpdir)}):
            result, gate, build = self.prepare(build=resumed, isolate=isolate)
        self.assertEqual(selected[0], selected[1])
        self.assertEqual(built[0], built[1])
        self.assertEqual(selected[1]["PATH"], "/fixture/session-one:/bin")
        self.assertEqual((self.out / "request.json").read_bytes(), request_before)
        self.assertEqual(result["attempt"], "attempts/000002")
        gate.assert_not_called()
        self.assertEqual(build.call_count, 1)

    def test_recorded_environment_tampering_rejects_before_tool_resolution(self):
        self.prepare()
        environment_path, request_path = self.out / "environment.json", self.out / "request.json"
        original_environment = environment_path.read_bytes()
        original_request = request_path.read_bytes()
        def replace_record(path, record):
            path.chmod(0o600)
            path.write_bytes(release.canonical_json_bytes(record))
            path.chmod(0o400)
        def must_not_resolve(*_args):
            self.fail("tampered environment reached compiler resolution")
        for mutation in ("changed_path", "hook_even_with_rebound_digest", "writable", "hardlink"):
            with self.subTest(mutation=mutation):
                environment = json.loads(original_environment)
                request = json.loads(original_request)
                if mutation == "changed_path":
                    environment["child_environment"]["PATH"] = "/foreign/tool/path"
                    replace_record(environment_path, environment)
                elif mutation == "hook_even_with_rebound_digest":
                    environment["child_environment"]["RUSTC_WRAPPER"] = "/foreign/wrapper"
                    replace_record(environment_path, environment)
                    request["environment_sha256"] = hashlib.sha256(environment_path.read_bytes()).hexdigest()
                    replace_record(request_path, request)
                elif mutation == "writable":
                    environment_path.chmod(0o600)
                else:
                    os.link(environment_path, self.root / "environment-alias")
                try:
                    with self.assertRaises(release.PrepareError):
                        self.prepare(isolate=must_not_resolve)
                finally:
                    if mutation == "hardlink":
                        (self.root / "environment-alias").unlink()
                    replace_record(environment_path, json.loads(original_environment))
                    replace_record(request_path, json.loads(original_request))

    def test_resume_rejects_changed_compiler_bytes_with_restored_environment(self):
        compiler = self.root / "fixture-rustc"
        compiler.write_bytes(b"original compiler fixture")
        compiler.chmod(0o755)
        def isolate(_root, _source, environment):
            row = {"name": "rustc", **release.verify_tool(
                compiler, hashlib.sha256(compiler.read_bytes()).hexdigest())}
            return dict(environment, CARGO="/fixed/cargo", RUSTC=str(compiler)), [row]
        self.prepare(isolate=isolate)
        compiler.write_bytes(b"changed compiler fixture")
        with patch.dict(os.environ, {"PATH": "/fixture/new-session:/bin"}):
            with self.assertRaisesRegex(release.PrepareError, "different inputs"):
                self.prepare(isolate=isolate)
        self.assertEqual(len(list((self.out / "attempts").iterdir())), 1)

    def test_resume_requires_environment_checkpoint_without_legacy_fallback(self):
        self.prepare()
        self.out.chmod(0o700)
        (self.out / "environment.json").unlink()
        with self.assertRaisesRegex(release.PrepareError, "environment checkpoint"):
            self.prepare()

    def test_resume_without_incremental_override_retains_recorded_zero(self):
        def interrupted(_root, _command, _environment, log):
            log.write_text("fixture interrupted nonincremental build")
            raise release.PrepareError("fixture interrupted nonincremental build")
        with patch.dict(os.environ, {"CARGO_INCREMENTAL": "0"}):
            with self.assertRaisesRegex(release.PrepareError, "interrupted nonincremental"):
                self.prepare(build=interrupted)
        request_before = (self.out / "request.json").read_bytes()
        inherited = {key: value for key, value in os.environ.items() if key != "CARGO_INCREMENTAL"}
        with patch.dict(os.environ, inherited, clear=True):
            result, gate, build = self.prepare()
        self.assertIs(result["native_incremental"], False)
        self.assertEqual((self.out / "request.json").read_bytes(), request_before)
        gate.assert_not_called()
        self.assertEqual(build.call_count, 1)

    def test_resume_rejects_explicit_invalid_incremental_policy_before_tool_resolution(self):
        with patch.dict(os.environ, {"CARGO_INCREMENTAL": "0"}):
            self.prepare()
        def must_not_resolve(*_args):
            self.fail("invalid incremental policy reached compiler resolution")
        for value in ("", "false", "2", "fixture-private-value"):
            with self.subTest(value=value), patch.dict(os.environ, {"CARGO_INCREMENTAL": value}):
                with self.assertRaisesRegex(release.PrepareError, "must be 0 or 1") as rejected:
                    self.prepare(isolate=must_not_resolve)
                self.assertNotIn("fixture-private-value", str(rejected.exception))

    def test_cache_retirement_preserves_false_observation_and_failed_build(self):
        def failed_build(_root, _command, _environment, log):
            log.write_bytes(b"fixture failed build")
            raise release.PrepareError("fixture build failed")
        with self.assertRaisesRegex(release.PrepareError, "fixture build failed"):
            self.prepare(build=failed_build)
        old_checks = (self.out / "checks.json").read_bytes()

        def retire(*_args, before_retire):
            before_retire()
            self.assertFalse((self.out / "checks.json").exists())
            return ["ivm"]

        with self.assertRaisesRegex(release.PrepareError, "fixture build failed"):
            self.prepare(cache_admission=retire, build=failed_build)
        self.assertIs(release.read_record(self.out / "checks.json")["passed"], False)
        self.assertEqual((self.out / "attempts/000002/retired-checks.json").read_bytes(), old_checks)
        result, gate, _build = self.prepare()
        gate.assert_not_called()
        self.assertEqual(result["attempt"], "attempts/000003")

    def test_capture_checkpoint_recovers_missing_final_result_without_build(self):
        real_write = release.write_record
        def fail_final(path, value):
            if path == self.out / "result.json":
                raise OSError("fixture crash before final result")
            real_write(path, value)
        with patch.object(release, "write_record", side_effect=fail_final):
            with self.assertRaisesRegex(OSError, "fixture crash"):
                self.prepare()
        result, gate, build = self.prepare()
        gate.assert_not_called()
        build.assert_not_called()
        self.assertEqual(result["attempt"], "attempts/000001")

    def test_changed_captured_binary_cannot_be_reused_or_trigger_build(self):
        result, _, _ = self.prepare()
        binary = Path(result["artifacts"][0]["path"])
        binary.chmod(0o700)
        binary.write_bytes(elf() + b"changed")
        binary.chmod(0o500)
        with patch.object(release, "run_build") as build:
            with self.assertRaisesRegex(release.PrepareError, "captured artifact changed"):
                self.prepare()
            build.assert_not_called()

    def test_changed_command_cannot_reuse_checkpoint(self):
        self.prepare()
        self.args.expected_commit = "c" * 40
        with self.assertRaisesRegex(release.PrepareError, "different inputs"):
            self.prepare()

    def test_concurrent_prepare_fails_without_waiting_or_breaking_lock(self):
        self.out.mkdir(mode=0o700)
        with release.preparation_lock(self.out):
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.preparation_lock(self.out):
                    self.fail("second writer acquired held lock")

    def test_capacity_groups_same_filesystem_and_exact_boundary(self):
        from types import SimpleNamespace
        with patch.object(release.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=100, f_frsize=1)):
            rows = release.capacity_preflight([(self.target, 60, "build"), (self.out, 40, "capture")])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["required_bytes"], 100)
            with self.assertRaisesRegex(release.PrepareError, "need 101 additional bytes"):
                release.capacity_preflight([(self.target, 60, "build"), (self.out, 41, "capture")])

    def test_low_space_stops_before_output_or_native_gate(self):
        with patch.object(release, "source_lane", side_effect=lambda *_: contextlib.nullcontext((self.source, 88))), \
             patch.object(release, "source_snapshot", return_value=[]), \
             patch.object(release, "verify_signed_source", return_value="b" * 40), \
             patch.object(release, "commit_entries", return_value=b""), \
             patch.object(release, "signed_source_size", return_value=0), \
             patch.object(release, "capture_source", return_value=self.source), \
             patch.object(release, "frozen_snapshot", return_value=[]), \
             patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (dict(env, CARGO="/fixed/cargo"), [])), \
             patch.object(release.shutil, "which", return_value=str(self.zigbuild)), \
             patch.object(release, "capacity_preflight", side_effect=release.PrepareError("insufficient free space")), \
             patch.object(development_gate, "run_checks") as gate:
            with self.assertRaisesRegex(release.PrepareError, "insufficient free space"):
                release.prepare(self.args)
            gate.assert_not_called()
            self.assertFalse(self.out.exists())

    def test_build_progress_only_inspects_elapsed_time_and_log_metadata(self):
        class Child:
            count = 0
            def wait(self, timeout=None):
                self.count += 1
                if self.count == 1:
                    raise subprocess.TimeoutExpired("fixture", timeout)
                return 0
            def poll(self):
                return 0
        log = self.root / "progress.log"
        with patch.object(release.subprocess, "Popen", return_value=Child()) as spawn, \
             patch.object(release, "source_snapshot", side_effect=AssertionError("poll must not hash source")), \
             patch.object(release, "stable_hash_path", side_effect=AssertionError("poll must not hash artifacts")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            release.run_build(self.root, ["fixture"], {}, log, lock_fd=77)
        self.assertIn("Linux build running", output.getvalue())
        self.assertEqual(spawn.call_args.kwargs["pass_fds"], (77,))
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_release_build_child_uses_private_umask_without_changing_parent(self):
        directory, output = self.root / "cargo-profile", self.root / "cargo-profile/.cargo-lock"
        source = (f"import os; os.mkdir({str(directory)!r}, 0o777); "
                  f"os.close(os.open({str(output)!r}, os.O_CREAT|os.O_WRONLY, 0o666))")
        original_umask = os.umask(0o002)
        try:
            release.run_build(self.root, [sys.executable, "-c", source], {}, self.root / "private-build.log")
            self.assertEqual(os.umask(0o002), 0o002)
        finally:
            os.umask(original_umask)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_environment_excludes_secrets_hooks_and_compiler_overrides(self):
        env = release.child_environment({"PATH": "/bin", "HOME": "/fixture",
            "CARGO_TARGET_DIR": "/wrong", "RUSTFLAGS": "bad", "CARGO_PROFILE_RELEASE_LTO": "off",
            "IROHA_GIT_COMMIT_HASH": "stale", "GIT_DIR": "/wrong", "PYTHONPATH": "/untrusted",
            "LD_PRELOAD": "bad", "ONBOARDING_TOKEN": "fixture-private-value",
            "SSH_AUTH_SOCK": "/agent", "SCCACHE_DIR": "/warm/cache"}, self.target)
        self.assertEqual(env["CARGO_TARGET_DIR"], str(self.target))
        self.assertEqual(env["SCCACHE_DIR"], "/warm/cache")
        self.assertEqual(set(env), {"PATH", "HOME", "SCCACHE_DIR", "LC_ALL", "PYTHONNOUSERSITE",
                                    "PYTHONDONTWRITEBYTECODE", "CARGO_TARGET_DIR"})

    def test_preparation_tmpdir_recreates_only_missing_scoped_directory(self):
        parent = self.root / "temporary-parent"
        parent.mkdir()
        parent.chmod(0o1777)
        scoped = parent / "iroha-taira-native-501"
        release.preflight_preparation_tmpdir({"TMPDIR": str(scoped)}, scoped_parent=parent)
        identity = (scoped.stat().st_dev, scoped.stat().st_ino)
        self.assertEqual(stat.S_IMODE(scoped.stat().st_mode), 0o700)
        self.assertEqual(list(scoped.iterdir()), [])
        release.preflight_preparation_tmpdir({"TMPDIR": str(scoped)}, scoped_parent=parent)
        self.assertEqual((scoped.stat().st_dev, scoped.stat().st_ino), identity)
        self.assertEqual(list(scoped.iterdir()), [])

    def test_preparation_tmpdir_rejects_missing_unscoped_and_unsafe_existing(self):
        parent = self.root / "temporary-parent"
        parent.mkdir()
        parent.chmod(0o1777)
        missing = self.root / "arbitrary-missing-directory"
        with self.assertRaisesRegex(release.PrepareError, "TMPDIR does not exist"):
            release.preflight_preparation_tmpdir({"TMPDIR": str(missing)}, scoped_parent=parent)
        self.assertFalse(missing.exists())
        loose = self.root / "loose-directory"
        loose.mkdir(mode=0o755)
        loose.chmod(0o755)
        with self.assertRaisesRegex(release.PrepareError, "owner-held 0700"):
            release.preflight_preparation_tmpdir({"TMPDIR": str(loose)}, scoped_parent=parent)
        self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o755)
        private = self.root / "private-directory"
        private.mkdir(mode=0o700)
        alias = self.root / "symlink-directory"
        alias.symlink_to(private, target_is_directory=True)
        with self.assertRaisesRegex(release.PrepareError, "owner-held 0700"):
            release.preflight_preparation_tmpdir({"TMPDIR": str(alias)}, scoped_parent=parent)
        self.assertTrue(alias.is_symlink())

    def test_preparation_tmpdir_fails_before_git_signature_verification(self):
        missing = self.root / "arbitrary-missing-directory"
        with patch.dict(os.environ, {"TMPDIR": str(missing)}), \
             patch.object(release, "verify_signed_source") as verify:
            with self.assertRaisesRegex(release.PrepareError, "TMPDIR does not exist"):
                release.prepare_in_lane(self.args, self.source, 88, 89)
        verify.assert_not_called()

    def test_native_incremental_admits_only_zero_or_one_without_release_environment_leak(self):
        environment = {"CARGO": "/fixed/cargo", "CARGO_TARGET_DIR": "/warm",
                       "RUSTC_WRAPPER": "/fixed/sccache", "CARGO_BUILD_JOBS": "6"}
        original = dict(environment)
        for inherited, expected in (({}, "1"), ({"CARGO_INCREMENTAL": "1"}, "1"),
                                    ({"CARGO_INCREMENTAL": "0"}, "0")):
            with self.subTest(inherited=inherited):
                native = release.native_check_environment(environment, inherited)
                expected_environment = original | {
                    "CARGO_INCREMENTAL": expected,
                    "CARGO_PROFILE_DEV_SPLIT_DEBUGINFO": "unpacked",
                    "CARGO_PROFILE_TEST_SPLIT_DEBUGINFO": "unpacked",
                }
                if expected == "1":
                    expected_environment.pop("RUSTC_WRAPPER")
                self.assertEqual(native, expected_environment)
                self.assertEqual(environment, original)
        for invalid in ("", "true", "false", "fixture-private-invalid-value"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(release.PrepareError, "must be 0 or 1") as rejected:
                release.native_check_environment(environment, {"CARGO_INCREMENTAL": invalid})
            if invalid:
                self.assertNotIn(invalid, str(rejected.exception))

    def test_prepare_scopes_incremental_to_native_gate_and_binds_resume_preference(self):
        for preference in ("0", "1"):
            with self.subTest(preference=preference):
                self.out = self.root / ("prepared-incremental-" + preference)
                self.args.output_dir = self.out
                def check(_root, *, environment, source_commit, lock_fds,
                          completed_independent_checks, update_independent_checks,
                          completed_pre_network_checks, update_pre_network_checks,
                          qualification_scope):
                    self.assertEqual(environment["CARGO_INCREMENTAL"], preference)
                    self.assertEqual(qualification_scope, "basic")
                    self.assertEqual(environment["CARGO_TARGET_DIR"], str(self.target))
                    self.assertEqual(source_commit, self.args.expected_commit)
                def build(_root, command, environment, log):
                    self.assertNotIn("CARGO_INCREMENTAL", environment)
                    self.assertNotIn("CARGO_PROFILE_TEST_INCREMENTAL", environment)
                    self.assertNotIn("CARGO_PROFILE_DEV_SPLIT_DEBUGINFO", environment)
                    self.assertNotIn("CARGO_PROFILE_TEST_SPLIT_DEBUGINFO", environment)
                    self.assertEqual(command[command.index("--profile") + 1], "release")
                    self.binaries()
                    log.write_bytes(b"fixture compiler output\n")
                with patch.dict(os.environ, {"CARGO_INCREMENTAL": preference}):
                    _, gate, build = self.prepare(check=check, build=build)
                gate.assert_not_called()
                self.assertEqual(build.call_count, 1)
                request = release.read_record(self.out / "request.json")
                result = release.read_record(self.out / "result.json")
                self.assertEqual(request["native_incremental"], preference == "1")
                self.assertEqual(result["native_incremental"], preference == "1")
                # The public transfer consumer reconstructs the immutable result
                # identity from every request field except these three wrappers.
                transfer_base = {key: value for key, value in request.items()
                                 if key not in ("schema", "repo_root", "target_dir")}
                self.assertEqual(set(result), set(transfer_base) | {"artifacts", "timings_seconds", "attempt"})
                self.assertTrue(all(result[key] == value for key, value in transfer_base.items()))
                self.assertEqual(release.read_record(self.out / result["attempt"] / "capture.json"), result)
                with patch.dict(os.environ, {"CARGO_INCREMENTAL": "1" if preference == "0" else "0"}):
                    with self.assertRaisesRegex(release.PrepareError, "checkpoint belongs to different inputs"):
                        self.prepare()

    def test_native_scope_is_bound_to_gate_result_and_resume(self):
        for scope in ("basic", "full"):
            self.args.native_check_scope = scope
            with self.assertRaisesRegex(release.PrepareError, "preparation is build-only"):
                self.prepare()
        self.assertFalse(self.out.exists())

    def test_build_only_captures_unqualified_release_without_running_native_checks(self):
        def forbidden_checks(*_args, **_kwargs):
            self.fail("build-only must not run regression checks")
        result, gate, build = self.prepare(check=forbidden_checks)
        gate.assert_not_called()
        build.assert_called_once()
        request = release.read_record(self.out / "request.json")
        self.assertEqual(request["native_check_scope"], "build-only")
        self.assertEqual(release.read_record(self.out / "checks.json"),
                         {"request": request, "passed": False})
        self.assertFalse(result["release_qualified"])
        self.assertFalse(result["deployed"])
        self.assertEqual(result["native_check_scope"], "build-only")
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertNotIn("native CLI checks", result["timings_seconds"])
        for row in result["artifacts"]:
            self.assertEqual(stat.S_IMODE(Path(row["path"]).stat().st_mode), 0o500)
        self.args.native_check_scope = "basic"
        with self.assertRaisesRegex(release.PrepareError, "preparation is build-only"):
            self.prepare()

    def test_build_only_retains_failed_build_and_retries_without_claiming_native_pass(self):
        def failed_build(_root, _command, _env, log):
            log.write_bytes(b"actual failed fixture build\n")
            raise release.PrepareError("fixture build failed")
        with self.assertRaisesRegex(release.PrepareError, "fixture build failed"):
            self.prepare(build=failed_build)
        request = release.read_record(self.out / "request.json")
        self.assertEqual(release.read_record(self.out / "checks.json"),
                         {"request": request, "passed": False})
        self.assertFalse((self.out / "result.json").exists())
        result, gate, build = self.prepare()
        gate.assert_not_called()
        build.assert_called_once()
        self.assertEqual(result["attempt"], "attempts/000002")
        self.assertEqual((self.out / "attempts/000001/cargo.log").read_bytes(),
                         b"actual failed fixture build\n")

    def test_preparation_cannot_relabel_a_prior_regression_request(self):
        def failed_build(_root, _command, _env, log):
            log.write_bytes(b"failed build\n")
            raise release.PrepareError("failed build")
        with self.assertRaisesRegex(release.PrepareError, "failed build"):
            self.prepare(build=failed_build)
        path = self.out / "request.json"
        request = release.read_record(path)
        request["native_check_scope"] = "basic"
        path.chmod(0o600)
        path.write_bytes(release.canonical_json_bytes(request))
        path.chmod(0o400)
        with self.assertRaisesRegex(release.PrepareError, "checkpoint belongs to different inputs"):
            self.prepare()
        self.assertEqual(release.read_record(path), request)
        self.assertFalse((self.out / "result.json").exists())

    def test_prepare_is_always_build_only_and_check_retains_regression_scopes(self):
        options = ["--expected-commit", self.args.expected_commit,
                   "--expected-signer", self.args.expected_signer,
                   "--output-dir", str(self.out), "--zig", str(self.zig),
                   "--zig-sha256", self.args.zig_sha256,
                   "--cargo-zigbuild", str(self.zigbuild),
                   "--cargo-zigbuild-sha256", self.args.cargo_zigbuild_sha256]
        self.assertEqual(release.parser().parse_args(["prepare", *options]).native_check_scope, "build-only")
        for scope in ("basic", "full"):
            self.assertEqual(release.parser().parse_args(["check", "--native-check-scope", scope]).native_check_scope, scope)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                release.parser().parse_args(["prepare", "--native-check-scope", scope, *options])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            release.parser().parse_args(["prepare", "--build-only", *options])

    def test_build_command_uses_four_fixed_binaries_six_jobs_and_warm_lane(self):
        command = release.build_command(Path("/frozen"), self.target, "/fixed/cargo")
        self.assertEqual(command[:4], ["/fixed/cargo", "zigbuild", "--config", "/frozen/.cargo/config.toml"])
        self.assertEqual(command[4:6], ["--manifest-path", "/frozen/Cargo.toml"])
        self.assertEqual(command.count("--bin"), 4)
        self.assertEqual(command[command.index("--profile") + 1], "release")
        self.assertNotIn("clean", command)

    def test_failed_build_keeps_diagnostic_log(self):
        class FailedChild:
            pid = 123
            def wait(self, timeout=None):
                return 101
            def poll(self):
                return 101
        def spawn(_command, **kwargs):
            os.write(kwargs["stdout"], b"error: fixture compiler failure\n")
            return FailedChild()
        log = self.root / "cargo.log"
        with patch.object(release.subprocess, "Popen", side_effect=spawn) as popen:
            with self.assertRaisesRegex(release.PrepareError, "first error: error: fixture compiler failure"):
                release.run_build(self.root, ["fixture"], {}, log)
        popen.assert_called_once()
        self.assertEqual(log.read_bytes(), b"error: fixture compiler failure\n")
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_failed_build_reports_first_error_without_relaying_later_private_output(self):
        class FailedChild:
            pid = 123
            def wait(self, timeout=None):
                return 101
            def poll(self):
                return 101
        transcript = (b"warning: fixture warning\n"
                      b"\x1b[31merror[E0123]: first compile failure\x1b[0m\n"
                      b"error: later private-secret diagnostic\n")
        def spawn(_command, **kwargs):
            os.write(kwargs["stdout"], transcript)
            return FailedChild()
        log = self.root / "cargo.log"
        with patch.object(release.subprocess, "Popen", side_effect=spawn) as popen, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(release.PrepareError) as caught:
                release.run_build(self.root, ["fixture"], {}, log)
        self.assertEqual(popen.call_count, 1)
        self.assertIn("first error: error[E0123]: first compile failure", str(caught.exception))
        self.assertNotIn("private-secret", str(caught.exception))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(log.read_bytes(), transcript)

    def test_first_build_error_accepts_cargo_json_and_bounds_excerpt(self):
        log = self.root / "cargo.log"
        diagnostic = "first compiler failure " + "x" * 400
        log.write_text(json.dumps({"reason": "compiler-message", "message":
                                   {"level": "warning", "message": "not the failure"}}) + "\n"
                       + json.dumps({"reason": "compiler-message", "message":
                                     {"level": "error", "message": diagnostic}}) + "\n")
        excerpt = release.first_build_error(log)
        self.assertTrue(excerpt.startswith("first compiler failure"))
        self.assertEqual(len(excerpt), 243)
        self.assertTrue(excerpt.endswith("..."))

    def test_unsigned_wrong_repository_branch_or_signer_source_is_rejected(self):
        def response(_root, *args):
            responses = {
                ("rev-parse", "--show-toplevel"): os.fsencode(self.root),
                ("branch", "--show-current"): b"optimizations",
                ("verify-commit", self.args.expected_commit): b"",
                ("rev-parse", self.args.expected_commit + "^{tree}"): b"b" * 40,
                ("show", "--no-patch", "--format=%GF", self.args.expected_commit): self.args.expected_signer.encode(),
            }
            self.assertIn(args, responses, "source selection must never consult mutable HEAD")
            return responses[args]
        failures = [(("rev-parse", "--show-toplevel"), b"/wrong/repository"),
                    (("branch", "--show-current"), b"other"),
                    (("verify-commit", self.args.expected_commit), None),
                    (("show", "--no-patch", "--format=%GF", self.args.expected_commit), b"B" * 40)]
        for command, result in failures:
            def failed(root, *args):
                if args == command:
                    if result is None:
                        raise release.PrepareError("signature verification failed")
                    return result
                return response(root, *args)
            with self.subTest(command=command), patch.object(release, "git", side_effect=failed), \
                 patch.object(release, "verify_controller_sources") as controller:
                with self.assertRaises(release.PrepareError):
                    release.verify_signed_source(self.root, self.args.expected_commit, self.args.expected_signer)
                controller.assert_not_called()
        with patch.object(release, "git", side_effect=response), \
             patch.object(release, "verify_controller_sources") as controller:
            self.assertEqual(release.verify_signed_source(self.root, self.args.expected_commit, self.args.expected_signer), "b" * 40)
            controller.assert_called_once_with(self.root, self.args.expected_commit)

    def test_selected_source_requires_full_commit_and_signer_before_git_reads(self):
        invalid = [(commit, self.args.expected_signer)
                   for commit in ("HEAD", "a" * 39, "A" * 40, "a" * 40 + "^{commit}")]
        invalid += [(self.args.expected_commit, signer)
                    for signer in ("", "a" * 40, "A" * 39, "SHA256:short")]
        for commit, signer in invalid:
            with self.subTest(commit=commit, signer=signer), \
                 patch.object(release, "git") as git, \
                 patch.object(release, "verify_controller_sources") as controller:
                with self.assertRaises(release.PrepareError):
                    release.verify_signed_source(self.root, commit, signer)
                git.assert_not_called()
                controller.assert_not_called()

    def test_snapshot_supports_empty_tracked_files_without_reading_untracked_inputs(self):
        (self.root / "empty").touch()
        (self.root / "source.rs").write_bytes(b"source fixture\n")
        (self.root / "untracked-private").write_bytes(b"do not inspect fixture")
        def blob(payload):
            return hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()
        listing = (f"100644 {blob(b'')} 0\tempty\0"
                   f"100644 {blob((self.root / 'source.rs').read_bytes())} 0\tsource.rs\0")
        with patch.object(release, "git", return_value=listing.encode()):
            snapshot = release.source_snapshot(self.root)
        self.assertEqual([row["path"] for row in snapshot], ["empty", "source.rs"])
        self.assertEqual(snapshot[0]["sha256"], hashlib.sha256(b"").hexdigest())

    def test_real_gitlink_index_allows_only_uninitialized_worktree(self):
        def git(*args):
            subprocess.run(["git", *args], cwd=self.root, check=True,
                           capture_output=True, env=release.child_environment(dict(os.environ), self.target))
        git("init", "--quiet")
        oid = "c" * 40
        git("update-index", "--add", "--cacheinfo", f"160000,{oid},iroha-docs")
        row, = release.source_snapshot(self.root)
        self.assertEqual((row["kind"], row["index_mode"], row["object"], row["checkout"]),
                         ("gitlink", "160000", oid, "absent"))
        link = self.root / "iroha-docs"
        link.mkdir()
        row, = release.source_snapshot(self.root)
        self.assertTrue(row["uninitialized"])
        self.assertEqual(row["checkout"], "empty")
        (link / "Cargo.toml").write_text("untracked submodule build input")
        with self.assertRaisesRegex(release.PrepareError, "uninitialized"):
            release.source_snapshot(self.root)
        (link / "Cargo.toml").unlink()
        link.rmdir()
        link.symlink_to(self.target, target_is_directory=True)
        with self.assertRaisesRegex(release.PrepareError, "uninitialized"):
            release.source_snapshot(self.root)
        link.unlink()
        git("update-index", "--cacheinfo", f"160000,{'d' * 40},iroha-docs")
        changed, = release.source_snapshot(self.root)
        self.assertNotEqual(changed["object"], row["object"])

    def test_index_merge_stages_are_rejected(self):
        with patch.object(release, "git", return_value=f"100644 {'a' * 40} 2\tsource.rs\0".encode()):
            with self.assertRaisesRegex(release.PrepareError, "merge stage"):
                release.source_snapshot(self.root)

    def fixture_git(self, *args, payload=None):
        return subprocess.run(["git", *args], cwd=self.root, check=True, input=payload,
                              capture_output=True,
                              env=release.child_environment(dict(os.environ), self.target)).stdout.strip()

    def controller_fixture(self):
        self.fixture_git("init", "--quiet", "--initial-branch=optimizations")
        files = {name: (b"committed controller fixture: " + name.encode() + b"\n")
                 for name in release.BUILD_SOURCES}
        files.update({name: b"# original captured Python fixture\n"
                      for name in release.CAPTURED_GATE_SOURCES})
        files["scripts/formal/rust_text.py"] += b"def mask_rust_comments(text): return text\n"
        files.update({"source.rs": b"committed build input\n", ".gitignore": b"target/\n"})
        for name, payload in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o755 if name.endswith(".sh") else 0o644)
        self.fixture_git("add", "--", *files)
        commit = self.commit_controller_fixture("committed preparation fixture")
        self.args.repo_root = self.root
        self.args.expected_commit = commit
        self.out = self.target / "prepared"
        self.args.output_dir = self.out
        return commit, files

    def commit_controller_fixture(self, message):
        tree = self.fixture_git("write-tree")
        parent = self.fixture_git("for-each-ref", "--format=%(objectname)", "refs/heads/optimizations")
        payload = b"tree " + tree + b"\n"
        if parent:
            payload += b"parent " + parent + b"\n"
        identity = b"Preparation Fixture <fixture@example.invalid> 1700000000 +0000\n"
        payload += b"author " + identity + b"committer " + identity + b"\n" + message.encode() + b"\n"
        commit = self.fixture_git("hash-object", "-t", "commit", "-w", "--stdin", payload=payload).decode()
        self.fixture_git("update-ref", "refs/heads/optimizations", commit, parent.decode() if parent else "0" * 40)
        return commit

    @contextlib.contextmanager
    def fixture_signature(self, commit):
        actual_git = release.git
        def verified_git(root, *args):
            if args == ("verify-commit", commit):
                return b""
            if args == ("show", "--no-patch", "--format=%GF", commit):
                return self.args.expected_signer.encode()
            return actual_git(root, *args)
        # The disposable commit is deliberately unsigned. Every source/tree/index
        # read is real Git; only the independent signature decision is stubbed.
        with patch.object(release, "git", side_effect=verified_git):
            yield

    def prepare_controller_fixture(self, commit, *, check=None, native_gate_from_capture=False, through_cli=False):
        def build(_root, _command, _env, log, **_kwargs):
            self.binaries()
            log.write_bytes(b"fixture compiler output\n")
        with self.fixture_signature(commit), \
             patch.object(release, "__file__", str(self.root / "scripts/taira_release.py")), \
             patch.object(release, "verify_controller_module_origins"), \
             patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (dict(env, CARGO="/fixed/cargo"), [])), \
             patch.object(release.shutil, "which", return_value=str(self.zigbuild)), \
             (contextlib.nullcontext() if native_gate_from_capture else \
              patch.object(release, "captured_gate", return_value=development_gate)), \
             patch.object(release, "local_package_names", return_value=set()), \
             patch.object(release, "admit_source_fingerprints", return_value=[]), \
             patch.object(release, "source_fingerprints", side_effect=lambda *_a, **_k: contextlib.nullcontext([])), \
             patch.object(development_gate, "run_checks", side_effect=check), \
             patch.object(release, "run_build", side_effect=build), \
             patch.object(release, "capacity_preflight", return_value=[]), \
             patch.object(release, "system_native_linker_paths", return_value=tuple(self.native_tools)), \
             contextlib.redirect_stdout(io.StringIO()):
            return release.main() if through_cli else release.prepare(self.args)

    def test_fresh_prepare_selects_signed_objects_before_unrelated_head_and_worktree_changes(self):
        commit, files = self.controller_fixture()
        source = self.root / "source.rs"
        source.write_bytes(b"unrelated later committed input\n")
        later_only = self.root / "later-only.rs"
        later_only.write_bytes(b"input absent from selected commit\n")
        self.fixture_git("add", "--", source.name, later_only.name)
        advanced = self.commit_controller_fixture("unrelated HEAD before fresh preparation")
        self.assertNotEqual(advanced, commit)
        source.write_bytes(b"unrelated staged edit\n")
        self.fixture_git("add", "--", source.name)
        source.write_bytes(b"unrelated unstaged edit after staging\n")
        untracked = self.root / "untracked-private-wip"
        untracked.write_bytes(b"unrelated untracked fixture\n")
        before_status = self.fixture_git("status", "--porcelain=v1", "--untracked-files=all")
        before_index = (self.root / ".git/index").read_bytes()
        before = {path: (path.read_bytes(), release.file_identity(path.lstat()))
                  for path in (source, untracked)}
        observed = []
        def check(root, **kwargs):
            observed.append(root)
            self.assertEqual(kwargs["source_commit"], commit)
            self.assertEqual((root / "source.rs").read_bytes(), files["source.rs"])
            self.assertFalse((root / untracked.name).exists())
            self.assertFalse((root / later_only.name).exists())
        result = self.prepare_controller_fixture(commit, check=check)
        self.assertEqual(observed, [])
        captured = Path(result["source_root"])
        self.assertEqual((captured / "source.rs").read_bytes(), files["source.rs"])
        self.assertFalse((captured / untracked.name).exists())
        self.assertFalse((captured / later_only.name).exists())
        self.assertEqual(result["commit"], commit)
        self.assertEqual(result["tree"], self.fixture_git("rev-parse", commit + "^{tree}").decode())
        self.assertEqual(self.fixture_git("rev-parse", "HEAD").decode(), advanced)
        self.assertEqual((self.root / ".git/index").read_bytes(), before_index)
        self.assertEqual({path: (path.read_bytes(), release.file_identity(path.lstat()))
                          for path in before}, before)
        self.assertEqual(self.fixture_git("status", "--porcelain=v1", "--untracked-files=all"), before_status)

    def test_prepare_cli_does_not_import_a_mutable_gate_with_side_effects(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("taira_release.py", "taira_cargo_cache.py", "taira_cargo_artifact.py", "release_artifact_contract.py"):
            (scripts / name).write_bytes((SCRIPT.parent / name).read_bytes())
        marker = self.root / "mutable-gate-executed"
        (scripts / "taira_release_check.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
            "raise RuntimeError('mutable gate executed before preparation')\n")
        arguments = [sys.executable, "-B", str(scripts / "taira_release.py"), "prepare",
                     "--repo-root", str(self.root), "--target-dir", str(self.target),
                     "--expected-commit", "not-a-commit", "--expected-signer", "A" * 40,
                     "--output-dir", str(self.target / "not-created"), "--zig", str(self.zig),
                     "--zig-sha256", self.args.zig_sha256,
                     "--cargo-zigbuild", str(self.zigbuild),
                     "--cargo-zigbuild-sha256", self.args.cargo_zigbuild_sha256]
        result = subprocess.run(arguments, cwd="/", capture_output=True, text=True, timeout=10,
                                env=release.child_environment(dict(os.environ), self.target))
        self.assertEqual(result.returncode, 1)
        self.assertIn("expected commit must be a full lowercase Git object ID", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.out.exists())


    def test_missing_signed_native_gate_or_inventory_is_rejected_before_capture(self):
        self.controller_fixture()
        for relative in release.CAPTURED_GATE_SOURCES:
            with self.subTest(relative=relative):
                self.assertIn(relative, release.BUILD_SOURCES)
                self.assertNotIn(relative, release.BOOTSTRAP_SOURCES)
                self.fixture_git("update-index", "--force-remove", relative)
                commit = self.commit_controller_fixture("missing selected gate dependency fixture")
                self.args.expected_commit = commit
                with self.fixture_signature(commit), \
                     patch.object(release, "verify_controller_module_origins"), \
                     self.assertRaisesRegex(release.PrepareError, "missing a required build controller source"):
                    release.verify_signed_source(self.root, commit, self.args.expected_signer)
                self.fixture_git("add", "--", relative)

    def test_controller_drift_is_rejected_before_capture_even_when_staged_or_hidden(self):
        commit, files = self.controller_fixture()
        relative = "scripts/taira_cargo_cache.py"
        controller = self.root / relative
        original = files[relative]
        self.fixture_git("config", "core.filemode", "false")
        for change in ("unstaged", "staged", "mode", "assume-unchanged", "skip-worktree"):
            with self.subTest(change=change):
                controller.write_bytes(original)
                controller.chmod(0o644)
                self.fixture_git("add", "--", relative)
                if change in ("assume-unchanged", "skip-worktree"):
                    self.fixture_git("update-index", "--" + change, "--", relative)
                if change == "mode":
                    controller.chmod(0o755)
                else:
                    controller.write_bytes(original + b"uncommitted controller change\n")
                if change == "staged":
                    self.fixture_git("add", "--", relative)
                if change == "mode":
                    # Low-level diff-files can report a stale stat cache after
                    # chmod even when filemode is ignored. Confirm unchanged
                    # bytes through Git before asserting this hidden drift.
                    self.fixture_git("update-index", "--refresh", "--", relative)
                if change in ("mode", "assume-unchanged", "skip-worktree"):
                    self.fixture_git("diff-files", "--quiet", "--", relative)
                with patch.object(release, "capture_source") as capture:
                    with self.assertRaises(release.PrepareError):
                        self.prepare_controller_fixture(commit)
                    capture.assert_not_called()
                self.assertFalse(self.out.exists())
                if change in ("assume-unchanged", "skip-worktree"):
                    self.fixture_git("update-index", "--no-" + change, "--", relative)

    def test_resume_keeps_pinned_commit_after_unrelated_head_advances_but_requires_matching_controller(self):
        commit, files = self.controller_fixture()
        prepared = self.prepare_controller_fixture(commit)
        (self.root / "source.rs").write_bytes(b"later unrelated committed build input\n")
        self.fixture_git("add", "--", "source.rs")
        advanced = self.commit_controller_fixture("unrelated later commit")
        self.assertNotEqual(advanced, commit)
        resumed = self.prepare_controller_fixture(commit, check=AssertionError("completed preparation reran native checks"))
        self.assertEqual(resumed, prepared)
        self.assertEqual((Path(resumed["source_root"]) / "source.rs").read_bytes(), files["source.rs"])
        with self.fixture_signature(commit), patch.object(release, "verify_controller_module_origins"):
            self.assertEqual(release.verify_signed_source(self.root, commit, self.args.expected_signer),
                             self.fixture_git("rev-parse", commit + "^{tree}").decode())
            relative = "scripts/taira_cargo_cache.py"
            (self.root / relative).write_bytes(files[relative] + b"later controller change\n")
            self.fixture_git("add", "--", relative)
            self.commit_controller_fixture("changed controller in later commit")
            with self.assertRaises(release.PrepareError):
                release.verify_signed_source(self.root, commit, self.args.expected_signer)

    def test_controller_module_origins_reject_shadow_package(self):
        modules = {}
        for name in ("release_artifact_contract", "taira_cargo_cache", "taira_cargo_artifact"):
            module = types.ModuleType(name)
            module.__file__ = str(self.root / "scripts" / (name + ".py"))
            module.__spec__ = importlib.util.spec_from_file_location(name, module.__file__)
            modules[name] = module
        entrypoint = types.ModuleType("__main__")
        entrypoint.__file__ = str(self.root / "scripts/taira_release.py")
        modules["__main__"] = entrypoint
        with patch.object(release.sys, "modules", modules):
            release.verify_controller_module_origins(self.root)
            for name in tuple(modules):
                with self.subTest(module=name):
                    shadow = types.ModuleType(name)
                    shadow.__file__ = str(self.root / "scripts" / name / "__init__.py")
                    shadow.__spec__ = importlib.util.spec_from_file_location(name, shadow.__file__)
                    with patch.dict(modules, {name: shadow}), self.assertRaises(release.PrepareError):
                        release.verify_controller_module_origins(self.root)

    def test_signed_source_size_uses_committed_objects_and_rejects_mismatched_entries(self):
        commit, files = self.controller_fixture()
        (self.root / "empty").touch()
        (self.root / "source-link").symlink_to("source.rs")
        self.fixture_git("add", "--", "empty", "source-link")
        self.fixture_git("update-index", "--add", "--cacheinfo", f"160000,{'c' * 40},iroha-docs")
        commit = self.commit_controller_fixture("committed sizing fixture")
        entries = release.commit_entries(self.root, commit)
        (self.root / "source.rs").write_bytes(b"unrelated WIP size" * 1000)
        expected_size = sum(map(len, files.values())) + len(b"source.rs")
        self.assertEqual(release.signed_source_size(self.root, commit, entries), expected_size)
        for mismatch in (
            entries.replace(b"\tsource.rs\0", b"\tother.rs\0"),
            entries.replace(b"100644 ", b"100755 ", 1),
            entries.replace(entries.split(b" ", 2)[1], b"d" * 40, 1),
            entries + entries.split(b"\0", 1)[0] + b"\0",
        ):
            with self.subTest(entries=mismatch), self.assertRaises(release.PrepareError):
                release.signed_source_size(self.root, commit, mismatch)

    def test_git_reads_original_object_even_when_replacement_ref_exists(self):
        self.fixture_git("init", "--quiet")
        original = self.fixture_git("hash-object", "-w", "--stdin", payload=b"original fixture").decode()
        replacement = self.fixture_git("hash-object", "-w", "--stdin", payload=b"replacement fixture").decode()
        self.fixture_git("replace", original, replacement)
        self.assertEqual(self.fixture_git("cat-file", "-p", original), b"replacement fixture")
        self.assertEqual(release.git(self.root, "cat-file", "-p", original), b"original fixture")

    def test_snapshot_rejects_bytes_hidden_by_git_index_flags(self):
        self.fixture_git("init", "--quiet")
        source = self.root / "source.rs"
        original = b"original source fixture"
        source.write_bytes(original)
        self.fixture_git("add", "--", source.name)
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.fixture_git("update-index", "--" + flag, "--", source.name)
                source.write_bytes(b"concealed compiler input")
                # Demonstrate Git's ordinary working-tree diff reports no change.
                self.fixture_git("diff-files", "--quiet", "--", source.name)
                with self.assertRaisesRegex(release.PrepareError, "bytes differ from the index"):
                    release.source_snapshot(self.root)
                source.write_bytes(original)
                self.fixture_git("update-index", "--no-" + flag, "--", source.name)
        release.source_snapshot(self.root)

    def test_snapshot_rejects_executable_mode_ignored_by_git(self):
        self.fixture_git("init", "--quiet")
        source = self.root / "source.rs"
        source.write_bytes(b"source fixture")
        source.chmod(0o644)
        self.fixture_git("add", "--", source.name)
        self.fixture_git("config", "core.filemode", "false")
        source.chmod(0o755)
        self.fixture_git("diff", "--quiet", "--", source.name)
        with self.assertRaisesRegex(release.PrepareError, "mode differs from the index"):
            release.source_snapshot(self.root)


    def source_entries(self, files):
        self.fixture_git("init", "--quiet")
        rows = []
        for name, (mode, payload) in sorted(files.items()):
            oid = ("c" * 40 if mode == "160000" else
                   self.fixture_git("hash-object", "-w", "--stdin", payload=payload).decode())
            rows.append(f"{mode} {oid} 0\t{name}".encode())
        return b"\0".join(rows) + b"\0"

    def test_prepare_cli_creates_private_source_lane_under_permissive_umask(self):
        arguments = [sys.executable, "-B", str(SCRIPT), "prepare",
                     "--target-dir", str(self.target), "--expected-commit", "not-a-commit",
                     "--expected-signer", "A" * 40, "--output-dir", str(self.out),
                     "--zig", str(self.zig), "--zig-sha256", self.args.zig_sha256,
                     "--cargo-zigbuild", str(self.zigbuild),
                     "--cargo-zigbuild-sha256", self.args.cargo_zigbuild_sha256]
        result = subprocess.run(arguments, cwd=SCRIPT.parent.parent, capture_output=True,
                                text=True, timeout=10, umask=0o002)
        self.assertEqual(result.returncode, 1)
        self.assertIn("expected commit must be a full lowercase Git object ID", result.stderr)
        self.assertNotIn("world-writable", result.stderr)
        key = hashlib.sha256(os.fsencode(self.target)).hexdigest()[:24]
        for path in (self.target / ".taira-build-lane", self.target / "taira-release-sources",
                     self.target / "taira-release-sources" / key):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), self.target_mode)
        self.assertFalse(self.out.exists())

    def test_source_lane_and_nested_capture_are_private_before_freeze_under_permissive_umask(self):
        entries = self.source_entries({"crates/deep/module/source.rs": ("100644", b"signed source"),
                                       "nested/modules/iroha-docs": ("160000", b"")})
        seal = release.PrivateSourceTree.seal
        observed = []
        def checked_seal(writer, previous, unchanged):
            for relative in writer.directories:
                path = writer.root / relative
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                observed.append(path)
            return seal(writer, previous, unchanged)
        original_umask = os.umask(0o002)
        try:
            with release.source_lane(self.root, self.target) as (source, _fd), \
                 patch.object(release.PrivateSourceTree, "seal", new=checked_seal):
                self.assertEqual(stat.S_IMODE(source.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(source.parent.parent.stat().st_mode), 0o700)
                release.capture_source(self.root, source, self.target, "a" * 40, entries)
                self.assertEqual((source / "crates/deep/module/source.rs").read_bytes(), b"signed source")
                release.frozen_snapshot(source, entries, self.target)
            self.assertEqual(os.umask(0o002), 0o002)
        finally:
            os.umask(original_umask)
        self.assertGreaterEqual(len(observed), 7)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), self.target_mode)

    def test_source_lane_refuses_existing_shared_parent_without_changing_it(self):
        parent = self.target / "taira-release-sources"
        parent.mkdir(mode=0o775)
        parent.chmod(0o775)
        with self.assertRaises(release.ReleaseArtifactError):
            with release.source_lane(self.root, self.target):
                self.fail("unsafe existing parent was admitted")
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o775)
        self.assertEqual(list(parent.iterdir()), [])

    @unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() != 0,
                         'Darwin directory publication requires a non-root native filesystem test')
    def test_darwin_readonly_directory_rename_and_real_signed_source_publication(self):
        stage = self.root / 'native-readonly-directory'
        stage.mkdir(mode=0o700)
        stage.chmod(0o500)
        try:
            os.rename(stage, self.root / 'native-readonly-published')
        except PermissionError:
            # The approved deployment Mac refuses this rename. Some Darwin
            # filesystems permit it; publication must work on both natively.
            stage.chmod(0o700)
            os.rename(stage, self.root / 'native-readonly-published')
        self.assertTrue((self.root / 'native-readonly-published').is_dir())
        commit, files = self.controller_fixture()
        key = self.root / 'fixture-ssh-signing-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True, capture_output=True, timeout=10)
        allowed = self.root / 'fixture-allowed-signers'
        allowed.write_bytes(b'fixture@example.invalid ' + key.with_suffix('.pub').read_bytes())
        for name, value in [('gpg.format', 'ssh'), ('user.signingkey', str(key)),
                            ('gpg.ssh.allowedSignersFile', str(allowed))]:
            self.fixture_git('config', name, value)
        self.fixture_git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '--allow-empty', '-S', '-m', 'real native signed source')
        commit = self.fixture_git('rev-parse', 'HEAD').decode()
        release.git(self.root, 'verify-commit', commit)
        self.assertTrue(release.git(self.root, 'show', '--no-patch', '--format=%GF', commit))
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, commit,
                                   release.commit_entries(self.root, commit))
            self.assertEqual((source / 'source.rs').read_bytes(), files['source.rs'])
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o500)
            self.assertEqual(release.read_record(source.parent / 'source-state.json'), {'commit': commit})

    def test_source_publication_keeps_original_root_fd_until_readonly_checkpoint(self):
        entries = self.source_entries({'deep/source.rs': ('100644', b'committed source')})
        publish, record = release.publish_directory_noreplace, release.write_record
        held = []
        with release.source_lane(self.root, self.target) as (source, _):
            def observe_publish(stage, destination, **kwargs):
                self.assertEqual(destination, source)
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((stage / 'deep').stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE((stage / 'deep/source.rs').stat().st_mode), 0o400)
                fd = os.dup(kwargs['stage_fd'])
                held.append(fd)
                self.assertEqual(release.file_identity(os.fstat(fd)), release.file_identity(stage.lstat()))
                return publish(stage, destination, **kwargs)
            def observe_checkpoint(path, value):
                if path.name.startswith('source-state.pending-'):
                    self.assertEqual(stat.S_IMODE(os.fstat(held[0]).st_mode), 0o500)
                    self.assertEqual(release.file_identity(os.fstat(held[0])),
                                     release.file_identity(source.lstat()))
                return record(path, value)
            try:
                with patch.object(release, 'publish_directory_noreplace', side_effect=observe_publish), \
                     patch.object(release, 'write_record', side_effect=observe_checkpoint):
                    release.capture_source(self.root, source, self.target, 'a' * 40, entries)
                release.frozen_snapshot(source, entries, self.target)
            finally:
                for fd in held:
                    os.close(fd)

    def test_source_root_substitution_before_publication_never_creates_checkpoint(self):
        entries = self.source_entries({'deep/source': ('100644', b'original')})
        publish = release.PrivateSourceTree.publish
        foreign = []
        with release.source_lane(self.root, self.target) as (source, _):
            def substitute(writer, destination):
                original = writer.root
                original.rename(original.with_name(original.name + '-original'))
                original.mkdir(mode=0o700)
                (original / 'foreign').write_bytes(b'preserve foreign root')
                foreign.append(original)
                return publish(writer, destination)
            with patch.object(release.PrivateSourceTree, 'publish', new=substitute), \
                 self.assertRaisesRegex(release.PrepareError, 'replaced|custody changed'):
                release.capture_source(self.root, source, self.target, 'a' * 40, entries)
            self.assertFalse(source.exists())
            self.assertFalse((source.parent / 'source-state.json').exists())
            self.assertFalse(list(source.parent.glob('source-state.pending-*')))
            self.assertEqual(stat.S_IMODE(foreign[0].stat().st_mode), 0o700)
            self.assertEqual((foreign[0] / 'foreign').read_bytes(), b'preserve foreign root')

    def test_source_root_substitution_during_final_freeze_never_creates_checkpoint(self):
        entries = self.source_entries({'deep/source': ('100644', b'original')})
        fsync = release.os.fsync
        attacked = False
        with release.source_lane(self.root, self.target) as (source, _):
            def substitute(fd):
                nonlocal attacked
                info = os.fstat(fd)
                if (not attacked and source.exists() and stat.S_ISDIR(info.st_mode)
                        and info.st_ino == source.stat().st_ino
                        and stat.S_IMODE(info.st_mode) == 0o500):
                    attacked = True
                    os.fchmod(fd, 0o700)
                    source.rename(source.with_name('original-published-source'))
                    os.fchmod(fd, 0o500)
                    source.mkdir(mode=0o700)
                    (source / 'foreign').write_bytes(b'preserve replacement')
                fsync(fd)
            with patch.object(release.os, 'fsync', side_effect=substitute), \
                 self.assertRaisesRegex(release.PrepareError, 'replaced|custody changed'):
                release.capture_source(self.root, source, self.target, 'a' * 40, entries)
            self.assertTrue(attacked)
            self.assertFalse((source.parent / 'source-state.json').exists())
            self.assertFalse(list(source.parent.glob('source-state.pending-*')))
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o700)
            self.assertEqual((source / 'foreign').read_bytes(), b'preserve replacement')

    def test_source_publication_refuses_even_empty_concurrent_destination(self):
        entries = self.source_entries({'source': ('100644', b'original')})
        publish = release.PrivateSourceTree.publish
        with release.source_lane(self.root, self.target) as (source, _):
            def occupy(writer, destination):
                destination.mkdir(mode=0o700)
                return publish(writer, destination)
            with patch.object(release.PrivateSourceTree, 'publish', new=occupy), \
                 self.assertRaises(release.ReleaseArtifactError):
                release.capture_source(self.root, source, self.target, 'a' * 40, entries)
            self.assertEqual(list(source.iterdir()), [])
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o700)
            self.assertFalse((source.parent / 'source-state.json').exists())

    def test_fixed_capture_reads_git_objects_and_survives_working_source_changes(self):
        entries = self.source_entries({"source.rs": ("100644", b"signed source"),
                                       "run.sh": ("100755", b"#!/bin/sh\nexit 0\n"),
                                       "iroha-docs": ("160000", b"")})
        (self.root / "source.rs").write_bytes(b"concurrent unsaved edit")
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            self.assertEqual((source / "source.rs").read_bytes(), b"signed source")
            self.assertEqual(stat.S_IMODE((source / "run.sh").stat().st_mode), 0o500)
            subprocess.run([str(source / "run.sh")], check=True)
            self.assertFalse((source / ".git").exists())
            self.assertEqual(list((source / "iroha-docs").iterdir()), [])
            (self.root / "source.rs").write_bytes(b"another unrelated merge")
            self.assertEqual(release.capture_source(self.root, source, self.target, "a" * 40, entries), source)
            release.frozen_snapshot(source, entries, self.target)

    def test_capture_refreshes_real_commit_tree_add_remove_rename_and_path_kinds(self):
        commit, files = self.controller_fixture()
        unchanged = next(iter(release.BUILD_SOURCES))
        stamp = 1_600_000_000_123_456_789
        warm = self.target / "warm-artifact"
        warm.write_bytes(b"preserve compiler cache")
        with release.source_lane(self.root, self.target) as (source, _):
            def capture(revision):
                # Real Git objects/tree selection; the independent signature
                # decision uses the existing explicit fixture boundary.
                with self.fixture_signature(revision), \
                     patch.object(release, "verify_controller_module_origins"):
                    release.verify_signed_source(self.root, revision, self.args.expected_signer)
                entries = release.commit_entries(self.root, revision)
                self.assertEqual(release.capture_source(
                    self.root, source, self.target, revision, entries), source)
                release.frozen_snapshot(source, entries, self.target)
                self.assertEqual(release.read_record(source.parent / "source-state.json"),
                                 {"commit": revision})
                self.assertEqual(list(source.parent.glob("source.retained-*")), [])
                self.assertEqual(list(source.parent.glob("source.pending-*")), [])
                self.assertEqual(warm.read_bytes(), b"preserve compiler cache")
            capture(commit)
            os.utime(source / unchanged, ns=(stamp, stamp))
            for operation in ("add", "remove", "rename", "file-to-directory", "directory-to-file"):
                with self.subTest(operation=operation):
                    if operation == "add":
                        added = self.root / "new-directory/added.rs"
                        added.parent.mkdir(mode=0o700)
                        added.write_bytes(b"new signed tree input")
                        self.fixture_git("add", "--", "new-directory/added.rs")
                    elif operation == "remove":
                        self.fixture_git("rm", "--", "new-directory/added.rs")
                    elif operation == "rename":
                        self.fixture_git("mv", "--", "source.rs", "renamed.rs")
                    elif operation == "file-to-directory":
                        self.fixture_git("rm", "--", "renamed.rs")
                        (self.root / "renamed.rs").mkdir(mode=0o700)
                        (self.root / "renamed.rs/child.rs").write_bytes(b"nested replacement")
                        self.fixture_git("add", "--", "renamed.rs/child.rs")
                    else:
                        self.fixture_git("rm", "--", "renamed.rs/child.rs")
                        if (self.root / "renamed.rs").exists():
                            (self.root / "renamed.rs").rmdir()
                        (self.root / "renamed.rs").write_bytes(b"file replacement")
                        self.fixture_git("add", "--", "renamed.rs")
                    capture(self.commit_controller_fixture(operation))
                    self.assertEqual((source / unchanged).stat().st_mtime_ns, stamp)
                    self.assertEqual((source / unchanged).read_bytes(), files[unchanged])
            self.assertEqual((source / "renamed.rs").read_bytes(), b"file replacement")
            self.assertFalse((source / "source.rs").exists())
            self.assertFalse((source / "new-directory").exists())

    def test_new_tree_refresh_refuses_corrupted_previous_capture_before_mutation(self):
        commit, files = self.controller_fixture()
        before = release.commit_entries(self.root, commit)
        (self.root / "added.rs").write_bytes(b"new committed input")
        self.fixture_git("add", "--", "added.rs")
        successor = self.commit_controller_fixture("added source")
        after = release.commit_entries(self.root, successor)
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, commit, before)
            original_inode = source.stat().st_ino
            captured = source / "source.rs"
            for corruption in ("missing", "bytes", "extra", "output-binding"):
                with self.subTest(corruption=corruption):
                    source.chmod(0o700)
                    if corruption == "missing":
                        captured.unlink()
                    elif corruption == "bytes":
                        captured.chmod(0o600)
                        captured.write_bytes(b"untrusted replacement")
                        captured.chmod(0o400)
                    elif corruption == "extra":
                        (source / "unknown-input").write_bytes(b"must not retire")
                    else:
                        (source / "target").unlink()
                        (source / "target").symlink_to(self.root, target_is_directory=True)
                    source.chmod(0o500)
                    with patch.object(release, "create_fresh_directory") as create, \
                         patch.object(release.os, "rename") as rename:
                        with self.assertRaises((release.PrepareError, FileNotFoundError)):
                            release.capture_source(self.root, source, self.target, successor, after)
                        create.assert_not_called()
                        rename.assert_not_called()
                    self.assertEqual(source.stat().st_ino, original_inode)
                    self.assertEqual(release.read_record(source.parent / "source-state.json"),
                                     {"commit": commit})
                    source.chmod(0o700)
                    if corruption in ("missing", "bytes"):
                        if captured.exists():
                            captured.chmod(0o600)
                        captured.write_bytes(files["source.rs"])
                        captured.chmod(0o400)
                    elif corruption == "extra":
                        self.assertEqual((source / "unknown-input").read_bytes(), b"must not retire")
                        (source / "unknown-input").unlink()
                    else:
                        (source / "target").unlink()
                        (source / "target").symlink_to(self.target, target_is_directory=True)
                    source.chmod(0o500)
                    release.frozen_snapshot(source, before, self.target)

    def test_capture_probe_preserves_nonstructural_io_errors_and_same_commit_missing_input(self):
        entries = self.source_entries({"source.rs": ("100644", b"source")})
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            for error in (PermissionError("read denied"), OSError(5, "input/output error")):
                with self.subTest(error=type(error).__name__), \
                     patch.object(release, "frozen_snapshot", side_effect=error), \
                     patch.object(release, "commit_entries") as previous, \
                     patch.object(release, "create_fresh_directory") as create:
                    with self.assertRaises(type(error)) as failure:
                        release.capture_source(self.root, source, self.target, "b" * 40, entries)
                    self.assertIs(failure.exception, error)
                    previous.assert_not_called()
                    create.assert_not_called()
            source.chmod(0o700)
            (source / "source.rs").unlink()
            source.chmod(0o500)
            with patch.object(release, "commit_entries") as previous, \
                 patch.object(release, "create_fresh_directory") as create:
                with self.assertRaises(FileNotFoundError):
                    release.capture_source(self.root, source, self.target, "a" * 40, entries)
                previous.assert_not_called()
                create.assert_not_called()

    def test_watched_subtrees_preserve_times_and_changed_ancestors_invalidate(self):
        first = {'vendor/pq/src/lib.rs': ('100644', b'unchanged'),
                 'vendor/pq/cfiles/c.c': ('100644', b'unchanged C'),
                 'core/mod.rs': ('100644', b'old')}
        before = self.source_entries(first)
        stamp = 1_600_000_000_123_456_789
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, 'a' * 40, before)
            for relative in ['vendor', 'vendor/pq', 'vendor/pq/src', 'vendor/pq/cfiles', 'core']:
                os.utime(source / relative, ns=(stamp, stamp))
            after = self.source_entries({**first, 'core/mod.rs': ('100644', b'new')})
            with patch.object(release, 'commit_entries', return_value=before):
                release.capture_source(self.root, source, self.target, 'b' * 40, after)
            for relative in ['vendor', 'vendor/pq', 'vendor/pq/src', 'vendor/pq/cfiles']:
                self.assertEqual((source / relative).stat().st_mtime_ns, stamp)
            self.assertNotEqual((source / 'core').stat().st_mtime_ns, stamp)
            release.frozen_snapshot(source, after, self.target)

    def test_file_add_remove_mode_symlink_and_gitlink_changes_invalidate_parents(self):
        initial = {'a/source': ('100644', b'payload'),
                   'b/link': ('120000', b'../a/source'),
                   'submodule': ('160000', b'')}
        before = self.source_entries(initial)
        identical = release.unchanged_source_directories(before, before)
        self.assertIn(Path('a'), identical)
        self.assertIn(Path('b'), identical)
        self.assertIn(Path('submodule'), identical)
        variants = [
            ({**initial, 'a/extra': ('100644', b'new')}, 'a'),
            ({k:v for k,v in initial.items() if k != 'a/source'}, 'a'),
            ({**initial, 'a/source': ('100755', b'payload')}, 'a'),
            ({**initial, 'b/link': ('120000', b'../a/other')}, 'b'),
        ]
        for files, parent in variants:
            with self.subTest(parent=parent, files=list(files)):
                after = self.source_entries(files)
                unchanged = release.unchanged_source_directories(before, after)
                self.assertNotIn(Path(parent), unchanged)
                self.assertNotIn(Path('.'), unchanged)
        changed_gitlink = before.replace(b'160000 ' + b'c' * 40, b'160000 ' + b'd' * 40)
        self.assertNotIn(Path('submodule'), release.unchanged_source_directories(before, changed_gitlink))


    def test_lane_path_and_unchanged_mtimes_survive_next_commit(self):
        entries = self.source_entries({"same.rs": ("100644", b"same"), "edit.rs": ("100644", b"old")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            unchanged_mtime = (source / "same.rs").stat().st_mtime_ns
            original = source
        updated = self.source_entries({"same.rs": ("100644", b"same"), "edit.rs": ("100644", b"new")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            with patch.object(release, "commit_entries", return_value=entries):
                release.capture_source(self.root, source, self.target, "b" * 40, updated)
            self.assertEqual(source, original)
            self.assertEqual((source / "same.rs").stat().st_mtime_ns, unchanged_mtime)
            self.assertEqual((source / "edit.rs").read_bytes(), b"new")
            self.assertEqual(list(source.parent.glob("source.retained-*")), [])

    def test_successful_refresh_retires_only_its_previous_source_and_keeps_warm_target(self):
        entries = self.source_entries({"nested/source.rs": ("100644", b"old"),
                                       "source-link": ("120000", b"nested/source.rs"),
                                       "iroha-docs": ("160000", b"")})
        warm = self.target / "warm-artifact"
        warm.write_bytes(b"preserve compiler cache")
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            interrupted = source.parent / ("source.retained-" + "f" * 32)
            interrupted.mkdir()
            (interrupted / "unknown").write_bytes(b"preserve failed attempt")
            pending = source.parent / "source.pending-unfinished"
            pending.mkdir()
            (pending / "unknown").write_bytes(b"preserve partial capture")
            previous = entries
            for revision, payload in (("b", b"second"), ("c", b"third")):
                updated = self.source_entries({"nested/source.rs": ("100644", payload),
                                               "source-link": ("120000", b"nested/source.rs"),
                                               "iroha-docs": ("160000", b"")})
                with patch.object(release, "commit_entries", return_value=previous):
                    release.capture_source(self.root, source, self.target, revision * 40, updated)
                self.assertEqual(list(source.parent.glob("source.retained-*")), [interrupted])
                self.assertEqual((source / "source-link").read_bytes(), payload)
                self.assertEqual(release.read_record(source.parent / "source-state.json"),
                                 {"commit": revision * 40})
                previous = updated
            self.assertEqual(warm.read_bytes(), b"preserve compiler cache")
            self.assertEqual((interrupted / "unknown").read_bytes(), b"preserve failed attempt")
            self.assertEqual((pending / "unknown").read_bytes(), b"preserve partial capture")

    def test_retirement_rejects_unknown_inputs_without_deleting_them(self):
        entries = self.source_entries({"source.rs": ("100644", b"old")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            updated = self.source_entries({"source.rs": ("100644", b"new")})
            retire = release.retire_source_capture
            def inject_unknown(retained, old_entries, target):
                self.assertEqual(release.read_record(source.parent / "source-state.json"),
                                 {"commit": "b" * 40})
                retained.chmod(0o700)
                (retained / "unknown").write_bytes(b"must survive")
                retained.chmod(0o500)
                retire(retained, old_entries, target)
            with patch.object(release, "commit_entries", return_value=entries), \
                 patch.object(release, "retire_source_capture", side_effect=inject_unknown):
                with self.assertRaisesRegex(release.PrepareError, "extra inputs"):
                    release.capture_source(self.root, source, self.target, "b" * 40, updated)
            retained, = source.parent.glob("source.retained-*")
            self.assertEqual((retained / "unknown").read_bytes(), b"must survive")
            self.assertEqual((retained / "source.rs").read_bytes(), b"old")
            self.assertEqual((source / "source.rs").read_bytes(), b"new")

    def test_checkpoint_publication_failure_retains_previous_source_for_recovery(self):
        entries = self.source_entries({"source.rs": ("100644", b"old")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            updated = self.source_entries({"source.rs": ("100644", b"new")})
            with patch.object(release, "commit_entries", return_value=entries), \
                 patch.object(release.os, "replace", side_effect=OSError("fixture checkpoint failure")), \
                 patch.object(release, "retire_source_capture") as retire:
                with self.assertRaisesRegex(OSError, "checkpoint failure"):
                    release.capture_source(self.root, source, self.target, "b" * 40, updated)
                retire.assert_not_called()
            retained, = source.parent.glob("source.retained-*")
            self.assertEqual((retained / "source.rs").read_bytes(), b"old")
            self.assertEqual(release.read_record(source.parent / "source-state.json"),
                             {"commit": "a" * 40})
            release.capture_source(self.root, source, self.target, "b" * 40, updated)
            self.assertEqual(release.read_record(source.parent / "source-state.json"),
                             {"commit": "b" * 40})
            self.assertTrue(retained.is_dir())

    def test_retirement_cannot_select_current_source(self):
        entries = self.source_entries({"source.rs": ("100644", b"current")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            with self.assertRaisesRegex(release.PrepareError, "superseded source"):
                release.retire_source_capture(source, entries, self.target)
            self.assertEqual((source / "source.rs").read_bytes(), b"current")

    def test_captured_source_tampering_or_extra_files_cannot_resume(self):
        entries = self.source_entries({"source.rs": ("100644", b"signed")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            source.chmod(0o700)
            (source / "injected.rs").write_bytes(b"untracked build input")
            source.chmod(0o500)
            with self.assertRaisesRegex(release.PrepareError, "extra inputs"):
                release.capture_source(self.root, source, self.target, "a" * 40, entries)

    def test_capture_rejects_escaping_symlink_before_publication(self):
        entries = self.source_entries({"escape": ("120000", b"../../outside")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            with self.assertRaisesRegex(release.PrepareError, "symlink escapes"):
                release.capture_source(self.root, source, self.target, "a" * 40, entries)
            self.assertFalse(source.exists())

    def test_source_refresh_recovers_after_old_directory_was_retained(self):
        entries = self.source_entries({"source.rs": ("100644", b"old")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            updated = self.source_entries({"source.rs": ("100644", b"new")})
            publish = release.publish_directory_noreplace
            def fail_publication(src, dst, **kwargs):
                if Path(dst) == source:
                    raise OSError("fixture interrupted source publication")
                return publish(src, dst, **kwargs)
            with patch.object(release, "publish_directory_noreplace", side_effect=fail_publication), \
                 patch.object(release, "commit_entries", return_value=entries):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    release.capture_source(self.root, source, self.target, "b" * 40, updated)
            self.assertFalse(source.exists())
            release.capture_source(self.root, source, self.target, "b" * 40, updated)
            self.assertEqual((source / "source.rs").read_bytes(), b"new")
            self.assertTrue(list(source.parent.glob("source.retained-*")))

    def test_source_lane_blocks_another_output_until_owner_releases_it(self):
        with release.source_lane(self.root, self.target):
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.source_lane(self.root, self.target):
                    self.fail("another preparation replaced a live source lane")

    def test_working_checkout_is_never_rechecked_after_capture(self):
        def check(*_args, **kwargs):
            guard = patch.object(release, "source_snapshot", side_effect=AssertionError("mutable source read"))
            guard.start()
            self.addCleanup(guard.stop)
            self.assertEqual(kwargs["source_commit"], self.args.expected_commit)
            self.assertEqual(kwargs["lock_fds"][1], 88)
        result, _, build = self.prepare(check=check)
        self.assertEqual(build.call_args.args[0], self.source)
        self.assertEqual(result["source_root"], str(self.source))

    def test_frozen_native_fixture_output_uses_only_the_exact_warm_target(self):
        entries = self.source_entries({"crates/iroha_cli/source.rs": ("100644", b"signed")})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            before = release.frozen_snapshot(source, entries, self.target)
            fixture = source / "crates/iroha_cli/../../target/disposable-native-fixture"
            fixture.mkdir()
            (fixture / "generated").write_bytes(b"fixture output, never inventoried")
            self.assertEqual(before, release.frozen_snapshot(source, entries, self.target))
            self.assertTrue((self.target / "disposable-native-fixture/generated").is_file())
            self.assertNotIn("target", [row["path"] for row in before])
            source.chmod(0o700)
            (source / "target").unlink()
            (source / "target").symlink_to(self.root, target_is_directory=True)
            source.chmod(0o500)
            with self.assertRaisesRegex(release.PrepareError, "output binding differs"):
                release.frozen_snapshot(source, entries, self.target)

    def test_native_gate_selection_is_loaded_from_verified_captured_source(self):
        code = b"SELECTION = _captured_native_inventory['SELECTION']\n"
        payloads = {"scripts/taira_release_check.py": code,
                    "scripts/taira_native_test_inventory.py": b"SELECTION = ('captured regression',)\n",
                    "scripts/formal/rust_text.py": b"def mask_rust_comments(text): return text\n"}
        entries = self.source_entries({path: ("100644", payload) for path, payload in payloads.items()})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            before = release.frozen_snapshot(source, entries, self.target)
            (self.root / "scripts").mkdir()
            for relative in payloads:
                (self.root / relative).parent.mkdir(exist_ok=True)
                (self.root / relative).write_text("raise RuntimeError('mutable dependency must not execute')")
            selected = release.captured_gate(source, before)
            self.assertEqual(selected.SELECTION, ("captured regression",))
            for relative, original in payloads.items():
                with self.subTest(relative=relative):
                    captured = source / relative
                    marker = self.target / "altered-captured-dependency-executed"
                    captured.chmod(0o600)
                    captured.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
                    captured.chmod(0o400)
                    with self.assertRaisesRegex(release.PrepareError, "captured native gate changed"):
                        release.captured_gate(source, before)
                    self.assertFalse(marker.exists())
                    captured.chmod(0o600)
                    captured.write_bytes(original)
                    captured.chmod(0o400)
                    with self.assertRaisesRegex(release.PrepareError, "dependency is absent"):
                        release.captured_gate(source, [row for row in before if row['path'] != relative])

    def test_captured_native_inventory_uses_verified_bytes_after_path_substitution(self):
        payloads = {relative: (SCRIPT.parent.parent / relative).read_bytes()
                    for relative in release.CAPTURED_GATE_SOURCES}
        entries = self.source_entries({path: ("100644", payload) for path, payload in payloads.items()})
        with release.source_lane(self.root, self.target) as (source, _fd):
            release.capture_source(self.root, source, self.target, "a" * 40, entries)
            before = release.frozen_snapshot(source, entries, self.target)
            original_open = release.stable_open_relative
            for relative in release.CAPTURED_GATE_SOURCES[1:]:
                with self.subTest(relative=relative):
                    dependency = source / relative
                    marker = self.target / "unverified-dependency-executed"
                    substituted = []

                    @contextlib.contextmanager
                    def substitute_after_capture(*args, **kwargs):
                        with original_open(*args, **kwargs) as descriptor:
                            yield descriptor
                        if Path(args[0]) / args[1] == dependency:
                            dependency.chmod(0o600)
                            dependency.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
                            dependency.chmod(0o400)
                            substituted.append(dependency)

                    with patch.object(release, "stable_open_relative", side_effect=substitute_after_capture):
                        selected = release.captured_gate(source, before)
                    self.assertEqual(substituted, [dependency])
                    self.assertEqual(selected.native_owner_stages("native durable archive recovery"),
                                     development_gate.native_owner_stages("native durable archive recovery"))
                    mask = selected._native_inventory["rust_source_masker"](source)
                    self.assertEqual(mask("// comment\nfn source() {}"), "          \nfn source() {}")
                    self.assertFalse(marker.exists())
                    self.assertNotEqual(dependency.read_bytes(), payloads[relative])
                    dependency.chmod(0o600)
                    dependency.write_bytes(payloads[relative])
                    dependency.chmod(0o400)

    def test_captured_gate_never_reopens_inventory_when_retained_owner_is_absent(self):
        path = SCRIPT.with_name("taira_release_check.py")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("no path fallback")):
            with self.assertRaises(NameError):
                exec(compile(path.read_text(), str(path), "exec"),
                     {"__name__": "taira_captured_release_check", "__file__": str(path)})

    def test_captured_inventory_never_reopens_masker_when_retained_owner_is_absent(self):
        path = SCRIPT.with_name("taira_native_test_inventory.py")
        namespace = {"__name__": "taira_captured_native_inventory", "__file__": str(path)}
        exec(compile(path.read_text(), str(path), "exec"), namespace)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("no path fallback")):
            with self.assertRaises(NameError):
                namespace["rust_source_masker"](self.root)

    def test_isolated_cargo_ignores_home_and_ancestor_configuration(self):
        self.source.mkdir()
        (self.source / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.93.1"\n')
        home = self.root / "home"
        cache = home / ".cargo"
        cache.mkdir(parents=True)
        for name in ("registry", "git"):
            (cache / name).mkdir()
        (cache / "config.toml").write_text('this fixture config must never be parsed')
        env = release.child_environment({"HOME": str(home), "PATH": "/fixture", "RUSTFLAGS": "injected"}, self.target)
        with patch.object(release.subprocess, "check_output", return_value=str(self.zig) + "\n"), \
             patch.object(release.shutil, "which", return_value=None):
            selected, tools = release.isolated_cargo_environment(self.root, self.source, env)
            reused, _ = release.isolated_cargo_environment(self.root, self.source, env)
        self.assertEqual(selected, reused)
        self.assertEqual(selected["CARGO_BUILD_JOBS"], "6")
        self.assertEqual(selected["CARGO_TARGET_DIR"], str(self.target))
        self.assertNotIn("RUSTFLAGS", selected)
        isolated = Path(selected["CARGO_HOME"])
        self.assertNotEqual(isolated, cache)
        self.assertEqual((isolated / "registry").resolve(), cache / "registry")
        self.assertFalse((isolated / "config.toml").exists())
        command = release.build_command(self.source, self.target, selected["CARGO"])
        self.assertEqual(command[2:4], ["--config", str(self.source / ".cargo/config.toml")])
        class Child:
            def wait(self, timeout=None): return 0
        with patch.object(release.subprocess, "Popen", return_value=Child()) as spawn:
            release.run_build(self.source, command, selected, self.root / "isolated.log", lock_fd=77, lane_lock_fd=88, mode_lock_fd=99)
        self.assertEqual(spawn.call_args.kwargs["cwd"], "/")
        self.assertEqual(spawn.call_args.kwargs["pass_fds"], (77, 88, 99))


    def test_cache_initialization_closes_inheritable_lane_and_session_descriptors(self):
        observations = self.root / "cache-observation.json"
        cache = self.root / "sccache-fixture"
        cache.write_text(
            "#!" + sys.executable + "\n"
            "import json,os,sys\n"
            "seen=[]\n"
            "for fd in range(3,256):\n"
            " try:\n"
            "  info=os.fstat(fd);seen.append([info.st_dev,info.st_ino])\n"
            " except OSError:pass\n"
            "with open(" + repr(str(observations)) + ", 'w') as output:\n"
            " json.dump({'args':sys.argv[1:],'idle':os.environ.get('SCCACHE_IDLE_TIMEOUT'),'seen':seen},output)\n"
        )
        cache.chmod(0o755)
        env = release.child_environment(dict(os.environ), self.target)
        env.update(RUSTC_WRAPPER=str(cache), RUSTC=str(self.zig), SCCACHE_IDLE_TIMEOUT="600")
        with contextlib.ExitStack() as stack:
            held = []
            for name in ("mode", "source", "session"):
                directory = self.root / name
                directory.mkdir(mode=0o700)
                fd = stack.enter_context(release.preparation_lock(directory))
                os.set_inheritable(fd, True)
                held.append((fd, os.fstat(fd)))
            for _ in range(2):
                release.initialize_compiler_cache(env)
                observed = json.loads(observations.read_text())
                self.assertEqual(observed["args"], [str(self.zig), "--version"])
                self.assertEqual(observed["idle"], "0")
                for fd, info in held:
                    self.assertNotIn([info.st_dev, info.st_ino], observed["seen"])
                    self.assertEqual(os.fstat(fd).st_ino, info.st_ino)
                # The cache probe must not unlock the parent's live build custody.
                with self.assertRaisesRegex(release.PrepareError, "still running"):
                    with release.preparation_lock(self.root / "mode"):
                        self.fail("cache startup released the Cargo lane")

    def test_cache_initialization_failure_cannot_silently_continue_without_custody(self):
        env = {"RUSTC_WRAPPER": "/fixture/sccache", "RUSTC": "/fixture/rustc"}
        for failure in (subprocess.CompletedProcess([], 1),
                        subprocess.TimeoutExpired(["sccache"], 30), OSError("fixture failure")):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(release.subprocess, "run", side_effect=failure if isinstance(failure, Exception) else None,
                              return_value=failure) as run, \
                 self.assertRaisesRegex(release.PrepareError, "before Cargo"):
                release.initialize_compiler_cache(dict(env))
            self.assertEqual(run.call_args.args[0], ["/fixture/sccache", "/fixture/rustc", "--version"])
            self.assertTrue(run.call_args.kwargs["close_fds"])
            self.assertNotIn("pass_fds", run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_no_cache_wrapper_does_not_launch_a_cache_server(self):
        with patch.object(release.subprocess, "run") as run:
            release.initialize_compiler_cache({"RUSTC": "/fixture/rustc"})
        run.assert_not_called()

    def development_paths(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / "target").mkdir()
        routine = release.routine_target(repo)
        routine.mkdir(parents=True)
        return repo, routine

    def llvm_tools(self):
        directory = self.root / "llvm-tools"
        directory.mkdir()
        tools = []
        for role, name, alias in (("compiler", "clang", "clang-18"), ("linker", "lld", "ld.lld-18")):
            real = directory / name
            real.write_bytes(("disposable " + role).encode())
            real.chmod(0o755)
            invocation = directory / alias
            invocation.symlink_to(real)
            tools.append((role, invocation, real))
        return tuple(tools)

    def test_system_linker_preserves_native_environment_without_resolving_tools(self):
        environment = {"CARGO": "/fixed/cargo", "CARGO_TARGET_DIR": "/warm", "CARGO_INCREMENTAL": "0"}
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform), patch.object(release.sys, "platform", platform), \
                 patch.object(release, "stable_hash_path") as tool_hash, \
                 patch.object(Path, "resolve") as resolve:
                selected = release.development_linker_environment(environment, "system")
                self.assertEqual(selected, environment)
                self.assertIsNot(selected, environment)
                tool_hash.assert_not_called()
                resolve.assert_not_called()

    def test_explicit_llvm_rejects_darwin_before_tool_inspection(self):
        with patch.object(release.sys, "platform", "darwin"), \
             patch.object(release, "stable_hash_path") as tool_hash:
            with self.assertRaisesRegex(release.PrepareError, "only for Linux development checks"):
                release.development_linker_environment({}, "llvm")
            tool_hash.assert_not_called()

    def test_llvm_selection_has_fixed_paths_exact_flags_and_reported_stable_identities(self):
        self.assertEqual(release.LINUX_NATIVE_LLVM_TOOL_PATHS, (
            ("compiler", Path("/usr/bin/clang-18"), Path("/usr/lib/llvm-18/bin/clang")),
            ("linker", Path("/usr/bin/ld.lld-18"), Path("/usr/lib/llvm-18/bin/lld")),
        ))
        tools = self.llvm_tools()
        environment = {"CARGO": "/fixed/cargo", "CARGO_TARGET_DIR": "/warm"}
        output = io.StringIO()
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
             contextlib.redirect_stdout(output):
            selected = release.development_linker_environment(environment, "llvm")
        self.assertEqual(selected, environment | {
            "RUSTFLAGS": f"-Clinker={tools[0][2]} -Clink-arg=-fuse-ld={tools[1][1]}"})
        self.assertNotIn("RUSTFLAGS", environment)
        identity = json.loads(output.getvalue().splitlines()[0].split("llvm: ", 1)[1])
        for role, invocation, path in tools:
            self.assertEqual(identity[role], {"invocation": str(invocation), "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
        self.assertIn("one-time dependency rebuild", output.getvalue())
        self.assertIn("switching back invalidates it again", output.getvalue())

    def test_default_and_explicit_llvm_missing_tools_stop_before_native_build_or_tests(self):
        repo, routine = self.development_paths()
        tools = self.llvm_tools()
        for broken_index in (0, 1):
            for state in ("missing", "nonexecutable"):
                broken = tools[broken_index][2]
                if state == "missing":
                    saved = broken.with_suffix(".saved")
                    broken.rename(saved)
                else:
                    broken.chmod(0o600)
                try:
                    for preference in (None, "llvm"):
                        for focused in (None, ("cli=" + development_gate.STAGES[0][1][0],)):
                            with self.subTest(tool=broken_index, state=state, preference=preference, focused=bool(focused)), \
                                 patch.object(release.sys, "platform", "linux"), \
                                 patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
                                 patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
                                 patch.object(development_gate, "run_checks") as check, \
                                 patch.object(development_gate, "run_prequalification") as prequalify, \
                                 contextlib.redirect_stdout(io.StringIO()):
                                with self.assertRaisesRegex(release.PrepareError, "missing" if state == "missing" else "not executable") as failed:
                                    release.development_check(repo, routine, {}, native_linker=preference, focused_regressions=focused)
                                self.assertIn(str(tools[broken_index][1]), str(failed.exception))
                                self.assertIn("clang-18" if broken_index == 0 else "lld-18", str(failed.exception))
                                self.assertEqual("--native-linker system" in str(failed.exception), broken_index == 1)
                                check.assert_not_called()
                                prequalify.assert_not_called()
                finally:
                    if state == "missing":
                        saved.rename(broken)
                    broken.chmod(0o755)

    def test_llvm_rejects_retargeted_or_unsafe_installed_tools(self):
        tools = self.llvm_tools()
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools):
            tools[1][1].unlink()
            tools[1][1].symlink_to(tools[0][2])
            with self.assertRaisesRegex(release.PrepareError, "fixed installed path"):
                release.development_linker_environment({}, "llvm")
            tools[1][1].unlink()
            tools[1][1].symlink_to(tools[1][2])
            tools[1][2].chmod(0o777)
            with self.assertRaisesRegex(release.ReleaseArtifactError, "group- or world-writable"):
                release.development_linker_environment({}, "llvm")

    def test_explicit_llvm_reaches_only_development_gate_after_sanitization_with_same_lane(self):
        repo, routine = self.development_paths()
        tools = self.llvm_tools()
        for focused in (None, ("cli=" + development_gate.STAGES[0][1][0],)):
            held = []
            def check(root, *, environment, lock_fds, **options):
                self.assertEqual(root, repo)
                self.assertEqual(environment["CARGO_TARGET_DIR"], str(routine))
                self.assertEqual(environment["RUSTFLAGS"],
                    f"-Clinker={tools[0][2]} -Clink-arg=-fuse-ld={tools[1][1]}")
                self.assertNotIn("PRIVATE_KEY", environment)
                self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", environment)
                self.assertNotIn("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", environment)
                self.assertEqual(options["qualification_scope"], "full")
                if focused:
                    self.assertEqual(options["focused_regressions"], focused)
                held.extend(lock_fds)
                self.assertEqual(len(lock_fds), 1)
                with self.assertRaisesRegex(release.PrepareError, "still running"):
                    with release.cargo_lane(repo, routine, "development"):
                        self.fail("LLVM selection must preserve the lane lock")
            with self.subTest(focused=bool(focused)), patch.object(release.sys, "platform", "linux"), \
                 patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
                 patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
                 patch.object(development_gate, "run_checks", side_effect=check) as full, \
                 patch.object(development_gate, "run_prequalification", side_effect=check) as selected, \
                 contextlib.redirect_stdout(io.StringIO()):
                release.development_check(repo, routine, {"PRIVATE_KEY": "never forward", "RUSTFLAGS": "bad",
                    "CARGO_ENCODED_RUSTFLAGS": "bad", "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "bad"},
                    native_linker="llvm", focused_regressions=focused, native_check_scope="full")
                self.assertEqual((full.call_count, selected.call_count), (0, 1) if focused else (1, 0))
            with self.assertRaises(OSError):
                os.fstat(held[0])

    def test_development_default_routes_linux_to_llvm_and_darwin_to_system(self):
        repo, routine = self.development_paths()
        tools = self.llvm_tools()
        for platform in ("linux", "darwin"):
            for focused in (None, ("cli=" + development_gate.STAGES[0][1][0],)):
                with self.subTest(platform=platform, focused=bool(focused)), \
                     patch.object(release.sys, "platform", platform), \
                     patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
                     patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
                     patch.object(development_gate, "run_checks") as check, \
                     patch.object(development_gate, "run_prequalification") as prequalify, \
                     contextlib.redirect_stdout(io.StringIO()):
                    release.development_check(repo, routine, {}, focused_regressions=focused)
                selected = prequalify if focused else check
                selected.assert_called_once()
                (check if focused else prequalify).assert_not_called()
                environment = selected.call_args.kwargs["environment"]
                self.assertEqual(environment["CARGO_TARGET_DIR"], str(routine))
                if platform == "linux":
                    self.assertEqual(environment["RUSTFLAGS"],
                        f"-Clinker={tools[0][2]} -Clink-arg=-fuse-ld={tools[1][1]}")
                else:
                    self.assertNotIn("RUSTFLAGS", environment)

    def test_linux_explicit_system_runs_when_llvm_tools_are_absent(self):
        repo, routine = self.development_paths()
        tools = self.llvm_tools()
        for _, _, path in tools:
            path.unlink()
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
             patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
             patch.object(development_gate, "run_checks") as check, \
             contextlib.redirect_stdout(io.StringIO()):
            release.development_check(repo, routine, {}, native_linker="system")
        check.assert_called_once()
        self.assertNotIn("RUSTFLAGS", check.call_args.kwargs["environment"])

    def test_both_check_clis_forward_platform_default_and_explicit_native_linker_with_focus(self):
        focus = "cli=" + development_gate.STAGES[0][1][0]
        for platform, default in (("linux", "llvm"), ("darwin", "system")):
            for entrypoint in ("release", "gate"):
                for preference in (None, "system", "llvm"):
                    for focused in (False, True):
                        argv = (["taira_release.py", "check"] if entrypoint == "release" else ["taira_release_check.py"])
                        if preference:
                            argv.extend(("--native-linker", preference))
                        if focused:
                            argv.extend(("--focus-regression", focus))
                        with self.subTest(platform=platform, entrypoint=entrypoint, preference=preference, focused=focused), \
                             patch.dict(sys.modules, {"taira_release": release}), \
                             patch.object(release.sys, "platform", platform), \
                             patch.object(release.sys, "argv", argv), \
                             patch.object(release, "development_check") as check:
                            self.assertEqual((release.main if entrypoint == "release" else development_gate.main)(), 0)
                        expected = {"native_check_scope": "basic", "native_linker": preference or default}
                        if focused:
                            expected["focused_regressions"] = (focus,)
                        self.assertEqual(check.call_args.kwargs, expected)

    def test_prepare_accepts_native_linker_and_scopes_exact_flags_to_native_gate(self):
        arguments = ["prepare", "--expected-commit", "a" * 40, "--expected-signer", "A" * 40,
                     "--output-dir", str(self.out), "--zig", str(self.zig), "--zig-sha256", "a" * 64,
                     "--cargo-zigbuild", str(self.zigbuild), "--cargo-zigbuild-sha256", "b" * 64]
        for platform, default in (("linux", "llvm"), ("darwin", "system")):
            with patch.object(release.sys, "platform", platform):
                self.assertEqual(release.parser().parse_args(arguments).native_linker, default)
                for preference in ("system", "llvm"):
                    self.assertEqual(release.parser().parse_args(arguments + ["--native-linker", preference]).native_linker, preference)
        def check(_root, *, environment, **_kwargs):
            self.assertNotIn("RUSTFLAGS", environment)
            self.assertEqual(environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"), [
                f"-Clinker={self.native_tools[0][2]}", f"-Clink-arg=-fuse-ld={self.native_tools[1][1]}"])
            self.assertNotIn("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", environment)
        def build(_root, _command, environment, log):
            self.assertFalse(any(name in environment for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "NATIVE_LINKER")))
            self.binaries()
            log.write_bytes(b"fixture compiler output\n")
        with patch.object(release, "development_linker_environment", side_effect=AssertionError("prepare reached mutable workflow")), \
             patch.dict(os.environ, {"NATIVE_LINKER": "llvm", "RUSTFLAGS": "bad", "CARGO_ENCODED_RUSTFLAGS": "bad",
                                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "bad"}):
            result, _, _ = self.prepare(check=check, build=build)
        identity = result["native_linker"]
        self.assertEqual(identity["preference"], "system")
        self.assertEqual(identity["platform"], sys.platform)
        for role, invocation, path in self.native_tools:
            self.assertEqual(identity["tools"][role], {"invocation": str(invocation), "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
        self.assertEqual(release.read_record(self.out / "request.json")["native_linker"], identity)

    def test_prepare_linux_llvm_uses_shared_exact_resolver_and_never_falls_back(self):
        tools = self.llvm_tools()
        self.args.native_linker = "llvm"
        observed = []
        actual_environment = release.preparation_native_environment
        def observe_environment(environment, linker):
            value = actual_environment(environment, linker)
            observed.append(value["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"))
            return value
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
             patch.object(release, "preparation_native_environment", side_effect=observe_environment):
            result, gate, _ = self.prepare()
            gate.assert_not_called()
            self.assertEqual(observed, [[f"-Clinker={tools[0][2]}", f"-Clink-arg=-fuse-ld={tools[1][1]}"]])
            self.assertEqual(result["native_linker"]["preference"], "llvm")
            tools[1][2].unlink()
            with self.assertRaisesRegex(release.PrepareError, "requires installed LLVM 18"):
                self.prepare(check=AssertionError("missing linker resumed checks"), build=AssertionError("missing linker built"))

    def test_prepare_native_tool_changes_before_resume_reject_completed_capture(self):
        for role, _invocation, path in self.native_tools:
            with self.subTest(role=role):
                self.args.output_dir = self.root / ("prepared-" + role)
                self.out = self.args.output_dir
                self.prepare()
                old = path.read_bytes()
                path.write_bytes(old + b" changed")
                with self.assertRaisesRegex(release.PrepareError, "checkpoint belongs to different inputs"):
                    self.prepare(check=AssertionError("changed tool resumed checks"), build=AssertionError("changed tool built"))
                path.write_bytes(old)

    def test_prepare_native_tool_change_during_gate_or_build_never_publishes_success(self):
        for stage in ("cache", "build"):
            with self.subTest(stage=stage):
                self.out = self.root / ("changed-during-" + stage)
                self.args.output_dir = self.out
                path = self.native_tools[1][2]
                old = path.read_bytes()
                def check(_root, **_kwargs):
                    if stage == "gate": path.write_bytes(old + b" changed")
                def build(_root, _command, _env, log):
                    self.binaries()
                    log.write_bytes(b"fixture compiler output\n")
                    path.write_bytes(old + b" changed")
                with self.assertRaisesRegex(release.PrepareError, "native linker choice or tool identity changed"):
                    self.prepare(check=check, build=build, cache_admission=(
                        lambda *_a, **_k: path.write_bytes(old + b" changed")) if stage == "cache" else None)
                if stage != "build":
                    self.assertFalse((self.out / "checks.json").exists())
                self.assertFalse((self.out / "result.json").exists())
                self.assertFalse(any((self.out / "attempts").glob("*/capture.json")))
                path.write_bytes(old)

    def test_prepare_native_invocation_retarget_rejects_same_bytes_on_resume(self):
        role, original, _ = self.native_tools[1]
        alias = self.root / "native-linker-alias"
        alias.symlink_to(original)
        alternate = self.root / "native-linker-alternate"
        alternate.write_bytes(original.read_bytes())
        alternate.chmod(0o755)
        self.native_tools[1] = (role, alias, original)
        def resolve():
            return tuple((role, invocation, invocation.resolve(strict=True))
                         for role, invocation, _ in self.native_tools)
        self.prepare(native_paths=resolve)
        alias.unlink()
        alias.symlink_to(alternate)
        with self.assertRaisesRegex(release.PrepareError, "checkpoint belongs to different inputs"):
            self.prepare(native_paths=resolve, check=AssertionError("retargeted linker resumed checks"))

    def test_prepared_native_linux_system_keeps_fixed_clang_driver(self):
        tools = self.llvm_tools()
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools), \
             patch.object(Path, "resolve", return_value=Path("/fixed/system-ld")):
            paths = release.system_native_linker_paths()
        self.assertEqual(paths, (tools[0], ("linker", Path("/usr/bin/ld"), Path("/fixed/system-ld"))))

    def test_prepare_native_choice_change_does_not_reuse_successful_checkpoint(self):
        tools = self.llvm_tools()
        with patch.object(release.sys, "platform", "linux"), \
             patch.object(release, "LINUX_NATIVE_LLVM_TOOL_PATHS", tools):
            self.prepare()
            self.args.native_linker = "llvm"
            with self.assertRaisesRegex(release.PrepareError, "checkpoint belongs to different inputs"):
                self.prepare(check=AssertionError("choice changed but checks resumed"))

    def test_prepared_native_system_resolves_apple_tools_and_preserves_spaces(self):
        directory = self.root / "Xcode Beta.app"
        directory.mkdir()
        paths = [directory / name for name in ("clang", "ld")]
        for path in paths:
            path.write_bytes(b"fixture Apple executable")
            path.chmod(0o755)
        with patch.object(release.sys, "platform", "darwin"), \
             patch.object(release.subprocess, "check_output", side_effect=[str(path) + "\n" for path in paths]) as find:
            identity = release.preparation_native_linker("system")
        self.assertEqual([call.args[0] for call in find.call_args_list], [
            ["/usr/bin/xcrun", "--find", "clang"], ["/usr/bin/xcrun", "--find", "ld"]])
        self.assertEqual(release.preparation_native_environment({}, identity)["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"),
                         [f"-Clinker={paths[0]}", f"-Clink-arg=-fuse-ld={paths[1]}"])
        with patch.object(release.sys, "platform", "darwin"), self.assertRaisesRegex(release.PrepareError, "only on Linux"):
            release.preparation_native_linker("llvm")

    def test_development_target_defaults_and_explicit_selectors_must_agree(self):
        repo, routine = self.development_paths()
        self.assertEqual(release.development_target(repo, None, {"CARGO_TARGET_DIR": str(repo / "target")}), routine)
        selected = {"TAIRA_TESTNET_CARGO_TARGET_DIR": str(self.target)}
        self.assertEqual(release.development_target(repo, None, selected), self.target)
        self.assertEqual(release.development_target(repo, self.target, selected), self.target)
        with self.assertRaisesRegex(release.PrepareError, "conflicts"):
            release.development_target(repo, routine, selected)
        with self.assertRaisesRegex(release.PrepareError, "empty"):
            release.development_target(repo, None, {"TAIRA_TESTNET_CARGO_TARGET_DIR": ""})

    def test_missing_and_symlinked_development_target_never_create_lane(self):
        repo, _ = self.development_paths()
        missing = self.root / "missing"
        linked = self.root / "linked"
        linked.symlink_to(self.target, target_is_directory=True)
        for selected in (missing, linked):
            with self.subTest(selected=selected), self.assertRaises((OSError, release.PrepareError)):
                release.development_check(repo, selected, {})
        self.assertFalse(missing.exists())

    def test_reserved_and_marked_lanes_reject_mode_switches(self):
        repo, routine = self.development_paths()
        for lane, role in ((repo / "target", "development"), (routine, "release")):
            with self.subTest(lane=lane), self.assertRaises(release.PrepareError):
                with release.cargo_lane(repo, lane, role):
                    self.fail("must reject reserved lane")
            self.assertFalse((lane / ".taira-build-lane").exists())
        for original, changed in (("development", "release"), ("release", "development")):
            lane = self.root / original
            lane.mkdir()
            with release.cargo_lane(repo, lane, original):
                pass
            with self.assertRaisesRegex(release.PrepareError, "different build mode"):
                with release.cargo_lane(repo, lane, changed):
                    self.fail("must reject role switch")

    def test_existing_capture_lane_rejects_development_without_new_marker(self):
        repo, _ = self.development_paths()
        capture = self.target / "taira-release-sources"
        capture.mkdir()
        for lane in (self.target, capture):
            with self.assertRaisesRegex(release.PrepareError, "authenticated release lane"):
                with release.cargo_lane(repo, lane, "development"):
                    self.fail("must reject captured source lane")
            self.assertFalse((lane / ".taira-build-lane").exists())

    def test_lane_lock_is_held_through_the_gate_and_target_mode_is_unchanged(self):
        repo, routine = self.development_paths()
        target_mode = stat.S_IMODE(routine.stat().st_mode)
        descriptors = []
        def run(root, *, environment, lock_fds, qualification_scope):
            self.assertEqual(root, repo)
            self.assertEqual(qualification_scope, "basic")
            self.assertEqual(environment["CARGO_TARGET_DIR"], str(routine))
            self.assertNotIn("PRIVATE_KEY", environment)
            self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
            self.assertNotIn("RUSTFLAGS", environment)
            self.assertNotIn("CARGO_BUILD_TARGET", environment)
            descriptors.extend(lock_fds)
            self.assertEqual(len(lock_fds), 1)
            os.fstat(lock_fds[0])
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.cargo_lane(repo, routine, "development"):
                    self.fail("must not admit competing check")
        with patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
             patch.object(development_gate, "run_checks", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            release.development_check(repo, None, {"PRIVATE_KEY": "fixture must not cross", "RUSTFLAGS": "bad", "CARGO_BUILD_TARGET": "bad", "CARGO_INCREMENTAL": "0"}, native_linker="system")
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.assertEqual(stat.S_IMODE(routine.stat().st_mode), target_mode)
        with release.cargo_lane(repo, routine, "development"):
            pass

    def test_both_check_clis_share_the_development_entrypoint(self):
        repo, routine = self.development_paths()
        argv = ["taira_release.py", "check", "--repo-root", str(repo), "--target-dir", str(routine)]
        with patch.object(release.sys, "argv", argv), patch.object(release, "development_check") as check:
            self.assertEqual(release.main(), 0)
        self.assertEqual(check.call_args.args[:2], (repo, routine))
        argv = ["taira_release_check.py", "--repo-root", str(repo), "--target-dir", str(routine)]
        with patch.dict(sys.modules, {"taira_release": release}), patch.object(release.sys, "argv", argv), \
             patch.object(release, "development_check") as check:
            self.assertEqual(development_gate.main(), 0)
        self.assertEqual(check.call_args.args[:2], (repo, routine))

    def test_focused_prequalification_keeps_development_lock_and_sanitized_environment(self):
        repo, routine = self.development_paths()
        focused = ("core=sumeragi::certified_chain::tests::borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash",)
        held = []
        def diagnostic(root, *, focused_regressions, environment, lock_fds, qualification_scope):
            self.assertEqual((root, focused_regressions, qualification_scope), (repo, focused, "basic"))
            self.assertEqual(environment["CARGO_TARGET_DIR"], str(routine))
            self.assertNotIn("PRIVATE_KEY", environment)
            self.assertNotIn("RUSTFLAGS", environment)
            self.assertEqual(len(lock_fds), 1)
            held.extend(lock_fds)
            os.fstat(lock_fds[0])
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.cargo_lane(repo, routine, "development"):
                    self.fail("prequalification must hold the shared development lane")
        with patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
             patch.object(development_gate, "run_prequalification", side_effect=diagnostic) as prequalify, \
             patch.object(development_gate, "run_checks") as qualify, contextlib.redirect_stdout(io.StringIO()):
            release.development_check(repo, None, {"PRIVATE_KEY": "never forward", "RUSTFLAGS": "bad"},
                                      focused_regressions=focused, native_linker="system")
        prequalify.assert_called_once()
        qualify.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(held[0])
        self.assertFalse((routine / "checks.json").exists())
        self.assertFalse((routine / "result.json").exists())

    def test_invalid_focus_stops_before_target_or_tool_setup(self):
        repo, routine = self.development_paths()
        with patch.object(release, "isolated_cargo_environment") as tools, \
             patch.object(development_gate, "run_prequalification") as prequalify:
            with self.assertRaises(release.PrepareError):
                release.development_check(repo, routine, {}, focused_regressions=("core=*",))
        tools.assert_not_called()
        prequalify.assert_not_called()
        self.assertFalse((routine / ".taira-build-lane").exists())

    def test_development_gate_failures_keep_nonzero_cli_status_and_exact_diagnostics(self):
        repo, routine = self.development_paths()
        focus = "core=sumeragi::certified_chain::tests::borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash"
        for focused, entrypoint in ((False, "release"), (True, "release"),
                                    (False, "gate"), (True, "gate")):
            argv = (["taira_release.py", "check"] if entrypoint == "release" else ["taira_release_check.py"])
            argv.extend(["--repo-root", str(repo), "--target-dir", str(routine), "--native-linker", "system"])
            if focused:
                argv.extend(["--focus-regression", focus])
            output = io.StringIO()
            method = "run_prequalification" if focused else "run_checks"
            with self.subTest(focused=focused, entrypoint=entrypoint), \
                 patch.dict(sys.modules, {"taira_release": release}), \
                 patch.object(release.sys, "argv", argv), \
                 patch.object(release, "isolated_cargo_environment", side_effect=lambda _r, _s, env: (env, [])), \
                 patch.object(development_gate, method, side_effect=development_gate.CheckError("exact development refusal")) as run, \
                 contextlib.redirect_stderr(output), contextlib.redirect_stdout(io.StringIO()):
                main = release.main if entrypoint == "release" else development_gate.main
                self.assertEqual(main(), 1)
            run.assert_called_once()
            prefix = "taira-release" if entrypoint == "release" else "taira-check"
            self.assertEqual(output.getvalue(), f"[{prefix}] FAIL: exact development refusal\n")
            self.assertFalse((routine / "checks.json").exists())

    def test_prequalification_cannot_use_the_authenticated_release_target(self):
        repo, _ = self.development_paths()
        with patch.object(release, "isolated_cargo_environment") as tools, \
             patch.object(development_gate, "run_prequalification") as prequalify:
            with self.assertRaisesRegex(release.PrepareError, "authenticated release lane"):
                release.development_check(repo, repo / "target", {}, focused_regressions=(
                    "core=sumeragi::certified_chain::tests::borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash",))
        tools.assert_not_called()
        prequalify.assert_not_called()

    def test_only_check_parser_admits_focus_and_forwards_exact_names(self):
        focus = "core=sumeragi::certified_chain::tests::borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash"
        with patch.object(release.sys, "argv", ["taira_release.py", "check", "--focus-regression", focus]), \
             patch.object(release, "development_check") as check:
            self.assertEqual(release.main(), 0)
        self.assertEqual(check.call_args.kwargs, {"native_check_scope": "basic", "native_linker": "llvm" if sys.platform == "linux" else "system", "focused_regressions": (focus,)})
        arguments = ["prepare", "--expected-commit", "a" * 40, "--expected-signer", "A" * 40,
                     "--output-dir", str(self.out), "--zig", str(self.zig), "--zig-sha256", "a" * 64,
                     "--cargo-zigbuild", str(self.zigbuild), "--cargo-zigbuild-sha256", "b" * 64,
                     "--focus-regression", focus]
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as failed:
            release.parser().parse_args(arguments)
        self.assertEqual(failed.exception.code, 2)
        self.assertIn("unrecognized arguments: --focus-regression", errors.getvalue())

    def test_prepare_default_ignores_the_development_environment_selector(self):
        repo, routine = self.development_paths()
        argv = ["taira_release.py", "prepare", "--repo-root", str(repo), "--expected-commit", "a" * 40,
                "--expected-signer", "A" * 40, "--output-dir", str(self.out), "--zig", str(self.zig),
                "--zig-sha256", "b" * 64, "--cargo-zigbuild", str(self.zigbuild), "--cargo-zigbuild-sha256", "c" * 64]
        with patch.object(release.sys, "argv", argv), patch.dict(os.environ, {"TAIRA_TESTNET_CARGO_TARGET_DIR": str(routine)}), \
             patch.object(release, "prepare", return_value={"commit": "a" * 40}) as prepare, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release.main(), 0)
        self.assertEqual(prepare.call_args.args[0].target_dir, repo / "target")

    def test_development_and_release_share_exact_isolated_registry_paths(self):
        repo, routine = self.development_paths()
        (repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.93.1"\n')
        source = repo / "target" / "captured-fixture"
        source.mkdir()
        (source / "rust-toolchain.toml").write_bytes((repo / "rust-toolchain.toml").read_bytes())
        cache = self.root / "home" / ".cargo"
        (cache / "registry").mkdir(parents=True)
        (cache / "git").mkdir()
        (cache / "config.toml").write_text("fixture must never be parsed")
        inherited = {"HOME": str(cache.parent), "PATH": "/fixture", "RUSTFLAGS": "injected"}
        with patch.object(release.subprocess, "check_output", return_value=str(self.zig) + "\n"), \
             patch.object(release.shutil, "which", return_value=None):
            development, _ = release.isolated_cargo_environment(repo, repo, release.child_environment(inherited, routine))
            authenticated, _ = release.isolated_cargo_environment(repo, source, release.child_environment(inherited, repo / "target"))
        self.assertEqual(development["CARGO_HOME"], authenticated["CARGO_HOME"])
        self.assertEqual(development["CARGO_BUILD_JOBS"], "6")
        self.assertEqual(development["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(development["CARGO"], authenticated["CARGO"])
        self.assertEqual((Path(development["CARGO_HOME"]) / "registry").resolve(), cache / "registry")
        self.assertFalse((Path(development["CARGO_HOME"]) / "config.toml").exists())
        self.assertNotIn("RUSTFLAGS", development)

    def test_development_lane_is_bound_to_the_canonical_repository(self):
        repo, routine = self.development_paths()
        other = self.root / "other-repository"
        other.mkdir()
        with release.cargo_lane(repo, routine, "development"):
            pass
        with self.assertRaisesRegex(release.PrepareError, "different build mode or repository"):
            with release.cargo_lane(other, routine, "development"):
                self.fail("another repository must select its own stable lane")

    def test_invalid_lane_markers_fail_without_blocking_or_reading_aliases(self):
        repo, _ = self.development_paths()
        for kind in ("fifo", "symlink", "hardlink"):
            lane = self.root / kind
            lane.mkdir()
            private = lane / ".taira-build-lane"
            private.mkdir(mode=0o700)
            marker = private / "role.json"
            if kind == "fifo":
                os.mkfifo(marker, 0o600)
            else:
                unrelated = lane / "unrelated"
                unrelated.write_text("fixture contents must not be accepted")
                unrelated.chmod(0o600)
                if kind == "symlink":
                    marker.symlink_to(unrelated)
                else:
                    os.link(unrelated, marker)
            with self.subTest(kind=kind), self.assertRaises((release.PrepareError, OSError)):
                with release.cargo_lane(repo, lane, "development"):
                    self.fail("unsafe marker must fail")

    def test_lane_contention_reports_the_actual_coordination_path(self):
        repo, routine = self.development_paths()
        with release.cargo_lane(repo, routine, "development"):
            with self.assertRaises(release.PrepareError) as raised:
                with release.cargo_lane(repo, routine, "development"):
                    self.fail("must not overlap")
        self.assertIn(str(routine / ".taira-build-lane"), str(raised.exception))
        self.assertNotIn("/attempts", str(raised.exception))

    def test_ci_release_gate_no_longer_uses_development_lanes(self):
        # CI runs the nextest release-gate profile; these lanes remain local tooling.
        workflow = (SCRIPT.parent.parent / ".github/workflows/workspace_release.yml").read_text()
        for retired in ("taira_release", "taira-native-checks", "cargo_lane", "isolated_cargo_environment"):
            self.assertNotIn(retired, workflow)
        self.assertIn("cargo nextest run --profile release-gate", workflow)
        repo, _ = self.development_paths()
        lane = repo / "target" / "taira-native-checks"
        lane.mkdir()
        with release.cargo_lane(repo, lane, "development"):
            pass
        with release.source_lane(repo, repo / "target"):
            pass


    def test_private_source_final_metadata_precedes_single_file_and_bottom_up_directory_sync(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        previous = self.root / 'previous'
        (previous / 'deep/nested').mkdir(parents=True)
        stamp = 1_600_000_000_123_456_789
        os.utime(previous / 'deep/nested', ns=(stamp, stamp))
        synced = []
        fsync = release.os.fsync
        with release.PrivateSourceTree(pending) as writer:
            def observe(fd):
                info = os.fstat(fd)
                if stat.S_ISREG(info.st_mode):
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o500)
                    self.assertEqual(info.st_mtime_ns, stamp)
                    self.assertEqual(info.st_nlink, 1)
                    synced.append(('file', None))
                else:
                    relative = next(path for path, identity in writer.directories.items()
                                    if writer.identity(info) == identity)
                    self.assertEqual(stat.S_IMODE(info.st_mode),
                                     0o700 if relative == Path('.') else 0o500)
                    if relative == Path('deep/nested'):
                        self.assertEqual(info.st_mtime_ns, stamp)
                    synced.append(('directory', str(relative)))
                fsync(fd)
            with patch.object(release.os, 'fsync', side_effect=observe):
                writer.write(Path('deep/nested/run'), b'executable', executable=True,
                             timestamps=(stamp, stamp))
                writer.seal(previous, {Path('deep/nested')})
        self.assertEqual(synced, [('file', None), ('directory', 'deep/nested'),
                                 ('directory', 'deep'), ('directory', '.')])
        self.assertEqual((pending / 'deep/nested/run').read_bytes(), b'executable')

    def test_private_source_root_permission_drift_is_never_repaired(self):
        for mode in (0o755, 0o777, 0o500):
            for operation in ('write', 'seal'):
                with self.subTest(mode=oct(mode), operation=operation):
                    pending = self.root / ('pending-' + str(mode) + operation)
                    pending.mkdir(mode=0o700)
                    with release.PrivateSourceTree(pending) as writer:
                        pending.chmod(mode)
                        with self.assertRaises((release.PrepareError, release.ReleaseArtifactError)):
                            if operation == 'write':
                                writer.write(Path('source'), b'refused', executable=False)
                            else:
                                writer.seal(self.root, set())
                    self.assertEqual(stat.S_IMODE(pending.stat().st_mode), mode)
                    self.assertFalse((pending / 'source').exists())

    def test_private_source_short_writes_complete_before_durable_freeze(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        write = release.os.write
        with release.PrivateSourceTree(pending) as writer, \
             patch.object(release.os, 'write', side_effect=lambda fd, data: write(fd, data[:2])):
            writer.write(Path('source'), b'complete signed payload', executable=False)
            writer.seal(self.root, set())
        self.assertEqual((pending / 'source').read_bytes(), b'complete signed payload')
        self.assertEqual(stat.S_IMODE((pending / 'source').stat().st_mode), 0o400)

    def test_private_source_hardlink_race_scrubs_original_and_refuses_seal(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        alternate = self.root / 'alternate'
        fsync = release.os.fsync
        attacked = False
        def add_link(fd):
            nonlocal attacked
            if stat.S_ISREG(os.fstat(fd).st_mode) and not attacked:
                attacked = True
                os.link(pending / 'source', alternate)
            fsync(fd)
        with release.PrivateSourceTree(pending) as writer, \
             patch.object(release.os, 'fsync', side_effect=add_link):
            with self.assertRaisesRegex(release.PrepareError, 'file changed before sealing'):
                writer.write(Path('source'), b'must not survive failed custody', executable=False)
        self.assertTrue(attacked)
        self.assertFalse((pending / 'source').exists())
        self.assertEqual(alternate.read_bytes(), b'')

    def test_private_source_named_file_substitution_preserves_foreign_name(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        fsync = release.os.fsync
        attacked = False
        def substitute(fd):
            nonlocal attacked
            if stat.S_ISREG(os.fstat(fd).st_mode) and not attacked:
                attacked = True
                (pending / 'source').rename(pending / 'original')
                (pending / 'source').write_bytes(b'foreign name survives')
            fsync(fd)
        with release.PrivateSourceTree(pending) as writer, \
             patch.object(release.os, 'fsync', side_effect=substitute):
            with self.assertRaisesRegex(release.PrepareError, 'file changed before sealing'):
                writer.write(Path('source'), b'original source', executable=False)
        self.assertEqual((pending / 'source').read_bytes(), b'foreign name survives')
        self.assertEqual((pending / 'original').read_bytes(), b'')

    def test_private_source_replaced_root_and_nested_directory_refuse_publication(self):
        for relative in (Path('.'), Path('deep')):
            with self.subTest(relative=relative):
                pending = self.root / ('pending-' + ('root' if relative == Path('.') else 'nested'))
                pending.mkdir(mode=0o700)
                with release.PrivateSourceTree(pending) as writer:
                    writer.write(Path('deep/source'), b'signed source', executable=False)
                    selected = pending / relative
                    retained = selected.with_name(selected.name + '-retained')
                    selected.rename(retained)
                    selected.mkdir(mode=0o700)
                    with self.assertRaisesRegex(release.PrepareError, 'replaced|custody changed'):
                        writer.seal(self.root, set())
                self.assertEqual((retained / ('deep/source' if relative == Path('.') else 'source')).read_bytes(),
                                 b'signed source')

    def test_private_source_directory_replacement_during_sync_is_rejected(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        with release.PrivateSourceTree(pending) as writer:
            writer.write(Path('deep/source'), b'signed', executable=False)
            fsync = release.os.fsync
            attacked = False
            def substitute(fd):
                nonlocal attacked
                if writer.identity(os.fstat(fd)) == writer.directories[Path('deep')] and not attacked:
                    attacked = True
                    (pending / 'deep').rename(pending / 'old-deep')
                    (pending / 'deep').mkdir(mode=0o500)
                fsync(fd)
            with patch.object(release.os, 'fsync', side_effect=substitute):
                with self.assertRaisesRegex(release.PrepareError, 'directory path changed'):
                    writer.seal(self.root, set())
            self.assertTrue(attacked)

    def test_private_source_file_and_directory_sync_failures_keep_previous_capture(self):
        before = self.source_entries({'nested/source': ('100644', b'old')})
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, 'a' * 40, before)
            old_inode = source.stat().st_ino
            after = self.source_entries({'nested/source': ('100644', b'new')})
            for stage in ('file', 'directory'):
                with self.subTest(stage=stage):
                    fsync = release.os.fsync
                    failed = False
                    def fail(fd):
                        nonlocal failed
                        info = os.fstat(fd)
                        expected = stat.S_ISREG(info.st_mode) if stage == 'file' else stat.S_ISDIR(info.st_mode)
                        if expected and stat.S_IMODE(info.st_mode) in (0o400, 0o500) and not failed:
                            failed = True
                            raise OSError('injected ' + stage + ' durability failure')
                        fsync(fd)
                    with patch.object(release, 'commit_entries', return_value=before), \
                         patch.object(release.os, 'fsync', side_effect=fail), \
                         patch.object(release, 'retire_source_capture') as retire:
                        with self.assertRaisesRegex(OSError, 'durability failure'):
                            release.capture_source(self.root, source, self.target, 'b' * 40, after)
                        retire.assert_not_called()
                    self.assertTrue(failed)
                    self.assertEqual(source.stat().st_ino, old_inode)
                    self.assertEqual((source / 'nested/source').read_bytes(), b'old')
                    self.assertEqual(release.read_record(source.parent / 'source-state.json'), {'commit': 'a' * 40})
                    self.assertFalse(list(source.parent.glob('source.retained-*')))
                    release.frozen_snapshot(source, before, self.target)

    def test_private_source_signed_byte_check_still_precedes_old_source_rename(self):
        before = self.source_entries({'source': ('100644', b'old')})
        with release.source_lane(self.root, self.target) as (source, _):
            release.capture_source(self.root, source, self.target, 'a' * 40, before)
            after = self.source_entries({'source': ('100644', b'new')})
            seal = release.PrivateSourceTree.seal
            def corrupt(writer, previous, unchanged):
                path = writer.root / 'source'
                path.chmod(0o600)
                path.write_bytes(b'forged')
                path.chmod(0o400)
                seal(writer, previous, unchanged)
            with patch.object(release, 'commit_entries', return_value=before), \
                 patch.object(release.PrivateSourceTree, 'seal', new=corrupt), \
                 patch.object(release.os, 'rename') as rename:
                with self.assertRaisesRegex(release.PrepareError, 'bytes differ from the index'):
                    release.capture_source(self.root, source, self.target, 'b' * 40, after)
                rename.assert_not_called()
            self.assertEqual((source / 'source').read_bytes(), b'old')
            self.assertEqual(release.read_record(source.parent / 'source-state.json'), {'commit': 'a' * 40})

    def test_private_source_unknown_directory_and_symlink_are_not_adopted(self):
        pending = self.root / 'pending'
        pending.mkdir(mode=0o700)
        for kind in ('directory', 'symlink'):
            with self.subTest(kind=kind):
                selected = pending / kind
                if kind == 'directory':
                    selected.mkdir(mode=0o700)
                else:
                    selected.symlink_to(self.target, target_is_directory=True)
                with release.PrivateSourceTree(pending) as writer:
                    with self.assertRaises(FileExistsError):
                        writer.write(Path(kind) / 'source', b'must refuse', executable=False)
                self.assertFalse((selected / 'source').exists())



    def test_canonical_mode_compiles_checkout_and_keeps_capture_as_authority(self):
        self.args.source_mode = "canonical-checkout"
        root = self.args.repo_root
        roots = {"irohad": root / "crates/irohad"}
        def build(source, command, environment, log):
            self.assertEqual(source, root)
            self.assertEqual(command[command.index("--manifest-path") + 1], str(root / "Cargo.toml"))
            self.assertEqual(command[command.index("--config") + 1], str(root / ".cargo/config.toml"))
            self.assertNotIn(str(self.source / "Cargo.toml"), command)
            self.assertEqual(environment["IROHA_GIT_COMMIT_HASH"], self.args.expected_commit)
            with self.assertRaisesRegex(release.PrepareError, "still running"):
                with release.cargo_lane(root, self.target, "release"):
                    self.fail("canonical build lost the release lane lock")
            self.binaries()
            log.write_bytes(b"canonical fixture compiler output\n")
        tracked = [{"path": "Cargo.toml", "kind": "regular"},
                   {"path": "source-link", "kind": "symlink"}]
        def admit(source, target, triple, names, **options):
            self.assertEqual(options["package_roots"], roots)
            self.assertEqual(options["source_paths"], {root / "Cargo.toml"})
            return []
        with patch.object(release, "canonical_source_snapshot", return_value=tracked) as snapshot, \
             patch.object(release, "local_package_roots", return_value=roots) as packages:
            result, gate, compile = self.prepare(build=build, cache_admission=admit)
        self.assertGreaterEqual(snapshot.call_count, 5)
        packages.assert_called_once()
        self.assertEqual(packages.call_args.args[0], root)
        self.assertEqual(packages.call_args.kwargs["source_paths"], {root / "Cargo.toml"})
        self.assertEqual(result["source_root"], str(self.source))
        self.assertEqual(result["source_snapshot_sha256"], hashlib.sha256(release.canonical_json_bytes([])).hexdigest())
        self.assertEqual(result["jobs"], 6)
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertTrue(result["source_unchanged"])
        self.assertEqual(compile.call_count, 1)
        gate.assert_not_called()

    def test_canonical_mode_drift_after_build_cannot_publish_result(self):
        self.args.source_mode = "canonical-checkout"
        current = []
        def build(_source, _command, _environment, log):
            self.binaries()
            log.write_bytes(b"completed fixture build\n")
            current.append({"path": "Cargo.toml", "sha256": "f" * 64})
        with patch.object(release, "canonical_source_snapshot", side_effect=lambda *_: list(current)), \
             patch.object(release, "local_package_roots", return_value={}):
            with self.assertRaisesRegex(release.PrepareError, "canonical compiler source changed"):
                self.prepare(build=build)
        self.assertFalse((self.out / "result.json").exists())
        self.assertTrue((self.out / "attempts/000001/cargo.log").exists())

    def test_canonical_mode_does_not_skip_signed_source_authentication(self):
        self.args.source_mode = "canonical-checkout"
        with patch.object(release, "verify_signed_source", side_effect=release.PrepareError("signature refused")), \
             patch.object(release, "capture_source") as capture, \
             patch.object(release, "run_build") as build:
            with self.assertRaisesRegex(release.PrepareError, "signature refused"):
                release.prepare(self.args)
        capture.assert_not_called()
        build.assert_not_called()

    def test_canonical_snapshot_rejects_dirty_bytes_head_index_and_extra_source(self):
        source = self.root / "canonical-fixture"
        source.mkdir()
        item = source / "Cargo.toml"
        body = b"[workspace]\n"
        item.write_bytes(body)
        item.chmod(0o644)
        blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        entries = ("100644 " + blob + " 0\tCargo.toml\0").encode()
        replies = {("rev-parse", "HEAD"): self.args.expected_commit.encode(),
                   ("branch", "--show-current"): b"optimizations",
                   ("ls-files", "--stage", "-z"): entries,
                   ("ls-files", "--others", "--exclude-standard", "-z"): b""}
        with patch.object(release, "git", side_effect=lambda _root, *args: replies[args]):
            baseline = release.canonical_source_snapshot(source, self.args.expected_commit, entries)
            self.assertEqual(baseline[0]["sha256"], hashlib.sha256(body).hexdigest())
            item.write_bytes(b"dirty source\n")
            with self.assertRaisesRegex(release.PrepareError, "tracked source bytes differ"):
                release.canonical_source_snapshot(source, self.args.expected_commit, entries)
            item.write_bytes(body)
            for command, wrong, reason in [
                    (("rev-parse", "HEAD"), b"b" * 40, "HEAD differs"),
                    (("branch", "--show-current"), b"main", "requires optimizations"),
                    (("ls-files", "--stage", "-z"), entries + b"extra", "index differs"),
                    (("ls-files", "--others", "--exclude-standard", "-z"), b"extra.rs\0", "untracked source")]:
                with self.subTest(reason=reason):
                    old = replies[command]
                    replies[command] = wrong
                    with self.assertRaisesRegex(release.PrepareError, reason):
                        release.canonical_source_snapshot(source, self.args.expected_commit, entries)
                    replies[command] = old

    def test_canonical_snapshot_rechecks_head_after_reading_source(self):
        entries = b""
        heads = iter([self.args.expected_commit.encode(), b"b" * 40])
        def answer(_root, *args):
            if args == ("rev-parse", "HEAD"):
                return next(heads)
            if args == ("branch", "--show-current"):
                return b"optimizations"
            return b""
        with patch.object(release, "git", side_effect=answer):
            with self.assertRaisesRegex(release.PrepareError, "HEAD differs"):
                release.canonical_source_snapshot(self.root, self.args.expected_commit, entries)

    def test_canonical_snapshot_rejects_escaping_symlink(self):
        link = self.root / "external-source"
        link.symlink_to(self.root.parent / "outside")
        entries = b"120000 " + b"a" * 40 + b" 0\texternal-source\0"
        def answer(_root, *args):
            return {("rev-parse", "HEAD"): self.args.expected_commit.encode(),
                    ("branch", "--show-current"): b"optimizations",
                    ("ls-files", "--stage", "-z"): entries,
                    ("ls-files", "--others", "--exclude-standard", "-z"): b""}[args]
        with patch.object(release, "git", side_effect=answer):
            with self.assertRaisesRegex(release.PrepareError, "symlink escapes"):
                release.canonical_source_snapshot(self.root, self.args.expected_commit, entries)

    def test_canonical_mode_is_explicit_for_each_prepare_command(self):
        options = ["--expected-commit", self.args.expected_commit,
                   "--expected-signer", self.args.expected_signer,
                   "--output-dir", str(self.out), "--zig", str(self.zig),
                   "--zig-sha256", self.args.zig_sha256,
                   "--cargo-zigbuild", str(self.zigbuild),
                   "--cargo-zigbuild-sha256", self.args.cargo_zigbuild_sha256]
        native_options = ["--expected-commit", self.args.expected_commit,
                          "--expected-signer", self.args.expected_signer,
                          "--output-dir", str(self.out)]
        for command, arguments in (
            ("prepare", options),
            ("prepare-native-runtime", native_options),
            ("prepare-client", [*native_options, "--bin", "iroha"]),
        ):
            with self.subTest(command=command):
                self.assertEqual(release.parser().parse_args([command, *arguments]).source_mode,
                                 "captured")
                self.assertEqual(release.parser().parse_args(
                    [command, "--source-mode", "canonical-checkout", *arguments]).source_mode,
                    "canonical-checkout")
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    release.parser().parse_args(
                        [command, "--source-mode", "unchecked", *arguments])


if __name__ == "__main__":
    unittest.main()
