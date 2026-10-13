"""Native endpoint supervisor tests; synthetic children, no proof execution."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "check_parliament_ballot_native_probe.py"
SPEC = importlib.util.spec_from_file_location("native_probe_supervisor", SCRIPT)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ID = "00010203-0405-0607-0809-0A0B0C0D0E0F"


def snapshot(phase=2, positive=False, terminal=False):
    """Provide every fixed ABI field and endpoint, optionally one charged malloc."""
    counts = [[[0, 0, 0] for _ in range(21)] for _ in range(3)]
    if positive:
        counts[1][0] = [1, 64, 0]
    if terminal:
        return {"native_probe_terminal": True, "observation_valid": True, "profile_qualified": False,
                "complete_workspace_certificate": False, "phase_before_seal": phase, "invalid_flags": 0,
                "counters": counts}
    return {"abi_version": 1, "struct_bytes": 1584, "endpoint_count": 21, "phase_count": 3,
            "final_phase": 3, "inflight": 0, "invalid_flags": 0, "transitions": (8, 10, 14)[phase],
            "phase_before_seal": phase,
            "counters": [[dict(zip(("calls", "requested_bytes", "failures"), c)) for c in row] for row in counts]}


def runtime(binary, interposer):
    """Actual-process identity shape with required named images, without addresses."""
    paths = [str(binary), str(interposer)] + ["/usr/lib/" + name for name in (
        "libsystem_malloc.dylib", "libsystem_pthread.dylib", "libsystem_kernel.dylib")]
    return {"schema": "parliament-native-runtime-identity-v1", "installed_runtime_source_identity_established": False,
            "inserted_or_interposing_libraries": True, "image_count_before": len(paths), "image_count_after": len(paths),
            "loaded_images": [{"path": path, "lc_uuid": ID} for path in paths], "shared_cache_uuid": ID}


def control(name, binary=Path("/tmp/probe"), interposer=Path("/tmp/probe.dylib"), positive=None):
    """Construct a successfully exited synthetic control for validation mutations."""
    if name == "panic":
        return subprocess.CompletedProcess([], -signal.SIGABRT, "", "native observer deliberate panic control")
    if positive is None:
        positive = name in {"system", "thread", "tls"}
    value = {"control": name, "routed_allocations": 1 if name in {"routed", "tls"} else 0,
             "native": snapshot(positive=positive), "runtime": runtime(binary, interposer),
             "complete_workspace_certificate": False, "profile_qualified": False}
    return subprocess.CompletedProcess([], 0, json.dumps(value), "")


def corpus():
    """Fixed synthetic corpus shape; payload correctness belongs to fixture helper."""
    common = {"input": b"x", "flags": [], "expected_exit": 0, "expected_charge": 1, "expected_outcome": "accepted"}
    values = [{**common, "row": row, "role": "vote" if seats else "registration", "seats": seats, "case": case}
              for row in ("candidate", "comparator") for seats in (0, 3, 500, 1000) for case in M.VARIANTS]
    return values + [{**common, "row": "candidate", "role": "registration", "seats": 0, "case": case} for case in M.GLOBAL_CASES]


class NativeProbeTests(unittest.TestCase):
    def test_c_receipt_requires_positive_control_and_exact_interposer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / M.PROBE / "a.c"
            source.parent.mkdir(parents=True)
            source.write_text("source")
            interposer = root / "libnp.dylib"
            interposer.write_text("binary")
            checked = []
            helper = types.SimpleNamespace(SOURCE_NAMES=("a.c",), UNITS=("overflow",), CONTROLS=("malloc",),
                                           validate_control=lambda case, value: checked.append((case, value)))
            receipt = {"controls_passed": True, "profile_qualified": False, "complete_native_coverage": False,
                       "complete_workspace_certificate": False, "sources_before": {"a.c": M.digest(source)},
                       "sources_after": {"a.c": M.digest(source)}, "binaries": {"libnp.dylib": M.digest(interposer)},
                       "host": {"machine": M.platform.machine(), "macos_version": M.platform.mac_ver()[0]},
                       "commands": [{"label": "unit-overflow", "exit": 0},
                                    {"label": "control-malloc", "exit": 0, "stdout": "{}"}]}
            M.validate_c_controls(receipt, interposer, helper, root)
            self.assertEqual(checked, [("malloc", {})])
            removed = receipt["commands"].pop()
            with self.assertRaisesRegex(ValueError, "missing"):
                M.validate_c_controls(receipt, interposer, helper, root)
            receipt["commands"].append(removed)
            interposer.write_text("different")
            with self.assertRaisesRegex(ValueError, "interposer"):
                M.validate_c_controls(receipt, interposer, helper, root)

    def test_corpus_rejects_empty_truncated_duplicates_and_substitution(self):
        M.validate_corpus(corpus())
        for cases in ([], corpus()[:-1], corpus()[:-1] + [corpus()[0]]):
            with self.assertRaises(ValueError):
                M.validate_corpus(cases)
        wrong = corpus()
        wrong[-1]["case"] = "unreviewed"
        with self.assertRaises(ValueError):
            M.validate_corpus(wrong)
    def test_exact_helper_bytes_are_loaded(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "helper.py"
            source.write_text("value = 1\n")
            first, first_hash = M.helper(source, "first")
            source.write_text("value = 2\n")
            second, second_hash = M.helper(source, "second")
            self.assertEqual((first.value, second.value), (1, 2))
            self.assertNotEqual(first_hash, second_hash)
            self.assertEqual(second_hash, M.digest(source))

    def test_build_scope_mode_checks_and_log_bindings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generated = root / "generated"
            required = [root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
            required += [root / M.RESOURCE / (name + ".rs") for name in ("arena", "budget", "native", "workspace")]
            required += [root / M.PROBE / name for name in ("np_api.h", "driver.rs")]
            required += [generated / name for name in ("Cargo.toml", "Cargo.lock", "preparation.json", "driver.rs")]
            registry = root / "registry/package"
            required += [registry / name for name in ("Cargo.toml", "src/lib.rs", "build.rs", ".cargo-checksum.json")]
            for path in required:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("source")
            binaries = {mode: root / mode for mode in ("portable", "accel")}
            for mode, path in binaries.items():
                path.write_text(mode)
            interposer = root / "interposer"
            interposer.write_text("dylib")
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"packages": [{"source": "registry+test", "manifest_path": str(registry / "Cargo.toml")}]}))
            commands = []
            for accelerated in (False, True):
                for action in ("test", "clippy", "build"):
                    command = ["cargo", action, "--release", "--locked", "--manifest-path", str(generated / "Cargo.toml")]
                    if accelerated:
                        command += ["--features", "accel"]
                    if action == "clippy":
                        command += ["--all-targets", "--", "-D", "warnings"]
                    log = root / (str(accelerated) + action + ".txt")
                    log.write_text("passed")
                    commands.append({"command": command, "exit": 0, "source_changes": {}, "log": str(log), "log_sha256": M.digest(log)})
            receipt = {"schema": "parliament-native-probe-build-v1", "source_stable": True,
                       "profile_qualified": False, "complete_workspace_certificate": False,
                       "source_files": {str(path): M.digest(path) for path in required},
                       "generated_dir": str(generated), "dependency_metadata_path": str(metadata),
                       "dependency_metadata_sha256": M.digest(metadata), "commands": commands,
                       "binaries": {mode: {"path": str(path), "sha256": M.digest(path)} for mode, path in binaries.items()},
                       "interposer": {"sha256": M.digest(interposer)}}
            M.validate_build(receipt, binaries, interposer, root)
            # Alias spellings must denote the same required physical paths.
            alias = root / "alias"
            alias.symlink_to(generated, target_is_directory=True)
            original = str(generated / "driver.rs")
            receipt["source_files"][str(alias / "driver.rs")] = receipt["source_files"].pop(original)
            M.validate_build(receipt, binaries, interposer, root)
            omitted = receipt["source_files"].pop(str(registry / "src/lib.rs"))
            with self.assertRaisesRegex(ValueError, "omitted"):
                M.validate_build(receipt, binaries, interposer, root)
            receipt["source_files"][str(registry / "src/lib.rs")] = omitted
            for index in range(len(commands)):
                removed = commands.pop(index)
                with self.assertRaisesRegex(ValueError, "both locked"):
                    M.validate_build(receipt, binaries, interposer, root)
                commands.insert(index, removed)
            commands[1]["command"].remove("--all-targets")
            with self.assertRaisesRegex(ValueError, "strict"):
                M.validate_build(receipt, binaries, interposer, root)
            commands[1]["command"].append("--all-targets")
            for index in range(len(commands)):
                command = commands[index]["command"]
                manifest_index = command.index("--manifest-path") + 1
                original = command[manifest_index]
                command[manifest_index] = str(root / "another-Cargo.toml")
                with self.assertRaisesRegex(ValueError, "generated-manifest"):
                    M.validate_build(receipt, binaries, interposer, root)
                command[manifest_index] = original
                command[0] = "echo"
                with self.assertRaisesRegex(ValueError, "generated-manifest"):
                    M.validate_build(receipt, binaries, interposer, root)
                command[0] = "cargo"
            Path(commands[0]["log"]).write_text("changed")
            with self.assertRaisesRegex(ValueError, "log binding"):
                M.validate_build(receipt, binaries, interposer, root)

    def test_abi_and_all_three_endings(self):
        for phase in range(3):
            self.assertEqual(len(M.counters(snapshot(phase), phase=phase)), 3)
        self.assertEqual(len(M.counters(snapshot(1, terminal=True), terminal=True, phase=1)), 3)

    def test_missing_nonobject_and_bad_abi_not_zero(self):
        for value in (None, [], {}, snapshot(1)):
            with self.assertRaises(ValueError):
                M.counters(value)
        for key, bad in (("abi_version", True), ("struct_bytes", 1576), ("inflight", 1),
                         ("invalid_flags", 1), ("transitions", 10), ("phase_before_seal", True)):
            value = snapshot()
            value[key] = bad
            with self.assertRaises(ValueError):
                M.counters(value)
        with self.assertRaises(ValueError):
            M.object_json("[]")

    def test_counter_ranges_shapes_and_sentinels(self):
        for bad in (None, [], [0] * 20):
            value = snapshot()
            value["counters"][1] = bad
            with self.assertRaises(ValueError):
                M.counters(value)
        for key, bad in (("calls", True), ("requested_bytes", 1 << 64), ("failures", 1)):
            value = snapshot()
            value["counters"][1][0][key] = bad
            with self.assertRaises(ValueError):
                M.counters(value)
        terminal = snapshot(1, terminal=True)
        terminal["observation_valid"] = False
        with self.assertRaises(ValueError):
            M.counters(terminal, terminal=True, phase=1)

    def test_control_positive_and_negative_boundaries(self):
        for name in M.CONTROLS:
            M.validate_control(name, control(name), Path("/tmp/probe"), Path("/tmp/probe.dylib"))
        for name in ("system", "thread", "tls"):
            with self.assertRaisesRegex(ValueError, "not observed"):
                M.validate_control(name, control(name, positive=False), Path("/tmp/probe"), Path("/tmp/probe.dylib"))
        for name in ("empty", "routed"):
            with self.assertRaisesRegex(ValueError, "negative"):
                M.validate_control(name, control(name, positive=True), Path("/tmp/probe"), Path("/tmp/probe.dylib"))
        value = json.loads(control("routed").stdout)
        value["routed_allocations"] = 0
        with self.assertRaisesRegex(ValueError, "arena"):
            M.validate_control("routed", subprocess.CompletedProcess([], 0, json.dumps(value), ""), Path("/tmp/probe"), Path("/tmp/probe.dylib"))

    def test_panic_requires_original_abort_and_no_snapshot(self):
        result = M.validate_control("panic", control("panic"), Path("/tmp/p"), Path("/tmp/i"))
        self.assertIsNone(result["native_observation"])
        for child in (subprocess.CompletedProcess([], 1, "", "native observer deliberate panic control"),
                      subprocess.CompletedProcess([], -signal.SIGABRT, "{}", "native observer deliberate panic control"),
                      subprocess.CompletedProcess([], -signal.SIGABRT, "", "unrelated abort")):
            with self.assertRaises(ValueError):
                M.validate_control("panic", child, Path("/tmp/p"), Path("/tmp/i"))

    def test_runtime_missing_images_cache_or_source_overclaim_rejected(self):
        binary, interposer = Path("/tmp/probe"), Path("/tmp/probe.dylib")
        for key, bad in (("installed_runtime_source_identity_established", True), ("shared_cache_uuid", None),
                         ("inserted_or_interposing_libraries", False), ("image_count_after", 99)):
            value = runtime(binary, interposer)
            value[key] = bad
            with self.assertRaises(ValueError):
                M.runtime(value, binary, interposer)
        with self.assertRaises(ValueError):
            M.runtime(runtime(binary, interposer), Path("/tmp/other"), interposer)

    def test_oom_preserves_resource_outcome_and_incomplete_native(self):
        seen = []
        resource = types.SimpleNamespace(validate_observation=lambda *args: seen.append(args))
        child = subprocess.CompletedProcess([], 73, '{"outcome":"resource_exhausted"}', json.dumps(snapshot(1, terminal=True)))
        value = M.validate_case({"expected_charge": 1}, child, "portable", Path("/tmp/p"), Path("/tmp/i"), resource)
        self.assertEqual(value["native_kind"], "terminal_incomplete")
        self.assertEqual(seen[0][1], 73)
        child.stderr = '{"native_probe_terminal":true,"observation_valid":false}'
        with self.assertRaises(ValueError):
            M.validate_case({"expected_charge": 1}, child, "portable", Path("/tmp/p"), Path("/tmp/i"), resource)

    def test_ordinary_unwrap_does_not_reclassify_native_positive(self):
        resource = types.SimpleNamespace(validate_observation=lambda *args: None)
        binary, interposer = Path("/tmp/p"), Path("/tmp/i")
        for charge, phase in ((0, 0), (1, 2)):
            value = {"worker": {"outcome": "accepted"}, "native": snapshot(phase, positive=bool(charge)),
                     "runtime": runtime(binary, interposer), "profile_qualified": False, "complete_workspace_certificate": False}
            result = M.validate_case({"expected_charge": charge}, subprocess.CompletedProcess([], 0, json.dumps(value), ""),
                                     "portable", binary, interposer, resource)
            self.assertEqual(result["charged_endpoint_calls"], charge)

    def test_existing_output_refused_and_setup_failure_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "run"
            with patch.object(M.platform, "system", return_value="Linux"):
                result = M.campaign(Path(temp), {}, Path("i"), Path("b"), Path("c"), output)
            self.assertFalse(result["campaign_passed"])
            self.assertFalse(result["proof_cases_started"])
            self.assertTrue((output / "cases.jsonl").exists())
            self.assertIn("failure", json.loads((output / "report.json").read_text()))
            with self.assertRaises(FileExistsError):
                M.campaign(Path(temp), {}, Path("i"), Path("b"), Path("c"), output)

    def test_failed_positive_and_timeout_are_journaled_before_proofs(self):
        for failure_kind in ("missing-positive", "timeout", "interrupt"):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                paths = [root / name for name in ("portable", "accel", "interposer", "build.json", "controls.json")]
                for path in paths:
                    path.write_text("{}")
                scripts = root / "scripts"
                (scripts / "tests").mkdir(parents=True)
                (scripts / "tests/parliament_ballot_native_probe_test.py").write_text("test")
                source = scripts / "check_parliament_ballot_resource_contract.py"
                source.write_text("resource")
                c_path = root / M.PROBE / "run_controls.py"
                c_path.parent.mkdir(parents=True)
                c_path.write_text("c")
                resource = types.SimpleNamespace(FIXTURES=Path("fixtures"), cases=lambda _: corpus())
                mocks = [(resource, M.digest(source)), (object(), M.digest(c_path))]
                calls = []
                def execute(command, **kwargs):
                    calls.append(command)
                    if "DYLD_INSERT_LIBRARIES" not in kwargs["env"]:
                        return subprocess.CompletedProcess(command, 75, "", "native observer setup failed: missing")
                    name = command[-1]
                    if name == "system":
                        if failure_kind == "timeout":
                            raise subprocess.TimeoutExpired(command, 120, b"partial", b"err")
                        if failure_kind == "interrupt":
                            raise KeyboardInterrupt()
                        return control(name, Path(command[0]), paths[2], positive=False)
                    return control(name, Path(command[0]), paths[2])
                with patch.object(M.platform, "system", return_value="Darwin"), patch.dict(M.os.environ, {}, clear=True), \
                     patch.object(M, "helper", side_effect=mocks), patch.object(M, "validate_build", return_value={}), \
                     patch.object(M, "validate_c_controls", return_value={}):
                    result = M.campaign(root, {"portable": paths[0], "accel": paths[1]}, paths[2], paths[3], paths[4], root / "out", execute=execute)
                self.assertFalse(result["campaign_passed"])
                self.assertFalse(result["proof_cases_started"])
                self.assertEqual(calls[-1][-1], "system")
                self.assertFalse(result["observations"][-1]["check_passed"])
                journal = [json.loads(line) for line in (root / "out/cases.jsonl").read_text().splitlines()]
                self.assertTrue(journal[-1]["completed"])
                if failure_kind == "timeout":
                    self.assertEqual(journal[-1]["stdout"], "partial")


if __name__ == "__main__":
    unittest.main()
