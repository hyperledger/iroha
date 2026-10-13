#!/usr/bin/env python3
"""Run source-bound native endpoint controls, then existing ballot proof fixtures.

Python 3.11+, macOS, explicit portable/accelerated diagnostic binaries, their
successful build receipt, and the separately controlled C interposer. No new
proofs, network, devices or production writes. Output must be a NEW directory.
Inherited DYLD_* settings are refused; injection is added only to each child.
Missing required native-positive controls fail before the proof campaign.
Signals, missing snapshots and endpoint blind spots never become zero counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path("crates/iroha_parliament_ballot_proof/examples/native_probe")
RESOURCE = Path("crates/iroha_parliament_ballot_proof/examples/resource_contract")
CONTROLS = ("empty", "routed", "system", "thread", "tls", "panic")
ALLOCATION_ENDPOINTS = (0, 1, 2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 18, 19)
HEX = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")
VARIANTS = ("valid", "late_invalid_coefficient", "truncated_record", "impossible_proof_length",
            "work_short", "byte_short", "arena_exhaustion")
GLOBAL_CASES = ("long_path_work_short", "fifo_input", "empty_input", "oversized_input")


def digest(path: Path) -> str:
    """Hash exact file bytes, never infer identity from a path or timestamp."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def helper(path: Path, name: str):
    """Load the exact source bytes and return their hash, avoiding stale pyc."""
    data = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module, hashlib.sha256(data).hexdigest()


def object_json(text: str) -> dict:
    """Require one complete JSON object, never treating absent output as zero."""
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("child JSON must be an object")
    return value


def case_identity(case: dict) -> tuple:
    """Name one fixed corpus member without including mode or temporary paths."""
    return tuple(case.get(key) for key in ("row", "role", "seats", "case"))


def validate_corpus(cases: list) -> None:
    """Require every one of the 60 reviewed case identities exactly once."""
    expected = {(row, "vote" if seats else "registration", seats, variant)
                for row in ("candidate", "comparator") for seats in (0, 3, 500, 1000) for variant in VARIANTS}
    expected.update(("candidate", "registration", 0, name) for name in GLOBAL_CASES)
    if not isinstance(cases, list) or len(cases) != 60 or any(not isinstance(case, dict) for case in cases):
        raise ValueError("proof corpus must contain exactly 60 reviewed cases")
    identities = [case_identity(case) for case in cases]
    if len(set(identities)) != 60 or set(identities) != expected:
        raise ValueError("proof corpus has missing, duplicated or substituted cases")
    for case in cases:
        if (not isinstance(case.get("input"), bytes) or not isinstance(case.get("flags"), list)
                or any(not isinstance(flag, str) for flag in case["flags"])
                or type(case.get("expected_charge")) is not int or case["expected_charge"] not in (0, 1)
                or type(case.get("expected_exit")) is not int or not isinstance(case.get("expected_outcome"), str)):
            raise ValueError("proof corpus case metadata malformed")


def counters(value: dict, *, terminal: bool = False, phase: int = 2) -> list:
    """Validate the fixed ABI/terminal representation and normalize triples."""
    if not isinstance(value, dict):
        raise ValueError("native observation missing")
    if terminal:
        if (value.get("native_probe_terminal") is not True or value.get("observation_valid") is not True
                or value.get("profile_qualified") is not False
                or value.get("complete_workspace_certificate") is not False):
            raise ValueError("terminal native observation invalid or inflated")
    else:
        required = {"abi_version": 1, "struct_bytes": 1584, "endpoint_count": 21,
                    "phase_count": 3, "final_phase": 3, "inflight": 0, "transitions": (8, 10, 14)[phase]}
        if any(type(value.get(key)) is not int or value[key] != expected for key, expected in required.items()):
            raise ValueError("native ABI/seal/transition mismatch")
    if (type(value.get("phase_before_seal")) is not int or value["phase_before_seal"] != phase
            or type(value.get("invalid_flags")) is not int or value["invalid_flags"] != 0):
        raise ValueError("native interval phase/validity mismatch")
    rows = value.get("counters")
    if not isinstance(rows, list) or len(rows) != 3:
        raise ValueError("native phase array missing")
    result = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 21:
            raise ValueError("native endpoint inventory missing")
        normalized = []
        for item in row:
            triple = item if terminal else ([item.get(key) for key in ("calls", "requested_bytes", "failures")]
                                           if isinstance(item, dict) else None)
            if (not isinstance(triple, list) or len(triple) != 3
                    or any(type(n) is not int or not 0 <= n < 1 << 64 for n in triple)
                    or triple[2] > triple[0]):
                raise ValueError("native counter shape/range mismatch")
            normalized.append(triple)
        result.append(normalized)
    return result


def runtime(value: dict, binary: Path, interposer: Path) -> None:
    """Validate actual-process image identities without equating UUIDs to source."""
    if (not isinstance(value, dict) or value.get("schema") != "parliament-native-runtime-identity-v1"
            or value.get("installed_runtime_source_identity_established") is not False
            or value.get("inserted_or_interposing_libraries") is not True):
        raise ValueError("runtime observation absent or overclaimed")
    before, after = value.get("image_count_before"), value.get("image_count_after")
    images = value.get("loaded_images")
    if (type(before) is not int or not 0 < before <= 65536 or type(after) is not int or before != after
            or not isinstance(images, list) or len(images) != before):
        raise ValueError("runtime image inventory inconsistent")
    cache = value.get("shared_cache_uuid")
    if not isinstance(cache, str) or not UUID.fullmatch(cache):
        raise ValueError("runtime shared-cache UUID unavailable")
    identities = {}
    for item in images:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]:
            raise ValueError("invalid runtime image path")
        uuid = item.get("lc_uuid")
        if uuid is not None and (not isinstance(uuid, str) or not UUID.fullmatch(uuid)):
            raise ValueError("invalid runtime image UUID")
        path = str(Path(item["path"]).resolve())
        if path in identities:
            raise ValueError("duplicate runtime image path")
        identities[path] = uuid
    if any(not identities.get(str(path.resolve())) for path in (binary, interposer)):
        raise ValueError("actual process does not identify the supplied binary/interposer")
    for name in ("libsystem_malloc.dylib", "libsystem_pthread.dylib", "libsystem_kernel.dylib"):
        if not any(Path(path).name == name and uuid for path, uuid in identities.items()):
            raise ValueError(f"required native image identity unavailable: {name}")


def validate_control(name: str, result, binary: Path, interposer: Path) -> dict:
    """Separate positive/negative controls and retain panic as runtime failure."""
    if name == "panic":
        if result.returncode != -signal.SIGABRT or result.stdout.strip():
            raise ValueError("panic control must remain SIGABRT without a successful JSON observation")
        if "native observer deliberate panic control" not in result.stderr:
            raise ValueError("SIGABRT lacks the deliberate panic diagnostic")
        return {"classification": "expected_runtime_failure", "native_observation": None,
                "native_observation_missing_reason": "aborted before seal; no zero-count substitution"}
    if result.returncode != 0:
        raise ValueError(f"{name}: control runtime failure {result.returncode}")
    value = object_json(result.stdout)
    if (value.get("control") != name or value.get("profile_qualified") is not False
            or value.get("complete_workspace_certificate") is not False
            or type(value.get("routed_allocations")) is not int or value["routed_allocations"] < 0):
        raise ValueError("control identity/count/qualification mismatch")
    observed = counters(value.get("native"))
    runtime(value.get("runtime"), binary, interposer)
    charged_calls = sum(item[0] for item in observed[1])
    positive = any(observed[1][index][0] > 0 for index in ALLOCATION_ENDPOINTS)
    if name in {"empty", "routed"} and charged_calls:
        raise ValueError(f"{name}: negative native endpoint control observed calls")
    if name == "routed" and value["routed_allocations"] < 1:
        raise ValueError("routed allocation control did not exercise the arena")
    if name in {"system", "thread", "tls"} and not positive:
        raise ValueError(f"{name}: required native-positive control not observed; endpoint coverage incomplete")
    return {"classification": "control_observed", "parsed": value,
            "charged_endpoint_calls": charged_calls, "native_allocation_endpoint_observed": positive}


def validate_case(case: dict, result, mode: str, binary: Path, interposer: Path, resource) -> dict:
    """Preserve original verifier outcome/charge and separately assess native data."""
    value = object_json(result.stdout)
    if result.returncode == 73:
        resource.validate_observation(case, result.returncode, value, mode)
        terminal = object_json(result.stderr)
        observed = counters(terminal, terminal=True, phase=1)
        return {"worker": value, "native": terminal, "native_kind": "terminal_incomplete",
                "charged_endpoint_calls": sum(item[0] for item in observed[1]), "runtime": None,
                "runtime_identity_missing_reason": "terminal fixed-buffer report omits setup identity"}
    if value.get("profile_qualified") is not False or value.get("complete_workspace_certificate") is not False:
        raise ValueError("diagnostic wrapper inflated qualification")
    worker = value.get("worker")
    resource.validate_observation(case, result.returncode, worker, mode)
    phase = 2 if case["expected_charge"] else 0
    observed = counters(value.get("native"), phase=phase)
    runtime(value.get("runtime"), binary, interposer)
    if phase == 0 and any(item[0] for item in observed[1]):
        raise ValueError("unadmitted case has a charged native interval")
    return {"worker": worker, "native": value["native"], "native_kind": "ordinary" if phase else "unadmitted",
            "runtime": value["runtime"], "charged_endpoint_calls": sum(item[0] for item in observed[1])}


def validate_build(receipt: dict, binaries: dict, interposer: Path, root: Path) -> dict[str, str]:
    """Derive required local-source scope from retained Cargo metadata and bind bytes."""
    if (receipt.get("schema") != "parliament-native-probe-build-v1" or receipt.get("source_stable") is not True
            or receipt.get("failure") is not None
            or receipt.get("profile_qualified") is not False or receipt.get("complete_workspace_certificate") is not False):
        raise ValueError("diagnostic build receipt is not a stable unqualified build")
    sources = receipt.get("source_files")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("build source inventory missing")
    for name, expected in sources.items():
        if not isinstance(name, str) or not Path(name).is_absolute() or not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise ValueError("build source inventory must use absolute paths and SHA256")
        if digest(Path(name)) != expected:
            raise ValueError(f"compiled source changed: {name}")
    metadata_path = Path(receipt["dependency_metadata_path"])
    if not metadata_path.is_absolute() or digest(metadata_path) != receipt.get("dependency_metadata_sha256"):
        raise ValueError("Cargo metadata binding missing")
    metadata = object_json(metadata_path.read_text())
    packages = metadata.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo metadata package inventory missing")
    required = {root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")}
    required.update((root / PROBE).glob("*.rs"))
    required.add(root / PROBE / "np_api.h")
    required.update(root / RESOURCE / f"{name}.rs" for name in ("arena", "budget", "native", "workspace"))
    generated = Path(receipt["generated_dir"])
    if not generated.is_absolute():
        raise ValueError("generated directory must be absolute")
    required.update(generated.glob("*.rs"))
    required.update(generated / name for name in ("Cargo.toml", "Cargo.lock", "preparation.json"))
    for package in packages:
        if not isinstance(package, dict) or "source" not in package:
            raise ValueError("malformed Cargo metadata package")
        manifest = Path(package["manifest_path"])
        if not manifest.is_absolute():
            raise ValueError("package manifest path is not absolute")
        required.add(manifest)
        required.update((manifest.parent / "src").rglob("*.rs"))
        for filename in ("build.rs", ".cargo-checksum.json"):
            if (manifest.parent / filename).exists():
                required.add(manifest.parent / filename)
    if not {str(path.resolve()) for path in required}.issubset({str(Path(path).resolve()) for path in sources}):
        raise ValueError("build omitted required reviewed local dependency/adapter sources")
    for mode, path in binaries.items():
        entry = receipt["binaries"][mode]
        if Path(entry["path"]).resolve() != path.resolve() or entry["sha256"] != digest(path):
            raise ValueError("binary does not match diagnostic build receipt")
    if receipt["interposer"]["sha256"] != digest(interposer):
        raise ValueError("interposer does not match diagnostic build receipt")
    commands = receipt.get("commands")
    if (not isinstance(commands, list) or not commands
            or any(not isinstance(c, dict) or type(c.get("exit")) is not int
                   or c["exit"] != 0 or c.get("source_changes") != {} for c in commands)):
        raise ValueError("build command failure/source drift")
    logs = {}
    for command in commands:
        log = Path(command["log"])
        if not log.is_absolute() or digest(log) != command.get("log_sha256"):
            raise ValueError("build log binding changed")
        logs[str(log)] = digest(log)
    for accelerated in (False, True):
        for action in ("test", "clippy", "build"):
            found = False
            for entry in commands:
                command = entry.get("command")
                if (not isinstance(command, list) or any(not isinstance(arg, str) for arg in command)
                        or len(command) < 2 or Path(command[0]).name != "cargo" or command[1] != action
                        or "--release" not in command or "--locked" not in command
                        or "--stable-local-metadata" in command):
                    continue
                if command.count("--manifest-path") != 1:
                    continue
                manifest_index = command.index("--manifest-path") + 1
                if (manifest_index >= len(command)
                        or Path(command[manifest_index]).resolve() != (generated / "Cargo.toml").resolve()):
                    continue
                if command.count("--features") > 1:
                    continue
                feature = command.index("--features") + 1 if "--features" in command else None
                if feature is not None and (feature >= len(command) or command[feature] != "accel"):
                    continue
                if (feature is not None) != accelerated:
                    continue
                if action == "clippy" and not all(arg in command for arg in ("--all-targets", "--", "-D", "warnings")):
                    continue
                found = True
            if not found:
                raise ValueError("both locked feature modes require generated-manifest cargo tests, strict all-target clippy and release builds")
    return {**sources, **logs, str(metadata_path): digest(metadata_path)}


def validate_c_controls(receipt: dict, interposer: Path, control_helper, root: Path) -> dict[str, str]:
    """Require every separately calibrated endpoint and exact C source/binary identities."""
    if (receipt.get("controls_passed") is not True or receipt.get("failure") is not None
            or receipt.get("profile_qualified") is not False or receipt.get("complete_native_coverage") is not False
            or receipt.get("complete_workspace_certificate") is not False
            or receipt.get("sources_before") != receipt.get("sources_after")):
        raise ValueError("C endpoint calibration receipt failed/incomplete")
    sources = receipt.get("sources_before")
    if not isinstance(sources, dict) or set(sources) != set(control_helper.SOURCE_NAMES):
        raise ValueError("C calibration source scope incomplete")
    result = {}
    for name, expected in sources.items():
        path = root / PROBE / name
        if digest(path) != expected:
            raise ValueError(f"C calibration source changed: {name}")
        result[str(path)] = expected
    if receipt.get("binaries", {}).get("libnp.dylib") != digest(interposer):
        raise ValueError("C-calibrated interposer differs")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or any(c.get("exit") != 0 for c in commands):
        raise ValueError("C calibration commands incomplete")
    for case in control_helper.UNITS:
        if sum(c.get("label") == "unit-" + case for c in commands) != 1:
            raise ValueError("C internal control missing/duplicated")
    for case in control_helper.CONTROLS:
        selected = [c for c in commands if c.get("label") == "control-" + case]
        if len(selected) != 1:
            raise ValueError("C endpoint/scope control missing/duplicated")
        control_helper.validate_control(case, object_json(selected[0]["stdout"]))
    host = receipt.get("host", {})
    if host.get("machine") != platform.machine() or host.get("macos_version") != platform.mac_ver()[0]:
        raise ValueError("C calibration host architecture/macOS version differs")
    return result


def campaign(root: Path, binaries: dict, interposer: Path, build_receipt: Path,
             controls_receipt: Path, output: Path, timeout: int = 120, execute=subprocess.run) -> dict:
    """Journal every attempted child and fail closed before proofs on control gaps."""
    output.mkdir(parents=True, exist_ok=False)
    journal_path = output / "cases.jsonl"
    journal_path.touch()
    report = {"schema": "parliament-native-probe-campaign-v1", "campaign_passed": False,
              "proof_cases_started": False, "profile_qualified": False, "complete_native_coverage": False,
              "complete_workspace_certificate": False, "started_unix": time.time(), "observations": []}
    guards = {}

    def publish() -> None:
        path = output / "report.tmp"
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        path.replace(output / "report.json")

    def observe(command: list[str], record: dict, validate, env: dict) -> None:
        record["command"] = command
        report["observations"].append(record)
        # A start record remains if the supervisor itself is externally killed.
        with journal_path.open("a") as journal:
            journal.write(json.dumps({"started": True, **record}, sort_keys=True) + "\n")
            journal.flush()
            os.fsync(journal.fileno())
        try:
            child = execute(command, capture_output=True, text=True, env=env, timeout=timeout)
            record.update(exit=child.returncode, stdout=child.stdout, stderr=child.stderr)
            record.update(validate(child))
            record["check_passed"] = True
        except (Exception, KeyboardInterrupt) as error:
            record.update(check_passed=False, failure=f"{type(error).__name__}: {error}")
            if isinstance(error, subprocess.TimeoutExpired):
                for key, partial in (("stdout", error.stdout), ("stderr", error.stderr)):
                    record[key] = partial.decode(errors="replace") if isinstance(partial, bytes) else partial
            raise
        finally:
            with journal_path.open("a") as journal:
                journal.write(json.dumps({"completed": True, **record}, sort_keys=True) + "\n")
                journal.flush()
                os.fsync(journal.fileno())
            publish()

    try:
        if platform.system() != "Darwin" or any(key.startswith("DYLD_") for key in os.environ):
            raise ValueError("requires macOS without inherited DYLD_* variables")
        if set(binaries) != {"portable", "accel"} or timeout <= 0:
            raise ValueError("both feature slots and positive timeout required")
        resource, resource_hash = helper(root / "scripts/check_parliament_ballot_resource_contract.py", "native_resource_cases")
        c_helper, c_hash = helper(root / PROBE / "run_controls.py", "native_c_controls")
        guards.update(validate_build(object_json(build_receipt.read_text()), binaries, interposer, root))
        guards.update(validate_c_controls(object_json(controls_receipt.read_text()), interposer, c_helper, root))
        guards.update({str(build_receipt): digest(build_receipt), str(controls_receipt): digest(controls_receipt),
                       str(interposer): digest(interposer), **{str(path): digest(path) for path in binaries.values()},
                       str(root / "scripts/check_parliament_ballot_resource_contract.py"): resource_hash,
                       str(root / PROBE / "run_controls.py"): c_hash})
        for path in (Path(__file__), root / "scripts/tests/parliament_ballot_native_probe_test.py"):
            guards[str(path)] = digest(path)
        for path in (root / resource.FIXTURES).glob("*"):
            if path.suffix in {".txt", ".proof"}:
                guards[str(path)] = digest(path)
        report["guarded_inputs"] = guards
        corpus = list(resource.cases(root))
        validate_corpus(corpus)
        report["expected_proof_cases"] = 120
        report["host"] = {"machine": platform.machine(), "macos_version": platform.mac_ver()[0]}
        report["observation_scope"] = "Named process-wide endpoints from interposer effectiveness to seal, with charged phase explicit; nested calls are not unique/live bytes. Setup excludes prior loader history."
        plain = dict(os.environ)
        injected = dict(plain, DYLD_INSERT_LIBRARIES=str(interposer))
        report["child_injection"] = {"DYLD_INSERT_LIBRARIES": str(interposer)}
        for mode, binary in binaries.items():
            def missing(child):
                if child.returncode != 75 or child.stdout.strip() or "native observer setup failed" not in child.stderr:
                    raise ValueError("absent-interposer control failed to refuse observation")
                return {"classification": "expected_observer_unavailable", "native_observation": None}
            observe([str(binary), "--control", "empty"], {"kind": "no_interposer", "mode": mode}, missing, plain)
            for name in CONTROLS:
                observe([str(binary), "--control", name], {"kind": "rust_control", "control": name, "mode": mode},
                        lambda child, name=name: validate_control(name, child, binary, interposer), injected)
        if any(digest(Path(path)) != expected for path, expected in guards.items()):
            raise ValueError("guarded source/binary/receipt changed during controls")
        with tempfile.TemporaryDirectory(prefix="parliament-native-inputs-") as temporary:
            for case in corpus:
                path = Path(temporary) / "record.bin"
                if case.get("long_path"):
                    path = Path(temporary).joinpath(*(["x" * 64] * 7), "record.bin")
                    path.parent.mkdir(parents=True)
                if case.get("fifo"):
                    path = Path(temporary) / "record.fifo"
                    os.mkfifo(path)
                else:
                    path.write_bytes(case["input"])
                for mode, binary in binaries.items():
                    record = {key: value for key, value in case.items() if key != "input"}
                    record.update(kind="proof_case", mode=mode, input_bytes=len(case["input"]),
                                  input_sha256=hashlib.sha256(case["input"]).hexdigest())
                    report["proof_cases_started"] = True
                    observe([str(binary), case["row"], case["role"], str(path), *case["flags"]], record,
                            lambda child: validate_case(case, child, mode, binary, interposer, resource), injected)
        completed = [record for record in report["observations"] if record["kind"] == "proof_case" and record.get("check_passed")]
        identifiers = {(record["mode"], *case_identity(record)) for record in completed}
        if len(completed) != 120 or len(identifiers) != 120 or {record["mode"] for record in completed} != {"portable", "accel"}:
            raise ValueError("proof campaign incomplete or duplicated")
        report["campaign_passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        changes = {}
        for path, expected in guards.items():
            try:
                actual = digest(Path(path))
            except OSError:
                actual = None
            if actual != expected:
                changes[path] = {"before": expected, "after": actual}
        report["input_changes"] = changes
        if changes:
            report["campaign_passed"] = False
            report.setdefault("failure", "guarded source/binary/receipt changed")
        report["finished_unix"] = time.time()
        report["completed_observations"] = sum(o.get("check_passed", False) for o in report["observations"])
        report["completed_proof_cases"] = sum(o.get("check_passed", False) and o["kind"] == "proof_case" for o in report["observations"])
        publish()
    return report


def main() -> int:
    """Require explicit binaries/evidence and preserve an unsuccessful new run."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("portable", "accel", "build-receipt", "interposer", "controls-receipt", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        report = campaign(ROOT, {mode: getattr(args, mode).resolve() for mode in ("portable", "accel")},
                          args.interposer.resolve(), args.build_receipt.resolve(), args.controls_receipt.resolve(),
                          args.output_dir.resolve(), args.timeout)
    except OSError as error:
        print(json.dumps({"campaign_passed": False, "failure": str(error), "profile_qualified": False}))
        return 1
    print(json.dumps({key: report.get(key) for key in ("campaign_passed", "completed_proof_cases", "failure", "profile_qualified")}))
    return 0 if report["campaign_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
