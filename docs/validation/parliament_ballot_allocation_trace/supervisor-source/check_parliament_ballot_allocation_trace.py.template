#!/usr/bin/env python3
"""Compare finite compiled verifier allocation streams with the source grammar.

Python 3.11+, explicit separately built portable/accelerated diagnostic workers,
successful build receipt, local public fixtures and adjacent model helpers.
No network, device access, root build changes or production writes. Output must
be a NEW directory. Inherited loader injection is refused. Controls run first;
overflow, collision and terminal OOM never become complete allocation evidence.
Raw Norito JSON dumps are retained in deterministic gzip files, with both hashes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time

import check_parliament_ballot_resource_contract as resource
import parliament_ballot_allocation_cases as corpus
import parliament_ballot_allocation_match as matcher

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path("crates/iroha_parliament_ballot_proof/examples/allocation_trace")
RESOURCE = Path("crates/iroha_parliament_ballot_proof/examples/resource_contract")
HEX = re.compile(r"[0-9a-f]{64}")
CAPACITY = 524288
MAX_DUMP_BYTES = 64 * 1024 * 1024
CONTROLS = ("empty", "routed", "realloc", "overflow", "collision")


def digest(path: Path) -> str:
    """Identify file bytes, never a timestamp or path alone."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def object_json(text: str) -> dict:
    """Reject missing, trailing or non-object JSON data."""
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def read_dump(path: Path, expected_header: dict, *, phase: int, flags: int = 0) -> list:
    """Require complete typed records and the exact worker-reported sealed header."""
    if path.stat().st_size > MAX_DUMP_BYTES:
        raise ValueError("diagnostic dump exceeds reader cap")
    dump = object_json(path.read_text())
    header = dump.get("header")
    if set(dump) != {"header", "records"} or not isinstance(header, dict) or header != expected_header:
        raise ValueError("dump/header differs from worker report")
    expected = {"schema": "parliament-allocation-trace-v1", "capacity": CAPACITY,
                "flags": flags, "phase_before_seal": phase, "trace_reserved_bytes": 16 * 1024 * 1024,
                "arena_bytes": 32 * 1024 * 1024, "observation_valid": flags == 0,
                "terminal_prefix": False, "complete_workspace_certificate": False,
                "profile_qualified": False}
    if set(header) != set(expected) | {"events"} or any(type(header.get(k)) is not type(v) or header[k] != v for k, v in expected.items()):
        raise ValueError("trace schema/phase/flags/qualification mismatch")
    events, records = header.get("events"), dump.get("records")
    if type(events) is not int or not 0 <= events <= CAPACITY or not isinstance(records, list) or len(records) != events:
        raise ValueError("trace count/capacity mismatch")
    result = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"op", "offset", "size", "align"}:
            raise ValueError("malformed allocation record")
        row = [record[key] for key in ("op", "offset", "size", "align")]
        if (any(type(v) is not int or not 0 <= v < 1 << 64 for v in row)
                or row[0] not in (1, 2) or not 0 < row[2] <= 32 * 1024 * 1024
                or not row[3] or row[3] & (row[3] - 1)
                or row[1] % 64 or row[1] % row[3]
                or row[1] + row[2] > 32 * 1024 * 1024):
            raise ValueError("invalid allocation record layout/range")
        result.append(row)
    return result


def retain_dump(path: Path) -> dict:
    """Compress only this new run's dump losslessly and retain exact identities."""
    if not path.exists():
        return {"dump_missing": True}
    data = path.read_bytes()
    compressed = gzip.compress(data, compresslevel=9, mtime=0)
    target = path.with_suffix(path.suffix + ".gz")
    with target.open("xb") as output:
        output.write(compressed)
    if gzip.decompress(target.read_bytes()) != data:
        raise ValueError("retained dump roundtrip failed")
    path.unlink()
    return {"dump_path": str(target), "dump_raw_bytes": len(data),
            "dump_raw_sha256": hashlib.sha256(data).hexdigest(), "dump_gzip_sha256": digest(target)}


def validate_control(name: str, child, path: Path) -> dict:
    """Calibrate ordered allocation/reallocation and invalid recorder outcomes."""
    value = object_json(child.stdout)
    flags = {"overflow": 2, "collision": 4}.get(name, 0)
    expected_allocations = {"empty": 0, "routed": 1, "realloc": 2, "overflow": CAPACITY // 2 + 1, "collision": 0}
    if (name not in expected_allocations or child.returncode != (76 if flags else 0)
            or child.stderr.strip() or value.get("control") != name
            or value.get("profile_qualified") is not False or value.get("complete_workspace_certificate") is not False
            or type(value.get("routed_allocations")) is not int or value["routed_allocations"] != expected_allocations[name]):
        raise ValueError("unexpected control status/count/qualification")
    records = read_dump(path, value.get("trace"), phase=3, flags=flags)
    if flags:
        if len(records) != (CAPACITY if name == "overflow" else 0):
            raise ValueError("invalid control did not retain expected bounded prefix")
        return {"classification": "expected_invalid_recorder", "parsed": value,
                "finite_ordered_stream_match": False, "invalid_prefix_events": len(records)}
    grammar = []
    if name in {"routed", "realloc"}:
        grammar.append({"op": "alloc", "id": "original", "size": 73, "align": 16})
        if name == "realloc":
            grammar.append({"op": "alloc", "id": "grown", "size": 257, "align": 16})
        grammar.append({"op": "free", "id": "original"})
        if name == "realloc":
            grammar.append({"op": "free", "id": "grown"})
    return {"classification": "control_matched", "parsed": value, "match": matcher.compare(records, grammar)}


def validate_case(case: dict, child, path: Path, mode: str) -> dict:
    """Compare every observed event, plus actual outcome, stage, debit and peaks."""
    value = object_json(child.stdout)
    if (child.stderr.strip() or value.get("profile_qualified") is not False
            or value.get("complete_workspace_certificate") is not False):
        raise ValueError("unexpected stderr or inflated wrapper claim")
    worker = value.get("worker")
    resource.validate_observation(case, child.returncode, worker, mode)
    for key in ("charged_units", "charged_bytes", "arena_allocations", "arena_peak_requested_bytes", "arena_peak_block_bytes",
                "arena_live_exit_requested_bytes", "arena_live_exit_block_bytes"):
        if type(worker.get(key)) is not int or worker[key] < 0:
            raise ValueError("worker counter must be an unsigned integer: " + key)
    if worker["arena_live_exit_requested_bytes"] != 0 or worker["arena_live_exit_block_bytes"] != 0:
        raise ValueError("worker retained live allocation ownership")
    if worker.get("verifier_stage") != case["expected_stage"]:
        raise ValueError("case did not reach expected verifier boundary")
    expected_read = case["case"].removeprefix("charged_read_") if case["stop"] == "read" else "normal"
    if value.get("read_mode") != expected_read:
        raise ValueError("charged diagnostic read mode differs")
    records = read_dump(path, value.get("trace"), phase=3 if case["expected_charge"] else 1)
    match = matcher.compare(records, corpus.grammar(case, mode == "accel"))
    for actual, modeled in (("arena_allocations", "allocations_observed"), ("arena_peak_requested_bytes", "peak_requested_bytes"),
                            ("arena_peak_block_bytes", "peak_block_bytes")):
        if type(worker.get(actual)) is not int or worker[actual] != match[modeled]:
            raise ValueError("worker/model statistic mismatch: " + actual)
    return {"worker": worker, "trace": value["trace"], "match": match}


def validate_terminal(case: dict, child, path: Path, mode: str) -> dict:
    """Retain original terminal OOM without inventing a sealed stream."""
    worker = object_json(child.stdout)
    resource.validate_observation(case, child.returncode, worker, mode)
    if any(type(worker.get(key)) is not int for key in ("charged_units", "charged_bytes")):
        raise ValueError("terminal debit must be integer")
    if child.returncode != 73 or path.stat().st_size != 0 or child.stderr.strip():
        raise ValueError("terminal OOM unexpectedly published allocation evidence")
    return {"classification": "expected_terminal_without_trace", "allocation_observation": None,
            "missing_reason": "terminal worker exit precedes cleanup/seal; no complete stream or zero substitution"}


def validate_build(receipt: dict, binaries: dict, root: Path) -> dict[str, str]:
    """Derive required local-source scope from retained Cargo metadata and bind bytes."""
    if (receipt.get("schema") != "parliament-allocation-trace-build-v1" or receipt.get("source_stable") is not True
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
    required.add(root / "scripts/prepare_parliament_ballot_allocation_trace.py")
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
                if any(arg in {"--all-features", "--no-default-features", "-F"} or arg.startswith(("--features=", "-F")) for arg in command):
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


def campaign(root: Path, binaries: dict, build_receipt: Path, output: Path,
             timeout: int = 120, execute=subprocess.run) -> dict:
    """Retain every attempted observation, requiring controls before proof inputs."""
    output.mkdir(parents=True, exist_ok=False)
    journal = output / "cases.jsonl"
    journal.touch()
    guards = {}
    report = {"schema": "parliament-allocation-trace-campaign-v1", "campaign_passed": False,
              "profile_qualified": False, "complete_allocation_correspondence": False,
              "complete_workspace_certificate": False, "proof_cases_started": False,
              "started_unix": time.time(), "observations": []}

    def publish() -> None:
        temporary = output / "report.tmp"
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary.replace(output / "report.json")

    def append(value: dict) -> None:
        with journal.open("a") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def observe(command: list[str], row: dict, trace_path: Path, validate) -> None:
        row["command"] = command
        report["observations"].append(row)
        append({"started": True, **row})
        try:
            child = execute(command, capture_output=True, text=True, timeout=timeout)
            row.update(exit=child.returncode, stdout=child.stdout, stderr=child.stderr)
            row.update(validate(child))
            row["check_passed"] = True
        except (Exception, KeyboardInterrupt) as error:
            row.update(check_passed=False, failure=f"{type(error).__name__}: {error}")
            if isinstance(error, subprocess.TimeoutExpired):
                for key, value in (("stdout", error.stdout), ("stderr", error.stderr)):
                    row[key] = value.decode(errors="replace") if isinstance(value, bytes) else value
            raise
        finally:
            try:
                row.update(retain_dump(trace_path))
            except Exception as error:
                row.update(check_passed=False, retention_failure=str(error))
                raise
            finally:
                append({"completed": True, **row})
                publish()

    try:
        if any(key.startswith("DYLD_") or key == "LD_PRELOAD" for key in os.environ):
            raise ValueError("loader injection must be absent for this separate diagnostic")
        if set(binaries) != {"portable", "accel"} or timeout <= 0:
            raise ValueError("both binaries and a positive timeout required")
        guards.update(validate_build(object_json(build_receipt.read_text()), binaries, root))
        for path in [build_receipt, *binaries.values(), Path(__file__)]:
            guards[str(path)] = digest(path)
        for pattern in ("parliament_ballot_allocation*.py", "parliament_ballot_arena*.py", "check_parliament_ballot_resource_contract.py"):
            for path in (root / "scripts").glob(pattern):
                guards[str(path)] = digest(path)
        for path in (root / "scripts/tests").glob("parliament_ballot_allocation*_test.py"):
            guards[str(path)] = digest(path)
        for path in (root / resource.FIXTURES).glob("*"):
            if path.suffix in {".txt", ".proof"}:
                guards[str(path)] = digest(path)
        report["guarded_inputs"] = guards
        report["host"] = {"machine": platform.machine(), "system": platform.system(), "release": platform.release()}
        cases = corpus.build_cases(root)
        if len(cases) != 66 or len({case["name"] for case in cases}) != 66:
            raise ValueError("finite corpus incomplete/duplicated")
        for mode, binary in binaries.items():
            for name in CONTROLS:
                path = output / f"{mode}-control-{name}.json"
                observe([str(binary), str(path), "--control", name], {"kind": "control", "mode": mode, "name": name}, path,
                        lambda child, name=name, path=path: validate_control(name, child, path))
            path = output / f"{mode}-existing-output.json"
            path.write_bytes(b"preserve-existing-output\n")

            def existing(child):
                if child.returncode != 75 or child.stdout.strip() or "allocation trace setup failed" not in child.stderr or path.read_bytes() != b"preserve-existing-output\n":
                    raise ValueError("existing dump was not refused and preserved")
                return {"classification": "expected_setup_refusal"}

            observe([str(binary), str(path), "--control", "empty"], {"kind": "existing_output", "mode": mode}, path, existing)
        if any(digest(Path(name)) != expected for name, expected in guards.items()):
            raise ValueError("guarded inputs changed during controls")
        with tempfile.TemporaryDirectory(prefix="parliament-allocation-inputs-") as temporary:
            record_path = Path(temporary) / "record.bin"
            terminal = next(case.copy() for case in cases if case["name"] == "candidate-registration-0-valid")
            terminal.update(case="arena_exhaustion", expected_outcome="resource_exhausted", expected_exit=73)
            record_path.write_bytes(terminal["input"])
            for mode, binary in binaries.items():
                path = output / f"{mode}-terminal-oom.json"
                observe([str(binary), str(path), "candidate", "registration", str(record_path), "--heap-limit", "0"],
                        {"kind": "terminal_control", "mode": mode}, path,
                        lambda child, path=path, mode=mode: validate_terminal(terminal, child, path, mode))
            for case in cases:
                record_path.write_bytes(case["input"])
                for mode, binary in binaries.items():
                    path = output / f"{mode}-{case['name']}.json"
                    row = {key: value for key, value in case.items() if key != "input"}
                    row.update(kind="proof_case", mode=mode, input_bytes=len(case["input"]), input_sha256=hashlib.sha256(case["input"]).hexdigest())
                    report["proof_cases_started"] = True
                    observe([str(binary), str(path), case["row"], case["role"], str(record_path), *case["flags"]], row, path,
                            lambda child, path=path, mode=mode: validate_case(case, child, path, mode))
        proofs = [row for row in report["observations"] if row["kind"] == "proof_case" and row.get("check_passed")]
        if len(proofs) != 132 or len({(row["mode"], row["name"]) for row in proofs}) != 132:
            raise ValueError("proof campaign incomplete or duplicated")
        report["campaign_passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        changes = {}
        for name, expected in guards.items():
            try:
                actual = digest(Path(name))
            except OSError:
                actual = None
            if actual != expected:
                changes[name] = {"before": expected, "after": actual}
        report["input_changes"] = changes
        if changes:
            report["campaign_passed"] = False
            report.setdefault("failure", "guarded inputs changed during campaign")
        report["completed_observations"] = sum(row.get("check_passed", False) for row in report["observations"])
        report["completed_proof_cases"] = sum(row.get("check_passed", False) and row["kind"] == "proof_case" for row in report["observations"])
        report["finished_unix"] = time.time()
        publish()
    return report


def main() -> int:
    """Require explicit evidence paths and fail on any incomplete observation."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("portable", "accel", "build-receipt", "output-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    report = campaign(ROOT, {"portable": args.portable.resolve(), "accel": args.accel.resolve()},
                      args.build_receipt.resolve(), args.output_dir.resolve(), args.timeout)
    print(json.dumps({key: value for key, value in report.items() if key not in {"observations", "guarded_inputs"}}, sort_keys=True))
    return 0 if report["campaign_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
