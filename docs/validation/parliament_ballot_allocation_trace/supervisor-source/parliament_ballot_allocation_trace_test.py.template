"""Allocation-stream supervisor guards; synthetic children, no proof execution."""
from __future__ import annotations

from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_parliament_ballot_allocation_trace as runner


def header(events=0, phase=3, flags=0):
    return {"schema": "parliament-allocation-trace-v1", "events": events,
            "capacity": runner.CAPACITY, "flags": flags, "phase_before_seal": phase,
            "trace_reserved_bytes": 16 * 1024 * 1024, "arena_bytes": 32 * 1024 * 1024,
            "observation_valid": flags == 0, "terminal_prefix": False,
            "complete_workspace_certificate": False, "profile_qualified": False}


def dump(path, records=(), phase=3, flags=0):
    value = header(len(records), phase, flags)
    path.write_text(json.dumps({"header": value, "records": [
        dict(zip(("op", "offset", "size", "align"), row)) for row in records]}))
    return value


def child(value, code=0, stderr=""):
    return subprocess.CompletedProcess([], code, json.dumps(value), stderr)


def simple_case(charge=1, stop="backend"):
    return {"input": b"12345678", "expected_charge": charge,
            "expected_exit": 0 if charge else 2,
            "expected_outcome": "accepted" if charge else "admission_rejected",
            "expected_stage": "complete" if charge else "reserve", "stop": stop,
            "case": "valid", "row": "candidate", "role": "registration", "flags": []}


def worker(case, mode="portable"):
    parts = {"heap_reserved_bytes": 32 * 1024 * 1024,
             "metadata_reserved_bytes": 1024 * 1024, "stack_usable_bytes": 8 * 1024 * 1024,
             "control_reserved_bytes": 64 * 1024, "guard_bytes": 2 * runner.os.sysconf("SC_PAGESIZE")}
    return {**parts, "workspace_reserved_bytes": sum(parts.values()),
            "heap_limit_bytes": 32 * 1024 * 1024, "arena_enforced": True,
            "outcome": case["expected_outcome"], "verifier_stage": case["expected_stage"],
            "charged_units": case["expected_charge"],
            "charged_bytes": len(case["input"]) if case["expected_charge"] else 0,
            "accelerated": mode == "accel", "complete_workspace_certificate": False,
            "profile_qualified": False, "arena_allocations": int(bool(case["expected_charge"])),
            "arena_peak_requested_bytes": len(case["input"]) if case["expected_charge"] else 0,
            "arena_peak_block_bytes": 64 if case["expected_charge"] else 0,
            "arena_live_exit_requested_bytes": 0, "arena_live_exit_block_bytes": 0}


def ordinary(path, case=None, mode="portable"):
    case = simple_case() if case is None else case
    records = [[1, 0, len(case["input"]), 1], [2, 0, len(case["input"]), 1]] if case["expected_charge"] else []
    return {"worker": worker(case, mode), "trace": dump(path, records, 3 if case["expected_charge"] else 1),
            "read_mode": case["case"].removeprefix("charged_read_") if case["stop"] == "read" else "normal",
            "profile_qualified": False, "complete_workspace_certificate": False}


def simple_grammar(case, accelerated):
    if not case["expected_charge"]:
        return []
    return [{"op": "alloc", "id": "record", "size": len(case["input"]), "align": 1},
            {"op": "free", "id": "record"}]


def build_fixture(root):
    generated = root / "generated"
    registry = root / "registry/package"
    required = [root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
    required += [root / runner.RESOURCE / (name + ".rs") for name in ("arena", "budget", "native", "workspace")]
    required += [root / runner.PROBE / name for name in ("trace.rs", "driver.rs", "controls.rs")]
    required += [root / "scripts/prepare_parliament_ballot_allocation_trace.py"]
    required += [generated / name for name in ("Cargo.toml", "Cargo.lock", "preparation.json", "driver.rs")]
    required += [registry / name for name in ("Cargo.toml", "src/lib.rs", "build.rs", ".cargo-checksum.json")]
    for path in required:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("reviewed source")
    binaries = {mode: root / mode for mode in ("portable", "accel")}
    for mode, path in binaries.items():
        path.write_text(mode)
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
            log = root / f"{accelerated}-{action}.txt"
            log.write_text("passed")
            commands.append({"command": command, "exit": 0, "source_changes": {},
                             "log": str(log), "log_sha256": runner.digest(log)})
    receipt = {"schema": "parliament-allocation-trace-build-v1", "source_stable": True,
               "failure": None, "profile_qualified": False, "complete_workspace_certificate": False,
               "source_files": {str(path): runner.digest(path) for path in required},
               "generated_dir": str(generated), "dependency_metadata_path": str(metadata),
               "dependency_metadata_sha256": runner.digest(metadata), "commands": commands,
               "binaries": {mode: {"path": str(path), "sha256": runner.digest(path)} for mode, path in binaries.items()}}
    return receipt, binaries


def synthetic_corpus():
    cases = [{**simple_case(), "name": f"case-{i}"} for i in range(66)]
    cases[0]["name"] = "candidate-registration-0-valid"
    return cases


def campaign_setup(root):
    binaries = {mode: root / mode for mode in ("portable", "accel")}
    for mode, path in binaries.items():
        path.write_text(mode)
    receipt = root / "build.json"
    receipt.write_text("{}")
    return binaries, receipt


def synthetic_execute(command, **kwargs):
    path = Path(command[1])
    if path.exists() and path.read_bytes() == b"preserve-existing-output\n":
        return subprocess.CompletedProcess(command, 75, "", "allocation trace setup failed: exists")
    path.write_bytes(b"" if "--heap-limit" in command else b"observed dump")
    return subprocess.CompletedProcess(command, 73 if "--heap-limit" in command else 0, "{}", "")


def test_digest_and_object_json_are_exact(tmp_path):
    path = tmp_path / "bytes"
    path.write_bytes(b"abc")
    assert runner.digest(path) == hashlib.sha256(b"abc").hexdigest()
    assert runner.object_json('{"key":1}') == {"key": 1}
    for text in ("", "[]", "null", "1", "{} {}"):
        with pytest.raises(ValueError):
            runner.object_json(text)


def test_dump_exact_records_and_type_guards(tmp_path):
    path = tmp_path / "dump.json"
    records = [[1, 64, 73, 16], [2, 64, 73, 16]]
    expected = dump(path, records)
    assert runner.read_dump(path, expected, phase=3) == records
    original = json.loads(path.read_text())
    for key, value in (("capacity", True), ("events", True), ("flags", False),
                       ("phase_before_seal", 2), ("terminal_prefix", True),
                       ("profile_qualified", True), ("trace_reserved_bytes", 1)):
        changed = deepcopy(original)
        changed["header"][key] = value
        path.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            runner.read_dump(path, changed["header"], phase=3)
    for key, value in (("op", True), ("op", 3), ("offset", 1), ("offset", 1 << 25),
                       ("size", 0), ("size", 1 << 64), ("align", 3), ("align", False)):
        changed = deepcopy(original)
        changed["records"][0][key] = value
        path.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            runner.read_dump(path, expected, phase=3)
    for changed in ({**original, "extra": 0}, {**original, "records": []},
                    {**original, "records": [[1, 0, 1, 1]]}):
        path.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            runner.read_dump(path, expected, phase=3)
    path.write_text(json.dumps(original))
    with pytest.raises(ValueError):
        runner.read_dump(path, {**expected, "events": 0}, phase=3)
    with patch.object(runner, "MAX_DUMP_BYTES", 1), pytest.raises(ValueError, match="reader cap"):
        runner.read_dump(path, expected, phase=3)


def test_dump_retention_is_lossless_exclusive_and_missing_explicit(tmp_path):
    path = tmp_path / "dump.json"
    assert runner.retain_dump(path) == {"dump_missing": True}
    content = b'{"records":[]}\n'
    path.write_bytes(content)
    result = runner.retain_dump(path)
    assert not path.exists()
    compressed = Path(result["dump_path"])
    assert gzip.decompress(compressed.read_bytes()) == content
    assert result["dump_raw_sha256"] == hashlib.sha256(content).hexdigest()
    assert result["dump_gzip_sha256"] == runner.digest(compressed)
    assert compressed.read_bytes()[4:8] == bytes(4)
    path.write_bytes(b"new")
    with pytest.raises(FileExistsError):
        runner.retain_dump(path)
    assert path.read_bytes() == b"new"


@pytest.mark.parametrize("name,records,count", [
    ("empty", [], 0), ("routed", [[1, 0, 73, 16], [2, 0, 73, 16]], 1),
    ("realloc", [[1, 0, 73, 16], [1, 512, 257, 16], [2, 0, 73, 16], [2, 512, 257, 16]], 2)])
def test_controls_require_actual_exact_stream(tmp_path, name, records, count):
    path = tmp_path / "dump.json"
    value = {"control": name, "routed_allocations": count, "trace": dump(path, records),
             "profile_qualified": False, "complete_workspace_certificate": False}
    result = runner.validate_control(name, child(value), path)
    assert result["classification"] == "control_matched"
    assert result["match"]["events_matched"] == len(records)
    for key, wrong in (("control", "other"), ("routed_allocations", True),
                       ("routed_allocations", count + 1), ("profile_qualified", True)):
        with pytest.raises(ValueError):
            runner.validate_control(name, child({**value, key: wrong}), path)
    for bad_child in (child(value, 76), child(value, stderr="unexpected")):
        with pytest.raises(ValueError):
            runner.validate_control(name, bad_child, path)


def test_invalid_controls_retain_prefix_but_never_match(tmp_path):
    path = tmp_path / "dump.json"
    with patch.object(runner, "CAPACITY", 4):
        for name, flags, records, count in (
            ("overflow", 2, [[1, 0, 73, 16], [2, 0, 73, 16]] * 2, 3),
            ("collision", 4, [], 0)):
            value = {"control": name, "routed_allocations": count, "trace": dump(path, records, flags=flags),
                     "profile_qualified": False, "complete_workspace_certificate": False}
            result = runner.validate_control(name, child(value, 76), path)
            assert result["classification"] == "expected_invalid_recorder"
            assert not result["finite_ordered_stream_match"]
            with pytest.raises(ValueError):
                runner.validate_control(name, child(value), path)
        value["trace"] = dump(path, [[1, 0, 73, 16]], flags=4)
        with pytest.raises(ValueError, match="bounded prefix"):
            runner.validate_control("collision", child(value, 76), path)


def test_case_checks_stage_debit_mode_and_real_match(tmp_path):
    path = tmp_path / "dump.json"
    with patch.object(runner.corpus, "grammar", side_effect=simple_grammar):
        for mode in ("portable", "accel"):
            for charge in (0, 1):
                case = simple_case(charge)
                value = ordinary(path, case, mode)
                assert runner.validate_case(case, child(value, case["expected_exit"]), path, mode)["match"]["finite_ordered_stream_match"]
        case = simple_case()
        value = ordinary(path, case)
        for key, wrong in (("verifier_stage", "codec"), ("charged_units", 0), ("charged_bytes", 7),
                           ("accelerated", True), ("arena_allocations", 2),
                           ("arena_peak_requested_bytes", 7), ("arena_live_exit_block_bytes", 64)):
            bad = deepcopy(value)
            bad["worker"][key] = wrong
            with pytest.raises(ValueError):
                runner.validate_case(case, child(bad), path, "portable")
        for key, wrong in (("read_mode", "eof"), ("profile_qualified", True), ("worker", [])):
            with pytest.raises(ValueError):
                runner.validate_case(case, child({**value, key: wrong}), path, "portable")
        value["trace"] = dump(path, [[1, 64, 8, 1], [2, 64, 8, 1]])
        with pytest.raises(ValueError, match="expected"):
            runner.validate_case(case, child(value), path, "portable")


def test_case_debits_and_cleanup_require_real_integers(tmp_path):
    path = tmp_path / "dump.json"
    case = simple_case()
    with patch.object(runner.corpus, "grammar", side_effect=simple_grammar):
        for key, wrong in (("charged_units", True), ("charged_bytes", 8.0),
                           ("arena_live_exit_requested_bytes", False), ("arena_live_exit_block_bytes", 0.0)):
            value = ordinary(path, case)
            value["worker"][key] = wrong
            with pytest.raises(ValueError):
                runner.validate_case(case, child(value), path, "portable")


def test_charged_read_and_terminal_are_not_complete_proof_streams(tmp_path):
    path = tmp_path / "dump.json"
    with patch.object(runner.corpus, "grammar", side_effect=simple_grammar):
        for mode in ("eof", "eio"):
            case = {**simple_case(), "case": "charged_read_" + mode, "stop": "read",
                    "expected_exit": 3, "expected_outcome": "input_error", "expected_stage": "read"}
            value = ordinary(path, case)
            assert runner.validate_case(case, child(value, 3), path, "portable")["worker"]["outcome"] == "input_error"
    case = {**simple_case(), "case": "arena_exhaustion", "expected_exit": 73, "expected_outcome": "arena_exhausted"}
    value = worker(case)
    path.write_bytes(b"")
    result = runner.validate_terminal(case, child(value, 73), path, "portable")
    assert result["allocation_observation"] is None
    for altered, exit_code in ((value, -6), ({**value, "charged_units": 0}, 73),
                                ({**value, "charged_units": True}, 73)):
        with pytest.raises(ValueError):
            runner.validate_terminal(case, child(altered, exit_code), path, "portable")
    path.write_text("{}")
    with pytest.raises(ValueError):
        runner.validate_terminal(case, child(value, 73), path, "portable")
    path.unlink()
    with pytest.raises((OSError, ValueError)):
        runner.validate_terminal(case, child(value, 73), path, "portable")


def test_build_binds_required_sources_binaries_metadata_logs_and_aliases(tmp_path):
    receipt, binaries = build_fixture(tmp_path)
    checked = runner.validate_build(receipt, binaries, tmp_path)
    assert receipt["dependency_metadata_path"] in checked
    original = str(tmp_path / "generated/driver.rs")
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / "generated", target_is_directory=True)
    aliased = deepcopy(receipt)
    aliased["source_files"][str(alias / "driver.rs")] = aliased["source_files"].pop(original)
    runner.validate_build(aliased, binaries, tmp_path)
    mutations = []
    for key, wrong in (("source_stable", False), ("failure", "failed"),
                       ("profile_qualified", True), ("source_files", {})):
        mutations.append({**receipt, key: wrong})
    missing = deepcopy(receipt)
    del missing["source_files"][str(tmp_path / "registry/package/src/lib.rs")]
    mutations.append(missing)
    bad = deepcopy(receipt); bad["binaries"]["portable"]["sha256"] = "0" * 64; mutations.append(bad)
    bad = deepcopy(receipt); bad["dependency_metadata_sha256"] = "0" * 64; mutations.append(bad)
    bad = deepcopy(receipt); bad["commands"][0]["log_sha256"] = "0" * 64; mutations.append(bad)
    bad = deepcopy(receipt); bad["commands"][0]["source_changes"] = {"drift": True}; mutations.append(bad)
    bad = deepcopy(receipt); bad["commands"][0]["exit"] = False; mutations.append(bad)
    for bad in mutations:
        with pytest.raises(ValueError):
            runner.validate_build(bad, binaries, tmp_path)
    (tmp_path / "registry/package/src/lib.rs").write_text("drift")
    with pytest.raises(ValueError, match="source changed"):
        runner.validate_build(receipt, binaries, tmp_path)


def test_build_requires_all_six_exact_command_bindings(tmp_path):
    receipt, binaries = build_fixture(tmp_path)
    for i in range(6):
        variants = []
        bad = deepcopy(receipt); del bad["commands"][i]; variants.append(bad)
        for token in ("--locked", "--release"):
            bad = deepcopy(receipt); bad["commands"][i]["command"].remove(token); variants.append(bad)
        bad = deepcopy(receipt); bad["commands"][i]["command"][0] = "echo"; variants.append(bad)
        bad = deepcopy(receipt)
        command = bad["commands"][i]["command"]
        command[command.index("--manifest-path") + 1] = str(tmp_path / "Cargo.toml")
        variants.append(bad)
        for bad in variants:
            with pytest.raises(ValueError):
                runner.validate_build(bad, binaries, tmp_path)
    bad = deepcopy(receipt); bad["commands"][1]["command"].remove("--all-targets")
    with pytest.raises(ValueError):
        runner.validate_build(bad, binaries, tmp_path)


@pytest.mark.parametrize("option", ["--all-features", "--features=accel", "-Faccel", "--no-default-features"])
def test_build_rejects_unparsed_feature_mode_options(tmp_path, option):
    receipt, binaries = build_fixture(tmp_path)
    receipt["commands"][0]["command"].append(option)
    with pytest.raises(ValueError):
        runner.validate_build(receipt, binaries, tmp_path)


def test_campaign_setup_failures_saved_and_output_not_overwritten(tmp_path):
    out = tmp_path / "out"
    with patch.dict(runner.os.environ, {}, clear=True):
        result = runner.campaign(tmp_path, {}, tmp_path / "missing", out)
    assert not result["campaign_passed"] and not result["proof_cases_started"]
    assert json.loads((out / "report.json").read_text())["failure"]
    assert (out / "cases.jsonl").read_text() == ""
    with pytest.raises(FileExistsError):
        runner.campaign(tmp_path, {}, tmp_path / "missing", out)
    with patch.dict(runner.os.environ, {"DYLD_INSERT_LIBRARIES": "unexpected"}, clear=True):
        result = runner.campaign(tmp_path, {}, tmp_path / "missing", tmp_path / "injected")
    assert "loader injection" in result["failure"]


@pytest.mark.parametrize("failure_kind", ["control", "timeout", "interrupt", "retention"])
def test_controls_fail_before_proofs_and_keep_partial_receipts(tmp_path, failure_kind):
    binaries, receipt = campaign_setup(tmp_path)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if failure_kind == "timeout":
            raise subprocess.TimeoutExpired(command, 1, b"partial", b"error")
        if failure_kind == "interrupt":
            raise KeyboardInterrupt()
        return synthetic_execute(command, **kwargs)

    with patch.dict(runner.os.environ, {}, clear=True), \
         patch.object(runner, "validate_build", return_value={}), \
         patch.object(runner.corpus, "build_cases", return_value=synthetic_corpus()), \
         patch.object(runner, "validate_control", side_effect=ValueError("control failed") if failure_kind == "control" else None), \
         patch.object(runner, "retain_dump", side_effect=OSError("retain failed") if failure_kind == "retention" else runner.retain_dump):
        result = runner.campaign(tmp_path, binaries, receipt, tmp_path / "out", execute=execute)
    assert not result["campaign_passed"] and not result["proof_cases_started"]
    assert len(calls) == 1
    journal = [json.loads(line) for line in (tmp_path / "out/cases.jsonl").read_text().splitlines()]
    assert journal[0]["started"] and journal[-1]["completed"]
    assert not journal[-1]["check_passed"]
    if failure_kind == "timeout":
        assert journal[-1]["stdout"] == "partial" and journal[-1]["stderr"] == "error"
    if failure_kind == "retention":
        assert journal[-1]["retention_failure"] == "retain failed"


@pytest.mark.parametrize("bad", [[], synthetic_corpus()[:-1], synthetic_corpus()[:-1] + [synthetic_corpus()[0]]])
def test_incomplete_corpus_starts_no_children(tmp_path, bad):
    binaries, receipt = campaign_setup(tmp_path)
    with patch.dict(runner.os.environ, {}, clear=True), \
         patch.object(runner, "validate_build", return_value={}), \
         patch.object(runner.corpus, "build_cases", return_value=bad), \
         patch.object(runner.subprocess, "run") as execute:
        result = runner.campaign(tmp_path, binaries, receipt, tmp_path / "out", execute=execute)
    execute.assert_not_called()
    assert not result["campaign_passed"] and not result["proof_cases_started"]


@pytest.mark.parametrize("failure_kind", [None, "proof", "source-drift", "existing-output"])
def test_full_campaign_order_counts_refusals_and_drift(tmp_path, failure_kind):
    binaries, receipt = campaign_setup(tmp_path)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if failure_kind == "source-drift" and len(calls) == 1:
            binaries["portable"].write_text("drift")
        if failure_kind == "existing-output" and "existing-output" in command[1]:
            Path(command[1]).write_text("overwritten")
            return subprocess.CompletedProcess(command, 75, "", "allocation trace setup failed")
        return synthetic_execute(command, **kwargs)

    with patch.dict(runner.os.environ, {}, clear=True), \
         patch.object(runner, "validate_build", return_value={}), \
         patch.object(runner.corpus, "build_cases", return_value=synthetic_corpus()), \
         patch.object(runner, "validate_control", return_value={"classification": "control"}), \
         patch.object(runner, "validate_terminal", return_value={"allocation_observation": None}), \
         patch.object(runner, "validate_case", side_effect=ValueError("proof mismatch") if failure_kind == "proof" else None) as validate:
        validate.return_value = {"match": {"finite_ordered_stream_match": True}}
        result = runner.campaign(tmp_path, binaries, receipt, tmp_path / "out", execute=execute)
    saved = json.loads((tmp_path / "out/report.json").read_text())
    assert saved == result
    if failure_kind is None:
        assert result["campaign_passed"]
        assert result["completed_observations"] == 146 and result["completed_proof_cases"] == 132
        assert all("--control" in command for command in calls[:12])
        assert all("--heap-limit" in command for command in calls[12:14])
        assert all("--control" not in command and "--heap-limit" not in command for command in calls[14:])
        assert not result["complete_workspace_certificate"] and not result["complete_allocation_correspondence"]
    else:
        assert not result["campaign_passed"]
        assert result["proof_cases_started"] == (failure_kind == "proof")
        assert result["completed_proof_cases"] == 0
        if failure_kind == "source-drift":
            assert str(binaries["portable"]) in result["input_changes"]
    assert not (tmp_path / "out/report.tmp").exists()


def test_cli_resolves_paths_omits_raw_streams_and_uses_campaign_status(tmp_path, capsys):
    arguments = ["trace"]
    for name in ("portable", "accel", "build-receipt", "output-dir"):
        arguments += ["--" + name, str(tmp_path / name)]
    for success in (False, True):
        value = {"campaign_passed": success, "profile_qualified": False, "observations": ["large"], "guarded_inputs": {"large": "hash"}}
        with patch.object(sys, "argv", arguments), patch.object(runner, "campaign", return_value=value) as campaign:
            assert runner.main() == (0 if success else 1)
        output = json.loads(capsys.readouterr().out)
        assert output == {"campaign_passed": success, "profile_qualified": False}
        assert campaign.call_args.args[1] == {mode: (tmp_path / mode).resolve() for mode in ("portable", "accel")}
