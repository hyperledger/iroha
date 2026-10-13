"""Fixture, worker-failure, accounting and durable-publication regressions."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check_parliament_ballot_resource_contract.py"
SPEC = importlib.util.spec_from_file_location("resource_contract_campaign", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def observation(case):
    """Supply a complete synthetic worker receipt for supervisor unit tests."""
    charge = case["expected_charge"]
    return {"outcome": case["expected_outcome"], "charged_units": charge,
            "charged_bytes": len(case["input"]) if charge else 0,
            "heap_reserved_bytes": 32 * 1024 * 1024, "metadata_reserved_bytes": 1024 * 1024,
            "stack_usable_bytes": 8 * 1024 * 1024, "guard_bytes": 2 * os.sysconf("SC_PAGESIZE"),
            "control_reserved_bytes": 65536,
            "workspace_reserved_bytes": 41 * 1024 * 1024 + 65536 + 2 * os.sysconf("SC_PAGESIZE"),
            "heap_limit_bytes": 32 * 1024 * 1024, "arena_enforced": True,
            "arena_peak_requested_bytes": 123, "arena_peak_block_bytes": 128,
            "arena_live_exit_requested_bytes": 0, "arena_live_exit_block_bytes": 0,
            "arena_allocations": 0 if case["expected_exit"] == 2 else 10,
            "complete_workspace_certificate": False, "profile_qualified": False,
            "verifier_stage": "proof" if case["case"] == "late_invalid_coefficient" else "complete"}


def test_fixture_records_match_all_eight_independent_digests():
    records = [MODULE.fixture_record(MODULE.ROOT, row, seats)
               for row in ("candidate", "comparator") for seats in (0, 3, 500, 1000)]
    assert [len(record[2]) for record in records] == [160728, 233980, 297596, 361596,
                                                       110078, 159042, 222658, 286658]
    assert len({MODULE.digest(record[2]) for record in records}) == 8
    assert MODULE.digest(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_fixture_reader_and_framing_reject_ambiguous_fields(tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_text("# fixture\na = 0102\n\n")
    assert MODULE.fields(path) == {"a": b"\1\2"}
    path.write_text("a = 01\na = 02\n")
    with pytest.raises(ValueError, match="duplicate"):
        MODULE.fields(path)
    assert MODULE.frame(b"T", [b"AB", b""]) == b"\1\0T\2\0\2\0\0\0AB\0\0\0\0"


def test_case_inputs_retain_charge_on_malformed_and_resource_failure():
    cases = list(MODULE.cases(MODULE.ROOT))
    assert len(cases) == 60
    assert sum(case["case"] == "valid" for case in cases) == 8
    by_name = {(case["fixture"], case["case"]): case for case in cases}
    for case in cases:
        MODULE.validate_observation(case, case["expected_exit"], observation(case))
        if case["case"] == "late_invalid_coefficient":
            valid = by_name[case["fixture"], "valid"]["input"]
            assert len(valid) == len(case["input"])
            assert sum(a != b for a, b in zip(valid, case["input"])) == 1
        if case["expected_outcome"] in ("rejected", "resource_exhausted"):
            assert case["expected_charge"] == 1
    assert len(cases[-1]["input"]) == MODULE.MAX_INPUT_BYTES + 1
    assert cases[-1]["expected_charge"] == 0
    assert by_name["reg_fast", "long_path_work_short"]["long_path"] is True
    assert by_name[None, "fifo_input"]["fifo"] is True


@pytest.mark.parametrize("change,reason", [
    ({"charged_units": 0}, "debit"),
    ({"charged_bytes": 0}, "debit"),
    ({"profile_qualified": True}, "qualification"),
    ({"complete_workspace_certificate": True}, "qualification"),
    ({"workspace_reserved_bytes": MODULE.WORKSPACE_LIMIT + 1}, "mapping"),
    ({"stack_usable_bytes": -1}, "mapping"),
    ({"arena_peak_block_bytes": 33 * 1024 * 1024}, "quota"),
    ({"arena_live_exit_requested_bytes": 1}, "survived"),
    ({"arena_enforced": False}, "enforced"),
])
def test_receipts_cannot_turn_bad_accounting_into_a_pass(change, reason):
    case = next(MODULE.cases(MODULE.ROOT))
    with pytest.raises(ValueError, match=reason):
        MODULE.validate_observation(case, 0, {**observation(case), **change})


def test_signal_is_not_misclassified_as_oom_or_invalid_proof():
    case = next(case for case in MODULE.cases(MODULE.ROOT) if case["case"] == "arena_exhaustion")
    with pytest.raises(ValueError, match="signals"):
        MODULE.validate_observation(case, -6, observation(case))


def test_feature_mode_and_late_verification_cannot_be_misreported():
    case = next(case for case in MODULE.cases(MODULE.ROOT) if case["case"] == "late_invalid_coefficient")
    with pytest.raises(ValueError, match="feature mode"):
        MODULE.validate_observation(case, 1, {**observation(case), "accelerated": False}, "accel")
    with pytest.raises(ValueError, match="proof verification"):
        MODULE.validate_observation(case, 1, {**observation(case), "verifier_stage": "codec"})


def test_admission_refusal_never_allocates_verifier_workspace():
    case = next(case for case in MODULE.cases(MODULE.ROOT) if case["case"] == "work_short")
    with pytest.raises(ValueError, match="allocated"):
        MODULE.validate_observation(case, 2, {**observation(case), "arena_allocations": 1})


def configure_campaign(monkeypatch, tmp_path):
    """Keep orchestration tests small while retaining the real publication path."""
    case = next(MODULE.cases(MODULE.ROOT))
    monkeypatch.setattr(MODULE, "cases", lambda _: iter([case]))
    source = tmp_path / "source"
    source.write_text("before")
    monkeypatch.setattr(MODULE, "source_inventory", lambda _: {"source": MODULE.digest(source.read_bytes())})
    binaries = {mode: tmp_path / mode for mode in ("portable", "accel")}
    for binary in binaries.values():
        binary.write_text("test binary")
    receipt = tmp_path / "build.json"
    receipt.write_text(json.dumps({"build_passed": True, "failure": None, "source_changes": {},
        "started_source_sha256": {"source": MODULE.digest(source.read_bytes())},
        "binaries": {mode: {"sha256": MODULE.digest(binary.read_bytes())} for mode, binary in binaries.items()}}))

    def execute(command, **_):
        value = {**observation(case), "accelerated": Path(command[0]).name == "accel"}
        return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

    return case, source, binaries, receipt, execute


def test_completed_records_survive_source_drift(monkeypatch, tmp_path):
    _, source, binaries, receipt, execute = configure_campaign(monkeypatch, tmp_path)

    def drift(command, **kwargs):
        source.write_text("after")
        return execute(command, **kwargs)

    report = MODULE.campaign(tmp_path, binaries, tmp_path / "out", receipt, execute=drift)
    assert report["status"] == "diagnostic_failed"
    assert report["observations"] == 2
    assert report["source_changes"]["source"]["before"] != report["source_changes"]["source"]["after"]
    assert len((tmp_path / "out/cases.jsonl").read_text().splitlines()) == 2
    assert json.loads((tmp_path / "out/report.json").read_text()) == report
    assert report["profile_qualified"] is False


def test_worker_failure_is_retained_before_stopping(monkeypatch, tmp_path):
    _, _, binaries, receipt, _ = configure_campaign(monkeypatch, tmp_path)

    def crash(command, **_):
        return subprocess.CompletedProcess(command, -6, "", "crashed")

    report = MODULE.campaign(tmp_path, binaries, tmp_path / "out", receipt, execute=crash)
    assert report["status"] == "diagnostic_failed"
    assert report["observations"] == 1
    record = json.loads((tmp_path / "out/cases.jsonl").read_text())
    assert record["exit"] == -6
    assert record["check_passed"] is False
    assert report["feature_mode_pairs"] == 0


def test_success_stays_unqualified_and_existing_output_cannot_be_overwritten(monkeypatch, tmp_path):
    _, _, binaries, receipt, execute = configure_campaign(monkeypatch, tmp_path)
    output = tmp_path / "out"
    report = MODULE.campaign(tmp_path, binaries, output, receipt, execute=execute)
    assert report["status"] == "diagnostic_complete"
    assert report["reservation_campaign_passed"] is True
    assert report["physical_cost_calibrated"] is False
    assert report["complete_workspace_certificate"] is False
    with pytest.raises(FileExistsError):
        MODULE.campaign(tmp_path, binaries, output, receipt, execute=execute)


@pytest.mark.parametrize("stdout", ["null", "[]", "42"])
def test_nonobject_worker_json_is_retained_as_failure(monkeypatch, tmp_path, stdout):
    _, _, binaries, receipt, _ = configure_campaign(monkeypatch, tmp_path)
    def execute(command, **_):
        return subprocess.CompletedProcess(command, 0, stdout, "")
    report = MODULE.campaign(tmp_path, binaries, tmp_path / "out", receipt, execute=execute)
    assert report["status"] == "diagnostic_failed"
    assert report["observations"] == 1 and report["feature_mode_pairs"] == 0
    assert "JSON must be an object" in report["failure"]


@pytest.mark.parametrize("phase", ["inventory", "fixtures", "interrupt", "timeout"])
def test_setup_generation_and_interruption_failures_publish_receipts(monkeypatch, tmp_path, phase):
    _, _, binaries, receipt, execute = configure_campaign(monkeypatch, tmp_path)
    def fail(*_, **__):
        if phase == "interrupt":
            raise KeyboardInterrupt()
        if phase == "timeout":
            raise subprocess.TimeoutExpired("worker", 1, output=b"partial", stderr=b"diagnostic")
        raise KeyError("missing_input")
    if phase == "inventory":
        monkeypatch.setattr(MODULE, "source_inventory", fail)
    elif phase == "fixtures":
        monkeypatch.setattr(MODULE, "cases", fail)
    else:
        execute = fail
    output = tmp_path / "out"
    report = MODULE.campaign(tmp_path, binaries, output, receipt, execute=execute)
    assert report["status"] == "diagnostic_failed" and report["feature_mode_pairs"] == 0
    assert json.loads((output / "report.json").read_text()) == report
    assert (output / "cases.jsonl").exists()
    if phase == "timeout":
        record = json.loads((output / "cases.jsonl").read_text())
        assert record["stdout"] == "partial" and record["stderr"] == "diagnostic"


@pytest.mark.parametrize("change", ["source", "binary", "failed_build", "missing_snapshot"])
def test_campaign_rejects_unmatched_build_provenance(monkeypatch, tmp_path, change):
    _, source, binaries, receipt, execute = configure_campaign(monkeypatch, tmp_path)
    data = json.loads(receipt.read_text())
    if change == "source":
        source.write_text("different")
    elif change == "binary":
        binaries["portable"].write_text("different")
    elif change == "failed_build":
        data["build_passed"] = False
    else:
        data["started_source_sha256"] = {}
    receipt.write_text(json.dumps(data))
    report = MODULE.campaign(tmp_path, binaries, tmp_path / "out", receipt, execute=execute)
    assert report["status"] == "diagnostic_failed" and report["observations"] == 0
    assert report["build_snapshot_matched"] is False


def test_fixed_partition_cannot_be_replaced_with_smaller_control_area():
    case = next(MODULE.cases(MODULE.ROOT))
    value = observation(case)
    value["control_reserved_bytes"] = 4096
    value["workspace_reserved_bytes"] -= 65536 - 4096
    with pytest.raises(ValueError, match="fixed partition"):
        MODULE.validate_observation(case, 0, value)


def test_build_receipt_cannot_omit_a_changed_compiled_source():
    receipt = {"build_passed": True, "failure": None, "source_changes": {},
               "started_source_sha256": {"first.rs": "matching"},
               "binaries": {"portable": {"sha256": "binary"}}}
    sources = {"first.rs": "matching", "omitted.rs": "changed"}
    with pytest.raises(ValueError, match="complete reviewed source scope"):
        MODULE.validate_build_provenance(receipt, sources, {"portable": "binary"})
    receipt["started_source_sha256"]["omitted.rs"] = "changed"
    MODULE.validate_build_provenance(receipt, sources, {"portable": "binary"})


def test_fixture_and_supervisor_inputs_are_outside_compiled_scope_only():
    receipt = {"build_passed": True, "failure": None, "source_changes": {},
               "started_source_sha256": {"code.rs": "matching"},
               "binaries": {"portable": {"sha256": "binary"}}}
    sources = {"code.rs": "matching", (MODULE.FIXTURES / "vector.proof").as_posix(): "observed",
               "scripts/check_parliament_ballot_resource_contract.py": "observed",
               "scripts/tests/parliament_ballot_resource_contract_test.py": "observed",
               "specs/parliament_ballot_resource_contract.md": "observed"}
    MODULE.validate_build_provenance(receipt, sources, {"portable": "binary"})
    receipt["started_source_sha256"]["untracked.rs"] = "extra"
    with pytest.raises(ValueError, match="complete reviewed source scope"):
        MODULE.validate_build_provenance(receipt, sources, {"portable": "binary"})


def test_empty_campaign_never_passes(monkeypatch, tmp_path):
    _, _, binaries, receipt, execute = configure_campaign(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "cases", lambda _: iter([]))
    report = MODULE.campaign(tmp_path, binaries, tmp_path / "out", receipt, execute=execute)
    assert report["status"] == "diagnostic_failed"
    assert report["observations"] == 0 and report["feature_mode_pairs"] == 0


def test_source_inventory_covers_native_worker_and_protocol_dependencies():
    inventory = MODULE.source_inventory(MODULE.ROOT)
    for name in ["Cargo.lock", "crates/iroha_parliament_ballot_proof/Cargo.toml",
                 "crates/norito/src/lib.rs", "scripts/check_parliament_ballot_resource_contract.py",
                 "crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs",
                 "specs/parliament_ballot_resource_contract.md"]:
        assert name in inventory
        assert len(inventory[name]) == 64


def test_cli_requires_explicit_binaries_and_output():
    result = subprocess.run(["python3.11", str(SCRIPT), "--help"], text=True, capture_output=True)
    assert result.returncode == 0
    assert "--portable" in result.stdout and "--accel" in result.stdout and "--output-dir" in result.stdout
