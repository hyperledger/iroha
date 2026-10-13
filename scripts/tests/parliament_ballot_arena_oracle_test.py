"""Finite actual-Arena parity rejects changed offsets and crashed processes."""
import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_parliament_ballot_arena_oracle as check


def test_observed_model_and_comparison_require_exact_offsets():
    trace = {"events": [{"op": "alloc", "id": "x", "size": 3, "align": 8}, {"op": "free", "id": "x"}]}
    expected = check.model_result(trace)
    report = {**expected["report"], "allocator_trace_passed": True}
    assert check.compare(expected, 0, json.dumps(report))["agreement"]
    report["allocation_offsets"][0]["offset"] = 64
    fresh = check.model_result(trace)
    with pytest.raises(ValueError, match="allocation_offsets"):
        check.compare(fresh, 0, json.dumps(report))
    with pytest.raises(ValueError, match="exit"):
        check.compare(fresh, 1, "")


def test_rejection_requires_ordinary_nonzero_exit():
    expected = check.model_result({"events": [{"op": "free", "id": "missing"}]})
    assert not expected["accepted"]
    assert check.compare(expected, 1, "", 'Error: "unknown or freed ID: missing"\n', "unknown or freed ID: missing")["agreement"]
    for code in (0, -9, -11, 73):
        with pytest.raises(ValueError):
            check.compare(expected, code, "")


def test_generated_cases_include_all_kinds_and_reproducible_randomness():
    cases = check.cases()
    assert len(cases) == 88
    assert len({c["name"] for c in cases}) == len(cases)
    results = [check.model_result(c["trace"]) for c in cases]
    assert sum(r["accepted"] for r in results) == 82
    assert check.random_trace(3) == check.random_trace(3)
    assert check.random_trace(3) != check.random_trace(4)


def test_run_records_exact_inputs_and_checks_binary(tmp_path):
    oracle = tmp_path / "oracle"
    oracle.write_text("placeholder")
    case = {"name": "empty", "trace": {"events": []}}
    report = {**check.model_result(case["trace"])["report"], "allocator_trace_passed": True}
    from subprocess import CompletedProcess
    process = CompletedProcess([], 0, stdout=json.dumps(report), stderr="")
    with patch.object(check, "cases", return_value=[case]), patch.object(check.subprocess, "run", return_value=process):
        result = check.run(oracle)
    assert result["cases_checked"] == 1
    assert result["finite_allocator_parity_passed"]
    assert not result["verifier_allocation_trace_measured"]
    assert not result["profile_qualified"]


def test_main_failure_replaces_old_result(tmp_path):
    output = tmp_path / "result.json"
    output.write_text('{"finite_allocator_parity_passed": true}')
    with patch.object(check, "run", side_effect=ValueError("source drift")):
        with patch.object(sys, "argv", ["check", "--oracle", "missing", "--output", str(output)]):
            assert check.main() == 1
    assert json.loads(output.read_text())["finite_allocator_parity_passed"] is False
    with patch.object(check, "run", return_value={"profile_qualified": False}):
        with patch.object(sys, "argv", ["check", "--oracle", "missing", "--output", str(output)]):
            assert check.main() == 0


def test_wrong_json_type_and_failure_category_overwrite_stale_output(tmp_path):
    from subprocess import CompletedProcess
    oracle = tmp_path / "oracle"
    oracle.write_text("placeholder")
    output = tmp_path / "result.json"
    for stdout in ("[]", "null", '"text"'):
        output.write_text('{"finite_allocator_parity_passed": true}')
        process = CompletedProcess([], 0, stdout=stdout, stderr="")
        with patch.object(check, "cases", return_value=[{"name": "empty", "trace": {"events": []}}]):
            with patch.object(check.subprocess, "run", return_value=process):
                with patch.object(sys, "argv", ["check", "--oracle", str(oracle), "--output", str(output)]):
                    assert check.main() == 1
        assert json.loads(output.read_text())["finite_allocator_parity_passed"] is False
    expected = {"accepted": False}
    for stdout, stderr in (("", "No such file"), ('{"allocator_trace_passed": true}', ""), ("", "")):
        with pytest.raises(ValueError, match="diagnostic"):
            check.compare(expected, 1, stdout, stderr, "arena admission failed: x")


def test_workspace_qualification_and_checker_drift_are_rejected(tmp_path):
    from subprocess import CompletedProcess
    expected = check.model_result({"events": []})
    report = {**expected["report"], "allocator_trace_passed": True, "complete_workspace_certificate": True}
    with pytest.raises(ValueError, match="scope"):
        check.compare(expected, 0, json.dumps(report))
    report["complete_workspace_certificate"] = False
    oracle = tmp_path / "oracle"
    oracle.write_text("placeholder")
    checker = tmp_path / "checker.py"
    checker.write_text("initial")
    def drift(*args, **kwargs):
        checker.write_text("changed")
        return CompletedProcess([], 0, stdout=json.dumps(report), stderr="")
    with patch.object(check, "cases", return_value=[{"name": "empty", "trace": {"events": []}}]):
        with patch.object(check, "__file__", str(checker)), patch.object(check.subprocess, "run", side_effect=drift):
            with pytest.raises(ValueError, match="changed"):
                check.run(oracle)
