"""Keep the strict Sumeragi mutation table tied to real hooks and named tests."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sumeragi_mutation_gate_under_test", ROOT / "scripts" / "sumeragi_mutation_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def selected_cargo_results(monkeypatch, code, output, names=("tests::named",), seconds=1.0):
    """Supply a completed executable inventory and a separate runtime response."""
    def cargo_test(*args):
        if "--list" in args[3]:
            listing = "".join(name + ": test\n" for name in names)
            return 0, listing + f"\n{len(names)} tests, 0 benchmarks\n", 0.0
        return code, output, seconds
    monkeypatch.setattr(gate, "cargo_test", cargo_test)


def test_duplicate_mutation_id_cannot_select_a_different_kill_test():
    original = gate.MUTATIONS[0]
    duplicate = gate.m(original.id, "another rule", ["unrelated_test"])
    with pytest.raises(ValueError, match=f"duplicate mutation id {original.id}"):
        gate.index_mutations([original, duplicate])
    assert gate.index_mutations([original]) == {original.id: original}


def test_every_registered_mutation_has_a_current_source_switch_and_named_test():
    sources = "\n".join(path.read_text() for path in gate.CRATE_SRC.rglob("*.rs"))
    switches = set(re.findall(r'sumeragi_mutation\s*=\s*"([^"]+)"', sources))
    functions = set(re.findall(r"\bfn\s+(\w+)\s*\(", sources))
    registered = [mutation.id for mutation in gate.MUTATIONS]
    assert len(registered) == len(set(registered)), "duplicate mutation id hides a gate entry"
    assert set(registered) <= switches, "retired hooks must not masquerade as active mutations"
    for mutation in gate.MUTATIONS:
        assert mutation.tests, f"{mutation.id} has no named deterministic kill test"
        for test in mutation.tests:
            assert test.rsplit("::", 1)[-1] in functions, (mutation.id, test)


def test_actual_availability_boundaries_have_separate_strict_kill_tests():
    expected = {
        "MS20": "acquisition_rejects_corrupt_actual_row_before_counting_custody",
        "MS20b": "source_bound_storage_job_never_confuses_refusal_with_absence_or_rebinds_source",
        "MS20c": "signed_inconsistent_codeword_and_payload_commitments_are_rejected",
        "MS20d": "signed_inconsistent_codeword_and_payload_commitments_are_rejected",
        "MS20e": "stored_body_restoration_checks_actual_codeword_without_resigning_or_copying_payload",
        "MS35": "det_s35_relay_tamper_no_evidence",
    }
    for mutation, test in expected.items():
        assert test in gate.BY_ID[mutation].tests
        assert gate.has_switch(mutation)


@pytest.mark.parametrize("baseline,expected", [("pass", 0), ("fail", 1), ("error", 1)])
def test_baseline_failure_cannot_pass_when_every_mutant_is_killed(
    monkeypatch, tmp_path, baseline, expected
):
    monkeypatch.setattr(
        sys, "argv",
        ["sumeragi_mutation_gate.py", "--only", "MX1", "--strict", "--fast",
         "--target-dir", str(tmp_path)],
    )
    monkeypatch.setattr(
        gate, "evaluate_baseline",
        lambda *_: {"id": "baseline", "verdict": baseline},
    )
    monkeypatch.setattr(
        gate, "evaluate",
        lambda *_: {"id": "MX1", "verdict": "killed_by_test"},
    )
    assert gate.main() == expected


@pytest.mark.parametrize(
    "code,output,expected",
    [
        (-9, "", "execution-error"),
        (-9, "test tests::named ... FAILED\n", "execution-error"),
        (101, "test tests::named ... ok\nerror: test process crashed", "execution-error"),
        (101, "test tests::named ... FAILED\nerror: test process crashed", "execution-error"),
        (0, "test tests::named ... ignored\n", "missing-test"),
        (101, "test tests::other ... FAILED\n", "missing-test"),
        (0, "running 1 test\ntest tests::named ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n", "pass"),
        (101, "running 1 test\ntest tests::named ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n", "fail"),
        (None, "test tests::named ... ", "timeout"),
    ],
)
def test_only_executed_named_test_results_establish_a_mutation_kill(
    monkeypatch, tmp_path, code, output, expected
):
    selected_cargo_results(monkeypatch, code, output)
    step = gate.run_step(
        SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
        tmp_path / "named.log",
    )
    assert step.status == expected


@pytest.mark.parametrize("status", ["execution-error", "missing-test", "timeout"])
def test_failed_test_execution_cannot_be_reported_as_a_named_kill(
    monkeypatch, tmp_path, status
):
    mutation = gate.BY_ID["MS1"]
    monkeypatch.setattr(gate, "has_switch", lambda _: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args: gate.Step(status=status))
    args = SimpleNamespace(target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, mutation)
    assert result["verdict"] == "error"


def test_missing_second_filter_is_an_error_even_if_first_named_test_fails(monkeypatch, tmp_path):
    selected_cargo_results(monkeypatch, 101, "test tests::present ... FAILED\n",
                           names=("tests::present", "tests::missing"))
    step = gate.run_step(
        SimpleNamespace(), tmp_path, "MS1", ["present", "missing"], None, 5,
        tmp_path / "named.log",
    )
    assert step.status == "missing-test"
    assert step.failed == ["tests::present"]


@pytest.mark.parametrize("terminals,summary", [
    ("test tests::named ... FAILED\n", "0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"),
    ("test tests::named ... FAILED\ntest tests::named ... FAILED\n", "0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out;"),
    ("test tests::named ... FAILED\ntest tests::named_extra ... ok\n", "0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out;"),
    ("test tests::named ... FAILED\ntest tests::named_extra ... ignored, deferred control\n", "0 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out;"),
    ("test tests::named ... FAILED\ntest tests::unexpected ... ok\n", "1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"),
])
def test_substring_selection_cannot_hide_missing_duplicate_ignored_or_wrong_results(
    monkeypatch, tmp_path, terminals, summary
):
    selected_cargo_results(monkeypatch, 101, terminals + "test result: FAILED. " + summary + "\n",
                           names=("tests::named", "tests::named_extra"))
    step = gate.run_step(SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "execution-error"
    assert step.selected == ["tests::named", "tests::named_extra"]


@pytest.mark.parametrize("code,verdict,passed,failed", [(0, "ok", 2, 0), (101, "FAILED", 1, 1)])
def test_every_actual_substring_match_is_accounted_before_passing_or_killing(
    monkeypatch, tmp_path, code, verdict, passed, failed
):
    output = (f"running 2 tests\ntest tests::named ... {verdict}\ntest tests::named_extra ... ok\n"
              f"test result: {verdict}. {passed} passed; {failed} failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n")
    selected_cargo_results(monkeypatch, code, output,
                           names=("tests::named", "tests::named_extra"))
    step = gate.run_step(SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == ("fail" if failed else "pass")
    assert step.ran == step.selected


@pytest.mark.parametrize("listing", [
    "tests::named: test\n",  # Incomplete discovery.
    "tests::named: test\n\n2 tests, 0 benchmarks\n",  # Missing name.
    "tests::named: test\ntests::named: test\n\n2 tests, 0 benchmarks\n",  # Duplicate.
])
def test_incomplete_executable_discovery_cannot_run_or_kill_a_mutant(monkeypatch, tmp_path, listing):
    def cargo_test(*args):
        assert "--list" in args[3], "invalid discovery must stop before execution"
        return 0, listing, 0.0
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "execution-error"


def test_discovery_and_execution_share_the_original_step_deadline(monkeypatch, tmp_path):
    moments = iter((100.0, 101.0, 102.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    calls = []
    def cargo_test(*args):
        calls.append((args[3], args[5]))
        if "--list" in args[3]:
            return 0, "tests::named: test\n\n1 test, 0 benchmarks\n", 1.0
        return 0, ("running 1 test\ntest tests::named ... ok\ntest result: ok. 1 passed; 0 failed; "
                   "0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"), 1.0
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, None, ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "pass"
    assert [timeout for _, timeout in calls] == [5, 4]
    assert "--test-threads=1" in calls[1][0]


def test_discovery_timeout_never_replenishes_or_disables_the_execution_deadline(monkeypatch, tmp_path):
    def cargo_test(*args):
        assert "--list" in args[3], "the exhausted deadline cannot launch a test"
        return 0, "tests::named: test\n\n1 test, 0 benchmarks\n", 5.0
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, None, ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "timeout"


@pytest.mark.parametrize("timeout,expected", [(0, None), (20, 20)])
def test_explicit_unbounded_wait_never_installs_a_process_deadline(
    monkeypatch, tmp_path, timeout, expected
):
    deadlines = []

    class Process:
        returncode = 0

        def communicate(self, *, timeout):
            deadlines.append(timeout)
            return "test tests::named ... ok\n", None

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: Process())
    code, output, _ = gate.cargo_test(
        SimpleNamespace(), tmp_path, "MS1", ["named"], None, timeout,
        tmp_path / "named.log",
    )
    assert deadlines == [expected]
    assert code == 0
    assert "tests::named ... ok" in output


@pytest.mark.parametrize("option", ["--timeout-build", "--timeout-test", "--timeout-scenario"])
def test_negative_timeouts_are_rejected_before_running_commands(monkeypatch, option):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", option, "-1", "--list"])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2


def test_scenario_timeout_is_an_execution_error_even_when_named_test_was_killed(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "has_switch", lambda _: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    outcomes = iter([
        gate.Step(status="fail", failed=[gate.BY_ID["MS1"].tests[0]]),
        gate.Step(status="timeout"),
    ])
    monkeypatch.setattr(gate, "run_step", lambda *args: next(outcomes))
    args = SimpleNamespace(
        target_dir=tmp_path, timeout_test=5, timeout_scenario=5, seeds=1, fast=False,
    )
    result = gate.evaluate(args, tmp_path, gate.BY_ID["MS1"])
    assert result["verdict"] == "error"
    assert result["reason"] == "scenarios: timeout"


@pytest.mark.parametrize("core", [False, True])
def test_package_mutation_environment_is_confined_to_its_actual_owner(monkeypatch, tmp_path, core):
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, timeout):
            captured["timeout"] = timeout
            return "test result: ok. 1 passed; 0 failed;", None
    def popen(command, **options):
        captured["command"] = command
        captured["env"] = options["env"]
        return Process()
    monkeypatch.setenv("SUMERAGI_MUTATION", "foreign-protocol-hook")
    monkeypatch.setenv("SUMERAGI_CORE_MUTATION", "foreign-core-hook")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=core)
    mutation = "HC1" if core else "MS1"
    code, _, _ = gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0, tmp_path / "log")
    crate, features, environment = gate.package_options(args)
    assert code == 0
    profile_options = ["--profile", "test"] if core else ["--release"]
    assert captured["command"] == ["cargo", "test", "--locked", "-p", crate,
                                   *profile_options, "--features", features, "--lib", "--", "named"]
    assert captured["env"][environment] == mutation
    foreign = "SUMERAGI_MUTATION" if core else "SUMERAGI_CORE_MUTATION"
    assert foreign not in captured["env"]
    assert captured["timeout"] is None


def test_core_table_is_separate_from_protocol_scenario_hooks(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--core", "--list"])
    assert gate.main() == 0
    listing = capsys.readouterr().out
    assert "HC1" in listing
    assert "MS1" not in listing
    assert "f01" not in listing


@pytest.mark.parametrize("arguments", [["--core", "--only", "MS1"], ["--only", "HC1"]])
def test_mutation_ids_cannot_select_a_different_implementation_owner(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2


def test_registered_core_rules_have_real_hooks_and_named_core_regressions():
    source = gate.REPO / "crates" / "iroha_core" / "src"
    text = "\n".join(path.read_text() for path in source.rglob("*.rs"))
    functions = set(re.findall(r"\bfn\s+(\w+)\s*\(", text))
    functions.update(re.findall(r"\bstate_test!\s*\{\s*(?:sync|result|large_stack|consensus_stack)\s+(\w+)\b", text))
    ids = [mutation.id for mutation in gate.CORE_MUTATIONS]
    assert len(ids) == len(set(ids))
    for mutation in gate.CORE_MUTATIONS:
        assert gate.has_switch(mutation.id, core=True)
        assert not gate.has_switch(mutation.id)
        assert mutation.tests and not mutation.scenarios
        assert all(name.rsplit("::", 1)[-1] in functions for name in mutation.tests)


def test_mutation_ids_select_one_rule_across_all_implementation_owners():
    mutations = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS]
    assert len(gate.index_mutations(mutations)) == len(mutations)
    core_and_daemon = gate.index_mutations([*gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS])
    rows = re.findall(
        r"^\| (HC\d+|SC4) \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE
    )
    identifiers = [identifier for identifier, _ in rows]
    assert len(identifiers) == len(set(identifiers))
    assert set(identifiers) == set(core_and_daemon)
    for identifier, row in rows:
        for name in core_and_daemon[identifier].tests:
            assert name.rsplit("::", 1)[-1] in row, (identifier, name)


def test_core_custody_mutations_have_distinct_source_owners():
    expected = {
        "HC120": {"sumeragi/evidence_history.rs"},
        "HC121": {"state/output_capacity.rs"},
        "HC122": {"sumeragi/lanes/registry.rs"},
        "HC123": {"sumeragi/lanes/store.rs"},
        "HC124": {"sumeragi/lanes/registry.rs"},
        "HC125": {"sumeragi/lanes/registry.rs"},
        "HC126": {"sumeragi/crypto.rs"},
        "HC127": {"snapshot.rs"},
        "HC147": {"query/native_receipts/amx_read.rs"},
        "HC148": {"query/native_receipts/amx_read.rs"},
        "HC149": {"sumeragi/amx/native.rs"},
    }
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    source = gate.REPO / "crates/iroha_core/src"
    owners = {identifier: set() for identifier in expected}
    for path in source.rglob("*.rs"):
        for identifier in re.findall(r'sumeragi_core_mutation\s*=\s*"([^"]+)"', path.read_text()):
            if identifier in owners:
                owners[identifier].add(path.relative_to(source).as_posix())
    assert owners == expected
    for identifier in expected:
        assert registered[identifier].tests
        assert not registered[identifier].scenarios
        assert not gate.has_switch(identifier)
        assert not gate.has_switch(identifier, daemon=True)


@pytest.mark.parametrize("test_build,mutation_feature,accepted", [
    (False, False, True), (True, False, True),
    (True, True, True), (False, True, False),
])
def test_core_guard_rejects_mutation_feature_in_non_test_builds(
    tmp_path, test_build, mutation_feature, accepted
):
    guard = ROOT / "crates/iroha_core/src/mutation_guard.rs"
    assert "mod mutation_guard;" in (guard.parent / "lib.rs").read_text()
    command = ["rustc", "--edition=2024", "--crate-type=lib", "--emit=metadata",
               str(guard), "-o", str(tmp_path / "guard.rmeta")]
    if test_build:
        command += ["--cfg", "test"]
    if mutation_feature:
        command += ["--cfg", 'feature="mutation-testing"']
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    if not accepted:
        assert "mutation-testing is test-only" in result.stderr


@pytest.mark.parametrize("status", ["execution-error", "missing-test", "timeout"])
def test_core_gate_preserves_strict_failed_execution_classification(monkeypatch, tmp_path, status):
    monkeypatch.setattr(gate, "has_switch", lambda _, *, core: core)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args: gate.Step(status=status))
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=0, fast=True)
    result = gate.evaluate(args, tmp_path, gate.CORE_MUTATIONS[0])
    assert result["verdict"] == "error"
    assert result["reason"] == f"named tests: {status}"


@pytest.fixture(scope="module")
def core_build_script(tmp_path_factory):
    executable = tmp_path_factory.mktemp("core-mutation-build") / "build-script"
    result = subprocess.run(
        ["rustc", "--edition=2024", str(ROOT / "crates/iroha_core/build.rs"),
         "-o", str(executable)], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return executable


@pytest.mark.parametrize("feature,mutation,flags,accepted,emitted", [
    (False, "HC1", "", True, False),
    (False, None, '--cfg\x1fsumeragi_core_mutation="HC1"', False, False),
    (True, "HC1", "", True, True),
    (True, None, "", True, False),
    (True, "unknown_rule", "", False, False),
    (True, 'HC1"', "", False, False),
])
def test_core_build_script_never_treats_environment_as_a_production_fault_switch(
    core_build_script, feature, mutation, flags, accepted, emitted
):
    environment = dict(os.environ)
    for key in ("CARGO_FEATURE_MUTATION_TESTING", "SUMERAGI_CORE_MUTATION"):
        environment.pop(key, None)
    environment["SUMERAGI_MUTATION"] = "foreign-protocol-rule"
    environment["CARGO_ENCODED_RUSTFLAGS"] = flags
    if feature:
        environment["CARGO_FEATURE_MUTATION_TESTING"] = "1"
    if mutation is not None:
        environment["SUMERAGI_CORE_MUTATION"] = mutation
    result = subprocess.run(
        [str(core_build_script)], cwd=ROOT / "crates/iroha_core", env=environment,
        capture_output=True, text=True, check=False,
    )
    assert (result.returncode == 0) == accepted, result.stderr
    assert ('cargo:rustc-cfg=sumeragi_core_mutation="HC1"' in result.stdout) == emitted
    assert "cargo:rustc-cfg=sumeragi_mutation=" not in result.stdout
    if not feature and mutation:
        assert "ignored" in result.stdout


@pytest.mark.parametrize("arguments", [
    ["--core-profile", "test"], ["--core", "--core-profile", "dev"],
    ["--core", "--core-profile", "bogus"], ["--core", "--core-profile", ""],
])
def test_core_profile_rejects_invalid_values_and_protocol_overrides(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments, "--list"])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2


@pytest.mark.parametrize("profile", [None, "release", "test"])
def test_core_profile_is_identical_for_baseline_and_mutant_and_recorded(monkeypatch, tmp_path, profile):
    captured = []
    class Process:
        returncode = 0
        def communicate(self, timeout):
            assert timeout is None
            return "test result: ok. 1 passed; 0 failed;", None
    def popen(command, **options):
        captured.append(command)
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=True, core_profile=profile)
    for mutation in (None, "HC1"):
        assert gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0,
                               tmp_path / f"{mutation}.log")[0] == 0
    assert captured[0] == captured[1]
    expected_profile = profile or "test"
    assert captured[0][5:7] == ["--profile", expected_profile]
    profile_option = ["--core-profile", profile] if profile else []
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--core", *profile_option,
                                     "--only", "HC1", "--strict", "--fast", "--target-dir", str(tmp_path)])
    monkeypatch.setattr(gate, "evaluate_baseline", lambda *_: {"id": "baseline", "verdict": "pass"})
    monkeypatch.setattr(gate, "evaluate", lambda *_: {"id": "HC1", "verdict": "killed_by_test"})
    assert gate.main() == 0
    import json
    assert json.loads((tmp_path / "report.json").read_text())["profile"] == expected_profile


def test_hc10_selects_only_the_original_query_scratch_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC10"]
    assert rule.tests == (
        "sumeragi::certified_chain::tests::state_certificate::"
        "state_certificate_signed_availability_scratch_uses_original_query_allowance",
        "sumeragi::certified_chain::terminal_selection::tests::terminal_amx_prefix_refuses_original_payload_scratch_without_advancing",
        "sumeragi::certified_chain::terminal_selection::tests::terminal_amx_prefix_refuses_original_rs16_scratch_without_advancing",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC10", core=True)
    assert not gate.has_switch("HC10")


def test_hc12_selects_only_the_original_beacon_complete_prepaid_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC12"]
    assert rule.tests == (
        "beacon::validation::tests::"
        "beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC12", core=True)
    assert not gate.has_switch("HC12")


def test_hc13_selects_only_the_original_query_pairing_constructor_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC13"]
    assert rule.tests == (
        "sumeragi::certified_chain::tests::state_certificate::"
        "state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC13", core=True)
    assert not gate.has_switch("HC13")


def test_hc15_selects_only_the_original_committed_quorum_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC15"]
    assert rule.tests == (
        "sumeragi::block_store::committed_read::tests::"
        "committed_read_returns_original_qc_backing_after_projection_refusal_and_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC15", core=True)
    assert not gate.has_switch("HC15")


def test_hc16_selects_only_original_lane_signer_ownership_handoffs():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC16"]
    assert rule.tests == (
        "sumeragi::lanes::custody::tests::original_signer_state_handoff_retains_backing_and_refuses_foreign_pool",
        "sumeragi::lanes::custody::tests::original_signer_world_handoff_admits_both_generations_before_replacing_either",
        "state::deserialize::native_lane_custody_tests::native_lane_signer_snapshot_retains_exact_raw_source_until_both_cuts_are_funded",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC16", core=True)
    assert not gate.has_switch("HC16")


def test_hc17_selects_only_current_tip_control_publication_binding():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC17"]
    assert rule.tests == (
        "sumeragi::epoch_beacon::producer::tests::"
        "control_requires_original_tip_and_matching_published_hash_journal",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC17", core=True)
    assert not gate.has_switch("HC17")


def test_hc19_preserves_amx_decoder_refusal_outside_instruction_results():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC19"]
    assert rule.tests == (
        "sumeragi::amx::tests::amx_anchor_decode_refusal_cannot_publish_even_when_instruction_error_is_caught",
        "sumeragi::amx::tests::amx_relay_decode_refusal_keeps_original_undecided_record_and_retries_proof",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC19", core=True)
    assert not gate.has_switch("HC19")


def test_hc18_selects_only_original_lane_sample_ownership_handoffs():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC18"]
    assert rule.tests == (
        "sumeragi::lanes::custody::tests::sample_state_admission_refuses_unfunded_source",
        "sumeragi::lanes::step::sample_owner_tests::sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix",
        "state::deserialize::native_lane_custody_tests::native_lane_sample_snapshot_retains_raw_source_through_both_cut_refusal_and_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC18", core=True)
    assert not gate.has_switch("HC18")


def test_hc20_preserves_original_stored_result_read_on_decoder_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC20"]
    assert rule.tests == (
        "sumeragi::block_store::body_read::tests::stored_result_decode_refusal_retains_original_decoded_owners_and_retries",
        "sumeragi::block_store::committed_read::tests::committed_result_decode_refusal_keeps_original_read_slot_and_retries",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC20", core=True)
    assert not gate.has_switch("HC20")


def test_hc21_selects_only_original_root_store_affinity():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC21"]
    assert rule.tests == (
        "sumeragi::node::tests::root_owner_tests::prepared_root_uses_original_state_store",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC21", core=True)
    assert not gate.has_switch("HC21")


def test_hc22_checks_every_canonical_queue_entrypoint_domain():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC22"]
    assert rule.tests == (
        "queue::tests::queue_rejects_preaccepted_foreign_external_before_custody",
        "queue::tests::queue_rejects_preaccepted_foreign_commitment_before_custody",
        "queue::tests::queue_rejects_preaccepted_foreign_reveal_before_custody",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC22", core=True)
    assert not gate.has_switch("HC22")


def test_hc24_preserves_allocation_free_original_read_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC24"]
    assert rule.tests == (
        "sumeragi::block_store::body_read::tests::stored_result_decode_refusal_retains_original_decoded_owners_and_retries",
        "sumeragi::block_store::committed_read::tests::committed_result_decode_refusal_keeps_original_read_slot_and_retries",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC24", core=True)
    assert not gate.has_switch("HC24")


def test_hc23_requires_retained_actor_before_startup_effects():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC23"]
    assert rule.tests == (
        "sumeragi::node::tests::p2p_owner_tests::network_start_rejects_closed_retained_actor_before_driver_files",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC23", core=True)
    assert not gate.has_switch("HC23")


def test_hc25_preserves_physical_certificate_decode_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC25"]
    assert rule.tests == (
        "sumeragi::block_store::body_read::tests::stored_certificate_allocator_refusal_keeps_original_read_and_retries",
        "sumeragi::block_store::committed_read::tests::committed_certificate_allocator_refusal_retains_original_slot_and_retries",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC25", core=True)
    assert not gate.has_switch("HC25")


def test_core_amx_role_gate_names_signed_genesis_and_all_coordinator_operations():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC26"]
    assert rule.tests == (
        "sumeragi::node::tests::dataspace_roots::amx_scope_tests::signed_private_genesis_cannot_install_global_amx_coordinator",
        "executor::root_scope::tests::amx_roles::every_amx_coordinator_instruction_rejects_private_execution_before_proof_decoding",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC26", core=True)
    assert not gate.has_switch("HC26")


def test_core_root_scope_refusal_gate_requires_original_signed_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC27"]
    assert rule.tests == (
        "sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_work_keeps_scope_decode_refusal_local_and_retries_original_carrier",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC27", core=True)
    assert not gate.has_switch("HC27")


def test_core_readonly_scope_gate_requires_query_and_vm_host_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC28"]
    assert rule.tests == (
        "sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_manifest_query_does_not_turn_scope_refusal_into_permanent_error",
        "sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_host_query_keeps_scope_refusal_out_of_completed_vm_errors",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC28", core=True)
    assert not gate.has_switch("HC28")


def test_hc29_keeps_original_lane_batch_refusal_local_through_read_execute_and_recovery():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC29"]
    assert rule.tests == (
        "sumeragi::lanes::tests::original_signed_batch_decode_preserves_exact_local_refusal_and_terminal_limits",
        "sumeragi::lanes::registry::tests::authenticated_registry_batch_decode_refusal_is_retryable_not_byzantine",
        "sumeragi::lanes::executor::native_decode_tests::signed_four_validator_lane_execution_refusal_never_caches_invalid_or_publishes",
        "sumeragi::lanes::executor::native_decode_tests::signed_four_validator_lane_recovery_keeps_available_phase_and_exact_original_owners",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC29", core=True)
    assert not gate.has_switch("HC29")


def test_hc31_borrows_original_lane_payload_and_checks_exact_allocation_census():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC31"]
    assert rule.tests == (
        "sumeragi::lanes::tests::signed_lane_batch_canonical_validation_preserves_original_bytes_without_new_allocations",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC31", core=True)
    assert not gate.has_switch("HC31")


def test_core_registry_refusal_gate_requires_native_fee_host_and_parliament_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC30"]
    assert rule.tests == (
        'sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_contract_lookup_does_not_turn_scope_refusal_into_vm_permission_denial',
        'sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_account_permission_read_defers_without_constructing_a_json_token',
        'validation_fee::tests::registry_refusal_tests::signed_fee_runtime_read_does_not_turn_scope_refusal_into_a_nonmatching_origin',
        'validation_fee::tests::registry_refusal_tests::original_retained_fee_registry_does_not_publish_local_decode_refusal_as_malformed',
        'smartcontracts::isi::world::isi::tests::signed_payout_scope_refusal_cannot_publish_a_parliament_terminal_outcome',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC30", core=True)
    assert not gate.has_switch("HC30")


def test_core_decode_gate_requires_credit_and_both_native_worker_original_source_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC32"]
    assert rule.tests == (
        "validation_fee_rewards::tests::original_fee_credit_alias_decode_refusal_preserves_balance_and_retries",
        "validation_fee_rewards::tests::original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries",
        "sumeragi::executor::publication_tests::context_proof_decoder_refusal_retains_original_inputs_and_retries",
        "sumeragi::executor::publication_tests::native_context_archive_decoder_refusal_retains_original_execution_and_retries",
        'smartcontracts::isi::kaigi::typed_deferral_tests::stored_record_refusal_is_sticky_and_retries_original_json_without_publication',
        'smartcontracts::isi::kaigi::typed_deferral_tests::indexed_record_refusal_preserves_unregister_guard_and_original_retry',
        'state::deserialize::kaigi_typed_deferral_tests::restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::registration_refusal_preserves_original_relay_retirement_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::feedback_refusal_preserves_both_original_relay_rows_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::checked_record_writer_refusal_keeps_original_create_unpublished_and_retries',
        'state::deserialize::kaigi_relay_typed_deferral_tests::restored_registration_refusal_retains_original_snapshot_and_retry',
        'state::deserialize::kaigi_relay_typed_deferral_tests::restored_allowlist_refusal_retains_original_snapshot_and_retry',
        'state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source',
        'state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::lineage_refusal_preserves_original_relay_retirement_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::primary_alias_refusal_preserves_original_registration_and_retry',
        'execution_attempt::tests::json_scoped_refusal_preserves_original_context_source_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::live_manifest_dependency_refusal_preserves_original_route_and_retry',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC32", core=True)
    assert not gate.has_switch("HC32")


def test_core_decode_refusal_classifier_gate_retains_global_and_inner_format_rejections():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC33"]
    assert rule.tests == (
        "execution_attempt::tests::norito_global_archive_cap_is_terminal_inside_an_outer_decode_scope",
        "execution_attempt::tests::norito_inner_format_limits_are_terminal_under_a_wider_outer_scope",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC33", core=True)
    assert not gate.has_switch("HC33")


def test_core_sns_permission_gate_requires_original_record_refusal_and_retry_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC35"]
    assert rule.tests == (
        "executor::tests::original_sns_alias_domain_permission_refusal_retries_without_a_rejection",
        "executor::tests::original_sns_domain_transfer_permission_refusal_retries_without_a_rejection",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC35", core=True)
    assert not gate.has_switch("HC35")


def test_core_claim_fee_gate_requires_original_metadata_and_alias_refusal_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC36"]
    assert rule.tests == (
        "executor::tests::original_claim_metadata_refusal_defers_fee_quote_and_retries_exact_payload",
        "executor::tests::original_claim_alias_refusal_after_metadata_defers_fee_quote_and_retries",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC36", core=True)
    assert not gate.has_switch("HC36")


def test_core_fee_selector_gate_requires_original_account_and_currency_read_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC37"]
    assert rule.tests == (
        "block::original_canonical_account_refusal_does_not_fall_through_to_alias_absence",
        "executor::tests::original_network_xor_pin_refusal_defers_quote_and_retries_same_parameter",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC37", core=True)
    assert not gate.has_switch("HC37")
def test_native_source_owner_requires_applied_transcripts_and_isolated_capacity():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC34"]
    assert rule.tests == (
        'fastpq::source_reservation::admission::tests::native_authorization_has_no_entry_until_an_applied_transcript_and_drops_atomically',
        'fastpq::source_reservation::admission::tests::native_pool_overflow_cannot_borrow_ordinary_or_governance_reservations',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC34", core=True)
    assert not gate.has_switch("HC34")




def test_core_routing_gate_requires_original_sns_custody_and_capture_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC38"]
    assert rule.tests == (
        "queue::router::tests::original_dataspace_alias_read_refusal_keeps_routing_retryable",
        "queue::router::tests::original_physical_policy_read_refusal_never_enters_captured_row",
        "executor::root_scope::tests::original_private_instruction_routing_refusal_latches_before_scope_verdict",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC38", core=True)
    assert not gate.has_switch("HC38")


def test_core_native_metadata_gate_requires_original_root_and_late_policy_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC39"]
    assert rule.tests == (
        "state::network_policy_routes::tests::original_root_scope_read_refusal_does_not_publish_invalid_native_context",
        "state::network_policy_routes::tests::original_lane_policy_read_refusal_after_root_keeps_exact_capture_retryable",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC39", core=True)
    assert not gate.has_switch("HC39")

def test_account_matchers_retain_original_sns_and_canonical_read_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC40"]
    assert rule.tests == ('queue::router::tests::account_refusal_tests::original_account_target_refusal_never_selects_the_default_route', 'queue::router::tests::account_refusal_tests::original_canonical_account_matcher_preserves_decode_refusal_and_retry', 'queue::router::tests::account_refusal_tests::original_signed_account_matcher_refusal_is_not_a_mismatch_or_panic', 'queue::router::tests::account_refusal_tests::original_native_policy_account_matcher_retains_refusal_before_route_selection')
    assert not rule.scenarios
    assert gate.has_switch("HC40", core=True)
    assert not gate.has_switch("HC40")


def test_parameter_control_scope_gate_preserves_signed_global_and_physical_authority():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC41"]
    assert rule.tests == (
        "queue::router::alias_registry_routing_tests::parameter_control_preserves_global_physical_route_before_private_account_rule",
        "queue::router::alias_registry_routing_tests::alias_registry_routing_paid_post_genesis_dataspace_domain_and_renewal",
        "queue::router::alias_registry_routing_tests::alias_registry_routing_cold_replay_with_expanded_catalog_preserves_paid_bootstrap",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC41", core=True)
    assert not gate.has_switch("HC41")

def test_auto_renew_rekey_keeps_current_owner_revision_and_capacity():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC42"]
    assert rule.tests == ('smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_current_owner_can_replace_stale_auto_renew_configuration', 'smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_same_configuration_requires_owner_replacement_cas', 'smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_disabled_clean_record_requires_exact_owner_revision')
    assert not rule.scenarios
    assert gate.has_switch("HC42", core=True)
    assert not gate.has_switch("HC42")


def test_worker_validation_and_certificate_gate_preserves_original_attempt_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC44"]
    assert rule.tests == (
        "sumeragi::executor::validation_refusal_tests::original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry",
        "sumeragi::executor::validation_refusal_tests::original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC44", core=True)
    assert not gate.has_switch("HC44")

def test_payload_local_decoder_gate_retains_original_typed_worker_reason():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC45"]
    assert rule.tests == ("sumeragi::executor::payload_refusal_tests::original_available_payload_local_decode_refusal_keeps_typed_worker_reason_and_retry",)
    assert not rule.scenarios
    assert gate.has_switch("HC45", core=True)
    assert not gate.has_switch("HC45")


def test_narrow_caller_depth_gate_requires_original_bytes_and_worker_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC46"]
    assert rule.tests == (
        "execution_attempt::tests::original_surviving_narrow_decode_depth_refusal_retries_identical_bytes",
        "sumeragi::executor::payload_refusal_tests::original_available_payload_narrow_depth_refusal_keeps_typed_worker_reason_and_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC46", core=True)
    assert not gate.has_switch("HC46")

def test_certified_history_keeps_original_result_and_successor_refusal_local():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC43"]
    assert rule.tests == ('sumeragi::certified_chain::refusal_tests::original_result_frame_refusal_is_local_and_same_bytes_retry', 'sumeragi::certified_chain::refusal_tests::original_successor_history_refusal_is_local_and_same_source_retries', 'sumeragi::certified_chain::tests::state_certificate::state_certificate_native_qc_decode_refusal_is_capacity_and_retries_original_source')
    assert not rule.scenarios
    assert gate.has_switch("HC43", core=True)
    assert not gate.has_switch("HC43")
def test_staking_payload_gate_preserves_original_preparation_and_worker_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC49"]
    assert rule.tests == (
        "sumeragi::penalties::tests::original_staking_payload_refusal_retains_evidence_pool_and_exact_assembly_retry",
        "sumeragi::executor::publication_tests::original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC49", core=True)
    assert not gate.has_switch("HC49")




def test_availability_attempts_keep_original_reader_and_retry_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC47"]
    assert rule.tests == ('sumeragi::certified_chain::refusal_tests::original_availability_history_refusal_is_pending_without_corruption', 'sumeragi::certified_chain::refusal_tests::original_availability_constructor_refusal_retries_without_installing_authority', 'sumeragi::driver::exec::refusal_tests::append_refusal_keeps_original_commit_and_release_owner_until_durable', 'sumeragi::driver::serve::tests::refused_metadata_owner_cannot_be_replaced_by_another_peer_during_backoff')
    assert not rule.scenarios
    assert gate.has_switch("HC47", core=True)
    assert not gate.has_switch("HC47")


def test_lane_history_attempts_preserve_original_producers_and_consumer_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC51"]
    assert rule.tests == ('sumeragi::runtime_availability::history::source_refusal_tests::original_archive_read_refusal_preserves_pool_release_and_same_lane_prefix', 'sumeragi::runtime_availability::history::source_refusal_tests::original_certificate_projection_refusal_preserves_pool_release_and_exact_carrier', 'sumeragi::runtime_availability::history::source_refusal_tests::original_lane_evidence_handoff_preserves_actual_decode_refusal_and_exact_cut', 'sumeragi::lanes::registry::tests::original_native_lane_authority_refusal_reaches_merge_and_original_pool_retry', 'sumeragi::evidence::tests::original_lane_history_refusal_reaches_evidence_without_recovery_or_rejection', 'sumeragi::executor::publication_tests::original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry')
    assert not rule.scenarios
    assert gate.has_switch("HC51", core=True)
    assert not gate.has_switch("HC51")


def test_incumbent_and_lifecycle_refusals_keep_original_state_attempt():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC48"]
    assert rule.tests == ('state::validator_committee::tests::refusal::original_incumbent_history_refusal_keeps_authority_and_same_source_retry', 'state::validator_committee::tests::refusal::original_credentials_authority_refusal_keeps_command_and_same_source_retry', 'state::validator_committee::tests::refusal::original_credentials_command_decode_refusal_has_no_publication_and_retries', 'state::validator_committee::tests::refusal::original_beacon_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_tle_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry')
    assert not rule.scenarios
    assert gate.has_switch("HC48", core=True)
    assert not gate.has_switch("HC48")


def test_original_npos_policy_read_refusal_keeps_connected_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC50"]
    assert rule.tests == ('state::validator_committee::tests::refusal::original_npos_parameter_refusal_does_not_become_missing_staking_policy', 'state::validator_committee::tests::refusal::original_npos_exit_policy_refusal_keeps_stake_and_same_signed_retry', 'state::validator_committee::tests::refusal::original_npos_reserve_validation_refuses_without_changing_current_or_undo', 'smartcontracts::ivm::host::return_resource_tests::original_npos_policy_refusal_preserves_host_seed_projection_and_retries', 'sumeragi::evidence::tests::original_npos_policy_refusal_cannot_prune_retained_evidence', 'state::validator_committee::tests::refusal::late_original_npos_activation_read_refusal_rolls_back_and_same_signed_retry', 'sumeragi::evidence_history::lane::tests::original_lane_observer_late_policy_refusal_retains_observation_and_retries')
    assert not rule.scenarios
    assert gate.has_switch("HC50", core=True)
    assert not gate.has_switch("HC50")


def test_original_checkpoint_decode_resource_stays_a_typed_attempt():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC52"]
    assert rule.tests == ('sumeragi::finality::tests::original_checkpoint_binary_refusal_is_local_and_retries_exact_original_source',)
    assert not rule.scenarios
    assert gate.has_switch("HC52", core=True)
    assert not gate.has_switch("HC52")


@pytest.mark.parametrize("late_verdict,late_exit", [("ok", 0), ("FAILED", 101)])
def test_deadline_waits_for_owned_cargo_without_signalling_or_counting_late_result(
    monkeypatch, tmp_path, late_verdict, late_exit
):
    late_output = (
        f"test tests::named ... {late_verdict}\n"
        + ("test result: ok. 1 passed; 0 failed;\n" if late_exit == 0
           else "test result: FAILED. 0 passed; 1 failed;\n")
    )
    calls = []
    omitted = object()

    class Process:
        pid = 123
        returncode = late_exit

        def communicate(self, *, timeout=omitted):
            calls.append(timeout)
            if timeout is not omitted:
                raise subprocess.TimeoutExpired("cargo test", timeout)
            return late_output, None

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        gate.os, "killpg",
        lambda *args: pytest.fail("a qualification deadline must not signal Cargo"),
    )
    args = SimpleNamespace(core=True, core_profile="test")
    log = tmp_path / "owned-deadline.log"
    code, output, _ = gate.cargo_test(args, tmp_path, None, ["named"], None, 7, log)
    assert calls == [7, omitted], "original deadline is retained; then wait for natural exit"
    assert code is None, "neither late success nor a late failed test satisfies its deadline"
    assert output == late_output
    assert "# exit None" in log.read_text()
    selected_cargo_results(monkeypatch, code, output, seconds=8)
    step = gate.run_step(args, tmp_path, None, ["named"], None, 7, log)
    assert step.status == "timeout"
    assert step.ran == ["tests::named"]


def test_suspend_inclusive_network_time_has_original_deterministic_kill_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC53"]
    assert rule.tests == (
        'time::tests::suspend_inclusive_clock_advances_admission_and_expires_retained_probes',
        'time::tests::suspend_inclusive_clock_counts_entire_probe_round_trip',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC53", core=True)
    assert not gate.has_switch("HC53")


def test_beacon_generation_binding_has_genuine_dkg_kill_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC54"]
    assert rule.tests == (
        'state::validator_committee::tests::generation::committee_bootstrap_rejects_genuine_dkg_from_another_generation',
        'state::validator_committee::tests::generation::committee_restore_rejects_genuine_dkg_from_another_generation',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC54", core=True)
    assert not gate.has_switch("HC54")


def test_stake_index_quantities_have_a_distinct_original_pool_kill_control():
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    rule = rules["HC87"]
    assert rule.tests == (
        "smartcontracts::isi::staking::tests::stake_index_quantities_prepaid_and_borrowed_from_original_pool",
    )
    assert not rule.scenarios
    assert rule.id != rules["HC55"].id
    assert gate.has_switch("HC87", core=True)
    assert not gate.has_switch("HC87")


def test_replay_configuration_has_a_distinct_original_source_kill_control():
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    rule = rules["HC94"]
    assert rule.tests == (
        "sumeragi::executor::publication_tests::replay_completion_retirement_keeps_exact_source_and_original_pool_retry",
    )
    assert not rule.scenarios
    assert rule.id != rules["HC56"].id
    assert gate.has_switch("HC94", core=True)
    assert not gate.has_switch("HC94")


def test_native_amx_binding_has_a_distinct_original_paid_restart_kill_control():
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    rule = rules["HC95"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::native_amx_paid_commit_survives_certified_restart_and_rejects_bypass",
    )
    assert not rule.scenarios
    assert rule.id != rules["HC54"].id
    assert gate.has_switch("HC95", core=True)
    assert not gate.has_switch("HC95")
def test_fee_reward_claim_has_exact_signed_entitlement_kill_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC55"]
    assert rule.tests == (
        'validation_fee_rewards::tests::signed_fee_reward_claim_rejects_every_changed_binding_before_mutation',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC55", core=True)
    assert not gate.has_switch("HC55")


def test_shared_staking_custody_has_additive_fee_reserve_kill_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC56"]
    assert rule.tests == (
        'validation_fee_rewards::tests::shared_fee_stake_reward_custody_is_additive',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC56", core=True)
    assert not gate.has_switch("HC56")


def test_completed_replay_requires_exact_certificate_and_source_kill_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC57"]
    assert rule.tests == (
        'sumeragi::executor::replay::tests::completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC57", core=True)
    assert not gate.has_switch("HC57")


def test_fee_rewards_require_canonical_network_xor_kill_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC58"]
    assert rule.tests == (
        'validation_fee_rewards::tests::canonical_network_xor_is_required_before_fee_reward_state_changes',
        'state::network_xor::tests::network_xor_rejects_wrong_definition_scope_and_precision',
        'smartcontracts::isi::staking::tests::staking_registration_rejects_wrong_xor_shape_with_transaction_rollback',
        'validation_fee_rewards::tests::public_fee_reward_claim_rejects_wrong_network_xor_without_writes_and_retries_original_plan',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC58", core=True)
    assert not gate.has_switch("HC58")
    assert 'sumeragi_core_mutation = "HC58"' in (
        gate.REPO / "crates/iroha_core/src/state/network_xor.rs"
    ).read_text()


def test_current_network_xor_claim_control_owns_actual_public_fee_claim_and_original_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC58"]
    selector = "validation_fee_rewards::tests::public_fee_reward_claim_rejects_wrong_network_xor_without_writes_and_retries_original_plan"
    assert rule.tests[-1] == selector and len(rule.tests) == 4
    core = gate.REPO / "crates/iroha_core/src"
    source = (core / "validation_fee_rewards/signed_claim_tests.rs").read_text()
    body = source.split("fn " + selector.rsplit("::", 1)[-1] + "()", 1)[1].split("#[test]", 1)[0]
    for required in ("seed_claim_credit", "signed_claim_instruction", "instruction.clone()",
                     "NumericSpec::fractional(18)", "changed.xor_asset_definition_id",
                     "rows_before", "source_before", "destination_before", "stake_before",
                     "original_wire", "original_parameters", "original_definition",
                     "unchanged original authorized claim plan", "reserved_xor", "receipt.sequence"):
        assert required in body
    assert 'include!("validation_fee_rewards/signed_claim_tests.rs");' in (core / "validation_fee_rewards.rs").read_text()
    assert "reward_claim_rejects_wrong_xor_shape_with_transaction_rollback" not in rule.tests[-1]
    for mid, leaf in (("HC67", "live_multisig_proposal_decode_refusal_retries_original_signed_xor_transfer"),
                      ("HC68", "live_multisig_proposal_body_binding_rolls_back_original_signed_xor_transfer")):
        current = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
        assert current.tests[0].endswith("::" + leaf)
        assert "fn " + leaf + "()" in (core / "smartcontracts/isi/multisig/tests/proposal_attempt.rs").read_text()
        assert all("signed_xor_claim" not in name for name in current.tests)


def test_inline_beacon_reducer_verifies_each_share_before_retention():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC59"]
    assert rule.tests == (
        'beacon::tests::threshold_beacon_inline_reducer_rejects_invalid_share_without_losing_original_slots',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC59", core=True)
    assert not gate.has_switch("HC59")


def test_preparation_capacity_source_survives_queued_publication_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC60"]
    assert rule.tests == (
        'sumeragi::executor::preparation::tests::certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC60", core=True)
    assert not gate.has_switch("HC60")


def test_lane_anchor_history_preserves_original_refusal_and_same_source_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC61"]
    assert rule.tests == (
        'sumeragi::lanes::executor::native_decode_tests::anchor_read_refusal_retains_original_lane_body_until_capacity_returns',
        'sumeragi::lanes::evidence::tests::anchor_history_refusal_retains_exact_source_through_lane_evidence_retry',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC61", core=True)
    assert not gate.has_switch("HC61")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/lanes/mod.rs"
    assert 'sumeragi_core_mutation = "HC61"' in source.read_text()


def test_prepared_block_keeps_original_shared_execution_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC62"]
    assert rule.tests == (
        'sumeragi::executor::publication_tests::prepared_block_moves_original_graph_and_rejects_replaced_shared_control',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC62", core=True)
    assert not gate.has_switch("HC62")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor.rs"
    assert 'sumeragi_core_mutation = "HC62"' in source.read_text()


def test_state_publication_preserves_original_resource_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC63"]
    assert rule.tests == (
        'sumeragi::executor::publication::tests::state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release',
        'sumeragi::executor::publication::tests::state_execution_and_membership_refusals_preserve_actual_release_owners',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC63", core=True)
    assert not gate.has_switch("HC63")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor/publication.rs"
    assert 'sumeragi_core_mutation = "HC63"' in source.read_text()


def test_committed_archive_capture_preserves_original_resource_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC64"]
    assert rule.tests == (
        'sumeragi::executor::archive_tests::committed_archive_index_refusal_retains_original_release_and_exact_publication',
        'sumeragi::executor::archive_tests::committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC64", core=True)
    assert not gate.has_switch("HC64")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor.rs"
    assert 'sumeragi_core_mutation = "HC64"' in source.read_text()


def test_cold_preparation_preserves_original_execution_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC65"]
    assert rule.tests == (
        'sumeragi::executor::preparation::tests::cold_prepare_refusal_retains_original_finishing_owner_and_exact_release',
        'sumeragi::executor::preparation::tests::cold_prepare_validation_refusals_retain_original_storage_owners',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC65", core=True)
    assert not gate.has_switch("HC65")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor.rs"
    assert 'sumeragi_core_mutation = "HC65"' in source.read_text()


def test_original_cell_acquisition_preserves_nonblocking_physical_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC71"]
    assert rule.tests == (
        'sumeragi::executor::preparation::tests::cold_prepare_validation_refusals_retain_original_storage_owners',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC71", core=True)
    assert not gate.has_switch("HC71")
    source = gate.REPO / "crates/iroha_core/src/state/world_acquisition.rs"
    assert 'sumeragi_core_mutation = "HC71"' in source.read_text()


def test_physical_history_contention_ignores_logical_membership_release():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC73"]
    assert rule.tests == (
        'state::storage_transactions::history::tests::physical_history_busy_ignores_logical_cleanup_and_retries_actual_release',
        'sumeragi::executor::publication::tests::state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC73", core=True)
    assert not gate.has_switch("HC73")
    source = gate.REPO / "crates/iroha_core/src/state/storage_transactions.rs"
    assert 'sumeragi_core_mutation = "HC73"' in source.read_text()


def test_opaque_host_and_replay_preserve_signed_staking_authority():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC66"]
    assert rule.tests == (
        'executor::opaque_monetary_tests::raw_ivm_staking_trigger_requires_signed_monetary_plan',
        'executor::opaque_monetary_tests::supplied_proved_staking_effects_require_signed_monetary_plan',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC66", core=True)
    assert not gate.has_switch("HC66")
    source = gate.REPO / "crates/iroha_core/src/deferred_authority.rs"
    assert 'sumeragi_core_mutation = "HC66"' in source.read_text()


def test_live_multisig_proposals_preserve_original_decoder_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC67"]
    assert rule.tests == (
        'smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_decode_refusal_retries_original_signed_xor_transfer',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC67", core=True)
    assert not gate.has_switch("HC67")
    source = gate.REPO / "crates/iroha_core/src/smartcontracts/isi/multisig.rs"
    assert 'sumeragi_core_mutation = "HC67"' in source.read_text()


def test_retained_multisig_proposals_bind_exact_approved_body_and_physical_row():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC68"]
    assert rule.tests == (
        'smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_body_binding_rolls_back_original_signed_xor_transfer',
        'smartcontracts::isi::multisig::tests::proposal_attempt::proposal_migration_validates_original_physical_key_and_body_before_writes',
        'queue::router::tests::persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission',
        'state::deserialize::decode_tests::restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC68", core=True)
    assert not gate.has_switch("HC68")
    source = gate.REPO / "crates/iroha_core/src/smartcontracts/isi/multisig.rs"
    assert 'sumeragi_core_mutation = "HC68"' in source.read_text()


def test_multisig_cancellation_and_expiry_keep_original_custom_decode_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC69"]
    assert rule.tests == (
        'smartcontracts::isi::multisig::tests::proposal_attempt::cancel_wrapper_decode_refusal_rolls_back_and_retries_original_signed_approval',
        'smartcontracts::isi::multisig::tests::proposal_attempt::expiry_child_decode_refusal_rolls_back_and_retries_original_signed_approval',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC69", core=True)
    assert not gate.has_switch("HC69")
    source = gate.REPO / "crates/iroha_core/src/smartcontracts/isi/multisig.rs"
    assert 'sumeragi_core_mutation = "HC69"' in source.read_text()


def test_multisig_queue_traversal_preserves_native_depth_bound():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC70"]
    assert rule.tests == (
        'queue::router::tests::persisted_multisig_chain_is_checked_in_linear_expansions',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC70", core=True)
    assert not gate.has_switch("HC70")
    source = gate.REPO / "crates/iroha_core/src/queue/router.rs"
    assert 'sumeragi_core_mutation = "HC70"' in source.read_text()


def test_prepared_certificate_preserves_original_state_reader_release():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC72"]
    assert rule.tests == (
        'sumeragi::executor::validation_refusal_tests::prepared_certificate_busy_retries_same_execution_after_original_reader_release',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC72", core=True)
    assert not gate.has_switch("HC72")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor.rs"
    assert 'sumeragi_core_mutation = "HC72"' in source.read_text()


def test_da_cold_refunds_retain_original_writer_custody():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC75"]
    assert rule.tests == (
        'state::da_hydration::release_tests::original_cold_da_refunds_follow_all_rebuild_and_rewind_writers',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC75", core=True)
    assert not gate.has_switch("HC75")
    source = gate.REPO / "crates/iroha_core/src/state/da_hydration.rs"
    assert 'sumeragi_core_mutation = "HC75"' in source.read_text()


def test_committed_head_retries_require_the_original_source_release():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC74"]
    assert rule.tests == (
        'sumeragi::driver::exec::source_retry_tests::committed_head_waits_for_original_release_across_prepare_append_and_commit',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC74", core=True)
    assert not gate.has_switch("HC74")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/exec.rs"
    assert 'sumeragi_core_mutation = "HC74"' in source.read_text()



def test_all_execution_producer_retries_require_original_physical_release():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC76"]
    assert rule.tests == (
        'sumeragi::driver::exec::producer_retry_tests::every_execution_producer_retains_original_source_until_actual_release',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC76", core=True)
    assert not gate.has_switch("HC76")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/exec.rs"
    assert 'sumeragi_core_mutation = "HC76"' in source.read_text()



def test_cancelled_execution_producers_cannot_resume_when_context_returns():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC78"]
    assert rule.tests == (
        'sumeragi::driver::exec::producer_retry_tests::cancellation_stays_final_when_the_identical_context_and_request_return',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC78", core=True)
    assert not gate.has_switch("HC78")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/exec.rs"
    assert 'sumeragi_core_mutation = "HC78"' in source.read_text()


def test_pending_ingress_admission_requires_its_exact_original_capacity_source():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC77"]
    assert rule.tests == (
        'sumeragi::driver::witness_admission_tests::pending_capacity_requires_original_release_despite_foreign_wake_and_huge_clock',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC77", core=True)
    assert not gate.has_switch("HC77")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/mod.rs"
    assert 'sumeragi_core_mutation = "HC77"' in source.read_text()



def test_admitted_ingress_refunds_follow_both_original_mutexes():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC80"]
    assert rule.tests == (
        'sumeragi::driver::witness_admission_tests::admitted_ingress_eviction_refunds_only_after_pending_and_ingress_mutexes_release',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC80", core=True)
    assert not gate.has_switch("HC80")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/mod.rs"
    assert 'sumeragi_core_mutation = "HC80"' in source.read_text()


def test_completed_replay_retains_original_encoding_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC79"]
    assert rule.tests == (
        'sumeragi::executor::replay::tests::completed_replay_retains_exact_receipt_through_original_pool_scratch_refusal',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC79", core=True)
    assert not gate.has_switch("HC79")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor/replay.rs"
    assert 'sumeragi_core_mutation = "HC79"' in source.read_text()


def test_native_beacon_startup_retains_original_readiness_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC81"]
    assert rule.tests == (
        "sumeragi::executor::publication_tests::beacon_startup_retains_original_capacity_through_worker_channel_and_node",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC81", core=True)
    assert not gate.has_switch("HC81")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor_control.rs"
    assert 'sumeragi_core_mutation = "HC81"' in source.read_text()


def test_scheduler_retirement_cancels_original_waiters_before_refunds():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC83"]
    assert rule.tests == (
        "sumeragi::driver::exec::producer_retry_tests::cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC83", core=True)
    assert not gate.has_switch("HC83")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/exec.rs"
    assert 'sumeragi_core_mutation = "HC83"' in source.read_text()


def test_world_root_verification_retains_original_storage_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC82"]
    assert rule.tests == (
        'sumeragi::test_chain::tests::world_state_tests::world_root_verification_preserves_original_writer_refusal_and_exact_retry',
        'sumeragi::test_chain::tests::world_state_tests::world_root_verification_preserves_original_capacity_refusal_and_exact_retry',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC82", core=True)
    assert not gate.has_switch("HC82")
    source = gate.REPO / "crates/iroha_core/src/state/world_state_accumulator.rs"
    assert 'sumeragi_core_mutation = "HC82"' in source.read_text()


def test_startup_history_retains_original_cold_kura_read_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC84"]
    assert rule.tests == (
        "kura::tests::startup_history_retains_original_cold_kura_refusal_and_exact_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC84", core=True)
    assert not gate.has_switch("HC84")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/driver/mod.rs"
    assert 'sumeragi_core_mutation = "HC84"' in source.read_text()


def test_shared_beacon_owner_requires_complete_current_external_binding():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC85"]
    assert rule.tests == (
        "beacon::session_owner::validated::tests::"
        "shared_authenticated_session_rechecks_every_current_external_binding",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC85", core=True)
    assert not gate.has_switch("HC85")
    source = gate.REPO / "crates/iroha_core/src/beacon/session_owner/validated.rs"
    assert 'sumeragi_core_mutation = "HC85"' in source.read_text()


def test_original_local_custody_invariant_requires_native_recovery():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC86"]
    assert rule.tests == (
        "sumeragi::executor::preparation::tests::"
        "original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC86", core=True)
    assert not gate.has_switch("HC86")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/executor/preparation.rs"
    assert 'sumeragi_core_mutation = "HC86"' in source.read_text()


def test_stake_index_and_signed_reward_controls_have_distinct_source_identities():
    indexed = gate.index_mutations(gate.CORE_MUTATIONS)
    assert indexed["HC55"].tests == (
        "validation_fee_rewards::tests::signed_fee_reward_claim_rejects_every_changed_binding_before_mutation",
    )
    assert indexed["HC87"].tests == (
        "smartcontracts::isi::staking::tests::stake_index_quantities_prepaid_and_borrowed_from_original_pool",
    )
    assert not indexed["HC87"].scenarios
    assert gate.has_switch("HC55", core=True)
    assert gate.has_switch("HC87", core=True)
    assert not gate.has_switch("HC87")
    stake = (gate.REPO / "crates/iroha_core/src/smartcontracts/isi/staking.rs").read_text()
    reward = (gate.REPO / "crates/iroha_core/src/validation_fee_rewards.rs").read_text()
    assert 'sumeragi_core_mutation = "HC87"' in stake
    assert 'sumeragi_core_mutation = "HC55"' not in stake
    assert 'sumeragi_core_mutation = "HC55"' in reward
    assert 'sumeragi_core_mutation = "HC87"' not in reward


def test_beacon_decoder_preserves_actual_local_decode_scope():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC88"]
    assert rule.tests == (
        "beacon::tests::session_decoder_preserves_actual_local_scope_without_invalidity_or_fabricated_pool",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC88", core=True)
    assert not gate.has_switch("HC88")
    source = gate.REPO / "crates/iroha_core/src/beacon.rs"
    assert 'sumeragi_core_mutation = "HC88"' in source.read_text()


def test_credential_decoder_preserves_captured_original_scope_and_allocator_cause():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC89"]
    assert rule.tests == (
        "beacon::credential::tests::credential_decoder_captures_original_scope_before_unwind_and_retries_unchanged_bytes",
        "beacon::credential::tests::credential_decoder_physical_refusal_keeps_exact_allocator_cause_and_retries",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC89", core=True)
    assert not gate.has_switch("HC89")
    source = gate.REPO / "crates/iroha_core/src/beacon/credential.rs"
    assert 'sumeragi_core_mutation = "HC89"' in source.read_text()


def test_native_journal_preserves_original_control_refusal():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC90"]
    assert rule.tests == (
        "sumeragi::native_journal::tests::native_cursor_preserves_original_pool_refusal_and_retries_identical_prefix",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC90", core=True)
    assert not gate.has_switch("HC90")
    source = gate.REPO / "crates/iroha_core/src/sumeragi/native_journal.rs"
    assert 'sumeragi_core_mutation = "HC90"' in source.read_text()


def test_live_dkg_owns_physical_outputs_before_durable_claim_and_randomness():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC91"]
    assert rule.tests == (
        "beacon::dkg_local_seat::ownership_tests::prepared_local_outputs_are_complete_before_randomness_at_four_and_thirty_one",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC91", core=True)
    assert not gate.has_switch("HC91")
    source = gate.REPO / "crates/iroha_core/src/beacon/session_owner/dkg/pending.rs"
    assert 'sumeragi_core_mutation = "HC91"' in source.read_text()


def test_beacon_credential_output_uses_only_its_pre_extraction_physical_backing():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC92"]
    assert rule.tests == (
        "beacon::credential::prepared_output::tests::prepared_credential_uses_exact_original_output_without_late_growth_at_four_and_thirty_one",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC92", core=True)
    assert not gate.has_switch("HC92")
    source = gate.REPO / "crates/iroha_core/src/beacon/credential/prepared_output.rs"
    assert 'sumeragi_core_mutation = "HC92"' in source.read_text()


def test_daemon_beacon_mutation_has_its_actual_owner_and_exact_regression():
    rule = gate.index_mutations(gate.DAEMON_MUTATIONS)["HC93"]
    assert rule.tests == (
        "runtime_provider_broker::protocol::platform::tests::beacon_operation_reuses_original_graph_across_ingress_dispatch_and_response",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC93", daemon=True)
    assert not gate.has_switch("HC93", core=True)
    assert not gate.has_switch("HC93")
    with pytest.raises(ValueError, match="exactly one"):
        gate.has_switch("HC93", daemon=True, core=True)


def test_daemon_mutation_table_cannot_select_a_dependency_rule(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--daemon", "--list"])
    assert gate.main() == 0
    listing = capsys.readouterr().out
    assert "HC93" in listing
    assert "HC92" not in listing
    assert "MS1" not in listing


@pytest.mark.parametrize("arguments", [
    ["--daemon", "--core"], ["--daemon", "--only", "HC92"],
    ["--core", "--only", "HC93"], ["--only", "HC93"],
    ["--daemon", "--core-profile", "test"],
])
def test_daemon_mutation_owner_and_profile_are_exact(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2


@pytest.mark.parametrize("owner", ["daemon", "core", "protocol"])
@pytest.mark.parametrize("mutation", [None, "HC93"])
def test_daemon_mutation_environment_never_reaches_dependency_owners(
    monkeypatch, tmp_path, owner, mutation
):
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            return "test result: ok. 1 passed; 0 failed;", None
    def popen(command, **options):
        captured.update(command=command, environment=options["env"])
        return Process()
    for name in ["SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION", "SUMERAGI_MODEL_MUTATION"]:
        monkeypatch.setenv(name, "inherited-foreign-rule")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=owner == "core", daemon=owner == "daemon")
    code, _, _ = gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0, tmp_path / "log")
    assert code == 0
    package, features, selected_environment = gate.package_options(args)
    profile_options = ["--profile", "test"] if owner == "core" else ["--release"]
    assert captured["command"] == [
        "cargo", "test", "--locked", "-p", package, *profile_options,
        "--features", features, "--lib", "--", "named"
    ]
    if owner == "daemon":
        assert (package, features, selected_environment) == (
            "irohad_lib", "mutation-testing", "SUMERAGI_DAEMON_MUTATION"
        )
    for name in ["SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION", "SUMERAGI_MODEL_MUTATION"]:
        if mutation is not None and name == selected_environment:
            assert captured["environment"][name] == mutation
        else:
            assert name not in captured["environment"]


@pytest.mark.parametrize("status", ["execution-error", "missing-test", "timeout"])
def test_daemon_gate_requires_a_named_test_failure(monkeypatch, tmp_path, status):
    monkeypatch.setattr(gate, "has_switch", lambda _, *, daemon: daemon)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args: gate.Step(status=status))
    args = SimpleNamespace(daemon=True, target_dir=tmp_path, timeout_test=0, fast=True)
    result = gate.evaluate(args, tmp_path, gate.DAEMON_MUTATIONS[0])
    assert result["verdict"] == "error"
    assert result["reason"] == f"named tests: {status}"


@pytest.mark.parametrize("test_build,mutation_feature,accepted", [
    (False, False, True), (True, False, True),
    (True, True, True), (False, True, False),
])
def test_daemon_guard_rejects_mutation_features_in_non_test_builds(
    tmp_path, test_build, mutation_feature, accepted
):
    guard = ROOT / "crates/irohad/src/mutation_guard.rs"
    assert "mod mutation_guard;" in (guard.parent / "lib.rs").read_text()
    command = ["rustc", "--edition=2024", "--crate-type=lib", "--emit=metadata",
               str(guard), "-o", str(tmp_path / "guard.rmeta")]
    if test_build:
        command += ["--cfg", "test"]
    if mutation_feature:
        command += ["--cfg", 'feature="mutation-testing"']
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    if not accepted:
        assert "mutation-testing is test-only" in result.stderr


@pytest.fixture(scope="module")
def daemon_build_script(tmp_path_factory):
    executable = tmp_path_factory.mktemp("daemon-mutation-build") / "build-script"
    result = subprocess.run(
        ["rustc", "--edition=2024", str(ROOT / "crates/irohad/build.rs"),
         "-o", str(executable)], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return executable


@pytest.mark.parametrize("feature,mutation,flags,accepted,emitted", [
    (False, "HC93", "", True, False),
    (False, None, '--cfg\x1fsumeragi_daemon_mutation="HC93"', False, False),
    (True, "HC93", "", True, True),
    (True, None, "", True, False),
    (True, "unknown_rule", "", False, False),
    (True, 'HC93"', "", False, False),
])
def test_daemon_build_script_has_no_shipping_fault_control(
    daemon_build_script, feature, mutation, flags, accepted, emitted
):
    environment = dict(os.environ)
    for key in ("CARGO_FEATURE_MUTATION_TESTING", "SUMERAGI_DAEMON_MUTATION"):
        environment.pop(key, None)
    environment["SUMERAGI_MUTATION"] = "foreign-protocol-rule"
    environment["SUMERAGI_CORE_MUTATION"] = "foreign-core-rule"
    environment["CARGO_ENCODED_RUSTFLAGS"] = flags
    if feature:
        environment["CARGO_FEATURE_MUTATION_TESTING"] = "1"
    if mutation is not None:
        environment["SUMERAGI_DAEMON_MUTATION"] = mutation
    result = subprocess.run(
        [str(daemon_build_script)], cwd=ROOT / "crates/irohad", env=environment,
        capture_output=True, text=True, check=False,
    )
    assert (result.returncode == 0) == accepted, result.stderr
    assert ('cargo:rustc-cfg=sumeragi_daemon_mutation="HC93"' in result.stdout) == emitted
    assert "cargo:rustc-cfg=sumeragi_mutation=" not in result.stdout
    assert "cargo:rustc-cfg=sumeragi_core_mutation=" not in result.stdout
    if not feature and mutation:
        assert "ignored" in result.stdout


def capture_command(monkeypatch,tmp_path):
    captured={}
    class Child:
        returncode=0
        def communicate(self,*,timeout=None): return '',None
    def popen(command,**kwargs):
        captured.update(command=command,seed_base=kwargs['env'].get('SUMERAGI_SIM_SEED_BASE'))
        return Child()
    monkeypatch.setattr(gate.subprocess,'Popen',popen)
    gate.cargo_test(SimpleNamespace(),tmp_path,None,[],None,900,tmp_path/'cargo.log',no_run=True)
    return captured

def test_actual_mutation_command_cannot_resolve_an_unlocked_dependency_graph(monkeypatch,tmp_path):
    assert '--locked' in capture_command(monkeypatch,tmp_path)['command']

def test_actual_mutation_command_rejects_inherited_simulator_seed_base(monkeypatch,tmp_path):
    monkeypatch.setenv('SUMERAGI_SIM_SEED_BASE','123456789')
    assert capture_command(monkeypatch,tmp_path)['seed_base'] is None

@pytest.mark.parametrize('scenarios,expected',[ ((),[900]), (('F1',),[900,3600]) ])
def test_actual_baseline_keeps_original_named_and_scenario_deadlines(monkeypatch,tmp_path,scenarios,expected):
    if scenarios: scenarios=(next(iter(gate.SCENARIOS)),)
    calls=[]
    monkeypatch.setattr(gate,'build',lambda *args:gate.Step(status='pass'))
    def step(args,target,mutation,filters,seeds,timeout,log):
        calls.append(timeout);return gate.Step(status='pass')
    monkeypatch.setattr(gate,'run_step',step)
    args=SimpleNamespace(target_dir=tmp_path,timeout_test=900,timeout_scenario=3600,seeds=200,fast=False)
    result=gate.evaluate_baseline(args,tmp_path,[SimpleNamespace(tests=('tests::named',),scenarios=scenarios)])
    assert result['verdict']=='pass'
    assert calls==expected,'each original invocation must retain its configured deadline'

def setup_main(monkeypatch,tmp_path,extra=()):
    monkeypatch.setattr(sys,'argv',['sumeragi_mutation_gate.py','--only','MS1','--fast','--jobs','1','--target-dir',str(tmp_path),*extra])
    captured={}
    def baseline(args,*rest):
        captured['build_cap']=args.timeout_build
        return {'id':'baseline','verdict':'pass'}
    monkeypatch.setattr(gate,'evaluate_baseline',baseline)
    monkeypatch.setattr(gate,'evaluate',lambda args,target,mu:{'id':mu.id,'verdict':'killed_by_test','named':{'failed':['tests::named']}})
    return captured

def test_actual_mutation_default_build_deadline_is_twenty_minutes(monkeypatch,tmp_path):
    captured=setup_main(monkeypatch,tmp_path)
    assert gate.main()==0
    assert captured['build_cap']==1200

def test_actual_strict_gate_cannot_pass_without_an_unmutated_baseline(monkeypatch,tmp_path):
    setup_main(monkeypatch,tmp_path,('--strict','--skip-baseline'))
    with pytest.raises(SystemExit) as error: gate.main()
    assert error.value.code==2


@pytest.mark.parametrize("timeout", [900, 1200, 3600])
@pytest.mark.parametrize("completed_code", [0, 101])
def test_mutation_command_retains_cap_failure_after_late_natural_completion(
    monkeypatch, tmp_path, timeout, completed_code
):
    output = "test tests::named ... " + ("ok" if completed_code == 0 else "FAILED") + "\n"
    class Process:
        returncode = completed_code
        def communicate(self, *, timeout=None):
            return output, None
    moments = iter((100.0, 100.0 + timeout + 1.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    code, retained, elapsed = gate.cargo_test(
        SimpleNamespace(), tmp_path, None, ["named"], None, timeout, tmp_path / "late.log"
    )
    assert elapsed == timeout + 1.0
    assert retained == output
    assert code is None, "a late natural completion cannot pass or kill a mutant"


def test_mutation_command_keeps_explicit_unbounded_diagnostic_wait(
    monkeypatch, tmp_path
):
    class Process:
        returncode = 0
        def communicate(self, *, timeout=None):
            assert timeout is None
            return "retained original output", None
    moments = iter((100.0, 10000.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    code, retained, elapsed = gate.cargo_test(
        SimpleNamespace(), tmp_path, None, [], None, 0, tmp_path / "unbounded.log"
    )
    assert (code, retained, elapsed) == (0, "retained original output", 9900.0)


def test_nightly_runs_every_actual_daemon_mutation_and_retains_its_report():
    workflow = (ROOT / ".github/workflows/nightly_sumeragi.yml").read_text()
    match = re.search(r"(?ms)^  daemon_mutation_gate:\n(.*?)(?=^  [a-z_]+:|\Z)", workflow)
    assert match is not None, "daemon rules need their own maintained nightly owner"
    job = match.group(1)
    command = "python3 scripts/sumeragi_mutation_gate.py --daemon --jobs 1 --strict --fast"
    assert f"run: {command}\n" in job
    assert "--only" not in job, "nightly qualification must cover the complete owner table"
    assert "if: always()" in job
    assert "target/sumeragi-daemon-mutants/report.json" in job
    assert "target/sumeragi-daemon-mutants/logs" in job
    assert "sumeragi-daemon-mutation-gate-${{ github.run_id }}" in job


def test_nightly_core_mutations_keep_dependency_instrumentation_and_full_inventory():
    workflow = (ROOT / ".github/workflows/nightly_sumeragi.yml").read_text()
    match = re.search(r"(?ms)^  core_mutation_gate:\n(.*?)(?=^  [a-z_]+:|\Z)", workflow)
    assert match is not None
    job = match.group(1)
    command = (
        "python3 scripts/sumeragi_mutation_gate.py --core --core-profile test "
        "--jobs 1 --strict --fast"
    )
    assert f"run: {command}\n" in job
    assert "--only" not in job
    assert not any(option in job for option in (
        "--skip-baseline", "--timeout-build", "--timeout-test", "--timeout-scenario",
    ))
    assert "if: always()" in job
    assert "target/sumeragi-core-mutants/report.json" in job
    assert "target/sumeragi-core-mutants/logs" in job


SUMERAGI_CI_JOBS = (
    ("nightly_sumeragi.yml", "simulator"),
    ("nightly_sumeragi.yml", "mutation_gate"),
    ("nightly_sumeragi.yml", "core_mutation_gate"),
    ("nightly_sumeragi.yml", "daemon_mutation_gate"),
    ("nightly_sumeragi.yml", "model_mutation_gate"),
    ("pr.yml", "sumeragi"),
)


def require_pinned_sumeragi_toolchain(job):
    """Check compiler selection before restoring or executing native artifacts."""
    channel = re.search(
        r'^channel\s*=\s*"([^"]+)"$',
        (ROOT / "rust-toolchain.toml").read_text(), re.MULTILINE,
    )
    assert channel is not None
    action = (
        "      - uses: actions-rust-lang/setup-rust-toolchain@"
        "166cdcfd11aee3cb47222f9ddb555ce30ddb9659\n"
        "        with:\n"
        '          cache: "false"\n'
        f"          toolchain: {channel.group(1)}\n"
    )
    assert action in job, "Sumeragi must install the repository-pinned Rust toolchain"
    setup = job.index(action)
    assert setup < job.index("      - uses: Swatinem/rust-cache@")
    assert setup < job.index("        run:")


@pytest.mark.parametrize("workflow_name,job_name", SUMERAGI_CI_JOBS)
def test_sumeragi_ci_installs_current_compiler_before_cache_and_execution(
    workflow_name, job_name
):
    workflow = (ROOT / ".github/workflows" / workflow_name).read_text()
    match = re.search(rf"(?ms)^  {job_name}:\n(.*?)(?=^  [a-z_]+:|\Z)", workflow)
    assert match is not None
    require_pinned_sumeragi_toolchain(match.group(1))


@pytest.mark.parametrize("change", ("missing", "stale", "unreviewed", "late"))
def test_sumeragi_ci_rejects_missing_stale_or_late_compiler_selection(change):
    workflow = (ROOT / ".github/workflows/nightly_sumeragi.yml").read_text()
    match = re.search(r"(?ms)^  simulator:\n(.*?)(?=^  [a-z_]+:|\Z)", workflow)
    assert match is not None
    job = match.group(1)
    action = re.search(
        r"(?m)^      - uses: actions-rust-lang/setup-rust-toolchain@[^\n]+\n"
        r"        with:\n          cache: [^\n]+\n          toolchain: [^\n]+\n", job,
    )
    assert action is not None
    if change == "missing":
        job = job.replace(action.group(0), "")
    elif change == "stale":
        job = job.replace(action.group(0), re.sub(
            r"toolchain: [^\n]+", "toolchain: retired-compiler", action.group(0),
        ))
    elif change == "unreviewed":
        job = job.replace("166cdcfd11aee3cb47222f9ddb555ce30ddb9659", "v1")
    else:
        job = job.replace(action.group(0), "") + action.group(0)
    with pytest.raises(AssertionError):
        require_pinned_sumeragi_toolchain(job)


def test_committee_boundary_mutations_use_their_exact_production_source_owners():
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    expected = {
        "HC100": "genuine_candidate_pools_choose_largest_equal_vote_committee",
        "HC101": "prepared_boundary_readiness_requires_every_frozen_seat_custody",
        "HC102": "prepared_boundary_readiness_requires_every_frozen_seat_custody",
        "HC103": "frozen_boundary_refusal_returns_original_pool_and_does_not_need_fresh_incumbent_keys",
    }
    for identifier, test in expected.items():
        rule = registered[identifier]
        assert rule.tests == (f"sumeragi::epoch_election::tests::{test}",)
        assert not rule.scenarios
        assert gate.has_switch(identifier, core=True)
        assert not gate.has_switch(identifier)
        assert not gate.has_switch(identifier, daemon=True)
    plan = (gate.REPO / "crates/iroha_core/src/sumeragi/epoch_election/plan.rs").read_text()
    assert "let ready = prepared_committee_ready(&source, transition);" in plan
    assert 'cfg!(all(test, sumeragi_core_mutation = "HC102"))' in plan
    assert '#[cfg(all(test, sumeragi_core_mutation = "HC101"))]' in plan
    assert '#[cfg(all(test, sumeragi_core_mutation = "HC103"))]' in plan


def test_native_lane_finalizer_gate_requires_original_validator_return_and_publication():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC133"]
    assert rule.tests == (
        "sumeragi::executor::validation_refusal_tests::original_lane_finalizer_refusal_returns_same_graph_before_seal_and_publishes_after_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC133", core=True)
    assert not gate.has_switch("HC133")


def test_native_witness_handoff_gate_requires_source_guard_and_one_shot_recovery():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC134"]
    assert rule.tests == (
        "sumeragi::executor::validation_refusal_tests::validated_witness_guard_failure_requires_recovery_without_reexecuting_original_source",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC134", core=True)
    assert not gate.has_switch("HC134")
    assert not gate.has_switch("HC134", daemon=True)


def test_borrowed_amx_clone_gate_requires_actual_paid_persisted_source():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC135"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::paid_borrowed_custody::native_amx_persisted_paid_borrowed_prepared_proof_clone_retains_original_graph_and_lifetime",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC135", core=True)
    assert not gate.has_switch("HC135")
    assert not gate.has_switch("HC135", daemon=True)


def test_native_lane_refusal_gate_requires_both_actual_original_pool_boundaries():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC136"]
    assert rule.tests == (
        "sumeragi::lanes::custody::tests::original_signer_pinning_refuses_then_retries_the_same_pool_and_stake_cut",
        "sumeragi::lanes::step::sample_owner_tests::sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC136", core=True)
    assert not gate.has_switch("HC136")
    assert not gate.has_switch("HC136", daemon=True)


def test_queue_resident_gate_requires_actual_last_owner_pressure_and_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC137"]
    assert rule.tests == (
        "queue::tests::resident_owner_tests::removed_pending_owner_retains_original_resident_credit_until_last_reader",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC137", core=True)
    assert not gate.has_switch("HC137")
    assert not gate.has_switch("HC137", daemon=True)


def test_queue_cold_fence_gate_requires_actual_thread_and_original_refund():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC138"]
    assert rule.tests == (
        "queue::tests::resident_owner_tests::cold_queue_retirement_holds_original_fence_until_first_admission_can_publish",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC138", core=True)
    assert not gate.has_switch("HC138")
    assert not gate.has_switch("HC138", daemon=True)


def test_pending_payload_lease_mutations_bind_distinct_actual_original_boundaries():
    expected = {
        "HC140": "queue::payload_leases::tests::pending_payload_lease_retires_on_actual_certified_state_publication",
        "HC141": "queue::payload_leases::tests::pending_payload_selection_cannot_adopt_clear_and_readmission_during_selection",
        "HC142": "queue::payload_leases::tests::pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue",
        "HC143": "queue::payload_leases::tests::pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue",
        "HC144": "queue::payload_leases::tests::pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap",
        "HC145": "queue::payload_leases::tests::pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap",
    }
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    source = gate.REPO / "crates/iroha_core/src/queue/payload_leases.rs"
    text = source.read_text()
    for identifier, name in expected.items():
        rule = registered[identifier]
        assert rule.tests == (name,)
        assert not rule.scenarios
        assert gate.has_switch(identifier, core=True)
        assert not gate.has_switch(identifier)
        assert not gate.has_switch(identifier, daemon=True)
        assert 'fn ' + name.rsplit("::", 1)[-1] + '(' in text
        assert 'all(test, sumeragi_core_mutation = "' + identifier + '")' in text
        owners = {path.relative_to(gate.REPO / "crates/iroha_core/src").as_posix()
                  for path in (gate.REPO / "crates/iroha_core/src").rglob("*.rs")
                  if 'sumeragi_core_mutation = "' + identifier + '"' in path.read_text()}
        assert owners == {"queue/payload_leases.rs"}


def test_signed_root_gate_requires_actual_bounded_worker_and_original_parent_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC139"]
    assert rule.tests == (
        "sumeragi::executor::validation_refusal_tests::prepared_certificate_uses_bounded_signed_root_without_rewalking_execution_history",
        "sumeragi::executor::validation_refusal_tests::successor_context_uses_original_parent_and_bounded_signed_root_without_history_rewalk",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC139", core=True)
    assert not gate.has_switch("HC139")
    assert not gate.has_switch("HC139", daemon=True)


@pytest.mark.parametrize("code,status,passed,failed", [(0, "ok", 1, 0), (101, "FAILED", 0, 1)])
@pytest.mark.parametrize("shape", ["missing_running", "duplicate_running", "wrong_running", "missing_duration", "bad_duration", "trailing_summary", "duplicate_summary", "malformed_extra_summary", "summary_before_terminal", "header_after_terminal"])
def test_incomplete_or_conflicting_full_completion_cannot_pass_or_kill(
    monkeypatch, tmp_path, code, status, passed, failed, shape
):
    header = "running 1 test\n"
    summary = (f"test result: {status}. {passed} passed; {failed} failed; 0 ignored; "
               "0 measured; 0 filtered out; finished in 0.01s\n")
    if shape == "missing_running":
        header = ""
    elif shape == "duplicate_running":
        header *= 2
    elif shape == "wrong_running":
        header = "running 2 tests\n"
    elif shape == "missing_duration":
        summary = summary.replace(" finished in 0.01s", "")
    elif shape == "bad_duration":
        summary = summary.replace("0.01s", "unobserved")
    elif shape == "trailing_summary":
        summary = summary.rstrip() + " unexpected\n"
    elif shape == "duplicate_summary":
        summary *= 2
    elif shape == "malformed_extra_summary":
        summary += "test result: incomplete\n"
    terminal = f"test tests::named ... {status}\n"
    output = header + terminal + summary
    if shape == "summary_before_terminal":
        output = header + summary + terminal
    elif shape == "header_after_terminal":
        output = terminal + header + summary
    selected_cargo_results(monkeypatch, code, output)
    result = gate.run_step(SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
                           tmp_path / "named.log")
    assert result.status == "execution-error"


def synthetic_scheduling_args(tmp_path, *, fast=False):
    """Use isolated Python scheduling fixtures, never positive native qualification."""
    return SimpleNamespace(target_dir=tmp_path, timeout_build=1200, timeout_test=900,
                           timeout_scenario=3600, seeds=200, fast=fast)


def test_baseline_keeps_distinct_ordered_named_tuples_and_scenario_union(monkeypatch, tmp_path):
    scenarios = list(gate.SCENARIOS)[:2]
    mutations = [gate.m('SYNTHETIC_A', 'fixture', ['tests::b', 'tests::a'], scenarios),
                 gate.m('SYNTHETIC_B', 'fixture', ['tests::c'], [scenarios[0]]),
                 gate.m('SYNTHETIC_C', 'fixture', ['tests::b', 'tests::a'], [scenarios[1]])]
    builds, calls = [], []
    monkeypatch.setattr(gate, 'build', lambda *args: builds.append(args) or gate.Step(status='pass'))
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append((tuple(filters), seeds, timeout, log))
        return gate.Step(status='pass', selected=list(filters), ran=list(filters), log=str(log))
    monkeypatch.setattr(gate, 'run_step', run_step)
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    assert result['verdict'] == 'pass'
    assert len(builds) == 1 and builds[0][2] is None
    expected_tuples = sorted({mu.tests for mu in mutations})
    expected_scenarios = sorted({gate.SCENARIOS[s] for mu in mutations for s in mu.scenarios})
    assert [filters for filters, seeds, _, _ in calls if seeds is None] == expected_tuples
    assert [filters for filters, seeds, _, _ in calls if seeds == 200] == [(s,) for s in expected_scenarios]
    assert all(cap == (900 if seeds is None else 3600) for _, seeds, cap, _ in calls)
    assert len({log for _, _, _, log in calls}) == len(calls)
    assert result['named']['ran'] == sorted({t for mu in mutations for t in mu.tests})
    assert result['scenario']['ran'] == expected_scenarios
    assert result['named']['steps'][0]['filters'] == list(expected_tuples[0])


@pytest.mark.parametrize('table', ['MUTATIONS', 'CORE_MUTATIONS', 'DAEMON_MUTATIONS'])
def test_baseline_group_plan_preserves_every_current_registry_filter(monkeypatch, tmp_path, table):
    """Inspect actual registered selectors; mocked terminals are not native evidence."""
    mutations = getattr(gate, table)
    calls = []
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append((tuple(filters), seeds, timeout))
        return gate.Step(status='pass', selected=list(filters), ran=list(filters))
    monkeypatch.setattr(gate, 'run_step', run_step)
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    named = [filters for filters, seeds, _ in calls if seeds is None]
    scenarios = [filters for filters, seeds, _ in calls if seeds is not None]
    assert named == sorted({mu.tests for mu in mutations})
    assert {f for filters in named for f in filters} == {t for mu in mutations for t in mu.tests}
    assert scenarios == [(s,) for s in sorted({gate.SCENARIOS[s] for mu in mutations for s in mu.scenarios})]
    assert result['verdict'] == 'pass'
    assert all(cap == (900 if seeds is None else 3600) for _, seeds, cap in calls)


@pytest.mark.parametrize('bad_status', ['timeout', 'missing-test', 'execution-error', 'build-error', 'fail'])
def test_any_baseline_group_refusal_survives_later_pass_and_preserves_union(monkeypatch, tmp_path, bad_status):
    mutations = [gate.m('SYNTHETIC_A', 'fixture', ['tests::a']),
                 gate.m('SYNTHETIC_B', 'fixture', ['tests::b'])]
    calls = []
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append(tuple(filters))
        status = bad_status if len(calls) == 1 else 'pass'
        return gate.Step(status=status, selected=list(filters), ran=list(filters),
                         failed=list(filters) if status == 'fail' else [])
    monkeypatch.setattr(gate, 'run_step', run_step)
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    assert calls == [('tests::a',), ('tests::b',)]
    assert result['verdict'] == 'fail'
    assert result['named']['status'] == bad_status
    assert [step['status'] for step in result['named']['steps']] == [bad_status, 'pass']
    assert result['named']['selected'] == ['tests::a', 'tests::b']


def test_grouped_discovery_timeout_never_launches_or_replenishes_that_step(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.time, 'monotonic', lambda: 100.0)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    calls = []
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False):
        calls.append((tuple(filters), timeout))
        if filters[0] == 'tests::a':
            assert '--list' in filters, 'an exhausted discovery cannot launch runtime'
            return 0, 'tests::a: test\n\n1 test, 0 benchmarks\n', 900.0
        if '--list' in filters:
            return 0, 'tests::b: test\n\n1 test, 0 benchmarks\n', 1.0
        return 0, ('running 1 test\ntest tests::b ... ok\ntest result: ok. 1 passed; 0 failed; '
                   '0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'), 1.0
    monkeypatch.setattr(gate, 'cargo_test', cargo_test)
    mutations = [gate.m('SYNTHETIC_A', 'fixture', ['tests::a']),
                 gate.m('SYNTHETIC_B', 'fixture', ['tests::b'])]
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    assert result['verdict'] == 'fail' and result['named']['status'] == 'timeout'
    assert len(calls) == 3
    assert [timeout for _, timeout in calls] == [900, 900, 899]
    assert [step['status'] for step in result['named']['steps']] == ['timeout', 'pass']
    assert result['named']['steps'][0]['ran'] == []
    assert result['named']['steps'][1]['ran'] == ['tests::b']


@pytest.mark.parametrize('output,code', [
    ('running 1 test\ntest tests::a ... ok\n', 0),
    ('running 1 test\ntest tests::a ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n', 0),
    ('running 1 test\ntest tests::a ... ok\ntest tests::a ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n', 0),
    ('running 1 test\ntest tests::foreign ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n', 0),
])
def test_grouped_baseline_requires_exact_actual_discovered_terminals(monkeypatch, tmp_path, output, code):
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    monkeypatch.setattr(gate.time, 'monotonic', lambda: 100.0)
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False):
        if '--list' in filters:
            return 0, 'tests::a: test\n\n1 test, 0 benchmarks\n', 0.0
        return code, output, 1.0
    monkeypatch.setattr(gate, 'cargo_test', cargo_test)
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path,
                                    [gate.m('SYNTHETIC_A', 'fixture', ['tests::a'])])
    assert result['verdict'] == 'fail'
    assert result['named']['status'] not in ('pass', 'fail')
    assert len(result['named']['steps']) == 1
    assert result['named']['steps'][0]['selected'] == ['tests::a']


def test_mutant_preserves_named_tuple_and_runs_each_distinct_scenario_once(monkeypatch, tmp_path):
    scenarios = list(gate.SCENARIOS)[:2]
    mu = gate.m('SYNTHETIC_A', 'fixture', ['tests::b', 'tests::a'],
                [scenarios[1], scenarios[0], scenarios[1]])
    calls, builds = [], []
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: builds.append(args) or gate.Step(status='pass'))
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append((mutation, tuple(filters), seeds, timeout, log))
        return gate.Step(status='fail' if seeds is None else 'pass',
                         failed=['tests::a'] if seeds is None else [], selected=list(filters), ran=list(filters))
    monkeypatch.setattr(gate, 'run_step', run_step)
    result = gate.evaluate(synthetic_scheduling_args(tmp_path), tmp_path, mu)
    assert result['verdict'] == 'killed_by_test'
    assert len(builds) == 1 and builds[0][2] == mu.id
    assert calls[0][1:4] == (mu.tests, None, 900)
    assert [call[1:4] for call in calls[1:]] == [
        ((gate.SCENARIOS[scenarios[1]],), 200, 3600),
        ((gate.SCENARIOS[scenarios[0]],), 200, 3600)]
    assert all(call[0] == mu.id for call in calls)
    assert len({call[4] for call in calls}) == 3
    assert result['named']['failed'] == ['tests::a']
    assert result['scenario']['status'] == 'pass'
    assert len(result['scenario']['steps']) == 2


@pytest.mark.parametrize('bad_status', ['timeout', 'missing-test', 'execution-error', 'build-error'])
def test_mutant_scenario_error_cannot_be_hidden_by_named_or_earlier_scenario_kill(monkeypatch, tmp_path, bad_status):
    scenarios = list(gate.SCENARIOS)[:2]
    mu = gate.m('SYNTHETIC_A', 'fixture', ['tests::named'], scenarios)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    steps = iter([gate.Step(status='fail', failed=['tests::named']),
                  gate.Step(status='fail', failed=[gate.SCENARIOS[scenarios[0]]]),
                  gate.Step(status=bad_status)])
    monkeypatch.setattr(gate, 'run_step', lambda *args: next(steps))
    result = gate.evaluate(synthetic_scheduling_args(tmp_path), tmp_path, mu)
    assert result['verdict'] == 'error' and result['reason'] == f'scenarios: {bad_status}'
    assert result['scenario']['status'] == bad_status
    assert len(result['scenario']['steps']) == 2
    assert result['scenario']['failed'] == [gate.SCENARIOS[scenarios[0]]]


def test_independent_steps_may_exceed_union_budget_without_replenishing_a_step(monkeypatch, tmp_path):
    """The prospective policy is per invocation; no historical timeout is reclassified."""
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    calls = []
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append(timeout)
        return gate.Step(status='pass', seconds=800.0, selected=list(filters), ran=list(filters))
    monkeypatch.setattr(gate, 'run_step', run_step)
    mutations = [gate.m('SYNTHETIC_A', 'fixture', ['tests::a']),
                 gate.m('SYNTHETIC_B', 'fixture', ['tests::b'])]
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    assert calls == [900, 900]
    assert result['verdict'] == 'pass' and result['named']['seconds'] == 1600.0
    assert [step['deadline_seconds'] for step in result['named']['steps']] == [900, 900]


@pytest.mark.parametrize('fast', [False, True])
def test_baseline_and_mutant_fast_mode_preserve_named_coverage_only(monkeypatch, tmp_path, fast):
    scenario = next(iter(gate.SCENARIOS))
    mu = gate.m('SYNTHETIC_A', 'fixture', ['tests::b', 'tests::a'], [scenario])
    calls = []
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        calls.append((mutation, tuple(filters), seeds, timeout))
        return gate.Step(status='pass')
    monkeypatch.setattr(gate, 'run_step', run_step)
    args = synthetic_scheduling_args(tmp_path, fast=fast)
    baseline = gate.evaluate_baseline(args, tmp_path, [mu])
    mutant = gate.evaluate(args, tmp_path, mu)
    assert len(calls) == (2 if fast else 4)
    assert [filters for _, filters, seeds, _ in calls if seeds is None] == [mu.tests, mu.tests]
    assert ('scenario' in baseline) == ('scenario' in mutant) == (not fast)


@pytest.mark.parametrize('named_status,scenario_statuses,strict,expected,verdict', [
    ('pass', ('fail', 'pass'), False, 0, 'killed_by_scenario_only'),
    ('pass', ('fail', 'pass'), True, 1, 'killed_by_scenario_only'),
    ('fail', ('pass', 'pass'), True, 0, 'killed_by_test'),
    ('fail', ('fail', 'timeout'), True, 1, 'error'),
    ('pass', ('pass', 'pass'), False, 1, 'survived'),
])
def test_main_report_preserves_strict_and_error_semantics_of_grouped_scenarios(
    monkeypatch, tmp_path, named_status, scenario_statuses, strict, expected, verdict
):
    """Synthetic in-memory registry and mocked terminals are not native evidence."""
    scenarios = list(gate.SCENARIOS)[:2]
    mu = gate.m('SYNTHETIC_A', 'fixture', ['tests::named'], scenarios)
    monkeypatch.setattr(gate, 'MUTATIONS', [mu])
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    def run_step(args, target, mutation, filters, seeds, timeout, log):
        if mutation is None:
            status = 'pass'
        elif seeds is None:
            status = named_status
        else:
            status = scenario_statuses[scenarios.index(next(s for s in scenarios if gate.SCENARIOS[s] == filters[0]))]
        return gate.Step(status=status, selected=list(filters), ran=list(filters),
                         failed=list(filters) if status == 'fail' else [])
    monkeypatch.setattr(gate, 'run_step', run_step)
    monkeypatch.setattr(sys, 'argv', ['sumeragi_mutation_gate.py', '--jobs', '1',
                                    '--target-dir', str(tmp_path), *(['--strict'] if strict else [])])
    assert gate.main() == expected
    report = gate.json.loads((tmp_path / 'report.json').read_text())
    assert report['baseline']['verdict'] == 'pass'
    assert report['mutations'][0]['verdict'] == verdict
    assert len(report['mutations'][0]['scenario']['steps']) == 2
    assert report['summary']['scenario_missed'] == ([mu.id] if scenario_statuses == ('pass', 'pass') else [])
    assert report['summary']['error'] == ([mu.id] if verdict == 'error' else [])


def test_grouped_substring_discovery_preserves_extra_and_overlapping_actual_names(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    monkeypatch.setattr(gate.time, 'monotonic', lambda: 100.0)
    actual_names = ['tests::named', 'tests::named_extra', 'tests::other']
    runtime = []
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False):
        selected = [name for name in actual_names if any(f in name for f in filters if not f.startswith('--'))]
        if '--list' in filters:
            return 0, ''.join(f'{name}: test\n' for name in selected) + f'\n{len(selected)} tests, 0 benchmarks\n', 0.0
        runtime.append(selected)
        return 0, (f'running {len(selected)} tests\n' + ''.join(f'test {name} ... ok\n' for name in selected)
                   + f'test result: ok. {len(selected)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'), 1.0
    monkeypatch.setattr(gate, 'cargo_test', cargo_test)
    mutations = [gate.m('SYNTHETIC_A', 'fixture', ['tests::named']),
                 gate.m('SYNTHETIC_B', 'fixture', ['tests::named_extra']),
                 gate.m('SYNTHETIC_C', 'fixture', ['tests::other'])]
    result = gate.evaluate_baseline(synthetic_scheduling_args(tmp_path), tmp_path, mutations)
    assert result['verdict'] == 'pass'
    assert runtime == [['tests::named', 'tests::named_extra'], ['tests::named_extra'], ['tests::other']]
    assert result['named']['selected'] == result['named']['ran'] == actual_names
    assert [step['selected'] for step in result['named']['steps']] == runtime


def test_mutant_scenario_runtime_cannot_reset_discovery_budget_or_hide_late_pass(monkeypatch, tmp_path):
    scenarios = list(gate.SCENARIOS)[:2]
    mu = gate.m('SYNTHETIC_A', 'fixture', ['tests::named'], scenarios)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    monkeypatch.setattr(gate.time, 'monotonic', lambda: 100.0)
    calls = []
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False):
        assert len([f for f in filters if f == 'tests::named' or f in (gate.SCENARIOS[s] for s in scenarios)]) == 1
        name = filters[0]
        calls.append((name, '--list' in filters, timeout))
        if '--list' in filters:
            return 0, f'{name}: test\n\n1 test, 0 benchmarks\n', 2.0
        late = name == gate.SCENARIOS[scenarios[1]]
        verdict = 'ok' if late else 'FAILED'
        output = (f'running 1 test\ntest {name} ... {verdict}\ntest result: {verdict}. '
                  f'{1 if late else 0} passed; {0 if late else 1} failed; '
                  '0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
        return (0 if late else 101), output, (3598.5 if late else 1.0)
    monkeypatch.setattr(gate, 'cargo_test', cargo_test)
    result = gate.evaluate(synthetic_scheduling_args(tmp_path), tmp_path, mu)
    assert result['named']['status'] == 'fail'
    assert result['verdict'] == 'error' and result['reason'] == 'scenarios: timeout'
    assert [step['status'] for step in result['scenario']['steps']] == ['fail', 'timeout']
    assert [timeout for _, _, timeout in calls] == [900, 898, 3600, 3598, 3600, 3598]
    assert result['scenario']['steps'][1]['ran'] == [gate.SCENARIOS[scenarios[1]]]


@pytest.mark.parametrize('groups', [[], [()]])
def test_empty_group_or_selector_tuple_refuses_without_unfiltered_native_run(monkeypatch, tmp_path, groups):
    def no_step(*args):
        raise AssertionError('an empty selector cannot spawn a broad unfiltered suite')
    monkeypatch.setattr(gate, 'run_step', no_step)
    result = gate.run_grouped_steps(synthetic_scheduling_args(tmp_path), tmp_path, None,
                                   groups, None, 900, tmp_path, 'synthetic-empty')
    assert result['status'] == 'missing-test'
    assert result['selected'] == result['ran'] == result['failed'] == []
    assert len(result['steps']) == len(groups)
    if groups:
        assert result['steps'][0]['detail'] == ['no selectors for this invocation']
        assert result['steps'][0]['status'] == 'missing-test'
        assert result['steps'][0]['discovery_log'] == ''


def test_empty_mutant_named_tuple_refuses_before_source_build_or_unfiltered_run(monkeypatch, tmp_path):
    def no_operation(*args, **kwargs):
        raise AssertionError('a mutation without named controls cannot inspect/build/run an unfiltered suite')
    for name in ('has_switch', 'build', 'run_step'):
        monkeypatch.setattr(gate, name, no_operation)
    result = gate.evaluate(synthetic_scheduling_args(tmp_path), tmp_path,
                           gate.m('SYNTHETIC_EMPTY', 'fixture', [], [next(iter(gate.SCENARIOS))]))
    assert result['verdict'] == 'error' and result['reason'] == 'no named test selectors'
    assert 'build' not in result and 'named' not in result and 'scenario' not in result


@pytest.mark.parametrize("extra,message", [
    (["--seeds", "0"], "positive u64 count"),
    (["--seeds", "-1"], "positive u64 count"),
    (["--seeds", str(1 << 64)], "positive u64 count"),
    (["--seeds", str(-(1 << 64))], "positive u64 count"),
    (["--jobs", "0"], "must be positive"),
    (["--jobs", "-1"], "must be positive"),
    (["--only", ""], "at least one mutation"),
    (["--only", " , , "], "at least one mutation"),
    (["--only", "MS1,MS1"], "duplicate mutation"),
    (["--only", " MS1, MS1 "], "duplicate mutation"),
])
@pytest.mark.parametrize("strict", [False, True])
def test_mutation_cli_invalid_counts_refuse_before_output_or_native_child(monkeypatch, tmp_path, capsys, extra, message, strict):
    output = tmp_path / "unused-campaign"
    def forbidden(*args, **kwargs):
        pytest.fail("invalid counts reached execution")
    monkeypatch.setattr(gate, "evaluate_baseline", forbidden)
    monkeypatch.setattr(gate, "evaluate", forbidden)
    monkeypatch.setattr(gate.subprocess, "Popen", forbidden)
    monkeypatch.setattr(sys, "argv", ["gate", "--target-dir", str(output), *(["--strict"] if strict else []), *extra])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2
    assert message in capsys.readouterr().err
    assert not output.exists()

@pytest.mark.parametrize("seeds,jobs", [(1,1),(200,4),(10000,2),((1 << 64)-1,1)])
def test_mutation_cli_valid_counts_and_unique_selection_keep_exact_report(monkeypatch, tmp_path, seeds, jobs):
    import json
    called=[]
    def baseline(args, target, mutations):
        called.append((args.seeds, args.jobs, [m.id for m in mutations]))
        return {"id":"baseline", "verdict":"pass"}
    monkeypatch.setattr(gate,"evaluate_baseline",baseline)
    monkeypatch.setattr(gate,"evaluate",lambda args,target,mu:{"id":mu.id,"verdict":"killed_by_test","named":{"failed":["tests::named"]}})
    monkeypatch.setattr(sys,"argv",["gate","--strict","--only"," MS1, MS2 ","--seeds",str(seeds),"--jobs",str(jobs),"--target-dir",str(tmp_path)])
    assert gate.main()==0
    assert called==[(seeds,jobs,["MS1","MS2"])]
    report=json.loads((tmp_path/"report.json").read_text())
    assert report["summary"]["mutations"]==2
    assert report["summary"]["killed_by_test"]==["MS1","MS2"]
    assert [m["id"] for m in report["mutations"]]==["MS1","MS2"]
    assert report["seeds"]==seeds
    assert report["fast"] is False


def test_state_native_descriptor_mutation_binds_exact_admitted_engine_and_original_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC146"]
    assert rule.tests == (
        "state::state_preverify_backend_admission_tests::unsupported_retired_and_claimed_backends_fail_state_admission",
        "state::state_preverify_backend_admission_tests::native_compiled_descriptor_refusal_preserves_key_admission_and_original_retry",
    )
    assert not rule.scenarios
    assert gate.has_switch("HC146", core=True)
    assert not gate.has_switch("HC146")
    assert not gate.has_switch("HC146", daemon=True)
    assert not gate.has_switch("HC146", model=True)
    source = (gate.REPO / "crates/iroha_core/src/state.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC146")' in source
    assert 'production_verify_backend_tag(proof.backend.as_str())' in source
    assert 'Some(iroha_data_model::zk::BackendTag::NativePipaRPasta)' in source
    owners = {path.relative_to(gate.REPO / "crates/iroha_core/src").as_posix()
              for path in (gate.REPO / "crates/iroha_core/src").rglob("*.rs")
              if 'sumeragi_core_mutation = "HC146"' in path.read_text()}
    assert owners == {"state.rs"}
    assert "self.zk.halo2" not in source
    assert "crate::zk::preverify_with_budget(" in source
    assert "crate::zk::native_pipa_r::validate_key(" in source
    backend = (gate.REPO / "crates/iroha_data_model/src/zk.rs").read_text()
    assert "pub const ALL: [Self; 2] = [Self::NativePipaRPasta, Self::Stark]" in backend
    controls = (gate.REPO / "crates/iroha_core/src/state/state_preverify_backend_admission_tests.rs").read_text()
    for name in rule.tests:
        assert f"fn {name.rsplit('::', 1)[-1]}(" in controls
    assert "ZK_BACKEND_NATIVE_PIPA_R" in controls
    assert "ZK_BACKEND_STARK_FRI_V1" in controls
    assert "PreverifyResult::Duplicate" in controls


@pytest.mark.parametrize("failed_item", ["baseline", "mutation"])
@pytest.mark.parametrize("error_type", [AssertionError, OSError])
@pytest.mark.parametrize("jobs", [1, 3])
@pytest.mark.parametrize("strict", [False, True])
def test_worker_exception_retains_original_item_and_complete_failed_report(
    monkeypatch, tmp_path, capsys, failed_item, error_type, jobs, strict
):
    """Mocked evaluators exercise real worker threads/reporting, never native kills."""
    table = [gate.m(f"SYNTHETIC_{n}", "script exception fixture", ["tests::named"])
             for n in range(3)]
    monkeypatch.setattr(gate, "MUTATIONS", table)
    calls = []
    def baseline(*_):
        calls.append("baseline")
        if failed_item == "baseline":
            raise error_type("original source guard refused")
        return {"id": "baseline", "verdict": "pass"}
    def mutant(args, target, mu):
        calls.append(mu.id)
        if failed_item == "mutation" and mu.id == table[1].id:
            raise error_type("original source guard refused")
        return {"id": mu.id, "verdict": "killed_by_test"}
    monkeypatch.setattr(gate, "evaluate_baseline", baseline)
    monkeypatch.setattr(gate, "evaluate", mutant)
    monkeypatch.setattr(sys, "argv", ["gate", "--jobs", str(jobs), "--target-dir", str(tmp_path),
                                     *(["--strict"] if strict else [])])
    assert gate.main() == 1
    report = gate.json.loads((tmp_path / "report.json").read_text())
    assert sorted(calls) == sorted(["baseline", *(mu.id for mu in table)])
    assert [row["id"] for row in report["mutations"]] == [mu.id for mu in table]
    failed_id = "baseline" if failed_item == "baseline" else table[1].id
    rows = {row["id"]: row for row in [report["baseline"], *report["mutations"]]}
    assert rows[failed_id] == {"id": failed_id, "verdict": "error",
                              "reason": f"worker evaluation raised {error_type.__name__}: original source guard refused"}
    assert report["summary"]["baseline"] == ("error" if failed_item == "baseline" else "pass")
    assert report["summary"]["error"] == ([] if failed_item == "baseline" else [failed_id])
    assert report["summary"]["killed_by_test"] == [mu.id for mu in table if mu.id != failed_id]
    assert report["summary"]["survived"] == report["summary"]["killed_by_scenario_only"] == []
    assert "[4/4]" in capsys.readouterr().out


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_worker_does_not_catch_process_interrupts(monkeypatch, tmp_path, interrupt):
    """Run the actual worker synchronously to observe its uncaught BaseException."""
    class InlineThread:
        def __init__(self, target, args, daemon):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
        def join(self):
            pass
    monkeypatch.setattr(gate.threading, "Thread", InlineThread)
    monkeypatch.setattr(gate, "MUTATIONS", [gate.m("SYNTHETIC_A", "interrupt fixture", ["tests::named"])])
    def baseline(*_):
        raise interrupt("original process interrupt")
    monkeypatch.setattr(gate, "evaluate_baseline", baseline)
    monkeypatch.setattr(sys, "argv", ["gate", "--jobs", "1", "--target-dir", str(tmp_path)])
    with pytest.raises(interrupt, match="original process interrupt"):
        gate.main()
    assert not (tmp_path / "report.json").exists()


def test_missing_required_baseline_cannot_be_relabelled_as_skipped(monkeypatch, tmp_path):
    """Model Thread's isolated BaseException boundary without suppressing it in the gate."""
    observed = []
    class IsolatedInterruptThread:
        def __init__(self, target, args, daemon):
            self.target, self.args = target, args
        def start(self):
            try:
                self.target(*self.args)
            except SystemExit as error:
                observed.append(error)
        def join(self):
            pass
    monkeypatch.setattr(gate.threading, "Thread", IsolatedInterruptThread)
    table = [gate.m("SYNTHETIC_A", "missing baseline fixture", ["tests::named"])]
    monkeypatch.setattr(gate, "MUTATIONS", table)
    def baseline(*_):
        raise SystemExit("uncaught baseline worker interrupt")
    monkeypatch.setattr(gate, "evaluate_baseline", baseline)
    monkeypatch.setattr(gate, "evaluate", lambda args, target, mu: {"id": mu.id, "verdict": "killed_by_test"})
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--jobs", "2", "--target-dir", str(tmp_path)])
    assert gate.main() == 1
    assert len(observed) == 1 and str(observed[0]) == "uncaught baseline worker interrupt"
    report = gate.json.loads((tmp_path / "report.json").read_text())
    assert report["baseline"] is None
    assert report["summary"]["baseline"] == "error"
    assert report["summary"]["killed_by_test"] == [table[0].id]


@pytest.mark.parametrize("workflow_name,step_name,expected_argv,explicit_count", (
    ("nightly_sumeragi.yml", "Run every fault scenario at 10 000 seeds",
     ["test", "--locked", "-p", "iroha_sumeragi", "--release", "--features", "sim", "--lib", "--", "sim::"], "10000"),
    ("pr.yml", "Core, simulator, specification traceability and quorums (default seeds)",
     ["test", "--locked", "-p", "iroha_sumeragi", "--features", "sim"], None),
    ("pr.yml", "Node driver, lanes and four-validator node tests",
     ["test", "--locked", "-p", "iroha_core", "--lib", "--", "sumeragi::lanes", "sumeragi::node", "sumeragi::driver", "sumeragi::executor"], None),
))
@pytest.mark.parametrize("inherited", (
    {"SUMERAGI_SIM_SEED": "7"},
    {"SUMERAGI_SIM_SEED_BASE": "18446744073709551615"},
    {"SUMERAGI_SIM_SEEDS": "0"},
    {"SUMERAGI_SIM_SEED": "7", "SUMERAGI_SIM_SEED_BASE": "18446744073709551615", "SUMERAGI_SIM_SEEDS": "0"},
))
def test_ci_sumeragi_sweeps_execute_with_their_declared_seed_environment(
    tmp_path, workflow_name, step_name, expected_argv, explicit_count, inherited,
):
    """Execute the actual CI shell with a metadata-only Cargo substitute, never Rust."""
    workflow = (ROOT / ".github/workflows" / workflow_name).read_text()
    step = re.search(
        r"(?ms)^      - name: " + re.escape(step_name) + r"\n(.*?)(?=^      - |^  [a-z_]+:|\Z)",
        workflow,
    )
    assert step is not None
    run = re.search(r"(?m)^        run: (.+)$", step.group(1))
    assert run is not None
    command = run.group(1)
    if command.startswith('"'):
        command = json.loads(command)
    declared = re.search(r'(?m)^          SUMERAGI_SIM_SEEDS: "([0-9]+)"$', step.group(1))
    assert (declared.group(1) if declared else None) == explicit_count
    recorder = tmp_path / "cargo"
    recorder.write_text(
        "#!" + sys.executable + "\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'seeds': {key: os.environ.get(key) "
        "for key in ('SUMERAGI_SIM_SEED', 'SUMERAGI_SIM_SEED_BASE', 'SUMERAGI_SIM_SEEDS')}}))\n"
    )
    recorder.chmod(0o700)
    environment = dict(os.environ)
    for key in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"):
        environment.pop(key, None)
    environment.update(inherited)
    if explicit_count is not None:
        environment["SUMERAGI_SIM_SEEDS"] = explicit_count
    environment["PATH"] = str(tmp_path) + os.pathsep + environment.get("PATH", "")
    result = subprocess.run(["/bin/sh", "-c", command], env=environment,
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["argv"] == expected_argv
    assert observed["seeds"] == {
        "SUMERAGI_SIM_SEED": None,
        "SUMERAGI_SIM_SEED_BASE": None,
        "SUMERAGI_SIM_SEEDS": explicit_count,
    }


@pytest.mark.parametrize('code,status,passed,failed', [(0, 'ok', 2, 0), (101, 'FAILED', 1, 1)])
@pytest.mark.parametrize('annotation', ['', ' - should panic'])
def test_logger_split_terminals_preserve_actual_named_mutation_results(
    monkeypatch, tmp_path, code, status, passed, failed, annotation
):
    """Native stdout logging can split libtest's selected name from its status."""
    names = ('tests::named', 'tests::named_extra')
    output = (
        'running 2 tests\n'
        f'test tests::named{annotation} ...   \x1b[2m2026-10-06T14:48:08Z\x1b[0m DEBUG native log\n'
        '    at crates/iroha_core/src/sumeragi/node.rs:1508\n\n'
        f'{status}\n'
        'test tests::named_extra ... ok\n\n'
        f'test result: {status}. {passed} passed; {failed} failed; 0 ignored; '
        '0 measured; 11763 filtered out; finished in 3.72s\n'
    )
    selected_cargo_results(monkeypatch, code, output, names=names)
    step = gate.run_step(SimpleNamespace(), tmp_path, 'HC23', ['named'], None, 5,
                         tmp_path / 'named.log')
    assert step.status == ('fail' if failed else 'pass')
    assert step.ran == list(names)
    assert step.failed == (['tests::named'] if failed else [])


@pytest.mark.parametrize('status,code,passed,failed', [('ok', 0, 1, 0), ('FAILED', 101, 0, 1)])
@pytest.mark.parametrize('annotation', ['', ' - should panic'])
@pytest.mark.parametrize('damage', [
    'missing_terminal', 'duplicate_terminal', 'opposite_terminal', 'orphan_terminal',
    'duplicate_start', 'foreign_start', 'summary_before_terminal',
    'ignored_terminal', 'trailing_start', 'trailing_terminal',
])
def test_logger_split_invalid_output_never_passes_or_kills(
    monkeypatch, tmp_path, status, code, passed, failed, damage, annotation
):
    """Only an unambiguous serial test owner may consume a split terminal."""
    start = f'test tests::named{annotation} ... DEBUG log\n'
    terminal = status + '\n'
    summary = (f'test result: {status}. {passed} passed; {failed} failed; 0 ignored; '
               '0 measured; 11764 filtered out; finished in 3.72s\n')
    output = 'running 1 test\n' + start + terminal + summary
    if damage == 'missing_terminal':
        output = output.replace(terminal, '', 1)
    elif damage == 'duplicate_terminal':
        output = output.replace(terminal, terminal * 2, 1)
    elif damage == 'opposite_terminal':
        output = output.replace(terminal, ('FAILED' if status == 'ok' else 'ok') + '\n', 1)
    elif damage == 'orphan_terminal':
        output = terminal + output
    elif damage == 'duplicate_start':
        output = output.replace(start, start * 2)
    elif damage == 'foreign_start':
        output = output.replace(start, 'test tests::foreign ... DEBUG log\n')
    elif damage == 'summary_before_terminal':
        output = 'running 1 test\n' + start + summary + terminal
    elif damage == 'ignored_terminal':
        output = output.replace(terminal, 'ignored\n', 1)
    elif damage == 'trailing_start':
        output += start + terminal
    elif damage == 'trailing_terminal':
        output += terminal
    selected_cargo_results(monkeypatch, code, output)
    step = gate.run_step(SimpleNamespace(), tmp_path, 'HC23', ['named'], None, 5,
                         tmp_path / 'named.log')
    assert step.status not in ('pass', 'fail')


@pytest.mark.parametrize('status,code,passed,failed', [('ok', 0, 1, 0), ('FAILED', 101, 0, 1)])
def test_should_panic_annotation_keeps_the_actual_test_identity_and_verdict(
    monkeypatch, tmp_path, status, code, passed, failed
):
    """Libtest annotates expected panics; only its terminal result proves success."""
    output = (
        'running 1 test\n'
        f'test tests::named - should panic ... {status}\n'
        f'test result: {status}. {passed} passed; {failed} failed; 0 ignored; '
        '0 measured; 11 filtered out; finished in 0.01s\n'
    )
    selected_cargo_results(monkeypatch, code, output)
    step = gate.run_step(SimpleNamespace(), tmp_path, 'HC23', ['named'], None, 5,
                         tmp_path / 'named.log')
    assert step.status == ('fail' if failed else 'pass')
    assert step.ran == ['tests::named']
    assert step.failed == (['tests::named'] if failed else [])


MODEL_NAMES = {
    "DM1": "isi::amx_owner::tests::original_amx_instruction_clone_retains_exact_graph_and_pool_through_last_reader",
    "DM2": "isi::amx_owner::tests::original_amx_instruction_admits_complete_actual_layouts_before_copy_and_retries_same_pool",
    "DM3": "isi::amx_owner::tests::original_amx_instruction_last_owner_destroys_fields_and_refunds_exact_ledger",
    "DM4": "sumeragi_amx::allocation::tests::original_begin_record_scan_preserves_canonical_depth_refusal_and_exact_retry",
    "DM5": "amx_prepare_streaming_allocations::transaction_id_streaming_matches_canonical_frames_without_heap_allocations",
    "DM6": "amx_prepare_streaming_allocations::begin_matches_borrows_original_graph_without_heap_allocations",
    "DM7": "amx_prepare_streaming_allocations::native_transfer_effects_stream_exact_monetary_fields_without_heap_allocations",
    "DM8": "sumeragi_amx::tests::sumeragi_amx_expiry_refusal_and_unwind_preserve_original_pending_graph",
    "DM9": "sumeragi_amx::tests::sumeragi_amx_encoding_keeps_exact_physical_allocator_refusal",
    "DM10": "sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_uses_one_original_decode_and_retains_metadata",
    "DM11": "sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_binary_refusal",
    "DM12": "sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_json_refusal_and_retry",
    "DM13": "sumeragi_finality::tests::consensus_fingerprint_reuses_original_authenticated_metadata_under_one_pass_budget",
    "DM14": "sumeragi_finality::tests::initial_chain_parameters_reuses_constructor_authenticated_metadata_under_one_pass_budget",
    "DM15": "sumeragi_finality::genesis::original_policy::tests::original_completed_policy_survives_metadata_refusal_without_another_decode",
    "DM16": "sumeragi::epoch::tests::epoch_validation_retains_original_signed_roster_without_generation_allocation",
    "DM17": "parameter::system::npos_json::tests::admitted_npos_record_moves_exact_original_quantity_backing_and_funded_charge_ledger",
    "DM18": "nexus::committee::tests::public_readiness_borrows_original_roster_with_only_canonical_transcript_work",
    "DM19": "nexus::committee::tests::public_activation_borrows_original_generation_beyond_existing_readiness_work",
    "DM20": "smart_contract::multisig_call::tests::canonical_recognition_preserves_original_scoped_refusal_and_same_envelope_retry",
    "DM21": "account::address::tests::canonical_address_json_preserves_original_refusal_fields_scope_and_retry",
    "DM22": "account::json_tests::canonical_account_json_preserves_original_refusal_fields_scope_and_retry",
    "DM23": "account::address::tests::numeric_i105_resource_refusal_stops_at_original_candidate_without_later_allocations",
    "DM24": "account::address::tests::expected_i105_prefix_diagnostics_do_not_retry_original_resource_refusal",
    "DM25": "json_key_codec::tests::account_storage_keys_preserve_original_refusal_fields_scope_and_retry",
    "DM26": "role::native_assignment_tests::role_assignment_storage_keys_preserve_original_account_refusal_and_retry",
    "DM27": "kaigi::tests::kaigi_participant_metadata_preserves_original_account_refusal_and_canonical_map",
    "DM28": "isi::instruction_decode_refusal_tests::archived_instruction_refusal_stops_without_allocating_an_owned_pair_retry",
    "DM29": "isi::instruction_decode_refusal_tests::instruction_slice_retains_original_scoped_refusal_and_retry",
    "DM30": "isi::instruction_decode_refusal_tests::instruction_json_retains_original_scoped_refusal_and_retry",
    "DM31": "isi::instruction_decode_refusal_tests::instruction_base64_scratch_is_admitted_before_decode_and_retries_original_input",
    "DM32": "isi::instruction_decode_refusal_tests::structured_asset_instructions_preserve_original_account_refusal_and_retry",
    "DM33": "sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_threshold_replay_preserves_original_cause_without_diagnostic_allocations",
    "DM34": "sumeragi_finality::epoch_graph::validation_tests::epoch_scope_retains_exact_context_without_a_hidden_heap_graph",
    "DM35": "sumeragi_amx::tests::sumeragi_amx_delayed_decisions_survive_three_rotations_and_restart",
}
MODEL_ALLOCATION_OBSERVER = "amx_prepare_streaming_allocations::observer_counts_all_three_allocation_routes_and_resets_after_unwind"


def test_model_mutations_have_owning_source_hooks_named_controls_and_exact_spec_rows():
    registered = gate.index_mutations(gate.MODEL_MUTATIONS)
    assert set(registered) == set(MODEL_NAMES)
    model = ROOT / "crates/iroha_data_model"
    source = "\n".join(path.read_text() for path in (model / "src").rglob("*.rs"))
    shared = model / "tests/amx_prepare_streaming_allocations.rs"
    lib = (model / "src/lib.rs").read_text()
    assert '#[cfg(test)]\n#[path = "../tests/amx_prepare_streaming_allocations.rs"]\nmod amx_prepare_streaming_allocations;' in lib
    source += "\n" + shared.read_text()
    functions = set(re.findall(r"\bfn\s+(\w+)\s*\(", source))
    rows = re.findall(r"^\| (DM\d+) \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == len(dict(rows)) == len(MODEL_NAMES)
    assert set(dict(rows)) == set(MODEL_NAMES)
    for identifier, name in MODEL_NAMES.items():
        rule = registered[identifier]
        expected = (MODEL_ALLOCATION_OBSERVER, name) if identifier in ("DM5", "DM6", "DM7") else (name,)
        if identifier == "DM17":
            expected = (name,
                "parameter::system::tests::sumeragi_npos_synthetic_identity_is_exact_and_validation_never_allocates",
                "nexus::committee::tests::frozen_policy_validation_borrows_fixed_synthetic_identity_without_allocation")
        if identifier == "DM21":
            expected = (name,
                "account::address::tests::account_address_value_and_map_key_json_decoders_are_borrowed_and_measured",
                "account::address::tests::address_resource_conversions_preserve_fields_and_anonymous_bounds_without_minting_scope")
        if identifier == "DM33":
            expected = (name, "sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_member_replay_preserves_original_cause_without_diagnostic_allocations")
        if identifier == "DM22":
            expected = (name,
                "account::json_tests::account_id_json_roundtrips_large_multisig_as_canonical_i105",
                "account::json_tests::account_id_value_and_map_key_json_decoders_are_borrowed_and_measured",
                "account::json_tests::canonical_account_public_parser_preserves_original_address_cause_and_diagnostics")
        assert rule.tests == expected
        assert all(test.rsplit("::", 1)[-1] in functions for test in expected)
        assert not rule.scenarios
        assert name.rsplit("::", 1)[-1] in functions
        assert name.rsplit("::", 1)[-1] in dict(rows)[identifier]
        assert gate.has_switch(identifier, model=True)
        assert not gate.has_switch(identifier)
        assert not gate.has_switch(identifier, core=True)
        assert not gate.has_switch(identifier, daemon=True)
    assert "mutation-testing = []" in (model / "Cargo.toml").read_text()
    assert "mod model_mutation_guard;" in (model / "src/lib.rs").read_text()
    assert tuple(re.findall(r'"(DM\d+)"', (model / "build.rs").read_text().split("const IDS:", 1)[1].split(";", 1)[0])) == tuple(MODEL_NAMES)


def test_model_streaming_mutations_keep_exact_heap_observation_and_fresh_thread_inputs():
    """The named Model tests observe real allocator routes, not decode or budget counters."""

    model = ROOT / "crates/iroha_data_model"
    observer = (model / "tests/amx_prepare_streaming_allocations.rs").read_text()
    assert observer.count("#[global_allocator]") == 1
    assert "impl GlobalAlloc for TrackingAllocator" in observer
    for route in ("alloc", "alloc_zeroed", "realloc", "dealloc"):
        assert f"unsafe fn {route}(" in observer
        assert f"System.{route}(" in observer
    for route in range(3):
        assert f"record_request({route});" in observer
    assert "fn measured_fresh_thread<T: Send>" in observer
    assert ".spawn(|| measured(operation))" in observer
    assert "std::panic::catch_unwind" in observer
    assert "impl Drop for StopTracking" in observer
    assert "assert_eq!(count, [1, 1, 1]);" in observer
    assert "assert_eq!(measured(|| black_box(7)).1, [0; 3]);" in observer
    assert "AllocationBudget" not in observer and "with_decode_limits" not in observer
    source = (model / "src/sumeragi_amx.rs").read_text()
    for identifier, restored in (("DM5", "norito::encode_canonical(self)"),
                                  ("DM6", "transaction.begin().is_ok_and")):
        assert source.count(f'all(test, sumeragi_model_mutation = "{identifier}")') == 2
        assert restored in source
    guard = (model / "src/model_mutation_guard.rs").read_text()
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard


def test_native_effects_mutation_keeps_exact_domain_streaming_and_actual_allocator_control():
    model = ROOT / "crates/iroha_data_model"
    source = (model / "src/sumeragi_amx/native.rs").read_text()
    assert source.count('all(test, sumeragi_model_mutation = "DM7")') == 3
    assert 'norito::encode_canonical(leg).map(|bytes|' in source
    assert 'writer.write_all(b"iroha:native-amx-transfer:v1")?' in source
    assert 'writer.write_all(&[0])?' in source
    assert 'norito::core::write_canonical_to_writer(leg, writer)' in source
    assert 'return Err(cause);' in source and 'hash.map_err(norito::Error::Io)?' in source
    observer = (model / "tests/amx_prepare_streaming_allocations.rs").read_text()
    assert 'fn native_transfer_effects_stream_exact_monetary_fields_without_heap_allocations()' in observer
    assert '[(0, 0), (1, 64), (64, 1)]' in observer
    assert 'Quantity::zero(), u128::MAX.into(), wide.clone()' in observer
    assert re.search(
        r"let\s*\(actual,\s*requests\)\s*=\s*measured_fresh_thread\s*\(\s*\|\|\s*native_transfer_effects_hash\b",
        observer,
    )
    assert 'assert_eq!(requests, [0; 3]);' in observer
    assert 'AllocationBudget' not in observer and 'with_decode_limits' not in observer


def test_original_begin_depth_mutation_bypasses_only_its_participant_payload_context():
    """DM4 recreates one nested field defect without changing the pool or fixed leaves."""

    source = (ROOT / "crates/iroha_data_model/src/sumeragi_amx/allocation.rs").read_text()
    cfg = 'all(test, sumeragi_model_mutation = "DM4")'
    assert source.count(cfg) == 2
    start = source.index('                // DM4 skips only')
    end = source.index('                let deadline =', start)
    hook = source[start:end]
    assert '#[cfg(' + cfg + ')]' in hook
    assert '#[cfg(not(' + cfg + '))]' in hook
    assert 'ncore::framed_field::<Vec<DataSpaceId>>(body, &mut field_offset)?' in hook
    assert 'read_participants(field.bytes())?' in hook
    assert 'fixed_field::<Vec<DataSpaceId>, _>(body, &mut field_offset, read_participants)?' in hook
    assert not any(owner in hook for owner in ('AllocationBudget', 'ChargedBuffer', 'with_decode_limits', 'unsafe'))
    assert source.index('let read_participants = |bytes: &[u8]|') < start
    assert source[end:].startswith('                let deadline = fixed_field::<u64, _>')


@pytest.mark.parametrize("selected", [None, *MODEL_NAMES])
def test_model_actual_cargo_argv_profile_and_isolated_environment(monkeypatch, tmp_path, selected):
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 900
            return "isolated process result", None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    foreign = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION", "SUMERAGI_MODEL_MUTATION")
    for variable in foreign:
        monkeypatch.setenv(variable, "inherited-foreign-rule")
    for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"):
        monkeypatch.setenv(variable, "7")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    code, output, elapsed = gate.cargo_test(SimpleNamespace(model=True), tmp_path, selected,
        ["isi::amx_owner::tests::named"], None, 900, tmp_path / "model.log")
    assert code == 0 and output == "isolated process result" and elapsed >= 0
    assert captured["command"] == ["cargo", "test", "--locked", "-p", "iroha_data_model",
        "--profile", "test", "--features", "mutation-testing", "--lib", "--", "isi::amx_owner::tests::named"]
    environment = captured["options"]["env"]
    assert captured["options"]["cwd"] == ROOT
    assert captured["options"]["start_new_session"] is True
    assert environment["CARGO_TARGET_DIR"] == str(tmp_path)
    for variable in foreign:
        assert environment.get(variable) == (selected if variable == "SUMERAGI_MODEL_MUTATION" else None)
    assert all(variable not in environment for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"))


@pytest.mark.parametrize("status,verdict", [("fail", "killed_by_test"), ("pass", "survived"),
    ("execution-error", "error"), ("missing-test", "error"), ("timeout", "error")])
def test_model_gate_requires_actual_named_failure_classification(monkeypatch, tmp_path, status, verdict):
    observed = []
    monkeypatch.setattr(gate, "has_switch", lambda identifier, *, model: model and identifier == "DM1")
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    def run(*args):
        observed.append(args)
        return gate.Step(status=status, failed=list(args[3]) if status == "fail" else [])
    monkeypatch.setattr(gate, "run_step", run)
    args = SimpleNamespace(model=True, target_dir=tmp_path, timeout_test=900, fast=False)
    result = gate.evaluate(args, tmp_path, gate.MODEL_MUTATIONS[0])
    assert result["verdict"] == verdict
    assert result["id"] == "DM1"
    assert len(observed) == 1
    assert observed[0][2:6] == ("DM1", gate.MODEL_MUTATIONS[0].tests, None, 900)
    assert "scenario" not in result


@pytest.mark.parametrize("baseline,expected", [("pass", 0), ("fail", 1), ("error", 1)])
def test_model_main_keeps_positive_baseline_exact_report_and_default_caps(monkeypatch, tmp_path, baseline, expected):
    target = tmp_path / "model"
    captured = []
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--model", "--jobs", "1", "--strict", "--target-dir", str(target)])
    def unmutated(args, directory, rules):
        captured.append((args, directory, tuple(rule.id for rule in rules)))
        return {"id": "baseline", "verdict": baseline}
    monkeypatch.setattr(gate, "evaluate_baseline", unmutated)
    monkeypatch.setattr(gate, "evaluate", lambda args, directory, rule: {"id": rule.id, "verdict": "killed_by_test"})
    assert gate.main() == expected
    assert len(captured) == 1
    args, directory, ids = captured[0]
    assert ids == tuple(MODEL_NAMES)
    assert directory == target / "job0"
    assert (args.timeout_build, args.timeout_test, args.timeout_scenario, args.seeds) == (1200, 900, 3600, 200)
    assert not args.fast and not args.skip_baseline
    report = json.loads((target / "report.json").read_text())
    assert report["package"] == "iroha_data_model" and report["profile"] == "test"
    assert report["summary"]["baseline"] == baseline
    assert [result["id"] for result in report["mutations"]] == list(ids)
    assert report["summary"]["mutations"] == len(MODEL_NAMES)


@pytest.mark.parametrize("arguments", [
    ["--model", "--core"], ["--model", "--daemon"],
    ["--model", "--core-profile", "test"], ["--model", "--only", "HC1"],
    ["--core", "--only", "DM1"], ["--daemon", "--only", "DM1"],
    ["--only", "DM1"], ["--model", "--strict", "--skip-baseline"],
])
def test_model_owner_cli_refuses_cross_owner_and_missing_baseline(monkeypatch, tmp_path, arguments):
    target = tmp_path / "refused"
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments, "--target-dir", str(target)])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2
    assert not target.exists(), "refusal must precede any build-lane or native child"


@pytest.mark.parametrize("owners", [(True, True, False), (True, False, True), (False, True, True)])
def test_model_source_census_refuses_multiple_owners(owners):
    with pytest.raises(ValueError, match="exactly one implementation owner"):
        gate.has_switch("DM1", core=owners[0], daemon=owners[1], model=owners[2])


def test_nightly_model_mutations_keep_baseline_tools_profiles_and_full_inventory():
    source = (ROOT / ".github/workflows/nightly_sumeragi.yml").read_text()
    match = re.search(r"(?ms)^  model_mutation_gate:\n(.*?)(?=^  [a-z_]+:|\Z)", source)
    assert match is not None
    job = match.group(1)
    assert "run: python3 scripts/sumeragi_mutation_gate.py --model --jobs 1 --strict\n" in job
    assert not any(argument in job for argument in ("--only", "--skip-baseline", "--fast", "--timeout-build", "--timeout-test", "--timeout-scenario"))
    assert "target/sumeragi-model-mutants/report.json" in job
    assert "target/sumeragi-model-mutants/logs" in job
    assert "if: always()" in job
    assert "CARGO_BUILD_JOBS: \"2\"" in job
    require_pinned_sumeragi_toolchain(job)


@pytest.mark.parametrize("test_build,mutation_feature,accepted", [
    (False, False, True), (True, False, True),
    (True, True, True), (False, True, False),
])
def test_model_guard_rejects_mutation_feature_in_non_test_builds(tmp_path, test_build, mutation_feature, accepted):
    guard = ROOT / "crates/iroha_data_model/src/model_mutation_guard.rs"
    command = ["rustc", "--edition=2024", "--crate-type=lib", "--emit=metadata", str(guard), "-o", str(tmp_path / "model-guard.rmeta")]
    if test_build: command += ["--cfg", "test"]
    if mutation_feature: command += ["--cfg", 'feature="mutation-testing"']
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    if not accepted: assert "mutation-testing is test-only" in result.stderr


@pytest.fixture(scope="module")
def model_build_script(tmp_path_factory):
    executable = tmp_path_factory.mktemp("model-mutation-build") / "build-script"
    result = subprocess.run(["rustc", "--edition=2024", str(ROOT / "crates/iroha_data_model/build.rs"), "-o", str(executable)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return executable


@pytest.mark.parametrize("feature,mutation,flags,accepted,emitted", [
    (False, "DM1", "", True, False), (True, None, "", True, False),
    (True, "DM1", "", True, True), (True, "DM2", "", True, True), (True, "DM3", "", True, True),
    (True, "DM4", "", True, True), (False, "DM4", "", True, False),
    (True, "DM5", "", True, True), (False, "DM5", "", True, False),
    (True, "DM6", "", True, True), (False, "DM6", "", True, False),
    (True, "DM7", "", True, True), (False, "DM7", "", True, False),
    (True, "DM8", "", True, True), (False, "DM8", "", True, False),
    (True, "DM9", "", True, True), (False, "DM9", "", True, False),
    (True, "DM10", "", True, True), (False, "DM10", "", True, False),
    (True, "DM11", "", True, True), (False, "DM11", "", True, False),
    (True, "DM12", "", True, True), (False, "DM12", "", True, False),
    (True, "DM13", "", True, True), (False, "DM13", "", True, False),
    (True, "DM14", "", True, True), (False, "DM14", "", True, False),
    (True, "DM15", "", True, True), (False, "DM15", "", True, False),
    (True, "DM16", "", True, True), (False, "DM16", "", True, False),
    (True, "DM17", "", True, True), (False, "DM17", "", True, False),
    (True, "DM18", "", True, True), (False, "DM18", "", True, False),
    (True, "DM19", "", True, True), (False, "DM19", "", True, False),
    (True, "DM20", "", True, True), (False, "DM20", "", True, False),
    (True, "DM21", "", True, True), (False, "DM21", "", True, False),
    (True, "DM22", "", True, True), (False, "DM22", "", True, False),
    (True, "DM23", "", True, True), (False, "DM23", "", True, False),
    (True, "DM24", "", True, True), (False, "DM24", "", True, False),
    (True, "DM25", "", True, True), (False, "DM25", "", True, False),
    (True, "DM26", "", True, True), (False, "DM26", "", True, False),
    (True, "DM27", "", True, True), (False, "DM27", "", True, False),
    (True, "DM28", "", True, True), (False, "DM28", "", True, False),
    (True, "DM29", "", True, True), (False, "DM29", "", True, False),
    (True, "DM30", "", True, True), (False, "DM30", "", True, False),
    (True, "DM31", "", True, True), (False, "DM31", "", True, False),
    (True, "DM32", "", True, True), (False, "DM32", "", True, False),
    (True, "DM33", "", True, True), (False, "DM33", "", True, False),
    (True, "DM34", "", True, True), (False, "DM34", "", True, False),
    (True, "DM35", "", True, True), (False, "DM35", "", True, False),
    (True, "unknown_rule", "", False, False), (True, "HC1", "", False, False),
    (False, None, '--cfg\x1fsumeragi_model_mutation="DM1"', False, False),
    (True, "DM1", '--cfg\x1fsumeragi_model_mutation="DM2"', False, False),
])
def test_model_build_script_selects_only_registered_owned_test_cfg(model_build_script, feature, mutation, flags, accepted, emitted):
    environment = dict(os.environ)
    for key in ("CARGO_FEATURE_MUTATION_TESTING", "SUMERAGI_MODEL_MUTATION"):
        environment.pop(key, None)
    environment.update(SUMERAGI_MUTATION="MS1", SUMERAGI_CORE_MUTATION="HC1", SUMERAGI_DAEMON_MUTATION="HC93", CARGO_ENCODED_RUSTFLAGS=flags)
    if feature: environment["CARGO_FEATURE_MUTATION_TESTING"] = "1"
    if mutation is not None: environment["SUMERAGI_MODEL_MUTATION"] = mutation
    result = subprocess.run([str(model_build_script)], cwd=ROOT / "crates/iroha_data_model", env=environment, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    expected_values = ", ".join(f'"{identifier}"' for identifier in MODEL_NAMES)
    assert f"cargo:rustc-check-cfg=cfg(sumeragi_model_mutation, values({expected_values}))" in result.stdout
    assert (f'cargo:rustc-cfg=sumeragi_model_mutation="{mutation}"' in result.stdout) == emitted
    for prefix in ("sumeragi_mutation", "sumeragi_core_mutation", "sumeragi_daemon_mutation"):
        assert f"cargo:rustc-cfg={prefix}=" not in result.stdout


def test_native_amx_leg_mutation_keeps_original_pool_rule_and_actual_allocator_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC149"]
    name = "sumeragi::amx::native::tests::native_leg_decode_refuses_occupied_original_pool_before_any_copy_and_retries_exact_source"
    assert rule.tests == (name,)
    assert not rule.scenarios
    assert gate.has_switch("HC149", core=True)
    assert not gate.has_switch("HC149")
    assert not gate.has_switch("HC149", model=True)
    assert not gate.has_switch("HC149", daemon=True)
    implementation = (ROOT / "crates/iroha_core/src/sumeragi/amx/native.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC149")' in implementation
    assert 'AllocationBudget::new(budget.limit_bytes())' in implementation
    assert 'PendingAmxTransferLegDecodeV1::new(bytes, budget).try_decode(bytes)' in implementation
    control = (ROOT / "crates/iroha_core/src/sumeragi/amx/native/tests.rs").read_text()
    assert 'fn ' + name.rsplit('::', 1)[-1] + '(' in control
    assert 'crate::test_allocations::allocations_during' in control
    assert 'budget.try_reserve_layouts(controls)' in control
    assert 'no key, alignment, quantity or graph copy may precede original pool refusal' in control
    assert 'budget.set_limit_bytes(0)' in control


@pytest.mark.parametrize("mutation,name", [
    ("HC150", "original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry"),
    ("HC151", "completed_amx_worker_bank_refuses_replaced_source_parent_and_foreign_pool"),
    ("HC152", "completed_amx_worker_bank_preserves_equal_occurrences_and_metadata_refusal"),
])
def test_native_amx_worker_retry_rules_have_exact_owning_selectors(mutation, name):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == ("sumeragi::executor::amx_retry_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)
    assert not gate.has_switch(mutation, daemon=True)
    control = (ROOT / "crates/iroha_core/src/sumeragi/executor_amx_retry_tests.rs").read_text()
    assert "fn " + name + "(" in control
    implementation = (ROOT / "crates/iroha_core/src/sumeragi/amx/native/retry.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "' + mutation + '")' in implementation


@pytest.mark.parametrize("mutation,names", [
    ("HC153", ("state::storage_transactions::authority::tests::original_publication_pair_matches_real_advance_replace_and_repeat",)),
    ("HC154", ("state::storage_transactions::authority::tests::original_publication_pair_matches_real_advance_replace_and_repeat",)),
    ("HC155", (
        "state::storage_transactions::block::capture::publication_capture_phase_tests::original_membership_cut_refuses_started_published_unwind_and_completed_phases",
        "state::storage_transactions::block::detached_publication::publication_capture_phase_tests::detached_membership_cut_refuses_started_published_unwind_and_released_phases",
    )),
    ("HC156", ("state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse",)),
    ("HC157", ("state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse",)),
    ("HC158", ("state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse",)),
])
def test_original_membership_capture_mutations_have_exact_owning_hooks_and_controls(mutation, names):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == names
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)
    assert not gate.has_switch(mutation, daemon=True)
    source = ROOT / "crates/iroha_core/src"
    hook_owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
                   if re.search(r'sumeragi_core_mutation\s*=\s*"' + mutation + r'"', path.read_text())}
    implementation_path = "state/authority_registry/complete/transaction_membership.rs" if mutation in {"HC156", "HC157", "HC158"} else "state/storage_transactions.rs"
    assert hook_owners == {implementation_path}
    if mutation == "HC155":
        source_files = (
            "state/storage_transactions/block/capture.rs",
            "state/storage_transactions/block/detached_publication.rs",
        )
    elif mutation in {"HC156", "HC157", "HC158"}:
        source_files = ("state/authority_registry/complete/transaction_membership_tests.rs",)
    else:
        source_files = ("state/storage_transactions/authority/tests.rs",)
    for name, path in zip(names, source_files, strict=True):
        assert "fn " + name.rsplit("::", 1)[-1] + "(" in (source / path).read_text()
    implementation = (source / implementation_path).read_text()
    assert 'all(test, sumeragi_core_mutation = "' + mutation + '")' in implementation
    row = re.search(r"^\| " + mutation + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert row is not None
    assert all(name.rsplit("::", 1)[-1] in row.group() for name in names)



def test_completed_native_amx_proof_has_original_graph_retry_mutation():
    name = "persisted_amx_completed_proof_retains_exact_graph_through_final_namespace_refusal"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC159"]
    assert rule.tests == ("sumeragi::amx::proof_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC159", core=True)
    assert not gate.has_switch("HC159")
    assert not gate.has_switch("HC159", model=True)
    assert not gate.has_switch("HC159", daemon=True)
    implementation = (ROOT / "crates/iroha_core/src/query/native_receipts/amx_read.rs").read_text()
    assert "portable: Option<Option<AllocatedAmxRecordProofV1>>" in implementation
    assert 'all(test, sumeragi_core_mutation = "HC159")' in implementation
    assert "if namespace.is_err()" in implementation
    assert implementation.index("namespace?;") < implementation.index('.take()\n            .ok_or(Error::Source("completed portable proof is not retained"))')
    control = (ROOT / "crates/iroha_core/src/sumeragi/amx/proof_tests.rs").read_text()
    assert "fn " + name + "(" in control
    assert "NativeContextArchiveError::Io" in control
    assert "crate::test_allocations::allocations_during" in control
    assert "norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX)" in control
    assert "completed proof fields must refund only after their last owner" in control
    assert "fs::rename(&self.retained, &self.original)" in control



def test_pending_penalty_physical_key_refusal_has_exact_original_owner_and_control():
    name = "pending_penalty_peer_key_allocator_refusal_preserves_original_source_and_retries"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC160"]
    assert rule.tests == ("sumeragi::penalties::tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC160", core=True)
    assert not gate.has_switch("HC160")
    assert not gate.has_switch("HC160", model=True)
    assert not gate.has_switch("HC160", daemon=True)
    source = (ROOT / "crates/iroha_core/src/sumeragi/penalties.rs").read_text()
    implementation = source.split("    fn parent_snapshot(", 1)[1].split("    fn ", 1)[0]
    assert "offender.peer_id.clone()" not in implementation
    assert ".try_clone_from_charge(budget, charge)" in implementation
    assert 'all(test, sumeragi_core_mutation = "HC160")' in implementation
    assert "requested_bytes: layout.size()" in implementation
    assert "PeerId::new(peer_key)" in implementation
    assert "unsafe { owned.into_allocation_parts() }" in implementation
    assert "fn " + name + "(" in source
    control = source.split("    fn " + name + "() {", 1)[1].split("    #[test]", 1)[0]
    assert "crate::test_allocations::refuse_one_layout_during(layout" in control
    assert "EvidencePreparationError::Allocator { requested_bytes }" in control
    assert "charge.belongs_to(budget)" in control
    assert "charge.layout(), layout" in control
    assert "last-owner drop refunds actual pending fields" in control
    assert "original_pointer" in control

# These families belong to actual SDK/Deploy unit-test compilations. The production
# registry/feature hooks below never inject a cfg into Core or a dependency.
MANAGED_BOOTSTRAP_OWNERS = (
    ("sdk", "iroha", "SDK", "sumeragi_sdk_mutation", "SUMERAGI_SDK_MUTATION"),
    ("deploy", "iroha_deploy", "DEP", "sumeragi_deploy_mutation", "SUMERAGI_DEPLOY_MUTATION"),
)


UNIT_TEST_MUTATION_OWNERS = MANAGED_BOOTSTRAP_OWNERS + (
    ("torii", "iroha_torii", "TOR", "sumeragi_torii_mutation", "SUMERAGI_TORII_MUTATION"),
    ("norito", "norito", "NC", "sumeragi_norito_mutation", "SUMERAGI_NORITO_MUTATION"),
)


def test_managed_bootstrap_owned_registry_has_real_hooks_and_original_named_controls():
    expected = {
        "sdk": {"SDK1": "public_norito_reads_refuse_missing_foreign_media_and_elapsed_requests"},
        "deploy": {
            "DEP1": "managed_amx_sources_refuse_partial_removed_and_substituted_custody_without_http_repair",
            "DEP2": "managed_amx_sources_bind_original_file_identity_and_exact_capsule_inventory",
            "DEP3": "managed_amx_sources_recheck_release_after_retained_authentication_without_refetch",
            "DEP4": "managed_amx_sources_refuse_wrong_parent_height_and_expired_reads_before_publication",
            "DEP5": "managed_amx_sources_reopen_refuses_identical_g1_h2_replacement_without_http_repair",
            "DEP6": "original_amx_administrator_child_fees_time_and_checkpoint_survive_reopen_and_refuse_substitution",
            "DEP7": "private_root_preparation_executes_signed_genesis_and_retains_owner_on_reopen",
        },
    }
    for owner, package, _, cfg, environment in MANAGED_BOOTSTRAP_OWNERS:
        source = ROOT / "crates" / package
        table = getattr(gate, owner.upper() + "_MUTATIONS")
        indexed = gate.index_mutations(table)
        assert {identifier: rule.tests[0].rsplit("::", 1)[-1] for identifier, rule in indexed.items()} == expected[owner]
        texts = "\n".join(path.read_text() for path in (source / "src").rglob("*.rs"))
        assert set(re.findall(rf'{cfg}\s*=\s*"([^"]+)"', texts)) == set(indexed)
        for identifier, rule in indexed.items():
            assert rule.tests and rule.scenarios == ()
            assert gate.has_switch(identifier, **{owner: True})
            for selector in rule.tests:
                assert f'fn {selector.rsplit("::", 1)[-1]}(' in texts
            assert f'all(test, {cfg} = "{identifier}")' in texts
            assert not gate.has_switch(identifier, **{"deploy" if owner == "sdk" else "sdk": True})
        baseline_names = {selector.rsplit("::", 1)[-1] for rule in table for selector in rule.tests}
        assert baseline_names == set(expected[owner].values()) | (
            {"public_norito_reads_select_only_fixed_media_and_retain_original_public_policies"}
            if owner == "sdk" else {
                "managed_amx_sources_keep_original_g1_h2_across_advanced_checkpoint_and_reopen",
                "managed_amx_sources_feed_real_private_staging_and_exact_retained_generation",
                "managed_amx_sources_reopen_preserves_original_native_pair_and_directory_without_new_reads",
                "managed_amx_sources_refuse_incomplete_staging_without_refetch_or_new_deadline",
            }
        )
        manifest = (source / "Cargo.toml").read_text()
        assert "mutation-testing = []" in manifest
        assert "/mutation-testing" not in manifest
        build = (source / "build.rs").read_text()
        declared_ids = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
        assert declared_ids is not None
        assert set(re.findall(r'"([A-Z]+[0-9]+)"', declared_ids.group(1))) == set(indexed)
        assert f'const ENV: &str = "{environment}";' in build
        assert f'const CFG: &str = "{cfg}";' in build
        assert 'CARGO_ENCODED_RUSTFLAGS' in build and '!rustflags.contains(CFG)' in build
        assert 'CARGO_FEATURE_MUTATION_TESTING' in build
        assert 'IDS.contains(&id.as_str())' in build and 'mentions(Path::new("src"), &needle)' in build
        guard = (source / "src" / f"{owner}_mutation_guard.rs").read_text()
        assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
        assert "mutation-testing is test-only" in guard and "compile_error!" in guard
        assert f'mod {owner}_mutation_guard;' in (source / "src/lib.rs").read_text()


@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
@pytest.mark.parametrize("selected", [False, True])
def test_managed_bootstrap_cargo_preserves_exact_owner_profile_caps_and_isolates_all_selectors(
    monkeypatch, tmp_path, owner, package, prefix, cfg, environment, selected
):
    identifier = prefix + "1" if selected else None
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 900
            return "original isolated native output", None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    variables = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION",
                 "SUMERAGI_MODEL_MUTATION", "SUMERAGI_SDK_MUTATION", "SUMERAGI_DEPLOY_MUTATION",
                 "SUMERAGI_TORII_MUTATION", "SUMERAGI_NORITO_MUTATION")
    for variable in variables:
        monkeypatch.setenv(variable, "foreign-inherited-rule")
    for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"):
        monkeypatch.setenv(variable, "7")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(**{owner: True})
    code, output, elapsed = gate.cargo_test(args, tmp_path, identifier, ["original::named"], None, 900, tmp_path / "run.log")
    assert code == 0 and output == "original isolated native output" and elapsed >= 0
    assert captured["command"] == ["cargo", "test", "--locked", "-p", package, "--profile", "test",
                                   "--features", "mutation-testing", "--lib", "--", "original::named"]
    options = captured["options"]
    assert options["cwd"] == ROOT and options["start_new_session"] is True
    assert options["env"]["CARGO_TARGET_DIR"] == str(tmp_path)
    for variable in variables:
        assert options["env"].get(variable) == (identifier if variable == environment else None)
    assert all(variable not in options["env"] for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"))
    assert cfg not in " ".join(captured["command"])


@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
@pytest.mark.parametrize("status,verdict", [("fail", "killed_by_test"), ("pass", "survived"),
    ("execution-error", "error"), ("build-error", "error"), ("missing-test", "error"), ("timeout", "error")])
def test_managed_bootstrap_kill_requires_actual_complete_named_failure(
    monkeypatch, tmp_path, owner, package, prefix, cfg, environment, status, verdict
):
    observed = []
    def switch(identifier, **owners):
        observed.append(owners)
        return owners == {owner: True} and identifier == prefix + "1"
    monkeypatch.setattr(gate, "has_switch", switch)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    calls = []
    def named(*args):
        calls.append(args)
        return gate.Step(status=status, failed=list(args[3]) if status == "fail" else [])
    monkeypatch.setattr(gate, "run_step", named)
    args = SimpleNamespace(**{owner: True}, target_dir=tmp_path, timeout_test=900, fast=False)
    rule = getattr(gate, owner.upper() + "_MUTATIONS")[0]
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == verdict and result["id"] == prefix + "1"
    assert observed == [{owner: True}] and len(calls) == 1
    assert calls[0][2:6] == (rule.id, rule.tests, None, 900)
    assert "scenario" not in result


@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
@pytest.mark.parametrize("baseline,expected", [("pass", 0), ("fail", 1), ("error", 1)])
def test_managed_bootstrap_main_keeps_baseline_all_rules_default_caps_and_truthful_report(
    monkeypatch, tmp_path, owner, package, prefix, cfg, environment, baseline, expected
):
    target = tmp_path / owner
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--" + owner, "--jobs", "1", "--strict", "--target-dir", str(target)])
    calls = []
    def positive(args, directory, rules):
        calls.append((args, directory, tuple(rule.id for rule in rules)))
        return {"id": "baseline", "verdict": baseline}
    monkeypatch.setattr(gate, "evaluate_baseline", positive)
    monkeypatch.setattr(gate, "evaluate", lambda args, directory, rule: {"id": rule.id, "verdict": "killed_by_test"})
    assert gate.main() == expected
    assert len(calls) == 1
    args, directory, identifiers = calls[0]
    assert identifiers == tuple(rule.id for rule in getattr(gate, owner.upper() + "_MUTATIONS"))
    assert directory == target / "job0"
    assert (args.timeout_build, args.timeout_test, args.timeout_scenario, args.seeds) == (1200, 900, 3600, 200)
    assert not args.fast and not args.skip_baseline
    report = json.loads((target / "report.json").read_text())
    assert report["package"] == package and report["profile"] == "test"
    assert report["summary"]["baseline"] == baseline
    assert [row["id"] for row in report["mutations"]] == list(identifiers)
    assert report["summary"]["mutations"] == len(identifiers)


@pytest.mark.parametrize("arguments", [
    ["--torii", "--sdk"], ["--torii", "--deploy"], ["--torii", "--core"],
    ["--torii", "--daemon"], ["--torii", "--model"],
    ["--torii", "--core-profile", "test"], ["--torii", "--strict", "--skip-baseline"],
    ["--torii", "--only", "HC184"], ["--core", "--only", "TOR1"],
    ["--torii", "--only", "TOR1,TOR1"], ["--torii", "--only", ","],
    ["--sdk", "--deploy"], ["--sdk", "--core"], ["--sdk", "--model"], ["--sdk", "--daemon"],
    ["--deploy", "--core"], ["--deploy", "--model"], ["--deploy", "--daemon"],
    ["--sdk", "--core-profile", "test"], ["--deploy", "--core-profile", "test"],
    ["--sdk", "--only", "DEP1"], ["--deploy", "--only", "SDK1"],
    ["--sdk", "--only", "DEP5"], ["--core", "--only", "DEP5"],
    ["--core", "--only", "DEP1"], ["--model", "--only", "SDK1"], ["--only", "SDK1"],
    ["--sdk", "--strict", "--skip-baseline"], ["--deploy", "--strict", "--skip-baseline"],
])
def test_managed_bootstrap_cli_refuses_cross_owner_and_skipped_baseline_before_native_launch(monkeypatch, tmp_path, arguments):
    target = tmp_path / "refused"
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments, "--target-dir", str(target)])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2 and not target.exists()


@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
def test_managed_bootstrap_nightly_owns_all_rules_and_ordinary_feature_policy_remains_closed(owner, package, prefix, cfg, environment):
    source = (ROOT / ".github/workflows/nightly_sumeragi.yml").read_text()
    match = re.search(rf"(?ms)^  {owner}_mutation_gate:\n(.*?)(?=^  [a-z_]+:|\Z)", source)
    assert match is not None
    job = match.group(1)
    assert f"run: python3 scripts/sumeragi_mutation_gate.py --{owner} --jobs 1 --strict\n" in job
    assert not any(argument in job for argument in ("--only", "--skip-baseline", "--fast", "--timeout-build", "--timeout-test", "--timeout-scenario"))
    assert f"target/sumeragi-{owner}-mutants/report.json" in job
    assert f"target/sumeragi-{owner}-mutants/logs" in job
    assert 'CARGO_BUILD_JOBS: "2"' in job and "if: always()" in job
    require_pinned_sumeragi_toolchain(job)
    ci_spec = importlib.util.spec_from_file_location("managed_bootstrap_rust_ci", ROOT / "scripts/rust_ci.py")
    module = importlib.util.module_from_spec(ci_spec)
    sys.modules[ci_spec.name] = module
    ci_spec.loader.exec_module(module)
    assert module.MUTATION_FEATURE_OWNERS == {"iroha_data_model", "iroha_core", "irohad_lib", "iroha_sumeragi", "iroha", "iroha_deploy", "iroha_torii", "norito"}


# Genuine standalone compiler guard checks are part of the subsequent owner gate review.
# They are intentionally not executed by an ignored source-only preparation.
@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
@pytest.mark.parametrize("test_build,mutation_feature,accepted", [
    (False, False, True), (True, False, True), (True, True, True), (False, True, False),
])
def test_managed_bootstrap_compiler_guard_rejects_mutation_feature_in_dependencies(tmp_path, owner, package, prefix, cfg, environment, test_build, mutation_feature, accepted):
    guard = ROOT / "crates" / package / "src" / f"{owner}_mutation_guard.rs"
    command = ["rustc", "--edition=2024", "--crate-type=lib", "--emit=metadata", str(guard), "-o", str(tmp_path / "guard.rmeta")]
    if test_build:
        command += ["--cfg", "test"]
    if mutation_feature:
        command += ["--cfg", 'feature="mutation-testing"']
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    if not accepted:
        assert "mutation-testing is test-only" in result.stderr


@pytest.fixture(scope="session", params=UNIT_TEST_MUTATION_OWNERS)
def managed_bootstrap_compiler_build_script(request, tmp_path_factory):
    owner, package, prefix, cfg, environment = request.param
    executable = tmp_path_factory.mktemp(owner + "-build-guard") / "build-script"
    result = subprocess.run(["rustc", "--edition=2024", str(ROOT / "crates" / package / "build.rs"), "-o", str(executable)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return request.param, executable


@pytest.mark.parametrize("feature,selection,flags,accepted,emitted", [
    (False, None, "", True, False), (False, "first", "", True, False),
    (False, "unknown", "", True, False), (True, None, "", True, False),
    (True, "", "", True, False), (True, "first", "", True, True),
    (True, "unknown", "", False, False), (False, None, "injected", False, False),
    (True, "first", "injected", False, False),
    (False, "last", "", True, False), (True, "last", "", True, True),
])
def test_managed_bootstrap_compiler_build_script_selects_only_registered_owning_cfg(managed_bootstrap_compiler_build_script, feature, selection, flags, accepted, emitted):
    (owner, package, prefix, cfg, environment), executable = managed_bootstrap_compiler_build_script
    build = (ROOT / "crates" / package / "build.rs").read_text()
    ids = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert ids is not None
    declared = re.findall(r'"([A-Z]+[0-9]+)"', ids.group(1))
    identifier = prefix + "1" if selection == "first" else declared[-1] if selection == "last" else selection
    variables = dict(os.environ)
    variables.pop("CARGO_FEATURE_MUTATION_TESTING", None)
    variables.pop(environment, None)
    variables["CARGO_ENCODED_RUSTFLAGS"] = f'--cfg\x1f{cfg}="{prefix}1"' if flags else ""
    if feature:
        variables["CARGO_FEATURE_MUTATION_TESTING"] = "1"
    if identifier is not None:
        variables[environment] = identifier
    result = subprocess.run([str(executable)], cwd=ROOT / "crates" / package, env=variables, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == accepted, result.stderr
    assert (f'cargo:rustc-cfg={cfg}="{identifier}"' in result.stdout) == emitted
    values = ", ".join(f'"{identifier}"' for identifier in declared)
    assert f'cargo:rustc-check-cfg=cfg({cfg}, values({values}))' in result.stdout

@pytest.mark.parametrize("owner,package,prefix,cfg,environment", UNIT_TEST_MUTATION_OWNERS)
@pytest.mark.parametrize("forwarded", [False, True])
def test_managed_bootstrap_ordinary_feature_matrix_excludes_only_the_owned_selector(tmp_path, owner, package, prefix, cfg, environment, forwarded):
    spec = importlib.util.spec_from_file_location("managed_bootstrap_feature_matrix", ROOT / "scripts/rust_ci.py")
    ci = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ci
    spec.loader.exec_module(ci)
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["owner"]\n')
    directory = tmp_path / "owner"
    directory.mkdir()
    (directory / "Cargo.toml").write_text(
        f'[package]\nname = "{package}"\nversion = "1.0.0"\n'
        '[features]\nmutation-testing = []\n'
        'default = ["production"]\nproduction = []\ntest-fixtures = []\n'
        + ('forbidden = ["dependency/mutation-testing"]\n' if forwarded else '')
    )
    if forwarded:
        with pytest.raises(ci.ClassificationError, match="forwards a test-only mutation"):
            ci.workspace_check_features(tmp_path)
    else:
        assert ci.workspace_check_features(tmp_path) == {package: ("default", "production", "test-fixtures")}


@pytest.mark.parametrize("owners", [
    {"torii": True, "sdk": True}, {"torii": True, "deploy": True},
    {"torii": True, "core": True}, {"torii": True, "daemon": True}, {"torii": True, "model": True},
    {"sdk": True, "core": True}, {"sdk": True, "model": True},
    {"sdk": True, "daemon": True}, {"sdk": True, "deploy": True},
    {"deploy": True, "core": True}, {"deploy": True, "model": True},
    {"deploy": True, "daemon": True},
])
def test_managed_bootstrap_source_selector_refuses_more_than_one_actual_owner(owners):
    with pytest.raises(ValueError, match="exactly one implementation owner"):
        gate.has_switch("SDK1", **owners)


@pytest.mark.parametrize("mutation,name,core", [
    ('DM8', 'sumeragi_amx::tests::sumeragi_amx_expiry_refusal_and_unwind_preserve_original_pending_graph', False),
    ('DM9', 'sumeragi_amx::tests::sumeragi_amx_encoding_keeps_exact_physical_allocator_refusal', False),
    ('HC161', 'sumeragi::amx::tests::amx_deadline_record_refusal_keeps_original_pending_state_and_typed_retry', True),
    ("HC162", "block::valid::tests::amx_deadline_finalizer_preserves_exact_local_refusal_without_rejection", True),
])
def test_amx_deadline_retry_mutations_have_exact_owner_and_native_control(mutation, name, core):
    rules = gate.CORE_MUTATIONS if core else gate.MODEL_MUTATIONS
    rule = gate.index_mutations(rules)[mutation]
    assert rule.tests == (name,)
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=core, model=not core)
    assert not gate.has_switch(mutation, core=not core, model=core)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, daemon=True)
    owner = "iroha_core" if core else "iroha_data_model"
    source = "\n".join(p.read_text() for p in (ROOT / "crates" / owner / "src").rglob("*.rs"))
    assert "fn " + name.rsplit("::", 1)[-1] + "(" in source
    rows = re.findall(r"^\| " + mutation + r" \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1
    assert name.rsplit("::", 1)[-1] in rows[0]


def test_native_amx_retry_visibility_is_separate_from_original_byte_custody():
    """The owning named mutation restores only stale-publication coupling."""
    mutation = gate.index_mutations(gate.CORE_MUTATIONS)["HC167"]
    assert mutation.tests == (
        "sumeragi::executor::amx_retry_tests::original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry",
    )
    assert not mutation.scenarios
    assert gate.has_switch("HC167", core=True)
    assert not gate.has_switch("HC167")
    assert not gate.has_switch("HC167", model=True)
    assert not gate.has_switch("HC167", daemon=True)
    retry = (ROOT / "crates/iroha_core/src/sumeragi/amx/native/retry.rs").read_text()
    executor = (ROOT / "crates/iroha_core/src/sumeragi/executor.rs").read_text()
    validator = (ROOT / "crates/iroha_core/src/block.rs").read_text()
    control = (ROOT / "crates/iroha_core/src/sumeragi/executor_amx_retry_tests.rs").read_text()
    specification = (ROOT / "specs/sumeragi.md").read_text()
    assert re.search(r'#\[cfg\(all\(test,\s*sumeragi_core_mutation\s*=\s*"HC167"\)\)\]\s*original_publication:', retry)
    assert 'fn matches_original_publication' in retry
    assert 'bank.matches_original_publication(state.state_view_generation())' in executor
    assert 'parent_is_current' not in retry + validator
    assert re.search(r'fn matches_original\([^)]*\) -> bool', retry, re.S)
    signature = re.search(r'fn matches_original\(([^)]*)\) -> bool', retry, re.S).group(1)
    assert 'generation' not in signature
    assert 'with_held_view_publication_for_reader_test' in control
    assert 'generation.checked_add(2)' in control
    assert 'fn original_paid_amx_worker_retry_reauthenticates_changed_native_parent(' in control
    assert 'fresh native successor authentication must reject a changed committed parent result' in control
    assert 'match Self::native_header_source(&block, state, native_header, native_payload)' in validator
    assert 'source_generation: source.generation' in validator
    assert '.validate_native_pristine_control_owner(' in validator
    assert '| HC167 |' in specification
    assert 'original pool and completed parent generation' not in specification


# These controls exercise the real parser/evaluator with mocked Cargo children.
# They establish script classification only, never a native mutation kill.
def exact_control_output(rows):
    """Construct a complete serial libtest response for exact acceptance controls."""
    passed = sum(status == "ok" for _, status in rows)
    failed = sum(status == "FAILED" for _, status in rows)
    ignored = sum(status == "ignored" for _, status in rows)
    verdict = "FAILED" if failed else "ok"
    output = (f"running {len(rows)} tests\n"
              + "".join(f"test {name} ... {status}\n" for name, status in rows)
              + f"test result: {verdict}. {passed} passed; {failed} failed; {ignored} ignored; "
              "0 measured; 37 filtered out; finished in 0.01s\n")
    return (101 if failed else 0), output


def exact_control_evaluate(monkeypatch, tmp_path, filters, rows, scenarios=()):
    """Keep actual discovery, run_step and evaluate, mocking only Cargo and build."""
    mutation = gate.m("EXACT_CONTROL_FIXTURE", "parser classification", filters, scenarios)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    args = SimpleNamespace(target_dir=tmp_path, timeout_test=5, fast=True)
    return gate.evaluate(args, tmp_path, mutation)


@pytest.mark.parametrize("selector", ["named", "tests::named"])
@pytest.mark.parametrize("replacement", ["tests::named_unrelated_replacement", "foreign::tests::named"])
def test_exact_control_missing_refuses_before_runtime_even_if_substring_replacement_fails(
    monkeypatch, tmp_path, selector, replacement
):
    if selector == "named" and replacement == "foreign::tests::named":
        # A real exact leaf in a different module is deliberately a named match.
        replacement += "_extra"
    calls = []
    def cargo_test(*args):
        calls.append(args[3])
        if "--list" in args[3]:
            return 0, f"{replacement}: test\n\n1 test, 0 benchmarks\n", 0.0
        return exact_control_output([(replacement, "FAILED")]) + (1.0,)
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(target_dir=tmp_path, timeout_test=5, fast=True),
                           tmp_path, gate.m("EXACT_CONTROL_FIXTURE", "fixture", [selector]))
    assert result["verdict"] == "error", result
    assert result["reason"] == "named tests: missing-test"
    assert result["named"]["selected"] == [replacement]
    assert len(calls) == 1 and "--list" in calls[0]


@pytest.mark.parametrize("selector", ["named", "tests::named"])
def test_exact_control_pass_cannot_borrow_an_extra_failure_for_named_kill(
    monkeypatch, tmp_path, selector
):
    rows = [("tests::named", "ok"), ("tests::named_unrelated_replacement", "FAILED")]
    result = exact_control_evaluate(monkeypatch, tmp_path, [selector], rows)
    assert result["verdict"] == "error", result
    assert result["reason"] == "named tests: only additional substring-selected tests failed"
    assert result["named"]["status"] == "fail"
    assert result["named"]["failed"] == [rows[1][0]]
    assert result["named"]["required_failed"] == []
    assert result["named"]["ran"] == result["named"]["selected"] == [name for name, _ in rows]


@pytest.mark.parametrize("selector", ["named", "tests::named"])
@pytest.mark.parametrize("extra_status", ["ok", "FAILED"])
def test_exact_control_failure_kills_without_dropping_selected_extra_results(
    monkeypatch, tmp_path, selector, extra_status
):
    rows = [("tests::named", "FAILED"), ("tests::named_extra", extra_status)]
    result = exact_control_evaluate(monkeypatch, tmp_path, [selector], rows)
    assert result["verdict"] == "killed_by_test", result
    assert result["named"]["required_failed"] == ["tests::named"]
    assert result["named"]["failed"] == [name for name, status in rows if status == "FAILED"]
    assert result["named"]["ran"] == result["named"]["selected"] == [name for name, _ in rows]


@pytest.mark.parametrize("selector", ["named", "tests::named"])
def test_exact_control_ignored_cannot_be_replaced_by_extra_failure(monkeypatch, tmp_path, selector):
    rows = [("tests::named", "ignored"), ("tests::named_extra", "FAILED")]
    result = exact_control_evaluate(monkeypatch, tmp_path, [selector], rows)
    assert result["verdict"] == "error", result
    assert result["reason"] == "named tests: missing-test"
    assert result["named"]["failed"] == ["tests::named_extra"]
    assert result["named"]["ran"] == ["tests::named_extra"]


@pytest.mark.parametrize("second_status,expected", [("ok", "killed_by_test"), ("FAILED", "killed_by_test"),
                                                       ("ignored", "error")])
def test_exact_control_multi_declaration_requires_each_original_control(
    monkeypatch, tmp_path, second_status, expected
):
    rows = [("tests::named", "FAILED"), ("tests::named_extra", "FAILED"),
            ("tests::second", second_status)]
    result = exact_control_evaluate(monkeypatch, tmp_path, ["tests::named", "tests::second"], rows)
    assert result["verdict"] == expected, result
    assert result["named"]["failed"] == [name for name, status in rows if status == "FAILED"]
    if expected == "killed_by_test":
        assert result["named"]["required_failed"] == [name for name, status in rows
                                                      if status == "FAILED" and name != "tests::named_extra"]
    else:
        assert result["reason"] == "named tests: missing-test"


@pytest.mark.parametrize("second_status,expected", [("ok", "killed_by_test"), ("FAILED", "killed_by_test"),
                                                       ("ignored", "error")])
def test_exact_control_leaf_duplicates_keep_each_exact_module_owner(monkeypatch, tmp_path, second_status, expected):
    rows = [("machine::tests::named", "FAILED"), ("machine::tests::named_extra", "FAILED"),
            ("pacemaker::tests::named", second_status)]
    result = exact_control_evaluate(monkeypatch, tmp_path, ["named"], rows)
    assert result["verdict"] == expected, result
    if expected == "killed_by_test":
        assert result["named"]["required_failed"] == [name for name, status in rows
                                                      if status == "FAILED" and name.rsplit("::", 1)[-1] == "named"]
        assert result["named"]["ran"] == result["named"]["selected"]
    else:
        assert result["reason"] == "named tests: missing-test"


@pytest.mark.parametrize("named_status", ["ok", "FAILED"])
@pytest.mark.parametrize("scenario_status", ["ok", "FAILED", "ignored", "missing"])
def test_exact_control_scenario_extras_cannot_replace_declared_failure(
    monkeypatch, tmp_path, named_status, scenario_status
):
    scenario_id = next(iter(gate.SCENARIOS))
    scenario = gate.SCENARIOS[scenario_id]
    mutation = gate.m("EXACT_CONTROL_FIXTURE", "parser fixture", ["tests::named"], [scenario_id])
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    calls = []
    def cargo_test(*args):
        selected_scenario = args[3][0] == scenario
        rows = ([(scenario + "_extra", "FAILED")] if scenario_status == "missing" else
                [(scenario, scenario_status), (scenario + "_extra", "FAILED")]) if selected_scenario else [("tests::named", named_status)]
        calls.append((args[3][0], "--list" in args[3]))
        if "--list" in args[3]:
            return 0, "".join(name + ": test\n" for name, _ in rows) + f"\n{len(rows)} tests, 0 benchmarks\n", 0.0
        return exact_control_output(rows) + (1.0,)
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    args = SimpleNamespace(target_dir=tmp_path, timeout_test=5, timeout_scenario=5, seeds=200, fast=False)
    result = gate.evaluate(args, tmp_path, mutation)
    expected = ("killed_by_test" if named_status == "FAILED" else "killed_by_scenario_only") if scenario_status == "FAILED" else "error"
    assert result["verdict"] == expected, result
    if scenario_status == "ok":
        assert result["reason"] == "scenarios: only additional substring-selected tests failed"
        assert result["scenario"]["required_failed"] == []
    elif scenario_status in ("ignored", "missing"):
        assert result["reason"] == "scenarios: missing-test"
    else:
        assert result["scenario"]["required_failed"] == [scenario]
        assert result["scenario"]["failed"] == [scenario, scenario + "_extra"]
    if scenario_status == "missing":
        assert calls[-1] == (scenario, True), "absent exact scenario must stop before runtime"


def test_exact_control_later_extra_scenario_failure_cannot_hide_behind_earlier_control_kill(monkeypatch, tmp_path):
    scenarios = list(gate.SCENARIOS)[:2]
    mutation = gate.m("EXACT_CONTROL_FIXTURE", "parser fixture", ["tests::named"], scenarios)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    def cargo_test(*args):
        name = args[3][0]
        rows = [(name, "ok")] if name == "tests::named" else [(name, "FAILED")] if name == gate.SCENARIOS[scenarios[0]] else [(name, "ok"), (name + "_extra", "FAILED")]
        if "--list" in args[3]:
            return 0, "".join(n + ": test\n" for n, _ in rows) + f"\n{len(rows)} tests, 0 benchmarks\n", 0.0
        return exact_control_output(rows) + (1.0,)
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    args = SimpleNamespace(target_dir=tmp_path, timeout_test=5, timeout_scenario=5, seeds=200, fast=False)
    result = gate.evaluate(args, tmp_path, mutation)
    assert result["verdict"] == "error", result
    assert result["reason"] == "scenarios: only additional substring-selected tests failed"
    assert [step["required_failed"] for step in result["scenario"]["steps"]] == [[gate.SCENARIOS[scenarios[0]]], []]


@pytest.mark.parametrize("mutation,name,owner", [
    ("HC172", "original_musubi_group_equal_same_predecessor_revision_substitution_retains_original_pair",
     "state/publication/retained_musubi_group.rs"),
    ("HC173", "original_musubi_group_revision_reader_refusal_retains_completed_tables_and_exact_scope",
     "state/block_field/retained_read.rs"),
])
def test_retained_cell_revision_mutations_bind_actual_core_pair_and_exact_control(mutation, name, owner):
    prefix = "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_musubi_group_tests::"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == (prefix + name,)
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)
    assert not gate.has_switch(mutation, daemon=True)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mutation + '"', path.read_text())}
    assert owners == {owner}
    implementation = (source / owner).read_text()
    assert 'all(test, sumeragi_core_mutation = "' + mutation + '")' in implementation
    controls = (source / "state/publication/retained_musubi_group/tests.rs").read_text()
    assert "fn " + name + "(" in controls
    assert "allocations_during" in controls
    assert "std::mem::replace" in controls
    assert "scope_belongs_to(&foreign)" in controls
    row = re.search(r"^\| " + mutation + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert row is not None and name in row.group()
    if mutation == "HC172":
        assert "revision.retained_read_matches_source(source)" in implementation
        assert "revision: Option<mv::cell::FrozenDetachedRead<MusubiResolverIndexRevisionV1>>" in implementation
    else:
        cell = implementation.split("impl<V: Value", 1)[1]
        assert "original.matches_read(source)" in cell
        assert "original.try_into_detached()" in cell
        assert "self.phase = Some(Phase::Reading(original))" in cell
        assert "Err(RetainedReadPhaseError::ReadersRetained)" in cell


@pytest.mark.parametrize("mutation,name", [
    ("HC174", "retained_predecessor_ordered_merge_matches_exact_original_before_rows_in_both_modes"),
    ("HC175", "retained_predecessor_later_work_refusal_preserves_descriptor_heads_frontiers_and_pool"),
])
def test_retained_predecessor_mutations_bind_original_descriptor_kernel_and_exact_control(mutation, name):
    prefix = "state::publication::retained_rows::predecessor::tests::"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == (prefix + name,)
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mutation, **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mutation + '"', path.read_text())}
    owner = "state/publication/retained_rows/predecessor.rs"
    assert owners == {owner}
    implementation = (source / owner).read_text()
    assert 'all(test, sumeragi_core_mutation = "' + mutation + '")' in implementation
    controls = (source / "state/publication/retained_rows/predecessor_tests.rs").read_text()
    assert "fn " + name + "(" in controls
    assert '#[path = "predecessor_tests.rs"]' in implementation
    assert "allocations_during" in controls
    assert "resolve_amount" in controls
    assert "original preimage value allocation" in controls
    assert "same completed descriptor frontiers survive refusal" in controls
    row = re.search(r"^\| " + mutation + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert row is not None and name in row.group()
    assert "admit(work, required, limit)" in implementation
    assert "exact_resolve(amount, head.resolve)" in implementation


def test_retained_predecessor_closed_keys_and_actual_group_consumer_keep_fallible_work():
    source = ROOT / "crates/iroha_core/src/state/publication"
    group = (source / "retained_musubi_group.rs").read_text()
    kernel = (source / "retained_rows/predecessor.rs").read_text()
    keys = (source / "retained_rows/key_work.rs").read_text()
    assert "advance_original_musubi_group_predecessor_read" in group
    assert "self.check_original_musubi_group_read()?" in group
    assert "self.scope.allocation_budget(),&mutself.work,limit" in re.sub(r"\s+", "", group)
    assert "current_consumed" in kernel and "undo_consumed" in kernel
    assert "ChargedBuffer::new(capacity, budget)" in kernel
    assert "current_head" in kernel and "undo_head" in kernel
    assert "comparison_units(work, limit)?" in kernel
    assert "key.cmp(old_key)" in kernel
    assert "key.clone()" not in kernel and "value.clone()" not in kernel
    assert "StorageReadOnly" not in kernel
    assert "MusubiReleaseIdV1" in keys and "self.version.prerelease.len()" in keys
    assert "mod sealed" in keys
    controls = (source / "retained_musubi_group/tests.rs").read_text()
    assert "fn original_musubi_group_retained_predecessor_descriptors_use_exact_pair_and_scope(" in controls
    assert "retired index grants no old row authority" in controls


def test_retained_semantic_materializer_mutation_binds_original_rows_and_three_real_producers():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC176"]
    name = "retained_semantic_original_rows_and_cursor_survive_later_refusal"
    assert rule.tests == ("state::authority_registry::leaf::paired::retained_semantic::tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC176", core=True)
    assert not gate.has_switch("HC176")
    assert not gate.has_switch("HC176", model=True)
    assert not gate.has_switch("HC176", daemon=True)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC176"', path.read_text())}
    # The mutation wrapper and its private physical-row retirement kernel.
    assert owners == {"state/authority_registry/leaf/paired/retained_semantic.rs",
                      "state/authority_registry/leaf/paired/staging.rs"}
    kernel = (source / "state/authority_registry/leaf/paired/retained_semantic.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC176")' in kernel
    assert "self.builder.encoded.discard_for_mutation()" in kernel
    assert "scope: scope.cloned()" in kernel
    assert "setup_registry_work(key_literal, value_literal)" in kernel
    assert kernel.index("admit_work(", kernel.index("fn from_source(")) < kernel.index("RetainedSemanticTable::new(", kernel.index("fn from_source("))
    assert "self.pending = self.rows.next()" in kernel
    assert "self.pending_row.take()" in re.sub(r"\s+", "", kernel)
    assert "self.ordered=Some(NoritoKeyDigestRangeTreeV1::from_sorted_digests" in re.sub(r"\s+", "", kernel)
    controls = (source / "state/authority_registry/leaf/paired/retained_semantic_tests.rs").read_text()
    assert "fn " + name + "(" in controls
    for obligation in ["first_key", "polls.get()", "original_value", "budget.reserved_bytes()", "allocations_during"]:
        assert obligation in controls
    assert "retained_semantic_physical_lookup_refusal_and_zero_budget_retirement_keep_completed_nodes" in controls
    candidate = (source / "state/deserialize_world_musubi_capture_candidate.rs").read_text()
    once = candidate.split("fn capture_table(", 1)[1].split("/// Retain", 1)[0]
    assert once.count("RetainedSemanticRows::once(") == 3
    assert "paired_semantic_table_from_rows" not in once
    for owner in ["availability", "resolver", "directory"]:
        assert "fn retain_" + owner + "_capture" in candidate
    producer_controls = (source / "state/deserialize_world_musubi_retained_capture_tests.rs").read_text()
    assert "actual_three_validated_semantic_producers_retry_in_the_original_pool" in producer_controls
    assert "actual_retained_semantic_source_remains_the_original_snapshot_after_new_commit" in producer_controls
    row = re.search(r"^\| HC176 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert row is not None and name in row.group()


def test_retained_musubi_validation_stage_has_exact_core_owner_and_real_late_refusal_control():
    mutation = "HC177"
    name = "retained_state_successful_musubi_validation_survives_late_writer_refusal"
    prefix = "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == (prefix + name,)
    assert not rule.scenarios
    assert gate.has_switch(mutation, core=True)
    for other_owner in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mutation, **other_owner)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC177"', path.read_text())}
    assert owners == {"state/publication.rs"}
    publication = (source / "state/publication.rs").read_text()
    validators = (source / "state/world_commit.rs").read_text()
    controls = (source / "state/direct_commit_musubi_scratch_tests.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC177")' in publication
    assert "original.musubi_validated = false;" in publication
    assert publication.index("validate_prepared_policy_transition(world)") < publication.index("if !*musubi_validated")
    assert publication.index("validate_prepared_musubi_universal(") < publication.index("*musubi_validated = true;")
    assert publication.index("let current_generation =") < publication.index("if !*musubi_validated")
    compact_publication = re.sub(r"\s+", "", publication)
    assert compact_publication.index("if!*musubi_validated") < compact_publication.index("world.install_frozen_publication(")
    assert "world.try_prepare_frozen_publication()" in compact_publication
    assert "original_preparation_error" in publication
    assert "fn " + name + "(" in controls
    assert "state.world.merge_global_state_root.block()" in controls
    assert "successful Musubi validation must survive a later original writer refusal" in controls
    assert "refused_prefix[0] + 1" in controls and "refused_prefix[1] + 1" in controls
    assert "state.world.musubi_packages.block()" in controls
    assert "retained_state_validated_musubi_refuses_changed_visibility_before_retry" in controls
    assert "retained_state_validated_musubi_refuses_equal_predecessor_advance" in controls
    assert "retained_state_unchanged_musubi_skips_both_validators" in controls
    assert "nested_validation_observation_restores_original_counts_after_unwind" in validators
    original_predicates = {
        "musubi_archives", "musubi_archive_locations", "musubi_provider_bundle_attestations",
        "musubi_locations_by_pin", "musubi_locations_by_replication_order", "musubi_locations_by_provider",
        "pin_manifests", "replication_orders", "provider_owners", "musubi_archive_availability",
        "musubi_packages", "musubi_releases", "musubi_resolver_index", "musubi_public_directory",
        "musubi_resolver_index_revision",
    }
    body = validators.split("fn validate_prepared_musubi(", 1)[1].split("/// Read the completed overlay", 1)[0]
    assert set(re.findall(r"world\.(\w+)\.is_dirty\(\)", body)) == original_predicates
    assert "validate_musubi_live_projection_cut" in body
    assert "validate_musubi_universal_projection_cut" in body
    assert "ProjectionCut::Candidate" in body
    rows = re.findall(r"^\| HC177 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_partial_musubi_validation_phase_binds_original_pool_and_exact_control():
    name = "retained_state_live_musubi_success_survives_universal_capacity_refusal"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC178"]
    assert rule.tests == ("state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC178", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC178", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(root).as_posix() for p in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC178"', p.read_text())}
    assert owners == {"state/publication.rs"}
    publication = (root / "state/publication.rs").read_text()
    validators = (root / "state/world_commit.rs").read_text()
    controls = (root / "state/direct_commit_musubi_scratch_tests.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC178")' in publication
    assert "original.musubi_live_validated = false;" in publication
    assert publication.index("validate_prepared_policy_transition(world)") < publication.index("if !*musubi_live_validated")
    assert publication.index("let current_generation =") < publication.index("if !*musubi_live_validated")
    assert publication.index("validate_prepared_musubi_live(") < publication.index("*musubi_live_validated = true;") < publication.index("validate_prepared_musubi_universal(")
    assert publication.index("validate_prepared_musubi_universal(") < publication.index("*musubi_validated = true;")
    assert "world.try_prepare_frozen_publication()" in re.sub(r"\s+", "", publication)
    assert "Self::validate_prepared_musubi_live(world, execution_budget)?;" in validators
    assert "Self::validate_prepared_musubi_universal(world, execution_budget)" in validators
    assert validators.count("if Self::requires_musubi_validation(world)") == 2
    assert "fn " + name + "(" in controls
    for obligation in ["remaining - live_bytes", "universal_bytes > live_bytes", "original_reserved",
                       "successful live Musubi pass must survive original universal capacity refusal",
                       "retained_state_partial_musubi_validation_refuses_changed_visibility"]:
        assert obligation in controls
    assert "AllocationBudget::new" not in controls.split("fn " + name + "(", 1)[1]
    rows = re.findall(r"^\| HC178 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_completed_world_cut_mutation_uses_actual_worker_and_original_final_shell():
    name = "original_worker_world_cut_retains_completed_tail_after_final_control_refusal"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC179"]
    assert rule.tests == ("sumeragi::executor::publication_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC179", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC179", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(root).as_posix() for p in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC179"', p.read_text())}
    assert owners == {"state/publication.rs"}
    publication = (root / "state/publication.rs").read_text()
    cut = (root / "state/world_state_cut.rs").read_text()
    controls = (root / "sumeragi/executor_publication_tests.rs").read_text()
    compact = re.sub(r"\s+", "", publication)
    assert 'all(test,sumeragi_core_mutation="HC179")' in compact
    assert "*world_cut_pending=None;" in compact
    assert publication.index("let current_generation =") < publication.index("match world_cut_pending.take()")
    assert "world.try_prepare_frozen_publication()" in compact
    assert "budget: budget.clone()" in cut
    assert "self.budget.try_reserve" in re.sub(r"\s+", "", cut)
    assert "Err((self, error.into()))" in cut
    assert "(Self { capsule, budget }, error)" in cut
    assert cut.index("let mut reconstructed = applied.clone()") < cut.index("completion_observer::completed(&capsule)") < cut.index("let pending = PendingCutCapsule")
    assert 'if matches!(&error, CutError::Deferred(_))' in cut
    assert "fn " + name + "(" in controls
    body = controls.split("fn " + name + "(", 1)[1].split("/// Completed local cut custody", 1)[0]
    for obligation in ["executed(chain, worker)", "worker.prepare(&block, &qc)", "blocks.append(&block, &qc)",
                       "worker.commit(&block, &qc)", "completed_world_cut_identity_for_test",
                       "completed original World cut must survive final shared-control refusal",
                       "observation.release_original_blocker()", "budget.limit_bytes()", "budget.same_pool",
                       "final shell retry must not hash or reconstruct the original tail again"]:
        assert obligation in body
    assert "AllocationBudget::new" not in body and "set_limit_bytes" not in body
    assert "original_worker_completed_world_cut_refuses_changed_publication_source" in controls
    assert "with_held_view_publication_for_reader_test" in controls
    positive = (root / "state/world_state_cut_tests.rs").read_text()
    assert "completed_cut_refusal_retains_exact_tail_rows_and_original_pool_until_delivery" in positive
    assert "capsule.rows.as_slice().as_ptr(), tail" in positive
    rows = re.findall(r"^\| HC179 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_funded_offender_graph_mutation_uses_original_lane_pool_and_exact_control():
    name = "lane_verified_offender_graph_refuses_occupied_original_pool_and_retries"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC180"]
    assert rule.tests == ("sumeragi::evidence_history::lane::tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC180", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC180", **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(source).as_posix() for p in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC180"', p.read_text())}
    assert owners == {"sumeragi/evidence_history/funded_attribution.rs"}
    owner = (source / "sumeragi/evidence_history/funded_attribution.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC180")' in owner
    assert "AllocationBudget::new(budget.limit_bytes())" in owner
    controls = (source / "sumeragi/evidence_history/lane/tests.rs").read_text()
    body = controls.split("fn " + name + "(", 1)[1]
    for obligation in ["reader.poll().unwrap()", ".try_reserve_bytes(", "reader.verify(&proof)",
                       "occupied original offender pool must refuse", "let error = result.expect_err(",
                       "EvidencePreparationError::Admission(actual)", "actual == expected",
                       "drop(blocker)", "attribution.belongs_to(&budget)", "drop(attribution)"]:
        assert obligation in body
    assert "set_limit_bytes" not in body and "AllocationBudget::new" not in body
    rows = re.findall(r"^\| HC180 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_funded_offender_graph_moves_original_backing_into_admission_without_world_claim():
    source = ROOT / "crates/iroha_core/src/sumeragi"
    owner = (source / "evidence_history/funded_attribution.rs").read_text()
    assert "RetainedPayload<Vec<EvidenceOffender>>" in owner
    assert "RetainedPayload<EvidenceAttribution>" in owner
    assert owner.index("let mut charges =") < owner.index("let mut values =")
    assert "values.into_allocation_parts()" in owner and "key.into_allocation_parts()" in owner
    assert "RetainedPayload::try_new(values, charges, budget)" in owner
    assert "DerefMut" not in owner and "impl Clone" not in owner
    assert "Partial construction retires on refusal" in owner
    assert "into_record_fields" in owner
    assert "map_payload" in owner
    evidence = (source / "evidence.rs").read_text()
    assert "NativeEvidenceError::Preparation(error) => Self::Preparation(error)" in evidence
    assert "Option<super::evidence_history::FundedEvidenceAttribution>" in evidence
    assert "EvidenceRecordBody::reserve(budget)?" in evidence
    assert "original proof bytes" in evidence
    record = (source / "evidence/record.rs").read_text()
    assert "ManuallyDrop<AllocationCharge>" in record
    assert "ManuallyDrop::drop(&mut self.fields)" in record
    assert record.index("ManuallyDrop::drop(&mut self.fields)") < record.index("ManuallyDrop::drop(&mut self.proof_charge)")
    assert "native proof-decoder/canonical-pair scratch" in record
    tests = (source / "evidence_history/funded_attribution/tests.rs").read_text()
    for name in ["original_offender_graph_moves_exact_vector_keys_and_ledger_without_allocation",
                 "original_offender_graph_refuses_each_exact_physical_backing_and_retries",
                 "original_offender_graph_late_capacity_count_foreign_and_unwind_retire_partial_owners"]:
        assert "fn " + name + "(" in tests


def test_funded_material_key_uses_canonical_validation_before_original_backing():
    path = ROOT / "crates/iroha_crypto/src/prepared_decode.rs"
    body = path.read_text().split("pub fn try_from_material(", 1)[1].split("/// Decode once", 1)[0]
    assert body.index("public_key_decode::validate(algorithm, payload)?") < body.index("ChargedBuffer::new(exact_bytes, budget)")
    assert body.index("ChargedBuffer::new(exact_bytes, budget)") < body.index("backing.push_reserved")
    assert "PublicKey::bind_compact_allocation(backing)" in body
    assert "reserve_compact_decode_backing" not in body and "from_bytes(" not in body


def test_world_evidence_shared_body_mutation_has_exact_original_cow_control():
    name = "world_evidence_current_undo_and_cow_retain_original_proof_and_offender_allocations"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC181"]
    assert rule.tests == ("sumeragi::evidence::lifecycle_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC181", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC181", **family)
    source = ROOT / "crates/iroha_core/src/sumeragi/evidence"
    owner = (source / "record.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC181")' in owner
    assert "Self::from_fixture(self.canonical_projection(), &self.body.budget)" in owner
    assert "body: self.body.clone()" in owner
    assert "AllocationBudget::new" not in owner
    body = (source / "lifecycle_tests.rs").read_text().split("fn " + name + "(", 1)[1]
    for obligation in ["let copied = pending.clone()", "World COW must share the original paid proof allocation",
                       "offenders_pointer", "compact_pointer", "source.current().get(&key)",
                       "source.revert_map().get(&key)", "EvidencePenaltyStatus::Pending",
                       "EvidencePenaltyStatus::Applied { height: 5 }", "validate_persisted_records"]:
        assert obligation in body
    assert body.index("World COW must share the original paid proof allocation") < body.index("chain.commit")
    rows = re.findall(r"^\| HC181 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_world_evidence_restore_uses_explicit_original_pool_and_canonical_owner_seams():
    root = ROOT / "crates"
    owner = (root / "iroha_core/src/sumeragi/evidence/record.rs").read_text()
    assert "impl JsonDeserialize for RetainedEvidenceRecord" not in owner
    assert "impl DerefMut" not in owner
    assert "parse_record" in owner and "Evidence::decode_native_frame(bytes.as_slice())" in owner
    assert "restore_storage" in owner and "Storage::from_snapshot_parts(current, undo)" in owner
    core = (root / "iroha_core/src/state/deserialize_world.rs").read_text()
    assert "decode_evidence(execution_budget)" in core
    crypto = (root / "iroha_crypto/src/lib.rs").read_text()
    assert "PublicKeyJsonAdmissionError" in crypto and "pub mod prepared_decode" not in crypto
    helpers = (root / "iroha_core/src/sumeragi/evidence/record/tests.rs").read_text()
    for name in ["retained_record_restore_and_borrowed_encoding_preserve_exact_canonical_schema",
                 "retained_record_storage_restores_complete_current_undo_claims_without_budgetless_decode",
                 "retained_record_body_rejects_equivalent_foreign_graph_pool_before_shell_allocation",
                 "retained_record_reordered_fields_preserve_canonical_values_and_first_invalid_field"]:
        assert "fn " + name + "(" in helpers


def test_administrative_amx_registration_mutation_preserves_permission_and_exact_carrier_authority():
    rule = gate.index_mutations(gate.DEPLOY_MUTATIONS)["DEP6"]
    source = (ROOT / "crates/iroha_deploy/src/attachment/amx_registration.rs").read_text()
    wallet = (ROOT / "crates/iroha_wallet/src/operations_amx_registration.rs").read_text()
    native = (ROOT / "crates/iroha_deploy/src/managed/native_operation.rs").read_text()
    managed = (ROOT / "crates/iroha_deploy/src/managed/remote.rs").read_text()
    assert rule.tests == ("attachment::amx_registration::tests::original_amx_administrator_child_fees_time_and_checkpoint_survive_reopen_and_refuse_substitution",)
    assert 'all(test, sumeragi_deploy_mutation = "DEP6")' in source
    assert "self.identity == identity && self.administrator == config.account" in source
    assert "RegisterAmxDataspaceV1" in wallet and "registration.validate()?" in wallet
    assert "CanSetParameters" in source and "Registered" in source and "Rejected" in source
    assert "verify_carrier_execution" in native and "retain_carrier_execution_progress" in native
    assert '"runtime.lock"' in managed and re.search(r"sources\s*\.\s*require_signed_generation\(&prepared\)", managed)



def test_detached_native_amx_source_has_exact_transfer_mutation_and_control():
    name = "persisted_amx_detached_source_keeps_original_frame_pool_and_retry_after_view_drop"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC182"]
    assert rule.tests == ("sumeragi::amx::proof_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC182", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC182", **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC182"', path.read_text())}
    assert owners == {"query/native_receipts/amx_read.rs"}
    owner = (source / "query/native_receipts/amx_read.rs").read_text()
    transfer = owner.split("pub fn try_detach(", 1)[1].split("/// Observe one actual", 1)[0]
    assert 'all(test, sumeragi_core_mutation = "HC182")' in transfer
    assert "source.bytes = None;" in transfer
    assert transfer.index("source.acquire_bytes()?") < transfer.index("self.source.take()")
    body = (source / "sumeragi/amx/proof_tests.rs").read_text().split("fn " + name + "(", 1)[1].split("#[test]", 1)[0]
    for obligation in ["detached AMX source must retain the exact acquired frame",
                       "drop(read)", "drop(view)", "owned.complete().unwrap_err()",
                       "detach must not retire original prefix or source charges inside the State borrow",
                       "NativeAmxRecordProofErrorV1::Admission(actual)",
                       "AllocationRefusal::Capacity", "budget.try_reserve_bytes(*requested_bytes)",
                       "owned.acquired_frame().unwrap().as_ptr()", "proof.belongs_to(&budget)",
                       "!proof.belongs_to(&foreign)", "fs::rename(&archive, &retained_path)",
                       "tracker.verify_record", "chain.root_scope().into()", "proof.allocation_bytes()"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    assert body.index("drop(view)") < body.index("owned.complete().unwrap_err()")
    assert body.index("detached AMX source must retain the exact acquired frame") < body.index("owned.complete().unwrap_err()")
    rows = re.findall(r"^\| HC182 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_detached_native_amx_source_reuses_the_borrowed_engine_and_original_guards():
    source = ROOT / "crates/iroha_core/src"
    owner = (source / "query/native_receipts/amx_read.rs").read_text()
    assert owner.count("AllocatedAmxRecordProofV1::from_original_witness(") == 1
    engine = owner.split("struct OriginalAmxSource {", 1)[1].split("/// Original State cut", 1)[0]
    assert "StateReadOnly" not in engine and "&'" not in engine
    assert "certified: Option<CertifiedBlock>" in engine and "read: Option<NativeContextRead>" in engine
    assert "budget: AllocationBudget" in engine and "source_started: bool" in engine
    owned = owner.split("pub struct NativeAmxRecordProofOwnedV1", 1)[1].split("impl<'v, V: StateReadOnly>", 1)[0]
    assert "source: OriginalAmxSource" in owned
    assert "pub fn new" not in owned and "impl Clone" not in owner
    transfer = owner.split("pub fn try_detach(", 1)[1].split("/// Observe one actual", 1)[0]
    assert transfer.index("borrowed portable observer must finish before detach") < transfer.index("self.acquire_original_source()?")
    assert "if !source.source_started" in transfer
    assert transfer.count("recheck_namespace()?") == 2
    assert "self.chain = None" not in transfer
    assert "uncached prefix/genesis bodies" in transfer
    assert "No prefix refund/notification is introduced inside detachment" in transfer
    assert "native AMX proof already completed" in owner
    for mutation in ("HC147", "HC148", "HC159"):
        assert 'all(test, sumeragi_core_mutation = "' + mutation + '")' in owner
    public = (source / "query/native_receipts.rs").read_text()
    assert "NativeAmxRecordProofOwnedV1" in public and "pub fn amx_record_proof" in public
    assert "NativeAmxRecordProofReadV1::new(view, height, kind, transaction)" in public


def test_detached_native_amx_source_controls_keep_real_partial_and_completed_custody():
    body = (ROOT / "crates/iroha_core/src/sumeragi/amx/proof_tests.rs").read_text()
    for name in ["persisted_amx_detach_pins_partial_inode_and_continues_without_original_view",
                 "persisted_amx_detach_namespace_refusal_preserves_original_reader_for_retry",
                 "persisted_amx_detach_after_final_guard_refusal_moves_completed_graph_without_work",
                 "persisted_amx_detach_preserves_borrowed_probe_and_authenticated_absence",
                 "persisted_amx_detached_source_rejects_substituted_uncertified_archive_fields"]:
        assert "fn " + name + "(" in body
    fixture = body.split("fn chain_with_begins(", 1)[1].split("fn read_proof(", 1)[0]
    assert "MAX_AMX_PENDING).contains(&count)" in fixture
    assert "for index in 1..count" in fixture and "BeginAmxV1" in fixture
    assert "u64::try_from(index).unwrap().to_le_bytes()" in fixture
    assert "chain.commit_at(2_000, vec![signed]), vec![true]" in fixture
    assert "4096 / iroha_data_model::sumeragi_amx::AMX_RECORD_WITNESS_KEY_BYTES + 1" in body
    assert "chain_with_begins(count)" in body
    assert "SetKeyValue::account(" not in fixture
    assert "!prefix.is_empty() && prefix.len() <= 4096" in body
    assert "assert_eq!(prefix, &original_file[..prefix.len()])" in body
    assert "assert_eq!(owned.acquired_frame().unwrap(), original_file)" in body
    assert "borrowed portable observer must finish before detach" in body
    assert "amx_proof_backing_identity(&proof), original" in body
    assert "detach moves completed original owners without allocation" in body
    assert "before_drop - original.allocation_bytes" in body
    assert "changed.carrier_hash" in body
    reader = (ROOT / "crates/iroha_core/src/query/native_context_archive/read.rs").read_text()
    assert "#[cfg(test)]\n    pub(crate) fn acquired_prefix" in reader


def test_prepared_intent_publication_has_exact_owner_mutation_and_native_control():
    name = "original_paid_prepared_commit_captures_durable_intent_before_acknowledgement"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC183"]
    assert rule.tests == ("sumeragi::executor::amx_intent_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC183", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC183", **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC183"', path.read_text())}
    assert owners == {"query/native_context_archive.rs"}
    owner = (source / "query/native_context_archive.rs").read_text()
    publish = owner.split("pub fn publish(", 1)[1].split("pub fn read_job", 1)[0]
    assert publish.index("original intent capture is incomplete") < publish.index("publish_record(")
    assert publish.index("publish_record(") < publish.index('sumeragi_core_mutation = "HC183"')
    assert 'RecordName::intent(original.height, original.carrier_hash, false)' in publish
    body = (source / "sumeragi/executor_amx_intent_tests.rs").read_text().split("fn " + name + "(", 1)[1].split("#[test]", 1)[0]
    for obligation in ["worker.prepare(&block, &qc)", "blocks.append(&block, &qc)",
                       "worker.commit(&block, &qc)", "worker.applied", "amx_record_proof",
                       "committed Prepared must durably retain its original outbound intent",
                       "uncommitted overlay must not publish outbound intent",
                       "prepared certificate is still not published State"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    rows = re.findall(r"^\| HC183 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_prepared_intent_capture_uses_original_witness_and_authenticated_source():
    source = ROOT / "crates/iroha_core/src"
    owner = (source / "query/native_context_archive/prepared_intents.rs").read_text()
    capture = owner.split("pub(crate) fn prepare_amx_intents(", 1)[1].split("#[cfg(test)]", 1)[0]
    for obligation in ["self.recheck_namespace()?", "witness.pool().same_pool(&self.budget)",
                       "witness.matches_original_native_execution", "original.carrier_hash != executed.hash()",
                       "executed.header() != overlay._curr_block", "count(&witness.writes)?",
                       "authenticated_parent_source(&self.budget)", "parent.global_genesis",
                       "parent.global_successor", "Hash::new", "authority: 0",
                       "ChargedBuffer::new(length, &self.budget)"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", capture)
    assert "core_hash" not in capture and "header.instance" not in capture
    normalized_capture = re.sub(r"\s+", "", capture)
    witness_check = normalized_capture.index("witness.matches_original_native_execution")
    assert witness_check < normalized_capture.index("iforiginal.intents_complete{", witness_check)
    assert normalized_capture.index("ChargedBuffer::new(length,&self.budget)") < normalized_capture.index("write_canonical_to_writer")
    assert "decode_canonical" not in capture and "AllocationBudget::new" not in capture
    assert "write_element_sequence::<Row, _>" in owner
    assert "rows: RowsRef" in owner
    assert 'frame = "iroha_core::amx::PreparedIntentCoordinatesV1"' in owner
    assert "borrowed_intent_coordinates_declare_exact_owned_frame_without_erasing_nominal_lifetime" in owner
    source_binding = (source / "state/fastpq_quantity_capture/commitment_journal/finalized_source/witness.rs").read_text()
    assert "self.native == Some((executed.hash(), execution))" in source_binding
    assert "std::ptr::eq(self.wire(), self.wire.get())" in source_binding


def test_prepared_intent_worker_retains_completed_original_context_before_later_admission():
    source = ROOT / "crates/iroha_core/src"
    owner = (source / "sumeragi/executor.rs").read_text()
    capture = owner.split("fn prepare_original_context_archive(", 1)[1].split("fn finish_execution_with_encoder(", 1)[0]
    assert "if original.native_contexts.is_none()" in capture
    assert re.sub(r"\s+", "", capture).index("original.native_contexts=Some") < re.sub(r"\s+", "", capture).index(".prepare_amx_intents(")
    assert "original.archive_refusal = Some(error)" in capture
    assert "preparation::buffer_refusal(error)" in capture
    assert "AllocationBudget::new" not in capture and "native_contexts = None" not in capture
    controls = (source / "sumeragi/executor_amx_intent_tests.rs").read_text()
    for name in ["original_paid_intent_capacity_refusal_retains_completed_context_and_same_pool_retry",
                 "original_paid_intent_namespace_refusal_retains_both_buffers_and_exact_commit_retry",
                 "original_paid_intent_changed_durable_bytes_never_acknowledge_or_repair",
                 "original_paid_intent_capture_rejects_changed_carrier_execution_and_foreign_pool",
                 "original_paid_intent_historical_replay_preserves_exact_record_and_repetition_identity",
                 "rejected_paid_prepare_overlay_never_publishes_outbound_intent"]:
        assert "fn " + name + "(" in controls
    for obligation in ["AllocationRefusal::Capacity", "budget.try_reserve_bytes", "context_pointer",
                       "intent_pointer", "worker.pending_commit", "fs::rename(&hidden, &directory)",
                       "CommitTelemetryOrigin::HistoricalReplay", "completed_replay", "foreign_pool"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", controls)


def test_prepared_intent_real_same_block_pruning_uses_committed_witness():
    source = ROOT / "crates/iroha_core/src"
    controls = (source / "sumeragi/executor_amx_intent_tests.rs").read_text()
    name = "original_paid_prepared_witness_survives_same_block_pruning_before_intent_commit"
    body = controls.split("fn " + name + "(", 1)[1].split("#[test]", 1)[0]
    for obligation in ["with_paid_prepare_pruning_fixture", "chain.sign(&customer, instructions, time)",
                       "participant.entry(&transactions[0]).is_none()", "participant.entry(&transactions[1]).is_some()",
                       "participant.prepared.len()", "witness.writes.iter()", "prepared_intent_bytes()",
                       "worker.commit(&block, &qc)", "both original committed Prepared records survive final-state pruning"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    fixture = (source / "sumeragi/amx/native/tests/paid_borrowed_custody.rs").read_text().split("fn with_paid_prepare_pruning_fixture(", 1)[1]
    for obligation in ["paid_roots()", "roots.transaction(2_000", "expired.deadline = 5",
                       "commit_at(3_000", "commit_at(4_000", "commit_at(5_000",
                       "global_paid_images(&roots.global, 5)", "AmxRecordKind::Begin", "into_prepare(FIRST",
                       "AmxRecordKind::Decision", "into_settle(FIRST)", "[expired_instruction, settle, next_instruction]"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", fixture)
    domains = (source / "state/state_table_inventory_domains.rs").read_text()
    schema_owner = (source / "query/native_context_archive/prepared_intents.rs").read_text()
    scanner = (source / "state/state_table_inventory_tests.rs").read_text()
    # Rust schema names are excluded by the existing exact domain-literal rule.
    for identity in ("iroha_core::amx::PreparedIntentCoordinatesV1", "iroha_core::amx::PreparedIntentRowV1"):
        assert identity in schema_owner and identity not in domains
        assert identity in scanner



def test_checkpoint_status_query_pool_has_exact_owner_mutation_and_native_control():
    name = "genesis_status_prefix_retains_original_admitted_pool_and_cumulative_refusal_work"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC184"]
    assert rule.tests == ("smartcontracts::isi::tx::native_carrier_reader_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC184", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC184", **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC184"', path.read_text())}
    assert owners == {"state.rs"}
    owner = (source / "state.rs").read_text()
    adapter = owner.split("pub fn read_finalized_execution_carrier_with_read_budget(", 1)[1].split("fn read_finalized_execution_carrier_in_pool(", 1)[0]
    assert 'sumeragi_core_mutation = "HC184"' in adapter
    assert "read_budget.with(||" in adapter
    assert "let pool = read_budget.frames();" in adapter
    assert "let budget = self.ivm_execution_budget();" in adapter
    body = (source / "smartcontracts/isi/tx/native_carrier_reader_tests.rs").read_text().split("fn " + name + "(", 1)[1].split("#[test]", 1)[0]
    for obligation in ["try_reserve_bytes(frames.limit_bytes())", "Layout::array::<u8>(original_wire.len())",
                       "original.allocation_refusal(), Some(&expected)",
                       "finalized status must retain the original admitted query frame pool",
                       "context.consumed_allocated_bytes()", "carrier.block().belongs_to(&frames)",
                       "drop(carrier)", "drop(retained)", "frames.reserved_bytes(), 0"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    rows = re.findall(r"^\| HC184 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_checkpoint_status_preserves_g1_h2_and_internal_full_prefix_boundaries():
    source = (ROOT / "crates/iroha_torii/src/lib_pipeline_handlers.rs").read_text()
    http = source.split("fn read_pipeline_transaction_carrier(", 1)[1].split("\nfn ", 1)[0]
    assert "HistoryProducerOwner::authentication_read(app)?" in http
    assert "owner.scope(||" in http
    assert "if anchor.height == NonZeroUsize::MIN" in http
    assert "read_finalized_execution_carrier_with_read_budget(" in http
    assert "read_executed_carrier_from_checkpoints(" in http
    assert "or_else" not in http and "unwrap_or" not in http
    ordinary = source.split("fn authenticate_canonical_transaction_outcome(", 1)[1].split("// HTTP status", 1)[0]
    assert "visit_finalized_network_transactions(" in ordinary
    assert "checkpoint" not in ordinary.split("// HTTP", 1)[0]
    status = source.split("fn pipeline_status_terminal_or_state_entry(", 1)[1].split("\nfn ", 1)[0]
    assert "read_pipeline_transaction_carrier(app, anchor)" in status
    assert "pipeline_status_terminal_or_state_entry_with_carrier_reader(" in status
    checked = source.split("fn pipeline_status_terminal_or_state_entry_with_carrier_reader(", 1)[1].split("\nfn ", 1)[0]
    assert "reconcile_pending_pipeline_transaction_with_carrier_reader(app, hash, read)?" in checked
    reconciled = source.split("fn reconcile_pending_pipeline_transaction_with_carrier_reader(", 1)[1].split("\nfn ", 1)[0]
    assert "canonical_transaction_read_with_authenticator(&app.state, hash" in reconciled
    assert reconciled.index("canonical_transaction_read_with_authenticator") < reconciled.index("complete_pending_from_carrier")
    tests = (ROOT / "crates/iroha_torii/src/tests/lib_runtime_handlers/part_5.rs").read_text()
    for name in ["pipeline_status_authentication_keeps_original_admitted_query_pool_on_refusal",
                 "pipeline_status_checkpoint_reader_preserves_exact_rejection_and_publication_bracket",
                 "pipeline_status_rejects_foreign_query_owner_but_absent_membership_needs_no_history_admission",
                 "pipeline_status_checkpoint_outcome_rejects_duplicate_original_borrowed_rows",
                 "pipeline_status_genesis_requires_actual_h2_and_refuses_substituted_successor"]:
        assert "async fn " + name + "(" in tests
    body = tests.split("async fn pipeline_status_genesis_requires_actual_h2_and_refuses_substituted_successor(", 1)[1]
    for obligation in ["height 2 is not committed in this view", "chain.commit(Vec::new())",
                       "journal.push_for_tests(replacement)", "query_conversion_message(&ordinary)",
                       "cached Applied and opaque G1 State cannot replace original H2 authentication"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)


def test_checkpoint_status_capture_releases_world_and_brackets_original_journal():
    source = (ROOT / "crates/iroha_core/src/state.rs").read_text()
    body = source.split("pub fn read_executed_carrier_from_checkpoints(", 1)[1].split("pub fn read_canonical_history_block(", 1)[0]
    for obligation in ["let before = self.state_view_generation()", "self.block_hashes.view()",
                       "*self.native_execution_tip.view().get()",
                       "is_stable_state_view_generation(before, self.state_view_generation())",
                       "drop(hashes)", "CanonicalHistorySource::new(",
                       "self.block_hashes.view().get(height.get() - 1).copied() != expected"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    assert "self.view()" not in body
    assert "FinalizedExecutionCarrier" in body
    assert "AllocationBudget::new" not in body
    reads = (ROOT / "crates/iroha_core/src/smartcontracts/isi/tx/native_carrier_reader_tests.rs").read_text()
    for name in ["checkpoint_tip_status_authentication_uses_one_original_source_without_changing_prefix_metering",
                 "checkpoint_status_refusal_retries_the_original_frame_pool_and_refunds_after_last_carrier",
                 "authenticated_carrier_network_visitor_preserves_borrowed_rows_and_refuses_foreign_selection",
                 "genesis_status_prefix_requires_actual_h2_and_refuses_substituted_successor"]:
        assert "fn " + name + "(" in reads


def test_checkpoint_status_registry_composes_existing_prepared_intent_registration():
    for mutation in ("HC183", "HC184"):
        assert gate.index_mutations(gate.CORE_MUTATIONS)[mutation].tests
        assert len(re.findall(r"^\| " + mutation + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)) == 1



def test_torii_cache_mutation_has_exact_owner_hook_and_both_native_adapters():
    rule = gate.index_mutations(gate.TORII_MUTATIONS)["TOR1"]
    assert rule.tests == (
        "tests_runtime_handlers::pipeline_status_cached_applied_refuses_removed_original_membership",
        "tests_runtime_handlers::prepared_submit_outcome_cached_applied_refuses_removed_original_membership",
    )
    assert rule.scenarios == ()
    assert gate.has_switch("TOR1", torii=True)
    for owner in ({}, {"core": True}, {"daemon": True}, {"model": True}, {"sdk": True}, {"deploy": True}):
        assert not gate.has_switch("TOR1", **owner)
    source = ROOT / "crates/iroha_torii"
    handler = (source / "src/lib_pipeline_handlers.rs").read_text()
    helper = handler.split("fn pipeline_status_cached_entry_without_canonical(", 1)[1].split("pub(crate) fn ", 1)[0]
    assert 'if needs_canonical && !cfg!(all(test, sumeragi_torii_mutation = "TOR1"))' in helper
    assert "PipelineStatusKind::Committed | PipelineStatusKind::Applied" in helper
    assert "PipelineStatusKind::Rejected | PipelineStatusKind::Expired" in helper
    assert "pipeline_status_projection_error" in helper and "Ok(cached)" in helper
    assert ".remove_entry" not in helper and ".record_entry" not in helper
    actual_switches = {
        identifier for path in (source / "src").rglob("*.rs")
        for identifier in re.findall(r'sumeragi_torii_mutation\s*=\s*"([^"]+)"', path.read_text())
    }
    assert actual_switches == set(gate.index_mutations(gate.TORII_MUTATIONS))
    controls = (source / "src/tests/lib_runtime_handlers/part_5.rs").read_text()
    for name in rule.tests:
        assert "fn " + name.rsplit("::", 1)[-1] + "(" in controls
    assert "cached Applied must retain its original canonical membership" in controls
    assert "prepared submission cache must retain its original canonical membership" in controls
    assert "canonical_outcome_test_fixture(false)" in controls
    assert "membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap())" in controls
    build = (source / "build.rs").read_text()
    declared = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert declared is not None
    ids = re.findall(r'"(TOR[0-9]+)"', declared.group(1))
    assert ids == [rule.id for rule in gate.TORII_MUTATIONS]
    assert 'const ENV: &str = "SUMERAGI_TORII_MUTATION";' in build
    assert 'const CFG: &str = "sumeragi_torii_mutation";' in build
    assert 'let values = IDS' in build
    assert 'println!("cargo:rustc-check-cfg=cfg({CFG}, values({values}))")' in build
    assert "!rustflags.contains(CFG)" in build
    assert "CARGO_FEATURE_MUTATION_TESTING" in build
    assert 'mentions(Path::new("src"), &needle)' in build
    guard = (source / "src/torii_mutation_guard.rs").read_text()
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard and "mutation-testing is test-only" in guard
    assert "mod torii_mutation_guard;" in (source / "src/lib.rs").read_text()
    manifest = (source / "Cargo.toml").read_text()
    assert "mutation-testing = []" in manifest and "/mutation-testing" not in manifest
    rows = re.findall(r"^\| TOR1 \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("damage,verdict", [
    ("none", "killed_by_test"), ("second_pass", "killed_by_test"),
    ("incidental_only", "error"), ("missing_second", "error"), ("ignored_second", "error"),
])
def test_torii_named_kill_accounts_for_both_exact_adapters_and_selected_extras(
    monkeypatch, tmp_path, damage, verdict
):
    rule = gate.TORII_MUTATIONS[0]
    rows = [(name, "FAILED") for name in rule.tests]
    if damage == "second_pass":
        rows[1] = (rows[1][0], "ok")
    elif damage == "incidental_only":
        rows = [(name, "ok") for name in rule.tests]
    elif damage == "missing_second":
        rows.pop()
    elif damage == "ignored_second":
        rows[1] = (rows[1][0], "ignored")
    rows.append((rule.tests[0] + "_incidental", "FAILED"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(torii=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert "scenario" not in result
    assert result["named"]["selected"] == [name for name, _ in rows]
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == [name for name, status in rows if status == "FAILED" and name in rule.tests]
    elif damage == "incidental_only":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    else:
        assert result["reason"] == "named tests: missing-test"


@pytest.mark.parametrize("owner,package,features,profile,environment", [
    (None, "iroha_sumeragi", "mutation-testing,sim", ["--release"], "SUMERAGI_MUTATION"),
    ("core", "iroha_core", "mutation-testing,iroha-core-tests", ["--profile", "test"], "SUMERAGI_CORE_MUTATION"),
    ("daemon", "irohad_lib", "mutation-testing", ["--release"], "SUMERAGI_DAEMON_MUTATION"),
    ("model", "iroha_data_model", "mutation-testing", ["--profile", "test"], "SUMERAGI_MODEL_MUTATION"),
    ("sdk", "iroha", "mutation-testing", ["--profile", "test"], "SUMERAGI_SDK_MUTATION"),
    ("deploy", "iroha_deploy", "mutation-testing", ["--profile", "test"], "SUMERAGI_DEPLOY_MUTATION"),
    ("torii", "iroha_torii", "mutation-testing", ["--profile", "test"], "SUMERAGI_TORII_MUTATION"),
    ("norito", "norito", "mutation-testing", ["--profile", "test"], "SUMERAGI_NORITO_MUTATION"),
])
@pytest.mark.parametrize("mutant", [None, "original-owned-rule"])
def test_all_mutation_families_clear_inherited_torii_selection_without_changing_profiles(
    monkeypatch, tmp_path, owner, package, features, profile, environment, mutant
):
    variables = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION",
                 "SUMERAGI_MODEL_MUTATION", "SUMERAGI_SDK_MUTATION", "SUMERAGI_DEPLOY_MUTATION",
                 "SUMERAGI_TORII_MUTATION", "SUMERAGI_NORITO_MUTATION")
    for variable in variables:
        monkeypatch.setenv(variable, "inherited-foreign-rule")
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 1200
            return "unexecuted mock build", None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(**({owner: True} if owner else {}))
    code, output, _ = gate.cargo_test(args, tmp_path, mutant, [], None, 1200, tmp_path / "build.log", no_run=True)
    assert code == 0 and output == "unexecuted mock build"
    assert captured["command"] == ["cargo", "test", "--locked", "-p", package, *profile, "--features", features, "--lib", "--no-run"]
    for variable in variables:
        assert captured["options"]["env"].get(variable) == (mutant if variable == environment else None)
    assert captured["options"]["start_new_session"] is True


def test_torii_pending_mutation_is_the_actual_original_query_refusal_rule():
    rule = gate.index_mutations(gate.TORII_MUTATIONS)["TOR2"]
    assert rule.tests == (
        "tests_runtime_handlers::pipeline_status_pending_refresh_retains_original_query_refusal_and_pending_source",
    )
    assert rule.scenarios == ()
    assert gate.has_switch("TOR2", torii=True)
    for owner in ({}, {"core": True}, {"daemon": True}, {"model": True}, {"sdk": True}, {"deploy": True}):
        assert not gate.has_switch("TOR2", **owner)
    source = ROOT / "crates/iroha_torii/src"
    handler = (source / "lib_pipeline_handlers.rs").read_text()
    status = handler.split("fn reconcile_pending_pipeline_transaction_with_carrier_reader(", 1)[1].split("// A cached block outcome", 1)[0]
    assert '#[cfg(all(test, sumeragi_torii_mutation = "TOR2"))]\n    app.pipeline_status_cache.refresh_pending_blocks(&app.state);' in status
    assert status.index("canonical_transaction_read_with_authenticator") < status.index("complete_pending_from_carrier")
    outer = handler.split("fn pipeline_status_terminal_or_state_entry_with_carrier_reader(", 1)[1].split("// Test convenience delegates", 1)[0]
    assert outer.index("reconcile_pending_pipeline_transaction_with_carrier_reader") < outer.index("record_entry(hash.clone()")
    assert "read_pipeline_transaction_carrier(app, anchor)" in handler
    retained = handler.split("struct AuthenticatedPipelineCarrier {", 1)[1].split("}", 1)[0]
    assert retained.index("carrier:") < retained.index("owner:")
    native = (source / "lib.rs").read_text()
    assert '#[cfg(all(test, sumeragi_torii_mutation = "TOR2"))]\n    fn refresh_pending_blocks' in native
    completion = native.split("fn complete_pending_from_carrier(", 1)[1].split("fn record_network_result(", 1)[0]
    assert "DashEntry::Occupied(pending)" in completion
    assert "pending.get().block_hash != expected_hash" in completion
    assert completion.index("visit_network_transactions") < completion.index("pending.remove()")
    assert "remove_pending_by_height" not in completion
    for forbidden in ("record_block_results", "read_finalized", "read_executed", "collect()"):
        assert forbidden not in completion
    controls = (source / "tests/lib_runtime_handlers/part_5.rs").read_text()
    for name in (
        rule.tests[0].rsplit("::", 1)[-1],
        "pipeline_status_pending_completion_reuses_original_carrier_and_leaves_other_sources",
        "pipeline_status_pending_foreign_or_absent_query_keeps_exact_deferred_source",
        "pipeline_status_pending_recheck_refuses_changed_membership_without_cache_effects",
        "pipeline_status_pending_replacement_and_foreign_carrier_cannot_retire_original_entry",
    ):
        assert "fn " + name + "(" in controls
    assert "pending cache refresh must not bypass the original query refusal with execution capacity" in controls
    assert "pending completion must not decode a second original carrier" in controls
    for mutation in ("TOR1", "HC183", "HC184"):
        table = gate.TORII_MUTATIONS if mutation.startswith("TOR") else gate.CORE_MUTATIONS
        assert gate.index_mutations(table)[mutation].tests
    rows = re.findall(r"^\| TOR2 \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and rule.tests[0] in rows[0]


@pytest.mark.parametrize("damage,verdict", [
    ("none", "killed_by_test"), ("incidental_only", "error"),
    ("missing", "error"), ("ignored", "error"),
])
def test_torii_pending_named_kill_requires_its_original_refusal_control(
    monkeypatch, tmp_path, damage, verdict
):
    rule = gate.index_mutations(gate.TORII_MUTATIONS)["TOR2"]
    rows = [(rule.tests[0], "FAILED")]
    if damage == "incidental_only":
        rows[0] = (rule.tests[0], "ok")
    elif damage == "missing":
        rows.clear()
    elif damage == "ignored":
        rows[0] = (rule.tests[0], "ignored")
    rows.append((rule.tests[0] + "_incidental", "FAILED"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(torii=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert "scenario" not in result
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == list(rule.tests)
    elif damage == "incidental_only":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    else:
        assert result["reason"] == "named tests: missing-test"


def test_torii_pending_positive_controls_use_current_query_owned_reconciliation():
    source = ROOT / "crates/iroha_torii/src"
    controls = (source / "tests/lib_runtime_handlers/part_5_pipeline_cache.rs").read_text()
    assert "refresh_pending_blocks" not in controls
    assert controls.count("reconcile_pending_pipeline_transaction(&app, &tx_hash)") == 3
    assert "let cache = &app.pipeline_status_cache;" in controls
    assert "assert_eq!(stored.kind, PipelineStatusKind::Committed)" in controls
    assert "pending.deferred.is_some()" in controls
    assert "assert_eq!(pending.block_hash, block.hash())" in controls
    assert "drop(occupied);" in controls and "drop(occupied_cold);" in controls


def test_owned_native_amx_issuer_has_exact_refused_descriptor_mutation_and_control():
    name = "owned_issuer_retains_first_refused_archive_descriptor_after_original_view_drop"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC185"]
    assert rule.tests == ("query::native_receipts::amx_read::issuer_tests::" + name,)
    assert not rule.scenarios
    assert gate.has_switch("HC185", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC185", **family)
    source = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC185"', path.read_text())}
    assert owners == {"query/native_receipts/amx_read.rs"}
    owner = (source / "query/native_receipts/amx_read.rs").read_text()
    issue = owner.split("pub fn try_issue(", 1)[1].split("/// Observe one actual", 1)[0]
    assert 'all(test, sumeragi_core_mutation = "HC185")' in issue
    assert "read.into_archive().read_job(" in issue
    compact_issue = re.sub(r"\s+", "", issue)
    assert compact_issue.index("self.try_detach()") < compact_issue.index("NativeContextRead::has_pinned_source") < compact_issue.index("self.source.take()")
    body = (source / "query/native_receipts/amx_read/issuer_tests.rs").read_text().split("fn " + name + "(", 1)[1].split("#[test]", 1)[0]
    compact = re.sub(r"\s+", "", body)
    for obligation in ["amx_record_proof(&view", "read.acquire_original_source().unwrap()",
                       "budget.try_reserve_bytes(original_file.len()).unwrap_err()",
                       "AllocationRefusal::Capacity", "assert_eq!(actual,expected)",
                       "read.try_issue().unwrap()", "original.source.budget.same_pool(&budget)",
                       "std::ptr::eq::<SignedBlock>", "drop(read)", "drop(view)",
                       "fs::rename(&archive,&retained_path)", "vec![0;original_file.len()]",
                       "owned issuer must retain the first refused archive descriptor",
                       "proof.belongs_to(&budget)", "!proof.belongs_to(&foreign)",
                       "tracker.verify_record", "before_drop-bytes"]:
        assert re.sub(r"\s+", "", obligation) in compact
    assert body.index("drop(view)") < body.index("original.poll().unwrap()")
    assert body.index("owned issuer must retain the first refused archive descriptor") < body.index("original.complete().unwrap()")
    rows = re.findall(r"^\| HC185 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_owned_native_amx_issuer_moves_refusal_without_a_second_verifier_or_decoder():
    source = ROOT / "crates/iroha_core/src"
    owner = (source / "query/native_receipts/amx_read.rs").read_text()
    issue = owner.split("pub fn try_issue(", 1)[1].split("/// Observe one actual", 1)[0]
    assert issue.count("self.try_detach()") == 1
    assert "source.completed" in issue and "source.certified.is_none()" in issue
    assert "self.portable_probe.is_some()" in issue
    assert "NativeContextRead::has_pinned_source" in issue
    assert "NativeAmxRecordProofIssuedV1::Refused" in issue and "cause," in issue
    for forbidden in ["CertifiedChain::new", "decode_projection", "source.acquire_bytes", "self.chain = None", "source.bytes = None", "AllocationBudget::new"]:
        assert forbidden not in issue
    assert owner.count("AllocatedAmxRecordProofV1::from_original_witness(") == 1
    reader = (source / "query/native_context_archive/read.rs").read_text()
    pinned = reader.split("pub(crate) fn has_pinned_source", 1)[1].split("// Borrow the actual", 1)[0]
    assert "self.read.file.is_some() && self.read.length.is_some()" in pinned
    assert "open_record" not in pinned and "poll(" not in pinned
    public = (source / "query/native_receipts.rs").read_text()
    assert "NativeAmxRecordProofIssuedV1" in public
    controls = (source / "query/native_receipts/amx_read/issuer_tests.rs").read_text()
    for name in ["owned_issuer_preserves_partial_frame_and_same_pool_without_an_extra_poll",
                 "owned_issuer_keeps_missing_uncertified_and_armed_probe_sources_in_borrower",
                 "owned_issuer_carries_final_namespace_refusal_without_rebuilding_completed_graph",
                 "owned_issuer_retains_original_decoder_refusal_and_rejects_substituted_carrier_fields"]:
        assert "fn " + name + "(" in controls
    for obligation in ["CertifiedTestChain::start", "chain.commit_at(2_000", "probe_portable_prepared_once",
                       "assert_eq!(allocations, 0)", "original.source.portable", "replacement.restore()",
                       "cause.decode_resource_error().is_some()", "changed.carrier_hash", "before_drop - observed.get().unwrap().bytes"]:
        assert obligation in controls


def test_native_original_start_mutation_has_exact_kura_source_and_control():
    selector = "kura::native_execution_read_tests::native_frame_original_start_refuses_same_inode_relocation_before_body_admission"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC187"]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch("HC187", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC187", **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC187"', p.read_text())}
    assert owners == {"kura/native_execution_reads.rs"}
    rows = re.findall(r"^\| HC187 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]


def test_native_original_start_guard_refuses_before_body_admission():
    source = (ROOT / "crates/iroha_core/src/kura/native_execution_reads.rs").read_text()
    capture = source.split("pub(crate) fn native_frame_read(", 1)[1].split("/// Read the exact frame", 1)[0]
    assert "let slot = store.read_block_index(position)?;" in capture
    assert "start: slot.start" in capture
    read = source.split("pub(crate) fn read(", 1)[1].split("impl Kura", 1)[0]
    assert read.index('sumeragi_core_mutation = "HC187"') < read.index("NativeFrameDestination::new")
    assert "slot.start != start" in read
    body = source.split("fn native_frame_original_start_refuses_same_inode_relocation_before_body_admission()", 1)[1].split("#[test]", 1)[0]
    for required in ["slot.start.checked_add(1)", "pool.try_reserve_bytes(pool.limit_bytes())",
                     "source.read(length, &pool)", "Error::CanonicalBlockWireMismatch { height: 2 }",
                     "captured native start must refuse relocation before original body admission",
                     "canonical_query_reads_for_test(), (0, 0)"]:
        assert required in body
    assert body.index("write_block_index(1, original.start, original.length)") < body.index("captured native start must refuse relocation")


def test_terminal_amx_retention_mutations_have_exact_core_owners_and_native_controls():
    expected = {
        "HC186": ("sumeragi/certified_chain/native_acquisition.rs",
                  "terminal_amx_raw_frame_survives_original_shared_shell_refusal"),
        "HC188": ("sumeragi/certified_chain/terminal_selection.rs",
                  "terminal_amx_target_survives_original_later_gap_capacity_and_proof_retry"),
    }
    core = ROOT / "crates/iroha_core/src"
    native = (core / "query/native_receipts/amx_read/certification_tests.rs").read_text()
    spec = (ROOT / "specs/sumeragi.md").read_text()
    for mid, (owner, name) in expected.items():
        selector = "query::native_receipts::amx_read::certification_tests::" + name
        rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
        assert rule.tests == (selector,) and not rule.scenarios
        assert gate.has_switch(mid, core=True)
        owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
                  if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
        assert owners == {owner}
        for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        rows = re.findall(r"^\| " + mid + r" \|.*$", spec, re.MULTILINE)
        assert len(rows) == 1 and selector in rows[0]
        assert "fn " + name + "(" in native
    for message in ("terminal AMX source must retain the exact acquired frame",
                    "terminal AMX selection must retain the exact decoded target across gap refusal"):
        assert message in native


def test_native_queue_startup_and_delivery_mutations_have_closed_core_owners_and_exact_controls():
    expected = {
        "HC189": ("queue/sumeragi_wake.rs", "sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_global_driver_after_empty"),
        "HC190": ("queue/sumeragi_wake.rs", "sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty"),
        "HC191": ("queue.rs", "sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart"),
        "HC192": ("queue/resident_owner.rs", "queue::sumeragi_wake::tests::reserved_original_pool_refuses_foreign_resident_admission_before_allocation"),
        "HC193": ("queue.rs", "sumeragi::node::tests::queue_wake_tests::native_queue_reservation_refuses_foreign_funded_pool_without_changing_original_pending"),
        "HC194": ("queue.rs", "sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart"),
    }
    core = ROOT / "crates/iroha_core/src"
    spec = (ROOT / "specs/sumeragi.md").read_text()
    for mid, (owner, selector) in expected.items():
        rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
        assert rule.tests == (selector,) and not rule.scenarios
        assert gate.has_switch(mid, core=True)
        owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
                  if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
        assert owners == {owner}
        for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        rows = re.findall(r"^\| " + mid + r" \|.*$", spec, re.MULTILINE)
        assert len(rows) == 1 and selector in rows[0]
        native = core / ("queue/sumeragi_wake.rs" if mid == "HC192" else "sumeragi/node/tests/queue_wake_tests.rs")
        assert "fn " + selector.rsplit("::", 1)[1] + "(" in native.read_text()


@pytest.mark.parametrize("mid,selector,control", [
    ("HC195", "sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty",
     "sumeragi/node/tests/queue_wake_tests.rs"),
    ("HC196", "sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry",
     "sumeragi/lanes/store/publication_tests.rs"),
    ("HC197", "sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry",
     "sumeragi/lanes/store/publication_tests.rs"),
])
def test_durable_lane_publication_mutations_have_exact_original_consumers_and_spec_owners(mid, selector, control):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"sumeragi/lanes/store.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / control).read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_daemon_output_mode_mutation_has_one_actual_owner_and_exact_native_control():
    mid = "HC198"
    selector = "beacon_bootstrap::seat_export::tests::public_output_initializes_exact_original_creation_mode_before_publication_and_restore"
    rule = gate.index_mutations(gate.DAEMON_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, daemon=True)
    daemon = ROOT / "crates/irohad/src"
    owners = {p.relative_to(daemon).as_posix() for p in daemon.rglob("*.rs")
              if f'sumeragi_daemon_mutation = "{mid}"' in p.read_text()}
    assert owners == {"beacon_bootstrap/seat_export.rs"}
    for family in ({}, {"core": True}, {"model": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (daemon / "beacon_bootstrap/seat_export/tests.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_completed_lane_payload_mutation_has_one_actual_owner_and_exact_native_control():
    mid = "HC199"
    selector = "sumeragi::executor::payload_owner::tests::completed_certified_lane_payload_keeps_original_output_across_same_scope_build_retry"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"sumeragi/executor.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / "sumeragi/executor/payload_owner.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native



def test_block_event_reader_mutation_has_one_actual_owner_and_exact_native_control():
    mid = "HC201"
    selector = "smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_reads_recent_certified_source_under_original_finite_work"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"state.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / "smartcontracts/isi/tx/native_carrier_reader_tests.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native



def test_block_event_view_refusal_mutation_has_one_actual_owner_and_exact_native_control():
    mid = "HC202"
    selector = "state::event_carrier_tests::event_carrier_returns_from_original_writer_refusal_without_waiting"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"state.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / "state/event_carrier_tests.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_status_prelude_mutation_has_one_actual_actor_owner_and_exact_native_controls():
    mid = "HC203"
    selectors = (
        "telemetry::tests::classified_status_tests::status_prelude_refuses_original_publication_before_service_deadline",
        "telemetry::tests::classified_status_tests::status_final_world_sample_refuses_publication_after_verified_chunk",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == selectors and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"telemetry.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(selector in rows[0] for selector in selectors)
    native = (core / "telemetry/classified_status_tests.rs").read_text()
    for selector in selectors:
        assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_initial_amx_acquisition_mutation_has_original_public_reader_control():
    mid = "HC204"
    selector = "query::native_receipts::amx_read::issuer_tests::public_amx_initial_shell_refusal_retains_original_genesis_frame_without_reread"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"sumeragi/certified_chain/amx_initialization.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / "query/native_receipts/amx_read/issuer_tests.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_authenticated_genesis_scope_mutation_has_original_reader_control():
    mid = "HC205"
    selector = "sumeragi::certified_chain::tests::signed_genesis_initialization_does_not_repeat_completed_scope_decode"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"sumeragi/certified_chain.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    native = (core / "sumeragi/certified_chain/tests.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_pinned_genesis_model_mutations_have_original_public_reader_controls():
    controls = {
        "DM10": "pinned_signed_genesis_uses_one_original_decode_and_retains_metadata",
        "DM11": "pinned_signed_genesis_preserves_original_binary_refusal",
        "DM12": "pinned_signed_genesis_preserves_original_json_refusal_and_retry",
    }
    model = ROOT / "crates/iroha_data_model/src"
    for mid, name in controls.items():
        selector = "sumeragi_finality::genesis_dataspace::tests::" + name
        rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
        assert rule.tests == (selector,) and not rule.scenarios
        assert gate.has_switch(mid, model=True)
        owners = {p.relative_to(model).as_posix() for p in model.rglob("*.rs")
                  if f'sumeragi_model_mutation = "{mid}"' in p.read_text()}
        assert owners == {"sumeragi_finality/genesis.rs"}
        for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
        assert len(rows) == 1 and selector in rows[0]
        native = (model / "sumeragi_finality/genesis_dataspace_tests.rs").read_text()
        assert "fn " + name + "(" in native


def test_native_carrier_metadata_mutation_has_actual_state_reader_controls():
    mid = "HC206"
    selectors = (
        "smartcontracts::isi::tx::native_carrier_reader_tests::full_prefix_carrier_preserves_original_cumulative_metadata_refusal",
        "smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_preserves_original_cumulative_metadata_refusal",
        "smartcontracts::isi::tx::native_carrier_reader_tests::bounded_native_extent_preserves_original_cumulative_metadata_refusal",
        "state::block_proofs::native_proof_reader_tests::native_block_proof_preserves_original_cumulative_metadata_refusal",
        "sumeragi::finality::compact_source::tests::compact_source_preserves_original_cumulative_metadata_refusal_before_body_io",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == selectors and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"execution_attempt.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(selector in rows[0] for selector in selectors)
    natives = "\n".join((core / path).read_text() for path in (
        "smartcontracts/isi/tx/native_carrier_reader_tests.rs",
        "state/block_proofs.rs", "sumeragi/finality/compact_source.rs",
    ))
    assert all("fn " + selector.rsplit("::", 1)[1] + "(" in natives for selector in selectors)


def test_deploy_completed_genesis_metadata_mutation_has_original_profile_owner():
    mid = "DEP7"
    selector = "localnet::private_root::tests::private_root_preparation_executes_signed_genesis_and_retains_owner_on_reopen"
    rule = gate.index_mutations(gate.DEPLOY_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, deploy=True)
    source = ROOT / "crates/iroha_deploy"
    owners = {p.relative_to(source / "src").as_posix() for p in (source / "src").rglob("*.rs")
              if f'sumeragi_deploy_mutation = "{mid}"' in p.read_text()}
    assert owners == {"localnet/service_authorities.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"core": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    build = (source / "build.rs").read_text()
    ids = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert ids is not None and mid in re.findall(r'"(DEP[0-9]+)"', ids.group(1))
    assert 'println!("cargo:rustc-check-cfg=cfg({CFG}, values({values}))")' in build
    assert 'let values = IDS' in build
    row = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(row) == 1 and selector in row[0]
    native = (source / "src/localnet/private_root.rs").read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_original_amx_completed_policy_mutation_keeps_exact_public_native_control():
    mid = "HC215"
    selector = "query::native_receipts::amx_read::issuer_tests::public_amx_signed_policy_retains_completed_npos_stage_on_metadata_refusal"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"sumeragi/certified_chain/amx_initialization.rs"}
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in (core / "query/native_receipts/amx_read/issuer_tests.rs").read_text()


def test_private_root_home_mutations_have_isolated_native_guard_controls():
    cases = {
        "HC207": "restricted_home_requires_original_private_root_not_global_missing_or_foreign_scope",
        "HC208": "original_private_home_requires_both_exact_captured_routes",
        "HC209": "original_private_home_requires_canonical_single_root_geometry",
    }
    core = ROOT / "crates/iroha_core/src"
    controls = (core / "smartcontracts/isi/domain/private_root_home_tests.rs").read_text()
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    for mid, name in cases.items():
        selector = "smartcontracts::isi::domain::isi::private_root_home_tests::" + name
        rule = registered[mid]
        assert rule.tests == (selector,) and not rule.scenarios
        assert gate.has_switch(mid, core=True)
        owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
                  if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
        assert owners == {"smartcontracts/isi/domain/asset_alias_scope.rs"}
        for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                       {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
        assert len(rows) == 1 and selector in rows[0]
        assert "fn " + name + "(" in controls


def test_finite_finality_interval_mutations_have_original_native_owner_controls():
    cases = {'HC210': ('sumeragi::finality::proof_reader_tests::finite_finality_interval_under_original_codec_checks_each_real_quorum_once',
               'sumeragi/certified_chain.rs',
               'sumeragi/finality/proof_reader_tests.rs'),
     'HC211': ('sumeragi::finality::interval::tests::finite_interval_rejects_earlier_real_qc_changed_after_verification_before_publication',
               'sumeragi/finality/interval.rs',
               'sumeragi/finality/interval/tests.rs'),
     'HC212': ('sumeragi::finality::interval::tests::finite_interval_stop_retires_real_original_cursor_without_next_native_read',
               'sumeragi/finality/interval.rs',
               'sumeragi/finality/interval/tests.rs'),
     'HC213': ('sumeragi::finality::proof_destination::tests::original_proof_destination_charges_each_actual_compact_key_before_clone_and_refunds',
               'sumeragi/finality/proof_destination.rs',
               'sumeragi/finality/proof_destination/tests.rs'),
     'HC214': ('state::finality_proof_interval::tests::interval_post_read_writer_refusal_retires_response_and_preserves_original_release',
               'state/finality_proof_interval.rs',
               'state/finality_proof_interval/tests.rs')}
    core = ROOT / "crates/iroha_core/src"
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    for mid, (selector, owner, control) in cases.items():
        rule = registered[mid]
        assert rule.tests == (selector,) and not rule.scenarios
        assert gate.has_switch(mid, core=True)
        owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
                  if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
        assert owners == {owner}
        for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                       {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
        assert len(rows) == 1 and selector in rows[0]
        native = (core / control).read_text()
        assert "fn " + selector.rsplit("::", 1)[1] + "(" in native


def test_borrowed_epoch_and_fixed_identity_mutations_keep_exact_physical_controls():
    model = ROOT / "crates/iroha_data_model"
    registered = gate.index_mutations(gate.MODEL_MUTATIONS)
    owners = {
        "DM16": {"sumeragi/epoch.rs"},
        "DM17": {"parameter/system.rs", "nexus/committee.rs"},
    }
    for mid, expected in owners.items():
        actual = {path.relative_to(model / "src").as_posix()
                  for path in (model / "src").rglob("*.rs")
                  if f'sumeragi_model_mutation = "{mid}"' in path.read_text()}
        assert actual == expected
        assert gate.has_switch(mid, model=True)
        for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True},
                       {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        assert not registered[mid].scenarios
    epoch = (model / "src/sumeragi/epoch.rs").read_text()
    assert epoch.count('sumeragi_model_mutation = "DM16"') == 2
    assert '#[cfg(all(test, sumeragi_model_mutation = "DM16"))]\n        self.authorization\n            .validate_against_generation(&self.generation())' in epoch
    assert '.validate_against_committee(' in epoch
    primary = (model / "src/sumeragi/epoch/tests.rs").read_text()
    assert "validating the original signed epoch must not allocate a temporary generation roster" in primary
    assert "PhysicalObservation::start()" in primary
    assert registered["DM16"].tests == (MODEL_NAMES["DM16"],)
    assert registered["DM17"].tests == (
        MODEL_NAMES["DM17"],
        "parameter::system::tests::sumeragi_npos_synthetic_identity_is_exact_and_validation_never_allocates",
        "nexus::committee::tests::frozen_policy_validation_borrows_fixed_synthetic_identity_without_allocation",
    )
    for owner in owners["DM17"]:
        native = (model / "src" / owner).read_text()
        assert native.count('sumeragi_model_mutation = "DM17"') == 2
        assert '#[cfg(all(test, sumeragi_model_mutation = "DM17"))]\n' in native
        constructor = 'crate::asset::AssetDefinitionId' if owner == 'parameter/system.rs' else 'AssetDefinitionId'
        assert 'let synthetic_bytes = ' + constructor + '::derive_from_components(' in native
        assert '::REJECTED_SYNTHETIC_XOR_ASSET_BYTES;' in native
        assert '.aid_bytes() == synthetic_bytes' in native
    record = (model / "src/parameter/system/npos_json/tests.rs").read_text()
    assert "record transfer allocates/reallocates no replacement digit graph" in record
    assert "transfer.retirements(pointer)" in record
    assert "original native-digit allocation retires exactly with its admitted record" in record


@pytest.mark.parametrize("mid", ["DM16", "DM17", "DM18", "DM19"])
@pytest.mark.parametrize("damage,verdict", [
    ("none", "killed_by_test"), ("incidental_only", "error"),
    ("missing", "error"), ("ignored", "error"),
])
def test_original_model_allocation_kill_requires_the_exact_native_control(
    monkeypatch, tmp_path, mid, damage, verdict
):
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    rows = [(name, "FAILED") for name in rule.tests]
    if damage == "incidental_only":
        rows = [(name, "ok") for name in rule.tests]
    elif damage == "missing":
        rows.clear()
    elif damage == "ignored":
        rows = [(name, "ignored") for name in rule.tests]
    rows.append((rule.tests[0] + "_incidental", "FAILED"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(model=True, target_dir=tmp_path,
                          timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == sorted(rule.tests)
    elif damage == "incidental_only":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    else:
        assert result["reason"] == "named tests: missing-test"


def test_finality_stop_mutation_keeps_original_query_credit_control_and_exact_owner():
    mid = "TOR3"
    selector = "finality_interval::tests::failed_and_timed_out_workers_keep_original_credit_until_unpolled_stop_control_retires"
    rule = gate.index_mutations(gate.TORII_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, torii=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"model": True},
                   {"sdk": True}, {"deploy": True}):
        assert not gate.has_switch(mid, **family)
    source = ROOT / "crates/iroha_torii"
    owners = {path.relative_to(source / "src").as_posix()
              for path in (source / "src").rglob("*.rs")
              if f'sumeragi_torii_mutation = "{mid}"' in path.read_text()}
    assert owners == {"finality_interval.rs"}
    native = (source / "src/finality_interval.rs").read_text()
    retained = native.split("struct CancelOnDrop {", 1)[1].split("impl Drop", 1)[0]
    assert retained.index("flag:") < retained.index("_owner:")
    guard = '#[cfg(not(all(test, sumeragi_torii_mutation = "TOR3")))]'
    assert native.count(guard) == 2
    assert guard + "\n    _owner: history_producer::HistoryProducerOwner" in retained
    assert guard + "\n                _owner: owner.clone()" in native
    assert "self.flag.store(true, Ordering::Release)" in native
    controls = (source / "src/finality_interval/tests.rs").read_text()
    body = controls.split("async fn " + selector.rsplit("::", 1)[-1] + "()", 1)[1]
    for observation in (
        "for expired in [false, true]", "std::future::Future::poll",
        "notified).await", "cpu_credit_retired", "original_credit_held",
        "StatusCode::REQUEST_TIMEOUT", "QueryExecutionFail::NotFound",
        "None => request.await", "drop(result)", "fully_refunded",
        "native worker error must retain original query credit until the unpolled HTTP stop control retires",
    ):
        assert observation in body
    assert body.index("drop(result)") < body.index("assert!(\n            original_credit_held")
    build = (source / "build.rs").read_text()
    declared = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert declared is not None
    ids = re.findall(r'"(TOR[0-9]+)"', declared.group(1))
    assert ids == [rule.id for rule in gate.TORII_MUTATIONS]
    assert "let values = IDS" in build
    assert 'println!("cargo:rustc-check-cfg=cfg({CFG}, values({values}))")' in build
    rows = re.findall(r"^\| TOR3 \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("damage,verdict", [
    ("none", "killed_by_test"), ("incidental_only", "error"),
    ("missing", "error"), ("ignored", "error"),
])
def test_finality_stop_named_kill_requires_original_worker_credit_control(
    monkeypatch, tmp_path, damage, verdict
):
    rule = gate.index_mutations(gate.TORII_MUTATIONS)["TOR3"]
    rows = [(rule.tests[0], "FAILED")]
    if damage == "incidental_only":
        rows[0] = (rule.tests[0], "ok")
    elif damage == "missing":
        rows.clear()
    elif damage == "ignored":
        rows[0] = (rule.tests[0], "ignored")
    rows.append((rule.tests[0] + "_incidental", "FAILED"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(torii=True, target_dir=tmp_path,
                          timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert "scenario" not in result
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == list(rule.tests)
    elif damage == "incidental_only":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    else:
        assert result["reason"] == "named tests: missing-test"


def test_committee_borrowed_generation_mutations_keep_public_transcript_work_and_short_circuits():
    model = ROOT / "crates/iroha_data_model"
    registered = gate.index_mutations(gate.MODEL_MUTATIONS)
    source = (model / "src/nexus/committee.rs").read_text()
    for mid in ("DM18", "DM19"):
        assert registered[mid].tests == (MODEL_NAMES[mid],)
        assert not registered[mid].scenarios
        assert gate.has_switch(mid, model=True)
        actual = {path.relative_to(model / "src").as_posix()
                  for path in (model / "src").rglob("*.rs")
                  if f'sumeragi_model_mutation = "{mid}"' in path.read_text()}
        assert actual == {"nexus/committee.rs"}
        for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True},
                       {"deploy": True}, {"torii": True}):
            assert not gate.has_switch(mid, **family)
        assert source.count(f'sumeragi_model_mutation = "{mid}"') == 2
    context = source.split("pub fn readiness_context(", 1)[1].split("/// Validate structural consistency", 1)[0]
    assert 'let identity = self.preparation.generation().generation_id();' in context
    assert 'let identity = ValidatorGenerationV1::generation_id_from_committee(' in context
    assert context.index("let credentials = self.validated_credentials()?") < context.index("target validator seat is out of range") < context.index("transition_id: self.preparation.transition_id()?") < context.index("let identity")
    activation = source.split("ValidatorEpochDecisionV1::Activate => {", 1)[1].split("ValidatorEpochDecisionV1::RetainAndCancel", 1)[0]
    assert activation.index("self.readiness.len() != preparation.committee.len()") < activation.index("outcome.beacon !=") < activation.index("|| {") < activation.index("let relation")
    assert 'outcome.validate_against_generation(&preparation.generation());' in activation
    assert 'let relation = outcome.validate_against_committee(' in activation
    assert 'relation.is_err()' in activation
    for name, message in (
        (MODEL_NAMES["DM18"], "public readiness must borrow the original roster beyond its independently measured canonical transcript work"),
        (MODEL_NAMES["DM19"], "public activation must borrow the original target generation beyond existing readiness and canonical transcript work"),
    ):
        control = source.split("fn " + name.rsplit("::", 1)[1] + "()", 1)[1].split("#[test]", 1)[0]
        assert 'measured(||' in control and message in control
        assert control.index('original_committee_storage(') < control.index('measured(||')
        assert 'original.encode(), original_wire' in control
        assert 'required_requests' in control and 'actual_requests' in control
        assert 'PhysicalObservation::start' not in control



def test_native_tip_restore_mutation_has_original_resource_and_same_source_controls():
    mid = "HC216"
    selectors = (
        "state::native_execution_tip::tests::restore_preserves_original_pool_refusal_release_and_same_source_retry",
        "state::native_execution_tip::tests::restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == selectors and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"state/native_execution_tip.rs"}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(selector in rows[0] for selector in selectors)
    native = (core / "state/native_execution_tip/tests.rs").read_text()
    assert all("fn " + selector.rsplit("::", 1)[1] + "(" in native for selector in selectors)
    assert "restore_keeps_corrupt_native_history_a_completed_schema_rejection" in native
    owner = (core / "state/native_execution_tip.rs").read_text()
    assert 'all(test, sumeragi_core_mutation = "HC216")' in owner
    assert "ExecutionAttemptError::<ChainReadError>::Deferred(original).to_string()" in owner
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'cfg({CFG}, values(any()))' in build
    assert 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("statuses,expected", [
    (("ok", "ok"), "survived"),
    (("FAILED", "ok"), "killed_by_test"),
    (("ok", "FAILED"), "killed_by_test"),
    (("FAILED", "FAILED"), "killed_by_test"),
    (("FAILED", "ignored"), "error"),
])
def test_native_tip_mutation_accounts_both_original_named_controls(monkeypatch, tmp_path, statuses, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC216"]
    rows = tuple(zip(rule.tests, statuses))
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == expected
    assert result["named"]["selected"] == list(rule.tests)
    assert result["named"]["ran"] == sorted(name for name, status in rows if status != "ignored")
    assert result["named"]["failed"] == sorted(name for name, status in rows if status == "FAILED")



def test_restarted_prepared_intent_mutation_uses_original_funded_delivery_and_final_namespace():
    mid = "HC217"
    prefix = "sumeragi::amx::native::tests::paid_borrowed_custody::"
    names = (
        "restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool",
        "restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == tuple(prefix + name for name in names) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in p.read_text()}
    assert owners == {"query/native_receipts/amx_intents.rs"}
    owner = (core / "query/native_receipts/amx_intents.rs").read_text()
    joined = owner.split("// The actual complete instruction remains owned here", 1)[1]
    compact = re.sub(r"\s+", "", joined)
    assert compact.index(f'sumeragi_core_mutation="{mid}"') < compact.index("self.recheck()?") < compact.index("self.instruction.take()")
    assert "self.pending" in owner and "matches_completed_execution" in owner
    assert "AllocationBudget::new" not in owner and "witness_value()" not in owner
    assert 'height >= 2' in owner and '.block_hashes()' in owner
    assert "prepared_intent_read_job(height, carrier)" in owner
    assert "classify_decode_attempt" in owner and "Decode(#[from] norito::core::DecodeAttemptError)" in owner
    assert "TODO(S6)" in owner and "No selector" in owner
    controls = (core / "sumeragi/amx/native/tests/paid_borrowed_custody.rs").read_text()
    fixture = controls.split("fn with_restarted_paid_prepared_intent(", 1)[1].split("fn prepared_intent_path", 1)[0]
    for evidence in ("paid_roots()", "roots.prepare(", "authenticate_original_prepared(",
                     "CertifiedTestChain::start(", "restored.replay_from(", "same_pool("):
        assert evidence in fixture
    refusal = controls.split("fn " + names[1] + "()", 1)[1].split("#[test]", 1)[0]
    assert refusal.index("replacement.borrow_mut().restore()") < refusal.index("assert!(matches!(refused")
    assert "completed restarted intent must retain exact funded relay through final original namespace refusal" in refusal
    assert "retained_instruction()" in refusal and "original_pointers" in refusal
    for name in names + (
        "restarted_paid_intent_original_pool_refusal_keeps_frame_and_selected_source_without_reread",
        "restarted_paid_intent_rejects_substituted_authority_carrier_and_execution_claims",
    ):
        assert "fn " + name + "(" in controls
    assert "acquired_frame_is_complete()" in controls
    assert "DecodeAttemptErrorKind::EnclosingLimit" in controls
    assert "original_release" in controls and "drop(instruction)" in controls
    codec = (core / "query/native_context_archive/prepared_intents.rs").read_text()
    assert "struct Decoded {" not in codec
    for boundary in ("framed_field", "visit_binary_sequence_with_count", "decode_exact_with", "from_bytes_view",
                     "SchemaMismatch", "NonCanonicalEncoding", "sole_intent_decoder_borrows_original_charged_ranges"):
        assert boundary in codec
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(prefix + name in rows[0] for name in names)
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'cfg({CFG}, values(any()))' in build
    assert 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("statuses,expected", [
    (("ok", "ok"), "survived"),
    (("ok", "FAILED"), "killed_by_test"),
    (("FAILED", "ok"), "killed_by_test"),
    (("FAILED", "FAILED"), "killed_by_test"),
    (("ok", "ignored"), "error"),
])
def test_restarted_prepared_intent_mutation_accounts_each_genuine_control(monkeypatch, tmp_path, statuses, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC217"]
    rows = tuple(zip(rule.tests, statuses))
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == expected
    assert result["named"]["selected"] == list(rule.tests)
    assert result["named"]["ran"] == sorted(name for name, status in rows if status != "ignored")
    assert result["named"]["failed"] == sorted(name for name, status in rows if status == "FAILED")



def test_restarted_prepared_intent_completeness_mutation_uses_authenticated_full_witness():
    mid = "HC218"
    name = "restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery"
    selector = "sumeragi::amx::native::tests::paid_borrowed_custody::" + name
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    core = ROOT / "crates/iroha_core/src"
    owner = (core / "query/native_receipts/amx_intents.rs").read_text()
    assert owner.index('sumeragi_core_mutation = "HC218"') < owner.index(".authenticated_prepared_count()?") < owner.index(".into_relay()")
    proof = (core / "query/native_receipts/amx_read.rs").read_text()
    count = proof.split("fn authenticated_prepared_count", 1)[1].split("// Only this sibling", 1)[0]
    assert "source.completed && source.authenticated" in count
    assert re.search(r"prepared_intents::count\(&projection\.witness\.get\(\)\.writes,?\)", re.sub(r"\s+", "", count))
    assert "clone()" not in count and "collect(" not in count
    controls = (core / "sumeragi/amx/native/tests/paid_borrowed_custody.rs").read_text()
    control = controls.split("fn " + name + "()", 1)[1]
    for evidence in ("roots.transaction(40", "roots.transaction(60", "roots.participants[0].sign(&payer(), prepares",
                     "restored.replay_from(", "one_row_subset(&original)",
                     "restarted canonical intent must match every authenticated Prepared row before first delivery",
                     "retained_instruction().is_none()", "let first = complete.complete_next()", "let second = complete.complete_next()"):
        assert evidence in control
    assert control.index("std::fs::write(&path, &original)") < control.index("assert!(matches!(refused")
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("status,expected", [("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error")])
def test_restarted_prepared_intent_completeness_accounts_exact_named_native_control(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC218"]
    rows = ((rule.tests[0], status),)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == expected
    assert result["named"]["selected"] == list(rule.tests)


def test_returned_native_amx_context_mutation_uses_exact_original_graph_custody():
    mid = "HC219"
    name = "native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement"
    selector = "sumeragi::amx::native::tests::returned_context::" + name
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in path.read_text()}
    assert owners == {"sumeragi/amx/native/retained.rs"}
    retained = (core / "sumeragi/amx/native/retained.rs").read_text()
    owner = retained.split("pub(super) struct RetainedGlobalSource", 1)[1].split("/// Original initial registration inputs", 1)[0]
    assert "RetainedPayload<AmxForeignInstanceV1>" in owner
    assert 'all(test, sumeragi_core_mutation = "HC219")' in owner
    assert "current: context.clone()" in owner
    assert "demand.context(context)?" in owner and "construction.context(context, budget)?" in owner
    assert "RetainedPayload::try_new(value, charges, budget)" in owner
    assert "AllocationBudget::new" not in owner
    assert "into_uncharged" not in retained and "fn uncharged(" not in retained
    production = (core / "sumeragi/amx/native.rs").read_text()
    source = production.split("fn authenticated_global_source(", 1)[1].split("impl Execute for RegisterAmxParticipantV1", 1)[0]
    assert source.index("RetainedGlobalSource::admit") < source.index("authenticate_global_successor") < source.index(".validate()")
    assert 'sumeragi_core_mutation = "HC219"' not in production
    assert "TODO(S6)" in production
    controls = (core / "sumeragi/amx/native/tests/returned_context.rs").read_text()
    for boundary in ("CertifiedTestChain::start(config)", "global.commit_at(1_500", "global.committed(2)",
                     "committee_pointer", "key_pointers", "pop_pointers", "retained_allocation_layout()",
                     "owner.belongs_to(&budget)", "!owner.belongs_to(&foreign)", "registration.poll_wait(&release",
                     "drop(owner)", "drop(retry)",
                     "returned native AMX context must retain exact original-pool committee/key/PoP custody after genuine H2"):
        assert boundary in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'cfg({CFG}, values(any()))' in build and 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("status,expected", [("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error")])
def test_returned_native_amx_context_accounts_exact_named_custody_control(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC219"]
    rows = ((rule.tests[0], status),)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == expected
    assert result["named"]["selected"] == list(rule.tests)
    assert result["named"]["ran"] == sorted(name for name, state in rows if state != "ignored")
    assert result["named"]["failed"] == sorted(name for name, state in rows if state == "FAILED")


@pytest.mark.parametrize("arguments", [
    ["--norito", "--core"], ["--norito", "--daemon"], ["--norito", "--model"],
    ["--norito", "--sdk"], ["--norito", "--deploy"], ["--norito", "--torii"],
    ["--norito", "--core-profile", "test"], ["--norito", "--strict", "--skip-baseline"],
    ["--norito", "--only", "HC32"], ["--core", "--only", "NC1"],
    ["--only", "NC1"], ["--norito", "--only", "NC1,NC1"], ["--norito", "--only", ","],
])
def test_norito_owner_refuses_cross_owner_and_incomplete_qualification(monkeypatch, tmp_path, arguments):
    target = tmp_path / "refused-norito"
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments, "--target-dir", str(target)])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2 and not target.exists()


def test_norito_registry_matches_actual_owner_switches_and_original_controls():
    indexed = gate.index_mutations(gate.NORITO_MUTATIONS)
    assert set(indexed) == {"NC1", "NC2", "NC3", "NC4", "NC5"}
    assert indexed["NC1"].tests == ("core::decode_attempt::tests::direct_json_refusal_keeps_original_context_and_retry",)
    assert indexed["NC2"].tests == (
        "core::decode_attempt::tests::direct_attempt_replay_under_same_counter_owner_is_invalid",
        "core::decode_attempt::tests::direct_attempt_cross_thread_replay_with_original_shared_context_is_invalid",
        "core::decode_attempt::tests::direct_nested_attempts_preserve_parent_origin_and_refuse_old_sibling",
        "core::decode_attempt::tests::already_active_direct_attempt_rejects_later_foreign_thread_root",
    )
    assert indexed["NC3"].tests == ("core::decode_attempt::tests::observer_boundary_sequence_exhaustion_never_wraps",)
    assert indexed["NC4"].tests == (
        "json::tests::core_resource_errors_roundtrip_exact_fields_without_fresh_scope",
        "json::tests::direct_json_parser_retains_unscoped_fields_and_same_input_retry",
    )
    assert indexed["NC5"].tests == ("json::tests::non_resource_core_errors_cannot_become_json_allocator_refusals",)
    source = ROOT / "crates/norito"
    texts = "\n".join(path.read_text() for path in (source / "src").rglob("*.rs"))
    assert set(re.findall(r'sumeragi_norito_mutation\s*=\s*"([^"]+)"', texts)) == set(indexed)
    for identifier, rule in indexed.items():
        assert gate.has_switch(identifier, norito=True)
        assert not gate.has_switch(identifier, core=True)
        assert not gate.has_switch(identifier)
        assert not rule.scenarios
        assert f'all(test, sumeragi_norito_mutation = "{identifier}")' in texts
        for selector in rule.tests:
            assert f'fn {selector.rsplit("::", 1)[-1]}(' in texts
    manifest = (source / "Cargo.toml").read_text()
    assert "mutation-testing = []" in manifest and "/mutation-testing" not in manifest
    build = (source / "build.rs").read_text()
    declared = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert declared is not None
    assert set(re.findall(r'"(NC[0-9]+)"', declared.group(1))) == set(indexed)
    assert 'const CFG: &str = "sumeragi_norito_mutation";' in build
    assert 'const ENV: &str = "SUMERAGI_NORITO_MUTATION";' in build
    assert '!rustflags.contains(CFG)' in build and 'CARGO_FEATURE_MUTATION_TESTING' in build
    assert 'IDS.contains(&id.as_str())' in build
    assert 'mentions_mutation(std::path::Path::new("src"), &needle)' in build
    assert 'mod norito_mutation_guard;' in (source / "src/lib.rs").read_text()
    with pytest.raises(ValueError, match="exactly one implementation owner"):
        gate.has_switch("NC1", norito=True, core=True)


def test_model_scoped_multisig_refusal_mutation_omits_only_original_error_return():
    """DM20 restores nonmatch only at the original scoped JSON inspection boundary."""
    mid = "DM20"
    model = ROOT / "crates/iroha_data_model"
    path = model / "src/smart_contract/multisig_call.rs"
    source = path.read_text()
    registered = gate.index_mutations(gate.MODEL_MUTATIONS)
    assert registered[mid].tests == (MODEL_NAMES[mid],)
    assert not registered[mid].scenarios
    owners = {p.relative_to(model / "src").as_posix()
              for p in (model / "src").rglob("*.rs")
              if f'sumeragi_model_mutation = "{mid}"' in p.read_text()}
    assert owners == {"smart_contract/multisig_call.rs"}
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == 1
    assert gate.has_switch(mid, model=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    kernel = source.split("fn read_recognition_json<", 1)[1].split("/// Recognize only", 1)[0]
    assert 'Err(error @ norito::json::Error::ScopedDecodeResource(_))' in kernel
    assert 'if !cfg!(all(test, sumeragi_model_mutation = "DM20"))' in kernel
    assert kernel.count('Err(MultisigContractCallRecognitionError::Json(error))') == 2
    assert 'Err(_) => Ok(None)' in kernel
    assert 'norito::json::Error::DecodeResource(_)' in kernel
    assert 'norito::json::Error::AllocationFailed' in kernel
    assert 'from_decode_resource' not in kernel and 'classify_decode_attempt' not in kernel
    control = source.split('fn ' + MODEL_NAMES[mid].rsplit('::', 1)[1] + '()', 1)[1]
    control = control.split('    #[test]', 1)[0]
    for required in ('recognition_fixture()', 'recognize_multisig_contract_call(',
                     'classify_decode_attempt(', 'DecodeAttemptErrorKind::EnclosingLimit',
                     'assert_eq!(returned, observed)', 'call.instructions.as_ptr()',
                     'original_wire', 'pool.reserved_bytes()', '&malformed',
                     '&call.instructions[..1]',
                     'a genuine scoped refusal must not become a nonmatching multisig envelope'):
        assert required in control
    assert f'sumeragi_model_mutation = "{mid}"' not in control


@pytest.mark.parametrize("mid,path,function,required", [
    ("DM21", "account/address.rs", "fn from_decode_error", "error.decode_resource_error().is_some()"),
    ("DM22", "account.rs", "fn from_address_error", "error.is_decode_resource_limit()"),
])
def test_account_resource_mutations_have_one_owning_omission_and_unchanged_genuine_controls(mid, path, function, required):
    """Typed account causes may be erased only by the owning test-only omission."""
    model = ROOT / "crates/iroha_data_model"
    source = (model / "src" / path).read_text()
    registered = gate.index_mutations(gate.MODEL_MUTATIONS)
    rules = {
        "DM21": (
            MODEL_NAMES["DM21"],
            "account::address::tests::account_address_value_and_map_key_json_decoders_are_borrowed_and_measured",
            "account::address::tests::address_resource_conversions_preserve_fields_and_anonymous_bounds_without_minting_scope"),
        "DM22": (
            MODEL_NAMES["DM22"],
            "account::json_tests::account_id_json_roundtrips_large_multisig_as_canonical_i105",
            "account::json_tests::account_id_value_and_map_key_json_decoders_are_borrowed_and_measured",
            "account::json_tests::canonical_account_public_parser_preserves_original_address_cause_and_diagnostics"),
    }
    assert registered[mid].tests == rules[mid]
    assert not registered[mid].scenarios
    owners = {p.relative_to(model / "src").as_posix() for p in (model / "src").rglob("*.rs")
              if f'sumeragi_model_mutation = "{mid}"' in p.read_text()}
    assert owners == {path}
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == 1
    kernel = source.split(function, 1)[1].split("    #[test]", 1)[0]
    assert f'cfg!(all(test, sumeragi_model_mutation = "{mid}"))' in kernel
    assert required in kernel
    assert "DecodeResourceLimit" in kernel
    assert gate.has_switch(mid, model=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    for selector in rules[mid]:
        body = source.split("fn " + selector.rsplit("::", 1)[1] + "()", 1)[1]
        body = body.split("    #[test]", 1)[0]
        assert f'sumeragi_model_mutation = "{mid}"' not in body
    primary = source.split("fn " + MODEL_NAMES[mid].rsplit("::", 1)[1] + "()", 1)[1]
    for text in ("classify_decode_attempt(", "DecodeAttemptErrorKind::EnclosingLimit", "original.with(decode)",
                 "assert_eq!(returned, observed.unwrap())", "pool.reserved_bytes()", "total_allocated_bytes()",
                 "from_json::<", "from_json_key_text", "Value::Bool(false)"):
        assert re.sub(r"\s+", "", text) in re.sub(r"\s+", "", primary)


@pytest.mark.parametrize("mid", ["DM21", "DM22"])
@pytest.mark.parametrize("status,verdict", [("pass", "survived"), ("fail", "killed_by_test"), ("execution-error", "error"), ("missing-test", "error"), ("timeout", "error")])
def test_account_resource_mutation_gate_requires_declared_native_results(monkeypatch, tmp_path, mid, status, verdict):
    """No missing/failed execution can masquerade as an account custody kill."""
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args, **kwargs: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args, **kwargs: gate.Step(status=status, failed=list(rule.tests) if status == "fail" else []))
    args = SimpleNamespace(norito=False, core=False, daemon=False, model=True, sdk=False, deploy=False, torii=False,
                           core_profile="test", model_profile="test", fast=True, jobs=1, timeout_test=900,
                           rand_timeout=3600, build_timeout=1200, target_dir=tmp_path, seed_count=200,
                           output=tmp_path / "result.json", require_all=False, strict=True)
    assert gate.evaluate(args, tmp_path, rule)["verdict"] == verdict


@pytest.mark.parametrize("mid,owner,count,causal", [
    ("DM23", "fn decode_i105_literal_with_embedded_discriminant(", 3,
     "a numeric I105 resource refusal must terminate before later candidate allocations"),
    ("DM24", "fn decode_i105_literal(", 1,
     "expected I105 prefix diagnostics must not allocate another payload after resource refusal"),
])
def test_i105_terminal_resource_mutations_keep_distinct_owning_phases_and_genuine_controls(mid, owner, count, causal):
    """Each omission restores only its original post-refusal candidate or diagnostic work."""
    path = ROOT / "crates/iroha_data_model/src/account/address.rs"
    source = path.read_text()
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    assert rule.tests == (MODEL_NAMES[mid],)
    assert not rule.scenarios
    assert gate.has_switch(mid, model=True)
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == count
    kernel = source.split(owner, 1)[1].split("fn numeric_i105_sentinel_candidate(", 1)[0]
    if mid == "DM24":
        kernel = kernel.split("fn decode_i105_literal_with_embedded_discriminant(", 1)[0]
    normalized = re.sub(r"\s+", "", kernel)
    variable = "err" if mid == "DM23" else "error"
    assert normalized.count(f'if{variable}.is_decode_resource_limit()&&!cfg!(all(test,sumeragi_model_mutation="{mid}"))') == count
    other = "DM24" if mid == "DM23" else "DM23"
    assert f'sumeragi_model_mutation = "{other}"' not in kernel
    control = source.split("fn " + MODEL_NAMES[mid].rsplit("::", 1)[1] + "()", 1)[1].split("    #[test]", 1)[0]
    assert causal in control
    assert f'sumeragi_model_mutation = "{mid}"' not in control
    for text in ("observed_i105_terminal_refusal", "actual_requests", "expected_requests", "original.with(",
                 "before_retry", "consumed_allocated_bytes()", "source_pointer", "pool.reserved_bytes()"):
        assert re.sub(r"\s+", "", text) in re.sub(r"\s+", "", control)
    shared = source.split("fn observed_i105_terminal_refusal(", 1)[1].split("fn first_i105_controller_charge(", 1)[0]
    for text in ("amx_prepare_streaming_allocations::measured", "classify_decode_attempt", "DecodeAttemptErrorKind::EnclosingLimit", "assert_eq!(returned, observed.unwrap())"):
        assert re.sub(r"\s+", "", text) in re.sub(r"\s+", "", shared)


@pytest.mark.parametrize("mid", ["DM23", "DM24"])
@pytest.mark.parametrize("status,failed,verdict", [
    ("pass", "none", "survived"), ("fail", "required", "killed_by_test"),
    ("fail", "unrelated", "error"), ("execution-error", "required", "error"),
    ("missing-test", "none", "error"), ("timeout", "none", "error"),
])
def test_i105_terminal_resource_mutations_require_exact_native_causal_failure(monkeypatch, tmp_path, mid, status, failed, verdict):
    """A surviving, missing, unrelated or crashed control cannot close the custody rule."""
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    failures = list(rule.tests) if failed == "required" else ["unrelated::test"] if failed == "unrelated" else []
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args, **kwargs: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args, **kwargs: gate.Step(status=status, failed=failures))
    args = SimpleNamespace(norito=False, core=False, daemon=False, model=True, sdk=False, deploy=False, torii=False,
                           core_profile="test", model_profile="test", fast=True, jobs=1, timeout_test=900,
                           rand_timeout=3600, build_timeout=1200, target_dir=tmp_path, seed_count=200,
                           output=tmp_path / "result.json", require_all=False, strict=True)
    assert gate.evaluate(args, tmp_path, rule)["verdict"] == verdict


def test_account_cause_mutation_owns_all_actual_parser_address_projections():
    """DM22 must reach final controller refusal instead of mutating an earlier unused error arm."""
    source = (ROOT / "crates/iroha_data_model/src/account.rs").read_text()
    helper = source.split("fn from_address_error(", 1)[1].split("    /// Stable diagnostic label", 1)[0]
    assert source.count('sumeragi_model_mutation = "DM22"') == 1
    assert 'cfg!(all(test, sumeragi_model_mutation = "DM22"))' in helper
    assert 'error.is_decode_resource_limit()' in helper
    assert 'Self::Address(AccountAddressError::DecodeResourceLimit)' in helper
    assert 'Self::Address(error)' in helper
    parser = source.split('pub fn parse_encoded(input: &str)', 1)[1].split('impl fmt::Display for AccountId', 1)[0]
    assert 'AccountIdParseError::Address(' not in parser
    assert '.map_err(AccountIdParseError::Address)' not in parser
    assert parser.count('AccountIdParseError::from_address_error') == 4
    assert 'AccountIdParseError::InvalidFormat' in parser
    assert 'AccountAddressError::ChecksumMismatch' not in parser
    assert '.to_account_controller()' in parser
    assert '.canonical_i105()' in parser
    rules = gate.index_mutations(gate.MODEL_MUTATIONS)
    assert rules['DM22'].tests == (MODEL_NAMES['DM22'],
        'account::json_tests::account_id_json_roundtrips_large_multisig_as_canonical_i105',
        'account::json_tests::account_id_value_and_map_key_json_decoders_are_borrowed_and_measured',
        'account::json_tests::canonical_account_public_parser_preserves_original_address_cause_and_diagnostics')


def test_core_upload_account_key_mutation_owns_only_original_error_projection():
    mid = "HC220"
    name = "upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry"
    selector = "state::account_key_refusal_tests::" + name
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in path.read_text()}
    assert owners == {"state.rs"}
    state = (core / "state.rs").read_text()
    projection = state.split("fn account_key_json_error(", 1)[1].split("impl norito::json::JsonKeyCodec", 1)[0]
    assert 'all(test, sumeragi_core_mutation = "HC220")' in projection
    assert "error.is_decode_resource_limit()" in projection and "terminal(error)" in projection
    assert state.count("account_key_json_error(error,") == 1
    assert state.count('<AccountId as json::JsonObjectKeyOwned>::from_json_key_text(') == 1
    assert "governance_locks_map_json" not in state and "governance_slash_map_json" not in state
    controls = (core / "state/account_key_refusal_tests.rs").read_text()
    assert "fn " + name + "()" in controls
    for evidence in ("SmartContractCodeUploadKey::decode_json_key", "original scoped refusal",
                     "Some(expected)", "DecodeAttemptErrorKind::EnclosingLimit", "returned, observed.unwrap()",
                     "same source and original context retry", "pool.reserved_bytes(), 0"):
        assert evidence in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and selector in rows[0]
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("status,expected", [("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error")])
def test_core_upload_account_key_mutation_requires_its_actual_named_native_result(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC220"]
    rows = ((rule.tests[0], status),)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == expected
    assert result["named"]["selected"] == list(rule.tests)
    assert result["named"]["ran"] == sorted(name for name, state in rows if state != "ignored")
    assert result["named"]["failed"] == sorted(name for name, state in rows if state == "FAILED")


def test_native_pulse_demand_mutation_has_a_distinct_owner_and_rule():
    """Merged governance and allocation controls must select independent mutations."""
    mid = "HC224"
    name = "pending_parliament_slots_create_no_native_control_demand_and_never_block_unrelated_work"
    selector = "sumeragi::epoch_beacon::producer::tests::execution_tests::" + name
    ids = [rule.id for rule in gate.CORE_MUTATIONS]
    assert len(ids) == len(set(ids))
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    assert rules[mid].tests == (selector,) and not rules[mid].scenarios
    assert rules["HC220"].tests == (
        "state::account_key_refusal_tests::upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry",
    )
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if f'sumeragi_core_mutation = "{mid}"' in path.read_text()}
    assert owners == {"sumeragi/epoch_beacon.rs"}
    source = (core / "sumeragi/epoch_beacon.rs").read_text()
    assert source.count('sumeragi_core_mutation = "HC224"') == 2
    assert 'sumeragi_core_mutation = "HC220"' not in source
    controls = (core / "sumeragi/epoch_beacon/producer/execution_tests.rs").read_text()
    assert "fn " + name + "()" in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("mid,path,delegation,causal", [
    ("DM25", "json_key_codec.rs", "<Self as json::JsonObjectKeyOwned>::from_json_key_text(encoded)",
     "AccountId storage key must retain its original scoped refusal"),
    ("DM26", "role.rs", "<AccountId as norito::json::JsonObjectKeyOwned>::from_json_key_text(account_raw)",
     "Role assignment storage key must retain its original account scoped refusal"),
    ("DM27", "json_helpers.rs", "BTreeMap::<AccountId, Metadata>::json_deserialize(parser)",
     "Kaigi participant metadata must retain its original account scoped refusal"),
])
def test_persisted_account_json_mutations_own_only_typed_refusal_at_canonical_delegation(mid, path, delegation, causal):
    """No source omission restores a retired parser or mints a new provenance owner."""
    model = ROOT / "crates/iroha_data_model/src"
    source = (model / path).read_text()
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    assert rule.tests == (MODEL_NAMES[mid],)
    assert not rule.scenarios
    hooks = {p.relative_to(model).as_posix() for p in model.rglob("*.rs")
             if f'sumeragi_model_mutation = "{mid}"' in p.read_text()}
    assert hooks == {path}
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == 1
    owner = re.split(r"\n\s*error\s*\n\s*}", source.split(delegation, 1)[1], maxsplit=1)[0]
    assert f'cfg!(all(test, sumeragi_model_mutation = "{mid}"))' in owner
    assert "::ScopedDecodeResource(_)" in owner and "::DecodeResource(_)" in owner
    assert "::Message(error.to_string())" in owner
    assert not any(name in owner for name in ("parse_encoded", "Value::", "with_decode_limits", "AllocationBudget", "unsafe"))
    assert gate.has_switch(mid, model=True)
    for family in ("core", "daemon", "sdk", "deploy", "torii", "norito"):
        assert not gate.has_switch(mid, **{family: True})
    selector = MODEL_NAMES[mid]
    control_path = model / ("kaigi.rs" if mid == "DM27" else path)
    body = control_path.read_text().split("fn " + selector.rsplit("::", 1)[1] + "()", 1)[1].split("    #[test]", 1)[0]
    assert causal in body
    assert f'sumeragi_model_mutation = "{mid}"' not in body
    for required in ("DecodeAttemptErrorKind::EnclosingLimit", "returned, observed.unwrap()",
                     "consumed_allocated_bytes", "pool.reserved_bytes()", "original.with("):
        assert re.sub(r"\s+", "", required) in re.sub(r"\s+", "", body)


@pytest.mark.parametrize("mid", ["DM25", "DM26", "DM27", "DM28", "DM29", "DM30", "DM31", "DM32", "DM33"])
@pytest.mark.parametrize("status,failed,verdict", [
    ("pass", "none", "survived"), ("fail", "required", "killed_by_test"),
    ("fail", "unrelated", "error"), ("execution-error", "required", "error"),
    ("missing-test", "none", "error"), ("timeout", "none", "error"),
])
def test_persisted_account_json_mutations_require_exact_native_control(monkeypatch, tmp_path, mid, status, failed, verdict):
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    failures = list(rule.tests) if failed == "required" else ["unrelated::test"] if failed == "unrelated" else []
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args, **kwargs: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *args, **kwargs: gate.Step(status=status, failed=failures))
    args = SimpleNamespace(norito=False, core=False, daemon=False, model=True, sdk=False, deploy=False, torii=False,
                           core_profile="test", model_profile="test", fast=True, jobs=1, timeout_test=900,
                           rand_timeout=3600, build_timeout=1200, target_dir=tmp_path, seed_count=200,
                           output=tmp_path / "result.json", require_all=False, strict=True)
    assert gate.evaluate(args, tmp_path, rule)["verdict"] == verdict


def test_kaigi_record_refusal_controls_use_the_existing_shared_hc32_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    required = (
        'smartcontracts::isi::kaigi::typed_deferral_tests::stored_record_refusal_is_sticky_and_retries_original_json_without_publication',
        'smartcontracts::isi::kaigi::typed_deferral_tests::indexed_record_refusal_preserves_unregister_guard_and_original_retry',
        'state::deserialize::kaigi_typed_deferral_tests::restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot',
    )
    assert rule.tests[4:7] == required
    source = (ROOT / 'crates/iroha_core/src/smartcontracts/isi/kaigi.rs').read_text()
    start = source.index('fn decode_stored_kaigi_record(')
    stop = source.index('fn store_relay_feedback(', start)
    decoder = source[start:stop]
    assert 'norito_decode_attempt_error(error' in decoder
    assert 'value.clone().try_into_any_norito' not in decoder
    assert 'sumeragi_core_mutation' not in decoder
    assert 'ExecutionAttemptError<Error>' in decoder
    for selector in required:
        leaf = selector.rsplit('::', 1)[1]
        owner = ('crates/iroha_core/src/state/deserialize_world_kaigi_deferral_tests.rs'
                 if selector.startswith('state::') else
                 'crates/iroha_core/src/smartcontracts/isi/kaigi/typed_deferral_tests.rs')
        assert (ROOT / owner).read_text().count('fn ' + leaf + '(') == 1
    assert gate.has_switch('HC32', core=True)


def test_kaigi_relay_refusals_use_the_same_owned_hc32_classifier():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    required = (
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::registration_refusal_preserves_original_relay_retirement_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::feedback_refusal_preserves_both_original_relay_rows_and_retry',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json',
        'smartcontracts::isi::kaigi::relay_typed_deferral_tests::checked_record_writer_refusal_keeps_original_create_unpublished_and_retries',
        'state::deserialize::kaigi_relay_typed_deferral_tests::restored_registration_refusal_retains_original_snapshot_and_retry',
        'state::deserialize::kaigi_relay_typed_deferral_tests::restored_allowlist_refusal_retains_original_snapshot_and_retry',
    )
    assert rule.tests[7:13] == required
    assert len(rule.tests) == 19
    source = (ROOT / 'crates/iroha_core/src/smartcontracts/isi/kaigi.rs').read_text()
    for begin, end in [
        ('fn decode_stored_relay_registration(', 'fn decode_stored_relay_feedback('),
        ('fn decode_stored_relay_feedback(', 'fn collect_kaigi_relay_registry('),
        ('fn decode_kaigi_relay_allowlist(', 'fn decode_stored_kaigi_relay_allowlist('),
    ]:
        decoder = source[source.index(begin):source.index(end)]
        assert 'norito_decode_attempt_error(error' in decoder
        assert 'value.clone()' not in decoder
        assert 'ExecutionAttemptError<' in decoder
    start = source.index('fn ensure_manifest_relays_registered(')
    end = source.index('fn ensure_relay_allowed_by_governance_with_graph(', start)
    manifest = source[start:end]
    assert 'decode_stored_relay_registration(&domain_id, &key, stored)' in manifest
    assert 'try_into_any_norito' not in manifest
    assert 'registration.relay_id != hop.relay_id' in manifest
    assert 'registration.bandwidth_class == 0' in manifest
    assert 'registration.hpke_public_key != hop.hpke_public_key' in manifest
    assert gate.has_switch('HC32', core=True)
    for selector in required:
        owner = ('crates/iroha_core/src/state/deserialize_world_kaigi_relay_deferral_tests.rs'
                 if selector.startswith('state::') else
                 'crates/iroha_core/src/smartcontracts/isi/kaigi/relay_typed_deferral_tests.rs')
        assert (ROOT / owner).read_text().count('fn ' + selector.rsplit('::', 1)[1] + '(') == 1


def test_fallible_world_constructor_mutation_owns_the_single_public_result_boundary():
    mid = 'HC221'
    required = (
        'state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source',
        'state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source',
        'state::world_construction_tests::world_constructor_rejects_malformed_kaigi_without_panicking',
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == required and not rule.scenarios
    assert gate.has_switch(mid, core=True) and not gate.has_switch(mid)
    core = ROOT / 'crates/iroha_core/src'
    owners = {path.relative_to(core).as_posix() for path in core.rglob('*.rs')
              if f'sumeragi_core_mutation = "{mid}"' in path.read_text()}
    assert owners == {'state.rs'}
    state = (core / 'state.rs').read_text()
    boundary = state.split('pub fn try_with_execution_budget<D, A, Ad>(', 1)[1].split('fn try_with_assets_on', 1)[0]
    assert boundary.count('Self::try_with_assets_on(') == 1
    assert 'WorldData::try_new_with_execution_budget(execution_budget)?' in boundary
    assert 'all(test, sumeragi_core_mutation = "HC221")' in boundary
    assert 'result.expect("invalid World initialization in restored infallible boundary")' in boundary
    kernel = state.split('fn try_with_assets_on', 1)[1].split('/// Creates a [`World`] populated', 1)[0]
    assert 'sumeragi_core_mutation' not in kernel
    assert 'expect(' not in kernel and 'panic!(' not in kernel and 'assert!(' not in kernel
    assert 'rebuild_kaigi_relay_registry(&mut world)' in kernel
    assert 'rebuild_kaigi_account_dependencies(&mut world)' in kernel
    assert kernel.count('error.map_rejection(') == 3
    controls = (core / 'state/world_construction_tests.rs').read_text()
    for selector in required:
        assert controls.count('fn '+selector.rsplit('::', 1)[1]+'(') == 1
    assert 'try_new_owned(' in controls and 'consumed_before_retry' in controls
    assert 'original.release_wait(), expected.release_wait()' in controls
    assert 'json.get().as_ptr(), pointer' in controls
    rows = [row for row in (ROOT / 'specs/sumeragi.md').read_text().splitlines()
            if row.startswith('| HC221 |')]
    assert len(rows) == 1 and all(selector in rows[0] for selector in required)
    assert 'mentions(Path::new("src"), &needle)' in (core.parent / 'build.rs').read_text()
    shared = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    assert tuple(name for name in shared.tests if name in required) == required[:2]


@pytest.mark.parametrize('status,expected', [('ok', 'survived'), ('FAILED', 'killed_by_test'), ('ignored', 'error')])
def test_fallible_world_constructor_mutation_requires_all_actual_named_results(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC221']
    rows = tuple((name, status) for name in rule.tests)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result['verdict'] == expected
    assert result['named']['selected'] == list(rule.tests)
    assert result['named']['ran'] == sorted(name for name, state in rows if state != 'ignored')
    assert result['named']['failed'] == sorted(name for name, state in rows if state == 'FAILED')


def test_kaigi_sns_refusals_use_original_sns_owner_and_shared_hc32():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    required = ('smartcontracts::isi::kaigi::relay_typed_deferral_tests::lineage_refusal_preserves_original_relay_retirement_and_retry', 'smartcontracts::isi::kaigi::relay_typed_deferral_tests::primary_alias_refusal_preserves_original_registration_and_retry')
    assert tuple(name for name in rule.tests if name in required) == required
    assert len(rule.tests) == 19
    source = (ROOT / 'crates/iroha_core/src/smartcontracts/isi/kaigi.rs').read_text()
    for begin, end in [
        ('fn resolve_active_kaigi_account_with_graph(', 'fn accounts_share_active_lineage('),
        ('fn active_relay_subject_domain(', 'fn relay_subject_domain('),
    ]:
        projection = source[source.index(begin):source.index(end)]
        assert 'error.into_attempt_error(|error|' in projection
        assert '.attempt_error_to_instruction_error(' in projection
    sns = (ROOT / 'crates/iroha_core/src/sns.rs').read_text()
    start = sns.index('fn sns_decode_error(')
    stop = sns.index('impl From<PricingError>', start)
    assert 'norito_decode_attempt_error(error' in sns[start:stop]
    assert gate.has_switch('HC32', core=True)
    owner = (ROOT / 'crates/iroha_core/src/smartcontracts/isi/kaigi/relay_typed_deferral_tests.rs').read_text()
    for selector in required:
        assert owner.count('fn ' + selector.rsplit('::', 1)[1] + '(') == 1
    assert 'relay_attempt(checkpoint, &relay, &registration, &mut transaction)' in owner
    assert 'relay_prefix(' in owner and 'lineage_prefix.checked_add(row_prefix)' in owner


def test_json_scoped_attempt_delegates_original_error_to_existing_hc32_owner():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    positive = 'execution_attempt::tests::json_scoped_refusal_preserves_original_context_source_and_retry'
    negative = 'execution_attempt::tests::json_stale_scoped_refusal_keeps_its_original_tag_without_retry_authority'
    assert tuple(name for name in rule.tests if name == positive) == (positive,)
    assert len(rule.tests) == 19
    assert negative not in rule.tests
    source = (ROOT / 'crates/iroha_core/src/execution_attempt.rs').read_text()
    start = source.index('pub(crate) fn json_decode_attempt_error<E>(')
    stop = source.index('pub(crate) fn genesis_read_attempt_error<E>(', start)
    decoder = source[start:stop]
    assert 'norito::json::Error::ScopedDecodeResource(original)' in decoder
    assert 'norito_decode_attempt_error(' in decoder
    assert 'norito::Error::ScopedDecodeResource(original)' in decoder
    assert 'rejected(norito::json::Error::from_decode_resource(original))' in decoder
    assert 'classify_decode_attempt(' not in decoder
    assert 'sumeragi_core_mutation' not in decoder
    assert gate.has_switch('HC32', core=True)
    owner = (ROOT / 'crates/iroha_core/src/execution_attempt/json_scoped_tests.rs').read_text()
    for name in (positive, negative):
        assert owner.count('fn ' + name.rsplit('::', 1)[1] + '(') == 1
    assert 'try_new_owned' in owner and 'source.as_slice().as_ptr()' in owner
    assert 'assert_eq!(returned, tag)' in owner


def test_live_manifest_dependency_refusal_uses_original_world_bridge_and_hc32():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC32']
    required = 'smartcontracts::isi::kaigi::relay_typed_deferral_tests::live_manifest_dependency_refusal_preserves_original_route_and_retry'
    assert tuple(name for name in rule.tests if name == required) == (required,) and len(rule.tests) == 19
    owner = ROOT / 'crates/iroha_core/src/smartcontracts/isi/kaigi/relay_lifecycle_guard_v1.rs'
    source = owner.read_text().split('#[cfg(test)]', 1)[0]
    assert source.count('validate_indexed_kaigi_dependency(') == 1
    assert '.attempt_error_to_instruction_error(error)' in source and 'state_transaction' in source and '.world' in source
    assert 'sumeragi_core_mutation' not in source
    assert 'manifest.hops.iter().any(|hop| &hop.relay_id == relay_id)' in source
    tests = (owner.parent / 'relay_typed_deferral_tests.rs').read_text()
    assert tests.count('fn live_manifest_dependency_refusal_preserves_original_route_and_retry(') == 1
    assert 'RegisterKaigiRelay { relay: rotated' in tests
    assert 'the completed live-route guard' in tests
    assert gate.has_switch('HC32', core=True)


def test_partial_native_amx_worker_custody_has_one_owned_omission_and_all_three_actual_controls():
    required = ('sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_controls_and_release_wait', 'sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_completed_source_prefix_without_reallocation', 'sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_multisig_member_prefix_without_reallocation')
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC222']
    assert rule.tests == required and not rule.scenarios
    assert gate.has_switch('HC222', core=True)
    assert not gate.has_switch('HC222') and not gate.has_switch('HC222', model=True) and not gate.has_switch('HC222', daemon=True)
    core = ROOT / 'crates/iroha_core/src'
    owners = {path.relative_to(core).as_posix() for path in core.rglob('*.rs')
              if 'sumeragi_core_mutation = "HC222"' in path.read_text()}
    assert owners == {'sumeragi/amx/native/retry.rs'}
    source = (core / 'sumeragi/amx/native/retry.rs').read_text()
    boundary = source.split('let leg = match super::decode_retained_leg(', 1)[1].split('// No fallible work', 1)[0]
    assert boundary.count('sumeragi_core_mutation = "HC222"') == 1
    assert 'Err(error) =>' in boundary and 'self.bank.pending = None' in boundary
    assert 'get_mut(index)' in boundary and '= None' in boundary
    assert 'return Err(LegExecutionError::Decode(error));' in boundary
    assert 'AllocationBudget::new' not in boundary and 'set_limit_bytes' not in boundary
    model = (ROOT / 'crates/iroha_data_model/src/sumeragi_amx/native/leg_decode.rs').read_text()
    assert 'sumeragi_core_mutation' not in model
    assert tuple(re.findall(r'sumeragi_model_mutation\s*=\s*"([^"]+)"', model)) == ('DM33',)
    assert 'workspace: Option<PreparedDecodeWorkspace>' in model
    assert 'ncore::RetainedElementSequence' in model
    controls = (core / 'sumeragi/executor_amx_retry_tests.rs').read_text()
    for name in required:
        assert controls.count('fn '+name.rsplit('::', 1)[1]+'(') == 1
    assert 'partial AMX Worker decoder must not wake its own original refusal by retiring original controls' in controls
    assert 'partial AMX Worker decoder must retain every original completed source/member allocation without waking its own refusal' in controls
    assert 'allocations_during' in controls and 'Poll::Pending' in controls
    rows = [row for row in (ROOT / 'specs/sumeragi.md').read_text().splitlines() if row.startswith('| HC222 |')]
    assert len(rows) == 1 and all(name in rows[0] for name in required)
    assert 'mentions(Path::new("src"), &needle)' in (core.parent / 'build.rs').read_text()


@pytest.mark.parametrize('status,expected', [('ok', 'survived'), ('FAILED', 'killed_by_test'), ('ignored', 'error')])
def test_partial_native_amx_worker_custody_requires_every_declared_native_result(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC222']
    rows = tuple((name, status) for name in rule.tests)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result['verdict'] == expected
    assert result['named']['selected'] == list(rule.tests)
    assert result['named']['ran'] == sorted(name for name, state in rows if state != 'ignored')
    assert result['named']['failed'] == sorted(name for name, state in rows if state == 'FAILED')


def test_original_native_amx_worker_replay_owns_parked_resumption_and_preserves_captured_classifier():
    name = 'sumeragi::executor::amx_retry_tests::rejected_amx_worker_occurrence_retains_source_prefix_and_replays_before_later_partial_occurrence'
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC223']
    assert rule.tests == (name,) and not rule.scenarios
    assert gate.has_switch('HC223', core=True) and not gate.has_switch('HC223')
    assert not gate.has_switch('HC223', model=True) and not gate.has_switch('HC223', daemon=True)
    core = ROOT / 'crates/iroha_core/src'
    owners = {path.relative_to(core).as_posix() for path in core.rglob('*.rs')
              if 'sumeragi_core_mutation = "HC223"' in path.read_text()}
    assert owners == {'sumeragi/amx/native/retry.rs'}
    native = (core / 'sumeragi/amx/native.rs').read_text()
    assert 'fn leg_decode_is_completed_rejection(' not in native
    classifier = native.split('fn leg_decode_error(', 1)[1].split('fn ', 1)[0]
    assert 'canonical_decode_attempt_error' in classifier
    source = (core / 'sumeragi/amx/native/retry.rs').read_text()
    assert 'parked: Option<ChargedBuffer<Option<PendingOccurrence>>>' in source
    boundary = source.split('sumeragi_core_mutation = "HC223"', 1)[1].split('if parked.is_none()', 1)[0]
    assert 'if parked.is_some()' in boundary and 'return Err(LegExecutionError::Invariant)' in boundary
    assert '.pending = None' not in boundary and 'decode_retained_leg' not in boundary
    assert 'AllocationBudget::new' not in source and 'set_limit_bytes' not in source
    control = (core / 'sumeragi/executor_amx_retry_tests.rs').read_text()
    assert control.count('fn '+name.rsplit('::', 1)[1]+'(') == 1
    replay = control.split('fn '+name.rsplit('::', 1)[1]+'(', 1)[1].split('fn original_quantity_layout(', 1)[0]
    assert 'proposal_with_transactions' in replay
    assert 'chain.sign(&customer, [invalid.into()], time)' in replay
    assert 'chain.sign(&customer, [instruction], time + 1)' in replay
    assert 'worker.run_execution' in replay and 'partial_snapshot' in replay
    assert 'replayed A must produce its canonical rejection while B remains retained' in replay
    assert "whole-block replay preserves B's exact original refusal and release generation" in replay
    assert replay.count('reject_a(&mut bank)') == 3
    assert 'Poll::Pending' in replay and 'Poll::Ready(())' in replay
    assert 'bank.matches_original' in replay and 'partial_metadata_bytes' in replay
    rows = [row for row in (ROOT / 'specs/sumeragi.md').read_text().splitlines() if row.startswith('| HC223 |')]
    assert len(rows) == 1 and name in rows[0]


@pytest.mark.parametrize('status,expected', [('ok', 'survived'), ('FAILED', 'killed_by_test'), ('ignored', 'error')])
def test_original_native_amx_worker_replay_requires_its_actual_named_result(monkeypatch, tmp_path, status, expected):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)['HC223']
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    code, output = exact_control_output(((rule.tests[0], status),))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    args = SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=5, fast=True)
    result = gate.evaluate(args, tmp_path, rule)
    assert result['verdict'] == expected
    assert result['named']['selected'] == list(rule.tests)


def test_native_multisig_semantic_mutation_owns_only_the_original_cause_projection():
    mid = "DM33"
    prefix = "sumeragi_amx::native::leg_decode::tests::"
    leaves = (
        "invalid_native_multisig_threshold_replay_preserves_original_cause_without_diagnostic_allocations",
        "invalid_native_multisig_member_replay_preserves_original_cause_without_diagnostic_allocations",
    )
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)[mid]
    assert rule.tests == tuple(prefix + leaf for leaf in leaves) and not rule.scenarios
    assert gate.has_switch(mid, model=True)
    for family in ("core", "daemon", "sdk", "deploy", "torii", "norito"):
        assert not gate.has_switch(mid, **{family: True})
    model = ROOT / "crates/iroha_data_model/src"
    owners = {path.relative_to(model).as_posix() for path in model.rglob("*.rs")
              if f'sumeragi_model_mutation = "{mid}"' in path.read_text()}
    assert owners == {"sumeragi_amx/native/leg_decode.rs"}
    source = (model / "sumeragi_amx/native/leg_decode.rs").read_text()
    owner = source.split("fn policy_error(", 1)[1].split("fn scope(", 1)[0]
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == 1
    assert 'cfg!(all(test, sumeragi_model_mutation = "DM33"))' in owner
    assert 'norito::Error::Message(error.to_string()).into()' in owner
    assert 'Error::Multisig(error)' in owner
    assert 'Multisig(#[from] crate::account::MultisigPolicyError)' in source
    tests = (model / "sumeragi_amx/native/leg_decode/tests.rs").read_text()
    helper = tests.split("fn assert_multisig_semantic_replay_has_no_diagnostic_allocation(", 1)[1]
    for proof in ('measured(|| pending.decode(&frame))', 'pool.limit_bytes()',
                  'pending.original_source_identity()', 'values_pointer', 'ledger_pointer',
                  'key_pointer', 'workspace', 'ordinary_message', 'Some(original_span_bytes(&original))',
                  'retained multisig semantic replay must not allocate a diagnostic or replacement backing'):
        assert re.sub(r"\s+", "", proof) in re.sub(r"\s+", "", helper)
    assert f'sumeragi_model_mutation = "{mid}"' not in tests
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(prefix + leaf in rows[0] for leaf in leaves)
    core = (ROOT / "crates/iroha_core/src/sumeragi/amx/native.rs").read_text()
    assert 'AmxLegDecodeErrorV1::Multisig(error) => invalid(error.to_string())' in core


def test_push_retry_mutation_has_exact_retained_operation_owner():
    mid = "TOR4"
    selector = "push::tests::push_replay_late_capacity_retains_original_frame_and_waits_for_external_release"
    rule = gate.index_mutations(gate.TORII_MUTATIONS)[mid]
    verification = "push::tests::push_replay_verification_slot_capacity_preserves_original_wait_and_resumes"
    assert rule.tests == (selector, verification) and not rule.scenarios
    assert gate.has_switch(mid, torii=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"model": True},
                   {"sdk": True}, {"deploy": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    source = ROOT / "crates/iroha_torii"
    owners = {path.relative_to(source / "src").as_posix()
              for path in (source / "src").rglob("*.rs")
              if f'sumeragi_torii_mutation = "{mid}"' in path.read_text()}
    assert owners == {"push.rs"}
    native = (source / "src/push.rs").read_text()
    assert all("fn " + name.rsplit("::", 1)[-1] + "(" in native for name in rule.tests)
    build = (source / "build.rs").read_text()
    declared = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert declared is not None
    ids = re.findall(r'"(TOR[0-9]+)"', declared.group(1))
    assert ids == [rule.id for rule in gate.TORII_MUTATIONS]
    rows = re.findall(r"^\| TOR4 \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("damage,verdict", [
    ("none", "killed_by_test"), ("incidental_only", "error"),
    ("missing", "error"), ("ignored", "error"),
])
@pytest.mark.parametrize("mid", ["TOR4", "TOR5"])
def test_push_named_kill_requires_declared_control(
    monkeypatch, tmp_path, damage, verdict, mid
):
    rule = gate.index_mutations(gate.TORII_MUTATIONS)[mid]
    rows = [(name, "FAILED") for name in rule.tests]
    if damage == "incidental_only":
        rows = [(name, "ok") for name in rule.tests]
    elif damage == "missing":
        rows.clear()
    elif damage == "ignored":
        rows[0] = (rule.tests[0], "ignored")
    rows.append((rule.tests[0] + "_incidental", "FAILED"))
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    result = gate.evaluate(SimpleNamespace(torii=True, target_dir=tmp_path,
                          timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert "scenario" not in result
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == sorted(rule.tests)
    elif damage == "incidental_only":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    else:
        assert result["reason"] == "named tests: missing-test"


def test_push_genesis_mutation_has_own_lifecycle_controls():
    mid = "TOR5"
    rule = gate.index_mutations(gate.TORII_MUTATIONS)[mid]
    assert rule.tests == (
        "push::tests::push_worker_genesis_bootstrap_waits_for_authenticated_successor_and_shutdown",
        "push::tests::push_worker_genesis_bootstrap_rejects_corrupt_history_and_nonzero_cursor",
    ) and not rule.scenarios
    assert gate.has_switch(mid, torii=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"model": True},
                   {"sdk": True}, {"deploy": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    source = ROOT / "crates/iroha_torii/src"
    owners = {path.relative_to(source).as_posix() for path in source.rglob("*.rs")
              if f'sumeragi_torii_mutation = "{mid}"' in path.read_text()}
    assert owners == {"push.rs"}
    native = (source / "push.rs").read_text()
    assert all("fn " + name.rsplit("::", 1)[-1] + "(" in native for name in rule.tests)
    rows = re.findall(r"^\| TOR5 \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


SCCP_LIFECYCLE_MUTATIONS = (('HC225', 'outbound.rs', 'smartcontracts::isi::sccp::outbound::tests::degraded_parent_refuses_before_money_nonce_or_leaf_and_recovers'), ('HC226', 'hook.rs', 'smartcontracts::isi::sccp::hook::tests::native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor'), ('HC227', 'generations.rs', 'smartcontracts::isi::sccp::generations::tests::resync_uses_real_native_parent_time_then_boundary_rotates_again'), ('HC228', 'hook.rs', 'smartcontracts::isi::sccp::hook::tests::degraded_hook_still_appends_original_parent_anchor_and_recovers_without_rotation'), ('HC229', 'hook.rs', 'smartcontracts::isi::sccp::hook::tests::begin_block_clamps_halt_time_using_original_native_parent'), ('HC230', 'generations.rs', 'smartcontracts::isi::sccp::generations::tests::handoff_resolves_original_registration_for_successor_tenure_and_freezes_it'), ('HC231', 'height.rs', 'smartcontracts::isi::sccp::height::tests::height_capture_preserves_original_graph_without_admission_at_full_pool'))


@pytest.mark.parametrize("mid,owner,selector", SCCP_LIFECYCLE_MUTATIONS)
def test_sccp_lifecycle_mutation_has_exact_core_owner_and_causal_control(mid, owner, selector):
    """New lifecycle rules use the existing strict Core family and no shipping switch."""
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    assert rules[mid].tests == (selector,)
    assert not rules[mid].scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if needle in path.read_text()}
    assert owners == {"smartcontracts/isi/sccp/" + owner}
    source = (core / "smartcontracts/isi/sccp" / owner).read_text()
    assert source.count(needle) == 1
    assert f'cfg!(all(test, {needle}))' in source
    control_path = (core / "smartcontracts/isi/sccp/generations/tests.rs"
                    if owner == "generations.rs" else core / "smartcontracts/isi/sccp" / owner)
    assert control_path.read_text().count("fn " + selector.rsplit("::", 1)[1] + "(") == 1
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'CARGO_FEATURE_MUTATION_TESTING' in build
    assert 'mentions(Path::new("src"), &needle)' in build
    assert gate.package_options(SimpleNamespace(core=True)) == (
        "iroha_core", "mutation-testing,iroha-core-tests", "SUMERAGI_CORE_MUTATION"
    )


@pytest.mark.parametrize("mid,owner,selector", SCCP_LIFECYCLE_MUTATIONS)
@pytest.mark.parametrize("outcome,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"),
    ("missing", "error"), ("ignored", "error"), ("incidental", "error"),
])
def test_sccp_lifecycle_kill_requires_actual_declared_result(
    monkeypatch, tmp_path, mid, owner, selector, outcome, verdict
):
    """A discovery row or unrelated failure cannot substitute for a real named kill."""
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    if outcome == "missing":
        rows = [(selector + "_incidental", "FAILED")]
    elif outcome == "incidental":
        rows = [(selector, "ok"), (selector + "_incidental", "FAILED")]
    else:
        rows = [(selector, outcome)]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path,
                          timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == [selector]
    assert result["named"]["selected"] == sorted(name for name, _ in rows)
    assert "scenario" not in result
    if verdict == "killed_by_test":
        assert result["named"]["required_failed"] == [selector]
    elif outcome == "incidental":
        assert result["reason"] == "named tests: only additional substring-selected tests failed"
    elif outcome in ("missing", "ignored"):
        assert result["reason"] == "named tests: missing-test"


def test_sccp_rotation_header_control_executes_signed_native_heartbeat_work():
    """Header generation is checked after the real seal/QC/persistence, not only a plan."""
    source = (ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs").read_text()
    name = "native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor"
    body = source.split("fn " + name + "()", 1)[1].split("\n    fn assert_native_certificate_projection", 1)[0]
    assert "CertifiedTestChain::start(native_init_config(SumeragiRootScope::Global))" in body
    assert "chain.commit_at(time, Vec::new())" in body
    assert "chain.commit_at(time + 1_000, Vec::new())" in body
    assert body.count("network_entrypoint_count() > 0") == 2
    assert body.count("certified_result().header()") == 2
    assert "assert_native_certificate_projection(&chain, 2, 1, true)" in body
    assert "assert_native_certificate_projection(&chain, 3, 2, false)" in body
    assert '"X certifies the outgoing generation"' in body
    assert '"only the successor height uses G2"' in body
    assert "header.next_committee_root()" in body and "next.start_height" in body
    assert not any(shortcut in body for shortcut in (
        "setup_world_at", "finalize_block(", "SccpHeightInputsV1 {", "sumeragi_core_mutation"
    ))


def test_terminal_verification_slot_mutation_has_exact_owner_and_both_native_controls():
    mid = "HC232"
    prefix = "sumeragi::certified_chain::terminal_selection::tests::"
    selectors = tuple(prefix + name for name in (
        "terminal_target_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel",
        "terminal_gap_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel",
    ))
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == selectors and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if needle in path.read_text()}
    assert owners == {"sumeragi/certified_chain/terminal_selection.rs"}
    source = (core / "sumeragi/certified_chain/terminal_selection.rs").read_text()
    assert source.count(needle) == 1
    assert f'#[cfg(all(test, {needle}))]' in source
    assert "frame: AdmittedFrameRead" in source
    assert "self.frame.initialize(" in source
    assert "self.frame.take_committed()" in source
    mutation = source.split(needle, 1)[1].split("return Err(cause)", 1)[0]
    assert "ExecutionAttemptError::Deferred(_)" in mutation
    assert "self.frame = AdmittedFrameRead::default();" in mutation
    assert "AllocationBudget::new" not in source
    tests = (core / "sumeragi/certified_chain/terminal_selection/tests.rs").read_text()
    assert all(tests.count("fn " + name.rsplit("::", 1)[1] + "(") == 1
               for name in selectors)
    control = tests.split("fn terminal_late_result_slot(", 1)[1]
    for requirement in ("reader.certified_terminal_amx(3)", "wait_for_release(&mut registration)",
                        "Poll::Pending", "Poll::Ready(())", "SharedSignedBlock::ptr_eq",
                        "original.allocation_refusal()", "baseline + occupied_bytes",
                        "delivered.result(), expected_result", "delivered.block_hash(), expected_hash"):
        assert requirement in control
    rows = re.findall(r"^\| HC232 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in selectors)
    assert gate.package_options(SimpleNamespace(core=True)) == (
        "iroha_core", "mutation-testing,iroha-core-tests", "SUMERAGI_CORE_MUTATION"
    )
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    assert 'CARGO_FEATURE_MUTATION_TESTING' in build
    assert 'mentions(Path::new("src"), &needle)' in build


@pytest.mark.parametrize("statuses,verdict", [
    (("ok", "ok"), "survived"),
    (("FAILED", "FAILED"), "killed_by_test"),
    (("FAILED", "ok"), "killed_by_test"),
    (("ok", "FAILED"), "killed_by_test"),
    (("ignored", "FAILED"), "error"),
    (("FAILED", "ignored"), "error"),
    (("missing", "FAILED"), "error"),
    (("FAILED", "missing"), "error"),
    (("incidental", "ok"), "error"),
])
def test_terminal_verification_slot_kill_requires_complete_native_accounting(
    monkeypatch, tmp_path, statuses, verdict
):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC232"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)
            for name, status in zip(rule.tests, statuses) if status != "missing"]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path,
                          timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


@pytest.mark.parametrize("mid,name,retirement", [
    ("HC233", "native_cursor_genesis_result_slot_refusal_retains_original_source_until_release", "self.initializing = None;"),
    ("HC234", "native_cursor_successor_result_slot_refusal_retains_original_source_until_release", "original.acquiring = None;"),
])
def test_native_cursor_retention_mutations_have_original_owner_and_causal_controls(mid, name, retirement):
    selector = "sumeragi::finality::cursor::tests::" + name
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs") if needle in path.read_text()}
    assert owners == {"sumeragi/finality/cursor.rs"}
    source = (core / "sumeragi/finality/cursor.rs").read_text()
    assert source.count(needle) == 1
    assert f'#[cfg(all(test, {needle}))]' in source
    mutation = source.split(needle, 1)[1].split("?;", 1)[0]
    assert "ProofError::Deferred(_)" in mutation and retirement in mutation
    assert "AllocationBudget::new" not in source.split("#[cfg(test)]\nmod tests", 1)[0]
    for requirement in ("AdmittedPrefixInitialization", "AdmittedPrefixPush", "matches_owner(view.kura()",
                        "original.carrier.recheck(view, budget)?", "recheck_original_source()",
                        "MAX_CHAIN_ID_BYTES", "ChainIdentity::new(view.chain_id())"):
        assert requirement in source
    control = re.sub(r"\s+", "", source.split("fn native_cursor_late_result_slot(", 1)[1])
    for requirement in ("CertifiedTestChain::start", "chain.commit_at(20_000", "wait_for_release(&mut registration)",
                        "Poll::Pending", "Poll::Ready(())", "repeated.allocation_refusal(), cause.allocation_refusal()",
                        "cursor.original.is_none()", "native_height, 1", "Arc::ptr_eq(chain.kura(), foreign.kura())",
                        "current.native_block().block_hash(), hash", "current.native_block().result(), result",
                        "pointers.borrow()[0], pointers.borrow()[1]", "budget.reserved_bytes(), 0"):
        assert re.sub(r"\s+", "", requirement) in control
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]
    state = (core / "state.rs").read_text()
    assert state.count("kura: &'state Arc<Kura>") == 4
    handle = state.split("macro_rules! impl_state_ro", 1)[1].split("fn kura_handle(&self) -> Arc<Kura> {", 1)[1].split("}", 1)[0]
    assert "Arc::clone(self.kura)" in handle
    acquisition = (core / "sumeragi/certified_chain/native_acquisition.rs").read_text()
    assert acquisition.count("decode_framed_signed_block(") == 1
    assert "KuraOwner::Owned(kura)" in acquisition and "self.budget.same_pool(budget)" in acquisition
    storage = (core / "kura/native_execution_reads.rs").read_text()
    assert storage.count("let confirmed = store.read_block_index(position)?;") == 1
    assert "binding: source.binding" in storage and "kura: Arc::clone(self)" in storage


@pytest.mark.parametrize("mid", ["HC233", "HC234"])
@pytest.mark.parametrize("status,verdict", [("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error")])
def test_native_cursor_retention_kill_requires_actual_named_control(monkeypatch, tmp_path, mid, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    name = rule.tests[0]
    rows = [] if status == "missing" else [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_native_cursor_output_retention_has_original_owner_and_causal_control():
    mid = "HC235"
    selector = "sumeragi::finality::cursor::tests::native_cursor_output_shell_refusal_retains_projection_and_observes_new_tip"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {"sumeragi/finality/cursor.rs"}
    source = (core / "sumeragi/finality/cursor.rs").read_text()
    assert source.count(needle) == 1
    assert f'#[cfg(all(test, {needle}))]' in source
    mutation = source.split(needle, 1)[1].split("completed?", 1)[0]
    assert "ProofError::Deferred(_)" in mutation and "self.projecting = None;" in mutation
    compact = re.sub(r"\s+", "", source)
    for obligation in (
        "projecting: Option<OutputRead>", "original.finish_output(view, budget, deadline, current)?",
        "if original.native_height == target", "drop(completed)",
        "checkpoint: Option<SumeragiFinalityCheckpoint>", "carrier: Option<Carrier>",
        "admit_verification_slot(budget).map_err(ProofError::from)?",
        "coherent_height(view)? != current", "verified.block().hash() != *hash",
        "receipt.result() != verified.result()", "receipt.id().0.as_ref() != verified.context_id().as_ref()",
        "read_frame(durable.clone(), *height, verified.root_scope())",
    ):
        assert re.sub(r"\s+", "", obligation) in compact
    production = source.split("#[cfg(test)]\nmod tests", 1)[0]
    assert "AllocationBudget::new" not in production and "bounded_native_carrier(" not in production
    output = source.split("struct OutputRead {", 1)[1].split("impl OutputRead", 1)[0]
    assert output.index("output:") < output.index("custody:")
    assert output.index("checkpoint:") < output.index("custody:")
    assert output.index("carrier:") < output.index("custody:")
    control = re.sub(r"\s+", "", source.split("fn native_cursor_output_refusal(", 1)[1])
    for obligation in (
        "CertifiedTestChain::start", "chain.commit_at(20_000", "chain.commit_at(30_000",
        "wait_for_release(&mut registration)", "Poll::Pending", "Poll::Ready(())",
        "repeated.allocation_refusal(), cause.allocation_refusal()",
        "canonical_query_reads_for_test(), reads", "current.native_block().result(), expected_result",
        "current.native_block().block_hash(), expected_hash", "budget.reserved_bytes(), 0",
        "native_cursor_output_refusal(true, false, true)", "native_cursor_output_refusal(true, true, false)",
    ):
        assert re.sub(r"\s+", "", obligation) in control
    rows = re.findall(r"^\| HC235 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("status,verdict", [("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error")])
def test_native_cursor_output_retention_kill_requires_actual_named_control(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC235"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    name = rule.tests[0]
    rows = [] if status == "missing" else [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_native_cursor_pending_retention_has_one_shared_kernel_and_causal_controls():
    mid = "HC236"
    names = tuple("sumeragi::finality::cursor::tests::native_cursor_pending_" + phase +
                  "_refusal_retains_original_graph_and_release"
                  for phase in ("last_key", "envelope", "checkpoint"))
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == names and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {"sumeragi/finality/cursor.rs"}
    source = (core / "sumeragi/finality/cursor.rs").read_text()
    assert source.count(needle) == 1 and f'#[cfg(all(test, {needle}))]' in source
    mutation = source.split(needle, 1)[1].split("completed?", 1)[0]
    assert "ProofError::Deferred(_)" in mutation and "self.preparing = None;" in mutation
    compact = re.sub(r"\s+", "", source)
    for obligation in (
        "preparing: Option<PendingPreparation>", "get_or_insert_with(PendingPreparation::default)",
        "destination: super::proof_destination::ProofPreparation", "checkpoint: Option<SumeragiFinalityCheckpoint>",
        "encoded: Option<ChargedBuffer<u8>>", "custody: Option<DecodeCustody>",
        "self.destination.complete(block, members, budget, deadline)",
        "verifier.verify(&owned.proof)", "verifier.export_checkpoint(&owned.proof)",
        "self.encoded = Some(encode_checkpoint(checkpoint, budget, deadline)?)",
        "ChargedBuffer::new(length, budget).map_err(buffer_error)?",
        "Error::Proof(ProofError::Deferred(cause.into()))", "map_err(allocation_error)?",
    ):
        assert re.sub(r"\s+", "", obligation) in compact
    preparation = source.split("struct PendingPreparation {", 1)[1].split("impl PendingPreparation", 1)[0]
    assert preparation.index("destination:") < preparation.index("custody:")
    assert preparation.index("checkpoint:") < preparation.index("custody:")
    assert preparation.index("encoded:") < preparation.index("custody:")
    kernel = (core / "sumeragi/finality/proof_destination.rs").read_text()
    assert kernel.count("write_canonical_to_writer(") == 1
    assert kernel.count("try_clone_from_charge(") == 1
    assert "original.complete(block, members, budget, deadline)?" in kernel
    for obligation in ("members_address != members.as_ptr() as usize", "!original.owned._charges.belongs_to(budget)",
                       "std::ptr::eq(original.block.as_ref(), block.as_ref())", "if pop.is_none()",
                       "pop.take().expect", "wire_complete", 'sumeragi_core_mutation = "HC213"'):
        assert obligation in kernel
    construction = kernel.split("struct Construction {", 1)[1].split("impl ProofPreparation", 1)[0]
    assert construction.index("pop:") < construction.index("owned:")
    owned = kernel.split("pub(super) struct OwnedProof {", 1)[1].split("impl OwnedProof", 1)[0]
    assert owned.index("proof:") < owned.index("_charges:")
    for body in (source.split("#[cfg(test)]\nmod tests", 1)[0], kernel.split("#[cfg(test)]\nmod tests", 1)[0]):
        assert "AllocationBudget::new" not in body and "mem::forget" not in body
    control = re.sub(r"\s+", "", source.split("fn native_cursor_pending_refusal(", 1)[1])
    for obligation in ("CertifiedTestChain::start", "chain.commit_at(20_000", "wait_for_release(&mut registration)",
                       "Poll::Pending", "Poll::Ready(())", "repeated.allocation_refusal(), Some(&cause)",
                       "pointers.borrow()[0], pointers.borrow()[1]", "checkpoint.as_ref().unwrap().as_slice(), preceding",
                       "current.native_block().result(), result", "current.native_block().block_hash(), hash",
                       "budget.reserved_bytes(), 0"):
        assert re.sub(r"\s+", "", obligation) in control
    assert control.index("Poll::Pending") < control.index("letError::Proof(ProofError::Deferred(deferred))=error")
    proof_tests = (core / "sumeragi/finality/proof_destination/tests.rs").read_text()
    assert "fn original_proof_destination_charges_each_actual_compact_key_before_clone_and_refunds()" in proof_tests
    assert "fn retained_proof_preparation_binds_original_source_and_refunds_partial_key_unwind()" in proof_tests
    assert "catch_unwind" in proof_tests and "&foreign_members" in proof_tests and "genesis.block()" in proof_tests
    rows = re.findall(r"^\| HC236 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in names)


@pytest.mark.parametrize("statuses,verdict", [
    (("ok", "ok", "ok"), "survived"),
    (("FAILED", "ok", "ok"), "killed_by_test"),
    (("ok", "FAILED", "ok"), "killed_by_test"),
    (("ok", "ok", "FAILED"), "killed_by_test"),
    (("FAILED", "FAILED", "FAILED"), "killed_by_test"),
    (("FAILED", "ignored", "ok"), "error"),
    (("FAILED", "ok", "missing"), "error"),
    (("ok", "incidental", "ok"), "error"),
])
def test_native_cursor_pending_retention_accounts_every_named_control(monkeypatch, tmp_path, statuses, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC236"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)
            for name, status in zip(rule.tests, statuses) if status != "missing"]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


@pytest.mark.parametrize("mid,owner", [
    ("HC237", "smartcontracts/isi/world.rs"),
    ("HC238", "smartcontracts/isi/sccp/controls.rs"),
])
def test_sccp_control_mutation_preserves_original_cause_and_pause_owner(mid, owner):
    name = "smartcontracts::isi::world::isi::tests::parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (name,) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {owner}
    source = (core / owner).read_text()
    assert source.count(needle) == 1
    compact = re.sub(r"\s+", "", source)
    assert f'all(test,{needle.replace(" ", "")})' in compact
    if mid == "HC237":
        effect = source.split("fn apply_parliament_proposal_effect_v1(", 1)[1]
        effect = effect.split("ProposalKind::SccpRouteGovernance(payload) => {", 1)[1]
        effect = effect.split("ProposalKind::SorafsProviderGovernance", 1)[0]
        compact_effect = re.sub(r"\s+", "", effect)
        assert re.search(r"GovernanceCertificateId::derive_v1\(certificate,?\)\.as_bytes\(\)", compact_effect)
        assert "effect_hash:certificate.effect_preimage_hash" in compact_effect
        assert "certificate_id:proposal_id,..cause" in compact_effect
        assert effect.index("GovernanceCertificateId::derive_v1") < effect.index(needle)
        assert effect.index(needle) < effect.index("sccp::governance::enact(")
        assert "exact_due_parliament_certificate_context_v1(governance_attempt_id,state_transaction)?" in compact
    else:
        assert f'ifcfg!(all(test,{needle.replace(" ", "")})){{0}}else{{' in compact
        assert "store::fast_pauses::get(&*state_transaction.world,&network).map_or(0,|pause|" in compact
        assert "pause.destination_expiry(revision,state_transaction.block_unix_timestamp_ms())" in compact
        production = source.split("#[cfg(test)]\nmod tests", 1)[0]
        assert "destination_paused =" not in production
        assert "fast_pauses::insert(" not in production
    tests = (core / "smartcontracts/isi/world_sccp_governance_tests.rs").read_text()
    control = tests.split("fn parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state()", 1)[1]
    control = control.split("\n#[test]", 1)[0]
    compact_control = re.sub(r"\s+", "", control)
    for obligation in (
        "seed_due_sccp_control_certificate(&mut seed, paused)",
        "execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)",
        "GovernanceCertificateId::derive_v1(&fixture.certificate).as_bytes()",
        "assert_ne!(expected_id, fixture.proposal_id)",
        'assert_eq!(row.certificate_id, expected_id, "control record must bind the exact enacting governance certificate")',
        "assert_eq!(row.effect_hash, fixture.certificate.effect_preimage_hash)",
        'assert_eq!((row.track, row.parliament_paused, row.fast_pause_until_ms), (1, paused, original_pause.until_ms), "control record must preserve both original pause owners")',
        "assert_eq!(row.leaf, control_leaf(",
        "Some(&original_pause)",
        "event.certificate_id == expected_id", "event.fast_pause_until_ms == original_pause.until_ms",
    ):
        assert re.sub(r"\s+", "", obligation) in compact_control
    spec = (ROOT / "specs/sumeragi.md").read_text()
    rows = re.findall(rf"^\| {mid} \|.*$", spec, re.M)
    assert len(rows) == 1 and name in rows[0]
    assert "| SC5 | CT1 disabled |" in spec and "| SC6 | CT3 builder pacing disabled |" in spec
    # The existing pending-proof custody rule remains an independent live rule.
    assert len(gate.index_mutations(gate.CORE_MUTATIONS)["HC236"].tests) == 3


@pytest.mark.parametrize("mid", ["HC237", "HC238"])
@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error"),
])
def test_sccp_control_kill_requires_actual_stored_certificate_control(monkeypatch, tmp_path, mid, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    name = rule.tests[0]
    rows = [] if status == "missing" else [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_epoch_construction_unwind_mutation_preserves_original_refund_control():
    name = "sumeragi::epoch_election::owned::tests::partial_epoch_committee_unwind_refunds_retired_nested_backing"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC239"]
    assert rule.tests == (name,) and not rule.scenarios
    assert gate.has_switch("HC239", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC239", **family)
    core = ROOT / "crates/iroha_core/src"
    needle = 'sumeragi_core_mutation = "HC239"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {"sumeragi/epoch_election/owned.rs"}
    source = (core / "sumeragi/epoch_election/owned.rs").read_text()
    assert source.count(needle) == 1
    compact = re.sub(r"\s+", "", source)
    assert '#[cfg(all(test,sumeragi_core_mutation="HC239"))]implDropforConstruction' in compact
    assert 'ifstd::thread::panicking(){ifletSome(charges)=self.charges.take(){std::mem::forget(charges);' in compact
    tests = (core / "sumeragi/epoch_election/owned/tests.rs").read_text()
    assert "partial_unwind(ConstructionCheckpoint::NestedCommitteeMember)" in tests
    assert "all partial payload allocations retired before their exact original credit refund" in tests
    rows = re.findall(r"^\| HC239 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and name in rows[0]


@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error"),
])
def test_epoch_construction_unwind_kill_requires_declared_native_control(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC239"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    name = rule.tests[0]
    rows = [] if status == "missing" else [(name + "_incidental", "FAILED") if status == "incidental" else (name, status)]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


_SCCP_HOLD_MUTATION_CONTROLS = {'HC240': {'description': 'SCCP retained fast Taira pause: omit the active network hold from original consumers', 'owner': 'smartcontracts/isi/sccp/hold.rs', 'controls': {'smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects': 'the actual Record instruction must respect the exact active pause', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_holds_inbound_only_without_losing_proof_money_or_retry': 'an active Taira pause must preserve the authenticated inbound as pending', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_keeps_void_refund_pending_without_stranding_or_moving_money': 'fast pause must defer actual refund movement'}}, 'HC241': {'description': 'SCCP retained destination pause: omit the active exact-revision outbound hold', 'owner': 'smartcontracts/isi/sccp/hold.rs', 'controls': {'smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects': 'the actual Record instruction must respect the exact active pause'}}, 'HC242': {'description': 'SCCP committed pause time: substitute the executing timestamp for the original native prefix', 'owner': 'smartcontracts/isi/sccp/hold.rs', 'controls': {'smartcontracts::isi::sccp::hold::tests::committed_pause_time_binds_original_native_prefix_and_ignores_executing_header': 'pause expiry must use the original native prefix time, not the executing header'}}, 'HC243': {'description': 'SCCP eligibility: replace original pre-block facts with the executing writes', 'owner': 'smartcontracts/isi/sccp/eligibility.rs', 'controls': {'smartcontracts::isi::sccp::eligibility_tests::original_eligibility_preimages_survive_siblings_rollback_and_replacement': 'eligibility must retain the original pre-block parameters through local and sibling writes'}}}
_SCCP_HOLD_TEST_FILES = {'smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects': 'smartcontracts/isi/sccp/outbound.rs', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_holds_inbound_only_without_losing_proof_money_or_retry': 'smartcontracts/isi/sccp/settle/tests.rs', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_keeps_void_refund_pending_without_stranding_or_moving_money': 'smartcontracts/isi/sccp/settle/tests.rs', 'smartcontracts::isi::sccp::hold::tests::committed_pause_time_binds_original_native_prefix_and_ignores_executing_header': 'smartcontracts/isi/sccp/hold.rs', 'smartcontracts::isi::sccp::eligibility_tests::original_eligibility_preimages_survive_siblings_rollback_and_replacement': 'smartcontracts/isi/sccp/eligibility_tests.rs'}


@pytest.mark.parametrize("mid", list(_SCCP_HOLD_MUTATION_CONTROLS))
def test_sccp_fast_pause_mutations_bind_original_consumer_controls(mid):
    expected = _SCCP_HOLD_MUTATION_CONTROLS[mid]
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == tuple(expected["controls"]) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {expected["owner"]}
    compact = re.sub(r"\s+", "", (core / expected["owner"]).read_text())
    assert f'all(test,sumeragi_core_mutation="{mid}")' in compact
    for name, cause in expected["controls"].items():
        source = (core / _SCCP_HOLD_TEST_FILES[name]).read_text()
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        assert cause in body
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("mid", list(_SCCP_HOLD_MUTATION_CONTROLS))
@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error"),
])
def test_sccp_fast_pause_kill_requires_declared_native_controls(monkeypatch, tmp_path, mid, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


_FEE_TAIL_MUTATION_CONTROLS = {'HC244': {'description': 'Network failure-fee settlement: swallow the original local execution deferral as a completed rejection', 'owner': 'state/output_network.rs', 'controls': {'state::output_capacity::producer::tests::network::fees::sccp_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'the original fee-tail deferral must not become a completed Network rejection', 'state::output_capacity::producer::tests::network::fees::ordinary_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'the original fee-tail deferral must not become a completed Network rejection', 'state::output_capacity::producer::tests::network::penalties::refusal::fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once': 'fee refusal after an actual slash must preserve the original deferral'}}, 'HC245': {'description': 'Network ballot-penalty settlement: swallow the original local execution deferral as a completed rejection', 'owner': 'state/output_network.rs', 'controls': {'state::output_capacity::producer::tests::network::penalties::refusal::actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry': 'the original penalty-tail deferral must not become a completed Network rejection'}}}
_FEE_TAIL_TEST_FILES = {'state::output_capacity::producer::tests::network::fees::sccp_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'state/output_network_fee_tests.rs', 'state::output_capacity::producer::tests::network::fees::ordinary_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'state/output_network_fee_tests.rs', 'state::output_capacity::producer::tests::network::penalties::refusal::actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry': 'state/output_network_penalty_refusal_tests.rs', 'state::output_capacity::producer::tests::network::penalties::refusal::fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once': 'state/output_network_penalty_refusal_tests.rs'}


@pytest.mark.parametrize("mid", list(_FEE_TAIL_MUTATION_CONTROLS))
def test_failure_fee_tail_mutation_binds_original_consumer_controls(mid):
    expected = _FEE_TAIL_MUTATION_CONTROLS[mid]
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == tuple(expected["controls"]) and not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    core = ROOT / "crates/iroha_core/src"
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {expected["owner"]}
    compact = re.sub(r"\s+", "", (core / expected["owner"]).read_text())
    assert f'all(test,sumeragi_core_mutation="{mid}")' in compact
    for name, cause in expected["controls"].items():
        source = (core / _FEE_TAIL_TEST_FILES[name]).read_text()
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        penalty_fixture = "::penalties::refusal::" in name
        if penalty_fixture:
            helper_name = "actual_penalty_refusal_and_fresh_retry"
            argument = "true" if mid == "HC244" else "false"
        else:
            helper_name = "fee_decoder_refusal_preserves_original_attempt_and_fresh_retry"
            argument = "true" if name.rsplit("::", 1)[-1].startswith("sccp_") else "false"
        assert f"{helper_name}({argument})" in body
        helper_marker = "fn " + helper_name + "("
        assert source.count(helper_marker) == 1
        helper = source.split(helper_marker, 1)[1].split("#[test]", 1)[0]
        assert cause in helper
        if penalty_fixture:
            probe = "fee_decode_test_scope" if mid == "HC244" else "penalty_decode_test_scope"
            assert probe + "::refuse_actual_" in helper
            assert "let result = execute(&mut block, &source)" in helper
            assert "assert_slash(" in helper
        else:
            assert "fee_decode_test_scope::refuse_actual_fee_decode()" in helper
            assert "let outcome = execute(&mut block, &source)" in helper
        assert "Err(ExecutionOutputAttemptError::Deferred(original))" in helper
        assert "execute(&mut retry, &source)" in helper
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("mid", list(_FEE_TAIL_MUTATION_CONTROLS))
@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"),
    ("ignored", "error"), ("missing", "error"), ("incidental", "error"),
])
def test_failure_fee_tail_kill_requires_declared_native_controls(monkeypatch, tmp_path, mid, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_epoch_cache_mutation_preserves_exact_native_owner_and_physical_cause():
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)["DM34"]
    assert rule.tests == (MODEL_NAMES["DM34"],) and not rule.scenarios
    source = (ROOT / "crates/iroha_data_model/src/sumeragi_finality/epoch_graph.rs").read_text()
    tests = (ROOT / "crates/iroha_data_model/src/sumeragi_finality/epoch_graph/validation_tests.rs").read_text()
    assert source.count('sumeragi_model_mutation = "DM34"') == 2
    assert '#[cfg(not(all(test, sumeragi_model_mutation = "DM34")))]\n        let snapshot = ExactEpoch::capture(context);' in source
    assert '#[cfg(all(test, sumeragi_model_mutation = "DM34"))]\n        let snapshot = norito::core::to_bytes_bounded(context, usize::MAX)' in source
    assert 'norito::decode_canonical::<ValidatorEpochContextV1>(&encoded)' in source
    assert 'let context_id = context.context_id()?;' in source
    assert 'entry.context.matches(context)' in source
    for field in ('da_layout', 'version', 'network_id', 'mode', 'authorization', 'leader_seed'):
        assert f'self.{field} == *{field}' in source
    assert 'self.committee_len == committee.len()' in source
    assert 'original.matches(supplied)' in source
    assert 'committee.len() > crate::sumeragi::epoch::MAX_VALIDATORS' in source
    assert 'member' in source and 'proof_of_possession.as_slice() == self.proof' in source
    test = tests.split('fn epoch_scope_retains_exact_context_without_a_hidden_heap_graph()', 1)[1].split('\n#[test]', 1)[0]
    cause = test.index('epoch cache adds no heap graph beyond original context validation')
    assert cause < test.index('let blocker = budget')
    assert cause < test.index('assert_eq!(validation.entries.iter().flatten().count(), 1)')
    assert 'PhysicalObservation::start()' in test and 'physical.snapshot().requests()' in test
    assert 'original mandatory context validation must succeed' in test
    assert 'full_scope.core_epoch(&context)' in test
    assert 'decoder.consumed_allocated_bytes()' in test
    assert 'size_of::<EpochValidationScope>() <= 12 * 1024' in test
    assert 'epoch_scope_compares_every_original_field_and_last_bounded_credential' in tests
    row = re.findall(r'^\| DM34 \|.*$', (ROOT / 'specs/sumeragi.md').read_text(), re.M)
    assert len(row) == 1 and rule.tests[0] in row[0]


@pytest.mark.parametrize('status,verdict', [
    ('ok', 'survived'), ('FAILED', 'killed_by_test'), ('ignored', 'error'),
    ('missing', 'error'), ('incidental', 'error'),
])
def test_epoch_cache_mutation_requires_its_exact_native_terminal(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)['DM34']
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    rows = [] if status == 'missing' else [
        (rule.tests[0] + '_incidental', 'FAILED') if status == 'incidental' else (rule.tests[0], status)
    ]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(model=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result['verdict'] == verdict, result
    assert result['named_tests'] == list(rule.tests)


_PAUSE_LAPSE_CONTROLS = {'smartcontracts::isi::sccp::read::control::tests::lapse::native_fast_pause_lapse_uses_exact_time_and_preserves_parliament_confirmation': 'the first native block at expiry must remove the original fast-pause record', 'smartcontracts::isi::sccp::read::control::tests::lapse::native_fast_pause_lapse_cancellation_keeps_original_record_and_retries_once': 'the original native execution must stage lapse before publication'}


def test_fast_pause_lapse_mutation_retains_exact_global_native_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC246"]
    assert rule.tests == tuple(_PAUSE_LAPSE_CONTROLS) and not rule.scenarios
    assert gate.has_switch("HC246", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC246", **family)
    core = ROOT / "crates/iroha_core/src"
    owner = "smartcontracts/isi/sccp/pause_lifecycle.rs"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if 'sumeragi_core_mutation = "HC246"' in p.read_text()}
    assert owners == {owner}
    compact = re.sub(r"\s+", "", (core / owner).read_text())
    assert 'cfg!(all(test,sumeragi_core_mutation="HC246"))' in compact
    assert compact.index("original_root_scope()") < compact.index('sumeragi_core_mutation="HC246"')
    assert "time>=original.until_ms" in compact
    assert "transaction.require_storage_admission()?" in compact
    source = (core / "smartcontracts/isi/sccp/read/control/tests/lapse.rs").read_text()
    for name, cause in _PAUSE_LAPSE_CONTROLS.items():
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        assert cause in body
        assert "control_chain(false)" in body
    assert "mod lapse;" in (core / "smartcontracts/isi/sccp/read/control/tests.rs").read_text()
    state = (core / "state.rs").read_text()
    assert state.index("Self::apply_block_start_parliament_enactments(&mut sb, now_h)?") < state.index("pause_lifecycle::lapse_after_enactments(&mut sb)")
    rows = re.findall(r"^\| HC246 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


_PRODUCER_DEFERRAL_CONTROLS = {'sumeragi::executor::publication_tests::original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry': 'original lane policy refusal must reach the driver as a typed deferral', 'sumeragi::executor::publication_tests::original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry': 'original staking capacity must reach the driver as a typed deferral'}


def test_payload_producer_deferral_mutation_selects_original_worker_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC247"]
    assert rule.tests == tuple(_PRODUCER_DEFERRAL_CONTROLS) and not rule.scenarios
    assert gate.has_switch("HC247", core=True)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if 'sumeragi_core_mutation = "HC247"' in p.read_text()}
    assert owners == {"sumeragi/executor/preparation.rs"}
    source = (core / "sumeragi/executor_publication_tests.rs").read_text()
    for name, cause in _PRODUCER_DEFERRAL_CONTROLS.items():
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        assert cause in body and "worker.build(" in body
    rows = re.findall(r"^\| HC247 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error"),
    ("missing", "error"), ("incidental", "error"),
])
def test_payload_producer_mutation_requires_its_exact_native_terminals(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC247"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = exact_control_output(rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)
