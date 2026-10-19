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

RUST_INDEX_SPEC = importlib.util.spec_from_file_location(
    "sumeragi_mutation_rust_index", ROOT / "scripts" / "zk_rust_lexical_index.py"
)
assert RUST_INDEX_SPEC is not None and RUST_INDEX_SPEC.loader is not None
rust_index = importlib.util.module_from_spec(RUST_INDEX_SPEC)
RUST_INDEX_SPEC.loader.exec_module(rust_index)


@pytest.fixture(autouse=True)
def accounting_source_observation(monkeypatch):
    """Keep existing subprocess doubles independent of live Git/source hashing.

    Source-boundary controls below replace these explicit accounting doubles
    with the real shared observer over their own minimal Git fixture.
    """
    state = {"root": str(ROOT), "branch": "refs/heads/optimizations"}
    monkeypatch.setattr(gate, "workspace_source_git_state", lambda _root: dict(state))
    monkeypatch.setattr(gate, "workspace_source_observation", lambda _root: {
        **state, "workspace_source_manifest_sha256": "a" * 64,
        "cargo_source_consumption": "not_proven"})


def named_rust_function(source: str, name: str) -> str:
    """Select one complete function without borrowing neighboring controls."""
    matches = [item for item in rust_index.functions(source) if item.name == name]
    assert len(matches) == 1, f"expected one Rust function {name}, found {len(matches)}"
    function = matches[0]
    return source[function.header_start:function.end]


def test_named_rust_function_keeps_nested_blocks_but_excludes_neighboring_controls():
    source = '''
#[test]
fn original() {
    let message = r#"a brace } and fn original() { inside a string"#;
    // A comment with } does not end the control.
    if ready() { reader.verify(&proof); }
}
fn unrelated_helper() { budget.set_limit_bytes(0); }
#[test]
fn later_control() { drop(blocker); AllocationBudget::new(1); }
'''
    body = named_rust_function(source, "original")
    assert "reader.verify(&proof)" in body
    assert "set_limit_bytes" not in body
    assert "AllocationBudget::new" not in body
    assert "drop(blocker)" not in body


@pytest.mark.parametrize("source", ["fn other() {}", "fn original() {} fn original() {}"])
def test_named_rust_function_rejects_missing_or_ambiguous_controls(source):
    with pytest.raises(AssertionError, match="expected one Rust function original"):
        named_rust_function(source, "original")


def empty_custody():
    """Explicit accounting-layer double; never represents native execution evidence."""
    return {"artifact": None, "errors": [], "compiler_errors": []}


def fixture_artifact(args, target, mutation):
    """A real temporary file plus synthetic Cargo metadata for pure subprocess tests."""
    path = target / "original-libtest"
    if not path.exists():
        path.write_bytes(b"unit-test artifact bytes; never executed")
        path.chmod(0o700)
    crate, features, _ = gate.package_options(args)
    directory = "irohad" if crate == "irohad_lib" else crate
    owner = ROOT / "crates" / directory
    artifact = {"package_id": "path+" + owner.as_uri() + "#fixture-version",
            "manifest_path": str(owner / "Cargo.toml"),
            "target": {"kind": ["lib"], "crate_types": ["lib"],
                       "name": "irohad" if crate == "irohad_lib" else crate,
                       "src_path": str(owner / "src/lib.rs"), "test": True},
            "profile": {"test": True}, "features": features.split(","),
            "executable": str(path), "mutation": mutation,
            "identity": gate.executable_identity(path, target)}
    environment = {key: None for key in gate.CARGO_RUNTIME_FIELDS}
    environment[gate.runtime_loader_key()] = "/synthetic/runtime"
    environment.update(CARGO="/synthetic/cargo", CARGO_MANIFEST_DIR=str(owner),
                       CARGO_MANIFEST_PATH=str(owner / "Cargo.toml"), CARGO_PKG_NAME=crate)
    artifact["runtime"] = {"argv": [str(path)], "cwd": str(owner), "environment": environment}
    artifact["build_options"] = gate.cargo_build_options(args)
    artifact["binding_sha256"] = gate.artifact_digest(artifact)
    return artifact


def selected_cargo_results(monkeypatch, code, output, names=("tests::named",), seconds=1.0):
    """Supply a completed executable inventory and a separate runtime response."""
    def cargo_test(*args, **_kwargs):
        if "--list" in args[3]:
            listing = "".join(name + ": test\n" for name in names)
            return 0, listing + f"\n{len(names)} tests, 0 benchmarks\n", 0.0, empty_custody()
        return code, output, seconds, empty_custody()
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


@pytest.mark.parametrize("mid,tests,hook", [
    ("MS51", (
        "sim::world::clock_guard::tests::f33_hidden_prepareqc_due_work_block_commits_after_lag",
        "machine::tests::liveness::det_s51_execute_certified_flag",
        "machine::tests::liveness::det_s51_reproposal_q_certifies_without_matching_lock",
    ), "machine/proposal.rs"),
    ("MS52", (
        "sim::world::clock_guard::tests::guard_rules_and_leads",
        "sim::world::clock_guard::tests::clock_guard_certified_time_within_two_drifts",
        "sim::world::clock_guard::tests::clock_guard_liveness_with_f_plus_one_slow_clocks",
    ), "sim/world/clock_guard.rs"),
    ("MS65", (
        "sim::world::clock_guard::tests::clock_guard_due_work_lower_bound_at_first_prepare",
    ), "sim/world/clock_guard.rs"),
    ("MS66", (
        "sim::world::clock_guard::tests::clock_guard_accepts_exact_drift_allowance",
        "sim::world::clock_guard::tests::clock_guard_liveness_with_f_plus_one_slow_clocks",
    ), "sim/world/clock_guard.rs"),
    ("MS80", (
        "machine::tests::liveness::det_s80_unrelated_lock_does_not_certify_execution",
    ), "machine/proposal.rs"),
    ("MS81", (
        "machine::tests::recovery::det_s81_unsigned_proposal_restart_refuses_mismatched_high_pqc",
        "machine::tests::recovery::det_s81_signed_proposal_restart_refuses_mismatched_high_pqc",
    ), "safety.rs"),
])
def test_clock_guard_mutations_pin_exact_controls_and_owning_hooks(mid, tests, hook):
    rule = gate.BY_ID[mid]
    assert rule.tests == tests
    assert rule.scenarios == (() if mid in {"MS80", "MS81"} else ("f39",))
    source = (gate.CRATE_SRC / hook).read_text()
    assert re.search(r'sumeragi_mutation\s*=\s*"' + mid + r'"', source)
    assert gate.has_switch(mid)
    assert not gate.has_switch(mid, core=True)
    assert not gate.has_switch(mid, model=True)


def test_unrelated_lock_mutation_requires_original_certification_failure():
    rule = gate.BY_ID["MS80"]
    cause = "a held PrepareQC must certify the executed block, not merely its height"
    source = "crates/iroha_sumeragi/src/machine/tests/liveness.rs"
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    body = named_rust_function(
        (ROOT / source).read_text(), "det_s80_unrelated_lock_does_not_certify_execution"
    )
    assert cause in body


def test_restored_proposal_mutation_requires_original_block_binding_failure():
    rule = gate.BY_ID["MS81"]
    cause = "a restored proposal must name the block certified by its TC high-PQC before signing or execution"
    source = "crates/iroha_sumeragi/src/machine/tests/recovery.rs"
    assert rule.causes == (gate.ExpectedFailure(cause, source),) * 2
    text = (ROOT / source).read_text()
    body = named_rust_function(text, "rejects_mismatched_proposal_justify")
    assert cause in body
    for signed, selector in zip((False, True), rule.tests):
        control = named_rust_function(text, selector.rsplit("::", 1)[1])
        assert f"rejects_mismatched_proposal_justify({str(signed).lower()})" in control


@pytest.mark.parametrize("mid,test,cause,source", [
    ("MX13", "sim::tests::amx_final_payment::amx_final_payment_silent_participant_requires_actionable_abort",
     "healthy global root must resolve the due final obligation without unrelated height advancement",
     "crates/iroha_sumeragi/src/sim/tests/amx_final_payment.rs"),
    ("MX14", "sim::amx::tests::det_amx_time_expiry_orders_last_yes_and_expire_identically",
     "signed time expiry must dominate the last Yes at the exact boundary regardless of payload order",
     "crates/iroha_sumeragi/src/sim/amx/tests.rs"),
    ("MX15", "sim::amx::tests::det_amx_time_sensitive_carriers_refuse_stale_time_but_certified_replay_is_exempt",
     "Begin and Vote carriers must enforce certified-time freshness alongside Expire",
     "crates/iroha_sumeragi/src/sim/amx/tests.rs"),
])
def test_amx_final_payment_mutations_require_the_original_outcome_failure(mid, test, cause, source):
    rule = gate.BY_ID[mid]
    assert rule.tests == (test,)
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert not rule.scenarios
    assert gate.has_switch(mid)
    assert not gate.has_switch(mid, core=True)
    assert not gate.has_switch(mid, model=True)


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
    def cargo_test(*args, **_kwargs):
        assert "--list" in args[3], "invalid discovery must stop before execution"
        return 0, listing, 0.0, empty_custody()
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, "MS1", ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "execution-error"


def test_discovery_and_execution_share_the_original_step_deadline(monkeypatch, tmp_path):
    moments = iter((100.0, 101.0, 102.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    calls = []
    def cargo_test(*args, **_kwargs):
        calls.append((args[3], args[5]))
        if "--list" in args[3]:
            return 0, "tests::named: test\n\n1 test, 0 benchmarks\n", 1.0, empty_custody()
        return 0, ("running 1 test\ntest tests::named ... ok\ntest result: ok. 1 passed; 0 failed; "
                   "0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"), 1.0, empty_custody()
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, None, ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "pass"
    assert [timeout for _, timeout in calls] == [5, 4]
    assert "--test-threads=1" in calls[1][0]


def test_discovery_timeout_never_replenishes_or_disables_the_execution_deadline(monkeypatch, tmp_path):
    def cargo_test(*args, **_kwargs):
        assert "--list" in args[3], "the exhausted deadline cannot launch a test"
        return 0, "tests::named: test\n\n1 test, 0 benchmarks\n", 5.0, empty_custody()
    monkeypatch.setattr(gate, "cargo_test", cargo_test)
    step = gate.run_step(SimpleNamespace(), tmp_path, None, ["named"], None, 5,
                         tmp_path / "named.log")
    assert step.status == "timeout"


@pytest.mark.parametrize("timeout,expected", [(0, None), (20, 20)])
def test_explicit_unbounded_wait_never_installs_a_process_deadline(
    monkeypatch, tmp_path, timeout, expected
):
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    deadlines = []

    class Process:
        returncode = 0

        def communicate(self, *, timeout):
            deadlines.append(timeout)
            return ("test tests::named ... ok\n").encode(), None

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: Process())
    code, output, _, _custody = gate.cargo_test(
        SimpleNamespace(), tmp_path, "MS1", ["named"], None, timeout,
        tmp_path / "named.log",
        expected_artifact=fixture_artifact(SimpleNamespace(), tmp_path, "MS1"))
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
            return ("test result: ok. 1 passed; 0 failed;").encode(), None
    def popen(command, **options):
        captured["command"] = command
        captured["env"] = options["env"]
        return Process()
    monkeypatch.setenv("SUMERAGI_MUTATION", "foreign-protocol-hook")
    monkeypatch.setenv("SUMERAGI_CORE_MUTATION", "foreign-core-hook")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=core)
    mutation = "HC1" if core else "MS1"
    code, _, _, _custody = gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0, tmp_path / "log", expected_artifact=fixture_artifact(args, tmp_path, mutation))
    crate, features, environment = gate.package_options(args)
    assert code == 0
    assert (crate, features) == (("iroha_core", "mutation-testing,iroha-core-tests") if core
                                 else ("iroha_sumeragi", "mutation-testing,sim"))
    assert captured["command"] == [str(tmp_path / "original-libtest"), "named"]
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
    world = (source / "smartcontracts/isi/world.rs").read_text()
    assert re.search(r"macro_rules! world_test\s*\{\s*\(\$name:ident \$body:block\)\s*=>\s*\{\s*#\[test\]\s*fn \$name\(\) \$body", world)
    assert 'include!("world_sccp_governance_tests.rs");' in world
    functions.update(re.findall(r"\bworld_test!\s*\(\s*(\w+)\s*\{", text))
    ids = [mutation.id for mutation in gate.CORE_MUTATIONS]
    assert len(ids) == len(set(ids))
    for mutation in gate.CORE_MUTATIONS:
        assert gate.has_switch(mutation.id, core=True)
        assert not gate.has_switch(mutation.id)
        assert mutation.tests and not mutation.scenarios
        assert all(name.rsplit("::", 1)[-1] in functions for name in mutation.tests), mutation.id


def test_mutation_ids_select_one_rule_across_all_implementation_owners():
    mutations = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS,
                 *gate.SDK_MUTATIONS, *gate.DEPLOY_MUTATIONS, *gate.TORII_MUTATIONS,
                 *gate.NORITO_MUTATIONS, *gate.P2P_MUTATIONS]
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
            return ("test result: ok. 1 passed; 0 failed;").encode(), None
    def popen(command, **options):
        captured.append(command)
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=True, core_profile=profile)
    for mutation in (None, "HC1"):
        assert gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0,
                               tmp_path / f"{mutation}.log", expected_artifact=fixture_artifact(args, tmp_path, mutation))[0] == 0
    assert captured[0] == captured[1]
    expected_profile = profile or "test"
    stub_compiler_host(monkeypatch)
    command, _ = gate.capture_build_command(args, {}, tmp_path / "profile.build.log", 0, 0)
    assert command[5:7] == ["--profile", expected_profile]
    assert captured[0] == [str(tmp_path / "original-libtest"), "named"]
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
    assert rule.tests == ("sumeragi::executor::payload_refusal_tests::original_available_payload_local_decode_refusal_transfers_typed_original_reason_and_retry",)
    assert not rule.scenarios
    assert gate.has_switch("HC45", core=True)
    assert not gate.has_switch("HC45")


def test_narrow_caller_depth_gate_requires_original_bytes_and_worker_retry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC46"]
    assert rule.tests == (
        "execution_attempt::tests::original_surviving_narrow_decode_depth_refusal_retries_identical_bytes",
        "sumeragi::executor::payload_refusal_tests::original_available_payload_narrow_depth_refusal_transfers_typed_original_reason_and_retry",
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
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
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
            return (late_output).encode(), None

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        gate.os, "killpg",
        lambda *args: pytest.fail("a qualification deadline must not signal Cargo"),
    )
    args = SimpleNamespace(core=True, core_profile="test")
    log = tmp_path / "owned-deadline.log"
    code, output, _, _custody = gate.cargo_test(args, tmp_path, None, ["named"], None, 7, log, expected_artifact=fixture_artifact(args, tmp_path, None))
    assert calls == [7, omitted], "original deadline is retained; then wait for natural exit"
    assert code is None, "neither late success nor a late failed test satisfies its deadline"
    assert output == late_output
    assert log.read_bytes() == late_output.encode()
    assert json.loads(log.with_suffix(".artifact.json").read_text())["exit_code"] is None
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
        'smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_missing_malformed_and_rebound_state_are_not_deferrals',
        'queue::router::tests::persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission',
        'state::deserialize::decode_tests::restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal',
    )
    assert not rule.scenarios
    assert gate.has_switch("HC68", core=True)
    assert not gate.has_switch("HC68")
    source = gate.REPO / "crates/iroha_core/src/smartcontracts/isi/multisig.rs"
    assert 'sumeragi_core_mutation = "HC68"' in source.read_text()
    # Decoder-capacity invalidation alone does not exercise HC68's disabled
    # body/occurrence/physical-key guard. Keep its adversarial binding control.
    attempts = source.parent / "multisig/tests/proposal_attempt.rs"
    leaf = rule.tests[1].rsplit("::", 1)[-1]
    body = attempts.read_text().split(f"fn {leaf}()", 1)[1].split("#[test]", 1)[0]
    for coordinate in ("multisig_account_id", "instructions_hash", "proposal_nonce",
                       "proposal_id", "network_id", "transaction_ttl_ms"):
        assert f"altered.{coordinate} =" in body
    assert "ExecutionAttemptError::Rejected" in body
    # The transaction now exposes the refusal bit directly.  This malformed
    # state path must remain an ordinary rejection and leave no deferral.
    assert "assert!(!tx.is_execution_deferred());" in body


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
        "sumeragi::certified_chain::funded_authority::tests::"
        "native_authority_prepaid_custody_errors_require_recovery",
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
            return ("test result: ok. 1 passed; 0 failed;").encode(), None
    def popen(command, **options):
        captured.update(command=command, environment=options["env"])
        return Process()
    for name in ["SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION", "SUMERAGI_MODEL_MUTATION"]:
        monkeypatch.setenv(name, "inherited-foreign-rule")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(core=owner == "core", daemon=owner == "daemon")
    code, _, _, _custody = gate.cargo_test(args, tmp_path, mutation, ["named"], None, 0, tmp_path / "log", expected_artifact=fixture_artifact(args, tmp_path, mutation))
    assert code == 0
    package, features, selected_environment = gate.package_options(args)
    assert captured["command"] == [str(tmp_path / "original-libtest"), "named"]
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
        def communicate(self,*,timeout=None): return ('').encode(),None
    def popen(command,**kwargs):
        captured.update(command=command,seed_base=kwargs['env'].get('SUMERAGI_SIM_SEED_BASE'))
        return Child()
    monkeypatch.setattr(gate.subprocess,'Popen',popen)
    stub_compiler_host(monkeypatch)
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
    def step(args,target,mutation,filters,seeds,timeout,log, artifact=None):
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
            return (output).encode(), None
    moments = iter((100.0, 100.0, 100.0 + timeout + 1.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    code, retained, elapsed, _custody = gate.cargo_test(
        SimpleNamespace(), tmp_path, None, ["named"], None, timeout, tmp_path / "late.log",
        expected_artifact=fixture_artifact(SimpleNamespace(), tmp_path, None))
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
            return ("retained original output").encode(), None
    moments = iter((100.0, 10000.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    code, retained, elapsed, _custody = gate.cargo_test(
        SimpleNamespace(), tmp_path, None, [], None, 0, tmp_path / "unbounded.log",
        expected_artifact=fixture_artifact(SimpleNamespace(), tmp_path, None))
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
        expected_tests = (name,)
        if identifier == "HC145":
            expected_tests += (
                "queue::payload_leases::tests::pending_payload_admission_exhaustion_refuses_before_input_publication",
            )
        assert rule.tests == expected_tests
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False, **_kwargs):
        calls.append((tuple(filters), timeout))
        if filters[0] == 'tests::a':
            assert '--list' in filters, 'an exhausted discovery cannot launch runtime'
            return 0, 'tests::a: test\n\n1 test, 0 benchmarks\n', 900.0, empty_custody()
        if '--list' in filters:
            return 0, 'tests::b: test\n\n1 test, 0 benchmarks\n', 1.0, empty_custody()
        return 0, ('running 1 test\ntest tests::b ... ok\ntest result: ok. 1 passed; 0 failed; '
                   '0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'), 1.0, empty_custody()
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
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False, **_kwargs):
        if '--list' in filters:
            return 0, 'tests::a: test\n\n1 test, 0 benchmarks\n', 0.0, empty_custody()
        return code, output, 1.0, empty_custody()
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def run_step(args, target, mutation, filters, seeds, timeout, log, artifact=None):
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
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False, **_kwargs):
        selected = [name for name in actual_names if any(f in name for f in filters if not f.startswith('--'))]
        if '--list' in filters:
            return 0, ''.join(f'{name}: test\n' for name in selected) + f'\n{len(selected)} tests, 0 benchmarks\n', 0.0, empty_custody()
        runtime.append(selected)
        return 0, (f'running {len(selected)} tests\n' + ''.join(f'test {name} ... ok\n' for name in selected)
                   + f'test result: ok. {len(selected)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'), 1.0, empty_custody()
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
    def cargo_test(args, target, mutation, filters, seeds, timeout, log, no_run=False, **_kwargs):
        assert len([f for f in filters if f == 'tests::named' or f in (gate.SCENARIOS[s] for s in scenarios)]) == 1
        name = filters[0]
        calls.append((name, '--list' in filters, timeout))
        if '--list' in filters:
            return 0, f'{name}: test\n\n1 test, 0 benchmarks\n', 2.0, empty_custody()
        late = name == gate.SCENARIOS[scenarios[1]]
        verdict = 'ok' if late else 'FAILED'
        output = (f'running 1 test\ntest {name} ... {verdict}\ntest result: {verdict}. '
                  f'{1 if late else 0} passed; {0 if late else 1} failed; '
                  '0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
        return (0 if late else 101), output, (3598.5 if late else 1.0), empty_custody()
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
                              "reason": f"worker evaluation raised {error_type.__name__}: original source guard refused",
                              "source_git": {
                                  "before": {"root": str(ROOT), "branch": "refs/heads/optimizations"},
                                  "after": {"root": str(ROOT), "branch": "refs/heads/optimizations"},
                                  "errors": [],
                              }}
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
    "DM36": "parameter::system::tests::clock_drift_bound_accepts_exact_limit_and_rejects_excess_without_overflow",
    "DM37": "parameter::system::tests::due_work_policy_checks_combined_margin_and_overflow_without_local_clock",
    "DM38": "sumeragi_amx::approval_proof::tests::exact_debit_approval_rejects_substituted_roots_terms_relays_schema_and_permission_preimages",
    "DM39": "sumeragi_amx::tests::time_tests::sumeragi_amx_time_boundary_is_exclusive_and_height_boundary_inclusive",
    "DM40": "sumeragi_amx::tests::time_tests::sumeragi_amx_time_expiry_preserves_all_pending_rows_on_writer_refusal",
    "DM41": "compute::tests::price_delta_bounds_keep_full_width_before_comparison",
    "DM42": "compute::tests::sponsor_caps_keep_exact_daily_total_and_per_call_precedence",
    "DM43": "compute::tests::price_delta_wide_numerator_rejects_extreme_reduction",
    "DM44": "fastpq::execution_effect::admitted::tests::completed_tape_take_rejects_prepared_replay_without_reminting_custody",
    "DM45": "consensus::penalty_actions::prepared::tests::penalty_action_owner_preserves_sole_wire_schema_json_and_original_shared_graph",
    "DM46": "consensus::penalty_actions::prepared::tests::penalty_action_source_binds_full_original_frame_pool_and_layout",
    "DM47": "consensus::penalty_actions::prepared::tests::penalty_action_original_partial_refusal_retains_exact_prefix_pool_and_retry",
    "DM48": "block::prepared_signatures::tests::penalty_action_tests::field5_penalty_actions_keep_canonical_wire_and_original_shared_graph",
    "DM49": "block::prepared_signatures::tests::penalty_action_tests::field5_penalty_refusal_retains_original_prefix_pool_and_exact_retry",
    "DM50": "consensus::parent_service::prepared::tests::parent_service_owner_keeps_vec_wire_json_and_exact_admitted_clone",
    "DM51": "consensus::parent_service::prepared::tests::parent_service_source_and_capacity_retry_preserve_original_full_frame_pool_and_layout",
    "DM52": "block::prepared_signatures::tests::parent_service_tests::field5_parent_service_survives_later_action_refusal_with_exact_original_cut_and_retry",
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
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 900
            return ("isolated process result").encode(), None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    foreign = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION", "SUMERAGI_MODEL_MUTATION")
    for variable in foreign:
        monkeypatch.setenv(variable, "inherited-foreign-rule")
    for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"):
        monkeypatch.setenv(variable, "7")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    code, output, elapsed, _custody = gate.cargo_test(SimpleNamespace(model=True), tmp_path, selected,
        ["isi::amx_owner::tests::named"], None, 900, tmp_path / "model.log", expected_artifact=fixture_artifact(SimpleNamespace(model=True), tmp_path, selected))
    assert code == 0 and output == "isolated process result" and elapsed >= 0
    assert captured["command"] == [str(tmp_path / "original-libtest"), "isi::amx_owner::tests::named"]
    environment = captured["options"]["env"]
    assert captured["options"]["cwd"] == ROOT / "crates/iroha_data_model"
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
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)["DM1"]
    result = gate.evaluate(args, tmp_path, rule)
    assert result["verdict"] == verdict
    assert result["id"] == "DM1"
    assert len(observed) == 1
    assert observed[0][2:6] == ("DM1", rule.tests, None, 900)
    assert "scenario" not in result


@pytest.mark.parametrize("baseline,expected", [("pass", 0), ("fail", 1), ("error", 1)])
@pytest.mark.parametrize("reverse_registry", [False, True])
def test_model_main_keeps_positive_baseline_exact_report_and_default_caps(monkeypatch, tmp_path, baseline, expected, reverse_registry):
    rules = list(reversed(gate.MODEL_MUTATIONS)) if reverse_registry else list(gate.MODEL_MUTATIONS)
    monkeypatch.setattr(gate, "MODEL_MUTATIONS", rules)
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
    assert len(ids) == len(set(ids)) == len(MODEL_NAMES)
    assert set(ids) == set(MODEL_NAMES)
    assert ids == tuple(rule.id for rule in rules)
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
    (True, "DM36", "", True, True), (False, "DM36", "", True, False),
    (True, "DM41", "", True, True), (False, "DM41", "", True, False),
    (True, "DM42", "", True, True), (False, "DM42", "", True, False),
    (True, "DM43", "", True, True), (False, "DM43", "", True, False),
    (True, "DM44", "", True, True), (False, "DM44", "", True, False),
    (False, None, '--cfg\x1fsumeragi_model_mutation="DM41"', False, False),
    (False, None, '--cfg\x1fsumeragi_model_mutation="DM42"', False, False),
    (False, None, '--cfg\x1fsumeragi_model_mutation="DM43"', False, False),
    (True, "DM41", '--cfg\x1fsumeragi_model_mutation="DM41"', False, False),
    (True, "DM42", '--cfg\x1fsumeragi_model_mutation="DM42"', False, False),
    (True, "DM43", '--cfg\x1fsumeragi_model_mutation="DM43"', False, False),
    (True, "DM41", '--cfg\x1fsumeragi_model_mutation="DM42"', False, False),
    (True, "DM42", '--cfg\x1fsumeragi_model_mutation="DM43"', False, False),
    (True, "DM43", '--cfg\x1fsumeragi_model_mutation="DM41"', False, False),
    (False, None, '--cfg\x1fsumeragi_model_mutation="DM44"', False, False),
    (True, "DM44", '--cfg\x1fsumeragi_model_mutation="DM44"', False, False),
    (True, "DM44", '--cfg\x1fsumeragi_model_mutation="DM43"', False, False),
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
    assert re.findall(r'^cargo:rustc-cfg=sumeragi_model_mutation="([^"]+)"$', result.stdout, re.MULTILINE) == ([mutation] if emitted else [])
    if not accepted:
        expected_reason = "cannot be injected through compiler flags" if flags else "unknown Model mutation id"
        assert expected_reason in result.stderr
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
    assert "portable: PortableProof" in implementation
    representation = implementation.split("enum PortableProof {", 1)[1].split("}", 1)[0]
    assert "Unbuilt," in representation
    assert "Completed(Option<AllocatedAmxRecordProofV1>)" in representation
    assert 'all(test, sumeragi_core_mutation = "HC159")' in implementation
    assert "if namespace.is_err()" in implementation
    compact = re.sub(r"\s+", "", implementation)
    delivery = "std::mem::replace(&mutself.portable,PortableProof::Unbuilt)"
    assert compact.index("namespace?;") < compact.index(delivery)
    assert "letPortableProof::Completed(proof)=" + delivery in compact
    assert 'Error::Source("completed portable proof is not retained")' in implementation
    mutation = implementation.split('sumeragi_core_mutation = "HC159"', 1)[1].split("namespace?;", 1)[0]
    assert "self.portable = PortableProof::Unbuilt;" in mutation
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
    ("p2p", "iroha_p2p", "NET", "sumeragi_p2p_mutation", "SUMERAGI_P2P_MUTATION"),
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
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    identifier = prefix + "1" if selected else None
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 900
            return ("original isolated native output").encode(), None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    variables = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION",
                 "SUMERAGI_MODEL_MUTATION", "SUMERAGI_SDK_MUTATION", "SUMERAGI_DEPLOY_MUTATION",
                 "SUMERAGI_TORII_MUTATION", "SUMERAGI_NORITO_MUTATION", "SUMERAGI_P2P_MUTATION")
    for variable in variables:
        monkeypatch.setenv(variable, "foreign-inherited-rule")
    for variable in ("SUMERAGI_SIM_SEED", "SUMERAGI_SIM_SEED_BASE", "SUMERAGI_SIM_SEEDS"):
        monkeypatch.setenv(variable, "7")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    args = SimpleNamespace(**{owner: True})
    code, output, elapsed, _custody = gate.cargo_test(args, tmp_path, identifier, ["original::named"], None, 900, tmp_path / "run.log", expected_artifact=fixture_artifact(args, tmp_path, identifier))
    assert code == 0 and output == "original isolated native output" and elapsed >= 0
    assert captured["command"] == [str(tmp_path / "original-libtest"), "original::named"]
    options = captured["options"]
    assert options["cwd"] == ROOT / "crates" / package and options["start_new_session"] is True
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
        panics = {name: [{"thread": name, "source": expected.source, "message": expected.cause}]
                  for name, expected in zip(rule.tests, rule.causes)} if status == "fail" else {}
        return gate.Step(status=status, failed=list(args[3]) if status == "fail" else [],
                         panics=panics, panic_owners_valid=True)
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
    assert module.MUTATION_FEATURE_OWNERS == {"iroha_data_model", "iroha_core", "irohad_lib", "iroha_sumeragi", "iroha", "iroha_deploy", "iroha_torii", "norito", "iroha_p2p"}


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
    def cargo_test(*args, **_kwargs):
        calls.append(args[3])
        if "--list" in args[3]:
            return 0, f"{replacement}: test\n\n1 test, 0 benchmarks\n", 0.0, empty_custody()
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
    def cargo_test(*args, **_kwargs):
        selected_scenario = args[3][0] == scenario
        rows = ([(scenario + "_extra", "FAILED")] if scenario_status == "missing" else
                [(scenario, scenario_status), (scenario + "_extra", "FAILED")]) if selected_scenario else [("tests::named", named_status)]
        calls.append((args[3][0], "--list" in args[3]))
        if "--list" in args[3]:
            return 0, "".join(name + ": test\n" for name, _ in rows) + f"\n{len(rows)} tests, 0 benchmarks\n", 0.0, empty_custody()
        return exact_control_output(rows) + (1.0, empty_custody())
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
    def cargo_test(*args, **_kwargs):
        name = args[3][0]
        rows = [(name, "ok")] if name == "tests::named" else [(name, "FAILED")] if name == gate.SCENARIOS[scenarios[0]] else [(name, "ok"), (name + "_extra", "FAILED")]
        if "--list" in args[3]:
            return 0, "".join(n + ": test\n" for n, _ in rows) + f"\n{len(rows)} tests, 0 benchmarks\n", 0.0, empty_custody()
        return exact_control_output(rows) + (1.0, empty_custody())
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
    body = named_rust_function(controls, name)
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
    assert "Self::from_fixture(self.canonical_projection(), self.body.budget())" in owner
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
                       "let tracker = AmxForeignInstanceV1::new(chain.instance().0,"
                       "authenticated_genesis(chain.genesis()).map(|genesis| genesis.into_parts().0).unwrap(),"
                       "iroha_data_model::sumeragi_finality::CertifiedResultScope::TairaGlobal,).unwrap();",
                       "assert_eq!(tracker.verify_record(proof.canonical()).unwrap().height, 2);",
                       "proof.allocation_bytes()"]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", body)
    # Scope belongs to the independently authenticated tracker, not to each
    # offered proof. Bind the current API and its signed scope/codec control.
    tracker_source = (ROOT / "crates/iroha_data_model/src/sumeragi_amx/tracker.rs").read_text()
    constructor = tracker_source.split("pub fn new(", 1)[1].split("/// Latest tracked epoch", 1)[0]
    verifier = tracker_source.split("pub fn verify_block(", 1)[1].split("/// Verify a record proof", 1)[0]
    record = tracker_source.split("pub fn verify_record(", 1)[1].split("/// Apply a handoff proof", 1)[0]
    assert "result_scope: CertifiedResultScope" in constructor
    assert "instance,result_scope,current:anchor,previous:None," in re.sub(r"\s+", "", constructor)
    assert "CertifiedResultV1::decode(&block.result_preimage,self.result_scope)" in re.sub(r"\s+", "", verifier)
    assert "&self,proof:&AmxRecordProofV1" in re.sub(r"\s+", "", record)
    assert "self.verify_record_with_contexts(proof, &[])" in record
    assert "let verified = self.verify_block_with_contexts(&proof.block, decision_contexts)?;" in record
    assert "self.verify_block_with_contexts(block, &[])" in verifier
    assert "root == verified.commitment().execution.ordinary_writes_root" in record
    model = (ROOT / "crates/iroha_data_model/src/sumeragi_amx/tests.rs").read_text()
    scope = model.split("fn native_certified_result_scope_is_original_tracker_authority_and_survives_codec(", 1)[1].split("#[test]", 1)[0]
    for obligation in [
        "AmxForeignInstanceV1::new(instance, context.clone(), CertifiedResultScope::NonGlobal)",
        "let (header, qc) = sign(instance, &context, 2, active.result().unwrap(), 3);",
        'matches!(private.verify_block(&proof), Err(AmxError::Proof(reason)) if reason.contains("non-global"))',
        "assert_eq!(private, original);",
        "AmxForeignInstanceV1::new(instance, context, CertifiedResultScope::TairaGlobal)",
        "global.verify_block(&proof).unwrap();",
        "for tracker in [private, global]",
        "assert_eq!(norito::decode_canonical::<AmxForeignInstanceV1>(&encoded).unwrap(),tracker);",
        "assert_eq!(norito::json::from_value::<AmxForeignInstanceV1>(json.clone()).unwrap(),tracker);",
        'json.as_object_mut().unwrap().remove("result_scope");',
        "assert!(norito::json::from_value::<AmxForeignInstanceV1>(json).is_err());",
    ]:
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", scope)
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
                       "authenticated_parent_source(&self.budget)", "source.global_genesis",
                       "source.global_successor", "Hash::new", "authority: 0",
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
    assert 'frame = "iroha_core::amx::AmxIntentCoordinatesV1"' in owner
    assert "borrowed_intent_coordinates_declare_exact_owned_frame_without_erasing_nominal_lifetime" in owner
    source_binding = (source / "state/fastpq_quantity_capture/commitment_journal/finalized_source/witness.rs").read_text()
    native_match = source_binding.split("pub(crate) fn matches_original_native_execution(", 1)[1].split("\n    }", 1)[0]
    assert "self.native.as_ref().is_some_and(|(block,original)|*block==executed.hash()&&original==execution)" in re.sub(r"\s+", "", native_match)
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
    for identity in ("iroha_core::amx::AmxParentCoordinatesV1", "iroha_core::amx::AmxIntentCoordinatesV1", "iroha_core::amx::AmxIntentRowV1"):
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
    selected = source.split("fn read_pipeline_transaction_carrier(", 1)[1].split("\nfn ", 1)[0]
    assert "read_pipeline_execution_carrier(app, anchor.height)" in selected
    http = source.split("fn read_pipeline_execution_carrier(", 1)[1].split("\nfn ", 1)[0]
    assert "HistoryProducerOwner::authentication_read(app)?" in http
    assert "owner.scope(||" in http
    assert "if height == NonZeroUsize::MIN" in http
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
    assert "membership.insert_block(BTreeSet::new(), NonZeroUsize::new(2).unwrap())" in controls
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
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    variables = ("SUMERAGI_MUTATION", "SUMERAGI_CORE_MUTATION", "SUMERAGI_DAEMON_MUTATION",
                 "SUMERAGI_MODEL_MUTATION", "SUMERAGI_SDK_MUTATION", "SUMERAGI_DEPLOY_MUTATION",
                 "SUMERAGI_TORII_MUTATION", "SUMERAGI_NORITO_MUTATION", "SUMERAGI_P2P_MUTATION")
    for variable in variables:
        monkeypatch.setenv(variable, "inherited-foreign-rule")
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 1200
            return ("unexecuted mock build").encode(), None
    def popen(command, **options):
        captured.update(command=command, options=options)
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    stub_compiler_host(monkeypatch)
    args = SimpleNamespace(**({owner: True} if owner else {}))
    code, output, _, _custody = gate.cargo_test(args, tmp_path, mutant, [], None, 1200, tmp_path / "build.log", no_run=True)
    assert code == 0 and output == "unexecuted mock build"
    prefix = ["cargo", "test", "--locked", "-p", package, *profile, "--features", features,
              "--lib", "--message-format=json-render-diagnostics"]
    assert captured["command"][:len(prefix)] == prefix
    assert captured["command"][len(prefix):len(prefix) + 2] == ["--target", "synthetic-native-host"]
    assert "--no-run" not in captured["command"]
    assert "--capture-runtime" in captured["command"][-1]
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
               'sumeragi/certified_chain/query_reader.rs',
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
    assert owner.index('sumeragi_core_mutation = "HC218"') < owner.index(".authenticated_relay_record_count()?") < owner.index(".into_relay()")
    proof = (core / "query/native_receipts/amx_read.rs").read_text()
    count = proof.split("fn authenticated_relay_record_count", 1)[1].split("// Only this sibling", 1)[0]
    assert "source.completed && source.authenticated" in count
    assert re.search(r"prepared_intents::count\(&projection\.witness\.get\(\)\.writes,?\)", re.sub(r"\s+", "", count))
    assert "clone()" not in count and "collect(" not in count
    controls = (core / "sumeragi/amx/native/tests/paid_borrowed_custody.rs").read_text()
    control = controls.split("fn " + name + "()", 1)[1]
    for evidence in ("roots.transaction(40", "roots.transaction(60", "roots.participants[0].sign(&payer(), prepares",
                     "restored.replay_from(", "one_row_subset(&original)",
                     "restarted canonical intent must match every authenticated Prepared row before first delivery",
                     "retained_instruction().is_none()", "let (first_descriptor, first) = complete.complete_next()", "let (second_descriptor, second) = complete.complete_next()",
                     "assert_ne!(first_descriptor.source(), second_descriptor.source())",
                     "instruction_relay(&first).record.tx(), instruction_relay(&second).record.tx()",
                     "delivered == original.canonical()", "first.amx_proof_admitted_to(&budget) && second.amx_proof_admitted_to(&budget)"):
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
    assert set(indexed) == {"NC1", "NC2", "NC3", "NC4", "NC5", "NC6", "NC7", "NC8", "NC9", "NC10", "NC11", "NC12", "NC13", "NC14", "NC15"}
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
    assert indexed["NC6"].tests == ('json::decode_depth_tests::typed_and_fast_documents_preserve_exact_and_short_active_depth', 'json::decode_depth_tests::borrowed_and_skipped_values_check_the_peak_before_advancing_the_cursor', 'json::value_depth_tests::native_value_and_aggregate_conversions_enforce_exact_and_short_depth')
    assert indexed["NC7"].tests == ('json_parse_string_allocations::fast_depth_order::active_depth_refuses_before_structural_tape_allocation', 'json_parse_string_allocations::fast_depth_order::fixed_depth_refuses_before_structural_tape_allocation')
    assert indexed["NC8"].tests == ('json_from_value_fast::resource_budget::native_value_clone_charges_strings_arrays_and_object_owners',)
    assert indexed["NC9"].tests == ('json_from_value_fast::resource_budget::vec_conversion_enforces_sequence_total_and_storage_budgets',)
    assert indexed["NC10"].tests == ('json_from_value_fast::resource_budget::btree_set_conversion_enforces_sequence_total_and_storage_budgets',)
    assert indexed["NC11"].tests == ('json_from_value_fast::resource_budget::hash_set_conversion_enforces_sequence_total_and_storage_budgets',)
    assert indexed["NC12"].tests == ('json_from_value_fast::resource_budget::btree_map_conversion_enforces_sequence_total_and_storage_budgets',)
    assert indexed["NC13"].tests == ('json_from_value_fast::resource_budget::hash_map_conversion_enforces_sequence_total_and_storage_budgets',)
    assert indexed["NC14"].tests == ('json_parse_string_allocations::field_budget::owned_strings_check_decoded_field_before_allocation', 'json_parse_string_allocations::field_budget::parser_reference_fields_refuse_before_escape_scratch', 'json_parse_string_allocations::field_budget::tape_reference_fields_refuse_before_escape_scratch', 'json_parse_string_allocations::field_budget::native_string_copies_and_hex_fields_use_decoded_utf8_length', 'json_parse_string_allocations::field_budget::borrowed_and_buffered_keys_preserve_field_admission_and_colon_progress', 'json_parse_string_allocations::field_budget::key_hash_fields_preserve_hash_last_key_and_tape_cursor', 'json_parse_string_allocations::field_budget::direct_numeric_map_keys_cannot_bypass_field_limit', 'json_parse_string_allocations::field_budget::field_refusal_preserves_scope_identity_retry_and_cumulative_charge')
    assert indexed["NC15"].tests == ('json_cleanup_stack_tests::array_comb_cleanup_survives_default_stack_child', 'json_cleanup_stack_tests::object_comb_cleanup_survives_default_stack_child')
    source = ROOT / "crates/norito"
    texts = "\n".join(path.read_text() for path in (source / "src").rglob("*.rs"))
    assert set(re.findall(r'sumeragi_norito_mutation\s*=\s*"([^"]+)"', texts)) == set(indexed)
    lib = (source / "src/lib.rs").read_text()
    shared_controls = ("json_from_value_fast", "json_parse_string_allocations")
    control_texts = texts
    for name in shared_controls:
        declaration = f'#[cfg(all(test, feature = "json"))]\n#[path = "../tests/{name}.rs"]\nmod {name};'
        assert declaration in lib
        control_texts += "\n" + (source / "tests" / f"{name}.rs").read_text()
    for identifier, rule in indexed.items():
        assert gate.has_switch(identifier, norito=True)
        assert not gate.has_switch(identifier, core=True)
        assert not gate.has_switch(identifier)
        assert not rule.scenarios
        assert f'all(test, sumeragi_norito_mutation = "{identifier}")' in texts
        for selector in rule.tests:
            assert f'fn {selector.rsplit("::", 1)[-1]}(' in control_texts
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
    account = (ROOT / 'crates/iroha_data_model/src/account/prepared_decode.rs').read_text()
    assert not re.findall(r'sumeragi_model_mutation\s*=\s*"([^"]+)"', model)
    assert tuple(re.findall(r'sumeragi_model_mutation\s*=\s*"([^"]+)"', account)) == ('DM33',)
    assert 'workspace: Option<PreparedDecodeWorkspace>' in model
    assert 'ncore::RetainedElementSequence' in account
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
    assert owners == {"account/prepared_decode.rs"}
    source = (model / "account/prepared_decode.rs").read_text()
    owner = source.split("fn policy_error(", 1)[1]
    assert source.count(f'sumeragi_model_mutation = "{mid}"') == 1
    assert 'cfg!(all(test, sumeragi_model_mutation = "DM33"))' in owner
    assert 'norito::Error::Message(error.to_string()).into()' in owner
    assert 'Error::Multisig(error)' in owner
    assert 'Multisig(#[from] super::MultisigPolicyError)' in source
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
        "coherent_height(view)? != current", "authenticated.block().hash() != *hash",
        "receipt.result() != authenticated.result()", "receipt.id().0.as_ref() != authenticated.context_id().as_ref()",
        "read_frame(durable.clone(), *height, authenticated.root_scope())",
        "receipt.block_hash() != authenticated.block().hash()", "receipt.core_hash() != authenticated.core_hash()",
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
    for obligation in ("members_address != members.as_ptr() as usize", "!original.owned.charges.belongs_to(budget)",
                       "std::ptr::eq(original.block.as_ref(), block.as_ref())", "if pop.is_none()",
                       "pop.take().expect", "wire_complete", 'sumeragi_core_mutation = "HC213"'):
        assert obligation in kernel
    construction = kernel.split("struct Construction {", 1)[1].split("impl ProofPreparation", 1)[0]
    assert construction.index("pop:") < construction.index("owned:")
    owned = kernel.split("pub(super) struct OwnedProof {", 1)[1].split("impl OwnedProof", 1)[0]
    assert owned.index("proof:") < owned.index("charges:")
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
    ("HC237", "smartcontracts/isi/sccp/governance.rs"),
    ("HC238", "smartcontracts/isi/sccp/controls.rs"),
])
def test_sccp_control_mutation_preserves_original_cause_and_pause_owner(mid, owner):
    name = "smartcontracts::isi::world::isi::tests::sccp_enactment_component_binds_exact_certificate_and_complete_pause_state"
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
        effect = named_rust_function(source, "enact")
        compact_effect = re.sub(r"\s+", "", effect)
        assert "letcertificate_id={let_=certificate_id;proposal_id};" in compact_effect
        assert "ControlCauseV1::from_parliament(certificate_id,effect_hash)?" in compact_effect
        assert effect.index(needle) < effect.index("ControlCauseV1::from_parliament")
        assert effect.index("ControlCauseV1::from_parliament") < effect.index("apply_action(")
        cause_source = (core / "smartcontracts/isi/sccp/controls.rs").read_text()
        constructor = named_rust_function(cause_source, "from_parliament")
        compact_constructor = re.sub(r"\s+", "", constructor)
        assert "certificate_id:[u8;32],effect_hash:[u8;32]," in compact_constructor
        assert "certificate_id==[0;32]||effect_hash==[0;32]" in compact_constructor
        assert "Ok(Self{track:iroha_sccp::v1::control::TRACK_PARLIAMENT,certificate_id,effect_hash,})" in compact_constructor
        assert "GovernanceCertificateV1" not in cause_source
        assert "GovernanceCertificateId" not in cause_source
    else:
        assert f'ifcfg!(all(test,{needle.replace(" ", "")})){{0}}else{{' in compact
        assert "store::fast_pauses::get(&*state_transaction.world,&network).map_or(0,|pause|" in compact
        assert "pause.destination_expiry(revision,state_transaction.block_unix_timestamp_ms())" in compact
        production = source.split("#[cfg(test)]\nmod tests", 1)[0]
        assert "destination_paused =" not in production
        assert "fast_pauses::insert(" not in production
    tests = (core / "smartcontracts/isi/world_sccp_governance_tests.rs").read_text()
    control = named_rust_function(tests, name.rsplit("::", 1)[-1])
    compact_control = re.sub(r"\s+", "", control)
    for obligation in (
        "seed_due_sccp_control_certificate(&mut seed, paused)",
        "enact_sccp_control_component(&fixture, &mut execution)",
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
    component = re.sub(r"\s+", "", named_rust_function(tests, "enact_sccp_control_component"))
    assert "fixture.certificate.validate()" in component
    assert "governance::enact(execution,*GovernanceCertificateId::derive_v1(&fixture.certificate).as_bytes(),fixture.certificate.effect_preimage_hash,s0,&payload.proposal,)" in component
    spec = (ROOT / "specs/sumeragi.md").read_text()
    rows = re.findall(rf"^\| {mid} \|.*$", spec, re.M)
    assert len(rows) == 1 and name in rows[0]
    assert "| SC5 (HC257) | CT1 disabled |" in spec
    assert "| SC6 (HC259, HC260, HC264) | CT3 builder pacing disabled |" in spec
    # The existing pending-proof custody rule remains an independent live rule.
    assert len(gate.index_mutations(gate.CORE_MUTATIONS)["HC236"].tests) == 3


def test_sccp_parliament_boundary_owns_certificate_checks_and_requires_original_s0():
    core = ROOT / "crates/iroha_core/src"
    world = (core / "smartcontracts/isi/world.rs").read_text()
    effect = named_rust_function(world, "apply_parliament_proposal_effect_v1")
    adapter = effect.split("ProposalKind::SccpRouteGovernance(payload) => {", 1)[1]
    adapter = adapter.split("ProposalKind::SorafsProviderGovernance", 1)[0]
    compact_adapter = re.sub(r"\s+", "", adapter)
    assert "payload.proposal.network_id!=state_transaction.network_id" in compact_adapter
    assert "certificate.validate()" in compact_adapter
    assert "GovernanceCertificateId::derive_v1(certificate,).as_bytes()" in compact_adapter
    assert "None::<iroha_data_model::governance::GovernanceAnchorV1>.ok_or_else(" in compact_adapter
    assert "casting-open source is unavailable" in adapter
    assert "sccp::governance::enact(state_transaction,certificate_id,certificate.effect_preimage_hash,s0,&payload.proposal,)" in compact_adapter
    assert adapter.index("certificate.validate()") < adapter.index("GovernanceCertificateId::derive_v1")
    assert adapter.index("GovernanceCertificateId::derive_v1") < adapter.index("let s0")
    assert adapter.index("let s0") < adapter.index("sccp::governance::enact(")
    for fabrication in ("GovernanceAnchorV1 {", "GovernanceAnchorV1::", "for_test", "#[cfg(test)]"):
        assert fabrication not in adapter

    context = re.sub(r"\s+", "", named_rust_function(world, "exact_due_parliament_certificate_context_v1"))
    for obligation in (
        "attempt.validate().map_err(parliament_reducer_error)?",
        "attempt.attempt().status != GovernanceAttemptStatusV1::Certified",
        "certificate.validate()",
        "certificate.enact_at_height != current_height",
        "ensure_certificate_only_proposal_v1(proposal_id, &proposal, state_transaction)?",
        "validate_proposal_bindings_v1(&proposal.kind)",
        "certificate.proposal_content_id != attempt.proposal_content_id()",
        "certificate.governance_attempt_id != governance_attempt_id",
        "certificate.governance_attempt_sequence != attempt.attempt().sequence",
        "certificate.effect_preimage_hash != proposal.kind.effect_preimage_hash_v1()",
        "proposal.kind.fingerprint() != proposal_id",
    ):
        assert re.sub(r"\s+", "", obligation) in context
    executor = named_rust_function(world, "execute_due_parliament_certificate_v1")
    compact_executor = re.sub(r"\s+", "", executor)
    assert "exact_due_parliament_certificate_context_v1(governance_attempt_id,state_transaction)?" in compact_executor
    assert "observed_head!=certificate.expected_head" in compact_executor
    assert executor.index("exact_due_parliament_certificate_context_v1(") < executor.index("observed_head != certificate.expected_head")
    assert executor.index("observed_head != certificate.expected_head") < executor.index("apply_parliament_proposal_effect_v1(")

    governance = (core / "smartcontracts/isi/sccp/governance.rs").read_text()
    enact = named_rust_function(governance, "enact")
    signature = enact.split("->", 1)[0]
    assert "GovernanceCertificateV1" not in enact and "GovernanceCertificateId" not in enact
    assert "certificate_id:[u8;32],effect_hash:[u8;32],s0:GovernanceAnchorV1,proposal:&SccpGovernanceProposalV1," in re.sub(r"\s+", "", signature)
    assert "apply_action(state_transaction,action,proposal_id,cause,s0)" in re.sub(r"\s+", "", enact)
    action = re.sub(r"\s+", "", named_rust_function(governance, "apply_action"))
    assert action.count("super::fast_pause::lift(") == 2
    assert "SccpFastPausePartV1::Taira,s0,)?" in action
    assert "SccpFastPausePartV1::Destination{revision:action.revision,},s0,)?" in action
    pause = (core / "smartcontracts/isi/sccp/fast_pause.rs").read_text()
    lift = named_rust_function(pause, "lift")
    assert "precedes_casting_open(s0)" in lift
    assert 'sumeragi_core_mutation = "HC298"' in lift
    assert "policy_jury_casting_open" not in pause
    iface = (core / "smartcontracts/isi/sccp/parliament_iface.rs").read_text()
    assert "PolicyJuryOpening" not in iface and "policy_jury_casting_open" not in iface

    tests = (core / "smartcontracts/isi/world_sccp_governance_tests.rs").read_text()
    closed = re.sub(r"\s+", "", named_rust_function(
        tests, "parliament_due_sccp_certificate_without_casting_open_anchor_fails_without_effects"
    ))
    for obligation in (
        "for paused in [false, true]",
        "fixture.certificate.validate()",
        "apply_parliament_proposal_effect_v1(",
        "execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)",
        "DueParliamentCertificateExecutionV1::EffectFailed",
        "parliament_execution_failure_root_v1(&fixture.certificate, PARLIAMENT_DUE_CERTIFICATE_HEIGHT,)",
        "Some(&original_route)", "Some(&original_pause)", "Some(&original_attempt)",
        "Some(norito::codec::Encode::encode(&original_proposal))",
        "assert_eq!(execution.world.internal_event_buf.len(), original_events)",
        "SccpGovernanceSubjectV1::RouteControl(network)", "SccpGovernanceSubjectV1::FastHold(network)",
        "assert!(store::control_messages::is_empty(&*execution.world))",
        "assert_eq!(leaves::leaf_count_at(&*execution.world, PARLIAMENT_DUE_CERTIFICATE_HEIGHT), 0)",
        "assert_eq!(original_route.revisions[&1].next_control_nonce, 1)",
    ):
        assert re.sub(r"\s+", "", obligation) in closed


@pytest.mark.parametrize("mid,name,cause,path", [
    ("HC400", "registration_requires_both_launch_gates_even_after_native_preconditions",
     "SCCP registration must require both launch gates after native preconditions pass",
     "installation_tests"),
    ("HC401", "enactment_preserves_casting_open_anchor_for_each_pause_part",
     "SCCP enactment must preserve the authenticated casting-open anchor for the requested pause part",
     "anchor_tests"),
])
def test_sccp_registration_and_anchor_mutations_keep_exact_owners_and_failures(mid, name, cause, path):
    core = ROOT / "crates/iroha_core/src"
    owner = "smartcontracts/isi/sccp/governance.rs"
    control_path = f"crates/iroha_core/src/smartcontracts/isi/sccp/governance/{path}.rs"
    qualified = f"smartcontracts::isi::sccp::governance::{path}::{name}"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (qualified,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, control_path),)
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mid, **family)
    needle = f'sumeragi_core_mutation = "{mid}"'
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs") if needle in p.read_text()}
    assert owners == {owner}
    source = (core / owner).read_text()
    assert source.count(needle) == 1
    assert f'all(test,{needle.replace(" ", "")})' in re.sub(r"\s+", "", source)
    controls = (ROOT / control_path).read_text()
    control = named_rust_function(controls, name)
    assert json.dumps(cause) in control
    compact_control = re.sub(r"\s+", "", control)
    if mid == "HC400":
        registration = named_rust_function(source, "register_route")
        compact_registration = re.sub(r"\s+", "", registration)
        assert 'if!(cfg!(all(test,sumeragi_core_mutation="HC400"))||gates.0&&gates.1)' in compact_registration
        assert registration.index("registration::validate_available(") < registration.index(needle)
        assert registration.index(needle) < registration.index("store::routes::insert(")
        assert '#[cfg(test)]letgates=tests::LAUNCH_GATES.with(' in compact_registration
        assert "forgatesin[(true,false),(false,true)]" in compact_control
        assert "super::tests::with_launch_gates(gates," in compact_control
        assert "Some(&before)" in compact_control
        assert "store::destination_words::is_empty(&*stx.world)" in compact_control
        assert "stx.world.take_external_events().is_empty()" in compact_control
        initialize = named_rust_function(controls, "initialize")
        assert "registration::validate_available(stx, &register)" in initialize
        closed = named_rust_function(controls, "registration_with_real_launch_gates_fails_closed_without_state_or_events")
        assert "with_launch_gates" not in closed
        iface = (core / "smartcontracts/isi/sccp/parliament_iface.rs").read_text()
        for gate_source, function in ((source, "sccp_reconciliation_available"),
                                      (iface, "parliament_binding_ballot_available")):
            assert named_rust_function(gate_source, function).split("{", 1)[1].strip() == "false\n}"
    else:
        enact = named_rust_function(source, "enact")
        compact_enact = re.sub(r"\s+", "", enact)
        assert '#[cfg(all(test,sumeragi_core_mutation="HC401"))]lets0={let_=s0;GovernanceAnchorV1{height:0,position:0,timestamp_ms:0,}};' in compact_enact
        assert "apply_action(state_transaction,action,proposal_id,cause,s0)" in compact_enact
        assert "forpartin[Part::Taira,Part::Destination{revision:1}]" in compact_control
        for anchor in ("(1,u32::MAX,false)", "(2,4,false)", "(2,5,false)", "(2,6,true)", "(3,0,true)"):
            assert anchor in compact_control
        assert "fortimestamp_msin[0,8_000,u64::MAX]" in compact_control
        assert "enact(&mutstx,CERTIFICATE_ID,EFFECT_HASH,GovernanceAnchorV1{height,position,timestamp_ms,},&proposal,)" in compact_control
        assert "assert_eq!(control.certificate_id,CERTIFICATE_ID)" in compact_control
        assert "assert_eq!(control.effect_hash,EFFECT_HASH)" in compact_control
        assert "control.fast_pause_until_ms,iflifted{0}else{source.until_ms}" in compact_control
    rows = re.findall(rf"^\| {mid} \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and qualified in rows[0]


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


_FEE_TAIL_MUTATION_CONTROLS = {'HC244': {'description': 'Network failure-fee settlement: swallow the original local execution deferral as a completed rejection', 'owner': 'state/output_network.rs', 'controls': {'state::output_capacity::producer::tests::network::fees::sccp_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'the original fee-tail deferral must not become a completed Network rejection', 'state::output_capacity::producer::tests::network::fees::ordinary_failure_fee_decoder_refusal_keeps_original_deferral_and_retry': 'the original fee-tail deferral must not become a completed Network rejection', 'state::output_capacity::producer::tests::network::penalties::refusal::fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once': 'the original penalty/fee-tail refusal must remain deferred, including after a slash'}}, 'HC245': {'description': 'Network ballot-penalty settlement: swallow the original local execution deferral as a completed rejection', 'owner': 'state/output_network.rs', 'controls': {'state::output_capacity::producer::tests::network::penalties::refusal::actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry': 'the original penalty/fee-tail refusal must remain deferred, including after a slash'}}}
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
        assert "Err(ExecutionOutputAttemptError::Deferred(returned))" in helper
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
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(model=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result['verdict'] == verdict, result
    assert result['named_tests'] == list(rule.tests)


_PAUSE_LAPSE_CONTROLS = {'smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_uses_exact_time_and_preserves_parliament_confirmation': 'the first native block at expiry must remove the original fast-pause record', 'smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_cancellation_keeps_original_record_and_retries_once': 'the original native execution must stage lapse before publication'}


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
    source = (core / "smartcontracts/isi/sccp/read/native/control_producer_tests/lapse_tests.rs").read_text()
    for name, cause in _PAUSE_LAPSE_CONTROLS.items():
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        assert cause in body
        assert "control_chain(false)" in body
    assert "mod lapse_tests;" in (core / "smartcontracts/isi/sccp/read/native/control_producer_tests.rs").read_text()
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
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


_PARENT_SERVICE_CUSTODY_CONTROLS = {'sumeragi::executor::parent_service_custody_tests::parent_service_validation_retains_original_receipts_without_waking_its_own_retry': 'parent-service validation keeps original receipts instead of refunding its own waiter', 'sumeragi::executor::parent_service_custody_tests::parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry': 'parent-service assembly retains original receipt charges at first refusal'}


def test_parent_service_custody_mutation_selects_both_actual_worker_waiters():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC248"]
    assert rule.tests == tuple(_PARENT_SERVICE_CUSTODY_CONTROLS) and not rule.scenarios
    assert gate.has_switch("HC248", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC248", **family)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if 'sumeragi_core_mutation = "HC248"' in p.read_text()}
    assert owners == {"sumeragi/executor.rs"}
    executor = (core / "sumeragi/executor.rs").read_text()
    compact = re.sub(r"\s+", "", executor)
    assert compact.count('#[cfg(all(test,sumeragi_core_mutation="HC248"))]') == 2
    assert 'ifprepared.is_err(){self.signature_decode.as_mut().expect("originalsignedproposal").parent_service=Default::default();}' in compact
    assert 'ifprepared.is_err(){self.assembly_parent_service=None;}' in compact
    source = (core / "sumeragi/executor_parent_service_custody_tests.rs").read_text()
    for name, cause in _PARENT_SERVICE_CUSTODY_CONTROLS.items():
        marker = "fn " + name.rsplit("::", 1)[-1] + "("
        assert source.count(marker) == 1
        body = source.split(marker, 1)[1].split("#[test]", 1)[0]
        normalized = re.sub(r"\s+", "", body)
        assert cause in body and 'occupy_at_real_authority(&budget)' in normalized
        assert 'registration.poll_wait(release,&mutcontext).is_pending()' in normalized
        assert 'drop(occupied.borrow_mut().take())' in normalized
        assert 'registration.poll_wait(release,&mutcontext).is_ready()' in normalized
        assert 'observe_parent_service_admission(' in body
    assembly = source.split(
        "fn parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry(", 1
    )[1].split("#[test]", 1)[0]
    assembly_compact = re.sub(r"\s+", "", assembly)
    original_charge = 'assert_eq!(budget.reserved_bytes(),budget.limit_bytes(),"parent-serviceassemblyretainsoriginalreceiptchargesatfirstrefusal");'
    assert original_charge in assembly_compact
    assert assembly_compact.index(original_charge) < assembly_compact.index(".original_pointers()")
    assert "parent-service assembly retains original parent receipts instead of waking its own retry" in assembly
    assert "unchanged full pool still refuses original assembly" in assembly
    assert "pointers_before_retry" in assembly
    assert 'mod parent_service_custody_tests;' in executor
    rows = re.findall(r"^\| HC248 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error"),
    ("missing", "error"), ("incidental", "error"),
])
def test_parent_service_custody_mutation_requires_exact_declared_terminals(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC248"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def causal_control_output(rule, rows):
    """Generate captured panic fixtures for script checks, never native kill evidence."""
    code, output = exact_control_output(rows)
    sections = []
    expectations = dict(zip(rule.tests, rule.causes))
    for name, verdict in rows:
        if verdict != "FAILED" or name not in expectations:
            continue
        expected = expectations[name]
        body = (f"---- {name} stdout ----\n\n"
                f"thread '{expected.worker_thread or name}' (12) panicked at {expected.source}:123:7:\n"
                f"{expected.cause}\n")
        if expected.worker_thread:
            body += (f"\nthread '{name}' (13) panicked at {expected.join_source}:59:10:\n"
                     f"{expected.join_message}\n")
        sections.append(body)
    if sections:
        output = output.replace('test result:', 'failures:\n\n' + '\n'.join(sections) + '\nfailures:\n\ntest result:')
    return code, output


def causal_rule(mid):
    """Select the registered original owner of a declared cause."""
    return gate.index_mutations(gate.MODEL_MUTATIONS if mid == 'DM34' else gate.CORE_MUTATIONS)[mid]


@pytest.mark.parametrize('mid', ['HC246', 'HC247', 'HC248', 'HC252', 'HC254', 'HC255', 'HC256', 'HC328', 'HC329', 'DM34'])
@pytest.mark.parametrize('corruption', ['none', 'unrelated', 'incidental', 'source', 'owner', 'missing_panic', 'extra_panic', 'outside_section', 'duplicate_section', 'one_passes', 'all_pass'])
def test_declared_causal_mutation_requires_every_owned_cause(monkeypatch, tmp_path, mid, corruption):
    rule = causal_rule(mid)
    assert len(rule.causes) == len(rule.tests)
    rows = [(name, 'ok' if corruption == 'all_pass' or corruption == 'one_passes' and index == 0 else 'FAILED') for index, name in enumerate(rule.tests)]
    code, output = causal_control_output(rule, rows)
    name, expected = rule.tests[0], rule.causes[0]
    panic = f"thread '{expected.worker_thread or name}' (12) panicked at {expected.source}:123:7:\n{expected.cause}\n"
    if corruption == 'unrelated':
        output = output.replace(expected.cause, 'unexpected setup failure', 1)
    elif corruption == 'incidental':
        output = output.replace(expected.cause, 'unexpected setup failure\n' + expected.cause, 1)
    elif corruption == 'source':
        output = output.replace(expected.source + ':123:', 'wrong_source.rs:123:', 1)
    elif corruption == 'owner':
        output = output.replace("thread '" + (expected.worker_thread or name) + "'", "thread 'wrong_owner'", 1)
    elif corruption == 'missing_panic':
        output = output.replace(panic, '', 1)
    elif corruption == 'extra_panic':
        output = output.replace(panic, panic + "thread 'extra' panicked at extra.rs:1:1:\nextra failure\n", 1)
    elif corruption == 'outside_section':
        output = panic + output.replace(panic, '', 1)
    elif corruption == 'duplicate_section':
        output = output.replace(panic, panic + f'---- {name} stdout ----\n', 1)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(model=mid == 'DM34', core=mid != 'DM34', target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = 'killed_by_test' if corruption == 'none' else 'survived' if corruption == 'all_pass' or corruption == 'one_passes' and len(rule.tests) == 1 else 'error'
    assert result['verdict'] == verdict, result
    if corruption == 'none':
        assert result['named']['causal_failures'] == dict.fromkeys(rule.tests, True)


@pytest.mark.parametrize('mid', ['HC247', 'HC248', 'HC252', 'HC328', 'HC329'])
@pytest.mark.parametrize('corruption', ['join_owner', 'join_source', 'join_message', 'reversed', 'missing_join'])
def test_declared_causal_worker_requires_original_child_and_join(monkeypatch, tmp_path, mid, corruption):
    rule = causal_rule(mid)
    code, output = causal_control_output(rule, [(name, 'FAILED') for name in rule.tests])
    name, expected = rule.tests[0], rule.causes[0]
    child = f"thread '{expected.worker_thread}' (12) panicked at {expected.source}:123:7:\n{expected.cause}\n"
    join = f"thread '{name}' (13) panicked at {expected.join_source}:59:10:\n{expected.join_message}\n"
    if corruption == 'join_owner':
        output = output.replace(join, join.replace(name, 'wrong_join'), 1)
    elif corruption == 'join_source':
        output = output.replace(join, join.replace(expected.join_source, 'wrong_join.rs'), 1)
    elif corruption == 'join_message':
        output = output.replace(join, join.replace(expected.join_message, 'unrelated failure'), 1)
    elif corruption == 'reversed':
        output = output.replace(child + '\n' + join, join + '\n' + child, 1)
    elif corruption == 'missing_join':
        output = output.replace(join, '', 1)
    monkeypatch.setattr(gate, 'has_switch', lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, 'build', lambda *args: gate.Step(status='pass'))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result['verdict'] == 'error', result


def test_declared_causal_registration_rejects_incomplete_or_ambiguous_policy():
    expected = gate.ExpectedFailure('own cause', 'original.rs')
    for tests, causes in [(['leaf'], [expected]), (['tests::named'], [expected, expected]), (['tests::named', 'tests::named'], [expected, expected]), (['tests::named'], [gate.ExpectedFailure('', 'original.rs')]), (['tests::named'], [gate.ExpectedFailure('own cause', 'original.rs', worker_thread='worker')])]:
        with pytest.raises(ValueError):
            gate.m('FIXTURE', 'script control', tests, causes=causes)


def test_native_authority_mapper_has_an_independent_original_custody_mutation():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC249"]
    assert rule.tests == (
        "sumeragi::certified_chain::funded_authority::tests::"
        "native_authority_prepaid_custody_errors_require_recovery",
    )
    assert not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(
        "prepaid authority custody violations must require recovery",
        "crates/iroha_core/src/sumeragi/certified_chain/funded_authority/tests.rs",
    ),)
    assert gate.has_switch("HC249", core=True)
    assert not gate.has_switch("HC249")


def test_direct_payment_replay_mutation_requires_original_fee_effect_failure():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC265"]
    assert rule.tests == (
        "executor::settlement_replay::tests::"
        "direct_payment_replay_two_carriers_charge_once_and_recover_after_certified_restart",
    )
    assert not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(
        "same direct payment identity charges one execution fee across distinct carriers",
        "crates/iroha_core/src/executor/settlement_replay_tests.rs",
    ),)
    assert gate.has_switch("HC265", core=True)
    for family in ({}, {"model": True}):
        assert not gate.has_switch("HC265", **family)


def test_amx_discovery_mutation_requires_authenticated_zero_record_progress_failure():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC270"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::paid_borrowed_custody::discovery::"
        "native_amx_discovery_advances_ordinary_global_height_then_delivers_both_final_tip_decisions",
    )
    assert rule.causes == (gate.ExpectedFailure(
        "authenticated zero-record height must advance without an AMX coordinates file",
        "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/discovery.rs",
    ),)
    assert gate.has_switch("HC270", core=True)
    assert not gate.has_switch("HC270")
    assert not gate.has_switch("HC270", model=True)


@pytest.mark.parametrize("mutation,test,path,cause", [
    ("HC328",
     "sumeragi::executor::payload_owner::tests::fresh_view_refreshes_authenticated_block_time_without_replacing_signed_input",
     "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
     "fresh view must refresh certified time without another signed transaction"),
    ("HC329",
     "sumeragi::executor::clock_tests::authenticated_proposer_time_above_floor_executes_and_replays_without_restamping",
     "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
     "authenticated proposer time above the input floor must execute: Ok(Some(Invalid))"),
])
def test_authenticated_proposer_time_mutations_require_exact_native_regressions(
    mutation, test, path, cause
):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert rule.tests == (test,)
    assert rule.causes == (gate.ExpectedFailure(
        cause, path,
        worker_thread="sumeragi-publication-test",
        join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
        join_message="publication worker fixture: Any { .. }",
    ),)
    assert gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)


@pytest.mark.parametrize("mutation,test,path,message", [
    ("HC328",
     "sumeragi::executor::payload_owner::tests::fresh_view_refreshes_authenticated_block_time_without_replacing_signed_input",
     "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
     "assertion `left == right` failed: fresh view must refresh certified time without another signed transaction"),
    ("HC329",
     "sumeragi::executor::clock_tests::authenticated_proposer_time_above_floor_executes_and_replays_without_restamping",
     "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
     "authenticated proposer time above the input floor must execute: Ok(Some(Invalid))"),
])
def test_authenticated_proposer_time_accepts_exact_publication_worker_failure(
    mutation, test, path, message
):
    # Literal native panic shapes are independent of the expected-cause declaration.
    output = (
        f"---- {test} stdout ----\n\n"
        f"thread 'sumeragi-publication-test' (12) panicked at {path}:123:7:\n{message}\n"
        f"\nthread '{test}' (13) panicked at "
        "crates/iroha_core/src/sumeragi/executor_publication_tests.rs:142:10:\n"
        "publication worker fixture: Any { .. }\n"
    )
    panics, valid = gate.captured_test_panics(output)
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    assert valid and gate.expected_test_failure(test, rule.causes[0], panics[test])


@pytest.mark.parametrize("outcome", ["Ok(None)", "Err(StorageBusy)", "Ok(Some(Valid))", ""])
def test_authenticated_proposer_time_rejects_unrelated_execution_outcome(outcome):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC329"]
    name, expected = rule.tests[0], rule.causes[0]
    panics = [
        dict(thread="sumeragi-publication-test",
             source="crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
             message="authenticated proposer time above the input floor must execute: " + outcome),
        dict(thread=name,
             source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
             message="publication worker fixture: Any { .. }"),
    ]
    assert not gate.expected_test_failure(name, expected, panics)


@pytest.mark.parametrize("mutation,daemon,test,path,cause", [
    ("HC330", False,
     "sumeragi::amx::native::tests::paid_borrowed_custody::handoffs::native_amx_handoff_discovery_delivers_final_boundary_without_record_and_replays_both_roots",
     "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/handoffs.rs",
     "authenticated final epoch boundary must deliver its handoff without an AMX row or successor"),
    ("HC331", True,
     "amx_relay::ledger::handoff_recovery_tests::fresh_relayer_recovers_independent_native_handoffs_after_two_epochs_and_restart",
     "crates/irohad/src/amx_relay/handoff_recovery_tests.rs",
     "fresh relayer must recover the original independent successful handoff after its source epoch is no longer tracked"),
    ("HC332", True,
     "amx_relay::tests::growing_source_tip_cannot_starve_pending_original_handoff_retry",
     "crates/irohad/src/amx_relay.rs",
     "continuous source growth must not starve bounded retry of the original handoff"),
])
def test_native_amx_handoff_mutations_require_exact_recovery_regressions(
    mutation, daemon, test, path, cause
):
    rules = gate.DAEMON_MUTATIONS if daemon else gate.CORE_MUTATIONS
    rule = gate.index_mutations(rules)[mutation]
    assert rule.tests == (test,)
    assert rule.causes == (gate.ExpectedFailure(cause, path),)
    assert gate.has_switch(mutation, daemon=daemon, core=not daemon)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)
    assert not gate.has_switch(mutation, daemon=not daemon, core=daemon)


@pytest.mark.parametrize("mutation,daemon,test,path,cause", [
    ("HC342", False,
     "sumeragi::amx::native::tests::paid_borrowed_custody::route_discovery::native_amx_route_discovery_retains_refused_handoff_while_another_destination_advances",
     "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/route_discovery.rs",
     "requested route must be selected before unrelated target graph acquisition"),
    ("HC338", False,
     "sumeragi::amx::native::tests::paid_borrowed_custody::expiry_recovery::native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive",
     "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/expiry_recovery.rs",
     "a child root cannot authenticate the Global expiry decision"),
    ("HC339", False,
     "sumeragi::amx::native::tests::paid_borrowed_custody::expiry_recovery::native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive",
     "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/expiry_recovery.rs",
     "cached positive height must reauthenticate original proof before suppressing a carrier"),
    ("HC340", True,
     "amx_relay::ledger::expiry_recovery_tests::independently_decided_expiry_recovers_only_the_existing_exact_carrier_without_dispatch",
     "crates/irohad/src/amx_relay/expiry_recovery_tests.rs",
     "read-only carrier recovery must preserve independently authenticated outcomes: unknown"),
])
def test_native_amx_expiry_recovery_mutations_require_authenticated_outcomes(
    mutation, daemon, test, path, cause
):
    rules = gate.DAEMON_MUTATIONS if daemon else gate.CORE_MUTATIONS
    rule = gate.index_mutations(rules)[mutation]
    assert rule.tests == (test,)
    assert rule.causes == (gate.ExpectedFailure(cause, path),)
    assert gate.has_switch(mutation, daemon=daemon, core=not daemon)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)
    assert not gate.has_switch(mutation, daemon=not daemon, core=daemon)


def test_lane_first_prepare_mutation_requires_original_source_regression():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC333"]
    assert rule.tests == (
        "sumeragi::lanes::executor::native_decode_tests::native_lane_first_prepare_admission_binds_original_source_and_retains_its_charge",
    )
    assert rule.causes == (gate.ExpectedFailure(
        "certification never exempts source substitution",
        "crates/iroha_core/src/sumeragi/lanes/executor/native_decode_tests.rs",
    ),)
    assert gate.has_switch("HC333", core=True)
    assert not gate.has_switch("HC333")
    assert not gate.has_switch("HC333", model=True)
    assert not gate.has_switch("HC333", daemon=True)


def test_lane_queue_lease_mutation_preserves_original_admission_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC327"]
    prefix = "sumeragi::lanes::executor::queue_lease_tests::"
    assert rule.tests == tuple(prefix + name for name in (
        "lane_original_queue_lease_retires_expiry_and_withdrawal_during_clock_wait",
        "lane_original_queue_lease_rechecks_withdrawal_after_actual_encoding",
        "lane_original_queue_lease_preserves_same_output_across_clock_rewind_and_retires_readmission",
    ))
    assert rule.causes == tuple(gate.ExpectedFailure(message,
        "crates/iroha_core/src/sumeragi/lanes/executor/queue_lease_tests.rs")
        for message in (
            "lane clock retry must retire expired or withdrawn original Queue admission",
            "lane retained output must not outlive its original Queue admission",
            "same-hash readmission must not revive the retained lane Queue lease",
        ))
    assert gate.has_switch("HC327", core=True)
    assert not gate.has_switch("HC327")
    assert not gate.has_switch("HC327", model=True)


def test_begin_delivery_mutation_requires_original_post_admission_source_failure():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC271"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::paid_borrowed_custody::begins::"
        "native_amx_begin_delivery_final_namespace_refusal_preserves_original_instruction",
    )
    assert rule.causes == (gate.ExpectedFailure(
        "source namespace must be rechecked after instruction admission",
        "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/begins.rs",
    ),)
    assert gate.has_switch("HC271", core=True)
    assert not gate.has_switch("HC271")
    assert not gate.has_switch("HC271", model=True)


def test_decision_delivery_mutation_requires_original_post_admission_source_failure():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC267"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::paid_borrowed_custody::"
        "native_amx_decision_delivery_final_namespace_refusal_preserves_original_instruction",
    )
    assert rule.causes == (gate.ExpectedFailure(
        "Decision delivery must recheck original namespace after instruction admission",
        "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody.rs",
    ),)
    assert gate.has_switch("HC267", core=True)
    assert not gate.has_switch("HC267")


def test_proposer_clock_selection_mutation_preserves_both_native_selection_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC259"]
    assert rule.tests == (
        "sumeragi::payload::resource_contract_tests::"
        "proposer_clock_selection_retains_future_signed_inputs_until_the_exact_time",
        "sumeragi::payload::resource_contract_tests::"
        "lane_proposer_clock_selection_preserves_future_inputs_and_resumes_after_advance",
    )
    assert rule.causes == (
        gate.ExpectedFailure(
            "global proposer must leave future signed input queued",
            "crates/iroha_core/src/sumeragi/payload/resource_contract_tests.rs",
        ),
        gate.ExpectedFailure(
            "lane proposer must leave future signed input queued",
            "crates/iroha_core/src/sumeragi/payload/resource_contract_tests.rs",
        ),
    )
    assert gate.has_switch("HC259", core=True)
    assert not gate.has_switch("HC259")


def test_proposer_clock_publication_mutation_preserves_original_payload_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC260"]
    assert rule.tests == (
        "sumeragi::executor::payload_owner::tests::"
        "proposer_clock_retains_final_input_and_canonical_output_until_due",
        "sumeragi::executor::payload_owner::tests::"
        "proposer_clock_retains_certified_lane_floor_and_completed_original",
    )
    assert tuple(cause.cause for cause in rule.causes) == (
        "canonical payload clock must wait after its signed input becomes due",
        "canonical lane merge floor must wait without empty or unrelated work",
    )
    assert gate.has_switch("HC260", core=True)
    assert not gate.has_switch("HC260")


@pytest.mark.parametrize("mid,owner,controls", [
    ("HC248", "sumeragi/executor.rs", (
        "sumeragi::executor::parent_service_custody_tests::parent_service_validation_retains_original_receipts_without_waking_its_own_retry",
        "sumeragi::executor::parent_service_custody_tests::parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry",
    )),
    ("HC249", "sumeragi/certified_chain/funded_authority.rs", (
        "sumeragi::certified_chain::funded_authority::tests::native_authority_prepaid_custody_errors_require_recovery",
    )),
    ("HC250", "smartcontracts/isi/sccp/generations.rs", (
        "smartcontracts::isi::sccp::generations::tests::global_member_binding_ignores_participant_staking_registration",
    )),
    ("HC251", "smartcontracts/isi/sccp/generations.rs", (
        "smartcontracts::isi::sccp::generations::tests::destination_clearance_visits_only_bounded_pending_index_after_cleared_history",
    )),
])
def test_sccp_generation_mutations_keep_unique_rules_and_original_custody_owners(mid, owner, controls):
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    assert tuple(registered[mid].tests) == controls
    assert not registered[mid].scenarios
    source = ROOT / "crates/iroha_core/src"
    owners = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*.rs")
        if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())
    }
    assert owners == {owner}, "another source rule must not share this mutation's causal identity"
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1
    assert all(control.rsplit("::", 1)[-1] in rows[0] for control in controls)


@pytest.mark.parametrize("mid,test,cause,relation", [
    ("HC250", "global_member_binding_ignores_participant_staking_registration",
     "global elected signer remains slashable", "key.0 == LaneId::SINGLE"),
    ("HC251", "destination_clearance_visits_only_bounded_pending_index_after_cleared_history",
     "work is independent of {cleared_history} cleared records", ".take(64)"),
])
def test_sccp_generation_mutations_keep_their_original_causal_assertions(mid, test, cause, relation):
    source = ROOT / "crates/iroha_core/src/smartcontracts/isi/sccp/generations.rs"
    code = source.read_text()
    condition = 'all(test, sumeragi_core_mutation = "' + mid + '")'
    if mid == "HC251":
        assert code.count("#[cfg(" + condition + ")]") == 1
        assert code.count("#[cfg(not(" + condition + "))]") == 1
    else:
        assert code.count("cfg!(" + condition + ")") == 1
    assert relation in code
    controls = source.with_suffix("") / "tests.rs"
    text = controls.read_text()
    body = text.split("fn " + test + "() {", 1)[1].split("\n#[test]", 1)[0]
    assert cause in body
    assert gate.index_mutations(gate.CORE_MUTATIONS)[mid].tests == (
        "smartcontracts::isi::sccp::generations::tests::" + test,
    )


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("fault", ["unrelated", "old_assembly_wait", "incidental"])
def test_parent_service_each_cause_cannot_be_masked_by_its_sibling(monkeypatch, tmp_path, index, fault):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC248"]
    code, output = causal_control_output(rule, [(name, "FAILED") for name in rule.tests])
    cause = rule.causes[index].cause
    replacement = {
        "unrelated": "unrelated setup refusal",
        "old_assembly_wait": "parent-service assembly retains original parent receipts instead of waking its own retry",
        "incidental": "unrelated setup refusal\nincidental diagnostic: " + cause,
    }[fault]
    output = output.replace(cause, replacement, 1)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == "error", result



def test_retained_execution_wakeup_mutation_owns_actual_partial_payload_expiry():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC252"]
    assert rule.tests == ("sumeragi::executor::payload_owner::tests::retained_partial_payload_idle_expiry_wakes_original_commit_with_live_execution",) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(
        "actual original-pool retirement permits the same committed head to retry",
        "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
        worker_thread="sumeragi-publication-test",
        join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
        join_message="publication worker fixture: Any { .. }",
    ),)
    core = ROOT / "crates/iroha_core/src"
    owners = {p.relative_to(core).as_posix() for p in core.rglob("*.rs")
              if 'sumeragi_core_mutation = "HC252"' in p.read_text()}
    assert owners == {"sumeragi/driver/exec.rs"}
    assert gate.has_switch("HC252", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC252", **family)
    source = (core / "sumeragi/executor/payload_owner.rs").read_text()
    body = source.split("fn retained_partial_payload_idle_expiry_wakes_original_commit_with_live_execution() {", 1)[1].split("#[test]", 1)[0]
    for original in ["stage_original_partial", "publication_tests::executed", "scheduler.bind_release_thread",
                     "clock.advance(queue.tx_time_to_live", "worker.payload_storage_wait()",
                     "budget.reserved_bytes() < occupied", "queue.contains_entrypoint_hash(input_hash)",
                     "live.overlay.as_deref()", "live.commitment().get()", "live.source, original_source",
                     "live.result, original_result", "Arc::ptr_eq(&original, &retry)"]:
        assert original in body
    assert body.index("actual original-pool retirement permits the same committed head to retry") < body.index("drop(pressure)")
    rows = re.findall(r"^\| HC252 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and rule.tests[0] in rows[0]


def test_original_journal_availability_mutation_preserves_both_physical_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC253"]
    assert rule.tests == tuple(
        "sumeragi::executor::payload_owner::tests::retained_partial_payload_refuses_"
        + kind + "_original_parent_and_resumes_same_paid_wire"
        for kind in ("missing", "substituted")
    )
    assert len(rule.causes) == 2
    for cause in rule.causes:
        assert cause == gate.ExpectedFailure(
            "original parent journal unavailability remains retryable",
            "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
            worker_thread="sumeragi-publication-test",
            join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
            join_message="publication worker fixture: Any { .. }",
        )
    assert gate.has_switch("HC253", core=True)
    rows = re.findall(r"^\| HC253 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error"),
    ("missing", "error"), ("incidental", "error"),
])
def test_original_journal_availability_requires_exact_failures(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC253"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error"),
    ("missing", "error"), ("incidental", "error"),
])
def test_retained_execution_wakeup_requires_its_exact_native_control(monkeypatch, tmp_path, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC252"]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_full_state_clock_mutations_have_exact_owners_and_runtime_controls():
    expected = {
        "HC257": (
            "sumeragi/executor.rs",
            "sumeragi::executor::clock_tests::prepare_withheld_while_block_time_ahead",
        ),
        "HC258": (
            "sumeragi/driver/mod.rs",
            "sumeragi::driver::tests::sched::certified_execution_flag_reaches_the_application_without_inference",
        ),
    }
    core = ROOT / "crates/iroha_core/src"
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    for identifier, (owner, selector) in expected.items():
        rule = rules[identifier]
        assert rule.tests == (selector,) and not rule.scenarios
        assert len(rule.causes) == 1
        owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
                  if f'sumeragi_core_mutation = "{identifier}"' in path.read_text()}
        assert owners == {owner}
        assert gate.has_switch(identifier, core=True)
        for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                       {"deploy": True}, {"torii": True}, {"norito": True}):
            assert not gate.has_switch(identifier, **family)
        rows = re.findall(r"^\| " + identifier + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
        assert len(rows) == 1 and selector in rows[0]
    controls = (core / "sumeragi/executor/clock_tests.rs").read_text()
    for name in ("prepare_withheld_while_block_time_ahead", "certified_execution_skips_clock_guards"):
        assert f"fn {name}()" in controls
    assert "restored.replay(&block, &qc)" in controls
    assert "!worker.results.contains_key(&hash)" in controls


def assert_original_journal_static_causal_literal(source, name, expected):
    """Bind the gate cause to the exact executed Retryable assertion's literal."""
    body = source.split("fn " + name.rsplit("::", 1)[-1] + "() {", 1)[1].split("#[test]", 1)[0]
    literals = re.findall(
        r'assert!\(\s*matches!\(result, Err\(PublicationError::Retryable\(_\)\)\),'
        r'\s*("(?:[^"\\]|\\.)*")\s*\);', body
    )
    assert literals == [json.dumps(expected.cause)], "HC253 requires the exact static native causal message"


@pytest.mark.parametrize("index", [0, 1])
def test_original_journal_causal_messages_match_actual_rust_assertions(index):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC253"]
    expected = rule.causes[index]
    source = (ROOT / expected.source).read_text()
    assert_original_journal_static_causal_literal(source, rule.tests[index], expected)


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("replacement", [
    '"original parent journal unavailability remains retryable: {result:?}"',
    '"original parent journal unavailability remains retryable: {:?}", result',
    '"original parent journal unavailability remains retryable {}", ""',
    '"original parent journal unavailability remains retryable "',
])
def test_original_journal_causal_literal_rejects_dynamic_or_extra_message_text(index, replacement):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC253"]
    expected = rule.causes[index]
    source = (ROOT / expected.source).read_text()
    original = json.dumps(expected.cause)
    assert source.count(original) == 2
    source = source.replace(original, replacement)
    with pytest.raises(AssertionError, match="exact static native causal message"):
        assert_original_journal_static_causal_literal(source, rule.tests[index], expected)


LANE_GEOMETRY_CAUSAL_CONTROLS = (
    ("HC254", 0, "completed_publication_refuses_substituted_journal_namespace_and_retries_original_owner", "result.is_err()"),
    ("HC254", 1, "substituted_tiered_path", "result.is_err()"),
    ("HC254", 2, "substituted_tiered_path", "result.is_err()"),
    ("HC255", 0, "assert_retained", "original.tiered.as_ref().unwrap().is_applied()"),
    ("HC256", 0, "completed_publication_refuses_changed_baseline_and_retries_original_owner", "result.is_err()"),
)


def assert_lane_geometry_static_cause(source, function, condition, expected):
    """Require the exact executed assertion condition and static owner message."""
    body = source.split("fn " + function + "(", 1)[1].split("\nfn ", 1)[0]
    literals = re.findall(
        r'assert!\(\s*' + re.escape(condition) + r',\s*("(?:[^"\\]|\\.)*")\s*\);', body
    )
    assert literals == [json.dumps(expected.cause)], "geometry mutation requires its exact static native cause"


@pytest.mark.parametrize("mid,owner,tests", [
    ("HC254", "state/geometry_publication.rs", (
        "completed_publication_refuses_substituted_journal_namespace_and_retries_original_owner",
        "prepublication_refuses_substituted_tiered_directory_and_retries_original_owner",
        "completed_publication_refuses_substituted_tiered_directory_and_retries_original_owner",
    )),
    ("HC255", "state/geometry_publication.rs", (
        "completed_retry_preserves_original_applied_progress_on_tiered_identity_refusal",
    )),
    ("HC256", "kura/lane_geometry/raw_attempt.rs", (
        "completed_publication_refuses_changed_baseline_and_retries_original_owner",
    )),
])
def test_lane_geometry_mutations_keep_separate_original_production_owners(mid, owner, tests):
    registry = gate.index_mutations(gate.CORE_MUTATIONS)
    assert len(registry) == len(gate.CORE_MUTATIONS)
    rule = registry[mid]
    assert rule.tests == tuple("state::tests::geometry_completion_tests::" + name for name in tests)
    assert not rule.scenarios
    assert len(rule.causes) == len(rule.tests)
    assert all(expected.source == "crates/iroha_core/src/state/geometry_completion_tests.rs"
               and expected.worker_thread == "" and expected.join_source == ""
               and expected.join_message == ""
               for expected in rule.causes)
    core = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())}
    assert owners == {owner}
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True},
                   {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch(mid, **family)
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("mid,index,function,condition", LANE_GEOMETRY_CAUSAL_CONTROLS)
def test_lane_geometry_causal_messages_match_actual_rust_assertions(mid, index, function, condition):
    expected = gate.index_mutations(gate.CORE_MUTATIONS)[mid].causes[index]
    assert_lane_geometry_static_cause((ROOT / expected.source).read_text(), function, condition, expected)


@pytest.mark.parametrize("mid,index,function,condition", LANE_GEOMETRY_CAUSAL_CONTROLS)
@pytest.mark.parametrize("suffix", [': {result:?}', ' ', ' {}'])
def test_lane_geometry_causal_message_rejects_dynamic_or_extra_text(mid, index, function, condition, suffix):
    expected = gate.index_mutations(gate.CORE_MUTATIONS)[mid].causes[index]
    source = (ROOT / expected.source).read_text()
    original = json.dumps(expected.cause)
    assert source.count(original) == 1
    with pytest.raises(AssertionError, match="exact static native cause"):
        assert_lane_geometry_static_cause(source.replace(original, json.dumps(expected.cause + suffix)), function, condition, expected)


@pytest.mark.parametrize("mid", ["HC254", "HC255", "HC256"])
@pytest.mark.parametrize("status,verdict", [
    ("ok", "survived"), ("FAILED", "killed_by_test"), ("ignored", "error"),
    ("missing", "error"), ("incidental", "error"),
])
def test_lane_geometry_requires_every_exact_declared_terminal(monkeypatch, tmp_path, mid, status, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    rows = [] if status == "missing" else [
        (name + "_incidental", "FAILED") if status == "incidental" else (name, status)
        for name in rule.tests
    ]
    code, output = causal_control_output(rule, rows)
    selected_cargo_results(monkeypatch, code, output, names=tuple(name for name, _ in rows))
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == verdict, result
    assert result["named_tests"] == list(rule.tests)


def test_lane_geometry_regressions_keep_original_source_and_prepublication_boundaries():
    source = (ROOT / "crates/iroha_core/src/state/geometry_completion_tests.rs").read_text()
    for required in [
        "raw.publish_catalog_under(&lease, Some(baseline))", "original_owners(state),",
        "RawGeometryPhase::FilesApplied", "RawGeometryPhase::CatalogPublished",
        "!failure.rollback_safe", "original.cursors_updated", "original_metadata.ctime()",
        "original_metadata.ctime_nsec()", "fs::rename(&displaced, store_root)",
        "fs::rename(&displaced, &lane)", "for changed in [None, Some(foreign)]",
        "substituted_tiered_path(false, false)", "substituted_tiered_path(true, false)",
        "substituted_tiered_path(true, true)", "retry_original(state, configured, kura, baseline)",
    ]:
        assert required in source
    assert "stack_size" not in source and "#[ignore" not in source


@pytest.mark.parametrize("mid,index,function,condition", LANE_GEOMETRY_CAUSAL_CONTROLS)
@pytest.mark.parametrize("corruption", ["unrelated", "wrong_source", "missing_panic"])
def test_lane_geometry_other_controls_cannot_mask_one_wrong_cause(monkeypatch, tmp_path, mid, index, function, condition, corruption):
    del function, condition
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    code, output = causal_control_output(rule, [(name, "FAILED") for name in rule.tests])
    name, expected = rule.tests[index], rule.causes[index]
    panic = f"thread '{name}' (12) panicked at {expected.source}:123:7:\n{expected.cause}\n"
    assert output.count(panic) == 1
    wrong = (panic.replace(expected.cause, "unrelated fixture failure") if corruption == "unrelated"
             else panic.replace(expected.source, "wrong_source.rs") if corruption == "wrong_source"
             else "")
    output = output.replace(panic, wrong, 1)
    monkeypatch.setattr(gate, "has_switch", lambda *args, **kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == "error", result


def test_lane_clock_retry_mutation_owns_the_original_builder_answer():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC264"]
    name = "sumeragi::lanes::executor::tests::future_only_lane_work_retries_without_an_empty_answer_or_new_traffic"
    assert rule.tests == (name,)
    assert not rule.scenarios
    assert len(rule.causes) == 1
    cause = rule.causes[0]
    assert cause.source == "crates/iroha_core/src/sumeragi/lanes/executor.rs"
    assert cause.cause == "future-only lane work must retry instead of reporting an empty payload"
    assert not cause.worker_thread and not cause.join_source and not cause.join_message
    source = (ROOT / cause.source).read_text()
    assert 'sumeragi_core_mutation = "HC264"' in source
    assert 'Err(LaneSelectionError::ClockAhead)' in source
    assert 'return Err(PublicationError::Retryable("ClockAhead".into()))' in source
    assert 'clock.advance(Duration::from_millis(1))' in source
    assert source.count('"' + cause.cause + '"') == 1
    assert gate.has_switch("HC264", core=True)
    assert not gate.has_switch("HC264")
    assert len(re.findall(r"^\| HC264 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)) == 1


@pytest.mark.parametrize("mid,name,source,cause", [
    ("HC268", "sumeragi::lanes::executor::native_decode_tests::signed_lane_clock_retains_original_admission_until_exact_boundary_and_certified_replay", "crates/iroha_core/src/sumeragi/lanes/executor/native_decode_tests.rs", "uncertified lane must wait at its authenticated effective clock boundary"),
    ("HC269", "sumeragi::lanes::executor::tests::lane_builder_effective_clock_retains_original_payload_across_clock_rewind", "crates/iroha_core/src/sumeragi/lanes/executor.rs", "lane builder must retain its original effective timestamp before publication"),
])
def test_lane_effective_clock_rules_have_exact_original_owners(mid, name, source, cause):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (name,) and not rule.scenarios
    assert len(rule.causes) == 1
    expected = rule.causes[0]
    assert expected.source == source and expected.cause == cause
    assert not expected.worker_thread and not expected.join_source and not expected.join_message
    assert (ROOT / source).read_text().count('"' + cause + '"') == 1
    assert gate.has_switch(mid, core=True) and not gate.has_switch(mid)
    assert len(re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)) == 1


@pytest.mark.parametrize("mutation,test,cause", [
    ('HC334', 'sumeragi::executor::prepare_admission_tests::ct5_post_encoding_clock_advance_rolls_back_actual_begin_and_fees_with_original_decode', 'time-sensitive effects must be locally deferred after the last encoding wait'),
    ('HC335', 'sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source', 'cached native Valid cannot bypass a fresh local clock check'),
    ('HC336', 'sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source', 'a certificate flag cannot substitute another result'),
    ('HC337', 'sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source', 'native first signing must recheck the actual wall clock after execution'),
])
def test_native_first_prepare_mutations_bind_original_control(mutation, test, cause):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation]
    expected_tests = (test,)
    expected_causes = (gate.ExpectedFailure(cause,
        "crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs",
        worker_thread="ct5-paid-original",
        join_source="crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs",
        join_message="called `Result::unwrap()` on an `Err` value: Any { .. }"),)
    if mutation == "HC334":
        expected_tests += ("sumeragi::executor::clock_tests::sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry",)
        expected_causes += (gate.ExpectedFailure(
            "CT5 must resample after completing the original execution before returning Valid",
            "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
            worker_thread="sumeragi-publication-test",
            join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
            join_message="publication worker fixture: Any { .. }"),)
    if mutation == "HC337":
        expected_tests += ("sumeragi::executor::clock_tests::sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate",)
        expected_causes += (gate.ExpectedFailure(
            "CT5 must resample the original clock at Prepare signing after Valid was delivered",
            "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
            worker_thread="sumeragi-publication-test",
            join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
            join_message="publication worker fixture: Any { .. }"),)
    assert rule.tests == expected_tests
    assert rule.causes == expected_causes
    assert gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation)
    assert not gate.has_switch(mutation, model=True)


@pytest.mark.parametrize("mutation,test,cause", [
    ('MS71', 'machine::tests::signing::det_ct5_cached_execution_waits_for_stage_and_checks_actual_first_signing_time', 'cached Valid cannot bypass first-Prepare freshness after stage delay'),
    ('MS72', 'machine::tests::signing::det_ct5_unsigned_prepare_reservation_restart_never_synthesizes_first_signature', 'a durable unsigned reservation cannot synthesize a first Prepare without fresh source-bound execution or a genuine matching PQC'),
    ('MS73', 'machine::tests::signing::det_ct5_successful_prepare_signature_is_exact_durable_and_authenticated_on_restart', 'a checksummed fabricated successful signature is not restart authority'),
])
def test_first_prepare_consensus_mutations_bind_original_control(mutation, test, cause):
    rule = gate.index_mutations(gate.MUTATIONS)[mutation]
    expected_tests = (test,)
    expected_causes = (gate.ExpectedFailure(cause,
        "crates/iroha_sumeragi/src/machine/tests/signing.rs"),)
    if mutation == "MS71":
        expected_tests += ("sim::world::clock_guard::tests::det_ct5_world_retained_execution_rechecks_clock_at_first_prepare",)
        expected_causes += (gate.ExpectedFailure(
            "a retained World result must not sign after its actual wall clock advances",
            "crates/iroha_sumeragi/src/sim/world/clock_guard/tests.rs"),)
    assert rule.tests == expected_tests
    assert rule.causes == expected_causes
    assert gate.has_switch(mutation)
    assert not gate.has_switch(mutation, core=True)
    assert not gate.has_switch(mutation, model=True)


def test_native_amx_approval_scope_mutation_requires_real_owner_grant():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC341"]
    assert rule.tests == (
        "sumeragi::amx::native::tests::paid_borrowed_custody::authorization::native_amx_exact_owner_grant_revocation_and_separate_relay_preserve_settlement",
        "sumeragi::amx::native::tests::paid_borrowed_custody::approval_proof::native_amx_approval_proof_requires_owner_grant_and_rechecks_exact_private_cut",
    )
    assert rule.causes == (gate.ExpectedFailure(
        "actual debit owner grants the exact native AMX intent",
        "crates/iroha_core/src/sumeragi/amx/native/tests.rs",
    ),) * 2
    assert gate.has_switch("HC341", core=True)
    assert not gate.has_switch("HC341")
    assert not gate.has_switch("HC341", model=True)
    assert not gate.has_switch("HC341", daemon=True)

def test_state_effect_contention_mutation_has_actual_publisher_and_exact_refusal():
    prefix = "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::effect_retry_tests::"
    names = (
        "actual_state_effect_reader_refusal_retains_original_and_retries_after_release",
        "actual_state_effect_writer_refusal_retains_original_and_retries_after_release",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC272"]
    lifecycle_name = "signed_lifecycle_index_refusal_precedes_geometry_and_replays_final_cursor_journal"
    lifecycle_prefix = "state::tests::publication_effect_lifecycle_tests::"
    assert rule.tests == tuple(prefix + name for name in names) + (lifecycle_prefix + lifecycle_name,)
    assert not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(
        "the original index blocker must defer before visibility",
        "crates/iroha_core/src/state/publication_effect_retry_tests.rs",
    ), gate.ExpectedFailure(
        "the original index blocker must defer before visibility",
        "crates/iroha_core/src/state/publication_effect_retry_tests.rs",
    ), gate.ExpectedFailure(
        "the signed lifecycle index blocker must defer before geometry",
        "crates/iroha_core/src/state/publication_effect_lifecycle_tests.rs",
    ))
    assert gate.has_switch("HC272", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC272", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC272"', path.read_text())}
    assert owners == {"state/publication.rs"}
    publication = (root / "state/publication.rs").read_text()
    effect = (root / "state/effect_publication.rs").read_text()
    controls = (root / "state/publication_effect_retry_tests.rs").read_text()
    compact = re.sub(r"\s+", "", publication)
    assert 'all(test,sumeragi_core_mutation="HC272")' in compact
    assert "TransactionsBlockError::PublicationBusy(wait)" in publication
    assert "prepare_blocking" not in publication and "prepare_blocking" not in effect
    assert "effect indexes must be released before retry" in effect
    for name in names:
        assert "fn " + name + "(" in controls
    for obligation in ("staged_block(", "original.try_publish()", "state.da_indexes_hydrated.read()",
                       "state.da_indexes_hydrated.write()", "original.publication_identity_for_test()",
                       "state.world.try_block(&budget)", "budget.same_pool", "drop(reader)",
                       "drop(exclusive)", "worker.join()", "probe.blocked.load", "generation + 2"):
        assert obligation in controls
    assert "AllocationBudget::new" not in controls and "set_limit_bytes" not in controls
    rows = re.findall(r"^\| HC272 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name in rows[0] for name in (*names, lifecycle_name))
    lifecycle = (root / "state/publication_effect_lifecycle_tests.rs").read_text()
    for obligation in ("manual_lane_lifecycle_payload()", "pending.prepare(Signers::Quorum)",
                       "pending.publish(Signers::Quorum)", "prepared_lifecycle_identity",
                       "lane_geometry_journal_state_for_test", "state.geometry_publication.lock().is_none()",
                       "budget.same_pool", "drop(blocker)", "worker.join()", "generation + 2",
                       "path.is_file()", "DaShardCursorJournal::load", ".replay_from(&chain)"):
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", lifecycle)
    assert "AllocationBudget::new" not in lifecycle and "set_limit_bytes" not in lifecycle
    assert "prepare_committed_autoscale_lane_geometry" in publication
    assert compact.index("effect_locks.try_prepare()") < compact.index("geometry.apply(geometry_lease.lease())")
    geometry = (root / "state/geometry_publication.rs").read_text()
    owner = geometry[geometry.index("impl PreparedCommittedLaneGeometry") :]
    assert "resume_lane_geometry_publication(&request,&update.replaced_lane_ids,None,Some(lease),)" in re.sub(r"\s+", "", owner)
    assert "persist_lane_lifecycle_cursor_journal" not in owner
    effects = (root / "state/carrier_lifecycle_effects.rs").read_text()
    assert ".sync_mapping(&self.lane_config)" in effects
    assert "mapping_changed || !self.lanes_to_reset.is_empty()" in effects
    assert "pub(super) fn capture_snapshot" in effects


def test_lifecycle_manifest_refusal_mutation_preserves_each_original_read_and_cause():
    name = "signed_lifecycle_manifest_writer_refusal_retains_preflight_and_original_retry"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC273"]
    assert rule.tests == ("state::tests::publication_effect_manifest_tests::" + name,)
    assert rule.causes == (gate.ExpectedFailure(
        "the signed manifest preflight must retain its original local refusal",
        "crates/iroha_core/src/state/publication_effect_manifest_tests.rs",
    ),)
    assert not rule.scenarios
    assert gate.has_switch("HC273", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC273", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC273"', path.read_text())}
    assert owners == {"state/publication.rs"}
    state = (root / "state.rs").read_text()
    start = state.index("fn validate_committed_autoscale_lane_lifecycle(")
    end = state.index("/// Update tiered state backend settings", start)
    preflight = re.sub(r"\s+", "", state[start:end])
    assert preflight.count("releases.manifests.try_read_or_wait()") == 3
    assert "releases.manifests.read()" not in preflight
    assert preflight.count('field:"lane_manifests"') == 3
    publication = (root / "state/publication.rs").read_text()
    assert 'sumeragi_core_mutation = "HC273"' in publication
    assert "TransactionsBlockError::PublicationBusy(wait)" in publication
    controls = (root / "state/publication_effect_manifest_tests.rs").read_text()
    compact = re.sub(r"\s+", "", controls)
    for obligation in ("manual_lane_lifecycle_payload()", "pending.prepare(Signers::Quorum)",
                       "pending.publish(Signers::Quorum)", "state.lane_manifests.write()",
                       "state.geometry_publication.lock().is_none()", "lane_geometry_journal_state_for_test",
                       "drop(blocker)", "worker.join()", "generation + 2", "DaShardCursorJournal::load"):
        assert re.sub(r"\s+", "", obligation) in compact
    assert "AllocationBudget::new" not in controls and "set_limit_bytes" not in controls
    rows = re.findall(r"^\| HC273 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_kura_publication_cleanup_mutation_keeps_actual_enclosing_owners():
    names = (
        "original_kura_partial_refusal_callbacks_follow_all_state_siblings",
        "original_kura_success_callbacks_follow_all_state_siblings",
        "original_kura_unwind_callbacks_follow_all_state_siblings",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC274"]
    assert rule.tests == tuple("state::tests::publication_effect_kura_tests::" + name for name in names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original Kura notifications must wait for complete State cleanup",
        "crates/iroha_core/src/state/publication_effect_kura_tests.rs",
    ) for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC274", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC274", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC274"', path.read_text())}
    assert owners == {"kura/publication_lease/retained.rs"}
    retained = (root / "kura/publication_lease/retained.rs").read_text()
    assert "releases: KuraPublicationReleases" in retained
    assert ".zip(&mut releases.fences)" in retained
    assert "guard.try_release_into(batch)" in retained
    assert "impl Drop for Acquisition" in retained and "impl Drop for KuraPhysicalScope" in retained
    assert "Vec<" not in retained and "AllocationBudget::new" not in retained
    canonical = (root / "kura/publication_lease.rs").read_text()
    # The same four original batches now travel with their geometry watch senders.
    assert "fences: [iroha_allocation::release::DeferredReleaseBatch; 4]" in canonical
    assert "claims: super::lane_geometry::RawGeometryReleases" in canonical
    assert "source: super::KuraInstanceIdentity" in canonical
    assert "releases.claims.append(gate.end_publication())" in retained
    assert canonical.count("fn prepare_publication_fences") == 1
    assert "self.prepare_publication_fences(&mut fences)?" in canonical
    assert ".prepare_publication_fences(&mut acquisition.fences)?" in retained
    publication = re.sub(r"\s+", "", (root / "state/publication.rs").read_text())
    acquire = publication.index("ifprepared_geometry.is_some()")
    assert acquire < publication.index("let_state_write_lock=write_fence.lock();", acquire)
    assert publication.index("geometry.apply(geometry_lease.lease())") > acquire
    assert publication.index("drop(geometry_lease)") < publication.index("state_ref.enforce_nexus_storage_budget(")
    assert publication.count(".geometry_cleanup.retire_notices()") == 2
    controls = (root / "state/publication_effect_kura_tests.rs").read_text()
    for name in names:
        assert "fn " + name + "(" in controls
    for obligation in ("manual_lane_lifecycle_test_chain", "state.state_commit_lock.lock()",
                       "state.state_write_lock.lock()", "state.lane_lifecycle_lock.lock()",
                       "effects.physical_scope()", "publication_fences_for_test",
                       "original.physical_scope()", "original.retire_notices()",
                       "std::panic::catch_unwind", "probe.blocked.load", "budget.reserved_bytes()"):
        assert obligation in controls
    assert "AllocationBudget::new" not in controls and "set_limit_bytes" not in controls
    rows = re.findall(r"^\| HC274 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name in rows[0] for name in names)


def test_native_append_physical_state_refusal_keeps_actual_driver_release_owner():
    name = "original_append_driver_retains_manifest_release_without_timer_or_foreign_wake"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC275"]
    assert rule.tests == ("state::tests::publication_effect_manifest_tests::" + name,)
    assert rule.causes == (gate.ExpectedFailure(
        "the original append scheduler must retain its physical State release",
        "crates/iroha_core/src/state/publication_effect_manifest_tests.rs",
    ),)
    assert not rule.scenarios
    assert gate.has_switch("HC275", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC275", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC275"', path.read_text())}
    assert owners == {"sumeragi/driver/mod.rs"}
    authority = (root / "sumeragi/runtime_availability.rs").read_text()
    compact = re.sub(r"\s+", "", authority)
    assert compact.count("try_view_once().map_err(state_view_error)?") == 2
    assert "letview=state.view();" not in compact and "letview=self.state.view();" not in compact
    assert "io::Error::new(kind,error).into()" in compact
    driver = (root / "sumeragi/driver/mod.rs").read_text()
    assert "cause.downcast_ref::<crate::state::StateViewError>()" in driver
    assert "traits::PublicationDeferral::StateViewBusy(wait.clone())" in driver
    scheduler = (root / "sumeragi/driver/exec.rs").read_text()
    assert "append_refusal: Option<PublicationDeferral>" in scheduler
    assert ".and_then(PublicationDeferral::release_wait)" in scheduler
    controls = (root / "state/publication_effect_manifest_tests.rs").read_text()
    fixture = (root / "sumeragi/test_chain.rs").read_text()
    for obligation in ("pending.append_prepared()", "pending.run_original_append_for_test(append)",
                       "state.lane_manifests.write()", "state.lane_manifests.observe_release()",
                       "scheduler.next(u64::MAX - 1)", "Arc::ptr_eq(&original, &append)",
                       "drop(state.crypto.read())", "drop(blocker)", "worker.join()"):
        assert re.sub(r"\s+", "", obligation) in re.sub(r"\s+", "", controls)
    assert "if !self.appended" in fixture and "self.appended = true" in fixture
    assert "super::driver::run_original_append_for_test" in fixture
    assert "AllocationBudget::new" not in controls and "set_limit_bytes" not in controls
    rows = re.findall(r"^\| HC275 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_native_lane_merge_preserves_original_entrypoint_after_certificate_admission():
    name = "certified_merge_retains_sealed_carrier_and_enforces_original_salt_before_execution"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC344"]
    assert rule.tests == ("sumeragi::lanes::merge::tests::sealed_entrypoints::" + name,)
    assert rule.causes == (gate.ExpectedFailure(
        "certified lane merge retains the complete original entrypoint",
        "crates/iroha_core/src/sumeragi/lanes/merge_tests/sealed_entrypoints.rs",
    ),)
    assert not rule.scenarios
    assert gate.has_switch("HC344", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC344", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC344"', path.read_text())}
    assert owners == {"sumeragi/lanes/merge.rs"}
    owner = (root / "sumeragi/lanes/merge.rs").read_text()
    controls = (root / "sumeragi/lanes/merge_tests/sealed_entrypoints.rs").read_text()
    assert "let original = tx;" in owner
    assert "expansion.entrypoints.push(original);" in owner
    assert "MergeIdentityIndex::new" in owner
    assert "state.ivm_execution_budget()" in owner
    assert "with_deferred_refund_notifications" in owner
    assert "view.has_entrypoint(hash)" in owner
    assert "cached.replay_alias.is_some_and(|alias|view.has_entrypoint(alias))" in re.sub(r"\s+", "", owner)
    assert "Some(reveal.signed_transaction().hash_as_entrypoint())" in owner
    assert "accept_borrowed_entrypoint_at_time" in owner
    for obligation in ("assert_stored_source(&fixture, 2", "assert_proposed_source(&fixture, &wrong)",
                       "sealed transaction reveal does not match commitment", "assert_merged_source(&fixture, 6",
                       "signed.hash_as_entrypoint()", "fixture.record().merged.height, 4"):
        assert obligation in controls
    rows = re.findall(r"^\| HC344 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


def test_ingress_retirement_mutation_retains_real_pool_refund_and_unlocked_reentry():
    name = "ingress_unregister_refunds_outside_original_route_lock"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC347"]
    assert rule.tests == ("sumeragi::net::tests::" + name,)
    assert rule.causes == (gate.ExpectedFailure(
        "original ingress refund must run after the route lock releases",
        "crates/iroha_core/src/sumeragi/net.rs",
    ),)
    assert not rule.scenarios
    assert gate.has_switch("HC347", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC347", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC347"', path.read_text())}
    assert owners == {"sumeragi/net.rs"}
    source = (root / "sumeragi/net.rs").read_text()
    for obligation in (
        'cfg!(all(test, sumeragi_core_mutation = "HC347"))',
        'let removed = { self.routes.write().remove(instance) };',
        'let replaced = { self.routes.write().insert(instance, sink) };',
        'let sink = { self.routes.read().get(&frame.instance).cloned() };',
        'ChargedBuffer::new(64, &budget)', 'ReleaseRegistration::from_reservation(',
        'ingress.routes.try_write()', 'AllocationRefusal::Capacity { release, .. }',
        'ingress.unregister(&self.instance)', 'self.probe.reentered.load(Ordering::SeqCst)',
        'assert_eq!(self.budget.reserved_bytes(), 0)',
    ):
        assert obligation in source
    for control in (
        "ingress_register_replacement_refunds_outside_original_route_lock",
        name,
        "ingress_deliver_reentry_retires_original_sink_after_route_lock_release",
    ):
        assert "fn " + control + "()" in source
        assert "sumeragi::net::tests::" + control in (ROOT / "scripts/taira_release_check.py").read_text()
    rows = re.findall(r"^\| HC347 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and name in rows[0]


@pytest.mark.parametrize("mid", ["HC348", "HC349"])
def test_lane_retirement_refunds_cover_original_registry_and_enclosing_runner(mid):
    names = (
        "original_runtime_opening_explicit_retirement_refunds_after_registry_unlock",
        "original_runtime_opening_applied_retirement_refunds_after_registry_unlock",
        "original_runtime_opening_recovery_refunds_after_registry_unlock",
        "original_runtime_retirement_refunds_after_registry_and_runner_unlock",
    )
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    selected = names if mid == "HC348" else names[-1:]
    assert rule.tests == tuple("sumeragi::lanes::registry::tests::" + name for name in selected)
    causes = ("original lane store refund must run after the registry lock releases",) * 3 + (
        "original lane retirement refund must wait for both registry and runner unlock",)
    assert rule.causes == tuple(gate.ExpectedFailure(cause, "crates/iroha_core/src/sumeragi/lanes/registry/tests.rs")
                               for cause in (causes if mid == "HC348" else causes[-1:]))
    assert not rule.scenarios
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch(mid, **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())}
    assert owners == ({"sumeragi/lanes/registry.rs"} if mid == "HC348" else {"sumeragi/lanes/runner.rs"})
    registry = (root / "sumeragi/lanes/registry.rs").read_text()
    runner = (root / "sumeragi/lanes/runner.rs").read_text()
    controls = (root / "sumeragi/lanes/registry/tests.rs").read_text()
    original_refund_owners = ("store_with_demand", "release", "release_retired",
                              "clean_cancelled_proposal_reads")
    for function in original_refund_owners:
        assert named_rust_function(registry, function).count("self.with_original_refunds(|| {") == 1
    assert named_rust_function(registry, "resume_retired_publications").count("self.with_original_refunds(|| {") == 1
    assert registry.count("self.with_original_refunds(|| {") == 5
    assert "self.budget" in registry and "with_deferred_refund_notifications" in registry
    assert "let retired = { self.running.lock().remove(&key) };" in runner
    assert "let replaced = { self.running.lock().insert(key, lane) };" in runner
    for obligation in (
        'Fixture::new(true)', 'StoreSlot::Opening(_, owners)) if !owners.historical', 'ReleaseRegistration::from_reservation(',
        'budget.same_pool(&fixture.stores.budget)', 'CertifiedTestChain::start(',
        'runner.reconcile()', 'runner.running_lock_available()', 'stores.stores.try_lock()',
        'probe.reentered.load(Ordering::SeqCst)', 'fs::read(&path).unwrap(), original',
    ):
        assert obligation in controls
    catalog = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name + "()" in controls
        assert "sumeragi::lanes::registry::tests::" + name in catalog
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name in rows[0] for name in selected)


def test_direct_lane_store_refunds_cover_state_batch_and_original_opening():
    names = ('original_lane_body_refund_waits_for_state_unlock', 'original_lane_batch_refund_waits_for_both_original_guards', 'original_lane_entry_refund_waits_for_state_unlock', 'original_lane_authenticated_height_refund_waits_for_state_unlock', 'original_lane_append_refund_waits_for_state_unlock', 'original_lane_repeated_append_refund_waits_for_state_unlock', 'original_lane_rejected_append_refund_waits_for_state_unlock', 'original_lane_opening_refund_follows_complete_recovery_cleanup')
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC350"]
    assert rule.tests == tuple("sumeragi::lanes::store::refund_tests::" + name for name in names)
    causes = ("original lane operation refund must wait for both state and batch unlock",) * 7 + (
        "original lane opening refund must wait for completed recovery cleanup",)
    assert rule.causes == tuple(gate.ExpectedFailure(cause, "crates/iroha_core/src/sumeragi/lanes/store/refund_tests.rs") for cause in causes)
    assert not rule.scenarios
    assert gate.has_switch("HC350", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC350", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC350"', path.read_text())}
    assert owners == {"sumeragi/lanes/store.rs"}
    store = (root / "sumeragi/lanes/store.rs").read_text()
    recovery = (root / "sumeragi/lanes/store/recovery.rs").read_text()
    controls = (root / "sumeragi/lanes/store/refund_tests.rs").read_text()
    inherent, trait = store.split("impl BlockStore for FileLaneBlockStore {", 1)
    for function in ("committed_body", "batch_with_interest", "authenticated_height", "release_cancelled_reads"):
        assert named_rust_function(inherent, function).count("Self::with_original_refunds(&self.budget, || {") == 1
    for function in ("entry", "append"):
        assert named_rust_function(trait, function).count("Self::with_original_refunds(&self.budget, || {") == 1
    assert named_rust_function(inherent, "resume_retired_publication").count("Self::with_original_refunds(&self.budget, || {") == 1
    notification = named_rust_function(inherent, "notify_retired_publication")
    assert notification.count("Self::with_original_refunds(&self.budget, || {") == 1
    assert ('#[cfg(all(test, sumeragi_core_mutation = "HC423"))]\n'
            '        Self::with_original_refunds(&self.budget, || {') in notification
    assert "self.batch_with_interest(height, ReadInterest::Historical)" in named_rust_function(inherent, "committed_batch")
    assert "self.batch_with_interest(height, requested)" in named_rust_function(inherent, "proposal_batch")
    # Seven production operations plus the independently guarded HC423 negative control.
    assert store.count("Self::with_original_refunds(&self.budget, || {") == 8
    assert "FileLaneBlockStore::with_original_refunds(&budget, || {" in recovery
    assert "let budget = self.store.budget.clone();" in recovery
    for obligation in (
        'fixture(1025)', 'ReleaseRegistration::from_reservation(',
        'store.state.try_lock()', 'store.batch_read.try_lock()',
        'store.committed_body(1)', 'store.committed_batch(1)', 'store.entry(1)',
        'store.authenticated_height()', 'store.append(&body, &qc)',
        'store.append(&body, &changed)',
        'probe.reentered.load(Ordering::SeqCst)', 'budget.reserved_bytes(), 0',
    ):
        assert obligation in controls
    catalog = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name + "()" in controls
        assert "sumeragi::lanes::store::refund_tests::" + name in catalog
    assert re.search(r"opening\s*\.complete\(\)", controls)
    rows = re.findall(r"^\| HC350 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name in rows[0] for name in names)


def test_native_history_refunds_preserve_original_scan_and_default_stack_reentry():
    names = ('original_history_scan_progress_refunds_after_scan_unlock', 'original_history_scan_finish_refunds_after_scan_unlock', 'original_history_scan_cancellation_refunds_after_scan_unlock', 'original_history_scan_stale_cut_refunds_after_scan_unlock', 'original_history_scan_terminal_cleanup_refunds_after_scan_unlock', 'original_history_scan_cancelled_error_refunds_after_scan_unlock', 'original_history_scan_invalid_prefix_refunds_after_scan_unlock', 'original_history_scan_refused_retry_refunds_after_scan_unlock')
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC351"]
    assert rule.tests == tuple("sumeragi::runtime_availability::refund_tests::" + name for name in names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original history refund must wait for scan unlock",
        "crates/iroha_core/src/sumeragi/runtime_availability/refund_tests.rs",
    ) for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC351", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC351", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC351"', path.read_text())}
    assert owners == {"sumeragi/runtime_availability.rs"}
    owner = (root / "sumeragi/runtime_availability.rs").read_text()
    controls = (root / "sumeragi/runtime_availability/refund_tests.rs").read_text()
    for obligation in (
        "let budget = self.state.ivm_execution_budget();",
        "budget.with_deferred_refund_notifications(|_| read())",
        "let mut releases = StateViewReleases::new(&self.state);",
        "self.historical_record_with_scan(lane, incarnation, &mut releases)",
        "#[inline(never)]\n    fn historical_record_with_scan(",
    ):
        assert obligation in owner
    for obligation in (
        "fixed_lane_chain()", "HistoryRefundWatch::arm(", "provider.scan.try_lock()",
        "provider.historical_record(self.lane, self.incarnation)",
        "owner.belongs_to(&budget)", "budget.reserved_bytes(), baseline",
        'error.to_string().contains("publication changed")',
        'error.to_string().contains("identity changed")',
        "scan.complete().unwrap()", "chain.commit(Vec::new())",
        "std::fs::rename(&path, &retained)", 'b"history-refund-substituted-creation-write"',
    ):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    catalog = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name + "()" in controls
        assert "sumeragi::runtime_availability::refund_tests::" + name in catalog
    rows = re.findall(r"^\| HC351 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name in rows[0] for name in names)


def test_geometry_claim_watch_release_retains_original_cleanup_and_default_stack():
    names = ['kura::lane_geometry::tests::original_watch_release_tests::original_geometry_captured_rollback_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_applied_rollback_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_catalog_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_pure_drop_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_partial_error_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_unwind_watch_follows_physical_cleanup', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_direct_state_completion', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_all_state_sibling_owners', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_all_state_sibling_unwind', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_capture_error_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_capture_unwind_watch_follows_physical_cleanup']
    paths = ['crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC352"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure('original geometry watch must wait for all physical owners', path) for path in paths)
    assert gate.has_switch("HC352", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC352", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC352"', path.read_text())}
    assert owners == {"kura/lane_geometry/raw_attempt.rs"}
    claim = (root / "kura/lane_geometry/raw_attempt.rs").read_text()
    lease = (root / "kura/publication_lease.rs").read_text()
    retained = (root / "kura/publication_lease/retained.rs").read_text()
    for obligation in (
        "signal: Arc<ClaimSignal>", "next: Mutex<Option<Arc<ClaimSignal>>>",
        "state.releases.push(Arc::clone(&self.signal))", "drop(immediate)",
        "signal.released.send_replace(true)", "self.signal.ready.swap(true, Ordering::AcqRel)",
    ):
        assert obligation in claim
    assert "gate.end_publication()" in lease and "gate.end_publication()" in retained
    assert "try_merge_into(batch)" in lease
    assert "try_scoped_publication_lease" in retained
    assert "publication: bool" in claim and "scope_count" not in claim
    for relative in ("kura/lane_geometry_tests/08_raw_attempt.rs", "state/geometry_completion_tests.rs"):
        controls = (root / relative).read_text()
        assert "wait.wait_for_release()" in controls
        assert "Context::from_waker" in controls
        assert "publication_fences_for_test()" in controls
        assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    catalog = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names + ['kura::lane_geometry::tests::original_watch_release_tests::original_geometry_detached_notices_do_not_wait_for_another_cleanup_owner', 'kura::lane_geometry::raw_attempt::claim_queue_tests::original_claim_cleanup_reentry_does_not_hold_gate_or_duplicate_notices', 'kura::lane_geometry::raw_attempt::claim_queue_tests::original_claim_old_cleanup_and_concurrent_new_owner_keep_separate_notices']:
        assert name in catalog
    rows = re.findall(r"^\| HC352 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)

def test_private_root_role_removal_mutation_requires_paid_restart_regression():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC343"]
    assert rule.tests == ("sumeragi::amx::native::tests::paid_borrowed_custody::read_roles::native_private_read_role_removal_preserves_debit_and_survives_certified_restart",)
    assert rule.causes == (gate.ExpectedFailure(
        "bank management must delete its dedicated read role through ordinary native authorization",
        "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/read_roles.rs",
    ),)
    assert not rule.scenarios
    assert gate.has_switch("HC343", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC343", **family)
    rows = re.findall(r"^\| HC343 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and "native_private_read_role_removal_preserves_debit_and_survives_certified_restart" in rows[0]


def test_native_history_physical_reader_notifications_retain_original_sources_outside_locks():
    names = ['sumeragi::lanes::registry::tests::original_native_history_reader_success_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_absence_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_error_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_reentry_preserves_concurrent_ready_owner', 'sumeragi::lanes::registry::tests::original_native_history_partial_reader_refusal_retains_exact_source_after_unlock', 'sumeragi::lanes::registry::tests::original_authority_recheck_retains_reentrant_opening_and_historical_interest']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC353"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original State reader notices must follow scan and registry unlock",
        "crates/iroha_core/src/sumeragi/lanes/registry/tests.rs") for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC353", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC353", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC353"', path.read_text())}
    assert owners == {"sumeragi/runtime_availability/history.rs", "sumeragi/lanes/registry.rs"}
    provider = (root / "sumeragi/runtime_availability.rs").read_text()
    assert "let mut releases = StateViewReleases::new(&self.state);" in provider
    assert "self.historical_record_with_scan(lane, incarnation, &mut releases)" in provider
    assert "budget.with_deferred_refund_notifications(|_| read())" in provider
    assert "HistoryScan::open_retaining(releases, lane, incarnation)?" in provider
    history = (root / "sumeragi/runtime_availability/history.rs").read_text()
    capture = history[history.index("pub(super) fn open_retaining("):history.index("pub(in crate::sumeragi) fn open_captured(")]
    assert "let state = releases.state();" in capture
    assert "releases.try_view_once().map_err(super::state_view_error)?" in capture
    assert "state.view()" not in capture
    registry = (root / "sumeragi/lanes/registry.rs").read_text()
    lookup = registry[registry.index("fn store_with_runtime_owner("):registry.index("fn open_store_with_authority(")]
    unlock = lookup.index("drop(stores)")
    authority = lookup.index(".authority(lane, incarnation, instance)?")
    reacquire = lookup.index("let mut stores = self.stores.lock();", authority)
    ready = lookup.index("Some(StoreSlot::Ready(store))", reacquire)
    opening = lookup.index("Self::resume_store_opening(&mut stores, key, &demand)", ready)
    begin = lookup.index("Self::open_store_with_authority(", opening)
    assert unlock < authority < reacquire < ready < opening < begin
    controls = (root / "sumeragi/lanes/registry/tests.rs").read_text()
    for obligation in (
        "npos_fixed_lane_chain_at(4)", "state.lane_manifests.observe_release()",
        "state.world.accounts.observe_reader_release()", "scan_unlocked_for_reader_test()",
        "assert_original_state_readers_available_for_test()", "stores.stores.try_lock()",
        "drop(state.da_pin_intents.read())", "Arc::ptr_eq(inner, &outer)",
        "StateViewError::Busy(retained)", "assert_eq!(*retained, original_wait)",
        "Some(StoreSlot::Opening(_, owners)) if owners.historical", "budget.reserved_bytes(), baseline + bytes.len()",
    ):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC353 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_geometry_recovery_physical_notifications_keep_original_fences_through_every_exit():
    names = ['kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_preflight_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_preflight_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_replay_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_replay_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_startup_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_startup_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_recovery_partial_refusals_keep_exact_errors_and_release_sources', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_recovery_unwind_notifies_after_every_acquired_fence']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC354"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original geometry recovery notice must wait for every physical fence",
        "crates/iroha_core/src/kura/lane_geometry_tests/09_recovery_releases.rs") for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC354", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}):
        assert not gate.has_switch("HC354", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC354"', path.read_text())}
    assert owners == {"kura/lane_geometry.rs", "kura/lane_geometry/instance_recovery.rs"}
    geometry = (root / "kura/lane_geometry.rs").read_text()
    preflight = geometry[geometry.index("pub(crate) fn preflight_lane_geometry_recovery_floor_with_lineage_root("):geometry.index("fn recover_lane_geometry_journal_with_lineage_root_inner(")]
    recovery = geometry[geometry.index("fn recover_lane_geometry_journal_with_lineage_root_inner("):geometry.index("fn reconcile_lane_geometry_history(")]
    startup = (root / "kura/lane_geometry/instance_recovery.rs").read_text()
    startup = startup[startup.index("fn recover_journal_owned_lane_instances_on_startup("):startup.index("fn authenticate_existing_lane_instance_on_startup(")]
    for body, locks in ((preflight, ("prune", "canonical", "geometry")),
                        (recovery, ("prune", "canonical", "geometry", "sidecar")),
                        (startup, ("prune", "canonical", "geometry", "sidecar"))):
        first_guard = body.index("let _prune_guard =")
        for lock, field in zip(locks, ("prune_lock", "canonical_chain_lock", "lane_geometry_lock", "sidecar_lock")):
            assert body.index("self." + field + ".defer_notifications()") < first_guard
            assert lock + "_releases.lock()" in body
        assert "sumeragi_core_mutation = \"HC354\"" in body
    assert "self.ensure_prune_recovery_not_required()?" in preflight
    assert "self.resolve_canonical_storage_before_mutation()?" in recovery
    assert "self.raw_geometry_claim.ensure_unclaimed()?" in recovery
    assert "self.durable_mutation_authorized()?" in startup
    controls = (root / "kura/lane_geometry_tests/09_recovery_releases.rs").read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "native_observation_tree(&root)",
                       "Error::PruneRecoveryRequired", "Error::CanonicalStoragePoisoned", "catch_unwind",
                       "registration.belongs_to(&budget)", "reserved - charge"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC354 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_native_frame_physical_notifications_outlive_all_original_storage_fences():
    names = ['kura::native_frame_release_tests::original_native_frame_metadata_success_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_metadata_absence_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_metadata_refusal_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_body_success_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_body_refusal_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_partial_refusals_retain_exact_storage_errors', 'kura::native_frame_release_tests::original_native_frame_unwind_notifies_after_each_acquired_prefix']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC355"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        'original native frame notice must wait for every storage fence', 'crates/iroha_core/src/kura/native_frame_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC355", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC355", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC355"', path.read_text())}
    assert owners == {"kura/native_execution_reads.rs"}
    native = (ROOT / 'crates/iroha_core/src/kura/native_execution_reads.rs').read_text()
    start = native.index("impl NativeFrameBinding {")
    body = native[native.index("fn read_original(", start):native.index("impl Kura {", start)]
    metadata = native[native.index("pub(crate) fn native_frame_read("):native.index("pub(crate) fn native_frame_read_owned(")]
    assert "budget.with_deferred_refund_notifications" in body
    for implementation, owner in ((body, "kura"), (metadata, "self")):
        first_guard = implementation.index("let _prune =")
        for field in ("prune_lock", "canonical_chain_lock"):
            assert implementation.index(owner + "." + field + ".defer_notifications()") < first_guard
        assert "prune_releases.lock()" in implementation
        assert "canonical_releases.lock()" in implementation
        assert "sumeragi_core_mutation = \"HC355\"" in implementation
        assert "ensure_prune_recovery_not_required()?" in implementation
        assert "ensure_canonical_storage_not_poisoned()?" in implementation
    controls = (ROOT / 'crates/iroha_core/src/kura/native_frame_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "Error::PruneRecoveryRequired", "Error::CanonicalStoragePoisoned", "catch_unwind",
                       "registration.belongs_to(&budget)", "bytes.belongs_to(&budget)", "reserved - charge",
                       "unrelated physical release", "EVICTED_BLOCK_START"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC355 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


@pytest.mark.parametrize(
    ("mutation_id", "owner", "test_name"),
    [
        ("HC377", "sumeragi/proposal_admission.rs",
         "native_original_proposal_rechecks_clock_after_worker_wait_and_restart"),
        ("HC378", "sumeragi/driver/exec.rs",
         "proposal_recovery_replacement_rejects_stale_worker_and_retains_only_latest_body"),
        ("HC379", "sumeragi/driver/exec.rs",
         "proposal_recovery_terminal_original_propagates_even_after_request_replacement"),
        ("HC380", "sumeragi/executor/proposal_publication.rs",
         "completed_original_payload_cannot_adopt_clear_and_readmission_during_original_build"),
        ("HC381", "sumeragi/driver/exec.rs",
         "proposal_recovery_discard_retires_original_waiter_before_decode_refund"),
        ("HC382", "sumeragi/executor/prepare_admission.rs",
         "ct1_native_first_prepare_rechecks_original_clock_after_execution"),
        ("HC383", "sumeragi/lanes/executor.rs",
         "native_lane_first_prepare_rechecks_pinned_clock_after_execution"),
        ("HC384", "sumeragi/payload.rs",
         "fresh_proposal_progress_recheck_uses_captured_time_with_original_signed_input"),
    ],
)
def test_sccp_clock_mutation_ids_are_distinct_from_storage_controls(
    mutation_id, owner, test_name
):
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    rule = rules[mutation_id]
    assert any(name.rsplit("::", 1)[-1] == test_name for name in rule.tests)
    assert len(rule.causes) == len(rule.tests)
    assert not rule.scenarios
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mutation_id + '"', path.read_text())}
    assert owners == {owner}
    rows = re.findall(r"^\| " + mutation_id + r" \|.*$",
                      (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and test_name in rows[0]
    for storage_number in range(353, 364):
        storage_id = f"HC{storage_number}"
        assert set(rule.tests).isdisjoint(rules[storage_id].tests)


def test_recovery_capacity_notifications_outlive_fences_and_final_accounting():
    names = ['kura::capacity_release_tests::original_capacity_recovery_success_notifies_after_final_accounting', 'kura::capacity_release_tests::original_capacity_restore_success_notifies_after_final_accounting', 'kura::capacity_release_tests::original_capacity_recovery_capacity_refusal_notifies_after_invalidation', 'kura::capacity_release_tests::original_capacity_recovery_prune_refusal_notifies_after_invalidation', 'kura::capacity_release_tests::original_capacity_recovery_canonical_refusal_notifies_after_invalidation', 'kura::capacity_release_tests::original_capacity_recovery_accounting_refusal_notifies_after_invalidation', 'kura::capacity_release_tests::original_capacity_recovery_unwind_notifies_after_each_acquired_prefix']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC356"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        'original capacity recovery notice must follow all fences and final accounting', 'crates/iroha_core/src/kura/capacity_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC356", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC356", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC356"', path.read_text())}
    assert owners == {"kura/publication_capacity.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura/publication_capacity.rs').read_text()
    implementation = source[source.index("fn validate_and_publish_configured_kura_capacity_after_startup_recovery("):]
    closure = implementation.index("let publication = (|| -> Result<()>")
    for field, batch in (("prune_lock", "prune_releases"), ("canonical_chain_lock", "canonical_releases"),
                         ("lane_geometry_lock", "geometry_releases"), ("sidecar_lock", "sidecar_releases")):
        assert implementation.index("self." + field + ".defer_notifications()") < closure
        assert batch + ".lock()" in implementation
    assert implementation.index("if publication.is_err()") > implementation.index("})();")
    assert "self.invalidate_durable_budget_snapshot();" in implementation
    controls = (ROOT / 'crates/iroha_core/src/kura/capacity_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "Error::PruneRecoveryRequired", "Error::StorageBudgetExceeded", "catch_unwind",
                       "registration.belongs_to(&budget)", "reserved - charge", "unrelated physical release",
                       "finish_restored_lane_segments_with_geometry", "disk_usage_initialized",
                       "disk_usage_total_initialized", "durable_budget_snapshot_valid", "1..=4",
                       "block index journal has a partial trailing entry",
                       "Kura retained geometry root must be a non-symlink directory"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC356 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_durable_publication_notifications_outlive_outer_storage_writers():
    names = ['kura::tests::original_durable_release_tests::original_durable_append_notifies_after_every_storage_fence', 'kura::tests::original_durable_release_tests::original_durable_retry_notifies_after_every_storage_fence', 'kura::tests::original_durable_release_tests::original_durable_refusal_notifies_after_every_storage_fence', 'kura::tests::original_durable_release_tests::original_durable_debug_append_notifies_after_outer_writer_retires']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC357"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        'original durable publication notice must wait for every storage fence', 'crates/iroha_core/src/kura/tests/15_remaining_physical_writer_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC357", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC357", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC357"', path.read_text())}
    assert owners == {"kura/durable_block_and_atomic_sidecar_io.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura/durable_block_and_atomic_sidecar_io.rs').read_text()
    durable = source[source.index("fn store_block_durable("):source.index("fn validate_next_or_existing_block(")]
    first_guard = durable.index("let _prune_guard =")
    for field in ("prune_lock", "canonical_chain_lock", "lane_geometry_lock", "sidecar_lock"):
        assert durable.index("self." + field + ".defer_notifications()") < first_guard
    assert "self.append_debug_block_dump(" in durable
    debug = source[source.index("fn append_debug_block_dump("):source.index("fn append_bound_debug_block_dump(")]
    assert debug.count("DeferredPublicationFence") == 2
    assert "defer_notifications()" not in debug
    assert "validate_publication_disk_peak_locked(" in debug
    controls = (ROOT / 'crates/iroha_core/src/kura/tests/15_remaining_physical_writer_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "block_store_write_lock.try_lock()", "block_data.try_lock()", "block_plain_text_path.try_lock()",
                       "Error::BlockHeightGap", "canonical_block_wire_bytes_for_testing",
                       "registration.belongs_to(&budget)", "reserved - charge", "foreign store release",
                       "metadata_physical_assert_actual", "NativeBlocks::new()", "debug_output_new_blocks"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC357 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_fastpq_artifact_notifications_outlive_all_original_storage_fences():
    names = ['kura::fastpq_artifact_store::original_release_tests::original_artifact_persist_success_notifies_after_storage_fences', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_exact_retry_notifies_after_storage_fences', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_quota_refusal_notifies_after_storage_fences', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_content_conflict_notifies_after_storage_fences', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_read_success_notifies_after_storage_fences', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_read_refusals_retain_exact_errors_and_bytes', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_partial_refusals_retain_exact_storage_errors', 'kura::fastpq_artifact_store::original_release_tests::original_artifact_unwind_notifies_after_each_acquired_prefix', 'kura::fastpq_artifact_store::original_release_tests::original_producer_read_success_and_absence_notify_after_storage_fences']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC358"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        'original FASTPQ artifact notice must wait for every storage fence', 'crates/iroha_core/src/kura/fastpq_artifact_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC358", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC358", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC358"', path.read_text())}
    assert owners == {"kura/fastpq_artifact_store.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura/fastpq_artifact_store.rs').read_text()
    persisted = named_rust_function(source, "persist_fastpq_object")
    recovered = named_rust_function(source, "read_fastpq_artifact")
    producer_read = named_rust_function(source, "read_fastpq_producer_record")
    for wrapper in ("persist_fastpq_artifact", "persist_fastpq_producer_record", "persist_fastpq_source_record"):
        assert "self.persist_fastpq_object(" in named_rust_function(source, wrapper)
    for implementation in (persisted, recovered, producer_read):
        first_guard = implementation.index("let _prune_guard =")
        for field, batch, guard in (("prune_lock", "prune_releases", "_prune_guard"),
                                    ("canonical_chain_lock", "canonical_releases", "_canonical_guard"),
                                    ("sidecar_lock", "sidecar_releases", "_sidecar_guard")):
            assert implementation.index("self." + field + ".defer_notifications()") < first_guard
            assert batch + ".lock()" in implementation
            assert re.search(
                re.escape('#[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]')
                + r"\s*" + re.escape(f"let {guard} = {batch}.lock();"), implementation
            )
            assert re.search(
                re.escape('#[cfg(all(test, sumeragi_core_mutation = "HC358"))]')
                + r"\s*" + re.escape(f"let {guard} = self.{field}.lock();"), implementation
            )
        assert "ensure_prune_recovery_not_required()?" in implementation
        assert "durable_mutation_authorized()?" in implementation
    assert persisted.index("self.lane_geometry_lock.defer_notifications()") < persisted.index("let _prune_guard =")
    assert "geometry_releases.lock()" in persisted
    assert "usage_mutation.finish_resources_before_disk_rescan()" in persisted
    controls = (ROOT / 'crates/iroha_core/src/kura/fastpq_artifact_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "Error::PruneRecoveryRequired", "Error::CanonicalStoragePoisoned", "catch_unwind",
                       "registration.belongs_to(&budget)", "reserved - charge", "unrelated physical release",
                       "receipt.is_from(&kura)", "inventory(&kura)", "source.kind() == ErrorKind::InvalidData",
                       "Error::FastpqArtifactQuota", "FASTPQ content address contains different bytes",
                       "FASTPQ artifact reference is absent", "FASTPQ artifact content or exact length differs from reference"):
        assert obligation in controls
    quota = named_rust_function(controls, "original_artifact_quota_refusal_notifies_after_storage_fences")
    compact_quota = re.sub(r"\s+", "", quota)
    assert "letkura=fixture(1);" in compact_quota
    assert 'kura.persist_fastpq_artifact(b"retained").unwrap()' in compact_quota
    assert 'observe_original_release(&kura,3,||kura.persist_fastpq_artifact(b"additional"))' in compact_quota
    assert (
        "assert!(matches!(result,Err(Error::FastpqArtifactQuota{"
        "stable_count:1,retained_bytes:8,incoming_bytes:10,maximum_records:1,maximum_bytes:256,})));"
    ) in compact_quota
    assert "assert_eq!(inventory(&kura),before);" in compact_quota
    assert (
        "returnErr(Error::FastpqArtifactQuota{stable_count:inventory.stable_count,"
        "retained_bytes:inventory.total_bytes,incoming_bytes:reference.byte_len,"
        "maximum_records:limits.max_artifacts.get(),maximum_bytes:limits.max_total_bytes.get(),});"
    ) in re.sub(r"\s+", "", persisted)
    producer_control = named_rust_function(
        controls, "original_producer_read_success_and_absence_notify_after_storage_fences"
    )
    for obligation in (
        "assert!(missing.is_none());", "assert!(inventory(&kura).is_empty());",
        "observe_original_release(&kura, 3, || kura.read_fastpq_producer_record(key))",
        "observe_original_release(&kura, 3, || kura.read_fastpq_producer_record(selected))",
        "(key, Some(bytes.to_vec()))", '(Hash::new(b"absent producer position"), None)',
        "assert_eq!(read, expected);", "assert_eq!(inventory(&kura), before);",
    ):
        assert obligation in producer_control
    for control in (
        "original_artifact_partial_refusals_retain_exact_storage_errors",
        "original_artifact_unwind_notifies_after_each_acquired_prefix",
    ):
        assert 'for operation in ["persist", "artifact-read", "producer-read"]' in named_rust_function(controls, control)
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC358 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_queued_sidecar_notifications_outlive_writer_and_retry_queues():
    names = ['kura::original_queued_sidecar_release_tests::original_direct_pipeline_success_notifies_after_outer_prune', 'kura::original_queued_sidecar_release_tests::original_direct_pipeline_io_refusal_retains_exact_bytes', 'kura::original_queued_sidecar_release_tests::original_queued_pipeline_writer_notifies_after_outer_prune', 'kura::original_queued_sidecar_release_tests::original_queued_fastpq_writer_notifies_after_attachment_publication', 'kura::original_queued_sidecar_release_tests::original_queued_fastpq_retry_and_exhaustion_finalize_before_notice', 'kura::original_queued_sidecar_release_tests::original_queued_fastpq_hash_refusal_retains_exact_bytes', 'kura::original_queued_sidecar_release_tests::original_standalone_fastpq_flush_notifies_after_retry_queue_finalizes', 'kura::original_queued_sidecar_release_tests::original_queued_sidecar_unwind_notifies_after_each_acquired_prefix']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC359"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure('original queued sidecar notice must follow outer fences and finalized queues', 'crates/iroha_core/src/kura/queued_sidecar_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC359", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC359", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC359"', path.read_text())}
    assert owners == {"kura.rs", "kura/indexed_sidecar_io.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura.rs').read_text()
    writer = source[source.index("fn receive_blocks_loop("):source.index("/// Get the hash of the block", source.index("fn receive_blocks_loop("))]
    first_guard = writer.index("let prune_guard =")
    for field in ("prune_lock", "sidecar_lock"):
        assert writer.index("kura." + field + ".defer_notifications()") < first_guard
    assert "flush_pipeline_sidecars(&mut sidecar_releases)" in writer
    assert "flush_fastpq_proof_snapshots(&mut sidecar_releases)" in writer
    source = (ROOT / 'crates/iroha_core/src/kura/indexed_sidecar_io.rs').read_text()
    direct = source[source.index("pub fn write_pipeline_metadata("):source.index("fn write_pipeline_metadata_unlocked(")]
    for field in ("prune_lock", "sidecar_lock"):
        assert direct.index("self." + field + ".defer_notifications()") < direct.index("let _prune_guard =")
    assert "write_pipeline_metadata_unlocked(sidecar, &mut sidecar_releases)" in direct
    for start, end in (("fn flush_pipeline_sidecars(", "/// Enqueue a FASTPQ"),
                       ("fn flush_fastpq_proof_snapshots(", "/// Write per-block pipeline"),
                       ("fn write_pipeline_metadata_unlocked(", "fn write_fastpq_proof_snapshots("),
                       ("fn write_fastpq_proof_snapshots(", "/// Decode pipeline recovery")):
        body = source[source.index(start):source.index(end, source.index(start))]
        assert "sidecar_releases: &mut crate::publication_lock::DeferredPublicationFence<'_, ()>" in body
        assert ".defer_notifications()" not in body
    assert "self.write_fastpq_proof_snapshots(&snapshots, sidecar_releases)" in source
    assert "queue.extend(retry.drain(..requeued))" in source
    controls = (ROOT / 'crates/iroha_core/src/kura/queued_sidecar_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "pipeline_sidecar_queue", "fastpq_proof_queue", "catch_unwind",
                       "registration.belongs_to(&budget)", "reserved - charge", "unrelated physical release",
                       "receive_blocks_loop(&shutdown)", "shutdown.send()", "inventory(&kura)",
                       "std::io::ErrorKind::AlreadyExists", "item.retries", "snapshot.clone()"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC359 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_snapshot_boundary_notifications_outlive_all_startup_storage_fences():
    names = ['kura::tests::original_snapshot_release_tests::original_snapshot_boundary_empty_notifies_after_storage_fences', 'kura::tests::original_snapshot_release_tests::original_snapshot_boundary_native_hash_notifies_after_storage_fences', 'kura::tests::original_snapshot_release_tests::original_snapshot_mapping_empty_notifies_after_storage_fences', 'kura::tests::original_snapshot_release_tests::original_snapshot_mapping_native_bytes_notifies_after_storage_fences', 'kura::tests::original_snapshot_release_tests::original_snapshot_mapping_height_refusal_retains_exact_journals', 'kura::tests::original_snapshot_release_tests::original_snapshot_corrupt_journal_refusal_retains_exact_error_and_bytes', 'kura::tests::original_snapshot_release_tests::original_snapshot_partial_refusals_preserve_storage_and_mode_errors', 'kura::tests::original_snapshot_release_tests::original_snapshot_unwind_notifies_after_each_acquired_prefix']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC360"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure('original snapshot boundary notice must wait for all storage fences', 'crates/iroha_core/src/kura/tests/snapshot_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC360", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC360", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC360"', path.read_text())}
    assert owners == {"kura.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura.rs').read_text()
    for start, end in (("pub(crate) fn emergency_fast_snapshot_boundary(", "pub(crate) fn emergency_fast_snapshot_hash_mapping("),
                       ("pub(crate) fn emergency_fast_snapshot_hash_mapping(", "/// Exclude canonical Kura writers")):
        body = source[source.index(start):source.index(end, source.index(start))]
        first_guard = body.index("let _prune_guard =")
        for field, batch in (("prune_lock", "prune_releases"), ("canonical_chain_lock", "canonical_releases")):
            assert body.index("self." + field + ".defer_notifications()") < first_guard
            assert batch + ".lock()" in body
        assert "ensure_prune_recovery_not_required()?" in body
        assert "ensure_canonical_storage_not_poisoned()?" in body
        assert "read_exact_durable_index_count()?" in body
        assert "emergency_fast_startup_enabled()" in body
    controls = (ROOT / 'crates/iroha_core/src/kura/tests/snapshot_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "Error::PruneRecoveryRequired", "Error::CanonicalStoragePoisoned", "catch_unwind",
                       "registration.belongs_to(&budget)", "reserved - charge", "unrelated physical release",
                       "test_kura_with_default_lane_markers", "store_dummy_blocks(&kura, count)",
                       "config.init_mode = InitMode::Fast", "snapshot_regular_test_tree", "mapping.as_slice()",
                       "Error::HashesFileHeightMismatch", "block index journal has a partial trailing entry",
                       "canonical_body_bytes_read_for_test()"):
        assert obligation in controls
    assert "auxiliary_history_deferred =" not in controls
    assert "blank_kura_for_testing_in_emergency_fast_mode" not in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC360 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_inventory_notifications_outlive_outer_fences_and_final_accounting():
    names = ['kura::original_inventory_release_tests::original_inventory_absent_artifacts_publish_before_source_notice', 'kura::original_inventory_release_tests::original_inventory_retained_artifacts_publish_exact_counts_before_notice', 'kura::original_inventory_release_tests::original_inventory_artifact_refusal_invalidates_every_family_before_notice', 'kura::original_inventory_release_tests::original_inventory_tree_refusal_invalidates_every_family_before_notice', 'kura::original_inventory_release_tests::original_inventory_busy_owner_refusal_invalidates_before_prefix_notice', 'kura::original_inventory_release_tests::original_inventory_acquired_prefix_refusal_invalidates_before_notice', 'kura::original_inventory_release_tests::original_inventory_unwind_notifies_after_each_acquired_prefix']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC361"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure('original inventory notice must follow all fences and final family accounting', 'crates/iroha_core/src/kura/inventory_release_tests.rs') for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC361", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC361", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC361"', path.read_text())}
    assert owners == {"kura/physical_resource_initialization.rs", "kura/fastpq_artifact_store.rs"}
    source = (ROOT / 'crates/iroha_core/src/kura/physical_resource_initialization.rs').read_text()
    body = source[source.index("pub(crate) fn reconcile_physical_resource_inventory("):]
    for field, batch in (("prune_lock", "prune_releases"), ("canonical_chain_lock", "canonical_releases"), ("sidecar_lock", "sidecar_releases")):
        assert body.index("self." + field + ".defer_notifications()") < body.index("let result = (||")
        if field != "sidecar_lock":
            assert batch + ".lock()" in body
    assert "validate_fastpq_artifact_inventory_on_startup(&mut sidecar_releases)" in body
    assert body.index("let result = (||") < body.index(".invalidate(physical_resource_mask(), reason)") < body.index("\n        result\n")
    artifact = (ROOT / 'crates/iroha_core/src/kura/fastpq_artifact_store.rs').read_text()
    helper = artifact[artifact.index("pub(super) fn validate_fastpq_artifact_inventory_on_startup("):artifact.index("fn validate_fastpq_artifact_root(")]
    assert "sidecar_releases: &mut crate::publication_lock::DeferredPublicationFence<'_, ()>" in helper
    assert "sidecar_releases.lock()" in helper
    assert "defer_notifications()" not in helper
    controls = (ROOT / 'crates/iroha_core/src/kura/inventory_release_tests.rs').read_text()
    for obligation in ("transaction_history_budget()", "observe_release()", "wait_for_release(&mut registration)",
                       "publication_fences_for_test()", "try_publication_lease()", "block_store.try_lock()",
                       "components(&self.kura) == self.expected", "Unavailable::InvalidInventory", "Unavailable::Busy",
                       "Unavailable::Unregistered", "catch_unwind", "registration.belongs_to(&budget)",
                       "reserved - charge", "unrelated physical source release", "ResourceFamily::ResidentQueue.mask()",
                       "persist_fastpq_artifact", "canonical_bytes", "physical_resource_scope()", "observed(&kura)"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected
    rows = re.findall(r"^\| HC361 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in names)


def test_completed_recovery_authenticates_durable_boundary_without_capacity_policy():
    names = ['kura::capacity_release_tests::original_capacity_recovery_canonical_refusal_notifies_after_invalidation', 'kura::capacity_release_tests::original_capacity_recovery_cached_boundary_cannot_mask_corrupt_journals', 'kura::capacity_release_tests::original_capacity_recovery_poisoned_boundary_cannot_publish_accounting']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC362"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original capacity recovery notice must follow all fences and final accounting",
        "crates/iroha_core/src/kura/capacity_release_tests.rs",
    ) for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC362", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC362", **family)
    source = (ROOT / "crates/iroha_core/src/kura/publication_capacity.rs").read_text()
    body = source.split("fn validate_and_publish_configured_kura_capacity_after_startup_recovery(", 1)[1]
    assert body.index("self.exact_durable_blocks_count()?") < body.index("self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?")
    assert body.index("self.exact_durable_blocks_count()?") < body.index("let _geometry =")
    controls = (ROOT / "crates/iroha_core/src/kura/capacity_release_tests.rs").read_text()
    for obligation in ("for limit in [0, 1 << 30]", "Some((0, 0))", "HASHES_FILE_NAME", "INDEX_FILE_NAME", "Error::CanonicalStoragePoisoned", "observe_original_release", "Some(false)"):
        assert obligation in controls
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    rows = re.findall(r"^\| HC362 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected and name.rsplit("::", 1)[-1] in rows[0]


def test_native_lane_evidence_retains_original_directory_and_completed_frame():
    names = ['sumeragi::evidence_history::lane::tests::lane_proof_original_namespace_survives_funded_refusal_and_identical_replacement', 'sumeragi::evidence_history::lane::tests::completed_lane_proof_rejoins_original_namespace_before_attribution', 'sumeragi::lanes::evidence::frame::tests::funded_lane_frame_late_namespace_refusal_retains_completed_original_body']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC363"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original native lane namespace must remain retained", path) for path in (
        "crates/iroha_core/src/sumeragi/evidence_history/lane/tests.rs",
        "crates/iroha_core/src/sumeragi/evidence_history/lane/tests.rs",
        "crates/iroha_core/src/sumeragi/lanes/evidence/frame/tests.rs"))
    assert not rule.scenarios
    assert gate.has_switch("HC363", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC363", **family)
    lane = (ROOT / "crates/iroha_core/src/sumeragi/evidence_history/lane.rs").read_text()
    frame = (ROOT / "crates/iroha_core/src/sumeragi/lanes/evidence/frame.rs").read_text()
    read = (ROOT / "crates/iroha_core/src/sumeragi/lanes/store/read.rs").read_text()
    assert "directory: Option<iroha_fs::OwnerDirectory>" in lane
    assert "directory: iroha_fs::OwnerDirectory" in frame
    assert "ReadRecord::open_owned(" in frame and "ReadRecord::open(" not in frame
    assert "ArtifactRead::open_in(directory, name, MAX_FRAME_FILE_BYTES)" in read
    assert "Stage::Ready(original)" in frame and "self.stage = Stage::Ready(original)" in frame
    assert "self.directory.revalidate()?" in frame
    assert lane.index("self.revalidate_directory()?;") < lane.index(".copy_config(&self.budget)")
    verify = lane.split("pub(super) fn verify(", 1)[1]
    assert verify.count("self.revalidate_directory()") == 2
    assert verify.index("self.revalidate_directory()") < verify.index("verify_evidence(")
    assert verify.rindex("self.revalidate_directory()") > verify.index("FundedOffenders::collect(")
    controls = [(ROOT / "crates/iroha_core/src/sumeragi/evidence_history/lane/tests.rs").read_text(),
                (ROOT / "crates/iroha_core/src/sumeragi/lanes/evidence/frame/tests.rs").read_text()]
    for obligation in ("anchored_chain(3)", "substitute_lane_namespace", "Attempt::Deferred", "io::ErrorKind::NotFound",
                       "io::ErrorKind::Other", "budget.reserved_bytes(), baseline", "restore_lane_namespace"):
        assert obligation in controls[0]
    for obligation in ("Stage::Ready(complete)", "body_pointer", "original.body.admitted_to", "AtomicBool::new(true)",
                       "verified > 1", "context.budget.set_limit_bytes(held)", "original.qc.block_hash, hash"):
        assert obligation in controls[1]
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    rows = re.findall(r"^\| HC363 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1
    for name in names:
        assert name in selected and name.rsplit("::", 1)[-1] in rows[0]
    for source in controls:
        assert "stack_size" not in source and "RUST_MIN_STACK" not in source


def test_lane_recovery_keeps_exact_per_key_owner_without_shared_map_io():
    names = ['sumeragi::lanes::registry::tests::isolation_tests::original_lane_recovery_allows_ready_disjoint_owner_during_native_sync', 'sumeragi::lanes::registry::tests::isolation_tests::original_lane_recovery_retains_in_flight_historical_join_through_retirement', 'sumeragi::lanes::registry::tests::isolation_tests::original_lane_recovery_runtime_refusal_cancels_only_after_active_owner_returns']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC364"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(
        "original lane recovery must release the shared registry before native I/O",
        "crates/iroha_core/src/sumeragi/lanes/registry/isolation_tests.rs") for _ in names)
    assert not rule.scenarios
    assert gate.has_switch("HC364", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}):
        assert not gate.has_switch("HC364", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC364"', path.read_text())}
    assert owners == {"sumeragi/lanes/registry.rs"}
    registry = (root / "sumeragi/lanes/registry.rs").read_text()
    assert "Opening(Arc<StoreOpening>, OpeningOwners)" in registry
    assert "Pending(Option<LaneStoreOpen>)" in registry
    assert "progress: Mutex<OpeningProgress>" in registry
    lookup = registry[registry.index("fn store_with_runtime_owner("):registry.index("fn open_store_with_authority(")]
    assert lookup.count("drop(stores);") == 4
    assert lookup.count("self.complete_store_opening(key, opening)") == 3
    assert "FileLaneBlockStore::begin_open" not in lookup
    completion = registry[registry.index("fn complete_store_opening("):registry.index("fn progress_store_opening(")]
    assert "opening.progress.try_lock()" in completion
    assert completion.index("OpeningProgress::Ready(store)") < completion.index("self.progress_store_opening(")
    assert "*progress = OpeningProgress::Ready(Arc::clone(&store));" in completion
    assert "Arc::ptr_eq(retained, opening)" in completion
    assert re.search(r"StoreSlot::Ready\(ReadyStore\{registration,store:Arc::clone\(&store\),?\}\)", re.sub(r"\s+", "", completion))
    assert completion.index("owners.registration") < completion.index("StoreSlot::Ready(ReadyStore")
    assert registry.count("Arc::strong_count(opening) > 1") == 2
    assert registry.count("#[inline(never)]") == 2
    original_refund_owners = ("store_with_demand", "release", "release_retired",
                              "clean_cancelled_proposal_reads")
    for function in original_refund_owners:
        assert named_rust_function(registry, function).count("self.with_original_refunds(|| {") == 1
    assert named_rust_function(registry, "resume_retired_publications").count("self.with_original_refunds(|| {") == 1
    assert registry.count("self.with_original_refunds(|| {") == 5
    probe = (root / "sumeragi/lanes/registry/tests.rs").read_text()
    assert "opening.progress.try_lock().is_some()" in probe
    controls = (root / "sumeragi/lanes/registry/isolation_tests.rs").read_text()
    for obligation in ("Fixture::new(true)", "FsStep::SyncFile", "stores.stores.try_lock()",
                       "worker.join()", "Arc::ptr_eq(&disjoint", "independent_lock_refused",
                       "observation.bytes_before, observation.bytes_after",
                       "for retire_first in [false, true]", "budget.set_limit_bytes(retained)",
                       "OpeningProgress::Pending(Some(opening))", "Arc::clone(&earlier_join)",
                       "original.upgrade().is_none()", "fs::read(fixture.path()).unwrap(), original_bytes"):
        assert obligation in controls
    assert controls.index("worker.join()") < controls.index("observation.is_some()")
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    rows = re.findall(r"^\| HC364 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1
    for name in names:
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert name in selected and name.rsplit("::", 1)[-1] in rows[0]
    assert 'sumeragi::lanes::registry::tests::isolation_tests::original_lane_opening_cloned_before_completion_joins_the_same_ready_store' in selected


def test_original_retail_idle_batch_owns_exact_native_sources_and_shared_finite_pool():
    names = ['retail_fee_tests::original_idle_sweep_admits_exact_native_receipts_before_carrier_execution', 'retail_fee_tests::original_idle_sweep_keeps_bounded_month_prefix_and_fair_native_share', 'retail_fee_tests::original_one_entry_native_policy_alternates_retail_and_sns_admission']
    markers = ['original idle sweep must admit its own receipt purpose', 'original native pool must admit a fair exact retail prefix', 'one finite native slot alternates by height']
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC365"]
    assert rule.tests == tuple(names)
    assert rule.causes == tuple(gate.ExpectedFailure(marker,
        "crates/iroha_core/src/retail_fee_tests.rs") for marker in markers)
    assert not rule.scenarios
    assert gate.has_switch("HC365", core=True)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC365"', path.read_text())}
    assert owners == {"state/prepared_transfer_transcript.rs"}
    source = (root / "state/native_maintenance.rs").read_text()
    assert "matches_native_identity(&self.transaction)" in source
    assert "std::sync::Arc::ptr_eq(&self.context" in source
    assert "share.saturating_sub(used).min(remaining)" in source
    assert "self.prepare_apply().map_err(str::to_owned)?;" in source
    assert source.index("self.apply_prepared();") < source.index("witness.commit();")
    retail = (root / "retail_fee.rs").read_text()
    assert "begin_exec_witness_overlay()" in retail
    assert "admitted_idle_boundary" in retail
    assert "last_processed = Some(key)" in retail
    assert "RETAIL_FEE_MAX_CATCH_UP_MONTHS" in retail and ".take(128)" in retail
    permit = (root / "retail_fee/native_maintenance.rs").read_text()
    assert "std::mem::take(&mut stx.world.retail_fee_pending_transcripts)" in permit
    assert "receipt_commitment != self.receipt_commitment" in permit
    assert "bytes.clone()" not in permit
    quota = (root / "fastpq/source_reservation/admission.rs").read_text()
    assert "journal.has_staged_entry(hash)" in quota
    assert "retail_purposes" not in quota
    policy = (ROOT / "crates/iroha_data_model/src/parameter/fastpq_source.rs").read_text()
    assert "NATIVE_MAINTENANCE_INVOCATIONS: u32 = 64" in policy
    rows = re.findall(r"^\| HC365 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    controls = (root / "retail_fee_tests.rs").read_text()
    for name, marker in zip(names, markers):
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert marker in controls and name in selected
        assert name.rsplit("::", 1)[-1] in rows[0]
    for name in ['retail_fee_tests::original_idle_sweep_admits_exact_native_receipts_before_carrier_execution', 'retail_fee_tests::original_idle_sweep_keeps_bounded_month_prefix_and_fair_native_share', 'retail_fee_tests::original_one_entry_native_policy_alternates_retail_and_sns_admission', 'retail_fee_tests::original_idle_waived_receipts_keep_exact_history_without_native_entries', 'retail_fee::native_maintenance::tests::original_retail_permit_rejects_identical_discarded_sibling', 'retail_fee::native_maintenance::tests::original_retail_permit_rejects_changed_receipt_and_foreign_invocation_scope', 'retail_fee::native_maintenance::tests::original_idle_reward_refusal_rolls_back_witness_and_source_before_exact_retry', 'retail_fee::native_maintenance::tests::original_retail_receipt_decode_refusal_retains_exact_pending_owner_for_retry', 'fastpq::source_reservation::admission::tests::retail_native_batch_owns_only_its_exact_applied_receipt_prefix', 'fastpq::source_reservation::admission::tests::retail_native_quota_rejects_foreign_identity_and_mixed_authorities', 'fastpq::source_reservation::admission::tests::retail_and_sns_share_exact_original_native_capacity_without_lending']:
        assert name in selected
    assert "stack_size" not in controls and "RUST_MIN_STACK" not in controls


def test_sns_shared_native_selection_and_witness_have_independent_causal_mutations():
    cases = [
        ("HC366", 'sns::native_maintenance_tests::original_sns_late_fee_refusal_drops_witness_before_retry_metadata', 'original SNS late refusal must drop its prepared witness before retry metadata', "sns/native_maintenance_tests.rs", "sns.rs"),
        ("HC367", 'retail_fee_tests::original_time_sns_sweep_uses_only_capacity_left_by_exact_retail_prefix', 'native capacity deferral must preserve the exact unselected renewal', "retail_fee_tests.rs", "state/native_maintenance.rs"),
    ]
    root = ROOT / "crates/iroha_core/src"
    selected = (ROOT / "scripts/taira_release_check.py").read_text()
    for identity, name, marker, control_path, owner_path in cases:
        rule = gate.index_mutations(gate.CORE_MUTATIONS)[identity]
        assert rule.tests == (name,)
        assert rule.causes == (gate.ExpectedFailure(marker, "crates/iroha_core/src/" + control_path),)
        assert not rule.scenarios
        assert gate.has_switch(identity, core=True)
        owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
                  if re.search(r'sumeragi_core_mutation\s*=\s*"' + identity + '"', path.read_text())}
        assert owners == {owner_path}
        controls = (root / control_path).read_text()
        assert "fn " + name.rsplit("::", 1)[-1] + "()" in controls
        assert marker in controls and name in selected
        rows = re.findall(r"^\| " + identity + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
        assert len(rows) == 1 and name.rsplit("::", 1)[-1] in rows[0]
    source = (root / "state/native_maintenance.rs").read_text()
    assert ".checked_sub(quota.native_usage().executed_entries)" in source
    assert "native_maintenance_invocation_limit" not in source
    sns = (root / "sns.rs").read_text()
    assert "ALIAS_AUTO_RENEW_SWEEP_LIMIT.min(scope.invocation_limit())" in sns
    attempt = sns[sns.index("fn process_alias_auto_renew_storage_key("):sns.index("pub(crate) fn process_alias_auto_renewals(")]
    assert "begin_exec_witness_overlay()" in attempt and "apply_sns_maintenance(witness)" in attempt
    retry = attempt[attempt.index("AliasAutoRenewAttempt::Retry(error) =>") :]
    assert retry.index("drop(transaction)") < retry.index("drop(witness)") < retry.index("record_alias_auto_renew_failure")
    assert 'sumeragi_core_mutation = "HC365"' not in sns


@pytest.mark.parametrize("identifier,function,statement,control,cause", [
    ("HC385", "new_inner",
     "world_acquisition::validate_world_original_pools(&world, &execution_budget)",
     "state::world_acquisition::pool_identity_tests::fresh_state_refuses_a_foreign_pool_before_resource_admission",
     "fresh State must reject the original foreign pool before admission"),
    ("HC386", "write_sccp_execution_delta", "storage!(sccp_destination_pending_generations);",
     "state::tests::sccp_derived_indexes_bind_inserted_keys_and_deletions_in_merge_write_sets",
     "every changed SCCP index must appear in its canonical delta"),
    ("HC387", "write_sccp_execution_delta", "storage!(sccp_reconciliation_due);",
     "state::tests::sccp_derived_indexes_bind_inserted_keys_and_deletions_in_merge_write_sets",
     "every changed SCCP index must appear in its canonical delta"),
])
def test_original_state_pool_and_sccp_delta_mutations_keep_exact_owned_controls(
    identifier, function, statement, control, cause
):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    assert rule.tests == (control,)
    assert not rule.scenarios
    assert len(rule.causes) == 1 and rule.causes[0].cause == cause
    source = (ROOT / "crates/iroha_core/src/state.rs").read_text()
    body = named_rust_function(source, function)
    guard = f'#[cfg(not(all(test, sumeragi_core_mutation = "{identifier}")))]'
    assert re.search(re.escape(guard) + r"\s*" + re.escape(statement), body)
    assertion = (ROOT / rule.causes[0].source).read_text()
    assert f'"{cause}"' in named_rust_function(assertion, control.rsplit("::", 1)[-1])


def test_snapshot_structural_depth_mutation_keeps_public_and_scanner_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC388"]
    controls = (
        "snapshot::tests::snapshot_scanner_direct_policy_cannot_relax_fixed_structural_depth",
        "snapshot::tests::signed_snapshot_reader_refuses_depth_before_state_decode_with_direct_policy",
    )
    assert rule.tests == controls and not rule.scenarios
    assert [cause.cause for cause in rule.causes] == [
        "direct snapshot policy must not relax the fixed structural depth",
        "signed snapshot depth must refuse before typed State decoding",
    ]
    source = (ROOT / "crates/iroha_core/src/snapshot.rs").read_text()
    body = named_rust_function(source, "parse_value")
    guard = '#[cfg(not(all(test, sumeragi_core_mutation = "HC388")))]'
    assert re.search(re.escape(guard) + r"\s*if depth > norito::core::MAX_VALUE_NESTING_DEPTH", body)
    assert body.index("depth > self.policy.max_decode_depth.get()") < body.index(guard)
    assert body.index(guard) < body.index("let token = self.peek()")
    tests = (ROOT / "crates/iroha_core/src/snapshot/support_policy_tests.rs").read_text()
    for control, cause in zip(controls, rule.causes, strict=True):
        assert f'"{cause.cause}"' in named_rust_function(tests, control.rsplit("::", 1)[-1])
    public = named_rust_function(tests, controls[1].rsplit("::", 1)[-1])
    assert "try_read_snapshot_with_limits(" in public
    assert "write_snapshot_bundle_from_bytes(" in public
    assert "read_budget.reserved_bytes()" in public
    rows = re.findall(r"^\| HC388 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.MULTILINE)
    assert len(rows) == 1 and all(control.rsplit("::", 1)[-1] in rows[0] for control in controls)


def test_compute_full_width_model_mutations_preserve_owner_and_shipping_guards():
    rules = gate.index_mutations(gate.MODEL_MUTATIONS)
    source_path = "crates/iroha_data_model/src/compute/mod.rs"
    source = (ROOT / source_path).read_text()
    build = (ROOT / "crates/iroha_data_model/build.rs").read_text()
    spec = (ROOT / "specs/sumeragi.md").read_text()
    cases = {
        "DM41": ("price_delta_bounds_keep_full_width_before_comparison", "delta_bps",
                 "price updates must compare full-width deltas before applying bounds"),
        "DM42": ("sponsor_caps_keep_exact_daily_total_and_per_call_precedence", "enforce_sponsor_policy",
                 "the full daily sum must retain per-call refusal precedence"),
        "DM43": ("price_delta_wide_numerator_rejects_extreme_reduction", "delta_bps",
                 "price percentage must widen the numerator before multiplication"),
    }
    for mid, (control, owner, cause) in cases.items():
        rule = rules[mid]
        assert rule.tests == (f"compute::tests::{control}",) and not rule.scenarios
        assert [(item.cause, item.source) for item in rule.causes] == [(cause, source_path)]
        assert f'"{mid}"' in build
        kernel = named_rust_function(source, owner)
        assert f'#[cfg(all(test, sumeragi_model_mutation = "{mid}"))]' in kernel
        test = named_rust_function(source, control)
        assert cause in test and "sumeragi_model_mutation" not in test
        rows = re.findall(rf"^\| {mid} \|.*$", spec, re.MULTILINE)
        assert len(rows) == 1 and f"compute::tests::{control}" in rows[0]
    delta = named_rust_function(source, "delta_bps")
    assert "u128::from(current.get())" in delta and "u128::from(updated.get())" in delta
    assert "let numerator = delta * 10_000;" in delta
    assert '#[cfg(not(all(test, sumeragi_model_mutation = "DM41")))]' in delta
    sponsor = named_rust_function(source, "enforce_sponsor_policy")
    assert '#[cfg(not(all(test, sumeragi_model_mutation = "DM42")))]' in sponsor
    assert "u128::from(consumed_today) + u128::from(requested_cu)" in sponsor
    assert sponsor.index("requested_cu > policy.max_cu_per_call.get()") < sponsor.index("let running_total")
    config = (ROOT / "crates/iroha_config/src/parameters/actual.rs").read_text()
    assert "fn delta_bps(" not in config
    assert "iroha_data_model::compute::validate_price_family_update(" in config
    assert "iroha_data_model::compute::enforce_sponsor_policy(" in config


def artifact_envelopes(artifact, native="", *, extra=()):
    """Synthetic Cargo protocol for Python unit tests; no executable is launched."""
    record = {key: value for key, value in artifact.items()
              if key not in ("identity", "mutation", "runtime", "build_options", "binding_sha256")}
    record.update(reason="compiler-artifact", filenames=[artifact["executable"]], fresh=False)
    return "".join(json.dumps(row) + "\n" for row in
                   [record, *extra, {"reason": "build-finished", "success": True}]) + native


def stub_compiler_host(monkeypatch):
    """Only intercept the compiler identity query; every native/build call stays visible."""
    original_popen = gate.subprocess.Popen
    def popen(command, **options):
        if command[-1:] == ["-vV"]:
            class Probe:
                returncode = 0
                def communicate(self, *, timeout=None):
                    return b"rustc synthetic\nhost: synthetic-native-host\n", None
            return Probe()
        return original_popen(command, **options)
    monkeypatch.setattr(gate.subprocess, "Popen", popen)


def stub_artifact_cargo(monkeypatch, output):
    """Replace Popen only; real custody, capture validation and accounting remain."""
    calls = []
    def popen(command, **options):
        calls.append((command, options))
        class Process:
            returncode = 0
            def communicate(self, *, timeout=None):
                raw = output(command, options)
                if command[0] == "cargo":
                    records = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
                    artifacts = [row for row in records if row.get("reason") == "compiler-artifact"
                                 and row.get("executable") is not None]
                    if len(artifacts) == 1:
                        artifact = artifacts[0]
                        capture_option = command[-1].split("=", 1)[1]
                        runner = json.loads(capture_option).split()
                        capture = Path(runner[runner.index("--capture-runtime") + 1])
                        owner = Path(artifact["manifest_path"]).parent
                        environment = {key: None for key in gate.CARGO_RUNTIME_FIELDS}
                        environment[gate.runtime_loader_key()] = "/synthetic/runtime"
                        environment.update(CARGO="/synthetic/cargo", CARGO_MANIFEST_DIR=str(owner),
                            CARGO_MANIFEST_PATH=artifact["manifest_path"],
                            CARGO_PKG_NAME=gate.package_options(SimpleNamespace(
                                daemon=owner.name == "irohad"))[0] if owner.name == "irohad" else owner.name)
                        capture.write_text(json.dumps({"argv": [artifact["executable"]],
                            "cwd": str(owner), "environment": environment}))
                return raw.encode(), None
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    stub_compiler_host(monkeypatch)
    return calls


@pytest.mark.parametrize("owner", [None, "core", "daemon", "model", "sdk", "deploy", "torii", "norito", "p2p"])
def test_artifact_custody_uses_actual_emitted_owning_libtest_for_every_package(monkeypatch, tmp_path, owner):
    args = SimpleNamespace(timeout_build=30, **({owner: True} if owner else {}))
    original = fixture_artifact(args, tmp_path, None)
    raw = artifact_envelopes(original)
    stub_artifact_cargo(monkeypatch, lambda *_: raw)
    step = gate.build(args, tmp_path, None, tmp_path / "build.log")
    assert step.status == "pass" and step.artifact == original
    receipt = json.loads((tmp_path / "build.artifact.json").read_text())
    assert receipt["artifact"] == original and receipt["before"] is None
    assert receipt["errors"] == [] and receipt["launched"] is True
    assert (tmp_path / "build.log").read_bytes() == raw.encode()


@pytest.mark.parametrize("defect", [
    "absent", "duplicate", "foreign-extra", "manifest", "package", "target-name",
    "target-source", "target-kind", "profile", "features", "filenames", "outside",
    "failed-finish", "absent-finish", "malformed-target", "malformed-profile",
])
def test_artifact_custody_rejects_incomplete_ambiguous_or_foreign_cargo_records(tmp_path, defect):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    records = [json.loads(line) for line in artifact_envelopes(original).splitlines()]
    record = records[0]
    if defect == "absent": records.pop(0)
    elif defect == "duplicate": records.insert(0, dict(record))
    elif defect == "foreign-extra": records.insert(0, {**record, "manifest_path": "/foreign/Cargo.toml"})
    elif defect == "manifest": record["manifest_path"] = "/foreign/Cargo.toml"
    elif defect == "package": record["package_id"] = "registry+https://foreign#iroha_data_model"
    elif defect == "target-name": record["target"]["name"] = "foreign"
    elif defect == "target-source": record["target"]["src_path"] = str(ROOT / "crates/iroha_core/src/lib.rs")
    elif defect == "target-kind": record["target"]["kind"] = ["bin"]
    elif defect == "profile": record["profile"]["test"] = False
    elif defect == "features": record["features"] = []
    elif defect == "filenames": record["filenames"] = []
    elif defect == "outside": record["executable"] = str(tmp_path.parent / "foreign-libtest"); record["filenames"] = [record["executable"]]
    elif defect == "failed-finish": records[-1]["success"] = False
    elif defect == "absent-finish": records.pop()
    elif defect == "malformed-target": record["target"] = None
    elif defect == "malformed-profile": record["profile"] = None
    raw = "".join(json.dumps(row) + "\n" for row in records)
    _, receipt = gate.cargo_observation(raw, args, tmp_path, "DM41")
    assert receipt["artifact"] is None and receipt["errors"]


def test_artifact_custody_preserves_arbitrary_native_json_and_full_raw_stream(tmp_path):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    native = ('{"reason":"compiler-artifact","executable":"/printed/by/test"}\n'
              '{"application":"plain JSON output"}\n')
    raw = '{"application":"build log JSON, not a Cargo envelope"}\n' + artifact_envelopes(original, native)
    text, receipt = gate.cargo_observation(raw, args, tmp_path, "DM41")
    assert receipt["errors"] == [] and receipt["artifact"] == {
        key: value for key, value in original.items()
        if key not in ("runtime", "build_options", "binding_sha256")}
    assert text == '{"application":"build log JSON, not a Cargo envelope"}\n' + native
    diagnostic = {"reason": "compiler-message", "message": {
        "level": "warning", "rendered": "test tests::foreign ... FAILED\ntest result: FAILED.\n"}}
    text, receipt = gate.cargo_observation(artifact_envelopes(original, native, extra=[diagnostic]), args, tmp_path, "DM41")
    assert text == native and receipt["errors"] == []


def test_artifact_custody_retains_build_discovery_and_runtime_before_next_mutation(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True, timeout_build=30)
    baseline = fixture_artifact(args, tmp_path, None)
    names = "tests::named: test\n\n1 test, 0 benchmarks\n"
    terminal = "running 1 test\ntest tests::named ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
    def output(command, options):
        return artifact_envelopes(baseline) if command[0] == "cargo" else names if "--list" in command else terminal
    calls = stub_artifact_cargo(monkeypatch, output)
    build = gate.build(args, tmp_path, None, tmp_path / "baseline.build.log")
    step = gate.run_step(args, tmp_path, None, ["tests::named"], None, 30,
                         tmp_path / "baseline.named.log", build.artifact)
    assert step.status == "pass" and step.ran == ["tests::named"]
    assert len(calls) == 3
    assert calls[0][0][0:2] == ["cargo", "test"]
    assert all(call[0][0] == baseline["executable"] for call in calls[1:])
    assert all(call[1]["cwd"] == Path(baseline["manifest_path"]).parent for call in calls[1:])
    paths = [tmp_path / name for name in ("baseline.build.artifact.json", "baseline.named.discovery.artifact.json", "baseline.named.artifact.json")]
    retained = [path.read_bytes() for path in paths]
    for phase in ("discovery", "runtime"):
        receipt = step.custody[phase]
        assert receipt["artifact"] == baseline
        assert receipt["before"] == receipt["after"] == baseline["identity"]
        assert receipt["errors"] == []
    Path(baseline["executable"]).write_bytes(b"a different mutant image")
    mutant = fixture_artifact(args, tmp_path, "DM41")
    stub_artifact_cargo(monkeypatch, lambda *_: artifact_envelopes(mutant))
    new_build = gate.build(args, tmp_path, "DM41", tmp_path / "DM41.build.log")
    assert new_build.status == "pass" and new_build.artifact == mutant
    assert mutant["identity"]["sha256"] != baseline["identity"]["sha256"]
    assert [path.read_bytes() for path in paths] == retained
    assert json.loads(paths[0].read_text())["artifact"] == baseline
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("foreign mutation custody cannot launch"))
    refused = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                            tmp_path / "foreign.named.log", baseline)
    assert refused.status == "execution-error" and calls == []


@pytest.mark.parametrize("replacement", ["bytes", "same-bytes-inode", "symlink"])
def test_artifact_custody_refuses_changed_original_before_discovery(monkeypatch, tmp_path, replacement):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    path = Path(original["executable"])
    if replacement == "bytes": path.write_bytes(b"different original bytes")
    else:
        moved = tmp_path / "replacement"
        moved.write_bytes(path.read_bytes()); moved.chmod(0o700)
        if replacement == "same-bytes-inode": moved.replace(path)
        else: path.unlink(); path.symlink_to(moved)
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("drift must refuse before Cargo"))
    step = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                         tmp_path / "named.log", original)
    assert step.status == "execution-error" and calls == []
    assert step.custody["discovery"]["errors"]


@pytest.mark.parametrize("when", ["discovery", "runtime"])
def test_artifact_custody_refuses_executable_overwrite_during_original_invocation(monkeypatch, tmp_path, when):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    def output(command, _):
        listing = "--list" in command
        if listing == (when == "discovery"):
            Path(original["executable"]).write_bytes(b"same path overwritten during invocation")
        native = ("tests::named: test\n\n1 test, 0 benchmarks\n" if listing else
                  "running 1 test\ntest tests::named ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
        return native
    calls = stub_artifact_cargo(monkeypatch, output)
    step = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                         tmp_path / "named.log", original)
    assert step.status == "execution-error" and len(calls) == (1 if when == "discovery" else 2)
    receipt = step.custody[when]
    assert receipt["before"] == original["identity"]
    assert receipt["after"] != receipt["before"] and receipt["errors"]


def test_artifact_custody_hashing_cannot_replenish_the_original_deadline(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    moments = iter((100.0, 106.0, 106.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("expired admission cannot launch"))
    code, _, elapsed, receipt = gate.cargo_test(args, tmp_path, "DM41", ["tests::named"], None, 5,
                                               tmp_path / "expired.log", expected_artifact=original)
    assert code is None and elapsed == 6 and calls == []
    assert receipt["original_deadline_seconds"] == 5 and not receipt["launched"]
    assert receipt["deadline_exceeded"] is True
    assert receipt["artifact"] is None and receipt["errors"]


def test_artifact_custody_rechecks_original_between_discovery_and_runtime(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    names = "tests::named: test\n\n1 test, 0 benchmarks\n"
    calls = stub_artifact_cargo(monkeypatch, lambda *_: names)
    original_cargo_test = gate.cargo_test
    def change_before_runtime(*args, **kwargs):
        if "--list" not in args[3]:
            Path(original["executable"]).write_bytes(b"replacement after discovery closed")
        return original_cargo_test(*args, **kwargs)
    monkeypatch.setattr(gate, "cargo_test", change_before_runtime)
    step = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                         tmp_path / "between.log", original)
    assert step.status == "execution-error" and len(calls) == 1
    assert step.custody["discovery"]["errors"] == []
    assert not step.custody["runtime"]["launched"]
    assert "original executable changed before native invocation" in step.custody["runtime"]["errors"]


@pytest.mark.parametrize("changed", ["profile", "features", "executable"])
def test_artifact_custody_requires_original_bound_metadata_before_each_native_phase(monkeypatch, tmp_path, changed):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    different = json.loads(json.dumps(original))
    if changed == "profile":
        different["profile"]["opt_level"] = "3"
    elif changed == "features":
        different["features"].append("unexpected-feature")
    else:
        other = tmp_path / "another-libtest"
        other.write_bytes(Path(original["executable"]).read_bytes())
        other.chmod(0o700)
        different["executable"] = str(other)
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("altered metadata cannot launch"))
    step = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                         tmp_path / "metadata.log", different)
    assert step.status == "execution-error"
    receipt = step.custody["discovery"]
    assert calls == [] and not receipt["launched"]
    if changed != "executable":
        assert receipt["before"] == receipt["after"] == original["identity"]
        assert "original Cargo metadata or captured runtime changed before native invocation" in receipt["errors"]
    else:
        assert "original executable changed before native invocation" in receipt["errors"]


@pytest.mark.parametrize("damage", ["missing", "empty", "non-executable"])
def test_artifact_custody_rejects_unusable_original_without_launch(monkeypatch, tmp_path, damage):
    args = SimpleNamespace(model=True)
    original = fixture_artifact(args, tmp_path, "DM41")
    path = Path(original["executable"])
    if damage == "missing":
        path.unlink()
    elif damage == "empty":
        path.write_bytes(b"")
    else:
        path.chmod(0o600)
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("unusable original must not launch"))
    step = gate.run_step(args, tmp_path, "DM41", ["tests::named"], None, 30,
                         tmp_path / "unusable.log", original)
    assert step.status == "execution-error" and calls == []


def test_artifact_custody_retains_non_utf8_raw_bytes_and_refuses_classification(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True, timeout_build=30)
    original = fixture_artifact(args, tmp_path, None)
    raw = artifact_envelopes(original).encode() + b"\xff\xfe\r\n"
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            return raw, None
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    stub_compiler_host(monkeypatch)
    step = gate.build(args, tmp_path, None, tmp_path / "raw.log")
    assert step.status == "build-error" and step.artifact is None
    assert (tmp_path / "raw.log").read_bytes() == raw
    assert step.custody["build"]["errors"]

def test_p2p_constructor_mutation_owns_exact_refusal_controls_and_source_order():
    rules = gate.index_mutations(gate.P2P_MUTATIONS)
    assert set(rules) == {"NET1"}
    rule = rules["NET1"]
    prefix = "peer::receive_credit::stream::constructor_tests::"
    names = (
        "constructor_peer_mismatch_closes_io_before_source_reuse",
        "constructor_writer_refusal_closes_io_before_source_reuse",
    )
    assert rule.tests == tuple(prefix + name for name in names)
    assert rule.scenarios == ()
    source_path = "crates/iroha_p2p/src/peer/receive_credit/stream.rs"
    cause = "source cannot be rebound while either I/O half remains alive"
    assert rule.causes == (gate.ExpectedFailure(cause, source_path),) * len(names)
    assert gate.has_switch("NET1", p2p=True)
    for owner in (None, "core", "daemon", "model", "sdk", "deploy", "torii", "norito"):
        assert not gate.has_switch("NET1", **({owner: True} if owner else {}))
    root = ROOT / "crates/iroha_p2p"
    texts = {path.relative_to(root / "src").as_posix(): path.read_text()
             for path in (root / "src").rglob("*.rs")}
    assert {path for path, text in texts.items() if 'sumeragi_p2p_mutation = "NET1"' in text} == {
        "peer/receive_credit/stream.rs"
    }
    source = (ROOT / source_path).read_text()
    for name in names + ("constructor_success_transfers_original_io_and_source_until_drop",):
        assert f"fn {name}(" in source
    assert cause in source
    assert 'assert_eq!(*observation.order.lock().unwrap(), ["read", "write"]);' in source
    assert "if self.pool.bind(&self.peer).is_ok()" in source
    assert "live stream must retain its exact source" in source
    assert "closed transport releases its source exactly once" in source
    marker = "    pub(in crate::peer) fn new("
    assert source.count(marker) == 1
    body = source.split(marker, 1)[1].split("    /// Only fully authenticated", 1)[0]
    compact = re.sub(r"\s+", "", body)
    early = '#[cfg(all(test,sumeragi_p2p_mutation="NET1"))]letnegotiation::OwnedTransport{read,write,source,}=transport;'
    late = '#[cfg(not(all(test,sumeragi_p2p_mutation="NET1")))]letnegotiation::OwnedTransport{read,write,source,}=transport;'
    assert compact.index(early) < compact.index("if!peer_matches{")
    assert compact.index("super::writer_partitions(maximum,limits)?") < compact.index(late)
    assert 'letpeer_matches=source.peer==*peer.id();' in compact
    assert 'letpeer_matches=transport.source.peer==*peer.id();' in compact
    assert "record::encrypted_len::<E>(0)?>64" in compact
    manifest = (root / "Cargo.toml").read_text()
    assert "mutation-testing = []" in manifest and "/mutation-testing" not in manifest
    build = (root / "build.rs").read_text()
    declared = re.search(r'const IDS: &\[&str\] = &\[(.*?)\];', build, re.S)
    assert declared is not None
    assert set(re.findall(r'"([A-Z]+[0-9]+)"', declared.group(1))) == set(rules)
    for text in ('const CFG: &str = "sumeragi_p2p_mutation";',
                 'const ENV: &str = "SUMERAGI_P2P_MUTATION";',
                 '!rustflags.contains(CFG)', 'CARGO_FEATURE_MUTATION_TESTING',
                 'IDS.contains(&id.as_str())', 'mentions(Path::new("src"), &needle)'):
        assert text in build
    guard = (root / "src/p2p_mutation_guard.rs").read_text()
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard and "mutation-testing is test-only" in guard
    assert "mod p2p_mutation_guard;" in (root / "src/lib.rs").read_text()
    rows = re.findall(r"^\| (NET\d+) \| (.+)$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == len(rules) and {identifier for identifier, _ in rows} == set(rules)
    for identifier, row in rows:
        assert all(name in row for name in rules[identifier].tests)


@pytest.mark.parametrize("defect", [None, "missing-failure", "missing-panic", "wrong-source",
    "wrong-cause", "wrong-thread", "extra-panic", "unowned-panic"])
def test_p2p_constructor_mutation_requires_both_exact_owned_causal_failures(monkeypatch, tmp_path, defect):
    rule = gate.P2P_MUTATIONS[0]
    panics = {name: [{"thread": name, "source": expected.source, "message": expected.cause}]
              for name, expected in zip(rule.tests, rule.causes, strict=True)}
    failed = list(rule.tests)
    second = rule.tests[1]
    if defect == "missing-failure":
        failed.remove(second)
    elif defect == "missing-panic":
        del panics[second]
    elif defect == "wrong-source":
        panics[second][0]["source"] = "unrelated.rs"
    elif defect == "wrong-cause":
        panics[second][0]["message"] = "assertion failed: wrong error variant"
    elif defect == "wrong-thread":
        panics[second][0]["thread"] = "unrelated worker"
    elif defect == "extra-panic":
        panics[second].append(dict(panics[second][0]))
    monkeypatch.setattr(gate, "has_switch", lambda identifier, **owners:
                        identifier == rule.id and owners == {"p2p": True})
    monkeypatch.setattr(gate, "build", lambda *_: gate.Step(status="pass"))
    monkeypatch.setattr(gate, "run_step", lambda *_: gate.Step(
        status="fail", failed=failed, panics=panics, panic_owners_valid=defect != "unowned-panic"))
    result = gate.evaluate(SimpleNamespace(p2p=True, target_dir=tmp_path, timeout_test=900, fast=False),
                           tmp_path, rule)
    assert result["verdict"] == ("killed_by_test" if defect is None else "error")
    assert set(result["named"]["causal_failures"]) == set(rule.tests)
    assert all(result["named"]["causal_failures"].values()) == (defect is None)


@pytest.mark.parametrize("owner", [None, "core", "daemon", "model", "sdk", "deploy", "torii", "norito", "p2p"])
def test_p2p_mutation_environment_cannot_escape_into_another_owner(monkeypatch, tmp_path, owner):
    args = SimpleNamespace(**({owner: True} if owner else {}))
    captured = {}
    class Process:
        returncode = 0
        def communicate(self, *, timeout):
            return b"stub output", None
    def popen(command, **options):
        captured.update(command=command, env=options["env"])
        return Process()
    monkeypatch.setenv("SUMERAGI_P2P_MUTATION", "NET1")
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    code, output, _, _ = gate.cargo_test(args, tmp_path, None, ["named"], None, 900,
        tmp_path / "stub.log", expected_artifact=fixture_artifact(args, tmp_path, None))
    assert code == 0 and output == "stub output"
    assert "SUMERAGI_P2P_MUTATION" not in captured["env"]
    if owner == "p2p":
        assert captured["command"] == [str(tmp_path / "original-libtest"), "named"]


@pytest.mark.parametrize("owner", ["core", "daemon", "model", "sdk", "deploy", "torii", "norito"])
def test_p2p_mutation_source_selector_refuses_another_owner(owner):
    with pytest.raises(ValueError, match="exactly one implementation owner"):
        gate.has_switch("NET1", p2p=True, **{owner: True})


@pytest.mark.parametrize("arguments", [
    ["--p2p", "--core"], ["--p2p", "--norito"], ["--p2p", "--core-profile", "test"],
    ["--p2p", "--strict", "--skip-baseline"], ["--p2p", "--only", "HC23"],
    ["--core", "--only", "NET1"], ["--only", "NET1"], ["--norito", "--only", "NET1"],
    ["--p2p", "--only", "NET1,NET1"], ["--p2p", "--only", ","],
])
def test_p2p_mutation_cli_rejects_foreign_owners_and_skipped_baseline(monkeypatch, tmp_path, arguments):
    target = tmp_path / "refused"
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", *arguments, "--target-dir", str(target)])
    with pytest.raises(SystemExit) as error:
        gate.main()
    assert error.value.code == 2 and not target.exists()


def test_p2p_mutation_listing_uses_only_the_current_owner(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sumeragi_mutation_gate.py", "--p2p", "--list"])
    observed = []
    index = gate.index_mutations
    def inspect(table):
        observed.append(table)
        return index(table)
    monkeypatch.setattr(gate, "index_mutations", inspect)
    assert gate.main() == 0
    listing = capsys.readouterr().out
    assert observed == [gate.P2P_MUTATIONS]
    assert all(rule.id in listing and all(name in listing for name in rule.tests) for rule in gate.P2P_MUTATIONS)
    assert "HC23" not in listing and "NC1" not in listing


def test_capture_runner_records_only_cargo_runtime_and_never_executes_the_harness(monkeypatch, tmp_path):
    owner = tmp_path / "owner"
    owner.mkdir()
    monkeypatch.chdir(owner)
    monkeypatch.delenv("RUST_MIN_STACK", raising=False)
    monkeypatch.setenv("CARGO_MANIFEST_DIR", str(owner))
    monkeypatch.setenv("CARGO_MANIFEST_PATH", str(owner / "Cargo.toml"))
    monkeypatch.setenv("SECRET_CAPTURE_SENTINEL", "must-not-be-retained")
    monkeypatch.setenv(gate.runtime_loader_key(), "/actual/with spaces:/actual/second")
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_a, **_k: pytest.fail("capture cannot execute"))
    executable = owner / "never-executed"
    output = tmp_path / "runtime.json"
    assert gate.capture_runtime([str(output), str(owner), str(executable)]) == 0
    raw = output.read_bytes()
    captured = json.loads(raw)
    assert captured["argv"] == [str(executable)] and captured["cwd"] == str(owner)
    assert set(captured["environment"]) == set(gate.CARGO_RUNTIME_FIELDS)
    assert captured["environment"][gate.runtime_loader_key()] == "/actual/with spaces:/actual/second"
    assert b"SECRET_CAPTURE_SENTINEL" not in raw and b"must-not-be-retained" not in raw
    with pytest.raises(FileExistsError):
        gate.capture_runtime([str(output), str(owner), str(executable)])
    assert output.read_bytes() == raw, "a duplicate capture cannot replace the original"


@pytest.mark.parametrize("defect", ["extra-argv", "relative-executable", "wrong-cwd", "wrong-manifest", "stack"])
def test_capture_runner_refuses_a_foreign_or_nondefault_invocation(monkeypatch, tmp_path, defect):
    owner = tmp_path / "owner"
    owner.mkdir()
    monkeypatch.chdir(owner)
    monkeypatch.delenv("RUST_MIN_STACK", raising=False)
    monkeypatch.setenv("CARGO_MANIFEST_DIR", str(owner))
    monkeypatch.setenv("CARGO_MANIFEST_PATH", str(owner / "Cargo.toml"))
    output = tmp_path / "runtime.json"
    arguments = [str(output), str(owner), str(owner / "libtest")]
    if defect == "extra-argv": arguments.append("--list")
    elif defect == "relative-executable": arguments[-1] = "libtest"
    elif defect == "wrong-cwd": monkeypatch.chdir(tmp_path)
    elif defect == "wrong-manifest": monkeypatch.setenv("CARGO_MANIFEST_PATH", "/foreign/Cargo.toml")
    else: monkeypatch.setenv("RUST_MIN_STACK", "8388608")
    with pytest.raises(ValueError):
        gate.capture_runtime(arguments)
    assert not output.exists()


@pytest.mark.parametrize("platform,system,expected", [
    ("darwin", "posix", "DYLD_FALLBACK_LIBRARY_PATH"), ("linux", "posix", "LD_LIBRARY_PATH"),
    ("aix7", "posix", "LIBPATH"), ("win32", "nt", "PATH"),
])
def test_cargo_runtime_requires_the_native_platform_loader_field(monkeypatch, platform, system, expected):
    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(gate, "os", SimpleNamespace(name=system))
    assert gate.runtime_loader_key() == expected


@pytest.mark.parametrize("defect", ["argv", "cwd", "unknown-field", "unknown-env", "missing-env", "bad-env", "package", "loader"])
def test_capture_validation_refuses_foreign_or_incomplete_runtime(tmp_path, defect):
    artifact = fixture_artifact(SimpleNamespace(model=True), tmp_path, None)
    runtime = artifact["runtime"]
    if defect == "argv": runtime["argv"].append("--list")
    elif defect == "cwd": runtime["cwd"] = str(tmp_path)
    elif defect == "unknown-field": runtime["extra"] = "not-capture"
    elif defect == "unknown-env": runtime["environment"]["SECRET"] = "not-captured"
    elif defect == "missing-env": del runtime["environment"]["CARGO"]
    elif defect == "bad-env": runtime["environment"]["CARGO"] = ["not-a-string"]
    elif defect == "package": runtime["environment"]["CARGO_PKG_NAME"] = "foreign-owner"
    else: runtime["environment"][gate.runtime_loader_key()] = None
    with pytest.raises(ValueError, match="captured runtime"):
        gate.validate_runtime(artifact)


@pytest.mark.parametrize("override", [None, "RUSTC", "CARGO_BUILD_RUSTC"])
def test_capture_build_pins_the_queried_compiler_and_native_runner(monkeypatch, tmp_path, override):
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    calls = []
    class Probe:
        returncode = 0
        def communicate(self, *, timeout):
            assert timeout == 1200
            return b"rustc synthetic\nhost: verified-native-host\n", None
    def popen(command, **options):
        calls.append((command, options))
        return Probe()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    environment = {"CARGO_BUILD_TARGET": "ambient-cross-target"}
    if override:
        environment[override] = "/explicit/compiler"
    command, preparation = gate.capture_build_command(SimpleNamespace(p2p=True), environment,
                                                       tmp_path / "build.log", 100.0, 1200)
    compiler = "/explicit/compiler" if override else "rustc"
    assert len(calls) == 1 and calls[0][0] == [compiler, "-vV"]
    assert command[:13] == ["cargo", "test", "--locked", "-p", "iroha_p2p", "--profile", "test",
                            "--features", "mutation-testing", "--lib", "--message-format=json-render-diagnostics",
                            "--target", "verified-native-host"]
    assert command[-3:] == ["build.rustc=" + json.dumps(compiler), "--config",
                            "target.verified-native-host.runner=" + json.dumps(" ".join(preparation["runner"]))]
    assert "--no-run" not in command and "--capture-runtime" in preparation["runner"]
    assert environment["RUSTC"] == compiler and preparation["explicit_native_target"] is True
    assert Path(preparation["compiler_log"]).read_bytes() == b"rustc synthetic\nhost: verified-native-host\n"


@pytest.mark.parametrize("raw,exit_code", [(b"no host\n", 0), (b"host: one\nhost: two\n", 0),
                                          (b"host: valid-host\n", 1), (b"\xff\n", 0)])
def test_capture_build_refuses_failed_or_ambiguous_compiler_identity(monkeypatch, tmp_path, raw, exit_code):
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    calls = []
    class Probe:
        returncode = exit_code
        def communicate(self, *, timeout): return raw, None
    def popen(command, **options):
        calls.append(command)
        return Probe()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    with pytest.raises(ValueError):
        gate.capture_build_command(SimpleNamespace(), {}, tmp_path / "build.log", 100.0, 1200)
    assert calls == [["rustc", "-vV"]]
    assert (tmp_path / "build.compiler.log").read_bytes() == raw


def test_capture_compiler_deadline_waits_naturally_without_replenishment(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.time, "monotonic", lambda: 100.0)
    waits = []
    omitted = object()
    class Probe:
        returncode = 0
        def communicate(self, *, timeout=omitted):
            waits.append(timeout)
            if timeout is not omitted:
                raise subprocess.TimeoutExpired("compiler identity", timeout)
            return b"host: verified-native-host\n", None
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *_a, **_k: Probe())
    with pytest.raises(ValueError, match="within the build deadline"):
        gate.capture_build_command(SimpleNamespace(), {}, tmp_path / "build.log", 100.0, 1200)
    assert waits == [1200, omitted]


@pytest.mark.parametrize("defect", ["absent", "foreign-cwd", "foreign-argv", "runner-error", "compiler-error", "non-utf8"])
def test_build_requires_one_successful_capture_of_its_original_artifact(monkeypatch, tmp_path, defect):
    args = SimpleNamespace(model=True, timeout_build=1200)
    artifact = fixture_artifact(args, tmp_path, None)
    raw = artifact_envelopes(artifact)
    if defect == "compiler-error":
        raw = artifact_envelopes(artifact, extra=[{"reason": "compiler-message", "message": {
            "level": "error", "rendered": "error: synthetic compiler refusal"}}])
    captured = json.loads(json.dumps(artifact["runtime"]))
    if defect == "foreign-cwd": captured["cwd"] = str(tmp_path)
    elif defect == "foreign-argv": captured["argv"] = ["/foreign/libtest"]
    calls = []
    def popen(command, **options):
        calls.append(command)
        class Process:
            returncode = 101 if defect == "runner-error" else 0
            def communicate(self, *, timeout):
                if defect != "absent":
                    output = tmp_path / "build.runtime.json"
                    output.write_bytes(b"\xff" if defect == "non-utf8" else json.dumps(captured).encode())
                return raw.encode(), None
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    stub_compiler_host(monkeypatch)
    step = gate.build(args, tmp_path, None, tmp_path / "build.log")
    assert step.status == "build-error" and step.artifact is None
    assert step.custody["build"]["errors"] and len(calls) == 1
    assert calls[0][0:2] == ["cargo", "test"]
    assert (tmp_path / "build.log").read_bytes() == raw.encode()


@pytest.mark.parametrize("changed", ["owner", "profile", "runtime"])
def test_direct_native_refuses_changed_build_selection_or_captured_context(monkeypatch, tmp_path, changed):
    args = SimpleNamespace(core=True, core_profile="test")
    artifact = fixture_artifact(args, tmp_path, None)
    if changed == "owner": args = SimpleNamespace(model=True)
    elif changed == "profile": args.core_profile = "release"
    else: artifact["runtime"]["environment"][gate.runtime_loader_key()] = "/replacement/runtime"
    calls = stub_artifact_cargo(monkeypatch, lambda *_: pytest.fail("changed custody cannot launch"))
    code, _, _, receipt = gate.cargo_test(args, tmp_path, None, ["named"], None, 900,
                                         tmp_path / "run.log", expected_artifact=artifact)
    assert code is None and calls == [] and not receipt["launched"] and receipt["errors"]
    assert receipt["before"] == receipt["after"] == artifact["identity"]


def test_direct_native_keeps_json_bytes_and_captured_cwd_loader_environment(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True)
    artifact = fixture_artifact(args, tmp_path, None)
    captured = artifact["runtime"]["environment"]
    monkeypatch.setenv(gate.runtime_loader_key(), "/later/ambient/path")
    monkeypatch.setenv("CARGO_PKG_README", "/later/ambient/readme")
    raw = '{"reason":"compiler-artifact","executable":"/foreign/stdout"}\n'
    calls = stub_artifact_cargo(monkeypatch, lambda *_: raw)
    code, output, _, receipt = gate.cargo_test(args, tmp_path, None, ["named"], None, 900,
                                             tmp_path / "run.log", expected_artifact=artifact)
    assert code == 0 and output == raw and receipt["errors"] == []
    assert len(calls) == 1 and calls[0][0] == [artifact["executable"], "named"]
    assert calls[0][1]["cwd"] == Path(artifact["manifest_path"]).parent
    assert calls[0][1]["env"][gate.runtime_loader_key()] == captured[gate.runtime_loader_key()]
    assert "CARGO_PKG_README" not in calls[0][1]["env"]
    assert receipt["artifact"] == artifact and (tmp_path / "run.log").read_bytes() == raw.encode()


def test_direct_native_uses_owning_package_for_relative_fixture_reads(monkeypatch, tmp_path):
    """A real local Python child reproduces package-relative native fixture ownership."""
    args = SimpleNamespace(model=True)
    artifact = fixture_artifact(args, tmp_path, None)
    owner = tmp_path / "package/iroha_data_model"
    (owner / "tests/data").mkdir(parents=True)
    (owner / "tests/data/original.txt").write_text("original package fixture\n")
    program = "from pathlib import Path\nprint(Path('tests/data/original.txt').read_text(), end='')\n"
    executable = Path(artifact["executable"])
    executable.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + program)
    artifact["identity"] = gate.executable_identity(executable, tmp_path)
    artifact["manifest_path"] = str(owner / "Cargo.toml")
    artifact["runtime"]["cwd"] = str(owner)
    artifact["runtime"]["environment"].update(CARGO_MANIFEST_DIR=str(owner),
                                               CARGO_MANIFEST_PATH=str(owner / "Cargo.toml"))
    artifact["binding_sha256"] = gate.artifact_digest(artifact)
    monkeypatch.delenv("RUST_MIN_STACK", raising=False)
    refused = subprocess.run([str(executable)], cwd=tmp_path, capture_output=True, check=False)
    assert refused.returncode != 0 and b"FileNotFoundError" in refused.stderr
    code, output, _, receipt = gate.cargo_test(args, tmp_path, None, [], None, 900,
                                             tmp_path / "run.log", expected_artifact=artifact)
    assert code == 0 and output == "original package fixture\n" and receipt["errors"] == []
    assert receipt["cwd"] == str(owner)
    assert receipt["before"] == receipt["after"] == artifact["identity"]


def test_capture_preparation_and_cargo_share_the_original_build_deadline(monkeypatch, tmp_path):
    args = SimpleNamespace(model=True, timeout_build=5)
    artifact = fixture_artifact(args, tmp_path, None)
    moments = iter((100.0, 100.0, 103.0, 106.0))
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(moments))
    waits, calls = [], []
    def popen(command, **options):
        calls.append(command)
        class Process:
            returncode = 0
            def communicate(self, *, timeout):
                waits.append(timeout)
                if command[-1:] == ["-vV"]:
                    return b"host: verified-native-host\n", None
                (tmp_path / "build.runtime.json").write_text(json.dumps(artifact["runtime"]))
                return artifact_envelopes(artifact).encode(), None
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    step = gate.build(args, tmp_path, None, tmp_path / "build.log")
    receipt = step.custody["build"]
    assert waits == [5, 2] and len(calls) == 2
    assert step.status == "build-error" and receipt["exit_code"] is None
    assert receipt["seconds"] == 6 and receipt["original_deadline_seconds"] == 5
    assert receipt["deadline_exceeded"] is True


def test_norito_json_mutations_keep_single_test_allocator_and_shipping_guards():
    owner = ROOT / "crates/norito"
    lib = (owner / "src/lib.rs").read_text()
    allocator = (owner / "tests/json_parse_string_allocations.rs").read_text()
    assert not any("#[global_allocator]" in path.read_text() for path in (owner / "src").rglob("*.rs"))
    assert allocator.count("#[global_allocator]") == 1
    assert "static OBSERVED_ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };" in allocator
    for call in ("System.alloc(layout)", "System.alloc_zeroed(layout)", "System.realloc(ptr, layout, new_size)", "System.dealloc(ptr, layout)"):
        assert call in allocator
    for control in ("allocation_observation_is_thread_local_under_overlapping_scopes", "allocation_observation_restores_tracking_after_unwind", "allocation_observation_forwards_zeroed_and_reallocated_storage"):
        assert f"fn {control}(" in allocator
    assert "record_allocation_request();" in allocator
    guard = (owner / "src/norito_mutation_guard.rs").read_text()
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard
    assert 'mod norito_mutation_guard;' in lib
    for mid in range(6, 15):
        assert f'all(test, sumeragi_norito_mutation = "NC{mid}")' in lib
    # Each collection has one independently faulted original admission site.
    for mid in range(9, 14):
        assert lib.count(f'sumeragi_norito_mutation = "NC{mid}"') == 1
    fast = lib[lib.index("pub fn from_json_fast<'a, T>"):lib.index("pub fn from_json_fast_smart<'a, T>")]
    assert fast.index('sumeragi_norito_mutation = "NC7"') < fast.index("TapeWalker::new(s)") < fast.index("w.ensure_document_depth()?")
    depth = lib[lib.index("fn ensure_json_value_depth("):lib.index("fn try_decode_vec_with_capacity")]
    assert depth.index("depth > MAX_JSON_VALUE_NESTING_DEPTH") < depth.index('sumeragi_norito_mutation = "NC6"') < depth.index("checked_decode_depth")
    gate_owner = gate.index_mutations(gate.NORITO_MUTATIONS)["NC7"]
    assert tuple(cause.cause for cause in gate_owner.causes) == (
        "active depth refusal must precede structural tape allocation",
        "fixed depth refusal must precede structural tape allocation",
    )


def test_norito_cleanup_mutation_keeps_child_isolation_and_original_test_owners():
    rule = gate.index_mutations(gate.NORITO_MUTATIONS)["NC15"]
    owner = ROOT / "crates/norito"
    source = (owner / "src/json/value_drop.rs").read_text()
    control = (owner / "src/json_cleanup_stack_tests.rs").read_text()
    shared = (owner / "tests/support/json_cleanup_comb.rs").read_text()
    original = (owner / "tests/json_object_key_allocations.rs").read_text()
    lib = (owner / "src/lib.rs").read_text()
    assert rule.tests == (
        "json_cleanup_stack_tests::array_comb_cleanup_survives_default_stack_child",
        "json_cleanup_stack_tests::object_comb_cleanup_survives_default_stack_child",
    )
    assert [(cause.cause, cause.source) for cause in rule.causes] == [
        ("original JSON cleanup must not overflow the default-stack child", "crates/norito/src/json_cleanup_stack_tests.rs")
    ] * 2
    assert 'if cfg!(all(test, sumeragi_norito_mutation = "NC15")) {\n        drop(pending);\n        return;\n    }' in source
    assert '#[cfg(all(test, feature = "json"))]\nmod json_cleanup_stack_tests;' in lib
    assert '#[path = "../tests/support/json_cleanup_comb.rs"]\nmod json_cleanup_comb;' in lib
    assert '#[path = "support/json_cleanup_comb.rs"]\nmod json_cleanup_comb;' in original
    assert 'use json_cleanup_comb::{CombContainer, deep_comb, pair};' in original
    assert 'fn deep_comb(' not in original and shared.count('fn deep_comb(') == 1
    assert 'for _ in 0..json::MAX_JSON_VALUE_NESTING_DEPTH' in shared
    assert 'deep_comb(container, 4_096)' in control
    assert 'Command::new(std::env::current_exe()' in control
    arguments = re.search(r"\.args\(\[(.*?)\]\)", control, re.S)
    assert arguments is not None
    assert re.findall(r'"[^"]*"|\bname\b', arguments.group(1)) == [
        '"--exact"', 'name', '"--nocapture"', '"--test-threads=1"', '"--format=pretty"', '"--color=never"'
    ]
    assert '.env(CHILD_ENV, name)' in control and '.output()' in control
    assert 'std::env::var_os("RUST_MIN_STACK").is_none()' in control
    assert 'output.stdout.escape_ascii()' in control and 'output.stderr.escape_ascii()' in control
    assert 'std::io::stderr().lock()' in control
    assert 'std::str::from_utf8(&output.stdout)' in control and 'std::str::from_utf8(&output.stderr)' in control
    assert control.index('let value = deep_comb(') < control.index('eprintln!("NORITO_CLEANUP_READY:') < control.index('json::drop_json_value_iteratively(value)')
    for text in (control, shared):
        assert '#[global_allocator]' not in text and 'stack_size(' not in text
    for name in rule.tests:
        assert f'fn {name.rsplit("::", 1)[-1]}(' in control
    assert not rule.scenarios
    rows = re.findall(r'^\| NC15 \|.*$', (ROOT / 'specs/sumeragi.md').read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name in rule.tests)


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-parent-panic", "one-passes", "missing-terminal", "raw-child-terminal", "parent-abort", "timeout"])
def test_norito_cleanup_kill_requires_normal_parent_census_and_each_exact_cause(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.NORITO_MUTATIONS)["NC15"]
    rows = [(name, "ok" if defect == "one-passes" and index == 0 else "FAILED") for index, name in enumerate(rule.tests)]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    name, expected = rule.tests[0], rule.causes[0]
    panic = f"thread '{name}' (12) panicked at {expected.source}:123:7:\n{expected.cause}\n"
    # These are escaped diagnostic lines, never another native terminal or panic owner.
    escaped = 'cleanup child stdout: ' + json.dumps(f"running 1 test\ntest {name} ... ") + '\n'
    escaped += 'cleanup child stderr: ' + json.dumps(f"thread '{name}' (123) has overflowed its stack\nfatal runtime error: stack overflow, aborting\n") + '\n'
    output = output.replace(panic, escaped + panic, 1)
    if defect == "unrelated":
        output = output.replace(expected.cause, "cleanup child did not complete its exact declared protocol", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "missing-parent-panic":
        output = output.replace(panic, '', 1)
    elif defect == "raw-child-terminal":
        output = 'running 1 test\ntest foreign_child ... ok\n' + output
    elif defect == "parent-abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(norito=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    assert result["verdict"] == ("killed_by_test" if defect == "none" else "error"), result
    if defect == "none":
        assert result["named"]["causal_failures"] == dict.fromkeys(rule.tests, True)


def test_norito_cleanup_parent_launch_drops_only_the_child_marker(monkeypatch, tmp_path):
    monkeypatch.delenv("RUST_MIN_STACK", raising=False)
    monkeypatch.setenv("NORITO_JSON_CLEANUP_TEST_CHILD", "foreign inherited child marker")
    monkeypatch.setenv("KEEP_NATIVE_TEST_ENVIRONMENT", "unchanged")
    args = SimpleNamespace(norito=True)
    artifact = fixture_artifact(args, tmp_path, "NC15")
    captured = []
    def popen(command, **options):
        captured.append((command, options))
        class Process:
            returncode = 0
            def communicate(self, *, timeout=None):
                return b"synthetic native output", None
        return Process()
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    code, _, _, _ = gate.cargo_test(args, tmp_path, "NC15", ["named"], None, 900,
        tmp_path / "parent.log", expected_artifact=artifact)
    assert code == 0 and len(captured) == 1
    command, options = captured[0]
    assert command == [artifact["executable"], "named"]
    assert "NORITO_JSON_CLEANUP_TEST_CHILD" not in options["env"]
    assert options["env"]["KEEP_NATIVE_TEST_ENVIRONMENT"] == "unchanged"
    assert options["env"]["SUMERAGI_NORITO_MUTATION"] == "NC15"


@pytest.mark.parametrize("identifier,owner,controls,cause,source", [
    ('HC389', 'crates/iroha_core/src/sumeragi/lanes/store.rs', ('sumeragi::lanes::store::retirement_probe_tests::durable_tip_zero_wait_does_not_acquire_original_io_state',), 'a zero-time durable-tip observation must complete while the original I/O state remains held', 'crates/iroha_core/src/sumeragi/lanes/store/retirement_probe_tests.rs'),
    ('HC390', 'crates/iroha_core/src/sumeragi/lanes/runner.rs', ('sumeragi::lanes::registry::tests::retired_reconcile_finishes_original_publication_after_create_refusal', 'sumeragi::lanes::registry::tests::retired_reconcile_finishes_original_publication_after_directory_sync_refusal'), 'retired reconciliation must finish the original pending publication after refusal clears, then release only its idle in-memory owner', 'crates/iroha_core/src/sumeragi/lanes/registry/tests.rs'),
    ('HC391', 'crates/iroha_core/src/sumeragi/lanes/registry.rs', ('sumeragi::lanes::registry::tests::registry_debug_releases_original_map_before_field_callback',), 'registry Debug field callbacks must not retain the original map lock', 'crates/iroha_core/src/sumeragi/lanes/registry/tests.rs'),
    ('HC392', 'crates/iroha_core/src/sumeragi/lanes/runner.rs', ('sumeragi::lanes::registry::tests::runner_debug_releases_original_map_before_field_callback',), 'runner Debug field callbacks must not retain the original map lock', 'crates/iroha_core/src/sumeragi/lanes/registry/tests.rs'),
])
def test_lane_wait_retirement_and_debug_mutations_keep_exact_original_owners(
    identifier, owner, controls, cause, source
):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    assert rule.tests == controls and not rule.scenarios
    assert rule.causes == tuple(gate.ExpectedFailure(cause, source) for _ in controls)
    assert gate.has_switch(identifier, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(identifier, **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(ROOT).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + identifier + '"', path.read_text())}
    assert owners == {owner}
    code = (ROOT / owner).read_text()
    assert code.count(f'sumeragi_core_mutation = "{identifier}"') == 1
    if identifier == "HC390":
        guard = f'#[cfg(not(all(test, sumeragi_core_mutation = "{identifier}")))]'


        continuation = re.search(
            re.escape(guard)
            + r"\s*self\s*\.\s*inputs\s*\.\s*stores\s*\.\s*resume_retired_publications\(&lanes,\s*\|key\|\s*\{(?P<predicate>.*?)\}\);",
            code, re.DOTALL,
        )
        assert continuation is not None
        predicate = re.sub(r"//[^\n]*", "", continuation.group("predicate"))
        # Each probe yields a bool at its own semicolon. No map guard or callback
        # can survive the predicate into original native publication continuation.
        assert "".join(predicate.split()) == (
            'letrunning=self.running.lock().contains_key(key);'
            'letstarting=self.starting.lock().contains_key(key);'
            '!running&&!starting'
        )
        assert code.index(guard) < code.index('if cfg!(all(test, sumeragi_core_mutation = "HC349"))')
    else:
        guard = f'#[cfg(all(test, sumeragi_core_mutation = "{identifier}"))]'
        statement = {
            "HC389": "let _original_io_state = self.state.lock();",
            "HC391": "let _original_map = self.stores.lock();",
            "HC392": "let _original_map = self.inner.running.lock();",
        }[identifier]
        assert re.search(re.escape(guard) + r"\s*" + re.escape(statement), code)
    control = (ROOT / source).read_text()
    for name in controls:
        assert f"fn {name.rsplit('::', 1)[-1]}(" in control
    assert json.dumps(cause) in control
    if identifier == "HC389":
        body = named_rust_function(control, controls[0].rsplit("::", 1)[-1])
        assert body.index("drop(state);") < body.index("waiter.join()") < body.index(json.dumps(cause))
        assert "store.wait_for(0, Duration::ZERO)" in body
        assert "store.wait_for(1, Duration::ZERO)" in body
    elif identifier == "HC390":
        body = named_rust_function(control, "retired_publication_continuation_control")
        assert re.search(r"runner\.running_count\(\),\s*0\b", body)
        assert body.count("runner.reconcile();") == 3
        assert body.index("let completed =") < body.index("publication.retire();") < body.index("publication.join().unwrap();")
        assert body.index("publication.join().unwrap();") < body.index(json.dumps(cause))
        assert "faults.attempts.load(Ordering::SeqCst) >= 2" in body
        assert "notified && completed && released" in body
        assert "budget.reserved_bytes(), limit" in body
        assert "original.upgrade().is_none()" in body
        assert re.search(r"Arc::ptr_eq\(\s*&same\b", body)
        assert re.search(r"authorities\.calls\.load\(Ordering::SeqCst\),\s*authority_calls", body)
        assert "certificate, qc" in body
    else:
        body = named_rust_function(control, controls[0].rsplit("::", 1)[-1])
        assert "formatted.unwrap();" in body and "Some(true)" in body
        assert body.index("formatted.unwrap();") < body.index(json.dumps(cause))
        if identifier == "HC391":
            assert "assert_eq!(probe.output, expected)" in body
        else:
            assert 'assert_eq!(output, "LaneRunner { running: 0, .. }")' in body
    rows = re.findall(r"^\| " + identifier + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in controls)
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    guard = (root / "mutation_guard.rs").read_text()
    assert 'env::var_os("CARGO_FEATURE_MUTATION_TESTING").is_none()' in build
    assert 'mentions(Path::new("src"), &needle)' in build
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard
    assert "mod mutation_guard;" in (root / "lib.rs").read_text()


@pytest.mark.parametrize("identifier", ["HC389", "HC390", "HC391", "HC392"])
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_lane_custody_kills_require_normal_complete_exact_causal_failures(monkeypatch, tmp_path, identifier, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    rows = [(name, "ok" if defect == "one-passes" and index == 0 else "FAILED") for index, name in enumerate(rule.tests)]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" and len(rule.tests) == 1 else "error"
    assert result["verdict"] == verdict, result
    if defect == "none":
        assert result["named"]["causal_failures"] == dict.fromkeys(rule.tests, True)


@pytest.mark.parametrize("identifier,owner,control,cause", [
    ('HC393', 'crates/iroha_core/src/sumeragi/driver/mod.rs', 'sumeragi::driver::tests::threaded::retirement_tests::retiring_executor_does_not_block_other_lane_transaction_delivery', 'retired worker joins must not block the actual lane lifecycle turn'),
    ('HC394', 'crates/iroha_core/src/sumeragi/lanes/runner.rs', 'sumeragi::driver::tests::threaded::retirement_tests::retiring_incarnation_blocks_same_lane_start_until_original_workers_finish', 'a new incarnation must not acquire startup authority before its same-lane predecessor physically finishes'),
])
def test_lane_shutdown_mutations_keep_independent_original_owners(identifier, owner, control, cause):
    source = "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs"
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    assert rule.tests == (control,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert gate.has_switch(identifier, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(identifier, **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(ROOT).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + identifier + '"', path.read_text())}
    assert owners == {owner}
    code = (ROOT / owner).read_text()
    assert code.count(f'sumeragi_core_mutation = "{identifier}"') == 1
    if identifier == "HC393":
        body = named_rust_function(code, "poll_shutdown")
        guard = '#[cfg(all(test, sumeragi_core_mutation = "HC393"))]'
        assert re.search(re.escape(guard) + r"\s*self\.stop_and_join\(\);", body)
        assert body.index(guard) < body.index("self.request_shutdown();")
        assert "!thread.is_finished()" in body and "joiner.handoff" in body
    elif identifier == "HC394":
        assert re.search(r'if cfg!\(all\(test, sumeragi_core_mutation = "HC394"\)\)\s*\{\s*self\s*\.\s*running\s*\.\s*lock\(\)\s*\.\s*contains_key\(&key\)\s*\}\s*else\s*\{\s*self\s*\.\s*running\s*\.\s*lock\(\)\s*\.\s*keys\(\)\s*\.\s*any\(\|\(lane, _\)\| \*lane == record\.lane\)\s*\}', code)
    controls = (ROOT / source).read_text()
    body = named_rust_function(controls, control.rsplit("::", 1)[-1])
    assert body.index("lifecycle.join()") < body.index("joined.unwrap();") < body.index(json.dumps(cause))
    assert body.index("release.0.set_open(true);") < body.index("lifecycle.join()")
    assert "OpenExecutorOnDrop(release.0.clone())" in body
    assert "runner.shutdown();" in body
    spec_rows = re.findall(r"^\| " + identifier + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(spec_rows) == 1 and control.rsplit("::", 1)[-1] in spec_rows[0]
    build = (ROOT / "crates/iroha_core/build.rs").read_text()
    guard = (root / "mutation_guard.rs").read_text()
    assert 'env::var_os("CARGO_FEATURE_MUTATION_TESTING").is_none()' in build
    assert 'mentions(Path::new("src"), &needle)' in build
    assert '#[cfg(all(feature = "mutation-testing", not(test)))]' in guard
    assert "compile_error!" in guard
    assert "mod mutation_guard;" in (root / "lib.rs").read_text()


@pytest.mark.parametrize("identifier", ["HC393", "HC394", "HC395"])
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_lane_shutdown_kills_require_normal_complete_causal_failure(monkeypatch, tmp_path, identifier, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result
    if defect == "none":
        assert result["named"]["causal_failures"] == dict.fromkeys(rule.tests, True)




@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_retired_publication_kill_requires_complete_exact_causal_terminal(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC414"]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result
    if defect == "none":
        assert result["named"]["causal_failures"] == dict.fromkeys(rule.tests, True)


@pytest.mark.parametrize("verdict", ["ok", "FAILED", "missing"])
def test_retired_publication_baseline_requires_its_original_complete_control(monkeypatch, tmp_path, verdict):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC414"]
    rows = [] if verdict == "missing" else [(name, verdict) for name in rule.tests]
    code, output = causal_control_output(rule, rows)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate_baseline(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, [rule])
    assert result["verdict"] == ("pass" if verdict == "ok" else "fail"), result
    assert result["named"]["steps"][0]["filters"] == list(rule.tests)


def test_lane_registry_final_destructor_mutation_has_exact_native_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC415"]
    source = "crates/iroha_core/src/sumeragi/lanes/registry/destruction_tests.rs"
    controls = (ROOT / source).read_text()
    names = re.findall(r"#\[test\]\s+fn (\w+)\(", controls)
    assert len(names) == len(set(names)) == 4
    assert rule.tests == tuple("sumeragi::lanes::registry::tests::destruction_tests::" + name for name in names)
    assert rule.causes == (gate.ExpectedFailure("final original lane authority destructor must run after registry unlock", source),) * 4
    assert not rule.scenarios and gate.has_switch("HC415", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC415", **family)
    registry = (ROOT / "crates/iroha_core/src/sumeragi/lanes/registry.rs").read_text()
    assert registry.count('sumeragi_core_mutation = "HC415"') == 2
    for name in ("release", "release_retired"):
        drop_owner = named_rust_function(registry, name)
        compact = re.sub(r"\s+", "", drop_owner)
        compact = re.sub(r",(?=\))", "", compact)
        assert '#[cfg(all(test,any(sumeragi_core_mutation="HC348",sumeragi_core_mutation="HC415")))]' in compact
        assert drop_owner.index("let _original_map = self.stores.lock();") < drop_owner.index("drop(retired);")
    assert "fixture.stores.stores.try_lock()" in controls
    assert "impl Drop for DestructionSchedule" in controls
    assert controls.index("drop(guard);") < controls.index("fixture.stores.release(LANE, &INCARNATION);")
    assert "baseline + original.len()" in controls
    assert '"final original lane authority can reenter the released registry"' in controls
    assert "fs::read(fixture.path()).unwrap(), original" in controls


def test_read_only_absent_frame_mutation_preserves_exact_native_cause():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC403"]
    owner = "crates/iroha_core/src/sumeragi/lanes/store/tests.rs"
    assert rule.tests == ("sumeragi::lanes::store::tests::read_only_missing_frame_preserves_not_found_and_reopens_after_publication",)
    assert rule.causes == (gate.ExpectedFailure("read-only absent frame must remain NotFound before any retained restore job", owner),)
    assert gate.has_switch("HC403", core=True) and not rule.scenarios
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC403", **family)
    source = (ROOT / "crates/iroha_core/src/sumeragi/lanes/store/read.rs").read_text()
    assert source.count('sumeragi_core_mutation = "HC403"') == 1
    assert '#[cfg(not(all(test, sumeragi_core_mutation = "HC403")))]' in source
    assert '"committed lane frame disappeared"' in source


@pytest.mark.parametrize("mutation_id,selector,cause,owner", [
    ("HC404", "sumeragi::driver::tests::threaded::retirement_tests::native_lane_startup_sync_does_not_block_other_lane_transaction_delivery", "original native startup SyncFile must not block another lane's actual lifecycle turn and transaction commit", "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs"),
    ("HC405", "sumeragi::driver::tests::threaded::retirement_tests::ready_transfer_reissues_consumed_transaction_wake_to_original_workers", "Ready transfer must redeliver the consumed transaction wake to the original workers", "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs"),
    ("HC406", "sumeragi::driver::startup::tests::pending_ready_with_finished_original_joiner_stays_owned_and_unexposed", "Ready must remain unexposed with exact workers when its original joiner already ended", "crates/iroha_core/src/sumeragi/driver/startup/tests.rs"),
    ("HC407", "sumeragi::driver::startup::tests::pending_transfer_retains_original_startup_charge_until_worker_join", "original startup registration and control charge must survive transfer until workers join", "crates/iroha_core/src/sumeragi/driver/startup/tests.rs"),
    ("HC408", "sumeragi::lanes::runner::startup::tests::original_record_log_os_failure_retries_same_stage_and_store", "original custody log I/O must retry without replacing the startup generation", "crates/iroha_core/src/sumeragi/lanes/runner/startup/tests.rs"),
    ("HC409", "sumeragi::lanes::runner::startup::tests::changed_original_directory_custody_is_terminal_without_native_retry", "actual changed directory custody must remain a typed terminal refusal", "crates/iroha_core/src/sumeragi/lanes/runner/startup/tests.rs"),
    ("HC410", "sumeragi::driver::tests::threaded::retirement_tests::stale_failed_startup_releases_same_lane_only_after_original_workers_join", "committed retirement must release the original failed startup after successful physical cleanup", "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs"),
    ("HC411", "sumeragi::lanes::runner::startup::tests::custom_custody_other_stays_terminal_with_its_original_source", "terminal native source must remain typed", "crates/iroha_core/src/sumeragi/lanes/runner/startup/tests.rs"),
    ("HC412", "sumeragi::driver::persist::tests::installation_encoding_refusal_preserves_original_record_error", "installation encoding refusal must stay deterministic InvalidData", "crates/iroha_core/src/sumeragi/driver/persist.rs"),
    ("HC413", "sumeragi::driver::startup::tests::cancelled_failed_joiner_cannot_report_startup_retirement_success", "failed or missing original joiner must never certify retired startup success", "crates/iroha_core/src/sumeragi/driver/startup/tests.rs"),
 ])
def test_original_startup_mutations_require_exact_native_ownership_causes(mutation_id, selector, cause, owner):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mutation_id]
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, owner),)
    assert not rule.scenarios and gate.has_switch(mutation_id, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mutation_id, **family)
    controls = (ROOT / owner).read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in controls
    assert cause in controls


def test_original_startup_transfer_cancellation_mutation_preserves_physical_join_cause():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC416"]
    owner = "crates/iroha_core/src/sumeragi/driver/startup/tests.rs"
    assert rule.tests == ("sumeragi::driver::startup::tests::cancelled_ready_transfer_keeps_original_joiner_until_every_worker_finishes",)
    assert rule.causes == (gate.ExpectedFailure("cancelled Ready transfer must retain its original physical joining owner", owner),)
    assert not rule.scenarios and gate.has_switch("HC416", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC416", **family)
    source = (ROOT / "crates/iroha_core/src/sumeragi/driver/startup/pending.rs").read_text()
    assert source.count('sumeragi_core_mutation = "HC416"') == 1
    assert 'cfg!(all(test, sumeragi_core_mutation = "HC416"))' in source
    controls = (ROOT / owner).read_text()
    assert 'TRANSFER_OBSERVATION' in controls and "cancelled Ready transfer must retain its original physical joining owner" in controls


def test_read_only_lane_authority_destruction_mutation_retains_native_owners():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC402"]
    source = "crates/iroha_core/src/sumeragi/lanes/registry/read_only_destruction_tests.rs"
    names = (
        "completed_read_only_frame_destroys_final_authority_after_read_unlock",
        "missing_read_only_frame_destroys_final_authority_after_read_unlock",
        "reselected_read_only_frame_destroys_each_final_authority_after_read_unlock",
    )
    assert rule.tests == tuple("sumeragi::lanes::registry::tests::read_only_destruction_tests::" + name for name in names)
    assert rule.causes == (gate.ExpectedFailure("final original read-only authority destructor must run after read mutex unlock", source),) * 3
    assert not rule.scenarios and gate.has_switch("HC402", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC402", **family)
    owner = (ROOT / "crates/iroha_core/src/sumeragi/lanes/registry/read_only.rs").read_text()
    assert owner.count('sumeragi_core_mutation = "HC402"') == 2
    assert owner.count('#[cfg(all(test, sumeragi_core_mutation = "HC402"))]') == 2
    assert owner.count("let _held_read_mutex = self.read.lock();") == 2
    controls = (ROOT / source).read_text()
    assert "impl Drop for ReadDropSchedule" in controls
    assert "source.read_lock_available_for_test()" in controls
    assert "read_only_capacity_retry_retains_the_original_authority_and_partial_frame" in controls




def test_hc418_preserves_exact_original_owner_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC418"]
    assert rule.tests == ("sumeragi::lanes::registry::tests::read_only_destruction_tests::read_only_post_open_not_found_retains_original_source",)
    assert rule.causes == (gate.ExpectedFailure("post-open NotFound must retain the original funded frame and authority without recapture", "crates/iroha_core/src/sumeragi/lanes/registry/read_only_destruction_tests.rs"),)
    assert not rule.scenarios and gate.has_switch("HC418", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC418", **family)
    source = (ROOT / "crates/iroha_core/src/sumeragi/lanes/registry/read_only.rs").read_text()
    assert source.count('sumeragi_core_mutation = "HC418"') == 1
    assert 'cfg!(all(test, sumeragi_core_mutation = "HC418"))' in source
    controls = (ROOT / "crates/iroha_core/src/sumeragi/lanes/registry/read_only_destruction_tests.rs").read_text()
    assert "fn read_only_post_open_not_found_retains_original_source(" in controls
    assert "post-open NotFound must retain the original funded frame and authority without recapture" in controls


@pytest.mark.parametrize("identifier,selector,cause,source,owner", [
    ('HC419', 'sumeragi::driver::tests::threaded::retirement_tests::retired_startup_keeps_publication_on_its_original_joiner', 'committed startup retirement must finish publication on its original joiner without blocking another lane', 'crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs', 'crates/iroha_core/src/sumeragi/driver/startup/pending.rs'),
    ('HC420', 'sumeragi::driver::tests::threaded::retirement_tests::final_startup_shutdown_preserves_unpublished_original_store', 'final startup shutdown must stop its admitted job and preserve the original unpublished store', 'crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs', 'crates/iroha_core/src/sumeragi/driver/startup/pending.rs'),
    ('HC421', 'sumeragi::driver::retirement::tests::original_worker_panic_never_authorizes_publication_or_retirement_success', 'a failed original worker join must retain failure and never authorize publication', 'crates/iroha_core/src/sumeragi/driver/retirement/tests.rs', 'crates/iroha_core/src/sumeragi/driver/mod.rs'),
 ])
def test_startup_retirement_publication_mutations_require_exact_original_causes(identifier, selector, cause, source, owner):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    assert rule.tests == (selector,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert gate.has_switch(identifier, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(identifier, **family)
    code = (ROOT / owner).read_text()
    assert code.count(f'sumeragi_core_mutation = "{identifier}"') == 1
    assert f'cfg!(all(test, sumeragi_core_mutation = "{identifier}"))' in code
    controls = (ROOT / source).read_text()
    body = named_rust_function(controls, selector.rsplit("::", 1)[-1])
    assert body.index("budget.reserved_bytes(), 0") < body.index(json.dumps(cause))
    if identifier == "HC419":
        assert "fixture.gate.synchronizer() == Some(joiner)" in body
        assert "Duration::from_secs(1)" in body
        assert "shutdown_startup_for_test(fixture.retired)" in body
    elif identifier == "HC420":
        assert body.index("original.cancel();") < body.index("fixture.gate.release();") < body.index("drop(original);")
    else:
        assert body.index("release.send(())") < body.index("thread.join()") < body.index(json.dumps(cause))
    rows = re.findall(r"^\| " + identifier + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector.rsplit("::", 1)[-1] in rows[0]


@pytest.mark.parametrize("identifier", ["HC419", "HC420", "HC421"])
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_startup_retirement_kills_require_normal_completed_causal_failures(monkeypatch, tmp_path, identifier, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


@pytest.mark.parametrize("identifier,owner,selector,cause,source", [('HC395', 'crates/iroha_core/src/sumeragi/driver/mod.rs', 'sumeragi::driver::retirement::tests::original_joiner_physically_joins_workers_before_running_exact_publication', 'original publication must wait for every successful physical worker join', 'crates/iroha_core/src/sumeragi/driver/retirement/tests.rs'), ('HC414', 'crates/iroha_core/src/sumeragi/lanes/store.rs', 'sumeragi::driver::tests::threaded::retirement_tests::native_driver_binds_original_publication_before_its_first_append', 'native driver readiness must bind its exact funded joining owner before the first append', 'crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs'), ('HC422', 'crates/iroha_core/src/sumeragi/lanes/store.rs', 'sumeragi::lanes::store::owner_tests::native_append_without_original_joiner_refuses_before_any_write_or_tip_change', 'ownerless append must refuse before any native write, retained write or tip mutation', 'crates/iroha_core/src/sumeragi/lanes/store/owner_tests.rs'), ('HC423', 'crates/iroha_core/src/sumeragi/lanes/store.rs', 'sumeragi::driver::tests::threaded::retirement_tests::original_orphan_publication_does_not_block_other_lane_transaction_delivery', "original orphan SyncDir must not block another lane's actual lifecycle turn and transaction commit", 'crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs'), ('HC424', 'crates/iroha_core/src/sumeragi/lanes/store.rs', 'sumeragi::lanes::store::owner_tests::native_owner_binding_refuses_repeated_concurrent_and_foreign_admission', 'a second original joining owner must fail before replacing or acknowledging a bound store', 'crates/iroha_core/src/sumeragi/lanes/store/owner_tests.rs'), ('HC425', 'crates/iroha_core/src/sumeragi/driver/retirement.rs', 'sumeragi::lanes::store::owner_tests::stopped_original_owner_refuses_append_and_stays_bound_until_final_store_release', 'a stopped original publication owner must never admit another append', 'crates/iroha_core/src/sumeragi/lanes/store/owner_tests.rs'), ('HC426', 'crates/iroha_core/src/sumeragi/driver/retirement.rs', 'sumeragi::driver::retirement::tests::retirement_waits_for_every_original_append_permit_before_native_continuation', 'original retirement must wait for every admitted append permit before native continuation', 'crates/iroha_core/src/sumeragi/driver/retirement/tests.rs')])
def test_original_publication_owner_mutations_use_current_causal_boundaries(identifier, owner, selector, cause, source):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    expected_tests = (selector,)
    expected_causes = (gate.ExpectedFailure(cause, source),)
    if identifier == "HC426":
        expected_tests += ("sumeragi::driver::retirement::tests::final_stop_drains_original_append_permit_without_retrying_publication",)
        expected_causes += (gate.ExpectedFailure("final stop must drain every admitted append permit without retrying publication", source),)
    assert rule.tests == expected_tests and not rule.scenarios
    assert rule.causes == expected_causes
    assert gate.has_switch(identifier, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(identifier, **family)
    owners = {path.relative_to(ROOT).as_posix() for path in (ROOT / "crates/iroha_core/src").rglob("*.rs")
        if re.search(r'sumeragi_core_mutation\s*=\s*"' + identifier + '"', path.read_text())}
    assert owners == {owner}
    code = (ROOT / owner).read_text()
    assert code.count(f'sumeragi_core_mutation = "{identifier}"') == (3 if identifier == "HC426" else 2 if identifier == "HC414" else 1)
    controls = (ROOT / source).read_text()
    body = named_rust_function(controls, selector.rsplit("::", 1)[-1])
    assert body.index("budget.reserved_bytes(), 0") < body.index(json.dumps(cause))
    if identifier == "HC395":
        join = named_rust_function(code, "join_workers")
        assert join.index('sumeragi_core_mutation = "HC395"') < join.index("join_original_workers(threads)") < join.index("error.resume()")
        cleanup = (ROOT / "crates/iroha_core/src/sumeragi/driver/worker_panic.rs").read_text()
        physical = named_rust_function(cleanup, "join_original_workers")
        assert physical.index("thread.join()") < physical.index("drop(failures);") < physical.index("\n    first")
        assert "calls.recv_timeout(Duration::from_millis(30))" in body
        executable_body = rust_index.mask(body)
        joined = re.search(r"\blet\s+joined\s*=\s*thread\s*\.\s*join\s*\(\s*\)\s*;", executable_body)
        assert joined is not None
        assert executable_body.index("release.send(())") < joined.start() < body.index(json.dumps(cause))
    elif identifier == "HC423":
        assert "full_turn&&live_handle.status()" in "".join(body.split())
        assert "Duration::from_secs(1)" in body
        assert "publication.original_thread()" in body and "publication.finished()" in body
    elif identifier == "HC414":
        assert "spawn_retiring_store_driver" in body and "store.append(&body, &certificate)" in body
        assert "instance.running.shutdown();" in body and "original.admitted_to(&budget)" in body
    elif identifier == "HC426":
        assert body.index("drop(last);") < body.index("thread.join()") < body.index(json.dumps(cause))
        assert "complete_with_both" in body and "complete_with_last" in body
        final_stop = named_rust_function(controls, "final_stop_drains_original_append_permit_without_retrying_publication")
        assert final_stop.index("drop(original);") < final_stop.index("thread.join()") < final_stop.index("budget.reserved_bytes(), 0")
        assert final_stop.index("budget.reserved_bytes(), 0") < final_stop.index(json.dumps(expected_causes[1].cause))
        assert "rejects_new" in final_stop and "calls_while_held" in final_stop and "!resumed" in final_stop
    rows = re.findall(r"^\| " + identifier + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name.rsplit("::", 1)[-1] in rows[0] for name in expected_tests)


def test_obsolete_map_publication_mutation_is_replaced_by_original_join_ownership():
    assert "HC417" not in gate.index_mutations(gate.CORE_MUTATIONS)
    assert not gate.has_switch("HC417", core=True)
    runner = (ROOT / "crates/iroha_core/src/sumeragi/lanes/runner.rs").read_text()
    assert "!running && !starting" in runner
    controls = (ROOT / "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs").read_text()
    assert "an original pending startup must exclude its publication until every acquired worker is physically joined" in controls
    assert "a still-owned retiring driver must exclude its original pending publication from lifecycle continuation" in controls


@pytest.mark.parametrize("identifier", ["HC422", "HC423", "HC424", "HC425", "HC426"])
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_original_publication_kills_require_completed_named_causal_failure(monkeypatch, tmp_path, identifier, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[identifier]
    rows = [(name, "ok" if defect == "one-passes" and index == 0 else "FAILED") for index, name in enumerate(rule.tests)]
    if defect == "missing-terminal": rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated": output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source": output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort": code = -6
    elif defect == "timeout": code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" and len(rule.tests) == 1 else "error"
    assert result["verdict"] == verdict, result
    if defect == "none": assert result["named"]["causal_failures"] == dict.fromkeys(rule.tests, True)


def test_secondary_worker_panic_mutation_keeps_exact_physical_join_cause():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC427"]
    selector = "sumeragi::driver::retirement::tests::original_worker_panics_keep_secondary_payloads_until_every_physical_join_finishes"
    cause = "secondary panic payloads must remain owned until every original worker physically joins"
    source = "crates/iroha_core/src/sumeragi/driver/retirement/tests.rs"
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert not rule.scenarios and gate.has_switch("HC427", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC427", **family)
    owner = (ROOT / "crates/iroha_core/src/sumeragi/driver/worker_panic.rs").read_text()
    assert owner.count('sumeragi_core_mutation = "HC427"') == 1
    body = named_rust_function(owner, "join_original_workers")
    assert "[Option<OriginalWorkerPanic>; Worker::COUNT]" in body
    assert body.index("thread.join()") < body.index('sumeragi_core_mutation = "HC427"') < body.index("drop(failure);")
    assert body.index("let first =") < body.index("drop(failures);")
    controls = named_rust_function((ROOT / source).read_text(), selector.rsplit("::", 1)[-1])
    assert controls.index("workers.release();") < controls.index("thread.join()") < controls.index("workers.assert_clean();") < controls.index(json.dumps(cause))
    assert "Arc::ptr_eq(error, &workers.original)" in controls
    assert "!completed && append_refused && publication_calls == 0" in controls
    rows = re.findall(r"^\| HC427 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector.rsplit("::", 1)[-1] in rows[0]


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_secondary_worker_panic_kill_requires_completed_causal_failure(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC427"]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


def test_proposal_tip_retirement_mutation_preserves_real_history_and_exact_cause():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC428"]
    selector = "sumeragi::lanes::merge::tests::opening_retirement::abandoned_proposal_tip_releases_original_opening_after_certified_retirement"
    cause = "an abandoned proposal tip must release its original opening after certified retirement"
    source = "crates/iroha_core/src/sumeragi/lanes/merge_tests/opening_retirement.rs"
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert not rule.scenarios and gate.has_switch("HC428", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC428", **family)
    registry = (ROOT / "crates/iroha_core/src/sumeragi/lanes/registry.rs").read_text()
    tip = named_rust_function(registry, "tip")
    assert 'let runtime_owner = !cfg!(all(test, sumeragi_core_mutation = "HC428"));' in tip
    assert "self.store_with_runtime_owner(lane, incarnation, runtime_owner)" in tip
    assert "store.authenticated_height()" in tip
    assert "self.store(lane, incarnation)?.committed_batch(height)" in registry
    assert "self.store(lane, incarnation)?.wait_for(height, timeout)" in registry
    controls = (ROOT / source).read_text()
    native = named_rust_function(controls, selector.rsplit("::", 1)[-1])
    assert "commit_independent_global_work(&mut closed.fixture)" in native
    assert "closed.record.retirement_height()" in native
    assert "Some(closed.frame.len())" in native
    assert native.index("drop((body, certificate, replay, closed));") < native.index("assert_eq!(budget.reserved_bytes(), 0);") < native.index(json.dumps(cause))
    assert "refunded && released_lock" in native
    assert "closed_unhosted_lane_proposal_retries_original_opening_and_preserves_certified_backlog" in controls
    rows = re.findall(r"^\| HC428 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector.rsplit("::", 1)[-1] in rows[0]


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_proposal_tip_retirement_kill_requires_completed_causal_failure(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC428"]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated":
        output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source":
        output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


def test_lane_startup_decode_refusal_mutation_preserves_original_carrier():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC432"]
    selector = "sumeragi::lanes::executor::native_decode_tests::startup_refusal_observation_borrows_the_original_native_recovery_carrier"
    cause = "lane startup must retain its original decode refusal through the public startup projection"
    source = "crates/iroha_core/src/sumeragi/lanes/executor/native_decode_tests.rs"
    assert rule.tests == (selector,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert gate.has_switch("HC432", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC432", **family)
    owner = (ROOT / "crates/iroha_core/src/sumeragi/lanes/executor.rs").read_text()
    assert owner.count('sumeragi_core_mutation = "HC432"') == 1
    assert "Err(AdmissionAttemptError::Deferred(original))" in owner
    assert "return Err(Attempt::Deferred(original.into()));" in owner
    native = named_rust_function((ROOT / source).read_text(), selector.rsplit("::", 1)[-1])
    assert "recovery.original_startup_refusal()" in native
    assert "std::ptr::eq(borrowed, stored)" in native
    assert "original.decode_refusal().is_some()" in native
    assert native.index("drop((lane, fixture));") < native.index("assert_eq!(budget.reserved_bytes(), 0);") < native.index(json.dumps(cause))
    rows = re.findall(r"^\| HC432 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector.rsplit("::", 1)[-1] in rows[0]


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_lane_startup_decode_refusal_kill_requires_completed_cause(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC432"]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal": rows.pop()
    code, output = causal_control_output(rule, rows)
    expected = rule.causes[0]
    if defect == "unrelated": output = output.replace(expected.cause, "unrelated setup refusal", 1)
    elif defect == "wrong-source": output = output.replace(expected.source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort": code = -6
    elif defect == "timeout": code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


PROPOSAL_READ_RULES = (('HC429', 'sumeragi::lanes::registry::tests::proposal_reads::cancelled_proposal_releases_actual_ready_read_and_native_lock_without_another_driver_tick', 'cancelled proposal reads must release original ready custody without successor traffic', 'crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs'), ('HC430', 'sumeragi::lanes::registry::tests::proposal_reads::historical_join_retains_exact_authenticated_body_after_proposal_cancellation', 'historical joining must retain the exact original authenticated proposal read', 'crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs'), ('HC431', 'sumeragi::lanes::registry::tests::proposal_reads::successor_proposal_cannot_consume_live_or_incompatible_original_read', 'a successor proposal must not consume another live or incompatible original read', 'crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs'), ('HC433', 'sumeragi::executor::proposal_read_tests::original_lane_read_request_survives_refusal_busy_state_and_incidental_publication', 'the original lane read request must survive refusal and incidental publication until explicit cancellation', 'crates/iroha_core/src/sumeragi/executor/proposal_read_tests.rs'), ('HC434', 'sumeragi::lanes::store::refund_tests::busy_original_native_operation_inherits_cancelled_read_cleanup_before_returning', 'the original busy native operation must finish cancelled read cleanup before returning', 'crates/iroha_core/src/sumeragi/lanes/store/refund_tests.rs'))

@pytest.mark.parametrize("mid,selector,cause,source", PROPOSAL_READ_RULES)
def test_original_proposal_read_rule_requires_complete_native_custody(mid, selector, cause, source):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mid, **family)
    native = named_rust_function((ROOT / source).read_text(), selector.rsplit("::", 1)[-1])
    assert native.index("assert_eq!(budget.reserved_bytes(), 0);") < native.index(json.dumps(cause))
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("mid,selector,cause,source", PROPOSAL_READ_RULES)
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_original_proposal_read_kill_requires_exact_completed_cause(monkeypatch, tmp_path, mid, selector, cause, source, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal": rows.pop()
    code, output = causal_control_output(rule, rows)
    if defect == "unrelated": output = output.replace(cause, "unrelated fixture failure", 1)
    elif defect == "wrong-source": output = output.replace(source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort": code = -6
    elif defect == "timeout": code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


def test_original_proposal_read_lifecycle_has_one_explicit_owner_and_no_historical_fallback():
    lanes = ROOT / "crates/iroha_core/src/sumeragi/lanes"
    merge = (lanes / "merge.rs").read_text()
    proposal = named_rust_function(merge, "propose")
    assert "request: &mut ProposalReadScope" in proposal
    assert "request.admit(&view.execution_budget())?" in proposal
    assert re.search(r"source\.proposal_block\(\s*record\.lane,\s*&record\.incarnation,\s*lane_height,\s*request,?\s*\)", proposal)
    assert "source.block(" not in proposal
    registry = (lanes / "registry.rs").read_text()
    cleanup = named_rust_function(registry, "clean_cancelled_proposal_reads")
    compact_cleanup = re.sub(r"\s+", "", cleanup)
    assert "Arc::ptr_eq(&original.store,&store)" in compact_cleanup
    assert "Arc::strong_count(&original.store)==2" in compact_cleanup
    assert "store.release_cancelled_reads();" in cleanup and "drop(retired);" in cleanup
    owner = (ROOT / "crates/iroha_core/src/sumeragi/executor/payload_owner.rs").read_text()
    request = owner.split("pub(super) struct ProposalReadRequest", 1)[1].split("}", 1)[0]
    assert "applied: (u64, Hash32)" in request and "generation" not in request
    cancellation = named_rust_function(owner, "cancel_proposal_reads")
    assert cancellation.index("drop(self.proposal_reads.take());") < cancellation.index("release_cancelled_proposal_reads()")
    store = (lanes / "store.rs").read_text()
    cleanup = named_rust_function(store, "release_cancelled_reads")
    assert "self.state.try_lock()" in cleanup and "self.batch_read.try_lock()" in cleanup
    assert cleanup.index("drop((read, batch, observed_read, observed_batch));") > cleanup.index("self.batch_read.try_lock()")
    assert ".same_request(interest)" in cleanup and ".cancelled()" in cleanup


INCOMING_READ_RULES = (('HC435', ('sumeragi::executor::proposal_read_tests::discarded_incoming_execution_releases_its_original_lane_read_after_keep_exclusion',), 'discarded incoming execution must release its own actual lane read without successor traffic', 'crates/iroha_core/src/sumeragi/executor/proposal_read_tests.rs'), ('HC436', ('sumeragi::executor::proposal_read_tests::authenticated_incoming_execution_moves_the_original_local_lane_request_without_reopening',), 'authenticated incoming execution must move the exact original local lane request and continue its native source', 'crates/iroha_core/src/sumeragi/executor/proposal_read_tests.rs'), ('HC437', ('sumeragi::lanes::registry::tests::proposal_reads::cancelled_read_only_incoming_frame_is_released_when_original_inflight_owner_parks',), 'cancelled incoming read-only custody must retire when the original in-flight owner parks', 'crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs'), ('HC438', ('sumeragi::lanes::store::refund_tests::state_read_cancellation_after_cleanup_observation_cannot_be_lost', 'sumeragi::lanes::store::refund_tests::batch_read_cancellation_after_cleanup_observation_cannot_be_lost'), 'cancellation after the original cleanup observation must release that exact read without successor traffic', 'crates/iroha_core/src/sumeragi/lanes/store/refund_tests.rs'), ('HC439', ('sumeragi::lanes::registry::tests::isolation_tests::final_inflight_incoming_opening_cleans_cancelled_request_but_keeps_historical_recovery',), 'the final incoming opening caller must acknowledge cancellation without dropping independent historical recovery', 'crates/iroha_core/src/sumeragi/lanes/registry/isolation_tests.rs'))

@pytest.mark.parametrize("mid,selectors,cause,source", INCOMING_READ_RULES)
def test_incoming_native_read_rule_preserves_exact_completed_custody(mid, selectors, cause, source):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == selectors and not rule.scenarios
    assert rule.causes == tuple(gate.ExpectedFailure(cause, source) for _ in selectors)
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mid, **family)
    native = (ROOT / source).read_text()
    if mid == "HC438":
        function = named_rust_function(native, "cancellation_after_native_cleanup_observation")
        for selector, mode in zip(selectors, ("false", "true")):
            control = named_rust_function(native, selector.rsplit("::", 1)[-1])
            assert "cancellation_after_native_cleanup_observation(" + mode + ");" in control
    else:
        function = named_rust_function(native, selectors[0].rsplit("::", 1)[-1])
    assert function.index("assert_eq!(budget.reserved_bytes(), 0);") < function.index(json.dumps(cause))
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(selector in rows[0] for selector in selectors)

@pytest.mark.parametrize("mid,selectors,cause,source", INCOMING_READ_RULES)
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_incoming_read_mutation_kill_requires_exact_completed_native_cause(monkeypatch, tmp_path, mid, selectors, cause, source, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    rows = [(name, "ok" if defect == "one-passes" else "FAILED") for name in rule.tests]
    if defect == "missing-terminal": rows.pop()
    code, output = causal_control_output(rule, rows)
    if defect == "unrelated": output = output.replace(cause, "unrelated fixture failure", 1)
    elif defect == "wrong-source": output = output.replace(source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort": code = -6
    elif defect == "timeout": code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result


def test_incoming_execution_uses_one_scoped_merge_algorithm_and_explicit_native_cleanup():
    lanes = ROOT / "crates/iroha_core/src/sumeragi/lanes"
    merge = (lanes / "merge.rs").read_text()
    assert merge.count("pub fn expand<'state>(") == 1
    load = named_rust_function(merge, "load")
    assert ".execution_block(" in load and ".execution_wait_for(" in load
    assert ".block(" not in load and ".wait_for(" not in load
    expansion = named_rust_function(merge, "expand_from_view")
    assert "request.admit(&state.ivm_execution_budget())" in re.sub(r"\s+", "", expansion)
    owner = (ROOT / "crates/iroha_core/src/sumeragi/executor/payload_owner.rs").read_text()
    handoff = named_rust_function(owner, "retain_incoming_lane_reads")
    for obligation in ("references_lanes", "self.parent_applied(source)", "request.applied == self.applied", "original.instance != header.instance", "original.height != header.height", "original.view != header.origin_view", "original.block_hash != block_hash"):
        assert obligation in handoff
    assert re.search(r"self\.proposal_reads\s*\.take\(\)", handoff)
    assert ".clone()" not in handoff
    coordinates = owner.split("pub(super) struct IncomingLaneReads {", 1)[1].split("}", 1)[0]
    fields = re.findall(r"pub\(super\) (\w+): ([^,]+),", coordinates)
    assert fields == [("instance", "Hash32"), ("height", "u64"), ("view", "u64"),
                      ("block_hash", "Hash32"), ("scope", "lanes::ProposalReadScope")]
    execution = named_rust_function((ROOT / "crates/iroha_core/src/sumeragi/executor.rs").read_text(), "run_execution_with_finisher")
    assert execution.index("if attempt.source != *block") < execution.index("self.retain_incoming_lane_reads(")
    assert execution.index("block.source().config() != &configured") < execution.index("self.retain_incoming_lane_reads(")
    assert execution.index("proposal_matches_header(") < execution.index("self.retain_incoming_lane_reads(")
    registry = (lanes / "registry.rs").read_text()
    completion = named_rust_function(registry, "complete_store_opening")
    assert completion.index("self.progress_registered_opening(") < completion.index("drop(opening);") < completion.index("self.clean_cancelled_proposal_reads(false)")
    readonly = (lanes / "registry/read_only.rs").read_text()
    parking = readonly.split("impl Drop for OriginalRead", 1)[1].split("/// One retained", 1)[0]
    assert parking.index("self.slot.lock()") < parking.index("read.interest.cancelled()") < parking.index("ReadSlot::Available(self.selected.take())")
    assert parking.index("drop(previous);") < parking.index("drop(cancelled);")


SCCP_MERGED_CUSTODY_RULES = (('HC440', 'HC420', 'smartcontracts/isi/sccp/forgery/execution/event_graph.rs', 'sumeragi/driver/startup/pending.rs', 'smartcontracts::isi::sccp::forgery::execution::event_graph::tests::event_graph_retains_exact_original_layouts_through_publication_and_last_reader', 'event graph retains the original pool', 'smartcontracts/isi/sccp/forgery/execution/event_graph/tests.rs'), ('HC441', 'HC422', 'sumeragi/evidence/sccp_record.rs', 'sumeragi/lanes/store.rs', 'sumeragi::evidence::record::sccp_record::tests::offender_preflight_rejects_each_oversized_graph_before_nested_decode', 'oversized SCCP graph is refused before nested decode', 'sumeragi/evidence/sccp_record/tests.rs'), ('HC442', 'HC424', 'smartcontracts/isi/sccp/forgery/execution.rs', 'sumeragi/lanes/store.rs', 'smartcontracts::isi::sccp::forgery::execution::tests::exact_local_refusal_survives_instruction_mapping_and_protocol_error_does_not_poison', 'local SCCP refusal cannot allocate a replacement diagnostic', 'smartcontracts/isi/sccp/forgery/execution/tests.rs'))


@pytest.mark.parametrize("mid,old_mid,owner,old_owner,selector,cause,source", SCCP_MERGED_CUSTODY_RULES)
def test_sccp_merged_custody_mutations_keep_distinct_native_owners(
    mid, old_mid, owner, old_owner, selector, cause, source
):
    rules = gate.index_mutations(gate.CORE_MUTATIONS)
    rule = rules[mid]
    control_source = "crates/iroha_core/src/" + source
    assert rule.tests == (selector,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, control_source),)
    assert set(rule.tests).isdisjoint(rules[old_mid].tests)
    for reserved in ("HC435", "HC436", "HC437", "HC438", "HC439"):
        assert set(rule.tests).isdisjoint(rules[reserved].tests)
    core = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())}
    assert owners == {owner}
    old_owners = {path.relative_to(core).as_posix() for path in core.rglob("*.rs")
                  if re.search(r'sumeragi_core_mutation\s*=\s*"' + old_mid + '"', path.read_text())}
    assert old_owners == {old_owner}
    assert gate.has_switch(mid, core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mid, **family)
    native = named_rust_function((ROOT / control_source).read_text(), selector.rsplit("::", 1)[-1])
    assert json.dumps(cause) in native
    assert "#[cfg(all(test, sumeragi_core_mutation = \"" + mid + "\"))]" in (core / owner).read_text()
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("mid,old_mid,owner,old_owner,selector,cause,source", SCCP_MERGED_CUSTODY_RULES)
@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "one-passes", "abort", "timeout"])
def test_sccp_merged_custody_mutation_kill_requires_original_named_cause(
    monkeypatch, tmp_path, mid, old_mid, owner, old_owner, selector, cause, source, defect
):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    rows = [(selector, "ok" if defect == "one-passes" else "FAILED")]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    if defect == "unrelated":
        output = output.replace(cause, "unrelated fixture failure", 1)
    elif defect == "wrong-source":
        output = output.replace("crates/iroha_core/src/" + source + ':123:', 'foreign.rs:123:', 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "one-passes" else "error"
    assert result["verdict"] == verdict, result
    if defect == "none":
        assert result["named"]["causal_failures"] == {selector: True}


ORIGINAL_SWEEP_CONTROLS = (('sumeragi::lanes::registry::tests::proposal_reads::cancelled_original_sweep_does_not_wait_for_new_disjoint_opening', 'original cancelled lane cleanup cannot wait for an unrelated newly registered opening'), ('sumeragi::lanes::registry::tests::proposal_reads::original_sweep_preserves_a_later_same_key_native_owner', 'an original lane sweep cannot retire a later same-key registration'))


def test_original_lane_sweep_binds_initial_membership_and_preserves_native_controls():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC443"]
    source = "crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs"
    assert rule.tests == tuple(name for name, _ in ORIGINAL_SWEEP_CONTROLS)
    assert rule.causes == tuple(gate.ExpectedFailure(cause, source) for _, cause in ORIGINAL_SWEEP_CONTROLS)
    assert not rule.scenarios and gate.has_switch("HC443", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC443", **family)
    root = ROOT / "crates/iroha_core/src"
    owners = {path.relative_to(root).as_posix() for path in root.rglob("*.rs")
              if re.search(r'sumeragi_core_mutation\s*=\s*"HC443"', path.read_text())}
    assert owners == {"sumeragi/lanes/registry.rs"}
    registry = (root / "sumeragi/lanes/registry.rs").read_text()
    compact = re.sub(r"\s+", "", registry)
    assert "registrations:AtomicU64" in compact
    registration = named_rust_function(registry, "next_registration")
    assert "last.checked_add(1)" in registration and ".map_err(" in registration
    assert "wrapping" not in registration and "unwrap" not in registration
    assert "MutexGuard" in registration
    capture = re.sub(r"\s+", "", named_rust_function(registry, "original_sweep"))
    assert "letstores=self.stores.lock();" in capture
    assert "(stores.len(),self.registrations.load(Ordering::Relaxed))" in capture
    for function in ("clean_cancelled_proposal_reads", "release_retired", "resume_retired_publications"):
        body = re.sub(r"\s+", "", named_rust_function(registry, function))
        assert "self.original_sweep()" in body and "slot.belongs_to_sweep(watermark)" in body
        assert ".collect" not in body and "Vec::" not in body
    completion = named_rust_function(registry, "progress_registered_opening")
    assert completion.index("Arc::ptr_eq(retained, opening)") < completion.index("owners.registration")
    assert "store: Arc::clone(&store)" in completion
    native = (ROOT / source).read_text()
    for name, cause in ORIGINAL_SWEEP_CONTROLS:
        body = named_rust_function(native, name.rsplit("::", 1)[-1])
        assert body.index("assert_eq!(budget.reserved_bytes(), 0);") < body.index(json.dumps(cause))
    assert "FsStep::CreateDir" in native
    assert "stores.runtime_store(inserted.0,&inserted.1)" in re.sub(r"\s+", "", native)
    assert "stores.release_cancelled_proposal_reads()" in native
    assert "drop(replacement);" in native
    assert "u64::MAX" in named_rust_function(native, "exhausted_registration_identity_refuses_before_new_native_custody")
    rows = re.findall(r"^\| HC443 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and all(name in rows[0] for name, _ in ORIGINAL_SWEEP_CONTROLS)


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "all-pass", "first-passes", "second-passes", "abort", "timeout"])
def test_original_lane_sweep_mutation_requires_both_completed_native_causes(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC443"]
    passing = {"all-pass": {0, 1}, "first-passes": {0}, "second-passes": {1}}.get(defect, set())
    rows = [(name, "ok" if index in passing else "FAILED") for index, name in enumerate(rule.tests)]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    if defect == "unrelated":
        output = output.replace(ORIGINAL_SWEEP_CONTROLS[0][1], "unrelated fixture failure", 1)
    elif defect == "wrong-source":
        output = output.replace("crates/iroha_core/src/sumeragi/lanes/registry/proposal_reads.rs:123:", "foreign.rs:123:", 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(core=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "all-pass" else "error"
    assert result["verdict"] == verdict, result
    if defect in ("none", "first-passes", "second-passes"):
        assert result["named"]["status"] == "fail"
        assert result["named"]["causal_failures"] == {name: index not in passing for index, name in enumerate(rule.tests)}
    if defect in ("first-passes", "second-passes"):
        assert result["reason"] == "named tests: every declared causal control must fail at its exact owned assertion"


def source_observation_fixture(tmp_path, monkeypatch):
    """A minimal source fixture, never a copied checkout or build workspace."""
    source_module = gate._workspace_source

    root = tmp_path / "observed-source"
    root.mkdir()
    def git(*arguments, **kwargs):
        return subprocess.run(["git", *arguments], cwd=root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    git("init", "--quiet")
    git("symbolic-ref", "HEAD", "refs/heads/optimizations")
    (root / "Cargo.lock").write_text("version = 4\n")
    (root / "source.rs").write_text("original source\n")
    git("add", "Cargo.lock", "source.rs")
    # Dirty source is a valid candidate. The manifest binds these actual bytes.
    (root / "source.rs").write_text("the intended dirty candidate\n")
    observations = []
    def observe(_root):
        observations.append("full manifest")
        return source_module.workspace_source_observation(root)
    monkeypatch.setattr(gate, "workspace_source_observation", observe)
    monkeypatch.setattr(gate, "workspace_source_git_state",
                        lambda _root: source_module.workspace_source_git_state(root))
    return root, git, observations


@pytest.mark.parametrize("drift", ["none", "stage-same-source", "bytes", "untracked", "branch", "merge", "conflict"])
def test_campaign_source_binding_surrounds_completed_native_mutation(
    monkeypatch, tmp_path, drift,
):
    root, git, observations = source_observation_fixture(tmp_path, monkeypatch)
    # Retain the real read-only Git runner while the existing native subprocess
    # double owns Popen. The observer still reads actual fixture bytes/index.
    real_run = subprocess.run
    real_popen = subprocess.Popen
    def read_only_run(*args, **kwargs):
        # subprocess.run resolves Popen in its module; isolate only this call.
        with monkeypatch.context() as local:
            local.setattr(subprocess, "Popen", real_popen)
            return real_run(*args, **kwargs)
    source_module = gate._workspace_source
    monkeypatch.setattr(source_module.subprocess, "run", read_only_run)
    target = tmp_path / "target"
    (target / "job0").mkdir(parents=True)
    args = SimpleNamespace()
    baseline = fixture_artifact(args, target / "job0", None)
    mutant = fixture_artifact(args, target / "job0", "SOURCE")
    rule = gate.m("SOURCE", "source receipt control", ["tests::named"])
    monkeypatch.setattr(gate, "MUTATIONS", [rule])
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--fast", "--only", "SOURCE",
                                     "--target-dir", str(target)])
    changed = []
    def native_output(command, options):
        active = options["env"].get("SUMERAGI_MUTATION") == "SOURCE"
        if command[0] == "cargo":
            return artifact_envelopes(mutant if active else baseline)
        if "--list" in command:
            return "tests::named: test\n\n1 test, 0 benchmarks\n"
        if active:
            changed.append(drift)
            if drift == "bytes": (root / "source.rs").write_text("changed during native execution\n")
            elif drift == "untracked": (root / "extra.rs").write_text("new nonignored source\n")
            elif drift == "branch": git("symbolic-ref", "HEAD", "refs/heads/different")
            elif drift == "merge": (root / ".git/MERGE_HEAD").write_text("a" * 40 + "\n")
            elif drift == "conflict":
                blob = git("hash-object", "-w", "--stdin", input=b"original conflict source\n").stdout.decode().strip()
                git("update-index", "--index-info", input=(
                    f"0 {'0' * len(blob)}\tsource.rs\n"
                    f"100644 {blob} 1\tsource.rs\n100644 {blob} 2\tsource.rs\n").encode())
            elif drift == "stage-same-source": git("add", "source.rs")
        status = "FAILED" if active else "ok"
        return (f"running 1 test\ntest tests::named ... {status}\n"
                f"test result: {status}. {0 if active else 1} passed; {1 if active else 0} failed; "
                "0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
    calls = stub_artifact_cargo(monkeypatch, native_output)
    captured_popen = gate.subprocess.Popen
    def popen(command, **options):
        process = captured_popen(command, **options)
        if (command[0] == mutant["executable"] and "--list" not in command
                and options["env"].get("SUMERAGI_MUTATION") == "SOURCE"):
            process.returncode = 101
        return process
    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    valid = drift in ("none", "stage-same-source")
    assert gate.main() == (0 if valid else 1)
    report = json.loads((target / "report.json").read_text())
    assert observations == ["full manifest", "full manifest"]
    assert changed == [drift] and len(calls) == 6
    assert report["baseline"]["verdict"] == "pass"
    assert report["mutations"][0]["named"]["failed"] == ["tests::named"]
    assert report["mutations"][0]["named"]["status"] == "fail"
    assert report["source"]["before"]["branch"] == "refs/heads/optimizations"
    assert report["source"]["before"]["cargo_source_consumption"] == "not_proven"
    assert report["source"]["unchanged"] is valid
    assert report["summary"]["source"] == ("pass" if valid else "error")
    if drift in ("branch", "merge", "conflict"):
        assert report["mutations"][0]["verdict"] == "error"
        assert report["mutations"][0]["execution_verdict"] == "killed_by_test"
    else:
        assert report["mutations"][0]["verdict"] == "killed_by_test"
    if valid:
        assert report["source"]["before"] == report["source"]["after"]
        assert report["source"]["errors"] == []
    else:
        assert report["source"]["errors"]


def test_campaign_refuses_initial_merge_without_running_owned_work(monkeypatch, tmp_path):
    root, _git, observations = source_observation_fixture(tmp_path, monkeypatch)
    (root / ".git/MERGE_HEAD").write_text("a" * 40 + "\n")
    target = tmp_path / "target"
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--fast", "--only", "MX1",
                                     "--target-dir", str(target)])
    monkeypatch.setattr(gate, "evaluate_baseline", lambda *_: pytest.fail("merge cannot build baseline"))
    monkeypatch.setattr(gate, "evaluate", lambda *_: pytest.fail("merge cannot build mutant"))
    assert gate.main() == 1
    report = json.loads((target / "report.json").read_text())
    assert observations == ["full manifest", "full manifest"]
    assert report["source"]["before"] is None and report["source"]["after"] is None
    assert report["summary"]["source"] == "error"
    assert report["summary"]["baseline"] == "error"
    assert report["summary"]["error"] == ["MX1"]
    assert all("active Git operation" in error for error in report["source"]["errors"][:2])
    assert report["source"]["errors"][2] == "work-item source Git state refused: MX1, baseline"


def test_campaign_branch_drift_stops_next_item_without_refreshing_candidate(monkeypatch, tmp_path):
    root, git, observations = source_observation_fixture(tmp_path, monkeypatch)
    target = tmp_path / "target"
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--fast", "--only", "MX1",
                                     "--target-dir", str(target)])
    def baseline(*_args):
        git("symbolic-ref", "HEAD", "refs/heads/replacement")
        return {"id": "baseline", "verdict": "pass"}
    monkeypatch.setattr(gate, "evaluate_baseline", baseline)
    monkeypatch.setattr(gate, "evaluate", lambda *_: pytest.fail("branch drift cannot launch next work item"))
    assert gate.main() == 1
    report = json.loads((target / "report.json").read_text())
    assert observations == ["full manifest", "full manifest"]
    assert report["baseline"]["execution_verdict"] == "pass"
    assert report["baseline"]["verdict"] == "error"
    assert report["mutations"][0]["verdict"] == "error"
    assert report["source"]["before"]["branch"] == "refs/heads/optimizations"
    assert report["source"]["after"]["branch"] == "refs/heads/replacement"


def test_campaign_accepts_stable_detached_ci_observation(monkeypatch, tmp_path):
    state = {"root": str(ROOT), "branch": None}
    monkeypatch.setattr(gate, "workspace_source_git_state", lambda _root: dict(state))
    monkeypatch.setattr(gate, "workspace_source_observation", lambda _root: {
        **state, "workspace_source_manifest_sha256": "b" * 64,
        "cargo_source_consumption": "not_proven"})
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--fast", "--only", "MX1",
                                     "--target-dir", str(tmp_path)])
    monkeypatch.setattr(gate, "evaluate_baseline", lambda *_: {"id": "baseline", "verdict": "pass"})
    monkeypatch.setattr(gate, "evaluate", lambda *_: {"id": "MX1", "verdict": "killed_by_test"})
    assert gate.main() == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["source"]["unchanged"] and report["source"]["before"]["branch"] is None


@pytest.mark.parametrize("returncode,branch", [(1, ""), (2, ""), (0, "refs/tags/foreign")])
def test_workspace_source_git_state_distinguishes_detached_from_failed_git(
    monkeypatch, tmp_path, returncode, branch,
):
    source_module = gate._workspace_source

    root, _git, _observations = source_observation_fixture(tmp_path, monkeypatch)
    real_run = subprocess.run
    def run(command, **kwargs):
        if command[-3:] == ["symbolic-ref", "--quiet", "HEAD"]:
            return subprocess.CompletedProcess(command, returncode, branch, "")
        return real_run(command, **kwargs)
    monkeypatch.setattr(source_module.subprocess, "run", run)
    if returncode == 1:
        assert source_module.workspace_source_git_state(root) == {"root": str(root), "branch": None}
    else:
        with pytest.raises((subprocess.CalledProcessError, RuntimeError)):
            source_module.workspace_source_git_state(root)


def test_gate_import_uses_exact_sibling_source_helper_from_foreign_cwd(tmp_path):
    (tmp_path / "compute_workspace_source_manifest.py").write_text(
        "raise RuntimeError('a foreign helper must never be loaded')\n")
    program = '''
import importlib.util
from pathlib import Path
import sys
import types

sys.path.insert(0, str(Path.cwd()))
sys.modules["compute_workspace_source_manifest"] = types.ModuleType("foreign_source_helper")
sys.modules["sumeragi_workspace_source_manifest"] = types.ModuleType("foreign_cached_helper")
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("gate_from_foreign_cwd", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert module._workspace_source.__file__ == str(path.with_name("compute_workspace_source_manifest.py"))
assert module.workspace_source_observation is module._workspace_source.workspace_source_observation
print("exact sibling loaded")
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program, str(ROOT / "scripts/sumeragi_mutation_gate.py")],
        cwd=tmp_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert completed.stdout == "exact sibling loaded\n" and completed.stderr == ""


def test_seen_git_drift_cannot_pass_after_original_boundary_source_returns(monkeypatch, tmp_path):
    source_module = gate._workspace_source

    root, git, observations = source_observation_fixture(tmp_path, monkeypatch)
    target = tmp_path / "target"
    seen = []
    def observe_git(_root):
        state = source_module.workspace_source_git_state(root)
        if state["branch"] == "refs/heads/replacement":
            seen.append(state)
            git("symbolic-ref", "HEAD", "refs/heads/optimizations")
        return state
    monkeypatch.setattr(gate, "workspace_source_git_state", observe_git)
    monkeypatch.setattr(sys, "argv", ["gate", "--strict", "--fast", "--only", "MX1",
                                     "--target-dir", str(target)])
    def baseline(*_args):
        git("symbolic-ref", "HEAD", "refs/heads/replacement")
        return {"id": "baseline", "verdict": "pass"}
    monkeypatch.setattr(gate, "evaluate_baseline", baseline)
    monkeypatch.setattr(gate, "evaluate", lambda *_: {"id": "MX1", "verdict": "killed_by_test"})
    assert gate.main() == 1
    report = json.loads((target / "report.json").read_text())
    assert observations == ["full manifest", "full manifest"] and len(seen) == 1
    assert report["source"]["before"] == report["source"]["after"]
    assert report["source"]["boundaries_match"] is True
    assert report["source"]["unchanged"] is False
    assert report["summary"]["source"] == "error"
    assert report["baseline"]["execution_verdict"] == "pass"
    assert report["mutations"][0]["verdict"] == "killed_by_test"
    assert report["source"]["errors"] == ["work-item source Git state refused: baseline"]


def test_fastpq_terminal_take_model_mutation_keeps_original_custody_and_owned_control():
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)["DM44"]
    owner = "crates/iroha_data_model/src/fastpq/execution_effect/admitted.rs"
    source = "crates/iroha_data_model/src/fastpq/execution_effect/admitted/tests.rs"
    selector = "fastpq::execution_effect::admitted::tests::completed_tape_take_rejects_prepared_replay_without_reminting_custody"
    cause = "completed FASTPQ tape must refuse prepared replay without minting another graph"
    assert rule.tests == (selector,) and not rule.scenarios
    assert rule.causes == (gate.ExpectedFailure(cause, source),)
    model = ROOT / "crates/iroha_data_model/src"
    owners = {path.relative_to(ROOT).as_posix() for path in model.rglob("*.rs")
              if re.search(r'sumeragi_model_mutation\s*=\s*"DM44"', path.read_text())}
    assert owners == {owner}
    assert gate.has_switch("DM44", model=True)
    for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("DM44", **family)
    model_source = (ROOT / owner).read_text()
    reset = named_rust_function(model_source, "reset")
    compact = re.sub(r"\s+", "", reset)
    assert '#[cfg(not(all(test,sumeragi_model_mutation="DM44")))]' in compact
    assert "ifself.phase==TapePhase::Taken{return;}self.phase=TapePhase::Pending;" in compact
    assert "pub fn finish(&mut self) -> Result<AllocatedFastpqEffectsV1, Error>" in model_source
    assert "Result<AllocatedFastpqEffectsV1, Self>" not in model_source
    native = named_rust_function((ROOT / source).read_text(), selector.rsplit("::", 1)[-1])
    assert json.dumps(cause) in native and "sumeragi_model_mutation" not in native
    assert "decode(&mut workspace, &bytes, &mut pending)" in native
    assert "complete.canonical().effects.as_ptr(), pointer" in native
    assert "pool.reserved_bytes(), 0" in native
    core = (ROOT / "crates/iroha_core/src/query/native_context_archive/fastpq_source/read/decode.rs").read_text()
    complete = re.sub(r"\s+", "", named_rust_function(core, "take_complete"))
    assert "pending.as_mut_slice().last_mut()" in complete
    assert "original.finish().map_err(|_|incomplete())?" in complete
    assert "pending.truncate(pending.as_slice().len()-1)" in complete
    assert "pending.pop()" not in complete
    rows = re.findall(r"^\| DM44 \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("defect", ["none", "unrelated", "wrong-source", "missing-terminal", "survived", "abort", "timeout"])
def test_fastpq_terminal_take_mutation_requires_exact_completed_native_cause(monkeypatch, tmp_path, defect):
    rule = gate.index_mutations(gate.MODEL_MUTATIONS)["DM44"]
    rows = [(rule.tests[0], "ok" if defect == "survived" else "FAILED")]
    if defect == "missing-terminal":
        rows.pop()
    code, output = causal_control_output(rule, rows)
    if defect == "unrelated":
        output = output.replace(rule.causes[0].cause, "unrelated fixture failure", 1)
    elif defect == "wrong-source":
        output = output.replace(rule.causes[0].source + ":123:", "foreign.rs:123:", 1)
    elif defect == "abort":
        code = -6
    elif defect == "timeout":
        code = None
    monkeypatch.setattr(gate, "has_switch", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(gate, "build", lambda *_args: gate.Step(status="pass"))
    selected_cargo_results(monkeypatch, code, output, names=rule.tests)
    result = gate.evaluate(SimpleNamespace(model=True, target_dir=tmp_path, timeout_test=900, fast=False), tmp_path, rule)
    verdict = "killed_by_test" if defect == "none" else "survived" if defect == "survived" else "error"
    assert result["verdict"] == verdict, result
    if defect == "none":
        assert result["named"]["causal_failures"] == {rule.tests[0]: True}


def test_native_socket_row_withholding_has_unique_causal_harness_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC449"]
    owner = "crates/iroha_core/src/sumeragi/node/tests/selective_rs16_tests.rs"
    selector = "sumeragi::node::tests::dataspace_roots::selective_rs16_tests::native_socket_selective_signed_rows_preserve_partial_delivery_and_original_paid_recovery"
    cause = "selected original row deprivation must prevent native Apply"
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, owner),)
    assert not rule.scenarios and gate.has_switch("HC449", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC449", **family)
    owners = {path.relative_to(ROOT).as_posix() for path in (ROOT / "crates/iroha_core/src").rglob("*.rs")
              if 'sumeragi_core_mutation = "HC449"' in path.read_text()}
    assert owners == {owner}
    source = (ROOT / owner).read_text()
    assert 'cfg!(all(test, sumeragi_core_mutation = "HC449"))' in source
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in source
    assert cause in source
    assert "| HC449 |" in (ROOT / "specs/sumeragi.md").read_text()


def test_penalty_registration_lookup_mutation_uses_original_key_control():
    rule = gate.index_mutations(gate.CORE_MUTATIONS)["HC444"]
    owner = "crates/iroha_core/src/sumeragi/penalties/key_custody_tests.rs"
    selector = "sumeragi::penalties::tests::validator_registration_lookup_borrows_original_single_and_multisig_keys_without_allocation"
    cause = "penalty registration lookup must borrow the exact funded key without replacement allocation"
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, owner),)
    assert not rule.scenarios and gate.has_switch("HC444", core=True)
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch("HC444", **family)
    source = (ROOT / "crates/iroha_core/src/sumeragi/penalties.rs").read_text()
    assert '#[cfg(all(test, sumeragi_core_mutation = "HC444"))]' in source
    assert "let key = &self.registration_key.clone();" in source
    controls = (ROOT / owner).read_text()
    assert "fn " + selector.rsplit("::", 1)[1] + "(" in controls
    assert cause in controls


def test_penalty_sort_and_lane_wake_mutations_have_distinct_hooks_and_controls():
    registered = gate.index_mutations(gate.CORE_MUTATIONS)
    ordering = registered["HC445"]
    wake = registered["HC405"]
    penalty_owner = "crates/iroha_core/src/sumeragi/penalties.rs"
    lane_owner = "crates/iroha_core/src/sumeragi/lanes/runner/startup.rs"
    assert ordering.tests == (
        "sumeragi::penalties::tests::canonical_action_order_deduplicates_without_allocator_scratch",
    )
    assert ordering.causes == (gate.ExpectedFailure(
        "canonical penalty sorting must not allocate stable-sort scratch", penalty_owner,
    ),)
    assert wake.tests == (
        "sumeragi::driver::tests::threaded::retirement_tests::ready_transfer_reissues_consumed_transaction_wake_to_original_workers",
    )
    assert wake.causes == (gate.ExpectedFailure(
        "Ready transfer must redeliver the consumed transaction wake to the original workers",
        "crates/iroha_core/src/sumeragi/driver/tests/threaded_retirement.rs",
    ),)
    owners = {"HC405": set(), "HC445": set()}
    for path in (ROOT / "crates/iroha_core/src").rglob("*.rs"):
        for mid in re.findall(r'sumeragi_core_mutation\s*=\s*"(HC405|HC445)"', path.read_text()):
            owners[mid].add(path.relative_to(ROOT).as_posix())
    assert owners == {"HC405": {lane_owner}, "HC445": {penalty_owner}}
    source = (ROOT / penalty_owner).read_text()
    assert '#[cfg(all(test, sumeragi_core_mutation = "HC445"))]\n    actions.sort();' in source
    assert '#[cfg(not(all(test, sumeragi_core_mutation = "HC445")))]\n    actions.sort_unstable();' in source
    for mid in owners:
        assert gate.has_switch(mid, core=True)
        assert not registered[mid].scenarios


def test_native_penalty_action_model_custody_controls_are_unique_and_causal():
    controls = {
        "DM45": ("penalty_action_owner_preserves_sole_wire_schema_json_and_original_shared_graph", "admitted penalty action clone must retain the original graph", "crates/iroha_data_model/src/consensus/penalty_actions.rs"),
        "DM46": ("penalty_action_source_binds_full_original_frame_pool_and_layout", "penalty action custody must bind the full original source", "crates/iroha_data_model/src/consensus/penalty_actions/prepared.rs"),
        "DM47": ("penalty_action_original_partial_refusal_retains_exact_prefix_pool_and_retry", "partial penalty retry must retain exact original refusal and release cut", "crates/iroha_data_model/src/consensus/penalty_actions/prepared.rs"),
    }
    cause_source = "crates/iroha_data_model/src/consensus/penalty_actions/prepared/tests.rs"
    rules = gate.index_mutations(gate.MODEL_MUTATIONS)
    assert set(rules) == set(MODEL_NAMES)
    build = (gate.REPO / "crates/iroha_data_model/build.rs").read_text()
    assert tuple(re.findall(r'"(DM\d+)"', build.split("const IDS:", 1)[1].split(";", 1)[0])) == tuple(MODEL_NAMES)
    for identity, (test, cause, owner) in controls.items():
        rule = rules[identity]
        assert rule.tests == ("consensus::penalty_actions::prepared::tests::" + test,)
        assert rule.causes == (gate.ExpectedFailure(cause, cause_source),)
        assert not rule.scenarios and gate.has_switch(identity, model=True)
        for family in ({}, {"core": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
            assert not gate.has_switch(identity, **family)
        owners = {path.relative_to(gate.REPO).as_posix() for path in (gate.REPO / "crates/iroha_data_model/src").rglob("*.rs") if f'sumeragi_model_mutation = "{identity}"' in path.read_text()}
        assert owners == {owner}
        assert cause in (gate.REPO / cause_source).read_text()
        assert "fn " + test + "(" in (gate.REPO / cause_source).read_text()
        assert f"| {identity} |" in (gate.REPO / "specs/sumeragi.md").read_text()


@pytest.mark.parametrize("mid,name,cause", [
    ("HC446", "change_intent_matches_complete_stream_but_cannot_emit_a_snapshot", "change-only original capture must refuse complete snapshot delivery before callbacks"),
    ("HC447", "change_intent_ignores_untouched_native_rows_and_replays_exact_original_changes", "change capture must inspect only original touched native rows"),
    ("HC448", "change_capture_refusal_retains_original_partial_frame_through_retry_and_refund", "change capture retry must retain its original partial key frame"),
])
def test_original_change_capture_mutations_bind_native_custody_controls(mid, name, cause):
    source_owner = "crates/iroha_core/src/state/authority_registry/complete/original_stream.rs"
    test_owner = "crates/iroha_core/src/state/authority_registry/complete/original_stream/changes_tests.rs"
    selector = "state::authority_registry::complete::original_stream::tests::" + name
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, test_owner),)
    assert not rule.scenarios and gate.has_switch(mid, core=True)
    owners = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "crates/iroha_core/src").rglob("*.rs")
        if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())
    }
    assert owners == {source_owner}
    for family in ({}, {"model": True}, {"daemon": True}, {"sdk": True}, {"deploy": True}, {"torii": True}, {"norito": True}, {"p2p": True}):
        assert not gate.has_switch(mid, **family)
    controls = (ROOT / test_owner).read_text()
    assert "fn " + name + "(" in controls and cause in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("mid,selector,cause,test_owner,source_owner", [
    ('HC454', 'state::authority_registry::complete::original_stream::tests::membership_delta_capacity_refusal_keeps_original_key_base_cause_and_refund', 'membership retry must retain the exact original partial-key capacity cause', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/membership_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/membership.rs'),
    ('HC450', 'state::storage_transactions::authority::tests::paired_publication_delta_recreates_exact_advance_replace_repeat_and_empty_cuts', 'original rollback delta must recreate exact successor pair', 'crates/iroha_core/src/state/storage_transactions/authority/delta_tests.rs', 'crates/iroha_core/src/state/storage_transactions.rs'),
    ('HC451', 'state::storage_transactions::authority::tests::paired_publication_delta_requires_exact_original_surface_before_visitation', 'membership delta must reject a substituted original publication surface', 'crates/iroha_core/src/state/storage_transactions/authority/delta_tests.rs', 'crates/iroha_core/src/state/storage_transactions/authority.rs'),
    ('HC452', 'state::authority_registry::complete::original_stream::tests::membership_delta_base_refusal_precedes_every_change_and_retains_original_retry', 'membership base refusal must precede every original change callback', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/membership_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream.rs'),
    ('HC453', 'state::authority_registry::complete::original_stream::tests::change_membership_capture_uses_only_delta_sets_and_recreates_complete_pair', 'membership change capture must avoid complete history scans', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/membership_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/membership.rs'),
 ])
def test_paired_membership_delta_mutations_bind_exact_original_native_controls(mid, selector, cause, test_owner, source_owner):
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, test_owner),)
    assert not rule.scenarios and gate.has_switch(mid, core=True)
    owners = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "crates/iroha_core/src").rglob("*.rs")
        if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())
    }
    assert owners == {source_owner}
    all_rules = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS,
                 *gate.SDK_MUTATIONS, *gate.DEPLOY_MUTATIONS, *gate.TORII_MUTATIONS,
                 *gate.NORITO_MUTATIONS, *gate.P2P_MUTATIONS]
    assert len(gate.index_mutations(all_rules)) == len(all_rules)
    controls = (ROOT / test_owner).read_text()
    assert "fn " + selector.rsplit("::", 1)[-1] + "(" in controls and cause in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


@pytest.mark.parametrize("mid,selector,cause,test_owner,source_owner", [
    ('HC455', 'state::authority_registry::complete::original_stream::tests::untouched_cell_delta_keeps_original_identity_without_value_work_or_credit', 'untouched cell change capture must admit no value work or credit', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/cell_policy_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream.rs'),
    ('HC456', 'state::authority_registry::complete::original_stream::tests::unchanged_policy_delta_skips_projection_scratch_with_exhausted_original_pool', 'unchanged policies must skip borrowed projection scratch before allocation', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/cell_policy_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream.rs'),
    ('HC457', 'state::authority_registry::complete::original_stream::tests::runtime_catalog_touch_keeps_manifest_preimage_and_refuses_foreign_binding', 'runtime catalog touches must retain original manifest preimage', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/cell_policy_delta_tests.rs', 'crates/iroha_core/src/state/authority_registry/complete/original_stream/policies.rs'),
 ])
def test_cell_policy_delta_mutations_keep_exact_source_and_causal_controls(mid, selector, cause, test_owner, source_owner):
    all_rules = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS,
                 *gate.SDK_MUTATIONS, *gate.DEPLOY_MUTATIONS, *gate.TORII_MUTATIONS,
                 *gate.NORITO_MUTATIONS, *gate.P2P_MUTATIONS]
    assert len(gate.index_mutations(all_rules)) == len(all_rules)
    rule = gate.index_mutations(gate.CORE_MUTATIONS)[mid]
    assert rule.tests == (selector,)
    assert rule.causes == (gate.ExpectedFailure(cause, test_owner),)
    assert not rule.scenarios and gate.has_switch(mid, core=True)
    owners = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "crates/iroha_core/src").rglob("*.rs")
        if re.search(r'sumeragi_core_mutation\s*=\s*"' + mid + '"', path.read_text())
    }
    assert owners == {source_owner}
    controls = (ROOT / test_owner).read_text()
    assert "fn " + selector.rsplit("::", 1)[-1] + "(" in controls and cause in controls
    rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
    assert len(rows) == 1 and selector in rows[0]


def test_field5_penalty_custody_mutations_have_unique_original_owners_and_causal_controls():
    controls = (('DM48', 'block::prepared_signatures::tests::penalty_action_tests::field5_penalty_actions_keep_canonical_wire_and_original_shared_graph', 'field 5 must retain the original admitted action graph', 'crates/iroha_data_model/src/block/prepared_signatures/tests/penalty_action_tests.rs', 'crates/iroha_data_model/src/block/prepared_signatures.rs'), ('DM49', 'block::prepared_signatures::tests::penalty_action_tests::field5_penalty_refusal_retains_original_prefix_pool_and_exact_retry', 'field 5 retry must retain the original partial action owner and release cut', 'crates/iroha_data_model/src/block/prepared_signatures/tests/penalty_action_tests.rs', 'crates/iroha_data_model/src/block/prepared_signatures.rs'), ('HC458', 'sumeragi::executor::decoded_custody_tests::same_wire_distinct_action_owner_is_refused_at_original_lend_and_validation_return', 'same-wire action substitution must fail original lend', 'crates/iroha_core/src/sumeragi/executor_decoded_custody_tests.rs', 'crates/iroha_core/src/sumeragi/executor.rs'), ('HC459', 'execution_attempt::prepared_penalty_action_attempt_retains_exact_capacity_and_allocator_causes', 'field 5 must preserve the exact original capacity cause', 'crates/iroha_core/src/execution_attempt.rs', 'crates/iroha_core/src/execution_attempt.rs'))
    all_rules = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS,
                 *gate.SDK_MUTATIONS, *gate.DEPLOY_MUTATIONS, *gate.TORII_MUTATIONS,
                 *gate.NORITO_MUTATIONS, *gate.P2P_MUTATIONS]
    assert len(gate.index_mutations(all_rules)) == len(all_rules)
    for mid, selector, cause, test_owner, source_owner in controls:
        model = mid.startswith("DM")
        rules = gate.MODEL_MUTATIONS if model else gate.CORE_MUTATIONS
        rule = gate.index_mutations(rules)[mid]
        assert rule.tests == (selector,)
        assert rule.causes == (gate.ExpectedFailure(cause, test_owner),)
        assert not rule.scenarios and gate.has_switch(mid, **({"model": True} if model else {"core": True}))
        family = "model" if model else "core"
        folder = ROOT / ("crates/iroha_data_model/src" if model else "crates/iroha_core/src")
        owners = {path.relative_to(ROOT).as_posix() for path in folder.rglob("*.rs")
                  if re.search(r"sumeragi_" + family + r'_mutation\s*=\s*"' + mid + '"', path.read_text())}
        assert owners == {source_owner}
        controls_source = (ROOT / test_owner).read_text()
        assert "fn " + selector.rsplit("::", 1)[-1] + "(" in controls_source and cause in controls_source
        rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
        assert len(rows) == 1 and selector in rows[0]
        if model:
            assert MODEL_NAMES[mid] == selector
    build = (ROOT / "crates/iroha_data_model/build.rs").read_text()
    assert tuple(re.findall(r'"(DM\d+)"', build.split("const IDS:", 1)[1].split(";", 1)[0])) == tuple(MODEL_NAMES)


def test_parent_qc_custody_mutations_have_unique_owners_and_causal_controls():
    controls = (('DM50', 'consensus::parent_service::prepared::tests::parent_service_owner_keeps_vec_wire_json_and_exact_admitted_clone', 'parent-QC clone must retain the original immutable byte owner', 'crates/iroha_data_model/src/consensus/parent_service/tests.rs', 'crates/iroha_data_model/src/consensus/parent_service.rs'), ('DM51', 'consensus::parent_service::prepared::tests::parent_service_source_and_capacity_retry_preserve_original_full_frame_pool_and_layout', 'parent-QC custody must bind bytes outside the selected field', 'crates/iroha_data_model/src/consensus/parent_service/tests.rs', 'crates/iroha_data_model/src/consensus/parent_service/prepared.rs'), ('DM52', 'block::prepared_signatures::tests::parent_service_tests::field5_parent_service_survives_later_action_refusal_with_exact_original_cut_and_retry', 'outer retry must retain parent-QC custody and original release cut', 'crates/iroha_data_model/src/block/prepared_signatures/tests/parent_service_tests.rs', 'crates/iroha_data_model/src/block/prepared_signatures.rs'), ('HC460', 'sumeragi::executor::decoded_custody_tests::same_wire_parent_qc_substitution_preserving_actions_and_signatures_is_refused_at_both_boundaries', 'same-wire parent-QC substitution must fail original lend', 'crates/iroha_core/src/sumeragi/executor_decoded_custody_tests.rs', 'crates/iroha_core/src/sumeragi/executor.rs'), ('HC461', 'execution_attempt::prepared_parent_service_attempt_preserves_original_capacity_and_allocator_fields', 'parent-QC decode must retain its original capacity cause', 'crates/iroha_core/src/execution_attempt.rs', 'crates/iroha_core/src/execution_attempt.rs'))
    all_rules = [*gate.MUTATIONS, *gate.CORE_MUTATIONS, *gate.DAEMON_MUTATIONS, *gate.MODEL_MUTATIONS,
                 *gate.SDK_MUTATIONS, *gate.DEPLOY_MUTATIONS, *gate.TORII_MUTATIONS,
                 *gate.NORITO_MUTATIONS, *gate.P2P_MUTATIONS]
    assert len(gate.index_mutations(all_rules)) == len(all_rules)
    for mid, selector, cause, test_owner, source_owner in controls:
        model = mid.startswith("DM")
        rules = gate.MODEL_MUTATIONS if model else gate.CORE_MUTATIONS
        rule = gate.index_mutations(rules)[mid]
        assert rule.tests == (selector,)
        assert rule.causes == (gate.ExpectedFailure(cause, test_owner),)
        assert not rule.scenarios and gate.has_switch(mid, **({"model": True} if model else {"core": True}))
        family = "model" if model else "core"
        folder = ROOT / ("crates/iroha_data_model/src" if model else "crates/iroha_core/src")
        owners = {path.relative_to(ROOT).as_posix() for path in folder.rglob("*.rs")
                  if re.search(r"sumeragi_" + family + r'_mutation\s*=\s*"' + mid + '"', path.read_text())}
        assert owners == {source_owner}
        controls_source = (ROOT / test_owner).read_text()
        assert "fn " + selector.rsplit("::", 1)[-1] + "(" in controls_source and cause in controls_source
        rows = re.findall(r"^\| " + mid + r" \|.*$", (ROOT / "specs/sumeragi.md").read_text(), re.M)
        assert len(rows) == 1 and selector in rows[0]
        if model:
            assert MODEL_NAMES[mid] == selector
    build = (ROOT / "crates/iroha_data_model/build.rs").read_text()
    assert tuple(re.findall(r'"(DM\d+)"', build.split("const IDS:", 1)[1].split(";", 1)[0])) == tuple(MODEL_NAMES)
