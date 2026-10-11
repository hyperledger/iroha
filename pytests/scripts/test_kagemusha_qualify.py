"""Qualification rejects missing evidence, cherry-picking and cap overruns."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import random
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "kagemusha_qualify.py"
SPEC = importlib.util.spec_from_file_location("kagemusha_qualify", SCRIPT)
assert SPEC and SPEC.loader
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)


def report(cpu=25, wall=8, rss=700_000_000, workers=1):
    return {
        "schema": "kagemusha.m3.process.v1", "workers": workers,
        "binary_sha256": "ab" * 32, "witness_api": "owned",
        "coset_cache": "on_demand", "commitment_tables": False,
        "quotient_workspace": "caller_owned", "quotient_workspace_budget_bytes": 256 << 20,
        "quotient_workspace_allocated_bytes": 128 << 20,
        "msm_process_budget_bytes": 64 << 20,
        "msm_process_peak_bytes": 1 << 20, "msm_process_retained_bytes": 0,
        "transcript_profile": "pipa-r", "gate": "G3.6/q_exact_shape", "k": 16, "shape": "test-shape", "seed": 7,
        "descriptor_digest": "cd" * 32, "descriptor_hash": "blake2b256-pipa-v2-circdesc",
        "peak_rss_source": "kernel_lifetime_high_water", "peak_rss_bytes": rss,
        "thermal_before": "nominal", "thermal_after": "nominal",
        "samples": [
            {"index": i, "cpu_ns": int(cpu * 1e9), "total_ns": int(wall * 1e9),
             "quotient_workspace_before_bytes": 0 if i == 0 else 128 << 20,
             "quotient_workspace_after_bytes": 128 << 20,
             "verified": True, "thermal_before": "nominal", "thermal_after": "nominal"}
            for i in range(2)
        ],
    }


def attempts(value=None):
    value = value or report()
    return [{"block": block, "report": deepcopy(value), "reasons": []}
            for block in range(3) for _ in range(3)]


def test_all_nine_processes_and_each_block_median_are_required():
    rows = attempts()
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)["status"] == "pass"
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows[:8])["status"] == "inconclusive"
    rows[0]["block"] = 1
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)["status"] == "inconclusive"


def test_single_hard_failure_cannot_be_hidden_by_median_or_faster_second_proof():
    rows = attempts()
    rows[4]["report"]["samples"][0]["cpu_ns"] = 30_000_000_001
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)["status"] == "fail"
    rows = attempts()
    rows[4]["report"]["peak_rss_bytes"] = int(0.75 * qualify.GIB) + 1
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)["status"] == "fail"


def test_headroom_misses_are_borderline_and_every_block_matters():
    rows = attempts()
    for index in (3, 4):
        rows[index]["report"] = report(cpu=28)
    result = qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)
    assert result["block_medians_seconds"] == [25, 28, 25]
    assert result["status"] == "borderline"
    rows = attempts(report(rss=int(0.73 * qualify.GIB)))
    assert qualify.verdict(qualify.CONFIGS["q_chips-1"], rows)["status"] == "borderline"


@pytest.mark.parametrize("name", ["q_chips-1", "q_chips-4", "a_chips-1", "a_chips-4"])
def test_rss_headroom_uses_each_block_median_but_caps_every_process(name):
    config = qualify.CONFIGS[name]
    hard = int((0.75 if name.startswith("q") else 0.85) * qualify.GIB)
    below_margin, above_margin = int(hard * 0.94), int(hard * 0.99)
    rows = attempts(report(rss=below_margin, workers=config["workers"]))
    for index in (2, 5, 8):
        rows[index]["report"]["peak_rss_bytes"] = above_margin
    result = qualify.verdict(config, rows)
    assert result["status"] == "pass"
    assert result["block_medians_rss_bytes"] == [below_margin] * 3
    assert result["maximum_kernel_rss_bytes"] == above_margin
    assert result["all_process_rss_bytes"] == [below_margin, below_margin, above_margin] * 3

    # A single block without the specified headroom is borderline, even if
    # its median remains below the hard cap and the other blocks are better.
    rows[7]["report"]["peak_rss_bytes"] = above_margin
    result = qualify.verdict(config, rows)
    assert result["status"] == "borderline"
    assert result["block_medians_rss_bytes"] == [below_margin, below_margin, above_margin]

    # Restore a passing median; one hard-cap breach still fails the candidate.
    rows[7]["report"]["peak_rss_bytes"] = below_margin
    rows[8]["report"]["peak_rss_bytes"] = hard + 1
    assert qualify.verdict(config, rows)["status"] == "fail"


def test_four_worker_observed_wall_is_never_cpu_divided_by_four():
    rows = attempts(report(cpu=20, wall=10.1, workers=4))
    assert qualify.verdict(qualify.CONFIGS["q_chips-4"], rows)["status"] == "fail"
    # A4 has a memory gate and diagnostic elapsed time, no invented time cap.
    rows = attempts(report(cpu=80, wall=40, workers=4))
    assert qualify.verdict(qualify.CONFIGS["a_exact-4"], rows)["status"] == "pass"


def test_invalid_samples_are_retained_but_cannot_supply_a_passing_count():
    rows = attempts()
    rows[2]["reasons"] = ["thermal state unavailable"]
    assert qualify.verdict(qualify.CONFIGS["q_exact-1"], rows)["status"] == "inconclusive"
    rows.append({"block": 0, "report": report(), "reasons": []})
    result = qualify.verdict(qualify.CONFIGS["q_exact-1"], rows)
    assert result["status"] == "pass"
    assert result["attempts"] == 10
    assert result["valid_processes"] == 9


def test_probe_errors_wrong_api_wrong_pool_and_unverified_proofs_invalidate():
    candidate = {"binary_sha256": "ab" * 32, "layouts": {
        "G3.6/q_exact_shape": {key: report()[key] for key in
            ("gate", "k", "shape", "descriptor_digest", "descriptor_hash")}
    }}
    config = qualify.CONFIGS["q_exact-1"]
    assert not qualify.report_reasons(report(), config, candidate, 7)
    for field, bad in [
        ("workers", 4), ("binary_sha256", "different"), ("witness_api", "borrowed"),
        ("peak_rss_bytes", 0), ("peak_rss_source", "sampled"),
        ("msm_process_budget_bytes", None), ("thermal_after", "unavailable"),
        ("quotient_workspace", "fresh"), ("quotient_workspace_budget_bytes", 1 << 30),
        ("quotient_workspace_allocated_bytes", 0), ("quotient_workspace_allocated_bytes", (256 << 20) + 1),
        ("msm_process_peak_bytes", (64 << 20) + 1), ("msm_process_retained_bytes", 1),
        ("gate", "G3.6/q_leaf_chips"), ("k", 15), ("shape", "other"), ("seed", 8),
        ("descriptor_digest", "different"), ("descriptor_hash", "sha256"),
        ("samples", None), ("samples", [None]),
    ]:
        value = report()
        value[field] = bad
        assert qualify.report_reasons(value, config, candidate, 7), field
    for field, bad in [("cpu_ns", 0), ("cpu_ns", -1), ("verified", False), ("index", 2)]:
        value = report()
        value["samples"][0][field] = bad
        assert qualify.report_reasons(value, config, candidate, 7), field


def test_calibration_uses_both_direct_metrics_with_no_normalization():
    assert not qualify.calibration_reasons(report(cpu=20, wall=10), report(cpu=21, wall=10.5))
    assert qualify.calibration_reasons(report(cpu=20), report(cpu=21.01))
    assert qualify.calibration_reasons(report(wall=10), report(wall=10.51))


def test_report_parser_requires_one_complete_known_record():
    text = "test ignored ... " + qualify.PREFIX + json.dumps(report()) + "\nok\n"
    assert qualify.parse_report(text) == report()
    for bad in ("", text + text, qualify.PREFIX + "[]", qualify.PREFIX + "{}"):
        with pytest.raises(ValueError):
            qualify.parse_report(bad)


def test_vm_counters_require_complete_valid_evidence():
    text = "Compressions: 123.\nPageouts: 0.\nSwapouts: 2.\nSwapins: 3.\n"
    assert qualify.parse_vm_stat(text) == {"Compressions": 123, "Pageouts": 0, "Swapouts": 2, "Swapins": 3}
    with pytest.raises(ValueError):
        qualify.parse_vm_stat("Compressions: 0.\n")
    before = environment_fixture()
    before["raw"]["vm"]["stdout"] = text
    assert not qualify.environment_reasons(before, deepcopy(before))
    after = deepcopy(before)
    after["raw"]["vm"]["stdout"] = text.replace("123", "124")
    assert qualify.environment_reasons(before, after)
    # Existing counters are not a rejection; failed probes still invalidate.
    after = deepcopy(before)
    after["raw"]["pressure"]["code"] = 1
    assert qualify.environment_reasons(before, after)


def test_swapins_alone_are_diagnostic_under_the_declared_memory_policy():
    before = environment_fixture()
    after = deepcopy(before)
    after["raw"]["vm"]["stdout"] = after["raw"]["vm"]["stdout"].replace("Swapins: 3.", "Swapins: 999.")
    assert not qualify.environment_reasons(before, after)


@pytest.mark.parametrize("counter", qualify.QUIET_MEMORY_COUNTERS)
def test_every_required_quiet_memory_counter_invalidates_on_increase(counter):
    before = environment_fixture()
    after = deepcopy(before)
    value = qualify.environment_counters(before)[counter]
    after["raw"]["vm"]["stdout"] = after["raw"]["vm"]["stdout"].replace(
        f"{counter}: {value}.", f"{counter}: {value + 1}.",
    )
    assert qualify.environment_reasons(before, after) == [f"memory counter changed: {counter}"]


@pytest.mark.parametrize("counter", (*qualify.QUIET_MEMORY_COUNTERS, "Swapins"))
def test_counter_reset_invalidates_even_diagnostic_evidence(counter):
    before = environment_fixture()
    before["raw"]["vm"]["stdout"] = "".join(
        f"{label}: 10.\n" for label in (*qualify.QUIET_MEMORY_COUNTERS, "Swapins")
    )
    after = deepcopy(before)
    after["raw"]["vm"]["stdout"] = after["raw"]["vm"]["stdout"].replace(
        f"{counter}: 10.", f"{counter}: 9.",
    )
    assert qualify.environment_reasons(before, after) == [f"memory counter decreased: {counter}"]


def environment_fixture():
    outputs = {
        "pressure": "1\n", "vm": "Compressions: 123.\nPageouts: 0.\nSwapouts: 2.\nSwapins: 3.\n",
        "power": "AC Power:\n lowpowermode 0\n", "source": "Now drawing from 'AC Power'\n",
        "load": "{ 4.25 3.00 2.50 }\n",
    }
    return {"platform": "darwin", "raw": {
        name: {"code": 0, "stdout": output, "stderr": ""} for name, output in outputs.items()
    }}


@pytest.mark.parametrize("power", [
    "unavailable\n", "AC Power:\n", "Battery Power:\n lowpowermode 0\n",
    "AC Power:\n lowpowermode 0\nAC Power:\n lowpowermode 0\n",
    "AC Power:\n lowpowermode 0\n lowpowermode 0\n",
    "AC Power:\n lowpowermode unknown\n",
])
def test_power_probe_requires_an_unambiguous_active_profile(power):
    before = environment_fixture()
    before["raw"]["power"]["stdout"] = power
    assert qualify.environment_reasons(before, deepcopy(before))


@pytest.mark.parametrize("source", [
    "AC Power unavailable\n", "Now drawing from 'Battery Power'\nAC Power\n",
    "Now drawing from 'AC Power'\nNow drawing from 'Battery Power'\n",
])
def test_power_source_requires_the_actual_unique_ac_header(source):
    before = environment_fixture()
    before["raw"]["source"]["stdout"] = source
    assert qualify.environment_reasons(before, deepcopy(before))


def test_only_the_active_ac_low_power_setting_controls_qualification():
    before = environment_fixture()
    before["raw"]["power"]["stdout"] = (
        "Battery Power:\n lowpowermode 1\nAC Power:\n lowpowermode 0\n"
    )
    assert qualify.environment_reasons(before, deepcopy(before)) == []
    before["raw"]["power"]["stdout"] = (
        "Battery Power:\n lowpowermode 0\nAC Power:\n lowpowermode 1\n"
    )
    assert qualify.environment_reasons(before, deepcopy(before))


def test_recognized_ac_profile_without_optional_low_power_capability_is_supported():
    before = environment_fixture()
    # The retained qualification host reports this multiword key and ordinary
    # AC settings, without exposing a lowpowermode capability.
    before["raw"]["power"]["stdout"] = (
        "AC Power:\n Sleep On Power Button 1\n sleep 0\n displaysleep 10\n"
    )
    assert qualify.environment_reasons(before, deepcopy(before)) == []


def observation_fixture(value):
    return {"seed": value["seed"], "report": deepcopy(value), "reasons": [],
            "process": {"code": 0, "stdout": qualify.PREFIX + json.dumps(value), "stderr": ""},
            "before": environment_fixture(), "after": environment_fixture()}


def refresh_raw(observation):
    observation["process"]["stdout"] = qualify.PREFIX + json.dumps(observation["report"])


def ledger_fixture():
    candidate = {"binary_sha256": "ab" * 32, "source_sha256": "ef" * 32, "layouts": {},
                 "memory_activity_policy": qualify.MEMORY_ACTIVITY_POLICY, "source_policy": qualify.SOURCE_POLICY,
                 "source_scope": {"kind": "cargo_component"}}
    configs = {}
    for name, config in qualify.CONFIGS.items():
        layout = {key: report()[key] for key in
                  ("k", "shape", "descriptor_digest", "descriptor_hash", "transcript_profile")}
        layout["gate"] = config["gate"]
        candidate["layouts"][config["gate"]] = layout
        rows = attempts(report(workers=config["workers"]))
        for seed, row in enumerate(rows):
            row["seed"] = seed
            row["report"].update(layout)
            row["report"]["seed"] = seed
        configs[name] = rows
    for name, rows in configs.items():
        config = qualify.CONFIGS[name]
        calibration = qualify.CONFIGS[f"{config['kind'][0]}_exact-{config['workers']}"]
        for row in rows:
            row["measured"] = observation_fixture(row["report"])
            value = report(workers=config["workers"])
            value.update(candidate["layouts"][calibration["gate"]])
            value["seed"] = 0
            row["pre"] = observation_fixture(value)
            row["post"] = observation_fixture(value)
            for boundary in ("candidate_before", "candidate_after"):
                row[boundary] = {key: candidate[key] for key in ("source_sha256", "binary_sha256")}
    rng = random.Random(123)
    order = qualify.schedule(rng)
    sequence = 0
    for block, names in enumerate(order):
        for name in names:
            for row in configs[name]:
                if row["block"] == block:
                    row["seed"] = rng.randrange(1 << 64)
                    row["report"]["seed"] = row["seed"]
                    row["measured"]["seed"] = row["seed"]
                    row["measured"]["report"]["seed"] = row["seed"]
                    refresh_raw(row["measured"])
                    row["sequence"] = sequence
                    sequence += 1
    return {"schema": "kagemusha.m3.runs.v1", "shuffle_seed": 123,
            "schedule": order, "candidate": candidate, "attempts": configs}


def test_summary_cannot_qualify_report_only_records(tmp_path):
    path = tmp_path / "runs.json"
    ledger = ledger_fixture()
    for rows in ledger["attempts"].values():
        for row in rows:
            for key in ("pre", "measured", "post", "candidate_before", "candidate_after"):
                del row[key]
    qualify.write_json(path, ledger)
    # No process exit, raw probe, calibration or candidate-boundary records
    # were retained. Empty reason strings are not evidence of validity.
    assert qualify.summarize(path)["status"] != "pass"


def test_summary_rejects_resampled_seed_even_when_raw_measurement_agrees(tmp_path):
    ledger = ledger_fixture()
    row = ledger["attempts"]["q_chips-1"][0]
    row["seed"] ^= 1 << 63
    row["report"]["seed"] = row["seed"]
    row["measured"]["seed"] = row["seed"]
    row["measured"]["report"]["seed"] = row["seed"]
    refresh_raw(row["measured"])
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"


@pytest.mark.parametrize("policy", [None, "all-vm-counters-unchanged", "unknown"])
def test_changed_or_missing_policy_cannot_requalify_an_earlier_ledger(tmp_path, policy):
    ledger = ledger_fixture()
    if policy is None:
        del ledger["candidate"]["memory_activity_policy"]
    else:
        ledger["candidate"]["memory_activity_policy"] = policy
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"
    candidate_path = tmp_path / "candidate.json"
    qualify.write_json(candidate_path, ledger["candidate"])
    with pytest.raises(ValueError, match="prepare a fresh candidate"):
        qualify.run(candidate_path, 123)


def test_summary_preserves_recorded_swapin_refusal_and_valid_hard_failure(tmp_path):
    ledger = ledger_fixture()
    rejected, failed = ledger["attempts"]["q_chips-4"][:2]
    rejected["reasons"] = ["memory counter changed: Swapins"]
    rejected["measured"]["after"]["raw"]["vm"]["stdout"] = (
        rejected["measured"]["after"]["raw"]["vm"]["stdout"].replace("Swapins: 3.", "Swapins: 4.")
    )
    failed["report"]["samples"][0]["total_ns"] = 10_000_000_001
    failed["measured"]["report"] = deepcopy(failed["report"])
    refresh_raw(failed["measured"])
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    result = qualify.summarize(path)["configurations"]["q_chips-4"]
    assert result["status"] == "fail"
    assert result["valid_processes"] == 8
    assert result["invalid_attempts"][0]["reasons"] == ["memory counter changed: Swapins"]


def test_summary_does_not_replace_failing_real_chips_with_passing_synthetic(tmp_path):
    ledger = ledger_fixture()
    for row in ledger["attempts"]["q_chips-1"]:
        row["report"]["samples"][0]["cpu_ns"] = 31_000_000_000
        row["measured"]["report"] = deepcopy(row["report"])
        refresh_raw(row["measured"])
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    result = qualify.summarize(path)
    assert result["status"] == "fail"
    assert result["configurations"]["q_exact-1"]["status"] == "pass"
    assert result["configurations"]["q_chips-1"]["status"] == "fail"


def test_summary_revalidates_retained_reports_and_process_identity(tmp_path):
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger_fixture())
    assert qualify.summarize(path)["status"] == "pass"
    for field, bad in (("workers", 4), ("seed", 100), ("samples", None),
                       ("peak_rss_bytes", 0), ("descriptor_digest", "other")):
        ledger = ledger_fixture()
        ledger["attempts"]["q_chips-1"][0]["report"][field] = bad
        qualify.write_json(path, ledger)
        assert qualify.summarize(path)["status"] == "inconclusive", field
    ledger = ledger_fixture()
    ledger["attempts"]["q_chips-1"][1] = deepcopy(ledger["attempts"]["q_chips-1"][0])
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"
    ledger = ledger_fixture()
    ledger["attempts"]["q_chips-1"][0]["block"] = 3
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"


@pytest.mark.parametrize("defect", [
    "missing_pre", "missing_post", "missing_measured", "missing_environment",
    "failed_probe", "failed_exit", "missing_exit", "counter_drift", "calibration_cpu",
    "calibration_wall", "calibration_descriptor", "calibration_workers", "calibration_seed",
    "missing_raw_output", "changed_raw_output", "missing_source_boundary", "changed_source",
    "changed_binary", "fake_valid_flag",
])
def test_summary_rechecks_raw_process_environment_and_calibration(tmp_path, defect):
    ledger = ledger_fixture()
    row = ledger["attempts"]["q_chips-1"][0]
    if defect.startswith("missing_") and defect[8:] in ("pre", "post", "measured"):
        del row[defect[8:]]
    elif defect == "missing_environment":
        del row["measured"]["before"]
    elif defect == "failed_probe":
        row["post"]["after"]["raw"]["pressure"]["code"] = 1
    elif defect == "failed_exit":
        row["measured"]["process"]["code"] = 101
    elif defect == "missing_exit":
        del row["pre"]["process"]["code"]
    elif defect == "counter_drift":
        row["measured"]["after"]["raw"]["vm"]["stdout"] = "Compressions: 124.\nPageouts: 0.\nSwapouts: 2.\nSwapins: 3.\n"
    elif defect in ("calibration_cpu", "calibration_wall"):
        metric = "cpu_ns" if defect == "calibration_cpu" else "total_ns"
        row["post"]["report"]["samples"][0][metric] *= 2
        refresh_raw(row["post"])
    elif defect in ("calibration_descriptor", "calibration_workers", "calibration_seed"):
        field, value = {"calibration_descriptor": ("descriptor_digest", "other"),
                        "calibration_workers": ("workers", 4), "calibration_seed": ("seed", 1)}[defect]
        row["post"]["report"][field] = value
        refresh_raw(row["post"])
    elif defect == "missing_raw_output":
        del row["measured"]["process"]["stdout"]
    elif defect == "changed_raw_output":
        row["measured"]["process"]["stdout"] = qualify.PREFIX + "{}"
    elif defect == "missing_source_boundary":
        del row["candidate_before"]
    elif defect == "changed_source":
        row["candidate_after"]["source_sha256"] = "different"
    elif defect == "changed_binary":
        row["candidate_before"]["binary_sha256"] = "different"
    elif defect == "fake_valid_flag":
        row["measured"]["before"] = {"valid": True, "counters": {}, "raw": {}}
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    result = qualify.summarize(path)
    assert result["status"] == "inconclusive"
    assert result["configurations"]["q_chips-1"]["invalid_attempts"][0]["reasons"]


def test_summary_enforces_declared_schedule_and_attempt_limit(tmp_path):
    path = tmp_path / "runs.json"
    for defect in ("schedule", "seed", "attempts", "order", "execution"):
        ledger = ledger_fixture()
        if defect == "schedule":
            ledger["schedule"][0].reverse()
        elif defect == "seed":
            ledger["shuffle_seed"] += 1
        elif defect == "attempts":
            rows = ledger["attempts"]["q_chips-1"]
            # All nine passing samples remain, followed by retained failures.
            for seed in range(9, 19):
                invalid = deepcopy(rows[-1])
                invalid.update(seed=seed, reasons=["invalid environment"])
                rows.append(invalid)
        elif defect == "order":
            rows = ledger["attempts"]["q_chips-1"]
            rows[0], rows[3] = rows[3], rows[0]
        else:
            ledger["attempts"]["q_chips-1"][0]["sequence"] = 1000
        qualify.write_json(path, ledger)
        assert qualify.summarize(path)["status"] == "inconclusive", defect


def test_run_process_retains_probe_and_spawn_failures(tmp_path, monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError("fixture executable missing")

    monkeypatch.setattr(qualify.sys, "platform", "darwin")
    monkeypatch.setattr(qualify, "command", unavailable)
    candidate = {**ledger_fixture()["candidate"], "binary": "/missing-fixture"}
    prefix = tmp_path / "attempt"
    value = qualify.run_process(candidate, qualify.CONFIGS["q_chips-1"], 7, prefix)
    assert value["process"]["code"] is None
    assert value["reasons"]
    assert value["before"]["raw"]["pressure"]["code"] is None
    assert json.loads(prefix.with_suffix(".json").read_text()) == value
    assert prefix.with_suffix(".stdout.log").exists()
    assert "missing" in prefix.with_suffix(".stderr.log").read_text()


@pytest.mark.parametrize("source_changes", [False, True])
def test_run_retains_complete_recomputable_attempts(tmp_path, monkeypatch, source_changes):
    candidate = {**ledger_fixture()["candidate"], "binary": "/fixture-executable"}
    path = tmp_path / "candidate.json"
    qualify.write_json(path, candidate)
    monkeypatch.setattr(qualify, "source_digest", lambda *_args: candidate["source_sha256"])
    monkeypatch.setattr(qualify, "file_hash", lambda _path: candidate["binary_sha256"])
    calls = []

    def measured(_candidate, config, seed, _path):
        calls.append((config["gate"], config["workers"], seed))
        value = report(workers=config["workers"])
        value.update(candidate["layouts"][config["gate"]], seed=seed)
        if source_changes and len(calls) == 3:
            monkeypatch.setattr(qualify, "source_digest", lambda *_args: "changed-source")
        return observation_fixture(value)

    monkeypatch.setattr(qualify, "run_process", measured)
    if source_changes:
        with pytest.raises(ValueError, match="candidate changed"):
            qualify.run(path, 123)
    else:
        qualify.run(path, 123)
    result = qualify.summarize(tmp_path / "runs.json")
    assert result["status"] == ("inconclusive" if source_changes else "pass")
    ledger = json.loads((tmp_path / "runs.json").read_text())
    rows = [row for values in ledger["attempts"].values() for row in values]
    assert len(rows) == (1 if source_changes else 72)
    assert len(calls) == len(rows) * 3
    assert all(set(("pre", "measured", "post", "candidate_before", "candidate_after")) <= row.keys() for row in rows)
    if source_changes:
        assert "candidate_after differs" in " ".join(rows[0]["reasons"])


def test_hash_stream_and_external_output(tmp_path):
    path = tmp_path / "bytes"
    path.write_bytes(b"abc")
    assert qualify.file_hash(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert qualify.ignored_output(tmp_path / "outputs").is_dir()
    with pytest.raises(ValueError):
        qualify.ignored_output(qualify.ROOT / "specs" / "qualification-output")


def test_incomplete_configuration_sets_cannot_pass(tmp_path):
    path = tmp_path / "runs.json"
    for rows in ({}, {"q_exact-1": attempts()}):
        qualify.write_json(path, {"candidate": {}, "attempts": rows})
        result = qualify.summarize(path)
        assert result["status"] == "inconclusive"
        assert set(result["configurations"]) == set(qualify.CONFIGS)
    qualify.write_json(path, {"candidate": {}, "attempts": {"unknown": []}})
    with pytest.raises(ValueError):
        qualify.summarize(path)


def test_layout_inventory_binds_all_actual_descriptors():
    records = []
    for gate in sorted({config["gate"] for config in qualify.CONFIGS.values()}):
        item = {key: report()[key] for key in
                ("k", "shape", "descriptor_digest", "descriptor_hash", "transcript_profile")}
        records.append("M3_LAYOUT_JSON " + json.dumps({**item, "gate": gate}))
    text = "\n".join(records)
    assert len(qualify.parse_layouts(text)) == 4
    for invalid in ("", "\n".join(records[1:]), text + "\n" + records[0],
                    text.replace('"k": 16', '"k": 15'),
                    text.replace("blake2b256-pipa-v2-circdesc", "sha256")):
        with pytest.raises(ValueError):
            qualify.parse_layouts(invalid)


def source_fixture(tmp_path, monkeypatch):
    """Create a real ignored vendor input and artifact depfile, without Cargo."""
    monkeypatch.setattr(qualify, "ROOT", tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("target/\nvendor/\nfixtures/ignored.txt\n")
    package = tmp_path / "crates/iroha_plonk_gadgets"
    vendor = tmp_path / "vendor/local"
    for directory in (package, vendor, tmp_path / ".cargo", tmp_path / "fixtures", tmp_path / "target"):
        directory.mkdir(parents=True)
    for directory in (package, vendor):
        (directory / "Cargo.toml").write_text("[package]\n")
        (directory / "lib.rs").write_text("// source\n")
    (tmp_path / "Cargo.toml").write_text("[workspace]\n")
    (tmp_path / "Cargo.lock").write_text("# lock\n")
    (tmp_path / "fixtures/shared input.txt").write_text("original")
    binary = tmp_path / "target/m3_gates-fixture"
    binary.write_bytes(b"fixture executable")
    library = tmp_path / "target/libvendor.rlib"
    library.write_bytes(b"fixture library")
    binary.with_suffix(".d").write_text(f"{binary}: crates/iroha_plonk_gadgets/lib.rs fixtures/shared\\ input.txt\n")
    library.with_name("vendor.d").write_text(f"{library}: vendor/local/lib.rs\n")
    packages = [dict(id=name, name=name, version="1", source=None, manifest_path=str(path / "Cargo.toml"))
                for name, path in [("iroha_plonk_gadgets", package), ("vendor", vendor)]]
    metadata = {"packages": packages}
    artifacts = [dict(reason="compiler-artifact", package_id="iroha_plonk_gadgets",
                      target={"name": "m3_gates"}, filenames=[str(binary)], executable=str(binary)),
                 dict(reason="compiler-artifact", package_id="vendor", target={"name": "vendor"}, filenames=[str(library)])]
    monkeypatch.setattr(qualify, "cargo_metadata", lambda: deepcopy(metadata))
    monkeypatch.setattr(qualify, "tool_identity", lambda: {"rustc": "fixture", "cargo": "fixture"})
    return metadata, artifacts, binary


def mocked_build(monkeypatch, artifacts, binary, *, during_build=None, during_inventory=None):
    def command(argv, **_kwargs):
        if argv[0] == "git":
            return subprocess.run(argv, cwd=qualify.ROOT, text=True, capture_output=True)
        if argv[0] == "scripts/cargo_fast.sh":
            if during_build:
                during_build()
            output = "\n".join(json.dumps(item) for item in artifacts)
        elif argv[0] == "rustc":
            output = "fixture compiler\n"
        elif "--list" in argv:
            output = "\n".join(f"{config['test']}: test" for config in qualify.CONFIGS.values())
        else:
            output = "\n".join("M3_LAYOUT_JSON " + json.dumps(layout)
                               for layout in ledger_fixture()["candidate"]["layouts"].values())
            if during_inventory:
                during_inventory()
        return subprocess.CompletedProcess(argv, 0, output, "")
    monkeypatch.setattr(qualify, "command", command)


@pytest.mark.parametrize("change", [None, "source", "executable"])
def test_prepare_binds_inventory_to_unchanged_source_and_binary(tmp_path, monkeypatch, change):
    _, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    def mutate():
        if change == "source":
            (tmp_path / "vendor/local/lib.rs").write_text("changed")
        elif change == "executable":
            binary.write_bytes(b"changed")
    mocked_build(monkeypatch, artifacts, binary, during_inventory=mutate)
    output = tmp_path / "target/qualification"
    if change:
        with pytest.raises(ValueError, match=f"{change} changed during descriptor inventory"):
            qualify.prepare(output)
        assert not (output / "candidate.json").exists()
    else:
        qualify.prepare(output)
        candidate = json.loads((output / "candidate.json").read_text())
        assert candidate["binary_sha256"] == qualify.file_hash(binary)
        assert candidate["source_sha256"] == qualify.source_digest(candidate["source_scope"])
        assert candidate["source_policy"] == qualify.SOURCE_POLICY


def test_component_scope_uses_actual_dependencies_and_cross_crate_inputs(tmp_path, monkeypatch):
    metadata, artifacts, _ = source_fixture(tmp_path, monkeypatch)
    scope = qualify.component_scope(metadata, artifacts)
    assert scope["roots"] == [".cargo", "crates/iroha_plonk_gadgets", "vendor/local"]
    assert "fixtures/shared input.txt" in scope["required_inputs"]
    manifest = qualify.source_manifest(qualify.metadata_roots(metadata))
    expected = qualify.manifest_digest(qualify.selected_sources(manifest, scope))
    manifest["crates/unrelated/src/lib.rs"] = "concurrent unrelated edit"
    assert qualify.manifest_digest(qualify.selected_sources(manifest, scope)) == expected
    for path in ("Cargo.lock", ".cargo/config.toml", "vendor/local/new.rs",
                 "crates/iroha_plonk_gadgets/src/new.rs", "fixtures/shared input.txt"):
        changed = {**manifest, path: "file:changed"}
        assert qualify.manifest_digest(qualify.selected_sources(changed, scope)) != expected, path
    with pytest.raises(ValueError, match="omits"):
        qualify.component_scope(metadata, artifacts[1:])


@pytest.mark.parametrize("change", [None, "owned", "unrelated"])
def test_component_prepare_keeps_captured_scope_distinct_from_release(tmp_path, monkeypatch, change):
    _, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("before")
    def mutate():
        if change:
            path = tmp_path / "vendor/local/lib.rs" if change == "owned" else unrelated
            path.write_text("changed")
    mocked_build(monkeypatch, artifacts, binary, during_build=mutate)
    output = tmp_path / "target/qualification"
    if change == "owned":
        with pytest.raises(ValueError, match="source changed during build"):
            qualify.prepare(output, component=True)
        assert not (output / "candidate.json").exists()
    else:
        qualify.prepare(output, component=True)
        candidate = json.loads((output / "candidate.json").read_text())
        assert candidate["qualification_scope"] == "component"
        assert candidate["source_sha256"] == qualify.source_digest(candidate["source_scope"])
    provenance = json.loads((output / "source-provenance.json").read_text())
    assert bool(provenance["changed_in_scope"]) == (change == "owned")
    assert (provenance["whole_checkout_before"] != provenance["whole_checkout_after"]) == bool(change)


@pytest.mark.parametrize("change", ["edit", "add", "delete"])
def test_ignored_local_package_files_are_bound_at_build_and_runtime(tmp_path, monkeypatch, change):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    mocked_build(monkeypatch, artifacts, binary)
    scope = qualify.component_scope(metadata, artifacts)
    before = qualify.source_digest(scope)
    old = tmp_path / "vendor/local/uncompiled.txt"
    old.write_text("before")
    before = qualify.source_digest(scope)
    def mutate():
        if change == "edit":
            old.write_text("changed")
        elif change == "add":
            (old.parent / "new.txt").write_text("new")
        else:
            old.unlink()
    mutate()
    assert qualify.source_digest(scope) != before
    # Same mutation during a build must refuse creating candidate.json.
    old.write_text("before")
    (old.parent / "new.txt").unlink(missing_ok=True)
    mocked_build(monkeypatch, artifacts, binary, during_build=mutate)
    with pytest.raises(ValueError, match="source changed during build"):
        qualify.prepare(tmp_path / "target/output", component=True)


def test_missing_prebuild_ignored_external_include_is_never_late_pinned(tmp_path, monkeypatch):
    _, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    (tmp_path / "fixtures/ignored.txt").write_text("not in initial inventory")
    with binary.with_suffix(".d").open("a") as stream:
        stream.write(f"{binary}: fixtures/ignored.txt\n")
    mocked_build(monkeypatch, artifacts, binary)
    with pytest.raises(ValueError, match="mandatory compiler input was not captured"):
        qualify.prepare(tmp_path / "target/output", component=True)
    assert not (tmp_path / "target/output/candidate.json").exists()


@pytest.mark.parametrize("kind", ["root", "file", "parent"])
def test_symlinked_local_input_is_refused(tmp_path, monkeypatch, kind):
    metadata, artifacts, _ = source_fixture(tmp_path, monkeypatch)
    vendor = tmp_path / "vendor/local"
    if kind == "root":
        vendor.rename(tmp_path / "original")
        vendor.symlink_to(tmp_path / "original", target_is_directory=True)
    elif kind == "file":
        (vendor / "lib.rs").unlink()
        (vendor / "lib.rs").symlink_to(tmp_path / "Cargo.toml")
    else:
        (tmp_path / "link").symlink_to(vendor, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            qualify.local_path("link/../Cargo.toml")
        return
    with pytest.raises(ValueError, match="symlink"):
        qualify.source_manifest(qualify.metadata_roots(metadata))


@pytest.mark.parametrize("failure", ["missing", "wrong-target", "generated"])
def test_every_local_compiler_artifact_requires_exact_dep_info(tmp_path, monkeypatch, failure):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    depfile = binary.with_suffix(".d")
    if failure == "missing":
        depfile.unlink()
    elif failure == "wrong-target":
        depfile.write_text("Cargo.toml: crates/iroha_plonk_gadgets/lib.rs\n")
    else:
        (binary.parent / "generated.rs").write_text("// unverified generated")
        depfile.write_text(f"{binary}: target/generated.rs\n")
    with pytest.raises(ValueError, match="missing source|does not bind|verified disposition"):
        qualify.component_scope(metadata, artifacts)


def build_script_fixture(tmp_path, artifacts):
    base = tmp_path / "target/build/driver"
    base.mkdir(parents=True)
    alias = base / "build-script-build"
    actual = base / "build_script_build-abc"
    alias.write_bytes(b"script")
    actual.write_bytes(b"script")
    actual.with_suffix(".d").write_text(f"{actual}: crates/iroha_plonk_gadgets/lib.rs\n")
    artifacts.append(dict(package_id="iroha_plonk_gadgets", filenames=[str(alias)],
                          target={"kind": ["custom-build"]}))
    output = base / "out"
    output.mkdir()
    (base / "output").write_text("cargo:rerun-if-env-changed=TEST_CONTROL\n")
    scripts = [dict(package_id="iroha_plonk_gadgets", out_dir=str(output))]
    return actual, scripts


def test_build_script_alias_requires_unique_exact_executable_and_depfile(tmp_path, monkeypatch):
    metadata, artifacts, _ = source_fixture(tmp_path, monkeypatch)
    actual, scripts = build_script_fixture(tmp_path, artifacts)
    scope = qualify.component_scope(metadata, artifacts, scripts)
    assert scope["build_script_aliases"][0]["actual"] == str(actual)
    actual.write_bytes(b"foreign script")
    with pytest.raises(ValueError, match="exact build-script alias"):
        qualify.component_scope(metadata, artifacts, scripts)
    actual.write_bytes(b"script")
    actual.with_suffix(".d").write_text("Cargo.toml: Cargo.lock\n")
    with pytest.raises(ValueError, match="does not bind"):
        qualify.component_scope(metadata, artifacts, scripts)


def test_build_script_output_requires_explicit_generated_disposition(tmp_path, monkeypatch):
    metadata, artifacts, _ = source_fixture(tmp_path, monkeypatch)
    _, scripts = build_script_fixture(tmp_path, artifacts)
    scope = qualify.component_scope(metadata, artifacts, scripts)
    assert scope["build_script_outputs"][0]["generated_disposition"].startswith("empty")
    assert scope["build_environment"] == {"TEST_CONTROL": None}
    with pytest.raises(ValueError, match="executed output record"):
        qualify.component_scope(metadata, artifacts)
    output = Path(scripts[0]["out_dir"])
    (output / "unknown.rs").write_text("// generated")
    with pytest.raises(ValueError, match="verified disposition"):
        qualify.component_scope(metadata, artifacts, scripts)


@pytest.mark.parametrize("change", ["metadata", "tools"])
def test_prepare_refuses_metadata_or_tool_drift(tmp_path, monkeypatch, change):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    def mutate():
        if change == "metadata":
            metadata["changed"] = True
        else:
            monkeypatch.setattr(qualify, "tool_identity", lambda: {"rustc": "changed"})
    mocked_build(monkeypatch, artifacts, binary, during_build=mutate)
    with pytest.raises(ValueError, match="metadata or tools changed"):
        qualify.prepare(tmp_path / "target/output", component=True)


def test_old_source_policy_cannot_requalify_retained_ledger(tmp_path):
    ledger = ledger_fixture()
    del ledger["candidate"]["source_policy"]
    qualify.write_json(tmp_path / "candidate.json", ledger["candidate"])
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"
    with pytest.raises(ValueError, match="prepare a fresh candidate"):
        qualify.run(tmp_path / "candidate.json", 123)


def test_hard_failure_stop_keeps_complete_attempt_and_failing_partial_verdict(tmp_path, monkeypatch):
    candidate = {**ledger_fixture()["candidate"], "binary": "/fixture-executable"}
    path = tmp_path / "candidate.json"
    qualify.write_json(path, candidate)
    monkeypatch.setattr(qualify, "source_digest", lambda *_args: candidate["source_sha256"])
    monkeypatch.setattr(qualify, "file_hash", lambda _path: candidate["binary_sha256"])

    def measured(_candidate, config, seed, _path):
        value = report(workers=config["workers"])
        value.update(candidate["layouts"][config["gate"]], seed=seed)
        if config["kind"] == "q_chips":
            value["samples"][0]["total_ns"] = 10_000_000_001
        return observation_fixture(value)

    monkeypatch.setattr(qualify, "run_process", measured)
    qualify.run(path, 20261007, stop_on_hard_failure=True)
    result = qualify.summarize(tmp_path / "runs.json")
    assert result["status"] == "fail"
    assert result["configurations"]["q_chips-4"]["attempts"] == 1
    assert result["configurations"]["q_chips-4"]["valid_processes"] == 1
    assert all(item["status"] != "pass" for item in result["configurations"].values())


@pytest.mark.parametrize("action", ["run", "summarize"])
@pytest.mark.parametrize("status", ["pass", "fail", "inconclusive", "borderline"])
def test_cli_never_reports_success_for_a_nonpassing_verdict(monkeypatch, action, status):
    monkeypatch.setattr(qualify, "run", lambda *_args, **_kwargs: {"status": status})
    monkeypatch.setattr(qualify, "summarize", lambda *_args: {"status": status})
    args = ["qualification", action] + (["--candidate", "candidate.json"] if action == "run" else ["runs.json"])
    monkeypatch.setattr(qualify.sys, "argv", args)
    with pytest.raises(SystemExit) as error:
        qualify.main()
    assert error.value.code == (0 if status == "pass" else 1)


@pytest.mark.parametrize("index,field,bad", [
    (0, "quotient_workspace_before_bytes", 1),
    (0, "quotient_workspace_after_bytes", 1),
    (1, "quotient_workspace_before_bytes", 0),
    (1, "quotient_workspace_after_bytes", (128 << 20) + 1),
    (1, "quotient_workspace_before_bytes", None),
])
def test_workspace_evidence_must_show_exact_reuse(index, field, bad):
    value = report()
    candidate = {"binary_sha256": value["binary_sha256"], "layouts": {
        value["gate"]: {key: value[key] for key in
            ("gate", "k", "shape", "descriptor_digest", "descriptor_hash")}
    }}
    value["samples"][index][field] = bad
    reasons = qualify.report_reasons(value, qualify.CONFIGS["q_exact-1"], candidate, 7)
    assert "quotient workspace not retained and reused between proofs" in reasons


@pytest.mark.parametrize("name", ["CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"])
def test_compiler_configuration_wrapper_override_is_refused(tmp_path, monkeypatch, name):
    tool = tmp_path / "tool"
    tool.write_bytes(b"selected binary")
    monkeypatch.setattr(qualify.shutil, "which", lambda _name: str(tool))
    monkeypatch.setattr(qualify.sys, "executable", str(tool))
    monkeypatch.setattr(qualify, "command", lambda argv: subprocess.CompletedProcess(
        argv, 0, str(tool) if argv[0] == "rustup" else "fixture version", ""))
    monkeypatch.setenv(name, "/foreign/wrapper")
    with pytest.raises(ValueError, match="custom compiler/wrapper"):
        qualify.tool_identity()


def test_tool_identity_binds_auto_cache_and_script_interpreters(tmp_path, monkeypatch):
    tool = tmp_path / "tool"
    tool.write_bytes(b"selected binary")
    wrapper = tmp_path / "sccache"
    wrapper.write_bytes(b"cache owner")
    monkeypatch.setattr(qualify.shutil, "which", lambda name: str(wrapper if name == "sccache" else tool))
    monkeypatch.setattr(qualify.sys, "executable", str(tool))
    monkeypatch.setattr(qualify, "command", lambda argv: subprocess.CompletedProcess(
        argv, 0, str(tool) if argv[0] == "rustup" else "fixture version", ""))
    before = qualify.tool_identity()
    assert before["automatic_sccache"]["sha256"] == qualify.file_hash(wrapper)
    assert before["launcher:bash"] == before["launcher:python3"] == before["python"]
    wrapper.write_bytes(b"changed cache owner")
    assert qualify.tool_identity() != before
    monkeypatch.setattr(qualify.shutil, "which", lambda name: None if name == "sccache" else str(tool))
    assert qualify.tool_identity()["automatic_sccache"] is None


def test_source_custody_error_after_measurement_preserves_failed_attempt(tmp_path, monkeypatch):
    candidate = {**ledger_fixture()["candidate"], "binary": "/fixture-executable"}
    path = tmp_path / "candidate.json"
    qualify.write_json(path, candidate)
    monkeypatch.setattr(qualify, "source_digest", lambda *_args: candidate["source_sha256"])
    monkeypatch.setattr(qualify, "file_hash", lambda _path: candidate["binary_sha256"])
    calls = []
    def measured(_candidate, config, seed, _path):
        calls.append(seed)
        value = report(workers=config["workers"])
        value.update(candidate["layouts"][config["gate"]], seed=seed)
        if len(calls) == 3:
            def unavailable(*_args):
                raise ValueError("mandatory compiler input lost")
            monkeypatch.setattr(qualify, "source_digest", unavailable)
        return observation_fixture(value)
    monkeypatch.setattr(qualify, "run_process", measured)
    with pytest.raises(ValueError, match="raw evidence retained"):
        qualify.run(path, 123)
    ledger = json.loads((tmp_path / "runs.json").read_text())
    rows = [row for values in ledger["attempts"].values() for row in values]
    assert len(rows) == 1 and len(calls) == 3
    assert rows[0]["candidate_after"]["error"] == "mandatory compiler input lost"
    assert rows[0]["pre"]["process"]["code"] == rows[0]["post"]["process"]["code"] == 0
    assert qualify.summarize(tmp_path / "runs.json")["status"] == "inconclusive"


def test_unknown_or_missing_source_scope_has_no_git_only_fallback():
    with pytest.raises(ValueError, match="captured Cargo source scope"):
        qualify.source_digest()


def test_compiler_environment_dependency_is_bound_or_explicitly_derived(tmp_path, monkeypatch):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    original = binary.with_suffix(".d").read_text()
    depfile = binary.with_suffix(".d")
    monkeypatch.setenv("FIXTURE_BUILD_SETTING", "selected")
    depfile.write_text(original + "# env-dep:FIXTURE_BUILD_SETTING=selected\n")
    scope = qualify.component_scope(metadata, artifacts)
    assert scope["build_environment"] == {"FIXTURE_BUILD_SETTING": "selected"}
    before = qualify.source_digest(scope)
    monkeypatch.setenv("FIXTURE_BUILD_SETTING", "foreign")
    assert qualify.source_digest(scope) != before
    with pytest.raises(ValueError, match="compiler environment differs"):
        qualify.component_scope(metadata, artifacts)
    depfile.write_text(original + "# env-dep:CARGO_MANIFEST_DIR=/foreign\n")
    with pytest.raises(ValueError, match="foreign manifest"):
        qualify.component_scope(metadata, artifacts)
    depfile.write_text(original + "# env-dep:CARGO_UNKNOWN=value\n")
    with pytest.raises(ValueError, match="no disposition"):
        qualify.component_scope(metadata, artifacts)


@pytest.mark.parametrize("location", ["ancestor", "home"])
def test_cargo_configuration_absence_creation_change_and_removal_are_bound(tmp_path, monkeypatch, location):
    checkout = tmp_path / "work/checkout"
    checkout.mkdir(parents=True)
    home = tmp_path / "cargo-home"
    home.mkdir()
    monkeypatch.setattr(qualify, "ROOT", checkout)
    monkeypatch.setenv("CARGO_HOME", str(home))
    directory = tmp_path / "work/.cargo" if location == "ancestor" else home
    directory.mkdir(exist_ok=True)
    path = directory / "config.toml"
    before = qualify.cargo_configuration()
    assert before[str(path)] is None
    path.write_text('[build]\njobs = 2\n')
    present = qualify.cargo_configuration()
    assert present[str(path)] == qualify.file_hash(path) and present != before
    path.write_text('[build]\njobs = 4\n')
    assert qualify.cargo_configuration() != present
    path.unlink()
    assert qualify.cargo_configuration() == before


@pytest.mark.parametrize("selector", ["rustc", "rustc-wrapper", "rustc-workspace-wrapper"])
@pytest.mark.parametrize("location", ["ancestor", "home"])
def test_cargo_configuration_cannot_silently_select_unpinned_compiler(tmp_path, monkeypatch, selector, location):
    checkout = tmp_path / "work/checkout"
    checkout.mkdir(parents=True)
    home = tmp_path / "cargo-home"
    home.mkdir()
    monkeypatch.setattr(qualify, "ROOT", checkout)
    monkeypatch.setenv("CARGO_HOME", str(home))
    directory = tmp_path / "work/.cargo" if location == "ancestor" else home
    directory.mkdir(exist_ok=True)
    (directory / "config").write_text(f'[build]\n"{selector}" = "/unqualified/tool"\n')
    with pytest.raises(ValueError, match="configured compiler/wrapper"):
        qualify.cargo_configuration()


@pytest.mark.parametrize("text,reason", [
    ('[env]\nRUSTC = {value="/unqualified/rustc", force=true}\n', "configuration environment"),
    ('include = ["other.toml"]\n', "configuration include"),
    ('[build]\nrustc-wrapper =', "Invalid value"),
])
def test_cargo_configuration_includes_environment_and_malformed_data_refuse(tmp_path, monkeypatch, text, reason):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(home))
    (home / "config.toml").write_text(text)
    with pytest.raises(ValueError, match=reason):
        qualify.cargo_configuration()


@pytest.mark.parametrize("kind", ["file", "directory", "missing-leaf"])
def test_cargo_configuration_symlink_custody_refuses(tmp_path, monkeypatch, kind):
    home = tmp_path / "home"
    home.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (other / "config.toml").write_text('[build]\njobs = 2\n')
    if kind == "file":
        (home / "config.toml").symlink_to(other / "config.toml")
    else:
        home.rmdir()
        home.symlink_to(other, target_is_directory=True)
        if kind == "missing-leaf":
            (other / "config.toml").unlink()
    monkeypatch.setenv("CARGO_HOME", str(home))
    with pytest.raises(ValueError, match="symlinked Cargo"):
        qualify.cargo_configuration()


def test_both_cargo_config_names_are_pinned_even_with_precedence(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(home))
    (home / "config").write_text('[build]\njobs = 1\n')
    (home / "config.toml").write_text('[build]\njobs = 2\n')
    values = qualify.cargo_configuration()
    assert values[str(home / "config")] == qualify.file_hash(home / "config")
    assert values[str(home / "config.toml")] == qualify.file_hash(home / "config.toml")


@pytest.mark.parametrize("phase", ["build", "runtime"])
def test_new_ancestor_configuration_invalidates_actual_candidate_binding(tmp_path, monkeypatch, phase):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    home = tmp_path / "cargo-home"
    home.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(home))
    monkeypatch.setattr(qualify, "tool_identity", lambda: {"config": qualify.cargo_configuration()})
    path = home / "config.toml"
    def mutate():
        path.write_text('[build]\njobs = 2\n')
    if phase == "build":
        mocked_build(monkeypatch, artifacts, binary, during_build=mutate)
        with pytest.raises(ValueError, match="metadata or tools changed"):
            qualify.prepare(tmp_path / "target/output", component=True)
        assert not (tmp_path / "target/output/candidate.json").exists()
    else:
        scope = qualify.component_scope(metadata, artifacts)
        before = qualify.source_digest(scope)
        mutate()
        assert qualify.source_digest(scope) != before


def test_unavailable_cargo_configuration_is_not_absence(tmp_path, monkeypatch):
    home = tmp_path / "cargo-home"
    home.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(home))
    original = qualify.file_hash
    def inaccessible(path):
        if path == home / "config.toml":
            raise PermissionError("fixture denied")
        return original(path)
    monkeypatch.setattr(qualify, "file_hash", inaccessible)
    with pytest.raises(PermissionError, match="fixture denied"):
        qualify.cargo_configuration()
