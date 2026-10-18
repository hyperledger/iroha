"""Qualification rejects missing evidence, cherry-picking and cap overruns."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import subprocess
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "kagemusha_qualify.py"
SPEC = importlib.util.spec_from_file_location("kagemusha_qualify", SCRIPT)
assert SPEC and SPEC.loader
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)


# Independently evaluated with wrapping 64-bit integer arithmetic from the
# Rust mix(seed, index, 0) contract, rather than computed by the Python validator.
FIXTURE_SEED_KATS = (
    (0, 0, 0xE220A8397B1DCDAF),
    (0, 1, 0x7EC2F3D2E3AE3E6B),
    (7, 0, 0xF75F04CBB5A1A1DD),
    (7, 1, 0x90BF7C7430732C49),
    ((1 << 64) - 1, 0, 0xDE0A564CBCD060C4),
    ((1 << 64) - 1, 1, 0x4921325150033EEC),
)


def report(cpu=25, wall=8, rss=700_000_000, workers=1, seed=7):
    return {
        "schema": "kagemusha.m3.process.v1", "workers": workers,
        "binary_sha256": "ab" * 32, "witness_api": "owned",
        "coset_cache": "on_demand", "commitment_tables": False,
        "quotient_workspace": "caller_owned", "quotient_workspace_budget_bytes": 256 << 20,
        "quotient_workspace_allocated_bytes": 128 << 20,
        "msm_process_budget_bytes": 64 << 20,
        "msm_process_peak_bytes": 1 << 20, "msm_process_retained_bytes": 0,
        "transcript_profile": "pipa-r", "gate": "G3.6/q_exact_shape", "k": 16, "shape": "test-shape", "seed": seed,
        "randomness": "fresh-hedged", "fixture_seed_derivation": "splitmix64-process-sample-v1",
        "descriptor_digest": "cd" * 32, "descriptor_hash": "blake2b256-pipa-v2-circdesc",
        "peak_rss_source": "kernel_lifetime_high_water", "peak_rss_bytes": rss,
        "thermal_before": "nominal", "thermal_after": "nominal",
        "samples": [
            {"index": i, "fixture_seed": qualify.sample_fixture_seed(seed, i),
             "cpu_ns": int(cpu * 1e9), "total_ns": int(wall * 1e9),
             "quotient_workspace_before_bytes": 0 if i == 0 else 128 << 20,
             "quotient_workspace_after_bytes": 128 << 20,
             "verified": True, "thermal_before": "nominal", "thermal_after": "nominal"}
            for i in range(2)
        ],
    }


def reseed_report(value, seed):
    """Keep honest specimen evidence coherent when constructing scheduled rows."""
    value["seed"] = seed
    for index, sample in enumerate(value["samples"]):
        sample["fixture_seed"] = qualify.sample_fixture_seed(seed, index)


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


@pytest.mark.parametrize("seed,index,expected", FIXTURE_SEED_KATS)
def test_fixture_seed_matches_independent_wrapping_u64_known_answers(seed, index, expected):
    assert qualify.sample_fixture_seed(seed, index) == expected


@pytest.mark.parametrize("seed,index", [
    (False, 0), (True, 0), (-1, 0), (1 << 64, 0), ("7", 0), (7.0, 0), (None, 0),
    (7, False), (7, True), (7, -1), (7, 2), (7, "0"), (7, 0.0), (7, None),
])
def test_fixture_seed_rejects_noncanonical_process_or_sample_identity(seed, index):
    with pytest.raises(ValueError):
        qualify.sample_fixture_seed(seed, index)


FIXTURE_EVIDENCE_DEFECTS = (
    "missing_randomness", "wrong_randomness", "missing_derivation", "wrong_derivation",
    "missing_seed", "wrong_seed", "repeated_seed", "swapped_seeds", "foreign_process",
    "boolean_seed", "negative_seed", "overflow_seed", "string_seed", "float_seed", "null_seed",
    "missing_index", "boolean_index", "float_index", "reversed_samples",
)


def corrupt_fixture_evidence(value, defect):
    """Change specimen evidence while leaving its scheduled process seed intact."""
    samples = value["samples"]
    if defect == "missing_randomness":
        del value["randomness"]
    elif defect == "wrong_randomness":
        value["randomness"] = "deterministic"
    elif defect == "missing_derivation":
        del value["fixture_seed_derivation"]
    elif defect == "wrong_derivation":
        value["fixture_seed_derivation"] = "unknown"
    elif defect == "missing_seed":
        del samples[0]["fixture_seed"]
    elif defect == "wrong_seed":
        samples[0]["fixture_seed"] ^= 1
    elif defect == "repeated_seed":
        samples[1]["fixture_seed"] = samples[0]["fixture_seed"]
    elif defect == "swapped_seeds":
        samples[0]["fixture_seed"], samples[1]["fixture_seed"] = (
            samples[1]["fixture_seed"], samples[0]["fixture_seed"])
    elif defect == "foreign_process":
        for index, sample in enumerate(samples):
            sample["fixture_seed"] = qualify.sample_fixture_seed(value["seed"] ^ 1, index)
    elif defect in ("boolean_seed", "negative_seed", "overflow_seed", "string_seed", "float_seed", "null_seed"):
        samples[0]["fixture_seed"] = {
            "boolean_seed": True, "negative_seed": -1, "overflow_seed": 1 << 64,
            "string_seed": str(samples[0]["fixture_seed"]),
            "float_seed": float(samples[0]["fixture_seed"]), "null_seed": None,
        }[defect]
    elif defect == "missing_index":
        del samples[0]["index"]
    elif defect == "boolean_index":
        samples[0]["index"], samples[1]["index"] = False, True
    elif defect == "float_index":
        samples[0]["index"], samples[1]["index"] = 0.0, 1.0
    elif defect == "reversed_samples":
        samples.reverse()
    else:
        raise AssertionError(defect)


@pytest.mark.parametrize("defect", FIXTURE_EVIDENCE_DEFECTS)
def test_report_requires_exact_specimen_and_randomness_evidence(defect):
    candidate = ledger_fixture()["candidate"]
    config = qualify.CONFIGS["q_exact-1"]
    value = report()
    assert qualify.report_reasons(value, config, candidate, 7) == []
    corrupt_fixture_evidence(value, defect)
    assert qualify.report_reasons(value, config, candidate, 7), defect


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


def bind_execution_fixture(ledger, order, rng):
    """Bind raw measured seeds and sequence numbers to the supplied execution order."""
    sequence = 0
    for block, names in enumerate(order):
        for name in names:
            for row in ledger["attempts"][name]:
                if row["block"] == block:
                    row["seed"] = rng.randrange(1 << 64)
                    reseed_report(row["report"], row["seed"])
                    row["measured"]["seed"] = row["seed"]
                    reseed_report(row["measured"]["report"], row["seed"])
                    refresh_raw(row["measured"])
                    row["sequence"] = sequence
                    sequence += 1


def ledger_fixture(shuffle_seed=123):
    candidate = {"binary_sha256": "ab" * 32, "source_sha256": "ef" * 32, "layouts": {},
                 "memory_activity_policy": qualify.MEMORY_ACTIVITY_POLICY, "source_policy": qualify.SOURCE_POLICY,
                 "source_scope": {"kind": "cargo_component"}}
    native, identity, process = retained_native_fixture(candidate["binary_sha256"])
    candidate["source_scope"]["native_source"] = native
    candidate["source_scope"]["build_script_outputs"] = retained_native_build_outputs(native)
    candidate["native_identity"] = identity
    candidate["native_identity_process"] = process
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
            reseed_report(row["report"], seed)
        configs[name] = rows
    for name, rows in configs.items():
        config = qualify.CONFIGS[name]
        calibration = qualify.CONFIGS[f"{config['kind'][0]}_exact-{config['workers']}"]
        for row in rows:
            row["measured"] = observation_fixture(row["report"])
            value = report(workers=config["workers"], seed=0)
            value.update(candidate["layouts"][calibration["gate"]])
            row["pre"] = observation_fixture(value)
            row["post"] = observation_fixture(value)
            for boundary in ("candidate_before", "candidate_after"):
                row[boundary] = {key: candidate[key] for key in ("source_sha256", "binary_sha256")}
    rng = random.Random(shuffle_seed)
    order = qualify.schedule(rng)
    ledger = {"schema": "kagemusha.m3.runs.v1", "shuffle_seed": shuffle_seed,
              "schedule": order, "candidate": candidate, "attempts": configs}
    bind_execution_fixture(ledger, order, rng)
    return ledger


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
    reseed_report(row["report"], row["seed"])
    row["measured"]["seed"] = row["seed"]
    reseed_report(row["measured"]["report"], row["seed"])
    refresh_raw(row["measured"])
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    assert qualify.summarize(path)["status"] == "inconclusive"


@pytest.mark.parametrize("boundary", ["pre", "measured", "post"])
@pytest.mark.parametrize("defect", FIXTURE_EVIDENCE_DEFECTS)
def test_summary_rejects_raw_consistent_specimen_mutations(tmp_path, boundary, defect):
    ledger = ledger_fixture()
    row = ledger["attempts"]["q_chips-1"][0]
    observation = row[boundary]
    corrupt_fixture_evidence(observation["report"], defect)
    refresh_raw(observation)
    if boundary == "measured":
        row["report"] = deepcopy(observation["report"])
    assert qualify.parse_report(observation["process"]["stdout"]) == observation["report"]
    assert observation["seed"] == row[boundary]["report"]["seed"]
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    result = qualify.summarize(path)
    assert result["status"] == "inconclusive"
    configuration = result["configurations"]["q_chips-1"]
    assert configuration["valid_processes"] == 8
    reasons = configuration["invalid_attempts"][0]["reasons"]
    assert reasons
    assert not any("retained report differs" in reason for reason in reasons)
    assert all(result["configurations"][name]["status"] == "pass"
               for name in qualify.CONFIGS if name != "q_chips-1")


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


@pytest.mark.parametrize("seed", [1, 5, 0, -1, 20261006, 20261007, (1 << 100) + 1])
def test_schedule_separates_blocks_without_extra_random_draws(seed):
    rng = random.Random(seed)
    order = qualify.schedule(rng)
    original_rng = random.Random(seed)
    original = []
    for _ in range(3):
        names = list(qualify.CONFIGS)
        original_rng.shuffle(names)
        original.append(names)
    assert len(order) == 3
    assert all(sorted(names) == sorted(qualify.CONFIGS) for names in order)
    assert all(before[-1] != after[0] for before, after in zip(order, order[1:]))
    assert order == qualify.schedule(random.Random(seed))
    assert rng.getstate() == original_rng.getstate()
    assert [rng.randrange(1 << 64) for _ in range(72)] == [
        original_rng.randrange(1 << 64) for _ in range(72)
    ]
    if seed in (1, 5):
        # These accepted seeds originally placed identical configurations on
        # both sides of the first block boundary.
        assert original[0][-1] == original[1][0]
        assert order != original
    elif seed == 20261006:
        assert order == original


@pytest.mark.parametrize("seed", [1, 5])
def test_summary_accepts_separated_seed_one_and_five_schedules(tmp_path, seed):
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger_fixture(seed))
    result = qualify.summarize(path)
    assert result["status"] == "pass"
    assert all(value["valid_processes"] == 9 for value in result["configurations"].values())


@pytest.mark.parametrize("seed", [1, 5])
@pytest.mark.parametrize("forge_declaration", [False, True])
def test_summary_rejects_adjacent_order_with_coherent_process_records(tmp_path, seed, forge_declaration):
    ledger = ledger_fixture(seed)
    rng = random.Random(seed)
    adjacent = []
    for _ in range(3):
        names = list(qualify.CONFIGS)
        rng.shuffle(names)
        adjacent.append(names)
    assert adjacent[0][-1] == adjacent[1][0]
    bind_execution_fixture(ledger, adjacent, rng)
    if forge_declaration:
        ledger["schedule"] = adjacent
    # Every raw observation is internally consistent and individually valid.
    # Neither changing the declaration nor disguising the execution order
    # behind a correct declaration can admit the unseparated batches.
    for name, rows in ledger["attempts"].items():
        assert all(not qualify.attempt_reasons(row, qualify.CONFIGS[name], ledger["candidate"])
                   for row in rows)
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    retained = path.read_bytes()
    result = qualify.summarize(path)
    assert result["status"] == "inconclusive"
    reason = ("invalid predeclared configuration schedule" if forge_declaration
              else "attempt execution differs from predeclared schedule")
    for value in result["configurations"].values():
        assert value["valid_processes"] == 0
        assert all(reason in row["reasons"] for row in value["invalid_attempts"])
    assert path.read_bytes() == retained


@pytest.mark.parametrize("intervening", [
    "exhausted", "launch_failure", "invalid_environment", "invalid_calibration", "failed_child",
])
def test_summary_checks_executed_batches_when_intervening_measurements_fail(tmp_path, intervening):
    ledger = ledger_fixture(1)
    order = ledger["schedule"]
    target = order[0][-1]
    separating = order[1][:order[1].index(target)]
    assert separating
    for name in separating:
        template = deepcopy(ledger["attempts"][name][0])
        rows = []
        # Exhaust all eighteen attempts before the next target batch. A
        # declared later batch must not stand in for an actual process.
        batches = ((0, 18),) if intervening == "exhausted" else ((0, 3), (1, 15))
        for block, count in batches:
            for _ in range(count):
                row = deepcopy(template)
                row["block"] = block
                if intervening == "exhausted" or block == 1:
                    if intervening == "launch_failure":
                        row["measured"]["process"]["code"] = None
                    elif intervening == "failed_child":
                        row["measured"]["process"]["code"] = 101
                    elif intervening == "invalid_calibration":
                        row["post"]["report"]["samples"][0]["cpu_ns"] *= 2
                        refresh_raw(row["post"])
                    else:
                        row["measured"]["after"]["raw"]["pressure"]["stdout"] = "2\n"
                rows.append(row)
        ledger["attempts"][name] = rows
    rng = random.Random(ledger["shuffle_seed"])
    assert qualify.schedule(rng) == order
    bind_execution_fixture(ledger, order, rng)
    for name in separating:
        for row in ledger["attempts"][name]:
            if intervening in ("launch_failure", "failed_child") and row["block"] == 1:
                row["report"] = None
                row["measured"]["report"] = None
                row["measured"]["process"].update(stdout="", stderr="fixture child unavailable or failed")
            row["reasons"] = qualify.attempt_reasons(row, qualify.CONFIGS[name], ledger["candidate"])
        assert len(ledger["attempts"][name]) == 18
        assert all(row["reasons"] for row in ledger["attempts"][name] if
                   intervening == "exhausted" or row["block"] == 1)
    # The target still has all nine passing observations, three per block.
    assert qualify.verdict(qualify.CONFIGS[target], ledger["attempts"][target])["status"] == "pass"
    path = tmp_path / "runs.json"
    qualify.write_json(path, ledger)
    retained = path.read_bytes()
    result = qualify.summarize(path)
    assert result["status"] == "inconclusive"
    value = result["configurations"][target]
    if intervening in ("exhausted", "launch_failure"):
        assert value["status"] == "inconclusive"
        assert value["qualification_reasons"] == [
            "measurement blocks lack an intervening executed configuration batch"
        ]
    else:
        # Separation requires actual execution, not a valid calibration,
        # environment or successful proof. Failed samples still cannot pass.
        assert value["status"] == "pass"
        assert value["qualification_reasons"] == []
    assert value["valid_processes"] == 9
    assert len(value["all_process_times_seconds"]) == 9
    assert len(value["all_process_rss_bytes"]) == 9
    assert value["invalid_attempts"] == []
    assert path.read_bytes() == retained
    if intervening in ("exhausted", "launch_failure"):
        # Both an affected configuration and an unrelated configuration must
        # retain authenticated hard failures even when separation is absent.
        other = next(name for name in qualify.CONFIGS if name not in separating and name != target)
        for name in (target, other):
            row = ledger["attempts"][name][0]
            row["report"]["peak_rss_bytes"] = qualify.GIB
            row["measured"]["report"] = deepcopy(row["report"])
            refresh_raw(row["measured"])
        qualify.write_json(path, ledger)
        retained = path.read_bytes()
        failed = qualify.summarize(path)
        assert failed["status"] == "fail"
        for name in (target, other):
            assert failed["configurations"][name]["status"] == "fail"
            assert failed["configurations"][name]["maximum_kernel_rss_bytes"] == qualify.GIB
        assert failed["configurations"][target]["qualification_reasons"] == value["qualification_reasons"]
        assert failed["configurations"][other]["qualification_reasons"] == []
        assert path.read_bytes() == retained


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
        value = report(workers=config["workers"], seed=seed)
        value.update(candidate["layouts"][config["gate"]])
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


def mocked_build(monkeypatch, artifacts, binary, *, during_build=None, during_inventory=None, identity_record=None):
    if identity_record is None and any(item.get("target", {}).get("name") == "iroha_plonk" for item in artifacts):
        identity_record = retained_native_fixture(qualify.file_hash(binary))[1]
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
            if identity_record is not None:
                output += "\nqualification_candidate_identity: test"
        elif "qualification_candidate_identity" in argv:
            output = "M3_SOURCE_JSON " + json.dumps(identity_record)
        else:
            output = "\n".join("M3_LAYOUT_JSON " + json.dumps(layout)
                               for layout in ledger_fixture()["candidate"]["layouts"].values())
            if during_inventory:
                during_inventory()
        return subprocess.CompletedProcess(argv, 0, output, "")
    monkeypatch.setattr(qualify, "command", command)


@pytest.mark.parametrize("change", [None, "source", "executable"])
def test_prepare_binds_inventory_to_unchanged_source_and_binary(tmp_path, monkeypatch, change):
    _, artifacts, binary = prepare_source_fixture(tmp_path, monkeypatch)
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
    _, artifacts, binary = prepare_source_fixture(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated.md"
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
    fixture = native_source_fixture(tmp_path, monkeypatch)
    metadata, artifacts, binary = fixture.metadata, fixture.artifacts, fixture.binary
    mocked_build(monkeypatch, [*artifacts, *fixture.scripts], binary)
    scope = qualify.component_scope(metadata, artifacts, fixture.scripts, capture_native_fixture(fixture))
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
    mocked_build(monkeypatch, [*artifacts, *fixture.scripts], binary, during_build=mutate)
    with pytest.raises(ValueError, match="source changed during build"):
        qualify.prepare(tmp_path / "target/output", component=True)


def test_missing_prebuild_ignored_external_include_is_never_late_pinned(tmp_path, monkeypatch):
    _, artifacts, binary = prepare_source_fixture(tmp_path, monkeypatch)
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
        value = report(workers=config["workers"], seed=seed)
        value.update(candidate["layouts"][config["gate"]])
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


COMPILER_OVERRIDE_VARIABLES = (
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
)


@pytest.fixture
def clean_compiler_environment(monkeypatch):
    """Keep mocked tool selection independent of the real test runner's compiler."""
    for name in COMPILER_OVERRIDE_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("name", COMPILER_OVERRIDE_VARIABLES)
def test_compiler_configuration_wrapper_override_is_refused(
    tmp_path, monkeypatch, name, clean_compiler_environment
):
    tool = tmp_path / "tool"
    tool.write_bytes(b"selected binary")
    monkeypatch.setattr(qualify.shutil, "which", lambda _name: str(tool))
    monkeypatch.setattr(qualify.sys, "executable", str(tool))
    monkeypatch.setattr(qualify, "command", lambda argv: subprocess.CompletedProcess(
        argv, 0, str(tool) if argv[0] == "rustup" else "fixture version", ""))
    monkeypatch.setenv(name, "/foreign/wrapper")
    with pytest.raises(ValueError, match="custom compiler/wrapper"):
        qualify.tool_identity()


def test_tool_identity_binds_auto_cache_and_script_interpreters(
    tmp_path, monkeypatch, clean_compiler_environment
):
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
        value = report(workers=config["workers"], seed=seed)
        value.update(candidate["layouts"][config["gate"]])
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


def native_source_fixture(tmp_path, monkeypatch):
    """Model exact Cargo originals; only compiler/snapshot execution is stubbed."""
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    package = tmp_path / "crates/iroha_plonk"
    source_names = ("Cargo.toml", "build.rs", "build_support/source_identity.rs",
                    "src/lib.rs", "src/keys/keygen/builtin/generated.rs")
    for name in source_names:
        path = package / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// original " + name + "\n")
    for name in ("audit_native_source_inputs.py", "native_source_snapshot.rs"):
        path = tmp_path / "scripts" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("# maintained evaluator input\n")
    metadata["packages"].append(dict(id="plonk", name="iroha_plonk", version="1", source=None,
                                     manifest_path=str(package / "Cargo.toml")))
    base = tmp_path / "target/release/build/iroha_plonk-selected"
    out = base / "out"
    out.mkdir(parents=True)
    alias, executable = base / "build-script-build", base / "build_script_build-selected"
    alias.write_bytes(b"selected generator")
    executable.write_bytes(b"selected generator")
    executable.with_suffix(".d").write_text(
        f"{executable}: crates/iroha_plonk/build.rs crates/iroha_plonk/build_support/source_identity.rs\n")
    library = tmp_path / "target/release/deps/libiroha_plonk.rlib"
    library.parent.mkdir()
    library.write_bytes(b"selected library")
    identity = out / "native_source_identity.rs"
    identity.write_text(
        "// Generated from actual workspace inputs, not an environment digest.\n"
        "pub(super) const CURRENT_NATIVE_SOURCE_DIGEST: [u8; 32] = [" + ", ".join(["17"] * 32) + "];\n"
        "pub(super) const NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;\n"
        "pub(super) const BUILTIN_TARGET_SUPPORTED: bool = true;\n"
        "#[allow(dead_code)]\n"
        'pub(super) const NATIVE_SOURCE_TARGET: &str = "aarch64-apple-darwin";\n')
    depfile = library.with_name("iroha_plonk.d")
    depfile.write_text(f"{library}: crates/iroha_plonk/src/lib.rs {identity}\n# env-dep:OUT_DIR={out}\n")
    artifacts.extend([
        dict(reason="compiler-artifact", package_id="plonk", filenames=[str(alias)],
             target={"name": "build-script-build", "kind": ["custom-build"]}),
        dict(reason="compiler-artifact", package_id="plonk", filenames=[str(library)],
             target={"name": "iroha_plonk", "kind": ["lib"]}),
    ])
    scripts = [dict(reason="build-script-executed", package_id="plonk", out_dir=str(out))]
    target = {"triple": "aarch64-apple-darwin", "cfg": {"target_arch": "aarch64", "target_os": "macos",
              "target_pointer_width": "64", "target_endian": "little"},
              "cfg_stdout": 'target_arch="aarch64"\ntarget_os="macos"\ntarget_pointer_width="64"\ntarget_endian="little"\n',
              "environment": {"TARGET": "aarch64-apple-darwin", "CARGO_CFG_TARGET_ARCH": "aarch64",
                              "CARGO_CFG_TARGET_OS": "macos", "CARGO_CFG_TARGET_POINTER_WIDTH": "64",
                              "CARGO_CFG_TARGET_ENDIAN": "little"}}
    watched = sorted({".git/index", ".git/info/exclude", "Cargo.lock",
                      *("crates/iroha_plonk/" + name for name in source_names),
                      "scripts/audit_native_source_inputs.py", "scripts/native_source_snapshot.rs"})
    snapshot = {"digest": "11" * 32, "watched": watched}
    rescan = out / "native-source-rescan-required"
    build_output = base / "output"
    build_output.write_text("".join(f"cargo:rerun-if-changed={tmp_path / name}\n" for name in watched)
                            + f"cargo:rerun-if-changed={rescan}\n"
                            + "".join(f"cargo:rerun-if-env-changed={name}\n" for name in target["environment"]))
    sha2 = library.with_name("libsha2-selected.rlib")
    sha2.write_bytes(b"Cargo-selected host sha2")
    helper, driver = package / "build_support/source_identity.rs", tmp_path / "scripts/native_source_snapshot.rs"

    def build_tool(directory, events):
        assert events == [*artifacts, *scripts]
        tool = directory / "source-snapshot"
        tool.write_bytes(b"selected evaluator")
        record = {"helperPath": str(helper), "helperSha256": qualify.file_hash(helper),
                  "driverPath": str(driver), "driverSha256": qualify.file_hash(driver),
                  "binaryPath": str(tool), "binarySha256": qualify.file_hash(tool),
                  "sha2Path": str(sha2), "sha2Sha256": qualify.file_hash(sha2),
                  "sha2Features": [],
                  "command": ["rustc", "--edition=2024", "--crate-name", "iroha_native_source_snapshot", str(driver),
                              "--extern", "sha2=" + str(sha2), "-L", "dependency=" + str(sha2.parent), "-o", str(tool)]}
        qualify.write_json(tool.with_name("source-snapshot-build.json"), record)
        return tool

    audit = SimpleNamespace(HELPER=helper, DRIVER=driver, build_snapshot_tool=build_tool,
                            actual_snapshot=lambda _tool: (snapshot["digest"], {tmp_path / name for name in snapshot["watched"]}))
    monkeypatch.setattr(qualify, "native_audit_module", lambda: audit)
    monkeypatch.setattr(qualify, "native_host_target", lambda: deepcopy(target))
    output = tmp_path / "target/qualification"
    output.mkdir()
    return SimpleNamespace(metadata=metadata, artifacts=artifacts, scripts=scripts, binary=binary, output=output,
                           identity=identity, out=out, depfile=depfile, library=library, rescan=rescan,
                           build_output=build_output, target=target, snapshot=snapshot, sha2=sha2,
                           helper=helper, driver=driver, audit=audit, generator=executable)


def prepare_source_fixture(tmp_path, monkeypatch):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    return fixture.metadata, [*fixture.artifacts, *fixture.scripts], fixture.binary


def retained_native_fixture(binary_sha256):
    """Synthetic retained evidence for verdict tests that never inspect live files."""
    root = qualify.ROOT
    tool = root / "target/fixture/native-source-evaluator/source-snapshot"
    helper = root / "crates/iroha_plonk/build_support/source_identity.rs"
    driver = root / "scripts/native_source_snapshot.rs"
    sha2 = root / "target/release/deps/libsha2-fixture.rlib"
    out = root / "target/release/build/iroha_plonk-fixture/out"
    generated = out / "native_source_identity.rs"
    # Literal build.rs framing, independent of the qualifier's reconstruction.
    source = ("// Generated from actual workspace inputs, not an environment digest.\n"
              "pub(super) const CURRENT_NATIVE_SOURCE_DIGEST: [u8; 32] = [" + ", ".join(["17"] * 32) + "];\n"
              "pub(super) const NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;\n"
              "pub(super) const BUILTIN_TARGET_SUPPORTED: bool = true;\n"
              "#[allow(dead_code)]\n"
              'pub(super) const NATIVE_SOURCE_TARGET: &str = "aarch64-apple-darwin";\n')
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    native = {"policy": "complete-native-source-identity-v1", "source_digest": "11" * 32,
              "tool": str(tool), "evaluator": {
                  "helperPath": str(helper), "helperSha256": "ac" * 32,
                  "driverPath": str(driver), "driverSha256": "bc" * 32,
                  "binaryPath": str(tool), "binarySha256": "cd" * 32,
                  "sha2Path": str(sha2), "sha2Sha256": "dc" * 32, "sha2Features": [],
                  "command": ["rustc", "--edition=2024", "--crate-name", "iroha_native_source_snapshot", str(driver),
                              "--extern", "sha2=" + str(sha2), "-L", "dependency=" + str(sha2.parent), "-o", str(tool)]},
              "evaluator_record_sha256": "de" * 32,
              "builds": [{"package_id": "plonk", "out_dir": str(out), "identity": str(generated),
                          "identity_sha256": source_hash, "rescan": str(out / "native-source-rescan-required"),
                          "output": str(out.parent / "output"), "output_sha256": "ed" * 32,
                          "inventory": {generated.relative_to(root).as_posix(): "file:" + source_hash}}],
              "watched": sorted([".git/index", ".git/info/exclude", "crates/iroha_plonk/build.rs",
                                 "crates/iroha_plonk/build_support/source_identity.rs",
                                 "crates/iroha_plonk/src/keys/keygen/builtin/generated.rs",
                                 "scripts/audit_native_source_inputs.py", "scripts/native_source_snapshot.rs"]),
              "admin_watchers": {".git/index": None, ".git/info/exclude": "ef" * 32},
              "target": {"triple": "aarch64-apple-darwin", "cfg": {"target_arch": "aarch64", "target_os": "macos",
                         "target_pointer_width": "64", "target_endian": "little"},
                         "cfg_stdout": 'target_arch="aarch64"\ntarget_os="macos"\ntarget_pointer_width="64"\ntarget_endian="little"\n',
                         "environment": {"TARGET": "aarch64-apple-darwin", "CARGO_CFG_TARGET_ARCH": "aarch64",
                                         "CARGO_CFG_TARGET_OS": "macos", "CARGO_CFG_TARGET_POINTER_WIDTH": "64",
                                         "CARGO_CFG_TARGET_ENDIAN": "little"}}}
    identity = {"schema": "kagemusha.m3.native-source.v1", "native_source_digest": "11" * 32,
                "binary_sha256": binary_sha256, "target_arch": "aarch64", "target_os": "macos",
                "pointer_width": 64, "little_endian": True}
    native["builds"][0]["output_sha256"] = retained_native_build_outputs(native)[0]["sha256"]
    process = {"code": 0, "stdout": "M3_SOURCE_JSON " + json.dumps(identity), "stderr": ""}
    return native, identity, process


def retained_native_build_outputs(native):
    """Retain Cargo's raw watcher declarations alongside their selected event."""
    result = []
    for build in native["builds"]:
        text = ("".join(f"cargo:rerun-if-changed={qualify.ROOT / name}\n" for name in native["watched"])
                + f"cargo:rerun-if-changed={build['rescan']}\n"
                + "".join(f"cargo:rerun-if-env-changed={name}\n" for name in native["target"]["environment"]))
        result.append({"record": {"reason": "build-script-executed", "package_id": build["package_id"],
                                  "out_dir": build["out_dir"]}, "path": build["output"],
                       "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text,
                       "generated_disposition": "exact complete native source identity"})
    return result


def capture_native_fixture(fixture):
    return qualify.capture_native_source(fixture.metadata, fixture.artifacts, fixture.scripts, fixture.output)


def test_native_identity_has_exact_generated_and_admin_dispositions(tmp_path, monkeypatch):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    scope = qualify.component_scope(fixture.metadata, fixture.artifacts, fixture.scripts, native)
    assert native["source_digest"] == "11" * 32
    assert native["admin_watchers"][".git/index"] is None
    assert native["admin_watchers"][".git/info/exclude"] == qualify.file_hash(tmp_path / ".git/info/exclude")
    assert not set(native["admin_watchers"]) & set(scope["required_inputs"])
    assert fixture.identity.relative_to(tmp_path).as_posix() not in scope["required_inputs"]
    assert fixture.rescan.relative_to(tmp_path).as_posix() not in scope["required_inputs"]
    assert scope["build_environment"] == {}
    assert scope["depfiles"][str(fixture.depfile)]["derived_environment"] == {"OUT_DIR": str(fixture.out)}
    assert scope["build_script_outputs"][0]["generated_disposition"] == "exact complete native source identity"
    before = qualify.source_digest(scope)
    monkeypatch.setenv("OUT_DIR", "/not-a-Cargo-compiler-input")
    monkeypatch.setenv("TARGET", "not-a-Cargo-compiler-input")
    assert qualify.source_digest(scope) == before


@pytest.mark.parametrize("defect", [
    "incomplete", "unsupported", "digest", "target", "malformed", "extra_code", "missing_identity",
    "extra_output", "nested_target", "nested_git", "empty_directory", "rescan_created", "rescan_symlink",
    "missing_watch", "extra_absent_watch", "missing_environment", "unknown_environment", "duplicate_out_dir", "snapshot_drift",
])
def test_native_capture_refuses_unverified_identity_or_watchers(tmp_path, monkeypatch, defect):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    replacements = {
        "incomplete": ("NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true", "NATIVE_SOURCE_CLOSURE_COMPLETE: bool = false"),
        "unsupported": ("BUILTIN_TARGET_SUPPORTED: bool = true", "BUILTIN_TARGET_SUPPORTED: bool = false"),
        "digest": ("[17,", "[18,"), "target": ("aarch64-apple-darwin", "x86_64-apple-darwin"),
    }
    if defect in replacements:
        fixture.identity.write_text(fixture.identity.read_text().replace(*replacements[defect]))
    elif defect == "malformed":
        fixture.identity.write_text("// no valid identity\n")
    elif defect == "extra_code":
        fixture.identity.write_text(fixture.identity.read_text() + "pub const UNREVIEWED: u8 = 1;\n")
    elif defect == "missing_identity":
        fixture.identity.unlink()
    elif defect == "extra_output":
        (fixture.out / "other.rs").write_text("// unverified\n")
    elif defect in ("nested_target", "nested_git", "empty_directory"):
        directory = fixture.out / {"nested_target": "target", "nested_git": ".git", "empty_directory": "empty"}[defect]
        directory.mkdir()
        if defect != "empty_directory":
            (directory / "other.rs").write_text("// unverified\n")
    elif defect == "rescan_created":
        fixture.rescan.write_text("must remain absent")
    elif defect == "rescan_symlink":
        fixture.rescan.symlink_to(fixture.out / "missing")
    elif defect == "missing_watch":
        fixture.build_output.write_text(fixture.build_output.read_text().replace(
            f"cargo:rerun-if-changed={fixture.rescan}\n", ""))
    elif defect == "extra_absent_watch":
        with fixture.build_output.open("a") as stream:
            stream.write(f"cargo:rerun-if-changed={fixture.out / 'unreviewed-absent'}\n")
    elif defect == "missing_environment":
        fixture.build_output.write_text(fixture.build_output.read_text().replace("cargo:rerun-if-env-changed=TARGET\n", ""))
    elif defect == "unknown_environment":
        with fixture.build_output.open("a") as stream:
            stream.write("cargo:rerun-if-env-changed=UNREVIEWED_NATIVE_CONTROL\n")
    elif defect == "duplicate_out_dir":
        fixture.scripts.append(deepcopy(fixture.scripts[0]))
    else:
        observations = []
        def changed(_tool):
            observations.append(None)
            return ("11" * 32 if len(observations) == 1 else "22" * 32,
                    {tmp_path / name for name in fixture.snapshot["watched"]})
        fixture.audit.actual_snapshot = changed
    with pytest.raises((ValueError, FileNotFoundError)):
        capture_native_fixture(fixture)


@pytest.mark.parametrize("defect", [
    "missing_env", "foreign_env", "unknown_cargo_env", "foreign_include", "missing_include", "generator_include",
])
def test_native_compiler_include_and_out_dir_must_match_exact_cargo_event(tmp_path, monkeypatch, defect):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    text = fixture.depfile.read_text()
    if defect == "missing_env":
        text = text.split("# env-dep:")[0]
    elif defect == "foreign_env":
        text = text.replace(f"# env-dep:OUT_DIR={fixture.out}", "# env-dep:OUT_DIR=/foreign/out")
    elif defect == "unknown_cargo_env":
        text += "# env-dep:CARGO_UNREVIEWED=1\n"
    elif defect == "foreign_include":
        foreign = tmp_path / "target/foreign_native_source_identity.rs"
        foreign.write_bytes(fixture.identity.read_bytes())
        text = text.replace(str(fixture.identity), str(foreign))
    elif defect == "generator_include":
        fixture.generator.with_suffix(".d").write_text(
            f"{fixture.generator}: crates/iroha_plonk/build.rs {fixture.identity}\n# env-dep:OUT_DIR={fixture.out}\n")
        text = text.replace(str(fixture.identity), "")
    else:
        text = text.replace(str(fixture.identity), "")
    fixture.depfile.write_text(text)
    with pytest.raises(ValueError):
        qualify.component_scope(fixture.metadata, fixture.artifacts, fixture.scripts, native)


@pytest.mark.parametrize("defect", [
    "identity", "build_output", "extra_output", "rescan", "index_creation", "exclude_change", "exclude_symlink",
    "snapshot_digest", "snapshot_membership", "helper", "driver", "sha2", "evaluator", "record", "record_whitespace", "depfile",
])
def test_native_boundary_rechecks_source_generated_inputs_and_evaluator_custody(tmp_path, monkeypatch, defect):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    scope = qualify.component_scope(fixture.metadata, fixture.artifacts, fixture.scripts, native)
    qualify.source_digest(scope)
    paths = {"identity": fixture.identity, "build_output": fixture.build_output, "helper": fixture.helper,
             "driver": fixture.driver, "sha2": fixture.sha2, "evaluator": Path(native["tool"]),
             "record": Path(native["tool"]).with_name("source-snapshot-build.json"), "depfile": fixture.depfile}
    if defect in paths:
        with paths[defect].open("ab") as stream:
            stream.write(b"changed")
    elif defect == "extra_output":
        (fixture.out / "extra.rs").write_text("// unexpected\n")
    elif defect == "rescan":
        fixture.rescan.write_text("not absent")
    elif defect == "index_creation":
        (tmp_path / ".git/index").write_bytes(b"new index")
    elif defect == "exclude_change":
        (tmp_path / ".git/info/exclude").write_text("changed\n")
    elif defect == "exclude_symlink":
        (tmp_path / ".git/info/exclude").unlink()
        (tmp_path / ".git/info/exclude").symlink_to(tmp_path / "Cargo.toml")
    elif defect == "snapshot_digest":
        fixture.snapshot["digest"] = "22" * 32
    elif defect == "record_whitespace":
        with Path(native["tool"]).with_name("source-snapshot-build.json").open("a") as stream:
            stream.write("\n")
    else:
        fixture.snapshot["watched"] = [*fixture.snapshot["watched"], "new-native-input.rs"]
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        qualify.source_digest(scope)


@pytest.mark.parametrize("component", [False, True])
def test_prepare_joins_exact_generated_native_identity_to_executable(tmp_path, monkeypatch, component):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    identity_record = {"schema": "kagemusha.m3.native-source.v1", "native_source_digest": "11" * 32,
                       "binary_sha256": qualify.file_hash(fixture.binary), "target_arch": "aarch64",
                       "target_os": "macos", "pointer_width": 64, "little_endian": True}
    mocked_build(monkeypatch, [*fixture.artifacts, *fixture.scripts], fixture.binary, identity_record=identity_record)
    qualify.prepare(fixture.output, component=component)
    candidate = json.loads((fixture.output / "candidate.json").read_text())
    assert candidate["native_identity"] == identity_record
    assert candidate["source_sha256"] == qualify.source_digest(candidate["source_scope"])
    assert json.loads((fixture.output / "native-identity.json").read_text()) == identity_record
    assert (fixture.output / "native-source-evaluator/source-snapshot-build.json").is_file()


@pytest.mark.parametrize("field,bad", [
    ("schema", "unknown"), ("native_source_digest", "22" * 32), ("binary_sha256", "cd" * 32),
    ("target_arch", "x86_64"), ("target_os", "linux"), ("pointer_width", 32),
    ("pointer_width", 64.0), ("little_endian", False), ("little_endian", 1),
])
def test_compiled_native_identity_rejects_source_binary_target_or_type_substitution(tmp_path, monkeypatch, field, bad):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    value = {"schema": "kagemusha.m3.native-source.v1", "native_source_digest": "11" * 32,
             "binary_sha256": "ab" * 32, "target_arch": "aarch64", "target_os": "macos",
             "pointer_width": 64, "little_endian": True}
    prefix = "M3_SOURCE_JSON "
    assert qualify.parse_native_identity(prefix + json.dumps(value), native, "ab" * 32) == value
    value[field] = bad
    with pytest.raises(ValueError):
        qualify.parse_native_identity(prefix + json.dumps(value), native, "ab" * 32)
    for text in ("", prefix + "{}", prefix + json.dumps(value) + "\n" + prefix + json.dumps(value)):
        with pytest.raises(ValueError):
            qualify.parse_native_identity(text, native, "ab" * 32)


@pytest.mark.parametrize("defect", [None, "host_missing", "host_duplicate", "cfg_missing", "cfg_duplicate", "unsupported"])
def test_native_host_target_is_independent_of_generated_output_and_shell_env(monkeypatch, defect):
    version = "rustc fixture\nhost: aarch64-apple-darwin\n"
    cfg = 'target_arch="aarch64"\ntarget_os="macos"\ntarget_pointer_width="64"\ntarget_endian="little"\n'
    if defect == "host_missing":
        version = "rustc fixture\n"
    elif defect == "host_duplicate":
        version += "host: x86_64-apple-darwin\n"
    elif defect == "cfg_missing":
        cfg = cfg.replace('target_endian="little"\n', "")
    elif defect == "cfg_duplicate":
        cfg += 'target_pointer_width="32"\n'
    elif defect == "unsupported":
        cfg = cfg.replace('target_os="macos"', 'target_os="linux"')
    calls = []
    def compiler(argv, **_kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, version if "-Vv" in argv else cfg, "")
    monkeypatch.setattr(qualify, "command", compiler)
    monkeypatch.setenv("TARGET", "foreign-target")
    monkeypatch.setenv("CARGO_CFG_TARGET_ARCH", "foreign-arch")
    if defect:
        with pytest.raises(ValueError):
            qualify.native_host_target()
    else:
        result = qualify.native_host_target()
        assert result["triple"] == "aarch64-apple-darwin"
        assert result["environment"] == {"TARGET": "aarch64-apple-darwin", "CARGO_CFG_TARGET_ARCH": "aarch64",
                                         "CARGO_CFG_TARGET_OS": "macos", "CARGO_CFG_TARGET_POINTER_WIDTH": "64",
                                         "CARGO_CFG_TARGET_ENDIAN": "little"}
        assert calls == [["rustc", "-Vv"], ["rustc", "--print", "cfg", "--target", "aarch64-apple-darwin"]]


@pytest.mark.parametrize("defect", [None, "different_spelling", "different_name", "no_native_disposition", "parent_symlink"])
def test_only_exact_native_policy_swift_output_link_is_classified(tmp_path, monkeypatch, defect):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    scope = qualify.component_scope(fixture.metadata, fixture.artifacts, fixture.scripts, native)
    scope["kind"] = "whole_checkout"
    swift = tmp_path / "IrohaSwift"
    swift.mkdir()
    name = "other.xcframework" if defect == "different_name" else "NoritoBridge.xcframework"
    spelling = "./../dist/NoritoBridge.xcframework" if defect == "different_spelling" else "../dist/NoritoBridge.xcframework"
    (swift / name).symlink_to(spelling)
    manifest = qualify.source_manifest(qualify.metadata_roots(fixture.metadata))
    if defect == "no_native_disposition":
        scope["native_source"] = None
    elif defect == "parent_symlink":
        swift.rename(tmp_path / "original-swift")
        swift.symlink_to(tmp_path / "original-swift", target_is_directory=True)
    if defect:
        with pytest.raises(ValueError, match="symlink"):
            qualify.selected_sources(manifest, scope)
    else:
        selected = qualify.selected_sources(manifest, scope)
        assert selected["IrohaSwift/NoritoBridge.xcframework"] == "symlink:../dist/NoritoBridge.xcframework"


@pytest.mark.parametrize("watcher", [".git/index", ".git/info/exclude"])
def test_native_prepare_refuses_admin_watcher_change_during_build(tmp_path, monkeypatch, watcher):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    def mutate():
        path = tmp_path / watcher
        if watcher.endswith("index"):
            # A valid empty index is unnecessary: refusing Git's failed read is
            # also correct, and the retained build result is not qualified.
            path.write_bytes(b"unreadable changed index")
        else:
            path.write_text("changed exclusion policy\n")
    mocked_build(monkeypatch, [*fixture.artifacts, *fixture.scripts], fixture.binary, during_build=mutate)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        qualify.prepare(fixture.output, component=True)
    assert not (fixture.output / "candidate.json").exists()


@pytest.mark.parametrize("defect", ["digest", "failed_process", "missing_record"])
def test_prepare_refuses_bad_compiled_native_join_before_key_inventory(tmp_path, monkeypatch, defect):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    value = {"schema": "kagemusha.m3.native-source.v1", "native_source_digest": "22" * 32,
             "binary_sha256": qualify.file_hash(fixture.binary), "target_arch": "aarch64", "target_os": "macos",
             "pointer_width": 64, "little_endian": True}
    mocked_build(monkeypatch, [*fixture.artifacts, *fixture.scripts], fixture.binary, identity_record=value)
    original = qualify.command
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        if "qualification_candidate_identity" in argv:
            if defect == "failed_process":
                return subprocess.CompletedProcess(argv, 101, "", "incomplete native closure")
            if defect == "missing_record":
                return subprocess.CompletedProcess(argv, 0, "", "")
        return original(argv, **kwargs)
    monkeypatch.setattr(qualify, "command", command)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        qualify.prepare(fixture.output, component=True)
    assert not any("qualification_candidate_layouts" in argv for argv in calls)
    assert not (fixture.output / "candidate.json").exists()


@pytest.mark.parametrize("changed", ["identity", "build_output", "rescan", "admin"])
def test_native_outputs_and_watchers_are_rechecked_after_snapshot_evaluation(tmp_path, monkeypatch, changed):
    fixture = native_source_fixture(tmp_path, monkeypatch)
    native = capture_native_fixture(fixture)
    original = fixture.audit.actual_snapshot
    def snapshot(tool):
        result = original(tool)
        path = {"identity": fixture.identity, "build_output": fixture.build_output,
                "rescan": fixture.rescan, "admin": tmp_path / ".git/info/exclude"}[changed]
        with path.open("a") as stream:
            stream.write("changed during evaluation\n")
        return result
    fixture.audit.actual_snapshot = snapshot
    with pytest.raises(ValueError):
        qualify.recheck_native_source(native)


@pytest.mark.parametrize("component", [False, True])
def test_prepare_requires_native_dependency_and_never_skips_executable_identity(tmp_path, monkeypatch, component):
    metadata, artifacts, binary = source_fixture(tmp_path, monkeypatch)
    # The general compiler-input helper can still exercise isolated fixtures.
    assert qualify.component_scope(metadata, artifacts)["native_source"] is None
    mocked_build(monkeypatch, artifacts, binary)
    original = qualify.command
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return original(argv, **kwargs)
    monkeypatch.setattr(qualify, "command", command)
    output = tmp_path / "target/required-native"
    with pytest.raises(ValueError, match="requires the selected iroha_plonk native source identity"):
        qualify.prepare(output, component=component)
    assert (output / "build.stdout.log").exists()
    assert not (output / "candidate.json").exists()
    assert not any(argv[0] == str(binary) for argv in calls)


@pytest.mark.parametrize("defect", [
    "missing_scope", "missing_native", "null_native", "empty_native", "wrong_native_policy",
    "empty_builds", "missing_evaluator", "missing_digest", "scope_digest_mismatch", "unsupported_target",
    "missing_identity", "null_identity", "cached_digest_mismatch", "cached_boolean_alias",
    "missing_process", "failed_exit", "boolean_exit", "missing_stdout", "empty_stdout", "duplicate_stdout",
    "raw_consistent_wrong_source", "raw_consistent_wrong_binary",
    "sentinel_evaluator", "sentinel_build", "extra_evaluator_field", "extra_build_field", "duplicate_build",
    "foreign_helper", "foreign_driver", "foreign_binary", "foreign_sha2", "relative_tool", "parent_tool",
    "empty_evaluator_hash", "malformed_output_hash", "wrong_generated_hash", "wrong_inventory_hash", "extra_inventory",
    "wrong_identity_path", "wrong_rescan_path", "wrong_output_path", "foreign_out_dir", "empty_package",
    "wrong_command", "extra_command", "malformed_features", "duplicate_features",
    "wrong_triple", "wrong_cfg_stdout", "duplicate_cfg_stdout", "wrong_environment", "extra_environment",
    "missing_watch", "duplicate_watch", "unordered_watch", "absolute_watch", "parent_watch", "empty_watch",
    "missing_native_outputs", "empty_native_outputs", "duplicate_native_output", "sentinel_native_output",
    "wrong_output_package", "wrong_output_outdir", "wrong_output_event", "wrong_output_disposition", "wrong_output_capture_hash",
    "wrong_output_text", "raw_consistent_missing_watch", "raw_consistent_extra_watch", "raw_consistent_relative_watch",
    "raw_consistent_missing_rescan", "raw_consistent_wrong_env",
] + [f"delete:{section}:{field}" for section, names in {
    "evaluator": "helperPath helperSha256 driverPath driverSha256 binaryPath binarySha256 sha2Path sha2Sha256 sha2Features command",
    "build": "package_id out_dir identity identity_sha256 rescan output output_sha256 inventory",
    "target": "triple cfg cfg_stdout environment",
    "cfg": "target_arch target_os target_pointer_width target_endian",
    "environment": "TARGET CARGO_CFG_TARGET_ARCH CARGO_CFG_TARGET_OS CARGO_CFG_TARGET_POINTER_WIDTH CARGO_CFG_TARGET_ENDIAN",
    "admin": ".git/index .git/info/exclude",
    "output": "record path sha256 text generated_disposition",
    "output_event": "reason package_id out_dir",
}.items() for field in names.split()])
def test_run_and_summary_require_matching_successful_compiled_native_identity(tmp_path, monkeypatch, defect):
    ledger = ledger_fixture()
    candidate = ledger["candidate"]
    assert qualify.candidate_native_reasons(candidate) == []
    native = candidate["source_scope"]["native_source"]
    if defect.startswith("delete:"):
        _, section, field = defect.split(":")
        records = {"evaluator": native["evaluator"], "build": native["builds"][0], "target": native["target"],
                   "cfg": native["target"]["cfg"], "environment": native["target"]["environment"],
                   "admin": native["admin_watchers"], "output": candidate["source_scope"]["build_script_outputs"][0],
                   "output_event": candidate["source_scope"]["build_script_outputs"][0]["record"]}
        del records[section][field]
    elif defect == "missing_native_outputs":
        del candidate["source_scope"]["build_script_outputs"]
    elif defect == "empty_native_outputs":
        candidate["source_scope"]["build_script_outputs"] = []
    elif defect == "duplicate_native_output":
        candidate["source_scope"]["build_script_outputs"] *= 2
    elif defect == "sentinel_native_output":
        candidate["source_scope"]["build_script_outputs"] = [{"path": native["builds"][0]["output"]}]
    elif defect in ("wrong_output_package", "wrong_output_outdir", "wrong_output_event"):
        key = {"wrong_output_package": "package_id", "wrong_output_outdir": "out_dir", "wrong_output_event": "reason"}[defect]
        candidate["source_scope"]["build_script_outputs"][0]["record"][key] = "foreign"
    elif defect == "wrong_output_disposition":
        candidate["source_scope"]["build_script_outputs"][0]["generated_disposition"] = "unverified"
    elif defect == "wrong_output_capture_hash":
        candidate["source_scope"]["build_script_outputs"][0]["sha256"] = "22" * 32
    elif defect == "wrong_output_text" or defect.startswith("raw_consistent_") and defect not in (
            "raw_consistent_wrong_source", "raw_consistent_wrong_binary"):
        output = candidate["source_scope"]["build_script_outputs"][0]
        watch = f"cargo:rerun-if-changed={qualify.ROOT / '.git/index'}\n"
        if defect == "wrong_output_text":
            output["text"] += "cargo:warning=changed after capture\n"
        elif defect == "raw_consistent_missing_watch":
            output["text"] = output["text"].replace(watch, "")
        elif defect == "raw_consistent_extra_watch":
            output["text"] += f"cargo:rerun-if-changed={qualify.ROOT / 'unreviewed'}\n"
        elif defect == "raw_consistent_relative_watch":
            output["text"] = output["text"].replace(watch, "cargo:rerun-if-changed=.git/index\n")
        elif defect == "raw_consistent_missing_rescan":
            output["text"] = output["text"].replace(f"cargo:rerun-if-changed={native['builds'][0]['rescan']}\n", "")
        else:
            output["text"] = output["text"].replace("cargo:rerun-if-env-changed=TARGET\n", "cargo:rerun-if-env-changed=UNREVIEWED\n")
        if defect != "wrong_output_text":
            output["sha256"] = hashlib.sha256(output["text"].encode()).hexdigest()
            native["builds"][0]["output_sha256"] = output["sha256"]
    elif defect == "sentinel_evaluator":
        native["evaluator"] = {"bogus": 1}
    elif defect == "sentinel_build":
        native["builds"] = [{"package_id": "plonk"}]
    elif defect == "extra_evaluator_field":
        native["evaluator"]["unreviewed"] = True
    elif defect == "extra_build_field":
        native["builds"][0]["unreviewed"] = True
    elif defect == "duplicate_build":
        native["builds"].append(deepcopy(native["builds"][0]))
    elif defect in ("foreign_helper", "foreign_driver", "foreign_binary", "foreign_sha2"):
        native["evaluator"][defect.removeprefix("foreign_") + "Path"] = "/foreign/input"
    elif defect in ("relative_tool", "parent_tool"):
        native["tool"] = "relative/source-snapshot" if defect == "relative_tool" else "/foreign/../source-snapshot"
    elif defect == "empty_evaluator_hash":
        native["evaluator"]["binarySha256"] = ""
    elif defect == "malformed_output_hash":
        native["builds"][0]["output_sha256"] = "not-a-digest"
    elif defect == "wrong_generated_hash":
        native["builds"][0]["identity_sha256"] = "22" * 32
    elif defect in ("wrong_inventory_hash", "extra_inventory"):
        inventory = native["builds"][0]["inventory"]
        inventory[next(iter(inventory)) if defect == "wrong_inventory_hash" else "target/foreign.rs"] = "file:" + "22" * 32
    elif defect in ("wrong_identity_path", "wrong_rescan_path", "wrong_output_path"):
        native["builds"][0][defect.removeprefix("wrong_").removesuffix("_path")] += ".foreign"
    elif defect == "foreign_out_dir":
        native["builds"][0]["out_dir"] = "/foreign/out"
    elif defect == "empty_package":
        native["builds"][0]["package_id"] = ""
    elif defect == "wrong_command":
        native["evaluator"]["command"][-1] = "/foreign/tool"
    elif defect == "extra_command":
        native["evaluator"]["command"].append("--unreviewed")
    elif defect == "malformed_features":
        native["evaluator"]["sha2Features"] = [[]]
    elif defect == "duplicate_features":
        native["evaluator"]["sha2Features"] = ["std", "std"]
    elif defect == "wrong_triple":
        native["target"]["triple"] = "x86_64-apple-darwin"
    elif defect == "wrong_cfg_stdout":
        native["target"]["cfg_stdout"] = "sentinel"
    elif defect == "duplicate_cfg_stdout":
        native["target"]["cfg_stdout"] += 'target_arch="aarch64"\n'
    elif defect == "wrong_environment":
        native["target"]["environment"]["TARGET"] = "x86_64-apple-darwin"
    elif defect == "extra_environment":
        native["target"]["environment"]["UNREVIEWED"] = "1"
    elif defect == "missing_watch":
        native["watched"].remove(".git/index")
    elif defect == "duplicate_watch":
        native["watched"].append(native["watched"][0])
    elif defect == "unordered_watch":
        native["watched"].reverse()
    elif defect in ("absolute_watch", "parent_watch", "empty_watch"):
        native["watched"] = sorted([*native["watched"], {
            "absolute_watch": "/foreign/input", "parent_watch": "../foreign", "empty_watch": "",
        }[defect]])
    elif defect == "missing_scope":
        del candidate["source_scope"]
    elif defect == "missing_native":
        del candidate["source_scope"]["native_source"]
    elif defect == "null_native":
        candidate["source_scope"]["native_source"] = None
    elif defect == "empty_native":
        candidate["source_scope"]["native_source"] = {}
    elif defect == "wrong_native_policy":
        native["policy"] = "unverified"
    elif defect == "empty_builds":
        native["builds"] = []
    elif defect == "missing_evaluator":
        del native["evaluator"]
    elif defect == "missing_digest":
        del native["source_digest"]
    elif defect == "scope_digest_mismatch":
        native["source_digest"] = "22" * 32
    elif defect == "unsupported_target":
        native["target"]["cfg"]["target_os"] = "linux"
    elif defect == "missing_identity":
        del candidate["native_identity"]
    elif defect == "null_identity":
        candidate["native_identity"] = None
    elif defect == "cached_digest_mismatch":
        candidate["native_identity"]["native_source_digest"] = "22" * 32
    elif defect == "cached_boolean_alias":
        candidate["native_identity"]["little_endian"] = 1
    elif defect == "missing_process":
        del candidate["native_identity_process"]
    elif defect == "failed_exit":
        candidate["native_identity_process"]["code"] = 101
    elif defect == "boolean_exit":
        candidate["native_identity_process"]["code"] = False
    elif defect == "missing_stdout":
        del candidate["native_identity_process"]["stdout"]
    elif defect == "empty_stdout":
        candidate["native_identity_process"]["stdout"] = ""
    elif defect == "duplicate_stdout":
        candidate["native_identity_process"]["stdout"] += "\n" + candidate["native_identity_process"]["stdout"]
    else:
        field = "native_source_digest" if defect == "raw_consistent_wrong_source" else "binary_sha256"
        candidate["native_identity"][field] = "22" * 32
        candidate["native_identity_process"]["stdout"] = "M3_SOURCE_JSON " + json.dumps(candidate["native_identity"])
    assert qualify.candidate_native_reasons(candidate)
    retained = tmp_path / "retained-runs.json"
    qualify.write_json(retained, ledger)
    result = qualify.summarize(retained)
    assert result["status"] == "inconclusive"
    assert all(item["valid_processes"] == 0 for item in result["configurations"].values())
    assert all(any("candidate native identity invalid" in reason for reason in item["invalid_attempts"][0]["reasons"])
               for item in result["configurations"].values())
    calls = []
    monkeypatch.setattr(qualify, "candidate_boundary", lambda *_args: calls.append("boundary"))
    monkeypatch.setattr(qualify, "run_process", lambda *_args: calls.append("process"))
    path = tmp_path / "candidate.json"
    qualify.write_json(path, candidate)
    with pytest.raises(ValueError, match="candidate native identity invalid.*prepare a fresh candidate"):
        qualify.run(path, 123)
    assert calls == []
    assert not (tmp_path / "runs.json").exists()


def test_retained_native_identity_and_summary_do_not_require_live_artifacts(tmp_path, monkeypatch):
    ledger = ledger_fixture()
    retained = tmp_path / "retained-runs.json"
    qualify.write_json(retained, ledger)
    def unavailable(*_args, **_kwargs):
        raise AssertionError("offline summary attempted to inspect live source or artifacts")
    for name in ("file_hash", "local_path", "native_snapshot", "command"):
        monkeypatch.setattr(qualify, name, unavailable)
    assert qualify.candidate_native_reasons(ledger["candidate"]) == []
    assert qualify.summarize(retained)["status"] == "pass"
