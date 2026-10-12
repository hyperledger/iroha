"""Exercise the RNS-BGV cost model, its summary check and the independent reference vectors."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
from io import StringIO
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "fhe_bgv_cost_model.py"
SPEC = importlib.util.spec_from_file_location("fhe_bgv_cost_model", SCRIPT)
assert SPEC and SPEC.loader
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)

REFERENCE = ROOT / "crates" / "iroha_fhe" / "tests" / "vectors" / "bgv_reference.py"
SUMMARY = ROOT / MODEL.SUMMARY_PATH
AFFINE = "bgv.f257.n14.q6x50.p2x60"
BOUNDED = "bgv.f257.n16.q22x50.p2x60"
REFRESH = "bgv.f257.n16.q32x50.p2x60"

# Every file of the tree that `check_summary` reads.
CHECKED_FILES = (
    MODEL.PROFILE_SOURCE,
    MODEL.CLASS_SOURCE,
    MODEL.HARNESS_SOURCE,
    MODEL.COINS_SOURCE,
    MODEL.CHAIN_SOURCE,
    MODEL.ESTIMATOR_SCRIPT,
    MODEL.ESTIMATOR_OUTPUT,
    MODEL.VECTORS_TEST,
    MODEL.MODEL_VECTORS_PATH,
    MODEL.COMPARISON_SPEC,
    MODEL.CANDIDATE_SPEC,
)


def tracked_summary() -> dict:
    return json.loads(SUMMARY.read_text())


class PinnedRunTest(unittest.TestCase):
    """Cost ingestion consumes one verified snapshot and mandatory external pins."""

    PIN = "ab" * 32

    def verified(self) -> dict:
        """Synthetic reader return for testing the consumer, not harness acceptance."""
        labels = ["root", "profile"] + [path for _, path in MODEL.PHASES]
        labels += [f"operation_profile/{name}" for name in MODEL.OPERATIONS]
        labels = list(dict.fromkeys(labels))
        record = {
            "outcome": "succeeded", "identity": {"workload": "bgv.synthetic"},
            "phase_tree": {"nodes": [
                {"label": label, "parent": None if index == 0 else 0, "calls": 1,
                 "wall_inclusive_ns": 100, "wall_exclusive_ns": 1}
                for index, label in enumerate(labels)]},
            "work_counters": {"entries": [{"phase": 1, "label": "degree", "max_units": 8,
                                           "total_units": 8}]},
            "byte_counters": {"entries": []}, "declared": [],
            "process": {"thermal_begin": None, "thermal_finish": None,
                        "load_milli_begin": 0, "load_milli_finish": 0},
            "scheduling": {"workers": 1},
        }
        return {
            "manifest_sha256": self.PIN, "documents": {"child/bgv-synthetic.json": record},
            "report": {
                "verdict": "accepted", "records": [{"json": {"path": "child/bgv-synthetic.json"}}],
                "host": {"model": "verified-host"},
                "context": {"config": MODEL.SPARSE_CONFIG, "artifact": "sha256:" + "cd" * 32,
                            "source_commit": "12" * 20, "source_dirty": False,
                            "source_dirty_digest": "34" * 32, "hardware": "verified-hardware",
                            "profile": "verified-profile", "cache_policy": "warm"},
                "process": {"peak_rss_bytes": 1, "cpu_user_ns": 2, "cpu_system_ns": 3},
            },
        }

    def test_read_run_consumes_only_verified_documents_and_host(self) -> None:
        verified = self.verified()
        with patch.object(MODEL.HARNESS, "read_pinned_run", return_value=verified) as reader, \
             patch.object(Path, "read_text", side_effect=AssertionError("evidence reopened")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("evidence reopened")), \
             patch.object(Path, "glob", side_effect=AssertionError("unsealed directory scan")):
            block, host = MODEL.read_run(Path("run-original"), self.PIN)
        reader.assert_called_once_with(Path("run-original"), self.PIN)
        self.assertIs(host, verified["report"]["host"])
        self.assertEqual(block["run"]["manifest_sha256"], self.PIN)
        self.assertEqual(block["workload"], "bgv.synthetic")
        self.assertEqual(block["run"]["artifact"], "sha256:" + "cd" * 32)

    def test_original_reader_refusal_is_not_reclassified_or_retried(self) -> None:
        original = MODEL.HARNESS.HarnessRefusal("pinned run refused: manifest_digest_differs")
        with patch.object(MODEL.HARNESS, "read_pinned_run", side_effect=original) as reader:
            with self.assertRaises(MODEL.HARNESS.HarnessRefusal) as refused:
                MODEL.read_run(Path("run-original"), self.PIN)
        self.assertIs(refused.exception, original)
        reader.assert_called_once()

    def test_exactly_one_successful_sealed_bgv_record_is_required(self) -> None:
        for count in (0, 2):
            verified = self.verified()
            verified["report"]["records"] *= count
            with self.subTest(count=count), patch.object(MODEL.HARNESS, "read_pinned_run", return_value=verified):
                with self.assertRaisesRegex(SystemExit, "exactly one workload record"):
                    MODEL.read_run(Path("run-original"), self.PIN)
        verified = self.verified()
        verified["documents"]["child/bgv-synthetic.json"]["outcome"] = "failed"
        with patch.object(MODEL.HARNESS, "read_pinned_run", return_value=verified):
            with self.assertRaisesRegex(SystemExit, "workload did not succeed"):
                MODEL.read_run(Path("run-original"), self.PIN)

    def test_missing_invalid_and_duplicate_pins_refuse_before_reading(self) -> None:
        with patch.object(MODEL, "read_run") as reader:
            with self.assertRaises(TypeError):
                MODEL.build_summary([Path("run")])
            for paths, pins in (([], []), ([Path("run")], []),
                                ([Path("run")], ["invalid"]),
                                ([Path("a"), Path("b")], [self.PIN, self.PIN])):
                with self.subTest(pins=pins), self.assertRaises(ValueError):
                    MODEL.build_summary(paths, manifest_sha256=pins)
        reader.assert_not_called()

    def test_builder_uses_returned_host_and_pin_without_reopening_report(self) -> None:
        summary = tracked_summary()
        expected = MODEL.rederive(summary)
        host = {key: value["value"] if isinstance(value, dict) else value
                for key, value in summary["host"].items() if key != "hardware_record"}
        by_name = {run["run"]["run_directory"]: run for run in summary["runs"]}
        paths = [Path(name) for name in by_name]
        pins = [by_name[path.name]["run"]["manifest_sha256"] for path in paths]
        original_read = Path.read_text

        def read(path, pin):
            block = copy.deepcopy(by_name[path.name])
            self.assertEqual(pin, block["run"]["manifest_sha256"])
            return block, host

        def read_text(path, *args, **kwargs):
            self.assertNotEqual(path.name, "report.json", "verified host must not be reopened")
            return original_read(path, *args, **kwargs)

        with patch.object(MODEL, "read_run", side_effect=read) as reader, \
             patch.object(Path, "read_text", read_text), \
             patch.object(MODEL, "sha256_of", side_effect=AssertionError("post-hoc pin")):
            rebuilt = MODEL.build_summary(paths, manifest_sha256=pins)
        self.assertEqual(rebuilt, expected)
        self.assertEqual(reader.call_count, len(paths))

    def test_cli_requires_build_pins_and_preserves_refusal_before_write(self) -> None:
        for args in (["--build", "run"], ["--manifest-sha256", self.PIN]):
            with self.subTest(args=args), redirect_stderr(StringIO()), self.assertRaises(SystemExit) as refusal:
                MODEL.main(args)
            self.assertEqual(refusal.exception.code, 2)
        with patch.object(MODEL, "build_summary", side_effect=MODEL.HARNESS.HarnessRefusal("bad pin")), \
             patch.object(MODEL, "write_outputs") as write, redirect_stderr(StringIO()) as stderr:
            self.assertEqual(MODEL.main(["--build", "run", "--manifest-sha256", self.PIN, "--write"]), 1)
        write.assert_not_called()
        self.assertIn("bad pin", stderr.getvalue())


class ScratchRoot:
    """A copy of the files the check reads, with one of them edited (or none, without a path)."""

    def __init__(self, path: str = "", old: str = "", new: str = ""):
        self.path, self.old, self.new = path, old, new

    def __enter__(self) -> Path:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        for relative in CHECKED_FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        if not self.path:
            return root
        edited = root / self.path
        text = edited.read_text()
        if text.count(self.old) != 1:
            raise AssertionError(f"{self.path}: {self.old!r} occurs {text.count(self.old)} times")
        edited.write_text(text.replace(self.old, self.new))
        return root

    def __exit__(self, *_exc) -> None:
        self.directory.cleanup()


class TrackedSummaryTest(unittest.TestCase):
    def test_tracked_summary_matches_the_source_tree_and_its_own_measurements(self) -> None:
        self.assertEqual(MODEL.check_summary(tracked_summary()), [])
        with redirect_stdout(StringIO()) as stdout:
            self.assertEqual(MODEL.main([]), 0)
        self.assertIn("consistent", stdout.getvalue())

    def test_every_number_is_classified_measured_projection_parameter_or_estimator(self) -> None:
        summary = tracked_summary()
        self.assertEqual(MODEL.unclassified_numbers(summary), [])
        classes = set()

        def walk(value) -> None:
            if isinstance(value, dict):
                if "class" in value and "value" in value:
                    classes.add(value["class"])
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(summary)
        self.assertEqual(classes, {"measured", "projection", "parameter", "estimator"})
        self.assertEqual(set(summary["classification"]), classes)
        # A bare number, an unknown class and a missing unit are all reported.
        summary["runs"][0]["process"]["peak_rss_bytes"] = 5
        self.assertIn("/runs[0]/process/peak_rss_bytes: bare number 5", MODEL.unclassified_numbers(summary))
        self.assertEqual(
            MODEL.unclassified_numbers({"a": {"value": 1, "class": "guess", "unit": "count"}}),
            ["/a: class 'guess'"],
        )
        self.assertEqual(MODEL.unclassified_numbers({"a": {"value": 1, "class": "measured"}}), ["/a: no unit"])
        # A flag is not a number.
        self.assertEqual(MODEL.unclassified_numbers({"fits": True, "minimal": None}), [])

    def test_measured_runs_cover_every_configuration_and_were_accepted(self) -> None:
        summary = tracked_summary()
        by_config: dict = {}
        for run in summary["runs"]:
            by_config.setdefault(run["config"], []).append(run)
        self.assertEqual(set(by_config), set(MODEL.RUN_CONFIGS))
        artifacts = set()
        for config, runs in by_config.items():
            for run in runs:
                self.assertEqual(run["run"]["verdict"], "accepted")
                self.assertEqual(run["kind"], MODEL.RUN_CONFIGS[config][0])
                self.assertEqual(run["run"]["hardware"], summary["host"]["hardware_record"])
                self.assertEqual(run["run"]["workers"]["value"], 1)
                self.assertEqual(len(run["run"]["manifest_sha256"]), 64)
                artifacts.add(run["run"]["artifact"])
                # At most one percent of the wall time is outside every phase.
                process = run["process"]
                self.assertLessEqual(
                    process["root_unattributed_wall_ns"]["value"] * 100, process["root_wall_ns"]["value"]
                )
            spread = summary["run_spread"][config]
            self.assertEqual(spread["runs"]["value"], len(runs))
            self.assertLessEqual(
                spread["evaluation_wall_ns_min"]["value"], spread["evaluation_wall_ns_median"]["value"]
            )
            self.assertLessEqual(
                spread["evaluation_wall_ns_median"]["value"], spread["evaluation_wall_ns_max"]["value"]
            )
        # One binary produced every run, and both encodings and both workloads ran several times.
        self.assertEqual(len(artifacts), 1)
        for config in (MODEL.SPARSE_CONFIG, MODEL.BATCHING_CONFIG, MODEL.BOUNDED_TAPE_CONFIG, MODEL.AFFINE_TAPE_CONFIG):
            self.assertGreaterEqual(len(by_config[config]), 3, config)
        comparison = summary["encoding_comparison_n16"]
        for part in (
            "equality_exponentiation",
            "load_broadcast_key_switches",
            "scalar_subalgebra_and_range_check",
            "load_mask_multiplication",
            "output_masking",
            "unused_output_zeroing",
        ):
            self.assertEqual(comparison[part]["f257_sparse_wall_ns"]["class"], "measured")
            self.assertEqual(comparison[part]["batching_wall_ns"]["class"], "measured")
            self.assertGreater(comparison[part]["f257_sparse_wall_ns"]["value"], 0)
        # The select took both branches at full size.
        branches = summary["select_branch_comparison_n16"]["evaluation_total"]
        self.assertGreater(branches["zero_branch_wall_ns"]["value"], 0)
        self.assertGreater(branches["nonzero_branch_wall_ns"]["value"], 0)
        self.assertEqual(summary["security_estimate"]["lattice_estimator"]["status"], "run")

    def test_every_opcode_was_measured_and_reported_the_modelled_work(self) -> None:
        summary = tracked_summary()
        measurements = summary["tape_instruction_measurements"]
        bounded = measurements[MODEL.BOUNDED_TAPE_CONFIG]["instructions"]
        self.assertEqual(set(bounded), set(MODEL.OPCODES) | {"final zeroing mask"})
        affine = measurements[MODEL.AFFINE_TAPE_CONFIG]["instructions"]
        self.assertEqual(
            set(affine), {MODEL.OPCODES[tag] for tag in MODEL.AFFINE_OPCODES} | {"final zeroing mask"}
        )
        for block in list(bounded.values()) + list(affine.values()):
            self.assertEqual(block["wall_ns"]["class"], "measured")
            self.assertGreater(block["wall_ns"]["value"], 0)
        # The work the encrypted harness reported is the work of the shape run.
        costs = summary["tape_lowering"]["candidates"][BOUNDED]["instruction_costs"]
        select = bounded["SelectEqZero"]
        self.assertEqual(select["ciphertext_multiplications"]["value"], 10)
        self.assertEqual(select["model_work_units"]["value"], costs["SelectEqZero"]["work_units"]["value"])
        self.assertEqual(bounded["LoadInput"]["calls"]["value"], 2)
        self.assertEqual(
            bounded["LoadInput"]["model_work_units"]["value"], 2 * costs["LoadInput"]["work_units"]["value"]
        )
        # A key-switching instruction dominates a plaintext one in measured time as in the model.
        self.assertGreater(
            bounded["LoadInput"]["wall_ns_per_call"]["value"], 10 * bounded["MulPlain"]["wall_ns_per_call"]["value"]
        )
        # The measured peak memory is within a quarter of the projected keys and working set.
        for config in (MODEL.BOUNDED_TAPE_CONFIG,):
            memory = measurements[config]["memory"]
            self.assertEqual(
                memory["projected_total_bytes"]["value"],
                memory["projected_evaluation_keys_bytes"]["value"] + memory["projected_peak_working_bytes"]["value"],
            )
            self.assertTrue(750 <= memory["measured_over_projected_permille"]["value"] <= 1250, memory)

    def test_a_changed_projection_measurement_or_status_is_detected(self) -> None:
        summary = tracked_summary()
        mutated = copy.deepcopy(summary)
        mutated["candidates"][BOUNDED]["sizes"]["switching_key_frame_bytes"]["value"] += 1
        self.assertIn("candidates: differs from its recomputation", MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        mutated["resource_contract_inputs"][AFFINE]["ram_lfe.ciphertext_bytes"]["value"] -= 8
        self.assertIn("resource_contract_inputs: differs from its recomputation", MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        family = mutated["tape_lowering"]["candidates"][BOUNDED]["families"]["bounded.rank_chain_outputs"]
        family["minimal_main_primes"]["value"] -= 1
        self.assertIn("tape_lowering: differs from its recomputation", MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        mutated["class_cost_model"]["bounded.v1"]["holds_every_planned_family"] = True
        self.assertIn("class_cost_model: differs from its recomputation", MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        relation = mutated["proof_work_projection"]["input_relation"][MODEL.SPARSE_CONFIG]
        relation["range_checked_limbs"]["value"] += 1
        self.assertIn("proof_work_projection: differs from its recomputation", MODEL.check_summary(mutated))
        # A measured time of the representative run feeds the comparison.
        representative = summary["run_spread"][MODEL.SPARSE_CONFIG]["representative_run_directory"]
        mutated = copy.deepcopy(summary)
        run = next(run for run in mutated["runs"] if run["run"]["run_directory"] == representative)
        run["phases"]["equality_exponentiation"]["wall_ns"]["value"] += 1
        self.assertIn("encoding_comparison_n16: differs from its recomputation", MODEL.check_summary(mutated))
        # Reported geometry, sizes and operation counts must equal the model.
        equal = next(index for index, run in enumerate(summary["runs"]) if run["kind"] == "equal_workload")
        mutated = copy.deepcopy(summary)
        mutated["runs"][equal]["geometry"]["scalar_slots"]["value"] += 1
        self.assertTrue(any("reported geometry" in problem for problem in MODEL.check_summary(mutated)))
        mutated = copy.deepcopy(summary)
        mutated["runs"][equal]["sizes"]["evaluation_keys_frame"]["value"] += 1
        self.assertTrue(any("reported sizes" in problem for problem in MODEL.check_summary(mutated)))
        mutated = copy.deepcopy(summary)
        mutated["runs"][equal]["phases"]["equality_exponentiation"]["ciphertext_multiplications"]["value"] += 1
        self.assertTrue(any("operation counts" in problem for problem in MODEL.check_summary(mutated)))
        # The public noise bounds the evaluator reported must equal the plan's.
        mutated = copy.deepcopy(summary)
        mutated["runs"][equal]["phases"]["equality_exponentiation"]["noise_bound_bits"]["value"] += 1
        self.assertTrue(
            any(
                "noise_bound_bits reported after equality_exponentiation" in problem
                for problem in MODEL.check_summary(mutated)
            )
        )
        mutated = copy.deepcopy(summary)
        mutated["runs"][equal]["phases"]["unused_output_zeroing"]["capacity_bits"]["value"] -= 1
        self.assertTrue(any("capacity_bits reported after" in problem for problem in MODEL.check_summary(mutated)))
        # What the encrypted harness reported per opcode must equal the shape run.
        tape = next(index for index, run in enumerate(summary["runs"]) if run["kind"] == "tape_profile")
        mutated = copy.deepcopy(summary)
        mutated["runs"][tape]["instructions"]["LoadInput"]["key_switches"]["value"] += 1
        self.assertTrue(any("LoadInput work differs" in problem for problem in MODEL.check_summary(mutated)))
        mutated = copy.deepcopy(summary)
        mutated["runs"][tape]["declared_model_values"]["model.peak_working_bytes"]["value"] += 8
        self.assertTrue(any("declared model values" in problem for problem in MODEL.check_summary(mutated)))
        mutated = copy.deepcopy(summary)
        mutated["runs"][tape]["final_zeroing_mask"]["noise_bound_bits"]["value"] += 1
        self.assertTrue(any("noise_bound_bits of the output" in problem for problem in MODEL.check_summary(mutated)))
        # An estimator number, a verdict and the status are held to the tracked output record.
        expected = f"security_estimate: differs from its recomputation from {MODEL.ESTIMATOR_OUTPUT}"
        estimator = summary["security_estimate"]["lattice_estimator"]
        mutated = copy.deepcopy(summary)
        mutated["security_estimate"]["lattice_estimator"]["status"] = "not_run"
        self.assertIn(expected, MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        usvp = mutated["security_estimate"]["lattice_estimator"]["profiles"][AFFINE]["instances"]["QP:n"]["models"]
        usvp["ADPS16"]["attacks"]["usvp"]["log2_cost"]["value"] += 30
        self.assertIn(expected, MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        verdict = mutated["security_estimate"]["lattice_estimator"]["profiles"][REFRESH]["verdict"]["ADPS16"]
        self.assertFalse(verdict["meets_design_target_on_the_attacks_with_a_cost"])
        verdict["meets_design_target_on_the_attacks_with_a_cost"] = True
        self.assertIn(expected, MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        mutated["security_estimate"]["lattice_estimator"]["not_covered"].pop()
        self.assertIn(expected, MODEL.check_summary(mutated))
        self.assertEqual(estimator["output_record"], MODEL.ESTIMATOR_OUTPUT)
        mutated = copy.deepcopy(summary)
        mutated["runs"][0]["run"]["verdict"] = "rejected"
        self.assertTrue(any("not accepted" in problem for problem in MODEL.check_summary(mutated)))
        mutated = copy.deepcopy(summary)
        mutated["runs"] = [run for run in mutated["runs"] if run["config"] != MODEL.AFFINE_TAPE_CONFIG]
        self.assertIn(f"no run of {MODEL.AFFINE_TAPE_CONFIG}", MODEL.check_summary(mutated))
        mutated = copy.deepcopy(summary)
        mutated["schema"] = "other"
        self.assertIn("schema", MODEL.check_summary(mutated))
        with redirect_stderr(StringIO()) as stderr:
            self.assertEqual(MODEL.main(["--summary", str(ROOT / "specs" / "missing.json")]), 1)
        self.assertIn("is missing", stderr.getvalue())

    def test_the_summary_rebuilds_from_its_own_runs(self) -> None:
        summary = tracked_summary()
        self.assertEqual(MODEL.rederive(summary), summary)
        self.assertEqual(MODEL.render(MODEL.rederive(summary)), SUMMARY.read_text())


class SourceDriftTest(unittest.TestCase):
    """The summary is held to the Rust sources: a change there fails the check."""

    def test_the_constants_of_the_model_are_those_of_the_rust_sources(self) -> None:
        self.assertEqual(MODEL.source_problems(ROOT), [])
        descriptor = MODEL.class_descriptor((ROOT / MODEL.CLASS_SOURCE).read_text())
        self.assertEqual(descriptor["opcodes"][9], "SelectEqZero")
        self.assertEqual(descriptor["classes"]["affine.v1"], (MODEL.AFFINE_OPCODES, 0, 0))
        constants = MODEL.rust_constants("pub const A: usize = 1_024;\n    pub const B: u16 = 2;\npub const C: u64 = 7;")
        self.assertEqual(constants, {"A": 1024, "C": 7})

    def test_a_changed_class_limit_is_detected(self) -> None:
        summary = tracked_summary()
        for constant, old, new in (
            ("RAM_LFE_V1_MAX_INSTRUCTIONS", "usize = 256;", "usize = 512;"),
            ("RAM_LFE_V1_BOUNDED_MAX_RANK", "u16 = 16;", "u16 = 24;"),
            ("RAM_LFE_V1_STATE_LANES", "usize = 32;", "usize = 16;"),
            ("RAM_LFE_V1_SELECT_CONDITION_RANK", "u16 = 10;", "u16 = 11;"),
        ):
            with ScratchRoot(MODEL.CLASS_SOURCE, f"pub const {constant}: {old}", f"pub const {constant}: {new}") as root:
                problems = MODEL.check_summary(summary, root)
            self.assertTrue(any(constant in problem for problem in problems), (constant, problems))
        # The semantics descriptor is checked too: an opcode added to the affine class.
        with ScratchRoot(
            MODEL.CLASS_SOURCE,
            "class=affine.v1;opcodes=0,1,2,3,4,5,6,7,10;",
            "class=affine.v1;opcodes=0,1,2,3,4,5,6,7,8,10;",
        ) as root:
            problems = MODEL.check_summary(summary, root)
        self.assertTrue(any("class lines" in problem for problem in problems), problems)
        with ScratchRoot(MODEL.CLASS_SOURCE, "opcode=7:MulPlain(", "opcode=7:Scale(") as root:
            problems = MODEL.check_summary(summary, root)
        self.assertTrue(any("opcode lines" in problem for problem in problems), problems)

    def test_a_changed_harness_or_scheme_constant_is_detected(self) -> None:
        summary = tracked_summary()
        for path, old, new, expected in (
            (MODEL.HARNESS_SOURCE, "pub const SELECT_SQUARINGS: usize = 8;", "pub const SELECT_SQUARINGS: usize = 7;", "SELECT_SQUARINGS"),
            (MODEL.HARNESS_SOURCE, "pub const MAX_OUTPUTS: usize = 64;", "pub const MAX_OUTPUTS: usize = 32;", "MAX_OUTPUTS"),
            (MODEL.HARNESS_SOURCE, '    "MulPlain",\n', '    "Scale",\n', "OPCODE_NAMES"),
            (MODEL.COINS_SOURCE, "pub const ERROR_ETA: u32 = 21;", "pub const ERROR_ETA: u32 = 20;", "ERROR_ETA"),
            (MODEL.CHAIN_SOURCE, "pub const MAX_BASIS_PRIMES: usize = 64;", "pub const MAX_BASIS_PRIMES: usize = 48;", "MAX_BASIS_PRIMES"),
        ):
            with ScratchRoot(path, old, new) as root:
                problems = MODEL.check_summary(summary, root)
            self.assertTrue(any(expected in problem for problem in problems), (expected, problems))

    def test_a_changed_view_or_embedded_table_is_detected(self) -> None:
        summary = tracked_summary()
        view = (ROOT / MODEL.MODEL_VECTORS_PATH).read_text()
        self.assertEqual(view, MODEL.model_vectors_text(summary))
        # The view the Rust test reads holds the contract inputs and every family plan.
        self.assertIn(f"[candidate {BOUNDED}]", view)
        self.assertIn(f"[tape {BOUNDED} bounded.scaled_rank_chain]", view)
        self.assertIn(f"[instruction {AFFINE} LoadInput]", view)
        for old, new in (("[shape]\n", "[shape]\nextra = 1\n"), ("registers = 4\n", "registers = 5\n")):
            with ScratchRoot(MODEL.MODEL_VECTORS_PATH, old, new) as root:
                problems = MODEL.check_summary(summary, root)
            self.assertEqual(problems, [f"{MODEL.MODEL_VECTORS_PATH}: differs from the view of the summary"])
        for spec, marker in (
            (MODEL.CANDIDATE_SPEC, MODEL.CLASS_FIT_MARKER),
            (MODEL.CANDIDATE_SPEC, MODEL.CANDIDATE_MARKER),
            (MODEL.CANDIDATE_SPEC, MODEL.ESTIMATOR_MARKER),
            (MODEL.CANDIDATE_SPEC, MODEL.ESTIMATOR_ATTACKS_MARKER),
            (MODEL.CANDIDATE_SPEC, MODEL.ESTIMATOR_PROPOSALS_MARKER),
            (MODEL.COMPARISON_SPEC, MODEL.COMPARISON_MARKER),
            (MODEL.COMPARISON_SPEC, MODEL.INSTRUCTION_MARKER),
            (MODEL.COMPARISON_SPEC, MODEL.INPUT_PROOF_MARKER),
        ):
            with ScratchRoot(spec, f"<!-- {marker}:end -->", f"| extra | row |\n<!-- {marker}:end -->") as root:
                problems = MODEL.check_summary(summary, root)
                self.assertEqual(problems, [f"{spec}: the {marker} table differs from the summary"])
                # Writing the tables restores the block.
                MODEL.write_embedded_tables(summary, root)
                self.assertEqual(MODEL.check_summary(summary, root), [])


class ModelTest(unittest.TestCase):
    def test_pinned_rust_tables_follow_the_first_prime_rule(self) -> None:
        tables = MODEL.rust_prime_tables(ROOT)
        self.assertEqual(len(tables["F257_N14_MAIN_PRIMES"]), 6)
        self.assertEqual(len(tables["F257_N16_MAIN_PRIMES"]), 32)
        affine = MODEL.profile(AFFINE, MODEL.CANDIDATES[AFFINE])
        self.assertEqual(tables["F257_N14_MAIN_PRIMES"], affine.main)
        self.assertEqual(tables["F257_N14_SPECIAL_PRIMES"], affine.special)
        self.assertEqual(affine.main[0], 562_950_180_667_393)
        for prime in affine.main + affine.special:
            self.assertTrue(MODEL.is_prime(prime))
            self.assertEqual(prime % (2 * 16384 * 257), 1)
        # A longer list of the same size extends a shorter one, and equal sizes skip each other.
        step = 2 * 16 * 257
        self.assertEqual(MODEL.first_primes(30, step, 5)[:3], MODEL.first_primes(30, step, 3))
        main = MODEL.first_primes(30, step, 2)
        self.assertEqual(MODEL.first_primes(30, step, 1, tuple(main)), MODEL.first_primes(30, step, 3)[2:])
        with self.assertRaises(ValueError):
            MODEL.first_primes(14, step, 1)

    def test_slot_geometry_of_both_encodings(self) -> None:
        sparse = MODEL.profile(BOUNDED, MODEL.CANDIDATES[BOUNDED])
        self.assertEqual((sparse.slots(), sparse.slot_root(), sparse.mask_l1(), sparse.broadcast_steps()), (128, 3, 8256, 7))
        batching = MODEL.profile(*MODEL.MEASURED_CONFIGS[MODEL.BATCHING_CONFIG])
        self.assertEqual((batching.slots(), batching.broadcast_steps()), (65536, 16))
        # The mask of a fully splitting modulus is dense: about slots * t / 4.
        self.assertGreater(batching.mask_l1(), 65536 * 786433 // 5)
        self.assertLessEqual(batching.mask_l1(), batching.vector_l1())

    def test_noise_rules_match_the_rust_formulas_on_a_small_case(self) -> None:
        toy = MODEL.Profile("toy", 4, 257, (30, 3), (31, 2), 2)
        self.assertEqual(toy.fresh_noise(), 128 + 257 * 21 * 33)
        self.assertEqual(toy.switch_down_noise(0, 2), 257 * 17 // 2)
        special = toy.special_product
        halves = toy.main[0] * toy.main[1] // 2 + toy.main[2] // 2
        self.assertEqual(
            toy.key_switch_noise(2),
            (257 * 16 * 21 * halves + 257 * ((special - 1) // 2) * 17) // special,
        )
        # Work units of the Rust unit test `operation_units_compose_the_kernel_units`.
        forward, inverse, n = 32, 48, 16
        key_switch = (
            n * 9 + 5 * forward + 10 * n + n * 5 + 5 * forward + 10 * n + 10 * inverse + 2 * n * 17
        )
        self.assertEqual(toy.key_switch_units(2), key_switch)
        self.assertEqual(toy.multiplication_units(2), 3 * (4 * forward + 4 * n + 3 * inverse) + key_switch)
        self.assertEqual(toy.switch_down_units(2), 2 * n * 8)
        # Sizes of the Rust unit test `sizes_match_the_encoded_objects`.
        self.assertEqual(toy.ciphertext_bytes(2), 36 + 16 + 8 * 2 * 3 * 16)
        self.assertEqual(toy.switching_key_bytes(), 37 + 8 * 2 * 2 * 5 * 16)
        self.assertEqual(toy.secret_key_bytes(), 32 + 4)
        self.assertEqual(toy.residue_bytes(2), 8 * 2 * 3 * 16)
        self.assertEqual(toy.residue_bytes(0, 3), 8 * 3 * 16)
        self.assertEqual(toy.constant_l1(), 128)

    def test_equal_workload_plans_have_the_measured_shape(self) -> None:
        sparse = MODEL.profile(*MODEL.MEASURED_CONFIGS[MODEL.SPARSE_CONFIG])
        plan = MODEL.plan_equal_workload(sparse)
        # Eight squarings, the embedded one and the select; two loads of seven key switches.
        self.assertEqual(plan.counts["multiplications"], 10)
        self.assertEqual(plan.counts["key_switches"], 10 + 14)
        self.assertEqual(plan.counts["plaintext_multiplications"], 5)
        batching = MODEL.profile(*MODEL.MEASURED_CONFIGS[MODEL.BATCHING_CONFIG])
        plan = MODEL.plan_equal_workload(batching)
        # x^(3 * 2^18): nineteen squarings and one product, then the embedded one and the select.
        self.assertEqual(plan.counts["multiplications"], 22)
        self.assertEqual(plan.counts["key_switches"], 22 + 32)
        # The chains are the shortest ones the worst-case rules admit.
        self.assertEqual(MODEL.minimal_main_primes((16, 257, (50, 22), (60, 2), 2), MODEL.plan_equal_workload), 13)
        self.assertEqual(MODEL.minimal_main_primes((16, 786433, (60, 25), (60, 3), 2), MODEL.plan_equal_workload), 25)
        with self.assertRaises(MODEL.NoiseBudgetExceeded):
            MODEL.plan_equal_workload(MODEL.Profile("short", 16, 257, (50, 12), (60, 2), 2))
        # With one switch per multiplication a 50-bit chain cannot carry the fully splitting prime.
        self.assertIsNone(MODEL.minimal_main_primes((16, 786433, (50, 1), (60, 3), 2), MODEL.plan_equal_workload))

    def test_core_svp_sanity_reproduces_the_published_128_bit_rows(self) -> None:
        # Homomorphic Encryption Standard (2018), uniform ternary secret, 128-bit classical:
        # (N, log2 q) = (4096, 109), (8192, 218), (16384, 438), (32768, 881). The BDGL16-style
        # figure of this sanity calculation lands within one bit of 128 for each row.
        for degree, log_modulus in ((4096, 109), (8192, 218), (16384, 438), (32768, 881)):
            beta = MODEL.core_svp_block_size(degree, log_modulus)
            bits = 0.292 * beta + 16.4 + math.log2(8 * (2 * degree + 1))
            self.assertLess(abs(bits - 128), 1.0, (degree, log_modulus, beta, bits))
        # A larger modulus at the same dimension is weaker.
        self.assertLess(MODEL.core_svp_block_size(16384, 755), MODEL.core_svp_block_size(16384, 412))
        sanity = MODEL.security_sanity(MODEL.profile(AFFINE, MODEL.CANDIDATES[AFFINE]))
        self.assertEqual(sanity["bkz_block_size"]["class"], "projection")
        self.assertLess(sanity["core_svp_classical_bits"]["value"], 128)
        self.assertGreater(sanity["bdgl16_style_classical_bits"]["value"], 128)


class TapeLoweringTest(unittest.TestCase):
    """The shape run of the tape lowering: the second implementation beside the Rust harness."""

    def small(self, primes: int = 22) -> object:
        return MODEL.Profile("small", 8, 257, (40, primes), (41, 3), 2)

    def test_each_instruction_is_charged_the_operations_of_its_lowering(self) -> None:
        p = self.small()
        plan = MODEL.plan_tape(p, MODEL.INSTRUCTION_PROFILE_BOUNDED)
        self.assertTrue(plan["fits"])
        self.assertEqual(plan["instructions"], [2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2])
        top = p.top
        load = p.plaintext_multiplication_units(top) + 7 * p.key_switch_units(top)
        self.assertEqual(plan["costliest"][MODEL.LOAD_INPUT], [1, 7, 0, 0, load])
        self.assertEqual(plan["by_opcode"][MODEL.LOAD_INPUT], [2, 14, 0, 0, 2 * load])
        # Copies, constants and plaintext additions are not charged.
        for tag in (MODEL.LOAD_STATE, MODEL.STORE_STATE, MODEL.LOAD_CONST, MODEL.ADD_PLAIN, MODEL.SUB_PLAIN):
            self.assertEqual(plan["by_opcode"][tag], [0] * 5)
        self.assertEqual(plan["by_opcode"][MODEL.MUL_PLAIN], [1, 0, 0, 0, p.plaintext_multiplication_units(top)])
        self.assertEqual(plan["by_opcode"][MODEL.MUL][:3], [0, 1, 1])
        self.assertEqual(plan["by_opcode"][MODEL.SELECT_EQ_ZERO][:3], [0, 10, 10])
        self.assertEqual(plan["by_opcode"][MODEL.OUTPUT][0], 2)
        self.assertEqual(plan["by_opcode"][MODEL.FINAL_MASK][0], 1)
        for index in range(5):
            self.assertEqual(plan["total"][index], sum(work[index] for work in plan["by_opcode"]))
        # The input, four registers and 32 lanes at the top level, then the output accumulator.
        ciphertext = p.residue_bytes(top)
        self.assertGreater(plan["peak_persistent_bytes"], 37 * ciphertext)
        self.assertLessEqual(plan["peak_persistent_bytes"], 38 * ciphertext)
        self.assertGreaterEqual(
            plan["peak_working_bytes"], 37 * ciphertext + 2 * ciphertext + p.key_switch_scratch_bytes(top)
        )
        self.assertLessEqual(plan["bound"], plan["capacity"])
        # The affine profile is the bounded one without its two multiplicative instructions.
        affine = MODEL.plan_tape(p, MODEL.INSTRUCTION_PROFILE_AFFINE)
        self.assertEqual(affine["instructions"][MODEL.MUL], 0)
        self.assertEqual(affine["instructions"][MODEL.SELECT_EQ_ZERO], 0)
        self.assertEqual(affine["total"][MODEL.CM], 0)
        self.assertEqual(affine["costliest"][MODEL.LOAD_INPUT], plan["costliest"][MODEL.LOAD_INPUT])

    def test_a_short_chain_is_refused_at_the_instruction_that_exceeds_it(self) -> None:
        tape = MODEL.INSTRUCTION_PROFILE_BOUNDED
        refused = MODEL.plan_tape(self.small(5), tape)
        self.assertEqual(refused, {"fits": False, "instruction": 10, "tag": MODEL.SELECT_EQ_ZERO})
        # A chain that cannot hold a fresh ciphertext refuses before the first instruction.
        narrow = MODEL.Profile("narrow", 8, 257, (22, 1), (23, 1), 1)
        self.assertEqual(MODEL.plan_tape(narrow, tape), {"fits": False, "instruction": 0, "tag": MODEL.LOAD_INPUT})
        with self.assertRaises(ValueError):
            machine = MODEL.TapeMachine(self.small())
            machine.step((MODEL.LOAD_CONST, 0, 1))
            machine.finish()
        with self.assertRaises(ValueError):
            MODEL.TapeMachine(self.small()).step((99,))

    def test_products_are_lowered_while_the_capacity_ratio_grows(self) -> None:
        p = self.small()
        machine = MODEL.TapeMachine(p)
        top = p.top
        large = (1 << 100, top)
        self.assertTrue(machine._lower_multiplication(large, large))
        floor = machine._switch_down_shape(machine._switch_down_shape(large))
        self.assertFalse(machine._lower_multiplication(floor, floor))
        self.assertFalse(machine._lower_multiplication((100, 0), (100, 0)))
        # The decision is the exact comparison of the two ratios, admitted or not.
        for bits in range(20, 200, 7):
            operand = (1 << bits, top)
            here = p.degree * operand[0] ** 2 + p.key_switch_noise(top)
            lower = machine._switch_down_shape(operand)
            there = p.degree * lower[0] ** 2 + p.key_switch_noise(top - 1)
            self.assertEqual(
                machine._lower_multiplication(operand, operand),
                p.capacity(top - 1) * here > p.capacity(top) * there,
                bits,
            )
        # A squaring switches its operand once; a product of two values switches both.
        machine.current = [0] * 5
        machine._lowered_product(large, large, True)
        squared = machine.current[MODEL.MS]
        machine.current = [0] * 5
        machine._lowered_product(large, large, False)
        self.assertEqual(machine.current[MODEL.MS], 2 * squared)
        self.assertGreater(squared, 0)

    def test_the_families_have_the_maximum_shape_their_names_claim(self) -> None:
        self.assertEqual(len(MODEL.FAMILIES), 9)
        for name, (cls, _description, tape) in MODEL.FAMILIES.items():
            self.assertTrue(name.startswith(cls.split(".")[0]), name)
            self.assertLessEqual(len(tape), MODEL.MAX_INSTRUCTIONS, name)
            outputs = sum(1 for item in tape if item[0] == MODEL.OUTPUT)
            self.assertTrue(1 <= outputs <= MODEL.MAX_OUTPUTS, name)
            rank = MODEL.peak_rank(tape)
            if cls == "affine.v1":
                self.assertTrue(all(item[0] in MODEL.AFFINE_OPCODES for item in tape), name)
                self.assertEqual(rank, 0, name)
            else:
                self.assertLessEqual(rank, MODEL.BOUNDED_MAX_RANK, name)

        def count(name: str, tag: int) -> int:
            return sum(1 for item in MODEL.FAMILIES[name][2] if item[0] == tag)

        self.assertEqual((len(MODEL.FAMILIES["affine.loads"][2]), count("affine.loads", MODEL.LOAD_INPUT)), (256, 255))
        self.assertEqual(count("affine.scale_chain", MODEL.MUL_PLAIN), 254)
        self.assertEqual(count("affine.scale_then_outputs", MODEL.OUTPUT), 64)
        self.assertEqual(count("affine.state_and_registers", MODEL.STORE_STATE), 32)
        self.assertEqual(len(MODEL.FAMILIES["affine.state_and_registers"][2]), 256)
        self.assertEqual(count("bounded.selects", MODEL.SELECT_EQ_ZERO), 255)
        self.assertEqual(MODEL.peak_rank(MODEL.FAMILIES["bounded.selects"][2]), 10)
        self.assertEqual(
            (count("bounded.scaled_rank_chain", MODEL.MUL_PLAIN), count("bounded.scaled_rank_chain", MODEL.MUL)),
            (238, 16),
        )
        self.assertEqual(len(MODEL.FAMILIES["bounded.scaled_rank_chain"][2]), 256)
        for name in ("bounded.scaled_rank_chain", "bounded.rank_chain_outputs", "bounded.alternating_rank_chain", "bounded.select_then_products"):
            self.assertEqual(MODEL.peak_rank(MODEL.FAMILIES[name][2]), 16, name)
        self.assertEqual(MODEL.candidate_families(AFFINE), [name for name in MODEL.FAMILIES if name.startswith("affine")])
        self.assertEqual(MODEL.candidate_families(REFRESH), list(MODEL.FAMILIES))
        self.assertEqual(MODEL.instruction_profile(AFFINE), MODEL.INSTRUCTION_PROFILE_AFFINE)
        self.assertEqual(MODEL.instruction_profile(BOUNDED), MODEL.INSTRUCTION_PROFILE_BOUNDED)
        self.assertEqual(MODEL.opcode_label(7), "MulPlain")
        self.assertEqual(MODEL.opcode_label(11), "final zeroing mask")

    def test_no_candidate_holds_the_maximum_shape_lowered_instruction_by_instruction(self) -> None:
        summary = tracked_summary()
        classes = summary["class_cost_model"]
        for cls, name in (("affine.v1", AFFINE), ("bounded.v1", BOUNDED), ("refresh.v1", REFRESH)):
            block = classes[cls]
            self.assertEqual(block["profile"], name)
            self.assertFalse(block["holds_every_planned_family"])
            self.assertIn("affine.scale_chain", block["maximum_shape_families_refused"])
            needed = block["main_primes_for_every_planned_family"]["value"]
            self.assertGreater(needed, block["main_primes_in_candidate"]["value"])
        self.assertIn("bounded.scaled_rank_chain", classes["bounded.v1"]["maximum_shape_families_refused"])
        # What the bounded candidate does hold, and what a rank-16 chain leaves for constants.
        for family in ("bounded.selects", "bounded.rank_chain_outputs", "bounded.select_then_products"):
            self.assertIn(family, classes["bounded.v1"]["maximum_shape_families_that_fit"])
        shape = MODEL.CANDIDATES[BOUNDED]
        fits = {rank: MODEL.frontier_scales(shape, rank) for rank in (0, 10, 16)}
        self.assertTrue(fits[0] > fits[10] > fits[16] > 0, fits)
        self.assertLess(fits[16], 238)
        for rank, scales in fits.items():
            self.assertTrue(MODEL.cached_plan(shape, MODEL._frontier(rank, scales, 64))["fits"])
            self.assertFalse(MODEL.cached_plan(shape, MODEL._frontier(rank, scales + 1, 64))["fits"])
        # The fewest primes of a family: it fits that chain and not one prime less.
        tape = MODEL.FAMILIES["bounded.rank_chain_outputs"][2]
        minimal = MODEL.tape_minimal_main_primes(shape, tape)
        self.assertLessEqual(minimal, 22)
        self.assertTrue(MODEL.cached_plan(MODEL.with_main_primes(shape, minimal), tape)["fits"])
        self.assertFalse(MODEL.cached_plan(MODEL.with_main_primes(shape, minimal - 1), tape)["fits"])
        self.assertEqual(MODEL.largest_main_primes(shape), 62)
        # A refresh has no lowering; the candidate is planned as one segment, and the cited
        # bootstrapping depth does not fit beside it.
        room = classes["refresh.v1"]["refresh_room_projection"]
        self.assertEqual(room["cited_bootstrapping_depth"]["class"], "parameter")
        self.assertFalse(room["fits_beside_the_segment"])
        self.assertIn("not implemented", classes["refresh.v1"]["refresh_algorithm"])

    def test_flooding_is_a_labelled_projection_with_its_formula(self) -> None:
        p = self.small(4)
        fresh = p.fresh_noise()
        for bound, releases, kappa in ((1, 0, 0), (257, 3, 5), (1_000_003, 20, 40)):
            error = -(-bound // 257)
            self.assertEqual(
                MODEL.flooded_bound(p, bound, releases, kappa),
                bound + ((error * 256) << (releases + kappa)) * 257 + fresh,
            )
        summary = tracked_summary()
        self.assertIn("not a construction", summary["tape_lowering"]["sanitization_projection"])
        plan = summary["tape_lowering"]["candidates"][BOUNDED]["families"]["bounded.rank_chain_outputs"]
        flooding = plan["with_flooding_sanitization"]
        self.assertEqual([(entry["log2_releases"]["value"], entry["kappa"]["value"]) for entry in flooding], [(20, 80), (20, 40)])
        for entry in flooding:
            self.assertEqual(entry["kappa"]["class"], "parameter")
            # The flood adds log2(H) + log2(N) + kappa bits and never lowers the primes needed.
            self.assertGreaterEqual(
                entry["flooded_noise_bound_bits"]["value"],
                plan["output_noise_bound_bits"]["value"] + 20 + 16 + entry["kappa"]["value"] - 9,
            )
            self.assertGreaterEqual(entry["minimal_main_primes"]["value"], plan["minimal_main_primes"]["value"])
        self.assertGreaterEqual(flooding[0]["minimal_main_primes"]["value"], flooding[1]["minimal_main_primes"]["value"])

    def test_contract_inputs_charge_the_costliest_affine_instruction(self) -> None:
        summary = tracked_summary()
        for name, shape in MODEL.CANDIDATES.items():
            p = MODEL.profile(name, shape)
            inputs = summary["resource_contract_inputs"][name]
            load = p.plaintext_multiplication_units(p.top) + 7 * p.key_switch_units(p.top)
            self.assertEqual(inputs["ram_lfe.plain_operation_work_units"]["value"], load)
            # It is the costliest affine instruction of the lowering, far above a plaintext multiplication.
            costs = summary["tape_lowering"]["candidates"][name]["instruction_costs"]
            affine = [costs[MODEL.OPCODES[tag]]["work_units"]["value"] for tag in MODEL.AFFINE_OPCODES]
            self.assertEqual(max(affine), load)
            self.assertEqual(costs["LoadInput"]["work_units"]["value"], load)
            self.assertGreater(load, 10 * p.plaintext_multiplication_units(p.top))
            self.assertEqual(
                inputs["proposed_additional_inputs"]["ram_lfe.key_switch_work_units"]["value"],
                p.key_switch_units(p.top),
            )
            budgets = inputs["budget_formulas_against_planned_families"]
            affine_budget = budgets["ram_lfe.affine_evaluation_work_units"]
            self.assertEqual(affine_budget["formula_value"]["value"], 256 * load)
            self.assertEqual(affine_budget["largest_planned_family"], "affine.loads")
            self.assertTrue(affine_budget["covers_every_planned_family_that_fits"])
            # A plaintext multiplication as the input would not cover 255 loads.
            self.assertLess(
                256 * p.plaintext_multiplication_units(p.top), affine_budget["largest_planned_work_units"]["value"]
            )
            if name != AFFINE:
                bounded_budget = budgets["ram_lfe.bounded_evaluation_work_units"]
                self.assertEqual(bounded_budget["largest_planned_family"], "bounded.selects")
                self.assertTrue(bounded_budget["covers_every_planned_family_that_fits"])

    def test_the_input_proof_projection_follows_its_stated_layout(self) -> None:
        toy = MODEL.Profile("toy", 8, 257, (40, 3), (41, 2), 2)
        block = MODEL.input_relation_block(toy)
        n, primes, slots = 256, 3, 128
        butterflies = n // 2 * 8
        chain = primes * (3 * butterflies + 4 * n)
        slot_butterflies = slots // 2 * 7
        self.assertEqual(block["secret_coefficients_range_checked"]["value"], 3 * n)
        self.assertEqual(block["plaintext_slots_range_checked"]["value"], slots)
        self.assertEqual(block["plaintext_coefficients_fixed_to_zero"]["value"], n - slots)
        self.assertEqual(block["slot_transform_butterflies"]["value"], slot_butterflies)
        self.assertEqual(block["ciphertext_coefficient_equations"]["value"], 2 * primes * n)
        self.assertEqual(block["chain_residue_multiplications"]["value"], chain)
        # A 40-bit prime is three 16-bit limbs; 257 is one.
        self.assertEqual(block["limbs_per_chain_residue"]["value"], 3)
        self.assertEqual(block["limb_products"]["value"], 9 * chain + slot_butterflies)
        encoding_specific = 2 * slot_butterflies + slots
        self.assertEqual(block["encoding_specific_range_checked_limbs"]["value"], encoding_specific)
        self.assertEqual(
            block["range_checked_limbs"]["value"], 6 * chain + encoding_specific + 3 * n + 2 * primes * n
        )
        self.assertEqual(block["rows_at_one_multiplication_per_row"]["value"], chain + slot_butterflies)
        self.assertEqual((MODEL.limbs_of(1), MODEL.limbs_of(16), MODEL.limbs_of(17), MODEL.limbs_of(60)), (1, 1, 2, 4))
        for item in block.values():
            self.assertEqual(item["class"], "projection")
        summary = tracked_summary()
        projection = summary["proof_work_projection"]
        self.assertIn("projection only", projection["status"])
        sparse = projection["input_relation"][MODEL.SPARSE_CONFIG]
        batching = projection["input_relation"][MODEL.BATCHING_CONFIG]
        # The encryption relation dominates both; the encoding-specific part differs by orders.
        self.assertLess(sparse["encoding_specific_share_ppm"]["value"], 10)
        self.assertGreater(
            batching["encoding_specific_range_checked_limbs"]["value"],
            1000 * sparse["encoding_specific_range_checked_limbs"]["value"],
        )
        self.assertGreater(batching["range_checked_limbs"]["value"], sparse["range_checked_limbs"]["value"])
        # The execution relation is one constrained multiplication per model work unit.
        units = summary["tape_lowering"]["candidates"][BOUNDED]["families"]["bounded.selects"]["work"]["work_units"]["value"]
        execution = projection["execution_relation"][BOUNDED]["bounded.selects"]
        self.assertEqual(execution["residue_multiplications"]["value"], units)
        self.assertEqual(execution["range_checked_limbs"]["value"], 8 * units)
        self.assertNotIn("bounded.scaled_rank_chain", projection["execution_relation"][BOUNDED])


class ReferenceVectorsTest(unittest.TestCase):
    def test_known_answer_file_is_the_output_of_the_python_reference(self) -> None:
        result = subprocess.run([sys.executable, str(REFERENCE), "--check"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reference_blake3_matches_the_official_empty_and_abc_digests(self) -> None:
        spec = importlib.util.spec_from_file_location("bgv_reference", REFERENCE)
        assert spec and spec.loader
        reference = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = reference
        spec.loader.exec_module(reference)
        # Plain BLAKE3 of the empty string and of "abc" (published test values) through the
        # same compression function the derive_key mode uses.
        empty = reference._Output(reference.IV, b"", 0).read(32).hex()
        self.assertEqual(empty, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        abc = reference._Output(reference.IV, b"abc", 0).read(32).hex()
        self.assertEqual(abc, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")


class EstimatorRecordTest(unittest.TestCase):
    """The Lattice Estimator numbers of the summary are the tracked output record, restated."""

    def record(self) -> dict:
        return MODEL.read_estimator_record((ROOT / MODEL.ESTIMATOR_OUTPUT).read_text())

    def test_the_record_is_the_output_of_the_script_as_it_stands(self) -> None:
        self.assertEqual(MODEL.estimator_record_problems(ROOT), [])
        script = (ROOT / MODEL.ESTIMATOR_SCRIPT).read_text()
        self.assertIn("STATUS: RUN", script)
        self.assertNotIn("NOT RUN", script)
        self.assertIn("ND.CenteredBinomial(ZZ(ERROR_ETA))", script)
        self.assertIn("ND.Uniform(ZZ(-1), ZZ(1))", script)
        facts = MODEL.estimator_script_facts(ROOT)
        self.assertRegex(facts["commit"], r"^[0-9a-f]{40}$")
        record = self.record()
        self.assertGreaterEqual(len(record["RUN"]), 1)
        for run, end in record["invocations"]:
            self.assertEqual(run["estimator_commit"], facts["commit"])
            self.assertEqual(run["estimator_commit_expected"], facts["commit"])
            self.assertEqual(run["script_code_sha256"], facts["code_sha256"])
            self.assertIn("SageMath version", run["sagemath"])
            self.assertTrue(run["command"].startswith("PYTHONPATH="))
            self.assertIn(f"sage {MODEL.ESTIMATOR_SCRIPT}", run["command"])
            self.assertIsNotNone(end)
        self.assertTrue(all(check["equal_to_LWE_estimate"] for check in record["SELFCHECK"]))
        # The header of the script does not enter the hash; its code does.
        with ScratchRoot(MODEL.ESTIMATOR_SCRIPT, "# Purpose\n", "# Purpose of this script\n") as root:
            self.assertEqual(MODEL.estimator_script_facts(root), facts)
        with ScratchRoot(MODEL.ESTIMATOR_SCRIPT, "ERROR_ETA = 21\n", "ERROR_ETA = 20\n") as root:
            self.assertNotEqual(MODEL.estimator_script_facts(root)["code_sha256"], facts["code_sha256"])
            problems = MODEL.check_summary(tracked_summary(), root)
        self.assertTrue(any("produced by other code" in problem for problem in problems), problems)

    def test_the_estimated_instances_are_the_moduli_of_the_pinned_profiles(self) -> None:
        record = self.record()
        profiles = MODEL.estimated_profiles()
        self.assertEqual(set(profiles), set(MODEL.CANDIDATES) | {name for name, _shape in MODEL.MEASURED_CONFIGS.values()})
        tables = MODEL.rust_prime_tables(ROOT)
        pinned = {
            AFFINE: (tables["F257_N14_MAIN_PRIMES"], tables["F257_N14_SPECIAL_PRIMES"]),
            BOUNDED: (tables["F257_N16_MAIN_PRIMES"][:22], tables["F257_N16_SPECIAL_PRIMES"]),
            REFRESH: (tables["F257_N16_MAIN_PRIMES"], tables["F257_N16_SPECIAL_PRIMES"]),
        }
        seen = set()
        for instance in record["INSTANCE"]:
            if not instance["pinned"]:
                continue
            seen.add((instance["profile"], instance["instance"]))
            self.assertEqual(instance["error"], "centered binomial, eta = 21")
            self.assertEqual(instance["secret"], "uniform ternary on {-1, 0, 1}")
            self.assertAlmostEqual(instance["error_stddev"], math.sqrt(10.5), places=5)
            self.assertAlmostEqual(instance["secret_stddev"], math.sqrt(2 / 3), places=5)
            if instance["profile"] in pinned:
                # The modulus the estimator was given is the product of the primes the Rust file pins.
                main, special = pinned[instance["profile"]]
                modulus = math.prod(main) * (math.prod(special) if instance["modulus"] == "QP" else 1)
                self.assertEqual(instance["q"], str(modulus))
                self.assertEqual(instance["modulus_bits"], modulus.bit_length())
        self.assertEqual(seen, {(name, instance) for name in profiles for instance in MODEL.ESTIMATOR_INSTANCES})
        # A changed dimension, modulus or distribution in the record is detected.
        for old, new, expected in (
            ('"n": 16384', '"n": 8192', "the modulus or the dimension"),
            ('"q": "1', '"q": "2', "the modulus or the dimension"),
            ("eta = 21", "eta = 3", "the error distribution"),
            ("uniform ternary on {-1, 0, 1}", "uniform binary", "the secret distribution"),
        ):
            with ScratchRoot() as root:
                path = root / MODEL.ESTIMATOR_OUTPUT
                self.assertIn(old, path.read_text())
                path.write_text(path.read_text().replace(old, new))
                problems = MODEL.estimator_record_problems(root)
            self.assertTrue(any(expected in problem for problem in problems), (expected, problems))

    def test_every_estimator_number_is_a_result_line_of_the_record(self) -> None:
        estimator = tracked_summary()["security_estimate"]["lattice_estimator"]
        results = MODEL.estimator_results(self.record())
        self.assertEqual(
            estimator["output_record_sha256"],
            hashlib.sha256((ROOT / MODEL.ESTIMATOR_OUTPUT).read_bytes()).hexdigest(),
        )
        finished = 0
        for name, block in estimator["profiles"].items():
            self.assertEqual(set(block["instances"]), set(MODEL.ESTIMATOR_INSTANCES))
            for instance, item in block["instances"].items():
                self.assertEqual(set(item["models"]), set(MODEL.ESTIMATOR_MODELS))
                groups = [(model, entry["attacks"]) for model, entry in item["models"].items()]
                groups.append((MODEL.ESTIMATOR_MODEL_FREE, item["attacks_without_a_cost_model"]))
                for model, attacks in groups:
                    for attack, entry in attacks.items():
                        result = results.get((name, instance, model, attack))
                        if result is None:
                            self.assertEqual(entry["status"], "not_attempted")
                            self.assertNotIn("log2_cost", entry)
                            continue
                        self.assertEqual(entry["status"], result["status"])
                        if result["status"] != "ok":
                            # An attack without a cost carries its reason, never a number of bits.
                            self.assertNotIn("log2_cost", entry)
                            self.assertEqual(entry["reason"], result["message"])
                        elif result["log2_rop"] == "oo":
                            self.assertEqual(entry["log2_cost"], "infinite")
                        else:
                            finished += 1
                            self.assertEqual(entry["log2_cost"], {"value": result["log2_rop"], "unit": "bits", "class": "estimator"})
                # The minimum of a cost model is the cheapest of its finished attacks.
                for model, entry in item["models"].items():
                    costs = [
                        attack["log2_cost"]["value"]
                        for attack in entry["attacks"].values()
                        if isinstance(attack.get("log2_cost"), dict)
                    ]
                    if costs:
                        self.assertEqual(entry["minimum"]["log2_cost"]["value"], min(costs))
                    else:
                        self.assertNotIn("minimum", entry)
        # The four attacks that always finish cover every profile, instance and cost model.
        self.assertGreaterEqual(finished, 5 * 3 * 3 * 4)

    def test_the_verdicts_follow_the_design_target(self) -> None:
        estimator = tracked_summary()["security_estimate"]["lattice_estimator"]
        self.assertEqual(estimator["design_target"]["classical_bits"]["value"], 128)
        self.assertEqual(estimator["design_target"]["cost_model"], "BDGL16")
        for name, block in estimator["profiles"].items():
            for model in MODEL.ESTIMATOR_MODELS:
                verdict = block["verdict"][model]
                lowest = min(
                    entry["minimum"]["log2_cost"]["value"]
                    for entry in (item["models"][model] for item in block["instances"].values())
                    if "minimum" in entry
                )
                self.assertLessEqual(verdict["minimum_log2_cost"]["value"], lowest)
                self.assertTrue(verdict["minimum_instance"].startswith("QP"), (name, model))
                if model in MODEL.ESTIMATOR_CLASSICAL_MODELS:
                    self.assertEqual(
                        verdict["meets_design_target_on_the_attacks_with_a_cost"],
                        verdict["minimum_log2_cost"]["value"] >= 128,
                    )
                    self.assertAlmostEqual(
                        verdict["margin_bits"]["value"], verdict["minimum_log2_cost"]["value"] - 128, places=3
                    )
                else:
                    self.assertNotIn("meets_design_target_on_the_attacks_with_a_cost", verdict)
            # The quantum exponent is below the classical one of the same model family.
            self.assertLess(
                block["verdict"]["ADPS16-quantum"]["minimum_log2_cost"]["value"],
                block["verdict"]["ADPS16"]["minimum_log2_cost"]["value"],
            )
        # What the record says about the three candidates: all pass under the cost model the
        # design memo names; under core-SVP only the bounded candidate does.
        verdicts = {name: estimator["profiles"][name]["verdict"] for name in (AFFINE, BOUNDED, REFRESH)}
        for name in (AFFINE, BOUNDED, REFRESH):
            self.assertTrue(verdicts[name]["BDGL16"]["meets_design_target_on_the_attacks_with_a_cost"], name)
        self.assertFalse(verdicts[AFFINE]["ADPS16"]["meets_design_target_on_the_attacks_with_a_cost"])
        self.assertTrue(verdicts[BOUNDED]["ADPS16"]["meets_design_target_on_the_attacks_with_a_cost"])
        self.assertFalse(verdicts[REFRESH]["ADPS16"]["meets_design_target_on_the_attacks_with_a_cost"])
        # Nothing of this qualifies a profile, and the limits are stated beside the numbers.
        self.assertIn("No profile is qualified", tracked_summary()["security_estimate"]["status"])
        limits = " ".join(estimator["not_covered"])
        for phrase in ("ring structure", "circular-security", "not sampled honestly", "side channels", "maximum shape", "review"):
            self.assertIn(phrase, limits)

    def test_the_core_svp_sanity_numbers_are_kept_and_compared(self) -> None:
        summary = tracked_summary()
        estimator = summary["security_estimate"]["lattice_estimator"]
        for name, shape in MODEL.CANDIDATES.items():
            comparison = estimator["profiles"][name]["core_svp_sanity_comparison"]
            sanity = summary["candidates"][name]["security_sanity"]
            self.assertEqual(comparison["core_svp_classical"]["sanity_bits"], sanity["core_svp_classical_bits"])
            self.assertEqual(comparison["bdgl16_style_classical"]["sanity_bits"], sanity["bdgl16_style_classical_bits"])
            self.assertEqual(comparison["block_size"]["sanity"], sanity["bkz_block_size"])
            usvp = estimator["profiles"][name]["instances"]["QP:n"]["models"]["ADPS16"]["attacks"]["usvp"]
            self.assertEqual(comparison["core_svp_classical"]["estimator_bits"], usvp["log2_cost"])
            self.assertEqual(comparison["block_size"]["estimator"], usvp["block_size"])
            # ADPS16 is 0.292 * beta: the estimator's cost is its own block size times the exponent.
            self.assertAlmostEqual(usvp["log2_cost"]["value"], 0.292 * usvp["block_size"]["value"], places=3)
            # No large discrepancy: the sanity formula and the estimator's primal uSVP agree within a bit.
            self.assertTrue(comparison["agrees_within_one_bit"], name)
            self.assertLessEqual(comparison["largest_difference_bits"]["value"], 1.0)

    def test_an_attack_without_a_cost_is_reported_with_its_reason(self) -> None:
        identity = {"profile": AFFINE, "instance": "QP:n", "model": "BDGL16", "attack": "bdd_hybrid"}
        timeout = dict(identity, status="timeout", message="stopped at the limit of 3600 seconds", seconds=3600.2)
        done = dict(identity, status="ok", log2_rop=136.5, seconds=412.0, cost={"beta": 350, "d": 31000, "zeta": 0, "rop": {"log2": 136.5}})
        self.assertEqual(
            MODEL._attack_entry(timeout),
            {
                "status": "timeout",
                "reason": "stopped at the limit of 3600 seconds",
                "seconds": {"value": 3600.2, "unit": "seconds", "class": "estimator"},
            },
        )
        self.assertEqual(MODEL._attack_entry(None)["status"], "not_attempted")
        entry = MODEL._attack_entry(done)
        self.assertEqual(entry["log2_cost"]["value"], 136.5)
        self.assertEqual(entry["block_size"], {"value": 350, "unit": "count", "class": "estimator"})
        self.assertEqual(entry["guessed_coordinates"]["value"], 0)
        infinite = MODEL._attack_entry(dict(done, log2_rop="oo", cost={"rop": "oo"}))
        self.assertEqual(infinite["log2_cost"], "infinite")
        self.assertEqual(MODEL._cost_cell(infinite), "infinite")
        self.assertEqual(MODEL._cost_cell(MODEL._attack_entry(timeout)), "timeout")
        self.assertEqual(MODEL._cost_cell(entry), "136.5")
        # A finished attempt is reported whether it comes before or after one that was cut off.
        key = (AFFINE, "QP:n", "BDGL16", "bdd_hybrid")
        for order in ((timeout, done), (done, timeout)):
            self.assertEqual(MODEL.estimator_results({"RESULT": list(order)})[key]["status"], "ok")
        self.assertEqual(MODEL.estimator_results({"RESULT": [timeout, dict(timeout, status="stopped")]})[key]["status"], "stopped")
        # An invocation that was cut off has no END line, and the check says so.
        text = 'RUN {"a": 1}\nRESULT ' + json.dumps(done) + '\nRUN {"a": 2}\nEND {"b": 3}\nnoise line\n'
        record = MODEL.read_estimator_record(text)
        self.assertEqual(record["invocations"], [[{"a": 1}, None], [{"a": 2}, {"b": 3}]])
        self.assertEqual(len(record["RESULT"]), 1)
        with ScratchRoot() as root:
            path = root / MODEL.ESTIMATOR_OUTPUT
            lines = path.read_text().splitlines(keepends=True)
            last_end = max(index for index, line in enumerate(lines) if line.startswith("END "))
            path.write_text("".join(lines[:last_end] + lines[last_end + 1 :]))
            problems = MODEL.estimator_record_problems(root)
        self.assertTrue(any("no END line" in problem for problem in problems), problems)

    def test_a_changed_record_is_detected(self) -> None:
        summary = tracked_summary()
        expected = f"security_estimate: differs from its recomputation from {MODEL.ESTIMATOR_OUTPUT}"
        tracked = (ROOT / MODEL.ESTIMATOR_OUTPUT).read_text().splitlines(keepends=True)
        index = next(
            index
            for index, item in enumerate(tracked)
            if item.startswith("RESULT ") and '"attack": "usvp"' in item and f'"profile": "{REFRESH}"' in item
        )
        result = json.loads(tracked[index][len("RESULT ") :])
        result["log2_rop"] += 40
        changed = "RESULT " + json.dumps(result, sort_keys=True) + "\n"
        for replacement in (changed, ""):
            with ScratchRoot() as root:
                (root / MODEL.ESTIMATOR_OUTPUT).write_text("".join(tracked[:index] + [replacement] + tracked[index + 1 :]))
                self.assertEqual(MODEL.check_summary(summary, root), [expected])
                # Rebuilding the summary from the changed record gives another block.
                rebuilt = MODEL.rederive(summary, root)
                self.assertNotEqual(rebuilt["security_estimate"], summary["security_estimate"])
                self.assertEqual(rebuilt["candidates"], summary["candidates"])
        # Without the record the summary would say that nothing was run, and the check fails.
        with ScratchRoot() as root:
            (root / MODEL.ESTIMATOR_OUTPUT).unlink()
            self.assertEqual(MODEL.estimator_block(root)["status"], "not_run")
            self.assertEqual(MODEL.check_summary(summary, root), [f"{MODEL.ESTIMATOR_OUTPUT} is missing"])

    def test_the_numbers_quoted_in_the_crate_documentation_are_those_of_the_summary(self) -> None:
        estimator = tracked_summary()["security_estimate"]["lattice_estimator"]
        source = (ROOT / MODEL.PROFILE_SOURCE).read_text()
        readme = " ".join((ROOT / "crates" / "iroha_fhe" / "README.md").read_text().split())
        for name, variant, label in (
            (AFFINE, "AffineF257", "affine"),
            (BOUNDED, "BoundedF257", "bounded"),
            (REFRESH, "RefreshF257", "refresh"),
        ):
            verdict = estimator["profiles"][name]["verdict"]
            cells = [f"{verdict[model]['minimum_log2_cost']['value']:.1f}" for model in MODEL.ESTIMATOR_MODELS]
            self.assertIn(f"/// | [`Self::{variant}`] | " + " | ".join(cells) + " |", source)
            self.assertIn(f"{label} " + " / ".join(cells), readme)
        # The documentation states the limits beside the numbers and qualifies nothing.
        for text in (source, readme):
            self.assertIn("ring structure", text)
            self.assertIn("circular-security", text)
            self.assertIn("side channels", text)
        self.assertIn("No candidate is qualified", source)
        self.assertIn("No candidate is qualified", readme)

    def test_shapes_outside_the_pinned_list_are_proposals(self) -> None:
        self.assertEqual(MODEL.proposal_shape("bgv.derive.n14.t257.q4x50.p2x60"), (14, 257, (50, 4), (60, 2), 2))
        self.assertIsNone(MODEL.proposal_shape("bgv.derive.n14.t257.q13x50.p2x60.d2"))
        self.assertIsNone(MODEL.proposal_shape(AFFINE))
        self.assertEqual(MODEL._variation_of((14, 257, (50, 4), (60, 2), 2)), (AFFINE, "main_primes"))
        self.assertEqual(MODEL._variation_of((15, 257, (50, 6), (60, 2), 2)), (AFFINE, "ring_degree"))
        self.assertEqual(MODEL._variation_of((17, 257, (50, 32), (60, 2), 2)), (REFRESH, "ring_degree"))
        # Between two candidates of one ring degree a chain is a shorter chain of the longer one.
        self.assertEqual(MODEL._variation_of((16, 257, (50, 26), (60, 2), 2)), (REFRESH, "main_primes"))
        self.assertEqual(MODEL._variation_of((16, 257, (50, 20), (60, 2), 2)), (BOUNDED, "main_primes"))
        self.assertEqual(MODEL._variation_of((16, 257, (50, 40), (60, 2), 2)), (REFRESH, "main_primes"))
        self.assertIsNone(MODEL._variation_of((14, 257, (50, 4), (60, 3), 2)))
        proposals = tracked_summary()["security_estimate"]["lattice_estimator"]["proposals"]
        self.assertIn("not changes", proposals["status"])
        self.assertEqual(set(proposals["shortfalls_and_smallest_changes"]), set(MODEL.CANDIDATES))
        # No shape of the proposals is a pinned profile, and each names the candidate it varies.
        for name, block in proposals["shapes"].items():
            self.assertNotIn(name, MODEL.estimated_profiles())
            self.assertIn(block["varies"]["candidate"], MODEL.CANDIDATES)
        # A shortfall is recorded exactly where a classical verdict fails, with a change that meets it.
        estimator = tracked_summary()["security_estimate"]["lattice_estimator"]
        for name in MODEL.CANDIDATES:
            failing = {
                model
                for model in MODEL.ESTIMATOR_CLASSICAL_MODELS
                if not estimator["profiles"][name]["verdict"][model]["meets_design_target_on_the_attacks_with_a_cost"]
            }
            shortfalls = proposals["shortfalls_and_smallest_changes"][name]
            self.assertEqual(set(shortfalls), failing, name)
            for model, entry in shortfalls.items():
                self.assertGreater(entry["shortfall_bits"]["value"], 0)
                chain = entry["longest_chain_meeting_the_target_at_the_same_ring_degree"]
                self.assertTrue(chain["the_next_longer_chain_is_recorded_and_fails"], (name, model))
                shape = proposals["shapes"][chain["shape"]]
                self.assertTrue(shape["verdict"][model]["meets_design_target_on_the_attacks_with_a_cost"])
                self.assertLess(chain["main_primes"]["value"], MODEL.CANDIDATES[name][2][1])


if __name__ == "__main__":
    unittest.main()
