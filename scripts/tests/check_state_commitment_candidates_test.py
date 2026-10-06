"""Exercise the State commitment candidate comparison checker on synthetic records and on the repository."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts" / "check_state_commitment_candidates.py"
SPEC = importlib.util.spec_from_file_location("check_state_commitment_candidates", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

PROCESS = {
    "peak_rss_bytes": 4096,
    "peak_rss_bytes_at_begin": 2048,
    "load_milli_begin": 1500,
    "load_milli_finish": 2500,
    "thermal_begin": "nominal",
    "thermal_finish": "nominal",
}


def node(label: str, parent: int | None, wall: int, exclusive: int = 0) -> dict:
    """A phase whose process CPU time is twice its wall time."""
    return {
        "label": label,
        "parent": parent,
        "wall_inclusive_ns": wall,
        "wall_exclusive_ns": exclusive,
        "process_cpu_window_inclusive_ns": wall * 2,
    }


INVENTORY_SCHEMA = CHECKER.inventory_schema(REPOSITORY)
# The schema phase every flow records first: here, the tracked inventory's.
SCHEMA_PHASE = (
    "schema",
    1,
    {
        "schema.tables": INVENTORY_SCHEMA["tables"],
        "schema.cells": INVENTORY_SCHEMA["cells"],
        "schema.descriptor_bytes": INVENTORY_SCHEMA["descriptor_bytes"],
        "schema.descriptor_sha256_prefix": int(INVENTORY_SCHEMA["descriptor_sha256"][:16], 16),
    },
    {},
)


def record(workload: str, phases: list[tuple[str, int, dict, dict]]) -> dict:
    """A measurement record view: a root, the schema phase and the given phases as its children.

    A work counter is a total, or (count, total, min, max). A byte counter is
    (count, total, min, max).
    """
    nodes = [node("flow", None, 100_000, 50)]
    work = []
    sizes = []
    for label, wall, counters, byte_counters in [SCHEMA_PHASE, *phases]:
        index = len(nodes)
        nodes.append(node(label, 0, wall))
        for name, value in counters.items():
            count, total, low, high = value if isinstance(value, tuple) else (1, value, value, value)
            work.append(
                {"phase": index, "label": name, "count": count, "total_units": total, "min_units": low, "max_units": high}
            )
        for name, (count, total, low, high) in byte_counters.items():
            sizes.append(
                {"phase": index, "label": name, "count": count, "total_bytes": total, "min_bytes": low, "max_bytes": high}
            )
    return {
        "identity": {"workload": workload},
        "phase_tree": {"nodes": nodes},
        "work_counters": {"entries": work},
        "byte_counters": {"entries": sizes},
        "process": dict(PROCESS),
        "scheduling": {"workers": 20},
    }


HASH = {"hash.compressions": 40, "hash.byte_hashes": 20, "hash.hashed_bytes": 640, "hash.permutations": 0}
BUILD_WALLS = [2_000, 2_100, 1_900, 2_050, 2_500]


def native_phases(build_walls: list[int] = BUILD_WALLS, repeats: int = 5) -> list[tuple[str, int, dict, dict]]:
    phases: list[tuple[str, int, dict, dict]] = [("generate_workload", 100, {}, {})]
    for repetition in range(repeats):
        if repetition < len(build_walls):
            phases.append(
                (
                    f"r{repetition}.cold_build",
                    build_walls[repetition],
                    {"entries": 10, "heap.live_bytes": 3_000, "heap.peak_bytes": 4_500, **HASH},
                    {},
                )
            )
        phases.append((f"r{repetition}.update_set_100", 800 + 40 * repetition, {"change_sets": 4, "changes": 400, **HASH}, {}))
    phases.append(
        ("storage", 1, {"entries": 10, "structure_bytes": 1_036, "structure_digests": 29, "auxiliary_bytes": 0, "max_depth": 5}, {})
    )
    for repetition in range(repeats):
        phases += [
            (f"r{repetition}.prove_inclusion", 50, {"statements": 4}, {"witness": (4, 400, 90, 110)}),
            (f"r{repetition}.verify_inclusion", 80 + repetition, {"statements": 4, **HASH}, {}),
            (f"r{repetition}.prove_absence", 50, {"statements": 4}, {"witness": (4, 480, 110, 130)}),
            (f"r{repetition}.verify_absence", 80, {"statements": 4, **HASH}, {}),
            (f"r{repetition}.prove_range_16", 60, {"statements": 2, "claimed_entries": 32}, {"witness": (2, 2_000, 900, 1_100)}),
            (f"r{repetition}.verify_range_16", 90, {"statements": 2, **HASH}, {}),
        ]
    return phases


NATIVE = record("state_candidates.native.radix.blake2b.p16.scattered-32.v32", native_phases())

CIRCUIT = record(
    "state_candidates.circuit.radix.rescue-prime.p16.scattered-32.v32",
    [
        (
            "inclusion.statements",
            20,
            {
                "native_permutations": (4, 112, 27, 29),
                "permutations": (4, 112, 27, 29),
                "anchors": (4, 4, 1, 1),
                "registers": (4, 4, 1, 1),
                "rows": (4, 1_024, 256, 256),
                "private_siblings": (4, 88, 21, 23),
                "gadget_bit_scans": 0,
                "gadget_comparisons": 0,
            },
            {"native_witness": (4, 3_040, 724, 796)},
        ),
        (
            "inclusion.geometry",
            5,
            {
                "permutations": 28,
                "registers": 1,
                "rows": 256,
                "width": 64,
                "constraints": 22,
                "rows_per_permutation": 8,
                "private_siblings": 22,
                "exceeds_reference_rows": 0,
                "numerator_degree_bound": 2_041,
                "trace_cells": 16_384,
                "interpolation_rows": 2_048,
                "reference_declared_payload_bytes": 1_000_000,
                "reference_declared_work_units": 2_000_000,
                "reference_repeats": 3,
            },
            {},
        ),
        *[
            phase
            for repetition in range(3)
            for phase in (
                (f"r{repetition}.inclusion.witness_columns", 300 + repetition, {}, {}),
                (
                    f"r{repetition}.inclusion.reference_build",
                    9_000 + 100 * repetition,
                    {"heap.peak_bytes": 500_000 + repetition},
                    {"uncommitted_reference_artifact": (1, 180_000, 180_000, 180_000)},
                ),
                (f"r{repetition}.inclusion.reference_check", 8_000, {"heap.peak_bytes": 400_000}, {}),
            )
        ],
        (
            "range_1024.statements",
            20,
            {
                "native_permutations": (2, 60_000, 30_000, 30_000),
                "permutations": (2, 60_000, 30_000, 30_000),
                "anchors": (2, 2, 1, 1),
                "registers": (2, 23, 11, 12),
                "rows": (2, 524_288, 262_144, 262_144),
                "private_siblings": (2, 44, 22, 22),
                "gadget_bit_scans": 0,
                "gadget_comparisons": 2,
            },
            {"native_witness": (2, 140_000, 70_000, 70_000)},
        ),
        (
            "range_1024.geometry",
            5,
            {
                "permutations": 30_000,
                "registers": 12,
                "rows": 262_144,
                "width": 130,
                "constraints": 66,
                "rows_per_permutation": 8,
                "private_siblings": 22,
                "exceeds_reference_rows": 1,
            },
            {},
        ),
        ("forged_traces_rejected", 9, {"forged_traces_rejected": 3}, {}),
    ],
)

LATENCY = record(
    "state_candidates.latency.hash_profiles",
    [
        *[(f"r{repetition}.blake2b.compress", 1_500 + 10 * repetition, {"calls": 10}, {}) for repetition in range(5)],
        *[(f"r{repetition}.rescue-prime.permutation", 70_000, {"calls": 2}, {}) for repetition in range(5)],
        ("as_built_blake2b_gadget", 1, {"rows": 408, "columns": 310, "physical_rows_per_hash_slot": 512}, {}),
    ],
)

GADGET = record(
    "state_candidates.gadget.key_gadgets",
    [
        (
            "order_k36.geometry",
            2,
            {"key_bytes": 36, "rows": 64, "width": 42, "private_columns": 32, "constraints": 47, "numerator_degree_bound": 253, "trace_cells": 2_688, "reference_repeats": 3},
            {},
        ),
        *[
            phase
            for repetition in range(3)
            for phase in (
                (f"r{repetition}.order_k36.witness_columns", 10, {}, {}),
                (f"r{repetition}.order_k36.reference_build", 500 + repetition, {}, {}),
                (f"r{repetition}.order_k36.reference_check", 400, {}, {}),
            )
        ],
        ("false_statements_rejected", 1, {"false_statements_rejected": 4}, {}),
    ],
)

SHARED = record(
    "state_candidates.native.linked.blake2b.p16.scattered-32.v32",
    [
        *native_phases(),
        (
            "shared_paths_range_16",
            30,
            {"leaves": (2, 34, 17, 17), "carried_steps": (2, 680, 330, 350), "distinct_branches": (2, 160, 78, 82), "carried_siblings": (2, 128, 62, 66)},
            {"witness": (2, 25_000, 12_400, 12_600)},
        ),
    ],
)


def view(document: dict) -> object:
    return CHECKER.Record(document, "run-x", "child/a.json")


class RecordSummaries(unittest.TestCase):
    def test_workload_tags_are_read_from_the_workload_name(self) -> None:
        self.assertEqual(
            CHECKER.workload_tags("state_candidates.native.linked.rescue-prime.p20.shared-prefix-32.v256"),
            {
                "flow": "native",
                "construction": "linked",
                "profile": "rescue-prime",
                "population_log2": 20,
                "key_shape": "shared-prefix-32",
                "value_bytes": 256,
            },
        )

    def test_ratio_is_none_without_a_count(self) -> None:
        self.assertEqual(CHECKER.ratio(10, 4), 2.5)
        self.assertEqual(CHECKER.ratio(10, 3, 2), 3.33)
        self.assertIsNone(CHECKER.ratio(10, 0))
        self.assertIsNone(CHECKER.ratio(None, 4))

    def test_timing_is_the_minimum_median_and_maximum_per_unit(self) -> None:
        self.assertEqual(
            CHECKER.timing([300, 100, 200], 2),
            {"min": 50.0, "median": 100.0, "max": 150.0, "repetitions": 3},
        )
        self.assertEqual(CHECKER.timing([7], 1, 0), {"min": 7, "median": 7, "max": 7, "repetitions": 1})
        self.assertIsNone(CHECKER.timing([], 2))
        self.assertIsNone(CHECKER.timing([5], 0))

    def test_record_lookups_follow_phase_labels_and_repetitions(self) -> None:
        native = view(NATIVE)
        self.assertEqual(native.wall("r1.cold_build"), 2_100)
        self.assertEqual(native.units("r0.cold_build", "entries"), 10)
        self.assertIsNone(native.units("r0.cold_build", "absent"))
        self.assertIsNone(native.wall("absent"))
        self.assertEqual(native.walls("cold_build"), BUILD_WALLS)
        self.assertEqual(native.repetitions("verify_range_16")[4], "r4.verify_range_16")
        self.assertEqual(native.same_units("cold_build", "hash.compressions"), 40)
        self.assertIsNone(native.same_units("absent", "entries"))
        self.assertEqual(native.same_size("prove_inclusion", "witness")["total_bytes"], 400)
        self.assertEqual(
            native.labels()[:5], ["flow", "schema", "generate_workload", "cold_build", "update_set_100"]
        )
        provenance = native.provenance()
        self.assertEqual(provenance["class"], "measured")
        self.assertEqual(provenance["run"], "run-x")
        self.assertEqual(provenance["peak_rss_bytes"], 4096)
        self.assertEqual(provenance["flow_wall_ns"], 100_000)
        self.assertEqual(provenance["unattributed_ppm"], 500)

    def test_a_count_that_differs_between_repetitions_is_refused(self) -> None:
        document = copy.deepcopy(NATIVE)
        entry = next(
            entry
            for entry in document["work_counters"]["entries"]
            if entry["label"] == "hash.compressions" and document["phase_tree"]["nodes"][entry["phase"]]["label"] == "r3.cold_build"
        )
        entry["total_units"] = 41
        with self.assertRaisesRegex(ValueError, "differs between repetitions"):
            CHECKER.native_row(view(document))
        document = copy.deepcopy(NATIVE)
        size = next(
            entry
            for entry in document["byte_counters"]["entries"]
            if document["phase_tree"]["nodes"][entry["phase"]]["label"] == "r2.prove_absence"
        )
        size["total_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "differs between repetitions"):
            CHECKER.native_row(view(document))

    def test_native_row_derives_counts_and_repetition_statistics(self) -> None:
        row = CHECKER.native_row(view(NATIVE))
        self.assertEqual((row["construction"], row["profile"], row["population_log2"]), ("radix", "blake2b", 16))
        self.assertEqual(
            row["cold_build"]["ns_per_entry"], {"min": 190.0, "median": 205.0, "max": 250.0, "repetitions": 5}
        )
        self.assertTrue(row["cold_build"]["replicated"])
        self.assertEqual(row["cold_build"]["compressions"], 40)
        self.assertEqual(
            row["updates"],
            [
                {
                    "changes_per_set": 100,
                    "change_sets": 4,
                    "wall_ns_per_change": {"min": 2.0, "median": 2.2, "max": 2.4, "repetitions": 5},
                    "compressions_per_change": 0.1,
                    "byte_hashes_per_change": 0.05,
                    "permutations_per_change": 0.0,
                }
            ],
        )
        self.assertEqual(row["storage_model"]["class"], "accounting_model")
        self.assertEqual(row["storage_model"]["structure_bytes_per_entry"], 103.6)
        self.assertEqual(
            row["memory"],
            {
                "heap_live_bytes": 3_000,
                "heap_live_bytes_per_entry": 300.0,
                "heap_peak_build_bytes": 4_500,
                "heap_readings": {"repetitions": 5, "agreeing": 5, "live_min": 3_000, "live_max": 3_000},
            },
        )
        inclusion = row["witness"]["inclusion"]
        self.assertEqual((inclusion["bytes_mean"], inclusion["bytes_min"], inclusion["bytes_max"]), (100.0, 90, 110))
        self.assertEqual(
            inclusion["verify_ns_per_statement"], {"min": 20.0, "median": 20.5, "max": 21.0, "repetitions": 5}
        )
        self.assertEqual(inclusion["verify_compressions_per_statement"], 10.0)
        self.assertIsNone(row["witness"]["cell_inclusion"])
        self.assertEqual(row["witness"]["range"][0]["claimed_entries"], 16)
        self.assertEqual(row["witness"]["range"][0]["bytes_mean"], 1_000.0)
        self.assertEqual(row["record"]["unattributed_ppm"], 500)

    def test_a_second_run_of_a_workload_is_pooled_with_the_first(self) -> None:
        """A row of a test that was run twice counts the repetitions of both runs."""
        slower = [wall * 2 for wall in BUILD_WALLS]
        first = CHECKER.Record(copy.deepcopy(NATIVE), "run-a", "child/a.json")
        second = CHECKER.Record(record(NATIVE["identity"]["workload"], native_phases(slower)), "run-b", "child/b.json")
        self.assertEqual(first.pooled(), [first])
        self.assertEqual(first.median_ratios(), {})
        first.pool(second)
        self.assertEqual(first.pooled(), [first, second])
        self.assertEqual(first.run_walls("cold_build"), BUILD_WALLS)
        self.assertEqual(first.walls("cold_build"), BUILD_WALLS + slower)
        self.assertEqual(len(first.process_cpus("cold_build")), 10)
        self.assertEqual(first.repetition_units("cold_build", "heap.peak_bytes"), [4_500] * 10)
        self.assertEqual(first.repetition_units("cold_build", "absent"), [])
        self.assertEqual(first.same_units("cold_build", "hash.compressions"), 40)
        self.assertEqual(first.same_size("prove_inclusion", "witness")["count"], 4)
        row = CHECKER.native_row(first)
        # The interval spans both runs: 1,900 ns to 5,000 ns over ten entries.
        self.assertEqual(
            row["cold_build"]["ns_per_entry"], {"min": 190.0, "median": 315.0, "max": 500.0, "repetitions": 10}
        )
        self.assertEqual(row["updates"][0]["wall_ns_per_change"]["repetitions"], 10)
        self.assertEqual(row["record"]["run"], "run-a")
        self.assertEqual(
            row["record"]["replicates"],
            [
                {
                    "run": "run-b",
                    "flow_wall_ns": 100_000,
                    "unattributed_ppm": 500,
                    "peak_rss_bytes": 4096,
                    "peak_rss_bytes_at_begin": 2048,
                    "load_milli_begin": 1500,
                    "load_milli_finish": 2500,
                }
            ],
        )
        # The build's median doubled; every other timed phase kept its median.
        ratios = first.median_ratios()["run-b"]
        self.assertEqual(sorted(set(ratios)), [1.0, 2.0])
        self.assertEqual(ratios.count(2.0), 1)
        self.assertEqual(len(ratios), len(first.repeats))

    def test_every_record_names_the_schema_its_process_read(self) -> None:
        named = {
            "class": "measured_deterministic_count",
            "tables": INVENTORY_SCHEMA["tables"],
            "cells": INVENTORY_SCHEMA["cells"],
            "descriptor_bytes": INVENTORY_SCHEMA["descriptor_bytes"],
            "descriptor_sha256_prefix": INVENTORY_SCHEMA["descriptor_sha256"][:16],
        }
        first = CHECKER.Record(copy.deepcopy(NATIVE), "run-a", "child/a.json")
        first.pool(CHECKER.Record(copy.deepcopy(NATIVE), "run-b", "child/b.json"))
        self.assertEqual(CHECKER.recorded_schema([first, view(LATENCY)]), named)
        self.assertIsNone(CHECKER.recorded_schema([]))
        # A prefix with leading zero digits keeps its sixteen digits.
        short = copy.deepcopy(NATIVE)
        for entry in short["work_counters"]["entries"]:
            if entry["label"] == "schema.descriptor_sha256_prefix":
                entry["total_units"] = 0xABC
        self.assertEqual(CHECKER.recorded_schema([view(short)])["descriptor_sha256_prefix"], "0000000000000abc")

        # A run over another schema, here one more table, is not this comparison's.
        other = copy.deepcopy(SHARED)
        for entry in other["work_counters"]["entries"]:
            if entry["label"] == "schema.tables":
                entry["total_units"] += 1
        with self.assertRaisesRegex(ValueError, "the runs read different schemas"):
            CHECKER.recorded_schema([view(NATIVE), CHECKER.Record(other, "run-b", "child/b.json")])
        # The same holds for the further run pooled into a row. It is refused
        # when it is pooled, because the schema counters are not a time.
        with self.assertRaisesRegex(ValueError, "a deterministic counter differs"):
            CHECKER.Record(copy.deepcopy(SHARED), "run-a", "child/a.json").pool(
                CHECKER.Record(other, "run-b", "child/b.json")
            )
        silent = copy.deepcopy(NATIVE)
        silent["work_counters"]["entries"] = [
            entry for entry in silent["work_counters"]["entries"] if entry["label"] != "schema.cells"
        ]
        with self.assertRaisesRegex(ValueError, "does not name the schema it read"):
            CHECKER.recorded_schema([view(silent)])

    def test_a_heap_figure_is_the_reading_of_most_builds(self) -> None:
        """One build that another thread's allocation fell into does not move the figure."""

        def with_live(values: list[int]) -> object:
            document = copy.deepcopy(NATIVE)
            nodes = document["phase_tree"]["nodes"]
            for entry in document["work_counters"]["entries"]:
                label = nodes[entry["phase"]]["label"]
                if entry["label"] == "heap.live_bytes" and label.endswith(".cold_build"):
                    entry["total_units"] = values[int(label[1])]
            return view(document)

        noisy = with_live([4_456, 3_000, 3_000, 3_000, 3_000])
        self.assertEqual(
            noisy.majority_units("cold_build", "heap.live_bytes"),
            {"value": 3_000, "agreeing": 4, "repetitions": 5, "min": 3_000, "max": 4_456},
        )
        self.assertIsNone(noisy.majority_units("cold_build", "absent"))
        row = CHECKER.native_row(noisy)
        self.assertEqual(row["memory"]["heap_live_bytes"], 3_000)
        self.assertEqual(
            row["memory"]["heap_readings"], {"repetitions": 5, "agreeing": 4, "live_min": 3_000, "live_max": 4_456}
        )
        # Without a value that most builds read there is no figure.
        with self.assertRaisesRegex(ValueError, "no value that most repetitions agree on"):
            CHECKER.native_row(with_live([1, 2, 3, 3, 4]))
        with self.assertRaisesRegex(ValueError, "no value that most repetitions agree on"):
            with_live([1, 1, 2, 2, 3]).majority_units("cold_build", "heap.live_bytes")

    def test_a_record_that_differs_in_a_count_or_a_phase_is_not_pooled(self) -> None:
        first = CHECKER.Record(copy.deepcopy(NATIVE), "run-a", "child/a.json")
        fixed = first.fixed_counters()
        self.assertEqual(fixed[("storage", "work", "structure_bytes")], (1, 1_036, 1_036, 1_036))
        self.assertFalse(any(label.startswith("r0.") for label, _, _ in fixed))
        other = copy.deepcopy(NATIVE)
        for entry in other["work_counters"]["entries"]:
            if entry["label"] == "structure_bytes":
                entry["total_units"] += 1
        with self.assertRaisesRegex(ValueError, "a deterministic counter differs between runs run-a and run-b"):
            first.pool(CHECKER.Record(other, "run-b", "child/b.json"))
        # A count of a repetition is compared when the row is read.
        other = copy.deepcopy(NATIVE)
        for entry in other["work_counters"]["entries"]:
            if entry["label"] == "hash.compressions":
                entry["total_units"] += 1
        pooled = CHECKER.Record(copy.deepcopy(NATIVE), "run-a", "child/a.json")
        pooled.pool(CHECKER.Record(other, "run-b", "child/b.json"))
        with self.assertRaisesRegex(ValueError, "differs between repetitions"):
            CHECKER.native_row(pooled)
        shorter = record(NATIVE["identity"]["workload"], native_phases()[:-1])
        with self.assertRaisesRegex(ValueError, "recorded different phases"):
            first.pool(CHECKER.Record(shorter, "run-b", "child/b.json"))
        with self.assertRaisesRegex(ValueError, "cannot pool the record"):
            first.pool(CHECKER.Record(copy.deepcopy(SHARED), "run-b", "child/b.json"))
        self.assertEqual(first.replicates, [])

    def test_records_are_pooled_by_workload_and_runs_are_compared(self) -> None:
        def run(name: str, test: str, documents: list[dict]) -> dict:
            return {
                "summary": {"run": name, "test": test},
                "records": [CHECKER.Record(copy.deepcopy(document), name, "child/a.json") for document in documents],
            }

        slower = record(NATIVE["identity"]["workload"], native_phases([wall * 2 for wall in BUILD_WALLS]))
        runs = [run("run-a", "native", [NATIVE, SHARED]), run("run-l", "latency", [LATENCY]), run("run-b", "native", [slower, SHARED])]
        records = CHECKER.pool_records(runs)
        self.assertEqual(
            [(entry.workload.split(".")[2], entry.run, len(entry.replicates)) for entry in records],
            [("radix", "run-a", 1), ("linked", "run-a", 1), ("hash_profiles", "run-l", 0)],
        )
        table = CHECKER.run_to_run(runs, records)
        self.assertEqual(len(table), 1)
        entry = table[0]
        self.assertEqual((entry["test"], entry["first_run"], entry["further_run"]), ("native", "run-a", "run-b"))
        self.assertEqual(entry["class"], "derived_from_measured")
        self.assertEqual(entry["workloads"], 2)
        self.assertEqual(entry["median_wall_ratio"], {"min": 1.0, "median": 1.0, "max": 2.0})
        self.assertEqual(entry["timed_phases"] - entry["phases_within_ten_percent"], 1)
        self.assertEqual(CHECKER.run_to_run(runs[:2], CHECKER.pool_records([run("run-a", "native", [NATIVE])])), [])
        with self.assertRaisesRegex(ValueError, "recorded twice by run run-a"):
            CHECKER.pool_records([run("run-a", "native", [NATIVE, NATIVE])])

    def test_a_build_run_once_is_not_replicated(self) -> None:
        once = record("state_candidates.native.radix.rescue-prime.p20.scattered-32.v32", native_phases(build_walls=[9_000]))
        row = CHECKER.native_row(view(once))
        self.assertFalse(row["cold_build"]["replicated"])
        self.assertEqual(row["cold_build"]["ns_per_entry"]["repetitions"], 1)
        self.assertEqual(row["updates"][0]["wall_ns_per_change"]["repetitions"], 5)

    def test_circuit_rows_carry_native_counts_and_null_committed_proof_fields(self) -> None:
        rows = CHECKER.circuit_rows(view(CIRCUIT))
        self.assertEqual([row["statement"] for row in rows], ["inclusion", "range_1024"])
        built, oversized = rows
        self.assertFalse(built["exceeds_reference_limit"])
        self.assertEqual(built["geometry"]["rows"], 256)
        self.assertEqual(built["geometry"]["registers"], 1)
        statements = built["statements"]
        self.assertEqual(statements["permutations"], {"count": 4, "total": 112, "min": 27, "mean": 28.0, "max": 29})
        self.assertEqual(statements["native_verifier_permutations"], statements["permutations"])
        self.assertEqual((statements["registers_min"], statements["registers_max"]), (1, 1))
        self.assertEqual((statements["native_witness_bytes_mean"], statements["native_witness_bytes_max"]), (760.0, 796))
        self.assertEqual(built["gadget_instances"], {"class": "as_built_source_constant", "bit_scans": 0, "comparisons": 0})
        reference = built["reference"]
        self.assertTrue(reference["replicated"])
        self.assertEqual(reference["build_wall_ns"], {"min": 9_000, "median": 9_100, "max": 9_200, "repetitions": 3})
        self.assertEqual(reference["build_process_cpu_ns_median"], 18_200)
        self.assertEqual(reference["check_process_cpu_ns_median"], 16_000)
        self.assertEqual(reference["build_peak_heap_bytes"], 500_002)
        self.assertEqual(reference["check_peak_heap_bytes"], 400_000)
        self.assertEqual(reference["uncommitted_artifact_bytes"], 180_000)
        self.assertIn("uncommitted", reference["label"])
        for row in rows:
            proof = row["committed_proof"]
            for key in ("prove_time_ns", "verify_time_ns", "proof_bytes", "prover_memory_bytes"):
                self.assertIsNone(proof[key])
            self.assertIn("B.2", proof["null_reason"])
            self.assertEqual(row["record"]["forged_traces_rejected"], 3)
        self.assertTrue(oversized["exceeds_reference_limit"])
        self.assertIsNone(oversized["reference"])
        self.assertIn("65,536", oversized["reference_null_reason"])
        self.assertEqual(oversized["geometry"]["rows"], 262_144)
        self.assertEqual(oversized["gadget_instances"]["comparisons"], 2)
        self.assertEqual((oversized["statements"]["registers_min"], oversized["statements"]["registers_max"]), (11, 12))

    def test_gadget_rows_read_geometry_and_reference_statistics(self) -> None:
        rows = CHECKER.gadget_rows(view(GADGET))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["gadget"], row["relation"], row["key_bytes"]), ("order", "KeyOrderAir", 36))
        self.assertEqual((row["rows"], row["width"], row["private_columns"], row["constraints"]), (64, 42, 32, 47))
        self.assertEqual(row["reference"]["build_wall_ns"], {"min": 500, "median": 501, "max": 502, "repetitions": 3})
        self.assertEqual(CHECKER.gadget_cells(rows, "order", 36), 2_688)
        self.assertIsNone(CHECKER.gadget_cells(rows, "bits", 36))
        self.assertEqual((CHECKER.composite_key_bytes("scattered-32"), CHECKER.composite_key_bytes("long-128")), (36, 132))

    def test_private_key_projection_adds_gadget_cells_to_the_hash_chain(self) -> None:
        gadgets = [
            {"gadget": "order", "key_bytes": 36, "trace_cells": 2_688},
            {"gadget": "bits", "key_bytes": 36, "trace_cells": 2_368},
        ]
        row = {
            "key_shape": "scattered-32",
            "geometry": {"rows": 256, "width": 64},
            "gadget_instances": {"bit_scans": 2, "comparisons": 1},
        }
        self.assertEqual(
            CHECKER.private_key_projection(row, gadgets),
            {
                "class": "projection",
                "key_bytes": 36,
                "hash_chain_trace_cells": 16_384,
                "gadget_trace_cells": 2 * 2_368 + 2_688,
                "sum_trace_cells": 16_384 + 2 * 2_368 + 2_688,
            },
        )
        self.assertIsNone(CHECKER.private_key_projection({**row, "key_shape": "long-128"}, gadgets))

    def test_latency_rows_divide_wall_time_by_calls_in_each_repetition(self) -> None:
        rows, gadget = CHECKER.latency_rows(view(LATENCY))
        self.assertEqual(
            rows,
            [
                {
                    "profile": "blake2b",
                    "operation": "compress",
                    "calls": 10,
                    "ns_per_call": {"min": 150.0, "median": 152.0, "max": 154.0, "repetitions": 5},
                },
                {
                    "profile": "rescue-prime",
                    "operation": "permutation",
                    "calls": 2,
                    "ns_per_call": {"min": 35_000.0, "median": 35_000.0, "max": 35_000.0, "repetitions": 5},
                },
            ],
        )
        self.assertEqual(CHECKER.find_latency(rows, "blake2b", "compress"), 152.0)
        self.assertIsNone(CHECKER.find_latency(rows, "blake3", "compress"))
        self.assertEqual(gadget["class"], "as_built_source_constant")
        self.assertEqual((gadget["rows"], gadget["columns"], gadget["physical_rows_per_hash_slot"]), (408, 310, 512))

    def test_shared_path_rows_project_a_witness_with_shared_address_paths(self) -> None:
        rows = CHECKER.shared_path_rows(view(SHARED))
        self.assertEqual(len(rows), 1)
        self.assertEqual(CHECKER.shared_path_rows(view(NATIVE)), [])
        row = rows[0]
        self.assertEqual((row["profile"], row["claimed_entries"], row["statements"]), ("blake2b", 16, 2))
        self.assertEqual((row["leaves_mean"], row["prototype_path_steps_mean"]), (17.0, 340.0))
        self.assertEqual((row["shared_branches_mean"], row["shared_carried_siblings_mean"]), (80.0, 64.0))
        self.assertEqual(row["prototype_witness_bytes_mean"], 12_500.0)
        self.assertEqual(row["shared_witness_bytes_mean"], 12_500 - 36 * 340 + 32 * 64 + 5 * 80)

    def test_load_run_reads_only_candidate_records_and_hashes_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run-test"
            (run / "child").mkdir(parents=True)
            other = record("another.workload", [])
            for name, document in (("a", NATIVE), ("b", other)):
                (run / "child" / f"{name}.json").write_text(json.dumps(document))
            report = {
                "command": {"arguments": ["--ignored", "--exact", "native_blake2b"], "executable_sha256": "e" * 64},
                "context": {"source_commit": "c" * 40, "source_dirty": True, "source_dirty_digest": "d" * 64, "config": "k"},
                "process": {"wall_ns": 5, "cpu_user_ns": 4, "peak_rss_bytes": 3},
                "records": [{"json": {"path": "child/a.json"}}, {"json": {"path": "child/b.json"}}],
                "reasons": [],
                "verdict": "accepted",
            }
            (run / "report.json").write_text(json.dumps(report))
            (run / "manifest.json").write_text("{}")
            loaded = CHECKER.load_run(run)
        summary = loaded["summary"]
        self.assertEqual(len(loaded["records"]), 1)
        self.assertEqual(summary["test"], "native_blake2b")
        self.assertEqual(summary["manifest_sha256"], hashlib.sha256(b"{}").hexdigest())
        self.assertEqual(summary["raw_records"], "dist/zk-resource-harness/run-test/child/")
        self.assertEqual((summary["load_milli_min"], summary["load_milli_max"]), (1500, 2500))
        self.assertEqual(summary["thermal_states"], ["nominal"])
        self.assertEqual(summary["workers"], [20])
        self.assertEqual(summary["records"], 1)
        self.assertEqual(summary["config"], "k")
        self.assertEqual(summary["unattributed_ppm_max"], 500)


def timed(low: float, high: float) -> dict:
    return {"min": low, "median": (low + high) / 2, "max": high, "repetitions": 5}


def native_stub(construction: str, build: dict | None, verify: dict) -> dict:
    return {
        "construction": construction,
        "profile": "blake2b",
        "population_log2": 16,
        "key_shape": "scattered-32",
        "value_bytes": 32,
        "cold_build": {"ns_per_entry": build or timed(1, 2), "replicated": build is not None},
        "updates": [{"changes_per_set": 1, "wall_ns_per_change": timed(10, 20)}],
        "witness": {"inclusion": {"verify_ns_per_statement": verify}, "absence": None, "range": []},
    }


class Derivations(unittest.TestCase):
    def test_timings_separate_constructions_only_when_their_intervals_are_disjoint(self) -> None:
        groups = CHECKER.comparability(
            [
                native_stub("btree", timed(30, 40), timed(5, 9)),
                native_stub("radix", timed(10, 20), timed(6, 7)),
                native_stub("linked", None, timed(1, 2)),
            ]
        )
        by_measure = {group["measure"]: group for group in groups}
        build = by_measure["cold_build.ns_per_entry"]
        self.assertEqual(build["separated"], ["radix<btree"])
        self.assertEqual(build["overlapping"], [])
        self.assertEqual(build["not_replicated"], ["linked"])
        update = by_measure["updates[1].wall_ns_per_change"]
        self.assertEqual(update["separated"], [])
        self.assertEqual(update["overlapping"], ["radix~btree", "radix~linked", "btree~linked"])
        verify = by_measure["witness.inclusion.verify_ns_per_statement"]
        self.assertEqual(verify["separated"], ["linked<radix", "linked<btree"])
        self.assertEqual(verify["overlapping"], ["radix~btree"])
        self.assertEqual((build["profile"], build["population_log2"]), ("blake2b", 16))

    def test_projection_status_follows_the_recorded_values(self) -> None:
        interval = CHECKER.projection("id", "q", [1, 2], "ns", "interval", 3, "revised", "note")
        self.assertEqual((interval["status"], interval["revision"]), ("contradicted", "revised"))
        self.assertEqual(interval["projection"]["class"], "projection")
        self.assertEqual(interval["measured"]["class"], "derived_from_measured")
        inside = CHECKER.projection("id", "q", [1, 2], "ns", "interval", 1.5, "unused")
        self.assertEqual((inside["status"], inside["revision"]), ("confirmed", None))
        self.assertEqual(CHECKER.projection("id", "q", 640, "bytes", "at_most", 600)["status"], "confirmed")
        self.assertEqual(CHECKER.projection("id", "q", 640, "bytes", "at_most", 700)["status"], "contradicted")
        self.assertEqual(CHECKER.projection("id", "q", 2400, "bytes", "within_half", 780)["status"], "contradicted")
        self.assertEqual(CHECKER.projection("id", "q", 2400, "bytes", "within_half", 2000)["status"], "confirmed")
        projected = {"rows": 30, "columns": [24, 60]}
        self.assertEqual(
            CHECKER.projection("id", "q", projected, "rows", "geometry", {"rows": 32, "columns_total": 54})["status"],
            "contradicted",
        )
        self.assertEqual(
            CHECKER.projection("id", "q", projected, "rows", "geometry", {"rows": 30, "columns_total": 54})["status"],
            "confirmed",
        )
        self.assertEqual(CHECKER.projection("id", "q", 1, "ns", "interval")["status"], "unmeasured")
        fixed = CHECKER.projection("air-rpo-permutation", "q", {"rows": 14}, "rows", None, None, "why")
        self.assertEqual((fixed["status"], fixed["revision"], fixed["measured"]), ("not_comparable", "why", None))
        self.assertEqual(CHECKER.projection("storage-tree-hashes-per-row", "q", 1, "bytes", None, None, "r")["status"], "revised_by_model")
        with self.assertRaisesRegex(ValueError, "no comparison rule"):
            CHECKER.projection("id", "q", 1, "ns", None, 5)

    def test_cached_page_rows_project_the_btree_with_kept_nodes(self) -> None:
        row = {
            "construction": "btree",
            "profile": "blake2b",
            "population_log2": 16,
            "key_shape": "scattered-32",
            "value_bytes": 32,
            "updates": [{"changes_per_set": 1, "compressions_per_change": 130.0}],
            "witness": {"inclusion": {"verify_compressions_per_statement": 24.5}},
            "storage_model": {"entries": 1_000, "structure_digests": 2_060, "structure_bytes": 67_460, "structure_bytes_per_entry": 67.46},
        }
        self.assertEqual(
            CHECKER.cached_page_rows([row, {**row, "construction": "radix"}]),
            [
                {
                    "profile": "blake2b",
                    "population_log2": 16,
                    "key_shape": "scattered-32",
                    "value_bytes": 32,
                    "prototype_compressions_per_single_change": 130.0,
                    "cached_compressions_per_value_rewrite": 23.5,
                    "page_internal_nodes": 939,
                    "prototype_model_bytes_per_entry": 67.46,
                    "cached_model_bytes_per_entry": round((67_460 + 32 * 939) / 1_000, 2),
                }
            ],
        )

    def test_storage_model_bytes_follow_the_declared_constants(self) -> None:
        constants = CHECKER.STORAGE_MODEL["constants"]
        model = {"entries": 10, "structure_digests": 29}
        self.assertEqual(CHECKER.storage_model_bytes("radix", model, constants), (10 * 64 + 9 * 44, 0))
        self.assertEqual(CHECKER.storage_model_bytes("btree", {"entries": 10, "structure_digests": 23}, constants), (10 * 65 + 3 * 41, 0))
        self.assertEqual(CHECKER.storage_model_bytes("linked", model, constants), (11 * 96 + 10 * 44, 80))
        self.assertEqual(CHECKER.storage_model_bytes("chain", model, constants), (10 * 96 + 32, 0))
        self.assertEqual(CHECKER.storage_model_bytes("radix", {"entries": 0}, constants), (0, 0))

    def test_conformance_tests_cover_every_construction_under_every_checked_profile(self) -> None:
        tests = CHECKER.conformance_tests()
        self.assertEqual(len(tests), 20)
        self.assertIn(
            {
                "construction": "linked",
                "profile": "rescue-prime",
                "engine_type": "LinkedLeafMap",
                "profile_type": "RescuePrimeProfile",
                "test": "linked_leaf_map_over_rescue_prime_satisfies_the_keyed_state_contract",
            },
            tests,
        )

    def test_inventory_schema_is_the_canonical_descriptor_of_the_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "specs").mkdir()
            (root / "specs" / "state_table_inventory.json").write_text(
                json.dumps(
                    {
                        "fields": [
                            {"id": "w.b", "role": "canonical", "shape": "table", "key": "K", "value": "V"},
                            {"id": "w.index", "role": "derived"},
                            {"id": "w.a", "role": "canonical", "shape": "cell", "value": "C"},
                        ]
                    }
                )
            )
            schema = CHECKER.inventory_schema(root)
        descriptor = (
            b"iroha:state-keyed-commitment:schema:v1\0"
            + (2).to_bytes(4, "little")
            + b"\x01" + (3).to_bytes(4, "little") + b"w.a" + (0).to_bytes(4, "little") + (1).to_bytes(4, "little") + b"C"
            + b"\x00" + (3).to_bytes(4, "little") + b"w.b" + (1).to_bytes(4, "little") + b"K" + (1).to_bytes(4, "little") + b"V"
        )
        self.assertEqual((schema["tables"], schema["cells"]), (1, 1))
        self.assertEqual(schema["descriptor_bytes"], len(descriptor))
        self.assertEqual(schema["descriptor_sha256"], hashlib.sha256(descriptor).hexdigest())


class Classification(unittest.TestCase):
    def test_every_number_needs_a_classified_ancestor(self) -> None:
        errors: list[str] = []
        CHECKER.walk_numbers({"a": {"class": "measured", "rows": [{"x": 1.5}]}, "flag": True, "text": "7"}, "$", False, errors)
        self.assertEqual(errors, [])
        CHECKER.walk_numbers({"a": {"class": "accounting_model", "x": 1}}, "$", False, errors)
        self.assertEqual(errors, [])
        CHECKER.walk_numbers({"a": {"x": 1}}, "$", False, errors)
        self.assertEqual(errors, ["$.a.x: number 1 has no class"])
        errors = []
        CHECKER.walk_numbers({"a": {"class": "guessed", "x": 1}}, "$", False, errors)
        self.assertEqual(len(errors), 2)
        self.assertIn("unknown class `guessed`", errors[0])

    def test_selection_keys_are_refused_at_any_depth(self) -> None:
        errors: list[str] = []
        CHECKER.walk_keys({"a": [{"winner": "radix"}], "selection_note": "none"}, "$", errors)
        self.assertEqual(errors, ["$.a[0].winner: the comparison must not record a selection"])

    def test_rendering_keeps_scalar_objects_on_one_line_and_round_trips(self) -> None:
        value = {
            "a": {"x": 1, "y": "two"},
            "b": [1, 2, 3],
            "c": [{"k": [1.5, None]}],
            "d": {},
            "e": [],
            "long": ["w" * 250, "v" * 250],
        }
        text = CHECKER.render(value)
        self.assertEqual(json.loads(text), value)
        self.assertIn(' "a": {"x": 1, "y": "two"},', text)
        self.assertIn(' "b": [1, 2, 3],', text)
        # An object that holds a container is expanded; its scalar array stays inline.
        self.assertIn('  {\n   "k": [1.5, null]\n  }', text)
        self.assertIn(' "d": {},\n "e": [],', text)
        # A scalar array wider than the limit is expanded.
        self.assertIn(' "long": [\n  "' + "w" * 250 + '",', text)
        self.assertTrue(text.endswith("}\n"))
        self.assertLessEqual(max(len(line) for line in text.splitlines()), CHECKER.RENDER_WIDTH)

    def test_timing_checks_order_and_repetitions(self) -> None:
        errors: list[str] = []
        CHECKER.check_timing(timed(1, 2), "t", 5, errors)
        self.assertEqual(errors, [])
        CHECKER.check_timing({"min": 3, "median": 2, "max": 4, "repetitions": 5}, "t", 5, errors)
        CHECKER.check_timing({**timed(1, 2), "repetitions": 4}, "t", 5, errors)
        CHECKER.check_timing(12.5, "t", 5, errors)
        self.assertEqual(
            errors,
            [
                "t: minimum, median and maximum are not ordered",
                "t: 4 repetitions, fewer than 5",
                "t: not a timing of the form min, median, max, repetitions",
            ],
        )


class SourceFacts(unittest.TestCase):
    """What the checker reads from the Rust sources of the repository."""

    def test_relation_geometry_is_read_from_the_relation_source(self) -> None:
        relation = CHECKER.relation_constants(REPOSITORY)
        self.assertEqual(relation["poseidon2"], {"rows": 32, "periodic": 15})
        self.assertEqual(relation["rescue-prime"], {"rows": 8, "periodic": 25})
        self.assertEqual((relation["private_base"], relation["private_per_register"]), (13, 4))
        self.assertEqual((relation["public_base"], relation["public_per_register"]), (20, 2))
        self.assertEqual((relation["constraints_base"], relation["constraints_per_register"]), (18, 4))
        self.assertEqual(relation["degree"], 8)
        self.assertEqual(
            relation["hash_constants"],
            {
                "poseidon2": {"width": 12, "full_rounds": 8, "partial_rounds": 22, "rounds": 30},
                "rescue-prime": {"width": 12, "rounds": 7},
            },
        )

    def test_gadget_geometry_storage_constants_and_as_built_constants_are_read_from_source(self) -> None:
        self.assertEqual(
            CHECKER.gadget_constants(REPOSITORY),
            {
                "order": {"private_columns": 32, "width": 42, "constraints": 47, "degree": 4},
                "bits": {"private_columns": 11, "width": 37, "constraints": 25, "degree": 3},
            },
        )
        self.assertEqual([CHECKER.gadget_rows_for(length) for length in (0, 7, 8, 15, 36, 63, 64, 132)], [8, 8, 16, 32, 64, 64, 128, 256])
        self.assertEqual(CHECKER.storage_constants(REPOSITORY), CHECKER.STORAGE_MODEL["constants"])
        self.assertEqual(
            CHECKER.as_built_constants(REPOSITORY), {"rows": 408, "columns": 310, "physical_rows_per_hash_slot": 512}
        )

    def test_engines_conformance_table_and_gadget_instances_are_read_from_source(self) -> None:
        engines = CHECKER.engines_in_source(REPOSITORY)
        self.assertEqual(
            engines,
            {(entry["source"], entry["type"], entry["identity"]) for entry in CHECKER.CONSTRUCTIONS},
        )
        table = CHECKER.conformance_table((REPOSITORY / CHECKER.ADAPTERS).read_text())
        self.assertEqual(
            set(table),
            {(entry["test"], entry["engine_type"], entry["profile_type"]) for entry in CHECKER.conformance_tests()},
        )
        use = CHECKER.gadget_use_in_source((REPOSITORY / CHECKER.PROTOTYPES / "circuit.rs").read_text())
        self.assertEqual(use["RadixTree"], {"absence": (2, 0), "range": (0, 2)})
        self.assertEqual(use["MerkleBTree"], {"absence": (0, 2), "range": (0, 2)})
        self.assertEqual(use["LinkedLeafMap"], {"absence": (0, 2), "range": (0, 2)})

    def test_unreadable_sources_are_errors_not_defaults(self) -> None:
        with self.assertRaisesRegex(CHECKER.SourceError, "cannot read the width"):
            CHECKER.read_integer("const HEIGHT: usize = 3;", r"const WIDTH: usize = (\d+);", "the width")
        self.assertEqual(CHECKER.read_integer("const WIDTH: usize = 1_024;", r"const WIDTH: usize = (\d[\d_]*);", "w"), 1024)
        with self.assertRaisesRegex(CHECKER.SourceError, "table is missing"):
            CHECKER.conformance_table("fn nothing() {}\n")
        with self.assertRaisesRegex(CHECKER.SourceError, "unreadable conformance table row"):
            CHECKER.conformance_table("\nconformance_tests! {\n    name RadixTree;\n}\n")
        with self.assertRaisesRegex(CHECKER.SourceError, "declares no absence gadget"):
            CHECKER.gadget_use_in_source("\nimpl<P: AirPermutation> WitnessPrograms for Other<AlgebraicSponge<P>> {\n}\n")

    def test_function_bodies_carry_their_attributes(self) -> None:
        text = "#[test]\n#[ignore = \"slow\"]\nfn first() {\n    if true { assert_eq!(1, 1); }\n}\n\nfn second() {}\n"
        body = CHECKER.function_body(text, "first")
        self.assertIn("#[ignore", body)
        self.assertIn("assert_eq!(1, 1)", body)
        self.assertNotIn("second", body)
        self.assertEqual(CHECKER.function_body(text, "second"), "}")
        self.assertIsNone(CHECKER.function_body(text, "third"))

    def test_source_digest_binds_every_prototype_source(self) -> None:
        digest = CHECKER.source_digest(REPOSITORY)
        self.assertEqual(digest["class"], "identity")
        self.assertRegex(digest["sha256"], r"^[0-9a-f]{64}$")
        names = {path.name for path in CHECKER.prototype_sources(REPOSITORY)}
        self.assertEqual(digest["files"], len(names))
        self.assertTrue(
            {"circuit.rs", "key_gadgets.rs", "fringe.rs", "state_commitment_prototypes.rs", "candidates_tests.rs",
             "state_commitment_candidates_measurement.rs"} <= names
        )
        self.assertEqual(CHECKER.expected_config(REPOSITORY), CHECKER.CONFIG_PREFIX + digest["sha256"][:16])
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--source-digest"]), 0)
        self.assertEqual(output.getvalue().strip(), CHECKER.expected_config(REPOSITORY))


TREE_FILES = [
    str(CHECKER.PROTOTYPE_ROOT),
    str(CHECKER.ADAPTERS),
    str(CHECKER.INTERFACE),
    str(CHECKER.MEASUREMENT),
    str(CHECKER.INVENTORY),
    str(CHECKER.BLAKE2B_GADGET),
    str(CHECKER.SMT_GADGET),
    "crates/fastpq_prover/src/lib.rs",
    ".gitignore",
]


def copy_tree(root: Path) -> None:
    """Copy every source the checker reads into another repository root."""
    relatives = [str(path.relative_to(REPOSITORY)) for path in (REPOSITORY / CHECKER.PROTOTYPES).glob("*.rs")]
    for relative in relatives + TREE_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((REPOSITORY / relative).read_text())


class TrackedSummary(unittest.TestCase):
    """The tracked comparison passes, and each kind of drift is reported."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tracked = json.loads((REPOSITORY / CHECKER.SUMMARY).read_text())

    def errors(self, mutate) -> list[str]:
        summary = copy.deepcopy(self.tracked)
        mutate(summary)
        return CHECKER.check_summary(summary, REPOSITORY)

    def assert_reported(self, mutate, fragment: str) -> None:
        errors = self.errors(mutate)
        self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors[:5]}")

    def test_tracked_summary_matches_the_tree(self) -> None:
        self.assertEqual(CHECKER.check_summary(self.tracked, REPOSITORY), [])
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(CHECKER.main([]), 0)
        self.assertIn("no construction is selected", output.getvalue())

    def test_tracked_summary_is_the_canonical_rendering(self) -> None:
        self.assertEqual(CHECKER.render(self.tracked), (REPOSITORY / CHECKER.SUMMARY).read_text())

    def test_tracked_summary_meets_the_task_shape(self) -> None:
        summary = self.tracked
        self.assertIsNone(summary["selection"])
        self.assertGreaterEqual(len(summary["constructions"]), 4)
        kinds = [profile["kind"] for profile in summary["hash_profiles"]]
        self.assertGreaterEqual(kinds.count("arithmetization_friendly"), 2)
        self.assertIn("native_fast", kinds)
        self.assertEqual(summary["workloads"]["maximum_measured_population_log2"], 20)
        rows = summary["in_circuit"]["rows"]
        statements = {row["statement"] for row in rows}
        self.assertTrue({"inclusion", "absence", "range_16", "range_1024"} <= statements)
        self.assertTrue(any(row["exceeds_reference_limit"] for row in rows))
        self.assertTrue({"long-128", "scattered-32"} <= {row["key_shape"] for row in rows})
        self.assertTrue({32, 256} <= {row["value_bytes"] for row in rows})
        self.assertTrue(any(entry["status"] == "contradicted" for entry in summary["projections"]))
        self.assertTrue(any(not row["cold_build"]["replicated"] for row in summary["native"]["rows"]))
        self.assertTrue(any(group["separated"] for group in summary["timing_comparability"]["groups"]))
        self.assertTrue(any(group["overlapping"] for group in summary["timing_comparability"]["groups"]))
        self.assertEqual(len(summary["in_circuit"]["gadgets"]["rows"]), 4)
        self.assertTrue(summary["as_built_alternatives"]["linked_range_shared_paths"]["rows"])
        self.assertTrue(summary["as_built_alternatives"]["btree_cached_page_nodes"]["rows"])

    def test_in_circuit_ranges_cost_what_the_native_verifier_hashes(self) -> None:
        """The finding this file answers: a range is hashed once, as natively."""
        for row in self.tracked["in_circuit"]["rows"]:
            statements = row["statements"]
            circuit, native, anchors = (
                statements["permutations"],
                statements["native_verifier_permutations"],
                statements["anchors"],
            )
            self.assertEqual(circuit["total"], native["total"] + anchors["total"] - anchors["count"])
            if row["construction"] != "linked":
                self.assertEqual(circuit, native, f"{row['construction']} {row['statement']}")

    def test_another_layout_or_a_malformed_section_is_reported_and_never_raises(self) -> None:
        """An older or damaged file is an inconsistency of the check, not a traceback."""
        older = {
            "schema": "iroha.state_commitment_candidates.v1",
            "selection": None,
            "native": {"class": "measured", "rows": [{"cold_build": {"ns_per_entry": 2618.0}}]},
        }
        errors = CHECKER.check_summary(older, REPOSITORY)
        self.assertEqual(len(errors), 1)
        self.assertIn("another layout is not read further", errors[0])
        for document in ([], "text", None, {}):
            self.assertIn("another layout", CHECKER.check_summary(document, REPOSITORY)[0])

        # This layout with a section of another shape: the errors found before
        # it are kept and the shape is named.
        def flatten(summary: dict) -> None:
            summary["benchmark_identity"].pop("hardware")
            summary["native"]["rows"][0]["cold_build"]["ns_per_entry"] = 2618.0

        errors = self.errors(flatten)
        self.assertIn("benchmark_identity.hardware is missing", errors)
        self.assertTrue(errors[-1].startswith("malformed comparison"), errors[-1])
        self.assertTrue(
            self.errors(lambda s: s["in_circuit"].__setitem__("rows", [7]))[-1].startswith("malformed comparison")
        )
        self.assertTrue(
            self.errors(lambda s: s.__setitem__("projections", ["text"]))[-1].startswith("malformed comparison")
        )

        # The command reports both, and a file that is not JSON, with exit 1.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / CHECKER.SUMMARY.parent).mkdir(parents=True)
            for content, fragment in (
                (json.dumps(older), "another layout"),
                ("{not json", "not a JSON document"),
            ):
                (root / CHECKER.SUMMARY).write_text(content)
                output = StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(CHECKER.main(["--repository", str(root)]), 1)
                self.assertIn(fragment, output.getvalue())

    def test_a_recorded_selection_is_refused(self) -> None:
        self.assert_reported(lambda s: s.__setitem__("selection", "radix"), "selection must be present and null")
        self.assert_reported(lambda s: s["native"].__setitem__("winner", "radix"), "must not record a selection")
        self.assert_reported(
            lambda s: s["decision_criteria"].__setitem__("selection_recorded_here", True),
            "must not record a selection",
        )
        self.assert_reported(
            lambda s: s["decision_criteria"]["criteria"][0].__setitem__("proposed_weight", 0.9),
            "sum to 1",
        )

    def test_an_unclassified_number_is_refused(self) -> None:
        self.assert_reported(lambda s: s["native"].pop("class"), "has no class")
        self.assert_reported(lambda s: s.__setitem__("extra", {"count": 3}), "$.extra.count: number 3 has no class")

    def test_incomplete_benchmark_identity_is_refused(self) -> None:
        self.assert_reported(lambda s: s["benchmark_identity"].pop("hardware"), "benchmark_identity.hardware is missing")
        self.assert_reported(lambda s: s["benchmark_identity"]["host"].pop("model"), "host.model is missing")
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("verdict", "rejected"),
            "did not accept the run",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("manifest_sha256", "abc"),
            "manifest_sha256 is not a SHA-256 digest",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("raw_records", "specs/raw/"),
            "must be under the untracked",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("executable_sha256", "f" * 64),
            "different executables",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("load_milli_max", None),
            "load of the run is not recorded",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("config", "another"),
            "configuration differs from the benchmark identity",
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["runs"][0].__setitem__("unattributed_ppm_max", 10_001),
            "more than one percent of its flow in no phase",
        )
        self.assert_reported(lambda s: s["benchmark_identity"].__setitem__("raw_records_tracked", True), "must be false")
        # The asserted hardware record names the host the harness observed.
        observed = "does not name the host the harness observed"
        self.assert_reported(lambda s: s["benchmark_identity"].__setitem__("hardware", "Cray-1/x/1c/1GiB"), observed)
        self.assert_reported(lambda s: s["benchmark_identity"]["host"].__setitem__("logical_cpus", 4), observed)
        self.assert_reported(lambda s: s["benchmark_identity"]["host"].__setitem__("model", "Cray-1"), observed)
        self.assert_reported(
            lambda s: s["benchmark_identity"]["host"].__setitem__("physical_memory_bytes", 1 << 30), observed
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"].__setitem__("hardware", "a fast machine"), "is not a record of the form"
        )
        self.assert_reported(lambda s: s["units"].pop("wall_ns"), "units differs from the checker's table")

    def test_classes_units_and_notes_of_the_measured_sections_are_the_checkers_text(self) -> None:
        text = "differs from the checker's text"
        for section, key in (
            ("native", "class"),
            ("native", "note"),
            ("native", "memory_note"),
            ("in_circuit", "class"),
            ("in_circuit", "memory_note"),
            ("in_circuit", "committed_proof_null_reason"),
            ("latency", "unit"),
            ("timing_comparability", "class"),
            ("as_built_alternatives", "class"),
            ("benchmark_identity", "load_note"),
            ("benchmark_identity", "allocator_note"),
            ("workloads", "class"),
        ):
            # A class that is valid somewhere and right in none of these places.
            errors = self.errors(lambda s, section=section, key=key: s[section].__setitem__(key, "published_parameter"))
            self.assertIn(f"{section}.{key} {text}", errors)
        self.assert_reported(
            lambda s: s["as_built_alternatives"]["btree_cached_page_nodes"].__setitem__("note", "kept"),
            f"as_built_alternatives.btree_cached_page_nodes.note {text}",
        )
        self.assert_reported(lambda s: s.pop("latency"), f"latency.class {text}")
        # What is compared is text only: rows and numbers are not this check's.
        errors: list[str] = []
        CHECKER.check_static_text(
            {"class": "measured", "inner": {"note": "n"}, "rows": [], "count": None},
            {"class": "measured", "inner": {"note": "n", "extra": 1}, "rows": [1, 2], "count": 7},
            "section",
            errors,
        )
        self.assertEqual(errors, [])
        CHECKER.check_static_text({"class": "measured", "inner": {"note": "n"}}, {"class": "model"}, "section", errors)
        self.assertEqual(
            errors, ["section.class differs from the checker's text", "section.inner.note differs from the checker's text"]
        )

    def test_the_tracked_file_is_what_its_cited_runs_give(self) -> None:
        """The raw records are untracked: where they are present, the file is rebuilt from them."""
        runs = [run["run"] for run in self.tracked["benchmark_identity"]["runs"]]
        if not all((REPOSITORY / CHECKER.RAW_ROOT / run / "report.json").is_file() for run in runs):
            self.skipTest("the raw records are untracked and not present in this checkout")
        text = (REPOSITORY / CHECKER.SUMMARY).read_text()
        self.assertEqual(CHECKER.reproduction_errors(self.tracked, text, REPOSITORY), [])
        # A measured count that nothing in the file contradicts.
        edited = copy.deepcopy(self.tracked)
        edited["native"]["rows"][0]["updates"][0]["compressions_per_change"] += 1.0
        self.assertEqual(CHECKER.check_summary(edited, REPOSITORY), [])
        self.assertEqual(
            CHECKER.reproduction_errors(edited, CHECKER.render(edited), REPOSITORY),
            ["--reproduce: the tracked comparison is not what its cited runs give; first difference in `native`"],
        )
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(CHECKER.main(["--reproduce"]), 0)
        self.assertIn("exactly what its cited raw records give", output.getvalue())

    def test_the_measured_sources_are_bound(self) -> None:
        fragment = "are not the ones that were measured"
        self.assert_reported(
            lambda s: s["benchmark_identity"].__setitem__("config", CHECKER.CONFIG_PREFIX + "0" * 16), fragment
        )
        self.assert_reported(
            lambda s: s["benchmark_identity"]["prototype_sources"].__setitem__("sha256", "0" * 64), fragment
        )
        self.assert_reported(lambda s: s["benchmark_identity"]["prototype_sources"].__setitem__("files", 1), fragment)

    def test_descriptive_sections_are_the_checkers_tables(self) -> None:
        def rewrite_parameters(summary: dict) -> None:
            summary["hash_profiles"][2]["parameters"] = "Poseidon2 with three rounds"

        self.assert_reported(rewrite_parameters, "hash_profiles differs from the checker's table")
        self.assert_reported(
            lambda s: s["constructions"][0].__setitem__("identity", "another-tree/v9"),
            "constructions differs from the checker's table",
        )

        def swap_conformance(summary: dict) -> None:
            tests = summary["conformance"]["tests"]
            tests[0]["test"], tests[5]["test"] = tests[5]["test"], tests[0]["test"]

        self.assert_reported(swap_conformance, "conformance differs from the checker's table")
        self.assert_reported(swap_conformance, "is not in the comparison")
        self.assert_reported(lambda s: s["limits"].pop(), "limits differs from the checker's table")
        self.assert_reported(
            lambda s: s["storage_model"]["constants"]["radix"].__setitem__("leaf_bytes", 32),
            "storage_model differs from the checker's table",
        )
        self.assert_reported(
            lambda s: s["in_circuit"]["relation_scope"].__setitem__("forgery_tests", "all of them"),
            "in_circuit.relation_scope differs from the checker's table",
        )
        self.assert_reported(lambda s: s["in_circuit"]["relation_scope"].pop("outside_the_relation"), "relation_scope.outside_the_relation")
        self.assert_reported(lambda s: s["in_circuit"]["gadget_scope"].pop("status"), "gadget_scope.status is missing")
        self.assert_reported(
            lambda s: s["workloads"].__setitem__("seed", "another"), "workloads.seed differs from the checker's table"
        )
        self.assert_reported(
            lambda s: s["decision_criteria"]["admissible_measures"].pop(),
            "decision_criteria differs from the checker's table",
        )

    def test_a_filled_committed_proof_field_or_a_missing_reason_is_refused(self) -> None:
        self.assert_reported(
            lambda s: s["in_circuit"]["rows"][0]["committed_proof"].__setitem__("proof_bytes", 100_000),
            "must be null until task B.2",
        )
        self.assert_reported(
            lambda s: s["in_circuit"]["rows"][0]["committed_proof"].__setitem__("null_reason", "later"),
            "no reason naming task B.2",
        )
        self.assert_reported(
            lambda s: s["in_circuit"].__setitem__("committed_proof_null_reason", "later"),
            "committed_proof_null_reason must name task B.2",
        )

        def drop_reference(summary: dict) -> None:
            row = next(row for row in summary["in_circuit"]["rows"] if not row["exceeds_reference_limit"])
            row["reference"]["label"] = "proof"

        self.assert_reported(drop_reference, "not labelled as the uncommitted reference")

        def fill_oversized(summary: dict) -> None:
            row = next(row for row in summary["in_circuit"]["rows"] if row["exceeds_reference_limit"])
            row["reference"] = {"build_wall_ns": 1}

        self.assert_reported(fill_oversized, "beyond the reference limit")

    def built_row(self, summary: dict) -> dict:
        return next(row for row in summary["in_circuit"]["rows"] if not row["exceeds_reference_limit"])

    def test_relation_geometry_is_checked_against_the_source(self) -> None:
        for key in ("width", "rows_per_permutation", "constraints", "rows", "numerator_degree_bound", "trace_cells"):
            with self.subTest(key=key):
                self.assert_reported(
                    lambda s, key=key: self.built_row(s)["geometry"].__setitem__(key, self.built_row(s)["geometry"][key] + 1),
                    f"geometry.{key} is",
                )

        def every_width(summary: dict) -> None:
            for row in summary["in_circuit"]["rows"]:
                row["geometry"]["width"] = 7

        self.assertGreaterEqual(
            sum("geometry.width is 7" in error for error in self.errors(every_width)),
            len(self.tracked["in_circuit"]["rows"]),
        )
        self.assert_reported(
            lambda s: self.built_row(s).__setitem__("exceeds_reference_limit", True), "does not follow from its"
        )

    def test_in_circuit_counts_gadgets_and_projections_are_checked(self) -> None:
        def inflate(summary: dict) -> None:
            self.built_row(summary)["statements"]["permutations"]["total"] += 5

        self.assert_reported(inflate, "does not hash what the native verifier hashes")
        self.assert_reported(
            lambda s: self.built_row(s)["statements"].pop("native_verifier_permutations"),
            "native verifier's permutations are not recorded beside",
        )

        def more_scans(summary: dict) -> None:
            self.built_row(summary)["gadget_instances"]["bit_scans"] = 9

        self.assert_reported(more_scans, "gadget_instances differ from the instances circuit.rs declares")

        def cheaper(summary: dict) -> None:
            self.built_row(summary)["private_key_projection"]["sum_trace_cells"] = 1

        self.assert_reported(cheaper, "private_key_projection is not the sum")
        self.assert_reported(
            lambda s: self.built_row(s)["reference"].__setitem__("replicated", not self.built_row(s)["reference"]["replicated"]),
            "reference.replicated does not follow",
        )
        self.assert_reported(lambda s: self.built_row(s)["record"].__setitem__("unattributed_ppm", 20_000), "in no phase")
        self.assert_reported(lambda s: self.built_row(s)["record"].__setitem__("forged_traces_rejected", 0), "no forged trace rejected")
        self.assert_reported(lambda s: s["in_circuit"]["gadgets"]["rows"][0].__setitem__("width", 1), "the gadget's source gives")
        self.assert_reported(lambda s: s["in_circuit"]["gadgets"]["rows"].pop(), "both gadgets must be measured")
        self.assert_reported(lambda s: s["in_circuit"]["gadgets"].__setitem__("false_statements_rejected", 0), "no false statement")

    def test_missing_statement_kinds_are_refused(self) -> None:
        def drop_absence(summary: dict) -> None:
            summary["in_circuit"]["rows"] = [
                row for row in summary["in_circuit"]["rows"] if row["statement"] != "absence"
            ]

        self.assert_reported(drop_absence, "lacks ['absence']")

        # A profile declared as measured needs its rows: natively for every
        # profile, in-circuit for every shortlisted construction under it.
        def drop_circuit_profile(summary: dict) -> None:
            summary["in_circuit"]["rows"] = [
                row for row in summary["in_circuit"]["rows"] if row["profile"] != "rescue-prime"
            ]

        errors = self.errors(drop_circuit_profile)
        for construction in ("radix", "btree", "linked"):
            self.assertIn(
                f"in_circuit: shortlisted construction `{construction}` has no measurement over `rescue-prime`", errors
            )

        def drop_native_profile(summary: dict) -> None:
            summary["native"]["rows"] = [row for row in summary["native"]["rows"] if row["profile"] != "blake3"]

        self.assert_reported(drop_native_profile, "hash profile `blake3` has no native measurement")

        def relabel(summary: dict) -> None:
            summary["in_circuit"]["rows"][0]["construction"] = "chain"

        self.assert_reported(relabel, "which the comparison does not declare as measured in-circuit")
        self.assert_reported(lambda s: s["native"]["rows"][0]["witness"].__setitem__("range", []), "no complete-range witness")
        self.assert_reported(lambda s: s["native"]["rows"][0].__setitem__("updates", []), "no update measurement")

    def test_native_figures_are_checked(self) -> None:
        def disorder(summary: dict) -> None:
            summary["native"]["rows"][0]["cold_build"]["ns_per_entry"]["min"] = 10**12

        self.assert_reported(disorder, "minimum, median and maximum are not ordered")

        def too_few(summary: dict) -> None:
            summary["native"]["rows"][0]["updates"][0]["wall_ns_per_change"]["repetitions"] = 1

        self.assert_reported(too_few, "1 repetitions, fewer than 5")
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["cold_build"].__setitem__("replicated", not s["native"]["rows"][0]["cold_build"]["replicated"]),
            "cold_build.replicated does not follow",
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["storage_model"].__setitem__("structure_bytes", 1),
            "storage_model does not follow from its node counts",
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["storage_model"].__setitem__("class", "measured"),
            "storage_model is not classified as an accounting model",
        )
        self.assert_reported(lambda s: s["native"]["rows"][0].__setitem__("memory", {}), "heap of the built map is not recorded")
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["storage_model"].__setitem__("structure_bytes_per_entry", 0.1),
            "structure_bytes_per_entry is not its bytes over its entries",
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["memory"].__setitem__("heap_live_bytes_per_entry", 1.0),
            "heap_live_bytes_per_entry is not its bytes over the entries of the State",
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["witness"]["inclusion"].__setitem__("bytes_mean", 1.0),
            "the mean witness size is outside its smallest and largest",
        )
        majority = "is not the reading of a strict majority of its cold builds"
        self.assert_reported(lambda s: s["native"]["rows"][0]["memory"].pop("heap_readings"), majority)
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["memory"]["heap_readings"].__setitem__("agreeing", 1), majority
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["memory"]["heap_readings"].__setitem__("repetitions", 99), majority
        )
        self.assert_reported(
            lambda s: s["native"]["rows"][0]["memory"].__setitem__("heap_live_bytes", 1), majority
        )
        self.assert_reported(lambda s: s["native"]["rows"][0]["record"].__setitem__("unattributed_ppm", 10_001), "in no phase")
        self.assert_reported(
            lambda s: s["timing_comparability"]["groups"][0].__setitem__("separated", ["chain<radix"]),
            "timing_comparability.groups do not follow",
        )
        self.assert_reported(
            lambda s: s["as_built_alternatives"]["btree_cached_page_nodes"]["rows"][0].__setitem__("page_internal_nodes", 0),
            "btree_cached_page_nodes.rows do not follow",
        )
        self.assert_reported(lambda s: s["latency"]["rows"][0]["ns_per_call"].__setitem__("repetitions", 1), "fewer than 5")

        def unmeasured_pair(summary: dict) -> None:
            summary["conformance"]["tests"] = [
                entry for entry in summary["conformance"]["tests"] if entry["construction"] != "btree"
            ]

        self.assert_reported(unmeasured_pair, "was measured without a conformance test")

    def test_runs_of_one_test_are_pooled_and_their_movement_is_listed(self) -> None:
        """The finding this answers: a time comparison from one process is not reproducible."""
        table = self.tracked["timing_comparability"]["run_to_run"]
        self.assertTrue(table)
        runs = {run["run"]: run["test"] for run in self.tracked["benchmark_identity"]["runs"]}
        further: dict[str, set[str]] = {}
        for entry in table:
            self.assertEqual(runs[entry["first_run"]], runs[entry["further_run"]])
            self.assertGreater(entry["timed_phases"], 0)
            further.setdefault(entry["first_run"], set()).add(entry["further_run"])
        self.assertIn("native_blake2b", {entry["test"] for entry in table})
        rows = self.tracked["native"]["rows"] + self.tracked["in_circuit"]["rows"]
        for row in rows:
            record = row["record"]
            self.assertEqual({facts["run"] for facts in record["replicates"]}, further.get(record["run"], set()))
        # A row of a test that ran twice has the repetitions of both runs.
        pooled = next(row for row in self.tracked["native"]["rows"] if row["record"]["replicates"])
        self.assertGreaterEqual(pooled["updates"][0]["wall_ns_per_change"]["repetitions"], 10)

        section = "timing_comparability"
        self.assert_reported(lambda s: s[section]["run_to_run"].pop(), "does not list exactly the runs")

        def single_runs(summary: dict) -> None:
            seen: set[str] = set()
            kept = []
            for run in summary["benchmark_identity"]["runs"]:
                if run["test"] not in seen:
                    kept.append(run)
                seen.add(run["test"])
            summary["benchmark_identity"]["runs"] = kept
            summary[section]["run_to_run"] = []

        self.assert_reported(single_runs, "run_to_run is empty: no measurement test was run a second time")
        self.assert_reported(
            lambda s: s[section]["run_to_run"][0].__setitem__("further_run", s[section]["run_to_run"][0]["first_run"]),
            "are not two runs of the benchmark identity",
        )
        self.assert_reported(
            lambda s: s[section]["run_to_run"][0].__setitem__("test", "another"), "are not two runs of the test it names"
        )
        self.assert_reported(
            lambda s: s[section]["run_to_run"][0]["median_wall_ratio"].__setitem__("min", 99.0),
            "not an ordered minimum, median and maximum",
        )
        self.assert_reported(
            lambda s: s[section]["run_to_run"][0].__setitem__("phases_within_ten_percent", 10**9),
            "the counted phases are inconsistent",
        )
        self.assert_reported(lambda s: s[section].__setitem__("rule", "any"), "the rule or the run-to-run note differs")
        self.assert_reported(lambda s: s[section].pop("run_to_run_note"), "the rule or the run-to-run note differs")

        def position(summary: dict) -> int:
            return next(i for i, row in enumerate(summary["native"]["rows"]) if row["record"]["replicates"])

        def drop_replicate(summary: dict) -> None:
            summary["native"]["rows"][position(summary)]["record"]["replicates"] = []

        self.assert_reported(drop_replicate, "record.replicates are not the further runs of its test")

        def unattributed(summary: dict) -> None:
            summary["native"]["rows"][position(summary)]["record"]["replicates"][0]["unattributed_ppm"] = 10_001

        self.assert_reported(unattributed, "more than one percent of the flow is in no phase")

        def no_load(summary: dict) -> None:
            summary["native"]["rows"][position(summary)]["record"]["replicates"][0]["load_milli_begin"] = None

        self.assert_reported(no_load, "record.load_milli_begin is missing")
        self.assert_reported(lambda s: s["native"]["rows"][0]["record"].pop("replicates"), "record.replicates is missing")
        self.assert_reported(lambda s: s["latency"]["record"].__setitem__("run", "run-unknown"), "latency: its record is from a run")
        self.assert_reported(
            lambda s: s["in_circuit"]["gadgets"]["record"].__setitem__("unattributed_ppm", 10_001),
            "in_circuit.gadgets: more than one percent",
        )

    def test_projection_statuses_are_recomputed(self) -> None:
        def flip_all(summary: dict) -> None:
            for entry in summary["projections"]:
                if entry["status"] == "contradicted":
                    entry["status"], entry["revision"] = "confirmed", None

        contradicted = sum(entry["status"] == "contradicted" for entry in self.tracked["projections"])
        self.assertGreaterEqual(contradicted, 3)
        self.assertEqual(
            sum("does not follow from its recorded values" in error for error in self.errors(flip_all)), contradicted
        )

        def drop_revision(summary: dict) -> None:
            entry = next(entry for entry in summary["projections"] if entry["status"] == "contradicted")
            entry["revision"] = None

        self.assert_reported(drop_revision, "a projection that is contradicted needs its revision")
        self.assert_reported(
            lambda s: s["projections"][0]["projection"].__setitem__("class", "measured"),
            "not classified as a projection",
        )
        self.assert_reported(lambda s: s["projections"][0].__setitem__("status", "fine"), "unknown status `fine`")

        def measure_rpo(summary: dict) -> None:
            entry = next(entry for entry in summary["projections"] if entry["id"] == "air-rpo-permutation")
            entry["status"] = "contradicted"
            entry["measured"] = {"class": "derived_from_measured", "value": {"rows": 8, "columns_total": 64}}

        self.assert_reported(measure_rpo, "status `contradicted` does not follow")
        statuses = {entry["id"]: entry["status"] for entry in self.tracked["projections"]}
        self.assertEqual(statuses["air-rpo-permutation"], "not_comparable")
        self.assertEqual(statuses["native-rpo-permutation"], "not_comparable")
        self.assertEqual(statuses["air-blake2b-as-built"], "unmeasured")
        self.assertEqual(statuses["storage-tree-hashes-per-row"], "revised_by_model")
        self.assert_reported(
            lambda s: s["projections"].__setitem__(slice(None), [e for e in s["projections"] if e["id"] != "tip5"]),
            "`tip5` is missing",
        )

    def test_workload_and_as_built_claims_are_checked_against_the_tree(self) -> None:
        self.assert_reported(
            lambda s: s["workloads"].__setitem__("maximum_measured_population_log2", 24),
            "is not the largest measured population",
        )
        self.assert_reported(lambda s: s["workloads"]["combinations_run"].pop(), "differs from the measured rows")
        self.assert_reported(lambda s: s["workloads"]["schema"].__setitem__("tables", 1), "is not the schema")
        self.assert_reported(
            lambda s: s["workloads"]["schema"].__setitem__("descriptor_sha256", "0" * 64), "is not the schema"
        )
        # What the runs themselves named when they ran.
        recorded = self.tracked["workloads"]["schema_recorded_by_the_runs"]
        self.assertEqual(recorded["descriptor_sha256_prefix"], self.tracked["workloads"]["schema"]["descriptor_sha256"][:16])
        for key, value in (("tables", 1), ("cells", 1), ("descriptor_bytes", 1), ("descriptor_sha256_prefix", "0" * 16)):
            self.assert_reported(
                lambda s, key=key, value=value: s["workloads"]["schema_recorded_by_the_runs"].__setitem__(key, value),
                "the runs read another schema",
            )
        self.assert_reported(lambda s: s["workloads"].pop("schema_recorded_by_the_runs"), "the runs read another schema")
        self.assert_reported(lambda s: s["as_built_blake2b_gadget"].__setitem__("rows", 1), "as_built_blake2b_gadget differs")

        # Every run counted the entries of the declared schema: the populated
        # table, one entry per cell and four in every other table.
        schema = self.tracked["workloads"]["schema"]
        background = CHECKER.background_entries(REPOSITORY)
        self.assertEqual(background, 4)
        for row in self.tracked["native"]["rows"]:
            self.assertEqual(
                row["entries_total"], CHECKER.populated_entries(schema, row["population_log2"], background)
            )
        self.assertEqual(CHECKER.populated_entries({"tables": 3, "cells": 2}, 4, 4), 16 + 2 + 8)

        def another_schema(summary: dict) -> None:
            for row in summary["native"]["rows"]:
                row["entries_total"] += 4
                row["storage_model"]["entries"] += 4

        self.assert_reported(another_schema, "the run populated another schema")

        def projected_constant(summary: dict) -> None:
            entry = next(entry for entry in summary["projections"] if entry["id"] == "air-blake2b-as-built")
            entry["source_constant"]["columns"] = 1

        self.assert_reported(projected_constant, "its source constant differs")

    def copy_tree(self, root: Path) -> None:
        copy_tree(root)

    def source_errors(self, relative: Path | str, old: str, new: str) -> list[str]:
        """The checker's verdict on a copy of the tree with one source edited."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_tree(root)
            self.assertEqual(CHECKER.check_summary(self.tracked, root), [])
            path = root / relative
            text = path.read_text()
            self.assertIn(old, text, f"{relative} no longer holds the probed text")
            path.write_text(text.replace(old, new))
            return CHECKER.check_summary(self.tracked, root)

    def assert_source_drift(self, relative: Path | str, old: str, new: str, *fragments: str) -> None:
        errors = self.source_errors(relative, old, new)
        for fragment in fragments:
            self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors[:6]}")

    def test_any_edit_of_a_measured_source_is_drift(self) -> None:
        measured = "are not the ones that were measured"
        self.assert_source_drift(CHECKER.PROTOTYPES / "radix.rs", "//! Candidate 1", "//! Candidate one", measured)
        self.assert_source_drift(CHECKER.ADAPTERS, "//! State commitment candidates", "//! Candidates", measured)
        self.assert_source_drift(CHECKER.MEASUREMENT, "const EMITTER", "const  EMITTER", measured)
        self.assert_source_drift(CHECKER.PROTOTYPE_ROOT, "pub mod btree;", "pub mod btree; ", measured)

    def test_relation_and_gadget_source_drift_is_reported(self) -> None:
        circuit = CHECKER.PROTOTYPES / "circuit.rs"
        self.assert_source_drift(
            circuit, "12 + 4 * self.registers + 1 + 1 + 4\n", "12 + 4 * self.registers + 1 + 1 + 5\n", "geometry.constraints is"
        )
        self.assert_source_drift(
            circuit, "const PERIODIC: usize = 3 + poseidon2::WIDTH;", "const PERIODIC: usize = 4 + poseidon2::WIDTH;", "geometry.width is"
        )
        self.assert_source_drift(
            circuit, "const ROWS: usize = rescue::ROUNDS + 1;", "const ROWS: usize = rescue::ROUNDS + 2;", "geometry.rows_per_permutation is"
        )
        self.assert_source_drift(circuit, "const FIXED_PUBLIC: usize = 20;", "const FIXED: usize = 20;", "cannot read")
        self.assert_source_drift(
            circuit,
            "    const ABSENCE_GADGETS: GadgetUse = GadgetUse {\n        bit_scans: 2,",
            "    const ABSENCE_GADGETS: GadgetUse = GadgetUse {\n        bit_scans: 1,",
            "gadget_instances differ",
        )
        gadgets = CHECKER.PROTOTYPES / "key_gadgets.rs"
        self.assert_source_drift(gadgets, "const LANE_WIDTH: usize = 11;", "const LANE_WIDTH: usize = 12;", "the gadget's source gives")
        self.assert_source_drift(
            gadgets, "const LANE_CONSTRAINTS: usize = 16;", "const LANE_CONSTRAINTS: usize = 15;", "gadgets.rows[0].constraints"
        )

    def test_hash_parameter_and_known_answer_drift_is_reported(self) -> None:
        poseidon2 = CHECKER.PROTOTYPES / "poseidon2.rs"
        self.assert_source_drift(
            poseidon2,
            "pub const PARTIAL_ROUNDS: usize = 22;",
            "pub const PARTIAL_ROUNDS: usize = 21;",
            "hash profile `poseidon2`: its constants differ from the source's",
            "geometry.rows_per_permutation is",
        )
        text = (REPOSITORY / poseidon2).read_text()
        start = text.index("fn permutation_reproduces_the_published_known_answer_vector")
        test = text[start : text.index("\n    }\n", start)]
        self.assertIn("assert_eq!(", test)
        errors = self.source_errors(poseidon2, test, test.replace("assert_eq!(", "drop(("))
        self.assertTrue(any("is not a running test with an equality assertion" in error for error in errors), errors[:4])
        self.assert_source_drift(
            poseidon2,
            "fn permutation_reproduces_the_published_known_answer_vector",
            "fn renamed_vector_test",
            "known-answer test `permutation_reproduces_the_published_known_answer_vector` not found",
        )
        self.assert_source_drift(
            CHECKER.ADAPTERS, "*blake3::hash(b\"abc\").as_bytes()", "[0_u8; 32]", "no longer compares the profile with blake3::hash"
        )
        self.assert_source_drift(
            CHECKER.PROTOTYPES / "rescue.rs", '"rescue-prime-rp64-256', '"rescue-prime-rp65-256', "hash profile identity"
        )

    def test_construction_and_conformance_source_drift_is_reported(self) -> None:
        adapters = CHECKER.ADAPTERS
        row = "    radix_tree_over_blake2b_satisfies_the_keyed_state_contract: RadixTree<Blake2bProfile>;\n"
        self.assert_source_drift(
            adapters,
            row,
            "    radix_tree_over_blake2b_satisfies_the_keyed_state_contract: SortedHashChain<Poseidon2Profile>;\n",
            "for RadixTree<Blake2bProfile> not found",
            "for SortedHashChain<Poseidon2Profile> is not in the comparison",
        )
        self.assert_source_drift(
            adapters, row, row + "    one_more_satisfies_the_keyed_state_contract: RadixTree<Blake2bProfile>;\n", "`one_more_satisfies_the_keyed_state_contract` for RadixTree<Blake2bProfile> is not in the comparison"
        )
        self.assert_source_drift(adapters, "        #[test]\n        fn $name() {", '        #[test]\n        #[ignore = "later"]\n        fn $name() {', "an adapter test is ignored")
        self.assert_source_drift(
            adapters,
            "            assert_eq!(conforms::<$engine<$profile>>(), Ok(()));",
            "            let _ = conforms::<$engine<$profile>>();",
            "no longer run the conformance suite",
        )
        self.assert_source_drift(
            CHECKER.PROTOTYPES / "radix.rs",
            'const CONSTRUCTION: &\'static str = "sparse-radix-critbit-merkle/key-order/v0";',
            'const CONSTRUCTION: &\'static str = "sparse-radix-critbit-merkle/key-order/v1";',
            "construction identity `sparse-radix-critbit-merkle/key-order/v0` not found",
            "is not a construction of the comparison",
        )
        self.assert_source_drift(
            CHECKER.PROTOTYPES / "chain.rs",
            "pub const MODEL_ENTRY_BYTES: u64 = 96;",
            "pub const MODEL_ENTRY_BYTES: u64 = 64;",
            "storage_model.constants differ",
            "storage_model does not follow from its node counts",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_tree(root)
            fifth = root / CHECKER.PROTOTYPES / "fifth.rs"
            fifth.write_text(
                "//! TODO(G.3): another engine.\n"
                "impl<H: HashProfile> Engine for FifthTree<H> {\n"
                "    const CONSTRUCTION: &'static str = \"fifth-tree/v0\";\n}\n"
            )
            errors = CHECKER.check_summary(self.tracked, root)
        self.assertTrue(any("engine `FifthTree` (`fifth-tree/v0`) is not a construction of the comparison" in e for e in errors), errors[:4])

    def test_inventory_and_as_built_source_drift_is_reported(self) -> None:
        inventory = json.loads((REPOSITORY / CHECKER.INVENTORY).read_text())
        first = json.dumps(next(field["id"] for field in inventory["fields"] if field["role"] == "canonical"))
        self.assert_source_drift(
            CHECKER.INVENTORY, first, json.dumps("zz.renamed_table"), "is not the schema", "the runs read another schema"
        )
        self.assert_source_drift(
            CHECKER.BLAKE2B_GADGET, "pub const ROW_COUNT: usize = 408;", "pub const ROW_COUNT: usize = 409;", "as_built_blake2b_gadget differs", "its source constant differs"
        )
        self.assert_source_drift(
            CHECKER.SMT_GADGET, "pub const PHYSICAL_HASH_ROWS: usize = 512;", "pub const PHYSICAL_HASH_ROWS: usize = 1024;", "as_built_blake2b_gadget differs"
        )
        # A workload that fills the other tables differently no longer built
        # the States whose entries the rows counted; one that states no
        # background count is unreadable, not a default.
        background = "pub const BACKGROUND_ENTRIES: u64 = 4;"
        workload = CHECKER.PROTOTYPES / "workload.rs"
        self.assert_source_drift(
            workload, background, "pub const BACKGROUND_ENTRIES: u64 = 5;", "the run populated another schema"
        )
        self.assert_source_drift(
            workload, background, "pub const BACKGROUND: u64 = 4;", "cannot read the background entries of a table"
        )

    def test_prototypes_are_named_only_by_their_development_owners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_tree(root)
            self.assertEqual(CHECKER.check_summary(self.tracked, root), [])
            leak = root / "crates/iroha_core/src/block.rs"
            leak.write_text("use fastpq_prover::state_commitment_prototypes::radix::RadixTree;\n")
            errors = CHECKER.check_summary(self.tracked, root)
            self.assertEqual(len(errors), 1)
            self.assertIn("crates/iroha_core/src/block.rs: names the development-only prototypes", errors[0])
            leak.unlink()
            library = root / "crates/fastpq_prover/src/lib.rs"
            library.write_text(library.read_text().replace('#[cfg(any(test, feature = "dev-tools"))]\npub mod state_commitment_prototypes;', "pub mod state_commitment_prototypes;"))
            self.assertTrue(
                any("not development-only" in error for error in CHECKER.check_summary(self.tracked, root))
            )
            missing = root / CHECKER.BLAKE2B_GADGET
            missing.unlink()
            self.assertTrue(any("is missing" in error for error in CHECKER.check_summary(self.tracked, root)))


class Refresh(unittest.TestCase):
    """A summary is built from run directories, and refused when its inputs disagree."""

    def run_directory(
        self, root: Path, test: str, documents: list[dict], config: str, name: str | None = None
    ) -> Path:
        """A harness run directory of the measurement test `test`, named `name` or after the test."""
        run = root / (name or test)
        name = test
        (run / "child").mkdir(parents=True)
        for index, document in enumerate(documents):
            (run / "child" / f"{index}.json").write_text(json.dumps(document))
        report = {
            "command": {"arguments": ["--ignored", "--exact", name], "executable_sha256": "e" * 64},
            "context": {
                "source_commit": "c" * 40,
                "source_dirty": True,
                "source_dirty_digest": "d" * 64,
                "config": config,
                "hardware": "h",
                "profile": "p",
                "cache_policy": "warm",
                "artifact": "a",
            },
            "host": {"model": "m", "cpu": "c", "logical_cpus": 1, "physical_memory_bytes": 1, "system": "s"},
            "process": {"wall_ns": 5, "cpu_user_ns": 4, "peak_rss_bytes": 3},
            "records": [{"json": {"path": f"child/{index}.json"}} for index in range(len(documents))],
            "reasons": [],
            "verdict": "accepted",
        }
        (run / "report.json").write_text(json.dumps(report))
        (run / "manifest.json").write_text("{}")
        return run

    def test_a_summary_is_assembled_from_every_flow(self) -> None:
        config = CHECKER.expected_config(REPOSITORY)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = [
                self.run_directory(root, "native", [NATIVE, SHARED], config),
                self.run_directory(root, "circuit", [CIRCUIT], config),
                self.run_directory(root, "latency", [LATENCY, GADGET], config),
            ]
            summary = CHECKER.build_summary(runs, REPOSITORY)
            again = self.run_directory(root, "native", [NATIVE, SHARED], config, name="run-again")
            twice = CHECKER.build_summary([*runs, again], REPOSITORY)
        # A second run of a test adds no row: its repetitions join the first run's.
        self.assertEqual(len(twice["native"]["rows"]), 2)
        self.assertEqual(twice["native"]["rows"][0]["cold_build"]["ns_per_entry"]["repetitions"], 10)
        self.assertEqual([facts["run"] for facts in twice["native"]["rows"][0]["record"]["replicates"]], ["run-again"])
        self.assertEqual(len(twice["benchmark_identity"]["runs"]), 4)
        (movement,) = twice["timing_comparability"]["run_to_run"]
        self.assertEqual((movement["test"], movement["further_run"]), ("native", "run-again"))
        self.assertEqual(movement["median_wall_ratio"], {"min": 1.0, "median": 1.0, "max": 1.0})
        self.assertEqual(movement["phases_within_ten_percent"], movement["timed_phases"])
        self.assertFalse(
            any("run_to_run" in error for error in CHECKER.check_summary(twice, REPOSITORY)),
        )
        self.assertEqual(summary["timing_comparability"]["run_to_run"], [])
        self.assertTrue(any("run_to_run is empty" in error for error in CHECKER.check_summary(summary, REPOSITORY)))
        self.assertEqual(summary["native"]["rows"][0]["record"]["replicates"], [])
        self.assertEqual(list(summary)[:5], ["schema", "plan", "purpose", "selection", "selection_note"])
        self.assertEqual(summary["schema"], CHECKER.SCHEMA)
        self.assertIsNone(summary["selection"])
        self.assertEqual([row["construction"] for row in summary["native"]["rows"]], ["radix", "linked"])
        self.assertEqual(len(summary["in_circuit"]["rows"]), 2)
        self.assertEqual(len(summary["in_circuit"]["gadgets"]["rows"]), 1)
        self.assertEqual(summary["in_circuit"]["gadgets"]["false_statements_rejected"], 4)
        self.assertEqual(len(summary["latency"]["rows"]), 2)
        self.assertEqual(len(summary["as_built_alternatives"]["linked_range_shared_paths"]["rows"]), 1)
        identity = summary["benchmark_identity"]
        self.assertTrue(identity["contexts_agree"])
        self.assertEqual(identity["config"], config)
        self.assertEqual(identity["prototype_sources"], CHECKER.source_digest(REPOSITORY))
        self.assertEqual([run["test"] for run in identity["runs"]], ["native", "circuit", "latency"])
        self.assertEqual(summary["workloads"]["schema"], CHECKER.inventory_schema(REPOSITORY))
        self.assertEqual(
            summary["workloads"]["schema_recorded_by_the_runs"]["descriptor_sha256_prefix"],
            INVENTORY_SCHEMA["descriptor_sha256"][:16],
        )
        errors = CHECKER.check_summary(summary, REPOSITORY)
        self.assertFalse(any("the runs read another schema" in error for error in errors))
        # The synthetic rows count ten entries, not those of the inventory's schema.
        self.assertTrue(any("the run populated another schema" in error for error in errors))
        self.assertEqual(
            [entry["construction"] for entry in summary["workloads"]["combinations_run"]], ["linked", "radix"]
        )
        # The first in-circuit statement has no gadget of its key length here.
        self.assertIsNone(summary["in_circuit"]["rows"][0]["private_key_projection"])
        self.assertEqual(json.loads(CHECKER.render(summary)), summary)
        # One synthetic row is not a comparison: the checker says what is missing.
        errors = CHECKER.check_summary(summary, REPOSITORY)
        self.assertTrue(any("native.rows does not cover every construction" in error for error in errors))
        self.assertFalse(any("differs from the checker's table" in error for error in errors), errors[:5])

    def test_a_comparison_is_reproduced_from_the_runs_it_cites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_tree(root)
            raw = root / CHECKER.RAW_ROOT
            raw.mkdir(parents=True)
            config = CHECKER.expected_config(root)
            runs = [
                self.run_directory(raw, "native", [NATIVE, SHARED], config),
                self.run_directory(raw, "latency", [LATENCY, GADGET], config),
            ]
            summary = CHECKER.build_summary(runs, root)
            text = CHECKER.render(summary)
            self.assertEqual(CHECKER.reproduction_errors(summary, text, root), [])
            # An edited measured number is found, and so is another rendering.
            edited = copy.deepcopy(summary)
            edited["latency"]["rows"][0]["ns_per_call"]["median"] = 1.0
            self.assertEqual(
                CHECKER.reproduction_errors(edited, CHECKER.render(edited), root),
                ["--reproduce: the tracked comparison is not what its cited runs give; first difference in `latency`"],
            )
            self.assertIn("first difference in `its rendering`", CHECKER.reproduction_errors(summary, text + "\n", root)[0])
            # Records that no longer build a comparison, and records that are gone.
            broken = json.loads((runs[0] / "child" / "0.json").read_text())
            broken["work_counters"]["entries"] = [
                entry for entry in broken["work_counters"]["entries"] if entry["label"] != "schema.cells"
            ]
            (runs[0] / "child" / "0.json").write_text(json.dumps(broken))
            self.assertIn(
                "do not build a comparison (state_candidates.native.radix", CHECKER.reproduction_errors(summary, text, root)[0]
            )
            (runs[1] / "report.json").unlink()
            self.assertEqual(
                CHECKER.reproduction_errors(summary, text, root),
                [f"--reproduce: the raw records of latency are not under {CHECKER.RAW_ROOT}/"],
            )

    def test_runs_of_other_sources_or_unequal_repetitions_are_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stale = self.run_directory(root, "native", [NATIVE], CHECKER.CONFIG_PREFIX + "0" * 16)
            summary = CHECKER.build_summary([stale], REPOSITORY)
            self.assertTrue(
                any("are not the ones that were measured" in error for error in CHECKER.check_summary(summary, REPOSITORY))
            )
            broken = copy.deepcopy(NATIVE)
            for entry in broken["work_counters"]["entries"]:
                if entry["label"] == "changes" and broken["phase_tree"]["nodes"][entry["phase"]]["label"] == "r4.update_set_100":
                    entry["total_units"] = 399
            unequal = self.run_directory(root, "unequal", [broken], CHECKER.expected_config(REPOSITORY))
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(CHECKER.main(["--refresh", str(unequal)]), 1)
            self.assertIn("differs between repetitions", output.getvalue())
            self.assertIn("not written", output.getvalue())
            # A directory that is not a harness run, or a report of another
            # shape, is reported the same way and nothing is written.
            tracked = (REPOSITORY / CHECKER.SUMMARY).read_text()
            (root / "empty").mkdir()
            (root / "odd").mkdir()
            (root / "odd" / "report.json").write_text("{}")
            for directory, fragment in ((root / "empty", "FileNotFoundError"), (root / "odd", "KeyError")):
                output = StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(CHECKER.main(["--refresh", str(directory)]), 1)
                self.assertIn(fragment, output.getvalue())
                self.assertIn("not written", output.getvalue())
            self.assertEqual((REPOSITORY / CHECKER.SUMMARY).read_text(), tracked)


if __name__ == "__main__":
    unittest.main()
