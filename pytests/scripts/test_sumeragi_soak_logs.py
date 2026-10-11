"""Unit tests of the soak's log parsing and oracles (``scripts/sumeragi_soak_logs.py``).

Every oracle is exercised on synthetic node logs, both clean and with each kind of violation.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sumeragi_soak_logs.py"
SPEC = importlib.util.spec_from_file_location("sumeragi_soak_logs_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = soak
SPEC.loader.exec_module(soak)

INSTANCE = "11" * 32
LANE = "22" * 32
KEY_A = "a0" * 48
KEY_B = "b0" * 48
T0 = 1_790_000_000_000.0  # ms


def h(byte: int) -> str:
    """A 32-byte hash of one repeated byte, as hex."""
    return f"{byte:02x}" * 32


def iso(ms: float) -> str:
    """RFC 3339 of ``ms`` with microseconds, like the node logger."""
    from datetime import datetime, timezone

    moment = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def applied_json(ms: float, height: int, block: int, result: int | None = None, instance: str = INSTANCE, view: int = 0) -> str:
    """A ``sumeragi block applied`` line in the logger's JSON format."""
    return json.dumps(
        {
            "timestamp": iso(ms),
            "level": "INFO",
            "fields": {
                "message": soak.APPLIED_MESSAGE,
                "instance": instance,
                "height": height,
                "view": view,
                "origin_view": 0,
                "block": h(block),
                "result": h(result if result is not None else block + 1),
                "proposer": height % 4,
                "payload_bytes": 100,
            },
            "target": soak.AUDIT_TARGET,
        }
    )


def durable_json(ms: float, height: int, signed: str, key: str = KEY_A, instance: str = INSTANCE) -> str:
    """A ``sumeragi record durable`` line in the logger's JSON format."""
    return json.dumps(
        {
            "timestamp": iso(ms),
            "level": "DEBUG",
            "fields": {
                "message": soak.DURABLE_MESSAGE,
                "instance": instance,
                "key": key,
                "height": height,
                "epoch": 1,
                "signed": signed,
            },
            "target": soak.AUDIT_TARGET,
        }
    )


def node_log(node: str, boots: list[list[str]]) -> "soak.NodeLog":
    """Parse ``boots`` (lines per boot) of one node."""
    log = soak.NodeLog(node=node)
    for boot, lines in enumerate(boots):
        log.boots += 1
        soak.parse_log_lines(node, boot, lines, log)
    return log


def records(boots: list[list[str]], node: str = "peer0") -> list["soak.Record"]:
    """The durable records of one node."""
    return node_log(node, boots).records


def kinds(violations: list["soak.Violation"]) -> list[str]:
    """Violation kinds, in order."""
    return [violation.kind for violation in violations]


class ParsingTests(unittest.TestCase):
    def test_timestamps_of_any_precision_and_offset(self) -> None:
        base = soak.parse_timestamp_ms("2026-09-29T12:00:00Z")
        self.assertAlmostEqual(soak.parse_timestamp_ms("2026-09-29T12:00:00.123456Z") - base, 123.456, places=3)
        self.assertAlmostEqual(soak.parse_timestamp_ms("2026-09-29T12:00:00.123456789Z") - base, 123.456, places=3)
        self.assertAlmostEqual(soak.parse_timestamp_ms("2026-09-29T21:00:00+09:00"), base, places=3)
        self.assertAlmostEqual(soak.parse_timestamp_ms("2026-09-29T11:30:00-0030"), base, places=3)
        with self.assertRaises(soak.AuditParseError):
            soak.parse_timestamp_ms("yesterday")

    def test_signed_grammar(self) -> None:
        self.assertEqual(soak.parse_signed("-"), soak.Signed())
        signed = soak.parse_signed(
            f"proposal:1:{h(1)},prepare:1:{h(1)}:{h(2)},lock:1:{h(1)}:{h(2)},timeout:2:1"
        )
        self.assertEqual(signed.proposal, (1, h(1)))
        self.assertEqual(signed.prepare, (1, h(1), h(2)))
        self.assertEqual(signed.lock, (1, h(1), h(2)))
        self.assertEqual(signed.timeout, (2, 1))
        self.assertEqual(soak.parse_signed("timeout:0:-").timeout, (0, None))
        for bad in ("vote:1:ab", "prepare:1:ab", "prepare:x:ab:cd", "timeout:1", f"proposal:1:{h(1)},proposal:2:{h(2)}", "lock:1:ZZ:cd", "prepare:1:ab:cd:2", "prepare:1:ab:cd:0", "lock:1:ab:cd:1"):
            with self.assertRaises(soak.AuditParseError, msg=bad):
                soak.parse_signed(bad)

    def test_json_and_text_formats_decode_the_same_event(self) -> None:
        json_line = applied_json(T0, 5, 0xB5)
        compact = (
            f"\x1b[2m{iso(T0)}\x1b[0m \x1b[32m INFO\x1b[0m {soak.AUDIT_TARGET}: {soak.APPLIED_MESSAGE} "
            f"instance={INSTANCE} height=5 view=0 origin_view=0 block={h(0xB5)} result={h(0xB6)} "
            "proposer=1 payload_bytes=100 height=99"
        )
        full = (
            f"{iso(T0)}  INFO run{{peer=abc height=77}}: {soak.AUDIT_TARGET}: {soak.APPLIED_MESSAGE} "
            f"instance={INSTANCE} height=5 view=0 origin_view=0 block={h(0xB5)} result={h(0xB6)} "
            "proposer=1 payload_bytes=100"
        )
        events = [node_log("n", [[line]]).applied[0] for line in (json_line, compact, full)]
        for event in events:
            self.assertEqual((event.instance, event.height, event.block, event.result), (INSTANCE, 5, h(0xB5), h(0xB6)))
            self.assertAlmostEqual(event.ts_ms, T0, delta=0.01)
        durable_text = (
            f"{iso(T0)} DEBUG {soak.AUDIT_TARGET}: {soak.DURABLE_MESSAGE} instance={INSTANCE} key={KEY_A} "
            f"height=3 epoch=1 signed=prepare:0:{h(1)}:{h(2)}"
        )
        record = node_log("n", [[durable_text]]).records[0]
        self.assertEqual(record.signed.prepare, (0, h(1), h(2)))

    def test_observations_do_not_need_timestamps_and_other_lines_are_ignored(self) -> None:
        log = node_log(
            "n",
            [
                [
                    "thread 'main' panicked at crates/x.rs:1:1:",
                    f"{iso(T0)}  WARN iroha_core::sumeragi::node: sumeragi: local fault fault=RecordMissing",
                    json.dumps({"timestamp": iso(T0), "level": "WARN", "fields": {"message": "sumeragi: evidence of misbehaviour"}}),
                    json.dumps({"timestamp": iso(T0), "level": "INFO", "fields": {"message": "unrelated"}}),
                    "not json {",
                    "",
                ]
            ],
        )
        self.assertEqual(log.observations, {"panic": 1, "local_fault": 1, "evidence": 1})
        self.assertEqual(log.parse_errors, [])
        self.assertEqual(log.lines, 6)

    def test_malformed_audit_lines_are_kept_as_parse_errors(self) -> None:
        missing_field = json.loads(applied_json(T0, 1, 1))
        del missing_field["fields"]["block"]
        no_timestamp = json.loads(durable_json(T0, 1, "-"))
        del no_timestamp["timestamp"]
        log = node_log("n", [[json.dumps(missing_field), json.dumps(no_timestamp), durable_json(T0, 1, "vote:1")]])
        self.assertEqual(len(log.parse_errors), 3)
        self.assertEqual(log.applied, [])

    def test_boot_files_are_read_in_numeric_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node_dir = Path(tmp) / "peer0"
            node_dir.mkdir()
            for boot in (0, 2, 10):
                (node_dir / f"boot{boot}.log").write_text(applied_json(T0 + boot, boot + 1, boot) + "\n")
            (node_dir / "notes.txt").write_text("ignored")
            logs = soak.load_node_logs(Path(tmp))
        self.assertEqual([event.boot for event in logs["peer0"].applied], [0, 2, 10])
        self.assertEqual(logs["peer0"].boots, 3)


class AgreementTests(unittest.TestCase):
    def check(self, per_node: dict[str, list[list[str]]]) -> list["soak.Violation"]:
        applied = [event for node, boots in per_node.items() for event in node_log(node, boots).applied]
        return soak.check_agreement(applied)[0]

    def test_equal_contiguous_chains_agree(self) -> None:
        chain = [applied_json(T0 + i, i, i) for i in range(1, 6)]
        lane = [applied_json(T0 + i, i, 0x80 + i, instance=LANE) for i in range(1, 3)]
        self.assertEqual(self.check({"peer0": [chain + lane], "peer1": [chain], "peer2": [chain[:3], chain[3:]]}), [])

    def test_different_blocks_or_results_at_one_height_conflict(self) -> None:
        violations = self.check(
            {
                "peer0": [[applied_json(T0, 1, 1), applied_json(T0 + 1, 2, 2)]],
                "peer1": [[applied_json(T0, 1, 1), applied_json(T0 + 1, 2, 9)]],
                "peer2": [[applied_json(T0, 1, 1), applied_json(T0 + 1, 2, 2, result=7)]],
            }
        )
        self.assertEqual(kinds(violations), ["conflicting-commit"])
        self.assertEqual(violations[0].detail["height"], 2)
        self.assertEqual(len(violations[0].detail["commits"]), 3)

    def test_one_node_that_changes_its_block_across_a_restart_conflicts(self) -> None:
        violations = self.check({"peer0": [[applied_json(T0, 1, 1)], [applied_json(T0 + 5, 1, 2)]]})
        self.assertIn("conflicting-commit", kinds(violations))

    def test_gaps_and_regressions_within_a_boot(self) -> None:
        self.assertEqual(
            kinds(self.check({"peer0": [[applied_json(T0, 1, 1), applied_json(T0 + 1, 3, 3)]]})),
            ["chain-gap"],
        )
        self.assertEqual(
            kinds(self.check({"peer0": [[applied_json(T0, 2, 2), applied_json(T0 + 1, 2, 2)]]})),
            ["height-regression"],
        )

    def test_a_restart_may_hide_one_unlogged_height_but_not_two(self) -> None:
        ok = self.check({"peer0": [[applied_json(T0, 1, 1)], [applied_json(T0 + 9, 3, 3)]]})
        self.assertEqual(ok, [])
        reapplied = self.check({"peer0": [[applied_json(T0, 1, 1), applied_json(T0 + 1, 2, 2)], [applied_json(T0 + 9, 2, 2), applied_json(T0 + 10, 3, 3)]]})
        self.assertEqual(reapplied, [])
        gap = self.check({"peer0": [[applied_json(T0, 1, 1)], [applied_json(T0 + 9, 4, 4)]]})
        self.assertEqual(kinds(gap), ["chain-gap-across-restart"])


class SignOnceTests(unittest.TestCase):
    def check(self, boots: list[list[str]], node: str = "peer0") -> list["soak.Violation"]:
        return soak.check_sign_once(records(boots, node))[0]

    def test_a_growing_record_across_views_heights_and_restarts_is_clean(self) -> None:
        b, r = h(1), h(2)
        boot0 = [
            durable_json(T0, 5, f"proposal:0:{b}"),
            durable_json(T0 + 1, 5, f"proposal:0:{b},prepare:0:{b}:{r}"),
            durable_json(T0 + 2, 5, f"proposal:0:{b},prepare:0:{b}:{r},lock:0:{b}:{r}"),
            durable_json(T0 + 3, 5, f"proposal:0:{b},prepare:0:{b}:{r},lock:0:{b}:{r},timeout:1:0"),
        ]
        boot1 = [
            # The restored record re-signs identical preimages; then view 2 and the next height.
            durable_json(T0 + 10, 5, f"proposal:0:{b},prepare:2:{h(3)}:{h(4)},lock:0:{b}:{r},timeout:1:0"),
            durable_json(T0 + 11, 6, "-"),
            durable_json(T0 + 12, 6, f"prepare:0:{h(5)}:{h(6)}"),
        ]
        lane = [durable_json(T0 + 1, 1, f"prepare:0:{h(7)}:{h(8)}", instance=LANE)]
        self.assertEqual(self.check([boot0 + lane, boot1]), [])

    def test_two_prepares_of_one_view_across_a_restart_are_a_double_sign(self) -> None:
        violations = self.check(
            [
                [durable_json(T0, 5, f"prepare:1:{h(1)}:{h(2)}")],
                [durable_json(T0 + 9, 5, f"prepare:1:{h(3)}:{h(4)}")],
            ]
        )
        self.assertIn("double-prepare", kinds(violations))

    def test_double_proposal_conflicting_lock_and_double_timeout(self) -> None:
        self.assertIn(
            "double-proposal",
            kinds(self.check([[durable_json(T0, 5, f"proposal:2:{h(1)}")], [durable_json(T0 + 1, 5, f"proposal:2:{h(9)}")]])),
        )
        self.assertIn(
            "conflicting-lock",
            kinds(self.check([[durable_json(T0, 5, f"lock:1:{h(1)}:{h(2)}")], [durable_json(T0 + 1, 5, f"lock:1:{h(3)}:{h(2)}")]])),
        )
        self.assertIn(
            "double-timeout",
            kinds(self.check([[durable_json(T0, 5, "timeout:3:1")], [durable_json(T0 + 1, 5, "timeout:3:2")]])),
        )

    def test_a_prepare_at_or_below_an_earlier_timeout_view_is_a_violation(self) -> None:
        violations = self.check(
            [[durable_json(T0, 5, "timeout:2:-"), durable_json(T0 + 1, 5, f"prepare:2:{h(1)}:{h(2)},timeout:2:-")]]
        )
        self.assertEqual(kinds(violations), ["prepare-after-timeout"])
        # Signed in one step before the timeout, both entries appear in the same record: legal.
        self.assertEqual(self.check([[durable_json(T0, 5, f"prepare:2:{h(1)}:{h(2)},timeout:2:-")]]), [])

    def test_a_timeout_carrying_less_than_an_earlier_lock_is_a_violation(self) -> None:
        violations = self.check(
            [[durable_json(T0, 5, f"lock:3:{h(1)}:{h(2)}"), durable_json(T0 + 1, 5, f"lock:3:{h(1)}:{h(2)},timeout:4:2")]]
        )
        self.assertEqual(kinds(violations), ["timeout-below-lock"])
        empty = self.check(
            [[durable_json(T0, 5, f"lock:3:{h(1)}:{h(2)}"), durable_json(T0 + 1, 5, f"lock:3:{h(1)}:{h(2)},timeout:4:-")]]
        )
        self.assertEqual(kinds(empty), ["timeout-below-lock"])
        # The lock learnt after the timeout was signed (same record) bounds only later timeouts.
        self.assertEqual(self.check([[durable_json(T0, 5, f"lock:3:{h(1)}:{h(2)},timeout:2:1")]]), [])

    def test_a_record_that_goes_backwards_is_a_rollback(self) -> None:
        self.assertIn(
            "record-regression",
            kinds(self.check([[durable_json(T0, 5, f"prepare:3:{h(1)}:{h(2)}")], [durable_json(T0 + 1, 5, f"prepare:1:{h(1)}:{h(2)}")]])),
        )
        self.assertIn(
            "record-regression",
            kinds(self.check([[durable_json(T0, 5, "timeout:3:-")], [durable_json(T0 + 1, 5, "-")]])),
        )
        self.assertIn(
            "record-regression",
            kinds(self.check([[durable_json(T0, 6, "-")], [durable_json(T0 + 1, 5, "-")]])),
        )

    def test_a_key_on_two_nodes_is_reported(self) -> None:
        mixed = records([[durable_json(T0, 5, "-")]], "peer0") + records([[durable_json(T0 + 1, 5, "-")]], "peer1")
        self.assertEqual(kinds(soak.check_sign_once(mixed)[0]), ["shared-key"])

    def test_keys_are_judged_separately(self) -> None:
        self.assertEqual(
            self.check([[durable_json(T0, 5, f"prepare:1:{h(1)}:{h(2)}", KEY_A), durable_json(T0, 5, f"prepare:1:{h(3)}:{h(4)}", KEY_B)]]),
            [],
        )


def timeline(windows: list[tuple[float, float, str, tuple[str, ...]]] = (), boots: list["soak.Boot"] = (), end: float = 100_000.0, nodes: tuple[str, ...] = ("peer0", "peer1")) -> "soak.Timeline":
    """A run from ``T0`` to ``T0 + end`` (ms) with the given fault windows (offsets in ms)."""
    return soak.Timeline(
        start_ms=T0,
        end_ms=T0 + end,
        nodes=nodes,
        windows=tuple(soak.Window(T0 + start, T0 + stop, kind, names) for start, stop, kind, names in windows),
        boots=tuple(boots),
    )


def commits(node: str, offsets_ms: list[float], instance: str = INSTANCE) -> list["soak.Applied"]:
    """Applied events of ``node`` at ``T0 + offset``, heights 1, 2, ..."""
    return [
        soak.Applied(node, 0, i, T0 + offset, instance, i + 1, 0, 0, h(i % 250), h(1), 0, 10 * (i + 1))
        for i, offset in enumerate(offsets_ms)
    ]


def liveness(applied: list["soak.Applied"], run: "soak.Timeline", instance: str | None, bound_ms: float):
    """O-LIVE over a list of applied events."""
    return soak.check_liveness(soak.commit_times(applied), run, instance, bound_ms)


def performance(
    applied: list["soak.Applied"],
    run: "soak.Timeline",
    instance: str | None,
    limits: "soak.Thresholds",
    load: "soak.LoadRecord | None",
):
    """O-PERF over a list of applied events."""
    return soak.check_performance(soak.commit_times(applied), run, instance, limits, load)


class LivenessTests(unittest.TestCase):
    def test_steady_intervals_are_the_complement_of_merged_windows(self) -> None:
        run = timeline([(10_000, 20_000, "kill", ("peer0",)), (15_000, 25_000, "net", ()), (90_000, 120_000, "disk", ())])
        self.assertEqual(
            run.steady_intervals(),
            [(T0, T0 + 10_000), (T0 + 25_000, T0 + 90_000)],
        )

    def test_commits_resuming_within_the_bound_after_every_heal_pass(self) -> None:
        run = timeline([(30_000, 40_000, "kill", ("peer1",))])
        offsets = [1_000 * i for i in range(1, 30)] + [45_000 + 1_000 * i for i in range(55)]
        applied = commits("peer0", offsets) + commits("peer1", offsets)
        violations, checked = liveness(applied, run, INSTANCE, bound_ms=10_000)
        self.assertEqual(violations, [])
        self.assertEqual(checked["steady_intervals"], 2)

    def test_a_stall_after_a_heal_and_a_stall_before_the_end_are_violations(self) -> None:
        run = timeline([(30_000, 40_000, "net", ())])
        healthy = [1_000 * i for i in range(1, 30)] + [41_000 + 1_000 * i for i in range(59)]
        late = [1_000 * i for i in range(1, 30)] + [60_000, 61_000]
        applied = commits("peer0", healthy) + commits("peer1", late)
        violations, _ = liveness(applied, run, INSTANCE, bound_ms=15_000)
        details = [(v.kind, v.detail["node"], v.detail["next_commit_ms"] is None) for v in violations]
        self.assertEqual(
            details,
            [("no-commit-within-bound", "peer1", False), ("no-commit-within-bound", "peer1", True)],
        )

    def test_an_interval_shorter_than_the_bound_is_not_judged_without_commits(self) -> None:
        run = timeline([(5_000, 95_000, "net", ())])
        violations, _ = liveness([], run, INSTANCE, bound_ms=10_000)
        self.assertEqual(violations, [])

    def test_exits_are_violations_unless_a_disk_window_of_that_node_explains_them(self) -> None:
        boots = [
            soak.Boot("peer0", 0, T0, T0 + 50_000, "exited:unknown"),
            soak.Boot("peer1", 0, T0, T0 + 12_000, "exited:unknown"),
            soak.Boot("peer1", 1, T0 + 20_000, T0 + 30_000, "killed"),
            soak.Boot("peer0", 1, T0 + 51_000, T0 + 100_000, "stopped"),
        ]
        run = timeline([(10_000, 20_000, "disk", ("peer1",))], boots)
        offsets = [1_000 * i for i in range(1, 100)]
        violations, _ = liveness(commits("peer0", offsets) + commits("peer1", offsets), run, INSTANCE, 30_000)
        self.assertEqual([(v.kind, v.detail["node"]) for v in violations], [("unexpected-exit", "peer0")])

    def test_no_commit_at_all_is_a_violation(self) -> None:
        violations, _ = liveness([], timeline(), None, bound_ms=10_000)
        self.assertIn("no-commit-at-all", kinds(violations))
        self.assertEqual(kinds(violations).count("no-commit-within-bound"), 2)

    def test_the_observed_instance_is_the_busiest(self) -> None:
        applied = commits("peer0", [1, 2, 3]) + commits("peer0", [4], instance=LANE)
        self.assertEqual(soak.commit_times(applied).observed_instance(), INSTANCE)
        self.assertIsNone(soak.commit_times([]).observed_instance())


def thresholds(**overrides: float) -> "soak.Thresholds":
    """Thresholds with small defaults for the tests."""
    values = dict(live_bound_ms=60_000.0, max_gap_p99_ms=1_500.0, max_gap_ms=5_000.0, max_latency_p99_ms=3_000.0, min_tps=0.0, warmup_heights=2)
    values.update(overrides)
    return soak.Thresholds(**values)


class PerformanceTests(unittest.TestCase):
    def test_percentiles_skip_the_warmup_and_fault_windows(self) -> None:
        run = timeline([(50_000, 60_000, "kill", ("peer1",))])
        # Before the fault: warm-up gaps of 9 s, then 1 s gaps; after the heal the same.
        offsets = [0, 9_000, 18_000] + [18_000 + 1_000 * i for i in range(1, 30)]
        offsets += [60_000, 69_000, 78_000] + [78_000 + 1_000 * i for i in range(1, 20)]
        violations, metrics = performance(commits("peer0", offsets), run, INSTANCE, thresholds(), None)
        self.assertEqual(violations, [])
        self.assertEqual(metrics["gap_p99_ms"], 1_000.0)
        self.assertEqual(metrics["gap_max_ms"], 1_000.0)
        self.assertEqual(metrics["gap_samples"], 28 + 18 + 2)
        self.assertIsNone(metrics["committed_tps"])

    def test_slow_gaps_are_violations(self) -> None:
        offsets = [2_000 * i for i in range(40)] + [90_000]
        violations, metrics = performance(commits("peer0", offsets), timeline(), INSTANCE, thresholds(), None)
        self.assertEqual(kinds(violations), ["gap-p99-above-threshold", "gap-max-above-threshold"])
        self.assertEqual(metrics["gap_max_ms"], 12_000.0)

    def test_no_gap_samples_is_a_violation(self) -> None:
        violations, _ = performance(commits("peer0", [0, 1_000]), timeline(), INSTANCE, thresholds(), None)
        self.assertEqual(kinds(violations), ["no-gap-samples"])

    def test_throughput_counts_counter_restarts_and_is_checked(self) -> None:
        samples = (
            soak.LoadSample(T0, "peer0", 0, 100),
            soak.LoadSample(T0 + 50_000, "peer0", 0, 400),
            soak.LoadSample(T0 + 60_000, "peer0", 1, 5),
            soak.LoadSample(T0 + 100_000, "peer0", 1, 205),
            soak.LoadSample(T0 + 100_000, "peer1", 0, 450),
        )
        self.assertEqual(soak.committed_transactions(samples), 500)
        load = soak.LoadRecord(submitted=900, attempted=1_000, samples=samples, probes=())
        offsets = [1_000 * i for i in range(90)]
        ok, metrics = performance(commits("peer0", offsets), timeline(), INSTANCE, thresholds(min_tps=4.0), load)
        self.assertEqual(ok, [])
        self.assertEqual(metrics["committed_tps"], 5.0)
        slow, _ = performance(commits("peer0", offsets), timeline(), INSTANCE, thresholds(min_tps=6.0), load)
        self.assertEqual(kinds(slow), ["throughput-below-threshold"])
        unmeasured, _ = performance(commits("peer0", offsets), timeline(), INSTANCE, thresholds(min_tps=1.0), None)
        self.assertEqual(kinds(unmeasured), ["throughput-unmeasured"])

    def test_latency_probes_in_fault_free_intervals_are_judged(self) -> None:
        run = timeline([(40_000, 50_000, "net", ())])
        probes = tuple(soak.Probe(T0 + 1_000 * i, T0 + 1_000 * i + 500, True) for i in range(30))
        probes += (soak.Probe(T0 + 41_000, T0 + 49_000, True),)  # inside the fault: ignored
        load = soak.LoadRecord(0, 0, (), probes)
        offsets = [1_000 * i for i in range(100)]
        violations, metrics = performance(commits("peer0", offsets), run, INSTANCE, thresholds(), load)
        self.assertEqual(violations, [])
        self.assertEqual((metrics["latency_samples"], metrics["latency_p99_ms"]), (30, 500.0))
        slow = soak.LoadRecord(0, 0, (), tuple(soak.Probe(T0 + 1_000 * i, T0 + 1_000 * i + 4_000, True) for i in range(10)))
        violations, _ = performance(commits("peer0", offsets), run, INSTANCE, thresholds(), slow)
        self.assertEqual(kinds(violations), ["latency-p99-above-threshold"])
        failed = soak.LoadRecord(0, 0, (), (soak.Probe(T0 + 1_000, T0 + 2_000, False),))
        violations, metrics = performance(commits("peer0", offsets), run, INSTANCE, thresholds(), failed)
        self.assertEqual(kinds(violations), ["no-successful-latency-probe"])
        self.assertEqual(metrics["latency_failed_probes"], 1)

    def test_nearest_rank_percentile(self) -> None:
        self.assertIsNone(soak.percentile([], 0.5))
        self.assertEqual(soak.percentile([5.0], 0.99), 5.0)
        self.assertEqual(soak.percentile(list(map(float, range(1, 101))), 0.99), 99.0)
        self.assertEqual(soak.percentile([3.0, 1.0, 2.0], 0.5), 2.0)


class BoundAndVerdictTests(unittest.TestCase):
    def test_live_bound_matches_the_spec_formula(self) -> None:
        # n = 4: f = 1, level_cap 7, B_view = 30000 + 5000 + 400 + 1000 + 2000 + 250.
        self.assertEqual(soak.live_bound_ms(soak.LiveBoundParams(n=4)), 10 * 38_650 + (1_000 + 1_000 + 64 * 5_000))
        # n = 22: f = 7, level_cap 6, B_view = 30000 + 5000 + 400 + 2000 + 2000 + 3 * 500.
        self.assertEqual(soak.live_bound_ms(soak.LiveBoundParams(n=22)), 15 * 40_900 + 322_000)
        self.assertEqual(soak.live_bound_ms(soak.LiveBoundParams(n=4, lag_heights=65)), 10 * 38_650 + 2 * 322_000)

    def test_verdict_of_a_clean_run_and_of_a_blind_one(self) -> None:
        chain = [applied_json(T0 + 1_000 * i, i, i) for i in range(1, 40)]
        record = [durable_json(T0 + 1_000 * i, i + 1, f"prepare:0:{h(i)}:{h(i + 1)}") for i in range(1, 40)]
        logs = {
            "peer0": node_log("peer0", [chain + record]),
            "peer1": node_log("peer1", [chain + [line.replace(KEY_A, KEY_B) for line in record]]),
        }
        run = timeline(end=40_000)
        limits = thresholds(live_bound_ms=30_000.0)  # the 40 s run can show a stall
        verdict = soak.build_verdict(soak.Analysis.from_logs(logs), run, limits, None, {"seed": 1, "faults": []})
        json.dumps(verdict)
        self.assertTrue(verdict["ok"], json.dumps(verdict, indent=1))
        self.assertEqual(verdict["schema"], soak.VERDICT_SCHEMA)
        self.assertEqual(verdict["run"], {"seed": 1, "faults": []})
        self.assertEqual(verdict["nodes"]["peer0"]["max_height"], 39)
        blind = {"peer0": node_log("peer0", [chain]), "peer1": node_log("peer1", [chain])}
        verdict = soak.build_verdict(soak.Analysis.from_logs(blind), run, limits, None)
        self.assertFalse(verdict["ok"])
        self.assertEqual([entry["kind"] for entry in verdict["harness"]], ["node-without-record-lines"])
        conflicting = dict(logs)
        conflicting["peer1"] = node_log("peer1", [[applied_json(T0 + 1_000, 1, 99)] + chain[1:] + [line.replace(KEY_A, KEY_B) for line in record]])
        verdict = soak.build_verdict(soak.Analysis.from_logs(conflicting), run, limits, None)
        self.assertFalse(verdict["ok"])
        self.assertFalse(verdict["oracles"]["O-AGR"]["ok"])
        self.assertTrue(verdict["oracles"]["O-SIGN"]["ok"])

    def test_a_run_without_an_interval_as_long_as_the_bound_is_a_harness_failure(self) -> None:
        chain = [applied_json(T0 + 1_000 * i, i, i) for i in range(1, 40)]
        record = [durable_json(T0 + 1_000 * i, i + 1, f"prepare:0:{h(i)}:{h(i + 1)}") for i in range(1, 40)]
        logs = {"peer0": node_log("peer0", [chain + record])}
        # Faults leave fault-free intervals of 20 s at most: a 30 s stall inside one is invisible.
        run = timeline([(20_000, 25_000, "net", ()), (45_000, 50_000, "net", ()), (70_000, 80_000, "net", ())], nodes=("peer0",))
        verdict = soak.build_verdict(soak.Analysis.from_logs(logs), run, thresholds(live_bound_ms=30_000.0), None)
        self.assertFalse(verdict["ok"])
        self.assertTrue(verdict["oracles"]["O-LIVE"]["ok"])
        self.assertEqual(verdict["oracles"]["O-LIVE"]["checked"]["judged_intervals"], 0)
        vacuous = [entry for entry in verdict["harness"] if entry["kind"] == "no-interval-judged-by-o-live"]
        self.assertEqual(vacuous, [{"oracle": "HARNESS", "kind": "no-interval-judged-by-o-live", "bound_ms": 30_000.0, "longest_interval_ms": 20_000.0}])
        judged = soak.build_verdict(soak.Analysis.from_logs(logs), run, thresholds(live_bound_ms=20_000.0), None)
        # Four fault-free intervals of 20 s each: 0-20, 25-45, 50-70 and 80-100 s.
        self.assertEqual(judged["oracles"]["O-LIVE"]["checked"]["judged_intervals"], 4)
        self.assertNotIn("no-interval-judged-by-o-live", [entry["kind"] for entry in judged["harness"]])

    def test_requested_fault_coverage_is_not_inferred_from_healthy_consensus(self) -> None:
        chain = [applied_json(T0 + 1_000 * i, i, i) for i in range(1, 100)]
        record = [durable_json(T0 + 1_000 * i, i + 1, f"prepare:0:{h(i)}:{h(i + 1)}") for i in range(1, 100)]
        analysis = soak.Analysis.from_logs({"peer0": node_log("peer0", [chain + record])})
        run = timeline([(10_000, 20_000, "kill", ("peer0",)), (30_000, 40_000, "disk", ("peer0",))], nodes=("peer0",))
        limits = thresholds(live_bound_ms=20_000.0)
        requested = {"faults": ["kill", "disk", "net"]}
        verdict = soak.build_verdict(analysis, run, limits, None, requested)
        self.assertTrue(all(entry["ok"] for entry in verdict["oracles"].values()))
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["harness"], [{"oracle": "HARNESS", "kind": "missing-requested-fault-kinds",
            "requested": ["disk", "kill", "net"], "observed": ["disk", "kill"], "missing": ["net"]}])
        # A nonempty in-run observed window is required, not a declared plan or a zero-size marker.
        for start, stop in ((50_000, 50_000), (-1, 1), (90_000, 110_000)):
            with self.subTest(start=start, stop=stop):
                partial = timeline([(10_000, 20_000, "kill", ("peer0",)), (30_000, 40_000, "disk", ("peer0",)), (start, stop, "net", ())], nodes=("peer0",))
                missing = soak.build_verdict(analysis, partial, limits, None, requested)
                self.assertFalse(missing["ok"])
                self.assertTrue(any(entry["kind"] == "missing-requested-fault-kinds" for entry in missing["harness"]))
        complete = timeline([(10_000, 20_000, "kill", ("peer0",)), (30_000, 40_000, "disk", ("peer0",)), (50_000, 60_000, "net", ())], nodes=("peer0",))
        self.assertTrue(soak.build_verdict(analysis, complete, limits, None, requested)["ok"])
        self.assertTrue(soak.build_verdict(analysis, timeline(nodes=("peer0",)), limits, None, {"faults": []})["ok"])

    def test_malformed_or_missing_report_fault_contract_cannot_pass(self) -> None:
        chain = [applied_json(T0 + 1_000 * i, i, i) for i in range(1, 40)]
        record = [durable_json(T0 + 1_000 * i, i + 1, "-") for i in range(1, 40)]
        analysis = soak.Analysis.from_logs({"peer0": node_log("peer0", [chain + record])})
        run = timeline(nodes=("peer0",), end=40_000)
        limits = thresholds(live_bound_ms=30_000.0)
        for contract in ({}, {"faults": None}, {"faults": "net"}, {"faults": ["net", "net"]}, {"faults": ["unknown"]}, {"faults": [1]}, {"faults": [["net"]]}):
            with self.subTest(contract=contract):
                verdict = soak.build_verdict(analysis, run, limits, None, contract)
                self.assertTrue(all(entry["ok"] for entry in verdict["oracles"].values()))
                self.assertFalse(verdict["ok"])
                self.assertEqual([entry["kind"] for entry in verdict["harness"]], ["invalid-requested-fault-kinds"])

    def test_timeline_round_trips(self) -> None:
        run = timeline([(1, 2, "kill", ("peer0",))], [soak.Boot("peer0", 0, T0, None, "running")])
        self.assertEqual(soak.Timeline.from_json(json.loads(json.dumps(run.to_json()))), run)


class StreamingTests(unittest.TestCase):
    """The incremental analysis of a run directory (``analyze_logs``), which judges a 24 h gate in
    bounded memory."""

    @staticmethod
    def write_logs(root: Path, per_node: dict[str, list[list[str]]]) -> Path:
        log_root = root / "logs"
        for node, boots in per_node.items():
            node_dir = log_root / node
            node_dir.mkdir(parents=True)
            for boot, lines in enumerate(boots):
                (node_dir / f"boot{boot}.log").write_text("\n".join(lines) + "\n")
        return log_root

    def test_streamed_and_kept_analyses_give_the_same_verdict(self) -> None:
        chain = [applied_json(T0 + 1_000 * i, i, i) for i in range(1, 40)]
        record = [durable_json(T0 + 1_000 * i, i + 1, f"prepare:0:{h(i)}:{h(i + 1)}") for i in range(1, 40)]
        other = [line.replace(KEY_A, KEY_B) for line in record]
        # peer1 commits another block at height 1 and its key signs two Prepares at (40, 0).
        other.append(durable_json(T0 + 39_500, 40, f"prepare:0:{h(77)}:{h(78)}", KEY_B))
        per_node = {
            "peer0": [chain[:20] + record[:20], chain[20:] + record[20:]],
            "peer1": [[applied_json(T0 + 1_000, 1, 99)] + chain[1:] + other],
        }
        run = timeline(end=40_000)
        with tempfile.TemporaryDirectory() as tmp:
            log_root = self.write_logs(Path(tmp), per_node)
            analysis = soak.analyze_logs(log_root)
            streamed = soak.build_verdict(analysis, run, thresholds(), None)
            kept = soak.build_verdict(soak.Analysis.from_logs(soak.load_node_logs(log_root)), run, thresholds(), None)
        self.assertEqual(streamed, kept)
        self.assertEqual([entry["kind"] for entry in streamed["oracles"]["O-AGR"]["violations"]], ["conflicting-commit"])
        self.assertEqual([entry["kind"] for entry in streamed["oracles"]["O-SIGN"]["violations"]], ["double-prepare"])
        self.assertEqual(streamed["nodes"]["peer0"]["boots"], 2)
        self.assertEqual(streamed["nodes"]["peer0"]["applied_lines"], 39)
        # The streamed analysis fed the oracles without keeping the events.
        self.assertEqual((analysis.nodes["peer0"].applied, analysis.nodes["peer0"].records), ([], []))

    def test_every_violation_is_counted_but_only_the_first_are_kept(self) -> None:
        # Every other height is missing: one chain gap per applied line after the first.
        gaps = [applied_json(T0 + i, 2 * i, i % 250) for i in range(1, soak.MAX_REPORTED_VIOLATIONS + 12)]
        analysis = soak.Analysis.from_logs({"peer0": node_log("peer0", [gaps])})
        kept, count, _ = analysis.agreement.finish()
        self.assertEqual(count, soak.MAX_REPORTED_VIOLATIONS + 10)
        self.assertEqual(len(kept), soak.MAX_REPORTED_VIOLATIONS)
        verdict = soak.build_verdict(analysis, timeline(nodes=("peer0",)), thresholds(), None)
        self.assertFalse(verdict["oracles"]["O-AGR"]["ok"])
        self.assertEqual(verdict["oracles"]["O-AGR"]["violation_count"], soak.MAX_REPORTED_VIOLATIONS + 10)
        self.assertEqual(len(verdict["oracles"]["O-AGR"]["violations"]), soak.MAX_REPORTED_VIOLATIONS)

    def test_parse_errors_are_counted_beyond_the_kept_examples(self) -> None:
        log = node_log("peer0", [[durable_json(T0, 1, "vote:1")] * (soak.MAX_KEPT_PARSE_ERRORS + 5)])
        self.assertEqual(log.parse_error_count, soak.MAX_KEPT_PARSE_ERRORS + 5)
        self.assertEqual(len(log.parse_errors), soak.MAX_KEPT_PARSE_ERRORS)
        verdict = soak.build_verdict(soak.Analysis.from_logs({"peer0": log}), timeline(nodes=("peer0",)), thresholds(), None)
        unparsed = [entry for entry in verdict["harness"] if entry["kind"] == "unparsed-audit-lines"]
        self.assertEqual(unparsed[0]["count"], soak.MAX_KEPT_PARSE_ERRORS + 5)
        self.assertFalse(verdict["ok"])

    def test_sign_once_keeps_only_recent_heights_and_still_judges_them(self) -> None:
        checker = soak.SignOnceChecker()
        for height in range(1, 1_001):
            for record in records([[durable_json(T0 + height, height, f"prepare:0:{h(height % 250)}:{h(1)}")]]):
                checker.add(record)
        self.assertEqual(len(checker.slots[(KEY_A, INSTANCE)]), soak.SignOnceChecker.KEEP_HEIGHTS + 1)
        self.assertEqual(checker.finish()[1], 0)
        # A second Prepare at the current height is still a double sign, and a record that
        # returns to a height long pruned is a rollback.
        late = [durable_json(T0 + 2_000, 1_000, f"prepare:0:{h(7)}:{h(8)}"), durable_json(T0 + 2_001, 3, "-")]
        for record in records([late]):
            checker.add(record)
        self.assertEqual(kinds(checker.finish()[0]), ["double-prepare", "record-regression"])


if __name__ == "__main__":
    unittest.main()
