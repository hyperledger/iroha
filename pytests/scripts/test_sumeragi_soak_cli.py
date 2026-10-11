"""Unit tests of the soak orchestrator (``scripts/sumeragi_soak.py``) that need no network:
argument parsing, profiles and thresholds, config rewriting, CLI output parsing, and the
offline verdict (``--analyze``) of a synthetic run directory, clean and violating.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sumeragi_soak.py"
SPEC = importlib.util.spec_from_file_location("sumeragi_soak_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = soak
SPEC.loader.exec_module(soak)
logs = soak.logs

T0 = 1_790_000_000_000.0
INSTANCE = "11" * 32


class ArgumentTests(unittest.TestCase):
    def test_durations(self) -> None:
        self.assertEqual(soak.parse_duration("300"), 300.0)
        self.assertEqual(soak.parse_duration("5m"), 300.0)
        self.assertEqual(soak.parse_duration("24h"), 86_400.0)
        self.assertEqual(soak.parse_duration("1d"), 86_400.0)
        self.assertEqual(soak.parse_duration("250ms"), 0.25)
        with self.assertRaises(argparse.ArgumentTypeError):
            soak.parse_duration("soon")

    def test_ranges_and_loss(self) -> None:
        self.assertEqual(soak.parse_range("15-60"), (15.0, 60.0))
        self.assertEqual(soak.parse_range("20"), (20.0, 20.0))
        self.assertEqual(soak.parse_loss("10-30"), (0.10, 0.30))
        self.assertEqual(soak.parse_loss("0.1-0.3"), (0.1, 0.3))
        for bad in ("30-10", "1-2-3"):
            with self.assertRaises(argparse.ArgumentTypeError):
                soak.parse_range(bad)
        with self.assertRaises(argparse.ArgumentTypeError):
            soak.parse_loss("50-150")

    def test_only_exact_3f_plus_1_committees(self) -> None:
        for good in (4, 7, 22, 31):
            self.assertEqual(soak.validators_arg(str(good)), good)
        for bad in (1, 3, 5, 21, 34):
            with self.assertRaises(argparse.ArgumentTypeError):
                soak.validators_arg(str(bad))

    def test_profiles_and_derived_thresholds(self) -> None:
        parser = soak.build_parser()
        gate = soak.resolve_options(parser.parse_args(["--profile", "gate", "--validators", "22", "--seed", "3", "--net-mode", "proxy"]))
        self.assertEqual(gate.duration_s, 86_400.0)
        self.assertEqual(gate.thresholds.live_bound_ms, logs.live_bound_ms(logs.LiveBoundParams(n=22)))
        self.assertEqual(gate.kinds, ("kill", "disk", "net"))
        self.assertEqual(gate.disk_node, 21)
        self.assertEqual(gate.max_kill, 1)
        self.assertEqual(gate.thresholds.min_tps, 10.0)  # half of the 20 tps load
        smoke = soak.resolve_options(
            parser.parse_args(
                ["--validators", "4", "--faults", "kill,net", "--net-mode", "proxy", "--duration", "4m", "--live-bound", "90s", "--max-kill", "5", "--min-tps", "0.5"]
            )
        )
        self.assertEqual((smoke.duration_s, smoke.thresholds.live_bound_ms), (240.0, 90_000.0))
        self.assertIsNone(smoke.disk_node)
        self.assertEqual(smoke.max_kill, 1)  # capped at f = 1
        self.assertEqual(smoke.thresholds.min_tps, 0.5)
        off = soak.resolve_options(parser.parse_args(["--net-mode", "off", "--seed", "1"]))
        self.assertEqual(off.kinds, ("kill", "disk"))
        self.assertEqual(soak.resolve_options(parser.parse_args(["--faults", "none", "--seed", "1"])).kinds, ())
        with self.assertRaises(SystemExit):
            soak.resolve_options(parser.parse_args(["--faults", "kill,flood"]))

    def test_the_final_interval_must_be_judgeable_by_o_live(self) -> None:
        parser = soak.build_parser()
        for arguments in (
            ["--final-quiet", "60s", "--live-bound", "90s"],
            ["--faults", "none", "--duration", "60s", "--live-bound", "90s"],
        ):
            with self.assertRaises(SystemExit, msg=arguments):
                soak.resolve_options(parser.parse_args(["--seed", "1", "--net-mode", "proxy", *arguments]))
        equal = soak.resolve_options(parser.parse_args(["--seed", "1", "--net-mode", "proxy", "--final-quiet", "90s", "--live-bound", "90s"]))
        self.assertEqual((equal.final_quiet_s, equal.thresholds.live_bound_ms), (90.0, 90_000.0))
        for n in range(4, 32, 3):
            gate = soak.resolve_options(parser.parse_args(["--profile", "gate", "--validators", str(n), "--seed", "1", "--net-mode", "proxy"]))
            self.assertGreaterEqual(gate.final_quiet_s * 1000.0, gate.thresholds.live_bound_ms, n)

    def test_the_storage_budget_fits_the_disk_full_volume(self) -> None:
        parser = soak.build_parser()
        gate = soak.resolve_options(parser.parse_args(["--profile", "gate", "--seed", "1", "--net-mode", "proxy"]))
        self.assertLess(gate.storage_budget_mb, gate.disk_size_mb)
        smoke = soak.resolve_options(parser.parse_args(["--seed", "1", "--net-mode", "proxy"]))
        self.assertLess(smoke.storage_budget_mb, smoke.disk_size_mb)
        explicit = soak.resolve_options(
            parser.parse_args(["--seed", "1", "--faults", "kill", "--storage-budget-mb", "4096", "--disk-size-mb", "1024"])
        )
        # Without a disk fault the volume does not exist, so the budget is not bound by it.
        self.assertEqual((explicit.storage_budget_mb, explicit.disk_node), (4096, None))
        for arguments in (["--storage-budget-mb", "2048", "--disk-size-mb", "2048"], ["--storage-budget-mb", "0"]):
            with self.assertRaises(SystemExit, msg=arguments):
                soak.resolve_options(parser.parse_args(["--seed", "1", "--faults", "kill,disk", *arguments]))


class FaultCoverageTests(unittest.TestCase):
    """Requested faults must be covered before namespace or native startup."""

    def test_seed_310_missing_network_fault_is_refused_before_any_launch(self) -> None:
        args = soak.build_parser().parse_args(["--seed", "310", "--net-mode", "proxy"])
        options = soak.resolve_options(args)
        plan = soak.faults.plan_faults(soak.faults.PlanOptions(
            duration_s=options.duration_s, warmup_s=options.warmup_s,
            final_quiet_s=options.final_quiet_s, kinds=options.kinds,
            validators=options.validators, disk_node=options.disk_node,
            gap_s=options.fault_gap, window_s=options.fault_window,
            loss=options.loss, max_kill=options.max_kill,
        ), random.Random(options.seed))
        self.assertEqual({fault.kind for fault in plan}, {"kill", "disk"})
        self.assertEqual((options.duration_s, options.final_quiet_s), (300.0, 100.0))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "uncreated"
            with mock.patch.object(soak, "enter_namespace_if_needed") as namespace, \
                 mock.patch.object(soak, "resolve_bins") as bins, \
                 mock.patch.object(soak, "Localnet") as net, \
                 mock.patch.object(soak.subprocess, "Popen", side_effect=AssertionError("native child forbidden")), \
                 mock.patch.object(soak.subprocess, "run", side_effect=AssertionError("native child forbidden")):
                with self.assertRaisesRegex(SystemExit, "does not cover requested kinds.*net"):
                    soak.main(["--seed", "310", "--net-mode", "proxy", "--out", str(out)])
                namespace.assert_not_called()
                bins.assert_not_called()
                net.assert_not_called()
            self.assertFalse(out.exists())

    def test_explicit_empty_and_complete_plans_keep_the_existing_startup_path(self) -> None:
        for arguments in (["--faults", "none", "--seed", "310"], ["--profile", "gate", "--seed", "310"]):
            with self.subTest(arguments=arguments):
                with mock.patch.object(soak, "enter_namespace_if_needed", side_effect=RuntimeError("preflight complete")) as namespace:
                    with self.assertRaisesRegex(RuntimeError, "preflight complete"):
                        soak.main(["--net-mode", "proxy", *arguments])
                    namespace.assert_called_once()

    def test_an_empty_supplied_plan_cannot_bypass_requested_coverage(self) -> None:
        with mock.patch.object(soak.faults, "plan_faults", return_value=[]), \
             mock.patch.object(soak, "enter_namespace_if_needed") as namespace:
            with self.assertRaisesRegex(SystemExit, "does not cover requested kinds.*kill"):
                soak.main(["--net-mode", "proxy", "--seed", "1"])
            namespace.assert_not_called()


    def test_supplied_invalid_timing_or_kind_plan_is_refused_before_startup(self) -> None:
        plans = (
            [soak.faults.Fault("unknown", 45.0, 20.0)],
            [soak.faults.Fault("net", 45.0, 0.0)],
            [soak.faults.Fault("net", 45.0, -1.0)],
            [soak.faults.Fault("net", 45.0, float("nan"))],
            [soak.faults.Fault("net", 45.0, float("inf"))],
            [soak.faults.Fault("net", 44.0, 20.0)],
            [soak.faults.Fault("net", 45.0, 200.0)],
            [soak.faults.Fault("net", 45.0, 20.0), soak.faults.Fault("kill", 50.0, 20.0)],
            [soak.faults.Fault("kill", 45.0, 20.0)],
            [soak.faults.Fault("kill", 45.0, 20.0, (0, 0))],
            [soak.faults.Fault("kill", 45.0, 20.0, (4,))],
            [soak.faults.Fault("disk", 45.0, 20.0, (0,))],
            [soak.faults.Fault("net", 45.0, 20.0, (0,))],
        )
        for plan in plans:
            with self.subTest(plan=plan):
                with mock.patch.object(soak.faults, "plan_faults", return_value=plan), \
                     mock.patch.object(soak, "enter_namespace_if_needed") as namespace:
                    with self.assertRaisesRegex(SystemExit, "invalid fault plan"):
                        soak.main(["--net-mode", "proxy", "--seed", "1"])
                    namespace.assert_not_called()


class FaultExecutionTests(unittest.TestCase):
    """Clock/owner models verify actual injection bookkeeping without children or sockets."""

    def options(self):
        return soak.resolve_options(soak.build_parser().parse_args(["--net-mode", "proxy", "--seed", "1"]))

    def test_expired_kill_disk_and_network_windows_refuse_before_side_effects(self) -> None:
        for kind in ("kill", "disk", "net"):
            with self.subTest(kind=kind):
                net, conditions, netem, volume = mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
                fault = soak.faults.Fault(kind, 0.0, 1.0, (0,) if kind != "net" else (), 0.1)
                with mock.patch.object(soak.time, "monotonic", return_value=10.0), \
                     mock.patch.object(soak, "now_ms", side_effect=[1_000.0, 1_001.0]), \
                     mock.patch.object(soak, "supervise_until") as supervise:
                    with self.assertRaisesRegex(RuntimeError, "expired before injection"):
                        soak.run_fault(fault, net, 9.0, random.Random(1), self.options(), conditions, netem, volume)
                net.kill.assert_not_called()
                net.start.assert_not_called()
                volume.fill.assert_not_called()
                conditions.set.assert_not_called()
                netem.apply.assert_not_called()
                supervise.assert_not_called()

    def test_slow_kill_or_disk_injection_cannot_record_an_expired_window(self) -> None:
        for kind in ("kill", "disk"):
            with self.subTest(kind=kind):
                net, volume = mock.Mock(), mock.Mock()
                volume.fill.return_value = 1024
                with mock.patch.object(soak.time, "monotonic", side_effect=[9.0, 10.0]), \
                     mock.patch.object(soak, "now_ms", side_effect=[1_000.0, 1_001.0]), \
                     mock.patch.object(soak, "supervise_until") as supervise:
                    with self.assertRaisesRegex(RuntimeError, "expired before injection completed"):
                        soak.run_fault(soak.faults.Fault(kind, 0.0, 1.0, (0,)), net, 9.0,
                            random.Random(1), self.options(), mock.Mock(), None, volume)
                if kind == "kill":
                    net.kill.assert_called_once_with(0)
                    volume.fill.assert_not_called()
                else:
                    volume.fill.assert_called_once()
                supervise.assert_not_called()
                net.start.assert_not_called()
                # The orchestrator catches this error and performs its original full cleanup.
                volume.free.assert_not_called()

    def test_network_expiring_after_entry_check_cannot_record_a_clear_only_window(self) -> None:
        for kernel in (False, True):
            with self.subTest(kernel=kernel):
                conditions = mock.Mock()
                netem = mock.Mock() if kernel else None
                with mock.patch.object(soak.time, "monotonic", side_effect=[9.5, 10.0]), \
                     mock.patch.object(soak, "now_ms", side_effect=[1_000.0, 1_001.0]), \
                     mock.patch.object(soak, "supervise_until") as supervise:
                    with self.assertRaisesRegex(RuntimeError, "without applying a non-clear condition"):
                        soak.run_fault(soak.faults.Fault("net", 0.0, 1.0, loss=0.1), mock.Mock(), 9.0,
                            random.Random(1), self.options(), conditions, netem, None)
                conditions.set.assert_called_once_with(soak.faults.CLEAR)
                if netem is not None:
                    netem.apply.assert_called_once_with(soak.faults.CLEAR)
                supervise.assert_not_called()

    def test_condition_application_must_complete_before_the_original_deadline(self) -> None:
        for kernel in (False, True):
            for completed in (9.5, 10.0, 11.0):
                with self.subTest(kernel=kernel, completed=completed):
                    clock = {"now": 9.0}
                    conditions = soak.faults.ConditionBox()
                    original_set = conditions.set
                    observed_commands = []

                    def set_condition(condition):
                        if not kernel and condition != soak.faults.CLEAR:
                            # Model a delayed lock acquisition before the proxy condition becomes visible.
                            clock["now"] = completed
                        original_set(condition)

                    def kernel_apply(command, *, check):
                        self.assertTrue(check)
                        observed_commands.append(command)
                        if command[-1] != "0%":
                            clock["now"] = completed

                    netem = soak.faults.Netem([11337], run=kernel_apply) if kernel else None

                    def supervise(*_args):
                        clock["now"] = max(clock["now"], 10.0)

                    with mock.patch.object(conditions, "set", side_effect=set_condition), \
                         mock.patch.object(soak.time, "monotonic", side_effect=lambda: clock["now"]), \
                         mock.patch.object(soak, "now_ms", side_effect=lambda: clock["now"] * 1_000), \
                         mock.patch.object(soak, "supervise_until", side_effect=supervise):
                        args = (soak.faults.Fault("net", 0.0, 1.0, loss=0.1), mock.Mock(), 9.0,
                            random.Random(1), self.options(), conditions, netem, None)
                        if completed < 10.0:
                            window = soak.run_fault(*args)
                            self.assertEqual(window, {"start_ms": 9_000.0, "end_ms": 10_000.0,
                                "kind": "net", "nodes": []})
                        else:
                            with self.assertRaisesRegex(RuntimeError, "application completed at or after its endpoint"):
                                soak.run_fault(*args)
                    # Refusal is after the original healing path, for both ownership routes.
                    self.assertEqual(conditions.get(), soak.faults.CLEAR)
                    if kernel:
                        self.assertEqual(len(observed_commands), 2)
                        self.assertEqual(observed_commands[0][-2:], ["loss", "10%"])
                        self.assertEqual(observed_commands[1][-2:], ["loss", "0%"])

    def test_a_late_subsequent_condition_cannot_reuse_earlier_success(self) -> None:
        for kernel in (False, True):
            for second_completed in (9.75, 10.0, 11.0):
                with self.subTest(kernel=kernel, second_completed=second_completed):
                    clock = {"now": 9.0, "injections": 0, "supervision": 0}
                    completion = (9.25, second_completed)
                    conditions = soak.faults.ConditionBox()
                    original_set = conditions.set
                    observed_commands = []

                    def injected():
                        clock["now"] = completion[clock["injections"]]
                        clock["injections"] += 1

                    def set_condition(condition):
                        if not kernel and condition != soak.faults.CLEAR:
                            injected()
                        original_set(condition)

                    def kernel_apply(command, *, check):
                        self.assertTrue(check)
                        observed_commands.append(command)
                        if command[-1] != "0%":
                            injected()

                    def supervise(*_args):
                        clock["supervision"] += 1
                        clock["now"] = max(clock["now"], 9.25 if clock["supervision"] == 1 else 10.0)

                    netem = soak.faults.Netem([11337], run=kernel_apply) if kernel else None
                    with mock.patch.object(conditions, "set", side_effect=set_condition), \
                         mock.patch.object(soak.faults, "spike_plan", return_value=[(0.25, 0.5, 300.0)]), \
                         mock.patch.object(soak.time, "monotonic", side_effect=lambda: clock["now"]), \
                         mock.patch.object(soak, "now_ms", side_effect=lambda: clock["now"] * 1_000), \
                         mock.patch.object(soak, "supervise_until", side_effect=supervise):
                        args = (soak.faults.Fault("net", 0.0, 1.0, loss=0.1), mock.Mock(), 9.0,
                            random.Random(1), self.options(), conditions, netem, None)
                        if second_completed < 10.0:
                            window = soak.run_fault(*args)
                            self.assertEqual(window["kind"], "net")
                            self.assertEqual(window["end_ms"], 10_000.0)
                        else:
                            with self.assertRaisesRegex(RuntimeError, "application completed at or after its endpoint"):
                                soak.run_fault(*args)
                    self.assertEqual(clock["injections"], 2)
                    self.assertEqual(conditions.get(), soak.faults.CLEAR)
                    if kernel:
                        self.assertEqual(len(observed_commands), 3)
                        self.assertNotEqual(observed_commands[0], observed_commands[1])
                        self.assertEqual(observed_commands[-1][-2:], ["loss", "0%"])

    def test_genuine_non_clear_condition_is_applied_then_healed_before_recording(self) -> None:
        for kernel in (False, True):
            with self.subTest(kernel=kernel):
                conditions = mock.Mock()
                netem = mock.Mock() if kernel else None
                with mock.patch.object(soak.time, "monotonic", side_effect=[9.0, 9.5, 9.75, 10.0]), \
                     mock.patch.object(soak, "now_ms", side_effect=[1_000.0, 1_100.0]), \
                     mock.patch.object(soak, "supervise_until") as supervise:
                    observed = soak.run_fault(soak.faults.Fault("net", 0.0, 1.0, loss=0.1), mock.Mock(), 9.0,
                        random.Random(1), self.options(), conditions, netem, None)
                applied = [call.args[0] for call in conditions.set.call_args_list]
                self.assertEqual(len(applied), 2)
                self.assertNotEqual(applied[0], soak.faults.CLEAR)
                self.assertEqual(applied[1], soak.faults.CLEAR)
                if netem is not None:
                    self.assertEqual([call.args[0] for call in netem.apply.call_args_list], applied)
                supervise.assert_called_once()
                self.assertEqual(observed, {"start_ms": 1_000.0, "end_ms": 1_100.0, "kind": "net", "nodes": []})


class KillCustodyTests(unittest.TestCase):
    """A kill is observed only after exit; failed injection retains PID and boot custody."""

    def network(self):
        net = soak.Localnet(Path("unused-pure-fixture"), {}, 4, 1, 18080, 11337)
        peer = net.peers[0]
        peer.pid, peer.boot, peer.boot_start_ms = 123, 0, 1_000.0
        return net, peer

    def test_kill_timeout_retains_original_live_process_and_boot(self) -> None:
        net, peer = self.network()
        with mock.patch.object(soak.os, "kill") as signal, \
             mock.patch.object(soak.time, "monotonic", side_effect=[0.0, 30.0]), \
             mock.patch.object(soak.time, "sleep") as sleep, \
             mock.patch.object(net, "alive", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "remained alive.*30 s"):
                net.kill(0)
        signal.assert_called_once_with(123, soak.signal.SIGKILL)
        sleep.assert_not_called()
        self.assertIs(net.peers[0], peer)
        self.assertEqual((peer.pid, peer.boot, peer.boot_start_ms), (123, 0, 1_000.0))
        self.assertEqual(net.boots, [])

    def test_already_exited_process_is_not_relabelled_an_intentional_kill(self) -> None:
        net, peer = self.network()
        with mock.patch.object(soak.os, "kill", side_effect=ProcessLookupError) as signal, \
             mock.patch.object(net, "alive") as alive:
            with self.assertRaisesRegex(RuntimeError, "exited before kill injection"):
                net.kill(0)
        signal.assert_called_once_with(123, soak.signal.SIGKILL)
        alive.assert_not_called()
        self.assertIs(net.peers[0], peer)
        self.assertEqual((peer.pid, peer.boot), (123, 0))
        self.assertEqual(net.boots, [])

    def test_absent_pid_is_not_an_observed_kill(self) -> None:
        net, peer = self.network()
        peer.pid = None
        with mock.patch.object(soak.os, "kill") as signal:
            with self.assertRaisesRegex(RuntimeError, "not running before kill injection"):
                net.kill(0)
        signal.assert_not_called()
        self.assertEqual(net.boots, [])

    def test_successful_original_kill_records_boot_only_after_exit(self) -> None:
        net, peer = self.network()
        with mock.patch.object(soak.os, "kill") as signal, \
             mock.patch.object(soak.time, "monotonic", side_effect=[0.0, 0.1]), \
             mock.patch.object(soak.time, "sleep") as sleep, \
             mock.patch.object(net, "alive", side_effect=[True, False, False]), \
             mock.patch.object(soak, "now_ms", return_value=1_050.0):
            net.kill(0)
        signal.assert_called_once_with(123, soak.signal.SIGKILL)
        sleep.assert_called_once_with(0.05)
        self.assertIs(net.peers[0], peer)
        self.assertIsNone(peer.pid)
        self.assertEqual(len(net.boots), 1)
        self.assertEqual((net.boots[0].node, net.boots[0].index, net.boots[0].start_ms,
            net.boots[0].end_ms, net.boots[0].ended), ("peer0", 0, 1_000.0, 1_050.0, "killed"))


class RewriteTests(unittest.TestCase):
    CONFIG = """chain = "soak"
public_key = "ea0130..."
trusted_peers = ["ea01@127.0.0.1:11337", "ea02@127.0.0.1:11338"]

[network]
address = "127.0.0.1:11337"
public_address = "127.0.0.1:11337"

[logger]
format = "compact"
level = "info"

[torii]
address = "127.0.0.1:18080"
"""

    def test_logger_keys_are_replaced_and_added(self) -> None:
        text = soak.set_toml_keys(self.CONFIG, "logger", {"format": '"json"', "filter": '"info,a=debug"'})
        self.assertIn('[logger]\nformat = "json"\nlevel = "info"\nfilter = "info,a=debug"\n\n[torii]', text)
        created = soak.set_toml_keys('x = 1\n', "logger", {"format": '"json"'})
        self.assertEqual(created, 'x = 1\n\n[logger]\nformat = "json"\n')

    def test_advertised_p2p_addresses_point_at_the_proxies(self) -> None:
        text = soak.rewrite_p2p_ports(self.CONFIG, {11337: 11437, 11338: 11438})
        self.assertIn('trusted_peers = ["ea01@127.0.0.1:11437", "ea02@127.0.0.1:11438"]', text)
        self.assertIn('address = "127.0.0.1:11337"\npublic_address = "127.0.0.1:11437"', text)
        self.assertIn('[torii]\naddress = "127.0.0.1:18080"', text)
        multiline = 'trusted_peers = [\n  "ea01@127.0.0.1:11337",\n]\n'
        self.assertIn('"ea01@127.0.0.1:11437"', soak.rewrite_p2p_ports(multiline, {11337: 11437}))

    def test_checksummed_address_literals_get_a_fresh_checksum(self) -> None:
        # Literals of a real kagami localnet config (crates/norito/src/literal.rs checksums).
        self.assertEqual(soak.addr_literal("127.0.0.1", 11437), "addr:127.0.0.1:11437#FAEF")
        self.assertEqual(soak.addr_literal("0.0.0.0", 18180), "addr:0.0.0.0:18180#1826")
        config = (
            'trusted_peers = ["ea01@addr:127.0.0.1:11437#FAEF", "ea02@addr:127.0.0.1:11438#0B00"]\n\n'
            '[network]\naddress = "addr:0.0.0.0:11437#ACBC"\npublic_address = "addr:127.0.0.1:11437#FAEF"\n\n'
            '[torii]\naddress = "addr:0.0.0.0:18180#1826"\n'
        )
        text = soak.rewrite_p2p_ports(config, {11437: 11537, 11438: 11538})
        self.assertIn(f'"ea01@{soak.addr_literal("127.0.0.1", 11537)}", "ea02@{soak.addr_literal("127.0.0.1", 11538)}"', text)
        self.assertIn('address = "addr:0.0.0.0:11437#ACBC"', text)
        self.assertIn(f'public_address = "{soak.addr_literal("127.0.0.1", 11537)}"', text)
        self.assertIn('[torii]\naddress = "addr:0.0.0.0:18180#1826"', text)

    def test_the_disk_peer_keeps_kura_under_its_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            net = soak.Localnet(Path(tmp), {}, 4, 1, 18080, 11337)
            (net.net_dir / "storage" / "peer3").mkdir(parents=True)
            (net.net_dir / "storage" / "peer3" / "blocks").write_text("kura")
            net.config(3).write_text(
                f'a = 1\n\n[kura]\nstore_dir = "{net.net_dir}/storage/peer3"\nfsync_mode = "batched"\n\n[logger]\nformat = "compact"\n'
            )
            target = net.move_kura_into_state(3)
            self.assertEqual(target, net.state_dir(3) / "kura")
            self.assertEqual((target / "blocks").read_text(), "kura")
            self.assertFalse((net.net_dir / "storage" / "peer3").exists())
            text = net.config(3).read_text()
            self.assertIn(f'[kura]\nstore_dir = "{target}"\nfsync_mode = "batched"', text)
            net.config(2).write_text("[logger]\n")
            with self.assertRaises(RuntimeError):
                net.move_kura_into_state(2)

    def test_string_values_are_read_from_their_own_table(self) -> None:
        text = (
            'public_key = "top"\n\n[account]\nchain_discriminant = 753\npublic_key  = "ed0120AB"  # comment\n\n'
            '[[torii.account_onboarding.credentials]]\npublic_key = "array"\n\n'
            '[torii.faucet]\nasset_definition_id = "6TEA\\"x"\nenabled = true\n'
        )
        self.assertEqual(soak.toml_string_value(text, "account", "public_key"), "ed0120AB")
        self.assertEqual(soak.toml_string_value(text, "torii.faucet", "asset_definition_id"), '6TEA"x')
        self.assertIsNone(soak.toml_string_value(text, "torii.faucet", "enabled"))  # not a string
        self.assertIsNone(soak.toml_string_value(text, "nexus.fees", "fee_asset_id"))
        self.assertIsNone(soak.toml_string_value(text, "torii.account_onboarding.credentials", "public_key"))

    def test_the_fund_quantity_is_a_decimal(self) -> None:
        parser = soak.build_parser()
        self.assertEqual(soak.resolve_options(parser.parse_args(["--seed", "1"])).fund, soak.DEFAULT_FUND)
        self.assertEqual(soak.resolve_options(parser.parse_args(["--seed", "1", "--fund", "0"])).fund, "0")
        for bad in ("-5", "1e6", "lots"):
            with self.assertRaises(SystemExit, msg=bad):
                soak.resolve_options(parser.parse_args(["--seed", "1", "--fund", bad]))

    def test_relative_paths_of_a_copied_config_become_absolute(self) -> None:
        base = Path("/net")
        text = 'chain = "c"\nnetwork_id_file = "genesis.expected_hash"\n\n[x]\nnetwork_id_file = "other"\n'
        self.assertEqual(
            soak.absolutize_path_key(text, "network_id_file", base),
            'chain = "c"\nnetwork_id_file = "/net/genesis.expected_hash"\n\n[x]\nnetwork_id_file = "other"\n',
        )
        absolute = 'network_id_file = "/elsewhere/id"\n'
        self.assertEqual(soak.absolutize_path_key(absolute, "network_id_file", base), absolute)
        self.assertEqual(soak.absolutize_path_key("a = 1\n", "network_id_file", base), "a = 1\n")

    def test_client_configs_talk_to_their_peer_and_keep_the_network_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            net = soak.Localnet(Path(tmp), {}, 4, 1, 18080, 11337)
            net.net_dir.mkdir(parents=True)
            (net.net_dir / "client.toml").write_text(
                'chain = "c"\nnetwork_id_file = "genesis.expected_hash"\ntorii_url = "http://127.0.0.1:18080/"\n\n'
                '[account]\nchain_discriminant = 753\nprivate_key = "secret"\n'
            )
            path = net.client_config(2)
            text = path.read_text()
            self.assertIn(f'network_id_file = "{net.net_dir / "genesis.expected_hash"}"', text)
            self.assertIn('torii_url = "http://127.0.0.1:18082/"', text)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(entry.name for entry in path.parent.iterdir()), ["client2.toml"])
            self.assertEqual(net.client_config(2), path)

    def test_process_liveness(self) -> None:
        import subprocess

        self.assertTrue(soak.process_running(os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        self.assertFalse(soak.process_running(child.pid))

    def test_ping_output(self) -> None:
        self.assertEqual(soak.parse_submitted("Clamped\nSubmitted 7/10 ping transactions without confirmation\n"), (7, 10))
        self.assertIsNone(soak.parse_submitted("error: connection refused"))


def applied_line(ms: float, height: int, block: int) -> str:
    from datetime import datetime, timezone

    stamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return json.dumps(
        {
            "timestamp": stamp,
            "level": "INFO",
            "fields": {
                "message": logs.APPLIED_MESSAGE,
                "instance": INSTANCE,
                "height": height,
                "view": 0,
                "origin_view": 0,
                "block": f"{block:02x}" * 32,
                "result": "ee" * 32,
                "proposer": 0,
                "payload_bytes": 10,
            },
        }
    )


def durable_line(ms: float, height: int, key: str) -> str:
    from datetime import datetime, timezone

    stamp = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return json.dumps(
        {
            "timestamp": stamp,
            "level": "DEBUG",
            "fields": {
                "message": logs.DURABLE_MESSAGE,
                "instance": INSTANCE,
                "key": key,
                "height": height,
                "epoch": 1,
                "signed": "prepare:0:" + "aa" * 32 + ":" + "bb" * 32,
            },
        }
    )


class AnalyzeTests(unittest.TestCase):
    def write_run(self, root: Path, conflicting: bool) -> None:
        run = {
            "seed": 9,
            "validators": 4,
            "faults": ["kill"],
            "net_mode": "proxy",
            "platform": "test",
            "duration_s": 60.0,
            "load_tps": 5.0,
            "thresholds": {
                "live_bound_ms": 20_000.0,
                "max_gap_p99_ms": 2_000.0,
                "max_gap_ms": 5_000.0,
                "max_latency_p99_ms": 5_000.0,
                "min_tps": 0.0,
                "warmup_heights": 2,
            },
            "proxy": {"connections": 3},
        }
        (root / "run.json").write_text(json.dumps(run))
        nodes = [f"peer{index}" for index in range(4)]
        timeline = logs.Timeline(
            start_ms=T0,
            end_ms=T0 + 60_000,
            nodes=tuple(nodes),
            windows=(logs.Window(T0 + 20_000, T0 + 30_000, "kill", ("peer3",)),),
            boots=(
                logs.Boot("peer3", 0, T0, T0 + 20_000, "killed"),
                logs.Boot("peer3", 1, T0 + 30_000, T0 + 60_000, "stopped"),
            ),
        )
        (root / "timeline.json").write_text(json.dumps(timeline.to_json()))
        (root / "load.json").write_text(json.dumps({"submitted": 10, "attempted": 10, "samples": [], "probes": []}))
        for index, node in enumerate(nodes):
            node_dir = root / "logs" / node
            node_dir.mkdir(parents=True)
            key = f"{index + 1:02x}" * 48
            lines = []
            for height in range(1, 60):
                block = height
                if conflicting and index == 0 and height == 40:
                    block = 0xEE
                lines.append(applied_line(T0 + 1_000 * height, height, block))
                lines.append(durable_line(T0 + 1_000 * height + 1, height + 1, key))
            if node == "peer3":
                # Killed after height 19; the restart at 30 s syncs heights 20..29 at once.
                (node_dir / "boot0.log").write_text("\n".join(lines[:38]) + "\n")
                catch_up = [applied_line(T0 + 30_000 + 50 * (height - 20), height, height) for height in range(20, 30)]
                (node_dir / "boot1.log").write_text("\n".join(catch_up + lines[58:]) + "\n")
            else:
                (node_dir / "boot0.log").write_text("\n".join(lines) + "\n")

    def test_report_only_refuses_missing_requested_faults_and_missing_contract(self) -> None:
        for requested in (["kill", "net"], None):
            with self.subTest(requested=requested), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_run(root, conflicting=False)
                record = json.loads((root / "run.json").read_text())
                if requested is None:
                    del record["faults"]
                else:
                    record["faults"] = requested
                (root / "run.json").write_text(json.dumps(record))
                with mock.patch.object(soak.subprocess, "Popen", side_effect=AssertionError("native child forbidden")), \
                     mock.patch.object(soak.subprocess, "run", side_effect=AssertionError("native child forbidden")):
                    self.assertEqual(soak.main(["--analyze", str(root)]), soak.EXIT_VIOLATION)
                verdict = json.loads((root / "verdict.json").read_text())
                self.assertTrue(all(entry["ok"] for entry in verdict["oracles"].values()))
                expected = "invalid-requested-fault-kinds" if requested is None else "missing-requested-fault-kinds"
                self.assertEqual([entry["kind"] for entry in verdict["harness"]], [expected])

    def test_a_clean_run_passes_and_a_conflicting_commit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_run(root, conflicting=False)
            self.assertEqual(soak.main(["--analyze", str(root)]), soak.EXIT_OK)
            verdict = json.loads((root / "verdict.json").read_text())
            self.assertTrue(verdict["ok"], json.dumps(verdict, indent=1))
            self.assertEqual(verdict["run"]["seed"], 9)
            self.assertEqual(verdict["proxy"], {"connections": 3})
            self.assertEqual(verdict["timeline"]["kills"], 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_run(root, conflicting=True)
            self.assertEqual(soak.main(["--analyze", str(root)]), soak.EXIT_VIOLATION)
            verdict = json.loads((root / "verdict.json").read_text())
            self.assertEqual(
                [entry["kind"] for entry in verdict["oracles"]["O-AGR"]["violations"]],
                ["conflicting-commit"],
            )


if __name__ == "__main__":
    unittest.main()
