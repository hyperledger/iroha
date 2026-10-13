"""Phase and resource harness: schema twin, real native child, retained failures,
public-only retention, enforced limits and salvage from the evidence itself."""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "scripts"))
import zk_resource_harness as harness

FIXTURES = REPOSITORY / "crates" / "iroha_measurement" / "fixtures"
DESCRIPTOR = harness.load_descriptor()
GOLDEN = json.loads((FIXTURES / "measurement_record_v1.json").read_text())
MUTATIONS = json.loads((FIXTURES / "record_mutations_v1.json").read_text())
# A direct native executable: framework Python launchers may exec another image.
TEE = Path(shutil.which("tee") or "/usr/bin/tee").resolve()
CAT = Path(shutil.which("cat") or "/bin/cat").resolve()
SCOPE = ["--hardware", "reference/unit-test-host", "--profile", "test+tee",
         "--config", "defaults", "--cache-policy", "warm"]


def walk(value, path):
    for key in path:
        value = value[key]
    return value


def mutated(case):
    """Apply one case of the shared mutation fixture to a copy of the golden view."""
    view = copy.deepcopy(GOLDEN)
    for operation in case.get("set", []):
        *parents, last = operation["path"]
        walk(view, parents)[last] = copy.deepcopy(operation["value"])
    for operation in case.get("append", []):
        walk(view, operation["path"]).append(copy.deepcopy(operation["value"]))
    for path in case.get("remove", []):
        *parents, last = path
        del walk(view, parents)[last]
    return view


def git(repository, *arguments, stdin=None):
    environment = dict(os.environ, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                       GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                       GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z")
    return subprocess.run(["git", "-C", str(repository), *arguments], input=stdin, env=environment,
                          capture_output=True, check=True).stdout.strip()


def fixture_repository(directory):
    """A small repository with one plumbing commit; no signing or user config is touched."""
    repository = Path(directory) / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / "source.txt").write_text("tracked\n")
    (repository / ".gitignore").write_text("generated/\n")
    (repository / "tracked").mkdir()
    (repository / "tracked" / "kept.txt").write_text("kept\n")
    git(repository, "add", "source.txt", ".gitignore", "tracked/kept.txt")
    tree = git(repository, "write-tree").decode()
    commit = git(repository, "commit-tree", tree, "-m", "fixture").decode()
    git(repository, "update-ref", "HEAD", commit)
    return repository.resolve()


def run_harness(arguments, stdin=None):
    """Invoke the CLI in-process; return (exit status, parsed stdout line, stderr)."""
    parsed = harness.parser().parse_args(arguments)
    if stdin is not None:
        parsed.stdin = stdin
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            status = parsed.handler(parsed)
        except harness.HarnessRefusal as refusal:
            return 2, {"refused": str(refusal)}, err.getvalue()
    lines = [json.loads(line) for line in out.getvalue().splitlines() if line]
    return status, (lines[-1] if lines else None), err.getvalue()


class SchemaTwinTests(unittest.TestCase):
    def test_descriptor_is_the_tracked_rust_generated_schema(self):
        self.assertEqual(DESCRIPTOR["record_schema"], "iroha.measurement.record.v1")
        self.assertEqual(DESCRIPTOR["harness_output_dir_env"], "IROHA_MEASUREMENT_OUTPUT_DIR")
        self.assertEqual(DESCRIPTOR["limits"]["unattributed_numerator"], 1)
        self.assertEqual(DESCRIPTOR["limits"]["unattributed_denominator"], 100)
        self.assertEqual(set(DESCRIPTOR["enums"]["classification"]),
                         {"projection", "engineering_target", "deterministic_consensus_bound",
                          "local_scheduling", "measured"})
        self.assertEqual(len(DESCRIPTOR["fields"]), 19)
        self.assertEqual(DESCRIPTOR["norito_sibling_emitter_prefixes"], ["rust."])
        self.assertEqual(DESCRIPTOR["classification_by_section"]["work_counters"], "measured")
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "schema.json"
            wrong.write_text(json.dumps({"fields": {}}))
            with self.assertRaises(harness.HarnessRefusal):
                harness.load_descriptor(wrong)

    def test_golden_record_decodes_with_no_finding_and_every_number_classified(self):
        record = harness.decode_record(DESCRIPTOR, copy.deepcopy(GOLDEN))
        self.assertEqual(harness.record_findings(DESCRIPTOR, record), [])
        self.assertEqual(harness.unclassified_numbers(DESCRIPTOR, record), [])
        measured = harness.attribution(record)
        self.assertEqual(measured, {"root_wall_ns": 1_000_000_000, "unattributed_wall_ns": 1_000_000})
        self.assertTrue(harness.within_limit(DESCRIPTOR, measured))
        self.assertEqual(harness.unattributed_ppm(measured), 1000)

    def test_largest_undivided_phase_matches_the_rust_report(self):
        # The same values as `largest_undivided_phase_states_how_coarse_the_tree_is`.
        self.assertEqual(harness.largest_undivided_phase(DESCRIPTOR, GOLDEN),
                         {"phase": 2, "label": "transform", "wall_exclusive_ns": 600_000_000,
                          "share_ppm": 600_000})
        tied = copy.deepcopy(GOLDEN)
        tied["phase_tree"]["nodes"][4]["wall_exclusive_ns"] = 600_000_000
        self.assertEqual(harness.largest_undivided_phase(DESCRIPTOR, tied)["phase"], 2)
        tied["phase_tree"]["nodes"][4]["wall_exclusive_ns"] = 1_600_000_000
        self.assertEqual(harness.largest_undivided_phase(DESCRIPTOR, tied),
                         {"phase": 4, "label": "worker", "wall_exclusive_ns": 1_600_000_000,
                          "share_ppm": 1_600_000})
        tied["phase_tree"]["nodes"][4]["label"] = "not a label"
        self.assertEqual(harness.largest_undivided_phase(DESCRIPTOR, tied)["label"], "invalid_label")
        bare = copy.deepcopy(GOLDEN)
        del bare["phase_tree"]["nodes"][1:]
        self.assertIsNone(harness.largest_undivided_phase(DESCRIPTOR, bare))
        self.assertEqual(harness._parts_per_million(1, 3), 333_334)
        self.assertEqual(harness._parts_per_million(0, 0), 1_000_000)

    def test_shared_mutation_fixture_yields_the_same_codes_as_the_rust_report(self):
        self.assertEqual(MUTATIONS["schema"], "iroha.measurement.record_mutations.v1")
        self.assertEqual(MUTATIONS["base"], "measurement_record_v1.json")
        self.assertGreaterEqual(len(MUTATIONS["cases"]), 40)
        decoded = rejected = 0
        for case in MUTATIONS["cases"]:
            with self.subTest(case=case["name"]):
                view = mutated(case)
                if case.get("decode_error"):
                    self.assertNotIn("findings", case)
                    with self.assertRaises(harness.RecordDecodeError):
                        harness.decode_record(DESCRIPTOR, view)
                    rejected += 1
                    continue
                record = harness.decode_record(DESCRIPTOR, view)
                self.assertEqual(harness.record_findings(DESCRIPTOR, record), case["findings"])
                decoded += 1
        self.assertGreaterEqual(rejected, 10)
        self.assertGreaterEqual(decoded, 40)

    def test_one_percent_rule_is_exact_integer_arithmetic(self):
        exact = {"root_wall_ns": 1_000_000_000, "unattributed_wall_ns": 10_000_000}
        self.assertTrue(harness.within_limit(DESCRIPTOR, exact))
        self.assertEqual(harness.unattributed_ppm(exact), 10_000)
        over = dict(exact, unattributed_wall_ns=10_000_001)
        self.assertFalse(harness.within_limit(DESCRIPTOR, over))
        self.assertEqual(harness.unattributed_ppm(over), 10_001)
        self.assertFalse(harness.within_limit(DESCRIPTOR, {"root_wall_ns": 0, "unattributed_wall_ns": 0}))
        self.assertEqual(harness.unattributed_ppm({"root_wall_ns": 0, "unattributed_wall_ns": 0}), 1_000_000)
        huge = {"root_wall_ns": harness.MAX_U64, "unattributed_wall_ns": harness.MAX_U64 // 100}
        self.assertTrue(harness.within_limit(DESCRIPTOR, huge))
        self.assertFalse(harness.within_limit(DESCRIPTOR, dict(huge, unattributed_wall_ns=harness.MAX_U64 // 100 + 1)))
        empty = copy.deepcopy(GOLDEN)
        empty["phase_tree"]["nodes"] = []
        self.assertIsNone(harness.attribution(empty))

    def test_strict_json_rejects_duplicates_non_finite_and_malformed_text(self):
        self.assertEqual(harness.strict_json(b'{"a":[1,{"b":null}]}'), {"a": [1, {"b": None}]})
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":', b'\xff\xfe'):
            with self.assertRaises(harness.RecordDecodeError):
                harness.strict_json(raw)

    def test_typed_decoding_names_the_offending_path(self):
        cases = (
            (["phase_tree", "nodes", 0, "calls"], True, "record.phase_tree.nodes[0].calls"),
            (["phase_tree", "nodes", 1, "parent"], 1 << 32, "record.phase_tree.nodes[1].parent"),
            (["process", "peak_rss_bytes"], 1.0, "record.process.peak_rss_bytes"),
            (["outcome"], "maybe", "record.outcome"),
            (["declared"], None, "record.declared"),
            (["identity"], [], "record.identity"),
        )
        for path, value, expected in cases:
            view = copy.deepcopy(GOLDEN)
            *parents, last = path
            walk(view, parents)[last] = value
            with self.assertRaises(harness.RecordDecodeError) as raised:
                harness.decode_record(DESCRIPTOR, view)
            self.assertEqual(raised.exception.path, expected)
        with self.assertRaises(harness.RecordDecodeError):
            harness.decode_view(DESCRIPTOR, "context", {"schema": "x"}, "context")
        # Optional fields accept null.
        view = copy.deepcopy(GOLDEN)
        view["address_space"].update(soft_limit_bytes=None, hard_limit_bytes=None, enforced=False)
        harness.decode_record(DESCRIPTOR, view)

    def test_unclassified_numbers_are_found_and_structural_numbers_are_exempt(self):
        view = copy.deepcopy(GOLDEN)
        del view["phase_tree"]["classification"]
        found = harness.unclassified_numbers(DESCRIPTOR, view)
        self.assertEqual(len(found), 5 * 19)
        self.assertIn("record.phase_tree.nodes[0].wall_inclusive_ns", found)
        self.assertFalse(any(path.endswith(".parent") for path in found))
        view = copy.deepcopy(GOLDEN)
        view["budget"] = 7
        self.assertEqual(harness.unclassified_numbers(DESCRIPTOR, view), ["record.budget"])

    def test_validate_subcommand_reports_codes_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / "good.json"
            good.write_text(json.dumps(GOLDEN))
            bad = Path(directory) / "bad.json"
            over = copy.deepcopy(GOLDEN)
            over["phase_tree"]["nodes"][0].update(wall_inclusive_ns=1_020_000_000, wall_exclusive_ns=21_000_000)
            bad.write_text(json.dumps(over))
            broken = Path(directory) / "broken.json"
            broken.write_text('{"schema":1}')
            largest = {"phase": 2, "label": "transform", "wall_exclusive_ns": 600_000_000,
                       "share_ppm": 600_000}
            self.assertEqual(run_harness(["validate", str(good)])[:2],
                             (0, {"record": str(good), "findings": [],
                                  "largest_undivided_phase": largest}))
            status, line, _ = run_harness(["validate", str(good), str(bad)])
            self.assertEqual((status, line["findings"]),
                             (1, ["unattributed_exceeds_limit:21000000:1020000000"]))
            status, line, _ = run_harness(["validate", str(broken)])
            self.assertEqual((status, line["findings"]), (1, ["decode_error:record"]))
            status, line, _ = run_harness(["validate", str(Path(directory) / "absent.json")])
            self.assertEqual((status, line["findings"]), (1, ["unreadable"]))


class IdentityTests(unittest.TestCase):
    def test_source_state_binds_commit_diff_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = fixture_repository(directory)
            clean = harness.source_state(repository)
            self.assertEqual(clean["source_commit"], git(repository, "rev-parse", "HEAD").decode())
            self.assertEqual((clean["source_dirty"], clean["source_dirty_digest"]), (False, None))
            # Ignored output does not make the tree dirty.
            (repository / "generated").mkdir()
            (repository / "generated" / "log.txt").write_text("log\n")
            self.assertEqual(harness.source_state(repository), clean)
            (repository / "source.txt").write_text("changed\n")
            first = harness.source_state(repository)
            self.assertTrue(first["source_dirty"])
            self.assertRegex(first["source_dirty_digest"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(harness.source_state(repository), first)
            (repository / "source.txt").write_text("changed again\n")
            second = harness.source_state(repository)
            self.assertNotEqual(second["source_dirty_digest"], first["source_dirty_digest"])
            (repository / "new.txt").write_text("untracked\n")
            third = harness.source_state(repository)
            self.assertNotEqual(third["source_dirty_digest"], second["source_dirty_digest"])
            (repository / "new.txt").write_text("untracked changed\n")
            self.assertNotEqual(harness.source_state(repository)["source_dirty_digest"],
                                third["source_dirty_digest"])
            os.symlink("source.txt", repository / "link")
            self.assertTrue(harness.source_state(repository)["source_dirty"])
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(harness.HarnessRefusal), \
                mock.patch.object(harness, "_git", return_value=subprocess.CompletedProcess([], 128, b"", b"")):
            harness.source_state(Path(directory))

    def test_output_root_must_be_untracked_and_ignored_inside_a_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = fixture_repository(directory)
            outside = Path(directory) / "outside"
            self.assertEqual(harness.ensure_untracked_root(repository, outside),
                             Path(os.path.realpath(outside)))
            self.assertEqual(harness.ensure_untracked_root(repository, repository / "generated" / "runs"),
                             repository / "generated" / "runs")
            for refused in (repository, repository / "tracked", repository / "unignored"):
                with self.assertRaises(harness.HarnessRefusal):
                    harness.ensure_untracked_root(repository, refused)
        # The default root of this checkout is ignored; tracked paths are refused.
        self.assertEqual(harness.ensure_untracked_root(REPOSITORY, harness.DEFAULT_OUTPUT_ROOT),
                         harness.DEFAULT_OUTPUT_ROOT)
        with self.assertRaises(harness.HarnessRefusal):
            harness.ensure_untracked_root(REPOSITORY, REPOSITORY / "scripts")

    def test_executable_and_scope_must_be_real_and_bound(self):
        self.assertEqual(harness.resolve_executable(str(CAT)), CAT)
        self.assertEqual(harness.resolve_executable("cat"), CAT)
        with tempfile.TemporaryDirectory() as directory:
            for refused in (str(Path(directory) / "absent"), directory, "no-such-command-e1"):
                with self.assertRaises(harness.HarnessRefusal):
                    harness.resolve_executable(refused)
            plain = Path(directory) / "plain.txt"
            plain.write_text("not executable\n")
            with self.assertRaises(harness.HarnessRefusal):
                harness.resolve_executable(str(plain))
            self.assertEqual(harness.sha256_file(plain),
                             (hashlib.sha256(b"not executable\n").hexdigest(), 15))
            repository = fixture_repository(directory)
            context = harness.build_context(DESCRIPTOR, repository, "a" * 64, "release", "defaults",
                                            "reference/host", "cold")
            self.assertEqual(context["artifact"], "sha256:" + "a" * 64)
            self.assertEqual(context["schema"], "iroha.measurement.context.v1")
            self.assertEqual(set(context), set(DESCRIPTOR["fields"]["context"]))
            for profile, config, hardware, policy in (
                ("unbound", "defaults", "reference/host", "cold"),
                ("release", "two words", "reference/host", "cold"),
                ("release", "defaults", "invalid_label", "cold"),
                ("release", "defaults", "", "cold"),
                ("release", "defaults", "reference/host", "lukewarm"),
            ):
                with self.assertRaises(harness.HarnessRefusal):
                    harness.build_context(DESCRIPTOR, repository, "a" * 64, profile, config, hardware, policy)

    def test_run_directories_are_owner_only_fresh_and_never_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            first = harness.new_run_directory(Path(directory) / "root")
            second = harness.new_run_directory(Path(directory) / "root")
            self.assertNotEqual(first, second)
            for run in (first, second):
                self.assertEqual(os.stat(run).st_mode & 0o777, 0o700)
                self.assertEqual(sorted(os.listdir(run)), ["child", "observations"])
            with mock.patch.object(harness.secrets, "token_hex", return_value="00000000"), \
                    mock.patch.object(harness.os, "getpid", return_value=1):
                frozen = mock.Mock(wraps=harness.datetime.datetime)
                frozen.now.return_value = harness.datetime.datetime(2026, 1, 1, tzinfo=harness.datetime.timezone.utc)
                with mock.patch.object(harness.datetime, "datetime", frozen):
                    harness.new_run_directory(Path(directory) / "root")
                    with self.assertRaises(FileExistsError):
                        harness.new_run_directory(Path(directory) / "root")

    def test_host_facts_are_observed_bounded_and_carry_no_host_name(self):
        facts = harness.host_facts()
        self.assertEqual(set(facts), {"classification", "system", "release", "machine", "model", "cpu",
                                      "logical_cpus", "physical_memory_bytes"})
        self.assertEqual(facts["classification"], "measured")
        self.assertEqual(facts["system"], harness.platform.uname().system)
        self.assertEqual(facts["machine"], harness.platform.uname().machine)
        self.assertEqual(facts["logical_cpus"], os.cpu_count())
        self.assertGreater(facts["physical_memory_bytes"], 1 << 28)
        self.assertNotIn(harness.platform.node(), [value for value in facts.values() if value != ""])
        if sys.platform == "darwin":
            self.assertNotEqual((facts["model"], facts["cpu"]), ("unavailable", "unavailable"))
        self.assertEqual(harness._host_text("  Apple   M1\tUltra \n"), "Apple M1 Ultra")
        for rejected in (None, "", "x" * 161, "caf\u00e9", "nul\0"):
            self.assertEqual(harness._host_text(rejected), "unavailable")
        self.assertIsNone(harness._sysctl("no.such.sysctl.e1"))
        with mock.patch.object(harness.subprocess, "run", side_effect=OSError):
            self.assertIsNone(harness._sysctl("hw.model"))
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "cpuinfo"
            listing.write_text("processor\t: 0\nmodel name\t: Example CPU @ 3.0GHz\n")
            self.assertEqual(harness._first_line(str(listing), "model name"), "Example CPU @ 3.0GHz")
            self.assertEqual(harness._first_line(str(listing)), "processor\t: 0")
            self.assertIsNone(harness._first_line(str(listing), "absent"))
            self.assertIsNone(harness._first_line(str(Path(directory) / "absent")))

    def test_argument_digest_binds_order_and_boundaries_without_keeping_text(self):
        digest = harness.arguments_digest(["--exact", "name"])
        self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(digest, harness.arguments_digest(["--exact", "name"]))
        for other in (["name", "--exact"], ["--exactname"], ["--exact", "name", ""], ["--exact"], []):
            self.assertNotEqual(harness.arguments_digest(other), digest)
        self.assertNotEqual(harness.arguments_digest(["ab", "c"]), harness.arguments_digest(["a", "bc"]))

    def test_linux_limits_text_is_parsed_exactly(self):
        text = (b"Limit                     Soft Limit           Hard Limit           Units     \n"
                b"Max cpu time              unlimited            unlimited            seconds   \n"
                b"Max address space         8589934592           8589934592           bytes     \n"
                b"Max file locks            unlimited            unlimited            locks     \n")
        self.assertEqual(harness.parse_linux_address_space_limit(text), (8 << 30, 8 << 30))
        self.assertEqual(harness.parse_linux_address_space_limit(
            text.replace(b"8589934592           8589934592", b"unlimited            unlimited ")), (None, None))
        self.assertEqual(harness.parse_linux_address_space_limit(
            text.replace(b"8589934592           8589934592", b"4096                 unlimited ")), (4096, None))
        for malformed in (b"", b"Max address space\n", b"Max address space  many unlimited bytes\n",
                          b"Max address space  99999999999999999999 unlimited bytes\n"):
            self.assertIsNone(harness.parse_linux_address_space_limit(malformed))
        observed = harness.kernel_address_space_limit(os.getpid())
        if sys.platform.startswith("linux"):
            self.assertIsInstance(observed, tuple)
        else:
            self.assertIsNone(observed)
        self.assertIsNone(harness.kernel_address_space_limit(0) if sys.platform.startswith("linux") else None)
        self.assertEqual(harness.address_space_enforcement(None, None),
                         {"classification": "local_scheduling", "enforced": False, "soft_limit_bytes": None,
                          "hard_limit_bytes": None, "source": "not_requested", "kernel_observed": None})
        self.assertEqual(harness.address_space_enforcement(8 << 30, (8 << 30, 8 << 30)),
                         {"classification": "local_scheduling", "enforced": True, "soft_limit_bytes": 8 << 30,
                          "hard_limit_bytes": 8 << 30, "source": "harness.setrlimit.RLIMIT_AS",
                          "kernel_observed": {"soft_limit_bytes": 8 << 30, "hard_limit_bytes": 8 << 30}})

    def test_image_mismatch_reasons_are_the_observers_own_fixed_texts(self):
        from nexus import resource_process
        sources = inspect.getsource(harness.observer) + inspect.getsource(resource_process)
        for reason in harness.IMAGE_MISMATCH_REASONS:
            self.assertIn(reason, sources)
        differs = harness.observer.ProcessObservationError("running Mach-O image differs")
        self.assertTrue(harness._image_differs(differs))
        self.assertFalse(harness._image_differs(harness.observer.ProcessObservationError("other")))
        self.assertFalse(harness._image_differs(ValueError("running Mach-O image differs")))

    def test_kernel_accounting_conversions(self):
        self.assertEqual(harness._rusage_ns(1.5), 1_500_000_000)
        self.assertEqual(harness._rusage_ns(0.000001), 1000)
        self.assertEqual(harness._peak_rss_bytes(4096), 4096 if sys.platform == "darwin" else 4096 * 1024)
        self.assertEqual(harness._exit_fact(3 << 8), {"kind": "exited", "code": 3})
        self.assertEqual(harness._exit_fact(9), {"kind": "signaled", "signal": 9})
        self.assertTrue(harness._union_bound(110, 110, 1))
        self.assertFalse(harness._union_bound(110, 111, 1))
        self.assertTrue(harness._union_bound(0, 0, 0))
        self.assertTrue(harness._is_hex("ab" * 20, (40, 64)))
        self.assertFalse(harness._is_hex("AB" * 20, (40, 64)))
        self.assertFalse(harness._is_hex(None, (40,)))


class NativeRunTests(unittest.TestCase):
    """End to end with a real native child whose lifetime the test controls."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repository = fixture_repository(self.directory.name)
        self.root = Path(self.directory.name) / "runs"
        self.fed = None

    def record_for(self, context, pid, change=None):
        record = copy.deepcopy(GOLDEN)
        for key, value in context.items():
            if key != "schema":
                record["identity"][key] = value
        # `tee` writes the JSON view only, as an SDK emitter in another
        # language does; a native emitter also writes the Norito form.
        record["identity"]["emitter"] = "python.harness_test"
        record["process"].update(pid=pid, cpu_user_ns=0, cpu_system_ns=0,
                                 peak_rss_bytes=4096, peak_rss_bytes_at_begin=4096)
        if change is not None:
            change(record)
        return record

    def run_tee(self, change=None, hold_seconds=0.45, timeout="30", emit=True, extra=(),
                files=("phase-tree.json",)):
        """Run `tee {output_dir}/<file>...`, feeding it one record on stdin."""
        read_end, write_end = os.pipe()
        started = threading.Event()
        spawned = {}
        real_popen = subprocess.Popen
        self.fed = None

        def capture(argv, **keywords):
            environment = keywords.get("env") or {}
            variable = DESCRIPTOR["harness_output_dir_env"]
            if variable not in environment:
                return real_popen(argv, **keywords)
            try:
                child = real_popen(argv, **keywords)
                spawned.update(pid=child.pid, child=Path(environment[variable]))
                return child
            finally:
                # Also released when the command could not be started.
                started.set()

        def feed():
            try:
                if started.wait(20) and emit and spawned:
                    context = json.loads((spawned["child"] / "context.json").read_text())
                    record = self.record_for(context, spawned["pid"], change)
                    self.fed = json.dumps(record).encode()
                    os.write(write_end, self.fed)
                if hold_seconds is not None:
                    time.sleep(hold_seconds)
            finally:
                if hold_seconds is not None:
                    os.close(write_end)

        feeder = threading.Thread(target=feed)
        feeder.start()
        try:
            with mock.patch.object(harness.subprocess, "Popen", side_effect=capture), \
                    os.fdopen(read_end, "rb") as stdin:
                result = run_harness(
                    ["run", "--repository", str(self.repository), *SCOPE, "--output-root", str(self.root),
                     "--interval-ms", "50", "--timeout-seconds", timeout, *extra, "--",
                     str(TEE), *("{output_dir}/" + name for name in files)], stdin=stdin)
        finally:
            feeder.join()
            if hold_seconds is None:
                os.close(write_end)
        return result

    def report(self, line):
        run = Path(line["run_directory"])
        return run, json.loads((run / "report.json").read_text())

    def test_accepted_run_merges_the_record_with_kernel_process_observations(self):
        status, line, _ = self.run_tee()
        self.assertEqual((status, line["verdict"], line["reasons"]), (0, "accepted", []))
        run, report = self.report(line)
        self.assertEqual(run.parent, self.root.resolve())
        self.assertEqual(os.stat(run).st_mode & 0o777, 0o700)
        self.assertEqual(report["schema"], "iroha.measurement.harness_report.v1")
        self.assertEqual(set(report), harness.REPORT_KEYS)
        self.assertEqual(report["verdict"], "accepted")
        context = report["context"]
        self.assertEqual(context["source_commit"], git(self.repository, "rev-parse", "HEAD").decode())
        self.assertEqual((context["source_dirty"], context["source_dirty_digest"]), (False, None))
        self.assertEqual(context["artifact"], "sha256:" + harness.sha256_file(TEE)[0])
        self.assertEqual((context["hardware"], context["profile"], context["cache_policy"]),
                         ("reference/unit-test-host", "test+tee", "warm"))
        self.assertEqual(report["host"], harness.host_facts())
        # The argument vector is bound by digest and not stored.
        self.assertEqual(report["command"],
                         {"executable": str(TEE), "executable_sha256": harness.sha256_file(TEE)[0],
                          "arguments_sha256": harness.arguments_digest(["{output_dir}/phase-tree.json"]),
                          "arguments": None})
        process = report["process"]
        self.assertEqual(process["exit"], {"kind": "exited", "code": 0})
        self.assertFalse(process["timed_out"])
        self.assertGreater(process["wall_ns"], 400_000_000)
        self.assertGreater(process["peak_rss_bytes"], 4096)
        self.assertEqual(process["peak_rss_source"], "kernel_child_rusage")
        self.assertEqual(process["address_space"]["source"], "not_requested")
        self.assertFalse(process["address_space"]["enforced"])
        sampled = process["sampled"]
        self.assertEqual(sampled["state"], "validated")
        self.assertGreaterEqual(sampled["observations"], 2)
        self.assertGreater(sampled["sampled_peak_rss_bytes"], 0)
        self.assertTrue((run / sampled["window"]["path"]).is_file())
        self.assertTrue((run / "observations" / "baseline.json").is_file())
        # `tee` copies the record to its standard output: the stream is
        # counted and hashed exactly, and its text is not stored.
        self.assertEqual(report["output"],
                         {"classification": "measured", "retention": "digest_only",
                          "stdout": {"bytes": len(self.fed), "sha256": hashlib.sha256(self.fed).hexdigest(),
                                     "complete": True, "tail": None},
                          "stderr": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(),
                                     "complete": True, "tail": None}})
        (entry,) = report["records"]
        self.assertEqual(entry["findings"], [])
        self.assertTrue(entry["decoded"] and entry["within_one_percent"])
        self.assertEqual(entry["attribution"],
                         {"root_wall_ns": 1_000_000_000, "unattributed_wall_ns": 1_000_000, "unattributed_ppm": 1000})
        self.assertEqual(entry["largest_undivided_phase"],
                         {"phase": 2, "label": "transform", "wall_exclusive_ns": 600_000_000, "share_ppm": 600_000})
        self.assertEqual((entry["workload"], entry["flow"], entry["outcome"]),
                         ("sample_prove", "proof", "succeeded"))
        self.assertEqual(entry["json"]["path"], "child/phase-tree.json")
        self.assertEqual(entry["json"]["sha256"], harness.sha256_file(run / "child" / "phase-tree.json")[0])
        self.assertIsNone(entry["norito"])
        self.assertEqual(report["orphans"], [])
        # Every quantitative value of the merged report is classified.
        self.assertEqual(harness.unclassified_numbers(DESCRIPTOR, report, "report"), [])
        self.assertEqual(report["limits"]["classification"], "local_scheduling")
        self.assertEqual(report["requirements"],
                         {"classification": "engineering_target", "address_space_limit_bytes": None,
                          "thermal_state": False, "max_undivided_phase_ppm": None})
        manifest = json.loads((run / "manifest.json").read_text())
        self.assertEqual(manifest["verdict"], "accepted")
        self.assertEqual(line["manifest_sha256"], harness.sha256_file(run / "manifest.json")[0])
        listed = {row["path"]: row for row in manifest["files"]}
        self.assertEqual(set(listed) >= {"report.json", "child/context.json",
                                         "child/phase-tree.json", "observations/baseline.json"}, True)
        self.assertEqual({path for path in listed if path.endswith(".log")}, set())
        for path, row in listed.items():
            self.assertEqual(harness.sha256_file(run / path), (row["sha256"], row["bytes"]))

    def test_unattributed_share_above_one_percent_is_rejected_and_retained(self):
        def over(record):
            record["phase_tree"]["nodes"][0].update(wall_inclusive_ns=1_020_000_000, wall_exclusive_ns=21_000_000)
        status, line, _ = self.run_tee(change=over)
        self.assertEqual((status, line["verdict"], line["reasons"]), (1, "rejected", ["record_rejected:0"]))
        run, report = self.report(line)
        (entry,) = report["records"]
        self.assertEqual(entry["findings"], ["unattributed_exceeds_limit:21000000:1020000000"])
        self.assertFalse(entry["within_one_percent"])
        self.assertEqual(entry["attribution"]["unattributed_ppm"], 20589)
        self.assertTrue((run / "child" / "phase-tree.json").is_file())
        self.assertEqual(json.loads((run / "manifest.json").read_text())["verdict"], "rejected")

    def test_substituted_identity_wrong_process_and_inflated_accounting_are_rejected(self):
        cases = (
            (lambda record: record["identity"].update(hardware="another/host"),
             ["identity_differs_from_harness_context"]),
            (lambda record: record["process"].update(pid=1), ["pid_differs_from_observed_process"]),
            (lambda record: record["process"].update(peak_rss_bytes=1 << 40),
             ["record_exceeds_kernel_process_accounting"]),
            (lambda record: record["process"].update(cpu_user_ns=3_600_000_000_000),
             ["record_exceeds_kernel_process_accounting"]),
            (lambda record: record["identity"].update(hardware="unbound"),
             ["identity_incomplete:hardware", "identity_differs_from_harness_context"]),
            (lambda record: record.update(outcome="failed") or record["failures"]["entries"].append(
                {"code": "refused", "phase": 1, "stage": "commit"}), ["run_not_succeeded:failed"]),
            # A native emitter writes both forms: its JSON view alone means the
            # Norito record was lost.
            (lambda record: record["identity"].update(emitter="rust.iroha_measurement"),
             ["norito_sibling_missing"]),
            (lambda record: record["identity"].update(workload="free text 0xdeadbeef"),
             ["identity_incomplete:workload"]),
        )
        for change, expected in cases:
            status, line, _ = self.run_tee(change=change, hold_seconds=0.2)
            self.assertEqual(status, 1)
            _, report = self.report(line)
            self.assertEqual(report["records"][0]["findings"], expected)
            self.assertEqual(report["verdict"], "rejected")
        # Free text in an identity field is not copied into the report.
        self.assertEqual(report["records"][0]["workload"], "invalid_label")

    def test_malformed_record_is_a_retained_decode_failure(self):
        status, line, _ = self.run_tee(change=lambda record: record["phase_tree"]["nodes"][0].update(witness="secret"),
                                       hold_seconds=0.2)
        self.assertEqual((status, line["reasons"]), (1, ["record_decode_error:0"]))
        run, report = self.report(line)
        (entry,) = report["records"]
        self.assertEqual((entry["decoded"], entry["decode_error"]), (False, "record.phase_tree.nodes[0]"))
        self.assertTrue((run / "child" / "phase-tree.json").is_file())
        # The report names the place of the unknown key, never its text.
        self.assertNotIn(b"witness", (run / "report.json").read_bytes())

    def fail(self, *extra):
        return run_harness(["run", "--repository", str(self.repository), *SCOPE, "--output-root", str(self.root),
                            "--interval-ms", "50", "--timeout-seconds", "30", *extra, "--",
                            str(CAT), str(Path(self.directory.name) / "absent-input")])

    def test_failed_commands_are_recorded_and_earlier_failures_are_never_erased(self):
        status, line, _ = self.fail()
        self.assertEqual((status, line["verdict"]), (1, "rejected"))
        self.assertEqual(line["reasons"], ["command_exit:1", "no_record_emitted"])
        first, report = self.report(line)
        self.assertEqual(report["process"]["exit"], {"kind": "exited", "code": 1})
        # The command ended before a second sample; its kernel totals are exact.
        self.assertEqual(report["process"]["sampled"]["state"], "not_sampled")
        # The failure is retained as an exit status and an exact digest of
        # what the command printed, not as its text.
        stderr = report["output"]["stderr"]
        self.assertGreater(stderr["bytes"], len("absent-input"))
        self.assertRegex(stderr["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual((stderr["complete"], stderr["tail"]), (True, None))
        self.assertFalse((first / "stderr.log").exists())
        snapshot = {path: (first / path).read_bytes() for path in ("report.json", "manifest.json")}
        # Later runs, failing or succeeding, leave the earlier failure untouched.
        second = Path(self.fail()[1]["run_directory"])
        accepted = Path(self.run_tee()[1]["run_directory"])
        self.assertEqual(len({first, second, accepted}), 3)
        self.assertEqual({path: (first / path).read_bytes() for path in snapshot}, snapshot)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()),
                         sorted(path.name for path in (first, second, accepted)))

    def test_private_text_printed_or_passed_by_the_command_is_not_retained(self):
        secret = Path(self.directory.name) / "secret.txt"
        secret.write_text("witness=0xDEADBEEF secret_key=MARKER_STDOUT_4e9314\n")
        absent = Path(self.directory.name) / "hidden_program_MARKER_ARGV_77aa01"
        markers = (b"MARKER_STDOUT_4e9314", b"MARKER_ARGV_77aa01", b"0xDEADBEEF", b"secret.txt")

        def run(*extra):
            return run_harness(["run", "--repository", str(self.repository), *SCOPE, "--output-root",
                                str(self.root), "--interval-ms", "50", "--timeout-seconds", "30", *extra, "--",
                                str(CAT), str(secret), str(absent)])

        status, line, _ = run()
        self.assertEqual(status, 1)
        run_directory, report = self.report(line)
        files = [path for path in run_directory.rglob("*") if path.is_file()]
        self.assertGreaterEqual(len(files), 3)
        for path in files:
            content = path.read_bytes()
            for marker in markers:
                self.assertNotIn(marker, content, path)
        for marker in markers:
            self.assertNotIn(marker, json.dumps(line).encode())
        # What is kept is exact and public: lengths, digests and a digest of
        # the argument vector.
        printed = secret.read_bytes()
        self.assertEqual(report["output"]["stdout"],
                         {"bytes": len(printed), "sha256": hashlib.sha256(printed).hexdigest(),
                          "complete": True, "tail": None})
        self.assertGreater(report["output"]["stderr"]["bytes"], 0)
        self.assertEqual(report["output"]["retention"], "digest_only")
        self.assertEqual(report["command"]["arguments"], None)
        self.assertEqual(report["command"]["arguments_sha256"],
                         harness.arguments_digest([str(secret), str(absent)]))

        # Both retentions are explicit opt-ins, bounded, and marked in the report.
        status, line, _ = run("--retain-output-tail-bytes", "16", "--record-arguments")
        run_directory, report = self.report(line)
        self.assertEqual(report["command"]["arguments"], [str(secret), str(absent)])
        self.assertEqual(report["output"]["retention"], "tail")
        self.assertEqual(report["limits"]["output_tail_bytes"], 16)
        tail = report["output"]["stdout"]["tail"]
        self.assertEqual(tail, {"path": "stdout.tail.log", "sha256": hashlib.sha256(printed[-16:]).hexdigest(),
                                "bytes": 16})
        self.assertEqual((run_directory / "stdout.tail.log").read_bytes(), printed[-16:])
        self.assertLessEqual((run_directory / "stderr.tail.log").stat().st_size, 16)
        manifest = json.loads((run_directory / "manifest.json").read_text())
        self.assertIn("stdout.tail.log", {row["path"] for row in manifest["files"]})

    def test_stream_digest_counts_hashes_and_bounds_the_tail(self):
        read_end, write_end = os.pipe()
        stream = harness.StreamDigest(read_end, 4)
        stream.start()
        os.write(write_end, b"0123456789")
        os.write(write_end, b"ab")
        os.close(write_end)
        run = harness.new_run_directory(self.root)
        with harness.control.RecordDirectory(run) as records:
            result = stream.result(records, "stdout.tail.log")
            self.assertEqual(result, {"bytes": 12, "sha256": hashlib.sha256(b"0123456789ab").hexdigest(),
                                      "complete": True,
                                      "tail": {"path": "stdout.tail.log", "sha256": hashlib.sha256(b"89ab").hexdigest(),
                                               "bytes": 4}})
            os.close(read_end)
            # A stream that is still open after the command was reaped is
            # reported as incomplete, without a digest that would look final.
            read_end, write_end = os.pipe()
            held = harness.StreamDigest(read_end, 0)
            held.start()
            os.write(write_end, b"partial")
            with mock.patch.object(harness, "OUTPUT_DRAIN_SECONDS", 0.2):
                result = held.result(records, "stderr.tail.log")
            self.assertEqual((result["complete"], result["sha256"], result["tail"]), (False, None, None))
            os.close(write_end)
            held.join(5)
            os.close(read_end)
            # A closed descriptor ends the reader instead of raising.
            closed = harness.StreamDigest(read_end, 0)
            closed.start()
            closed.join(5)
            self.assertEqual(closed.length, 0)
        output = {"stdout": {"complete": True}, "stderr": {"complete": False}}
        process = {"timed_out": False, "exit": {"kind": "exited", "code": 0}, "sampled": {"state": "validated"}}
        self.assertEqual(harness.process_reasons(process, output), ["output_stream_not_closed:stderr"])

    def test_a_command_that_emits_nothing_is_rejected(self):
        status, line, _ = self.run_tee(emit=False, hold_seconds=0.2)
        # tee still creates its empty output file, which is not a record.
        self.assertEqual((status, line["reasons"]), (1, ["record_decode_error:0"]))

    def test_short_command_keeps_exact_kernel_totals_and_observer_failures(self):
        status, line, _ = self.run_tee(hold_seconds=0.0)
        _, report = self.report(line)
        sampled = report["process"]["sampled"]
        # The live process may still exist at the exact failing observation.
        # A later exit no longer erases that failure. Deterministic mocked reap
        # outcomes below prove both sides without introducing a timing grace.
        if sampled["state"] == "failed":
            self.assertEqual((status, line["verdict"]), (1, "rejected"))
            self.assertEqual(len(line["reasons"]), 1)
            self.assertTrue(line["reasons"][0].startswith("process_observation_failed:"))
        else:
            self.assertEqual((status, line["verdict"], line["reasons"]), (0, "accepted", []))
            self.assertEqual(sampled["state"], "not_sampled")
            self.assertIn(sampled["reason"], ("exited_before_first_sample", "exited_before_second_sample"))
            self.assertLess(sampled["observations"], 2)
        # The kernel's totals for the child are exact without any sample.
        self.assertGreater(report["process"]["peak_rss_bytes"], 4096)
        self.assertEqual(report["process"]["peak_rss_source"], "kernel_child_rusage")
        self.assertEqual(report["process"]["exit"], {"kind": "exited", "code": 0})

    def test_a_running_image_other_than_the_pinned_executable_is_an_identity_failure(self):
        differs = harness.observer.ProcessObservationError("running Mach-O image differs")
        with mock.patch.object(harness.observer.ProcessScope, "observe", side_effect=differs):
            status, line, _ = self.run_tee(hold_seconds=0.3)
        self.assertEqual(status, 1)
        self.assertEqual(line["reasons"], ["process_observation_failed:executable_image_differs"])
        _, report = self.report(line)
        self.assertEqual(report["process"]["sampled"],
                         {"state": "failed", "reason": "executable_image_differs"})
        # Another observer failure while the process stays alive is reported
        # under its own fixed reason, not as an early exit.
        other = harness.observer.ProcessObservationError("native process accounting unavailable")
        real = harness.observer.ProcessScope.observe
        calls = []

        def baseline_then_fail(scope):
            calls.append(scope)
            if len(calls) == 1:
                return real(scope)
            raise other

        with mock.patch.object(harness.observer.ProcessScope, "observe", baseline_then_fail):
            status, line, _ = self.run_tee(hold_seconds=0.4)
        self.assertEqual(line["reasons"], ["process_observation_failed:process_observation_failed"])
        # The pinned executable must still be the same file after the run.
        real_observe, real_validate = harness.observe_child, harness.observer.ExecutableImage.validate
        observed = []

        def observe(*arguments, **keywords):
            result = real_observe(*arguments, **keywords)
            observed.append(result["pid"])
            return result

        def validate(image):
            if observed:
                raise harness.observer.ProcessObservationError("pinned executable changed")
            return real_validate(image)

        with mock.patch.object(harness, "observe_child", observe), \
                mock.patch.object(harness.observer.ExecutableImage, "validate", validate):
            status, line, _ = self.run_tee(hold_seconds=0.2)
        self.assertEqual((status, line["reasons"]), (1, ["executable_changed_during_run"]))

    def test_timeout_kills_only_the_child_and_retains_the_run(self):
        status, line, _ = self.run_tee(hold_seconds=None, timeout="1")
        self.assertEqual(status, 1)
        self.assertEqual(line["reasons"][0], "command_timeout")
        _, report = self.report(line)
        self.assertTrue(report["process"]["timed_out"])
        self.assertEqual(report["process"]["exit"], {"kind": "signaled", "signal": 9})
        self.assertEqual(report["verdict"], "rejected")

    LIMIT = 8 << 30

    @staticmethod
    def observed_limit(soft, hard, enforced):
        return lambda record: record["address_space"].update(
            soft_limit_bytes=soft, hard_limit_bytes=hard, enforced=enforced)

    def test_requested_address_space_limit_is_enforced_or_the_run_is_rejected(self):
        matching = self.observed_limit(self.LIMIT, self.LIMIT, True)
        status, line, _ = self.run_tee(change=matching, hold_seconds=0.2,
                                       extra=("--address-space-limit-bytes", str(self.LIMIT)))
        _, report = self.report(line)
        self.assertEqual(report["limits"]["requested_address_space_bytes"], self.LIMIT)
        if sys.platform == "darwin":
            # Darwin refuses RLIMIT_AS: the command is not started and the
            # refusal is a retained, rejected run rather than a silent pass.
            self.assertEqual((status, line["reasons"]), (1, ["address_space_limit_not_applied"]))
            self.assertIsNone(report["process"])
            return
        # Where the kernel applies the limit, the kernel's own record of the
        # child, the harness's statement and the record must all agree.
        self.assertEqual((status, line["verdict"]), (0, "accepted"))
        self.assertEqual(report["process"]["address_space"]["kernel_observed"],
                         {"soft_limit_bytes": self.LIMIT, "hard_limit_bytes": self.LIMIT})
        self.assertTrue(report["process"]["address_space"]["enforced"])
        # The golden record claims 32 GiB: under an 8 GiB request it is refused.
        status, line, _ = self.run_tee(hold_seconds=0.2, extra=("--address-space-limit-bytes", str(self.LIMIT)))
        self.assertEqual((status, line["reasons"]), (1, ["record_rejected:0"]))

    def test_a_record_must_observe_exactly_the_limit_the_harness_applied(self):
        # The platform's refusal is replaced by a success, as on Linux; the
        # cross-check itself needs no particular kernel.
        applied = mock.patch.object(harness, "_limit_address_space", lambda limit: (lambda: None))
        request = ("--address-space-limit-bytes", str(self.LIMIT))
        cases = (
            (None, ["address_space_differs_from_requested_limit"]),  # golden: 32 GiB enforced
            (self.observed_limit(None, None, False), ["address_space_differs_from_requested_limit"]),
            (self.observed_limit(self.LIMIT, 32 << 30, True), ["address_space_differs_from_requested_limit"]),
            (self.observed_limit(self.LIMIT - 1, self.LIMIT, True), ["address_space_differs_from_requested_limit"]),
            (self.observed_limit(self.LIMIT, self.LIMIT, True), []),
        )
        for change, expected in cases:
            with applied:
                status, line, _ = self.run_tee(change=change, hold_seconds=0.2, extra=request)
            _, report = self.report(line)
            self.assertEqual(report["records"][0]["findings"], expected)
            self.assertEqual((status, line["verdict"]), (1, "rejected") if expected else (0, "accepted"))
            # The effective limit is in the process section, not only the request.
            self.assertEqual(report["process"]["address_space"],
                             {"classification": "local_scheduling", "enforced": True,
                              "soft_limit_bytes": self.LIMIT, "hard_limit_bytes": self.LIMIT,
                              "source": "harness.setrlimit.RLIMIT_AS", "kernel_observed": None})
            self.assertEqual(report["requirements"]["address_space_limit_bytes"], self.LIMIT)
            self.assertEqual(harness.unclassified_numbers(DESCRIPTOR, report, "report"), [])
        # Without a request an inherited limit is an observation, not a finding.
        status, line, _ = self.run_tee(hold_seconds=0.2)
        self.assertEqual((status, line["verdict"]), (0, "accepted"))
        # The kernel's own record of the child outranks the harness's belief.
        with applied, mock.patch.object(harness, "kernel_address_space_limit", return_value=(1 << 30, 1 << 30)):
            status, line, _ = self.run_tee(change=self.observed_limit(self.LIMIT, self.LIMIT, True),
                                           hold_seconds=0.2, extra=request)
        self.assertEqual((status, line["reasons"]), (1, ["address_space_limit_differs_from_kernel"]))
        _, report = self.report(line)
        self.assertEqual(report["process"]["address_space"]["kernel_observed"],
                         {"soft_limit_bytes": 1 << 30, "hard_limit_bytes": 1 << 30})

    def test_device_thermal_state_and_granularity_requirements_are_enforced_when_stated(self):
        def unavailable(record):
            record["process"].update(thermal_finish="unavailable", thermal_source="unavailable")
        # Unavailable thermal state is an honest observation by default ...
        status, line, _ = self.run_tee(change=unavailable, hold_seconds=0.2)
        self.assertEqual((status, line["verdict"]), (0, "accepted"))
        # ... and a rejection where the run states that thermal state applies.
        status, line, _ = self.run_tee(change=unavailable, hold_seconds=0.2, extra=("--require-thermal-state",))
        _, report = self.report(line)
        self.assertEqual((status, report["records"][0]["findings"]), (1, ["thermal_state_unavailable"]))
        self.assertTrue(report["requirements"]["thermal_state"])
        status, line, _ = self.run_tee(hold_seconds=0.2, extra=("--require-thermal-state",))
        self.assertEqual((status, line["verdict"]), (0, "accepted"))
        # A consumer states the attribution granularity it needs: the golden
        # tree holds 600,000 ppm of its root in one undivided phase.
        status, line, _ = self.run_tee(hold_seconds=0.2, extra=("--max-undivided-phase-ppm", "599999"))
        _, report = self.report(line)
        self.assertEqual((status, report["records"][0]["findings"]),
                         (1, ["undivided_phase_exceeds_bound:2:600000"]))
        self.assertEqual(report["requirements"]["max_undivided_phase_ppm"], 599_999)
        status, line, _ = self.run_tee(hold_seconds=0.2, extra=("--max-undivided-phase-ppm", "600000"))
        self.assertEqual((status, line["verdict"]), (0, "accepted"))

    def test_partial_and_excess_record_files_are_reported(self):
        # A Norito file without its JSON view is a record that was only half written.
        status, line, _ = self.run_tee(hold_seconds=0.2, files=("phase-tree.json", "lost.norito"))
        self.assertEqual((status, line["reasons"]), (1, ["record_without_json_view:0"]))
        run, report = self.report(line)
        self.assertEqual(report["orphans"],
                         [{"classification": "measured", "path": "child/lost.norito",
                           "sha256": harness.sha256_file(run / "child" / "lost.norito")[0],
                           "bytes": len(self.fed)}])
        # A native emitter's view with its Norito sibling is bound to it.
        native = lambda record: record["identity"].update(emitter="rust.iroha_measurement")
        status, line, _ = self.run_tee(change=native, hold_seconds=0.2,
                                       files=("phase-tree.json", "phase-tree.norito"))
        self.assertEqual((status, line["verdict"]), (0, "accepted"))
        run, report = self.report(line)
        self.assertEqual(report["records"][0]["norito"],
                         {"path": "child/phase-tree.norito", "bytes": len(self.fed),
                          "sha256": harness.sha256_file(run / "child" / "phase-tree.norito")[0]})
        self.assertEqual(report["orphans"], [])
        # Bounds on the number and size of records are enforced and reported.
        with mock.patch.object(harness, "MAX_RECORDS", 1):
            status, line, _ = self.run_tee(hold_seconds=0.2, files=("a.json", "b.json"))
        self.assertEqual((status, line["reasons"]), (1, ["too_many_records"]))
        self.assertEqual(len(self.report(line)[1]["records"]), 1)
        with mock.patch.object(harness, "MAX_RECORD_BYTES", 64):
            status, line, _ = self.run_tee(hold_seconds=0.2)
        self.assertEqual(status, 1)
        self.assertTrue(any(reason.startswith("unsafe_or_oversize_evidence:") for reason in line["reasons"]))
        self.assertEqual(self.report(line)[1]["records"], [])

    def test_a_report_that_cannot_be_written_leaves_a_failure_marker(self):
        real = harness.control.RecordDirectory.publish

        def refuse_report(records, name, raw):
            if name == "report.json":
                raise OSError("disk full")
            return real(records, name, raw)

        with mock.patch.object(harness.control.RecordDirectory, "publish", refuse_report):
            status, line, _ = self.run_tee(hold_seconds=0.2)
        self.assertEqual((status, line["verdict"], line["manifest_sha256"]), (1, "rejected", None))
        run = Path(line["run_directory"])
        self.assertEqual(json.loads((run / "harness_failure.json").read_text()),
                         {"schema": "iroha.measurement.harness_failure.v1", "reason": "OSError"})
        self.assertFalse((run / "report.json").exists() or (run / "manifest.json").exists())
        # The record the command wrote is still retained.
        self.assertTrue((run / "child" / "phase-tree.json").is_file())
        scope = harness.build_context(DESCRIPTOR, self.repository, harness.sha256_file(TEE)[0],
                                      "test+tee", "defaults", "reference/unit-test-host", "warm")
        self.assertEqual(harness.salvage_reasons(run, scope), ["manifest_digest_required"])
        # A failure inside the run itself is a retained, rejected report.
        with mock.patch.object(harness, "collect_records", side_effect=RuntimeError("judge failed")):
            status, line, _ = self.run_tee(hold_seconds=0.2)
        self.assertEqual((status, line["reasons"]), (1, ["harness_failure:RuntimeError"]))
        self.assertEqual(self.report(line)[1]["verdict"], "rejected")

    def test_refusals_precede_any_run_directory(self):
        base = ["run", "--repository", str(self.repository), *SCOPE, "--output-root", str(self.root)]
        for arguments in (
            [*base, "--"],
            [*base, "--interval-ms", "5", "--", str(CAT)],
            [*base, "--timeout-seconds", "0", "--", str(CAT)],
            [*base, "--address-space-limit-bytes", "0", "--", str(CAT)],
            [*base, "--retain-output-tail-bytes", str(harness.MAX_OUTPUT_TAIL_BYTES + 1), "--", str(CAT)],
            [*base, "--retain-output-tail-bytes", "-1", "--", str(CAT)],
            [*base, "--max-undivided-phase-ppm", "0", "--", str(CAT)],
            [*base, "--record-arguments", "--", str(CAT), "x" * (harness.MAX_RECORDED_ARGUMENT_BYTES + 1)],
            [*base, "--record-arguments", "--", str(CAT), "\udcff"],
            [*base, "--", "no-such-command-e1"],
            ["run", "--repository", str(self.repository), *SCOPE, "--output-root",
             str(self.repository / "tracked"), "--", str(CAT)],
            ["run", "--repository", str(self.repository), "--hardware", "unbound", "--profile", "p",
             "--config", "c", "--cache-policy", "cold", "--output-root", str(self.root), "--", str(CAT)],
        ):
            status, line, _ = run_harness(arguments)
            self.assertEqual(status, 2, arguments)
            self.assertIn("refused", line)
        self.assertFalse(self.root.exists())
        self.assertEqual(harness.main(["run", *SCOPE, "--output-root", str(REPOSITORY / "scripts"), "--",
                                       str(CAT)]), 2)

    def salvage_scope(self):
        return ["salvage", "--repository", str(self.repository), *SCOPE, "--executable", str(TEE)]

    def test_salvage_accepts_only_unchanged_accepted_evidence_in_the_same_scope(self):
        status, line, _ = self.run_tee()
        self.assertEqual(status, 0)
        run = Path(line["run_directory"])
        scope = [*self.salvage_scope(), "--manifest-sha256", line["manifest_sha256"]]
        before = {path: os.stat(path).st_mtime_ns for path in run.rglob("*")}
        result = run_harness([*scope, str(run)])
        self.assertEqual(result[0], 0)
        self.assertEqual(result[1]["reasons"], [])
        self.assertEqual(result[1]["manifest_binding"], "external_sha256")
        self.assertEqual(result[1]["original_requirements"], result[1]["consumer_requirements"])
        consumer = run_harness([*scope, "--require-thermal-state", str(run)])[1]
        self.assertFalse(consumer["salvageable"])
        self.assertIn("consumer_requirement_not_established:thermal_state", consumer["reasons"])
        self.assertFalse(consumer["original_requirements"]["thermal_state"])
        self.assertTrue(consumer["consumer_requirements"]["thermal_state"])
        self.assertEqual({path: os.stat(path).st_mtime_ns for path in run.rglob("*")}, before)
        other = [*scope[:3], "--hardware", "another/host", *scope[5:]]
        self.assertEqual(run_harness([*other, str(run)])[1]["reasons"],
                         ["record_scope_differs:0:hardware", "scope_differs:hardware"])
        other_executable = [str(CAT) if value == str(TEE) else value for value in scope]
        self.assertEqual(run_harness([*other_executable, str(run)])[1]["reasons"],
                         ["record_scope_differs:0:artifact", "scope_differs:artifact"])
        (self.repository / "source.txt").write_text("changed after the run\n")
        self.assertEqual(run_harness([*scope, str(run)])[1]["reasons"],
                         ["record_scope_differs:0:source_dirty", "record_scope_differs:0:source_dirty_digest",
                          "scope_differs:source_dirty", "scope_differs:source_dirty_digest"])
        (self.repository / "source.txt").write_text("tracked\n")
        self.assertEqual(run_harness([*scope, str(run)])[0], 0)
        copied = Path(self.directory.name) / "copied"
        shutil.copytree(run, copied)
        with open(copied / "child" / "context.json", "ab") as stream:
            stream.write(b"edited")
        (copied / "extra.txt").write_text("added")
        os.unlink(copied / "observations" / "baseline.json")
        findings = run_harness([*scope, str(copied)])[1]["reasons"]
        for prefix in ("evidence_changed:", "evidence_missing:", "unexpected_evidence_entry:"):
            self.assertTrue(any(reason.startswith(prefix) for reason in findings))
        self.assertNotIn("extra.txt", str(findings))
        rejected_line = self.run_tee(change=lambda record: record.update(schema="other"),
                                     hold_seconds=0.2)[1]
        rejected = Path(rejected_line["run_directory"])
        self.assertEqual(run_harness([*self.salvage_scope(), "--manifest-sha256",
                                      rejected_line["manifest_sha256"], str(rejected)])[1]["reasons"],
                         ["run_was_rejected"])
        self.assertEqual(harness.salvage_reasons(run, {}), ["manifest_digest_required"])
        self.assertEqual(harness.salvage_reasons(run, {}, "bad"), ["manifest_digest_invalid"])
        self.assertEqual(run_harness([*self.salvage_scope(), "--manifest-sha256", "0" * 64,
                                      str(run)])[1]["reasons"], ["manifest_digest_differs"])
        self.assertEqual(run_harness([*self.salvage_scope(), "--manifest-sha256", "not-a-digest",
                                      str(run)])[0], 2)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            harness.parser().parse_args([*self.salvage_scope(), str(run)])

    def rewritten(self, run, name, change):
        """A copy of `run` with one JSON file edited and nothing else touched."""
        copied = Path(tempfile.mkdtemp(dir=self.directory.name)) / "run"
        shutil.copytree(run, copied)
        value = json.loads((copied / name).read_text())
        change(value)
        os.chmod(copied / name, 0o600)
        with open(copied / name, "wb") as stream:
            stream.write(harness.control.canonical(value))
        return copied

    def rebound(self, run):
        """Make the manifest of a copy bind the files as they are now."""
        def bind(manifest):
            for row in manifest["files"]:
                row["sha256"], row["bytes"] = harness.sha256_file(run / row["path"])
        return self.rewritten(run, "manifest.json", bind)

    def test_salvage_derives_the_verdict_and_scope_from_the_evidence_not_the_manifest(self):
        scope = self.salvage_scope()
        def reasons(*arguments):
            # Synthetic malformed input at its initial fixture boundary. This is
            # not a replacement receipt for an actual previously accepted run.
            if "--manifest-sha256" not in arguments:
                arguments = (*arguments[:-1], "--manifest-sha256",
                             harness.sha256_file(Path(arguments[-1]) / "manifest.json")[0], arguments[-1])
            return run_harness(list(arguments))[1]["reasons"]
        rejected = Path(self.run_tee(change=lambda record: record.update(schema="other"),
                                     hold_seconds=0.2)[1]["run_directory"])
        self.assertEqual(reasons(*scope, str(rejected)), ["run_was_rejected"])
        # Flipping only the manifest's verdict changes no evidence byte, and
        # no longer turns a rejected run into salvageable evidence.
        flipped = self.rewritten(rejected, "manifest.json", lambda manifest: manifest.update(verdict="accepted"))
        self.assertEqual(json.loads((flipped / "report.json").read_text())["verdict"], "rejected")
        self.assertEqual(reasons(*scope, str(flipped)),
                         ["manifest_verdict_differs_from_report", "run_was_rejected"])
        # A report edited to agree, with the manifest bound to it again, is
        # contradicted by the record it still carries.
        agreed = self.rewritten(rejected, "report.json",
                                lambda report: report.update(verdict="accepted", reasons=[]))
        agreed = self.rebound(self.rewritten(agreed, "manifest.json",
                                             lambda manifest: manifest.update(verdict="accepted")))
        self.assertEqual(reasons(*scope, str(agreed)),
                         ["reasons_not_reproducible", "report_verdict_differs_from_evidence",
                          "run_was_rejected"])
        accepted_line = self.run_tee()[1]
        accepted = Path(accepted_line["run_directory"])
        self.assertEqual(reasons(*scope, str(accepted)), [])
        # Rewriting the manifest's context cannot move evidence to another
        # hardware scope: the report and the records still name the original.
        other = [*scope[:3], "--hardware", "some/other-host", *scope[5:]]
        moved = self.rewritten(accepted, "manifest.json",
                               lambda manifest: manifest["context"].update(hardware="some/other-host"))
        self.assertEqual(reasons(*other, str(moved)),
                         ["manifest_context_differs_from_report", "record_scope_differs:0:hardware",
                          "scope_differs:hardware"])
        self.assertEqual(reasons(*scope, str(moved)), ["manifest_context_differs_from_report"])
        # Report and manifest rewritten together still leave the record's own
        # identity, which the harness context no longer matches.
        both = self.rewritten(accepted, "report.json",
                              lambda report: report["context"].update(hardware="some/other-host"))
        both = self.rebound(self.rewritten(
            both, "manifest.json", lambda manifest: manifest["context"].update(hardware="some/other-host")))
        self.assertEqual(reasons(*other, str(both)),
                         ["reasons_not_reproducible", "records_not_reproducible",
                          "report_verdict_differs_from_evidence", "run_was_rejected",
                          "record_scope_differs:0:hardware"])
        # A finding removed from the report is derived again from the record.
        hidden = self.rewritten(rejected, "report.json", lambda report: report["records"][0].update(findings=[]))
        self.assertEqual(reasons(*scope, str(self.rebound(hidden))),
                         ["records_not_reproducible", "run_was_rejected"])
        # The original external pin detects any coordinated manifest change;
        # a newly issued synthetic fixture pin below tests only rederivation.
        consistent = self.rebound(accepted)
        self.assertEqual(reasons(*scope, str(consistent)), [])
        self.assertEqual(reasons(*scope, "--manifest-sha256", accepted_line["manifest_sha256"],
                                 str(self.rewritten(accepted, "manifest.json",
                                                    lambda manifest: manifest.update(classification="other")))),
                         ["manifest_digest_differs"])
        # Malformed manifests and reports are named, never interpreted.
        for name, change, expected in (
            ("manifest.json", lambda manifest: manifest.update(files="none"), ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest.update(context="none"), ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest["files"].append({"path": 1}), ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest["files"].append(
                {"path": "../outside.json", "sha256": "0" * 64, "bytes": 1}), ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest["files"].append(
                {"path": "/etc/hosts", "sha256": "0" * 64, "bytes": 1}), ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest["files"].append(dict(manifest["files"][0])),
             ["manifest_malformed"]),
            ("manifest.json", lambda manifest: manifest.update(
                files=[row for row in manifest["files"] if row["path"] != "report.json"]),
             ["evidence_added:3", "report_not_bound"]),
            ("report.json", lambda report: report.pop("host"), ["report_malformed"]),
            ("report.json", lambda report: report.update(reasons=[1]), ["report_malformed"]),
            ("report.json", lambda report: report.update(requirements={}), ["report_requirements_invalid"]),
            ("report.json", lambda report: report.update(process={"pid": 1}),
             ["report_requirement_observations_differ", "report_malformed"]),
            ("report.json", lambda report: report.update(process=None), ["run_was_rejected"]),
        ):
            edited = self.rewritten(accepted, name, change)
            if name == "report.json":
                edited = self.rebound(edited)
            self.assertEqual(reasons(*scope, str(edited)), expected, change)
        unreadable = self.rewritten(accepted, "manifest.json", lambda manifest: None)
        with open(unreadable / "report.json", "wb") as stream:
            stream.write(b"{not json")
        self.assertEqual(reasons(*scope, str(self.rebound(unreadable))), ["report_unreadable"])


class ObservationExitRaceTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(harness, "_owned_child_monitor", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_immediate_reap_establishes_an_actual_exit_race(self):
        usage = SimpleNamespace(ru_utime=1.0, ru_stime=1.0, ru_maxrss=1024)
        child = SimpleNamespace(pid=424242, returncode=None)
        reader = mock.Mock()
        absent = harness.native_process.NativeProcessUnavailable(child.pid, "proc_pidinfo", 3, 300, 400)
        with mock.patch.object(harness.observer, "native_reader", return_value=reader), \
                mock.patch.object(harness.observer, "ProcessScope", side_effect=absent), \
                mock.patch.object(harness.os, "getpgid", return_value=1), \
                mock.patch.object(harness, "_try_reap", return_value=(0, usage)) as reaped:
            result = harness.observe_child(child, mock.Mock(), mock.Mock(), 100, 10000)
        self.assertEqual(result["sampled"], {"state": "not_sampled", "reason": "exited_before_first_sample",
                                           "observations": 0, "native_failure": absent.fact()})
        reaped.assert_called_once_with(child.pid)
        reader.close.assert_called_once()

    def test_later_exit_does_not_erase_initial_or_subsequent_observer_failure(self):
        usage = SimpleNamespace(ru_utime=1.0, ru_stime=1.0, ru_maxrss=1024)
        for after_baseline in (False, True):
            child = SimpleNamespace(pid=424242, returncode=None)
            reader = mock.Mock()
            scope = SimpleNamespace(initial={}, observe=mock.Mock(side_effect=ValueError("observer unavailable")))
            journal = SimpleNamespace(append=mock.Mock(), failed=False, failure_reason=None, count=1)
            with self.subTest(after_baseline=after_baseline), \
                    mock.patch.object(harness.observer, "native_reader", return_value=reader), \
                    mock.patch.object(harness.observer, "ProcessScope", return_value=scope,
                                      side_effect=None if after_baseline else ValueError("observer unavailable")), \
                    mock.patch.object(harness.observer, "ResourceObservationJournal", return_value=journal), \
                    mock.patch.object(harness.os, "getpgid", return_value=1), \
                    mock.patch.object(harness.time, "sleep"), \
                    mock.patch.object(harness, "_try_reap", side_effect=([None, None, (0, usage)]
                                                                 if after_baseline else [None, (0, usage)])):
                result = harness.observe_child(child, mock.Mock(), mock.Mock(), 100, 10000)
            self.assertEqual(result["sampled"]["state"], "failed")
            self.assertEqual(result["exit"], {"kind": "exited", "code": 0})
            self.assertFalse(result["timed_out"])
            reader.close.assert_called_once()


class PinnedEvidenceTests(unittest.TestCase):
    """Closed intake and consumer policies over deterministic public synthetic records."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.serial = 0
        self.requirements = {"classification": "engineering_target", "address_space_limit_bytes": None,
                             "thermal_state": False, "max_undivided_phase_ppm": None}

    def fixture(self, requirements=None, child_change=None, report_change=None):
        self.serial += 1
        run = self.root / str(self.serial)
        run.mkdir(mode=0o700)
        (run / "child").mkdir(mode=0o700)
        record = copy.deepcopy(GOLDEN)
        record["identity"]["emitter"] = "python.synthetic_test"
        context = {key: value for key, value in record["identity"].items()
                   if key not in {"emitter", "flow", "workload"}}
        context["schema"] = DESCRIPTOR["context_schema"]
        requirements = dict(self.requirements if requirements is None else requirements)
        limit = requirements["address_space_limit_bytes"]
        if limit is not None:
            record["address_space"].update(enforced=True, soft_limit_bytes=limit, hard_limit_bytes=limit)
        process = dict(record["process"], exit={"kind": "exited", "code": 0}, timed_out=False,
                       sampled={"state": "not_sampled", "reason": "exited_before_first_sample", "observations": 0},
                       address_space=harness.address_space_enforcement(limit, None), wall_ns=1_000_000_000)
        (run / "child/context.json").write_bytes(harness.control.canonical(context))
        (run / "child/record.json").write_bytes(harness.control.canonical(record))
        os.chmod(run / "child/record.json", 0o644)
        if child_change:
            child_change(run)
        entries, orphans, reasons = harness.collect_records(DESCRIPTOR, run, context, process, requirements)
        stream = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "complete": True, "tail": None}
        report = {"schema": harness.REPORT_SCHEMA, "context": context,
                  "command": {"arguments": None}, "host": {},
                  "limits": {"classification": "local_scheduling", "requested_address_space_bytes": limit,
                             "timeout_ms": 10000, "sampling_interval_ms": 100, "output_tail_bytes": 0},
                  "requirements": requirements, "process": process,
                  "output": {"classification": "measured", "retention": "digest_only",
                             "stdout": dict(stream), "stderr": dict(stream)},
                  "records": entries, "orphans": orphans, "reasons": reasons,
                  "verdict": "rejected" if reasons else "accepted"}
        if report_change:
            report_change(report)
        with harness.control.RecordDirectory(run) as directory:
            directory.publish("report.json", harness.control.canonical(report))
            binding = harness.write_manifest(run, directory, context, report["verdict"])
        return run, binding["sha256"], report

    def test_mandatory_pin_refuses_before_open_and_safe_reader_returns_bound_documents(self):
        run, pin, report = self.fixture()
        with mock.patch.object(harness, "_EvidenceDirectory", side_effect=AssertionError("must not open")):
            self.assertEqual(harness.salvage_reasons(run, {}), ["manifest_digest_required"])
            for invalid in (True, 42, "x" * 64, "1" * 63, "A" * 64):
                self.assertEqual(harness.salvage_reasons(run, {}, invalid), ["manifest_digest_invalid"])
        result = harness.read_pinned_run(run, pin)
        self.assertEqual(result["report"], report)
        self.assertEqual(result["manifest_sha256"], pin)
        self.assertEqual(set(result["documents"]), {"child/record.json"})
        self.assertEqual(result["documents"]["child/record.json"]["identity"],
                         json.loads((run / "child/record.json").read_bytes())["identity"])
        self.assertEqual(result["original_requirements"], result["consumer_requirements"])
        self.assertEqual(os.stat(run / "child/record.json").st_mode & 0o777, 0o644)

    def test_original_external_receipt_rejects_coordinated_report_manifest_rewrites(self):
        changes = (
            lambda report: report["requirements"].update(thermal_state=True),
            lambda report: report["process"]["exit"].update(code=1),
            lambda report: report["process"].update(timed_out=True),
            lambda report: report["process"].update(sampled={"state": "failed", "reason": "observer_failed"}),
        )
        for change in changes:
            run, original_pin, report = self.fixture()
            change(report)
            (run / "report.json").write_bytes(harness.control.canonical(report))
            manifest = json.loads((run / "manifest.json").read_bytes())
            for row in manifest["files"]:
                if row["path"] == "report.json":
                    row["sha256"], row["bytes"] = harness.sha256_file(run / "report.json")
            (run / "manifest.json").write_bytes(harness.control.canonical(manifest))
            self.assertEqual(harness.salvage_reasons(run, {}, original_pin), ["manifest_digest_differs"])

    def test_consumer_requirements_must_have_been_established_by_original_contract(self):
        run, pin, _ = self.fixture()
        for consumer, field in (
            (dict(self.requirements, thermal_state=True), "thermal_state"),
            (dict(self.requirements, max_undivided_phase_ppm=700_000), "max_undivided_phase_ppm"),
            (dict(self.requirements, address_space_limit_bytes=1 << 35), "address_space_limit_bytes"),
        ):
            self.assertIn("consumer_requirement_not_established:" + field,
                          harness.salvage_reasons(run, {}, pin, consumer))
        original = dict(self.requirements, thermal_state=True, max_undivided_phase_ppm=600_000,
                        address_space_limit_bytes=1 << 35)
        run, pin, _ = self.fixture(original)
        for consumer in (original, dict(original, thermal_state=False, max_undivided_phase_ppm=700_000),
                         self.requirements):
            result = harness.read_pinned_run(run, pin, consumer_requirements=consumer)
            self.assertEqual(result["original_requirements"], original)
            self.assertEqual(result["consumer_requirements"], consumer)
        for requested in (1 << 34, 1 << 36):
            self.assertIn("consumer_requirement_not_established:address_space_limit_bytes",
                          harness.salvage_reasons(run, {}, pin, dict(original, address_space_limit_bytes=requested)))
        self.assertIn("consumer_requirement_not_established:max_undivided_phase_ppm",
                      harness.salvage_reasons(run, {}, pin, dict(original, max_undivided_phase_ppm=599_999)))

    def test_weaker_consumer_never_rescues_rejected_original_evidence(self):
        original = dict(self.requirements, max_undivided_phase_ppm=599_999)
        run, pin, report = self.fixture(original)
        self.assertEqual(report["verdict"], "rejected")
        self.assertIn("run_was_rejected", harness.salvage_reasons(run, {}, pin, self.requirements))
        with self.assertRaises(harness.HarnessRefusal):
            harness.read_pinned_run(run, pin, consumer_requirements=self.requirements)

    def test_requirement_schema_checks_classification_types_and_ranges(self):
        invalid = [dict(self.requirements, **change) for change in (
            {"classification": "measured"}, {"thermal_state": 0},
            {"address_space_limit_bytes": True}, {"address_space_limit_bytes": 0},
            {"address_space_limit_bytes": 1 << 63}, {"max_undivided_phase_ppm": True},
            {"max_undivided_phase_ppm": 0}, {"max_undivided_phase_ppm": 1 << 32},
        )]
        invalid += [{}, dict(self.requirements, unknown=1)]
        run, pin, _ = self.fixture()
        for requirements in invalid:
            with self.assertRaises(harness.HarnessRefusal):
                harness.validate_requirements(requirements)
            self.assertEqual(harness.salvage_reasons(run, {}, pin, requirements),
                             ["consumer_requirements_invalid"])
            malformed, malformed_pin, _ = self.fixture(report_change=lambda report: report.update(requirements=requirements))
            self.assertIn("report_requirements_invalid", harness.salvage_reasons(malformed, {}, malformed_pin))

    def test_requested_applied_and_kernel_limit_observations_must_match(self):
        original = dict(self.requirements, address_space_limit_bytes=1 << 35)
        for change in (
            lambda report: report["limits"].update(requested_address_space_bytes=1 << 34),
            lambda report: report["process"]["address_space"].update(enforced=False),
            lambda report: report["process"]["address_space"].pop("kernel_observed"),
            lambda report: report["process"]["address_space"].update(soft_limit_bytes=1 << 34),
            lambda report: report["process"]["address_space"].update(kernel_observed={"soft_limit_bytes": 1, "hard_limit_bytes": 1}),
        ):
            run, pin, _ = self.fixture(original, report_change=change)
            self.assertIn("report_requirement_observations_differ", harness.salvage_reasons(run, {}, pin))

    def test_report_limits_are_closed_typed_and_missing_optional_value_still_refuses(self):
        for change in (
            lambda report: report["limits"].pop("requested_address_space_bytes"),
            lambda report: report["limits"].update(extra=1),
            lambda report: report["limits"].update(timeout_ms=True),
            lambda report: report["limits"].update(timeout_ms=999),
            lambda report: report["limits"].update(sampling_interval_ms=9),
            lambda report: report["limits"].update(output_tail_bytes=65537),
        ):
            run, pin, _ = self.fixture(report_change=change)
            self.assertIn("report_requirement_observations_differ", harness.salvage_reasons(run, {}, pin))

    def test_unknown_child_output_is_rejected_retained_and_not_promoted(self):
        secret_name = "private-looking-sentinel-928374.bin"
        for name in (secret_name, "unknown.log", "nested"):
            def create(run):
                path = run / "child" / name
                path.mkdir() if name == "nested" else path.write_bytes(b"PUBLIC TEST SENTINEL")
            run, pin, report = self.fixture(child_change=create)
            self.assertEqual(report["verdict"], "rejected")
            self.assertTrue((run / "child" / name).exists())
            self.assertTrue(any(reason.startswith("unexpected_evidence_entry:") for reason in report["reasons"]))
            self.assertNotIn(name, str(report["reasons"]))
            manifest = json.loads((run / "manifest.json").read_bytes())
            self.assertNotIn("child/" + name, {row["path"] for row in manifest["files"]})
            self.assertTrue(harness.salvage_reasons(run, {}, pin))

    def test_unsafe_files_refuse_without_following_or_blocking(self):
        creators = (
            lambda path, outside: path.symlink_to(outside),
            lambda path, outside: os.mkfifo(path),
            lambda path, outside: os.link(outside, path),
            lambda path, outside: (path.write_bytes(b"PUBLIC TEST SENTINEL"), os.chmod(path, 0o666)),
        )
        outside = self.root / "outside-public-sentinel"
        outside.write_bytes(b"PUBLIC TEST SENTINEL")
        for extension in ("json", "norito"):
            for creator in creators:
                name = "unsafe." + extension
                real_open = harness.os.open
                def refuse_unsafe_open(path, *args, **kwargs):
                    if path == name:
                        raise AssertionError("unsafe file must be rejected before opening")
                    return real_open(path, *args, **kwargs)
                with mock.patch.object(harness.os, "open", side_effect=refuse_unsafe_open):
                    run, pin, report = self.fixture(child_change=lambda run: creator(run / "child" / name, outside))
                    self.assertTrue(harness.salvage_reasons(run, {}, pin))
                self.assertEqual(report["verdict"], "rejected")
                self.assertTrue(any(reason.startswith("unsafe_or_oversize_evidence:") for reason in report["reasons"]))
                self.assertEqual(outside.read_bytes(), b"PUBLIC TEST SENTINEL")

    def test_replaced_named_file_is_rejected_during_held_descriptor_read(self):
        run, pin, _ = self.fixture()
        target = run / "child/record.json"
        inode = os.stat(target).st_ino
        real_read = harness.os.read
        replaced = []
        def replace_after_read(fd, length):
            raw = real_read(fd, length)
            if os.fstat(fd).st_ino == inode and not replaced:
                replacement = self.root / "replacement"
                replacement.write_bytes(target.read_bytes())
                os.replace(replacement, target)
                replaced.append(True)
            return raw
        with mock.patch.object(harness.os, "read", side_effect=replace_after_read):
            self.assertTrue(harness.salvage_reasons(run, {}, pin))
        self.assertEqual(replaced, [True])

    def test_consumer_receives_captured_bytes_even_if_path_changes_after_read(self):
        run, pin, _ = self.fixture()
        real_read = harness._EvidenceDirectory._read
        original = json.loads((run / "child/record.json").read_bytes())
        def change_after_complete_read(directory, name, maximum, retain):
            result = real_read(directory, name, maximum, retain)
            if name == "child/record.json":
                (run / name).write_bytes(b"{untrusted later replacement")
            return result
        with mock.patch.object(harness._EvidenceDirectory, "_read", change_after_complete_read):
            result = harness.read_pinned_run(run, pin)
        self.assertEqual(result["documents"]["child/record.json"], original)
        self.assertNotEqual((run / "child/record.json").read_bytes(), harness.control.canonical(original))
        self.assertTrue(harness.salvage_reasons(run, {}, pin))

    def test_parent_replacement_and_permissions_refuse_without_modifying_inputs(self):
        for change in (
            lambda run: os.chmod(run / "child", 0o755),
            lambda run: os.chmod(run, 0o755),
        ):
            run, pin, _ = self.fixture()
            change(run)
            before = {path: path.lstat().st_mode for path in run.rglob("*")}
            self.assertTrue(harness.salvage_reasons(run, {}, pin))
            self.assertEqual({path: path.lstat().st_mode for path in run.rglob("*")}, before)
        run, pin, _ = self.fixture()
        os.rename(run / "child", run / "moved")
        (run / "child").symlink_to(run / "moved", target_is_directory=True)
        self.assertTrue(harness.salvage_reasons(run, {}, pin))

    def test_output_stream_failure_is_reproduced_without_runtime_only_exception(self):
        def incomplete(report):
            report["output"]["stdout"]["complete"] = False
            report["reasons"] = ["output_stream_not_closed:stdout"]
            report["verdict"] = "rejected"
        run, pin, _ = self.fixture(report_change=incomplete)
        self.assertEqual(harness.salvage_reasons(run, {}, pin), ["run_was_rejected"])


class StaticSafetyTests(unittest.TestCase):
    def setUp(self):
        self.source = (REPOSITORY / "scripts" / "zk_resource_harness.py").read_text()
        self.tree = ast.parse(self.source)

    def test_harness_contains_no_removal_or_overwrite_call(self):
        removal = {"rmtree", "unlink", "remove", "rmdir", "removedirs", "truncate", "rename", "replace_file",
                   "write_text"}
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                function = node.func
                called.add(function.attr if isinstance(function, ast.Attribute)
                           else getattr(function, "id", ""))
                if getattr(function, "id", "") == "open":
                    modes = [argument.value for argument in node.args[1:2]
                             if isinstance(argument, ast.Constant)]
                    # Only reads and exclusive creation: nothing is overwritten.
                    self.assertTrue(modes and modes[0] in ("rb", "xb"), ast.dump(node))
        self.assertEqual(called & removal, set())
        # The single signal the harness can send goes to its own child, from
        # one function that is reached only after the command's deadline.
        self.assertEqual(self.source.count("os.kill("), 1)
        self.assertEqual(self.source.count("signal.SIGKILL"), 1)
        self.assertEqual(self.source.count("_kill_own_child("), 2)
        self.assertNotIn("os.environ[", self.source)
        self.assertNotIn("os.getenv", self.source)
        # The command's output goes to pipes that are hashed, never to a file.
        self.assertEqual(self.source.count("stdout=subprocess.PIPE, stderr=subprocess.PIPE"), 1)
        self.assertNotIn(".log\", \"xb\"", self.source)

    def test_every_function_is_documented_or_private(self):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
                nested = node.name in ("pairs", "constant", "apply", "scope")
                self.assertTrue(nested or ast.get_docstring(node), node.name)

    def test_help_lists_every_subcommand(self):
        with redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as raised:
            harness.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        for word in ("run", "validate", "salvage"):
            self.assertIn(word, out.getvalue())


if __name__ == "__main__":
    unittest.main()
