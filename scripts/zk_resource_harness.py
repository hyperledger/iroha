#!/usr/bin/env python3
"""Run one named command under the process observer and judge its phase-tree records.

Purpose
    ``run`` starts exactly one command, pins its executable by SHA-256, samples
    the process with the existing native observer
    (``private_settlement_process_observer``), collects the public phase-tree
    records the command emits through ``iroha_measurement``, merges them with
    the process-level CPU and RSS observations, and writes one report. The
    report is ``accepted`` only when the command succeeded, the process
    observation did not fail, every record is well formed, identity is
    complete, a requested address-space limit is the one the records observed,
    and at most 1% of each root's wall time is unattributed. ``validate``
    judges JSON views on their own. ``salvage`` says whether an earlier run
    directory is unchanged evidence for the scope given now; it derives the
    verdict and the scope again from the retained records, not from the
    manifest.

Prerequisites
    Python 3.9+, ``git``, and the sibling modules in ``scripts/``. No other
    dependency. The record schema is read from
    ``crates/iroha_measurement/fixtures/record_schema_v1.json``, which the Rust
    crate generates and checks, so the schema has one owner.

Environment
    The harness sets ``IROHA_MEASUREMENT_OUTPUT_DIR`` for the command it
    starts and reads no environment variable itself. That variable only tells a
    test or diagnostic adapter where to write public records.

What is retained
    The admitted evidence channel contains public facts. The command's standard output and standard error are
    hashed and counted, not stored: a prover that panics prints
    witness-dependent values. ``--retain-output-tail-bytes`` stores a bounded
    tail of each stream and is unsafe for a workload that handles private
    data. The argument vector is recorded as a digest unless
    ``--record-arguments`` is given; arguments are then stored verbatim and
    must be public. The record directory is the emitter's own public channel:
    the harness admits only the closed record inventory and does not rewrite it.
    Unknown child files remain private, rejected workload state; they are not
    promoted into the evidence manifest. An arbitrary command can write private
    data elsewhere: this harness provides no filesystem sandbox or witness-clearing
    guarantee. Reviewed typed emitters own the public-only record contract.
    The hardware name, profile, configuration and cache policy are asserted
    by the operator; the report carries observed host facts beside them.

Custody
    The manifest binds each admitted evidence file by digest and is not signed. This
    tool creates no signing or qualification authority. ``run`` prints the
    manifest's SHA-256; an operator who retains or signs that digest under the
    existing release-signing contract passes it to ``salvage`` with
    the required ``--manifest-sha256`` to bind the manifest itself. Salvage always
    reproduces the original requirements before checking any consumer requirements.
    Directories must remain owner-only. Native child files may be 0644 inside
    them, but must be owned regular single-link files, unwritable by others.

Safe defaults
    Output goes to a new owner-only directory under ``dist/zk-resource-harness``
    (ignored by Git). Paths that Git tracks are refused. Nothing is ever
    overwritten or deleted: every run, including a failed one, keeps its own
    directory, and this script contains no removal call. The only signal it
    ever sends is ``SIGKILL`` to its own child after ``--timeout-seconds``.

Measurements never affect validity. This tool reports; it gates nothing.

Exit status: 0 accepted or salvageable, 1 rejected (evidence retained),
2 refused before any run directory was created.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import private_settlement_process_observer as observer
import private_settlement_session_control as control

SCHEMA_PATH = REPOSITORY / "crates" / "iroha_measurement" / "fixtures" / "record_schema_v1.json"
DEFAULT_OUTPUT_ROOT = REPOSITORY / "dist" / "zk-resource-harness"
REPORT_SCHEMA = "iroha.measurement.harness_report.v1"
MANIFEST_SCHEMA = "iroha.measurement.harness_manifest.v1"
FAILURE_SCHEMA = "iroha.measurement.harness_failure.v1"
DIRTY_DOMAIN = b"iroha.measurement.dirty.v1\0"
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 64
# Bound manifest/inventory intake independently of an attacker-controlled file list.
MAX_EVIDENCE_FILES = 100_000
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
OUTPUT_PLACEHOLDER = "{output_dir}"
ARGUMENTS_DOMAIN = b"iroha.measurement.arguments.v1\0"
# Most bytes of each output stream that --retain-output-tail-bytes may keep.
MAX_OUTPUT_TAIL_BYTES = 64 * 1024
# Most argument bytes --record-arguments may store verbatim.
MAX_RECORDED_ARGUMENT_BYTES = 64 * 1024
# Output readers may drain after reap. Only an immediate nonblocking reap
# excuses an observer exit race; a later exit cannot erase a genuine failure.
OUTPUT_DRAIN_SECONDS = 5.0
# Fixed reasons of the process observer that mean the running image is not
# the pinned executable (for example a shell that re-executes another image).
IMAGE_MISMATCH_REASONS = frozenset({
    "running Mach-O image differs",
    "running Linux executable differs",
    "running executable path changed or was deleted",
    "running Linux image changed during observation",
})
# Reasons established while the command ran. Salvage cannot derive them again
# from retained files; a run that carries one was rejected.
RUNTIME_ONLY_REASONS = ("address_space_limit_not_applied", "command_not_started",
                        "harness_failure:", "executable_changed_during_run",
                        "address_space_limit_differs_from_kernel")
# Kernel rusage reports CPU in microseconds; a record read from the clock a
# moment earlier may differ from the final total by at most this much.
CPU_ROUNDING_SLACK_NS = 2_000_000


class HarnessRefusal(ValueError):
    """The request is refused before any run directory exists."""


class RecordDecodeError(ValueError):
    """A JSON view does not follow the record schema."""

    def __init__(self, path: str, reason: str):
        super().__init__(f"{path}: {reason}")
        self.path, self.reason = path, reason


# --------------------------------------------------------------------------
# Schema: strict JSON, typed decoding and the report findings.
# --------------------------------------------------------------------------

def strict_json(raw: bytes) -> Any:
    """Parse JSON, rejecting duplicate keys and non-finite constants."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RecordDecodeError("json", "duplicate key")
            result[key] = value
        return result

    def constant(_: str) -> Any:
        raise RecordDecodeError("json", "non-finite number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, RecordDecodeError):
            raise
        raise RecordDecodeError("json", "does not parse") from error


def load_descriptor(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Load the schema descriptor that the Rust crate generates and checks."""
    descriptor = strict_json(path.read_bytes())
    required = {"classification_by_section", "context_file", "context_schema",
                "declared_provenance", "decode_fixed_classification", "enums", "fields",
                "harness_output_dir_env", "invalid_label", "limits",
                "norito_sibling_emitter_prefixes", "record_schema",
                "structural_number_keys", "unbound"}
    if type(descriptor) is not dict or set(descriptor) != required:
        raise HarnessRefusal("schema descriptor has an unexpected shape")
    return descriptor


def _unsigned(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def decode_view(descriptor: dict[str, Any], kind: str, value: Any, path: str) -> None:
    """Check one JSON object against the declared field types of ``kind``.

    Unknown keys, missing keys, booleans or text in place of integers,
    fractions, negative numbers, values above the integer width and unknown
    enumerated words are all rejected, exactly as the Rust decoder does.
    """
    fields = descriptor["fields"][kind]
    if type(value) is not dict:
        raise RecordDecodeError(path, "expected object")
    for key in value:
        if key not in fields:
            raise RecordDecodeError(path, f"unknown key {key}")
    for key in fields:
        if key not in value:
            raise RecordDecodeError(path, f"missing key {key}")
    for key, declared in fields.items():
        item, where = value[key], f"{path}.{key}"
        optional = declared.endswith("?")
        base = declared[:-1] if optional else declared
        if optional and item is None:
            continue
        if base == "u64":
            accepted = _unsigned(item, MAX_U64)
        elif base == "u32":
            accepted = _unsigned(item, MAX_U32)
        elif base == "bool":
            accepted = type(item) is bool
        elif base == "text":
            accepted = type(item) is str
        elif base.startswith("enum:"):
            accepted = type(item) is str and item in descriptor["enums"][base[5:]]
        elif base.startswith("object:"):
            decode_view(descriptor, base[7:], item, where)
            accepted = True
        elif base.startswith("list:"):
            if type(item) is not list:
                raise RecordDecodeError(where, "expected list")
            for index, entry in enumerate(item):
                decode_view(descriptor, base[5:], entry, f"{where}[{index}]")
            accepted = True
        else:
            raise RecordDecodeError(where, f"unknown declared type {declared}")
        if not accepted:
            raise RecordDecodeError(where, f"expected {declared}")
    if (kind in descriptor["decode_fixed_classification"]
            and value["classification"] != descriptor["classification_by_section"][kind]):
        raise RecordDecodeError(f"{path}.classification", "fixed classification differs")


def decode_record(descriptor: dict[str, Any], view: Any) -> dict[str, Any]:
    """Decode one record JSON view; the returned object is the view itself."""
    decode_view(descriptor, "record", view, "record")
    return view


def _grammar(extra: str, limit: int) -> Callable[[Any], bool]:
    pattern = re.compile(r"[A-Za-z0-9_.:" + extra + r"-]{1," + str(limit) + r"}\Z")
    return lambda text: type(text) is str and pattern.match(text) is not None


def _is_hex(text: Any, lengths: Sequence[int]) -> bool:
    return (type(text) is str and len(text) in lengths
            and re.match(r"[0-9a-f]+\Z", text) is not None)


def attribution(record: dict[str, Any]) -> dict[str, int] | None:
    """Root wall time and its unattributed part: the root's exclusive time."""
    nodes = record["phase_tree"]["nodes"]
    if not nodes:
        return None
    return {"root_wall_ns": nodes[0]["wall_inclusive_ns"],
            "unattributed_wall_ns": nodes[0]["wall_exclusive_ns"]}


def within_limit(descriptor: dict[str, Any], measured: dict[str, int]) -> bool:
    """Exact integer check that at most 1% of a nonzero root is unattributed."""
    limits = descriptor["limits"]
    return (measured["root_wall_ns"] > 0
            and measured["unattributed_wall_ns"] * limits["unattributed_denominator"]
            <= measured["root_wall_ns"] * limits["unattributed_numerator"])


def unattributed_ppm(measured: dict[str, int]) -> int:
    """Unattributed share in parts per million, rounded up; for display."""
    return _parts_per_million(measured["unattributed_wall_ns"], measured["root_wall_ns"])


def _parts_per_million(part: int, whole: int) -> int:
    return 1_000_000 if whole == 0 else -(-part * 1_000_000 // whole)


def largest_undivided_phase(descriptor: dict[str, Any],
                            record: dict[str, Any]) -> dict[str, Any] | None:
    """The non-root phase with the most exclusive wall time and its share.

    The 1% rule bounds only the time outside every phase, so a root with one
    wrapper phase passes it. This states how coarse the tree is; the earliest
    phase wins a tie. Mirrors ``MeasurementRecord::largest_undivided_phase``.
    """
    nodes = record["phase_tree"]["nodes"]
    if len(nodes) < 2:
        return None
    index = max(range(1, len(nodes)), key=lambda at: (nodes[at]["wall_exclusive_ns"], -at))
    label = nodes[index]["label"]
    public = _grammar("", descriptor["limits"]["label_max_bytes"])(label)
    return {"phase": index, "label": label if public else descriptor["invalid_label"],
            "wall_exclusive_ns": nodes[index]["wall_exclusive_ns"],
            "share_ppm": _parts_per_million(nodes[index]["wall_exclusive_ns"],
                                            nodes[0]["wall_inclusive_ns"])}


def _union_bound(covered: int, children: int, peak: int) -> bool:
    return covered <= children <= peak * covered


def record_findings(descriptor: dict[str, Any], record: dict[str, Any]) -> list[str]:
    """Every reason a decoded record is not an acceptable complete measurement.

    This mirrors ``MeasurementRecord::findings`` in ``crates/iroha_measurement``
    code for code and in the same order;
    ``fixtures/record_mutations_v1.json`` is tested against both.
    """
    limits = descriptor["limits"]
    label = _grammar("", limits["label_max_bytes"])
    identity_text = _grammar("/+@=,", limits["identity_max_bytes"])
    unbound, invalid = descriptor["unbound"], descriptor["invalid_label"]
    found: list[str] = []
    if record["schema"] != descriptor["record_schema"]:
        found.append("schema_mismatch")

    identity = record["identity"]
    for field, valid in (
        ("workload", label(identity["workload"])),
        ("emitter", label(identity["emitter"])),
        ("source_commit", _is_hex(identity["source_commit"], (40, 64))),
        ("artifact", identity_text(identity["artifact"])),
        ("profile", identity_text(identity["profile"])),
        ("config", identity_text(identity["config"])),
        ("hardware", identity_text(identity["hardware"])),
    ):
        if not valid:
            found.append(f"identity_incomplete:{field}")
    for field in ("workload", "emitter", "artifact", "profile", "config", "hardware"):
        if identity[field] in (unbound, invalid):
            found.append(f"identity_incomplete:{field}")
    digest, dirty = identity["source_dirty_digest"], identity["source_dirty"]
    if not ((digest is not None and dirty and _is_hex(digest, (64,)))
            or (digest is None and not dirty)):
        found.append("dirty_digest_mismatch")

    fixed = descriptor["classification_by_section"]
    for section in ("failures", "phase_tree", "byte_counters", "work_counters", "allocations",
                    "process", "scheduling", "address_space"):
        if record[section]["classification"] != fixed[section]:
            found.append(f"section_classification:{section}")
    for index, declared in enumerate(record["declared"]):
        admitted = descriptor["declared_provenance"].get(declared["classification"], [])
        if declared["provenance_kind"] not in admitted:
            found.append(f"declared_classification:{index}")
        if (not label(declared["label"]) or not identity_text(declared["provenance"])
                or declared["provenance"] == invalid):
            found.append(f"label_not_public:declared:{index}")

    nodes = record["phase_tree"]["nodes"]
    if not nodes:
        found.append("tree_empty")
    for index, node in enumerate(nodes):
        parent = node["parent"]
        if index == 0 and parent is None:
            if node["calls"] != 1:
                found.append("root_shape")
        elif index == 0 or parent is None:
            found.append("root_shape")
        elif parent >= index:
            found.append(f"parent_order:{index}")
        if not label(node["label"]):
            found.append(f"label_not_public:phase_tree:{index}")
        if any(earlier["parent"] == parent and earlier["label"] == node["label"]
               for earlier in nodes[:index]):
            found.append(f"duplicate_sibling:{index}")
        total = node["completed"] + node["interrupted"]
        if (total > MAX_U64 or total != node["calls"] or node["unwound"] > node["interrupted"]
                or node["truncated"] > node["interrupted"]):
            found.append(f"call_accounting:{index}")
        children = [child for child in nodes if child["parent"] == index]
        child_calls = sum(child["calls"] for child in children)
        peak = node["peak_concurrent_children"]
        covered = node["wall_inclusive_ns"] - node["wall_exclusive_ns"]
        if covered < 0 or not _union_bound(
                covered, sum(child["wall_inclusive_ns"] for child in children), peak):
            found.append(f"wall_accounting:{index}")
        covered = node["thread_cpu_inclusive_ns"] - node["thread_cpu_exclusive_ns"]
        if covered < 0 or covered > sum(child["thread_cpu_inclusive_ns"] for child in children):
            found.append(f"thread_cpu_accounting:{index}")
        covered = (node["process_cpu_window_inclusive_ns"]
                   - node["process_cpu_window_exclusive_ns"])
        if covered < 0 or not _union_bound(
                covered, sum(child["process_cpu_window_inclusive_ns"] for child in children),
                peak):
            found.append(f"process_cpu_accounting:{index}")
        if ((peak == 0) != (child_calls == 0) or peak > child_calls
                or node["load_milli_max"] < node["load_milli_first_enter"]
                or node["load_milli_max"] < node["load_milli_last_exit"]
                or (node["calls"] > 0 and node["active_threads_max"] == 0)):
            found.append(f"boundary_accounting:{index}")

    phases = len(nodes)
    for index, failure in enumerate(record["failures"]["entries"]):
        if failure["phase"] >= phases:
            found.append(f"phase_reference:failures:{index}")
        if not label(failure["stage"]) or not label(failure["code"]):
            found.append(f"label_not_public:failures:{index}")
    for index, counter in enumerate(record["byte_counters"]["entries"]):
        if counter["phase"] >= phases:
            found.append(f"phase_reference:byte_counters:{index}")
        if not label(counter["label"]):
            found.append(f"label_not_public:byte_counters:{index}")
        count, total = counter["count"], counter["total_bytes"]
        if (count == 0 or counter["min_bytes"] > counter["max_bytes"]
                or total < count * counter["min_bytes"]
                or total > count * counter["max_bytes"]):
            found.append(f"byte_counter_accounting:{index}")
    for index, counter in enumerate(record["work_counters"]["entries"]):
        if counter["phase"] >= phases:
            found.append(f"phase_reference:work_counters:{index}")
        if not label(counter["label"]):
            found.append(f"label_not_public:work_counters:{index}")
        count, total = counter["count"], counter["total_units"]
        if (count == 0 or counter["min_units"] > counter["max_units"]
                or total < count * counter["min_units"]
                or total > count * counter["max_units"]):
            found.append(f"work_counter_accounting:{index}")
    allocations = allocated_bytes = 0
    sources = record["allocations"]["sources"]
    for index, source in enumerate(sources):
        if not label(source["label"]):
            found.append(f"label_not_public:allocations:{index}")
        if source["kind"] == "scoped_counter":
            allocations += source["allocations"]
            allocated_bytes += source["allocated_bytes"]
            consistent = (
                source["allocated_bytes"] - source["freed_bytes"] == source["live_bytes"]
                and source["allocations"] - source["frees"] == source["live_buffers"]
                and source["live_bytes"] <= source["live_bytes_high_water"]
                <= source["allocated_bytes"]
                and source["live_buffers"] <= source["live_buffers_high_water"]
                <= source["allocations"])
        else:
            consistent = (
                source["allocations"] == source["allocated_bytes"] == source["frees"]
                == source["freed_bytes"] == source["live_buffers"]
                == source["live_buffers_high_water"] == 0
                and source["live_bytes_high_water"] >= source["live_bytes"])
        if not consistent:
            found.append(f"allocation_accounting:{index}")
    if (sum(node["allocations"] for node in nodes),
            sum(node["allocated_bytes"] for node in nodes)) != (allocations, allocated_bytes):
        found.append(f"allocation_accounting:{len(sources)}")
    scheduling = record["scheduling"]
    if scheduling["workers"] == 0 or any(
            entry["workers"] == 0 for entry in scheduling["phase_workers"]):
        found.append("scheduling_accounting")
    if (not identity_text(scheduling["workers_provenance"])
            or scheduling["workers_provenance"] == invalid):
        found.append("label_not_public:scheduling:0")
    for index, entry in enumerate(scheduling["phase_workers"]):
        if entry["phase"] >= phases:
            found.append(f"phase_reference:scheduling:{index}")

    address = record["address_space"]
    soft, hard = address["soft_limit_bytes"], address["hard_limit_bytes"]
    ordered = hard is None or (soft is not None and soft <= hard)
    if not ordered or address["enforced"] != (soft is not None):
        found.append("address_space_accounting")
    if not label(address["source"]):
        found.append("label_not_public:address_space:0")
    process = record["process"]
    if not label(process["thermal_source"]):
        found.append("label_not_public:process:0")
    if process["peak_rss_source"] == "kernel_lifetime_high_water":
        if (process["peak_rss_bytes"] == 0
                or process["peak_rss_bytes"] < process["peak_rss_bytes_at_begin"]):
            found.append("process_accounting")
    else:
        if process["peak_rss_bytes"] != 0 or process["peak_rss_bytes_at_begin"] != 0:
            found.append("process_accounting")
        found.append("peak_rss_unavailable")

    failures = record["failures"]
    failed = bool(failures["entries"]) or failures["dropped"] > 0
    root = nodes[0] if nodes else None
    outcome = record["outcome"]
    if outcome == "succeeded":
        consistent = not failed and (root is None or root["completed"] == 1)
    elif outcome == "failed":
        consistent = failed and (root is None or root["completed"] == 1)
    elif outcome == "abandoned":
        consistent = root is None or (root["interrupted"] == 1 and root["unwound"] == 0)
    else:
        consistent = root is None or root["unwound"] == 1
    if not consistent:
        found.append("outcome_mismatch")
    if failures["dropped"] > 0:
        found.append(f"failures_dropped:{failures['dropped']}")
    if outcome != "succeeded":
        found.append(f"run_not_succeeded:{outcome}")
    health = record["recorder"]
    if (health["node_overflow_events"] or health["span_overflow_events"]
            or health["counter_overflow_events"]):
        found.append("recorder_overflow")
    if health["invalid_label_events"]:
        found.append("label_not_public:recorder:0")
    if health["clock_anomaly_events"]:
        found.append("clock_anomaly")

    measured = attribution(record)
    if measured is not None:
        if not any(node["parent"] == 0 for node in nodes):
            found.append("no_phases")
        elif not within_limit(descriptor, measured):
            found.append("unattributed_exceeds_limit:"
                         f"{measured['unattributed_wall_ns']}:{measured['root_wall_ns']}")
    return found


def unclassified_numbers(descriptor: dict[str, Any], view: Any, path: str = "record",
                         classified: bool = False) -> list[str]:
    """Paths of numbers with no ``classification`` on them or an ancestor.

    Structural numbers (phase indices and the process identifier) are exempt.
    """
    found: list[str] = []
    if type(view) in (int, float):
        if not classified:
            found.append(path)
    elif type(view) is list:
        for index, item in enumerate(view):
            found += unclassified_numbers(descriptor, item, f"{path}[{index}]", classified)
    elif type(view) is dict:
        classified = classified or "classification" in view
        for key, item in view.items():
            structural = (type(item) in (int, float)
                          and key in descriptor["structural_number_keys"])
            if not structural:
                found += unclassified_numbers(descriptor, item, f"{path}.{key}", classified)
    return found


# --------------------------------------------------------------------------
# Source and artifact identity.
# --------------------------------------------------------------------------

def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repository), *arguments],
                          capture_output=True, check=False)


def sha256_file(path: Path) -> tuple[str, int]:
    """SHA-256 and length of one regular file, read in bounded chunks."""
    digest, length = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
    return digest.hexdigest(), length


def source_state(repository: Path) -> dict[str, Any]:
    """Exact source identity: the commit and, when dirty, a digest of the difference.

    The digest covers the binary diff against ``HEAD`` and the path and content
    hash of every untracked, unignored file, so two dirty trees share a digest
    only when they hold the same source.
    """
    head = _git(repository, "rev-parse", "--verify", "HEAD")
    commit = head.stdout.decode("ascii", "replace").strip()
    if head.returncode != 0 or not _is_hex(commit, (40, 64)):
        raise HarnessRefusal("repository has no resolvable HEAD commit")
    status = _git(repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status.returncode != 0:
        raise HarnessRefusal("git status failed")
    if not status.stdout:
        return {"source_commit": commit, "source_dirty": False, "source_dirty_digest": None}
    digest = hashlib.sha256(DIRTY_DOMAIN)
    with subprocess.Popen(
            ["git", "-C", str(repository), "diff", "HEAD", "--binary", "--no-ext-diff",
             "--no-color"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as diff:
        assert diff.stdout is not None
        while True:
            chunk = diff.stdout.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    if diff.returncode != 0:
        raise HarnessRefusal("git diff failed")
    untracked = _git(repository, "ls-files", "--others", "--exclude-standard", "-z")
    if untracked.returncode != 0:
        raise HarnessRefusal("git ls-files failed")
    for name in sorted(item for item in untracked.stdout.split(b"\0") if item):
        path = repository / os.fsdecode(name)
        digest.update(b"\0untracked\0" + name + b"\0")
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            digest.update(b"link\0" + os.fsencode(os.readlink(path)))
        elif stat.S_ISREG(info.st_mode):
            digest.update(sha256_file(path)[0].encode("ascii"))
        else:
            raise HarnessRefusal("untracked source entry is neither a file nor a link")
    return {"source_commit": commit, "source_dirty": True,
            "source_dirty_digest": digest.hexdigest()}


def resolve_executable(command: str) -> Path:
    """The regular executable file that will be pinned and started."""
    located = command if os.sep in command else shutil.which(command)
    if located is None:
        raise HarnessRefusal("command executable was not found")
    try:
        path = Path(located).resolve(strict=True)
    except OSError as error:
        raise HarnessRefusal("command executable was not found") from error
    if not path.is_file() or not os.access(path, os.X_OK):
        raise HarnessRefusal("command is not an executable regular file")
    return path


def ensure_untracked_root(repository: Path, root: Path) -> Path:
    """Refuse an output root that Git tracks or would let Git add."""
    # Resolve links in the existing prefix so a linked path into the
    # repository cannot bypass the tracked-path refusal.
    root = Path(os.path.realpath(root))
    try:
        relative = root.relative_to(repository.resolve())
    except ValueError:
        return root
    if str(relative) in ("", "."):
        raise HarnessRefusal("output root is the repository itself")
    tracked = _git(repository, "ls-files", "-z", "--", str(relative))
    if tracked.returncode != 0 or tracked.stdout:
        raise HarnessRefusal("output root contains tracked files")
    ignored = _git(repository, "check-ignore", "-q", "--", str(relative / "probe"))
    if ignored.returncode != 0:
        raise HarnessRefusal("output root inside the repository is not ignored by Git")
    return root


def build_context(descriptor: dict[str, Any], repository: Path, executable_sha256: str,
                  profile: str, config: str, hardware: str, cache_policy: str) -> dict[str, Any]:
    """The hand-off context: everything the harness knows before the run."""
    identity_text = _grammar("/+@=,", descriptor["limits"]["identity_max_bytes"])
    for name, value in (("profile", profile), ("config", config), ("hardware", hardware)):
        if not identity_text(value) or value in (descriptor["unbound"],
                                                 descriptor["invalid_label"]):
            raise HarnessRefusal(f"--{name} is not a bound identity text")
    if cache_policy not in descriptor["enums"]["cache_policy"]:
        raise HarnessRefusal("--cache-policy is not a known policy")
    context = {"schema": descriptor["context_schema"], "artifact": "sha256:" + executable_sha256,
               "profile": profile, "config": config, "hardware": hardware,
               "cache_policy": cache_policy}
    context.update(source_state(repository))
    decode_view(descriptor, "context", context, "context")
    return context


# --------------------------------------------------------------------------
# Host facts, argument digest and output streams.
# --------------------------------------------------------------------------

def _host_text(value: Any) -> str:
    """One bounded printable host fact; anything else is ``unavailable``."""
    text = " ".join(str(value).split()) if value is not None else ""
    return text if re.fullmatch(r"[ -~]{1,160}", text) else "unavailable"


def _sysctl(name: str) -> str | None:
    try:
        result = subprocess.run(["/usr/sbin/sysctl", "-n", name], capture_output=True,
                                check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.decode("utf-8", "replace") if result.returncode == 0 else None


def _first_line(path: str, prefix: str = "") -> str | None:
    try:
        with open(path, "rb") as stream:
            for raw in stream.read(1 << 16).decode("utf-8", "replace").splitlines():
                if raw.startswith(prefix):
                    return raw[len(prefix):].lstrip(" \t:")
    except OSError:
        return None
    return None


def host_facts() -> dict[str, Any]:
    """Facts the harness observed about the host it ran on.

    ``--hardware`` is a name the operator asserts. These facts are what the
    operating system reported, so a mislabelled run is visible in its own
    report. The host name is not recorded.
    """
    uname = platform.uname()
    if sys.platform == "darwin":
        model, cpu = _sysctl("hw.model"), _sysctl("machdep.cpu.brand_string")
    else:
        model = _first_line("/sys/devices/virtual/dmi/id/product_name")
        cpu = _first_line("/proc/cpuinfo", "model name")
    try:
        memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        memory = 0
    return {"classification": "measured", "system": _host_text(uname.system),
            "release": _host_text(uname.release), "machine": _host_text(uname.machine),
            "model": _host_text(model), "cpu": _host_text(cpu),
            "logical_cpus": os.cpu_count() or 0,
            "physical_memory_bytes": memory if 0 < memory <= MAX_U64 else 0}


def arguments_digest(arguments: Sequence[str]) -> str:
    """SHA-256 over the length-prefixed argument vector; the text is not kept."""
    digest = hashlib.sha256(ARGUMENTS_DOMAIN)
    digest.update(len(arguments).to_bytes(8, "big"))
    for argument in arguments:
        raw = os.fsencode(argument)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()


class StreamDigest(threading.Thread):
    """Hash and count one output stream of the command without storing it.

    At most ``tail_bytes`` of the end of the stream are kept in memory, and
    only when the operator asked for a tail.
    """

    def __init__(self, descriptor: int, tail_bytes: int):
        super().__init__(daemon=True)
        self.descriptor, self.tail_bytes = descriptor, tail_bytes
        self.digest, self.length, self.tail = hashlib.sha256(), 0, b""

    def run(self) -> None:
        """Read to end of stream."""
        while True:
            try:
                chunk = os.read(self.descriptor, 1 << 16)
            except OSError:
                return
            if not chunk:
                return
            self.digest.update(chunk)
            self.length += len(chunk)
            if self.tail_bytes:
                self.tail = (self.tail + chunk)[-self.tail_bytes:]

    def result(self, records: Any, name: str) -> dict[str, Any]:
        """The stream's length and digest, and the tail reference if one was kept."""
        self.join(OUTPUT_DRAIN_SECONDS)
        complete = not self.is_alive()
        tail = None
        if complete and self.tail_bytes and self.tail:
            tail = records.publish(name, self.tail)
        return {"bytes": self.length, "sha256": self.digest.hexdigest() if complete else None,
                "complete": complete, "tail": tail}


# --------------------------------------------------------------------------
# Running and observing the command.
# --------------------------------------------------------------------------

def new_run_directory(root: Path) -> Path:
    """Create a fresh owner-only run directory; an existing one is never reused."""
    os.makedirs(root, mode=0o755, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dt%H%M%Sz")
    run = root / f"run-{stamp}-{os.getpid()}-{secrets.token_hex(4)}"
    os.mkdir(run, 0o700)
    for name in ("child", "observations"):
        os.mkdir(run / name, 0o700)
    return run


def _rusage_ns(seconds: float) -> int:
    return round(seconds * 1_000_000) * 1000


def _peak_rss_bytes(maxrss: int) -> int:
    """``ru_maxrss`` is bytes on Darwin and kilobytes on Linux."""
    return maxrss if sys.platform == "darwin" else maxrss * 1024


def _try_reap(pid: int) -> tuple[int, Any] | None:
    reaped, status, usage = os.wait4(pid, os.WNOHANG)
    return (status, usage) if reaped == pid else None


def _kill_own_child(pid: int) -> tuple[int, Any]:
    """Kill the harness's own child after its deadline and take its totals."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return os.wait4(pid, 0)[1:]


def _exit_fact(status: int) -> dict[str, Any]:
    if os.WIFSIGNALED(status):
        return {"kind": "signaled", "signal": os.WTERMSIG(status)}
    return {"kind": "exited", "code": os.WEXITSTATUS(status)}


def _image_differs(error: BaseException) -> bool:
    return (isinstance(error, observer.ProcessObservationError)
            and str(error) in IMAGE_MISMATCH_REASONS)


def observe_child(child: subprocess.Popen, image: observer.ExecutableImage, records: Any,
                  interval_ms: int, timeout_ms: int) -> dict[str, Any]:
    """Sample the pinned child until it exits, then take the kernel's totals.

    Sampling reuses the observer's identity-pinned ``ProcessScope`` and its
    bounded ``ResourceObservationJournal``; the retained samples are
    recomputed by ``validate_resource_window``. The final CPU and peak RSS
    come from ``wait4``: exact kernel accounting of the whole child, not a
    sample.

    ``sampled.state`` is ``validated`` for two or more samples,
    ``not_sampled`` when the command exited before a second sample could be
    taken (the kernel totals are still exact), and ``failed`` when the
    observer could not authenticate the process: a running image other than
    the pinned executable is reported as ``executable_image_differs``.
    """
    started = time.monotonic_ns()
    deadline = started + timeout_ms * 1_000_000
    policy = observer.resource_window_policy(timeout_ms, interval_ms)
    sampled: dict[str, Any] = {"state": "failed", "reason": "not_started"}
    reaped: tuple[int, Any] | None = None
    reader = None
    try:
        reader = observer.native_reader()
        scope = None
        try:
            scope = observer.ProcessScope(
                [{"label": "measured_command", "pid": child.pid, "ppid": os.getpid(),
                  "pgid": os.getpgid(child.pid), "image": "command"}], reader,
                {"command": image})
        except (ValueError, OSError) as error:
            if _image_differs(error):
                sampled = {"state": "failed", "reason": "executable_image_differs"}
            else:
                reaped = _try_reap(child.pid)
                sampled = ({"state": "not_sampled", "reason": "exited_before_first_sample",
                            "observations": 0} if reaped is not None
                           else {"state": "failed", "reason": type(error).__name__})
        if scope is not None:
            journal = observer.ResourceObservationJournal(records, "observations", policy)
            baseline = scope.initial
            journal.append(baseline)
            baseline_reference = records.publish("observations/baseline.json",
                                                 control.canonical(baseline))
            failure: str | None = None
            while reaped is None:
                reaped = _try_reap(child.pid)
                if reaped is not None or time.monotonic_ns() >= deadline:
                    break
                time.sleep(interval_ms / 1000)
                if failure is not None:
                    continue
                try:
                    journal.append(scope.observe())
                except (ValueError, OSError) as error:
                    if _image_differs(error):
                        failure = "executable_image_differs"
                        continue
                    # The process may have exited between the reap check and
                    # the sample. Only a failure while it stays alive is one.
                    reaped = _try_reap(child.pid)
                    if reaped is None:
                        failure = journal.failure_reason or "process_observation_failed"
            if failure is None and not journal.failed:
                journal.flush()
            if failure is not None or journal.failed:
                sampled = {"state": "failed",
                           "reason": failure or journal.failure_reason or "journal_failed"}
            elif journal.count < 2:
                sampled = {"state": "not_sampled", "reason": "exited_before_second_sample",
                           "observations": journal.count}
            else:
                first, last = journal.first, journal.last
                window = {
                    "version": 1, "kind": "benchmark_process_resource_window",
                    "baseline": baseline_reference, "sampler_stopped_observed": True,
                    "journal": journal.manifest(),
                    "outcome": {
                        "kind": "succeeded",
                        "cpu_time_ns": last["cpu_time_ns"] - first["cpu_time_ns"],
                        "sampled_peak_rss_bytes": journal.peak,
                        "maximum_observation_gap_ns": journal.maximum_gap,
                        "baseline_started_monotonic_ns": first["started_monotonic_ns"],
                        "baseline_finished_monotonic_ns": first["finished_monotonic_ns"],
                        "final_started_monotonic_ns": last["started_monotonic_ns"],
                        "final_finished_monotonic_ns": last["finished_monotonic_ns"]}}
                row = baseline["processes"][0]
                metrics = observer.validate_resource_window(
                    window, records=records, outer_timeout_ms=timeout_ms,
                    expected_processes=[{"label": row["label"], "identity": row["identity"],
                                         "cpu_counter_unit_ns": row["cpu_counter_unit_ns"]}],
                    interval_ms=interval_ms)
                window_reference = records.publish("observations/window.json",
                                                   control.canonical(window))
                sampled = {"state": "validated", "observations": journal.count,
                           "window": window_reference,
                           "sampled_cpu_time_ns": metrics["cpu_time_ns"],
                           "sampled_peak_rss_bytes": metrics["sampled_peak_rss_bytes"],
                           "maximum_observation_gap_ns": metrics["maximum_observation_gap_ns"]}
    except (ValueError, OSError) as error:
        # Reader, journal or window failure: the run is still reaped and
        # reported; only a fixed reason is recorded.
        sampled = {"state": "failed", "reason": type(error).__name__}
    finally:
        if reader is not None:
            reader.close()
    timed_out = False
    while reaped is None:
        reaped = _try_reap(child.pid)
        if reaped is None:
            if time.monotonic_ns() >= deadline:
                timed_out = True
                reaped = _kill_own_child(child.pid)
            else:
                time.sleep(interval_ms / 1000)
    status, usage = reaped
    finished = time.monotonic_ns()
    child.returncode = (-os.WTERMSIG(status) if os.WIFSIGNALED(status)
                        else os.WEXITSTATUS(status))
    return {"classification": "measured", "pid": child.pid, "exit": _exit_fact(status),
            "timed_out": timed_out, "wall_ns": finished - started,
            "cpu_user_ns": _rusage_ns(usage.ru_utime),
            "cpu_system_ns": _rusage_ns(usage.ru_stime),
            "peak_rss_bytes": _peak_rss_bytes(usage.ru_maxrss),
            "peak_rss_source": "kernel_child_rusage", "sampled": sampled}


def _limit_address_space(limit: int) -> Callable[[], None]:
    # TODO: Darwin refuses RLIMIT_AS, so the applied-limit path has only been
    # exercised with this function replaced in tests. Run it once on Linux.
    def apply() -> None:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    return apply


def parse_linux_address_space_limit(raw: bytes) -> tuple[int | None, int | None] | None:
    """Soft and hard ``Max address space`` of a ``/proc/<pid>/limits`` text.

    ``None`` inside the pair means unlimited; ``None`` for the pair means the
    line is absent or malformed.
    """
    for line in raw.decode("ascii", "replace").splitlines():
        if line.startswith("Max address space"):
            fields = line[len("Max address space"):].split()
            if len(fields) < 2:
                return None
            pair = []
            for field in fields[:2]:
                if field == "unlimited":
                    pair.append(None)
                elif field.isdigit() and int(field) <= MAX_U64:
                    pair.append(int(field))
                else:
                    return None
            return pair[0], pair[1]
    return None


def kernel_address_space_limit(pid: int) -> tuple[int | None, int | None] | None:
    """The kernel's own record of the child's limit, where it exposes one.

    Linux publishes another process's limits under ``/proc``. Darwin has no
    such interface, so there the applied limit is corroborated only by the
    records the command itself emits.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open(f"/proc/{pid}/limits", "rb") as stream:
            return parse_linux_address_space_limit(stream.read(1 << 16))
    except OSError:
        return None


def address_space_enforcement(limit: int | None,
                              kernel: tuple[int | None, int | None] | None) -> dict[str, Any]:
    """What limit the harness put in force for the command it started."""
    observed = (None if kernel is None
                else {"soft_limit_bytes": kernel[0], "hard_limit_bytes": kernel[1]})
    if limit is None:
        return {"classification": "local_scheduling", "enforced": False,
                "soft_limit_bytes": None, "hard_limit_bytes": None,
                "source": "not_requested", "kernel_observed": observed}
    return {"classification": "local_scheduling", "enforced": True, "soft_limit_bytes": limit,
            "hard_limit_bytes": limit, "source": "harness.setrlimit.RLIMIT_AS",
            "kernel_observed": observed}


def process_reasons(process: dict[str, Any], output: dict[str, Any]) -> list[str]:
    """Rejection reasons that follow from how the command ended and was observed."""
    reasons: list[str] = []
    if process["timed_out"]:
        reasons.append("command_timeout")
    elif process["exit"]["kind"] == "signaled":
        reasons.append(f"command_signal:{process['exit']['signal']}")
    elif process["exit"]["code"] != 0:
        reasons.append(f"command_exit:{process['exit']['code']}")
    if process["sampled"]["state"] == "failed":
        reasons.append("process_observation_failed:" + str(process["sampled"]["reason"]))
    for name in ("stdout", "stderr"):
        if not output[name]["complete"]:
            reasons.append(f"output_stream_not_closed:{name}")
    return reasons


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(info, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns"))


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid"))


def _evidence_kind(name: str, context_file: str) -> str | None:
    """Closed first-release output paths; unknown workload state is never evidence."""
    if name in {"report.json", "manifest.json", "harness_failure.json",
                "stdout.tail.log", "stderr.tail.log"}:
        return "harness"
    parts = name.split("/")
    if len(parts) != 2:
        return None
    directory, leaf = parts
    if directory == "child":
        if leaf == context_file:
            return "context"
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(json|norito)", leaf):
            return "view" if leaf.endswith(".json") else "binary"
    if directory == "observations" and (leaf in {"baseline.json", "window.json"}
            or re.fullmatch(r"chunk-[0-9]{20}\.json", leaf)):
        return "observation"
    return None


class _EvidenceDirectory:
    """Held-directory reads with the native emitter's explicit permission contract.

    The existing session directory anchors owner-only parents. Child emitters use
    ordinary file creation, so their owned 0644 files are accepted inside that
    private tree; group/other write access, hard links and nonregular files are not.
    """

    def __init__(self, run: Path):
        self.root = control.RecordDirectory(run)
        self.directories: dict[str, tuple[int, tuple[int, ...]]] = {}

    def _parent(self, name: str) -> int:
        if not name:
            return self.root.fd
        if name not in {"child", "observations"}:
            raise ValueError("evidence parent outside closed inventory")
        if name not in self.directories:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=self.root.fd)
            info = os.fstat(fd)
            if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) & 0o077 == 0):
                os.close(fd)
                raise ValueError("evidence parent is not owner-only")
            self.directories[name] = fd, _directory_identity(info)
        return self.directories[name][0]

    def _validate(self) -> None:
        self.root.validate()
        for name, (fd, identity) in self.directories.items():
            if not (identity == _directory_identity(os.fstat(fd))
                    == _directory_identity(os.stat(name, dir_fd=self.root.fd, follow_symlinks=False))):
                raise ValueError("evidence parent identity changed")

    def _names(self, directory: str) -> list[str]:
        names = []
        with os.scandir(self._parent(directory)) as entries:
            for entry in entries:
                if len(names) >= MAX_EVIDENCE_FILES:
                    raise ValueError("evidence inventory exceeds bound")
                names.append(entry.name)
        return sorted(names)

    def _read(self, name: str, maximum: int, retain: bool) -> tuple[dict[str, Any], bytes | None]:
        self._validate()
        directory, _, leaf = name.rpartition("/")
        fd_parent = self._parent(directory)
        named = os.stat(leaf, dir_fd=fd_parent, follow_symlinks=False)
        # Inspect before opening to reject FIFOs/devices without touching them.
        if not (stat.S_ISREG(named.st_mode) and named.st_uid == os.geteuid()
                and named.st_nlink == 1 and stat.S_IMODE(named.st_mode) & 0o022 == 0):
            raise ValueError("unsafe evidence file")
        if not 0 <= named.st_size <= maximum:
            raise ValueError("evidence file exceeds bound")
        fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=fd_parent)
        try:
            before = os.fstat(fd)
            if _file_identity(before) != _file_identity(named):
                raise ValueError("evidence file identity changed")
            digest, chunks, remaining = hashlib.sha256(), [], before.st_size
            while remaining:
                raw = os.read(fd, min(remaining, 65536))
                if not raw:
                    raise ValueError("evidence file truncated")
                digest.update(raw)
                if retain:
                    chunks.append(raw)
                remaining -= len(raw)
            if not (_file_identity(before) == _file_identity(os.fstat(fd))
                    == _file_identity(os.stat(leaf, dir_fd=fd_parent, follow_symlinks=False))):
                raise ValueError("evidence file changed during read")
            self._validate()
            return ({"path": name, "sha256": digest.hexdigest(), "bytes": before.st_size},
                    b"".join(chunks) if retain else None)
        finally:
            os.close(fd)

    def __enter__(self) -> _EvidenceDirectory:
        return self

    def __exit__(self, *_: object) -> None:
        for fd, _identity in self.directories.values():
            os.close(fd)
        self.root.close()


class _EvidenceSnapshot:
    """One bounded byte snapshot: hashing and JSON decoding share the same reads."""

    def __init__(self, directory: _EvidenceDirectory, descriptor: dict[str, Any]):
        self.bindings: dict[str, dict[str, Any]] = {}
        self.raw: dict[str, bytes] = {}
        self.reasons: list[str] = []
        self.child_names: list[str] = []
        inventories: dict[str, list[str]] = {"": directory._names("")}
        paths: list[str] = []
        for index, name in enumerate(inventories[""]):
            if name in {"child", "observations"}:
                try:
                    inventories[name] = directory._names(name)
                except (OSError, ValueError):
                    self.reasons.append(f"unsafe_evidence_directory:{index}")
                    continue
                paths.extend(f"{name}/{leaf}" for leaf in inventories[name])
            elif name != "manifest.json":
                paths.append(name)
        if len(paths) > MAX_EVIDENCE_FILES:
            raise ValueError("evidence inventory exceeds bound")
        self.child_names = inventories.get("child", [])
        allowed_child = set(self.child_names[:2 * MAX_RECORDS + 1])
        if len(self.child_names) > 2 * MAX_RECORDS + 1:
            self.reasons.append("too_many_child_entries")
        views = [name for name in self.child_names if name.endswith(".json")
                 and name != descriptor["context_file"]]
        allowed_views = set(views[:MAX_RECORDS])
        if len(views) > MAX_RECORDS:
            self.reasons.append("too_many_records")
        for index, path in enumerate(sorted(paths)):
            if path.startswith("child/") and path[len("child/"):] not in allowed_child:
                continue
            kind = _evidence_kind(path, descriptor["context_file"])
            if kind is None:
                self.reasons.append(f"unexpected_evidence_entry:{index}")
                continue
            leaf = path.rsplit("/", 1)[-1]
            if kind == "view" and leaf not in allowed_views:
                continue
            maximum = MAX_RECORD_BYTES if kind in {"view", "binary"} else MAX_EVIDENCE_BYTES
            try:
                binding, raw = directory._read(path, maximum, kind in {"view", "context"}
                                               or path == "report.json")
            except (OSError, ValueError):
                self.reasons.append(f"unsafe_or_oversize_evidence:{index}")
                continue
            self.bindings[path] = binding
            if raw is not None:
                self.raw[path] = raw
        for name, previous in inventories.items():
            if directory._names(name) != previous:
                self.reasons.append("evidence_inventory_changed")
        directory._validate()


def judge_records(descriptor: dict[str, Any], run: Path, context: dict[str, Any],
                  process: dict[str, Any], requirements: dict[str, Any],
                  *, snapshot: _EvidenceSnapshot | None = None,
                  ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str],
                             list[dict[str, Any]]]:
    """Decode and judge every record the command wrote into ``run/child``.

    Returns the report entries, the Norito files left without a JSON view,
    the rejection reasons and the decoded records. ``requirements`` carries
    the requested address-space limit, whether a thermal state is required
    and the consumer's bound on the largest undivided phase. Read-only.
    """
    entries: list[dict[str, Any]] = []
    if snapshot is None:
        with _EvidenceDirectory(run) as directory:
            snapshot = _EvidenceSnapshot(directory, descriptor)
    reasons: list[str] = list(snapshot.reasons)
    decoded: list[dict[str, Any]] = []
    present = snapshot.child_names
    names = [name for name in present
             if name.endswith(".json") and name != descriptor["context_file"]
             and f"child/{name}" in snapshot.raw]
    try:
        if strict_json(snapshot.raw["child/" + descriptor["context_file"]]) != context:
            reasons.append("child_context_differs")
    except (KeyError, RecordDecodeError):
        reasons.append("child_context_unreadable")
    orphans = []
    for index, name in enumerate(name for name in present if name.endswith(".norito")
                                 and name[:-len(".norito")] + ".json" not in present):
        binding = snapshot.bindings.get(f"child/{name}")
        if binding is not None:
            orphans.append(dict(binding, classification="measured"))
        reasons.append(f"record_without_json_view:{index}")
    if not any(name.endswith(".json") and name != descriptor["context_file"] for name in present):
        reasons.append("no_record_emitted")
    limit = requirements["address_space_limit_bytes"]
    label = _grammar("", descriptor["limits"]["label_max_bytes"])
    for index, name in enumerate(names):
        path = "child/" + name
        entry: dict[str, Any] = {
            "classification": "measured",
            "json": snapshot.bindings[path],
            "norito": None, "decoded": False, "findings": []}
        # TODO: the Norito sibling is bound by digest only. Decoding it here and
        # comparing it with the JSON view needs a Python Norito decoder for
        # this schema; the equality of both forms is proven on the Rust side.
        entry["norito"] = snapshot.bindings.get(path[:-len(".json")] + ".norito")
        entries.append(entry)
        try:
            record = decode_record(descriptor, strict_json(snapshot.raw[path]))
        except RecordDecodeError as error:
            entry["decode_error"] = error.path
            reasons.append(f"record_decode_error:{index}")
            continue
        decoded.append(record)
        identity = record["identity"]
        entry["decoded"] = True
        entry["workload"] = (identity["workload"] if label(identity["workload"])
                             else descriptor["invalid_label"])
        entry["flow"] = identity["flow"]
        entry["outcome"] = record["outcome"]
        measured = attribution(record)
        if measured is not None:
            entry["attribution"] = dict(measured, unattributed_ppm=unattributed_ppm(measured))
            entry["within_one_percent"] = within_limit(descriptor, measured)
        largest = largest_undivided_phase(descriptor, record)
        entry["largest_undivided_phase"] = largest
        findings = record_findings(descriptor, record)
        if unclassified_numbers(descriptor, record):
            findings.append("unclassified_number")
        if any(identity[key] != context[key] for key in context if key != "schema"):
            findings.append("identity_differs_from_harness_context")
        if (entry["norito"] is None and type(identity["emitter"]) is str
                and identity["emitter"].startswith(
                    tuple(descriptor["norito_sibling_emitter_prefixes"]))):
            # A native emitter writes both forms; the binary one was lost.
            findings.append("norito_sibling_missing")
        observed = record["process"]
        if observed["pid"] != process["pid"]:
            findings.append("pid_differs_from_observed_process")
        elif (observed["peak_rss_bytes"] > process["peak_rss_bytes"]
              or observed["cpu_user_ns"] + observed["cpu_system_ns"]
              > process["cpu_user_ns"] + process["cpu_system_ns"] + CPU_ROUNDING_SLACK_NS):
            findings.append("record_exceeds_kernel_process_accounting")
        address = record["address_space"]
        if limit is not None and not (address["enforced"] is True
                                      and address["soft_limit_bytes"] == limit
                                      and address["hard_limit_bytes"] == limit):
            # The command must itself observe exactly the limit the harness
            # applied; a sampled peak below a limit is not an enforced limit.
            findings.append("address_space_differs_from_requested_limit")
        if requirements["thermal_state"] and "unavailable" in (
                observed["thermal_begin"], observed["thermal_finish"]):
            findings.append("thermal_state_unavailable")
        bound = requirements["max_undivided_phase_ppm"]
        if bound is not None and largest is not None and largest["share_ppm"] > bound:
            findings.append(
                f"undivided_phase_exceeds_bound:{largest['phase']}:{largest['share_ppm']}")
        entry["findings"] = findings
        if findings:
            reasons.append(f"record_rejected:{index}")
    return entries, orphans, reasons, decoded


def collect_records(descriptor: dict[str, Any], run: Path, context: dict[str, Any],
                    process: dict[str, Any], requirements: dict[str, Any],
                    *, snapshot: _EvidenceSnapshot | None = None,
                    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Report entries, orphaned Norito files and reasons for one run directory."""
    return judge_records(descriptor, run, context, process, requirements, snapshot=snapshot)[:3]


def write_manifest(run: Path, records: Any, context: dict[str, Any],
                   verdict: str, *, snapshot: _EvidenceSnapshot | None = None) -> dict[str, Any]:
    """Bind only the closed evidence inventory, retaining rejected private state in place.

    The manifest is not signed. Its own reference is returned so the caller
    can print the digest an operator retains or signs outside this tool.
    """
    with _EvidenceDirectory(run) as directory:
        current = _EvidenceSnapshot(directory, load_descriptor())
    if verdict == "accepted" and current.reasons:
        raise ValueError("accepted evidence inventory changed")
    if snapshot is not None and any(current.bindings.get(name) != binding
                                    for name, binding in snapshot.bindings.items()):
        raise ValueError("evidence changed after judgment")
    if snapshot is not None and set(current.bindings) - set(snapshot.bindings) != {"report.json"}:
        raise ValueError("evidence added after judgment")
    files = [current.bindings[name] for name in sorted(current.bindings)]
    return records.publish("manifest.json", control.canonical({
        "schema": MANIFEST_SCHEMA, "context": context, "verdict": verdict,
        "classification": "measured", "files": files}))


def run_requirements(arguments: argparse.Namespace) -> dict[str, Any]:
    """Operator-stated requirements beyond the record schema's own rules."""
    return validate_requirements({"classification": "engineering_target",
                                 "address_space_limit_bytes": arguments.address_space_limit_bytes,
                                 "thermal_state": arguments.require_thermal_state,
                                 "max_undivided_phase_ppm": arguments.max_undivided_phase_ppm})


def validate_requirements(requirements: Any) -> dict[str, Any]:
    """Validate the exact engineering-target contract without boolean/integer coercion."""
    if (type(requirements) is not dict
            or set(requirements) != {"classification", "address_space_limit_bytes",
                                    "thermal_state", "max_undivided_phase_ppm"}
            or requirements["classification"] != "engineering_target"
            or type(requirements["thermal_state"]) is not bool):
        raise HarnessRefusal("requirements have invalid fields or classification")
    for field, maximum in (("address_space_limit_bytes", MAX_U64 // 2),
                           ("max_undivided_phase_ppm", MAX_U32)):
        value = requirements[field]
        if value is not None and not (type(value) is int and 1 <= value <= maximum):
            raise HarnessRefusal("requirement is outside its range: " + field)
    return dict(requirements)


def _consumer_reasons(original: dict[str, Any], consumer: dict[str, Any]) -> list[str]:
    reasons = []
    if (consumer["address_space_limit_bytes"] is not None
            and consumer["address_space_limit_bytes"] != original["address_space_limit_bytes"]):
        reasons.append("consumer_requirement_not_established:address_space_limit_bytes")
    if consumer["thermal_state"] and not original["thermal_state"]:
        reasons.append("consumer_requirement_not_established:thermal_state")
    bound = consumer["max_undivided_phase_ppm"]
    if bound is not None and (original["max_undivided_phase_ppm"] is None
                             or original["max_undivided_phase_ppm"] > bound):
        reasons.append("consumer_requirement_not_established:max_undivided_phase_ppm")
    return reasons


def run_command(arguments: argparse.Namespace) -> int:
    """Run the command once and write its report; never raises after spawn."""
    descriptor = load_descriptor()
    repository = Path(arguments.repository).resolve()
    command = list(arguments.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise HarnessRefusal("no command was given after --")
    if not 10 <= arguments.interval_ms <= 1000:
        raise HarnessRefusal("--interval-ms must be between 10 and 1000")
    if not 1 <= arguments.timeout_seconds <= 7 * 24 * 3600:
        raise HarnessRefusal("--timeout-seconds is outside its range")
    requirements = run_requirements(arguments)
    limit = requirements["address_space_limit_bytes"]
    tail_bytes = arguments.retain_output_tail_bytes
    if not 0 <= tail_bytes <= MAX_OUTPUT_TAIL_BYTES:
        raise HarnessRefusal("--retain-output-tail-bytes is outside its range")
    recorded_arguments = None
    if arguments.record_arguments:
        try:
            size = sum(len(argument.encode("utf-8")) for argument in command[1:])
        except UnicodeError as error:
            raise HarnessRefusal("--record-arguments needs UTF-8 arguments") from error
        if size > MAX_RECORDED_ARGUMENT_BYTES:
            raise HarnessRefusal("--record-arguments exceeds its byte bound")
        recorded_arguments = command[1:]
    executable = resolve_executable(command[0])
    executable_sha256 = sha256_file(executable)[0]
    context = build_context(descriptor, repository, executable_sha256, arguments.profile,
                            arguments.config, arguments.hardware, arguments.cache_policy)
    root = ensure_untracked_root(repository, Path(arguments.output_root))
    run = new_run_directory(root)
    records = control.RecordDirectory(run)
    reasons: list[str] = []
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA, "context": context,
        "command": {"executable": str(executable), "executable_sha256": executable_sha256,
                    "arguments_sha256": arguments_digest(command[1:]),
                    "arguments": recorded_arguments},
        "limits": {"classification": "local_scheduling",
                   "timeout_ms": arguments.timeout_seconds * 1000,
                   "sampling_interval_ms": arguments.interval_ms,
                   "requested_address_space_bytes": limit,
                   "output_tail_bytes": tail_bytes},
        "requirements": requirements, "host": host_facts(),
        "process": None, "output": None, "records": [], "orphans": [],
        "verdict": "rejected", "reasons": reasons}
    manifest_reference = None
    snapshot = None
    try:
        records.publish("child/" + descriptor["context_file"], control.canonical(context))
        environment = dict(os.environ)
        environment[descriptor["harness_output_dir_env"]] = str(run / "child")
        argv = [str(executable)] + [
            argument.replace(OUTPUT_PLACEHOLDER, str(run / "child")) for argument in command[1:]]
        with observer.ExecutableImage(executable, executable_sha256) as image:
            try:
                # The harness is single-threaded here, and setrlimit must run
                # in the child between fork and exec to bind only that child.
                child = subprocess.Popen(
                    argv, stdin=arguments.stdin or subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                    cwd=str(repository),
                    preexec_fn=None if limit is None  # noqa: PLW1509
                    else _limit_address_space(limit))
            except subprocess.SubprocessError:
                # The only step between fork and exec is setrlimit: the
                # platform refused the limit, so nothing was started.
                reasons.append("address_space_limit_not_applied")
                child = None
            except OSError:
                reasons.append("command_not_started")
                child = None
            if child is not None:
                assert child.stdout is not None and child.stderr is not None
                streams = {"stdout": StreamDigest(child.stdout.fileno(), tail_bytes),
                           "stderr": StreamDigest(child.stderr.fileno(), tail_bytes)}
                for stream in streams.values():
                    stream.start()
                kernel_limit = kernel_address_space_limit(child.pid)
                process = observe_child(child, image, records, arguments.interval_ms,
                                        arguments.timeout_seconds * 1000)
                process["address_space"] = address_space_enforcement(limit, kernel_limit)
                report["process"] = process
                output = {name: stream.result(records, f"{name}.tail.log")
                          for name, stream in streams.items()}
                output.update(classification="measured",
                              retention="tail" if tail_bytes else "digest_only")
                report["output"] = output
                for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                    if output[name]["complete"]:
                        pipe.close()
                reasons.extend(process_reasons(process, output))
                if limit is not None and kernel_limit not in (None, (limit, limit)):
                    reasons.append("address_space_limit_differs_from_kernel")
                try:
                    image.validate()
                except ValueError:
                    reasons.append("executable_changed_during_run")
                with _EvidenceDirectory(run) as directory:
                    snapshot = _EvidenceSnapshot(directory, descriptor)
                entries, orphans, record_reasons = collect_records(
                    descriptor, run, context, process, requirements, snapshot=snapshot)
                report["records"], report["orphans"] = entries, orphans
                reasons.extend(record_reasons)
        if not reasons:
            report["verdict"] = "accepted"
    except Exception as error:  # noqa: BLE001 - the failed run must still be retained
        reasons.append("harness_failure:" + type(error).__name__)
    finally:
        try:
            records.publish("report.json", control.canonical(report))
            manifest_reference = write_manifest(run, records, context, report["verdict"],
                                                snapshot=snapshot)
        except Exception as error:  # noqa: BLE001
            with open(run / "harness_failure.json", "xb") as stream:
                stream.write(control.canonical(
                    {"schema": FAILURE_SCHEMA, "reason": type(error).__name__}))
            report["verdict"] = "rejected"
        records.close()
    print(json.dumps({
        "run_directory": str(run), "verdict": report["verdict"], "reasons": reasons,
        "manifest_sha256": None if manifest_reference is None else manifest_reference["sha256"],
    }, sort_keys=True))
    return 0 if report["verdict"] == "accepted" else 1


# --------------------------------------------------------------------------
# Validating views and salvaging earlier evidence.
# --------------------------------------------------------------------------

def validate_files(arguments: argparse.Namespace) -> int:
    """Judge JSON views on their own; print one line of findings per file."""
    descriptor = load_descriptor()
    rejected = False
    for name in arguments.records:
        largest = None
        try:
            record = decode_record(descriptor, strict_json(Path(name).read_bytes()))
            findings = record_findings(descriptor, record)
            if unclassified_numbers(descriptor, record):
                findings.append("unclassified_number")
            largest = largest_undivided_phase(descriptor, record)
        except RecordDecodeError as error:
            findings = [f"decode_error:{error.path}"]
        except OSError:
            findings = ["unreadable"]
        rejected = rejected or bool(findings)
        print(json.dumps({"record": name, "findings": findings,
                          "largest_undivided_phase": largest}, sort_keys=True))
    return 1 if rejected else 0


REPORT_KEYS = frozenset({"schema", "context", "command", "limits", "requirements", "host",
                         "process", "output", "records", "orphans", "verdict", "reasons"})


def _evidence_reasons(snapshot: _EvidenceSnapshot, manifest: dict[str, Any],
                      descriptor: dict[str, Any]) -> list[str] | None:
    """Compare the externally bound file set to the same bytes used for decoding."""
    reasons = list(snapshot.reasons)
    listed = set()
    if len(manifest["files"]) > MAX_EVIDENCE_FILES:
        return None
    for index, row in enumerate(manifest["files"]):
        if (type(row) is not dict or set(row) != {"path", "sha256", "bytes"}
                or type(row["path"]) is not str or row["path"] in listed
                or row["path"] == "manifest.json"
                or _evidence_kind(row["path"], descriptor["context_file"]) is None
                or not _is_hex(row["sha256"], (64,))
                or not _unsigned(row["bytes"], MAX_EVIDENCE_BYTES)):
            return None
        listed.add(row["path"])
        actual = snapshot.bindings.get(row["path"])
        if actual is None:
            reasons.append(f"evidence_missing:{index}")
        elif actual != row:
            reasons.append(f"evidence_changed:{index}")
    for index, path in enumerate(sorted(snapshot.bindings)):
        if path not in listed:
            reasons.append(f"evidence_added:{index}")
    return reasons


def _requirement_observations_match(report: dict[str, Any], requirements: dict[str, Any]) -> bool:
    limit = requirements["address_space_limit_bytes"]
    limits = report["limits"]
    if (type(limits) is not dict
            or set(limits) != {"classification", "timeout_ms", "sampling_interval_ms",
                               "requested_address_space_bytes", "output_tail_bytes"}
            or limits["classification"] != "local_scheduling"
            or not _unsigned(limits["timeout_ms"], 7 * 24 * 3600 * 1000)
            or limits["timeout_ms"] < 1000
            or not _unsigned(limits["sampling_interval_ms"], 1000)
            or limits["sampling_interval_ms"] < 10
            or not _unsigned(limits["output_tail_bytes"], MAX_OUTPUT_TAIL_BYTES)
            or type(limits["requested_address_space_bytes"]) is not type(limit)
            or limits["requested_address_space_bytes"] != limit):
        return False
    process = report["process"]
    if process is None:
        return True  # Rejected as unobserved independently.
    if type(process) is not dict or type(process.get("address_space")) is not dict:
        return False
    address = process["address_space"]
    expected = address_space_enforcement(limit, None)
    if set(address) != set(expected):
        return False
    if any(type(address[key]) is not type(value) or address[key] != value
           for key, value in expected.items() if key != "kernel_observed"):
        return False
    kernel = address.get("kernel_observed")
    if kernel is not None:
        if (type(kernel) is not dict or set(kernel) != {"soft_limit_bytes", "hard_limit_bytes"}
                or any(value is not None and not _unsigned(value, MAX_U64)
                       for value in kernel.values())):
            return False
        if limit is not None and any(value != limit for value in kernel.values()):
            return False
    return True


def _derived_reasons(descriptor: dict[str, Any], run: Path, report: dict[str, Any],
                     scope: dict[str, Any], snapshot: _EvidenceSnapshot,
                     consumer: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Reproduce the original experiment before checking the separate consumer contract."""
    process, output, requirements = report["process"], report["output"], report["requirements"]
    if type(process) is not dict or type(output) is not dict:
        return ["run_was_rejected"], {}
    reasons: list[str] = []
    try:
        derived = process_reasons(process, output)
        entries, orphans, record_reasons, decoded = judge_records(
            descriptor, run, report["context"], process, requirements, snapshot=snapshot)
    except (KeyError, TypeError, ValueError, OSError):
        return ["report_malformed"], {}
    derived += record_reasons
    stated = report["reasons"]
    reproducible = [reason for reason in stated if not reason.startswith(RUNTIME_ONLY_REASONS)]
    if derived != reproducible:
        reasons.append("reasons_not_reproducible")
    if entries != report["records"] or orphans != report["orphans"]:
        reasons.append("records_not_reproducible")
    verdict = "rejected" if derived or stated else "accepted"
    if verdict != report["verdict"]:
        reasons.append("report_verdict_differs_from_evidence")
    if verdict != "accepted":
        reasons.append("run_was_rejected")
    for index, record in enumerate(decoded):
        for key in sorted(scope):
            if key != "schema" and record["identity"].get(key) != scope[key]:
                reasons.append(f"record_scope_differs:{index}:{key}")
    reasons += _consumer_reasons(requirements, consumer)
    # Even an established original requirement must be supported by the retained
    # observations. Reuse the same captured bytes, never reopen record paths.
    if consumer != requirements:
        _, _, consumer_rejections, _ = judge_records(
            descriptor, run, report["context"], process, consumer, snapshot=snapshot)
        reasons += ["consumer_evidence_rejected:" + reason for reason in consumer_rejections]
    documents = {entry["json"]["path"]: record
                 for entry, record in zip((entry for entry in entries if entry["decoded"]), decoded)}
    return reasons, documents


def _inspect_pinned_run(run: Path, scope: dict[str, Any], manifest_sha256: str | None,
                        consumer_requirements: dict[str, Any] | None = None,
                        consumer_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"reasons": [], "report": None, "documents": {},
                              "manifest_sha256": manifest_sha256,
                              "original_requirements": None, "consumer_requirements": None}
    reasons = result["reasons"]
    if manifest_sha256 is None:
        reasons.append("manifest_digest_required")
        return result
    if not _is_hex(manifest_sha256, (64,)):
        reasons.append("manifest_digest_invalid")
        return result
    descriptor = load_descriptor()
    try:
        with _EvidenceDirectory(run) as directory:
            binding, raw = directory._read("manifest.json", MAX_EVIDENCE_BYTES, True)
            if binding["sha256"] != manifest_sha256:
                reasons.append("manifest_digest_differs")
                return result
            manifest = strict_json(raw)
            snapshot = _EvidenceSnapshot(directory, descriptor)
    except (OSError, ValueError):
        reasons.append("manifest_or_evidence_unreadable")
        return result
    if (type(manifest) is not dict
            or set(manifest) != {"schema", "context", "verdict", "classification", "files"}
            or manifest["schema"] != MANIFEST_SCHEMA or type(manifest["files"]) is not list
            or manifest["classification"] != "measured"
            or type(manifest["verdict"]) is not str
            or manifest["verdict"] not in {"accepted", "rejected"}
            or type(manifest["context"]) is not dict):
        reasons.append("manifest_malformed")
        return result
    evidence = _evidence_reasons(snapshot, manifest, descriptor)
    if evidence is None:
        reasons.append("manifest_malformed")
        return result
    reasons += evidence
    if "report.json" not in {row["path"] for row in manifest["files"]}:
        reasons.append("report_not_bound")
        return result
    try:
        report = strict_json(snapshot.raw["report.json"])
    except (KeyError, RecordDecodeError):
        reasons.append("report_unreadable")
        return result
    if (type(report) is not dict or set(report) != REPORT_KEYS
            or report["schema"] != REPORT_SCHEMA or type(report["reasons"]) is not list
            or not all(type(reason) is str for reason in report["reasons"])):
        reasons.append("report_malformed")
        return result
    try:
        original = validate_requirements(report["requirements"])
    except HarnessRefusal:
        reasons.append("report_requirements_invalid")
        return result
    result.update(report=report, original_requirements=original)
    try:
        consumer = validate_requirements(original if consumer_requirements is None
                                         else consumer_requirements)
        if consumer_overrides is not None:
            consumer = validate_requirements(dict(consumer, **consumer_overrides))
    except HarnessRefusal:
        reasons.append("consumer_requirements_invalid")
        return result
    result["consumer_requirements"] = consumer
    if not _requirement_observations_match(report, original):
        reasons.append("report_requirement_observations_differ")
    if report["verdict"] != manifest["verdict"]:
        reasons.append("manifest_verdict_differs_from_report")
    if report["context"] != manifest["context"]:
        reasons.append("manifest_context_differs_from_report")
    if not evidence:
        derived, documents = _derived_reasons(descriptor, run, report, scope, snapshot, consumer)
        reasons += derived
        result["documents"] = documents
    for key in sorted(scope):
        if type(report["context"]) is not dict or report["context"].get(key) != scope[key]:
            reasons.append("scope_differs:" + key)
    return result


def salvage_reasons(run: Path, scope: dict[str, Any], manifest_sha256: str | None = None,
                    consumer_requirements: dict[str, Any] | None = None) -> list[str]:
    """Read-only refusal reasons under a mandatory externally retained manifest pin.

    A missing pin always refuses; there is no unsigned-success mode. The original
    report and requirements are reproduced before optional consumer constraints.
    Files that were hashed are the same held-FD bytes subsequently decoded.
    """
    return _inspect_pinned_run(run, scope, manifest_sha256, consumer_requirements)["reasons"]


def read_pinned_run(run: Path, manifest_sha256: str, *, scope: dict[str, Any] | None = None,
                    consumer_requirements: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return verified report/documents from one immutable byte snapshot, or refuse.

    Consumers must use the returned ``report`` and ``documents`` (keyed by the
    report's relative JSON paths), never reopen those paths after verification.
    The external pin binds unchanged evidence, not honest execution or proof validity.
    Omitted scope adds no new identity restriction; original context and requirements
    are still reproduced. Omitted consumer requirements retain the original contract.
    """
    result = _inspect_pinned_run(run, {} if scope is None else scope,
                                 manifest_sha256, consumer_requirements)
    if result["reasons"]:
        raise HarnessRefusal("pinned run refused: " + ",".join(result["reasons"]))
    return result


def salvage(arguments: argparse.Namespace) -> int:
    """Report unchanged acceptance under original and separately requested conditions."""
    descriptor = load_descriptor()
    repository = Path(arguments.repository).resolve()
    run = Path(arguments.run_directory)
    pinned = arguments.manifest_sha256
    if not _is_hex(pinned, (64,)):
        raise HarnessRefusal("--manifest-sha256 must be an externally retained SHA-256 digest")
    executable = resolve_executable(arguments.executable)
    scope = build_context(descriptor, repository, sha256_file(executable)[0], arguments.profile,
                          arguments.config, arguments.hardware, arguments.cache_policy)
    overrides = {key: value for key, value in {
        "address_space_limit_bytes": arguments.address_space_limit_bytes,
        "thermal_state": arguments.require_thermal_state,
        "max_undivided_phase_ppm": arguments.max_undivided_phase_ppm,
    }.items() if value is not None}
    # Validate CLI values before reading evidence, including bool-as-int helper input.
    validate_requirements(dict(classification="engineering_target", address_space_limit_bytes=None,
                               thermal_state=False, max_undivided_phase_ppm=None) | overrides)
    result = _inspect_pinned_run(run, scope, pinned, consumer_overrides=overrides)
    print(json.dumps({"run_directory": str(run), "salvageable": not result["reasons"],
                      "reasons": result["reasons"], "manifest_binding": "external_sha256",
                      "original_requirements": result["original_requirements"],
                      "consumer_requirements": result["consumer_requirements"]}, sort_keys=True))
    return 1 if result["reasons"] else 0


def parser() -> argparse.ArgumentParser:
    """Command-line interface."""
    top = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        epilog="Measurements never affect validity; this tool reports and gates nothing.")
    commands = top.add_subparsers(dest="action", required=True)

    def scope(command: argparse.ArgumentParser) -> None:
        command.add_argument("--repository", default=str(REPOSITORY),
                             help="source checkout whose commit and dirty digest are recorded")
        command.add_argument("--hardware", required=True,
                             help="name of the reference hardware record, asserted by the "
                                  "operator; observed host facts are recorded beside it")
        command.add_argument("--profile", required=True,
                             help="semantic and build profile identity, asserted by the operator")
        command.add_argument("--config", required=True,
                             help="configuration identity, asserted by the operator")
        command.add_argument("--cache-policy", required=True, choices=("cold", "warm"),
                             help="whether caches of this workload were populated, asserted "
                                  "by the operator; the harness neither clears nor checks them")

    run = commands.add_parser("run", help="run a command and judge its records")
    scope(run)
    run.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT),
                     help="untracked directory that receives one new run directory")
    run.add_argument("--interval-ms", type=int, default=100,
                     help="process sampling interval (10 to 1000)")
    run.add_argument("--timeout-seconds", type=int, default=7200,
                     help="kill the command and reject the run after this long")
    run.add_argument("--address-space-limit-bytes", type=int, default=None,
                     help="enforce RLIMIT_AS on the command; the run is rejected when the "
                          "platform cannot apply it or a record observed another limit")
    run.add_argument("--retain-output-tail-bytes", type=int, default=0,
                     help="store this many final bytes of stdout and stderr (at most "
                          f"{MAX_OUTPUT_TAIL_BYTES}); by default only their length and "
                          "SHA-256 are kept. UNSAFE for a workload that handles private "
                          "data: a panic prints witness-dependent values")
    run.add_argument("--record-arguments", action="store_true",
                     help="store the argument vector verbatim instead of its digest; "
                          "the arguments must be public")
    run.add_argument("--require-thermal-state", action="store_true",
                     help="reject a record whose thermal state is unavailable; use it for "
                          "device runs, where thermal state applies")
    run.add_argument("--max-undivided-phase-ppm", type=int, default=None,
                     help="reject a record whose largest undivided phase holds more than "
                          "this share of the root, in parts per million; states the "
                          "attribution granularity a consumer needs")
    run.add_argument("command", nargs=argparse.REMAINDER,
                     help="-- executable [arguments]; {output_dir} in an argument is "
                          "replaced by the record directory")
    run.set_defaults(handler=run_command, stdin=None)

    validate = commands.add_parser("validate", help="judge record JSON views")
    validate.add_argument("records", nargs="+", help="record JSON view files")
    validate.set_defaults(handler=validate_files)

    keep = commands.add_parser("salvage",
                               help="check that an earlier run is unchanged scoped evidence")
    scope(keep)
    keep.add_argument("--executable", required=True,
                      help="the executable whose current digest is the artifact scope")
    keep.add_argument("--manifest-sha256", required=True,
                      help="SHA-256 of manifest.json that the operator retained or signed "
                           "when the run was made; required for every salvage claim")
    keep.add_argument("--address-space-limit-bytes", type=int, default=None,
                      help="require the exact originally applied address-space experiment")
    keep.add_argument("--require-thermal-state", action="store_true", default=None,
                      help="require that the original run required and observed thermal state")
    keep.add_argument("--max-undivided-phase-ppm", type=int, default=None,
                      help="require an original granularity bound no weaker than this one")
    keep.add_argument("run_directory", help="an earlier run directory")
    keep.set_defaults(handler=salvage)
    return top


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    arguments = parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except HarnessRefusal as refusal:
        print(json.dumps({"refused": str(refusal)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
