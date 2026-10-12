#!/usr/bin/env python3
"""Check structural consistency of the ZK delivery graph and Markdown plan.

Requires Python 3.10+ and its standard library; it uses no environment variables,
installed packages or subprocesses. Defaults read specs/zk_delivery_graph.json,
specs/zk_delivery_plan.md and specs/zk_delivery_reconciliation.json relative to
this script's repository. Archived source files need not be present. This read-only
check never changes files and does not establish code or cryptographic readiness.
A validation run exits with status 0 only when every check passes and writing the
report did not fail; a closed pipe or failed device is exit status 1 without a
traceback, for the report and for --help alike.

The plan holds one table row per task and delivery and one `### <ID> <title>`
contract per task, each equal to the graph. No other heading, wholly emphasized
line or first table cell may name an ID, whatever block quote, list marker,
emphasis or code mark decorates it. The roots sentence and both count statements
are stated once, word for word, where a line break is the only tolerated spacing
difference; the same words in another letter case, spacing or emphasis are a second
statement. The plan is read as lines of text. Left to review, because they are not
interpreted: HTML other than a one-line h1-h6 heading, comments, code fences, a
title that spans lines, a table row without a pipe and a restatement in other words.

Task `status` is `planned`, `in_progress` or `implemented`. A non-planned task
records `evidence` with four fields:
  source      text containing the observed 40-hex commit id;
  paths       repository files outside ignored build and archive trees (dist,
              target, .git, __pycache__, node_modules, build), each a regular file
              that resolves inside --root; Git tracking is not examined here;
  commands    [{command, outcome}] with outcome `passed`, `failed` or `not_run`;
  acceptance  [{clause, state, proof}] with state `met`, `partial` or `unmet`.
A clause is exactly one whole sentence of the task's outputs or acceptance text,
recorded once. A proof cites at least one recorded path or command verbatim.
A command entry may add `platform_todo` for execution that needs a platform the
development Mac lacks: {platform, reason, todo_site: {path, marker}, owner}, with
platform `windows`, `linux`, `physical_x86_64` or `cuda` and owner `H.3` or `V.4`.
The path is one of `paths`; the marker contains `TODO:` and occurs exactly once in
that file. Any other key is an error. A platform TODO is open until its command is
`passed`. `in_progress` records any nonempty subset of sentences. `implemented`
requires an entry for every sentence, every prerequisite implemented, every recorded
path and command cited by a proof, no command `failed` and every command without a
`platform_todo` `passed`; each sentence is `met`, or `partial` with a proof that
cites an open platform TODO command verbatim. Neither H.3 nor V.4 is `implemented`
while a platform TODO is open anywhere in the graph. Both formats report
`open_platform_todos` for every task, their total with each originating command
counted once, and every open item; an open TODO is never a passed check. Recorded
status is traceability; it grants no runtime permission and qualifies no cryptography.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPE = "Structural consistency only; not code or cryptographic qualification."
IDENTIFIER = re.compile(r"[A-Z][A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
SUPPORTED_SDKS = ["Rust", "Kotlin/Java/Android", "Swift", "JavaScript", "Python", "C#"]
NON_GATING_TASKS = {"H.3", "V.4", "V.6"}
TASK_STATUSES = ("planned", "in_progress", "implemented")
COMMAND_OUTCOMES = ("passed", "failed", "not_run")
CLAUSE_STATES = ("met", "partial", "unmet")
# A command entry, and the deferred platform execution that it may carry.
EVIDENCE_FIELDS = ("source", "paths", "commands", "acceptance")
ACCEPTANCE_FIELDS = ("clause", "state", "proof")
COMMAND_FIELDS = ("command", "outcome", "platform_todo")
PLATFORM_TODO_FIELDS = ("platform", "reason", "todo_site", "owner")
PLATFORM_TODO_SITE_FIELDS = ("path", "marker")
PLATFORM_TODO_PLATFORMS = ("windows", "linux", "physical_x86_64", "cuda")
PLATFORM_TODO_OWNERS = ("H.3", "V.4")
PLATFORM_TODO_LITERAL = "TODO:"
# Under `implemented` only a deferred platform check may be unexecuted; nothing may have failed.
IMPLEMENTED_OUTCOMES = ("passed",)
IMPLEMENTED_DEFERRED_OUTCOMES = ("passed", "not_run")
LEDGER_DISPOSITIONS = {
    "requirements": ("retained", "corrected"),
    "findings": ("addressed_in_plan", "addressed_with_correction"),
    "prior_findings": ("carried_forward", "superseded_by_user_direction"),
}
FINDING_SEVERITIES = ("blocker", "major", "minor")
# Ignored build and archive trees cannot carry evidence: validation must not need them.
IGNORED_EVIDENCE_COMPONENTS = frozenset(("dist", "target", ".git", "__pycache__", "node_modules", "build"))
SOURCE_REQUIREMENT_IDS = {f"REQ-{index:03d}" for index in range(1, 120)}
# Markdown that may precede a title or table row: indentation, block quotes and list markers.
PLAN_DECORATION = re.compile(r"(?:[ \t>]|[-*+][ \t]|\d+[.)][ \t])*")
# A line that renders as a title: an ATX or HTML heading or a wholly emphasized line.
PLAN_TITLE = re.compile(r"#|<[hH][1-6]\b|[*_].*[*_][ \t]*\Z")
PLAN_UNDERLINE = re.compile(r"(?:=+|-+)[ \t]*\Z")
# The first ID that a title or first table cell names, through emphasis, code or link marks.
# An ID starts its word, so that one long line is scanned once rather than from every character.
NAMED_ID = re.compile(r"(?<![A-Za-z0-9_-])_*([A-Z][A-Za-z0-9_-]*\.[A-Za-z0-9_-]+)")
# A pipe that divides table cells; an escaped pipe is cell text.
PLAN_CELL_BREAK = re.compile(r"(?<!\\)\|")
# The words that open the roots statement, and the two count statements with `{}` for each number.
PLAN_ROOTS = "Start in parallel at"
PLAN_GRAPH_COUNTS = "contains {} implementation/evidence tasks and {} named deliveries"
PLAN_LEDGER_COUNTS = (
    "preserves {} verbatim revision-6 requirement units, all {} revision-6 findings, "
    "all {} earlier report IDs and all {} original graph tasks"
)


def printable(text: str) -> str:
    """Escape lone surrogates so that both output formats can always render the text."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def load_json(path: Path) -> Any:
    """Parse one JSON input, rejecting duplicate object keys and non-finite numbers."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    def reject_constant(name: str) -> Any:
        raise ValueError(f"non-finite JSON number {name}")

    def finite(literal: str) -> float:
        # An overflowing literal such as 1e999 parses to infinity without reaching parse_constant.
        value = float(literal)
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number {literal}")
        return value

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object, parse_constant=reject_constant, parse_float=finite,
    )


def reconciliation_inventory_sha256(ledger: dict[str, Any]) -> str:
    """Hash embedded source evidence, independently of the new plan's mappings."""
    fields = {
        "sources": ("id", "path", "sha256"),
        "requirements": ("id", "source", "original_text"),
        "findings": ("id", "source", "original_text"),
        "prior_findings": ("id", "source", "original_record"),
        "original_tasks": ("id", "original_record"),
    }
    snapshot = {
        section: sorted(
            ({field: record[field] for field in names} for record in ledger[section]),
            key=lambda record: record["id"],
        )
        for section, names in fields.items()
    }
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def check_reconciliation(
    ledger: Any, baseline: Any, task_ids: set[str]
) -> list[str]:
    """Validate complete embedded source inventories and their current task maps.

    The ledger's own `revision` names the reconstruction it was extracted for; it is
    provenance and is not compared with the graph revision.
    """
    errors: list[str] = []
    if not isinstance(ledger, dict):
        return ["reconciliation must be an object"]
    if type(ledger.get("schema_version")) is not int or ledger["schema_version"] != 1:
        errors.append("reconciliation.schema_version must be 1")
    if not isinstance(baseline, dict):
        return errors + ["reconciliation_baseline must be an object"]
    for key in ("requirement_ids", "original_task_ids"):
        value = baseline.get(key)
        if (
            not isinstance(value, list) or not value
            or any(not isinstance(item, str) or not item.strip() for item in value)
            or len(set(value)) != len(value)
        ):
            errors.append(f"reconciliation_baseline.{key} must be unique nonempty IDs")
    fingerprint = baseline.get("ledger_inventory_sha256")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        errors.append("reconciliation_baseline.ledger_inventory_sha256 must be a SHA256 digest")
    if errors:
        return errors
    if set(baseline["requirement_ids"]) != SOURCE_REQUIREMENT_IDS:
        errors.append("reconciliation_baseline.requirement_ids must preserve REQ-001 through REQ-119")
    if len(baseline["original_task_ids"]) != 52:
        errors.append("reconciliation_baseline.original_task_ids must preserve all 52 original tasks")

    sections: dict[str, dict[str, dict[str, Any]]] = {}
    for name in ("sources", "requirements", "findings", "prior_findings", "original_tasks"):
        records = ledger.get(name)
        sections[name] = {}
        if not isinstance(records, list) or not records:
            errors.append(f"reconciliation.{name} must be a nonempty list")
            continue
        for record in records:
            if not isinstance(record, dict):
                errors.append(f"reconciliation.{name} records must be objects")
                continue
            identifier = record.get("id")
            if not isinstance(identifier, str) or not identifier.strip():
                errors.append(f"reconciliation.{name} IDs must be nonempty strings")
                continue
            if identifier in sections[name]:
                errors.append(f"duplicate reconciliation.{name} ID {identifier}")
                continue
            sections[name][identifier] = record
    expected = {
        "requirements": SOURCE_REQUIREMENT_IDS,
        "original_tasks": set(baseline["original_task_ids"]),
        "findings": {f"R6-{index}" for index in range(23)},
        "prior_findings": {f"F{index}" for index in range(133)},
    }
    for name, identifiers in expected.items():
        actual = set(sections[name])
        if actual != identifiers:
            missing = ", ".join(sorted(identifiers - actual)) or "none"
            unexpected = ", ".join(sorted(actual - identifiers)) or "none"
            errors.append(f"reconciliation.{name} inventory differs: missing {missing}; unexpected {unexpected}")

    for identifier, source in sections["sources"].items():
        if not isinstance(source.get("path"), str) or not source["path"].strip():
            errors.append(f"source {identifier}.path must be nonempty")
        digest = source.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            errors.append(f"source {identifier}.sha256 must be a SHA256 digest")
        if source.get("available_optional") is not True:
            errors.append(f"source {identifier}.available_optional must be true")

    for name in ("requirements", "findings", "prior_findings", "original_tasks"):
        for identifier, record in sections[name].items():
            mapping = record.get("task_ids")
            if not isinstance(mapping, list) or not mapping or any(
                not isinstance(item, str) or item not in task_ids for item in mapping
            ):
                errors.append(f"{identifier}.task_ids must map to existing tasks")
            elif len(mapping) != len(set(mapping)):
                errors.append(f"{identifier}.task_ids contains duplicates")
            rationale = record.get("rationale")
            if not isinstance(rationale, str) or len(rationale.strip()) < 20:
                errors.append(f"{identifier}.rationale must explain the mapping (at least 20 characters)")
            if name in LEDGER_DISPOSITIONS and record.get("disposition") not in LEDGER_DISPOSITIONS[name]:
                errors.append(f"{identifier}.disposition is not a supported source disposition")
            if name in ("requirements", "findings"):
                for key in (("original_text", "summary") if name == "requirements" else ("original_text", "title")):
                    if not isinstance(record.get(key), str) or not record[key].strip():
                        errors.append(f"{identifier}.{key} must be nonempty")
            if name == "findings" and record.get("severity") not in FINDING_SEVERITIES:
                errors.append(f"{identifier}.severity must be blocker, major or minor")
            if name in ("prior_findings", "original_tasks"):
                if not isinstance(record.get("original_record"), dict) or not record["original_record"]:
                    errors.append(f"{identifier}.original_record must preserve the original object")
                elif name == "prior_findings":
                    original = record["original_record"]
                    if not isinstance(original.get("triage"), dict) or not original["triage"]:
                        errors.append(f"{identifier}.original_record.triage must preserve the original object")
                    if not isinstance(original.get("original_report_text"), str) or not original["original_report_text"].strip():
                        errors.append(f"{identifier}.original_record.original_report_text must be nonempty")
            if name == "original_tasks":
                original = record.get("original_record")
                if isinstance(original, dict) and original.get("id") != identifier:
                    errors.append(f"{identifier}.original_record.id differs from the original task ID")
                continue
            reference = record.get("source")
            if not isinstance(reference, dict):
                errors.append(f"{identifier}.source must identify original source lines")
                continue
            source_id = reference.get("source_id")
            source = sections["sources"].get(source_id) if isinstance(source_id, str) else None
            if source is None or reference.get("path") != source.get("path"):
                errors.append(f"{identifier}.source must reference a declared source and its exact path")
            start, end = reference.get("line_start"), reference.get("line_end")
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                errors.append(f"{identifier}.source must contain a positive ordered line span")

    prior = [record.get("disposition") for record in sections["prior_findings"].values()]
    recorded = {
        "requirements": len(sections["requirements"]),
        "r6_findings": len(sections["findings"]),
        "prior_findings": len(sections["prior_findings"]),
        "original_tasks": len(sections["original_tasks"]),
        "prior_carried_forward": sum(item == "carried_forward" for item in prior),
        "prior_superseded_by_user_direction": sum(item == "superseded_by_user_direction" for item in prior),
    }
    counts = ledger.get("counts")
    if not isinstance(counts, dict) or set(counts) != set(recorded) or any(
        type(counts[key]) is not int or counts[key] != value for key, value in recorded.items()
    ):
        stated = ", ".join(f"{key} {value}" for key, value in recorded.items())
        errors.append(f"reconciliation.counts must equal the recorded inventories: {stated}")
    if errors:
        return errors
    try:
        actual_fingerprint = reconciliation_inventory_sha256(ledger)
    except (RecursionError, UnicodeError):
        return ["reconciliation source inventory cannot be hashed: text is not valid Unicode or nesting is too deep"]
    if actual_fingerprint != fingerprint:
        errors.append("reconciliation source inventory fingerprint differs from the graph baseline")
    return errors


def task_sentences(record: dict[str, Any]) -> list[str]:
    """Return the distinct whole sentences of a task's outputs and acceptance, in order."""
    sentences: list[str] = []
    for field in ("outputs", "acceptance"):
        texts = record.get(field)
        for text in texts if isinstance(texts, list) else []:
            for sentence in SENTENCE_BOUNDARY.split(text) if isinstance(text, str) else []:
                sentence = sentence.strip()
                if sentence and sentence not in sentences:
                    sentences.append(sentence)
    return sentences


def named_exactly(root: Path, parts: list[str]) -> bool:
    """Whether each component is a directory entry by its exact name, on any volume."""
    directory = root
    for part in parts:
        if part not in os.listdir(directory):
            return False
        directory = directory / part
    return True


def check_evidence_paths(identifier: str, paths: list[str], root: Path | None) -> list[str]:
    """Admit only distinct repository files outside ignored build and archive trees."""
    errors: list[str] = []
    recorded: set[str] = set()
    locations: set[Path] = set()
    for path in paths:
        parts = path.split("/")
        if (
            not path.isprintable() or path != path.strip() or "\\" in path
            or any(part in ("", ".", "..") or part.casefold() in IGNORED_EVIDENCE_COMPONENTS for part in parts)
        ):
            errors.append(
                f"{identifier}.evidence.paths must be repository files outside ignored build and archive trees: {path}"
            )
            continue
        if path.casefold() in recorded:
            errors.append(f"{identifier}.evidence.paths repeats a path: {path}")
            continue
        recorded.add(path.casefold())
        if root is None:
            continue
        try:
            base = root.resolve()
            candidate = root.joinpath(*parts)
            if not candidate.exists() or not named_exactly(root, parts):
                errors.append(f"{identifier}.evidence path does not exist: {path}")
                continue
            if not candidate.is_file():
                errors.append(f"{identifier}.evidence path is not a regular file: {path}")
                continue
            # Symbolic links must not lead out of the repository or into an ignored tree.
            location = candidate.resolve()
            if not location.is_relative_to(base) or any(
                part.casefold() in IGNORED_EVIDENCE_COMPONENTS for part in location.relative_to(base).parts
            ):
                errors.append(
                    f"{identifier}.evidence path resolves outside the repository or into an ignored tree: {path}"
                )
            elif location in locations:
                errors.append(f"{identifier}.evidence.paths repeats a file: {path}")
            locations.add(location)
        except (OSError, RuntimeError):
            errors.append(f"{identifier}.evidence path cannot be examined: {path}")
    return errors


def unknown_fields(label: str, record: dict[Any, Any], fields: tuple[str, ...]) -> list[str]:
    """Report each key outside the admitted fields, in recorded order."""
    return [f"{label} has an unknown field: {key}" for key in record if key not in fields]


def open_platform_todo(entry: dict[str, Any]) -> bool:
    """Whether a valid command entry defers platform execution that has not passed."""
    return "platform_todo" in entry and entry["outcome"] != "passed"


def check_platform_todo(label: str, todo: Any, paths: list[str] | None, root: Path | None) -> list[str]:
    """Validate the deferred platform execution that one command entry carries.

    `paths` is the task's recorded path list, or None when that list is malformed.
    `root` is given only when every recorded path was admitted, so that a marker is
    looked for in admitted repository files alone.
    """
    if not isinstance(todo, dict):
        return [f"{label} must be an object with platform, reason, todo_site and owner"]
    errors = unknown_fields(label, todo, PLATFORM_TODO_FIELDS)
    if todo.get("platform") not in PLATFORM_TODO_PLATFORMS:
        errors.append(f"{label}.platform must be windows, linux, physical_x86_64 or cuda")
    reason = todo.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append(f"{label}.reason must be a nonempty string")
    site = todo.get("todo_site")
    if not isinstance(site, dict):
        errors.append(f"{label}.todo_site must be an object with path and marker")
    else:
        errors.extend(unknown_fields(f"{label}.todo_site", site, PLATFORM_TODO_SITE_FIELDS))
        path, marker = site.get("path"), site.get("marker")
        listed = paths is None or path in paths
        if not listed:
            errors.append(f"{label}.todo_site.path must be one of the task's evidence.paths")
        marked = isinstance(marker, str) and PLATFORM_TODO_LITERAL in marker
        if not marked:
            errors.append(f"{label}.todo_site.marker must be text containing the literal TODO:")
        if root is not None and listed and marked:
            # Every occurrence counts, overlapping ones included; the file is read as bytes.
            sought = b"(?=" + re.escape(marker.encode("utf-8", "surrogatepass")) + b")"
            try:
                found = len(re.findall(sought, root.joinpath(*path.split("/")).read_bytes()))
            except OSError:
                errors.append(f"{label}.todo_site cannot be examined: {path}")
            else:
                if found != 1:
                    errors.append(f"{label}.todo_site.marker must occur exactly once in {path}: found {found}")
    if todo.get("owner") not in PLATFORM_TODO_OWNERS:
        errors.append(f"{label}.owner must be H.3 or V.4")
    return errors


def check_evidence(identifier: str, record: dict[str, Any], root: Path | None) -> list[str]:
    """Validate the evidence a non-planned task records for its status."""
    errors: list[str] = []
    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        return [f"{identifier}.evidence must record source, paths, commands and acceptance for a non-planned status"]
    implemented = record.get("status") == "implemented"
    # A record placed at the wrong level, such as a platform_todo beside the commands, is never silently ignored.
    errors.extend(unknown_fields(f"{identifier}.evidence", evidence, EVIDENCE_FIELDS))
    source = evidence.get("source")
    if not isinstance(source, str) or not COMMIT_ID.search(source):
        errors.append(f"{identifier}.evidence.source must contain the observed 40-hex commit id")

    citable: list[str] | None = []
    recorded: list[str] | None = None
    site_root: Path | None = None
    paths = evidence.get("paths")
    if not isinstance(paths, list) or not paths or any(not isinstance(path, str) for path in paths):
        errors.append(f"{identifier}.evidence.paths must be a nonempty list of path strings")
        citable = None
    else:
        refused = check_evidence_paths(identifier, paths, root)
        errors.extend(refused)
        citable.extend(paths)
        # A TODO marker is looked for only where every recorded path was admitted.
        recorded, site_root = paths, None if refused else root

    # The commands whose platform TODO is open; a partial clause may rest on these alone.
    deferred: list[str] = []
    commands = evidence.get("commands")
    if not isinstance(commands, list) or not commands or any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("command"), str) or not entry["command"].strip()
        or not isinstance(entry.get("outcome"), str) or entry["outcome"] not in COMMAND_OUTCOMES
        for entry in commands
    ):
        errors.append(f"{identifier}.evidence.commands must record each command with outcome passed, failed or not_run")
        citable = None
    else:
        for index, entry in enumerate(commands):
            label = f"{identifier}.evidence.commands[{index}]"
            errors.extend(unknown_fields(label, entry, COMMAND_FIELDS))
            if "platform_todo" in entry:
                errors.extend(check_platform_todo(f"{label}.platform_todo", entry["platform_todo"], recorded, site_root))
        deferred = [entry["command"] for entry in commands if open_platform_todo(entry)]
        if implemented:
            unadmitted = [
                entry["command"] for entry in commands
                if entry["outcome"] not in (IMPLEMENTED_DEFERRED_OUTCOMES if "platform_todo" in entry else IMPLEMENTED_OUTCOMES)
            ]
            if unadmitted:
                errors.append(f"{identifier} cannot be implemented with a failed or unexecuted check: {unadmitted[0]}")
        if citable is not None:
            citable.extend(entry["command"] for entry in commands)

    clauses = evidence.get("acceptance")
    if not isinstance(clauses, list) or not clauses or any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("clause"), str) or not entry["clause"].strip()
        or not isinstance(entry.get("state"), str) or entry["state"] not in CLAUSE_STATES
        or not isinstance(entry.get("proof"), str) or not entry["proof"].strip()
        for entry in clauses
    ):
        errors.append(f"{identifier}.evidence.acceptance must record each clause with state met, partial or unmet and its proof")
        return errors
    sentences = task_sentences(record)
    quoted: set[str] = set()
    cited: set[str] = set()
    for index, entry in enumerate(clauses):
        errors.extend(unknown_fields(f"{identifier}.evidence.acceptance[{index}]", entry, ACCEPTANCE_FIELDS))
        clause = entry["clause"].strip()
        if clause in quoted:
            errors.append(f"{identifier}.evidence.acceptance repeats a clause: {clause[:60]}")
            continue
        quoted.add(clause)
        if clause not in sentences:
            errors.append(f"{identifier}.evidence.acceptance clause is not one whole sentence of the task: {clause[:60]}")
        # A clause may stay partial only where its proof cites an open platform TODO command.
        if implemented and entry["state"] != "met" and not (
            entry["state"] == "partial" and any(command in entry["proof"] for command in deferred)
        ):
            errors.append(f"{identifier} cannot be implemented with a clause that is {entry['state']}: {clause[:60]}")
        if citable is not None:
            references = [item for item in citable if item in entry["proof"]]
            if not references:
                errors.append(f"{identifier}.evidence.acceptance proof must cite a recorded path or command: {clause[:60]}")
            cited.update(references)
    if implemented:
        for sentence in sentences:
            if sentence not in quoted:
                errors.append(f"{identifier} cannot be implemented without evidence for: {sentence[:60]}")
        for item in citable or []:
            if item not in cited:
                errors.append(f"{identifier} cannot be implemented with evidence that no proof cites: {item}")
    return errors


def empty_report() -> dict[str, Any]:
    """Return the failing report that validation fills; both formats render this one shape."""
    return {
        "ok": False,
        "scope": SCOPE,
        "errors": [],
        "task_count": 0,
        "delivery_count": 0,
        "roots": [],
        "status_counts": {status: 0 for status in TASK_STATUSES},
        "progress": [],
        "complete_deliveries": [],
        "open_platform_todos": {},
        "open_platform_todo_total": 0,
        "open_platform_todo_items": [],
    }


def check_plan(graph: Any, plan: str, reconciliation: Any, root: Path | None = None) -> dict[str, Any]:
    """Return one format-independent report for the graph and plan.

    `root` is the repository that evidence paths are resolved against; without it
    the file system is not examined.
    """
    report = empty_report()
    errors: list[str] = report["errors"]
    try:
        validate(graph, plan, reconciliation, root, report)
    except RecursionError:
        errors.append("validation stopped: an input is nested too deeply")
    except (OSError, UnicodeError) as error:
        errors.append(f"validation stopped: {error}")
    errors[:] = [printable(error) for error in errors]
    return report


def validate(graph: Any, plan: str, reconciliation: Any, root: Path | None, report: dict[str, Any]) -> None:
    """Fill `report`; only the last statement, reached when every check has run, can mark it ok."""
    errors: list[str] = report["errors"]
    if not isinstance(graph, dict):
        errors.append("graph must be an object")
        return
    if type(graph.get("schema_version")) is not int or graph["schema_version"] != 1:
        errors.append("schema_version must be 1")
    if not isinstance(graph.get("source_commit"), str) or not graph["source_commit"].strip():
        errors.append("source_commit must be a nonempty string")
    if graph.get("source_plan_available") is not True:
        errors.append("source_plan_available must be true for the reconciled source plan")
    if type(graph.get("revision")) is not int or graph["revision"] != 8:
        errors.append("revision must be 8")
    if graph.get("status") != "ready_for_development":
        errors.append("graph status must be ready_for_development")

    def string_list(value: Any, label: str, *, nonempty: bool = False) -> bool:
        valid = isinstance(value, list) and all(
            isinstance(item, str) and bool(item.strip()) for item in value
        )
        if not valid or (nonempty and not value):
            errors.append(f"{label} must be {'a nonempty' if nonempty else 'a'} list of nonempty strings")
            return False
        return True

    nodes: dict[str, dict[str, Any]] = {}
    task_ids: set[str] = set()
    delivery_ids: set[str] = set()
    for kind, ids in (("tasks", task_ids), ("deliveries", delivery_ids)):
        records = graph.get(kind)
        if not isinstance(records, list) or not records:
            errors.append(f"{kind} must be a nonempty list")
            continue
        for index, record in enumerate(records):
            label = f"{kind}[{index}]"
            if not isinstance(record, dict):
                errors.append(f"{label} must be an object")
                continue
            identifier = record.get("id")
            if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
                errors.append(f"{label}.id must be a dotted identifier such as W.1")
                continue
            if identifier in nodes:
                errors.append(f"duplicate task/delivery ID: {identifier}")
                continue
            nodes[identifier] = record
            ids.add(identifier)
            for field in (("title", "owner") if kind == "tasks" else ("title",)):
                if not isinstance(record.get(field), str) or not record[field].strip():
                    errors.append(f"{identifier}.{field} must be a nonempty string")
            if string_list(record.get("requires"), f"{identifier}.requires"):
                if len(record["requires"]) != len(set(record["requires"])):
                    errors.append(f"{identifier}.requires contains duplicate edges")
                if kind == "deliveries" and not record["requires"]:
                    errors.append(f"{identifier}.requires must name at least one task or delivery")
            if kind == "tasks":
                for field in ("outputs", "acceptance"):
                    string_list(record.get(field), f"{identifier}.{field}", nonempty=True)
                status = record.get("status")
                if status not in TASK_STATUSES:
                    errors.append(f"{identifier}.status must be planned, in_progress or implemented")
                elif status == "planned":
                    if "evidence" in record:
                        errors.append(f"{identifier}.evidence is recorded only for in_progress or implemented status")
                else:
                    errors.extend(check_evidence(identifier, record, root))
            else:
                if record.get("kind") not in ("functional", "evidence"):
                    errors.append(f"{identifier}.kind must be functional or evidence")
                if record.get("kind") == "functional" and record.get("surface_contract") != "operation-v1":
                    errors.append(f"{identifier} must use the operation-v1 developer surface contract")
    report["task_count"] = len(task_ids)
    report["delivery_count"] = len(delivery_ids)
    if string_list(graph.get("required_task_ids"), "required_task_ids", nonempty=True):
        for identifier in graph["required_task_ids"]:
            if identifier not in task_ids:
                errors.append(f"required task missing from graph: {identifier}")
        if len(graph["required_task_ids"]) != len(set(graph["required_task_ids"])):
            errors.append("required_task_ids contains duplicate IDs")
    surface = graph.get("developer_surface_contract")
    if not isinstance(surface, dict):
        errors.append("developer_surface_contract must define the common operation-v1 surface")
    else:
        if surface.get("id") != "operation-v1":
            errors.append("developer_surface_contract.id must be operation-v1")
        for field in ("native_isi", "kotodama", "one_call_sdk", "prepared_form", "four_validator_restart"):
            if surface.get(field) is not True:
                errors.append(f"developer_surface_contract.{field} must be true")
        if surface.get("supported_sdks") != SUPPORTED_SDKS:
            errors.append("developer_surface_contract.supported_sdks must preserve all six canonical SDK targets")
        for field in ("atomic_semantics", "progress_semantics"):
            if not isinstance(surface.get(field), str) or not surface[field].strip():
                errors.append(f"developer_surface_contract.{field} must be nonempty")
    if string_list(graph.get("start_immediately"), "start_immediately"):
        if len(graph["start_immediately"]) != len(set(graph["start_immediately"])):
            errors.append("start_immediately contains duplicate IDs")

    constraints = graph.get("constraints")
    if not isinstance(constraints, dict):
        errors.append("constraints must be an object")
    else:
        pairs = constraints.get("required_ancestors")
        if not isinstance(pairs, list) or any(
            not isinstance(pair, list)
            or len(pair) != 2
            or any(not isinstance(item, str) or not item for item in pair)
            for pair in pairs
        ):
            errors.append("constraints.required_ancestors must contain [dependent, ancestor] pairs")
        forbidden = constraints.get("forbidden_ancestors")
        if not isinstance(forbidden, list) or any(
            not isinstance(rule, dict)
            or not isinstance(rule.get("task"), str)
            or not rule["task"]
            or not isinstance(rule.get("prefix"), str)
            or not rule["prefix"]
            or ("exact" in rule and type(rule["exact"]) is not bool)
            for rule in forbidden
        ):
            errors.append("constraints.forbidden_ancestors must contain task/prefix objects")
        if string_list(constraints.get("non_gating_tasks"), "constraints.non_gating_tasks"):
            if not NON_GATING_TASKS.issubset(set(constraints["non_gating_tasks"])):
                errors.append("non_gating_tasks must include H.3, V.4 and V.6")
        if not isinstance(constraints.get("runtime_admission_task"), str):
            errors.append("constraints.runtime_admission_task must be a task ID")
    # Schema failures must not turn into traceback exceptions during graph walks.
    if errors:
        return

    errors.extend(check_reconciliation(reconciliation, graph.get("reconciliation_baseline"), task_ids))

    for identifier, record in nodes.items():
        for dependency in record["requires"]:
            if dependency not in nodes:
                errors.append(f"{identifier} requires unknown ID {dependency}")
            elif identifier in task_ids and dependency in delivery_ids:
                errors.append(f"task {identifier} may require only tasks, not delivery {dependency}")
    for identifier in graph["start_immediately"]:
        if identifier not in task_ids:
            errors.append(f"start_immediately contains unknown task {identifier}")
    for dependent, ancestor in constraints["required_ancestors"]:
        for identifier in (dependent, ancestor):
            if identifier not in nodes:
                errors.append(f"required_ancestors contains unknown ID {identifier}")
    for rule in constraints["forbidden_ancestors"]:
        if rule["task"] not in task_ids:
            errors.append(f"forbidden_ancestors contains unknown task {rule['task']}")
    for identifier in constraints["non_gating_tasks"] + [constraints["runtime_admission_task"]]:
        if identifier not in task_ids:
            errors.append(f"admission constraints contain unknown task {identifier}")
    for identifier in sorted(task_ids):
        if nodes[identifier]["status"] != "implemented":
            continue
        pending = sorted(
            dependency for dependency in nodes[identifier]["requires"]
            if nodes.get(dependency, {}).get("status") != "implemented"
        )
        if pending:
            errors.append(f"{identifier} cannot be implemented before its prerequisites: {', '.join(pending)}")
    if errors:
        return

    # Each open platform TODO is recorded once, under the task whose command carries it.
    todos = {
        identifier: [
            {"task": identifier, "command": entry["command"], "outcome": entry["outcome"], **entry["platform_todo"]}
            for entry in nodes[identifier].get("evidence", {}).get("commands", []) if open_platform_todo(entry)
        ]
        for identifier in sorted(task_ids)
    }
    report["open_platform_todos"] = {identifier: len(items) for identifier, items in todos.items()}
    report["open_platform_todo_items"] = [item for items in todos.values() for item in items]
    report["open_platform_todo_total"] = len(report["open_platform_todo_items"])
    holders = [identifier for identifier, items in todos.items() if items]
    for identifier in PLATFORM_TODO_OWNERS:
        if holders and nodes[identifier]["status"] == "implemented":
            errors.append(f"{identifier} cannot be implemented while a platform TODO is open: {', '.join(holders)}")

    # Iterative traversal also handles malformed, very deep graphs predictably.
    ancestors: dict[str, set[str]] = {}
    for identifier in nodes:
        reachable: set[str] = set()
        pending = list(nodes[identifier]["requires"])
        while pending:
            dependency = pending.pop()
            if dependency in reachable:
                continue
            reachable.add(dependency)
            pending.extend(nodes[dependency]["requires"])
        ancestors[identifier] = reachable
        if identifier in reachable:
            errors.append(f"dependency cycle includes {identifier}")
    roots = sorted(record["id"] for record in graph["tasks"] if not record["requires"])
    report["roots"] = roots
    if set(roots) != set(graph["start_immediately"]):
        errors.append(f"start_immediately must equal task roots: {', '.join(roots) or '(none)'}")
    delivered = set().union(*(ancestors[identifier] for identifier in delivery_ids))
    for identifier in sorted(task_ids - delivered):
        errors.append(f"orphan task {identifier} reaches no delivery")
    for dependent, ancestor in constraints["required_ancestors"]:
        if ancestor not in ancestors[dependent]:
            errors.append(f"required ancestry missing: {dependent} must depend on {ancestor}")
    for rule in constraints["forbidden_ancestors"]:
        matches = sorted(
            item for item in ancestors[rule["task"]]
            if (item == rule["prefix"] if rule.get("exact", False) else item.startswith(rule["prefix"]))
        )
        if matches:
            errors.append(f"forbidden ancestry for {rule['task']}: {', '.join(matches)}")
    admission = constraints["runtime_admission_task"]
    for identifier in constraints["non_gating_tasks"]:
        if identifier == admission or identifier in ancestors[admission]:
            errors.append(f"runtime admission {admission} depends on non-gating task {identifier}")
    evidence_deliveries = {record["id"] for record in graph["deliveries"] if record["kind"] == "evidence"}
    for identifier in sorted(delivery_ids):
        if nodes[identifier]["kind"] != "functional":
            continue
        gates = ancestors[identifier] & (set(constraints["non_gating_tasks"]) | evidence_deliveries)
        if gates:
            errors.append(f"functional delivery {identifier} depends on evidence gates: {', '.join(sorted(gates))}")

    rows: dict[str, list[str]] = {}
    headings: set[str] = set()
    # Titles and rows are read through Markdown decoration, so that a second, weaker
    # contract or row cannot hide behind a block quote, list marker or emphasis.
    texts = [line[PLAN_DECORATION.match(line).end():] for line in plan.splitlines()]
    for line_number, text in enumerate(texts, 1):
        underlined = line_number < len(texts) and PLAN_UNDERLINE.match(texts[line_number])
        if PLAN_TITLE.match(text) or underlined:
            named = NAMED_ID.search(text)
            if named is None:
                continue
            identifier = named.group(1)
            if identifier in headings:
                errors.append(f"duplicate plan task contract heading for {identifier} at line {line_number}")
            elif identifier not in task_ids:
                errors.append(f"plan contains a task contract heading for unknown ID {identifier} at line {line_number}")
            headings.add(identifier)
            continue
        if "|" not in text:
            continue
        # The opening and the closing pipe of a table row are both optional in Markdown.
        cells = [cell.strip() for cell in PLAN_CELL_BREAK.split(text)]
        if text.startswith("|"):
            cells.pop(0)
        if not cells[-1]:
            cells.pop()
        named = NAMED_ID.search(cells[0]) if cells else None
        if named is None:
            continue
        identifier = named.group(1)
        if identifier in rows:
            errors.append(f"duplicate plan table row for {identifier} at line {line_number}")
        rows[identifier] = cells
        if identifier not in nodes:
            errors.append(f"plan table contains unknown ID {identifier} at line {line_number}")
    for identifier, record in nodes.items():
        expected = [identifier, record["title"]]
        if identifier in task_ids:
            expected.append(record["owner"])
        expected.append(", ".join(record["requires"]) if record["requires"] else "—")
        if identifier not in rows:
            errors.append(f"plan table is missing {identifier}")
        elif rows[identifier] != expected:
            errors.append(f"plan table differs from graph for {identifier}")
        if identifier in task_ids:
            contract = (
                f"### {identifier} {record['title']}\n\n"
                f"Deliverable: {' '.join(record['outputs'])}\n\n"
                f"Acceptance: {' '.join(record['acceptance'])}"
            )
            if not re.search(r"^" + re.escape(contract) + r"(?=\n\n|\n?\Z)", plan, re.MULTILINE):
                errors.append(f"plan task contract differs from graph for {identifier}")
    # A statement is found in any letter case and spacing, so that a second one cannot hide,
    # and is accepted only word for word, with each line break read as one space.
    prose = plan.replace("\n", " ")
    loose = " ".join(plan.casefold().split())
    statements = [(f"{PLAN_ROOTS} **{', '.join(graph['start_immediately'])}**.", re.escape(PLAN_ROOTS.casefold()))]
    for template, counts in (
        (PLAN_GRAPH_COUNTS, (len(task_ids), len(delivery_ids))),
        (PLAN_LEDGER_COUNTS, tuple(
            len(reconciliation[name]) for name in ("requirements", "findings", "prior_findings", "original_tasks")
        )),
    ):
        # Whatever stands where a number belongs, the sentence is a count statement.
        statements.append((template.format(*counts), re.escape(template.casefold()).replace(re.escape("{}"), r"\S+")))
    for stated, words in statements:
        if len(re.findall(rf"\b{words}\b", loose)) != 1 or stated not in prose:
            errors.append(f"plan prose must state once: {stated}")

    for identifier in sorted(task_ids):
        status = nodes[identifier]["status"]
        report["status_counts"][status] += 1
        if status != "planned":
            clauses = nodes[identifier]["evidence"]["acceptance"]
            met = sum(entry["state"] == "met" for entry in clauses)
            report["progress"].append(
                f"{identifier} {status}: {met} of {len(task_sentences(nodes[identifier]))} clauses met"
            )
    report["complete_deliveries"] = sorted(
        record["id"] for record in graph["deliveries"]
        if all(nodes[item]["status"] == "implemented" for item in ancestors[record["id"]] & task_ids)
    )
    report["ok"] = not errors


def write_report(lines: list[str]) -> bool:
    """Print the rendered report; return False, without a traceback, when the stream refuses it."""
    stream = sys.stdout
    if stream is None:
        return True
    # A stream that cannot encode a character receives its escape instead of a traceback.
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        for line in lines:
            print(line.encode(encoding, "backslashreplace").decode(encoding))
        stream.flush()
    except OSError:
        # A closed pipe or failed device. The interpreter flushes this stream again at
        # exit; that flush must have somewhere to go instead of failing a second time.
        try:
            sink = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(sink, stream.fileno())
            finally:
                os.close(sink)
        except (OSError, ValueError):
            pass
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Read inputs, validate once, and render the same report in either format."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--graph", type=Path, default=ROOT / "specs/zk_delivery_graph.json",
        help="delivery graph JSON (default: specs/zk_delivery_graph.json in this repository)",
    )
    parser.add_argument(
        "--plan", type=Path, default=ROOT / "specs/zk_delivery_plan.md",
        help="Markdown plan compared with the graph (default: specs/zk_delivery_plan.md)",
    )
    parser.add_argument(
        "--reconciliation", type=Path, default=ROOT / "specs/zk_delivery_reconciliation.json",
        help="source reconciliation ledger JSON (default: specs/zk_delivery_reconciliation.json)",
    )
    parser.add_argument(
        "--root", type=Path, default=ROOT,
        help="repository that evidence paths resolve against (default: this script's repository)",
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="render the one validation report as text or JSON (default: text)",
    )
    try:
        args = parser.parse_args(argv)
    except (SystemExit, OSError) as stopped:
        # argparse has printed its help or a usage error. A stream that refuses that
        # text is exit status 1 without a traceback, as it is for a report.
        if write_report([]) and isinstance(stopped, SystemExit):
            raise
        return 1
    inputs: dict[str, Any] = {}
    report = empty_report()
    for label, path, reader in (
        ("graph", args.graph, load_json),
        ("plan", args.plan, lambda source: source.read_text(encoding="utf-8")),
        ("reconciliation", args.reconciliation, load_json),
    ):
        try:
            inputs[label] = reader(path)
        except RecursionError:
            report["errors"].append(f"cannot read inputs: {label} is nested too deeply")
        except (OSError, ValueError) as error:
            report["errors"].append(f"cannot read inputs: {label}: {error}")
    if not report["errors"]:
        report = check_plan(inputs["graph"], inputs["plan"], inputs["reconciliation"], args.root)
    if args.format == "json":
        lines = [json.dumps(report, indent=2, sort_keys=True)]
    else:
        lines = ["PASS" if report["ok"] else "FAIL", SCOPE]
        lines.extend(f"- {error}" for error in report["errors"])
        if report["ok"]:
            counts = report["status_counts"]
            lines.append(f"{report['task_count']} tasks, {report['delivery_count']} deliveries; graph and plan agree.")
            lines.append(
                f"Recorded status: {counts['planned']} planned, {counts['in_progress']} in progress, "
                f"{counts['implemented']} implemented; {len(report['complete_deliveries'])} deliveries complete."
            )
            lines.extend(f"- {line}" for line in report["progress"])
            lines.append(
                f"Open platform TODOs: {report['open_platform_todo_total']} in total; an open TODO is never a passed check."
            )
            lines.append("- open_platform_todos: " + ", ".join(
                f"{identifier} {count}" for identifier, count in report["open_platform_todos"].items()
            ))
            # Free text is quoted as JSON, so that each open item stays on one line.
            lines.extend(
                f"- {item['task']} open platform TODO, {item['platform']}, owner {item['owner']}, "
                f"outcome {item['outcome']}: command {json.dumps(item['command'])}; reason {json.dumps(item['reason'])}; "
                f"site {json.dumps(item['todo_site']['path'])} marker {json.dumps(item['todo_site']['marker'])}"
                for item in report["open_platform_todo_items"]
            )
    return 0 if write_report(lines) and report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
