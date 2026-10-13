"""Exercise structural failures, evidence rules and output parity of the ZK plan checker."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "check_zk_delivery_plan.py"
REPOSITORY = SCRIPT.parents[1]
SPEC = importlib.util.spec_from_file_location("check_zk_delivery_plan", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

# Literal expectations: a change to the checker's own constants must fail here.
SCOPE = "Structural consistency only; not code or cryptographic qualification."
SUPPORTED_SDKS = ["Rust", "Kotlin/Java/Android", "Swift", "JavaScript", "Python", "C#"]
REPORT_KEYS = {
    "ok", "scope", "errors", "task_count", "delivery_count", "roots", "status_counts", "progress",
    "complete_deliveries", "open_platform_todos", "open_platform_todo_total", "open_platform_todo_items",
}
FIXTURE_TASKS = ["B.1", "C.1", "H.3", "P.5", "R.1", "V.4", "V.6"]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
ARTIFACT = "specs/artifact.json"
COMMAND = "python3 -m unittest plan_test"
SENTENCES = ("Concrete artifact.", "Observable acceptance.", "Second observable result.")
# A check that only another platform can execute, and the TODO that its evidence file carries.
DEFERRED = "cargo test -p plan --features linux"
MARKER = "TODO: run the plan tests on Linux"
REASON = "No Linux host is attached to the development Mac."
TODO_FILE = f"// {MARKER}.\n"
PATH_RULE = "B.1.evidence.paths must be repository files outside ignored build and archive trees: "
COUNTS_RULE = (
    "reconciliation.counts must equal the recorded inventories: requirements 119, r6_findings 23, "
    "prior_findings 133, original_tasks 52, prior_carried_forward 133, prior_superseded_by_user_direction 0"
)
LEDGER_PROSE = (
    "plan prose must state once: preserves 119 verbatim revision-6 requirement units, all 23 revision-6 "
    "findings, all 133 earlier report IDs and all 52 original graph tasks"
)


def ledger_fixture() -> dict:
    """Embed the complete inventories without depending on archived files."""
    reference = {
        "source_id": "r6", "path": "dist/zk_checker_intentionally_absent_source.md",
        "line_start": 1, "line_end": 1,
    }
    rationale = "Mapped to the canonical implementation and its acceptance tests."
    return {
        "schema_version": 1,
        "sources": [{"id": "r6", "path": reference["path"], "sha256": "0" * 64, "available_optional": True}],
        "requirements": [{
            "id": f"REQ-{index:03d}", "source": dict(reference),
            "original_text": f"Original requirement {index}", "summary": f"Requirement {index}",
            "disposition": "retained", "task_ids": ["B.1"], "rationale": rationale,
        } for index in range(1, 120)],
        "findings": [{
            "id": f"R6-{index}", "source": dict(reference),
            "original_text": f"Original finding {index}", "title": f"Finding {index}",
            "severity": "minor", "disposition": "addressed_in_plan",
            "task_ids": ["B.1"], "rationale": rationale,
        } for index in range(23)],
        "prior_findings": [{
            "id": f"F{index}", "source": dict(reference),
            "original_record": {"triage": {"id": f"F{index}"}, "original_report_text": f"Original review {index}"},
            "disposition": "carried_forward", "task_ids": ["B.1"], "rationale": rationale,
        } for index in range(133)],
        "original_tasks": [{
            "id": f"O.{index}", "original_record": {"id": f"O.{index}", "title": f"Original task {index}"},
            "task_ids": ["B.1"], "rationale": rationale,
        } for index in range(52)],
        "counts": {
            "requirements": 119, "r6_findings": 23, "prior_findings": 133, "original_tasks": 52,
            "prior_carried_forward": 133, "prior_superseded_by_user_direction": 0,
        },
    }


def refresh_fingerprint(graph: dict, ledger: dict) -> None:
    """Re-certify a changed ledger in the graph, as a dishonest edit would."""
    graph["reconciliation_baseline"]["ledger_inventory_sha256"] = CHECKER.reconciliation_inventory_sha256(ledger)


def task(identifier: str, dependencies: list[str]) -> dict:
    """Return one planned fixture task whose text has three sentences."""
    return {
        "id": identifier,
        "title": f"Task {identifier}",
        "owner": "Core",
        "requires": dependencies,
        "outputs": [SENTENCES[0]],
        "acceptance": [f"{SENTENCES[1]} {SENTENCES[2]}"],
        "status": "planned",
    }


def fixture() -> dict:
    """Return a small graph with independent runtime and review deliveries."""
    ledger = ledger_fixture()
    return {
        "schema_version": 1,
        "source_commit": "abc123",
        "source_plan_available": True,
        "revision": 8,
        "status": "ready_for_development",
        "start_immediately": ["B.1", "R.1", "H.3", "V.4", "V.6"],
        "tasks": [
            task("B.1", []), task("R.1", []), task("H.3", []), task("P.5", ["B.1"]), task("C.1", ["B.1"]),
            task("V.4", []), task("V.6", []),
        ],
        "required_task_ids": ["B.1", "C.1"],
        "reconciliation_baseline": {
            "requirement_ids": [record["id"] for record in ledger["requirements"]],
            "original_task_ids": [record["id"] for record in ledger["original_tasks"]],
            "ledger_inventory_sha256": CHECKER.reconciliation_inventory_sha256(ledger),
        },
        "developer_surface_contract": {
            "id": "operation-v1", "native_isi": True, "kotodama": True,
            "one_call_sdk": True, "prepared_form": True, "four_validator_restart": True,
            "supported_sdks": list(SUPPORTED_SDKS),
            "atomic_semantics": "One atomic transaction for each atomic operation.",
            "progress_semantics": "Explicit durable progress for multi-round workflows.",
        },
        "deliveries": [
            {"id": "D.1", "title": "Delivery", "requires": ["R.1", "P.5", "C.1"], "kind": "functional", "surface_contract": "operation-v1"},
            {"id": "D.EVIDENCE", "title": "Evidence", "requires": ["H.3", "V.4", "V.6"], "kind": "evidence"},
        ],
        "constraints": {
            "required_ancestors": [["P.5", "B.1"]],
            "forbidden_ancestors": [{"task": "C.1", "prefix": "R."}],
            "non_gating_tasks": ["H.3", "V.4", "V.6"],
            "runtime_admission_task": "P.5",
        },
    }


def find(graph: dict, identifier: str) -> dict:
    """Return the fixture task or delivery with this ID."""
    return next(record for record in graph["tasks"] + graph["deliveries"] if record["id"] == identifier)


def clause(index: int, state: str = "met", proof: str | None = None) -> dict:
    """Return one acceptance entry for a fixture sentence, citing the recorded command."""
    return {"clause": SENTENCES[index], "state": state, "proof": f"`{COMMAND}` shows it" if proof is None else proof}


def evidence(**overrides: object) -> dict:
    """Return complete passing evidence for a fixture task, with selected fields replaced."""
    record = {
        "source": f"{COMMIT} with uncommitted task changes",
        "paths": [ARTIFACT],
        "commands": [{"command": COMMAND, "outcome": "passed"}],
        "acceptance": [clause(0, proof=f"{ARTIFACT} is produced and `{COMMAND}` reads it"), clause(1), clause(2)],
    }
    record.update(overrides)
    return record


def platform_todo(**overrides: object) -> dict:
    """Return one complete deferred platform execution, with selected fields replaced."""
    record = {
        "platform": "linux", "reason": REASON, "todo_site": {"path": ARTIFACT, "marker": MARKER}, "owner": "H.3",
    }
    record.update(overrides)
    return record


def deferred(command: str = DEFERRED, outcome: str = "not_run", **overrides: object) -> dict:
    """Return a command entry whose execution is deferred to another platform."""
    return {"command": command, "outcome": outcome, "platform_todo": platform_todo(**overrides)}


def deferring(*entries: dict, state: str = "partial", **overrides: object) -> dict:
    """Return evidence whose third sentence rests on these deferred commands beside the passing one."""
    proof = " and ".join(f"`{entry['command']}`" for entry in entries)
    record = evidence(
        commands=[{"command": COMMAND, "outcome": "passed"}, *entries],
        acceptance=[
            clause(0, proof=f"{ARTIFACT} is produced and `{COMMAND}` reads it"), clause(1),
            clause(2, state, f"{proof} must still run on the other platform"),
        ],
    )
    record.update(overrides)
    return record


def open_item(identifier: str, entry: dict) -> dict:
    """Return the report item of one open platform TODO, written out field by field."""
    todo = entry["platform_todo"]
    return {
        "task": identifier, "command": entry["command"], "outcome": entry["outcome"], "platform": todo["platform"],
        "reason": todo["reason"], "todo_site": {"path": todo["todo_site"]["path"], "marker": todo["todo_site"]["marker"]},
        "owner": todo["owner"],
    }


def no_todos(**counts: int) -> dict:
    """Return the per-task open TODO counts of the fixture graph: zero unless named, as B_1=2."""
    result = dict.fromkeys(FIXTURE_TASKS, 0)
    result.update({name.replace("_", "."): count for name, count in counts.items()})
    return result


def cited(path: str) -> list[dict]:
    """Return a met entry for every fixture sentence whose proof cites this path and the command."""
    return [clause(index, proof=f"{path} and `{COMMAND}`") for index in range(3)]


def implement(graph: dict, *identifiers: str) -> None:
    """Record complete passing evidence for these fixture tasks."""
    for identifier in identifiers:
        find(graph, identifier).update(status="implemented", evidence=evidence())


# Nine names: an unsorted set would report them in this order once in 362880 runs.
NAMES = [f"Y.{index}" for index in range(1, 10)]


def markdown(graph: dict) -> str:
    """Render the prose statements, exact rows and task contracts for the test fixture."""
    rows = [
        f"The [task graph](graph.json) contains {len(graph['tasks'])} implementation/evidence",
        f"tasks and {len(graph['deliveries'])} named deliveries. The [source reconciliation](ledger.json)",
        "preserves 119 verbatim revision-6 requirement units, all 23 revision-6 findings,",
        "all 133 earlier report IDs and all 52 original graph tasks.",
        "",
        f"Start in parallel at **{', '.join(graph['start_immediately'])}**.",
        "",
        "## Task graph",
        "",
        "| ID | Title | Owner | Requires |",
        "| --- | --- | --- | --- |",
    ]
    for record in graph["tasks"]:
        requires = ", ".join(record["requires"]) or "—"
        rows.append(f"| {record['id']} | {record['title']} | {record['owner']} | {requires} |")
    rows.extend(["", "| ID | Title | Requires |", "| --- | --- | --- |"])
    for delivery in graph["deliveries"]:
        requires = ", ".join(delivery["requires"]) or "—"
        rows.append(f"| {delivery['id']} | {delivery['title']} | {requires} |")
    for record in graph["tasks"]:
        rows.append(
            f"\n### {record['id']} {record['title']}\n\n"
            f"Deliverable: {' '.join(record['outputs'])}\n\n"
            f"Acceptance: {' '.join(record['acceptance'])}"
        )
    return "\n".join(rows)


def line_of(plan: str, line: str, occurrence: int = 1) -> int:
    """Return the 1-based number of the nth line equal to `line`."""
    numbers = [number for number, text in enumerate(plan.splitlines(), 1) if text == line]
    return numbers[occurrence - 1]


def canonical_sha256(value: object) -> str:
    """Hash a JSON value independently of key order and whitespace."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class CheckerCase(unittest.TestCase):
    """Shared assertions over the one format-independent report."""

    def check(self, graph: object, plan: str | None = None, ledger: object = None, root: Path | None = None) -> dict:
        return CHECKER.check_plan(
            graph, markdown(graph) if plan is None else plan, ledger_fixture() if ledger is None else ledger, root,
        )

    def assert_valid(self, graph: dict, plan: str | None = None, ledger: object = None, root: Path | None = None) -> dict:
        report = self.check(graph, plan, ledger, root)
        self.assertEqual(report["errors"], [])
        self.assertIs(report["ok"], True)
        return report

    def assert_error(self, message: str, graph: object, plan: str | None = None, ledger: object = None, root: Path | None = None) -> dict:
        """The exact message is reported, possibly beside consequential errors."""
        report = self.check(graph, plan, ledger, root)
        self.assertIs(report["ok"], False)
        self.assertIn(message, report["errors"])
        return report

    def assert_only(self, messages: str | list[str], graph: object, plan: str | None = None, ledger: object = None, root: Path | None = None) -> dict:
        """Exactly these messages are reported, in this order."""
        report = self.check(graph, plan, ledger, root)
        self.assertEqual(report["errors"], [messages] if isinstance(messages, str) else messages)
        self.assertIs(report["ok"], False)
        return report


class GraphTests(CheckerCase):
    """Graph schema, edges, roots, reachability and ancestry constraints."""

    def test_valid_graph_and_plan_report(self) -> None:
        graph = fixture()
        self.assertEqual(self.check(graph), {
            "ok": True,
            "scope": SCOPE,
            "errors": [],
            "task_count": 7,
            "delivery_count": 2,
            "roots": ["B.1", "H.3", "R.1", "V.4", "V.6"],
            "status_counts": {"planned": 7, "in_progress": 0, "implemented": 0},
            "progress": [],
            "complete_deliveries": [],
            "open_platform_todos": {"B.1": 0, "C.1": 0, "H.3": 0, "P.5": 0, "R.1": 0, "V.4": 0, "V.6": 0},
            "open_platform_todo_total": 0,
            "open_platform_todo_items": [],
        })
        self.assertEqual(CHECKER.SCOPE, SCOPE)

    def test_non_object_graphs_fail_without_traceback(self) -> None:
        for graph in (None, [], "graph", 5):
            with self.subTest(graph=graph):
                self.assert_only("graph must be an object", graph, plan="")
        for graph in ({}, {"tasks": [None]}, {"schema_version": True}):
            with self.subTest(graph=graph):
                self.assertIs(self.check(graph, plan="")["ok"], False)

    def test_graph_header_is_pinned(self) -> None:
        for field, values, message in (
            ("schema_version", (2, True, "1", None), "schema_version must be 1"),
            ("source_commit", ("", " ", None, 5), "source_commit must be a nonempty string"),
            ("source_plan_available", (False, 1, None), "source_plan_available must be true for the reconciled source plan"),
            ("revision", (7, 9, "8", True, 8.0), "revision must be 8"),
            ("status", ("released", None, ["ready_for_development"]), "graph status must be ready_for_development"),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    graph = fixture()
                    graph[field] = value
                    self.assert_only(message, graph)

    def test_record_shapes(self) -> None:
        for kind in ("tasks", "deliveries"):
            for value in ([], None, {}, 7, True, "records", {"id": "B.1"}):
                with self.subTest(kind=kind, value=value):
                    graph = fixture()
                    graph[kind] = value
                    self.assert_error(f"{kind} must be a nonempty list", graph, plan="")
        graph = fixture()
        graph["tasks"].append(None)
        self.assert_only("tasks[7] must be an object", graph, plan="")
        # An ID is one capitalized word, one dot and one further word.
        for identifier in ("b1", "B1", 5, None, "B.1 ", [], {}, ["B.1"], "b.1", "B.1.2", "1.2", "B.", ".1", "B.1\n", "B 1.2"):
            with self.subTest(identifier=identifier):
                graph = fixture()
                graph["deliveries"].append({"id": identifier, "title": "Extra", "requires": ["R.1"], "kind": "evidence"})
                self.assert_only("deliveries[2].id must be a dotted identifier such as W.1", graph, plan="")
        # A record without a usable ID is reported once and not examined further.
        graph = fixture()
        graph["tasks"].insert(1, {"id": "b1", "title": "", "requires": None})
        self.assert_only("tasks[1].id must be a dotted identifier such as W.1", graph, plan="")
        for field, value, message in (
            ("title", "", "B.1.title must be a nonempty string"),
            ("title", None, "B.1.title must be a nonempty string"),
            ("owner", " ", "B.1.owner must be a nonempty string"),
            ("requires", None, "B.1.requires must be a list of nonempty strings"),
            ("requires", "R.1", "B.1.requires must be a list of nonempty strings"),
            ("requires", [" "], "B.1.requires must be a list of nonempty strings"),
            ("outputs", [], "B.1.outputs must be a nonempty list of nonempty strings"),
            ("outputs", [" "], "B.1.outputs must be a nonempty list of nonempty strings"),
            ("acceptance", [None], "B.1.acceptance must be a nonempty list of nonempty strings"),
            ("status", "done", "B.1.status must be planned, in_progress or implemented"),
            ("status", None, "B.1.status must be planned, in_progress or implemented"),
            ("status", ["implemented"], "B.1.status must be planned, in_progress or implemented"),
        ):
            with self.subTest(field=field, value=value):
                graph = fixture()
                graph["tasks"][0][field] = value
                self.assert_only(message, graph, plan="")
        graph = fixture()
        del graph["deliveries"][0]["title"]
        self.assert_only("D.1.title must be a nonempty string", graph, plan="")
        # The kind and status words are exact: no other case, spacing or spelling is one of them.
        for kind in ("optional", None, [], "functional ", "Evidence", "EVIDENCE", " evidence", ""):
            graph = fixture()
            graph["deliveries"][1]["kind"] = kind
            self.assert_only("D.EVIDENCE.kind must be functional or evidence", graph)
        for status in ("planned ", " planned", "Planned", "IMPLEMENTED", "implemented\n", "in progress", "in-progress", "", 0, False):
            for recorded in ({}, {"evidence": evidence()}):
                with self.subTest(status=status, recorded=bool(recorded)):
                    graph = fixture()
                    graph["tasks"][0].update(status=status, **recorded)
                    self.assert_only("B.1.status must be planned, in_progress or implemented", graph, plan="")

    def test_no_field_has_a_default(self) -> None:
        # An absent field is never read as its permitted value.
        for key, message in (
            ("schema_version", "schema_version must be 1"),
            ("source_commit", "source_commit must be a nonempty string"),
            ("source_plan_available", "source_plan_available must be true for the reconciled source plan"),
            ("revision", "revision must be 8"),
            ("status", "graph status must be ready_for_development"),
            ("tasks", "tasks must be a nonempty list"),
            ("deliveries", "deliveries must be a nonempty list"),
            ("required_task_ids", "required_task_ids must be a nonempty list of nonempty strings"),
            ("developer_surface_contract", "developer_surface_contract must define the common operation-v1 surface"),
            ("start_immediately", "start_immediately must be a list of nonempty strings"),
            ("constraints", "constraints must be an object"),
            ("reconciliation_baseline", "reconciliation_baseline must be an object"),
        ):
            with self.subTest(key=key):
                graph = fixture()
                del graph[key]
                self.assert_error(message, graph, plan="")
        for block, fields in (
            ("developer_surface_contract", {
                "id": "developer_surface_contract.id must be operation-v1",
                "native_isi": "developer_surface_contract.native_isi must be true",
                "kotodama": "developer_surface_contract.kotodama must be true",
                "one_call_sdk": "developer_surface_contract.one_call_sdk must be true",
                "prepared_form": "developer_surface_contract.prepared_form must be true",
                "four_validator_restart": "developer_surface_contract.four_validator_restart must be true",
                "supported_sdks": "developer_surface_contract.supported_sdks must preserve all six canonical SDK targets",
                "atomic_semantics": "developer_surface_contract.atomic_semantics must be nonempty",
                "progress_semantics": "developer_surface_contract.progress_semantics must be nonempty",
            }),
            ("constraints", {
                "required_ancestors": "constraints.required_ancestors must contain [dependent, ancestor] pairs",
                "forbidden_ancestors": "constraints.forbidden_ancestors must contain task/prefix objects",
                "non_gating_tasks": "constraints.non_gating_tasks must be a list of nonempty strings",
                "runtime_admission_task": "constraints.runtime_admission_task must be a task ID",
            }),
            ("reconciliation_baseline", {
                "requirement_ids": "reconciliation_baseline.requirement_ids must be unique nonempty IDs",
                "original_task_ids": "reconciliation_baseline.original_task_ids must be unique nonempty IDs",
                "ledger_inventory_sha256": "reconciliation_baseline.ledger_inventory_sha256 must be a SHA256 digest",
            }),
        ):
            self.assertEqual(set(fields), set(fixture()[block]))
            for field, message in fields.items():
                with self.subTest(block=block, field=field):
                    graph = fixture()
                    del graph[block][field]
                    self.assert_only(message, graph, plan="")
        for kind, index, identifier, fields in (
            ("tasks", 4, "C.1", {
                "id": "tasks[4].id must be a dotted identifier such as W.1",
                "title": "C.1.title must be a nonempty string",
                "owner": "C.1.owner must be a nonempty string",
                "requires": "C.1.requires must be a list of nonempty strings",
                "outputs": "C.1.outputs must be a nonempty list of nonempty strings",
                "acceptance": "C.1.acceptance must be a nonempty list of nonempty strings",
                "status": "C.1.status must be planned, in_progress or implemented",
            }),
            ("deliveries", 0, "D.1", {
                "id": "deliveries[0].id must be a dotted identifier such as W.1",
                "title": "D.1.title must be a nonempty string",
                "requires": "D.1.requires must be a list of nonempty strings",
                "kind": "D.1.kind must be functional or evidence",
                "surface_contract": "D.1 must use the operation-v1 developer surface contract",
            }),
        ):
            self.assertEqual(set(fields), set(fixture()[kind][index]))
            for field, message in fields.items():
                with self.subTest(identifier=identifier, field=field):
                    graph = fixture()
                    del graph[kind][index][field]
                    self.assert_error(message, graph, plan="")

    def test_unknown_and_duplicate_dependency_edges(self) -> None:
        # Every edge of every node is examined, whatever its position.
        for identifier, requires in (
            ("C.1", ["MISSING.1"]), ("C.1", ["MISSING.1", "B.1"]), ("C.1", ["B.1", "R.1", "MISSING.1"]),
            ("B.1", ["MISSING.1"]), ("D.1", ["MISSING.1", "R.1", "P.5", "C.1"]),
            ("D.EVIDENCE", ["H.3", "V.4", "V.6", "MISSING.1"]),
        ):
            with self.subTest(identifier=identifier, requires=requires):
                graph = fixture()
                find(graph, identifier)["requires"] = requires
                self.assert_only(f"{identifier} requires unknown ID MISSING.1", graph)
        graph = fixture()
        find(graph, "C.1")["requires"] = ["MISSING.2", "B.1", "MISSING.1"]
        self.assert_only(["C.1 requires unknown ID MISSING.2", "C.1 requires unknown ID MISSING.1"], graph)
        for identifier in ("B.1", "C.1", "V.6", "D.1", "D.EVIDENCE"):
            for requires in (["B.1", "B.1"], ["R.1", "B.1", "R.1"], ["B.1", "R.1", "R.1"]):
                graph = fixture()
                find(graph, identifier)["requires"] = requires
                self.assert_only(f"{identifier}.requires contains duplicate edges", graph)

    def test_task_requires_only_tasks(self) -> None:
        for identifier, requires in (
            ("C.1", ["B.1", "D.EVIDENCE"]), ("C.1", ["D.EVIDENCE", "B.1"]), ("B.1", ["D.EVIDENCE"]), ("V.6", ["D.EVIDENCE"]),
        ):
            graph = fixture()
            find(graph, identifier)["requires"] = requires
            self.assert_only(f"task {identifier} may require only tasks, not delivery D.EVIDENCE", graph)
        graph = fixture()
        graph["deliveries"].append({"id": "D.2", "title": "Second", "requires": ["D.1"], "kind": "functional", "surface_contract": "operation-v1"})
        self.assert_valid(graph)

    def test_delivery_requires_at_least_one_node(self) -> None:
        graph = fixture()
        graph["deliveries"].append({"id": "D.2", "title": "Empty", "requires": [], "kind": "functional", "surface_contract": "operation-v1"})
        self.assert_only("D.2.requires must name at least one task or delivery", graph)

    def test_every_record_is_validated(self) -> None:
        # Each check applies to every task and delivery, not only to the first or last record.
        for index, identifier in enumerate(record["id"] for record in fixture()["tasks"]):
            for field, value, message in (
                ("title", "", f"{identifier}.title must be a nonempty string"),
                ("owner", None, f"{identifier}.owner must be a nonempty string"),
                ("requires", "B.1", f"{identifier}.requires must be a list of nonempty strings"),
                ("outputs", [], f"{identifier}.outputs must be a nonempty list of nonempty strings"),
                ("acceptance", [], f"{identifier}.acceptance must be a nonempty list of nonempty strings"),
                ("status", "done", f"{identifier}.status must be planned, in_progress or implemented"),
                ("evidence", evidence(), f"{identifier}.evidence is recorded only for in_progress or implemented status"),
            ):
                with self.subTest(identifier=identifier, field=field):
                    graph = fixture()
                    graph["tasks"][index][field] = value
                    self.assert_only(message, graph, plan="")
            for status in ("in_progress", "implemented"):
                with self.subTest(identifier=identifier, status=status):
                    graph = fixture()
                    graph["tasks"][index].update(status=status, evidence=evidence(source="no commit"))
                    self.assert_only(f"{identifier}.evidence.source must contain the observed 40-hex commit id", graph, plan="")
        third = {"id": "D.2", "title": "Second", "requires": ["D.1"], "kind": "functional", "surface_contract": "operation-v1"}
        for index, identifier in enumerate(("D.1", "D.EVIDENCE", "D.2")):
            for change, message in (
                ({"title": None}, f"{identifier}.title must be a nonempty string"),
                ({"requires": None}, f"{identifier}.requires must be a list of nonempty strings"),
                ({"requires": []}, f"{identifier}.requires must name at least one task or delivery"),
                ({"kind": "optional"}, f"{identifier}.kind must be functional or evidence"),
                ({"kind": "functional", "surface_contract": "sdk-only"}, f"{identifier} must use the operation-v1 developer surface contract"),
            ):
                with self.subTest(identifier=identifier, change=change):
                    graph = fixture()
                    graph["deliveries"].append(dict(third))
                    graph["deliveries"][index].update(change)
                    self.assert_only(message, graph, plan="")

    def test_every_list_element_is_validated(self) -> None:
        def task_field(field: str):
            return lambda graph, value: graph["tasks"][4].update({field: value})

        for label, good, assign in (
            ("C.1.requires must be a list", ["B.1"], task_field("requires")),
            ("C.1.outputs must be a nonempty list", [SENTENCES[0]], task_field("outputs")),
            ("C.1.acceptance must be a nonempty list", [SENTENCES[1]], task_field("acceptance")),
            ("D.1.requires must be a list", ["R.1"], lambda graph, value: graph["deliveries"][0].update(requires=value)),
            ("required_task_ids must be a nonempty list", ["B.1"], lambda graph, value: graph.update(required_task_ids=value)),
            ("start_immediately must be a list", ["B.1", "R.1"], lambda graph, value: graph.update(start_immediately=value)),
            (
                "constraints.non_gating_tasks must be a list", ["H.3", "V.4", "V.6"],
                lambda graph, value: graph["constraints"].update(non_gating_tasks=value),
            ),
        ):
            for bad in (" ", "", None, 5, ["B.1"]):
                for value in ([bad] + good, good + [bad], good + [bad] + good):
                    with self.subTest(label=label, value=value):
                        graph = fixture()
                        assign(graph, value)
                        self.assert_only(f"{label} of nonempty strings", graph, plan="")

    def test_implemented_task_with_unknown_prerequisite_is_reported(self) -> None:
        graph = fixture()
        find(graph, "C.1").update(requires=["MISSING.1"], status="implemented", evidence=evidence())
        self.assert_only([
            "C.1 requires unknown ID MISSING.1",
            "C.1 cannot be implemented before its prerequisites: MISSING.1",
        ], graph)

    def test_duplicate_ids_across_task_and_delivery(self) -> None:
        graph = fixture()
        graph["deliveries"][0]["id"] = "B.1"
        self.assert_only("duplicate task/delivery ID: B.1", graph)
        # The first record keeps the ID; a repeat is reported once and not examined further.
        for kind, record in (
            ("tasks", dict(task("B.1", []), title="", status="done")), ("tasks", dict(task("V.6", []), outputs=[])),
            ("deliveries", {"id": "D.1", "title": "", "requires": [], "kind": "optional"}),
        ):
            graph = fixture()
            graph[kind].append(record)
            self.assert_only(f"duplicate task/delivery ID: {record['id']}", graph)

    def test_dependency_cycle(self) -> None:
        graph = fixture()
        find(graph, "B.1")["requires"] = ["P.5"]
        report = self.assert_error("dependency cycle includes B.1", graph)
        self.assertIn("dependency cycle includes P.5", report["errors"])
        graph = fixture()
        find(graph, "C.1")["requires"] = ["B.1", "C.1"]
        self.assert_only("dependency cycle includes C.1", graph)
        # Deliveries are nodes of the same graph.
        graph = fixture()
        graph["deliveries"].extend([
            {"id": "D.2", "title": "Second", "requires": ["D.3", "R.1"], "kind": "evidence"},
            {"id": "D.3", "title": "Third", "requires": ["D.2"], "kind": "evidence"},
        ])
        self.assert_only(["dependency cycle includes D.2", "dependency cycle includes D.3"], graph)

    def test_immediate_roots_are_the_true_roots(self) -> None:
        message = "start_immediately must equal task roots: B.1, H.3, R.1, V.4, V.6"
        graph = fixture()
        graph["start_immediately"].append("P.5")
        self.assert_only(message, graph)
        graph["start_immediately"] = ["B.1"]
        self.assert_only(message, graph)
        graph["start_immediately"] = ["V.6", "V.4", "H.3", "R.1", "B.1"]
        self.assertEqual(self.assert_valid(graph)["roots"], ["B.1", "H.3", "R.1", "V.4", "V.6"])
        graph = fixture()
        graph["start_immediately"].append("B.1")
        self.assert_only("start_immediately contains duplicate IDs", graph)
        for unknown in ("Z.9", "D.1"):
            for position in (0, 2, 5):
                graph = fixture()
                graph["start_immediately"].insert(position, unknown)
                self.assert_only(f"start_immediately contains unknown task {unknown}", graph)
        graph = fixture()
        graph["start_immediately"] = "B.1"
        self.assert_only("start_immediately must be a list of nonempty strings", graph)

    def test_every_task_reaches_a_delivery(self) -> None:
        graph = fixture()
        find(graph, "D.1")["requires"].remove("C.1")
        self.assert_only("orphan task C.1 reaches no delivery", graph)
        graph = fixture()
        graph["tasks"].extend([task("Y.1", ["B.1"]), task("Z.1", ["Y.1"])])
        self.assert_only(["orphan task Y.1 reaches no delivery", "orphan task Z.1 reaches no delivery"], graph)

    def test_required_ancestry_is_transitive(self) -> None:
        graph = fixture()
        find(graph, "P.5")["requires"] = ["C.1"]
        self.assert_valid(graph)
        find(graph, "P.5")["requires"] = ["R.1"]
        self.assert_only("required ancestry missing: P.5 must depend on B.1", graph)
        valid = ["P.5", "B.1"]
        for pair, unknown in ((["P.5", "NOPE.1"], "NOPE.1"), (["NOPE.2", "B.1"], "NOPE.2")):
            for pairs in ([pair], [valid, pair], [pair, valid]):
                graph = fixture()
                graph["constraints"]["required_ancestors"] = pairs
                self.assert_only(f"required_ancestors contains unknown ID {unknown}", graph)
        for value in (
            [None], {}, None, [["P.5"]], [["P.5", "B.1", "R.1"]], [["P.5", ""]], [["P.5", []]], [["", "B.1"]], [[5, "B.1"]],
            [valid, None], [None, valid], [valid, ["P.5", ""]], [["", "B.1"], valid], [valid, "P.5"],
        ):
            with self.subTest(value=value):
                graph = fixture()
                graph["constraints"]["required_ancestors"] = value
                self.assert_only("constraints.required_ancestors must contain [dependent, ancestor] pairs", graph)

    def test_every_ancestry_constraint_is_enforced(self) -> None:
        # The real graph has 33 required pairs and 30 forbidden rules; none may be skipped.
        held, missing = ["P.5", "B.1"], ["C.1", "R.1"]
        for pairs in ([held, missing], [missing, held], [held, missing, held]):
            graph = fixture()
            graph["constraints"]["required_ancestors"] = pairs
            self.assert_only("required ancestry missing: C.1 must depend on R.1", graph)
        graph = fixture()
        graph["constraints"]["required_ancestors"] = [missing, held, ["P.5", "R.1"]]
        self.assert_only([
            "required ancestry missing: C.1 must depend on R.1", "required ancestry missing: P.5 must depend on R.1",
        ], graph)
        kept, broken = {"task": "C.1", "prefix": "R."}, {"task": "P.5", "prefix": "B."}
        for rules in ([kept, broken], [broken, kept], [kept, broken, kept]):
            graph = fixture()
            graph["constraints"]["forbidden_ancestors"] = rules
            self.assert_only("forbidden ancestry for P.5: B.1", graph)
        graph = fixture()
        graph["constraints"]["forbidden_ancestors"] = [broken, kept, {"task": "C.1", "prefix": "B.1", "exact": True}]
        self.assert_only(["forbidden ancestry for P.5: B.1", "forbidden ancestry for C.1: B.1"], graph)

    def test_forbidden_ancestry_is_transitive(self) -> None:
        graph = fixture()
        find(graph, "B.1")["requires"] = ["R.1"]
        graph["start_immediately"].remove("B.1")
        self.assert_only("forbidden ancestry for C.1: R.1", graph)

    def test_exact_forbidden_ancestor_distinguishes_r1_from_r11(self) -> None:
        graph = fixture()
        graph["tasks"].append(task("R.11", []))
        graph["start_immediately"].append("R.11")
        find(graph, "C.1")["requires"].append("R.11")
        find(graph, "D.1")["requires"].append("R.11")
        graph["constraints"]["forbidden_ancestors"] = [{"task": "C.1", "prefix": "R.1", "exact": True}]
        self.assert_valid(graph)
        graph["constraints"]["forbidden_ancestors"][0]["exact"] = False
        self.assert_only("forbidden ancestry for C.1: R.11", graph)
        del graph["constraints"]["forbidden_ancestors"][0]["exact"]
        self.assert_only("forbidden ancestry for C.1: R.11", graph)
        graph["constraints"]["forbidden_ancestors"][0]["exact"] = True
        find(graph, "C.1")["requires"].append("R.1")
        self.assert_only("forbidden ancestry for C.1: R.1", graph)
        valid = {"task": "C.1", "prefix": "X."}
        for rule in (
            {"task": "C.1", "prefix": "R.1", "exact": "true"}, {"task": "C.1"}, {"task": "", "prefix": "R."},
            {"task": [], "prefix": "R."}, {"task": "C.1", "prefix": ""}, {"prefix": "R."}, {"task": "C.1", "prefix": 5},
            {"task": "C.1", "prefix": "R.", "exact": 1}, {"task": "C.1", "prefix": "R.", "exact": None}, None, "C.1",
        ):
            for rules in ([rule], [valid, rule], [rule, valid]):
                with self.subTest(rules=rules):
                    graph["constraints"]["forbidden_ancestors"] = rules
                    self.assert_only("constraints.forbidden_ancestors must contain task/prefix objects", graph)
        for value in (None, {}, "C.1"):
            graph["constraints"]["forbidden_ancestors"] = value
            self.assert_only("constraints.forbidden_ancestors must contain task/prefix objects", graph)
        for unknown in ("D.EVIDENCE", "NOPE.1"):
            rule = {"task": unknown, "prefix": "X."}
            for rules in ([rule], [valid, rule], [rule, valid]):
                graph["constraints"]["forbidden_ancestors"] = rules
                self.assert_only(f"forbidden_ancestors contains unknown task {unknown}", graph)

    def test_constraints_block_is_required_and_pinned(self) -> None:
        graph = fixture()
        graph["constraints"] = []
        self.assert_only("constraints must be an object", graph)
        for dropped in ("H.3", "V.4", "V.6"):
            with self.subTest(dropped=dropped):
                graph = fixture()
                graph["constraints"]["non_gating_tasks"].remove(dropped)
                self.assert_only("non_gating_tasks must include H.3, V.4 and V.6", graph)
        graph = fixture()
        graph["constraints"]["non_gating_tasks"] = "H.3"
        self.assert_only("constraints.non_gating_tasks must be a list of nonempty strings", graph)
        for value in (None, [], 5):
            graph = fixture()
            graph["constraints"]["runtime_admission_task"] = value
            self.assert_only("constraints.runtime_admission_task must be a task ID", graph)
        graph = fixture()
        graph["constraints"]["runtime_admission_task"] = "D.1"
        self.assert_only("admission constraints contain unknown task D.1", graph)
        for position in (0, 1, 3):
            graph = fixture()
            graph["constraints"]["non_gating_tasks"].insert(position, "NOPE.1")
            self.assert_only("admission constraints contain unknown task NOPE.1", graph)

    def test_non_gating_review_cannot_gate_runtime(self) -> None:
        for gate in ("H.3", "V.4", "V.6"):
            with self.subTest(gate=gate):
                graph = fixture()
                find(graph, "B.1")["requires"] = [gate]
                graph["start_immediately"].remove("B.1")
                self.assert_only([
                    f"runtime admission P.5 depends on non-gating task {gate}",
                    f"functional delivery D.1 depends on evidence gates: {gate}",
                ], graph)
                graph = fixture()
                graph["constraints"]["runtime_admission_task"] = gate
                self.assert_only(f"runtime admission {gate} depends on non-gating task {gate}", graph)
        graph = fixture()
        find(graph, "B.1")["requires"] = ["V.6", "H.3"]
        graph["start_immediately"].remove("B.1")
        self.assert_only([
            "runtime admission P.5 depends on non-gating task H.3",
            "runtime admission P.5 depends on non-gating task V.6",
            "functional delivery D.1 depends on evidence gates: H.3, V.6",
        ], graph)

    def test_functional_deliveries_cannot_depend_on_evidence(self) -> None:
        graph = fixture()
        find(graph, "D.1")["requires"].append("V.4")
        self.assert_only("functional delivery D.1 depends on evidence gates: V.4", graph)
        # An evidence delivery gates on its own, without any non-gating task behind it.
        graph = fixture()
        graph["deliveries"].append({"id": "D.E2", "title": "Pure evidence", "requires": ["R.1"], "kind": "evidence"})
        find(graph, "D.1")["requires"].append("D.E2")
        self.assert_only("functional delivery D.1 depends on evidence gates: D.E2", graph)
        find(graph, "D.EVIDENCE")["requires"].append("D.E2")
        find(graph, "D.1")["requires"].remove("D.E2")
        self.assert_valid(graph)
        # Every evidence delivery gates, wherever it stands in the graph.
        for position in (0, 1, 2):
            graph = fixture()
            graph["deliveries"].insert(position, {"id": "A.E", "title": "Other evidence", "requires": ["R.1"], "kind": "evidence"})
            find(graph, "D.1")["requires"].append("A.E")
            self.assert_only("functional delivery D.1 depends on evidence gates: A.E", graph)
            find(graph, "D.1")["requires"].append("D.EVIDENCE")
            self.assert_only("functional delivery D.1 depends on evidence gates: A.E, D.EVIDENCE, H.3, V.4, V.6", graph)

    def test_functional_surface_cannot_be_weakened(self) -> None:
        for value in ("sdk-only", "operation-v1 ", None, []):
            graph = fixture()
            graph["deliveries"][0]["surface_contract"] = value
            self.assert_only("D.1 must use the operation-v1 developer surface contract", graph)
        graph = fixture()
        del graph["deliveries"][0]["surface_contract"]
        self.assert_only("D.1 must use the operation-v1 developer surface contract", graph)
        for field in ("native_isi", "kotodama", "one_call_sdk", "prepared_form", "four_validator_restart"):
            for value in (False, 1, None):
                graph = fixture()
                graph["developer_surface_contract"][field] = value
                self.assert_only(f"developer_surface_contract.{field} must be true", graph)
        for sdks in (
            SUPPORTED_SDKS[:-1], SUPPORTED_SDKS[:4] + SUPPORTED_SDKS[5:], list(reversed(SUPPORTED_SDKS)),
            SUPPORTED_SDKS + ["Go"], SUPPORTED_SDKS + ["C#"], None,
        ):
            with self.subTest(sdks=sdks):
                graph = fixture()
                graph["developer_surface_contract"]["supported_sdks"] = sdks
                self.assert_only("developer_surface_contract.supported_sdks must preserve all six canonical SDK targets", graph)
        self.assertEqual(CHECKER.SUPPORTED_SDKS, SUPPORTED_SDKS)
        graph = fixture()
        graph["developer_surface_contract"] = []
        self.assert_only("developer_surface_contract must define the common operation-v1 surface", graph)
        graph = fixture()
        graph["developer_surface_contract"]["id"] = "operation-v2"
        self.assert_only("developer_surface_contract.id must be operation-v1", graph)
        for field in ("atomic_semantics", "progress_semantics"):
            for value in ("", " ", None):
                graph = fixture()
                graph["developer_surface_contract"][field] = value
                self.assert_only(f"developer_surface_contract.{field} must be nonempty", graph)

    def test_required_source_scope_task_cannot_be_omitted(self) -> None:
        graph = fixture()
        graph["tasks"] = [record for record in graph["tasks"] if record["id"] != "C.1"]
        find(graph, "D.1")["requires"].remove("C.1")
        graph["constraints"]["forbidden_ancestors"] = []
        self.assert_only("required task missing from graph: C.1", graph)
        for identifiers in (["MISSING.1", "B.1", "C.1"], ["B.1", "MISSING.1", "C.1"], ["B.1", "C.1", "MISSING.1"], ["D.1"]):
            graph = fixture()
            graph["required_task_ids"] = identifiers
            missing = "D.1" if identifiers == ["D.1"] else "MISSING.1"
            self.assert_only(f"required task missing from graph: {missing}", graph)
        for identifiers in (["B.1", "C.1", "B.1"], ["B.1", "C.1", "C.1"]):
            graph = fixture()
            graph["required_task_ids"] = identifiers
            self.assert_only("required_task_ids contains duplicate IDs", graph)
        for value in ([], None, [" "]):
            graph = fixture()
            graph["required_task_ids"] = value
            self.assert_only("required_task_ids must be a nonempty list of nonempty strings", graph)


    def test_reports_are_sorted_whatever_the_set_or_edge_order(self) -> None:
        graph = fixture()
        graph["tasks"].extend(task(name, ["B.1"]) for name in reversed(NAMES))
        self.assert_only([f"orphan task {name} reaches no delivery" for name in NAMES], graph)

        graph = fixture()
        graph["tasks"].extend(task(name, []) for name in reversed(NAMES))
        graph["start_immediately"].extend(reversed(NAMES))
        find(graph, "D.EVIDENCE")["requires"].extend(reversed(NAMES))
        self.assertEqual(self.assert_valid(graph)["roots"], ["B.1", "H.3", "R.1", "V.4", "V.6"] + NAMES)
        graph["constraints"]["forbidden_ancestors"] = [{"task": "C.1", "prefix": "Y."}]
        find(graph, "C.1")["requires"].extend(reversed(NAMES))
        self.assert_only(f"forbidden ancestry for C.1: {', '.join(NAMES)}", graph)
        graph["constraints"].update(forbidden_ancestors=[], non_gating_tasks=["H.3", "V.4", "V.6"] + NAMES[::-1])
        self.assert_only(f"functional delivery D.1 depends on evidence gates: {', '.join(NAMES)}", graph)

        graph = fixture()
        for name in reversed(NAMES):
            graph["tasks"].append(dict(task(name, ["R.1", "B.1"]), status="implemented", evidence=evidence()))
        self.assert_only([f"{name} cannot be implemented before its prerequisites: B.1, R.1" for name in NAMES], graph)

        graph = fixture()
        for name in reversed(NAMES):
            graph["tasks"].append(dict(task(name, ["B.1"]), status="in_progress", evidence=evidence()))
            graph["deliveries"].append({"id": name.replace("Y", "E"), "title": f"Evidence {name}", "requires": [name], "kind": "evidence"})
        report = self.assert_valid(graph)
        self.assertEqual(report["progress"], [f"{name} in_progress: 3 of 3 clauses met" for name in NAMES])
        self.assertEqual(report["complete_deliveries"], [])
        implement(graph, "B.1", *NAMES)
        report = self.assert_valid(graph)
        self.assertEqual(report["progress"], [f"{name} implemented: 3 of 3 clauses met" for name in ["B.1"] + NAMES])
        self.assertEqual(report["complete_deliveries"], [name.replace("Y", "E") for name in NAMES])
        # Every evidence delivery is an evidence gate, and each one is named.
        find(graph, "D.1")["requires"].extend(name.replace("Y", "E") for name in reversed(NAMES))
        self.assert_only(
            f"functional delivery D.1 depends on evidence gates: {', '.join(name.replace('Y', 'E') for name in NAMES)}", graph,
        )


class PlanTests(CheckerCase):
    """Markdown rows, task contracts, headings and stated roots and counts."""

    def test_table_rows_match_the_graph(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        for changed, message in (
            (plan.replace("| B.1 | Task B.1 |", "| B.1 | Changed title |"), "plan table differs from graph for B.1"),
            (plan.replace("| Core |", "| Wrong owner |", 1), "plan table differs from graph for B.1"),
            (plan.replace("| P.5 | Task P.5 | Core | B.1 |", "| P.5 | Task P.5 | Core | R.1 |"), "plan table differs from graph for P.5"),
            (plan.replace("| B.1 | Task B.1 | Core | — |", "| B.1 | Task B.1 | Core | — | extra |"), "plan table differs from graph for B.1"),
            (plan.replace("| B.1 | Task B.1 | Core | — |\n", ""), "plan table is missing B.1"),
            (plan.replace("| D.1 | Delivery |", "| D.1 | Renamed delivery |"), "plan table differs from graph for D.1"),
            (plan.replace("| D.EVIDENCE | Evidence | H.3, V.4, V.6 |\n", ""), "plan table is missing D.EVIDENCE"),
        ):
            with self.subTest(message=message, changed=changed):
                self.assertNotEqual(changed, plan)
                self.assert_only(message, graph, plan=changed)

    def test_every_row_and_contract_is_compared(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        for record in graph["tasks"] + graph["deliveries"]:
            identifier = record["id"]
            with self.subTest(identifier=identifier):
                row = next(line for line in plan.splitlines() if line.startswith(f"| {identifier} |"))
                self.assert_only(f"plan table is missing {identifier}", graph, plan=plan.replace(row + "\n", ""))
                self.assert_only(
                    f"plan table differs from graph for {identifier}", graph,
                    plan=plan.replace(row, row.replace(record["title"], "Changed title")),
                )
                self.assert_only(
                    f"plan table differs from graph for {identifier}", graph, plan=plan.replace(row, row[:-1] + "extra |"),
                )
                if record in graph["tasks"]:
                    heading = f"### {identifier} {record['title']}"
                    for changed in (
                        plan.replace(heading, f"### {identifier} Changed title"),
                        plan.replace(f"{heading}\n\nDeliverable: {SENTENCES[0]}", f"{heading}\n\nDeliverable: Less."),
                        plan.replace(f"{heading}\n\nDeliverable: {SENTENCES[0]}\n\nAcceptance: {SENTENCES[1]}", f"{heading}\n\nDeliverable: {SENTENCES[0]}\n\nAcceptance: Less."),
                    ):
                        self.assertNotEqual(changed, plan)
                        self.assert_only(f"plan task contract differs from graph for {identifier}", graph, plan=changed)

    def test_duplicate_and_unknown_rows_are_rejected_in_isolation(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        separator = "| --- | --- | --- | --- |\n"
        duplicate = "| B.1 | Task B.1 | Core | — |"
        changed = plan.replace(separator, separator + duplicate + "\n", 1)
        self.assert_only(f"duplicate plan table row for B.1 at line {line_of(changed, duplicate, 2)}", graph, plan=changed)
        unknown = "| Z.9 | Unknown | Core | — |"
        changed = plan.replace(separator, separator + unknown + "\n", 1)
        self.assert_only(f"plan table contains unknown ID Z.9 at line {line_of(changed, unknown)}", graph, plan=changed)
        # A row is a row with or without its optional closing pipe.
        changed = plan.replace(separator, separator + "| B.1 | Weaker title | Core | —\n", 1)
        self.assert_only(f"duplicate plan table row for B.1 at line {line_of(changed, duplicate)}", graph, plan=changed)
        changed = plan.replace(separator, separator + unknown[:-2] + "\n", 1)
        self.assert_only(f"plan table contains unknown ID Z.9 at line {line_of(changed, unknown[:-2])}", graph, plan=changed)
        self.assert_valid(graph, plan=plan.replace(duplicate, duplicate[:-2]))
        self.assert_valid(graph, plan=plan.replace(duplicate, "  " + duplicate + "  "))
        # Both pipes are optional, so a row cannot hide by omitting the opening one either.
        self.assert_valid(graph, plan=plan.replace(duplicate, duplicate[2:]))
        self.assert_valid(graph, plan=plan.replace(duplicate, duplicate[2:-2]))
        self.assert_valid(graph, plan=plan.replace(duplicate, "|\n" + duplicate[2:]))
        self.assert_only("plan table is missing B.1", graph, plan=plan.replace(duplicate, "|\n" + duplicate[2:5]))

    def test_decorated_rows_are_still_rows(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        separator = "| --- | --- | --- | --- |\n"
        canonical = "| B.1 | Task B.1 | Core | — |"
        for row in (
            "B.1 | Weaker title | Core | — |", "B.1 | Weaker title | Core | —", "| **B.1** | Weaker title | Core | — |",
            "| `B.1` | Weaker title | Core | — |", "| *B.1* | Weaker title | Core | — |", "| [B.1](#b1) | Weaker title | Core | — |",
            "> | B.1 | Weaker title | Core | — |", "- | B.1 | Weaker title | Core | — |", "\t| B.1 | Weaker title | Core | — |",
            "1. B.1 | Weaker title | Core | — |", "| task B.1 | Weaker title | Core | — |", "| _B.1 | Weaker title | Core | — |",
            "| __B.1 __ | Weaker title | Core | — |", "|B.1|Weaker title|Core|—|", "B.1|Weaker title|Core|—", "|B.1|Weaker title|Core|—",
        ):
            with self.subTest(row=row):
                changed = plan.replace(separator, separator + row + "\n", 1)
                self.assert_only(f"duplicate plan table row for B.1 at line {line_of(changed, canonical)}", graph, plan=changed)
                # Marks inside the first cell never equal the graph; a quoted or listed exact row does.
                alone = plan.replace(canonical, row.replace("Weaker title", "Task B.1"))
                if any(mark in row for mark in ("*", "`", "[", "_", "task")):
                    self.assert_only("plan table differs from graph for B.1", graph, plan=alone)
                else:
                    self.assert_valid(graph, plan=alone)
        for row, identifier in (
            ("| **Z.9** | Unknown | Core | — |", "Z.9"), ("Z.9 | Unknown | Core | —", "Z.9"), ("> | `Z.9` | Unknown |", "Z.9"),
            ("| __Z.9__ | Unknown |", "Z.9__"), ("| __B.1__ | Weaker title | Core | — |", "B.1__"),
        ):
            changed = plan.replace(separator, separator + row + "\n", 1)
            self.assert_only(f"plan table contains unknown ID {identifier} at line {line_of(changed, row)}", graph, plan=changed)
        # Only the first cell names a row, and prose is not a row.
        for line in (
            "| Notes | B.1 | Core | — |", "| | B.1 |", "|", "||", "a | b", "| b.1 | lower case |", "| 1.2 | version |",
            "| 3B.1 | not an ID |", "| xB.1 | not an ID |", "| pre-B.1 | not an ID |", "| a_B.1 | not an ID |",
            "| B. 1 | spaced |", "| B .1 | spaced |",
            "3B.1 | not a row", "### Notes | with a pipe", "**Bold | pipe**",
            "B.1 and C.1 are described below.", "- B.1 first", "> C.1 quoted", "Use `x | y` when B.1 lands.",
            "\\| | B.1 |", "\\|", "Notes \\| | B.1 |",
        ):
            with self.subTest(line=line):
                self.assert_valid(graph, plan=plan.replace(separator, separator + line + "\n", 1))

    def test_escaped_pipes_are_cell_text(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        separator = "| --- | --- | --- | --- |\n"
        canonical = "| B.1 | Task B.1 | Core | — |"
        # An escaped pipe does not end a cell, so a row cannot hide its ID behind one.
        for row in (
            "\\| B.1 | Weaker title | Core | — |", "x \\| B.1 | Weaker title | Core | — |", "| \\| B.1 | Weaker title | Core | — |",
            "| Notes \\| B.1 | Weaker title |", "\\|B.1 | Weaker title", "B.1 \\| Weaker title", "| B.1 \\| Weaker title \\|",
        ):
            with self.subTest(row=row):
                changed = plan.replace(separator, separator + row + "\n", 1)
                self.assert_only(f"duplicate plan table row for B.1 at line {line_of(changed, canonical)}", graph, plan=changed)
                self.assert_only("plan table differs from graph for B.1", graph, plan=plan.replace(canonical, row))
        row = "| Z.9 \\| Unknown \\|"
        changed = plan.replace(separator, separator + row + "\n", 1)
        self.assert_only(f"plan table contains unknown ID Z.9 at line {line_of(changed, row)}", graph, plan=changed)
        # A closing escaped pipe closes nothing: the cell before it is kept and compared.
        for row in (canonical + " x \\|", canonical[:-1] + "\\|", canonical[:-2] + "\\|"):
            with self.subTest(row=row):
                self.assert_only("plan table differs from graph for B.1", graph, plan=plan.replace(canonical, row))
        # A title is compared as written, so an escaped pipe in the plan needs the same text in the graph.
        graph["tasks"][0]["title"] = "Task \\| B.1"
        self.assert_valid(graph)
        graph["tasks"][0]["title"] = "Task | B.1"
        self.assert_only("plan table differs from graph for B.1", graph)

    def test_task_contracts_match_the_graph(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        for changed in (
            plan.replace("### B.1 Task B.1", "### B.1 Changed title"),
            plan.replace("### B.1 Task B.1", "## B.1 Task B.1"),
            plan.replace(f"Acceptance: {SENTENCES[1]} {SENTENCES[2]}", f"Acceptance: {SENTENCES[1]}", 1),
            plan.replace(f"Acceptance: {SENTENCES[1]} {SENTENCES[2]}", f"Acceptance: {SENTENCES[1]} {SENTENCES[2]} More.", 1),
            plan.replace(f"Deliverable: {SENTENCES[0]}", "Deliverable: Different artifact.", 1),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(changed, plan)
                self.assert_only("plan task contract differs from graph for B.1", graph, plan=changed)
        # The contract is its own heading line and paragraphs, with nothing attached.
        acceptance = f"Acceptance: {SENTENCES[1]} {SENTENCES[2]}"
        deliverable = f"Deliverable: {SENTENCES[0]}"
        for changed in (
            plan.replace("### B.1 Task B.1", "#### B.1 Task B.1"),
            plan.replace("### B.1 Task B.1", "x ### B.1 Task B.1"),
            plan.replace("### B.1 Task B.1", "> ### B.1 Task B.1"),
            plan.replace("### B.1 Task B.1", " ### B.1 Task B.1"),
            plan.replace("### B.1 Task B.1", "### B.1 Task B.1 "),
            plan.replace("### B.1 Task B.1\n", "### B.1 Task B.1\nInserted line.\n"),
            plan.replace(acceptance, acceptance + "\nExcept when inconvenient.", 1),
            plan.replace(acceptance, acceptance + " ", 1),
            plan.replace(deliverable, deliverable + "\nOr something smaller.", 1),
            plan.replace(deliverable + "\n\n", deliverable + "\n", 1),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(changed, plan)
                self.assert_only("plan task contract differs from graph for B.1", graph, plan=changed)
        # A trailing newline at the end of the file is not part of the last contract.
        self.assert_valid(graph, plan=plan + "\n")
        self.assert_only("plan task contract differs from graph for V.6", graph, plan=plan + "\nMore.")
        last = f"\n### V.6 Task V.6\n\nDeliverable: {SENTENCES[0]}\n\nAcceptance: {SENTENCES[1]} {SENTENCES[2]}"
        self.assertTrue(plan.endswith(last))
        self.assert_only("plan task contract differs from graph for V.6", graph, plan=plan[:-len(last)])

    def test_task_contract_holds_every_list_item_in_exact_case(self) -> None:
        for field in ("outputs", "acceptance"):
            for position in (0, 1):
                with self.subTest(field=field, position=position):
                    graph = fixture()
                    plan = markdown(graph)
                    graph["tasks"][0][field].insert(position, "Another list item.")
                    self.assert_only("plan task contract differs from graph for B.1", graph, plan=plan)
                    self.assertEqual(markdown(graph).count("Another list item."), 1)
                    self.assert_valid(graph, plan=markdown(graph))
        graph = fixture()
        plan = markdown(graph)
        for old, new in (
            ("### B.1 Task B.1", "### B.1 TASK B.1"), ("### B.1 Task B.1", "### B.1 task B.1"),
            (f"Deliverable: {SENTENCES[0]}", f"Deliverable: {SENTENCES[0].upper()}"),
            (f"Deliverable: {SENTENCES[0]}", f"deliverable: {SENTENCES[0]}"),
            (f"Acceptance: {SENTENCES[1]}", f"Acceptance: {SENTENCES[1].lower()}"),
            (f"Acceptance: {SENTENCES[1]}", f"ACCEPTANCE: {SENTENCES[1]}"),
        ):
            with self.subTest(new=new):
                changed = plan.replace(old, new, 1)
                self.assertNotEqual(changed, plan)
                self.assert_only("plan task contract differs from graph for B.1", graph, plan=changed)

    def test_task_contract_headings_equal_the_task_ids(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        for heading, message in (
            ("### B.1 Task B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("#### B.1 Task B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("# B.1 Task B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("   ### B.1\tTask B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("###\tB.1 Task B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("###  B.1", "duplicate plan task contract heading for B.1 at line {}"),
            ("### Z.9 Ghost task", "plan contains a task contract heading for unknown ID Z.9 at line {}"),
            ("### D.1 Delivery", "plan contains a task contract heading for unknown ID D.1 at line {}"),
        ):
            with self.subTest(heading=heading):
                # A second, weaker contract must not hide behind the matching one.
                changed = plan + f"\n\n{heading}\n\nDeliverable: Something weaker.\n\nAcceptance: Nothing."
                occurrence = 2 if heading == "### B.1 Task B.1" else 1
                self.assert_only(message.format(line_of(changed, heading, occurrence)), graph, plan=changed)
        # Headings that do not name a dotted ID are not task contracts.
        self.assert_valid(graph, plan=plan + "\n\n### Notes\n\nText.\n\n## Appendix\n\nText.")
        # The first and the last line of the plan are read like any other.
        changed = "### B.1 Weaker\n\n" + plan
        self.assert_only(f"duplicate plan task contract heading for B.1 at line {line_of(changed, '### B.1 Task B.1')}", graph, plan=changed)
        self.assert_only("plan contains a task contract heading for unknown ID Z.9 at line 1", graph, plan="# Z.9 Ghost\n\n" + plan)
        self.assert_only("plan table contains unknown ID Z.9 at line 1", graph, plan="| Z.9 | Ghost | Core | — |\n\n" + plan)
        last = len(plan.splitlines()) + 2
        self.assert_only(f"duplicate plan task contract heading for B.1 at line {last}", graph, plan=plan + "\n\n### B.1 Weaker")
        self.assert_only(f"plan table contains unknown ID Z.9 at line {last}", graph, plan=plan + "\n\n| Z.9 | Ghost | Core | — |")
        # An unknown ID is reported where it first appears and as a repeat afterwards.
        changed = plan + "\n\n### Z.9 Ghost\n\n### Z.9 Ghost again"
        self.assert_only([
            f"plan contains a task contract heading for unknown ID Z.9 at line {line_of(changed, '### Z.9 Ghost')}",
            f"duplicate plan task contract heading for Z.9 at line {line_of(changed, '### Z.9 Ghost again')}",
        ], graph, plan=changed)

    def test_decorated_titles_are_still_task_headings(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        weaker = "\n\nDeliverable: Something weaker.\n\nAcceptance: Nothing."
        for title in (
            "### B.1: Task B.1", "### B.1. Task B.1", "### B.1, Task B.1", "### B.1.2 Task B.1", "### v2.B.1 Task B.1",
            "### /B.1 Task B.1", "### __B.1 Task B.1", "### **B.1** Task B.1", "### `B.1` Task B.1",
            "### *B.1* Task B.1", "### [B.1](#b1) Task B.1", "### (B.1) Task B.1", "### Task B.1 again", "###B.1 Task B.1",
            "####### B.1 Task B.1", "> ### B.1 Task B.1", ">### B.1 Task B.1", "> > ### B.1 Task B.1", "- ### B.1 Task B.1",
            "* ### B.1 Task B.1", "+ ### B.1 Task B.1", "1. ### B.1 Task B.1", "2) ### B.1 Task B.1", "\t### B.1 Task B.1",
            "     ### B.1 Task B.1", "- > ### B.1 Task B.1", "<h3>B.1 Task B.1</h3>", "<H2 id=\"b1\">B.1 Task B.1</H2>",
            "**B.1 Task B.1**", "__B.1 Task B.1__", "*B.1 Task B.1*", "_B.1 Task B.1_", "***B.1 Task B.1***", "**B.1 Task B.1** ",
            "- **B.1 Task B.1**", "> **B.1 Task B.1**", "**Task B.1**", "### B.1 | Task B.1", "**B.1 | Task B.1**",
        ):
            with self.subTest(title=title):
                changed = plan + f"\n\n{title}{weaker}"
                self.assert_only(f"duplicate plan task contract heading for B.1 at line {line_of(changed, title)}", graph, plan=changed)
        for underline in ("===", "=", "---", "-", "=== ", "-----\t"):
            with self.subTest(underline=underline):
                changed = plan + f"\n\nB.1 Task B.1\n{underline}{weaker}"
                self.assert_only(f"duplicate plan task contract heading for B.1 at line {line_of(changed, 'B.1 Task B.1')}", graph, plan=changed)
        # The underline may be the last line of the plan.
        for ending in ("===", "---\n"):
            changed = plan + f"\n\nB.1 Task B.1\n{ending}"
            self.assert_only(f"duplicate plan task contract heading for B.1 at line {line_of(changed, 'B.1 Task B.1')}", graph, plan=changed)
        changed = plan + f"\n\n> B.1 Task B.1\n> ==={weaker}"
        self.assert_only(f"duplicate plan task contract heading for B.1 at line {line_of(changed, '> B.1 Task B.1')}", graph, plan=changed)
        for title, identifier in (
            ("### **Z.9** Ghost", "Z.9"), ("**Z.9 Ghost**", "Z.9"), ("<h4>D.1 Delivery</h4>", "D.1"), ("### __B.1__ Task", "B.1__"),
            ("### X-B.1 Task", "X-B.1"), ("### X_B.1 Task", "X_B.1"),
        ):
            changed = plan + f"\n\n{title}{weaker}"
            self.assert_only(
                f"plan contains a task contract heading for unknown ID {identifier} at line {line_of(changed, title)}", graph, plan=changed,
            )
        # The decorated form never stands in for the contract itself.
        changed = plan.replace("### B.1 Task B.1", "### **B.1** Task B.1")
        self.assert_only("plan task contract differs from graph for B.1", graph, plan=changed)
        # Prose, lists, quotes, code and rules that mention a task are not titles.
        for text in (
            "B.1 delivers the first artifact.", "B.1 delivers the first artifact.\n\n---", "**B.1** is the first root.",
            "See **B.1** and `C.1` for details.", "*B.1* and C.1 follow", "- B.1 first\n- C.1 second", "> B.1 quoted",
            "1. B.1 numbered", "`B.1`", "#hashtag", "### Version 1.2 and v1.B", "**Status: ready.**", "<hr>\nB.1 follows",
            "### 3B.1 and xB.1 are not IDs", "### pre-B.1 and a_B.1 are not IDs", "### b.1 lower case", "<header>B.1</header>",
            "<h7>B.1</h7>", "**B.1 Task B.1** follows",
            "B.1 delivers.\n=-=", "B.1 delivers.\n", "\\### B.1 escaped", "See C.1 and also **B.1**", "Details are in `B.1` and *C.1*",
            "12 ### B.1 is prose", "2026 #1 B.1 note",
            "B.1 delivers.\n== not an underline", "B.1 delivers.\n-- x",
        ):
            with self.subTest(text=text):
                self.assert_valid(graph, plan=plan + f"\n\n{text}")

    def test_stated_roots_equal_start_immediately_in_order(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        stated = "Start in parallel at **B.1, R.1, H.3, V.4, V.6**."
        message = "plan prose must state once: Start in parallel at **B.1, R.1, H.3, V.4, V.6**."
        self.assertEqual(plan.count(stated), 1)
        for replacement in (
            "Start in parallel at **B.1, R.1, H.3, V.4**.",
            "Start in parallel at **R.1, B.1, H.3, V.4, V.6**.",
            "Start in parallel at **B.1, R.1, H.3, V.4, V.6, P.5**.",
            "Start in parallel at **B.1,R.1,H.3,V.4,V.6**.",
            "Start in parallel at B.1, R.1, H.3, V.4, V.6.",
            "Start anywhere.",
            stated + "\n\n" + stated,
            stated + "\n\nStart in parallel at **B.1**.",
            # The list is bold, the words keep their case, and the sentence ends with the list.
            "Start in parallel at *B.1, R.1, H.3, V.4, V.6*.",
            "Start in parallel at ***B.1, R.1, H.3, V.4, V.6***.",
            "Start in parallel at __B.1, R.1, H.3, V.4, V.6__.",
            "start in parallel at **B.1, R.1, H.3, V.4, V.6**.",
            "START IN PARALLEL AT **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel at **B.1, R.1, H.3, V.4, V.6**, P.5.",
            "Start in parallel at **B.1, R.1, H.3, V.4, V.6** and P.5.",
            "Start in parallel at **B.1, R.1, H.3, V.4, V.6**",
            "Start in parallel at **B.1, R.1, H.3, V.4, V.6**!",
            stated + " Start in parallel at **B.1, R.1, H.3, V.4, V.6** or at P.5.",
            # One line break stands for one space; no other spacing does.
            "Start in parallel  at **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel\tat **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel\u00a0at **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel\n\nat **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel \nat **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallel\n at **B.1, R.1, H.3, V.4, V.6**.",
            "Start in parallelat **B.1, R.1, H.3, V.4, V.6**.",
            # The statement is its own words, not the tail of another word.
            "x" + stated,
        ):
            with self.subTest(replacement=replacement):
                self.assert_only(message, graph, plan=plan.replace(stated, replacement))
        # A second statement is seen wherever it stands and in any case, spacing or emphasis:
        # the opening words appear once in the plan.
        for second in (
            "Start in parallel at **B.1**", "Start in parallel at **B.1, R.1, H.3, V.4, V.6**", "start in parallel at **B.1**.",
            "START IN PARALLEL AT **B.1**.", "Start  in parallel at **B.1**.", "Start\tin parallel\u00a0at **B.1**.",
            "Start\nin\n\nparallel at **B.1**.", "Start in parallel at *B.1*.", "Start in parallel at __B.1__.",
            "Start in parallel at B.1.", "Then start in parallel at the next stage.", "> Start in parallel at **B.1**.",
            "(start in parallel at)", "**Start in parallel at** the roots.",
        ):
            with self.subTest(second=second):
                self.assert_only(message, graph, plan=plan + "\n\n" + second)
                self.assert_only(message, graph, plan=second + "\n\n" + plan)
        # Other words are not that statement.
        for other in (
            "Start in parallel.", "Start at **B.1**.", "Start in parallel with **B.1**.", "In parallel, start at **B.1**.",
            "Restart in parallel at **B.1**.", "Start in parallel attic **B.1**.", "Start in parallel, at **B.1**.",
        ):
            with self.subTest(other=other):
                self.assert_valid(graph, plan=plan + "\n\n" + other)
        # Line wrapping is the only tolerated difference.
        self.assert_valid(graph, plan=plan.replace(stated, "Start in parallel\nat **B.1, R.1,\nH.3, V.4, V.6**."))
        self.assert_valid(graph, plan=plan.replace(stated, "Start\nin\nparallel\nat\n**B.1,\nR.1,\nH.3,\nV.4,\nV.6**."))

    def test_stated_counts_equal_the_files(self) -> None:
        graph = fixture()
        plan = markdown(graph)
        graph_message = "plan prose must state once: contains 7 implementation/evidence tasks and 2 named deliveries"
        for old, new, message in (
            ("contains 7 implementation", "contains 6 implementation", graph_message),
            ("contains 7 implementation", "contains 07 implementation", graph_message),
            ("tasks and 2 named", "tasks and 3 named", graph_message),
            ("contains 7 implementation", "holds 7 implementation", graph_message),
            ("preserves 119 verbatim", "preserves 118 verbatim", LEDGER_PROSE),
            ("all 23 revision-6", "all 22 revision-6", LEDGER_PROSE),
            ("all 133 earlier", "all 134 earlier", LEDGER_PROSE),
            ("all 52 original", "all 51 original", LEDGER_PROSE),
            ("all 52 original graph tasks.", "all 52 original tasks.", LEDGER_PROSE),
            # One line break stands for one space; no other spacing does, and the words keep their case.
            ("contains 7 implementation", "contains  7 implementation", graph_message),
            ("contains 7 implementation", "contains\t7 implementation", graph_message),
            ("contains 7 implementation", "contains\u00a07 implementation", graph_message),
            ("contains 7 implementation", "Contains 7 implementation", graph_message),
            ("implementation/evidence\ntasks", "implementation/evidence\n\ntasks", graph_message),
            ("implementation/evidence\ntasks", "implementation/evidence \ntasks", graph_message),
            ("implementation/evidence\ntasks", "implementation/evidencetasks", graph_message),
            ("findings,\nall 133", "findings,\n\nall 133", LEDGER_PROSE),
            ("findings,\nall 133", "findings,\n all 133", LEDGER_PROSE),
            ("findings,\nall 133", "findings,all 133", LEDGER_PROSE),
            ("all 52 original", "All 52 original", LEDGER_PROSE),
            # The statement is its own words, not a part of longer ones.
            ("contains 7 implementation", "miscontains 7 implementation", graph_message),
            ("named deliveries. The", "named deliveriesx. The", graph_message),
            ("preserves 119 verbatim", "xpreserves 119 verbatim", LEDGER_PROSE),
            ("original graph tasks.", "original graph tasksx.", LEDGER_PROSE),
        ):
            with self.subTest(new=new):
                self.assertEqual(plan.count(old), 1)
                self.assert_only(message, graph, plan=plan.replace(old, new))
        # Wrapping is free: either statement may stand on one line or on many.
        self.assert_valid(graph, plan=plan.replace("implementation/evidence\ntasks", "implementation/evidence tasks").replace("findings,\nall 133", "findings, all 133"))
        self.assert_valid(graph, plan=plan.replace("contains 7 implementation", "contains\n7\nimplementation").replace("all 52 original", "all\n52\noriginal"))
        # A sentence without its numbers is not a count statement.
        self.assert_valid(graph, plan=plan + "\n\nNothing contains  implementation/evidence tasks and  named deliveries here.")
        # A second, contradicting statement is not hidden by the first.
        self.assert_only(
            graph_message, graph,
            plan=plan + "\n\nIt contains 5 implementation/evidence tasks and 2 named deliveries.",
        )
        self.assert_only(
            LEDGER_PROSE, graph,
            plan=plan + "\n\nIt preserves 119 verbatim revision-6 requirement units, all 23 revision-6 findings, "
            "all 133 earlier report IDs and all 52 original graph tasks.",
        )
        # Nor by its letter case, its spacing or what it writes where a number belongs.
        for second, message in (
            ("It contains 7 implementation/evidence tasks and 2 named deliveries.", graph_message),
            ("It CONTAINS 5 Implementation/Evidence tasks and 2 named deliveries.", graph_message),
            ("It contains  5 implementation/evidence\ttasks\u00a0and 2 named deliveries.", graph_message),
            ("It contains 5\n\nimplementation/evidence tasks and 2 named deliveries.", graph_message),
            ("It contains seven implementation/evidence tasks and two named deliveries.", graph_message),
            ("It contains **5** implementation/evidence tasks and ~2 named deliveries.", graph_message),
            ("(contains 5 implementation/evidence tasks and 2 named deliveries)", graph_message),
            (
                "It Preserves 100 verbatim revision-6 requirement units,  all twenty revision-6 findings, all 133 earlier report ids "
                "and all 52 original graph tasks.", LEDGER_PROSE,
            ),
        ):
            with self.subTest(second=second):
                self.assert_only(message, graph, plan=plan + "\n\n" + second)
                self.assert_only(message, graph, plan=second + "\n\n" + plan)
        # Other words are not those statements.
        for other in (
            "It contains 5 implementation tasks and 2 named deliveries.", "It contains 5 implementation/evidence tasks.",
            "It contains no more implementation/evidence tasks and 2 named deliveries.",
            "It miscontains 5 implementation/evidence tasks and 2 named deliveries.",
            "It contains 5 implementation/evidence tasks and 2 named deliveriesx.",
            "It preserves 119 verbatim revision-6 requirement units.",
        ):
            with self.subTest(other=other):
                self.assert_valid(graph, plan=plan + "\n\n" + other)


class LedgerTests(CheckerCase):
    """Embedded source inventories, mappings, counts and the source fingerprint."""

    def assert_ledger_only(self, message: str | list[str], change, *, recertify: bool = False) -> None:
        graph, ledger = fixture(), ledger_fixture()
        change(ledger)
        if recertify:
            refresh_fingerprint(graph, ledger)
        self.assert_only(message, graph, ledger=ledger)

    def assert_error_in_ledger(self, message: str, change) -> None:
        graph, ledger = fixture(), ledger_fixture()
        change(ledger)
        self.assert_error(message, graph, ledger=ledger)

    def test_missing_original_sources_do_not_block_validation(self) -> None:
        graph, ledger = fixture(), ledger_fixture()
        self.assertFalse((CHECKER.ROOT / ledger["sources"][0]["path"]).exists())
        self.assert_valid(graph, ledger=ledger)

    def test_ledger_and_baseline_shapes(self) -> None:
        graph = fixture()
        for ledger in ([], "ledger", 5):
            self.assert_only("reconciliation must be an object", graph, ledger=ledger)
        for value in (2, True, "1", None):
            ledger = ledger_fixture()
            ledger["schema_version"] = value
            self.assert_only("reconciliation.schema_version must be 1", graph, ledger=ledger)
        self.assert_only("reconciliation.schema_version must be 1", graph, ledger={})
        for baseline in (None, [], "baseline"):
            graph = fixture()
            graph["reconciliation_baseline"] = baseline
            self.assert_only("reconciliation_baseline must be an object", graph)
        for key in ("requirement_ids", "original_task_ids"):
            listed = fixture()["reconciliation_baseline"][key]
            for value in (
                [], None, [5], [" "], ["A", "A"], ["A", 5], [5, "A"], ["A", " ", "B"], ["A", "B", "A"], ["A", "B", "B"],
                # The same IDs in anything but a list are not a baseline.
                "AB", 7, True, dict.fromkeys(listed, 1), {"ids": listed},
            ):
                with self.subTest(key=key, value=value):
                    graph = fixture()
                    graph["reconciliation_baseline"][key] = value
                    self.assert_only(f"reconciliation_baseline.{key} must be unique nonempty IDs", graph)
        for value in ("xyz", 5, None, "0" * 63, "A" * 64, "0" * 65, "g" * 64, "0" * 63 + "G", "0" * 64 + "\n", ["0" * 64]):
            graph = fixture()
            graph["reconciliation_baseline"]["ledger_inventory_sha256"] = value
            self.assert_only("reconciliation_baseline.ledger_inventory_sha256 must be a SHA256 digest", graph)
        # The baseline is exactly REQ-001 through REQ-119: nothing may be added beside them.
        for extra in ("REQ-120", "REQ-000", "REQ-1"):
            graph = fixture()
            graph["reconciliation_baseline"]["requirement_ids"].append(extra)
            self.assert_only("reconciliation_baseline.requirement_ids must preserve REQ-001 through REQ-119", graph)

    def test_sections_are_nonempty_lists_of_identified_objects(self) -> None:
        for section in ("sources", "requirements", "findings", "prior_findings", "original_tasks"):
            for value in ([], None, {}, 7, True, "records", {"id": "r6"}):
                with self.subTest(section=section, value=value):
                    graph, ledger = fixture(), ledger_fixture()
                    ledger[section] = value
                    self.assert_error(f"reconciliation.{section} must be a nonempty list", graph, ledger=ledger)
            self.assert_ledger_only(
                f"reconciliation.{section} records must be objects", lambda ledger: ledger[section].append(None),
            )
            for identifier in ("", " ", 5, None):
                self.assert_ledger_only(
                    f"reconciliation.{section} IDs must be nonempty strings",
                    lambda ledger: ledger[section].append({"id": identifier}),
                )
            graph, ledger = fixture(), ledger_fixture()
            ledger[section].append(dict(ledger[section][0]))
            self.assert_only(f"duplicate reconciliation.{section} ID {ledger[section][0]['id']}", graph, ledger=ledger)
            # The first record keeps the ID; a repeat is reported once and not examined further.
            ledger[section][-1] = {"id": ledger[section][0]["id"], "task_ids": ["MISSING.1"], "path": "", "sha256": ""}
            self.assert_only(f"duplicate reconciliation.{section} ID {ledger[section][0]['id']}", graph, ledger=ledger)

    def test_all_original_inventories_are_complete(self) -> None:
        for section in ("requirements", "findings", "prior_findings", "original_tasks"):
            with self.subTest(section=section):
                graph, ledger = fixture(), ledger_fixture()
                dropped = ledger[section].pop()["id"]
                self.assert_error(
                    f"reconciliation.{section} inventory differs: missing {dropped}; unexpected none", graph, ledger=ledger,
                )

    def test_inventory_differences_are_listed_in_order(self) -> None:
        graph, ledger = fixture(), ledger_fixture()
        dropped = [ledger["requirements"].pop(index)["id"] for index in (110, 90, 70, 50, 40, 30, 20, 10, 0)]
        for index in range(9):
            ledger["requirements"].append(dict(ledger["requirements"][0], id=f"REQ-9{8 - index}0"))
        self.assertEqual(sorted(dropped), dropped[::-1])
        self.assert_only(
            f"reconciliation.requirements inventory differs: missing {', '.join(dropped[::-1])}; "
            f"unexpected {', '.join(f'REQ-9{index}0' for index in range(9))}",
            graph, ledger=ledger,
        )

    def test_inventories_admit_no_extra_records(self) -> None:
        for section, identifier, counted in (
            ("requirements", "REQ-120", ("requirements",)),
            ("findings", "R6-23", ("r6_findings",)),
            ("prior_findings", "F133", ("prior_findings", "prior_carried_forward")),
            ("original_tasks", "O.52", ("original_tasks",)),
        ):
            with self.subTest(section=section):
                graph, ledger = fixture(), ledger_fixture()
                extra = json.loads(json.dumps(ledger[section][0]))
                extra["id"] = identifier
                if section == "original_tasks":
                    extra["original_record"]["id"] = identifier
                ledger[section].append(extra)
                for key in counted:
                    ledger["counts"][key] += 1
                refresh_fingerprint(graph, ledger)
                self.assert_only(
                    f"reconciliation.{section} inventory differs: missing none; unexpected {identifier}", graph, ledger=ledger,
                )

    def test_inventories_cannot_be_self_certified_through_the_baseline(self) -> None:
        graph, ledger = fixture(), ledger_fixture()
        ledger["requirements"].pop()
        graph["reconciliation_baseline"]["requirement_ids"].pop()
        ledger["counts"]["requirements"] = 118
        refresh_fingerprint(graph, ledger)
        self.assert_only([
            "reconciliation_baseline.requirement_ids must preserve REQ-001 through REQ-119",
            "reconciliation.requirements inventory differs: missing REQ-119; unexpected none",
        ], graph, ledger=ledger)
        message = "reconciliation_baseline.original_task_ids must preserve all 52 original tasks"
        graph, ledger = fixture(), ledger_fixture()
        ledger["original_tasks"].pop()
        graph["reconciliation_baseline"]["original_task_ids"].pop()
        ledger["counts"]["original_tasks"] = 51
        refresh_fingerprint(graph, ledger)
        self.assert_only(message, graph, ledger=ledger)
        graph, ledger = fixture(), ledger_fixture()
        extra = {"id": "O.52", "original_record": {"id": "O.52"}, "task_ids": ["B.1"], "rationale": ledger["original_tasks"][0]["rationale"]}
        ledger["original_tasks"].append(extra)
        graph["reconciliation_baseline"]["original_task_ids"].append("O.52")
        ledger["counts"]["original_tasks"] = 53
        refresh_fingerprint(graph, ledger)
        self.assert_only(message, graph, ledger=ledger)

    def test_sources_are_declared_with_digests(self) -> None:
        self.assert_error_in_ledger("source r6.path must be nonempty", lambda ledger: ledger["sources"][0].update(path=" "))
        for value in ("not a hash", None, "0" * 63, "0" * 65, "g" * 64, "0" * 63 + "G", "A" * 64, "0" * 64 + "\n", ["0" * 64]):
            self.assert_ledger_only(
                "source r6.sha256 must be a SHA256 digest", lambda ledger: ledger["sources"][0].update(sha256=value),
            )
        for value in (False, 1, None):
            self.assert_ledger_only(
                "source r6.available_optional must be true",
                lambda ledger: ledger["sources"][0].update(available_optional=value),
            )
        # Every declared source is checked, not only the first or the last one.
        second = {"id": "r5", "path": "dist/zk_checker_second_absent_source.md", "sha256": "1" * 64, "available_optional": True}
        for position in (0, 1, 2):
            graph, ledger = fixture(), ledger_fixture()
            ledger["sources"].append({**second, "id": "r4"})
            ledger["sources"].insert(position, dict(second))
            refresh_fingerprint(graph, ledger)
            self.assert_valid(graph, ledger=ledger)
            for change, message in (
                ({"path": ""}, "source r5.path must be nonempty"),
                ({"path": None}, "source r5.path must be nonempty"),
                ({"sha256": "1" * 63}, "source r5.sha256 must be a SHA256 digest"),
                ({"available_optional": False}, "source r5.available_optional must be true"),
            ):
                with self.subTest(position=position, change=change):
                    ledger["sources"][position] = {**second, **change}
                    self.assert_only(message, graph, ledger=ledger)

    def test_every_record_maps_to_existing_tasks(self) -> None:
        for section, identifier in (("requirements", "REQ-001"), ("findings", "R6-0"), ("prior_findings", "F0"), ("original_tasks", "O.0")):
            for mapping in (["MISSING.1"], [], None, [{}], ["D.1"], "B.1", {"B.1": 1}, {"B.1": 1, "C.1": 2}, 7, True):
                with self.subTest(section=section, mapping=mapping):
                    self.assert_ledger_only(
                        f"{identifier}.task_ids must map to existing tasks",
                        lambda ledger: ledger[section][0].update(task_ids=mapping),
                    )
            self.assert_ledger_only(
                f"{identifier}.task_ids contains duplicates",
                lambda ledger: ledger[section][0].update(task_ids=["B.1", "C.1", "B.1"]),
            )
            for rationale in ("TODO", None, " " * 40, "x" * 19, " " + "x" * 19 + " "):
                self.assert_ledger_only(
                    f"{identifier}.rationale must explain the mapping (at least 20 characters)",
                    lambda ledger: ledger[section][0].update(rationale=rationale),
                )
            graph, ledger = fixture(), ledger_fixture()
            ledger[section][0]["rationale"] = "x" * 20
            self.assert_valid(graph, ledger=ledger)

    def test_every_record_and_every_mapped_task_is_checked(self) -> None:
        for section in ("requirements", "findings", "prior_findings", "original_tasks"):
            for index in (0, 1, 11, -1):
                identifier = ledger_fixture()[section][index]["id"]
                for change, message in (
                    ({"task_ids": ["MISSING.1"]}, f"{identifier}.task_ids must map to existing tasks"),
                    ({"task_ids": ["B.1", "B.1"]}, f"{identifier}.task_ids contains duplicates"),
                    ({"rationale": "TODO"}, f"{identifier}.rationale must explain the mapping (at least 20 characters)"),
                ):
                    with self.subTest(section=section, index=index, change=change):
                        self.assert_ledger_only(message, lambda ledger: ledger[section][index].update(change))
            for mapping in (["B.1", "MISSING.1"], ["MISSING.1", "B.1"], ["B.1", "MISSING.1", "C.1"], ["B.1", 5], [None, "B.1"]):
                with self.subTest(section=section, mapping=mapping):
                    self.assert_ledger_only(
                        f"{ledger_fixture()[section][0]['id']}.task_ids must map to existing tasks",
                        lambda ledger: ledger[section][0].update(task_ids=mapping),
                    )
        for section, index, change, message in (
            ("requirements", 7, {"disposition": "fixed_in_code"}, "REQ-008.disposition is not a supported source disposition"),
            ("requirements", 7, {"summary": " "}, "REQ-008.summary must be nonempty"),
            ("findings", 22, {"disposition": None}, "R6-22.disposition is not a supported source disposition"),
            ("findings", 22, {"severity": "critical"}, "R6-22.severity must be blocker, major or minor"),
            ("findings", 9, {"source": None}, "R6-9.source must identify original source lines"),
            ("prior_findings", 132, {"original_record": {}}, "F132.original_record must preserve the original object"),
            ("original_tasks", 51, {"original_record": {"id": "O.50"}}, "O.51.original_record.id differs from the original task ID"),
        ):
            with self.subTest(section=section, change=change):
                self.assert_ledger_only(message, lambda ledger: ledger[section][index].update(change))
        # An unsupported prior disposition is neither carried forward nor superseded.
        self.assert_ledger_only(
            ["F5.disposition is not a supported source disposition", COUNTS_RULE.replace("forward 133", "forward 132")],
            lambda ledger: ledger["prior_findings"][5].update(disposition="fixed_in_code"),
        )

    def test_ledger_vocabularies_are_pinned(self) -> None:
        dispositions = {
            "requirements": ("retained", "corrected"),
            "findings": ("addressed_in_plan", "addressed_with_correction"),
            "prior_findings": ("carried_forward", "superseded_by_user_direction"),
        }
        self.assertEqual(CHECKER.LEDGER_DISPOSITIONS, dispositions)
        self.assertEqual(CHECKER.FINDING_SEVERITIES, ("blocker", "major", "minor"))
        every = [word for words in dispositions.values() for word in words]
        for section in dispositions:
            for index in (0, 11, -1):
                identifier = ledger_fixture()[section][index]["id"]
                # Each section admits its own two words and no word of another section.
                for word in every + ["Retained", "retained ", "dropped", "wontfix", "ignored", "", ["retained"], {"retained": 1}]:
                    with self.subTest(section=section, index=index, word=word):
                        graph, ledger = fixture(), ledger_fixture()
                        ledger[section][index]["disposition"] = word
                        if section == "prior_findings":
                            ledger["counts"].update(
                                prior_carried_forward=132 + (word == "carried_forward"),
                                prior_superseded_by_user_direction=int(word == "superseded_by_user_direction"),
                            )
                        if word in dispositions[section]:
                            self.assert_valid(graph, ledger=ledger)
                        else:
                            self.assert_only(f"{identifier}.disposition is not a supported source disposition", graph, ledger=ledger)
        for index in (0, 11, -1):
            identifier = ledger_fixture()["findings"][index]["id"]
            for severity in ("blocker", "major", "minor"):
                graph, ledger = fixture(), ledger_fixture()
                ledger["findings"][index]["severity"] = severity
                self.assert_valid(graph, ledger=ledger)
            for severity in ("info", "critical", "Major", "minor ", "", None, ["minor"], 1):
                with self.subTest(index=index, severity=severity):
                    self.assert_ledger_only(
                        f"{identifier}.severity must be blocker, major or minor",
                        lambda ledger: ledger["findings"][index].update(severity=severity),
                    )

    def test_no_ledger_field_has_a_default(self) -> None:
        # An absent field is never read as its permitted value.
        self.assert_ledger_only("reconciliation.schema_version must be 1", lambda ledger: ledger.pop("schema_version"))
        self.assert_ledger_only(COUNTS_RULE, lambda ledger: ledger.pop("counts"))
        mapping = "{}.task_ids must map to existing tasks"
        rationale = "{}.rationale must explain the mapping (at least 20 characters)"
        disposition = "{}.disposition is not a supported source disposition"
        source = "{}.source must identify original source lines"
        original = "{}.original_record must preserve the original object"
        for section, identifier, fields in (
            ("sources", "r6", {
                "id": "reconciliation.sources IDs must be nonempty strings", "path": "source r6.path must be nonempty",
                "sha256": "source r6.sha256 must be a SHA256 digest", "available_optional": "source r6.available_optional must be true",
            }),
            ("requirements", "REQ-001", {
                "id": "reconciliation.requirements IDs must be nonempty strings", "source": source,
                "original_text": "{}.original_text must be nonempty", "summary": "{}.summary must be nonempty",
                "disposition": disposition, "task_ids": mapping, "rationale": rationale,
            }),
            ("findings", "R6-0", {
                "id": "reconciliation.findings IDs must be nonempty strings", "source": source,
                "original_text": "{}.original_text must be nonempty", "title": "{}.title must be nonempty",
                "severity": "{}.severity must be blocker, major or minor", "disposition": disposition, "task_ids": mapping,
                "rationale": rationale,
            }),
            ("prior_findings", "F0", {
                "id": "reconciliation.prior_findings IDs must be nonempty strings", "source": source, "original_record": original,
                "disposition": disposition, "task_ids": mapping, "rationale": rationale,
            }),
            ("original_tasks", "O.0", {
                "id": "reconciliation.original_tasks IDs must be nonempty strings", "original_record": original,
                "task_ids": mapping, "rationale": rationale,
            }),
        ):
            self.assert_error_in_ledger(f"reconciliation.{section} must be a nonempty list", lambda ledger: ledger.pop(section))
            self.assertEqual(set(fields), set(ledger_fixture()[section][0]))
            for field, message in fields.items():
                with self.subTest(section=section, field=field):
                    self.assert_error_in_ledger(message.format(identifier), lambda ledger: ledger[section][0].pop(field))
        for section, identifier in (("requirements", "REQ-001"), ("findings", "R6-0"), ("prior_findings", "F0")):
            for field in ("source_id", "path"):
                self.assert_ledger_only(
                    f"{identifier}.source must reference a declared source and its exact path",
                    lambda ledger: ledger[section][0]["source"].pop(field),
                )
            for field in ("line_start", "line_end"):
                self.assert_ledger_only(
                    f"{identifier}.source must contain a positive ordered line span", lambda ledger: ledger[section][0]["source"].pop(field),
                )
        for field, message in (
            ("triage", "F0.original_record.triage must preserve the original object"),
            ("original_report_text", "F0.original_record.original_report_text must be nonempty"),
        ):
            self.assert_ledger_only(message, lambda ledger: ledger["prior_findings"][0]["original_record"].pop(field))
        self.assert_ledger_only(
            "O.0.original_record.id differs from the original task ID", lambda ledger: ledger["original_tasks"][0]["original_record"].pop("id"),
        )

    def test_dispositions_and_record_metadata(self) -> None:
        for section, identifier in (("requirements", "REQ-001"), ("findings", "R6-0"), ("prior_findings", "F0")):
            for disposition in ("fixed_in_code", None, []):
                with self.subTest(section=section, disposition=disposition):
                    self.assert_error_in_ledger(
                        f"{identifier}.disposition is not a supported source disposition",
                        lambda ledger: ledger[section][0].update(disposition=disposition),
                    )
            # A record without the field has no disposition.
            self.assert_error_in_ledger(
                f"{identifier}.disposition is not a supported source disposition", lambda ledger: ledger[section][0].pop("disposition"),
            )
        for section, identifier, field in (
            ("requirements", "REQ-001", "original_text"), ("requirements", "REQ-001", "summary"),
            ("findings", "R6-0", "original_text"), ("findings", "R6-0", "title"),
        ):
            for value in ("", " ", None):
                self.assert_ledger_only(
                    f"{identifier}.{field} must be nonempty", lambda ledger: ledger[section][0].update({field: value}),
                )
        for severity in ("critical", None):
            self.assert_ledger_only(
                "R6-0.severity must be blocker, major or minor", lambda ledger: ledger["findings"][0].update(severity=severity),
            )
        for section, identifier, values in (
            ("prior_findings", "F0", ("missing original", {}, None)), ("original_tasks", "O.0", ("missing original", [], None)),
        ):
            for value in values:
                self.assert_ledger_only(
                    f"{identifier}.original_record must preserve the original object",
                    lambda ledger: ledger[section][0].update(original_record=value),
                )
        graph, ledger = fixture(), ledger_fixture()
        ledger["original_tasks"][0]["original_record"] = {}
        self.assert_only([
            "O.0.original_record must preserve the original object",
            "O.0.original_record.id differs from the original task ID",
        ], graph, ledger=ledger)
        for value in ([], {}, None, "text", ["triage"], 7, True):
            self.assert_ledger_only(
                "F0.original_record.triage must preserve the original object",
                lambda ledger: ledger["prior_findings"][0]["original_record"].update(triage=value),
            )
        for value in (" ", 5):
            self.assert_ledger_only(
                "F0.original_record.original_report_text must be nonempty",
                lambda ledger: ledger["prior_findings"][0]["original_record"].update(original_report_text=value),
            )
        for value in ("O.1", None):
            self.assert_ledger_only(
                "O.0.original_record.id differs from the original task ID",
                lambda ledger: ledger["original_tasks"][0]["original_record"].update(id=value),
            )

    def test_source_references_name_declared_sources_and_line_spans(self) -> None:
        for section, identifier in (("requirements", "REQ-001"), ("findings", "R6-0"), ("prior_findings", "F0")):
            for value in ([], None, "r6"):
                self.assert_ledger_only(
                    f"{identifier}.source must identify original source lines",
                    lambda ledger: ledger[section][0].update(source=value),
                )
            # A missing reference is reported; it must not reach the fingerprint as an exception.
            self.assert_ledger_only(
                f"{identifier}.source must identify original source lines", lambda ledger: ledger[section][0].pop("source"),
            )
            for field, value in (("source_id", "missing"), ("source_id", []), ("source_id", None), ("path", "wrong")):
                self.assert_ledger_only(
                    f"{identifier}.source must reference a declared source and its exact path",
                    lambda ledger: ledger[section][0]["source"].update({field: value}),
                )
            for start, end in ((2, 1), (0, 1), (True, 1), (1, "2"), (None, None)):
                self.assert_ledger_only(
                    f"{identifier}.source must contain a positive ordered line span",
                    lambda ledger: ledger[section][0]["source"].update(line_start=start, line_end=end),
                )

    def test_counts_block_equals_the_recorded_inventories(self) -> None:
        for change in (
            lambda ledger: ledger.pop("counts"),
            lambda ledger: ledger.update(counts=[119, 23, 133, 52, 133, 0]),
            lambda ledger: ledger["counts"].update(extra=1),
            lambda ledger: ledger["counts"].pop("prior_superseded_by_user_direction"),
            lambda ledger: ledger["counts"].update(requirements="119"),
            lambda ledger: ledger["counts"].update(requirements=119.0),
            lambda ledger: ledger["counts"].update(prior_superseded_by_user_direction=False),
        ):
            self.assert_ledger_only(COUNTS_RULE, change)
        for key in ("requirements", "r6_findings", "prior_findings", "original_tasks", "prior_carried_forward", "prior_superseded_by_user_direction"):
            for delta in (-1, 1):
                with self.subTest(key=key, delta=delta):
                    self.assert_ledger_only(COUNTS_RULE, lambda ledger: ledger["counts"].update({key: ledger["counts"][key] + delta}))
        # The disposition split is counted from the records, not taken on trust.
        graph, ledger = fixture(), ledger_fixture()
        ledger["prior_findings"][0]["disposition"] = "superseded_by_user_direction"
        self.assert_only(COUNTS_RULE.replace("forward 133", "forward 132").replace("direction 0", "direction 1"), graph, ledger=ledger)
        ledger["counts"].update(prior_carried_forward=132, prior_superseded_by_user_direction=1)
        self.assert_valid(graph, ledger=ledger)
        for index in (1, 66, -1):
            graph, ledger = fixture(), ledger_fixture()
            ledger["prior_findings"][index]["disposition"] = "superseded_by_user_direction"
            ledger["counts"].update(prior_carried_forward=132, prior_superseded_by_user_direction=1)
            self.assert_valid(graph, ledger=ledger)

    def test_source_fingerprint_covers_every_preserved_original(self) -> None:
        message = "reconciliation source inventory fingerprint differs from the graph baseline"
        for change in (
            lambda ledger: ledger["sources"][0].update(sha256="1" * 64),
            lambda ledger: ledger["requirements"][0].update(original_text="Changed original source requirement"),
            lambda ledger: ledger["requirements"][0]["source"].update(line_end=2),
            lambda ledger: ledger["findings"][0].update(original_text="Changed original finding"),
            lambda ledger: ledger["findings"][0]["source"].update(line_end=2),
            lambda ledger: ledger["prior_findings"][0]["original_record"].update(original_report_text="Changed original review"),
            lambda ledger: ledger["prior_findings"][0]["source"].update(line_end=2),
            lambda ledger: ledger["original_tasks"][0]["original_record"].update(title="Changed original task"),
        ):
            self.assert_ledger_only(message, change)
        # The fingerprint is independent of the current plan's mappings and rationale.
        graph, ledger = fixture(), ledger_fixture()
        ledger["requirements"][0].update(task_ids=["C.1"], rationale="A different but sufficient mapping rationale.", disposition="corrected")
        self.assert_valid(graph, ledger=ledger)

    def test_unhashable_ledger_text_is_reported(self) -> None:
        message = "reconciliation source inventory cannot be hashed: text is not valid Unicode or nesting is too deep"
        self.assert_ledger_only(message, lambda ledger: ledger["requirements"][0].update(original_text="\ud800"))
        nested: dict = {}
        for _ in range(100000):
            nested = {"nested": nested}
        self.assert_ledger_only(message, lambda ledger: ledger["original_tasks"][0]["original_record"].update(extra=nested))


class EvidenceTests(CheckerCase):
    """Recorded task status and the evidence that admits it."""

    def with_status(self, status: str, identifier: str = "B.1", **overrides: object) -> dict:
        graph = fixture()
        find(graph, identifier).update(status=status, evidence=evidence(**overrides))
        return graph

    def test_vocabularies_are_pinned(self) -> None:
        self.assertEqual(CHECKER.TASK_STATUSES, ("planned", "in_progress", "implemented"))
        self.assertEqual(CHECKER.COMMAND_OUTCOMES, ("passed", "failed", "not_run"))
        self.assertEqual(CHECKER.CLAUSE_STATES, ("met", "partial", "unmet"))
        self.assertEqual(
            CHECKER.IGNORED_EVIDENCE_COMPONENTS, {"dist", "target", ".git", "__pycache__", "node_modules", "build"},
        )

    def test_planned_task_cannot_carry_evidence(self) -> None:
        for value in (evidence(), {}, None, []):
            with self.subTest(value=value):
                graph = fixture()
                graph["tasks"][0]["evidence"] = value
                self.assert_only("B.1.evidence is recorded only for in_progress or implemented status", graph)

    def test_non_planned_status_requires_an_evidence_object(self) -> None:
        message = "B.1.evidence must record source, paths, commands and acceptance for a non-planned status"
        for status in ("in_progress", "implemented"):
            graph = fixture()
            graph["tasks"][0]["status"] = status
            self.assert_only(message, graph)
            for value in (None, [], "evidence", 5, True):
                with self.subTest(status=status, value=value):
                    graph["tasks"][0]["evidence"] = value
                    self.assert_only(message, graph)

    def test_source_contains_a_commit_id(self) -> None:
        message = "B.1.evidence.source must contain the observed 40-hex commit id"
        for source in (
            " ", 5, None, [], "abc123 with uncommitted task changes", COMMIT[:39], COMMIT + "0", COMMIT.upper(), "0" * 64,
            "g" * 40, "z" + COMMIT[1:], COMMIT[:-1] + "g", f"{COMMIT[:20]} {COMMIT[20:]}", [COMMIT], {"commit": COMMIT}, (COMMIT,),
        ):
            for status in ("in_progress", "implemented"):
                with self.subTest(source=source, status=status):
                    self.assert_only(message, self.with_status(status, source=source))
        for source in (COMMIT, f"commit {COMMIT}, with uncommitted changes", f"sha256 {'0' * 64} at {COMMIT}"):
            with self.subTest(source=source):
                self.assert_valid(self.with_status("in_progress", source=source))

    def test_malformed_evidence_fields(self) -> None:
        run = {"command": COMMAND, "outcome": "passed"}
        for field, values, message in (
            (
                "paths", ([], None, [None], [5], "a", {"a": 1}, ("a",), ["specs/a.json", ["b"]]),
                "B.1.evidence.paths must be a nonempty list of path strings",
            ),
            (
                "commands",
                (
                    [], None, [None], "run", (run,), dict(run), [[run]],
                    [{"command": COMMAND, "outcome": "ok"}], [{"command": COMMAND, "outcome": "skipped"}],
                    [{"command": COMMAND, "outcome": "passed "}], [{"command": COMMAND, "outcome": "Passed"}],
                    [{"command": COMMAND, "outcome": "PASSED"}], [{"command": COMMAND, "outcome": "not run"}],
                    [{"command": COMMAND, "outcome": ""}], [{"command": COMMAND, "outcome": True}],
                    [{"command": COMMAND, "outcome": []}], [{"command": COMMAND}], [{"outcome": "passed"}],
                    [{"command": " ", "outcome": "passed"}], [{"command": [], "outcome": "passed"}], [run, None],
                ),
                "B.1.evidence.commands must record each command with outcome passed, failed or not_run",
            ),
            (
                "acceptance",
                (
                    [], None, SENTENCES[0], (clause(0),), dict(clause(0)), [None],
                    [dict(clause(0), state="done")], [dict(clause(0), state="waived")], [dict(clause(0), state=[])],
                    [dict(clause(0), state="met ")], [dict(clause(0), state="Met")], [dict(clause(0), state="MET")],
                    [dict(clause(0), state="")], [dict(clause(0), state=True)],
                    [dict(clause(0), proof="")], [dict(clause(0), proof=" ")], [dict(clause(0), proof=[])],
                    [{"clause": SENTENCES[0], "state": "met"}], [{"clause": SENTENCES[0], "proof": COMMAND}],
                    [dict(clause(0), clause=" ")], [dict(clause(0), clause=[])], [{"state": "met", "proof": COMMAND}],
                ),
                "B.1.evidence.acceptance must record each clause with state met, partial or unmet and its proof",
            ),
        ):
            for value in values:
                for status in ("in_progress", "implemented"):
                    with self.subTest(field=field, value=value, status=status):
                        self.assert_only(message, self.with_status(status, **{field: value}))
            # An absent field is the same error as a malformed one.
            for status in ("in_progress", "implemented"):
                graph = self.with_status(status)
                del graph["tasks"][0]["evidence"][field]
                self.assert_only(message, graph)
        for status in ("in_progress", "implemented"):
            graph = self.with_status(status)
            del graph["tasks"][0]["evidence"]["source"]
            self.assert_only("B.1.evidence.source must contain the observed 40-hex commit id", graph)

    def test_every_evidence_entry_is_validated(self) -> None:
        run = {"command": COMMAND, "outcome": "passed"}
        for status in ("in_progress", "implemented"):
            for bad in (None, 5, ["specs/b.json"]):
                for paths in ([bad, ARTIFACT], [ARTIFACT, bad], [ARTIFACT, bad, ARTIFACT]):
                    with self.subTest(status=status, paths=paths):
                        self.assert_only("B.1.evidence.paths must be a nonempty list of path strings", self.with_status(status, paths=paths))
            for bad in (None, {"command": COMMAND, "outcome": "skipped"}, {"command": " ", "outcome": "passed"}, {"command": COMMAND}):
                for commands in ([bad, run], [run, bad], [run, bad, run]):
                    with self.subTest(status=status, commands=commands):
                        self.assert_only(
                            "B.1.evidence.commands must record each command with outcome passed, failed or not_run",
                            self.with_status(status, commands=commands),
                        )
            for bad in (None, dict(clause(1), state="waived"), dict(clause(1), proof=" "), dict(clause(1), clause=""), {"clause": SENTENCES[1]}):
                first = clause(0, proof=f"{ARTIFACT} and `{COMMAND}`")
                for entries in ([bad, first, clause(2)], [first, bad, clause(2)], [first, clause(2), bad]):
                    with self.subTest(status=status, entries=entries):
                        self.assert_only(
                            "B.1.evidence.acceptance must record each clause with state met, partial or unmet and its proof",
                            self.with_status(status, acceptance=entries),
                        )

    def test_malformed_paths_or_commands_are_one_error_each(self) -> None:
        # Citations cannot be judged against a malformed list, so they add no second error.
        self.assert_only(
            "B.1.evidence.paths must be a nonempty list of path strings",
            self.with_status("implemented", paths=[], acceptance=[clause(0, proof=ARTIFACT), clause(1), clause(2)]),
        )
        self.assert_only(
            "B.1.evidence.commands must record each command with outcome passed, failed or not_run",
            self.with_status("implemented", commands=[], acceptance=[clause(0, proof=ARTIFACT), clause(1), clause(2)]),
        )

    def test_in_progress_admits_partial_failed_and_unexecuted_checks(self) -> None:
        graph = self.with_status(
            "in_progress",
            commands=[{"command": "run", "outcome": "failed"}, {"command": "later", "outcome": "not_run"}],
            acceptance=[clause(1, "partial", "`run` passes half of the cases"), clause(2, "unmet", "`later` is pending")],
        )
        report = self.assert_valid(graph)
        self.assertEqual(report["status_counts"], {"planned": 6, "in_progress": 1, "implemented": 0})
        self.assertEqual(report["progress"], ["B.1 in_progress: 0 of 3 clauses met"])
        self.assertEqual(report["complete_deliveries"], [])
        report = self.assert_valid(self.with_status("in_progress", acceptance=[clause(1), clause(2, "partial")]))
        self.assertEqual(report["progress"], ["B.1 in_progress: 1 of 3 clauses met"])

    def test_clause_is_exactly_one_whole_sentence_recorded_once(self) -> None:
        self.assertEqual(CHECKER.task_sentences(fixture()["tasks"][0]), list(SENTENCES))
        self.assert_only(
            "B.1.evidence.acceptance repeats a clause: Observable acceptance.",
            self.with_status("in_progress", acceptance=[clause(1), clause(1)]),
        )
        self.assert_only(
            "B.1.evidence.acceptance repeats a clause: Observable acceptance.",
            self.with_status("in_progress", acceptance=[clause(1), dict(clause(1), clause=f" {SENTENCES[1]}\n")]),
        )
        # A repeated entry is reported once, as a repeat.
        reworded = dict(clause(1), clause="Reworded.")
        self.assert_only([
            "B.1.evidence.acceptance clause is not one whole sentence of the task: Reworded.",
            "B.1.evidence.acceptance repeats a clause: Reworded.",
        ], self.with_status("in_progress", acceptance=[reworded, dict(reworded)]))
        # A repeat is rejected for an implemented task too, and its proof cites nothing.
        entries = evidence()["acceptance"]
        self.assert_only(
            "B.1.evidence.acceptance repeats a clause: Observable acceptance.",
            self.with_status("implemented", acceptance=entries + [dict(entries[1])]),
        )
        self.assert_only(
            ["B.1.evidence.acceptance repeats a clause: Second observable result.", "B.1 cannot be implemented with evidence that no proof cites: specs/artifact.json"],
            self.with_status("implemented", acceptance=[clause(0), clause(1), clause(2), clause(2, proof=ARTIFACT)]),
        )
        # Each entry is judged, wherever it stands in the list.
        for entries in ([reworded, clause(1), clause(2)], [clause(1), reworded, clause(2)], [clause(1), clause(2), reworded]):
            for status in ("in_progress", "implemented"):
                errors = ["B.1.evidence.acceptance clause is not one whole sentence of the task: Reworded."]
                if status == "implemented":
                    errors.append("B.1 cannot be implemented without evidence for: Concrete artifact.")
                    errors.append("B.1 cannot be implemented with evidence that no proof cites: specs/artifact.json")
                self.assert_only(errors, self.with_status(status, acceptance=entries))
        # Surrounding whitespace is the only tolerated difference from the task text.
        self.assert_valid(self.with_status("in_progress", acceptance=[dict(clause(1), clause=f"  {SENTENCES[1]} \n")]))
        for text in (
            "Observable acceptance, reworded.",
            "Observable acceptance",
            "Observable",
            "able accept",
            "e",
            "observable acceptance.",
            "Observable  acceptance.",
            f"{SENTENCES[1]} {SENTENCES[2]}",
            f"{SENTENCES[0]} {SENTENCES[1]}",
            "Second observable result. More.",
        ):
            with self.subTest(text=text):
                self.assert_only(
                    f"B.1.evidence.acceptance clause is not one whole sentence of the task: {text[:60]}",
                    self.with_status("in_progress", acceptance=[dict(clause(1), clause=text)]),
                )
        # A sentence of another task is not this task's text.
        graph = self.with_status("in_progress", acceptance=[clause(1)])
        graph["tasks"][0]["acceptance"] = ["Different text."]
        self.assert_only(f"B.1.evidence.acceptance clause is not one whole sentence of the task: {SENTENCES[1]}", graph)

    def test_messages_quote_at_most_sixty_characters_of_a_clause(self) -> None:
        long = "This observable acceptance sentence is deliberately longer than sixty characters."
        shown = long[:60]
        self.assertEqual((len(shown), shown), (60, "This observable acceptance sentence is deliberately longer t"))

        def graph_with(status: str, entries: list[dict]) -> dict:
            graph = fixture()
            graph["tasks"][0].update(acceptance=[long], status=status, evidence=evidence(acceptance=entries))
            return graph

        first = clause(0, proof=f"{ARTIFACT} and `{COMMAND}`")
        entry = {"clause": long, "state": "met", "proof": f"`{COMMAND}` shows it"}
        self.assert_valid(graph_with("implemented", [first, entry]))
        self.assert_only(f"B.1.evidence.acceptance repeats a clause: {shown}", graph_with("implemented", [first, entry, dict(entry)]))
        self.assert_only(f"B.1 cannot be implemented with a clause that is partial: {shown}", graph_with("implemented", [first, dict(entry, state="partial")]))
        self.assert_only(
            f"B.1.evidence.acceptance proof must cite a recorded path or command: {shown}",
            graph_with("implemented", [first, dict(entry, proof="it works")]),
        )
        self.assert_only(f"B.1 cannot be implemented without evidence for: {shown}", graph_with("implemented", [first]))
        self.assert_only(
            f"B.1.evidence.acceptance clause is not one whole sentence of the task: {shown}",
            graph_with("in_progress", [dict(entry, clause=long + " More.")]),
        )

    def test_sentences_split_after_terminal_punctuation(self) -> None:
        record = {"outputs": ["One. Two? Three!  Four", " Five.\nSix; still six. "], "acceptance": ["Two?", "Seven v1.2 e.g. eight."]}
        self.assertEqual(
            CHECKER.task_sentences(record),
            ["One.", "Two?", "Three!", "Four", "Five.", "Six; still six.", "Seven v1.2 e.g.", "eight."],
        )
        self.assertEqual(CHECKER.task_sentences({"outputs": None, "acceptance": [None, "Kept."]}), ["Kept."])
        # A sentence repeated in the task text is one clause.
        graph = fixture()
        graph["tasks"][0].update(outputs=["Same. Same."], acceptance=["Same."], status="implemented", evidence=evidence(
            acceptance=[{"clause": "Same.", "state": "met", "proof": f"{ARTIFACT} and `{COMMAND}`"}],
        ))
        self.assertEqual(self.assert_valid(graph)["progress"], ["B.1 implemented: 1 of 1 clauses met"])

    def test_proof_cites_a_recorded_path_or_command(self) -> None:
        for proof in ("x", "the artifact and its test", ARTIFACT.upper(), "specs/other.json", "python3 -m unittest"):
            with self.subTest(proof=proof):
                self.assert_only(
                    "B.1.evidence.acceptance proof must cite a recorded path or command: Observable acceptance.",
                    self.with_status("in_progress", acceptance=[clause(1, proof=proof)]),
                )
        for proof in (ARTIFACT, f"see {ARTIFACT}.", COMMAND, f"`{COMMAND}` passed"):
            with self.subTest(proof=proof):
                self.assert_valid(self.with_status("in_progress", acceptance=[clause(1, proof=proof)]))
        for missing in range(3):
            for status in ("in_progress", "implemented"):
                entries = cited(ARTIFACT)
                entries[missing]["proof"] = "it works"
                self.assert_only(
                    f"B.1.evidence.acceptance proof must cite a recorded path or command: {SENTENCES[missing]}",
                    self.with_status(status, acceptance=entries),
                )
        # Any recorded path or command will do, whichever one it is.
        paths = [ARTIFACT, "specs/second.json", "specs/third.json"]
        commands = [{"command": name, "outcome": "passed"} for name in (COMMAND, "cargo test -p plan", "cargo fmt --check")]
        for citation in paths + [entry["command"] for entry in commands]:
            self.assert_valid(self.with_status("in_progress", paths=paths, commands=commands, acceptance=[clause(1, proof=citation)]))

    def test_proof_cites_the_whole_recorded_text(self) -> None:
        unproven = "B.1.evidence.acceptance proof must cite a recorded path or command: Observable acceptance."
        uncited = "B.1 cannot be implemented with evidence that no proof cites: "
        # However long the proof is, it cites nothing unless it holds a whole recorded path or command.
        for proof in (
            "The observable behaviour was inspected by hand, twice, and found correct in every respect.",
            "artifact.json", "specs/artifact", "specs / artifact.json", "the specs directory holds artifact.json",
            "python3 -m unittest", "unittest plan_test", "python3  -m unittest plan_test", COMMAND.upper(), "x" * 400,
        ):
            for status in ("in_progress", "implemented"):
                with self.subTest(proof=proof, status=status):
                    entries = cited(ARTIFACT)
                    entries[1]["proof"] = proof
                    self.assert_only(unproven, self.with_status(status, acceptance=entries))
        # A file name or a part of a command does not cite the recorded item.
        entries = [clause(index, proof=f"artifact.json and `{COMMAND}`") for index in range(3)]
        self.assert_only(uncited + ARTIFACT, self.with_status("implemented", acceptance=entries))
        entries = [clause(index, proof=f"{ARTIFACT} and `python3 -m unittest`") for index in range(3)]
        self.assert_only(uncited + COMMAND, self.with_status("implemented", acceptance=entries))
        # A command is cited as recorded, with the spaces it was recorded with.
        spaced = [{"command": " run ", "outcome": "passed"}]
        entries = [clause(index, proof=f"{ARTIFACT} and `run`") for index in range(3)]
        self.assert_only(uncited + " run ", self.with_status("implemented", commands=spaced, acceptance=entries))
        self.assert_only(unproven, self.with_status("in_progress", commands=spaced, acceptance=[clause(1, proof="`run`")]))
        entries = [clause(index, proof=f"{ARTIFACT} and then run it") for index in range(3)]
        self.assert_valid(self.with_status("implemented", commands=spaced, acceptance=entries))

    def test_implemented_requires_every_sentence_check_and_citation(self) -> None:
        report = self.assert_valid(self.with_status("implemented"))
        self.assertEqual(report["status_counts"], {"planned": 6, "in_progress": 0, "implemented": 1})
        self.assertEqual(report["progress"], ["B.1 implemented: 3 of 3 clauses met"])
        for outcome in ("failed", "not_run"):
            self.assert_only(
                f"B.1 cannot be implemented with a failed or unexecuted check: {COMMAND}",
                self.with_status("implemented", commands=[{"command": COMMAND, "outcome": outcome}]),
            )
        for state in ("partial", "unmet"):
            entries = evidence()["acceptance"]
            entries[1]["state"] = state
            self.assert_only(
                f"B.1 cannot be implemented with a clause that is {state}: Observable acceptance.",
                self.with_status("implemented", acceptance=entries),
            )
        for index, sentence in enumerate(SENTENCES):
            with self.subTest(sentence=sentence):
                entries = evidence()["acceptance"]
                del entries[index]
                if index == 0:
                    entries[0]["proof"] = f"{ARTIFACT} and `{COMMAND}`"
                self.assert_only(
                    f"B.1 cannot be implemented without evidence for: {sentence}", self.with_status("implemented", acceptance=entries),
                )
        uncited = "B.1 cannot be implemented with evidence that no proof cites: "
        self.assert_only(uncited + "specs/second.json", self.with_status("implemented", paths=[ARTIFACT, "specs/second.json"]))
        self.assert_only(uncited + "specs/second.json", self.with_status("implemented", paths=["specs/second.json", ARTIFACT]))
        commands = [{"command": COMMAND, "outcome": "passed"}, {"command": "cargo test -p plan", "outcome": "passed"}]
        self.assert_only(uncited + "cargo test -p plan", self.with_status("implemented", commands=commands))
        self.assert_only(uncited + "cargo test -p plan", self.with_status("implemented", commands=commands[::-1]))
        self.assert_only(
            [uncited + "specs/second.json", uncited + "specs/third.json", uncited + "cargo test -p plan"],
            self.with_status("implemented", paths=[ARTIFACT, "specs/second.json", "specs/third.json"], commands=commands),
        )
        self.assert_valid(self.with_status("in_progress", paths=[ARTIFACT, "specs/second.json"], commands=commands))

    def test_implemented_requires_every_command_passed(self) -> None:
        other, third = "cargo test -p plan", "cargo fmt --check"
        entries = evidence()["acceptance"]
        entries[1]["proof"] = f"`{COMMAND}`, `{other}` and `{third}`"

        def run(command: str, outcome: str = "passed") -> dict:
            return {"command": command, "outcome": outcome}

        for outcome in ("failed", "not_run"):
            for commands in (
                [run(COMMAND), run(other, outcome)], [run(other, outcome), run(COMMAND)],
                [run(COMMAND), run(other, outcome), run(third)], [run(third), run(COMMAND), run(other, outcome)],
                [run(other, outcome), run(third), run(COMMAND)],
            ):
                with self.subTest(commands=commands):
                    proofs = [dict(entry) for entry in entries]
                    if len(commands) == 2:
                        proofs[1]["proof"] = f"`{COMMAND}` and `{other}`"
                    self.assert_only(
                        f"B.1 cannot be implemented with a failed or unexecuted check: {other}",
                        self.with_status("implemented", commands=commands, acceptance=proofs),
                    )
                    self.assert_valid(self.with_status("in_progress", commands=commands, acceptance=proofs))
        # The first failing check is the one named.
        self.assert_only(
            f"B.1 cannot be implemented with a failed or unexecuted check: {third}",
            self.with_status("implemented", commands=[run(COMMAND), run(third, "not_run"), run(other, "failed")], acceptance=entries),
        )

    def test_boilerplate_evidence_cannot_mark_a_task_implemented(self) -> None:
        graph = fixture()
        record = graph["tasks"][0]
        record.update(status="implemented", evidence={
            "source": "x",
            "paths": ["README.md"],
            "commands": [{"command": "true", "outcome": "passed"}],
            "acceptance": [
                {"clause": record["outputs"][0], "state": "met", "proof": "x"},
                {"clause": record["acceptance"][0], "state": "met", "proof": "x"},
            ],
        })
        report = self.check(graph)
        self.assertIs(report["ok"], False)
        self.assertEqual(report["errors"], [
            "B.1.evidence.source must contain the observed 40-hex commit id",
            "B.1.evidence.acceptance proof must cite a recorded path or command: Concrete artifact.",
            "B.1.evidence.acceptance clause is not one whole sentence of the task: Observable acceptance. Second observable result.",
            "B.1.evidence.acceptance proof must cite a recorded path or command: Observable acceptance. Second observable result.",
            "B.1 cannot be implemented without evidence for: Observable acceptance.",
            "B.1 cannot be implemented without evidence for: Second observable result.",
            "B.1 cannot be implemented with evidence that no proof cites: README.md",
            "B.1 cannot be implemented with evidence that no proof cites: true",
        ])

    def test_implemented_requires_implemented_prerequisites(self) -> None:
        message = "P.5 cannot be implemented before its prerequisites: B.1"
        graph = self.with_status("implemented", "P.5")
        self.assert_only(message, graph)
        find(graph, "B.1").update(status="in_progress", evidence=evidence())
        self.assert_only(message, graph)
        find(graph, "B.1")["status"] = "implemented"
        self.assert_valid(graph)

    def test_implemented_requires_every_prerequisite(self) -> None:
        def with_prerequisites(*done: str) -> dict:
            graph = fixture()
            graph["tasks"].append(task("Z.1", ["B.1", "R.1", "H.3"]))
            find(graph, "D.EVIDENCE")["requires"].append("Z.1")
            implement(graph, "Z.1", *done)
            return graph

        message = "Z.1 cannot be implemented before its prerequisites: "
        for done, pending in (
            (("B.1", "R.1"), "H.3"), (("B.1", "H.3"), "R.1"), (("R.1", "H.3"), "B.1"),
            (("B.1",), "H.3, R.1"), (("R.1",), "B.1, H.3"), (("H.3",), "B.1, R.1"), ((), "B.1, H.3, R.1"),
        ):
            with self.subTest(done=done):
                self.assert_only(message + pending, with_prerequisites(*done))
        # A prerequisite that is only in progress is not implemented.
        graph = with_prerequisites("B.1", "R.1")
        find(graph, "H.3").update(status="in_progress", evidence=evidence())
        self.assert_only(message + "H.3", graph)
        self.assert_valid(with_prerequisites("B.1", "R.1", "H.3"))
        # Every implemented task is judged, whatever its place in the ID order.
        for identifier in ("A.1", "C.2", "Z.1"):
            graph = fixture()
            graph["tasks"].append(task(identifier, ["R.1"]))
            find(graph, "D.1")["requires"].append(identifier)
            implement(graph, identifier)
            self.assert_only(f"{identifier} cannot be implemented before its prerequisites: R.1", graph)
        # Only direct prerequisites gate a task; each task is judged on its own edges.
        graph = fixture()
        graph["tasks"].append(task("Z.1", ["P.5"]))
        find(graph, "D.1")["requires"].append("Z.1")
        implement(graph, "Z.1", "P.5")
        self.assert_only("P.5 cannot be implemented before its prerequisites: B.1", graph)

    def test_complete_deliveries_need_every_ancestor_implemented(self) -> None:
        graph = fixture()
        graph["deliveries"].append({"id": "D.2", "title": "Second", "requires": ["D.1"], "kind": "functional", "surface_contract": "operation-v1"})
        self.assertEqual(self.assert_valid(graph)["complete_deliveries"], [])
        for identifier in ("B.1", "R.1", "P.5"):
            find(graph, identifier).update(status="implemented", evidence=evidence())
        self.assertEqual(self.assert_valid(graph)["complete_deliveries"], [])
        find(graph, "C.1").update(status="implemented", evidence=evidence())
        self.assertEqual(self.assert_valid(graph)["complete_deliveries"], ["D.1", "D.2"])
        # Whichever single ancestor is unfinished, the delivery is incomplete.
        gates = ("H.3", "V.4", "V.6")
        for pending in gates:
            graph = fixture()
            implement(graph, *(identifier for identifier in gates if identifier != pending))
            self.assertEqual(self.assert_valid(graph)["complete_deliveries"], [])
        graph = fixture()
        implement(graph, *gates)
        self.assertEqual(self.assert_valid(graph)["complete_deliveries"], ["D.EVIDENCE"])
        # An ancestor that is only in progress, however complete its evidence, completes nothing.
        for pending in gates:
            graph = fixture()
            implement(graph, *(identifier for identifier in gates if identifier != pending))
            find(graph, pending).update(status="in_progress", evidence=evidence())
            report = self.assert_valid(graph)
            self.assertEqual(report["complete_deliveries"], [])
            self.assertEqual(report["status_counts"], {"planned": 4, "in_progress": 1, "implemented": 2})
        graph = fixture()
        for identifier in gates:
            find(graph, identifier).update(status="in_progress", evidence=evidence())
        self.assertEqual(self.assert_valid(graph)["complete_deliveries"], [])

    def test_evidence_paths_are_normalized_repository_paths(self) -> None:
        for path in (
            "/absolute/file", "", " ", ".", "./specs/a.json", "..", "../outside", "specs/../specs/a.json",
            "specs/../../outside", "specs//a.json", "specs/a.json/", "specs/", "specs/a.json ", " specs/a.json",
            "specs\\a.json", "specs/a\x00.json", "specs/a\n.json", "specs/a\u200b.json", "\ud800",
            "dist/reports/review.md", "Dist/reports/review.md", "DIST/x", "target/debug/out", "Target", "target",
            "crates/x/target/out", ".git/HEAD", ".GIT/HEAD", "scripts/tests/__pycache__/x.pyc",
            "docs/node_modules/x.js", "build/untracked.log", "kotlin/Build/out", "di\u017ft/reports/review.md",
            "node_module\u017f/x.js", "specs/a.json/.", "specs/./a.json",
        ):
            with self.subTest(path=path):
                shown = path.encode("utf-8", "backslashreplace").decode("utf-8")
                self.assert_only(PATH_RULE + shown, self.with_status("in_progress", paths=[path]))
                # The status does not relax the rule, and neither does the path's position.
                self.assert_only(PATH_RULE + shown, self.with_status("implemented", paths=[path], acceptance=cited(path)))
                self.assert_only(PATH_RULE + shown, self.with_status("in_progress", paths=[ARTIFACT, path]))
        for path in ("specs/a.json", "docs/my file.md", "kotlin/build.gradle.kts", "distribution/notes.md", "targets/x.rs", ".github/workflows/pr.yml"):
            with self.subTest(path=path):
                self.assert_valid(self.with_status("in_progress", paths=[path]))
        self.assert_only(
            "B.1.evidence.paths repeats a path: specs/a.json", self.with_status("in_progress", paths=["specs/a.json", "specs/a.json"]),
        )
        # A case variant is a repeat whichever spelling comes first, with or without a root to examine.
        for first, second in (("specs/a.json", "Specs/A.json"), ("Specs/A.json", "specs/a.json"), ("SPECS/A.JSON", "specs/A.json")):
            self.assert_only(
                f"B.1.evidence.paths repeats a path: {second}", self.with_status("in_progress", paths=[first, second]),
            )
            self.assert_only(
                f"B.1.evidence.paths repeats a path: {second}",
                self.with_status("implemented", paths=[first, second], acceptance=cited(f"{first} {second}")),
            )
        self.assert_only(
            "B.1.evidence.paths repeats a path: specs/a.json",
            self.with_status("implemented", paths=["specs/a.json", "specs/b.json", "specs/a.json"], acceptance=cited("specs/a.json specs/b.json")),
        )
        # Every bad path is reported, in order.
        self.assert_only(
            [PATH_RULE + "dist/a", PATH_RULE + "../b", "B.1.evidence.paths repeats a path: specs/a.json", PATH_RULE + "target/c"],
            self.with_status("in_progress", paths=["dist/a", "specs/a.json", "../b", "specs/a.json", "target/c"]),
        )

    def test_evidence_paths_are_regular_files_inside_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            (root / "specs").mkdir(parents=True)
            (root / "dist/reports").mkdir(parents=True)
            (root / ".git").mkdir()
            outside = Path(directory) / "outside.txt"
            for file in (root / "dist/reports/review.md", root / ".git/HEAD", outside):
                file.write_text("x", encoding="utf-8")

            def only(message: str, *paths: str) -> None:
                self.assert_only(message, self.with_status("in_progress", paths=list(paths)), root=root)

            only("B.1.evidence path does not exist: specs/artifact.json", ARTIFACT)
            # An implemented task is held to the same file-system rules.
            for path, message in (
                ("specs/missing.json", "B.1.evidence path does not exist: specs/missing.json"),
                ("specs", "B.1.evidence path is not a regular file: specs"),
            ):
                self.assert_only(message, self.with_status("implemented", paths=[path], acceptance=cited(path)), root=root)
            (root / ARTIFACT).write_text("{}", encoding="utf-8")
            self.assert_valid(self.with_status("in_progress"), root=root)
            self.assert_valid(self.with_status("implemented"), root=root)
            only("B.1.evidence path does not exist: specs/Artifact.json", "specs/Artifact.json")
            only("B.1.evidence path does not exist: Specs/artifact.json", "Specs/artifact.json")
            only("B.1.evidence path does not exist: specs/artifact.json/inner", "specs/artifact.json/inner")
            only("B.1.evidence path is not a regular file: specs", "specs")
            # An ignored tree is refused by name even where the file exists.
            only(PATH_RULE + "dist/reports/review.md", "dist/reports/review.md")
            only(PATH_RULE + ".git/HEAD", ".git/HEAD")
            # Every path is examined, in order.
            self.assert_only(
                ["B.1.evidence path does not exist: specs/missing.json", "B.1.evidence path is not a regular file: specs"],
                self.with_status("in_progress", paths=[ARTIFACT, "specs/missing.json", "specs"]), root=root,
            )

            escape = "B.1.evidence path resolves outside the repository or into an ignored tree: "
            os.symlink(outside, root / "specs/outside_link")
            os.symlink(root / "dist", root / "specs/distlink")
            os.symlink(root / ".git/HEAD", root / "specs/head_link")
            os.symlink("nowhere", root / "specs/dangling")
            os.symlink("loop.json", root / "specs/loop.json")
            os.symlink("artifact.json", root / "specs/alias.json")
            only(escape + "specs/outside_link", "specs/outside_link")
            only(escape + "specs/distlink/reports/review.md", "specs/distlink/reports/review.md")
            only(escape + "specs/head_link", "specs/head_link")
            only("B.1.evidence path does not exist: specs/dangling", "specs/dangling")
            only("B.1.evidence path does not exist: specs/loop.json", "specs/loop.json")
            # Each path yields one error: a repeat or a directory is not examined further.
            only("B.1.evidence.paths repeats a path: specs/artifact.json", ARTIFACT, ARTIFACT)
            only("B.1.evidence path is not a regular file: specs/distlink", "specs/distlink")
            # An ignored tree below the root is refused wherever a link reaches it.
            (root / "crates/x/target").mkdir(parents=True)
            (root / "crates/x/target/out").write_text("x", encoding="utf-8")
            os.symlink(root / "crates/x/target/out", root / "specs/nested")
            only(escape + "specs/nested", "specs/nested")
            (root / "crates/x/build").write_text("x", encoding="utf-8")
            os.symlink(root / "crates/x/build", root / "specs/named_build")
            only(escape + "specs/named_build", "specs/named_build")
            # A wrong-case link target exists only on a case-insensitive volume, and is refused there too.
            os.symlink("../Dist/reports/review.md", root / "specs/wrong_case")
            report = self.check(self.with_status("in_progress", paths=["specs/wrong_case"]), root=root)
            self.assertIn(report["errors"], ([escape + "specs/wrong_case"], ["B.1.evidence path does not exist: specs/wrong_case"]))
            self.assert_valid(self.with_status("in_progress", paths=["specs/alias.json"]), root=root)
            only("B.1.evidence.paths repeats a file: specs/alias.json", ARTIFACT, "specs/alias.json")

            # A path that the file system refuses is one ordinary error beside the others.
            for path in ("a" * 300, "x/" * 600 + "y"):
                graph = self.with_status("in_progress", paths=[ARTIFACT, path, "specs/missing.json"])
                report = self.check(graph, root=root)
                self.assertIs(report["ok"], False)
                self.assertEqual(len(report["errors"]), 2)
                self.assertIn(report["errors"][0], (
                    f"B.1.evidence path cannot be examined: {path}", f"B.1.evidence path does not exist: {path}",
                ))
                self.assertEqual(report["errors"][1], "B.1.evidence path does not exist: specs/missing.json")
            # A root that cannot be resolved is the same ordinary error.
            os.symlink("looproot", Path(directory) / "looproot")
            report = self.check(self.with_status("in_progress"), root=Path(directory) / "looproot")
            self.assertIn(report["errors"], (
                [f"B.1.evidence path cannot be examined: {ARTIFACT}"], [f"B.1.evidence path does not exist: {ARTIFACT}"],
            ))
            # Without a root the file system is not examined.
            self.assert_valid(self.with_status("in_progress", paths=["specs/missing.json"]))

    def test_unexpected_failures_are_reports(self) -> None:
        unencodable = UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")
        for failure, message in (
            (RecursionError("deep"), "validation stopped: an input is nested too deeply"),
            (OSError("device failure"), "validation stopped: device failure"),
            (unencodable, f"validation stopped: {unencodable}"),
        ):
            with self.subTest(failure=failure):
                with mock.patch.object(CHECKER, "check_reconciliation", side_effect=failure):
                    report = self.check(fixture())
                self.assertEqual(report["errors"], [message])
                self.assertIs(report["ok"], False)
                self.assertEqual(set(report), REPORT_KEYS)


class PlatformTodoTests(CheckerCase):
    """Deferred platform execution: its record, the statuses it admits, the review owners and the report."""

    LABEL = "B.1.evidence.commands[1].platform_todo"
    STATUSES = ("in_progress", "implemented")
    JSON_VALUES = (None, True, False, 0, 7, 1.5, "", "text", [], ["text"], {}, {"text": 1})
    PLATFORM_RULE = LABEL + ".platform must be windows, linux, physical_x86_64 or cuda"
    REASON_RULE = LABEL + ".reason must be a nonempty string"
    SITE_RULE = LABEL + ".todo_site must be an object with path and marker"
    SITE_PATH_RULE = LABEL + ".todo_site.path must be one of the task's evidence.paths"
    MARKER_RULE = LABEL + ".todo_site.marker must be text containing the literal TODO:"
    OWNER_RULE = LABEL + ".owner must be H.3 or V.4"
    COUNT_RULE = LABEL + f".todo_site.marker must occur exactly once in {ARTIFACT}: found "
    UNEXECUTED = "B.1 cannot be implemented with a failed or unexecuted check: "
    PARTIAL = "B.1 cannot be implemented with a clause that is partial: Second observable result."
    HELD = "{} cannot be implemented while a platform TODO is open: {}"

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.root = self.directory / "repository"
        (self.root / "specs").mkdir(parents=True)
        self.site = self.root / ARTIFACT
        self.site.write_text(TODO_FILE, encoding="utf-8")

    def with_todo(self, status: str = "in_progress", identifier: str = "B.1", **overrides: object) -> dict:
        """Return the fixture with one task whose second command is deferred to another platform."""
        graph = fixture()
        find(graph, identifier).update(status=status, evidence=deferring(deferred(**overrides)))
        return graph

    def todo_of(self, graph: dict, identifier: str = "B.1", index: int = 1) -> dict:
        return find(graph, identifier)["evidence"]["commands"][index]["platform_todo"]

    def assert_everywhere(self, messages: str | list[str], change) -> None:
        """The change yields exactly these errors under both statuses, with and without a root to examine."""
        for status in self.STATUSES:
            for root in (None, self.root):
                graph = self.with_todo(status)
                change(graph)
                self.assert_only(messages, graph, root=root)

    def test_vocabularies_are_pinned(self) -> None:
        self.assertEqual(CHECKER.COMMAND_FIELDS, ("command", "outcome", "platform_todo"))
        self.assertEqual(CHECKER.PLATFORM_TODO_FIELDS, ("platform", "reason", "todo_site", "owner"))
        self.assertEqual(CHECKER.PLATFORM_TODO_SITE_FIELDS, ("path", "marker"))
        self.assertEqual(CHECKER.PLATFORM_TODO_PLATFORMS, ("windows", "linux", "physical_x86_64", "cuda"))
        self.assertEqual(CHECKER.PLATFORM_TODO_OWNERS, ("H.3", "V.4"))
        self.assertEqual(CHECKER.PLATFORM_TODO_LITERAL, "TODO:")
        self.assertEqual(CHECKER.IMPLEMENTED_OUTCOMES, ("passed",))
        self.assertEqual(CHECKER.IMPLEMENTED_DEFERRED_OUTCOMES, ("passed", "not_run"))
        for status in self.STATUSES:
            for platform in ("windows", "linux", "physical_x86_64", "cuda"):
                with self.subTest(status=status, platform=platform):
                    report = self.assert_valid(self.with_todo(status, platform=platform), root=self.root)
                    self.assertEqual([item["platform"] for item in report["open_platform_todo_items"]], [platform])
            for owner in ("H.3", "V.4"):
                with self.subTest(status=status, owner=owner):
                    report = self.assert_valid(self.with_todo(status, owner=owner), root=self.root)
                    self.assertEqual([item["owner"] for item in report["open_platform_todo_items"]], [owner])
        # The words are exact: no other platform, owner, case or spacing is one of them.
        for platform in (
            "Linux", "LINUX", "linux ", " linux", "macos", "darwin", "x86_64", "physical-x86_64", "physical_x86", "gpu", "CUDA",
            "win", "windows,linux", "",
        ):
            with self.subTest(platform=platform):
                self.assert_everywhere(self.PLATFORM_RULE, lambda graph: self.todo_of(graph).update(platform=platform))
        for owner in ("H.1", "H.2", "V.1", "V.3", "V.5", "V.6", "B.1", "h.3", "v.4", "H.3 ", " V.4", "H3", "H.3, V.4", ""):
            with self.subTest(owner=owner):
                self.assert_everywhere(self.OWNER_RULE, lambda graph: self.todo_of(graph).update(owner=owner))

    def test_every_field_is_required(self) -> None:
        fields = {
            "platform": self.PLATFORM_RULE, "reason": self.REASON_RULE, "todo_site": self.SITE_RULE, "owner": self.OWNER_RULE,
        }
        self.assertEqual(list(fields), list(platform_todo()))
        for field, message in fields.items():
            with self.subTest(field=field):
                self.assert_everywhere(message, lambda graph: self.todo_of(graph).pop(field))
        # A record without any field lacks each one, in the order of the rule.
        self.assert_everywhere(list(fields.values()), lambda graph: self.todo_of(graph).clear())
        site = {"path": self.SITE_PATH_RULE, "marker": self.MARKER_RULE}
        self.assertEqual(list(site), list(platform_todo()["todo_site"]))
        for field, message in site.items():
            with self.subTest(field=field):
                self.assert_everywhere(message, lambda graph: self.todo_of(graph)["todo_site"].pop(field))
        self.assert_everywhere(list(site.values()), lambda graph: self.todo_of(graph)["todo_site"].clear())
        for reason in ("", " ", "\n\t "):
            with self.subTest(reason=reason):
                self.assert_everywhere(self.REASON_RULE, lambda graph: self.todo_of(graph).update(reason=reason))
        # Every defect of one record is reported, in the order of the rule.
        self.assert_everywhere(
            [self.PLATFORM_RULE, self.REASON_RULE, self.SITE_PATH_RULE, self.MARKER_RULE, self.OWNER_RULE],
            lambda graph: self.todo_of(graph).update(
                platform="macos", reason="", todo_site={"path": "specs/other.json", "marker": "later"}, owner="V.6",
            ),
        )

    def test_unknown_fields_are_errors_at_every_level(self) -> None:
        entry = "B.1.evidence.commands[1] has an unknown field: "

        def command(graph: dict, index: int = 1) -> dict:
            return find(graph, "B.1")["evidence"]["commands"][index]

        self.assert_everywhere(entry + "note", lambda graph: command(graph).update(note="ran on the Mac"))
        # A record one level too high is refused as well: on the evidence object and on an acceptance entry.
        misplaced = {"platform": "linux", "reason": "r", "todo_site": {"path": "p", "marker": "TODO: m"}, "owner": "V.4"}
        self.assert_everywhere(
            "B.1.evidence has an unknown field: platform_todo",
            lambda graph: find(graph, "B.1")["evidence"].update(platform_todo=dict(misplaced)),
        )
        self.assert_everywhere(
            "B.1.evidence.acceptance[1] has an unknown field: platform_todo",
            lambda graph: find(graph, "B.1")["evidence"]["acceptance"][1].update(platform_todo=dict(misplaced)),
        )
        self.assert_everywhere(
            ["B.1.evidence has an unknown field: open", "B.1.evidence.acceptance[0] has an unknown field: note"],
            lambda graph: (
                find(graph, "B.1")["evidence"].update(open=["later"]),
                find(graph, "B.1")["evidence"]["acceptance"][0].update(note="x"),
            ),
        )
        self.assert_everywhere(
            "B.1.evidence.commands[0] has an unknown field: platform", lambda graph: command(graph, 0).update(platform="linux"),
        )
        self.assert_everywhere(self.LABEL + " has an unknown field: issue", lambda graph: self.todo_of(graph).update(issue=7))
        self.assert_everywhere(
            self.LABEL + ".todo_site has an unknown field: line", lambda graph: self.todo_of(graph)["todo_site"].update(line=3),
        )
        # Each unknown key is named, in recorded order, before the fields of its own level and beside every other defect.
        self.assert_everywhere(
            [entry + "zeta", entry + "alpha", self.LABEL + " has an unknown field: zulu", self.LABEL + " has an unknown field: bravo",
             self.PLATFORM_RULE, self.LABEL + ".todo_site has an unknown field: yankee",
             self.LABEL + ".todo_site has an unknown field: charlie", self.MARKER_RULE],
            lambda graph: (
                command(graph).update(zeta=1, alpha=2), self.todo_of(graph).update(zulu=1, bravo=2, platform="macos"),
                self.todo_of(graph)["todo_site"].update(yankee=1, charlie=2, marker="later"),
            ),
        )
        # An unknown key is seen wherever it stands in its record, the first place included.
        def leading(graph: dict) -> None:
            commands = find(graph, "B.1")["evidence"]["commands"]
            todo = commands[1]["platform_todo"]
            commands[1] = {"note": 1, **commands[1], "platform_todo": {"issue": 2, **todo, "todo_site": {"line": 3, **todo["todo_site"]}}}

        self.assert_everywhere(
            [entry + "note", self.LABEL + " has an unknown field: issue", self.LABEL + ".todo_site has an unknown field: line"], leading,
        )
        # No spelling marks a key as a comment or as private.
        for name in ("_comment", "_", "__note", "$schema", "//", "#", "", " ", "x-note", "Command", "PATH", "Marker"):
            with self.subTest(name=name):
                self.assert_everywhere(entry + name, lambda graph: command(graph).update({name: "x"}))
                self.assert_everywhere(
                    f"{self.LABEL} has an unknown field: {name}", lambda graph: self.todo_of(graph).update({name: "x"}),
                )
                self.assert_everywhere(
                    f"{self.LABEL}.todo_site has an unknown field: {name}",
                    lambda graph: self.todo_of(graph)["todo_site"].update({name: "x"}),
                )
        # A key in another spelling defers nothing: it is unknown, and the command stands as recorded.
        for name in ("platform_todos", "platformTodo", "platform-todo", "Platform_todo", "PLATFORM_TODO", "platform_todo ", "todo"):
            with self.subTest(name=name):
                for root in (None, self.root):
                    graph = self.with_todo("in_progress")
                    command(graph)[name] = command(graph).pop("platform_todo")
                    report = self.assert_only(entry + name, graph, root=root)
                    self.assertEqual(report["open_platform_todo_total"], 0)
                    graph = self.with_todo("implemented")
                    command(graph)[name] = command(graph).pop("platform_todo")
                    self.assert_only([entry + name, self.UNEXECUTED + DEFERRED, self.PARTIAL], graph, root=root)

    def test_malformed_records_of_every_json_type_are_reports(self) -> None:
        shape = self.LABEL + " must be an object with platform, reason, todo_site and owner"
        every = [self.PLATFORM_RULE, self.REASON_RULE, self.SITE_RULE, self.OWNER_RULE]
        for value in self.JSON_VALUES + ([platform_todo()], "linux", [[]], 1e308, -1):
            with self.subTest(value=value):
                if value == {}:
                    expected = every
                elif value == {"text": 1}:
                    expected = [self.LABEL + " has an unknown field: text"] + every
                else:
                    expected = [shape]

                def replace(graph: dict) -> None:
                    find(graph, "B.1")["evidence"]["commands"][1]["platform_todo"] = value

                self.assert_everywhere(expected, replace)
        for value in self.JSON_VALUES:
            with self.subTest(field="platform", value=value):
                self.assert_everywhere(self.PLATFORM_RULE, lambda graph: self.todo_of(graph).update(platform=value))
            with self.subTest(field="owner", value=value):
                self.assert_everywhere(self.OWNER_RULE, lambda graph: self.todo_of(graph).update(owner=value))
            with self.subTest(field="reason", value=value):
                if value == "text":
                    for status in self.STATUSES:
                        self.assert_valid(self.with_todo(status, reason=value), root=self.root)
                else:
                    self.assert_everywhere(self.REASON_RULE, lambda graph: self.todo_of(graph).update(reason=value))
            with self.subTest(field="todo_site", value=value):
                if value == {}:
                    expected = [self.SITE_PATH_RULE, self.MARKER_RULE]
                elif value == {"text": 1}:
                    expected = [self.LABEL + ".todo_site has an unknown field: text", self.SITE_PATH_RULE, self.MARKER_RULE]
                else:
                    expected = [self.SITE_RULE]
                self.assert_everywhere(expected, lambda graph: self.todo_of(graph).update(todo_site=value))
            with self.subTest(field="path", value=value):
                self.assert_everywhere(self.SITE_PATH_RULE, lambda graph: self.todo_of(graph)["todo_site"].update(path=value))
            with self.subTest(field="marker", value=value):
                self.assert_everywhere(self.MARKER_RULE, lambda graph: self.todo_of(graph)["todo_site"].update(marker=value))

    def test_every_command_entry_is_validated(self) -> None:
        run = {"command": COMMAND, "outcome": "passed"}
        other = {"command": "cargo fmt --check", "outcome": "passed"}
        for status in self.STATUSES:
            for position in (0, 1, 2):
                with self.subTest(status=status, position=position):
                    commands = [dict(run), dict(other)]
                    commands.insert(position, deferred(platform="macos"))
                    graph = fixture()
                    find(graph, "B.1").update(status=status, evidence=evidence(commands=commands, acceptance=[
                        clause(0, proof=f"{ARTIFACT} and `{COMMAND}`"), clause(1, proof="`cargo fmt --check`"),
                        clause(2, "partial", f"`{DEFERRED}` is deferred"),
                    ]))
                    self.assert_only(
                        f"B.1.evidence.commands[{position}].platform_todo.platform must be windows, linux, physical_x86_64 or cuda",
                        graph, root=self.root,
                    )
                    commands[position]["platform_todo"]["platform"] = "linux"
                    commands[(position + 1) % 3]["note"] = "x"
                    self.assert_only(f"B.1.evidence.commands[{(position + 1) % 3}] has an unknown field: note", graph, root=self.root)
        # Every task is held to the rule, whatever its place in the graph.
        for identifier in FIXTURE_TASKS:
            for status in self.STATUSES:
                graph = self.with_todo(status, identifier, owner="V.6")
                if status == "implemented":
                    implement(graph, *find(graph, identifier)["requires"])
                self.assert_only(f"{identifier}.evidence.commands[1].platform_todo.owner must be H.3 or V.4", graph, root=self.root)
        # A list that is malformed as a whole is one error; no entry of it is examined further.
        graph = self.with_todo("in_progress")
        find(graph, "B.1")["evidence"]["commands"].append({"command": COMMAND})
        self.todo_of(graph).update(platform="macos")
        self.assert_only("B.1.evidence.commands must record each command with outcome passed, failed or not_run", graph)

    def test_todo_site_path_is_one_of_the_evidence_paths(self) -> None:
        (self.root / "specs/other.json").write_text(TODO_FILE, encoding="utf-8")
        for path in (
            "specs/other.json", "specs/missing.json", "specs/Artifact.json", "SPECS/ARTIFACT.JSON", "./specs/artifact.json",
            "specs/artifact.json ", "specs//artifact.json", "artifact.json", "specs", str(self.site), [ARTIFACT], {"path": ARTIFACT},
        ):
            with self.subTest(path=path):
                self.assert_everywhere(self.SITE_PATH_RULE, lambda graph: self.todo_of(graph)["todo_site"].update(path=path))
        # Any recorded path will do, whichever one it is.
        paths = [ARTIFACT, "specs/second.json", "specs/third.json"]
        for path in paths:
            (self.root / path).write_text(TODO_FILE, encoding="utf-8")
        for path in paths:
            with self.subTest(path=path):
                graph = self.with_todo("in_progress", todo_site={"path": path, "marker": MARKER})
                find(graph, "B.1")["evidence"]["paths"] = paths
                for root in (None, self.root):
                    report = self.assert_valid(graph, root=root)
                    self.assertEqual(report["open_platform_todo_items"][0]["todo_site"], {"path": path, "marker": MARKER})
        # The marker is looked for in the site's own file, not in another recorded one.
        (self.root / "specs/second.json").write_text("// nothing is deferred here\n", encoding="utf-8")
        for path, others in (("specs/second.json", [ARTIFACT, "specs/third.json"]), (ARTIFACT, ["specs/second.json"])):
            for paths in ([path] + others, others + [path]):
                with self.subTest(path=path, paths=paths):
                    graph = self.with_todo("in_progress", todo_site={"path": path, "marker": MARKER})
                    find(graph, "B.1")["evidence"]["paths"] = paths
                    if path == ARTIFACT:
                        self.assert_valid(graph, root=self.root)
                    else:
                        self.assert_only(
                            f"{self.LABEL}.todo_site.marker must occur exactly once in specs/second.json: found 0", graph, root=self.root,
                        )
        # The site cannot be judged against a malformed path list, so it adds no second error.
        for paths in ([], None, [5], ARTIFACT):
            for path in (ARTIFACT, "specs/other.json", None, 5):
                with self.subTest(paths=paths, path=path):
                    self.assert_everywhere(
                        "B.1.evidence.paths must be a nonempty list of path strings",
                        lambda graph: (
                            find(graph, "B.1")["evidence"].update(paths=paths), self.todo_of(graph)["todo_site"].update(path=path),
                        ),
                    )

    def test_todo_marker_contains_the_literal(self) -> None:
        for marker in (
            "run the plan tests on Linux", "todo: run the plan tests on Linux", "Todo: run", "TODO run", "TODO :", "TODO;",
            "TO DO:", "TODO", "T ODO:", "FIXME: run", "XXX", " ",
        ):
            with self.subTest(marker=marker):
                self.site.write_text(f"// {marker}.\n", encoding="utf-8")
                self.assert_everywhere(self.MARKER_RULE, lambda graph: self.todo_of(graph)["todo_site"].update(marker=marker))
        # The literal may stand anywhere in the marker.
        for marker in ("TODO:", MARKER, "// TODO: run", "(windows) TODO:", "TODO:TODO:", "# TODO: テスト — later"):
            with self.subTest(marker=marker):
                self.site.write_text(f"fn main() {{}} // {marker}\n", encoding="utf-8")
                for status in self.STATUSES:
                    for root in (None, self.root):
                        self.assert_valid(self.with_todo(status, todo_site={"path": ARTIFACT, "marker": marker}), root=root)

    def test_todo_marker_occurs_exactly_once_in_its_file(self) -> None:
        for content, found in (
            ("", 0), ("// todo: run the plan tests on linux.\n", 0), (MARKER[:-1], 0), (MARKER.replace(" ", "\n"), 0),
            (TODO_FILE * 2, 2), (MARKER + MARKER, 2), (TODO_FILE * 3, 3), (f"x\n{TODO_FILE}y\n# {MARKER} again\n", 2),
        ):
            with self.subTest(content=content):
                self.site.write_text(content, encoding="utf-8")
                for status in self.STATUSES:
                    self.assert_only(self.COUNT_RULE + str(found), self.with_todo(status), root=self.root)
                    # A closed TODO is held to its site as an open one is.
                    self.assert_only(
                        [self.COUNT_RULE + str(found)] + [self.PARTIAL] * (status == "implemented"),
                        self.with_todo(status, outcome="passed"), root=self.root,
                    )
                    # Without a root the file system is not examined.
                    self.assert_valid(self.with_todo(status))
        # One occurrence is enough wherever it stands, beside other TODO lines and bytes that are not text.
        for content in (
            MARKER.encode("utf-8"), f"// TODO: something else.\n{TODO_FILE}// TODO: a third.\n".encode("utf-8"),
            b"\xff\xfe\x00 not text " + MARKER.encode("utf-8") + b"\x00\xff", f"{MARKER[:-1]} {MARKER}".encode("utf-8"),
        ):
            with self.subTest(content=content):
                self.site.write_bytes(content)
                for status in self.STATUSES:
                    self.assert_valid(self.with_todo(status), root=self.root)
        # An overlapping occurrence is a second one.
        overlapping = {"path": ARTIFACT, "marker": "x TODO: x"}
        self.site.write_text("x TODO: x TODO: y", encoding="utf-8")
        self.assert_valid(self.with_todo(todo_site=overlapping), root=self.root)
        self.site.write_text("x TODO: x TODO: x", encoding="utf-8")
        self.assert_only(self.COUNT_RULE + "2", self.with_todo(todo_site=overlapping), root=self.root)
        self.site.write_text("TODO:TODO:TODO:", encoding="utf-8")
        self.assert_only(self.COUNT_RULE + "2", self.with_todo(todo_site={"path": ARTIFACT, "marker": "TODO:TODO:"}), root=self.root)
        # A short marker names every TODO of its file; a longer one names its own.
        self.site.write_text(f"// TODO: run on Windows.\n{TODO_FILE}", encoding="utf-8")
        self.assert_only(self.COUNT_RULE + "2", self.with_todo(todo_site={"path": ARTIFACT, "marker": "TODO:"}), root=self.root)
        self.assert_only(self.COUNT_RULE + "2", self.with_todo(todo_site={"path": ARTIFACT, "marker": "TODO: run"}), root=self.root)
        self.assert_valid(self.with_todo(), root=self.root)
        # The marker is matched as its UTF-8 bytes, and letter for letter.
        for marker, content, found in (
            ("TODO: テスト — Linux", "// TODO: テスト — Linux\n", 1),
            ("TODO: テスト — Linux", "// TODO: テスト - Linux\n", 0),
            ("TODO: a.c (x)* [y]", "// TODO: a.c (x)* [y]\n// TODO: abc (x)* [y]\n", 1),
            ("TODO: a.c", "// TODO: abc\n", 0),
            # Spaces at either end of the marker are part of it.
            ("TODO: a.c ", "// TODO: a.c\n", 0), (" TODO: a.c", "//TODO: a.c\n", 0), ("\tTODO: a.c\n", "// TODO: a.c\n", 0),
            (" TODO: a.c ", "// TODO: a.c \n", 1),
            ("TODO: \ud800", "// TODO: ?\n", 0),
            ("TODO: line one\n// line two", "// TODO: line one\n// line two\n", 1),
        ):
            with self.subTest(marker=marker):
                self.site.write_bytes(content.encode("utf-8"))
                graph = self.with_todo(todo_site={"path": ARTIFACT, "marker": marker})
                if found == 1:
                    self.assert_valid(graph, root=self.root)
                else:
                    self.assert_only(self.COUNT_RULE + str(found), graph, root=self.root)

    def test_todo_site_is_examined_only_among_admitted_paths(self) -> None:
        outside = self.directory / "outside.txt"
        outside.write_text(TODO_FILE * 2, encoding="utf-8")
        os.symlink(outside, self.root / "specs/outside_link")
        (self.root / "specs/directory").mkdir()
        for path, message in (
            ("specs/missing.json", "B.1.evidence path does not exist: specs/missing.json"),
            ("specs/directory", "B.1.evidence path is not a regular file: specs/directory"),
            ("specs/outside_link", "B.1.evidence path resolves outside the repository or into an ignored tree: specs/outside_link"),
            ("dist/site.rs", PATH_RULE + "dist/site.rs"),
        ):
            for paths in ([ARTIFACT, path], [path, ARTIFACT]):
                with self.subTest(path=path, paths=paths):
                    # The refused path is reported once, whether it is the site or stands beside it.
                    for site in (path, ARTIFACT):
                        graph = self.with_todo(todo_site={"path": site, "marker": "TODO: absent from every file"})
                        find(graph, "B.1")["evidence"]["paths"] = paths
                        self.assert_only(message, graph, root=self.root)
        # A file that cannot be read is one ordinary error beside the others.
        graph = self.with_todo()
        find(graph, "B.1")["evidence"]["commands"].append(deferred("cargo test --features cuda", platform="gpu"))
        with mock.patch.object(Path, "read_bytes", side_effect=PermissionError(errno.EACCES, "Permission denied")):
            self.assert_only([
                self.LABEL + f".todo_site cannot be examined: {ARTIFACT}",
                "B.1.evidence.commands[2].platform_todo.platform must be windows, linux, physical_x86_64 or cuda",
                f"B.1.evidence.commands[2].platform_todo.todo_site cannot be examined: {ARTIFACT}",
            ], graph, root=self.root)
        self.todo_of(graph, index=2).update(platform="cuda")
        self.assert_valid(graph, root=self.root)

    def test_platform_todo_is_admitted_under_both_statuses(self) -> None:
        for outcome, total in (("not_run", 1), ("failed", 1), ("passed", 0)):
            with self.subTest(outcome=outcome):
                report = self.assert_valid(self.with_todo("in_progress", outcome=outcome), root=self.root)
                self.assertEqual(report["status_counts"], {"planned": 6, "in_progress": 1, "implemented": 0})
                self.assertEqual(report["open_platform_todo_total"], total)
                self.assertEqual(report["progress"], ["B.1 in_progress: 2 of 3 clauses met"])
        report = self.assert_valid(self.with_todo("implemented"), root=self.root)
        self.assertEqual(report["status_counts"], {"planned": 6, "in_progress": 0, "implemented": 1})
        self.assertEqual(report["open_platform_todo_total"], 1)
        # A deferred check is never a passed check or a met clause: the clause count says so.
        self.assertEqual(report["progress"], ["B.1 implemented: 2 of 3 clauses met"])

    def test_implemented_admits_no_failed_check_and_only_deferred_unexecuted_ones(self) -> None:
        self.assert_only(self.UNEXECUTED + DEFERRED, self.with_todo("implemented", outcome="failed"))
        self.assert_valid(self.with_todo("in_progress", outcome="failed"))
        # A deferred check that has passed is closed, and its clause is met.
        graph = fixture()
        find(graph, "B.1").update(status="implemented", evidence=deferring(deferred(outcome="passed"), state="met"))
        report = self.assert_valid(graph)
        self.assertEqual((report["open_platform_todo_total"], report["progress"]), (0, ["B.1 implemented: 3 of 3 clauses met"]))
        # Each command is judged on its own record, and the first one refused is named.
        later = {"command": "cargo bench -p plan", "outcome": "not_run"}
        broken = {"command": "cargo doc -p plan", "outcome": "failed"}
        windows = deferred("cargo test -p plan --features windows", platform="windows")
        cuda = deferred("cargo test -p plan --features cuda", "failed", platform="cuda", owner="V.4")
        for entries, named in (
            ([deferred(), later], later), ([later, deferred()], later), ([deferred(), broken], broken),
            ([deferred(), windows, later, broken], later), ([deferred(), windows, cuda, later], cuda),
            ([windows, deferred(), broken, cuda], broken), ([deferred(), cuda], cuda), ([cuda, deferred()], cuda),
        ):
            with self.subTest(entries=entries):
                graph = fixture()
                find(graph, "B.1").update(status="implemented", evidence=deferring(*entries))
                self.assert_only(self.UNEXECUTED + named["command"], graph)
                find(graph, "B.1")["status"] = "in_progress"
                self.assert_valid(graph)
        graph = fixture()
        find(graph, "B.1").update(status="implemented", evidence=deferring(deferred(), windows))
        self.assertEqual(self.assert_valid(graph)["open_platform_todos"], no_todos(B_1=2))

    def test_implemented_partial_clause_cites_an_open_platform_todo(self) -> None:
        self.assert_valid(self.with_todo("implemented"))
        # A partial clause that cites no deferred command is refused, whatever else its proof cites.
        for proof in (
            f"`{COMMAND}` covers the Mac", f"{ARTIFACT} holds the TODO", f"{ARTIFACT} and `{COMMAND}`", f"{MARKER} in {ARTIFACT}",
            f"`{DEFERRED[:-1]}` and {ARTIFACT}", f"`{DEFERRED.upper()}` and `{COMMAND}`", f"`{DEFERRED.replace(' ', '  ')}`, {ARTIFACT}",
            f"linux, H.3 and {ARTIFACT}",
        ):
            with self.subTest(proof=proof):
                graph = self.with_todo("implemented")
                entries = find(graph, "B.1")["evidence"]["acceptance"]
                # A met clause cites the deferred command, so every recorded command is still cited.
                entries[1]["proof"] = f"`{COMMAND}` and `{DEFERRED}`"
                entries[2]["proof"] = proof
                self.assert_only(self.PARTIAL, graph)
                find(graph, "B.1")["status"] = "in_progress"
                self.assert_valid(graph)
        # An unmet clause is refused even where it cites the deferred command.
        graph = fixture()
        find(graph, "B.1").update(status="implemented", evidence=deferring(deferred(), state="unmet"))
        self.assert_only("B.1 cannot be implemented with a clause that is unmet: Second observable result.", graph)
        # A closed TODO covers no remaining gap, and a failed one is refused as a failed check.
        self.assert_only(self.PARTIAL, self.with_todo("implemented", outcome="passed"))
        self.assert_only(self.UNEXECUTED + DEFERRED, self.with_todo("implemented", outcome="failed"))
        # One open TODO of several is enough, and each partial clause rests on its own proof.
        windows = deferred("cargo test -p plan --features windows", platform="windows")
        closed = deferred("cargo test -p plan --features cuda", "passed", platform="cuda")
        for first, second, errors in (
            (f"`{COMMAND}`, `{windows['command']}` and `{closed['command']}`", f"`{DEFERRED}`", []),
            (f"`{COMMAND}`, `{DEFERRED}` and `{closed['command']}`", f"`{windows['command']}`", []),
            (f"`{COMMAND}`, `{DEFERRED}` and `{windows['command']}`", f"`{closed['command']}`", [self.PARTIAL]),
            (f"`{COMMAND}`, `{DEFERRED}` and `{windows['command']}`", f"`{closed['command']}` and {ARTIFACT}", [self.PARTIAL]),
        ):
            with self.subTest(second=second):
                graph = fixture()
                record = deferring(deferred(), windows, closed)
                record["acceptance"][1]["proof"], record["acceptance"][2]["proof"] = first, second
                find(graph, "B.1").update(status="implemented", evidence=record)
                if errors:
                    self.assert_only(errors, graph)
                else:
                    self.assert_valid(graph)
        graph = self.with_todo("implemented")
        entries = find(graph, "B.1")["evidence"]["acceptance"]
        entries[0]["state"] = entries[1]["state"] = "partial"
        self.assert_only([
            "B.1 cannot be implemented with a clause that is partial: Concrete artifact.",
            "B.1 cannot be implemented with a clause that is partial: Observable acceptance.",
        ], graph)
        entries[1]["proof"] = f"`{DEFERRED}` also covers this"
        self.assert_only("B.1 cannot be implemented with a clause that is partial: Concrete artifact.", graph)
        entries[0]["proof"] = f"{ARTIFACT} is produced, `{COMMAND}` reads it and `{DEFERRED}` is deferred"
        self.assertEqual(self.assert_valid(graph)["progress"], ["B.1 implemented: 0 of 3 clauses met"])
        # Deferred commands cannot be judged in a malformed list, so a partial clause is refused there.
        graph = self.with_todo("implemented")
        find(graph, "B.1")["evidence"]["commands"].append(None)
        self.assert_only(
            ["B.1.evidence.commands must record each command with outcome passed, failed or not_run", self.PARTIAL], graph,
        )
        # Every sentence still needs its entry, and every recorded command its citation.
        graph = self.with_todo("implemented")
        del find(graph, "B.1")["evidence"]["acceptance"][2]
        self.assert_only([
            "B.1 cannot be implemented without evidence for: Second observable result.",
            f"B.1 cannot be implemented with evidence that no proof cites: {DEFERRED}",
        ], graph)

    def test_implemented_task_with_an_open_todo_satisfies_prerequisites(self) -> None:
        graph = self.with_todo("implemented")
        implement(graph, "P.5", "C.1", "R.1")
        report = self.assert_valid(graph)
        self.assertEqual(report["status_counts"], {"planned": 3, "in_progress": 0, "implemented": 4})
        self.assertEqual(report["complete_deliveries"], ["D.1"])
        # The deferred check is still reported, once, under the task that recorded it.
        self.assertEqual(report["open_platform_todos"], no_todos(B_1=1))
        self.assertEqual(report["open_platform_todo_items"], [open_item("B.1", deferred())])

    def test_review_owners_wait_for_every_open_platform_todo(self) -> None:
        for owner in ("H.3", "V.4"):
            for status in self.STATUSES:
                for outcome in ("not_run",) if status == "implemented" else ("not_run", "failed"):
                    for recorded in ("H.3", "V.4"):
                        with self.subTest(owner=owner, status=status, outcome=outcome, recorded=recorded):
                            # Any open TODO holds both reviews back, whichever of them owns it.
                            graph = self.with_todo(status, outcome=outcome, owner=recorded)
                            implement(graph, owner)
                            self.assert_only(self.HELD.format(owner, "B.1"), graph)
                            find(graph, owner)["status"] = "in_progress"
                            self.assert_valid(graph)
        graph = self.with_todo()
        implement(graph, "V.4", "H.3")
        self.assert_only([self.HELD.format("H.3", "B.1"), self.HELD.format("V.4", "B.1")], graph)
        # No other task is held back.
        graph = self.with_todo()
        implement(graph, "V.6", "R.1")
        self.assertEqual(self.assert_valid(graph)["status_counts"], {"planned": 4, "in_progress": 1, "implemented": 2})
        # A closed TODO holds nothing back.
        graph = self.with_todo(outcome="passed")
        implement(graph, "H.3", "V.4", "V.6")
        report = self.assert_valid(graph)
        self.assertEqual((report["open_platform_todo_total"], report["complete_deliveries"]), (0, ["D.EVIDENCE"]))
        # A review that records an open TODO of its own is held back by it.
        for owner in ("H.3", "V.4"):
            self.assert_only(self.HELD.format(owner, owner), self.with_todo("implemented", owner))
            self.assert_valid(self.with_todo("in_progress", owner))
        # A review that is not a task of the graph is the ordinary error: the rule is judged among known tasks.
        graph = self.with_todo()
        implement(graph, "V.4")
        graph["tasks"] = [record for record in graph["tasks"] if record["id"] != "H.3"]
        graph["start_immediately"].remove("H.3")
        find(graph, "D.EVIDENCE")["requires"].remove("H.3")
        self.assert_only("admission constraints contain unknown task H.3", graph)
        graph["deliveries"].append({"id": "H.3", "title": "Not a task", "requires": ["R.1"], "kind": "evidence"})
        self.assert_only("admission constraints contain unknown task H.3", graph)
        # Every task that holds an open TODO is named once, in order.
        graph = fixture()
        graph["tasks"].extend(task(name, []) for name in reversed(NAMES))
        graph["start_immediately"].extend(NAMES)
        find(graph, "D.EVIDENCE")["requires"].extend(NAMES)
        for name in NAMES:
            find(graph, name).update(status="in_progress", evidence=deferring(deferred(), deferred("cargo test --features cuda", platform="cuda")))
        implement(graph, "H.3")
        self.assert_only(self.HELD.format("H.3", ", ".join(NAMES)), graph)

    def test_report_counts_each_open_platform_todo_once(self) -> None:
        first = deferred()
        second = deferred("cargo test -p plan --features cuda", "failed", platform="cuda", owner="V.4", reason="No CUDA device.")
        closed = deferred("cargo test -p plan --features windows", "passed", platform="windows")
        graph = fixture()
        find(graph, "B.1").update(status="in_progress", evidence=deferring(first, closed, second))
        # The same command, deferred by another task, is that task's own open item.
        find(graph, "R.1").update(status="in_progress", evidence=deferring(deferred()))
        find(graph, "V.6").update(status="in_progress", evidence=evidence())
        for root in (None, self.root):
            report = self.assert_valid(graph, root=root)
            # Every task is counted, the owners and the dependents of B.1 at zero.
            self.assertEqual(report["open_platform_todos"], {"B.1": 2, "C.1": 0, "H.3": 0, "P.5": 0, "R.1": 1, "V.4": 0, "V.6": 0})
            self.assertEqual(report["open_platform_todo_total"], 3)
            self.assertEqual(report["open_platform_todo_items"], [
                {
                    "task": "B.1", "command": "cargo test -p plan --features linux", "outcome": "not_run", "platform": "linux",
                    "reason": "No Linux host is attached to the development Mac.",
                    "todo_site": {"path": "specs/artifact.json", "marker": "TODO: run the plan tests on Linux"}, "owner": "H.3",
                },
                {
                    "task": "B.1", "command": "cargo test -p plan --features cuda", "outcome": "failed", "platform": "cuda",
                    "reason": "No CUDA device.",
                    "todo_site": {"path": "specs/artifact.json", "marker": "TODO: run the plan tests on Linux"}, "owner": "V.4",
                },
                open_item("R.1", first),
            ])
            self.assertEqual(report["progress"], [
                "B.1 in_progress: 2 of 3 clauses met", "R.1 in_progress: 2 of 3 clauses met", "V.6 in_progress: 3 of 3 clauses met",
            ])
        # One command text deferred to two platforms is two entries and two open items.
        graph = fixture()
        find(graph, "B.1").update(status="implemented", evidence=deferring(deferred(), deferred(platform="windows", owner="V.4")))
        report = self.assert_valid(graph)
        self.assertEqual(report["open_platform_todos"], no_todos(B_1=2))
        self.assertEqual([item["platform"] for item in report["open_platform_todo_items"]], ["linux", "windows"])
        self.assertEqual(report["open_platform_todo_total"], 2)
        # Tasks and their items are reported in order, whatever the order of the graph.
        graph = fixture()
        graph["tasks"].extend(task(name, []) for name in reversed(NAMES))
        graph["start_immediately"].extend(NAMES)
        find(graph, "D.EVIDENCE")["requires"].extend(NAMES)
        for name in NAMES:
            record = deferring(deferred(f"cargo test {name} second"), deferred(f"cargo test {name} first"))
            # A deferred command is counted wherever it stands in its list, the first place included.
            record["commands"].append(record["commands"].pop(0))
            self.assertEqual([command["outcome"] for command in record["commands"]], ["not_run", "not_run", "passed"])
            find(graph, name).update(status="in_progress", evidence=record)
        report = self.assert_valid(graph)
        self.assertEqual(list(report["open_platform_todos"]), sorted(FIXTURE_TASKS + NAMES))
        self.assertEqual(report["open_platform_todos"], {**no_todos(), **dict.fromkeys(NAMES, 2)})
        self.assertEqual(report["open_platform_todo_total"], 18)
        self.assertEqual(
            [(item["task"], item["command"]) for item in report["open_platform_todo_items"]],
            [(name, f"cargo test {name} {position}") for name in NAMES for position in ("second", "first")],
        )
        # A report that fails before the graph is walked counts nothing.
        report = self.check(self.with_todo(platform="macos"))
        self.assertEqual(
            (report["open_platform_todos"], report["open_platform_todo_total"], report["open_platform_todo_items"]), ({}, 0, []),
        )
        # A graph that is walked is counted, also where a later check fails.
        graph = self.with_todo()
        implement(graph, "H.3")
        report = self.assert_only(self.HELD.format("H.3", "B.1"), graph)
        self.assertEqual((report["open_platform_todos"], report["open_platform_todo_total"]), (no_todos(B_1=1), 1))


class CommandLineTests(unittest.TestCase):
    """One validator backs both output formats."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.root = self.directory / "repository"
        (self.root / "specs").mkdir(parents=True)
        (self.root / ARTIFACT).write_text("{}", encoding="utf-8")

    def arguments(self, graph: object, plan: str | None = None, ledger: object = None) -> list[str]:
        """Write the three inputs and return the arguments that select them."""
        contents = (
            ("graph.json", graph if isinstance(graph, (str, bytes)) else json.dumps(graph)),
            ("plan.md", markdown(graph) if plan is None else plan),
            ("ledger.json", json.dumps(ledger_fixture() if ledger is None else ledger)),
        )
        for name, content in contents:
            if isinstance(content, bytes):
                (self.directory / name).write_bytes(content)
            else:
                (self.directory / name).write_text(content, encoding="utf-8")
        return [
            "--graph", str(self.directory / "graph.json"), "--plan", str(self.directory / "plan.md"),
            "--reconciliation", str(self.directory / "ledger.json"), "--root", str(self.root),
        ]

    def run_format(self, arguments: list[str], output_format: str) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = CHECKER.main(arguments + ["--format", output_format])
        return status, output.getvalue()

    def run_both(self, arguments: list[str]) -> dict:
        """Run both formats and assert that they render one report identically."""
        text_status, text = self.run_format(arguments, "text")
        json_status, encoded = self.run_format(arguments, "json")
        report = json.loads(encoded)
        self.assertEqual(set(report), REPORT_KEYS)
        self.assertEqual(report["scope"], SCOPE)
        self.assertEqual(text_status, json_status)
        self.assertEqual(json_status, 0 if report["ok"] else 1)
        self.assertEqual(report["ok"], not report["errors"])
        lines = text.splitlines()
        self.assertEqual(lines[:2], ["PASS" if report["ok"] else "FAIL", SCOPE])
        if not report["ok"]:
            self.assertEqual(lines[2:], [f"- {error}" for error in report["errors"]])
            return report
        counts = report["status_counts"]
        self.assertEqual(lines[2:], [
            f"{report['task_count']} tasks, {report['delivery_count']} deliveries; graph and plan agree.",
            f"Recorded status: {counts['planned']} planned, {counts['in_progress']} in progress, "
            f"{counts['implemented']} implemented; {len(report['complete_deliveries'])} deliveries complete.",
        ] + [f"- {line}" for line in report["progress"]] + [
            f"Open platform TODOs: {report['open_platform_todo_total']} in total; an open TODO is never a passed check.",
            "- open_platform_todos: " + ", ".join(
                f"{identifier} {report['open_platform_todos'][identifier]}" for identifier in sorted(report["open_platform_todos"])
            ),
        ] + [
            f"- {item['task']} open platform TODO, {item['platform']}, owner {item['owner']}, outcome {item['outcome']}: "
            f"command {json.dumps(item['command'])}; reason {json.dumps(item['reason'])}; "
            f"site {json.dumps(item['todo_site']['path'])} marker {json.dumps(item['todo_site']['marker'])}"
            for item in report["open_platform_todo_items"]
        ])
        # The counts cover every task, and the total counts each open item once.
        self.assertEqual(len(report["open_platform_todos"]), report["task_count"])
        self.assertEqual(sum(report["open_platform_todos"].values()), report["open_platform_todo_total"])
        self.assertEqual(len(report["open_platform_todo_items"]), report["open_platform_todo_total"])
        return report

    def test_both_formats_render_the_same_passing_report(self) -> None:
        graph = fixture()
        graph["tasks"][0].update(status="implemented", evidence=evidence())
        graph["tasks"][1].update(status="in_progress", evidence=evidence(acceptance=[clause(1, "partial")]))
        arguments = self.arguments(graph)
        report = self.run_both(arguments)
        self.assertEqual(report, {
            "ok": True, "scope": SCOPE, "errors": [], "task_count": 7, "delivery_count": 2,
            "roots": ["B.1", "H.3", "R.1", "V.4", "V.6"],
            "status_counts": {"planned": 5, "in_progress": 1, "implemented": 1},
            "progress": ["B.1 implemented: 3 of 3 clauses met", "R.1 in_progress: 0 of 3 clauses met"],
            "complete_deliveries": [],
            "open_platform_todos": no_todos(), "open_platform_todo_total": 0, "open_platform_todo_items": [],
        })
        self.assertEqual(self.run_format(arguments, "json"), (0, json.dumps(report, indent=2, sort_keys=True) + "\n"))
        self.assertEqual(self.run_format(arguments, "text"), (0, "\n".join([
            "PASS", SCOPE, "7 tasks, 2 deliveries; graph and plan agree.",
            "Recorded status: 5 planned, 1 in progress, 1 implemented; 0 deliveries complete.",
            "- B.1 implemented: 3 of 3 clauses met", "- R.1 in_progress: 0 of 3 clauses met",
            "Open platform TODOs: 0 in total; an open TODO is never a passed check.",
            "- open_platform_todos: B.1 0, C.1 0, H.3 0, P.5 0, R.1 0, V.4 0, V.6 0", "",
        ])))

    def test_both_formats_report_every_failure_identically(self) -> None:
        ancestry, revision, prose, missing, ledger = fixture(), fixture(), fixture(), fixture(), ledger_fixture()
        find(ancestry, "C.1")["requires"] = ["R.1"]
        revision["revision"] = 7
        ledger["prior_findings"].pop()
        missing["tasks"][0].update(status="in_progress", evidence=evidence(paths=["specs/missing.json"]))
        for inputs, errors in (
            ((ancestry,), ["forbidden ancestry for C.1: R.1"]),
            ((revision,), ["revision must be 8"]),
            ((fixture(), None, ledger), [
                "reconciliation.prior_findings inventory differs: missing F132; unexpected none",
                COUNTS_RULE.replace("prior_findings 133", "prior_findings 132").replace("forward 133", "forward 132"),
            ]),
            ((prose, markdown(prose).replace("all 23", "all 22")), [LEDGER_PROSE]),
            # Only the file system distinguishes this one, so neither format may skip the root.
            ((missing,), ["B.1.evidence path does not exist: specs/missing.json"]),
        ):
            with self.subTest(errors=errors):
                self.assertEqual(self.run_both(self.arguments(*inputs))["errors"], errors)

    def test_both_formats_report_open_platform_todos_identically(self) -> None:
        (self.root / ARTIFACT).write_text(TODO_FILE, encoding="utf-8")
        # Free text may hold quotes, line breaks and characters that a stream cannot encode.
        awkward = deferred(
            'cargo test -- "quoted"\n  --second-line', "failed", platform="cuda", owner="V.4",
            reason="No CUDA device;\tnone — here\u2028or there.",
        )
        closed = deferred("cargo test -p plan --features windows", "passed", platform="windows")
        graph = fixture()
        graph["tasks"][0].update(status="implemented", evidence=deferring(deferred()))
        graph["tasks"][1].update(status="in_progress", evidence=deferring(closed, awkward))
        arguments = self.arguments(graph)
        report = self.run_both(arguments)
        self.assertEqual(report, {
            "ok": True, "scope": SCOPE, "errors": [], "task_count": 7, "delivery_count": 2,
            "roots": ["B.1", "H.3", "R.1", "V.4", "V.6"],
            "status_counts": {"planned": 5, "in_progress": 1, "implemented": 1},
            "progress": ["B.1 implemented: 2 of 3 clauses met", "R.1 in_progress: 2 of 3 clauses met"],
            "complete_deliveries": [],
            "open_platform_todos": {"B.1": 1, "C.1": 0, "H.3": 0, "P.5": 0, "R.1": 1, "V.4": 0, "V.6": 0},
            "open_platform_todo_total": 2,
            "open_platform_todo_items": [open_item("B.1", deferred()), open_item("R.1", awkward)],
        })
        self.assertEqual(self.run_format(arguments, "json"), (0, json.dumps(report, indent=2, sort_keys=True) + "\n"))
        # The text names the total, every task's count and each open item on one line of its own.
        self.assertEqual(self.run_format(arguments, "text"), (0, "\n".join([
            "PASS", SCOPE, "7 tasks, 2 deliveries; graph and plan agree.",
            "Recorded status: 5 planned, 1 in progress, 1 implemented; 0 deliveries complete.",
            "- B.1 implemented: 2 of 3 clauses met", "- R.1 in_progress: 2 of 3 clauses met",
            "Open platform TODOs: 2 in total; an open TODO is never a passed check.",
            "- open_platform_todos: B.1 1, C.1 0, H.3 0, P.5 0, R.1 1, V.4 0, V.6 0",
            '- B.1 open platform TODO, linux, owner H.3, outcome not_run: command "cargo test -p plan --features linux"; '
            'reason "No Linux host is attached to the development Mac."; '
            'site "specs/artifact.json" marker "TODO: run the plan tests on Linux"',
            '- R.1 open platform TODO, cuda, owner V.4, outcome failed: command "cargo test -- \\"quoted\\"\\n  --second-line"; '
            'reason "No CUDA device;\\tnone \\u2014 here\\u2028or there."; '
            'site "specs/artifact.json" marker "TODO: run the plan tests on Linux"',
            "",
        ])))
        # A stream that cannot encode a character still receives every line.
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="ascii")
        with redirect_stdout(stream):
            self.assertEqual(CHECKER.main(arguments), 0)
        stream.flush()
        self.assertEqual(raw.getvalue().decode("ascii"), self.run_format(arguments, "text")[1])
        # Text that is not valid Unicode is escaped in both formats.
        graph["tasks"][1]["evidence"]["commands"][2]["platform_todo"]["reason"] = "No device \ud800 here."
        report = self.run_both(self.arguments(graph))
        self.assertEqual(report["open_platform_todo_items"][1]["reason"], "No device \ud800 here.")
        self.assertIn('reason "No device \\ud800 here."', self.run_format(self.arguments(graph), "text")[1])

    def test_both_formats_report_platform_todo_failures_identically(self) -> None:
        (self.root / ARTIFACT).write_text(TODO_FILE, encoding="utf-8")
        label = "B.1.evidence.commands[1].platform_todo"

        def graph_with(status: str = "in_progress", **overrides: object) -> dict:
            graph = fixture()
            graph["tasks"][0].update(status=status, evidence=deferring(deferred(**overrides)))
            return graph

        held = graph_with()
        implement(held, "V.4", "H.3")
        unknown = graph_with()
        unknown["tasks"][0]["evidence"]["commands"][1]["platform_todos"] = {}
        for graph, errors in (
            (graph_with(platform="macos"), [label + ".platform must be windows, linux, physical_x86_64 or cuda"]),
            (graph_with(owner="V.6", reason=" "), [label + ".reason must be a nonempty string", label + ".owner must be H.3 or V.4"]),
            (graph_with(todo_site={"path": "specs/other.json", "marker": "later", "line": 3}), [
                label + ".todo_site has an unknown field: line", label + ".todo_site.path must be one of the task's evidence.paths",
                label + ".todo_site.marker must be text containing the literal TODO:",
            ]),
            (unknown, ["B.1.evidence.commands[1] has an unknown field: platform_todos"]),
            # Only the file system distinguishes these two, so neither format may skip the root.
            (graph_with(todo_site={"path": ARTIFACT, "marker": "TODO: absent"}), [
                label + f".todo_site.marker must occur exactly once in {ARTIFACT}: found 0",
            ]),
            (graph_with(todo_site={"path": ARTIFACT, "marker": "TODO:"}, outcome="passed"), []),
            (graph_with("implemented", outcome="failed"), [f"B.1 cannot be implemented with a failed or unexecuted check: {DEFERRED}"]),
            (graph_with("implemented", outcome="passed"), ["B.1 cannot be implemented with a clause that is partial: Second observable result."]),
            (held, [
                "H.3 cannot be implemented while a platform TODO is open: B.1",
                "V.4 cannot be implemented while a platform TODO is open: B.1",
            ]),
        ):
            with self.subTest(errors=errors):
                self.assertEqual(self.run_both(self.arguments(graph))["errors"], errors)
        # A record of any JSON type is a report in both formats, never an exception.
        shape = label + " must be an object with platform, reason, todo_site and owner"
        for value in (None, True, False, 0, 7, 1.5, "", "linux", [], ["linux"], [{}]):
            with self.subTest(value=value):
                graph = graph_with()
                graph["tasks"][0]["evidence"]["commands"][1]["platform_todo"] = value
                self.assertEqual(self.run_both(self.arguments(graph))["errors"], [shape])
        for field in ("platform", "reason", "todo_site", "owner"):
            for value in (None, True, 7, 1.5, "", [], ["x"], {}, {"x": 1}):
                with self.subTest(field=field, value=value):
                    report = self.run_both(self.arguments(graph_with(**{field: value})))
                    self.assertIs(report["ok"], False)
                    self.assertTrue(all(error.startswith(f"{label}.{field}") for error in report["errors"]), report["errors"])
        for field in ("path", "marker"):
            for value in (None, True, 7, 1.5, "", [], ["x"], {}, {"x": 1}):
                with self.subTest(field=field, value=value):
                    site = {"path": ARTIFACT, "marker": MARKER, field: value}
                    report = self.run_both(self.arguments(graph_with(todo_site=site)))
                    self.assertEqual(len(report["errors"]), 1)
                    self.assertTrue(report["errors"][0].startswith(f"{label}.todo_site.{field} must be "), report["errors"])
        # The script itself ends such a run with exit status 1 and nothing on standard error.
        graph = graph_with()
        graph["tasks"][0]["evidence"]["commands"][1]["platform_todo"] = [None, {"platform": 5}]
        arguments = self.arguments(graph)
        for output_format in ("text", "json"):
            process = subprocess.run(
                [sys.executable, str(SCRIPT), *arguments, "--format", output_format], capture_output=True, text=True, check=False,
            )
            self.assertEqual((process.returncode, process.stderr), (1, ""))
            self.assertIn(shape, process.stdout)

    def test_unreadable_inputs_are_reports_in_both_formats(self) -> None:
        valid = json.dumps(fixture())
        # Well-formed JSON whose one string holds a byte that is not UTF-8.
        undecodable = valid.encode("utf-8").replace(b'"abc123"', b'"abc\xff123"')
        self.assertEqual(undecodable.count(b"\xff"), 1)
        for graph, message in (
            ("{bad", None),
            (b"\xff\xfe bad utf8", None),
            (undecodable, None),
            (valid.replace('"revision": 8', '"revision": 7, "revision": 8'), "cannot read inputs: graph: duplicate JSON object key 'revision'"),
            (valid.replace('"revision": 8', '"revision": 8, "extra": NaN'), "cannot read inputs: graph: non-finite JSON number NaN"),
            (valid.replace('"revision": 8', '"revision": 8, "extra": Infinity'), "cannot read inputs: graph: non-finite JSON number Infinity"),
            (valid.replace('"revision": 8', '"revision": 8, "extra": -Infinity'), "cannot read inputs: graph: non-finite JSON number -Infinity"),
            (valid.replace('"revision": 8', '"revision": 8, "extra": 1e999'), "cannot read inputs: graph: non-finite JSON number 1e999"),
            (valid.replace('"revision": 8', '"revision": 8, "extra": [0.5, -1E+999]'), "cannot read inputs: graph: non-finite JSON number -1E+999"),
            ("[" * 200000 + "]" * 200000, "cannot read inputs: graph is nested too deeply"),
        ):
            with self.subTest(graph=graph[:40]):
                report = self.run_both(self.arguments(graph, plan=""))
                self.assertEqual(len(report["errors"]), 1)
                self.assertTrue(report["errors"][0].startswith("cannot read inputs: graph"), report)
                if message is not None:
                    self.assertEqual(report["errors"], [message])
                self.assertEqual({key: value for key, value in report.items() if key != "errors"}, {
                    "ok": False, "scope": SCOPE, "task_count": 0, "delivery_count": 0, "roots": [],
                    "status_counts": {"planned": 0, "in_progress": 0, "implemented": 0}, "progress": [], "complete_deliveries": [],
                    "open_platform_todos": {}, "open_platform_todo_total": 0, "open_platform_todo_items": [],
                })
        # Finite numbers load; an unvalidated extra field does not change the verdict.
        finite = valid.replace('"revision": 8', '"revision": 8, "extra": [1.5, -2.5e3, 1e308, 0.0, 12345678901234567890]')
        self.assertEqual(self.run_both(self.arguments(finite, plan=markdown(fixture())))["errors"], [])
        self.assertEqual(
            self.run_both(self.arguments(valid.replace('"revision": 8', '"revision": 8.0'), plan=markdown(fixture())))["errors"],
            ["revision must be 8"],
        )
        arguments = self.arguments(fixture())
        for content in (b"\xff\xfe bad utf8", markdown(fixture()).encode("utf-8").replace(b"## Task graph", b"## Task\xff graph")):
            (self.directory / "plan.md").write_bytes(content)
            report = self.run_both(arguments)
            self.assertEqual(len(report["errors"]), 1)
            self.assertTrue(report["errors"][0].startswith("cannot read inputs: plan: 'utf-8' codec can't decode byte 0xff"), report)
        (self.directory / "plan.md").write_text(markdown(fixture()), encoding="utf-8")
        (self.directory / "ledger.json").write_bytes(json.dumps(ledger_fixture()).encode("utf-8").replace(b"Requirement 1\"", b"Requirement \xff1\""))
        report = self.run_both(arguments)
        self.assertEqual(len(report["errors"]), 1)
        self.assertTrue(report["errors"][0].startswith("cannot read inputs: reconciliation: 'utf-8' codec can't decode byte 0xff"), report)
        # Every unreadable input is named: a missing file, a directory and a duplicate key.
        (self.directory / "graph.json").unlink()
        (self.directory / "plan.md").unlink()
        (self.directory / "plan.md").mkdir()
        (self.directory / "ledger.json").write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
        report = self.run_both(arguments)
        self.assertEqual(len(report["errors"]), 3)
        self.assertTrue(report["errors"][0].startswith("cannot read inputs: graph: "), report)
        self.assertTrue(report["errors"][1].startswith("cannot read inputs: plan: "), report)
        self.assertEqual(report["errors"][2], "cannot read inputs: reconciliation: duplicate JSON object key 'schema_version'")

    def test_unencodable_text_is_escaped_in_both_formats(self) -> None:
        graph = fixture()
        find(graph, "C.1")["requires"] = ["B.1", "\ud800.1"]
        self.assertEqual(self.run_both(self.arguments(graph, plan=""))["errors"], ["C.1 requires unknown ID \\ud800.1"])
        graph = fixture()
        graph["tasks"][0].update(status="in_progress", evidence=evidence(paths=["\ud800"]))
        self.assertEqual(self.run_both(self.arguments(graph))["errors"], [PATH_RULE + "\\ud800"])
        ledger = ledger_fixture()
        ledger["requirements"][0]["original_text"] = "\ud800"
        self.assertEqual(self.run_both(self.arguments(fixture(), ledger=ledger))["errors"], [
            "reconciliation source inventory cannot be hashed: text is not valid Unicode or nesting is too deep",
        ])
        graph = fixture()
        graph["tasks"][0].update(status="in_progress", evidence=evidence(paths=[ARTIFACT, "a" * 300]))
        errors = self.run_both(self.arguments(graph))["errors"]
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("B.1.evidence path "), errors)
        # A stream that cannot encode a character receives its escape, not an exception.
        graph = fixture()
        find(graph, "C.1")["requires"] = ["B.1", "Ω.1"]
        arguments = self.arguments(graph)
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="ascii")
        with redirect_stdout(stream):
            self.assertEqual(CHECKER.main(arguments), 1)
        stream.flush()
        self.assertEqual(raw.getvalue().decode("ascii").splitlines(), ["FAIL", SCOPE, "- C.1 requires unknown ID \\u03a9.1"])
        self.assertEqual(self.run_both(arguments)["errors"], ["C.1 requires unknown ID Ω.1"])

    def test_closed_output_pipe_is_a_failure_without_traceback(self) -> None:
        passing = fixture()
        failing_plan = markdown(passing) + "\n" + "\n".join(f"| Z.{index} | Unknown | Core | — |" for index in range(6000))
        # One report overflows any pipe buffer; the other fits and fails only when flushed.
        for name, plan, status, size in (("failing", failing_plan, 1, 250000), ("passing", None, 0, 100)):
            arguments = self.arguments(passing, plan=plan)
            for output_format in ("text", "json"):
                with self.subTest(report=name, output_format=output_format):
                    command = [sys.executable, str(SCRIPT), *arguments, "--format", output_format]
                    intact = subprocess.run(command, capture_output=True, text=True, check=False)
                    self.assertEqual((intact.returncode, intact.stderr), (status, ""))
                    self.assertGreater(len(intact.stdout), size)
                    # The reader is gone before the first byte is written.
                    read_end, write_end = os.pipe()
                    os.close(read_end)
                    try:
                        closed = subprocess.run(command, stdout=write_end, stderr=subprocess.PIPE, text=True, check=False)
                    finally:
                        os.close(write_end)
                    self.assertEqual((closed.returncode, closed.stderr), (1, ""))
        # The help text is held to the same rule, buffered or not.
        for options in ([], ["-u"]):
            command = [sys.executable, *options, str(SCRIPT), "--help"]
            intact = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual((intact.returncode, intact.stderr), (0, ""))
            self.assertTrue(intact.stdout.startswith("usage: check_zk_delivery_plan.py"), intact.stdout)
            read_end, write_end = os.pipe()
            os.close(read_end)
            try:
                closed = subprocess.run(command, stdout=write_end, stderr=subprocess.PIPE, text=True, check=False)
            finally:
                os.close(write_end)
            self.assertEqual(closed.stderr, "")
            # An interpreter whose argparse swallows the failed write itself reports success.
            self.assertIn(closed.returncode, (1,) if options == [] else (0, 1))

    def test_failed_output_stream_is_a_failure_without_traceback(self) -> None:
        class FailedDevice(io.TextIOBase):
            """A stream with no descriptor that refuses every write, as a full device does."""

            def write(self, text: str) -> int:
                raise OSError(errno.ENOSPC, "No space left on device")

        class FailedFlush(io.StringIO):
            """A stream that accepts text and fails only when it is flushed."""

            def flush(self) -> None:
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        class ClosedDescriptor(FailedDevice):
            """A failed stream whose descriptor cannot be asked for."""

            def fileno(self) -> int:
                raise ValueError("I/O operation on closed file")

        class InvalidDescriptor(FailedDevice):
            """A failed stream whose descriptor cannot be redirected."""

            def fileno(self) -> int:
                return 1 << 30

        arguments = self.arguments(fixture())
        real_open = os.open
        for stream in (FailedDevice, FailedFlush, ClosedDescriptor, InvalidDescriptor):
            for output_format in ("text", "json"):
                with self.subTest(stream=stream.__name__, output_format=output_format):
                    sinks: list[int] = []

                    def recording_open(name: str, flags: int) -> int:
                        self.assertEqual((name, flags), (os.devnull, os.O_WRONLY))
                        sinks.append(real_open(name, flags))
                        return sinks[-1]

                    with mock.patch.object(os, "open", side_effect=recording_open), redirect_stdout(stream()):
                        self.assertEqual(CHECKER.main(arguments + ["--format", output_format]), 1)
                    # Only the null device is opened, once, and its descriptor does not leak.
                    self.assertEqual(len(sinks), 1)
                    with self.assertRaises(OSError):
                        os.fstat(sinks[0])
        # Without any stream the exit status alone carries the verdict.
        with mock.patch.object(sys, "stdout", None):
            self.assertEqual(CHECKER.main(arguments), 0)
            self.assertEqual(CHECKER.main(self.arguments(fixture(), plan="")), 1)
        # Help that its stream refuses, when flushed or when written, is the same failure.
        with redirect_stdout(FailedFlush()):
            self.assertEqual(CHECKER.main(["--help"]), 1)
        for failure in (BrokenPipeError(errno.EPIPE, "Broken pipe"), OSError(errno.ENOSPC, "No space left on device")):
            with mock.patch.object(argparse.ArgumentParser, "parse_args", side_effect=failure):
                self.assertEqual(CHECKER.main(["--help"]), 1)
                with redirect_stdout(FailedFlush()):
                    self.assertEqual(CHECKER.main(["--help"]), 1)

    def test_defaults_do_not_depend_on_the_working_directory(self) -> None:
        script, absent = "scripts/check_zk_delivery_plan.py", "scripts/zk_delivery_plan_absent_evidence.py"
        self.assertTrue((REPOSITORY / script).is_file())
        self.assertFalse((REPOSITORY / absent).exists())
        # The working directory holds the file that the repository lacks, and lacks the one it holds.
        elsewhere = self.directory / "elsewhere"
        (elsewhere / "scripts").mkdir(parents=True)
        (elsewhere / absent).write_text("", encoding="utf-8")

        def errors_from(arguments: list[str], program: Path = SCRIPT) -> list[str]:
            """Run both formats from the other directory and return the errors they agree on."""
            reported = []
            for output_format in ("text", "json"):
                process = subprocess.run(
                    [sys.executable, str(program), *arguments, "--format", output_format],
                    cwd=elsewhere, capture_output=True, text=True, check=False,
                )
                self.assertEqual(process.stderr, "")
                if output_format == "json":
                    report = json.loads(process.stdout)
                    self.assertIs(report["ok"], not report["errors"])
                    errors = report["errors"]
                else:
                    lines = process.stdout.splitlines()
                    self.assertEqual(lines[:2], ["FAIL" if process.returncode else "PASS", SCOPE])
                    errors = [line[2:] for line in lines[2:]] if process.returncode else []
                self.assertEqual(process.returncode, 1 if errors else 0)
                reported.append(errors)
            self.assertEqual(reported[0], reported[1])
            return reported[0]

        def recorded(status: str, path: str) -> list[str]:
            """Select fixture inputs whose first task records this one evidence path, without naming a root."""
            graph = fixture()
            graph["tasks"][0].update(status=status, evidence=evidence(paths=[path], acceptance=cited(path)))
            selected = self.arguments(graph)
            self.assertEqual(selected[-2:], ["--root", str(self.root)])
            return selected[:-2]

        # The default root is the script's repository, whatever the working directory holds.
        self.assertEqual(errors_from(recorded("in_progress", script)), [])
        # The default run examines the file system: a missing file and a directory are refused.
        self.assertEqual(errors_from(recorded("implemented", absent)), [f"B.1.evidence path does not exist: {absent}"])
        self.assertEqual(errors_from(recorded("implemented", "scripts")), ["B.1.evidence path is not a regular file: scripts"])
        # A named root replaces the default one.
        self.assertEqual(errors_from(recorded("implemented", absent) + ["--root", str(elsewhere)]), [])
        # Every default together selects the repository's own graph, plan and ledger,
        # also when the script is reached through a symbolic link.
        self.assertEqual(errors_from([]), [])
        link = self.directory / "linked_checker.py"
        os.symlink(SCRIPT, link)
        self.assertEqual(errors_from([], link), [])

    def test_default_root_is_examined_in_process(self) -> None:
        # The same default applies to each status when main() is called without a root, in both formats.
        for path, message in (
            ("scripts/zk_delivery_plan_absent_evidence.py", "B.1.evidence path does not exist: scripts/zk_delivery_plan_absent_evidence.py"),
            ("scripts", "B.1.evidence path is not a regular file: scripts"),
            ("scripts/check_zk_delivery_plan.py", None),
        ):
            for status in ("in_progress", "implemented"):
                with self.subTest(path=path, status=status):
                    graph = fixture()
                    graph["tasks"][0].update(status=status, evidence=evidence(paths=[path], acceptance=cited(path)))
                    report = self.run_both(self.arguments(graph)[:-2])
                    self.assertEqual(report["errors"], [] if message is None else [message])

    def test_error_order_does_not_depend_on_the_hash_seed(self) -> None:
        graph = fixture()
        for index in range(9):
            graph["deliveries"].append({
                "id": f"D.F{index}", "title": f"Functional {index}", "requires": ["R.1", "V.4"],
                "kind": "functional", "surface_contract": "operation-v1",
            })
        arguments = self.arguments(graph)
        expected = [f"functional delivery D.F{index} depends on evidence gates: V.4" for index in range(9)]
        for seed in ("1", "2", "3", "4"):
            environment = dict(os.environ, PYTHONHASHSEED=seed)
            process = subprocess.run(
                [sys.executable, str(SCRIPT), *arguments, "--format", "json"],
                capture_output=True, text=True, env=environment, check=False,
            )
            self.assertEqual(process.returncode, 1, process.stderr)
            self.assertEqual(json.loads(process.stdout)["errors"], expected)

    def test_help_documents_every_option(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            CHECKER.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        text = " ".join(output.getvalue().split())
        for expected in (
            "--graph GRAPH delivery graph JSON",
            "--plan PLAN Markdown plan compared with the graph",
            "--reconciliation RECONCILIATION source reconciliation ledger JSON",
            "--root ROOT repository that evidence paths resolve against",
            "--format {text,json} render the one validation report as text or JSON",
            "A clause is exactly one whole sentence",
            "A command entry may add `platform_todo`",
            "platform `windows`, `linux`, `physical_x86_64` or `cuda` and owner `H.3` or `V.4`",
            "Neither H.3 nor V.4 is `implemented` while a platform TODO is open anywhere in the graph.",
            "an open TODO is never a passed check",
        ):
            self.assertIn(expected, text)
        # A usage error keeps argparse's own message and exit status, and validates nothing.
        for arguments in (["--format", "xml"], ["--unknown"], ["--root"], ["extra"]):
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                CHECKER.main(arguments)
            self.assertEqual((raised.exception.code, output.getvalue()), (2, ""))
            self.assertTrue(errors.getvalue().startswith("usage: "), errors.getvalue())


class RepositoryFileTests(unittest.TestCase):
    """The real graph, plan and ledger; each pin changes only with a deliberate edit."""

    CONSTRAINTS_SHA256 = "ba253b1cd565510b4ebddff0752226dbce82fcefbb460257d029790dbc55380d"
    DELIVERY_SURFACES_SHA256 = "b09e271cb83139ac0f223868c9441a19f9ac5ebfb3dd582c64093522f074c4cd"
    LEDGER_FINGERPRINT = "224122c9908cf16222641c34800f84eea3cc4e55a0e68d05953ebdd984ca9bae"
    # The whole ledger, including the text its source fingerprint leaves out (titles, severities, mappings).
    LEDGER_SHA256 = "b5208231ce1568242cc42eadbc0fceb6cddd7b5e0084db79daef4676fea53d0d"
    REQUIRED_TASK_IDS = [
        "B.1", "B.2", "B.3", "G.1", "G.2", "G.3", "G.4", "G.5", "M.1", "M.2", "M.3", "R.0", "R.3", "R.7", "R.8",
        "R.9", "R.10", "R.11", "R.12", "C.8", "C.9", "X.5", "X.6", "P.7", "P.8", "P.9", "T.1", "E.1", "F.5",
    ]
    NON_GATING_TASKS = ["H.3", "V.4", "V.6", "S.6", "A.4", "B.3", "P.6", "V.3", "V.5"]
    ORIGINAL_TASK_IDS = [
        "S.0", "S.1", "S.2", "F.0", "F.1", "F.2", "F.3", "G.0", "G.1", "G.2", "G.3", "A.0", "A.1", "I.0", "I.1",
        "I.2", "I.3", "R.0", "R.1", "R.2", "R.3", "R.4", "R.5", "R.6", "R.7", "C.0", "C.1", "C.2", "X.0", "X.1",
        "X.2", "X.3", "W.OR", "W.NF", "W.FC", "W.PG", "W.VR", "W.JI", "W.BL", "W.AC", "W.VG", "W.ZA", "W.CV",
        "W.KG", "W.ZV", "D.0", "E.F", "E.R", "E.G", "E.X", "E.W", "M.0",
    ]

    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = CHECKER.load_json(REPOSITORY / "specs/zk_delivery_graph.json")
        cls.plan = (REPOSITORY / "specs/zk_delivery_plan.md").read_text(encoding="utf-8")
        cls.ledger = CHECKER.load_json(REPOSITORY / "specs/zk_delivery_reconciliation.json")

    def test_repository_files_pass(self) -> None:
        self.assertEqual(CHECKER.ROOT, REPOSITORY)
        report = CHECKER.check_plan(self.graph, self.plan, self.ledger, REPOSITORY)
        self.assertEqual(report["errors"], [])
        self.assertIs(report["ok"], True)
        self.assertEqual((report["task_count"], report["delivery_count"]), (91, 32))
        self.assertEqual(report["roots"], sorted(self.graph["start_immediately"]))
        self.assertEqual(len(report["roots"]), 15)
        self.assertEqual(sum(report["status_counts"].values()), 91)
        # Every task is counted, and the total is the number of open items.
        self.assertEqual(list(report["open_platform_todos"]), sorted(record["id"] for record in self.graph["tasks"]))
        self.assertEqual(sum(report["open_platform_todos"].values()), report["open_platform_todo_total"])
        self.assertEqual(len(report["open_platform_todo_items"]), report["open_platform_todo_total"])
        for output_format, first in (("text", "PASS\n"), ("json", "{\n")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CHECKER.main(["--format", output_format]), 0)
            self.assertTrue(output.getvalue().startswith(first))

    def test_constraints_and_source_anchors_are_pinned(self) -> None:
        graph, ledger = self.graph, self.ledger
        self.assertEqual(canonical_sha256(graph["constraints"]), self.CONSTRAINTS_SHA256)
        surfaces = {record["id"]: [record["kind"], record.get("surface_contract")] for record in graph["deliveries"]}
        self.assertEqual(canonical_sha256(surfaces), self.DELIVERY_SURFACES_SHA256)
        self.assertEqual(graph["required_task_ids"], self.REQUIRED_TASK_IDS)
        self.assertEqual(graph["constraints"]["non_gating_tasks"], self.NON_GATING_TASKS)
        self.assertEqual(len(self.ORIGINAL_TASK_IDS), 52)
        self.assertEqual(graph["reconciliation_baseline"]["original_task_ids"], self.ORIGINAL_TASK_IDS)
        self.assertEqual([record["id"] for record in ledger["original_tasks"]], self.ORIGINAL_TASK_IDS)
        self.assertEqual(graph["reconciliation_baseline"]["ledger_inventory_sha256"], self.LEDGER_FINGERPRINT)
        self.assertEqual(CHECKER.reconciliation_inventory_sha256(ledger), self.LEDGER_FINGERPRINT)
        self.assertEqual(canonical_sha256(ledger), self.LEDGER_SHA256)
        self.assertEqual(graph["developer_surface_contract"]["supported_sdks"], SUPPORTED_SDKS)
        self.assertEqual(
            [len(ledger[name]) for name in ("requirements", "findings", "prior_findings", "original_tasks")], [119, 23, 133, 52],
        )

    def test_recorded_platform_todos_are_counted_and_do_not_certify_themselves(self) -> None:
        report = CHECKER.check_plan(self.graph, self.plan, self.ledger, REPOSITORY)
        recorded = [
            (record["id"], entry) for record in self.graph["tasks"]
            for entry in record.get("evidence", {}).get("commands", []) if "platform_todo" in entry
        ]
        still_open = sorted((identifier, entry["command"]) for identifier, entry in recorded if entry["outcome"] != "passed")
        self.assertEqual(sorted((item["task"], item["command"]) for item in report["open_platform_todo_items"]), still_open)
        self.assertEqual(report["open_platform_todo_total"], len(still_open))
        statuses = {record["id"]: record["status"] for record in self.graph["tasks"]}
        if still_open:
            self.assertNotIn("implemented", (statuses["H.3"], statuses["V.4"]))
        for identifier, entry in recorded:
            with self.subTest(task=identifier, command=entry["command"]):
                # The graph holds every marker as JSON text, so it cannot be the site of its own TODO.
                self.assertNotEqual(entry["platform_todo"]["todo_site"]["path"], "specs/zk_delivery_graph.json")

    def test_plan_states_the_platform_todo_rule_that_the_checker_enforces(self) -> None:
        prose = " ".join(self.plan.split())
        for statement in (
            "`platform` (`windows`, `linux`, `physical_x86_64` or `cuda`)", "`owner` (`H.3` or `V.4`)",
            "The TODO path must appear in evidence.paths; its marker must uniquely identify literal `TODO:` text in that file.",
            "Failed checks prohibit `implemented`.",
            "Neither H.3 nor V.4 may be `implemented` while any TODO remains open anywhere in the graph.",
            "print `open_platform_todos` counts for every task, including zero, and a global total, counting each originating "
            "command once",
            "TODOs never count as passed checks or platform qualification.",
        ):
            with self.subTest(statement=statement):
                self.assertEqual(prose.count(statement), 1)
        self.assertEqual(CHECKER.PLATFORM_TODO_PLATFORMS, ("windows", "linux", "physical_x86_64", "cuda"))
        self.assertEqual(CHECKER.PLATFORM_TODO_OWNERS, ("H.3", "V.4"))

    def test_task_text_splits_into_whole_sentences(self) -> None:
        for record in self.graph["tasks"]:
            sentences = CHECKER.task_sentences(record)
            # Nothing is lost or repeated, and every clause boundary is explicit punctuation.
            self.assertEqual(" ".join(sentences).split(), " ".join(record["outputs"] + record["acceptance"]).split())
            for sentence in sentences:
                self.assertRegex(sentence, r"[.!?]\Z", f"{record['id']}: a contract sentence ends with . ! or ?")

    def test_recorded_evidence_paths_are_not_ignored_by_git(self) -> None:
        def ignored(path: str) -> int:
            return subprocess.run(
                ["git", "-C", str(REPOSITORY), "check-ignore", "-q", "--", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            ).returncode

        try:
            control = ignored("target/zk-delivery-plan-probe")
        except OSError:
            self.skipTest("git is unavailable")
        if control not in (0, 1):
            self.skipTest("this checkout cannot evaluate Git ignore rules")
        self.assertEqual(control, 0, "target/ is expected to be ignored")
        self.assertEqual(ignored("specs/zk_delivery_graph.json"), 1)
        for record in self.graph["tasks"]:
            for path in record.get("evidence", {}).get("paths", []):
                with self.subTest(task=record["id"], path=path):
                    self.assertEqual(ignored(path), 1, "evidence must not live in an ignored tree")

    def test_pull_request_workflow_runs_the_checker_and_these_tests(self) -> None:
        workflow = (REPOSITORY / ".github/workflows/pr.yml").read_text(encoding="utf-8")

        def wired(text: str) -> list[int]:
            """Count the whole lines that run the checker and that list these tests for pytest."""
            return [
                len(re.findall(rf"^ +{line}$", text, re.MULTILINE))
                for line in (r"python3 -I -S scripts/check_zk_delivery_plan\.py", r"scripts/tests/check_zk_delivery_plan_test\.py \\")
            ]

        self.assertEqual(wired(workflow), [1, 1])
        # A commented-out line is not a step.
        commented = re.sub(r"^( +)(?=\S.*check_zk_delivery_plan)", r"\1# ", workflow, flags=re.MULTILINE)
        self.assertEqual(commented.count("# "), workflow.count("# ") + 2)
        self.assertEqual(wired(commented), [0, 0])


if __name__ == "__main__":
    unittest.main()
