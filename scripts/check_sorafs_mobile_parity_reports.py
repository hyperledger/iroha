#!/usr/bin/env python3
"""Require actual, passing JUnit execution for every SoraFS mobile CI task.

Run after the five canonical Gradle tasks in a newly created external build
directory. No environment variables or native artifacts are consumed here;
the workflow separately authenticates the exact JNI library before/after tests.
Inputs are bounded, link-free Gradle JUnit reports, including Gradle's encoded
__TEST-* filenames. Unknown XML files are refused, not counted or ignored.
The caller must supply a fresh build tree: this checker does not authenticate
run freshness from report timestamps or mtimes, or reconcile historical output.
Output contains only fixed task identifiers, execution counts, and report
digests, never test payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from xml.parsers import expat

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from sorafs_evidence_json import read_evidence_bytes  # noqa: E402
from sorafs_evidence_paths import validate_evidence_parent_chain  # noqa: E402

TASKS = (
    ("core-jvm", "test"),
    ("tools", "test"),
    ("client-android", "testDebugUnitTest"),
    ("client-android", "testDebugHostNative"),
    ("kagemusha-wallet-android", "testDebugUnitTest"),
)
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
MAX_XML_ELEMENTS = 100_000
MAX_XML_DEPTH = 32
SCHEMA = "sorafs.mobile_parity_reports.v1"


def parse_report(payload: bytes) -> int:
    """Count executed test cases, rejecting unsafe XML and forged suite totals."""

    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("JUnit report exceeds the byte limit")
    depth = 0
    elements = 0
    cases = 0
    declared = None

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, elements, cases, declared
        depth += 1
        elements += 1
        if depth > MAX_XML_DEPTH or elements > MAX_XML_ELEMENTS:
            raise ValueError("JUnit report exceeds XML structure limits")
        if depth == 1:
            if name != "testsuite":
                raise ValueError("JUnit report must contain one Gradle test suite")
            for field in ("tests", "failures", "errors", "skipped"):
                value = attributes.get(field, "")
                if re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None:
                    raise ValueError("JUnit suite counts must be canonical integers")
                if field == "tests":
                    declared = int(value)
                elif int(value) != 0:
                    raise ValueError("JUnit suite contains failures, errors or skipped tests")
        elif name == "testsuite":
            raise ValueError("JUnit report contains nested test suites")
        if name in {"failure", "error", "skipped"}:
            raise ValueError("JUnit report contains a non-passing test case")
        if name == "testcase":
            if depth != 2:
                raise ValueError("JUnit test cases must belong directly to their suite")
            cases += 1

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    def reject_declaration(*_arguments: object) -> None:
        raise ValueError("JUnit document types and entities are forbidden")

    parser = expat.ParserCreate()
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    try:
        parser.Parse(payload, True)
    except expat.ExpatError:
        raise ValueError("JUnit report is malformed XML") from None
    if declared is None or cases != declared:
        raise ValueError("JUnit declared count differs from actual test cases")
    return cases


def validate_reports(root: Path) -> dict[str, object]:
    """Require bounded, stable reports and positive executed counts for all tasks."""

    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("report root must be an absolute canonical path")
    rows = []
    total_bytes = 0
    for module, task in TASKS:
        task_id = f":{module}:{task}"
        directory = root / module / "test-results" / task
        errors: list[str] = []
        try:
            if not validate_evidence_parent_chain(
                directory / "report", errors, label="evidence file"
            ):
                raise ValueError("unsafe report directory")
            before = directory.lstat()
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError("report directory must be a real directory")
            reports = []
            with os.scandir(directory) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_DIRECTORY_ENTRIES:
                        raise ValueError("report directory exceeds its entry limit")
                    if entry.name.endswith(".xml"):
                        # Gradle encodes some suite filenames with __TEST-.
                        # Inspect every XML candidate so an unrecognized name
                        # cannot conceal a failed suite or inflate the count.
                        if not any(
                            entry.name.startswith(prefix)
                            and len(entry.name) > len(prefix) + len(".xml")
                            for prefix in ("TEST-", "__TEST-")
                        ):
                            raise ValueError("unrecognized JUnit report filename")
                        reports.append(directory / entry.name)
            cases = 0
            digests = []
            for path in sorted(reports):
                raw = read_evidence_bytes(path, MAX_REPORT_BYTES)
                total_bytes += len(raw)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError("JUnit reports exceed the total byte limit")
                cases += parse_report(raw)
                digests.append(hashlib.sha256(raw).hexdigest())
            after = directory.lstat()
            fields = ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, key) != getattr(after, key) for key in fields):
                raise ValueError("report directory changed during validation")
            if not reports or cases == 0:
                raise ValueError("task requires nonempty executed JUnit reports")
        except (OSError, RuntimeError, ValueError):
            # Neither exception text nor report filenames/payloads are public evidence.
            raise ValueError(f"{task_id} lacks complete passing JUnit evidence") from None
        rows.append(
            {"task": task_id, "executed": cases, "reports": len(reports), "sha256": digests}
        )
    return {"schema": SCHEMA, "status": "verified", "tasks": rows}


def main(argv: list[str] | None = None) -> int:
    """Check the exact task inventory and print a payload-free JSON result."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_reports(args.report_root)
    except ValueError as error:
        print(json.dumps({"schema": SCHEMA, "status": "blocked", "errors": [str(error)]}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
