#!/usr/bin/env python3
"""Compare the ZK validity record of `iroha_core` across Cargo feature selections.

Task F.4 of specs/zk_delivery_plan.md: a Cargo feature must not change a
certified root, an effect or a gas charge. The unit test
`zk_validity_policy::parity_tests::feature_parity::feature_parity_record`
(crates/iroha_core/src/zk_validity_policy_feature_parity_tests.rs) executes one
fixed scenario and prints named digests:

    ZK_FEATURE_PARITY features=<compiled features>
    ZK_FEATURE_PARITY must_equal.<name>=<digest>
    ZK_FEATURE_PARITY gated.<feature>.<operation>=<outcome>

This script builds and runs that test once per feature selection and compares
the lines.

* Every `must_equal` record has to be identical in every selection. A
  difference is a feature that changes a root, an effect or gas, and fails.
* A `gated` record names an operation that is still compiled only under a
  Cargo feature. It may differ between selections only while
  specs/zk_runtime_validity_census.json classifies that `iroha_core` feature as
  a validity or availability gate whose entry is `open`. A gated record that
  differs without such an entry fails, and so does an entry that is `open`
  while every compared selection agrees on all its gated records although at
  least one selection lacks the feature (the census is then stale).

The script changes no tracked file. It reads no environment variable; the
Cargo target directory is the `--target-dir` argument. Each selection is a
separate build of the `iroha_core` unit-test binary, so a full run takes two
long builds. `--from-output NAME=FILE` compares captured outputs without
building (the unit tests of this script use it).

Limits: the comparison covers the scenario of the test (a certified history
with an authorized policy change, policy identities, limit decisions and
verification gas) and the listed selections. It is not a proof that no other
operation depends on a feature; the census lists every `#[cfg(feature)]` site
of the scanned crates.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
CENSUS = "specs/zk_runtime_validity_census.json"
LINE_PREFIX = "ZK_FEATURE_PARITY "
TEST_FILTER = "zk_validity_policy::parity_tests::feature_parity::feature_parity_record"
GATE_CLASSES = ("validity_gate", "availability_gate")

# Feature selections of `iroha_core`. `node` is the shipped default feature
# set (`node` plus `simd`). Each other selection removes one gate family from
# the same list; `None` means the crate's default features.
NODE_FEATURES = (
    "runtime",
    "proofs-stark",
    "app_api",
    "gost",
    "sm",
    "telemetry",
    "zk-preverify",
    "simd",
)
SELECTIONS: dict[str, Optional[tuple[str, ...]]] = {
    "node": None,
    "node-without-stark": tuple(f for f in NODE_FEATURES if f != "proofs-stark"),
    "node-without-sm-gost": tuple(f for f in NODE_FEATURES if f not in ("sm", "gost")),
}
DEFAULT_SELECTIONS = ("node", "node-without-stark")


class ParityError(Exception):
    """A malformed record or an unusable input."""


def parse_record(name: str, output: str) -> dict[str, dict[str, str]]:
    """Return {'features': {...}, 'must_equal': {...}, 'gated': {...}} of one run."""
    record: dict[str, dict[str, str]] = {"features": {}, "must_equal": {}, "gated": {}}
    seen = False
    for raw in output.splitlines():
        # With `--nocapture` the test harness prints `test <name> ... ` before
        # the first line of the test's own output, on the same line.
        start = raw.find(LINE_PREFIX)
        if start < 0:
            continue
        line = raw[start:].strip()
        seen = True
        body = line[len(LINE_PREFIX) :]
        key, separator, value = body.partition("=")
        if not separator or not key:
            raise ParityError(f"{name}: malformed record line `{line}`")
        if key == "features":
            record["features"]["compiled"] = value
            continue
        group, dot, item = key.partition(".")
        if group not in ("must_equal", "gated") or not dot or not item:
            raise ParityError(f"{name}: unknown record `{key}`")
        if item in record[group]:
            raise ParityError(f"{name}: record `{key}` is printed twice")
        if not value:
            raise ParityError(f"{name}: record `{key}` is empty")
        record[group][item] = value
    if not seen:
        raise ParityError(f"{name}: the test printed no `{LINE_PREFIX.strip()}` line")
    if not record["must_equal"]:
        raise ParityError(f"{name}: no `must_equal` record")
    return record


def load_gates(census: dict) -> dict[str, dict[str, str]]:
    """Map each gate feature of `iroha_core` to its census entry and status."""
    statuses = {entry["id"]: entry.get("status") for entry in census.get("entries", [])}
    gates: dict[str, dict[str, str]] = {}
    for feature, row in census.get("features", {}).get("iroha_core", {}).items():
        if row.get("class") in GATE_CLASSES:
            entry = row.get("entry", "")
            gates[feature] = {"entry": entry, "status": statuses.get(entry, "")}
    return gates


def compare(
    records: dict[str, dict[str, dict[str, str]]], gates: dict[str, dict[str, str]]
) -> list[str]:
    """Return the problems of a set of per-selection records (empty when they agree)."""
    problems: list[str] = []
    names = sorted(records)
    if len(names) < 2:
        return [f"need at least two feature selections to compare, got {names}"]

    keys = set()
    for name in names:
        keys.update(records[name]["must_equal"])
    for key in sorted(keys):
        values = {name: records[name]["must_equal"].get(key) for name in names}
        if any(value is None for value in values.values()):
            missing = [name for name, value in values.items() if value is None]
            problems.append(f"must_equal.{key}: not printed by {missing}")
        elif len(set(values.values())) != 1:
            detail = ", ".join(f"{name}={values[name]}" for name in names)
            problems.append(
                f"must_equal.{key}: a Cargo feature changes this record ({detail})"
            )

    gated_keys = set()
    for name in names:
        gated_keys.update(records[name]["gated"])
    differing_features: set[str] = set()
    covered_features: set[str] = set()
    for key in sorted(gated_keys):
        feature = key.split(".", 1)[0]
        covered_features.add(feature)
        values = {name: records[name]["gated"].get(key) for name in names}
        if any(value is None for value in values.values()):
            missing = [name for name, value in values.items() if value is None]
            problems.append(f"gated.{key}: not printed by {missing}")
            continue
        if len(set(values.values())) == 1:
            continue
        differing_features.add(feature)
        gate = gates.get(feature)
        detail = ", ".join(f"{name}={values[name]}" for name in names)
        if gate is None:
            problems.append(
                f"gated.{key}: differs ({detail}) but the census does not classify "
                f"`iroha_core/{feature}` as a validity or availability gate"
            )
        elif gate["status"] != "open":
            problems.append(
                f"gated.{key}: differs ({detail}) although census entry "
                f"`{gate['entry']}` has status `{gate['status']}`"
            )

    # A gate the census still lists as open must show in a comparison that
    # includes a selection without the feature.
    for feature in sorted(covered_features - differing_features):
        gate = gates.get(feature)
        compiled = {
            name: feature in records[name]["features"].get("compiled", "").split(",")
            for name in names
        }
        if gate and gate["status"] == "open" and len(set(compiled.values())) > 1:
            problems.append(
                f"gated records of `{feature}` agree across {names} although one "
                f"selection lacks the feature and census entry `{gate['entry']}` is "
                "still `open`: update the census"
            )
    return problems


def cargo_command(selection: str, target_dir: Optional[str]) -> list[str]:
    """The cargo invocation that runs the record test for one selection."""
    features = SELECTIONS[selection]
    command = ["cargo", "test", "-p", "iroha_core", "--lib"]
    if features is not None:
        command += ["--no-default-features", "--features", ",".join(features)]
    if target_dir:
        command += ["--target-dir", target_dir]
    command += ["--", TEST_FILTER, "--exact", "--nocapture", "--test-threads=1"]
    return command


def run_selection(selection: str, target_dir: Optional[str]) -> str:
    """Build and run the record test under one feature selection."""
    command = cargo_command(selection, target_dir)
    print(f"check_zk_feature_parity: running `{' '.join(command)}`", flush=True)
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        tail = "\n".join((completed.stdout + completed.stderr).splitlines()[-40:])
        raise ParityError(
            f"{selection}: cargo exited with {completed.returncode}\n{tail}"
        )
    return completed.stdout


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--selection",
        action="append",
        choices=sorted(SELECTIONS),
        help="feature selection to build and run (repeatable; default: "
        + ", ".join(DEFAULT_SELECTIONS)
        + ")",
    )
    parser.add_argument(
        "--from-output",
        action="append",
        default=[],
        metavar="NAME=FILE",
        help="use the captured test output FILE as selection NAME instead of building",
    )
    parser.add_argument("--target-dir", help="Cargo target directory for the builds")
    parser.add_argument("--census", default=CENSUS, help="census path, relative to the repository")
    parser.add_argument(
        "--print-commands",
        action="store_true",
        help="print the cargo command of each selection and exit",
    )
    args = parser.parse_args(argv)

    if args.print_commands:
        for selection in args.selection or DEFAULT_SELECTIONS:
            print(" ".join(cargo_command(selection, args.target_dir)))
        return 0

    try:
        census_path = Path(args.census)
        if not census_path.is_absolute():
            census_path = ROOT / census_path
        gates = load_gates(json.loads(census_path.read_text(encoding="utf-8")))
        records: dict[str, dict[str, dict[str, str]]] = {}
        for item in args.from_output:
            name, separator, path = item.partition("=")
            if not separator or not name or not path:
                raise ParityError(f"--from-output expects NAME=FILE, got `{item}`")
            if name in records:
                raise ParityError(f"selection `{name}` is given twice")
            records[name] = parse_record(name, Path(path).read_text(encoding="utf-8"))
        if not args.from_output or args.selection:
            for selection in args.selection or DEFAULT_SELECTIONS:
                if selection in records:
                    raise ParityError(f"selection `{selection}` is given twice")
                records[selection] = parse_record(
                    selection, run_selection(selection, args.target_dir)
                )
        problems = compare(records, gates)
    except (ParityError, OSError, json.JSONDecodeError) as error:
        print(f"check_zk_feature_parity: error: {error}", file=sys.stderr)
        return 2

    for name in sorted(records):
        compiled = records[name]["features"].get("compiled", "")
        print(f"check_zk_feature_parity: {name}: features [{compiled}]")
        for key, value in sorted(records[name]["gated"].items()):
            print(f"check_zk_feature_parity: {name}: gated.{key}={value}")
    if problems:
        for problem in problems:
            print(f"check_zk_feature_parity: FAIL: {problem}", file=sys.stderr)
        return 1
    names = sorted(records)
    count = len(records[names[0]]["must_equal"])
    print(
        f"check_zk_feature_parity: OK ({count} must-equal records identical across "
        f"{names}; gated differences are open census gates)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
