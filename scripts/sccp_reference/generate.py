#!/usr/bin/env python3
"""Regenerate or check the SCCP v1 fixtures produced by the independent Python reference.

Purpose: `specs/sccp.md` §11 requires an independent re-derivation of every
contract-visible SCCP vector. This command builds

* `fixtures/sccp/finality_v1.json` (X, R, P, m, QC_FIXED, anchors, full certificates),
* `fixtures/sccp/committee_transitions_v1.json` (the §5.1 destination state machine),
* `fixtures/sccp/control_v1.json` (control leaves and their destination effects),
* `fixtures/sccp/governance_v1.json` (proposal frames and subject heads),
* `fixtures/sccp/fast_pause_v1.json` (Core emergency pause component boundaries),
* `fixtures/sccp/forgery_evidence_v1.json` (E0--E4, anchors and offender custody),
* `fixtures/sccp/liability_v1.json` (clock, L3/L5, pruning and P2),
* `fixtures/sccp/bls_consensus_v1.json` (hash-to-G2, signatures, aggregates, allowlist),

asserting every worked value the specification pins while it builds them.

The finality, transition and control files are also written, byte for byte, by the Rust reference
(`cargo test -p iroha_sccp --test v1_reference_finality --test
v1_reference_transitions --test v1_reference_control -- --ignored regenerate`),
so a changed or added row needs both generators. `bls_consensus_v1.json` has
this generator only; `iroha_crypto` reproduces it row by row. The four Core
fixtures have independent Rust producers in iroha_core SCCP unit tests, with
byte-for-byte drift tests and ignored regenerate_<file-stem> tests.

Prerequisites: Python 3.10+ and nothing else (the BLS12-381 and Keccak code is
self-contained). The Ethereum cross-check reads the captured responses in
`fixtures/sccp/rpc/eth/`.

Usage (from the repository root):

    python3 scripts/sccp_reference/generate.py --check          # fail on drift (default)
    python3 scripts/sccp_reference/generate.py --write          # rewrite the files
    python3 scripts/sccp_reference/generate.py --check --only finality_v1.json

No environment variables are read.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from sccp_reference import vectors_bls, vectors_control, vectors_finality, vectors_transitions, vectors_governance, vectors_fast_pause, vectors_forgery_evidence, vectors_liability  # type: ignore
else:
    from . import vectors_bls, vectors_control, vectors_finality, vectors_transitions, vectors_governance, vectors_fast_pause, vectors_forgery_evidence, vectors_liability

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "sccp"

BUILDERS: dict[str, Callable[[], dict]] = {
    "finality_v1.json": vectors_finality.build,
    "committee_transitions_v1.json": vectors_transitions.build,
    "control_v1.json": vectors_control.build,
    "governance_v1.json": vectors_governance.build,
    "fast_pause_v1.json": vectors_fast_pause.build,
    "forgery_evidence_v1.json": vectors_forgery_evidence.build,
    "liability_v1.json": vectors_liability.build,
    "bls_consensus_v1.json": vectors_bls.build,
}


def render(document: dict) -> str:
    """Canonical text of a fixture: sorted keys, two-space indent, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def build(name: str) -> str:
    """Build one fixture file's text."""
    return render(BUILDERS[name]())


def check(name: str, directory: Path = FIXTURE_DIR) -> list[str]:
    """Return a short unified diff when the committed file differs from a fresh build (empty when equal)."""
    expected = build(name)
    path = directory / name
    actual = path.read_text() if path.exists() else ""
    if actual == expected:
        return []
    diff = difflib.unified_diff(
        actual.splitlines(), expected.splitlines(), f"committed/{name}", f"regenerated/{name}", lineterm="", n=1
    )
    return list(diff)[:60] or [f"{name}: missing"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="compare with the committed files (default)")
    mode.add_argument("--write", action="store_true", help="rewrite the fixture files")
    parser.add_argument("--only", action="append", choices=sorted(BUILDERS), help="restrict to one file (repeatable)")
    parser.add_argument("--fixtures-dir", type=Path, default=FIXTURE_DIR, help="directory holding the fixtures")
    args = parser.parse_args(argv)
    names = args.only or list(BUILDERS)
    failed = False
    for name in names:
        if args.write:
            (args.fixtures_dir / name).write_text(build(name))
            print(f"wrote {args.fixtures_dir / name}")
            continue
        diff = check(name, args.fixtures_dir)
        if diff:
            failed = True
            print(f"DRIFT {name}:")
            print("\n".join(diff))
        else:
            print(f"ok {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
