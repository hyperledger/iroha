#!/usr/bin/env python3
"""Read-only reconstruction of lifecycle source identities (Python 3.11+).

Prefer current bytes when they match. Otherwise permit only the explicitly
archived lock, Norito, spec, and runner versions, checking their original hashes.
No live source is rewritten. --output optionally writes the JSON receipt.
"""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    """Hash a source file without modifying it."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    """Check every source entry against current bytes or an exact archive."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.repo.resolve()
    evidence = root / "docs/validation/parliament_ballot_prover_lifecycle"
    overrides = {
        "Cargo.lock": "build-Cargo.lock.template",
        "crates/norito/src/lib.rs": "build-norito-lib.rs.template",
        "specs/parliament_ballot_prover_lifecycle.md": "build-spec.md.template",
        "docs/validation/parliament_ballot_prover_lifecycle/run_validation.py": "run_validation.py.template",
        "docs/validation/parliament_ballot_prover_lifecycle/finish_validation.py": "finish_validation.py.template",
    }
    receipt = {"read_only": True, "helper_sha256": sha(Path(__file__)), "scopes": {}}
    for name in ["test-campaign", "supplemental", "attempts/source-drift-during-accel"]:
        directory = evidence / name
        records = []
        seen = set()
        for line in (directory / "source.sha256").read_text().splitlines():
            expected, source = line.split("  ", 1)
            assert len(expected) == 64 and all(c in "0123456789abcdef" for c in expected)
            assert source not in seen and not Path(source).is_absolute() and ".." not in Path(source).parts
            seen.add(source)
            live = sha(root / source) if (root / source).is_file() else None
            selected = root / source
            if live != expected and source in overrides:
                selected = directory / overrides[source]
            actual = sha(selected) if selected.is_file() else None
            records.append({"source": source, "expected": expected, "live_sha256": live, "selected": str(selected.relative_to(root)), "actual": actual, "matched": actual == expected})
        receipt["scopes"][name] = {"entries": len(records), "matched": sum(r["matched"] for r in records), "mismatches": [r for r in records if not r["matched"]], "archived_substitutions": [r for r in records if r["selected"] != r["source"]], "source_manifest_sha256": sha(directory / "source.sha256")}
    receipt["passed"] = all(not scope["mismatches"] for scope in receipt["scopes"].values())
    text = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
