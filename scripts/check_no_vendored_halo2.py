#!/usr/bin/env python3
"""Reject the retired Axiom proof stack in every workspace dependency closure.

No oracle root or development edge is exempt. Orchard's separate Zcash
halo2_proofs and the nonvendored halo2curves primitive are not retired.
"""
from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import subprocess
import sys

RETIRED = frozenset({
    "halo2-axiom", "halo2-base", "halo2-ecc", "halo2curves-axiom",
    "snark-verifier", "snark-verifier-sdk", "poseidon-primitives",
    "iroha_plonk_oracle",
})


def violations(metadata: dict, root: Path) -> list[str]:
    """Return forbidden normal/build/development paths; incomplete Cargo data fails closed."""
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    members = metadata["workspace_members"]
    if not members or not packages or not nodes:
        raise ValueError("Cargo metadata must contain workspace members and a resolved graph")
    edges = {}
    for package_id, node in nodes.items():
        if package_id not in packages:
            raise ValueError(f"resolved package has no package metadata: {package_id}")
        selected = []
        for dep in node["deps"]:
            kinds = dep["dep_kinds"]
            if not kinds or any(item["kind"] not in (None, "build", "dev") for item in kinds):
                raise ValueError(f"unknown dependency kind from {package_id}")
            if dep["pkg"] not in packages or dep["pkg"] not in nodes:
                raise ValueError(f"dependency has no resolved package: {dep['pkg']}")
            # First-release retirement covers every target and dependency kind,
            # including test-only, platform-specific and optional selected edges.
            selected.append(dep["pkg"])
        edges[package_id] = selected
    problems = []
    for member in members:
        if member not in packages or member not in nodes:
            raise ValueError(f"workspace member has no resolved package: {member}")
        package = packages[member]
        queue = deque([(member, (package["name"],))])
        visited = set()
        while queue:
            current, path = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if packages[current]["name"] in RETIRED:
                problems.append(" -> ".join(path))
                break
            queue.extend((dep, (*path, packages[dep]["name"])) for dep in edges[current])
    return problems


def main() -> int:
    """Check the all-feature, all-target Cargo graph without building code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--metadata", type=Path, help="inspect an already captured Cargo graph")
    parser.add_argument("--offline", action="store_true", help="require cached Cargo dependencies")
    args = parser.parse_args()
    try:
        if args.metadata:
            metadata = json.loads(args.metadata.read_text())
        else:
            command = ["cargo", "metadata", "--locked", "--all-features", "--format-version=1"]
            if args.offline:
                command.append("--offline")
            result = subprocess.run(
                command,
                cwd=args.root, check=True, capture_output=True, text=True,
            )
            metadata = json.loads(result.stdout)
        problems = violations(metadata, args.root)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"[no-vendored-halo2] invalid dependency evidence: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"[no-vendored-halo2] forbidden dependency path: {problem}", file=sys.stderr)
        return 1
    print("[no-vendored-halo2] PASS: all workspace normal/build/development closures exclude the retired stack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
