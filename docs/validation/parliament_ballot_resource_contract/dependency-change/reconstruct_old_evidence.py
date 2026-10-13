#!/usr/bin/env python3
"""Reconstruct three historical source inventories without changing the checkout.

Python 3.11+, standard library only; no environment variables or builds. Run
from any directory. --repo selects the checkout; --output writes a NEW receipt.
Otherwise JSON goes to stdout. --self-test exercises strict patch reversal and
manifest/path validation without reading the checkout. Archived input hashes
are pinned here; a new source mismatch is reported, never silently accepted.

The reconstructed bytes exist only in memory. Original 223/225/92-file
manifests, fixtures, patches, dependency snapshots and prior reports remain
unchanged. This establishes source byte identity, not a new qualification run.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[4]
B6 = "docs/validation/parliament_ballot_b6/"
DEPENDENCIES = "docs/validation/parliament_ballot_resource_contract/dependency-change/"
PINS = {
    B6 + "mac-source.sha256": "044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb",
    B6 + "malformed-source.sha256": "7cc9ad79e452fe3cfd58cc0fdc570a7d5b76614f7352d9c13ba9b17be670a409",
    B6 + "nonminimal-counter-source.sha256": "ad76c42230d77f73b57f5903397e4a31ecd54cd8117a4aaf57dca815adee4559",
    B6 + "measured-root-Cargo.lock.template": "ecfb0f0635527e68e3e329bfbde338e051912e10986839d66d8e384011e9e303",
    B6 + "qualification-root-Cargo.lock.template": "dc55d38cf752be174f1e270b0c3ff7d292bdaed5f7d8297daf2225d4249c1c48",
    B6 + "qualification-norito-lib.rs.template": "e7540b2a30b5d5a7e8ff15d7b354ef5ba0d0bc891289276e6b40ddaacc2fd5dd",
    B6 + "post-measurement-rustdoc.patch": "ca32f64a4e3a64cb635792eb14179d46c6b6314f576df6165c1238a7a5805181",
    B6 + "post-measurement-malformed-runner.patch": "ae4275e1d803e948fc455c15c0c7fbf8fdd422bf9739c9030857d98efc007d5c",
    DEPENDENCIES + "ballot-Cargo.toml.before.template": "1b555b57b3541f5b031378628aaa42c5b78ad86dc36ceee043d023f49a83a3b7",
    DEPENDENCIES + "ballot-Cargo.toml.after.template": "f1b9e23aceb1039ff92b3d4dc2f9a94d63afa35842b5b3541b7c9e32b00f76d5",
    DEPENDENCIES + "root-Cargo.lock.after.template": "3caa5fbc9bc169e27257e456abf13beb1c7b53fae27f63dff68ffb39054b8cba",
}
SCOPES = (("mac-source.sha256", 223), ("malformed-source.sha256", 225),
          ("nonminimal-counter-source.sha256", 92))


def sha256(data: bytes) -> str:
    """Return a source-content digest; never infer identity from modification time."""
    return hashlib.sha256(data).hexdigest()


def relative_path(path: str) -> str:
    """Only normalized repository-relative paths may address snapshot inputs."""
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or not parsed.parts or ".." in parsed.parts or str(parsed) != path:
        raise ValueError(f"unsafe or noncanonical source path: {path!r}")
    return path


def parse_manifest(data: bytes) -> dict[str, str]:
    """Require canonical SHA-256 lines and unique paths in an old inventory."""
    entries = {}
    for line in data.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("invalid source manifest line")
        digest, path = match.groups()
        relative_path(path)
        if path in entries:
            raise ValueError(f"duplicate source path: {path}")
        entries[path] = digest
    if not entries:
        raise ValueError("empty source manifest")
    return entries


def reverse_patch(patch: bytes, sources: dict[str, bytes]) -> dict[str, bytes]:
    """Reverse exact unified hunks at their recorded post-change line positions.

    No fuzzy matching, shell patch execution, file writes or ignored context.
    Only ordinary text hunks are accepted. Any unknown concurrent source change
    in a recorded hunk makes this reconstruction fail closed.
    """
    lines = patch.decode("utf-8").splitlines(keepends=True)
    result = {}
    position = 0
    while position < len(lines):
        if not lines[position].startswith("--- a/"):
            raise ValueError("expected unified before-file header")
        path = relative_path(lines[position][6:].rstrip("\n"))
        position += 1
        if position >= len(lines) or lines[position] != f"+++ b/{path}\n":
            raise ValueError("inconsistent unified file headers")
        position += 1
        if path in result or path not in sources:
            raise ValueError(f"missing or duplicate patch source: {path}")
        original = sources[path].decode("utf-8").splitlines(keepends=True)
        reconstructed = []
        cursor = 0
        hunks = 0
        while position < len(lines) and lines[position].startswith("@@ "):
            header = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[position])
            if not header:
                raise ValueError("invalid unified hunk")
            old_start, old_count, new_start, new_count = header.groups()
            old_count = int(old_count) if old_count is not None else 1
            new_count = int(new_count) if new_count is not None else 1
            at = int(new_start) - (1 if new_count else 0)
            if at < cursor or at > len(original):
                raise ValueError(f"out-of-order or out-of-range patch hunk: {path}")
            position += 1
            before, after = [], []
            while position < len(lines) and not lines[position].startswith(("@@ ", "--- a/")):
                line = lines[position]
                if line[:1] not in (" ", "+", "-"):
                    raise ValueError("unsupported unified hunk body")
                if line[0] in (" ", "-"):
                    before.append(line[1:])
                if line[0] in (" ", "+"):
                    after.append(line[1:])
                position += 1
            if len(before) != old_count or len(after) != new_count:
                raise ValueError("hunk line count does not match header")
            if original[at:at + new_count] != after:
                raise ValueError(f"post-change hunk context differs: {path}:{new_start}")
            reconstructed.extend(original[cursor:at])
            reconstructed.extend(before)
            cursor = at + new_count
            hunks += 1
        if not hunks:
            raise ValueError("patch file has no hunks")
        reconstructed.extend(original[cursor:])
        result[path] = "".join(reconstructed).encode("utf-8")
    if not result:
        raise ValueError("empty patch")
    return result


def lock_package_changes(before: bytes, after: bytes) -> dict:
    """Describe current lock drift separately from historical reconstruction."""
    def packages(data):
        return {(p["name"], p["version"], p.get("source", "")): p
                for p in tomllib.loads(data.decode("utf-8"))["package"]}

    old, new = packages(before), packages(after)
    return {"removed": [old[key] for key in sorted(old.keys() - new.keys())],
            "added": [new[key] for key in sorted(new.keys() - old.keys())],
            "changed": [{"before": old[key], "after": new[key]}
                        for key in sorted(old.keys() & new.keys()) if old[key] != new[key]]}


def reconstruct(repo: Path) -> dict:
    """Check every old input after only the explicitly archived substitutions."""
    archived = {}
    for path, expected in PINS.items():
        data = (repo / path).read_bytes()
        if sha256(data) != expected:
            raise ValueError(f"archived reconstruction input changed: {path}")
        archived[path] = data
    manifests = {name: parse_manifest(archived[B6 + name]) for name, _ in SCOPES}
    live = {}
    for path in sorted(set().union(*(manifest.keys() for manifest in manifests.values()))):
        source = repo / path
        live[path] = source.read_bytes() if source.is_file() else None
    patch_results, patch_methods = {}, {}
    for name in ("post-measurement-rustdoc.patch", "post-measurement-malformed-runner.patch"):
        reconstructed = reverse_patch(archived[B6 + name], {p: b for p, b in live.items() if b is not None})
        if patch_results.keys() & reconstructed.keys():
            raise ValueError("overlapping patch outputs require an explicit ordering contract")
        patch_results.update(reconstructed)
        patch_methods.update({path: {"method": "strict_in_memory_reverse_patch", "artifact": B6 + name}
                              for path in reconstructed})
    scopes = []
    for name, count in SCOPES:
        expected = manifests[name]
        if len(expected) != count:
            raise ValueError(f"historical source count changed: {name}")
        templates = {
            "Cargo.lock": B6 + ("measured-root-Cargo.lock.template" if name == "mac-source.sha256"
                                else "qualification-root-Cargo.lock.template"),
            "crates/iroha_parliament_ballot_proof/Cargo.toml": DEPENDENCIES + "ballot-Cargo.toml.before.template",
        }
        if "crates/norito/src/lib.rs" in expected:
            templates["crates/norito/src/lib.rs"] = B6 + "qualification-norito-lib.rs.template"
        records = []
        for path, digest in expected.items():
            current = live[path]
            effective = current
            method = {"method": "unchanged_checkout_bytes"}
            if path in templates:
                effective = archived[templates[path]]
                method = {"method": "archived_exact_template", "artifact": templates[path]}
            elif name == "mac-source.sha256" and path in patch_results:
                effective = patch_results[path]
                method = patch_methods[path]
            actual = sha256(effective) if effective is not None else None
            records.append({"path": path, "expected_sha256": digest,
                            "live_sha256": sha256(current) if current is not None else None,
                            "reconstructed_sha256": actual, "matches": actual == digest, **method})
        mismatches = [record for record in records if not record["matches"]]
        scopes.append({"source_manifest": B6 + name, "manifest_sha256": PINS[B6 + name],
                       "expected_files": count, "verified_files": count - len(mismatches),
                       "unresolved_mismatches": mismatches, "files": records})
    current_lock = sha256(live["Cargo.lock"]) if live["Cargo.lock"] is not None else None
    after_lock = PINS[DEPENDENCIES + "root-Cargo.lock.after.template"]
    return {"schema": "parliament-old-evidence-reconstruction-v1",
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "script_sha256": sha256(Path(__file__).read_bytes()),
            "archived_input_sha256": PINS,
            "all_historical_sources_reconstructed": all(not scope["unresolved_mismatches"] for scope in scopes),
            "source_scopes": scopes,
            "current_lock_after_dependency_snapshot": {"live_sha256": current_lock, "archived_after_sha256": after_lock,
                                                       "matches": current_lock == after_lock,
                                                       "package_changes": lock_package_changes(archived[DEPENDENCIES + "root-Cargo.lock.after.template"], live["Cargo.lock"]) if live["Cargo.lock"] is not None else None,
                                                       "interpretation": "A mismatch is current checkout drift, not a failure to reconstruct archived old locks."},
            "scope": "Exact historical source byte identity only. Templates replace the old locks, Norito source and ballot manifest. Recorded Rustdoc/malformed patches are reversed strictly in memory for the original 223-file campaign. No live or historical file is modified; no tests/builds/measurements are retargeted to the new dependency.",
            "production_qualified": False}


class ReconstructionTests(unittest.TestCase):
    """Cheap independent cases for the reconstruction's fail-closed mechanics."""

    def test_hash_and_manifest(self):
        self.assertEqual(sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        line = "0" * 64 + "  src/a.rs\n"
        self.assertEqual(parse_manifest(line.encode()), {"src/a.rs": "0" * 64})
        for text in ("", "wrong", line + line, "0" * 64 + "  ../outside\n"):
            with self.assertRaises(ValueError):
                parse_manifest(text.encode())

    def test_paths(self):
        self.assertEqual(relative_path("src/file.rs"), "src/file.rs")
        for path in ("/absolute", "../parent", "a/../b", "./file", "a//b", ""):
            with self.assertRaises(ValueError):
                relative_path(path)

    def test_exact_reverse_with_two_hunks(self):
        patch = b"--- a/file\n+++ b/file\n@@ -1,2 +1,3 @@\n one\n-old\n+new\n+insert\n@@ -4 +5 @@\n-oldtail\n+newtail\n"
        current = b"one\nnew\ninsert\nmiddle\nnewtail\n"
        self.assertEqual(reverse_patch(patch, {"file": current}), {"file": b"one\nold\nmiddle\noldtail\n"})
        with self.assertRaisesRegex(ValueError, "context differs"):
            reverse_patch(patch, {"file": current.replace(b"new\n", b"drift\n")})
        with self.assertRaisesRegex(ValueError, "line count"):
            reverse_patch(patch.replace(b"+1,3", b"+1,4"), {"file": current})
        with self.assertRaisesRegex(ValueError, "missing"):
            reverse_patch(patch, {})

    def test_lock_drift_does_not_relabel_a_dependency_snapshot(self):
        before = b'[[package]]\nname="keep"\nversion="1"\ndependencies=["old"]\n[[package]]\nname="gone"\nversion="2"\n'
        after = b'[[package]]\nname="keep"\nversion="1"\ndependencies=["new"]\n[[package]]\nname="added"\nversion="3"\n'
        changes = lock_package_changes(before, after)
        self.assertEqual([p["name"] for p in changes["removed"]], ["gone"])
        self.assertEqual([p["name"] for p in changes["added"]], ["added"])
        self.assertEqual(changes["changed"][0]["before"]["dependencies"], ["old"])
        self.assertEqual(changes["changed"][0]["after"]["dependencies"], ["new"])


def main(argv: list[str] | None = None) -> int:
    """Write a fresh receipt; failures never amend the archived source pins."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReconstructionTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        result = reconstruct(args.repo.resolve())
    except (OSError, ValueError) as error:
        result = {"all_historical_sources_reconstructed": False, "error": str(error),
                  "production_qualified": False}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if result["all_historical_sources_reconstructed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
