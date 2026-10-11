#!/usr/bin/env python3
"""Retain a privacy Python guard's original test evidence before its cleanup.

Requires Python 3.12 and the caller's completed source, wheel and ABI checks.
This file-copy receipt is not independent build, release or deployment authority.
The output must be a fresh canonical child of ROOT/target/qualification. No SDK
or extension is imported. Existing outputs are never replaced.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import xml.etree.ElementTree as ET

SCHEMA = "iroha.python.native-guard-evidence.v1"
TEST_SOURCE = "python/iroha_python/tests/confidential_wallet_native_test.py"
EXPECTED = frozenset({
    "test_wallet_public_exports",
    "test_private_change_can_be_spent_with_its_default_owner",
    "test_one_input_at_full_tree_capacity_proves_and_locally_verifies",
    "test_actual_wallet_rejects_wrong_root_duplicate_inputs_and_bad_change",
    "test_real_proof_releases_gil_and_closes_native_owner",
})
TOOL_FIELDS = (
    "IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH", "IROHA_PRIVACY_AUTHENTICATED_CARGO_SEAL",
    "IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH", "IROHA_PRIVACY_AUTHENTICATED_RUSTC_SEAL",
    "IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH", "IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_SEAL",
    "IROHA_PRIVACY_AUTHENTICATED_RUSTUP_PATH", "IROHA_PRIVACY_AUTHENTICATED_RUSTUP_SEAL",
    "IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH", "IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL",
    "IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR",
    "IROHA_PRIVACY_AUTHENTICATED_MATURIN_VERSION",
)


def canonical(path: Path) -> Path:
    """Require an existing absolute path without symlink or parent normalization."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("evidence input is not an exact canonical path")
    return path


def identity(row: os.stat_result) -> tuple:
    """Bind one file's identity, extent, timestamps and permissions."""
    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns, stat.S_IMODE(row.st_mode)


def copy_original(source: Path, destination: Path, maximum: int) -> dict:
    """Copy one unchanged regular original through a bounded retained descriptor."""
    canonical(source)
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("evidence original is not a bounded regular file")
    digest = hashlib.sha256()
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if identity(os.fstat(descriptor)) != identity(before):
            raise ValueError("evidence original changed before open")
        with os.fdopen(os.dup(descriptor), "rb") as reader, destination.open("xb") as writer:
            total = 0
            while chunk := reader.read(1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise ValueError("evidence original grew beyond its bound")
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        if identity(os.fstat(descriptor)) != identity(before) or identity(source.lstat()) != identity(before):
            raise ValueError("evidence original changed during copy")
        canonical(source)
    finally:
        os.close(descriptor)
    destination.chmod(0o400)
    seal = ":".join(map(str, (digest.hexdigest(), before.st_dev, before.st_ino, before.st_size,
                               before.st_mtime_ns, before.st_ctime_ns))) + ":" + oct(stat.S_IMODE(before.st_mode))
    return {"original": str(source), "file": destination.name, "bytes": total,
            "sha256": digest.hexdigest(), "original_seal": seal}


def inspect_tests(raw: bytes, test_exit: int) -> dict:
    """Require all five original native cases, and report every suite failure/skip."""
    if len(raw) > 16 * 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("test XML is not bounded plain JUnit XML")
    tree = ET.fromstring(raw)
    cases = tree.findall(".//testcase")
    selected = [row for row in cases if row.get("classname", "").split(".")[-1] == "InstalledConfidentialWalletTests"]
    names = collections.Counter(row.get("name") for row in selected)
    faults = sum(row.find(tag) is not None for row in cases for tag in ("failure", "error", "skipped"))
    return {"exit": test_exit, "total_cases": len(cases), "native_cases": dict(names),
            "faults_or_skips": faults,
            "passed": test_exit == 0 and faults == 0 and names == collections.Counter(EXPECTED)}


def retain(args: argparse.Namespace) -> dict:
    """Preserve caller-verified originals and a truthful test result outside cleanup."""
    root = canonical(args.root)
    qualification = canonical(root / "target/qualification")
    parent = canonical(args.output.parent)
    if parent != qualification and qualification not in parent.parents:
        raise ValueError("evidence output is outside original target/qualification")
    canonical(args.private_dir)
    canonical(args.venv)
    if args.output == args.private_dir or args.private_dir in args.output.parents:
        raise ValueError("evidence output would be removed by guard cleanup")
    if args.venv not in canonical(args.native).parents:
        raise ValueError("installed native original is outside the private venv")
    if len(args.source_pin.encode()) > 65536:
        raise ValueError("source pin exceeds control bound")
    source_pin = json.loads(args.source_pin)
    args.output.mkdir(mode=0o700)  # Deliberately refuse existing or partial output.
    files = {}
    selections = {
        "native_wheel": (args.native_wheel, "native.whl", 1024**3),
        "sdk_wheel": (args.sdk_wheel, "sdk.whl", 1024**3),
        "native": (args.native, "installed-native.original", 1024**3),
        "manifest": (args.manifest, "artifact-manifest.json", 65536),
        "tests": (args.tests, "tests.xml", 16 * 1024**2),
        "cargo_audit": (args.cargo_audit, "cargo-invocations.original", 64 * 1024**2),
        "test_source": (root / TEST_SOURCE, "confidential_wallet_native_test.py", 1024**2),
        "guard_source": (root / "ci/check_privacy_python_sdk.sh", "guard.sh", 1024**2),
    }
    for label, (source, name, maximum) in selections.items():
        files[label] = copy_original(source, args.output / name, maximum)
    if files["native_wheel"]["original_seal"] != args.native_wheel_seal or files["sdk_wheel"]["original_seal"] != args.sdk_wheel_seal:
        raise ValueError("retained wheel changed from the caller's authenticated original")
    manifest = json.loads((args.output / "artifact-manifest.json").read_bytes())
    if manifest.get("sdk") != "python" or manifest.get("artifact_sha256") != files["native"]["sha256"]:
        raise ValueError("retained installed native differs from the verified manifest")
    if any(manifest.get(key) != source_pin.get(key) for key in ("workspace_source_manifest_sha256",)) or manifest.get("source_commit") != source_pin.get("head_commit"):
        raise ValueError("retained manifest differs from the original source pin")
    tests = inspect_tests((args.output / "tests.xml").read_bytes(), args.test_exit)
    record = {"schema": SCHEMA, "scope": "Caller-verified release-guard file and test evidence; not standalone build, release or deployment authority.",
              "source_pin": source_pin, "files": files, "tests": tests,
              "tools": {key: os.environ.get(key) for key in TOOL_FIELDS},
              "python": {"path": str(Path(sys.executable).resolve()), "version": sys.version},
              "guard_cleanup_exit_not_observed": True, "passed": tests["passed"]}
    with (args.output / "receipt.json").open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    (args.output / "receipt.json").chmod(0o400)
    directory = os.open(args.output, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return record


def main() -> int:
    """Expose only explicit original paths; never import a native SDK."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "output", "private-dir", "venv", "native", "native-wheel", "sdk-wheel", "manifest", "tests", "cargo-audit"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("native-wheel-seal", "sdk-wheel-seal", "source-pin"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--test-exit", required=True, type=int)
    args = parser.parse_args()
    try:
        record = retain(args)
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"receipt": str(args.output / "receipt.json"), "passed": record["passed"]}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
