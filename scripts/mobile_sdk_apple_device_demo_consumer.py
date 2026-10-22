#!/usr/bin/env python3
"""Prepare a separate physical iOS Debug consumer record for SwiftPM validation.

This does not produce, rebuild, sign or qualify a native artifact. Package.swift
independently checks the original artifact and every record field before use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    """Hash an existing canonical regular file without following an alias."""
    if not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"noncanonical regular input: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_record(artifact_directory: Path, *, allow_source_head_drift: bool) -> dict:
    """Observe unchanged producer facts; SwiftPM remains the admission owner."""
    if (not artifact_directory.is_absolute()
            or artifact_directory.resolve(strict=True) != artifact_directory):
        raise ValueError("artifact directory must be an existing canonical absolute path")
    artifact = artifact_directory / "NoritoBridge.xcframework"
    manifest_path = artifact / "NoritoBridge.artifacts.json"
    manifest_hash = sha256(manifest_path)
    manifest = json.loads(manifest_path.read_bytes())
    original = manifest.get("source_commit")
    current = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    if (not isinstance(original, str) or re.fullmatch("[0-9a-f]{40}", original) is None
            or re.fullmatch("[0-9a-f]{40}", current) is None):
        raise ValueError("source commits must be exact canonical Git identities")
    if original != current and not allow_source_head_drift:
        raise ValueError("physical-device demo source commit differs from the selected checkout")
    if (manifest.get("schema") != "iroha.norito-bridge-device-demo-artifact.v1"
            or manifest.get("artifact_scope") != "physical-device-demo"
            or manifest.get("purpose") != "physical-ios-debug"
            or manifest.get("source_root") != str(ROOT)
            or manifest.get("target_triple") != "aarch64-apple-ios"
            or type(manifest.get("native_bridge_abi_version")) is not int
            or manifest["native_bridge_abi_version"] != 31):
        raise ValueError("the original physical iOS Debug producer metadata differs")
    archive_hash = sha256(artifact / "ios-arm64/libNoritoBridge.a")
    if manifest.get("hashes") != {"ios-arm64": archive_hash}:
        raise ValueError("the original archive hash differs")
    evidence = manifest.get("evidence")
    names = {"producer-launch.json", "producer-record.json", "cargo-messages.jsonl",
             "pqcrypto-normalization.json", "consumer", "source-observation.json"}
    if not isinstance(evidence, dict) or set(evidence) != names:
        raise ValueError("the original producer evidence inventory differs")
    if any(sha256(artifact / "evidence" / name) != value for name, value in evidence.items()):
        raise ValueError("the original producer evidence changed")
    if (sha256(manifest_path) != manifest_hash
            or subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip() != current):
        raise ValueError("source or artifact changed during receipt preparation")
    return {
        "schema": "iroha.norito-bridge-device-demo-consumption.v1",
        "purpose": "physical-ios-debug",
        "artifact_root": str(artifact),
        "artifact_source_commit": original,
        "current_source_commit": current,
        "allow_source_head_drift": allow_source_head_drift,
        "source_head_drifted": current != original,
        "native_bridge_abi_version": 31,
        "target_triple": "aarch64-apple-ios",
        "archive_sha256": archive_hash,
        "artifact_manifest_sha256": manifest_hash,
        "evidence": evidence,
    }


def retain_record(destination: Path, record: dict) -> None:
    """Create once outside producer custody; accept an identical retained record."""
    artifact_directory = Path(record["artifact_root"]).parent
    if (not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent
            or destination == artifact_directory or artifact_directory in destination.parents):
        raise ValueError("receipt must have a canonical existing parent outside the artifact directory")
    if destination.is_symlink():
        raise ValueError("receipt must not be a symbolic link")
    if destination.exists():
        if not destination.is_file() or json.loads(destination.read_bytes()) != record:
            raise ValueError("existing consumption receipt differs; select a fresh path")
        return
    payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def main() -> int:
    """Prepare only the explicitly selected existing physical consumer input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--allow-source-head-drift", action="store_true")
    args = parser.parse_args()
    try:
        record = prepare_record(args.artifact_dir, allow_source_head_drift=args.allow_source_head_drift)
        retain_record(args.receipt, record)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")
    print(json.dumps({"status": "prepared-for-manifest-validation", "receipt": str(args.receipt)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
