#!/usr/bin/env python3
"""Validate canonical publication destinations and retain structural artifact hashes.

Python3.12 standard library only. This helper does not build, sign, authenticate
an operator or qualify a release. Called publication first preserves the existing
source/native/NDK custody checks. Required SDK unit suites run before SBOM
signing and publication; lint remains a separate development diagnostic. Receipt outputs are exclusively created outside source; runtime Maven credentials are never arguments or receipt fields.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
import zipfile

SPEC = importlib.util.spec_from_file_location("artifact_owner", Path(__file__).resolve().with_name("mobile_sdk_android_artifacts.py"))
assert SPEC is not None and SPEC.loader is not None
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


def remote_url(value):
    if value == "":
        return
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or any(ord(character) <= 32 for character in value)
            or any(part in (".", "..") for part in parsed.path.split("/"))):
        raise ValueError("remote Maven URL must be explicit HTTPS without credentials, query or fragment")
    _ = parsed.port


def validate(args):
    root = OWNER.canonical_directory(str(args.root), "repository")
    artifacts = OWNER.canonical_directory(args.artifact_dir, "artifact directory")
    OWNER.build_root(root, args.artifact_dir)
    OWNER.sdk_version(args.version)
    remote_url(args.remote_url)
    outputs = (args.repo, args.report, args.sbom)
    for path in outputs:
        if (not path.is_absolute() or path.resolve() != path or path == artifacts
                or path == root or path.is_relative_to(root) or path.exists() or path.is_symlink()
                or any(character in str(path) for character in "\n\r\0")):
            raise ValueError("publication outputs must be new canonical external directories")
        OWNER.canonical_directory(str(path.parent), "publication output parent")
    for index, path in enumerate(outputs):
        if any(path == other or path in other.parents or other in path.parents for other in outputs[index + 1:]):
            raise ValueError("publication output generations must not overlap")


def receipt(args):
    if not re.fullmatch("[0-9a-f]{40}", args.source_commit or ""):
        raise ValueError("receipt requires the actual guarded source commit")
    remote_url(args.remote_url)
    OWNER.maven_artifacts(args.root, args.artifact_dir, args.repo, args.version)
    root = OWNER.build_root(args.root, args.artifact_dir)
    provenance = root / "client-android/generated/nativeProvenance/production/iroha/native-build-provenance-v1.json"
    OWNER.regular_file(provenance)
    if provenance.stat().st_size > 1024 * 1024:
        raise ValueError("native provenance exceeds1MiB")
    document = json.loads(provenance.read_bytes())
    if (document.get("schema") != "iroha.android-native-build-provenance.v1" or document.get("build_profile") != "release"
            or document.get("privacy_production_enabled") is not True or document.get("cargo_locked") is not True
            or document.get("source_tree_dirty") is not False or document.get("source_commit") != args.source_commit
            or document.get("artifact_scope") == "local-integration"):
        raise ValueError("publication requires production native provenance from its exact clean source")
    abis = ("arm64-v8a", "armeabi-v7a", "x86_64")
    if set(document.get("libraries", {})) != set(abis):
        raise ValueError("publication requires exact three-ABI native provenance")
    client = root / "client-android/outputs/aar/client-android-release.aar"
    with zipfile.ZipFile(client) as archive:
        names = archive.namelist()
        expected = {f"jni/{abi}/libconnect_norito_bridge.so" for abi in abis}
        if len(names) != len(set(names)) or {name for name in names if name.startswith("jni/") and name.endswith("/libconnect_norito_bridge.so")} != expected:
            raise ValueError("published client requires exact three-ABI originals")
        for abi in abis:
            generated = root / f"client-android/generated/jniLibs/production/{abi}/libconnect_norito_bridge.so"
            selected = document["libraries"][abi]
            entry = f"jni/{abi}/libconnect_norito_bridge.so"
            digest = OWNER.file_digest(generated)
            if (selected["aar_path"] != entry or selected["sha256"] != digest
                    or selected["bytes"] != generated.stat().st_size
                    or archive.getinfo(entry).file_size != selected["bytes"]):
                raise ValueError("published native member differs from generated provenance")
            actual = hashlib.sha256()
            with archive.open(entry) as member:
                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                    actual.update(chunk)
            if actual.hexdigest() != digest:
                raise ValueError("published native payload differs from its generated original")
        entry = "assets/iroha/native-build-provenance-v1.json"
        if archive.getinfo(entry).file_size > 1024 * 1024 or hashlib.sha256(archive.read(entry)).hexdigest() != OWNER.file_digest(provenance):
            raise ValueError("published client provenance differs from its generated original")
    paths = [(path, "maven") for path in sorted(args.repo.rglob("*")) if not path.is_dir()]
    for module in OWNER.SDK_MODULES:
        path = args.sbom / f"iroha-{module}.cyclonedx.json"
        OWNER.regular_file(path)
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("publication SBOM exceeds32MiB")
        bom = json.loads(path.read_bytes())
        component = bom.get("metadata", {}).get("component", {})
        if (bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list)
                or (component.get("group"), component.get("name"), component.get("version")) != ("org.hyperledger.iroha.sdk", module, args.version)):
            raise ValueError("publication SBOM must bind its exact module and version")
        paths.extend(((path, "sbom"), (path.with_suffix(path.suffix + ".sigstore"), "sbom-signature")))
    paths.append((provenance, "native-provenance"))
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        paths.append((root / f"client-android/generated/jniLibs/production/{abi}/libconnect_norito_bridge.so", "native"))
    records = [{"path": str(path), "sha256": OWNER.file_digest(path), "kind": kind} for path, kind in paths]
    OWNER.canonical_directory(str(args.report.parent), "publication receipt parent")
    if (not args.report.is_absolute() or args.report.resolve() != args.report
            or args.report == args.root or args.report.is_relative_to(args.root)):
        raise ValueError("receipt must be a new canonical external directory")
    payload = {"schema": "iroha.canonical-android-publication.v1", "version": args.version,
               "modules": list(OWNER.SDK_MODULES), "source_commit": args.source_commit,
               "release_qualification": False, "remote_repository": args.remote_url or None, "artifacts": records}
    args.report.mkdir(mode=0o700)
    with (args.report / "publish_summary.json").open("x") as output:
        json.dump(payload, output, indent=2); output.write("\n")
    with (args.report / "checksums.txt").open("x") as output:
        for record in records:
            output.write(f"{record['sha256']}  {record['path']}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "receipt"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--remote-url", default="")
    args = parser.parse_args()
    try:
        if sys.version_info[:2] != (3, 12) or not sys.flags.isolated or not sys.flags.no_site:
            raise ValueError("publication tooling requires isolated Python3.12")
        (validate if args.command == "validate" else receipt)(args)
        return 0
    except (OSError, ValueError, TypeError, AttributeError, KeyError, zipfile.BadZipFile) as error:
        print(f"[android-publication] ERROR: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
