#!/usr/bin/env python3
"""Snapshot and copy the exact validated Android SDK package inputs.

Python3.12 stdlib only. Capture occurs before graph/native validation; verification
immediately afterward rejects validation-time drift. Copy uses original regular
file identities and hashes; ZIP verification compares actual archived payloads
against the same snapshot. No build, qualification, signing or authority grant.
Snapshot/stage directories must already be private, owned, canonical directories.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

OWNER_PATH = Path(__file__).resolve().with_name("mobile_sdk_android_artifacts.py")
SPEC = importlib.util.spec_from_file_location("android_artifacts", OWNER_PATH)
assert SPEC is not None and SPEC.loader is not None
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)
SCHEMA = "iroha.android-package-input-snapshot.v1"


def private_directory(path: Path) -> Path:
    path = OWNER.canonical_directory(str(path), "private package directory")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("package snapshot/stage directory must be owned and mode0700")
    return path


def identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, info.st_mode, info.st_uid, info.st_gid]


def original(path: Path, expected=None, destination: Path | None = None):
    OWNER.regular_file(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size == 0 or expected is not None and identity(before) != expected["identity"]):
            raise ValueError("package source identity differs from the validated snapshot")
        output = None
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.parent.resolve(strict=True) != destination.parent:
                raise ValueError("package destination must not traverse symbolic links")
            output = os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
        digest = hashlib.sha256()
        try:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output is not None:
                output.close()
        after = os.fstat(source.fileno())
    value = digest.hexdigest()
    if identity(before) != identity(after) or identity(after) != identity(path.lstat()) or path.resolve(strict=True) != path:
        raise ValueError("package source changed during its original read")
    if expected is not None and value != expected["sha256"]:
        raise ValueError("package source bytes differ from the validated snapshot")
    return {"source": str(path), "identity": identity(after), "sha256": value}


def inputs(root: Path, artifacts: str, maven: Path, version: str, mode: str):
    build = OWNER.build_root(root, artifacts)
    runtime = OWNER.built_artifacts(root, artifacts, version=version)
    OWNER.maven_artifacts(root, artifacts, maven, version)
    mapping = {}
    for module, path in zip(OWNER.SDK_MODULES, runtime, strict=True):
        mapping[path] = f"{module}/{path.name}"
        mapping[build / module / "publications/release/pom-default.xml"] = None
    for path in sorted(maven.rglob("*")):
        if not path.is_dir():
            mapping[path] = "maven/" + path.relative_to(maven).as_posix()
    client = build / "client-android"
    verify_native_originals(runtime[1], client, mode)
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        mapping[client / f"generated/jniLibs/{mode}/{abi}/libconnect_norito_bridge.so"] = f"native/{abi}/libconnect_norito_bridge.so"
    mapping[client / f"generated/nativeProvenance/{mode}/iroha/native-build-provenance-v1.json"] = "native/native-build-provenance-v1.json"
    return mapping


def verify_native_originals(runtime: Path, client: Path, mode: str):
    provenance = client / f"generated/nativeProvenance/{mode}/iroha/native-build-provenance-v1.json"
    with os.fdopen(os.open(runtime, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = identity(os.fstat(source.fileno()))
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("client AAR contains duplicate original entries")
            entry = "assets/iroha/native-build-provenance-v1.json"
            if archive.getinfo(entry).file_size > 1024 * 1024:
                raise ValueError("embedded native provenance exceeds1MiB")
            if hashlib.sha256(archive.read(entry)).hexdigest() != OWNER.file_digest(provenance):
                raise ValueError("embedded native provenance differs from its generated original")
            expected = {f"jni/{abi}/libconnect_norito_bridge.so" for abi in ("arm64-v8a", "armeabi-v7a", "x86_64")}
            actual = {name for name in names if name.startswith("jni/") and name.endswith("/libconnect_norito_bridge.so")}
            if actual != expected:
                raise ValueError("client AAR requires exact three-ABI native originals")
            document = json.loads(provenance.read_bytes())
            if set(document.get("libraries", {})) != {"arm64-v8a", "armeabi-v7a", "x86_64"}:
                raise ValueError("native provenance requires exact three-ABI originals")
            for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
                generated = client / f"generated/jniLibs/{mode}/{abi}/libconnect_norito_bridge.so"
                entry = f"jni/{abi}/libconnect_norito_bridge.so"
                if archive.getinfo(entry).file_size != generated.stat().st_size:
                    raise ValueError("client AAR native payload size differs from its generated original")
                digest = hashlib.sha256()
                with archive.open(entry) as member:
                    for chunk in iter(lambda: member.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != OWNER.file_digest(generated):
                    raise ValueError("client AAR native payload differs from its generated original")
        if before != identity(os.fstat(source.fileno())) or before != identity(runtime.lstat()):
            raise ValueError("client AAR changed during native original correlation")


def capture(args):
    private_directory(args.snapshot.parent)
    mapping = inputs(args.root, args.artifact_dir, args.maven_repo, args.version, args.native_mode)
    records = []
    for path, destination in sorted(mapping.items()):
        records.append({**original(path), "destination": destination})
    document = {"schema": SCHEMA, "root": str(args.root), "artifact_dir": args.artifact_dir,
                "maven_repo": str(args.maven_repo), "version": args.version,
                "native_mode": args.native_mode, "records": records}
    # Confirm the admitted graph and every exact source remained unchanged across
    # capture; actual native validation follows under this retained baseline.
    verify_sources(document)
    content = (json.dumps(document, indent=2) + "\n").encode()
    with os.fdopen(os.open(args.snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(content); output.flush(); os.fsync(output.fileno())
    print(hashlib.sha256(content).hexdigest())


def load_snapshot(args):
    private_directory(args.snapshot.parent)
    if args.snapshot.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("package input snapshot exceeds2MiB")
    original(args.snapshot)
    content = args.snapshot.read_bytes()
    if hashlib.sha256(content).hexdigest() != args.snapshot_sha256:
        raise ValueError("package input snapshot differs from its captured digest")
    document = json.loads(content)
    if document.get("schema") != SCHEMA or not isinstance(document.get("records"), list):
        raise ValueError("invalid package input snapshot")
    for record in document["records"]:
        destination = record.get("destination")
        if destination is not None:
            path = Path(destination)
            if path.is_absolute() or str(path) != destination or any(part in (".", "..") for part in path.parts):
                raise ValueError("package snapshot destination must be canonical and relative")
    return document


def verify_sources(document):
    mapping = inputs(Path(document["root"]), document["artifact_dir"], Path(document["maven_repo"]),
                     document["version"], document["native_mode"])
    expected = {record["source"]: record["destination"] for record in document["records"]}
    if expected != {str(path): destination for path, destination in mapping.items()} or len(expected) != len(document["records"]):
        raise ValueError("package source inventory changed after validation")
    for record in document["records"]:
        original(Path(record["source"]), record)


def copy(args, document):
    stage = private_directory(args.stage)
    verify_sources(document)
    records = sorted((record for record in document["records"] if record["destination"] is not None), key=lambda record: record["destination"])
    for record in records:
        original(Path(record["source"]), record, stage / record["destination"])
        print(f"{record['sha256']}  {record['destination']}")
    verify_sources(document)


def verify_stage(stage: Path, document):
    stage = private_directory(stage)
    records = {record["destination"]: record for record in document["records"] if record["destination"] is not None}
    actual = {path.relative_to(stage).as_posix() for path in stage.rglob("*") if not path.is_dir()}
    if actual != set(records) | {"SHA256SUMS.txt"}:
        raise ValueError("copied Android package inventory differs from its snapshot")
    for destination, record in records.items():
        if OWNER.file_digest(stage / destination) != record["sha256"] or (stage / destination).stat().st_size != record["identity"][2]:
            raise ValueError("copied Android payload differs from its original snapshot")
    checksums = "".join(f"{record['sha256']}  {destination}\n" for destination, record in sorted(records.items()))
    checksum_path = stage / "SHA256SUMS.txt"
    original(checksum_path)
    if checksum_path.read_text() != checksums:
        raise ValueError("Android package checksums differ from the original snapshot")
    return records, checksums.encode()


def verify_archive(archive: Path, prefix: str, records, checksums):
    OWNER.regular_file(archive)
    payloads = {f"{prefix}/{destination}": (record["identity"][2], record["sha256"])
                for destination, record in records.items()}
    payloads[f"{prefix}/SHA256SUMS.txt"] = (len(checksums), hashlib.sha256(checksums).hexdigest())
    directories = {prefix + "/"}
    for name in payloads:
        parts = Path(name).parts[:-1]
        directories.update("/".join(parts[:index]) + "/" for index in range(1, len(parts) + 1))
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = identity(os.fstat(source.fileno()))
        with zipfile.ZipFile(source) as bundle:
            names = bundle.namelist()
            if len(names) != len(set(names)) or set(names) - directories != set(payloads):
                raise ValueError("Android ZIP inventory differs from the copied original snapshot")
            for name, (size, expected_digest) in payloads.items():
                if bundle.getinfo(name).file_size != size:
                    raise ValueError("Android ZIP payload size differs from original snapshot")
                digest = hashlib.sha256()
                with bundle.open(name) as member:
                    for chunk in iter(lambda: member.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != expected_digest:
                    raise ValueError("Android ZIP payload differs from original snapshot")
        if before != identity(os.fstat(source.fileno())) or before != identity(archive.lstat()):
            raise ValueError("Android ZIP changed during verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture", "copy", "verify"))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--snapshot-sha256")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--artifact-dir")
    parser.add_argument("--maven-repo", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--native-mode", choices=("production",))
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "capture":
            if any(value is None for value in (args.root, args.artifact_dir, args.maven_repo, args.version, args.native_mode)):
                raise ValueError("capture requires the explicit canonical source graph")
            capture(args)
        else:
            if args.snapshot_sha256 is None:
                raise ValueError("the captured snapshot digest is required")
            document = load_snapshot(args)
            if args.command == "copy":
                if args.stage is None:
                    raise ValueError("copy requires the private stage")
                copy(args, document)
            else:
                verify_sources(document)
                if args.stage is not None:
                    records, checksums = verify_stage(args.stage, document)
                    if args.archive is not None:
                        verify_archive(args.archive, args.stage.name, records, checksums)
                elif args.archive is not None:
                    raise ValueError("archive verification requires its private copied stage")
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, zipfile.BadZipFile) as error:
        print(f"[android-package-inputs] ERROR: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
