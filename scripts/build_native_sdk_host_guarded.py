#!/usr/bin/env python3
"""Run a genuine guarded macOS host build for local SDK execution prerequisites.

This produces original Cargo/dep-info/static-capture/ABI observations only. It does
not qualify a release, an Apple cross target, a physical device, or native proofs.
The existing local-unit producer remains the independent admission/packaging owner.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import time

import native_sdk_source_custody as custody
import norito_bridge_local_unit as unit


def file_identity(path: Path):
    """Track replacement and edits/restoration in addition to the original byte hash."""
    value = unit.regular(path)
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def source_identities(root: Path, sources: dict):
    """Resolve only the original source-custody key syntax, never an emitted source guess."""
    return {key: file_identity(Path(key.split(":", 1)[1])
                              if key.startswith(("registry:", "git:")) else root / key)
            for key in sources}


def changes(before: dict, after: dict):
    """Return all membership or value changes deterministically."""
    return sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))


def source_guard(metadata, root, originals, original_ids, before, before_ids, after, after_ids, receipts):
    """Keep literal broad observations while guarding every verified consumed input.

    Complete Cargo dep-info must have been verified before this is called. The
    original pre-build capture remains authoritative through retention and probe;
    an unchanged hash never excuses replacement of a selected source file.
    """
    selected = custody.consumed_source_projection(metadata, root, originals, after, receipts)
    unit.require(custody.consumed_source_projection(metadata, root, originals, before, receipts) == selected,
                 "consumed source membership changed")
    expected_ids = {name: original_ids[name] for name in selected}
    first_ids = {name: before_ids[name] for name in selected}
    last_ids = {name: after_ids[name] for name in selected}
    unit.require(first_ids == last_ids == expected_ids, "consumed source identity changed")
    identity_changes = changes(before_ids, after_ids)
    return {"source_scope": unit.SOURCE_SCOPE, "source_before": before, "source_after": after,
            "source_identity_changes": identity_changes,
            "source_changes": sorted(set(changes(before, after)) | set(identity_changes)),
            "consumed_source": selected, "consumed_identities_before": first_ids,
            "consumed_identities_after": last_ids}


def tool_identities(tools: dict):
    """Bind both tool aliases and retained executable identities across the whole run."""
    return {name: [str(Path(name).resolve(strict=True)), *file_identity(Path(name).resolve(strict=True))]
            for name in tools}


def run_text(command, *, root: Path, environment=None):
    """Wait for a natural exit; this owner never kills a Cargo/rustc process."""
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True,
                            check=False)
    unit.require(result.returncode == 0, "command failed: " + repr(command) + "\n" + result.stderr)
    return result.stdout.strip()


def collect_tools(root: Path):
    """Pin actual compiler, native toolchain, collector and current admission policy bytes."""
    rustup = shutil.which("rustup")
    unit.require(rustup is not None, "rustup executable unavailable")
    cargo = Path(run_text([rustup, "which", "cargo"], root=root))
    rustc = Path(run_text([rustup, "which", "rustc"], root=root))
    paths = [cargo, rustc, Path(rustup), Path(sys.executable), Path(__file__).resolve()]
    for name in ["clang", "clang++", "ar", "ranlib", "ld", "nm"]:
        paths.append(Path(run_text(["/usr/bin/xcrun", "--find", name], root=root)))
    for name in ["cc", "c++", "clang", "clang++", "ar", "ranlib", "ld", "nm"]:
        selected = shutil.which(name)
        unit.require(selected is not None, "native tool executable unavailable: " + name)
        paths.append(Path(selected))
    fallback_nm = shutil.which("llvm-nm")
    if fallback_nm is not None:
        paths.append(Path(fallback_nm))
    paths += [Path("/usr/bin/xcrun"), root / "scripts/native_sdk_source_custody.py",
              root / "scripts/norito_bridge_local_unit.py", root / "scripts/check_native_sdk_artifact.py",
              root / "scripts/validate_norito_bridge_xcframework.py"]
    return cargo, rustc, {str(path): unit.tool_digest(path) for path in paths}


def build_environment(rustc: Path, target: Path, jobs: int | None, temporary: Path):
    """Use the repository's captured Cargo configuration without inherited build overrides."""
    forbidden = [key for key in os.environ if key.startswith(("CARGO_ENCODED_", "CARGO_PROFILE_",
                  "CARGO_TARGET_", "RUSTFLAGS", "RUSTDOCFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                  "CC_", "CXX_", "AR_", "RANLIB_", "HOST_CC", "HOST_CXX", "TARGET_CC", "TARGET_CXX"))
                 or key in {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS",
                            "CARGO_BUILD_TARGET", "CARGO_BUILD_JOBS", "CC", "CXX", "AR", "RANLIB", "LD"}]
    unit.require(not forbidden, "unreviewed inherited compiler overrides: " + ", ".join(sorted(forbidden)))
    custody.original_directory(temporary)
    metadata = temporary.stat()
    unit.require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
                 "compiler scratch must be owned canonical mode0700")
    environment = os.environ.copy()
    environment.update(RUSTC=str(rustc), CARGO_TARGET_DIR=str(target), TMPDIR=str(temporary))
    if jobs is not None:
        environment["CARGO_BUILD_JOBS"] = str(jobs)
    return environment


@contextmanager
def warm_target_custody(target: Path):
    """Retain a warm lane under a nonblocking exclusive emitter lock.

    Existing Cargo outputs are preserved. The lock is additional coordination;
    current Cargo messages, full dep-info and source/tool/archive guards remain
    mandatory, including when Cargo truthfully reports a cached artifact.
    """
    custody.original_directory(target.parent)
    if not os.path.lexists(target):
        target.mkdir(mode=0o700)
    custody.original_directory(target)
    lock = target / ".guarded-host-sdk.lock"
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        raise unit.Refused("cannot open original warm-lane lock: " + str(error)) from error
    acquired = False
    try:
        held = os.fstat(fd)
        unit.require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                     and held.st_uid == os.getuid(), "warm-lane lock must be an app-owned original file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise unit.Refused("warm build lane is already in use") from error
        acquired = True
        identity = file_identity(lock)
        unit.require(identity[:2] == [held.st_dev, held.st_ino], "warm-lane lock changed before admission")
        def assert_custody():
            unit.require(file_identity(lock) == identity, "warm-lane lock changed during the build")
        yield assert_custody
        assert_custody()
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def host_build(root: Path, output: Path, target: Path, jobs: int | None):
    """Capture prospective originals, build naturally, reconcile, retain and probe actual output."""
    unit.require(sys.platform == "darwin" and platform.machine() in unit.TARGETS,
                 "guarded host emitter requires a supported macOS host")
    custody.original_directory(root)
    unit.artifact_root(root, output)
    unit.require(target.is_absolute() and target.resolve() == target
                 and target.is_relative_to(root / "target"), "target must be a canonical worktree target directory")
    unit.require(not output.is_relative_to(target) and not target.is_relative_to(output),
                 "retained artifacts and the warm Cargo lane must be disjoint")
    with warm_target_custody(target) as assert_custody:
        pins = _host_build_locked(root, output, target, jobs, assert_custody)
    # Context exit must pass before publishing or announcing admissible receipt pins.
    unit.save(output / "pins.json", pins)
    print(str(output / "pins.json"))


def admit_under_custody(root: Path, pins: dict, assert_custody):
    """Recheck the original lock around independent admission; publish nothing here."""
    assert_custody()
    unit.admit(root, pins)
    assert_custody()
    return pins


def _host_build_locked(root: Path, output: Path, target: Path, jobs: int | None, assert_custody):
    """Emit and admit only actual outputs while holding the stable target lane."""
    output.mkdir(mode=0o700)
    temporary = output / "temporary"
    temporary.mkdir(mode=0o700)
    cargo, rustc, tools_before = collect_tools(root)
    compiler_version = run_text([str(rustc), "-vV"], root=root)
    unit.require("host: " + unit.TARGETS[platform.machine()] in compiler_version.splitlines(),
                 "selected compiler is not the native host toolchain")
    tool_ids_before = tool_identities(tools_before)
    environment = build_environment(rustc, target, jobs, temporary)
    metadata_raw = run_text([str(cargo), "metadata", "--locked", "--format-version=1",
                             "--features", "connect_norito_bridge/privacy-production-enabled"],
                            root=root, environment=environment)
    metadata = json.loads(metadata_raw, object_pairs_hook=unit.duplicates)
    unit.save(output / "metadata.json", metadata)
    before = custody.capture(metadata, root, unit.digest)
    identities_before = source_identities(root, before)
    unit.save(output / "source-before.json", before)
    unit.save(output / "source-identities-before.json", identities_before)
    unit.save(output / "tool-identities-before.json", tool_ids_before)
    command = [str(cargo), "build", "--locked", "--no-default-features", "--features",
               "privacy-production-enabled", "-p", "connect_norito_bridge", "--lib",
               "--message-format=json-render-diagnostics"]
    with (output / "artifacts.jsonl").open("x") as stdout, (output / "cargo.stderr.log").open("x") as stderr:
        result = subprocess.run(command, cwd=root, env=environment, stdout=stdout, stderr=stderr, check=False)
    record = {"scope": "host-local-component-observations", "command": command, "compiler_version": compiler_version,
              "compiler_temporary_directory": str(temporary),
              "natural_exit": result.returncode, "capture_errors": [], "source_changes": [],
              "dep_info_errors": [], "collector_toolchain_changes": [], "dep_info": [], "emitted": [],
              "source_before": before, "collector_toolchain_before": tools_before,
              "metadata_sha256": unit.digest(output / "metadata.json"),
              "artifacts_sha256": unit.digest(output / "artifacts.jsonl")}
    try:
        after = custody.capture(metadata, root, unit.digest)
        identities_after = source_identities(root, after)
        record["source_after"] = after
        record["source_identity_changes"] = changes(identities_before, identities_after)
        record["source_changes"] = sorted(set(changes(before, after)) | set(record["source_identity_changes"]))
        _, _, tools_after = collect_tools(root)
        record["collector_toolchain_after"] = tools_after
        record["collector_toolchain_changes"] = sorted(set(changes(tools_before, tools_after))
             | set(changes(tool_ids_before, tool_identities(tools_after))))
        unit.require(result.returncode == 0, "Cargo failed naturally")
        unit.require(not record["collector_toolchain_changes"], "prospective tool guard changed")
        messages = custody.cargo_messages((output / "artifacts.jsonl").read_text(), unit.duplicates)
        retained = output / "dep-info"
        retained.mkdir(mode=0o700)
        try:
            record["dep_info"] = [custody.reconcile(message, root, before, retained, unit.digest, target)
                                  for message in messages if message.get("reason") == "compiler-artifact"]
            custody.verify_dep_info(messages, record["dep_info"], root, before, target, retained, unit.digest)
        except Exception as error:
            record["dep_info_errors"].append(str(error))
            raise
        record.update(source_guard(metadata, root, before, identities_before, before, identities_before,
                                   after, identities_after, record["dep_info"]))
        actual = [message for message in messages if message.get("reason") == "compiler-artifact"
                  and message.get("target", {}).get("name") == "connect_norito_bridge"]
        unit.require(len(actual) == 1, "Cargo did not emit one exact bridge artifact")
        actual = actual[0]
        unit.require(actual.get("features") == ["privacy-production-enabled"] and actual.get("profile", {}).get("test") is False,
                     "Cargo feature/profile differs from the host ABI contract")
        dylib = [Path(path) for path in actual["filenames"] if path.endswith("/libconnect_norito_bridge.dylib")]
        archives = [Path(path) for path in actual["filenames"] if path.endswith("/libconnect_norito_bridge.a")]
        unit.require(len(dylib) == len(archives) == 1, "Cargo artifact lacks its exact dylib/archive pair")
        snapshot = output / dylib[0].name
        archive_snapshot = output / archives[0].name
        static_before = custody.capture(metadata, root, unit.digest)
        static_ids_before = source_identities(root, static_before)
        source_guard(metadata, root, before, identities_before, static_before, static_ids_before,
                     static_before, static_ids_before, record["dep_info"])
        archive_identity = unit.regular(archives[0], single_link=True)
        unit.clone(dylib[0], snapshot)
        unit.clone(archives[0], archive_snapshot)
        static_after = custody.capture(metadata, root, unit.digest)
        static_ids_after = source_identities(root, static_after)
        static_guard = source_guard(metadata, root, before, identities_before, static_before, static_ids_before,
                                    static_after, static_ids_after, record["dep_info"])
        unit.require(file_identity(archives[0]) == [archive_identity.st_dev, archive_identity.st_ino,
                     archive_identity.st_size, archive_identity.st_mtime_ns, archive_identity.st_ctime_ns],
                     "original archive identity changed during retention")
        record["emitted"] = [{"cargo_artifact": actual, "snapshot": str(snapshot), "sha256": unit.digest(snapshot)}]
    except Exception as error:
        record["capture_errors"].append(str(error))
    record["finished_unix"] = time.time()
    emitter = output / "emitter.json"
    unit.save(emitter, record)
    unit.require(not record["capture_errors"], "guarded build refused; original observations retained at " + str(emitter))
    emitter_sha = unit.digest(emitter)
    original = archive_identity
    capture = {"emitter": str(emitter), "emitter_sha256": emitter_sha,
               "actual_cargo_artifact": actual, "target_triple": unit.TARGETS[platform.machine()],
               "archive_original": str(archives[0]), "archive_snapshot": str(archive_snapshot),
               "archive_original_device": original.st_dev, "archive_original_inode": original.st_ino,
               "archive_bytes": archive_snapshot.stat().st_size, "archive_sha256": unit.digest(archive_snapshot),
               "snapshot_method": "clonefile-cow", **static_guard, "collector_tools": tools_before,
               "native_companion_sha256": unit.digest(snapshot), "finished_unix": time.time()}
    native = unit.module(root / "scripts/check_native_sdk_artifact.py", "guarded_host_native_policy")
    policy = unit.native_policy(root)
    exports = native.inspect_exported_symbols(snapshot, required=True)
    native.validate_retired_protocol_symbols(exports, sdk="c-jni")
    native.validate_privacy_c_exports(exports, require_exact=True)
    unit.require(set(policy["required"]) <= set(exports), "current required native exports are missing")
    abi = native.probe_c_abi(snapshot, policy["required"], forbidden_symbols=policy["forbidden"])
    unit.require(abi == 29, "actual native library is not ABI29")
    inventory = output / "exports.json"
    unit.save(inventory, sorted(set(exports)))
    component = {"emitter_path": str(emitter), "emitter_sha256": emitter_sha, "qualified": True,
                 "scope": "host-ABI29-and-symbols-only", "observed_abi_version": abi,
                 "artifact_path": str(snapshot), "artifact_sha256": unit.digest(snapshot),
                 "source_before": static_after, "source_after": custody.capture(metadata, root, unit.digest),
                 "toolchain_before": tools_before, "toolchain_after": collect_tools(root)[2],
                 "finished_unix": time.time(), "export_count": len(set(exports)),
                 "required_c_jni_symbols": policy["c_jni"], "privacy_c_exports": policy["privacy"],
                 "export_inventory_path": str(inventory), "export_inventory_sha256": unit.digest(inventory)}
    component.update(source_guard(metadata, root, before, identities_before, static_after, static_ids_after,
                                  component["source_after"], source_identities(root, component["source_after"]),
                                  record["dep_info"]))
    unit.require(not changes(tool_ids_before, tool_identities(component["toolchain_after"])), "tools changed during retention/probe")
    assert_custody()
    unit.check_record_semantics(record, capture, component, emitter, emitter_sha, unit.TARGETS[platform.machine()])
    unit.save(output / "static-capture.json", capture)
    unit.save(output / "component.json", component)
    pins = {role: {"path": str(path), "sha256": unit.digest(path)} for role, path in {
        "emitter": emitter, "static_capture": output / "static-capture.json", "component": output / "component.json"}.items()}
    return admit_under_custody(root, pins, assert_custody)


def main():
    """CLI: all destinations are explicit and observations are create-only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path,
                        help="stable warm worktree lane; existing Cargo outputs are retained")
    parser.add_argument("--jobs", type=int,
                        help="explicit operator override; defaults to Cargo's native jobserver")
    args = parser.parse_args()
    unit.require(args.jobs is None or 1 <= args.jobs <= 8, "jobs must be between one and eight")
    host_build(args.root, args.output, args.target_dir, args.jobs)


if __name__ == "__main__":
    main()
