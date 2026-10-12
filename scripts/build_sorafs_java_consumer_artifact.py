#!/usr/bin/env python3
"""Execute SoraFS Java consumers against actual Kotlin packages and retain evidence.

The resulting unsigned host-consumer artifact is not a six-SDK release approval.
No caller-supplied qualification flag or existing JUnit report is an input.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import zipfile

import check_native_sdk_artifact as native
from jvm_classfile import MAX_CLASS_BYTES, parse_class
from sorafs_evidence_json import decode_evidence_json, read_evidence_bytes
from sorafs_java_consumer_artifact import (
    ArtifactError, CORE_OWNERS, GROUPS, MAX_ARCHIVE_BYTES, MAX_LOG_BYTES, MAX_REPORT_BYTES,
    SCHEMA, SDK_PREFIX, SUITE, archive_members, canonical_json, deterministic_archive,
    identity, package_classes, read_file, validate_class_origins,
    dependency_classes, dependency_classpath, validate_dependency_origins,
    validate_library_origin, validate_report, validate_test_classes,
)

SOURCE = "kotlin/core-jvm/src/sorafsJavaTest/java/org/hyperledger/iroha/sdk/sorafs/SorafsReferenceValidatorsJavaConsumerTest.java"
RUNNER = "scripts/fixtures/SorafsJavaConsumerQualificationRunner.java"
PROBE = "scripts/fixtures/SorafsAndroidPackageLinkProbe.java"
DEPENDENCIES = frozenset({
    "org.jetbrains.kotlin:kotlin-stdlib", "org.jetbrains:annotations",
    "org.junit.jupiter:junit-jupiter-api", "org.junit.jupiter:junit-jupiter-engine",
    "org.junit.platform:junit-platform-commons", "org.junit.platform:junit-platform-engine",
    "org.junit.platform:junit-platform-launcher", "org.apiguardian:apiguardian-api",
    "org.opentest4j:opentest4j",
})
COMMAND_TIMEOUT_SECONDS = 1200
MAX_FIXTURE_BYTES = 64 * 1024 * 1024
REPORT_PREFIX = b"SORAFS_JAVA_REPORT_V1="


def write_fresh(path: Path, raw: bytes) -> None:
    """Write one private retained file, never replacing an existing output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        position = 0
        while position < len(raw):
            count = os.write(fd, raw[position:])
            if count <= 0:
                raise ArtifactError("artifact output made no write progress")
            position += count
        os.fsync(fd)
    finally:
        os.close(fd)


def capture_tree(root: Path, maximum: int) -> dict[str, bytes]:
    """Capture a bounded exact ordinary-file tree, excluding links and aliases."""
    if root.resolve(strict=True) != root or root.is_symlink() or not root.is_dir():
        raise ArtifactError("input tree must be an absolute canonical directory")
    result = {}
    total = 0
    count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if count > 4096 or entry.is_symlink() or len(relative.encode("utf-8")) > 1024:
                    raise ArtifactError("input tree has excessive entries or a symbolic link")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                remaining = maximum - total
                raw = read_evidence_bytes(path, max(remaining, 1))
                if len(raw) > remaining:
                    raise ArtifactError("input tree exceeds its total byte limit")
                total += len(raw)
                result[relative] = raw
    if not result:
        raise ArtifactError("input tree is empty")
    return dict(sorted(result.items()))


def load_dependencies(raw: bytes, expected_sha256: str) -> dict[str, tuple[Path, bytes]]:
    """Consume an independently pinned exact JUnit/Kotlin tool dependency list."""
    if not isinstance(raw, bytes) or len(raw) > 64 * 1024:
        raise ArtifactError("tool dependency manifest byte limit exceeded")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ArtifactError("tool dependency manifest differs from its independent pin")
    value = decode_evidence_json(raw)
    if not isinstance(value, dict) or set(value) != {"schema", "jars"} or value["schema"] != "sorafs.java_consumer.dependencies.v1" or not isinstance(value["jars"], list):
        raise ArtifactError("tool dependency manifest schema differs")
    result = {}
    class_names = set()
    for row in value["jars"]:
        if not isinstance(row, dict) or set(row) != {"module", "version", "path", "sha256", "size"}:
            raise ArtifactError("tool dependency row is not closed")
        name = row["module"]
        if not isinstance(name, str) or name not in DEPENDENCIES or name in result or not isinstance(row["version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", row["version"]):
            raise ArtifactError("tool dependency identity is unknown or repeated")
        if not isinstance(row["path"], str):
            raise ArtifactError("tool dependency path is not text")
        source = Path(row["path"])
        body = read_file(source, 64 * 1024 * 1024)
        if identity(body) != {"sha256": row["sha256"], "size": row["size"]} or type(row["size"]) is not int:
            raise ArtifactError("tool dependency bytes differ")
        classes = dependency_classes(body)
        if class_names.intersection(classes):
            raise ArtifactError("tool dependencies shadow effective runtime class ownership")
        class_names.update(classes)
        result[name] = (source, body)
    if set(result) != DEPENDENCIES:
        raise ArtifactError("tool dependency inventory is incomplete")
    return result


def parse_native_manifest(raw: bytes) -> dict[str, object]:
    """Validate the original captured bytes with the native owner's exact codec."""
    if not raw or len(raw) > native.MAX_MANIFEST_BYTES:
        raise ArtifactError("native manifest byte limit exceeded")
    value = native.validate_manifest(decode_evidence_json(raw))
    if native.canonical_manifest_bytes(value) != raw:
        raise ArtifactError("native artifact manifest JSON is not canonical")
    return value


def consume_runtime_output(raw: bytes, *, report_required: bool) -> tuple[bytes, bytes, bytes | None]:
    """Extract complete logs/report from the one bounded stdout observation."""
    if not raw or len(raw) > MAX_LOG_BYTES or not raw.endswith(b"\n"):
        raise ArtifactError("consumer output is empty, excessive or incomplete")
    classes, libraries, reports = [], [], []
    for line in raw.splitlines(keepends=True):
        if REPORT_PREFIX in line:
            if not line.startswith(REPORT_PREFIX) or not line.endswith(b"\n"):
                raise ArtifactError("consumer report frame is malformed")
            reports.append(line[len(REPORT_PREFIX):].rstrip(b"\r\n"))
        elif b"[class,load]" in line:
            classes.append(line)
        elif re.search(rb"\[library *\]", line):
            libraries.append(line)
    if len(reports) != (1 if report_required else 0):
        raise ArtifactError("consumer output lost or repeated its exact report frame")
    report = None
    if reports:
        encoded = reports[0]
        if not encoded or len(encoded) > ((MAX_REPORT_BYTES + 2) // 3) * 4:
            raise ArtifactError("consumer report frame exceeds its byte limit")
        try:
            report = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ArtifactError("consumer report frame is invalid Base64") from error
        if not report or len(report) > MAX_REPORT_BYTES or base64.b64encode(report) != encoded:
            raise ArtifactError("consumer report frame is noncanonical or excessive")
    if not classes or (report_required and not libraries):
        raise ArtifactError("consumer output lacks complete class/native log streams")
    return b"".join(classes), b"".join(libraries), report


def run_command(command: list[str], cwd: Path, log: Path, *, timeout: float = COMMAND_TIMEOUT_SECONDS) -> None:
    """Run only an owned child with bounded retained output and a fixed deadline."""
    # Clear inherited JVM agents, classpaths, launcher options and library paths.
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    if sys.platform == "win32" and "SystemRoot" in os.environ:
        environment["SystemRoot"] = os.environ["SystemRoot"]
    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=4)
    stopped = threading.Event()
    process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert process.stdout is not None

    def receive() -> None:
        try:
            while not stopped.is_set():
                raw = process.stdout.read(64 * 1024)
                while not stopped.is_set():
                    try:
                        chunks.put(raw if raw else None, timeout=0.1)
                        break
                    except queue.Full:
                        pass
                if not raw:
                    break
        finally:
            process.stdout.close()

    reader = threading.Thread(target=receive, daemon=True)
    reader.start()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactError("owned consumer command exceeded its deadline")
            try:
                chunk = chunks.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if chunk is None:
                break
            if len(output) + len(chunk) > MAX_LOG_BYTES:
                raise ArtifactError("owned consumer command exceeded its output limit")
            output.extend(chunk)
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ArtifactError("owned consumer command failed; retained log identifies the failure")
    finally:
        stopped.set()
        if process.poll() is None:
            process.kill()  # Only this function's own bounded Java/javac child.
        process.wait()
        reader.join(timeout=5)
        write_fresh(log, bytes(output))


def produce(args: argparse.Namespace) -> dict[str, object]:
    """Compile, execute and package observations from the original captured inputs."""
    root = args.source_root
    work = args.work_dir
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ArtifactError("source root must be an absolute canonical directory")
    if not work.is_absolute() or work.parent.resolve(strict=True) != work.parent or os.path.lexists(work):
        raise ArtifactError("qualification work directory must be fresh under a canonical parent")
    if root == work or (root in work.parents and work.relative_to(root).parts[0] != "target"):
        raise ArtifactError("qualification outputs within the source tree must be under target/")
    work.mkdir(mode=0o700)
    captures: dict[Path, bytes] = {}
    private_inputs: dict[str, bytes] = {}
    retained = {}

    def capture(path: Path, relative: str, bound: int) -> bytes:
        raw = read_file(path, bound)
        captures[path] = raw
        private_inputs[relative] = raw
        write_fresh(work / relative, raw)
        return raw

    # Retain the actual loaded Python producer/helper source alongside runner
    # sources. Their byte identities are observations, not an audit sign-off.
    script_directory = Path(__file__).resolve(strict=True).parent
    tool_sources = {}
    for name in ("build_sorafs_java_consumer_artifact.py", "sorafs_java_consumer_artifact.py", "jvm_classfile.py", "sorafs_evidence_json.py", "check_native_sdk_artifact.py", "compute_workspace_source_manifest.py"):
        if name != "build_sorafs_java_consumer_artifact.py" and name != "compute_workspace_source_manifest.py":
            module = sys.modules[name.removesuffix(".py")]
            if Path(module.__file__).resolve(strict=True) != script_directory / name:
                raise ArtifactError("producer helper was imported from a different tool directory")
        tool_sources[name] = identity(capture(script_directory / name, "inputs/tools/" + name, 1024 * 1024))
    core = capture(args.core_jar, "packages/core.jar", MAX_ARCHIVE_BYTES)
    aar = capture(args.client_aar, "packages/client.aar", MAX_ARCHIVE_BYTES)
    core_classes, android_classes, android_jar = package_classes(core, aar)
    write_fresh(work / "packages/android-classes.jar", android_jar)
    private_inputs["packages/android-classes.jar"] = android_jar
    dependency_manifest = capture(args.dependency_manifest, "inputs/dependencies.json", 64 * 1024)
    dependencies = load_dependencies(dependency_manifest, args.dependency_manifest_sha256)
    dependency_paths = []
    for index, (name, (path, raw)) in enumerate(sorted(dependencies.items())):
        relative = f"dependencies/{index}.jar"
        captures[path] = raw
        private_inputs[relative] = raw
        write_fresh(work / relative, raw)
        dependency_paths.append(work / relative)
    dependency_jars = dependency_classpath({name: raw for name, (_path, raw) in dependencies.items()}, work)
    source = capture(root / SOURCE, "sources/SorafsReferenceValidatorsJavaConsumerTest.java", 256 * 1024)
    capture(root / RUNNER, "sources/SorafsJavaConsumerQualificationRunner.java", 64 * 1024)
    capture(root / PROBE, "sources/SorafsAndroidPackageLinkProbe.java", 64 * 1024)
    if tuple(re.findall(rb"@Test\s+(?:public\s+)?void\s+(\w+)\s*\(", source)) != tuple(name.encode() for name in GROUPS):
        raise ArtifactError("canonical Java source must retain all exact 25 groups in order")
    fixtures = capture_tree(root / "fixtures/sorafs_manifest", MAX_FIXTURE_BYTES)
    for relative, raw in fixtures.items():
        write_fresh(work / "snapshot/fixtures/sorafs_manifest" / relative, raw)
    manifest_raw = capture(args.native_manifest, "inputs/native-abi29.json", native.MAX_MANIFEST_BYTES)
    manifest = parse_native_manifest(manifest_raw)
    if manifest["sdk"] != "c-jni":
        raise ArtifactError("native evidence must authenticate the actual C/JNI owner")
    native.verify_manifest(manifest, artifact_path=args.native_artifact, source_root=root)
    expected_library = {"darwin": "libconnect_norito_bridge.dylib", "linux": "libconnect_norito_bridge.so", "win32": "connect_norito_bridge.dll"}.get(sys.platform)
    if expected_library is None or args.native_artifact.name != expected_library:
        raise ArtifactError("native artifact name does not match this host loader")
    native_raw = capture(args.native_artifact, "native/" + expected_library, MAX_ARCHIVE_BYTES)
    copied_native = work / "native" / expected_library
    native.verify_manifest(manifest, artifact_path=copied_native, source_root=root)
    jdk = args.jdk_home
    if jdk.resolve(strict=True) != jdk or not jdk.is_dir():
        raise ArtifactError("JDK home must be an absolute canonical directory")
    executable_suffix = ".exe" if sys.platform == "win32" else ""
    tool_paths = ["release", "lib/modules", "lib/ct.sym", "bin/java" + executable_suffix, "bin/javac" + executable_suffix]
    for relative in tool_paths:
        captures[jdk / relative] = read_file(jdk / relative, MAX_ARCHIVE_BYTES)
    if re.search(rb'(?m)^JAVA_VERSION="21(?:\.|\")', captures[jdk / "release"]) is None:
        raise ArtifactError("qualification requires the reviewed JDK 21 toolchain with --release 8")
    java, javac = str(jdk / ("bin/java" + executable_suffix)), str(jdk / ("bin/javac" + executable_suffix))
    empty_sources = work / "empty-sourcepath"
    empty_sources.mkdir(mode=0o700)
    results = []
    consumed_outputs = {}
    for lane in ("jvm", "android-host"):
        directory = work / lane
        directory.mkdir(mode=0o700)
        classes = directory / "classes"
        classes.mkdir(mode=0o700)
        jars = {work / "packages/core.jar": core_classes}
        if lane == "android-host":
            jars[work / "packages/android-classes.jar"] = android_classes
        classpath = os.pathsep.join(str(path) for path in (*jars, *dependency_paths))
        sources = [work / "sources/SorafsReferenceValidatorsJavaConsumerTest.java", work / "sources/SorafsJavaConsumerQualificationRunner.java"]
        if lane == "android-host":
            sources.append(work / "sources/SorafsAndroidPackageLinkProbe.java")
        run_command([javac, "--release", "8", "-proc:none", "-implicit:none", "-sourcepath", str(empty_sources), "-encoding", "UTF-8", "-classpath", classpath, "-d", str(classes), *map(str, sources)], directory, directory / "compile.log")
        compiled_files = capture_tree(classes, 16 * 1024 * 1024)
        compiled = {}
        for relative, raw in compiled_files.items():
            owner = parse_class(raw)
            if not relative.endswith(".class") or relative != owner.name + ".class" or owner.major != 52:
                raise ArtifactError("Java compiler output owner or JDK-8 target differs")
            allowed = {
                SUITE.replace(".", "/"): "SorafsReferenceValidatorsJavaConsumerTest.java",
                "org/hyperledger/iroha/qualification/SorafsJavaConsumerQualificationRunner": "SorafsJavaConsumerQualificationRunner.java",
            }
            if lane == "android-host":
                allowed["org/hyperledger/iroha/qualification/SorafsAndroidPackageLinkProbe"] = "SorafsAndroidPackageLinkProbe.java"
            if not any((owner.name == name or owner.name.startswith(name + "$")) and owner.source_file == source_file for name, source_file in allowed.items()):
                raise ArtifactError("compiler introduced an unexpected source owner")
            compiled[owner.name] = raw
        validate_test_classes(compiled)
        if not set(allowed) <= compiled.keys():
            raise ArtifactError("compiler omitted a required runner/assertion/probe owner")
        runtime_classpath = str(classes) + os.pathsep + classpath
        common = [java, "-ea", "-XX:-UsePerfData", "-Djava.library.path=" + str(work / "native"), "-Diroha.sorafs.fixtureRoot=" + str(work / "snapshot"), "-classpath", runtime_classpath]
        probe_log = b""
        if lane == "android-host":
            run_command(common + ["-Xlog:class+load=info:stdout:uptime,level,tags", "org.hyperledger.iroha.qualification.SorafsAndroidPackageLinkProbe"], directory, directory / "probe.log")
            probe_output = read_file(directory / "probe.log", MAX_LOG_BYTES)
            probe_log, _probe_libraries, _probe_report = consume_runtime_output(probe_output, report_required=False)
            write_fresh(directory / "probe-classes.log", probe_log)
        # JVM logs and the fixed runner's report share the same bounded pipe.
        # No JVM file log, rotation segment or child-created XML can escape it.
        run_command(common + ["-Xlog:class+load=info,library=info:stdout:uptime,level,tags", "org.hyperledger.iroha.qualification.SorafsJavaConsumerQualificationRunner"], directory, directory / "execute.log")
        execution_output = read_file(directory / "execute.log", MAX_LOG_BYTES)
        classes_log, libraries_log, report = consume_runtime_output(execution_output, report_required=True)
        assert report is not None
        write_fresh(directory / "junit.xml", report)
        write_fresh(directory / "classes.log", classes_log)
        write_fresh(directory / "libraries.log", libraries_log)
        dependency_loads = {"execution": validate_dependency_origins(classes_log, dependency_jars, execution=True), "android_probe": validate_dependency_origins(probe_log, dependency_jars, execution=False) if lane == "android-host" else []}
        cases = validate_report(report)
        loaded = validate_class_origins(classes_log + b"\n" + probe_log, jars, android=lane == "android-host", consumer_classes=(classes, compiled), required_consumer_owners=tuple(allowed))
        validate_library_origin(libraries_log, copied_native)
        if capture_tree(classes, 16 * 1024 * 1024) != compiled_files:
            raise ArtifactError("compiled consumers changed during execution")
        consumed_outputs[lane] = capture_tree(directory, MAX_ARCHIVE_BYTES)
        expected_outputs = {"compile.log", "execute.log", "junit.xml", "classes.log", "libraries.log"} | {"classes/" + name for name in compiled_files}
        if lane == "android-host":
            expected_outputs |= {"probe.log", "probe-classes.log"}
        if set(consumed_outputs[lane]) != expected_outputs:
            raise ArtifactError("consumer output inventory contains an unobserved file")
        if any(consumed_outputs[lane].get(name) != raw for name, raw in {"junit.xml": report, "classes.log": classes_log, "libraries.log": libraries_log, "execute.log": execution_output}.items()):
            raise ArtifactError("observed runtime report or origin log changed before capture")
        if lane == "android-host" and (consumed_outputs[lane].get("probe-classes.log") != probe_log or consumed_outputs[lane].get("probe.log") != probe_output):
            raise ArtifactError("observed Android probe log changed before capture")
        if {name.removeprefix("classes/"): raw for name, raw in consumed_outputs[lane].items() if name.startswith("classes/")} != compiled_files:
            raise ArtifactError("consumed compiled classes changed before capture")
        results.append({"lane": lane, "cases": list(cases), "loaded_classes": loaded, "dependency_classes": dependency_loads, "report": identity(report), "compiled_classes": {name: identity(raw) for name, raw in sorted(compiled_files.items())}})
    if any(empty_sources.iterdir()):
        raise ArtifactError("isolated empty source path was populated")
    native.verify_manifest(manifest, artifact_path=copied_native, source_root=root)
    native.verify_manifest(manifest, artifact_path=args.native_artifact, source_root=root)
    for path, expected in captures.items():
        if read_file(path, max(len(expected), 1)) != expected:
            raise ArtifactError("original qualification input changed during execution")
    if capture_tree(root / "fixtures/sorafs_manifest", MAX_FIXTURE_BYTES) != fixtures:
        raise ArtifactError("original fixtures changed during execution")
    # Authenticate every exact private classpath/native/fixture copy again.
    for relative, expected in private_inputs.items():
        if read_file(work / relative, len(expected)) != expected:
            raise ArtifactError("consumed private input changed during execution")
    if capture_tree(work / "snapshot/fixtures/sorafs_manifest", MAX_FIXTURE_BYTES) != fixtures:
        raise ArtifactError("consumed fixture snapshot changed during execution")
    for subtree in ("sources", "snapshot", "inputs", "jvm", "android-host"):
        observed = capture_tree(work / subtree, MAX_ARCHIVE_BYTES)
        if subtree in consumed_outputs and observed != consumed_outputs[subtree]:
            raise ArtifactError("executed lane outputs changed before packaging")
        if subtree in ("sources", "inputs") and observed != {name[len(subtree) + 1:]: raw for name, raw in private_inputs.items() if name.startswith(subtree + "/")}:
            raise ArtifactError("copied source or metadata changed before packaging")
        if subtree == "snapshot" and observed != {"fixtures/sorafs_manifest/" + name: raw for name, raw in fixtures.items()}:
            raise ArtifactError("fixture snapshot changed before packaging")
        for relative, raw in observed.items():
            retained[subtree + "/" + relative] = raw
    record = {"schema": SCHEMA, "consumer": "java_source_kotlin", "scope": "jvm-and-android-host-native", "source_commit": manifest["source_commit"], "native_source_manifest_sha256": manifest["workspace_source_manifest_sha256"], "packages": {"core_jar": identity(core), "client_aar": identity(aar), "android_classes_jar": identity(android_jar)}, "native_artifact": identity(native_raw), "native_manifest": identity(manifest_raw), "dependency_manifest": identity(dependency_manifest), "producer_inputs": tool_sources, "jdk_inputs": {relative: identity(captures[jdk / relative]) for relative in tool_paths}, "executions": results, "retained": {name: identity(raw) for name, raw in sorted(retained.items())}}
    retained["manifest.json"] = canonical_json(record)
    archive = deterministic_archive(retained)
    if deterministic_archive(retained) != archive:
        raise ArtifactError("qualification archive reconstruction differs")
    output = work / "java-source-kotlin-consumer.zip"
    write_fresh(output, archive)
    return {"schema": SCHEMA, "artifact": str(output), **identity(archive), "lanes": [row["lane"] for row in results], "groups_per_lane": len(GROUPS)}


def main() -> int:
    """Accept exact artifact paths and an independent tool dependency pin."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "work-dir", "core-jar", "client-aar", "native-artifact", "native-manifest", "jdk-home", "dependency-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--dependency-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = produce(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f"SoraFS Java consumer artifact rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
