"""Recheck original Java-consumer observations against actual indexed artifacts.

This verifies internal evidence and actual byte joins. It does not authenticate
an untrusted process origin or replace independent producer/operator approval,
the ReleaseManifest receipt, required device runs, or the other five adapters.
"""
from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path, PureWindowsPath
import re
import stat
from urllib.parse import urlsplit
from urllib.request import url2pathname
import zipfile

from build_sorafs_java_consumer_artifact import (
    DEPENDENCIES, MAX_FIXTURE_BYTES, SOURCE, RUNNER, PROBE, capture_tree,
    consume_runtime_output, parse_native_manifest,
)
from jvm_classfile import parse_class
from sorafs_evidence_json import decode_evidence_json
from sorafs_java_consumer_artifact import (
    CORE_OWNERS, GROUPS, MAX_ARCHIVE_BYTES, MAX_MEMBERS,
    MAX_MEMBER_BYTES, SCHEMA, SUITE, archive_members, canonical_json,
    deterministic_archive, identity, package_classes, read_file,
    dependency_classpath, validate_dependency_origins,
    validate_class_origins, validate_library_origin, validate_report,
    validate_test_classes,
)
from sorafs_sdk_artifact_index import IndexError, OpenedIndexFiles, PackageIndex

TOOLS = ("build_sorafs_java_consumer_artifact.py", "sorafs_java_consumer_artifact.py", "jvm_classfile.py", "sorafs_evidence_json.py", "check_native_sdk_artifact.py", "compute_workspace_source_manifest.py")
_MANIFEST_FIELDS = {"schema", "consumer", "scope", "source_commit", "native_source_manifest_sha256", "packages", "native_artifact", "native_manifest", "dependency_manifest", "producer_inputs", "jdk_inputs", "executions", "retained"}


def _exact(value: object, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise IndexError(f"Java {label} does not have its exact field inventory")
    return value


def _same_identity(raw: bytes, expected: object, label: str) -> None:
    expected = _exact(expected, {"sha256", "size"}, label)
    if type(expected["size"]) is not int or identity(raw) != expected:
        raise IndexError(f"Java {label} differs from the actual original bytes")


def _kotlin_members(raw: bytes, version: str) -> tuple[bytes, bytes]:
    """Select exact original JAR/AAR members without inflating native ZIP slices."""
    prefix = "iroha-mobile-sdk-android-" + version + "/"
    names, selected, total = set(), {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_MEMBERS:
            raise IndexError("Kotlin distribution has an excessive member inventory")
        for entry in entries:
            name = entry.filename
            if (entry.orig_filename != name or not name or name in names
                    or not name.startswith(prefix) or "\\" in name or ":" in name
                    or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
                raise IndexError("Kotlin distribution has an unsafe or duplicate member")
            names.add(name)
            mode = entry.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise IndexError("Kotlin distribution member type is unsupported")
            if entry.is_dir():
                if entry.file_size:
                    raise IndexError("Kotlin distribution directory has payload")
                continue
            total += entry.file_size
            if entry.file_size > 1024 * 1024 * 1024 or total > 3 * 1024 * 1024 * 1024:
                raise IndexError("Kotlin distribution exceeds its declared expansion bound")
            relative = name.removeprefix(prefix)
            role = None
            if relative == "client-android/client-android-release.aar": role = "aar"
            elif relative.startswith("core-jvm/") and relative.endswith(".jar") and relative.count("/") == 1: role = "jar"
            if role is not None:
                if role in selected or entry.file_size > MAX_MEMBER_BYTES:
                    raise IndexError("Kotlin distribution repeats or oversizes the original JAR/AAR")
                selected[role] = archive.read(entry)
                if len(selected[role]) != entry.file_size:
                    raise IndexError("Kotlin distribution JAR/AAR size differs")
    if set(selected) != {"jar", "aar"}:
        raise IndexError("Kotlin distribution does not contain the original JAR/AAR pair")
    return selected["jar"], selected["aar"]


def _logged_root(raw: bytes) -> Path:
    """Recover one exact original private package root from its observed load URI."""
    owner = CORE_OWNERS[0].replace("/", ".")
    matches = re.findall(r"\[class,load\]\s+" + re.escape(owner) + r" source: (.+)$", raw.decode("utf-8", "strict"), re.MULTILINE)
    if len(matches) != 1:
        raise IndexError("Java execution has no exact sole core-package origin")
    value = urlsplit(matches[0])
    if value.scheme != "file" or value.netloc or value.query or value.fragment:
        raise IndexError("Java package origin is not a local original file URI")
    path = Path(url2pathname(value.path))
    if not path.is_absolute() or ".." in path.parts or path.parts[-2:] != ("packages", "core.jar"):
        raise IndexError("Java package origin does not belong to its original private layout")
    return path.parent.parent


def _native_path(raw: bytes, root: Path) -> Path:
    origins = re.findall(r"Loaded library (.+?), handle", raw.decode("utf-8", "strict"))
    originals = [value for value in origins if "connect_norito_bridge" in value]
    if len(originals) != 1:
        raise IndexError("Java execution lacks its exact sole native load")
    value = originals[0]
    windows = PureWindowsPath(value)
    allowed = {"libconnect_norito_bridge.dylib", "libconnect_norito_bridge.so", "connect_norito_bridge.dll"}
    if windows.drive:
        # A Windows file URI carries /C:/ while the loader prints C:\\... . This
        # is the URI codec's exact drive mapping, never a second accepted SDK ID.
        expected = PureWindowsPath(root.as_posix().removeprefix("/")) / "native" / "connect_norito_bridge.dll"
        if windows != expected or value != str(expected):
            raise IndexError("Java native load escaped the original Windows input owner")
    else:
        path = Path(value)
        if path.name not in allowed or path != root / "native" / path.name:
            raise IndexError("Java native load escaped the original private input owner")
    return Path(value)


@dataclass(frozen=True)
class JavaConsumerObservations:
    """Immutable rechecked host observations; not an authenticated release approval."""
    artifact_sha256: str
    source_commit: str
    native_source_manifest_sha256: str
    kotlin_artifact_sha256: str
    native_artifact_sha256: str
    cases: tuple[tuple[str, tuple[str, ...]], ...]


def verify_java_consumer(index: PackageIndex, opened: OpenedIndexFiles, *, trusted_source_root: Path) -> JavaConsumerObservations:
    """Validate the actual archived observations and every immutable input join."""
    if opened.index is not index:
        raise IndexError("Java adapter must consume the original indexed file owner")
    row = index.consumer("java_source_kotlin")
    kotlin = index.consumer("kotlin_jvm")
    archive_raw = opened.read(row.artifact, MAX_ARCHIVE_BYTES)
    members = archive_members(archive_raw)
    if "manifest.json" not in members or deterministic_archive(members) != archive_raw:
        raise IndexError("Java qualification archive is not its exact deterministic representation")
    manifest = _exact(decode_evidence_json(members["manifest.json"]), _MANIFEST_FIELDS, "manifest")
    if members["manifest.json"] != canonical_json(manifest):
        raise IndexError("Java manifest bytes are not canonical")
    if (manifest["schema"] != SCHEMA or manifest["consumer"] != row.name
            or manifest["scope"] != "jvm-and-android-host-native"
            or manifest["source_commit"] != index.source_commit
            or manifest["native_source_manifest_sha256"] != index.workspace_source_manifest_sha256):
        raise IndexError("Java archive belongs to a different candidate or consumer scope")
    retained = manifest["retained"]
    if type(retained) is not dict or set(retained) != members.keys() - {"manifest.json"}:
        raise IndexError("Java retained byte inventory is incomplete or extra")
    for name, expected in retained.items():
        _same_identity(members[name], expected, "retained member")
    references = [index.file(path) for path in row.inputs]
    used = {kotlin.artifact}
    def original(expected: object, label: str, maximum: int) -> bytes:
        expected = _exact(expected, {"sha256", "size"}, label)
        found = [value for value in references if value.sha256 == expected["sha256"] and type(expected["size"]) is int and value.size == expected["size"]]
        if len(found) != 1:
            raise IndexError(f"Java {label} has no unique actual indexed input")
        used.add(found[0].path)
        return opened.read(found[0].path, maximum)
    packages = _exact(manifest["packages"], {"core_jar", "client_aar", "android_classes_jar"}, "packages")
    core = original(packages["core_jar"], "core JAR", MAX_ARCHIVE_BYTES)
    aar = original(packages["client_aar"], "client AAR", MAX_ARCHIVE_BYTES)
    core_classes, android_classes, android_jar = package_classes(core, aar)
    _same_identity(android_jar, packages["android_classes_jar"], "Android classes JAR")
    distribution = opened.read(kotlin.artifact, 1024 * 1024 * 1024)
    if _kotlin_members(distribution, kotlin.version) != (core, aar):
        raise IndexError("Java executed packages differ from the actual Kotlin distribution")
    native_raw = original(manifest["native_artifact"], "native artifact", MAX_ARCHIVE_BYTES)
    native_manifest = original(manifest["native_manifest"], "native manifest", 64 * 1024)
    if members.get("inputs/native-abi29.json") != native_manifest:
        raise IndexError("Java retained native manifest is a different original")
    native = parse_native_manifest(native_manifest)
    if native["sdk"] != "c-jni" or native["source_commit"] != index.source_commit or native["workspace_source_manifest_sha256"] != index.workspace_source_manifest_sha256 or native["artifact_sha256"] != identity(native_raw)["sha256"] or native["artifact_size"] != len(native_raw):
        raise IndexError("Java native artifact is not the original candidate ABI-29 input")
    dependency_raw = original(manifest["dependency_manifest"], "dependency manifest", 64 * 1024)
    if members.get("inputs/dependencies.json") != dependency_raw:
        raise IndexError("Java retained dependency manifest is a different original")
    dependency = _exact(decode_evidence_json(dependency_raw), {"schema", "jars"}, "dependency manifest")
    if dependency["schema"] != "sorafs.java_consumer.dependencies.v1" or type(dependency["jars"]) is not list:
        raise IndexError("Java dependency manifest schema differs")
    names, dependency_bytes = set(), {}
    for entry in dependency["jars"]:
        entry = _exact(entry, {"module", "version", "path", "sha256", "size"}, "dependency")
        name = entry["module"]
        if type(name) is not str or name not in DEPENDENCIES or name in names or type(entry["version"]) is not str or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", entry["version"]) is None or type(entry["path"]) is not str or not Path(entry["path"]).is_absolute():
            raise IndexError("Java dependency identity is unknown or repeated")
        names.add(name)
        raw = original({key: entry[key] for key in ("sha256", "size")}, "dependency JAR", 64 * 1024 * 1024)
        dependency_bytes[name] = raw
    if names != DEPENDENCIES:
        raise IndexError("Java dependency inventory is incomplete")
    jdk = manifest["jdk_inputs"]
    if type(jdk) is not dict or set(jdk) not in ({"release", "lib/modules", "lib/ct.sym", "bin/java", "bin/javac"}, {"release", "lib/modules", "lib/ct.sym", "bin/java.exe", "bin/javac.exe"}):
        raise IndexError("Java toolchain input inventory differs")
    for name, expected in jdk.items():
        raw = original(expected, "JDK input", MAX_ARCHIVE_BYTES)
        if name == "release" and re.search(rb'(?m)^JAVA_VERSION="21(?:\.|\")', raw) is None:
            raise IndexError("Java observation used a different toolchain release")
    tool_map = _exact(manifest["producer_inputs"], set(TOOLS), "producer tools")
    trusted = {}
    for name in TOOLS:
        trusted["inputs/tools/" + name] = read_file(trusted_source_root / "scripts" / name, 1024 * 1024)
        _same_identity(trusted["inputs/tools/" + name], tool_map[name], "reviewed producer tool")
    for name, path in (("SorafsReferenceValidatorsJavaConsumerTest.java", SOURCE), ("SorafsJavaConsumerQualificationRunner.java", RUNNER), ("SorafsAndroidPackageLinkProbe.java", PROBE)):
        trusted["sources/" + name] = read_file(trusted_source_root / path, 256 * 1024)
    fixtures = capture_tree(trusted_source_root / "fixtures/sorafs_manifest", MAX_FIXTURE_BYTES)
    trusted.update({"snapshot/fixtures/sorafs_manifest/" + name: raw for name, raw in fixtures.items()})
    if any(members.get(name) != raw for name, raw in trusted.items()):
        raise IndexError("Java archived source/fixtures/tools differ from the independently reviewed original")
    source = trusted["sources/SorafsReferenceValidatorsJavaConsumerTest.java"]
    if tuple(re.findall(rb"@Test\s+(?:public\s+)?void\s+(\w+)\s*\(", source)) != tuple(name.encode() for name in GROUPS):
        raise IndexError("Java source no longer contains the exact 25 original assertions")
    expected_members = set(trusted) | {"manifest.json", "inputs/dependencies.json", "inputs/native-abi29.json"}
    executions = manifest["executions"]
    if type(executions) is not list or len(executions) != 2:
        raise IndexError("Java executions must contain exactly two original lanes")
    cases = []
    work_roots = set()
    for lane, execution in zip(("jvm", "android-host"), executions, strict=True):
        execution = _exact(execution, {"lane", "cases", "loaded_classes", "dependency_classes", "report", "compiled_classes"}, "execution")
        if execution["lane"] != lane:
            raise IndexError("Java execution lane order differs")
        def observed(name: str) -> bytes:
            key = lane + "/" + name
            expected_members.add(key)
            if key not in members:
                raise IndexError("Java execution omits an original observed file")
            return members[key]
        observed("compile.log")
        full = observed("execute.log")
        class_log, library_log, report = consume_runtime_output(full, report_required=True)
        if observed("classes.log") != class_log or observed("libraries.log") != library_log or observed("junit.xml") != report:
            raise IndexError("Java retained logs/report differ from the original bounded stream")
        _same_identity(report, execution["report"], "executed report")
        actual_cases = validate_report(report)
        if execution["cases"] != list(actual_cases):
            raise IndexError("Java declared cases differ from actual non-skipped executions")
        root = _logged_root(class_log)
        work_roots.add(root)
        dependency_jars = dependency_classpath(dependency_bytes, root)
        dependency_loads = {"execution": validate_dependency_origins(class_log, dependency_jars, execution=True), "android_probe": []}
        jars = {root / "packages/core.jar": core_classes}
        if lane == "android-host":
            jars[root / "packages/android-classes.jar"] = android_classes
            probe, _, _ = consume_runtime_output(observed("probe.log"), report_required=False)
            if observed("probe-classes.log") != probe:
                raise IndexError("Java Android probe differs from its full observed stream")
            dependency_loads["android_probe"] = validate_dependency_origins(probe, dependency_jars, execution=False)
            class_log += b"\n" + probe
        if execution["dependency_classes"] != dependency_loads:
            raise IndexError("Java dependency origins differ from the actual runtime class bytes/log")
        inventory = execution["compiled_classes"]
        if type(inventory) is not dict or not inventory:
            raise IndexError("Java compiled owner inventory is absent")
        compiled = {}
        allowed = {SUITE.replace(".", "/"): "SorafsReferenceValidatorsJavaConsumerTest.java", "org/hyperledger/iroha/qualification/SorafsJavaConsumerQualificationRunner": "SorafsJavaConsumerQualificationRunner.java"}
        if lane == "android-host": allowed["org/hyperledger/iroha/qualification/SorafsAndroidPackageLinkProbe"] = "SorafsAndroidPackageLinkProbe.java"
        for name, expected in inventory.items():
            raw = observed("classes/" + name)
            _same_identity(raw, expected, "compiled source owner")
            owner = parse_class(raw)
            if name != owner.name + ".class" or owner.major != 52 or not any((owner.name == key or owner.name.startswith(key + "$")) and owner.source_file == source_file for key, source_file in allowed.items()):
                raise IndexError("Java compiled output belongs to an unreviewed source/target")
            compiled[owner.name] = raw
        if not set(allowed) <= compiled.keys():
            raise IndexError("Java compiler omitted a required runner/assertion/probe owner")
        validate_test_classes(compiled)
        loaded = validate_class_origins(class_log, jars, android=lane == "android-host", consumer_classes=(root / lane / "classes", compiled), required_consumer_owners=tuple(allowed))
        if execution["loaded_classes"] != loaded:
            raise IndexError("Java class-origin result differs from the actual package bytes/log")
        validate_library_origin(library_log, _native_path(library_log, root))
        cases.append((lane, tuple(actual_cases)))
    if len(work_roots) != 1 or set(members) != expected_members or used != set(row.inputs):
        raise IndexError("Java observations have extra files/inputs or split original operation roots")
    # No parsed input is reopened here. Trusted source inputs are independently
    # rechecked to detect local drift before returning immutable observations.
    for name, raw in trusted.items():
        if name.startswith("inputs/tools/"):
            path = trusted_source_root / "scripts" / name.removeprefix("inputs/tools/")
        elif name.startswith("sources/"):
            path = trusted_source_root / {"SorafsReferenceValidatorsJavaConsumerTest.java": SOURCE, "SorafsJavaConsumerQualificationRunner.java": RUNNER, "SorafsAndroidPackageLinkProbe.java": PROBE}[name.removeprefix("sources/")]
        else:
            continue
        if read_file(path, max(len(raw), 1)) != raw:
            raise IndexError("reviewed Java source/tool changed during verification")
    if capture_tree(trusted_source_root / "fixtures/sorafs_manifest", MAX_FIXTURE_BYTES) != fixtures:
        raise IndexError("reviewed Java fixtures changed during verification")
    opened.recheck()
    return JavaConsumerObservations(index.file(row.artifact).sha256, index.source_commit, index.workspace_source_manifest_sha256, index.file(kotlin.artifact).sha256, identity(native_raw)["sha256"], tuple(cases))
