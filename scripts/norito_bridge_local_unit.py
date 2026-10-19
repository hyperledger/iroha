"""Produce genuine, strictly local macOS Swift unit prerequisites from retained Cargo output.

No Cargo invocation, release admission, or native bypass.
The produce command requires explicit acknowledgement of its local-unit recipe.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))
import native_sdk_source_custody as source_custody

SCHEMA = "iroha.norito-bridge-local-unit-artifact.v1"
RECORD_SCHEMA = "iroha.norito-bridge-local-unit-producer.v1"
SCOPE = "local-unit"
PURPOSE = "macos-swift-debug-unit-tests"
SOURCE_SCOPE = "verified-compiler-native-runtime-manifest-inputs"
SHA = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}
HEADER_INPUTS = {
    "NoritoBridge.h": "crates/connect_norito_bridge/include/NoritoBridge.h",
    "connect_norito_bridge.h": "crates/connect_norito_bridge/include/connect_norito_bridge.h",
    "module.modulemap": "crates/connect_norito_bridge/module.modulemap.template",
}
POLICY_INPUTS = [
    "scripts/build_norito_xcframework.sh", "scripts/normalize_pqcrypto_archive.py",
    "scripts/validate_norito_bridge_xcframework.py", "scripts/check_native_sdk_artifact.py",
    "crates/soranet_pq/include/soranet_pq.h", "crates/iroha_data_model/src/privacy/protocol.rs",
    "docs/norito_bridge_release.md",
    "scripts/compute_workspace_source_manifest.py",
]
MANIFEST_FIELDS = {
    "schema", "artifact_scope", "purpose", "version", "native_bridge_abi_version",
    "target_triple", "hashes", "source_inputs", "tool_inputs", "receipt_inputs",
    "producer_record", "producer_record_sha256",
}


class Refused(RuntimeError):
    """A required original input or genuine component receipt did not pass."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON member: " + key)
        value[key] = item
    return value


def regular(path: Path, *, canonical=True, single_link=False):
    path = Path(path)
    require(path.is_absolute(), "input path must be absolute")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "input is not a real regular file: " + str(path))
    if canonical:
        require(path.resolve(strict=True) == path, "input traverses a lexical alias: " + str(path))
    if single_link:
        require(metadata.st_nlink == 1, "archive has a hardlink alias")
    return metadata


def digest(path: Path, *, canonical=True):
    before = regular(path, canonical=canonical)
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    after = regular(path, canonical=canonical)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "input changed during hashing: " + str(path))
    return value.hexdigest()


def load(path: Path, expected: str | None = None):
    if expected is not None:
        require(isinstance(expected, str) and SHA.fullmatch(expected), "receipt pin is malformed")
        require(digest(path) == expected, "receipt digest differs: " + str(path))
    else:
        regular(path)
    require(path.stat().st_size <= 64 * 1024 * 1024, "receipt exceeds the fixed 64 MiB input bound")
    value = json.loads(path.read_text(), object_pairs_hook=duplicates)
    require(isinstance(value, dict), "receipt must be a JSON object")
    return value


def save(path: Path, value):
    require(not os.path.lexists(path), "refusing existing record/output: " + str(path))
    with path.open("x", encoding="utf-8") as target:
        target.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
    path.chmod(0o400)


def verify_hashes(inputs: dict, *, tools=False):
    require(isinstance(inputs, dict) and inputs, "custody input inventory is empty")
    for name, expected in inputs.items():
        require(isinstance(name, str) and name.startswith("/")
                and isinstance(expected, str) and SHA.fullmatch(expected), "custody input is malformed")
        require((tool_digest(Path(name)) if tools else digest(Path(name))) == expected,
                "original input changed: " + name)


def tool_digest(path: Path):
    """Preserve a recorded tool spelling while guarding its canonical target."""
    require(path.is_absolute(), "tool path must be absolute")
    target = path.resolve(strict=True)
    value = digest(target)
    require(path.resolve(strict=True) == target, "tool alias target changed during hashing")
    return value


def native_policy(root: Path):
    """Read current symbol policy only from fixed repository-owned implementations."""
    native = module(root / "scripts/check_native_sdk_artifact.py", "current_unit_native_policy")
    apple = module(root / "scripts/validate_norito_bridge_xcframework.py", "current_unit_apple_policy")
    return {"c_jni": list(native.REQUIRED_SYMBOLS["c-jni"]),
            "privacy": list(native.APPROVED_PRIVACY_C_EXPORTS),
            "required": sorted(set(native.REQUIRED_SYMBOLS["c-jni"])
                               | set(native.APPROVED_PRIVACY_C_EXPORTS)
                               | set(apple.EXPECTED_REQUIRED_SYMBOLS)),
            "forbidden": list(apple.EXPECTED_FORBIDDEN_SYMBOLS)}


def check_source_record(record: dict):
    """Validate distinct broad diagnostics and the prospective consumed guard.

    This structural check does not authenticate the selected inventory: admission
    independently rederives it from complete actual compiler dep-info below.
    """
    require(record.get("source_scope") == SOURCE_SCOPE, "source custody scope is absent or differs")
    before, after = record.get("source_before"), record.get("source_after")
    require(isinstance(before, dict) and before and isinstance(after, dict) and after,
            "broad source observations are absent")
    identity_changes = record.get("source_identity_changes")
    require(isinstance(identity_changes, list) and all(isinstance(name, str) for name in identity_changes)
            and identity_changes == sorted(set(identity_changes)), "broad source identity diagnostic differs")
    require(record.get("source_changes") == sorted(set(source_changes(before, after)) | set(identity_changes)),
            "broad source diagnostic is absent or relabelled")
    selected = record.get("consumed_source")
    require(isinstance(selected, dict) and selected and all(before.get(name) == after.get(name) == sha
            for name, sha in selected.items()), "consumed source guard failed")
    first, last = record.get("consumed_identities_before"), record.get("consumed_identities_after")
    require(isinstance(first, dict) and first.keys() == selected.keys() and first == last
            and all(isinstance(value, list) and len(value) == 5
                    and all(type(item) is int for item in value) for value in first.values()),
            "consumed source identity guard failed")
    require(not set(identity_changes).intersection(selected), "consumed identity drift was relabelled")
    return selected


def check_record_semantics(emitter: dict, capture: dict, component: dict,
                           emitter_path: Path, emitter_sha: str, target: str):
    """Validate actual record relationships; never promote a compiler fingerprint."""
    require(type(emitter.get("natural_exit")) is int and emitter["natural_exit"] == 0
            and type(emitter.get("finished_unix")) in {int, float} and emitter["finished_unix"] > 0,
            "emitter did not complete successfully")
    for key in ["capture_errors", "dep_info_errors", "collector_toolchain_changes"]:
        require(key in emitter and emitter[key] == [], "emitter custody failed: " + key)
    source = check_source_record(emitter)
    require(emitter.get("collector_toolchain_after") == emitter.get("collector_toolchain_before")
            and emitter.get("collector_toolchain_after"), "emitter tool guard failed")
    require(isinstance(emitter.get("dep_info"), list) and emitter["dep_info"], "actual compiler dep-info is absent")
    emitted = emitter.get("emitted")
    require(isinstance(emitted, list) and len(emitted) == 1, "bridge emitted capture inventory is not exact")
    item = emitted[0]
    actual = item.get("cargo_artifact", {})
    require(actual.get("reason") == "compiler-artifact" and actual.get("target", {}).get("name") == "connect_norito_bridge"
            and set(actual["target"].get("crate_types", [])) == {"cdylib", "staticlib", "rlib"}, "not an actual bridge compiler artifact")
    require(type(actual.get("fresh")) is bool, "Cargo freshness observation is missing")
    # fresh=true is retained truth for a genuine current warm build whose complete
    # compiler dep-info/source custody passes. Never rewrite it as a fresh compilation.
    require(actual.get("features") == ["privacy-production-enabled"], "mandatory native features differ")
    require(actual.get("profile", {}).get("test") is False, "archive came from a test harness")
    require(capture.get("emitter") == str(emitter_path) and capture.get("emitter_sha256") == emitter_sha,
            "static capture names a different emitter")
    require(capture.get("actual_cargo_artifact") == actual, "static capture differs from exact Cargo JSON record")
    require(capture.get("target_triple") == target, "static capture target differs from the host")
    require(capture.get("archive_original") in actual.get("filenames", [])
            and str(capture["archive_original"]).endswith("/libconnect_norito_bridge.a"), "static archive is not the JSON-emitted archive")
    require(capture.get("snapshot_method") == "clonefile-cow", "static capture did not retain an independent COW original")
    require(check_source_record(capture) == source
            and capture["consumed_identities_before"] == emitter["consumed_identities_before"],
            "static capture consumed source guard differs")
    require(capture.get("finished_unix") and capture["finished_unix"] >= emitter["finished_unix"], "static capture predates emitter closure")
    require(capture.get("native_companion_sha256") == item.get("sha256"), "static archive companion differs")
    require(component.get("emitter_path") == str(emitter_path) and component.get("emitter_sha256") == emitter_sha,
            "native component names a different emitter")
    require(component.get("qualified") is True and component.get("observed_abi_version") == 31,
            "original ABI component did not pass exact ABI31")
    require(component.get("artifact_path") == item.get("snapshot")
            and component.get("artifact_sha256") == item.get("sha256"), "native component tested a different library")
    require(check_source_record(component) == source
            and component["consumed_identities_before"] == emitter["consumed_identities_before"],
            "native component consumed source guard differs")
    require(component.get("toolchain_before") == component.get("toolchain_after")
            and component.get("toolchain_after"), "native component tool guard differs")
    require(component.get("finished_unix") and component.get("export_count", 0) > 0,
            "native component did not close its export checks")
    return actual


def module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def recapture_native(root: Path, base: Path, emitter: dict):
    """Use the repository-owned capture contract; original private receipts are data."""
    metadata_path = base / "metadata.json"
    require(digest(metadata_path) == emitter["metadata_sha256"], "original metadata changed")
    return source_custody.capture(load(metadata_path), root, digest)


def source_changes(expected: dict, current: dict):
    return sorted(name for name in expected.keys() | current.keys() if expected.get(name) != current.get(name))


def verify_record_source_projections(metadata, root, emitter, capture, component):
    """Rederive every phase's selected inventory from verified emitted dependencies."""
    originals = emitter["source_before"]
    for record in (emitter, capture, component):
        for boundary in ("source_before", "source_after"):
            selected = source_custody.consumed_source_projection(metadata, root, originals,
                                                                record[boundary], emitter["dep_info"])
            require(selected == record["consumed_source"], "recorded consumed projection differs from actual inputs")


def verify_native_inputs(root: Path, base: Path, emitter: dict):
    current = recapture_native(root, base, emitter)
    changes = source_changes(emitter["source_before"], current)
    metadata = load(base / "metadata.json", emitter["metadata_sha256"])
    consumed = source_custody.consumed_source_projection(metadata, root, emitter["source_before"],
                                                       current, emitter["dep_info"])
    require(consumed == emitter["consumed_source"], "current consumed projection differs")
    for name, expected in emitter["consumed_identities_before"].items():
        path = Path(name.split(":", 1)[1]) if name.startswith(("registry:", "git:")) else root / name
        value = regular(path)
        require([value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns] == expected,
                "current consumed source identity changed: " + name)
    return consumed, {"captured_input_count": len(emitter["source_before"]),
                      "current_input_count": len(current), "broad_changed_paths": changes,
                      "scope": "broad original retained; current admission uses complete compiler/runtime/manifest custody"}


def admit(root: Path, pins: dict):
    """Read-only positive admission, including actual current source and tool custody."""
    target = TARGETS.get(platform.machine())
    require(sys.platform == "darwin" and target, "host unit producer requires a supported macOS host")
    values = {role: load(Path(data["path"]), data["sha256"]) for role, data in pins.items()}
    require(set(values) == {"emitter", "static_capture", "component"}, "input receipt role inventory is not exact")
    e, c, abi = values["emitter"], values["static_capture"], values["component"]
    ep = Path(pins["emitter"]["path"])
    check_record_semantics(e, c, abi, ep, pins["emitter"]["sha256"], target)
    policy = native_policy(root)
    require(abi.get("required_c_jni_symbols") == policy["c_jni"]
            and abi.get("privacy_c_exports") == policy["privacy"],
            "component current C/JNI/privacy policy inventory is not exact")
    verify_hashes(e["collector_toolchain_after"], tools=True)
    verify_hashes(c["collector_tools"], tools=True)
    verify_hashes(abi["toolchain_after"], tools=True)
    archive = Path(c["archive_snapshot"])
    metadata = regular(archive, single_link=True)
    require((metadata.st_dev, metadata.st_ino) != (c["archive_original_device"], c["archive_original_inode"]), "static capture aliases the original inode")
    require(metadata.st_size == c["archive_bytes"] and digest(archive) == c["archive_sha256"], "retained static archive changed")
    require(digest(Path(abi["artifact_path"])) == abi["artifact_sha256"], "retained actual native component changed")
    inventory_path = Path(abi["export_inventory_path"])
    require(digest(inventory_path) == abi["export_inventory_sha256"], "original export inventory changed")
    exports = json.loads(inventory_path.read_text())
    require(isinstance(exports, list) and len(exports) == abi["export_count"]
            and len(exports) == len(set(exports)), "original export inventory cardinality differs")
    require(set(abi["required_c_jni_symbols"]) <= set(exports)
            and set(abi["privacy_c_exports"]) <= set(exports), "original required export checks are incomplete")
    messages_path = ep.parent / "artifacts.jsonl"
    require(digest(messages_path) == e["artifacts_sha256"], "actual Cargo JSON changed")
    messages = source_custody.cargo_messages(messages_path.read_text(), duplicates)
    require(messages and messages[-1] == {"reason": "build-finished", "success": True}
            and sum(item.get("reason") == "build-finished" for item in messages) == 1,
            "actual Cargo JSON lacks one successful terminal")
    actual = c["actual_cargo_artifact"]
    require(sum(item == actual for item in messages) == 1, "exact static artifact is absent/duplicated in actual Cargo JSON")
    count = sum(item.get("reason") == "compiler-artifact" for item in messages)
    require(len(e["dep_info"]) == count, "actual Cargo compiler artifacts lack complete dep-info receipts")
    output_root = Path(c["archive_original"]).parent.parent
    require(output_root.is_relative_to(root / "target"), "actual output root is outside the worktree warm lane")
    source_custody.verify_dep_info(messages, e["dep_info"], root, e["source_before"],
                                  output_root, ep.parent / "dep-info", digest)
    metadata = load(ep.parent / "metadata.json", e["metadata_sha256"])
    verify_record_source_projections(metadata, root, e, c, abi)
    current, broad_diagnostic = verify_native_inputs(root, ep.parent, e)
    return {"pins": pins, "emitter": e, "capture": c, "component": abi,
            "native_source": current, "native_broad_diagnostic": broad_diagnostic,
            "messages_path": messages_path, "target": target, "policy": policy}


def swift_sources(root: Path):
    inputs = {}
    for current, directories, files in os.walk(root / "IrohaSwift", followlinks=False):
        directories[:] = sorted(name for name in directories if name not in {".build", ".swiftpm", ".git", "__pycache__"})
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                require(path == root / "IrohaSwift/NoritoBridge.xcframework"
                        and os.readlink(path) == "../dist/NoritoBridge.xcframework",
                        "Swift source alias is not the declared release artifact selector")
                inputs["@symlink:IrohaSwift/NoritoBridge.xcframework"] = hashlib.sha256(
                    os.readlink(path).encode()).hexdigest()
                continue
            inputs[str(path.relative_to(root))] = digest(path)
    for name in POLICY_INPUTS + list(HEADER_INPUTS.values()):
        inputs[name] = digest(root / name)
    return inputs


def guard_inputs(root: Path, admitted: dict, swift: dict, tools: dict):
    admit(root, admitted["pins"])
    require(swift_sources(root) == swift, "Swift/package/tests/fixtures input membership or bytes changed")
    verify_hashes(tools, tools=True)


def host_policy(scope: str, platform_name: str, configuration: str, require_external=False):
    require(scope == SCOPE, "host unit scope is not local-unit")
    require(platform_name == "macos", "local-unit artifacts cannot target iOS/non-macOS")
    require(configuration == "debug", "local-unit artifacts cannot enter Release")
    require(not require_external, "local-unit artifacts cannot enter external/release admission")


def expected_commands(root: Path, output: Path, target: str, config: dict):
    """The sole five-child normalization, index, link, run, package recipe."""
    stage = output / "staging"
    archive = stage / "libNoritoBridge.a"
    bridge_output = Path(config["actual_archive_original"]).parent
    architecture = {value: key for key, value in TARGETS.items()}[target]
    return [
        ([config["python"], "-I", "-S", "-B", str(root / "scripts/normalize_pqcrypto_archive.py"),
          "--library", str(archive), "--cargo-build-dir", str(bridge_output / "build"),
          "--cargo-messages", config["messages_path"], "--target", target,
          "--cargo-lock", str(root / "Cargo.lock"), "--report", str(stage / "normalization.json")],
         config["python"], "normalization.log"),
        (["ranlib", "-D", str(archive)], config["ranlib"], "ranlib.log"),
        ([config["clang"], "-target", architecture + "-apple-macos" + config["deployment_target"],
          "-isysroot", config["sdk"], "-I", str(root / "crates/connect_norito_bridge/include"),
          "-I", str(root / "crates/soranet_pq/include"), str(stage / "main.c"),
          "-Wl,-all_load", "-Wl,-export_dynamic", str(archive), "-framework", "Foundation",
          "-framework", "Security", "-framework", "Metal", "-framework", "CoreGraphics",
          "-framework", "Accelerate", "-lc++", "-liconv", "-o", str(stage / "consumer")],
         config["clang"], "consumer-link.log"),
        ([str(stage / "consumer")], str(stage / "consumer"), "consumer-run.log"),
        ([config["xcodebuild"], "-create-xcframework", "-library", str(archive),
          "-headers", str(stage / "Headers"), "-output", str(output / "NoritoBridge.xcframework")],
         config["xcodebuild"], "package.log"),
    ]


def verify_commands(root: Path, output: Path, target: str, config: dict, environment: dict, commands: list,
                    tools: dict):
    """Refuse fabricated recipe relationships before opening any child log."""
    expected = expected_commands(root, output, target, config)
    require(type(commands) is list and len(commands) == len(expected), "five child receipts are required")
    previous = 0
    for record, (argv, executable, log_name) in zip(commands, expected):
        require(set(record) == {"argv", "executable", "environment", "cwd", "started_unix",
                               "finished_unix", "natural_exit", "log", "log_sha256"}, "child receipt shape differs")
        require(record["argv"] == argv and record["executable"] == executable
                and record["environment"] == environment and record["cwd"] == str(root)
                and record["log"] == str(output / "staging" / log_name)
                and type(record["natural_exit"]) is int and record["natural_exit"] == 0,
                "child argv/tool/environment/log relationship differs")
        require(type(record["started_unix"]) in {int, float} and type(record["finished_unix"]) in {int, float}
                and previous <= record["started_unix"] <= record["finished_unix"], "child natural execution order differs")
        previous = record["finished_unix"]
        if executable != str(output / "staging" / "consumer"):
            require(executable in tools and SHA.fullmatch(tools[executable]), "child tool has no guarded original")
        require(type(record["log_sha256"]) is str and SHA.fullmatch(record["log_sha256"]), "child log pin is malformed")


def check_info(info: dict, target: str):
    """One exact real host slice; no invented universal/iOS metadata."""
    architecture = {value: key for key, value in TARGETS.items()}[target]
    identifier = "macos-" + architecture
    library = {"HeadersPath": "Headers", "LibraryIdentifier": identifier,
               "LibraryPath": "libNoritoBridge.a", "SupportedArchitectures": [architecture],
               "SupportedPlatform": "macos"}
    require(type(info) is dict and set(info) == {"CFBundlePackageType", "XCFrameworkFormatVersion", "AvailableLibraries"}
            and info["CFBundlePackageType"] == "XFWK" and info["XCFrameworkFormatVersion"] == "1.0"
            and info["AvailableLibraries"] in [[library], [dict(library, BinaryPath="libNoritoBridge.a")]],
            "Info.plist does not describe exactly one genuine host library")


def check_manifest(manifest: dict, target: str, producer: Path, producer_pin: str):
    """Refuse other scope/ABI or a substituted producer before reading source inputs."""
    architecture = {value: key for key, value in TARGETS.items()}[target]
    require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS
            and manifest["schema"] == SCHEMA and manifest["artifact_scope"] == SCOPE
            and manifest["purpose"] == PURPOSE and manifest["version"] == "0.1.0"
            and type(manifest["native_bridge_abi_version"]) is int and manifest["native_bridge_abi_version"] == 31
            and manifest["target_triple"] == target, "local-unit manifest schema/scope/ABI is not exact")
    require(manifest["producer_record"] == str(producer) and manifest["producer_record_sha256"] == producer_pin,
            "manifest producer pin differs")
    require(type(manifest["hashes"]) is dict and set(manifest["hashes"]) == {"macos-" + architecture}
            and all(type(value) is str and SHA.fullmatch(value) for value in manifest["hashes"].values()),
            "manifest archive identity is not exact")
    for key in ["source_inputs", "tool_inputs", "receipt_inputs"]:
        require(type(manifest[key]) is dict and manifest[key], "manifest custody inventory is missing")


def validate_tool_config(config: dict):
    """Bind the four executable roles to the selected Python and actual Xcode installation."""
    require(sys.version_info[:2] == (3, 12), "local-unit custody owner requires Python 3.12")
    developer = Path(config["developer_dir"])
    require(developer.is_absolute() and developer.resolve(strict=True) == developer and developer.is_dir(),
            "Xcode developer directory is not canonical")
    toolchain = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    require(Path(config["python"]).resolve(strict=True) == Path(sys.executable).resolve(strict=True),
            "normalizer/verifier Python differs from the current interpreter")
    require(Path(config["clang"]) == toolchain / "clang" and Path(config["ranlib"]) == toolchain / "ranlib"
            and Path(config["xcodebuild"]) == Path("/usr/bin/xcodebuild"),
            "native child tools do not belong to the selected actual Xcode recipe")
    sdk = Path(config["sdk"])
    require(sdk.resolve(strict=True) == sdk and sdk.is_dir()
            and sdk.is_relative_to(developer / "Platforms/MacOSX.platform/Developer/SDKs"),
            "consumer SDK is not the selected canonical macOS SDK")
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", config["deployment_target"]), "deployment target is malformed")
    return {str(developer / "usr/bin/xcodebuild"), str(sdk / "SDKSettings.json")}


def command_record(argv: list[str], *, environment: dict[str, str], cwd: Path, log: Path,
                   executable: str | None = None):
    """Run one reviewed finite child, recording a natural exit; never kill/timeout children."""
    started = time.time()
    with log.open("xb") as output:
        result = subprocess.run(argv, executable=executable, cwd=cwd, env=environment,
                                stdout=output, stderr=subprocess.STDOUT, check=False)
    record = {"argv": argv, "executable": executable or argv[0], "environment": environment,
              "cwd": str(cwd), "started_unix": started, "finished_unix": time.time(),
              "natural_exit": result.returncode, "log": str(log), "log_sha256": digest(log)}
    save(log.with_suffix(".record.json"), record)
    require(result.returncode == 0, "native unit child failed: " + str(log))
    return record


def clone(source: Path, destination: Path):
    regular(source, single_link=True)
    require(not os.path.lexists(destination), "COW destination already exists")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.clonefile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
    libc.clonefile.restype = ctypes.c_int
    require(libc.clonefile(os.fsencode(source), os.fsencode(destination), 0) == 0, "native clonefile failed")
    a, b = regular(source), regular(destination, single_link=True)
    require((a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) and digest(source) == digest(destination), "COW retention changed bytes/aliased source")


def artifact_root(root: Path, output: Path):
    """Keep create-only retained artifacts in the original checkout's qualification lane."""
    require(output.is_absolute() and str(output) == os.path.abspath(output), "output must be an absolute canonical path")
    qualification = root / "target" / "qualification"
    require(output != qualification and output.is_relative_to(qualification),
            "unit output must be below the original checkout target/qualification")
    require(not os.path.lexists(output), "unit output must be create-only")
    parent = output.parent
    metadata = parent.lstat()
    require(parent.resolve(strict=True) == parent and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
            "unit output parent must be owned canonical mode0700")


def consumer_source(root: Path):
    source = (root / "scripts/build_norito_xcframework.sh").read_text()
    marker = "cat > \"$consumer_dir/main.c\" <<'CONSUMER_EOF'\n"
    require(source.count(marker) == 1, "native consumer source owner is not unique")
    result = source.split(marker, 1)[1].split("\nCONSUMER_EOF", 1)[0] + "\n"
    require("check_mldsa_ffi()" in result and "PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec" in result
            and "CONNECT_NORITO_BRIDGE_ABI_VERSION" in result, "complete original native consumer checks are absent")
    policy = native_policy(root)
    required = ",\n".join("    " + json.dumps(name) for name in policy["required"])
    forbidden = ",\n".join("    " + json.dumps(name) for name in policy["forbidden"])
    # Retain every original crypto/ABI check unchanged and wrap its entrypoint.
    return ("#include <dlfcn.h>\n#include <stdio.h>\n#define main iroha_original_crypto_main\n" + result
            + "\n#undef main\nstatic const char *required_symbols[] = {\n" + required + "\n};\n"
            + "static const char *forbidden_symbols[] = {\n" + forbidden + "\n};\n"
            + "int main(void) {\n"
            + "    for (size_t i = 0; i < sizeof(required_symbols)/sizeof(required_symbols[0]); ++i) {\n"
            + "        if (!dlsym(RTLD_DEFAULT, required_symbols[i])) { fprintf(stderr, \"missing native symbol: %s\\n\", required_symbols[i]); return 21; }\n    }\n"
            + "    for (size_t i = 0; i < sizeof(forbidden_symbols)/sizeof(forbidden_symbols[0]); ++i) {\n"
            + "        if (dlsym(RTLD_DEFAULT, forbidden_symbols[i])) { fprintf(stderr, \"retired native symbol: %s\\n\", forbidden_symbols[i]); return 22; }\n    }\n"
            + "    return iroha_original_crypto_main();\n}\n")


def child_environment(root: Path, output: Path, config: dict):
    """Bind native packaging scratch to its private original-checkout capture."""
    qualification = root / "target/qualification"
    require(output.is_absolute() and str(output) == os.path.abspath(output)
            and output != qualification and output.is_relative_to(qualification),
            "native scratch must belong to an original qualification capture")
    temporary = output / "temporary"
    for directory in (output, temporary):
        metadata = directory.lstat()
        require(directory.resolve(strict=True) == directory and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
                "native scratch directory must be owned canonical mode0700")
    return {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "TMPDIR": str(temporary),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "DEVELOPER_DIR": config["developer_dir"]}


def produce(root: Path, pins: dict, output: Path, config: dict, acknowledge_recipe: bool):
    """Assemble a real thin host artifact after all genuine-input guards pass."""
    require(acknowledge_recipe, "native packaging requires explicit local-unit recipe acknowledgement")
    host_policy(SCOPE, "macos", "debug", os.environ.get("MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT") == "1")
    require("MOBILE_SDK_APPLE_ARTIFACT_DIR" not in os.environ, "release/external artifact selector must be absent")
    artifact_root(root, output)
    admitted = admit(root, pins)
    require(set(config) == {"python", "clang", "ranlib", "xcodebuild", "developer_dir", "sdk", "deployment_target"}, "native tool configuration is not exact")
    extra_tools = validate_tool_config(config)
    tools = {str(Path(config[k])): tool_digest(Path(config[k]))
             for k in ["python", "clang", "ranlib", "xcodebuild"]}
    tools.update({name: tool_digest(Path(name)) for name in extra_tools})
    tools[str(Path(__file__).resolve())] = digest(Path(__file__).resolve())
    tools[str(Path(source_custody.__file__).resolve())] = digest(Path(source_custody.__file__).resolve())
    require(Path(config["sdk"]).resolve(strict=True) == Path(config["sdk"]), "macOS SDK path is not canonical")
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", config["deployment_target"]), "deployment target is malformed")
    config = dict(config, actual_archive_original=admitted["capture"]["archive_original"],
                  messages_path=str(admitted["messages_path"]))
    swift = swift_sources(root)
    output.mkdir(mode=0o700)
    (output / "temporary").mkdir(mode=0o700)
    environment = child_environment(root, output, config)
    stage = output / "staging"
    stage.mkdir(mode=0o700)
    commands = []
    archive = stage / "libNoritoBridge.a"
    clone(Path(admitted["capture"]["archive_snapshot"]), archive)
    archive.chmod(0o600)
    normalizer = root / "scripts/normalize_pqcrypto_archive.py"
    normalizer_owner = module(normalizer, "current_original_unit_normalizer")
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    packages = [p for p in lock["package"] if p["name"] == "pqcrypto-internals"]
    require(len(packages) == 1, "locked PQClean reference package is not unique")
    actual = admitted["capture"]["actual_cargo_artifact"]
    build_dir = Path(admitted["capture"]["archive_original"]).parent / "build"
    references, reference_record = normalizer_owner.cargo_references(build_dir, admitted["target"], admitted["messages_path"], packages[0])
    ref_dir = stage / "reference-originals"
    ref_dir.mkdir(mode=0o700)
    reference_inputs = {reference_record["cargo_build_output"]: reference_record["cargo_build_output_sha256"]}
    out_dir = Path(reference_record["cargo_build_output"]).parent / "out"
    for name, value in references.items():
        reference_inputs[str(out_dir / name)] = hashlib.sha256(value).hexdigest()
        clone(out_dir / name, ref_dir / name)
        (ref_dir / name).chmod(0o400)
    clone(Path(reference_record["cargo_build_output"]), ref_dir / "output")
    (ref_dir / "output").chmod(0o400)
    save(stage / "reference-inputs.json", {"scope": SCOPE, "original_inputs": reference_inputs,
        "held_inputs": {str(p): digest(p) for p in ref_dir.iterdir()}, "provenance": reference_record})
    guard_inputs(root, admitted, swift, tools)
    commands.append(command_record([config["python"], "-I", "-S", "-B", str(normalizer), "--library", str(archive),
        "--cargo-build-dir", str(build_dir), "--cargo-messages", str(admitted["messages_path"]),
        "--target", admitted["target"], "--cargo-lock", str(root / "Cargo.lock"),
        "--report", str(stage / "normalization.json")], environment=environment, cwd=root, log=stage / "normalization.log"))
    verify_hashes(reference_inputs)
    normalization = load(stage / "normalization.json")
    require(normalization["input_sha256"] == admitted["capture"]["archive_sha256"]
            and normalization["unindexed_output_sha256"] == digest(archive),
            "normalizer input/output differs from the actual retained/derived archives")
    guard_inputs(root, admitted, swift, tools)
    commands.append(command_record(["ranlib", "-D", str(archive)], executable=config["ranlib"],
        environment=environment, cwd=root, log=stage / "ranlib.log"))
    indexed_sha = digest(archive)
    main = stage / "main.c"
    main.write_text(consumer_source(root))
    consumer = stage / "consumer"
    architecture = platform.machine()
    clang_target = architecture + "-apple-macos" + config["deployment_target"]
    guard_inputs(root, admitted, swift, tools)
    commands.append(command_record([config["clang"], "-target", clang_target, "-isysroot", config["sdk"],
        "-I", str(root / "crates/connect_norito_bridge/include"), "-I", str(root / "crates/soranet_pq/include"), str(main),
        "-Wl,-all_load", "-Wl,-export_dynamic", str(archive), "-framework", "Foundation", "-framework", "Security", "-framework", "Metal",
        "-framework", "CoreGraphics", "-framework", "Accelerate", "-lc++", "-liconv", "-o", str(consumer)],
        environment=environment, cwd=root, log=stage / "consumer-link.log"))
    require(digest(archive) == indexed_sha, "native consumer link changed archive")
    commands.append(command_record([str(consumer)], environment=environment, cwd=root, log=stage / "consumer-run.log"))
    guard_inputs(root, admitted, swift, tools)
    headers = stage / "Headers"
    headers.mkdir(mode=0o700)
    for name, source in HEADER_INPUTS.items():
        (headers / name).write_bytes((root / source).read_bytes())
    framework = output / "NoritoBridge.xcframework"
    commands.append(command_record([config["xcodebuild"], "-create-xcframework", "-library", str(archive),
        "-headers", str(headers), "-output", str(framework)], environment=environment, cwd=root, log=stage / "package.log"))
    guard_inputs(root, admitted, swift, tools)
    identifier = "macos-" + architecture
    binary = framework / identifier / "libNoritoBridge.a"
    require(digest(binary) == indexed_sha, "XCFramework package changed native archive")
    info = plistlib.loads((framework / "Info.plist").read_bytes())
    library = {"HeadersPath": "Headers", "LibraryIdentifier": identifier, "LibraryPath": "libNoritoBridge.a",
               "SupportedArchitectures": [architecture], "SupportedPlatform": "macos"}
    check_info(info, admitted["target"])
    verify_commands(root, output, admitted["target"], config, environment, commands, tools)
    record = {"schema": RECORD_SCHEMA, "scope": SCOPE, "purpose": PURPOSE, "passed": True,
              "target_triple": admitted["target"], "pins": pins, "cargo_artifact": actual,
              "native_source": admitted["native_source"], "swift_sources": swift, "tool_inputs": tools,
              "native_broad_diagnostic": admitted["native_broad_diagnostic"],
              "reference_inputs_record": str(stage / "reference-inputs.json"), "reference_inputs_record_sha256": digest(stage / "reference-inputs.json"),
              "normalization": str(stage / "normalization.json"), "normalization_sha256": digest(stage / "normalization.json"),
              "unindexed_archive_sha256": normalization["unindexed_output_sha256"],
              "consumer_source_sha256": digest(main), "consumer_sha256": digest(consumer), "commands": commands,
              "archive_sha256": indexed_sha, "finished_unix": time.time(), "release_qualified": False,
              "config": config, "environment": environment, "info_plist": info,
              "policy": admitted["policy"]}
    producer = output / "producer-record.json"
    save(producer, record)
    source = {**swift}
    for path, expected in admitted["native_source"].items():
        if path.startswith(("registry:", "git:")):
            path = path.split(":", 1)[1]
        source[path] = expected
    receipts = {value["path"]: value["sha256"] for value in pins.values()}
    manifest = {"schema": SCHEMA, "artifact_scope": SCOPE, "purpose": PURPOSE, "version": "0.1.0",
                "native_bridge_abi_version": 31, "target_triple": admitted["target"], "hashes": {identifier: indexed_sha},
                "source_inputs": source, "tool_inputs": tools, "receipt_inputs": receipts,
                "producer_record": str(producer), "producer_record_sha256": digest(producer)}
    save(framework / "NoritoBridge.artifacts.json", manifest)
    verify_artifact(root, output, digest(producer))
    return producer


def verify_artifact(root: Path, output: Path, producer_pin: str):
    """Re-admit source/component custody and actual completed commands before Swift use."""
    producer = output / "producer-record.json"
    record = load(producer, producer_pin)
    require(record.get("schema") == RECORD_SCHEMA and record.get("scope") == SCOPE
            and record.get("purpose") == PURPOSE and record.get("passed") is True
            and record.get("release_qualified") is False, "producer did not pass local-unit admission")
    target = TARGETS.get(platform.machine())
    require(target is not None and sys.platform == "darwin", "local-unit verification requires the actual macOS host")
    framework = output / "NoritoBridge.xcframework"
    manifest = load(framework / "NoritoBridge.artifacts.json")
    check_manifest(manifest, target, producer, producer_pin)
    admitted = admit(root, record["pins"])
    require(record["cargo_artifact"] == admitted["capture"]["actual_cargo_artifact"], "producer references a different actual archive")
    require(record["native_source"] == admitted["native_source"], "current consumed native source projection differs")
    config = record["config"]
    require(set(config) == {"python", "clang", "ranlib", "xcodebuild", "developer_dir", "sdk", "deployment_target",
                           "actual_archive_original", "messages_path"}
            and config["actual_archive_original"] == admitted["capture"]["archive_original"]
            and config["messages_path"] == str(admitted["messages_path"]), "child input configuration differs")
    expected_tools = {config[key] for key in ["python", "clang", "ranlib", "xcodebuild"]}
    expected_tools |= {str(Path(__file__).resolve()), str(Path(source_custody.__file__).resolve())}
    expected_tools |= validate_tool_config(config)
    require(set(record["tool_inputs"]) == expected_tools, "producer tool/code input membership is pruned or substituted")
    require(record["environment"] == child_environment(root, output, config),
            "child environment is not the fixed unit recipe")
    require(record["policy"] == admitted["policy"], "current native symbol policy differs")
    verify_commands(root, output, admitted["target"], config, record["environment"], record["commands"], record["tool_inputs"])
    for c in record["commands"]:
        require(digest(Path(c["log"])) == c["log_sha256"], "actual child log changed")
        require(load(Path(c["log"]).with_suffix(".record.json")) == c,
                "actual child natural-exit receipt differs")
    stage = output / "staging"
    require(digest(stage / "main.c") == record["consumer_source_sha256"]
            and (stage / "main.c").read_text() == consumer_source(root), "complete original native consumer source differs")
    require(digest(stage / "consumer") == record["consumer_sha256"], "actual complete-archive consumer changed")
    require(record["commands"][3]["argv"] == [str(stage / "consumer")], "native execution receipt ran a different consumer")
    require(digest(Path(record["normalization"])) == record["normalization_sha256"], "normalization record changed")
    normalized = load(Path(record["normalization"]))
    require(set(normalized) == {"schema", "target", "input_sha256", "unindexed_output_sha256",
                                "removed_identical_members", "references"}
            and normalized["schema"] == "iroha.pqcrypto-common-archive-normalization.v1"
            and normalized["input_sha256"] == admitted["capture"]["archive_sha256"]
            and normalized["target"] == admitted["target"]
            and normalized["unindexed_output_sha256"] == record["unindexed_archive_sha256"],
            "normalization used a stale/different archive")
    reference = load(Path(record["reference_inputs_record"]), record["reference_inputs_record_sha256"])
    require(record["normalization"] == str(stage / "normalization.json")
            and record["reference_inputs_record"] == str(stage / "reference-inputs.json")
            and set(reference) == {"scope", "original_inputs", "held_inputs", "provenance"}
            and reference["scope"] == SCOPE and normalized["references"] == reference["provenance"],
            "normalization/reference source relationships differ")
    normalizer = module(root / "scripts/normalize_pqcrypto_archive.py", "current_verified_unit_normalizer")
    packages = [package for package in tomllib.loads((root / "Cargo.lock").read_text())["package"]
                if package["name"] == "pqcrypto-internals"]
    require(len(packages) == 1, "locked PQClean package owner differs")
    refs, provenance = normalizer.cargo_references(Path(config["actual_archive_original"]).parent / "build",
                                                  admitted["target"], admitted["messages_path"], packages[0])
    require(provenance == reference["provenance"], "actual current Cargo-linked reference provenance differs")
    ref_root = stage / "reference-originals"
    expected_original = {provenance["cargo_build_output"]: provenance["cargo_build_output_sha256"]}
    out_dir = Path(provenance["cargo_build_output"]).parent / "out"
    expected_original.update({str(out_dir / name): hashlib.sha256(raw).hexdigest() for name, raw in refs.items()})
    expected_held = {str(ref_root / "output"): provenance["cargo_build_output_sha256"]}
    expected_held.update({str(ref_root / name): hashlib.sha256(raw).hexdigest() for name, raw in refs.items()})
    require(reference["original_inputs"] == expected_original and reference["held_inputs"] == expected_held
            and set(path.name for path in ref_root.iterdir()) == set(refs) | {"output"},
            "reference input membership is pruned/substituted")
    verify_hashes(reference["held_inputs"])
    verify_hashes(reference["original_inputs"])
    guard_inputs(root, admitted, record["swift_sources"], record["tool_inputs"])
    expected_inputs = dict(record["swift_sources"])
    for name, expected in admitted["native_source"].items():
        if name.startswith(("registry:", "git:")):
            name = name.split(":", 1)[1]
        expected_inputs[name] = expected
    require(manifest["source_inputs"] == expected_inputs and manifest["tool_inputs"] == record["tool_inputs"]
            and manifest["receipt_inputs"] == {v["path"]: v["sha256"] for v in record["pins"].values()},
            "manifest source/tool/receipt membership is pruned or substituted")
    identifier = "macos-" + platform.machine()
    require(manifest["target_triple"] == admitted["target"] and manifest["hashes"] == {identifier: record["archive_sha256"]}, "manifest invents target/architecture provenance")
    require(set(p.name for p in framework.iterdir()) == {"Info.plist", "NoritoBridge.artifacts.json", identifier}, "local-unit framework inventory is not exact")
    info = plistlib.loads((framework / "Info.plist").read_bytes())
    check_info(info, admitted["target"])
    require(info == record["info_plist"], "actual produced Info.plist changed")
    require(set(p.name for p in (framework / identifier).iterdir()) == {"Headers", "libNoritoBridge.a"}
            and set(p.name for p in (framework / identifier / "Headers").iterdir()) == set(HEADER_INPUTS),
            "packaged slice/header inventory is not exact")
    require(digest(framework / identifier / "libNoritoBridge.a") == record["archive_sha256"], "packaged archive changed")
    for name, source in HEADER_INPUTS.items():
        require(digest(framework / identifier / "Headers" / name) == digest(root / source), "packaged current header changed")
    return record


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["admit", "produce", "verify"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--producer-sha256")
    parser.add_argument("--acknowledge-local-unit-recipe", action="store_true")
    parser.add_argument("--consumer-platform", choices=["macos", "ios"], default="macos")
    parser.add_argument("--consumer-configuration", choices=["debug", "release"], default="debug")
    args = parser.parse_args()
    try:
        require(args.root.resolve(strict=True) == args.root, "source root is not canonical")
        if args.mode == "verify":
            host_policy(SCOPE, args.consumer_platform, args.consumer_configuration,
                        os.environ.get("MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT") == "1")
            require(args.output and args.producer_sha256, "verify requires exact output/producer pin")
            verify_artifact(args.root, args.output, args.producer_sha256)
        else:
            require(args.pins, "actual receipt pin selection is mandatory")
            pins = load(args.pins)
            if args.mode == "admit":
                value = admit(args.root, pins)
                print("Current compiler/runtime/manifest source0 and original component/static custody admitted", len(value["native_source"]))
            else:
                require(args.output and args.config, "produce requires output and explicit native tool configuration")
                print(produce(args.root, pins, args.output, load(args.config), args.acknowledge_local_unit_recipe))
        return 0
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print("local-unit refused:", error)
        return 3


if __name__ == "__main__":
    raise SystemExit(cli())
