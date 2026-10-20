"""Produce and verify genuine current host N-API artifacts for ordinary local units.

This owner builds the original checkout in an existing Cargo lane and retains
artifacts in a private child of its target/qualification directory, separate from
the Cargo lane. It grants no package, authenticated release, device or network
qualification. Current source, dep-info, tools, artifact bytes and ABI remain
bound through the ordinary SDK loader.
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
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_sdk_source_custody as custody

SCHEMA = "iroha.js-native-local-unit.v1"
RECORD_SCHEMA = "iroha.js-native-local-unit-producer.v1"
PACKAGE = "iroha_js_host"
FILENAME = "iroha_js_host.node"
MANIFEST = "iroha_js_host.local-unit.json"
HOSTS = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def regular(path, *, single=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "input is not canonical")
    row = path.lstat()
    require(stat.S_ISREG(row.st_mode) and row.st_size > 0 and (not single or row.st_nlink == 1),
            "input is not a nonempty original regular file")
    return row


def digest(path):
    path = Path(path); before = regular(path); sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    after = regular(path)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "input changed while hashed")
    return sha.hexdigest()


def source_digest(path):
    """Authenticate complete original source bytes, including valid empty files."""
    path = custody.original_file(Path(path))
    before = path.stat(); sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    after = custody.original_file(path).stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "original source changed while hashed")
    return sha.hexdigest()


def duplicates(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON member")
        result[name] = value
    return result


def load(path, sha=None):
    path = Path(path); regular(path)
    require(path.stat().st_size <= 64 * 1024 * 1024, "JSON input exceeds 64MiB")
    if sha is not None:
        require(digest(path) == sha, "input record hash differs")
    return json.loads(path.read_text(), object_pairs_hook=duplicates)


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def fixed_module(path, name):
    regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def policy(root):
    owner = fixed_module(root / "scripts/check_native_sdk_artifact.py", "current_local_napi_policy")
    text = (root / "javascript/iroha_js/scripts/copy-native.mjs").read_text()
    selection = re.findall(r"export const REQUIRED_NATIVE_EXPORTS = Object\.freeze\(\[(.*?)\]\);", text, re.S)
    require(len(selection) == 1, "current Node required export policy is not unique")
    literals = "[" + selection[0] + "]"
    required = json.loads(re.sub(r",\s*\]$", "]", literals), object_pairs_hook=duplicates)
    require(isinstance(required, list) and len(required) == len(set(required))
            and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) for name in required),
            "current Node export policy is not a literal exact inventory")
    return {"required": sorted(set(required) | set(owner.REQUIRED_SYMBOLS["node"])),
            "forbidden": sorted(owner.RETIRED_PROTOCOL_SYMBOLS["node"]), "abi_version": 31,
            "required_results": {"connectNoritoBridgeAbiVersion": 31, "securePrivateFileAbiVersion": 1}}


def local_policy(scope, profile):
    require(scope == "local-unit" and profile == "debug", "local N-API scope requires Debug local-unit")


def qualification_child(root, path):
    """Admit only lexical children of the original checkout's generated lane."""
    parent = root / "target/qualification"
    return (path.is_absolute() and str(path) == os.path.abspath(path)
            and path != parent and path.is_relative_to(parent))


def artifact_directory(root, output, *, create):
    """Keep retained native bytes in private, canonical qualification directories."""
    require(qualification_child(root, output), "local artifact must be below original target/qualification")
    checked = output.parent if create else output
    require(not create or not os.path.lexists(output), "local artifact output must be create-only")
    metadata = checked.lstat()
    require(checked.resolve(strict=True) == checked and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
            "local artifact directory is not owned canonical mode0700")


def build_directory(root, target, output):
    """Keep the original-checkout Cargo lane distinct from retained artifacts."""
    require((target.is_relative_to(root / "target/cargo-fast") or qualification_child(root, target))
            and target.is_dir() and target.resolve(strict=True) == target,
            "existing worktree warm lane required")
    require(not target.is_relative_to(output) and not output.is_relative_to(target),
            "Cargo lane and retained artifact must be disjoint")


def expected_build(root, target):
    return [str(root / "scripts/cargo_fast.sh"), "--target-dir", str(target),
            "--stable-local-metadata", "--no-incremental", "--zero-debug", "--jobs", "1", "--", "build", "--locked", "--offline",
            "-p", PACKAGE, "--lib", "--message-format=json"]


def artifact(messages, root, target, *, authenticate_file=True):
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    expected = target / "debug/libiroha_js_host.dylib"
    candidates = [item for item in messages if item.get("reason") == "compiler-artifact"
                  and item.get("target", {}).get("name") == PACKAGE]
    require(len(candidates) == 1, "Cargo did not emit exactly one genuine iroha_js_host artifact")
    row = candidates[0]; pkg = root / "crates" / PACKAGE
    require(row.get("package_id") == "path+" + pkg.as_uri() + "#" + version
            and row.get("manifest_path") == str(pkg / "Cargo.toml")
            and row.get("target", {}).get("src_path") == str(pkg / "src/lib.rs")
            and row["target"].get("kind") == ["cdylib"]
            and row["target"].get("crate_types") == ["cdylib"]
            and row.get("features") == [] and row.get("executable") is None
            and type(row.get("fresh")) is bool
            and row.get("profile") == {"opt_level": "0", "debuginfo": 0,
                                       "debug_assertions": True, "overflow_checks": True, "test": False}
            and row.get("filenames") == [str(expected)], "Cargo N-API identity/profile/output differs")
    if authenticate_file:
        regular(expected)
    return row, expected


def tool_digest(path):
    path = Path(path); target = path.resolve(strict=True); value = digest(target)
    require(path.resolve(strict=True) == target, "tool alias resolution changed")
    return value


def tool_inputs(root, config):
    paths = [config[key] for key in ("python", "cargo", "rustc", "rustdoc", "node", "clang", "ld", "codesign")]
    paths += [str(Path(__file__).resolve()), str(Path(custody.__file__).resolve()),
              str(root / "scripts/cargo_fast.sh"), str(root / "scripts/check_native_sdk_artifact.py"),
              str(root / "scripts/compute_workspace_source_manifest.py"),
              str(root / "scripts/check_cargo_target_owner.py"),
              str(root / "javascript/iroha_js/scripts/probe-local-native-unit.mjs"),
              str(root / "javascript/iroha_js/scripts/copy-native.mjs"),
              str(root / "javascript/iroha_js/src/nativeArtifactHash.js"),
              str(root / "javascript/iroha_js/src/native.js"), str(Path(config["sdk"]) / "SDKSettings.json")]
    python_fast = shutil.which("python3", path=tool_path(config))
    require(python_fast, "Cargo wrapper Python tool is absent")
    paths.append(python_fast)
    for name in ("bash", "git", "cc", "c++", "clang", "clang++", "ar", "ranlib", "xcrun"):
        path = shutil.which(name, path=tool_path(config))
        require(path, "actual native recipe tool is absent: " + name)
        paths.append(path)
    apple_tools = Path(config["clang"]).parent
    paths.extend(str(apple_tools / name) for name in ("clang++", "ar", "ranlib"))
    for name in ("config", "config.toml"):
        path = Path.home() / ".cargo" / name
        if os.path.lexists(path): paths.append(str(path))
    for current, directories, files in os.walk(Path(config["rustc"]).parent.parent / "lib", followlinks=False):
        for name in directories: custody.original_directory(Path(current) / name)
        for name in files:
            path = Path(current) / name
            if path.suffix in {".dylib", ".so", ".rlib", ".rmeta"}: paths.append(str(path))
    return {path: tool_digest(path) for path in paths}


def check_tools(expected):
    require(expected and all(tool_digest(path) == value for path, value in expected.items()), "current tools/policy/recipe differ")


def tool_path(config):
    """Resolve tools through the same fixed path used by native children."""
    return str(Path(config["cargo"]).parent) + ":/opt/homebrew/bin:/usr/bin:/bin"


def environment(root, config, output):
    """Keep compiler scratch inside the same private original-checkout capture."""
    artifact_directory(root, output, create=False)
    temporary = output / "temporary"
    artifact_directory(root, temporary, create=False)
    return {"HOME": str(Path.home()), "PATH": tool_path(config),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": str(temporary),
            "RUSTC": config["rustc"], "RUSTDOC": config["rustdoc"],
            "SDKROOT": config["sdk"], "MACOSX_DEPLOYMENT_TARGET": "13.0",
            "DEVELOPER_DIR": config["developer_dir"], "NODE_OPTIONS": "",
            # Client-side sccache creates a per-process Unix socket under TMPDIR;
            # private source-capture paths can exceed macOS's SUN_LEN limit.
            # Keep the persistent server cache and the private compiler scratch.
            "SCCACHE_CLIENT_SIDE": "0",
            "CC": config["clang"], "CXX": str(Path(config["clang"]).with_name("clang++")),
            "AR": str(Path(config["clang"]).with_name("ar")),
            "RANLIB": str(Path(config["clang"]).with_name("ranlib"))}


def log_hash(path):
    path = Path(path)
    if path.stat().st_size == 0:
        require(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), "empty log is not original")
        return hashlib.sha256(b"").hexdigest()
    return digest(path)


def run(argv, root, env, log, *, data_stdout=False):
    started = time.time()
    with Path(log).open("xb") as stream, Path(str(log) + ".stderr").open("xb") as errors:
        child = subprocess.run(argv, cwd=root, env=env, stdout=stream,
                               stderr=errors if data_stdout else subprocess.STDOUT)
    value = {"argv": argv, "cwd": str(root), "environment": env, "started_unix": started,
             "finished_unix": time.time(), "natural_exit": child.returncode,
             "log": str(log), "log_sha256": log_hash(log),
             "stderr": str(log) + ".stderr", "stderr_sha256": log_hash(str(log) + ".stderr")}
    save(Path(log).with_suffix(".record.json"), value)
    require(child.returncode == 0, "local native child failed: " + str(log))
    return value


def validate_config(root, config):
    require(Path(__file__).resolve() == root / "scripts/native_js_local_unit.py"
            and Path(custody.__file__).resolve() == root / "scripts/native_sdk_source_custody.py",
            "local native intake requires fixed repository-owned producer/source custody code")
    require(sys.platform == "darwin" and platform.machine() in HOSTS, "local N-API requires current macOS host")
    require(sys.version_info[:2] == (3, 12), "local N-API owner requires Python3.12")
    require(set(config) == {"python", "cargo", "rustc", "rustdoc", "node", "clang", "ld", "codesign", "sdk", "developer_dir"}, "tool configuration is not exact")
    require(Path(config["python"]).resolve() == Path(sys.executable).resolve(), "Python owner differs")
    node = shutil.which("node", path=tool_path(config))
    require(node and Path(config["node"]) == Path(node).resolve(strict=True), "Node tool differs from the actual local recipe")
    toolchain = Path.home() / ".rustup/toolchains" / ("1.93.1-" + HOSTS[platform.machine()]) / "bin"
    require(all(Path(config[key]) == toolchain / key for key in ("cargo", "rustc", "rustdoc")), "Rust tools do not name the pinned stock toolchain")
    developer = Path(config["developer_dir"])
    require(developer.resolve(strict=True) == developer, "developer directory is not canonical")
    tool = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    require(Path(config["clang"]) == tool / "clang" and Path(config["ld"]) == tool / "ld"
            and config["codesign"] == "/usr/bin/codesign", "local native tools differ from stock Apple tools")
    sdk = developer / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    require(Path(config["sdk"]) == sdk and sdk.resolve(strict=True) == sdk, "macOS SDK is not canonical")
    require(tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"] == "1.93.1", "workspace Rust toolchain differs")


def current_consumed(root, metadata, before, receipts):
    """Re-capture exact graph membership, then compare only admitted consumed inputs."""
    current = custody.capture(metadata, root, source_digest, PACKAGE)
    return custody.consumed_source_projection(metadata, root, before, current, receipts, PACKAGE)


def clone(source, output):
    before = regular(source); source_sha = digest(source)
    require(not os.path.lexists(output), "artifact output already exists")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.clonefile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
    libc.clonefile.restype = ctypes.c_int
    require(libc.clonefile(os.fsencode(source), os.fsencode(output), 0) == 0, "artifact COW retention failed")
    held = regular(output, single=True)
    require((held.st_dev, held.st_ino) != (before.st_dev, before.st_ino)
            and digest(source) == source_sha and digest(output) == source_sha, "retained artifact differs/aliases emitted original")
    return source_sha


def check_child(receipt, argv, root, env, log):
    require(set(receipt) == {"argv", "cwd", "environment", "started_unix", "finished_unix", "natural_exit",
                             "log", "log_sha256", "stderr", "stderr_sha256"}
            and receipt["argv"] == argv and receipt["cwd"] == str(root) and receipt["environment"] == env
            and type(receipt["natural_exit"]) is int and receipt["natural_exit"] == 0
            and type(receipt["started_unix"]) in {int, float}
            and type(receipt["finished_unix"]) in {int, float}
            and 0 < receipt["started_unix"] <= receipt["finished_unix"]
            and receipt["log"] == str(log) and receipt["stderr"] == str(log) + ".stderr",
            "actual child command/environment/terminal/log relationship differs")
    require(log_hash(log) == receipt["log_sha256"]
            and log_hash(str(log) + ".stderr") == receipt["stderr_sha256"]
            and load(Path(log).with_suffix(".record.json")) == receipt,
            "actual child immutable log/sidecar differs")


def check_probe(proof, selected_policy):
    require(set(proof) == {"abi_version", "exports", "forbidden", "required_exports", "required_results",
                          "signing_independent_emitted", "signing_independent_artifact"}
            and type(proof["abi_version"]) is int and proof["abi_version"] == 31 and proof["forbidden"] == []
            and proof["required_exports"] == selected_policy["required"]
            and proof["required_results"] == selected_policy["required_results"]
            and all(type(value) is int for value in proof["required_results"].values())
            and isinstance(proof["exports"], list) and proof["exports"]
            and all(isinstance(name, str) for name in proof["exports"])
            and proof["exports"] == sorted(set(proof["exports"]))
            and set(selected_policy["required"]) <= set(proof["exports"])
            and not any(name in selected_policy["forbidden"]
                        or name.startswith("connect_norito_" + "offline_cash_") for name in proof["exports"])
            and isinstance(proof["signing_independent_emitted"], str)
            and re.fullmatch(r"[0-9a-f]{64}", proof["signing_independent_emitted"])
            and proof["signing_independent_emitted"] == proof["signing_independent_artifact"],
            "real N-API export/ABI/derived code probe differs")


def check_record(record, root, output):
    local_policy(record.get("artifact_scope"), record.get("cargo_profile"))
    require(record.get("schema") == RECORD_SCHEMA and record.get("release_qualified") is False
            and record.get("passed") is True and record.get("source_root") == str(root)
            and record.get("build_provenance_version") == 4, "local producer record scope differs")
    require(type(record.get("started_unix")) in {int, float}
            and type(record.get("finished_unix")) in {int, float}
            and 0 < record["started_unix"] <= record["finished_unix"], "actual Cargo timing is absent")
    target = Path(record["target_dir"])
    build_directory(root, target, output)
    validate_config(root, record["config"])
    require(record["tools"] == tool_inputs(root, record["config"]), "current exact tool/code/SDK policy differs")
    require(record["environment"] == environment(root, record["config"], output), "native child environment differs")
    metadata = load(output / "metadata.json", record["metadata_sha256"])
    messages_path = output / "artifacts.jsonl"
    require(digest(messages_path) == record["artifacts_sha256"]
            and log_hash(output / "build.log") == record["build_log_sha256"], "actual Cargo JSON/log changed")
    messages = custody.cargo_messages(messages_path.read_text(), duplicates)
    row, _ = artifact(messages, root, target, authenticate_file=False)
    require(row == record["cargo_artifact"] and record["build_command"] == expected_build(root, target)
            and type(record["natural_exit"]) is int and record["natural_exit"] == 0, "actual build natural terminal or identity differs")
    require(record["stream_compiler_artifacts"] == [item for item in messages if item.get("reason") == "compiler-artifact"]
            and record["stream_errors"] == [], "retained live compiler JSON differs from natural completed stream")
    terminal = load(output / "build-terminal.json", record["build_terminal_sha256"])
    require(terminal and terminal.get("passed") is False
            and all(record.get(key) == value for key, value in terminal.items() if key != "passed"),
            "original actual Cargo terminal was rewritten or relabelled")
    require(record["broad_source_diagnostic"] == sorted(name for name in record["source_before"].keys() | record["source_after"].keys()
            if record["source_before"].get(name) != record["source_after"].get(name)), "broad original/current source diagnostic is relabelled")
    custody.verify_dep_info(messages, record["dep_info"], root, record["source_before"], target, output / "dep-info", source_digest)
    consumed = current_consumed(root, metadata, record["source_before"], record["dep_info"])
    require(consumed == record["consumed_inputs"] and record["policy"] == policy(root), "current consumed input/policy inventory differs")
    require(digest(output / "emitted-original.dylib") == record["emitted_sha256"]
            and digest(output / FILENAME) == record["artifact_sha256"], "retained N-API bytes differ")
    regular(output / "emitted-original.dylib", single=True); regular(output / FILENAME, single=True)
    env = record["environment"]; config = record["config"]
    metadata_command = [config["cargo"], "metadata", "--locked", "--offline", "--format-version=1", "--filter-platform", HOSTS[platform.machine()]]
    check_child(record["metadata_receipt"], metadata_command, root, env, output / "metadata.json")
    check_child(record["sign"], [config["codesign"], "--force", "--sign", "-", str(output / FILENAME)], root, env, output / "codesign.log")
    probe_command = [config["node"], str(root / "javascript/iroha_js/scripts/probe-local-native-unit.mjs"),
                     str(output / FILENAME), str(output / "emitted-original.dylib"), json.dumps(record["policy"], sort_keys=True)]
    check_child(record["probe"], probe_command, root, env, output / "probe.json")
    require(record["metadata_receipt"]["finished_unix"] <= record["started_unix"]
            and record["finished_unix"] <= record["sign"]["started_unix"]
            and record["sign"]["finished_unix"] <= record["probe"]["started_unix"]
            and record["probe"]["finished_unix"] <= record["producer_finished_unix"], "actual native child order differs")
    proof = load(output / "probe.json")
    require(proof == record["probe_result"], "actual N-API probe bytes changed")
    check_probe(proof, record["policy"])
    return record


def verify(root, output, producer_sha):
    require(root.resolve(strict=True) == root, "source root differs")
    artifact_directory(root, output, create=False)
    manifest = load(output / MANIFEST)
    require(set(manifest) == {"schema", "artifact_scope", "build_provenance_version", "cargo_profile",
                              "platform", "source_root", "producer_record_sha256", "artifact_sha256"}
            and manifest["schema"] == SCHEMA and manifest["artifact_scope"] == "local-unit"
            and manifest["build_provenance_version"] == 4 and manifest["cargo_profile"] == "debug"
            and manifest["platform"] == "darwin-" + ("arm64" if platform.machine() == "arm64" else "x64")
            and manifest["source_root"] == str(root) and manifest["producer_record_sha256"] == producer_sha,
            "local-unit manifest is not exact")
    record = check_record(load(output / "producer-record.json", producer_sha), root, output)
    require(record["artifact_sha256"] == manifest["artifact_sha256"], "local manifest names different bytes")
    return {"schema": SCHEMA, "artifact_scope": "local-unit", "artifact_sha256": record["artifact_sha256"],
            "artifact_path": str(output / FILENAME), "build_provenance_version": 4, "verified": True}


def produce(root, target, output, config, acknowledge):
    require(acknowledge, "local native recipe acknowledgement required")
    local_policy("local-unit", os.environ.get("IROHA_JS_NATIVE_BUILD_PROFILE", "debug"))
    require(root.resolve(strict=True) == root, "source root differs")
    build_directory(root, target, output)
    artifact_directory(root, output, create=True)
    validate_config(root, config); tools = tool_inputs(root, config)
    output.mkdir(mode=0o700); (output / "dep-info").mkdir(mode=0o700)
    (output / "temporary").mkdir(mode=0o700)
    env = environment(root, config, output)
    command = [config["cargo"], "metadata", "--locked", "--offline", "--format-version=1",
               "--filter-platform", HOSTS[platform.machine()]]
    metadata_receipt = run(command, root, env, output / "metadata.json", data_stdout=True)
    metadata = load(output / "metadata.json")
    before = custody.capture(metadata, root, source_digest, PACKAGE)
    record = {"schema": RECORD_SCHEMA, "artifact_scope": "local-unit", "cargo_profile": "debug",
              "build_provenance_version": 4, "release_qualified": False, "passed": False,
              "source_root": str(root), "target_dir": str(target), "source_before": before,
              "config": config, "environment": env, "tools": tools,
              "metadata_sha256": digest(output / "metadata.json"), "policy": policy(root),
              "metadata_receipt": metadata_receipt,
              "build_command": expected_build(root, target), "started_unix": time.time(),
              "stream_compiler_artifacts": [], "stream_errors": []}
    with (output / "artifacts.jsonl").open("xb") as messages, (output / "build.log").open("xb") as errors:
        child = subprocess.Popen(record["build_command"], cwd=root, env=env, stdout=subprocess.PIPE, stderr=errors)
        # Preserve actual emitted JSON during the stream. Do not inspect top-level
        # aliases/dep-info until Cargo naturally finishes publishing every output.
        for line in child.stdout:
            messages.write(line)
            if line.startswith(b"[cargo-fast] "):
                continue
            try:
                message = json.loads(line, object_pairs_hook=duplicates)
                if message.get("reason") == "compiler-artifact":
                    record["stream_compiler_artifacts"].append(message)
            except (ValueError, RuntimeError, AttributeError) as error:
                record["stream_errors"].append(str(error)[:4096])
        record["natural_exit"] = child.wait()
    record["finished_unix"] = time.time()
    record["artifacts_sha256"] = digest(output / "artifacts.jsonl")
    record["build_log_sha256"] = log_hash(output / "build.log")
    save(output / "build-terminal.json", record)
    record["build_terminal_sha256"] = digest(output / "build-terminal.json")
    require(record["natural_exit"] == 0, "actual Cargo child did not naturally exit zero")
    require(record["stream_errors"] == [], "actual Cargo JSON had stream errors")
    messages = custody.cargo_messages((output / "artifacts.jsonl").read_text(), duplicates)
    row, emitted = artifact(messages, root, target)
    record["cargo_artifact"] = row
    record["dep_info"] = [custody.reconcile(item, root, before, output / "dep-info", source_digest, target)
                          for item in messages if item.get("reason") == "compiler-artifact"]
    custody.verify_dep_info(messages, record["dep_info"], root, before, target, output / "dep-info", source_digest)
    after = custody.capture(metadata, root, source_digest, PACKAGE)
    record["source_after"] = after
    record["broad_source_diagnostic"] = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    record["consumed_inputs"] = custody.consumed_source_projection(metadata, root, before, after, record["dep_info"], PACKAGE)
    check_tools(tools)
    record["emitted_sha256"] = clone(emitted, output / "emitted-original.dylib")
    (output / "emitted-original.dylib").chmod(0o400)
    clone(output / "emitted-original.dylib", output / FILENAME); (output / FILENAME).chmod(0o600)
    record["sign"] = run([config["codesign"], "--force", "--sign", "-", str(output / FILENAME)], root, env, output / "codesign.log")
    helper = root / "javascript/iroha_js/scripts/probe-local-native-unit.mjs"
    record["probe"] = run([config["node"], str(helper), str(output / FILENAME), str(output / "emitted-original.dylib"),
                           json.dumps(record["policy"], sort_keys=True)], root, env, output / "probe.json", data_stdout=True)
    proof = load(output / "probe.json")
    check_probe(proof, record["policy"])
    record["probe_result"] = proof; record["artifact_sha256"] = digest(output / FILENAME)
    require(current_consumed(root, metadata, before, record["dep_info"]) == record["consumed_inputs"], "native consumed inputs changed during consumer execution")
    check_tools(tools); record["passed"] = True; record["producer_finished_unix"] = time.time()
    save(output / "producer-record.json", record)
    save(output / MANIFEST, {"schema": SCHEMA, "artifact_scope": "local-unit", "build_provenance_version": 4,
         "cargo_profile": "debug", "platform": "darwin-" + ("arm64" if platform.machine() == "arm64" else "x64"),
         "source_root": str(root), "producer_record_sha256": digest(output / "producer-record.json"),
         "artifact_sha256": record["artifact_sha256"]})
    verify(root, output, digest(output / "producer-record.json"))
    for path in output.rglob("*"):
        if path.is_file(): path.chmod(0o400)
    return output


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["produce", "verify"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--producer-sha256")
    parser.add_argument("--acknowledge-local-unit-recipe", action="store_true")
    args = parser.parse_args()
    try:
        if args.mode == "verify":
            require(args.producer_sha256, "producer pin is mandatory")
            print(json.dumps(verify(args.root, args.output, args.producer_sha256), sort_keys=True))
        else:
            require(args.target_dir and args.config, "producer requires exact existing target/config")
            print(produce(args.root, args.target_dir, args.output, load(args.config), args.acknowledge_local_unit_recipe))
        return 0
    except (RuntimeError, OSError, KeyError, ValueError, TypeError) as error:
        print("local N-API refused: " + str(error), file=sys.stderr); return 3


if __name__ == "__main__":
    raise SystemExit(cli())
