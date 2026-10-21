#!/usr/bin/env python3
"""Build and qualify the native KAGEMUSHA M3 candidate on a shared macOS host.

Requires Python 3.10+, Cargo, the repository toolchain and macOS vm_stat/sysctl/
pmset. No signing inputs or network access are used. All output must go to an
untracked directory (normally target/qualification). No process is interrupted
or killed. RAYON_NUM_THREADS and M3_SEED are test-only controls of the child.

prepare builds the test executable and binds it to source/compiler provenance.
run executes the predeclared three-block schedule, retaining every raw attempt.
summarize can recompute verdicts without rerunning proofs. Qualification uses
observed values only; calibration never normalizes a failure into a pass.
Blocks of the same configuration require an intervening configuration batch
with an actually launched measured child; skipped batches and failed launches
do not provide separation. This does not require a valid intervening sample.
Each proof specimen must match the scheduled process seed and sample index;
fixture derivation never replaces the prover's fresh hedged randomness.
Native generated identity is admitted only after the maintained Rust source
snapshot, exact Cargo output, host target and executable identity agree. This
also binds the generator's wider prerequisites during component qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import re
import shlex
import shutil
import statistics
import stat
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python3.10 uses the already pinned scripts dependency.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = {
    f"{kind}-{workers}": {"kind": kind, "workers": workers, "test": test, "gate": gate}
    for kind, test, gate in (
        ("q_chips", "g3_6_q_leaf_proof", "G3.6/q_leaf_chips"),
        ("q_exact", "g3_6_q_exact_shape_proof", "G3.6/q_exact_shape"),
        ("a_chips", "g3_7_a_load_proof", "G3.7/a_imt_load"),
        ("a_exact", "g3_7_a_exact_shape_proof", "G3.7/a_exact_shape"),
    )
    for workers in (1, 4)
}
PREFIX = "M3_GATE_JSON "
GIB = 1 << 30
SOURCE_POLICY = "cargo-local-input-closure-native-identity-v1"
MEMORY_ACTIVITY_POLICY = "unchanged-compressions-pageouts-swapouts;monotonic-swapins"
QUIET_MEMORY_COUNTERS = ("Compressions", "Pageouts", "Swapouts")
PROBES = {
    "pressure": ["sysctl", "-n", "kern.memorystatus_vm_pressure_level"],
    "vm": ["vm_stat"], "power": ["pmset", "-g", "custom"],
    "source": ["pmset", "-g", "batt"], "load": ["sysctl", "-n", "vm.loadavg"],
}


def command(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run to natural completion; never send timeout signals to build workers."""
    return subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, **kwargs)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def file_hash(path: Path) -> str:
    """Hash one unchanged regular file without following its final symlink."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        opened = os.fstat(source.fileno())
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
        finished = os.fstat(source.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
    if len({fields(value) for value in (before, opened, finished, path.lstat())}) != 1:
        raise ValueError(f"file changed while hashing: {path}")
    return digest.hexdigest()


def local_path(value: str | Path, *, missing: bool = False) -> Path:
    """Validate every lexical component before normalizing parent traversals."""
    path = Path(value)
    relative = path.relative_to(ROOT) if path.is_absolute() else path
    parts = []
    for part in relative.parts:
        if part == "..":
            if not parts:
                raise ValueError(f"input leaves checkout: {value}")
            parts.pop()
            continue
        if part == ".":
            continue
        parts.append(part)
        current = ROOT.joinpath(*parts)
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if missing:
                continue
            raise ValueError(f"missing source input: {value}") from None
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlinked source input: {value}")
    return ROOT.joinpath(*parts)


def scan_local_root(name: str) -> dict[str, str]:
    """Include ignored package files; only root build/admin directories are excluded."""
    root = local_path(name)
    if not root.is_dir():
        raise ValueError(f"local source root is not a directory: {name}")
    result = {}
    def unavailable(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unavailable):
        base = Path(directory)
        for child in list(dirs):
            path = local_path(base / child)
            if child in ("target", ".git") and base == root:
                dirs.remove(child)
        for child in files:
            path = local_path(base / child)
            result[path.relative_to(ROOT).as_posix()] = "file:" + file_hash(path)
    return result


def source_manifest(roots: list[str] | tuple = ()) -> dict[str, str]:
    """Snapshot Git entries plus complete local packages, including ignored files."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, check=True,
    )
    manifest = {}
    for raw in sorted(set(result.stdout.split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = ROOT / name
        # Unconsumed Git symlinks may remain in the broad diagnostic snapshot.
        # Selected package and compiler inputs must pass local_path instead.
        if path.is_symlink():
            data = "symlink:" + os.readlink(path)
        elif path.is_file():
            data = "file:" + file_hash(local_path(path))
        else:
            data = "deleted"
        manifest[name] = data
    for root in roots:
        manifest.update(scan_local_root(root))
    return manifest


def cargo_metadata() -> dict:
    result = command(["cargo", "metadata", "--locked", "--offline", "--format-version=1"])
    result.check_returncode()
    return json.loads(result.stdout)


def metadata_roots(metadata: dict) -> list[str]:
    roots = set()
    for package in metadata["packages"]:
        if package["source"] is None:
            manifest = local_path(package["manifest_path"])
            file_hash(manifest)
            root = manifest.parent.relative_to(ROOT).as_posix()
            if root == ".":
                raise ValueError("root package requires an explicit bounded source scan")
            roots.add(root)
    if (ROOT / ".cargo").exists():
        roots.add(".cargo")
    return sorted(roots)


def native_admin_watchers() -> dict[str, str | None]:
    """Bind the two Git census controls without treating them as Rust inputs."""
    values = {}
    for name in (".git/index", ".git/info/exclude"):
        path = local_path(name, missing=True)
        values[name] = file_hash(path) if path.exists() else None
    return values


def native_audit_module():
    """Reuse the maintained Rust snapshot evaluator, not a second source census."""
    path = local_path("scripts/audit_native_source_inputs.py")
    spec = importlib.util.spec_from_file_location("m3_native_source_audit", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load maintained native source audit")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_host_target() -> dict:
    """Derive Cargo's native qualification target from the pinned host compiler."""
    version = command(["rustc", "-Vv"])
    version.check_returncode()
    hosts = re.findall(r"^host: ([a-zA-Z0-9_.-]+)$", version.stdout, re.MULTILINE)
    if len(hosts) != 1:
        raise ValueError("missing or ambiguous native rustc host")
    result = command(["rustc", "--print", "cfg", "--target", hosts[0]])
    result.check_returncode()
    fields = {}
    for name in ("target_arch", "target_os", "target_pointer_width", "target_endian"):
        values = re.findall(rf'^{name}="([a-zA-Z0-9_]+)"$', result.stdout, re.MULTILINE)
        if len(values) != 1:
            raise ValueError(f"missing or ambiguous native rustc cfg: {name}")
        fields[name] = values[0]
    if (fields["target_arch"] not in ("aarch64", "x86_64") or fields["target_os"] != "macos" or
            fields["target_pointer_width"] != "64" or fields["target_endian"] != "little"):
        raise ValueError("M3 resource qualification requires a supported native macOS target")
    return {"triple": hosts[0], "cfg": fields, "cfg_stdout": result.stdout,
            "environment": {"TARGET": hosts[0], **{
                "CARGO_CFG_" + name.upper(): value
                for name, value in fields.items()
            }}}


def native_identity_source(digest: str, target: dict) -> str:
    """The exact maintained build.rs output for a complete supported native build."""
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("malformed maintained native source digest")
    values = ", ".join(str(value) for value in bytes.fromhex(digest))
    return ("// Generated from actual workspace inputs, not an environment digest.\n"
            f"pub(super) const CURRENT_NATIVE_SOURCE_DIGEST: [u8; 32] = [{values}];\n"
            "pub(super) const NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;\n"
            "pub(super) const BUILTIN_TARGET_SUPPORTED: bool = true;\n"
            "#[allow(dead_code)]\n"
            f"pub(super) const NATIVE_SOURCE_TARGET: &str = {json.dumps(target['triple'])};\n")


def native_output_inventory(out: Path) -> dict[str, str]:
    """Allow precisely one regular output, with no skipped subdirectories."""
    entries = list(local_path(out).iterdir())
    if len(entries) != 1 or entries[0].name != "native_source_identity.rs":
        raise ValueError("native OUT_DIR contains an unverified generated output")
    path = local_path(entries[0])
    return {path.relative_to(ROOT).as_posix(): "file:" + file_hash(path)}


def native_snapshot(tool: Path, record: dict, record_sha256: str) -> tuple[str, list[str]]:
    """Check evaluator, helper and exact selected sha2 custody around each scan."""
    audit = native_audit_module()
    if (local_path(record["helperPath"]) != audit.HELPER or
            local_path(record["driverPath"]) != audit.DRIVER or
            local_path(record["sha2Path"]) != Path(record["sha2Path"])):
        raise ValueError("native snapshot evaluator has foreign input paths")
    protected = {"helper": (audit.HELPER, record["helperSha256"]),
                 "driver": (audit.DRIVER, record["driverSha256"]),
                 "binary": (tool, record["binarySha256"]),
                 "sha2": (Path(record["sha2Path"]), record["sha2Sha256"])}
    for path, expected in protected.values():
        if file_hash(path) != expected:
            raise ValueError("native snapshot evaluator input changed")
    record_path = tool.with_name("source-snapshot-build.json")
    if file_hash(record_path) != record_sha256:
        raise ValueError("native snapshot evaluator record changed")
    actual_record = json.loads(record_path.read_text())
    if actual_record != record or Path(record["binaryPath"]) != tool:
        raise ValueError("native snapshot evaluator record changed")
    digest, watched = audit.actual_snapshot(tool)
    paths = sorted(local_path(path, missing=True).relative_to(ROOT).as_posix() for path in watched)
    for path, expected in protected.values():
        if file_hash(path) != expected:
            raise ValueError("native snapshot evaluator input changed during scan")
    if file_hash(record_path) != record_sha256 or json.loads(record_path.read_text()) != record:
        raise ValueError("native snapshot evaluator record changed during scan")
    return digest, paths


def capture_native_source(metadata: dict, artifacts: list[dict], build_scripts: list[dict], output: Path) -> dict | None:
    """Admit only the selected plonk generator and its maintained prerequisites."""
    packages = {package["id"]: package for package in metadata["packages"]}
    plonk_ids = {key for key, package in packages.items()
                 if package["source"] is None and package["name"] == "iroha_plonk" and
                 local_path(package["manifest_path"]) == ROOT / "crates/iroha_plonk/Cargo.toml"}
    selected = [item for item in build_scripts if item["package_id"] in plonk_ids]
    compiled = {item["package_id"] for item in artifacts if item["package_id"] in plonk_ids}
    if not compiled and not selected:
        return None
    if len(plonk_ids) != 1 or compiled != plonk_ids or not selected:
        raise ValueError("native identity lacks exact selected plonk build")
    directory = output / "native-source-evaluator"
    directory.mkdir()
    audit = native_audit_module()
    tool = audit.build_snapshot_tool(directory, [*artifacts, *build_scripts])
    record = json.loads(tool.with_name("source-snapshot-build.json").read_text())
    record_sha256 = file_hash(tool.with_name("source-snapshot-build.json"))
    digest, watched = native_snapshot(tool, record, record_sha256)
    result = {"policy": "complete-native-source-identity-v1", "tool": str(tool), "evaluator": record,
              "evaluator_record_sha256": record_sha256,
              "source_digest": digest, "watched": watched, "admin_watchers": native_admin_watchers(),
              "target": native_host_target(), "builds": []}
    required = {"crates/iroha_plonk/build.rs", "crates/iroha_plonk/build_support/source_identity.rs",
                "crates/iroha_plonk/src/keys/keygen/builtin/generated.rs", "scripts/audit_native_source_inputs.py",
                "scripts/native_source_snapshot.rs", *result["admin_watchers"]}
    if not required.issubset(watched):
        raise ValueError("native snapshot omits mandatory generator or admin watchers")
    expected_source = native_identity_source(digest, result["target"])
    seen = set()
    for item in selected:
        out = local_path(item["out_dir"])
        if out in seen or out.name != "out" or not out.is_relative_to(ROOT / "target"):
            raise ValueError("native identity has foreign or duplicate Cargo OUT_DIR")
        seen.add(out)
        identity = local_path(out / "native_source_identity.rs")
        original = identity.read_text()
        if original != expected_source:
            raise ValueError("native generated identity differs from complete current snapshot and target")
        identity_hash = file_hash(identity)
        if hashlib.sha256(original.encode()).hexdigest() != identity_hash:
            raise ValueError("native generated identity changed while reading")
        expected_files = {identity.relative_to(ROOT).as_posix(): "file:" + identity_hash}
        if native_output_inventory(out) != expected_files:
            raise ValueError("native OUT_DIR contains an unverified generated output")
        rescan = local_path(out / "native-source-rescan-required", missing=True)
        if rescan.exists():
            raise ValueError("intentionally absent native rescan watcher exists")
        build_output = local_path(out.parent / "output")
        text = build_output.read_text()
        declared, environment = set(), set()
        for line in text.splitlines():
            directive = line.removeprefix("cargo::").removeprefix("cargo:")
            if directive.startswith("rerun-if-changed="):
                raw = Path(directive.partition("=")[2])
                path = local_path(raw, missing=True)
                if not raw.is_absolute() or raw != path:
                    raise ValueError("native build watcher is not an exact canonical path")
                declared.add(path.relative_to(ROOT).as_posix())
            elif directive.startswith("rerun-if-env-changed="):
                environment.add(directive.partition("=")[2])
        if declared != set(watched) | {rescan.relative_to(ROOT).as_posix()}:
            raise ValueError("native build watchers differ from maintained snapshot and exact rescan marker")
        if environment != set(result["target"]["environment"]):
            raise ValueError("native build environment declarations differ from native target inputs")
        output_hash = file_hash(build_output)
        if hashlib.sha256(text.encode()).hexdigest() != output_hash:
            raise ValueError("native build output changed while reading")
        result["builds"].append({"package_id": item["package_id"], "out_dir": str(out),
                                 "identity": str(identity), "identity_sha256": identity_hash,
                                 "rescan": str(rescan), "output": str(build_output),
                                 "output_sha256": output_hash, "inventory": expected_files})
    if native_snapshot(tool, record, record_sha256) != (digest, watched) or native_admin_watchers() != result["admin_watchers"]:
        raise ValueError("native source changed during generated-input audit")
    return recheck_native_source(result)


def recheck_native_source(value: dict | None) -> dict:
    """Recheck exact generated outputs, absent watchers and current source identity."""
    if value is None:
        return {}
    if value.get("policy") != "complete-native-source-identity-v1":
        raise ValueError("unknown generated native input policy")
    def check_outputs():
        if native_admin_watchers() != value["admin_watchers"]:
            raise ValueError("native Git admin watcher changed")
        for item in value["builds"]:
            if local_path(item["rescan"], missing=True).exists():
                raise ValueError("intentionally absent native rescan watcher exists")
            if (file_hash(local_path(item["identity"])) != item["identity_sha256"] or
                    file_hash(local_path(item["output"])) != item["output_sha256"] or
                    native_output_inventory(Path(item["out_dir"])) != item["inventory"]):
                raise ValueError("native generated input or build output changed")
    check_outputs()
    if native_snapshot(Path(value["tool"]), value["evaluator"], value["evaluator_record_sha256"]) != (value["source_digest"], value["watched"]):
        raise ValueError("native source identity changed")
    check_outputs()
    return value


def cargo_configuration() -> dict:
    """Pin Cargo's config hierarchy, including absent optional candidates.

    Both filename spellings are retained even where Cargo gives `config`
    precedence. Compiler overrides and Cargo-provided environment require a
    separately reviewed tool disposition; this M3 profile admits neither.
    Only hashes are retained, never configuration contents or credentials.
    """
    home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if not home.is_absolute():
        home = ROOT / home
    directories = {base / ".cargo" for base in (ROOT, *ROOT.parents)} | {home}
    result = {}
    for directory in sorted(directories):
        for name in ("config", "config.toml"):
            path = directory / name
            # Inspect each lexical ancestor so a symlink cannot conceal an
            # alternate configuration, even if its final leaf is absent.
            for parent in (*reversed(path.parents), path):
                try:
                    mode = parent.lstat().st_mode
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(mode):
                    raise ValueError(f"symlinked Cargo configuration: {path}")
            try:
                before = file_hash(path)
            except FileNotFoundError:
                result[str(path)] = None
                continue
            original = path.read_bytes()
            if hashlib.sha256(original).hexdigest() != before or file_hash(path) != before:
                raise ValueError(f"Cargo configuration changed while reading: {path}")
            config = tomllib.loads(original.decode("utf-8"))
            if "include" in config:
                raise ValueError("Cargo configuration include needs an explicit input policy")
            build = config.get("build", {})
            if not isinstance(build, dict):
                raise ValueError("malformed Cargo build configuration")
            if any(build.get(key) for key in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper")):
                raise ValueError("configured compiler/wrapper needs an explicit tool-input policy")
            if config.get("env"):
                raise ValueError("Cargo configuration environment needs an explicit tool-input policy")
            result[str(path)] = before
    return result


def tool_identity() -> dict:
    """Bind selected Rust tools and build controls, without claiming OS closure."""
    tools = {"cargo_configuration": cargo_configuration()}
    for name in ("bash", "git", "python3", "cargo", "rustc", "rustup"):
        selected = shutil.which(name)
        if selected is None:
            raise ValueError(f"missing build tool: {name}")
        path = Path(selected).resolve(strict=True)
        tools["launcher:" + name] = {"path": str(path), "sha256": file_hash(path)}
    interpreter = Path(sys.executable).resolve(strict=True)
    tools["python"] = {"path": str(interpreter), "sha256": file_hash(interpreter)}
    wrapper = shutil.which("sccache")
    tools["automatic_sccache"] = None
    if wrapper:
        path = Path(wrapper).resolve(strict=True)
        tools["automatic_sccache"] = {"path": str(path), "sha256": file_hash(path)}
    for name in ("cargo", "rustc"):
        selected = command(["rustup", "which", name])
        selected.check_returncode()
        path = Path(selected.stdout.strip()).resolve(strict=True)
        version = command([str(path), "-Vv"])
        version.check_returncode()
        tools[name] = {"path": str(path), "sha256": file_hash(path), "version": version.stdout}
    tools["environment"] = {key: os.environ.get(key) for key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO",
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN",
        "CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "CARGO_FAST_TARGET_ROOT",
        "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "DOCS_RS", "NORITO_CHECK_BINDINGS_SYNC", "NORITO_SKIP_BINDINGS_SYNC",
        "ENABLE_CABAC", "ENABLE_TRELLIS",
    )}
    if any(tools["environment"][key] for key in (
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    )):
        raise ValueError("custom compiler/wrapper needs an explicit tool-input policy")
    if os.environ.get("NORITO_CHECK_BINDINGS_SYNC") is not None and os.environ.get("NORITO_SKIP_BINDINGS_SYNC") is None:
        raise ValueError("bindings-sync subprocess needs an explicit tool-input policy")
    return tools


def selected_sources(manifest: dict, scope: dict | None) -> dict:
    if scope is None:
        return manifest
    if scope.get("kind") not in ("cargo_component", "whole_checkout"):
        raise ValueError("unknown source scope")
    for name in scope["required_inputs"]:
        if not manifest.get(name, "").startswith("file:"):
            raise ValueError(f"mandatory compiler input was not captured: {name}")
    selected = {name: value for name, value in manifest.items()
                if scope["kind"] == "whole_checkout" or name in scope["files"] or
                any(name == root or name.startswith(root + "/") for root in scope["roots"])}
    for name, value in selected.items():
        if not value.startswith("symlink:"):
            continue
        # The maintained native census binds this exact shipped-output link's
        # spelling without following its target, avoiding a binary self-hash.
        if (scope.get("native_source") is not None and name == "IrohaSwift/NoritoBridge.xcframework" and
                value == "symlink:../dist/NoritoBridge.xcframework"):
            local_path("IrohaSwift")
            continue
        raise ValueError("selected source contains an unclassified symlink")
    return selected


def manifest_digest(manifest: dict) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_digest(scope: dict | None = None) -> str:
    """Rescan the same roots, required inputs, metadata and tools at runtime."""
    if scope is None:
        raise ValueError("candidate lacks a captured Cargo source scope")
    manifest = source_manifest(scope["roots"])
    # Native watchers can bind ignored files in workspace packages that this
    # component does not compile. Preparation must still capture them before
    # building; runtime recensus must retain those exact required inputs too.
    for name in scope["required_inputs"]:
        if name not in manifest:
            manifest[name] = "file:" + file_hash(local_path(name))
    selected = selected_sources(manifest, scope)
    selected["@cargo_metadata"] = manifest_digest(cargo_metadata())
    selected["@tools"] = manifest_digest(tool_identity())
    selected["@build_environment"] = manifest_digest({key: os.environ.get(key) for key in scope["build_environment"]})
    selected["@generated_native_inputs"] = manifest_digest(recheck_native_source(scope.get("native_source")))
    selected["@cargo_build_inputs"] = manifest_digest(recheck_build_inputs(scope))
    return manifest_digest(selected)


def recheck_build_inputs(scope: dict) -> dict:
    """Keep retained compiler dependency and build-output originals bound."""
    values = {}
    for name, record in scope["depfiles"].items():
        values[name] = file_hash(local_path(name))
        if values[name] != record["sha256"]:
            raise ValueError("captured compiler depfile changed")
    for record in scope["build_script_outputs"]:
        name = record["path"]
        values[name] = file_hash(local_path(name))
        if values[name] != record["sha256"]:
            raise ValueError("captured build-script output changed")
    return values


def depfile_inputs(depinfo: Path, artifact: Path, absent_watchers: set[str] = frozenset()) -> set[str]:
    """Require a rule for the exact emitted artifact, never a nearby stale .d."""
    text = depinfo.read_text().replace("\\\n", " ")
    inputs = set()
    matched = False
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        left, separator, right = line.partition(": ")
        if not separator:
            continue
        targets = [local_path(name) for name in shlex.split(left)]
        if artifact not in targets:
            continue
        matched = True
        for name in shlex.split(right):
            path = local_path(name, missing=True)
            relative = path.relative_to(ROOT).as_posix()
            if relative in absent_watchers:
                if path.exists():
                    raise ValueError("intentionally absent native rescan watcher exists")
            else:
                local_path(path)
            inputs.add(relative)
    if not matched or not inputs:
        raise ValueError(f"depfile does not bind artifact: {artifact}")
    return inputs


def component_scope(metadata: dict, artifacts: list[dict], build_scripts: list[dict] = (),
                    native_source: dict | None = None) -> dict:
    """Bind actual local artifacts and fail closed on uncovered/generated inputs."""
    packages = {package["id"]: package for package in metadata["packages"]}
    roots = {".cargo"} if (ROOT / ".cargo").exists() else set()
    files = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain",
             "scripts/cargo_fast.sh", "scripts/check_cargo_target_owner.py",
             "scripts/kagemusha_qualify.py"}
    compiled, depfiles, aliases, required = {}, {}, [], set()
    compiler_environment = {}
    script_packages = set()
    native = recheck_native_source(native_source)
    native_builds = native.get("builds", [])
    native_outputs = {item["out_dir"]: item for item in native_builds}
    native_identities = {Path(item["identity"]).relative_to(ROOT).as_posix(): item for item in native_builds}
    native_rescans = {Path(item["rescan"]).relative_to(ROOT).as_posix() for item in native_builds}
    admin = set(native.get("admin_watchers", {}))
    observed_native = set()
    if native:
        required.update(set(native["watched"]) - admin)
        files.update(("scripts/audit_native_source_inputs.py", "scripts/native_source_snapshot.rs"))
    for artifact in artifacts:
        package = packages[artifact["package_id"]]
        compiled[package["id"]] = {key: package[key] for key in ("name", "version", "source", "manifest_path")}
        if package["source"] is not None:
            continue
        manifest = local_path(package["manifest_path"])
        if artifact.get("manifest_path") and local_path(artifact["manifest_path"]) != manifest:
            raise ValueError("artifact differs from metadata manifest")
        if artifact.get("target", {}).get("kind") == ["custom-build"]:
            script_packages.add(package["id"])
        roots.add(manifest.parent.relative_to(ROOT).as_posix())
        required.add(manifest.relative_to(ROOT).as_posix())
        if not artifact.get("filenames"):
            raise ValueError("local artifact has no emitted files")
        for filename in artifact["filenames"]:
            path = local_path(filename)
            artifact_hash = file_hash(path)
            stem = path.stem.removeprefix("lib") if path.suffix in (".rlib", ".rmeta", ".dylib", ".so") else path.stem
            depinfo = path.with_name(stem + ".d")
            actual = path
            if path.name == "build-script-build":
                matches = [p for p in path.parent.glob("build_script_build-*")
                           if p.suffix == "" and p.with_suffix(".d").is_file() and file_hash(local_path(p)) == artifact_hash]
                if len(matches) != 1:
                    raise ValueError("missing or ambiguous exact build-script alias")
                actual = matches[0]
                depinfo = actual.with_suffix(".d")
                aliases.append({"alias": str(path), "actual": str(actual), "sha256": artifact_hash})
            depinfo = local_path(depinfo)
            depinfo_hash = file_hash(depinfo)
            owner_builds = [item for item in native_builds if item["package_id"] == package["id"]]
            native_consumer = (bool(owner_builds) and artifact.get("target", {}).get("kind") == ["lib"] and
                               artifact.get("target", {}).get("name") == "iroha_plonk")
            absent = native_rescans if owner_builds else set()
            inputs = depfile_inputs(depinfo, actual, absent)
            generated = sorted(name for name in inputs if name.startswith("target/"))
            admitted = {name for name in generated if name in native_identities and
                        native_consumer and native_identities[name]["package_id"] == package["id"]}
            if set(generated) - admitted - absent:
                raise ValueError(f"generated compiler input has no verified disposition: {generated}")
            observed_native.update(admitted)
            required.update(inputs - admitted - absent - admin)
            derived_environment = {}
            for line in depinfo.read_text().splitlines():
                if not line.startswith("# env-dep:"):
                    continue
                name, separator, value = line.removeprefix("# env-dep:").partition("=")
                expected = value if separator else None
                if name == "OUT_DIR" and native_consumer:
                    if expected not in {item["out_dir"] for item in owner_builds}:
                        raise ValueError("native compiler OUT_DIR differs from selected Cargo output")
                    derived_environment[name] = expected
                elif name == "CARGO_MANIFEST_DIR":
                    if expected != str(manifest.parent):
                        raise ValueError("depfile has foreign manifest environment")
                    derived_environment[name] = expected
                elif name == "CARGO_TARGET_TMPDIR":
                    if expected is None or not local_path(expected, missing=True).is_relative_to(ROOT / "target"):
                        raise ValueError("depfile has foreign temporary directory")
                    derived_environment[name] = expected
                elif name.startswith("CARGO_"):
                    raise ValueError(f"derived compiler environment has no disposition: {name}")
                else:
                    if os.environ.get(name) != expected:
                        raise ValueError(f"compiler environment differs: {name}")
                    compiler_environment[name] = expected
            if admitted and (len(admitted) != 1 or derived_environment.get("OUT_DIR") !=
                             native_identities[next(iter(admitted))]["out_dir"]):
                raise ValueError("native generated input lacks its exact compiler OUT_DIR binding")
            if file_hash(depinfo) != depinfo_hash:
                raise ValueError("compiler depfile changed during capture")
            depfiles[str(depinfo)] = {"sha256": depinfo_hash, "inputs": sorted(inputs),
                                     "derived_environment": derived_environment}
    if not any(package["name"] == "iroha_plonk_gadgets" for package in compiled.values()):
        raise ValueError("component artifact set omits its measurement driver")
    if observed_native != set(native_identities):
        raise ValueError("selected native generated identity is absent from exact compiler depfiles")
    outputs, environment = [], compiler_environment
    observed_scripts = set()
    for item in build_scripts:
        package = packages[item["package_id"]]
        if package["source"] is not None:
            continue
        if package["id"] not in script_packages:
            raise ValueError("build script lacks captured compiler artifact")
        observed_scripts.add(package["id"])
        out = local_path(item["out_dir"])
        output = local_path(out.parent / "output")
        output_hash = file_hash(output)
        native_output = native_outputs.get(str(out))
        generated = (native_output_inventory(out) if native_output else
                     scan_local_root(out.relative_to(ROOT).as_posix()))
        if native_output and native_output["package_id"] != package["id"]:
            raise ValueError("native OUT_DIR belongs to a different Cargo package")
        if generated and (native_output is None or generated != native_output["inventory"]):
            raise ValueError("local generated build output has no verified disposition")
        text = output.read_text()
        for line in text.splitlines():
            directive = line.removeprefix("cargo::").removeprefix("cargo:")
            if directive.startswith("rerun-if-changed="):
                name = directive.partition("=")[2]
                base = local_path(package["manifest_path"]).parent
                path = local_path(base / name, missing=True)
                relative = path.relative_to(ROOT).as_posix()
                if native_output and relative in native_rescans | admin:
                    # Only capture_native_source's exact rescan and two separately
                    # bound Git census controls have a non-source disposition.
                    continue
                path = local_path(path)
                if path.is_dir():
                    roots.add(path.relative_to(ROOT).as_posix())
                    required.update(scan_local_root(path.relative_to(ROOT).as_posix()))
                else:
                    required.add(path.relative_to(ROOT).as_posix())
            elif directive.startswith("rerun-if-env-changed="):
                name = directive.partition("=")[2]
                if native_output and name in native["target"]["environment"]:
                    continue  # Cargo-derived, bound to the selected host compiler.
                environment[name] = os.environ.get(name)
        if hashlib.sha256(text.encode()).hexdigest() != output_hash or file_hash(output) != output_hash:
            raise ValueError("build-script output changed during capture")
        outputs.append({"record": item, "path": str(output), "sha256": output_hash, "text": text,
                        "generated_disposition": ("exact complete native source identity" if native_output else
                                                  "empty output directory; no generated compiler inputs")})
    if observed_scripts != script_packages:
        raise ValueError("local build script lacks its executed output record")
    files.update(required)
    return {"kind": "cargo_component", "roots": sorted(roots), "files": sorted(files),
            "required_inputs": sorted(required), "packages": [compiled[key] for key in sorted(compiled)],
            "depfiles": depfiles, "build_script_aliases": aliases, "build_script_outputs": outputs,
            "build_environment": environment, "native_source": native_source}


def ignored_output(path: Path) -> Path:
    """Refuse output inside a tracked or non-ignored part of the checkout."""
    path = path.resolve()
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        result = command(["git", "check-ignore", "--quiet", str(relative / "probe.json")])
        if result.returncode:
            raise ValueError("output must be outside the checkout or in an ignored directory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_native_identity(text: str, native: dict, binary_sha256: str) -> dict:
    """Join actual executable identity to the audited generated Cargo input."""
    prefix = "M3_SOURCE_JSON "
    lines = [line[line.index(prefix) + len(prefix):] for line in text.splitlines() if prefix in line]
    if len(lines) != 1:
        raise ValueError("expected one compiled native source identity record")
    value = json.loads(lines[0])
    cfg = native["target"]["cfg"]
    expected = {"schema": "kagemusha.m3.native-source.v1", "native_source_digest": native["source_digest"],
                "binary_sha256": binary_sha256, "target_arch": cfg["target_arch"], "target_os": cfg["target_os"],
                "pointer_width": int(cfg["target_pointer_width"]), "little_endian": cfg["target_endian"] == "little"}
    if (not isinstance(value, dict) or value.keys() != expected.keys() or
            any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items())):
        raise ValueError("compiled native source identity differs from audited Cargo inputs")
    return value


def validate_retained_native_source(native: dict, outputs: list[dict]) -> None:
    """Validate complete retained evidence without consulting the live filesystem."""
    def fields(value, names, label):
        if not isinstance(value, dict) or set(value) != set(names.split()):
            raise ValueError(f"incomplete native {label} evidence")

    def digest(value):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("malformed native provenance digest")

    def path(value, *, absolute=True):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("missing native provenance path")
        result = Path(value)
        if (result.is_absolute() != absolute or str(result) != value or
                any(part in (".", "..") for part in result.parts) or value == "."):
            raise ValueError("noncanonical native provenance path")
        return result

    fields(native, "policy tool evaluator evaluator_record_sha256 source_digest watched admin_watchers target builds", "scope")
    if native["policy"] != "complete-native-source-identity-v1":
        raise ValueError("missing complete audited native source scope")
    for name in ("source_digest", "evaluator_record_sha256"):
        digest(native[name])
    admin = native["admin_watchers"]
    fields(admin, ".git/index .git/info/exclude", "admin watcher")
    for value in admin.values():
        if value is not None:
            digest(value)
    watched = native["watched"]
    if not isinstance(watched, list) or any(not isinstance(value, str) for value in watched):
        raise ValueError("missing native watch inventory")
    if watched != sorted(set(watched)):
        raise ValueError("duplicate or unordered native watch inventory")
    for value in watched:
        path(value, absolute=False)
    required = {"crates/iroha_plonk/build.rs", "crates/iroha_plonk/build_support/source_identity.rs",
                "crates/iroha_plonk/src/keys/keygen/builtin/generated.rs", "scripts/audit_native_source_inputs.py",
                "scripts/native_source_snapshot.rs", *admin}
    if not required.issubset(watched):
        raise ValueError("native watch inventory omits generator or admin inputs")

    target = native["target"]
    fields(target, "triple cfg cfg_stdout environment", "target")
    cfg = target["cfg"]
    fields(cfg, "target_arch target_os target_pointer_width target_endian", "target cfg")
    if (cfg["target_arch"] not in ("aarch64", "x86_64") or cfg["target_os"] != "macos" or
            cfg["target_pointer_width"] != "64" or cfg["target_endian"] != "little" or
            target["triple"] != cfg["target_arch"] + "-apple-darwin"):
        raise ValueError("unsupported or inconsistent native qualification target")
    if not isinstance(target["cfg_stdout"], str):
        raise ValueError("missing native compiler cfg output")
    for name, value in cfg.items():
        if re.findall(rf'^{name}="([a-zA-Z0-9_]+)"$', target["cfg_stdout"], re.MULTILINE) != [value]:
            raise ValueError("native target differs from retained compiler cfg output")
    environment = {"TARGET": target["triple"], **{"CARGO_CFG_" + key.upper(): value for key, value in cfg.items()}}
    if target["environment"] != environment:
        raise ValueError("native target environment differs from compiler cfg")

    tool = path(native["tool"])
    evaluator = native["evaluator"]
    fields(evaluator, "helperPath helperSha256 driverPath driverSha256 binaryPath binarySha256 sha2Path sha2Sha256 sha2Features command", "evaluator")
    for prefix in ("helper", "driver", "binary", "sha2"):
        path(evaluator[prefix + "Path"])
        digest(evaluator[prefix + "Sha256"])
    helper = ROOT / "crates/iroha_plonk/build_support/source_identity.rs"
    driver = ROOT / "scripts/native_source_snapshot.rs"
    sha2 = path(evaluator["sha2Path"])
    if (tool.name != "source-snapshot" or evaluator["binaryPath"] != str(tool) or
            evaluator["helperPath"] != str(helper) or evaluator["driverPath"] != str(driver) or
            not sha2.is_relative_to(ROOT / "target") or sha2.parent.name != "deps" or
            re.fullmatch(r"libsha2-[a-zA-Z0-9_-]+\.rlib", sha2.name) is None):
        raise ValueError("native evaluator has foreign input paths")
    features = evaluator["sha2Features"]
    if (not isinstance(features, list) or any(not isinstance(value, str) or not value for value in features) or
            len(set(features)) != len(features)):
        raise ValueError("missing or duplicated native evaluator dependency features")
    expected_command = ["rustc", "--edition=2024", "--crate-name", "iroha_native_source_snapshot", str(driver),
                        "--extern", "sha2=" + str(sha2), "-L", "dependency=" + str(sha2.parent), "-o", str(tool)]
    if evaluator["command"] != expected_command:
        raise ValueError("native evaluator command differs from retained inputs")

    builds = native["builds"]
    if not isinstance(builds, list) or not builds:
        raise ValueError("missing selected native generator evidence")
    if not isinstance(outputs, list):
        raise ValueError("missing retained native build output originals")
    seen, packages = set(), set()
    expected_hash = hashlib.sha256(native_identity_source(native["source_digest"], target).encode()).hexdigest()
    for item in builds:
        fields(item, "package_id out_dir identity identity_sha256 rescan output output_sha256 inventory", "generator")
        if not isinstance(item["package_id"], str) or not item["package_id"]:
            raise ValueError("missing native generator package identity")
        packages.add(item["package_id"])
        out = path(item["out_dir"])
        if out in seen or out.name != "out" or not out.is_relative_to(ROOT / "target"):
            raise ValueError("foreign or duplicate native Cargo OUT_DIR")
        seen.add(out)
        identity = out / "native_source_identity.rs"
        for name, expected in (("identity", identity), ("rescan", out / "native-source-rescan-required"),
                               ("output", out.parent / "output")):
            if path(item[name]) != expected:
                raise ValueError("native generated output path differs from selected Cargo OUT_DIR")
        for name in ("identity_sha256", "output_sha256"):
            digest(item[name])
        if (item["identity_sha256"] != expected_hash or
                item["inventory"] != {identity.relative_to(ROOT).as_posix(): "file:" + expected_hash}):
            raise ValueError("native generated output differs from complete source identity and target")
        matches = [record for record in outputs if isinstance(record, dict) and record.get("path") == item["output"]]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous retained native build output")
        retained = matches[0]
        fields(retained, "record path sha256 text generated_disposition", "build output")
        event = retained["record"]
        if (not isinstance(event, dict) or event.get("reason") != "build-script-executed" or
                event.get("package_id") != item["package_id"] or event.get("out_dir") != str(out) or
                retained["generated_disposition"] != "exact complete native source identity" or
                not isinstance(retained["text"], str)):
            raise ValueError("retained native build output differs from selected Cargo event")
        if (retained["sha256"] != item["output_sha256"] or
                hashlib.sha256(retained["text"].encode()).hexdigest() != item["output_sha256"]):
            raise ValueError("retained native build output digest differs from original text")
        declared, declared_environment = set(), set()
        for line in retained["text"].splitlines():
            directive = line.removeprefix("cargo::").removeprefix("cargo:")
            if directive.startswith("rerun-if-changed="):
                declared.add(path(directive.partition("=")[2]).relative_to(ROOT).as_posix())
            elif directive.startswith("rerun-if-env-changed="):
                declared_environment.add(directive.partition("=")[2])
        if declared != set(watched) | {(out / "native-source-rescan-required").relative_to(ROOT).as_posix()}:
            raise ValueError("retained native build watchers differ from snapshot and exact rescan marker")
        if declared_environment != set(environment):
            raise ValueError("retained native build environment differs from target inputs")
    if len(packages) != 1:
        raise ValueError("native generated outputs select different Cargo packages")


def candidate_native_reasons(candidate: dict) -> list[str]:
    """Require retained successful executable identity and its audited native scope."""
    try:
        if candidate["source_scope"].get("kind") not in ("cargo_component", "whole_checkout"):
            raise ValueError("missing captured Cargo source scope")
        native = candidate["source_scope"]["native_source"]
        validate_retained_native_source(native, candidate["source_scope"]["build_script_outputs"])
        if (not isinstance(candidate.get("binary_sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}", candidate["binary_sha256"]) is None):
            raise ValueError("missing native executable digest")
        process = candidate["native_identity_process"]
        if (type(process["code"]) is not int or process["code"] != 0 or
                not isinstance(process["stdout"], str) or not isinstance(process["stderr"], str)):
            raise ValueError("compiled native identity process did not succeed")
        parsed = parse_native_identity(process["stdout"], native, candidate["binary_sha256"])
        retained = candidate["native_identity"]
        if (not isinstance(retained, dict) or retained.keys() != parsed.keys() or
                any(type(retained[key]) is not type(item) or retained[key] != item for key, item in parsed.items())):
            raise ValueError("retained native identity differs from raw executable output")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        return [f"candidate native identity invalid: {error}"]
    return []


def prepare(output: Path, *, component: bool = False, target_slot: str = "m3b") -> None:
    output = ignored_output(output)
    candidate_path = output / "candidate.json"
    if candidate_path.exists():
        raise ValueError("candidate.json already exists; use a fresh output directory")
    metadata = cargo_metadata()
    roots = metadata_roots(metadata)
    before_tools = tool_identity()
    before_admin = native_admin_watchers()
    before_manifest = source_manifest(roots)
    before = manifest_digest(before_manifest)
    write_json(output / "cargo-metadata-before.json", metadata)
    write_json(output / "tools-before.json", before_tools)
    write_json(output / "source-before.json", before_manifest)
    argv = [
        "scripts/cargo_fast.sh", "--stable-local-metadata", "--jobs", "2", "--target-slot", target_slot, "--",
        "test", "--locked", "--offline", "--release", "-p", "iroha_plonk_gadgets",
        "--test", "m3_gates", "--no-run", "--message-format=json",
    ]
    result = command(argv)
    (output / "build.stdout.log").write_text(result.stdout)
    (output / "build.stderr.log").write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f"build failed ({result.returncode}); see build.stderr.log")
    executables = set()
    artifacts = []
    build_scripts = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") == "build-script-executed":
            build_scripts.append(item)
        if item.get("reason") == "compiler-artifact":
            artifacts.append(item)
            if item.get("target", {}).get("name") == "m3_gates" and item.get("executable"):
                executables.add(item["executable"])
    if len(executables) != 1:
        raise ValueError(f"expected one m3_gates executable, found {len(executables)}")
    after_metadata = cargo_metadata()
    after_tools = tool_identity()
    after_manifest = source_manifest(metadata_roots(after_metadata))
    write_json(output / "cargo-metadata-after.json", after_metadata)
    write_json(output / "tools-after.json", after_tools)
    write_json(output / "source-after.json", after_manifest)
    if metadata != after_metadata or before_tools != after_tools:
        raise ValueError("metadata or tools changed during build")
    native = capture_native_source(metadata, artifacts, build_scripts, output)
    if native is None:
        raise ValueError("M3 qualification requires the selected iroha_plonk native source identity")
    if native["admin_watchers"] != before_admin:
        raise ValueError("native Git admin watchers changed during build")
    scope = component_scope(metadata, artifacts, build_scripts, native)
    if not component:
        scope["kind"] = "whole_checkout"
        scope["roots"] = roots
    source_files = selected_sources(after_manifest, scope)
    before_selected = selected_sources(before_manifest, scope)
    for values in (source_files, before_selected):
        values["@cargo_metadata"] = manifest_digest(metadata)
        values["@tools"] = manifest_digest(before_tools)
        values["@build_environment"] = manifest_digest(scope["build_environment"])
        values["@generated_native_inputs"] = manifest_digest(recheck_native_source(native))
        values["@cargo_build_inputs"] = manifest_digest(recheck_build_inputs(scope))
    write_json(output / "source-provenance.json", {
        "source_policy": SOURCE_POLICY, "scope": scope,
        "before": before_selected, "after": source_files,
        "whole_checkout_before": before, "whole_checkout_after": manifest_digest(after_manifest),
        "changed_in_scope": sorted(name for name in before_selected.keys() | source_files.keys()
                                   if before_selected.get(name) != source_files.get(name)),
    })
    retained = output / "dep-info"
    retained.mkdir()
    for path, record in scope["depfiles"].items():
        original = local_path(path)
        data = original.read_bytes()
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("depfile changed before retention")
        (retained / (record["sha256"] + ".d")).write_bytes(data)
    before = manifest_digest(before_selected)
    after = manifest_digest(source_files)
    if before != after:
        raise ValueError("source changed during build; candidate is not frozen")
    binary = Path(executables.pop()).resolve()
    binary_sha256 = file_hash(binary)
    compiler = command(["rustc", "-Vv"])
    compiler.check_returncode()
    listing = command([str(binary), "--list"])
    listing.check_returncode()
    for config in CONFIGS.values():
        if f"{config['test']}: test" not in listing.stdout:
            raise ValueError(f"missing benchmark {config['test']}")
    test = "qualification_candidate_identity"
    if f"{test}: test" not in listing.stdout:
        raise ValueError("measurement executable lacks compiled native source identity test")
    identity = command([str(binary), "--ignored", "--exact", test, "--nocapture", "--test-threads=1"])
    (output / "native-identity.stdout.log").write_text(identity.stdout)
    (output / "native-identity.stderr.log").write_text(identity.stderr)
    identity.check_returncode()
    native_identity = parse_native_identity(identity.stdout, native, binary_sha256)
    write_json(output / "native-identity.json", native_identity)
    if source_digest(scope) != after or file_hash(binary) != binary_sha256:
        raise ValueError("source or executable changed during native identity inventory")
    inventory = command([
        str(binary), "--ignored", "--exact", "qualification_candidate_layouts",
        "--nocapture", "--test-threads=1",
    ], env={**os.environ, "RAYON_NUM_THREADS": "1"})
    (output / "layouts.stdout.log").write_text(inventory.stdout)
    (output / "layouts.stderr.log").write_text(inventory.stderr)
    inventory.check_returncode()
    layouts = parse_layouts(inventory.stdout)
    if source_digest(scope) != after:
        raise ValueError("source changed during descriptor inventory; candidate is not frozen")
    if file_hash(binary) != binary_sha256:
        raise ValueError("executable changed during descriptor inventory; candidate is not frozen")
    candidate = {
        "schema": "kagemusha.m3.candidate.v1", "source_policy": SOURCE_POLICY, "source_sha256": after,
        "source_scope": scope, "qualification_scope": "component" if component else "whole_checkout",
        "binary": str(binary), "binary_sha256": binary_sha256,
        "native_identity": native_identity,
        "native_identity_process": {"code": identity.returncode, "stdout": identity.stdout, "stderr": identity.stderr},
        "compiler": compiler.stdout, "build_command": argv,
        "profile": "release", "features": "default",
        "memory_activity_policy": MEMORY_ACTIVITY_POLICY,
        "layouts": layouts,
        "platform": platform.platform(), "machine": platform.machine(),
        "build_flags": {key: os.environ.get(key) for key in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO",
        )},
    }
    reasons = candidate_native_reasons(candidate)
    if reasons:
        raise ValueError("; ".join(reasons))
    write_json(candidate_path, candidate)
    print(candidate_path)


def parse_vm_stat(text: str) -> dict[str, int]:
    counters = {}
    for label in (*QUIET_MEMORY_COUNTERS, "Swapins"):
        match = re.search(rf"^{label}:\s+(\d+)\.", text, re.MULTILINE)
        if not match:
            raise ValueError(f"missing vm_stat counter {label}")
        counters[label] = int(match[1])
    return counters


def environment() -> dict:
    """Capture raw evidence; unsupported or failed probes cannot qualify."""
    raw = {}
    if sys.platform == "darwin":
        for key, argv in PROBES.items():
            try:
                result = command(argv)
                raw[key] = {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
            except OSError as error:
                raw[key] = {"code": None, "stdout": "", "stderr": str(error)}
    return {"platform": sys.platform, "raw": raw}


def ac_power_settings(source: str, policy: str) -> dict[str, str]:
    """Read the active profile; absent optional settings are not invented."""
    source_lines = [line.strip() for line in source.splitlines() if line.strip()]
    headers = [line for line in source_lines if line.startswith("Now drawing from ")]
    if (not source_lines or source_lines[0] != "Now drawing from 'AC Power'" or
            headers != ["Now drawing from 'AC Power'"]):
        raise ValueError("qualification host has no unambiguous AC power source")
    profiles: dict[str, dict[str, str]] = {}
    current = None
    for line in policy.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            if line not in ("AC Power:", "Battery Power:", "UPS Power:") or line in profiles:
                raise ValueError("unrecognized or duplicate power profile")
            current = profiles[line] = {}
            continue
        setting = re.fullmatch(r"(Sleep On Power Button|[a-z][a-z0-9_]*)\s+(\S.*)", line)
        if current is None or setting is None or setting[1] in current:
            raise ValueError("unrecognized or duplicate power setting")
        current[setting[1]] = setting[2]
    active = profiles.get("AC Power:")
    if not active:
        raise ValueError("missing active AC power settings")
    # Some supported hosts do not expose this capability at all. When reported,
    # require an explicit off value in the active profile, not the battery one.
    if "lowpowermode" in active and active["lowpowermode"] != "0":
        raise ValueError("active low power mode is enabled or unavailable")
    return active


def environment_counters(value: dict) -> dict:
    """Derive validity from raw probe results, never cached validity flags."""
    if value.get("platform") != "darwin":
        raise ValueError("this qualification profile requires macOS")
    raw = value["raw"]
    if not isinstance(raw, dict) or set(raw) != set(PROBES):
        raise ValueError("incomplete environment probes")
    for name, probe in raw.items():
        if (not isinstance(probe, dict) or type(probe.get("code")) is not int or
                probe["code"] != 0 or not isinstance(probe.get("stdout"), str) or
                not isinstance(probe.get("stderr"), str) or not probe["stdout"].strip()):
            raise ValueError(f"environment probe failed: {name}")
    if raw["pressure"]["stdout"].strip() != "1":
        raise ValueError("memory pressure is not normal")
    ac_power_settings(raw["source"]["stdout"], raw["power"]["stdout"])
    return parse_vm_stat(raw["vm"]["stdout"])


def environment_reasons(before: dict, after: dict) -> list[str]:
    """Enforce the specified quiet-memory counters, retaining swap-ins as diagnostics."""
    reasons = []
    counters = []
    for name, value in (("before", before), ("after", after)):
        try:
            counters.append(environment_counters(value))
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            reasons.append(f"{name}: environment unavailable: {error}")
    if reasons:
        return reasons
    for name, count in counters[0].items():
        if counters[1][name] < count:
            reasons.append(f"memory counter decreased: {name}")
        elif name in QUIET_MEMORY_COUNTERS and counters[1][name] != count:
            reasons.append(f"memory counter changed: {name}")
    if before["raw"]["power"]["stdout"] != after["raw"]["power"]["stdout"]:
        reasons.append("power policy changed")
    return reasons


def parse_report(text: str) -> dict:
    lines = [line.split(PREFIX, 1)[1] for line in text.splitlines() if PREFIX in line]
    if len(lines) != 1:
        raise ValueError(f"expected one measurement record, found {len(lines)}")
    report = json.loads(lines[0])
    if not isinstance(report, dict) or report.get("schema") != "kagemusha.m3.process.v1":
        raise ValueError("unknown measurement schema")
    return report


def parse_layouts(text: str) -> dict:
    """Require one actual-key descriptor for each distinct circuit workload."""
    layouts = {}
    for line in text.splitlines():
        if "M3_LAYOUT_JSON " not in line:
            continue
        item = json.loads(line.split("M3_LAYOUT_JSON ", 1)[1])
        if (not isinstance(item, dict) or not isinstance(item.get("gate"), str) or
                item["gate"] in layouts):
            raise ValueError("malformed or duplicate layout inventory")
        if (item.get("k") != 16 or item.get("transcript_profile") != "pipa-r" or
                not isinstance(item.get("shape"), str) or
                not item["shape"] or item.get("descriptor_hash") != "blake2b256-pipa-v2-circdesc" or
                not isinstance(item.get("descriptor_digest"), str) or
                re.fullmatch(r"[0-9a-f]{64}", item["descriptor_digest"]) is None):
            raise ValueError("invalid layout descriptor")
        layouts[item["gate"]] = item
    if set(layouts) != {config["gate"] for config in CONFIGS.values()}:
        raise ValueError("incomplete or unexpected layout inventory")
    return layouts


def sample_fixture_seed(seed: int, index: int) -> int:
    """Reproduce m3_gates.rs mix(seed, index, 0) with wrapping u64 arithmetic."""
    if type(seed) is not int or not 0 <= seed < 1 << 64:
        raise ValueError("process seed must be a u64")
    if type(index) is not int or index not in (0, 1):
        raise ValueError("proof sample index must be zero or one")
    mask = (1 << 64) - 1
    value = seed ^ (index << 40) ^ 0x9E3779B97F4A7C15
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & mask
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & mask
    return value ^ (value >> 31)


def report_reasons(report: dict, config: dict, candidate: dict, seed: int) -> list[str]:
    reasons = []
    if type(seed) is not int or not 0 <= seed < 1 << 64:
        return ["invalid scheduled process seed"]
    expected = {
        "workers": config["workers"], "binary_sha256": candidate["binary_sha256"],
        "witness_api": "owned", "coset_cache": "on_demand", "commitment_tables": False,
        "peak_rss_source": "kernel_lifetime_high_water",
        "quotient_workspace": "caller_owned", "quotient_workspace_budget_bytes": 256 << 20,
        "msm_process_budget_bytes": 64 << 20,
        "msm_process_retained_bytes": 0, "seed": seed, "transcript_profile": "pipa-r",
        "randomness": "fresh-hedged", "fixture_seed_derivation": "splitmix64-process-sample-v1",
        **candidate["layouts"][config["gate"]],
    }
    for name, value in expected.items():
        if type(report.get(name)) is not type(value) or report[name] != value:
            reasons.append(f"measurement configuration mismatch: {name}")
    if type(report.get("peak_rss_bytes")) is not int or report["peak_rss_bytes"] <= 0:
        reasons.append("missing kernel peak RSS")
    scratch = report.get("msm_process_peak_bytes")
    if type(scratch) is not int or not 0 < scratch <= 64 << 20:
        reasons.append("invalid shared MSM scratch high-water")
    samples = report.get("samples", [])
    if not isinstance(samples, list) or any(not isinstance(sample, dict) for sample in samples):
        return reasons + ["malformed proof samples"]
    if len(samples) != 2:
        reasons.append("exactly the first two proofs must be retained")
    if (any(type(sample.get("index")) is not int for sample in samples) or
            [sample.get("index") for sample in samples] != [0, 1]):
        reasons.append("proof sample order or identity differs")
    for index, sample in enumerate(samples):
        fixture_seed = sample.get("fixture_seed")
        if (type(fixture_seed) is not int or not 0 <= fixture_seed < 1 << 64 or
                index >= 2 or fixture_seed != sample_fixture_seed(seed, index)):
            reasons.append(f"proof sample fixture seed differs: {index}")
        if sample.get("verified") is not True:
            reasons.append("unverified measured proof")
        for metric in ("cpu_ns", "total_ns"):
            if type(sample.get(metric)) is not int or sample[metric] <= 0:
                reasons.append(f"invalid {metric}")
        for boundary in ("thermal_before", "thermal_after"):
            if sample.get(boundary) != "nominal":
                reasons.append("non-nominal or unavailable thermal state")
    workspace = report.get("quotient_workspace_allocated_bytes")
    if type(workspace) is not int or not 0 < workspace <= 256 << 20:
        reasons.append("invalid caller-owned quotient workspace allocation")
    else:
        for index, sample in enumerate(samples):
            expected_before = 0 if index == 0 else workspace
            if (type(sample.get("quotient_workspace_before_bytes")) is not int or
                    sample["quotient_workspace_before_bytes"] != expected_before or
                    type(sample.get("quotient_workspace_after_bytes")) is not int or
                    sample["quotient_workspace_after_bytes"] != workspace):
                reasons.append("quotient workspace not retained and reused between proofs")
    for boundary in ("thermal_before", "thermal_after"):
        if report.get(boundary) != "nominal":
            reasons.append("non-nominal or unavailable process thermal state")
    return reasons


def slower(report: dict, metric: str) -> int:
    return max(sample[metric] for sample in report["samples"])


def calibration_reasons(before: dict, after: dict) -> list[str]:
    reasons = []
    for metric in ("cpu_ns", "total_ns"):
        values = [slower(before, metric), slower(after, metric)]
        if min(values) <= 0 or max(values) * 100 > min(values) * 105:
            reasons.append(f"calibration drift exceeds 5%: {metric}")
    return reasons


def run_process(candidate: dict, config: dict, seed: int, path: Path) -> dict:
    before = environment()
    env = {**os.environ, "RAYON_NUM_THREADS": str(config["workers"]), "M3_SEED": str(seed)}
    try:
        result = command([
            candidate["binary"], "--ignored", "--exact", config["test"], "--nocapture",
            "--test-threads=1",
        ], env=env)
        process = {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except OSError as error:
        process = {"code": None, "stdout": "", "stderr": str(error)}
    after = environment()
    (path.with_suffix(".stdout.log")).write_text(process["stdout"])
    (path.with_suffix(".stderr.log")).write_text(process["stderr"])
    try:
        report = parse_report(process["stdout"])
    except (ValueError, KeyError, TypeError):
        report = None
    observation = {"before": before, "after": after, "seed": seed,
                   "report": report, "process": process}
    observation["reasons"] = observation_reasons(observation, config, candidate, seed)
    write_json(path.with_suffix(".json"), observation)
    return observation


def observation_reasons(value: dict, config: dict, candidate: dict, seed: int) -> list[str]:
    """Recompute a process result from its exit, raw output and raw probes."""
    reasons = []
    try:
        reasons.extend(environment_reasons(value["before"], value["after"]))
        if type(value["seed"]) is not int or value["seed"] != seed:
            reasons.append("process seed differs")
        process = value["process"]
        if type(process["code"]) is not int or process["code"] != 0:
            reasons.append(f"benchmark exited {process['code']}")
        if not isinstance(process["stdout"], str) or not isinstance(process["stderr"], str):
            raise ValueError("missing raw process output")
        report = parse_report(process["stdout"])
        if report != value["report"]:
            reasons.append("retained report differs from raw process output")
        reasons.extend(report_reasons(report, config, candidate, seed))
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        reasons.append(f"retained process evidence invalid: {error}")
    return reasons


def candidate_boundary(candidate: dict) -> dict:
    try:
        return {"source_sha256": source_digest(candidate["source_scope"]),
                "binary_sha256": file_hash(Path(candidate["binary"]))}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        return {"source_sha256": None, "binary_sha256": None, "error": str(error)}


def attempt_reasons(item: dict, config: dict, candidate: dict) -> list[str]:
    """Validity is derived from all three processes and both candidate seals."""
    reasons = []
    try:
        seed = item["seed"]
        if type(seed) is not int or not 0 <= seed < 1 << 64:
            raise ValueError("invalid measurement seed")
        measured = item["measured"]
        if item["report"] != measured["report"]:
            reasons.append("attempt report differs from measured process")
        reasons.extend(observation_reasons(measured, config, candidate, seed))
        calibration = CONFIGS[f"{config['kind'][0]}_exact-{config['workers']}"]
        calibration_valid = True
        for label in ("pre", "post"):
            errors = observation_reasons(item[label], calibration, candidate, 0)
            reasons.extend(f"{label}-calibration: {error}" for error in errors)
            calibration_valid &= not errors
        if calibration_valid:
            reasons.extend(calibration_reasons(item["pre"]["report"], item["post"]["report"]))
        expected = {key: candidate[key] for key in ("source_sha256", "binary_sha256")}
        for label in ("candidate_before", "candidate_after"):
            if item[label] != expected:
                reasons.append(f"{label} differs from frozen candidate")
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        reasons.append(f"retained attempt evidence invalid: {error}")
    return reasons


def verdict(config: dict, attempts: list[dict]) -> dict:
    """All valid samples participate; a favorable minimum never decides a gate."""
    valid = [item for item in attempts if not item["reasons"]]
    family = config["kind"][0]
    hard_rss = (0.75 if family == "q" else 0.85) * GIB
    margin_rss = hard_rss * 0.95
    hard_time = 30 if family == "q" and config["workers"] == 1 else (
        36 if config["workers"] == 1 else (10 if family == "q" else None)
    )
    metric = "cpu_ns" if config["workers"] == 1 else "total_ns"
    peaks = [item["report"]["peak_rss_bytes"] for item in valid]
    times = [slower(item["report"], metric) / 1e9 for item in valid]
    medians = []
    rss_medians = []
    complete = True
    for block in range(3):
        block_reports = [item["report"] for item in valid if item["block"] == block]
        values = [slower(report, metric) / 1e9 for report in block_reports]
        complete &= len(values) == 3
        if values:
            medians.append(statistics.median(values))
            rss_medians.append(statistics.median(report["peak_rss_bytes"] for report in block_reports))
    hard_failure = any(value > hard_rss for value in peaks) or (
        hard_time is not None and any(value > hard_time for value in times)
    )
    margin_failure = any(value > margin_rss for value in rss_medians) or (
        hard_time is not None and any(value > hard_time * 0.9 for value in medians)
    )
    status = "fail" if hard_failure else (
        "inconclusive" if not complete else ("borderline" if margin_failure else "pass")
    )
    return {"status": status, "valid_processes": len(valid), "attempts": len(attempts),
            "block_medians_seconds": medians, "all_process_times_seconds": times,
            "block_medians_rss_bytes": rss_medians, "all_process_rss_bytes": peaks,
            "maximum_kernel_rss_bytes": max(peaks, default=None), "metric": metric}


def summarize(path: Path) -> dict:
    ledger = json.loads(path.read_text())
    if not isinstance(ledger["attempts"], dict) or set(ledger["attempts"]) - set(CONFIGS):
        raise ValueError("invalid or unknown qualification configuration")
    ledger_reasons = []
    separation_reasons = {name: [] for name in CONFIGS}
    if ledger.get("schema") != "kagemusha.m3.runs.v1":
        ledger_reasons.append("missing complete qualification ledger schema")
    if ledger["candidate"].get("source_policy") != SOURCE_POLICY:
        ledger_reasons.append("candidate does not bind the current source policy")
    if ledger["candidate"].get("memory_activity_policy") != MEMORY_ACTIVITY_POLICY:
        ledger_reasons.append("candidate does not bind the current memory activity policy")
    ledger_reasons.extend(candidate_native_reasons(ledger["candidate"]))
    seed = ledger.get("shuffle_seed")
    rng = random.Random(seed) if type(seed) is int else None
    if rng is None or ledger.get("schedule") != schedule(rng):
        ledger_reasons.append("invalid predeclared configuration schedule")
    if not ledger_reasons:
        sequence = []
        previous_executed_batch = None
        for block, names in enumerate(ledger["schedule"]):
            for name in names:
                rows = ledger["attempts"].get(name, [])
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    raise ValueError("attempts must be an ordered list of records")
                executed = False
                for row in rows:
                    if row.get("block") != block:
                        continue
                    sequence.append(row.get("sequence"))
                    measured = row.get("measured")
                    process = measured.get("process") if isinstance(measured, dict) else None
                    # subprocess supplies an integer return code only after a
                    # child ran. Failed launch attempts retain code=None. A
                    # nonzero exit or invalid environment still took place and
                    # can separate batches, independently of sample validity.
                    executed |= isinstance(process, dict) and type(process.get("code")) is int
                    # The driver consumes all shuffle draws before one seed per
                    # attempt, including invalid attempts. Uniqueness alone lets
                    # a replacement run masquerade as the declared schedule.
                    expected_seed = rng.randrange(1 << 64)
                    if type(row.get("seed")) is not int or row["seed"] != expected_seed:
                        ledger_reasons.append("measurement seed differs from predeclared draw")
                if executed:
                    if previous_executed_batch == name:
                        separation_reasons[name].append(
                            "measurement blocks lack an intervening executed configuration batch")
                    previous_executed_batch = name
        if (any(type(number) is not int for number in sequence) or
                sequence != list(range(sum(len(rows) for rows in ledger["attempts"].values())))):
            ledger_reasons.append("attempt execution differs from predeclared schedule")
    results = {}
    for name, config in CONFIGS.items():
        checked = []
        seen_seeds = set()
        rows = ledger["attempts"].get(name, [])
        if not isinstance(rows, list):
            raise ValueError("attempts must be an ordered list")
        config_reasons = ledger_reasons + (["configuration exceeds 18 attempts"] if len(rows) > 18 else [])
        previous_block = -1
        for item in rows:
            reasons = list(config_reasons)
            try:
                retained = item["reasons"]
                if not isinstance(retained, list) or any(not isinstance(reason, str) for reason in retained):
                    raise ValueError("malformed retained reasons")
                reasons.extend(retained)
                if type(item["block"]) is not int or item["block"] not in range(3):
                    raise ValueError("invalid measurement block")
                if item["block"] < previous_block:
                    reasons.append("measurement blocks are out of order")
                previous_block = item["block"]
                seed = item["seed"]
                if type(seed) is not int or not 0 <= seed < 1 << 64:
                    raise ValueError("invalid measurement seed")
                if seed in seen_seeds:
                    reasons.append("duplicate measured process seed")
                seen_seeds.add(seed)
                reasons.extend(attempt_reasons(item, config, ledger["candidate"]))
            except (ValueError, KeyError, TypeError) as error:
                reasons.append(f"retained evidence invalid: {error}")
            checked.append({**item, "reasons": list(dict.fromkeys(reasons))})
        results[name] = verdict(config, checked)
        # Missing separation prevents qualification, but does not erase valid
        # observations or turn an authenticated hard-limit breach inconclusive.
        results[name]["qualification_reasons"] = list(dict.fromkeys(separation_reasons[name]))
        if separation_reasons[name] and results[name]["status"] != "fail":
            results[name]["status"] = "inconclusive"
        results[name]["invalid_attempts"] = [
            {"attempt": index + 1, "reasons": item["reasons"]}
            for index, item in enumerate(checked) if item["reasons"]
        ]
    statuses = {value["status"] for value in results.values()}
    overall = next((status for status in ("fail", "inconclusive", "borderline") if status in statuses), "pass")
    return {"status": overall, "configurations": results, "candidate": ledger["candidate"]}


def schedule(rng: random.Random) -> list[list[str]]:
    """Declare three permutations with different configurations at every boundary.

    Swap a conflicting prefix rather than reshuffling: the measurement-seed
    stream consumes exactly the same RNG draws as the three original shuffles.
    Summarize also checks actual execution because exhausted attempt budgets
    can leave a declared intervening batch empty.
    """
    order = []
    for _ in range(3):
        names = list(CONFIGS)
        rng.shuffle(names)
        if order and names[0] == order[-1][-1]:
            names[0], names[1] = names[1], names[0]
        order.append(names)
    return order


def run(candidate_path: Path, seed: int, *, stop_on_hard_failure: bool = False) -> dict:
    candidate = json.loads(candidate_path.read_text())
    if candidate.get("source_policy") != SOURCE_POLICY:
        raise ValueError("candidate does not bind the current source policy; prepare a fresh candidate")
    if candidate.get("memory_activity_policy") != MEMORY_ACTIVITY_POLICY:
        raise ValueError("candidate does not bind the current memory activity policy; prepare a fresh candidate")
    reasons = candidate_native_reasons(candidate)
    if reasons:
        raise ValueError("; ".join(reasons) + "; prepare a fresh candidate")
    output = candidate_path.parent
    if (output / "runs.json").exists():
        raise ValueError("runs.json already exists; retained attempts may not be overwritten")
    boundary = candidate_boundary(candidate)
    if any(candidate.get(key) != boundary[key] for key in boundary):
        raise ValueError("source or executable differs from frozen candidate")
    rng = random.Random(seed)
    order = schedule(rng)
    ledger = {"schema": "kagemusha.m3.runs.v1", "candidate": candidate,
              "shuffle_seed": seed, "schedule": order,
              "stop_on_hard_failure": stop_on_hard_failure,
              "attempts": {name: [] for name in CONFIGS}}
    write_json(output / "runs.json", ledger)
    for block, names in enumerate(order):
        for name in names:
            config = CONFIGS[name]
            attempts = ledger["attempts"][name]
            while sum(not value["reasons"] and value["block"] == block for value in attempts) < 3 and len(attempts) < 18:
                before = candidate_boundary(candidate)
                if any(before[key] != candidate.get(key) for key in before):
                    raise ValueError("candidate changed during qualification; retained results cannot qualify the new source")
                number = len(attempts)
                prefix = output / f"{name}-b{block + 1}-attempt{number + 1:02}"
                calibration = CONFIGS[f"{config['kind'][0]}_exact-{config['workers']}"]
                # Fixed calibration witness, independent of the recorded measurement seed.
                pre = run_process(candidate, calibration, 0, prefix.with_name(prefix.name + "-pre"))
                measured = run_process(candidate, config, rng.randrange(1 << 64), prefix)
                post = run_process(candidate, calibration, 0, prefix.with_name(prefix.name + "-post"))
                after = candidate_boundary(candidate)
                changed = any(after[key] != candidate.get(key) for key in after)
                attempt = {"block": block, "seed": measured["seed"], "report": measured["report"],
                           "sequence": sum(len(rows) for rows in ledger["attempts"].values()),
                           "pre": pre, "measured": measured, "post": post,
                           "candidate_before": before, "candidate_after": after}
                reasons = attempt_reasons(attempt, config, candidate)
                attempt["reasons"] = reasons
                attempts.append(attempt)
                write_json(output / "runs.json", ledger)
                write_json(output / "summary.json", summarize(output / "runs.json"))
                print(f"{name} block {block + 1} attempt {number + 1}: " + ("valid" if not reasons else "; ".join(reasons)), flush=True)
                if changed:
                    raise ValueError("candidate changed; qualification stopped with raw evidence retained")
                if stop_on_hard_failure and verdict(config, attempts)["status"] == "fail":
                    print("observed hard limit exceeded; incomplete schedule retained", flush=True)
                    return summarize(output / "runs.json")
            # Summarize refuses adjacent executed batches of the same
            # configuration if intervening batches exhaust their attempts or
            # never launch a measured child. Retain all evidence without
            # adding replacement batches or increasing the attempt ceiling.
    result = summarize(output / "runs.json")
    write_json(output / "summary.json", result)
    print(json.dumps(result, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    build = actions.add_parser("prepare", help="build and freeze source/executable provenance")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--component", action="store_true",
                       help="bind actual Cargo dependency sources; cannot qualify the whole release")
    build.add_argument("--target-slot", default="m3b")
    execute = actions.add_parser("run", help="collect the fixed fresh-process qualification schedule")
    execute.add_argument("--candidate", type=Path, required=True)
    execute.add_argument("--seed", type=int, default=20261006)
    execute.add_argument("--stop-on-hard-failure", action="store_true",
                         help="retain a failing partial schedule and stop after a valid hard-cap breach")
    report = actions.add_parser("summarize", help="recompute verdicts from retained raw records")
    report.add_argument("runs", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.output, component=args.component, target_slot=args.target_slot)
    elif args.action == "run":
        result = run(args.candidate.resolve(), args.seed, stop_on_hard_failure=args.stop_on_hard_failure)
        raise SystemExit(0 if result["status"] == "pass" else 1)
    else:
        result = summarize(args.runs)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
