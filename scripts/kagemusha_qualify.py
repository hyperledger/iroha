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
"""

from __future__ import annotations

import argparse
import hashlib
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
SOURCE_POLICY = "cargo-local-input-closure-v1"
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
    if any(value.startswith("symlink:") for value in selected.values()):
        raise ValueError("selected source contains a symlink")
    return selected


def manifest_digest(manifest: dict) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_digest(scope: dict | None = None) -> str:
    """Rescan the same roots, required inputs, metadata and tools at runtime."""
    if scope is None:
        raise ValueError("candidate lacks a captured Cargo source scope")
    selected = selected_sources(source_manifest(scope["roots"]), scope)
    selected["@cargo_metadata"] = manifest_digest(cargo_metadata())
    selected["@tools"] = manifest_digest(tool_identity())
    selected["@build_environment"] = manifest_digest({key: os.environ.get(key) for key in scope["build_environment"]})
    return manifest_digest(selected)


def depfile_inputs(depinfo: Path, artifact: Path) -> set[str]:
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
        inputs.update(local_path(name).relative_to(ROOT).as_posix() for name in shlex.split(right))
    if not matched or not inputs:
        raise ValueError(f"depfile does not bind artifact: {artifact}")
    return inputs


def component_scope(metadata: dict, artifacts: list[dict], build_scripts: list[dict] = ()) -> dict:
    """Bind actual local artifacts and fail closed on uncovered/generated inputs."""
    packages = {package["id"]: package for package in metadata["packages"]}
    roots = {".cargo"} if (ROOT / ".cargo").exists() else set()
    files = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain",
             "scripts/cargo_fast.sh", "scripts/check_cargo_target_owner.py",
             "scripts/kagemusha_qualify.py"}
    compiled, depfiles, aliases, required = {}, {}, [], set()
    compiler_environment = {}
    script_packages = set()
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
            inputs = depfile_inputs(depinfo, actual)
            generated = sorted(name for name in inputs if name.startswith("target/"))
            if generated:
                # M3 currently has no generated Rust inputs. Do not grant a
                # blanket target/ exemption; a future producer needs a reviewed
                # reproducible transform and independently captured prerequisites.
                raise ValueError(f"generated compiler input has no verified disposition: {generated}")
            required.update(inputs)
            derived_environment = {}
            for line in depinfo.read_text().splitlines():
                if not line.startswith("# env-dep:"):
                    continue
                name, separator, value = line.removeprefix("# env-dep:").partition("=")
                expected = value if separator else None
                if name == "CARGO_MANIFEST_DIR":
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
            depfiles[str(depinfo)] = {"sha256": file_hash(depinfo), "inputs": sorted(inputs),
                                     "derived_environment": derived_environment}
    if not any(package["name"] == "iroha_plonk_gadgets" for package in compiled.values()):
        raise ValueError("component artifact set omits its measurement driver")
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
        generated = scan_local_root(out.relative_to(ROOT).as_posix())
        if generated:
            raise ValueError("local generated build output has no verified disposition")
        text = output.read_text()
        for line in text.splitlines():
            directive = line.removeprefix("cargo::").removeprefix("cargo:")
            if directive.startswith("rerun-if-changed="):
                name = directive.partition("=")[2]
                base = local_path(package["manifest_path"]).parent
                path = local_path(base / name)
                if path.is_dir():
                    roots.add(path.relative_to(ROOT).as_posix())
                    required.update(scan_local_root(path.relative_to(ROOT).as_posix()))
                else:
                    required.add(path.relative_to(ROOT).as_posix())
            elif directive.startswith("rerun-if-env-changed="):
                name = directive.partition("=")[2]
                environment[name] = os.environ.get(name)
        outputs.append({"record": item, "path": str(output), "sha256": file_hash(output), "text": text,
                        "generated_disposition": "empty output directory; no generated compiler inputs"})
    if observed_scripts != script_packages:
        raise ValueError("local build script lacks its executed output record")
    files.update(required)
    return {"kind": "cargo_component", "roots": sorted(roots), "files": sorted(files),
            "required_inputs": sorted(required), "packages": [compiled[key] for key in sorted(compiled)],
            "depfiles": depfiles, "build_script_aliases": aliases, "build_script_outputs": outputs,
            "build_environment": environment}


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


def prepare(output: Path, *, component: bool = False, target_slot: str = "m3b") -> None:
    output = ignored_output(output)
    candidate_path = output / "candidate.json"
    if candidate_path.exists():
        raise ValueError("candidate.json already exists; use a fresh output directory")
    metadata = cargo_metadata()
    roots = metadata_roots(metadata)
    before_tools = tool_identity()
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
    scope = component_scope(metadata, artifacts, build_scripts)
    if not component:
        scope["kind"] = "whole_checkout"
        scope["roots"] = roots
    source_files = selected_sources(after_manifest, scope)
    before_selected = selected_sources(before_manifest, scope)
    for values in (source_files, before_selected):
        values["@cargo_metadata"] = manifest_digest(metadata)
        values["@tools"] = manifest_digest(before_tools)
        values["@build_environment"] = manifest_digest(scope["build_environment"])
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
    write_json(candidate_path, {
        "schema": "kagemusha.m3.candidate.v1", "source_policy": SOURCE_POLICY, "source_sha256": after,
        "source_scope": scope, "qualification_scope": "component" if component else "whole_checkout",
        "binary": str(binary), "binary_sha256": binary_sha256,
        "compiler": compiler.stdout, "build_command": argv,
        "profile": "release", "features": "default",
        "memory_activity_policy": MEMORY_ACTIVITY_POLICY,
        "layouts": layouts,
        "platform": platform.platform(), "machine": platform.machine(),
        "build_flags": {key: os.environ.get(key) for key in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO",
        )},
    })
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


def report_reasons(report: dict, config: dict, candidate: dict, seed: int) -> list[str]:
    reasons = []
    expected = {
        "workers": config["workers"], "binary_sha256": candidate["binary_sha256"],
        "witness_api": "owned", "coset_cache": "on_demand", "commitment_tables": False,
        "peak_rss_source": "kernel_lifetime_high_water",
        "quotient_workspace": "caller_owned", "quotient_workspace_budget_bytes": 256 << 20,
        "msm_process_budget_bytes": 64 << 20,
        "msm_process_retained_bytes": 0, "seed": seed, "transcript_profile": "pipa-r",
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
    if [sample.get("index") for sample in samples] != [0, 1]:
        reasons.append("proof sample order or identity differs")
    for sample in samples:
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
    if ledger.get("schema") != "kagemusha.m3.runs.v1":
        ledger_reasons.append("missing complete qualification ledger schema")
    if ledger["candidate"].get("source_policy") != SOURCE_POLICY:
        ledger_reasons.append("candidate does not bind the current source policy")
    if ledger["candidate"].get("memory_activity_policy") != MEMORY_ACTIVITY_POLICY:
        ledger_reasons.append("candidate does not bind the current memory activity policy")
    seed = ledger.get("shuffle_seed")
    rng = random.Random(seed) if type(seed) is int else None
    if rng is None or ledger.get("schedule") != schedule(rng):
        ledger_reasons.append("invalid predeclared configuration schedule")
    if not ledger_reasons:
        sequence = []
        for block, names in enumerate(ledger["schedule"]):
            for name in names:
                rows = ledger["attempts"].get(name, [])
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    raise ValueError("attempts must be an ordered list of records")
                for row in rows:
                    if row.get("block") != block:
                        continue
                    sequence.append(row.get("sequence"))
                    # The driver consumes all shuffle draws before one seed per
                    # attempt, including invalid attempts. Uniqueness alone lets
                    # a replacement run masquerade as the declared schedule.
                    expected_seed = rng.randrange(1 << 64)
                    if type(row.get("seed")) is not int or row["seed"] != expected_seed:
                        ledger_reasons.append("measurement seed differs from predeclared draw")
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
        results[name]["invalid_attempts"] = [
            {"attempt": index + 1, "reasons": item["reasons"]}
            for index, item in enumerate(checked) if item["reasons"]
        ]
    statuses = {value["status"] for value in results.values()}
    overall = next((status for status in ("fail", "inconclusive", "borderline") if status in statuses), "pass")
    return {"status": overall, "configurations": results, "candidate": ledger["candidate"]}


def schedule(rng: random.Random) -> list[list[str]]:
    order = []
    for _ in range(3):
        names = list(CONFIGS)
        rng.shuffle(names)
        order.append(names)
    return order


def run(candidate_path: Path, seed: int, *, stop_on_hard_failure: bool = False) -> dict:
    candidate = json.loads(candidate_path.read_text())
    if candidate.get("source_policy") != SOURCE_POLICY:
        raise ValueError("candidate does not bind the current source policy; prepare a fresh candidate")
    if candidate.get("memory_activity_policy") != MEMORY_ACTIVITY_POLICY:
        raise ValueError("candidate does not bind the current memory activity policy; prepare a fresh candidate")
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
            # Configurations between blocks provide their temporal separation.
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
