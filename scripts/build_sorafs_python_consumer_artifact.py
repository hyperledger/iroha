#!/usr/bin/env python3
"""Execute the fixed SoraFS Python consumer against original offline wheels.

Requires a clean matching source candidate, native ABI-29 manifest, independently
pinned CPython3.12/runtime and offline dependency manifests, and prebuilt native
and SDK wheels. Outputs are fresh below the source's target/ directory. This
unsigned POSIX host artifact does not grant SDK parity or release promotion.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
from pathlib import Path
import sys

# Support an isolated parent invocation while resolving only this source's tools.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_native_sdk_artifact as native
from sorafs_evidence_json import decode_evidence_json
from sorafs_python_consumer_artifact import (
    ArtifactError, canonical_json, consume_runtime_output,
)
from sorafs_python_consumer_cases import TEST_PATH
from sorafs_python_commands import execution_commands, verify_command_observations, STDERR_LIMIT
from sorafs_python_archive import execution_archive
from sorafs_python_dependency_archive import parse_dependency_wheel
from sorafs_python_dependency_inputs import parse_dependency_manifest
from sorafs_python_dependency_install import verify_dependency_install
from sorafs_python_environment import (
    BOOTSTRAP_FILES, inspect_environment, pinned_requirements, verify_environment_bootstrap,
    verify_distributions, verify_runtime_probe,
)
from sorafs_python_package_source import authenticate_package_source
from sorafs_python_process import run_python_process
from sorafs_python_publication import PythonArtifactPublication
from sorafs_python_report_origins import verify_report_origins
from sorafs_python_producer_inputs import (
    POSIX_EXTENSION_SUFFIXES, OriginalInputs, capture_tree, child, identity,
    installed_wheel_join, native_member, source_snapshot, verifier, write_fresh,
)
from sorafs_python_runtime_custody import OriginalPythonRuntime
from sorafs_python_runtime_inputs import MAX_MANIFEST_BYTES, parse_runtime_bundle, parse_runtime_manifest

SCHEMA = "sorafs.python.consumer_artifact.v1"
TOOLS = ("build_sorafs_python_consumer_artifact.py", "sorafs_python_consumer_artifact.py",
         "sorafs_python_consumer_cases.py", "sorafs_python_producer_inputs.py",
         "sorafs_python_environment.py", "sorafs_python_process.py",
         "sorafs_python_runtime_inputs.py", "sorafs_python_runtime_custody.py",
         "sorafs_python_dependency_inputs.py", "sorafs_python_dependency_archive.py",
         "sorafs_python_dependency_install.py", "sorafs_python_package_source.py",
         "sorafs_python_publication.py", "sorafs_python_archive.py", "sorafs_python_commands.py",
         "sorafs_python_report_origins.py",
         "sorafs_evidence_json.py",
         "sorafs_evidence_paths.py", "sorafs_evidence_sensitivity.py", "sorafs_path_identity.py",
         "sorafs_sdk_artifact_index.py", "check_native_sdk_artifact.py",
         "compute_workspace_source_manifest.py", "release_manifest_signing.py")


def _produce(args: argparse.Namespace, originals: OriginalInputs, copied: OriginalInputs,
             lifetime: ExitStack) -> dict:
    """Create, execute and retain actual process observations from original inputs."""
    root, work = args.source_root, args.work_dir
    if root != Path(__file__).resolve().parents[1] or root.resolve(strict=True) != root:
        raise ArtifactError("producer must run from the selected canonical source checkout")
    if (not work.is_absolute() or work.parent.resolve(strict=True) != work.parent
            or not work.is_relative_to(root / "target") or work.exists() or work.is_symlink()):
        raise ArtifactError("work directory must be fresh beneath the selected source target/")
    commit, clean = native.source_state(root)
    if not clean:
        raise ArtifactError("Python qualification requires a clean immutable source candidate")
    if (commit != args.source_commit
            or native.workspace_source_manifest_sha256(root) != args.source_manifest_sha256):
        raise ArtifactError("source differs from the independently selected candidate")
    work.mkdir(mode=0o700)
    for name in ("home", "temporary", "logs", "inputs", "native", "snapshot", "wheels"):
        (work / name).mkdir(mode=0o700)
    retained, commands = {}, []

    def copy_input(path: Path, relative: str, maximum: int) -> bytes:
        raw = originals.read(path, maximum, hold=True)
        write_fresh(work / relative, raw)
        copied.read(work / relative, maximum, hold=True)
        return raw

    runtime_raw = copy_input(args.runtime_manifest, "inputs/runtime.json", MAX_MANIFEST_BYTES)
    runtime = parse_runtime_manifest(runtime_raw, expected_sha256=args.runtime_manifest_sha256)
    originals.read(Path(runtime.executable.path), verifier.MAX_MEMBER_BYTES, hold=True)
    for shared in runtime.shared_runtime:
        originals.read(Path(shared.path), verifier.MAX_MEMBER_BYTES, hold=True)
    dependency_raw = copy_input(args.dependency_manifest, "inputs/dependencies.json", 128 * 1024)
    dependencies = parse_dependency_manifest(dependency_raw, expected_sha256=args.dependency_manifest_sha256)
    manifest_raw = copy_input(args.native_manifest, "inputs/native-abi29.json", native.MAX_MANIFEST_BYTES)
    manifest = native.validate_manifest(decode_evidence_json(manifest_raw))
    if (native.canonical_manifest_bytes(manifest) != manifest_raw or manifest["sdk"] != "python"
            or manifest["source_commit"] != commit
            or manifest["workspace_source_manifest_sha256"] != args.source_manifest_sha256
            or commit != args.source_commit):
        raise ArtifactError("native manifest differs from the independently selected candidate")
    for name in TOOLS:
        retained["tools/" + name] = originals.read(root / "scripts" / name, 1024 * 1024)
    sources = source_snapshot(root, originals)
    for name, raw in sources.items():
        write_fresh(work / "snapshot" / name, raw)
        copied.read(work / "snapshot" / name, max(1, len(raw)))
        retained["snapshot/" + name] = raw
    requirements, wheels, parsed_wheels, package_sources = [], [], [], []
    for path, owner in ((args.native_wheel, verifier.NATIVE_OWNER), (args.sdk_wheel, verifier.SDK_OWNER)):
        raw = copy_input(path, "wheels/" + path.name, verifier.MAX_WHEEL_BYTES)
        parsed = verifier.parse_wheel_bytes(raw, owner=owner, extension_suffixes=POSIX_EXTENSION_SUFFIXES)
        package_source = authenticate_package_source(parsed, root, originals)
        parsed_wheels.append(parsed)
        package_sources.append(package_source)
        retained.update({"package-source/" + name: body for name, body in package_source.items()})
        private = work / "wheels" / path.name
        wheel = verifier.preflight_wheel(private, verifier.seal_wheel(private).render(), owner=owner,
                                        extension_suffixes=POSIX_EXTENSION_SUFFIXES)
        wheels.append(wheel)
        requirements.append((private, hashlib.sha256(raw).hexdigest()))
        if owner == verifier.NATIVE_OWNER:
            body = native_member(raw, parsed)
            if identity(body) != {"sha256": manifest["artifact_sha256"], "size": manifest["artifact_size"]}:
                raise ArtifactError("original native wheel extension differs from native manifest")
            native_path = work / "native" / Path(parsed.native_member).name
            write_fresh(native_path, body)
            copied.read(native_path, verifier.MAX_MEMBER_BYTES)
    dependency_paths, dependency_archives = {}, []
    for wheel in dependencies.wheels:
        path = Path(wheel.file.path)
        raw = copy_input(path, "wheels/" + path.name, verifier.MAX_WHEEL_BYTES)
        if identity(raw) != {"sha256": wheel.file.sha256, "size": wheel.file.size}:
            raise ArtifactError("original offline dependency differs from independent pin")
        dependency_archives.append(parse_dependency_wheel(raw, wheel=wheel))
        private = work / "wheels" / path.name
        dependency_paths[wheel.module] = private
        requirements.append((private, wheel.file.sha256))
    requirements_raw = pinned_requirements(requirements)
    write_fresh(work / "inputs/requirements.txt", requirements_raw)
    copied.read(work / "inputs/requirements.txt", 128 * 1024)

    command_catalog = execution_commands(source_root=root, work=work, runtime=runtime,
                                         pip_filename=dependency_paths["pip"].name,
                                         native_filename=native_path.name)

    def run(label: str) -> bytes:
        command = command_catalog[len(commands)]
        if command.label != label:
            raise ArtifactError("producer operation order differs from the fixed catalog")
        argv, limit = command.argv, command.stdout_limit
        result = run_python_process(argv, cwd=work, stdout_path=work / "logs" / (label + ".stdout"),
                                    stderr_path=work / "logs" / (label + ".stderr"),
                                    home=work / "home", temporary=work / "temporary",
                                    stdout_limit=limit, stderr_limit=STDERR_LIMIT, timeout_seconds=command.timeout_seconds)
        stdout = copied.read(result.stdout.path, limit)
        stderr = copied.read(result.stderr.path, STDERR_LIMIT)
        if identity(stdout) != {"sha256": result.stdout.sha256, "size": result.stdout.size} or identity(stderr) != {"sha256": result.stderr.sha256, "size": result.stderr.size}:
            raise ArtifactError("actual process output changed before consumption")
        commands.append({"label": label, "argv": list(argv), "returncode": result.returncode,
                         "stdout": identity(stdout), "stderr": identity(stderr)})
        retained["logs/" + label + ".stdout"] = stdout
        retained["logs/" + label + ".stderr"] = stderr
        if result.returncode != 0 or (command.empty_stderr and stderr):
            raise ArtifactError("owned Python operation refused: " + label + "; original logs retained")
        return stdout

    environment = work / "environment"
    selected_python = environment / "bin/python3.12"
    runtime_owner = OriginalPythonRuntime(runtime)
    lifetime.callback(runtime_owner.close)
    runtime_owner.__enter__()
    env_originals = OriginalInputs()
    lifetime.callback(env_originals.close)
    probe = run("runtime-before")
    base_runtime = verify_runtime_probe(probe, runtime)
    run("create-environment")
    environment_links = {"lib64": "lib"} if runtime.platform == "linux" and (environment / "lib64").is_symlink() else {}

    def capture_environment():
        return capture_tree(environment, env_originals, maximum=512 * 1024 * 1024,
                            maximum_file=verifier.MAX_MEMBER_BYTES, maximum_entries=16000,
                            directory_links=environment_links)

    fresh = capture_environment()
    inspect_environment(fresh, installed=False)
    bootstrap = verify_environment_bootstrap(fresh, runtime, environment)
    if set(fresh) != BOOTSTRAP_FILES:
        raise ArtifactError("new environment differs from the exact bootstrap inventory")
    env_originals.read(selected_python, verifier.MAX_MEMBER_BYTES, hold=True)
    env_originals.read(environment / "pyvenv.cfg", 64 * 1024, hold=True)
    before_env = run("environment-before")
    private_runtime = verify_runtime_probe(before_env, runtime, environment=environment)
    if private_runtime["base_prefix"] != base_runtime["base_prefix"]:
        raise ArtifactError("private environment changed the original runtime prefix")
    run("native-before")
    run("install")
    installed = capture_environment()
    inspect_environment(installed, installed=True)

    def authenticate_install(files):
        if verify_environment_bootstrap(files, runtime, environment) != bootstrap:
            raise ArtifactError("original bootstrap changed during installation or execution")
        native_sdk = tuple(verifier.verify_installed_files(wheel, verifier.derive_installed_layout(
            environment_root=environment, site_roots={environment / "lib/python3.12/site-packages"},
            wheel=wheel)) for wheel in wheels)
        content = tuple(value.content for value in native_sdk)
        dependencies = verify_dependency_install(tuple(dependency_archives), files, environment=environment,
                                                  wheel_paths_by_module=dependency_paths,
                                                  native_sdk_content=content)
        owned = BOOTSTRAP_FILES | {row.path for row in dependencies.files}
        owned |= {"lib/python3.12/site-packages/" + row.name for value in content for row in value.files}
        if set(files) != owned:
            raise ArtifactError("installed environment contains unowned files")
        return dependencies, content

    installed_dependencies, installed_contents = authenticate_install(installed)
    expected_distributions = {wheel.module: wheel.version for wheel in dependencies.wheels}
    expected_distributions.update({wheel.owner.distribution: wheel.metadata_version for wheel in wheels})
    distribution_output = run("installed-distributions")
    verify_distributions(distribution_output, expected_distributions, environment)
    execution_input = {"schema": child.INPUT_SCHEMA, "snapshot_root": str(work / "snapshot"),
                       "environment_root": str(environment),
                       "native_wheel": {"path": str(wheels[0].path), "seal": wheels[0].seal.render()},
                       "sdk_wheel": {"path": str(wheels[1].path), "seal": wheels[1].seal.render()},
                       "source_files": [{"path": name, **identity(raw)} for name, raw in sources.items()],
                       "python": {"path": str(selected_python), **identity(fresh["bin/python3.12"])}}
    input_raw = canonical_json(execution_input)
    write_fresh(work / "inputs/child.json", input_raw)
    copied.read(work / "inputs/child.json", child.MAX_INPUT)
    child.parse_input(input_raw)
    output = run("execute")
    consumed = consume_runtime_output(output, expected_input_sha256=hashlib.sha256(input_raw).hexdigest(),
                                      test_source=sources[TEST_PATH])
    for observation, wheel in zip(consumed.observations.wheels, wheels, strict=True):
        for name, raw in installed_wheel_join(observation, wheel, env_originals).items():
            retained["installed-metadata/" + name] = raw
    metadata = verify_report_origins(consumed.observations, environment=environment,
                                     snapshot=work / "snapshot", sources=sources, environment_files=installed,
                                     wheels=tuple(zip(parsed_wheels, installed_contents, strict=True)),
                                     wheel_paths=tuple(wheel.path for wheel in wheels),
                                     wheel_seals=tuple(wheel.seal for wheel in wheels), runtime=runtime)
    if any(retained.get(name) != raw for name, raw in metadata.items()):
        raise ArtifactError("live and captured report metadata origins differ")
    retained["child-report.json"] = consumed.report_bytes
    if capture_environment() != installed:
        raise ArtifactError("installed environment changed during fixed child execution")
    for name, raw in installed.items():
        retained["environment/" + name] = raw
    after_env = run("environment-after")
    if verify_runtime_probe(after_env, runtime, environment=environment) != decode_evidence_json(before_env):
        raise ArtifactError("private runtime changed during execution")
    run("native-after")
    verify_command_observations(commands, retained, expected=command_catalog)
    publication = lifetime.enter_context(PythonArtifactPublication(work))
    with publication.runtime_stream() as stream:
        runtime_bundle = runtime_owner.write_bundle(stream)
    bundle_raw = publication.read_runtime_bundle(expected_sha256=runtime_bundle.sha256,
                                                expected_size=runtime_bundle.size)
    if parse_runtime_bundle(bundle_raw, expected_manifest_sha256=runtime.sha256).manifest != runtime:
        raise ArtifactError("retained runtime bundle differs from original runtime manifest")
    for name in ("runtime.json", "dependencies.json", "native-abi29.json", "requirements.txt", "child.json"):
        retained["inputs/" + name] = copied.read(work / "inputs" / name, MAX_MANIFEST_BYTES)
    record = {"schema": SCHEMA, "consumer": "python", "scope": "posix-host-native",
              "source_commit": commit, "source_manifest_sha256": args.source_manifest_sha256,
              "runtime_manifest": identity(runtime_raw), "dependency_manifest": identity(dependency_raw),
              "runtime_bundle": asdict(runtime_bundle), "native_manifest": identity(manifest_raw),
              "environment_links": environment_links,
              "dependency_files": [asdict(row) for row in installed_dependencies.files],
              "wheels": [{"owner": wheel.owner.package, "path": str(wheel.path), "seal": wheel.seal.render()} for wheel in wheels],
              "commands": commands, "retained": {name: identity(raw) for name, raw in sorted(retained.items())}}
    retained["manifest.json"] = canonical_json(record)
    archive = execution_archive(retained)
    publication.stage_execution_archive(archive)

    def check_originals():
        # Every owner stays live through publication. No check is deferred until
        # context cleanup after a completed final artifact name becomes visible.
        if (capture_environment() != installed
                or authenticate_install(installed) != (installed_dependencies, installed_contents)):
            raise ArtifactError("installed environment changed before publication")
        for parsed, expected in zip(parsed_wheels, package_sources, strict=True):
            if authenticate_package_source(parsed, root, originals) != expected:
                raise ArtifactError("candidate package source changed before publication")
        if (source_snapshot(root, originals) != sources or native.source_state(root) != (commit, True)
                or native.workspace_source_manifest_sha256(root) != args.source_manifest_sha256):
            raise ArtifactError("candidate source changed before publication")
        runtime_owner.recheck()
        originals.recheck()
        copied.recheck()
        env_originals.recheck()

    published = publication.publish(check_originals=check_originals)
    return {"schema": SCHEMA, "artifact": str(published.execution_archive.path),
            "sha256": published.execution_archive.sha256, "size": published.execution_archive.size,
            "runtime_bundle": str(published.runtime_bundle.path),
            "cases": len(consumed.observations.cases)}


def produce(args: argparse.Namespace) -> dict:
    """Keep primary original descriptors until success or failed-operation cleanup."""
    with ExitStack() as lifetime:
        originals, copied = OriginalInputs(), OriginalInputs()
        lifetime.callback(originals.close)
        lifetime.callback(copied.close)
        return _produce(args, originals, copied, lifetime)


def main() -> int:
    """Accept fixed original artifacts and independent candidate/toolchain pins."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "work-dir", "native-wheel", "sdk-wheel", "native-manifest",
                 "runtime-manifest", "dependency-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-commit", "source-manifest-sha256", "runtime-manifest-sha256", "dependency-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    try:
        print(canonical_json(produce(parser.parse_args())).decode(), end="")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"SoraFS Python producer refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
