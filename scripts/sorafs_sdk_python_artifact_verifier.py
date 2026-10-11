"""Consume original indexed Python artifacts and their exact captured observations.

Requires the original index owner, a clean independently selected source checkout,
and separately approved runtime/dependency manifest digests. Historical producer
paths are labels only. This verifies content and observation consistency; it does
not authenticate a producer, rerun a process, or authorize signed SF11 promotion.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

import check_native_sdk_artifact as native
from build_sorafs_python_consumer_artifact import SCHEMA, TOOLS
from sorafs_evidence_json import decode_evidence_json
from sorafs_python_archive import MAX_ARCHIVE_BYTES, archive_members
from sorafs_python_commands import execution_commands, verify_command_observations
from sorafs_python_consumer_artifact import (
    ArtifactError, _digest, _object, _path, _require, canonical_json, consume_runtime_output,
)
from sorafs_python_consumer_cases import TEST_PATH
from sorafs_python_dependency_archive import parse_dependency_wheel
from sorafs_python_dependency_inputs import parse_dependency_manifest
from sorafs_python_dependency_install import SITE, verify_dependency_install
from sorafs_python_environment import (
    BOOTSTRAP_FILES, inspect_environment, pinned_requirements, verify_distributions,
    verify_environment_bootstrap, verify_runtime_probe,
)
from sorafs_python_package_source import authenticate_package_source
from sorafs_python_producer_inputs import (
    POSIX_EXTENSION_SUFFIXES, OriginalInputs, child, identity, native_member,
    source_snapshot, verifier,
)
from sorafs_python_report_origins import verify_report_origins
from sorafs_python_runtime_inputs import MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES, parse_runtime_bundle, parse_runtime_manifest
from sorafs_sdk_artifact_index import OpenedIndexFiles, PackageIndex

FIELDS = {"schema", "consumer", "scope", "source_commit", "source_manifest_sha256",
          "runtime_manifest", "dependency_manifest", "runtime_bundle", "native_manifest",
          "environment_links", "dependency_files", "wheels", "commands", "retained"}


def _same(raw: bytes, value: object, label: str) -> None:
    expected = _object(value, {"sha256", "size"}, label)
    _require(type(expected["size"]) is int and identity(raw) == expected,
             label + " differs from original bytes")


def _candidate(root: Path, index: PackageIndex) -> None:
    _require(root.is_absolute() and root.resolve(strict=True) == root,
             "trusted Python source root is not canonical")
    _require(native.source_state(root) == (index.source_commit, True)
             and native.workspace_source_manifest_sha256(root) == index.workspace_source_manifest_sha256,
             "trusted Python source differs from the clean selected candidate")


def _layout(inputs: dict, commands: object) -> tuple[Path, Path]:
    """Derive historical labels without resolving or opening those locations."""
    environment = Path(inputs["environment_root"])
    work = environment.parent
    _require(environment.name == "environment" and inputs["snapshot_root"] == str(work / "snapshot")
             and inputs["python"]["path"] == str(environment / "bin/python3.12"),
             "child paths differ from the sole private producer layout")
    _require(type(commands) is list and len(commands) == 9, "Python command count differs")
    row = _object(commands[3], {"label", "argv", "returncode", "stdout", "stderr"}, "native command")
    argv = row["argv"]
    _require(type(argv) is list and len(argv) == 13, "native command argv shape differs")
    source = Path(_path(argv[10], absolute=True))
    return work, source


def _environment(files: dict[str, bytes], runtime, environment: Path, dependency_rows, contents) -> None:
    """Admit the complete fixed venv image; generated activation files never execute."""
    inspect_environment(files, installed=True)
    bootstrap = verify_environment_bootstrap(files, runtime, environment)
    installed = {row.path for row in dependency_rows}
    installed.update(SITE + row.name for content in contents for row in content.files)
    _require(not {name.casefold() for name in installed}.intersection(name.casefold() for name in BOOTSTRAP_FILES)
             and set(files) == set(bootstrap) | installed, "retained environment has missing or unowned files")


@dataclass(frozen=True)
class PythonConsumerObservations:
    """Rechecked scoped observations; no physical file or release approval authority."""
    artifact_sha256: str
    execution_sha256: str
    source_commit: str
    source_manifest_sha256: str
    runtime_manifest_sha256: str
    dependency_manifest_sha256: str
    native_wheel_sha256: str
    native_artifact_sha256: str
    cases: tuple[tuple[str, tuple[str, ...]], ...]


def verify_python_consumer(index: PackageIndex, opened: OpenedIndexFiles, *,
                           trusted_source_root: Path, expected_runtime_manifest_sha256: str,
                           expected_dependency_manifest_sha256: str) -> PythonConsumerObservations:
    """Join all twenty original inputs, exact execution bytes and trusted source."""
    _require(type(index) is PackageIndex and type(opened) is OpenedIndexFiles and opened.index is index,
             "Python adapter requires the same original indexed file owner")
    _digest(expected_runtime_manifest_sha256)
    _digest(expected_dependency_manifest_sha256)
    _candidate(trusted_source_root, index)
    consumer = index.consumer("python")
    _require(len(consumer.inputs) == 20, "Python requires exactly twenty original input roles")
    members = archive_members(opened.read(consumer.execution, MAX_ARCHIVE_BYTES))
    _require("manifest.json" in members, "Python execution manifest is absent")
    manifest = _object(decode_evidence_json(members["manifest.json"]), FIELDS, "Python manifest")
    _require(canonical_json(manifest) == members["manifest.json"], "Python manifest is not canonical")
    _require((manifest["schema"], manifest["consumer"], manifest["scope"], manifest["source_commit"],
              manifest["source_manifest_sha256"]) ==
             (SCHEMA, "python", "posix-host-native", index.source_commit, index.workspace_source_manifest_sha256),
             "Python artifact belongs to a different consumer or candidate")
    retained = manifest["retained"]
    _require(type(retained) is dict and set(retained) == members.keys() - {"manifest.json"},
             "Python retained inventory has missing or extra members")
    for name, expected in retained.items():
        _same(members[name], expected, "retained " + name)
    references = tuple(index.file(path) for path in consumer.inputs)
    used = set()

    def original(expected: object, label: str, maximum: int) -> bytes:
        expected = _object(expected, {"sha256", "size"}, label)
        _digest(expected["sha256"])
        _require(type(expected["size"]) is int and 0 < expected["size"] <= maximum,
                 label + " byte bound")
        matches = [row for row in references if (row.sha256, row.size) == (expected["sha256"], expected["size"])]
        _require(len(matches) == 1 and matches[0].path not in used,
                 label + " has no unique unconsumed original indexed role")
        used.add(matches[0].path)
        return opened.read(matches[0].path, maximum)

    expected_members = {"manifest.json"}
    def retained_original(name: str, role: str, maximum: int) -> bytes:
        raw = original(manifest[role], role, maximum)
        _require(members.get(name) == raw, role + " differs from retained original")
        expected_members.add(name)
        return raw

    runtime_raw = retained_original("inputs/runtime.json", "runtime_manifest", MAX_MANIFEST_BYTES)
    runtime = parse_runtime_manifest(runtime_raw, expected_sha256=expected_runtime_manifest_sha256)
    bundle = parse_runtime_bundle(original(manifest["runtime_bundle"], "runtime bundle", MAX_BUNDLE_BYTES),
                                  expected_manifest_sha256=expected_runtime_manifest_sha256)
    _require(bundle.manifest == runtime, "runtime bundle and selected manifest differ")
    dependency_raw = retained_original("inputs/dependencies.json", "dependency_manifest", 64 * 1024)
    dependencies = parse_dependency_manifest(dependency_raw, expected_sha256=expected_dependency_manifest_sha256)
    native_raw = retained_original("inputs/native-abi29.json", "native_manifest", native.MAX_MANIFEST_BYTES)
    native_manifest = native.validate_manifest(decode_evidence_json(native_raw))
    _require(native.canonical_manifest_bytes(native_manifest) == native_raw
             and native_manifest["sdk"] == "python" and native_manifest["source_commit"] == index.source_commit
             and native_manifest["workspace_source_manifest_sha256"] == index.workspace_source_manifest_sha256,
             "native manifest differs from selected Python candidate")
    target_suffix = "-apple-darwin" if runtime.platform == "darwin" else "-unknown-linux-gnu"
    _require(native_manifest["target"] in tuple(arch + target_suffix for arch in ("aarch64", "x86_64")),
             "native target differs from the POSIX runtime profile")
    _require("inputs/child.json" in members, "original child input is absent")
    inputs = child.parse_input_content(members["inputs/child.json"])
    work, recorded_source = _layout(inputs, manifest["commands"])
    environment = work / "environment"
    files = {name.removeprefix("environment/"): raw for name, raw in members.items() if name.startswith("environment/")}
    wheel_rows = manifest["wheels"]
    _require(type(wheel_rows) is list and len(wheel_rows) == 2, "both original wheels are required")
    parsed, contents, paths, seals, raw_wheels = [], [], [], [], []
    for number, (entry, owner, child_key) in enumerate(zip(wheel_rows, (verifier.NATIVE_OWNER, verifier.SDK_OWNER),
                                                         ("native_wheel", "sdk_wheel"), strict=True)):
        entry = _object(entry, {"owner", "path", "seal"}, "original wheel")
        path = Path(_path(entry["path"], absolute=True))
        _require(type(entry["seal"]) is str and len(entry["seal"]) <= 512, "wheel seal observation exceeds its bound")
        seal = verifier.FileSeal.parse(entry["seal"])
        _require(entry["owner"] == owner.package and path.parent == work / "wheels" and path.suffix == ".whl"
                 and inputs[child_key] == {"path": str(path), "seal": seal.render()},
                 "wheel observation differs from fixed original child input")
        raw = (original({"sha256": seal.sha256, "size": seal.size}, "native wheel", verifier.MAX_WHEEL_BYTES)
               if number == 0 else opened.read(consumer.artifact, verifier.MAX_WHEEL_BYTES))
        _same(raw, {"sha256": seal.sha256, "size": seal.size}, "wheel seal content")
        wheel = verifier.parse_wheel_bytes(raw, owner=owner, extension_suffixes=POSIX_EXTENSION_SUFFIXES)
        _require(wheel.metadata_version == consumer.version, "wheel version differs from indexed SDK version")
        installed = {name.removeprefix(SITE): body for name, body in files.items()
                     if name.startswith((SITE + owner.package + "/", SITE + wheel.dist_info_root + "/"))}
        content = verifier.verify_installed_wheel_bytes(wheel, source_uri=path.as_uri(), wheel_sha256=seal.sha256,
                                                       installed_files=installed)
        parsed.append(wheel); contents.append(content); paths.append(path); seals.append(seal); raw_wheels.append(raw)
    _require(paths[0] != paths[1], "native and SDK wheel locations alias")
    body = native_member(raw_wheels[0], parsed[0])
    _same(body, {"sha256": native_manifest["artifact_sha256"], "size": native_manifest["artifact_size"]}, "native extension")
    archives, dependency_paths = [], {}
    for wheel in dependencies.wheels:
        raw = original({"sha256": wheel.file.sha256, "size": wheel.file.size}, "dependency " + wheel.module, verifier.MAX_WHEEL_BYTES)
        archives.append(parse_dependency_wheel(raw, wheel=wheel))
        dependency_paths[wheel.module] = work / "wheels" / PurePosixPath(wheel.file.path).name
    requirements = pinned_requirements([(path, seal.sha256) for path, seal in zip(paths, seals, strict=True)]
                                      + [(dependency_paths[wheel.module], wheel.file.sha256) for wheel in dependencies.wheels])
    _require(members.get("inputs/requirements.txt") == requirements, "offline requirements differ from original wheel pins")
    installed = verify_dependency_install(tuple(archives), files, environment=environment,
                                         wheel_paths_by_module=dependency_paths, native_sdk_content=tuple(contents))
    _require(canonical_json(manifest["dependency_files"]) == canonical_json([asdict(row) for row in installed.files]),
             "dependency observations differ from original bytes")
    _environment(files, runtime, environment, installed.files, contents)
    allowed_links = ({}, {"lib64": "lib"}) if runtime.platform == "linux" else ({},)
    _require(manifest["environment_links"] in allowed_links, "environment directory aliases differ")
    catalog = execution_commands(source_root=recorded_source, work=work, runtime=runtime,
                                 pip_filename=dependency_paths["pip"].name, native_filename=Path(parsed[0].native_member).name)
    verify_command_observations(manifest["commands"], members, expected=catalog)
    base = verify_runtime_probe(members["logs/runtime-before.stdout"], runtime)
    before = verify_runtime_probe(members["logs/environment-before.stdout"], runtime, environment=environment)
    after = verify_runtime_probe(members["logs/environment-after.stdout"], runtime, environment=environment)
    _require(before == after and base["base_prefix"] == before["base_prefix"], "runtime changed across original execution")
    _require(all(members["logs/" + name + ".stdout"] == b"" for name in ("create-environment", "native-before", "native-after")),
             "silent producer operations contain unowned output")
    versions = {wheel.module: wheel.version for wheel in dependencies.wheels}
    versions.update({wheel.owner.distribution: wheel.metadata_version for wheel in parsed})
    verify_distributions(members["logs/installed-distributions.stdout"], versions, environment)
    with OriginalInputs() as trusted:
        sources = source_snapshot(trusted_source_root, trusted)
        selected = {"snapshot/" + name: raw for name, raw in sources.items()}
        selected.update({"tools/" + name: trusted.read(trusted_source_root / "scripts" / name, 1024 * 1024) for name in TOOLS})
        package_sources = tuple(authenticate_package_source(wheel, trusted_source_root, trusted) for wheel in parsed)
        for package_source in package_sources:
            selected.update({"package-source/" + name: raw for name, raw in package_source.items()})
        _require(all(members.get(name) == raw for name, raw in selected.items()), "archived tools/source/fixtures differ from selected candidate")
        expected_input = {"schema": child.INPUT_SCHEMA, "snapshot_root": str(work / "snapshot"),
                          "environment_root": str(environment), "native_wheel": inputs["native_wheel"], "sdk_wheel": inputs["sdk_wheel"],
                          "source_files": [{"path": name, **identity(raw)} for name, raw in sources.items()],
                          "python": {"path": str(environment / "bin/python3.12"), **identity(bundle.member_bytes(runtime.executable.path))}}
        _require(canonical_json(expected_input) == members["inputs/child.json"], "child input differs from independently reconstructed originals")
        consumed = consume_runtime_output(members["logs/execute.stdout"], expected_input_sha256=identity(members["inputs/child.json"])["sha256"],
                                          test_source=sources[TEST_PATH])
        _require(members.get("child-report.json") == consumed.report_bytes, "retained child report differs from actual output frame")
        metadata = verify_report_origins(consumed.observations, environment=environment, snapshot=work / "snapshot", sources=sources,
                                         environment_files=files, wheels=tuple(zip(parsed, contents, strict=True)),
                                         wheel_paths=tuple(paths), wheel_seals=tuple(seals), runtime=runtime)
        _require(all(members.get(name) == raw for name, raw in metadata.items()), "retained installed metadata differs from original relation")
        expected_members.update(selected)
        expected_members.update(metadata)
        expected_members.update("environment/" + name for name in files)
        expected_members.update("logs/" + command.label + "." + stream for command in catalog for stream in ("stdout", "stderr"))
        expected_members.update({"inputs/requirements.txt", "inputs/child.json", "child-report.json"})
        _require(set(members) == expected_members and used == set(consumer.inputs), "Python inventory contains unconsumed originals or members")
        _require(source_snapshot(trusted_source_root, trusted) == sources, "trusted source inventory changed during replay")
        _require(tuple(authenticate_package_source(wheel, trusted_source_root, trusted) for wheel in parsed) == package_sources,
                 "trusted package build selection changed during replay")
        _candidate(trusted_source_root, index)
        trusted.recheck()
        opened.recheck()
    return PythonConsumerObservations(index.file(consumer.artifact).sha256, index.file(consumer.execution).sha256,
                                      index.source_commit, index.workspace_source_manifest_sha256,
                                      runtime.sha256, dependencies.sha256, seals[0].sha256, native_manifest["artifact_sha256"],
                                      tuple((case.nodeid, tuple(phase.phase for phase in case.phases)) for case in consumed.observations.cases))
