"""Tests for the platform-independent current Kotodama artifact owner."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "regenerate_current_rust_contract_artifact.py"
)
SPEC = importlib.util.spec_from_file_location(
    "regenerate_current_rust_contract_artifact", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader  # pragma: no cover - defensive
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _cache(tmp_path: Path) -> tuple[MODULE.BoundDirectory, Path]:
    root = tmp_path.resolve() / "portable-cache"
    root.mkdir(mode=0o755)
    return MODULE._bind_directory(root, "test cache"), root


def _output_stage(root: Path, suffix: str = "A1b2C3d4") -> Path:
    stage = root / f"current-rust-contract-artifact.{suffix}"
    stage.mkdir(mode=0o700)
    return stage


def _artifact_and_manifest() -> tuple[bytes, dict[str, object]]:
    abi_hash = bytes.fromhex("ab" * 32)
    artifact = bytearray(b"IVM\0")
    artifact.extend((1, 1, 0, 0))
    artifact.extend((0).to_bytes(8, "little"))
    artifact.append(1)
    artifact.extend(abi_hash)
    artifact.extend(b"CNTR")
    artifact.extend((1).to_bytes(4, "little"))
    artifact.extend(b"x")
    artifact.extend(b"\x00\x00\x00\x00")
    frozen = bytes(artifact)
    manifest: dict[str, object] = {
        "code_hash": f"hash:{MODULE._contract_hash(frozen).upper()}#1234",
        "abi_hash": f"hash:{abi_hash.hex().upper()}#5678",
        "entrypoints": [{"name": "run"}],
    }
    return frozen, manifest


def _closure_with_file(
    path: Path, snapshot: MODULE.FileSnapshot
) -> MODULE.SourceClosure:
    entry = MODULE.GitIndexEntry(path=path, mode="100644", object_id="a" * 40)
    record = MODULE.SourceClosureRecord(
        kind=MODULE.SOURCE_RECORD_FILE,
        path=path,
        snapshot=snapshot,
        index_entry=entry,
    )
    return MODULE.SourceClosure(
        records=(record,),
        files={path: snapshot},
        index_entries={path: entry},
        untracked_paths=frozenset(),
        package_directories=frozenset(),
        required_present_paths=frozenset({path}),
        closure_sha256=MODULE._source_record_digest((record,)),
        git_binding="test-binding",
    )


def _raw_index(
    entries: dict[Path, MODULE.GitIndexEntry],
) -> dict[Path, tuple[MODULE.GitIndexEntry, ...]]:
    return {path: (entry,) for path, entry in entries.items()}


def test_git_blob_id_matches_git_object_format() -> None:
    assert MODULE._git_blob_id(b"test content\n") == (
        "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
    )


def test_manifest_hash_accepts_only_canonical_literals() -> None:
    digest = "ab" * 32
    manifest = {"abi_hash": f"hash:{digest.upper()}#1234"}
    assert MODULE._manifest_hash(manifest, "abi_hash") == digest

    for invalid in (digest, f"hash:{digest}#1234", f"hash:{digest.upper()}"):
        with pytest.raises(MODULE.FixtureError, match="noncanonical abi_hash"):
            MODULE._manifest_hash({"abi_hash": invalid}, "abi_hash")


def test_generated_manifest_json_rejects_duplicate_keys_at_every_depth(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"outer":{"name":"a","name":"b"}}\n', encoding="utf-8")

    with pytest.raises(MODULE.FixtureError, match="duplicate object key 'name'"):
        MODULE._load_json_strict(manifest, "generated compiler manifest")


def test_semantic_expectation_derives_only_platform_independent_fields() -> None:
    artifact, manifest = _artifact_and_manifest()

    assert MODULE._semantic_expectation(artifact, manifest) == {
        "code_hash_hex": MODULE._contract_hash(artifact),
        "abi_hash_hex": "ab" * 32,
        "header_len": 49,
        "code_offset": 58,
        "entrypoint_count": 1,
    }


def test_fixture_document_has_no_host_tool_or_binary_identity() -> None:
    artifact, manifest = _artifact_and_manifest()
    provenance = {
        "scope": "semantic-worktree-source-closure-v2",
        "closure_algorithm": "sha256-framed-present-path-and-bytes-v2",
        "closure_sha256": "01" * 32,
        "file_count": 16,
        "contract_source_git_blob": "02" * 20,
        "artifact_generator_git_blob": "03" * 20,
    }

    fixture = MODULE._fixture_document(artifact, manifest, provenance)
    encoded = json.dumps(fixture, sort_keys=True)

    assert fixture["fixture_version"] == 1
    assert fixture["source_provenance"] == provenance
    assert "generation_provenance" not in fixture
    for retired in ("koto_sha256", "rustc_sha256", "ivm_rlib_sha256", "dependency"):
        assert retired not in encoded


def test_attestation_keeps_local_koto_identity_outside_fixture(tmp_path: Path) -> None:
    koto = tmp_path / "koto"
    koto.write_bytes(b"host-specific-koto")
    koto.chmod(0o700)
    koto_snapshot = MODULE._snapshot_file(koto, "koto", executable=True)
    artifact, manifest = _artifact_and_manifest()
    fixture = MODULE._fixture_document(
        artifact,
        manifest,
        {
            "scope": "semantic-worktree-source-closure-v2",
            "closure_algorithm": "sha256-framed-present-path-and-bytes-v2",
            "closure_sha256": "01" * 32,
            "file_count": 1,
            "contract_source_git_blob": "02" * 20,
            "artifact_generator_git_blob": "03" * 20,
        },
    )
    fixture_text = MODULE._render(fixture)
    git = tmp_path / "git"
    git.write_bytes(b"host-specific-git")
    git.chmod(0o700)
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_bytes(b"host-specific-lock")

    attestation = json.loads(
        MODULE._attestation(
            koto_snapshot,
            MODULE._snapshot_file(git, "git", executable=True),
            MODULE._snapshot_file(cargo_lock, "Cargo.lock"),
            {"git": "darwin-sealed-private-path", "koto": "darwin-sealed-private-path"},
            fixture_text,
            fixture,
            _closure_with_file(Path("source"), koto_snapshot),
        )
    )

    assert attestation["koto_sha256"] == MODULE._sha256(b"host-specific-koto")
    assert attestation["cargo_lock_sha256"] == MODULE._sha256(b"host-specific-lock")
    assert attestation["source_inventory"]["tracked_file_count"] == 1
    assert attestation["source_inventory"]["tracked_absent_count"] == 0
    assert attestation["source_inventory"]["untracked_file_count"] == 0
    assert attestation["darwin_executable_binding_limitation"] is not None
    assert "koto_sha256" not in fixture_text
    assert "cargo_lock_sha256" not in fixture_text


def test_write_mode_uses_an_explicit_portable_cache_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve() / "another-machine-cache"
    root.mkdir(mode=0o755)
    output = _output_stage(root) / MODULE.FIXTURE_PATH.name
    monkeypatch.setenv("IROHA_KOTODAMA_CACHE_ROOT", os.fspath(root))

    args = MODULE._parse_args(
        [
            "--write",
            "--koto",
            "koto",
            "--git",
            "git",
            "--output",
            os.fspath(output),
        ]
    )

    assert args.cache_root == root
    assert args.output == output
    assert "/Users/takemiyamakoto" not in MODULE_PATH.read_text(encoding="utf-8")


def test_git_discovery_uses_copyable_developer_tools_binary_on_macos(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_git = tmp_path / "git"
    real_git.write_bytes(b"test executable")
    real_git.chmod(0o500)

    def locate_git(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["/usr/bin/xcrun", "--find", "git"]
        assert kwargs["check"] is True
        return subprocess.CompletedProcess(command, 0, stdout=f"{real_git}\n")

    monkeypatch.setattr(MODULE.subprocess, "run", locate_git)
    selected = MODULE._default_git_path(platform="darwin")
    assert selected == real_git
    assert MODULE._resolve_input_file(selected, "Git", executable=True) == real_git

    args = MODULE._parse_args(
        ["--check", "--koto", "koto", "--cache-root", os.fspath(tmp_path.resolve())]
    )
    assert args.git is None


def test_macos_git_discovery_rejects_uncopyable_system_shim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout="/usr/bin/git\n"
        ),
    )
    with pytest.raises(MODULE.FixtureError, match="real developer-tools Git"):
        MODULE._default_git_path(platform="darwin")


def test_retired_rustc_and_rlib_arguments_are_rejected(tmp_path: Path) -> None:
    common = [
        "--check",
        "--koto",
        "koto",
        "--git",
        "git",
        "--cache-root",
        os.fspath(tmp_path.resolve()),
    ]
    for retired in ("--rustc", "--ivm-rlib"):
        with pytest.raises(SystemExit):
            MODULE._parse_args([*common, retired, "retired"])


def test_output_binding_rejects_repo_arbitrary_and_symbolic_destinations(
    tmp_path: Path,
) -> None:
    cache, root = _cache(tmp_path)
    try:
        with pytest.raises(MODULE.FixtureError, match="must be absolute"):
            MODULE._bind_output(cache, Path(MODULE.FIXTURE_PATH.name))
        with pytest.raises(MODULE.FixtureError, match="directly below"):
            MODULE._bind_output(cache, MODULE.REPOSITORY_ROOT / MODULE.FIXTURE_PATH)

        real = _output_stage(root, "Real1234")
        link = root / "current-rust-contract-artifact.Link1234"
        link.symlink_to(real, target_is_directory=True)
        with pytest.raises(MODULE.FixtureError, match="non-symbolic directory"):
            MODULE._bind_output(cache, link / MODULE.FIXTURE_PATH.name)
    finally:
        cache.close()


def test_direct_publication_creates_final_file_without_temporary_cleanup(
    tmp_path: Path,
) -> None:
    cache, root = _cache(tmp_path)
    stage_path = _output_stage(root)
    output = MODULE._bind_output(cache, stage_path / MODULE.FIXTURE_PATH.name)
    try:
        snapshot = MODULE._write_new_file(
            output,
            MODULE.FIXTURE_PATH.name,
            b"new\n",
            mode=0o644,
        )
    finally:
        output.close()
        cache.close()

    assert snapshot.data == b"new\n"
    assert [path.name for path in stage_path.iterdir()] == [MODULE.FIXTURE_PATH.name]


def test_competitor_creation_is_preserved_and_never_unlinked(tmp_path: Path) -> None:
    cache, root = _cache(tmp_path)
    stage_path = _output_stage(root)
    output = MODULE._bind_output(cache, stage_path / MODULE.FIXTURE_PATH.name)
    competitor = stage_path / MODULE.FIXTURE_PATH.name
    competitor.write_bytes(b"competitor")
    try:
        with pytest.raises(MODULE.FixtureError, match="already exists"):
            MODULE._write_new_file(output, competitor.name, b"ours", mode=0o644)
    finally:
        output.close()
        cache.close()

    assert competitor.read_bytes() == b"competitor"


def test_competitor_replacement_is_preserved_and_never_unlinked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache, root = _cache(tmp_path)
    stage_path = _output_stage(root)
    output = MODULE._bind_output(cache, stage_path / MODULE.FIXTURE_PATH.name)
    original_write = MODULE._write_all
    competitor = stage_path / MODULE.FIXTURE_PATH.name

    def replace_after_write(descriptor: int, data: bytes) -> None:
        original_write(descriptor, data)
        competitor.unlink()
        competitor.write_bytes(b"foreign replacement")

    monkeypatch.setattr(MODULE, "_write_all", replace_after_write)
    try:
        with pytest.raises(MODULE.FixtureError, match="replaced or changed"):
            MODULE._write_new_file(output, competitor.name, b"ours", mode=0o644)
    finally:
        output.close()
        cache.close()

    assert competitor.read_bytes() == b"foreign replacement"


def test_work_stage_keeps_failure_residue_for_forensics(tmp_path: Path) -> None:
    cache, _root = _cache(tmp_path)
    stage = MODULE._create_work_stage(cache)
    residue = stage.path / "partial.log"
    residue.write_text("partial", encoding="utf-8")
    stage_path = stage.path
    stage.close()
    cache.close()

    assert stage_path.is_dir()
    assert residue.read_text(encoding="utf-8") == "partial"


def test_bound_executable_drift_aborts_after_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    koto_path = tmp_path / "koto"
    koto_path.write_bytes(b"koto")
    koto_path.chmod(0o500)
    koto = MODULE._snapshot_file(koto_path, "koto", executable=True)

    def drift(
        command: object,
        *,
        environment: object,
        pass_fds: object,
    ) -> subprocess.CompletedProcess[str]:
        del command, environment, pass_fds
        koto_path.chmod(0o700)
        koto_path.write_bytes(b"changed")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(MODULE, "_run", drift)
    with pytest.raises(MODULE.FixtureError, match="changed"):
        MODULE._run_bound_executable(koto, ("--version",), environment={})


def test_linux_uses_the_held_executable_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tool_path = tmp_path / "tool"
    tool_path.write_bytes(b"tool")
    tool_path.chmod(0o500)
    tool = MODULE._snapshot_file(tool_path, "tool", executable=True)
    observed: dict[str, object] = {}

    def capture(
        command: object,
        *,
        environment: object,
        pass_fds: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.update(command=tuple(command), environment=environment, pass_fds=tuple(pass_fds))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(MODULE.sys, "platform", "linux")
    monkeypatch.setattr(MODULE, "_run", capture)
    _result, binding = MODULE._run_bound_executable(
        tool,
        ("--version",),
        environment={"PATH": "/trusted"},
    )

    executable = str(observed["command"][0])
    assert executable.startswith("/proc/self/fd/")
    assert int(executable.rsplit("/", 1)[1]) in observed["pass_fds"]
    assert observed["environment"] == {"PATH": "/trusted"}
    assert binding == "linux-proc-self-fd"


def test_hermetic_environment_drops_hostile_ambient_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache, _root = _cache(tmp_path)
    stage = MODULE._create_work_stage(cache)
    monkeypatch.setenv("PATH", "/attacker/bin")
    monkeypatch.setenv("LD_PRELOAD", "/attacker/lib.so")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/attacker/lib.dylib")
    monkeypatch.setenv("RUSTFLAGS", "--cfg attacker")
    try:
        environment = MODULE._hermetic_environment(stage)
    finally:
        stage.close()
        cache.close()

    assert environment["PATH"] == "/usr/bin:/bin"
    for hostile in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "RUSTFLAGS"):
        assert hostile not in environment
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_index_inventory_uses_only_the_explicit_authenticated_git(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    git_path = tmp_path / "exact-git"
    git_path.write_bytes(b"git")
    git_path.chmod(0o500)
    git = MODULE._snapshot_file(git_path, "exact Git", executable=True)
    observed: dict[str, object] = {}

    def enumerate_paths(
        executable: MODULE.FileSnapshot,
        arguments: object,
        *,
        environment: object,
        inherited_fds: object = (),
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        observed.update(
            executable=executable,
            arguments=tuple(arguments),
            environment=environment,
            inherited_fds=inherited_fds,
        )
        return subprocess.CompletedProcess(
            [],
            0,
            "100644 " + "a" * 40 + " 0\ttracked/file\0",
            "",
        ), "test-binding"

    monkeypatch.setattr(MODULE, "_run_bound_executable", enumerate_paths)
    entries, binding = MODULE._index_entries(git, {"PATH": "/trusted"})

    assert observed["executable"] is git
    assert observed["arguments"][-4:] == ("ls-files", "--stage", "-z", "--")
    assert observed["environment"] == {"PATH": "/trusted"}
    assert entries == {
        Path("tracked/file"): (
            MODULE.GitIndexEntry(
                path=Path("tracked/file"), mode="100644", object_id="a" * 40
            ),
        )
    }
    assert binding == "test-binding"


@pytest.mark.parametrize(
    ("entry", "path", "message"),
    [
        (
            "100644 " + "a" * 40 + " 2\tconflicted",
            Path("conflicted"),
            "unresolved stages",
        ),
        (
            "100644 " + "0" * 40 + " 0\tintent",
            Path("intent"),
            "intent-to-add",
        ),
    ],
)
def test_index_inventory_preserves_anomalies_for_relevant_path_filtering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry: str,
    path: Path,
    message: str,
) -> None:
    git_path = tmp_path / "git"
    git_path.write_bytes(b"git")
    git_path.chmod(0o500)
    git = MODULE._snapshot_file(git_path, "Git", executable=True)
    monkeypatch.setattr(
        MODULE,
        "_run_bound_executable",
        lambda *_args, **_kwargs: (
            subprocess.CompletedProcess([], 0, entry + "\0", ""),
            "test-binding",
        ),
    )

    entries, _binding = MODULE._index_entries(git, {})
    with pytest.raises(MODULE.FixtureError, match=message):
        MODULE._canonical_index_entry(entries, path)


def test_index_inventory_rejects_noncanonical_repository_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    git_path = tmp_path / "git"
    git_path.write_bytes(b"git")
    git_path.chmod(0o500)
    git = MODULE._snapshot_file(git_path, "Git", executable=True)
    monkeypatch.setattr(
        MODULE,
        "_run_bound_executable",
        lambda *_args, **_kwargs: (
            subprocess.CompletedProcess(
                [], 0, "100644 " + "a" * 40 + " 0\t../escape\0", ""
            ),
            "test-binding",
        ),
    )

    with pytest.raises(MODULE.FixtureError, match="noncanonical"):
        MODULE._index_entries(git, {})


def test_canonical_closure_is_invariant_to_tracking_and_committed_deletion(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.rs"
    source.write_bytes(b"pub fn current() {}\n")
    snapshot = MODULE._snapshot_file(source, "source")
    path = Path("crates/pkg/src/source.rs")
    entry = MODULE.GitIndexEntry(path=path, mode="100644", object_id="a" * 40)
    tracked = MODULE.SourceClosureRecord(
        MODULE.SOURCE_RECORD_FILE, path, snapshot, entry
    )
    untracked = MODULE.SourceClosureRecord(
        MODULE.SOURCE_RECORD_UNTRACKED_FILE, path, snapshot, None
    )
    absent = MODULE.SourceClosureRecord(
        MODULE.SOURCE_RECORD_ABSENT,
        Path("crates/pkg/src/deleted.rs"),
        None,
        MODULE.GitIndexEntry(
            path=Path("crates/pkg/src/deleted.rs"),
            mode="100644",
            object_id="b" * 40,
        ),
    )

    assert MODULE._source_record_digest((tracked,)) == MODULE._source_record_digest(
        (untracked,)
    )
    assert MODULE._source_record_digest((absent, tracked)) == (
        MODULE._source_record_digest((tracked,))
    )


def test_private_inventory_records_file_absent_and_untracked_states(
    tmp_path: Path,
) -> None:
    tracked_path = Path("crates/pkg/src/lib.rs")
    untracked_path = Path("crates/pkg/src/new.rs")
    absent_path = Path("crates/pkg/src/deleted.rs")
    source = tmp_path / "source.rs"
    source.write_bytes(b"source\n")
    snapshot = MODULE._snapshot_file(source, "source")
    tracked_entry = MODULE.GitIndexEntry(tracked_path, "100644", "a" * 40)
    absent_entry = MODULE.GitIndexEntry(absent_path, "100644", "b" * 40)
    records = (
        MODULE.SourceClosureRecord(
            MODULE.SOURCE_RECORD_ABSENT, absent_path, None, absent_entry
        ),
        MODULE.SourceClosureRecord(
            MODULE.SOURCE_RECORD_FILE, tracked_path, snapshot, tracked_entry
        ),
        MODULE.SourceClosureRecord(
            MODULE.SOURCE_RECORD_UNTRACKED_FILE, untracked_path, snapshot, None
        ),
    )
    closure = MODULE.SourceClosure(
        records=records,
        files={tracked_path: snapshot, untracked_path: snapshot},
        index_entries={tracked_path: tracked_entry, absent_path: absent_entry},
        untracked_paths=frozenset({untracked_path}),
        package_directories=frozenset({Path("crates/pkg")}),
        required_present_paths=frozenset(),
        closure_sha256=MODULE._source_record_digest(records),
        git_binding="test-binding",
    )

    inventory = MODULE._source_inventory_document(closure)

    assert inventory["tracked_file_count"] == 1
    assert inventory["tracked_absent_count"] == 1
    assert inventory["untracked_file_count"] == 1
    absent_document = next(
        record for record in inventory["records"] if record["kind"] == "ABSENT"
    )
    assert absent_document == {
        "kind": "ABSENT",
        "path": str(absent_path),
        "index_mode": "100644",
        "index_object_id": "b" * 40,
    }
    assert inventory["inventory_sha256"] == MODULE._sha256(
        MODULE._render(
            {key: value for key, value in inventory.items() if key != "inventory_sha256"}
        ).encode("utf-8")
    )


def test_source_closure_includes_tracked_absence_and_untracked_build_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    package = Path("crates/pkg")
    (repo / package / "src").mkdir(parents=True)
    tracked_path = package / "src/lib.rs"
    absent_path = package / "src/deleted.rs"
    untracked_path = package / "src/new.rs"
    (repo / tracked_path).write_bytes(b"tracked\n")
    (repo / untracked_path).write_bytes(b"untracked\n")
    entries = {
        tracked_path: MODULE.GitIndexEntry(tracked_path, "100644", "a" * 40),
        absent_path: MODULE.GitIndexEntry(absent_path, "100644", "b" * 40),
    }
    monkeypatch.setattr(MODULE, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(MODULE, "ROOT_INPUTS", ())
    monkeypatch.setattr(
        MODULE, "_package_source_closure", lambda _available, *_args: ({}, {package})
    )
    monkeypatch.setattr(
        MODULE, "_index_entries", lambda *_args, **_kwargs: (_raw_index(entries), "binding")
    )
    monkeypatch.setattr(
        MODULE,
        "_untracked_paths",
        lambda *_args, **_kwargs: (frozenset({untracked_path}), "binding"),
    )

    closure = MODULE._source_closure(object(), {})

    assert [(record.path, record.kind) for record in closure.records] == [
        (absent_path, MODULE.SOURCE_RECORD_ABSENT),
        (tracked_path, MODULE.SOURCE_RECORD_FILE),
        (untracked_path, MODULE.SOURCE_RECORD_UNTRACKED_FILE),
    ]
    assert set(closure.files) == {tracked_path, untracked_path}
    assert closure.untracked_paths == frozenset({untracked_path})


def test_source_closure_reauthentication_detects_absence_materialization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    package = Path("crates/pkg")
    (repo / package / "src").mkdir(parents=True)
    absent_path = package / "src/deleted.rs"
    entries = {
        absent_path: MODULE.GitIndexEntry(absent_path, "100644", "b" * 40),
    }
    monkeypatch.setattr(MODULE, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(MODULE, "ROOT_INPUTS", ())
    monkeypatch.setattr(
        MODULE, "_package_source_closure", lambda _available, *_args: ({}, {package})
    )
    monkeypatch.setattr(
        MODULE, "_index_entries", lambda *_args, **_kwargs: (_raw_index(entries), "binding")
    )
    monkeypatch.setattr(
        MODULE,
        "_untracked_paths",
        lambda *_args, **_kwargs: (frozenset(), "binding"),
    )
    authenticate_absent = MODULE._assert_path_absent
    calls = 0

    def materialize_after_first_check(path: Path, label: str) -> None:
        nonlocal calls
        authenticate_absent(path, label)
        calls += 1
        if calls == 1:
            path.write_bytes(b"appeared\n")

    monkeypatch.setattr(MODULE, "_assert_path_absent", materialize_after_first_check)

    with pytest.raises(MODULE.FixtureError, match="no longer absent"):
        MODULE._source_closure(object(), {})


def test_required_source_input_cannot_be_an_absent_index_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    required = Path("required.rs")
    entries = {
        required: MODULE.GitIndexEntry(required, "100644", "a" * 40),
    }
    monkeypatch.setattr(MODULE, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(MODULE, "ROOT_INPUTS", (required,))
    monkeypatch.setattr(
        MODULE, "_package_source_closure", lambda _available, *_args: ({}, set())
    )
    monkeypatch.setattr(
        MODULE, "_index_entries", lambda *_args, **_kwargs: (_raw_index(entries), "binding")
    )
    monkeypatch.setattr(
        MODULE,
        "_untracked_paths",
        lambda *_args, **_kwargs: (frozenset(), "binding"),
    )

    with pytest.raises(MODULE.FixtureError, match="required source closure input is absent"):
        MODULE._source_closure(object(), {})


def test_source_closure_digest_rejects_unsorted_or_duplicate_records(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.rs"
    source.write_bytes(b"source\n")
    snapshot = MODULE._snapshot_file(source, "source")

    def record(path: str) -> MODULE.SourceClosureRecord:
        relative = Path(path)
        return MODULE.SourceClosureRecord(
            MODULE.SOURCE_RECORD_UNTRACKED_FILE, relative, snapshot, None
        )

    with pytest.raises(MODULE.FixtureError, match="unique sorted paths"):
        MODULE._source_record_digest((record("z.rs"), record("a.rs")))
    with pytest.raises(MODULE.FixtureError, match="unique sorted paths"):
        MODULE._source_record_digest((record("a.rs"), record("a.rs")))


@pytest.mark.parametrize("anomaly", ["conflict", "intent"])
def test_source_closure_authentication_allows_unrelated_index_anomaly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    anomaly: str,
) -> None:
    source = tmp_path / "source.rs"
    source.write_bytes(b"source\n")
    path = Path("required.rs")
    closure = _closure_with_file(path, MODULE._snapshot_file(source, "source"))
    unrelated = Path("docs/unrelated.md")
    index_now = _raw_index(closure.index_entries)
    if anomaly == "conflict":
        index_now[unrelated] = (
            MODULE.GitIndexEntry(unrelated, "100644", "b" * 40, stage=1),
            MODULE.GitIndexEntry(unrelated, "100644", "c" * 40, stage=2),
            MODULE.GitIndexEntry(unrelated, "100644", "d" * 40, stage=3),
        )
    else:
        index_now[unrelated] = (
            MODULE.GitIndexEntry(unrelated, "100644", "0" * 40),
        )
    monkeypatch.setattr(
        MODULE, "_index_entries", lambda *_args, **_kwargs: (index_now, "test-binding")
    )
    monkeypatch.setattr(
        MODULE,
        "_untracked_paths",
        lambda *_args, **_kwargs: (frozenset(), "test-binding"),
    )

    MODULE._authenticate_source_closure(closure, object(), {})


@pytest.mark.parametrize("change", ["modify", "add", "conflict", "intent"])
def test_source_closure_authentication_rejects_relevant_index_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    change: str,
) -> None:
    source = tmp_path / "source.rs"
    source.write_bytes(b"source\n")
    path = Path("crates/pkg/src/lib.rs")
    base = _closure_with_file(path, MODULE._snapshot_file(source, "source"))
    closure = MODULE.SourceClosure(
        records=base.records,
        files=base.files,
        index_entries=base.index_entries,
        untracked_paths=base.untracked_paths,
        package_directories=frozenset({Path("crates/pkg")}),
        required_present_paths=base.required_present_paths,
        closure_sha256=base.closure_sha256,
        git_binding=base.git_binding,
    )
    index_now = _raw_index(closure.index_entries)
    if change == "modify":
        index_now[path] = (MODULE.GitIndexEntry(path, "100644", "c" * 40),)
    elif change == "add":
        added = Path("crates/pkg/src/new.rs")
        index_now[added] = (MODULE.GitIndexEntry(added, "100644", "d" * 40),)
    elif change == "conflict":
        index_now[path] = (
            MODULE.GitIndexEntry(path, "100644", "a" * 40, stage=1),
            MODULE.GitIndexEntry(path, "100644", "b" * 40, stage=2),
            MODULE.GitIndexEntry(path, "100644", "c" * 40, stage=3),
        )
    else:
        index_now[path] = (MODULE.GitIndexEntry(path, "100644", "0" * 40),)
    monkeypatch.setattr(
        MODULE, "_index_entries", lambda *_args, **_kwargs: (index_now, "test-binding")
    )
    monkeypatch.setattr(
        MODULE,
        "_untracked_paths",
        lambda *_args, **_kwargs: (frozenset(), "test-binding"),
    )

    expected = {
        "modify": "index-stage inventory changed",
        "add": "index-stage inventory changed",
        "conflict": "unresolved stages",
        "intent": "intent-to-add",
    }[change]
    with pytest.raises(MODULE.FixtureError, match=expected):
        MODULE._authenticate_source_closure(closure, object(), {})


@pytest.mark.parametrize("source_mutation", [None, "replace", "mutate"])
def test_koto_selects_the_authenticated_sealed_ko_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_mutation: str | None,
) -> None:
    cache, _root = _cache(tmp_path)
    stage = MODULE._create_work_stage(cache)
    sealed_path = stage.path / "sealed-inputs"
    sealed_path.mkdir(mode=0o700)
    source_path = sealed_path / "source.ko"
    source_path.write_bytes(b"seiyaku A {}\n")
    source_path.chmod(0o400)
    koto_path = sealed_path / "koto"
    koto_path.write_bytes(b"koto")
    koto_path.chmod(0o500)
    sealed_path.chmod(0o500)
    sealed = MODULE._bind_directory(sealed_path, "sealed inputs", exact_mode=0o500)
    source = MODULE._snapshot_file(source_path, "source")
    koto = MODULE._snapshot_file(koto_path, "koto", executable=True)
    observed_sources: list[bytes] = []
    artifact, manifest = _artifact_and_manifest()

    def run_koto(
        executable: MODULE.FileSnapshot,
        arguments: object,
        *,
        environment: object,
        inherited_fds: object = (),
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        del executable, environment
        assert tuple(inherited_fds) == ()
        arguments = tuple(arguments)
        selected_source = Path(arguments[-1])
        assert selected_source == source.path
        assert selected_source.parent == sealed.path
        assert selected_source.suffix == ".ko"
        assert not selected_source.is_symlink()
        observed_sources.append(selected_source.read_bytes())
        if source_mutation == "replace":
            sealed_path.chmod(0o700)
            source_path.rename(sealed_path / "replaced.ko")
            source_path.write_bytes(source.data)
            source_path.chmod(0o400)
            sealed_path.chmod(0o500)
        elif source_mutation == "mutate":
            source_path.chmod(0o600)
            source_path.write_bytes(b"seiyaku B {}\n")
            source_path.chmod(0o400)
        if arguments[0] == "build":
            artifact_path = Path(arguments[arguments.index("--out") + 1])
            manifest_path = Path(arguments[arguments.index("--manifest-out") + 1])
            artifact_path.write_bytes(artifact)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return subprocess.CompletedProcess([], 0, "", ""), "test-binding"

    monkeypatch.setattr(MODULE, "_run_bound_executable", run_koto)
    try:
        if source_mutation is not None:
            with pytest.raises(MODULE.FixtureError, match="changed"):
                MODULE._build_artifact(koto, source, sealed, stage, {})
            assert observed_sources == [source.data]
            return
        generated, generated_manifest, binding = MODULE._build_artifact(
            koto,
            source,
            sealed,
            stage,
            {},
        )
    finally:
        sealed.close()
        stage.close()
        cache.close()

    assert observed_sources == [source.data, source.data]
    assert generated == artifact
    assert generated_manifest == manifest
    assert binding == "test-binding"


def test_current_koto_closure_covers_cli_compiler_abi_and_admission_inputs() -> None:
    """Follow actual Cargo manifests so another CLI split cannot silently omit its producer."""
    repo = MODULE.REPOSITORY_ROOT
    available = frozenset(
        {Path("Cargo.toml")}
        | {
            manifest.relative_to(repo)
            for tree in ("crates", "vendor")
            for manifest in (repo / tree).rglob("Cargo.toml")
        }
    )
    manifests, packages = MODULE._package_source_closure(available)
    expected_packages = {
        Path("crates/kotodama_toolchain"),
        Path("crates/kotodama_lang"),
        Path("crates/ivm"),
        Path("crates/ivm_abi"),
        Path("crates/ivm_artifact_admission"),
        Path("crates/iroha_data_model"),
    }
    assert expected_packages <= packages
    assert {package / "Cargo.toml" for package in expected_packages} <= set(manifests)

    producer_inputs = {
        Path("crates/kotodama_toolchain/src/bin/koto.rs"),
        Path("crates/kotodama_lang/src/compiler.rs"),
        Path("crates/kotodama_lang/grammar/v1.lex"),
        Path("crates/ivm/src/lib.rs"),
        Path("crates/ivm_abi/src/metadata.rs"),
        Path("crates/ivm_artifact_admission/src/lib.rs"),
        Path("crates/iroha_data_model/src/smart_contract.rs"),
    }
    assert all((repo / path).is_file() for path in producer_inputs)
    non_build_inputs = {
        package / tree / "developer_only.rs"
        for package in expected_packages
        for tree in ("tests", "examples", "benches", "fuzz", "docs")
    } | {Path("tools/unrelated/src/lib.rs")}
    assert MODULE._build_package_paths(
        producer_inputs | non_build_inputs, packages
    ) == frozenset(producer_inputs)


def test_default_package_closure_binds_the_current_koto_producer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path.resolve() / "repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        "[workspace]\n[workspace.dependencies]\n"
        "ivm = { path = 'crates/ivm' }\n"
        "kotodama_lang = { path = 'crates/kotodama_lang' }\n"
        "ivm_artifact_admission = { path = 'crates/ivm_artifact_admission' }\n",
        encoding="utf-8",
    )
    dependencies = {
        "kotodama_toolchain": (
            "[[bin]]\nname='koto'\npath='src/bin/koto.rs'\n"
            "[dependencies]\nivm.workspace=true\nkotodama_lang.workspace=true\n"
        ),
        "ivm": "[dependencies]\nivm_artifact_admission.workspace=true\n",
        "kotodama_lang": "",
        "ivm_artifact_admission": "",
    }
    for name, dependency_table in dependencies.items():
        package = repo / f"crates/{name}"
        package.mkdir(parents=True)
        (package / "Cargo.toml").write_text(
            f"[package]\nname='{name}'\nversion='0.1.0'\n{dependency_table}",
            encoding="utf-8",
        )
    available = frozenset(
        {Path("Cargo.toml")}
        | {Path(f"crates/{name}/Cargo.toml") for name in dependencies}
    )
    monkeypatch.setattr(MODULE, "REPOSITORY_ROOT", repo)

    # Keep the production ROOT_PACKAGES: an obsolete IVM root misses both the
    # executable owner and compiler even though admission remains reachable.
    snapshots, packages = MODULE._package_source_closure(available)

    assert packages == {Path(f"crates/{name}") for name in dependencies}
    assert set(snapshots) == set(available)
    assert MODULE._is_build_package_path(
        Path("crates/kotodama_toolchain/src/bin/koto.rs"), packages
    )
    assert MODULE._is_build_package_path(
        Path("crates/kotodama_lang/src/lib.rs"), packages
    )
    assert not MODULE._is_build_package_path(
        Path("crates/kotodama_lang/tests/parser.rs"), packages
    )


def test_local_package_closure_follows_workspace_build_and_patch_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path.resolve() / "repo"
    (repo / "crates/root").mkdir(parents=True)
    (repo / "crates/dep").mkdir(parents=True)
    (repo / "crates/build-dep").mkdir(parents=True)
    (repo / "crates/dev-only").mkdir(parents=True)
    (repo / "vendor/patched").mkdir(parents=True)
    (repo / "vendor/patch-dep").mkdir(parents=True)
    (repo / "Cargo.toml").write_text(
        "[workspace]\n[workspace.dependencies]\ndep = { path = 'crates/dep' }\n"
        "[patch.crates-io]\npatched = { path = 'vendor/patched' }\n",
        encoding="utf-8",
    )
    (repo / "crates/root/Cargo.toml").write_text(
        "[package]\nname='root'\nversion='0.1.0'\n"
        "[dependencies]\ndep.workspace=true\n"
        "[build-dependencies]\nbuild-dep={path='../build-dep'}\n"
        "[dev-dependencies]\ndev-only={path='../dev-only'}\n",
        encoding="utf-8",
    )
    for name in ("dep", "build-dep", "dev-only"):
        (repo / f"crates/{name}/Cargo.toml").write_text(
            f"[package]\nname='{name}'\nversion='0.1.0'\n",
            encoding="utf-8",
        )
    (repo / "vendor/patched/Cargo.toml").write_text(
        "[package]\nname='patched'\nversion='0.1.0'\n"
        "[dependencies]\npatch-dep={path='../patch-dep'}\n",
        encoding="utf-8",
    )
    (repo / "vendor/patch-dep/Cargo.toml").write_text(
        "[package]\nname='patch-dep'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    tracked = frozenset(
        {
            Path("Cargo.toml"),
            Path("crates/root/Cargo.toml"),
            Path("crates/dep/Cargo.toml"),
            Path("crates/build-dep/Cargo.toml"),
            Path("crates/dev-only/Cargo.toml"),
            Path("vendor/patched/Cargo.toml"),
            Path("vendor/patch-dep/Cargo.toml"),
        }
    )
    monkeypatch.setattr(MODULE, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(MODULE, "ROOT_PACKAGES", (Path("crates/root"),))

    snapshots, packages = MODULE._package_source_closure(tracked)

    assert packages == {
        Path("crates/root"),
        Path("crates/dep"),
        Path("crates/build-dep"),
        Path("vendor/patched"),
        Path("vendor/patch-dep"),
    }
    assert set(snapshots) == {
        Path("Cargo.toml"),
        Path("crates/root/Cargo.toml"),
        Path("crates/dep/Cargo.toml"),
        Path("crates/build-dep/Cargo.toml"),
        Path("vendor/patched/Cargo.toml"),
        Path("vendor/patch-dep/Cargo.toml"),
    }


@pytest.mark.parametrize(
    "packages",
    [
        (Path("crates/outer"), Path("crates/outer/nested")),
        (Path("crates/outer/nested"), Path("crates/outer")),
    ],
)
def test_build_package_paths_use_the_deepest_nested_owner(
    packages: tuple[Path, Path],
) -> None:
    paths = {
        Path("crates/outer/src/lib.rs"),
        Path("crates/outer/tests/outer.rs"),
        Path("crates/outer/nested/src/lib.rs"),
        Path("crates/outer/nested/tests/nested.rs"),
        Path("crates/unrelated/src/lib.rs"),
    }

    assert MODULE._build_package_paths(paths, packages) == frozenset(
        {
            Path("crates/outer/src/lib.rs"),
            Path("crates/outer/nested/src/lib.rs"),
        }
    )


def test_check_rejects_duplicates_before_reporting_staleness(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    fixture.write_text('{"old":true,"old":false}\n', encoding="utf-8")

    with pytest.raises(MODULE.FixtureError, match="duplicate object key 'old'"):
        MODULE._check('{"new":true}\n', fixture)


def test_check_compares_and_authenticates_one_file_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture.json"
    expected = '{"stable":true}\n'
    fixture.write_text(expected, encoding="utf-8")
    original_snapshot = MODULE._snapshot_file
    changed = False

    def snapshot_then_replace(
        path: Path,
        label: str,
        *,
        executable: bool = False,
    ) -> MODULE.FileSnapshot:
        nonlocal changed
        snapshot = original_snapshot(path, label, executable=executable)
        if label == "checked-in fixture" and not changed:
            path.write_text('{"replacement":true}\n', encoding="utf-8")
            changed = True
        return snapshot

    monkeypatch.setattr(MODULE, "_snapshot_file", snapshot_then_replace)
    with pytest.raises(MODULE.FixtureError, match="changed after it was snapshotted"):
        MODULE._check(expected, fixture)


def test_check_reports_stale_fixture_diff(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    fixture.write_text('{"old": true}\n', encoding="utf-8")

    with pytest.raises(MODULE.FixtureError, match="fixture is stale") as raised:
        MODULE._check('{"new": true}\n', fixture)

    assert '"old": true' in str(raised.value)
    assert '"new": true' in str(raised.value)


def _static_local_javascript_imports(source: str) -> list[str]:
    """Find static ESM edges, ignoring comments, literals, and dynamic imports."""
    identifier = r"[\w$]+"
    namespace = rf"\*\s+as\s+{identifier}"
    bindings = rf"(?:\{{[^{{}}]*\}}|{namespace})"
    clause = rf"(?:{bindings}|{identifier}(?:\s*,\s*{bindings})?)"
    declaration = (
        rf"(?:\bimport\s+(?:{clause}\s+from\s+)?"
        rf"|\bexport\s+(?:\{{[^{{}}]*\}}|\*(?:\s+as\s+{identifier})?)\s+from\s+)"
        r"(?P<quote>['\"])(?P<specifier>[^'\"\r\n]+)(?P=quote)"
    )
    tokens = re.compile(
        r"//[^\n]*|/\*[\s\S]*?\*/|`(?:\\.|[^`\\])*`"
        r"|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|" + declaration
    )
    return [
        match["specifier"]
        for match in tokens.finditer(source)
        if match["specifier"] is not None and match["specifier"].startswith(".")
    ]


def test_static_javascript_import_scanner_handles_module_forms() -> None:
    source = """
        import './side-effect.js';
        import Default from "./default.js";
        import { first,
 second as renamed } from './named.js';
        import * as namespace from './namespace.js';
        import Default, { named } from './combined.js';
        export { original as forwarded } from './reexport.js';
        export * from './all.js';
        export * as group from './group.js';
        import { external } from 'external-package';
        // import ignored from './comment.js';
        /* export * from './block-comment.js'; */
        const text = "import ignored from './string.js'";
        const template = `export * from './template.js'`;
        import('./dynamic.js');
        import.meta.url;
    """
    assert _static_local_javascript_imports(source) == [
        './side-effect.js', './default.js', './named.js', './namespace.js',
        './combined.js', './reexport.js', './all.js', './group.js',
    ]


def test_compiler_metadata_parser_dependencies_have_source_custody() -> None:
    root = Path(__file__).resolve().parents[2]
    source_root = Path("javascript/iroha_js/src")
    pending = [
        source_root / "ivmArtifact.js",
        source_root / "kotodamaCompiler/normalize.js",
    ]
    discovered: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in discovered:
            continue
        assert path.is_relative_to(source_root), f"parser import escaped SDK source: {path}"
        assert path.suffix == ".js", f"parser dependency must be an explicit JS file: {path}"
        discovered.add(path)
        for specifier in _static_local_javascript_imports((root / path).read_text(encoding="utf-8")):
            dependency = (root / path.parent / specifier).resolve().relative_to(root.resolve())
            pending.append(dependency)

    declared = {path for path in MODULE.ROOT_INPUTS if path.is_relative_to(source_root)}
    assert discovered == declared
    manifest = MODULE.tomllib.loads((root / "generated-files.toml").read_text(encoding="utf-8"))
    owners = [entry for entry in manifest["generated"] if str(MODULE.FIXTURE_PATH) in entry["outputs"]]
    assert len(owners) == 1
    owned = {Path(path) for path in owners[0]["inputs"] if Path(path).is_relative_to(source_root)}
    assert discovered == owned
