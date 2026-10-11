"""Tests for the affected-package Rust CI router."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rust_ci.py"
SPEC = importlib.util.spec_from_file_location("rust_ci", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rust_ci = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rust_ci
SPEC.loader.exec_module(rust_ci)


def _metadata(root: Path) -> dict[str, Any]:
    """Return a small Cargo metadata graph: base <- node <- integration."""

    packages = []
    members = []
    for name in ("base", "node", "integration"):
        package_id = f"path+file:///{name}#0.1.0"
        members.append(package_id)
        packages.append(
            {
                "id": package_id,
                "name": name,
                "manifest_path": str(root / "crates" / name / "Cargo.toml"),
            }
        )
    return {
        "workspace_members": members,
        "packages": packages,
        "resolve": {
            "nodes": [
                {"id": members[0], "deps": []},
                {
                    "id": members[1],
                    "deps": [{"name": "base", "pkg": members[0]}],
                },
                {
                    "id": members[2],
                    "deps": [{"name": "node", "pkg": members[1]}],
                },
            ]
        },
    }


def _manifest() -> Any:
    """Return an exhaustive manifest for the synthetic workspace."""

    return rust_ci.LaneManifest(
        lanes={
            "foundation": ("base",),
            "node": ("node",),
            "integration": ("integration",),
        },
        generated_patterns=("target/**", "**/target/**"),
        all_patterns=("Cargo.toml", "fixtures/**"),
        ignore_patterns=("docs/**", "specs/**"),
        lane_patterns={
            "foundation": ("codec/**",),
            "node": (),
            "integration": (),
        },
    )


def test_checked_in_manifest_exhaustively_maps_locked_workspace() -> None:
    """Every current workspace member belongs to exactly one checked-in lane."""

    metadata = rust_ci.load_cargo_metadata(root=ROOT)
    packages = rust_ci.workspace_packages(metadata, root=ROOT)
    manifest = rust_ci.load_lane_manifest()
    rust_ci.validate_manifest(manifest, packages)
    assert len(packages) == sum(len(packages) for packages in manifest.lanes.values())


@pytest.mark.parametrize("package", ("axum-core", "bytes", "http-body-util"))
@pytest.mark.parametrize("relative_path", ("src/lib.rs", "Cargo.toml"))
def test_vendored_foundation_owner_selects_real_http_consumers(
    package: str, relative_path: str,
) -> None:
    """Vendored HTTP primitives select their consumers through package ownership."""

    metadata = rust_ci.load_cargo_metadata(root=ROOT)
    manifest = rust_ci.load_lane_manifest()
    assert manifest.package_lane[package] == "foundation"
    result = rust_ci.classify_paths(
        [f"vendor/{package}/{relative_path}"],
        metadata=metadata, manifest=manifest, root=ROOT,
    )
    assert result.changed_packages == (package,)
    assert result.foundation_only and not result.full
    assert {package, "iroha_torii", "irohad_lib", "irohad"} <= set(result.impacted_packages)
    assert package in result.lane_packages["foundation"]
    assert "iroha_torii" in result.lane_packages["node"]
    assert {"irohad_lib", "irohad"} <= set(result.deferred_packages)


def test_native_filesystem_owner_selects_real_custody_consumers() -> None:
    """A native custody change selects its actual deployment and storage consumers."""

    metadata = rust_ci.load_cargo_metadata(root=ROOT)
    manifest = rust_ci.load_lane_manifest()
    assert manifest.package_lane["iroha_fs"] == "foundation"
    result = rust_ci.classify_paths(
        ["crates/iroha_fs/src/lib.rs"], metadata=metadata, manifest=manifest, root=ROOT,
    )
    assert result.changed_packages == ("iroha_fs",)
    assert result.foundation_only and not result.full
    assert {
        "iroha_fs", "iroha_contract_deploy", "iroha_deploy",
        "iroha_kagami", "iroha_storage_client",
    } <= set(result.impacted_packages)
    assert result.lane_packages["foundation"] == ("iroha_fs", "iroha_operation_journal")
    assert "iroha_storage_client" in result.lane_packages["services"]
    assert "iroha_deploy" in result.lane_packages["node"]


@pytest.mark.parametrize("changed_path", (
    "crates/iroha_operation_journal/src/lib.rs",
    "crates/iroha_operation_journal/Cargo.toml",
))
def test_operation_journal_foundation_change_selects_real_storage_consumers(changed_path: str) -> None:
    """The shared storage owner retains Wallet and CLI checks while deferring network consumers."""

    metadata = rust_ci.load_cargo_metadata(root=ROOT)
    manifest = rust_ci.load_lane_manifest()
    assert manifest.package_lane["iroha_operation_journal"] == "foundation"
    result = rust_ci.classify_paths(
        [changed_path], metadata=metadata, manifest=manifest, root=ROOT,
    )
    assert result.changed_packages == ("iroha_operation_journal",)
    assert result.foundation_only and not result.full
    assert {
        "iroha_operation_journal", "iroha_wallet", "iroha_sccp_wallet",
        "iroha_musubi_service", "iroha_deploy", "irohad_lib", "irohad",
        "iroha_cli_lib", "iroha_cli", "iroha_test_network", "integration_tests",
    } <= set(result.impacted_packages)
    assert result.lane_packages["foundation"] == ("iroha_operation_journal",)
    assert "iroha_wallet" in result.lane_packages["node"]
    assert "iroha_deploy" in result.lane_packages["node"]
    assert "iroha_cli_lib" in result.lane_packages["node"]
    assert "iroha_cli" in result.lane_packages["node"]
    assert "iroha_musubi_service" in result.lane_packages["services"]
    assert "iroha_sccp_wallet" in result.lane_packages["services"]
    assert {
        "irohad_lib", "irohad", "iroha_test_network", "integration_tests",
    } <= set(result.deferred_packages)
    assert set(result.deferred_packages).isdisjoint(
        package for packages in result.lane_packages.values() for package in packages
    )
    assert {"consistency", "pytests", "sora_parliament_lifecycle"} <= set(result.deferred_consumers)
    assert result.binaries == () and not any(result.consumers.values())
    document = result.as_dict()
    assert document["binary_matrix"] == {"include": []}
    assert not document["has_binary_rust"] and not document["has_binaries"]
    assert document["has_binary_free_rust"]
    selected = tuple(package for packages in result.lane_packages.values() for package in packages)
    for command in rust_ci.commands_for_checks(selected, ("clippy", "build", "test", "doc")):
        assert "iroha_cli" in command and "iroha_wallet" in command
        assert "irohad" not in command and "irohad_lib" not in command
        assert "iroha_test_network" not in command and "integration_tests" not in command
        assert "--workspace" not in command


def test_package_change_expands_reverse_dependency_closure(tmp_path: Path) -> None:
    """A foundation edit selects its node and integration dependants."""

    result = rust_ci.classify_paths(
        ["crates/base/src/lib.rs"],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    assert result.changed_packages == ("base",)
    assert result.impacted_packages == ("base", "integration", "node")
    assert list(result.lane_packages) == ["foundation", "node", "integration"]
    assert result.full is False


def test_package_change_reaches_consumers_through_registry_dependencies(
    tmp_path: Path,
) -> None:
    """External adapters retain workspace consumers and package ID identity."""

    metadata = _metadata(tmp_path)
    base_id = metadata["workspace_members"][0]
    first_adapter = "registry+https://example.test/index#adapter@1.0.0"
    second_adapter = "registry+https://example.test/index#base@2.0.0"
    metadata["packages"].extend((
        {"id": first_adapter, "name": "adapter"},
        {"id": second_adapter, "name": "base"},
    ))
    metadata["resolve"]["nodes"][1]["deps"] = [
        {"name": "adapter", "pkg": first_adapter},
    ]
    metadata["resolve"]["nodes"].extend((
        {"id": first_adapter, "deps": [{"name": "base", "pkg": second_adapter}]},
        {"id": second_adapter, "deps": [{"name": "base", "pkg": base_id}]},
    ))
    result = rust_ci.classify_paths(
        ["crates/base/src/lib.rs"],
        metadata=metadata, manifest=_manifest(), root=tmp_path,
    )
    assert result.changed_packages == ("base",)
    assert result.impacted_packages == ("base", "integration", "node")
    assert result.lane_packages == {
        "foundation": ("base",), "node": ("node",), "integration": ("integration",),
    }
    assert result.foundation_only and not result.full


def test_deepest_nested_package_owns_path(tmp_path: Path) -> None:
    """Nested proc-macro-style packages override their parent's directory."""

    metadata = _metadata(tmp_path)
    nested_id = "path+file:///nested#0.1.0"
    metadata["workspace_members"].append(nested_id)
    metadata["packages"].append(
        {
            "id": nested_id,
            "name": "nested",
            "manifest_path": str(
                tmp_path / "crates" / "base" / "proc_macro" / "Cargo.toml"
            ),
        }
    )
    metadata["resolve"]["nodes"].append({"id": nested_id, "deps": []})
    manifest = rust_ci.LaneManifest(
        lanes={
            "foundation": ("base", "nested"),
            "node": ("node",),
            "integration": ("integration",),
        },
        generated_patterns=("target/**", "**/target/**"),
        all_patterns=("Cargo.toml",),
        ignore_patterns=("docs/**", "specs/**"),
        lane_patterns={"foundation": (), "node": (), "integration": ()},
    )
    result = rust_ci.classify_paths(
        ["crates/base/proc_macro/src/lib.rs"],
        metadata=metadata,
        manifest=manifest,
        root=tmp_path,
    )
    assert result.changed_packages == ("nested",)


@pytest.mark.parametrize("path", ("new_rust_root/file.rs", "crates/deleted/src/lib.rs"))
def test_unmapped_paths_fail_closed_to_all_packages(
    tmp_path: Path, path: str
) -> None:
    """Unknown or deleted package paths can never silently skip validation."""

    result = rust_ci.classify_paths(
        [path],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    assert result.full is True
    assert result.impacted_packages == ("base", "integration", "node")
    assert result.reasons == (f"unmapped path changed: {path}",)


def test_root_and_shared_inputs_select_all_packages(tmp_path: Path) -> None:
    """Root Cargo and shared fixture changes deliberately select all lanes."""

    result = rust_ci.classify_paths(
        ["fixtures/block.json"],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    assert result.full is True
    assert result.impacted_packages == ("base", "integration", "node")


def test_explicit_non_rust_path_can_skip_rust_lanes(tmp_path: Path) -> None:
    """A documented non-Rust path produces an empty, valid matrix."""

    result = rust_ci.classify_paths(
        ["specs/index.md"],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    assert result.has_rust is False
    assert result.as_dict()["matrix"] == {"include": []}


def test_multiple_lane_path_matches_fail_closed(tmp_path: Path) -> None:
    """Overlapping lane globs cannot silently narrow validation."""

    manifest = _manifest()
    manifest = rust_ci.LaneManifest(
        lanes=manifest.lanes,
        generated_patterns=manifest.generated_patterns,
        all_patterns=manifest.all_patterns,
        ignore_patterns=manifest.ignore_patterns,
        lane_patterns={
            "foundation": ("shared/**",),
            "node": ("shared/config/**",),
            "integration": (),
        },
    )
    result = rust_ci.classify_paths(
        ["shared/config/profile.toml"],
        metadata=_metadata(tmp_path),
        manifest=manifest,
        root=tmp_path,
    )

    assert result.full is True
    assert result.impacted_packages == ("base", "integration", "node")
    assert result.reasons == (
        "ambiguous lane mapping (foundation, node): shared/config/profile.toml",
    )


def test_generated_output_inside_package_never_seeds_compile_lane(
    tmp_path: Path,
) -> None:
    """Ignored build products do not become authored package changes."""

    result = rust_ci.classify_paths(
        ["crates/base/target/debug/generated.rs"],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    assert result.has_rust is False


def test_manifest_rejects_missing_duplicate_and_stale_packages(
    tmp_path: Path,
) -> None:
    """Package ownership drift fails before any affected checks are skipped."""

    broken = rust_ci.LaneManifest(
        lanes={
            "foundation": ("base", "base", "stale"),
            "node": ("node",),
        },
        generated_patterns=("target/**",),
        all_patterns=("Cargo.toml",),
        ignore_patterns=(),
        lane_patterns={"foundation": (), "node": ()},
    )
    with pytest.raises(rust_ci.ClassificationError) as error:
        rust_ci.validate_manifest(
            broken, rust_ci.workspace_packages(_metadata(tmp_path), root=tmp_path)
        )
    message = str(error.value)
    assert "multiple lanes" in message
    assert "missing from lanes" in message
    assert "absent from workspace" in message


def test_cargo_commands_are_locked_package_scoped_and_feature_complete() -> None:
    """Routed lint and docs retain feature coverage without widening package scope."""

    commands = rust_ci.commands_for_checks(
        ("base", "node"), ("clippy", "build", "test", "doc")
    )
    assert len(commands) == 4
    for command in commands:
        assert command[0] == "cargo"
        assert "--locked" in command
        assert "--workspace" not in command
        assert command.count("-p") == 2
    assert commands[0][-3:] == ["--", "-D", "warnings"]
    assert "--all-targets" in commands[0]
    assert "--all-features" in commands[0]
    assert "--no-fail-fast" in commands[2]
    assert "--no-deps" in commands[3]
    assert "--all-features" in commands[3]


def test_cargo_command_rejects_untrusted_package_text() -> None:
    """Package arguments cannot become shell or Cargo option injection."""

    with pytest.raises(rust_ci.ClassificationError, match="invalid Cargo package"):
        rust_ci.commands_for_checks(("base;touch-output",), ("test",))


def test_github_output_is_compact_and_machine_readable(tmp_path: Path) -> None:
    """The workflow output contains a valid dynamic matrix on one line."""

    result = rust_ci.classify_paths(
        ["crates/node/src/lib.rs"],
        metadata=_metadata(tmp_path),
        manifest=_manifest(),
        root=tmp_path,
    )
    output = tmp_path / "github-output"
    rust_ci._write_github_output(output, result)
    values = dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
    )
    assert values["has_rust"] == "true"
    assert values["full"] == "false"
    matrix = json.loads(values["matrix"])
    assert [entry["lane"] for entry in matrix["include"]] == [
        "node",
        "integration",
    ]


def _manifest_with_binaries() -> Any:
    """Model a binary-free node package and a network integration consumer."""

    return replace(
        _manifest(),
        package_binaries={"integration": ("iroha", "iroha3d")},
        consumers={
            "consistency": rust_ci.BinaryConsumer(("node",), (), ("iroha", "kagami")),
            "kotodama_docs": rust_ci.BinaryConsumer((), ("specs/contracts/**",), ("koto",)),
            "pytests": rust_ci.BinaryConsumer(
                (), ("pytests/network/**",), ("iroha", "iroha3d", "kagami")
            ),
        },
    )


def test_split_matrices_partition_reverse_dependency_closure(tmp_path: Path) -> None:
    """Each selected package runs once, with binaries only for its own needs."""

    result = rust_ci.classify_paths(
        ["crates/base/src/lib.rs", "crates/node/src/lib.rs"], metadata=_metadata(tmp_path),
        manifest=_manifest_with_binaries(), root=tmp_path,
    )
    document = result.as_dict()
    assert document["binary_free_matrix"]["include"] == [
        {"lane": "foundation", "packages": "base", "package_count": 1},
        {"lane": "node", "packages": "node", "package_count": 1},
    ]
    assert document["binary_matrix"]["include"] == [
        {"lane": "integration", "packages": "integration", "package_count": 1}
    ]
    assert result.binaries == ("iroha", "iroha3d", "kagami")
    assert result.consumers == {"consistency": True, "kotodama_docs": False, "pytests": False}


def test_packages_in_one_lane_can_have_different_binary_requirements(tmp_path: Path) -> None:
    """Sharing a logical lane does not make every package wait for node builds."""

    manifest = replace(
        _manifest_with_binaries(),
        lanes={"node": ("base", "node", "integration")},
        lane_patterns={"node": ()},
    )
    document = rust_ci.classify_paths(
        ["crates/node/src/lib.rs"], metadata=_metadata(tmp_path), manifest=manifest, root=tmp_path,
    ).as_dict()
    assert document["binary_free_matrix"]["include"][0]["packages"] == "node"
    assert document["binary_matrix"]["include"][0]["packages"] == "integration"


@pytest.mark.parametrize("path", ("new/unknown.rs", "Cargo.toml"))
def test_full_and_unknown_changes_select_all_binary_consumers(tmp_path: Path, path: str) -> None:
    """Fail-closed routing selects all consumers and the complete binary union."""

    result = rust_ci.classify_paths(
        [path], metadata=_metadata(tmp_path), manifest=_manifest_with_binaries(), root=tmp_path,
    )
    assert result.full
    assert all(result.consumers.values())
    assert result.binaries == ("iroha", "iroha3d", "kagami", "koto")


@pytest.mark.parametrize(
    ("path", "binaries", "consumer"),
    (("specs/index.md", (), None), ("specs/contracts/example.ko", ("koto",), "kotodama_docs"),
     ("pytests/network/test_client.py", ("iroha", "iroha3d", "kagami"), "pytests")),
)
def test_non_rust_inputs_select_only_their_binary_consumer(
    tmp_path: Path, path: str, binaries: tuple[str, ...], consumer: str | None,
) -> None:
    """Documentation and Python changes can select artifacts without Rust lanes."""

    manifest = replace(
        _manifest_with_binaries(), ignore_patterns=("specs/**", "docs/**", "pytests/**")
    )
    result = rust_ci.classify_paths(
        [path], metadata=_metadata(tmp_path), manifest=manifest, root=tmp_path
    )
    assert not result.has_rust
    assert result.binaries == binaries
    assert {name for name, selected in result.consumers.items() if selected} == (
        {consumer} if consumer else set()
    )
    output = tmp_path / "outputs"
    rust_ci._write_github_output(output, result)
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["has_binary_free_rust"] == values["has_binary_rust"] == "false"
    assert values["has_binaries"] == str(bool(binaries)).lower()
    assert json.loads(values["binary_matrix"]) == {"include": []}


def test_checked_in_external_binary_requirements_are_package_scoped() -> None:
    """Only packages that start independent test nodes require release artifacts."""

    manifest = rust_ci.load_lane_manifest()
    assert manifest.daemon_packages == ("irohad", "irohad_lib")
    assert manifest.package_binaries == {
        "integration_tests": ("iroha", "iroha3d", "iroha3d_private_settlement_routes"),
        "iroha_test_network": ("iroha", "iroha3d", "iroha3d_private_settlement_routes"),
        "izanami": ("iroha", "iroha3d"),
    }
    assert manifest.consumers["consistency"].binaries == ("iroha", "kagami")
    assert manifest.consumers["kotodama_docs"].binaries == ("koto",)


def test_compiler_documentation_consumer_covers_its_complete_source_inventory() -> None:
    """New or existing scanned compiler fences cannot evade the routed docs job."""

    inventory = json.loads((ROOT / "specs/kotodama_v1_docs.json").read_text())
    consumer = rust_ci.load_lane_manifest().consumers["kotodama_docs"]
    assert consumer.kotodama_document_inventory == "specs/kotodama_v1_docs.json"
    assert set(inventory["source_roots"]) == {"docs", "specs"}
    assert not rust_ci._matches("docs/ordinary-prose.md", consumer.paths)
    assert not rust_ci._matches("specs/ordinary-prose.md", consumer.paths)


def _git(root: Path, *arguments: str) -> str:
    """Operate only on a temporary documentation fixture repository."""

    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def executable_docs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Create independent Git history without importing caller configuration."""

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Documentation Routing Fixture")
    _git(tmp_path, "config", "user.email", "documentation-routing@example.invalid")
    (tmp_path / "specs").mkdir()
    (tmp_path / "docs").mkdir()
    inventory = "specs/kotodama_v1_docs.json"
    (tmp_path / inventory).write_text(json.dumps({
        "schema": 2, "normative_grammar": "specs/grammar.md",
        "source_documents": ["specs/grammar.md"], "source_roots": ["docs", "specs"],
    }))
    source = "```kotodama\nseiyaku Example {}\n```\n"
    (tmp_path / "specs/grammar.md").write_text(source)
    (tmp_path / "docs/example.md").write_text(source)
    (tmp_path / "docs/prose.md").write_text("# Ordinary prose\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "documentation fixture")
    manifest = replace(_manifest_with_binaries(), consumers={
        "kotodama_docs": rust_ci.BinaryConsumer((), (), ("koto",), inventory),
    })
    return tmp_path, manifest, source


@pytest.mark.parametrize("path,contents,selected", [
    ("docs/new.md", "# New prose\n", False),
    ("specs/new.md", "# New prose\n", False),
    ("docs/example.md", "New introduction\n\n```kotodama\nseiyaku Example {}\n```\nAfterword\n", False),
    ("docs/prose.md", None, False),
    ("docs/example.md", None, True),
    ("docs/example.md", "The executable example was removed.\n", True),
    ("docs/example.md", "```kotodama\nseiyaku Changed {}\n```\n", True),
    ("docs/example.md", "```ko zk\nseiyaku Example {}\n```\n", True),
    ("docs/new.mdx", "~~~ko\nseiyaku Added {}\n~~~\n", True),
    ("docs/new.md", "```sh\ncat > example.ko <<'KO'\nseiyaku Shell {}\nKO\n```\n", True),
    ("docs/new.md", "```kotodma\nseiyaku Typo {}\n```\n", True),
    ("docs/new.md", "```\nseiyaku Unlabelled {}\n```\n", True),
    ("docs/new.md", "```kotodama\nseiyaku Unterminated {}\n", True),
    ("docs/new.md", "```kotodama\n\n```\n", True),
    ("docs/history/retired.md", "```kotodama\nmalformed retired example\n", False),
])
def test_executable_document_routing_uses_source_and_git_history(
    executable_docs, path: str, contents: str | None, selected: bool,
) -> None:
    """Actual examples select Koto; prose and retired inputs request no binaries."""

    root, manifest, _ = executable_docs
    document = root / path
    if contents is None:
        document.unlink()
    else:
        document.parent.mkdir(parents=True, exist_ok=True)
        document.write_text(contents)
    result = rust_ci.classify_paths(
        [path], metadata=_metadata(root), manifest=manifest, root=root,
    )
    assert result.consumers["kotodama_docs"] is selected
    assert result.binaries == (("koto",) if selected else ())
    assert result.has_rust is False
    assert result.full is False


def test_committed_fence_deletion_is_compared_to_supplied_base(executable_docs) -> None:
    """A clean PR checkout must not hide code removed after its merge base."""

    root, manifest, _ = executable_docs
    base = _git(root, "rev-parse", "HEAD")
    (root / "docs/example.md").write_text("Only prose remains.\n")
    _git(root, "add", "docs/example.md")
    _git(root, "commit", "-qm", "remove executable example")
    paths = rust_ci.git_changed_paths(base, root=root)
    assert paths == ("docs/example.md",)
    result = rust_ci.classify_paths(
        paths, metadata=_metadata(root), manifest=manifest, root=root, base_revision=base,
    )
    assert result.binaries == ("koto",)
    assert "executable documentation source changed: docs/example.md" in result.reasons


@pytest.mark.parametrize("problem", ["missing_base", "unreadable_utf8", "escaping_symlink", "inventory_changed"])
def test_documentation_uncertainty_still_selects_compiler(executable_docs, problem: str) -> None:
    """Incomplete evidence cannot turn executable documentation into a skip."""

    root, manifest, _ = executable_docs
    path = "docs/prose.md"
    base = "HEAD"
    if problem == "missing_base":
        base = "missing-fixture-reference"
    elif problem == "unreadable_utf8":
        (root / path).write_bytes(b"\xff")
    elif problem == "escaping_symlink":
        (root / path).unlink()
        (root / path).symlink_to(root.parent / "outside.md")
    else:
        path = "specs/kotodama_v1_docs.json"
    result = rust_ci.classify_paths(
        [path], metadata=_metadata(root), manifest=manifest, root=root, base_revision=base,
    )
    assert result.binaries == ("koto",)
    assert result.reasons


def test_retired_directory_is_excluded_from_current_checker_inputs(executable_docs) -> None:
    """The retired-directory denylist excludes malformed obsolete examples."""

    root, _, _ = executable_docs
    retired = root / "docs/history/obsolete.md"
    retired.parent.mkdir(parents=True)
    retired.write_text("```kotodama\nthis obsolete fence was never terminated\n")
    checker = rust_ci.KOTODAMA_DOCS
    inventory = checker.load_document_set(root / "specs/kotodama_v1_docs.json", root)
    fences = checker.collect_source_fences(inventory, root)
    assert {fence.document for fence in fences} == {Path("docs/example.md"), Path("specs/grammar.md")}


def test_cli_passes_merge_base_to_executable_document_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Path enumeration and source comparison use the same PR revision."""

    args = rust_ci.build_parser().parse_args(["classify", "--base", "fixture-main"])
    monkeypatch.setattr(rust_ci, "load_cargo_metadata", lambda **_: {})
    monkeypatch.setattr(rust_ci, "load_lane_manifest", lambda _: _manifest())
    monkeypatch.setattr(rust_ci, "git_changed_paths", lambda _: ("docs/deleted.md",))
    monkeypatch.setattr(rust_ci, "_run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "base-commit\n"))
    monkeypatch.setattr(rust_ci, "classify_paths", lambda *args, **kwargs: kwargs)
    assert rust_ci._classification_from_args(args)["base_revision"] == "base-commit"


@pytest.mark.parametrize("inventory", [0, False, "", "../outside.json", "/outside.json", "./specs/docs.json", "specs/docs.md"])
def test_consumer_rejects_invalid_document_inventory_paths(tmp_path: Path, inventory) -> None:
    """A malformed source selector cannot quietly become a prose-only skip."""

    text = rust_ci.DEFAULT_MANIFEST.read_text().replace(
        'kotodama_document_inventory = "specs/kotodama_v1_docs.json"',
        f"kotodama_document_inventory = {json.dumps(inventory)}",
    )
    manifest = tmp_path / "lanes.toml"
    manifest.write_text(text)
    with pytest.raises(rust_ci.ClassificationError):
        rust_ci.load_lane_manifest(manifest)


def test_misspelled_consumer_source_selector_is_rejected(tmp_path: Path) -> None:
    """Unknown consumer fields fail closed instead of disabling source scanning."""

    manifest = tmp_path / "lanes.toml"
    manifest.write_text(rust_ci.DEFAULT_MANIFEST.read_text().replace(
        "kotodama_document_inventory =", "kotodama_doc_inventory =",
    ))
    with pytest.raises(rust_ci.ClassificationError, match="unknown fields"):
        rust_ci.load_lane_manifest(manifest)


@pytest.mark.parametrize("binary", ("unknown", "iroha;touch-output", "--workspace"))
def test_invalid_binary_requirements_fail_before_build(binary: str) -> None:
    """The artifact selection cannot inject package names or Cargo options."""

    with pytest.raises(rust_ci.ClassificationError, match="binary artifacts"):
        rust_ci._binary_names([binary], "test")


def test_unknown_binary_requirement_owner_is_rejected(tmp_path: Path) -> None:
    """A stale consumer package cannot silently stop requesting its binaries."""

    manifest = replace(_manifest(), package_binaries={"removed": ("iroha",)})
    with pytest.raises(rust_ci.ClassificationError, match="unknown packages"):
        rust_ci.validate_manifest(
            manifest, rust_ci.workspace_packages(_metadata(tmp_path), root=tmp_path)
        )


def test_unknown_daemon_owner_is_rejected(tmp_path: Path) -> None:
    """A misspelled deferred daemon package cannot silently disable the foundation tier."""

    manifest = replace(_manifest(), daemon_packages=("removed",))
    with pytest.raises(rust_ci.ClassificationError, match="unknown packages"):
        rust_ci.validate_manifest(
            manifest, rust_ci.workspace_packages(_metadata(tmp_path), root=tmp_path)
        )


def test_selected_binaries_build_once_and_stage_only_requested_outputs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Artifact staging uses one locked build and excludes unrelated executable outputs."""

    calls = []
    def fake_run(command: Any, **kwargs: Any) -> None:
        calls.append((command, kwargs))
        target = Path(command[command.index("--target-dir") + 1]) / "release"
        target.mkdir(parents=True)
        for name, artifact in rust_ci.BINARY_ARTIFACTS.items():
            if artifact.target_group == "shipping":
                (target / artifact.binary).write_text(name)
    monkeypatch.setattr(rust_ci, "_run", fake_run)
    output = tmp_path / "artifacts"
    rust_ci.build_binaries(("koto", "iroha"), output, root=tmp_path)
    assert len(calls) == 1
    command, options = calls[0]
    assert command == [
        "cargo", "build", "--locked", "--release",
        "--target-dir", str(tmp_path / "target/ci-binaries/shipping"),
        "-p", "iroha_cli", "--bin", "iroha", "-p", "kotodama_toolchain", "--bin", "koto",
    ]
    assert options == {"cwd": tmp_path, "capture_output": False}
    assert sorted(path.name for path in output.iterdir()) == ["iroha", "koto"]
    with pytest.raises(rust_ci.ClassificationError, match="already exists"):
        rust_ci.build_binaries(("iroha",), output, root=tmp_path)
    assert len(calls) == 1


def _real_owner_routing_fixture(root: Path) -> tuple[dict[str, Any], Any]:
    """Use checked-in owners with explicit foundation-to-network reverse edges."""

    manifest = rust_ci.load_lane_manifest()
    # Executable document parsing has its own real-source tests above. This
    # graph fixture isolates package routing without a temporary docs checkout.
    manifest = replace(manifest, consumers={
        name: replace(consumer, kotodama_document_inventory=None)
        for name, consumer in manifest.consumers.items()
    })
    names = sorted(manifest.package_lane)
    ids = {name: f"path+file:///{name}#0.1.0" for name in names}
    dependencies = {
        "iroha_core": ("iroha_crypto", "norito"),
        "iroha": ("iroha_core",),
        "iroha_cli": ("iroha",),
        "irohad": ("iroha_core",),
        "iroha_test_network": ("iroha", "iroha_core"),
        "integration_tests": ("iroha_test_network",),
    }
    return {
        "workspace_members": list(ids.values()),
        "packages": [{
            "id": ids[name], "name": name,
            "manifest_path": str(root / (
                name if name == "integration_tests" else f"crates/{name}"
            ) / "Cargo.toml"),
        } for name in names],
        "resolve": {"nodes": [{
            "id": ids[name],
            "deps": [{"name": dependency, "pkg": ids[dependency]}
                     for dependency in dependencies.get(name, ())],
        } for name in names]},
    }, manifest


@pytest.mark.parametrize("owner", ("iroha_crypto", "norito"))
def test_known_foundation_changes_defer_network_reverse_dependants(tmp_path: Path, owner: str) -> None:
    """Real foundation owners retain the binary-free closure without daemon prebuilds."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    assert manifest.package_lane[owner] == "foundation"
    result = rust_ci.classify_paths(
        [f"crates/{owner}/src/lib.rs"], metadata=metadata, manifest=manifest, root=tmp_path,
    )
    document = result.as_dict()
    assert result.foundation_only and not result.full
    assert result.impacted_packages == tuple(sorted((
        owner, "iroha_core", "iroha", "iroha_cli", "irohad",
        "iroha_test_network", "integration_tests",
    )))
    assert result.lane_packages == {
        "foundation": (owner,),
        "node": ("iroha", "iroha_cli", "iroha_core"),
    }
    assert result.deferred_packages == ("integration_tests", "iroha_test_network", "irohad")
    assert set(result.deferred_consumers) == {
        "consistency", "pytests", "sora_parliament_lifecycle",
    }
    assert result.binaries == () and not any(result.consumers.values())
    assert document["binary_matrix"] == {"include": []}
    assert not document["has_binary_rust"] and not document["has_binaries"]
    assert document["has_binary_free_rust"]
    selected = tuple(package for packages in result.lane_packages.values() for package in packages)
    commands = rust_ci.commands_for_checks(selected, ("clippy", "build", "test", "doc"))
    for command in commands:
        assert "irohad" not in command and "--workspace" not in command
        assert "iroha_cli" in command and "iroha_core" in command


@pytest.mark.parametrize("owner", ("iroha_crypto", "norito"))
def test_mixed_foundation_and_network_changes_select_complete_artifact_union(tmp_path: Path, owner: str) -> None:
    """Adding a network owner restores its entire affected network/corridor tier."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    result = rust_ci.classify_paths(
        [f"crates/{owner}/src/lib.rs", "crates/iroha_test_network/src/lib.rs"],
        metadata=metadata, manifest=manifest, root=tmp_path,
    )
    assert not result.foundation_only and not result.full
    assert result.deferred_packages == result.deferred_consumers == ()
    assert "irohad" in result.lane_packages["node"]
    assert result.binaries == ("iroha", "iroha3d", "iroha3d_private_settlement_routes", "kagami")
    assert result.as_dict()["binary_matrix"]["include"] == [
        {"lane": "node", "packages": "iroha_test_network", "package_count": 1},
        {"lane": "integration", "packages": "integration_tests", "package_count": 1},
    ]
    assert result.consumers["sora_parliament_lifecycle"]


def test_foundation_and_direct_python_input_retains_python_network_consumer(tmp_path: Path) -> None:
    """The foundation tier cannot hide another directly changed network input."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    result = rust_ci.classify_paths(
        ["crates/norito/src/lib.rs", "pytests/iroha_torii_tests/test_status.py"],
        metadata=metadata, manifest=manifest, root=tmp_path,
    )
    assert result.consumers["pytests"]
    assert result.binaries == ("iroha", "iroha3d", "kagami")
    assert "pytests" not in result.deferred_consumers


@pytest.mark.parametrize("path", (
    "docs/ordinary-prose.md", "specs/ordinary-prose.md",
    "crates/iroha/README.md", "crates/iroha_cli/README.md", "crates/norito/README.md",
    "defaults/README.md", "pytests/iroha_torii_tests/README.md",
))
def test_prose_only_changes_select_no_daemon_or_qualified_corridor(tmp_path: Path, path: str) -> None:
    """A prose-only PR selects neither downloaded nor separately qualified daemons."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    result = rust_ci.classify_paths([path], metadata=metadata, manifest=manifest, root=tmp_path)
    assert not result.has_rust
    assert result.binaries == ()
    assert not any(result.consumers.values())


@pytest.mark.parametrize("path", ("new/unknown.rs", "Cargo.toml"))
def test_full_selection_includes_isolated_and_qualified_daemon_owners(tmp_path: Path, path: str) -> None:
    """Unknown changes and the ci/full input retain every explicit binary owner."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    result = rust_ci.classify_paths([path], metadata=metadata, manifest=manifest, root=tmp_path)
    assert result.full and not result.foundation_only
    assert result.binaries == tuple(sorted(rust_ci.BINARY_ARTIFACTS))
    assert all(result.consumers.values())
    assert result.deferred_packages == result.deferred_consumers == ()


@pytest.mark.parametrize("name", ("sora_parliament_lifecycle",))
def test_qualified_runner_has_its_own_explicit_selection_and_binary_owner(tmp_path: Path, name: str) -> None:
    """Runner ownership remains explicit even without the broad shared-CI fallback."""

    metadata, manifest = _real_owner_routing_fixture(tmp_path)
    manifest = replace(manifest, all_patterns=(), ignore_patterns=("ci/**",))
    consumer = manifest.consumers[name]
    assert consumer.binaries == ()
    assert consumer.qualified_runner == f"ci/check_{name}.sh"
    assert (ROOT / consumer.qualified_runner).is_file()
    result = rust_ci.classify_paths(
        [consumer.qualified_runner], metadata=metadata, manifest=manifest, root=tmp_path,
    )
    assert not result.full and not result.has_rust
    assert result.binaries == ()
    assert {name for name, selected in result.consumers.items() if selected} == {name}


@pytest.mark.parametrize("runner", ("../outside.sh", "/ci/run.sh", "ci/run.py", "scripts/run.sh", ""))
def test_qualified_runner_must_name_a_repository_ci_shell_owner(tmp_path: Path, runner: str) -> None:
    """Invalid qualified owners cannot turn missing artifacts into a successful empty union."""

    path = tmp_path / "lanes.toml"
    path.write_text(rust_ci.DEFAULT_MANIFEST.read_text().replace(
        'qualified_runner = "ci/check_sora_parliament_lifecycle.sh"',
        f"qualified_runner = {json.dumps(runner)}",
    ))
    with pytest.raises(rust_ci.ClassificationError):
        rust_ci.load_lane_manifest(path)


def test_qualified_consumer_cannot_mix_downloaded_binary_ownership(tmp_path: Path) -> None:
    """A separately qualified bundle cannot silently substitute PR shipping artifacts."""

    path = tmp_path / "lanes.toml"
    path.write_text(rust_ci.DEFAULT_MANIFEST.read_text().replace(
        'binaries = []\nqualified_runner', 'binaries = ["iroha3d"]\nqualified_runner', 1,
    ))
    with pytest.raises(rust_ci.ClassificationError, match="cannot mix"):
        rust_ci.load_lane_manifest(path)


def test_empty_binary_union_requires_an_explicit_qualified_owner(tmp_path: Path) -> None:
    """An accidental empty artifact list still fails before any binary build."""

    path = tmp_path / "lanes.toml"
    path.write_text(rust_ci.DEFAULT_MANIFEST.read_text().replace(
        'qualified_runner = "ci/check_sora_parliament_lifecycle.sh"\n', "", 1,
    ))
    with pytest.raises(rust_ci.ClassificationError, match="binary artifacts"):
        rust_ci.load_lane_manifest(path)


def test_route_control_artifact_build_and_staging_preserve_shipping_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-named daemon binaries retain separate feature graphs, directories, and output bytes."""

    calls = []
    def fake_run(command: list[str], **kwargs: Any) -> None:
        calls.append(command)
        target = Path(command[command.index("--target-dir") + 1]) / "release"
        target.mkdir(parents=True)
        (target / "iroha3d").write_bytes(
            b"route-control daemon" if "--features" in command else b"shipping daemon"
        )
    monkeypatch.setattr(rust_ci, "_run", fake_run)
    output = tmp_path / "artifacts"
    rust_ci.build_binaries(("iroha3d", "iroha3d_private_settlement_routes"), output, root=tmp_path)
    assert calls == [
        ["cargo", "build", "--locked", "--release", "--target-dir",
         str(tmp_path / "target/ci-binaries/private-settlement-route-control"),
         "-p", "irohad", "--bin", "iroha3d", "--features", "irohad/test-network-private-settlement-route-control"],
        ["cargo", "build", "--locked", "--release", "--target-dir",
         str(tmp_path / "target/ci-binaries/shipping"), "-p", "irohad", "--bin", "iroha3d"],
    ]
    assert sorted(path.name for path in output.iterdir()) == ["iroha3d", "iroha3d_private_settlement_routes"]
    assert (output / "iroha3d").read_bytes() == b"shipping daemon"
    assert (output / "iroha3d_private_settlement_routes").read_bytes() == b"route-control daemon"


def test_isolated_build_failure_never_publishes_a_partial_binary_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No artifact directory is published when one required build fails."""

    def fail_run(*args: Any, **kwargs: Any) -> None:
        raise rust_ci.ClassificationError("isolated compile failed")
    monkeypatch.setattr(rust_ci, "_run", fail_run)
    output = tmp_path / "artifacts"
    with pytest.raises(rust_ci.ClassificationError, match="isolated compile failed"):
        rust_ci.build_binaries(("iroha3d", "iroha3d_private_settlement_routes"), output, root=tmp_path)
    assert not output.exists()


@pytest.mark.parametrize("directory", ("python/node", "tools/node"))
def test_rust_ownership_still_precedes_non_prose_directory_ignores(tmp_path: Path, directory: str) -> None:
    """Skipping nested README prose does not hide Rust packages under ignored SDK/tool roots."""

    metadata = _metadata(tmp_path)
    metadata["packages"][1]["manifest_path"] = str(tmp_path / directory / "Cargo.toml")
    manifest = replace(_manifest(), ignore_patterns=("python/**", "tools/**"))
    result = rust_ci.classify_paths(
        [f"{directory}/src/lib.rs"], metadata=metadata, manifest=manifest, root=tmp_path,
    )
    assert result.changed_packages == ("node",)
    assert result.impacted_packages == ("integration", "node")
    assert result.has_rust


def test_isolated_only_union_does_not_build_shipping_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Selecting only the control artifact never widens to a shipping build."""

    calls = []
    def fake_run(command: list[str], **kwargs: Any) -> None:
        calls.append(command)
        target = Path(command[command.index("--target-dir") + 1]) / "release"
        target.mkdir(parents=True)
        (target / "iroha3d").write_bytes(b"control only")
    monkeypatch.setattr(rust_ci, "_run", fake_run)
    output = tmp_path / "artifacts"
    rust_ci.build_binaries(("iroha3d_private_settlement_routes",), output, root=tmp_path)
    assert len(calls) == 1
    assert calls[0][-2:] == ["--features", "irohad/test-network-private-settlement-route-control"]
    assert sorted(path.name for path in output.iterdir()) == ["iroha3d_private_settlement_routes"]
    assert (output / "iroha3d_private_settlement_routes").read_bytes() == b"control only"
    assert not (tmp_path / "target/ci-binaries/shipping").exists()
