"""Unit tests for the focused Cargo dependency-budget guard."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "check_dependency_budget.py"
SPEC = importlib.util.spec_from_file_location("check_dependency_budget", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "dependency_budget_metadata.json"
)


def _write_package(root: Path, relative: str, manifest: str) -> None:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / "Cargo.toml").write_text(manifest, encoding="utf-8")


def _write_manifest_fixture(root: Path) -> None:
    (root / "Cargo.toml").write_text(
        """\
[workspace]
resolver = "2"
members = ["crates/*"]
exclude = ["crates/excluded"]

[workspace.dependencies]
model = { package = "model", path = "crates/model" }
codec = "1"

[patch.crates-io]
patched = { path = "vendor/patched" }
""",
        encoding="utf-8",
    )
    _write_package(
        root,
        "crates/model",
        """\
[package]
name = "model"
version = "0.1.0"

[dependencies]
codec = { workspace = true }
image = { version = "1", optional = true }
patched = "1"

[build-dependencies]
build-helper = { path = "../../vendor/build-helper" }

[target.'cfg(unix)'.dependencies]
unix-only = "1"
""",
    )
    _write_package(
        root,
        "crates/daemon",
        """\
[package]
name = "daemon"
version = "0.1.0"

[dependencies]
model = { workspace = true }
tokio = "1"

[dev-dependencies]
criterion = "1"
""",
    )
    _write_package(
        root,
        "crates/cli",
        """\
[package]
name = "cli"
version = "0.1.0"

[dependencies]
model = { workspace = true }
image = { version = "1", optional = true }
""",
    )
    _write_package(
        root,
        "crates/excluded",
        """\
[package]
name = "excluded"
version = "0.1.0"

[dependencies]
forbidden = "1"
""",
    )
    _write_package(
        root,
        "vendor/build-helper",
        """\
[package]
name = "build-helper"
version = "0.1.0"

[dependencies]
syn = "2"
""",
    )
    _write_package(
        root,
        "vendor/patched",
        """\
[package]
name = "patched"
version = "1.0.0"

[dependencies]
quote = "1"
""",
    )


def _scope(limits: dict[str, int]) -> dict[str, object]:
    return {
        "roots": ["model"],
        "include_root_dev_dependencies": False,
        "limits": limits,
    }


def _config(limits: dict[str, int], denied: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "measurement": {"kind": MODULE.MEASUREMENT_KIND},
        "denied_required_packages": denied or [],
        "scopes": {"model": _scope(limits)},
    }


def test_manifest_graph_measures_required_and_declared_closures(
    tmp_path: Path,
) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")

    metrics, required, declared = MODULE.measure_scope(
        graph,
        roots=["model"],
        include_root_dev_dependencies=False,
    )

    assert metrics == {
        "required_local_packages": 3,
        "required_workspace_packages": 1,
        "required_path_packages": 2,
        "required_external_packages": 4,
        "required_dependency_edges": 6,
        "required_external_dependency_edges": 4,
        "declared_local_packages": 3,
        "declared_workspace_packages": 1,
        "declared_path_packages": 2,
        "declared_external_packages": 5,
        "declared_dependency_edges": 7,
        "declared_external_dependency_edges": 5,
    }
    assert "image" not in required.package_names
    assert "image" in declared.package_names
    assert "forbidden" not in declared.package_names


def test_workspace_scope_includes_dev_dependencies_only_for_workspace_roots(
    tmp_path: Path,
) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")

    _metrics, required, _declared = MODULE.measure_scope(
        graph,
        roots=["*"],
        include_root_dev_dependencies=True,
    )

    assert "criterion" in required.package_names
    # Path dependencies are not workspace roots, so their own dev graphs would
    # remain excluded even if one were added to this fixture.
    assert "forbidden" not in required.package_names


def test_budget_is_an_exact_no_growth_ratchet(tmp_path: Path) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")
    metrics, _required, _declared = MODULE.measure_scope(
        graph,
        roots=["model"],
        include_root_dev_dependencies=False,
    )

    report, violations = MODULE.build_source_report(graph, _config(metrics))
    assert violations == []
    assert report["within_budget"] is True

    lower_limits = dict(metrics)
    lower_limits["required_external_packages"] -= 1
    report, violations = MODULE.build_source_report(graph, _config(lower_limits))
    assert report["within_budget"] is False
    assert violations == [
        "model: required_external_packages 4 exceeds limit 3"
    ]


def test_denied_packages_apply_to_required_not_optional_closure(
    tmp_path: Path,
) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")
    metrics, _required, _declared = MODULE.measure_scope(
        graph,
        roots=["model"],
        include_root_dev_dependencies=False,
    )

    _report, violations = MODULE.build_source_report(
        graph, _config(metrics, ["image"])
    )
    assert violations == []

    _report, violations = MODULE.build_source_report(
        graph, _config(metrics, ["codec"])
    )
    assert violations == ["model: denied package `codec` is required"]


def test_reviewed_manifest_fingerprint_fails_closed(tmp_path: Path) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")
    metrics, _required, _declared = MODULE.measure_scope(
        graph,
        roots=["model"],
        include_root_dev_dependencies=False,
    )
    config = _config(metrics)
    config["baseline"] = {"manifest_fingerprint": "sha256:" + "00" * 32}

    report, violations = MODULE.build_source_report(graph, config)

    assert report["fingerprint_matches_baseline"] is False
    assert report["within_budget"] is False
    assert violations == [
        "manifest fingerprint differs from the reviewed dependency baseline: "
        f"{graph.manifest_fingerprint} != {'sha256:' + '00' * 32}"
    ]


def test_refresh_sets_observed_metrics_and_content_fingerprint(tmp_path: Path) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")
    zero_limits = {metric: 0 for metric in MODULE.METRIC_KEYS}
    config = _config(zero_limits)
    report, _violations = MODULE.build_source_report(graph, config)

    refreshed = MODULE.refreshed_config(config, graph, report)

    assert refreshed["scopes"]["model"]["limits"] == report["scopes"]["model"][
        "metrics"
    ]
    assert refreshed["baseline"]["manifest_fingerprint"] == graph.manifest_fingerprint
    assert graph.manifest_fingerprint.startswith("sha256:")


def test_config_rejects_incomplete_metric_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "budget.json"
    config_path.write_text(
        json.dumps(_config({"required_local_packages": 1})),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing"):
        MODULE.load_budget_config(config_path)


def test_captured_metadata_supports_focused_and_workspace_closures() -> None:
    metadata = json.loads(FIXTURE.read_text(encoding="utf-8"))

    model = MODULE.resolved_report(
        metadata,
        root_names=["iroha_data_model"],
        workspace=False,
        watched=["serde_json", "tokio"],
    )
    assert model["total_packages"] == 3
    assert model["package_sources"] == {
        "registry": 1,
        "path": 2,
        "git": 0,
        "other": 0,
    }
    assert model["watched_packages"] == {
        "serde_json": ["1.0.0"],
        "tokio": [],
    }

    workspace = MODULE.resolved_report(
        metadata,
        root_names=[],
        workspace=True,
        watched=[],
    )
    assert workspace["total_packages"] == 6


def test_resolved_metadata_command_is_locked_by_default() -> None:
    args = argparse.Namespace(
        manifest_path=Path("Cargo.toml"),
        allow_lock_update=False,
    )

    assert MODULE.cargo_metadata_command(args) == [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--manifest-path",
        "Cargo.toml",
        "--locked",
    ]


def test_stdout_json_is_not_mixed_with_human_diagnostics(capsys: pytest.CaptureFixture) -> None:
    result = MODULE.main(
        [
            "--metadata-json",
            str(FIXTURE),
            "-p",
            "iroha_data_model",
            "--json-out",
            "-",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert json.loads(captured.out)["total_packages"] == 3
    assert "total_packages=3" in captured.err


def _boundary_policy() -> dict:
    return {
        "schema_version": 1,
        "layers": {
            "sdk": ["sdk"],
            "wire": ["wire", "compiler"],
            "node": ["engine", "optional-engine", "dev-only"],
            "proof": ["proof"],
        },
        "configurations": {
            "sdk": {
                "package": "sdk", "default_features": False, "features": [],
                "target": "all", "forbidden_layers": ["node"],
                "forbidden_features": {"proof": ["full"]},
            },
        },
    }


@pytest.mark.parametrize("field,value", [
    ("package", "unowned"),
    ("default_features", None),
    ("target", ""),
    ("features", ["a", "a"]),
    ("forbidden_layers", ["missing"]),
    ("forbidden_layers", ["sdk"]),
    ("forbidden_features", {"unowned": ["full"]}),
])
def test_boundary_policy_rejects_ambiguous_selections(field: str, value: object) -> None:
    policy = _boundary_policy()
    policy["configurations"]["sdk"][field] = value
    with pytest.raises(ValueError):
        MODULE.validate_boundary_policy({"architecture": policy})


def test_boundary_policy_rejects_duplicate_ownership() -> None:
    policy = _boundary_policy()
    policy["layers"]["wire"].append("sdk")
    with pytest.raises(ValueError, match="multiple layer owners"):
        MODULE.validate_boundary_policy({"architecture": policy})


def test_boundary_command_selects_features_targets_and_dependency_kinds() -> None:
    policy = _boundary_policy()
    MODULE.validate_boundary_policy({"architecture": policy})
    selection = policy["configurations"]["sdk"]
    selection["features"] = ["tls", "sm"]
    command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    assert command == [
        "cargo", "tree", "--manifest-path", "Cargo.toml", "--locked",
        "--package", "sdk", "--edges", "normal,build", "--target", "all",
        "--prefix", "depth", "--format", "|{p}|{f}", "--charset", "ascii",
        "--color", "never", "--no-default-features", "--features", "tls,sm",
        "--offline",
    ]
    selection["default_features"] = True
    assert "--no-default-features" not in MODULE.boundary_tree_command(
        Path("Cargo.toml"), selection, offline=False
    )


@pytest.mark.parametrize("tree", [
    "", "not a tree", "0|wrong v1.0.0|", "1|sdk v1.0.0|",
    "0|sdk v1.0.0|\n2|wire v1.0.0|", "0|sdk v1.0.0|\n0|sdk v1.0.0|",
    "0|sdk|", "0|sdk v1.0.0|\n[build-dependencies]",
])
def test_boundary_tree_rejects_incomplete_or_mismatched_output(tree: str) -> None:
    with pytest.raises(ValueError):
        MODULE.parse_boundary_tree(tree, "sdk")


def test_boundary_tree_reports_paths_and_feature_leaks_in_deduplicated_rows() -> None:
    policy = _boundary_policy()
    tree = """0|sdk v1.0.0 (/workspace/sdk)|default
1|wire v1.0.0 (/workspace/wire)|
2|compiler v1.0.0 (/workspace/compiler)|
3|engine v1.0.0 (/workspace/engine)|runtime
1|engine v1.0.0 (/workspace/engine)|runtime (*)
1|proof v1.0.0 (/workspace/proof)|model-primitives
1|proof v1.0.0 (/workspace/proof)|full,model-primitives (*)
"""
    report = MODULE.evaluate_boundary_tree(policy, policy["configurations"]["sdk"], tree)
    assert not report["within_boundary"]
    assert report["violations"] == [
        {"package": "engine", "forbidden_layer": "node", "path": ["sdk", "engine"]},
        {"package": "proof", "forbidden_feature": "full", "path": ["sdk", "proof"]},
    ]
    assert len(report["resolved_tree_sha256"]) == 64


def test_boundary_mode_fails_closed_on_cargo_failure(tmp_path, monkeypatch, capsys) -> None:
    config = _config({key: 100 for key in MODULE.METRIC_KEYS})
    config["architecture"] = _boundary_policy()
    path = tmp_path / "budget.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 101, "", "lockfile needs to be updated"
    ))
    assert MODULE.main(["--config", str(path), "--check-boundaries"]) == 2
    assert "lockfile needs to be updated" in capsys.readouterr().err


def test_boundary_mode_emits_json_and_cannot_refresh_a_violation(tmp_path, monkeypatch, capsys) -> None:
    config = _config({key: 100 for key in MODULE.METRIC_KEYS})
    config["architecture"] = _boundary_policy()
    path = tmp_path / "budget.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, "0|sdk v1.0.0|\n1|engine v1.0.0|", ""
    ))
    assert MODULE.main(["--config", str(path), "--check-boundaries", "--json-out", "-"]) == 1
    captured = capsys.readouterr()
    assert not json.loads(captured.out)["within_boundary"]
    assert "sdk -> engine" in captured.err
    before = path.read_bytes()
    assert MODULE.main(["--config", str(path), "--check-boundaries", "--write-baseline"]) == 2
    assert path.read_bytes() == before


@pytest.mark.skipif(shutil.which("cargo") is None, reason="Cargo required for feature resolution")
def test_boundary_resolution_covers_builds_excludes_dev_and_isolates_features(tmp_path: Path) -> None:
    """Exercise Cargo, including features enabled only by another workspace root."""

    (tmp_path / "Cargo.toml").write_text('[workspace]\nresolver="2"\nmembers=["crates/*"]\n')
    dependencies = {
        "sdk": '''[dependencies]
wire={path="../wire"}
optional-engine={path="../optional-engine", optional=true}
[build-dependencies]
compiler={path="../compiler"}
[dev-dependencies]
dev-only={path="../dev-only"}
[features]
execution=["dep:optional-engine"]
''',
        "wire": '''[dependencies]
proof={path="../proof", default-features=false}
[features]
execution=["proof/full"]
''',
        "compiler": '[build-dependencies]\nengine={path="../engine"}\n',
        "daemon": '[dependencies]\nwire={path="../wire", features=["execution"]}\n',
        "proof": '[features]\nfull=[]\n',
        "engine": "", "dev-only": "", "optional-engine": "",
    }
    for name, deps in dependencies.items():
        _write_package(tmp_path, f"crates/{name}", f'[package]\nname="{name}"\nversion="1.0.0"\n{deps}')
        source = tmp_path / "crates" / name / "src"
        source.mkdir()
        (source / "lib.rs").write_text("//! Dependency resolution fixture.\n")
    manifest = tmp_path / "Cargo.toml"
    subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", str(manifest)], check=True, capture_output=True)
    policy = _boundary_policy()
    selection = policy["configurations"]["sdk"]
    tree = subprocess.check_output(MODULE.boundary_tree_command(manifest, selection, offline=True), text=True)
    report = MODULE.evaluate_boundary_tree(policy, selection, tree)
    assert report["violations"] == [{
        "package": "engine", "forbidden_layer": "node", "path": ["sdk", "compiler", "engine"],
    }]
    assert "dev-only" not in report["packages"]
    assert "optional-engine" not in report["packages"]
    selection["features"] = ["execution"]
    tree = subprocess.check_output(MODULE.boundary_tree_command(manifest, selection, offline=True), text=True)
    assert "optional-engine" in MODULE.evaluate_boundary_tree(policy, selection, tree)["packages"]


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}])
def test_boundary_policy_rejects_nonboolean_root_dev_selection(value: object) -> None:
    policy = _boundary_policy()
    MODULE.validate_boundary_policy({"architecture": policy})
    policy["configurations"]["sdk"]["include_root_dev_dependencies"] = value
    with pytest.raises(
        ValueError,
        match="^boundary `sdk` include_root_dev_dependencies must be boolean$",
    ):
        MODULE.validate_boundary_policy({"architecture": policy})


def test_boundary_root_dev_opt_in_preserves_shipping_command() -> None:
    policy = _boundary_policy()
    selection = policy["configurations"]["sdk"]
    shipping = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    selection["include_root_dev_dependencies"] = False
    MODULE.validate_boundary_policy({"architecture": policy})
    assert MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True) == shipping

    selection["include_root_dev_dependencies"] = True
    MODULE.validate_boundary_policy({"architecture": policy})
    expected = list(shipping)
    expected[expected.index("--edges") + 1] = "normal,build,dev"
    actual = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    assert actual == expected
    assert actual.count("--package") == 1
    assert "--workspace" not in actual
    assert "--all-features" not in actual
    assert "--prune" not in actual


def test_foundation_model_selections_reject_upper_layer_dependencies() -> None:
    path = Path(__file__).resolve().parents[2] / "ci" / "dependency_budget.json"
    policy = MODULE.validate_boundary_policy(json.loads(path.read_text()))
    selections = {
        name: selection for name, selection in policy["configurations"].items()
        if selection["package"] == "iroha_model_base"
    }
    assert {tuple(row["features"]) for row in selections.values()} == {
        (), ("transparent_api",),
    }
    forbidden = {
        "iroha_data_model", "iroha_privacy_model", "iroha_service_model",
        "iroha_core", "iroha_torii", "irohad", "ivm", "ivm_abi",
        "iroha_config", "iroha_telemetry", "iroha_zkp_halo2", "fastpq_prover",
        "zk_ace_prover", "sorafs_manifest", "sorafs_car", "sorafs_orchestrator",
        "iroha_musubi_service", "iroha_storage_client", "iroha",
        "reqwest", "axum", "tungstenite",
    }
    baseline = "0|iroha_model_base v1.0.0|\n1|norito v1.0.0|\n"
    for selection in selections.values():
        assert selection["target"] == "all"
        command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
        assert command[command.index("--edges") + 1] == "normal,build"
        assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
        for package in forbidden:
            result = MODULE.evaluate_boundary_tree(
                policy, selection, baseline + f"2|{package} v1.0.0|\n",
            )
            assert not result["within_boundary"], package


@pytest.mark.parametrize("owner", ["iroha_core_privacy", "iroha_core_timed_ovn"])
def test_extracted_native_owners_remain_forbidden_from_lower_layer_selections(owner: str) -> None:
    path = Path(__file__).resolve().parents[2] / "ci" / "dependency_budget.json"
    policy = MODULE.validate_boundary_policy(json.loads(path.read_text()))
    assert owner in policy["layers"]["node_execution"]
    selections = [
        selection for selection in policy["configurations"].values()
        if "node_execution" in selection["forbidden_layers"]
    ]
    assert {selection["package"] for selection in selections} >= {
        "iroha", "iroha_model_base", "iroha_data_model",
    }
    for selection in selections:
        root = selection["package"]
        baseline = f"0|{root} v1.0.0|\n1|norito v1.0.0|\n"
        if selection.get("package_contracts"):
            baseline = _native_custody_tree(selection) + "1|norito v1.0.0|\n"
        assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
        leaked = MODULE.evaluate_boundary_tree(
            policy, selection, baseline + f"2|{owner} v1.0.0|\n",
        )
        assert leaked["violations"] == [{
            "package": owner,
            "forbidden_layer": "node_execution",
            "path": [root, "norito", owner],
        }]


def test_aggregate_model_test_boundary_retains_protocol_ownership_and_denials() -> None:
    path = Path(__file__).resolve().parents[2] / "ci" / "dependency_budget.json"
    policy = MODULE.validate_boundary_policy(json.loads(path.read_text()))
    shipping = policy["configurations"]["aggregate-model"]
    tests = policy["configurations"]["aggregate-model-tests"]
    assert shipping["forbidden_packages"] == ["iroha_plonk_oracle"]
    assert "forbidden_packages" not in tests
    assert tests == {
        **{key: value for key, value in shipping.items() if key != "forbidden_packages"},
        "default_features": True,
        "features": ["http"],
        "include_root_dev_dependencies": True,
    }
    assert tests["package"] == "iroha_data_model"
    assert tests["target"] == "all"
    assert set(tests["forbidden_layers"]) == {
        "node_execution", "node_configuration", "telemetry_runtime", "storage_runtime",
        "wallet_proof_execution",
    }
    assert tests["forbidden_features"] == {
        "iroha_zkp_halo2": ["full", "parallel", "goldilocks_backend"],
    }
    assert "ivm_abi" in policy["layers"]["protocol"]
    assert "ivm" in policy["layers"]["node_execution"]
    for selection, expected_edges in [(shipping, "normal,build"), (tests, "normal,build,dev")]:
        command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
        assert command[command.index("--edges") + 1] == expected_edges
    baseline = "0|iroha_data_model v1.0.0|\n1|ivm_abi v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, tests, baseline)["within_boundary"]
    with_engine = MODULE.evaluate_boundary_tree(policy, tests, baseline + "2|ivm v1.0.0|\n")
    assert with_engine["violations"] == [{
        "package": "ivm", "forbidden_layer": "node_execution",
        "path": ["iroha_data_model", "ivm_abi", "ivm"],
    }]


@pytest.mark.parametrize("owner", ["wire", "compiler", "test-support"])
def test_boundary_test_closure_rejects_forbidden_transitive_paths(owner: str) -> None:
    policy = _boundary_policy()
    selection = policy["configurations"]["sdk"]
    selection["include_root_dev_dependencies"] = True
    policy["layers"]["wire"].append("test-support")
    MODULE.validate_boundary_policy({"architecture": policy})
    baseline = f"0|sdk v1.0.0|\n1|{owner} v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    mutated = baseline + "2|engine v1.0.0|runtime\n"
    assert mutated != baseline
    report = MODULE.evaluate_boundary_tree(policy, selection, mutated)
    assert report["violations"] == [{
        "package": "engine", "forbidden_layer": "node", "path": ["sdk", owner, "engine"],
    }]


def test_boundary_mode_enforces_explicit_test_selection(tmp_path, monkeypatch, capsys) -> None:
    policy = _boundary_policy()
    shipping = policy["configurations"]["sdk"]
    policy["configurations"]["sdk-tests"] = {
        **shipping, "include_root_dev_dependencies": True,
    }
    policy["layers"]["wire"].append("test-support")
    config = _config({key: 100 for key in MODULE.METRIC_KEYS})
    config["architecture"] = policy
    path = tmp_path / "budget.json"
    path.write_text(json.dumps(config))
    commands = []

    def resolve(command, **kwargs):
        commands.append(command)
        tree = "0|sdk v1.0.0|\n1|wire v1.0.0|\n"
        if command[command.index("--edges") + 1] == "normal,build,dev":
            tree += "1|test-support v1.0.0|\n2|engine v1.0.0|runtime\n"
        return subprocess.CompletedProcess(command, 0, tree, "")

    monkeypatch.setattr(MODULE.subprocess, "run", resolve)
    assert MODULE.main(["--config", str(path), "--check-boundaries", "--json-out", "-"]) == 1
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["measurement_kind"] == "cargo-feature-resolved-layer-boundaries-v1"
    assert report["configurations"]["sdk"]["within_boundary"]
    assert report["configurations"]["sdk-tests"]["violations"] == [{
        "package": "engine", "forbidden_layer": "node", "path": ["sdk", "test-support", "engine"],
    }]
    assert not report["within_boundary"]
    assert "sdk-tests: sdk -> test-support -> engine (node)" in output.err
    assert [command[command.index("--edges") + 1] for command in commands] == [
        "normal,build", "normal,build,dev",
    ]


@pytest.mark.skipif(shutil.which("cargo") is None, reason="Cargo required for feature resolution")
def test_boundary_resolution_includes_only_root_dev_dependencies(tmp_path: Path) -> None:
    """Qualify root-only dev resolution and normal/build closure of its test helpers."""

    (tmp_path / "Cargo.toml").write_text('[workspace]\nresolver="2"\nmembers=["crates/*"]\n')
    dependencies = {
        "sdk": '''[dependencies]
wire={path="../wire"}
[build-dependencies]
compiler={path="../compiler"}
[dev-dependencies]
test-support={path="../test-support"}
[features]
normal-leak=["wire/execution"]
build-leak=["compiler/execution"]
dev-leak=["test-support/execution"]
''',
        "wire": '''[dependencies]
proof={path="../proof", default-features=false}
engine={path="../engine", optional=true}
[dev-dependencies]
nonroot-dev-only={path="../nonroot-dev-only"}
[features]
execution=["dep:engine"]
''',
        "compiler": '''[build-dependencies]
engine={path="../engine", optional=true}
[features]
execution=["dep:engine"]
''',
        "test-support": '''[dependencies]
engine={path="../engine", optional=true}
[dev-dependencies]
nonroot-dev-only={path="../nonroot-dev-only"}
[features]
execution=["dep:engine"]
''',
        "daemon": '''[dependencies]
proof={path="../proof", features=["full"]}
[dev-dependencies]
workspace-dev-only={path="../workspace-dev-only"}
''',
        "proof": '[features]\nfull=[]\n',
        "engine": "", "nonroot-dev-only": "", "workspace-dev-only": "",
    }
    for name, deps in dependencies.items():
        _write_package(tmp_path, f"crates/{name}", f'[package]\nname="{name}"\nversion="1.0.0"\n{deps}')
        source = tmp_path / "crates" / name / "src"
        source.mkdir()
        (source / "lib.rs").write_text("//! Root test dependency boundary fixture.\n")
    manifest = tmp_path / "Cargo.toml"
    subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", str(manifest)], check=True, capture_output=True)
    policy = _boundary_policy()
    policy["layers"]["wire"].append("test-support")
    policy["layers"]["node"].extend(["nonroot-dev-only", "workspace-dev-only"])
    selection = policy["configurations"]["sdk"]

    def inspect() -> dict:
        tree = subprocess.check_output(MODULE.boundary_tree_command(manifest, selection, offline=True), text=True)
        return MODULE.evaluate_boundary_tree(policy, selection, tree)

    shipping = inspect()
    assert shipping["within_boundary"]
    assert "test-support" not in shipping["packages"]
    selection["include_root_dev_dependencies"] = True
    baseline = inspect()
    assert baseline["within_boundary"]
    assert set(baseline["packages"]) == {"sdk", "wire", "proof", "compiler", "test-support"}
    assert "nonroot-dev-only" not in baseline["packages"]
    assert "workspace-dev-only" not in baseline["packages"]
    for feature, owner in [
        ("normal-leak", "wire"), ("build-leak", "compiler"), ("dev-leak", "test-support"),
    ]:
        selection["features"] = [feature]
        report = inspect()
        assert not report["within_boundary"]
        assert report["violations"] == [{
            "package": "engine", "forbidden_layer": "node", "path": ["sdk", owner, "engine"],
        }]



def _native_policy() -> dict:
    path = Path(__file__).resolve().parents[2] / "ci" / "dependency_budget.json"
    return MODULE.validate_boundary_policy(json.loads(path.read_text()))


WALLET_PROOF_OWNERS = ["iroha_plonk_recursion", "iroha_kagemusha_proof"]
SHARED_NATIVE_PROOF_PRIMITIVES = ["iroha_pasta", "iroha_plonk", "iroha_plonk_gadgets"]
WALLET_PROOF_DENIAL_CONTEXTS = [
    "aggregate-model",
    "aggregate-model-tests",
    "incentives",
    "model-base-default",
    "model-base-transparent",
    "musubi-service-default",
    "sccp-rpc-default",
    "sccp-wallet-default",
    "sdk-default",
    "sdk-tls-native",
    "sdk-tls-native-vendored",
    "sdk-tls-rustls-native-roots",
    "sdk-tls-rustls-webpki-roots",
    "service-model",
    "storage-client-default",
    "storage-client-tls-native",
    "storage-client-tls-native-vendored",
    "storage-client-tls-rustls-native-roots",
    "storage-client-tls-rustls-webpki-roots",
    "torii-wire"
]


SDK_SELECTIONS = [
    "sdk-default", "sdk-tls-native", "sdk-tls-native-vendored",
    "sdk-tls-rustls-native-roots", "sdk-tls-rustls-webpki-roots",
    "musubi-service-default", "sccp-wallet-default", "storage-client-default",
    "storage-client-tls-native", "storage-client-tls-native-vendored",
    "storage-client-tls-rustls-native-roots", "storage-client-tls-rustls-webpki-roots",
]


def _sdk_tree(selection: dict) -> str:
    """The SDK path of one shipping consumer without any proof/custody owner."""

    root = selection["package"]
    path = [root] + (["iroha_wallet"] if root == "iroha_sccp_wallet" else [])
    path += [] if root == "iroha" else ["iroha"]
    return "".join(
        f"{depth}|{package} v1.0.0|" + ("default" if package == "iroha" else "") + "\n"
        for depth, package in enumerate(path)
    )


@pytest.mark.parametrize("context", SDK_SELECTIONS)
def test_sdk_selections_admit_no_node_execution_owner(context) -> None:
    """The SDK carries no proof/custody exception: Core ZK is plain node execution."""

    policy = _native_policy()
    selection = policy["configurations"][context]
    assert "package_contracts" not in selection
    tree = _sdk_tree(selection)
    assert MODULE.evaluate_boundary_tree(policy, selection, tree)["within_boundary"]
    depth = len(tree.splitlines())
    sdk_path = [line.split("|")[1].split(" ")[0] for line in tree.splitlines()]
    report = MODULE.evaluate_boundary_tree(
        policy, selection, tree + f"{depth}|iroha_core_zk v1.0.0|\n",
    )
    assert not report["within_boundary"]
    assert {
        "package": "iroha_core_zk", "forbidden_layer": "node_execution",
        "path": sdk_path + ["iroha_core_zk"],
    } in report["violations"]


@pytest.mark.parametrize("context", SDK_SELECTIONS)
def test_retired_package_contract_admission_is_rejected(context) -> None:
    policy = _native_policy()
    policy["configurations"][context]["package_contracts"] = {
        "iroha_core_zk": {"permitted_layer": "node_execution"},
    }
    with pytest.raises(ValueError, match="retired package_contracts admission"):
        MODULE.validate_boundary_policy({"architecture": policy})


def test_native_policy_preserves_every_original_context_and_layer() -> None:
    policy = _native_policy()
    assert len(policy["configurations"]) == 21
    assert set(WALLET_PROOF_DENIAL_CONTEXTS) == (
        set(policy["configurations"]) - {"iroha3d-without-sccp-wallet"}
    )
    # This test-only invariant projects out exactly the reviewed additions and
    # keeps every original ownership, denial, feature, target and root-dev choice.
    original_configurations = copy.deepcopy(policy["configurations"])
    for context in WALLET_PROOF_DENIAL_CONTEXTS:
        layers = original_configurations[context]["forbidden_layers"]
        assert layers.count("wallet_proof_execution") == 1
        layers.remove("wallet_proof_execution")
    original_layers = copy.deepcopy(policy["layers"])
    assert original_layers.pop("wallet_proof_execution") == WALLET_PROOF_OWNERS
    assert original_layers["proof_primitives"] == [
        "iroha_zkp_halo2", *SHARED_NATIVE_PROOF_PRIMITIVES,
    ]
    for primitive in SHARED_NATIVE_PROOF_PRIMITIVES:
        original_layers["proof_primitives"].remove(primitive)
    assert hashlib.sha256(json.dumps(
        original_configurations, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest() == "b095915d17f2d3e3371b2f8ec46529639d23a509c0341dea8e8ba2bb762d383e"
    # The retired Kagemusha real-proof harness feature no longer exists to forbid.
    assert all(
        "kagemusha-real-proof-harness" not in features
        for selection in policy["configurations"].values()
        for features in selection["forbidden_features"].values()
    )
    assert hashlib.sha256(json.dumps(
        original_layers, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest() == "3cca600ca6223358c8889fe065f5d8b2a400b360e04083506dd23d2b007fb880"
    assert hashlib.sha256(json.dumps(
        policy["configurations"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest() == "a82622b18157e40ba1b0e68633322ba8cac5afbd87d60efb033c3e5c87cf80c8"
    assert hashlib.sha256(json.dumps(
        policy["layers"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest() == "09a4b45b8c8fb31b19effe8135c6858d98abe3ba66e1b2ad2265074057c801a9"


@pytest.mark.parametrize("metric", MODULE.METRIC_KEYS)
def test_every_dependency_metric_still_rejects_one_unit_of_unreviewed_growth(tmp_path, metric) -> None:
    _write_manifest_fixture(tmp_path)
    graph = MODULE.load_manifest_graph(tmp_path / "Cargo.toml")
    metrics, _required, _declared = MODULE.measure_scope(
        graph, roots=["model"], include_root_dev_dependencies=False,
    )
    bounds = dict(metrics)
    assert bounds[metric] > 0
    bounds[metric] -= 1
    report, violations = MODULE.build_source_report(graph, _config(bounds))
    assert not report["within_budget"]
    assert violations == [f"model: {metric} {metrics[metric]} exceeds limit {bounds[metric]}"]


SHIPPING_ORACLE_DENIAL_CONTEXTS = [
    "aggregate-model",
    "incentives",
    "iroha3d-without-sccp-wallet",
    "model-base-default",
    "model-base-transparent",
    "musubi-service-default",
    "sccp-rpc-default",
    "sccp-wallet-default",
    "sdk-default",
    "sdk-tls-native",
    "sdk-tls-native-vendored",
    "sdk-tls-rustls-native-roots",
    "sdk-tls-rustls-webpki-roots",
    "service-model",
    "storage-client-default",
    "storage-client-tls-native",
    "storage-client-tls-native-vendored",
    "storage-client-tls-rustls-native-roots",
    "storage-client-tls-rustls-webpki-roots",
    "torii-wire"
]


@pytest.mark.parametrize("context", SHIPPING_ORACLE_DENIAL_CONTEXTS)
def test_every_shipping_selection_rejects_direct_and_transitive_plonk_oracle(context) -> None:
    policy = _native_policy()
    selection = policy["configurations"][context]
    root = selection["package"]
    assert selection.get("include_root_dev_dependencies", False) is False
    assert selection["forbidden_packages"].count("iroha_plonk_oracle") == 1
    command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    assert command[command.index("--edges") + 1] == "normal,build"
    baseline = f"0|{root} v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    for suffix, path in [
        ("1|iroha_plonk_oracle v1.0.0|circuit-params,default\n",
         [root, "iroha_plonk_oracle"]),
        ("1|norito v1.0.0|\n2|iroha_plonk_oracle v1.0.0|circuit-params,default\n",
         [root, "norito", "iroha_plonk_oracle"]),
    ]:
        tree = baseline + suffix
        report = MODULE.evaluate_boundary_tree(policy, selection, tree)
        assert not report["within_boundary"]
        assert report["violations"] == [{
            "package": "iroha_plonk_oracle", "forbidden_package": True, "path": path,
        }]
        # Removing just this package denial admits the same parsed fixture;
        # the rejection above cannot be borrowed from another policy violation.
        missing_denial = copy.deepcopy(selection)
        missing_denial["forbidden_packages"].remove("iroha_plonk_oracle")
        assert MODULE.evaluate_boundary_tree(policy, missing_denial, tree)["within_boundary"]


def test_model_test_selection_keeps_dev_oracle_without_relaxing_shipping_or_layers() -> None:
    policy = _native_policy()
    configurations = policy["configurations"]
    assert {
        name for name, row in configurations.items()
        if not row.get("include_root_dev_dependencies", False)
    } == set(SHIPPING_ORACLE_DENIAL_CONTEXTS)
    assert {
        name for name, row in configurations.items()
        if row.get("include_root_dev_dependencies", False)
    } == {"aggregate-model-tests"}
    selection = configurations["aggregate-model-tests"]
    assert "iroha_plonk_oracle" not in selection.get("forbidden_packages", [])
    assert not any("iroha_plonk_oracle" in packages for packages in policy["layers"].values())
    command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    assert command[command.index("--edges") + 1] == "normal,build,dev"
    tree = "0|iroha_data_model v1.0.0|\n1|iroha_plonk_oracle v1.0.0|circuit-params,default\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, tree)["within_boundary"]
    with_engine = MODULE.evaluate_boundary_tree(policy, selection, tree + "2|ivm v1.0.0|\n")
    assert with_engine["violations"] == [{
        "package": "ivm", "forbidden_layer": "node_execution",
        "path": ["iroha_data_model", "iroha_plonk_oracle", "ivm"],
    }]
    with_proof_feature = MODULE.evaluate_boundary_tree(
        policy, selection, tree + "2|iroha_zkp_halo2 v1.0.0|full\n",
    )
    assert with_proof_feature["violations"] == [{
        "package": "iroha_zkp_halo2", "forbidden_feature": "full",
        "path": ["iroha_data_model", "iroha_plonk_oracle", "iroha_zkp_halo2"],
    }]


@pytest.mark.parametrize("context", [
    "aggregate-model", "aggregate-model-tests", "sdk-default", "sdk-tls-native",
    "sdk-tls-native-vendored", "sdk-tls-rustls-native-roots",
    "sdk-tls-rustls-webpki-roots",
])
def test_shared_native_primitives_keep_existing_model_and_sdk_paths(context) -> None:
    """Model Poseidon and SoraFS PoP use shared Pasta/PLONK primitives."""

    policy = _native_policy()
    selection = policy["configurations"][context]
    root = selection["package"]
    baseline = f"0|{root} v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    # Both roots own a normal SoraFS manifest edge; PoP fully verifies with PLONK.
    tree = baseline + (
        "1|sorafs_manifest v1.0.0|\n"
        "2|iroha_plonk v1.0.0|\n"
        "3|iroha_pasta v1.0.0|\n"
    )
    if root == "iroha":
        tree += "1|iroha_data_model v1.0.0|\n2|iroha_pasta v1.0.0|\n"
    else:
        tree += "1|iroha_pasta v1.0.0|\n"
    report = MODULE.evaluate_boundary_tree(policy, selection, tree)
    assert report["within_boundary"]
    assert report["violations"] == []
    assert {"iroha_pasta", "iroha_plonk"} <= set(report["packages"])


@pytest.mark.parametrize("context", WALLET_PROOF_DENIAL_CONTEXTS)
@pytest.mark.parametrize("owner", WALLET_PROOF_OWNERS)
def test_non_node_selections_reject_each_wallet_proof_owner(context, owner) -> None:
    """Ordinary model, SDK, wire and service roots cannot execute wallet proofs."""

    policy = _native_policy()
    selection = policy["configurations"][context]
    root = selection["package"]
    assert selection["forbidden_layers"].count("wallet_proof_execution") == 1
    assert policy["layers"]["wallet_proof_execution"].count(owner) == 1
    command = MODULE.boundary_tree_command(Path("Cargo.toml"), selection, offline=True)
    expected_edges = "normal,build,dev" if context == "aggregate-model-tests" else "normal,build"
    assert command[command.index("--edges") + 1] == expected_edges
    baseline = f"0|{root} v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    for suffix, path in [
        (f"1|{owner} v1.0.0|\n", [root, owner]),
        (f"1|norito v1.0.0|\n2|{owner} v1.0.0|\n", [root, "norito", owner]),
    ]:
        tree = baseline + suffix
        report = MODULE.evaluate_boundary_tree(policy, selection, tree)
        assert not report["within_boundary"]
        assert report["violations"] == [{
            "package": owner, "forbidden_layer": "wallet_proof_execution", "path": path,
        }]
        # Each owner and each context denial independently causes this rejection.
        missing_owner = copy.deepcopy(policy)
        missing_owner["layers"]["wallet_proof_execution"].remove(owner)
        assert MODULE.evaluate_boundary_tree(missing_owner, selection, tree)["within_boundary"]
        missing_denial = copy.deepcopy(selection)
        missing_denial["forbidden_layers"].remove("wallet_proof_execution")
        assert MODULE.evaluate_boundary_tree(policy, missing_denial, tree)["within_boundary"]


@pytest.mark.parametrize("context", ["model-base-default", "model-base-transparent"])
@pytest.mark.parametrize("primitive", SHARED_NATIVE_PROOF_PRIMITIVES)
def test_foundation_model_rejects_shared_native_proof_primitives(context, primitive) -> None:
    """Shared cryptographic primitives remain above the foundational model."""

    policy = _native_policy()
    selection = policy["configurations"][context]
    root = selection["package"]
    assert root == "iroha_model_base"
    assert selection["forbidden_layers"].count("proof_primitives") == 1
    assert policy["layers"]["proof_primitives"].count(primitive) == 1
    baseline = f"0|{root} v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    for suffix, path in [
        (f"1|{primitive} v1.0.0|\n", [root, primitive]),
        (f"1|norito v1.0.0|\n2|{primitive} v1.0.0|\n", [root, "norito", primitive]),
    ]:
        tree = baseline + suffix
        report = MODULE.evaluate_boundary_tree(policy, selection, tree)
        assert not report["within_boundary"]
        assert report["violations"] == [{
            "package": primitive, "forbidden_layer": "proof_primitives", "path": path,
        }]
        missing_owner = copy.deepcopy(policy)
        missing_owner["layers"]["proof_primitives"].remove(primitive)
        assert MODULE.evaluate_boundary_tree(missing_owner, selection, tree)["within_boundary"]
        missing_denial = copy.deepcopy(selection)
        missing_denial["forbidden_layers"].remove("proof_primitives")
        assert MODULE.evaluate_boundary_tree(policy, missing_denial, tree)["within_boundary"]


@pytest.mark.parametrize("intermediate", [None, "iroha_core", "iroha_torii"])
def test_node_consumer_paths_keep_mandatory_wallet_verification(intermediate) -> None:
    """Daemon, Core and Torii retain their normal native wallet verifier paths."""

    policy = _native_policy()
    selection = policy["configurations"]["iroha3d-without-sccp-wallet"]
    assert "wallet_proof_execution" not in selection["forbidden_layers"]
    baseline = "0|irohad v1.0.0|\n"
    assert MODULE.evaluate_boundary_tree(policy, selection, baseline)["within_boundary"]
    prefix = ["irohad"] + ([] if intermediate is None else [intermediate]) + [
        "iroha_core_zk",
    ]
    for proof_owner in [[], ["iroha_kagemusha_proof"]]:
        path = prefix + proof_owner + [
            "iroha_plonk_recursion", "iroha_plonk_gadgets",
            "iroha_plonk", "iroha_pasta",
        ]
        tree = "".join(f"{depth}|{package} v1.0.0|\n" for depth, package in enumerate(path))
        report = MODULE.evaluate_boundary_tree(policy, selection, tree)
        assert report["within_boundary"]
        assert report["violations"] == []
        assert set(path) <= set(report["packages"])


# Canonical metadata parsing is pure; feature-boundary Cargo tests above stay separate.
def _canonical_resolved_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _focused_resolved_ids(metadata: dict) -> frozenset[str]:
    return MODULE.resolved_package_ids(
        metadata, root_names=["iroha_data_model"], workspace=False
    )


@pytest.mark.parametrize("redundant_ids", [False, True])
def test_canonical_resolved_deps_are_required_even_with_redundant_ids(redundant_ids) -> None:
    metadata = _canonical_resolved_fixture()
    node = metadata["resolve"]["nodes"][0]
    dependencies = node.pop("deps")
    if redundant_ids:
        node["dependencies"] = [dependency["pkg"] for dependency in dependencies]
    with pytest.raises(ValueError, match="deps must be a list"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("invalid", [None, False, 1, {}, "package-id"])
def test_canonical_resolved_deps_reject_malformed_lists_without_fallback(invalid) -> None:
    metadata = _canonical_resolved_fixture()
    node = metadata["resolve"]["nodes"][0]
    node["dependencies"] = [dependency["pkg"] for dependency in node["deps"]]
    node["deps"] = invalid
    with pytest.raises(ValueError, match="deps must be a list"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("invalid", [None, False, 1, [], "package-id", {}])
def test_canonical_resolved_deps_reject_nonrecords_and_missing_fields(invalid) -> None:
    metadata = _canonical_resolved_fixture()
    metadata["resolve"]["nodes"][0]["deps"][0] = invalid
    with pytest.raises(ValueError, match=r"deps\[0\]"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("field", ["name", "pkg"])
@pytest.mark.parametrize("invalid", [None, False, 1, [], {}, ""])
def test_canonical_resolved_deps_reject_malformed_names_and_ids(field, invalid) -> None:
    metadata = _canonical_resolved_fixture()
    metadata["resolve"]["nodes"][0]["deps"][0][field] = invalid
    with pytest.raises(ValueError, match=field + " must be a nonempty string"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("invalid", [None, False, 1, {}, "normal", []])
def test_canonical_resolved_deps_require_nonempty_kind_descriptions(invalid) -> None:
    metadata = _canonical_resolved_fixture()
    metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = invalid
    with pytest.raises(ValueError, match="dep_kinds must be a nonempty list"):
        _focused_resolved_ids(metadata)


def test_canonical_resolved_deps_reject_missing_kind_descriptions() -> None:
    metadata = _canonical_resolved_fixture()
    del metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"]
    with pytest.raises(ValueError, match="dep_kinds must be a nonempty list"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("invalid", [
    None, False, 1, [], {},
    {"kind": None}, {"target": None},
    {"kind": "normal", "target": None},
    {"kind": "unknown", "target": None},
    {"kind": [], "target": None},
    {"kind": None, "target": False},
    {"kind": None, "target": 1},
    {"kind": None, "target": []},
    {"kind": None, "target": {}},
    {"kind": None, "target": ""},
])
def test_canonical_resolved_deps_reject_malformed_kind_records(invalid) -> None:
    metadata = _canonical_resolved_fixture()
    metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = [invalid]
    with pytest.raises(ValueError, match=r"dep_kinds\[0\]"):
        _focused_resolved_ids(metadata)


@pytest.mark.parametrize("kind", [None, "build", "dev"])
@pytest.mark.parametrize("target", [None, "cfg(unix)"])
def test_canonical_resolved_deps_preserve_all_declared_kinds_and_targets(kind, target) -> None:
    metadata = _canonical_resolved_fixture()
    expected = _focused_resolved_ids(metadata)
    metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = [
        {"kind": kind, "target": target}
    ]
    assert _focused_resolved_ids(metadata) == expected
    assert len(expected) == 3


def test_canonical_resolved_deps_keep_renamed_edges_and_ignore_redundant_ids() -> None:
    metadata = _canonical_resolved_fixture()
    expected = _focused_resolved_ids(metadata)
    node = metadata["resolve"]["nodes"][0]
    node["deps"][0]["name"] = "renamed_crypto"
    node["dependencies"] = [metadata["packages"][3]["id"]]
    assert _focused_resolved_ids(metadata) == expected
    assert metadata["packages"][3]["id"] not in expected


def test_canonical_resolved_deps_report_unknown_canonical_package_ids() -> None:
    metadata = _canonical_resolved_fixture()
    metadata["resolve"]["nodes"][0]["deps"][0]["pkg"] = "unknown-package-id"
    with pytest.raises(ValueError, match="unknown-package-id.*has no node"):
        _focused_resolved_ids(metadata)


def test_canonical_resolved_deps_cli_refuses_before_emitting_a_partial_report(tmp_path, capsys) -> None:
    metadata = _canonical_resolved_fixture()
    del metadata["resolve"]["nodes"][0]["deps"]
    path = tmp_path / "missing-deps.json"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    result = MODULE.main([
        "--metadata-json", str(path), "-p", "iroha_data_model", "--json-out", "-"
    ])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "deps must be a list" in captured.err
