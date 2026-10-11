"""Tests for the ordinary-workspace target inventory guard."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_workspace_target_inventory.py"
SPEC = importlib.util.spec_from_file_location("check_workspace_target_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TARGET_INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TARGET_INVENTORY)


def test_repository_target_inventory() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)

    assert TARGET_INVENTORY.check_metadata(metadata) == []


def test_musubi_fixture_owner_is_declared_but_never_default() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    target = ("iroha_data_model", "musubi_fixtures")

    assert TARGET_INVENTORY.EXPECTED_DECLARED_BIN_COUNT == 98
    assert target in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert target not in TARGET_INVENTORY.resolved_default_bins(metadata)


def test_external_software_signer_is_declared_but_never_default() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    target = ("irohad", "sorafs_external_software_signer")

    assert target in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert target not in TARGET_INVENTORY.resolved_default_bins(metadata)


def test_disposable_beacon_conductor_requires_explicit_dev_tools_opt_in() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_test_network", "taira_beacon_bootstrap")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    manifest = tomllib.loads(
        (ROOT / "crates/iroha_test_network/Cargo.toml").read_text(encoding="utf-8")
    )
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])
    assert manifest["features"]["default"] == []
    assert manifest["features"]["dev-tools"] == []
    assert declared["path"] == "src/bin/taira_beacon_bootstrap.rs"
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23


@pytest.mark.parametrize("mutation", ("missing", "replaced", "ungated", "default-feature"))
def test_disposable_beacon_conductor_cannot_escape_its_development_inventory(
    mutation: str,
) -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    owner = ("iroha_test_network", "taira_beacon_bootstrap")
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = "unreviewed_beacon_conductor"
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
        node["features"].append("dev-tools")
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert errors
    if mutation in ("missing", "replaced"):
        assert any("reviewed binary owners are no longer declared" in e and repr(owner) in e
                   for e in errors)
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        if mutation == "missing":
            assert any("declared binary count 97 differs from the expected 98" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 98
            assert any("unreviewed binary owners are declared" in e for e in errors)
            assert not any("declared binary count" in e for e in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        assert any("non-shipping binaries enabled by default" in e and repr(owner) in e
                   for e in errors)
        assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
        assert not any("exceeds" in e or "declared binary count" in e for e in errors)


def test_external_software_signer_requires_explicit_release_opt_in() -> None:
    manifest = tomllib.loads(
        (ROOT / "crates" / "irohad" / "bins" / "Cargo.toml").read_text(encoding="utf-8")
    )
    marker = "external-software-signer-bin"
    signer = next(
        target
        for target in manifest["bin"]
        if target["name"] == "sorafs_external_software_signer"
    )

    assert manifest["features"][marker] == ["daemon"]
    assert marker not in manifest["features"]["default"]
    assert signer["required-features"] == [marker]

    caller_markers = {
        "scripts/build_canonical_binaries.sh": (
            'daemon_features="irohad/external-software-signer-bin,iroha_cli/cli"'
        ),
        "ci/check_sorafs_cli_release.sh": "--features external-software-signer-bin",
        ".github/workflows/sorafs-cli-release.yml": (
            "--features external-software-signer-bin"
        ),
        "Dockerfile": 'ARG FEATURES="external-software-signer-bin"',
    }
    for relative, expected in caller_markers.items():
        assert expected in (ROOT / relative).read_text(encoding="utf-8")

    # The bundle packages authenticated prebuilt artifacts; it verifies their
    # explicit signer feature instead of launching its own Cargo build.
    bundle = (ROOT / "scripts/build_release_bundle.sh").read_text(encoding="utf-8")
    for expected in (
        'provenance_features+=",irohad/external-software-signer-bin"',
        'provenance_features="irohad/external-software-signer-bin"',
        '"$repo_root/scripts/verify_release_prebuilt_provenance.py"',
        '--features "$provenance_features"',
    ):
        assert expected in bundle


def test_publication_governance_qualification_uses_the_explicit_parliament_boundary() -> None:
    manifest = tomllib.loads(
        (ROOT / "integration_tests" / "Cargo.toml").read_text(encoding="utf-8")
    )
    target = next(
        target
        for target in manifest["test"]
        if target["name"] == "sorafs_publication_governance"
    )
    assert target["path"] == "tests/sorafs_publication_governance.rs"
    assert target["required-features"] == ["parliament-test-signers"]
    assert "parliament-test-signers" not in manifest["features"]["default"]
    assert all(
        target["name"] != "sorafs_publication_governance"
        for target in manifest["bin"]
    )
    core_api = (ROOT / "integration_tests/tests/core_api.rs").read_text(encoding="utf-8")
    assert "mod sorafs_publication;" in core_api


def test_rejects_default_tool_and_retired_alias() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(
        package for package in modified["packages"] if package["name"] == "iroha_cli"
    )
    package["targets"].extend(
        [
            {
                "kind": ["bin"],
                "name": "fixture_refresher",
                "required-features": [],
            },
            {
                "kind": ["bin"],
                "name": "iroha3",
                "required-features": ["dev-tools"],
            },
        ]
    )

    errors = TARGET_INVENTORY.check_metadata(modified)

    assert any("non-shipping binaries enabled by default" in error for error in errors)
    assert any("declared binary count" in error for error in errors)
    assert any("retired compatibility binaries are declared" in error for error in errors)


def test_rejects_removed_developer_tool() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(
        package for package in modified["packages"] if package["name"] == "ivm"
    )
    package["targets"] = [
        target
        for target in package["targets"]
        if target["name"] != "ivm_fixture_export"
    ]

    errors = TARGET_INVENTORY.check_metadata(modified)

    assert any("declared binary count" in error for error in errors)


def test_rejects_retired_irohad_daemon_alias() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(
        package for package in modified["packages"] if package["name"] == "irohad"
    )
    daemon = next(target for target in package["targets"] if target["name"] == "iroha3d")
    daemon["name"] = "irohad"

    errors = TARGET_INVENTORY.check_metadata(modified)

    assert any("shipping binaries no longer enabled by default" in error for error in errors)
    assert any("non-shipping binaries enabled by default" in error for error in errors)
    assert any("retired compatibility binaries are declared" in error for error in errors)


def test_reviewed_inventory_preserves_the_existing_default_ceiling() -> None:
    assert TARGET_INVENTORY.BASELINE_DEFAULT_BIN_COUNT == 92
    assert TARGET_INVENTORY.BASELINE_DECLARED_BIN_COUNT == 116
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    assert len(TARGET_INVENTORY.EXPECTED_DEFAULT_BINS) == 23
    assert len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS) == 98
    assert TARGET_INVENTORY.EXPECTED_DEFAULT_BINS <= TARGET_INVENTORY.EXPECTED_DECLARED_BINS


def test_taira_custody_launcher_is_an_explicit_shipping_owner() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    target = ("irohad", "iroha3d_taira")
    assert target in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert target in TARGET_INVENTORY.resolved_default_bins(metadata)
    manifest = tomllib.loads((ROOT / "crates/irohad/bins/Cargo.toml").read_text())
    launcher = next(row for row in manifest["bin"] if row["name"] == target[1])
    assert launcher["path"] == "src/bin/iroha3d_taira.rs"
    assert launcher["required-features"] == ["daemon"]
    assert "daemon" in manifest["features"]["default"]
    assert "irohad::taira_runtime_signer::main_entry(iroha_core::compiled_build_metadata!());" in (
        ROOT / "crates/irohad/bins/src/bin/iroha3d_taira.rs"
    ).read_text()


def test_validator_capability_has_only_the_canonical_iroha_binary() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert ("sorafs_manifest", "sorafs-validate") not in (
        TARGET_INVENTORY.all_workspace_bins(metadata)
    )
    assert ("iroha_cli", "iroha") in TARGET_INVENTORY.resolved_default_bins(metadata)


def test_rejects_developer_owner_replacement_at_unchanged_count() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == "ivm")
    target = next(row for row in package["targets"] if row["name"] == "ivm_fixture_export")
    target["name"] = "unreviewed_fixture_export"
    assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 98
    assert TARGET_INVENTORY.resolved_default_bins(modified) == (
        TARGET_INVENTORY.resolved_default_bins(metadata)
    )
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any("reviewed binary owners are no longer declared" in error for error in errors)
    assert any("unreviewed binary owners are declared" in error for error in errors)
    assert not any("declared binary count" in error for error in errors)


def test_rejects_new_default_enablement_of_an_existing_developer_owner() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == "ivm")
    target = next(row for row in package["targets"] if row["name"] == "ivm_fixture_export")
    target["required-features"] = []
    second_target = next(row for row in package["targets"] if row["name"] == "gas_probe")
    second_target["required-features"] = []
    assert TARGET_INVENTORY.all_workspace_bins(modified) == (
        TARGET_INVENTORY.all_workspace_bins(metadata)
    )
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any("non-shipping binaries enabled by default" in error for error in errors)
    assert any("default binary count 25 exceeds 24" in error for error in errors)
    assert not any("declared binary count" in error for error in errors)


def test_instruction_builder_has_only_the_canonical_iroha_binary() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert ("sorafs_car", "sorafs_tx_stdin_builder") not in (
        TARGET_INVENTORY.all_workspace_bins(metadata)
    )
    assert ("iroha_cli", "iroha") in TARGET_INVENTORY.resolved_default_bins(metadata)


def test_rejects_unreviewed_default_owner_within_unchanged_ceiling() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == "ivm")
    target = next(row for row in package["targets"] if row["name"] == "ivm_fixture_export")
    target["required-features"] = []
    assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any("non-shipping binaries enabled by default" in error for error in errors)
    assert not any("exceeds" in error for error in errors)
    assert not any("declared binary count" in error for error in errors)


def test_runtime_libraries_do_not_capture_executable_source_revisions() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    packages = {package["name"]: package for package in metadata["packages"]}
    for package_name, crate_name in (("irohad", "irohad"), ("iroha_cli", "iroha_cli")):
        library = packages[package_name + "_lib"]
        executable = packages[package_name]
        library_builds = [
            target for target in library["targets"] if "custom-build" in target["kind"]
        ]
        if package_name == "irohad":
            # The daemon library owns test-only mutation selection. Its build
            # script must stay independent of executable source revision metadata.
            mutation_build = ROOT / "crates" / package_name / "build.rs"
            assert [Path(target["src_path"]) for target in library_builds] == [mutation_build]
            mutation_source = mutation_build.read_text(encoding="utf-8")
            assert "CARGO_FEATURE_MUTATION_TESTING" in mutation_source
            assert "SUMERAGI_DAEMON_MUTATION" in mutation_source
            assert "VERGEN" not in mutation_source
            assert "IROHA_GIT_COMMIT_HASH" not in mutation_source
            assert "build-support" not in mutation_source
        else:
            assert library_builds == []
        assert any(target["name"] == crate_name and target["kind"] == ["lib"]
                   for target in library["targets"])
        assert any("custom-build" in target["kind"] for target in executable["targets"])
        assert not any("lib" in target["kind"] for target in executable["targets"])
        source_root = ROOT / "crates" / package_name / "src"
        for source in source_root.rglob("*.rs"):
            text = source.read_text(encoding="utf-8")
            assert "compiled_build_metadata!" not in text, source
            assert "compiled_build_identity!" not in text, source
            assert 'option_env!("VERGEN_GIT_SHA")' not in text, source
            assert 'option_env!("IROHA_GIT_COMMIT_HASH")' not in text, source


def test_beacon_bootstrap_requires_explicit_developer_artifact_selection() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_test_network", "taira_beacon_bootstrap")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    manifest = tomllib.loads((ROOT / "crates/iroha_test_network/Cargo.toml").read_text())
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])
    assert declared["path"] == "src/bin/taira_beacon_bootstrap.rs"
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert "dev-tools" not in manifest["features"]["default"]
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    next(row for row in package["targets"] if row["name"] == owner[1])["required-features"] = []
    assert any("non-shipping binaries enabled by default" in error and repr(owner) in error
               for error in TARGET_INVENTORY.check_metadata(modified))


def test_unreviewed_owner_is_refused_behind_dev_tools() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == "iroha_data_model")
    node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
    assert "dev-tools" not in node["features"]
    unknown = (package["name"], "unreviewed_model_tool")
    package["targets"].append({"kind": ["bin"], "name": unknown[1], "required-features": ["dev-tools"]})
    assert TARGET_INVENTORY.resolved_default_bins(modified) == TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 99
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any("unreviewed binary owners are declared" in e and repr(unknown) in e for e in errors)
    assert any("declared binary count 99 differs from the expected 98" in e for e in errors)
    assert not any("non-shipping binaries enabled by default" in e for e in errors)


def test_declared_count_is_derived_from_the_complete_closed_owner_set() -> None:
    assert TARGET_INVENTORY.EXPECTED_DECLARED_BIN_COUNT == len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS) == 98
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    assert len(TARGET_INVENTORY.EXPECTED_DEFAULT_BINS) == 23


def test_fee_rewards_evidence_verifier_requires_explicit_dev_tools_opt_in() -> None:
    """The native evidence verifier is retained as a non-default development tool."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_core", "validation_fee_rewards_evidence_verify")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    node = next(row for row in metadata["resolve"]["nodes"] if row["id"] == package["id"])
    manifest = tomllib.loads((ROOT / "crates/iroha_core/Cargo.toml").read_text())
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])

    assert manifest["package"]["autobins"] is False
    assert declared["path"] == "src/bin/validation_fee_rewards_evidence_verify.rs"
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert manifest["features"]["dev-tools"] == []
    assert "dev-tools" not in manifest["features"]["default"]
    assert "dev-tools" not in node["features"]
    assert owner in TARGET_INVENTORY.EXPECTED_DECLARED_BINS
    assert owner not in TARGET_INVENTORY.EXPECTED_DEFAULT_BINS
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 98
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    assert TARGET_INVENTORY.check_metadata(metadata) == []


@pytest.mark.parametrize(
    "mutation", ("missing", "replaced", "ungated", "default-feature", "shipping-context")
)
def test_fee_rewards_evidence_verifier_cannot_escape_development_inventory(
    mutation: str,
) -> None:
    """Retain the verifier's owner and reject accidental default/shipping exposure."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    modified = copy.deepcopy(metadata)
    owner = ("iroha_core", "validation_fee_rewards_evidence_verify")
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
    assert target["required-features"] == ["dev-tools"]
    assert "dev-tools" not in node["features"]
    assert "node" in node["features"]
    replacement = (owner[0], "unreviewed_fee_rewards_evidence_verifier")
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = replacement[1]
    elif mutation == "ungated":
        target["required-features"] = []
    elif mutation == "default-feature":
        node["features"].append("dev-tools")
    else:
        target["required-features"] = ["node"]

    errors = TARGET_INVENTORY.check_metadata(modified)
    assert errors
    if mutation in ("missing", "replaced"):
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        assert any(
            "reviewed binary owners are no longer declared" in error and repr(owner) in error
            for error in errors
        )
        if mutation == "missing":
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 97
            assert any("declared binary count 97 differs from the expected 98" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 98
            assert any("unreviewed binary owners are declared" in e and repr(replacement) in e for e in errors)
            assert not any("declared binary count" in e for e in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        enabled = {owner}
        if mutation == "default-feature":
            enabled.add(("iroha_core", "fastpq_fixture_capture"))
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata) | enabled
        )
        assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 23 + len(enabled)
        assert any("non-shipping binaries enabled by default" in e and repr(owner) in e for e in errors)
        assert not any("declared binary count" in e for e in errors)
        assert any("exceeds 24" in e for e in errors) == (mutation == "default-feature")


ARTIFACT_ADMISSION_TOOL = ("ivm_artifact_admission", "ivm_artifact_admit")
ARTIFACT_ADMISSION_TOOL_BUILD = (
    "-p ivm_artifact_admission --features ivm_artifact_admission/dev-tools --bin ivm_artifact_admit"
)


def test_artifact_admission_tool_requires_explicit_dev_tools_opt_in() -> None:
    """The golden-regeneration admission tool is a non-default development target."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ARTIFACT_ADMISSION_TOOL
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    node = next(row for row in metadata["resolve"]["nodes"] if row["id"] == package["id"])
    manifest = tomllib.loads(
        (ROOT / "crates/ivm_artifact_admission/Cargo.toml").read_text(encoding="utf-8")
    )
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])

    assert declared["path"] == "src/bin/ivm_artifact_admit.rs"
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert manifest["features"]["dev-tools"] == []
    assert "dev-tools" not in manifest["features"].get("default", [])
    assert "dev-tools" not in node["features"]
    assert owner in TARGET_INVENTORY.EXPECTED_DECLARED_BINS
    assert owner not in TARGET_INVENTORY.EXPECTED_DEFAULT_BINS
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 98
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    # The release gate and the fixture regeneration guide build the tool explicitly.
    for relative in (
        ".github/workflows/kotodama_perf.yml",
        "crates/iroha/tests/fixtures/contract_code_readback/README.md",
    ):
        assert ARTIFACT_ADMISSION_TOOL_BUILD in (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("mutation", ("missing", "replaced", "ungated", "default-feature"))
def test_artifact_admission_tool_cannot_escape_development_inventory(mutation: str) -> None:
    """Retain the admission tool's owner and reject accidental default exposure."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    modified = copy.deepcopy(metadata)
    owner = ARTIFACT_ADMISSION_TOOL
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    replacement = (owner[0], "unreviewed_artifact_admit")
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = replacement[1]
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
        node["features"].append("dev-tools")

    errors = TARGET_INVENTORY.check_metadata(modified)
    assert errors
    if mutation in ("missing", "replaced"):
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        assert any(
            "reviewed binary owners are no longer declared" in error and repr(owner) in error
            for error in errors
        )
        if mutation == "missing":
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 97
            assert any("declared binary count 97 differs from the expected 98" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 98
            assert any("unreviewed binary owners are declared" in e and repr(replacement) in e for e in errors)
            assert not any("declared binary count" in e for e in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata) | {owner}
        )
        assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
        assert any("non-shipping binaries enabled by default" in e and repr(owner) in e for e in errors)
        assert not any("exceeds" in e or "declared binary count" in e for e in errors)


@pytest.mark.parametrize(
    "owner",
    (
        ("connect_norito_bridge", "kagemusha_sender_release_parser"),
        ("iroha", "iroha_ordinary_native_inventory_assemble"),
        ("iroha", "hardware_evidence_bootstrap_prepare"),
    ),
)
def test_retired_tools_cannot_reenter_development_inventory(
    owner: tuple[str, str],
) -> None:
    """Retired tool implementations cannot return through non-default features."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert owner not in TARGET_INVENTORY.EXPECTED_DECLARED_BINS
    assert owner not in TARGET_INVENTORY.all_workspace_bins(metadata)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    package["targets"].append({
        "kind": ["bin"], "name": owner[1], "required-features": ["dev-tools"],
    })
    assert TARGET_INVENTORY.resolved_default_bins(modified) == (
        TARGET_INVENTORY.resolved_default_bins(metadata)
    )
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any(
        "unreviewed binary owners are declared" in error and repr(owner) in error
        for error in errors
    )
    assert any(
        (
            f"declared binary count {len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS) + 1} "
            f"differs from the expected {len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS)}"
        ) in error
        for error in errors
    )


@pytest.mark.parametrize("mutation", (None, "missing", "replaced", "ungated", "default-feature"))
def test_wallet_artifact_generator_requires_exact_nondefault_owner(mutation: str | None) -> None:
    """Offline signing originals remain explicitly selected and inventory-bound."""
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_core_zk", "kagemusha_wallet_artifacts")
    manifest = tomllib.loads((ROOT / "crates/iroha_core_zk/Cargo.toml").read_text())
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])
    assert declared["path"] == "src/bin/kagemusha_wallet_artifacts.rs"
    assert declared["required-features"] == ["dev-tools"]
    assert manifest["features"]["dev-tools"] == []
    assert "dev-tools" not in manifest["features"]["default"]
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    if mutation is None:
        assert TARGET_INVENTORY.check_metadata(metadata) == []
        return
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = "unreviewed_wallet_artifact_generator"
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(row for row in metadata["resolve"]["nodes"] if row["id"] == package["id"])
        node["features"].append("dev-tools")
    errors = TARGET_INVENTORY.check_metadata(metadata)
    marker = ("reviewed binary owners are no longer declared" if mutation in ("missing", "replaced")
              else "non-shipping binaries enabled by default")
    assert any(marker in error and repr(owner) in error for error in errors)
    if mutation == "replaced":
        assert any("unreviewed binary owners are declared" in error for error in errors)
        assert not any("declared binary count" in error for error in errors)
