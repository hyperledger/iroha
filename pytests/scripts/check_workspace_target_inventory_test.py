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

    assert TARGET_INVENTORY.EXPECTED_DECLARED_BIN_COUNT == 105
    assert target in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert target not in TARGET_INVENTORY.resolved_default_bins(metadata)


def test_app_certificate_encoder_requires_explicit_dev_tools_opt_in() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_data_model", "kagemusha_app_certificate_encoder_v1")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    manifest = tomllib.loads(
        (ROOT / "crates/iroha_data_model/Cargo.toml").read_text(encoding="utf-8")
    )
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])

    assert declared["path"] == "src/bin/kagemusha_app_certificate_encoder_v1.rs"
    assert declared["required-features"] == ["dev-tools"]
    assert target["required-features"] == ["dev-tools"]
    assert "dev-tools" not in manifest["features"]["default"]
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)


@pytest.mark.parametrize("mutation", ("missing", "replaced", "ungated", "default-feature"))
def test_rejects_app_certificate_encoder_inventory_changes(mutation: str) -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    owner = ("iroha_data_model", "kagemusha_app_certificate_encoder_v1")
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = "unreviewed_app_certificate_encoder"
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(
            row for row in modified["resolve"]["nodes"] if row["id"] == package["id"]
        )
        node["features"].append("dev-tools")

    errors = TARGET_INVENTORY.check_metadata(modified)

    if mutation in ("missing", "replaced"):
        assert any(
            "reviewed binary owners are no longer declared" in error and repr(owner) in error
            for error in errors
        )
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        if mutation == "missing":
            assert any(
                "declared binary count 104 differs from the expected 105" in error
                for error in errors
            )
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
            assert any("unreviewed binary owners are declared" in error for error in errors)
            assert not any("declared binary count" in error for error in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        assert any(
            "non-shipping binaries enabled by default" in error and repr(owner) in error
            for error in errors
        )
        assert not any("declared binary count" in error for error in errors)
        if mutation == "ungated":
            assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
            assert not any("exceeds" in error for error in errors)


def test_raw_app_attestation_encoder_requires_explicit_dev_tools_opt_in() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha_data_model", "kagemusha_raw_app_attestation_encoder_v1")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    manifest = tomllib.loads(
        (ROOT / "crates/iroha_data_model/Cargo.toml").read_text(encoding="utf-8")
    )
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])

    assert declared["path"] == "src/bin/kagemusha_raw_app_attestation_encoder_v1.rs"
    assert declared["required-features"] == ["dev-tools"]
    assert target["required-features"] == ["dev-tools"]
    assert "dev-tools" not in manifest["features"]["default"]
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)


@pytest.mark.parametrize("mutation", ("missing", "replaced", "ungated", "default-feature"))
def test_rejects_raw_app_attestation_encoder_inventory_changes(mutation: str) -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    owner = ("iroha_data_model", "kagemusha_raw_app_attestation_encoder_v1")
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = "unreviewed_raw_app_attestation_encoder"
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(
            row for row in modified["resolve"]["nodes"] if row["id"] == package["id"]
        )
        node["features"].append("dev-tools")

    errors = TARGET_INVENTORY.check_metadata(modified)

    if mutation in ("missing", "replaced"):
        assert any(
            "reviewed binary owners are no longer declared" in error and repr(owner) in error
            for error in errors
        )
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        if mutation == "missing":
            assert any(
                "declared binary count 104 differs from the expected 105" in error
                for error in errors
            )
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
            assert any("unreviewed binary owners are declared" in error for error in errors)
            assert not any("declared binary count" in error for error in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        assert any(
            "non-shipping binaries enabled by default" in error and repr(owner) in error
            for error in errors
        )
        assert not any("declared binary count" in error for error in errors)
        if mutation == "ungated":
            assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
            assert not any("exceeds" in error for error in errors)


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
            assert any("declared binary count 104 differs from the expected 105" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
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
    assert len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS) == 105
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
    assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
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
ORDINARY_NATIVE_TOOL_CASES = (
    (
        "iroha",
        "iroha_ordinary_native_inventory_assemble",
        "src/bin/ordinary_native_inventory_assemble.rs",
        "tls-rustls-native-roots",
    ),
    (
        "iroha_data_model",
        "kagemusha_ordinary_preparation_encoder_v1",
        "src/bin/kagemusha_ordinary_preparation_encoder_v1.rs",
        "application-model",
    ),
    (
        "iroha_data_model",
        "kagemusha_ordinary_installed_context_codec_v1",
        "src/bin/kagemusha_ordinary_installed_context_codec_v1.rs",
        "application-model",
    ),
)


@pytest.mark.parametrize(
    ("package_name", "bin_name", "source_path", "shipping_feature"),
    ORDINARY_NATIVE_TOOL_CASES,
)
def test_ordinary_native_tools_require_explicit_dev_tools_opt_in(
    package_name: str,
    bin_name: str,
    source_path: str,
    shipping_feature: str,
) -> None:
    """Ordinary native assembly and preparation tools remain development targets."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = (package_name, bin_name)
    package = next(row for row in metadata["packages"] if row["name"] == package_name)
    target = next(row for row in package["targets"] if row["name"] == bin_name)
    node = next(row for row in metadata["resolve"]["nodes"] if row["id"] == package["id"])
    manifest = tomllib.loads(
        (ROOT / "crates" / package_name / "Cargo.toml").read_text(encoding="utf-8")
    )
    declared = next(row for row in manifest["bin"] if row["name"] == bin_name)

    assert declared["path"] == source_path
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert "dev-tools" in manifest["features"]
    assert "dev-tools" not in manifest["features"]["default"]
    assert "dev-tools" not in node["features"]
    assert shipping_feature in manifest["features"]
    if package_name == "iroha":
        assert manifest["features"]["dev-tools"] == []
        assert manifest["dependencies"]["iroha_core_zk"].get("optional", False) is False
        assert manifest["dependencies"]["iroha_core_zk"]["features"] == []
    assert owner in TARGET_INVENTORY.EXPECTED_DECLARED_BINS
    assert owner not in TARGET_INVENTORY.EXPECTED_DEFAULT_BINS
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 105
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    assert TARGET_INVENTORY.check_metadata(metadata) == []


@pytest.mark.parametrize(
    ("package_name", "bin_name", "source_path", "shipping_feature"),
    ORDINARY_NATIVE_TOOL_CASES,
)
@pytest.mark.parametrize(
    "mutation", ("missing", "replaced", "ungated", "default-feature", "shipping-context")
)
def test_ordinary_native_tools_cannot_escape_the_development_inventory(
    package_name: str,
    bin_name: str,
    source_path: str,
    shipping_feature: str,
    mutation: str,
) -> None:
    """Reject owner drift and tool exposure through defaults or shipping features."""

    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 105
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    modified = copy.deepcopy(metadata)
    owner = (package_name, bin_name)
    package = next(row for row in modified["packages"] if row["name"] == package_name)
    target = next(row for row in package["targets"] if row["name"] == bin_name)
    assert target["required-features"] == ["dev-tools"]
    node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
    assert "dev-tools" not in node["features"]
    replacement = (package_name, "unreviewed_" + bin_name)
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = replacement[1]
    elif mutation == "ungated":
        target["required-features"] = []
    elif mutation == "default-feature":
        node["features"].append("dev-tools")
    else:
        target["required-features"] = [shipping_feature]
        if shipping_feature not in node["features"]:
            node["features"].append(shipping_feature)
        assert "dev-tools" not in node["features"]
        assert target["required-features"] == [shipping_feature]
        assert shipping_feature in node["features"]
    assert modified != metadata

    errors = TARGET_INVENTORY.check_metadata(modified)
    assert errors
    if mutation in ("missing", "replaced"):
        assert any(
            "reviewed binary owners are no longer declared" in error and repr(owner) in error
            for error in errors
        )
        assert TARGET_INVENTORY.resolved_default_bins(modified) == (
            TARGET_INVENTORY.resolved_default_bins(metadata)
        )
        assert not any("non-shipping binaries enabled by default" in error for error in errors)
        assert not any("exceeds" in error for error in errors)
        if mutation == "missing":
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 104
            assert any(
                "declared binary count 104 differs from the expected 105" in error
                for error in errors
            )
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
            assert any(
                "unreviewed binary owners are declared" in error and repr(replacement) in error
                for error in errors
            )
            assert not any("declared binary count" in error for error in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == (
            TARGET_INVENTORY.all_workspace_bins(metadata)
        )
        assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
        assert owner in TARGET_INVENTORY.resolved_default_bins(modified)
        assert any(
            "non-shipping binaries enabled by default" in error and repr(owner) in error
            for error in errors
        )
        assert not any("declared binary count" in error for error in errors)
        assert not any("reviewed binary owners are no longer declared" in error for error in errors)
        assert not any("unreviewed binary owners are declared" in error for error in errors)
        if mutation == "default-feature" and package_name == "iroha":
            # The two exact declared Iroha tools share the same dev-tools marker.
            assert TARGET_INVENTORY.resolved_default_bins(modified) == (
                TARGET_INVENTORY.resolved_default_bins(metadata) | IROHA_DEVELOPMENT_TOOL_OWNERS
            )
            assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 25
            assert any("exceeds 24" in error for error in errors)
        elif mutation == "default-feature" and package_name == "iroha_data_model":
            # Five Model tools require only dev-tools; enabling that marker
            # exceeds the ceiling even before any fixture-specific tools join.
            assert len(TARGET_INVENTORY.resolved_default_bins(modified)) >= 27
            assert any("exceeds 24" in error for error in errors)
        else:
            assert TARGET_INVENTORY.resolved_default_bins(modified) == (
                TARGET_INVENTORY.resolved_default_bins(metadata) | {owner}
            )
            assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 24
            assert not any("exceeds" in error for error in errors)


def test_unreviewed_owner_is_refused_behind_dev_tools() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    modified = copy.deepcopy(metadata)
    package = next(row for row in modified["packages"] if row["name"] == "iroha_data_model")
    node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
    assert "dev-tools" not in node["features"]
    unknown = (package["name"], "unreviewed_kagemusha_app_tool")
    package["targets"].append({"kind": ["bin"], "name": unknown[1], "required-features": ["dev-tools"]})
    assert TARGET_INVENTORY.resolved_default_bins(modified) == TARGET_INVENTORY.resolved_default_bins(metadata)
    assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 106
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert any("unreviewed binary owners are declared" in e and repr(unknown) in e for e in errors)
    assert any("declared binary count 106 differs from the expected 105" in e for e in errors)
    assert not any("non-shipping binaries enabled by default" in e for e in errors)


def test_declared_count_is_derived_from_the_complete_closed_owner_set() -> None:
    assert TARGET_INVENTORY.EXPECTED_DECLARED_BIN_COUNT == len(TARGET_INVENTORY.EXPECTED_DECLARED_BINS) == 105
    assert TARGET_INVENTORY.MAX_DEFAULT_BIN_COUNT == 24
    assert len(TARGET_INVENTORY.EXPECTED_DEFAULT_BINS) == 23


IROHA_DEVELOPMENT_TOOL_OWNERS = {
    ("iroha", "iroha_ordinary_native_inventory_assemble"),
    ("iroha", "hardware_evidence_bootstrap_prepare"),
}



def test_public_hardware_preparation_is_an_exact_development_only_owner() -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    owner = ("iroha", "hardware_evidence_bootstrap_prepare")
    package = next(row for row in metadata["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    node = next(row for row in metadata["resolve"]["nodes"] if row["id"] == package["id"])
    manifest = tomllib.loads((ROOT / "crates/iroha/Cargo.toml").read_text())
    declared = next(row for row in manifest["bin"] if row["name"] == owner[1])
    assert declared["path"] == "src/bin/hardware_evidence_bootstrap_prepare.rs"
    assert declared["required-features"] == target["required-features"] == ["dev-tools"]
    assert manifest["features"]["dev-tools"] == []
    assert "dev-tools" not in manifest["features"]["default"]
    assert "dev-tools" not in node["features"]
    assert owner in TARGET_INVENTORY.EXPECTED_DECLARED_BINS
    assert owner not in TARGET_INVENTORY.EXPECTED_DEFAULT_BINS
    assert owner in TARGET_INVENTORY.all_workspace_bins(metadata)
    assert owner not in TARGET_INVENTORY.resolved_default_bins(metadata)
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 105
    assert len(TARGET_INVENTORY.resolved_default_bins(metadata)) == 23
    selected = copy.deepcopy(metadata)
    selected_node = next(row for row in selected["resolve"]["nodes"] if row["id"] == package["id"])
    selected_node["features"].append("dev-tools")
    assert TARGET_INVENTORY.all_workspace_bins(selected) == TARGET_INVENTORY.all_workspace_bins(metadata)
    assert TARGET_INVENTORY.resolved_default_bins(selected) == TARGET_INVENTORY.resolved_default_bins(metadata) | IROHA_DEVELOPMENT_TOOL_OWNERS
    assert len(TARGET_INVENTORY.resolved_default_bins(selected)) == 25


@pytest.mark.parametrize("mutation", ("missing", "replaced", "ungated", "default-feature"))
def test_public_hardware_preparation_owner_and_default_exposure_mutations_refuse(mutation: str) -> None:
    metadata = TARGET_INVENTORY.load_metadata(ROOT)
    assert TARGET_INVENTORY.check_metadata(metadata) == []
    modified = copy.deepcopy(metadata)
    owner = ("iroha", "hardware_evidence_bootstrap_prepare")
    package = next(row for row in modified["packages"] if row["name"] == owner[0])
    target = next(row for row in package["targets"] if row["name"] == owner[1])
    if mutation == "missing":
        package["targets"].remove(target)
    elif mutation == "replaced":
        target["name"] = "unreviewed_hardware_preparation"
    elif mutation == "ungated":
        target["required-features"] = []
    else:
        node = next(row for row in modified["resolve"]["nodes"] if row["id"] == package["id"])
        node["features"].append("dev-tools")
    errors = TARGET_INVENTORY.check_metadata(modified)
    assert errors
    if mutation in ("missing", "replaced"):
        assert any("reviewed binary owners are no longer declared" in e and repr(owner) in e for e in errors)
        assert TARGET_INVENTORY.resolved_default_bins(modified) == TARGET_INVENTORY.resolved_default_bins(metadata)
        if mutation == "missing":
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 104
            assert any("declared binary count 104 differs from the expected 105" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
            assert any("unreviewed binary owners are declared" in e for e in errors)
            assert not any("declared binary count" in e for e in errors)
    else:
        assert TARGET_INVENTORY.all_workspace_bins(modified) == TARGET_INVENTORY.all_workspace_bins(metadata)
        enabled = IROHA_DEVELOPMENT_TOOL_OWNERS if mutation == "default-feature" else {owner}
        assert TARGET_INVENTORY.resolved_default_bins(modified) == TARGET_INVENTORY.resolved_default_bins(metadata) | enabled
        assert len(TARGET_INVENTORY.resolved_default_bins(modified)) == 23 + len(enabled)
        assert any("non-shipping binaries enabled by default" in e and repr(owner) in e for e in errors)
        assert not any("declared binary count" in e for e in errors)
        assert any("exceeds 24" in e for e in errors) == (mutation == "default-feature")


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
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 105
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
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 104
            assert any("declared binary count 104 differs from the expected 105" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
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
    assert len(TARGET_INVENTORY.all_workspace_bins(metadata)) == 105
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
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 104
            assert any("declared binary count 104 differs from the expected 105" in e for e in errors)
        else:
            assert len(TARGET_INVENTORY.all_workspace_bins(modified)) == 105
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
