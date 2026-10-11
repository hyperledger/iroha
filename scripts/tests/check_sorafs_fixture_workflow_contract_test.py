"""Contract tests for SoraFS fixture and native-SDK workflow coverage."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"

CORE_VERIFIER_OWNER_WORKFLOWS = (
    "mobile_sdk_artifacts.yml",
    "sorafs-cli-release.yml",
    "sorafs-orchestrator-sdk.yml",
    "sorafs-fixtures-nightly.yml",
)
CORE_VERIFIER_OWNER_TRIGGER_PATHS = {
    "crates/iroha_core_privacy/**",
    "crates/iroha_core_timed_ovn/**",
}

NATIVE_ESCROW_TRIGGER_PATHS = {
    "crates/connect_norito_bridge/**",
    "crates/iroha_core/src/smartcontracts/isi/mod.rs",
    "crates/iroha_core/src/smartcontracts/isi/escrow.rs",
    "crates/iroha_data_model/src/bin/cancel_asset_lock_fixtures.rs",
    "crates/iroha_data_model/src/escrow.rs",
    "crates/iroha_data_model/src/events/data/escrow.rs",
    "crates/iroha_data_model/src/isi/mod.rs",
    "crates/iroha_data_model/src/isi/escrow.rs",
    "crates/iroha_data_model/src/isi/registry.rs",
    "crates/iroha_data_model/src/testing/cancel_asset_lock.rs",
    "crates/kotodama_lang/src/samples/native_escrow.ko",
    "crates/kotodama_lang/src/samples/native_escrow.to",
    "crates/sorafs_manifest/**",
    "fixtures/sorafs_manifest/appeal_finance/**",
    "fixtures/sorafs_manifest/reference_sdk/**",
    "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json",
    "integration_tests/tests/native_escrow.rs",
}

APPEAL_FINANCE_FIXTURE_PATHS = (
    "cancel_asset_lock_v1.json",
    "cancel_asset_lock_v1.to",
    "negative/cancel_asset_lock_legacy_missing_expected_v1.json",
    "negative/cancel_asset_lock_legacy_missing_expected_v1.to",
    "negative/cancel_asset_lock_nested_escrow_id_v1.to",
    "negative/cancel_asset_lock_noncanonical_quantity_v1.json",
    "negative/cancel_asset_lock_zero_expected_v1.json",
    "negative/cancel_asset_lock_zero_expected_v1.to",
)

APPEAL_FINANCE_SHARED_FIXTURE_TRIGGER_PATHS = {
    f"fixtures/sorafs_manifest/appeal_finance/{relative}"
    for relative in APPEAL_FINANCE_FIXTURE_PATHS
}

APPEAL_FINANCE_VALIDATION_PROFILE_TRIGGER_PATHS = {
    (
        "fixtures/sorafs_manifest/reference_sdk/"
        "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
    ),
    (
        "fixtures/sorafs_manifest/reference_sdk/"
        "appeal_finance_cancel_asset_lock_zero_expected_negative_"
        "validation_outcome_v1.json"
    ),
}

SDK_FIXTURE_READERS = {
    "IrohaSwift/Tests/IrohaSwiftTests/CancelAssetLockV1Tests.swift": (
        "testAppealFinanceReferenceFixturesAreByteExactAndFailClosed",
        "Data(contentsOf:",
        "XCTFail(",
    ),
    (
        "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/"
        "core/model/instructions/CancelAssetLockInstructionTest.kt"
    ): (
        "REQUIRED_FIXTURE_NAMES.associateWith",
        "readMandatoryFixture(root, relative)",
        "check(Files.isRegularFile(path))",
        "CancelAssetLockInstruction.fromCanonicalFields(",
        "CancelAssetLockInstruction.fromWirePayload(",
    ),
    (
        "java/iroha_android/src/test/java/org/hyperledger/iroha/android/"
        "model/instructions/CancelAssetLockInstructionTests.java"
    ): (
        "for (final String relative : REQUIRED_FIXTURE_NAMES)",
        "readMandatoryFixture(root, relative)",
        "Files.isRegularFile(path)",
    ),
    "csharp/tests/Hyperledger.Iroha.Sdk.Tests/CancelAssetLockInstructionTests.cs": (
        "public void SharedFixturesEnforceTheV1HardCut()",
        "Assert.True(",
        "File.Exists(path)",
        "return File.ReadAllBytes(path);",
    ),
    "javascript/iroha_js/test/sorafsNativeSuites/cancelAssetLockV1.js": (
        "requiredFixtureNames.map",
        "fs.readFileSync(path.join(fixtureRoot, name))",
        "all eight appeal-finance CancelAssetLock fixtures are mandatory",
    ),
    "python/iroha_python/tests/cancel_asset_lock_v1_test.py": (
        "_FIXTURES = {",
        "(_FIXTURE_ROOT / name).read_bytes()",
        "test_all_eight_appeal_finance_cancel_asset_lock_fixtures_are_mandatory",
    ),
}

STRICT_NATIVE_PROFILE_MARKERS = {
    "IrohaSwift/Tests/IrohaSwiftTests/SorafsReferenceValidatorsTests.swift": (
        "guard SorafsReferenceValidators.isAppealFinanceNativeAvailable else {",
        'return XCTFail("ABI-29 appeal-finance reference bridge is required")',
    ),
    (
        "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/"
        "sorafs/SorafsReferenceValidatorsTest.kt"
    ): (
        "SorafsReferenceValidators.isNativeAvailable()",
        '"ABI-29 appeal-finance reference bridge is required"',
    ),
    (
        "java/iroha_android/src/test/java/org/hyperledger/iroha/android/"
        "sorafs/SorafsReferenceValidatorsTests.java"
    ): (
        "requireNativeBridge();",
        "throw new AssertionError(",
        '"ABI-29 connect_norito_bridge with all SoraFS reference symbols is required."',
    ),
    "csharp/tests/Hyperledger.Iroha.Sdk.Tests/SoraFsReferenceValidatorsTests.cs": (
        "SoraFsReferenceValidators.IsAppealFinanceAvailable()",
        '"ABI-29 appeal-finance reference bridge is required."',
    ),
    "javascript/iroha_js/test/helpers/nativeRequirements.js": (
        "registerNativeRequirementFailure(",
        "throw createError();",
        'error.code = "ERR_IROHA_NATIVE_TEST_REQUIREMENT"',
    ),
}

MATERIAL_CLOSURE_PATHS_BY_WORKFLOW = {
    "openapi.yml": {
        "crates/iroha_torii_shared/src/sorafs_moderation_api.rs",
        "crates/iroha_torii_shared/src/lib.rs",
        "crates/iroha_torii_shared/src/route_catalog.rs",
        "crates/iroha_torii/src/lib.rs",
        "crates/iroha_torii/src/openapi.rs",
        "crates/iroha_torii/src/sorafs/api.rs",
    },
    "mobile_sdk_artifacts.yml": {
        "IrohaSwift/Package.swift",
        "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift",
        "IrohaSwift/Tests/IrohaSwiftTests/NativeBridgeLoaderTests.swift",
        "fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.json",
        (
            "fixtures/sorafs_manifest/reference_sdk/"
            "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
        ),
        "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json",
        "integration_tests/tests/native_escrow.rs",
        "roadmap.md",
        "specs/sorafs/v1_closure_ledger.md",
        "specs/sorafs_reference_sdk_plan.md",
    },
    "pr_csharp.yml": {
        (
            "csharp/tests/Hyperledger.Iroha.Sdk.Tests/"
            "SoraFsReferenceValidatorsTests.cs"
        ),
        "fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.json",
        (
            "fixtures/sorafs_manifest/reference_sdk/"
            "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
        ),
        "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json",
        "integration_tests/tests/native_escrow.rs",
    },
    "sorafs-orchestrator-sdk.yml": {
        "scripts/sorafs_javascript_test_events.mjs",
        "scripts/tests/sorafs_javascript_test_events_test.mjs",
        "scripts/sorafs_javascript_child_files.mjs",
        "scripts/tests/sorafs_javascript_child_files_test.mjs",
        "IrohaSwift/Package.swift",
        "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift",
        "IrohaSwift/Tests/IrohaSwiftTests/NativeBridgeLoaderTests.swift",
        "javascript/iroha_js/scripts/run-test-profile.mjs",
        "javascript/iroha_js/test/sorafsFixtureBundleValidation.test.js",
        "javascript/iroha_js/test/sorafsPdpValidation.test.js",
        "fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.json",
        "fixtures/sorafs_manifest/orderbook/order_request_v1.to",
        "fixtures/sorafs_manifest/pdp/commitment_v1.to",
        "fixtures/sorafs_manifest/por/proof_v1.to",
        "fixtures/sorafs_manifest/potr/receipt_v1.to",
        "fixtures/sorafs_manifest/provider_admission/advert_v1.to",
        "fixtures/sorafs_manifest/repair/task_v1.to",
        "fixtures/sorafs_manifest/replication_order/order_v1.to",
        (
            "fixtures/sorafs_manifest/reference_sdk/"
            "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
        ),
        "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json",
        "integration_tests/tests/native_escrow.rs",
        "python/iroha_torii_client/tests/orderbook_submission_test.py",
        "crates/iroha_data_model/src/sorafs/orderbook_submission_tests.rs",
        "scripts/deploy_localnet.sh",
        "scripts/norito_bridge_apple_slice_handoff.py",
        "scripts/norito_bridge_source_seal.py",
        "scripts/package_mobile_sdk_artifacts.sh",
        "scripts/run_mobile_hermetic_command.py",
    },
    "sorafs-fixtures-nightly.yml": {
        "fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.json",
        (
            "fixtures/sorafs_manifest/reference_sdk/"
            "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
        ),
        "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json",
        "integration_tests/tests/native_escrow.rs",
    },
}


def read(relative: str) -> str:
    """Read one repository file as UTF-8."""

    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def workflow_event_paths(workflow_name: str, event: str) -> set[str]:
    """Return one literal GitHub workflow event path filter."""

    source = (WORKFLOW_ROOT / workflow_name).read_text(encoding="utf-8")
    match = re.search(
        rf"(?m)^  {re.escape(event)}:\n"
        r"(?P<body>(?:^    [^\n]*\n)*)",
        source,
    )
    assert match is not None, f"{workflow_name} must define {event}"
    body = match.group("body")
    paths = re.search(
        r'(?m)^    paths:\n(?P<paths>(?:^      - "[^"\n]+"\n)+)',
        body,
    )
    assert paths is not None, f"{workflow_name} must define {event}.paths"
    return {
        line.removeprefix("      - ").strip().strip('"')
        for line in paths.group("paths").splitlines()
    }


def pull_request_paths(workflow_name: str) -> set[str]:
    """Return the literal pull-request path filter from one workflow."""

    return workflow_event_paths(workflow_name, "pull_request")


def workflow_filter_covers(path: str, filters: set[str]) -> bool:
    """Return whether literal GitHub path filters cover one repository path."""

    for candidate in filters:
        if candidate == path:
            return True
        if candidate.endswith("/**"):
            prefix = candidate.removesuffix("/**")
            if path == prefix or path.startswith(f"{prefix}/"):
                return True
    return False


def core_verifier_owner_trigger_errors(source: str) -> list[str]:
    """Require extracted verifier paths in each event already filtered on Core."""

    errors = []
    for match in re.finditer(
        r"(?m)^  (?P<event>pull_request|push):\n"
        r"(?P<body>(?:^    [^\n]*\n)*)",
        source,
    ):
        paths = set(re.findall(r'^      - "([^"\n]+)"$', match["body"], re.M))
        if "crates/iroha_core/**" in paths:
            missing = sorted(CORE_VERIFIER_OWNER_TRIGGER_PATHS - paths)
            if missing:
                errors.append(f"{match['event']} omits verifier owner triggers: {missing}")
    return errors


@pytest.mark.parametrize("workflow_name", CORE_VERIFIER_OWNER_WORKFLOWS)
def test_core_verifier_owners_trigger_existing_core_workflows(workflow_name: str) -> None:
    """Owner-only changes retain the qualification previously selected by Core."""

    assert "crates/iroha_core/**" in pull_request_paths(workflow_name)
    source = read(f".github/workflows/{workflow_name}")
    assert not core_verifier_owner_trigger_errors(source)


@pytest.mark.parametrize("event", ("pull_request", "push"))
@pytest.mark.parametrize("owner", sorted(CORE_VERIFIER_OWNER_TRIGGER_PATHS))
def test_core_verifier_owner_triggers_reject_missing_owner_per_event(
    event: str, owner: str,
) -> None:
    """An unrelated event's complete paths cannot hide a missing owner trigger."""

    paths = "".join(
        f'      - "{path}"\n'
        for path in sorted(CORE_VERIFIER_OWNER_TRIGGER_PATHS | {"crates/iroha_core/**"})
    )
    source = "on:\n" + "".join(
        f"  {name}:\n    paths:\n{paths}"
        for name in ("pull_request", "push")
    )
    assert not core_verifier_owner_trigger_errors(source)
    original = f"  {event}:\n    paths:\n{paths}"
    missing = original.replace(f'      - "{owner}"\n', "", 1)
    mutated = source.replace(original, missing, 1)
    assert core_verifier_owner_trigger_errors(mutated) == [
        f"{event} omits verifier owner triggers: {[owner]}"
    ]


@pytest.mark.parametrize(
    ("workflow_name", "material_paths"),
    MATERIAL_CLOSURE_PATHS_BY_WORKFLOW.items(),
)
def test_material_closure_files_are_routed_to_relevant_workflows(
    workflow_name: str,
    material_paths: set[str],
) -> None:
    """Changed V1 closure inputs must start every workflow that consumes them."""

    filters = pull_request_paths(workflow_name)
    missing_files = sorted(
        path for path in material_paths if not (REPO_ROOT / path).is_file()
    )
    assert not missing_files, f"closure inventory names missing files: {missing_files}"
    uncovered = sorted(
        path
        for path in material_paths
        if not workflow_filter_covers(path, filters)
    )
    assert not uncovered, f"{workflow_name} omits closure triggers: {uncovered}"


@pytest.mark.parametrize("workflow_name", ("sorafs-cli-release.yml", "sorafs-orchestrator-sdk.yml"))
def test_javascript_event_owner_and_controls_have_explicit_workflow_triggers(workflow_name):
    """Tool changes must trigger parity independently of the broad SDK path."""
    filters = pull_request_paths(workflow_name)
    from scripts import check_sorafs_release_automation as automation
    for path in automation.SORAFS_JAVASCRIPT_CHILD_PATHS:
        assert (REPO_ROOT / path).is_file()
        assert path in filters and workflow_filter_covers(path, filters)
        assert not workflow_filter_covers(path, filters - {path})


def test_javascript_event_controls_execute_immediately_after_node24_setup():
    """The tool suite is a mandatory step, not a marker or Node20 SDK unit test."""
    from scripts import check_sorafs_release_automation as automation

    relative = ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = read(relative)
    assert not automation._javascript_child_controls_workflow_errors(relative, source)
    command = automation.SORAFS_JAVASCRIPT_CHILD_COMMAND
    changed = source.replace("        run: " + command, "        run: true", 1)
    changed += "\n# " + command + "\n"
    assert automation._javascript_child_controls_workflow_errors(relative, changed)


def test_pure_orderbook_submit_suite_requires_its_orchestrator_trigger() -> None:
    path = "python/iroha_torii_client/tests/orderbook_submission_test.py"
    filters = pull_request_paths("sorafs-orchestrator-sdk.yml")
    trigger = "python/iroha_torii_client/**"
    assert trigger in filters and workflow_filter_covers(path, filters)
    assert not workflow_filter_covers(path, filters - {trigger})


def test_orchestrator_runner_executes_shared_orderbook_submission_boundary() -> None:
    runner = read("ci/sdk_sorafs_orchestrator.sh")
    assert "cargo test -p iroha_data_model sorafs::orderbook_submission::tests" in runner
    assert "signed orderbook submission boundary" in runner


def test_openapi_push_and_pull_request_filters_cover_moderation_sources() -> None:
    """The canonical generator must run for moderation changes on both events."""

    for event in ("pull_request", "push"):
        filters = workflow_event_paths("openapi.yml", event)
        uncovered = sorted(
            path
            for path in MATERIAL_CLOSURE_PATHS_BY_WORKFLOW["openapi.yml"]
            if not workflow_filter_covers(path, filters)
        )
        assert not uncovered, (
            f"openapi.yml {event} omits closure triggers: {uncovered}"
        )


@pytest.mark.parametrize(
    "workflow_name",
    [
        "mobile_sdk_artifacts.yml",
        "pr_csharp.yml",
        "sorafs-orchestrator-sdk.yml",
    ],
)
def test_native_sdk_workflows_cover_appeal_finance_and_escrow_sources(
    workflow_name: str,
) -> None:
    """Every relevant SDK job reruns for all shared native-escrow inputs."""

    paths = pull_request_paths(workflow_name)
    assert not any(
        path.startswith(("jobs:", "name:", "run:", "runs-on:", "uses:"))
        for path in paths
    ), f"{workflow_name} path parser leaked workflow job fields"
    assert NATIVE_ESCROW_TRIGGER_PATHS <= paths
    assert "scripts/check_sorafs_reference_sdk_fixtures.py" in paths
    assert "scripts/tests/check_sorafs_fixture_workflow_contract_test.py" in paths


@pytest.mark.parametrize(
    "workflow_name",
    [
        "mobile_sdk_artifacts.yml",
        "pr_csharp.yml",
        "sorafs-orchestrator-sdk.yml",
    ],
)
def test_native_sdk_workflows_cover_every_shared_appeal_finance_fixture(
    workflow_name: str,
) -> None:
    """Each mandatory payload and outcome must independently rerun SDK parity."""

    required = (
        APPEAL_FINANCE_SHARED_FIXTURE_TRIGGER_PATHS
        | APPEAL_FINANCE_VALIDATION_PROFILE_TRIGGER_PATHS
    )
    missing_files = sorted(
        path for path in required if not (REPO_ROOT / path).is_file()
    )
    assert not missing_files, (
        f"appeal-finance workflow inventory names missing files: {missing_files}"
    )

    filters = pull_request_paths(workflow_name)
    uncovered = sorted(
        path for path in required if not workflow_filter_covers(path, filters)
    )
    assert not uncovered, (
        f"{workflow_name} omits appeal-finance fixture triggers: {uncovered}"
    )


@pytest.mark.parametrize(
    ("test_path", "mandatory_markers"),
    SDK_FIXTURE_READERS.items(),
)
def test_every_sdk_unconditionally_reads_all_eight_appeal_finance_fixtures(
    test_path: str,
    mandatory_markers: tuple[str, ...],
) -> None:
    """Every SDK loader must fail when any shared cancellation fixture is absent."""

    source = read(test_path)
    for fixture_path in APPEAL_FINANCE_FIXTURE_PATHS:
        assert Path(fixture_path).name in source, (
            f"{test_path} does not require {fixture_path}"
        )
    for marker in mandatory_markers:
        assert marker in source, f"{test_path} lost mandatory loader marker {marker!r}"
    assert "fixture missing; skipping" not in source.lower()
    assert "skipif" not in source.lower()


@pytest.mark.parametrize(
    ("test_path", "required_markers"),
    STRICT_NATIVE_PROFILE_MARKERS.items(),
)
def test_native_appeal_finance_profiles_fail_instead_of_skipping(
    test_path: str,
    required_markers: tuple[str, ...],
) -> None:
    """A missing ABI-29 bridge is a parity failure in every native SDK lane."""

    source = read(test_path)
    for marker in required_markers:
        assert marker in source, f"{test_path} lost strict native marker {marker!r}"
    for skip_marker in (
        "XCTSkip(",
        "Assumptions.assume",
        "assumeTrue(",
        "Assert.Skip(",
        "test.skip(",
    ):
        assert skip_marker not in source


def test_appeal_finance_fixture_directory_has_the_exact_eight_payloads() -> None:
    """The shared payload directory cannot silently add or lose a V1 fixture."""

    fixture_root = (
        REPO_ROOT / "fixtures" / "sorafs_manifest" / "appeal_finance"
    )
    actual = {
        path.relative_to(fixture_root).as_posix()
        for path in fixture_root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".to"}
    }
    assert actual == set(APPEAL_FINANCE_FIXTURE_PATHS)


def test_por_generator_closed_set_count_matches_checked_in_managed_outputs() -> None:
    """Keep the generator tripwire synchronized with its closed output tree."""

    generator = read("crates/sorafs_manifest/src/bin/generate_por_fixtures.rs")
    count_match = re.search(
        r"EXPECTED_MANAGED_FIXTURE_COUNT:\s*usize\s*=\s*(\d+);",
        generator,
    )
    assert count_match is not None

    fixture_root = REPO_ROOT / "fixtures" / "sorafs_manifest"
    managed_directories = (
        "governance",
        "moderation",
        "por",
        "potr",
        "reference_sdk",
        "repair",
    )
    managed_paths = {
        path.relative_to(fixture_root).as_posix()
        for directory in managed_directories
        for path in (fixture_root / directory).rglob("*")
        if path.is_file() and path.name != "README.md"
    }
    managed_paths.add("reference_sdk_validation_inventory_v1.json")

    assert int(count_match.group(1)) == len(managed_paths) == 61
    assert {
        (
            "reference_sdk/"
            "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"
        ),
        (
            "reference_sdk/"
            "appeal_finance_cancel_asset_lock_zero_expected_negative_"
            "validation_outcome_v1.json"
        ),
        "reference_sdk/pop_membership_current_v1.to",
        "reference_sdk/pop_membership_current_v1_validation_outcome.json",
        "reference_sdk/pop_membership_missing_binding_v1.to",
        "reference_sdk/pop_membership_missing_binding_v1_validation_outcome.json",
        "reference_sdk/pop_membership_zero_binding_v1.to",
        "reference_sdk/pop_membership_zero_binding_v1_validation_outcome.json",
    } <= managed_paths


def test_fixture_workflow_covers_closed_reference_sdk_inputs() -> None:
    """The nightly fixture job cannot miss wire, fixture, or checker changes."""

    paths = pull_request_paths("sorafs-fixtures-nightly.yml")
    expected = NATIVE_ESCROW_TRIGGER_PATHS - {"crates/connect_norito_bridge/**"}
    assert expected <= paths
    assert {
        "ci/check_sorafs_fixtures.sh",
        "fixtures/sorafs_manifest/**",
        "scripts/check_sorafs_reference_sdk_fixtures.py",
        "scripts/tests/check_sorafs_fixture_workflow_contract_test.py",
        "scripts/tests/check_sorafs_reference_sdk_fixtures_test.py",
    } <= paths


def test_fixture_workflow_requires_its_installed_toolchains() -> None:
    """A broken Node or Go setup is a gate failure, not a capability skip."""

    workflow = read(".github/workflows/sorafs-fixtures-nightly.yml")
    fixture_gate = read("ci/check_sorafs_fixtures.sh")
    assert "SORAFS_FIXTURE_REQUIRE_TOOLCHAIN" not in workflow
    assert "SORAFS_FIXTURE_REQUIRE_TOOLCHAIN" not in fixture_gate
    assert "require_fixture_tool node" in fixture_gate
    assert "require_fixture_tool go" in fixture_gate
    assert "error: ${check_label} requires ${tool_name}" in fixture_gate
    assert "skipping ${check_label}" not in fixture_gate


def test_reference_sdk_regeneration_is_closed_and_double_run_stable() -> None:
    """Both generators, the signed inventory, and all bytes are checked twice."""

    fixture_gate = read("ci/check_sorafs_fixtures.sh")
    cargo_commands = [
        line.strip()
        for line in fixture_gate.splitlines()
        if line.strip().startswith("cargo ")
        or line.strip().startswith("NORITO_SKIP_BINDINGS_SYNC=1 cargo ")
    ]
    assert cargo_commands
    assert all("--locked" in command for command in cargo_commands)
    assert (
        fixture_gate.count(
            "python3 scripts/check_sorafs_reference_sdk_fixtures.py"
        )
        == 2
    )
    assert "for fixture_regeneration_pass in 1 2; do" in fixture_gate
    assert "--bin cancel_asset_lock_fixtures" in fixture_gate
    assert "--bin generate_pdp_fixtures" in fixture_gate
    assert "--bin generate_por_fixtures" in fixture_gate
    assert 'copy_manifest_tree "${pass_root}"' in fixture_gate
    assert 'verify_manifest_tree_paths "${pass_root}"' in fixture_gate
    assert '--output-dir "${pass_root}/appeal_finance"' in fixture_gate
    assert '--output-dir "${pass_root}/pdp"' in fixture_gate
    assert '--output-dir "${pass_root}"' in fixture_gate
    assert '--inventory "${pass_root}/reference_sdk_validation_inventory_v1.json"' in fixture_gate
    regeneration_loop = fixture_gate.split(
        "for fixture_regeneration_pass in 1 2; do", maxsplit=1
    )[1].split("\ndone\n", maxsplit=1)[0]
    assert regeneration_loop.index("--bin generate_pdp_fixtures") < (
        regeneration_loop.index("--bin generate_por_fixtures")
    )
    assert '"git", "ls-files", "-z", "--", str(source_root)' in fixture_gate
    assert "if actual_paths != tracked_paths:" in fixture_gate
    assert "missing = sorted(tracked_paths - actual_paths)" in fixture_gate
    assert "extra = sorted(actual_paths - tracked_paths)" in fixture_gate
    assert '"fixtures/sorafs_manifest"' in fixture_gate
    assert '"byte_length": byte_length' in fixture_gate
    assert '"sha256": digest.hexdigest()' in fixture_gate
    assert "generators run in place" not in fixture_gate
    assert "Reference-SDK generators run in two isolated" in fixture_gate
    assert 'getattr(os, "O_NOFOLLOW", 0)' in fixture_gate
    assert "descriptor = os.open(path, read_flags)" in fixture_gate
    assert "path.open(" not in fixture_gate
    assert "opened.st_nlink != 1" in fixture_gate
    assert "(before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)" in fixture_gate
    assert "opened.st_mtime_ns != after.st_mtime_ns" in fixture_gate
    assert "byte_length != after.st_size" in fixture_gate
    assert "max_copy_file_bytes = 64 << 20" in fixture_gate
    assert "changed during fixture copy" in fixture_gate
    assert "changed while it was hashed" in fixture_gate
    assert "directory_identities" in fixture_gate
    assert "manifest-checked-in.json" in fixture_gate
    assert "manifest-pass-1.json" in fixture_gate
    assert "manifest-pass-2.json" in fixture_gate
    assert "cmp -s" in fixture_gate
    assert 'fixture_snapshot_root="$(mktemp -d ' in fixture_gate
    assert 'cd -- "${fixture_snapshot_root}"' in fixture_gate
    assert "pwd -P" in fixture_gate
    assert "git status --short --untracked-files=all -- fixtures/sorafs_manifest" not in fixture_gate


def test_manifest_generator_enables_required_vrf_and_drand_crypto() -> None:
    """The standalone locked generator must compile without feature unification."""

    manifest = read("crates/sorafs_manifest/Cargo.toml")
    assert (
        'iroha_crypto = { workspace = true, default-features = false, '
        'features = ["application", "bls"] }'
    ) in manifest


def test_por_fixture_generator_has_a_strict_isolated_output_root() -> None:
    """The aggregate generator cannot ambiguously redirect fixture writes."""

    entrypoint = read("crates/sorafs_manifest/src/bin/generate_por_fixtures.rs")
    assert '#[path = "common/fixture_fs.rs"]\nmod fixture_fs;' in entrypoint
    generator = "\n".join(
        (
            entrypoint,
            read(
                "crates/sorafs_manifest/src/bin/generate_por_fixtures/"
                "output_transaction_tests.rs"
            ),
            read("crates/sorafs_manifest/src/bin/common/fixture_fs.rs"),
        )
    )
    assert "fn parse_args(" in generator
    assert 'Some("--output-dir")' in generator
    assert "`--output-dir` may be specified only once" in generator
    assert "`--output-dir` requires a separate path argument" in generator
    assert "`--output-dir` path must be valid UTF-8" in generator
    assert "`--output-dir` path must not be ambiguous with an option" in generator
    assert "Component::CurDir" in generator
    assert "Component::ParentDir" in generator
    assert "`--output-dir` must name a bounded fixture directory" in generator
    assert "fn generate_fixtures(fixtures_root: &Path)" in generator
    assert "struct BoundDirectory" in generator
    assert "struct BoundWorkingDirectory" in generator
    assert "require_real_directory_ancestry" in generator
    assert "same_directory_identity" in generator
    assert "set_working_directory_handle" in generator
    assert "fchdir(directory.as_raw_fd())" in generator
    assert "output_root_binding_rejects_an_existing_non_directory" in generator
    assert "output_root_binding_rejects_an_existing_symlink" in generator
    assert "bound_output_never_follows_a_parent_substitution" in generator
    assert "output_dir_rejects_missing_duplicate_and_joined_values" in generator
    assert "output_dir_rejects_ambiguous_or_unbounded_paths" in generator


def test_pdp_fixture_generator_has_a_strict_isolated_output_root() -> None:
    """The PDP precursor cannot ambiguously redirect or alias fixture writes."""

    entrypoint = read("crates/sorafs_manifest/src/bin/generate_pdp_fixtures.rs")
    assert '#[path = "common/fixture_fs.rs"]\nmod fixture_fs;' in entrypoint
    generator = "\n".join(
        (entrypoint, read("crates/sorafs_manifest/src/bin/common/fixture_fs.rs"))
    )
    assert "fn parse_args(" in generator
    assert 'Some("--output-dir")' in generator
    assert "`--output-dir` may be specified only once" in generator
    assert "`--output-dir` requires a separate path argument" in generator
    assert "`--output-dir` path must be valid UTF-8" in generator
    assert "`--output-dir` path must not be ambiguous with an option" in generator
    assert "Component::CurDir" in generator
    assert "Component::ParentDir" in generator
    assert "MAX_OUTPUT_PATH_BYTES" in generator
    assert "MAX_OUTPUT_PATH_COMPONENTS" in generator
    assert "`--output-dir` must name a bounded PDP fixture directory" in generator
    assert "struct BoundDirectory" in generator
    assert "require_real_directory_ancestry" in generator
    assert "same_directory_identity" in generator
    assert "fn write_fixture_file(" in generator
    assert "must have exactly one hard link" in generator


def test_parity_fixture_snapshot_rejects_missing_inputs() -> None:
    """The SDK parity artifact collector cannot silently omit a fixture."""

    parity_gate = read("ci/sdk_sorafs_orchestrator.sh")
    assert 'sys.exit(f"[sorafs-sdk] {label} missing: {path}")' in parity_gate
    assert "warning: fixture file missing" not in parity_gate
    assert "if source is None:" not in parity_gate


def test_native_release_jobs_build_and_require_the_bridge() -> None:
    """C# and both mobile jobs fail closed when the ABI-29 bridge is absent."""

    csharp = read(".github/workflows/pr_csharp.yml")
    mobile = read(".github/workflows/mobile_sdk_artifacts.yml")
    parity = read(".github/workflows/sorafs-orchestrator-sdk.yml")

    assert 'IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"' in csharp
    assert (
        'cargo build --locked --release -p connect_norito_bridge --target "$target"'
        in csharp
    )
    assert "package_csharp_native_artifacts.py verify-package" in csharp
    assert mobile.count('IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"') == 2
    assert "name: Build NoritoBridge XCFramework" in mobile
    assert "name: Build host SoraFS reference native bridge" in mobile
    parity_runner = read("ci/sdk_sorafs_orchestrator.sh")
    assert parity_runner.count("npm run build:native") == 1
    assert parity_runner.count("IROHA_JS_NATIVE_BUILD_PROFILE=") == 1
    assert (
        "IROHA_JS_NATIVE_BUILD_PROFILE=release npm run build:native"
        in parity_runner
    )
    assert 'mktemp -d "${TMPDIR:-/tmp}/iroha-sorafs-js-native-target.XXXXXX"' in parity_runner
    assert "native_cargo=\"$(rustup which cargo)\"" in parity_runner
    assert "native_rustc=\"$(rustup which rustc)\"" in parity_runner
    assert "native_rustdoc=\"$(rustup which rustdoc)\"" in parity_runner
    for build_binding in (
        "CARGO_BUILD_JOBS=1",
        "CARGO_INCREMENTAL=0",
        "CARGO_NET_OFFLINE=true",
        'CARGO_TARGET_DIR="${native_build_target}"',
        'IROHA_JS_CARGO_LOCKFILE_PATH="${REPO_ROOT}/Cargo.lock"',
        'IROHA_JS_CARGO_PATH="${native_cargo}"',
        'RUSTC="${native_rustc}"',
        "unset RUSTC_BOOTSTRAP",
        'RUSTDOC="${native_rustdoc}"',
    ):
        assert build_binding in parity_runner
    assert "RUSTC_BOOTSTRAP=1" not in parity_runner
    assert "node scripts/run-test-profile.mjs sorafs-native" in parity_runner
    javascript_profile_runner = read("javascript/iroha_js/scripts/run-test-profile.mjs")
    assert '"cancelAssetLockV1.test.js"' in javascript_profile_runner
    assert '"sorafsAppealFinanceValidation.test.js"' in javascript_profile_runner
    assert '"sorafsFixtureBundleValidation.test.js"' in javascript_profile_runner
    assert '"sorafsOrderbookSubmission.test.js"' in javascript_profile_runner
    assert '"sorafsOrchestrator.parity.test.js"' in javascript_profile_runner
    assert '"sorafsPdpValidation.test.js"' in javascript_profile_runner
    assert "swift test --filter SorafsOrchestratorParityTests" in parity_runner
    assert "swift test --filter CancelAssetLockV1Tests" in parity_runner
    assert "swift test --filter SorafsReferenceValidatorsTests" in parity_runner
    assert "name: Build exact ABI-29 NoritoBridge XCFramework" in parity
    assert "check_mobile_sdk_artifacts.sh --apple-only" in parity
    assert parity.count("IROHA_JS_NATIVE_BUILD_PROFILE:") == 1
    assert 'IROHA_JS_NATIVE_BUILD_PROFILE: "release"' in parity
    assert parity.count('IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"') == 3
    assert '"crates/iroha_js_host/**"' in parity
    assert '"python/iroha_torii_client/**"' in parity
    assert "bash ci/sdk_sorafs_orchestrator.sh" in parity
    assert "  mobile-parity:" in parity
    assert "  csharp-parity:" in parity
    assert parity.count("name: Bind the canonical mobile Python") == 2
    assert parity.count(
        'echo "MOBILE_SDK_PYTHON_BINARY=$mobile_python" >> "$GITHUB_ENV"'
    ) == 2
    assert 'java-version: "21"' in parity
    assert 'echo "IROHA_NATIVE_LIBRARY_PATH=$native_dir" >> "$GITHUB_ENV"' in parity
    assert 'test ! -e "$native_root"' in parity
    assert '--target "$target" --target-dir "$native_root/cargo-target"' in parity
    assert "./gradlew --no-daemon --no-build-cache --rerun-tasks" in parity
    assert ":core-jvm:test :tools:test" in parity
    assert ":client-android:testDebugHostNative" in parity
    assert "Reauthenticate the consumed Kotlin bridge" in parity
    assert 'sdkmanager_status="${PIPESTATUS[1]}"' in parity
    assert 'exit "$sdkmanager_status"' in parity
    assert (
        'cargo build --locked --release -p connect_norito_bridge --target "$target"'
        in parity
    )
    assert "check_native_sdk_artifact.py record" in parity
    assert "check_native_sdk_artifact.py verify" in parity
    assert "native-sdk-abi29.json" in parity
    assert "ABI-21" not in parity
    assert (
        "dotnet build Hyperledger.Iroha.Sdk.sln -c Release --no-restore "
        "-warnaserror"
        in parity
    )
    assert "dotnet test Hyperledger.Iroha.Sdk.sln -c Release --no-build" in parity
    assert "continue-on-error:" not in parity
    assert "|| true" not in parity
    for trigger in (
        '".cargo/**"',
        '"codec/**"',
        '"kotlin/**"',
        '"java/iroha_android/**"',
        '"java/norito_java/**"',
        '"csharp/**"',
        '"gradle/mobile-sdk-external-android-build.settings.gradle.kts"',
        '"scripts/package_mobile_sdk_artifacts.sh"',
        '"scripts/tests/deploy_localnet_test.py"',
        '"rust-toolchain"',
        '"vendor/**"',
    ):
        assert trigger in parity


def test_swift_native_bridge_contract_requires_universal_macos_slice() -> None:
    """Apple release lanes build and authenticate both macOS architectures."""

    mobile = read(".github/workflows/mobile_sdk_artifacts.yml")
    parity = read(".github/workflows/sorafs-orchestrator-sdk.yml")
    for workflow in (mobile, parity):
        assert (
            '"$rustup_path" target add aarch64-apple-ios aarch64-apple-ios-sim '
            "x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin"
            in workflow
        )
        assert 'rustup_source="$(command -v rustup)"' in workflow
        assert 'rustup_path="$rustup_tools/rustup"' in workflow
        assert '/bin/cp "$rustup_source" "$rustup_path"' in workflow
        assert '"${rustup_path##*/}" == rustup' in workflow
        assert "MOBILE_SDK_RUSTUP_BINARY=$rustup_path" in workflow
        assert (
            'rustc_path="$("$MOBILE_SDK_RUSTUP_BINARY" which '
            '--toolchain 1.93.1 rustc)"'
            in workflow
        )

    builder = read("scripts/build_norito_xcframework.sh")
    assert "MOBILE_SDK_RUSTUP_BINARY" in builder
    assert 'MOBILE_SDK_RUSTUP_BINARY="$RUSTUP_BINARY"' in builder
    assert 'MACOS_ARM_TRIPLE="aarch64-apple-darwin"' in builder
    assert 'MACOS_X64_TRIPLE="x86_64-apple-darwin"' in builder
    assert (
        '"$LIPO_BINARY" -create -output "$MAC_UNI" '
        '"$LIB_MAC_ARM" "$LIB_MAC_X64"'
        in builder
    )
    assert '"macos-arm64_x86_64"' in builder

    checker = read("scripts/check_mobile_sdk_artifacts.sh")
    assert "MOBILE_SDK_RUSTUP_BINARY" in checker
    assert (
        "for slice in ios-arm64 ios-arm64_x86_64-simulator "
        "macos-arm64_x86_64; do"
        in checker
    )
    # The shell owns authenticated dispatch; the shared validator owns the
    # closed slice inventory and checks the actual Info.plist metadata.
    assert '"$ROOT_DIR/scripts/validate_norito_bridge_xcframework.py"' in checker
    for argument in (
        '--root "$ROOT_DIR"',
        '--lockfile-path "$CARGO_LOCKFILE"',
        '--xcframework "$xcframework"',
        '--manifest "$manifest"',
        '--manifest-link "$manifest_link"',
        '--expected-link-target "NoritoBridge.xcframework/NoritoBridge.artifacts.json"',
        '--swift-loader "$loader"',
        "--verify-repository-provenance",
    ):
        assert argument in checker
    assert 'if ! run_source_authenticated_python "${validation[@]}"; then' in checker
    assert 'fail "strict NoritoBridge XCFramework validation failed"' in checker
    validator = read("scripts/validate_norito_bridge_xcframework.py")
    assert '"macos-arm64_x86_64": {' in validator
    assert '"architectures": ["arm64", "x86_64"]' in validator
    assert "set(metadata) != set(EXPECTED_SLICES)" in validator
    assert 'library.get("SupportedArchitectures") != expected["architectures"]' in validator

    loader = read("IrohaSwift/Sources/IrohaSwift/NativeBridge.swift")
    assert 'return "macos-arm64_x86_64"' in loader
    assert '"macos-arm64_x86_64":' in loader
    assert '"macos-arm64":' not in loader


def test_python_native_lane_covers_appeal_finance_and_provider_ingest_without_skips() -> None:
    """The Python ABI-29 lane must exercise every native SoraFS V1 profile."""

    runner = read("ci/check_sorafs_python_native_sdk.sh")
    ignore_rules = read(".gitignore")
    assert 'if [[ "${PYTHON_VERSION}" != "3.12" ]]' in runner
    assert 'git -C "${ROOT_DIR}" ls-files -- \\' in runner
    for native_pattern in ("*.so", "*.so.*", "*.dylib", "*.pyd", "*.dll"):
        assert (
            f"'python/iroha_python/src/iroha_python/{native_pattern}'" in runner
        )
        assert (
            f"python/iroha_python/src/iroha_python/{native_pattern}" in ignore_rules
        )
    assert "Python native SDK artifacts must be rebuilt in the ABI-29 lane, not tracked" in runner
    assert 'export VIRTUAL_ENV="${SDK_SESSION}/venv"' in runner
    assert 'export PATH="${VIRTUAL_ENV}/bin:${PATH}"' in runner
    assert 'cd "${ROOT_DIR}/python/iroha_native"' in runner
    assert (
        '"${VENV_PYTHON}" -m maturin build --release --locked --out "${NATIVE_WHEELS}"'
        in runner
    )
    assert "maturin develop" not in runner
    assert 'cd "${ROOT_DIR}/python/iroha_python"' in runner
    assert '-m pip --isolated wheel --no-deps --no-index' in runner
    assert '--no-build-isolation --wheel-dir "${SDK_WHEELS}" .' in runner
    assert "each Python owner must produce exactly one fresh wheel" in runner
    assert 'WHEEL_VERIFIER="${ROOT_DIR}/ci/verify_privacy_python_wheel.py"' in runner
    for owner in ("NATIVE", "SDK"):
        assert f'--seal "${{{owner}_WHEEL}}"' in runner
        assert (
            f'--preflight {owner.lower()} "${{{owner}_WHEEL}}" "${{{owner}_SEAL}}"'
            in runner
        )
    assert '-m pip --isolated install --no-compile --no-deps --no-index' in runner
    assert 'NATIVE_EXTENSION="$(verify_installed_wheels)"' in runner
    assert "verify_installed_wheels >/dev/null" in runner
    assert (
        '"${VENV_PYTHON}" -I "${ROOT_DIR}/scripts/check_native_sdk_artifact.py"'
        in runner
    )
    assert "tests/cancel_asset_lock_v1_test.py" in runner
    assert "tests/cancel_asset_lock_client_helpers_test.py" in runner
    assert "tests/client_hard_cut_contract_test.py" in runner
    assert "tests/client_ledger_helpers_test.py" in runner
    assert "tests/client_sorafs_orderbook_test.py" in runner
    assert "tests/sorafs_reference_validation_test.py" in runner
    assert "tests/sorafs_replication_instruction_test.py" in runner
    assert "../iroha_torii_client/tests/orderbook_submission_test.py" in runner
    for suite in ("account_identity_native_v1_test.py", "requests_deadline_test.py",
                  "staking_preparation_test.py", "validator_staking_test.py"):
        assert f"tests/{suite}" in runner
    assert runner.index('SOURCE_BEFORE_PIN=') < runner.index('-m maturin build')
    assert runner.index('SOURCE_BEFORE_ARTIFACT=') < runner.index('-m maturin build')
    assert 'IROHA_PYTHON_SKIP_RUNTIME_LINK=1' in runner
    assert 'SOURCE_RECEIPT_SEAL=' in runner
    assert 'env -u IROHA_PYTHON_TEST_INSTALLED_PACKAGE' in runner
    assert 'PYTHONPYCACHEPREFIX="${SDK_SESSION}/source-bytecode"' in runner
    assert runner.count('verify_source_delivery') >= 4
    assert '--junitxml "${JUNIT_REPORT}"' in runner
    assert 'skipped = sum(int(suite.attrib.get("skipped", "0")) for suite in suites)' in runner
    assert "SoraFS native Python SDK parity may not contain skipped tests" in runner


@pytest.mark.parametrize("inherited_mode", [None, "0"])
@pytest.mark.parametrize("remove_binding", [False, True])
def test_python_native_lane_requires_installed_packages_in_pytest_child(
    tmp_path: Path, inherited_mode: str | None, remove_binding: bool
) -> None:
    """Execute the actual child command and detect removal of its wheel binding."""

    runner = read("ci/check_sorafs_python_native_sdk.sh")
    start = runner.index('JUNIT_REPORT="${SDK_SESSION}/pytest.xml"')
    end = runner.index('"${VENV_PYTHON}" -I - "${JUNIT_REPORT}"', start)
    command = runner[start:end]
    if remove_binding:
        command = command.replace("IROHA_PYTHON_TEST_INSTALLED_PACKAGE=1 \\\n", "", 1)
    # This child observes dispatch only; it never claims to execute SDK tests.
    child = tmp_path / "observe-pytest"
    child.write_text(
        '#!/bin/sh\n'
        '[ "${IROHA_PYTHON_TEST_INSTALLED_PACKAGE:-}" = 1 ] || exit 73\n'
        '[ "$1" = -m ] && [ "$2" = pytest ] || exit 74\n'
        'printf "%s\\n" "$@" > "${SDK_SESSION}/observed-arguments"\n',
        encoding="utf-8",
    )
    child.chmod(0o700)
    environment = dict(os.environ, SDK_SESSION=str(tmp_path), VENV_PYTHON=str(child))
    if inherited_mode is None:
        environment.pop("IROHA_PYTHON_TEST_INSTALLED_PACKAGE", None)
    else:
        environment["IROHA_PYTHON_TEST_INSTALLED_PACKAGE"] = inherited_mode
    result = subprocess.run(
        ["bash", "-eu", "-c", command], cwd=tmp_path, env=environment,
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == (73 if remove_binding else 0), result.stderr
    if not remove_binding:
        arguments = (tmp_path / "observed-arguments").read_text().splitlines()
        assert arguments[:5] == ["-m", "pytest", "-q", "-p", "no:cacheprovider"]
        assert arguments[5:7] == ["--junitxml", str(tmp_path / "pytest.xml")]
        assert arguments[7:] == [
            "tests/cancel_asset_lock_v1_test.py",
            "tests/cancel_asset_lock_client_helpers_test.py",
            "tests/client_hard_cut_contract_test.py",
            "tests/client_ledger_helpers_test.py",
            "tests/client_sorafs_orderbook_test.py",
            "tests/sorafs_reference_validation_test.py",
            "tests/sorafs_replication_instruction_test.py",
            "../iroha_torii_client/tests/orderbook_submission_test.py",
            "tests/account_identity_native_v1_test.py",
            "tests/requests_deadline_test.py",
            "tests/staking_preparation_test.py",
            "tests/validator_staking_test.py",
        ]


def test_python_cancel_builder_has_exact_archive_and_typed_two_argument_coverage() -> None:
    """The native Python lane must decode and pin the hard-cut cancellation archive."""

    tests = read("python/iroha_python/tests/cancel_asset_lock_client_helpers_test.py")
    crypto = read("python/iroha_python/src/iroha_python/crypto.py")
    assert "instruction_json_bytes = draft.instructions[0].to_json().encode(\"utf-8\")" in tests
    assert "instruction_archive = base64.b64decode(" in tests
    assert "json.loads(instruction_json_bytes)" in tests
    assert "validate=True" in tests
    assert "cancel_asset_lock_archive = instruction_archive[-85:]" in tests
    assert "decode_cancel_asset_lock_v1(cancel_asset_lock_archive)" in tests
    assert "assert instruction_json_bytes == (" in tests
    assert "assert instruction_archive == bytes.fromhex(" in tests
    assert "assert len(cancel_asset_lock_archive) == 85" in tests
    assert "decoded_cancel_asset_lock.escrow_id ==" in tests
    assert "decoded_cancel_asset_lock.expected_remaining_amount == \"10\"" in tests
    assert "in draft.instructions[0].to_json()" not in tests
    typed_builder = (
        "def cancel_asset_lock(\n"
        "            escrow_id: str,\n"
        "            expected_remaining_amount: str,\n"
        "        ) -> Instruction:"
    )
    assert typed_builder in crypto


@pytest.mark.parametrize("entrypoint,registration", [
    ("cancelAssetLockV1", "registerCancelAssetLockV1Tests"),
    ("sorafsAppealFinanceValidation", "registerSorafsAppealFinanceValidationTests"),
    ("sorafsFixtureBundleValidation", "registerSorafsFixtureBundleValidationTests"),
    ("sorafsOrderbookSubmission", "registerSorafsOrderbookSubmissionTests"),
    ("sorafsOrchestrator.parity", "registerSorafsOrchestratorParityTests"),
    ("sorafsPdpValidation", "registerSorafsPdpValidationTests"),
])
def test_javascript_sorafs_source_entrypoints_delegate_to_sole_assertion_owners(entrypoint, registration):
    """Moved assertions remain reached by the original required profile files."""
    base = "javascript/iroha_js/test/"
    entry = read(base + entrypoint + ".test.js")
    shared = read(base + "sorafsNativeSuites/" + entrypoint + ".js")
    assert f'from "./sorafsNativeSuites/{entrypoint}.js"' in entry
    assert entry.count(registration + "({") == 1
    assert f"export function {registration}(context)" in shared
    assert "../src/" not in shared
    assert "helpers/native.js" not in shared
    assert not re.search(r"\bskip\s*:|\.skip\s*(?:\(|=)", shared)
    assert f'"{entrypoint}.test.js"' in read("javascript/iroha_js/scripts/run-test-profile.mjs")


def test_javascript_eager_native_helper_binds_the_single_pure_failure_owner():
    """Source convenience loading cannot replace the required pure gate."""
    eager = read("javascript/iroha_js/test/helpers/native.js")
    pure = read("javascript/iroha_js/test/helpers/nativeRequirements.js")
    assert 'import { getNativeBinding } from "../../src/native.js"' in eager
    assert 'import { createNativeTestHelper } from "./nativeRequirements.js"' in eager
    assert eager.count("createNativeTestHelper(binding, bindingError)") == 1
    assert "export function createNativeTestHelper(binding, bindingError)" in pure
    assert "../src/" not in pure
    assert "getNativeBinding" not in pure
    assert not re.search(r"\bskip\s*:|\.skip\s*(?:\(|=)", pure)


@pytest.mark.parametrize("mutation", ("original", "remove", "comment", "before_install", "conditional", "skip_structure", "filter", "duplicate"))
def test_child_source_controls_follow_locked_npm_before_native_build(mutation):
    """AST controls need the actual locked TypeScript dependency installation."""
    from scripts import check_sorafs_release_automation as automation
    source = read("ci/sdk_sorafs_orchestrator.sh")
    command = automation.SORAFS_JAVASCRIPT_SOURCE_COMMAND + "\n"
    assert source.count(command) == 1
    changed = source
    if mutation == "remove": changed = source.replace(command, "")
    elif mutation == "comment": changed = source.replace(command, "    # " + command.lstrip())
    elif mutation == "before_install": changed = source.replace("    npm ci\n" + command, command + "    npm ci\n")
    elif mutation == "conditional": changed = source.replace(command, "    if false; then\n" + command + "    fi\n")
    elif mutation == "skip_structure": changed = source.replace(' "${sdk_root}/test/sorafsNativeSuiteStructure.test.js"', "")
    elif mutation == "filter": changed = source.replace(command, command.rstrip() + " --test-name-pattern absent\n")
    elif mutation == "duplicate": changed = source.replace(command, command * 2)
    errors = automation._javascript_child_source_controls_errors(changed)
    assert bool(errors) == (mutation != "original")


@pytest.mark.parametrize("mutation", ("original", "remove", "comment", "outside_batch", "duplicate"))
@pytest.mark.parametrize("test", (
    "scripts/tests/sorafs_javascript_child_abi_contract_test.py",
    "scripts/tests/sorafs_javascript_input_files_test.py",
    "scripts/tests/sorafs_javascript_parent_input_test.py",
    "scripts/tests/sorafs_javascript_runtime_inputs_test.py",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_accepts_thin_and_nonoverlapping_fat_images",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_rejects_nonzero_fat64_reserved_field",
))
def test_child_abi_controls_are_in_the_installed_pytest_batch(mutation, test):
    """The Python-only source guard uses the existing scripts requirement owner."""
    from scripts import check_sorafs_release_automation as automation
    source = read("ci/check_sorafs_cli_release.sh")
    line = "  " + test + " \\\n"
    assert source.count(line) == 1
    changed = source
    if mutation == "remove": changed = source.replace(line, "")
    elif mutation == "comment": changed = source.replace(line, "") + "\n# " + line.lstrip()
    elif mutation == "outside_batch": changed = source.replace(line, "") + "\n" + line
    elif mutation == "duplicate": changed = source.replace(line, line * 2)
    assert bool(automation._javascript_child_python_controls_errors(changed)) == (mutation != "original")


@pytest.mark.parametrize("selector", (
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_accepts_thin_and_nonoverlapping_fat_images",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_rejects_nonzero_fat64_reserved_field",
))
def test_runtime_parser_registration_cannot_expand_to_framework_execution(selector):
    """The exact pure selectors cannot become the unrelated native module run."""
    from scripts import check_sorafs_release_automation as automation
    source = read("ci/check_sorafs_cli_release.sh")
    assert source.count(selector) == 1
    changed = source.replace(selector, selector.split("::", 1)[0])
    assert automation._javascript_child_python_controls_errors(changed)


@pytest.fixture(scope="module")
def mobile_host_jvm_prerequisite_checker():
    import importlib.util
    path = REPO_ROOT / "scripts/check_sorafs_release_automation.py"
    spec = importlib.util.spec_from_file_location("mobile_host_jvm_prerequisite_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mobile_full_jvm_suite_builds_and_binds_its_fixture_generator(mobile_host_jvm_prerequisite_checker) -> None:
    source = read(".github/workflows/mobile_sdk_artifacts.yml")
    assert mobile_host_jvm_prerequisite_checker._mobile_host_jvm_prerequisite_errors(source) == []
    assert '- "tools/kotlin-fixture-gen/**"' in source
    # Preserve every original complete-suite consumer and publication command.
    for task in (
        ":core-jvm:test", ":tools:test", ":client-android:testDebugUnitTest",
        ":client-android:testDebugHostNative", ":client-android:lintRelease",
        ":kagemusha-wallet-android:testDebugUnitTest", ":kagemusha-wallet-android:lintRelease",
        ":core-jvm:cyclonedxDirectBom", ":client-android:cyclonedxDirectBom",
        ":kagemusha-wallet-android:cyclonedxDirectBom",
        ":core-jvm:publishReleasePublicationToMavenLocal",
        ":client-android:publishReleasePublicationToMavenLocal",
        ":kagemusha-wallet-android:publishReleasePublicationToMavenLocal",
        ":core-jvm:publishReleasePublicationToMobileSdkRepository",
        ":client-android:publishReleasePublicationToMobileSdkRepository",
        ":kagemusha-wallet-android:publishReleasePublicationToMobileSdkRepository",
    ):
        assert task in source


@pytest.mark.parametrize("before,after", (
    ('--features privacy-production-enabled', '--features dev-tools'),
    ('cargo build --locked -p kotlin-fixture-gen', '# cargo build --locked -p kotlin-fixture-gen'),
    ('--features dev-tools --bin kotlin-fixture-gen', '--bin kotlin-fixture-gen'),
    ('--features dev-tools --bin kotlin-fixture-gen', '--features dev-tools --bin wrong-generator'),
    ('fixture_generator="$CARGO_TARGET_DIR/debug/kotlin-fixture-gen"', 'fixture_generator="$GITHUB_WORKSPACE/target/debug/kotlin-fixture-gen"'),
    ('&& ! -L "$fixture_generator" && -x "$fixture_generator"', '&& -x "$fixture_generator"'),
    ('&& ! -L "$fixture_generator" && -x "$fixture_generator"', '&& ! -L "$fixture_generator"'),
    ('echo "IROHA_KOTLIN_FIXTURE_GEN_BIN=$fixture_generator"', 'echo "IROHA_KOTLIN_FIXTURE_GEN_BIN=stale-generator"'),
    ('set -euo pipefail', 'set -uo pipefail'),
    ('--no-build-cache --rerun-tasks', ''),
))
def test_mobile_full_jvm_suite_refuses_missing_wrong_or_unexecuted_generator_prerequisites(mobile_host_jvm_prerequisite_checker, before, after) -> None:
    source = read(".github/workflows/mobile_sdk_artifacts.yml")
    # Only the actual host prerequisite step is changed; other jobs keep their
    # genuine source, ABI, artifact and SDK assertions.
    start = source.index('      - name: Build host SoraFS reference native bridge\n')
    prefix, body = source[:start], source[start:]
    assert before in body
    changed = prefix + body.replace(before, after, 1)
    assert mobile_host_jvm_prerequisite_checker._mobile_host_jvm_prerequisite_errors(changed)


def test_mobile_full_jvm_suite_rejects_late_generator_build(mobile_host_jvm_prerequisite_checker) -> None:
    source = read(".github/workflows/mobile_sdk_artifacts.yml")
    start = source.index('      - name: Build host SoraFS reference native bridge\n')
    end = source.index('      - name: Build Android native bridge libraries\n', start)
    block = source[start:end]
    changed = source[:start] + source[end:]
    position = changed.index('      - name: Collect canonical Kotlin runtime SBOMs\n')
    changed = changed[:position] + block + changed[position:]
    assert mobile_host_jvm_prerequisite_checker._mobile_host_jvm_prerequisite_errors(changed)
