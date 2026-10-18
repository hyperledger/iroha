"""Adversarial tests for the SoraFS release-automation contract guard."""

from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path

import pytest

from scripts import check_sorafs_release_automation as automation
from scripts.tests import check_runtime_provider_broker_install_test as broker_contract_tests


REPO_ROOT = Path(__file__).resolve().parents[2]
# Use the child's actual unittest discovery so additions remain mandatory in
# both modes and each deliberate failure/lock mutation adds exactly one case.
BROKER_CASE_COUNT = unittest.defaultTestLoader.loadTestsFromModule(
    broker_contract_tests
).countTestCases()
assert BROKER_CASE_COUNT > 0


def _copy_workflows(target: Path) -> None:
    (target / "docs").mkdir(parents=True, exist_ok=True)
    for relative in (
        *automation.WORKFLOWS,
        *automation.RELEASE_DOCUMENTS,
        *automation.RELEASE_AUTH_HISTORICAL_FINDINGS,
        *automation.REFERENCE_SDK_RELEASE_EXAMPLE_REQUIRED_MARKERS,
        *automation.NATIVE_GOVERNANCE_SDK_CONTRACTS,
        *automation.RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS,
        *automation.RELEASE_VERSION_MAP_CONTRACT_MARKERS,
        automation.SORAFS_CLI_RELEASE_GATE_SCRIPT,
        automation.SORAFS_JAVASCRIPT_PARITY_RUNNER,
        automation.SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT,
        automation.SORAFS_COSIGN_QUALIFICATION_HELPER,
        automation.SORAFS_COSIGN_VERIFIER_POLICY,
        automation.PACKAGE_RELEASE_SMOKE_SCRIPT,
    ):
        source = REPO_ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    for relative in automation.RELEASE_AUTH_ROOT_DOCUMENTS:
        destination = target / relative
        destination.write_text("# Release-auth test fixture\n", encoding="utf-8")


@pytest.mark.parametrize("relative", automation.SORAFS_JAVASCRIPT_CHILD_WORKFLOWS)
def test_javascript_test_event_workflow_contract_accepts_fixed_execution(relative):
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    assert not automation._javascript_child_controls_workflow_errors(relative, source)


@pytest.mark.parametrize("relative", automation.SORAFS_JAVASCRIPT_CHILD_WORKFLOWS)
@pytest.mark.parametrize("trigger", sorted(automation.SORAFS_JAVASCRIPT_CHILD_PATHS))
@pytest.mark.parametrize("mutation", ("remove", "comment_decoy", "duplicate"))
def test_javascript_test_event_workflow_requires_actual_triggers(relative, trigger, mutation):
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    original = f'      - "{trigger}"\n'
    assert source.count(original) == 1
    changed = source.replace(original, original * 2 if mutation == "duplicate" else "", 1)
    if mutation == "comment_decoy":
        changed += f'\n# - "{trigger}"\n'
    errors = automation._validate_workflow_source(relative, changed)
    assert any("JavaScript child-custody pull_request paths" in error for error in errors)


@pytest.mark.parametrize("mutation", (
    "remove", "comment_decoy", "duplicate", "conditional", "conditional_job", "filter",
    "ignore_failure", "wrong_directory", "echo", "comment_block", "late", "wrong_node", "extra_command",
    "omit_events", "omit_files", "omit_input", "omit_loads", "omit_session",
))
def test_javascript_test_event_workflow_requires_unconditional_node24_step(mutation):
    relative = ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    step = automation.SORAFS_JAVASCRIPT_CHILD_STEP + "\n"
    command = automation.SORAFS_JAVASCRIPT_CHILD_COMMAND
    assert source.count(step) == 1
    replacement = {
        "remove": "", "comment_decoy": "", "duplicate": step * 2,
        "omit_events": step.replace(" scripts/tests/sorafs_javascript_test_events_test.mjs", ""),
        "omit_files": step.replace(" scripts/tests/sorafs_javascript_child_files_test.mjs", ""),
        "omit_input": step.replace(" scripts/tests/sorafs_javascript_child_input_test.mjs", ""),
        "omit_loads": step.replace(" scripts/tests/sorafs_javascript_child_loads_test.mjs", ""),
        "omit_session": step.replace(" scripts/tests/sorafs_javascript_child_session_test.mjs", ""),
        "conditional": step.replace("        run:", "        if: false\n        run:"),
        "conditional_job": step, "wrong_node": step,
        "filter": step.replace(command, command + " --test-name-pattern nonexistent"),
        "ignore_failure": step.replace(command, command + " || true"),
        "wrong_directory": step.replace("        run:", "        working-directory: elsewhere\n        run:"),
        "echo": step.replace("run: node", "run: echo node"),
        "comment_block": step.replace("run: " + command, "run: |\n          # " + command + "\n          true"),
        "late": "      - name: Interposed step\n        run: true\n" + step,
        "extra_command": step + step.replace("Verify fixed JavaScript child-custody ownership", "Repeat event command"),
    }[mutation]
    changed = source.replace(step, replacement, 1)
    if mutation == "comment_decoy":
        changed += "\n# " + command + "\n"
    if mutation == "conditional_job":
        changed = changed.replace("  sdk-parity:\n", "  sdk-parity:\n    if: false\n", 1)
    if mutation == "wrong_node":
        changed = changed.replace('node-version: "24"', 'node-version: "20"', 1)
    errors = automation._validate_workflow_source(relative, changed)
    assert any("JavaScript child-custody controls must run unconditionally" in error for error in errors)


@pytest.mark.parametrize("trigger", sorted(automation.SORAFS_JAVASCRIPT_CONTENT_PATHS))
@pytest.mark.parametrize("mutation", ("remove", "comment_decoy", "duplicate"))
def test_installed_javascript_tools_require_actual_release_triggers(trigger, mutation):
    """The installed-content owner and its controls must reach the release gate."""
    relative = ".github/workflows/sorafs-cli-release.yml"
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    marker = f'      - "{trigger}"\n'
    assert source.count(marker) == 1
    changed = source.replace(marker, marker * 2 if mutation == "duplicate" else "", 1)
    if mutation == "comment_decoy":
        changed += f'\n# - "{trigger}"\n'
    assert any("JavaScript content source/test triggers" in error
               for error in automation._validate_workflow_source(relative, changed))


def test_validate_release_automation_accepts_repository_contract() -> None:
    summary = automation.validate_release_automation(REPO_ROOT)
    assert summary == {
        "schema": automation.SCHEMA,
        "workflow_count": 3,
        "workflows": sorted(automation.WORKFLOWS),
    }


@pytest.mark.parametrize("backend", ("software", "hsm"))
@pytest.mark.parametrize("quote", ("'", '"'))
def test_topology_trust_cannot_claim_signer_backend(
    tmp_path: Path, backend: str, quote: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    marker = '              "schema": "sorafs.l1.deployment_qualification.trust.v1",\n'
    assert source.count(marker) == 1
    workflow.write_text(
        source.replace(marker, marker + f'              {quote}signer_backend{quote}: "{backend}",\n'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="topology trust must not claim a signing backend"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("mutation", ("remove", "duplicate", "conditional", "ignore_failure"))
def test_release_gate_requires_mandatory_cosign_qualification(tmp_path, mutation):
    _copy_workflows(tmp_path)
    gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = gate.read_text()
    command = f"python3 {automation.SORAFS_COSIGN_QUALIFICATION_HELPER}\n"
    replacement = {
        "remove": "", "duplicate": command * 2,
        "conditional": "if false; then\n" + command + "fi\n",
        "ignore_failure": command.rstrip() + " || true\n",
    }[mutation]
    gate.write_text(source.replace(command, replacement, 1))
    with pytest.raises(ValueError, match="mandatory cosign qualification"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("mutation", ("remove", "comment", "duplicate", "conditional", "ignore_failure"))
def test_release_gate_requires_mandatory_native_authority_runtime(tmp_path, mutation):
    _copy_workflows(tmp_path)
    gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    command = f"bash {automation.SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT}\n"
    source = gate.read_text()
    assert source.count(command) == 1
    replacement = {
        "remove": "", "comment": "# " + command, "duplicate": command * 2,
        "conditional": "if false; then\n" + command + "fi\n",
        "ignore_failure": command.rstrip() + " || true\n",
    }[mutation]
    gate.write_text(source.replace(command, replacement, 1))
    with pytest.raises(ValueError, match="mandatory native authority runtime"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("mutation", (
    "remove", "comment", "duplicate", "conditional", "ignore_failure", "filter",
    *("omit_" + package for package in automation.SORAFS_SIGNER_CONTRACT_LIBRARIES),
))
def test_release_gate_requires_full_signer_contract_libraries(tmp_path, mutation):
    _copy_workflows(tmp_path)
    gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    command = automation.SORAFS_SIGNER_CONTRACT_COMMAND + "\n"
    source = gate.read_text()
    assert source.count(command) == 1
    if mutation.startswith("omit_"):
        replacement = command.replace("-p " + mutation.removeprefix("omit_") + " ", "", 1)
    else:
        replacement = {
            "remove": "", "comment": "# " + command, "duplicate": command * 2,
            "conditional": "if false; then\n" + command + "fi\n",
            "ignore_failure": command.rstrip() + " || true\n",
            "filter": command.rstrip() + " -- one_nonexistent_case\n",
        }[mutation]
    gate.write_text(source.replace(command, replacement, 1))
    with pytest.raises(ValueError, match="mandatory signer contract libraries"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("sentinel", automation.SORAFS_NATIVE_AUTHORITY_SENTINELS)
@pytest.mark.parametrize("mutation", ("remove", "comment", "duplicate"))
def test_native_authority_runtime_requires_each_critical_test_exactly_once(tmp_path, sentinel, mutation):
    _copy_workflows(tmp_path)
    helper = tmp_path / automation.SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT
    source = helper.read_text()
    line = f'  "{sentinel}"\n'
    assert source.count(line) == 1
    replacement = {"remove": "", "comment": "# " + line, "duplicate": line * 2}[mutation]
    helper.write_text(source.replace(line, replacement, 1))
    with pytest.raises(ValueError, match="mandatory native authority runtime"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("marker", (
    *(f"  -p {package}\n" for package in automation.SORAFS_NATIVE_AUTHORITY_PACKAGES),
    *(f'  "{value}"\n' for value in automation.SORAFS_NATIVE_AUTHORITY_FILTERS),
    'set -euo pipefail', '--locked', '--lib', '--list',
    'for native_test in "${native_test_sentinels[@]}"; do',
    'grep -Fxc -- "${native_test}: test"', '!= 1', 'exit 1',
    '--include-ignored', '--nocapture',
))
def test_native_authority_runtime_rejects_deleted_or_weakened_commands(tmp_path, marker):
    _copy_workflows(tmp_path)
    helper = tmp_path / automation.SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT
    source = helper.read_text()
    assert marker in source
    helper.write_text(source.replace(marker, "removed", 1))
    with pytest.raises(ValueError, match="mandatory native authority runtime"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("addition", ("exit 0\n", "set +e\n", "if false; then\n"))
def test_native_authority_runtime_rejects_early_exit_or_conditional_execution(tmp_path, addition):
    _copy_workflows(tmp_path)
    helper = tmp_path / automation.SORAFS_NATIVE_AUTHORITY_RUNTIME_SCRIPT
    helper.write_text(addition + helper.read_text())
    with pytest.raises(ValueError, match="mandatory native authority runtime"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("marker", (
    "results.passed != REQUIRED_CASES", "results.skipped",
    "set(results.collected) != REQUIRED_CASES",
    "len(results.collected) != len(REQUIRED_CASES)",
    "--sorafs-cosign-verifier-sha256", "load_evidence_json(path, 16 * 1024)",
))
def test_release_gate_rejects_weakened_cosign_helper(tmp_path, marker):
    _copy_workflows(tmp_path)
    helper = tmp_path / automation.SORAFS_COSIGN_QUALIFICATION_HELPER
    helper.write_text(helper.read_text().replace(marker, "removed", 1))
    with pytest.raises(ValueError, match="mandatory cosign qualification"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("replacement", ("", '          cosign-release: "latest"\n'))
def test_cosign_installer_release_version_must_remain_pinned(tmp_path, replacement):
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text()
    workflow.write_text(source.replace('          cosign-release: "v3.1.3"\n', replacement, 1))
    with pytest.raises(ValueError, match="both cosign installer steps"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "marker",
    (
        'test ! -e "$native_root"',
        "cargo build --locked --offline --release -p connect_norito_bridge",
        "cargo build --locked --offline --release -p kotlin-fixture-gen",
        "--features dev-tools --bin kotlin-fixture-gen",
        '--target "$target" --target-dir "$native_root/cargo-target"',
        '--sdk c-jni --target "$target"',
        'echo "IROHA_NATIVE_LIBRARY_PATH=$native_dir" >> "$GITHUB_ENV"',
        'echo "IROHA_KOTLIN_FIXTURE_GEN_BIN=$native_dir/kotlin-fixture-gen" >> "$GITHUB_ENV"',
        "./gradlew --no-daemon --no-build-cache --rerun-tasks",
        ":core-jvm:test :tools:test",
        ":client-android:testDebugUnitTest",
        ":client-android:testDebugHostNative",
        ":kagemusha-wallet-android:testDebugUnitTest --console=plain",
        "python3 -I scripts/check_sorafs_mobile_parity_reports.py",
        '--report-root "$MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk"',
        '> "$MOBILE_SDK_ANDROID_ARTIFACT_DIR/test-execution.json"',
        "sorafs-mobile-parity/test-execution.json",
        '--manifest "$SORAFS_MOBILE_NATIVE_MANIFEST"',
        "sorafs-mobile-parity/gradle-build/iroha_kotlin_sdk/*/test-results/**/TEST-*.xml",
    ),
)
def test_mobile_native_qualification_rejects_removed_security_controls(
    tmp_path: Path, marker: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = workflow.read_text(encoding="utf-8")
    expected_count = 2 if marker.startswith('--target "$target"') else 1
    assert source.count(marker) == expected_count
    workflow.write_text(source.replace(marker, "removed", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="mobile-parity.*missing contract marker|must both use the isolated build target",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("mutation", ("conditional", "reordered", "duplicate"))
def test_mobile_native_qualification_cannot_skip_or_reorder_execution(
    tmp_path: Path, mutation: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = workflow.read_text(encoding="utf-8")
    before = (
        "      - name: Require fresh ABI-30 JNI bridge "
        "in complete Kotlin and Java suites\n"
    )
    after = "      - name: Reauthenticate the consumed Kotlin bridge\n"
    if mutation == "conditional":
        source = source.replace(before, before + "        if: false\n", 1)
        message = "qualification must not be conditional"
    elif mutation == "reordered":
        start = source.index(before)
        middle = source.index(after, start)
        end = source.index(
            "      - name: Upload Kotlin and Java native parity evidence\n", middle
        )
        source = (
            source[:start] + source[middle:end] + source[start:middle] + source[end:]
        )
        message = "stages must execute exactly once"
    else:
        source = source.replace(before, before + before, 1)
        message = "stages must execute exactly once"
    workflow.write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    (
        ".github/workflows/sorafs-cli-release.yml",
        ".github/workflows/sorafs-orchestrator-sdk.yml",
    ),
)
@pytest.mark.parametrize(
    "dependency",
    (
        "scripts/check_sorafs_mobile_parity_reports.py",
        "scripts/tests/check_sorafs_mobile_parity_reports_test.py",
    ),
)
def test_mobile_report_security_changes_must_trigger_both_release_workflows(
    tmp_path: Path, relative: str, dependency: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / relative
    source = workflow.read_text(encoding="utf-8")
    marker = f'      - "{dependency}"\n'
    assert source.count(marker) == 1
    workflow.write_text(source.replace(marker, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "dependency",
    (
        "scripts/sorafs_evidence_json.py",
        "scripts/sorafs_evidence_paths.py",
        "scripts/sorafs_evidence_sensitivity.py",
        "scripts/sorafs_path_identity.py",
        "tools/kotlin-fixture-gen/**",
    ),
)
def test_mobile_native_transitive_dependencies_must_trigger_parity(
    tmp_path: Path, dependency: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = workflow.read_text(encoding="utf-8")
    marker = f'      - "{dependency}"\n'
    assert source.count(marker) == 1
    workflow.write_text(source.replace(marker, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_TOPOLOGY_TRIGGER_PATHS),
)
def test_topology_envelope_dependency_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits topology-envelope dependency trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TRIGGER_PATHS),
)
@pytest.mark.parametrize("mutation", ("remove", "duplicate"))
def test_production_promotion_import_triggers_are_exactly_once(
    tmp_path: Path, relative: str, mutation: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    replacement = "" if mutation == "remove" else trigger * 2
    workflow.write_text(source.replace(trigger, replacement, 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"must list each production-promotion import trigger exactly once",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TRIGGER_PATHS),
)
def test_build_efficiency_provenance_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits build-efficiency provenance contract trigger",
    ):
        automation.validate_release_automation(tmp_path)






@pytest.mark.parametrize("relative", automation.SORAFS_CLI_L1_QUALIFICATION_TESTS)
def test_l1_qualification_regression_suites_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    release_gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = release_gate.read_text(encoding="utf-8")
    assert source.count(relative) == 1
    release_gate.write_text(
        source.replace(relative, "removed-l1-suite", 1), encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match=r"must execute L1 qualification regression suite",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative", automation.SORAFS_CLI_PRODUCTION_PROMOTION_IMPORT_TESTS
)
@pytest.mark.parametrize("mutation", ("remove", "duplicate"))
def test_production_promotion_import_regression_suites_are_exactly_once(
    tmp_path: Path, relative: str, mutation: str
) -> None:
    _copy_workflows(tmp_path)
    release_gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = release_gate.read_text(encoding="utf-8")
    assert source.count(relative) == 1
    replacement = (
        "removed-production-promotion-suite"
        if mutation == "remove"
        else f"{relative} {relative}"
    )
    release_gate.write_text(
        source.replace(relative, replacement, 1), encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match=r"must execute production-promotion import regression suite",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "true",
            "build-efficiency provenance command must appear exactly once",
        ),
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            f"{automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND} || true",
            "build-efficiency provenance command must appear exactly once",
        ),
        (
            "set -euo pipefail",
            "set -uo pipefail",
            "strict shell mode must precede",
        ),
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "set +e\n" + automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "build-efficiency provenance command must not run with errexit disabled",
        ),
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "set +o errexit\n" + automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "build-efficiency provenance command must not run with errexit disabled",
        ),
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND,
            "cargo fmt --all -- --check\n"
            f"{automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND}",
            "build-efficiency provenance command must run before every Cargo command",
        ),
        (
            automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_TEST,
            "scripts/tests/removed_provenance_suite.py",
            "must execute the build-efficiency provenance regression suite",
        ),
    ),
)
def test_build_efficiency_provenance_release_gate_fails_closed_first(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    _copy_workflows(tmp_path)
    release_gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = release_gate.read_text(encoding="utf-8")
    drifted = source.replace(old, new, 1)
    assert drifted != source
    release_gate.write_text(drifted, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


def test_release_gate_job_must_invoke_strict_cli_gate() -> None:
    relative = ".github/workflows/sorafs-cli-release.yml"
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    marker = f"run: bash {automation.SORAFS_CLI_RELEASE_GATE_SCRIPT}"
    assert source.count(marker) == 1
    drifted = source.replace(f"        {marker}", "        run: true", 1)
    drifted += f"\n# {marker}\n"

    errors = automation._validate_workflow_source(relative, drifted)
    assert any("release-gate job must run" in error for error in errors)


def test_release_gate_checkout_requires_complete_history_exclusively() -> None:
    relative = ".github/workflows/sorafs-cli-release.yml"
    source = (REPO_ROOT / relative).read_text(encoding="utf-8")
    full_history = "        with:\n          fetch-depth: 0\n"
    assert source.count(full_history) == 1

    errors = automation._validate_workflow_source(
        relative, source.replace(full_history, "", 1)
    )
    assert any("release-gate checkout must fetch" in error for error in errors)

    second_checkout = source.find("      - uses: actions/checkout@", source.find(full_history))
    assert second_checkout >= 0
    checkout_line_end = source.index("\n", second_checkout) + 1
    drifted = (
        source[:checkout_line_end]
        + full_history
        + source[checkout_line_end:]
    )
    errors = automation._validate_workflow_source(relative, drifted)
    assert any("release-gate checkout must fetch" in error for error in errors)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_RESERVE_TRIGGER_PATHS),
)
def test_reserve_client_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits reserve-client contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_REPAIR_TRIGGER_PATHS),
)
def test_repair_client_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits repair-client contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_RUST_OWNER_TRIGGER_PATHS),
)
def test_rust_module_owner_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits Rust module-owner contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("mutation", ("remove", "duplicate"))
def test_rust_module_owner_regression_suite_executes_exactly_once(
    tmp_path: Path, mutation: str
) -> None:
    _copy_workflows(tmp_path)
    release_gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = release_gate.read_text(encoding="utf-8")
    suite = automation.SORAFS_CLI_RUST_OWNER_CONTRACT_TEST
    assert source.count(suite) == 1
    replacement = "" if mutation == "remove" else suite + " " + suite
    release_gate.write_text(source.replace(suite, replacement, 1), encoding="utf-8")

    with pytest.raises(
        ValueError, match="Rust module-owner regression suite exactly once"
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_PROVIDER_INGEST_TRIGGER_PATHS),
)
def test_provider_ingest_crash_restart_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits provider-ingest crash/restart contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_LOCK_TRIGGER_PATHS),
)
def test_workspace_lock_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits workspace lock contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_VERSION_MAP_TRIGGER_PATHS),
)
def test_swift_version_map_dependency_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits Swift version-map dependency trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.SORAFS_CLI_RELEASE_VERSION_TRIGGER_PATHS),
)
def test_cli_release_version_contract_triggers_are_mandatory(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    trigger = f'      - "{relative}"\n'
    assert source.count(trigger) == 1
    workflow.write_text(source.replace(trigger, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"pull_request\.paths omits CLI release-version contract trigger",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (relative, marker)
        for relative, markers in sorted(
            automation.RELEASE_VERSION_MAP_CONTRACT_MARKERS.items()
        )
        for marker in markers
    ],
)
def test_cli_release_version_contract_markers_are_mandatory(
    tmp_path: Path, relative: str, marker: str
) -> None:
    _copy_workflows(tmp_path)
    source_path = tmp_path / relative
    source = source_path.read_text(encoding="utf-8")
    assert marker in source
    source_path.write_text(source.replace(marker, "removed", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="missing CLI release-version contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "marker",
    automation.RUNTIME_PROVIDER_RELEASE_WORKFLOW_MARKERS,
)
def test_runtime_provider_release_workflow_markers_are_mandatory(
    tmp_path: Path, marker: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    drifted = source.replace(marker, "REMOVED_RUNTIME_PROVIDER_CONTRACT", 1)
    assert drifted != source
    workflow.write_text(drifted, encoding="utf-8")

    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "relative",
    sorted(automation.RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS),
)
def test_runtime_provider_deployment_asset_removal_fails_closed(
    tmp_path: Path, relative: str
) -> None:
    _copy_workflows(tmp_path)
    (tmp_path / relative).unlink()

    with pytest.raises(ValueError, match="source is missing"):
        automation.validate_release_automation(tmp_path)


def test_runtime_provider_deployment_markers_track_split_broker_modules() -> None:
    markers = automation.RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS

    assert markers["crates/irohad/src/runtime_provider_broker.rs"] == (
        "mod api;",
        "mod launcher;",
        'include!("runtime_provider_broker/protocol.rs");',
    )
    assert markers["crates/iroha_config/src/parameters/defaults.rs"] == (
        "/run/iroha-runtime-provider-broker-v1/runtime-provider-broker-v1.sock",
        "/private/var/iroha/run/runtime-provider-broker-v1.sock",
    )
    assert markers["crates/irohad/src/runtime_provider_broker/platform.rs"] == (
        'include!("platform_server_qualification.rs");',
        'include!("pop_recipient_client.rs");',
    )
    assert markers["crates/irohad/src/runtime_provider_broker/platform_server_qualification.rs"] == (
        "EndpointPolicy",
        "if policy.verify_all_ancestors {",
        "verify_directory(ancestor, policy.expected_service_uid, true)?;",
    )
    assert markers[
        "crates/irohad/src/runtime_provider_broker/platform_server_transport.rs"
    ] == ("endpoint_recovery::prepare_endpoint",)
    assert markers[
        "crates/irohad/src/runtime_provider_broker/platform_operation_dispatch.rs"
    ] == (
        "OPERATION_POP_RUNTIME_OPEN_V1",
        "OPERATION_POP_ENROLLMENT_RECIPIENT_OPEN_V1",
        "OPERATION_POP_WALLET_RECIPIENT_OPEN_V1",
    )


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (relative, marker)
        for relative, markers in sorted(
            automation.RUNTIME_PROVIDER_DEPLOYMENT_ASSET_MARKERS.items()
        )
        for marker in markers
    ],
)
def test_runtime_provider_deployment_asset_markers_are_mandatory(
    tmp_path: Path, relative: str, marker: str
) -> None:
    _copy_workflows(tmp_path)
    asset = tmp_path / relative
    source = asset.read_text(encoding="utf-8")
    # Some security invariants are intentionally enforced at more than one
    # boundary. Remove every occurrence so this mutation proves the release
    # gate requires the invariant itself, not merely one duplicated spelling.
    drifted = source.replace(marker, "REMOVED_RUNTIME_PROVIDER_ASSET_MARKER")
    assert drifted != source
    asset.write_text(drifted, encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="missing runtime-provider deployment contract marker",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (relative, marker)
        for relative, markers in sorted(
            automation.RUNTIME_PROVIDER_DEPLOYMENT_FORBIDDEN_MARKERS.items()
        )
        for marker in markers
    ],
)
def test_runtime_provider_deployment_assets_reject_credential_or_override_inputs(
    tmp_path: Path, relative: str, marker: str
) -> None:
    _copy_workflows(tmp_path)
    asset = tmp_path / relative
    with asset.open("a", encoding="utf-8") as destination:
        destination.write(f"\n{marker}\n")

    with pytest.raises(
        ValueError,
        match="forbidden runtime-provider deployment marker",
    ):
        automation.validate_release_automation(tmp_path)


def test_pop_broker_hard_cut_contract_accepts_repository() -> None:
    assert automation._validate_pop_broker_hard_cut_contract(REPO_ROOT) == []


def test_retired_pop_runtime_resolve_operation_cannot_return(tmp_path: Path) -> None:
    _copy_workflows(tmp_path)
    protocol = (
        tmp_path
        / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    )
    with protocol.open("a", encoding="utf-8") as destination:
        destination.write(
            "\npub(super) const OPERATION_POP_RUNTIME_RESOLVE_V1: u16 = 123;\n"
        )

    with pytest.raises(ValueError, match="forbidden runtime-provider deployment marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "struct_name",
    sorted(automation.POP_BROKER_WIRE_FIELD_INVENTORIES),
)
def test_pop_broker_wire_structs_reject_private_recipient_fields(
    tmp_path: Path, struct_name: str
) -> None:
    _copy_workflows(tmp_path)
    protocol = (
        tmp_path
        / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    )
    source = protocol.read_text(encoding="utf-8")
    declaration = re.search(
        rf'pub\(super\)\s+{re.escape(struct_name)}\s*\{{', source
    )
    assert declaration is not None
    drifted = (
        source[: declaration.end()]
        + "\n    pub(super) recipient_private_key: Vec<u8>,"
        + source[declaration.end() :]
    )
    protocol.write_text(drifted, encoding="utf-8")

    with pytest.raises(ValueError, match=rf"wire struct {struct_name} fields must be exactly"):
        automation.validate_release_automation(tmp_path)


def test_pop_broker_wire_structs_reject_field_type_substitution(tmp_path: Path) -> None:
    _copy_workflows(tmp_path)
    protocol = (
        tmp_path
        / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    )
    source = protocol.read_text(encoding="utf-8")
    drifted = source.replace(
        "issuer_public_key: [u8; 32],",
        "issuer_public_key: Vec<u8>,",
        1,
    )
    assert drifted != source
    protocol.write_text(drifted, encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="wire struct PopRuntimeOpenResultWireV1 fields must be exactly",
    ):
        automation.validate_release_automation(tmp_path)


def _pop_wire_declaration(source: str, struct_name: str) -> str:
    """Locate the actual owner only to mutate the closed declaration contract."""

    declarations = re.findall(
        rf'(?m)^define_broker_wire_struct!\([^\n]*\b{re.escape(struct_name)}\s*\{{[^\n]*\}}\);$',
        source,
    )
    assert len(declarations) == 1
    return declarations[0]


@pytest.mark.parametrize("struct_name", sorted(automation.POP_BROKER_WIRE_FIELD_INVENTORIES))
@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_owner", "different_name", "duplicate_owner",
        "missing_frame", "unknown_mode", "wrong_mode",
        "public_owner", "public_field", "duplicate", "duplicate_old_header",
        "duplicate_struct", "missing_semicolon", "missing_delimiter",
        "mismatched_delimiter", "missing_comma", "empty_type",
        "extra_field", "duplicate_field", "unsupported_struct", "nested_owner",
        "comment_decoy", "string_decoy", "raw_string_decoy", "unterminated_comment",
    ),
)
def test_pop_broker_canonical_declaration_rejects_source_mutation(
    tmp_path: Path, struct_name: str, mutation: str
) -> None:
    _copy_workflows(tmp_path)
    path = tmp_path / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    source = path.read_text(encoding="utf-8")
    declaration = _pop_wire_declaration(source, struct_name)
    owner = f'"irohad::runtime_provider_broker::protocol::primitives::{struct_name}"'
    old_header = declaration.replace(f"frame {owner}; ", "", 1)
    body = declaration.split(f"pub(super) {struct_name}", 1)[1]
    direct = f"pub(super) struct {struct_name}{body}"
    direct = direct.removesuffix(");")
    first_field = re.search(r'\{\s*(pub\(super\)\s+\w+\s*:[^,]+,)', declaration)
    assert first_field is not None
    if mutation == "wrong_owner":
        replacement = declaration.replace(owner, '"incorrect::WireV1"', 1)
    elif mutation in ("different_name", "duplicate_owner"):
        renamed = declaration.replace(
            f"pub(super) {struct_name}", "pub(super) SubstitutedWireV1", 1
        )
        replacement = renamed if mutation == "different_name" else declaration + "\n" + renamed
    elif mutation == "missing_frame":
        replacement = old_header
    elif mutation == "unknown_mode":
        replacement = declaration.replace("!(", "!(unknown ", 1)
    elif mutation == "wrong_mode":
        replacement = re.sub(r'!\(\w+', '!(copy', declaration, count=1)
    elif mutation == "public_owner":
        replacement = declaration.replace(f"pub(super) {struct_name}", f"pub {struct_name}", 1)
    elif mutation == "public_field":
        replacement = declaration.replace(
            first_field.group(1), first_field.group(1).replace("pub(super)", "pub", 1), 1
        )
    elif mutation == "duplicate":
        replacement = declaration + "\n" + declaration
    elif mutation == "duplicate_old_header":
        replacement = declaration + "\n" + old_header
    elif mutation == "duplicate_struct":
        replacement = declaration + "\n" + direct
    elif mutation == "missing_semicolon":
        replacement = declaration[:-1]
    elif mutation == "missing_delimiter":
        replacement = declaration.removesuffix(");")
    elif mutation == "mismatched_delimiter":
        replacement = declaration.replace("}", "]", 1)
    elif mutation == "missing_comma":
        replacement = declaration.replace(first_field.group(1), first_field.group(1)[:-1], 1)
    elif mutation == "empty_type":
        replacement = declaration.replace(
            first_field.group(1), first_field.group(1).split(":", 1)[0] + ": ,", 1
        )
    elif mutation == "extra_field":
        replacement = declaration.replace("{", "{ pub(super) recipient_private_key: Vec<u8>,", 1)
    elif mutation == "duplicate_field":
        replacement = declaration.replace(first_field.group(1), first_field.group(1) * 2, 1)
    elif mutation == "unsupported_struct":
        replacement = direct
    elif mutation == "nested_owner":
        replacement = "mod substituted_owner {\n" + declaration + "\n}"
    elif mutation == "comment_decoy":
        replacement = "/* " + declaration + " */"
    elif mutation == "string_decoy":
        replacement = "const DECOY: &str = " + json.dumps(declaration) + ";"
    elif mutation == "raw_string_decoy":
        replacement = 'const DECOY: &str = r###"' + declaration + '"###;'
    else:
        assert mutation == "unterminated_comment"
        replacement = declaration + "\n/* unclosed"
    assert replacement != declaration
    path.write_text(source.replace(declaration, replacement, 1), encoding="utf-8")
    errors = automation._validate_pop_broker_hard_cut_contract(tmp_path)
    assert any(
        f"wire struct {struct_name} fields must be exactly" in error for error in errors
    )


@pytest.mark.parametrize(
    "struct_name",
    [
        name for name, fields in automation.POP_BROKER_WIRE_FIELD_INVENTORIES.items()
        if len(fields) > 1
    ],
)
def test_pop_broker_canonical_declaration_rejects_field_reordering(struct_name: str) -> None:
    source = (
        REPO_ROOT / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    ).read_text(encoding="utf-8")
    declaration = _pop_wire_declaration(source, struct_name)
    fields = re.findall(r"pub\(super\)\s+\w+\s*:[^,]+,", declaration)
    assert len(fields) >= 2
    replacement = (
        declaration.replace(fields[0], "__FIRST_FIELD__", 1)
        .replace(fields[1], fields[0], 1)
        .replace("__FIRST_FIELD__", fields[1], 1)
    )
    observed = automation._pop_broker_wire_field_inventory(
        source.replace(declaration, replacement, 1), struct_name
    )
    assert observed != automation.POP_BROKER_WIRE_FIELD_INVENTORIES[struct_name]


@pytest.mark.parametrize("struct_name", sorted(automation.POP_BROKER_WIRE_FIELD_INVENTORIES))
def test_pop_broker_canonical_declaration_ignores_trivia_and_noncode_decoys(struct_name: str) -> None:
    source = (
        REPO_ROOT / "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    ).read_text(encoding="utf-8")
    declaration = _pop_wire_declaration(source, struct_name)
    formatted = (
        declaration.replace(" frame ", "\n /* nested /* comment */ trivia */ frame\n")
        .replace("; pub", ";\n pub")
    )
    decoys = "\n// " + declaration + "\n/* " + declaration + ' */\nconst DECOY: &str = r#"' + declaration + '"#;\n'
    observed = automation._pop_broker_wire_field_inventory(
        source.replace(declaration, formatted, 1) + decoys, struct_name
    )
    assert observed == automation.POP_BROKER_WIRE_FIELD_INVENTORIES[struct_name]


def test_pop_runtime_production_source_rejects_private_recipient_material(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    runtime = tmp_path / "crates/irohad/src/sorafs_pop_runtime.rs"
    source = runtime.read_text(encoding="utf-8")
    drifted = source.replace(
        "#[cfg(test)]",
        "type LeakedRecipient = iroha_crypto::HybridSecretKey;\n\n#[cfg(test)]",
        1,
    )
    assert drifted != source
    runtime.write_text(drifted, encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="production PoP runtime must not own private recipient material",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "python3 scripts/check_sorafs_release_version_map.py | tee "
            "version-map-summary.replay.json",
            "printf '{}\\n' | tee version-map-summary.replay.json",
        ),
        (
            "cmp version-map-summary.first.json version-map-summary.replay.json",
            "true # removed version-map replay comparison",
        ),
    ],
)
def test_release_gate_requires_byte_identical_version_map_double_run(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    """The release version cannot come from a single or unchecked map pass."""

    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert original in source
    workflow.write_text(source.replace(original, replacement, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="version map must be validated exactly twice"):
        automation.validate_release_automation(tmp_path)


def test_csharp_ci_requires_native_sorafs_governance_validation() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "pr_csharp.yml"
    ).read_text(encoding="utf-8")
    build_job_start = workflow.index("  build-test-pack:\n")
    build_steps_start = workflow.index("    steps:\n", build_job_start)
    build_job_header = workflow[build_job_start:build_steps_start]
    validator_tests = (
        REPO_ROOT
        / "csharp"
        / "tests"
        / "Hyperledger.Iroha.Sdk.Tests"
        / "SoraFsReferenceValidatorsTests.cs"
    ).read_text(encoding="utf-8")

    assert 'IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION: "1"' in workflow
    assert "Bind authenticated target-native package paths" in workflow
    assert (
        "printf 'LD_LIBRARY_PATH=%s\\n' "
        '"$RUNNER_TEMP/csharp-native-package/runtimes/linux-x64/native"'
    ) in workflow
    assert (
        "printf 'IrohaNativePackageRoot=%s\\n' "
        '"$RUNNER_TEMP/csharp-native-package"'
    ) in workflow
    assert (
        "printf 'CSHARP_SDK_PACKAGE_CONSUMER_NATIVE_PACKAGE_ROOT=%s\\n' "
        '"$RUNNER_TEMP/csharp-native-package"'
    ) in workflow
    assert "${{ runner.temp }}" not in build_job_header
    assert (
        'cargo build --locked --release -p connect_norito_bridge --target "$target"'
        in workflow
    )
    assert "package_csharp_native_artifacts.py stage" in workflow
    assert "package_csharp_native_artifacts.py verify-package" in workflow
    assert "dotnet test Hyperledger.Iroha.Sdk.sln" in workflow
    assert "IROHA_REQUIRE_SORAFS_NATIVE_VALIDATION" not in validator_tests
    assert "WhenAvailable" not in validator_tests
    assert "Assert.True(" in validator_tests
    assert (
        "ABI-30 connect_norito_bridge with Governance DAG symbols is required."
        in validator_tests
    )


@pytest.mark.parametrize(
    "relative",
    [
        automation.MOBILE_SDK_ARTIFACTS_WORKFLOW,
    ],
)
def test_native_governance_sdk_contract_requires_fail_closed_environment(
    tmp_path: Path,
    relative: str,
) -> None:
    _copy_workflows(tmp_path)
    target = tmp_path / relative
    source = target.read_text(encoding="utf-8")
    drifted = source.replace(
        automation.NATIVE_GOVERNANCE_VALIDATION_REQUIRED_ENV,
        "REMOVED_NATIVE_GOVERNANCE_REQUIREMENT",
    )
    assert drifted != source
    target.write_text(drifted, encoding="utf-8")

    with pytest.raises(ValueError, match="native Governance DAG"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "marker",
    automation.JAVA_GOVERNANCE_WORKFLOW_STEP_MARKERS,
)
def test_java_governance_validator_uses_external_writable_gradle_state(
    tmp_path: Path,
    marker: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / automation.MOBILE_SDK_ARTIFACTS_WORKFLOW
    source = workflow.read_text(encoding="utf-8")
    start = source.index(automation.JAVA_GOVERNANCE_WORKFLOW_STEP_NAME)
    end = source.index("name: Validate Android mobile SDK artifact", start)
    section = source[start:end]
    assert marker in section
    drifted_section = section.replace(marker, "REMOVED_EXTERNAL_STATE", 1)
    workflow.write_text(
        source[:start] + drifted_section + source[end:],
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Governance DAG"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "required_call", "unconditional_skip"),
    [
        (
            automation.SWIFT_GOVERNANCE_VALIDATOR_TEST,
            (
                "        guard try requireGovernanceDagNativeBridge() else {\n"
                "            return\n"
                "        }\n"
            ),
            (
                "        try XCTSkipIf(\n"
                "            !SorafsReferenceValidators.isGovernanceDagNativeAvailable,\n"
                '            "SoraFS governance DAG reference bridge unavailable"\n'
                "        )\n"
            ),
        ),
        (
            automation.KOTLIN_GOVERNANCE_VALIDATOR_TEST,
            "        requireGovernanceDagNativeBridge()\n",
            (
                "        assumeTrue("
                "SorafsReferenceValidators.isNativeAvailable(), "
                '"connect_norito_bridge not available")\n'
            ),
        ),
        (
            automation.JAVA_GOVERNANCE_VALIDATOR_TEST,
            (
                "  private static void "
                "validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable()\n"
                "      throws IOException {\n"
                "    requireNativeBridge();\n"
            ),
            (
                "  private static void "
                "validatesGovernanceDagFixturesAndNegativeVectorsWhenNativeBridgeIsAvailable()\n"
                "      throws IOException {\n"
                "    if (!SorafsReferenceValidators.isNativeAvailable()) {\n"
                "      return;\n"
                "    }\n"
            ),
        ),
    ],
)
def test_native_governance_sdk_contract_rejects_unconditional_skip(
    tmp_path: Path,
    relative: str,
    required_call: str,
    unconditional_skip: str,
) -> None:
    _copy_workflows(tmp_path)
    target = tmp_path / relative
    source = target.read_text(encoding="utf-8")
    drifted = source.replace(required_call, unconditional_skip, 1)
    assert drifted != source
    target.write_text(drifted, encoding="utf-8")

    with pytest.raises(ValueError, match="Governance DAG"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (".github/workflows/sorafs-cli-release.yml", "run: bash ci/check_sorafs_cli_release.sh"),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "python3 scripts/check_workflow_action_pins.py",
        ),
        (".github/workflows/sorafs-cli-release.yml", "cosign sign-blob --yes --bundle"),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Verify platform package checksums before signing",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "actions/attest@a1948c3f048ba23858d222213b7c278aabede763",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "SHA256SUMS does not cover the exact platform candidate file set",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "grype-version: v0.112.0",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Rebuild deterministic platform archive and run clean-consumer smoke",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Stage source release scan evidence",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "specs/sorafs/runbooks/release_rollback_yank.md "
            "artifacts/sorafs-cli/ROLLBACK-YANK.md",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/build_release_bundle.sh"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/release_profile_validation_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Verify the protected external Ed25519 manifest tuple",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Verify authenticated release-manifest candidate binding before provenance",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/build_sorafs_reference_sdk_supply_chain_sources.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/build_sorafs_foundational_prerequisite.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/build_sorafs_topology_qualification_envelope.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/sorafs_software_signer_receipt.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/sorafs_topology_qualification.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/sorafs_evidence_json.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/sorafs_response_args.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/build_sorafs_reference_sdk_supply_chain_sources_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/build_sorafs_foundational_prerequisite_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/sorafs_topology_qualification_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/sorafs_evidence_json_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/sorafs_foundational_receipt_test_support.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/tests/sorafs_response_args_test.py"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "scripts/examples/sorafs_l1_topology_qualification_envelope.md"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "specs/sorafs/l1_deployment_qualification.md"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Assemble and validate the canonical SF-11 source indexes",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Build and gate source-derived SF-11 supply-chain evidence",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "expected one aggregate offline provenance bundle",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Attest aggregate signed-input provenance",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '"signed-input/github-attestations/${target}.json"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            'gh attestation verify "$provenance_file"',
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "realpath -e --",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "SORAFS_TRUSTED_GH_CLI_SHA256: ${{ vars.SORAFS_TRUSTED_GH_CLI_SHA256 }}",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            "name: Upload replay-complete SF-11 supply-chain evidence",
        ),
        (
            ".github/workflows/sorafs-cli-release.yml",
            '- "specs/release_automation_plan*.md"',
        ),
        (
            ".github/workflows/sorafs-fixtures-nightly.yml",
            "bash ci/check_sorafs_fixtures.sh",
        ),
        (
            ".github/workflows/sorafs-fixtures-nightly.yml",
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        (".github/workflows/sorafs-orchestrator-sdk.yml", "runs-on: macos-14"),
        (".github/workflows/sorafs-orchestrator-sdk.yml", "bash ci/sdk_sorafs_orchestrator.sh"),
        (".github/workflows/sorafs-orchestrator-sdk.yml", "  mobile-parity:"),
        (".github/workflows/sorafs-orchestrator-sdk.yml", "  csharp-parity:"),
        (".github/workflows/sorafs-orchestrator-sdk.yml", '- ".cargo/**"'),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            '- "scripts/package_mobile_sdk_artifacts.sh"',
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            "bash ci/check_sorafs_python_native_sdk.sh",
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            "check_native_sdk_artifact.py verify",
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            "Build and authenticate the exact ABI-30 C# bridge",
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            'sdkmanager_status="${PIPESTATUS[1]}"',
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            "dotnet restore Hyperledger.Iroha.Sdk.sln",
        ),
        (
            ".github/workflows/sorafs-orchestrator-sdk.yml",
            "dotnet test Hyperledger.Iroha.Sdk.sln -c Release --no-build",
        ),
    ],
)
def test_validate_release_automation_rejects_removed_contract_markers(
    tmp_path: Path, relative: str, marker: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / relative
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(marker, "removed"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "    runs-on: ubuntu-latest\n",
            "    continue-on-error: true\n    runs-on: ubuntu-latest\n",
        ),
        (
            "        run: cargo fetch --locked\n",
            "        run: cargo fetch --locked || true\n",
        ),
    ],
)
def test_validate_release_automation_rejects_fail_open_parity_jobs(
    tmp_path: Path, needle: str, replacement: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-orchestrator-sdk.yml"
    source = workflow.read_text(encoding="utf-8")
    assert source.count(needle) == 1
    workflow.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="fail-open marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("injection", "message"),
    [
        ("pull_request_target:\n", "pull_request_target is forbidden"),
        ("# curl https://unreviewed.invalid/installer | sh\n", "network bootstrap"),
        ("      - uses: example/action@main\n", "floating action"),
    ],
)
def test_validate_release_automation_rejects_unsafe_workflow_mutations(
    tmp_path: Path, injection: str, message: str
) -> None:
    _copy_workflows(tmp_path)
    relative = ".github/workflows/sorafs-cli-release.yml"
    workflow = tmp_path / relative
    workflow.write_text(injection + workflow.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "permission", ["id-token: write", "attestations: write", "artifact-metadata: write"]
)
def test_validate_release_automation_rejects_global_elevated_permission(
    tmp_path: Path, permission: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "permissions:\n  contents: read",
            f"permissions:\n  contents: read\n  {permission}",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must be signing-job scoped"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "step_name",
    ["Generate platform binary SBOM", "Scan platform binary SBOM"],
)
def test_validate_release_automation_requires_platform_binary_scanning(
    tmp_path: Path, step_name: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(f"name: {step_name}", f"name: Removed {step_name}", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_both_scans_to_pin_grype(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace("grype-version: v0.112.0", "grype-version: v0.111.0", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must both pin Grype v0.112.0"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "          - os: ubuntu-24.04-arm\n"
            "            target: aarch64-unknown-linux-gnu",
            "          - os: ubuntu-24.04\n"
            "            target: aarch64-unknown-linux-gnu",
        ),
        (
            "          - os: macos-15-intel\n"
            "            target: x86_64-apple-darwin",
            "          - os: macos-14\n"
            "            target: x86_64-apple-darwin",
        ),
        (
            "          - os: windows-latest\n"
            "            target: x86_64-pc-windows-msvc",
            "          - os: windows-latest\n"
            "            target: i686-pc-windows-msvc",
        ),
    ],
)
def test_validate_release_automation_rejects_wrong_native_target_runner_pairs(
    tmp_path: Path, original: str, replacement: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert original in source
    workflow.write_text(source.replace(original, replacement, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="native release matrix must contain exactly"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_missing_mandatory_target(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    entry = (
        "          - os: macos-14\n"
        "            target: aarch64-apple-darwin\n"
        '            binary_suffix: ""\n'
    )
    assert entry in source
    workflow.write_text(source.replace(entry, "", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="native release matrix must contain exactly"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_signing_inventory_drift(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "            aarch64-apple-darwin\n"
            "            x86_64-pc-windows-msvc\n",
            "            aarch64-apple-darwin\n"
            "            i686-pc-windows-msvc\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="target inventory must exactly match"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_promotion_auth_bypass(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "needs: [release-gate, package, verify-release-auth]",
            "needs: [release-gate, package]",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match="release promotion must depend on protected Ed25519",
    ):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_alternate_promotion_job(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8")
        + "\n"
        + "  bypass-promotion:\n"
        + "    runs-on: ubuntu-latest\n"
        + "    steps: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="job inventory must be exactly"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("binding", "message"),
    [
        (
            "SORAFS_REFERENCE_SDK_DEPLOYMENT_ID: "
            "${{ vars.SORAFS_REFERENCE_SDK_DEPLOYMENT_ID }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_REFERENCE_SDK_RECEIPTS_ROOT: "
            "${{ vars.SORAFS_REFERENCE_SDK_RECEIPTS_ROOT }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX: "
            "${{ vars.SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_TRUSTED_GH_CLI_SHA256: "
            "${{ vars.SORAFS_TRUSTED_GH_CLI_SHA256 }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SUMMARY_PATH }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_ENVELOPE_PATH }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_SERVICE_ID }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_ADMINISTRATOR_ID }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_KEY_REVISION }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_REVISION }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX: "
            "${{ vars.SORAFS_L1_TOPOLOGY_QUALIFICATION_SIGNER_POLICY_DIGEST_HEX }}",
            "external receipt, topology, or public-key binding",
        ),
        (
            "--supply-chain-source-root sf11-source",
            "source root and exact public provenance trust tuple",
        ),
        (
            '--provenance-certificate-identity "$certificate_identity"',
            "source root and exact public provenance trust tuple",
        ),
        (
            '--provenance-oidc-issuer "$oidc_issuer"',
            "source root and exact public provenance trust tuple",
        ),
    ],
)
def test_validate_release_automation_rejects_source_evidence_binding_drift(
    tmp_path: Path,
    binding: str,
    message: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert binding in source
    workflow.write_text(
        source.replace(binding, "REMOVED_SOURCE_BINDING", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_source_evidence_job_reordering(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    original = (
        "name: Reverify exact target provenance before source assembly"
    )
    replacement = (
        "name: Temporarily moved target provenance verification"
    )
    source = source.replace(original, replacement, 1)
    source = source.replace(
        "name: Assemble and validate the canonical SF-11 source indexes",
        "name: Assemble and validate the canonical SF-11 source indexes\n"
        f"      - name: {original}",
        1,
    )
    workflow.write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_source_target_order_drift(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    job_start = source.index("  reference-sdk-supply-chain-evidence:\n")
    job = source[job_start:]
    original = (
        "            x86_64-apple-darwin\n"
        "            aarch64-apple-darwin\n"
    )
    replacement = (
        "            aarch64-apple-darwin\n"
        "            x86_64-apple-darwin\n"
    )
    assert original in job
    workflow.write_text(
        source[:job_start] + job.replace(original, replacement, 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="canonical source order"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "provenance_file",
    [
        '"${candidate}/SHA256SUMS"',
        '"${candidate}/sorafs-release.spdx.json"',
        '"${candidate}/sorafs-release-vulnerabilities.sarif"',
        '"${candidate}/sorafs-cli-${target}.spdx.json"',
        '"${candidate}/sorafs-cli-${target}-vulnerabilities.sarif"',
    ],
)
def test_validate_release_automation_rejects_incomplete_provenance_file_inventory(
    tmp_path: Path,
    provenance_file: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert source.count(provenance_file) == 1
    workflow.write_text(
        source.replace(f"              {provenance_file}\n", "", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact checksum, archive, and scan files"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "marker",
    [
        "! -name '*.sigstore.json'",
        "signed candidate SHA256SUMS contains duplicate entries",
        "signed candidate SHA256SUMS does not cover the exact candidate file set",
    ],
)
def test_validate_release_automation_requires_signed_checksum_reconciliation(
    tmp_path: Path,
    marker: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    job_start = source.index("  reference-sdk-supply-chain-evidence:\n")
    job = source[job_start:]
    assert job.count(marker) == 1
    workflow.write_text(
        source[:job_start] + job.replace(marker, "REMOVED_CHECKSUM_GUARD", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="signed checksum manifest"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_unpinned_gh_verifier(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    original = '[[ "$actual_gh_sha256" != "$SORAFS_TRUSTED_GH_CLI_SHA256" ]]'
    assert original in source
    workflow.write_text(
        source.replace(original, '[[ "$actual_gh_sha256" == "" ]]', 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="protected SHA-256"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_independent_topology_key(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    original = (
        '[[ "$SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX" '
        '== "$SORAFS_PROVENANCE_VERIFICATION_PUBLIC_KEY_HEX" ]]'
    )
    assert original in source
    workflow.write_text(
        source.replace(
            original,
            '[[ "$SORAFS_L1_TOPOLOGY_QUALIFICATION_VERIFICATION_PUBLIC_KEY_HEX" == "" ]]',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="independently administered"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_lexical_external_path_check(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    original = '[[ "$path" != "$path_real" ]]'
    assert source.count(original) == 2
    workflow.write_text(
        source.replace(original, '[[ "$path" == "" ]]'),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="canonicalized before workspace exclusion"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_replay_complete_source_upload(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    upload_line = "            sf11-source/\n"
    assert source.count(upload_line) == 1
    workflow.write_text(
        source.replace(
            upload_line,
            "            sf11-source/release-rehearsal.json\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="complete replay source tree"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_source_job_oidc_authority(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    job_start = source.index("  reference-sdk-supply-chain-evidence:\n")
    job = source[job_start:]
    assert "    permissions:\n      contents: read\n" in job
    workflow.write_text(
        source[:job_start]
        + job.replace(
            "    permissions:\n      contents: read\n",
            "    permissions:\n      contents: read\n      id-token: write\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="verification-only"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        (
            "environment: sorafs-release-authentication",
            "environment: unprotected-release",
            "protected release-authentication environment",
        ),
        (
            "runs-on: [self-hosted, linux, x64, sorafs-release-auth]",
            "runs-on: ubuntu-latest",
            "protected self-hosted release-auth runner",
        ),
        (
            "SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256: "
            "${{ vars.SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256 }}",
            "SORAFS_TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256: ''",
            "missing an explicit protected public tuple",
        ),
    ],
)
def test_validate_release_automation_rejects_unprotected_auth_configuration(
    tmp_path: Path,
    original: str,
    replacement: str,
    message: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert original in source
    workflow.write_text(source.replace(original, replacement, 1), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_signing_in_auth_job(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    marker = "python3 scripts/release_manifest_signing.py verify"
    assert source.count(marker) == 2
    workflow.write_text(
        source.replace(
            marker,
            "python3 scripts/release_manifest_signing.py sign",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="verification-only"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_oidc_in_auth_job(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    anchor = (
        "  verify-release-auth:\n"
        "    if: ${{ startsWith(github.ref, 'refs/tags/sorafs-cli-v') "
        "|| inputs.sign_artifacts }}\n"
    )
    assert anchor in source
    workflow.write_text(
        source.replace(
            anchor,
            anchor + "    # id-token: write must never enter this job\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="OIDC and provenance authority"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_private_key_in_auth_job(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    anchor = (
        "    env:\n"
        "      SORAFS_RELEASE_SIGNATURE_PATH: "
        "${{ vars.SORAFS_RELEASE_SIGNATURE_PATH }}\n"
    )
    assert anchor in source
    workflow.write_text(
        source.replace(
            anchor,
            "    env:\n"
            "      SORAFS_RELEASE_PRIVATE_KEY_PATH: "
            "${{ vars.SORAFS_RELEASE_PRIVATE_KEY_PATH }}\n"
            "      SORAFS_RELEASE_SIGNATURE_PATH: "
            "${{ vars.SORAFS_RELEASE_SIGNATURE_PATH }}\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not receive private signing material"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_private_key_in_promotion_job(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    anchor = (
        "  sign:\n"
        "    if: ${{ startsWith(github.ref, 'refs/tags/sorafs-cli-v') "
        "|| inputs.sign_artifacts }}\n"
    )
    assert anchor in source
    workflow.write_text(
        source.replace(
            anchor,
            anchor
            + "    env:\n"
            + "      SORAFS_ED25519_PRIVATE_KEY_PATH: /run/forbidden.key\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not receive private signing material"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_promotion_candidate_binding_bypass(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    marker = "python3 scripts/generate_sorafs_cli_release_manifest.py check"
    assert source.count(marker) == 2
    second = source.index(marker, source.index(marker) + 1)
    workflow.write_text(
        source[:second] + marker.replace(" check", " create") + source[second + len(marker) :],
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reconcile the downloaded authenticated manifest"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_five_checksum_manifests(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            '[[ "${#checksum_files[@]}" -ne 5 ]]',
            '[[ "${#checksum_files[@]}" -ne 4 ]]',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_native_host_smoke_builds(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            'if [[ "$host_target" != "$target" ]]; then',
            'if [[ "$host_target" == "$target" ]]; then',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing contract marker"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_platform_scan_after_checksums(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "name: Scan platform binary SBOM",
            "name: Temporarily moved platform binary SBOM",
            1,
        ).replace(
            "name: Upload unsigned release candidate",
            "name: Scan platform binary SBOM\n      - name: Upload unsigned release candidate",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_archive_replay_after_checksums(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "name: Rebuild deterministic platform archive and run clean-consumer smoke",
            "name: Temporarily moved deterministic platform archive",
            1,
        ).replace(
            "name: Upload unsigned release candidate",
            "name: Rebuild deterministic platform archive and run clean-consumer smoke\n"
            "      - name: Upload unsigned release candidate",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_run_specific_scan_before_archive(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    archive_name = (
        "name: Rebuild deterministic platform archive and run clean-consumer smoke"
    )
    scan_name = "name: Stage source release scan evidence"
    workflow.write_text(
        source.replace(archive_name, "name: Temporary swap", 1)
        .replace(scan_name, archive_name, 1)
        .replace("name: Temporary swap", scan_name, 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_two_candidate_builds(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    first = "python3 scripts/package_sorafs_cli_candidate.py"
    assert source.count(first) == 2
    workflow.write_text(
        source.replace(first, "python3 removed-packager.py", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="built exactly twice"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_two_reference_validator_builds(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    first = source.find("bash scripts/package_iroha_cli_release.sh")
    second = source.find(
        "bash scripts/package_iroha_cli_release.sh",
        first + 1,
    )
    assert first >= 0 and second > first
    workflow.write_text(
        source[:second]
        + "bash removed_reference_validator_packager.sh"
        + source[
            second + len("bash scripts/package_iroha_cli_release.sh") :
        ],
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="reference-validator package must be built exactly twice",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("option", "message"),
    (
        (
            '--source-commit "$source_commit"',
            "both reference-validator package replays must bind the reviewed source commit",
        ),
        (
            '--source-date-epoch "$source_date_epoch"',
            "both reference-validator package replays must bind the canonical source epoch",
        ),
    ),
)
def test_validate_release_automation_requires_replayed_package_identity(
    tmp_path: Path,
    option: str,
    message: str,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    assert source.count(option) == 2
    workflow.write_text(source.replace(option, "REMOVED", 1), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_archive_and_manifest_comparisons(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    replay_compare = 'cmp \\\n            "${first_out}/${package_name}'
    assert source.count(replay_compare) == 2
    workflow.write_text(
        source.replace(replay_compare, 'true \\\n            "${first_out}/${package_name}', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="replay comparisons"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_reference_package_after_platform_sbom(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "name: Package Iroha CLI and SoraFS FFI header",
            "name: Temporarily moved reference validator package",
            1,
        ).replace(
            "name: Scan platform binary SBOM",
            "name: Package Iroha CLI and SoraFS FFI header\n"
            "      - name: Scan platform binary SBOM",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_checksum_verification_after_signing(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    source = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        source.replace(
            "name: Verify platform package checksums before signing",
            "name: Temporarily moved checksum verification",
            1,
        ).replace(
            "name: Upload signed release candidate",
            "name: Verify platform package checksums before signing\n"
            "      - name: Upload signed release candidate",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of order"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (
            "specs/sorafs/runbooks/index.md",
            "[Release rollback and yank](./release_rollback_yank.md)",
        ),
        (
            "specs/sorafs_release_pipeline_plan.md",
            "exactly the five expected target-triple checksum manifests",
        ),
        (
            "specs/sorafs/runbooks/release_rollback_yank.md",
            "`cargo yank --vers <version> <crate>`",
        ),
        (
            "specs/sorafs/runbooks/release_rollback_yank.md",
            "GitHub CLI artifacts",
        ),
        (
            "specs/sorafs/developer/releases.md",
            "all five native candidate archives",
        ),
        (
            "fixtures/documentation/sorafs_release_notes.md",
            "## Rollback / Yank Record",
        ),
    ],
)
def test_validate_release_automation_rejects_release_document_drift(
    tmp_path: Path, relative: str, marker: str
) -> None:
    _copy_workflows(tmp_path)
    document = tmp_path / relative
    source = document.read_text(encoding="utf-8")
    assert marker in source
    document.write_text(source.replace(marker, "removed", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="release-document contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "marker"),
    [
        (
            "scripts/examples/"
            "sorafs_reference_sdk_release_supply_chain_canary.args.example",
            "--supply-chain-source-root",
        ),
        (
            "scripts/examples/"
            "sorafs_reference_sdk_release_collection.args.example",
            "--provenance-certificate-identity",
        ),
        (
            "scripts/examples/"
            "sorafs_reference_sdk_release_evidence.args.example",
            "--provenance-verification-public-key-hex",
        ),
        ("scripts/examples/sorafs_reference_sdk_release_collection.args.example", "--signed-manifest-source-context-sha256"),
        ("scripts/examples/sorafs_reference_sdk_release_evidence.args.example", "--signed-manifest-source-context-sha256"),
        ("scripts/examples/sorafs_reference_sdk_release_signed_manifest_canary.args.example", "--signed-manifest-source-context-sha256"),
        ("scripts/examples/sorafs_reference_sdk_signed_manifest_canary.args.example", "--signed-manifest-source-context-sha256"),
    ],
)
def test_validate_release_automation_rejects_stale_source_examples(
    tmp_path: Path,
    relative: str,
    marker: str,
) -> None:
    _copy_workflows(tmp_path)
    example = tmp_path / relative
    source = example.read_text(encoding="utf-8")
    assert marker in source
    example.write_text(
        source.replace(marker, "REMOVED_SOURCE_INPUT", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing source-bound example marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    "retired",
    (
        "--target",
        "--sbom-index-digest-hex",
        "--vulnerability-report-digest-hex",
        "--provenance-bundle-digest-hex",
    ),
)
def test_validate_release_automation_rejects_retired_supply_chain_example_flags(
    tmp_path: Path,
    retired: str,
) -> None:
    _copy_workflows(tmp_path)
    relative = (
        "scripts/examples/"
        "sorafs_reference_sdk_release_supply_chain_canary.args.example"
    )
    example = tmp_path / relative
    example.write_text(
        example.read_text(encoding="utf-8") + f"{retired}\nretired-value\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="retired manual release marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("retired", ("--manifest-digest-hex", "--policy-digest-hex", "--public-key-fingerprint-hex", "--signature-algorithm", "--signing-provider", "--signing-backend"))
@pytest.mark.parametrize("name", ("sorafs_reference_sdk_release_signed_manifest_canary.args.example", "sorafs_reference_sdk_signed_manifest_canary.args.example"))
def test_validate_release_automation_rejects_signing_claims_in_source_examples(tmp_path, retired, name):
    _copy_workflows(tmp_path)
    path = tmp_path / "scripts/examples" / name
    path.write_text(path.read_text() + f"{retired}\nclaim\n")
    with pytest.raises(ValueError, match="retired manual release marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("relative", "stale_claim"),
    [
        ("specs/sorafs_release_pipeline_plan.md", "via cross"),
        (
            "specs/sorafs_release_pipeline_plan.md",
            "exactly the three expected platform checksum manifests",
        ),
        (
            "specs/sorafs/developer/releases.md",
            "git tag -s sorafs-v",
        ),
        (
            "specs/sorafs/developer/releases.md",
            "invokes the script above",
        ),
    ],
)
def test_validate_release_automation_rejects_stale_release_document_claims(
    tmp_path: Path, relative: str, stale_claim: str
) -> None:
    _copy_workflows(tmp_path)
    document = tmp_path / relative
    document.write_text(
        document.read_text(encoding="utf-8") + f"\n{stale_claim}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="stale release-document claim"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("stale_reference", "finding"),
    [
        (
            "sorafs_cli manifest sign --manifest manifest.to",
            "retired local manifest-authentication command",
        ),
        (
            "sorafs_cli manifest verify-signature --manifest manifest.to",
            "retired local manifest-authentication command",
        ),
        (
            "--identity-token-file=/run/release.jwt",
            "retired identity-token signing option",
        ),
        (
            "fixtures/sorafs_manifest/ci_sample/manifest.sig",
            "retired ci_sample authentication artifact",
        ),
        (
            "copy manifest.sign.summary.json into the release evidence",
            "retired local manifest-authentication artifact",
        ),
        (
            "openssl pkeyutl -sign -inkey release.pem -in manifest.json",
            "generic OpenSSL/RSA signing command",
        ),
        (
            "openssl dgst -sha256 -sign=release.pem manifest.json",
            "generic OpenSSL/RSA signing command",
        ),
        (
            "derive an Ed25519 signing key from the OIDC identity token",
            "OIDC-derived local Ed25519 signing material",
        ),
    ],
)
def test_validate_release_automation_rejects_retired_auth_across_document_tree(
    tmp_path: Path,
    stale_reference: str,
    finding: str,
) -> None:
    _copy_workflows(tmp_path)
    document = tmp_path / "docs/retired-release-auth.md"
    document.write_text(f"# Retired path\n\n{stale_reference}\n", encoding="utf-8")
    with pytest.raises(
        ValueError,
        match=rf"forbidden release-auth documentation reference \({finding}\)",
    ):
        automation.validate_release_automation(tmp_path)


def test_release_auth_document_discovery_rejects_symlinked_entries(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    target = tmp_path / "outside-release-auth.md"
    target.write_text("# External document\n", encoding="utf-8")
    (tmp_path / "docs/symlinked-release-auth.md").symlink_to(target)

    with pytest.raises(ValueError, match="must not contain symlinks"):
        automation.validate_release_automation(tmp_path)


def test_release_auth_document_discovery_ignores_generated_node_dependencies(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    generated = tmp_path / "tools/openapi/node_modules/package"
    generated.mkdir(parents=True)
    (generated / "stale-release-auth.md").write_text(
        "openssl pkeyutl -sign -inkey release.pem -in manifest.json\n",
        encoding="utf-8",
    )
    binary_dir = generated / ".bin"
    binary_dir.mkdir()
    (binary_dir / "tool").symlink_to(generated / "stale-release-auth.md")

    summary = automation.validate_release_automation(tmp_path)
    assert summary["workflow_count"] == len(automation.WORKFLOWS)


def test_release_auth_document_discovery_rejects_hard_linked_documents(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    target = tmp_path / "docs/release-auth-source.md"
    target.write_text("# Release authentication\n", encoding="utf-8")
    os.link(target, tmp_path / "docs/release-auth-alias.md")

    with pytest.raises(ValueError, match="must not be hard linked"):
        automation.validate_release_automation(tmp_path)


def test_release_auth_document_discovery_enforces_entry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _copy_workflows(tmp_path)
    for index in range(2):
        (tmp_path / "docs" / f"budget-{index}.md").write_text(
            "# Release-auth entry-budget fixture\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(automation, "MAX_RELEASE_AUTH_TREE_ENTRIES", 1)

    with pytest.raises(ValueError, match="exceeds its entry limit"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_historical_oidc_finding_remediation(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    relative = "specs/sorafs/reports/sf6_security_review.md"
    document = tmp_path / relative
    source = document.read_text(encoding="utf-8")
    marker = "Removed that CLI surface and all production callers"
    assert marker in source
    document.write_text(
        source.replace(marker, "Remediation pending", 1),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match="OIDC-derived local Ed25519 signing material",
    ):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize(
    ("injection", "message"),
    [
        (
            "openssl dgst -sha256 -sign release.pem dist/package.whl\n",
            "generic OpenSSL/RSA signing is forbidden",
        ),
        (
            '${OPENSSL_BIN} dgst -sha256 -sign release.pem dist/package.whl\n',
            "generic OpenSSL/RSA signing is forbidden",
        ),
        (
            "cosign sign-blob dist/package.whl\n",
            "signing/provenance marker",
        ),
        (
            "PYTHON_RELEASE_SIGNING_KEY=/run/private.pem\n",
            "signing/provenance marker",
        ),
    ],
)
def test_validate_release_automation_rejects_package_smoke_signers(
    tmp_path: Path,
    injection: str,
    message: str,
) -> None:
    _copy_workflows(tmp_path)
    smoke = tmp_path / automation.PACKAGE_RELEASE_SMOKE_SCRIPT
    smoke.write_text(
        smoke.read_text(encoding="utf-8") + f"\n{injection}",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=message):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_requires_external_auth_route_from_smoke(
    tmp_path: Path,
) -> None:
    _copy_workflows(tmp_path)
    smoke = tmp_path / automation.PACKAGE_RELEASE_SMOKE_SCRIPT
    source = smoke.read_text(encoding="utf-8")
    marker = "scripts/release_manifest_signing.py"
    assert marker in source
    smoke.write_text(source.replace(marker, "removed-auth-route", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="missing package-smoke contract marker"):
        automation.validate_release_automation(tmp_path)


@pytest.mark.parametrize("permission", ["attestations: write", "artifact-metadata: write"])
def test_validate_release_automation_requires_job_scoped_attestation_permissions(
    tmp_path: Path, permission: str
) -> None:
    _copy_workflows(tmp_path)
    workflow = tmp_path / ".github/workflows/sorafs-cli-release.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(f"      {permission}\n", "", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must request"):
        automation.validate_release_automation(tmp_path)


def test_validate_release_automation_rejects_symlinked_workflow(tmp_path: Path) -> None:
    _copy_workflows(tmp_path)
    relative = ".github/workflows/sorafs-orchestrator-sdk.yml"
    workflow = tmp_path / relative
    target = tmp_path / "workflow-target.yml"
    workflow.replace(target)
    workflow.symlink_to(target)
    with pytest.raises(ValueError, match="symlinks"):
        automation.validate_release_automation(tmp_path)


def test_main_emits_schema_closed_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert automation.main() == 0
    assert json.loads(capsys.readouterr().out) == automation.validate_release_automation(
        REPO_ROOT
    )


def test_cli_release_gate_runs_supply_chain_and_topology_adversarial_suites() -> None:
    """Explicit diagnostics retain SF-11 and topology adversarial tests."""

    source = (REPO_ROOT / "ci/check_sorafs_cli_release.sh").read_text(
        encoding="utf-8"
    )
    assert 'diagnostics=false\ncase "$#" in\n' in source
    assert 'if [[ "$1" != "--diagnostics" ]]; then' in source
    integrity_return = source.index('if [[ "${diagnostics}" != true ]]; then')
    assert source.index(automation.SORAFS_CLI_BUILD_EFFICIENCY_PROVENANCE_COMMAND) < integrity_return
    assert source.index("python3 -I -S scripts/check_release_feature_graph.py") < integrity_return
    assert integrity_return < source.index("cargo fmt --all -- --check")
    for relative in (
        "scripts/tests/check_sorafs_mobile_parity_reports_test.py",
        "scripts/tests/release_output_parent_cleanup_test.py",
        "scripts/tests/release_output_transaction_cleanup_test.py",
        "scripts/tests/build_sorafs_reference_sdk_supply_chain_sources_test.py",
        "scripts/tests/sorafs_reference_sdk_supply_chain_test.py",
        "scripts/tests/sorafs_reference_sdk_signed_manifest_test.py",
        "scripts/tests/sorafs_java_consumer_artifact_test.py",
        "scripts/tests/sorafs_java_dependency_origins_test.py",
        "scripts/tests/sorafs_sdk_artifact_index_test.py",
        "scripts/tests/sorafs_javascript_archive_test.py",
        "scripts/tests/sorafs_javascript_archive_bounds_test.py",
        "scripts/tests/sorafs_javascript_dependencies_test.py",
        "scripts/tests/sorafs_javascript_package_source_test.py",
        "scripts/tests/sorafs_javascript_package_bounds_test.py",
        "scripts/tests/sorafs_javascript_installed_test.py",
        "scripts/tests/sorafs_javascript_qualification_source_test.py",
        "scripts/tests/python_wheel_byte_owner_test.py",
        "scripts/tests/python_installed_content_owner_test.py",
        "scripts/tests/python_zip_directory_admission_test.py",
        "scripts/tests/sorafs_python_child_input_content_test.py",
        "scripts/tests/sorafs_python_posix_profile_test.py",
        "scripts/tests/sorafs_python_bootstrap_origin_test.py",
        "scripts/tests/sorafs_python_report_origins_test.py",
        "scripts/tests/sorafs_sdk_python_artifact_verifier_test.py",
        "scripts/tests/sorafs_python_child_runner_test.py",
        "scripts/tests/sorafs_python_consumer_artifact_test.py",
        "scripts/tests/build_sorafs_python_consumer_artifact_test.py",
        "scripts/tests/check_native_sdk_artifact_test.py",
        "scripts/tests/check_native_sdk_bounded_probe_test.py",
        "scripts/tests/sorafs_python_environment_test.py",
        "scripts/tests/sorafs_python_process_test.py",
        "scripts/tests/sorafs_python_producer_inputs_test.py",
        "scripts/tests/sorafs_python_package_source_test.py",
        "scripts/tests/sorafs_python_publication_test.py",
        "scripts/tests/sorafs_python_archive_test.py",
        "scripts/tests/sorafs_python_commands_test.py",
        "scripts/tests/sorafs_python_runtime_publication_join_test.py",
        "scripts/tests/sorafs_python_runtime_inputs_test.py",
        "scripts/tests/sorafs_python_dependency_install_test.py",
        "scripts/tests/check_sorafs_release_version_map_test.py",
        "cargo test --locked -p iroha --lib client::repair::tests -- --nocapture",
        "cargo test --locked -p iroha --lib client::reserve::tests -- --nocapture",
        "cargo test --locked -p iroha --lib does_not_follow_signed_body_redirects -- --nocapture",
        'provider_ingest_test="sorafs_provider_ingest_runtime::tests::quarantine_restart::post_admission_quarantine_survives_restart_with_shared_chunks"',
        'cargo test --locked -p irohad_lib --lib "${provider_ingest_test}" -- --exact --list',
        'grep -Fxc -- "${provider_ingest_test}: test"',
        "--exact --include-ignored --nocapture",
        "scripts/tests/check_sorafs_provider_ingest_runtime_contract_test.py",
        "scripts/tests/check_sorafs_production_promotion_bundle_test.py",
        'expected_cargo_lock_sha256="$(cargo_lock_sha256)"',
        'if [[ "$(cargo_lock_sha256)" != "${expected_cargo_lock_sha256}" ]]',
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py::test_sorafs_production_readiness_aggregate_gate_is_documented",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py::test_pdp_provider_protocol_and_chain_repair_boundary_are_documented",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py::test_repair_chain_authority_is_closed_and_live_evidence_stays_open_in_docs",
        "scripts/tests/check_sorafs_rollout_gate_contract_test.py::test_reserve_rent_chain_authoritative_contract_stays_open_until_evidence",
        "scripts/tests/check_sorafs_rust_owner_contract_test.py",
        "scripts/tests/sorafs_evidence_json_test.py",
        "scripts/tests/sorafs_response_args_test.py",
        "scripts/tests/sorafs_topology_qualification_test.py",
    ):
        assert source.count(relative) == 1


def test_release_workflow_script_dependencies_are_exactly_pinned() -> None:
    requirements = (REPO_ROOT / "scripts/requirements.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    assert requirements == sorted(requirements)
    assert requirements == [
        "blake3==1.0.9",
        'cffi==2.1.1; platform_python_implementation != "PyPy"',
        "cryptography==50.0.1",
        "jsonschema==4.26.0",
        'pycparser==3.0; platform_python_implementation != "PyPy"',
        "pytest==9.0.3",
        "requests==2.33.0",
        'tomli==2.4.1; python_version < "3.11"',
        "tomli_w==1.2.0",
        'typing_extensions==4.16.0; python_version < "3.11"',
    ]
    dependabot = (REPO_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    assert 'package-ecosystem: "pip"' in dependabot
    assert "      - /scripts" in dependabot


@pytest.mark.parametrize("test", (
    "scripts/tests/release_output_parent_cleanup_test.py",
    "scripts/tests/release_output_transaction_cleanup_test.py",
    "scripts/tests/sorafs_javascript_qualification_source_test.py",
    "scripts/tests/sorafs_javascript_child_abi_contract_test.py",
    "scripts/tests/sorafs_javascript_input_files_test.py",
    "scripts/tests/sorafs_javascript_parent_input_test.py",
    "scripts/tests/sorafs_javascript_runtime_inputs_test.py",
    "scripts/tests/sorafs_javascript_child_process_test.py",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_accepts_thin_and_nonoverlapping_fat_images",
    "scripts/tests/macho_decoder_test.py::test_strict_macho_parser_rejects_nonzero_fat64_reserved_field",
    "scripts/tests/sorafs_javascript_installed_test.py",
))
def test_release_parent_cleanup_controls_have_an_executable_registration(test):
    """The content and descriptor suites run in the strict pytest batch."""
    source = (REPO_ROOT / "ci/check_sorafs_cli_release.sh").read_text()
    batch = re.search(r"(?m)^python3 -m pytest -q \\\n((?:  [^\n]+\n)+)", source)
    assert batch is not None
    assert batch.group(1).splitlines().count("  " + test + " \\") == 1
    workflow = (REPO_ROOT / ".github/workflows/sorafs-cli-release.yml").read_text()
    assert automation._pull_request_path_entries(workflow).count(test.split("::", 1)[0]) == 1


@pytest.mark.parametrize("mutation", (
    "remove", "comment", "duplicate", "conditional", "ignore_failure",
    "after_return", "outer_conditional", "outer_function", "early_exit", "disable_errexit",
    "remove_lock_recheck", "swallow_lock_recheck",
    "remove_diagnostic_lock_recheck", "conditional_diagnostic_lock_recheck",
))
def test_broker_deployment_contract_has_one_unconditional_fail_closed_owner(tmp_path, mutation):
    """A plausible marker must not hide an omitted or swallowed real child."""
    _copy_workflows(tmp_path)
    gate = tmp_path / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT
    source = gate.read_text()
    phase = (
        'echo "[sorafs-release] runtime-provider broker deployment contracts"\n'
        "python3 scripts/tests/check_runtime_provider_broker_install_test.py\n\n"
    )
    command = "python3 scripts/tests/check_runtime_provider_broker_install_test.py\n"
    assert source.count(phase) == 1
    replacements = {
        "remove": "",
        "comment": phase.replace(command, "# " + command),
        "duplicate": phase * 2,
        "conditional": "if false; then\n" + phase + "fi\n",
        "ignore_failure": phase.replace(command, command.rstrip() + " || true\n"),
        "outer_function": "unused_broker_contract() {\n" + phase + "}\n",
        "early_exit": "exit 0\n" + phase,
        "disable_errexit": "set +e\n" + phase,
    }
    if mutation == "outer_conditional":
        # Unlike wrapping the single command, this encloses the lock function
        # and leaves the complete marker/boundary intact inside the false arm.
        boundary = "cargo_lock_sha256() {\n"
        assert source.count(boundary) == 1
        source = source.replace(boundary, "if false; then\n" + boundary, 1) + "\nfi\n"
    elif mutation in ("remove_lock_recheck", "swallow_lock_recheck"):
        check = phase + "verify_cargo_lock_unchanged\n\n"
        assert source.count(check) == 1
        replacement = phase if mutation == "remove_lock_recheck" else phase + "verify_cargo_lock_unchanged || true\n\n"
        source = source.replace(check, replacement, 1)
    elif mutation in ("remove_diagnostic_lock_recheck", "conditional_diagnostic_lock_recheck"):
        check = '\nverify_cargo_lock_unchanged\necho "[sorafs-release] release verification complete"\n'
        assert source.count(check) == 1
        call = "" if mutation == "remove_diagnostic_lock_recheck" else "if false; then\nverify_cargo_lock_unchanged\nfi\n"
        source = source.replace(check, '\n' + call + 'echo "[sorafs-release] release verification complete"\n', 1)
    elif mutation == "after_return":
        source = source.replace(phase, "", 1)
        boundary = 'echo "[sorafs-release] fmt check (workspace)"\n'
        assert source.count(boundary) == 1
        source = source.replace(boundary, phase + boundary, 1)
    else:
        source = source.replace(phase, replacements[mutation], 1)
    gate.write_text(source)
    with pytest.raises(ValueError, match="mandatory broker deployment contracts"):
        automation.validate_release_automation(tmp_path)


def _run_broker_release_gate_fixture(
    tmp_path: Path, mode: tuple[str, ...], fail_child: bool, mutate_lock: bool = False,
    mutate_diagnostics_lock: bool = False,
):
    """Run the real broker unittest child; model only unrelated expensive tools."""
    import shutil
    import subprocess
    import sys

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for relative in (
        automation.SORAFS_CLI_RELEASE_GATE_SCRIPT,
        "scripts/tests/check_runtime_provider_broker_install_test.py",
        "scripts/check_runtime_provider_broker_install.py",
        "crates/irohad/bins/src/bin/sorafs_external_software_signer.rs",
    ):
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPO_ROOT / relative).read_bytes())
    shutil.copytree(
        REPO_ROOT / "configs/sorafs/runtime_provider_broker",
        workspace / "configs/sorafs/runtime_provider_broker",
    )
    if fail_child or mutate_lock:
        child = workspace / "scripts/tests/check_runtime_provider_broker_install_test.py"
        original = child.read_text()
        boundary = 'if __name__ == "__main__":\n'
        assert original.count(boundary) == 1
        refusal = (
            "class DeliberateBrokerContractFailure(unittest.TestCase):\n"
            "    def test_child_failure_is_not_swallowed(self):\n"
            "        self.fail('genuine broker child assertion failure')\n\n\n"
        )
        if mutate_lock:
            refusal = (
                "class DeliberateBrokerLockMutation(unittest.TestCase):\n"
                "    def test_original_child_returns_success_after_lock_changes(self):\n"
                "        (REPO_ROOT / 'Cargo.lock').write_text('changed by fixture child\\n')\n\n\n"
            )
        child.write_text(original.replace(boundary, refusal + boundary, 1))
    (workspace / "Cargo.lock").write_text('# Local lock-reader fixture\nversion = 4\n')
    # These children are controlled callgraph fixtures, not release validation.
    # The complete original broker suite and the bounded lock reader are real.
    for relative in (
        "scripts/release_sorafs_cli.sh", "scripts/package_iroha_cli_release.sh",
        "scripts/build_canonical_binaries.sh", "scripts/build_release_bundle.sh",
        "scripts/build_release_image.sh",
        "configs/sorafs/external_software_signer/launchd/sorafs-external-software-signer-launchd-v1",
        "python/iroha_python/scripts/release_smoke.sh",
        "scripts/tests/release_manifest_signing_test.sh",
        "ci/check_sorafs_reference_ffi_header.sh", "ci/check_sorafs_native_authority_runtime.sh",
    ):
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\nset -euo pipefail\nexit 0\n")
        path.chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir()
    trace = tmp_path / "commands.jsonl"
    python = tools / "python3"
    python.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"trace = {str(trace)!r}\n"
        "with open(trace, 'a') as output:\n"
        "    output.write(json.dumps(['python3', *sys.argv[1:]]) + '\\n')\n"
        "if sys.argv[1:] == ['scripts/tests/check_runtime_provider_broker_install_test.py'] "
        "or sys.argv[1:] == ['-I', '-S', '-', 'Cargo.lock']:\n"
        f"    os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n"
    )
    python.chmod(0o755)
    cargo = tools / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"with open({str(trace)!r}, 'a') as output:\n"
        "    output.write(json.dumps(['cargo', *sys.argv[1:]]) + '\\n')\n"
        "if '--list' in sys.argv:\n"
        "    print('sorafs_provider_ingest_runtime::tests::quarantine_restart::"
        "post_admission_quarantine_survives_restart_with_shared_chunks: test')\n"
        + (
            "if sys.argv[1:] == ['test', '--locked', '-p', 'sorafs_chunker', '--all-targets']:\n"
            "    from pathlib import Path\n"
            "    Path('Cargo.lock').write_text('changed by diagnostic fixture child\\n')\n"
            if mutate_diagnostics_lock else ""
        )
    )
    cargo.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = str(tools) + os.pathsep + environment["PATH"]
    result = subprocess.run(
        ["bash", str(workspace / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT), *mode],
        cwd=workspace, env=environment, capture_output=True, text=True, timeout=30,
    )
    commands = [json.loads(line) for line in trace.read_text().splitlines()]
    return result, commands


@pytest.mark.parametrize("mode", ((), ("--diagnostics",)), ids=("default", "diagnostics"))
def test_broker_deployment_contract_executes_original_unittests_in_both_modes(tmp_path, mode):
    """Both modes really execute all broker cases exactly once before returning."""
    result, commands = _run_broker_release_gate_fixture(tmp_path, mode, False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Ran {BROKER_CASE_COUNT} tests" in result.stderr
    assert result.stderr.rstrip().endswith("OK")
    child = ["python3", "scripts/tests/check_runtime_provider_broker_install_test.py"]
    assert commands.count(child) == 1
    assert commands[:5] == [
        ["python3", "-I", "-S", "scripts/check_build_efficiency_provenance.py"],
        ["python3", "-I", "-S", "scripts/check_release_feature_graph.py"],
        ["python3", "-I", "-S", "-", "Cargo.lock"],
        child,
        ["python3", "-I", "-S", "-", "Cargo.lock"],
    ]
    if mode:
        assert any(command[0] == "cargo" for command in commands)
        assert "release verification complete" in result.stdout
    else:
        assert len(commands) == 5
        assert "diagnostics were not run" in result.stdout


@pytest.mark.parametrize("mode", ((), ("--diagnostics",)), ids=("default", "diagnostics"))
def test_broker_deployment_contract_child_assertion_failure_propagates_in_both_modes(tmp_path, mode):
    """A genuine failing unittest aborts before the lock/diagnostic children."""
    result, commands = _run_broker_release_gate_fixture(tmp_path, mode, True)
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Ran {BROKER_CASE_COUNT + 1} tests" in result.stderr
    assert "genuine broker child assertion failure" in result.stderr
    assert "FAILED (failures=1)" in result.stderr
    assert commands == [
        ["python3", "-I", "-S", "scripts/check_build_efficiency_provenance.py"],
        ["python3", "-I", "-S", "scripts/check_release_feature_graph.py"],
        ["python3", "-I", "-S", "-", "Cargo.lock"],
        ["python3", "scripts/tests/check_runtime_provider_broker_install_test.py"],
    ]
    assert "diagnostics were not run" not in result.stdout
    assert "release verification complete" not in result.stdout


@pytest.mark.parametrize("mode", ((), ("--diagnostics",)), ids=("default", "diagnostics"))
def test_broker_deployment_contract_lock_change_refuses_both_modes(tmp_path, mode):
    """A successful child cannot authorize a changed original lockfile."""
    result, commands = _run_broker_release_gate_fixture(tmp_path, mode, False, mutate_lock=True)
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Ran {BROKER_CASE_COUNT + 1} tests" in result.stderr
    assert "OK" in result.stderr
    assert "workspace Cargo.lock changed during the release gate" in result.stderr
    assert commands == [
        ["python3", "-I", "-S", "scripts/check_build_efficiency_provenance.py"],
        ["python3", "-I", "-S", "scripts/check_release_feature_graph.py"],
        ["python3", "-I", "-S", "-", "Cargo.lock"],
        ["python3", "scripts/tests/check_runtime_provider_broker_install_test.py"],
        ["python3", "-I", "-S", "-", "Cargo.lock"],
    ]
    assert "diagnostics were not run" not in result.stdout
    assert "release verification complete" not in result.stdout


def test_broker_deployment_contract_diagnostics_final_lock_change_refuses(tmp_path):
    """The same original lock-check owner also guards diagnostic completion."""
    result, commands = _run_broker_release_gate_fixture(
        tmp_path, ("--diagnostics",), False, mutate_diagnostics_lock=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Ran {BROKER_CASE_COUNT} tests" in result.stderr
    assert "OK" in result.stderr
    assert "workspace Cargo.lock changed during the release gate" in result.stderr
    assert commands.count(["python3", "scripts/tests/check_runtime_provider_broker_install_test.py"]) == 1
    assert commands.count(["python3", "-I", "-S", "-", "Cargo.lock"]) == 3
    assert ["cargo", "test", "--locked", "-p", "sorafs_chunker", "--all-targets"] in commands
    assert "release verification complete" not in result.stdout


def test_broker_deployment_contract_one_lock_helper_has_both_unconditional_boundaries():
    """One fail-closed comparison owner must serve both original intervals."""
    source = (REPO_ROOT / automation.SORAFS_CLI_RELEASE_GATE_SCRIPT).read_text()
    calls = tuple(re.finditer(r"(?m)^verify_cargo_lock_unchanged$", source))
    assert len(calls) == 2
    assert source.count("verify_cargo_lock_unchanged() {\n") == 1
    broker = source.index("python3 scripts/tests/check_runtime_provider_broker_install_test.py\n")
    optional_return = source.index('if [[ "${diagnostics}" != true ]]; then\n')
    last_child = source.index("cargo test --locked -p sorafs_chunker --all-targets\n")
    completion = source.index('echo "[sorafs-release] release verification complete"\n')
    assert broker < calls[0].start() < optional_return < last_child < calls[1].start() < completion
