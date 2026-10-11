#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="${REPO_ROOT}/ci/check_sorafs_python_native_sdk.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/sorafs-orchestrator-sdk.yml"

bash -n "${RUNNER}"

python3 -I -B - "${RUNNER}" "${WORKFLOW}" <<'PY'
import sys
from pathlib import Path

runner = Path(sys.argv[1]).read_text(encoding="utf-8")
workflow = Path(sys.argv[2]).read_text(encoding="utf-8")

required_runner_tokens = (
    'NATIVE_MANIFEST="${SDK_SESSION}/python-native-abi29.json"',
    'tests/client_hard_cut_contract_test.py',
    'SOURCE_BEFORE_PIN=',
    'SOURCE_BEFORE_ARTIFACT=',
    'tests/account_identity_native_v1_test.py',
    'tests/requests_deadline_test.py',
    'tests/staking_preparation_test.py',
    'tests/validator_staking_test.py',
    'SOURCE_RECEIPT_SEAL=',
    'Python native source qualification may not contain skipped tests',
    'verify_source_delivery',
    'IROHA_PYTHON_TEST_INSTALLED_PACKAGE=1 \\\n"${VENV_PYTHON}" -m pytest',
    'VERIFY_EVIDENCE_ARGS=()',
    'if [[ -n "${SORAFS_PYTHON_SDK_EVIDENCE_DIR:-}" ]]; then',
    '--evidence-dir "${SORAFS_PYTHON_SDK_EVIDENCE_DIR}"',
    '"${VERIFY_EVIDENCE_ARGS[@]}"',
)
for token in required_runner_tokens:
    if token not in runner:
        raise SystemExit(f"Python native evidence runner is missing {token!r}")
if runner.count("--evidence-dir") != 1:
    raise SystemExit("Python native evidence output must have one opt-in binding")
skip_audit = runner.index(
    "SoraFS native Python SDK parity may not contain skipped tests"
)
retention = runner.index("VERIFY_EVIDENCE_ARGS=()")
verification = runner.rindex("  verify \\")
source_skip_audit = runner.index("Python native source qualification may not contain skipped tests")
source_pin = runner.index("SOURCE_BEFORE_PIN=")
build = runner.index("-m maturin build")
if not source_pin < build or not skip_audit < source_skip_audit < retention < verification:
    raise SystemExit(
        "Python native evidence must be retained only by final post-test verification"
    )

evidence_directory = (
    "${{ runner.temp }}/iroha-sorafs-python-native-abi29-evidence"
)
evidence_file = f"{evidence_directory}/python-native-abi29.json"
required_workflow_tokens = (
    f"SORAFS_PYTHON_SDK_EVIDENCE_DIR: {evidence_directory}",
    "name: Upload verified Python ABI-29 evidence",
    evidence_file,
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "if-no-files-found: error",
    "retention-days: 30",
)
for token in required_workflow_tokens:
    if token not in workflow:
        raise SystemExit(f"Python native evidence workflow is missing {token!r}")
upload = workflow.split("name: Upload verified Python ABI-29 evidence", 1)[1]
upload = upload.split("- name: Upload parity evidence", 1)[0]
if "pytest.xml" in upload or "iroha-sorafs-python-sdk" in upload:
    raise SystemExit("Python native evidence upload must contain only the manifest")
PY
