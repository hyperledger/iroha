"""Actual maintained source-pin dispatch controls; no build/native evidence.

The privacy corridor already has an explicitly inert interpreter harness. These
controls exercise that added command only; its sentinel is deliberately not a
production source identity or ABI claim.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
PRIVACY = ROOT / "ci/check_privacy_python_sdk.sh"
HARNESS = ROOT / "ci/privacy_sdk_cargo_lockfile_test.sh"


def dispatch_script() -> str:
    source = HARNESS.read_text()
    start = source.index("  '# BEGIN explicitly inert source-pin dispatch control.'")
    end = source.index("  '# END explicitly inert source-pin dispatch control.'", start)
    lines = source[start:end].splitlines()
    assert all(line.startswith("  '") and line.endswith("' " + chr(92)) for line in lines)
    return "\n".join(line[3:-3] for line in lines) + "\n"


@pytest.fixture
def inert_dispatch(tmp_path):
    helper = tmp_path / "ci/python_native_source_delivery.py"
    helper.parent.mkdir()
    helper.write_bytes((ROOT / "ci/python_native_source_delivery.py").read_bytes())
    venv = tmp_path / "venv"
    interpreter = venv / "bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/bash\nset -euo pipefail\npython_invocation_kind=source-pin\n" + dispatch_script())
    interpreter.chmod(0o700)
    environment = dict(os.environ, PRIVACY_PYTHON_SDK_ROOT=str(tmp_path))
    return tmp_path, helper, venv, interpreter, environment


def run_dispatch(fixture, args, *, phase=None):
    root, helper, venv, interpreter, environment = fixture
    if phase:
        environment = dict(environment, FAKE_SOURCE_PIN_REFUSE_PHASE=phase)
    return subprocess.run([str(interpreter), "-I", "-B", str(helper), *args],
                          capture_output=True, text=True, timeout=10, env=environment)


def test_inert_pin_and_revalidation_have_exact_command_binding_and_no_provenance_claim(inert_dispatch):
    root = str(inert_dispatch[0])
    result = run_dispatch(inert_dispatch, ["pin", "--root", root])
    assert result.returncode == 0, result.stderr
    assert result.stdout == "unqualified-source-pin-dispatch-control\n"
    assert "head_commit" not in result.stdout and "source_tree_clean" not in result.stdout
    result = run_dispatch(inert_dispatch, ["assert-pin", "--root", root, "--source-pin", result.stdout.rstrip()])
    assert result.returncode == 0, result.stderr
    assert not result.stdout


@pytest.mark.parametrize("mutation", ["root", "flag", "extra", "absent", "mode", "pin-binding"])
def test_inert_dispatch_refuses_unsupported_command_before_any_real_owner_execution(inert_dispatch, mutation):
    root = str(inert_dispatch[0])
    args = ["assert-pin", "--root", root, "--source-pin", "unqualified-source-pin-dispatch-control"]
    if mutation == "root": args[2] += "/different"
    elif mutation == "flag": args[1] = "--other-root"
    elif mutation == "extra": args += ["--extra"]
    elif mutation == "absent": args = args[:-2]
    elif mutation == "mode": args[0] = "promote"
    else: args[-1] = '{"head_commit":"synthetic identity is forbidden"}'
    result = run_dispatch(inert_dispatch, args)
    assert result.returncode == 119
    assert not result.stdout


def test_actual_privacy_before_build_refusal_stops_before_original_maturin_dispatch(inert_dispatch):
    root, helper, venv, interpreter, environment = inert_dispatch
    source = PRIVACY.read_text()
    start = source.index('SOURCE_BEFORE_PIN="$(')
    end = source.index('cd "${ROOT_DIR}/python/iroha_native"', start)
    command = source[start:end] + '\nprintf dispatched > "$ROOT_DIR/builder-marker"\n'
    result = subprocess.run(["bash", "-eu", "-c", command], capture_output=True, text=True, timeout=10,
                            env=dict(environment, ROOT_DIR=str(root), SCRIPT_DIR=str(helper.parent),
                                     VENV_DIR=str(venv), FAKE_SOURCE_PIN_REFUSE_PHASE="pin"))
    assert result.returncode == 119
    assert "inert before-build source-pin refusal" in result.stderr
    assert not (root / "builder-marker").exists()


def test_actual_privacy_input_revalidation_returns_failure_for_original_source_refusal(inert_dispatch):
    root, helper, venv, interpreter, environment = inert_dispatch
    source = PRIVACY.read_text()
    start = source.index('  if [[ -n "${SOURCE_BEFORE_PIN}" ]]; then')
    end = source.index("  fi", start) + len("  fi")
    command = "status=0\n" + source[start:end] + "\nexit \"$status\"\n"
    result = subprocess.run(["bash", "-eu", "-c", command], capture_output=True, text=True, timeout=10,
                            env=dict(environment, ROOT_DIR=str(root), SCRIPT_DIR=str(helper.parent),
                                     VENV_DIR=str(venv), SOURCE_BEFORE_PIN="unqualified-source-pin-dispatch-control",
                                     FAKE_SOURCE_PIN_REFUSE_PHASE="assert-pin"))
    assert result.returncode == 1
    assert "inert original-source-pin revalidation refusal" in result.stderr


def test_production_pin_is_unconditional_and_original_privacy_transcript_assertions_are_retained():
    source = PRIVACY.read_text()
    start = source.index('SOURCE_BEFORE_PIN="$(')
    end = source.index('cd "${ROOT_DIR}/python/iroha_native"', start)
    capture = source[start:end]
    assert "TEST_MODE" not in capture and "FAKE_SOURCE" not in capture
    assert '"${SCRIPT_DIR}/python_native_source_delivery.py" pin --root "${ROOT_DIR}"' in capture
    assert source.count('SOURCE_BEFORE_PIN="$(') == 1
    harness = HARNESS.read_text()
    assert '"${PROVISION_HELPER_ROOT}/python_native_source_delivery.py"' in harness
    for assertion in (
        "Python SDK gate call inventory/order drifted", "Maturin Python transcript drifted",
        "pure SDK offline wheel build transcript drifted", "pure SDK preflight transcript drifted",
        "private wheel installation transcript drifted", "installed wheel verification transcript drifted",
        "ABI30 record transcript drifted", "ABI30 verification transcript drifted",
        "installed-package pytest transcript drifted",
    ):
        assert assertion in harness
    assert "source-pin dispatch did not bracket compilation and final cleanup" in harness
    assert "source-pin revalidation omitted original phase" in harness


def test_new_delivery_owners_trigger_both_real_gates_and_controls_precede_native_build():
    owners = ("ci/python_native_source_delivery.py", "scripts/tests/python_native_source_delivery_test.py",
              "scripts/tests/python_source_owner_admission_test.py", "scripts/tests/python_native_delivery_gate_contract_test.py")
    for name in ("sorafs-orchestrator-sdk.yml", "pr_privacy_sdk_guard.yml"):
        workflow = (ROOT / ".github/workflows" / name).read_text()
        paths = workflow.split("paths:", 1)[1].split("workflow_dispatch:", 1)[0]
        for owner in owners:
            assert f'- "{owner}"' in paths
    runner = (ROOT / "ci/check_sorafs_python_native_sdk.sh").read_text()
    build = runner.index("-m maturin build")
    for owner in owners[1:]:
        assert runner.index(owner) < build
    control = runner[runner.index("# These are file/admission controls only;"):runner.index('NATIVE_WHEELS=')]
    assert "if [[" not in control and "FAKE_SOURCE" not in control
    assert 'assert_build_source_unchanged' in control
