"""Exercise contributor Swift dispatch using inert child command recorders."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def workflow(tmp_path):
    root = tmp_path.resolve()
    scripts, commands = root / "scripts", root / "commands"
    scripts.mkdir()
    commands.mkdir()
    shutil.copyfile(ROOT / "scripts/dev_workflow.sh", scripts / "dev_workflow.sh")
    recorder = """import json, os, sys
from pathlib import Path
with Path(os.environ['TEST_COMMAND_LOG']).open('a') as output:
    output.write(json.dumps({'command': Path(sys.argv[0]).name, 'args': sys.argv[1:],
        'cargo_target_dir': os.environ.get('CARGO_TARGET_DIR')}) + '\\n')
raise SystemExit(int(os.environ.get('TEST_SWIFT_EXIT', '0')) if Path(sys.argv[0]).name == 'python3.12' else 0)
"""
    (scripts / "rust_ci.py").write_text("""import json, os, sys
from pathlib import Path
if sys.argv[1] == 'classify':
    impacted = json.loads(os.environ.get('TEST_IMPACTED_PACKAGES', '[]'))
    Path(sys.argv[sys.argv.index('--json-out') + 1]).write_text(json.dumps({
        'has_rust': bool(impacted), 'impacted_packages': impacted, 'full': False,
        'lanes': [{'name': 'inert test lane', 'packages': impacted}], 'reasons': [],
        'changed_paths': json.loads(os.environ['TEST_CHANGED_PATHS'])}))
    raise SystemExit(0)
""" + recorder)
    for name in ("cargo", "python3.12"):
        executable = commands / name
        executable.write_text(f"#!{sys.executable}\n" + recorder)
        executable.chmod(0o700)
    (commands / "python3").symlink_to(sys.executable)
    environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                       TEST_COMMAND_LOG=str(root / "commands.jsonl"),
                       TEST_CHANGED_PATHS='["IrohaSwift/Sources/changed.swift"]')
    return root, environment


def invoke(workflow, *arguments, **overrides):
    root, environment = workflow
    result = subprocess.run(["/bin/bash", str(root / "scripts/dev_workflow.sh"), *arguments],
                            cwd=root, env=dict(environment, **overrides), text=True,
                            capture_output=True, check=False)
    calls = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
    return result, calls


def test_affected_swift_uses_current_native_runner_without_inherited_rust_target(workflow):
    root, _ = workflow
    result, calls = invoke(workflow, "--target-dir", str(root / "rust-check-lane"))
    assert result.returncode == 0, result.stderr
    assert calls == [
        {"command": "cargo", "args": ["fmt", "--all", "--", "--check"],
         "cargo_target_dir": str(root / "rust-check-lane")},
        {"command": "python3.12", "args": [str(root / "scripts/test_swift_local.py")],
         "cargo_target_dir": None},
    ]


@pytest.mark.parametrize("arguments,changed", [(["--skip-swift"], '["IrohaSwift/changed.swift"]'),
                                              ([], '["docs/unchanged.md"]')])
def test_explicit_skip_and_unaffected_paths_do_not_launch_runner(workflow, arguments, changed):
    result, calls = invoke(workflow, *arguments, TEST_CHANGED_PATHS=changed)
    assert result.returncode == 0, result.stderr
    assert [call["command"] for call in calls] == ["cargo"]


def test_full_workflow_runs_swift_even_without_changed_paths(workflow):
    result, calls = invoke(workflow, "--full", TEST_CHANGED_PATHS="[]")
    assert result.returncode == 0, result.stderr
    assert calls[-1]["command"] == "python3.12"


@pytest.mark.parametrize("skip", [False, True])
def test_native_protocol_reverse_dependency_triggers_swift_unless_explicitly_skipped(workflow, skip):
    arguments = ["--skip-swift"] if skip else []
    result, calls = invoke(workflow, *arguments,
        TEST_CHANGED_PATHS='["crates/iroha_data_model/src/privacy/protocol.rs"]',
        TEST_IMPACTED_PACKAGES='["iroha_data_model", "connect_norito_bridge"]')
    assert result.returncode == 0, result.stderr
    expected = ["cargo", "rust_ci.py"] + ([] if skip else ["python3.12"])
    assert [call["command"] for call in calls] == expected
    assert calls[1]["args"] == ["run", "--packages", "iroha_data_model,connect_norito_bridge",
                                 "--checks", "clippy,build,test"]


@pytest.mark.parametrize("source", ["scripts/test_swift_local.py", "scripts/norito_bridge_local_unit.py",
                                    "scripts/build_native_sdk_host_guarded.py"])
def test_native_prerequisite_owner_changes_trigger_swift_without_package_impact(workflow, source):
    result, calls = invoke(workflow, TEST_CHANGED_PATHS=json.dumps([source]))
    assert result.returncode == 0, result.stderr
    assert calls[-1]["command"] == "python3.12"


def test_unsupported_host_or_runner_failure_is_not_silently_skipped(workflow):
    result, calls = invoke(workflow, TEST_SWIFT_EXIT="17")
    assert result.returncode == 17
    assert calls[-1]["command"] == "python3.12"
