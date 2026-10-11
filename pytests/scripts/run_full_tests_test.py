"""Exercise complete Torii test routing with inert child command recorders."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def workflow(tmp_path: Path):
    """Copy the real shell owner and replace Cargo with an inert recorder."""
    root = tmp_path.resolve()
    scripts, commands = root / "scripts", root / "commands"
    scripts.mkdir()
    commands.mkdir()
    shutil.copyfile(ROOT / "scripts/run_full_tests.sh", scripts / "run_full_tests.sh")
    recorder = commands / "cargo"
    recorder.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with Path(os.environ['TEST_COMMAND_LOG']).open('a') as output:\n"
        "    output.write(json.dumps(args) + '\\n')\n"
        "if args[0] == 'metadata':\n"
        "    print(json.dumps({'packages': [{'id': name, 'name': name} for name in "
        "['iroha_core', 'iroha_torii', 'integration_tests']], 'workspace_members': "
        "['iroha_core', 'iroha_torii', 'integration_tests']}))\n"
        "if args[0] == 'test' and os.environ.get('TEST_FAST_FAILURE') == '1':\n"
        "    if '--workspace' in args or ('-p' in args and args[args.index('-p') + 1] == 'iroha_torii'):\n"
        "        raise SystemExit(37)\n"
    )
    recorder.chmod(0o700)
    (commands / "python3").symlink_to(sys.executable)
    permit = root / "permits"
    permit.mkdir()
    environment = dict(
        os.environ,
        PATH=str(commands) + os.pathsep + os.environ["PATH"],
        TEST_COMMAND_LOG=str(root / "commands.jsonl"),
        IROHA_TEST_NETWORK_PERMIT_DIR=str(permit),
    )
    return root, environment


def invoke(workflow, *arguments: str, failure: bool = False):
    """Run only inert Cargo children and return their ordered argument records."""
    root, environment = workflow
    result = subprocess.run(
        ["/bin/bash", str(root / "scripts/run_full_tests.sh"), *arguments],
        cwd=root, env=dict(environment, TEST_FAST_FAILURE=str(int(failure))),
        text=True, capture_output=True, check=False,
    )
    records = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
    return result, records


@pytest.mark.parametrize("segmented", [False, True])
@pytest.mark.parametrize("threads", [False, True])
def test_full_and_segmented_routes_include_explicit_torii_integrations(
    workflow, segmented: bool, threads: bool,
) -> None:
    """Every complete fast-test route admits the required Torii fixture feature."""
    arguments = (["--segmented-fast"] if segmented else []) + (["--test-threads", "2"] if threads else [])
    result, calls = invoke(workflow, "--nocapture", *arguments)
    assert result.returncode == 0, result.stderr
    builds = [call for call in calls if call[0] == "build"]
    assert builds == [["build", "--locked", "--workspace"]]
    tests = [call for call in calls if call[0] == "test"]
    assert tests[-1] == ["test", "--locked", "-p", "integration_tests", "--", "--nocapture"] + (
        ["--test-threads=2"] if threads else []
    )
    assert "--features" not in tests[-1]
    if segmented:
        assert [call[call.index("-p") + 1] for call in tests[:-1]] == ["iroha_core", "iroha_torii"]
        assert "--features" not in tests[0]
        torii = tests[1]
    else:
        assert len(tests) == 2
        torii = tests[0]
        assert "--workspace" in torii
        assert torii[torii.index("--exclude") + 1] == "integration_tests"
    assert "--features" in torii, "complete Torii test routes must select the required integration fixture owner"
    assert torii[torii.index("--features") + 1] == "iroha_torii/test-fixtures"
    assert "mutation-testing" not in " ".join(torii)
    assert ("--test-threads=2" in torii) is threads


def test_network_only_does_not_enable_torii_fixture_authority(workflow) -> None:
    """The separate real-network phase keeps its original feature selection."""
    result, calls = invoke(workflow, "--only-network")
    assert result.returncode == 0, result.stderr
    assert calls == [
        ["build", "--locked", "--workspace"],
        ["test", "--locked", "-p", "integration_tests"],
    ]


def test_default_route_keeps_empty_integration_arguments_on_stock_bash(workflow) -> None:
    """An empty optional array is valid under stock macOS Bash 3.2 and set -u."""
    result, calls = invoke(workflow)
    assert result.returncode == 0, result.stderr
    assert calls == [
        ["build", "--locked", "--workspace"],
        ["test", "--locked", "--workspace", "--exclude", "integration_tests",
         "--features", "iroha_torii/test-fixtures"],
        ["test", "--locked", "-p", "integration_tests"],
    ]


@pytest.mark.parametrize("segmented", [False, True])
def test_fast_test_failure_preserves_exit_and_stops_network_phase(workflow, segmented: bool) -> None:
    """Fixture selection cannot hide a genuine failed fast-test command."""
    result, calls = invoke(workflow, *(["--segmented-fast"] if segmented else []), failure=True)
    assert result.returncode == 37
    assert not any(call[0] == "test" and "integration_tests" in call and "--workspace" not in call for call in calls)
