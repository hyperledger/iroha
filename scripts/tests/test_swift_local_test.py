"""Exercise local Swift orchestration and failure controls without building artifacts.

Child commands are mocked; these tests grant no native or Swift qualification.
"""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_swift_local as runner


@pytest.fixture
def recipe(tmp_path):
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    config = {"python": "/tools/python3.12", "clang": "/xcode/clang",
              "ranlib": "/xcode/ranlib", "xcodebuild": "/usr/bin/xcodebuild",
              "developer_dir": "/xcode", "sdk": "/xcode/sdk", "deployment_target": "12.0"}
    return root, root / "target/native-sdk-host-local", config


def intercept_steps(monkeypatch, *, failure=None, during_swift=None):
    calls = []
    failures = {failure} if isinstance(failure, str) else set(failure or [])

    def step(command, *, root, environment, log):
        calls.append((log.name, command, environment))
        if log.name == "swift-test.log":
            assert root.name == "IrohaSwift"
        if log.name in failures:
            raise subprocess.CalledProcessError(23, command)
        if log.name == "native-package.log":
            artifact = Path(command[command.index("--output") + 1])
            artifact.mkdir(mode=0o700)
            (artifact / "producer-record.json").write_text("inert mocked orchestration record")
        if log.name == "swift-test.log" and during_swift:
            during_swift(command, environment)

    monkeypatch.setattr(runner, "run_step", step)
    return calls


def test_full_suite_uses_only_fresh_admitted_artifact_and_rechecks_same_pin(monkeypatch, recipe):
    root, target, config = recipe
    calls = intercept_steps(monkeypatch)
    run = runner.run_suite(root, target, None, config, {"PATH": "/usr/bin:/bin"})
    assert [name for name, _, _ in calls] == ["native-build.log", "native-package.log",
        "verify-before.log", "swift-test.log", "verify-after.log"]
    assert run.is_relative_to(root / "target/qualification")
    assert run.stat().st_mode & 0o777 == 0o700
    build, package, before, swift, after = [command for _, command, _ in calls]
    assert build[:4] == [config["python"], "-E", "-s", "-B"]
    assert build[4].endswith("/scripts/build_native_sdk_host_guarded.py")
    assert build[build.index("--target-dir") + 1] == str(target)
    assert "--jobs" not in build
    assert package[:4] == [config["python"], "-I", "-S", "-B"]
    assert "--acknowledge-local-unit-recipe" in package
    assert before == after
    assert before[before.index("--producer-sha256") + 1] == runner.unit.digest(run / "artifact/producer-record.json")
    assert swift == ["/xcode/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift", "test",
        "--package-path", str(root / "IrohaSwift"), "--configuration", "debug",
        "--disable-automatic-resolution", "--manifest-cache", "none",
        "--scratch-path", str(root / "IrohaSwift/.build")]
    environment = calls[3][2]
    assert environment["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"] == str(run / "artifact")
    assert environment["MOBILE_SDK_PYTHON_BINARY"] == config["python"]
    assert "MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR" not in calls[-1][2]


@pytest.mark.parametrize("failure,expected", [
    ("native-build.log", ["native-build.log"]),
    ("native-package.log", ["native-build.log", "native-package.log"]),
    ("verify-before.log", ["native-build.log", "native-package.log", "verify-before.log"]),
    ("swift-test.log", ["native-build.log", "native-package.log", "verify-before.log",
                        "swift-test.log", "verify-after.log"]),
    ("verify-after.log", ["native-build.log", "native-package.log", "verify-before.log",
                          "swift-test.log", "verify-after.log"]),
])
def test_failure_never_becomes_success_or_starts_unadmitted_tests(monkeypatch, recipe, failure, expected):
    root, target, config = recipe
    calls = intercept_steps(monkeypatch, failure=failure)
    with pytest.raises(subprocess.CalledProcessError) as error:
        runner.run_suite(root, target, 3, config, {})
    assert error.value.returncode == 23
    assert [name for name, _, _ in calls] == expected
    assert calls[0][1][-2:] == ["--jobs", "3"]


def test_test_and_post_verification_failures_are_both_reported(monkeypatch, recipe):
    root, target, config = recipe
    calls = intercept_steps(monkeypatch, failure=["swift-test.log", "verify-after.log"])
    with pytest.raises(RuntimeError, match="Swift tests failed.*post-test custody verification also failed") as error:
        runner.run_suite(root, target, None, config, {})
    assert "swift-test.log" in str(error.value) and "verify-after.log" in str(error.value)
    assert calls[-1][0] == "verify-after.log"


def test_post_test_verification_does_not_repin_mutated_record(monkeypatch, recipe):
    root, target, config = recipe

    def mutate_record(command, environment):
        record = Path(environment["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"]) / "producer-record.json"
        record.write_text("changed during mocked tests")

    calls = intercept_steps(monkeypatch, during_swift=mutate_record)
    run = runner.run_suite(root, target, None, config, {})
    before, after = calls[2][1], calls[4][1]
    assert before == after
    assert after[-1] != runner.unit.digest(run / "artifact/producer-record.json")


def test_repeated_runs_keep_dist_and_warm_swift_and_cargo_outputs(monkeypatch, recipe):
    root, target, config = recipe
    markers = [root / "dist/unchanged", root / "IrohaSwift/.build/unchanged", target / "unchanged"]
    for marker in markers:
        marker.parent.mkdir(parents=True)
        marker.write_bytes(b"retained original")
    calls = intercept_steps(monkeypatch)
    first = runner.run_suite(root, target, None, config, {})
    second = runner.run_suite(root, target, None, config, {})
    assert first != second and first.exists() and second.exists()
    assert all(marker.read_bytes() == b"retained original" for marker in markers)
    assert calls[3][1] == calls[8][1]
    assert calls[3][2]["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"] != calls[8][2]["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR"]


def test_selected_sdk_and_deployment_target_replace_inherited_values_for_every_child(monkeypatch, recipe):
    root, target, config = recipe
    calls = intercept_steps(monkeypatch)
    inherited = {"SDKROOT": "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
                 "MACOSX_DEPLOYMENT_TARGET": "27.0"}
    runner.run_suite(root, target, None, config, inherited)
    assert all(environment["SDKROOT"] == config["sdk"] for _, _, environment in calls)
    assert all(environment["MACOSX_DEPLOYMENT_TARGET"] == config["deployment_target"]
               for _, _, environment in calls)
    assert inherited["SDKROOT"] == "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
    assert inherited["MACOSX_DEPLOYMENT_TARGET"] == "27.0"


@pytest.mark.parametrize("lane", ["outside", "target", "target/qualification/cargo", "relative"])
def test_inappropriate_cargo_lane_is_rejected_before_capture(monkeypatch, recipe, lane):
    root, _, config = recipe
    target = Path("relative") if lane == "relative" else root / lane
    calls = intercept_steps(monkeypatch)
    with pytest.raises(runner.unit.Refused, match="Cargo lane"):
        runner.run_suite(root, target, None, config, {})
    assert calls == []
    assert not (root / "target/qualification").exists()


def test_step_retains_failure_log_and_never_uses_timeout_or_signal(monkeypatch, tmp_path):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        kwargs["stdout"].write(b"actual child diagnostic")
        return subprocess.CompletedProcess(command, 19)

    monkeypatch.setattr(runner.subprocess, "run", run)
    log = tmp_path / "failure.log"
    with pytest.raises(subprocess.CalledProcessError) as error:
        runner.run_step(["child"], root=tmp_path, environment={}, log=log)
    assert error.value.returncode == 19
    assert log.read_bytes() == b"actual child diagnostic"
    assert "timeout" not in calls[0][1] and calls[0][1]["check"] is False
    with pytest.raises(FileExistsError):
        runner.run_step(["child"], root=tmp_path, environment={}, log=log)
    assert len(calls) == 1


@pytest.mark.parametrize("selector", ["MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR",
    "MOBILE_SDK_APPLE_ARTIFACT_DIR", "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT"])
def test_explicit_artifact_or_release_selection_never_falls_back(monkeypatch, selector):
    monkeypatch.setattr(runner.sys, "platform", "darwin")
    monkeypatch.setattr(runner.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runner.sys, "version_info", (3, 12, 0))
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: pytest.fail("must refuse before tools"))
    with pytest.raises(runner.unit.Refused, match="unset artifact/release selectors"):
        runner.selected_tools({selector: "explicit"})


@pytest.mark.parametrize("platform_name,version", [("linux", (3, 12, 0)), ("darwin", (3, 11, 0))])
def test_host_and_interpreter_requirements_fail_before_tools(monkeypatch, platform_name, version):
    monkeypatch.setattr(runner.sys, "platform", platform_name)
    monkeypatch.setattr(runner.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runner.sys, "version_info", version)
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: pytest.fail("must refuse before tools"))
    with pytest.raises(runner.unit.Refused):
        runner.selected_tools({})


def test_xcode_selection_keeps_exact_actual_recipe(monkeypatch, tmp_path):
    developer = tmp_path.resolve() / "Xcode.app/Contents/Developer"
    toolchain = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    sdk = developer / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    toolchain.mkdir(parents=True)
    sdk.mkdir(parents=True)
    (developer / "usr/bin").mkdir(parents=True)
    for path in [*(toolchain / name for name in ("swift", "clang", "ranlib")),
                 developer / "usr/bin/xcodebuild"]:
        path.write_text("inert tool path, never executed")
    monkeypatch.setattr(runner.sys, "platform", "darwin")
    monkeypatch.setattr(runner.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runner.sys, "version_info", (3, 12, 0))
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        selected = developer if command[0] == "/usr/bin/xcode-select" else sdk
        return subprocess.CompletedProcess(command, 0, str(selected) + "\n")

    monkeypatch.setattr(runner.subprocess, "run", run)
    config = runner.selected_tools({"SDKROOT": "/stale/command-line-tools/sdk"})
    assert config == {"python": str(Path(sys.executable).resolve()),
        "clang": str(toolchain / "clang"), "ranlib": str(toolchain / "ranlib"),
        "xcodebuild": "/usr/bin/xcodebuild", "developer_dir": str(developer),
        "sdk": str(sdk), "deployment_target": "12.0"}
    assert calls[1][1]["env"]["DEVELOPER_DIR"] == str(developer)
    assert "SDKROOT" not in calls[1][1]["env"]


@pytest.mark.parametrize("explicit", [False, True])
def test_command_line_tools_requires_explicit_full_xcode_before_sdk_discovery(monkeypatch, tmp_path, explicit):
    developer = tmp_path.resolve() / "CommandLineTools"
    developer.mkdir()
    monkeypatch.setattr(runner.sys, "platform", "darwin")
    monkeypatch.setattr(runner.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runner.sys, "version_info", (3, 12, 0))
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert command == ["/usr/bin/xcode-select", "-p"]
        return subprocess.CompletedProcess(command, 0, str(developer))

    monkeypatch.setattr(runner.subprocess, "run", run)
    environment = {"DEVELOPER_DIR": str(developer)} if explicit else {}
    with pytest.raises(runner.unit.Refused, match="full Xcode is required.*DEVELOPER_DIR or xcode-select"):
        runner.selected_tools(environment)
    assert len(calls) == (0 if explicit else 1)


@pytest.mark.parametrize("option", ["--filter", "--skip", "--skip-build", "--configuration"])
def test_cli_has_no_partial_suite_or_release_escape(option):
    with pytest.raises(SystemExit) as error:
        runner.main([option, "anything"])
    assert error.value.code == 2
