#!/usr/bin/env python3
"""Build current native prerequisites and run the complete macOS Debug Swift suite.

Requires Python 3.12, full Xcode (DEVELOPER_DIR or xcode-select), rustup and the
repository's locked dependencies. No artifact selector may already be set. This
local-unit recipe never modifies dist or qualifies release/device artifacts.
Cargo reuses a stable target lane; each run retains create-only evidence and logs
under target/qualification. No child is timed out, killed, or retried on failure.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

import norito_bridge_local_unit as unit


def selected_tools(environment: dict[str, str]) -> dict[str, str]:
    """Select the current interpreter and full Xcode's genuine host tools."""
    unit.require(sys.platform == "darwin" and platform.machine() in unit.TARGETS,
                 "local Swift tests require a supported macOS host")
    unit.require(sys.version_info[:2] == (3, 12), "run this command with Python 3.12")
    selectors = [name for name in ("MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR",
                 "MOBILE_SDK_APPLE_ARTIFACT_DIR", "MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT")
                 if name in environment]
    unit.require(not selectors, "local runner requires unset artifact/release selectors: "
                 + ", ".join(selectors))
    selected = environment.get("DEVELOPER_DIR")
    if selected is None:
        result = subprocess.run(["/usr/bin/xcode-select", "-p"], env=environment,
                                text=True, capture_output=True, check=True)
        selected = result.stdout.strip()
    developer = Path(selected)
    unit.require(developer.is_absolute() and developer.resolve(strict=True) == developer,
                 "selected Xcode developer directory must be absolute and canonical")
    toolchain = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    unit.require(all((toolchain / tool).is_file() for tool in ("swift", "clang", "ranlib"))
                 and (developer / "usr/bin/xcodebuild").is_file(),
                 "full Xcode is required; select its Contents/Developer directory with "
                 "DEVELOPER_DIR or xcode-select (Command Line Tools alone are insufficient)")
    environment = dict(environment, DEVELOPER_DIR=str(developer))
    environment.pop("SDKROOT", None)
    result = subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                            env=environment, text=True, capture_output=True, check=True)
    config = {"python": str(Path(sys.executable).resolve(strict=True)),
              "clang": str(toolchain / "clang"), "ranlib": str(toolchain / "ranlib"),
              "xcodebuild": "/usr/bin/xcodebuild", "developer_dir": str(developer),
              "sdk": str(Path(result.stdout.strip()).resolve(strict=True)),
              "deployment_target": "12.0"}
    unit.validate_tool_config(config)
    return config


def run_step(command: list[str], *, root: Path, environment: dict[str, str], log: Path):
    """Retain a child's diagnostics and propagate its natural failure."""
    print(f"{log.stem}: {log}", flush=True)
    with log.open("xb") as output:
        result = subprocess.run(command, cwd=root, env=environment, stdout=output,
                                stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)


def run_suite(root: Path, target: Path, jobs: int | None, config: dict[str, str],
              environment: dict[str, str]) -> Path:
    """Build, independently package/admit, test, and verify custody again."""
    unit.source_custody.original_directory(root)
    unit.require(target.is_absolute() and target.resolve() == target
                 and target != root / "target" and target.is_relative_to(root / "target")
                 and not target.is_relative_to(root / "target/qualification"),
                 "Cargo lane must be a canonical child of target, outside qualification")
    qualification = root / "target/qualification"
    for directory in (root / "target", qualification):
        directory.mkdir(mode=0o700, exist_ok=True)
        unit.source_custody.original_directory(directory)
    run = Path(tempfile.mkdtemp(prefix="swift-local-", dir=qualification))
    print(f"Local Swift artifacts and logs: {run}", flush=True)
    capture, artifact = run / "capture", run / "artifact"
    temporary = run / "temporary"
    temporary.mkdir(mode=0o700)
    config_path = run / "native-tools.json"
    unit.save(config_path, config)
    environment = dict(environment, DEVELOPER_DIR=config["developer_dir"],
                       SDKROOT=config["sdk"], MACOSX_DEPLOYMENT_TARGET=config["deployment_target"],
                       TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1")
    python = [config["python"], "-I", "-S", "-B"]
    # The emitter imports its repository siblings through the script directory.
    build = [config["python"], "-E", "-s", "-B", str(root / "scripts/build_native_sdk_host_guarded.py"),
             "--root", str(root), "--output", str(capture), "--target-dir", str(target)]
    if jobs is not None:
        build += ["--jobs", str(jobs)]
    run_step(build, root=root, environment=environment, log=run / "native-build.log")
    producer = [*python, str(root / "scripts/norito_bridge_local_unit.py")]
    run_step([*producer, "produce", "--root", str(root), "--pins", str(capture / "pins.json"),
              "--output", str(artifact), "--config", str(config_path),
              "--acknowledge-local-unit-recipe"], root=root, environment=environment,
             log=run / "native-package.log")
    verify = [*producer, "verify", "--root", str(root), "--output", str(artifact),
              "--producer-sha256", unit.digest(artifact / "producer-record.json")]
    run_step(verify, root=root, environment=environment, log=run / "verify-before.log")
    swift_environment = dict(environment, MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR=str(artifact),
                             MOBILE_SDK_PYTHON_BINARY=config["python"])
    swift = str(Path(config["developer_dir"]) / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swift")
    test_failure = None
    try:
        run_step([swift, "test", "--package-path", str(root / "IrohaSwift"),
                  "--configuration", "debug", "--disable-automatic-resolution",
                  "--manifest-cache", "none", "--scratch-path", str(root / "IrohaSwift/.build")],
                 root=root / "IrohaSwift", environment=swift_environment, log=run / "swift-test.log")
    except (subprocess.CalledProcessError, OSError) as error:
        test_failure = error
    try:
        run_step(verify, root=root, environment=environment, log=run / "verify-after.log")
    except (subprocess.CalledProcessError, OSError) as error:
        if test_failure is not None:
            raise RuntimeError(f"Swift tests failed ({test_failure}); post-test custody verification "
                               f"also failed ({error}). See {run / 'swift-test.log'} and "
                               f"{run / 'verify-after.log'}") from error
        raise
    if test_failure is not None:
        raise test_failure
    print(f"Complete local Swift suite passed; evidence retained at {run}", flush=True)
    return run


def main(argv=None) -> int:
    """Expose only the local build lane and job budget, never test skipping."""
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=root / "target/native-sdk-host-local",
                        help="stable canonical Cargo lane below this checkout's target directory")
    parser.add_argument("--jobs", type=int, choices=range(1, 9),
                        help="explicit Cargo override; defaults to the native jobserver")
    args = parser.parse_args(argv)
    try:
        environment = os.environ.copy()
        config = selected_tools(environment)
        run_suite(root, args.target_dir, args.jobs, config, environment)
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Local Swift run failed: {error}. Retained logs are listed above.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
