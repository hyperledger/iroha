from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    tomllib = None  # type: ignore[assignment]

SDK_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = SDK_ROOT.parent
REPO_ROOT = PYTHON_ROOT.parent
INPUT_PATH = SDK_ROOT / "requirements-ci.in"
LOCK_PATH = SDK_ROOT / "requirements-ci.lock"
LOCAL_PROJECT_NAMES = {"iroha-native", "iroha-norito", "iroha-python", "iroha-torii-client"}
HASH_PATTERN = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)")


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_lines(path: Path) -> Iterable[str]:
    pending: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pending.append(line.removesuffix("\\").rstrip())
        if not line.endswith("\\"):
            yield " ".join(pending)
            pending.clear()
    assert not pending, f"unterminated requirement in {path}"


def _requirements_by_name(path: Path) -> dict[str, Requirement]:
    requirements: dict[str, Requirement] = {}
    for line in _requirement_lines(path):
        requirement = Requirement(line.split()[0])
        requirements[_canonical_name(requirement.name)] = requirement
    return requirements


def _pyproject(path: Path) -> dict[str, Any]:
    assert tomllib is not None
    with path.open("rb") as source:
        return tomllib.load(source)


def _expected_direct_requirements() -> list[Requirement]:
    pyprojects = [
        _pyproject(SDK_ROOT / "pyproject.toml"),
        _pyproject(PYTHON_ROOT / "iroha_native" / "pyproject.toml"),
        _pyproject(PYTHON_ROOT / "iroha_torii_client" / "pyproject.toml"),
        _pyproject(PYTHON_ROOT / "norito_py" / "pyproject.toml"),
    ]
    metadata = [pyproject["project"] for pyproject in pyprojects]
    requirements = [
        Requirement(specification)
        for project in metadata
        for specification in project.get("dependencies", [])
        if _canonical_name(Requirement(specification).name) not in LOCAL_PROJECT_NAMES
    ]
    sdk_dev = metadata[0]["optional-dependencies"]["dev"]
    requirements.extend(
        Requirement(specification)
        for specification in sdk_dev
        if _canonical_name(Requirement(specification).name) == "pytest"
    )
    requirements.extend(
        Requirement(specification)
        for pyproject in pyprojects[:2]
        for specification in pyproject["build-system"]["requires"]
    )
    return requirements


def _exact_version(requirement: Requirement) -> Version:
    specifiers = list(requirement.specifier)
    assert len(specifiers) == 1
    assert specifiers[0].operator == "=="
    return Version(specifiers[0].version)


@pytest.mark.skipif(tomllib is None, reason="project metadata check requires Python 3.11+")
def test_ci_dependency_roots_match_local_project_metadata() -> None:
    input_requirements = _requirements_by_name(INPUT_PATH)
    expected_requirements = _expected_direct_requirements()
    expected_names = {_canonical_name(requirement.name) for requirement in expected_requirements}

    assert set(input_requirements) == expected_names
    for metadata_requirement in expected_requirements:
        name = _canonical_name(metadata_requirement.name)
        version = _exact_version(input_requirements[name])
        assert version in metadata_requirement.specifier


def test_ci_lock_is_exact_and_hash_pinned() -> None:
    input_requirements = _requirements_by_name(INPUT_PATH)
    lock_requirements = _requirements_by_name(LOCK_PATH)

    assert set(input_requirements) <= set(lock_requirements)
    for name, requirement in lock_requirements.items():
        assert _exact_version(requirement)
        logical_line = next(
            line
            for line in _requirement_lines(LOCK_PATH)
            if _canonical_name(Requirement(line.split()[0]).name) == name
        )
        assert HASH_PATTERN.search(logical_line), f"{name} has no SHA-256 artifact hash"
    for name, requirement in input_requirements.items():
        assert _exact_version(requirement) == _exact_version(lock_requirements[name])


def test_ci_uses_checkout_sources_and_blake3_runtime() -> None:
    import blake3
    import iroha_torii_client
    import norito

    origins = {
        "iroha_torii_client": Path(iroha_torii_client.__file__).resolve(strict=True),
        "norito_py": Path(norito.__file__).resolve(strict=True),
    }
    if os.environ.get("IROHA_PYTHON_TEST_INSTALLED_PACKAGE") == "1":
        assert sys.prefix != sys.base_prefix
        environment_root = Path(sys.prefix).resolve(strict=True)
        for source_name, origin in origins.items():
            assert origin.is_relative_to(environment_root)
            assert not origin.is_relative_to(PYTHON_ROOT / source_name)
    else:
        for source_name, origin in origins.items():
            assert origin.is_relative_to(PYTHON_ROOT / source_name)
    assert len(blake3.blake3(b"numeric-v1").digest()) == 32


def test_numeric_workflow_enforces_the_ci_lock() -> None:
    workflow = (REPO_ROOT / ".github/workflows/numeric_v1_sdk.yml").read_text(encoding="utf-8")

    assert "cache-dependency-path: python/iroha_python/requirements-ci.lock" in workflow
    assert "--require-hashes" in workflow
    assert "--only-binary=:all:" in workflow
    assert "PYTHONPATH: src:../norito_py/src:.." in workflow


def test_privacy_gate_enforces_the_ci_lock_and_native_build_policy() -> None:
    workflow = (REPO_ROOT / ".github/workflows/pr_privacy_sdk_guard.yml").read_text(
        encoding="utf-8"
    )
    gate = (REPO_ROOT / "ci/check_privacy_python_sdk.sh").read_text(encoding="utf-8")
    cargo_wrapper = (REPO_ROOT / "ci/privacy_sdk_cargo_wrapper.sh").read_text(encoding="utf-8")
    cargo_lock_helper = (REPO_ROOT / "ci/privacy_sdk_cargo_lockfile.sh").read_text(encoding="utf-8")
    wheel_verifier = (REPO_ROOT / "ci/verify_privacy_python_wheel.py").read_text(encoding="utf-8")
    conftest = (SDK_ROOT / "tests/conftest.py").read_text(encoding="utf-8")
    import_fallback_test = (SDK_ROOT / "tests/package_import_fallback_test.py").read_text(
        encoding="utf-8"
    )
    pyproject_source = (SDK_ROOT.parent / "iroha_native/pyproject.toml").read_text(encoding="utf-8")
    sdk_pyproject_source = (SDK_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'build-backend = "setuptools.build_meta"' in sdk_pyproject_source
    assert '"iroha-native==0.0.1"' in sdk_pyproject_source

    cargo_jobs = {
        "privacy_native_bridge_tests": {
            "consumer": ("cargo test -p connect_norito_bridge privacy_ --lib -- --test-threads=1"),
            "fetch_name": "Prime privacy native Cargo dependencies",
            "install_name": "Install host-qualified privacy SDK Rust toolchain",
            "provision_name": "Provision private privacy SDK Cargo lock",
            "verify_name": "Verify privacy SDK Cargo lock isolation",
            "python_path": None,
            "python_path_count": 0,
        },
        "privacy_jvm_sdk_tests": {
            "consumer": "run: ci/check_privacy_jvm_sdk.sh",
            "fetch_name": "Prime privacy JVM native dependencies",
            "install_name": "Install host-qualified privacy JVM Rust toolchain",
            "provision_name": "Provision private privacy JVM Cargo lock",
            "verify_name": "Verify privacy JVM Cargo lock isolation",
            "python_path": "${{ steps.privacy-jvm-python.outputs.python-path }}",
            "python_path_count": 4,
        },
        "privacy_python_sdk_tests": {
            "consumer": (
                "run: env -u PKG_CONFIG_PATH -u LD_LIBRARY_PATH ci/check_privacy_python_sdk.sh"
            ),
            "fetch_name": "Prime privacy Python SDK Cargo dependencies",
            "install_name": "Install host-qualified privacy SDK Rust toolchain",
            "provision_name": "Provision private privacy SDK Cargo lock",
            "verify_name": "Verify privacy SDK Cargo lock isolation",
            "python_path": "${{ steps.privacy-python.outputs.python-path }}",
            "python_path_count": 3,
        },
        "privacy-sdk-guard": {
            "consumer": (
                "run: env -u PKG_CONFIG_PATH -u LD_LIBRARY_PATH ci/check_privacy_sdk_guard.sh"
            ),
            "fetch_name": "Prime privacy Python SDK Cargo dependencies",
            "install_name": "Install host-qualified privacy SDK Rust toolchain",
            "provision_name": "Provision private privacy SDK Cargo lock",
            "verify_name": "Verify privacy SDK Cargo lock isolation",
            "python_path": "${{ steps.privacy-python.outputs.python-path }}",
            "python_path_count": 5,
        },
    }
    assert workflow.count("ci/privacy_sdk_cargo_lockfile.sh provision-ci") == 4
    assert workflow.count("ci/privacy_sdk_cargo_lockfile.sh verify-ci") == 8
    assert workflow.count("run: cargo fetch --locked") == 4
    assert workflow.count("cargo fetch --locked") == 4
    assert "Swatinem/rust-cache@" not in workflow
    assert workflow.count("id: privacy-python") == 2
    for setup_id, expected_count in {
        "privacy-swift-python": 1,
        "privacy-jvm-python": 4,
        "privacy-csharp-python": 3,
        "privacy-js-python": 2,
        "privacy-python": 8,
    }.items():
        assert workflow.count(f"${{{{ steps.{setup_id}.outputs.python-path }}}}") == expected_count
    assert workflow.count('python-version: "3.12"') == 6
    assert workflow.count("update-environment: false") == 6
    assert "cache: pip" not in workflow
    assert "cache-dependency-path: python/iroha_python/requirements-ci.lock" not in workflow
    for job, policy in cargo_jobs.items():
        match = re.search(
            rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            workflow,
        )
        assert match is not None
        block = match.group(1)
        assert block.count("provision-ci") == 1
        assert block.count("verify-ci") == 2
        assert block.count("run: cargo fetch --locked") == 1
        assert block.count('CARGO_NET_OFFLINE: "false"') == 1
        if policy["python_path"] is not None:
            assert block.count(policy["python_path"]) == policy["python_path_count"]
        positions = [
            block.find(marker)
            for marker in (
                policy["install_name"],
                policy["provision_name"],
                policy["verify_name"],
                policy["fetch_name"],
                'CARGO_NET_OFFLINE: "false"',
                "run: cargo fetch --locked",
                policy["consumer"],
                f"Verify final {policy['verify_name'][7:]}",
            )
        ]
        assert -1 not in positions
        assert positions == sorted(positions)
        assert "if: always()" in block[positions[-1] :]
    for artifact_job in (
        "privacy_javascript_sdk_tests",
        "privacy_swift_sdk_parse",
    ):
        block = re.search(
            rf"(?ms)^  {artifact_job}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            workflow,
        )
        assert block is not None
        source = block.group(1)
        assert source.count("Authenticate canonical privacy graph snapshot") == 1
        assert source.count('fetch --locked --manifest-path "$GITHUB_WORKSPACE/Cargo.toml"') == 1
        assert "fetch --locked --lockfile-path" not in source
        assert source.count('cmp -s "$release_lock" Cargo.lock') == 1
        assert source.count('pathlib.Path("Cargo.lock").read_bytes()') == (
            2 if artifact_job == "privacy_swift_sdk_parse" else 1
        )
        assert "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" in source
        assert "source ci/privacy_sdk_cargo_lockfile.sh" in source
        assert "provision-ci" not in source
    for workflow_path in (
        ".gitignore",
        ".cargo/config",
        ".cargo/config.toml",
        "**/.cargo/config",
        "**/.cargo/config.toml",
        "Cargo.toml",
        "**/Cargo.toml",
        "Cargo.lock",
        "**/Cargo.lock",
        "rust-toolchain",
        "rust-toolchain.toml",
        "**/rust-toolchain",
        "**/rust-toolchain.toml",
        "crates/**",
        "vendor/**",
        "crates/iroha_crypto/**",
        "crates/iroha_data_model/**",
        "crates/iroha_primitives/**",
        "crates/iroha_schema/**",
        "crates/iroha_version/**",
        "crates/iroha_torii_shared/**",
        "crates/norito/**",
        "crates/ivm/**",
        "crates/sorafs_manifest/**",
        "crates/iroha_config/**",
        "crates/iroha_core/**",
        "crates/iroha_zkp_halo2/**",
        "crates/zk_ace_prover/**",
        "crates/sorafs_car/**",
        "crates/sorafs_chunker/**",
        "crates/sorafs_orchestrator/**",
        "ci/verify_privacy_python_wheel.py",
        "python/iroha_python/pyproject.toml",
        "python/iroha_native/pyproject.toml",
        "python/iroha_native/src/**",
        "python/iroha_native/src/**/*.py",
        "python/iroha_native/src/**/*.so",
        "python/iroha_native/src/**/*.dylib",
        "python/iroha_native/src/**/*.pyd",
        "python/iroha_python/iroha_python_rs/build.rs",
        "python/iroha_python/iroha_python_rs/src/**",
        "python/iroha_python/requirements-ci.lock",
        "python/iroha_python/tests/conftest.py",
        "python/iroha_python/tests/package_import_fallback_test.py",
        "python/iroha_python/src/**",
        "python/iroha_python/src/**/*.py",
        "python/iroha_python/src/**/*.so",
        "python/iroha_python/src/**/*.dylib",
        "python/iroha_python/src/**/*.pyd",
        "python/norito_py/**",
        "python/norito_py/pyproject.toml",
        "python/norito_py/src/**/*.py",
        "python/iroha_torii_client/**",
        "python/iroha_torii_client/pyproject.toml",
        "python/iroha_torii_client/**/*.py",
    ):
        assert f'"{workflow_path}"' in workflow

    assert "resolve_python_312_bin" in gate
    assert "requirements-ci.lock" in gate
    assert "--require-hashes" in gate
    assert "--only-binary=:all:" in gate
    assert "--force-reinstall" in gate
    assert not re.search(r"'(?:pytest|requests|urllib3|maturin)[^']*[<>=]", gate)

    for marker in (
        "IROHA_PYTHON_SKIP_RUNTIME_LINK=1",
        'PYO3_PYTHON="${VENV_DIR}/bin/python"',
        "CARGO_BUILD_JOBS=1",
        "CARGO_NET_OFFLINE=true",
        'CARGO_TARGET_DIR="${PRIVATE_CARGO_TARGET_DIR}"',
        "--locked",
        "--offline",
        "--jobs 1",
        '--target-dir "${PRIVATE_CARGO_TARGET_DIR}"',
        "-I -m maturin build",
        '--out "${PRIVATE_WHEEL_DIR}"',
        '"${VENV_DIR}/bin/python" -I -B -m pip',
        "--no-compile",
        "--no-deps",
        "--no-index",
        "resolve_private_wheel",
        "verify_installed_wheel",
        "verify_privacy_python_wheel.py",
        '"${VENV_DIR}/bin/python" -I -B',
        '"${VENV_DIR}/bin/python" -I -B -m pytest -q',
        '"${ROOT_DIR}/python/norito_py/src"',
        '"${ROOT_DIR}/python/iroha_torii_client"',
        "checkout_native_artifact_state",
        "assert_checkout_native_artifacts_unchanged",
        'native_endings = (".so", ".dylib", ".pyd")',
        "path.name.casefold().endswith(native_endings)",
        "native artifact suffix must be lowercase",
        "IROHA_PYTHON_TEST_INSTALLED_PACKAGE=1",
        'PYTHONPATH="${ROOT_DIR}/python/norito_py/src:${ROOT_DIR}/python"',
        "assert_privacy_sdk_inputs_unchanged",
        "PRIVACY_PYTHON_SDK_VENV is forbidden",
        "Python/root overrides require explicit test mode",
        "PRIVACY_PYTHON_SDK_TEST_MODE",
        "PRIVACY_PYTHON_SDK_TEST_VENV",
        "assert_no_python_startup_injection",
        "capture_venv_distribution_names",
        "assert_expected_venv_distributions",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "configure_private_cargo_home",
        "inherited authenticated Cargo home does not match CARGO_HOME",
        "validate_repository_cargo_configuration",
        "IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME",
        "IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_SEAL",
        "IROHA_PRIVACY_AUTHENTICATED_PYO3_PYTHON",
        "IROHA_PRIVACY_AUTHENTICATED_WHEEL_SEAL",
        '"${WHEEL_SEAL}"',
        "preflight_private_wheel",
        '"PIP_"',
        "PIP_CONFIG_FILE=/dev/null",
        "--isolated",
        "--no-cache-dir",
        '"CARGO",',
        'name == "CARGO_INCREMENTAL" and os.environ[name] == "0"',
        'name == "CARGO_ENCODED_RUSTFLAGS" and os.environ[name] == ""',
    ):
        assert marker in gate
    for marker in (
        '"CARGO",',
        "CARGO_NET_OFFLINE=false",
        "privacy SDK CI Cargo selector must be absent before wrapper selection",
        "privacy SDK CI deterministic Cargo environment changed",
    ):
        assert marker in cargo_lock_helper
    for marker in (
        "metadata|rustc|build|check|test|fetch)",
        "--artifact-dir|--artifact-dir=*|--out-dir|--out-dir=*|--root|--root=*",
        "artifact or installation output override",
        "--crate-type|--crate-type=*",
        "Cargo-side compiler output override",
        "incremental policy must remain disabled",
        "encoded rustflags are not authenticated",
        "native Cargo invocation must not inherit the Cargo selector environment",
        "Maturin metadata must select the authenticated Cargo wrapper",
        "Maturin rustc must not inherit the Cargo selector environment",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "requires an authenticated Cargo home",
        "requires an authenticated Cargo config path",
        "requires an authenticated Cargo config seal",
    ):
        assert marker in cargo_wrapper
    for marker in (
        'WheelOwner("iroha_native", "iroha-native", True)',
        'WheelOwner("iroha_python", "iroha-python", False)',
        "pure SDK wheel must not contain a native module",
        "iroha_native._crypto",
        "preflight_wheel",
        'sys.argv[1] == "--preflight"',
        "expected_wheel_seal",
        "_canonical_zip_member_name",
        "_assert_contiguous_local_records",
        "data descriptor does not exactly cover",
        "authenticate_dependency_roots",
        "_capture_dependency_tree",
        "a bytecode or native loader alias",
        "sys.dont_write_bytecode = True",
        "return basename.casefold().endswith(NATIVE_FILE_ENDINGS)",
        "MAX_TOTAL_UNCOMPRESSED_BYTES",
        "DIST_INFO_REQUIRED_FILES",
        "scripts, data roots, or other packages",
        "reject_preseeded_modules",
        "ExtensionFileLoader",
        "loader_state",
        "verify_installed_files",
        "Python.framework",
        "libpython",
        '[str(otool), "-L", str(native_path)]',
    ):
        assert marker in wheel_verifier
    assert "-m maturin develop" not in gate
    for rejected_environment_name in (
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_",
        "CARGO_ALIAS_",
        "CARGO_HTTP_",
        "CARGO_HOST_",
        "CARGO_NET_",
        "CARGO_REGISTRIES_",
        "CARGO_REGISTRY_",
        "CARGO_SOURCE_",
        "CARGO_TARGET_",
        "CARGO_UNSTABLE_",
        "RUSTFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTUP_TOOLCHAIN",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "PYO3_CONFIG_FILE",
        "PYO3_",
        "PYTHON_SYS_EXECUTABLE",
        "PYTHONOPTIMIZE",
        '"PYTHON"',
        "IROHA_PYTHON_RUNTIME_PATH",
        "CARGO_PROFILE_",
    ):
        assert rejected_environment_name in gate

    assert "IROHA_PYTHON_TEST_INSTALLED_PACKAGE" in conftest
    assert "site.getsitepackages()" in conftest
    assert "sysconfig.get_paths()" in conftest
    assert "iroha_native._crypto" in conftest
    assert "PathFinder.find_spec" in conftest
    assert "ExtensionFileLoader" in conftest
    assert "loader_state" in conftest
    assert 'env.get("IROHA_PYTHON_TEST_INSTALLED_PACKAGE") != "1"' in import_fallback_test
    for source_artifact_pattern in (
        '"src/**/*.so"',
        '"src/**/*.dylib"',
        '"src/**/*.pyd"',
    ):
        assert source_artifact_pattern in pyproject_source
