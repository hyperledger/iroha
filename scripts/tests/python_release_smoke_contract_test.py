from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SMOKE = REPO_ROOT / "python/iroha_python/scripts/release_smoke.sh"
WHEEL_VERIFIER = REPO_ROOT / "ci/verify_privacy_python_wheel.py"


def run_wheel_verifier(
    *arguments: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", str(WHEEL_VERIFIER), *arguments],
        cwd=REPO_ROOT if cwd is None else cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_wheel_seal_cli_emits_the_stable_authenticated_file_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve(strict=True)
    wheel = root / "iroha_python-test.whl"
    payload = b"wheel-seal-fixture"
    wheel.write_bytes(payload)

    result = run_wheel_verifier("--seal", str(wheel))

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    fields = result.stdout.rstrip("\n").split(":")
    assert len(fields) == 7
    assert fields[0] == hashlib.sha256(payload).hexdigest()
    assert int(fields[3]) == len(payload)
    assert int(fields[1]) >= 0
    assert int(fields[2]) >= 0
    assert int(fields[4]) >= 0
    assert int(fields[5]) >= 0
    assert int(fields[6], 8) == (wheel.stat().st_mode & 0o7777)


@pytest.mark.parametrize(
    "kind", ["empty", "symlink", "hardlink", "relative", "parent-alias"]
)
def test_wheel_seal_cli_rejects_file_identity_aliases_and_empty_input(
    tmp_path: Path,
    kind: str,
) -> None:
    root = tmp_path.resolve(strict=True)
    source = root / "source.whl"
    source.write_bytes(b"candidate")

    if kind == "empty":
        candidate = root / "empty.whl"
        candidate.write_bytes(b"")
        cwd = REPO_ROOT
    elif kind == "symlink":
        candidate = root / "symlink.whl"
        candidate.symlink_to(source)
        cwd = REPO_ROOT
    elif kind == "hardlink":
        candidate = root / "hardlink.whl"
        try:
            os.link(source, candidate)
        except OSError as error:
            pytest.skip(f"hard links unavailable: {error}")
        cwd = REPO_ROOT
    elif kind == "relative":
        candidate = Path(source.name)
        cwd = root
    else:
        real_parent = root / "real-parent"
        real_parent.mkdir()
        nested = real_parent / "candidate.whl"
        nested.write_bytes(b"candidate")
        alias_parent = root / "parent-alias"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        candidate = alias_parent / nested.name
        cwd = REPO_ROOT

    result = run_wheel_verifier("--seal", str(candidate), cwd=cwd)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("error: ")


def test_release_smoke_authenticates_wheel_native_and_privacy_catalog_in_order() -> (
    None
):
    source = RELEASE_SMOKE.read_text(encoding="utf-8")
    required_markers = (
        "python -m build",
        '--preflight sdk "${SDK_WHEEL}" "${SDK_WHEEL_SEAL}"',
        "release smoke requires an empty pre-existing dist directory",
        "release smoke requires exactly one wheel candidate",
        '--seal "${WHEEL}"',
        '--preflight native "${WHEEL}" "${WHEEL_SEAL}"',
        'pip install "${WHEEL}" "${SDK_WHEEL}" --no-compile',
        '"${SMOKE_TMP_DIR}/venv"',
        '"${PROJECT_ROOT}/python/norito_py/src"',
        '"${PROJECT_ROOT}/python/iroha_torii_client"',
        "assert sdk.PRIVACY_REQUIRED_BRIDGE_ABI_VERSION == 29",
        "assert sdk.privacy_bridge_abi_version() == sdk.PRIVACY_REQUIRED_BRIDGE_ABI_VERSION",
        "assert sdk.is_privacy_native_available() is True",
        "catalog = sdk.privacy_compiled_profile_catalog_v1()",
        "sdk.PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES",
        "python/iroha_python/scripts/run_norito_rpc_smoke.sh",
        "python -m twine check",
        "--dry-run",
    )
    for marker in required_markers:
        assert marker in source

    ordered_markers = (
        "python -m build",
        '--seal "${WHEEL}"',
        '--preflight native "${WHEEL}" "${WHEEL_SEAL}"',
        'pip install "${WHEEL}" "${SDK_WHEEL}" --no-compile',
        "INSTALLED_NATIVE_PATH=",
        "assert sdk.PRIVACY_REQUIRED_BRIDGE_ABI_VERSION == 29",
        "python/iroha_python/scripts/run_norito_rpc_smoke.sh",
        "python -m twine check",
    )
    positions = tuple(source.index(marker) for marker in ordered_markers)
    assert positions == tuple(sorted(positions))
    assert 'ls "${DIST_DIR}"/*.whl' not in source
    assert "head -n 1" not in source
    assert 'SCRIPT_DIR="$(cd -P' in source
    assert 'PROJECT_ROOT="$(cd -P' in source
    assert source.count("ci/verify_privacy_python_wheel.py") == 5


def test_release_smoke_rejects_arguments_before_any_build_or_cleanup() -> None:
    result = subprocess.run(
        ["bash", str(RELEASE_SMOKE), "--legacy-wheel"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "Unknown argument: --legacy-wheel\n"


def test_wheel_verifier_rejects_single_owner_release_invocation(tmp_path: Path) -> None:
    result = run_wheel_verifier(str(tmp_path), "native.whl", "seal", "norito", "torii")
    assert result.returncode != 0
    assert result.stdout == ""
    assert "SDK_WHEEL SDK_SEAL" in result.stderr


def test_wheel_preflight_requires_an_explicit_owner_before_reading_bytes() -> None:
    result = run_wheel_verifier("--preflight", "legacy", "native.whl", "seal")
    assert result.returncode == 1
    assert result.stdout == ""
    assert "explicit native or sdk owner" in result.stderr
