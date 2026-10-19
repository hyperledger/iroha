#!/usr/bin/env bash
set -euo pipefail

# Python 3.12, authenticated Rust tools and a clean committed release source are
# required. Optional developer evidence retention names a fresh private child of
# ROOT/target/qualification; it never bypasses release or installed-wheel checks.
EVIDENCE_OUTPUT="${PRIVACY_PYTHON_SDK_EVIDENCE_DIR:-}"

ROOT_OVERRIDE="${PRIVACY_PYTHON_SDK_ROOT:-}"
ROOT_DIR="${ROOT_OVERRIDE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PYTHON_OVERRIDE="${PRIVACY_PYTHON_SDK_PYTHON_BIN:-}"
LEGACY_VENV_OVERRIDE="${PRIVACY_PYTHON_SDK_VENV:-}"
TEST_MODE="${PRIVACY_PYTHON_SDK_TEST_MODE:-0}"
TEST_VENV_OVERRIDE="${PRIVACY_PYTHON_SDK_TEST_VENV:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIREMENTS_LOCKFILE="${ROOT_DIR}/python/iroha_python/requirements-ci.lock"
CHECKOUT_NATIVE_DIR="${ROOT_DIR}/python"
ABI31_CHECKER="${ROOT_DIR}/scripts/check_native_sdk_artifact.py"
WHEEL_PATH=""
WHEEL_SEAL=""
SDK_WHEEL_PATH=""
SDK_WHEEL_SEAL=""
TEMPORARY_WORKSPACE_LOCK=0

export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1

resolve_python_312_bin() {
  if [[ -n "${PYTHON_OVERRIDE}" ]]; then
    printf '%s\n' "${PYTHON_OVERRIDE}"
    return 0
  fi
  if [[ -n "${IROHA_PRIVACY_LOCKFILE_PYTHON_BIN:-}" ]]; then
    printf '%s\n' "${IROHA_PRIVACY_LOCKFILE_PYTHON_BIN}"
    return 0
  fi

  local candidate
  for candidate in \
    python3.12 \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/opt/python@3.12/bin/python3.12 \
    /usr/local/bin/python3.12 \
    /usr/local/opt/python@3.12/bin/python3.12 \
    python3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      command -v "${candidate}"
      return 0
    fi
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  printf '%s\n' "python3"
}

reject_ambient_native_build_environment() {
  "${PYTHON_BIN}" -I - <<'PY'
import os

exact_names = {
    "CARGO",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTDOC",
    "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
    "AR",
    "CC",
    "CFLAGS",
    "CPATH",
    "CPPFLAGS",
    "CXX",
    "CXXFLAGS",
    "LD",
    "LD_LIBRARY_PATH",
    "LDFLAGS",
    "LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "RANLIB",
    "SDKROOT",
    "IROHA_PYTHON_RUNTIME_PATH",
    "IROHA_PYTHON_SKIP_RUNTIME_LINK",
    "PYO3_CONFIG_FILE",
    "PYO3_BUILD_EXTENSION_MODULE",
    "PYO3_ENVIRONMENT_SIGNATURE",
    "PYO3_PYTHON",
    "PYTHON",
    "PYTHONOPTIMIZE",
    "PYTHON_SYS_EXECUTABLE",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "IROHA_PRIVACY_AUTHENTICATED_PYTHON_BUILD_POLICY",
    "IROHA_PRIVACY_AUTHENTICATED_PYO3_PYTHON",
    "IROHA_PRIVACY_AUTHENTICATED_MATURIN_VERSION",
    "IROHA_PRIVACY_AUTHENTICATED_MATURIN_PYO3_CONFIG_PATH",
    "IROHA_PRIVACY_AUTHENTICATED_MATURIN_ENCODED_RUSTFLAGS",
    "IROHA_PRIVACY_AUTHENTICATED_MATURIN_RUSTC_LINK_ARG",
    "IROHA_PRIVACY_AUTHENTICATED_MACOSX_DEPLOYMENT_TARGET",
}
prefixes = (
    "CARGO_ALIAS_",
    "CARGO_BUILD_",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTDOC",
    "CARGO_HTTP_",
    "CARGO_HOST_",
    "CARGO_NET_",
    "CARGO_PROFILE_",
    "CARGO_REGISTRIES_",
    "CARGO_REGISTRY_",
    "CARGO_SOURCE_",
    "CARGO_TARGET_",
    "CARGO_UNSTABLE_",
    "PIP_",
    "DYLD_",
    "PKG_CONFIG_",
    "PYO3_",
    "RUSTUP_",
)
forbidden = sorted(
    name
    for name in os.environ
    if (
        name in exact_names
        or any(name.startswith(prefix) for prefix in prefixes)
    )
    and not (
        (
            name == "CARGO_BUILD_JOBS"
            and os.environ[name] == "1"
        )
        or (
            name == "CARGO_NET_OFFLINE"
            and os.environ[name] == "true"
        )
        or (
            name == "CARGO_TARGET_DIR"
            and os.environ[name]
            == os.environ.get("IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR")
        )
        or (name == "CARGO_INCREMENTAL" and os.environ[name] == "0")
        or (name == "CARGO_ENCODED_RUSTFLAGS" and os.environ[name] == "")
    )
)
if forbidden:
    raise SystemExit(
        "error: privacy Python SDK build rejects ambient native-build "
        f"environment variables: {', '.join(forbidden)}"
    )
PY
}

checkout_native_artifact_state() {
  "${PYTHON_BIN}" -I - "${CHECKOUT_NATIVE_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
try:
    canonical_root = root.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: checkout Python source directory is unavailable: {error}")
if canonical_root != root or not canonical_root.is_dir():
    raise SystemExit(
        "error: checkout Python source directory must be a canonical real directory"
    )

native_endings = (".so", ".dylib", ".pyd")
paths = sorted(
    {
        path
        for path in canonical_root.rglob("*")
        if path.name.casefold().endswith(native_endings)
    },
    key=lambda path: path.relative_to(canonical_root).as_posix(),
)
records = []
for path in paths:
    relative = path.relative_to(canonical_root).as_posix()
    if not path.name.endswith(native_endings):
        raise SystemExit(
            "error: checkout Python native artifact suffix must be lowercase: "
            f"{relative}"
        )
    if path.is_symlink():
        raise SystemExit(
            f"error: checkout Python native artifact must not be a symlink: {relative}"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(
            f"error: unable to seal checkout Python native artifact {relative}: {error}"
        )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(
                f"error: checkout Python native artifact is not regular: {relative}"
            )
        if before.st_nlink != 1:
            raise SystemExit(
                f"error: checkout Python native artifact must be singly linked: {relative}"
            )
        digest = hashlib.sha256()
        observed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    stable_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    path_state = os.stat(path, follow_symlinks=False)
    if (
        stable_before != stable_after
        or observed != before.st_size
        or (path_state.st_dev, path_state.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise SystemExit(
            f"error: checkout Python native artifact changed while sealed: {relative}"
        )
    records.append(
        {
            "path": relative,
            "sha256": digest.hexdigest(),
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": before.st_mode,
            "links": before.st_nlink,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
        }
    )
print(json.dumps(records, sort_keys=True, separators=(",", ":")))
PY
}

privacy_python_sdk_file_seal() {
  local path="$1"
  "${PYTHON_BIN}" -I - "${path}" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

MAX_BYTES = 512 * 1024 * 1024
path = Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as error:
    raise SystemExit(f"error: unable to seal private wheel {path}: {error}")
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("error: private wheel must be a singly linked regular file")
    if before.st_size <= 0 or before.st_size > MAX_BYTES:
        raise SystemExit(
            f"error: private wheel must be non-empty and no larger than {MAX_BYTES} bytes"
        )
    digest = hashlib.sha256()
    observed = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        observed += len(chunk)
        digest.update(chunk)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
stable_before = (
    before.st_dev,
    before.st_ino,
    before.st_mode,
    before.st_nlink,
    before.st_size,
    before.st_mtime_ns,
    before.st_ctime_ns,
)
stable_after = (
    after.st_dev,
    after.st_ino,
    after.st_mode,
    after.st_nlink,
    after.st_size,
    after.st_mtime_ns,
    after.st_ctime_ns,
)
path_state = os.stat(path, follow_symlinks=False)
if (
    stable_before != stable_after
    or observed != before.st_size
    or (path_state.st_dev, path_state.st_ino) != (before.st_dev, before.st_ino)
):
    raise SystemExit("error: private wheel changed while it was sealed")
print(
    ":".join(
        (
            digest.hexdigest(),
            str(before.st_dev),
            str(before.st_ino),
            str(before.st_size),
            str(before.st_mtime_ns),
            str(before.st_ctime_ns),
            oct(stat.S_IMODE(before.st_mode)),
        )
    )
)
PY
}

resolve_private_wheel() {
  "${PYTHON_BIN}" -I - "$1" <<'PY'
import os
import stat
import sys
from pathlib import Path

wheel_directory = Path(sys.argv[1])
if wheel_directory.resolve(strict=True) != wheel_directory:
    raise SystemExit("error: private wheel directory must be canonical")
entries = list(wheel_directory.iterdir())
if len(entries) != 1 or entries[0].suffix != ".whl":
    raise SystemExit("error: maturin must produce exactly one fresh private wheel")
wheel = entries[0]
if wheel.is_symlink():
    raise SystemExit("error: private wheel must not be a symbolic link")
metadata = os.stat(wheel, follow_symlinks=False)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("error: private wheel must be a singly linked regular file")
print(wheel)
PY
}

canonical_existing_venv() {
  "${PYTHON_BIN}" -I - "$1" <<'PY'
import os
import sys
from pathlib import Path

argument = Path(sys.argv[1])
if not argument.is_absolute() or argument != Path(os.path.abspath(argument)):
    raise SystemExit("error: privacy Python SDK venv path must be absolute and normalized")
try:
    resolved = argument.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: privacy Python SDK venv is unavailable: {error}")
if resolved != argument or not resolved.is_dir():
    raise SystemExit("error: privacy Python SDK venv must be a canonical real directory")
print(resolved)
PY
}

assert_no_python_startup_injection() {
  "${PYTHON_BIN}" -I - "${VENV_DIR}" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
try:
    canonical_root = root.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: privacy Python SDK venv is unavailable: {error}")
if canonical_root != root or not canonical_root.is_dir():
    raise SystemExit("error: privacy Python SDK venv must remain a canonical directory")

for path in canonical_root.rglob("*"):
    lowered = path.name.lower()
    if (
        lowered.endswith(".pth")
        or lowered in {"sitecustomize", "usercustomize"}
        or lowered.startswith("sitecustomize.")
        or lowered.startswith("usercustomize.")
    ):
        raise SystemExit(
            "error: privacy Python SDK venv contains forbidden Python startup "
            f"injection: {path.relative_to(canonical_root)}"
        )
PY
}

capture_venv_distribution_names() {
  "${PYTHON_BIN}" -I - "${VENV_DIR}" <<'PY'
import importlib.metadata
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
site_roots = sorted(
    path.resolve(strict=True)
    for path in root.rglob("site-packages")
    if path.is_dir() and not path.is_symlink()
)
if not site_roots:
    raise SystemExit("error: privacy Python SDK venv has no site-packages directory")


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


names = []
for distribution in importlib.metadata.distributions(path=[str(path) for path in site_roots]):
    name = distribution.metadata.get("Name")
    if not name:
        raise SystemExit("error: installed distribution is missing its canonical Name")
    names.append(canonical(name))
if len(names) != len(set(names)):
    raise SystemExit("error: privacy Python SDK venv contains duplicate distributions")
print(json.dumps(sorted(names), separators=(",", ":")))
PY
}

assert_expected_venv_distributions() {
  local include_sdk="$1"
  "${PYTHON_BIN}" -I - \
    "${VENV_DIR}" \
    "${REQUIREMENTS_LOCKFILE}" \
    "${BOOTSTRAP_VENV_DISTRIBUTIONS}" \
    "${include_sdk}" <<'PY'
import importlib.metadata
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
requirements = Path(sys.argv[2]).read_text(encoding="utf-8")
baseline = set(json.loads(sys.argv[3]))
include_sdk = sys.argv[4] == "1"


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


locked = {
    canonical(match.group(1))
    for match in re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==", requirements)
}
if not locked:
    raise SystemExit("error: requirements lock contains no pinned distributions")
expected = baseline | locked
if include_sdk:
    expected.update(("iroha-native", "iroha-python"))

site_roots = sorted(
    path.resolve(strict=True)
    for path in root.rglob("site-packages")
    if path.is_dir() and not path.is_symlink()
)
observed_list = []
for distribution in importlib.metadata.distributions(path=[str(path) for path in site_roots]):
    name = distribution.metadata.get("Name")
    if not name:
        raise SystemExit("error: installed distribution is missing its canonical Name")
    observed_list.append(canonical(name))
if len(observed_list) != len(set(observed_list)):
    raise SystemExit("error: privacy Python SDK venv contains duplicate distributions")
observed = set(observed_list)
if observed != expected:
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    raise SystemExit(
        "error: privacy Python SDK venv distribution set is not lock-complete; "
        f"missing={missing}, extra={extra}"
    )
PY
}

validate_repository_cargo_configuration() {
  "${PYTHON_BIN}" -I - "${ROOT_DIR}" \
    "${ROOT_DIR}/python/iroha_native" <<'PY'
import os
import stat
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
project = Path(sys.argv[2]).resolve(strict=True)
allowed_path = root / ".cargo/config.toml"
allowed_configuration = {
    "alias": {
        "xtask": "run --package xtask --features dev-tools --bin xtask --",
    },
}

directory = project
while True:
    cargo_directory = directory / ".cargo"
    candidates = (cargo_directory / "config", cargo_directory / "config.toml")
    present = [path for path in candidates if path.exists() or path.is_symlink()]
    if len(present) > 1:
        raise SystemExit(
            f"error: multiple Cargo configuration files are active in {cargo_directory}"
        )
    if present:
        path = present[0]
        try:
            canonical = path.resolve(strict=True)
        except OSError as error:
            raise SystemExit(f"error: Cargo configuration is unavailable: {error}")
        metadata = os.stat(path, follow_symlinks=False)
        if (
            path.is_symlink()
            or canonical != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise SystemExit(
                f"error: active Cargo configuration must be canonical and singly linked: {path}"
            )
        if path != allowed_path:
            raise SystemExit(f"error: untrusted ancestor Cargo configuration is active: {path}")
        try:
            configuration = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise SystemExit(f"error: unable to parse repository Cargo configuration: {error}")
        if configuration != allowed_configuration:
            raise SystemExit(
                "error: repository Cargo configuration may only define the "
                "approved xtask alias and must not impose global parallelism"
            )
    if directory.parent == directory:
        break
    directory = directory.parent
PY
}

configure_private_cargo_home() {
  local ambient_cargo_home authenticated_cargo_home
  local private_cargo_home private_cache_root component source_component
  ambient_cargo_home="${CARGO_HOME:-}"
  authenticated_cargo_home="${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME:-}"
  if [[ -n "${authenticated_cargo_home}" ]]; then
    if [[ "${ambient_cargo_home}" != "${authenticated_cargo_home}" ]]; then
      echo "error: inherited authenticated Cargo home does not match CARGO_HOME" >&2
      exit 1
    fi
    CARGO_HOME="$(
      "${PYTHON_BIN}" -I - "${authenticated_cargo_home}" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute() or path != Path(os.path.abspath(path)):
    raise SystemExit("error: authenticated Cargo home must be absolute and normalized")
try:
    resolved = path.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: authenticated Cargo home is unavailable: {error}")
if resolved != path or path.is_symlink() or not path.is_dir():
    raise SystemExit("error: authenticated Cargo home must be a canonical real directory")
for filename in ("config", "config.toml"):
    candidate = path / filename
    if os.path.lexists(candidate):
        raise SystemExit(
            "error: authenticated Cargo home must not contain Cargo configuration"
        )
for component_name in ("registry", "git"):
    component = path / component_name
    if os.path.lexists(component):
        try:
            target = component.resolve(strict=True)
        except OSError as error:
            raise SystemExit(
                f"error: authenticated Cargo cache component is unavailable: {error}"
            )
        if not target.is_dir():
            raise SystemExit(
                "error: authenticated Cargo cache component must resolve to a directory"
            )
print(path)
PY
    )"
    export CARGO_HOME
    privacy_sdk_assert_cargo_cache_component_state \
      "${CARGO_HOME}" registry \
      "${IROHA_PRIVACY_AUTHENTICATED_CARGO_REGISTRY_LINK_STATE:-}" \
      "${PYTHON_BIN}"
    privacy_sdk_assert_cargo_cache_component_state \
      "${CARGO_HOME}" git \
      "${IROHA_PRIVACY_AUTHENTICATED_CARGO_GIT_LINK_STATE:-}" \
      "${PYTHON_BIN}"
    return 0
  fi
  if [[ -z "${ambient_cargo_home}" ]]; then
    ambient_cargo_home="$(
      "${PYTHON_BIN}" -I - <<'PY'
from pathlib import Path

print(Path.home() / ".cargo")
PY
    )"
  fi
  ambient_cargo_home="$(
    "${PYTHON_BIN}" -I - "${ambient_cargo_home}" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute() or path != Path(os.path.abspath(path)):
    raise SystemExit("error: Cargo cache home must be absolute and normalized")
if path.exists():
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_dir():
        raise SystemExit("error: Cargo cache home must be a canonical real directory")
print(path)
PY
  )"

  private_cargo_home="${PRIVATE_CARGO_WRAPPER_DIR}/cargo-home"
  mkdir -m 700 "${private_cargo_home}"
  private_cache_root="${PRIVATE_CARGO_WRAPPER_DIR}/cargo-cache"
  mkdir -m 700 "${private_cache_root}"
  for component in registry git; do
    source_component="${ambient_cargo_home}/${component}"
    if [[ -e "${source_component}" || -L "${source_component}" ]]; then
      if [[ ! -d "${source_component}" || -L "${source_component}" ]]; then
        echo "error: Cargo cache component must be a real directory: ${source_component}" >&2
        exit 1
      fi
      ln -s "${source_component}" "${private_cargo_home}/${component}"
    else
      mkdir -m 700 "${private_cache_root}/${component}"
      ln -s "${private_cache_root}/${component}" \
        "${private_cargo_home}/${component}"
    fi
  done
  export CARGO_HOME="${private_cargo_home}"
}

create_venv() {
  if [[ -e "${VENV_DIR}" || -L "${VENV_DIR}" ]]; then
    echo "error: refusing to create a privacy Python SDK venv over an existing path" >&2
    exit 1
  fi
  "${PYTHON_BIN}" -I -m venv "${VENV_DIR}"
  VENV_DIR="$(canonical_existing_venv "${VENV_DIR}")"
}

verify_installed_wheel() {
  "${VENV_DIR}/bin/python" -I -B \
    "${SCRIPT_DIR}/verify_privacy_python_wheel.py" \
    "${VENV_DIR}" \
    "${WHEEL_PATH}" \
    "${WHEEL_SEAL}" \
    "${ROOT_DIR}/python/norito_py/src" \
    "${ROOT_DIR}/python/iroha_torii_client" \
    "${SDK_WHEEL_PATH}" \
    "${SDK_WHEEL_SEAL}"
}

preflight_private_wheel() {
  "${VENV_DIR}/bin/python" -I -B \
    "${SCRIPT_DIR}/verify_privacy_python_wheel.py" \
    --preflight "$1" "$2" "$3"
}

if [[ -n "${LEGACY_VENV_OVERRIDE}" ]]; then
  echo "error: PRIVACY_PYTHON_SDK_VENV is forbidden; production always uses a fresh private venv" >&2
  exit 1
fi
case "${TEST_MODE}" in
  0)
    if [[ -n "${TEST_VENV_OVERRIDE}" ]]; then
      echo "error: PRIVACY_PYTHON_SDK_TEST_VENV requires explicit test mode" >&2
      exit 1
    fi
    if [[ -n "${PYTHON_OVERRIDE}" || -n "${ROOT_OVERRIDE}" ]]; then
      echo "error: privacy Python SDK Python/root overrides require explicit test mode" >&2
      exit 1
    fi
    ;;
  1)
    if [[ -z "${TEST_VENV_OVERRIDE}" || -z "${PYTHON_OVERRIDE}" || -z "${ROOT_OVERRIDE}" ]]; then
      echo "error: privacy Python SDK test mode requires explicit venv, Python, and root overrides" >&2
      exit 1
    fi
    ;;
  *)
    echo "error: PRIVACY_PYTHON_SDK_TEST_MODE must be 0 or 1" >&2
    exit 1
    ;;
esac
PYTHON_BIN="$(resolve_python_312_bin)"
PYTHON_VERSION="$("${PYTHON_BIN}" -I -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
"${PYTHON_BIN}" -I --version
case "${PYTHON_VERSION}" in
  3.12) ;;
  *)
    echo "error: privacy Python SDK tests require Python 3.12; got ${PYTHON_VERSION}" >&2
    exit 1
    ;;
esac
reject_ambient_native_build_environment
unset \
  PYTHONBREAKPOINT \
  PYTHONCASEOK \
  PYTHONHOME \
  PYTHONINSPECT \
  PYTHONOPTIMIZE \
  PYTHONPATH \
  PYTHONSTARTUP \
  PYTHONUSERBASE \
  PYTHONWARNINGS
unset PYTEST_ADDOPTS PYTEST_PLUGINS
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
"${PYTHON_BIN}" -I -B \
  "${ROOT_DIR}/scripts/check_privacy_python_witness_boundary.py" \
  --root "${ROOT_DIR}"
validate_repository_cargo_configuration

# Maturin may invoke Cargo for both metadata and compilation. Route every such
# invocation through a wrapper that pins Cargo's explicitly selected lockfile;
# `--locked` by itself would still select and potentially rewrite the workspace
# Cargo.lock.
# shellcheck source=ci/privacy_sdk_cargo_lockfile.sh
source "${SCRIPT_DIR}/privacy_sdk_cargo_lockfile.sh"
privacy_sdk_assert_ci_cargo_lock_state "${ROOT_DIR}" "${PYTHON_BIN}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH:?privacy Python SDK gate requires an authenticated Rust toolchain path}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL:?privacy Python SDK gate requires an authenticated Rust toolchain seal}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR:?privacy Python SDK gate requires an authenticated Rust toolchain selector}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTUP_PATH:?privacy Python SDK gate requires an authenticated rustup path}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTUP_SEAL:?privacy Python SDK gate requires an authenticated rustup seal}"
: "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH:?privacy Python SDK gate requires an authenticated Cargo path}"
: "${IROHA_PRIVACY_AUTHENTICATED_CARGO_SEAL:?privacy Python SDK gate requires an authenticated Cargo seal}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH:?privacy Python SDK gate requires an authenticated rustc path}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_SEAL:?privacy Python SDK gate requires an authenticated rustc seal}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH:?privacy Python SDK gate requires an authenticated rustdoc path}"
: "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_SEAL:?privacy Python SDK gate requires an authenticated rustdoc seal}"
privacy_sdk_assert_authenticated_toolchain_state \
  "${ROOT_DIR}" "${ROOT_DIR}" "${PYTHON_BIN}"
privacy_sdk_assert_authenticated_toolchain_state \
  "${ROOT_DIR}" "${ROOT_DIR}/python/iroha_python" "${PYTHON_BIN}"
privacy_sdk_assert_authenticated_toolchain_state \
  "${ROOT_DIR}" "${ROOT_DIR}/python/iroha_native" "${PYTHON_BIN}"
SELECTED_CARGO_LOCKFILE="$(
  privacy_sdk_resolve_cargo_lockfile "${ROOT_DIR}" "${PYTHON_BIN}"
)"
export IROHA_PRIVACY_CARGO_LOCKFILE_PATH="${SELECTED_CARGO_LOCKFILE}"
export IROHA_JS_CARGO_LOCKFILE_PATH="${ROOT_DIR}/Cargo.lock"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_PATH="${SELECTED_CARGO_LOCKFILE}"
export IROHA_PRIVACY_SDK_ROOT="${ROOT_DIR}"
export IROHA_PRIVACY_LOCKFILE_PYTHON_BIN="${PYTHON_BIN}"

WORKSPACE_CARGO_LOCKFILE="${ROOT_DIR}/Cargo.lock"
WORKSPACE_CARGO_LOCK_STATE="$(
  privacy_sdk_capture_optional_file_state \
    "${WORKSPACE_CARGO_LOCKFILE}" \
    "workspace Cargo.lock" \
    "${PYTHON_BIN}"
)"
case "${WORKSPACE_CARGO_LOCK_STATE}" in
  "present:${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}:"*) ;;
  *)
    echo "error: privacy Python SDK requires the exact tracked root Cargo.lock authority" >&2
    exit 1
    ;;
esac
SELECTED_CARGO_LOCK_SEAL="$(
  privacy_sdk_file_seal "${SELECTED_CARGO_LOCKFILE}" "${PYTHON_BIN}"
)"
if [[ "${SELECTED_CARGO_LOCK_SEAL%%:*}" != "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" ]]; then
  echo "error: privacy Python SDK Cargo.lock does not match the canonical reviewed graph" >&2
  exit 1
fi
REQUIREMENTS_LOCKFILE_SEAL="$(
  privacy_sdk_file_seal "${REQUIREMENTS_LOCKFILE}" "${PYTHON_BIN}"
)"
CARGO_CONFIG_PATH="${ROOT_DIR}/.cargo/config.toml"
CARGO_CONFIG_SEAL="$(
  privacy_sdk_file_seal "${CARGO_CONFIG_PATH}" "${PYTHON_BIN}"
)"
CHECKOUT_NATIVE_STATE="$(checkout_native_artifact_state)"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_SEAL="${SELECTED_CARGO_LOCK_SEAL}"
export IROHA_PRIVACY_AUTHENTICATED_WORKSPACE_CARGO_LOCK_STATE="${WORKSPACE_CARGO_LOCK_STATE}"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_PATH="${CARGO_CONFIG_PATH}"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_SEAL="${CARGO_CONFIG_SEAL}"

REAL_CARGO_CANDIDATE="${IROHA_PRIVACY_REAL_CARGO:-}"
if [[ -z "${REAL_CARGO_CANDIDATE}" || \
  "${REAL_CARGO_CANDIDATE}" != \
  "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH}" ]]; then
  echo "error: privacy Python SDK real Cargo path is not authenticated" >&2
  exit 1
fi
IROHA_PRIVACY_REAL_CARGO="$(
  "${PYTHON_BIN}" -I - "${REAL_CARGO_CANDIDATE}" <<'PY'
import os
import sys
from pathlib import Path

candidate = Path(sys.argv[1])
if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
    raise SystemExit("error: Cargo path must be absolute and normalized")
if not candidate.is_file() or not os.access(candidate, os.X_OK):
    raise SystemExit("error: resolved Cargo path must be an executable file")
print(candidate)
PY
)"
export IROHA_PRIVACY_REAL_CARGO

PRIVATE_CARGO_WRAPPER_DIR="$(
  mktemp -d "${TMPDIR:-/tmp}/iroha-privacy-sdk-cargo.XXXXXX"
)"
PRIVATE_CARGO_WRAPPER_DIR="$(cd "${PRIVATE_CARGO_WRAPPER_DIR}" && pwd -P)"
PRIVATE_CARGO_AUDIT_PATH="${PRIVATE_CARGO_WRAPPER_DIR}/invocations"
PRIVATE_CARGO_TARGET_DIR="${PRIVATE_CARGO_WRAPPER_DIR}/target"
PRIVATE_WHEEL_DIR="${PRIVATE_CARGO_WRAPPER_DIR}/native-wheels"
PRIVATE_SDK_WHEEL_DIR="${PRIVATE_CARGO_WRAPPER_DIR}/sdk-wheels"
: >"${PRIVATE_CARGO_AUDIT_PATH}"
chmod 600 "${PRIVATE_CARGO_AUDIT_PATH}"
mkdir -m 700 "${PRIVATE_CARGO_TARGET_DIR}" "${PRIVATE_WHEEL_DIR}" "${PRIVATE_SDK_WHEEL_DIR}"
PRIVATE_CARGO_TARGET_DIR="$(cd "${PRIVATE_CARGO_TARGET_DIR}" && pwd -P)"
PRIVATE_WHEEL_DIR="$(cd "${PRIVATE_WHEEL_DIR}" && pwd -P)"
PRIVATE_SDK_WHEEL_DIR="$(cd "${PRIVATE_SDK_WHEEL_DIR}" && pwd -P)"
configure_private_cargo_home
export IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME="${CARGO_HOME}"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME_DIRECTORY_STATE="$(
  privacy_sdk_capture_directory_state "${CARGO_HOME}" "${PYTHON_BIN}"
)"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_REGISTRY_LINK_STATE="$(
  privacy_sdk_capture_cargo_cache_component_state \
    "${CARGO_HOME}" registry "${PYTHON_BIN}"
)"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_GIT_LINK_STATE="$(
  privacy_sdk_capture_cargo_cache_component_state \
    "${CARGO_HOME}" git "${PYTHON_BIN}"
)"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIRECTORY_STATE="$(
  privacy_sdk_capture_directory_state \
    "${PRIVATE_CARGO_TARGET_DIR}" "${PYTHON_BIN}"
)"
ln -s "${SCRIPT_DIR}/privacy_sdk_cargo_wrapper.sh" \
  "${PRIVATE_CARGO_WRAPPER_DIR}/cargo"
AUTHENTICATED_TOOLCHAIN_BIN="$(dirname "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH}")"
if [[ "$(dirname "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH}")" != \
    "${AUTHENTICATED_TOOLCHAIN_BIN}" || \
  "$(dirname "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH}")" != \
    "${AUTHENTICATED_TOOLCHAIN_BIN}" ]]; then
  echo "error: authenticated Rust tools do not share one bin directory" >&2
  exit 1
fi
export IROHA_PRIVACY_CARGO_AUDIT_PATH="${PRIVATE_CARGO_AUDIT_PATH}"
export IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR="${PRIVATE_CARGO_TARGET_DIR}"
export CARGO="${PRIVATE_CARGO_WRAPPER_DIR}/cargo"
export CARGO_BUILD_JOBS=1
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="${PRIVATE_CARGO_TARGET_DIR}"
export CARGO_INCREMENTAL=0
export CARGO_ENCODED_RUSTFLAGS=""
INHERITED_EXECUTABLE_PATH="${PATH}"
export PATH="${PRIVATE_CARGO_WRAPPER_DIR}:${AUTHENTICATED_TOOLCHAIN_BIN}:${INHERITED_EXECUTABLE_PATH}"

assert_checkout_native_artifacts_unchanged() {
  local observed_state
  if ! observed_state="$(checkout_native_artifact_state)"; then
    echo "error: checkout Python native artifacts became unreadable" >&2
    return 1
  fi
  if [[ "${observed_state}" != "${CHECKOUT_NATIVE_STATE}" ]]; then
    echo "error: checkout Python native artifacts changed while the guard was running" >&2
    return 1
  fi
}

assert_private_wheel_unchanged() {
  local observed_seal
  if [[ -n "${SDK_WHEEL_SEAL}" ]]; then
    observed_seal="$(privacy_python_sdk_file_seal "${SDK_WHEEL_PATH}")" || return 1
    if [[ "${observed_seal}" != "${SDK_WHEEL_SEAL}" ]]; then
      echo "error: fresh private SDK wheel changed while the guard was running" >&2
      return 1
    fi
  fi
  if [[ -z "${WHEEL_SEAL}" ]]; then
    return 0
  fi
  if ! observed_seal="$(privacy_python_sdk_file_seal "${WHEEL_PATH}")"; then
    echo "error: fresh private wheel became unreadable" >&2
    return 1
  fi
  if [[ "${observed_seal}" != "${WHEEL_SEAL}" ]]; then
    echo "error: fresh private wheel changed while the guard was running" >&2
    return 1
  fi
}

# This pin is captured once the admitted private interpreter exists and before
# compilation. Cleanup before that lifecycle point has no build to authenticate.
SOURCE_BEFORE_PIN=""
assert_privacy_sdk_inputs_unchanged() {
  local status=0
  if [[ -n "${SOURCE_BEFORE_PIN}" ]]; then
    "${VENV_DIR}/bin/python" -I -B "${SCRIPT_DIR}/python_native_source_delivery.py" \
      assert-pin --root "${ROOT_DIR}" --source-pin "${SOURCE_BEFORE_PIN}" || status=1
  fi
  privacy_sdk_assert_file_seal \
    "${SELECTED_CARGO_LOCKFILE}" \
    "${SELECTED_CARGO_LOCK_SEAL}" \
    "selected authenticated Cargo.lock" \
    "${PYTHON_BIN}" || status=1
  privacy_sdk_assert_optional_file_state \
    "${WORKSPACE_CARGO_LOCKFILE}" \
    "${WORKSPACE_CARGO_LOCK_STATE}" \
    "workspace Cargo.lock" \
    "${PYTHON_BIN}" || status=1
  privacy_sdk_assert_file_seal \
    "${REQUIREMENTS_LOCKFILE}" \
    "${REQUIREMENTS_LOCKFILE_SEAL}" \
    "Python SDK requirements lock" \
    "${PYTHON_BIN}" || status=1
  privacy_sdk_assert_file_seal \
    "${CARGO_CONFIG_PATH}" \
    "${CARGO_CONFIG_SEAL}" \
    "repository Cargo configuration" \
    "${PYTHON_BIN}" || status=1
  assert_checkout_native_artifacts_unchanged || status=1
  assert_private_wheel_unchanged || status=1
  privacy_sdk_assert_authenticated_toolchain_state \
    "${ROOT_DIR}" "${ROOT_DIR}" "${PYTHON_BIN}" || status=1
  privacy_sdk_assert_authenticated_toolchain_state \
    "${ROOT_DIR}" \
    "${ROOT_DIR}/python/iroha_python" \
    "${PYTHON_BIN}" || status=1
  privacy_sdk_assert_authenticated_toolchain_state \
    "${ROOT_DIR}" "${ROOT_DIR}/python/iroha_native" "${PYTHON_BIN}" || status=1
  return "${status}"
}

cleanup_privacy_sdk_cargo_wrapper() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ! assert_privacy_sdk_inputs_unchanged; then
    status=1
  fi
  if [[ -n "${PRIVATE_CARGO_WRAPPER_DIR:-}" && -d "${PRIVATE_CARGO_WRAPPER_DIR}" ]]; then
    rm -rf -- "${PRIVATE_CARGO_WRAPPER_DIR}"
  fi
  exit "${status}"
}
trap cleanup_privacy_sdk_cargo_wrapper EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_privacy_sdk_inputs_unchanged

if [[ "${TEST_MODE}" == "1" ]]; then
  VENV_DIR="$(canonical_existing_venv "${TEST_VENV_OVERRIDE}")"
else
  VENV_DIR="${PRIVATE_CARGO_WRAPPER_DIR}/venv"
  create_venv
fi
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "error: privacy Python SDK venv must provide an executable bin/python" >&2
  exit 1
fi
assert_no_python_startup_injection
if [[ "${TEST_MODE}" == "0" ]]; then
  BOOTSTRAP_VENV_DISTRIBUTIONS="$(capture_venv_distribution_names)"
else
  BOOTSTRAP_VENV_DISTRIBUTIONS="[]"
fi

VENV_PYTHON_VERSION="$("${VENV_DIR}/bin/python" -I -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
"${VENV_DIR}/bin/python" -I --version
case "${VENV_PYTHON_VERSION}" in
  3.12) ;;
  *)
    echo "error: privacy Python SDK venv must use Python 3.12; got ${VENV_PYTHON_VERSION}" >&2
    exit 1
    ;;
esac

export VIRTUAL_ENV="${VENV_DIR}"
export PATH="${PRIVATE_CARGO_WRAPPER_DIR}:${AUTHENTICATED_TOOLCHAIN_BIN}:${VENV_DIR}/bin:${INHERITED_EXECUTABLE_PATH}"
export PYO3_PYTHON="${VENV_DIR}/bin/python"
export IROHA_PRIVACY_AUTHENTICATED_PYO3_PYTHON="${PYO3_PYTHON}"
export IROHA_PYTHON_SKIP_RUNTIME_LINK=1

PIP_CONFIG_FILE=/dev/null \
  "${VENV_DIR}/bin/python" -I -m pip \
  --isolated \
  --disable-pip-version-check \
  --no-input \
  --no-cache-dir \
  install \
  --require-hashes \
  --only-binary=:all: \
  --force-reinstall \
  -r "${REQUIREMENTS_LOCKFILE}"
assert_no_python_startup_injection
if [[ "${TEST_MODE}" == "0" ]]; then
  assert_expected_venv_distributions 0
fi

MATURIN_VERSION="$(
  "${VENV_DIR}/bin/python" -I -c \
    'from importlib.metadata import version; print(version("maturin"))'
)"
if [[ "${MATURIN_VERSION}" != "1.14.1" ]]; then
  echo "error: privacy Python SDK requires authenticated Maturin 1.14.1" >&2
  exit 1
fi
export IROHA_PRIVACY_AUTHENTICATED_MATURIN_VERSION="${MATURIN_VERSION}"
case "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR}" in
  1.93.1-x86_64-unknown-linux-gnu)
    AUTHENTICATED_RUST_HOST_TRIPLE="x86_64-unknown-linux-gnu"
    unset \
      IROHA_PRIVACY_AUTHENTICATED_MATURIN_ENCODED_RUSTFLAGS \
      IROHA_PRIVACY_AUTHENTICATED_MATURIN_RUSTC_LINK_ARG \
      IROHA_PRIVACY_AUTHENTICATED_MACOSX_DEPLOYMENT_TARGET
    ;;
  1.93.1-aarch64-apple-darwin)
    AUTHENTICATED_RUST_HOST_TRIPLE="aarch64-apple-darwin"
    export IROHA_PRIVACY_AUTHENTICATED_MATURIN_ENCODED_RUSTFLAGS=$'-C\x1flink-arg=-undefined\x1f-C\x1flink-arg=dynamic_lookup'
    export IROHA_PRIVACY_AUTHENTICATED_MATURIN_RUSTC_LINK_ARG="link-args=-Wl,-install_name,@rpath/iroha_native._crypto.abi3.so"
    export IROHA_PRIVACY_AUTHENTICATED_MACOSX_DEPLOYMENT_TARGET="11.0"
    ;;
  *)
    echo "error: unsupported authenticated Rust host selector" >&2
    exit 1
    ;;
esac
export IROHA_PRIVACY_AUTHENTICATED_MATURIN_PYO3_CONFIG_PATH="${PRIVATE_CARGO_TARGET_DIR}/maturin/pyo3-config-${AUTHENTICATED_RUST_HOST_TRIPLE}-3.12-abi3.txt"
export IROHA_PRIVACY_AUTHENTICATED_PYTHON_BUILD_POLICY="$(
  printf 'v1|%s|%s|%s|%s|%s|%s|%s' \
    "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIRECTORY_STATE}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME_DIRECTORY_STATE}" \
    "${IROHA_PRIVACY_AUTHENTICATED_PYO3_PYTHON}" \
    "${IROHA_PRIVACY_AUTHENTICATED_MATURIN_VERSION}"
)"

# Unconditional in both production and the explicit inert command harness. The
# real CLI requires the existing complete, clean, committed source identity.
SOURCE_BEFORE_PIN="$("${VENV_DIR}/bin/python" -I -B \
  "${SCRIPT_DIR}/python_native_source_delivery.py" pin --root "${ROOT_DIR}")"
if [[ -z "${SOURCE_BEFORE_PIN}" ]]; then
  echo "error: Python native before-build source pin is absent" >&2
  exit 1
fi

cd "${ROOT_DIR}/python/iroha_native"
"${VENV_DIR}/bin/python" -I -m maturin build \
  --release \
  --locked \
  --offline \
  --jobs 1 \
  --target-dir "${PRIVATE_CARGO_TARGET_DIR}" \
  --out "${PRIVATE_WHEEL_DIR}"
if ! printf '%s\n' metadata rustc | cmp -s - "${PRIVATE_CARGO_AUDIT_PATH}"; then
  echo \
    "error: maturin must use the authenticated Cargo wrapper exactly for metadata then rustc" \
    >&2
  exit 1
fi
assert_privacy_sdk_inputs_unchanged

# The pure SDK is built offline by the hash-locked setuptools/wheel backend.
cd "${ROOT_DIR}/python/iroha_python"
PIP_CONFIG_FILE=/dev/null "${VENV_DIR}/bin/python" -I -B -m pip \
  --isolated --disable-pip-version-check --no-input --no-cache-dir \
  wheel --no-deps --no-index --no-build-isolation \
  --wheel-dir "${PRIVATE_SDK_WHEEL_DIR}" .
assert_privacy_sdk_inputs_unchanged

WHEEL_PATH="$(resolve_private_wheel "${PRIVATE_WHEEL_DIR}")"
SDK_WHEEL_PATH="$(resolve_private_wheel "${PRIVATE_SDK_WHEEL_DIR}")"
SDK_WHEEL_SEAL="$(privacy_python_sdk_file_seal "${SDK_WHEEL_PATH}")"
WHEEL_SEAL="$(privacy_python_sdk_file_seal "${WHEEL_PATH}")"
export IROHA_PRIVACY_AUTHENTICATED_SDK_WHEEL_PATH="${SDK_WHEEL_PATH}"
export IROHA_PRIVACY_AUTHENTICATED_SDK_WHEEL_SEAL="${SDK_WHEEL_SEAL}"
export IROHA_PRIVACY_AUTHENTICATED_WHEEL_PATH="${WHEEL_PATH}"
export IROHA_PRIVACY_AUTHENTICATED_WHEEL_SEAL="${WHEEL_SEAL}"
PREFLIGHT_WHEEL_PATH="$(preflight_private_wheel native "${WHEEL_PATH}" "${WHEEL_SEAL}")"
PREFLIGHT_SDK_WHEEL_PATH="$(preflight_private_wheel sdk "${SDK_WHEEL_PATH}" "${SDK_WHEEL_SEAL}")"
if [[ "${PREFLIGHT_SDK_WHEEL_PATH}" != "${SDK_WHEEL_PATH}" ]]; then
  echo "error: private SDK wheel preflight returned an unexpected path" >&2
  exit 1
fi
if [[ "${PREFLIGHT_WHEEL_PATH}" != "${WHEEL_PATH}" ]]; then
  echo "error: private wheel preflight returned an unexpected path" >&2
  exit 1
fi
assert_privacy_sdk_inputs_unchanged
PIP_CONFIG_FILE=/dev/null \
  "${VENV_DIR}/bin/python" -I -B -m pip \
  --isolated \
  --disable-pip-version-check \
  --no-input \
  --no-cache-dir \
  install \
  --no-compile \
  --no-deps \
  --no-index \
  --force-reinstall \
  "${WHEEL_PATH}" "${SDK_WHEEL_PATH}"
assert_no_python_startup_injection
if [[ "${TEST_MODE}" == "0" ]]; then
  assert_expected_venv_distributions 1
fi
assert_private_wheel_unchanged

INSTALLED_NATIVE_PATH="$(verify_installed_wheel)"
case "${INSTALLED_NATIVE_PATH}" in
  "${VENV_DIR}/"*) ;;
  *)
    echo "error: installed iroha_native._crypto escaped the private venv" >&2
    exit 1
    ;;
esac
assert_privacy_sdk_inputs_unchanged

NATIVE_ABI31_MANIFEST="${PRIVATE_CARGO_WRAPPER_DIR}/python-native-abi31.json"
"${VENV_DIR}/bin/python" -I -S "${ABI31_CHECKER}" record \
  --artifact "${INSTALLED_NATIVE_PATH}" \
  --manifest "${NATIVE_ABI31_MANIFEST}" \
  --source-root "${ROOT_DIR}" \
  --python "${VENV_DIR}/bin/python" \
  --sdk python \
  --target "${AUTHENTICATED_RUST_HOST_TRIPLE}-py312"
"${VENV_DIR}/bin/python" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${INSTALLED_NATIVE_PATH}" \
  --manifest "${NATIVE_ABI31_MANIFEST}" \
  --source-root "${ROOT_DIR}" \
  --python "${VENV_DIR}/bin/python"
assert_privacy_sdk_inputs_unchanged

export IROHA_PYTHON_TEST_INSTALLED_PACKAGE=1
export PYTHONPATH="${ROOT_DIR}/python/norito_py/src:${ROOT_DIR}/python"
NATIVE_TEST_XML="${PRIVATE_CARGO_WRAPPER_DIR}/installed-tests.xml"
PYTEST_STATUS=0
"${VENV_DIR}/bin/python" -I -B -m pytest -q \
  --junitxml "${NATIVE_TEST_XML}" \
  tests/confidential_wallet_native_test.py \
  tests/privacy_catalog_test.py \
  tests/privacy_exact12_fixture_test.py \
  tests/package_import_fallback_test.py \
  tests/privacy_native_registry_test.py \
  tests/privacy_native_integration_test.py \
  tests/privacy_wallet_worker_controller_test.py \
  tests/privacy_zk_x509_transport_test.py \
  tests/proof_attachment_contract_test.py \
  tests/crypto_algorithms_test.py \
  tests/governance_tally_test.py \
  "${ROOT_DIR}/python/iroha_torii_client/tests/governance_tally_response_test.py" \
  "${ROOT_DIR}/scripts/tests/check_privacy_jvm_native_gate_test.py" \
  "${ROOT_DIR}/scripts/tests/check_privacy_python_witness_boundary_test.py" || PYTEST_STATUS=$?
assert_privacy_sdk_inputs_unchanged

"${VENV_DIR}/bin/python" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${INSTALLED_NATIVE_PATH}" \
  --manifest "${NATIVE_ABI31_MANIFEST}" \
  --source-root "${ROOT_DIR}" \
  --python "${VENV_DIR}/bin/python"
assert_privacy_sdk_inputs_unchanged

# Retain only after the final installed-artifact/source verification. The receipt
# reports native test coverage; the outer guard exit still includes cleanup's
# final revalidation, and failures never become a passing native result.
if [[ -n "${EVIDENCE_OUTPUT}" ]]; then
  "${VENV_DIR}/bin/python" -I -B "${SCRIPT_DIR}/python_native_guard_evidence.py" \
    --root "${ROOT_DIR}" --output "${EVIDENCE_OUTPUT}" \
    --private-dir "${PRIVATE_CARGO_WRAPPER_DIR}" --venv "${VENV_DIR}" \
    --native "${INSTALLED_NATIVE_PATH}" \
    --native-wheel "${WHEEL_PATH}" --native-wheel-seal "${WHEEL_SEAL}" \
    --sdk-wheel "${SDK_WHEEL_PATH}" --sdk-wheel-seal "${SDK_WHEEL_SEAL}" \
    --manifest "${NATIVE_ABI31_MANIFEST}" --source-pin "${SOURCE_BEFORE_PIN}" \
    --tests "${NATIVE_TEST_XML}" --test-exit "${PYTEST_STATUS}" \
    --cargo-audit "${PRIVATE_CARGO_AUDIT_PATH}"
fi
exit "${PYTEST_STATUS}"
