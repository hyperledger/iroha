#!/usr/bin/env bash

# Authenticate original-root Cargo builds and independent lock evidence.
#
# This file is both a small command-line utility and a sourceable shell library.
# Callers must select exactly one lock with
# IROHA_PRIVACY_CARGO_LOCKFILE_PATH. The selected lock must be external to the
# repository. The tracked repository-root Cargo.lock owns the reviewed graph
# and is consumed by stock Cargo. The external evidence snapshot has the
# same authenticated bytes and an independently sealed physical identity.
# SDK-specific environment names are outputs derived from that
# authenticated selection, never aliases or fallback inputs.

readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\
"0a738f4416555a0a0a9214ffaaa142317354a2945a910be993216d2b22ce07a9"

privacy_sdk_resolve_cargo_lockfile() {
  local repository_root="$1"
  local python_bin="${2:-python3}"

  "${python_bin}" -I - "${repository_root}" <<'PY'
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Optional

PRIMARY_ENV = "IROHA_PRIVACY_CARGO_LOCKFILE_PATH"
MAX_LOCK_BYTES = 16 * 1024 * 1024


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"error: {message}")


def configured_value(name: str) -> Optional[str]:
    if name not in os.environ:
        return None
    value = os.environ[name]
    if not value:
        fail(f"{name} must not be empty")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        fail(f"{name} must not contain control characters")
    return value


root_argument = Path(sys.argv[1])
if not root_argument.is_absolute():
    fail("privacy SDK repository root must be absolute")
try:
    repository_root = root_argument.resolve(strict=True)
except OSError as error:
    fail(f"privacy SDK repository root is unavailable: {error}")
if not repository_root.is_dir():
    fail("privacy SDK repository root must be a directory")

primary = configured_value(PRIMARY_ENV)
if primary is None:
    fail(f"{PRIMARY_ENV} is required and must select a Cargo.lock")

selected_argument = Path(primary)
if not selected_argument.is_absolute():
    fail(f"{PRIMARY_ENV} must name an absolute Cargo.lock path")
try:
    selected = selected_argument.resolve(strict=True)
except OSError as error:
    fail(f"selected privacy SDK Cargo.lock is unavailable: {error}")
if selected != selected_argument:
    fail(
        f"{PRIMARY_ENV} must be canonical and contain no symbolic-link components"
    )

if selected.name != "Cargo.lock":
    fail("privacy SDK lockfile path must end in Cargo.lock")
workspace_lock = repository_root / "Cargo.lock"
if selected == workspace_lock:
    fail("privacy SDK Cargo.lock must not select the workspace Cargo.lock")
if repository_root in selected.parents:
    fail("privacy SDK Cargo.lock must remain external to the repository")

open_flags = os.O_RDONLY
open_flags |= getattr(os, "O_CLOEXEC", 0)
open_flags |= getattr(os, "O_NOFOLLOW", 0)
open_flags |= os.O_NONBLOCK
try:
    descriptor = os.open(selected, open_flags)
except OSError as error:
    fail(f"unable to open selected privacy SDK Cargo.lock: {error}")

try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        fail("selected privacy SDK Cargo.lock must be a regular file")
    if before.st_nlink != 1:
        fail("selected privacy SDK Cargo.lock must be singly linked")
    if before.st_mode & 0o111:
        fail("selected privacy SDK Cargo.lock must not be executable")
    if before.st_size <= 0 or before.st_size > MAX_LOCK_BYTES:
        fail(
            "selected privacy SDK Cargo.lock must be non-empty and no larger "
            f"than {MAX_LOCK_BYTES} bytes"
        )
    chunks: list[bytes] = []
    remaining = MAX_LOCK_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
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
if len(payload) != before.st_size or stable_before != stable_after:
    fail("selected privacy SDK Cargo.lock changed while it was read")
try:
    path_metadata = os.stat(selected, follow_symlinks=False)
except OSError as error:
    fail(f"selected privacy SDK Cargo.lock became unavailable: {error}")
if (path_metadata.st_dev, path_metadata.st_ino) != (before.st_dev, before.st_ino):
    fail("selected privacy SDK Cargo.lock changed identity while it was read")
if selected.resolve(strict=True) != selected:
    fail("selected privacy SDK Cargo.lock path became noncanonical while it was read")

try:
    lock_text = payload.decode("utf-8", errors="strict")
except UnicodeDecodeError as error:
    fail(f"selected privacy SDK Cargo.lock is not UTF-8: {error}")
if "\x00" in lock_text or "\r" in lock_text or not lock_text.endswith("\n"):
    fail("selected privacy SDK Cargo.lock is not canonical UTF-8 text")
lock_preamble = lock_text.split("[[package]]", 1)[0]
version_rows = re.findall(r"(?m)^version = (.+)$", lock_preamble)
if version_rows != ["4"]:
    fail("selected privacy SDK Cargo.lock must use Cargo lock format version 4")
if "[[package]]\n" not in lock_text:
    fail("selected privacy SDK Cargo.lock must contain at least one package")

# Consume the bytes before printing the canonical path so validation cannot be
# optimized into a path-only check.
hashlib.sha256(payload).digest()
print(selected)
PY
}

privacy_sdk_file_seal() {
  local path="$1"
  local python_bin="${2:-python3}"

  "${python_bin}" -I - "${path}" <<'PY'
from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
path = Path(sys.argv[1])
flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as error:
    raise SystemExit(f"error: unable to seal {path}: {error}")
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"error: {path} is not a regular file")
    if before.st_size < 0 or before.st_size > MAX_BYTES:
        raise SystemExit(f"error: {path} exceeds the file-seal size limit")
    digest = hashlib.sha256()
    observed = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        observed += len(chunk)
        if observed > MAX_BYTES:
            raise SystemExit(f"error: {path} exceeds the file-seal size limit")
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
if stable_before != stable_after or observed != before.st_size:
    raise SystemExit(f"error: {path} changed while it was sealed")
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

privacy_sdk_assert_file_seal() {
  local path="$1"
  local expected_seal="$2"
  local label="$3"
  local python_bin="${4:-python3}"
  local observed_seal

  if ! observed_seal="$(privacy_sdk_file_seal "${path}" "${python_bin}")"; then
    echo "error: ${label} became unreadable" >&2
    return 1
  fi
  if [[ "${observed_seal}" != "${expected_seal}" ]]; then
    echo "error: ${label} changed while the privacy SDK guard was running" >&2
    return 1
  fi
}

privacy_sdk_capture_directory_state() {
  local path="$1"
  local python_bin="${2:-python3}"

  "${python_bin}" -I - "${path}" <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("error: authenticated directory path must be absolute")
try:
    canonical = path.resolve(strict=True)
    metadata = os.stat(path, follow_symlinks=False)
except OSError as error:
    raise SystemExit(f"error: authenticated directory is unavailable: {error}")
if canonical != path or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(
        "error: authenticated directory must be canonical and must not be a symlink"
    )
print(
    ":".join(
        str(value)
        for value in (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
        )
    )
)
PY
}

privacy_sdk_assert_directory_state() {
  local path="$1"
  local expected_state="$2"
  local label="$3"
  local python_bin="${4:-python3}"
  local observed_state

  if [[ -z "${expected_state}" ]]; then
    echo "error: ${label} authenticated directory state is missing" >&2
    return 1
  fi
  if ! observed_state="$(
    privacy_sdk_capture_directory_state "${path}" "${python_bin}"
  )"; then
    echo "error: ${label} authenticated directory state is unavailable" >&2
    return 1
  fi
  if [[ "${observed_state}" != "${expected_state}" ]]; then
    echo "error: ${label} directory identity changed" >&2
    return 1
  fi
}

privacy_sdk_capture_cargo_cache_component_state() {
  local cargo_home="$1"
  local component_name="$2"
  local python_bin="${3:-python3}"

  case "${component_name}" in
    registry|git) ;;
    *)
      echo "error: unsupported Cargo cache component ${component_name}" >&2
      return 1
      ;;
  esac
  "${python_bin}" -I - "${cargo_home}" "${component_name}" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

home = Path(sys.argv[1])
component = home / sys.argv[2]
if not os.path.lexists(component):
    print("absent")
    raise SystemExit(0)
before = os.lstat(component)
if not stat.S_ISLNK(before.st_mode):
    raise SystemExit("error: authenticated Cargo cache component must be a symlink")
raw_target = os.readlink(component)
target_path = Path(raw_target)
if not target_path.is_absolute():
    raise SystemExit(
        "error: authenticated Cargo cache component must use an absolute target"
    )
try:
    canonical_target = component.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: authenticated Cargo cache target is unavailable: {error}")
if canonical_target != target_path or not canonical_target.is_dir():
    raise SystemExit(
        "error: authenticated Cargo cache target must be a canonical real directory"
    )
target = os.stat(canonical_target, follow_symlinks=False)
after = os.lstat(component)
link_before = (
    before.st_dev,
    before.st_ino,
    before.st_mode,
    before.st_uid,
    before.st_gid,
    before.st_size,
    before.st_mtime_ns,
    before.st_ctime_ns,
)
link_after = (
    after.st_dev,
    after.st_ino,
    after.st_mode,
    after.st_uid,
    after.st_gid,
    after.st_size,
    after.st_mtime_ns,
    after.st_ctime_ns,
)
if link_before != link_after or os.readlink(component) != raw_target:
    raise SystemExit("error: authenticated Cargo cache symlink changed while read")
print(
    ":".join(
        (
            "present",
            str(before.st_dev),
            str(before.st_ino),
            oct(stat.S_IMODE(before.st_mode)),
            str(before.st_uid),
            str(before.st_gid),
            str(before.st_size),
            str(before.st_mtime_ns),
            str(before.st_ctime_ns),
            hashlib.sha256(os.fsencode(raw_target)).hexdigest(),
            str(target.st_dev),
            str(target.st_ino),
            oct(stat.S_IMODE(target.st_mode)),
            str(target.st_uid),
            str(target.st_gid),
        )
    )
)
PY
}

privacy_sdk_assert_cargo_cache_component_state() {
  local cargo_home="$1"
  local component_name="$2"
  local expected_state="$3"
  local python_bin="${4:-python3}"
  local observed_state

  if [[ -z "${expected_state}" ]]; then
    echo \
      "error: authenticated Cargo ${component_name} cache state is missing" \
      >&2
    return 1
  fi
  observed_state="$(
    privacy_sdk_capture_cargo_cache_component_state \
      "${cargo_home}" "${component_name}" "${python_bin}"
  )" || return 1
  if [[ "${observed_state}" != "${expected_state}" ]]; then
    echo \
      "error: authenticated Cargo ${component_name} cache link identity changed" \
      >&2
    return 1
  fi
}

privacy_sdk_validate_rust_toolchain_overrides() {
  local repository_root="$1"
  local invocation_directory="$2"
  local python_bin="${3:-python3}"

  "${python_bin}" -I - "${repository_root}" "${invocation_directory}" <<'PY'
import os
import stat
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
invocation = Path(sys.argv[2])
try:
    canonical_root = root.resolve(strict=True)
    canonical_invocation = invocation.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: Rust toolchain override hierarchy is unavailable: {error}")
if canonical_root != root or not canonical_root.is_dir():
    raise SystemExit("error: Rust toolchain repository root must be canonical")
if canonical_invocation != canonical_root and canonical_root not in canonical_invocation.parents:
    raise SystemExit("error: Rust toolchain invocation directory escaped the repository")

allowed = canonical_root / "rust-toolchain.toml"
directory = canonical_invocation
observed_allowed = False
while True:
    for filename in ("rust-toolchain", "rust-toolchain.toml"):
        candidate = directory / filename
        if not os.path.lexists(candidate):
            continue
        if candidate != allowed:
            raise SystemExit(
                f"error: untrusted active Rust toolchain override: {candidate}"
            )
        try:
            canonical = candidate.resolve(strict=True)
            metadata = os.stat(candidate, follow_symlinks=False)
        except OSError as error:
            raise SystemExit(
                f"error: authenticated Rust toolchain override is unavailable: {error}"
            )
        if (
            canonical != candidate
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o111
        ):
            raise SystemExit(
                "error: authenticated Rust toolchain override must be a canonical, "
                "singly linked, non-executable regular file"
            )
        try:
            configuration = tomllib.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise SystemExit(
                f"error: unable to parse authenticated Rust toolchain override: {error}"
            )
        if configuration != {"toolchain": {"channel": "1.93.1"}}:
            raise SystemExit(
                "error: authenticated rust-toolchain.toml may only select the "
                "exact Rust 1.93.1 toolchain"
            )
        observed_allowed = True
    if directory == canonical_root:
        break
    directory = directory.parent
if not observed_allowed:
    raise SystemExit("error: authenticated root rust-toolchain.toml is missing")
PY
}

privacy_sdk_executable_seal() {
  local path="$1"
  local python_bin="${2:-python3}"

  "${python_bin}" -I - "${path}" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

MAX_BYTES = 512 * 1024 * 1024
path = Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("error: authenticated toolchain executable path must be absolute")
try:
    canonical = path.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: authenticated toolchain executable is unavailable: {error}")
if canonical != path:
    raise SystemExit(
        "error: authenticated toolchain executable path must be canonical"
    )
flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as error:
    raise SystemExit(f"error: unable to seal toolchain executable: {error}")
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or not before.st_mode & 0o111
        or before.st_nlink != 1
    ):
        raise SystemExit(
            "error: authenticated toolchain executable must be a singly linked "
            "executable regular file"
        )
    if before.st_size <= 0 or before.st_size > MAX_BYTES:
        raise SystemExit("error: authenticated toolchain executable has an invalid size")
    digest = hashlib.sha256()
    observed = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        observed += len(chunk)
        if observed > MAX_BYTES:
            raise SystemExit(
                "error: authenticated toolchain executable exceeds the size limit"
            )
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
if stable_before != stable_after or observed != before.st_size:
    raise SystemExit("error: authenticated toolchain executable changed while sealed")
try:
    path_metadata = os.stat(path, follow_symlinks=False)
except OSError as error:
    raise SystemExit(
        f"error: authenticated toolchain executable became unavailable: {error}"
    )
if (path_metadata.st_dev, path_metadata.st_ino) != (
    before.st_dev,
    before.st_ino,
):
    raise SystemExit(
        "error: authenticated toolchain executable changed identity while sealed"
    )
print(
    ":".join(
        (
            digest.hexdigest(),
            str(before.st_dev),
            str(before.st_ino),
            str(before.st_nlink),
            str(before.st_size),
            str(before.st_mtime_ns),
            str(before.st_ctime_ns),
            oct(stat.S_IMODE(before.st_mode)),
        )
    )
)
PY
}

privacy_sdk_assert_executable_seal() {
  local path="$1"
  local expected_seal="$2"
  local label="$3"
  local python_bin="${4:-python3}"
  local observed_seal

  if ! observed_seal="$(
    privacy_sdk_executable_seal "${path}" "${python_bin}"
  )"; then
    echo "error: ${label} became unreadable" >&2
    return 1
  fi
  if [[ "${observed_seal}" != "${expected_seal}" ]]; then
    echo "error: ${label} changed after toolchain authentication" >&2
    return 1
  fi
}

privacy_sdk_resolve_rustup_toolchain_binary() {
  local repository_root="$1"
  local binary_name="$2"
  local authenticated_toolchain_seal="$3"
  local rustup_path="$4"
  local authenticated_rustup_seal="$5"
  local toolchain_selector="$6"
  local python_bin="${7:-python3}"
  local candidate toolchain_path toolchain_channel

  case "${binary_name}" in
    cargo|rustc|rustdoc) ;;
    *)
      echo "error: unsupported Rust toolchain binary ${binary_name}" >&2
      return 1
      ;;
  esac
  toolchain_path="${repository_root}/rust-toolchain.toml"
  privacy_sdk_assert_file_seal \
    "${toolchain_path}" \
    "${authenticated_toolchain_seal}" \
    "authenticated rust-toolchain.toml before rustup resolution" \
    "${python_bin}" || return 1
  if ! toolchain_channel="$(
    "${python_bin}" -I - "${toolchain_path}" <<'PY'
import sys
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
try:
    configuration = tomllib.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
    raise SystemExit(f"error: unable to read authenticated Rust toolchain: {error}")
if configuration != {"toolchain": {"channel": "1.93.1"}}:
    raise SystemExit(
        "error: authenticated rust-toolchain.toml does not contain only the "
        "exact Rust 1.93.1 channel selector"
    )
print(configuration["toolchain"]["channel"])
PY
  )"; then
    return 1
  fi
  case "${toolchain_selector}" in
    1.93.1-x86_64-unknown-linux-gnu|1.93.1-aarch64-apple-darwin) ;;
    *)
      echo \
        "error: privacy SDK Rust toolchain selector is not an authenticated host-qualified 1.93.1 selector" \
        >&2
      return 1
      ;;
  esac
  if [[ "${toolchain_selector}" != "${toolchain_channel}-"* ]]; then
    echo "error: Rust toolchain selector does not match the sealed descriptor" >&2
    return 1
  fi
  privacy_sdk_assert_file_seal \
    "${toolchain_path}" \
    "${authenticated_toolchain_seal}" \
    "authenticated rust-toolchain.toml after channel selection" \
    "${python_bin}" || return 1
  privacy_sdk_assert_executable_seal \
    "${rustup_path}" \
    "${authenticated_rustup_seal}" \
    "authenticated rustup before toolchain resolution" \
    "${python_bin}" || return 1
  if ! candidate="$(
    cd "${repository_root}" || exit 1
    env -i \
      HOME="${HOME:?Rust toolchain resolution requires HOME}" \
      RUSTUP_AUTO_INSTALL=0 \
      "${rustup_path}" which \
        --toolchain "${toolchain_selector}" "${binary_name}"
  )"; then
    echo "error: authenticated rustup failed to resolve ${binary_name}" >&2
    return 1
  fi
  privacy_sdk_assert_file_seal \
    "${toolchain_path}" \
    "${authenticated_toolchain_seal}" \
    "authenticated rust-toolchain.toml after rustup resolution" \
    "${python_bin}" || return 1
  privacy_sdk_assert_executable_seal \
    "${rustup_path}" \
    "${authenticated_rustup_seal}" \
    "authenticated rustup after toolchain resolution" \
    "${python_bin}" || return 1
  "${python_bin}" -I - "${candidate}" "${binary_name}" <<'PY' || return 1
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_name = sys.argv[2]
if not path.is_absolute():
    raise SystemExit("error: rustup returned a non-absolute toolchain binary")
try:
    canonical = path.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: rustup toolchain binary is unavailable: {error}")
if canonical != path or path.name != expected_name:
    raise SystemExit(
        "error: rustup must resolve a canonical actual toolchain binary, not a shim"
    )
if not path.is_file() or not os.access(path, os.X_OK):
    raise SystemExit("error: rustup toolchain binary must be an executable file")
print(path)
PY
}

privacy_sdk_assert_authenticated_toolchain_state() {
  local repository_root="$1"
  local invocation_directory="$2"
  local python_bin="${3:-python3}"
  local status=0
  local name path seal

  : "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH:?authenticated Rust toolchain path is required}"
  : "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL:?authenticated Rust toolchain seal is required}"
  : "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR:?authenticated Rust toolchain selector is required}"
  case "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR}" in
    1.93.1-x86_64-unknown-linux-gnu|1.93.1-aarch64-apple-darwin) ;;
    *)
      echo "error: authenticated Rust toolchain selector is invalid" >&2
      return 1
      ;;
  esac
  if [[ "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH}" != \
    "${repository_root}/rust-toolchain.toml" ]]; then
    echo "error: authenticated Rust toolchain override path changed" >&2
    return 1
  fi
  privacy_sdk_validate_rust_toolchain_overrides \
    "${repository_root}" "${invocation_directory}" "${python_bin}" || status=1
  privacy_sdk_assert_file_seal \
    "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH}" \
    "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL}" \
    "authenticated rust-toolchain.toml" \
    "${python_bin}" || status=1
  for name in RUSTUP CARGO RUSTC RUSTDOC; do
    case "${name}" in
      RUSTUP)
        path="${IROHA_PRIVACY_AUTHENTICATED_RUSTUP_PATH:-}"
        seal="${IROHA_PRIVACY_AUTHENTICATED_RUSTUP_SEAL:-}"
        ;;
      CARGO)
        path="${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH:-}"
        seal="${IROHA_PRIVACY_AUTHENTICATED_CARGO_SEAL:-}"
        ;;
      RUSTC)
        path="${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH:-}"
        seal="${IROHA_PRIVACY_AUTHENTICATED_RUSTC_SEAL:-}"
        ;;
      RUSTDOC)
        path="${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH:-}"
        seal="${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_SEAL:-}"
        ;;
    esac
    if [[ -z "${path}" || -z "${seal}" ]]; then
      echo "error: authenticated ${name} path and seal are required" >&2
      status=1
      continue
    fi
    privacy_sdk_assert_executable_seal \
      "${path}" "${seal}" "authenticated ${name}" "${python_bin}" || status=1
  done
  local toolchain_bin_directory
  toolchain_bin_directory="$(
    dirname "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH:-/invalid/cargo}"
  )"
  if [[ "$(dirname "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH:-/invalid/rustc}")" != \
      "${toolchain_bin_directory}" || \
    "$(dirname "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH:-/invalid/rustdoc}")" != \
      "${toolchain_bin_directory}" || \
    "$(basename "${toolchain_bin_directory}")" != "bin" || \
    "$(basename "$(dirname "${toolchain_bin_directory}")")" != \
      "${IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR}" ]]; then
    echo \
      "error: authenticated Cargo, rustc, and rustdoc no longer share one toolchain bin directory" \
      >&2
    status=1
  fi
  return "${status}"
}

privacy_sdk_capture_optional_file_state() {
  local path="$1"
  local label="$2"
  local python_bin="${3:-python3}"
  local seal

  if [[ -L "${path}" ]]; then
    echo "error: ${label} must not be a symbolic link" >&2
    return 1
  fi
  if [[ ! -e "${path}" ]]; then
    printf '%s\n' "absent"
    return 0
  fi
  if ! seal="$(privacy_sdk_file_seal "${path}" "${python_bin}")"; then
    echo "error: ${label} must be a readable regular file when present" >&2
    return 1
  fi
  printf 'present:%s\n' "${seal}"
}

privacy_sdk_assert_optional_file_state() {
  local path="$1"
  local expected_state="$2"
  local label="$3"
  local python_bin="${4:-python3}"

  case "${expected_state}" in
    absent)
      if [[ -e "${path}" || -L "${path}" ]]; then
        echo "error: ${label} was created while the privacy SDK guard was running" >&2
        return 1
      fi
      ;;
    present:*)
      privacy_sdk_assert_file_seal \
        "${path}" "${expected_state#present:}" "${label}" "${python_bin}"
      ;;
    *)
      echo "error: invalid captured state for ${label}" >&2
      return 1
      ;;
  esac
}

privacy_sdk_validate_repository_cargo_configuration() {
  local repository_root="$1"
  local project_directory="$2"
  local python_bin="${3:-python3}"

  "${python_bin}" -I - "${repository_root}" "${project_directory}" <<'PY'
import os
import stat
import sys
import tomllib
from pathlib import Path

root_argument = Path(sys.argv[1])
project_argument = Path(sys.argv[2])
try:
    root = root_argument.resolve(strict=True)
    project = project_argument.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"error: Cargo configuration search path is unavailable: {error}")
if root != root_argument or project != project_argument:
    raise SystemExit("error: Cargo configuration search paths must be canonical")
if project != root and root not in project.parents:
    raise SystemExit("error: Cargo configuration project escaped the repository")

allowed_path = root / ".cargo/config.toml"
allowed_configuration = {
    "alias": {
        "xtask": "run --package xtask --features dev-tools --bin xtask --",
    },
}
observed_allowed = False
directory = project
while True:
    cargo_directory = directory / ".cargo"
    candidates = (cargo_directory / "config", cargo_directory / "config.toml")
    present = [path for path in candidates if os.path.lexists(path)]
    if len(present) > 1:
        raise SystemExit(
            f"error: multiple Cargo configuration files are active in {cargo_directory}"
        )
    if present:
        path = present[0]
        try:
            canonical = path.resolve(strict=True)
            metadata = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise SystemExit(f"error: Cargo configuration is unavailable: {error}")
        if (
            path.is_symlink()
            or canonical != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise SystemExit(
                "error: active Cargo configuration must be canonical and singly "
                f"linked: {path}"
            )
        if path != allowed_path:
            raise SystemExit(
                f"error: untrusted Cargo configuration is active: {path}"
            )
        observed_allowed = True
        try:
            configuration = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise SystemExit(
                f"error: unable to parse repository Cargo configuration: {error}"
            )
        if configuration != allowed_configuration:
            raise SystemExit(
                "error: repository Cargo configuration may only define the "
                "approved xtask alias and must not impose global parallelism"
            )
    if directory.parent == directory:
        break
    directory = directory.parent
if not observed_allowed:
    raise SystemExit("error: authenticated repository Cargo configuration is missing")
PY
}

privacy_sdk_reject_cargo_policy_environment() {
  local python_bin="${1:-python3}"

  "${python_bin}" -I - <<'PY'
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
    "CARGO_HOST_",
    "CARGO_HTTP_",
    "CARGO_NET_",
    "CARGO_PROFILE_",
    "CARGO_REGISTRIES_",
    "CARGO_REGISTRY_",
    "CARGO_SOURCE_",
    "CARGO_TARGET_",
    "CARGO_UNSTABLE_",
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
        (name == "CARGO_INCREMENTAL" and os.environ[name] == "0")
        or (name == "CARGO_ENCODED_RUSTFLAGS" and os.environ[name] == "")
    )
)
if forbidden:
    raise SystemExit(
        "error: privacy SDK Cargo provisioning rejects policy-affecting "
        f"environment variables: {', '.join(forbidden)}"
    )
PY
}

privacy_sdk_prepare_private_cargo_home() {
  local private_cargo_home="$1"
  local python_bin="${2:-python3}"
  local ambient_cargo_home="${CARGO_HOME:-}"
  local component source_component canonical_source_component
  local private_cache_root

  if [[ -z "${ambient_cargo_home}" ]]; then
    if ! ambient_cargo_home="$(
      "${python_bin}" -I - <<'PY'
from pathlib import Path

print(Path.home() / ".cargo")
PY
    )"; then
      return 1
    fi
  fi
  if ! ambient_cargo_home="$(
    "${python_bin}" -I - "${ambient_cargo_home}" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute() or path != Path(os.path.abspath(path)):
    raise SystemExit("error: ambient Cargo home must be absolute and normalized")
if path.exists():
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_dir():
        raise SystemExit("error: ambient Cargo home must be a canonical real directory")
print(path)
PY
  )"; then
    return 1
  fi
  if [[ -e "${private_cargo_home}" || -L "${private_cargo_home}" ]]; then
    echo "error: private Cargo home already exists" >&2
    return 1
  fi
  install -d -m 700 "${private_cargo_home}" || return 1
  private_cache_root="${private_cargo_home}-cache"
  install -d -m 700 "${private_cache_root}" || return 1
  for component in registry git; do
    source_component="${ambient_cargo_home}/${component}"
    if [[ -e "${source_component}" || -L "${source_component}" ]]; then
      if [[ ! -d "${source_component}" ]] || ! canonical_source_component="$(
        cd "${source_component}" && pwd -P
      )"; then
        echo "error: ambient Cargo cache component must resolve to a real directory" >&2
        return 1
      fi
      ln -s "${canonical_source_component}" \
        "${private_cargo_home}/${component}" || return 1
    else
      install -d -m 700 \
        "${private_cache_root}/${component}" || return 1
      ln -s "${private_cache_root}/${component}" \
        "${private_cargo_home}/${component}" || return 1
    fi
  done
}

# Stock Cargo consumes the original workspace graph; the selected external
# lock is independent evidence, never a Cargo command-line override.
privacy_sdk_assert_stock_cargo_manifest() {
  local repository_root="$1"
  local manifest_path="$2"
  local python_bin="${3:-python3}"
  "${python_bin}" -I - "${repository_root}" "${manifest_path}" <<'PY'
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1])
manifest = Path(sys.argv[2])
try:
    if (not manifest.is_absolute() or manifest.name != "Cargo.toml"
            or manifest.resolve(strict=True) != manifest or not manifest.is_file()
            or root.resolve(strict=True) != root):
        raise ValueError("manifest must be a canonical original Cargo.toml")
    if manifest == root / "Cargo.toml":
        raise SystemExit(0)
    directory = manifest.parent
    directory.relative_to(root)
    graph = tomllib.loads((root / "Cargo.toml").read_text())
    workspace = graph["workspace"]
    def selected(patterns):
        return any(directory in root.glob(pattern) for pattern in patterns)
    if not selected(workspace.get("members", [])) or selected(workspace.get("exclude", [])):
        raise ValueError("manifest is not an original workspace member")
    package = tomllib.loads(manifest.read_text())
    if "workspace" in package:
        raise ValueError("nested workspace cannot select the authenticated root graph")
    explicit = package.get("package", {}).get("workspace")
    if explicit is not None and (directory / explicit).resolve(strict=True) != root:
        raise ValueError("member redirects its workspace")
    for parent in directory.parents:
        if parent == root:
            break
        candidate = parent / "Cargo.toml"
        if candidate.exists() and "workspace" in tomllib.loads(candidate.read_text()):
            raise ValueError("intermediate workspace changes Cargo lock discovery")
except (OSError, ValueError, KeyError, TypeError) as error:
    raise SystemExit(f"error: stock Cargo manifest is not bound to the authenticated root: {error}")
PY
}

privacy_sdk_assert_ci_cargo_lock_state() {
  local repository_root="$1"
  local python_bin="${2:-python3}"
  local canonical_repository_root canonical_cargo_home resolved_lockfile status=0

  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_PATH:?CI lock verification requires an authenticated Cargo lock path}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_SEAL:?CI lock verification requires an authenticated Cargo lock seal}"
  : "${IROHA_PRIVACY_AUTHENTICATED_WORKSPACE_CARGO_LOCK_STATE:?CI lock verification requires an authenticated workspace lock state}"

  case "${IROHA_PRIVACY_AUTHENTICATED_WORKSPACE_CARGO_LOCK_STATE}" in
    "present:${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}:"*) ;;
    *)
      echo "error: privacy SDK CI requires the sealed tracked root Cargo.lock" >&2
      return 1
      ;;
  esac
  if ! resolved_lockfile="$(
    privacy_sdk_resolve_cargo_lockfile "${repository_root}" "${python_bin}"
  )"; then
    return 1
  fi
  canonical_repository_root="$(cd "${repository_root}" && pwd -P)"
  case "${resolved_lockfile}" in
    "${canonical_repository_root}/"*)
      echo "error: privacy SDK CI Cargo.lock must remain external to the repository" >&2
      return 1
      ;;
  esac
  if [[ -n "${CARGO+x}" ]]; then
    echo \
      "error: privacy SDK CI Cargo selector must be absent before wrapper selection" \
      >&2
    return 1
  fi
  if [[ "${CARGO_BUILD_JOBS:-}" != "1" || \
    "${CARGO_NET_OFFLINE:-}" != "true" || \
    "${CARGO_INCREMENTAL:-}" != "0" || \
    "${CARGO_ENCODED_RUSTFLAGS+x}" != "x" || \
    -n "${CARGO_ENCODED_RUSTFLAGS:-}" || \
    -n "${RUSTC_BOOTSTRAP+x}" ]]; then
    echo "error: privacy SDK CI deterministic Cargo environment changed" >&2
    return 1
  fi
  privacy_sdk_assert_authenticated_toolchain_state \
    "${canonical_repository_root}" \
    "${canonical_repository_root}" \
    "${python_bin}" || status=1
  if [[ -d "${canonical_repository_root}/python/iroha_python" ]]; then
    privacy_sdk_assert_authenticated_toolchain_state \
      "${canonical_repository_root}" \
      "${canonical_repository_root}/python/iroha_python" \
      "${python_bin}" || status=1
  fi
  if [[ "${IROHA_PRIVACY_REAL_CARGO:-}" != \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH:-}" ]]; then
    echo "error: privacy SDK CI real Cargo path is not authenticated" >&2
    status=1
  fi
  if [[ "${resolved_lockfile}" != "${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_PATH}" ]]; then
    echo "error: privacy SDK CI Cargo lock selection changed" >&2
    return 1
  fi
  case "${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_SEAL}" in
    "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}:"*) ;;
    *)
      echo "error: privacy SDK CI selected lock does not match the canonical reviewed dependency graph" >&2
      return 1
      ;;
  esac
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_PATH:?CI lock verification requires an authenticated Cargo config path}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_SEAL:?CI lock verification requires an authenticated Cargo config seal}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME:?CI lock verification requires an authenticated Cargo home}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME_DIRECTORY_STATE:?CI lock verification requires authenticated Cargo home directory state}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_REGISTRY_LINK_STATE:?CI lock verification requires authenticated Cargo registry cache state}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_GIT_LINK_STATE:?CI lock verification requires authenticated Cargo git cache state}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR:?CI lock verification requires an authenticated Cargo target}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIRECTORY_STATE:?CI lock verification requires authenticated Cargo target directory state}"
  if [[ "${IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_PATH}" != \
    "${canonical_repository_root}/.cargo/config.toml" ]]; then
    echo "error: privacy SDK CI Cargo configuration path changed" >&2
    return 1
  fi
  if [[ "${CARGO_HOME:-}" != "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" || \
    ! -d "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" || \
    -L "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" ]]; then
    echo "error: privacy SDK CI Cargo home is not the authenticated private directory" >&2
    return 1
  fi
  if ! canonical_cargo_home="$(
    cd "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" && pwd -P
  )" || [[ "${canonical_cargo_home}" != \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" ]]; then
    echo "error: privacy SDK CI Cargo home is not canonical" >&2
    return 1
  fi
  if [[ -e "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}/config" || \
    -L "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}/config" || \
    -e "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}/config.toml" || \
    -L "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}/config.toml" ]]; then
    echo "error: privacy SDK CI Cargo home contains untrusted configuration" >&2
    return 1
  fi
  privacy_sdk_assert_directory_state \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME_DIRECTORY_STATE}" \
    "privacy SDK CI Cargo home" \
    "${python_bin}" || status=1
  privacy_sdk_assert_cargo_cache_component_state \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" \
    registry \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_REGISTRY_LINK_STATE}" \
    "${python_bin}" || status=1
  privacy_sdk_assert_cargo_cache_component_state \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME}" \
    git \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_GIT_LINK_STATE}" \
    "${python_bin}" || status=1
  case "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR}/" in
    "${canonical_repository_root}/"*)
      echo "error: privacy SDK CI Cargo target must remain external" >&2
      status=1
      ;;
  esac
  if [[ "${CARGO_TARGET_DIR:-}" != \
      "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR}" ]]; then
    echo "error: privacy SDK CI Cargo target selection changed" >&2
    status=1
  fi
  privacy_sdk_assert_directory_state \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIRECTORY_STATE}" \
    "privacy SDK CI Cargo target" \
    "${python_bin}" || status=1
  privacy_sdk_validate_repository_cargo_configuration \
    "${canonical_repository_root}" \
    "${canonical_repository_root}" \
    "${python_bin}" || status=1
  privacy_sdk_assert_file_seal \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_PATH}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_SEAL}" \
    "authenticated repository Cargo configuration" \
    "${python_bin}" || status=1
  privacy_sdk_assert_file_seal \
    "${resolved_lockfile}" \
    "${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_SEAL}" \
    "selected external Cargo.lock" \
    "${python_bin}" || status=1
  privacy_sdk_assert_optional_file_state \
    "${repository_root}/Cargo.lock" \
    "${IROHA_PRIVACY_AUTHENTICATED_WORKSPACE_CARGO_LOCK_STATE}" \
    "workspace Cargo.lock" \
    "${python_bin}" || status=1
  return "${status}"
}

privacy_sdk_assert_ci_executable_path_order() {
  local expected_wrapper_directory expected_toolchain_directory
  local first_path_entry second_path_entry remaining_path

  : "${IROHA_PRIVACY_CARGO_AUDIT_PATH:?CI PATH verification requires an authenticated Cargo audit path}"
  : "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH:?CI PATH verification requires authenticated Cargo}"
  : "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH:?CI PATH verification requires authenticated rustc}"
  : "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH:?CI PATH verification requires authenticated rustdoc}"

  expected_wrapper_directory="$(
    dirname "$(dirname "${IROHA_PRIVACY_CARGO_AUDIT_PATH}")/bin/cargo"
  )"
  expected_toolchain_directory="$(
    dirname "${IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH}"
  )"
  first_path_entry="${PATH%%:*}"
  remaining_path="${PATH#*:}"
  second_path_entry="${remaining_path%%:*}"
  if [[ "${first_path_entry}" != "${expected_wrapper_directory}" || \
    "${second_path_entry}" != "${expected_toolchain_directory}" ]]; then
    echo \
      "error: privacy SDK CI PATH must begin with wrapper then authenticated toolchain" \
      >&2
    return 1
  fi
  if [[ "$(command -v cargo || true)" != \
      "${expected_wrapper_directory}/cargo" || \
    "$(command -v rustc || true)" != \
      "${IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH}" || \
    "$(command -v rustdoc || true)" != \
      "${IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH}" ]]; then
    echo "error: privacy SDK CI PATH does not resolve the authenticated Rust tools" >&2
    return 1
  fi
}

# Materialize authenticated graph bytes at a new external inode. This is not
# dependency resolution: Cargo must subsequently accept these exact bytes locked.
privacy_sdk_materialize_canonical_cargo_lock() {
  local repository_root="$1"
  local destination="$2"
  local workspace_lock_state="$3"
  local python_bin="${4:-python3}"

  "${python_bin}" -I - "${repository_root}" "${destination}" \
    "${workspace_lock_state}" "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

root, destination = map(Path, sys.argv[1:3])
expected_state, expected_digest = sys.argv[3:5]
source = root / "Cargo.lock"
maximum = 16 * 1024 * 1024


def fail(message):
    raise SystemExit("error: " + message)


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns,
            metadata.st_ctime_ns)


def seal(payload, metadata):
    return ":".join((hashlib.sha256(payload).hexdigest(), str(metadata.st_dev),
                     str(metadata.st_ino), str(metadata.st_size),
                     str(metadata.st_mtime_ns), str(metadata.st_ctime_ns),
                     oct(stat.S_IMODE(metadata.st_mode))))


if not root.is_absolute() or root.resolve(strict=True) != root:
    fail("canonical graph source root must be absolute and canonical")
if source.resolve(strict=True) != source:
    fail("canonical graph source must contain no symlink components")
if (not destination.is_absolute() or destination.name != "Cargo.lock"
        or destination.parent.resolve(strict=True) != destination.parent
        or destination == source or root in destination.parents):
    fail("canonical graph snapshot must be an explicit canonical external Cargo.lock")
flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
with os.fdopen(os.open(source, flags), "rb") as stream:
    before = os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o111 or not 0 < before.st_size <= maximum):
        fail("canonical graph source must be a bounded singly linked non-executable regular file")
    payload = stream.read(maximum + 1)
    after = os.fstat(stream.fileno())
    if (identity(before) != identity(after) or len(payload) != before.st_size
            or source.resolve(strict=True) != source
            or identity(os.stat(source, follow_symlinks=False)) != identity(before)):
        fail("canonical graph source changed during materialization")
    if ("present:" + seal(payload, before) != expected_state
            or hashlib.sha256(payload).hexdigest() != expected_digest):
        fail("canonical graph source differs from its authenticated reviewed state")
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent = os.open(destination.parent, parent_flags)
    try:
        parent_before = os.fstat(parent)
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination.name, write_flags, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o400)
            written = os.fstat(output.fileno())
            if (not stat.S_ISREG(written.st_mode) or written.st_nlink != 1
                    or written.st_size != len(payload)
                    or (written.st_dev, written.st_ino) == (before.st_dev, before.st_ino)):
                fail("canonical graph snapshot has invalid independent file identity")
        parent_after = os.stat(destination.parent, follow_symlinks=False)
        if ((parent_before.st_dev, parent_before.st_ino, parent_before.st_mode)
                != (parent_after.st_dev, parent_after.st_ino, parent_after.st_mode)
                or destination.parent.resolve(strict=True) != destination.parent
                or identity(os.stat(destination, follow_symlinks=False)) != identity(written)):
            fail("canonical graph snapshot path changed during materialization")
    finally:
        os.close(parent)
    if (identity(os.fstat(stream.fileno())) != identity(before)
            or source.resolve(strict=True) != source
            or identity(os.stat(source, follow_symlinks=False)) != identity(before)):
        fail("canonical graph source changed after materialization")
PY
}

privacy_sdk_provision_ci_cargo_lock() {
  local repository_root="$1"
  local corridor_root="$2"
  local github_env_path="$3"
  local github_path_path="$4"
  local authenticated_rustup_path="$5"
  local rust_toolchain_selector="$6"
  local python_bin="${7:-python3}"
  local canonical_repository_root canonical_corridor_root
  local workspace_lock workspace_lock_state lock_directory lock_path
  local resolved_lock resolved_lock_seal
  local real_cargo real_cargo_seal real_rustc real_rustc_seal
  local real_rustdoc real_rustdoc_seal rustup_seal toolchain_bin_directory
  local rust_toolchain_path rust_toolchain_seal
  local cargo_wrapper_directory cargo_audit_path script_directory
  local cargo_config_path cargo_config_seal private_cargo_home
  local private_cargo_home_state private_cargo_registry_state
  local private_cargo_git_state
  local private_cargo_target private_cargo_target_state
  local resolved_python_path compatibility_status=0

  case "${repository_root}" in
    /*) ;;
    *)
      echo "error: privacy SDK CI repository root must be absolute" >&2
      return 1
      ;;
  esac
  case "${corridor_root}" in
    /*) ;;
    *)
      echo "error: privacy SDK CI corridor root must be absolute" >&2
      return 1
      ;;
  esac
  if [[ ! -d "${repository_root}" || -L "${repository_root}" ]]; then
    echo "error: privacy SDK CI repository root must be a real directory" >&2
    return 1
  fi
  if [[ ! -f "${github_env_path}" || -L "${github_env_path}" ]]; then
    echo "error: privacy SDK CI GITHUB_ENV must be an existing regular file" >&2
    return 1
  fi
  if [[ ! -f "${github_path_path}" || -L "${github_path_path}" ]]; then
    echo "error: privacy SDK CI GITHUB_PATH must be an existing regular file" >&2
    return 1
  fi
  case "${authenticated_rustup_path}" in
    */rustup) ;;
    *)
      echo "error: authenticated rustup must have absolute basename rustup" >&2
      return 1
      ;;
  esac
  if [[ "$(command -v rustup || true)" != "${authenticated_rustup_path}" ]]; then
    echo "error: PATH does not select the explicit authenticated rustup" >&2
    return 1
  fi
  case "${rust_toolchain_selector}" in
    1.93.1-x86_64-unknown-linux-gnu|1.93.1-aarch64-apple-darwin) ;;
    *)
      echo \
        "error: privacy SDK Rust toolchain selector must be an exact supported host-qualified 1.93.1 selector" \
        >&2
      return 1
      ;;
  esac
  if ! rustup_seal="$(
    privacy_sdk_executable_seal "${authenticated_rustup_path}" "${python_bin}"
  )"; then
    return 1
  fi

  if ! canonical_repository_root="$(cd "${repository_root}" && pwd -P)"; then
    return 1
  fi
  workspace_lock="${canonical_repository_root}/Cargo.lock"
  if ! workspace_lock_state="$(
    privacy_sdk_capture_optional_file_state \
      "${workspace_lock}" "tracked root Cargo.lock" "${python_bin}"
  )"; then
    return 1
  fi
  case "${workspace_lock_state}" in
    "present:${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}:"*) ;;
    *)
      echo "error: privacy SDK CI requires the tracked root Cargo.lock" >&2
      return 1
      ;;
  esac
  privacy_sdk_reject_cargo_policy_environment "${python_bin}" || return 1
  privacy_sdk_validate_rust_toolchain_overrides \
    "${canonical_repository_root}" \
    "${canonical_repository_root}" \
    "${python_bin}" || return 1
  if [[ -d "${canonical_repository_root}/python/iroha_python" ]]; then
    privacy_sdk_validate_rust_toolchain_overrides \
      "${canonical_repository_root}" \
      "${canonical_repository_root}/python/iroha_python" \
      "${python_bin}" || return 1
  fi
  rust_toolchain_path="${canonical_repository_root}/rust-toolchain.toml"
  if ! rust_toolchain_seal="$(
    privacy_sdk_file_seal "${rust_toolchain_path}" "${python_bin}"
  )"; then
    return 1
  fi
  privacy_sdk_validate_repository_cargo_configuration \
    "${canonical_repository_root}" \
    "${canonical_repository_root}" \
    "${python_bin}" || return 1
  cargo_config_path="${canonical_repository_root}/.cargo/config.toml"
  if ! cargo_config_seal="$(
    privacy_sdk_file_seal "${cargo_config_path}" "${python_bin}"
  )"; then
    return 1
  fi

  install -d -m 700 "${corridor_root}" || return 1
  if ! canonical_corridor_root="$(cd "${corridor_root}" && pwd -P)"; then
    return 1
  fi
  case "${canonical_corridor_root}/" in
    "${canonical_repository_root}/"*)
      echo "error: privacy SDK CI Cargo corridor must be external to the repository" >&2
      return 1
      ;;
  esac

  lock_directory="${canonical_corridor_root}/lock"
  cargo_wrapper_directory="${canonical_corridor_root}/bin"
  cargo_audit_path="${canonical_corridor_root}/cargo-audit"
  private_cargo_home="${canonical_corridor_root}/cargo-home"
  install -d -m 700 \
    "${lock_directory}" "${cargo_wrapper_directory}" || return 1
  privacy_sdk_prepare_private_cargo_home \
    "${private_cargo_home}" "${python_bin}" || return 1
  if ! private_cargo_home="$(cd "${private_cargo_home}" && pwd -P)"; then
    return 1
  fi
  if ! private_cargo_home_state="$(
    privacy_sdk_capture_directory_state "${private_cargo_home}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! private_cargo_registry_state="$(
    privacy_sdk_capture_cargo_cache_component_state \
      "${private_cargo_home}" registry "${python_bin}"
  )"; then
    return 1
  fi
  if ! private_cargo_git_state="$(
    privacy_sdk_capture_cargo_cache_component_state \
      "${private_cargo_home}" git "${python_bin}"
  )"; then
    return 1
  fi
  private_cargo_target="${canonical_corridor_root}/target"
  install -d -m 700 "${private_cargo_target}" || return 1
  if ! private_cargo_target="$(
    cd "${private_cargo_target}" && pwd -P
  )"; then
    return 1
  fi
  if ! private_cargo_target_state="$(
    privacy_sdk_capture_directory_state "${private_cargo_target}" "${python_bin}"
  )"; then
    return 1
  fi
  lock_path="${lock_directory}/Cargo.lock"
  if [[ -e "${lock_path}" || -L "${lock_path}" ]]; then
    echo "error: privacy SDK CI external Cargo.lock already exists" >&2
    return 1
  fi

  if ! real_cargo="$(
    privacy_sdk_resolve_rustup_toolchain_binary \
      "${canonical_repository_root}" cargo \
      "${rust_toolchain_seal}" \
      "${authenticated_rustup_path}" "${rustup_seal}" \
      "${rust_toolchain_selector}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! real_rustc="$(
    privacy_sdk_resolve_rustup_toolchain_binary \
      "${canonical_repository_root}" rustc \
      "${rust_toolchain_seal}" \
      "${authenticated_rustup_path}" "${rustup_seal}" \
      "${rust_toolchain_selector}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! real_rustdoc="$(
    privacy_sdk_resolve_rustup_toolchain_binary \
      "${canonical_repository_root}" rustdoc \
      "${rust_toolchain_seal}" \
      "${authenticated_rustup_path}" "${rustup_seal}" \
      "${rust_toolchain_selector}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! toolchain_bin_directory="$(dirname "${real_cargo}")"; then
    return 1
  fi
  if [[ "$(dirname "${real_rustc}")" != "${toolchain_bin_directory}" || \
    "$(dirname "${real_rustdoc}")" != "${toolchain_bin_directory}" || \
    "$(basename "${toolchain_bin_directory}")" != "bin" || \
    "$(basename "$(dirname "${toolchain_bin_directory}")")" != \
      "${rust_toolchain_selector}" || \
    "$(cd "${toolchain_bin_directory}" && pwd -P)" != \
      "${toolchain_bin_directory}" ]]; then
    echo \
      "error: authenticated Cargo, rustc, and rustdoc must share one canonical toolchain bin directory" \
      >&2
    return 1
  fi
  if ! real_cargo_seal="$(
    privacy_sdk_executable_seal "${real_cargo}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! real_rustc_seal="$(
    privacy_sdk_executable_seal "${real_rustc}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! real_rustdoc_seal="$(
    privacy_sdk_executable_seal "${real_rustdoc}" "${python_bin}"
  )"; then
    return 1
  fi

  privacy_sdk_materialize_canonical_cargo_lock \
    "${canonical_repository_root}" "${lock_path}" \
    "${workspace_lock_state}" "${python_bin}" || return 1
  resolved_lock_seal="$(privacy_sdk_file_seal "${lock_path}" "${python_bin}")" || return 1
  # Full metadata resolves all workspace packages and target dependencies. The
  # original root graph must already fit; the independent external copy is
  # evidence only. Never retry without --locked or update either lock.
  (
    set -C
    cd "${canonical_repository_root}" || exit 1
    CARGO_HOME="${private_cargo_home}" \
    CARGO_NET_OFFLINE=false \
    RUSTC="${real_rustc}" \
    RUSTDOC="${real_rustdoc}" \
      "${real_cargo}" metadata --locked --format-version 1 \
        --manifest-path "${canonical_repository_root}/Cargo.toml" \
        >"${canonical_corridor_root}/dependency-metadata.json"
  ) || compatibility_status=$?
  privacy_sdk_assert_file_seal \
    "${lock_path}" "${resolved_lock_seal}" \
    "canonical external Cargo.lock after locked compatibility validation" \
    "${python_bin}" || return 1
  if ! privacy_sdk_assert_optional_file_state \
    "${workspace_lock}" "${workspace_lock_state}" \
    "tracked root Cargo.lock" "${python_bin}"; then
    echo "error: locked graph compatibility validation changed the tracked root Cargo.lock" >&2
    return 1
  fi
  if [[ ! -f "${lock_path}" || -L "${lock_path}" ]]; then
    echo "error: canonical external Cargo.lock disappeared after locked compatibility validation" >&2
    return 1
  fi
  privacy_sdk_validate_repository_cargo_configuration \
    "${canonical_repository_root}" \
    "${canonical_repository_root}" \
    "${python_bin}" || return 1
  privacy_sdk_assert_file_seal \
    "${cargo_config_path}" \
    "${cargo_config_seal}" \
    "authenticated repository Cargo configuration" \
    "${python_bin}" || return 1
  IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH="${rust_toolchain_path}" \
  IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL="${rust_toolchain_seal}" \
  IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR="${rust_toolchain_selector}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTUP_PATH="${authenticated_rustup_path}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTUP_SEAL="${rustup_seal}" \
  IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH="${real_cargo}" \
  IROHA_PRIVACY_AUTHENTICATED_CARGO_SEAL="${real_cargo_seal}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH="${real_rustc}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTC_SEAL="${real_rustc_seal}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH="${real_rustdoc}" \
  IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_SEAL="${real_rustdoc_seal}" \
    privacy_sdk_assert_authenticated_toolchain_state \
      "${canonical_repository_root}" \
      "${canonical_repository_root}" \
      "${python_bin}" || return 1

  if [[ "${compatibility_status}" != "0" ]]; then
    echo "error: Cargo rejected locked compatibility of the canonical dependency graph" >&2
    return 1
  fi

  if ! lock_path="$(
    cd "$(dirname "${lock_path}")" && printf '%s/Cargo.lock\n' "$(pwd -P)"
  )"; then
    return 1
  fi
  if ! resolved_lock="$(
    IROHA_PRIVACY_CARGO_LOCKFILE_PATH="${lock_path}" \
      privacy_sdk_resolve_cargo_lockfile \
        "${canonical_repository_root}" "${python_bin}"
  )"; then
    return 1
  fi
  if ! resolved_lock_seal="$(
    privacy_sdk_file_seal "${resolved_lock}" "${python_bin}"
  )"; then
    return 1
  fi
  case "${resolved_lock_seal}" in
    "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}:"*) ;;
    *)
      echo \
        "error: materialized Cargo.lock does not match the canonical reviewed dependency graph" \
        >&2
      return 1
      ;;
  esac

  if ! script_directory="$(
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P
  )"; then
    return 1
  fi
  install -m 600 /dev/null "${cargo_audit_path}" || return 1
  ln -s "${script_directory}/privacy_sdk_cargo_wrapper.sh" \
    "${cargo_wrapper_directory}/cargo" || return 1
  if ! resolved_python_path="$(command -v "${python_bin}")"; then
    echo "error: privacy SDK lockfile Python executable is unavailable" >&2
    return 1
  fi

  {
    printf 'IROHA_PRIVACY_CARGO_LOCKFILE_PATH=%s\n' "${resolved_lock}"
    printf 'IROHA_JS_CARGO_LOCKFILE_PATH=%s\n' "${canonical_repository_root}/Cargo.lock"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_PATH=%s\n' "${resolved_lock}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_SEAL=%s\n' "${resolved_lock_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_WORKSPACE_CARGO_LOCK_STATE=%s\n' \
      "${workspace_lock_state}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_PATH=%s\n' "${cargo_config_path}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_CONFIG_SEAL=%s\n' "${cargo_config_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME=%s\n' "${private_cargo_home}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_HOME_DIRECTORY_STATE=%s\n' "${private_cargo_home_state}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_REGISTRY_LINK_STATE=%s\n' "${private_cargo_registry_state}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_GIT_LINK_STATE=%s\n' "${private_cargo_git_state}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR=%s\n' "${private_cargo_target}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIRECTORY_STATE=%s\n' "${private_cargo_target_state}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_PATH=%s\n' "${rust_toolchain_path}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SEAL=%s\n' "${rust_toolchain_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUST_TOOLCHAIN_SELECTOR=%s\n' "${rust_toolchain_selector}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTUP_PATH=%s\n' "${authenticated_rustup_path}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTUP_SEAL=%s\n' "${rustup_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_PATH=%s\n' "${real_cargo}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_CARGO_SEAL=%s\n' "${real_cargo_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTC_PATH=%s\n' "${real_rustc}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTC_SEAL=%s\n' "${real_rustc_seal}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_PATH=%s\n' "${real_rustdoc}"
    printf 'IROHA_PRIVACY_AUTHENTICATED_RUSTDOC_SEAL=%s\n' "${real_rustdoc_seal}"
    printf 'IROHA_PRIVACY_SDK_ROOT=%s\n' "${canonical_repository_root}"
    printf 'IROHA_PRIVACY_REAL_CARGO=%s\n' "${real_cargo}"
    printf 'IROHA_PRIVACY_CARGO_AUDIT_PATH=%s\n' "${cargo_audit_path}"
    printf 'IROHA_PRIVACY_LOCKFILE_PYTHON_BIN=%s\n' "${resolved_python_path}"
    printf 'CARGO_HOME=%s\n' "${private_cargo_home}"
    printf 'CARGO_TARGET_DIR=%s\n' "${private_cargo_target}"
    printf 'CARGO_BUILD_JOBS=1\n'
    printf 'CARGO_NET_OFFLINE=true\n'
    printf 'CARGO_INCREMENTAL=0\n'
    printf 'CARGO_ENCODED_RUSTFLAGS=\n'
  } >>"${github_env_path}" || return 1
  # GitHub prepends each GITHUB_PATH entry as it is processed. Write the sealed
  # toolchain first and the wrapper second so the effective order is
  # wrapper:sealed-toolchain:ambient: Cargo stays wrapped while literal rustc
  # and rustdoc probes resolve to the authenticated toolchain binaries.
  printf '%s\n' "${toolchain_bin_directory}" \
    >>"${github_path_path}" || return 1
  printf '%s\n' "${cargo_wrapper_directory}" \
    >>"${github_path_path}" || return 1
  printf '%s\n' "${resolved_lock}" || return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    resolve)
      [[ $# -eq 2 ]] || {
        echo "usage: $0 resolve <absolute-repository-root>" >&2
        exit 2
      }
      privacy_sdk_resolve_cargo_lockfile "$2"
      ;;
    seal)
      [[ $# -eq 2 ]] || {
        echo "usage: $0 seal <absolute-file-path>" >&2
        exit 2
      }
      privacy_sdk_file_seal "$2"
      ;;
    provision-ci)
      [[ $# -eq 7 || $# -eq 8 ]] || {
        echo "usage: $0 provision-ci <absolute-repository-root> <absolute-corridor-root> <GITHUB_ENV> <GITHUB_PATH> <absolute-rustup> <host-qualified-toolchain> [python]" >&2
        exit 2
      }
      privacy_sdk_provision_ci_cargo_lock \
        "$2" "$3" "$4" "$5" "$6" "$7" "${8:-python3}" || exit 1
      ;;
    verify-ci)
      [[ $# -eq 2 || $# -eq 3 ]] || {
        echo "usage: $0 verify-ci <absolute-repository-root> [python]" >&2
        exit 2
      }
      privacy_sdk_assert_ci_cargo_lock_state \
        "$2" "${3:-python3}" || exit 1
      privacy_sdk_assert_ci_executable_path_order || exit 1
      ;;
    *)
      echo "usage: $0 {resolve <absolute-repository-root>|seal <absolute-file-path>|provision-ci <absolute-repository-root> <absolute-corridor-root> <GITHUB_ENV> <GITHUB_PATH> <absolute-rustup> <host-qualified-toolchain> [python]|verify-ci <absolute-repository-root> [python]}" >&2
      exit 2
      ;;
  esac
fi
