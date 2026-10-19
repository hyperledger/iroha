#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
# One independently selected public signer root is embedded in every Native slice.
WALLET_RUNTIME_AUTHORITY="${MOBILE_SDK_WALLET_RUNTIME_AUTHORITY:-}"
case "$WALLET_RUNTIME_AUTHORITY" in bpng-taira-v7|cbsi-release-v1|application-release-v1) ;; *)
  echo "[-] MOBILE_SDK_WALLET_RUNTIME_AUTHORITY must be bpng-taira-v7, cbsi-release-v1, or application-release-v1" >&2
  exit 1
  ;;
esac
WALLET_RUNTIME_TRUST_PUBLIC_HEX="${MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX:-}"
if [[ ! "$WALLET_RUNTIME_TRUST_PUBLIC_HEX" =~ ^[0-9a-f]{64}$ || "$WALLET_RUNTIME_TRUST_PUBLIC_HEX" == "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  echo "[-] MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX must be one nonzero lowercase 32-byte public key" >&2
  exit 1
fi
unset \
  DYLD_INSERT_LIBRARIES \
  DYLD_LIBRARY_PATH \
  LD_LIBRARY_PATH \
  LD_PRELOAD \
  SDKROOT \
  PYTHONHOME \
  PYTHONPATH

resolve_trusted_python312() {
  local candidate canonical
  local override="${MOBILE_SDK_PYTHON_BINARY:-}"
  local candidates=()

  if [[ -n "$override" ]]; then
    if [[ "$override" != /* || ! -f "$override" || -L "$override" || ! -x "$override" ]]; then
      echo "[-] MOBILE_SDK_PYTHON_BINARY must be an absolute canonical regular executable" >&2
      return 1
    fi
    candidates=("$override")
  else
    candidates=(
      /opt/homebrew/opt/python@3.12/bin/python3.12
      /opt/homebrew/bin/python3.12
      /usr/local/opt/python@3.12/bin/python3.12
      /usr/local/bin/python3.12
      /usr/bin/python3.12
      /usr/bin/python3
    )
  fi

  for candidate in "${candidates[@]}"; do
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    if ! canonical="$(
      env -i \
        HOME=/tmp \
        PATH=/usr/bin:/bin \
        TMPDIR=/tmp \
        LANG=C.UTF-8 \
        LC_ALL=C.UTF-8 \
        "$candidate" -I -S -B -c '
import os
import pathlib
import stat
import sys

if sys.version_info[:2] != (3, 12) or not sys.flags.isolated:
    raise SystemExit(1)
if "SDKROOT" in os.environ:
    raise SystemExit(1)
resolved = pathlib.Path(sys.executable).resolve(strict=True)
metadata = resolved.stat()
if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
    raise SystemExit(1)
print(resolved)
'
    )"; then
      continue
    fi
    if [[ "$canonical" != /* || ! -f "$canonical" || -L "$canonical" || ! -x "$canonical" ]]; then
      continue
    fi
    if [[ -n "$override" && "$canonical" != "$override" ]]; then
      echo "[-] MOBILE_SDK_PYTHON_BINARY must already name its canonical executable" >&2
      return 1
    fi
    printf '%s\n' "$canonical"
    return 0
  done

  if [[ -n "$override" ]]; then
    echo "[-] MOBILE_SDK_PYTHON_BINARY must be an isolated Python 3.12 executable" >&2
  else
    echo "[-] A trusted absolute Python 3.12 executable is required" >&2
  fi
  return 1
}

PYTHON_BINARY="$(resolve_trusted_python312)" || exit 1

run_python312_clean() {
  env -i \
    HOME=/tmp \
    PATH=/usr/bin:/bin \
    TMPDIR=/tmp \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$PYTHON_BINARY" -I -S -B "$@"
}

# Build a NoritoBridge.xcframework from the Rust connect_norito_bridge crate.
# - Produces a static-library XCFramework with iOS device, universal iOS
#   simulator, and universal macOS slices so Xcode links it without trying to
#   embed/sign a framework inside simulator app bundles.
# - Links every thin archive into a real C consumer with all members loaded;
#   the host macOS consumer also exercises SHA3/SHAKE and ML-DSA/ML-KEM.
# - Bridge packaging skips the broader Norito bindings sync gate because unrelated
#   Kotlin/Java parity drift should not block rebuilding the Swift bridge artifact.
# - Requires: Python 3.12, rustup + cargo, xcodebuild, lipo, and the exact
#   externally selected Cargo target/rustc/rustdoc build envelope.
# - MOBILE_SDK_PYTHON_BINARY may select an absolute canonical Python 3.12
#   executable when the fixed Homebrew/system locators are unavailable.
# - MOBILE_SDK_RUSTUP_BINARY may select an absolute canonical, non-symbolic
#   rustup executable when the canonical home-local proxy is unavailable.
# - MOBILE_SDK_CARGO_HOME may select an existing owned canonical writable Cargo
#   cache outside source, or build/cargo-home in the local integration lane.
# - MOBILE_SDK_CARGO_INVOCATION_DIR may select a private external Cargo cwd;
#   Cargo still builds the authenticated root manifest and locked graph.
#
# Usage:
#   # Normal and CI builds select the reviewed external read-only graph.
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE"
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --bridge-version 1.0.0
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --archive-output /absolute/NoritoBridge.xcframework.zip
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --allow-dirty-source
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --ci-handoff-only
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --ci-apple-slice aarch64-apple-ios
#   scripts/build_norito_xcframework.sh --lockfile-path "$MOBILE_SDK_CARGO_LOCKFILE" --ci-handoff-only \
#     --ci-assemble-apple-slices /absolute/download/root \
#     --ci-apple-slice-sha256 aarch64-apple-ios=<sha256> [...]
#   # The explicitly local integration corridor selects the source-root lock.
#   scripts/build_norito_xcframework.sh --lockfile-path "$PWD/Cargo.lock" --local-integration --allow-dirty-source
#
# NORITO_BRIDGE_OUT_DIR and NORITO_BRIDGE_BUILD_DIR are mandatory external
# cache roots by default. Explicit --local-integration admits only the fixed
# ignored checkout lane; its output cannot enter release or archive publication.

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
# Cargo and every authenticated helper must resolve workspace state from the
# same canonical tree whose inputs are source-sealed below, regardless of the
# caller's working directory.
builtin cd "$ROOT_DIR"
CRATE_DIR="$ROOT_DIR/crates/connect_norito_bridge"
INC_DIR="$CRATE_DIR/include"
if [[ -z "${NORITO_BRIDGE_OUT_DIR:-}" || -z "${NORITO_BRIDGE_BUILD_DIR:-}" ]]; then
  echo "[-] NORITO_BRIDGE_OUT_DIR and NORITO_BRIDGE_BUILD_DIR are required external cache directories" >&2
  exit 1
fi
OUT_DIR="$NORITO_BRIDGE_OUT_DIR"
BUILD_DIR="$NORITO_BRIDGE_BUILD_DIR"
PUBLISH_ROOT=""
# This tool-only mode never enters archive, CI handoff, or release publication.
LOCAL_INTEGRATION=0
for argument in "$@"; do
  if [[ "$argument" == "--local-integration" ]]; then
    LOCAL_INTEGRATION=1
  fi
done
LOCAL_INTEGRATION_ARGS=()
if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  LOCAL_INTEGRATION_ARGS=(--local-integration)
fi

reject_retired_mode() {
  local retired_name="$1"
  local retired_presence="$2"
  if [[ "$retired_presence" == "set" ]]; then
    echo "[-] $retired_name is not part of the first-release build contract" >&2
    exit 1
  fi
}
reject_retired_mode \
  NORITO_BRIDGE_BUILD_LOCK_HELD "${NORITO_BRIDGE_BUILD_LOCK_HELD+set}"
reject_retired_mode \
  NORITO_BRIDGE_PRESERVE_CARGO_TARGETS "${NORITO_BRIDGE_PRESERVE_CARGO_TARGETS+set}"
reject_retired_mode \
  NORITO_BRIDGE_SKIP_CARGO_BUILDS "${NORITO_BRIDGE_SKIP_CARGO_BUILDS+set}"
if [[ "${CARGO_BUILD_JOBS:-}" != "1" \
    || "${CARGO_INCREMENTAL:-}" != "0" \
    || "${CARGO_NET_OFFLINE:-}" != "true" ]]; then
  echo "[-] NoritoBridge requires CARGO_BUILD_JOBS=1, CARGO_INCREMENTAL=0, CARGO_NET_OFFLINE=true" >&2
  exit 1
fi
if [[ "${RUSTC_BOOTSTRAP+set}" == "set" ]]; then
  echo "[-] NoritoBridge requires stock Cargo; RUSTC_BOOTSTRAP must be unset" >&2
  exit 1
fi
if [[ -z "${CARGO_TARGET_DIR:-}" || -z "${RUSTC:-}" || -z "${RUSTDOC:-}" ]]; then
  echo "[-] NoritoBridge requires explicit CARGO_TARGET_DIR, RUSTC, and RUSTDOC" >&2
  exit 1
fi
if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  CARGO_TARGET_DIR="$(run_python312_clean "$ROOT_DIR/scripts/norito_bridge_local_integration.py" \
    --root "$ROOT_DIR" --path "$CARGO_TARGET_DIR" --role cargo)" || exit 1
else
CARGO_TARGET_DIR="$(run_python312_clean - "$CARGO_TARGET_DIR" "$ROOT_DIR" <<'PY'
import os
from pathlib import Path
import stat
import sys

candidate = Path(sys.argv[1])
source_root = Path(sys.argv[2])
if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
    raise SystemExit("CARGO_TARGET_DIR must be an absolute canonical directory")
try:
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
except OSError:
    raise SystemExit("CARGO_TARGET_DIR must already exist") from None
if (
    resolved != candidate
    or stat.S_ISLNK(metadata.st_mode)
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or not os.access(candidate, os.R_OK | os.W_OK | os.X_OK)
    or candidate == source_root
    or source_root in candidate.parents
):
    raise SystemExit(
        "CARGO_TARGET_DIR must be one writable, non-symbolic canonical directory "
        "outside the Iroha source tree"
    )
print(candidate)
PY
)" || exit 1
fi
export CARGO_TARGET_DIR

canonical_writable_directory() {
  if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
    local role=artifact
    [[ "$2" != "NORITO_BRIDGE_BUILD_DIR" ]] || role=build
    run_python312_clean "$ROOT_DIR/scripts/norito_bridge_local_integration.py" \
      --root "$ROOT_DIR" --path "$1" --role "$role"
    return
  fi
  run_python312_clean - "$1" "$2" "$ROOT_DIR" <<'PY'
import os
from pathlib import Path
import stat
import sys

candidate = Path(sys.argv[1])
label = sys.argv[2]
source_root = Path(sys.argv[3])
if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
    raise SystemExit(f"{label} must be an absolute canonical directory")
try:
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
except OSError:
    raise SystemExit(f"{label} must already exist") from None
if (
    resolved != candidate
    or stat.S_ISLNK(metadata.st_mode)
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or not os.access(candidate, os.R_OK | os.W_OK | os.X_OK)
    or candidate == source_root
    or source_root in candidate.parents
):
    raise SystemExit(
        f"{label} must be a writable, non-symbolic canonical directory "
        "outside the Iroha source tree"
    )
print(candidate)
PY
}
OUT_DIR="$(canonical_writable_directory "$OUT_DIR" NORITO_BRIDGE_OUT_DIR)" || exit 1
BUILD_DIR="$(canonical_writable_directory "$BUILD_DIR" NORITO_BRIDGE_BUILD_DIR)" || exit 1
paths_overlap() {
  [[ "$1" == "$2" || "$1" == "$2"/* || "$2" == "$1"/* ]]
}
if paths_overlap "$CARGO_TARGET_DIR" "$BUILD_DIR" \
    || paths_overlap "$CARGO_TARGET_DIR" "$OUT_DIR" \
    || paths_overlap "$BUILD_DIR" "$OUT_DIR"; then
  echo "[-] NoritoBridge Cargo target, build, and output directories must be pairwise disjoint" >&2
  exit 1
fi
STAGE_DIR="$BUILD_DIR/stage"

TARGET_BUILD_LOCK="$CARGO_TARGET_DIR/.NoritoBridge.cargo.lockfile"
STAGE_BUILD_LOCK="$BUILD_DIR/.NoritoBridge.stage.lockfile"
OUTPUT_PUBLISH_LOCK="$OUT_DIR/.NoritoBridge.publish.lockfile"
LOCK_DESCRIPTOR_ENV=NORITO_BRIDGE_BUILD_LOCK_FDS
if [[ -z "${NORITO_BRIDGE_BUILD_LOCK_FDS:-}" ]]; then
  LOCK_RUNNER="$ROOT_DIR/scripts/exec_with_file_lock.py"
  [[ -f "$LOCK_RUNNER" && ! -L "$LOCK_RUNNER" ]] || {
    echo "[-] NoritoBridge build lock runner is unavailable: $LOCK_RUNNER" >&2
    exit 1
  }
  exec "$PYTHON_BINARY" -I -S -B "$LOCK_RUNNER" \
    "$LOCK_DESCRIPTOR_ENV" \
    "$TARGET_BUILD_LOCK" "$STAGE_BUILD_LOCK" "$OUTPUT_PUBLISH_LOCK" \
    -- \
    "$SCRIPT_DIR/build_norito_xcframework.sh" "$@"
fi
NORITO_BRIDGE_OUTPUT_LOCK_FD="$(run_python312_clean - \
  "$NORITO_BRIDGE_BUILD_LOCK_FDS" \
  "$OUTPUT_PUBLISH_LOCK" \
  "$TARGET_BUILD_LOCK" "$STAGE_BUILD_LOCK" "$OUTPUT_PUBLISH_LOCK" <<'PY'
import fcntl
import os
from pathlib import Path
import stat
import sys


descriptors = sys.argv[1].split(",")
output_lock = Path(sys.argv[2])
lock_paths = sorted((Path(value) for value in sys.argv[3:]), key=os.fspath)
if len(descriptors) != len(lock_paths) or any(not value.isdecimal() for value in descriptors):
    raise SystemExit("NoritoBridge build lock descriptor inventory is malformed")
for raw_descriptor, lock_path in zip(descriptors, lock_paths, strict=True):
    descriptor = int(raw_descriptor)
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = lock_path.lstat()
    except OSError as error:
        raise SystemExit(f"NoritoBridge build lock is unavailable: {error}") from None
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or descriptor_metadata.st_nlink != 1
        or descriptor_metadata.st_uid != os.geteuid()
        or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise SystemExit(f"NoritoBridge build lock is not authenticated: {lock_path}")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise SystemExit(f"NoritoBridge build lock is not held: {lock_path}: {error}") from None
print(descriptors[lock_paths.index(output_lock)])
PY
)" || exit 1
export NORITO_BRIDGE_OUTPUT_LOCK_FD

LIB_CRATE_NAME="connect_norito_bridge"
FRAMEWORK_NAME="NoritoBridge"
STATIC_LIB_NAME="libNoritoBridge.a"
cleanup_build_state() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ -n "$PUBLISH_ROOT" && -d "$PUBLISH_ROOT" \
    && "${PUBLISH_ROOT##*/}" == .NoritoBridge.publish.* ]]; then
    rm -rf -- "$PUBLISH_ROOT"
  fi
  exit "$status"
}
trap cleanup_build_state EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

set_fixed_deployment_target() {
  local deployment_name="$1"
  local deployment_value="$2"
  local ambient_presence="$3"
  local ambient_value="$4"
  if [[ "$ambient_presence" == "set" && "$ambient_value" != "$deployment_value" ]]; then
    echo "[-] $deployment_name is fixed at $deployment_value for the first release" >&2
    exit 1
  fi
  printf -v "$deployment_name" '%s' "$deployment_value"
  export "$deployment_name"
}
set_fixed_deployment_target \
  IPHONEOS_DEPLOYMENT_TARGET 15.0 \
  "${IPHONEOS_DEPLOYMENT_TARGET+set}" "${IPHONEOS_DEPLOYMENT_TARGET-}"
set_fixed_deployment_target \
  IPHONESIMULATOR_DEPLOYMENT_TARGET 15.0 \
  "${IPHONESIMULATOR_DEPLOYMENT_TARGET+set}" "${IPHONESIMULATOR_DEPLOYMENT_TARGET-}"
set_fixed_deployment_target \
  MACOSX_DEPLOYMENT_TARGET 12.0 \
  "${MACOSX_DEPLOYMENT_TARGET+set}" "${MACOSX_DEPLOYMENT_TARGET-}"
readonly IPHONEOS_DEPLOYMENT_TARGET
readonly IPHONESIMULATOR_DEPLOYMENT_TARGET
readonly MACOSX_DEPLOYMENT_TARGET
export IPHONEOS_DEPLOYMENT_TARGET
export IPHONESIMULATOR_DEPLOYMENT_TARGET
export MACOSX_DEPLOYMENT_TARGET

BRIDGE_VERSION=""
ARCHIVE_OUTPUT=""
ALLOW_DIRTY_SOURCE=0
CI_HANDOFF_ONLY=0
CI_APPLE_SLICE=""
CI_ASSEMBLE_APPLE_SLICES=""
CI_APPLE_SLICE_SHA256=()
CARGO_LOCKFILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lockfile-path)
      shift
      if [[ -n "$CARGO_LOCKFILE" || -z "${1:-}" ]]; then
        echo "error: --lockfile-path requires exactly one explicit value" >&2
        exit 64
      fi
      CARGO_LOCKFILE="$1"
      ;;
    --bridge-version)
      shift
      BRIDGE_VERSION="${1:-}"
      if [[ -z "$BRIDGE_VERSION" ]]; then
        echo "[-] --bridge-version requires a value" >&2
        exit 1
      fi
      ;;
    --bridge-version=*)
      BRIDGE_VERSION="${1#*=}"
      ;;
    --archive-output)
      shift
      ARCHIVE_OUTPUT="${1:-}"
      if [[ -z "$ARCHIVE_OUTPUT" ]]; then
        echo "[-] --archive-output requires a value" >&2
        exit 1
      fi
      ;;
    --archive-output=*)
      ARCHIVE_OUTPUT="${1#*=}"
      if [[ -z "$ARCHIVE_OUTPUT" ]]; then
        echo "[-] --archive-output requires a value" >&2
        exit 1
      fi
      ;;
    --local-integration) ;;
    --allow-dirty-source)
      ALLOW_DIRTY_SOURCE=1
      ;;
    --ci-handoff-only)
      CI_HANDOFF_ONLY=1
      ;;
    --ci-apple-slice)
      shift
      CI_APPLE_SLICE="${1:-}"
      if [[ -z "$CI_APPLE_SLICE" ]]; then
        echo "[-] --ci-apple-slice requires a target triple" >&2
        exit 1
      fi
      ;;
    --ci-apple-slice=*)
      CI_APPLE_SLICE="${1#*=}"
      if [[ -z "$CI_APPLE_SLICE" ]]; then
        echo "[-] --ci-apple-slice requires a target triple" >&2
        exit 1
      fi
      ;;
    --ci-assemble-apple-slices)
      shift
      CI_ASSEMBLE_APPLE_SLICES="${1:-}"
      if [[ -z "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
        echo "[-] --ci-assemble-apple-slices requires an absolute directory" >&2
        exit 1
      fi
      ;;
    --ci-assemble-apple-slices=*)
      CI_ASSEMBLE_APPLE_SLICES="${1#*=}"
      if [[ -z "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
        echo "[-] --ci-assemble-apple-slices requires an absolute directory" >&2
        exit 1
      fi
      ;;
    --ci-apple-slice-sha256)
      shift
      if [[ -z "${1:-}" ]]; then
        echo "[-] --ci-apple-slice-sha256 requires target=digest" >&2
        exit 1
      fi
      CI_APPLE_SLICE_SHA256+=("$1")
      ;;
    --ci-apple-slice-sha256=*)
      if [[ -z "${1#*=}" ]]; then
        echo "[-] --ci-apple-slice-sha256 requires target=digest" >&2
        exit 1
      fi
      CI_APPLE_SLICE_SHA256+=("${1#*=}")
      ;;
    *)
      echo "[-] Unknown argument: $1" >&2
      echo "    Usage: $0 --lockfile-path <absolute-path> [--bridge-version <version>] [--archive-output <absolute-path>] [--allow-dirty-source] [--local-integration] [--ci-handoff-only] [--ci-apple-slice <target>] [--ci-assemble-apple-slices <absolute-dir> --ci-apple-slice-sha256 <target=digest> ...]" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ -z "$CARGO_LOCKFILE" ]]; then
  echo "error: --lockfile-path is required; no implicit Cargo.lock selection" >&2
  exit 64
fi

CI_HANDOFF_DIR="$OUT_DIR/NoritoBridge.ci-handoff"
CI_APPLE_SLICE_ARCHIVE="$OUT_DIR/NoritoBridge.apple-slice.tar"
if [[ -n "$CI_APPLE_SLICE" ]]; then
  if [[ "$CI_HANDOFF_ONLY" == "1" \
      || -n "$CI_ASSEMBLE_APPLE_SLICES" \
      || "${#CI_APPLE_SLICE_SHA256[@]}" -ne 0 \
      || -n "$ARCHIVE_OUTPUT" \
      || -n "$BRIDGE_VERSION" \
      || "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
    echo "[-] --ci-apple-slice is a standalone clean-source producer mode" >&2
    exit 1
  fi
  case "$CI_APPLE_SLICE" in
    aarch64-apple-ios)
      expected_slice_job=swift_slice_ios_device
      ;;
    aarch64-apple-ios-sim)
      expected_slice_job=swift_slice_ios_sim_arm
      ;;
    x86_64-apple-ios)
      expected_slice_job=swift_slice_ios_sim_x64
      ;;
    aarch64-apple-darwin)
      expected_slice_job=swift_slice_macos_arm
      ;;
    x86_64-apple-darwin)
      expected_slice_job=swift_slice_macos_x64
      ;;
    *)
      echo "[-] --ci-apple-slice names an unsupported target: $CI_APPLE_SLICE" >&2
      exit 1
      ;;
  esac
  if [[ "${CI:-}" != "true" \
      || "${GITHUB_ACTIONS:-}" != "true" \
      || "${GITHUB_WORKFLOW:-}" != "Mobile SDK Artifacts" \
      || "${GITHUB_JOB:-}" != "$expected_slice_job" \
      || "${GITHUB_WORKSPACE:-}" != "$ROOT_DIR" \
      || "${MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT:-}" != "1" ]]; then
    echo "[-] --ci-apple-slice is restricted to its authenticated mobile SDK producer" >&2
    exit 1
  fi
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | workflow_dispatch) ;;
    *)
      echo "[-] --ci-apple-slice requires a pull_request or workflow_dispatch event" >&2
      exit 1
      ;;
  esac
  if [[ -e "$CI_APPLE_SLICE_ARCHIVE" || -L "$CI_APPLE_SLICE_ARCHIVE" ]]; then
    echo "[-] CI Apple slice archive must not already exist: $CI_APPLE_SLICE_ARCHIVE" >&2
    exit 1
  fi
fi
if [[ -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
  if [[ "$CI_HANDOFF_ONLY" != "1" || "${#CI_APPLE_SLICE_SHA256[@]}" -ne 5 ]]; then
    echo "[-] --ci-assemble-apple-slices requires --ci-handoff-only and five slice digests" >&2
    exit 1
  fi
elif [[ "${#CI_APPLE_SLICE_SHA256[@]}" -ne 0 ]]; then
  echo "[-] --ci-apple-slice-sha256 requires --ci-assemble-apple-slices" >&2
  exit 1
fi
if [[ "$CI_HANDOFF_ONLY" == "1" ]]; then
  if [[ -n "$ARCHIVE_OUTPUT" || "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
    echo "[-] --ci-handoff-only cannot publish an archive or use dirty source" >&2
    exit 1
  fi
  if [[ "${CI:-}" != "true" \
      || "${GITHUB_ACTIONS:-}" != "true" \
      || "${GITHUB_WORKFLOW:-}" != "Mobile SDK Artifacts" \
      || "${GITHUB_JOB:-}" != "swift" \
      || "${GITHUB_WORKSPACE:-}" != "$ROOT_DIR" \
      || "${MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT:-}" != "1" ]]; then
    echo "[-] --ci-handoff-only is restricted to the authenticated Swift SDK producer" >&2
    exit 1
  fi
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | workflow_dispatch) ;;
    *)
      echo "[-] --ci-handoff-only requires a pull_request or workflow_dispatch event" >&2
      exit 1
      ;;
  esac
  if [[ -e "$CI_HANDOFF_DIR" || -L "$CI_HANDOFF_DIR" ]]; then
    echo "[-] CI handoff candidate must not already exist: $CI_HANDOFF_DIR" >&2
    exit 1
  fi
  for canonical_output in \
    "$OUT_DIR/NoritoBridge.xcframework" \
    "$OUT_DIR/NoritoBridge.artifacts.json"; do
    if [[ -e "$canonical_output" || -L "$canonical_output" ]]; then
      echo "[-] --ci-handoff-only requires canonical release outputs to remain absent" >&2
      exit 1
    fi
  done
fi

if [[ "$LOCAL_INTEGRATION" == "1" ]] && \
    [[ -n "$ARCHIVE_OUTPUT" || "$CI_HANDOFF_ONLY" == "1" || -n "$CI_APPLE_SLICE" \
      || -n "$CI_ASSEMBLE_APPLE_SLICES" || "${#CI_APPLE_SLICE_SHA256[@]}" != "0" \
      || "${MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT:-0}" == "1" \
      || -n "${IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH+x}" ]]; then
  echo "[-] Local integration cannot archive, hand off, or enter a release corridor" >&2
  exit 1
fi
if [[ -n "$ARCHIVE_OUTPUT" ]]; then
  ARCHIVE_OUTPUT="$(run_python312_clean - \
    "$ARCHIVE_OUTPUT" "${SOURCE_DATE_EPOCH:-}" "$ROOT_DIR" <<'PY'
import os
from pathlib import Path
import re
import stat
import sys

output = Path(sys.argv[1])
source_date_epoch = sys.argv[2]
source_root = Path(sys.argv[3])
if re.fullmatch(r"0|[1-9][0-9]*", source_date_epoch) is None:
    raise SystemExit(
        "SOURCE_DATE_EPOCH must be an explicit canonical unsigned integer "
        "with --archive-output"
    )
epoch = int(source_date_epoch, 10)
if not 315_532_800 <= epoch <= 4_354_819_199:
    raise SystemExit("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
if (
    not output.is_absolute()
    or output != Path(os.path.abspath(output))
    or output.name in {"", ".", ".."}
    or output.suffix != ".zip"
):
    raise SystemExit("--archive-output must be an absolute canonical .zip filename")
try:
    parent_metadata = output.parent.lstat()
    canonical_parent = output.parent.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"--archive-output parent is unavailable: {error}") from None
if (
    canonical_parent != output.parent
    or stat.S_ISLNK(parent_metadata.st_mode)
    or not stat.S_ISDIR(parent_metadata.st_mode)
    or not os.access(output.parent, os.R_OK | os.W_OK | os.X_OK)
    or output.parent == source_root
    or source_root in output.parent.parents
):
    raise SystemExit(
        "--archive-output parent must be a writable canonical directory "
        "outside the Iroha source tree"
    )
try:
    metadata = output.lstat()
except FileNotFoundError:
    pass
else:
    raise SystemExit("--archive-output must not already exist")
print(output)
PY
)" || exit 1
fi

# The bridge support and its provenance profile are mandatory for every slice.
CARGO_FEATURE_ARGS=(--features privacy-production-enabled)
PINNED_RUST_TOOLCHAIN="1.93.1"
SOURCE_SEAL_SCRIPT="$ROOT_DIR/scripts/norito_bridge_source_seal.py"
CARGO_GRAPH_OWNER="$ROOT_DIR/ci/privacy_sdk_cargo_lockfile.sh"
PIN_COMMIT_CHECKER="$ROOT_DIR/scripts/check_mobile_sdk_artifact_pin_commit.py"
HERMETIC_RUNNER="$ROOT_DIR/scripts/run_mobile_hermetic_command.py"
APPLE_SLICE_HANDOFF="$ROOT_DIR/scripts/norito_bridge_apple_slice_handoff.py"
PQCRYPTO_ARCHIVE_NORMALIZER="$ROOT_DIR/scripts/normalize_pqcrypto_archive.py"
USER_HOME_DIR="$(run_python312_clean -c \
  'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
USER_HOME_DIR="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$USER_HOME_DIR")"
GIT_BINARY="/usr/bin/git"
if [[ -n "${MOBILE_SDK_RUSTUP_BINARY+x}" ]]; then
  RUSTUP_BINARY="$MOBILE_SDK_RUSTUP_BINARY"
  if [[ -z "$RUSTUP_BINARY" || "$RUSTUP_BINARY" != /* ]]; then
    echo "[-] MOBILE_SDK_RUSTUP_BINARY must be an absolute canonical non-symbolic executable" >&2
    exit 1
  fi
  if ! canonical_rustup_binary="$(run_python312_clean -c \
      'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
      "$RUSTUP_BINARY")" \
      || [[ "$canonical_rustup_binary" != "$RUSTUP_BINARY" ]]; then
    echo "[-] MOBILE_SDK_RUSTUP_BINARY must be an absolute canonical non-symbolic executable" >&2
    exit 1
  fi
else
  RUSTUP_BINARY="$USER_HOME_DIR/.cargo/bin/rustup"
fi
for tool_path in "$PYTHON_BINARY" "$GIT_BINARY" "$RUSTUP_BINARY"; do
  [[ -f "$tool_path" && ! -L "$tool_path" && -x "$tool_path" ]] || {
    echo "[-] Pinned Python, Git, and rustup executables are required: $tool_path" >&2
    exit 1
  }
done
for required_input in \
  "$SOURCE_SEAL_SCRIPT" \
  "$CARGO_GRAPH_OWNER" \
  "$PIN_COMMIT_CHECKER" \
  "$HERMETIC_RUNNER" \
  "$APPLE_SLICE_HANDOFF" \
  "$PQCRYPTO_ARCHIVE_NORMALIZER" \
  "$ROOT_DIR/rust-toolchain.toml"; do
  [[ -f "$required_input" && ! -L "$required_input" ]] || {
    echo "[-] Required NoritoBridge build input is unavailable: $required_input" >&2
    exit 1
  }
done
ACTUAL_RUST_TOOLCHAIN="$(
  sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' \
    "$ROOT_DIR/rust-toolchain.toml"
)"
if [[ "$ACTUAL_RUST_TOOLCHAIN" != "$PINNED_RUST_TOOLCHAIN" ]]; then
  echo "[-] NoritoBridge production builds require exact Rust $PINNED_RUST_TOOLCHAIN" >&2
  exit 1
fi

resolve_mobile_cargo_home() {
  if [[ "${MOBILE_SDK_CARGO_HOME+x}" != "x" ]]; then
    printf '%s\n' "$USER_HOME_DIR/.cargo"
    return
  fi
  run_python312_clean "$ROOT_DIR/scripts/norito_bridge_local_integration.py" \
    --root "$ROOT_DIR" --path "$MOBILE_SDK_CARGO_HOME" --role cargo-home \
    "${LOCAL_INTEGRATION_ARGS[@]+"${LOCAL_INTEGRATION_ARGS[@]}"}"
}
MOBILE_CARGO_HOME="$(resolve_mobile_cargo_home)" || exit 1
if [[ "${MOBILE_SDK_CARGO_HOME+x}" == "x" ]]; then
  for cache_peer in "$CARGO_TARGET_DIR" "$BUILD_DIR" "$OUT_DIR"; do
    if [[ "$LOCAL_INTEGRATION" == "1" && "$cache_peer" == "$BUILD_DIR" \
        && "$MOBILE_CARGO_HOME" == "$BUILD_DIR/cargo-home" ]]; then
      continue
    fi
    if paths_overlap "$MOBILE_CARGO_HOME" "$cache_peer"; then
      echo "[-] MOBILE_SDK_CARGO_HOME must be disjoint from Cargo target, build, and output roots" >&2
      exit 1
    fi
  done
fi
MOBILE_CARGO_INVOCATION_DIR="$ROOT_DIR"
MOBILE_CARGO_INVOCATION_ARGS=()
if [[ "${MOBILE_SDK_CARGO_INVOCATION_DIR+x}" == "x" ]]; then
  MOBILE_CARGO_INVOCATION_DIR="$(run_python312_clean \
    "$ROOT_DIR/scripts/norito_bridge_local_integration.py" --root "$ROOT_DIR" \
    --path "$MOBILE_SDK_CARGO_INVOCATION_DIR" --role cargo-invocation)" || exit 1
  MOBILE_CARGO_INVOCATION_ARGS=(--working-directory "$MOBILE_CARGO_INVOCATION_DIR")
fi
MOBILE_RUSTUP_HOME="$USER_HOME_DIR/.rustup"
MOBILE_TMPDIR="/tmp"
if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  MOBILE_TMPDIR="$BUILD_DIR"
fi
for directory in "$USER_HOME_DIR" "$MOBILE_CARGO_HOME" "$MOBILE_RUSTUP_HOME" "$MOBILE_TMPDIR"; do
  [[ "$directory" == /* ]] || {
    echo "[-] NoritoBridge build directories must be absolute: $directory" >&2
    exit 1
  }
done
RUSTUP_ENV=(
  HOME="$USER_HOME_DIR"
  PATH="${RUSTUP_BINARY%/*}:/usr/bin:/bin"
  RUSTUP_HOME="$MOBILE_RUSTUP_HOME"
  CARGO_HOME="$MOBILE_CARGO_HOME"
  TMPDIR="$MOBILE_TMPDIR"
  LANG=C.UTF-8
  LC_ALL=C.UTF-8
)
CARGO_BINARY="$(
  env -i "${RUSTUP_ENV[@]}" \
    "$RUSTUP_BINARY" which --toolchain "$PINNED_RUST_TOOLCHAIN" cargo
)"
RUSTC_BINARY="$(
  env -i "${RUSTUP_ENV[@]}" \
    "$RUSTUP_BINARY" which --toolchain "$PINNED_RUST_TOOLCHAIN" rustc
)"
RUSTDOC_BINARY="$(
  env -i "${RUSTUP_ENV[@]}" \
    "$RUSTUP_BINARY" which --toolchain "$PINNED_RUST_TOOLCHAIN" rustdoc
)"
CARGO_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$CARGO_BINARY")"
RUSTC_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$RUSTC_BINARY")"
RUSTDOC_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$RUSTDOC_BINARY")"
[[ -x "$CARGO_BINARY" && -x "$RUSTC_BINARY" && -x "$RUSTDOC_BINARY" ]] || {
  echo "[-] Exact Rust $PINNED_RUST_TOOLCHAIN Cargo/rustc/rustdoc executables are unavailable" >&2
  exit 1
}
for supplied_tool in RUSTC RUSTDOC; do
  expected_tool="${supplied_tool}_BINARY"
  if [[ "${!supplied_tool}" != "${!expected_tool}" \
      || ! -f "${!supplied_tool}" || -L "${!supplied_tool}" \
      || ! -x "${!supplied_tool}" ]]; then
    echo "[-] $supplied_tool must be the canonical Rust $PINNED_RUST_TOOLCHAIN executable: ${!expected_tool}" >&2
    exit 1
  fi
done

run_source_seal() {
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${PYTHON_BINARY%/*}:${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:${RUSTDOC_BINARY%/*}:${GIT_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    NORITO_BRIDGE_SEAL_HOME="$USER_HOME_DIR" \
    NORITO_BRIDGE_SEAL_CARGO_HOME="$MOBILE_CARGO_HOME" \
    NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR="$MOBILE_CARGO_INVOCATION_DIR" \
    NORITO_BRIDGE_SEAL_RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
    NORITO_BRIDGE_SEAL_TMPDIR="$MOBILE_TMPDIR" \
    NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    NORITO_BRIDGE_SEAL_CARGO="$CARGO_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTC="$RUSTC_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTDOC="$RUSTDOC_BINARY" \
    "$PYTHON_BINARY" -I -S -B "$SOURCE_SEAL_SCRIPT" "$@"
}

run_source_git() {
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${GIT_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    "$GIT_BINARY" "$@"
}

run_isolated_python() {
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${PYTHON_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$PYTHON_BINARY" -I -S -B "$@"
}

selected_cargo_lock_sha256() {
  run_isolated_python - "$SOURCE_SEAL_SCRIPT" "$CARGO_LOCKFILE" "$LOCAL_INTEGRATION" "$ROOT_DIR" <<'PY_LOCK'
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("norito_bridge_selected_lock_owner", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit("selected Cargo lock owner is unavailable")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
try:
    selected = owner.selected_lockfile_path(Path(sys.argv[4]), Path(sys.argv[2]))
    identity = owner.lockfile_identity(selected)
except RuntimeError as error:
    raise SystemExit(str(error)) from error
if sys.argv[3] == "1" and selected != Path(sys.argv[4]) / "Cargo.lock":
    raise SystemExit("local integration requires the explicitly selected root Cargo.lock")
if sys.argv[3] != "1" and identity[2] & 0o222:
    raise SystemExit("privacy production selected Cargo lock must be read-only")
print(identity[-1])
PY_LOCK
}

CARGO_LOCK_SHA256_START="$(selected_cargo_lock_sha256)"
source "$CARGO_GRAPH_OWNER"
if [[ "$LOCAL_INTEGRATION" != "1" \
      && "$CARGO_LOCKFILE" == "$ROOT_DIR/Cargo.lock" ]]; then
  echo "[-] Privacy production builds require an explicit external canonical graph snapshot" >&2
  exit 1
fi
if [[ "$CARGO_LOCKFILE" != "$ROOT_DIR/Cargo.lock" ]]; then
  if [[ "$CARGO_LOCK_SHA256_START" != "$PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256" ]]; then
    echo "[-] External Cargo.lock must match the canonical reviewed graph" >&2
    exit 1
  fi
fi

assert_selected_cargo_lock() {
  local phase="$1"
  local current_digest
  if ! current_digest="$(selected_cargo_lock_sha256)"; then
    echo "[-] Selected Cargo lock became unreadable during $phase" >&2
    exit 1
  fi
  if [[ "$current_digest" != "$CARGO_LOCK_SHA256_START" ]]; then
    echo "[-] Selected Cargo lock changed during $phase" >&2
    exit 1
  fi
}

bridge_source_fingerprint() {
  run_source_seal fingerprint --root "$ROOT_DIR" --platform apple \
    --lockfile-path "$CARGO_LOCKFILE"
}

bridge_source_status() {
  run_source_seal status --root "$ROOT_DIR" --platform apple \
    --lockfile-path "$CARGO_LOCKFILE"
}

assert_selected_cargo_lock "initial source authentication"
SOURCE_COMMIT_START=$(run_source_git -C "$ROOT_DIR" rev-parse --verify HEAD)
SOURCE_STATUS_START=$(bridge_source_status)
SOURCE_FINGERPRINT_START=$(bridge_source_fingerprint)
assert_selected_cargo_lock "initial source authentication"
if [[ -n "$SOURCE_STATUS_START" && "$ALLOW_DIRTY_SOURCE" != "1" ]]; then
  echo "[-] NoritoBridge production artifacts require a clean dependency-closure source tree" >&2
  echo "    Commit the bridge inputs or pass --allow-dirty-source for a fingerprint-bound local integration artifact." >&2
  exit 1
fi
SOURCE_COMMIT="$SOURCE_COMMIT_START"
EMBEDDED_SOURCE_COMMIT="$(
  run_isolated_python "$PIN_COMMIT_CHECKER" \
    --root "$ROOT_DIR" \
    --print-embedded-source-commit
)"
if [[ ! "$EMBEDDED_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "[-] NoritoBridge embedded source commit is not canonical" >&2
  exit 1
fi
SOURCE_TREE_DIRTY=false
if [[ -n "$SOURCE_STATUS_START" ]]; then
  SOURCE_TREE_DIRTY=true
fi
SOURCE_FINGERPRINT="$SOURCE_FINGERPRINT_START"
CARGO_FEATURES_JSON='["privacy-production-enabled"]'

assert_bridge_source_seal() {
  local phase="$1"
  local current_commit current_status current_fingerprint
  assert_selected_cargo_lock "$phase"
  if ! current_commit=$(run_source_git -C "$ROOT_DIR" rev-parse --verify HEAD) \
      || ! current_status=$(bridge_source_status) \
      || ! current_fingerprint=$(bridge_source_fingerprint); then
    echo "[-] NoritoBridge source became unreadable during $phase; refusing mixed-source Apple slices" >&2
    exit 1
  fi
  if [[ "$current_commit" != "$SOURCE_COMMIT_START" \
      || "$current_status" != "$SOURCE_STATUS_START" \
      || "$current_fingerprint" != "$SOURCE_FINGERPRINT_START" ]]; then
    echo "[-] NoritoBridge source changed during $phase; refusing mixed-source Apple slices" >&2
    exit 1
  fi
  assert_selected_cargo_lock "$phase"
}

if [[ "${NORITO_BRIDGE_SOURCE_SEAL_TEST_ONLY:-0}" == "1" ]]; then
  if [[ -n "${NORITO_BRIDGE_SOURCE_SEAL_TEST_MUTATE:-}" ]]; then
    printf '\nsource-seal-negative-test\n' >> \
      "$ROOT_DIR/$NORITO_BRIDGE_SOURCE_SEAL_TEST_MUTATE"
  fi
  assert_bridge_source_seal "source-seal self-test"
  exit 0
fi

sha256_file() {
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${PYTHON_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$PYTHON_BINARY" -I -S -B - "$1" <<'PY'
from pathlib import Path
import hashlib
import sys

path = Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

PYTHON_VERSION="$(run_python312_clean -c \
  'import platform; print(platform.python_version())')"
GIT_VERSION="$(
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH=/usr/bin:/bin \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$GIT_BINARY" --version \
      | sed -nE 's/^git version ([0-9]+(\.[0-9]+){1,3}).*/\1/p'
)"
RUSTUP_VERSION="$(
  env -i "${RUSTUP_ENV[@]}" "$RUSTUP_BINARY" --version \
    | sed -nE '1s/^rustup ([0-9]+(\.[0-9]+){1,2}).*/\1/p'
)"
for tool_version in "$PYTHON_VERSION" "$RUSTUP_VERSION"; do
  [[ "$tool_version" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || {
    echo "[-] Native build tool returned a non-canonical version: $tool_version" >&2
    exit 1
  }
done
[[ "$GIT_VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || {
  echo "[-] Git returned a non-canonical version: $GIT_VERSION" >&2
  exit 1
}
PYTHON_BINARY_SHA256="$(sha256_file "$PYTHON_BINARY")"
GIT_BINARY_SHA256="$(sha256_file "$GIT_BINARY")"
RUSTUP_BINARY_SHA256="$(sha256_file "$RUSTUP_BINARY")"
HERMETIC_RUNNER_SHA256="$(sha256_file "$HERMETIC_RUNNER")"

CARGO_VERSION_VERBOSE="$(
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:/usr/bin:/bin" \
    RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
    CARGO_HOME="$MOBILE_CARGO_HOME" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$CARGO_BINARY" --version --verbose
)"
RUSTC_VERSION_VERBOSE="$(
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:/usr/bin:/bin" \
    RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
    CARGO_HOME="$MOBILE_CARGO_HOME" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$RUSTC_BINARY" --version --verbose
)"
RUSTDOC_VERSION_VERBOSE="$(
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:${RUSTDOC_BINARY%/*}:/usr/bin:/bin" \
    RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
    CARGO_HOME="$MOBILE_CARGO_HOME" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$RUSTDOC_BINARY" --version --verbose
)"
CARGO_RELEASE="$(sed -n 's/^release: //p' <<<"$CARGO_VERSION_VERBOSE")"
CARGO_COMMIT_HASH="$(sed -n 's/^commit-hash: //p' <<<"$CARGO_VERSION_VERBOSE")"
RUSTC_RELEASE="$(sed -n 's/^release: //p' <<<"$RUSTC_VERSION_VERBOSE")"
RUSTC_COMMIT_HASH="$(sed -n 's/^commit-hash: //p' <<<"$RUSTC_VERSION_VERBOSE")"
RUSTDOC_RELEASE="$(sed -n 's/^release: //p' <<<"$RUSTDOC_VERSION_VERBOSE")"
RUSTDOC_COMMIT_HASH="$(sed -n 's/^commit-hash: //p' <<<"$RUSTDOC_VERSION_VERBOSE")"
if [[ "$CARGO_RELEASE" != "$PINNED_RUST_TOOLCHAIN" \
  || "$RUSTC_RELEASE" != "$PINNED_RUST_TOOLCHAIN" \
  || "$RUSTDOC_RELEASE" != "$PINNED_RUST_TOOLCHAIN" \
  || ! "$CARGO_COMMIT_HASH" =~ ^[0-9a-f]{40}$ \
  || ! "$RUSTC_COMMIT_HASH" =~ ^[0-9a-f]{40}$ \
  || ! "$RUSTDOC_COMMIT_HASH" =~ ^[0-9a-f]{40}$ \
  || "$RUSTDOC_COMMIT_HASH" != "$RUSTC_COMMIT_HASH" ]]; then
  echo "[-] Cargo/rustc/rustdoc identity does not match exact Rust $PINNED_RUST_TOOLCHAIN" >&2
  exit 1
fi
CARGO_BINARY_SHA256="$(sha256_file "$CARGO_BINARY")"
RUSTC_BINARY_SHA256="$(sha256_file "$RUSTC_BINARY")"
RUSTDOC_BINARY_SHA256="$(sha256_file "$RUSTDOC_BINARY")"

XCODE_SELECT_BINARY="/usr/bin/xcode-select"
XCRUN_BINARY="/usr/bin/xcrun"
XCODEBUILD_BINARY="/usr/bin/xcodebuild"
for apple_tool in "$XCODE_SELECT_BINARY" "$XCRUN_BINARY" "$XCODEBUILD_BINARY"; do
  [[ -x "$apple_tool" ]] || {
    echo "[-] Required Apple developer tool is unavailable: $apple_tool" >&2
    exit 1
  }
done
if [[ -n "${NORITO_BRIDGE_DEVELOPER_DIR:-}" ]]; then
  XCODE_DEVELOPER_DIR="$NORITO_BRIDGE_DEVELOPER_DIR"
else
  XCODE_DEVELOPER_DIR="$(
    env -i \
      HOME="$USER_HOME_DIR" \
      PATH=/usr/bin:/bin \
      TMPDIR="$MOBILE_TMPDIR" \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      "$XCODE_SELECT_BINARY" -p
  )"
fi
[[ "$XCODE_DEVELOPER_DIR" == /* && -d "$XCODE_DEVELOPER_DIR" ]] || {
  echo "[-] Xcode developer directory is invalid: $XCODE_DEVELOPER_DIR" >&2
  exit 1
}
XCODE_DEVELOPER_DIR="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$XCODE_DEVELOPER_DIR")"

xcrun_value() {
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
    "$XCRUN_BINARY" "$@"
}

IPHONEOS_SDKROOT="$(xcrun_value --sdk iphoneos --show-sdk-path)"
IPHONESIMULATOR_SDKROOT="$(xcrun_value --sdk iphonesimulator --show-sdk-path)"
MACOSX_SDKROOT="$(xcrun_value --sdk macosx --show-sdk-path)"
IPHONEOS_SDK_VERSION="$(xcrun_value --sdk iphoneos --show-sdk-version)"
IPHONESIMULATOR_SDK_VERSION="$(xcrun_value --sdk iphonesimulator --show-sdk-version)"
MACOSX_SDK_VERSION="$(xcrun_value --sdk macosx --show-sdk-version)"
LIPO_BINARY="$(xcrun_value --find lipo)"
CLANG_BINARY="$(xcrun_value --find clang)"
RANLIB_BINARY="$(xcrun_value --find ranlib)"
for sdk_variable in IPHONEOS_SDKROOT IPHONESIMULATOR_SDKROOT MACOSX_SDKROOT; do
  sdkroot="${!sdk_variable}"
  printf -v "$sdk_variable" '%s' "$(run_python312_clean -c \
    'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$sdkroot")"
done
for sdkroot in "$IPHONEOS_SDKROOT" "$IPHONESIMULATOR_SDKROOT" "$MACOSX_SDKROOT"; do
  [[ "$sdkroot" == /* && -d "$sdkroot" && ! -L "$sdkroot" ]] || {
    echo "[-] Xcode returned an invalid SDK root: $sdkroot" >&2
    exit 1
  }
done
LIPO_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$LIPO_BINARY")"
[[ -x "$LIPO_BINARY" ]] || {
  echo "[-] Xcode lipo executable is unavailable" >&2
  exit 1
}
CLANG_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$CLANG_BINARY")"
[[ -x "$CLANG_BINARY" ]] || {
  echo "[-] Xcode clang executable is unavailable" >&2
  exit 1
}
RANLIB_BINARY="$(run_python312_clean -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$RANLIB_BINARY")"
[[ -x "$RANLIB_BINARY" ]] || {
  echo "[-] Xcode ranlib executable is unavailable" >&2
  exit 1
}
XCODE_VERSION_OUTPUT="$(
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
    "$XCODEBUILD_BINARY" -version
)"
XCODE_VERSION="$(sed -n 's/^Xcode //p' <<<"$XCODE_VERSION_OUTPUT")"
XCODE_BUILD_VERSION="$(sed -n 's/^Build version //p' <<<"$XCODE_VERSION_OUTPUT")"
for sdk_version in \
  "$IPHONEOS_SDK_VERSION" "$IPHONESIMULATOR_SDK_VERSION" "$MACOSX_SDK_VERSION"; do
  [[ "$sdk_version" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || {
    echo "[-] Xcode returned a non-canonical SDK version: $sdk_version" >&2
    exit 1
  }
done
if [[ ! "$XCODE_VERSION" =~ ^[0-9]+(\.[0-9]+){0,2}$ \
  || ! "$XCODE_BUILD_VERSION" =~ ^[A-Za-z0-9.]+$ ]]; then
  echo "[-] Xcode returned a non-canonical toolchain identity" >&2
  exit 1
fi

echo "[+] Using iOS deployment target (device): $IPHONEOS_DEPLOYMENT_TARGET" >&2
echo "[+] Using iOS deployment target (simulator): $IPHONESIMULATOR_DEPLOYMENT_TARGET" >&2

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR" "$OUT_DIR"
PUBLISH_XCFRAMEWORK=""
PUBLISH_MANIFEST=""
PUBLISH_MANIFEST_LINK=""
if [[ -z "$CI_APPLE_SLICE" ]]; then
  PUBLISH_ROOT="$(mktemp -d "$OUT_DIR/.NoritoBridge.publish.XXXXXX")"
  PUBLISH_XCFRAMEWORK="$PUBLISH_ROOT/${FRAMEWORK_NAME}.xcframework"
  PUBLISH_MANIFEST="$PUBLISH_XCFRAMEWORK/${FRAMEWORK_NAME}.artifacts.json"
  PUBLISH_MANIFEST_LINK="$PUBLISH_ROOT/${FRAMEWORK_NAME}.artifacts.json"
fi
FINAL_XCFRAMEWORK="$OUT_DIR/${FRAMEWORK_NAME}.xcframework"
FINAL_MANIFEST="$OUT_DIR/${FRAMEWORK_NAME}.artifacts.json"
CANONICAL_MANIFEST_RELATIVE_TARGET="${FRAMEWORK_NAME}.xcframework/${FRAMEWORK_NAME}.artifacts.json"

HEADER_HASH="$(sha256_file "$INC_DIR/connect_norito_bridge.h")"
APPLE_SLICE_COMMON_ATTESTATION="$STAGE_DIR/NoritoBridge.apple-slice-common.json"
if [[ -n "$CI_APPLE_SLICE" || -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
  cat > "$APPLE_SLICE_COMMON_ATTESTATION" <<EOF
{
  "schema": "iroha.norito-bridge-apple-slice-common.v1",
  "source_commit": "$SOURCE_COMMIT",
  "embedded_source_commit": "$EMBEDDED_SOURCE_COMMIT",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "source_fingerprint_sha256": "$SOURCE_FINGERPRINT",
  "cargo_lock_sha256": "$CARGO_LOCK_SHA256_START",
  "bridge_header_sha256": "$HEADER_HASH",
  "privacy_production_enabled": true,
  "cargo_features": $CARGO_FEATURES_JSON,
  "build_environment": {
    "schema": "iroha.mobile-native-build-environment.v1",
    "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
    "hermetic_runner_sha256": "$HERMETIC_RUNNER_SHA256",
    "wallet_runtime_authority": "$WALLET_RUNTIME_AUTHORITY",
    "wallet_runtime_trust_ed25519_hex": "$WALLET_RUNTIME_TRUST_PUBLIC_HEX",
    "cargo_build_jobs": 1,
    "cargo_incremental": 0,
    "cargo_net_offline": true,
    "rust_toolchain_channel": "$PINNED_RUST_TOOLCHAIN",
    "cargo_release": "$CARGO_RELEASE",
    "cargo_commit_hash": "$CARGO_COMMIT_HASH",
    "cargo_binary_sha256": "$CARGO_BINARY_SHA256",
    "rustc_release": "$RUSTC_RELEASE",
    "rustc_commit_hash": "$RUSTC_COMMIT_HASH",
    "rustc_binary_sha256": "$RUSTC_BINARY_SHA256",
    "rustdoc_release": "$RUSTDOC_RELEASE",
    "rustdoc_commit_hash": "$RUSTDOC_COMMIT_HASH",
    "rustdoc_binary_sha256": "$RUSTDOC_BINARY_SHA256",
    "python_version": "$PYTHON_VERSION",
    "python_binary_sha256": "$PYTHON_BINARY_SHA256",
    "git_version": "$GIT_VERSION",
    "git_binary_sha256": "$GIT_BINARY_SHA256",
    "rustup_version": "$RUSTUP_VERSION",
    "rustup_binary_sha256": "$RUSTUP_BINARY_SHA256",
    "xcode_version": "$XCODE_VERSION",
    "xcode_build_version": "$XCODE_BUILD_VERSION",
    "iphoneos_sdk_version": "$IPHONEOS_SDK_VERSION",
    "iphonesimulator_sdk_version": "$IPHONESIMULATOR_SDK_VERSION",
    "macosx_sdk_version": "$MACOSX_SDK_VERSION",
    "iphoneos_deployment_target": "$IPHONEOS_DEPLOYMENT_TARGET",
    "iphonesimulator_deployment_target": "$IPHONESIMULATOR_DEPLOYMENT_TARGET",
    "macosx_deployment_target": "$MACOSX_DEPLOYMENT_TARGET"
  }
}
EOF
fi

DEVICE_TRIPLE="aarch64-apple-ios"
SIM_ARM_TRIPLE="aarch64-apple-ios-sim"
SIM_X64_TRIPLE="x86_64-apple-ios"
MACOS_ARM_TRIPLE="aarch64-apple-darwin"
MACOS_X64_TRIPLE="x86_64-apple-darwin"
check_apple_consumer_link() {
  local target_triple="$1"
  local library="$2"
  local sdkroot clang_target host_arch
  local consumer_dir="$STAGE_DIR/consumer-link/$target_triple"
  case "$target_triple" in
    "$DEVICE_TRIPLE")
      sdkroot="$IPHONEOS_SDKROOT"
      clang_target="arm64-apple-ios$IPHONEOS_DEPLOYMENT_TARGET"
      ;;
    "$SIM_ARM_TRIPLE")
      sdkroot="$IPHONESIMULATOR_SDKROOT"
      clang_target="arm64-apple-ios$IPHONESIMULATOR_DEPLOYMENT_TARGET-simulator"
      ;;
    "$SIM_X64_TRIPLE")
      sdkroot="$IPHONESIMULATOR_SDKROOT"
      clang_target="x86_64-apple-ios$IPHONESIMULATOR_DEPLOYMENT_TARGET-simulator"
      ;;
    "$MACOS_ARM_TRIPLE")
      sdkroot="$MACOSX_SDKROOT"
      clang_target="arm64-apple-macos$MACOSX_DEPLOYMENT_TARGET"
      ;;
    "$MACOS_X64_TRIPLE")
      sdkroot="$MACOSX_SDKROOT"
      clang_target="x86_64-apple-macos$MACOSX_DEPLOYMENT_TARGET"
      ;;
    *) echo "[-] Unknown Apple consumer target: $target_triple" >&2; return 1 ;;
  esac
  mkdir -p "$consumer_dir"
  cat > "$consumer_dir/main.c" <<'CONSUMER_EOF'
#include "connect_norito_bridge.h"
#include "soranet_pq.h"
#include <stdint.h>
#include <string.h>

/* Pinned PQClean implementation symbols are exercised here, not added to the
 * public bridge ABI. Exact sizes/signatures match pqcrypto-mldsa 0.1.2 and
 * pqcrypto-mlkem 0.1.1. Loading all archive members also checks the accelerated
 * backends' helper closure on each packaged architecture. */
extern void sha3_256(uint8_t *, const uint8_t *, size_t);
extern void shake256(uint8_t *, size_t, const uint8_t *, size_t);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *, uint8_t *);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
    uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *, uint8_t *);
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *, uint8_t *, const uint8_t *);
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *, const uint8_t *, const uint8_t *);

/* Exercise the public ABI consumed by Swift, in addition to the retained
 * PQClean backend checks below. Suite 1 is ML-DSA-65 on the native owner. */
static int check_mldsa_ffi(void) {
    static const uint8_t message[] = {'a', 'b', 'c'};
    static const uint8_t changed[] = {'a', 'b', 'd'};
    uint8_t public_key[1952], secret_key[4032] = {0}, signature[3309];
    uint32_t public_len = 0, secret_len = 0, signature_len = 0;
    int result = 14;
    if (soranet_mldsa_parameters(1, &public_len, &secret_len, &signature_len)) goto done;
    if (public_len != sizeof(public_key) || secret_len != sizeof(secret_key)
        || signature_len != sizeof(signature)) goto done;
    if (soranet_mldsa_generate_keypair(1, public_key, sizeof(public_key),
            secret_key, sizeof(secret_key))) goto done;
    if (soranet_mldsa_sign(1, secret_key, sizeof(secret_key), message, sizeof(message),
            signature, sizeof(signature))) goto done;
    if (soranet_mldsa_verify(1, public_key, sizeof(public_key), message, sizeof(message),
            signature, sizeof(signature))) goto done;
    if (soranet_mldsa_verify(1, public_key, sizeof(public_key), changed, sizeof(changed),
            signature, sizeof(signature)) != SORANET_PQ_ERR_VERIFICATION_FAILED) goto done;
    result = 0;
done:
    for (size_t i = 0; i < sizeof(secret_key); ++i) ((volatile uint8_t *)secret_key)[i] = 0;
    return result;
}

int main(void) {
    static const uint8_t message[] = {'a', 'b', 'c'};
    static const uint8_t changed[] = {'a', 'b', 'd'};
    static const uint8_t sha3_expected[32] = {
        58, 152, 93, 167, 79, 226, 37, 178, 4, 92, 23, 45, 107, 211, 144, 189,
        133, 95, 8, 110, 62, 157, 82, 91, 70, 191, 226, 69, 17, 67, 21, 50};
    static const uint8_t shake_expected[32] = {
        72, 51, 102, 96, 19, 96, 168, 119, 28, 104, 99, 8, 12, 196, 17, 77,
        141, 180, 69, 48, 248, 241, 225, 238, 79, 148, 234, 55, 231, 139, 87, 57};
    uint8_t sha3[32], shake[32];
    uint8_t signing_public[1312], signing_secret[2560], signature[2420];
    uint8_t kem_public[800], kem_secret[1632], ciphertext[768], sent[32], received[32];
    size_t signature_len = 0;
    if (connect_norito_bridge_abi_version() != CONNECT_NORITO_BRIDGE_ABI_VERSION) return 1;
    static const char domain[] = "xn--bcher-kva.universal";
    static const char invalid_domain[] = "BANKA.universal";
    if (connect_norito_domain_id_validate_v1(domain, sizeof(domain) - 1) != 0) return 12;
    if (connect_norito_domain_id_validate_v1(invalid_domain, sizeof(invalid_domain) - 1) != 1) return 13;
    sha3_256(sha3, message, sizeof(message));
    shake256(shake, sizeof(shake), message, sizeof(message));
    if (memcmp(sha3, sha3_expected, sizeof(sha3)) || memcmp(shake, shake_expected, sizeof(shake))) return 2;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(signing_public, signing_secret)) return 3;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(signature, &signature_len,
            message, sizeof(message), NULL, 0, signing_secret)) return 4;
    if (signature_len != sizeof(signature)) return 5;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(signature, signature_len,
            message, sizeof(message), NULL, 0, signing_public)) return 6;
    if (!PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(signature, signature_len,
            changed, sizeof(changed), NULL, 0, signing_public)) return 7;
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_public, kem_secret)) return 8;
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ciphertext, sent, kem_public)) return 9;
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(received, ciphertext, kem_secret)) return 10;
    if (memcmp(sent, received, sizeof(sent))) return 11;
    return check_mldsa_ffi();
}
CONSUMER_EOF
  echo "[+] Linking complete native archive into a C consumer: $target_triple" >&2
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${CLANG_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
    "$CLANG_BINARY" -target "$clang_target" -isysroot "$sdkroot" \
    -I "$ROOT_DIR/crates/connect_norito_bridge/include" \
    -I "$ROOT_DIR/crates/soranet_pq/include" "$consumer_dir/main.c" \
    -Wl,-all_load "$library" \
    -framework Foundation -framework Security -framework Metal -framework CoreGraphics \
    -framework Accelerate \
    -lc++ -liconv -o "$consumer_dir/consumer" || return $?
  host_arch="$(/usr/bin/uname -m)"
  if [[ ( "$target_triple" == "$MACOS_ARM_TRIPLE" && "$host_arch" == "arm64" ) \
     || ( "$target_triple" == "$MACOS_X64_TRIPLE" && "$host_arch" == "x86_64" ) ]]; then
    env -i HOME="$USER_HOME_DIR" PATH=/usr/bin:/bin TMPDIR="$MOBILE_TMPDIR" \
      LANG=C.UTF-8 LC_ALL=C.UTF-8 "$consumer_dir/consumer" || return $?
    echo "[+] Host C consumer passed ABI, SHA3/SHAKE, ML-DSA and ML-KEM checks" >&2
  fi
}

rebuild_apple_archive_index() {
  local staged_library="$1"
  # Xcode's ranlib is a libtool alias. Keep the authenticated canonical binary
  # while preserving the invocation name that selects its archive-index mode.
  env -i HOME="$USER_HOME_DIR" PATH="${RANLIB_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
    "$PYTHON_BINARY" -I -S -B -c \
    'import subprocess,sys; subprocess.run(["ranlib", "-D", sys.argv[2]], executable=sys.argv[1], check=True)' \
    "$RANLIB_BINARY" "$staged_library"
}

stage_cargo_library() {
  local target_triple="$1"
  local label="$2"
  local source_library="$CARGO_TARGET_DIR/$target_triple/apple-release/lib${LIB_CRATE_NAME}.a"
  local staged_library="$STAGE_DIR/cargo-libraries/$target_triple/lib${LIB_CRATE_NAME}.a"
  if [[ ! -f "$source_library" ]]; then
    echo "[-] Missing $label static library after Cargo build: $source_library" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$staged_library")"
  cp "$source_library" "$staged_library"
  run_isolated_python "$PQCRYPTO_ARCHIVE_NORMALIZER" \
    --library "$staged_library" \
    --cargo-build-dir "$CARGO_TARGET_DIR/$target_triple/apple-release/build" \
    --cargo-messages "$STAGE_DIR/cargo-messages/$target_triple.jsonl" \
    --target "$target_triple" --cargo-lock "$CARGO_LOCKFILE" \
    --report "$staged_library.pqcrypto-normalization.json" || return $?
  rebuild_apple_archive_index "$staged_library" || return $?
  check_apple_consumer_link "$target_triple" "$staged_library" || return $?
  printf '%s\n' "$staged_library"
}

run_hermetic_apple_cargo() {
  local profile="$1"
  local sdkroot="$2"
  shift 2
  local cargo_subcommand="$1"
  shift
  local cargo_status
  local target_triple="" previous_argument="" argument
  for argument in "$@"; do
    if [[ "$previous_argument" == "--target" ]]; then
      [[ -z "$target_triple" ]] || { echo "[-] Duplicate Apple Cargo target" >&2; return 1; }
      target_triple="$argument"
    fi
    previous_argument="$argument"
  done
  case "$target_triple" in
    aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios|aarch64-apple-darwin|x86_64-apple-darwin) ;;
    *) echo "[-] Missing or unsupported Apple Cargo target" >&2; return 1 ;;
  esac
  local cargo_messages="$STAGE_DIR/cargo-messages/$target_triple.jsonl"
  mkdir -p "$STAGE_DIR/cargo-messages"
  local platform_environment=()
  case "$profile" in
    apple-ios-device)
      platform_environment=(
        --set "DEVELOPER_DIR=$XCODE_DEVELOPER_DIR"
        --set "IPHONEOS_DEPLOYMENT_TARGET=$IPHONEOS_DEPLOYMENT_TARGET"
        --set "SDKROOT=$sdkroot"
      )
      ;;
    apple-ios-simulator)
      platform_environment=(
        --set "DEVELOPER_DIR=$XCODE_DEVELOPER_DIR"
        --set "IPHONEOS_DEPLOYMENT_TARGET=$IPHONESIMULATOR_DEPLOYMENT_TARGET"
        --set "IPHONESIMULATOR_DEPLOYMENT_TARGET=$IPHONESIMULATOR_DEPLOYMENT_TARGET"
        --set "SDKROOT=$sdkroot"
      )
      ;;
    apple-macos)
      platform_environment=(
        --set "DEVELOPER_DIR=$XCODE_DEVELOPER_DIR"
        --set "MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET"
        --set "SDKROOT=$sdkroot"
      )
      ;;
    *)
      echo "[-] Unknown hermetic Apple Cargo profile: $profile" >&2
      exit 1
      ;;
  esac
  assert_selected_cargo_lock "the $profile Cargo preflight"
  # Compile the authenticated original root graph with stock Cargo. The selected
  # external lock is release evidence only; source admission requires byte-for-
  # byte equality with the root lock before and after this invocation.
  if run_isolated_python "$HERMETIC_RUNNER" \
      --profile "$profile" \
      "${MOBILE_CARGO_INVOCATION_ARGS[@]+"${MOBILE_CARGO_INVOCATION_ARGS[@]}"}" \
      --set "CARGO=$CARGO_BINARY" \
      --set "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
      --set "CARGO_HOME=$MOBILE_CARGO_HOME" \
      --set "CARGO_INCREMENTAL=0" \
      --set "CARGO_NET_OFFLINE=true" \
      --set "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
      --set "CONNECT_NORITO_SOURCE_REVISION=$EMBEDDED_SOURCE_COMMIT" \
      --set "HOME=$USER_HOME_DIR" \
      --set "IROHA_GIT_COMMIT_HASH=$EMBEDDED_SOURCE_COMMIT" \
      --set "LANG=C.UTF-8" \
      --set "LC_ALL=C.UTF-8" \
      --set "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY=$WALLET_RUNTIME_AUTHORITY" \
      --set "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX=$WALLET_RUNTIME_TRUST_PUBLIC_HEX" \
      --set "NORITO_SKIP_BINDINGS_SYNC=1" \
      --set "PATH=${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:${RUSTDOC_BINARY%/*}:/usr/bin:/bin" \
      --set "RUSTC=$RUSTC_BINARY" \
      --set "RUSTDOC=$RUSTDOC_BINARY" \
      --set "RUSTUP_HOME=$MOBILE_RUSTUP_HOME" \
      --set "TMPDIR=$MOBILE_TMPDIR" \
      --set "VERGEN_GIT_SHA=$EMBEDDED_SOURCE_COMMIT" \
      "${platform_environment[@]}" \
      -- "$CARGO_BINARY" "$cargo_subcommand" \
      --manifest-path "$ROOT_DIR/Cargo.toml" \
      --message-format=json-render-diagnostics "$@" > "$cargo_messages"; then
    cargo_status=0
  else
    cargo_status=$?
  fi
  assert_selected_cargo_lock "the $profile Cargo invocation"
  if [[ "$cargo_status" != "0" ]]; then
    echo "[-] Cargo diagnostic messages retained at $cargo_messages" >&2
  fi
  return "$cargo_status"
}

if [[ -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
  echo "[+] Authenticating five isolated CI Apple slice handoffs" >&2
elif [[ -n "$CI_APPLE_SLICE" ]]; then
  echo "[+] Building one Rust static library in the caller's fixed Cargo target (apple-release, staticlib-only ThinLTO)" >&2
  echo "    Target: $CI_APPLE_SLICE" >&2
else
  echo "[+] Building Rust static libraries in the caller's fixed Cargo target (apple-release, staticlib-only ThinLTO)" >&2
  echo "    Targets: $DEVICE_TRIPLE, $SIM_ARM_TRIPLE, $SIM_X64_TRIPLE, $MACOS_ARM_TRIPLE, $MACOS_X64_TRIPLE" >&2
  echo "    (Make sure you have installed targets via: rustup target add $DEVICE_TRIPLE $SIM_ARM_TRIPLE $SIM_X64_TRIPLE $MACOS_ARM_TRIPLE $MACOS_X64_TRIPLE)" >&2
fi

should_build_apple_slice() {
  local target_triple="$1"
  if [[ -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
    return 1
  fi
  [[ -z "$CI_APPLE_SLICE" || "$CI_APPLE_SLICE" == "$target_triple" ]]
}

# Run the native Apple Silicon consumer and cryptographic checks early. Every
# required slice still passes the same checks before XCFramework publication.
if should_build_apple_slice "$MACOS_ARM_TRIPLE"; then
  run_hermetic_apple_cargo \
    apple-macos "$MACOSX_SDKROOT" \
    rustc --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib \
    --crate-type staticlib --profile apple-release \
    --target "$MACOS_ARM_TRIPLE" \
    "${CARGO_FEATURE_ARGS[@]+"${CARGO_FEATURE_ARGS[@]}"}"
  assert_bridge_source_seal "the arm64 macOS build"
  LIB_MAC_ARM=$(stage_cargo_library "$MACOS_ARM_TRIPLE" "arm64 macOS")
fi

# Rust uses IPHONEOS_DEPLOYMENT_TARGET for both iOS device and simulator targets,
# while cc-based dependencies also honor IPHONESIMULATOR_DEPLOYMENT_TARGET.
if should_build_apple_slice "$DEVICE_TRIPLE"; then
  run_hermetic_apple_cargo \
    apple-ios-device "$IPHONEOS_SDKROOT" \
    rustc --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib \
    --crate-type staticlib --profile apple-release \
    --target "$DEVICE_TRIPLE" \
    "${CARGO_FEATURE_ARGS[@]+"${CARGO_FEATURE_ARGS[@]}"}"
  assert_bridge_source_seal "the iOS device build"
  LIB_DEV=$(stage_cargo_library "$DEVICE_TRIPLE" "iOS device")
fi
if should_build_apple_slice "$SIM_ARM_TRIPLE"; then
  run_hermetic_apple_cargo \
    apple-ios-simulator "$IPHONESIMULATOR_SDKROOT" \
    rustc --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib \
    --crate-type staticlib --profile apple-release \
    --target "$SIM_ARM_TRIPLE" \
    "${CARGO_FEATURE_ARGS[@]+"${CARGO_FEATURE_ARGS[@]}"}"
  assert_bridge_source_seal "the arm64 simulator build"
  LIB_SIM_ARM=$(stage_cargo_library "$SIM_ARM_TRIPLE" "arm64 simulator")
fi
if should_build_apple_slice "$SIM_X64_TRIPLE"; then
  run_hermetic_apple_cargo \
    apple-ios-simulator "$IPHONESIMULATOR_SDKROOT" \
    rustc --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib \
    --crate-type staticlib --profile apple-release \
    --target "$SIM_X64_TRIPLE" \
    "${CARGO_FEATURE_ARGS[@]+"${CARGO_FEATURE_ARGS[@]}"}"
  assert_bridge_source_seal "the x86_64 simulator build"
  LIB_SIM_X64=$(stage_cargo_library "$SIM_X64_TRIPLE" "x86_64 simulator")
fi
if should_build_apple_slice "$MACOS_X64_TRIPLE"; then
  run_hermetic_apple_cargo \
    apple-macos "$MACOSX_SDKROOT" \
    rustc --locked --offline --jobs 1 -p "$LIB_CRATE_NAME" --lib \
    --crate-type staticlib --profile apple-release \
    --target "$MACOS_X64_TRIPLE" \
    "${CARGO_FEATURE_ARGS[@]+"${CARGO_FEATURE_ARGS[@]}"}"
  assert_bridge_source_seal "the x86_64 macOS build"
  LIB_MAC_X64=$(stage_cargo_library "$MACOS_X64_TRIPLE" "x86_64 macOS")
fi

assert_bridge_source_seal "Apple slice staging"

if [[ -n "$CI_APPLE_SLICE" ]]; then
  case "$CI_APPLE_SLICE" in
    "$DEVICE_TRIPLE")
      CI_APPLE_SLICE_PROFILE=apple-ios-device
      CI_APPLE_SLICE_LIBRARY="$LIB_DEV"
      ;;
    "$SIM_ARM_TRIPLE")
      CI_APPLE_SLICE_PROFILE=apple-ios-simulator
      CI_APPLE_SLICE_LIBRARY="$LIB_SIM_ARM"
      ;;
    "$SIM_X64_TRIPLE")
      CI_APPLE_SLICE_PROFILE=apple-ios-simulator
      CI_APPLE_SLICE_LIBRARY="$LIB_SIM_X64"
      ;;
    "$MACOS_ARM_TRIPLE")
      CI_APPLE_SLICE_PROFILE=apple-macos
      CI_APPLE_SLICE_LIBRARY="$LIB_MAC_ARM"
      ;;
    "$MACOS_X64_TRIPLE")
      CI_APPLE_SLICE_PROFILE=apple-macos
      CI_APPLE_SLICE_LIBRARY="$LIB_MAC_X64"
      ;;
  esac
  run_isolated_python "$APPLE_SLICE_HANDOFF" pack \
    --common "$APPLE_SLICE_COMMON_ATTESTATION" \
    --target "$CI_APPLE_SLICE" \
    --profile "$CI_APPLE_SLICE_PROFILE" \
    --library "$CI_APPLE_SLICE_LIBRARY" \
    --archive "$CI_APPLE_SLICE_ARCHIVE"
  assert_bridge_source_seal "the CI Apple slice handoff"
  rm -rf "$STAGE_DIR"
  echo "[+] Packed authenticated Apple slice: $CI_APPLE_SLICE_ARCHIVE" >&2
  exit 0
fi

if [[ -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then
  restore_arguments=()
  for digest_mapping in "${CI_APPLE_SLICE_SHA256[@]}"; do
    restore_arguments+=(--sha256 "$digest_mapping")
  done
  run_isolated_python "$APPLE_SLICE_HANDOFF" restore \
    --common "$APPLE_SLICE_COMMON_ATTESTATION" \
    --archive-root "$CI_ASSEMBLE_APPLE_SLICES" \
    --destination "$STAGE_DIR/cargo-libraries" \
    "${restore_arguments[@]}"
  assert_bridge_source_seal "the authenticated CI Apple slice restore"
  LIB_DEV="$STAGE_DIR/cargo-libraries/$DEVICE_TRIPLE/lib${LIB_CRATE_NAME}.a"
  LIB_SIM_ARM="$STAGE_DIR/cargo-libraries/$SIM_ARM_TRIPLE/lib${LIB_CRATE_NAME}.a"
  LIB_SIM_X64="$STAGE_DIR/cargo-libraries/$SIM_X64_TRIPLE/lib${LIB_CRATE_NAME}.a"
  LIB_MAC_ARM="$STAGE_DIR/cargo-libraries/$MACOS_ARM_TRIPLE/lib${LIB_CRATE_NAME}.a"
  LIB_MAC_X64="$STAGE_DIR/cargo-libraries/$MACOS_X64_TRIPLE/lib${LIB_CRATE_NAME}.a"
  for restored_target in "$DEVICE_TRIPLE" "$SIM_ARM_TRIPLE" "$SIM_X64_TRIPLE" \
      "$MACOS_ARM_TRIPLE" "$MACOS_X64_TRIPLE"; do
    check_apple_consumer_link "$restored_target" \
      "$STAGE_DIR/cargo-libraries/$restored_target/lib${LIB_CRATE_NAME}.a"
  done
fi

if [[ ! -f "$LIB_DEV" || ! -f "$LIB_SIM_ARM" || ! -f "$LIB_SIM_X64" \
    || ! -f "$LIB_MAC_ARM" || ! -f "$LIB_MAC_X64" ]]; then
  echo "[-] Missing built libraries. Did the cargo builds succeed?" >&2
  exit 1
fi

if [[ -z "${BRIDGE_VERSION}" ]]; then
  VERSION_SOURCE="$ROOT_DIR/IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
  if command -v rg >/dev/null 2>&1; then
    BRIDGE_VERSION=$(rg -n "expectedVersion" "$VERSION_SOURCE" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
  else
    BRIDGE_VERSION=$(grep -m1 "expectedVersion" "$VERSION_SOURCE" | sed -E 's/.*"([^"]+)".*/\1/')
  fi
fi
if [[ -z "${BRIDGE_VERSION}" ]]; then
  echo "[-] Unable to determine NoritoBridge version for artifact manifest" >&2
  exit 1
fi
BRIDGE_BUNDLE_VERSION="${BRIDGE_VERSION%%-*}"
if [[ -z "$BRIDGE_BUNDLE_VERSION" ]]; then
  BRIDGE_BUNDLE_VERSION="1"
fi

SIM_UNI="$STAGE_DIR/${FRAMEWORK_NAME}-sim-universal.a"
MAC_UNI="$STAGE_DIR/${FRAMEWORK_NAME}-macos-universal.a"
echo "[+] Creating simulator universal static library" >&2
env -i \
  HOME="$USER_HOME_DIR" \
  PATH="${LIPO_BINARY%/*}:/usr/bin:/bin" \
  TMPDIR="$MOBILE_TMPDIR" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
  "$LIPO_BINARY" -create -output "$SIM_UNI" "$LIB_SIM_ARM" "$LIB_SIM_X64"

echo "[+] Creating macOS universal static library" >&2
env -i \
  HOME="$USER_HOME_DIR" \
  PATH="${LIPO_BINARY%/*}:/usr/bin:/bin" \
  TMPDIR="$MOBILE_TMPDIR" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
  "$LIPO_BINARY" -create -output "$MAC_UNI" "$LIB_MAC_ARM" "$LIB_MAC_X64"

echo "[+] Staging XCFramework slices" >&2
HEADERS_DEV="$STAGE_DIR/device-headers"
HEADERS_SIM="$STAGE_DIR/simulator-headers"
HEADERS_MAC="$STAGE_DIR/macos-headers"
LIB_DEV_STAGED="$STAGE_DIR/device/${STATIC_LIB_NAME}"
LIB_SIM_STAGED="$STAGE_DIR/simulator/${STATIC_LIB_NAME}"
LIB_MAC_STAGED="$STAGE_DIR/macos/${STATIC_LIB_NAME}"

mkdir -p "$HEADERS_DEV" "$HEADERS_SIM" "$HEADERS_MAC" "$(dirname "$LIB_DEV_STAGED")" "$(dirname "$LIB_SIM_STAGED")" "$(dirname "$LIB_MAC_STAGED")"

# Package only task-owned staging copies. The caller's Cargo target remains intact.
mv "$LIB_DEV" "$LIB_DEV_STAGED"
mv "$SIM_UNI" "$LIB_SIM_STAGED"
mv "$MAC_UNI" "$LIB_MAC_STAGED"
rm -f "$LIB_SIM_ARM" "$LIB_SIM_X64"

# Copy headers for static-library slices. xcodebuild copies this directory as the
# slice's Headers bundle, so the modulemap lives at Headers/module.modulemap.
cp "$INC_DIR/connect_norito_bridge.h" "$HEADERS_DEV/connect_norito_bridge.h"
cp "$INC_DIR/NoritoBridge.h" "$HEADERS_DEV/NoritoBridge.h"
cp "$CRATE_DIR/module.modulemap.template" "$HEADERS_DEV/module.modulemap"
cp "$INC_DIR/connect_norito_bridge.h" "$HEADERS_SIM/connect_norito_bridge.h"
cp "$INC_DIR/NoritoBridge.h" "$HEADERS_SIM/NoritoBridge.h"
cp "$CRATE_DIR/module.modulemap.template" "$HEADERS_SIM/module.modulemap"
cp "$INC_DIR/connect_norito_bridge.h" "$HEADERS_MAC/connect_norito_bridge.h"
cp "$INC_DIR/NoritoBridge.h" "$HEADERS_MAC/NoritoBridge.h"
cp "$CRATE_DIR/module.modulemap.template" "$HEADERS_MAC/module.modulemap"

echo "[+] Creating XCFramework" >&2
if env -i \
  HOME="$USER_HOME_DIR" \
  PATH=/usr/bin:/bin \
  TMPDIR="$MOBILE_TMPDIR" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
  "$XCODEBUILD_BINARY" -create-xcframework \
  -library "$LIB_DEV_STAGED" -headers "$HEADERS_DEV" \
  -library "$LIB_SIM_STAGED" -headers "$HEADERS_SIM" \
  -library "$LIB_MAC_STAGED" -headers "$HEADERS_MAC" \
  -output "$PUBLISH_XCFRAMEWORK"; then
  :
else
  xcodebuild_status=$?
  echo "[-] xcodebuild failed with status $xcodebuild_status; refusing to publish NoritoBridge" >&2
  exit "$xcodebuild_status"
fi

assert_bridge_source_seal "XCFramework packaging"

echo "[+] XCFramework staged: $PUBLISH_XCFRAMEWORK" >&2
touch "$PUBLISH_XCFRAMEWORK/.privacy-production-enabled"

IOS_BIN="$PUBLISH_XCFRAMEWORK/ios-arm64/${STATIC_LIB_NAME}"
SIM_BIN="$PUBLISH_XCFRAMEWORK/ios-arm64_x86_64-simulator/${STATIC_LIB_NAME}"
MAC_BIN="$PUBLISH_XCFRAMEWORK/macos-arm64_x86_64/${STATIC_LIB_NAME}"
if [[ ! -f "$IOS_BIN" || ! -f "$SIM_BIN" || ! -f "$MAC_BIN" ]]; then
  echo "[-] Missing XCFramework binaries needed to emit NoritoBridge.artifacts.json" >&2
  exit 1
fi

IOS_HASH=$(shasum -a 256 "$IOS_BIN" | awk '{print $1}')
SIM_HASH=$(shasum -a 256 "$SIM_BIN" | awk '{print $1}')
MAC_HASH=$(shasum -a 256 "$MAC_BIN" | awk '{print $1}')
BRIDGE_ABI_VERSION="$(run_isolated_python - \
  "$INC_DIR/connect_norito_bridge.h" \
  "$CRATE_DIR/src/lib.rs" \
  "$ROOT_DIR/crates/iroha_data_model/src/privacy/protocol.rs" <<'PY'
from pathlib import Path
import re
import sys

header, bridge_source, protocol = (Path(value) for value in sys.argv[1:])
header_abis = re.findall(
    r"^#define[ \t]+CONNECT_NORITO_BRIDGE_ABI_VERSION[ \t]+([0-9]+)[ \t]*$",
    header.read_text(encoding="utf-8"),
    re.MULTILINE,
)
bridge_aliases = re.findall(
    r"^const CONNECT_NORITO_BRIDGE_ABI_VERSION: u32 = "
    r"(PRIVACY_BRIDGE_ABI_VERSION_V1);$",
    bridge_source.read_text(encoding="utf-8"),
    re.MULTILINE,
)
protocol_abis = re.findall(
    r"^pub const PRIVACY_BRIDGE_ABI_VERSION_V1: u32 = ([0-9]+);$",
    protocol.read_text(encoding="utf-8"),
    re.MULTILINE,
)
if header_abis != ["31"]:
    raise SystemExit("authoritative NoritoBridge public header ABI is not exact 31")
if bridge_aliases != ["PRIVACY_BRIDGE_ABI_VERSION_V1"]:
    raise SystemExit("NoritoBridge Rust ABI alias is not exact")
if protocol_abis != header_abis:
    raise SystemExit("privacy protocol ABI differs from the public NoritoBridge header")
print(header_abis[0])
PY
)" || exit 1

RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS=(
  connect_norito_private_settlement_auditor_capsule_response
  verify
  v1
)
RETIRED_AUDITOR_CAPSULE_VERIFY_SYMBOL="${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[0]}_${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[1]}_${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[2]}"

cat > "$PUBLISH_MANIFEST" <<EOF
{
  "version": "$BRIDGE_VERSION",
  "native_bridge_abi_version": $BRIDGE_ABI_VERSION,
  "privacy_production_enabled": true,
  "cargo_features": $CARGO_FEATURES_JSON,
  "build_environment": {
    "schema": "iroha.mobile-native-build-environment.v1",
    "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
    "hermetic_runner_sha256": "$HERMETIC_RUNNER_SHA256",
    "wallet_runtime_authority": "$WALLET_RUNTIME_AUTHORITY",
    "wallet_runtime_trust_ed25519_hex": "$WALLET_RUNTIME_TRUST_PUBLIC_HEX",
    "environment_profiles": {
      "apple-ios-device": [
        "CARGO",
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CONNECT_NORITO_SOURCE_REVISION",
        "DEVELOPER_DIR",
        "HOME",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "IROHA_GIT_COMMIT_HASH",
        "LANG",
        "LC_ALL",
        "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY",
        "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX",
        "NORITO_SKIP_BINDINGS_SYNC",
        "PATH",
        "RUSTC",
        "RUSTDOC",
        "RUSTUP_HOME",
        "SDKROOT",
        "TMPDIR",
        "VERGEN_GIT_SHA"
      ],
      "apple-ios-simulator": [
        "CARGO",
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CONNECT_NORITO_SOURCE_REVISION",
        "DEVELOPER_DIR",
        "HOME",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "IPHONESIMULATOR_DEPLOYMENT_TARGET",
        "IROHA_GIT_COMMIT_HASH",
        "LANG",
        "LC_ALL",
        "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY",
        "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX",
        "NORITO_SKIP_BINDINGS_SYNC",
        "PATH",
        "RUSTC",
        "RUSTDOC",
        "RUSTUP_HOME",
        "SDKROOT",
        "TMPDIR",
        "VERGEN_GIT_SHA"
      ],
      "apple-macos": [
        "CARGO",
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CONNECT_NORITO_SOURCE_REVISION",
        "DEVELOPER_DIR",
        "HOME",
        "IROHA_GIT_COMMIT_HASH",
        "LANG",
        "LC_ALL",
        "MACOSX_DEPLOYMENT_TARGET",
        "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY",
        "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX",
        "NORITO_SKIP_BINDINGS_SYNC",
        "PATH",
        "RUSTC",
        "RUSTDOC",
        "RUSTUP_HOME",
        "SDKROOT",
        "TMPDIR",
        "VERGEN_GIT_SHA"
      ]
    },
    "cargo_build_jobs": 1,
    "rust_toolchain_channel": "$PINNED_RUST_TOOLCHAIN",
    "cargo_release": "$CARGO_RELEASE",
    "cargo_commit_hash": "$CARGO_COMMIT_HASH",
    "cargo_binary_sha256": "$CARGO_BINARY_SHA256",
    "rustc_release": "$RUSTC_RELEASE",
    "rustc_commit_hash": "$RUSTC_COMMIT_HASH",
    "rustc_binary_sha256": "$RUSTC_BINARY_SHA256",
    "rustdoc_release": "$RUSTDOC_RELEASE",
    "rustdoc_commit_hash": "$RUSTDOC_COMMIT_HASH",
    "rustdoc_binary_sha256": "$RUSTDOC_BINARY_SHA256",
    "python_version": "$PYTHON_VERSION",
    "python_binary_sha256": "$PYTHON_BINARY_SHA256",
    "git_version": "$GIT_VERSION",
    "git_binary_sha256": "$GIT_BINARY_SHA256",
    "rustup_version": "$RUSTUP_VERSION",
    "rustup_binary_sha256": "$RUSTUP_BINARY_SHA256",
    "xcode_version": "$XCODE_VERSION",
    "xcode_build_version": "$XCODE_BUILD_VERSION",
    "iphoneos_sdk_version": "$IPHONEOS_SDK_VERSION",
    "iphonesimulator_sdk_version": "$IPHONESIMULATOR_SDK_VERSION",
    "macosx_sdk_version": "$MACOSX_SDK_VERSION",
    "iphoneos_deployment_target": "$IPHONEOS_DEPLOYMENT_TARGET",
    "iphonesimulator_deployment_target": "$IPHONESIMULATOR_DEPLOYMENT_TARGET",
    "macosx_deployment_target": "$MACOSX_DEPLOYMENT_TARGET"
  },
  "source_commit": "$SOURCE_COMMIT",
  "embedded_source_commit": "$EMBEDDED_SOURCE_COMMIT",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "source_fingerprint_sha256": "$SOURCE_FINGERPRINT",
  "cargo_lock_sha256": "$CARGO_LOCK_SHA256_START",
  "bridge_header_sha256": "$HEADER_HASH",
  "required_symbols": [
    "connect_norito_bridge_abi_version",
    "connect_norito_domain_id_validate_v1",
    "soranet_mldsa_parameters",
    "soranet_mldsa_generate_keypair",
    "soranet_mldsa_sign",
    "soranet_mldsa_verify",
    "connect_norito_free",
    "connect_norito_chain_discriminant_scope_enter",
    "connect_norito_chain_discriminant_scope_exit",
    "connect_norito_encode_transfer_signed_transaction",
    "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg",
    "connect_norito_encode_transfer_instruction_box",
    "connect_norito_detached_transaction_scaffold_inspect_v1",
    "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1",
    "connect_norito_canonical_json_blake3_v1",
    "connect_norito_encode_account_onboarding_plan_body_v1",
    "connect_norito_alias_instruction_round_trip_v1",
    "connect_norito_account_read_permission_multisig_payload_hash",
    "connect_norito_account_read_permission_multisig_finalize",
    "iroha_privacy_compiled_profile_catalog_v1",
    "iroha_privacy_validate_compiled_profile_catalog_v1",
    "iroha_privacy_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_capability_manifest_v1",
    "iroha_privacy_free_buffer",
    "connect_norito_sorafs_reference_validate_bundle_json",
    "connect_norito_sorafs_reference_validate_governance_json",
    "connect_norito_sorafs_reference_validate_governance_dag_block_json",
    "connect_norito_sorafs_reference_validate_governance_dag_head_chain_json",
    "connect_norito_validation_fee_current_policy_proof_request_v1",
    "connect_norito_validation_fee_current_policy_proof_verify_v1",
    "connect_norito_retail_fee_intent_hash_v1",
    "connect_norito_retail_fee_assessment_marker_v1",
    "connect_norito_retail_fee_assessment_decode_v1",
    "connect_norito_private_settlement_committee_proof_response_verify_v1",
    "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
    "connect_norito_private_settlement_audit_approval_response_verify_v1",
    "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
    "connect_norito_kagemusha_wallet_revision_v1",
    "connect_norito_kagemusha_wallet_open_begin_v1",
    "connect_norito_kagemusha_wallet_open_finish_v1",
    "connect_norito_kagemusha_wallet_open_cancel_v1",
    "connect_norito_kagemusha_wallet_close_v1",
    "connect_norito_kagemusha_wallet_activity_v1",
    "connect_norito_kagemusha_wallet_setup_v1",
    "connect_norito_kagemusha_wallet_execute_v1",
    "connect_norito_kagemusha_wallet_load_original_validate_v1",
    "connect_norito_kagemusha_wallet_request_status_v1",
    "connect_norito_kagemusha_wallet_retry_v1",
    "connect_norito_kagemusha_wallet_resume_v1",
    "connect_norito_kagemusha_wallet_fold_v1",
    "connect_norito_kagemusha_wallet_credit_status_v1",
    "connect_norito_kagemusha_wallet_snapshot_v1",
    "connect_norito_kagemusha_wallet_review_v1",
    "connect_norito_kagemusha_wallet_execute_reviewed_v1",
    "connect_norito_kagemusha_wallet_discard_review_v1",
    "connect_norito_kagemusha_wallet_installation_begin_v1",
    "connect_norito_kagemusha_wallet_installation_register_v1",
    "connect_norito_kagemusha_wallet_installation_close_v1",
    "connect_norito_kagemusha_wallet_registration_source_relocate_v1",
    "connect_norito_kagemusha_wallet_observe_v1",
    "connect_norito_kagemusha_wallet_account_original_v1",
    "connect_norito_kagemusha_wallet_account_display_v1",
    "connect_norito_kagemusha_wallet_enrollment_v1",
    "connect_norito_kagemusha_wallet_enrollment_refusal_v1"
  ],
  "forbidden_symbols": [
    "connect_norito_kagemusha_v1_payment_request_validate",
    "connect_norito_kagemusha_v1_payment_validate",
    "connect_norito_kagemusha_v1_acknowledgement_validate",
    "connect_norito_kagemusha_v1_complete_exchange_validate",
    "connect_norito_kagemusha_v1_mint_authorization_validate",
    "connect_norito_kagemusha_v1_mint_credit_validate",
    "connect_norito_kagemusha_v1_mint_credit_against_authorization_validate",
    "connect_norito_kagemusha_v1_redemption_voucher_validate",
    "connect_norito_kagemusha_v1_payment_request_text_validate",
    "connect_norito_kagemusha_v1_payment_text_validate",
    "connect_norito_kagemusha_v1_acknowledgement_text_validate",
    "connect_norito_kagemusha_v1_complete_exchange_text_validate",
    "connect_norito_kagemusha_v1_mint_authorization_text_validate",
    "connect_norito_kagemusha_v1_mint_credit_text_validate",
    "connect_norito_kagemusha_v1_mint_credit_against_authorization_text_validate",
    "connect_norito_kagemusha_v1_redemption_voucher_text_validate",
    "connect_norito_kagemusha_device_mint_stage_command_v1_validate",
    "connect_norito_kagemusha_device_mint_stage_result_v1_validate",
    "connect_norito_kagemusha_contract_vector_v1",
    "connect_norito_kagemusha_core_coordinator_contract_v1",
    "connect_norito_kagemusha_core_coordinator_install_v1",
    "connect_norito_kagemusha_core_coordinator_open_v1",
    "connect_norito_kagemusha_core_coordinator_invoke_v1",
    "connect_norito_kagemusha_core_coordinator_close_v1",
    "connect_norito_kagemusha_testnet_state_proof_observe_v1",
    "connect_norito_kagemusha_testnet_finalized_mint_observe_v1",
    "connect_norito_kagemusha_testnet_value_admit_v1",
    "connect_norito_kagemusha_testnet_value_credit_v1",
    "connect_norito_kagemusha_testnet_native_startup_contract_v1",
    "connect_norito_kagemusha_testnet_native_startup_activate_v1",
    "connect_norito_kagemusha_ordinary_runtime_startup_v1",
    "connect_norito_kagemusha_ordinary_current_control_v1",
    "connect_norito_kagemusha_ordinary_outgoing_v1",
    "connect_norito_kagemusha_ordinary_incoming_v1",
    "connect_norito_kagemusha_ordinary_integrity_refresh_v1",
    "connect_norito_kagemusha_ordinary_mint_funding_v1",
    "connect_norito_kagemusha_device_capabilities_v1",
    "connect_norito_kagemusha_device_execute_v1",
    "connect_norito_kagemusha_device_command_response_v1_verify",
    "connect_norito_kagemusha_reserve_finality_hint_v1",
    "connect_norito_kagemusha_reserve_finality_verify_v1",
    "connect_norito_kagemusha_top_up_signed_request_validate_v1",
    "connect_norito_validation_fee_hijiri_quote_request_v1",
    "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
    "connect_norito_kagemusha_device_response_authenticator_v1_verify",
    "connect_norito_get_chain_discriminant",
    "connect_norito_set_chain_discriminant",
    "$RETIRED_AUDITOR_CAPSULE_VERIFY_SYMBOL",
    "iroha_privacy_capabilities_v1",
    "iroha_privacy_validate_capabilities_v1",
    "iroha_privacy_proof_request_v1",
    "iroha_privacy_build_proof_v1",
    "iroha_privacy_verify_proof_v1"
  ],
  "hashes": {
    "ios-arm64": "$IOS_HASH",
    "ios-arm64_x86_64-simulator": "$SIM_HASH",
    "macos-arm64_x86_64": "$MAC_HASH"
  }
}
EOF
if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  run_isolated_python - "$PUBLISH_MANIFEST" <<'PY'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["artifact_scope"] = "local-integration"
path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
fi
echo "[+] Wrote staged artifact manifest: $PUBLISH_MANIFEST" >&2
ln -s "$CANONICAL_MANIFEST_RELATIVE_TARGET" "$PUBLISH_MANIFEST_LINK"
PUBLISH_PROSPECTIVE_LOADER="$PUBLISH_ROOT/.NoritoBridge.prospective.NativeBridge.swift"
SWIFT_PIN_PREIMAGE_SHA256="$(
  sha256_file "$ROOT_DIR/IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
)"
SWIFT_PIN_OWNER_ARGUMENTS=(
  "${LOCAL_INTEGRATION_ARGS[@]+"${LOCAL_INTEGRATION_ARGS[@]}"}"
  --root "$ROOT_DIR"
  --artifact-dir "$PUBLISH_ROOT"
  --lockfile-path "$CARGO_LOCKFILE"
  --output "$PUBLISH_PROSPECTIVE_LOADER"
  --expected-preimage-sha256 "$SWIFT_PIN_PREIMAGE_SHA256"
)
if [[ "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
  SWIFT_PIN_OWNER_ARGUMENTS+=(--allow-dirty-source)
fi
env -i \
  HOME="$USER_HOME_DIR" \
  PATH="${PYTHON_BINARY%/*}:${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:${RUSTDOC_BINARY%/*}:${GIT_BINARY%/*}:/usr/bin:/bin" \
  TMPDIR="$MOBILE_TMPDIR" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  NORITO_BRIDGE_SEAL_HOME="$USER_HOME_DIR" \
  NORITO_BRIDGE_SEAL_CARGO_HOME="$MOBILE_CARGO_HOME" \
  NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR="$MOBILE_CARGO_INVOCATION_DIR" \
  NORITO_BRIDGE_SEAL_RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
  NORITO_BRIDGE_SEAL_TMPDIR="$MOBILE_TMPDIR" \
  NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  NORITO_BRIDGE_SEAL_CARGO="$CARGO_BINARY" \
  NORITO_BRIDGE_SEAL_RUSTC="$RUSTC_BINARY" \
  NORITO_BRIDGE_SEAL_RUSTDOC="$RUSTDOC_BINARY" \
  NORITO_BRIDGE_SEAL_RUSTUP="$RUSTUP_BINARY" \
  NORITO_BRIDGE_SEAL_DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
  "$PYTHON_BINARY" -I -S -B \
  "$ROOT_DIR/scripts/update_norito_bridge_swift_pins.py" \
  "${SWIFT_PIN_OWNER_ARGUMENTS[@]}"

run_isolated_python - \
  "$PUBLISH_XCFRAMEWORK" "$PUBLISH_MANIFEST" \
  "$PUBLISH_MANIFEST_LINK" "$CANONICAL_MANIFEST_RELATIVE_TARGET" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import sys


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


xcframework = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
manifest_link = Path(sys.argv[3])
manifest_link_target = sys.argv[4]
expected_slices = {
    "ios-arm64": {
        "architectures": ["arm64"],
        "platform": "ios",
        "variant": None,
    },
    "ios-arm64_x86_64-simulator": {
        "architectures": ["arm64", "x86_64"],
        "platform": "ios",
        "variant": "simulator",
    },
    "macos-arm64_x86_64": {
        "architectures": ["arm64", "x86_64"],
        "platform": "macos",
        "variant": None,
    },
}
library_name = "libNoritoBridge.a"

if xcframework.is_symlink() or not xcframework.is_dir():
    raise SystemExit("staged NoritoBridge XCFramework root is not a regular directory")
for root, directories, files in os.walk(xcframework, followlinks=False):
    for name in [*directories, *files]:
        path = Path(root) / name
        if stat.S_ISLNK(path.lstat().st_mode):
            raise SystemExit(f"staged NoritoBridge contains a symlink: {path}")

with manifest_path.open("r", encoding="utf-8") as handle:
    manifest = json.load(handle, object_pairs_hook=object_without_duplicates)
if manifest.get("native_bridge_abi_version") != 31:
    raise SystemExit("staged NoritoBridge manifest does not bind exact ABI 31")
hashes = manifest.get("hashes")
if not isinstance(hashes, dict) or set(hashes) != set(expected_slices):
    raise SystemExit("staged NoritoBridge manifest has a non-canonical slice inventory")
if not manifest_link.is_symlink() or os.readlink(manifest_link) != manifest_link_target:
    raise SystemExit("staged NoritoBridge public manifest link is not canonical")

info_path = xcframework / "Info.plist"
with info_path.open("rb") as handle:
    info = plistlib.load(handle)
libraries = info.get("AvailableLibraries")
if (
    not isinstance(libraries, list)
    or len(libraries) != len(expected_slices)
    or any(not isinstance(library, dict) for library in libraries)
):
    raise SystemExit("staged NoritoBridge Info.plist has a non-canonical slice list")
metadata = {}
for library in libraries:
    identifier = library.get("LibraryIdentifier")
    if identifier in metadata:
        raise SystemExit(f"duplicate staged NoritoBridge slice: {identifier!r}")
    metadata[identifier] = library
if set(metadata) != set(expected_slices):
    raise SystemExit("staged NoritoBridge Info.plist has a non-canonical slice inventory")
if info.get("CFBundlePackageType") != "XFWK":
    raise SystemExit("staged NoritoBridge Info.plist has the wrong package type")
if info.get("XCFrameworkFormatVersion") != "1.0":
    raise SystemExit("staged NoritoBridge Info.plist has the wrong format version")

for identifier, expected in expected_slices.items():
    library = metadata[identifier]
    if library.get("LibraryPath") != library_name:
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has a non-canonical LibraryPath"
        )
    if "BinaryPath" in library and library["BinaryPath"] != library_name:
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has a conflicting BinaryPath"
        )
    if library.get("HeadersPath") != "Headers":
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has a non-canonical HeadersPath"
        )
    if library.get("SupportedArchitectures") != expected["architectures"]:
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has non-canonical architectures"
        )
    if library.get("SupportedPlatform") != expected["platform"]:
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has a non-canonical platform"
        )
    if expected["variant"] is None:
        if "SupportedPlatformVariant" in library:
            raise SystemExit(
                f"staged NoritoBridge slice {identifier} has an unexpected variant"
            )
    elif library.get("SupportedPlatformVariant") != expected["variant"]:
        raise SystemExit(
            f"staged NoritoBridge slice {identifier} has a non-canonical variant"
        )

    binary = xcframework / identifier / library_name
    headers = xcframework / identifier / "Headers"
    modulemap = headers / "module.modulemap"
    if "module NoritoBridge" not in modulemap.read_text(encoding="utf-8"):
        raise SystemExit(f"staged NoritoBridge module map is invalid: {modulemap}")
    digest = hashlib.sha256()
    with binary.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_hash = digest.hexdigest()
    if hashes[identifier] != actual_hash:
        raise SystemExit(f"staged NoritoBridge hash mismatch for {identifier}")

expected_top_level = {
    "Info.plist",
    "NoritoBridge.artifacts.json",
    *expected_slices,
}
privacy_marker = xcframework / ".privacy-production-enabled"
if manifest.get("privacy_production_enabled") is not True:
    raise SystemExit("staged NoritoBridge must include mandatory privacy support")
expected_top_level.add(privacy_marker.name)
test_only_marker = xcframework / ".test-only-prebuilt-slices"
if "test_only_prebuilt_slices" in manifest or test_only_marker.exists():
    raise SystemExit("release staged NoritoBridge contains test-only prebuilt slices")
if {entry.name for entry in xcframework.iterdir()} != expected_top_level:
    raise SystemExit("staged NoritoBridge has unexpected top-level artifacts")

expected_slice_entries = {"Headers", library_name}
expected_header_entries = {
    "NoritoBridge.h",
    "connect_norito_bridge.h",
    "module.modulemap",
}
for identifier in expected_slices:
    slice_path = xcframework / identifier
    headers_path = slice_path / "Headers"
    if {entry.name for entry in slice_path.iterdir()} != expected_slice_entries:
        raise SystemExit(f"staged NoritoBridge slice {identifier} has unexpected files")
    if {entry.name for entry in headers_path.iterdir()} != expected_header_entries:
        raise SystemExit(f"staged NoritoBridge slice {identifier} has unexpected headers")

def fsync_path(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


directories_to_sync = []
for root, directories, files in os.walk(xcframework, topdown=True):
    root_path = Path(root)
    directories_to_sync.append(root_path)
    for name in files:
        fsync_path(root_path / name)
for directory in reversed(directories_to_sync):
    fsync_path(directory)
fsync_path(xcframework.parent)
PY

run_isolated_python \
  "$ROOT_DIR/scripts/validate_norito_bridge_xcframework.py" \
  --root "$ROOT_DIR" \
  --lockfile-path "$CARGO_LOCKFILE" \
  --xcframework "$PUBLISH_XCFRAMEWORK" \
  --manifest "$PUBLISH_MANIFEST" \
  --manifest-link "$PUBLISH_MANIFEST_LINK" \
  --expected-link-target "$CANONICAL_MANIFEST_RELATIVE_TARGET" \
  --swift-loader "$PUBLISH_PROSPECTIVE_LOADER" \
  "${LOCAL_INTEGRATION_ARGS[@]+"${LOCAL_INTEGRATION_ARGS[@]}"}"

assert_bridge_source_seal "staged artifact validation"

if [[ "$CI_HANDOFF_ONLY" == "1" ]]; then
  echo "[+] Deferring the full Apple SDK certification to the digest-authenticated CI consumer" >&2
  assert_bridge_source_seal "pre-handoff artifact verification"
else
  if [[ "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
    MOBILE_SDK_ALLOW_DIRTY_SOURCE=1 \
      MOBILE_SDK_APPLE_ARTIFACT_DIR="$PUBLISH_ROOT" \
      MOBILE_SDK_RUSTUP_BINARY="$RUSTUP_BINARY" \
      MOBILE_SDK_CARGO_HOME="$MOBILE_CARGO_HOME" \
      MOBILE_SDK_CARGO_INVOCATION_DIR="$MOBILE_CARGO_INVOCATION_DIR" \
      MOBILE_SDK_STAGED_BUILD_VALIDATION=1 \
      MOBILE_SDK_PROSPECTIVE_SWIFT_LOADER_PATH="$PUBLISH_PROSPECTIVE_LOADER" \
      bash "$ROOT_DIR/scripts/check_mobile_sdk_artifacts.sh" --root "$ROOT_DIR" --lockfile-path "$CARGO_LOCKFILE" --apple-only \
        "${LOCAL_INTEGRATION_ARGS[@]+"${LOCAL_INTEGRATION_ARGS[@]}"}"
  else
    MOBILE_SDK_APPLE_ARTIFACT_DIR="$PUBLISH_ROOT" \
      MOBILE_SDK_RUSTUP_BINARY="$RUSTUP_BINARY" \
      MOBILE_SDK_CARGO_HOME="$MOBILE_CARGO_HOME" \
      MOBILE_SDK_CARGO_INVOCATION_DIR="$MOBILE_CARGO_INVOCATION_DIR" \
      MOBILE_SDK_STAGED_BUILD_VALIDATION=1 \
      MOBILE_SDK_PROSPECTIVE_SWIFT_LOADER_PATH="$PUBLISH_PROSPECTIVE_LOADER" \
      bash "$ROOT_DIR/scripts/check_mobile_sdk_artifacts.sh" --root "$ROOT_DIR" --lockfile-path "$CARGO_LOCKFILE" --apple-only \
        "${LOCAL_INTEGRATION_ARGS[@]+"${LOCAL_INTEGRATION_ARGS[@]}"}"
  fi

  assert_bridge_source_seal "pre-publication artifact verification"
fi

echo "[+] Removing task-owned staging intermediates before publication" >&2
rm -rf "$STAGE_DIR"

if [[ "$CI_HANDOFF_ONLY" == "1" ]]; then
  # Pin projection leaves its task-private lock in the candidate root. The
  # immutable handoff publishes no live writer state, so remove it before the
  # exact two-entry root check and exclusive rename.
  rm -f "$PUBLISH_PROSPECTIVE_LOADER"
  rm -f "$PUBLISH_ROOT/.NoritoBridge.publish.lockfile"
  run_isolated_python - "$PUBLISH_ROOT" "$CI_HANDOFF_DIR" <<'PY'
import ctypes
import os
from pathlib import Path
import stat
import sys


RENAME_EXCL = 0x00000004
libc = ctypes.CDLL(None, use_errno=True)
staged = Path(sys.argv[1])
handoff = Path(sys.argv[2])
expected_entries = {
    "NoritoBridge.xcframework",
    "NoritoBridge.artifacts.json",
}
if (
    staged.parent != handoff.parent
    or not staged.name.startswith(".NoritoBridge.publish.")
    or staged.is_symlink()
    or not staged.is_dir()
    or {entry.name for entry in staged.iterdir()} != expected_entries
):
    raise SystemExit("CI handoff candidate staging root is not exact")
manifest = staged / "NoritoBridge.artifacts.json"
if (
    not manifest.is_symlink()
    or os.readlink(manifest)
    != "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
):
    raise SystemExit("CI handoff candidate manifest link is not canonical")
try:
    handoff.lstat()
except FileNotFoundError:
    pass
else:
    raise SystemExit("CI handoff candidate destination already exists")
if not hasattr(libc, "renamex_np"):
    raise SystemExit("CI handoff candidate requires macOS exclusive rename support")
renamex_np = libc.renamex_np
renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
renamex_np.restype = ctypes.c_int
if renamex_np(os.fsencode(staged), os.fsencode(handoff), RENAME_EXCL) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), f"{staged} -> {handoff}")
metadata = handoff.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("published CI handoff candidate is not a regular directory")
descriptor = os.open(handoff.parent, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  PUBLISH_ROOT=""
  echo "[+] Atomically staged uncertified CI handoff candidate: $CI_HANDOFF_DIR" >&2
  exit 0
fi

run_isolated_python - \
  "$PUBLISH_XCFRAMEWORK" "$FINAL_XCFRAMEWORK" "$FINAL_MANIFEST" \
  "$CANONICAL_MANIFEST_RELATIVE_TARGET" <<'PY'
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


RENAME_EXCHANGE = 0x00000002
libc = ctypes.CDLL(None, use_errno=True)
SLICE_PATHS = {
    "ios-arm64": "libNoritoBridge.a",
    "ios-arm64_x86_64-simulator": "libNoritoBridge.a",
    "macos-arm64_x86_64": "libNoritoBridge.a",
}


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_manifest_bytes(framework: Path, manifest_bytes: bytes) -> None:
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=object_without_duplicates,
        )
    except (UnicodeError, ValueError, TypeError) as error:
        raise RuntimeError("live NoritoBridge manifest is malformed") from error
    hashes = manifest.get("hashes")
    if not isinstance(hashes, dict) or set(hashes) != set(SLICE_PATHS):
        raise RuntimeError("live NoritoBridge manifest has a non-canonical hash inventory")
    for identifier, library_name in SLICE_PATHS.items():
        binary = framework / identifier / library_name
        if (
            not binary.is_file()
            or binary.is_symlink()
            or (framework / identifier).is_symlink()
        ):
            raise RuntimeError(f"live NoritoBridge slice is not regular: {binary}")
        digest = hashlib.sha256()
        with binary.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if hashes[identifier] != digest.hexdigest():
            raise RuntimeError(f"live NoritoBridge hash mismatch for {identifier}")


def install_public_manifest_link(link: Path, target: str) -> None:
    temporary = link.parent / f".NoritoBridge.artifacts.link.{os.getpid()}"
    if os.path.lexists(temporary):
        raise RuntimeError(f"refusing unexpected manifest-link temporary: {temporary}")
    try:
        os.symlink(target, temporary)
        os.replace(temporary, link)
        fsync_path(link.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def prepare_stable_manifest_link(
    final_framework: Path,
    final_manifest: Path,
    relative_target: str,
) -> None:
    framework_exists = os.path.lexists(final_framework)
    manifest_exists = os.path.lexists(final_manifest)

    if framework_exists:
        if final_framework.is_symlink() or not final_framework.is_dir():
            raise RuntimeError(
                f"refusing unexpected live XCFramework path: {final_framework}"
            )
        embedded = final_framework / "NoritoBridge.artifacts.json"
        if (
            not manifest_exists
            or not final_manifest.is_symlink()
            or os.readlink(final_manifest) != relative_target
        ):
            raise RuntimeError(
                "live XCFramework requires its canonical public manifest link"
            )
        if embedded.is_symlink() or not embedded.is_file():
            raise RuntimeError("canonical public manifest link has no regular target")
        contents = embedded.read_bytes()
        validate_manifest_bytes(final_framework, contents)
        return

    if manifest_exists:
        if (
            not final_manifest.is_symlink()
            or os.readlink(final_manifest) != relative_target
        ):
            raise RuntimeError(
                "refusing an orphaned non-canonical public NoritoBridge manifest"
            )
    else:
        install_public_manifest_link(final_manifest, relative_target)


def exchange(left: Path, right: Path) -> None:
    encoded_left = os.fsencode(left)
    encoded_right = os.fsencode(right)
    if hasattr(libc, "renamex_np"):
        renamex_np = libc.renamex_np
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(encoded_left, encoded_right, RENAME_EXCHANGE)
    elif hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100, encoded_left, -100, encoded_right, RENAME_EXCHANGE
        )
    else:
        raise OSError("this host lacks an atomic path-exchange primitive")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), f"{left} <-> {right}")


def publish(staged: Path, final: Path) -> None:
    if os.path.lexists(final):
        exchange(staged, final)
    else:
        os.rename(staged, final)
    fsync_path(staged.parent)
    fsync_path(final.parent)


staged_xcframework = Path(sys.argv[1])
final_xcframework = Path(sys.argv[2])
final_manifest = Path(sys.argv[3])
relative_target = sys.argv[4]

prepare_stable_manifest_link(
    final_xcframework,
    final_manifest,
    relative_target,
)
publish(staged_xcframework, final_xcframework)
PY

echo "[+] Atomically published XCFramework and canonical manifest: $FINAL_XCFRAMEWORK" >&2
echo "[+] Public manifest link: $FINAL_MANIFEST -> $CANONICAL_MANIFEST_RELATIVE_TARGET" >&2

if [[ -n "$ARCHIVE_OUTPUT" ]]; then
  ARCHIVE_OWNER="$ROOT_DIR/scripts/archive_norito_xcframework.py"
  if [[ ! -f "$ARCHIVE_OWNER" || -L "$ARCHIVE_OWNER" ]]; then
    echo "[-] Deterministic NoritoBridge archive owner is unavailable: $ARCHIVE_OWNER" >&2
    exit 1
  fi
  ARCHIVE_OWNER_ARGUMENTS=(
    --lockfile-path "$CARGO_LOCKFILE"
    --xcframework "$FINAL_XCFRAMEWORK"
    --output "$ARCHIVE_OUTPUT"
    --scratch-dir "$BUILD_DIR"
  )
  if [[ "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
    ARCHIVE_OWNER_ARGUMENTS+=(--allow-dirty-source)
  fi
  env -i \
    HOME="$USER_HOME_DIR" \
    PATH="${PYTHON_BINARY%/*}:${CARGO_BINARY%/*}:${RUSTC_BINARY%/*}:${RUSTDOC_BINARY%/*}:${GIT_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$MOBILE_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    NORITO_BRIDGE_OUTPUT_LOCK_FD="$NORITO_BRIDGE_OUTPUT_LOCK_FD" \
    NORITO_BRIDGE_SEAL_HOME="$USER_HOME_DIR" \
    NORITO_BRIDGE_SEAL_CARGO_HOME="$MOBILE_CARGO_HOME" \
    NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR="$MOBILE_CARGO_INVOCATION_DIR" \
    NORITO_BRIDGE_SEAL_RUSTUP_HOME="$MOBILE_RUSTUP_HOME" \
    NORITO_BRIDGE_SEAL_TMPDIR="$MOBILE_TMPDIR" \
    NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    NORITO_BRIDGE_SEAL_CARGO="$CARGO_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTC="$RUSTC_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTDOC="$RUSTDOC_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTUP="$RUSTUP_BINARY" \
    NORITO_BRIDGE_SEAL_DEVELOPER_DIR="$XCODE_DEVELOPER_DIR" \
    "$PYTHON_BINARY" -I -S -B "$ARCHIVE_OWNER" \
      "${ARCHIVE_OWNER_ARGUMENTS[@]}"
  echo "[+] Deterministic XCFramework archive: $ARCHIVE_OUTPUT" >&2
fi
