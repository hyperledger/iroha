#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/check_mobile_sdk_artifacts.sh [--root <repo-root>] --lockfile-path <absolute-path> [--apple-only|--android-only] [--require-built-android] [--allow-dirty-source] [--local-integration]

Validate the sole first-release mobile SDK surface:
  - canonical NoritoBridge C/header exports and retired export rejection;
  - current Swift and Kotlin SDK packaging;
  - source-authenticated NoritoBridge XCFramework manifest and slices; and
  - optional built Android jars/AARs with both qualified native ABIs.
USAGE
}

ROOT_ARG=""
CARGO_LOCKFILE=""
CHECK_APPLE=1
CHECK_ANDROID=1
REQUIRE_ANDROID_OUTPUTS="${MOBILE_SDK_REQUIRE_ANDROID_OUTPUTS:-0}"
ALLOW_DIRTY_SOURCE="${MOBILE_SDK_ALLOW_DIRTY_SOURCE:-0}"
LOCAL_INTEGRATION=0

if [[ -n "${MOBILE_SDK_SKIP_BINARY_INSPECTION+x}" ]]; then
  echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_SKIP_BINARY_INSPECTION is retired; binary inspection is mandatory" >&2
  exit 64
fi

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
    --root)
      shift
      [[ $# -gt 0 ]] || { echo "[mobile-sdk-artifacts] --root requires a value" >&2; exit 64; }
      ROOT_ARG="$1"
      ;;
    --root=*) ROOT_ARG="${1#*=}" ;;
    --apple-only) CHECK_APPLE=1; CHECK_ANDROID=0 ;;
    --local-integration) LOCAL_INTEGRATION=1 ;;
    --android-only) CHECK_APPLE=0; CHECK_ANDROID=1 ;;
    --require-built-android) REQUIRE_ANDROID_OUTPUTS=1 ;;
    --allow-dirty-source) ALLOW_DIRTY_SOURCE=1 ;;
    --help|-h) usage; exit 0 ;;
    *)
      if [[ -z "$ROOT_ARG" ]]; then
        ROOT_ARG="$1"
      else
        echo "[mobile-sdk-artifacts] unexpected argument: $1" >&2
        usage >&2
        exit 64
      fi
      ;;
  esac
  shift
done

if [[ "$CHECK_APPLE" == "1" ]]; then
if [[ -z "$CARGO_LOCKFILE" ]]; then
  echo "error: --lockfile-path is required; no implicit Cargo.lock selection" >&2
  exit 64
fi
fi

[[ "$REQUIRE_ANDROID_OUTPUTS" == "0" || "$REQUIRE_ANDROID_OUTPUTS" == "1" ]] || {
  echo "[mobile-sdk-artifacts] MOBILE_SDK_REQUIRE_ANDROID_OUTPUTS must be 0 or 1" >&2
  exit 64
}
[[ "$ALLOW_DIRTY_SOURCE" == "0" || "$ALLOW_DIRTY_SOURCE" == "1" ]] || {
  echo "[mobile-sdk-artifacts] MOBILE_SDK_ALLOW_DIRTY_SOURCE must be 0 or 1" >&2
  exit 64
}

if [[ "$LOCAL_INTEGRATION" == "1" ]] && \
    [[ "$CHECK_APPLE" != "1" || "$CHECK_ANDROID" != "0" \
      || "${MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT:-0}" == "1" \
      || -n "${IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH+x}" ]]; then
  echo "[mobile-sdk-artifacts] local integration requires --apple-only and cannot enter a release corridor" >&2
  exit 64
fi
if [[ -z "$ROOT_ARG" ]]; then
  ROOT_ARG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
[[ -d "$ROOT_ARG" ]] || { echo "[mobile-sdk-artifacts] repository root is missing: $ROOT_ARG" >&2; exit 66; }
ROOT_DIR="$(cd "$ROOT_ARG" && pwd -P)"
if [[ -n "${MOBILE_SDK_APPLE_CARGO_LOCK_PATH+x}" ]]; then
  echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_APPLE_CARGO_LOCK_PATH is not part of the first-release artifact contract" >&2
  exit 64
fi

resolve_trusted_python312() {
  local candidate canonical
  local override="${MOBILE_SDK_PYTHON_BINARY:-}"
  local candidates=()

  if [[ -n "$override" ]]; then
    if [[ "$override" != /* || ! -f "$override" || -L "$override" || ! -x "$override" ]]; then
      echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_PYTHON_BINARY must be an absolute canonical regular executable" >&2
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
      echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_PYTHON_BINARY must already name its canonical executable" >&2
      return 1
    fi
    printf '%s\n' "$canonical"
    return 0
  done

  if [[ -n "$override" ]]; then
    echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_PYTHON_BINARY must be an isolated Python 3.12 executable" >&2
  else
    echo "[mobile-sdk-artifacts] ERROR: a trusted absolute Python 3.12 executable is required" >&2
  fi
  return 1
}

CHECK_PYTHON_BINARY="$(resolve_trusted_python312)" || exit 69
CHECK_USER_HOME_DIR="$("$CHECK_PYTHON_BINARY" -I -S -B -c \
  'import os,pathlib,pwd; print(pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True))' \
  2>/dev/null || true)"
if [[ -z "$CHECK_USER_HOME_DIR" ]]; then
  CHECK_USER_HOME_DIR="$("$CHECK_PYTHON_BINARY" -I -S -B -c \
    'import pathlib; print(pathlib.Path.home().resolve(strict=True))')"
fi
CHECK_TMPDIR="/tmp"
if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  CHECK_TMPDIR="$ROOT_DIR/target/norito-bridge-local/build"
fi
for trusted_path in "$CHECK_PYTHON_BINARY" "$CHECK_USER_HOME_DIR" "$CHECK_TMPDIR"; do
  if [[ "$trusted_path" != /* ]]; then
    echo "[mobile-sdk-artifacts] ERROR: verifier runtime path is not absolute: $trusted_path" >&2
    exit 69
  fi
done
if [[ ! -f "$CHECK_PYTHON_BINARY" || -L "$CHECK_PYTHON_BINARY" \
  || ! -x "$CHECK_PYTHON_BINARY" || ! -d "$CHECK_USER_HOME_DIR" \
  || ! -d "$CHECK_TMPDIR" ]]; then
  echo "[mobile-sdk-artifacts] ERROR: verifier runtime paths are not canonical regular files/directories" >&2
  exit 69
fi

run_isolated_checker_python() {
  env -i \
    HOME="$CHECK_USER_HOME_DIR" \
    PATH="${CHECK_PYTHON_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$CHECK_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    "$CHECK_PYTHON_BINARY" -I -S -B "$@"
}

if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
  CHECK_TMPDIR="$(run_isolated_checker_python \
    "$ROOT_DIR/scripts/norito_bridge_local_integration.py" --root "$ROOT_DIR" \
    --path "$CHECK_TMPDIR" --role build)" || exit 69
fi

SOURCE_SEAL_TOOLS_INITIALIZED=0
SOURCE_SEAL_CARGO_BINARY=""
SOURCE_SEAL_RUSTC_BINARY=""
SOURCE_SEAL_RUSTDOC_BINARY=""
SOURCE_SEAL_RUSTUP_BINARY=""
SOURCE_SEAL_CARGO_HOME="$CHECK_USER_HOME_DIR/.cargo"
SOURCE_SEAL_CARGO_INVOCATION_DIR="$ROOT_DIR"
if [[ "${MOBILE_SDK_CARGO_INVOCATION_DIR+x}" == "x" \
    && "$MOBILE_SDK_CARGO_INVOCATION_DIR" != "$ROOT_DIR" ]]; then
  SOURCE_SEAL_CARGO_INVOCATION_DIR="$(run_isolated_checker_python \
    "$ROOT_DIR/scripts/norito_bridge_local_integration.py" --root "$ROOT_DIR" \
    --path "$MOBILE_SDK_CARGO_INVOCATION_DIR" --role cargo-invocation)" || exit 69
fi
if [[ "${MOBILE_SDK_CARGO_HOME+x}" == "x" ]]; then
  cargo_home_scope=()
  if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
    cargo_home_scope=(--local-integration)
  fi
  SOURCE_SEAL_CARGO_HOME="$(run_isolated_checker_python \
    "$ROOT_DIR/scripts/norito_bridge_local_integration.py" --root "$ROOT_DIR" \
    --path "$MOBILE_SDK_CARGO_HOME" --role cargo-home \
    "${cargo_home_scope[@]+"${cargo_home_scope[@]}"}")" || exit 69
fi
SOURCE_SEAL_RUSTUP_HOME="$CHECK_USER_HOME_DIR/.rustup"
SOURCE_SEAL_CARGO_TARGET_DIR=""
SOURCE_SEAL_DEVELOPER_DIR=""
CHECK_RUSTUP_OVERRIDE=""

if [[ -n "${MOBILE_SDK_RUSTUP_BINARY+x}" ]]; then
  CHECK_RUSTUP_OVERRIDE="$MOBILE_SDK_RUSTUP_BINARY"
  if [[ -z "$CHECK_RUSTUP_OVERRIDE" || "$CHECK_RUSTUP_OVERRIDE" != /* ]] \
    || ! canonical_rustup_binary="$(run_isolated_checker_python -c \
      'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
      "$CHECK_RUSTUP_OVERRIDE")" \
    || [[ "$canonical_rustup_binary" != "$CHECK_RUSTUP_OVERRIDE" ]] \
    || [[ ! -f "$CHECK_RUSTUP_OVERRIDE" || -L "$CHECK_RUSTUP_OVERRIDE" \
      || ! -x "$CHECK_RUSTUP_OVERRIDE" ]]; then
    echo "[mobile-sdk-artifacts] ERROR: MOBILE_SDK_RUSTUP_BINARY must be an absolute canonical non-symbolic executable" >&2
    exit 69
  fi
fi

initialize_source_seal_tools() {
  local actual_toolchain developer_dir
  if [[ "$SOURCE_SEAL_TOOLS_INITIALIZED" == "1" ]]; then
    return
  fi
  if [[ -n "${MOBILE_SDK_RUSTUP_BINARY+x}" ]]; then
    SOURCE_SEAL_RUSTUP_BINARY="$CHECK_RUSTUP_OVERRIDE"
  else
    SOURCE_SEAL_RUSTUP_BINARY="$CHECK_USER_HOME_DIR/.cargo/bin/rustup"
  fi
  if [[ ! -f "$SOURCE_SEAL_RUSTUP_BINARY" || -L "$SOURCE_SEAL_RUSTUP_BINARY" \
    || ! -x "$SOURCE_SEAL_RUSTUP_BINARY" || ! -x /usr/bin/git ]]; then
    echo "[mobile-sdk-artifacts] ERROR: pinned rustup and Git are required for source authentication" >&2
    return 1
  fi
  actual_toolchain="$(
    /usr/bin/sed -nE \
      's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' \
      "$ROOT_DIR/rust-toolchain.toml"
  )"
  if [[ "$actual_toolchain" != "1.93.1" ]]; then
    echo "[mobile-sdk-artifacts] ERROR: source authentication requires exact Rust 1.93.1" >&2
    return 1
  fi
  if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    echo "[mobile-sdk-artifacts] ERROR: source authentication requires an explicit CARGO_TARGET_DIR" >&2
    return 1
  fi
  if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
    SOURCE_SEAL_CARGO_TARGET_DIR="$(run_isolated_checker_python \
      "$ROOT_DIR/scripts/norito_bridge_local_integration.py" --root "$ROOT_DIR" \
      --path "$CARGO_TARGET_DIR" --role cargo)" || return 1
  else
  if ! SOURCE_SEAL_CARGO_TARGET_DIR="$(run_isolated_checker_python - \
      "$CARGO_TARGET_DIR" "$ROOT_DIR" <<'PY'
import os
from pathlib import Path
import stat
import sys

candidate = Path(sys.argv[1])
source_root = Path(sys.argv[2])
if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
    raise SystemExit(1)
try:
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
except OSError:
    raise SystemExit(1) from None
if (
    resolved != candidate
    or stat.S_ISLNK(metadata.st_mode)
    or not stat.S_ISDIR(metadata.st_mode)
    or not os.access(candidate, os.R_OK | os.W_OK | os.X_OK)
    or candidate == source_root
    or source_root in candidate.parents
):
    raise SystemExit(1)
print(candidate)
PY
  )"; then
    echo "[mobile-sdk-artifacts] ERROR: CARGO_TARGET_DIR must be a writable, non-symbolic canonical directory outside the Iroha source tree" >&2
    return 1
  fi
  fi
  SOURCE_SEAL_CARGO_BINARY="$(
    env -i \
      HOME="$CHECK_USER_HOME_DIR" \
      PATH="${SOURCE_SEAL_RUSTUP_BINARY%/*}:/usr/bin:/bin" \
      CARGO_HOME="$SOURCE_SEAL_CARGO_HOME" \
      RUSTUP_HOME="$SOURCE_SEAL_RUSTUP_HOME" \
      TMPDIR="$CHECK_TMPDIR" \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      "$SOURCE_SEAL_RUSTUP_BINARY" which --toolchain 1.93.1 cargo
  )" || return 1
  SOURCE_SEAL_RUSTC_BINARY="$(
    env -i \
      HOME="$CHECK_USER_HOME_DIR" \
      PATH="${SOURCE_SEAL_RUSTUP_BINARY%/*}:/usr/bin:/bin" \
      CARGO_HOME="$SOURCE_SEAL_CARGO_HOME" \
      RUSTUP_HOME="$SOURCE_SEAL_RUSTUP_HOME" \
      TMPDIR="$CHECK_TMPDIR" \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      "$SOURCE_SEAL_RUSTUP_BINARY" which --toolchain 1.93.1 rustc
  )" || return 1
  SOURCE_SEAL_RUSTDOC_BINARY="$(
    env -i \
      HOME="$CHECK_USER_HOME_DIR" \
      PATH="${SOURCE_SEAL_RUSTUP_BINARY%/*}:/usr/bin:/bin" \
      CARGO_HOME="$SOURCE_SEAL_CARGO_HOME" \
      RUSTUP_HOME="$SOURCE_SEAL_RUSTUP_HOME" \
      TMPDIR="$CHECK_TMPDIR" \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      "$SOURCE_SEAL_RUSTUP_BINARY" which --toolchain 1.93.1 rustdoc
  )" || return 1
  SOURCE_SEAL_CARGO_BINARY="$(run_isolated_checker_python -c \
    'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$SOURCE_SEAL_CARGO_BINARY")"
  SOURCE_SEAL_RUSTC_BINARY="$(run_isolated_checker_python -c \
    'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$SOURCE_SEAL_RUSTC_BINARY")"
  SOURCE_SEAL_RUSTDOC_BINARY="$(run_isolated_checker_python -c \
    'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$SOURCE_SEAL_RUSTDOC_BINARY")"
  if [[ ! -x "$SOURCE_SEAL_CARGO_BINARY" || ! -x "$SOURCE_SEAL_RUSTC_BINARY" \
    || ! -x "$SOURCE_SEAL_RUSTDOC_BINARY" ]]; then
    echo "[mobile-sdk-artifacts] ERROR: exact Rust 1.93.1 Cargo/rustc/rustdoc are unavailable" >&2
    return 1
  fi
  developer_dir="${NORITO_BRIDGE_SEAL_DEVELOPER_DIR:-${NORITO_BRIDGE_DEVELOPER_DIR:-}}"
  if [[ -z "$developer_dir" ]]; then
    if [[ ! -x /usr/bin/xcode-select ]]; then
      echo "[mobile-sdk-artifacts] ERROR: Xcode developer directory is required for Apple source authentication" >&2
      return 1
    fi
    developer_dir="$(/usr/bin/xcode-select -p)" || return 1
  fi
  if ! SOURCE_SEAL_DEVELOPER_DIR="$(run_isolated_checker_python - \
      "$developer_dir" <<'PY'
import os
from pathlib import Path
import stat
import sys

candidate = Path(sys.argv[1])
if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
    raise SystemExit(1)
try:
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
except OSError:
    raise SystemExit(1) from None
if resolved != candidate or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(1)
print(candidate)
PY
  )"; then
    echo "[mobile-sdk-artifacts] ERROR: Xcode developer directory must be canonical and non-symbolic" >&2
    return 1
  fi
  SOURCE_SEAL_TOOLS_INITIALIZED=1
}

run_source_authenticated_python() {
  initialize_source_seal_tools || return 1
  env -i \
    HOME="$CHECK_USER_HOME_DIR" \
    PATH="${CHECK_PYTHON_BINARY%/*}:${SOURCE_SEAL_CARGO_BINARY%/*}:${SOURCE_SEAL_RUSTC_BINARY%/*}:${SOURCE_SEAL_RUSTDOC_BINARY%/*}:/usr/bin:/bin" \
    TMPDIR="$CHECK_TMPDIR" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    NORITO_BRIDGE_SEAL_HOME="$CHECK_USER_HOME_DIR" \
    NORITO_BRIDGE_SEAL_CARGO_HOME="$SOURCE_SEAL_CARGO_HOME" \
    NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR="$SOURCE_SEAL_CARGO_INVOCATION_DIR" \
    NORITO_BRIDGE_SEAL_RUSTUP_HOME="$SOURCE_SEAL_RUSTUP_HOME" \
    NORITO_BRIDGE_SEAL_TMPDIR="$CHECK_TMPDIR" \
    NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR="$SOURCE_SEAL_CARGO_TARGET_DIR" \
    NORITO_BRIDGE_SEAL_CARGO="$SOURCE_SEAL_CARGO_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTC="$SOURCE_SEAL_RUSTC_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTDOC="$SOURCE_SEAL_RUSTDOC_BINARY" \
    NORITO_BRIDGE_SEAL_RUSTUP="$SOURCE_SEAL_RUSTUP_BINARY" \
    NORITO_BRIDGE_SEAL_DEVELOPER_DIR="$SOURCE_SEAL_DEVELOPER_DIR" \
    "$CHECK_PYTHON_BINARY" -I -S -B "$@"
}

FAILURES=0
fail() {
  echo "[mobile-sdk-artifacts] ERROR: $*" >&2
  FAILURES=1
}

require_file() {
  local path="$1"
  local label="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "missing $label: $path"
}

require_literal() {
  local path="$1"
  local literal="$2"
  local label="$3"
  if [[ ! -f "$path" ]] || ! grep -Fq -- "$literal" "$path"; then
    fail "$label is not exact in $path"
  fi
}

REQUIRED_PROTOCOL_C_SYMBOLS=(
  connect_norito_bridge_abi_version
  connect_norito_domain_id_validate_v1
  connect_norito_free
  connect_norito_chain_discriminant_scope_enter
  connect_norito_chain_discriminant_scope_exit
  connect_norito_encode_transfer_signed_transaction
  connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg
  connect_norito_encode_transfer_instruction_box
  connect_norito_detached_transaction_scaffold_inspect_v1
  connect_norito_detached_transaction_scaffold_finalize_ed25519_v1
  connect_norito_canonical_json_blake3_v1
  connect_norito_encode_account_onboarding_plan_body_v1
  connect_norito_alias_instruction_round_trip_v1
  connect_norito_account_read_permission_multisig_payload_hash
  connect_norito_account_read_permission_multisig_finalize
  connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1
  connect_norito_parliament_timed_ovn_verify_casting_proof_v1
  connect_norito_parliament_timed_ovn_registration_from_proof_v1
  connect_norito_parliament_timed_ovn_ballot_from_proof_v1
  iroha_privacy_compiled_profile_catalog_v1
  iroha_privacy_validate_compiled_profile_catalog_v1
  iroha_privacy_exact12_fixture_bundle_v1
  iroha_privacy_validate_exact12_fixture_bundle_v1
  iroha_privacy_validate_exact12_capability_manifest_v1
  iroha_privacy_free_buffer
  connect_norito_sorafs_reference_validate_bundle_json
  connect_norito_sorafs_reference_validate_governance_json
  connect_norito_sorafs_reference_validate_governance_dag_block_json
  connect_norito_sorafs_reference_validate_governance_dag_head_chain_json
  connect_norito_validation_fee_current_policy_proof_request_v1
  connect_norito_validation_fee_current_policy_proof_verify_v1
  connect_norito_retail_fee_intent_hash_v1
  connect_norito_retail_fee_assessment_marker_v1
  connect_norito_retail_fee_assessment_decode_v1
  connect_norito_private_settlement_committee_proof_response_verify_v1
  connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1
  connect_norito_private_settlement_audit_approval_response_verify_v1
  connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json
)
RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS=(
  connect_norito_private_settlement_auditor_capsule_response
  verify
  v1
)
RETIRED_PROTOCOL_C_SYMBOLS=(
  "${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[0]}_${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[1]}_${RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS[2]}"
)
RETIRED_KAGEMUSHA_PARTS=(cash offline)
RETIRED_KAGEMUSHA_C_PREFIX="connect_norito_${RETIRED_KAGEMUSHA_PARTS[1]}_${RETIRED_KAGEMUSHA_PARTS[0]}_"

check_source_contract() {
  local gate="$ROOT_DIR/ci/check_connect_norito_bridge_header.sh"
  require_file "$gate" "NoritoBridge header parity gate"
  if [[ -f "$gate" ]] && ! bash "$gate"; then
    fail "NoritoBridge C/Rust export parity failed"
  fi
}

check_binary_symbols() {
  local binary="$1"
  local label="$2"
  local nm_mode="$3"
  local symbols
  if ! command -v nm >/dev/null 2>&1; then
    fail "nm is required to inspect $label"
    return
  fi
  if [[ "$nm_mode" == "apple" ]]; then
    symbols="$(nm -gUj "$binary" 2>/dev/null || true)"
  else
    symbols="$(nm -D --defined-only "$binary" 2>/dev/null | awk '{print $NF}' || true)"
  fi
  [[ -n "$symbols" ]] || { fail "$label has no inspectable exported symbols"; return; }
  local symbol
  if [[ "$nm_mode" == "elf" ]]; then
    local retired_jni_prefix
    for retired_jni_prefix in \
      Java_org_hyperledger_iroha_sdk_offline_Kagemusha \
      Java_org_hyperledger_iroha_sdk_offline_probe_Kagemusha \
      Java_org_hyperledger_iroha_sdk_offline_wallet_Kagemusha \
      Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_; do
      if grep -Eq "^${retired_jni_prefix}" <<<"$symbols"; then
        fail "$label exposes a retired KAGEMUSHA JNI namespace"
      fi
    done
  fi
  for symbol in "${REQUIRED_PROTOCOL_C_SYMBOLS[@]}"; do
    if ! grep -Eq "^_?${symbol}$" <<<"$symbols"; then
      fail "$label is missing $symbol"
    fi
  done
  for symbol in "${RETIRED_PROTOCOL_C_SYMBOLS[@]}"; do
    if grep -Eq "^_?${symbol}$" <<<"$symbols"; then
      fail "$label exposes retired protocol symbol $symbol"
    fi
  done
  if grep -Eq "^_?${RETIRED_KAGEMUSHA_C_PREFIX}" <<<"$symbols"; then
    fail "$label exposes a retired KAGEMUSHA C namespace"
  fi
  if grep -Eq '^_?connect_norito_kagemusha_' <<<"$symbols"; then
    fail "$label exposes a retired KAGEMUSHA C namespace"
  fi
}

check_apple() {
  local artifact_root="${MOBILE_SDK_APPLE_ARTIFACT_DIR:-$ROOT_DIR/dist}"
  [[ "$artifact_root" == /* ]] || artifact_root="$ROOT_DIR/$artifact_root"
  local xcframework="$artifact_root/NoritoBridge.xcframework"
  local manifest="$xcframework/NoritoBridge.artifacts.json"
  local manifest_link="$artifact_root/NoritoBridge.artifacts.json"
  local loader="$ROOT_DIR/IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
  if [[ "${MOBILE_SDK_STAGED_BUILD_VALIDATION:-0}" == "1" ]]; then
    loader="${MOBILE_SDK_PROSPECTIVE_SWIFT_LOADER_PATH:-}"
  fi

  require_file "$ROOT_DIR/IrohaSwift/Package.swift" "Swift package manifest"
  require_literal "$ROOT_DIR/IrohaSwift/Package.swift" 'name: "NoritoBridge"' "Swift binary target"
  require_file "$loader" "Swift native bridge hash owner"
  require_file "$manifest" "embedded NoritoBridge manifest"
  [[ -L "$manifest_link" ]] || fail "public NoritoBridge manifest must be a relative symlink"

  if [[ -f "$manifest" && -f "$loader" ]]; then
    local validation=(
      "$ROOT_DIR/scripts/validate_norito_bridge_xcframework.py"
      --root "$ROOT_DIR"
      --lockfile-path "$CARGO_LOCKFILE"
      --xcframework "$xcframework"
      --manifest "$manifest"
      --manifest-link "$manifest_link"
      --expected-link-target "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
      --swift-loader "$loader"
      --verify-repository-provenance
    )
    if [[ "$LOCAL_INTEGRATION" == "1" ]]; then
      validation+=(--local-integration)
    fi
    if [[ "$ALLOW_DIRTY_SOURCE" == "1" ]]; then
      validation+=(--allow-dirty-source)
    fi
    if ! run_source_authenticated_python "${validation[@]}"; then
      fail "strict NoritoBridge XCFramework validation failed"
    fi
  fi

  if [[ "$(uname -s)" == "Darwin" && -d "$xcframework" ]]; then
    local slice
    for slice in ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64; do
      local binary="$xcframework/$slice/libNoritoBridge.a"
      require_file "$binary" "NoritoBridge $slice library"
      [[ -f "$binary" ]] && check_binary_symbols "$binary" "NoritoBridge $slice" apple
    done
  fi
}

check_android() {
  local settings="$ROOT_DIR/kotlin/settings.gradle.kts"
  require_file "$settings" "Kotlin settings"
  require_literal "$settings" 'include(":core-jvm")' "Kotlin core-jvm module"
  require_literal "$settings" 'include(":client-android")' "Kotlin client-android module"
  require_literal "$settings" 'include(":kagemusha-wallet-android")' "Kotlin wallet module"
  require_file "$ROOT_DIR/kotlin/core-jvm/build.gradle.kts" "Kotlin core-jvm build"
  require_file "$ROOT_DIR/kotlin/client-android/build.gradle.kts" "Kotlin client-android build"
  require_file "$ROOT_DIR/kotlin/kagemusha-wallet-android/build.gradle.kts" "Kotlin wallet build"

  if [[ "$REQUIRE_ANDROID_OUTPUTS" != "1" ]]; then
    return 0
  fi
  local paths jar aar wallet_aar remainder
  local path_arguments=("$ROOT_DIR/scripts/mobile_sdk_android_artifacts.py" --root "$ROOT_DIR")
  if [[ -n "${MOBILE_SDK_ANDROID_ARTIFACT_DIR+x}" ]]; then
    path_arguments+=(--artifact-dir "$MOBILE_SDK_ANDROID_ARTIFACT_DIR")
  fi
  if [[ -n "${MOBILE_SDK_MAVEN_VERSION:-}" ]]; then
    path_arguments+=(--version "$MOBILE_SDK_MAVEN_VERSION")
  fi
  paths="$(run_isolated_checker_python "${path_arguments[@]}")" || {
    fail "canonical Kotlin Android build artifacts are missing or invalid"
    return
  }
  jar="${paths%%$'\n'*}"
  remainder="${paths#*$'\n'}"
  aar="${remainder%%$'\n'*}"
  wallet_aar="${remainder#*$'\n'}"
  [[ "$paths" != "$remainder" && "$remainder" != "$wallet_aar" && "$wallet_aar" != *$'\n'* ]] || {
    fail "canonical Android artifact selection must return exactly three paths"
    return
  }
  require_file "$jar" "core-jvm runtime JAR"
  require_file "$wallet_aar" "kagemusha-wallet-android release AAR"
  require_file "$aar" "client-android release AAR"
  [[ -f "$aar" ]] || return
  command -v unzip >/dev/null 2>&1 || { fail "unzip is required for Android artifact validation"; return; }
  local entry
  for entry in AndroidManifest.xml classes.jar; do
    if ! unzip -Z1 "$wallet_aar" | grep -Fxq -- "$entry"; then
      fail "kagemusha-wallet-android release AAR is missing $entry"
    fi
  done
  for entry in \
    AndroidManifest.xml \
    classes.jar \
    assets/iroha/native-build-provenance-v1.json \
    jni/arm64-v8a/libconnect_norito_bridge.so \
    jni/x86_64/libconnect_norito_bridge.so; do
    if ! unzip -Z1 "$aar" | grep -Fxq -- "$entry"; then
      fail "client-android release AAR is missing $entry"
    fi
  done

  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/iroha-mobile-sdk.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  local abi
  for abi in arm64-v8a x86_64; do
    local archive_entry="jni/$abi/libconnect_norito_bridge.so"
    if unzip -p "$aar" "$archive_entry" >"$tmp/$abi.so"; then
      check_binary_symbols "$tmp/$abi.so" "client-android $abi bridge" elf
    else
      fail "unable to extract client-android $abi bridge"
    fi
  done
}

check_source_contract
if [[ "$CHECK_APPLE" == "1" ]]; then
  check_apple
fi
if [[ "$CHECK_ANDROID" == "1" ]]; then
  check_android
fi

if [[ "$FAILURES" -ne 0 ]]; then
  echo "[mobile-sdk-artifacts] validation failed for $ROOT_DIR" >&2
  exit 1
fi
echo "[mobile-sdk-artifacts] validation passed for $ROOT_DIR"
