#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
CHECK_SCRIPT="$SCRIPT_DIR/check_mobile_sdk_artifacts.sh"
HEADER_GATE="$ROOT_DIR/ci/check_connect_norito_bridge_header.sh"

fail() {
  printf '[mobile-sdk-artifacts-test] ERROR: %s\n' "$*" >&2
  exit 1
}

TEST_PYTHON_BINARY=""
for trusted_python in \
  /opt/homebrew/bin/python3.12 \
  /opt/homebrew/opt/python@3.12/bin/python3.12 \
  /usr/local/bin/python3.12 \
  /usr/local/opt/python@3.12/bin/python3.12 \
  /usr/bin/python3.12 \
  /usr/bin/python3; do
  if [[ -x "$trusted_python" ]] \
    && [[ "$("$trusted_python" -I -S -B -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)" == "3.12" ]]; then
    TEST_PYTHON_BINARY="$trusted_python"
    break
  fi
done
[[ -n "$TEST_PYTHON_BINARY" ]] || fail "pinned Python 3.12 is required"
TEST_PYTHON_BINARY="$("$TEST_PYTHON_BINARY" -I -S -B -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$TEST_PYTHON_BINARY")"
export MOBILE_SDK_PYTHON_BINARY="$TEST_PYTHON_BINARY"

TEST_RUSTUP_BINARY="$(command -v rustup)" || fail "rustup is required"
TEST_RUSTUP_BINARY="$("$TEST_PYTHON_BINARY" -I -S -B -c \
  'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
  "$TEST_RUSTUP_BINARY")" || fail "rustup must resolve to a canonical executable"
[[ "$TEST_RUSTUP_BINARY" == /* && -f "$TEST_RUSTUP_BINARY" \
  && ! -L "$TEST_RUSTUP_BINARY" && -x "$TEST_RUSTUP_BINARY" ]] \
  || fail "rustup must be an absolute canonical non-symbolic executable"
export MOBILE_SDK_RUSTUP_BINARY="$TEST_RUSTUP_BINARY"

[[ -x "$CHECK_SCRIPT" ]] || fail "artifact checker is not executable"
[[ -x "$HEADER_GATE" ]] || fail "bridge-header gate is not executable"
bash -n "$CHECK_SCRIPT"
"$CHECK_SCRIPT" --help >/dev/null

# The sole current wallet ABI is required exactly; all other KAGEMUSHA exports
# remain refused by namespace, including previously unseen retired names.
if grep -Eq 'Java_org_hyperledger_iroha_sdk_offline_(probe_|wallet_)?Kagemusha[A-Za-z0-9_]*_native' "$CHECK_SCRIPT"; then
  fail "artifact checker must not enumerate retired KAGEMUSHA JNI exports"
fi
[[ "$(grep -Fc -- "grep -E '^_?connect_norito_kagemusha_' <<<\"\$symbols\"" "$CHECK_SCRIPT")" == "1" ]] \
  || fail "artifact checker must reject the retired KAGEMUSHA C namespace exactly once"

wallet_symbols=(
  connect_norito_kagemusha_wallet_revision_v1
  connect_norito_kagemusha_wallet_open_begin_v1
  connect_norito_kagemusha_wallet_open_finish_v1
  connect_norito_kagemusha_wallet_open_cancel_v1
  connect_norito_kagemusha_wallet_close_v1
  connect_norito_kagemusha_wallet_activity_v1
  connect_norito_kagemusha_wallet_setup_v1
  connect_norito_kagemusha_wallet_enrollment_v1
  connect_norito_kagemusha_wallet_enrollment_refusal_v1
  connect_norito_kagemusha_wallet_execute_v1
  connect_norito_kagemusha_wallet_load_original_validate_v1
  connect_norito_kagemusha_wallet_request_status_v1
  connect_norito_kagemusha_wallet_retry_v1
  connect_norito_kagemusha_wallet_resume_v1
  connect_norito_kagemusha_wallet_fold_v1
  connect_norito_kagemusha_wallet_credit_status_v1
  connect_norito_kagemusha_wallet_snapshot_v1
  connect_norito_kagemusha_wallet_review_v1
  connect_norito_kagemusha_wallet_execute_reviewed_v1
  connect_norito_kagemusha_wallet_discard_review_v1
  connect_norito_kagemusha_wallet_installation_begin_v1
  connect_norito_kagemusha_wallet_installation_register_v1
  connect_norito_kagemusha_wallet_installation_close_v1
  connect_norito_kagemusha_wallet_registration_source_relocate_v1
)
wallet_jni_symbols=()
for method in revision openBegin openFinish openCancel close activity call setup enrollment enrollmentRefusal execute snapshot review executeReviewed discardReview; do
  wallet_jni_symbols+=("Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_${method}")
done
for method in beginInstallation registerInstallation closeInstallation relocateRegistrationSource; do
  wallet_jni_symbols+=("Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_${method}")
done
wallet_jni_symbols+=("Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletObservationNativeV1_observe")
load_original_jni_symbols=(
  Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate
)
retired_auth_jni_symbols=(
  Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_reserve
  Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_restore
)
required_protocol_symbols=(
  connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1
  "${wallet_symbols[@]}"
)
required_protocol_block="$(sed -n '/^REQUIRED_PROTOCOL_C_SYMBOLS=(/,/^)/p' "$CHECK_SCRIPT")"
for symbol in "${required_protocol_symbols[@]}"; do
  [[ "$(grep -Fc -- "$symbol" <<<"$required_protocol_block")" == "1" ]] \
    || fail "artifact checker must require $symbol exactly once"
done

retired_auditor_capsule_verify_parts=(
  connect_norito_private_settlement_auditor_capsule_response
  verify
  v1
)
retired_symbols=(
  "${retired_auditor_capsule_verify_parts[0]}_${retired_auditor_capsule_verify_parts[1]}_${retired_auditor_capsule_verify_parts[2]}"
)
grep -Fq -- "RETIRED_KAGEMUSHA_C_PREFIX" "$CHECK_SCRIPT" \
  || fail "artifact checker does not reject the retired KAGEMUSHA C namespace"
required_block="$(sed -n '/^REQUIRED_PROTOCOL_C_SYMBOLS=(/,/^)/p' "$CHECK_SCRIPT")"
for symbol in "${retired_symbols[@]}"; do
  if grep -Fq -- "$symbol" <<<"$required_block"; then
    fail "artifact checker still requires retired symbol $symbol"
  fi
  if grep -Fq -- "$symbol" "$CHECK_SCRIPT"; then
    fail "artifact checker must construct retired symbols without publishing them literally"
  fi
done
grep -Fq -- 'RETIRED_AUDITOR_CAPSULE_VERIFY_PARTS' "$CHECK_SCRIPT" \
  || fail "artifact checker does not retain the retired auditor-capsule symbol guard"
grep -Fq -- '--verify-repository-provenance' "$CHECK_SCRIPT" \
  || fail "artifact checker does not require repository provenance verification"

# Exercise the actual binary-symbol gate against synthetic nm inventories. The
# gate source is extracted verbatim; a fake nm prints the fixture file it is given.
symbol_gate_dir="$(mktemp -d "${TMPDIR:-/tmp}/mobile-sdk-symbol-gate.XXXXXX")"
trap 'rm -rf "$symbol_gate_dir"' EXIT
{
  sed -n '/^REQUIRED_PROTOCOL_C_SYMBOLS=(/,/^RETIRED_KAGEMUSHA_C_PREFIX=/p' "$CHECK_SCRIPT"
  sed -n '/^check_binary_symbols() {/,/^}/p' "$CHECK_SCRIPT"
} >"$symbol_gate_dir/gate.sh"
grep -Fq 'check_binary_symbols() {' "$symbol_gate_dir/gate.sh" \
  || fail "artifact checker binary-symbol gate could not be extracted"
printf '#!/usr/bin/env bash\ncat "${!#}"\n' >"$symbol_gate_dir/nm"
chmod 0755 "$symbol_gate_dir/nm"
required_fixture_symbols=()
while IFS= read -r symbol; do
  required_fixture_symbols+=("$symbol")
done < <(bash -c 'source "$1"; printf "%s\n" "${REQUIRED_PROTOCOL_C_SYMBOLS[@]}"' gate "$symbol_gate_dir/gate.sh")
[[ "${#required_fixture_symbols[@]}" -gt 0 ]] || fail "required protocol symbols could not be read"
required_jni_fixture_symbols=("${wallet_jni_symbols[@]}" "${load_original_jni_symbols[@]}")
while IFS= read -r symbol; do
  required_jni_fixture_symbols+=("$symbol")
done < <(bash -c 'source "$1"; printf "%s\n" "${REQUIRED_PRIVACY_JNI_SYMBOLS[@]}"' gate "$symbol_gate_dir/gate.sh")
retired_offline_prefix="$(bash -c 'source "$1"; printf "%s" "$RETIRED_KAGEMUSHA_C_PREFIX"' gate "$symbol_gate_dir/gate.sh")"
[[ "$retired_offline_prefix" == connect_norito_*_ ]] || fail "retired offline prefix could not be read"

run_symbol_gate() {
  local mode="$1"
  local prefix=""
  shift
  [[ "$mode" == "apple" ]] && prefix="_"
  {
    printf "${prefix}%s\n" "${required_fixture_symbols[@]}"
    if [[ "$mode" == "elf" ]]; then
      printf '%s\n' "${required_jni_fixture_symbols[@]}"
    fi
    if [[ "$#" -gt 0 ]]; then
      printf '%s\n' "$@"
    fi
  } >"$symbol_gate_dir/binary"
  PATH="$symbol_gate_dir:$PATH" bash -c '
    set -euo pipefail
    FAILURES=0
    fail() { printf "%s\n" "$*"; FAILURES=1; }
    source "$1"
    check_binary_symbols "$2" fixture "$3"
    exit "$FAILURES"
  ' gate "$symbol_gate_dir/gate.sh" "$symbol_gate_dir/binary" "$mode"
}

for mode in elf apple; do
  run_symbol_gate "$mode" >/dev/null \
    || fail "binary-symbol gate rejected the exact $mode protocol inventory"
done
for retired in \
  "elf connect_norito_kagemusha_wallet_install_runtime_v1" \
  "elf Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_installRuntime" \
  "elf Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletEnrollmentNativeV1_enroll" \
  "elf connect_norito_kagemusha_wallet_sign_v1" \
  "elf connect_norito_kagemusha_wallet_open_v2" \
  "elf Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_sign" \
  "elf connect_norito_kagemusha_wallet_v1_validate" \
  "elf connect_norito_kagemusha_wallet_unknown_v1" \
  "apple _connect_norito_kagemusha_wallet_commit_v2" \
  "apple _connect_norito_kagemusha_wallet_commit_v1" \
  "apple _connect_norito_kagemusha_core_coordinator_open_v1" \
  "elf ${retired_offline_prefix}payment_validate" \
  "apple _${retired_offline_prefix}payment_validate" \
  "elf Java_org_hyperledger_iroha_sdk_offline_KagemushaCoreCoordinatorJniV1_nativeOpenV1" \
  "elf Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetValueCreditJniV1_nativeCreditV1" \
  "elf Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaReserveFinalityJniV1_nativeVerify" \
  "elf Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_nativeCreateV1"; do
  # shellcheck disable=SC2086
  if output="$(run_symbol_gate $retired)"; then
    fail "binary-symbol gate accepted retired export: $retired"
  fi
  grep -Eq 'retired KAGEMUSHA (C|JNI) namespace' <<<"$output" \
    || fail "binary-symbol gate rejected $retired without naming the retired namespace"
done
for retired in "${retired_auth_jni_symbols[@]}"; do
  if output="$(run_symbol_gate elf "$retired")"; then
    fail "binary-symbol gate accepted retired first-device JNI export: $retired"
  fi
  grep -Fq "retired first-device JNI symbol $retired" <<<"$output" \
    || fail "binary-symbol gate rejected $retired without naming the retired first-device export"
done
retired_jni_symbols=()
for ((index = 0; index < 2048; index++)); do
  retired_jni_symbols+=("Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_unknown${index}")
done
if output="$(run_symbol_gate elf "${retired_jni_symbols[@]}")"; then
  fail "binary-symbol gate accepted a large retired JNI inventory"
fi
grep -Fq 'retired KAGEMUSHA JNI namespace' <<<"$output" \
  || fail "binary-symbol gate did not identify the large retired JNI inventory"
complete_required_jni_symbols=("${required_jni_fixture_symbols[@]}")
for missing in "${complete_required_jni_symbols[@]}"; do
  required_jni_fixture_symbols=()
  for symbol in "${complete_required_jni_symbols[@]}"; do
    [[ "$symbol" == "$missing" ]] || required_jni_fixture_symbols+=("$symbol")
  done
  if output="$(run_symbol_gate elf)"; then
    fail "binary-symbol gate accepted missing JNI export $missing"
  fi
  grep -Fq "missing $missing" <<<"$output" \
    || fail "binary-symbol gate did not identify missing JNI export $missing"
done
required_jni_fixture_symbols=("${complete_required_jni_symbols[@]}")
complete_required_symbols=("${required_fixture_symbols[@]}")
required_fixture_symbols=("${complete_required_symbols[@]:1}")
if run_symbol_gate elf >/dev/null; then
  fail "binary-symbol gate accepted a missing required protocol export"
fi
required_fixture_symbols=("${complete_required_symbols[@]}")
for missing in "${wallet_symbols[@]}"; do
  required_fixture_symbols=()
  for symbol in "${complete_required_symbols[@]}"; do
    [[ "$symbol" == "$missing" ]] || required_fixture_symbols+=("$symbol")
  done
  for mode in elf apple; do
    if output="$(run_symbol_gate "$mode")"; then
      fail "binary-symbol gate accepted missing wallet export $missing in $mode"
    fi
    grep -Fq "missing $missing" <<<"$output" \
      || fail "binary-symbol gate did not identify missing wallet export $missing"
  done
done
required_fixture_symbols=("${complete_required_symbols[@]}")

if MOBILE_SDK_REQUIRE_ANDROID_OUTPUTS=invalid "$CHECK_SCRIPT" --android-only >/dev/null 2>&1; then
  fail "artifact checker accepted an invalid Android-output policy"
fi

"$HEADER_GATE" --self-test
"$CHECK_SCRIPT" --root "$ROOT_DIR" --android-only
printf '[mobile-sdk-artifacts-test] first-release mobile SDK contract passed\n'
