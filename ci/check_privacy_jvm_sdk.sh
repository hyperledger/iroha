#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${PRIVACY_JVM_SDK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=ci/privacy_sdk_cargo_lockfile.sh
source "${ROOT_DIR}/ci/privacy_sdk_cargo_lockfile.sh"
JAVA_HOME_OVERRIDE="${PRIVACY_JVM_SDK_JAVA_HOME:-}"
PYTHON_BIN="${PRIVACY_JVM_SDK_PYTHON_BIN:-python3}"
CARGO_BIN="${PRIVACY_JVM_SDK_CARGO_BIN:-cargo}"
RUSTC_BIN="${PRIVACY_JVM_SDK_RUSTC_BIN:-rustc}"
ABI31_CHECKER="${ROOT_DIR}/scripts/check_native_sdk_artifact.py"
JAVA_OUT="$(mktemp -d "${TMPDIR:-/tmp}/iroha-privacy-java-sdk-test.XXXXXX")"
NATIVE_BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/iroha-privacy-jvm-native.XXXXXX")"

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "${JAVA_OUT}" "${NATIVE_BUILD_ROOT}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "error: $*" >&2
  exit 1
}

sha256_file() {
  "${PYTHON_BIN}" -I -S - "$1" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as source:
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

SELECTED_CARGO_LOCK="${IROHA_PRIVACY_AUTHENTICATED_CARGO_LOCKFILE_PATH:-}"
[[ -f "${SELECTED_CARGO_LOCK}" && ! -L "${SELECTED_CARGO_LOCK}" ]] \
  || fail "the authenticated privacy Cargo.lock is unavailable"
[[ "${SELECTED_CARGO_LOCK}" != "${ROOT_DIR}/Cargo.lock" ]] \
  || fail "the privacy release Cargo.lock must remain distinct from the tracked root lock"
[[ "$(sha256_file "${SELECTED_CARGO_LOCK}")" == "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" ]] \
  || fail "the authenticated privacy Cargo.lock does not match the canonical reviewed graph"
[[ -f "${ROOT_DIR}/Cargo.lock" && ! -L "${ROOT_DIR}/Cargo.lock" ]] \
  || fail "the tracked root Cargo.lock is unavailable"
[[ "$(sha256_file "${ROOT_DIR}/Cargo.lock")" == "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" ]] \
  || fail "the tracked root Cargo.lock does not match the canonical reviewed graph"

RUSTC_VERSION="$("${RUSTC_BIN}" --version)"
[[ "${RUSTC_VERSION}" == rustc\ 1.93.1\ * ]] \
  || fail "privacy JVM native execution requires exact rustc 1.93.1"
HOST_TRIPLE="$("${RUSTC_BIN}" -vV | sed -n 's/^host: //p')"
[[ "${HOST_TRIPLE}" =~ ^[A-Za-z0-9_.-]+$ ]] \
  || fail "rustc returned a non-canonical host triple"
export NORITO_SKIP_BINDINGS_SYNC=1

SOURCE_MANIFEST_BEFORE="$("${PYTHON_BIN}" -I -S "${ROOT_DIR}/scripts/compute_workspace_source_manifest.py" \
  --root "${ROOT_DIR}" --native-artifact-manifest)"
[[ "${SOURCE_MANIFEST_BEFORE}" =~ ^[0-9a-f]{64}$ ]] \
  || fail "native JVM source manifest is not canonical"

if [[ -n "${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR:-}" ]]; then
  BUILD_TARGET_DIR="${IROHA_PRIVACY_AUTHENTICATED_CARGO_TARGET_DIR}"
  "${CARGO_BIN}" build --locked -p connect_norito_bridge --lib \
    --features privacy-production-enabled \
    --target-dir "${BUILD_TARGET_DIR}"
  "${CARGO_BIN}" build --locked -p kotlin-fixture-gen \
    --features dev-tools --bin kotlin-fixture-gen \
    --target-dir "${BUILD_TARGET_DIR}"
  TARGET_ARTIFACT_DIR="${BUILD_TARGET_DIR}/debug"
else
  BUILD_TARGET_DIR="${NATIVE_BUILD_ROOT}/target"
  "${CARGO_BIN}" build --locked -p connect_norito_bridge --lib \
    --features privacy-production-enabled \
    --target "${HOST_TRIPLE}" \
    --target-dir "${BUILD_TARGET_DIR}"
  "${CARGO_BIN}" build --locked -p kotlin-fixture-gen \
    --features dev-tools --bin kotlin-fixture-gen \
    --target "${HOST_TRIPLE}" \
    --target-dir "${BUILD_TARGET_DIR}"
  TARGET_ARTIFACT_DIR="${BUILD_TARGET_DIR}/${HOST_TRIPLE}/debug"
fi
[[ "$("${PYTHON_BIN}" -I -S "${ROOT_DIR}/scripts/compute_workspace_source_manifest.py" \
  --root "${ROOT_DIR}" --native-artifact-manifest)" == "${SOURCE_MANIFEST_BEFORE}" ]] \
  || fail "native JVM source changed while bridge and fixture generator were built"

case "${HOST_TRIPLE}" in
  *-apple-*) NATIVE_LIBRARY="${TARGET_ARTIFACT_DIR}/libconnect_norito_bridge.dylib" ;;
  *-windows-*) NATIVE_LIBRARY="${TARGET_ARTIFACT_DIR}/connect_norito_bridge.dll" ;;
  *) NATIVE_LIBRARY="${TARGET_ARTIFACT_DIR}/libconnect_norito_bridge.so" ;;
esac
[[ -f "${NATIVE_LIBRARY}" && ! -L "${NATIVE_LIBRARY}" ]] \
  || fail "fresh ABI31 privacy JVM bridge is unavailable: ${NATIVE_LIBRARY}"
# This is the exact same-target dev-tools output just built above, never an
# inherited path or a Cargo command launched by a JVM test.
case "${HOST_TRIPLE}" in
  *-windows-*) FIXTURE_GENERATOR="${TARGET_ARTIFACT_DIR}/kotlin-fixture-gen.exe" ;;
  *) FIXTURE_GENERATOR="${TARGET_ARTIFACT_DIR}/kotlin-fixture-gen" ;;
esac
[[ -f "${FIXTURE_GENERATOR}" && ! -L "${FIXTURE_GENERATOR}" && -x "${FIXTURE_GENERATOR}" ]] \
  || fail "fresh dev-tools kotlin-fixture-gen is unavailable: ${FIXTURE_GENERATOR}"
FIXTURE_GENERATOR_SHA256="$(sha256_file "${FIXTURE_GENERATOR}")"

NATIVE_LIBRARY_DIR="$(cd "$(dirname "${NATIVE_LIBRARY}")" && pwd -P)"
NATIVE_MANIFEST="${NATIVE_BUILD_ROOT}/native-sdk-abi31.json"
CSHARP_NATIVE_MANIFEST="${NATIVE_BUILD_ROOT}/native-sdk-abi31-csharp.json"

# Native evidence binds the clean source tree, including the tracked root lock.
# The independently sealed canonical graph snapshot remains external for all
# wrapped Cargo invocations and is authenticated independently above.

"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" record \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}" \
  --sdk c-jni \
  --target "${HOST_TRIPLE}"
"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}"
"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" record \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${CSHARP_NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}" \
  --sdk csharp \
  --target "${HOST_TRIPLE}"
"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${CSHARP_NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}"

export IROHA_NATIVE_LIBRARY_PATH="${NATIVE_LIBRARY_DIR}"
export IROHA_KOTLIN_FIXTURE_GEN_BIN="${FIXTURE_GENERATOR}"
export IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE=1
case "${HOST_TRIPLE}" in
  *-apple-*) export DYLD_LIBRARY_PATH="${NATIVE_LIBRARY_DIR}" ;;
  *-windows-*) export PATH="${NATIVE_LIBRARY_DIR}:${PATH}" ;;
  *) export LD_LIBRARY_PATH="${NATIVE_LIBRARY_DIR}" ;;
esac

is_java_21_home() {
  local java_home="$1"
  local version_line
  [[ -x "${java_home}/bin/java" ]] || return 1
  version_line="$("${java_home}/bin/java" -version 2>&1 | head -n 1)"
  [[ "${version_line}" =~ version[[:space:]]+\"21(\.|\") ]]
}

resolve_java_home() {
  if [[ -n "${JAVA_HOME_OVERRIDE}" ]]; then
    if is_java_21_home "${JAVA_HOME_OVERRIDE}"; then
      printf '%s\n' "${JAVA_HOME_OVERRIDE}"
      return 0
    fi
    echo "PRIVACY_JVM_SDK_JAVA_HOME must point to a JDK 21 home." >&2
    return 1
  fi
  if [[ -n "${JAVA_HOME:-}" ]]; then
    if is_java_21_home "${JAVA_HOME}"; then
      printf '%s\n' "${JAVA_HOME}"
      return 0
    fi
    echo "JAVA_HOME must point to a JDK 21 home for privacy JVM SDK tests." >&2
    return 1
  fi
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    local macos_java_home
    if macos_java_home="$(/usr/libexec/java_home -v 21 2>/dev/null)" \
      && is_java_21_home "${macos_java_home}"; then
      printf '%s\n' "${macos_java_home}"
      return 0
    fi
  fi
  local candidates=(
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
    /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
    /opt/homebrew/Cellar/openjdk@21/*/libexec/openjdk.jdk/Contents/Home
    /usr/local/Cellar/openjdk@21/*/libexec/openjdk.jdk/Contents/Home
    /usr/lib/jvm/java-21-openjdk
    /usr/lib/jvm/java-21-openjdk-amd64
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if is_java_21_home "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  echo "JDK 21 is required for privacy JVM SDK tests." >&2
  return 1
}

JAVA_HOME="$(resolve_java_home)"
export JAVA_HOME
"${JAVA_HOME}/bin/java" -version

cd "${ROOT_DIR}/kotlin"
./gradlew --no-daemon -q :core-jvm:jar :core-jvm:test --no-build-cache --rerun-tasks \
  --tests org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridgeTest \
  --tests org.hyperledger.iroha.sdk.privacy.PrivacyExact12FixtureCodecV1Test \
  --tests org.hyperledger.iroha.sdk.privacy.PrivacyExact12FixtureJavaConsumerTest \
  --tests org.hyperledger.iroha.sdk.core.model.zk.VerifyingKeyBackendTagTest \
  --tests org.hyperledger.iroha.sdk.core.model.zk.VerifyingKeyRecordDescriptionTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.VerifyingKeyInstructionBuildersTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachmentTest \
  --tests org.hyperledger.iroha.sdk.address.AccountAddressNativeTest \
  --tests org.hyperledger.iroha.sdk.address.AccountAddressNativeUnavailableTest \
  --tests org.hyperledger.iroha.sdk.address.AccountAddressTest \
  --tests org.hyperledger.iroha.sdk.address.AccountIdLiteralTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.CanonicalMultisigWireParityTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.KaigiWirePayloadV1Test \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.KaigiInstructionValidationTest \
  --tests org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridgeJavaConsumerTest \
  --tests org.hyperledger.iroha.sdk.privacy.ConfidentialNoteJavaConsumerTest \
  --tests org.hyperledger.iroha.sdk.privacy.ZkAssetMerklePathJavaConsumerTest \
  --tests org.hyperledger.iroha.sdk.privacy.PrivacyRetiredWitnessBoundaryJavaConsumerTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.TransferWirePayloadEncoderParityTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.RegisterAccountWirePayloadEncoderParityTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.ClaimIdentifierWirePayloadEncoderParityTest \
  --tests org.hyperledger.iroha.sdk.core.model.instructions.ContractLifecycleWirePayloadEncoderParityTest

"${PYTHON_BIN}" -I -S "${ROOT_DIR}/scripts/check_privacy_jvm_class_contract.py" \
  --classes "${ROOT_DIR}/kotlin/core-jvm/build/classes/kotlin/main"

cd "${ROOT_DIR}/java/iroha_android"
./gradlew --no-daemon -q :core:test \
  --tests org.hyperledger.iroha.android.model.instructions.ProofAttachmentModelTests \
  --tests org.hyperledger.iroha.android.norito.ProofAttachmentNoritoTests

cd "${ROOT_DIR}"
PRIVACY_CORE_JVM_VERSION="$(
  awk -F= '$1 == "irohaSdkVersion" { print $2 }' kotlin/gradle.properties
)"
if [[ -z "${PRIVACY_CORE_JVM_VERSION}" ]]; then
  echo "kotlin/gradle.properties does not declare irohaSdkVersion." >&2
  exit 1
fi
PRIVACY_CORE_JVM_JAR="${ROOT_DIR}/kotlin/core-jvm/build/libs/core-jvm-${PRIVACY_CORE_JVM_VERSION}.jar"
if [[ ! -f "${PRIVACY_CORE_JVM_JAR}" ]]; then
  echo "core-jvm dependency was not built at ${PRIVACY_CORE_JVM_JAR}." >&2
  exit 1
fi
NORITO_PROJECT_DIR="${ROOT_DIR}/java/norito_java"
NORITO_RUNTIME_CLASSPATH_FILE="${NORITO_PROJECT_DIR}/build/runtime-classpath.txt"
"${ROOT_DIR}/java/iroha_android/gradlew" --no-daemon -q \
  -p "${NORITO_PROJECT_DIR}" writeRuntimeClasspath
[[ -s "${NORITO_RUNTIME_CLASSPATH_FILE}" ]] \
  || fail "Norito runtime classpath was not written"
NORITO_RUNTIME_CLASSPATH="$(<"${NORITO_RUNTIME_CLASSPATH_FILE}")"
[[ -n "${NORITO_RUNTIME_CLASSPATH}" ]] \
  || fail "Norito runtime classpath is empty"
"${JAVA_HOME}/bin/javac" \
  -cp "${PRIVACY_CORE_JVM_JAR}:${NORITO_RUNTIME_CLASSPATH}" \
  -sourcepath "java/iroha_android/src/main/java:java/iroha_android/src/test/java:java/norito_java/src/main/java" \
  -d "${JAVA_OUT}" \
  java/iroha_android/src/test/java/org/hyperledger/iroha/android/model/instructions/VerifyingKeyInstructionUtilsTests.java
"${JAVA_HOME}/bin/java" -ea -Djava.library.path="${NATIVE_LIBRARY_DIR}" \
  -cp "${JAVA_OUT}:${PRIVACY_CORE_JVM_JAR}:${NORITO_RUNTIME_CLASSPATH}" \
  org.hyperledger.iroha.android.model.instructions.VerifyingKeyInstructionUtilsTests

[[ -f "${FIXTURE_GENERATOR}" && ! -L "${FIXTURE_GENERATOR}" && -x "${FIXTURE_GENERATOR}" ]] \
  || fail "fixture generator was withdrawn during privacy JVM execution"
[[ "$(sha256_file "${FIXTURE_GENERATOR}")" == "${FIXTURE_GENERATOR_SHA256}" ]] \
  || fail "fixture generator changed during privacy JVM execution"

"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}"
"${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
  --artifact "${NATIVE_LIBRARY}" \
  --manifest "${CSHARP_NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}"
[[ "$(sha256_file "${ROOT_DIR}/Cargo.lock")" == "${PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256}" ]] \
  || fail "tracked root Cargo.lock changed during privacy JVM native execution"

if [[ -n "${PRIVACY_JVM_NATIVE_EXPORT_DIR:-}" ]]; then
  [[ "${PRIVACY_JVM_NATIVE_EXPORT_DIR}" == /* ]] \
    || fail "PRIVACY_JVM_NATIVE_EXPORT_DIR must be absolute"
  [[ ! -e "${PRIVACY_JVM_NATIVE_EXPORT_DIR}" && \
    ! -L "${PRIVACY_JVM_NATIVE_EXPORT_DIR}" ]] \
    || fail "PRIVACY_JVM_NATIVE_EXPORT_DIR must not already exist"
  install -d -m 700 "${PRIVACY_JVM_NATIVE_EXPORT_DIR}"
  EXPORTED_LIBRARY="${PRIVACY_JVM_NATIVE_EXPORT_DIR}/$(basename "${NATIVE_LIBRARY}")"
  install -m 500 "${NATIVE_LIBRARY}" "${EXPORTED_LIBRARY}"
  install -m 400 "${NATIVE_MANIFEST}" \
    "${PRIVACY_JVM_NATIVE_EXPORT_DIR}/native-sdk-abi31-c-jni.json"
  install -m 400 "${CSHARP_NATIVE_MANIFEST}" \
    "${PRIVACY_JVM_NATIVE_EXPORT_DIR}/native-sdk-abi31-csharp.json"
  install -m 400 "${SELECTED_CARGO_LOCK}" \
    "${PRIVACY_JVM_NATIVE_EXPORT_DIR}/Cargo.lock"
  "${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
    --artifact "${EXPORTED_LIBRARY}" \
    --manifest "${PRIVACY_JVM_NATIVE_EXPORT_DIR}/native-sdk-abi31-c-jni.json" \
    --source-root "${ROOT_DIR}"
  "${PYTHON_BIN}" -I -S "${ABI31_CHECKER}" verify \
    --artifact "${EXPORTED_LIBRARY}" \
    --manifest "${PRIVACY_JVM_NATIVE_EXPORT_DIR}/native-sdk-abi31-csharp.json" \
    --source-root "${ROOT_DIR}"
fi
