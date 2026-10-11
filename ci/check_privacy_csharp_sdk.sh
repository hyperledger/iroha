#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${PRIVACY_CSHARP_SDK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DOTNET_BIN="${PRIVACY_CSHARP_DOTNET_BIN:-dotnet}"
PYTHON_BIN="${PRIVACY_CSHARP_PYTHON_BIN:-python3}"
ABI29_ARTIFACT_CHECKER="${ROOT_DIR}/scripts/check_native_sdk_artifact.py"

if [[ "${IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE:-}" != "1" ]]; then
  echo "error: IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE=1 is required" >&2
  exit 1
fi
if [[ -z "${PRIVACY_CSHARP_NATIVE_ARTIFACT:-}" || \
  -z "${PRIVACY_CSHARP_NATIVE_MANIFEST:-}" ]]; then
  echo "error: authenticated C# privacy native artifact and manifest are required" >&2
  exit 1
fi
if ! NATIVE_DIRECTORY="$(
  cd "$(dirname "${PRIVACY_CSHARP_NATIVE_ARTIFACT}")" && pwd -P
)"; then
  echo "error: C# privacy native artifact directory is unavailable" >&2
  exit 1
fi
if [[ "${PRIVACY_CSHARP_NATIVE_ARTIFACT}" != \
    "${NATIVE_DIRECTORY}/libconnect_norito_bridge.so" || \
  "${PRIVACY_CSHARP_NATIVE_MANIFEST}" != \
    "${NATIVE_DIRECTORY}/native-sdk-abi29-csharp.json" ]]; then
  echo "error: C# privacy native paths are not canonical Linux ABI-29 paths" >&2
  exit 1
fi
if [[ "${LD_LIBRARY_PATH:-}" != "${NATIVE_DIRECTORY}" ]]; then
  echo "error: LD_LIBRARY_PATH must select only the authenticated C# privacy bridge" >&2
  exit 1
fi

"${PYTHON_BIN}" -I -B "${ABI29_ARTIFACT_CHECKER}" verify \
  --artifact "${PRIVACY_CSHARP_NATIVE_ARTIFACT}" \
  --manifest "${PRIVACY_CSHARP_NATIVE_MANIFEST}" \
  --source-root "${ROOT_DIR}"

export DOTNET_CLI_TELEMETRY_OPTOUT="${DOTNET_CLI_TELEMETRY_OPTOUT:-1}"
export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-${TMPDIR:-/tmp}/iroha-dotnet-home}"

cd "${ROOT_DIR}"
DOTNET_VERSION="$("${DOTNET_BIN}" --version)"
printf '%s\n' "${DOTNET_VERSION}"
if [[ ! "${DOTNET_VERSION}" =~ ^8\.0\.[1-9][0-9]*$ ]]; then
  echo "error: privacy C# SDK tests require a stable canonical .NET SDK 8.0.x with a non-zero patch; got ${DOTNET_VERSION}" >&2
  exit 1
fi

PRIVACY_DOTNET_BIN_PATH="$(command -v "${DOTNET_BIN}")"
PRIVACY_DOTNET_ROOT_CANDIDATE="$(
  cd "$(dirname "${PRIVACY_DOTNET_BIN_PATH}")" && pwd -P
)"
if [[ -z "${DOTNET_ROOT:-}" && -d "${PRIVACY_DOTNET_ROOT_CANDIDATE}/host/fxr" ]]; then
  export DOTNET_ROOT="${PRIVACY_DOTNET_ROOT_CANDIDATE}"
fi

for test_class in \
  "Hyperledger.Iroha.Sdk.Tests.PrivacyNativeTests" \
  "Hyperledger.Iroha.Sdk.Tests.PrivacyExact12CapabilityManifestV1Tests" \
  "Hyperledger.Iroha.Sdk.Tests.PrivacyExact12FixtureCodecV1Tests" \
  "Hyperledger.Iroha.Sdk.Tests.VerifyingKeyBackendTagTests"
do
  "${DOTNET_BIN}" test \
    csharp/tests/Hyperledger.Iroha.Sdk.Tests/Hyperledger.Iroha.Sdk.Tests.csproj \
    -- \
    --filter-class "${test_class}"
done
