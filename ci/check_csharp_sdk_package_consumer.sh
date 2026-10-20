#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CSHARP_SDK_PACKAGE_CONSUMER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DOTNET_BIN="${CSHARP_SDK_PACKAGE_CONSUMER_DOTNET_BIN:-dotnet}"
DOTNET_GLOBAL_JSON="${CSHARP_SDK_PACKAGE_CONSUMER_GLOBAL_JSON:-${ROOT_DIR}/csharp/global.json}"
PACKAGE_DIR="${CSHARP_SDK_PACKAGE_CONSUMER_PACKAGE_DIR:-${ROOT_DIR}/csharp/artifacts/packages}"
PACKAGE_VERSION="${CSHARP_SDK_PACKAGE_CONSUMER_PACKAGE_VERSION:-}"
NATIVE_PACKAGE_ROOT="${CSHARP_SDK_PACKAGE_CONSUMER_NATIVE_PACKAGE_ROOT:-${ROOT_DIR}/csharp/artifacts/native-package}"
NATIVE_PACKAGE_CHECKER="${ROOT_DIR}/scripts/package_csharp_native_artifacts.py"
PYTHON_BIN="${CSHARP_SDK_PACKAGE_CONSUMER_PYTHON_BIN:-python3}"
RUNTIME_IDENTIFIER="${CSHARP_SDK_PACKAGE_CONSUMER_RUNTIME_IDENTIFIER:-}"
WORK_PARENT="${CSHARP_SDK_PACKAGE_CONSUMER_WORK_PARENT:-${TMPDIR:-/tmp}}"
KEEP_WORK_DIR="${CSHARP_SDK_PACKAGE_CONSUMER_KEEP_WORK_DIR:-0}"
MODE="${1:-}"

usage() {
  cat <<'EOF'
Usage: ci/check_csharp_sdk_package_consumer.sh [negative-control]

Builds and runs a temporary net8.0 consumer project against the packed
Hyperledger.Iroha.Sdk NuGet package from csharp/artifacts/packages. Set
CSHARP_SDK_PACKAGE_CONSUMER_RUNTIME_IDENTIFIER to one of linux-x64,
linux-arm64, osx-x64, osx-arm64, or win-x64.

Negative controls:
  --negative-control-missing-local-package
  --negative-control-project-reference
  --negative-control-managed-smoke
EOF
}

if [[ "${MODE}" == "--help" || "${MODE}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${MODE}" == "--list-negative-controls" ]]; then
  cat <<'EOF'
--negative-control-missing-local-package
--negative-control-project-reference
--negative-control-managed-smoke
EOF
  exit 0
fi

case "${MODE}" in
  ""|--negative-control-missing-local-package|--negative-control-project-reference|--negative-control-managed-smoke) ;;
  *)
    usage >&2
    exit 2
    ;;
esac

cd "${ROOT_DIR}"
if [[ -z "${PACKAGE_VERSION}" ]]; then
  PACKAGE_VERSION="$(
    sed -n 's:.*<Version>\([^<][^<]*\)</Version>.*:\1:p' \
      csharp/src/Hyperledger.Iroha.Sdk/Hyperledger.Iroha.Sdk.csproj \
      | head -n 1
  )"
fi
if [[ -z "${PACKAGE_VERSION}" || "${PACKAGE_VERSION}" =~ [[:space:]] ]]; then
  echo "error: failed to determine a canonical Hyperledger.Iroha.Sdk package version" >&2
  exit 1
fi

mkdir -p "${WORK_PARENT}"

WORK_DIR=""
cleanup() {
  if [[ -n "${WORK_DIR}" && "${KEEP_WORK_DIR}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

require_local_package() {
  local package_dir="$1"
  local package_version="$2"
  local package_path="${package_dir}/Hyperledger.Iroha.Sdk.${package_version}.nupkg"
  local symbols_path="${package_dir}/Hyperledger.Iroha.Sdk.${package_version}.symbols.nupkg"
  if [[ ! -d "${package_dir}" ]]; then
    echo "error: local SDK package directory not found: ${package_dir}" >&2
    return 1
  fi
  if [[ ! -s "${package_path}" ]]; then
    echo "error: local SDK package not found or empty: ${package_path}" >&2
    return 1
  fi
  if [[ ! -s "${symbols_path}" ]]; then
    echo "error: local SDK symbols package not found or empty: ${symbols_path}" >&2
    return 1
  fi
}

run_dotnet() {
  local sdk_dir="$1"
  shift
  (
    cd "${sdk_dir}" || return 1
    "${DOTNET_BIN}" "$@"
  )
}

stage_pinned_dotnet_global_json() {
  local app_dir="$1"
  local staged_global_json="${app_dir}/global.json"
  if [[ ! -f "${DOTNET_GLOBAL_JSON}" || -L "${DOTNET_GLOBAL_JSON}" ]]; then
    echo "error: canonical C# SDK global.json is missing or not a regular file: ${DOTNET_GLOBAL_JSON}" >&2
    return 1
  fi
  if [[ ! -d "${app_dir}" || -L "${app_dir}" ]]; then
    echo "error: C# SDK package consumer directory is missing or not a real directory: ${app_dir}" >&2
    return 1
  fi
  if [[ -e "${staged_global_json}" || -L "${staged_global_json}" ]]; then
    echo "error: refusing to replace pre-existing package consumer SDK pin: ${staged_global_json}" >&2
    return 1
  fi
  cp "${DOTNET_GLOBAL_JSON}" "${staged_global_json}" || return 1
  if [[ ! -f "${staged_global_json}" || -L "${staged_global_json}" ]] \
    || ! cmp -s "${DOTNET_GLOBAL_JSON}" "${staged_global_json}"; then
    echo "error: staged package consumer SDK pin does not match ${DOTNET_GLOBAL_JSON}" >&2
    return 1
  fi
}

require_dotnet() {
  local sdk_dir="$1"
  if ! command -v "${DOTNET_BIN}" >/dev/null 2>&1; then
    echo "error: C# SDK package consumer smoke requires .NET SDK 8.0.x; '${DOTNET_BIN}' was not found" >&2
    return 1
  fi
  local dotnet_version
  dotnet_version="$(run_dotnet "${sdk_dir}" --version)"
  printf 'C# SDK package consumer dotnet version: %s\n' "${dotnet_version}"
  if [[ ! "${dotnet_version}" =~ ^8\.0\.[1-9][0-9]*$ ]]; then
    echo "error: C# SDK package consumer smoke requires a stable canonical .NET SDK 8.0.x with a non-zero patch; got ${dotnet_version}" >&2
    return 1
  fi
  printf 'C# SDK package consumer dotnet --info:\n'
  run_dotnet "${sdk_dir}" --info
}

require_runtime_identifier() {
  case "${RUNTIME_IDENTIFIER}" in
    linux-x64|linux-arm64|osx-x64|osx-arm64|win-x64) ;;
    *)
      echo "error: C# SDK package consumer requires one reviewed runtime identifier: linux-x64, linux-arm64, osx-x64, osx-arm64, or win-x64" >&2
      return 1
      ;;
  esac
}

verify_native_package() {
  local package_dir="$1"
  local package_version="$2"
  local package_path="${package_dir}/Hyperledger.Iroha.Sdk.${package_version}.nupkg"
  if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "error: C# SDK native package verification requires '${PYTHON_BIN}'" >&2
    return 1
  fi
  "${PYTHON_BIN}" -I "${NATIVE_PACKAGE_CHECKER}" verify-package \
    --package "${package_path}" \
    --stage-root "${NATIVE_PACKAGE_ROOT}" \
    --source-root "${ROOT_DIR}"
}

write_consumer_program() {
  local program_path="$1"
  local expected_query="$2"
  cat > "${program_path}" <<EOF
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Hyperledger.Iroha.Crypto;
using Hyperledger.Iroha.Http;
using Hyperledger.Iroha.SoraFs;
using Hyperledger.Iroha.Torii;

var seed = new byte[Ed25519Signer.PrivateKeySeedLength];
for (var index = 0; index < seed.Length; index++)
{
    seed[index] = (byte)index;
}

var message = Encoding.UTF8.GetBytes("iroha-csharp-package-smoke");
var publicKey = Ed25519Signer.GetPublicKey(seed);
var signature = Ed25519Signer.Sign(message, seed);
if (!Ed25519Signer.Verify(message, signature, publicKey))
{
    throw new InvalidOperationException("Ed25519 package smoke failed");
}

var canonicalQuery = CanonicalRequest.BuildCanonicalQueryString("?z=last&a=hello%20world");
if (canonicalQuery != "${expected_query}")
{
    throw new InvalidOperationException($"Unexpected canonical query: {canonicalQuery}");
}

var canonicalMessage = CanonicalRequest.BuildMessage("post", "/v1/transactions", canonicalQuery, message);
var expectedBodyHash = Convert.ToHexString(SHA256.HashData(message)).ToLowerInvariant();
var expectedMessage = $"POST\\n/v1/transactions\\n{canonicalQuery}\\n{expectedBodyHash}";
if (Encoding.UTF8.GetString(canonicalMessage) != expectedMessage)
{
    throw new InvalidOperationException("Canonical request package smoke failed");
}

if (SoraFsReferenceValidators.RequiredBridgeAbiVersion != 31u
    || !SoraFsReferenceValidators.IsAppealFinanceAvailable())
{
    throw new InvalidOperationException("Packed ABI-31 SoraFS native bridge is unavailable");
}

// Probe the actual library resolved from the installed, manifest-verified package.
// Codec export availability is DATA surface evidence, not authenticated money admission.
var feeBridge = System.Runtime.InteropServices.NativeLibrary.Load(
    "connect_norito_bridge", typeof(SoraFsReferenceValidators).Assembly, null);
try
{
    foreach (var symbol in new[] {
        "connect_norito_retail_fee_intent_hash_v1",
        "connect_norito_retail_fee_assessment_marker_v1",
        "connect_norito_retail_fee_assessment_decode_v1" })
    {
        _ = System.Runtime.InteropServices.NativeLibrary.GetExport(feeBridge, symbol);
    }
    foreach (var retired in new[] {
        "connect_norito_validation_fee_hijiri_quote_request_v1",
        "connect_norito_validation_fee_hijiri_quote_response_verify_v1" })
    {
        if (System.Runtime.InteropServices.NativeLibrary.TryGetExport(feeBridge, retired, out _))
        {
            throw new InvalidOperationException("Packed Native artifact retains a retired quote protocol");
        }
    }
}
finally
{
    System.Runtime.InteropServices.NativeLibrary.Free(feeBridge);
}

Console.WriteLine("Hyperledger.Iroha.Sdk package consumer smoke passed");
EOF
}

validate_consumer_project() {
  local project_file="$1"
  if grep -q '<ProjectReference' "${project_file}"; then
    echo "error: package consumer smoke must not use ProjectReference" >&2
    return 1
  fi
  if ! grep -q "<PackageReference Include=\"Hyperledger.Iroha.Sdk\" Version=\"${PACKAGE_VERSION}\"" "${project_file}"; then
    echo "error: package consumer smoke must reference Hyperledger.Iroha.Sdk ${PACKAGE_VERSION} as a package" >&2
    return 1
  fi
}

package_install_log_matches_local_source() {
  local log_file="$1"
  local package_dir="$2"
  local expected_sources=("${package_dir}")
  local source
  if command -v cygpath >/dev/null 2>&1; then
    source="$(cygpath -w "${package_dir}" 2>/dev/null || true)"
    [[ -z "${source}" ]] || expected_sources+=("${source}")
    source="$(cygpath -m "${package_dir}" 2>/dev/null || true)"
    [[ -z "${source}" ]] || expected_sources+=("${source}")
  fi
  for source in "${expected_sources[@]}"; do
    if grep -Fq "Installed Hyperledger.Iroha.Sdk ${PACKAGE_VERSION} from ${source}" "${log_file}"; then
      return 0
    fi
  done
  return 1
}

run_consumer_smoke() {
  local package_dir="$1"
  local expected_query="$2"
  local inject_project_reference="$3"
  package_dir="$(cd "${package_dir}" && pwd)" || return 1
  require_local_package "${package_dir}" "${PACKAGE_VERSION}" || return 1
  require_runtime_identifier || return 1
  verify_native_package "${package_dir}" "${PACKAGE_VERSION}" || return 1

  WORK_DIR="$(mktemp -d "${WORK_PARENT}/iroha-csharp-sdk-package-consumer.XXXXXX")" || return 1
  local app_dir="${WORK_DIR}/consumer"
  local project_file="${app_dir}/consumer.csproj"
  mkdir -p "${app_dir}" || return 1
  stage_pinned_dotnet_global_json "${app_dir}" || return 1
  require_dotnet "${app_dir}" || return 1
  export DOTNET_CLI_TELEMETRY_OPTOUT="${DOTNET_CLI_TELEMETRY_OPTOUT:-1}"
  export DOTNET_NOLOGO="${DOTNET_NOLOGO:-1}"
  export DOTNET_SKIP_FIRST_TIME_EXPERIENCE="${DOTNET_SKIP_FIRST_TIME_EXPERIENCE:-1}"
  export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-${WORK_DIR}/dotnet-home}"
  export NUGET_PACKAGES="${NUGET_PACKAGES:-${WORK_DIR}/nuget-packages}"

  run_dotnet "${app_dir}" new console --framework net8.0 --output . --no-restore || return 1
  cat > "${app_dir}/Directory.Build.props" <<EOF
<Project>
  <PropertyGroup>
    <RuntimeIdentifier>${RUNTIME_IDENTIFIER}</RuntimeIdentifier>
  </PropertyGroup>
</Project>
EOF
  cat > "${app_dir}/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="iroha-local" value="${package_dir}" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF
  run_dotnet "${app_dir}" add package Hyperledger.Iroha.Sdk --version "${PACKAGE_VERSION}" \
    | tee "${WORK_DIR}/dotnet-add-package.log" || return 1
  if ! package_install_log_matches_local_source "${WORK_DIR}/dotnet-add-package.log" "${package_dir}"; then
    echo "error: package consumer smoke did not install Hyperledger.Iroha.Sdk ${PACKAGE_VERSION} from ${package_dir}" >&2
    return 1
  fi
  if [[ "${inject_project_reference}" == "1" ]]; then
    local project_file_tmp="${project_file}.tmp"
    awk '
      /<\/Project>/ {
        print "  <ItemGroup>"
        print "    <ProjectReference Include=\"../../csharp/src/Hyperledger.Iroha.Sdk/Hyperledger.Iroha.Sdk.csproj\" />"
        print "  </ItemGroup>"
      }
      { print }
    ' "${project_file}" > "${project_file_tmp}" || return 1
    mv "${project_file_tmp}" "${project_file}" || return 1
  fi
  validate_consumer_project "${project_file}" || return 1
  write_consumer_program "${app_dir}/Program.cs" "${expected_query}"
  run_dotnet "${app_dir}" build "${project_file}" --configuration Release --no-restore -warnaserror || return 1
  run_dotnet "${app_dir}" run --project "${project_file}" --configuration Release --no-build || return 1
  printf 'C# SDK package consumer package: %s/Hyperledger.Iroha.Sdk.%s.nupkg\n' \
    "${package_dir}" "${PACKAGE_VERSION}"
}

expect_negative_control_failure() {
  local name="$1"
  local expected_message="$2"
  shift 2
  set +e
  local output
  output="$("$@" 2>&1)"
  local status=$?
  set -e
  printf '%s\n' "${output}"
  if [[ "${status}" -eq 0 ]]; then
    echo "error: ${name} negative control was accepted" >&2
    exit 1
  fi
  if [[ "${output}" != *"${expected_message}"* ]]; then
    echo "error: ${name} negative control failed for the wrong reason; expected ${expected_message}" >&2
    exit 1
  fi
  printf '%s rejected as expected\n' "${name}"
}

case "${MODE}" in
  --negative-control-missing-local-package)
    empty_package_dir="$(mktemp -d "${WORK_PARENT}/iroha-csharp-sdk-empty-packages.XXXXXX")"
    WORK_DIR="${empty_package_dir}"
    expect_negative_control_failure \
      "missing local package" \
      "local SDK package not found or empty" \
      run_consumer_smoke "${empty_package_dir}" "a=hello+world&z=last" 0
    ;;
  --negative-control-project-reference)
    expect_negative_control_failure \
      "project reference" \
      "package consumer smoke must not use ProjectReference" \
      run_consumer_smoke "${PACKAGE_DIR}" "a=hello+world&z=last" 1
    ;;
  --negative-control-managed-smoke)
    expect_negative_control_failure \
      "managed smoke" \
      "Unexpected canonical query" \
      run_consumer_smoke "${PACKAGE_DIR}" "a=hello%20world&z=last" 0
    ;;
  *)
    run_consumer_smoke "${PACKAGE_DIR}" "a=hello+world&z=last" 0
    ;;
esac
