#!/usr/bin/env bash
# Test the canonical Kotlin SDK and build its runtime SBOMs. Signing is an explicit operator
# action; sourceable collection performs no build, signature or publication.
set -euo pipefail

collect_sbom_reports() {
  local repo_root="$1" destination="$2" version="${3:-}"
  local owner="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/mobile_sdk_android_artifacts.py"
  local arguments=(--root "$repo_root" --collect-sboms "$destination")
  [[ -z "$version" ]] || arguments+=(--version "$version")
  "${MOBILE_SDK_PYTHON_BINARY:-python3}" -I -B "$owner" "${arguments[@]}"
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

usage() {
  cat <<'USAGE'
Usage: scripts/android_sbom_provenance.sh <sdk-version>

Runs the required JVM, Android managed and host-JNI unit suites, then builds
and collects CycloneDX runtime SBOMs for the canonical Kotlin core-jvm,
client-android and kagemusha-wallet-android publications, then signs each using
cosign keyless signing. Sample and retired Java SDK reports are never admitted.

Prerequisites:
  - JDK 21, Android SDK, pinned native build inputs and cosign on PATH
  - MOBILE_SDK_ANDROID_ARTIFACT_DIR: existing canonical external build root
  - MOBILE_SDK_SBOM_OUTPUT_DIR: new absolute external output directory
  - Optional MOBILE_SDK_PYTHON_BINARY and COSIGN select operator-owned tools
The output parent must exist. Existing outputs are never overwritten.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then usage; exit 0; fi
[[ $# == 1 && "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { usage >&2; exit 64; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SDK_VERSION="$1"
DEST="${MOBILE_SDK_SBOM_OUTPUT_DIR:?MOBILE_SDK_SBOM_OUTPUT_DIR is required}"
: "${MOBILE_SDK_ANDROID_ARTIFACT_DIR:?MOBILE_SDK_ANDROID_ARTIFACT_DIR is required}"
SDK_GRADLE_WRAPPER="$REPO_ROOT/kotlin/gradlew"
COSIGN_BIN="${COSIGN:-cosign}"
[[ -x "$SDK_GRADLE_WRAPPER" ]] || { echo 'canonical Kotlin Gradle wrapper is missing' >&2; exit 1; }
command -v "$COSIGN_BIN" >/dev/null 2>&1 || { echo 'cosign is required' >&2; exit 1; }
[[ ! -e "$DEST" && ! -L "$DEST" ]] || { echo 'SBOM output already exists' >&2; exit 1; }
"${MOBILE_SDK_PYTHON_BINARY:-python3}" -I -B \
  "$REPO_ROOT/scripts/mobile_sdk_android_artifacts.py" --root "$REPO_ROOT" \
  --print-build-root >/dev/null
SDK_PROJECT_CACHE="$MOBILE_SDK_ANDROID_ARTIFACT_DIR/sbom-project-cache"

echo '==> Testing canonical SDK and generating runtime SBOMs'
"$SDK_GRADLE_WRAPPER" -p "$REPO_ROOT/kotlin" --no-daemon --no-configuration-cache \
  --project-cache-dir "$SDK_PROJECT_CACHE" \
  -PirohaSdkVersion="$SDK_VERSION" \
  :core-jvm:test :client-android:testDebugUnitTest :client-android:testDebugHostNative \
  :kagemusha-wallet-android:testDebugUnitTest :kagemusha-wallet-android:testDebugHostNative \
  :core-jvm:cyclonedxDirectBom :client-android:cyclonedxDirectBom \
  :kagemusha-wallet-android:cyclonedxDirectBom

collect_sbom_reports "$REPO_ROOT" "$DEST" "$SDK_VERSION"
CHECKSUM_FILE="$DEST/checksums.txt"
: > "$CHECKSUM_FILE"
for bom in "$DEST"/*.json; do
  "$COSIGN_BIN" sign-blob --yes --bundle "$bom.sigstore" "$bom"
  shasum -a 256 "$bom" >> "$CHECKSUM_FILE"
done
echo "Canonical SDK SBOMs and signatures stored under $DEST"
