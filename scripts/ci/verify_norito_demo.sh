#!/usr/bin/env bash
set -euo pipefail

# CI guard that ensures the Norito SwiftUI demo assets are present and that the
# Swift/Xcode toolchain can build and test the checked-in project. Intended for
# macOS builders with simulators available.

if ! command -v swift >/dev/null 2>&1; then
  echo "error: swift toolchain not found" >&2
  exit 1
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "warning: xcodebuild not found; skipping project build" >&2
  exit 0
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "warning: xcrun not found; skipping project build" >&2
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.."
DEMO_DIR="$ROOT_DIR/examples/ios/NoritoDemoXcode"

if [[ ! -d "$DEMO_DIR" ]]; then
  echo "error: demo directory missing at $DEMO_DIR" >&2
  exit 1
fi

SCHEME="${NORITO_DEMO_SCHEME:-NoritoDemoXcode}"
DESTINATION="${NORITO_DEMO_DESTINATION:-platform=iOS Simulator,name=iPhone 15}"
DERIVED_DATA="${NORITO_DEMO_DERIVED_DATA:-$ROOT_DIR/artifacts/norito_demo_xcodebuild}"
PROJECT="$DEMO_DIR/NoritoDemoXcode.xcodeproj"

mkdir -p "$DERIVED_DATA"

run_xcodebuild() {
  if command -v xcbeautify >/dev/null 2>&1; then
    xcodebuild "$@" | xcbeautify
  elif command -v xcpretty >/dev/null 2>&1; then
    xcodebuild "$@" | xcpretty
  else
    xcodebuild "$@"
  fi
}

DEST_NAME="$(printf '%s\n' "$DESTINATION" | sed -n 's/.*name=\([^,]*\).*/\1/p')"
if [[ -n "$DEST_NAME" ]]; then
  if xcrun simctl list devices available >/dev/null 2>&1; then
    if ! xcrun simctl list devices available | grep -Fq "$DEST_NAME"; then
      SHOW_DEST=$(
        xcodebuild \
          -project "$PROJECT" \
          -scheme "$SCHEME" \
          -showdestinations 2>/dev/null || true
      )

      FALLBACK_LINE=$(printf '%s\n' "$SHOW_DEST" | sed -n 's/^ \\+{[[:space:]]*\(platform:[^}]*name:My Mac\)[[:space:]]*}.*/\1/p' | head -n1)
      if [[ -z "$FALLBACK_LINE" ]]; then
        FALLBACK_LINE=$(printf '%s\n' "$SHOW_DEST" | sed -n 's/^ \\+{[[:space:]]*\(platform:[^}]*\)[[:space:]]*}.*/\1/p' | head -n1)
      fi

      if [[ -n "$FALLBACK_LINE" ]]; then
        CLEAN=$(printf '%s\n' "$FALLBACK_LINE" | sed 's/: */=/g' | tr -d '\n')
        DESTINATION=${CLEAN//, /,}
        DEST_NAME="$(printf '%s\n' "$DESTINATION" | sed -n 's/.*name=\([^,]*\).*/\1/p')"
        echo "info: destination '$DEST_NAME' inferred from available destinations"
      else
        echo "warning: destination simulator '$DEST_NAME' not available and no fallback found; skipping build/test" >&2
        exit 0
      fi
    fi
  else
    echo "warning: unable to query available simulators; skipping build/test" >&2
    exit 0
  fi
fi

echo "Building scheme ${SCHEME} for destination '${DESTINATION}' (DerivedData: ${DERIVED_DATA})"
run_xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Debug \
  -destination "$DESTINATION" \
  -derivedDataPath "$DERIVED_DATA" \
  build

# Physical native qualification uses the explicit device-only test selection.
# This ordinary demo lane may select a simulator or a desktop fallback.
echo "Running demo tests for ${SCHEME}"
run_xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Debug \
  -destination "$DESTINATION" \
  -derivedDataPath "$DERIVED_DATA" \
  -skip-testing:NoritoDemoXcodeTests/NativePrivacyPhysicalDeviceTests \
  -skip-testing:NoritoDemoXcodeTests/KagemushaStoragePhysicalDeviceTests \
  -skip-testing:NoritoDemoXcodeTests/KagemushaEnrollmentPhysicalDeviceTests \
  test

echo "NoritoDemoXcode build + test finished successfully."
