---
title: Swift Reproducible Build Checklist
summary: Required source, native artifact, consumer, and telemetry evidence for IrohaSwift releases (IOS8).
---

# Swift Reproducible Build Checklist

Use this checklist for Swift SDK release candidates, security fixes, and release
audits. The build and publication contract is
[`docs/norito_bridge_release.md`](../../../docs/norito_bridge_release.md), together
with `.github/workflows/mobile_sdk_artifacts.yml` and the Iroha 3 release runbook
(`specs/release_runbook.md`). Retain evidence in an explicit external release
directory; generated native artifacts and evidence do not belong in Git.

## Prerequisites and directories

- A macOS host with the approved full Xcode toolchain, Swift 5.9 or newer,
  and isolated Python 3.12. Record the actual tool identities.
- Exact Rust 1.93.1 `cargo`, `rustc`, and `rustdoc`, with all five targets:
  `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`,
  `aarch64-apple-darwin`, and `x86_64-apple-darwin`.
- A clean, reviewed dependency-closure source tree and its authenticated root
  `Cargo.lock`. An explicitly selected external release lock must be read-only
  and byte-identical to that root lock.
- Existing owned, writable, canonical, non-symbolic external Cargo, build,
  artifact, and archive-parent directories. Reuse a stable Cargo lane. The build
  directory must be outside the source and archive-parent trees.
- An absent archive output, and an absent dedicated package destination whose
  basename contains `mobile-sdk`. Preserve prior outputs rather than replacing
  or deleting them.
- Reviewed canonical Norito fixtures and two absent absolute external fixture
  publication roots when regeneration is required.

The Swift package, tag, and archive SemVer comes only from `IrohaSwift/VERSION`.
Select session paths before invoking the builder:

```bash
export SWIFT_RELEASE_VERSION="$(cat IrohaSwift/VERSION)"
export SWIFT_RELEASE_DIR=/absolute/release-evidence/swift-release
export SWIFT_RELEASE_LOCKFILE=/absolute/read-only-release-input/Cargo.lock
export IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH="$SWIFT_RELEASE_LOCKFILE"
export CARGO_TARGET_DIR=/absolute/cache/iroha-apple-cargo
export NORITO_BRIDGE_BUILD_DIR=/absolute/cache/iroha-apple-build
export NORITO_BRIDGE_OUT_DIR=/absolute/cache/iroha-apple-artifacts
export NORITO_BRIDGE_ARCHIVE_OUTPUT="${SWIFT_RELEASE_DIR}/NoritoBridge-v${SWIFT_RELEASE_VERSION}.xcframework.zip"
export MOBILE_SDK_PACKAGE_OUT_DIR=/absolute/packages/mobile-sdk-release
export MOBILE_SDK_SWIFT_SCRATCH_DIR=/absolute/cache/iroha-mobile-swift-build
mkdir -p "$SWIFT_RELEASE_DIR" "$CARGO_TARGET_DIR" \
  "$NORITO_BRIDGE_BUILD_DIR" "$NORITO_BRIDGE_OUT_DIR" \
  "$MOBILE_SDK_SWIFT_SCRATCH_DIR" "$(dirname "$MOBILE_SDK_PACKAGE_OUT_DIR")"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
unset RUSTC_BOOTSTRAP MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR
export RUSTC="$(rustup which --toolchain 1.93.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.93.1 rustdoc)"
export MOBILE_SDK_PYTHON_BINARY=/absolute/canonical/path/to/python3.12
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export MOBILE_SDK_APPLE_ARTIFACT_DIR="$NORITO_BRIDGE_OUT_DIR"
export MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1
export MOBILE_SDK_VERSION="v${SWIFT_RELEASE_VERSION}"
```

The serialized Cargo envelope above is required by the authenticated Apple
release corridor. Fetch locked dependencies and install the five Rust targets
before enabling offline builds. Apply the source-read-only requirements from the
release contract before compilation.

## Checklist

| Step | Command or requirement | Evidence |
|------|------------------------|----------|
| 1. Select reviewed source | Record the commit, clean dependency-closure status, root lock digest, and canonical `v<version>` tag identity. | Source/toolchain custody, source snapshot, and release review. |
| 2. Verify fixtures | When regenerating, run `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-fixtures --output-root <absent-absolute-external-root>` at two independent roots. Require identical path sets, entry types, modes, completion manifests, and every file byte before applying the reviewed identity-relative tracked patch. Then run `norito-rpc-verify` and `make swift-fixtures-check`. | Both sealed owner-publication identities and tracked-tree verification in `swift_fixture_state.json`. Include fixture changes in the reviewed source before the native build. |
| 3. Build the native prerequisite | `scripts/build_norito_xcframework.sh --lockfile-path "$SWIFT_RELEASE_LOCKFILE" --archive-output "$NORITO_BRIDGE_ARCHIVE_OUTPUT"` | Exact ABI-29 XCFramework, embedded manifest, source/lock/tool provenance, export checks, and immutable ZIP. All five target libraries become device, universal simulator, and universal macOS slices. |
| 4. Authenticate the framework | `scripts/check_mobile_sdk_artifacts.sh --apple-only --lockfile-path "$SWIFT_RELEASE_LOCKFILE"` | Current-source validation of the external generation and exact three-slice inventory. Retain the embedded manifest and integrity output. `/usr/bin/unzip -t "$NORITO_BRIDGE_ARCHIVE_OUTPUT"` is an additional archive check. |
| 5. Run complete Swift tests | `ci/check_privacy_swift_sdk.sh` | Capture `IrohaSwift-tests.log`, successful exit, full test results, and the reviewed `Package.resolved`. The gate reauthenticates the external artifact and canonical lock, then executes all package tests with real native fixture, crypto and lifecycle support. |
| 6. Execute the Release SDK consumer | Use an ordinary external SwiftPM application depending on the public `IrohaSwift` product; run it with `--configuration release --disable-automatic-resolution` and a stable external scratch directory. | Successful native key generation, public-key derivation, directional-key agreement, all-zero peer rejection and exact ABI-29 admission without unsafe linker flags. An SDK library build alone is insufficient. |
| 7. Package and validate the SwiftPM ZIP | `scripts/package_mobile_sdk_artifacts.sh --apple --lockfile-path "$SWIFT_RELEASE_LOCKFILE" --version "$MOBILE_SDK_VERSION"`; authenticate the result with `scripts/validate_norito_bridge_archive.py` and run the workflow's separate SwiftPM binary-target ZIP consumer. | Exact packaged Apple inventory, authenticated archive and embedded manifest, checksums, package provenance and successful consumer linking. |
| 8. Capture parity dashboards | `make swift-ci`, with the selected `SWIFT_PARITY_FEED`, `SWIFT_CI_FEED`, and pipeline metadata feed. Copy those exact inputs into the external evidence directory. | `mobile_parity.json`, `mobile_ci.json`, pipeline metadata, and dashboard validation output. Sample feeds establish dashboard validation only; retain actual candidate feeds for release claims. |
| 9. Export status | Invoke `ci/swift_status_export.sh` with the retained feed/output paths below. | `swift_status.md`, `swift_status.json`, `swift_status.prom`, and persistent `swift_status_state.json`. |
| 10. Retain consumer smoke evidence | Retain actual sample/XCFramework smoke results, selected destinations, and native artifact identity. | Simulator coverage and physical-device qualification have separate verdicts. An absent or skipped device run does not establish physical qualification. |
| 11. Package source and evidence | `git archive --format=tar.gz --prefix=IrohaSwift/ <reviewed-tag> IrohaSwift > "$SWIFT_RELEASE_DIR/IrohaSwift-v${SWIFT_RELEASE_VERSION}.tar.gz"`; hash the retained files. | Source snapshot, ZIP/checksum, manifests, logs, telemetry, and signed publication evidence. |
| 12. Record release readiness | Link external evidence from the release ticket and identify remaining publication or device qualification requirements. | Update `status.md` or `roadmap.md` only when current health, blockers, or completion criteria change. Routine validation belongs in the review's Testing section. |

Use the retained telemetry for status export:

```bash
SWIFT_PARITY_FEED_PATH="${SWIFT_RELEASE_DIR}/mobile_parity.json" \
SWIFT_CI_FEED_PATH="${SWIFT_RELEASE_DIR}/mobile_ci.json" \
SWIFT_STATUS_EXPORT_OUT="${SWIFT_RELEASE_DIR}/swift_status.md" \
SWIFT_STATUS_SUMMARY_OUT="${SWIFT_RELEASE_DIR}/swift_status.json" \
SWIFT_STATUS_METRICS_PATH="${SWIFT_RELEASE_DIR}/swift_status.prom" \
SWIFT_STATUS_METRICS_STATE="${SWIFT_RELEASE_DIR}/swift_status_state.json" \
ci/swift_status_export.sh
```

Reuse the same feeds and status-state file on subsequent exports so counters
remain monotonic. Hash the retained source archive, native ZIP, manifests, logs,
and feeds into an evidence `SHA256SUMS` inventory.

## Artifact and publication rules

- The builder invokes the sole archive owner while holding the authenticated
  output lock. ZIP publication is atomic and create-only; an existing archive
  destination is refused. Do not invoke `zip` or `ditto` as a substitute.
- Local-integration and local-unit artifacts cannot enter this release
  checklist. Local-unit artifacts support genuine macOS debug tests and reject
  iOS and Release consumption.
- SwiftPM's path-based binary target requires the verified framework to be
  materialized before package resolution. A Git tag alone does not install it.
- SwiftPM is the sole supported Swift packaging path. Public installation
  readiness requires the immutable release asset, reviewed package source,
  installed ordinary Release consumer and signed provenance, as described in
  the release contract.
- Keep generated native artifacts, packages, and evidence external and
  untracked. Only `dist/.gitkeep` belongs in Git under the repository `dist/`.
