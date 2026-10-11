# NoritoBridge Release Packaging

This guide covers producing and publishing the authenticated `NoritoBridge`
XCFramework release asset. Swift Package Manager consumes that exact artifact
from an ignored local `dist/` directory or an explicitly configured external
artifact directory. SwiftPM is the sole supported Swift packaging path.
`IrohaSwift/VERSION` owns the Swift package, tag, and archive SemVer. The Rust
sources are bound by the reviewed commit, source fingerprint, and root lockfile. For
end-to-end instructions on consuming a published artifact inside an app, see the
[public Swift SDK tutorial](https://docs.iroha.tech/guide/tutorials/swift.html).

## Consumer installation

Before SwiftPM resolves `IrohaSwift`, install the matching native ZIP. Obtain its
SHA-256 and full producing commit from independently authenticated release
evidence; a digest computed from an untrusted download or its adjacent unsigned
manifest is not a trust anchor. The signed first public release remains
unpromoted. Local qualification uses the reviewed producing candidate and its
authenticated archive evidence.

The consumer verifier requires Python 3.10+, Apple command-line tools, a clean
checkout of that commit (or its exact mechanical pin child), and an external
read-only copy of that checkout's canonical `Cargo.lock`. Rust and identical
producer tool binaries are not required. `DEVELOPER_DIR` selects local Apple
tools; otherwise the verifier uses `xcode-select -p`.

```bash
python3 -I -S -B scripts/validate_norito_bridge_archive.py \
  --consumer \
  --root /absolute/path/to/clean-release-checkout \
  --archive /absolute/path/to/NoritoBridge-v0.1.0.xcframework.zip \
  --expected-sha256 "$TRUSTED_NORITO_ARCHIVE_SHA256" \
  --expected-source-commit "$TRUSTED_NORITO_SOURCE_COMMIT" \
  --lockfile-path /absolute/read-only-release-input/Cargo.lock \
  --install-dir /absolute/path/to/clean-release-checkout/dist
```

Run a trusted copy of the installer. It admits the release source before loading
its validation rules, checks the original archive digest before extraction, and
verifies headers, Swift pins, ABI, native architecture/export inventories, slice
digests and the lock. Installation creates the framework and its canonical
manifest symlink without replacing either existing destination. The existing
`dist/` directory may contain its tracked `.gitkeep`. A consumer verification
does not re-create producer build provenance; omitting `--consumer` retains the
strict producer tool and source checks.

## Producer packaging

The `.github/workflows/mobile_sdk_artifacts.yml` workflow builds, validates,
packages, and publishes tagged Apple artifacts on macOS. The steps below mirror
that workflow for local release verification.

## Prerequisites

- A macOS host with the approved full Xcode installation and its sealed tools.
- Exact Rust 1.93.1 `cargo`, `rustc`, and `rustdoc`.
- Python 3.12.
- Swift toolchain 5.9 or newer.
- Access to the Hyperledger Iroha release signing keys for tagging Swift artifacts.

## Versioning model

1. Select the canonical Swift package/archive SemVer in `IrohaSwift/VERSION`.
2. Tag the workspace with that release identifier (`v<version>`). This one tag
   binds the IrohaSwift package source and the NoritoBridge binary release asset.
3. Keep `IrohaSwift/VERSION`, the Swift loader's expected version, and the
   reviewed release version map aligned.
4. Do not require numeric equality with `crates/norito/Cargo.toml`; authenticate
   the exact Rust source commit, source fingerprint, and root lockfile instead.

## Build steps

1. From a clean pinned commit, create dedicated canonical build and artifact
   directories outside the repository and invoke the helper:

   ```bash
   export CARGO_TARGET_DIR=/absolute/non-symlink/path/to/iroha-apple-cargo
   mkdir -p "$CARGO_TARGET_DIR"
   export CARGO_BUILD_JOBS=1
   export CARGO_INCREMENTAL=0
   export CARGO_NET_OFFLINE=true
   unset RUSTC_BOOTSTRAP
   export RUSTC="$(rustup which --toolchain 1.93.1 rustc)"
   export RUSTDOC="$(rustup which --toolchain 1.93.1 rustdoc)"
   export MOBILE_SDK_PYTHON_BINARY=/absolute/path/to/python3.12
   export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
   export NORITO_BRIDGE_OUT_DIR=/absolute/cache/iroha-apple-artifacts
   export NORITO_BRIDGE_BUILD_DIR=/absolute/cache/iroha-apple-build
   export NORITO_BRIDGE_ARCHIVE_OUTPUT=/absolute/cache/NoritoBridge.xcframework.zip
   mkdir -p \
     "$NORITO_BRIDGE_OUT_DIR" \
     "$NORITO_BRIDGE_BUILD_DIR" \
     "$(dirname "$NORITO_BRIDGE_ARCHIVE_OUTPUT")"
   ./scripts/build_norito_xcframework.sh \
     --lockfile-path /absolute/read-only-release-input/Cargo.lock \
     --archive-output "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
   ```

   The selected external lock must be a read-only, byte-identical copy of the
   canonical reviewed root `Cargo.lock`; the builder authenticates both.
   The release command requires a clean dependency-closure source tree, compiles the Rust
   bridge for the iOS device, arm64 and x86_64 iOS simulator, and arm64 and x86_64 macOS targets,
   and writes `$NORITO_BRIDGE_OUT_DIR/NoritoBridge.xcframework`. The canonical manifest is embedded at
   `$NORITO_BRIDGE_OUT_DIR/NoritoBridge.xcframework/NoritoBridge.artifacts.json`; the companion
   `$NORITO_BRIDGE_OUT_DIR/NoritoBridge.artifacts.json` path is a stable relative symlink to that file, so
   one atomic XCFramework exchange publishes the binaries and manifest together. The
   manifest binds exact native bridge ABI 25, the mandatory privacy build recipe,
   source commit and fingerprint, embedded source commit, header digest,
   required-symbol inventory, and per-slice SHA-256 hashes. Ordinary builds embed
   their own commit. An exact mechanical fallback-pin child embeds its parent commit,
   preventing the three pin literals from recursively changing the static-library
   hashes they authenticate; the checker rejects every broader child as ordinary
   source. The hermetic Apple build binds that identity consistently through
   `CONNECT_NORITO_SOURCE_REVISION`, `IROHA_GIT_COMMIT_HASH`, and
   `VERGEN_GIT_SHA`. Stock pinned Cargo builds the original root manifest with
   its authenticated root lock; a separately selected release lock remains
   byte-identical evidence. The source-defined `apple-release` profile retains
   ThinLTO and target optimization, and the inherited release build override
   preserves host proc-macro symbols. Compiler/profile configuration overrides
   are refused instead of changing the compiler invocation.
   Before publication the helper invokes
   `scripts/check_mobile_sdk_artifacts.sh --apple-only` against the staged generation; a
   checker or `xcodebuild` failure leaves the live generation unchanged. The
   first-release builder has no skip-build, preserved-target, alternate-lock, or
   manual XCFramework fallback mode. Override only the recorded bridge version with
   `--bridge-version <version>` when needed. `--allow-dirty-source` is for local
   integration artifacts and must not be used for a release artifact.
   `scripts/update_norito_bridge_swift_pins.py` has no in-place update mode: use
   `--check` for a read-only repository verification or `--output` with the exact
   `--expected-preimage-sha256` to exclusively create a reviewed projection in an
   external directory. The owner never rewrites `NativeBridge.swift`; incorporate an
   approved projection through the normal guarded source-edit workflow.
   For a fingerprint-bound local integration artifact, pass `--allow-dirty-source`
   explicitly to either pin-owner mode or to `archive_norito_xcframework.py`.
   The builder forwards its own explicit allowance to both final projection and
   archive creation. This changes only dirty-tree admission;
   exact repository/tool provenance, artifact inventory, manifest link, locks,
   and loader preimage verification remain mandatory. Release commands keep the
   clean-source default.
   The Cargo target, artifact, build, and archive-parent directories must already
   exist as owned, writable, non-symbolic canonical directories. The archive output
   itself must be absent, and the external build directory used for retained archive
   snapshots must be outside both the repository and archive-parent tree. An existing
   generation is accepted only
   with its embedded manifest and canonical public manifest symlink already in
   the first-release layout; the builder does not migrate an older layout.

   `MOBILE_SDK_CARGO_HOME` optionally selects an existing owned, writable,
   non-symbolic canonical Cargo cache outside the source tree. The default remains
   the user's `.cargo` directory. Use a separate populated cache when personal
   Cargo configuration contains compiler wrappers or environment overrides that
   the authenticated build rejects; keep the reviewed configuration checks intact.
   For `--local-integration`, the exact mode-0700
   `target/norito-bridge-local/build/cargo-home` directory is also admitted.
   The selected cache is reused through rustup, source seals, every hermetic Cargo
   command and artifact verification; builds remain locked and offline.

   Cargo also reads configuration from its working directory and every ancestor.
   If the checkout is below a home directory containing rejected Cargo overrides,
   select `MOBILE_SDK_CARGO_INVOCATION_DIR` as an existing owned, writable,
   non-symbolic canonical mode-0700 directory outside that ancestry and disjoint
   from source, for example `/private/tmp/iroha-native-cargo-invocation`.
   Metadata and real Apple builds then run there with the explicit authenticated
   root `--manifest-path`. The checker, pin owner and archive owner use the same
   directory; its identity and every effective Cargo configuration are checked
   before and after Cargo. Keep both explicit inputs selected during verification
   and packaging. Neither input changes the pinned compiler, profile or graph.

   PQClean archive normalization binds the registry package identity and checksum
   from the selected Cargo lock to the exact successful build's JSON messages and
   native link outputs. It removes only byte-identical duplicate members from
   those authenticated archives; complete-archive linking remains mandatory.

2. Confirm the builder-owned archive publication:

   ```bash
   test -f "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
   /usr/bin/unzip -t "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
   zipinfo -1 "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
   ```

   Before releasing its authenticated artifact-publication lock, the builder invokes
   the sole archive owner on the generation it just published. The owner retains a
   unique source snapshot and re-authenticates the exact ABI-25 inventory,
   recomputes source and tool provenance, verifies each Mach-O architecture and the
   required/forbidden export policy with the sealed Xcode toolchain, sorts entries,
   stores them without host-zlib variance, normalizes modes and ZIP timestamps from
   `SOURCE_DATE_EPOCH`, and fsyncs a temporary archive while retaining its open file
   descriptor and authenticated inode identity. Publication uses one atomic
   no-replace rename. The owner never creates or removes an archive-destination lock,
   and any pre-existing or concurrently created destination is rejected and left
   untouched. Failed runs retain their uniquely named snapshot and archive residue
   for inspection instead of deleting a path that another process may have swapped.
   A concurrent builder or archiver is rejected; do not invoke `ditto` or `zip`
   directly. CI also feeds the published ZIP to a maintained local SwiftPM binary
   target and executes both that consumer and an ordinary public `IrohaSwift`
   dependency in Release.

3. Authenticate the archive against its embedded manifest and retain the signed
   release evidence outside the source tree. The checked-in Swift package uses
   the authenticated external artifact directory and does not embed generated
   release archives or their checksums.

4. Select a canonical existing external parent and an absent dedicated package
   destination whose basename contains `mobile-sdk`, then package and validate the
   final archive before tagging. `--version` is a diagnostic artifact label; the
   Swift package/archive SemVer still comes only from `IrohaSwift/VERSION`.

   ```bash
   export MOBILE_SDK_APPLE_ARTIFACT_DIR="$NORITO_BRIDGE_OUT_DIR"
   export MOBILE_SDK_PACKAGE_PARENT=/absolute/cache/iroha-mobile-packages
   mkdir -p "$MOBILE_SDK_PACKAGE_PARENT"
   export MOBILE_SDK_PACKAGE_OUT_DIR="$MOBILE_SDK_PACKAGE_PARENT/mobile-sdk-release"
   test ! -e "$MOBILE_SDK_PACKAGE_OUT_DIR"
   export MOBILE_SDK_VERSION="local-$(git rev-parse --short=12 HEAD)"
   scripts/package_mobile_sdk_artifacts.sh \
     --apple \
     --lockfile-path /absolute/read-only-release-input/Cargo.lock \
     --version "$MOBILE_SDK_VERSION"
   ```

   The package command creates
   `NoritoBridge-v<version>.xcframework.zip`, its versioned artifact manifest,
   and the closed package/checksum inventory. The embedded bridge version must
   equal `IrohaSwift/VERSION`. `scripts/validate_norito_bridge_archive.py`
   authenticates the bounded deterministic ZIP before materialization. Compile
   a SwiftPM binary-target consumer of that exact ZIP and execute an ordinary
   public `IrohaSwift` dependency in Release without unsafe linker flags.
   Reuse stable external Swift scratch directories. Do not hand-edit a release
   URL or checksum, or place generated package outputs in Git.

   The maintained gate is `scripts/check_swift_release_consumers.py`; pass the
   verifier's `archive_sha256` through `--archive-sha256`, the authenticated ZIP
   through `--archive`, and explicit `--work-dir`, `--archive-scratch` and
   `--sdk-scratch` directories outside source. It stages the checked-in
   `scripts/fixtures/swift_release_consumers` executables and uses `swift run
   --configuration release` for both. The public SDK consumer adds no direct
   native-target references or unsafe linker flags. Both execute ABI-25 native
   cryptography and Connect key agreement; the SDK also checks canonical JSON,
   BLAKE3 and AEAD. Either build or runtime failure stops the Apple release gate.

5. **Maintain the source header when exports or constants change.** The build
   copies `crates/connect_norito_bridge/include/connect_norito_bridge.h` into each
   XCFramework slice; it does not generate the header from Rust. Run
   `bash ci/check_connect_norito_bridge_header.sh` to check the ABI version, the
   exact C/Rust export inventories, the shared error codes and size bounds, and
   the rejection of retired namespaces. The bridge exports no KAGEMUSHA symbol.
   The gate also compiles the header as C11 and C++17.
   Ensure `NoritoBridge.xcframework/**/Headers/connect_norito_bridge.h`
   matches the source header before zipping.

6. Run the Swift validation suite before tagging:

   ```bash
   export MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1
   export MOBILE_SDK_APPLE_ARTIFACT_DIR="$NORITO_BRIDGE_OUT_DIR"
   export MOBILE_SDK_SWIFT_SCRATCH_DIR=/absolute/cache/iroha-mobile-swift-build
   export IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH=/absolute/read-only-release-input/Cargo.lock
   mkdir -p "$MOBILE_SDK_SWIFT_SCRATCH_DIR"
   ci/check_privacy_swift_sdk.sh
   make swift-ci
   ```

   The native gate reauthenticates the framework, exact tools and canonical
   external lock, then runs the complete Swift package suite, including native
   fixture, crypto and lifecycle tests. The dashboard command validates fixture
   parity, renders the parity/CI dashboards, and
   exercises the same telemetry checks enforced in Buildkite (including the
   `ci/xcframework-smoke:<lane>:device_tag` metadata requirement).

7. Record the signed publication evidence and tag the reviewed source commit.
   Generated `dist/*` outputs remain untracked; only `dist/.gitkeep` belongs in Git.

## Publishing

### Swift Package Manager

The checked-in package manifest uses a path-based binary target. Before package
resolution, materialize the verified release asset either under the ignored
repository `dist/` path or in a canonical external directory selected with
`MOBILE_SDK_APPLE_ARTIFACT_DIR`. Reviewed builds additionally set
`MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1`. A Git tag by itself does not
materialize the XCFramework and must not be reported as an installed native
package.

The package's native retention target uses ordinary export references, so an
application can depend on `IrohaSwift` without unsafe linker flags. Qualify both
the authenticated ZIP consumer and a separate ordinary SDK dependency in
Release. The SDK consumer must execute native key generation, public-key
derivation and directional-key agreement, reject an all-zero peer key, and
admit exact ABI 25. A library-only build does not establish this execution.

Publish the immutable `NoritoBridge-v<version>.xcframework.zip` with its
authenticated manifest/checksum inventory and reviewed package source. Retain
an installed SwiftPM Release consumer and signed provenance before claiming
public installation readiness. CocoaPods support is retired. Generated `dist/*`
stays untracked; only `dist/.gitkeep` belongs in Git. Host and simulator checks
do not establish physical-device qualification.

## CI considerations

- The Mobile SDK Artifacts workflow (`.github/workflows/mobile_sdk_artifacts.yml`)
  alone may invoke the restricted CI producer modes.
  Five isolated `--ci-apple-slice <target>` jobs each perform one fresh,
  offline, single-job Cargo build and emit a digest-bound source/tool
  attestation. The `swift` job supplies all five independent archive digests to
  `--ci-handoff-only --ci-assemble-apple-slices <root>`; the builder rejects a
  missing, duplicate, mixed-source, mixed-toolchain, or altered slice before
  running the exact XCFramework validators. It then atomically stages
  `NoritoBridge.ci-handoff` without publishing the canonical
  `NoritoBridge.xcframework` paths. Its digest-authenticated consumer restores
  those canonical paths in a fresh job and runs the full Apple artifact checker
  before any Swift lifecycle test. Per-runner Python, Git, and rustup evidence is
  retained but may differ because those orchestration tools remain outside the
  hermetic Cargo invocation. Release builds must not use these modes.
- `.github/workflows/mobile_sdk_artifacts.yml` runs the packaging and artifact
  checkers on `macos-14`, uploads the generated archives, and publishes release
  assets for `v*` tags.
- `ci/check_swift_samples.sh` gates the Swift demos against the freshly
  generated framework.
- Release logs and artifact manifests retain the source fingerprint, ABI,
  feature state, required-symbol inventory, and per-slice hashes.


## Checkout-local Swift integration

`--local-integration` selects one non-release lane below the current checkout's
ignored `target/norito-bridge-local/` directory. Create owned canonical mode-0700
`cargo`, `build`, `artifacts`, and `projections` directories there, and use the first
three as the explicit Cargo, build, and output roots. Reuse this fixed Cargo lane.
The builder still performs all five real Apple builds, source/lock/tool seals,
consumer links, ABI-25 checks and atomic artifact exchange. It does not clean Cargo.
Select the current root graph explicitly with `--lockfile-path "$PWD/Cargo.lock"`
for the builder, pin owner and artifact checker. This local-only route retains
`--locked --offline` and the source/lock identity checks; it never changes the
root lock or substitutes the release graph. External privacy-enabled builds
require a read-only graph snapshot matching the signed root lock and the sole
digest in `ci/privacy_sdk_cargo_lockfile.sh`; an older snapshot cannot authorize
the current source. Apps requiring an external artifact cannot consume this
checkout-local lane. If source inputs are
dirty, also pass the existing `--allow-dirty-source`; scope and dirty admission
are independent. Clean local builds retain their local-only scope.

The embedded `artifact_scope: "local-integration"` field is mandatory in this mode.
Pass `--local-integration` to the pin owner and Apple-only artifact checker too.
After reviewing any pin projection, select the canonical `artifacts` directory
with the existing `MOBILE_SDK_APPLE_ARTIFACT_DIR` for ordinary Swift unit tests.
`MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1` continues to reject this directory.
No runtime proof capability toggle or alternate native library is introduced.
Archive output, CI handoff and the frozen release corridor are forbidden in local
mode. Default validators, archive owners and publication continue to reject the
local-only manifest field even if its files are copied outside the checkout.
This is local integration evidence; release builds retain external writable output
roots and an immutable reviewed source tree.

The builder checks a prospective loader and leaves the maintained fallback pins
unchanged. Generate a canonical `--output` pin projection into `projections` using
the exact current loader preimage digest, then apply only its three digest literal
changes through the guarded source workflow. For an already-dirty tree at the same
HEAD, this preserves both the normalized source fingerprint and dirty-state truth;
re-run the canonical pin check and artifact checker before Swift tests. For a clean
tree, pin integration changes dirty-state truth: use the existing exact mechanical
pin-child commit procedure, or rebuild and requalify an explicitly dirty local
artifact. All other input changes require a native rebuild. Ordinary `swift test`
then links the real binary target, and `NativeBridge` validates the symbols from
the executable/`RTLD_DEFAULT`; no replacement loader or projected Swift package is
used. Physical-device qualification remains separate from these host unit tests.

## Local macOS unit prerequisite

The explicit `MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR` input selects only debug macOS
unit-test artifacts with scope `local-unit`. Its producer consumes a separately
retained static archive named by a genuine, source-guarded successful host Cargo
invocation. It normalizes only the current locked, Cargo-proven PQClean duplicate
members in a derived copy and records an actual complete-archive consumer link/run.
The archive/header/source/tool/receipt hashes remain bound through Swift execution.
No universal architecture or release environment is claimed. Every Swift test
stays enabled, and native ABI/symbol admission is unchanged. Selecting the release
corridor, targeting iOS, or compiling Release rejects this input. Canonical release,
pin, archive, and CI handoff owners retain the five-triple/three-slice contract.

## Canonical Android output and runtime inventory

The Kotlin build, Android artifact checker, and package owner use the same
`MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk/<module>` outputs.
An explicit external root must already exist, be absolute/canonical, and lie
outside the reviewed source tree. Missing external outputs never fall back to
old `kotlin/*/build` artifacts. Ordinary local checks retain source-tree outputs
only when the external variable is absent. The checker rejects ambiguous core
runtime JARs and symlinked or hard-linked selected artifacts. All three runtime
outputs are mandatory: the core JAR, client AAR, and wallet AAR. Generated release
POMs must select one exact version, including client-to-core and wallet-to-client
dependencies. Release packaging additionally requires the three matching Maven
artifacts, POMs and Gradle module metadata under `org.hyperledger.iroha.sdk`;
missing wallet outputs, different build/Maven bytes, and unrelated versions or
modules are rejected. Each library metadata variant retains its exact owned
dependency graph and artifact name, URL, size and checksums; source/javadoc
variants retain their own original files. A leading `v` in the package label is removed once to obtain
the Maven version, matching the mobile workflow. Native source authentication,
ABI inspection and provenance checks remain mandatory. Packaging captures the
complete original input identities/digests before native validation, rechecks
that snapshot afterward, copies through stable regular-file descriptors, and
compares both staged files and actual ZIP payloads against the captured bytes.
The source inventory, copied payloads and archive are rechecked immediately
before the existing atomic no-replace package publication. Source/copy mutation
or later restoration cannot replace the original validated payload.

The mobile workflow explicitly runs `:core-jvm:test` before publication and
creates per-module runtime CycloneDX reports for `core-jvm`, `client-android`,
and `kagemusha-wallet-android`. Version, group and module identity are checked
before the complete three-report inventory is collected into a new external
directory. The `kotlin-runtime-sbom-*` CI artifact is separate from the mobile
release publisher; it is not a signed release attestation or a native Rust SBOM.
Retired Java and sample reports cannot satisfy the Kotlin publication inventory.

For an operator-authorized signed inventory, `scripts/android_sbom_provenance.sh
<version>` requires `MOBILE_SDK_ANDROID_ARTIFACT_DIR` and a new absolute external
`MOBILE_SDK_SBOM_OUTPUT_DIR` whose parent exists. It uses the Kotlin wrapper and
an external project cache, tests the canonical SDK, generates its three reports,
and invokes keyless cosign signing. Do not run that command as a read-only check.
Sourceable `collect_sbom_reports` performs collection only and does not sign.

Focused tests: `python3.12 -I -S -B scripts/tests/mobile_sdk_android_artifacts_test.py`
and `python3 -m pytest pytests/scripts/bash_3_portability_test.py`. Full native,
Android device/R8/16KiB, clean release build and signed artifact qualification
remain separate requirements.
