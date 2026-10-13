# Standalone iOS observation host template

This is the source-only template of the temporary UIKit host used for B6 device
observations. It is outside the workspace and introduces no wallet, SDK, node or
production proof integration. Qualification remains false. The repository/team
substitutions below are the only differences from the tested host sources. The
fixed experimental bundle identifier is retained; use an available identifier if
your signing account requires one and record that local substitution.

Included: `project.yml`, `Sources/main.m`, bridge Rust source/manifest and its
independent `Cargo.lock.template` (restored to `Cargo.lock` in the disposable copy). The bridge lock is a separately resolved, pruned graph;
it is not the root workspace lock. The core ballot/backend sources are the same
frozen sources recorded by the B6 source manifest. Generated Xcode projects,
libraries, apps, provisioning profiles, certificates, signing probes, build
products and device identifiers are deliberately absent.

Prerequisites: macOS with Xcode, an iOS SDK, XcodeGen, the repository toolchain,
`aarch64-apple-ios` Rust target, cached locked Cargo dependencies, an available
Apple development team, and a trusted connected iPhone with development enabled.
Install the Rust target through `rustup target add aarch64-apple-ios`. If the
locked dependencies are not cached, fetch them with Cargo before the offline
commands. Run Cargo from the repository root so its toolchain selection applies.

Copy and substitute into a disposable directory, outside the repository. Set
these variables to your local paths and signing team; do not save personal
signing/device details in this repository.

```sh
export IROHA_REPO=/absolute/path/to/iroha
export IOS_HOST=/tmp/parliament-b6-ios-reproduction
export DEVELOPMENT_TEAM=YOUR_TEAM_IDENTIFIER
cp -R "$IROHA_REPO/docs/validation/parliament_ballot_b6/ios_host_template" "$IOS_HOST"
python3 - <<'PY'
import os
from pathlib import Path
host = Path(os.environ['IOS_HOST'])
replacements = {'@IROHA_REPO@': os.environ['IROHA_REPO'],
                '@DEVELOPMENT_TEAM@': os.environ['DEVELOPMENT_TEAM']}
for name in ['project.yml', 'bridge/Cargo.toml', 'bridge/src/lib.rs']:
    path = host / name
    text = path.read_text()
    for old, new in replacements.items():
        text = text.replace(old, new)
    path.write_text(text)
(host / "bridge/Cargo.lock.template").rename(host / "bridge/Cargo.lock")
PY
```

Host helper tests (two bridge checks plus eight included runner checks):

```sh
cargo test --offline --release --manifest-path "$IOS_HOST/bridge/Cargo.toml" --features accel -- --test-threads=1
cargo test --offline --release --manifest-path "$IOS_HOST/bridge/Cargo.toml" -- --test-threads=1
```

Use the external workspace's own warm Cargo target. The repository wrapper
correctly rejects reusing a target owned by a different source tree; do not bypass
that ownership check. These host tests are not device execution or FFI lifecycle
qualification.

The tested Rust device build command is below. Set `PARLIAMENT_B6_SOURCE_ID` to
the SHA-256 of the complete source manifest you verified before building. The B6
recorded source ID is
`044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb`.
Do not use that ID after changing any recorded input.

```sh
export PARLIAMENT_B6_SOURCE_ID=YOUR_VERIFIED_SOURCE_MANIFEST_SHA256
cargo build --offline --manifest-path "$IOS_HOST/bridge/Cargo.toml" --target aarch64-apple-ios --release --features accel
mkdir -p "$IOS_HOST/lib"
cp "$IOS_HOST/bridge/target/aarch64-apple-ios/release/libparliament_qualification_bridge.a" "$IOS_HOST/lib/"
```

For portable mode omit `--features accel`. Record the static library hash before
copying it, because the next build replaces that output. The bridge's own `accel`
feature forwards both backend and ballot acceleration and controls the JSON label.
Its release profile uses optimization level 3, thin LTO and one codegen unit.
This differs from the repository example build configuration and must remain in
any cross-platform timing interpretation.

Generate and sign the native host using your runtime device identifier:

```sh
(cd "$IOS_HOST" && xcodegen generate)
xcodebuild -project "$IOS_HOST/ParliamentQualification.xcodeproj" -scheme ParliamentQualification -configuration Release -destination "id=$DEVICE_UDID" -derivedDataPath "$IOS_HOST/build" -allowProvisioningUpdates build
xcrun devicectl device install app --device "$CORE_DEVICE_ID" "$IOS_HOST/build/Build/Products/Release-iphoneos/ParliamentQualification.app"
xcrun devicectl device process launch --device "$CORE_DEVICE_ID" org.iroha.experimental.parliament-b6 --run-label b6-accel-31 --samples 31 --row candidate
```

`DEVICE_UDID` and `CORE_DEVICE_ID` are runtime inputs from Xcode/CoreDevice; they
are not included in this template. Retain raw build receipts privately if they
contain signing details. Never terminate an ongoing run to start another until
its completed data has been copied and checked. Use a new run label for each run;
the host refuses to overwrite an existing directory. Keep the app in the foreground.

Copy `Documents/<run-label>` from the app data container with Xcode or CoreDevice.
A completed directory contains `measurements.ndjson`, `device.plist` and
`complete.txt`. Require result code 0, metadata saved, a final `run_complete` JSON
record, the expected sample counts and the expected source ID. Bridge codes are
2 for null pointers, 3 for invalid UTF-8, 4 for output-file creation, 5 for final
flush, 6 for runner failure and 7 for a caught panic. Retain failed runs as
failed evidence rather than treating partial output as completion.

The worker is a dedicated background `NSThread` with an 8 MiB virtual stack
reservation; this is not a claim of 8 MiB resident stack. The main thread records
thermal state, power mode, battery state/level, physical footprint and resident
bytes every 250 ms and at completion. Those sampled OS measurements can miss
transient peaks and are separate from exact requested Rust allocator events.
UIKit/Objective-C allocations are outside the Rust counter. The host does not
reset CPU caches, control thermal equilibrium, measure energy, enforce an
isolated baseline or qualify any phone model.

For proof parity compare `(row, case, sample_index, proof_shake256_32,
retry_counter)` with the corresponding desktop run. The same deterministic test
tape is derived independently on each device; these are public test credentials,
not production credentials or randomness. The core runner's method and exclusions
are described in the crate's `examples/QUALIFICATION.md` and each NDJSON header.

Both host commands passed all 10 tests on the B6 development Mac (release builds):
[accelerated log](../ios-bridge-host-tests-accel.txt) and
[portable log](../ios-bridge-host-tests-portable.txt). These tests ran in a separate
copied external workspace; the active device-build directory was not modified.
