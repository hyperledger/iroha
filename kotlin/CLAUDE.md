# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build all modules
./gradlew build --quiet

# Run all tests
./gradlew :core-jvm:test --console=plain

# Build a specific module
./gradlew :core-jvm:build --quiet
./gradlew :client-android:assembleRelease --quiet

# Build generated native .so files and provenance outside the source tree
export MOBILE_SDK_ANDROID_ARTIFACT_DIR=/absolute/non-symlink/path/to/android-artifacts
mkdir -p "$MOBILE_SDK_ANDROID_ARTIFACT_DIR"
./gradlew :client-android:buildNativeLibs

# Publish to local Maven
./gradlew publishToMavenLocal
```

## Architecture

Three published SDK modules and a separate JVM `tools` application (`iroha_kotlin_sdk`) serve Kotlin and Java consumers.

### Module: `core-jvm` (JAR, pure Kotlin/JVM)
All protocol logic — no Android dependencies. HTTP/SSE uses the Kotlin-owned
OkHttp adapter, with scoped client lifetimes and borrowed injected backends.
WebSockets use the injected Kotlin-owned Netty engine with explicit NIO/JDK TLS
resources, bounded complete messages and one upgrade attempt. No engine is
selected through platform discovery or a process-global client:
- **`sdk.norito`** — Norito binary codec (TypeAdapter, NoritoCodec, NoritoEncoder/Decoder, compression)
- **`sdk.core.model`** — transaction models, 84 instruction types, InstructionBox, Executable (sealed class)
- **`sdk.crypto`** — Blake2b/2s/3, Ed25519, IrohaHash, and Argon2id key export (JCA + direct BouncyCastle dependency)
- **`sdk.gpu`** — one bounded batch acceleration API for both JVM languages, with explicit backend injection/native loading and automatic CPU/GPU operation selection; `cudaHardwareTest` remains an open gate until JNI per-family completion receipts are implemented
- **`sdk.crypto.keystore.attestation`**, **`KeyAttestation`** — Android-free evidence records, certificate verification and governed revocation policy shared with Android clients and offline JVM tooling
- **`sdk.address`** — account/asset address encoding (IH58, Bech32M)
- **`sdk.tx`** — transaction building, signing, offline envelopes, norito adapters
- **`sdk.client`** — Torii HTTP/WS/SSE client, JSON, transport, queue
- **`sdk.offline`** — KAGEMUSHA wallet V1 wire (`KagemushaWalletWireV1`,
  `KagemushaP256Codec`) and the `IrohaPeer` QR/NFC/Nearby carriers
- **`sdk.connect`** — connect protocol (BouncyCastle)
- **`sdk.telemetry`** — telemetry sink, options, providers
- **`sdk.multisig`**, **`sdk.subscriptions`**, **`sdk.sorafs`**, **`sdk.nexus`** — feature packages

### Module: `client-android` (AAR, depends on `core-jvm`)
Android-specific additions:
- **`sdk.crypto.keystore`** — Android Keystore provisioning, provider dispatch and platform integration; pure evidence verification belongs to `core-jvm`
- **`sdk.telemetry`** — AndroidDeviceProfileProvider, AndroidNetworkContextProvider
- **`sdk.IrohaKeyManager`** — key provider orchestrator

### Module: `kagemusha-wallet-android` (AAR)
The KAGEMUSHA wallet Android platform handle (`KagemushaWalletAndroid*V1`): the payment-key
AndroidKeyStore adapter, the opaque platform handle whose private upcalls the Rust wallet adapter
binds, and the custody backup/data-extraction rules. It has no JNI library or device lifecycle of
its own. Keep pure wire and cryptographic contracts in `core-jvm` and general Android client
integration in `client-android`.

### Module: `tools` (JVM application)

`iroha-attestation` verifies collected evidence through the `core-jvm` verifier.
It owns command parsing, bounded certificate/ZIP input and atomic JSON output.
It has no Android dependency or Maven SDK publication. Trust roots, expected
challenge/SPKI, governed snapshot commitment and evaluation time are supplied
independently of the evidence bundle. Run `:tools:test :tools:installDist`.

## JDK Compatibility

All modules enforce **JDK 8 API compatibility at compile time** via `-Xjdk-release=8` in `freeCompilerArgs`. The compiler uses JDK 21 (`jvmToolchain(21)`) but restricts the available API surface to JDK 8. Using any JDK 9+ API (e.g. `Optional.isEmpty()`, `BigInteger.TWO`, `URLEncoder.encode(String, Charset)`, `Arrays.compareUnsigned()`) will cause a compilation error. Use Kotlin stdlib equivalents or JDK 8 overloads instead.

**Do not remove `-Xjdk-release=8` from any module's `freeCompilerArgs`.** This flag is the only compile-time guard against JDK 9+ API usage. Without it, incompatible calls compile silently and crash at runtime on Android.

## API Design Rules

### No data classes in public API
**Never use `data class` for public library API types.** Use regular immutable classes with explicit construction invariants, defensive copying and intentional `equals`/`hashCode` semantics. Avoid automatic copying or rendering of sensitive protocol state. This is the first release: remove superseded interfaces and migrate callers without compatibility aliases or wrappers.

### No Reflection
**Never use `java.lang.reflect.*` in this SDK.** This library is consumed by Android apps that use R8/D8 shrinking. Reflection forces consumers to add keep rules for every reflected class/method, complicating ProGuard/R8 configuration. Use unchecked casts, explicit type checks, or Kotlin type system features instead.

### Defensive Copying
All mutable collections and byte arrays are copied on construction and access. Use `toList()`, `toMap()`, `copyOf()` patterns.

### Java Interop
- `@JvmStatic` on companion object factory methods
- `@JvmField` on public properties where Java callers need field-style access
- No `Optional` in Kotlin API — use nullable types (`T?`)
- Authenticated Torii operations use `RequestSigner`; private keys stay with the application or its explicit software signer.

## Key Patterns
- **Two instruction representations**: typed (structured fields) vs wire (opaque `ByteArray` + wire name); `InstructionBox` unifies both
- **Source layout**: main sources under `src/main/java/` (Kotlin files, retained path from Java migration), tests under `src/test/kotlin/`
- **Native libraries**: `.so` files built from Rust via
  `./gradlew :client-android:buildNativeLibs`, not tracked in git. The maintained
  production inventory requires `arm64-v8a`, `armeabi-v7a` and `x86_64` originals
  throughout source seals, build, packaging and signed provenance; source
  configuration alone grants no Native artifact or release qualification.
  Raw cargo-ndk output is isolated below
  `$MOBILE_SDK_ANDROID_ARTIFACT_DIR/gradle-build/iroha_kotlin_sdk/client-android/native/cargo-ndk/<mode>/`;
  compiler state is separately isolated in the sibling
  `native/cargo-target/<mode>/` via `CARGO_TARGET_DIR`; canonically stripped
  authoritative bytes and provenance live in the sibling `generated/` tree.
  Cargo-ndk output first lands in a
  transient per-ABI staging directory so unrelated workspace `cdylib` outputs
  cannot enter the exact raw inventory. The build verifies its race-stable
  Android source seal after every ABI and immediately before and after each raw
  or stripped/provenance promotion, and binds the dependency-closure fingerprint
  into provenance. AGP packages those generated outputs and explicitly excludes
  `src/main/jniLibs`. Every ABI uses canonical Rust 1.93.1 `cargo`, `rustc`, and
  `rustdoc`, plus `CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`,
  and `CARGO_NET_OFFLINE=true`. Stock Cargo receives
  `--locked --offline --jobs 1 --manifest-path <canonical-iroha-root>/Cargo.toml`
  and consumes the authenticated repository-root `Cargo.lock`. Bootstrap,
  alternate locks, and compiler or profile configuration overrides are rejected;
  the root lock and effective Cargo configuration are rechecked after execution.
  Production builds may explicitly select both `MOBILE_SDK_CARGO_HOME` and
  `MOBILE_SDK_CARGO_INVOCATION_DIR`. They must be existing owned canonical
  non-symbolic mode-0700 directories disjoint from source and each other.
  The invocation directory must contain only the exact discovery manifest
  `[workspace]\nmembers = []\n` for Cargo discovery, with `Cargo.lock` absent;
  the actual build still selects the authenticated root manifest and lock.
  Every effective Cargo configuration, including absent candidates, is held
  through before/after checks. The source seal retains `cargo_configuration`
  and the producer joins it to the actual selected configuration before build
  and promotion. With neither variable set, the existing default cache/source
  working directory and strict configuration refusals remain in force. Setting
  only one variable fails. This selection never changes the production profile,
  ABI inventory, release admission, artifact directory or warm target.
- **Canonical wallet framing**: the reviewed wallet-local fixed-alignment source
  pins direct `u128` records/enums to 16-byte archived alignment and preserves all
  26 existing padding values through shipping compile-time assertions. Norito
  primitives, decoders and frozen vectors were preserved by that alignment
  change. Nine host codec cases passed in three runs with the same 3,435 inputs
  and 33 local packages unchanged. These results describe the recorded source
  cuts; subsequent source changes require fresh validation.
  Qualify ARMv7 compilation and identical canonical originals/exact decoding on
  32/64-bit Native targets. Packaging and ELF checks do not prove
  runtime parity; all required Android targets remain in scope.
- **ARMv7 diagnostic**: from `kotlin`, use the existing owner-only local artifact
  root and set `MOBILE_SDK_PYTHON_BINARY` to the canonical executable of Python
  3.12 (symbolic links are rejected). Explicitly set and export both
  `MOBILE_SDK_CARGO_HOME` and `MOBILE_SDK_CARGO_INVOCATION_DIR` before running the
  task. Each must select an existing owned writable absolute canonical,
  non-symbolic mode-0700 directory. The cache and invocation trees must be
  disjoint from the source tree and each other in both directions. Prepare an
  owned regular `Cargo.toml` in the invocation directory with exactly
  `[workspace]\nmembers = []\n` bytes and keep `Cargo.lock` absent. The manifest
  must have one hard link and no group/other write permissions; symbolic links
  are rejected. Pinned cargo-ndk 4.1.2 first discovers metadata from its cwd,
  so this empty workspace supplies no packages or sources. The actual build
  still selects the authenticated repository-root manifest and lock explicitly
  and uses the existing warm target. The diagnostic configuration receipt binds
  the discovery manifest bytes and identity plus lock absence, and rechecks them
  around metadata, source sealing and the child build. Authenticate
  every effective Cargo configuration from the chosen invocation directory,
  its ancestors and Cargo home, including absent candidates; keep global
  configuration unmodified, strict refusals intact and production routing
  unchanged. Reuse the same warm diagnostic target, then run
  `MOBILE_SDK_ANDROID_ARTIFACT_DIR=/Users/takemiyamakoto/dev/iroha/dist/norito-bridge-android-local ./gradlew :client-android:compileArmv7Diagnostic -PirohaAndroidLocalIntegration=true --console=plain`.
  This task uses the same pinned Rust, NDK, Python, locked offline Cargo and
  source-seal gates, with one `armv7-linux-androideabi` target and the fixed
  `privacy-production-enabled` feature. It preserves the warm
  `native/cargo-target/armv7-diagnostic/` lane and writes raw ELF32 bytes plus
  `native/armv7-diagnostic/diagnostic-manifest.json` under that root's SDK module
  build directory. The report records ARM machine 40, actual native exports and
  LOAD alignment; it grants no release admission. The task supplies no
  generated JNI, AAR or production-inventory outputs. The maintained production
  contract independently requires `arm64-v8a`, `armeabi-v7a` and `x86_64`; diagnostic
  bytes cannot satisfy it. Configure the pinned
  toolchain and install its ARMv7 standard library before compiling. Run
  `:client-android:verifyArmv7DiagnosticContract` to check routing without a
  native build.

## Testing

JUnit 5 with `@ParameterizedTest` / `@MethodSource` for data-driven tests. Test companion objects provide argument lists via `@JvmStatic` methods.

The separate `:client-android:testDebugHostNative` task requires an explicitly
rebuilt host bridge in one absolute `IROHA_NATIVE_LIBRARY_PATH` directory.
It runs the tagged Java software-key-manager and explicit-chain-context cases,
plus the shared SoraFS reference-validator cases. Missing native artifacts or
capabilities fail; host JNI execution is separate from Android/device qualification.

The current wallet module declares managed platform, payment-key, backup-rule,
setup and admission-contract unit tests. Its Rust `KagemushaWalletPlatformV1`
JNI adapter provides platform custody. Native startup authenticates installed
artifacts and retains custody; wallet opening requires original issuer/account
frames and the existing account's signature over a fresh native challenge. An
unavailable native runtime returns `ARTIFACTS_UNAVAILABLE` (`-4`). The separate
`:kagemusha-wallet-android:testDebugHostNative` task uses the explicit rebuilt
host library to check native failure results, malformed intake, closed handles
and unavailable runtime admission. It cannot qualify successful monetary
operations, Android artifacts or physical devices.

## Version Catalog

Dependencies managed in `gradle/libs.versions.toml`: Kotlin 2.3.10, AGP 9.0.1, JUnit 5.11.4, BouncyCastle 1.78.1, zstd-jni 1.5.7-7, OkHttp 4.12.0, Netty 4.2.17.Final.
