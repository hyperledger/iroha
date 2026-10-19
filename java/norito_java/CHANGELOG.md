# Changelog

## v0.1.0 (unreleased)
- Revalidated parity after the Rust Norito archived `Result` decoder now
  validates the payload-context bounds before reading the variant tag and
  length header, closing an out-of-bounds read on truncated input; Java
  bindings required no implementation changes beyond rerunning the parity
  suite because this is an internal Rust-side safety check.
- Revalidated parity after the Rust Norito accelerator-output hardening now
  rejects malformed Stage-1 structural tapes and invalid GPU zstd output
  lengths before consuming helper results; Java bindings required no
  implementation changes beyond rerunning the parity suite because these are
  internal Rust-side safety checks.
- Added ByteBuffer decode overloads plus CRC64 helpers for buffer-backed payloads.
- Revalidated parity after the Rust Norito enum named-variant self-delimiting decode fix; Java bindings required no implementation changes beyond rerunning the parity suite.
- Revalidated parity after the Rust Norito GPU zstd loader wrapped its CUDA
  symbol lookups in explicit `unsafe {}` blocks for Rust 2024 linting; Java
  bindings required no implementation changes beyond rerunning the parity
  suite.
- Bundled rANS is now forced on in Rust without requiring an env var; Java
  bindings needed no implementation changes beyond rerunning the parity suite.
- Revalidated parity after the Rust Norito GPU zstd CUDA loader now imports
  `CStr` for non-macOS targets; Java bindings required no implementation
  changes beyond rerunning the parity suite.
- Revalidated parity after Rust now implements `FastJsonWrite` for `json::Value`
  instead of `JsonSerialize`; Java bindings stay aligned after rerunning the
  parity checks.
- Documented the Rust JSON pretty-printer update that now escapes non-ASCII
  characters in pretty output; Java bindings stay aligned after rerunning the
  parity checks.
- Revalidated parity after the Rust Norito panic payload copy cleanup; Java
  bindings required no implementation changes beyond rerunning the parity suite.
- Recorded the Rust Norito cleanup (removed old length readers and lenient
  instruction deframing; bundled-only streaming defaults). Java bindings
  continue to use the canonical encoder/decoder paths with no API changes, and
  parity was revalidated for the stricter framing.
- Added `NoritoCodec.fromBytesView`/`ArchiveView` to expose header flags and
  minor hints (v1 minor fixed to `0x00`), aligning with the Rust
  `ArchiveView::flags*` helpers and rejecting unsupported minor versions when
  deframing.
- Added enum/discriminant NCB/AoS columnar helpers for `(u64, enum(Name|Code), bool)`
  rows, matching the Rust/Python descriptors and current AoS layout.
- Enabled Maven/Gradle publishing via `maven-publish` with coordinates
  `org.hyperledger.iroha:norito-java`.
- Revalidated parity after the Rust Norito streaming RD harness/PSNR flag
  tweaks; Java bindings stay unchanged beyond rerunning the parity suite for the
  sync guard.
- Revalidated parity after the Rust Norito x86 CLMUL intrinsic import fix on the
  CRC64 path; Java bindings required no implementation changes beyond rerunning
  the parity suite.
- Revalidated parity after the Rust Norito CRC64 hardware path now defers to
  runtime auto-detection in `crc64fast`; Java bindings remain unchanged aside
  from rerunning the parity suite.
- Revalidated parity after the Rust Norito option decode canonicalisation; Java bindings required no implementation changes beyond rerunning the parity suite for the sync check.
- Revalidated parity after the Rust Norito clippy cleanup touching streaming
  key snapshots and NEON mask helpers; Java bindings remain unchanged beyond
  rerunning the parity suite.
- Recorded the Rust Norito stage-1 benchmark/threshold refresh; Java bindings
  remain unchanged but parity was revalidated so the sync check stays aligned.
- Recorded the new GPU bundle-acceleration gating flag from Rust; Java bindings
  remain unchanged but parity was revalidated so the Norito sync check stays in
  lockstep.
- Revalidated parity after the Rust Norito encode-context tracing guard fix; Java bindings remain unchanged aside from rerunning the parity checks.
- Added `NoritoCodec.tryDecode` returning a `Result` wrapper so callers can
  inspect decode failures without throwing; mirrors Rust's
  `NoritoDeserialize::try_deserialize`.
- Revalidated the streaming snapshot/dump harness after the Rust codec tests
  inlined their hex helper; Java bindings required no code changes beyond this
  parity verification step.
- Recorded the Rust JSON pretty-printer multi-byte fix; Java bindings continue
  to match the core codec and only required parity verification.
- Revalidated parity after the Rust Norito audio/segment error structures were
  split into detail records. Java bindings continue to match the Rust codec and
  only required parity verification for the sync check.
- Confirmed parity after the Rust Norito Box/Rc/Arc deserialization alignment fix; Java bindings remain unchanged aside from parity validation.
- Confirmed parity with the latest Rust Norito crate after supervisor UI updates; no Java codec changes were required, but bindings are marked as refreshed for the sync check.
- Mirrored the Rust Norito dependency upgrades (`blake3` 1.8, `rand` 0.9); Java parity checks continue to pass without implementation changes.
- Added baseline RLE block decoding helpers that surface `MissingEndOfBlock`
  when the end-of-block marker is omitted, matching Rust parity expectations.
- Added `KeyUpdateState`/`ContentKeyState` snapshot helpers for deterministic
  resume parity with the Rust streaming state surface.
- Added NCB/AoS columnar helpers for `(u64, bytes)` rows, including optional byte columns,
  mirroring the Rust/ Python codecs for registry payloads.
- Implemented streaming ticket and revocation codecs (commitment/nullifier/proof metadata),
  aligning the Java bindings with the NSC-37a schema.
- Updated adaptive defaults to leave `VARINT_OFFSETS` disabled unless requested, matching the Rust Norito heuristics change.
- Noted Rust Norito now assumes a std environment; Java codec parity confirmed without code changes.
- Verified packed set encoding keeps `VARINT_OFFSETS` parity with the Rust
  Norito BTreeSet serialization fix
- Added compression profiles (`FAST`, `BALANCED`, `COMPACT`) via `CompressionConfig.zstdProfile`,
  matching the Python heuristics and surfacing runtime validation for the `zstd-jni` backend.
- Initial Java Norito codec (JDK 21-ready)
- Header encode/decode, CRC64-XZ, type adapters, packed sequences/structs
- CLI inspector (`NoritoDump`) and assertion-based test harness
- Adds optional Zstandard compression (when `com.github.luben:zstd-jni` is on the classpath)
- Implements structural schema hashing matching Rust's canonical JSON FNV-1a derivation
- Provides columnar helpers and adaptive AoS layout for `(u64, String, boolean)` rows
- Columnar helpers cover `(u64, String, boolean)`, `(u64, bytes)` (including optional bytes),
  and `(u64, enum(Name|Code), boolean)` rows.
