# Changelog

## v0.1.0 (unreleased)
- Revalidated parity after the Rust Norito archived `Result` decoder now
  validates the payload-context bounds before reading the variant tag and
  length header, closing an out-of-bounds read on truncated input; Python
  bindings required no implementation changes beyond rerunning the parity
  suite because this is an internal Rust-side safety check.
- Revalidated parity after the Rust Norito accelerator-output hardening now
  rejects malformed Stage-1 structural tapes and invalid GPU zstd output
  lengths before consuming helper results; Python bindings required no
  implementation changes beyond rerunning the parity suite because these are
  internal Rust-side safety checks.
- Revalidated parity after the Rust Norito enum named-variant self-delimiting decode fix; Python bindings required no code changes beyond rerunning the parity suite.
- Revalidated parity after the Rust Norito GPU zstd loader wrapped its CUDA
  symbol lookups in explicit `unsafe {}` blocks to satisfy the Rust 2024
  lint; Python bindings needed no code changes beyond rerunning the parity
  suite.
- Bundled rANS is now enabled unconditionally in Rust (no env var required);
  Python bindings needed no code changes beyond rerunning the parity suite.
- Revalidated parity after the Rust Norito GPU zstd CUDA loader now imports
  `CStr` to link on non-macOS targets; Python bindings required no code changes
  beyond rerunning the parity suite.
- Revalidated parity after Rust switched `json::Value` to implement `FastJsonWrite`
  in place of `JsonSerialize`; Python bindings required no code changes beyond
  rerunning the parity suite.
- Documented the Rust JSON pretty-printer change that now forces ASCII escapes
  for non-ASCII input; Python bindings remain in parity after rerunning the
  sync checks.
- Revalidated parity after the Rust Norito panic payload copy cleanup; Python
  bindings required no code changes beyond rerunning the parity suite.
- Recorded the Rust Norito cleanup (old length readers and lenient instruction
  deframing removed; bundled-only streaming defaults). Python bindings continue
  to use the canonical encoder/decoder paths and require no API changes, but
  the parity check was rerun to mirror the stricter framing.
- Added `from_bytes_view`/`ArchiveView.decode` so callers can deframe archives and
  inspect header flags/minor hints, matching the new Rust `ArchiveView::flags*`
  accessors.
- Revalidated parity after the Rust Norito streaming RD harness/PSNR flag
  tweaks; bindings remain unchanged, parity suite rerun to satisfy the sync
  guard.
- Revalidated parity after the Rust Norito x86 CLMUL intrinsic import fix used by
  the CRC64 path; Python bindings required no code changes beyond rerunning the
  parity suite.
- Revalidated parity after the Rust Norito CRC64 hardware path switched to runtime
  auto-detection via `crc64fast`; Python bindings remain unchanged aside from
  rerunning the parity suite.
- Revalidated parity after the Rust Norito option decode canonicalisation; Python bindings required no code changes beyond rerunning the parity suite for the sync check.
- Revalidated parity after the Rust Norito clippy cleanup for streaming key
  snapshots and NEON mask helpers; Python bindings remain unchanged aside from
  rerunning the parity suite.
- Recorded the Rust Norito stage-1 benchmark/threshold refresh; Python bindings
  remain unchanged but parity was revalidated so the sync check stays green.
- Recorded the GPU bundle-acceleration gating flag added in Rust; Python bindings
  require no code changes, but parity was revalidated so the roadmap sync check
  stays green.
- Revalidated parity after the Rust Norito encode-context tracing guard fix; Python bindings did not require code changes beyond rerunning the parity suite.
- Added `norito.try_decode` to mirror Rust's new `NoritoDeserialize::try_deserialize`
  helper; callers can now inspect decode failures without relying on exceptions.
- Revalidated the streaming snapshot/dump harness after the Rust codec tests
  switched to an internal hex helper; Python bindings needed no implementation
  changes beyond rerunning this parity check.
- Documented the Rust JSON pretty-printer fix for multi-byte characters; Python
  bindings remain behaviorally equivalent but parity was revalidated for the sync check.
- Revalidated parity after the Rust Norito audio/segment error detail cleanup
  (new structs for mismatch diagnostics); Python bindings required no code
  changes beyond rerunning the parity suite.
- Revalidated parity after the Rust Norito enum tagging adjustments used by the
  asset `Mintable` schema; Python bindings required no functional changes.
- Revalidated parity after the Rust Norito Box/Rc/Arc deserialization fix; Python bindings require no code changes beyond rerunning the parity checks.
- Recorded the `blake3` 1.8 / `rand` 0.9 dependency bumps from the Rust Norito crate; Python bindings require no code changes but parity was revalidated.
- Recorded parity for the new `MissingEndOfBlock` streaming error introduced in
  the Rust Norito codec; Python bindings will surface it once streaming façade
  support lands (tracked in the Python Norito roadmap).
- Documented the Rust streaming snapshot/resume flow (`KeyUpdateSnapshot`,
  `ContentKeySnapshot`, deterministic STS root re-derivation). Streaming support
  in these bindings still needs to mirror the persistence API and is scheduled
  alongside the upcoming streaming module port.
- Updated adaptive defaults to leave `VARINT_OFFSETS` unset unless explicitly requested, matching the Rust Norito heuristics change.
- Documented that the Rust bindings now require the standard library; no Python updates were needed beyond parity checks.
- Confirmed packed-set encoders honour the `VARINT_OFFSETS` flag to match the
  Rust Norito BTreeSet layout fix
- Initial release of the Python Norito codec
- Implements header parsing/serialization, CRC64 verification, and optional Zstandard compression
- Supports primitive values (signed/unsigned integers, floats, bool), strings, bytes, options, results, sequences, maps, and packed structs
- Includes CLI inspector (`norito-dump`), unittest coverage, and a publishing guide
- Adds structural schema hashing (type-name and structural descriptors) matching Rust FNV-1a output
- Implements columnar helpers and adaptive AoS layouts for `(u64, str, bool)` rows
- Columnar helpers currently target only the `(u64, str, bool)` telemetry shape with adaptive
  AoS layouts; extending coverage to additional row patterns and compression heuristics remains on
  the Python Norito backlog.
