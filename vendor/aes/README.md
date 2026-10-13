# RustCrypto: Advanced Encryption Standard (AES)

## Iroha patch note

This directory is upstream `aes` 0.8.4 from crates.io (RustCrypto/block-ciphers
commit `f2dbee516b4d0cf4cb4f3045d09e35b5fd80087b`, path `aes`; registry
`.crate` SHA-256 `b169f7a6d4742236a0a00c541b845991d0ac43e546831af1249753ab4c3aa3a0`),
copied unmodified and then patched as listed below. No cipher arithmetic, key
expansion, intrinsics or dispatch logic is changed; `src/soft/`, `src/ni/`,
`src/armv8/`, `src/soft.rs`, `src/ni.rs` and `src/armv8.rs` are byte-identical
to upstream.

Why: repository policy admits hardware acceleration only behind a Cargo feature
with a deterministic fallback. Upstream selects backends by `rustc --cfg` flags
and keeps its portable implementation private.

Changes:

- `Cargo.toml` (the upstream `Cargo.toml.orig` is not kept, as in
  `vendor/num-bigint-0.4.6`): new `hardware` feature, included in the new
  `default` feature set. The `zeroize` target tables key on
  `target_arch = "aarch64"` alone because Cargo cannot test features there
  (`default_features` is spelled `default-features`). `autobenches = false`
  keeps the nightly-only `benches/mod.rs` out of stable builds. An
  `unexpected_cfgs` table declares `aes_force_soft` and `aes_compact`. A
  `[lints.clippy]` table allows `doc_lazy_continuation` (one upstream doc
  line) and `incompatible_msrv` (the unchanged ARMv8 intrinsics are newer than
  the declared `rust-version = "1.56"`, which upstream only promises for the
  portable backend), so the vendored sources pass the workspace
  `clippy -D warnings` gate unedited. The
  normalized manifest drops `resolver = "1"`, which Cargo ignores for a
  workspace member.
- `src/lib.rs`, `src/hazmat.rs`, `src/autodetect.rs`: the AES-NI
  (`x86`/`x86_64`) and ARMv8 (`aarch64`) modules, the autodetecting top-level
  types and the `hazmat` intrinsics dispatch are compiled only with
  `feature = "hardware"`. On `aarch64` the feature replaces `--cfg aes_armv8`,
  which is no longer read. `--cfg aes_force_soft` still forces the portable
  backend everywhere.
- `src/lib.rs`: `mod soft` is now `pub mod soft`, so `aes::soft::{Aes128,
  Aes192, Aes256}` and their `Enc`/`Dec` variants name the portable fixsliced
  implementation whether or not `hardware` is enabled. Crate documentation
  describes the feature.
- `tests/portable.rs`: new FIPS-197 and cross-backend equality tests.
- `tests/data/aes{128,192,256}.blb` (unchanged upstream NESSIE vectors) are
  listed by exact path in `scripts/norito_bridge_source_seal.py`, which takes
  `vendor/` as a sealed input root.

Behaviour: with default features `x86`/`x86_64` is unchanged (runtime AES-NI
detection, portable fallback). On `aarch64`, default features now use the ARMv8
Cryptography Extensions when detected at runtime; upstream used the portable
backend there unless built with `--cfg aes_armv8`. Outputs are identical on
every backend. The patch applies to every `aes` 0.8.4 consumer in the
workspace graph (currently `iroha_sccp_rpc` and, through git, `orchard`). With
`default-features = false` every target uses the portable
backend, unless another crate in the same build enables `hardware`; code that
must be portable regardless names `aes::soft::*`.

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]
[![Downloads][downloads-image]][crate-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Pure Rust implementation of the [Advanced Encryption Standard (AES)][1].

This crate implements the low-level AES block function, and is intended
for use for implementing higher-level constructions *only*. It is NOT
intended for direct use in applications.

[Documentation][docs-link]

<img src="https://raw.githubusercontent.com/RustCrypto/media/85f62bb/img/block-ciphers/aes-round.svg" width="480px">

## Security

### ⚠️ Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

To avoid this, use an [AEAD][2] mode based on AES, such as [AES-GCM][3] or [AES-GCM-SIV][4].
See the [RustCrypto/AEADs][5] repository for more information.

USE AT YOUR OWN RISK!

### Notes

This crate has received one [security audit by NCC Group][6], with no significant
findings. We would like to thank [MobileCoin][7] for funding the audit.

All implementations contained in the crate are designed to execute in constant
time, either by relying on hardware intrinsics (i.e. AES-NI on x86/x86_64), or
using a portable implementation based on bitslicing.

## Minimum Supported Rust Version

Rust **1.56** or higher.

Minimum supported Rust version can be changed in future releases, but it will
be done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/aes.svg
[crate-link]: https://crates.io/crates/aes
[docs-image]: https://docs.rs/aes/badge.svg
[docs-link]: https://docs.rs/aes/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260039-block-ciphers
[build-image]: https://github.com/RustCrypto/block-ciphers/workflows/aes/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-ciphers/actions?query=workflow%3Aaes
[downloads-image]: https://img.shields.io/crates/d/aes.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[2]: https://en.wikipedia.org/wiki/Authenticated_encryption
[3]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[4]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv
[5]: https://github.com/RustCrypto/AEADs
[6]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
[7]: https://www.mobilecoin.com/
