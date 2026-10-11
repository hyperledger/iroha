# Bytes

A utility library for working with bytes.

[![Crates.io][crates-badge]][crates-url]
[![Build Status][ci-badge]][ci-url]

[crates-badge]: https://img.shields.io/crates/v/bytes.svg
[crates-url]: https://crates.io/crates/bytes
[ci-badge]: https://github.com/tokio-rs/bytes/workflows/CI/badge.svg
[ci-url]: https://github.com/tokio-rs/bytes/actions

[Documentation](https://docs.rs/bytes)

## Usage

To use `bytes`, first add this to your `Cargo.toml`:

```toml
[dependencies]
bytes = "1"
```

Next, add this to your crate:

```rust
use bytes::{Bytes, BytesMut, Buf, BufMut};
```

## Iroha native fork

This maintained fork is based on upstream `bytes` 1.11.1. It requires the Rust
standard library; disabling the `std` feature is a compile error. The default
`std` feature name remains available for dependency feature selection. Platforms
without native atomic compare-and-swap are not supported.

The local `Bytes::try_from_owner_with_reclaim` API retains admitted allocation
custody until the original buffer allocation is freed. Its fallible allocation,
owner-return and reclamation-order tests remain part of this fork.

The three benchmark targets use the workspace Criterion harness on the pinned
stable toolchain. Run them with `cargo bench -p bytes --benches`; use
`cargo bench -p bytes --benches -- --test` to exercise every case once.

## Serde support

Serde support is optional and disabled by default. To enable use the feature `serde`.

```toml
[dependencies]
bytes = { version = "1", features = ["serde"] }
```

The MSRV when `serde` feature is enabled depends on the MSRV of `serde`.

## Building documentation

When building the `bytes` documentation the `docsrs` option should be used, otherwise
feature gates will not be shown. This requires a nightly toolchain:

```
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc
```

## License

This project is licensed under the [MIT license](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `bytes` by you, shall be licensed as MIT, without any additional
terms or conditions.
