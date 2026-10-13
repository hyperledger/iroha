# Iroha Concread storage engine

This vendored fork retains the synchronous B+tree, linear cell, and
epoch-reclaimed cell used by `mv` and `iroha_core`. Readers retain immutable
generations while one writer prepares and publishes a successor. Admitted
storage keeps allocation charges attached through physical reclamation.

The crate uses the Rust standard library. Its default features are `ebr` and
`maps`; `skinny` exercises the same B+tree engine with smaller nodes. Norito
serialization belongs to the consuming `mv` layer.

From the repository root:

```sh
cargo test -p concread
cargo test -p concread --features skinny
cargo clippy -p concread --all-targets --all-features -- -D warnings
```

See [IROHA_PATCHES.md](IROHA_PATCHES.md) for the maintained storage ownership
contracts and [LICENSE.md](LICENSE.md) for the upstream MPL-2.0 license.
