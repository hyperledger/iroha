# AES provider allocation layout

The [receipt](provider-layout.json) records compile-only layout probes with
Rust 1.93.1, the vendored AES source and dependencies matching the measured
root lock. Eight builds cover portable and accelerated modes on ARM64 macOS,
iOS and Android, and x86-64 Linux musl. No code ran on those target devices;
this supplies no physical x86 qualification.

Every provider requests 960 heap bytes. Alignment is eight bytes for portable
AES and 16 for the accelerated wrapper, including its runtime fallback. The
`Prg` wrapper and trait-object pointer live outside that allocation. Its
encryption batch is on the stack. Allocation metadata, native allocator size
classes, stack and compiler temporaries are outside this measurement.

Source inspection establishes at most one provider allocation live during
verification: GGM expansion temporaries, leaf-commit generators and the
small-VOLE fold generators run sequentially. Each constructor also performs a
key schedule; encrypted-block counts alone omit that work.

To reproduce, create a separate temporary Cargo workspace. Copy
[the source](provider-layout.rs) to `src/lib.rs`, the
[manifest template](provider-layout-Cargo.toml.template) to `Cargo.toml` with
`@IROHA_REPO@` replaced by the checkout's absolute path, and the
[lock template](provider-layout-Cargo.lock.template) to `Cargo.lock`.
Use the exact target and mode from the receipt:

```sh
cargo +1.93.1 rustc --offline --locked --lib --release \
  --target aarch64-apple-darwin --target-dir pinned-target \
  --features accel -- --emit=llvm-ir=/absolute/temporary/probe.ll
```

Omit `--features accel` for portable mode. The `B6_*` LLVM globals encode
`size_of` and `align_of` as array lengths; their own global alignment is not
the provider's alignment. Retained `.ll.txt` outputs and their hashes allow
inspection without rebuilding. These layouts are pinned compiler/target
facts, not a Rust language guarantee for future versions.
