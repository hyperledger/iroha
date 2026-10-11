# Kotodama Examples

This directory contains small Kotodama (`.ko`) snippets that demonstrate language features and how they map to IVM bytecode and host syscalls.

How to compile and inspect
- From Rust: use the Kotodama compiler API from the `kotodama_lang` crate

```rust
use ivm::ProgramMetadata;
use kotodama_lang::compiler::Compiler;

fn main() {
    let code = Compiler::new()
        .compile_file("crates/ivm/docs/examples/10_meta_header.ko")
        .expect("compile");
    let parsed = ProgramMetadata::parse(&code).unwrap();
    let meta = parsed.metadata;
    println!(
        "abi_version={} mode=0x{:02x} vl={} max_cycles={}",
        meta.abi_version,
        meta.mode,
        meta.vector_length,
        meta.max_cycles
    );
}
```

- In tests: `cargo test -p ivm --test kotodama` exercises many of these patterns.

- Using the CLI bin (writes `.to`):

```
cargo run -p kotodama_toolchain --bin koto -- build crates/ivm/docs/examples/10_meta_header.ko --out /tmp/meta.to --manifest-out /tmp/meta.manifest.json
```

Build options include `--profile`, `--target-dir`, `--out`,
`--manifest-out`, `--max-cycles`, the explicit `--zk` build capability, and
`--verify` for read-only generated-output validation.
Use `--manifest-out -` to print the manifest JSON to stdout instead of writing a file.
ABI v1 and required execution capabilities are selected by release policy and
compiler analysis; source files cannot override ABI or vector metadata.

After building fresh `target/debug/koto` and `target/debug/iroha` binaries,
verify every tracked source and checked-in `.to` golden with:

```
make kotodama-goldens-check
```

To render a sealed create-only publication, select an absent absolute root
outside the workspace and run:

```
IROHA_KOTODAMA_V1_ARTIFACT_STAGE=/absolute/external/first-publication \
  make kotodama-goldens
```

Repeat with a second absent root and require identical path sets, types, modes,
owner manifests, and file bytes. Refresh tracked artifacts only as a reviewed
identity-relative patch from either sealed root, then rerun
`make kotodama-goldens-check`. The authoritative alias/output inventory is
`scripts/ivm_artifacts.tsv`; the workflow deliberately never accepts or
persists deployment signing material.

Contents
- `01_hajimari.ko`: Minimal `始まり` declaration inside an `誓約`.
- `02_view_public_fn.ko`: Explicitly open public `view fn` form.
- `03_kaizen_permission.ko`: `改善` lifecycle hook.
- `04_foreach_map.ko`: For-each syntax (unbounded form is rejected by semantics).
- `05_range_for.ko`: Range sugar lowered to C-style loop.
- `06_map_ops.ko`: Durable `StateMap` operations.
- `07_set_detail_authority.ko`: Write account metadata for `context::authority()` with `ledger::account::set_metadata`.
- `08_call_transfer_asset.ko`: Namespaced asset transfer from a seiyaku kotoage.
- `09_struct_and_state.ko`: Parsed-only examples for struct/state declarations.
- `10_meta_header.ko`: Compiler-derived ZK capability metadata and build-selected cycle ceiling.
- `11_detail_and_transfer.ko`: Pointer-ABI typed calls for metadata write and asset transfer.
- `12_nft_flow.ko`: Create an NFT and transfer it to another account.
- `13_register_and_mint.ko`: Register a new asset and mint to an account.
- `14_map_sum_take2.ko`: Deterministic two-iteration map sum via `.take(2)` on a state map.
- `15_modulo.ko`: `%` modulo operator, returns `a % b`.
- `18_ternary.ko`: Ternary conditional `cond ? then : else` expression.
- `19_contract_flow.ko` and `.test.ko`: Typed calls, scoped permissions and lifecycle fixtures.
- `20_commit_reveal.ko` and `.test.ko`: Schema-bound commitments, separate commit/reveal deadlines,
  participant binding and replay rejection. See the [determinism and randomness tutorial](https://docs.iroha.tech/guide/tutorials/randomness).

Notes
- Kotodama targets the Iroha Virtual Machine (IVM) and produces `.to` bytecode. Its canonical executable encoding uses fixed-width 32-bit IVM words and is not a hardware RISC-V target.
- Typed constructors are compiled into Norito-encoded TLV blobs and passed to
  the host through the validated pointer ABI. Raw pointers and direct syscall
  variants are not source APIs.
- ABI v1 is unconditional. The compiler derives capability bits from emitted
  instructions and uses the configured/default cycle ceiling.
- Durable `StateMap<K, V>` iteration uses `.take(n)` with a compiler-proven
  constant limit of at most 64 items. Use the map's typed `page` method and
  opaque cursor for pagination; `.range(start, end)` is not a map method.
- In-memory maps are not a V1 language type.
- Run `koto check` to review all parser, resolver, type, effect, and lint
  diagnostics without writing build outputs.
