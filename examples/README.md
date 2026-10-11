# Kotodama and IVM examples

This directory contains small strict-V1 Kotodama sources (`.ko`). The unified
`koto` driver checks them and builds canonical IVM artifacts (`.to`).

## Check and build

```sh
koto check examples/hello/hello.ko
koto build examples/hello/hello.ko \
  --out target/examples/hello.to \
  --max-cycles 1000000

koto check examples/transfer/transfer.ko
koto check examples/nft/nft.ko
koto build examples/transfer/transfer.ko examples/nft/nft.ko
```

Without `--out`, artifacts and hash-keyed sidecars are published under
`target/kotodama/<profile>/`. Unchanged inputs are reported as `fresh` and do
not rewrite outputs.

Use the Iroha CLI for a local named-entrypoint check:

```sh
iroha --config defaults/client.toml \
  contract debug-call \
  --code-file target/examples/hello.to \
  --entrypoint main
```

Kotodama V1 has no implicit entrypoint or source-order dispatch. Always select
the public `kotoage fn`/`言挙げ fn` or `view fn` by name. The local debugger reports gas,
cycles, syscalls, queued instructions, durable-state changes, and source-aware
traps. `koto test` reports the gas and cycles of every test, and
`koto test run --gas-report` adds a per-kotoage gas table.

Pass the build's `--source-map-file` to resolve a fault to its authenticated
source location. An optional `--source-file` override requires that map;
the debugger first checks its artifact hash.

## Files

- `coffee-club/` packages a small rewards contract with Musubi and includes four
  Kotodama VM tests; see its README for the local workflow.
- `hello/hello.ko` logs a greeting and calls
  `ledger::account::set_metadata` for `context::authority()`.
- `transfer/transfer.ko` uses typed pointer constructors and
  `ledger::asset::transfer`.
- `nft/nft.ko` uses `ledger::nft::mint` and `ledger::nft::transfer`.
- `map/map.ko` demonstrates compiler-bounded durable map iteration.
- `crates/kotodama_lang/src/samples/native_escrow.ko` wraps ledger-managed
  escrow operations instead of relying on a contract-controlled account.

The source language cannot select ABI/vector metadata, allocate raw host
memory, invoke direct syscall variants, or submit opaque instruction bytes. ABI
v1 is unconditional, and the selected cycle ceiling is embedded in the hashed
artifact header.

See `specs/kotodama_grammar.md` for the normative language and
`specs/kotodama_examples.md` for compile-checked examples and security
boundaries.
