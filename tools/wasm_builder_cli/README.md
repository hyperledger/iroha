# `iroha_wasm_builder_cli`

A CLI around [`iroha_wasm_builder`](../wasm_builder) crate.

## Usage

**Check the smartcontract:**

```bash
iroha_wasm_builder_cli check path/to/project
```

**Build the smartcontract:**

```bash
iroha_wasm_builder_cli build path/to/project --outfile ./smartcontract.wasm
```

**Build with options:**

```bash
iroha_wasm_builder_cli build path/to/project --optimize --format --outfile ./smartcontract.wasm
```
