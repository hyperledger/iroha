# `iroha_default_executor`

Use the [Wasm Builder CLI](../tools/wasm_builder_cli) in order to build it:

```bash
cargo run --bin iroha_wasm_builder -- \
  build ./default_executor --optimize --outfile ./configs/swarm/executor.wasm
```
