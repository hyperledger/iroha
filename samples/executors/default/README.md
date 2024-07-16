# `iroha_default_executor`

Use the [Wasm Builder CLI](../../../bins/iroha_wasm_builder_cli) in order to build it:

```bash
cargo run --bin iroha_wasm_builder -- \
  build ./samples/executors/default --optimize --out-file ./configs/swarm/executor.wasm
```
