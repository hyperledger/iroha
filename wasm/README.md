# How to optimize your binary size?

Smartcontracts should be optimized for because they are stored directly on the blockchain. By
following this list of optimization steps your binary's size can be reduced by an order of magnitude
(e.g. from 1.1MB to 100KB):

1. Create a `Cargo.toml` akin to the following template:

```toml
  [package]
  name = "smartcontract"
  version = "0.1.0"
  edition = "2021"

  [lib]
  crate-type = ['cdylib']    # Crate has to be linked dynamically

  [profile.release]
  strip = "debug"     # Remove debugging info from the binary
  panic = "abort"     # Panics are transcribed to Traps when compiling for wasm anyways
  lto = true          # Link-time-optimization produces notable decrease in binary size
  opt-level = "z"     # Optimize for size vs speed with "s"/"z"(removes vectorization)
  codegen-units = 1   # Further reduces binary size but increases compilation time

  [dependencies]
  iroha_data_model = { git = "https://github.com/hyperledger/iroha/", branch = "iroha2", default-features = false }
  iroha_wasm = { git = "https://github.com/hyperledger/iroha/", branch = "iroha2" }
```

2. Re-build `libcore` and `alloc` with excluded panicking infrastructure
```
  cargo +nightly build -Z build-std -Z build-std-features=panic_immediate_abort --target wasm32-unknown-unknown
```
**NOTE**: This cargo feature is unstable and may not be suitable for production

3. Use [wasm-opt](https://github.com/WebAssembly/binaryen) to further optimize the built binary:
```sh
$ wasm-opt -Os -o output.wasm input.wasm
```

While these settings will certainly result in a whooping size reduction of a binary,
users are encouraged to profile their releases for size and modify parameters accordingly.
