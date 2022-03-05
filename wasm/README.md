# How to optimize your binary size?

Smartcontracts' size should be optimized because they are stored directly on the blockchain. By
following this list of optimization steps your binary's size can be reduced by an order of magnitude
(e.g. from 1.1MB to 100KB):

1. Create a `Cargo.toml` following this template:

```toml
  [package]
  name = "smartcontract"
  version = "0.1.0"
  edition = "2021"

  [lib]
    # Smartcontract should be linked dynamically so that it may link to functions exported
    # from the host environment. Also, host environment executes the smartcontract by
    # calling the function which smartcontract exports(entry point of execution)
  crate-type = ['cdylib']

  [profile.release]
  strip = "debuginfo" # Remove debugging info from the binary
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

Following these steps is the bare minimum that can be done to all WASM smartcontracts.
Users are encouraged to further reduce the sizes of their binaries by profiling using
[twiggy](https://rustwasm.github.io/twiggy/) and avoid usage of large libraries.
