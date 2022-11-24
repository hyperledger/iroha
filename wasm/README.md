# Iroha WASM

The library crate that is used for writing Iroha-compliant smart contracts in Rust using the WebAssembly format.

## Usage

Check the [WASM section of our tutorial](https://hyperledger.github.io/iroha-2-docs/guide/blockchain/wasm.html) for a detailed guide.

## Running tests

To be able to run tests compiled for `wasm32-unknown-unknown` target install `webassembly-test-runner`:

```bash
cargo install webassembly-test-runner
```

Then run tests:

```bash
cargo test
```

## Reducing the size of WASM

Since smart contracts are stored directly on the blockchain, you would want to reduce their size.
By following this list of optimization steps you can reduce the size of your binary by an order of magnitude
(e.g. from 1.1MB to 100KB):

1. Create a `Cargo.toml` following this template:

  ```toml
    [package]
    name = "smartcontract"
    version = "0.1.0"
    edition = "2021"

    [lib]
      # A smart contract should be linked dynamically so that it may link to functions exported
      # from the host environment. The host environment executes a smart contract by
      # calling the function that smart contract exports (entry point of execution)
    crate-type = ['cdylib']

    [profile.release]
    strip = "debuginfo" # Remove debugging info from the binary
    panic = "abort"     # Panics are transcribed to Traps when compiling for WASM
    lto = true          # Link-time-optimization produces notable decrease in binary size
    opt-level = "z"     # Optimize for size vs speed with "s"/"z" (removes vectorization)
    codegen-units = 1   # Further reduces binary size but increases compilation time

    [dependencies]
    iroha_data_model = { git = "https://github.com/hyperledger/iroha/", branch = "iroha2", default-features = false }
    iroha_wasm = { git = "https://github.com/hyperledger/iroha/", branch = "iroha2" }
  ```

2. Re-build `libcore` and `alloc` with excluded panicking infrastructure:

  ```
    cargo +nightly build -Z build-std -Z build-std-features=panic_immediate_abort --target wasm32-unknown-unknown
  ```

  :exclamation: **NOTE:** This cargo feature is unstable and may not be suitable for production.

3. Use [wasm-opt](https://github.com/WebAssembly/binaryen) to further optimize the built binary:

  ```sh
  $ wasm-opt -Os -o output.wasm input.wasm
  ```

Following these steps is the bare minimum that can be done to all WASM smart contracts.
We encourage you to profile the binaries [using twiggy](https://rustwasm.github.io/twiggy/) to further reduce their size.
