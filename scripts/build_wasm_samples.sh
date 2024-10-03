#!/bin/sh
set -e;
SAMPLES_DIR="wasm_samples"
TARGET_DIR="$SAMPLES_DIR/target/prebuilt"
mkdir -p "$TARGET_DIR"
# FIXME: `executor_custom_data_model` doesn't compile: https://github.com/hyperledger/iroha/issues/5114
for dir in $(
  cargo metadata --no-deps --manifest-path ./wasm_samples/Cargo.toml --format-version=1 |
  jq -r '.packages[].manifest_path | rtrimstr("/Cargo.toml") | split("/") | last | select(. != "executor_custom_data_model")'
); do
  out_file="$TARGET_DIR/$dir.wasm"
  cargo run --bin iroha_wasm_builder -- build "$SAMPLES_DIR/$dir" --optimize --out-file "$out_file"
done
echo "info: WASM samples build complete"
cp "$TARGET_DIR/default_executor.wasm" ./defaults/executor.wasm
echo "info: copied default executor to ./defaults/executor.wasm"
