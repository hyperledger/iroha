#!/bin/sh
set -e;
SAMPLES_DIR="wasm_samples"
TARGET_DIR="$SAMPLES_DIR/target/prebuilt"
mkdir -p "$TARGET_DIR"
for dir in $(
  cargo metadata --no-deps --manifest-path ./wasm_samples/Cargo.toml --format-version=1 |
  jq '.packages | map(select(.targets[].kind | contains(["cdylib"]))) | map(.manifest_path | split("/") | .[-2]) | .[]' -r
); do
  out_file="$TARGET_DIR/$dir.wasm"
  cargo run --bin iroha_wasm_builder -- build "$SAMPLES_DIR/$dir" --optimize --out-file "$out_file"
done
echo "info: WASM samples build complete"
cp "$TARGET_DIR/default_executor.wasm" ./defaults/executor.wasm
echo "info: copied default executor to ./defaults/executor.wasm"
