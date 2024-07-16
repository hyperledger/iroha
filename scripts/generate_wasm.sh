#!/bin/sh

TARGET_DIR="test-smartcontracts"

mkdir -p "$TARGET_DIR"

generate()
{
  SOURCE_DIR="$1"
  for folder in "$SOURCE_DIR"/*; do
      if [ -d "$folder" ] && [ "$(basename "$folder")" != ".cargo" ]; then

          folder_name=$(basename "$folder")
          target_wasm_file_path="${TARGET_DIR}/${folder_name}.wasm"
          # Build the smart contracts
          cargo run --bin iroha_wasm_builder -- build "$folder" --optimize --out-file "$target_wasm_file_path"

      fi
  done
}

# If no arguments are provided, use the sample directory
if [ "$#" -eq 0 ]; then
    DEFAULT_EXECUTORS_DIR="samples/executors"
    DEFAULT_SMART_CONTRACTS_DIR="samples/smart_contracts"
    DEFAULT_TRIGGERS_DIR="samples/triggers"

    generate $DEFAULT_EXECUTORS_DIR
    echo "Executors build complete."
    generate $DEFAULT_SMART_CONTRACTS_DIR
    echo "Smart contracts build complete."
    generate $DEFAULT_TRIGGERS_DIR
    echo "Triggers build complete."
else
    generate "$1"
    echo "Smart contracts build complete."
fi
