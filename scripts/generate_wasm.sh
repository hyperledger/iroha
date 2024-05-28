#!/bin/sh

# Default source directory
DEFAULT_SOURCE_DIR="client/tests/integration/smartcontracts"

# If no arguments are provided, use the default source directory
if [ "$#" -eq 0 ]; then
    SOURCE_DIR="$DEFAULT_SOURCE_DIR"
else
    SOURCE_DIR="$1"
fi

TARGET_DIR="test-smartcontracts"

mkdir -p "$TARGET_DIR"

for folder in "$SOURCE_DIR"/*; do
    if [ -d "$folder" ] && [ "$(basename "$folder")" != ".cargo" ]; then

        folder_name=$(basename "$folder")
        target_wasm_file_path="${TARGET_DIR}/${folder_name}.wasm"
        # Build the smart contracts
        cargo run --bin iroha_wasm_builder -- build "$folder" --optimize --outfile "$target_wasm_file_path"

    fi
done

echo "Smart contracts build complete."
