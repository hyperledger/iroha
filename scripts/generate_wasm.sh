#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <source-dir>"
    exit 1
fi

# First argument is the source directory
SOURCE_DIR="$1"

TARGET_DIR="test-smartcontracts"

mkdir -p "$TARGET_DIR"

for folder in "$SOURCE_DIR"/**; do
    if [ -d "$folder" ] && [ "$(basename "$folder")" != ".cargo" ]; then

        folder_name=$(basename "$folder")
        target_wasm_file_path="${TARGET_DIR}/${folder_name}.wasm"
        # Build the smart contracts
        cargo run --bin iroha_wasm_builder_cli -- build "$folder" --optimize --outfile "$target_wasm_file_path"

    fi
done

echo "Smart contracts build complete."

# How to run:
# make sure you root from the root directrory if iroha or
# any iroha directory that is not a package in the working space
# run the following command:
# ./path/to/script/generate_wasm.sh /path/to/smart_contracts
