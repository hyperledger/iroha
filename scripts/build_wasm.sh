#!/bin/sh
set -e;

DEFAULTS_DIR="defaults"
CARGO_DIR="wasm"
TARGET_DIR="$CARGO_DIR/target/prebuilt"

build() {
    case $1 in
        "libs")
            NAMES=(
                # order by dependency
                "default_executor"
            )
            ;;
        "samples")
            NAMES=($(
                cargo metadata --no-deps --manifest-path "$CARGO_DIR/Cargo.toml" --format-version=1 |
                jq '.packages | map(select(.targets[].kind | contains(["cdylib"]))) | map(.manifest_path | split("/")) | map(select(.[-3] == "samples")) | map(.[-2]) | .[]' -r
            ))
    esac

    mkdir -p "$TARGET_DIR/$1"
    for name in ${NAMES[@]}; do
        out_file="$TARGET_DIR/$1/$name.wasm"
        cargo run --bin iroha_wasm_builder -- build "$CARGO_DIR/$1/$name" --optimize --out-file "$out_file"
    done
    echo "info: WASM $1 build complete"
    echo "artifacts written to $TARGET_DIR/$1/"
}

command() {
    case $1 in
        "libs")
            build $1
            cp -r "$TARGET_DIR/$1" "$DEFAULTS_DIR/"
            mv "$DEFAULTS_DIR/$1/default_executor.wasm" "$DEFAULTS_DIR/executor.wasm"
            echo "info: copied wasm $1 to $DEFAULTS_DIR/$1/"
            echo "info: copied default executor to $DEFAULTS_DIR/executor.wasm"
            ;;
        "samples")
            build $1
    esac
}

case $1 in
    "")
        command "libs"
        command "samples"
        ;;
    "libs")
        command "libs"
        ;;
    "samples")
        command "samples"
        ;;
    *)
        echo "error: arg must be 'libs', 'samples', or empty to build both"
        exit 1
esac
