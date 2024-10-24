#!/bin/sh
set -e;

build() {
    CRATES_DIR="wasm/$1"
    TARGET_DIR="wasm/target/prebuilt/$1"
    case $1 in
        "libs")
            NAMES=(
                # order by dependency
                "multisig_transactions"
                "multisig_accounts"
                "multisig_domains"
                "default_executor"
            )
            ;;
        "samples")
            NAMES=($(
                cargo metadata --no-deps --manifest-path ./wasm/Cargo.toml --format-version=1 |
                jq '.packages | map(select(.targets[].kind | contains(["cdylib"]))) | map(.manifest_path | split("/")) | map(select(.[-3] == "samples")) | map(.[-2]) | .[]' -r
            ))
    esac

    mkdir -p "$TARGET_DIR"
    for name in ${NAMES[@]}; do
        out_file="$TARGET_DIR/$name.wasm"
        cargo run --bin iroha_wasm_builder -- build "$CRATES_DIR/$name" --optimize --out-file "$out_file"
    done
    echo "info: WASM $1 build complete"
    echo "artifacts written to $TARGET_DIR"
}

command() {
    case $1 in
        "libs")
            build $1
            cp "wasm/target/prebuilt/$1/default_executor.wasm" ./defaults/executor.wasm
            echo "info: copied default executor to ./defaults/executor.wasm"
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
