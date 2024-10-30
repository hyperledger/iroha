#!/bin/sh
set -e;

DEFAULTS_DIR="defaults"
CRATES_DIR="wasm"
TARGET_DIR="wasm/target/prebuilt"

# Default options
DEFAULT_RELEASE_FLAG=""
DEFAULT_SHOW_HELP=false

# Build options
RELEASE_FLAG=$DEFAULT_RELEASE_FLAG
SHOW_HELP=$DEFAULT_SHOW_HELP

main() {
    # Parse args
    for arg in "$@"; do
        case $arg in
            "--release")
                RELEASE_FLAG="--release"
                ;;
            "--help")
                SHOW_HELP=true
        esac
    done

    if $SHOW_HELP; then
        print_help
        exit 0
    fi

    # Parse target
    case ${!#} in
        "libs")
            command "libs"
            ;;
        "samples")
            command "samples"
            ;;
        *)
            command "libs"
            command "samples"
            ;;
    esac
}

build() {
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
                cargo metadata --no-deps --manifest-path "$CRATES_DIR/Cargo.toml" --format-version=1 |
                jq '.packages | map(select(.targets[].kind | contains(["cdylib"]))) | map(.manifest_path | split("/")) | map(select(.[-3] == "samples")) | map(.[-2]) | .[]' -r
            ))
    esac

    mkdir -p "$TARGET_DIR/$1"
    for name in ${NAMES[@]}; do
        out_file="$TARGET_DIR/$1/$name.wasm"
        cargo run --bin iroha_wasm_builder -- build "$CRATES_DIR/$1/$name" $RELEASE_FLAG --out-file "$out_file"
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


print_help() {
    cat << END
Usage: build_wasm.sh [OPTIONS] [TARGET]

Options:
  --help           Show help message.
  --release        Enable release and size optimizations for the build.

Targets:
  libs             Specify to build libs.
  samples          Specify to build samples.
                   If omitted, both libraries and samples will be built.
END
}

main "$@"; exit