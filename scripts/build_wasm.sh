#!/bin/sh
set -e;

DEFAULTS_DIR="defaults"
CARGO_DIR="wasm"
TARGET_DIR="$CARGO_DIR/target/prebuilt"
PROFILE="profiling"
TARGET="all"
SHOW_HELP=false

main() {
    # Parse args
    for arg in "$@"; do
        case $arg in
            --profile=*)
                PROFILE="${arg#*=}"
                ;;
            --help)
                SHOW_HELP=true
                ;;
            --target=*)
                TARGET="${arg#*=}"
                ;;
            *)
                echo "error: unrecognized arg: $arg"
                exit 1
                ;;
        esac
    done

    case $PROFILE in
        "deploy")
            RELEASE_FLAG="--release"
            ;;
        "profiling")
            RELEASE_FLAG=""
            ;;
        *)
            echo "error: unrecognized profile: $PROFILE. Profile can be either [deploy, profiling]"
            exit 1
            ;;
    esac

    if $SHOW_HELP; then
        print_help
        exit 0
    fi

    # Parse target
    case $TARGET in
        "libs")
            command "libs"
            ;;
        "samples")
            command "samples"
            ;;
        "all")
            command "libs"
            command "samples"
            ;;
        *)
            echo "error: unrecognized target: $TARGET. Target can be either [libs, samples, all]"
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
                cargo metadata --no-deps --manifest-path "$CARGO_DIR/Cargo.toml" --format-version=1 |
                jq '.packages | map(select(.targets[].kind | contains(["cdylib"]))) | map(.manifest_path | split("/")) | map(select(.[-3] == "samples")) | map(.[-2]) | .[]' -r
            ))
    esac

    mkdir -p "$TARGET_DIR/$1"
    for name in ${NAMES[@]}; do
        out_file="$TARGET_DIR/$1/$name.wasm"
        cargo run --bin iroha_wasm_builder -- build "$CARGO_DIR/$1/$name" $RELEASE_FLAG --out-file "$out_file"
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
Usage: $0 [OPTIONS]

Options:
  --profile=<value>   Specify build profile (default: profiling)
                      Possible values: profiling, deploy

  --target=<value>    Specify build target (default: all)
                      Possible values: samples, libs, all

  --help              Show help message
END
}

main "$@"; exit