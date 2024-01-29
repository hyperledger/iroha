#!/bin/sh
set -e

case $1 in
    "genesis")
        cargo run --release --bin kagami -- genesis --executor-path-in-genesis ./executor.wasm | diff - configs/peer/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --release --bin kagami -- genesis --executor-path-in-genesis ./executor.wasm > configs/peer/genesis.json`'
            exit 1
        };;
    "client")
        cargo run --release --bin kagami -- config client | diff - configs/client/config.json || {
            echo 'Please re-generate client config with `cargo run --release --bin kagami -- config client > configs/client/config.json`'
            exit 1
        };;
    "peer")
        cargo run --release --bin kagami -- config peer | diff - configs/peer/config.json || {
            echo 'Please re-generate peer config with `cargo run --release --bin kagami -- config peer > configs/peer/config.json`'
            exit 1
        };;
    "schema")
        cargo run --release --bin kagami -- schema | diff - docs/source/references/schema.json || {
            echo 'Please re-generate schema with `cargo run --release --bin kagami -- schema > docs/source/references/schema.json`'
            exit 1
        };;
    "docker-compose")
        do_check() {
            cmd_base=$1
            target=$2
            # FIXME: not nice; add an option to `kagami swarm` to print content into stdout?
            #        it is not a default behaviour because Kagami resolves `build` path relative
            #        to the output file location
            temp_file="docker-compose.TMP.yml"
            full_cmd="$cmd_base --outfile $temp_file"

            eval "$full_cmd"
            diff "$temp_file" "$target" || {
                echo "Please re-generate \`$target\` with \`$cmd_base --outfile $target\`"
                exit 1
            }
        }

        command_base_for_single() {
            echo "cargo run --release --bin iroha_swarm -- -p 1 -s Iroha --force --config-dir ./configs/peer --build ."
        }

        command_base_for_multiple_local() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/peer --build ."
        }

        command_base_for_default() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/peer --image hyperledger/iroha2:dev"
        }


        do_check "$(command_base_for_single)" "docker-compose.single.yml"
        do_check "$(command_base_for_multiple_local)" "docker-compose.local.yml"
        do_check "$(command_base_for_default)" "docker-compose.yml"
esac
