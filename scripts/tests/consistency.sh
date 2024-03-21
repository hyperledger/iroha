#!/bin/sh
set -e

case $1 in
    "genesis")
        cargo run --release --bin kagami -- genesis --executor-path-in-genesis ./executor.wasm --genesis-public-key ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4 | diff - configs/swarm/genesis.json || {
            echo 'Please re-generate the default genesis with `cargo run --release --bin kagami -- genesis --executor-path-in-genesis ./executor.wasm --genesis-public-key ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4 > ./configs/swarm/genesis.json`'
            echo 'The assumption here is that the authority of the default genesis transaction is `test_samples::SAMPLE_GENESIS_ACCOUNT_ID`'
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
            temp_file="configs/swarm/docker-compose.TMP.yml"
            full_cmd="$cmd_base --outfile $temp_file"

            eval "$full_cmd"
            diff "$temp_file" "$target" || {
                echo "Please re-generate \`$target\` with \`$cmd_base --outfile $target\`"
                exit 1
            }
        }

        command_base_for_single() {
            echo "cargo run --release --bin iroha_swarm -- -p 1 -s Iroha --force --config-dir ./configs/swarm --health-check --build ."
        }

        command_base_for_multiple_local() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/swarm --health-check --build ."
        }

        command_base_for_default() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/swarm --health-check --image hyperledger/iroha2:dev"
        }


        do_check "$(command_base_for_single)" "configs/swarm/docker-compose.single.yml"
        do_check "$(command_base_for_multiple_local)" "configs/swarm/docker-compose.local.yml"
        do_check "$(command_base_for_default)" "configs/swarm/docker-compose.yml"
esac
