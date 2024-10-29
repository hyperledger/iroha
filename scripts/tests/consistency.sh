#!/bin/sh
set -e

case $1 in
    "genesis")
        cargo run --release --bin kagami -- genesis generate --executor executor.wasm --wasm-dir libs --genesis-public-key ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4 | diff - defaults/genesis.json || {
            echo 'Please re-generate the default genesis with `cargo run --release --bin kagami -- genesis --executor executor.wasm --wasm-dir libs --genesis-public-key ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4 > ./defaults/genesis.json`'
            echo 'The assumption here is that the authority of the default genesis transaction is `iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID`'
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
            full_cmd="$cmd_base --out-file $target --print"
            diff <(eval "$full_cmd") "$target" || {
                echo "Please re-generate \`$target\` with \`$cmd_base --out-file $target\`"
                exit 1
            }
        }

        command_base_for_single() {
            echo "cargo run --release --bin iroha_swarm -- -p 1 -s Iroha -H -c ./defaults -i hyperledger/iroha:local -b ."
        }

        command_base_for_multiple_local() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha -H -c ./defaults -i hyperledger/iroha:local -b ."
        }

        command_base_for_default() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha -H -c ./defaults -i hyperledger/iroha:dev"
        }


        do_check "$(command_base_for_single)" "defaults/docker-compose.single.yml"
        do_check "$(command_base_for_multiple_local)" "defaults/docker-compose.local.yml"
        do_check "$(command_base_for_default)" "defaults/docker-compose.yml"
esac
