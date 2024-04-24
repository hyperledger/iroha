#!/bin/sh
set -e

case $1 in
    "genesis")
        cargo run --release --bin kagami -- genesis generate --executor-path-in-genesis ./executor.wasm | diff - configs/swarm/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --release --bin kagami -- genesis --executor-path-in-genesis ./executor.wasm > configs/swarm/genesis.json`'
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
            full_cmd="$cmd_base --out-file $temp_file"

            eval "$full_cmd"
            diff "$temp_file" "$target" || {
                echo "Please re-generate \`$target\` with \`$cmd_base --out-file $target\`"
                exit 1
            }
        }

        genesis_keypair="--key-pair '{\"public_key\": \"ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB\",\"private_key\": {\"algorithm\": \"ed25519\",\"payload\": \"8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb\"}}'"
        genesis_signature="--signature 9030303030303030302d303030302d303030302d303030302d3030303030303030303030308c4b28660000000000811b2c0400808ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb0101819b61a8c82fc6565c5acc7f92ca6dc07ccd39fcc47dee3d6f85d59ec7b52fe651b20b985b401546b49a50057b4311beaccb822b8ef2cf4e25ce3fab3769c70e"

        command_base_for_single() {
            echo "cargo run --release --bin iroha_swarm -- -p 1 -s Iroha --force --config-dir ./configs/swarm --health-check --build . $genesis_keypair $genesis_signature"
        }

        command_base_for_multiple_local() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/swarm --health-check --build . $genesis_keypair $genesis_signature"
        }

        command_base_for_default() {
            echo "cargo run --release --bin iroha_swarm -- -p 4 -s Iroha --force --config-dir ./configs/swarm --health-check --image hyperledger/iroha2:dev $genesis_keypair $genesis_signature"
        }


        do_check "$(command_base_for_single)" "configs/swarm/docker-compose.single.yml"
        do_check "$(command_base_for_multiple_local)" "configs/swarm/docker-compose.local.yml"
        do_check "$(command_base_for_default)" "configs/swarm/docker-compose.yml"
esac
