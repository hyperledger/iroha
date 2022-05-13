#!/bin/bash

# Un-comment for debugging
set -ex

TEST=${TEST:-"./test"}
HOST=${HOST:-"127.0.0.1"}
IROHA2_CONFIG_PATH="$TEST/peers/config.json"
IROHA2_GENESIS_PATH="$TEST/peers/genesis.json"

# TODO: don't hard-code these, instead, generate them.
declare -A public_keys
public_keys[iroha0]='ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b'
public_keys[iroha1]='ed0120cc25624d62896d3a0bfd8940f928dc2abf27cc57cefeb442aa96d9081aae58a1'
public_keys[iroha2]='ed0120faca9e8aa83225cb4d16d67f27dd4f93fc30ffa11adc1f5c88fd5495ecc91020'
public_keys[iroha3]='ed01208e351a70b6a603ed285d666b8d689b680865913ba03ce29fb7d13a166c4e7f1f'

declare -A private_keys
private_keys[iroha0]='282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b'
private_keys[iroha1]='3bac34cda9e3763fa069c1198312d1ec73b53023b8180c822ac355435edc4a24cc25624d62896d3a0bfd8940f928dc2abf27cc57cefeb442aa96d9081aae58a1'
private_keys[iroha2]='1261a436d36779223d7d6cf20e8b644510e488e6a50bafd77a7485264d27197dfaca9e8aa83225cb4d16d67f27dd4f93fc30ffa11adc1f5c88fd5495ecc91020'
private_keys[iroha3]='a70dab95c7482eb9f159111b65947e482108cfe67df877bd8d3b9441a781c7c98e351a70b6a603ed285d666b8d689b680865913ba03ce29fb7d13a166c4e7f1f'

declare -A p2p_ports
p2p_ports[iroha0]='1337'
p2p_ports[iroha1]='1338'
p2p_ports[iroha2]='1339'
p2p_ports[iroha3]='1340'

declare -A api_ports
api_ports[iroha0]='8080'
api_ports[iroha1]='8081'
api_ports[iroha2]='8082'
api_ports[iroha3]='8083'

declare -A telemetry_ports
telemetry_ports[iroha0]='8180'
telemetry_ports[iroha1]='8181'
telemetry_ports[iroha2]='8182'
telemetry_ports[iroha3]='8183'

function trusted_peer_entry {
    # This way it's easier to read when debugging the script
    echo "{"
    echo "\"address\": \"$HOST:${p2p_ports[$1]}\","
    echo -n "\"public_key\": \"${public_keys[$1]}\""
    echo -n "}"
}

function generate_trusted_peers {
    echo -n "["
    for iter in {0..2}
    do
        trusted_peer_entry "iroha$iter"
        echo -n ","
    done
    trusted_peer_entry iroha3
    echo "]"
}

SUMERAGI_TRUSTED_PEERS="$(generate_trusted_peers)"

function set_up_peers_common {
    PEERS="$TEST/peers"
    mkdir -p "$PEERS"
    cp ./configs/peer/{config.json,genesis.json} "$PEERS"
    cp ./target/debug/iroha "$PEERS" || {
        # TODO this can fail for other reasons as well.
        echo 'Please build the `iroha` binary, by running:'
        echo '`cargo build --bin iroha`'
        exit 1
    }
}

function bulk_export {
    export TORII_P2P_ADDR
    export TORII_API_URL
    export TORII_TELEMETRY_URL
    export IROHA_PUBLIC_KEY
    export IROHA_PRIVATE_KEY
    export SUMERAGI_TRUSTED_PEERS
    export IROHA2_CONFIG_PATH
    export IROHA2_GENESIS_PATH
}

function run_peer () {
    TORII_P2P_ADDR="$HOST:${p2p_ports[$1]}"
    TORII_API_URL="$HOST:${api_ports[$1]}"
    TORII_TELEMETRY_URL="$HOST:${telemetry_ports[$1]}"
    IROHA_PUBLIC_KEY=${public_keys[$1]}
    IROHA_PRIVATE_KEY="{ \"digest_function\": \"ed25519\", \"payload\": \"${private_keys[$1]}\" }"
    exec -a "$1" "$TEST/peers/iroha" "$2" > "$TEST/peers/$1.log" & disown
}

function run_4_peers {
    run_peer iroha1
    run_peer iroha2
    run_peer iroha3
    run_peer iroha0 --submit-genesis
}

function clean_up_peers {
    # Note: We want an exact match, hence '^' in the beginning and '$'
    # at the end.  If any of the peers has stopped working we want to
    # signal a failure, but kill all the remaining peers.
    pkill '^iroha'
}

case $1 in

    setup)
        ## Set client up to communicate with the first peer.
        mkdir "$TEST" || echo "$TEST Already exists"
        cp ./target/debug/iroha_client_cli "$TEST" || {
            echo 'Please build `iroha_client_cli` by running'
            echo '`cargo build --bin iroha_client_cli`'
            exit
        }
        echo '{"comment":{"String": "Hello Meta!"}}' >"$TEST/metadata.json"
        cp ./configs/client_cli/config.json "$TEST"
        case $2 in
            docker)
                docker-compose up;;
            *)
                set_up_peers_common
                bulk_export
                run_4_peers
        esac
        ;;

    cleanup)
        case $2 in
            docker)
                docker-compose rm -s -f;;
            *)
                clean_up_peers
        esac
        rm "$TEST" -r -f
        ;;

    *)
        echo 'Specify either `setup` or `cleanup`'
        exit 1
esac
