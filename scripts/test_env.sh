#!/usr/bin/env bash

# Un-comment for debugging
set -ex

TEST=${TEST:-"./test"}
HOST=${HOST:-"127.0.0.1"}
IROHA2_CONFIG_PATH="$TEST/peers/config.json"
IROHA2_GENESIS_PATH="$TEST/peers/genesis.json"
IROHA_PEER_COUNT=${IROHA_PEER_COUNT:-"4"}

declare -A public_keys

declare -A private_keys

declare -A p2p_ports
P2P_STARTING_PORT='1337'

declare -A api_ports
API_STARTING_PORT='8080'

declare -A telemetry_ports
TELEMETRY_STARTING_PORT='8180'

declare -A tokio_console_ports
TOKIO_CONSOLE_STARTING_PORT='5555'

function generate_p2p_port {
    P2P_PORT=$(($P2P_STARTING_PORT + $1))
    p2p_ports[$1]=$P2P_PORT
}

function generate_api_port {
    API_PORT=$(($API_STARTING_PORT + $1))
    api_ports[$1]=$API_PORT
}

function generate_telemetry_port {
    TELEMETRY_PORT=$(($TELEMETRY_STARTING_PORT + $1))
    telemetry_ports[$1]=$TELEMETRY_PORT
}

function generate_tokio_console_port {
    TOKIO_CONSOLE_PORT=$(($TOKIO_CONSOLE_STARTING_PORT + $1))
    tokio_console_ports[$1]=$TOKIO_CONSOLE_PORT
}

function generate_peer_key_pair {
    mapfile -t -n 3 buffer < <($TEST/kagami crypto -c)
    public_keys[$1]="${buffer[0]}"
    private_keys[$1]=$(printf '{"digest_function": "%s", "payload": "%s"}' "${buffer[2]}" "${buffer[1]}")
}

function generate_genesis_key_pair {
    mapfile -t -n 3 buffer < <($TEST/kagami crypto -c)
    IROHA_GENESIS_ACCOUNT_PUBLIC_KEY="${buffer[0]}"
    IROHA_GENESIS_ACCOUNT_PRIVATE_KEY=$(printf '{"digest_function": "%s", "payload": "%s"}' "${buffer[2]}" "${buffer[1]}")
}

function trusted_peer_entry {
    # This way it's easier to read when debugging the script
    printf '{"address": "%s", "public_key": "%s"}' "$HOST:${p2p_ports[$1]}" "${public_keys[$1]}"
}

function generate_trusted_peers {
    printf "["
    for iter in $(seq 0 $(($1-2))); do
        trusted_peer_entry "$iter"
       printf ","
    done
    trusted_peer_entry $(($1-1))
    printf "]"
}

function set_up_peers_common {
    PEERS="$TEST/peers"
    mkdir -p "$PEERS"
    cp ./configs/peer/{config.json,genesis.json,validator.wasm} "$PEERS"
    cp ./target/debug/iroha "$PEERS" || {
        # TODO this can fail for other reasons as well.
        echo 'Please build the `iroha` binary, by running:'
        echo '`cargo build --bin iroha`'
        exit 1
    }
}

function bulk_export {
    export KURA_BLOCK_STORE_PATH
    export LOG_FILE_PATH
    export LOG_MAX_LEVEL
    export TORII_P2P_ADDR
    export TORII_API_URL
    export TORII_TELEMETRY_URL
    export IROHA_PUBLIC_KEY
    export IROHA_PRIVATE_KEY
    export SUMERAGI_TRUSTED_PEERS
    export IROHA_GENESIS_ACCOUNT_PUBLIC_KEY
    export IROHA_GENESIS_ACCOUNT_PRIVATE_KEY
    export IROHA2_CONFIG_PATH
    export IROHA2_GENESIS_PATH
    export SUMERAGI_DEBUG_FORCE_SOFT_FORK
    export TOKIO_CONSOLE_ADDR
}

function run_peer () {
    PEER="$TEST/peers/iroha$1"
    mkdir -p "$PEER"
    STORAGE="$PEER/storage"
    mkdir -p "$STORAGE"
    KURA_BLOCK_STORE_PATH="$STORAGE"
    LOG_FILE_PATH="$PEER/log.json"
    LOG_MAX_LEVEL="TRACE"
    TORII_P2P_ADDR="$HOST:${p2p_ports[$1]}"
    TORII_API_URL="$HOST:${api_ports[$1]}"
    TORII_TELEMETRY_URL="$HOST:${telemetry_ports[$1]}"
    IROHA_PUBLIC_KEY="${public_keys[$1]}"
    IROHA_PRIVATE_KEY="${private_keys[$1]}"
    SUMERAGI_DEBUG_FORCE_SOFT_FORK="false"
    TOKIO_CONSOLE_ADDR="$HOST:${tokio_console_ports[$1]}"
    exec -a "iroha$1" "$TEST/peers/iroha" "$2" &> "$PEER/.log" & disown
}

function run_n_peers {
    generate_genesis_key_pair
    for peer in $(seq 0 $(($1-1))); do
       generate_p2p_port $peer
       generate_api_port $peer
       generate_telemetry_port $peer
       generate_peer_key_pair $peer
       generate_tokio_console_port $peer
    done
    SUMERAGI_TRUSTED_PEERS="$(generate_trusted_peers $1)"
    for peer in $(seq 1 $(($1-1))); do
        run_peer $peer
    done
    run_peer 0 --submit-genesis
}

function clean_up_n_peers {
    for peer in $(seq 0 $(($1-1))); do
        pkill "iroha$peer";
    done
}

declare -i N_PEERS
if [ -z "$2" ]; then
    echo "Number of peers is not provided, using default value of $IROHA_PEER_COUNT"
    N_PEERS="$IROHA_PEER_COUNT"
else
    N_PEERS="$2"
fi

if [ "$N_PEERS" -le 0 ]; then
    echo "Expected number of peers as non-zero positive number (> 0)."
    exit 1
fi

case $1 in
    setup)
        echo "Starting iroha network with $N_PEERS peers"

        ## Set client up to communicate with the first peer.
        mkdir "$TEST" || echo "$TEST Already exists"
        cp ./target/debug/iroha_client_cli "$TEST" || {
            echo 'Please build `iroha_client_cli` by running'
            echo '`cargo build --bin iroha_client_cli`'
            exit
        }
        echo '{"comment":{"String": "Hello Meta!"}}' >"$TEST/metadata.json"
        cp ./configs/client/config.json "$TEST"
        cp ./target/debug/kagami "$TEST" || {
            echo 'Please build `kagami` by running'
            echo '`cargo build --bin kagami`'
            exit
        }

        set_up_peers_common
        bulk_export
        run_n_peers "$N_PEERS"
        ;;
    cleanup)
        # NOTE: It's not desirable for cleanup script to exit on the first failed command
        # because we're left with lingering peers processes that we have to manually kill
        set +e

        clean_up_n_peers N_PEERS
        rm -rf "$TEST"
        ;;

    *)
        echo 'Specify either `setup` or `cleanup`'
        exit 1
esac
