#!/bin/sh
# This script is intended for release updates, when LTS and Stable branch configurations may change.
#
# # Example
#
# You run it like:
# `./update_configs.sh lts`
# or:
# `./update_configs.sh stable`

MSG="Use './update_configs.sh lts' or './update_configs.sh stable'"

if [ -z "$1" ]; then
    echo $MSG && exit 1
fi
if [ "$1" != "stable" ] && [ "$1" != "lts" ]; then
    echo $MSG && exit 1
fi

curl https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/config.json -o ./configs/client/$1/config.json
curl https://raw.githubusercontent.com/hyperledger/iroha/iroha2-lts/configs/peer/config.json -o ./configs/client/$1/config.json

curl https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/config.json -o ./configs/peer/$1/config.json
curl https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/genesis.json -o ./configs/peer/$1/genesis.json
curl https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/genesis.json -o ./configs/peer/$1/executor.wasm
