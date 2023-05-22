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

wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/config.json -O "$(dirname "${BASH_SOURCE[0]}")/client_cli/$1/config.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-lts/configs/peer/config.json -O "$(dirname "${BASH_SOURCE[0]}")/client_cli/$1/config.json"

wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/config.json -O "$(dirname "${BASH_SOURCE[0]}")/peer/$1/config.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/genesis.json -O "$(dirname "${BASH_SOURCE[0]}")/peer/$1/genesis.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/genesis.json -O "$(dirname "${BASH_SOURCE[0]}")/peer/$1/validator.wasm"
