#!/bin/sh
# This script is intended for release updates,
# when LTS and Stable branch configurations may change.
# It downloads the previous configurations from raw.githubusercontent.com.
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/config.json -O "$(dirname "${BASH_SOURCE[0]}")/legacy_stable/config.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-stable/configs/peer/genesis.json -O "$(dirname "${BASH_SOURCE[0]}")/legacy_stable/genesis.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-lts/configs/peer/config.json -O "$(dirname "${BASH_SOURCE[0]}")/legacy_lts/config.json"
wget https://raw.githubusercontent.com/hyperledger/iroha/iroha2-lts/configs/peer/genesis.json -O "$(dirname "${BASH_SOURCE[0]}")/legacy_lts/genesis.json"
