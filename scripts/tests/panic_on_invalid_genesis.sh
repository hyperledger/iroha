#!/bin/bash
set -ex
# Setup env
# FIXME: these are obsolete
export TORII_P2P_ADDR='127.0.0.1:1341'
export TORII_API_URL='127.0.0.1:8084'
export IROHA_PUBLIC_KEY='ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B'
export IROHA_PRIVATE_KEY='{"digest_function": "ed25519", "payload": "282ED9F3CF92811C3818DBC4AE594ED59DC1A2F78E4241E31924E101D6B1FB831C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B"}'
export IROHA_GENESIS_ACCOUNT_PUBLIC_KEY='ed01203F4E3E98571B55514EDC5CCF7E53CA7509D89B2868E62921180A6F57C2F4E255'
export IROHA_GENESIS_ACCOUNT_PRIVATE_KEY="{ \"digest_function\": \"ed25519\", \"payload\": \"038AE16B219DA35AA036335ED0A43C28A2CC737150112C78A7B8034B9D99C9023F4E3E98571B55514EDC5CCF7E53CA7509D89B2868E62921180A6F57C2F4E255\" }"
export IROHA2_CONFIG_PATH="configs/peer/config.json"
export SUMERAGI_TRUSTED_PEERS='[{"address":"127.0.0.1:1341", "public_key": "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B"}]'
# Create tmp file for genesis
export IROHA2_GENESIS_PATH="$(mktemp).json"
# Create tmp folder for block storage
export KURA_BLOCK_STORE_PATH="$(mktemp -d)"
# Remove on exit
trap 'rm -rf -- "$IROHA2_GENESIS_PATH" "$KURA_BLOCK_STORE_PATH"' EXIT

# Create invalid genesis
# NewAssetDefinition replaced with AssetDefinition
sed 's/NewAssetDefinition/AssetDefinition/' ./configs/swarm/genesis.json > $IROHA2_GENESIS_PATH

timeout 1m target/debug/iroha --submit-genesis 2>&1 | tee /dev/stderr | grep -q 'Transaction validation failed in genesis block'
