#!/bin/bash
set -ex
# Setup env
export TORII_P2P_ADDR='127.0.0.1:1341'
export TORII_API_URL='127.0.0.1:8084'
export TORII_TELEMETRY_URL='127.0.0.1:8184'
export IROHA_PUBLIC_KEY='ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b'
export IROHA_PRIVATE_KEY='{"digest_function": "ed25519", "payload": "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"}'
export IROHA_GENESIS_ACCOUNT_PUBLIC_KEY='ed01203f4e3e98571b55514edc5ccf7e53ca7509d89b2868e62921180a6f57c2f4e255'
export IROHA_GENESIS_ACCOUNT_PRIVATE_KEY="{ \"digest_function\": \"ed25519\", \"payload\": \"038ae16b219da35aa036335ed0a43c28a2cc737150112c78a7b8034b9d99c9023f4e3e98571b55514edc5ccf7e53ca7509d89b2868e62921180a6f57c2f4e255\" }"
export IROHA2_CONFIG_PATH="configs/peer/config.json"
export SUMERAGI_TRUSTED_PEERS='[{"address":"127.0.0.1:1341", "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"}]'
# Create tmp file for genesis
export IROHA2_GENESIS_PATH="$(mktemp)"
# Create tmp folder for block storage
export KURA_BLOCK_STORE_PATH="$(mktemp -d)" 
# Remove on exit
trap 'rm -rf -- "$IROHA2_GENESIS_PATH" "$KURA_BLOCK_STORE_PATH"' EXIT

# Create invalid genesis
# NewAssetDefinition replaced with AssetDefinition
sed 's/NewAssetDefinition/AssetDefinition/' ./configs/peer/genesis.json > $IROHA2_GENESIS_PATH

timeout 1m target/debug/iroha --submit-genesis 2>&1 | tee /dev/stderr | grep -q 'Transaction validation failed in genesis block'
