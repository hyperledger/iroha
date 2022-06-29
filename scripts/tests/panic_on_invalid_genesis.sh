#!/bin/bash
set -ex
# Setup env
export TORII_P2P_ADDR='127.0.0.1:1341'
export TORII_API_URL='127.0.0.1:8084'
export TORII_TELEMETRY_URL='127.0.0.1:8184'
export IROHA_PUBLIC_KEY='ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b'
export IROHA_PRIVATE_KEY='{"digest_function": "ed25519", "payload": "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"}'
export IROHA2_CONFIG_PATH="configs/peer/config.json"
export SUMERAGI_TRUSTED_PEERS='[{"address":"127.0.0.1:1341", "public_key": "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"}]'
# Create tmp file for genesis
export IROHA2_GENESIS_PATH="$(mktemp)" 
# Remove on exit
trap 'rm -- "$IROHA2_GENESIS_PATH"' EXIT

# Create invalid genesis
# NewAssetDefinition replaced with AssetDefinition
cat > $IROHA2_GENESIS_PATH <<- EOF
{
  "transactions": [
    {
      "isi": [
        {
          "Register": {
            "object": {
              "Raw": {
                "Identifiable": {
                  "NewDomain": {
                    "id": {
                      "name": "wonderland"
                    },
                    "logo": null,
                    "metadata": {}
                  }
                }
              }
            }
          }
        },
        {
          "Register": {
            "object": {
              "Raw": {
                "Identifiable": {
                  "NewAccount": {
                    "id": {
                      "name": "alice",
                      "domain_id": {
                        "name": "wonderland"
                      }
                    },
                    "signatories": [
                      "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"
                    ],
                    "metadata": {}
                  }
                }
              }
            }
          }
        },
        {
          "Register": {
            "object": {
              "Raw": {
                "Identifiable": {
                  "AssetDefinition": {
                    "id": {
                      "name": "rose",
                      "domain_id": {
                        "name": "wonderland"
                      }
                    },
                    "value_type": "Quantity",
                    "mintable": "Infinitely",
                    "metadata": {}
                  }
                }
              }
            }
          }
        },
        {
          "Mint": {
            "object": {
              "Raw": {
                "U32": 13
              }
            },
            "destination_id": {
              "Raw": {
                "Id": {
                  "AssetId": {
                    "definition_id": {
                      "name": "rose",
                      "domain_id": {
                        "name": "wonderland"
                      }
                    },
                    "account_id": {
                      "name": "alice",
                      "domain_id": {
                        "name": "wonderland"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }
  ]
}
EOF

timeout 1m target/debug/iroha --submit-genesis 2>&1 | tee /dev/stderr | grep -q 'Transaction validation failed in genesis block'
