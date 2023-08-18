#!/bin/bash
set -ex
TEST=${TEST:-"./test"}
CMD="$TEST/iroha_client_cli --config $TEST/config.json"
$CMD domain register --id="Soramitsu" --metadata="$TEST/metadata.json"
sleep 2
$CMD account register --id="Alice@Soramitsu" --key="ed0120A753146E75B910AE5E2994DC8ADEA9E7D87E5D53024CFA310CE992F17106F92C"
sleep 2
$CMD asset register --id="XOR#Soramitsu" --value-type=Quantity
sleep 2
$CMD asset mint --account="Alice@Soramitsu" --asset="XOR#Soramitsu" --quantity="100"
sleep 2
$CMD asset get --account="Alice@Soramitsu" --asset="XOR#Soramitsu" | grep -q '"Quantity": 100'
