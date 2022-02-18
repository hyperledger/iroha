#!/bin/bash
set -ex
TEST=${TEST:-"./test"}
CMD="$TEST/iroha_client_cli --config $TEST/config.json"
$CMD domain register --id="Soramitsu" --metadata="$TEST/metadata.json"
sleep 2
$CMD account register --id="Alice@Soramitsu" --key="ed0120a753146e75b910ae5e2994dc8adea9e7d87e5d53024cfa310ce992f17106f92c"
sleep 2
$CMD asset register --id="XOR#Soramitsu" --value-type=Quantity
sleep 2
$CMD asset mint --account="Alice@Soramitsu" --asset="XOR#Soramitsu" --quantity="100"
sleep 2
$CMD asset get --account="Alice@Soramitsu" --asset="XOR#Soramitsu" | grep -q 'Quantity(100)'
