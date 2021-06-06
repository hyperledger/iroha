#!/bin/bash
set -ex
cd test_docker
./iroha_client_cli domain register --id="Soramitsu" --metadata="metadata.json"
sleep 2
./iroha_client_cli account register --id="Alice@Soramitsu" --key="ed0120a753146e75b910ae5e2994dc8adea9e7d87e5d53024cfa310ce992f17106f92c"
sleep 2
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
sleep 2
./iroha_client_cli asset mint --account="Alice@Soramitsu" --asset="XOR#Soramitsu" --quantity="100"
sleep 2
./iroha_client_cli asset get --account="Alice@Soramitsu" --asset="XOR#Soramitsu" | grep -q 'Quantity(100)'
