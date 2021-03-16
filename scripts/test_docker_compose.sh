#!/bin/bash
set -ex
cd test_docker
./iroha_client_cli domain add --name="Soramitsu"
sleep 2
./iroha_client_cli account register --name="Alice" --domain="Soramitsu" --key="[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]"
sleep 2
./iroha_client_cli asset register --name="XOR" --domain="Soramitsu"
sleep 2
./iroha_client_cli asset mint --account_id="Alice@Soramitsu" --id="XOR#Soramitsu" --quantity="100"
sleep 2
./iroha_client_cli asset get --account_id="Alice@Soramitsu" --id="XOR#Soramitsu" | grep -q 'Quantity(100)'
