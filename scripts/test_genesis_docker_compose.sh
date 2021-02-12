#!/bin/bash
set -ex
cd test_docker
./iroha_client_cli asset get --account_id alice@wonderland --id rose#wonderland | grep -q 'quantity: 13'
