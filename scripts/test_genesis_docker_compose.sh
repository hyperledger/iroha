#!/bin/bash
cd test_docker || exit
./iroha_client_cli asset get --account_id alice@wonderland --id rose#wonderland | grep -q 'quantity: 13'
