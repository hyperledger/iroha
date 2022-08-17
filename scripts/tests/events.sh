#!/bin/bash
set -ex
TEST=${TEST:-"./test"}
CMD="$TEST/iroha_client_cli --config $TEST/config.json"
$CMD events pipeline
# $CMD domain register --id="Soramitsu" --metadata="$TEST/metadata.json"
