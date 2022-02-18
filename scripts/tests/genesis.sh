#!/bin/bash
set -ex
TEST=${TEST:-"./test"}
CMD="$TEST/iroha_client_cli --config $TEST/config.json"
$CMD asset get --account alice@wonderland --asset 'rose#wonderland'  | grep -q 'Quantity(13)'
sleep ${SLEEP:-10}
