#!/bin/bash
cd test_docker
sleep 1s && ./iroha_client_cli domain add --name="Wonderland" &
timeout 2s ./iroha_client_cli maintenance connect --entity=transaction --event=created | grep -q 'Change received Created(Transaction('
