#!/bin/bash
git clone https://github.com/hyperledger/iroha.git
cd iroha || exit
# specific version of iroha2 to test with
git checkout 55f8ce6b21842a95f63abb1c4c611c305b6beff0
docker-compose -f docker-compose.yml up -d --build --force-recreate
sleep 10
