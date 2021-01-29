#!/bin/bash
git clone https://github.com/hyperledger/iroha.git
cd iroha || exit
# specific version of iroha2 to test with
git checkout 1a2bf8e621153497631a805fdea4d9255397c128
docker-compose -f docker-compose-single.yml up -d --build --force-recreate
sleep 10
