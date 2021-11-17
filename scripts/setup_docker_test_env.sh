#!/bin/bash
mkdir test_docker
cp ./target/debug/iroha_client_cli test_docker
cp ./test_configs/client/config.json test_docker
cp ./test_configs/scripts/metadata.json test_docker
docker-compose up -d --force-recreate
sleep 10
