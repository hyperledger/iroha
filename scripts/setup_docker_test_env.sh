#!/bin/bash
mkdir test_docker
cp ./target/debug/iroha_client_cli test_docker
echo '{"comment":{"String": "Hello Meta!"}}' >test_docker/metadata.json
cp ./configs/client_cli/config.json test_docker
docker-compose up -d --force-recreate
sleep 10
