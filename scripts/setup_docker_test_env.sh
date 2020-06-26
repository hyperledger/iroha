#!/bin/bash
mkdir test_docker
cp ./target/debug/iroha_client_cli test_docker
cp ./iroha_client/config.json test_docker
docker-compose up -d --build --force-recreate
sleep 10
