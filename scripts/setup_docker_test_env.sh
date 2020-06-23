#!/bin/bash
mkdir test_docker
cp ./target/debug/iroha_client_cli test_docker
cp ./iroha/config.json test_docker
docker-compose up -d
sleep 10
