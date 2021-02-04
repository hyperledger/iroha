#!/bin/bash
mkdir iroha_api_test
cd iroha_api_test || exit
git clone https://github.com/hyperledger/iroha.git
cd iroha || exit
git checkout iroha2-java
./gradlew build
