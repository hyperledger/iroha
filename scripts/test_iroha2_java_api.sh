#!/bin/bash
mkdir iroha_api_test
cd iroha_api_test || exit
git clone https://github.com/hyperledger/iroha-java.git
cd iroha-java || exit
git checkout iroha2-java
./gradlew build
