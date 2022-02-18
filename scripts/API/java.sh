#!/bin/bash

case $1 in
    setup)
        git clone https://github.com/hyperledger/iroha-java.git
        cd iroha-java || exit
        git checkout iroha2-dev # TODO: chagnge this to main after release.
    ;;
    run)
        cd iroha-java || exit
        ./gradlew build
        ;;
    cleanup)
        rm -rf iroha_api_test
        ;;
esac
