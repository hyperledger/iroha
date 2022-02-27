#!/bin/bash

JAVA_DIR=${JAVA_DIR:-"iroha-java"}
JAVA_REPO=${JAVA_REPO:-"https://github.com/hyperledger/iroha-java.git"}
JAVA_BRANCH=${JAVA_BRANCH:-"iroha2-dev"}

case $1 in
    setup)
        git clone "$JAVA_REPO"
        cd "$JAVA_DIR" || exit 1
        git checkout "$JAVA_BRANCH" # TODO: change this to main after release.
    ;;
    run)
        cd "$JAVA_DIR" || exit 1
        ./gradlew build
        ;;
    cleanup)
        rm -rf "$JAVA_DIR"
        ;;
esac
