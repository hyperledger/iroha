#!/usr/bin/env bash

CURDIR="$(cd "$(dirname "$0")"; pwd)"
IROHA_HOME="$(dirname "${CURDIR}")"
PROJECT=iroha${UID}
COMPOSE=${IROHA_HOME}/docker/docker-compose.yml

# actual values of are not needed here, but variables need to be defined
export IROHA_PORT=1
export DEBUGGER_PORT=2
export IROHA_TLS_PORT=3

docker-compose -f ${COMPOSE} -p ${PROJECT} down
