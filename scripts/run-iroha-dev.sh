#!/usr/bin/env bash

function next_free_port {
for port in $(seq $1 $2);
    do echo -ne "\035" | nc 127.0.0.1 $port > /dev/null 2>&1; [ $? -eq 1 ] && echo "$port" && break;
done
}

CURDIR="$(cd "$(dirname "$0")"; pwd)"
IROHA_HOME="$(dirname "${CURDIR}")"
PROJECT=iroha${UID}
COMPOSE=${IROHA_HOME}/docker/docker-compose.yml

export G_ID=$(id -g)
export U_ID=$(id -u)
export COMPOSE_PROJECT_NAME=${PROJECT}

if [ $(docker ps -q -f name=${PROJECT}_node_1 | wc -c) -eq 0 ];
then
    export IROHA_PORT="$(next_free_port 50051 50101)"
    export IROHA_TLS_PORT="$(next_free_port 55552 55601)"
    export DEBUGGER_PORT="$(next_free_port 20000 20100)"

    docker-compose -f ${COMPOSE} up -d
else
    IROHA_DBG_PORTS="$(docker port ${PROJECT}_node_1 | sed 's/\(.*\)://' | sort -r | paste -s -d ':' -)"
    export IROHA_TLS_PORT="$(echo ${IROHA_DBG_PORTS} | sed 's/:.*//')"
    export IROHA_PORT="$(echo ${IROHA_DBG_PORTS} | sed 's/.*:\(.*\):.*/\1/')"
    export DEBUGGER_PORT="$(echo ${IROHA_DBG_PORTS} | sed 's/.*://')"
fi
echo ""
echo "Iroha is mapped to host port ${IROHA_PORT}"
echo "Iroha TLS is mapped to host port ${IROHA_TLS_PORT}"
echo "Debugger is mapped to host port ${DEBUGGER_PORT}"
echo ""
docker-compose -f ${COMPOSE} exec node /bin/bash
