#!/usr/bin/env bash

CURDIR="$(cd "$(dirname "$0")"; pwd)"
IROHA_HOME="$(dirname "${CURDIR}")"

export COMPOSE_FILE=${IROHA_HOME}/docker/docker-compose-swarm.yml

i=0
while read -r node
do
    eval $(docker-machine env ${node})
    export COMPOSE_PROJECT_NAME=iroha${i}

    # remove services
    docker-compose down

    ((i++))
done < <(docker-machine ls -f "{{.Name}}")

# remove overlay network
eval $(docker-machine env $(docker-machine ls -f "{{.Name}}" | head -1))
docker network rm iroha_network
