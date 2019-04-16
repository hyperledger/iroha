#!/usr/bin/env bash

PG_CONTAINER_NAME="postgres"
PG_CONTAINER_DATA="/var/lib/postgresql/data"
PG_PORT="5432"

docker stop ${PG_CONTAINER_NAME}; docker rm ${PG_CONTAINER_NAME}
rm -rf ${PG_CONTAINER_DATA}

echo "postgres container is successfully stopped and removed from your OS"
