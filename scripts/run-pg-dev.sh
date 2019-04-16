#!/usr/bin/env bash

PG_CONTAINER_NAME="postgres"
PG_IMAGE_NAME="postgres:9.5"
PG_CONTAINER_DATA="/var/lib/postgresql/data"
PG_USER="iroha"
PG_PASS="mysecretpassword"
PG_PORT="5432"

G_ID=$(id -g)
U_ID=$(id -u)

mkdir -p ${PG_CONTAINER_DATA}
docker run -dt --user "${U_ID}:${G_ID}" \
        --name ${PG_CONTAINER_NAME} \
        -p 127.0.0.1:${PG_PORT}:${PG_PORT} \
        -v ${PG_CONTAINER_DATA} \
        -e POSTGRES_USER=${PG_USER} -e POSTGRES_PASSWORD=${PG_PASS} \
        ${PG_IMAGE_NAME}

echo "postgres is now available at 127.0.0.1:${PG_PORT}"
