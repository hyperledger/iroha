#!/usr/bin/env bash

echo key=$KEY
echo $PWD
if [ -n "$IROHA_POSTGRES_HOST" ]; then
  echo "NOTE: IROHA_POSTGRES_HOST should match 'host' option in config file"
  PG_PORT=${IROHA_POSTGRES_PORT:-5432}
  /wait-for-it.sh -h $IROHA_POSTGRES_HOST -p $PG_PORT -t 30 -- true
else
  echo "WARNING: IROHA_POSTGRES_HOST is not defined.
    Do not wait for Postgres to become ready. Iroha may fail to start up"
fi
irohad --genesis_block genesis.block --config config.docker --keypair_name $KEY
