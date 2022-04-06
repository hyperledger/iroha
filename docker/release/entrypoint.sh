#!/usr/bin/env bash
set -e

# if first arg looks like a flag, assume we want to run irohad server
if [ "${1:0:1}" = '-' ]; then
  set -- irohad "$@"
fi

if [ "$1" = 'irohad' ]; then
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
	exec "$@" --genesis_block genesis.block --config config.docker --keypair_name $KEY
fi

exec "$@"
