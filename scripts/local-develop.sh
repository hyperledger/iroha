#!/usr/bin/env bash

#
# This simple script starts postgres docker container and
# installs environment variables of the caller. Can be safely
# executed as many times as needed (it performs autocleaning).
#
# Usage:
#   source local-develop.sh
# or
#   ./local-develop.sh > env.sh
#   source env.sh
#

function dependency(){
	(command -v $1 > /dev/null || (echo "install $1. exiting..." && return 1))
}

dependency jq     || exit 1
dependency docker || exit 1
dependency grep   || exit 1
dependency sed    || exit 1

pgname=postgrestestimage

# cleanup
docker rm -f $pgname 2>/dev/null 1>&2

# vars
user=postgres
password=mysecretpassword
pgport=5432

# run postgres
pghost=127.0.0.1

pgid=$(docker run -p $pghost:$pgport:$pgport --rm --name $pgname -e POSTGRES_USER=$user -e POSTGRES_PASSSWORD=$password -d postgres:9.5)

# stderr
>&2 echo "postgres: 127.0.0.1:$pgport {login: $user, pwd: $password}"

# print variables (stdout)
cat << EOF
export IROHA_POSTGRES_HOST=$pghost
export IROHA_POSTGRES_PORT=$pgport
export IROHA_POSTGRES_USER=$user
export IROHA_POSTGRES_DATABASE=$user
export IROHA_POSTGRES_PASSWORD=$password
EOF

# apply variables
export IROHA_POSTGRES_HOST=$pghost
export IROHA_POSTGRES_PORT=$pgport
export IROHA_POSTGRES_USER=$user
export IROHA_POSTGRES_DATABASE=$user
export IROHA_POSTGRES_PASSWORD=$password
