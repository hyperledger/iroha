#!/usr/bin/env bash
set -xeuo pipefail

## Expects CWD is iroha repo root
##

while test $# -gt 0 ;do
    case $1 in
        -block_store_path)
            BLOCK_STORE_PATH=$2
            shift
        ;;
        -rocksdb_path)
            ROCKSDB_PATH=$2
            shift
        ;;
        -migration_tool)
            MIGRATION_TOOL=$2
            shift
        ;;
    esac
    shift
done

## Migrate and export blocks back, assert they are same

$MIGRATION_TOOL -block_store_path $BLOCK_STORE_PATH -rocksdb_path $ROCKSDB_PATH

$MIGRATION_TOOL -export_to /tmp/block_store_7000_exported  -rocksdb_path $ROCKSDB_PATH

diff -ur /tmp/block_store_7000_exported $BLOCK_STORE_PATH
