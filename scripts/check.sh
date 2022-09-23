#!/bin/sh
set -e

TMPFILE=$(mktemp)

case $1 in
    "docs")
        cargo run --bin kagami -- docs >"$TMPFILE"
        diff "$TMPFILE" docs/source/references/config.md || {
            echo 'Please re-generate docs using `cargo run --bin kagami -- docs > docs/source/references/config.md`'
            exit 1
        };;
    "genesis")
        cargo run --bin kagami -- genesis >"$TMPFILE"
        diff "$TMPFILE" configs/peer/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --bin kagami -- genesis > configs/peer/genesis.json`'
            exit 1
        };;
    "client")
        cargo run --bin kagami -- client >"$TMPFILE"
        diff "$TMPFILE" configs/client_cli/config.json || {
            echo 'Please re-generate client config with `cargo run --bin kagami -- client > configs/client_cli/config.json`'
            exit 1
        };;
    "schema")
        cargo run --bin kagami -- schema >"$TMPFILE"
        diff "$TMPFILE" docs/source/references/schema.json || {
            echo 'Please re-generate schema with `cargo run --bin kagami -- schema > docs/source/references/schema.json`'
            exit 1
        };;
esac
