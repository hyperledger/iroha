#!/bin/sh
set -e

TMPFILE=$(mktemp)

case $1 in
    "docs")
        cargo run --bin iroha_gen -- --docs >"$TMPFILE"
        diff "$TMPFILE" docs/source/references/config.md || {
            echo 'Please re-generate docs with git hook in ./hooks directory'
            exit 1
        };;
    "genesis")
        cargo run --bin iroha_gen -- --genesis >"$TMPFILE"
        diff "$TMPFILE" configs/peer/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --bin iroha_gen -- --genesis`'
            exit 1
        };;
esac
