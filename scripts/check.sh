#!/bin/sh
set -e

TMPFILE=$(mktemp)

case $1 in
    "docs")
        cargo run --bin kagami -- docs >"$TMPFILE"
        diff "$TMPFILE" docs/source/references/config.md || {
            echo 'Please re-generate docs using `cargo run --bin kagami -- docs`'
            exit 1
        };;
    "genesis")
        cargo run --bin kagami -- genesis >"$TMPFILE"
        diff "$TMPFILE" configs/peer/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --bin kagami -- genesis`'
            exit 1
        };;
esac
