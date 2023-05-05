#!/bin/sh
set -e

case $1 in
    "docs")
        cargo run --release --bin kagami -- docs | diff - docs/source/references/config.md || {
            echo 'Please re-generate docs using `cargo run --release --bin kagami -- docs > docs/source/references/config.md`'
            exit 1
        };;
    "genesis")
        cargo run --release --bin kagami -- genesis --compiled-validator-path ./validator.wasm | diff - configs/peer/genesis.json || {
            echo 'Please re-generate the genesis with `cargo run --release --bin kagami -- genesis > configs/peer/genesis.json`'
            exit 1
        };;
    "client")
        cargo run --release --bin kagami -- config client | diff - configs/client/config.json || {
            echo 'Please re-generate client config with `cargo run --release --bin kagami -- config client > configs/client/config.json`'
            exit 1
        };;
    "peer")
        cargo run --release --bin kagami -- config peer | diff - configs/peer/config.json || {
            echo 'Please re-generate peer config with `cargo run --release --bin kagami -- config peer > configs/peer/config.json`'
            exit 1
        };;
    "schema")
        cargo run --release --bin kagami -- schema | diff - docs/source/references/schema.json || {
            echo 'Please re-generate schema with `cargo run --release --bin kagami -- schema > docs/source/references/schema.json`'
            exit 1
        };;
esac
