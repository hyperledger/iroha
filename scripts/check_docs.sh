#!/bin/sh
set -ex
TMPFILE=$(mktemp)
cargo run --bin iroha_docs >$TMPFILE
diff $TMPFILE docs/source/references/config.md || {
    echo "Please regenerate docs with git hook in ./hooks directory"
    exit 1
}
