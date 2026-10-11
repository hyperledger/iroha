#!/usr/bin/env bash
set -euo pipefail

# cargo-fuzz 0.13.2 invokes a literal `cargo` child and exposes no generic
# Cargo-argument pass-through. The fuzz driver places this script at the front
# of PATH as `cargo` so the sanitizer build is bound to the lane-local lock
# projection. This utility alone does not authenticate the proxy, lock or compiler.

: "${IROHA_FUZZ_REAL_CARGO:?missing real Cargo path}"
: "${IROHA_FUZZ_NIGHTLY:?missing pinned nightly}"
: "${IROHA_FUZZ_LOCKFILE:?missing external fuzz lockfile}"

case "${1:-}" in
  build|rustc) ;;
  *)
    echo "unsupported cargo-fuzz child command: ${1:-<empty>}" >&2
    exit 2
    ;;
esac

cargo_args=()
rustc_args=()
seen_separator=0
for argument in "$@"; do
  if ((seen_separator)); then
    rustc_args+=("$argument")
  elif [[ "$argument" == "--" ]]; then
    seen_separator=1
  else
    cargo_args+=("$argument")
  fi
done

cargo_args+=(
  -Zunstable-options
  --lockfile-path "$IROHA_FUZZ_LOCKFILE"
  --locked
  --offline
  --jobs 1
)
if ((seen_separator)); then
  cargo_args+=(-- "${rustc_args[@]}")
fi

exec "$IROHA_FUZZ_REAL_CARGO" "+$IROHA_FUZZ_NIGHTLY" "${cargo_args[@]}"
