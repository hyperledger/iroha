#!/usr/bin/env bash
# Exercise the real candidate protocol without a running node or qualification record.
set -euo pipefail

case "${1:-}" in
  --help|-h)
    cat <<'USAGE'
Usage: scripts/test_parliament_ballot_local.sh [--full]

Runs real registration, wallet admission/execution/closure, and independent replay
tests against public fixtures. --full runs the entire typed ballot crate suite.
Uses the parliament-development Cargo target slot and the local-release profile.
This is an in-process protocol test; it does not start or enable a network.
USAGE
    exit 0
    ;;
  ""|--full) ;;
  *) echo "Usage: scripts/test_parliament_ballot_local.sh [--full]" >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  echo "Usage: scripts/test_parliament_ballot_local.sh [--full]" >&2
  exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$repo_root"

tests=(--nocapture --test-threads=1)
if [[ "${1:-}" != --full ]]; then
  tests+=(
    registration::tests::an_honest_registration_verifies_through_the_typed_inputs
    wallet::prepare::tests::a_wallet_ballot_goes_through_admission_execution_corpus_and_closure
    replay::tests::an_honest_interval_verifies_independently
    --exact
  )
fi

echo 'Testing the real candidate proofs and protocol rules with an in-memory board.'
exec scripts/cargo_fast.sh --target-slot parliament-development --jobs 4 \
  --stable-local-metadata -- test --profile local-release \
  -p iroha_parliament_ballot --lib -- "${tests[@]}"
