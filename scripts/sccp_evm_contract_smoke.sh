#!/usr/bin/env bash
# SCCP v1 EVM contract smoke (`specs/sccp.md` §5.2, §5.4, §5.5, §11).
#
# Builds `contracts/evm/sccp/SccpTairaXor.sol` and its one library,
# `contracts/evm/sccp/lib/BLS12_381.sol`, with the pinned native solc 0.8.31
# through `scripts/contract_artifact_corridor.py`, and proves that a mutated
# manifest, a stale contract or library source and a mutated compiler are
# refused. It then installs and audits the locked EDR runtime in a private
# copy, runs the provider test, and runs the four EDR suites (BLS library,
# fixture replay, behaviour, gas) against the locked build. Every suite runs
# under both the Prague and the Osaka rules and, where a row binds a network,
# under chain ids 1 and 56. The gas suite compares every §5.4 row with
# `contracts/evm/sccp/test/gas_baseline_v1.json`.
#
# Prerequisites: Python 3.9+, Node.js >= 22 with npm, and HTTPS for the first
# compiler download (cached by SHA-256 under target/sccp-contract-tooling) and
# for `npm ci` and `npm audit`. Runs natively on macOS arm64/x86-64 and Linux
# x86-64/arm64; no Rosetta or Docker. Developer overrides:
# SCCP_CORRIDOR_{PYTHON,NODE,NPM}_BIN select the tool binaries. All generated
# files live in a disposable private directory.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${SCCP_CORRIDOR_PYTHON_BIN:-python3}"
NODE_BIN="${SCCP_CORRIDOR_NODE_BIN:-node}"
NPM_BIN="${SCCP_CORRIDOR_NPM_BIN:-npm}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/iroha-sccp-evm-smoke.XXXXXX")"
chmod 700 "$WORK_DIR"

cleanup() {
  chmod -R u+w "$WORK_DIR" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

CONTRACT_SOURCE="contracts/evm/sccp/SccpTairaXor.sol"
LIBRARY_SOURCE="contracts/evm/sccp/lib/BLS12_381.sol"

# The deployed code has exactly two sources. Test-only harness contracts live
# under contracts/evm/sccp/test/harness and never enter the locked build.
require_exact_sources() {
  local directory="$1" expected="$2" found
  shopt -s nullglob
  found=("$directory"/*.sol)
  shopt -u nullglob
  if [[ "${found[*]-}" != "$expected" ]]; then
    echo "$directory must contain exactly $(basename "$expected"), found: ${found[*]-}" >&2
    exit 1
  fi
}
require_exact_sources contracts/evm/sccp "$CONTRACT_SOURCE"
require_exact_sources contracts/evm/sccp/lib "$LIBRARY_SOURCE"

ARTIFACT_DIR="$WORK_DIR/artifacts"
MANIFEST="$ARTIFACT_DIR/sccp-contract-artifacts-v1.json"
"$PYTHON_BIN" scripts/contract_artifact_corridor.py build --output-dir "$ARTIFACT_DIR"
"$PYTHON_BIN" scripts/contract_artifact_corridor.py verify --manifest "$MANIFEST"

# A manifest is usable only while it is byte-for-byte bound to the locks and to
# this checkout: a mutated artifact and a stale source must both be refused.
MUTATED_MANIFEST="$WORK_DIR/mutated-manifest.json"
"$PYTHON_BIN" - "$MANIFEST" "$MUTATED_MANIFEST" <<'PY'
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))
import contract_artifact_corridor as corridor

manifest = corridor.load_manifest(Path(sys.argv[1]))
mutated = copy.deepcopy(manifest)
contracts = [
    entry
    for entry in mutated["targets"]["evm"]["contracts"]
    if entry["fully_qualified_name"] == corridor.SCCP_CONTRACT
]
if len(contracts) != 1:
    raise SystemExit("the manifest must contain exactly one SccpTairaXor contract")
record = contracts[0]["runtime_bytecode"]
record["hex"] = record["hex"][:-2] + ("00" if not record["hex"].endswith("00") else "01")
corridor.write_canonical_file(Path(sys.argv[2]), mutated)
PY
if "$PYTHON_BIN" scripts/contract_artifact_corridor.py verify --manifest "$MUTATED_MANIFEST" >/dev/null 2>&1; then
  echo "a mutated SCCP artifact manifest was accepted" >&2
  exit 1
fi

# The same manifest verifies against an unchanged copy of the two sources, so
# each refusal below is caused by the one appended line.
make_checkout() {
  mkdir -p "$1/contracts/evm/sccp/lib"
  cp "$CONTRACT_SOURCE" "$1/$CONTRACT_SOURCE"
  cp "$LIBRARY_SOURCE" "$1/$LIBRARY_SOURCE"
}
CLEAN_REPO="$WORK_DIR/clean-checkout"
make_checkout "$CLEAN_REPO"
"$PYTHON_BIN" scripts/contract_artifact_corridor.py verify --manifest "$MANIFEST" --repo-root "$CLEAN_REPO" >/dev/null
for stale_source in "$CONTRACT_SOURCE" "$LIBRARY_SOURCE"; do
  STALE_REPO="$WORK_DIR/stale-checkout-$(basename "$stale_source" .sol)"
  make_checkout "$STALE_REPO"
  printf '\n// adversarial stale source\n' >>"$STALE_REPO/$stale_source"
  if "$PYTHON_BIN" scripts/contract_artifact_corridor.py verify \
    --manifest "$MANIFEST" --repo-root "$STALE_REPO" >/dev/null 2>&1
  then
    echo "a stale $stale_source was accepted by the artifact verifier" >&2
    exit 1
  fi
done

MUTATED_SOLC="$WORK_DIR/mutated-solc"
"$PYTHON_BIN" scripts/contract_artifact_corridor.py materialize --target evm --output "$WORK_DIR/solc-evm" >/dev/null
cp "$WORK_DIR/solc-evm" "$MUTATED_SOLC"
chmod u+w "$MUTATED_SOLC"
printf '\n' >>"$MUTATED_SOLC"
"$PYTHON_BIN" - "$MUTATED_SOLC" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))
import contract_artifact_corridor as corridor

config = corridor.load_corridor_config()
value, _ = corridor.standard_json_input(Path("."), config, "evm")
try:
    corridor.run_native_solc(Path(sys.argv[1]), config.compilers["evm"], corridor.canonical_json_bytes(value))
except corridor.CorridorError as error:
    if "digest mismatch before execution" not in str(error):
        raise
else:
    raise SystemExit("a mutated authenticated native compiler was accepted")
PY

# Install and audit the locked EDR runtime in a private copy.
RUNTIME_DIR="$WORK_DIR/evm-runtime"
mkdir -p "$RUNTIME_DIR"
cp scripts/contract_tooling/evm-runtime/package.json \
  scripts/contract_tooling/evm-runtime/package-lock.json \
  scripts/contract_tooling/evm-runtime/edr-provider.js \
  scripts/contract_tooling/evm-runtime/evm-errors.js \
  "$RUNTIME_DIR/"
(
  cd "$RUNTIME_DIR"
  "$NPM_BIN" ci --ignore-scripts --no-audit --no-fund --loglevel=error
  "$NPM_BIN" audit --omit=dev --audit-level=low
)

echo "Running the EDR provider test (EIP-2537 precompiles under Prague and Osaka)."
NODE_PATH="$RUNTIME_DIR/node_modules" "$NODE_BIN" --test scripts/tests/contract_edr_provider_test.cjs

# These adapter checks use committed structural fixtures, not a live export or
# an EDR fork run, so keep them outside the fork-suite and gas-report guards.
echo "Running structural native-replay adapter tests on the locked runtime."
SCCP_EVM_RUNTIME_DIR="$RUNTIME_DIR" \
  "$NODE_BIN" --test contracts/evm/sccp/test/sccp_live_rotation.test.js

# Every suite iterates the same two hardforks itself; a suite that dropped one
# would otherwise still pass.
SUITES=(
  contracts/evm/sccp/test/sccp_bls.test.js
  contracts/evm/sccp/test/sccp_v1_fixtures.test.js
  contracts/evm/sccp/test/sccp_taira_xor.test.js
  contracts/evm/sccp/test/sccp_gas.test.js
)
for suite in scripts/tests/contract_edr_provider_test.cjs "${SUITES[@]}"; do
  if ! grep -Eq '^const HARDFORKS = (Object\.freeze\()?\["prague", "osaka"\]\)?;$' "$suite"; then
    echo "$suite does not run under exactly the Prague and Osaka rules" >&2
    exit 1
  fi
done

# The suites load the manifest built above and re-verify it against the
# committed artifact lock; no variable may point them at another lock.
unset SCCP_CONTRACT_ARTIFACT_LOCK SCCP_GAS_BASELINE SCCP_ERROR_COVERAGE_REPORT
GAS_REPORT="$WORK_DIR/gas.json"
for suite in "${SUITES[@]}"; do
  echo "Running $suite on the locked native EDR runtime (Prague and Osaka; chain ids 1 and 56)."
  rm -f "$GAS_REPORT"
  SCCP_EVM_RUNTIME_DIR="$RUNTIME_DIR" \
  SCCP_CONTRACT_ARTIFACT_MANIFEST="$MANIFEST" \
  SCCP_CORRIDOR_PYTHON_BIN="$PYTHON_BIN" \
  SCCP_GAS_REPORT="$GAS_REPORT" \
    "$NODE_BIN" --test "$suite"
done

# The gas suite ran last and gates every row against the committed baseline
# (0.9..1.1 x). Its report must cover the baseline's rows for both hardforks
# and both profiles, so a row that silently stopped being measured fails here.
"$PYTHON_BIN" - "$GAS_REPORT" contracts/evm/sccp/test/gas_baseline_v1.json <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
baseline = json.load(open(sys.argv[2], encoding="utf-8"))["rows"]
if set(report) != {"prague", "osaka"} or set(baseline) != {"prague", "osaka"}:
    raise SystemExit(f"gas must be measured under prague and osaka, found: {sorted(report)}")
for hardfork, rows in baseline.items():
    if set(report[hardfork]) != set(rows):
        raise SystemExit(f"{hardfork}: measured rows differ from the baseline: {sorted(set(report[hardfork]) ^ set(rows))}")
    incomplete = [label for label, profiles in report[hardfork].items() if set(profiles) != {"ethereum", "bsc"}]
    if incomplete:
        raise SystemExit(f"{hardfork}: measured gas is missing a profile for: {incomplete}")
PY

echo "SCCP v1 EVM contract smoke passed: authenticated native build, fail-closed verification,"
echo "and the BLS, fixture, behaviour and gas suites under Prague and Osaka."
