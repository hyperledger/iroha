# SCCP contract toolchain (EVM)

`specs/sccp.md` §5.2.5 and §5.5. `contracts/evm/sccp/SccpTairaXor.sol` and the
one library it imports, `contracts/evm/sccp/lib/BLS12_381.sol` (hash-to-G2,
§5.2.4), are compiled by one pinned native compiler. The same creation code
serves Ethereum and BSC, so the corridor has a single target, `evm`:

| Target | Compiler | Platforms pinned in `compiler-lock.json` |
|---|---|---|
| `evm` (Ethereum, BSC) | Ethereum solc `0.8.31+commit.fd3a2265` | macOS universal (arm64 + x86-64), Linux x86-64, Linux arm64 |

Settings: `evmVersion: "cancun"` (explicit, because the compiler defaults to
`osaka`), `optimizer: {enabled: true, runs: 200}`, `viaIR: false` (legacy
pipeline), `metadata.bytecodeHash: "none"`, `metadata.appendCBOR: false`.
`compiler-lock.json` lists exactly the two sources above. Each must start with
an SPDX identifier, keep the exact `pragma solidity 0.8.31;`, declare no custom
storage layout and never use `delete` (the 0.8.31 legacy-pipeline bug
patterns). `SccpTairaXor.sol` contains exactly one import directive,
`import {BLS12_381} from "./lib/BLS12_381.sol";`; the library imports nothing.
The corridor rejects a violating source before compiling it, and requires the
compiler to emit exactly `SccpTairaXor` and the internal library `BLS12_381`
with no link references.

## Compiler authentication

The SHA-256 pins match `binaries.soliditylang.org/<platform>/list.json`.
`scripts/contract_artifact_corridor.py` checks the complete compiler record
against its reviewed constants before downloading anything, then authenticates
the download (SHA-256, ELF machine or universal Mach-O slices) and caches it by
digest under `target/sccp-contract-tooling/compilers`. Every execution re-reads
a stable regular file without following symlinks, re-authenticates it, copies
it into a private mode-0700 directory as mode 0500, checks the exact
`--version` banner and runs `--standard-json` with a clean environment and
bounded output. The compiler runs natively on macOS arm64/x86-64 and Linux
x86-64/arm64; a Python process under Rosetta translation (or one whose Rosetta
probe cannot run) is refused and Docker is never used. Compiler warnings fail
the build.

## Commands

```sh
python3 scripts/contract_artifact_corridor.py build    # compile, check against artifact-lock.json, publish
python3 scripts/contract_artifact_corridor.py verify   # re-authenticate a manifest against both locks and the sources
python3 scripts/contract_artifact_corridor.py lock     # recompile and rewrite artifact-lock.json (review the diff)
python3 scripts/contract_artifact_corridor.py materialize --target evm --output <new path>
python3 scripts/contract_artifact_corridor.py compile-input --target evm --compiler <path> < input.json
```

`build` writes `target/sccp-contract-artifacts/sccp-contract-artifacts-v1.json`
(override with `--output-dir`); `verify` defaults to that manifest. The
manifest carries the compiler identity, settings digest, source inventory and,
for both emitted contracts, the ABI, creation and runtime bytecode with SHA-256
and Keccak-256, metadata, and the named runtime immutable references.
`artifact-lock.json` records, under
`targets.evm.contracts["contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"]`,
the creation code (`creation_bytecode_hex`, which is `SCCP_EVM_CREATION_CODE`
of §4.14.3 P4, with its length and Keccak-256), the complete runtime template,
its `immutable_references` (`name`, AST id, `start`, `length`) and the ABI
digest, plus the digests of the compiler lock and the whole manifest. Any
drift fails closed. `iroha sccp deployment verify` fills the nine §5.2.3
immutables (the §5.2.1 constructor arguments `TAIRA_NETWORK_ID`,
`CONSENSUS_INSTANCE`, `NETWORK_TAG`, `ROUTE_REVISION`, `MAX_WRAPPED_SUPPLY`,
`INITIAL_GENERATION`, `INITIAL_COMMITTEE_ROOT`, `INITIAL_START_HEIGHT`,
`INITIAL_UNTIL_MS`) into the locked template and compares it with the deployed
code.

`scripts/contract_native_solc.js` exposes `compile-input` to Node harnesses.

## EVM runtime

`evm-runtime/` pins the native EDR `0.12.1` Node-API engine, ethers `6.16.0`
and `@noble/curves` `1.2.0` (the BLS12-381 implementation of the independent
JavaScript model; ethers already resolves the same version) for the EDR suites
under `contracts/evm/sccp/test/`. Install it with `npm ci --ignore-scripts` in
that directory; `node_modules/` is ignored by git. `edr-provider.js` creates
isolated in-memory chains with explicit chain ids, gas limits and
Hardhat-style time control.

**The provider's `hardfork` option.** `createNativeEdrProvider` has no default
hardfork: every caller names `hardfork: "prague"` or `hardfork: "osaka"`, and
any other value is refused. Both expose the EIP-2537 precompiles the contract
uses, and Osaka adds the EIP-7883 MODEXP pricing and the EIP-7825 transaction
gas cap of 2^24, so every suite runs under both and gas is measured under both
(§5.4). `allowBlocksWithSameTimestamp: true` lets consecutive blocks share a
timestamp for fixture replays; block time never decreases.

EDR runs the L1 chain type under each chain id, so it is execution evidence for
the contract, not evidence of BSC's precompile pricing or fork schedule.

## EDR suites

Four suites under `contracts/evm/sccp/test/` run the locked build on this
runtime. Each iterates the two hardforks itself, and the chain ids 1 and 56
where a row binds a network:

| Suite | Checks |
|---|---|
| `sccp_bls.test.js` | `lib/BLS12_381.sol` alone: hash-to-G2 against the traces of `fixtures/sccp/bls_consensus_v1.json` and against `@noble/curves`, G1 addition, the pairing check, the field comparisons, the precompile failure cases, and a build without the `Z_pad` writes |
| `sccp_v1_fixtures.test.js` | Replays `finality_v1.json`, `finality_rust_v1.json`, `committee_transitions_v1.json`, `control_v1.json` and the `transferToTaira` and `voidFrozen` entries of `evm_calldata_v1.json` row by row, on fresh and on dirty memory; its last test of each hardfork fails when a row did not run or a pinned row count changed |
| `sccp_taira_xor.test.js` | Behaviour and revert paths no fixture row reaches (§11.5), with a coverage listing: every error the contract declares must be reached, and the only asserted outcome outside the §5.2.2 error table is a revert with empty data |
| `sccp_gas.test.js` | Gas of every §5.4 row, compared with `contracts/evm/sccp/test/gas_baseline_v1.json` |

`gas_baseline_v1.json` (schema `sccp-evm-gas-baseline/v1`) records the gas per
hardfork, row and profile: whole transactions under `rows` (`gasUsed`,
`calldataBytes`, `intrinsic`, the EIP-7623 `floor` and `execution`) and, under
`derived`, the cost of each extra certificate and the `LOG3` of
`SccpCertificate`. A measurement `m` passes iff `0.9·b ≤ m ≤ 1.1·b` for its
baseline `b`, compared in integers as `9·b ≤ 10·m ≤ 11·b`: above is a
regression, and below is a stale baseline that would hide a later one. A row
that is missing from the baseline, or from the run, fails too.
`SCCP_GAS_BASELINE=write` rewrites the file from the run instead of comparing;
review the diff, and update the tables of `specs/sccp.md` §5.4 and
`contracts/evm/sccp/README.md` with it.

Environment variables of the suites, all for tests only:

| Variable | Effect |
|---|---|
| `SCCP_EVM_RUNTIME_DIR` | An installed copy of `evm-runtime/` to load the provider, EDR and ethers from, in place of this directory |
| `SCCP_CONTRACT_ARTIFACT_MANIFEST` | A manifest that is already built. The suites verify it against both locks and the sources and load it; without it they verify `target/sccp-contract-artifacts/sccp-contract-artifacts-v1.json` and rebuild it when it is missing or stale |
| `SCCP_CONTRACT_ARTIFACT_LOCK` | An artifact lock other than the committed `artifact-lock.json`, for work on a source whose lock is not regenerated yet |
| `SCCP_CORRIDOR_PYTHON_BIN` | The Python that runs `contract_artifact_corridor.py` (default `python3`) |
| `SCCP_GAS_BASELINE=write` | `sccp_gas.test.js`: rewrite the baseline, as above |
| `SCCP_GAS_REPORT=<file>` | `sccp_gas.test.js`: also write the measurements as JSON |
| `SCCP_ERROR_COVERAGE_REPORT=<file>` | `sccp_taira_xor.test.js`: also write the coverage listing as JSON (hardfork and profile, then error name, then the tests that reached it) |

`scripts/sccp_evm_contract_smoke.sh` runs everything fail-closed in a private
directory: it builds and verifies the artifacts, proves that a mutated
manifest, a stale source and a mutated compiler are refused, installs and
audits a private copy of the runtime (`npm audit --omit=dev
--audit-level=low`), and runs the provider test and the four suites against
the manifest it built. It unsets `SCCP_CONTRACT_ARTIFACT_LOCK`,
`SCCP_GAS_BASELINE` and `SCCP_ERROR_COVERAGE_REPORT`, so that the run is
always against the committed lock and baseline, and it requires the gas report
to cover every baseline row for both hardforks and both profiles.
`SCCP_CORRIDOR_{PYTHON,NODE,NPM}_BIN` select its tool binaries. A single suite
and the provider test also run directly:

```sh
(cd scripts/contract_tooling/evm-runtime && npm ci --ignore-scripts)
node --test contracts/evm/sccp/test/sccp_gas.test.js
NODE_PATH=<installed evm-runtime>/node_modules node --test scripts/tests/contract_edr_provider_test.cjs
```
