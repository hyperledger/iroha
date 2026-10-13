# SCCP v1 TON build and fixture tooling

The current native BLS destination lives in
[`contracts/ton/sccp`](../../contracts/ton/sccp). Its three contracts are
`SccpTairaXorMinter`, `SccpTairaXorWallet` and `SccpConsumedBucket`.
[`SECURITY.md`](../../contracts/ton/sccp/SECURITY.md) records the implementation
invariants; [`specs/sccp.md`](../../specs/sccp.md) defines the canonical layouts
and destination verification relation.

## Pinned toolchain

`scripts/ton_sccp_builder.py` selects Acton 1.2.0 with Tolk 1.4.2 for the host.
It checks the release archive against a pinned SHA-256 and caches only the
executable under the ignored `contracts/ton/sccp/.toolchain/`. `--acton PATH`
selects an existing executable with the same exact version check; `--offline`
forbids downloads. No container runtime is required.

From the repository root:

```sh
python3 scripts/ton_sccp_builder.py toolchain
python3 scripts/ton_sccp_builder.py vectors --check
python3 scripts/ton_sccp_builder.py fmt
python3 scripts/ton_sccp_builder.py build
python3 scripts/ton_sccp_builder.py wrappers
python3 scripts/ton_sccp_builder.py test
python3 scripts/generate_ton_sccp_stateinit_golden.py --check
python3 -m pytest scripts/tests/ton_sccp_builder_test.py
```

`scripts/sccp_ton_contract_build.sh` runs the complete `all` workflow: vector
freshness, formatting, compilation, wrapper freshness, emulator tests and the
StateInit golden check. `fmt --write`, `wrappers --write` and `vectors` regenerate
the corresponding outputs. Extra arguments to `test` pass through to Acton;
only a complete test invocation enforces the complete gas baseline.

## Native fixtures

The builder renders `sccp-test-vectors.gen.tolk`,
`sccp-cert-vectors.gen.tolk` and `sccp-boc-vectors.gen.tolk` from the committed `fixtures/sccp` data. These cover
native BLS consensus keys/signatures, finality certificates, committee
transitions, controls, payloads, commitment trees and history proofs. The
renderer does not create an independent signature authority or derive a second
set of expected results. Certificate replay checks use the same fixtures as the
Rust and Solidity implementations.

`ton_boc_v1.json` contains the actual Rust wallet encoder output: 28 native
cell graphs and five malformed burn snakes. The Python renderer independently
checks every cell hash, depth and canonical BoC serialization. The Tolk suite
imports these BoCs unchanged, re-encodes their native types, and replays
finalize/void (direct and historical, inline and checkpoint), control, rotation,
init, bucket deployment, retry, frozen range and burn operations against the
compiled contracts. Malformed snakes must fail before a wallet debit. Regenerate
with `cargo test -p iroha_sccp_wallet regenerate_ton_boc_vectors -- --ignored`,
then run `python3 scripts/ton_sccp_builder.py vectors`; the normal wallet tests
and builder checks reject drift.

`fixtures/sccp/ton_stateinit_v1.json` binds the compiled code hashes/depths and
the exact canonical initial data for native committees of sizes 4 and 31. It
includes the consensus instance, initial committee pin, compressed G1 key
chunks, empty checkpoint storage and derived minter, wallet and bucket
addresses. `generate_ton_sccp_stateinit_golden.py` independently recomputes cells
in Python and compares them with the Tolk script's output. Regenerate after a
contract change; update any affected Rust golden assertions in the same change.

The Rust mirror reads the expected addresses from that fixture. The minter's
maximum 512-operation graph is bounded by 2,380 cells/790,000 bits; destination
wallet and bucket fixtures retain 512 receipts each. These admitted capacities
are priced for 100 years at current TON storage rates. The canonical empty
minter book is 139 bits; each mandatory child receipt cell is 11 bits. Native
capacity, lost-ACK, stale-delete and full-graph tests accompany the layout and
code-hash checks. Component checks do not qualify deployment.

## Emulator and gas checks

`acton test tests/unit` covers native BLS verification, exact quorums, checkpoint
storage and equivocation, key-changing rotation, controls, payload/history
binding, canonical cell graphs, replay, supply and bounce/retry accounting,
burns and value floors.

Tests print `gas <label>: <used> (limit <limit>)`. The builder writes these
measurements to ignored `gas-current.json` and compares a complete run with
tracked `gas-baseline.json`; a step above 1.1 times its baseline fails. Changes
to the baseline require reviewing the measured result and the affected fee
bounds. Do not describe these component checks as network or settlement
qualification.
