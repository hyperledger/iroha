# SCCP v1 destination contract for Ethereum and BSC

`SccpTairaXor.sol` is the SCCP v1 destination for the two EVM profiles of
[`specs/sccp.md`](../../../specs/sccp.md) (§5.1, §5.2, revision 5). It is the
ERC-20/BEP-20 token **Taira XOR** (`tXOR`, 9 decimals, one token unit = one
Taira unit) with the bridge built in. It verifies Taira's Sumeragi CommitQC
directly: one BLS12-381 min-pk aggregate signature of exactly `q = n − f`
validators (`4 ≤ n ≤ 31`) over the commit preimage, checked through the
EIP-2537 precompiles. There are no bridge keys, and the contract has no owner,
guardian, admin key, setter, upgrade path or external call other than
precompiles. The minting pause changes only through a control leaf of a
certified Taira block.

| Profile | Tag | Chain id | Domain | Route id |
|---|---|---|---|---|
| `ethereum-mainnet` | `0x41` | 1 | 1 | `taira_eth_xor` |
| `bsc-mainnet` | `0x42` | 56 | 2 | `taira_bsc_xor` |

Both profiles use the same creation code, built by solc
`0.8.31+commit.fd3a2265`; the runtime code differs only in immutables.

## Files

| Path | Role |
|---|---|
| `SccpTairaXor.sol` | The destination contract and token |
| `lib/BLS12_381.sol` | Internal library: hash-to-G2, G1 addition, the pairing check and field comparisons over EIP-2537 |
| `test/sccp_v1_model.js` | Independent ethers and `@noble/curves` model of the §3 encodings, the interface of §5.2.2 and a Taira that signs certificates |
| `test/sccp_edr_harness.js` | Loads the locked build through the corridor, opens EDR chains, deploys, decodes reverts, records gas |
| `test/sccp_replay.js` | Replays fixture rows and scenario steps as calls and compares outcome, logs, return value and state |
| `test/harness/SccpBlsHarness.sol` | Test-only wrapper that exposes the library's internal functions |
| `test/harness/SccpDirtyMemoryHarness.sol` | Test-only subclass that runs the certificate-verifying entry points on memory that is not zero |
| `test/sccp_bls.test.js` | Library suite |
| `test/sccp_v1_fixtures.test.js` | Fixture replay suite |
| `test/sccp_taira_xor.test.js` | Behaviour and revert-path suite |
| `test/sccp_gas.test.js`, `test/gas_baseline_v1.json` | Gas suite and its committed baseline (§5.4) |

The harness contracts are compiled by the tests only and never enter the
locked build.

## Deployment

```solidity
constructor(bytes32 tairaNetworkId, bytes32 consensusInstance, uint8 networkTag,
            uint32 routeRevision, uint256 maxWrappedSupply,
            uint64 initialGeneration, bytes32 initialCommitteeRoot,
            uint64 initialStartHeight, uint64 initialUntilMs)
```

The constructor pins one committee generation (its root, first height and
trust deadline) and Taira's network and consensus instance ids. A tag other
than `0x41`/`0x42`, or a `block.chainid` that differs from the tag's identity
word, reverts `WrongChain()`; this is checked first. Every other violated
bound reverts `BadConfig()`: a zero `tairaNetworkId`, `consensusInstance`,
`routeRevision`, `initialGeneration`, `initialCommitteeRoot` or
`initialStartHeight`; a cap outside `1..2^128 − 1`; and an `initialUntilMs`
that is not after the deployment time or is more than `MAX_VALIDITY_MS +
MAX_INIT_SLACK_MS` (30 days + 1 hour) after it. `MAX_VALIDITY_MS` and
`MAX_FAST_PAUSE_MS` (30 days each) are constants of the source. The contract
is initialized by its constructor only, so the ABI has no `NotInitialized` or
`AlreadyInitialized` error.

The nine arguments are stored as the immutables `TAIRA_NETWORK_ID`,
`CONSENSUS_INSTANCE`, `NETWORK_TAG`, `ROUTE_REVISION`, `MAX_WRAPPED_SUPPLY`,
`INITIAL_GENERATION`, `INITIAL_COMMITTEE_ROOT`, `INITIAL_START_HEIGHT` and
`INITIAL_UNTIL_MS`. The deployed runtime equals the locked template in
`scripts/contract_tooling/artifact-lock.json` with those nine immutables filled
at the recorded `immutable_references`; the suites check this byte for byte.

The contract is created only through `SCCP_EVM_DEPLOYER` (the keyless
deterministic-deployment proxy, §5.2.1) with salt `0^32` and init code
`SCCP_EVM_CREATION_CODE ‖ abi.encode(arguments)`, so its address is a function
of the arguments. The creation code is `creation_bytecode_hex` of the artifact
lock: 18,271 bytes; the runtime is 17,059 bytes.

## Entry points

| Selector | Function | Rule |
|---|---|---|
| `0x07a5e706` | `submitCheckpoints(TairaCertificateV1[])` | §5.1.3: 1..=16 certificates of the current generation, in order; each stores a checkpoint, and a rotation installs the successor generation |
| `0x10efea88` | `finalizeFromTaira(TairaCertificateV1,MessageProofV1)` | §5.1.5 with the certificate inline |
| `0x55c39595` | `finalizeFromCheckpoint(CheckpointRefV1,MessageProofV1)` | §5.1.5 against a stored checkpoint |
| `0x32118e92` | `applyControl(TairaCertificateV1,ControlProofV1)` | §5.1.6 Parliament and fast-pause controls, strictly increasing `controlNonce` |
| `0x53899b1e` | `applyControlFromCheckpoint(CheckpointRefV1,ControlProofV1)` | §5.1.6 against a stored checkpoint |
| `0x997fcd99` | `voidExpired(uint64,TairaCertificateV1,MessageProofV1)` | §5.1.8 after the deadline, same nonce bit as a mint |
| `0xfbeb670e` | `voidExpiredFromCheckpoint(uint64,CheckpointRefV1,MessageProofV1)` | §5.1.8 against a stored checkpoint |
| `0x5b094c00` | `voidFrozen(uint64 firstNonce,uint64 count)` | §5.1.8: exactly 68 bytes of calldata, 1..=256 nonces |
| `0xebfc6ca8` | `transferToTaira(bytes,uint256,uint64)` | §5.1.7: canonical calldata only, per-sender nonce, burn |

Views: `committeeState`, `checkpointHeader`, `pauseState`, `mintingPaused`
(the effective pause at `block.timestamp`), `consensusInstance`,
`initialCommittee`, `equivocated`, `maxValidityMs`, `isConsumed`,
`controlNonce`, `opCount`, `transferNonces`, `tairaNetworkId`, `routeRevision`,
`maxWrappedSupply`, plus the ERC-20 surface with ERC-6093 errors. `opCount`
counts finalizations, voids, burns and applied controls, never checkpoints or
rotations, and saturates at `2^64 − 1` (§5.1.1). Two ABI JSON details change
no selector and no encoding (§5.2.2): the third output of `pauseState()` is
named `controlNonce_` (the spec name would shadow the `controlNonce()`
getter), and `maxValidityMs()` is `pure`.

`transferToTaira` uses the sender's source nonces `0 ..= 2^64 − 2` in order
(§5.1.7): `expectedNonce` must equal `transferNonces[sender]`, else
`BadNonce(transferNonces[sender])`. A stored next nonce of `2^64 − 1` means
the sender's nonces are exhausted: every burn of that sender then reverts
`BadNonce(2^64 − 1)`, whatever nonce it expects, and no nonce is reused or
wrapped. Neither counter can wrap or abort a call with an arithmetic panic
(§5.1.2 "Arithmetic").

## Certificate verification

`VerifyCertificate` (§5.1.3) runs its steps in the order of the spec, and the
first failing step is the call's error:

- A certificate whose finality header `X` is already stored takes the cheap
  path: no precompile call and no `SccpCertificate` event.
- Before any precompile runs, the contract checks every encoding (§5.2.4 "fail
  fast"): the signature is not `0^192`, every coordinate and limb is below `p`,
  every signer key's sign flag matches its `y`, and no signer has the
  coordinates `(0, 0)`. A failing precompile burns all forwarded gas, so
  nothing malformed reaches one.
- The supplied committee keys must hash to the current committee root, and the
  signer bitmap must name exactly `q = n − f` of them. The aggregate key is the
  sum of those signers' keys. The pairing input is the 768 bytes `apk ‖ Q ‖
  (−g1) ‖ σ` and must return 32 bytes equal to 1.
- `Q = hashToG2(m)` comes from `lib/BLS12_381.sol`. The library is written for
  this repository from RFC 9380 and EIP-2537 and is not a copy of a
  third-party file: `expand_message_xmd` with SHA-256 and
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, four 64-byte values reduced
  mod `p` by `MODEXP` with exponent 1, `MAP_FP2_TO_G2` twice and one `G2ADD`.
  Every precompile call forwards `gas()` and checks success and the exact
  return length; `Z_pad` and every 16-byte field padding are written
  explicitly, so no result depends on prior memory contents. Its audit is part
  of the EIP-2537 glue audit gate.
- BSC's precompile `0x66` is not used.

A failed SHA-256 or hash-to-G2 precompile call (reachable only by starving the
call of gas) reverts with empty data, outside the error table. Callers should
simulate with ample gas before treating `BadSignature()` or an empty revert as
a rejection.

`parliamentPaused` in `ControlProofV1` is a Solidity `bool`: a calldata word
above 1 is refused by the ABI decoder with empty revert data before any check
of the contract, not with `BadControl()`.

Time is `now_ms = min(block.timestamp × 1000, 2^64 − 1)`. The two time sums
and `opCount` saturate, a sender's source nonces end at `2^64 − 2`, and the
header bounds exclude every other overflow (§5.1.2 "Arithmetic").

## Storage

Storage follows §5.2.3; within a packed slot the first-named field is the
low-order one.

| Slot | Content |
|---|---|
| 0 (A) | `committeeRoot` |
| 1 (B) | `untilMs`, `start`, `high`, `generation` (64 bits each, from bit 0) |
| 2 (C) | `controlNonce`, `opCount`, `fastPauseUntilMs` (64 bits each), `parliamentPaused` (bit 192), `equivocated` (bit 200) |
| 3 | `checkpointHeader`: height ⇒ `keccak256(X)` |
| 4 | consumed bitmap: word `nonce >> 8`, bit `nonce & 255` |
| 5 | `transferNonces` |
| 6, 7, 8 | `totalSupply`, `balanceOf`, `allowance` |

## Canonical calldata

`transferToTaira` and `voidFrozen` accept only the encoding Solidity's own
encoder produces (§5.2.2): the canonical offset (`0x60` for the recipient),
integer words within their declared widths, zero `bytes` padding and the exact
length (`0x44` for `voidFrozen`). Anything else reverts
`NonCanonicalCalldata()`, or with empty data where Solidity's ABI decoder
already refuses it. `test/sccp_v1_fixtures.test.js` replays the
`transferToTaira` and `voidFrozen` entries of the `calldata_conformance` table
of `fixtures/sccp/evm_calldata_v1.json`.

## Build, verify and test

```sh
python3 scripts/contract_artifact_corridor.py build     # target/sccp-contract-artifacts/
python3 scripts/contract_artifact_corridor.py verify
(cd scripts/contract_tooling/evm-runtime && npm ci --ignore-scripts)
node --test contracts/evm/sccp/test/sccp_bls.test.js
node --test contracts/evm/sccp/test/sccp_v1_fixtures.test.js
node --test contracts/evm/sccp/test/sccp_taira_xor.test.js
node --test contracts/evm/sccp/test/sccp_gas.test.js
bash scripts/sccp_evm_contract_smoke.sh                  # all of the above, fail-closed, in a private directory
```

The toolchain policy (native arm64/x86-64 compiler, no Rosetta or Docker,
cancun legacy pipeline without metadata hash or CBOR) is described in
[`scripts/contract_tooling/README.md`](../../../scripts/contract_tooling/README.md).
Neither source may use `delete` or declare a custom storage layout (0.8.31
legacy-pipeline bug patterns), and a compiler warning fails the build; the
corridor enforces both. After any change to either source, regenerate the lock
with `python3 scripts/contract_artifact_corridor.py lock` and review the diff.

Every suite runs on the locked native EDR runtime under both the Prague and
the Osaka rules, and under chain ids 1 and 56 where a row binds a network.
EDR runs the L1 chain type under each chain id, so the BSC profile is
execution evidence for the contract, not a measurement of a BSC node.

- `sccp_bls.test.js` checks the library against the `hash_to_g2_dst_sig`
  traces of `fixtures/sccp/bls_consensus_v1.json` and against `@noble/curves`,
  with the precompile failure cases and a build that omits the `Z_pad` writes.
- `sccp_v1_fixtures.test.js` replays `finality_v1.json`,
  `finality_rust_v1.json`, `committee_transitions_v1.json` and
  `control_v1.json` row by row: outcome or exact error with its arguments,
  logs as raw topics and data, return value, and the full state after every
  step. Every certificate and scenario also runs through
  `SccpDirtyMemoryHarness.sol`. It also rebuilds all 24 selectors and eight
  event topics of the Rust `evm_calldata_v1.json`, executes its 13 golden
  calls and 15 views, compares its four logs and recorded view returns,
  and deploys its P4 sample at the CREATE2 address derived from the locked
  creation code and all nine constructor words. Its last test of each hardfork fails when a
  row did not run or a pinned row count changed.
- `sccp_taira_xor.test.js` covers what the fixtures do not (§11): constructor
  bounds, raw storage slots, every admitted committee size, the first failing
  step of `VerifyCertificate`, latch precedence, saturation of the clock and
  of the deadlines, payload and proof rules, the supply cap and bitmap word
  boundaries, canonical calldata, ERC-20, `WrongChain()` at run time, the
  selectors of the retired transport, and the two counter bounds, reached by
  storage injection (`opCount` at `2^64 − 1`, a sender whose source nonces are
  exhausted). Its last test of each run lists which test reached each
  declared error and fails when one was not reached, or when a test asserted
  an outcome outside the error table other than a revert with empty data.
  `SCCP_ERROR_COVERAGE_REPORT=<file>` writes that listing as JSON.
- `sccp_gas.test.js` measures every §5.4 row and fails when a row is missing
  or outside 0.9..1.1 × `gas_baseline_v1.json`. `SCCP_GAS_BASELINE=write`
  rewrites the baseline from the run (review the diff); `SCCP_GAS_REPORT=<file>`
  writes the measurements as JSON.

Test-only variables: `SCCP_EVM_RUNTIME_DIR` (an installed copy of
`scripts/contract_tooling/evm-runtime`), `SCCP_CONTRACT_ARTIFACT_MANIFEST` (a
manifest to verify and load in place of the default build),
`SCCP_CONTRACT_ARTIFACT_LOCK` (an artifact lock other than the committed one,
for work on an unlocked source) and `SCCP_CORRIDOR_PYTHON_BIN`.

## Measured gas (§5.4)

Gas used by the whole transaction on the locked EDR `0.12.1` runtime, Ethereum
profile: the values of the committed baseline `test/gas_baseline_v1.json`,
which the gas suite holds every row of the locked build to within 0.9..1.1 ×.
The BSC profile differs by at most 70 gas. A full-path certificate costs
exactly 1,200 gas more under Osaka (the EIP-7883 `MODEXP` repricing of the
four field reductions of hash-to-G2); nothing else differs between the two
hardforks. `n` is the committee size and `X` the finality header.

| Operation | Prague | Osaka |
|---|---|---|
| `submitCheckpoints`, 1 certificate, n = 4 / 7 / 31 | 253,265 / 260,396 / 316,706 | 254,465 / 261,596 / 317,906 |
| … with rotation, heartbeat (slot B), n = 4 / 7 / 31 | 256,908 / 264,027 / 320,337 | 258,108 / 265,227 / 321,537 |
| … with rotation, key change (root and slot B), n = 4 / 7 / 31 | 259,660 / 266,839 / 323,149 | 260,860 / 268,039 / 324,349 |
| … each extra certificate, n = 4 / 7 / 31 | 221,999 / 229,169 / 285,735 | 223,199 / 230,369 / 286,935 |
| `submitCheckpoints`, 16 certificates, n = 4 / 7 / 31 | 3,583,256 / 3,697,934 / 4,602,731 | 3,602,456 / 3,717,134 / 4,621,931 |
| `submitCheckpoints`, 16 rotations (key changes), n = 4 / 7 / 31 | 3,641,232 / 3,755,910 / 4,660,695 | 3,660,432 / 3,775,110 / 4,679,895 |
| `finalizeFromCheckpoint`, 1-leaf block, existing balance, used bitmap word | 71,400 | 71,400 |
| `finalizeFromCheckpoint`, 1-leaf block, first operation | 139,788 | 139,788 |
| `finalizeFromCheckpoint`, 512-leaf block, 32-sibling history path | 148,843 | 148,843 |
| `voidExpiredFromCheckpoint`, 1-leaf block / 512-leaf block with history path | 58,374 / 118,642 | 58,374 / 118,642 |
| `applyControlFromCheckpoint`, 1-leaf block / 512-leaf block with history path | 51,196 / 94,377 | 51,196 / 94,377 |
| `finalizeFromTaira` inline, new `X`, existing balance, n = 4 / 7 / 31 | 288,866 / 295,984 / 352,284 | 290,066 / 297,184 / 353,484 |
| `finalizeFromTaira` inline, new `X`, first operation, n = 4 / 7 / 31 | 356,192 / 363,310 / 419,646 | 357,392 / 364,510 / 420,846 |
| `finalizeFromTaira` inline, stored `X` (cheap path), n = 4 / 7 / 31 | 92,578 / 98,080 / 155,110 | 92,578 / 98,080 / 155,110 |
| `applyControl` inline, n = 4 / 7 / 31 | 267,508 / 274,662 / 330,986 | 268,708 / 275,862 / 332,186 |
| `voidExpired` inline, n = 4 / 7 / 31 | 274,694 / 281,872 / 338,172 | 275,894 / 283,072 / 339,372 |
| `voidFrozen`, 1 nonce | 54,458 | 54,458 |
| `voidFrozen`, 256 nonces in one / two bitmap words | 450,206 / 472,836 | 450,206 / 472,836 |
| `transferToTaira`, 34-byte recipient, first / later burn of the sender | 68,646 / 51,558 | 68,646 / 51,558 |
| `transferToTaira`, 1024-byte recipient, later burn | 75,829 | 75,829 |
| deployment through `SCCP_EVM_DEPLOYER` | 3,811,293 | 3,811,293 |

"First operation" also initializes the recipient's balance, the bitmap word
and slot C. The cheap path at n = 31 is bound by the EIP-7623 calldata floor
(4,036 bytes of calldata). `SccpCertificate` costs 7,388 gas on every
full-path verification. `voidFrozen` costs about 1,550 gas per further nonce,
because every nonce emits its own `SccpVoided(0, nonce)`. Sixteen certificates
at n = 31 stay below the EIP-7825 transaction gas cap of 2^24 that Osaka
applies. Library calls alone, measured by `sccp_bls.test.js`: `hashToG2` 54,036
(Prague) and 55,236 (Osaka), `pairingCheck` 103,124, `g1Add` 591.
