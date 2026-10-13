# SCCP v1 TON contracts: build, tests and artifacts

This note covers the repository tooling for the TON destination of SCCP v1
(`specs/sccp.md` revision 5, §5.3–§5.5). The contracts live in
[`contracts/ton/sccp`](../../contracts/ton/sccp):

| Contract | Source | Role |
|---|---|---|
| `SccpTairaXorMinter` | `contracts/SccpTairaXorMinter.tolk` | TEP-74 / TEP-89 Jetton master with the bridge built in |
| `SccpTairaXorWallet` | `contracts/SccpTairaXorWallet.tolk` | TEP-74 wallet; burns require the `sccp_burn_to_taira` payload |
| `SccpConsumedBucket` | `contracts/SccpConsumedBucket.tolk` | 512 replay flags of one minter; accepts flags only after the minter's one-time activation |

Shared modules: `sccp-constants`, `sccp-errors` (the exit codes of the §5.2.2
error table), `sccp-messages` and `sccp-storage` (exact TL-B of
§5.3.1–§5.3.3), `sccp-crypto` (`GLOBALID`, `HASHEXT` keccak and SHA-256,
`SDLEXCMP` and the `DUP TLEN UNTUPLEVAR BLS_FASTAGGREGATEVERIFY` wrapper),
`sccp-cells` (canonical snake, hash-chunk and key-chunk cells),
`sccp-finality` (the header `X`, committees, certificate verification, the
three checkpoint slots and the predicates of the committee state machine),
`sccp-verify` (trees, block references, leaves, control constraints and
payloads), `sccp-fees` (§5.3.5) and `sccp-addresses`.

The minter verifies Taira's Sumeragi `CommitQC` directly: one BLS12-381 min-pk
aggregate of exactly `q = n − f` signers (`4 ≤ n ≤ 31`) whose keys it stores.
There is no owner, admin, upgrade path, setter or bridge key. The minting pause
changes only through `sccp_apply_control` / `sccp_apply_control_checkpoint`
with a control leaf of a certified Taira block (§5.1.6). The security
invariants are listed in
[`contracts/ton/sccp/SECURITY.md`](../../contracts/ton/sccp/SECURITY.md).

## Toolchain

Acton 1.2.0 bundling Tolk 1.4.2, native on macOS arm64/x86-64 and Linux
arm64/x86-64; no Docker, container runtime or Rosetta. `Acton.toml` pins
`acton = "1.2.0"`. `scripts/ton_sccp_builder.py` pins the official release
archives by SHA-256 (from the release `sha256.sum`), downloads the host archive
once, verifies it, extracts only the `acton` executable into the ignored
`contracts/ton/sccp/.toolchain/` cache, and requires the exact version line
`acton 1.2.0 (16d49e1 2026-09-16)`. After a build it also requires the
project stdlib to declare `tolk 1.4.2`. `--acton /abs/path` uses an existing
executable with the same version check; `--offline` forbids downloads. No
environment variable changes behaviour.

## Commands

```text
scripts/sccp_ton_contract_build.sh            # everything below (default `all`)
python3 scripts/ton_sccp_builder.py toolchain  # resolve and print the pinned Acton
python3 scripts/ton_sccp_builder.py vectors [--check]
python3 scripts/ton_sccp_builder.py fmt [--write]
python3 scripts/ton_sccp_builder.py build
python3 scripts/ton_sccp_builder.py wrappers [--write]
python3 scripts/ton_sccp_builder.py test [acton test options]
python3 scripts/generate_ton_sccp_stateinit_golden.py [--check]
python3 -m pytest scripts/tests/ton_sccp_builder_test.py
```

`all` runs, in order: the test-vector freshness check, `acton fmt --check` on
the SCCP sources, `acton build` with the stdlib check, the wrapper freshness
check (`acton wrapper --all` in a scratch copy must reproduce
`wrappers/*.gen.tolk`), the emulator suite `acton test tests/unit` with the
gas comparison, and the StateInit golden check. Wrapper names are the
PascalCase contract ids.

For local end-to-end runs against a full TON node emulation, use
`acton simulator`. The four-validator TON lane scenarios belong to the
`integration_tests/tests/sccp_lanes/` harness, which does not have them yet
(TODO(ws36)).

## Test vectors

`tests/unit/sccp-test-vectors.gen.tolk` and `sccp-cert-vectors.gen.tolk` are
renderings of the committed fixtures under `fixtures/sccp/`
(`finality_v1.json`, `committee_transitions_v1.json`, `control_v1.json`,
`bls_consensus_v1.json`, `payload_v1.json`, `commitment_tree_v1.json`,
`history_v1.json`, `ton_stateinit_v1.json`, `finality_rust_v1.json`); the
builder derives no vector of its own. KeyChunk hashes, the Rust transcript
negative and scenario step counts are generated from these sources. `vectors
--check` fails when a fixture was regenerated and the two files were not, so
run `vectors` after any change under `fixtures/sccp/`.

Fixture certificates are replayed byte for byte. Certificates of scenarios the
fixtures do not carry are signed in the test VM (`tests/unit/sccp-test-bls.tolk`)
with the 35 fixture test keys; the BLS suite first proves that this signer
reproduces the fixture signatures and the hash-to-G2 traces under `DST_SIG`.
The TON rows of the fixtures commit to the placeholder minter account id
`0x35…35`, so the test helpers place the deployed minter at `0:35…35`
(`tests/unit/sccp-test-helpers.tolk`).

## StateInit golden

`fixtures/sccp/ton_stateinit_v1.json` pins, for the fixture committees `n4`
and `n31` under NetworkId `0x11…11` and consensus instance `0x77…77`:

- the code cell hash, depth, cell count and bit count of the minter, wallet
  and bucket;
- the pin (generation, committee root, start height, `until_ms`), the keys in
  canonical order, and each cell of the canonical initial data (§5.3.1) with
  its hash;
- the StateInit hash and the workchain-0 address;
- the wallet address of owner `0:abab…ab` and the addresses of buckets 0 and 1
  (canonical data: `activated = false`, flags clear).

The generator parses the compiled code BoCs, recomputes everything in Python,
runs `contracts/ton/sccp/scripts/stateinit-golden.tolk` (the same values from
the contracts' own Tolk types via `acton script`) and requires exact agreement.
Any contract change alters the code hashes: regenerate the fixture with
`python3 scripts/generate_ton_sccp_stateinit_golden.py`. The Rust mirror
`iroha_sccp::v1::ton_cell` recomputes the data hash and every address from the
recorded code hashes and depths, which is what Taira's `RegisterRoute` does.
The mirror reads the expected minter and bucket addresses from this fixture;
its `TON_MINTER_STATE_BITS` / `TON_MINTER_STATE_CELLS` bounds are 124 000 bits
and 265 cells. `iroha_sccp_wallet::pure::ton` funds deployment from the matching
`MINTER_FLOOR` (about 12.34 TON at the Rust mirror's pinned storage prices).

## Emulator suite (`tests/unit`)

282 Acton tests in 13 files cover §5.1, §5.3 and the §11 contract rows:

| Suite | Tests | Content |
|---|---|---|
| `sccp-bls` | 26 | The SHA-256, BLS and `SDLEXCMP` wrappers against `finality_v1.json`: `R`, `P`, `m`, checkpoint ids and committee roots; the stack shape and opcode gas at n = 4, 7 and 31; the opcode's refusal of invalid signer keys; every positive and negative certificate row through `sccp_checkpoint`; the identity signature before the cheap path |
| `sccp-checkpoint` | 64 | The committee state machine: checkpoints, eviction and `high`; heartbeat and key-changing rotations with `next_keys`; V1–V3 and the latch; expiry; the check order; the saturating time sums; replay of the TON and replayable scenarios of `committee_transitions_v1.json`; the exit-code table |
| `sccp-init` | 17 | `sccp_init`: canonical data, committee size, key order and root, the validity bound, the chain id, library-cell keys, double init, every operation before init |
| `sccp-finalize` | 44 | Inline and checkpoint finalize, history proofs, the deadline and cap edges, U1/U2 after a rotation, the check order, duplicates and pending supply, bounces, `LatchRequired`, a mint in flight across a latch, `op_count` saturation |
| `sccp-void` | 23 | `sccp_void_expired*` and `sccp_void_frozen`: deadline edges, the nonce argument, the range before `Frozen`, the last nonce of `u64`, bounced ranges |
| `sccp-control` | 30 | Control leaves on both tracks, the fast-pause clamp and expiry, stale, equal and gapped nonces, foreign leaves, the `control_v1.json` destination-effect scenarios rebuilt for the minter at `0:35…35` |
| `sccp-bucket` | 14 | Ordinary exact consumption tails, activation (a bucket deployed early, a deleted bucket recreated), flags, bounced replies, recorded retries and `sccp_retry` |
| `sccp-burn` | 14 | Burns: payload and message id, full recipient admission before debit, exact ordinary wrappers, the 1024-byte recipient, wallet and minter rejections with balance restore, burns after expiry and after a latch, exhausted source nonces (`BadNonce`), `op_count` saturation |
| `sccp-value` | 10 | Quotes taken before time advances, the entry minimum and the storage grace, underfunded calls failing before any signature, burns and bucket replies below the floor, a burn whose event cannot be sent, the floor deficit and top-ups |
| `sccp-fees` | 12 | State and message size constants against real cells, the §5.4 cost rows at n = 4, 7 and 31, the certificate steps at their largest inputs, the round trips and the floors |
| `sccp-rotation-run` | 2 | Ten thousand rotations (1 000 signed, 9 000 on the cheap path) leave the account at 232 cells and 110 608 bits; exact layout checks account for committee size and code/data deduplication |
| `sccp-vectors` | 18 | `GLOBALID`, the constants, the keccak wrappers, key chunks, canonical cells and library cells, control-leaf preimages, payload, tree and history vectors |
| `sccp-wallet` | 8 | TEP-74 transfers and bounces, large-payload forwarding fees, TEP-89, the TEP-64 content, top-ups, unknown operations |

`TODO: WP-TON-RUST` the golden message bodies of `fixtures/sccp/ton_boc_v1.json`
are replayed once `crates/iroha_sccp/src/v1/ton_cell.rs` writes that fixture.
The shared fixtures carry no TON rows for the `control_v1.json`
destination-effect scenarios, which the control suite rebuilds for the minter.
The BLS suite replays all 41 shared negative rows with a TON outcome, including
the six invalid signer-key rows whose `BadSignature` verdict is produced by
both reference models. Thirteen EVM-only negative rows have no TON outcome;
the separate Rust transcript negative is also replayed from generated data.

## Measured gas and value (§5.4)

Measured with the Acton 1.2.0 emulator and its default network config. The
suites print `gas <step>: <used> (limit <limit>)` lines; `test` writes them to
the ignored `gas-current.json` and fails when the committed
`contracts/ton/sccp/gas-baseline.json` is missing, a step exceeds its limit in
`sccp-fees.tolk` or 1.1 x its baseline row, a step has no baseline row, or (in a
complete run) a baseline row was not measured. To accept an intended change, copy
`gas-current.json` of a complete run over `gas-baseline.json` and review the
diff.

Gas is the compute gas of the minter step.

| Step | n = 4 (q = 3) | n = 7 (q = 5) | n = 31 (q = 21) | Limit |
|---|---|---|---|---|
| `BLS_FASTAGGREGATEVERIFY` (58 000 + 3 000·q, plus the wrapper) | 67 034 | 73 034 | 121 034 | — |
| certificate check through `sccp_checkpoint` | 97 564 | 104 668 | 161 644 | 250 000 |
| … heartbeat rotation | 101 229 | 108 333 | 165 309 | 250 000 |
| … key-changing rotation (n → n) | 108 162 | 119 656 | 206 472 | 250 000 |
| `sccp_finalize` inline | 120 541 | 127 645 | 184 621 | 300 000 |
| `sccp_void_expired` inline | 120 074 | 127 178 | 184 154 | 285 000 |
| `sccp_apply_control` inline | 110 775 | 117 879 | 174 855 | 260 000 |
| largest inputs: `sccp_checkpoint` / `sccp_finalize` / `sccp_void_expired` / `sccp_apply_control` | 108 178 / 184 671 / 183 803 / 158 137 | 120 165 / 192 268 / 191 400 / 165 734 | 208 942 / 251 280 / 250 412 / 224 746 | as above |

The largest inputs are the `q` highest signers, full checkpoint slots, the
last leaf of a 512-leaf block under a history of 2^32 blocks, a 1024-byte
sender and four bucket activations. A certificate on the cheap path costs
26 435 gas as a heartbeat and 33 368 as a key change at n = 4; a finalize, void
or control against a stored checkpoint costs 42 264, 41 378 and 29 624.

Other steps: `sccp_void_frozen` at the minter 12 751 (24 586 when it activates
four buckets), the bucket's range of 512 nonces 7 029 and the minter's range
reply 6 227; burn 12 573 at the wallet and 39 395 at the minter (1024-byte
recipient); bucket consume 7 085, activation 1 848, unconsume 3 800; minter
`sccp_consumed` 10 787 (void 8 862), `sccp_consume_reverted` 4 455,
`sccp_retry` 11 238, a 16-bucket deployment 50 662; wallet receive 4 255
(7 273 with notification) and transfer 6 091; `sccp_init` at n = 31 47 362.

Value under the emulator's prices (a gas fee of 6 666 668 nanoton per 100 000
gas; storage 0 per bit and 135 per cell and 2^16 s):

| Quantity | TON |
|---|---|
| `BUCKET_FLOOR` / `MINTER_FLOOR` (100 years) | 0.1754 / 1.7215 |
| `finalize_required_value` into an active bucket; consumed with an existing wallet | 0.2057; 0.0108 |
| inline finalize flow consumed at n = 4 / 7 / 31 | 0.0110 / 0.0115 / 0.0153 |
| `finalize_required_value` activating 4 buckets; consumed with a new wallet | 0.9119; 0.7233 |
| `void_required_value`; consumed | 0.1975; 0.0098 |
| `void_frozen_required_value`; consumed for 512 nonces | 0.1795; 0.1778 |
| `burn_required_value`; consumed | 0.0061; 0.0050 |

A quote exceeds what a flow consumes because it prices every step at its gas
limit and the largest messages; the rest returns to `response`. At storage
prices of 1 per bit and 500 per cell, which the Rust mirror pins, the size
bounds (minter 265 cells and 124 000 bits, bucket 27 cells and 9 500 bits)
give `MINTER_FLOOR` about 12.34 TON, `BUCKET_FLOOR` about 1.107 TON and the
7-day quote grace about 0.0023 TON. The measured largest minter state is 261
cells and 121 916 bits.

## Interface notes

- Quotes are get methods: `checkpoint_required_value()`,
  `finalize_required_value(nonce)`, `void_required_value(nonce)`,
  `void_frozen_required_value(first_nonce)` (the nonce selects how many
  buckets the call activates), `deploy_buckets_required_value(count)`,
  `apply_control_required_value()` and `retry_required_value()`. Each returns
  the step value, the floor deficit at the stored balance and a 7-day storage
  grace; every unused nanoton returns to `response`. `minter_floor()` returns
  `MINTER_FLOOR` and `get_sccp_retry(nonce)` a recorded retry. The wallet
  exposes `burn_required_value()` (a burn must carry strictly more). Before
  debiting or forwarding, it requires an ordinary burn wrapper with exactly
  the 32-bit SCCP opcode and one reference, and traverses the entire recipient
  snake: ordinary cells, canonical 127-byte chunks, no extra bits/references,
  and 1..=1024 bytes total. The minter repeats these checks. Missing payload
  or wrong opcode is `BadBurnPayload`; malformed/exotic cell shapes are
  `BadSnake`; oversized recipients are `BadRecipient`. The admitted maximum
  bounds the notification size used in the fee quote.
- State is read with `get_sccp_state()`, `get_sccp_committee()`,
  `get_sccp_checkpoints()` and `get_bucket_address(index)` (§5.3.6).
- `iroha_sccp_wallet::pure::ton::minter_deploy_value` funds a deployment with
  `MINTER_FLOOR` at the pinned storage prices plus 25% and the init headroom.
- External events use `addr_none` as destination and bounce on action
  failure; bodies follow §5.3.3 and are stored inline or in one reference as
  the message size requires.
- Minter entries reserve `min(max(MINTER_FLOOR, before), before + value −
  step)`, burns and bucket replies reserve the prior balance, and buckets
  reserve `max(BUCKET_FLOOR, before)`, all with `raw_reserve` mode 2, so
  top-ups extend an account's life instead of being forwarded to the next
  caller.
- Buckets expose `get_bucket_data` (`minter`, `index`, `activated`, `hi`,
  `lo`), `get_bits` (`(hi, lo)`, flag `i` is bit `i` of `hi ‖ lo`),
  `is_consumed(nonce)` and `is_activated()`.
