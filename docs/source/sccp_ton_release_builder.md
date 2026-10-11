# SCCP v1 TON contracts: build, tests and artifacts

This note covers the repository tooling for the TON destination of SCCP v1
(`specs/sccp.md` revision 4, §5.3–§5.5). The contracts live in
[`contracts/ton/sccp`](../../contracts/ton/sccp):

| Contract | Source | Role |
|---|---|---|
| `SccpTairaXorMinter` | `contracts/SccpTairaXorMinter.tolk` | TEP-74 / TEP-89 Jetton master with the bridge built in |
| `SccpTairaXorWallet` | `contracts/SccpTairaXorWallet.tolk` | TEP-74 wallet; burns require the `sccp_burn_to_taira` payload |
| `SccpConsumedBucket` | `contracts/SccpConsumedBucket.tolk` | 512 replay flags of one minter; accepts flags only after the minter's one-time activation |

Shared modules: `sccp-constants`, `sccp-errors`, `sccp-messages`,
`sccp-storage` (exact TL-B of §5.3.1–§5.3.3), `sccp-crypto` (`GLOBALID`,
`ECRECOVER` and `HASHEXT` keccak asm wrappers), `sccp-cells` (canonical snake,
hash-chunk and member-chunk cells), `sccp-verify` (§3 digests, leaves, paths,
payloads, signature sets), `sccp-fees` (§5.3.5) and `sccp-addresses`.

There is no owner, admin, upgrade path or setter. The minting pause changes
only through `sccp_apply_control` / `sccp_apply_control_historical` with a
Parliament control leaf attested by the Taira bridge roster (§5.1.6).

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
`wrappers/*.gen.tolk`), the emulator suite `acton test tests/unit`, and the
StateInit golden check. Wrapper names are the PascalCase contract ids.

For local end-to-end runs against a full TON node emulation, use
`acton simulator`. The four-validator TON lane scenarios belong to the
`integration_tests/tests/sccp_lanes/` harness, which does not have them yet
(TODO(ws36)).

## Test vectors

Tolk has no secp256k1 signing, so `sccp-test-vectors.gen.tolk` carries 31
deterministic test keys (sorted by address) with one fixed ECDSA nonce each,
plus golden values computed by the independent Python implementation of §3 in
`ton_sccp_builder.py` (domain separator, attestation digest, roster digests
with keyless slots and six chunks, TON-target control leaves, inbound and
outbound payload hashes and message ids, transfer leaf, promote-odd Merkle
paths, history leaf, and an independently signed ECDSA vector). The Python
implementation first pins itself against every constant printed in the spec,
including both `SCCP/CONTROL/V1` example leaves. Tests sign any digest with
two modular products, so the suite runs in seconds.

## StateInit golden

`fixtures/sccp/ton_stateinit_v1.json` pins, for two fixed rosters
(`n = 4`, and `n = 31` with three keyless slots and six member chunks) under
NetworkId `0x11…11`:

- the code cell hash, depth, cell count and bit count of the minter, wallet
  and bucket;
- every roster field, the §3.7 digest, and each cell of the canonical initial
  data (§5.3.1) with its data bits, hash, depth and references;
- the StateInit hash and the workchain-0 address;
- the wallet address of owner `0:abab…ab` and the addresses of buckets 0 and 1
  (canonical data: `activated = false`, flags clear).

The generator parses the compiled code BoCs, recomputes everything in Python,
runs `contracts/ton/sccp/scripts/stateinit-golden.tolk` (the same values from
the contracts' own Tolk types via `acton script`) and requires exact agreement.
The Python tests and the Rust `iroha_sccp::v1::ton_cell` tests recompute the
data hash and every address of both vectors from the recorded code hashes and
depths alone, which is exactly what Taira's `RegisterRoute` does. Any contract
change alters the code hashes: regenerate the fixture with
`python3 scripts/generate_ton_sccp_stateinit_golden.py` and update the `n4`
values pinned in `ton_cell.rs`.

## Emulator suite (`tests/unit`)

118 Acton tests cover every §5.3 rule and §11 Contracts bullet, including:
`sccp_init` (digest, generation, `n`/`t`/order, validity bounds, chain id,
non-canonical data, library-cell members, double init, every operation before
init); direct and historical finalize; deadline and cap edges; bucket
boundaries, the four-ahead activation rule and bucket activation (a bucket
deployed early by a stranger stays inactive until the minter's first use; a
deleted bucket redeployed by a third party rejects finalize, `void_expired`
and `void_frozen`, so no minted nonce becomes voidable); duplicate and
parallel duplicate finalizes and pending supply; bounced `sccp_consume`,
bounced `internal_transfer` then unconsume and re-finalization, bounced
`sccp_consumed` (with a bounce carrying little value), a forced action failure
of `sccp_consumed` (a forwarding-price rise between the steps) and a bounced
`sccp_already_consumed`, each releasing the pending supply through
`sccp_consume_reverted`, bounced `sccp_range_consumed`; recorded retries (a
bounced unconsume while the bucket is gone, a bounced activation, an
unaffordable unconsume) and `sccp_retry`; value safety (exact quotes taken
days before the send at a minter sitting at its floor, for every entry; the
entry minimum and the storage grace; a stale quote after a burn collects more
storage than the grace; underfunded calls failing before any signature check;
burns below the floor; a burn whose event cannot be paid bounces and restores
the wallet; a control on an under-floor minter); signature malleability
(high-S, `v ∉ {27,28}`, order, keyless slots, extra or missing cells); proof
and leaf negatives; voids (`void_expired` direct and historical, deadline
edge, nonce argument, `void_frozen` range, frozen and activation rules);
rotations (grace cap, sequential replay, current-roster-only, digest,
timestamp, validity, skew and `validFromMs` bounds, library-cell member
chunks, the `sccp_roster_rotated` event); controls (pause, resume, stale,
equal and zero nonces, gaps, historical mode, foreign network, destination,
revision or Taira network, a transfer leaf offered as a control, burns,
rotations and voids open while paused, frozen destinations); burns (payload
and message id, sequential nonce, 1024-byte recipient, plain-burn and
foreign-payload rejection, recipient length, shape and library cells,
workchain rule with balance restore); canonical cells (a library reference
with canonical content is rejected at every chunk of a snake, hash path or
member list); TEP-74 transfers and bounces, TEP-89 and the TEP-64 content;
and the fee constants.

## Measured gas and value (§5.4)

Measured with the Acton 1.2.0 emulator and its default network config
(`tests/unit/sccp-fees.test.tolk` and `sccp-bucket.test.tolk` print these
values and fail when a per-step limit in `sccp-fees.tolk` is exceeded). Gas is
the compute gas of the named step; value is what the finalizer paid net of the
returned excess.

| Operation | n = 4 (t = 3) | n = 31 (t = 21) | §5.4 estimate |
|---|---|---|---|
| finalize, minter step (direct) | 45 192 gas | 106 423 gas | ≈15k / ≈50k |
| finalize, minter step (historical, block path 9, history path 32, 1024-byte sender) | — | 173 884 gas | +2k–5k |
| finalize total value, bucket and wallet exist | 0.0051 TON | 0.0094 TON | 0.02–0.05 TON |
| finalize total value activating 4 buckets and deploying the wallet | — | 0.6468 TON | — |
| void expired, minter step (historical worst case) | — | 165 221 gas | as finalize |
| apply control, minter step (direct / historical worst case) | 30 888 gas | 97 989 / 146 066 gas | ≈12k / ≈45k |
| rotation, minter step (n → n) | 33 649 gas | 118 601 gas | ≈15k / ≈60k |
| burn: wallet / minter (1024-byte recipient) | 5 000 / 38 501 gas | — | burn + ≈10k |
| void frozen (512 nonces): minter / bucket / reply | 12 686 / 7 029 / 5 882 gas; 24 387 at the minter when it activates 4 buckets | — | ≈10k + round trip |
| other steps | bucket consume 6 155, bucket activation 1 848, minter `sccp_consumed` 9 744 (void 7 929), `sccp_consume_reverted` 4 244, `sccp_retry` 11 123, wallet receive 4 155 (7 173 with notification), wallet transfer 5 991, bucket unconsume 3 800, 16-bucket deploy 50 449 | | |

An underfunded n = 31 finalize fails `NotEnoughValue` after 13 028 gas, before
any signature check. Signature checks dominate: `ECRECOVER` is 1 526 gas each
and the per-signature parsing and bound checks add about 2 400 gas.

The emulator's storage prices (0 per bit, 135 per cell and 2^16 s) give
`BUCKET_FLOOR` 0.1754 TON and `MINTER_FLOOR` 1.3317 TON (100 years). At TON
mainnet prices (1 per bit, 500 per cell) the size bounds give `BUCKET_FLOOR`
about 1.083 TON and `MINTER_FLOOR` about 9.84 TON, and the 7-day quote grace
about 0.0019 TON. A new wallet keeps 0.0052 TON (emulator); a finalize that
activates a bucket pays that bucket's floor once, shared by its 512 nonces.

## Interface notes

- Quotes are get methods: `finalize_required_value(nonce)`,
  `void_required_value(nonce)`, `void_frozen_required_value(first_nonce)`
  (the nonce selects how many buckets the call activates),
  `deploy_buckets_required_value(count)`, `apply_control_required_value()`,
  `rotate_required_value()` and `retry_required_value()`. Each returns the
  step value, the floor deficit at the stored balance and a 7-day storage
  grace; every unused nanoton returns to `response`. `minter_floor()` returns
  `MINTER_FLOOR` and `get_sccp_retry(nonce)` a recorded retry. The wallet
  exposes `burn_required_value()` (a burn must carry strictly more).
- `iroha sccp deploy --network ton-mainnet` funds the minter with
  `MINTER_FLOOR` at mainnet prices plus 25%
  (`iroha_sccp_wallet::pure::ton::minter_deploy_value`); `finalize` and
  `roster-sync` attach the minter's quote plus 10% (at least 0.05 TON), and
  `roster-sync` sends every rotation of a run in one wallet message.
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
