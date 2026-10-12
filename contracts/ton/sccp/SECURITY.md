# TON SCCP v1 contract security invariants

The current native BLS destination consists of `SccpTairaXorMinter`,
`SccpTairaXorWallet` and `SccpConsumedBucket`. Its contract is
[`specs/sccp.md`](../../../specs/sccp.md) §5.1 and §5.3. The executable checks
live in `tests/unit`; a passing component suite does not establish whole-network
or settlement readiness.

## Authority and finality

The minter has no owner, admin, upgrade path or authority setter. Its canonical
initial data binds the Taira NetworkId, consensus instance, route revision,
supply cap, initial native committee pin and wallet/bucket code. Initialization
checks the TON network, the complete canonical initial state, sorted native BLS
keys, committee geometry/root and validity horizon.

Every new certificate authenticates the complete 221-byte finality header `X`
and the original result-body digest through the native Commit preimage. The
bitmap carries exactly `n - f` signatures for a `3f + 1` committee. Curve,
subgroup, signature and canonical encoding checks belong to the native
`BLS_FASTAGGREGATEVERIFY` path. An offered key list cannot replace the stored current root.

The three retained checkpoint slots bind exact header ids and heights. A cached
header can use the established checkpoint relation only; a changed header at an
already retained height cannot inherit its authority. Conflicting authenticated
certificates latch equivocation. Inline use that would require a latch reverts;
`sccp_checkpoint` records it and emits `sccp_latched`. Rotations advance native generation state
under the current certificate and validate successor keys when the root changes.
The committee deadline uses the specified destination progress bound.

## Controls and proof binding

`sccp_apply_control` proves the complete 199-byte control leaf under a native certificate.
It binds the Taira network, destination lane/address/revision, control nonce,
pause tracks and effective expiry. `control_nonce` strictly increases. Parliament pause
and the bounded fast pause are independent; only their effective combination
blocks finalization. Checkpoints, voids, burns and further authenticated controls
remain governed by their own checks.

Direct and historical message proofs bind the exact block root and message
count; historical mode additionally proves the block under the certified history
root. Transfer decoding checks destination, revision, recipient and amount.
Deadline, supply-cap and consumed-nonce checks occur before minting.

## Canonical cells

`SnakeBytes`, hash paths and native key chunks have one canonical shape, including
exact bits, references, maximal chunks and complete consumption. Every chunk must
be ordinary; library and other exotic cells cannot install externally mutable committee
keys or substitute a different proof graph. TON integer fields retain their full
protocol width; wallet quotes and nonces must not be narrowed to signed 64 bits.

## Replay and supply accounting

Nonce `k` uses bucket `k >> 9` and bit `k & 511`. Buckets accept activation and
consumption only from their minter. Canonical deployment starts inactive, and an
already activated index is never activated again. Recreating a deleted bucket
therefore cannot clear the authority required to replay a mint or void.

Finalization reserves pending supply before asking a bucket to consume. A
successful response transfers pending supply to total supply and sends a
bounceable mint. Failed or duplicate consumption releases pending supply;
bounced mint delivery removes the unminted supply and requests unconsumption.
Recorded retries preserve failed unconsumption/activation work. Callback senders
are checked against the canonical bucket or wallet address. These rules rely on
TON's authenticated bounced-message semantics.

Burns require the canonical SCCP burn payload. Only the owner's canonical wallet
can send the accepted notification. A rejected burn restores the wallet balance.
Frozen-range voids consume their bounded range atomically without minting.

## Value and validation

The fee model bounds verification, callback, forwarding and storage costs before
starting work. `raw_reserve` retains `MINTER_FLOOR` and `BUCKET_FLOOR`;
per-operation quotes cover retained minter,
bucket and wallet state. Current measured gas belongs in `gas-baseline.json` and
must be regenerated with the pinned Acton toolchain after contract changes.

The emulator suite covers native BLS verification and rotation, checkpoint
retention/latching, controls, deadline/cap boundaries, canonical cells, replay,
bounces, retry accounting, burns and required value. The Rust pure verification
and wallet suites exercise the same certificate/proof relations and exact
contract encodings.

The pinned toolchain is Acton 1.2.0 with Tolk 1.4.2.
`fixtures/sccp/ton_stateinit_v1.json` records the compiled code and native initial
state/address golden values.
