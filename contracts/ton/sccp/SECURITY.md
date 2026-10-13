# TON SCCP v1 contract security invariants

Scope: `SccpTairaXorMinter`, `SccpTairaXorWallet` and `SccpConsumedBucket`
(`specs/sccp.md` revision 5, §5.1 and §5.3). Build, test and golden tooling is
described in
[`docs/source/sccp_ton_release_builder.md`](../../../docs/source/sccp_ton_release_builder.md).
The Acton emulator suite in `tests/unit` exercises these invariants; the
TON network rules they rely on are named where they matter.

## Authority

- There is no owner, admin, guardian, upgrade path, code change or setter, and
  there are no bridge keys. The minter trusts one thing: a Sumeragi `CommitQC`
  of Taira's current committee generation over a finality header `X`. Minter
  state changes only through messages verified against such a certificate,
  plus the counters and replies those messages drive.
- The minting pause changes only through `sccp_apply_control` /
  `sccp_apply_control_checkpoint` (ops `0x53434d31` / `0x53434d32`). The
  message proves a 199-byte control leaf (§3.4) in a certified Taira block. The
  minter computes the leaf from its own values: `lane_bytes(sora-taira,
  ton-mainnet)` with the stored `taira_network_id`, destination word = its own
  account id, and its `route_revision`; the message supplies `control_nonce`,
  the track, `parliament_paused`, `fast_pause_until_ms`, the certificate id and
  the effect hash. A control for another network, destination, revision or
  Taira network, and a transfer leaf offered as a control, fail the inclusion
  proof (`BadProof`); a proved leaf that violates a §3.4 constraint is
  `BadControl`.
- `control_nonce` strictly increases: stale and equal nonces are `StaleControl`,
  gaps are allowed. An applied control sets `parliament_paused`, the clamped
  `fast_pause_until_ms` (at most `now_ms + MAX_FAST_PAUSE_MS`, saturating) and
  `control_nonce`, counts one operation and emits `sccp_control_applied`.
- The effective pause (`parliament_paused`, or `now_ms < fast_pause_until_ms`)
  blocks finalize only. Voids, checkpoints, rotations, burns and further
  controls stay open while paused; a fast pause ends by itself.

## Initialization

- The minter address is the hash of its canonical initial data (§5.3.1):
  `initialized = false`, `equivocated = false`, zero counters and supplies, no
  pause, no checkpoint, empty `retries`, and a committee equal to the pinned
  generation with its keys in maximal `KeyChunk`s and `high = start − 1`. Taira
  recomputes this address at `RegisterRoute`, so the stored committee is bound
  to the pin by construction.
- `sccp_init` is permissionless and runs once. It requires `GLOBALID = −239`,
  canonical initial data, a valid `n` (4, 7, …, 31) with exactly `n` keys in
  ordinary canonical cells, strictly ascending as byte strings (`SDLEXCMP`),
  the keccak committee root of the stored keys equal to `committee.root =
  initial.root`, the remaining committee fields equal to the pin, and `now_ms <
  until_ms ≤ now_ms + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`. Every
  state-changing operation other than `top_up` throws `NotInitialized` until
  then; TEP-89 `provide_wallet_address` answers regardless.

## Certificates

- A certificate is one BLS12-381 min-pk aggregate of exactly `q = n − f`
  signers. Signer keys always come from storage, selected by the set bits of
  `signers` in ascending order, never from the message.
- Checks run in the order of §5.1.3, and the first failure is the exit code:
  the cell shapes (`BadCertificate`, `BadHeader`; an exotic cell is
  `BadSnake`); X1–X7 with `ACTIVE` and `X.network_id` (`BadHeader`; X6 bounds a
  rotation's height and generation at `2^64 − 2`); the generation and committee
  root of the current generation (`CommitteeNotAccepted`); `signers >> n = 0`
  and `popcount(signers) = q` (`BadCertificate`); the identity signature; the
  cheap path; the opcode.
- The compressed identity signature (`0xc0` followed by 95 zero bytes) is
  `BadSignature` before the checkpoint lookup: the opcode does not enforce `σ ≠
  O`, and the cheap path never reaches it. All 96 bytes are compared.
- The cheap path is mandatory: when `checkpoint[X.height] = keccak256(X)` is
  stored, the certificate is accepted without a signature check and without an
  `sccp_certificate` event. It grants nothing new, because the stored id
  already authenticates `X`.
- On the full path the minter builds `m` as a slice of exactly 256 bits and
  runs `DUP TLEN UNTUPLEVAR BLS_FASTAGGREGATEVERIFY` over `[k_1 … k_q, q, m,
  σ]`, with keys of exactly 384 bits and a signature of exactly 768 bits. The
  opcode's result is the only verdict on keys, aggregate and signature: `false`
  is `BadSignature`. The minter runs no key or aggregate check of its own. The
  suite pins that the opcode answers `false` for a signer key with the
  infinity flag or without the compression flag, with `x ≥ p` or `x = 0`, on
  the curve but outside G1 (alone, and as two keys whose sum is the genuine
  aggregate), for keys that sum to the identity and for the identity key
  alone; a root Taira admitted holds no such key (§3.8).
- Every step that completes after a full verification, a latch included,
  publishes the certificate (`sccp_certificate`), so a certificate that the
  minter acted on is always available as evidence.

## Committee state machine

- `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.until_ms`. A minter that is not `Live`
  is `Frozen` for good: an entry point that needs `Live` throws `Equivocated`
  (433) when latched and `CommitteeNotAccepted` (402) when expired.
- `sccp_checkpoint` records a checkpoint (three slots; a stored height is never
  overwritten, and a fourth enters only above the lowest stored height, which
  it evicts), raises `high`, and at a `ROTATION` header installs the successor
  with generation + 1, `start = X.height + 1` and `until_ms = min(X.timestamp_ms,
  now_ms) + X.validity_ms`, saturating at `2^64 − 1`. A future-dated rotation
  therefore grants no more than `validity_ms` from the minter's own clock. A
  certificate that changes nothing throws `NothingToDo`.
- A key-changing rotation requires `next_keys`, parsed as ordinary canonical
  `KeyChunk`s (at most 16) and hashed against `X.next_committee_root`
  (`BadCommittee`); a heartbeat keeps the stored chain and does not read
  `next_keys`. A rotation replaces the key chain without retaining old
  generations. Ten thousand rotations preserve the fixed layout; physical
  cell-count checks account for code/data deduplication when the initial
  empty checkpoint cell is replaced.
- Violations V1 (another header at a stored height), V2 (a height below
  `cur.start`) and V3 (a rotation below `cur.high`) latch: `sccp_checkpoint`
  stores `equivocated = true` and `cur.until_ms = 0`, emits `sccp_latched` and
  returns the excess without throwing. An inline entry point that meets V1–V3
  throws `LatchRequired` (434) and changes nothing; only `sccp_checkpoint`
  latches.
- A stored checkpoint is usable by a `*_checkpoint` entry point only under U1
  (it is of the current generation) or U2 (it is the handoff that installed the
  current generation); otherwise `CommitteeNotAccepted`. An unknown or evicted
  checkpoint is `UnknownCheckpoint`.
- After a latch or an expiry, minted balances stay transferable and burnable,
  and unminted nonces are voided with `sccp_void_frozen`. A mint in flight when
  the latch fires is not minted: the minter sends `sccp_unconsume` and releases
  the pending supply. A void in flight completes.

## Canonical cells

- `SnakeBytes`, `HashChunk` and `KeyChunk` parsers accept exactly one shape
  (§5.3.2): maximal chunks, no empty chunk, no extra bits or references. The
  certificate and proof cells are opened by hand with exact bit and reference
  counts. A malformed shape is `BadSnake` (or `BadCertificate` / `BadHeader`
  for the certificate cells); a well-formed cell that fails a proof rule is
  `BadProof`.
- Every cell taken from a message must be an ordinary cell; exotic cells throw
  `BadSnake`. This matters for library references in particular: `CTOS`
  resolves them transparently, so without the check a relayer could install a
  committee whose key list points to a public masterchain library with
  canonical content, and unpublishing that library later would make every key
  read throw and freeze the minter. `sccp_init` and `sccp_checkpoint` therefore
  store only key lists that were fully parsed as ordinary canonical cells.
- Consumption tails are parsed as ordinary cells with no references and the
  exact mint/void layout before the bucket changes flags or echoes them, and
  again in both minter reply handlers. A malformed or library tail is
  `BadSnake`; authenticated origin does not bypass cell-shape validation.

## Replay protection

- Nonce `k` lives in bucket `k >> 9`, flag `k & 511`. A bucket sets or clears
  flags only for messages from its minter, and only once it is activated.
- A bucket's canonical StateInit has `activated = false` and clear flags, so
  anyone can deploy it. Only `sccp_activate_bucket` from the minter (with a
  matching index) sets `activated`. The minter sends it only for bucket
  indices `≥ deployed_buckets`, at most 4 ahead, advancing `deployed_buckets`
  in the same transaction, or through a recorded retry of an activation that
  bounced. It therefore activates each index once, and never a bucket that was
  ever active. A bucket deployed early by a stranger is activated by the
  minter's first use; a bucket deleted for unpaid rent (excluded in practice
  by `BUCKET_FLOOR`) and redeployed by anyone stays inactive. Its nonces stay
  unfinalizable and unvoidable, so already-minted nonces never become
  voidable (and refundable on Taira) again. Unfreezing with the exact state
  restores it.
- `sccp_consume` never carries a StateInit; activations precede it in the same
  minter transaction, and messages between two accounts arrive in order.
- The minter accepts `sccp_consumed`, `sccp_already_consumed`,
  `sccp_consume_reverted`, `sccp_range_consumed` and `sccp_range_rejected`
  only from the bucket address recomputed from `bucket_code`, the nonce and
  its own address.
- A new flag is answered with a bounceable `sccp_consumed`; if the minter's
  handler fails, the bounce makes the bucket clear the flag and report
  `sccp_consume_reverted`. A set flag is answered with a bounceable
  `sccp_already_consumed`; its bounce also makes the bucket report
  `sccp_consume_reverted`. The bucket pays these bounce handlers and reports
  from its own balance. Ranges (`sccp_void_frozen`, one bucket, `count ≤ 512`)
  are set all-or-nothing and a bounced `sccp_range_consumed` clears them.
- Outbound source nonces are `0 ..= 2^64 − 2`. At a stored `outbound_nonce` of
  `2^64 − 1` every burn towards Taira answers `BadNonce` (425) before any
  state change, and the bounce restores the wallet balance, so no source nonce
  is used twice. `op_count` saturates at `2^64 − 1`.

## Supply accounting

- A finalize or void checks the payload and its recipient before it obtains
  `X` (the required value depends on the payload nonce), then `Live`, the
  pause (mint only), the block reference, the deadline and the leaf path.
  Finalize then checks `total_supply + pending_supply + amount ≤ max_supply`
  and reserves `pending_supply` before contacting the bucket. On
  `sccp_consumed` the pending amount moves to `total_supply` and a bounceable
  `internal_transfer` (`query_id = nonce`) mints to the recipient's wallet.
- A bounced `sccp_consume`, an `sccp_already_consumed` and an
  `sccp_consume_reverted` each release the pending amount, and each pending
  amount is released exactly once: a revert is sent only when the minter's
  handling of the reply aborted, so nothing was released or moved.
- A bounced `internal_transfer` burns the unminted supply and sends a
  bounceable `sccp_unconsume{nonce}` (or records it when the balance cannot
  pay it), so the message becomes finalizable again. A bounced unconsume or
  activation is recorded in `retries`; the permissionless `sccp_retry`
  deletes the record and resends the message, and a bounce records it again.
  A record therefore never runs twice, which matters because a second
  unconsume after a re-mint would clear a minted flag. No nonce stays
  consumed without a mint, a void or a recorded unconsume.
- These rules rely on the TON rule that only the network sets the `bounced`
  flag, as the TEP-74 reference contracts do; the minter and the bucket run
  their bounce handlers on their own balance, which only bounces of their own
  messages can reach.
- Residual cases: a bounce whose value cannot pay even its own forwarding is
  not delivered (TON drops it), and a `sccp_consume_reverted` that the minter
  could not process would leave the amount pending, reducing cap headroom
  only. Both need a fee rise between steps far beyond the per-step headroom.
- Inbound payloads must target this deployment: route revision, route id,
  `amount < 2^96`, and a `ton_account36` recipient in workchain 0 that is
  nonzero and not the minter itself.
- `sccp_void_frozen` checks its range (`BadRange`) and then requires `Frozen`
  (`NotFrozen`): nonces of a `Live` minter are voided only one at a time,
  through a proved expired message.
- Before debiting or forwarding a burn, the wallet opens the mandatory
  `sccp_burn_to_taira` wrapper as an ordinary cell with exactly its 32-bit
  opcode and one reference, and validates the **entire** recipient snake:
  ordinary cells, canonical 127-byte nonterminal chunks, a 1..=127-byte
  terminal chunk, no extra bits or references, and 1..=1024 bytes in total.
  Missing payload or wrong opcode is `BadBurnPayload`; exotic or malformed
  wrapper/snake shapes are `BadSnake`; an oversized recipient is
  `BadRecipient`. These failures leave the wallet balance unchanged. The
  bounded body makes the notification forwarding fee a true upper bound.
- The minter repeats the same wrapper and recipient checks, requires the
  sender to be the canonical wallet of the owner, the owner to be `addr_std`
  in workchain 0 without anycast and `0 < amount < 2^96`. A minter failure
  bounces `burn_notification`, and the wallet restores the balance. Burns
  work while paused, after expiry and after a latch.

## Value and storage rent

- Step values are computed at entry from `GETGASFEE`, `GETFORWARDFEE` and
  `GETSTORAGEFEE`; there is no fixed TON amount. The per-step gas limits cover
  the measured maxima (n = 31, the 21 highest signers, the largest proofs)
  with headroom; `tests/unit/sccp-fees.test.tolk` fails when a measured step
  exceeds its limit, and the builder fails a run above 1.1 x
  `gas-baseline.json`.
- Every external-out event is sent with bounce on action failure: an event
  that cannot be paid aborts the step and bounces its inbound message (a burn
  is then restored by the wallet, a control refunded to its relayer, a reply
  reverted by its bucket). No step completes without its event, and no burn
  is destroyed without a Taira record.
- Minter entries (checkpoint, finalize, void, frozen void, bucket deployment,
  control, retry) require `value ≥ step + max(0, MINTER_FLOOR − stored)`,
  where `stored` is the balance before the storage phase, checked before any
  signature. They reserve `min(max(MINTER_FLOOR, before), before + value −
  step)` with `raw_reserve` mode 2, so the floor is topped up from the
  caller's value but never from what the step needs. A latch keeps the same
  accounting and refunds the rest.
- Burns and the bucket replies to the minter reserve only the prior balance
  and never pay toward the floor, so a minter below its floor (storage drift,
  a storage-price increase, an underfunded deployment) cannot make a burn
  fail. Buckets reserve `max(BUCKET_FLOOR, prior balance)`.
- Top-ups and prior balance are never forwarded to a later caller. The
  minter sends without a reserve only where nothing carries the balance: the
  TEP-89 answer (mode 64), the `sccp_voided` event of a range reply (covered
  by the value attached to the range request) and the bounce handlers.
- The `*_required_value` get methods quote with the same stored balance plus
  7 days of maximal minter storage, so an exact quote stays valid as time
  passes; it fails cheaply (before signatures, bounced) only when other
  transactions collect more storage than that between quote and send.
  `minter_floor()` reports `MINTER_FLOOR` for the maximal minter state (265
  cells, 124 000 bits) over 100 years at current prices.

## Chain identity and artifacts

- `GLOBALID = −239` is required by every state-changing entry point:
  `sccp_init`, `sccp_checkpoint`, `sccp_finalize*`, `sccp_void_expired*`,
  `sccp_void_frozen`, `sccp_apply_control*`, `sccp_deploy_buckets`,
  `sccp_retry` and `burn_notification`.
- Contracts are built natively with Acton 1.2.0 bundling Tolk 1.4.2, pinned by
  archive SHA-256 in `scripts/ton_sccp_builder.py`; no Docker or container
  runtime is involved. `fixtures/sccp/ton_stateinit_v1.json` pins the code
  cell hashes and depths, the canonical initial data and the resulting
  workchain-0 addresses. `scripts/generate_ton_sccp_stateinit_golden.py
  --check` recomputes it in Python and through the contracts' own Tolk types
  (`scripts/stateinit-golden.tolk`) and rejects any drift.
