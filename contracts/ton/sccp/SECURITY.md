# TON SCCP v1 contract security invariants

Scope: `SccpTairaXorMinter`, `SccpTairaXorWallet` and `SccpConsumedBucket`
(`specs/sccp.md` revision 4, §5.1 and §5.3). Build, test and golden tooling is
described in
[`docs/source/sccp_ton_release_builder.md`](../../../docs/source/sccp_ton_release_builder.md).
The Acton emulator suite in `tests/unit` exercises these invariants; the
TON network rules they rely on are named where they matter.

## Authority

- There is no owner, admin, upgrade path, code change or setter. Minter state
  changes only through messages whose authority is verified from attested
  Taira state, plus the counters those messages drive.
- `minting_paused` changes only through `sccp_apply_control` /
  `sccp_apply_control_historical` (ops `0x53434d31` / `0x53434d32`). The
  message proves a Parliament control leaf (§3.4) in a Taira attestation
  signed by at least `t` members of an accepted roster. The leaf binds
  `lane_bytes(sora-taira, ton-mainnet)` with the stored `taira_network_id`,
  destination word = the minter's own account id, the minter's
  `route_revision`, `control_nonce` and `paused`. A control leaf for another
  network, destination, revision or Taira network, and a transfer leaf
  offered as a control, fail the inclusion proof.
- `control_nonce` strictly increases: stale and equal nonces are rejected,
  gaps are allowed. An applied control sets `minting_paused` and
  `control_nonce`, increments `op_count` and emits `sccp_control_applied`.
- There are no guardian keys, no roster-signed pause and no one-way breaker.
  The pause blocks finalize only; voids, rotations, burns and further
  controls stay open while paused.

## Initialization

- The minter address is the hash of its canonical initial data (§5.3.1):
  zero counters and supplies, `minting_paused = false`, no previous roster,
  and a roster equal to Taira's pinned generation record in maximal 6-address
  chunks. Taira recomputes this address at `RegisterRoute`.
- `sccp_init` is permissionless and runs once. It requires `GLOBALID = −239`
  and canonical initial data, recomputes the §3.7 digest from the stored
  roster fields and `taira_network_id` (checking `n`, `t` and member order),
  requires it to equal both `roster.digest` and `config.initial_digest`,
  requires `generation = initial_generation`, and applies the §5.1.5 validity
  bounds. Every state-changing operation other than `top_up` throws until
  then (finalize, void, frozen void, rotation, control, bucket deployment,
  retry and burn are each tested); TEP-89 `provide_wallet_address` answers
  regardless.

## Rosters and signatures

- An attestation is accepted from the current roster while
  `now ≤ valid_until_ms`, or from the previous roster within its grace-capped
  validity (`min(valid_until_ms, rotation time + 24 h)`). Members always come
  from storage, never from the message.
- A signature set is a `uint32` bitmap with bits `≥ n` zero, one 521-bit cell
  per set bit in ascending order and nothing else. Each signature needs a
  nonzero member, `1 ≤ r < N`, `1 ≤ s ≤ N/2` and `v ∈ {27, 28}`; `ECRECOVER`
  receives `v − 27`, and the recovered address (low 160 bits of
  `keccak256(x ‖ y)`) must equal the member. At least `t` must verify.
- A rotation is signed by the current roster only, carries the announced next
  digest, advances the generation by exactly one, sets `valid_from_ms` to the
  attestation timestamp and satisfies the §5.1.5 bounds. The old roster moves
  to `prev_roster` with its grace-capped expiry, and `sccp_roster_rotated`
  reports the installed generation, digest and expiry.

## Canonical cells

- `SnakeBytes`, `HashChunk` and `MemberChunk` parsers accept exactly one shape
  (§5.3.2): maximal chunks, no empty chunk, no extra bits or references.
- Every chunk must be an ordinary cell; exotic cells throw `BadSnake`. This
  matters for library references in particular: `CTOS` resolves them
  transparently, so without the check a relayer could install a roster whose
  member list points to a public masterchain library with canonical content,
  and unpublishing that library later would make every roster read throw and
  freeze the minter. `sccp_init` and `sccp_rotate` therefore store only member
  lists that were fully parsed as ordinary canonical cells.

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
  from its own balance. Ranges (`void_frozen`, one bucket, `count ≤ 512`) are
  set all-or-nothing and a bounced `sccp_range_consumed` clears them.

## Supply accounting

- Finalize checks `total_supply + pending_supply + amount ≤ max_supply` and
  reserves `pending_supply` before contacting the bucket. On `sccp_consumed`
  the pending amount moves to `total_supply` and a bounceable
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
- A burn requires the `sccp_burn_to_taira` custom payload; plain TEP-74 burns
  are rejected by the wallet. The minter requires the sender to be the
  canonical wallet of the owner, the owner to be `addr_std` in workchain 0
  without anycast, and a canonical 1..=1024-byte recipient. Any failure
  bounces `burn_notification`, and the wallet restores the balance.

## Value and storage rent

- Step values are computed at entry from `GETGASFEE`, `GETFORWARDFEE` and
  `GETSTORAGEFEE`; there is no fixed TON amount. The per-step gas limits are
  measured maxima with about 20% headroom, and `tests/unit/sccp-fees.test.tolk`
  fails when a measured step exceeds its limit.
- Every external-out event is sent with bounce on action failure: an event
  that cannot be paid aborts the step and bounces its inbound message (a burn
  is then restored by the wallet, a control refunded to its relayer, a reply
  reverted by its bucket). No step completes without its event, and no burn
  is destroyed without a Taira record.
- Minter entries (finalize, void, frozen void, bucket deployment, control,
  rotation, retry) require `value ≥ step + max(0, MINTER_FLOOR − stored)`,
  where `stored` is the balance before the storage phase, checked before any
  signature. They reserve `min(max(MINTER_FLOOR, before), before + value −
  step)` with `raw_reserve` mode 2, so the floor is topped up from the
  caller's value but never from what the step needs.
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
  `minter_floor()` reports `MINTER_FLOOR`; the CLI funds a deployment with it
  at mainnet prices plus 25% and adds a margin to every quote.

## Chain identity and artifacts

- `GLOBALID = −239` is required by `sccp_init`, `sccp_finalize*`,
  `sccp_void_expired*` and `sccp_apply_control*`.
- Contracts are built natively with Acton 1.2.0 bundling Tolk 1.4.2, pinned by
  archive SHA-256 in `scripts/ton_sccp_builder.py`; no Docker or container
  runtime is involved. `fixtures/sccp/ton_stateinit_v1.json` pins the code
  cell hashes and depths, the canonical initial data and the resulting
  workchain-0 addresses. `scripts/generate_ton_sccp_stateinit_golden.py
  --check` recomputes it in Python and through the contracts' own Tolk types
  (`scripts/stateinit-golden.tolk`) and rejects any drift.
