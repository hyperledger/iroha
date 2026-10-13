# SCCP wallet source contract

`flow` owns the closed action/chain/phase vocabulary. `journal` retains each original signed
submission and its source evidence before recording the dispatch marker. CLI adapters in
`iroha_cli/src/sccp/flows.rs` verify the retained network, authority or destination and semantic
intent before recovery. Keys and transport authentication headers are runtime-only.

A crash before or after dispatch leaves the same original pending. Ordinary recovery observes
only. Explicit `--rebroadcast` reconciles first and may resend only the identical signed bytes;
it never changes a nonce, seqno, fee or proof. `--retry` prepares a new attempt only after a known
failed outcome, a confirmed pending settlement, or observed progress of a paid TON recovery.
Confirmation polling uses the original nested client configuration.

A confirmed Taira instruction is distinct from final settlement. Final message status records
release, bounce, refund or stranded custody separately. TON transfer completion requires the
exact successful event and shared source-chain proof. Its bounded linked-history cursor is a
four-KiB mutable hint bound to the original operation; corruption restarts discovery and cannot
authorize dispatch or completion. Deadline expiry with unknown execution remains pending. A terminal effect or maintenance
progress cannot free a still-live wallet envelope: completion also requires the original
wallet sequence to have advanced, and retains those observation coordinates.

`ton-retry` funds an existing immutable minter recovery id. Its retained row commits the original
cause; a changed or deleted row only supersedes that maintenance attempt. It does not establish
mint or burn completion. Deployment journals retain the first authenticated committee pin so a
restart cannot silently select a newer generation and deploy another address.

Finalization and independent committee upkeep share the same bounded journaled checkpoint and
newest-control sequence. Each invocation completes at most three prerequisites before retaining
progress for the next invocation. `finalize --emit` exports the next verified unsigned request
and signing hash (EIP-1559 bytes or the v5r1 request BoC), without loading a private key or sending.
Omitted RPC arguments use the nested client's endpoint lists, request deadlines and runtime
secret-header files; explicit lists replace only the public endpoint selection.

Tests cover the marker-before-send crash, lost response after dispatch, exact-byte replay,
semantic chain/phase refusal, terminal-evidence requirements, retained deployment identity,
discovery corruption and foreign-operation hints, and wallet envelope/recovery-row encodings.
