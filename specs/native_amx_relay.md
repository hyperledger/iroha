# Native AMX relay service

`irohad::amx_relay` owns local signing, dispatch and recovery. The AMX consensus
instructions and `iroha_core::query::native_receipts` remain the authority for
obligations and source evidence. The service starts after authenticated State
replay and joins the node supervisor. Emergency Fast inspection never starts it.

## Custody and routing

The file-only `[amx_relay]` table has these local settings:

| Field | Default | Meaning |
| --- | --- | --- |
| `journal_dir` | `./storage/amx/workflows` | Existing owner-private `FileWorkflowStorage` directory |
| `poll_interval_ms` | 2000 | Observation cadence, bounded to 1–60000 ms |
| `max_source_heights_per_pass` | 32 | Nonzero bound, at most 32 |
| `max_finality_proof_reads` | 64 | Nonzero bound, at most 64 per observation |
| `routes` | `[]` | At most 32 explicitly provisioned destinations |

Each `[[amx_relay.routes]]` contains `network_id`, `chain_id`, `scope_json`, `authority`,
`account_config`, `signed_genesis`, `signed_genesis_sha256`, `genesis_public_key`
and `fee_payment_json`. Each JSON field is one string containing its exact native
Norito type. `SumeragiRootScope` retains Global's required `"value":null`, or
Dataspace's exact parent network and full dataspace ID. `FeePaymentIntent` retains
its required `gas_limit` field (`null` for native carriers without executable gas).
TOML cannot represent these null values; the signed wire contracts are unchanged.
Other fields use
their native Norito JSON/TOML types; the digest is exactly 64 lowercase hexadecimal
characters. File paths resolve relative to the
node configuration. A route's SDK account file is loaded without environment
aliases and must match all three authority/network/chain pins. The account must
already hold the assets authorized by its exact signature-bound fee intent.
There is no validator-key fallback, automatic minting or inferred sponsor.

Signed genesis bytes must match the independently configured digest and signer.
The existing genesis authenticator checks the exact lineage, signed authority,
committee and proofs of possession. The resulting verifier must match the
opaque source intent's destination network, root scope and consensus instance.
Duplicate destination networks or invalid explicit custody fail activation. All routes
are validated before any worker starts. Each configured destination has one supervised
blocking worker, bounded by the 32-route limit; cooperative shutdown drains every worker.
No routes means no background signing and no journal directory creation.

## Original source and recovery

Core issues a move-only `NativeAmxRelayIntentV1`; its descriptor binds source
network, scope, height, carrier and a source discriminant: either the complete record key
or the exact current/next epochs of an authenticated boundary. It also binds destination network,
scope and instance. Descriptor bytes alone cannot authorize signing. Each worker
selects heights from authenticated State history and keeps the same State view
and proof job through local acquisition or allocation refusal. It does not scan
untrusted filenames to manufacture obligations.

The existing workflow engine persists unsigned preparation, exact signed bytes,
signed hash, entrypoint hash and dispatch intent before outbound effects. Its
CAS and exclusive runner lease own concurrency and restart. Before signing or
forwarding any resumed bytes, the private account and ledger adapters check the
actual canonical payload against the freshly authenticated original instruction,
pinned network and authority, exact configured fee, empty metadata and absent
attachments. Journal labels and checksums never authorize a different payload.
Signed dispatch additionally verifies the signature and both transaction identities.
There is no second
queue or acknowledgement journal. The plan identity binds authenticated source
coordinates, the exact instruction digest and any signed expiry wake coordinate;
endpoint, fee-cap and observation-cadence changes do not create a
new plan. Account authority remains the workflow's immutable binding; operators
must retain that authority and journal while its carriers remain unresolved.
Changing the configured fee intent refuses signing and dispatch of an old payload;
it never creates another workflow identity. Read-only authenticated recovery still
accepts an already successful exact source delivery under its original signed fee
intent. A pending carrier with incompatible current fees remains unresolved until
its authenticated outcome is known or the operator restores its authorization.

A status response selects a destination height only. The shared genesis-rooted
verifier authenticates the certified block and exact transaction input/output.
The signed authority and original instruction digest must also match the freshly
authenticated source intent. Membership with rejected execution never confirms
delivery. A decoded completed journal is checked against fresh authenticated
execution before the service reports successful delivery. Transport rejection,
read failure, local limits and elapsed time never close a transaction identity.
Canonical absence permits only a retry of the identical persisted signed bytes.
An authenticated rejected execution permits up to three total carrier identities.
Every replacement requires another opaque, freshly authenticated source intent;
fee replenishment can therefore resume the obligation. Exhaustion remains an
operator-actionable unresolved obligation and never counts as delivery.

Restart rescans original authenticated heights and resumes the same workflows.
The source scan repeats without requiring an additional payment or successor
block. Per-observation proof limits retain the verifier's authenticated progress.

The `decision_amx_relay` source reader separately authenticates the original Begin
and Decision at their selected heights on the same Global root. Begin binds the
transaction and participant set; the retained replayed Global registration binds
the child network, scope and consensus instance. Registration cannot be replaced,
and verified committee handoffs preserve that lineage. The funded Decision graph
moves into `SettleAmxV1` only after both original archive namespaces are rechecked.
Refusal after instruction admission retains that exact graph for retry. The reader
does not depend on a current unpruned transaction entry or a later Global block.
A successful Settle can retain a Decision before Prepare, so authenticated delivery
is not by itself a receipt for completed participant monetary effects.

## Current delivery boundary

The supervised source scan emits Begin as Prepare to each original participant,
Prepared to its Global coordinator, and Decision as Settle to every participant. One canonical `.ami` frame stores
Begin, Prepared and Decision scalar coordinates from the actual execution witness.
A Decision retains its original Begin height before the Global entry is pruned, including
an Abort emitted by the same pruning block. Replay regenerates the same frame. The
reader authenticates the complete original witness before advancing over an ordinary
height with no AMX records; a positive count requires the complete original frame.
Every Decision row and its Begin participants are authenticated before the existing
source-bound delivery reader constructs each target instruction. A frame or selector
never grants signing authority, and no second index or outbound journal is created.

Begin delivery additionally authenticates the original successful signed `BeginAmxV1`
input. Pending Prepare admission retains that original shared block owner and its input
indices; no transaction DTO replaces the authorized full terms. A foreign Begin never
creates debit consent. The debit owner must issue the exact direct `CanPrepareAmx`
permission to the configured relay (an explicit self-grant is also valid). The permission
binds parent and child genesis, child instance, dataspace, exact debited asset, and the
canonical transaction digest including every leg, height deadline and signed expiry.
Role grants, holder redelegation and implicit consent from the carrier's key are refused.
Native Prepare rechecks the current grant before escrow; later revocation does not block
settlement or release of an existing Yes escrow.

Before a fresh signature and before dispatching retained signed bytes, the service verifies
the exact grant in a complete authenticated private World cut. Its account-authenticated
bounded proof route and async SDK reader bind the requested relay, terms, schema and
independently verified block. The selected height cannot move below the route verifier's
retained authenticated height. A historical proof, including one fetched after restart,
cannot establish that no later revoke exists; the native use-time check remains decisive.
Evidence unavailability or original memory refusal preserves the unsigned reservation or
exact signed identity for retry. Read-only recovery of an already finalized carrier does
not require a still-live grant. Permission comparison streams canonical original payloads
with exact funded I105 scratch, without constructing another permission or parsed JSON graph.

The same source scan discovers each authenticated final-epoch boundary before taking the
zero-record fast path. Its original complete certified scheduling result determines the
next epoch; an `.ami` record, supplied committee or successor block is not required. A
Global boundary targets every immutable registered participant, bounded by the existing
256-registration limit. A private boundary targets its original registered Global parent.
The original header, quorum certificate and result bytes enter the source pool before
materialization, then move through a retryable funded action into the existing
`RelayGlobalAmxHandoffV1` or `RelayAmxHandoffV1`. Final source checks precede graph release.
Ascending source-height discovery and destination verification preserve sequential
handoffs. Each finite source sweep pins its original authenticated end height; continuous
new source traffic cannot postpone a historical retry forever. If a handoff has no
authenticated successful outcome, a bounded ephemeral
route barrier defers later deliveries for that route; other destinations continue.
The barrier retains the unresolved source position across passes, so an earlier handoff
already authenticated during this process cannot reset a later bounded recovery scan.
Its source network/scope, exact carrier and destination root binding scope the cursor;
a changed binding discards it. Process restart starts again from original history.

A fresh relayer can encounter an old handoff after independent carriers have advanced
the destination beyond the retained verifier epochs. Before opening or resuming its
workflow, the same adapter scans the pinned destination's certified history for an
exact successful handoff effect. Public node status supplies only an untrusted upper
scan bound. Each candidate's direction, dataspace, original source header and original
certified result must match the reconstructed opaque source intent; the shared finality
verifier authenticates its exact signed input and successful execution. An interchangeable
valid quorum witness may differ, but rejected inclusion or a reported destination epoch
never closes the barrier. An exhausted local workflow does not block this read-only recovery.

Each observation has the existing proof-read bound. An unfinished scan retains only its
next height; a local refusal is neither absence nor delivery. A cached positive height
is refetched and its exact effect reverified before a later recovery reports success.
This recognizes an already authenticated delivery without changing an unknown local
carrier's journal outcome or submitting a replacement. Restart reconstructs the same
source deliveries and verifies the destination again, with no extra index or journal.

TODO: qualify the complete two-bank loop on the current node candidate.
Consensus deadline progress must be carried by real committed obligation work;
local polling is never permission to release escrow or produce empty blocks.

The current native candidate binds a mandatory signed `expires_at_ms` into the complete
AMX transaction and Begin. Successful Global Begin discovery also emits a funded
`ExpireAmxV1` intent targeting that same Global root, including after its live entry was
pruned. The original Begin supplies its wake coordinate; local time only schedules this
work. Native execution chooses Abort at the signed ledger-time boundary or after the
height deadline. Neither polling nor an expiry carrier's rejected inclusion releases escrow.

Before dispatch, a bounded local reader searches authenticated Decision history from
the original Begin through `min(deadline + 1, captured_tip)`. Its one continuation per
configured route retains the original paid source through partial acquisition. A borrower
which has not issued its owned source stays with the same State view through refusal.
Other historical Begins cannot reset the active cursor, and ordinary delivery continues
between bounded passes once original source issuance permits yielding. Discovery verifies
the complete common source before selecting the configured destination, then acquires only
that destination's target proof and instruction. A pre-issuance refusal retains its worker's
original State view and graph while other destination workers continue independently.
Global expiry has its own same-Global destination and is selected before unrelated
participant Prepare acquisition. The original allocation pool remains shared and bounded;
worker separation does not promise progress through pool exhaustion or fairness among
obligations within one destination. The issued-read poll bound does not bound a refused
source acquisition. An absent record establishes only that captured prefix; native
expiry execution handles any subsequent competing decision. Every cached positive is
read and authenticated again. A verified Decision suppresses new expiry submission;
an existing exact carrier journal then receives only read-only outcome recovery. Its
unknown or rejected carrier is never relabelled Applied because another carrier decided
the obligation. Restart reconstructs authority from history without an extra journal.

TODO: qualify this native idle path on the current whole-node candidate, including a
carrier delayed beyond the first-Prepare freshness limit, resource refusal, partitions
and restart. Fresh proposals retain the same signed input while choosing an authenticated
timestamp above the deterministic floors; retained same-view output and certified replay
keep the original timestamp. A local stale-time refusal is neither rejection nor absence
and cannot authorize a replacement identity. A valid pre-expiry PrepareQC can finalize
later, so the signed deadline is not an absolute wall-clock finality bound.

Focused daemon tests use genuine exact-quorum certificates over explicit
synthetic execution outputs, including rejected execution, substituted history,
source-intent and resumed-payload substitution before signing or dispatch,
proof-read refusal, no successor block, and durable
ambiguous-submit restart with one signature and identical retransmission.
The handoff catch-up control additionally executes real native Global boundaries, delivers
them through different funded participant accounts, replays the participant from signed
genesis, and recovers both effects with a fresh verifier at the final tip. Its DKG sessions
are explicitly proved component prestate. These tests do not establish whole-network
payment qualification.
