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

Each `[[amx_relay.routes]]` contains `network_id`, `chain_id`, `scope`, `authority`,
`account_config`, `signed_genesis`, `signed_genesis_sha256`, `genesis_public_key`
and `fee_payment`. These use their native Norito JSON/TOML types; the digest is
exactly 64 lowercase hexadecimal characters. File paths resolve relative to the
node configuration. A route's SDK account file is loaded without environment
aliases and must match all three authority/network/chain pins. The account must
already hold the assets authorized by its exact signature-bound fee intent.
There is no validator-key fallback, automatic minting or inferred sponsor.

Signed genesis bytes must match the independently configured digest and signer.
The existing genesis authenticator checks the exact lineage, signed authority,
committee and proofs of possession. The resulting verifier must match the
opaque source intent's destination network, root scope and consensus instance.
Duplicate destination networks or invalid explicit custody fail activation.
No routes means no background signing and no journal directory creation.

## Original source and recovery

Core issues a move-only `NativeAmxRelayIntentV1`; its descriptor binds source
network, scope, height, carrier and complete record key, and destination network,
scope and instance. Descriptor bytes alone cannot authorize signing. The worker
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
coordinates; endpoint, fee-cap and observation-cadence changes do not create a
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

The supervised source scan currently emits Prepared records for delivery to their Global
coordinator. The supervisor, route custody, exact-byte journal and authenticated
outcome adapter cover that phase. The exact-selection Decision reader is separate
from durable obligation discovery. TODO: connect retained Begin/Decision/Handoff
discovery and delivery to the same supervisor and qualify the complete two-bank loop.
Consensus deadline progress must be carried by real committed obligation work;
local polling is never permission to release escrow or produce empty blocks.

Focused daemon tests use genuine exact-quorum certificates over explicit
synthetic execution outputs, including rejected execution, substituted history,
source-intent and resumed-payload substitution before signing or dispatch,
proof-read refusal, no successor block, and durable
ambiguous-submit restart with one signature and identical retransmission.
These component tests do not establish whole-network payment qualification.
