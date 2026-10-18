# FASTPQ ordinary source statements

Updated 2026-09-09. This is the source-coupled contract for complete-entry source
statements and local State-owned construction accounting. Production compact
admission remains disabled. The [readiness ledger](fastpq_production_readiness.md)
separates bounded source/reference validation from required native release gates.

## Transaction wires and execution sources

`PublicIO.tx_set_hash` retains the branch's authoritative ordered canonical
transaction-wire commitment. Both block execution paths compute it through
`axt_ordered_transaction_set_digest_v1` from the ordered external and time
entrypoints. It is cached before source-inventory finalization. An execution-call
identity list must never replace that commitment. Missing or zero cached hashes
fail before transcript digest finalization, and failure is latched.

Execution sources have a separate complete canonical projection:

1. External entrypoints in block order, using actual execution-call identities
   and validated routes. Sealed reveals retain their inner signed call identity.
2. Time invocations in invocation order, including failed invocations, using
   their distinct runtime call hashes and an explicitly absent lane.
3. Remaining applied transcript sources in ascending hash order, including
   internally derived calls and typed native protocol purposes.

This projection includes external/time entries without transfers. Native work
without a recorded transfer is not an additional proof source. Projection order
is independent of physical fragment scheduling.

The nominal model type `FastpqSourceExecutionEntryV1` contains the call/purpose
hash, execution kind, route and dataspace. `FastpqSourceExecutionKindV1`
distinguishes `ExecutionCall` from `ProtocolPurpose`; an execution call alone
asserts no external signature. `FastpqSourceRouteV1` distinguishes `Unrouted`
from a lane ID and its full incarnation `Hash`. No lane or hash sentinel is used.

`fastpq_source_execution_entries_digest_v1` commits the complete ordered entry
projection, including entries without statements. Its preimage is the domain
`iroha:fastpq:source-execution-entries:v1\0`, a little-endian `u32` entry count,
then each entry's little-endian `u32` canonical-frame length and complete nominal
Norito frame. The entry cap is checked before traversal. Streaming hashing uses
bounded per-entry scratch and does not allocate a concatenated archive. The
2,048-byte structural frame bound is not a production resource policy.
Completeness and identity uniqueness require the execution owner.

## Manifest and bounded opening

One statement leaf commits a complete nonempty execution-entry transcript bundle:
source network/height, statement and entry positions, complete per-entry transcript
count, all four source-entry fields, and the canonical path-free whole-bundle
statement digest. There is no transcript-index field. Original transcript/delta
grouping and order remain inside the statement; common asset scales, repeated-key
chronology and key allocation span the complete bundle. Entry indices are strictly
increasing and statement indices are consecutive. Empty execution entries remain
in the complete inventory digest without a synthetic leaf.

The manifest contains source network/height, executed-entry count,
`source_entries_digest`, statement count and application-Merkle root. The builder
receives the complete entry slice, enforces separate entry/statement caps and
checks every leaf against the entry at its advertised index. Empty statement
sets use a fixed empty root while retaining the complete source-entry digest.
A zero-entry manifest must carry the exact empty-entry digest.

The manifest's canonical frame is the ordinary-write value at the reserved fixed
`FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1` key (`0xD7`). Membership uses a
count-aware application-Merkle path, including ragged trees. One source opening
also has exactly 256 ordinary-write SMT siblings. Verification checks the exact
expected leaf and ordinary root; it does not authenticate the root's finality.

The sole first-release source leaf binds complete entry bundles and has no
transcript index; the manifest includes the complete entry digest. Earlier
prototype layouts must reject during canonical decoding even when they reused
the same nominal schema name. No compatibility fallback or compact production
profile is enabled by this layout.

Core's shared opening/archive preparation takes the complete expected entry
slice immediately after the source context. It checks the entry cap before
scanning witness writes, rejects malformed or duplicate members of the entire
reserved `0xD7` family, decodes the manifest under cumulative limits and rebuilds
it from exact entries and leaves before allocating the ordinary tree. Other
ordinary keys retain the existing last-write-wins rule. An opening checks its
requested position before copying ordinary writes. The returned root is a
computed claim requiring independent authority.

## Complete leaf archive

`FastpqOrdinarySourceStatementArchiveV1` contains an explicit version, manifest,
complete ordered leaf vector and one fixed `[Hash; 256]` manifest path. Empty
archives preserve their manifest and path. Statement preimages and private
transfer paths are excluded.

Model archive verification and decoding receive the complete expected entry
slice separately, alongside source context and expected ordinary root. They
recompute the entry digest and complete manifest. The expected entries must
come from an independently authoritative owner; they cannot be reconstructed
from leaves because non-transfer entries have no leaf.

Decoding rejects excessive wire bytes and expected-entry count before body work,
and narrows the sole variable sequence to the statement cap before allocation.
Field, cumulative element/allocation and nesting limits retain stricter enclosing
budgets. Fixed arrays do not consume the variable-sequence cap, so an empty leaf
archive can use a zero leaf cap. Complete-archive consistency checking traverses
entries and leaves; it is separate from succinct proof verification.

The Core archive constructor borrows the witness and expected entries, validates
the complete owned leaf vector, then moves that allocation into the result. It
computes one shared manifest path. Successful construction establishes
consistency with supplied facts, without granting source authority or spending
permission.

## Execution ownership and local derivation

`StateBlock` freezes network, height and active lane incarnations before staging
and lifecycle effects. Transactions capture each transfer's runtime identity,
kind, explicit route, dataspace and contributing fragment locally. `apply()`
publishes captures and capture errors together; dropping a transaction discards
both. Applied conflicts invalidate the complete source map. Changing an active
call hash after recording does not re-key an earlier occurrence.

Inventory finalization reconciles exact capture keys with the still-owned
transcript accumulator. It rejects empty/misidentified bundles, duplicate
identities, wrong routes/kinds and source-height conflicts. It completes missing
valid singleton digests only after validating supplied digests, then seals the
original finalized public occurrences. The owned inventory retains the canonical
wire hash unchanged and publishes the complete per-source dataspace map.
Neither success nor failure can be replaced by retrying with a smaller archive.

`derive_fastpq_ordinary_source_manifest_v1` takes source context, complete entries,
slot, permission root, explicit nonzero transaction-wire hash, transcript map and
construction limits. Every map key must match one entry. The owner wrapper also
requires its exact transcript-key set and public-content seal. Public quantities,
identities, optional digests and occurrence grouping must remain unchanged.

Six limits cover entries, cumulative transcripts, cumulative deltas, canonical
private-input bytes, largest public-statement frame and cumulative statement
bytes. Shared public preparation checks all six before private-tree construction.
It measures each complete entry bundle before any private tree or leaf allocation;
fragment measurements from the same entry cannot be added as separate statements.
It measures real canonical quantity frames and identities; only fixed-width
context placeholders are used for byte measurement. Missing singleton digests
reject rather than being enlarged after accounting. Final per-statement encoding
still enforces individual and cumulative byte caps. Repeated public preparation
costs CPU time that requires measurement on the final candidate.

`StateBlock::fastpq_source_statement_budget` creates a local budget tied to the
privately finalized inventory allocation. Its E count is the complete owned entry
slice, including entries without transfers. `prepare` verifies the current State
owner, remeasures the entire supplied archive with the canonical six-cap owner,
and checks its exact public seal. It never accepts a caller-supplied E, usage
increment, prefix size, or permission root. Same-entry bundles are always measured
whole; retrying the inventory replaces usage instead of adding it again.

The prepared attempt borrows its immutable transcript map and exclusively borrows
the local budget. Dropping it or encountering any error preserves the previously
committed usage. `materialize` rechecks the original State inventory allocation,
derives slot and permission root from the current block, and invokes the strict
producer. Its successful return is the sole accounting publication point. Empty
archives retain E, produce no synthetic statement, and permit zero T/D/I/M/S caps.
Private paths are not public-seal facts, but changed paths are remeasured for I.
No State, recorder, ordinary write, capture error or witness is published by this
local construction operation. Permission-table scanning is separately costed.

This post-execution construction budget has no Norito/wire identity and is not an
execution-admission token or authenticated policy. The existing test-only D7
preparer exercises it. Production `StateBlock::capture_exec_witness` still requires
an authenticated source policy and atomic D7 insertion/retained-context validation.
Runtime admission uses the independently frozen policy and the original
producer's ordinary invocation owners, native sweep capabilities and retained
governance obligations. Their quota journals apply or drop with the matching
State transaction. Current-source execution, complete final capture and replay
qualification remain required. Existing test-only occurrence/prefix helpers do
not authorize fragment sums for M or S.
The test-only complete-entry reservation adapter now replaces one contribution
from the complete borrowed, finalized transcript bundle. Reopening an entry hash
across physical fee fragments retains E=1. Its journal restores both accounting
and new identity bindings on rollback; an owner whose E must survive business
rejection must be retained separately before that business scope. These helpers
still require production State ownership and policy integration.

Independent-batch transcript preparation now returns errors to the whole batch
before the next movement and allocates transcript storage only for accepted
legs. Its declared entry-count bound is not an execution quota. Ignoring a
preparation error prevents transcript publication; rollback of earlier movements
still belongs to the enclosing State transaction. The compiled source passes
13 preparation, 30 reservation and 17 canonical measurement tests, including
real balance rollback and exact fee-fragment accounting. These focused checks do not establish release qualification.

Full-domain quantity preparation supports the ledger's nonnegative 512-bit
mantissa and scales 0 through 28 using 19 little-endian `u32` limbs. Canonical
value frames bind scale and all limbs, including zero padding. Narrow and
full-domain factories reject each other's value encodings. Checked arithmetic,
exact occurrence coverage and repeated-key balance continuity precede private
SMT materialization. Tree limits bound updates, unique keys, occupied nodes and
path allocation. Statements are built and dropped one at a time.

`DerivedTransferSmtWitnesses::intermediate_roots` borrows the existing complete
batch witnesses and returns each debit/credit pair boundary except the final
root. It preserves equal-root occurrences without preparing individual deltas,
building a second tree or allocating another root buffer. These local roots do
not establish authenticated finality or replace the full persisted WSV roots.

Statement roots describe touched balances for the complete execution-entry transfer
bundle. They exclude the ordinary-write tree that contains the manifest. Legal
mint/burn work between transfers can break the transfer-only chronology; the
whole-bundle source manifest then rejects before private-tree construction. It
does not split the entry into separately accepted operation leaves. TODO: cover
intervening supply, permission and metadata changes in the final complete execution
relation. Whole-ledger balances, supply and authorization require their own
authenticated execution relations.

Final witness capture, extraction and commit recheck the owned inventory,
canonical wire cache, dataspace cache and exact finalized public transcript
contents. Later applied transfers or changed contents invalidate publication.
The scoped witness recorder clears/deactivates its owned overlay on errors;
repeated capture checks retained contents without reading another block's
recorder. Authenticated replay does not invent local source ownership.

Only the thread holding `ExecWitnessGuard` can record, synchronize transcripts,
acquire an overlay's capture identity or mutate the recorder lifecycle. Detached
execution workers return results for application on that owning thread.
Unrelated `StateBlock` transactions and transcript drains on other threads cannot
append to, replace or clear its witness. Read-only recorder snapshots remain available
across threads; ownership is local and does not enter witness bytes.

The test-only qualification helper `prepare_owned_fastpq_d7_capture` retains the
inventory allocation, exact header milliseconds, saturating nanosecond slot,
permission root, manifest and limits.
Subsequent checks reject context drift, including timestamps that saturate to the
same slot. The helper does not insert the D7 write or confer finality. Permission
scans and repeated context checks require their own resource accounting; account
membership and direct permissions are not proved by the role-table root.

## Activation requirements

The September 26 candidate now freezes the required on-chain source policy before
block-start work, retains ordinary entry ownership before attempts, and keeps
ordinary, native-maintenance and mandatory reservation journals inside the disposable State/witness
transaction. Complete entry framing is charged before transfer mutation; intrinsic
refusals roll back business effects and retain one rejected invocation. Fee and
ballot-penalty tail shapes are checked before execution, and proposal packing uses
the same frozen policy. The bootstrap ordinary prefix is conservatively eleven
Network entries; it is not a qualified throughput optimum. Genesis normalization
preserves authored input boundaries and refuses an overbudget source. Draft generators
must author compatible physical routing phases explicitly; merging arbitrary adjacent
inputs by size can combine distinct authorization worlds. Generated crypto and
confidential parameters share one global metadata input after authored instructions.
In-genesis parameter
changes cannot enlarge that carrier's pre-frozen capacity.

Final inventory construction now retains the original ordinary, native-maintenance and mandatory
quota journal identities with their frozen policies, exact six-dimensional usage
and last applied transaction generations. Capture, extraction and commit require
that same inventory allocation and all three original journals. Discarded speculative
children and empty commits preserve the seal; a nonempty applied journal changes
it even when a later replacement restores all public counts. Reconstructing an
equal journal does not restore custody, and an observed mismatch remains latched.
The receipt shares existing allocation owners without adding backing storage;
it does not complete original inventory or serialization-scratch accounting.

SNS auto-renew runs only inside the original applying Time-phase output owner.
`FastpqSourcePolicyV1.max_native_maintenance_invocations` reserves a disjoint
finite native pool using the complete intrinsic entry ceiling; the bootstrap
profile reserves 64 entries, independently of Network/Pipeline/Time invocations
and retained governance obligations. The supported eleven Network inputs are
unchanged. The combined bootstrap ceiling is E=3723, T=D=58608,
I=510095248, M=272175 and S=1012055813; checked policy arithmetic includes all
three pools before proposal admission. Missing native policy fields are refused.

The sweep issues a move-only capability for the exact network, proposal,
direct-execution slot, persisted storage key, revision and canonical enabled
configuration. The charge rereads the live owner, expiry and exact quote before
consuming it. Only an actual nonempty numeric transcript opens a native source E
inside the same disposable State/source journal. A free quote or self-collector
renewal advances the lease without inventing a transcript or source entry.
Payment failure drops all movement/source effects before persisting deterministic
retry metadata in its separate transaction. Native intrinsic/capacity refusals
cannot borrow ordinary or governance reservations; authority/capture failures
invalidate the carrier. Final inventory reconciliation authenticates every
ProtocolPurpose against exactly one native or governance journal and compares
all E/T/D/I/M/S totals. The public kind alone confers no source authority.

TODO: complete current-source Core execution and genesis qualification, then bind
these journals to atomic D7 publication. The combined implementation is applied;
its actual Core tests remain pending. Truncation or omission of an applied source
is invalid. Final-capture limits alone cannot provide proposal liveness.

Prepared complete D7 contents now join original capture and authenticated native
source finality before entering the bounded Kura producer outbox described below.
TODO: finish missing-tape reconstruction, authority-aware retention and the separate
exact AXT spending/replay integration; artifact storage alone grants none of them.

Current-branch compilation, all affected tests, fresh complete artifacts,
independent cryptographic qualification, release-hardware CPU/Metal/CUDA parity
and a same-source four-validator recovery/adversarial corridor remain required.
The earlier 544-test/two-artifact reference gate is not evidence that this
integration candidate passed those gates or is production ready.


## Local durable producer

The existing FASTPQ lane owns one autonomous source at a time and its original typed
failure. It uses `NativeFinalityCursorV1` from the independently pinned signed genesis,
with an explicit selected root. The cursor keeps its authenticated prefix across finite
turns and exports the actual H2-authenticated genesis anchor with original decoder custody.
No decoded checkpoint or file cursor imports trust. Existing Global-only discovery callers
select Global explicitly. The producer reads complete D7 source inventories and complete
effect tapes through the existing funded native-context reader. A Complete manifest with
an exact canonical empty statement root may advance without an optional tape, after its
full ordinary-write root and bounds are authenticated. It grants no entry/effect inventory. A Complete manifest with
an exact canonical empty statement root may advance without an optional tape, after its
full ordinary-write root and bounds are authenticated. It grants no entry/effect inventory.

Kura's `fastpq_artifacts_v1` namespace is the sole aggregate store for content artifacts,
source tapes (`.fqs`), and producer artifacts (`.producer`). All stable objects and the
existing single publication temporary share the configured count/byte quota. A producer
key commits the actual carrier, certified R, complete manifest and exact statement leaf.
Its object is the complete canonical verified artifact, so a crash cannot split artifact
bytes from cursor metadata. The ordered verified objects form the disk cursor: every
restart first authenticates the source and freshly verifies each offered artifact before
advancing. Local file absence only requests production; it is never ledger absence or
successful execution evidence. Persisted artifact receipts are exact issuer/byte durability
facts, not settlement or transaction-submission receipts.

`[zk.fastpq.producer]` configures `poll_interval_ms`, `step_timeout_ms`,
`max_native_steps` (at most 64), `max_source_entries`, and `max_source_statements`.
One absolute monotonic budget spans a worker attempt; it is checked around bounded reads
and proof work. Synchronous filesystem or proof work cannot be preempted, so this is a
cooperative bound, not a wall-clock execution guarantee or a renewed payment deadline.
The same supervised worker polls while the native chain is idle. It signs and submits
nothing. Proof output is bounded by both its configured carrier ceiling and the actual
immutable Kura object ceiling before generation.

Optional tape size/admission/publication failure cannot strand mandatory native context
publication or change certified D7/outputs. It leaves that source unresolved. **Read-only
regeneration of a missing tape is still unfinished:** it must reuse authenticated signed
policy installation and canonical execution/result preparation in isolated replay State,
without invoking a normal second Worker against live Kura or publishing lane/SCCP effects.
The existing startup replay can republish original tapes on a genuine restart, but is not
that autonomous service. A nonempty unavailable source is never skipped; later producer
work remains pending behind it. Authority-aware retention and complete nested cryptographic
allocation accounting also remain open. Source tests and formatting do not establish
compiled, whole-node, or payment-release qualification.
