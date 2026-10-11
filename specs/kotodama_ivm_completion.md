# Kotodama and IVM completion

G1–G8 remain active and incomplete. The table below defines their outcomes;
component implementation and historical test results do not establish release
qualification.

## Goals and dependency order

| Goal | Required outcome | Current work |
| --- | --- | --- |
| G1: language and ABI | Caller-owned argument/result word tables for every compiled function; 64 KiB / 8,192-word limit; initialized-count, ownership, alignment and lifetime checks; full-width integer helpers and structural equality. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G2: authenticated State | One State-owned commitment over every authoritative persisted execution table; bounded inclusion, absence and complete range witnesses; atomic finalized publication and persistence/recovery custody. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G3: private execution | One complete native STARK relation and `IvmExecutionStatementV1`; normalized intent, exact public gas, complete reads/effects, private-trace masking, full typed valcom constraints and native local proving. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G4: anchored AXT | One `AxtAnchoredSpendV1` path binding finalized successful execution and exact transfer occurrence, fresh issuer authorization, atomic durable nonce/budget/effects, complete FASTPQ state transitions. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G5: memory ownership | Allocation-lifetime charges shared once across prepared artifacts, analyses, operations, templates and borrowed/nested VMs; aggregate 64 MiB retention; separate admitted active reservations; zero retention; observable live/borrowed/evicted/peak usage. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G6: automatic acceleration | Standard target-appropriate SIMD/Metal/CUDA, runtime-loaded driver, process owner, per-device/kernel qualification, public cost selection, unchanged-input fallback/quarantine, ten reproducible signed embedded PTX families. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G7: Musubi publication | Daemon-owned authenticated private TLS runner, finalized recovery, software signing, provider coordination/readback, durable journal/clock and filesystem custody, configuration through `iroha_config`. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |
| G8: candidate qualification | Regenerate ABI/schema/gas/SDK fixtures together; qualify one unchanged candidate across mandatory language/proof/state/AXT/memory/hardware/native/SDK/network/release checks. | Open; complete the stated outcome and the integration boundaries below on one qualified candidate. |

Component owners are compiler/IVM/Core/SDKs for G1; State/Kura/consensus for G2;
the native prover, verifier and transactional execution owner for G3;
AXT/FASTPQ/Core for G4; VM/cache/allocation owners for G5; acceleration/build/CI
for G6; daemon/config/provider services for G7; and release/native/SDK/network
qualification for G8.

Freeze the canonical ABI, numeric semantics, proof statement, state commitment and
AXT shapes first. Language, memory, hardware and Musubi implementations can then
proceed independently. Complete finalized state publication/recovery before
integrating private proofs and AXT. Regenerate and qualify a single candidate
only after these paths are coherent.

## Fixed invariants

- This first release has one ABI V1. Replace unfinished interfaces directly and
  remove retired layouts, aliases, decoders, fixtures and backend registrations;
  no backward compatibility path is permitted.
- `r10/r11` carry argument-table address/count and `r12/r13` carry result-table
  address/capacity. Returns carry result address/exact initialized count in
  `r10/r11`. Caller-owned returned storage outlives the callee.
- Current `Secret<T>` information-flow restrictions remain. General secret
  arithmetic/branching is outside scope. Raw witnesses stay local and never
  enter transactions or Torii requests.
- Hardware changes speed only. Results, errors, gas, state, event order,
  commitments and verification decisions must agree across devices. Test
  entropy plus an identical witness yields identical proof bytes; production
  randomness is fresh.
- “Optimal” means the fastest qualified operation/workload path including
  transfer and launch cost. Selection uses only public workload geometry.
- Cache pressure changes local scheduling or retention, never transaction
  validity or gas. Eviction never releases a charge still owned by a borrower.
- Public ledger replacement is a separate deployment operation. Initial network
  evidence uses disposable networks with at least four validators and mandatory
  signed RS16 DA/RBC.

## Next integration boundaries

G1 callable metadata now carries complete flat preorder type schemas instead of
shallow word roles. Compiler emission and admission bind nested Sum payloads,
exact List capacities and element types, nominal products/errors, String versus
Blob, cursor key kinds and private leaves. Public records retain their existing
schema limits; private callable schemas retain 250,000 nodes, depth 256 and
8,192-word tables, with checked interior allocation sizes. Interpreter loading
prepares immutable traversal layouts once, reserving original-pool backing before
allocation; snapshots share that owner and warm calls do not reanalyze metadata.
Bounded traversal charges before node/word/pointer work, checks complete aggregate
heap footprints and validates only active branches and logical List elements.
Failed validation cannot publish result ownership. Full proof constraints for this
traversal and coordinated ABI/gas/artifact/native/SDK regeneration and qualification
remain open. No shallow-role compatibility decoder is permitted.

Every program profile now uses header 1.1 with ABI V1. Header 1.0 is rejected
before section decoding; test syscalls still require the compiler-owned harness
capability. The ABI descriptor binds the accepted header version bytes. Borrowed
fixed-header dispatch selects canonical CNTR admission once, and native preparation
uses literal coordinates admitted from those same immutable artifact bytes.
Generated contract/header/ABI/native fixtures must move together; their regeneration
does not qualify execution proofs, native consumers or a release candidate.

G2 has an exhaustive typed inventory of World, State, trigger and durable-history
owners, classifying canonical authority, derived indexes, authenticated history
and local policy. Its machine-readable view is
[`state_table_inventory.json`](state_table_inventory.json), generated from the
authority registry, the accumulator's field index, the production World pass,
the exact table catalog, a scan of every non-test source of `iroha_core` and
`iroha_data_model`, and the declarations of the consensus-carried types (the
block header, the block payload and block result, the signed genesis consensus
parameters, the execution result, every Sumeragi wire message, the lane result,
the peer handshake capabilities and the node's network envelope).
`crates/iroha_core/src/state/state_table_inventory_tests.rs`
compares the tracked file with a fresh generation and fails when a field, its
root coverage, an execution-witness family or cited evidence drifts, and when a
domain literal, a new use of a listed literal, a use of a commitment
construction, a hash-bearing field of a consensus-carried type or of an
execution-witness value type, any field of a carrier type that holds a State
digest, or an `iroha_core` function that takes a State or
World reader and returns a hash-bearing value appears without an exact
listing; it detects carrier, signature, literal and construction drift, not
arbitrary State dataflow. The file's
`summary` holds the current counts; `fields` gives each field's role, shape,
codec identities, certified root and witness families; `roots` enumerates every
existing commitment over State content with its class, owner, disposition and
the detectors that report it, `protocol_carriers` every hash-bearing field of
the consensus-carried types (the block header, the block payload and block
result, signed genesis, `R`, the wire messages, the lane result, the peer
handshake and the network envelope) and every field of the types that hold
their State digests,
and `application_accumulator` the accumulators that
[`sumeragi.md`](sumeragi.md) §16.8 excludes; `open_defects` lists what the
as-built State still violates, each assigned to ZK delivery plan task G.3. The World accumulator commits
canonical World fields and their schema identities; derived indexes do not
become independent authority. Canonical State-level fields (transaction
membership, commit topologies, the canonical runtime, chain and network
identity, lane manifests and compliance, and the policy cells installed from
node configuration) affect no certified root, and the execution-witness roots
bind only the reserved witness families that the inventory lists; a family
value that digests State content (for example the FASTPQ permission-table root
over `world.roles`) is itself a listed commitment. One per-table State root is
certified today, the retail fee receipt-head root, and is an open defect.
Protocol objects also carry flat fingerprints of State content that validation
recomputes and compares: the execution-policy digest (signed genesis and the
peer handshake), the Nexus/AMX context hash (signed genesis), the DA
proof-policy bundle hash and the confidential feature digest (every block
header; the latter digests the effective verifying-key registry), and the AXT
policy snapshot (every block result: the projection of the derived table
`world.axt_policies`, which the apply path installs from the block without
rebuilding it from its registered sources). They are
listed as protocol fingerprints with open defects; none authenticates a State
read. The epoch context identity in every consensus message, the schedule
and beacon fields of `R`, and the pinned committee digest of every lane result
are listed as consensus bindings and keep their roles.
The contract
of the one keyed State commitment that replaces the accumulator, with
inclusion, absence and complete-range witnesses, is [`sumeragi.md`](sumeragi.md)
§16; its typed interface and conformance suite are
`crates/iroha_core/src/state/authority_registry/keyed_commitment.rs`. It is
specified, not built. Four development-only candidate constructions were
measured against it: natively under five hash profiles and, for the three tree
candidates under the Poseidon2 and Rescue-Prime profiles, in-circuit with the
uncommitted B.1 reference
([`state_commitment_candidates.json`](state_commitment_candidates.json)); none
is selected and no candidate root is published or certified. The
complete-table catalog checks exact identities and materializers, and the typed
inventory admits its canonical schema metadata. Inventory admission
is not complete State capture, publication, recovery or finalized-anchor evidence.
Dependency validation borrows its traversal ancestors without allocating graph
scratch; this preserves exact cycle and non-authority errors. Schema-name encoding
and the remaining capture scratch still need their own allocation custody.
Semantic configuration consumed by execution must be authenticated through agreed
parameters or context. Snapshot JSON hashes and touched-write roots are not
substitutes for a complete State commitment.

The scoped domains capture checks `domains_by_owner` against complete retained
current and predecessor domain images before encoding those same canonical rows.
Its allocation-free scan charges every physical current/undo row and index member
against a local work bound; work exhaustion is a deferral, distinct from corrupted
derived membership. Original native publication identities and the State generation
fence reject overlapping publication. Checking preserves undo entries, including
redundant touches, and never repairs live World. This is a consumed scoped capture
foundation; complete derived-index checking and State/Kura publication remain open.

Scoped account-alias capture uses one sealed committed/frozen relation over the
original account, alias and reverse-index readers. It preserves Current accounts,
aliases and reverse buckets before the same Predecessor passes, checking exact
membership, account existence, primary labels and the existing raw-PII restriction.
Every physical advance, complete mask/lookup/member tail, controller/alias equality
and label scan is prepaid. The 7,814-unit Single Ed25519 reference changes only local
work scheduling; wider or quadratic cuts can defer without changing validity or gas.
All three committed currentness Results precede validation and encoding outcomes;
encoding retains native reader release and the State generation fence. Frozen
capture requires all three actual State targets, equal acquisition modes and the
original State pool. These scoped adapters still require fresh runtime qualification;
complete State publication, physical admission of remaining scratch/owners and
finalized authority remain open. See [the coupled relation](frozen_account_alias_relation.md).

Scoped account capture retains the original accounts, universal-ID and opaque-ID
readers through encoding. Current and predecessor images require exact inverse
membership, unique universal IDs, and unique opaque members attached to a universal
ID; implicit accounts without either remain valid. The shared committed/frozen
relation prepays every physical row, undo mask, complete lookup and reverse member
scan, including candidates after a match. Both complete controller geometries or
fixed identifier keys are admitted before equality. The 1,196-unit Single Ed25519
reference is local work policy; wider or quadratic cuts can defer without changing
validity or gas. It neither invents an AccountId-to-identifier hash relation nor
repairs live indexes. Every original currentness probe runs before exposing a
validation or encoding outcome; native replacement or State publication invalidates
the capture. The frozen adapter retains all three exact State targets in the same
mode and uses the original State pool. See the [scoped relation](frozen_account_identity_relation.md).

Committed and frozen NFT/RWA capture share one sealed relation over the actual
three NFT and four RWA original owners. Both images require exact nonempty
owner/domain and owner/status/frozen membership; `None` status is a populated
key. Physical advances, complete predecessor masks, lookup/member tails and both
full typed equality operands are prepaid. The 4,332/4,626 singleton references
are local scheduling, with wider or denser cuts able to defer without changing
validity or gas. Every committed native currentness Result precedes the held
encoding result, reader drop and final State fence. Frozen capture requires the
actual State targets, equal Ordinary/Replace modes and the original State pool;
canonical restoration retains untouched rollback memberships and redundant or
absent touches. Original physical limits remain unchanged. These scoped checks
add no account/domain existence, economic, reference or finalized authority;
fresh runtime qualification and complete State publication remain open. See the
[source-coupled relations](frozen_nft_rwa_owner_relations.md).

Committed and frozen escrow capture share one sealed relation over the actual
source and seller, optional-buyer and status indexes in both original images.
Buyerless records require no buyer group and cannot appear in any such group.
Physical advances, complete predecessor masks, lookup/member tails and both
complete equality operands are prepaid; the 1,366-unit singleton reference is a
local schedule, with wider or denser cuts able to defer without changing validity
or gas. All four native probes run before the held encoding result, reader drop
and final State fence. Frozen capture retains four exact targets with equal
Ordinary/Replace modes and the original State pool. Snapshot index restoration
retains optional buyer changes and untouched rollback memberships. The original
16 MiB physical-pool control remains unchanged. See the
[scoped relation](frozen_escrow_owner_relation.md); complete State publication,
physical funding and finalized-anchor authority remain open.

Committed and frozen repo-agreement capture share one sealed relation over the
original rows and initiator, counterparty and optional-custodian indexes. Both
images require exact nonempty inverse membership; custodianless records cannot
appear in a custodian group. Physical advances, complete masks, lookups and member
tails admit both full Name UTF-8 or account-controller operands before equality.
The 1,222-unit reference is local scheduling, with wider or denser cuts able to
defer without changing validity or gas. All four committed currentness Results
precede the held encoding result, reader drop and final State fence. Frozen
capture requires four actual State targets, equal Ordinary/Replace modes and the
original State pool. Snapshot restoration preserves untouched rollback members
and optional custody changes. Original physical limits remain unchanged; fresh
runtime qualification, remaining physical backing and complete State publication
remain open. See the [scoped relation](frozen_repo_agreement_owner_relation.md).
These checks add no agreement-admission, economic, settlement or finalized-anchor
authority.

Asset lookup recovery projects all eight derived indexes from both retained
definition/domain/balance images. Owning-domain changes also move untouched
balances in the domain index; holder sets deduplicate balance partitions and
nonzero membership requires at least one nonzero partition in that image.
Both images must satisfy definition and domain references before any index is
replaced. Recovery retains complete predecessor buckets and redundant source
touches without modifying canonical source rows or undo. This is snapshot index
reconstruction, not an authenticated live capture or finalized State root.

The canonical asset-definition reader checks exact owner groups, optional domain
groups, definition-to-domain lookups and confidential-policy transition indexes
in both retained native images before encoding. Referenced domains must exist in
the same image, and restricted definitions must own a domain. Pending policies
must have a valid shape; exact height/definition memberships and nonzero counts
are checked against the complete original definitions, not `zk_assets` or another
derived index. All seven original readers survive through the final identity
check. Committed and frozen consumers share one sealed relation over these seven
actual owners, preserving each original Current/Predecessor phase and source/index
error. Complete physical scans, masked rows, no-op/absent undo, post-match lookup
and member tails admit both full typed comparison operands before access. One
reference row with a Single Ed25519 controller, 126 domain bytes and a pending
policy window costs 3,868 local work units across both images; this is no validity
or gas limit. All seven committed currentness Results precede propagation; readers
survive encoding and are dropped before the final State generation fence. Frozen
capture requires their actual StateBlock targets, matching Ordinary/Replace modes
and original State pool, with no refresh from later target publication. Dense cuts
can defer locally and retry the same immutable source with more admitted work.
Fresh runtime qualification and remaining native reader/control, serializer and
restore allocation custody remain open; see the
[source-coupled definition relation](frozen_asset_definition_relation.md). The balance
reader separately
checks its five derived indexes, including exact domain projections and holder
membership over all account/definition partitions. Both zero and nonzero holder
checks use the same current or predecessor source image; source undo tombstones
and inspected range rows consume the local work allowance. All eight original
balance/reference/index readers survive through encoding. These scoped checks
do not establish a complete State commitment or finalized anchor.

Contract-alias capture checks the exact inverse lookup and the shared persisted
lease-window relation in both retained native images, retaining both original
readers through encoding. It rejects duplicate targets for one alias, missing or
foreign inverse rows and invalid leases before allocating encoded rows. Physical
rows and undo tombstones consume bounded local work. Expired and undeployed
bindings remain representable until ordinary cleanup; this capture does not
replace invocation-time deployment, authority or expiry checks. Live writes,
restore and capture use the same lease-window primitive. The catalog consumes
this checked capture directly, with no parallel unchecked binding reader.

Account-rekey capture retains the original records, accounts, alias bindings and
occurrence index through encoding. Both native images must have exact nonempty
occurrence buckets for the active and all historical account IDs. The shared
provenance primitive selects only the maximal account-ID-rekey suffix: those
predecessors must be distinct, retired and unambiguous, while alias reassignment
history may refer to live accounts or repeat historical occurrences. Every active
account exists, every existing alias matches its record, and a record may remain
after alias cleanup. Physical rows, undo tombstones, inspected history and the
shared provenance scans consume bounded local work before access; dense histories
may require a larger local capture allowance. The catalog uses this checked
reader directly. Snapshot reconstruction also validates both retained record,
account and alias images before replacing the occurrence index. It preserves the
original source rows and undo, complete predecessor buckets and redundant source
touches. Snapshot reconstruction allocations, complete State publication and
finalized custody remain open.

Validation-fee proposal capture retains the original canonical proposals and
height index through encoding. In both native images, each fee-policy or
fee-payout-lifecycle proposal has exactly its stored ID at its creation height,
regardless of status; enactment filtering remains the consumer's responsibility.
Missing, orphan, non-fee, wrong-height and duplicate-height memberships reject
capture. Physical source/index rows, masked rows, undo tombstones and lookups
consume bounded local work. Capture neither repairs indexes nor clones proposal
payloads, and checks both original reader identities before returning. Exhausting
the local allowance defers capture without changing transaction validity.

Proof capture checks the exact stored-key/status projection against all three
status buckets in both native images. Ordered borrowed source/undo cursors
precharge physical rows, tombstones and variable backend-key comparisons without
allocating membership maps or searching variable keys in trees. Both original
readers remain through encoding and the native identity checks; the unchecked
proof reader is removed. Grouped captures retain encoding errors until those
readers are dropped and the State generation is checked. A changed publication
requires a fresh capture; only an unchanged owner can return its encoding error. Restore reconstructs both complete logical index images from
canonical proof history, including endpoint and redundant source touches. It does
not invent transient intermediate-status history absent from those endpoints.
Restore scratch admission remains open. These checks neither validate proof
contents nor grant finalized execution authority.

Verifying-key capture checks the exact stored-ID inverse at each record's
circuit/version in both retained native images. Every status and activation
interval remains represented, including withdrawn records without a key envelope.
The shared allocation-free relation precharges physical rows, masked rows,
tombstones and variable-string comparison bounds before inspection; dense registries
may require more local capture work without changing transaction validity or gas.
Both original registry/index identities remain checked through canonical encoding
and the final State generation fence, including validation or encoding failures.
The unchecked catalog reader is removed. Restore uses the same relation and
rejects a corrupt persisted inverse without rebuilding or repairing it; successful
validation leaves its exact physical current and undo maps unchanged. Startup
still has no work bound, and original-owner restore admission remains open. These
checks establish neither verifier eligibility nor complete finalized State authority.

Contract-subject capture retains original bindings, reverse addresses, accounts
and active instances through both-image source validation, exact inverse checks,
canonical encoding and the final native/State publication fences. It preserves
the existing lifecycle, current/pending owner-account and active-code rules,
including inactive bindings and no requirement for historical origin accounts.
Borrowed equality scans precharge physical rows, masked rows, tombstones and
nested key/reason geometry. Each V1 hash-to-point attempt is admitted before its
hash and strict uncached Ed25519 check; work exhaustion remains local refusal.
Bytes-only derivation allocates no key or error backing and never consults the
parse cache. The same private hash/counter loop preserves ordinary `subject_id`
cached parsing and separately owned final account construction.

Restore validates both original source images before replacing the reverse
index and retains canonical source/undo unchanged. Reverse undo records only
differences between projected images: lifecycle-only changes do not manufacture
reverse touches. It does not claim byte-identical arbitrary redundant inverse
history. Original-owner startup work and reconstruction admission remain open,
as do complete State commitments and finalized publication/recovery custody.

Frozen native storage exposes borrowed current rows and physical undo entries
from its original detached owner, preserving acquisition mode and predecessor
identity without cloning rows or reacquiring a reader. The sealed raw-image
boundary lets committed and frozen domain-owner, account-identity, verifying-key,
proof-status, validation-fee and contract-alias sources use their respective shared bounded
both-image inverse relations. Each frozen consumer
requires the actual StateBlock's completely frozen World, all exact State target
owners, equal acquisition modes and its original allocation pool; it feeds current
canonical rows into the existing paired encoder. The proof-status adapter checks
the complete stored `ProofId`/`ProofStatus` inverse in `world.proofs_by_status` at
both original cuts. It does not admit proof contents, proof-record payload IDs,
verifier keys, proof tags or historical finality. Its closed status enum uses three
borrowed stack slots and admits all physical current/undo index rows before
inspecting logical buckets. Insufficient local work can therefore defer before
latent empty-bucket corruption is reported; sufficient work on the same originals
reports that corruption, and neither refusal implies success. Valid exact work
and transaction gas are unchanged. Work, row and byte allowances remain
caller-admitted local controls, and refusal leaves the original frozen source
available for retry. These scoped consumers do not publish a root or establish
complete State currentness.

Contract-alias capture checks the exact stored alias/address bijection and lease
windows in both original images, retaining undeployed and expired bindings. It
prepays every physical row and both complete borrowed UTF-8 keys, without decoding
or normalizing original literals. Its named 6,696-unit per-row descriptor is a local
reference; larger quadratic or undo cuts may defer without changing gas or ledger
validity. See the [scoped relation](frozen_contract_alias_relation.md).

Domain-owner capture retains exact storage-key and stored-owner bucket membership
in both original images, including complete predecessor masking. It prepays every
physical advance and both full domain/controller comparisons without allocating
key normalization or tree lookups. The 1,292-unit single-Ed25519/max-domain reference
is local work policy; wider or quadratic cuts can defer without changing gas or
validity. It adds no account-existence or embedded record-id requirement. See the
[scoped relation](frozen_domain_owner_relation.md).

The fee-proposal adapter checks the exact `(created_height, stored proposal id)`
lookup for both fee kinds and every status in both original images. Its private
fixed-key merge admits every physical row, including masked rows and absent/no-op
undo, before advancing, and prepays both full keys before each comparison (64
bytes for proposal IDs and 80 for height/ID tuples). Both directions use complete
borrowed scans with no lookup, reconstructed map/set or cloned record. One indexed
row without undo costs 328; the committed descriptor replaces its former row-times-8
allowance with this named local unit. Larger cuts have explicit quadratic work and
may defer without changing gas, table validity or consensus limits. Work refusal can
precede latent missing/foreign membership corruption until the complete required
scan is admitted; committed source-identity changes still override either result.
The adapter encodes only checked current canonical proposals, using the actual
complete frozen StateBlock, both original matching-mode owners and its pool. It
does not establish proposal admission, exact JSON, operator identity, Parliament
execution/status/history or policy correctness.

The same 217-output table catalog derives both committed and original-frozen
callbacks from each of its 192 native field declarations. Frozen native callbacks
retain the actual selected field and concrete storage mode, require complete World
freeze and exact State target ownership, and use the original State encoding pool.
They return only existing scoped paired-table snapshots. Raw encoding does not
validate dependent indexes or other fields' modes and identities. Verifier and
domain-owner, account-identity, account-alias, asset-definition, asset-balance,
proof-status, validation-fee, contract-alias, contract-subject, escrow,
repo-agreement, NFT/RWA, account-rekey and trigger action/contract captures use their
complete bounded inverse relations. The scoped catalog has 192 raw adapters, 20 checked outputs
and 5 Musubi and membership outputs with an explicit
missing original adapter; missing adapters cannot yield partial success. Complete structural/cell/history checks and the sole
StatePublication integration remain open.
Account-rekey capture shares one complete four-source relation across committed
and frozen owners, preserving canonical rekey provenance and historical audit
occurrences. It retains native probes and encoding results through the final State
fence, with the original pool and Ordinary/Replace owners. Fresh compilation and
execution remain required; see the [source-coupled relation](frozen_account_rekey_occurrence_relation.md).

Trigger-contract capture shares one complete relation across committed readers,
startup validation and the original frozen Set owners. It checks every physical
action/contract history stream in Current-before-Predecessor order, retaining
complete lookup, code, count and dangling-occurrence checks. Its fixed counter
backing uses the original State pool. All five committed currentness Results
precede propagation; canonical encoding and reader release precede the final
State fence. Frozen capture requires all ten actual Set targets and one common
Ordinary/Replace mode. The registered image-order and inherited codec-budget
controls still require fresh execution; cold/warm allocator evidence and full
native physical custody remain open. Complete State publication remains unfinished.
See the [source-coupled relation](frozen_trigger_contract_owner_relation.md).

The four trigger-action outputs share one relation across committed and frozen
readers. Both images require exactly one typed action for each ID, its exact
ID-kind row, and active membership matching non-depleted, enabled actions. Every
capture retains all ten original Set sources, validates the contract relation
first, scans complete action/ID/active and metadata tails, and uses the same
original-pool counter. Bool-first and then u64 eligibility decoding is shared
with ordinary execution over borrowed Norito JSON text. All native currentness
Results, held encoding, reader release and the final State fence precede exposure.
Frozen capture requires all ten actual targets and one Ordinary/Replace mode.
Fresh runtime, allocation and canonical-byte controls remain required; these
local inverse checks do not establish complete State publication or finality.
See the [source-coupled relation](frozen_trigger_action_owner_relation.md).

Contract-subject capture shares one sealed native relation with committed readers
and startup history. It preserves source-before-index and Current-before-
Predecessor validation, strict V1 subject derivation, lifecycle controls, account
existence, active-code membership and both inverse directions. Physical scans,
complete masking/lookup tails and typed comparison geometry are admitted before
work. Committed capture computes all four currentness Results before propagation;
frozen capture retains the actual four matching-mode StateBlock sources and the
original State pool through canonical encoding. The scoped adapter and its tests
still require fresh runtime qualification. Full publication, startup allocation
custody and serializer scratch remain open; see the
[source-coupled relation](frozen_contract_subject_relation.md).

Asset-balance capture now shares the sole original relation across committed
readers and the caller's eight frozen balance/reference/index owners. Complete
physical masks, lookup/member/partition tails and typed comparison geometry are
prepaid before inspection. Original phased source/index errors, existential
partition membership and quantity-zero checks remain. All eight currentness
Results precede propagation; paired encoding retains its Result and readers
through release and the final State fence. Frozen capture retains exact targets,
equal modes and the original allocation pool, without later reader refresh.
The independent Global reference is4146, valid Restricted reference4148;
original fixtures2144/2838 and absent Global undo735/840 remain exact controls.
The original16MiB physical retry limit is preserved. Fresh runtime qualification,
complete physical backing and sole publication/recovery custody remain open;
see the [source-coupled balance relation](frozen_asset_balance_relation.md).

The complete root and its exact predecessor must travel with prepared State
journals and publish under the same State generation as World, runtime and replay
membership. Retained publication policy/work admission, exhaustive frozen table
and cell capture, and integration with the sole StatePublication owner remain
open. Recovery must authenticate that owner before exposing State. Scoped
paired tables already bind hash-key inclusion/absence and ordered raw-Norito-key
range commitments to the same canonical value encoding. Their bounded range
verifiers authenticate boundaries and interior rows, but neither these selected
table roots nor supplied composition digests establish a complete finalized State
anchor. Complete publication, node custody, recovery and current/predecessor range
integration remain open. Preserve the distinction between execution-prefix and
finalized-State commitments to avoid a header/root/finality cycle; table membership alone grants
no permission to disclose private rows.

The KAGEMUSHA verifier registry, its Parliament transitions and runtime artifact
cache were deleted with the old KAGEMUSHA implementation on 2026-10-05.

The sole native capture constructor now accepts public empty-argument roots with
an exact artifact-selected Unit or Bool leaf result. One return relation retains
all four original u16 limbs: Unit requires zero; Bool requires a Boolean low limb
and three zero upper limbs. Original gas debits, typed memory, initialization
scan, packet/history joins, workspace geometry and degree bounds are unchanged.
Unsupported aggregate, pointer, private, nested and syscall profiles remain
outside this local component. Fresh runtime qualification, complete physical
funding, jointly committed masked invocation/output columns and a registered
native STARK execution relation remain open; these local equations establish no
proof or finalized-State authority.

G3 retirement now removes the old four-hash/16-column binding schema, Halo2
IVM registration and key generator, dedicated native STARK binding relation,
Torii preparation/proving jobs, and SDK/CLI callers. The generic proof registry
rejects reserved IVM identities. Focused Core/Torii test builds and regenerated
OpenAPI provenance are still pending on the changing source tree.
The V1 statement model's `IvmCompleteStateRootClaimV1` is intentionally separate
from the current selected-table leaf/subset roots. Its constructor and digest
authenticate nothing on their own; only a Core-owned finalized State/Kura/QC/DA
handle can promote a root claim to an execution anchor. The access, return,
effect and event hashes are public claims until the complete interpreter/STARK
relation constrains their exact canonical contents and Core checks every current
dependency before transactional application.
Retain reserved-name rejection at generic proof-registration and OPEN_VERIFY
boundaries so removing the special binding circuit cannot re-admit it through a
generic digest circuit. The fail-closed admission is not evidence for private execution or finalized
full-state proofs; public preparation needs a new admissible V1 response shape.

The Norito lazy decode context retains its single original budget layer inline.
Clones share the same cumulative counters and preserve enclosing limits, depth and
unwind behavior without allocating a replacement layer vector. The counter owner,
TLS capacity, payload/scratch and decoded values still require full admission;
this change does not establish complete decoder allocation funding.

G5 production activation still requires funded fallible remaining trace/debug and
shared-host dispatcher allocations; scheduler graph/result/channel/pool allocations;
remaining generic `Memory::Clone` allocations; and fully prepaid
active and nested host execution. The protected return stack is now reserved before
child-call gas, and call-frame bitmap and vector-slot growth is prepared before
table-validation gas. Inactive runtime-template copies no longer duplicate spare
frame capacity. These bounded cuts do not fund all frame and scratch owners.

The V1 numeric payload writer borrows the existing canonical BigInt serializer,
writes decimal/quantity scale through the same destination and computes exact
body lengths without temporary buffers. Frame construction keeps its bounded
69-byte body on the stack and uses the existing nominal Norito header/CRC writer.
Opaque numeric-frame preparation now retains the exact immutable source borrow
and minimal length; owned and prepared encoding share that same nominal writer.
The four framing-only native-digit clone sites are removed. Output-length and
byte debits still precede canonical frame/envelope/hash and host allocation, with
result/status publication only after success. Preparation allocates no temporary
storage; the real frame-name String and final frame Vec remain counted. Decoded
native digits, arithmetic intermediates, materialized results, numeric snapshots,
schema initialization and final frame/envelope buffers still require physical
custody. Current-candidate byte, fault and gas parity and the isolated allocator
census remain required.

Private interval storage in State-owned VMs retains the original active pool;
growth reserves replacement capacity while the previous allocation remains live,
template copies partition the existing parent reservation, and warm reset reuses
interval capacity after a fallible preflight. Retention or a reduced pool limit
does not refund live interval storage.
Local diagnostic step/access recorders and the optional initial image now use
one checked parent-funded plan with child partitions; four new and 20 existing
recorder tests pass. Diagnostic owner coverage does not qualify remaining production scratch.
Parent-credit shortage
must not wait while holding parent funding. Configuration changes must retain the
original pool while allocations survive. Prepared-contract cache operations defer
original-pool refund notifications until their store mutex and complete preparation
claim are released, including partial-allocation refusal and unwind, and preserve
enclosing State refund batches. Register logger shells reserve their exact physical
shared owner from the VM's original pool before construction or invocation replacement.
TLS scopes and borrowed loggers retain that credit through final release; cache retention
does not charge the shell twice. Replacement refusal precedes guest-state or log changes,
and invalid detached host custody severs aliases without allocating. Syscall instructions
admit one detached shell before base gas or cycle debit; default-root input preparation
admits it before argument effects. Reserved quote and body callbacks reuse that shell,
checking the same invocation, code, trace epoch and mode before each isolation.
TLS scope retirement
releases its RefCell borrow before final-owner callbacks. Per-cycle register/memory
root rows use fixed backing admitted from the same VM pool before instruction or
padding effects, including a twelve-cycle instruction crossing the configured cycle
limit. Growth retains old and new credit until replacement publication; reset preserves
the original pool binding. Test-only snapshot copies own their independent row credit
without charging it again through the aggregate trace estimate, and defer refunds until
register-log guards are released. Register paths own eight inline digests copied from
one canonical borrowed, exact-size sibling traversal; the owned crypto proof API
collects that same traversal. Dirty and clean register path extraction use the existing
fixed tree backing, with no temporary proof or path allocation. Live register events
carry the fixed path inline, and detached diagnostic verification still rejects short,
long and out-of-range borrowed paths. Register-event rows now retain exact fixed
backing from the original VM pool. Growth admits replacement capacity while the old
allocation remains live; initialized values, tags, paths and roots are erased before
retirement. Root preparation, instructions and syscalls admit public upper bounds
before their effects. Nested scopes partition the existing event quota, host masks
preserve it without emitting, and an instruction retains its quota through delayed
native completion. Independent diagnostic snapshots fund their own copied rows;
retaining or evicting a shared logger never refunds another borrower's live storage.
PC and delta rows now retain fixed backing from the original VM pool. Instruction
preflight admits public destination bounds before effects, including root argument
preparation and payable padding; unused quota is cancelled on refusal or unwind.
Growth funds old and new storage together, and clears initialized values and tags
before retirement. Independent snapshots copy full public capacities with their
own credit. Immutable runtime captures admit their shared shell and complete row
storage before copying, retain the original optional pool through final release,
and reject composition across different owners as a local execution deferral.
The Kotodama test driver shares captures through checkpoints, preserves root-before-
nested report order and creates child VMs in the caller's original pool. Trace-off
runs allocate no capture. These changes do not fund every remaining diagnostic,
host, scheduler or standalone owner.
Semantic trap capture now retains only inline scalar context and a source-map
index. Diagnostic views borrow text from the VM's original metadata owner;
rendering uses the original returned error. Local refusals have no completed trap
view, and run/load/reset preflight clears stale context before any early return.
Core's public contextual mapper preserves the original typed refusal and its
allocation owner before formatting. Completed `ContractAbort` mapping moves the
original contract, error-type, name and optional-message backing into
`ContractRejected` without replacement string allocations, including through
metered abort wrappers. Other semantic errors retain their original metered
context and diagnostic display. Initial declared-error construction, source-metadata
storage and presentation allocations still require funding.
CLI contract-debug invocation classifies the original VM error before draining
host effects or constructing a completed report. Local refusals retain their typed
error, including metered wrappers and allocation custody, at the operational error
boundary. CLI return collection keeps its original typed decode error with static
context rather than replacing the cause with a formatted string. Torii view and
call-simulation return collection likewise preserves the
original local refusal before rendering a completed rejection; deterministic
malformed returns keep their semantic response. These checks do not fund rendered
diagnostic strings, CLI presentation or HTTP response allocations.
State dynamic access prepasses now use the original prepared-cache pool
for VM construction and raw-selector preparation, preserve typed VM resource refusals,
and decline optional hints through the existing conservative access/fence boundary.
Shipping standalone/CLI VMs, state-free overlay helpers and State seed/restore dummy VMs
without an explicit execution budget remain open funding boundaries; they are not
qualified by the funded paths above. Global cache
configuration publishes limits, retention budget, shard geometry and the snapshot
before eviction callbacks; callbacks can reenter ordinary configuration writers
without the outer writer partially overwriting their changes. The configuration
guard remains reentrant and held through callbacks; enclosing non-cache locks
still require their original refund owner. Generic-program verification and cold
runtime/template allocation now use the existing State pool. Generic summary bytecode
reserves its exact fixed backing and shared control from that same pool before
allocation; summary/image clones and evicted borrowers retain the original credit
until both allocations are reclaimed. Local cache eviction
and both State generic outer-cache sites defer refunds until their locks and leases
are released. Generic admission preserves typed allocation refusal through overlay,
executor and trigger owners, including original analysis allocation refusals;
trigger policy reuses the existing prepared cache
instead of creating a separate pool. Executor restore now performs the same static
admission as the VM loader without an eager default VM. Live validation and
migration fund VM images and baselines from their State's existing pool; warmed
variants keep the first pool's identity, while foreign-State clones execute
uncached on their own pool. Executor eviction and lease return defer original-pool
wakes until the pool guard and enclosing same-pool refund scope have released.
Decoded and prepared instruction arrays now reserve their fixed backing and shared
control from the original State pool before decoding/preparation. Same-pool loads
share those owners; diagnostic or foreign-pool arrays are rebuilt under the actual
VM pool before installation. State arrays bypass process-global code-only caches.
Contract admission also funds its temporary instruction buffer, and State contract
preparation funds the shared artifact image. Retained control-flow boundaries and
successor nodes are constructed directly in funded shared arrays without temporary
vectors; every clone retains the original credit through final reclamation.
Literal admission and native preparation share one borrowed descriptor/envelope
validator without directory vectors or payload copies. Native literal values and
pointer-provenance indexes reserve their exact original-pool arrays before
construction, rebind foreign-pool storage before VM installation, and retain credit
through snapshots and final borrowers. Empty indexes have no shared shell. Typed
canonical literal refusals preserve their original local classification; malformed
payloads retain the same deterministic admission failure.
The prepared contract's shared shell and fixed entrypoint index reserve their exact
original-pool layouts before allocation. Name lookup sorts descriptor indices in
place and borrows immutable metadata names instead of cloning strings. Private-input
reachability reuses one fixed queue/visited buffer, marks instructions on enqueue,
and releases scratch before publication. Shell and index charges remain with the
final shared borrower through eviction, pool shrink and unwinding; diagnostic
preparation does not grant a funded State owner.
Stateless instruction counts and syscall classifiers scan validated borrowed
instructions without decoded arrays or aggregate reports. Aggregate syscall analysis
reserves exact occurrence scratch and immutable histogram storage from the State's
original pool before allocation, preserving full-width IDs and sorted counts. Cache
hits and report clones share that histogram; eviction, shrink and unwinding refund
only after its final owner, with notifications deferred through the actual cache
and enclosing State guards. Empty histograms need no shared shell; zero retention
keeps only live analysis owners. Optional static-state dataflow borrows original
entrypoint roots and reserves combined instruction-fact rows and a bounded FIFO
from the actual State pool before traversal. A queued flag coalesces pending
changes while preserving the existing fixed-point merge. State-key analysis borrows
original pointer envelopes and Norito payloads without eager hex tables, retaining
the first symbolic key per state-syscall site through later ambiguous merges.
Sorted, distinct output keys reserve their exact UTF-8 arena, range index and shared
shell together before allocation. Read/write views and clones retain that original
pool charge through the final owner; empty results allocate no shell, and traversal
scratch is released before publication. Local refusal at traversal or key publication
declines exact scheduler hints and keeps conservative fences without changing gas
or transaction validity. Literal text analysis uses the shared Norito nominal-frame
validator and borrows original Name/StatePath bytes. One exact index and audited
ICU/stable-sort scratch demand are admitted together from the State pool before
allocation or NFC validation; normalization retains no replacement string, scratch
ends before publication, and index credit follows its actual lifetime. The shared
model predicate preserves syntax, exact NFC and original nominal identities; owned
binary and JSON decoders charge the same audited normalization demand. Physical
allocation census and owned/view framing parity remain required validation gates.
State artifact-admission consumers preserve local refusal through their existing sticky
transaction or overlay owner. Remaining raw executor/registry byte copies,
metadata and other typed literal decoder storage, admission-policy scratch,
cache indexes and executor-pool control
allocations, and host scratch still need funding.
Core exports
measured resident, reclaimable, borrowed, evicted-but-live and peak
reservation gauges alongside retained, active and unmeasured-owner totals. Composite
retained-owner classification and funding missing active/scratch owners remain open;
these gauges do not represent complete process RSS. The new
pool and buffer APIs are not evidence that those production paths are funded.
Shared and local idle-runtime rows now use one optional fixed ExecutionBuffer
backing reserved from the original pool and carried through the real active lease.
Warm checkout and return transfer that backing without growth; eviction refunds
only at its final reclamation. Cold row refusal declines retention after mandatory
VM/template admission, preserving completed guest outcomes and gas. Cache indexes,
executor controls, host/native scratch and composite retained-owner classification
remain open, and the current candidate still requires fresh execution tests.

G6 ordinary Linux and Windows daemon dependencies now include IVM CUDA, including
builds without default features. Apple builds retain target-appropriate Metal;
CPU SIMD remains capability-selected. The CUDA driver is loaded at runtime without
toolkit or driver linkage. One source-owned optional approval descriptor admits
only the exact signed manifest/key pins and ten unchanged kernel families through
the shared canonical borrowed verifier. Genuine bundle absence preserves ordinary
CPU builds and startup; supplied unreviewed, partial or nonregular material is an
error. Runtime admission retains the original immutable inputs before device or
private staging. Retired mode/environment/trust-input paths, daemon aliases and
placeholder PTX tests are removed. Ordinary startup neither compiles nor downloads
kernels. The approval remains `None`: authentic reproducible signed PTX, two clean
offline runs, twenty actual kernel completions, calibrated selection and hardware
parity remain open gates. Source and driverless tests do not qualify GPU execution
or a release candidate.

FASTPQ Metal has one private immutable compiled-bundle admission owner before
device discovery or private staging. Ordinary builds and startup no longer invoke
the Metal toolchain, compile source or resolve retired library-path aliases. The
sole explicit offline producer records eight ordered source inputs, six modules
and sixteen entry points with create-only publication and complete source/tool
currentness checks. Its metadata cannot authorize its own output. The actual
approved bundle remains absent; optional execution preserves CPU behavior and
explicit required-GPU policy preserves operational refusal. Genuine independently
reviewed compiled bytes, signed provenance, all sixteen real pipeline loads,
complete parity, calibrated selection and driver allocation/recovery custody
remain open. Source integrity and mocked producer controls provide no hardware
qualification or complete prover evidence.

BN254 add/subtract/multiply and Poseidon2/Poseidon6 batches share one nonblocking
public calibration scheduler. Five inline profile cells belong to each original
physical device/kernel policy and bind the exact artifact and CPU implementation.
Selection uses public batch counts from 64 through 4,096, fixed known-answer
operands and complete operation timings, including transfer, launch, validation,
copyback and cleanup. Conservative CPU/native bounds require a clear estimated
win; measurements never authorize an unqualified kernel. Original selection and
policy are rechecked before any caller write, with complete CPU recomputation on
refusal. Calibration receives no production completion credit. Signed performance
provenance, every kernel's fastest-path coverage, native CUDA compilation/device
qualification remains open. The canonical V1 CPU parameter owner now stores all
621 unchanged width-3/6 fields in fixed canonical byte arrays. Canonical Fr
initialization and exports, IVM four-limb banks and FastPQ flattened banks use
fixed inline arrays; the original generator is a test oracle only. This removes
heap parameter generation and export owners without changing domains, kernels,
gas or defaults. Full-field oracle/digest, complete-state parity and fresh-process
cold/warm allocation controls still require current-candidate execution. The finite pass
checks expiry between completed attempts; it does not interrupt a native call.

Merkle construction, root-only hashing and retained-tree rehash resolve one
operation-local policy from the complete acceleration configuration. Reapplying
`None` restores defaults or generic inheritance; `Some(0)` is an explicit zero
floor. Each backend's floor overrides the generic floor, and an available CPU
SHA2 ceiling applies to all three operations. Admission retains the existing
native qualification, staged publication and canonical fallback owners; these
operator thresholds do not establish fastest-path calibration or CUDA readiness.

G7 native Check binding and finalized verification return move-only failure owners.
They retain the original preparation, signed transaction graph, State pool and
absolute deadline; retry cannot replace them or request another signature.
Canonical framed transaction bytes reserve their complete output before encoding
and remain charged through native comparison and final readback. A single native
frame validator preserves local codec refusals; only completed semantic errors
become transaction rejections. Final-promotion, account, stream-token, gateway and
pin-outbox wrappers share the same exclusive original binding slot through late
history, clock and current-row checks. Successful readback consumes that slot;
failed verification returns the unchanged Pending. Gateway rechecks preserve the
already accepted UTC lower bound when returning Pending for fresh verification.
State-backed canonical source callbacks and certificate walks carry original typed
local refusals without inferring capacity from a wire `GasBudgetExceeded` value.
Walk coordinates use the original State pool and refund on completion, refusal or
abandonment; this does not fund the entire nested decoder/proof graph.

Daemon and Torii service boundaries retain retry owners on their stack during
bounded backoff, without a State view, pool mutex or parent execution lease.
Only terminal rejection or original expiry maps back to the existing service
error surface. Direct daemon submission borrows the pending owner's exact
transaction and deadline. The observer's combined sign/submit/finality transport
still has a pre-return custody gap. Signing, serializer and historical World-row
scratch ownership, opaque historical helper diagnostics, the complete publication
runner and restart/recovery qualification remain open. Musubi account/instruction
frame measurements preserve original codec refusals through the same binding
owner; pure coordinate validation cannot turn them into terminal transaction errors.
Stream-token evidence uses one typed admission outcome: original canonical decoder,
bounded-encoder and allocation errors remain distinct from completed semantic
rejections. All three public evidence verifiers borrow the original expectation in
place. Its private phase retires before verification starts and remains retired on
success, completed rejection or unwind; only the original retryable admission result
restores readiness. Repeated use rejects before decoding without allocating. The
returned error owns no expectation, and the former move-out failure API is removed.
After an observer reply returns, one move-only phase retains the exact
reply, original expectation/challenge, native Pending and absolute deadline while
borrowing the original receipt, token, preparation and custody markers. Bounded
local backoff retries only admission of those returned bytes with fresh handle/time
validation. Authentication, native verification and final acceptance have separate
owners; no retry calls observe, signs, submits or renews a deadline. Changed pins,
clock rollback and invalid evidence remain terminal. Immediate daemon and broker
boundaries preserve operational versus semantic categories without granting retry
custody through their fixed service errors.

The native completed-observation producer retains its own actual verified Check,
charged canonical frame and original Prepared deadline through unsigned body,
fallible payload encoding, one successful observer signature, signed-frame encoding
and a late native floor/time check. Only original evidence-admission or native
Deferred errors retry with the same owner. The exact encoded reply is retained
through the late check; cryptographic signing failures are terminal. This producer
Check remains distinct from Torii's prepared Check.

After its one complete socket read, the broker observer client retains the exact
response frame, operation request, admission permit, locked connection and original
15-second call deadline through phased canonical decoding and envelope/body
validation. Only original typed local codec or bounded-encoding refusal retries;
successful phases and the exact reply leaves stay owned. No retry writes, reads,
observes, signs or submits again. Immutable metadata and protocol failures remain
terminal. The authenticated server admits one absolute observer-operation deadline
before provider qualification and its one synchronous Observe. Its file-configured
budget is nonzero, defaults to the existing 15 seconds and cannot exceed that bound;
handshake and wire ingress retain their separate transport bounds. Embedded server
APIs carry the parsed broker policy, and standalone launchers read one bounded public
TOML policy file instead of an endpoint override.

Credential assembly validates the canonical catalog's positive memory bound against
that same parsed policy before either platform credential handoff, disposable input
or backend discovery. A zero catalog bound permits only inventories without either
threshold-signing slot. The software signer consumes its originally loaded catalog
through imports and executable assembly; the sole in-memory constructor does not
reopen its source file. Both platform threshold handoffs receive one original policy
pool, and currently admitted transcript owners retain its charges. This is local
operational admission, not current provider authority or transaction gas. Parliament
TLE import prepays its actual decoded handle/session/nested-vector backing, fixed
charge ledger and canonical prepared decoder controls from the same original pool.
The private backend retains that ledger through its final registry reader; payload
destruction precedes refund, and an unproven consuming unwind retains credit. Public
inventory hashing borrows the original sessions, and dealer validation uses the
existing 31-seat inline bound. Supervisor input buffers, outer shared controls and
Core custody-map nodes still lack complete physical funding and remain open gates.

The server's move-only completed-reply owner borrows the original accepted socket,
request, raw frame, inbound/decode admission and lifecycle permit. It retains the
actual returned reply, decoded query and original deadline across typed observation
admission, separate retained record/observation copies, wire encoding, response digest,
envelope validation and outer framing. Successful phases do not repeat; only original
typed codec, bounded-encoder or allocation causes authorize bounded local backoff.
Immutable handle qualification, protocol/cumulative limits and fixed backend service
categories remain terminal. Final qualification and the first write use that same
original deadline and complete encoded frame. Request IDs remain retired; local retry
cannot Observe, sign, submit Check, replace the socket or renew the budget.

Boundary checks suppress late publication after a synchronous provider returns; they
do not forcibly cancel a provider already running. Once the first write is attempted,
partial or failed I/O is terminal transport uncertainty and never re-enters the local
reply owner. Physical bounded-encoder/allocation refusal probes, complete backing for
existing buffers/scratch/clones and release qualification remain open. Combined
`finalize_check` sign/submission and partial socket I/O remain separate transport-custody
gaps; no process-local owner supplies durable restart recovery.
Nested receipt/custody codec projections, late consumer native/current-State
acceptance refusals and original-pool funding for existing reply buffers,
decoder/serializer scratch and native proof owners also remain open. No continuation
supplies durable recovery or activates the publication runner.

The local physical runner is an Apple M1 Ultra with 128 GiB memory. Exact-candidate
M1 Ultra calibration remains unrun. Graviton3 calibration, CUDA parity,
mixed-hardware four-validator execution and publication qualification still need
their required runners and service custody. Historical component kernel checks
do not qualify the current release candidate.

TODO: Freeze and record one complete candidate, regenerate all native/SDK artifacts,
and replace each open gate with its actual evidence. Physical runners, provenance
signing and deployment credentials are required inputs. Do not infer release
readiness from local components or represent skipped/missing execution as a pass.
