# Validator staking completion

This is the source-coupled implementation and qualification plan for validator staking.
It separates instruction implementation from production validator qualification.
No live deployment or release readiness is established by this record.

## Active implementation goal

The complete first-release implementation and qualification goal is active.
Implementation and validation use only the `optimizations` branch in
`/Users/takemiyamakoto/soramitsudev/iroha`. Results from another checkout do not
qualify this candidate; all outstanding gates must run against this source.
The selected design replaces retired layouts and paths; backward-compatible
decoders, aliases, shims and parallel implementations are prohibited.

| Milestone | Completion gate | Current state |
| --- | --- | --- |
| Custody and lifecycle | All focused staking, reserve, snapshot and restoration controls pass | Earlier focused Core custody, rollback, fee and restoration controls passed; the current shared beacon custody API and typed restoration errors await fresh compilation and runtime checks, followed by unchanged-candidate network qualification |
| Canonical XOR | Genesis-pinned network XOR funds bonds, rewards and withdrawals; no synthetic staking definition or implicit production minting | Immutable network XOR pin, global scale-nine genesis/operator validation and early staking/reward custody checks implemented; production implicit minting removed; current-candidate component and integration validation pending |
| Authority and election | Separate key generations and scheduling epochs; freeze E+2 membership at E and prepare through E+1 | Generation/authorization, authenticated native epoch graph and pristine E+2 boundary capture are integrated; current Core, runtime and network qualification remains open |
| Atomic transition | All target seats ready; current exact quorum certifies activation or retention and cancellation; restart preserves both sessions | Native prepare/activate/retain source capture, BLS-authenticated control, atomic application barrier and current/predecessor restore join are integrated; snapshot chain/network identity is checked before typed restore, but positive-height startup and real restart/transition qualification remain open |
| Monetary fees | Exact signed effects, bounded claims with retained dust, and principal distinct from assessed fees | Monetary plans and native effect checks are present. Required explicit fee-reward claim bindings and additive shared custody are implemented; canonical reward-currency admission, current-policy integration, multisig/proved execution and paid network coverage remain under validation |
| Production progress | One funded original execution reaches durable Apply; native lane runner is the sole production owner | Native execution/context retention, deterministic history and Kura's fail-stop gate are integrated. Complete original-pool funding through World/DA/proof graphs, publication, replay and retained-generation reclamation remains open |
| Operator/client delivery | Canonical signing, provisioning, status, SDK and fixture workflows | Candidate and credential commands and native evidence readers are present. Same-source native artifacts, regenerated fixtures, complete SDK consumers and operator network qualification remain open |
| Unchanged network qualification | Real 4→7→4 network, faults, replay, restart, penalties, rewards and full withdrawal; maintained formal/DA/workspace/SDK gates | Pending |

Rewards automatically accrue from authenticated funded XOR conversion using
historical validator and nominator exposure. Committee preparation
takes one full epoch. Every boundary advances the scheduling epoch; certified
retention keeps the current key generation without claiming forward security.
Missing target readiness cannot change the frozen roster in place. Missing the
current quorum does not authorize weakened voting rules.

The freshly compiled full Iroha DLMM fixture is 59,961 bytes, including 33,800
bytes of code. Removing private forwarding functions and selecting the swap
direction once before a common call removes 344 bytes from the 60,305-byte
baseline: 272 code bytes and 72 metadata bytes. The public manifest changes only
its code hash; schemas, permissions, access hints and ABI hash remain unchanged.
This measurement covers the full current Iroha fixture. The sibling SoraSwap
source still needs its current-language and shared-traversal migration;
cross-repository source or artifact parity remains unqualified.
Seven codec, three allocation and two compiler controls pass for CS1, together
with both JavaScript tape controls. Complete genuine native outputs are recorded;
mandatory reproduction rejects the obsolete captures, whose replacement awaits
the public schema format before canonical publication. The earlier full compiler
library run passed 1,241 controls and failed one spill-shape fixture that still
expected removed zero instructions. Its exact correction preserves reload
registers, lifetimes, operand order and independent original-zero comparisons;
a fresh full run with regenerated fixtures is pending.
The current IVM run passed seven of eight local cases; the map recorder's exact
diagnostic allocation was underfunded before execution and its repaired fixture
awaits a fresh run. Full compiler and VM candidate qualification remain open.

The full current Iroha DLMM fixture passes the production native wrapper and
effect-owner test under the unchanged default four-million-gas limit. Both the
full DLMM and funded-pool cases preserve nested pool authorities and exact
output through the signed callback. The artifact's nested byte charge remains
3,837,504 gas at the unchanged 64-gas-per-byte price; no metering or policy
allowance was relaxed. Focused native integration tests pass scheduled full-DLMM
and funded-pool conversion, automatic accrual for multiple validators and
nominators, authenticated signed claims and certified suffix replay. Real
four-peer network qualification remains open.
The strict workspace source inventory refuses an unsafe nested checkout path;
component measurements do not establish candidate or network qualification.
TODO: qualify the actual enacted payout under the default policy on the
disposable network, including all original byte and execution charges.

Canonical XOR means the asset authenticated for the particular network, not a
second token named XOR. Taira's public identity and an operator-provisioned SORA Nexus
identity are not interchangeable. Disposable-network allocations are explicit
genesis test allocations and are not claims of mainnet monetary value.

Kagami generation and profile verification require global scale-nine XOR for
both Taira and an operator-provisioned SORA Nexus identity. Core's shared
`state/network_xor.rs` guard binds the committed currency before staking deposits,
reward claims and fee-policy use. Retained custody and current/predecessor
stake/reward restoration reject incompatible definitions and scoped asset IDs
without rewriting the source. Positive, substitution, scope, precision and actual
transaction-rollback controls are implemented; their current-candidate gates
remain open.

Earlier focused Core compilation and custody/lifecycle checks passed. Repairs to
canonical DKG frame geometry, prepared credential funding, obsolete custody
fixtures and operator proof transport await complete combined Core and daemon checks. Complete
resource funding and unchanged-candidate real-network transition/monetary
qualification remain open.

## Implemented candidate under validation

The production owners are `lanes::LaneRunner` and `SumeragiLaneMerge`, specified in
[the lane specification](sumeragi_lanes.md). Custody and execution tests must
exercise these owners. The canonical execution proof/archive and strict
current/predecessor snapshots use complete
`SumeragiLaneState` in the integrated source. Native routing uses the same
committed policy for direct inputs and merged suffixes. Shared lane evidence
verification reproduces admission and checks the actual native quorum. The
current compiler/runtime gates and complete resource funding remain open.

Canonical executed blocks now use one `SharedSignedBlock` control admitted from
the original allocation pool. Certification moves the existing block graph into
that reserved control; publication, Kura and authenticated readers retain the same
handle. Local history allocation refusals remain typed through lane anchors,
restoration and DA reconstruction. A refused DA reconstruction publishes no
partial index and caches no invalid verdict. The control-owner regressions do not
qualify funding of nested decoded graphs or the full Validate-to-Apply path;
those obligations and current-candidate Core/network execution remain open.

Release waits use reusable registrations prepaid from the original pool;
there is no zero-argument or first-poll allocation path. The driver retains each
prepare, append, commit, payload, witness and control refusal with its exact work
and source. Its fixed 1,024-sender input bank and waiter controls are prepaid;
inline control values retain their complete context and a local occurrence token
through worker moves. Context cancellation and shutdown unlink affected waiters
before releasing original resources. Pending wire admission retains partially
admitted bytes and its typed refusal, and defers original-pool refund callbacks
until ingress mutexes release. Source-less failures use bounded backoff. The
charged wake unparks the driver without allocating a channel message.

Completed replay keeps its exact receipt through encoding refusal. The serialized
executor and startup replay error preserve original storage and publication
refusals instead of converting them to strings. Cold World-root verification
retains the actual storage refusal separately from a stored-root mismatch.
Native beacon readiness, attestation, driver and subscription startup failures
also retain their concrete errors through the serialized worker and node boundary.
Committed-history startup assembly preserves original cold-read refusal for both
global and lane callers; absent or corrupt history remains a separate completed
failure.
Verifier-key inverse validation also preserves the actual current/predecessor
storage reader refusal through snapshot decoding and daemon startup. Local
publication contention or reader poisoning cannot authorize empty-State fallback;
completed inverse inconsistencies still reject the snapshot. Startup relation-work
admission and the new connected reader regressions remain under qualification.
Connected regressions exercise
retirement after success, actual archive failure and post-publication unwind.
These implementations require current-candidate compilation, regression and
mutation qualification; component passes do not qualify the whole driver or network.

The immutable validated beacon session now owns its complete canonical graph,
shared control and verifier workspaces through one original-pool admission.
World current and undo rows, runtime signers and prepared credentials retain that
same seal; restore validates both generations before installation. Credential
registries use an explicit configured aggregate bound, exported in the sole
canonical provider catalog. Native provisioning commands use one explicit
operation budget. These connected changes are integrated but await Rust
compilation and runtime qualification.

Borrowed credential, lifecycle and broker encoders forward the canonical field
payloads without duplicating retained graphs. Provisioning retains its verified
session in the original caller pool. Snapshot beacon and lane custody failures
retain their typed causes and cannot select an empty-State recovery fallback.
Each broker operation retains its original authenticated beacon session across
request validation, signer dispatch and response validation. Reuse checks the
complete session record and the external binding; it cannot substitute a graph
with matching identifiers. Resource-saturation controls and the maximum-committee
socket deadline still require execution. Raw decoder and encoder backing remain
separate funding obligations. These repairs require the same pending compilation
and runtime gates.

The Rust client's shared canonical response decoder retains the original typed
decode attempt, including local resource refusal. Committee readers also preserve
the native finality decoder cause through query and transport boundaries. Stable
operation IDs identify these errors; the top-level SDK error moves its source
instead of cloning or flattening it. All affected consumers and their canonical
fixtures still require current-source compilation and runtime qualification.

TODO: complete original-pool funding of nested execution, proof and startup graphs,
including broker decoding, native-journal artifact and block graphs, and the
outer World/registry containers. Prepared DKG input banks and retained transport
frames are integrated but still require their runtime gates. Polling, rearming, cancellation
and release must remain allocation-free after admission. Physical-history and State
readers must retain actual release owners, with callbacks outside enclosing fences.

- The global native scheduler, signed-genesis committee builder and historical
  committee reader now require the exact `3f + 1` geometry (4 through 31).
  Restored windows also validate retained entries and canonical signer order.
  The schedule retains the original authenticated proofs and roster after genesis;
  mutable candidate registrations and key expiry cannot change voting authority.
  The native epoch graph, pristine election capture, BLS-authenticated control paths
  and boundary barrier require current-candidate component and real transition
  qualification.
- Account-owned lifecycle and signed peer consent: `isi/staking.rs` in the data
  model and Core, initial executor dispatch, canonical instruction
  registry and generated record fixtures. Consent binds network and exact
  activation tenure; rebind also binds the previous peer. Ordinary peer
  administration retains its permission gate. Fresh candidates enter the future
  election pool with exact funded XOR custody. The native scheduler now retains
  the authenticated roster and original proofs instead of promoting live
  Validator-role registrations; its candidate-pool and retention tests await Core
  validation. The integrated pristine boundary producer freezes the exact E+2
  target for a complete E+1 preparation interval; its BLS-authenticated control and
  network gates remain open. Requested election exit and actual end of service are distinct fields;
  retention extends pending-unbond slashing and release heights.
- CLI candidate registration, signed rebinding, bond/delegation, scheduled and
  finalized unbond and authenticated reward claiming. Runtime peer signing inputs
  use the existing owner-private file loader and remain outside the repository.
- Automatic funded validator/nominator rewards use authenticated service and
  historical eligible exposure, with zero commission. Chronological exposure
  pages are bounded to 128 KiB, 256 recipients, 1,024 cohorts and
  4,096 stake entries. Each earning month admits at most 4,096 distinct validator
  beneficiary roots. Capture creates at most one new page per serviced validator
  per block, bounded by the global committee ceiling of 31; adjacent identical
  exposure only increments its existing cohort. Capture seeks the current and
  undo trees by the policy's staking-owner lane and each authenticated validator's
  exact prefix. It does not scan unrelated retained validators or shares. Each
  validator has at most 256 retained parent positions; current-block touches to
  that same prefix remain bounded by admitted block work. An inactive policy
  traverses no staking rows. Staking participant and recovered
  reward-owner identities
  must fit 256 canonical Norito bytes; this does not limit the general account
  identity model. Account recovery while reward custody is retained must fit
  that bound for both the old beneficiary identity and the new owner.
  Registration, nomination, recovery and payout-lifecycle admission
  enforce that bound before creating an obligation. A full page rolls over even
  during mandatory slashing, without limiting the number of earning changes.
  Payout custody/provider identities have the same 256-byte cap. The complete
  hot signed fee-policy registry is limited to 1 MiB. Native maintenance removes
  superseded pricing and payout prefixes only after authenticating their exact
  original committed corpus. Its checkpoint binds the source height, registry
  hash, immutable genesis-policy hash and contiguous retired revision floors.
  Pricing retains the schedule at the earliest unsettled-wallet month, policies
  referenced by current-block settlement receipts and every later scheduled revision; payout
  retains the parent-service policy and later revisions. An append exceeding the
  remaining hot-state budget is still refused atomically. Settled historical
  revisions consume archive storage rather than the hot registry budget. Restore
  validates the checkpoint against one certified source, and historical policy
  proofs read the exact original registry rather than reconstructing it from
  current state.
  Retained signed oracle reports are limited to 16 KiB each and a funded
  allocation to 3 MiB before conversion mutates any reserves. Together with the
  identity, registry and page limits, these bounds keep a mandatory page and
  its independent evidence sources within the 8 MiB block corpus. Mandatory
  accrual runs before the optional idle-wallet sweep, whose complete batch
  rolls back when its additional receipts exceed the remaining budget.
  Before customer instructions, each committed block advances at most one funded
  exposure page per retained payout binding. Reward cursors create no blocks or
  transactions; a completely idle chain waits for ordinary submitted Network
  work or certified lane merges to produce the next block.
  Each changed tail also enters the original block's independent native archive
  projection. At most 31 tails, each with a bounded predecessor reference, fit
  within 4 MiB alongside the monetary corpus inside the 16 MiB native archive
  budget. World retains at most one mutable tail and a fixed-size head per outstanding
  validator/month. Rollover removes the previous tail body after its original
  certified archive is available. Every predecessor link binds the complete
  canonical archive wrapper. Accrual follows those links newest first while
  preserving each page's exact chronological service offsets and cumulative
  quotient allocation. An unavailable original archive defers the complete
  transaction; it cannot erase a source or change an entitlement.
  Closed-month maintenance authenticates and cools resident tails to their head
  references, including months awaiting delayed funding. After all original-month
  wallet fees are settled, its closure seal forbids new credits; with no pending
  funding or active allocation, bounded round-robin maintenance retires the month
  summary and heads. It examines at most 64 candidates per block even while an
  allocation advances, so an older delayed conversion does not pin unrelated
  completed months. A native monetary checkpoint compacts original funded allocations,
  entitlement and claim receipts into exact lifetime totals and outstanding
  original-beneficiary balances; the active allocation and uncompacted block
  remain hot. Retirement journals require the original authenticated evidence
  before removing any receipt. Superseded beneficiary revisions enter the recovery
  block's retirement journal; compaction verifies the original predecessor and
  successor evidence before retiring them alongside that block's claims. The
  current owner and aliases needed by delayed exposure remain live, while original
  native archives retain the audit trail. These bounds limit resident bodies and work per block;
  cold chain custody and outstanding month or beneficiary roots have no fixed
  lifetime disk cap. Entitlements never expire.
  Exact source-asset reserves
  protect unpaid rewards through transfers, burns, aggregate batches and
  snapshot current/predecessor restoration. Per-validator custody pins the exact
  scoped source asset; an aggregate index reserves all bonded and pending-unbond
  funds in addition to rewards. Only authenticated deposits, matured withdrawals
  and verified slashes change those reserves. Generic debits cannot consume
  bonded escrow, including a shared fee/stake account. Restore validates both
  ledger reconciliation and combined backing; deletion and account migration
  preserve the retained source. Configuration and alias drift cannot redirect a
  withdrawal, and incompatible new deposits are rejected. Funded balances below
  the current claim threshold remain accrued, and exit preserves captured
  entitlements. Changing fee policy cannot change an existing entitlement's source.
- Beacon startup authenticates the exact installed session and checks the local
  provider's non-signing capability for its actual seat. A present provider
  handle alone does not establish usable custody.
- The disposable scenarios in
  `integration_tests/tests/sumeragi_npos_committee_transition.rs` define pools of
  five, eight and eleven candidates, missing incumbent keys, missing target
  custody, and real-XOR 4→7→4 transitions. They use the native finality journal
  and restart all peers while provisioning pending credentials. Setup without
  an actual network fails the qualification. The scenarios explicitly exclude
  an enacted retail validation-fee policy. The complete rotation includes full
  withdrawal after retained liability expiry, with separately settled native
  fees. TODO: qualify positive automatic funded conversion and signed nominator
  claims across a monthly boundary on a real four-peer network. The connected Parliament
  helper requests and consumes a genuine sortition pulse during E+1 while current
  and pending credentials coexist; it separately verifies the fresh epoch-boundary
  scheduling pulse and rejects early activation. These scenarios require compilation
  and execution on one unchanged candidate. The connected enacted-policy scenario
  remains open; slashing uses the deterministic native component below.
- The finality-owned lane penalty component
  `native_lane_original_genesis_escrow_is_debited_only_by_delayed_authenticated_admission`
  now covers signed full-unbond scheduling, a delayed physical XOR transfer to a
  distinct slash sink, reduced pending liability, and repeated original-chain
  replay. Its exact remaining withdrawal is rejected while the unchanged global
  and lane seats retain custody. The connected `lane/tests/replacement.rs` extension
  then certifies a replacement, releases both seat obligations, waits for height
  and time maturity, withdraws the remaining XOR, and checks a freshly signed replay
  with exact fees, balances and reserves. The extension is implemented but awaits
  compilation and runtime qualification; it is a deterministic native component,
  not a real-peer slashing result.
  Torii exposes evidence reads, not an external evidence-submission endpoint;
  the Initial executor admits manual slashing only in genesis. An offline proof
  cannot currently drive the disposable network's finality-owned penalty through
  an existing external submission command. Keep mandatory-slash simulator and
  component evidence separate from network qualification; do not add a manual
  authority or node fault switch to make that gate pass.
- Candidate keys require BLS peer consent and the exact BLS proof of possession
  bound into the validator generation. Every prepared seat additionally proves
  custody of its exact beacon share under the finalized DKG transcript and complete transition context. A
  lifecycle certificate finalizes a pending beacon; only certified committee
  activation retires the old key and activates the new one. Genesis bootstrap
  requires the exact current genesis authority.
- The seven-seat Core fixture exercises fresh dealer commitments, distinct
  private shares, transcript validation, native custody import and real
  threshold signatures with the signed-genesis network XOR. It constructs
  dealer secrets centrally for deterministic testing only. The first-release
  DKG data model and reducer instead carry signed attempt-bound recipient keys,
  dealer commitments, encrypted dealer-to-recipient edges and signed recipient
  acceptances; no public complaint or private-share reveal record remains.
  The daemon's per-seat command path still needs independent broker custody,
  genesis orchestration, restart and network qualification. The Core fixture
  does not establish a 4→7→4 network transition.
- Current and predecessor restoration require the exact authenticated preparation
  and terminal boundary history, including missing-row detection and exact beacon
  activation state. A snapshot without the required retained finality is rejected;
  authenticated snapshot-bootstrap history delivery remains to be qualified.

## Execution inputs on the Sumeragi node

Staking, committee preparation and threshold-key lifecycle instructions execute
inside blocks, so they read only committed state that every node shares, never a
node's own certificates (certificates are per node, `specs/sumeragi.md` §12.7):

- The scheduling epochs are the committed NPoS epochs `[e·L + 1, (e + 1)·L]`,
  with `L` the signed, immutable `SumeragiNposParameters.epoch_length_blocks`.
  Frozen preparations in World fix their own target intervals after the current
  epoch and must follow it (selection at the preceding epoch's end, contiguous
  start). Global-lane tenure uses these intervals; other lanes use the epochs
  alone.
- The initial validator generation is the ordered BLS committee and original
  proofs of possession in the signed genesis, bound to the network. The native
  schedule carries the complete validator-generation and epoch-authorization
  graph; certified boundary application advances that graph atomically. The
  shared proof reader and BLS-authenticated transition integration remain under
  qualification.
- A threshold-key lifecycle certificate at height `h` is signed by the committee
  World's lag-2 consensus schedule holds for `h` (committed in `R_{h−2}`), in the
  core's canonical order; Torii admission checks the next height against the
  same entry.

## Outstanding protocol and runtime outcomes

| Outcome | Exact dependency and completion criterion | Owners |
| --- | --- | --- |
| Dynamic validator election | The native E+2 selector/producer, retained epoch graph, BLS-authenticated control paths and immediate next-epoch application barrier are integrated. TODO: qualify complete preparation and certified retention with the exact authenticated BLS committee on actual networks. Registration alone must never add voting authority. | Core/data model, Sumeragi and deployment |
| Prepared beacon transition | The signed encrypted all-edge DKG model and reducer bind the frozen exact roster and fail closed before finalization if an edge or acceptance is absent. The deterministic Core fixture still constructs secrets centrally; daemon per-seat custody, authenticated exchange, genesis orchestration, current/pending session restart and atomic activation need qualification. Parliament creates no pulse demand: its sortition waits governance-locally for the consensus-native epoch-end pulse ([ballot design](parliament_private_ballot_design.md) section 9). Do not bypass finalized pulse or certificate checks. | Beacon, Parliament, Sumeragi and daemon |
| Staking under the enacted validation-fee policy | `RetailMonthlyAllowance` is the canonical policy: calendar maintenance, included retail payments and overage, with an institutional per-payment fee and separate immutable reward custody. Native assessment checks qualifying payments of the enacted fee asset. TODO: complete and qualify staking integration, distinct fee-asset accounting, bounded claims, multisig/proved overlays and signed payer bounds through original execution. Staking principal cannot satisfy a fee obligation. | Core/native execution and fees |
| Production liveness | Complete the original Validate-to-Apply owner, admitted resources, durable publication and autonomous lane runner together. TODO: qualify silent authors, saturation, final-transaction progress and retirement/restart cuts, with named deterministic regressions and mutation controls. | Core/Sumeragi, Queue, Kura and formal owners |
| Reward allocation | Funded canonical-XOR conversion preserves validator service-count gross rewards and automatically divides them using historical eligible stake cohorts, with zero commission. TODO: qualify monthly funding, multiple nominator claims and restart together on a real four-peer network. | Core finalized service, fee conversion and staking custody |
| Network qualification | TODO: one unchanged candidate proves admission, prepared 4→7→4 rotation, Parliament sortition consuming the boundary pulse after rotation, missing target signer, all-seat restart, replay rejection, rewards, slashing and final withdrawal. Run the maintained fault/DA/formal gates and complete workspace checks. | Integration, release and subsystem owners |

The current fee owners are `iroha_data_model::validation_fee`,
`iroha_core::retail_fee` and the common numeric-asset mutation path. The native
payment recorder returns without assessment when a transfer's asset differs
from the enacted policy's `ds_asset_id`. An XOR staking transfer therefore does
not by itself establish payment of a distinct fee asset. The signed monetary
plan still binds exact custody and effects; `deferred_authority` rejects opaque
contract-generated monetary staking and resolves multisig approvals against the
execution overlay. Retained multisig rows must reproduce the exact approved body
hash and physical account/hash key in execution, queue admission, migration and
restoration. Cancellation and expiry preserve unfinished local decoder reads
before recording terminal state or pruning; these connected regressions remain
under validation. Complete fee/custody conservation requires connected tests
under the current policy, not a restored retired charging mode.

Retail-policy enactment checks the activation time against the actual finalized
Parliament enactment time: at least thirty days later, at a Honiara month boundary.
Backdated notice metadata cannot shorten this interval. A fresh short-lived
disposable network can qualify genuine enactment and delayed activation, but
active-policy staking requires an authentically aged chain or the actual elapsed
interval. Do not seed an enacted registry or substitute a fabricated chain clock
for that network gate.

The canonical reward plan requires one positive `fee_claim` with exact lifecycle,
beneficiary revision, global XOR source and destination, amount and next claim
sequence. Network scope and expiry are authenticated. Absent or null claims and
stale signed state reject before payment. One bounded claim consumes only its
funded entitlement; additive custody preserves all remaining fee and stake
obligations. Current execution, restoration, client and fixture qualification
must establish this behavior together.

The beacon producer also retains an explicit allocation TODO: its lower
transcript/reducer must use original-pool admission for nested allocations before
production resource qualification. Component threshold-signature checks do not
close this ownership requirement.

### Native epoch boundary contract

The selected integration changes the native lag-2 membership contract directly.
If B ends epoch E, the B+1 configuration is explicitly unavailable until the
incumbent exact quorum certifies B and its original execution is applied. The core
must not propose, vote, time out, or establish signing authority under B+1 before
that application. Ordinary chain-parameter scheduling retains its lag-2 rule.
Restart and catch-up must preserve the same pending boundary and reject a
conflicting replacement. No provisional B−1 election authorizes a transition.

B captures its election and activation inputs before transactions, including the
authenticated beacon pulse, exact custody and the complete frozen target. That
checked view guards stake obligations throughout the same original execution;
transactions in B cannot remove selected custody or rescue a missed preparation
cutoff. Applying B publishes the E+1 authorization, complete authority and beacon
disposition together, and first inserts the immutable E+2 preparation. Missing
target readiness produces certified retention and cancellation; a later attempt
uses a new transition and transcript. Missing the current quorum remains a halt.

Each preparation must freeze the exact network-pinned XOR definition, global
balance scope, scale-nine precision, positive self-bond and nomination floors,
maximum committee size and target epoch length. Later configuration changes
govern subsequent selections. Current custody and complete credentials still
must satisfy the frozen attempt at activation. Mandatory finality-authorized
slashing remains executable; voluntary withdrawals and rebinding cannot release
the boundary's retained obligations. The native selector ranks already eligible
candidates uniformly using network, selection epoch, target epoch, authenticated
seed and canonical peer identity, then freezes the largest allowed exact `3f+1`
committee. Stake gates eligibility and does not multiply votes. Target BLS
credentials and beacon shares are prepared during E+1.

The unimplemented concentration, seat-band and entity-correlation settings have
been removed from canonical parameters, profiles and genesis templates. Their
old fields are rejected, including zero-valued fields. Frozen policy/member
records and their native producer consumers are integrated. Current component
and network qualification is required; this contract does not attest completed rotation.

The canonical epoch identity must bind the complete generation, authorization,
ordered roster and original PoPs, network, mode and fresh leader seed. Every
signature must consume its epoch/context binding, and topology must consume the
fresh seed even when membership is retained. Idle chains produce no blocks.
Any protocol-authorized boundary block must retain its authenticated witness
and certified BLS committee decision. Replay, restart, formal and network
qualification remains open.

### Distributed beacon ceremony cutover

The first-release source candidate uses an all-edge Das–Ren ceremony over the
frozen target, with no public complaint or private-share reveal layout.
Each target seat publishes a fresh hybrid encryption public key signed by its
actual BLS consensus key. The signed key record binds the network, transition
ID, authority generation, complete DKG session, roster hash and recipient
index; the private key stays in that seat's broker custody. One dealer process
per seat generates only its own polynomial, signs its public commitment and
encrypts one verified contribution to each recipient. The private envelope is
signed by that dealer and uses canonical associated data consisting of a domain
tag, complete encoded DKG session, transition ID, authority generation, dealer
and recipient indexes, dealer commitment hash, recipient key digest and the
authenticated sharing height. The recipient checks that signature, exact
context and share equation, then signs one acceptance for the exact edge.

Use `iroha_crypto::hybrid::{HybridKeyPair, encapsulate, decapsulate}` for the
existing X25519/ML-KEM-768 key exchange and
`iroha_crypto::encryption::SymmetricEncryptor<ChaCha20Poly1305>` for nonce-bearing
AEAD over the associated data. Hybrid key and ciphertext owners now retain fixed
ML-KEM storage; private-share encryption returns the exact 124-byte envelope.
Contextual BLS signing uses one fixed-storage kernel for ordinary and prepaid
callers. Prepaid signatures retain their original output buffer and allocation
charge. Local preparation now constructs every phase output and its maximum
canonical frame before randomness or the durable attempt claim. Reducer rows,
snapshots and finalization retain their actual nested backing under the original
allocation pool; CLI and disposable coordinators consume that final owner.
The credential producer prepares exact secret output backing from that pool
before share extraction and encodes borrowed shares without a second output
allocation. Final export retains the private source, original descriptors and
write offsets on failure; retry verifies the same files and byte prefixes.
The canonical decoder now supports prepared destinations through the same generated
field walk as ordinary decoding. Separate commitment, delivery and final-session
banks retain their nested backing in the original pool, with exact source bindings
and unchanged canonicality checks. Genesis moves its finalized graph into a
prepared verifier instead of overlapping a cloned graph with the delivered snapshot.
The daemon's single `SeatDkgAttempt` retains the claim, input descriptors, partial
frames, decoded banks, signing phase and publication offsets across refusal.
It advances beyond signing before attempting publication and preserves the original
deadline. Native finality retains prepaid ranges into its original funded frame
through refused advancement. Ordinary and prepared journal decoding share the
same generated canonical field walk and source bounds; the native cursor uses
the same complete finality verifier. Journal indexes retain actual backing from
the original pool. TODO: fund the nested decoded SignedBlock and result graphs
through their complete physical lifetime.
These changes await fresh compilation, Core and daemon runtime qualification.
The crypto layer prepares encrypted private checkpoint banks before secret
production. Core derives checkpoint authority only from the exact signed genesis
body or verified committee selection and the original native finality cursor.
The canonical source record distinguishes signed genesis authorization from an
executed native tip; genesis provisioning never supplies a fictitious result.
The authenticated attempt cutoff extends beyond the acceptance window and cannot
be renewed by restoration.

The daemon publishes an immutable producer intent before secret production,
then the original private checkpoint, signed public output and complete phase
head. All original file and directory barriers complete before phase advancement
or secret retirement. The AEAD binds the intent, original claim and inherited
input identities. Restoration verifies the same source names and inodes before
and after syncing their held descriptors; a visible complete head alone is not
durable evidence. An original same-boot monotonic expiry cannot become a new
interval on restart.

Bounded generation, delivery and acceptance restoration reconstruct the original
prepared owners without RNG, re-signing, FIFO reopening or deadline renewal.
Each completed later intent binds the exact preserved input/native proof hashes
and inherited stream generations; restore replays genuine native ancestry and
checks every original signed capsule, acknowledgment and private equation before
installing that phase. Independent canonical output decoder banks preserve their
source identity through refusal. All exact raw file extents are admitted on the
original pool before the first private restore, and original file/directory
barriers complete before polynomial retirement or claim adoption.

A completed final aggregate now has a distinct checked native-finality context,
immutable extraction intent and encrypted aggregate/head files. Its original
96-byte scalar leaf and separate ciphertext/work/control backing remain charged
through a move-only export owner. The actual aggregation and nonce execute once;
individual contributions and acknowledgments remain until every original file
and directory barrier completes. The obsolete phase-four intent format and its
unused bank are removed directly.

Completed aggregate reload prepares only the final-session public decoder and
small aggregate bank. Nine exact original raw source extents precede private
restore. The original accepted head, intent, input marker and output bindings
remain checked; genuine H3→H4 native proofs authenticate their contexts. All same
held descriptors, named inodes and the parent directory are checked on both sides
of their actual sync barriers before claim or export adoption. The inherited
stream advances to its original empty generation and the same-boot expiry only
tightens. Provider handle/revision and the original sealed public owner bind the
four exact outputs; reload accepts only no outputs or a complete verified set,
without rewriting published bytes, RNG, signing or reconstructing erased private
phase graphs. The aggregate/export source controls await compilation and runtime.

An input marker or unfinished later producer cannot reopen a preceding phase.
TODO: restore partial input/producers and interrupted partial final outputs;
fund nested decoded native proof graphs; authenticate a rollback-resistant phase
head independently; and complete genuine 31-seat preparation and restore under
unchanged physical caps. The later restore source controls await compilation and runtime.
All-seat process restart and real-network preparation remain unqualified; source
integration and component controls do not establish those outcomes.
The public reducer requires all `n` distinct
commitments and all `n²` distinct signed acceptances before the finalized
acceptance cutoff. It derives the transcript from those exact commitments; a
recipient aggregates only its locally decrypted contributions. A missing,
invalid, replayed or late edge cannot finalize the target. The current exact
quorum instead certifies retention and cancellation, and a later election uses
a new attempt and transcript. This keeps current-chain progress but lets one
uncooperative target block that transition's activation.

Each dealer and recipient needs a durable, owner-private, one-shot attempt
journal keyed by network and transition ID. It must retain the original public
commitment, encrypted outbound envelopes, accepted edges and local aggregate
across restart, reject conflicting replays and never regenerate a polynomial
for the same attempt. The dealer polynomial can be erased after every original
outbound envelope is durably stored. The source cutover spans DKG records in
`iroha_data_model::consensus`, public reduction and share verification in
`iroha_core::beacon`, and per-seat broker custody and authenticated exchange in
`irohad`. The public complaint/reveal fields and the all-secrets production
coordinator are retired. CLI and disposable-network orchestration remain to be
qualified. Exact incumbent-quorum
transcript finalization, all-seat readiness and boundary activation still need
their separate authenticated evidence; an all-edge receipt is not activation.

The global committee remains exactly `3f + 1`, with `1 <= f <= 10` and exactly
`q = n - f` equal validator votes. Observers and admitted candidates cannot pad
quorum. Signed RS16 DA, canonical replay, source-bound evidence and the offline
monetary-authority policy remain mandatory.

## Validation

Global committee geometry and exact certificate cardinality are implemented.
Qualification must cover current Core, daemon, CLI, Torii and network consumers,
authenticated XOR identity, stake/fee/reward conservation, epoch transitions,
restart, resource admission and adversarial custody. Captured instruction records
retain strict identity checks and canonical roundtrips; no fallback decoder is
admitted. Run the maintained Sumeragi simulator and both protocol and Core mutation
gates; faults belong in the simulator, not node configuration. Real-peer
coverage includes `sumeragi.rs`, `sumeragi_lanes.rs` and the committee-transition
target. Skipped network tests and historical component results do not qualify
the current candidate.
