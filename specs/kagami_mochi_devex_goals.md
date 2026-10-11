# Kagami and Mochi developer experience

Status: implementation in progress. This is the first-release acceptance contract;
the commands and guarantees below are targets until their current-candidate
end-to-end checks pass. No backward-compatible command aliases, old wire layouts,
or parallel orchestration implementations are required.

## User contract

```sh
kagami localnet up
kagami dataspace up acme --network taira
kagami contract deploy hello.ko
```

These commands require no supplied TOML, prompts, source checkout, Cargo, Python,
shell scripts, or container runtime. Configuration and credentials are generated
in private managed storage outside projects. Kagami is the CLI frontend; Mochi
is the desktop frontend to the same services.

The default localnet has four validators and a funded deployment-capable account.
Fresh managed global genesis retains three distinct providers on peers 0–2, each with its own
credentials, native attestation history and retained CA/leaf identity. One network inventory owns
the reserve operations signer, reputation recorder, pricing and initial admission policy. Private
roots use the minimal `Standard` profile. Each provider has an original HTTPS listener; the shared
build-registry factory selects that exact provider and origin through fresh authenticated native
discovery. Both control and CAR clients validate its original CA, hostname and leaf, with the
original loopback address and port. Public remote discovery retains its public-address rules.
Prepared archive clients retain their exclusive build-registry discovery journal for their full
lifetime. Startup and Ready maintenance use an independent service-observation journal and lock;
both authenticate the original profile and fresh native finality. A build holding its archive
client therefore does not block the worker's bounded freshness observations.
Generation leaves token services disabled. The startup worker composes one reserve activation,
three independent funded provider/custody/gateway histories and one reputation policy through
their native owners. It promotes each signed compliance catalog and restarts all four owned peers
with the aggregate configuration. Every original transaction remains in the all-peer barrier;
a maximum-height observation floor never replaces those receipts. For each receipt, inactive
decode contexts join the four independent validator-local Applied reads before proceeding to
the next receipt. Every peer must confirm its exact hash and carrier height; all workers close
on failure, cancellation or expiry. Active caller decode budgets retain serial reads.
Reserve-policy finality is the common prerequisite. Each provider then retains its own strict custody, registration, funded
credit/capacity, ingest and gateway dependencies; there is no prerequisite from another provider's
gateway. Reputation follows all three gateways. Equal-block originals from different providers remain
distinct required transactions. Fresh histories may use three scoped, joined workers under the same
finite authorization and deadline, while resumed work and active caller decode budgets use serial
dispatch. Partial recovery validates each provider's frontier independently and refuses its later
material without a completed prerequisite. Funding absence checks reuse the held original profile
while retaining fresh child admission, locks and both parent checks on every ordinary result.
Active decode budgets and independently owned profiles retain full profile capture.
One shared epoch retains its original replacement limit;
parallelism creates no signing authority, budget extension or readiness from partial work.
Within that initial invocation, each admitted provider worker retries its own incomplete or
nonterminal operation under the same authorization and deadline, without waiting for another
provider's full chain. Terminal bootstrap failures stop that worker; every worker is joined.
Reopening a retained startup still uses serial dispatch. Within one joined advance, a new
purpose with no retained cursor may start finality verification from an authenticated immutable
carrier certificate owned by the same original network profile. This avoids replaying genesis
for every purpose. It still obtains a fresh independent quorum and current-state proofs; original
certificate custody is checked before and after observation, including error returns. Equal-height
certificates must identify the same native execution result; alternate valid quorum witnesses are
accepted. The scope ends after every worker joins and is never retained as current authority.
After an Applied hint, an operation's fresh native quorum may also supply its exact carrier.
Only an inactive decoder with no retained replay uses this handoff, and only when the observed
block is the immediate Global successor of the original certified checkpoint at height two or
above. The opaque native receipts must agree on network, chain, parent core hash, execution result,
Iroha parent and authenticated schedule. The actual replay file is still read first. Its absence
permits retaining the already observed checkpoint; original signed-wire and successful-output
membership are verified before carrier publication. This consumes the full native proof already
obtained through the fresh quorum and does not require a redundant second proof response. Missing
fresh observations still refuse. Existing replay, genesis parents, different heights, larger gaps,
active caller budgets and renewal keep independent bounded replay and its source failures.
Original profile custody and the original deadline close the handoff on ordinary failures too.
Fresh catalog activation also joins the three independent provider head/proof reads and catalog
promotions. Each phase checks that all catalog purposes are absent; existing purposes and active
Norito budgets keep ordered serial execution. Full live renderer validation remains exclusive
because it reopens shared bootstrap and custody owners; its deadline-aware guard closes before
catalog HTTP calls. Every worker joins before aggregate publication or failure, and renewal
retains serial execution. This combined path still needs native qualification. Reopen preserves each original finite interval, endpoint and profile;
it never upgrades a retained generation in place.
An attached private dataspace has four local validators with owner-only application
data, works behind NAT, and publishes only authenticated commitments and certificates
to its parent. Restricted FullReplica lanes do not satisfy that privacy contract.
Contract deployment accepts `.ko`, `.to`, and existing Musubi packages. Without a
selected environment it starts the default localnet in the same invocation.

## Implementation goals

| ID | Owner | Required outcome | Completion evidence |
| --- | --- | --- | --- |
| DX1 | Native filesystem / SDK / daemon | One private filesystem boundary on Unix and native Windows; handle-bound reads, exclusive custody, durable journals and publication. | Native macOS, Linux and Windows tests for permissions, links/reparse points, path replacement, crashes and concurrent owners. |
| DX2 | `iroha_deploy` / Kagami / Mochi | Shared persistent local runtime, generated identity/configuration, authenticated local IPC, managed workspace contexts, `up/status/logs/down/reset`. | Four real peers start without inputs; repeated up and down/up retain identity, funds and contract state; only reset creates a new ledger. |
| DX3 | Musubi / contract deployment | Shared source/artifact/package deployment API and thin Kagami/Mochi callers with automatic aliases and exact journal recovery. | All three inputs deploy and execute; concurrent and ambiguous attempts preserve original signed transactions and charges. |
| DX4 | Core / Torii / data model | Independent private dataspace State, execution, storage and artifact scope using native Sumeragi and IVM. | Four-node private execution; cross-dataspace authorization tests; no private canary data in parent storage, routes, events, logs or transport. |
| DX5 | Deployment / Taira / finality | Governed self-service committee admission, testnet funding, signed network metadata/checkpoint bootstrap, outbound parent anchoring. | Fresh-wallet registration and attachment behind blocked inbound ports; exact instance, quorum, epoch, funding and replay verification. |
| DX6 | Mochi / release | Complete matching native runtime bundles and desktop actions over shared APIs. | Clean-install flows on macOS/Linux ARM64 and x86-64 and Windows x86-64, with no build tools on PATH. |
| DX7 | CI / runtime | Startup and deployment latency with truthful readiness. | Twenty-run p95: local startup <=30 s, remote attachment <=60 s, small contract deploy on a ready environment <=30 s. |

DX7 uses preinstalled release binaries, 8 CPU cores, 32 GiB RAM and SSD storage;
remote measurements include metadata/proof retrieval, a healthy funded parent
network and RTT <=100 ms. Timeouts preserve resumable state and never count as
readiness. There are no empty blocks or consensus bypasses to meet these targets.
Generated validators begin outbound dialing without a fixed initial wait and use
the normal authenticated connection and retry behavior.
Startup may submit its one signed readiness transaction after all four validators
have applied genesis, while their authenticated peer links finish forming. Ready
requires that exact transaction to be state-resolved Applied on each peer through
explicit local status reads, followed by the complete four-validator mesh, within
the original deadline. A global fanout response does not prove an individual peer's
application. Failed startup retains its specific stage even when cleanup stops all
validators; an already Applied readiness transaction does not make that attempt Ready.

The `xtask mochi-latency` diagnostic collector records twenty fresh-state startup
attempts and separate ready `.ko`, distinct `.to` and local Musubi package cases;
its exact-twenty aggregator retains failed attempts and refuses to compute a
successful p95 from incomplete samples. `xtask mochi-latency-remote` invokes the
exact disposable eight-validator test twenty times, retaining separate attachment
and ready private-input durations plus whole-run exit/cleanup. These collectors are
implemented in source; no twenty-run collector campaign has yet been executed for
this candidate. Current signed-release campaigns on the reference host, production
remote attachment samples and RTT qualification remain outstanding. The native CI
workflow likewise does not claim reference-host latency qualification. See
[the measurement boundary](mochi_bundle.md#diagnostic-latency-samples).

## Ownership and protocol decisions

- `iroha_deploy` owns environment/context state, genesis/config rendering, local
  supervision and dataspace provisioning. Move the useful Kagami and Mochi
  implementations into this owner; it must not depend on either frontend.
- Musubi exposes the canonical typed compiler/deployment adapter. It accepts an
  immutable SDK configuration and alias scope, and calls `iroha_contract_deploy`.
  It does not depend on the environment engine.
- The supervisor owns live process handles and one environment lock. Frontends
  attach using owner-authenticated Unix sockets or Windows named pipes. They do
  not signal processes identified only by stored numeric PIDs.
  Terminal cleanup cancels new work and joins activation, maintenance and attachment
  tasks before publishing completion or releasing that lock. Authenticated `down`
  uses one observation deadline across IPC and ownership release; a timeout never
  proves cleanup. Cancellation preserves signed operations and ambiguous submission
  markers for exact read-only recovery without authorizing another paid dispatch.
- Managed generations and exact operation journals survive `down`; `reset` is
  explicit and local-only. Project context selection lives outside the project.
- Native dataspace instances have independent World/State, queues, Kura, body and
  artifact stores, events, archives and safety records. IVM ABI V1, canonical
  Norito, exact quorums and signed RS16 availability remain mandatory.
- All private peer and Torii traffic stays on loopback. Parent traffic contains
  public registration and certified root proofs only. No private relay fallback
  or global replay of private bodies is allowed.
- Artifact instructions, storage, routing, queries and receipts carry explicit
  dataspace scope. There is no hash-only global fallback for private artifacts.
- Fresh parent verification may use an independently release-signed native
  checkpoint. Metadata must bind genesis/network identity and enforce freshness
  and rollback protection; a queried peer cannot select its own trust root.
- Self-service admission grants only the governed dataspace capabilities. Exact
  rent, fees and original validator staking custody are required. Automatic
  budgets use dedicated managed test wallets and verified faucet allowances.
- Private finality and parent anchoring are distinct facts. Receipts report both;
  an anchoring timeout cannot undo already finalized private execution.
- Distributed private hosting, general cross-dataspace contract calls/AMX,
  Minamoto mutation and hardware-backed offline monetary guarantees are outside
  this developer workflow.

The publication clock and replay journal use the shared native filesystem owner on Unix and
Windows, with explicit initialization, existing-only reopen, original lock/file snapshots and
bounded recovery of unpublished atomic staging. The signed transaction writer is shared by model
and wallet callers. Purpose-specific wallet APIs can retain the exact unsigned request before a
managed attempt is committed; quotation and signing resume that original request. Managed
bootstrap retains clock-independent policy and fee intent. Only a newly started worker can issue
a finite, cancellable authorization for unfinished initial work. Expired unsigned requests may
advance through a bounded retained attempt chain; quoted payloads, signatures and paid carriers
are never replaced. Complete local recovery creates no authorization, and missing parent custody
with retained child work refuses without recreating history. Combined native validation remains open.

Seed storage uses the same portable filesystem owner. Provisioning explicitly initializes the
original owner marker; ordinary startup refuses
missing ownership. Canonical CAR records publish without replacement as immutable private files;
interrupted pending writes remain visible tombstones. The daemon storage modules and their
existing finality/custody fixtures use the portable owner. Native whole-service and Windows
execution are still qualification gates.

Authenticated provider-inventory reads retain the daemon's original live inventory and recheck
native archive, order, completion authority and admission before and after reading. The publisher
uses its own ordinary SDK identity to acquire complete original signed attestations from at least
three independently selected provider origins before constructing registration payloads. Its
immutable checkpoint binds every original attestation and the complete canonical storage request;
recovery never substitutes compact references or refetches missing anchored originals. The native
paid pin coordinator retains original requests, fee authorization, signatures and ordinary Queue
submission. The concrete storage backend stages exact finalized seed bytes through the existing
publisher-source owner and reports completion only from actual native provider workers. Generated
TLS selection binds the original network, provider, certificate and dedicated listener port.
Stock startup now selects the complete configured publication installation, opens its original
journal/seed/clock/pin custody before binding the private listener, and uses fresh native discovery
for each of the original three providers. The generated runtime installs this configuration only
on the seed peer after aggregate activation. These source paths require combined native validation.

## Qualification and documentation

Installed-release fixtures exercise both the local four-validator workflow and a
disposable four-parent/four-private attachment. They check all three contract inputs,
exact repeat receipts, localnet restart recovery, funded parent provisioning, paid SNS
ownership, private execution and independently authenticated parent anchoring.
The combined flows require a fresh run against the current implementation; component
tests do not establish their completion. The attachment fixture also checks
that its private canary, complete artifact bytes and listener token are absent
from captured parent requests and retained parent files. This bounded regression
does not establish universal secrecy, official Taira readiness, native desktop
interaction, signed multi-platform release qualification or the DX7 latency targets.

Signed genesis context now selects a global or private dataspace root. A private root binds
the exact parent network and full 64-bit dataspace identifier; its own genesis and chain label
derive a native Dataspace instance with root index zero. There is no node-local scope toggle
or missing-field fallback. Routing, execution-time instruction authorization, artifact scope,
parent registration and whole-network privacy still require qualification together before
the managed private-dataspace command can be declared ready.

Immutable artifacts use `ContractArtifactId { dataspace_id, code_hash }` throughout
storage, native instructions, queries and access hints. Equal bytecode hashes in
different dataspaces do not share uploads, manifests or read authority. REST artifact
resources include both identifiers and return their exact network binding; there is
no hash-only lookup fallback. Private roots require an owner-held listener API token
on every Torii route, including otherwise public gateway resources. Generated private
node and client contexts retain that credential automatically, while account signatures
and revocable ledger permissions still authorize individual reads. These source
boundaries remain subject to the combined private-network qualification above.

Private genesis now commits `PrivateRootFeePolicy` under `private_root_fees_v1`:
an exact dataspace-restricted currency and decimal transaction rates with positive
base and gas charges. Private execution derives its fee schedule from that committed
policy and burns the payer's exact private balance. Node-local currency/rate settings
cannot replace it; the global XOR economy remains separate. Private sponsors require
a separately implemented dataspace-local vault owner and are currently rejected.
The generated configuration mirrors the signed policy for configuration identity;
runtime startup and paid private execution still require combined qualification.

The parent now retains a canonical `PrivateDataspaceRegistry` and native
`RegisterPrivateDataspace` / `AnchorPrivateDataspace` transitions. Registration
requires a committed global root, an active SNS dataspace lease, its exact owner
and ownership generation, the parent's genesis identity, and the chain-governed
`private_dataspace_admission_v1` quota policy. Missing policy disables new
registrations. An external child cannot claim an existing physical parent
dataspace or lane; later physical catalog/lane policies cannot claim a registered
child either. Exact registration retries retain an advanced cursor. Lease expiry,
suspension or ownership replacement stops further anchoring without resetting the
child's registered genesis or committee.

Compact anchors retain the exact permissioned four-validator child context and
accept only contiguous genuine three-vote CommitQCs. Child genesis bodies,
transactions and artifacts never enter these records. Parent ordinary-write
receipts bind the public record to an exact certified execution result; a client
must verify them against independently authenticated parent finality. The bounded
`/v1/private-dataspaces/{dataspace_id}/records/{height}/proof` route and SDK reader
use the original certified archive write, never current mutable state. These model
and executor boundaries still need their complete runtime, funding,
crash/restart and privacy qualification before the remote command is declared ready.

`iroha_deploy::bootstrap` now authenticates one canonical native checkpoint
against an independently installed Ed25519 release authority. Signed metadata
binds the network label, genesis identity, chain label, reset generation,
publication serial, HTTPS roots, checkpoint digest/height/block and a validity
interval no longer than one day. Private exclusive custody retains the release
watermark across localnet resets; expiry does not discard rollback protection.
Same-generation identity changes, clock rollback, regressed releases and
same-height equivocation fail closed. Runtime finality progress remains a
separate retained checkpoint in `ParentFinalityStore`. Reopening preserves newer
verified progress; reset generations require separate contexts. Verification
updates publish durably before exposing a readiness report. Uncertain publication
requires reopening custody before another update, so retries cannot overwrite
newer disk state with an older in-memory prefix.
An observation that exhausts its bounded catch-up page retains its verified prefix
and continues to report `CatchingUp`; it cannot claim fresh quorum readiness. Other
observation failures retain the preceding checkpoint. The release watermark records
an explicit uninitialized state so a failed first download remains retryable without
treating a missing custody record as a fresh trust decision.
Initial release, finality, provisioning and attachment directories publish their complete
records and lock files atomically. Native wallet preparation first publishes its exact
unsigned request with the lock, then retains the quoted payload before signing and the
signed operation before dispatch. A crash can expose one of these complete durable
stages, but cannot expose a lock-only operation at its final path. Read-only recovery
never finishes preparation; explicit preparation preserves the original request, payload,
nonce, quote and lifetime. Retiring a clean request-only stage grants no replacement
authorization. The generated parent's live capability authorizes any permitted unsigned successor;
status, recovery, maintenance and daemon restart cannot create that capability. Cancellation is
checked at the wallet's preparation, signing and submission boundaries, including after HTTP
preflight. Native interruption and whole-worker qualification remain required.
Managed environments likewise publish keys, signed genesis, final-path configurations
and their sole generation manifest together. Only an unpublished stage may be discarded
under exclusive operation ownership. A published incomplete generation fails closed;
retrying cannot silently replace its identity.
The original foreground attachment deadline is published with the exact generation
binding before a supervisor can start parent work. Automatic startup must not select
the shorter background relay budget while that foreground activation is being written.
Expired or rejected parent transactions remain bound to their original journals and
are reported as terminal failures; retry cannot renew their signed lifetime.

The shared deployment report captures the original execution network and root scope
before dispatch. It preserves the canonical receipt and journal, and binds any separate
historical parent observation to the original child and parent networks. Changed local
selection or an unavailable parent observation cannot overturn that original Applied
result. Transaction-status scope on a private root does not imply public-parent inclusion.

The release requires an original committed global root and also binds the native
World schema, account-address profile, BLS member endpoint hints and
an optional exact faucet authority/currency/allowance with finite fee and namespace
rent caps. Hints never grant committee membership. Native public checkpoint reads
use the independently installed HTTPS location, one absolute deadline, a finite
response bound and no wallet credentials or redirects. The installation artifact
has exact named profiles; a missing Taira profile cannot select a response-supplied
key. Automatic parent SDK contexts use only the signed endpoint mapping and reject
child listener credentials. Optional build-registry roots explicitly select parent
discovery; a cold fetch authenticates the current provider policy and native token
signer against a newly observed parent decision. A private child context cannot
select its own registry or forward its listener credentials.

The composed cold-package workflow remains unqualified. Initial funding, governed token
custody, signed compliance catalog installation and runtime activation are wired into the
startup worker. Bounded advert/catalog maintenance rechecks current native discovery before
replacing its finite readiness observation. Restart reconstructs each provider's native-selected
enrollment and exact independent ancestry. Retained aggregate references can require original
component material but cannot select native state or replace missing committed bodies. Automatic
custody renewal withdraws Ready before a finite bounded turn, then reuses the original paid
readiness receipt across an owned restart. All three providers must remain current; unchanged
providers keep their original monotonic enrollment timers across another provider's renewal.
Startup continuation and aggregate construction select immutable provider plans through the
retained renderer, with fresh whole-profile and operation-lock checks at each selection.
Current enrollment, discovery, live gateway validation and observation clocks remain independent.
Active decode owners and independently owned profiles keep standalone capture. Ordinary refresh
also keeps its standalone capture after releasing its gateway owner.
Each runtime selection owns one bounded checkpoint-import scope across its three temporary custody
readers. It shares pure epoch validation, preserves each fresh source and wallet check, and closes
before the original-profile exit on success or error. No import scope survives in the selection.
Checkpoint export and canonical encoding bounds checks each share exact immutable epoch work
within that one producer call. Export still verifies the fresh witness, certificate and retained
decisions; encoding still checks every bound. The workspace ends before return or serialization,
and active decode owners retain their original independent validation and allocation charges.
Current attestation validation also shares pure epoch work across its ordered genesis and tip
proof checks within one call. Both proofs, certificates and runtime bindings remain mandatory;
active decode owners retain both independent decodes and their original charges and refusals.
Catalog startup retains each native-selected predecessor component before renewal and reconciles
an already-applied original renewal before strict current-use rendering. Initial startup and
purpose-closed renewal authorization share one finite epoch/claim owner. A later owned turn may
retire an expired, canonically proven unsigned wallet request while preserving its still-valid
attester body and original fees. If that body has expired, the sole custody body history can
retain a successor before attester signing, using fresh native predecessor evidence and live
purpose-closed authorization. The history permits at most 64 bodies and 64 aggregate dispatch
reservations. Paid payloads and signed envelopes remain immutable and retain exact recovery.
For inactive decode contexts, the read-only renewal parser with at least three original bodies
retains one bounded epoch source through complete entry and exit checks. Each selected epoch
and optional claim is freshly read before use; unselected changes may refuse at exit after
later wallet inspections. Changes restored entirely between observations need not be observed.
Within the same inactive read, signed Original comparisons borrow the exact owner’s freshly
authenticated provider plan. A full original-profile check closes every ordinary result, including
early errors; a persistent profile change supersedes a parse error. A change restored entirely
between entry and exit may be unobserved. The borrow ends before wallet callbacks, and each
callback keeps its own checks. No source or authorization verdict escapes the parser. Active
budgets preserve the original physical validation recipe; signing, retirement and publication
retain independent complete checks. The same inactive parse reuses a signed Original’s canonical
length and digest from its freshly decoded record snapshot; later history verification uses
that immutable Original's already established digest. Before that iteration's wallet callbacks,
scope and epoch-reference construction reuse the exact selection and reservation hashes already
produced for its successor. Each use rechecks active admission; absent successors and active
budgets retain the original hash computations. All native rereads, source exits and wallet
callbacks remain mandatory. The original deep-history latency gate remains outstanding.
Within an inactive native tree read, each local operation census groups its adjacent inventory,
Original hash and metadata reads into one scope, and its reverse checks into a second scope.
Every mutable record read, decoder and full graph check remains independent of wallet or write operations.
Both scopes close native ownership on ordinary errors; a directory change restored entirely
inside a scope may be unobserved. Active decode budgets and reads without a tree retain their
original scope sequence.
For the exact immutable snapshot layout, the root inventory and its adjacent Original and
anchor reads share one native scope. The external selection reference remains independently
checked, and the enclosing tree still closes on every ordinary result. Active budgets and
custom layouts keep their independent root checks; root changes restored entirely inside
the combined scope may be unobserved.
Within the complete read-only graph traversal, a separate borrowed capability covers only an
exact body's immutable Original already checked by the enclosing snapshot entry and exit.
Persistent source failure at exit supersedes any ordinary inner result; a change restored
entirely between observations may be unseen. Parser-local and wallet callback checks retain
their fresh Original reads, as do active budgets, unmatched snapshots and standalone bodies.
The same graph-only borrow shares native ancestry for scope evidence. Root inventory and body
suffix checks remain fresh, with complete root and immutable snapshot checks at both outer
boundaries. Exact native handle ownership determines prefix sharing; reopening the same path
does not qualify. All identity, semantic, predecessor and fee comparisons remain independent.
Persistent source failures still supersede ordinary inner results; a prefix change restored
between observations can be unseen. Active budgets and parser-local checks retain their
independent ancestry checks.
Completing an already-reserved successor that expired during downtime consumes that turn's one
replacement claim; attempting another body in the same turn returns `ReplacementLimit`. A later
fresh invocation may advance that unused body. Missing anchored local material refuses without
reconstruction.
Generic observation failures still use bounded retries because the existing source/SDK errors
conflate transport and proof rejection. Native qualification of this composed unsigned-body
recovery remains pending, alongside renewal and interrupted-bootstrap authorization qualification,
qualification of the implemented native paid pin coordinator and publisher acquisition of original
signed attestations, and the implemented stock publication-service and generated runtime projection.
The explicit generated publication API accepts the original client image, namespace binding and
owner-paid fee intent, exact prepared three-provider transport, and generation-bound journal/cache
paths. First use advances the original anchored wallet namespace parent; resume and recovery
retain the original request and cannot authorize another namespace transaction. Kagami
`package publish` and the Mochi Packages view call this same API and display its canonical
result, diagnostic and exit status. Resume uses the original operation without reopening source
files. Managed contract builds use the original generation build cache, separate from publication
cache; local source, bytecode and local-only packages perform no cache I/O. The implemented
frontend handoff and three-provider cold publication still require qualification, together with
DNS timeout/rebinding and revocation coverage, and the complete
HTTP/TLS, JSON, CAR and cache 64 MiB peak-RSS gate. Local-package smoke and isolated transport or allocation tests do not
establish that combined result.
Native provider ingest now carries a mandatory governed completion signer independently
of the provider owner throughout Model/Core, storage runtime and SDK consumers. Owner-only
authority CAS and provider-scoped completion permission remain native checks. The generated
profile funds the dedicated signer and the startup worker provisions its authority through
the sole wallet before activation. Qualification still requires a real distinct-key
Set-to-Complete flow, once-only recovery, current native token/chunk serving and native
Windows custody; direct storage injection or a relaxed key check cannot close it.
An explicitly empty external compliance-feed inventory is valid, but still requires the normal
signed catalog, independent acknowledgement quorum, promotion and freshness checks. Its production
feed transport refuses every unconfigured host before DNS or HTTP; it does not bypass compliance.
Its harness must exercise the native gateway owner with atomic quotas, leases and
durable callbacks through the complete daemon service graph. The SDK's bounded
provider-discovery reader authenticates current token custody against an independently selected signer
binding and certified native State, including configured-but-unenrolled controls.
That evidence supplies enrollment inputs; current signer eligibility and download
admission still require their separate checks.
The first release removes external broker gateway authority; bare gateway DTOs and
test providers cannot supply the native deployment authority.

The wallet owns a closed initial reserve-policy operation: revision one without a
predecessor, exact asset and role bindings, and original signed fee/deadline terms.
Its journal permits once-only dispatch and read-only recovery of that same request.
Caller-selected fields do not prove policy absence or governance permission.
The independent reserve-policy reader binds the selected Global decision and native
schema to the manager's direct governance permission, selected account and asset keys,
and exact policy and activation provenance. Its account-authenticated Torii route
works before service activation and shares the native snapshot and bounded transport
owners. Authenticated singleton absence does not establish namespace emptiness or
initial activation eligibility. The managed initial-policy coordinator authenticates
the original generated roles and signed genesis, retains the original policy and
authorization, and delegates signing and once-only dispatch to that wallet owner.
Native Set execution checks activation eligibility. The coordinator reports activation
only after independently verifying successful inclusion of the exact original
transaction and a fresh policy proof matching its policy, manager and activation time.
Read-only recovery never prepares or dispatches a transaction; historical inclusion
remains reportable when current evidence is unavailable. Current-candidate native
validation of managed collateral/credit/capacity provisioning and durable service
activation remains required for unattended cold-package setup.

The wallet also retains a closed provider reserve-registration request with its exact
selected policy, provider owner, underwriting terms, fee authorization and UTC deadline.
Its single native registration instruction uses the existing once-only journal; recovery
preserves the original signed wire. Native execution owns policy, operations-authority,
provider-owner and partition-absence checks. The managed registration coordinator uses the
original shared reserve-operations credential and retains the manager's finality context;
TopUp and capacity transactions use the selected provider's owner credential.
Its independent native account proof authenticates the exact provider owner, active policy
and optional partition at one certified Global cut through an account-authenticated route
available before service activation. The coordinator retains immutable selection and
authorization, delegates once-only dispatch to the wallet, and keeps historical successful
registration separate from fresh provider facts across restart, policy rotation and outages.
Read-only recovery never prepares or sends a transaction. Registration creates an unfunded
`Warning` partition. Current-candidate runtime validation, funded collateral, credit,
admission, capacity and durable configuration publication remain required before managed
service activation; neither registration nor its proof establishes usable collateral backing.

The managed top-up request retains the generated provider's selected policy, complete
partition, revision, movement id/amount and original UTC/fee authorization. It shares the
registration proof reader and the wallet's once-only journal. Preparation and first dispatch
require a fresh matching predecessor. Historical request evidence has a private constructor:
it requires the exact signed native TopUp request in an independently certified successful
carrier. Public transaction reports cannot create that evidence. Recovery preserves it across
current-read outages; an unprepared expired intent performs no reads, quotes or dispatch.
Current provider facts remain separate. Request execution grants no approval, transfers no
principal and establishes no service readiness.

The managed approval owner requires that original opaque request evidence on every call.
Its journal retains request claims for equality checks; decoding them cannot create historical
authority. It selects a fresh complete provider partition, current revision and active policy,
including legitimate policy rotation after the request. The wallet retains the exact manager
decision, rationale, UTC deadline and fee authorization and permits once-only dispatch.
Native execution resolves the Pending movement and atomically transfers provider principal
to custody. Historical approval requires the exact successful signed decision carrier joined
to the original request evidence. It remains separate from current account facts across
outages and restart; expired unprepared recovery performs no reads or signing. Native
component controls cover rotation, stale rejection, transfer, fees and recovery, but remain
unexecuted on the current candidate. The combined funded collateral, admission, capacity
and durable service activation path remains unqualified.

Provider credit updates require an explicit predecessor: `None` requires native absence,
and `Some` binds the canonical hash of the complete current record. Execution compares it
before reserve scans or mutation and retains the existing backing and slash checks. The
wallet preserves that selection, the full desired record and original fee/UTC terms through
once-only dispatch and recovery. The account proof authenticates optional credit alongside
the policy, owner and partition at the same certified Global cut; it conveys current facts
without granting service eligibility. The managed initial-credit coordinator retains the
generated roles, complete intent and original checkpoint, checks fresh absence before
preparation or first dispatch, and always submits the native absence guard. A collision
cannot become a replacement update. Recovery preserves the original successful carrier
and withholds any current cut older than it; expired unprepared intents perform no HTTP.
Native runtime validation remains open. Native capture preserves the nominal codec
identities and updates the populated guarded-instruction frames from their compiled owner.

The wallet's capacity-declaration operation retains the complete canonical manifest,
selected policy/partition/credit claims and original UTC/fee authorization. It signs one
provider-owner `RegisterCapacityDeclaration`, preserving native replacement semantics;
preflight observations do not become a capacity CAS. Recovery retains the original
envelope, and stake declarations transfer no principal. The managed capacity owner selects
the original generated plan and derives principal and nominal credit from canonical pricing
and reserve underwriting. It retains complete original inputs before the wallet operation
and keeps exact historical completion separate from fresh current facts. The startup worker
now composes automatic funding and initial service activation with explicit finite authorization
recovery; combined native validation remains open.

The same account proof also authenticates the provider's optional complete capacity
record and the required governed pricing cell at its selected Global cut. Capacity
may be absent, future or expired; these facts grant no registration or service
eligibility. Economic consumers validate the authenticated schedule before using it.
The native publisher retains all three typed credit/capacity/pricing frames and
their allocation reservations through response encoding. Combined native runtime
validation remains required.

The optional native Torii HTTPS listener shares the public router, authorization,
connection limits and shutdown with HTTP. It loads bounded private DER material and
limits TLS handshake time. Endpoint admission names this server certificate material
`Tls`; separate mutual-TLS ingress requirements retain their own policy. Generated-local
client trust, startup rendering and durable service activation are implemented; their
combined native qualification remains open.

The wallet also owns initial gateway setup as one ordered Configure, exact Operate
grant and exact Check grant, followed separately by the recorder policy's sole Set.
Both retain complete original policies, roles, UTC and fees through the same once-only
journal. Successful setup execution grants no current Serving authority; managed
coordination and native daemon qualification remain necessary.

The native gateway owner is separate from token-signing custody.
Gateway requests, quota inputs and receipts now have one canonical data-model owner;
each admission retains its original policy qualification so changed lease limits do
not reinterpret pending callbacks or exact replays. A gateway-generated serving-attempt
identity separates one HTTP worker's internal retries from a second worker replaying
the same caller nonce. Governed policy commitments bind
the network-derived gateway identity, limits, validity and independent operator and
observer controller keys. Core's bounded transition engine keeps permanent request
and token identities separate from live quota and expiry indexes. Its clocks come
from native execution, and delayed admission cannot renew the original lease.
The governed native instruction derives its execution from the exact directly signed
transaction. Genesis seeds a policy administrator; configured gateway scopes then
receive explicit operator permissions. Atomic protected World publication retains
original policies, admissions and mutation commitments through rotation and draining.
Six purpose-specific native Checks authenticate current qualification, historical admission,
current Serving, the exact pending prefix, acknowledgement and lease release. Historical
admission grants no new serving authority. Final Serving requires the original physical
attempt, acknowledged callback and unexpired original lease, plus current policy and
permissions. An opaque verifier authenticates the original signed executions and fresh Check
against one certified State cut. It revalidates before a short publication fence enclosing
the final synchronous admission handoff; subsequent HTTP transport is outside that fence.

Each native admission atomically retains a source-owned reputation delivery intent or an
explicit exclusion. Counted intents bind the original admission, source-time recorder policy
and complete unsigned append payload. Fresh certified Checks authorize the daemon to sign that
exact payload with its independent recorder credential; local files, queue acceptance and
process counters grant no delivery authority. Only committed delivery, expiry or an explicit
current-policy-manager cancellation closes a counted callback. Serving an accepted request
requires delivered reputation and acknowledgement. The former generic local stream-token
producer is removed; the separate PoR producer does not authorize native token delivery.

The daemon uses independent configured operator, observer and recorder software credentials
and rejects injected gateway providers. Startup performs live qualification; per-operation local identity
pins cannot replace each purpose-specific current proof. One absolute operation deadline,
default 30 seconds and configurable within 1..=60,000 milliseconds, starts before the worker
queue and covers admission, callback reconciliation, acknowledgement and final Serving.
The bounded native expiry action never renews leases. Permanent acknowledgement and terminal
provenance distinguishes exact replay without local rollback authority. Disabling admission
in governed policy still permits authenticated callback and lease draining.

Token-signing receipt custody uses one journal over `iroha_fs` on Unix and Windows.
Exact ancestor and lock identities remain retained through the last receipt reader;
a bounded writer is consumed into an opaque sealed reader before receipt use.
Inventory, pinned bytes and rereads share finite configured resource admission.
This source portability removes the token issuer's Unix-only startup gate; it does
not qualify native Windows custody, the complete service graph or installed bundles.
Native protocol State continues to own signing permission, revocation and replay;
local journal contents cannot authorize recovery after a protocol-state rollback.

Combined candidate validation, original-deadline runtime completion and multi-replica
recovery remain open. Component coverage of Check, provider and Capture owners does not
qualify the full native service graph or cold-package fetch. Signed native releases and
reference-host twenty-run p95 measurements remain separate DX6/DX7 outcomes; the 30-second
admission budget is a configured limit, not measured latency evidence.

The committed `defaults/developer/network-profiles.nrt` supplies the Taira installation
profile selected by both release packagers, and its published checkpoint has passed
native signature and finality verification. The HTTP adapter binds explicit SDK contexts
to the release-approved HTTPS roots, overlaps up to eight independent committee reads,
and retains one operation deadline plus bounded per-peer tip retries. Every successful
read still requires independent contiguous-chain and exact-committee verification.
Authenticated bundle distribution, recurring signed checkpoint publication, fresh committee
observation and combined dataspace provisioning remain required for remote qualification.
Key rotation requires an authenticated
migration of retained release custody, not a silent fresh store.

Use focused unit and native filesystem suites while developing; use real
four-global-plus-four-private node coverage for attachment and privacy. Every new
safety/liveness rule requires a deterministic simulator regression and named
mutation. Run applicable codec/ABI checks and release checks on one candidate.
Component passes alone do not close any whole-network acceptance goal.

`iroha_deploy::attachment` retains the selected child genesis and exact parent SNS
ownership generation, then advances its durable anchoring cursor only from original
parent ordinary-write proofs and independently verified finality. A prepared child
certificate or successful transaction submission does not advance that cursor.
Exact anchored replays require no new transaction. Restart revalidates retained
proofs, and incomplete custody or uncertain publication fails closed. The separate
wallet journal owns quoted signed transactions and the marker preceding their sole
dispatch. `AttachmentStore::advance_parent` now combines fresh parent observation,
approved endpoint/signer checks, exact quoted wallet preparation/recovery, original
carrier verification and durable receipt publication. It retains a pre-dispatch
checkpoint so later tip progress cannot prevent authenticating the original
carrier. Each replay turn verifies at most sixteen successors, persists its progress,
and joins the original carrier to an independently observed parent decision. Completion
publishes the receipt and clears pending work in one atomic update. Once an Applied
carrier is retained, recovery does not depend on a transaction-status endpoint keeping
that observation indefinitely.

The shared `relay_once` operation recovers pending work before polling a new child
certificate. Its local SDK source is restricted to an exact owner-token loopback
context and compares the registration with retained signed-genesis execution.
Only a contiguous native-verified compact successor can become a parent transaction;
local successor observations and confirmed parent receipts remain separate.

`provisioning::RemoteProvisioning` now coordinates the original signed private genesis,
separate parent owner wallet, fresh parent quorum, canonical faucet and bounded paid SNS
requests. Its exact public funding policy and operation journals survive local reset.
Reopening rejects a different child, parent generation, owner or funding authorization.
Once a namespace envelope exists, retry preserves that exact request; before signing,
an unsigned quote may refresh within the original release's allowance. A fresh parent
observation after namespace completion selects the certified native World cut used to
authenticate the active lease owner and generation. Committed parent execution rechecks
that generation when applying registration; only its verified receipt establishes
anchoring. Provisioning and relay turns share absolute deadlines. The native supervisor,
Kagami command and Mochi profile picker call these shared owners; their combined
real-network qualification remains required before `dataspace up` can meet its
one-command contract. Installed profile upgrades may raise the retained rollback floor
without replacing the private ledger. Lower floors and substituted trust keys or
checkpoint locations fail closed.

Update source-coupled specifications as behavior lands. Public guides belong in
the optional sibling `iroha-docs` repository. Keep `status.md` about current
health and `roadmap.md` about remaining outcomes; retain routine test receipts in
the change report rather than appending development history here.
