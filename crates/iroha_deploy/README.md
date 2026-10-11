# iroha_deploy

The shared deployment engine for Kagami and Mochi developer environments and
operator network/dataspace workflows. This crate owns native localnet generation,
persistent supervision, context selection, definition parsing and finality verification. `iroha_cli` wires
`iroha dataspace plan/apply/status` to the existing native deployment engine;
the broader network/host engine remains in the phase plan below.

The design, file formats and phase plan are in
[`specs/network_deployment.md`](../../specs/network_deployment.md).

What exists so far:

- `bootstrap::publication`: offline native release production from independently pinned complete
  manifest bytes, signed-genesis key/network and a bounded contiguous current finality-proof prefix. Kagami exposes
  `advanced network-bootstrap prepare`; it derives consensus coordinates, signs the canonical
  `SignedNetworkCheckpoint`, and atomically prepares `checkpoint.nrt` and `network-profiles.nrt`
  for an explicitly selected release authority and HTTPS publication location. The schema in its
  public receipt binds the compiled candidate; preparation does not qualify a live network,
  publish the endpoint, or authenticate a bundle installation. Release packaging selects the exact
  committed `defaults/developer/network-profiles.nrt` image automatically: use
  `cargo xtask kagami-bundle --profile release --out <fresh-directory>` for the matching
  client/worker/daemon CLI package, or `cargo xtask mochi-bundle --profile release --out <fresh-directory>`
  for the desktop application. `--network-profiles` is an override for development bundles only.
- `managed`: workspace-scoped private contexts, four-validator process ownership,
  authenticated native control IPC, durable stop/restart/reset and signed readiness.
  `ManagedStore::up` retains the same generation and signer across starts; readiness
  requires one signed transaction to be applied by every validator. Kagami and
  Mochi call this owner directly. Explicit deployment/recovery targets preserve the
  workspace selection; ordinary startup and default auto-creation select their environment.
  Startup transfers the original runtime lock through inherited stdin, preserving ownership
  through worker loading and into its validator children. Unix retains the shared native file
  lock; Windows relies on the trusted inherited handle's writer exclusion.
  Binary verification, worker loading, activation and Ready publication share the original
  startup budget. A same-boot continuous deadline includes suspend across the handoff;
  clock failures refuse startup. Selection preparation, including fresh generation validation,
  precedes the foreground's final matching Ready observation within that deadline. Only the
  atomic workspace-selection write follows admission. This uninterruptible persistence cannot
  retroactively time out readiness or stop its worker; publication errors remain explicit and
  may have published, as specified by the native filesystem owner. Whole-command latency still
  includes selection persistence. Later renewal and maintenance turns have separate budgets.
  A callback-free gateway observation round binds all three providers to the exact same
  owned launch. It checks the complete aggregate revision and current interval at entry and
  on every ordinary exit, preserving each provider's fresh compliance projections and child
  observations. The closing material check and all final child observations run before any
  inner failure propagates; deadline/cancellation refusal still takes precedence. Active
  codec budgets retain the original per-provider validation recipe. The inactive round
  observes aggregate material twice rather than once per provider, so it makes no claim to
  identical sampling of an external change fully restored between those boundaries. No
  result crosses bootstrap effects, callbacks or the next gateway round.
  Within worker admission, the current executable reuses the retained launcher's content hash
  only after a fresh native open rejoins its exact path, identity and unchanged snapshot.
  Both opened files are revalidated; different paths still receive full content admission.
  Readiness submission reuses peer zero's transport after checking its endpoint against the
  selected client configuration. The rebuilt submission context performs fresh compatibility
  checks and retains the original deadline, signer, fee limits and four-validator proof checks.
  After ownership and generation admission, failures before IPC publish Failed with zero
  children. Rejected IPC clients do not terminate the listener. Later supervisor errors
  cancel work and stop owned children before retaining a closed failure; cleanup and
  status-publication errors remain explicit. `down` waits for native ownership to close;
  missing IPC while ownership remains
  does not prove stopped. An unavailable endpoint is reconciled only against its unchanged
  admitted session, the original generation and explicit terminal zero-peer status.
  A new start retires the stale session and endpoint while holding both environment locks.
  These changes still require matching installed-runtime and native-platform validation.
  Unix sockets stay under the private managed store when the complete pathname fits the
  native limit; longer paths use the short owner-bound namespace. Reset removes a validated
  stale socket only while holding both environment locks. Windows uses owner-restricted native named pipes;
  native Windows lifecycle execution still requires qualification.
  A new generation renders its final paths in private staging, then publishes its
  complete keys, configuration and immutable manifest in one native directory rename.
  Interrupted unpublished staging is discarded under exclusive operation ownership;
  a visible generation with missing metadata fails closed and is never regenerated.
  `up_dataspace` uses an independently installed parent profile and a sixty-second
  foreground budget. The same supervisor owns private validators and bounded outbound
  provisioning/relay turns; parent failure leaves private execution running. Remote
  bindings and release watermarks survive local reset, which cannot replace their child
  identity. Status separates live local peers from historical verified parent receipts.
- `localnet` and `genesis`: canonical configuration generation, independent private
  authority seeds, profile policy and genuine core genesis execution. CLI parsing
  stays in Kagami; generation and process ownership have no CLI or GUI dependency.
- `bootstrap`: canonical release-signed native checkpoint verification against an
  independently installed authority, with private durable release/clock rollback
  protection and explicit network reset identity. `ParentFinalityStore` retains
  the advancing native prefix separately and publishes before returning fresh
  readiness; reopening an older release never rewinds it. The Taira installation profile is
  bundled from its committed image, and the published checkpoint has passed native verification.
  Authenticated bundle distribution, recurring signed checkpoint publication and combined
  parent-provisioning qualification remain outstanding.
  Native installation profiles and bounded unsigned HTTPS retrieval select the release
  independently. Signed account profiles, committee endpoints and optional faucet
  allowances feed exact parent SDK contexts without forwarding child credentials.
  Parent profiles require a committed global root. Signed native World schema and
  optional build-registry roots select cold-download discovery; a fresh committee
  observation precedes authentication of the provider policy and token signer.
  See the [developer acceptance contract](../../specs/kagami_mochi_devex_goals.md).
- `attachment`: exact compact parent registration/anchor operations using the shared
  wallet journal, explicit fee ceilings and fresh independent parent verification.
  Pre-dispatch checkpoints and original signed operations survive timeouts and restart;
  only verified parent ordinary-write receipts advance the anchored child cursor.
  Replay retains at most sixteen verified successors per turn and completes the receipt
  and pending marker in one atomic publication. `relay_once` connects owner-token
  loopback certificate reads to this workflow without forwarding private bodies or credentials.
- `provisioning`: retains the exact child registration, imports its owner into a
  separate public parent wallet, and coordinates the canonical faucet and paid SNS
  operations under signed release allowances. Fresh parent quorum precedes funding.
  One request leases the private dataspace and its owner's default `admin@ALIAS`
  account alias together, with both rents under the original combined allowance.
  Recovery preserves signed journals and the exact original namespace quote,
  expiry, owner label and spending allowance, including failure before journal creation.
  Its state lives outside local reset, so a replacement child cannot silently inherit
  an existing parent attachment. After namespace completion, a fresh certified parent
  World projection authenticates the exact active owner and lease generation.
  Only `attachment` receipts confirm anchoring. Native supervisor scheduling and CLI/GUI
  wiring share this owner; combined real-network qualification remains outstanding.
  Initial custody directories publish their complete records and locks atomically;
  interrupted staging cannot leave an empty operation journal at its final path.
- `definition`: parsers and validation for network definitions
  (`networks/*.toml`, spec §3.2) and dataspace definitions
  (`dataspaces/*.toml`, spec §3.3). Definitions are read through
  `iroha_config_base`, and every error names its file and key. Unknown keys are
  errors. Dataspaces default to restricted visibility and the parent network's
  committee; owner-run nodes require explicit `committee.source = "owner"`.
  [`dataspaces/dpn.toml`](../../dataspaces/dpn.toml) contains only dataspace
  choices, with no validator or parent-network configuration.
- `iroha dataspace plan/apply/status <definition> --trust <public-profile.json>`:
  the owner key is selected by the definition; the explicit operator credential
  authorizes protected network reads. No client TOML or hand-written native
  manifests are accepted. Plan retains an immutable local artifact; apply plans
  if necessary, then submits each retained transaction at most once; status
  performs no ledger writes. State defaults to `~/.iroha-dataspaces`.
  `max_fee` is one positive aggregate cap across catalog, bootstrap, aliases and
  recovery. Omitting `account_alias` creates no account alias. The supported
  runtime requires an HTTPS parent with exactly four authenticated NPoS
  validators. Owner-node provisioning and explicit `[monitor]` are rejected.
  Focused tests and four-validator runtime qualification remain separate gates.
- `verify::finality`: the light finality verifier behind gate G5 (spec §9,
  §11.2 D-7). It is anchored in an authenticated genesis or a stored
  complete native `checkpoint.norito`, verifies every contiguous successor under
  finite proof and peer budgets, and requires `2f + 1` fresh
  challenge-bound attestations from the authenticated committee. Each epoch's
  committee comes only from the boundary result its predecessor certified. A
  checkpoint that lags by more than one observation budget catches up in
  bounded, individually published pages (`catch_up`). Exact retained
  predecessor decisions permit one block of lag after checkpoint import. Within an
  observation, earlier responses count when their exact decisions were verified in
  its contiguous prefix, including across boundaries. Supplied proofs cannot select
  their own trust roots. `verify::http` supplies native SDK proof retrieval and
  concurrent challenge-bound committee reads, with one operation deadline and
  bounded per-peer tip retries. Release bootstraps constrain every selected endpoint
  to the independently signed HTTPS roots. Other gates remain in the phase plan.

The committed definitions are `networks/dev.toml`, `networks/ci.toml` and
`networks/perf-10k.toml`. The dataspace examples are in `dataspaces/`.

TODO: add `networks/taira.toml` at release time (P9), once the real host keys
are pinned. Until then `tests/fixtures/taira.toml` has the same shape with
generated keys. These operator definitions are separate from managed developer
commands, which use release-authenticated installation profiles and require no
user-supplied TOML.

Fresh managed global localnets use the `StreamTokenAuthorities` profile to prepare
three distinct providers on peers zero through two, with four unchanged validators. Each provider
has ten separate service-role credentials; the network has one reserve-operations account and one
reputation recorder, with the existing manager retained for decisions. Registered transaction
accounts are funded and receive exact initial capabilities in signed genesis. Each issuer
allocation covers the original reserve quote, pricing collateral and admitted stake, plus
the existing setup fee allowance; ordinary service roles receive the fee allowance.
Retained validation requires each exact allocation once and rejects direct reserve-account
minting. Proof-outcome,
repair and ingest completion grants are provider-scoped; the orderbook matcher receives no broad
grant. Native runtime bindings stay absent until a validated service revision selects them.
Generated keys alone do not authorize work or establish current matcher policy.
The original governance configuration and signed execution policy bind the complete three-owner
map in all four retained configs. One native signed-genesis initializer authenticates all three
provider admissions under one original council; pricing is initialized once. One aggregate public
commitment binds the shared original timestamp/pricing/council, every provider's capacity, stake,
finite interval and endpoint, and all role identities. Provider-specific plan selection requires
an exact ProviderId. Retained profiles have no implicit first-provider selection.
Each selected peer renders its own additional HTTPS listener at the exact retained port and private
certificate paths; peer three has no provider listener. Providers have distinct advert/PoR,
compliance and CA/leaf credentials under fixed per-slot directories. Shared operations, recorder
and council credentials reside in the separate network directory. Configuration and prepared
transport do not enable token services or establish current admission, backing or readiness.
The profile also registers one shared pair of non-signing reserve custody and treasury accounts,
with no private credentials, permissions or initial balance. Only the manager receives canonical
reserve-policy and provider-credit management capabilities. Reserve policy, owner-funded collateral,
credit projection and capacity declaration require ordinary signed native transitions. Sidecar
replacement, removal or slot reordering cannot reinterpret the original signed profile.
Each provider has a bounded compliance template and two-of-three distinct catalog keys, plus one
dedicated ACK key for its actual gateway (`managed-provider-gateway-0`, `-1` or `-2`). Each controller
requires that gateway's one real ACK; no disabled gateway or fictional quorum vote is counted. The
manager receives the native `sorafs_gateway_compliance_operator` role once for the network.
The opaque retained plan binds canonical trust to the actual genesis-derived network and original
plan commitment, retains the original finite interval and exact empty external-feed policy, and
revalidates all sidecars on reopen. Original trust does not establish a promoted catalog, current
operator permission, acknowledgements, runtime admission or serving readiness. Standard profiles
have no generated compliance plan.
Bootstrap recovery, child inventories, runtime custody selection and gateway plan lookups reuse
the parent's immutable decoded profile. Gateway projections refuse another prepared generation.
Runtime selection and startup polling reopen only existing bootstrap custody; explicit startup
initialization owns its creation. Polling uses the retained renderer's exact generation and closes
its original profile checks on successful and failed child admission. Missing bootstrap state is
refused without reconstruction.
The final runtime policy comparison borrows that same original intent outside active decode
budgets and owned-profile admission. It retains complete policy construction, canonical encoding,
equality and the original operation-lock observations. Only two nested immutable profile scans
consolidate into the enclosing full-image entry and unconditional ordinary-result exit. No child
read, current interval or finality check is shared. A profile change completely restored between
these observations may be unseen; the read is not an atomic snapshot or a reusable authority.
Within one RuntimeSelection read, existing child constructors and bootstrap policy projections
borrow only its exact captured image. All original operation-lock and provider-scope observations
remain at their old boundaries, while immutable image scans consolidate into the enclosing full
entry and unconditional ordinary-result exit. Each child still acquires its own lock and freshly
reads its mutable records. Initial-enrollment histories, wallet inspection, runtime components,
launch configurations and current intervals retain their separate checks. This constructor scope
never escapes the selection read or crosses a startup effect. A profile change fully restored
between image observations can be unseen; this is not an atomic snapshot. Foreign captures and
constructor parents are refused. Active Norito decode budgets and parents opened under those
budgets retain the original complete profile-capture recipe.
Each read-only bootstrap traversal and child census owns a separate cache of up to three
immutable checkpoint imports, keyed by their complete bytes, network and chain. Fresh custody
and transaction checks still run for every child. Each cache ends with its traversal; active
decode budgets always perform the original import and do not reuse cached results.
Each traversal also retains at most two complete validated epoch contexts for reuse by that
same importer. This separate bounded workspace supplies no source or current-state verdict.
Recovery rechecks the caller's deadline after its final inventory read. Startup also rechecks
cancellation before publishing original intent and validates each newly issued authorization
before returning it. Shared live-authorization checks close cancellation after the original
and epoch reads, while preserving custody and expiry errors. Failed attempts retain their
original intent and epoch history for retry.
The ordinary CLI and Mochi global creation paths share this default; their private-root request
constructors select `Standard`. Restart preserves the exact retained profile. Profile changes
require a new context, and private roots reject the global service profile. Explicit unmanaged
generators retain their own profile selection. Admission evidence still requires the original
executed genesis and current certified native state. The generated certificate and retained plan
grant neither current eligibility nor local-network transport authority. Token services remain
disabled. Activation requires the public TLS listener, exact profile-bound archive transport,
ordinary policies/enrollment/grants and a durably published configuration revision. The original HTTPS port is retained exactly; activation must acquire it
rather than silently replacing the admitted origin. Generation never changes the OS trust store.

`managed::ManagedStreamTokenCustody` implements shared initial Configure/Enroll and bounded renewal for
that authenticated profile and its original signed genesis. It retains the original requests,
UTC limits and bounded fees before dispatch, and recovers the exact wallet transaction through
its once-only journal. Independently verified inclusion of that transaction is separate from a
fresh native custody-state proof; retained inclusion remains reportable during a network outage
without granting current eligibility. This source implementation does not activate services,
admit providers, declare capacity or publish configuration revisions. CLI/Mochi integration and
runtime qualification remain separate work. Generated renewal uses the same Enroll wallet and
requires the original full configured policy, a fresh exact native head/CAS, and the latter half
of that head's original signed interval. Each explicit sequence in 2..=64 retains separate immutable
UTC/fee terms; expiry must extend the prior interval without exceeding the original policy/provider
end. Historical enrollment accessors verify the exact wallet/carrier and never select a latest
filename or grant current use. Initial parent recovery remains bound to the initial enrollment.

`managed::ManagedInitialReservePolicy` uses the same generated-authority, original UTC/fee,
and native carrier-evidence owners for a closed initial `SetSorafsReservePolicy` operation.
It pins the original XOR asset, non-signing reserve accounts, issuer operations role and manager
as the decision authority. The wallet remains the sole signed-transaction and once-only dispatch
journal; `recover` never prepares, quotes, signs or sends a transaction. Independently proved
singleton absence is only a collision preflight. Activation requires successful inclusion of the
exact original Set plus fresh proof of the exact policy, manager, digest and activation time at
an equal or later certified cut. Historical inclusion survives outages without a fresh activation
claim. This source prerequisite does not fund collateral, grant credit, declare capacity, enable
services or change a profile; native reserve activation/runtime qualification remains a separate
integration gate.

`managed::ManagedReserveAccountRegistration` registers the original generated provider using
its issuer-operator credential, while retaining the manager context for independent finality.
It binds the exact selected policy, provider owner, underwriting, original UTC deadline and
fee authorization. The wallet owns the signed request and once-only dispatch; read-only
recovery preserves that request across restart. A native account proof authenticates the
provider owner, active policy and optional partition before services are enabled. Successful
inclusion of the original registration remains separate from fresh provider state and survives
policy rotation or read outages. Registration creates a zero-balance `Warning` partition;
collateral backing, credit, admission, capacity and durable service configuration require their
own native transitions. Current-candidate runtime validation remains required.

`managed::ManagedReserveTopUpRequest` retains the generated provider's exact selected policy,
partition, independent revision, movement id/amount and original UTC/fee terms before its
wallet prepares or submits one native TopUp request. Registration and top-up share the same
`ServiceAuthority` native provider-proof reader. Preparation and dispatch require fresh evidence
matching the original partition; recovery never renews authorization or repeats a submission.
Only the exact original signed wallet envelope joined to an independently certified successful
carrier creates `ManagedHistoricalReserveTopUp`. Its private constructor derives immutable
request fields from that envelope; public node/finality reports cannot mint it. Optional current
account evidence remains separate and may be unavailable after policy rotation or outage.
This source slice establishes no current movement Pending status, manager approval, reserve
transfer, funded collateral, credit, capacity or service activation. Native component and
installed-runtime qualification remain separate gates.

`managed::ManagedReserveTopUpApproval` requires the authenticated original TopUp history again
on every approve, advance and recover call. Its retained historical fields are comparison data;
they cannot create that capability. Initial preparation and first submission require a fresh
native account proof matching the selected current policy, complete partition and independent
CAS at or after the original request carrier. The original manager signs one native approval,
pays its fees, and retains the exact rationale, UTC authorization and once-only wallet envelope.
Native execution alone checks the movement's Pending state and atomically transfers provider
principal into custody. Private historical approval evidence joins that exact successful decision
to the original TopUp; it does not establish current balances, credit or service readiness.
Current account evidence remains separate and may be unavailable during rotation or outage.

`managed::ManagedInitialProviderCredit` retains the original generated provider's complete
selected policy, partition and desired credit record, plus immutable UTC and fee terms.
The generated manager signs a single `UpsertProviderCredit` with explicit native credit absence;
preparation and first submission require fresh exact policy/partition evidence and no credit row.
Only the credit-row absence travels as native CAS: policy and partition selections are preflight
facts. Native execution owns actual permission, provider ownership and aggregate collateral
backing. The sole wallet journal preserves once-only dispatch and read-only recovery. Exact
successful original inclusion survives later credit changes or proof outages; optional fresh
account/credit evidence remains separate. This source owner transfers no principal and grants
no borrowing, capacity, admission or service activation. Native generated-profile and installed
runtime qualification remain distinct validation gates.

`managed::ManagedProviderCapacity` declares the exact original generated service plan using
its provider owner's sole wallet journal. Its internal bootstrap entry point admits fresh native
policy, partition, credit, capacity and pricing facts; pricing must equal the original signed
genesis selection. The bounded economics helper uses canonical pricing and reserve underwriting,
retains the original admitted stake and derives actual top-up principal separately from nominal
settlement credit. It never derives reserve borrowing. Capacity retains all original inputs,
UTC/fee terms and checkpoint before signing, refuses a changed predecessor before first dispatch,
and preserves read-only recovery. Native declarations have replacement semantics, with no atomic
capacity CAS. Independently authenticated exact original completion and optional fresh facts are
separate reports, not service activation capabilities. Current admission/gateway/reputation
qualification and runtime activation remain separate owners.

The internal provider-funding coordinator retains its original economic selection before composing
reserve top-up, approval, initial credit and capacity. It skips principal movements when the original
reserve already covers the requirement. Recovery checks each child's exact original intent and
authenticated carrier; a newer deadline cannot change amounts or renew signing authority. Capacity
preparation checks the selected partition, credit and absence at the child's actual native read.
This funding sequence still requires the earlier reserve-policy and account setup and does not
activate services or establish current eligibility.

The internal service-bootstrap coordinator retains the complete generated policies, underwriting
and original fee/deadline terms before composing custody configuration and enrollment, reserve
policy and registration, funding, distinct-key ingest authority, gateway configuration and reputation policy. Each child owns its
original wallet and authenticated carrier. Recovery verifies explicit wallet preparation stages;
partial request/payload history is read-only until an explicit advance rechecks the native
prerequisite and finishes that same original. Recovery compares every original selection before
network access and requires the reserve carrier before every provider, strict prerequisites within
each provider, and reputation after every gateway. Independent providers may share a certified block;
every original transaction remains in the all-peer barrier. A fresh closed name census permits at most
three scoped provider workers outside active decode budgets; existing purposes and resumed histories
use serial dispatch. That census selects scheduling only: raced material still goes through ordinary
native admission and the one shared epoch/replacement fence. Every spawned worker is joined before
census or returning a report, with the same original deadline and cancellation. A provider failure may
leave another provider's exact resumable work; it never grants readiness. A newer I/O deadline cannot
renew the original signing deadline. Complete reports describe historical execution. The worker now
composes those owners, promotes the original signed catalog and restarts only its owned peers
with the derived token configuration. It rechecks the same paid readiness receipt, exact Applied
carrier on all four peers, promoted catalog and fresh native discovery before reporting Ready.
Automatic custody renewal leaves Ready before advancing the exact next enrollment through its
sole wallet journal. One two-minute turn covers the owned restart and read-only reproof of the
same paid readiness transaction, bounded by the original enrollment expiry and generated
profile. Ready requires both the fresh discovery timer and the retained enrollment timer, even
when host UTC moves backwards. Combined native qualification, interrupted bootstrap recovery
and explicit authorization for expired unsigned requests remain open.

Generated compliance catalog signing uses two fixed original governance keys and the exact
empty-feed policy. Initial and successor catalogs are bound to the actual network, live for at most
one day, and cannot exceed the original material interval. The publisher must authenticate the
promoted predecessor and retain each original before dispatch. The managed catalog coordinator
performs stage, independent acknowledgement, promotion and exact retained readback against the
worker's actual owned gateway process.

The existing reserve-account route supplies optional complete capacity and required pricing
originals at the same independently selected native World cut as policy, partition and credit.
Credit, capacity and pricing frame reservations share the route's original working-set budget.
These exact facts do not grant active capacity. Automatic setup selects amounts internally from
the generated plan and canonical economics; this owner introduces no user TOML or amount prompt.

The managed provider-advert publisher signs only the original retained body and fixed advert key.
Twelve-hour slots reproduce exact bytes after restart; refreshed adverts remain within the original
admission and TLS interval. Each call makes at most one bounded POST to each original management
peer with a fair share of its deadline. Partial acknowledgments describe transport only. Native
admission/custody discovery and live service qualification still gate cold-package reads. The
worker refreshes at actual signed advert/catalog midpoints and rechecks native discovery within
its shared freshness limit. One bounded background attempt preserves the old observation; only
fresh successful checks can replace it. Failure never extends expiry, and expired readiness
stops the worker's owned peers. These paths still require combined native runtime qualification.

The private generated-service renderer retains separate, create-only sibling launch configurations
and exact content hashes. Original peer files, custody and signed execution policy remain unchanged.
Its first Catalog revision enables native discovery on four peers and the one generated storage /
compliance controller with four fixed software transaction roles; token issuance remains disabled.
Token configuration requires recovered original bootstrap carriers and exact retained enrollment.
Restart selects the enrollment named by fresh native state and reconstructs its complete original
runtime ancestry; missing ancestor material or receipt custody is never recreated. The process
owner checks the selected exact transaction on every peer, and custody verification shares the
provider discovery cut before readiness. The daemon still qualifies current native use. The
selected policies explicitly cap each native runtime transaction at one XOR, independently of
bootstrap authorization. Rendered configuration and historical evidence are not Serving readiness.

`ManagedInitialProviderIngestAuthority` shares the existing service-setup intent, finality and wallet
recovery owners. It authenticates the original generated profile, signs with its fixed provider-owner
credential and selects the separate generated completion role; the manager remains the native
finality reader. Exact historical Set execution survives peer outages but does not establish current
completion permission, source eligibility or serving. The selected parent intent supplies all inputs;
users do not provide authority TOML or keys.

Fresh generated provider profiles initialize one separate native attestation journal per selected
peer (zero through two) before generation publication and commit its fixed policy digest in original signed-genesis material. The derived
stream-token revision selects the dedicated completion-key approval, local durable clock and exact
inventory only after original ingest setup has finalized. Restart opens retained history and never
repairs a missing journal; the local inventory is not proof of registry inclusion or three-provider
cold-package readiness.

The generated publication plan commits one explicit host/provider (slot zero), its existing owner
receipt signer, a separate ordinary-funded `MusubiPin` account and immutable pin session. It retains
the original provider TLS identity on a separate reserved port and provisions the sole native seed,
replay-journal, clock and pin-session owners before generation publication. Missing custody is never
an initialization signal on restart. Its typed installation projection remains inactive in original
peer configs; the concrete backend, publisher-side manager handoff and complete three-provider
publication/cold-install qualification remain separate activation requirements.
