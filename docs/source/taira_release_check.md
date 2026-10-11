# Taira release checks

Run `python3 scripts/taira_release.py check` or
`python3 scripts/taira_release_check.py` for optional basic Taira regression checks. The default
`--native-check-scope basic` selects native regressions for startup
admission, configuration, deployment and secret custody, cryptography, public
onboarding/faucet and SDK/Torii contracts, plus real four-validator Applied
transactions and a signed-snapshot restart. It does not claim complete consensus
fault or advanced product qualification.

Use `--native-check-scope full` to execute the full native census,
including advanced Core history, compaction and fault matrices and proof
production. Linux additionally selects OpenSSH descriptor custody, native process
identity, and credential custody controls. The runner's selected regression census is authoritative for the current source and platform.
These checks run independently of deployment. Neither scope is a prerequisite
for Taira or production deployment; `prepare` builds and captures the signed
source directly and records that regression checks were not run. Both scopes retain
all runtime security enforcement, CLI custody tests, crypto verification tests
and proof-size limits. These are test selections, not runtime feature toggles.

Torii defaults allow 10,000 request tokens per second with 100,000-token
bursts for query, transaction, deployment, pre-authentication, content and
Soracloud application routes. MCP and proof endpoints allow 600,000 tokens per
minute with the same burst; content and proof egress allow 256 MiB/s with a
1 GiB token burst. The SoraFS gateway replenishes 600,000 request tokens over
60 seconds with a 600,000-token burst. Its integer token bucket retains constant
state per client, capped at 4,096 tracked clients, and preserves configured bans;
it does not allocate one timestamp per request. Weighted proof reads consume
their full cost. Regressions exercise large
single-client bursts through the real limiters and verify minimal configuration
inherits these defaults. Bodyless application reads wait in a bounded queue for
fanout memory before decoding, rather than immediately rejecting overlapping
reads. Memory ownership, cancellation, queue capacity and deadlines remain
covered independently of request-rate budgets.

Both scopes verify current embedded commit certificates and portable proofs with
real quorum signatures. Public proof, bundle and challenge-bound attestation
handlers run against an actual current consensus node, checking the signed tip,
node identity, resolved configuration and build identity. Missing certificates,
corrupt certificates, stopped drivers and foreign signers fail closed. The SDK
backpressure cases use these same current response types and preserve their
original bounded deadline and challenge through retries.

Current consensus selections include idle work wakeup, nonempty proposals at
late views, bounded rebuild after oversized payloads, far-behind joiners and
poisoned payloads. The application executor separately rejects both empty bytes
and canonically encoded zero-transaction proposals, and real node tests submit
work before and after restart.
Both scopes retain prepared signature custody across allocation refusal,
validation, publication and replay. Queued successor builds wait for Core's
exact applied parent, preserve transaction arrivals and permanently cancel
their original owners when that parent or view is withdrawn.

Both scopes reject pulse-only proposal work, including received and recovered
bodies. An idle mandatory height defers session activation and signing until
independent work exists; useful work still requires its exact validated pulse.
The bounded proposal snapshot retains its queue ownership while that pulse is
pending, and the real threshold-signature regression checks the shared gate.

Before the four-peer fixture, both scopes check that paid lane authorities come
from registered and activated accounts bound to peers in signed genesis, and
that failure summaries retain public phase status without transaction payloads.

Both scopes reject retired Kagami epoch-key derivation commands and verify
authenticated current-height observations. Before starting peers, retention
fixtures require exact compiled source identity and reject changed authority
generations, beacon bindings, predecessor authorizations and height intervals.
The same real four-peer scenario runs on every platform. Its four independently
genesis-anchored finality chains verify that certified scheduling transitions
retain original validator keys and the authenticated beacon session, alongside
a fresh verified pulse and exact fee-paid deployment effects.

Both scopes check Core beacon capability against the exact public session and
validator seat, consumed runtime credentials, and genesis-bound bootstrap before
network fixtures. Torii readiness exercises the running consensus driver's actual
state and leaves beacon setup ingress available; the separate Core capability
checks reject an uninitialized signer. Setup uses real committed transactions to
advance DKG phases; it never creates empty blocks or invents committed heights.
The shipping Taira bootstrap executable is a separately authenticated artifact.
The real four-peer fixture uses fresh native DKG custody and crosses the mandatory
beacon pulse during the complete paid dataspace deployment and four-peer
finality workflow, additive catalog recovery, and both public routing sequences.
DKG
finalization records the actual authenticated committed height; it does not
assume one block per operation. Pulse verification derives its height and parent
anchor from the signed genesis and accepts only a nonempty canonical carrier.
One fresh ceremony serves this complete sequence in both scopes. Its generated custody lives only in a validated owner-only
runtime directory outside Git; the isolated shipping Kagami and Taira launcher
are explicit inputs. The fixture's configured runtime-provider broker supplies
the exact signer custody. The full launcher's Linux/Inrou requirements remain enforced.

Both Core startup selections check the fixed-domain IPA parameter cache with
concurrent cold initialization, canonical bytes/fingerprints, owned clone
isolation, rejected domains, warm-cache malformed metadata and relabelled-key
rejection. Caching public parameters never substitutes for key authentication.

Both Core startup selections run the native durable archive recovery group
(`sumeragi::executor::archive_tests`): a partial archive failure retains the
exact decision and retries without re-execution, and pending capture rejects a
substituted header, certificate or state. This group runs immediately after
configuration and MV ownership checks in both scopes. Any failure stops the
optional diagnostic before its other startup groups, shipping binary builds
or fixture network execution; it reuses the same compiled harness and runs each case once.

After startup checks, the gate runs the exact reset-scope CLI control and Torii
canonical outcome, transaction-visibility and prepared-account admission tests
before its fixture shipping codegen. The optional diagnostic records this passed
prefix in its pre-network checkpoint; `prepare` records that regressions were not run. The gate then runs the real four-peer beacon fixture
before the long independent regression census. This order
exposes a fresh-network liveness or prepared-account failure early without
dropping any selected check or changing
the diagnostic evidence graph. A failed four-peer fixture fails the optional
diagnostic. Its passing groups do not grant deployment authority.

Both scopes run their selected MV ownership checks after configuration and
before native archive recovery: finite allocation credits, exact release/poison wakes, charged
Cell generations, original map/undo retention, actual epoch reclamation and
strict allocation-free map handoff/publication. These run once from the same
immutable copied artifacts and enter the exact pre-network and complete checkpoint
census. A failure stops later Core runtime checks, shipping builds and network
qualification; a changed MV artifact or selector cannot reuse an earlier checkpoint. The runner
still compiles its complete native feature graph first. For a cheaper development
check before that full compilation, `--focus-regression` runs selected `mv`,
`mv-ebr`, `mv-map`, `mv-admitted-map` and `concread` tests in an earlier build
phase. Any failure stops before configuration and heavier harness compilation.
After portable tests and their copied executables finish, the same coordinated
warm lane builds mandatory configuration and any remaining selected harnesses.
Configuration must still pass before the overall diagnostic succeeds, including
portable-only requests. Each phase reports its own feature graph; these results
provide no release qualification or independent-checkpoint credit. Authenticated
`prepare` builds and captures its signed source without running this test graph.

The source census includes charged Concread notification custody and the current
native State source, recorded-execution and allocation owners. Archive refusal,
retained dispatch and publication controls remain selected under their owning
modules. Exact selector checks also bind staking's atomic failed-payout control
and Kagami's permissioned-genesis prohibition on additional XOR minting.
Before peers start, both scopes verify that only the original fixture launch may
assert fresh consensus signing keys; restart cannot repeat that assertion.
The generic test-network harness also rejects this assertion after history loss.
They also check that stock beacon configuration retains existing providers and
uses the exact authenticated beacon credential binding.
The daemon selection checks exact broker catalog composition and rejects changed
credentials, substituted catalogs and unsupported provider slots.

Focused development checks validate an explicitly forwarded `TMPDIR` in the
execution environment before invoking the compiler. Set it to an existing,
writable absolute directory visible to the build guest; a host-only path fails
immediately with the path in the diagnostic. An unset `TMPDIR` keeps the
platform default. When the exact four-peer beacon regression is focused, the
diagnostic audits the complete shipping binary table but compiles only its
runtime inputs: `iroha3d`, `iroha`, `iroha3d_taira`, and `kagami`. A future different network runtime selection
uses the complete diagnostic shipping build. Authenticated `prepare`
continues to compile and capture `sorafs-node` with all shipping binaries.

Both scopes also require the signed stopped-predecessor controls: strict state
decoding, retained directory identity across archive/restore, complete process
absence, exact prior/successor unit authority, and rollback without restarting an
explicitly stopped predecessor or downgrading a failed running predecessor.

Both scopes exercise the native reset controller’s signed beacon plan, exact
roster/seat and provider/unit bindings, and bounded continuation after submission.
A lost ceremony or an early child exit cannot repeat committed canaries or admit
a later operation. Public input assembly derives beacon authority from the exact
native genesis and unsigned draft, rejects caller-supplied generated authority,
and preserves credential-free preparation and atomic public bundle publication.
These controls use the existing CLI harness and support exact focused selection.

Prepared canary and beacon-install transactions bind their TTL to the signed
execution window before fee quoting, retaining the exact creation timestamp and
any shorter configured lifetime. Both scopes check exhausted windows before HTTP
and delayed quotes without extending authorization or repeating submission.

Finality readback honors HTTP 429 retry delays within the caller’s original
absolute deadline. Invalid retry instructions and fixed response/proof failures
remain errors; a failed or late read cannot advance the verification anchor or
cause a transaction resubmission.

Both scopes require canonical transaction reads to release their State snapshot
before Kura authentication, then recheck the exact committed binding, and reject
corrupt or foreign durable evidence. These use the existing Torii unit harness.

Both scopes require the blocking SDK to drive pooled HTTP connections and
background tasks between calls, preserve clone ownership, and cancel tasks after
the final runtime owner is dropped. These reuse the existing native SDK harness.

Both scopes include seven public faucet policy checks: exact configuration,
asset alias resolution, disabled 403, route-catalog policy, OpenAPI shape and
read-only MCP visibility and dispatch. These reuse the existing Torii HTTP,
Torii unit and shared-library harnesses. Public discovery never replaces an
independently trusted faucet authority pin.

Both scopes require unsigned node-capability discovery before a fresh account's
registration transaction can be submitted. The full production HTTP router is
tested with an empty account registry, while privacy and operator routes remain
authenticated. SDK checks still reject ambiguous JSON and missing or mismatched
data-model and transaction-schema identities before sending transaction bytes.
OpenAPI authentication metadata and MCP forwarding policy must agree with the
route catalog. These checks reuse the existing SDK and Torii harnesses.

Contract view and simulation requests must bind the execution authority to the
authenticated caller before routing or VM work. Both scopes exercise the direct,
dynamic and delegated view paths, reject forged callers from online-only
observers, and prevent protected views from losing authentication through an
unsigned HTTP upstream. These checks run in the early startup preflight and
reuse the existing Torii unit harness.

Both scopes execute the additive catalog data-model, immutable policy, manifest,
transaction staging and startup reconstruction regressions. The four-validator
catalog test adds a dataspace and lane through one committed transition, then
checks retained history and replay. The data-model library joins the same native
Cargo graph; its selected tests execute before the optional diagnostic
fixture network and shipping-binary build. They do not precede or gate `prepare`.

Query failures decode the node's bounded error envelope; a missing asset, unknown
route or malformed response cannot be reported as an expired or missing cursor
solely from its HTTP status. Both scopes include these focused regressions.

Both scopes compile the identical MV library and explicit allocation integrations,
configuration, data-model, crypto, P2P, CLI, daemon, Core,
proof, Torii and consensus harness graph plus native shipping binaries with six
Cargo jobs. This preserves the warm target and dependency feature union. Deferred
harnesses have compile coverage only; their cases never appear as test passes.
The basic scope defers 636 seconds of advanced test execution measured in
preparation56. Preparation99 passed its then-selected 330 basic cases in 547.1
seconds, including 245.2 seconds for the real network sequence; its warm Linux
release build took 11 minutes 53 seconds. These are observed durations for that
candidate, not guarantees. Build, stage and test durations remain explicit.
Python 3.11+, the repository Rust
toolchain and previously fetched dependencies are required; Cargo runs offline.

The Torii harness executes the shipping routes through plan, prepare and submit,
checks SDK receipt verification, and applies queued fixture transactions. It
covers a 33-hour-old committed anchor, expiry without a new block, exact replay,
onboarding identity binding, faucet funding and proof-of-work anchor aging. A
fresh onboarding receipt uses service time for its lifetime; committed height,
hash and ledger time remain the anchor for state and lease observations. These
contract tests use real route and ledger code with disposable inputs; they do
not replace the deployed four-validator consensus and public application checks.

After the source inventory and Torii lifecycle registration checks, Cargo first
checks metadata for the exact selected test graph before compiling its executables. This expands
Rust macros and checks platform types that formatting and source audits cannot
validate. The check and build share their package and feature selection,
environment, warm target and held locks. A failed check stops code generation,
native fixtures and checkpoint publication; a successful check does not count
as a test pass or replace full compilation. Build scripts and procedural macros
can still require host code generation during the check.

The dedicated
`iroha_config --test taira_config_contracts` target checks production descriptor
defaults, malformed collection values and the maintained Taira Nexus profile.
It loads no runtime signers and has no Core or test-network dependency. These
four contracts execute first after the combined native harness build, so schema
failures stop before other runtime tests. Storage-budget and ambient-client isolation
checks remain in the test-network harness. The gate computes and reports the
complete native census from its required test selections. The configuration target uses the same source capture, Cargo environment,
warm target, profile and inherited locks; it retains all package defaults in the
same Cargo graph as the other harnesses. No first-run or total runtime improvement
is claimed without measurement.

The source inventory preflight rejects every selected declaration absent from the
captured packages and reports the complete missing list before Cargo. The native
harness `--list` remains authoritative for exact module paths and compiled test
registration. Run the lightweight current-checkout guard after test refactors:
`python3 -B -m unittest discover -s pytests/scripts -p test_taira_release_check_source_inventory.py`.
It scans both qualification scopes and checks that every current per-seat beacon
bootstrap test remains selected. The current census covers authenticated genesis
and rotation seats, bounded proof frames, one-shot attempt custody, exact provider
inputs, and consumed configuration descriptors.

The combined native test build selects the exact `iroha_cli_lib --lib`
and `irohad_lib --lib` test harnesses. The daemon cases execute signed genesis
and check the deployment account in its final staged state, including role and
revocation semantics; the deployment flag is restricted to offline `--check-config`. The genesis fixtures share the canonical daemon configuration and production staging setup; all affected unconditional manifest/crypto consumers are selected with them. A single Cargo invocation unifies the selected packages and their
default/dev-dependency features; it does not add feature overrides. The CLI test
copy executes under the original immutable artifact owner: its priority control
runs before the separate production `iroha3d`/`iroha` build and four-validator
test, and its remaining batch runs after that test. It needs no second Cargo test
build. Its manifest, bin target kind and test profile distinguish it from the Rust
SDK's `iroha` library harness and the production CLI. Each test copy is released
through its existing owner after its last selected stage; copies with no stage
after the four-validator test are released before production codegen. A startup
or priority failure stops before production codegen or network execution;
production snapshots remain retained. Configuration
and proof-bound checks retain their selected cases in both scopes. Adding the CLI changes the combined test feature union,
so the first run must warm and qualify that union; latency savings require actual
measurement and are not inferred from these orchestration checks.

After configuration, MV ownership and the native archive recovery group, both scopes execute empty-journal Queue
admission, HTTP readiness and daemon startup-policy regressions before CLI and other
runtime checks.
The full scope also executes Core snapshot-owner and cold
certified-history groups at this early boundary. Full-scope cold storage cases restore multiple completed slots, recover only the current
partial publication, recover independently pruned pairs using an authenticated
retention frontier, and reject corrupt or missing retained history. Discarded local
certificate history cannot be resurrected after replica application advances. The remaining startup
groups collect their failures before stopping expensive work. On success, the
four-peer fixture's shipping codegen builds the authoritative shipping binaries with
default features, without test targets, a test profile or fixture-feature overrides.
It preserves the warm target, tool environment and locks, and must observe every
production binary. Core and Torii library artifact events must exclude their
`iroha-core-tests` and `test-fixtures` features, so a dependency/default-feature
leak fails before any peer starts. This audit reruns on every attempt, including
checkpoint reuse. The remaining groups execute each selected test once.
Preparation keeps two checkpoints that bind the explicit scope, exact selected
census and copied artifact identity. The pre-network checkpoint covers MV
ownership, native archive recovery, startup and priority groups and is published before
shipping codegen; a retry after a shipping, capacity or network failure reuses
only that exact prefix. The complete checkpoint covers every selected independent
test and is published only after the four-peer fixture and the deferred groups
pass. Either is retired before its tests rerun. Core and daemon copies stay
retained until their final selected stage. A failed startup preflight never
publishes either checkpoint. Strict storage construction and both
snapshot geometry restoration paths share one recovery sequence: rebuild budgets,
finish publication recovery, then compact terminal history and rebuild route indexes.
The source contract rejects bypassing this sequence or moving compaction before
publication repair. Cold fixtures establish signed bootstrap and live lifecycle custody
before publishing payload history, so their negative controls reach the intended
corruption boundary. Startup inventory retains authenticated append-preimage bundle
rows through source validation; it does not reread an unfinished pair as a live one.

CLI client admission binds the configured chain, genesis NetworkId and account
address discriminant to the signed inventory during assembly, apply and recovery.
The same check runs before convergence child custody; stale runtime or validator
clients fail before operator-key admission or stage snapshots.

The full Core scope covers the complete Soracloud and SoraFS instruction inventories at
the Initial executor boundary. Dispatch and admission come from the same typed
registry; unavailable mailbox and direct provider-owner operations remain
explicitly closed. Citizen-bond operations have no production instruction API,
wire ID, or native handler. Before Cargo,
`check_taira_initial_executor.py --repo . --self-test` compares every wire type
with that registry and rejects mutations which remove or alter reviewed entries
or restore removed citizen-bond operations. The selected cases
exercise validator identity, role grants and revocation, pin fees and ownership,
and rejection before state mutation. Exact transaction confirmation uses the
dedicated details endpoint, with separate coverage for restricted history access
and failed child processes that attempt to return successful reports. A real
Torii socket-to-SDK regression checks the canonical ErrorEnvelope response;
only the dedicated proof-absence code plus HTTP 404 becomes retryable absence.

The same library batch includes Rust SDK envelope verification and Torii's exact
retained-payload, detached-signature and canonical response checks. The public
HTTP contract fixture then runs before node compilation and the four-validator
gate. It prepares and signs the exact Ordinary payload through real routes;
submission preserves its complete signature-bound envelope and requires durable
single-route custody. Unsupported intent or actual multi-route execution fails
before queue writes or accepted/pending receipts. Separate execution overlays retain contract state assertions.
Only the four-validator and deployed checks establish canonical Applied state.

Every Cargo-produced harness and native executable is copied under Cargo's
profile locks into a private read-only directory before execution. Captured
release checks verify source fingerprints while holding those locks; foreign
checkout fingerprints fail the check. Later stages and CLI capture use the
copies, preserving the original Cargo metadata. Another build cannot replace
the selected executable between compilation and execution. Each private test-harness
copy is released after its final subprocess finishes, including a failed test.
If an earlier stage fails, the same isolation owner releases its unused harnesses.
Only those exact copied inodes are eligible: Cargo outputs, native `iroha` and
`iroha3d` snapshots, fixture logs and artifact observations remain retained.
Changed paths fail cleanup without deleting their replacements. Abrupt preparer
termination or a failure before copy publication can leave copies for diagnosis;
this workflow never scans old runs or deletes other owners' files. Keep concurrent
development builds in their own stable Cargo target slots to avoid lock waits
and source-fingerprint conflicts; the warm release target remains reusable.

The crypto and P2P gates check authentication deadlines, puzzle cancellation,
memory ownership during in-flight work, exact solution verification and validator
dial/retry ownership. Dial plus preauth bounds outbound authentication and standby
takeover independently of established-session idle. Dev/test profiles optimize
Argon2 and Blake2 arithmetic while retaining the production puzzle policy.

The full proof-production gate produces and verifies fully witnessed eight- and sixteen-row
transfers with the default resource limits, checks the maximum admitted proof
shape against its canonical frame, and rejects proofs beyond explicit limits.
Payload accounting and framed persistence use separate ceilings derived from
the same canonical geometry. The CLI confirmation gate follows a queued hash
through its exact Applied wire proof, retaining ambiguous expiry as pending and
retaining the last observation when a status read times out under the remaining
confirmation budget. It continues polling within that deadline;
shorter configured request timeouts, malformed responses and other lookup
failures remain errors. Confirmation never resubmits the transaction.

The network gate runs one fresh native four-validator production-custody fixture
with mandatory NPoS/DA in both scopes. It preserves the generated Taira catalog
and tests both its funded universal default-route account and a distinct fresh
funded account explicitly routed through the configured PayNet lane. The paid
DPN workflow precedes a second additive catalog transition, full authenticated
Kura replay and signed-snapshot recovery, with exact historical transaction,
committee, permission and storage proofs retained on all four peers.

Each public routing sequence submits three consecutive signature-bound
Ordinary single-route transactions and requires the same exact state-resolved Applied
height in both local and global status on every validator. Between the second
and third transactions, all four validators publish complete signed snapshots
and restart with their retained storage and real custody. Every new process must
load its exact snapshot, serve `/readyz`, and retain at least that height; the
third transaction then proves renewed Applied execution on all four peers.
The original transaction, observation and restart deadlines remain unchanged.
Dedicated service-owned Ordinary admission remains a separate contract. A sole
native threshold-key lifecycle certificate also uses signed Ordinary admission
so that its exact next-height authorization executes in the same global carrier.
That ingress authenticates the current frozen-roster quorum certificate and
preserves fee, signature, network, height and routing checks. The current driver
does not consume multi-route work. Public single, entrypoint,
batch and peer ingress reject such submissions with
`unsupported_transaction_admission` before canonical retry lookup or durable
custody. Receiver regressions cover installed and absent journals, future
contexts, predecessor advancement and retained canonical registry records.
The Core queue enforces the same contract before fee or journal ownership, including
batch admission and startup replay. Transaction gossip rejects unsupported
certificate carriers before persistence or deferred retries; a valid historical
certificate cannot grant execution support. Regression tests check unchanged
journal bytes, no queue or certificate custody, explicit unsupported replay failure,
and successful durable admission of supported Ordinary work.
Current Ordinary queue regressions preserve exact signed FIFO bytes across a
nonempty committed successor and journal replay, and select a full-block gas
call while an unrelated catalog route is idle. The early beacon stage checks
that component commit topology leaves the scheduled network authority unchanged
and authenticates the shared validator fixture before dependent regressions.
Certificate verification and bounded transport component tests remain selected;
they do not establish current multi-route execution support. The KAGEMUSHA V1
top-up/redemption commands that required that unsupported admission contract were
deleted on 2026-10-05.
Global status can query other peers, so only the additional local observation
establishes each validator's own application. Peer clients ignore ambient client
identity and endpoint overrides. Each status read uses the SDK routed request
budget capped by the remaining absolute phase deadline. The blocking local read
recomputes that budget after its dedicated thread starts; thread scheduling cannot
give a late request a fresh timeout.
Public submission retains the SDK's routed request budget and reconciles its
original hash before the separate 90-second all-peer observation phase.
Cargo emits both node and client paths explicitly; fallback builds and
sandbox skips are disabled. The focused `taira_consensus_contracts` harness avoids
compiling the full consensus suite, and keeps private fixture logs in the warm
target for failure diagnosis. Test ports use lifetime-held OS leases in an
owner-private host runtime directory. A reserved but unbound port remains
exclusive; process exit releases its lease without writing into the source
tree or deleting shared lock files.

Each temporary peer has an explicit 1 GiB storage budget on the shared host.
The gate requires 8 GiB free before compilation and checks again before peer
startup: 4 GiB for the four budgets and 4 GiB for scratch files and logs.
Production filesystem auto-sizing remains unchanged. Codec table fixtures are
embedded, materialized without source permissions, and reused across restarts.

For a testnet attempt stuck on an unresolved canary before edge staging,
`iroha taira public-reset abandon` takes the original signed inventory,
authorization and SSH custody, `--expected-journal-sha256`, and the explicit
`--abandon-pending-mutations` flag. It preserves the exact unresolved journal
before running ordinary rollback; cache expiry never becomes a chain rejection.
Keep the original fixed host dispatcher until rollback completes. Use the
original journal digest again to resume an interrupted abandonment.

Ordinary checks use the existing sibling `.taira-testnet-build-targets/routine`
directory. `--target-dir` or `TAIRA_TESTNET_CARGO_TARGET_DIR` can select another
existing development lane; both must agree if supplied. Ambient
`CARGO_TARGET_DIR` does not select this lane. Neither command creates or cleans
a Cargo target. Keep a stable lane for repeated checks.

The focused native gate enables incremental compilation in that existing lane.
Incremental native runs bypass sccache, which rejects `CARGO_INCREMENTAL=1`.
Nonincremental native and Linux release builds retain the persistent sccache.
An explicit `CARGO_INCREMENTAL=0` preserves a constrained or CI build policy;
only `0` and `1` are admitted. This preference is passed only to native builds
and tests. Build-only preparation records that regression checks were not run. Linux
release compilation retains its original sanitized environment and release
profile. Each feature graph keeps its own Cargo cache; no test features are
added or removed to force reuse. The first incremental run populates those
caches, so a speed improvement must be measured on subsequent focused changes.
Within the optional diagnostic, source checks, startup and priority native
regressions precede the four-validator fixture check; their failures stop that
diagnostic before its shipping-binary compilation. The remaining independent regressions run after that check from the
earlier combined graph shared by the contract test harnesses. Its log
records the actual Cargo-selected native binary paths and profiles separately
from the later Linux release artifacts.

Authenticated `prepare` retains the repository's `target/` lane and its fixed
Git-object source capture. The live preparation bootstrap must match its selected
signed source. Build-only `prepare` does not run native qualification or select
regression tests; optional development diagnostics use the checkout's current
gate. Its explicit `--target-dir` override remains available;
the development environment selector does not affect preparation. Checks refuse
the exact repository `target/`, existing source capture lanes, and lanes marked
for release. Preparation refuses the routine lane and lanes marked for development.
A stable `.taira-build-lane/` owner-private directory records the role and canonical
repository root and holds a nonblocking mode lock through Cargo and every harness
child. Another checkout must select its own stable lane, so alternating checkouts
cannot churn the same lane's source paths. Preparation also
retains its original source-custody and output locks. A busy lane fails before
compilation. Existing target permissions remain unchanged.

Both modes use the same isolated `target/taira-release-cargo-home`, including the
same lexical registry paths, selected Rust toolchain, explicit repository Cargo
configuration, optional persistent sccache and the existing linker selection.
Cargo starts from `/` to exclude ancestor configuration. Ambient Cargo settings
and runtime credentials are not inherited. Diagnostic checks still compile the
mutable working tree and verify HEAD continuity; they never qualify a release.
The mode locks coordinate these entry points only: arbitrary direct Cargo commands
do not acquire them. Keep those commands out of an active preparation lane.

The check runs focused regressions for secure inherited configuration and signing FDs,
network-369 inventory decoding, aggregate timeout admission before custody,
required preseed budgets, per-host carrier verification and the exact action ledger,
native genesis-path rebasing with secret-free errors and owner-only output,
configuration artifact custody and signed genesis startup,
generated stages frozen to 0400 and their native consumers, preseed receipt
ordering, KVM ioctl error preservation on a regular file, and all five read-only
host preflights. The process-stream checks send an exact-digest 64 MiB closure
through real pipes with both outputs backpressured, bound each output turn,
retry interruptions, and verify absolute deadlines, early stdin closure, and
cleanup of a descendant retaining the output pipes. They also preserve a remote
rejection and its bounded stderr after early stdin closure, drain diagnostics
larger than pipe capacity, reject a successful exit with an incomplete frame,
and kill and reap a child that closes stdin then hangs. They use the system
`/usr/bin/python3` only for harmless disposable child fixtures. The KVM regression needs no KVM device or root access and runs
on macOS and Linux. The receipt namespace checks cover every host action and
canonical artifact role, including underscore-bearing labels, and retain path,
control-byte and Unicode rejection. Systemd checks use captured numeric
`ExecMainCode=1` evidence for a completed manager operation and require
`active/running` for the long-running validator. They cover terminal failures,
pending jobs, malformed evidence and read-only recovery after a deadline.
Start and restart also wait for the signed Python launcher to execute the exact
daemon within the original deadline, without submitting another manager job.
Changed launcher commands remain immediate failures.
The active journaled restart path waits for all four Torii `/readyz` responses
before onboarding, using the deadline captured before its one restart submission.
The endpoint rejects pending Queue reconciliation and restart-required admission;
a responsive `/status` alone does not establish write readiness.
Signed convergence uses its own bounded phase. Each validator's
`SumeragiStatus.committed_height` names the tip it must attest, and its
node-signed attestation answers a fresh challenge with the status captured for
that tip: no halt reason, the current protocol version, a signer (if any) equal to
the node key, `committed_height` equal to the attested CommitQC height and
`applied_height` equal to `committed_height`. A committed block whose body is not
yet applied therefore never authorizes onboarding, and an unsigned status read
never counts. All four validators must attest one height under two distinct
challenges, and each attested proof must carry the same decision as the contiguous
finality chain verified from the signed genesis. Different valid CommitQC
witnesses for one block are accepted; a different block or genesis hash at that
height is rejected. Node, build, configuration or consensus-instance mismatches
are immediate failures. A zero committed height, a tip that moves during its
challenge and validators at different heights keep polling, and the deadline
error reports each validator's last public progress. Wave zero accepts the
first common committed height, genesis included; each restart wave then
requires a strictly higher committed height, produced by that wave's three
journaled canaries (onboarding, faucet, write). A retained wave receipt is
reauthenticated under the signed genesis and rejects unknown fields and omitted
nullable status fields. Iroha does not create empty blocks; HTTP restart
readiness does not require idle tip growth.
Candidate tests exercise the real HTTP producer and strict host receipt consumer,
direct signed probe origins, private signer descriptor lifetime, ordered recovery
and failure before edge cutover. Prepared-envelope tests cross the actual typed
write producer into the authenticated host consumer and all four Inrou variants
through inherited descriptors and predecessor decoding. Binding checks cover
canonical object metadata before submission and after commit, rejecting changed
fields and JSON strings substituted for objects. Unknown envelope fields remain
invalid. Stopped-owner tests preserve the slot lock while
releasing exact empty worker cgroups, reject live or substituted runtime state,
and verify idempotent cleanup before a stop receipt can be reused. Firewall
fixtures admit only exact slot-owned rules and real construction/deletion cuts;
foreign references or changed rules keep the barrier in place. Cleanup removes
each admitted rule explicitly and never flushes a chain.
Linux also runs a real OpenSSH
configuration-only check that verifies parent-held descriptor paths survive its
descriptor cleanup and replacement of the original paths. Every test selected by the explicit scope must exist and execute exactly once.
Missing, ignored or failed selected tests fail the command; deferred cases are
omitted from the success census and independent-check evidence. After the mandatory startup
preflight passes, the priority CLI/Torii groups report their combined failures
before the four-peer fixture; the remaining independent cases report theirs after it.
The native archive recovery group stops before other startup groups on failure; the remaining
startup groups stop expensive work after collecting their failures. Missing selected tests, artifact custody
failures and infrastructure errors still stop immediately. Fix the named failures and
rerun the same command to reuse compiled dependencies.

The selected toolchain's Cargo executes this command from `/` with the isolated
environment and selected `CARGO_TARGET_DIR`:

```sh
cargo --config /absolute/repo/.cargo/config.toml test --manifest-path /absolute/repo/Cargo.toml --locked --offline -p iroha_cli_lib --lib --no-run --message-format=json-render-diagnostics
```

Only existing disposable test fixtures are used. The gate accepts no live
configuration, keys, tokens, SSH, signing or deployment inputs, and writes no
report files. It is an early regression check and does not replace existing
release qualification, exact signed-source and artifact checks, or the offline
probes against actual Linux release binaries. Public readiness still requires
the end-to-end live checks.

CI no longer runs this census. The `build` job in `.github/workflows/workspace_release.yml` runs the nextest `release-gate` profile (`.config/nextest.toml`), which selects tests by package and module path instead of hand-listed names, then builds the full workspace. This script is retired with the rest of the Taira toolchain (see `specs/network_deployment.md`). The census remains an optional developer diagnostic and is not a prerequisite for
cross-compilation or deployment. The canonical
release artifact producer remains `scripts/run_release_pipeline.py`; it does
not gain a hidden build step or additional runtime authority.

Validate the runner without Cargo:

```sh
python3 -B -m unittest discover -s pytests/scripts -p test_taira_release_check.py
```

Cargo compiler errors retain their rendered diagnostics while the gate consumes
JSON artifact events; accelerator progress is also preserved.
Each metadata, test-codegen and shipping-codegen phase reports requested and
observed Cargo targets, including additional library tests selected by Cargo's
package-wide `--lib` flag. Artifact counts distinguish fresh cached units,
rebuilt units and unavailable freshness; they include dependencies and do not
count as test passes. Running summaries continue during quiet compilation or
linking, even without new artifact events, and end with a summary when Cargo
exits, including failure. Unchanged counts mean no new completed artifacts have
been observed; they do not imply a stalled compiler. Shipping binaries retain their separate
feature graph, excluding test-only fixtures; shared source changes can require
both graphs to rebuild in the same warm target directory.

### Mutable focused source changes

Focused development diagnostics observe Git HEAD, the binary tracked diff and
content hashes of nonignored untracked files before work begins. They recheck that
observation before each subsequent source-check, metadata, codegen, configuration,
focused-runtime and network phase, and before final success. A change stops the
diagnostic at that boundary; a running child finishes normally, and no child is
killed or restarted. Start a new explicit check against the intended source.
Unchanged tracked files are represented by Git HEAD and its diff, rather than
rehashing the entire tree. This is a race detector, not proof of the source consumed
by Cargo; it provides no release qualification. Immutable `prepare` retains its
authenticated source, pinned tools and artifact custody without running
regression tests.
