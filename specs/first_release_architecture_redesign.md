# First-release architecture redesign

This plan tracks the canonical SDK and repository design. Source ownership,
dependency boundaries, wire semantics and measured compiler-memory limits remain
enforced. Code line-count gates are retired. Implementation presence does not
qualify a release candidate.

## Allocation and runtime storage boundary

`iroha_allocation` owns the std-only finite budget, original reservations and
charges, fixed buffers, shared backing and physical release notifications.
Model finality artifacts, cryptographic commitments, primitive codecs and VM
resource owners depend on it directly. Runtime storage generations, publication,
transactions and charged B+tree adapters remain in `mv` and `concread`; those
engines use the same lower allocation types rather than parallel custody owners.

The model's complete non-development dependency closure cannot reach either
storage engine. The Cargo feature-hygiene guard enforces that boundary, including
optional, target-specific and build dependencies. MV-backed model roundtrip tests
retain storage only as a development dependency. Canonical callers use the lower
owner directly; retired generic `mv::allocation` and `concread::shared`/`release`
exports are removed. Earlier footprint records below describe their own candidate
and do not supersede this ownership boundary.

## Current canonical protocol fixtures

The current Exact12 matrix and typed archive are generated from the compiled
canonical model types. The decoded archive has 390,344 bytes and SHA-256
`da62506174ea651123d5973b451f755032a498479be49b53e697dfcc38923972`.
SDK known-answer pins refer to this complete archive; older candidate captures
below retain their own original digests and test evidence.

The current normalized privacy transaction-intent fixture has 50,259 bytes and
BLAKE3 digest `52756936c8e625cec56483d94eda82a3a9f5e8749922239622d78b37ab9009bc`.
The model verifies its typed canonical projection against independently assembled
field framing and mutation controls; the explicit ignored KAT exporter reproduces
that value and the Vega digest from the public canonical model API.

Native finality checkpoints now carry genuine signed RS16 availability alongside
the real three-of-four BLS certificate. Three explicit exporter runs produced
identical H1 and H2 bytes, checked by canonical roundtrip and contiguous checkpoint
verification. Current fixture inputs and exact component evidence are recorded in
`fixtures/sumeragi/native-finality/capture.json`.
The fee-policy bridge tests read these shared archives and require their exact
heights and canonical re-encoding, so retired checkpoint layouts fail directly.
Supplied execution outputs remain synthetic and carry no World execution claim.

## Account-owned event and block streams

`AccountClient::events().subscribe(filters).await` and
`AccountClient::blocks().subscribe(height).await` own the canonical
`events.stream_websocket` and `blocks.stream_websocket` operations. The old flat
listeners, public flow handlers and direct socket connector are removed. Full
block access retains Torii's account and global-reader permission checks.

The context owns injectable HTTP and stream transports, selected explicitly by
`http_transport(...)` and `stream_transport(...)`. Streams preserve the exact
signed upgrade and initial Norito subscription. Establishment and initial send
share one request deadline; redirects, retries and automatic resubscription are
absent. Subscription encoding is fallible and bounds the complete frame before
output allocation. Caller-constructed nested rejected-instruction filters return
a typed invalid-request error instead of panicking on Norito's depth rejection;
the same context can then encode and send a valid subscription with exact bytes.
Initial subscriptions are bounded at 256 KiB, received messages at
64 MiB including fragmentation, and upgrade bodies at 64 KiB. Control-frame work
is bounded per poll. Protocol, decoding and abnormal close errors terminate the
stream and retain typed diagnostics; close codes and reasons remain observable.

Owned asynchronous streams outlive the account context. The explicit blocking
facade drives the same implementation through its reusable runtime and rejects
entry from an async runtime. Concurrent callers borrow that runtime without
holding a mutex across pending I/O; an idle stream cannot block a sibling
subscription, receive or close. A blocking receive deadline limits one wait without
resubscribing; normal EOF and timeout are distinct. Explicit close has a bounded
deadline and returns errors. CLI consumers retain both receive and close failures,
and their four per-command runtime loops are removed. All 27 existing external
SDK listener calls are migrated, preserving scenario assertions.

Mochi now uses these canonical capabilities through a generation-bound
supervisor reader carrying the exact genesis account, network and peer endpoint.
Its raw socket API is removed; UI fanout preserves actual received-message sizes,
typed errors, cancellation and a retained initial receiver. Arbitrary vault
signers do not inherit the genesis account's global-reader grant.
Remaining synchronous capabilities, real four-validator streams,
workspace/native/device and pinned-memory release gates remain unqualified.

## CI daemon ownership and affected tiers

The Rust lane manifest now declares the message-control daemon required by
`iroha_test_network` and `integration_tests`. The artifact builder compiles its
test feature in a separate target directory and stages it under a distinct name;
network jobs supply the exact `TEST_NETWORK_BIN_IROHAD_MESSAGE_CONTROL` path.
The shipping daemon remains a separate artifact with its own feature graph.
Izanami still requests only the shipping daemon and CLI.

Foundation-only changes defer the four affected daemon/network packages while
retaining the library and local CLI reverse dependencies. The `daemon_packages`
manifest entry prevents a bin-only `irohad` selection from building a daemon
inside the nominally binary-free matrix. Classification records every deferred
package and consumer. Direct consumer inputs, mixed source changes, unknown
inputs and full selection retain their required jobs and artifacts. Package
README prose no longer seeds Rust jobs; executable Kotodama document changes
retain their independent source comparison and Koto selection.

The Parliament lifecycle and both Nexus proof corridors now depend on explicit
classification outputs. Their existing qualified runners, build protocols and
job bodies remain intact. Required-result aggregation includes all three and
rejects failures, cancellations, unexpected skips and inconsistent selection.
The Parliament source contract follows the immutable client builder's exact
timeout binding and rejects both a disabled timeout and a disconnected rebuild.

## Operator configuration capability

`OperatorClient::configuration().get().await` is the sole configuration operation
for `operator.configuration.read`. Public and account contexts cannot access it;
the old `Client::get_config` and gas-schedule projection getter are removed.
Consumers obtain the gas schedule from the shared configuration DTO.

The exact empty-body GET is signed with the bound operator key and network,
excluding account and token authentication. The JSON-only route uses centralized
asynchronous dispatch, the context deadline and an 8-MiB response ceiling. It
issues no compatibility probe, representation fallback or automatic retry.
The direct `blocking::OperatorClient::from_client` constructor owns a reusable
runtime without binding an account; existing blocking clients can share their
runtime with the operator. Runtime construction errors now use the common typed
error family. Async-entry rejection and shutdown behavior remain unchanged.

All eight external reads are migrated: two CLI commands and six integration
readbacks, preserving operator credentials, restart contexts and every existing
scenario assertion. Shared test transport ownership removes duplicated async-only
test dispatch.

## SDK validation and result ownership

Multisig proposal validation now owns one typed intent containing instructions,
metadata and their hash. Parsed fee metadata feeds the exact proposal marker and
metadata projection; unsigned responses still match the complete requested
payload before signing. A dedicated `QueuePlan` classifier preserves conservative
submission ambiguity, canonical evidence and locally computed identities.
Subscription validation separates resource/state binding from exact instruction
checks. Private-settlement recovery uses an explicit phase context and shared
borrowed inputs, preserving authenticated prepare/commit evidence and finality.

Onboarding results and subscription payload drafts own their large variants through
`Box`; the CLI consumes those canonical types directly. Subscription futures are
`Send`, including injected-transport preparation. These result-storage changes are
separate from the AMX overflow fix: the finite participant settlement and hash-only
schema expansion remain unchanged and match the default-stack regression evidence.

## Asynchronous public node diagnostics

`Client::status().get().await` and `Client::status().version().await` own the
canonical `diagnostic.status` and `core.api_version` routes. Their explicit
blocking capabilities run the same implementation on the facade's reusable
runtime. Flat getters and the raw status-request wrapper are removed.

Status preserves negotiated JSON/Norito with an 8-MiB response ceiling; version
requires UTF-8 text with a 16-KiB ceiling. Shared asynchronous dispatch owns the
deadline, authoritative Accept header and structured transport errors. Ambiguous
content types reject. Injected transports obey the same response bounds and
deadline. These diagnostic reads neither probe compatibility nor replay failed
requests under another representation. Subscription operations now use this
same dispatch and media-type boundary; their signed bodies and tests remain.

Transport errors retain standard I/O categories through wrapped causes. Startup
and integration helpers use those categories for refusal, backpressure and
permission-denial handling. Async peer polling and startup height checks use
async contexts directly. One private injected status-source loop preserves the
minimum applied-height barrier, with no status-only blocking runtime or worker.
The 34-path caller migration covers 78 former status calls and three version
calls, preserving existing scenario assertions and synchronous facade users.

## Immutable SDK construction

`Client::builder(config).build()` is the canonical fallible constructor. Endpoint,
network, authority, headers and policies are private after construction; the old
constructors and mutation setters are removed. Validation rejects malformed or
ambiguous headers, embedded URL credentials, non-directory endpoints and invalid
account/key bindings before transport construction. Diagnostics exclude header
values. Default asynchronous transport initialization returns a structured error;
an injected transport avoids default initialization.

Clones share their compatibility decision and probe coordinator. Every builder
build creates fresh state, including `to_builder()`; changing a transport or
endpoint cannot inherit an old probe result. A copied builder retains the selected
transport and explicit configuration, including the address discriminant. Test
fixtures seed the newly constructed context rather than carrying over old cache
state. Existing submission, rejection, finality and response assertions remain.

## Musubi and model ownership

`iroha_primitives::fs` owns platform filesystem flags. Durable publisher,
clock/journal and archive consumers retain bounded handle-based custody and
unsupported-platform rejection. `sorafs_car::musubi::plan` owns CAR plan and
commitment validation. Publication must bind finalized State/Kura authority,
software signing, retained private source and provider readback through one
canonical workflow; see [Musubi](musubi.md), the
[operations procedure](musubi_operations_runbook.md) and
[workflow completion goals](musubi_taira_workflow_goals.md).

The [base extraction inventory](model_base_extraction.md) and
[Norito identity specification](norito_schema_identity.md) define canonical
ownership, captured wire identity and atomic consumer-cutover obligations.
Physical crate extraction and the required compiler-memory reduction remain open.

## Accepted design

- Split foundational, privacy, and service wire models into independent
  compilation units, with aggregate ledger composition in `iroha_data_model`.
- Keep node execution and product service implementations outside the Rust SDK
  and storage client dependency graphs.
- Replace mutable client configuration and global transports with immutable
  public/account/operator contexts and asynchronous capability interfaces.
- Keep an explicit blocking facade over the same transport implementation.
- Compose Core storage and Torii routes from capability-owned components.
- Enforce dependency boundaries, substantive duplication removal and measured
  compiler memory.
- Classify CI consumers before building their required binaries.
- Use Kotlin/JVM as the sole JVM implementation, with Java consumer tests.
- Keep status and roadmap focused on current outcomes and actionable blockers.

Focused new crates and a corresponding Cargo.lock refresh are authorized for
this redesign. Mandatory consensus behavior, Norito layout guarantees, and the
single IVM ABI remain enforced. Existing uncommitted work must be preserved.

## Completion gate

Qualify affected SDK, Core, Torii, CLI, daemon and native consumers on one
unchanged candidate. Preserve canonical wire fixtures and every substantive
consumer assertion. Measure comparable baseline/candidate compiler units on the
pinned runner, including new crates; source relocation alone proves no memory
improvement. Complete the required 25% model-memory reduction and preserve
release-unit ceilings. Follow [compile optimization goals](compile_bloat_optimization_goals.md),
[status](../status.md) and [roadmap](../roadmap.md) for current outcomes and blockers.
