# Iroha Daemon (irohad)

The `irohad` executable package contains the `iroha3d` Iroha server (peer) binary. The binary is used to instantiate a peer and bootstrap an Iroha-based network. Portable, release-qualified production capabilities are compiled into the default daemon; runtime configuration controls deployment policy.

Pass the `--language <code>` flag to override automatic language detection for informational and error messages.

## Build

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.93.1), installed and configured.

Optionally, [Docker](https://www.docker.com/) can be used to build images containing any of the provided binaries. Using [Docker buildx](https://docs.docker.com/buildx/working-with-buildx/) is recommended, but not required.

### Build the default Iroha binary

Build the Iroha peer binary as well as every other supporting binary:

```bash
cargo build --release
```

The results of the compilation can be found in `<IROHA REPO ROOT>/target/release/`, where `<IROHA REPO ROOT>` is the path to where you cloned this repository (without the angle brackets).

### Add specialized features

To add optional features, use ``--features``. For example, to add the support for _dev telemetry_, run:

```bash
cargo build --release --features dev-telemetry
```

A full list of features can be found in the [cargo manifest file](Cargo.toml) for this crate. Explicit features are reserved for platform accelerators, preview providers, profiling/developer tooling, release evidence, and test/fault-injection lanes that cannot form one portable production build.

An Inrou worker has one stock daemon watchdog, the pinned bubblewrap launcher,
bubblewrap's private PID1 reaper, and QEMU. The watchdog retains an exact daemon
pidfd and worker cgroup handle; daemon death during startup or normal operation
kills the entire worker cgroup. QEMU's `exit-with-parent` remains enabled, and
forced shutdown kills the cgroup before reaping the watchdog. Qualification
must exercise the stock daemon's actual startup attestation and supervisor
termination, including namespace construction, before publishing a release.

### Disable default features

By default, the Iroha binary selects the `daemon` aggregate. It includes the portable Core and Torii production surfaces, full Halo2/STARK proof support, GOST and SM algorithms, event and metrics telemetry, schema endpoints, DAG recovery verification, HTTPS/WSS webhooks, and the bounded app/MCP API surface. To construct a deliberately reduced specialist library, disable the aggregate explicitly.

```bash
cargo build -p irohad_lib --release --no-default-features --lib
```

This flag can be combined with the `--features` flag in order to precisely specify the feature set that you wish.

### Standalone beacon preparation

Every `iroha3d_taira beacon-bootstrap` command requires
`--credential-max-memory-bytes <positive-bytes>` before the subcommand. Configure
that explicit operation cap in the supervisor's launch arguments; the command
uses one pool for authenticated session custody and verification scratch and
preserves local capacity failures. It does not cap every raw DKG or encoding
buffer. The existing [beacon bootstrap contract](BEACON_BOOTSTRAP.md) records the
exact command and custody boundaries.

### Deployment runtime-provider launcher

`irohad_lib` provides the `irohad` library target; the `irohad` package owns the thin executable launchers. A deployment-owned binary can use the same
CLI/config/bootstrap path as the stock binary while supplying deployment-owned
signing, custody, authentication, transport, immutable-query, publication, and sealed
checkpoint adapters:

```rust
use irohad::IrohaRuntimeProviderRegistryV1;

fn run(registry: &dyn IrohaRuntimeProviderRegistryV1) -> irohad::ReportResult<(), irohad::MainError> {
    irohad::run_with_runtime_provider_registry(iroha_core::compiled_build_metadata!(), registry)
}
```

The registry receives an `IrohaRuntimeProviderBindingsV1` containing only the
display/routing chain ID, the exact genesis-derived `NetworkId` for daemon
catalogs, and an ordered set of public slot/handle/revision/policy-digest
bindings. Standalone services that never sign or validate transactions may
omit `NetworkId`. It does not receive the full node
configuration, validator key, provider credentials, API tokens, or private
evidence. Registry selection is a compile-time/launcher decision; the standard
launcher has no environment or config selector that dynamically loads
executable provider code.

The stock `iroha3d` binary does not embed deployment providers. With the default
empty binding catalog it starts without external adapters. With a non-empty
catalog it uses the stock local-broker client and fails before subsystem
startup if the broker or any exact requested role is
missing, substituted, stale, or unsupported.

For an installed global-beacon session, startup also authenticates the public
transcript against the committed network and ordered roster, then asks the
resolved signer for a non-signing custody attestation for the local session and
one-based seat. A provider for a different seat or a retired session cannot
pass startup. Fresh-network bootstrap can start before installation; height-bound
production readiness remains unavailable until the committed key and exact
runtime custody are present.

`iroha3d beacon-prepare-custody` (also available in `iroha3d_taira`) consumes
canonical `staking committee export-custody-evidence` output plus independent
`--network-id`, `--trusted-context-id`, `--anchor-height`, `--target-epoch` and
`--transition-id` pins. It requires the incumbent quorum's exact
`FinalizeGlobalBeaconKey` certificate and the selecting/current finality chain.
Its output proves pending custody preparation only; it does not prove certificate
inclusion, refresh the supplied chain tip, submit an instruction or activate a session.

The pending share arrives as three canonical 32-byte scalar components on
owner-only disposable inherited FD 198, which is consumed and scrubbed. Existing
members also supply `--current-catalog` and the complete retained credential on
FD 200, which is read without modifying its file. The import verifies the exact
current session and local seat, preserves all retained sessions and appends the
exact frozen target session. `--handle`, `--revision`, `--chain-id` and `--output`
produce a strictly advanced catalog, private credential and public receipt in a
new fsynced generation directory through a no-replace atomic rename. The output's
parent must already exist under non-writable, non-symlink ancestors. The command
never replaces an existing generation or changes a running provider. Deployment
must retain the other configured roles' credentials when assembling a complete
broker generation; the output catalog preserves their public qualifications.

Restart imports both sessions under the matched catalog revision and inventory
digest. The authenticated consensus boundary controls session selection and
retirement. Retention across scheduling epochs keeps the current authority's
credential. Append-only preparation does not implement secret pruning; the
existing 64-session bound fails closed rather than removing credentials without
retirement evidence. Secret owners and final frame buffers are zeroized on drop;
this software custody does not establish allocator-wide erasure of temporary
codec allocations, process-memory compromise resistance or physical disk erasure.

An enabled Musubi provider-attestation journal projects its combined durability
seal, approval-only signer, and authenticated coordinator inventory as three
independent public bindings in exact slots 57, 58, and 59. Slot 57 exposes
separate authenticated small-record namespaces for the monotonic UNIX-time
floor and checkpoint head, plus immutable content-addressed checkpoint blobs;
one qualification covers that complete durability contract. The binding
catalog and resolved dependency set are all-or-none and contain no endpoint,
credential, token, or private key. Registry resolution snapshots each exact
production handle/revision/policy digest before and after qualification, but it
does not call readiness or perform a durability, signing, or inventory effect.
The stock broker does not implement these roles.

`ExternalSoftwareSignerMusubiProviderAttestationAdapterV1` supplies the concrete
approval-only software custody leaf for the existing injected signer role. Each
isolated service pins the network, provider, complete canonical owner account,
and governed policy ID/revision/predecessor/digest. Provisioning imports a
runtime-only key through the existing encrypted-envelope owner after checking
controller membership. The adapter commits its fixed ordered endpoint/controller
set in the configured policy digest and requires every configured member on each
replay-stable operation. The service validates the complete typed payload and
persists its approval before returning; revocation and an exact retry survive
service restart. Generic rotation cannot replace a controller outside the pinned
owner. A finalized successor owner or policy requires independently provisioned
and qualified successor custody.

This leaf is injected through
`IrohaRuntimeDeps::with_sorafs_musubi_provider_attestation_approval_signer` and
uses the existing finalized-owner governed wrapper. It does not implement the
stock broker roles or activate publication routes. Tests use the real encrypted
service and journal for signing/restart controls and real Unix peer credentials
for rejection controls. Positive cross-UID socket deployment qualification still
requires separately administered service, client, and administrator accounts.
Software custody does not claim protection from privileged offline rollback.

These slots remain inert. Private daemon wrappers now pin the signer to its
configured adapter, chain/genesis/provider context, and finalized
`State::provider_owners()` value, and pin inventory calls and returned data to
their configured adapter and exact chain/genesis/archive/order scope, with
put/get restricted to the local provider. Neither wrapper is installed or
supervised. Because the stock broker does not support slots 57--59, ordinary
stock launch fails during pre-Tokio provider resolution. If an injected registry
resolves and qualifies the three roles, the shared `start_with_runtime_deps`
activation gate still rejects the journal before supervisor startup.

The inert capture foundation exposes request minting only through a doc-hidden
`NodeHandle` method. Its clone-shared marker identifies one process-local handle
incarnation with storage and an ingest outbox; restart creates a fresh marker.
The marker owns a non-resetting atomic take guard across handle clones. The
prepared daemon archive exposes its signed capture reader only as one movable
concrete value, and a private composer consumes it into a doc-hidden
non-generic coordinator retained on `Iroha`. Acquisition is reader-inert and
lazy binding retries that same reader/session after height-zero bootstrap; the
coordinator exposes no public operational surface and starts no child.
Same-head suppression is scanner-lifetime only. Reconciliation now performs a
qualified exact slot-59 read after fresh request verification and before
enqueue: an existing valid item with the exact request payload suppresses
admission, absence proceeds, and conflict or qualification failure fails closed.
Journal enqueue remains idempotent only while its key is retained because
delivered rows may be capacity-pruned. Concrete combined durability, signer,
and inventory adapters, broker readiness, effect-driver ownership, supervision,
and fault/chaos/platform qualification remain separate gates. Deployment must
also enforce one rooted
journal session for each exact external provider scope across machines, or an
equivalent authenticated provider-side session fence; the local OS lease
coordinates only processes sharing one state root.

The journal's raw checkpoint/CAS types, abstract store, transition engine, and
runtime constructor are crate-private, as is checkpoint-head orchestration. The
public root-fenced file store exposes no raw load/CAS operation. On Linux and
macOS its explicit initialization path proves the local cache empty and installs
the canonical empty external `H0`; ordinary open requires an existing `H0` or
later head, never initializes from local bytes, and consumes the store only
after matching chain/genesis/provider plus the exact retained journal-policy
digest. Canonical domain-separated hashes bind that scope and every
predecessor-linked head record.

A mutation exactly reads back an immutable content-addressed checkpoint blob,
then the external head CAS, before advancing the local two-slot cache. The
external head/blob remains authoritative after local rollback: only an exact
direct predecessor proved by the retained predecessor record and blob can be
repaired forward; deeper rollback, ahead/fork, missing, or substituted state
fails closed. The separate sealed time floor bounds the checkpoint timestamp.
The external-to-local window is protected by a nonblocking process and
cross-process lease on the two-slot initialization lock whose exact identity is
committed in the immutable slot headers. Contention returns unavailable,
cancellation releases the lease, and exact retry completes recovery. Other
platforms fail closed, and this runtime remains inert and unwired in stock
`irohad`.

There are two supported injection boundaries. A deployment-owned embedding
binary can statically link this crate, keep credentials inside reviewed
provider implementations, and call `run_with_runtime_provider_registry`.
Standard `irohad` startup instead projects the non-secret configured binding
catalog and, when that catalog is non-empty, creates the stock authenticated
local-broker client registry before starting Tokio or node-owned durable state.
The public `[runtime_provider_broker].endpoint_path` selects that registry's
Unix socket; the default is the packaged Linux or macOS path. Configuration
rejects relative, ambiguous, oversized, or wrongly named paths before provider
resolution. Connection and server bind still require exact service UID, socket
mode, inode, and safe ancestor ownership.
An explicitly injected registry remains authoritative. There is no
process-global registry, plugin loader, environment selector, or executable
provider selector in configuration.

When finalized moderation is enabled, that same catalog projection also
qualifies the configured strict-ingress handle, revision, and public-policy
digest against Torii's fixed V1 ingress binding. This happens before the stock
broker client or an injected registry is invoked, and therefore before Tokio
or node-owned durable state exists. The in-process ingress is intentionally not
an external broker slot; missing, substituted, stale, zero-qualified, or
test-marked configuration fails the common launcher preflight, while the live
adapter remains requalified at Torii construction and around every operation.

The source tree provides `RuntimeProviderBrokerDeploymentV1` as the standard
deployment assembly around the injected `serve_runtime_provider_broker_v1`
server boundary. `RuntimeProviderBrokerExecutableV1` adds the common process
shell: a two-public-argument `RuntimeProviderBrokerExecutableArgsV1` CLI
(`--catalog` and required `--broker-policy`), secure
bounded canonical-catalog and TOML-policy loading, redacted failures, supervisor-owned
readiness/lifecycle hooks, and SIGINT/SIGTERM shutdown. Its
`RuntimeProviderBrokerBackendRegistryV1` receives only the sanitized non-empty
public catalog, and the assembled launch performs exact live server
qualification before readiness. Deployment and server APIs receive the complete
parsed `actual::RuntimeProviderBroker` policy. The standalone public TOML file
contains that table's fields directly; it is root-owned, read-only, single-link,
and bounded to 16 KiB. Its `observer_operation_timeout_ms` defaults to 15000
and accepts 1..=15000 with no environment override. The original deadline
starts before admitted observer dispatch and spans reply publication. A
synchronous provider cannot be cancelled in flight, and late output is rejected.
The server accepts canonical non-empty client subsets of that catalog so the
stock daemon and packaged standalone services can share one configured endpoint;
the handshake requires the same exact genesis-derived `NetworkId` and every
binding byte-for-byte, and a session cannot invoke a provider outside its
authenticated subset. The packaged `sorafs_governance_dag` launcher therefore
requires `--chain-id`, `--network-id`, and `--broker-endpoint`. Deployment launchers can
handoff that projection without sharing `actual::Config` by calling
`IrohaRuntimeProviderBindingsV1::export_canonical_v1`; the broker side loads it
with `load_canonical_v1`, or uses
`load_runtime_provider_broker_catalog_file_v1` for the process shell's secure
absolute-path handoff. The explicitly versioned canonical Norito artifact is
bounded, non-empty, strictly ordered, and contains only the chain identity plus
the mandatory exact `NetworkId`, public handles, identities, revisions, bounds,
and policy digests already held by the sanitized projection. The common CLI has
no plugin, private-key, credential, or test-provider argument; Linux and macOS
use the required validated authenticated endpoint, while Windows
and other platforms fail before catalog filesystem access because V1 has no
equivalent authenticated transport.

The common shell does not supply provider implementations. The stock external
software signer supplies its supported roles through supervisor-provided
credentials; deployments needing other backends link a reviewed concrete
registry into a binary that parses `RuntimeProviderBrokerExecutableArgsV1` and
calls `RuntimeProviderBrokerExecutableV1`. Credentials stay inside those
provider objects. The feature-isolated `iroha_test_runtime_provider_broker`
qualifies disposable peer networks with the same canonical credential decoder
and broker server. It takes one exact bundle through inherited standard input
and never appears in shipping builds. Client wiring or an empty registry alone
does not qualify a production adapter.

Registry resolution itself validates the sanitized binding catalog and rejects
missing or unrequested dependency objects. It cannot independently attest to a
trait object. The following service-owned startup boundaries provide the actual
qualification:

- Moderation quarantine, transparency PRF/release anchors, the Governance DAG
  signer and public-service adapters, appeal finance, moderation runtime,
  the evidence viewer's WebAuthn/grant/signer/erasure providers and
  authoritative checkpoint store, PoP, PoTR, gateway ACME/feed transport,
  reputation publication/delivery, hedging/billing, and the provider-ingest
  source pool, signer resolver, and checkpoint store compare configured or
  deterministically derived public identities and recheck them around use.

- The reputation finalized query is not an injectable registry object. The
  daemon opens the configured bounded archive, performs exact zero-gap
  reconciliation against Kura before Sumeragi starts, applies the configured
  live-lag barrier, and installs that same archive in the Sumeragi executor
  apply path (`iroha_core::sumeragi::executor`).
  Every fresh height is captured after Kura finality and the durable WSV
  checkpoint but before live State publication; an archive failure makes the
  committed transition restart-required.

- The provider-ingest completion signer accepts only the configured session
  chain and expected owner, an `Instructions` executable containing exactly one
  non-zero `CompleteReplicationOrder`, and the exact retained signer-policy
  lineage, assignment revision, and finalized anchor. Broker admission and
  request/result validation, plus the durable outbox, reject alternate
  executables, extra instructions, proof attachments, even-empty multisig
  sidecars, invalid signatures, and any context substitution.

- The central launcher converts the four configured proof-outcome, repair,
  reserve/rent, and orderbook identities into immutable Torii bindings, then
  wraps each raw registry provider in a role-specific qualified facade before
  any subsystem receives it. Missing, unexpected, role-confused, substituted,
  stale, test-marked, or drifting providers fail resolution.

- Stream-token signing checks the configured production handle, Ed25519 public
  key, non-zero adapter revision, and public-policy digest.
  Both startup qualification probes are individually identity-fenced, and every signing
  operation rechecks the exact qualification and handle/key binding before and
  after the external call before verifying the returned signature.

- Provider-ingest source and resolver adapters check independently configured
  production handles, non-zero revisions and public-policy digests, the fixed
  source inventory, bounded readiness, and resolved signer identity. Startup,
  every worker probe, each fetch, and each signer resolution recheck the exact
  role-specific qualification before and after provider work.

Governance DAG Kubo request authentication, signed-HTTP head CAS
authentication, and sealed monotonic checkpoint/publish-intent storage are
separate required registry slots. When the service is enabled, irohad qualifies
their exact stable handles, revisions, and public-policy digests before Sumeragi
startup, then prepares and supervises the service from the already resolved
config view. The Kubo and head adapters must each return a live
`GovernanceDagRequestIngressQualificationV1` matching the exact configured
`GovernanceDagRequestIngressBindingV1`, exposed by
`ipfs_request_ingress_binding()` and `head_request_ingress_binding()`. The only
accepted ingress contract is an exclusive authenticated receiver backed by one
shared sealed atomic replay namespace for the complete replica set through
envelope expiry. The service rechecks identity around every authenticated
request and sealed CAS operation.

The publisher uses one fixed Kubo UnixFS profile, locally derives every expected
CID, and publishes the public head only through signed-HTTP strong-ETag CAS.
Its mirror retains the protocol-fixed suffix of at most 65,536 blocks and 512
MiB of canonical source bytes. A sealed intent owns the derived mirror candidate;
checkpoint/source recovery must reproduce its exact digest. All referenced Kubo
objects are verified or repaired before the public-head CAS, each checkpoint
generation receives a full first audit, and later polls rotate through the
retained objects. A missing post-CAS pin or object is restored from authenticated
bytes only when it reproduces the same deterministic CID.

Preparation also yields the service-owned authenticated mirror-read capability.
The launcher installs it into the embedded `NodeHandle` exactly once, before
spawning the service task or sharing the first node clone. Installation checks
the logical and retained physical producer root, the configured and retained
signer identity/qualification/peer/key, the sealed-checkpoint-store binding,
the reader-retained service-state root, and the existing typed mirror store.
Any mismatch is startup-fatal. Every mirror read authenticates the current typed
store and sealed checkpoint under the runner's readiness epoch; reconciliation
failure or runner exit withdraws all retained readers. Torii reads publication,
runtime, and mirror authority through these path-free typed snapshots.
The stock Governance DAG binary likewise has no built-in credential loader;
deployment launchers inject a
`GovernanceDagServiceRuntimeProviderRegistryV1` through the library entrypoint.

The stream-token source-side identity gap is closed. Production readiness still
requires a genuine deployment-owned signer matching that exact public binding
and multi-replica rotation/revocation/failover evidence. Likewise, moderation
strict-ingress preflight does not provide the real external moderation signer,
settlement, publication, notification, archive, or multi-replica deployment
evidence required for production readiness.

Stream-token gateway admission uses the native consensus owner. Enabled issuance requires
`stream_tokens.admission_native` with distinct direct Ed25519 operator, observer and reputation-recorder accounts,
owner-only credential paths, explicit operator/observer fee intent and declared UTC uncertainty in `0..=5000` ms.
The admission handle and policy revision/digest pin the governed policy. Startup performs a
live qualification; each operation authenticates its exact purpose and current permissions.
The local configured qualification is only an identity pin. External gateway broker providers
are retired, and daemon launch rejects injected gateway admission providers.

The same native owner supplies reputation delivery directly; it does not activate the broader
reputation publication or PoR runtime. The original admitted source retains the full governed
Append payload, including its fee intent and finite lifetime. A preloaded recorder credential
signs only an opaque current Core delivery capability. Queue presence is a readiness hint;
an independently verified terminal disposition must precede success and acknowledgement.
Expired or governance-cancelled sources can drain their original row, while Accepted serving
requires Delivered. Recovery preserves the original payload and deadline. The independent
`admission_reconcile_interval_ms` defaults to 1,000 ms and accepts `1..=60000`.

`admission_operation_timeout_ms` defaults to 30,000 ms and accepts `1..=60000`. Its absolute
deadline starts before the worker queue and covers admission, callback reconciliation,
acknowledgement and final Serving confirmation. That confirmation requires the original
physical attempt and an acknowledged, unexpired original lease. Expiry maintenance is bounded;
permanent native execution history owns exact acknowledgement/release replay. The publication
fence encloses the immediate synchronous admission handoff. HTTP transport runs afterward.

The token issuer's receipt journal uses the shared `iroha_fs` owner on Unix and Windows.
It retains exact path and lock identities, consumes each bounded writer into an opaque sealed
reader, and preserves interrupted writes and no-replace publication evidence. One configured
`signer_journal_inventory` pool funds complete scans, pinned receipts and rereads; see the
[source accounting](src/signer_operation/journal/inventory_budget.md) for native probe,
allocation and handle limits. The token issuer no longer has a Unix-only startup branch.
Native Windows custody and installed runtime qualification remain required, along with the
separate platform requirements of other SoraFS services.

The combined candidate still needs runtime validation and multi-replica recovery. Component
coverage does not qualify the complete native service graph, cold registry fetches or deployed
ingress. Native release matrices, the complete 64 MiB fetch-process RSS bound and reference-host
p95 startup/deployment measurements remain separate gates in the
[developer goals](../../specs/kagami_mochi_devex_goals.md).

## Configuration

To run the Iroha peer binary, you must [generate the keys](#generating-keys) and provide a [configuration file](#configuration-file).

### Generating Keys

Generate a new key pair for every non-testing deployment. Validator consensus
identities use BLS-normal keys and a Proof-of-Possession; client and transport
identities typically use Ed25519. The provided
[`kagami`](../iroha_kagami/README.md) tool writes keys directly into an
owner-only custody directory. For a validator identity:

```bash
cargo run --bin kagami -- keys --algorithm bls_normal --pop \
  --out-dir ./validator-key-custody
```

Kagami creates a fresh owner-only directory containing `public.key` and
`private.key`, plus `pop.hex` for this command; it never prints the private key
to standard output. To see the available options, run
`cargo run --bin kagami -- keys --help`.

**NOTE**: The `kagami` binary can be run without `cargo` using the `<IROHA REPO ROOT>/target/release/kagami` binary.
Refer to [generating key pairs with `kagami`](../iroha_kagami/CommandLineHelp.md#kagami-keys) for more details.

### Configuration file

See the current [peer configuration reference](https://docs.iroha.tech/reference/peer-config/params.html)
for the complete parameter list and examples.

`--config` accepts a custom flat file or a compact profile node file (one that
sets `profile`, `validators` and `data_dir`). `role` defaults to `validator`;
use `observer` or `lane_validator` explicitly. The profile supplies the network
discriminant, and the role supplies `sumeragi.role`; neither is repeated in a
profile node file. Start with [the validator example](../../configs/validator.example.toml).
Both forms are read through
`iroha_config::node_config`; a profile node file is layered over its compiled
profile, may set only the per-node keys, and must not be combined with `--sora`.
`--config-blake3` binds the exact bytes of either kind of file.

### Node secrets

When the configuration sets `data_dir`, the stock `iroha3d` reads its runtime
secrets from fixed files under `<data_dir>/secrets/` (`irohad::node_secrets`):

- `runtime_signer.key`: the Soracloud runtime signer, one canonical Ed25519
  private multihash and a newline (71 bytes). It is required when
  `soracloud_runtime.submission.signer` is configured (which `production_mode`
  requires). That binding must carry this key, its account as `authority`, the
  handle `software://iroha/node-secrets/runtime-signer/<public key hex>`,
  `revision = 1` and the policy digest
  `iroha_config::parameters::actual::node_runtime_signer::policy_digest_v1()`.
- `beacon.cred`: the global-beacon seat credential, loaded when present on a
  validator. Its provider binding comes from the credential header; a configured
  `sumeragi.global_beacon_partial_signer_provider_*` binding must equal it.
- `authority/onboarding.key`: checked for custody and matched to
  `torii.account_onboarding.authority` when onboarding reads it from that path.

Every file must be a regular file with one link, owned by root or the daemon user,
readable only by its owner, of its exact record size, and reached through
directories that are neither symlinks nor group/world-writable. The path is walked
as written: only root-owned system links in root-owned, non-writable directories
(such as macOS `/var`) are followed, so a symlinked `data_dir` or `secrets`
directory is refused. `--check-config` and `--check-storage` never open these files.

The key files the configuration itself names under `<data_dir>/secrets/`
(`validator.key`, `transport.key`, `streaming.key` and `authority/*.key`) pass the
same custody checks whenever the node file is loaded, before the configuration
parser reads them; `--check-config` and `--check-storage` do read those.

Deployment launchers that supply their own runtime-provider registry
(`iroha3d_taira` until the cutover) do not use `node_secrets`.

### Compatibility probes

Run these with a new binary before it replaces an old one:

- `iroha3d --config <file> --check-config --json` prints the handshake- and
  genesis-bound values of this build and configuration as one Norito JSON object
  (`config_fingerprint`, `protocol_version`, `wire_schema_hash`,
  `nexus_policy_digest`, `gas_schedule_hash`, `execution_policy_hash`,
  `nexus_amx_context_hash`, plus `status`). Genesis-bound values are `null`
  while the signed genesis is not available locally.
- `iroha3d --config <file> --check-storage` inspects a stopped node's store:
  it opens Kura in emergency-Fast mode (taking the store-root lock, so a store
  owned by a running node is refused), decodes every retained block body with
  this build, restores the newest snapshot into a scratch Kura, compares every
  block hash the snapshot retains with Kura's as a Strict startup does, and prints
  `{tip_height, tip_hash, snapshot_height, prefix_hash_at_snapshot_height,
  snapshot_restore_dry_run, snapshot_restore_error}`. It exits nonzero when the
  store cannot be read or the restore dry run fails, and never writes to the store.

`lifecycle.exit_on_stdin_close = true` makes the daemon shut down cleanly when
its standard input reaches end-of-file; a local supervisor sets it and holds the
other end of the pipe.

## Deployment

You may deploy Iroha as a [native binary](#native-binary) or by using [Docker](#docker).

### Native binary

1. **Build the binaries.**

    ```bash
    cargo build --release -p irohad --bin iroha3d
    cargo build --release -p iroha_kagami
    ```

2. **Stage a runtime directory.** Copy the release binary and the closest
   configuration template (the Sora Nexus profile ships under `defaults/nexus/`):

    ```bash
    mkdir -p deploy/peer
    cp target/release/iroha3d deploy/peer/
    cp defaults/nexus/config.toml deploy/peer/config.toml
    cp defaults/nexus/genesis.template.json deploy/peer/genesis.template.json
    ```

    Adjust the file layout if you prefer another location. `irohad` resolves
    relative paths from the directory that contains `config.toml`. The checked-in
    Nexus source is intentionally not a `RawGenesisTransaction` and cannot be
    signed or selected by `[genesis]`. Materialize it with the network's explicit
    canonical XOR asset definition, then embed the final ordered BLS topology and
    proofs of possession before signing. Do not substitute Taira validator keys
    or Taira's XOR asset ID.

3. **Provision keys and network settings.**

    - Generate a validator key pair into a fresh owner-only custody directory:

      ```bash
      cargo run --release -p iroha_kagami -- \
        keys --algorithm bls_normal --pop \
        --out-dir deploy/peer/validator-key-custody
      ```

    - Update `config.toml` with the new `chain` and the canonical records from
      `validator-key-custody/{public,private}.key`, plus the `trusted_peers` you
      expect in your initial topology and the matching `pop.hex` entry in
      `trusted_peers_pop`. Ensure each peer advertises a unique
      `network.address`/Torii port pair.

4. **Generate and sign the genesis block.**

    - Materialize the reviewed source. An NPoS source also takes the network's
      explicit canonical XOR definition; a permissioned source takes none:

      ```bash
      cargo run --release -p iroha_kagami -- \
        genesis materialize deploy/peer/genesis.template.json \
        --xor-asset-definition-id <XOR_ASSET_DEFINITION_ID> \
        > deploy/peer/genesis.json
      ```

    - Sign the manifest to obtain the Norito block (`.nrt`) that the daemon
      expects:

      ```bash
      cargo run --release -p iroha_kagami -- \
        genesis sign deploy/peer/genesis.json \
        --topology '<FINAL_VALIDATOR_PEER_ID_JSON_ARRAY>' \
        --private-key-file <MODE_0600_GENESIS_PRIVATE_KEY_FILE> \
        --expected-public-key <GENESIS_PUBLIC_KEY> \
        --bound-manifest-out deploy/peer/genesis.json \
        --out-file deploy/peer/genesis.signed.nrt \
        --expected-hash-out deploy/peer/genesis.expected_hash
      ```

      Then edit `config.toml` so that the `[genesis]` section references the
      signed block:

      ```toml
      [genesis]
      file = "genesis.signed.nrt"
      manifest_json = "genesis.json"
      public_key = "<GENESIS_PUBLIC_KEY>"
      expected_hash_file = "genesis.expected_hash"
      ```

      See `crates/iroha_kagami/CommandLineHelp.md` and the
      [public genesis reference](https://docs.iroha.tech/reference/genesis.html)
      for additional subcommands such as `validate` and `embed-pop`.

5. **Start an Iroha peer.** Point the daemon at your staged configuration (add
   `--sora` when using the Nexus profile from `defaults/nexus/`):

    ```bash
    cd deploy/peer
    ./iroha3d --config ./config.toml
    # or, for the Nexus demo profile:
    ./iroha3d --sora --config ./config.toml
    ```

    Repeat the validator configuration/key steps for every peer and provision
    the same signed genesis block plus exact bound manifest on every peer with
    empty storage. Genesis is a local startup trust artifact and is not fetched
    from another validator. To tolerate _f_ Byzantine faults the network must
    contain exactly _3f + 1_ validators with mutually listed `trusted_peers`
    entries.

### Docker

We provide an explicitly seeded development-only sample configuration in
[`docker-compose.yml`](../../defaults/docker-compose.yml). It contains no
genesis signing key or runtime signer. Provision the signed body, verifier key,
and independently approved exact hash for that exact sample roster before
evaluating the manifest:

```bash
cargo run --bin kagami -- localnet \
  --seed Iroha --peers 4 --sora-profile nexus --consensus-mode npos \
  --out-dir target/compose-genesis
export IROHA_GENESIS_SIGNED_FILE="$PWD/target/compose-genesis/genesis.signed.nrt"
export IROHA_GENESIS_PUBLIC_KEY_FILE="$PWD/target/compose-genesis/genesis.public_key"
export IROHA_GENESIS_EXPECTED_HASH_FILE="$PWD/target/compose-genesis/genesis.expected_hash"
docker compose -f defaults/docker-compose.yml up --build
```

The checked seeded Compose mounts all three runtime inputs read-only into every
validator. Prepared seedless Compose validates each exact `peerN.toml`, derives
a content-addressed container-safe projection, proves that its consensus and
deterministic execution fingerprints are unchanged, and mounts that projection
as `/config/peer.toml` through a file-backed Compose secret. Validator keys do
not appear in Compose YAML or environment variables. Neither mode mounts the
genesis signing key, client credentials, source manifest, or source peer config.
Host-only account-onboarding and faucet services are omitted from the
validator-only projection. Missing files and trust-root mismatches fail closed.
For a deployed network, generate one authoritative `kagami localnet` bundle and
run `kagami docker` without `--seed`; Kagami validates and reuses its identities,
PoPs, signed body, verifier key, hash, and policy-equivalent configs rather than
inheriting the sample validator credentials.
To keep containers running after closing the terminal,
use the `-d` (*detached*) flag:

```bash
docker compose -f defaults/docker-compose.yml up --build -d
```

- Stop containers:

    ```bash
    docker compose -f defaults/docker-compose.yml stop
    ```

- Remove containers:

    ```bash
    docker compose -f defaults/docker-compose.yml down
    ```

### Native publication pin custody

`NativeMusubiPinCoordinatorV1` uses the portable wallet journal for exact source,
unsigned payload, signed envelope and permanent exposure custody. Each effect
follows an actual signed native Check round; ordinary Queue admission and native
Advance CAS remain authoritative. Reopen never creates a session or renews the
original UTC, Nexus fee or round authorization. Cancellation preserves originals
for read-only recovery. Native pin pricing is separate from those Nexus ceilings.
The concrete storage backend, complete three-provider publication and physical
Queue allocation qualification remain required before activating this path.
